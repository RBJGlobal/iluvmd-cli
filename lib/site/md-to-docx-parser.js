/**
 * MD → DOCX adapter.
 *
 * Builds a Word document from a Markdown string using the `docx` library
 * (https://github.com/dolanmiu/docx), vendored locally at
 * /vendor/docx-9.6.1.umd.js. Vendoring keeps CSP narrow (no new origin)
 * and eliminates third-party CDN trust. See /vendor/PROVENANCE.md.
 *
 * The library is ~230KB gzipped — heavy enough that we lazy-load it on
 * the first call to parse(). Call MdToDocxParser.loadLibrary() explicitly
 * to prewarm if you want to avoid the first-click latency spike.
 *
 * The block tokenizer + inline runner + URL allowlist + table-cell
 * sanitizer live in markdown-block-tokenizer.js (shared with MD→PDF) so
 * the security caps and the hardening rules cannot drift between formats.
 *
 * Hardening (security review 2026-04-18, refined 2026-05-18):
 *   - 5MB input cap, 50-level nesting cap, 10k table-cell cap — enforced
 *     by the shared tokenizer.
 *   - Hyperlink scheme allowlist (http/https/mailto) — shared tokenizer.
 *   - Formula-injection guard on table cells (CWE-1236) — shared tokenizer.
 *   - Trojan-source-class char stripping at input boundary — shared tokenizer.
 *   - Only docx's high-level typed API is used — no raw XML concatenation,
 *     no ImportedXmlComponent, no user-controlled string interpolation
 *     into OOXML. Blocks DDE-field and OOXML injection.
 */

const MD_TO_DOCX_VENDOR_SRC = '/vendor/docx-9.6.1.umd.js';
const MD_TO_DOCX_VENDOR_SRI = 'sha384-uivVsQ/IfB9fV8HkO1Mfl0uqULuzGx66o5GNZx3JiyownvWWcDfZG/luWYSZjrFk';

const MD_TO_DOCX_MAX_MERMAID_BLOCKS = 50; // diagrams rendered per document (see _renderMermaidBlocks)

// Body paragraph spacing — matches Word's Normal style (line 1.15, 8pt after).
const MD_TO_DOCX_BODY_SPACING = { before: 0, after: 160, line: 276 };

// Heading paragraph styles. Values here MUST be JS source literals — never
// derive from user-supplied markdown. `id`/`name`/`basedOn`/`next` are XML
// attribute sinks in the OOXML output; routing tokenized text through them
// would widen the trust boundary established by the high-level-API-only rule.
// (Security invariant per 2026-05-17 review.)
//
// IDs use PascalCase with no space (`Heading1`, not `Heading 1`) so they
// bind to docx's HeadingLevel.HEADING_1..6 enum.
const MD_TO_DOCX_HEADING_STYLES = [
    { id: 'Heading1', name: 'Heading 1', sizeHalfPt: 56, color: '1A1A1A', italics: false, before: 480, after: 120 },
    { id: 'Heading2', name: 'Heading 2', sizeHalfPt: 44, color: '1A1A1A', italics: false, before: 320, after: 80  },
    { id: 'Heading3', name: 'Heading 3', sizeHalfPt: 32, color: '1A1A1A', italics: false, before: 240, after: 80  },
    { id: 'Heading4', name: 'Heading 4', sizeHalfPt: 26, color: '1A1A1A', italics: false, before: 200, after: 60  },
    { id: 'Heading5', name: 'Heading 5', sizeHalfPt: 22, color: '4A4A4A', italics: false, before: 180, after: 60  },
    { id: 'Heading6', name: 'Heading 6', sizeHalfPt: 22, color: '6A6A6A', italics: true,  before: 180, after: 60  }
];

class MdToDocxParser {
    constructor(options = {}) {
        this.options = options;
        // Defaults preserve the historical DOCX caps (5MB / 50-nest / 10k cells).
        // MD→PDF instantiates its own tokenizer with lower limits.
        this.tokenizer = new MarkdownBlockTokenizer({
            maxInputChars: 5_000_000,
            maxNestDepth: 50,
            maxTableCells: 10_000,
            label: 'DOCX export'
        });
    }

    /**
     * Lazy-load the vendored docx library. Idempotent; safe to call from
     * multiple sites concurrently. Rejects if the script fails to load or
     * fails the SRI check.
     */
    static loadLibrary() {
        if (typeof docx !== 'undefined') return Promise.resolve();

        // Reuse an in-flight or already-loaded script tag if one exists.
        const existing = document.querySelector('script[data-lib="docx"]');
        if (existing) {
            if (existing.dataset.loaded === 'true') return Promise.resolve();
            return new Promise((resolve, reject) => {
                existing.addEventListener('load', () => resolve(), { once: true });
                existing.addEventListener('error', () => reject(new Error('DOCX library failed to load.')), { once: true });
            });
        }

        return new Promise((resolve, reject) => {
            const s = document.createElement('script');
            s.src = MD_TO_DOCX_VENDOR_SRC;
            s.integrity = MD_TO_DOCX_VENDOR_SRI;
            s.crossOrigin = 'anonymous';
            s.dataset.lib = 'docx';
            s.onload = () => {
                s.dataset.loaded = 'true';
                resolve();
            };
            s.onerror = () => reject(new Error('DOCX library failed to load. Check your network connection and try again.'));
            document.head.appendChild(s);
        });
    }

    async parse(markdown) {
        if (typeof markdown !== 'string') markdown = String(markdown || '');

        if (typeof docx === 'undefined') {
            await MdToDocxParser.loadLibrary();
        }
        if (typeof docx === 'undefined') {
            throw new Error('DOCX library failed to load. Check your network connection and try again.');
        }

        // tokenize() enforces input-size / nesting / table-cell caps and
        // strips trojan-source-class invisible chars at the boundary.
        const tokens = this.tokenizer.tokenize(markdown);
        // Pre-pass: render any ```mermaid``` blocks to PNG ArrayBuffers
        // so _renderCodeBlock can emit ImageRun instead of text paragraphs.
        // Each render is independent — Promise.allSettled lets one bad
        // diagram fall back to text rendering without failing the rest.
        this._mermaidImages = await this._renderMermaidBlocks(tokens);
        const doc = this._buildDocument(tokens);
        return docx.Packer.toBlob(doc);
    }

    // Walk tokens (and nested children via blockquote/list/table), find
    // every ```mermaid code block, render in parallel via
    // window.iLoveMD.mermaid.renderSafe, return a Map<token, {data, w, h}>.
    // Bypassed entirely if the Mermaid API is not available on the page.
    async _renderMermaidBlocks(tokens) {
        const result = new Map();
        if (!window.iLoveMD || !window.iLoveMD.mermaid || !window.iLoveMD.mermaid.renderSafe) return result;
        const mermaidToks = [];
        const walk = (toks) => {
            if (!Array.isArray(toks)) return;
            for (const t of toks) {
                if (t && t.type === 'code' && (t.lang || '').toLowerCase() === 'mermaid' && t.text && t.text.trim()) {
                    // Past the cap a diagram stays a fenced code block (no entry
                    // in the map): each render is a full Mermaid layout plus a
                    // 2x PNG rasterization, unbounded would hang the tab.
                    if (mermaidToks.length < MD_TO_DOCX_MAX_MERMAID_BLOCKS) mermaidToks.push(t);
                }
                if (t && t.children) walk(t.children);
                // List items can carry child blocks (a fenced diagram under
                // a numbered step is a common README shape).
                if (t && Array.isArray(t.items)) {
                    for (const item of t.items) if (item && item.children) walk(item.children);
                }
            }
        };
        walk(tokens);
        if (mermaidToks.length === 0) return result;
        const renderSafe = window.iLoveMD.mermaid.renderSafe;
        const settled = await Promise.allSettled(mermaidToks.map(async (tok) => {
            const r = await renderSafe(tok.text);
            // Attach the SVG off-DOM so getBBox works inside the rasterizer.
            const hidden = document.createElement('div');
            hidden.style.cssText = 'position:absolute;left:-9999px;top:-9999px;visibility:hidden;width:800px';
            hidden.appendChild(r.svg);
            document.body.appendChild(hidden);
            let arrBuf, w, h;
            try {
                const bbox = r.svg.getBBox();
                w = Math.ceil(bbox.width + 24);
                h = Math.ceil(bbox.height + 24);
                const blob = await r.png({ scale: 2, padding: 12 });
                arrBuf = await blob.arrayBuffer();
            } finally {
                document.body.removeChild(hidden);
            }
            return { tok, data: new Uint8Array(arrBuf), w, h };
        }));
        for (const s of settled) {
            if (s.status === 'fulfilled') {
                result.set(s.value.tok, { data: s.value.data, w: s.value.w, h: s.value.h });
            }
            // Failed renders are silently absent from the map — the
            // text fallback in _renderCodeBlock will render the source.
        }
        return result;
    }

    // ------------------------------------------------------------------
    // Document builder
    // ------------------------------------------------------------------

    _buildDocument(tokens) {
        const { Document } = docx;

        // Ordered lists each get their own numbering definition so Word
        // restarts at the list's own start number instead of continuing
        // the previous list (3., 4.). References are collected while the
        // blocks render, then turned into config here; names are a fixed
        // prefix plus a counter, never user text.
        this._orderedRefs = [];
        const children = [];
        this._renderBlocks(tokens, children, 0);

        const numbering = {
            config: [
                { reference: 'md-unordered', levels: this._buildUnorderedLevels() },
                ...this._orderedRefs.map(r => ({ reference: r.reference, levels: this._buildOrderedLevels(r.start) }))
            ]
        };

        // docx requires at least one paragraph in a section
        if (children.length === 0) {
            children.push(new docx.Paragraph({ children: [] }));
        }

        return new Document({
            numbering,
            styles: {
                default: {
                    // Apply BODY_SPACING to the Normal style so the
                    // constant is authoritative: heading paragraphs
                    // (basedOn: 'Normal') now inherit our line-height
                    // rather than Word's built-in default.
                    document: {
                        run: { font: 'Calibri', size: 22 },
                        paragraph: { spacing: MD_TO_DOCX_BODY_SPACING }
                    }
                },
                paragraphStyles: MD_TO_DOCX_HEADING_STYLES.map(h => ({
                    id: h.id,
                    name: h.name,
                    basedOn: 'Normal',
                    next: 'Normal',
                    quickFormat: true,
                    run: { size: h.sizeHalfPt, bold: true, italics: h.italics, color: h.color },
                    paragraph: { spacing: { before: h.before, after: h.after } }
                }))
            },
            sections: [{ properties: {}, children }]
        });
    }

    _buildUnorderedLevels() {
        const { LevelFormat, AlignmentType, convertInchesToTwip } = docx;
        const glyphs = ['\u2022', '\u25E6', '\u25AA'];
        return Array.from({ length: 9 }, (_, i) => ({
            level: i,
            format: LevelFormat.BULLET,
            text: glyphs[i % 3],
            alignment: AlignmentType.LEFT,
            style: {
                paragraph: {
                    indent: {
                        left: convertInchesToTwip(0.25 + 0.25 * i),
                        hanging: convertInchesToTwip(0.25)
                    }
                }
            }
        }));
    }

    _buildOrderedLevels(start = 1) {
        const { LevelFormat, AlignmentType, convertInchesToTwip } = docx;
        const safeStart = Number.isInteger(start) && start >= 0 && start <= 999_999_999 ? start : 1;
        return Array.from({ length: 9 }, (_, i) => ({
            level: i,
            format: LevelFormat.DECIMAL,
            text: `%${i + 1}.`,
            start: i === 0 ? safeStart : 1,
            alignment: AlignmentType.LEFT,
            style: {
                paragraph: {
                    indent: {
                        left: convertInchesToTwip(0.25 + 0.25 * i),
                        hanging: convertInchesToTwip(0.3)
                    }
                }
            }
        }));
    }

    _renderBlocks(tokens, out, depth) {
        if (depth > this.tokenizer.maxNestDepth) {
            throw new Error(`Nesting exceeds ${this.tokenizer.maxNestDepth} levels.`);
        }
        for (const tok of tokens) {
            switch (tok.type) {
                case 'heading':
                    out.push(this._renderHeading(tok));
                    break;
                case 'paragraph':
                    out.push(this._renderParagraph(tok.text));
                    break;
                case 'hr':
                    out.push(this._renderHr());
                    break;
                case 'code':
                    this._renderCodeBlock(tok, out);
                    break;
                case 'blockquote':
                    this._renderBlockquote(tok, out);
                    break;
                case 'list':
                    this._renderList(tok, out, 0, depth);
                    break;
                case 'table':
                    out.push(this._renderTable(tok));
                    break;
            }
        }
    }

    _renderHeading(tok) {
        const { Paragraph, HeadingLevel } = docx;
        const levels = [
            HeadingLevel.HEADING_1, HeadingLevel.HEADING_2, HeadingLevel.HEADING_3,
            HeadingLevel.HEADING_4, HeadingLevel.HEADING_5, HeadingLevel.HEADING_6
        ];
        return new Paragraph({
            heading: levels[Math.min(tok.level, 6) - 1],
            // keepNext prevents a heading from widowing at a page bottom.
            keepNext: true,
            children: this._toRuns(this.tokenizer.renderInlines(tok.text))
        });
    }

    _renderParagraph(text) {
        return new docx.Paragraph({
            children: this._toRuns(this.tokenizer.renderInlines(text)),
            spacing: MD_TO_DOCX_BODY_SPACING
        });
    }

    _renderHr() {
        const { Paragraph, BorderStyle } = docx;
        return new Paragraph({
            children: [],
            border: {
                bottom: { color: 'CCCCCC', style: BorderStyle.SINGLE, size: 6, space: 1 }
            },
            spacing: { before: 240, after: 240 }
        });
    }

    _renderCodeBlock(tok, out) {
        const { Paragraph, TextRun, ImageRun, BorderStyle, AlignmentType } = docx;
        // Mermaid block with a successful pre-pass render → embed as image.
        // The pre-pass (this._renderMermaidBlocks) populated _mermaidImages.
        if ((tok.lang || '').toLowerCase() === 'mermaid' && this._mermaidImages && this._mermaidImages.has(tok)) {
            const img = this._mermaidImages.get(tok);
            // Cap display width to ~6 inches (576px) so the image doesn't
            // run off a portrait letter page. Preserve aspect ratio.
            const MAX_W = 576;
            const w = img.w > MAX_W ? MAX_W : img.w;
            const h = img.w > MAX_W ? Math.round(img.h * (MAX_W / img.w)) : img.h;
            out.push(new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [new ImageRun({
                    data: img.data,
                    transformation: { width: w, height: h },
                    type: 'png'
                })],
                spacing: { before: 200, after: 200 }
            }));
            return;
        }
        const lines = tok.text.length ? tok.text.split('\n') : [''];
        const sideBorder = { color: 'D0D0D0', style: BorderStyle.SINGLE, size: 8, space: 6 };
        lines.forEach((line, idx) => {
            const isFirst = idx === 0;
            const isLast = idx === lines.length - 1;
            out.push(new Paragraph({
                children: [new TextRun({ text: line || ' ', font: 'Courier New', size: 20 })],
                shading: { fill: 'F5F5F5' },
                border: { left: sideBorder },
                spacing: {
                    before: isFirst ? 120 : 0,
                    after: isLast ? 120 : 0,
                    line: 260
                }
            }));
        });
    }

    _renderBlockquote(tok, out) {
        const { Paragraph, BorderStyle, convertInchesToTwip } = docx;
        // Split into paragraphs on blank lines; render each with a left border.
        // Neutral slate (not brand orange) — the exported document is the
        // user's, not iLoveMD's.
        const paras = tok.text.split(/\n{2,}/);
        for (const para of paras) {
            if (!para.trim()) continue;
            out.push(new Paragraph({
                children: this._toRuns(this.tokenizer.renderInlines(para.replace(/\n/g, ' ').trim()), { italics: true, color: '4A4A4A' }),
                border: {
                    left: { color: 'B0B0B0', style: BorderStyle.SINGLE, size: 18, space: 10 }
                },
                indent: { left: convertInchesToTwip(0.3) },
                spacing: { before: 120, after: 120, line: 276 }
            }));
        }
    }

    _renderList(list, out, level, depth) {
        if (depth > this.tokenizer.maxNestDepth) {
            throw new Error(`Nesting exceeds ${this.tokenizer.maxNestDepth} levels.`);
        }
        const { Paragraph, convertInchesToTwip } = docx;
        let reference = 'md-unordered';
        if (list.ordered) {
            // One definition per ordered list (capped: beyond 1000 lists
            // reuse the last one rather than bloat numbering.xml).
            if (this._orderedRefs.length < 1000) {
                reference = `md-ol-${this._orderedRefs.length}`;
                this._orderedRefs.push({ reference, start: Number.isInteger(list.start) ? list.start : 1 });
            } else {
                reference = this._orderedRefs[this._orderedRefs.length - 1].reference;
            }
        }
        const clampedLevel = Math.min(level, 8);
        for (const item of list.items) {
            out.push(new Paragraph({
                children: this._toRuns(this.tokenizer.renderInlines(item.text)),
                numbering: { reference, level: clampedLevel },
                spacing: { before: 40, after: 40, line: 276 }
            }));
            if (item.children && item.children.length) {
                for (const child of item.children) {
                    if (child.type === 'list') {
                        this._renderList(child, out, level + 1, depth + 1);
                    } else {
                        // Paragraphs, code, quotes and tables inside a list
                        // item: render as normal blocks, indented under the
                        // marker so they read as part of the item.
                        if (child.type === 'paragraph') {
                            out.push(new Paragraph({
                                children: this._toRuns(this.tokenizer.renderInlines(child.text)),
                                indent: { left: convertInchesToTwip(0.25 + 0.25 * clampedLevel) },
                                spacing: MD_TO_DOCX_BODY_SPACING
                            }));
                        } else {
                            this._renderBlocks([child], out, depth + 1);
                        }
                    }
                }
            }
        }
    }

    _renderTable(tok) {
        const { Table, TableRow, TableCell, Paragraph, AlignmentType, WidthType, BorderStyle } = docx;
        const allRows = [tok.header, ...tok.rows];

        const alignToType = a =>
            a === 'center' ? AlignmentType.CENTER :
            a === 'right' ? AlignmentType.RIGHT :
            AlignmentType.LEFT;

        const cellBorder = { style: BorderStyle.SINGLE, size: 4, color: 'D0D0D0' };
        const cellBorders = {
            top: cellBorder, bottom: cellBorder, left: cellBorder, right: cellBorder
        };

        const rows = allRows.map((row, rowIdx) => {
            const isHeader = rowIdx === 0;
            return new TableRow({
                tableHeader: isHeader,
                children: row.map((cell, colIdx) => {
                    const safe = this.tokenizer.sanitizeTableCell(cell);
                    const align = tok.aligns[colIdx] || 'left';
                    return new TableCell({
                        borders: cellBorders,
                        shading: isHeader ? { fill: 'F5F5F5' } : undefined,
                        children: [new Paragraph({
                            alignment: alignToType(align),
                            children: this._toRuns(this.tokenizer.guardFormulaRuns(this.tokenizer.renderInlines(safe)), { bold: isHeader })
                        })]
                    });
                })
            });
        });

        return new Table({
            rows,
            width: { size: 100, type: WidthType.PERCENTAGE }
        });
    }

    _toRuns(parts, override = {}) {
        const { TextRun, ExternalHyperlink } = docx;
        const out = [];
        for (const part of parts) {
            if (part.br) {
                out.push(new TextRun({ break: 1 }));
                continue;
            }
            const runOpts = {
                text: part.text || '',
                bold: override.bold || !!part.bold,
                italics: override.italics || !!part.italic,
                strike: !!part.strike
            };
            // `override.color` must remain a hard-coded literal at call sites
            // (slate hex for blockquote). Never derive from user input — this
            // becomes <w:color w:val="..."/> in the OOXML output.
            if (override.color) runOpts.color = override.color;
            if (part.code) {
                runOpts.font = 'Courier New';
                runOpts.shading = { fill: 'F5F5F5' };
            }
            const run = new TextRun(runOpts);
            if (part.link) {
                out.push(new ExternalHyperlink({ link: part.link, children: [run] }));
            } else {
                out.push(run);
            }
        }
        return out;
    }
}

window.MdToDocxParser = MdToDocxParser;
