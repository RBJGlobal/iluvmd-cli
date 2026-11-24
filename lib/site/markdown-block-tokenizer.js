/**
 * Shared markdown block tokenizer.
 *
 * Lifted from md-to-docx-parser.js on 2026-05-18 when MD→PDF was added.
 * Both MD→DOCX and MD→PDF consume this — single source of truth for the
 * tokenizer and the security caps. Drift between exporters would be a
 * quality bug today and a "behaviour differs between exporters" CWE-class
 * finding tomorrow.
 *
 * 2026-11-13: rewritten as an adapter over the vendored markdown-it
 * (the same CommonMark+GFM engine the md-to-html preview uses). The old
 * hand-rolled scanner toggled emphasis on every `*` and `_` (deleting
 * intraword underscores), missed `~~~` fences, closed 4-backtick fences
 * on an inner ``` and split loose lists. Parsing with one grammar gives
 * what-you-see-is-what-you-export parity with the preview. The public
 * API and the block/run shapes are unchanged so the renderers did not
 * have to move; two additive fields appeared: list.start and run.br.
 *
 * Public API:
 *   const t = new MarkdownBlockTokenizer({ maxInputChars, maxNestDepth,
 *                                         maxTableCells, safeSchemes });
 *   const tokens   = t.tokenize(markdownString);  // throws on cap violations
 *   const runs     = t.renderInlines(text);
 *   const ok       = t.isSafeUrl(url);
 *   const safeText = t.sanitizeTableCell(cellText);
 *
 * Block shapes:
 *   { type:'heading', level, text }
 *   { type:'paragraph', text }
 *   { type:'hr' }
 *   { type:'code', lang, text }
 *   { type:'blockquote', text }            // source lines with one `>` stripped
 *   { type:'list', ordered, start, items:[{ text, children:[blocks] }] }
 *   { type:'table', header:[], aligns:[], rows:[[]] }
 * Run shape: { text, bold, italic, strike, code?, link?, br? }
 *
 * Caps are configurable per consumer. Defaults match the DOCX exporter
 * (5MB / 50-nest / 10k cells); MD→PDF passes lower limits because
 * pdfmake's layout engine is more expensive than docx packing.
 *
 * Hardening:
 *   - Input size cap, list-nesting cap, table-cell cap (all configurable).
 *     markdown-it silently drops content past its own maxNesting, so we
 *     give it headroom and throw ourselves when a block nests too deep.
 *   - Private markdown-it instance with html:false and linkify:false. Any
 *     HTML in the source is literal text, never a tag, link or image.
 *   - URL scheme allowlist for link annotations (http/https/mailto by
 *     default) re-checked on every link_open href, whatever markdown-it
 *     accepted — blocks javascript:, file://, data:, ms-msdt: (Follina),
 *     UNC, and relative URLs that resolve unpredictably in output formats
 *   - Images are alt text only. src never reaches the exporters.
 *   - Formula-injection guard for table cells (CWE-1236) — prefixes a
 *     zero-width space onto cells starting with `= + - @` so Excel does
 *     not parse them as formulas if the user copies a cell out
 *   - Trojan-source-class character stripping at the input boundary AND
 *     on every emitted run/code string: markdown-it decodes `&#x202E;`
 *     into a live bidi override after the boundary strip, so the strip
 *     runs again on parsed text. Tabs, LF, CR are preserved because
 *     markdown depends on them.
 */

const MARKDOWN_BLOCK_DEFAULTS = {
    maxInputChars: 5_000_000,
    maxNestDepth: 50,
    maxTableCells: 10_000,
    safeSchemes: ['http:', 'https:', 'mailto:'],
    // Short human label used in cap-exceeded error messages so the user
    // knows which export triggered the limit (e.g. "DOCX export", "PDF
    // export"). Empty default → generic message.
    label: ''
};

// Invisible code-point classes stripped at the input boundary and again
// on parsed text. C0 controls (except \t \n \r), DEL, ALM, LRM/RLM, the
// bidi override class and the bidi isolate class. Same set as every
// other parser's CTRL_BIDI_RE (tests/run-source-hygiene.js keeps the
// escapes literal-free).
const MARKDOWN_BLOCK_TROJAN_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

// Front matter: `---` on the first line, a closing `---` (or `...`) later.
// CommonMark would render it as <hr> + setext heading; exporters show it
// as a yaml code block instead so no key/value pair silently vanishes.
// The opener must be followed directly by a `key:` line so a document that
// merely starts with a horizontal rule is not swallowed into a code block.
const MARKDOWN_BLOCK_FRONT_MATTER_RE = /^---[ \t]*\r?\n(?=[A-Za-z_][\w.-]*[ \t]*:)([\s\S]*?)\r?\n(?:---|\.\.\.)[ \t]*(?:\r?\n|$)/;

class MarkdownBlockTokenizer {
    constructor(options = {}) {
        this.maxInputChars = options.maxInputChars ?? MARKDOWN_BLOCK_DEFAULTS.maxInputChars;
        this.maxNestDepth  = options.maxNestDepth  ?? MARKDOWN_BLOCK_DEFAULTS.maxNestDepth;
        this.maxTableCells = options.maxTableCells ?? MARKDOWN_BLOCK_DEFAULTS.maxTableCells;
        this.safeSchemes   = options.safeSchemes   ?? MARKDOWN_BLOCK_DEFAULTS.safeSchemes;
        this.label         = options.label         ?? MARKDOWN_BLOCK_DEFAULTS.label;
        this._md = null;
        // env of the most recent tokenize() call. renderInlines() reuses it
        // so reference-style links ([text][ref]) defined anywhere in the
        // document resolve when a renderer re-parses a block's text.
        this._env = {};
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    tokenize(markdown) {
        if (typeof markdown !== 'string') markdown = String(markdown ?? '');

        if (markdown.length > this.maxInputChars) {
            const mb = (markdown.length / 1024 / 1024).toFixed(1);
            const limMb = (this.maxInputChars / 1024 / 1024).toFixed(0);
            const suffix = this.label ? ` for ${this.label}` : '';
            throw new Error(`Input is too large (${mb} MB). Keep it under ${limMb} MB${suffix}.`);
        }

        const md = this._engine();
        let src = markdown.replace(MARKDOWN_BLOCK_TROJAN_RE, '');
        const blocks = [];

        const fm = MARKDOWN_BLOCK_FRONT_MATTER_RE.exec(src);
        if (fm) {
            blocks.push({ type: 'code', lang: 'yaml', text: fm[1] });
            src = src.slice(fm[0].length);
        }

        this._env = {};
        const tokens = md.parse(src, this._env);
        const lines = src.split(/\r\n?|\n/);
        const state = { tokens, lines, i: 0 };
        this._walkBlocks(state, blocks, 0, null);
        return blocks;
    }

    renderInlines(text) {
        if (typeof text !== 'string') text = String(text ?? '');
        if (!text) return [];
        const md = this._engine();
        const parsed = md.parseInline(text, this._env);
        const children = (parsed && parsed[0] && parsed[0].children) || [];
        const runs = [];
        this._emitRuns(children, runs, [], null, 0);
        return runs;
    }

    isSafeUrl(url) {
        if (typeof url !== 'string' || !url) return false;
        // Parse without a base — relative URLs throw and get rejected. An
        // absolute URL-to-nowhere in output formats is worse than no link.
        try {
            const parsed = new URL(url);
            return this.safeSchemes.includes(parsed.protocol);
        } catch {
            return false;
        }
    }

    // Same guard, applied to rendered runs. Entities (&#61;) and escapes
    // (\=) decode after sanitizeTableCell ran on the raw cell, so the first
    // visible character is checked again here (security review 2026-11-13).
    guardFormulaRuns(runs) {
        if (!Array.isArray(runs) || !runs.length) return runs;
        const first = runs.find(r => r && typeof r.text === 'string' && r.text.length);
        if (first && /^\s*[=+\-@]/.test(first.text)) first.text = '\u200B' + first.text;
        return runs;
    }

    sanitizeTableCell(text) {
        // CSV-injection class (CWE-1236): spreadsheets parse cells starting
        // with = + - @ as formulas on paste. Prefix a zero-width space so
        // the literal characters survive but spreadsheet formula parsers
        // don't see a leading metachar.
        if (/^\s*[=+\-@]/.test(text)) {
            return '​' + text;
        }
        return text;
    }

    // ------------------------------------------------------------------
    // markdown-it engine (private instance, fail closed)
    // ------------------------------------------------------------------

    _engine() {
        if (this._md) return this._md;
        const factory = (typeof window !== 'undefined' && window.markdownit) || null;
        if (typeof factory !== 'function') {
            throw new Error('Markdown engine failed to load. Reload the page and try again.');
        }
        // html:false      raw HTML is text, never markup (exporters have no
        //                 sanitizer downstream, so there is nothing to sanitize)
        // linkify:false   bare URLs stay text; only explicit [..](..) links
        //                 become annotations, and only after isSafeUrl
        // maxNesting      headroom above our own cap so markdown-it never
        //                 truncates before _walkBlocks can throw
        this._md = factory({
            html: false,
            linkify: false,
            breaks: false,
            typographer: false,
            maxNesting: this.maxNestDepth * 4 + 20
        });
        return this._md;
    }

    _clean(s) {
        return String(s == null ? '' : s).replace(MARKDOWN_BLOCK_TROJAN_RE, '');
    }

    // ------------------------------------------------------------------
    // Block walk
    // ------------------------------------------------------------------

    _nestError(kind) {
        return new Error(`${kind || 'List'} nesting exceeds ${this.maxNestDepth} levels.`);
    }

    /**
     * Consume tokens from state.i until `closeType` (or end of stream),
     * appending block objects to `out`. Recursion depth is bounded by
     * maxNestDepth: lists and blockquotes both count.
     */
    _walkBlocks(state, out, depth, closeType) {
        if (depth > this.maxNestDepth) throw this._nestError(closeType === 'blockquote_close' ? 'Blockquote' : 'List');
        const toks = state.tokens;
        while (state.i < toks.length) {
            const t = toks[state.i];
            if (closeType && t.type === closeType) { state.i++; return; }

            switch (t.type) {
                case 'heading_open': {
                    const inline = toks[state.i + 1];
                    const level = parseInt(t.tag.slice(1), 10) || 1;
                    out.push({ type: 'heading', level, text: this._inlineText(inline) });
                    state.i = this._skipTo(state, 'heading_close');
                    break;
                }
                case 'paragraph_open': {
                    const inline = toks[state.i + 1];
                    out.push({ type: 'paragraph', text: this._inlineText(inline) });
                    state.i = this._skipTo(state, 'paragraph_close');
                    break;
                }
                case 'hr':
                    out.push({ type: 'hr' });
                    state.i++;
                    break;
                case 'fence': {
                    const lang = (t.info || '').trim().split(/\s+/)[0] || '';
                    out.push({ type: 'code', lang: this._clean(lang), text: this._clean(t.content.replace(/\n$/, '')) });
                    state.i++;
                    break;
                }
                case 'code_block':
                    out.push({ type: 'code', lang: '', text: this._clean(t.content.replace(/\n$/, '')) });
                    state.i++;
                    break;
                case 'blockquote_open': {
                    // Exporters render a quote as italic paragraphs split on
                    // blank lines, so hand them the source lines with one
                    // marker stripped (exactly what the old tokenizer did).
                    const text = this._sourceSlice(state.lines, t.map)
                        .map(l => l.replace(/^\s*>\s?/, ''))
                        .join('\n');
                    out.push({ type: 'blockquote', text });
                    // Skip the whole quote, counting nesting so an absurdly
                    // deep `> > > …` still trips the cap instead of silently
                    // flattening.
                    state.i++;
                    const inner = [];
                    this._walkBlocks(state, inner, depth + 1, 'blockquote_close');
                    break;
                }
                case 'bullet_list_open':
                case 'ordered_list_open': {
                    const ordered = t.type === 'ordered_list_open';
                    const startAttr = ordered ? t.attrGet('start') : null;
                    const start = startAttr != null && /^\d+$/.test(startAttr) ? parseInt(startAttr, 10) : 1;
                    state.i++;
                    const items = this._walkListItems(state, depth + 1, ordered ? 'ordered_list_close' : 'bullet_list_close');
                    out.push({ type: 'list', ordered, start, items });
                    break;
                }
                case 'table_open':
                    out.push(this._walkTable(state));
                    break;
                case 'html_block':
                    // html:false makes this unreachable; keep the fail-safe
                    // (literal text) in case the engine config ever drifts.
                    out.push({ type: 'paragraph', text: this._clean(t.content.replace(/\n$/, '')) });
                    state.i++;
                    break;
                default:
                    // Unknown or structural token (e.g. a stray *_close):
                    // step over it rather than loop forever.
                    state.i++;
            }
        }
    }

    _walkListItems(state, depth, closeType) {
        if (depth > this.maxNestDepth) throw this._nestError();
        const toks = state.tokens;
        const items = [];
        while (state.i < toks.length) {
            const t = toks[state.i];
            if (t.type === closeType) { state.i++; return items; }
            if (t.type !== 'list_item_open') { state.i++; continue; }
            state.i++;
            const blocks = [];
            this._walkBlocks(state, blocks, depth, 'list_item_close');
            // The first paragraph is the item's own text; everything else
            // (nested lists, code, further paragraphs, tables) becomes a
            // child block the renderers lay out under the marker.
            let text = '';
            if (blocks.length && blocks[0].type === 'paragraph') {
                text = blocks.shift().text;
            }
            items.push({ text, children: blocks });
        }
        return items;
    }

    _walkTable(state) {
        const toks = state.tokens;
        let header = [];
        const aligns = [];
        const rows = [];
        let inHead = false;
        let row = null;
        state.i++; // table_open
        while (state.i < toks.length) {
            const t = toks[state.i];
            state.i++;
            if (t.type === 'table_close') break;
            if (t.type === 'thead_open') { inHead = true; continue; }
            if (t.type === 'thead_close') { inHead = false; continue; }
            if (t.type === 'tr_open') { row = []; continue; }
            if (t.type === 'tr_close') {
                if (inHead) header = row; else rows.push(row);
                row = null;
                continue;
            }
            if (t.type === 'th_open' || t.type === 'td_open') {
                const inline = toks[state.i];
                const cellText = this._inlineText(inline);
                if (row) row.push(cellText);
                if (inHead) {
                    const style = t.attrGet('style') || '';
                    const m = /text-align:\s*(left|center|right)/i.exec(style);
                    aligns.push(m ? m[1].toLowerCase() : 'left');
                }
                // step over inline + *_close
                while (state.i < toks.length && toks[state.i].type !== 'th_close' && toks[state.i].type !== 'td_close') state.i++;
                state.i++;
                continue;
            }
        }
        const cellCount = (rows.length + 1) * header.length;
        if (cellCount > this.maxTableCells) {
            throw new Error(`Table is too large (${cellCount} cells). Maximum is ${this.maxTableCells}.`);
        }
        return { type: 'table', header, aligns, rows };
    }

    _skipTo(state, closeType) {
        const toks = state.tokens;
        let i = state.i;
        while (i < toks.length && toks[i].type !== closeType) i++;
        return i + 1;
    }

    _inlineText(inline) {
        // Raw inline source (`inline.content`); entities are still encoded
        // here, so no post-strip is needed yet. renderInlines() decodes and
        // strips when a renderer turns it into runs.
        return inline && inline.type === 'inline' ? inline.content : '';
    }

    _sourceSlice(lines, map) {
        if (!map || map.length < 2) return [];
        return lines.slice(map[0], map[1]);
    }

    // ------------------------------------------------------------------
    // Inline runs
    // ------------------------------------------------------------------

    _emitRuns(children, runs, stack, link, depth) {
        if (depth > this.maxNestDepth) throw this._nestError('Inline');
        const push = (text, extra) => {
            const clean = this._clean(text);
            if (!clean && !(extra && extra.br)) return;
            const run = { text: clean, ...this._styleFromStack(stack) };
            if (extra) Object.assign(run, extra);
            if (link) run.link = link;
            runs.push(run);
        };
        for (const c of children) {
            switch (c.type) {
                case 'text':
                    push(c.content);
                    break;
                case 'code_inline':
                    push(c.content, { code: true });
                    break;
                case 'softbreak':
                    push(' ');
                    break;
                case 'hardbreak':
                    push('', { br: true });
                    break;
                case 'strong_open': stack.push('bold'); break;
                case 'strong_close': this._pop(stack, 'bold'); break;
                case 'em_open': stack.push('italic'); break;
                case 'em_close': this._pop(stack, 'italic'); break;
                case 's_open': stack.push('strike'); break;
                case 's_close': this._pop(stack, 'strike'); break;
                case 'link_open': {
                    // Re-validate: markdown-it's own validateLink admits
                    // data:image/* and relative URLs; our allowlist does not.
                    const href = c.attrGet('href') || '';
                    link = this.isSafeUrl(href) ? href : null;
                    break;
                }
                case 'link_close':
                    link = null;
                    break;
                case 'image':
                    // Alt text only. Exporters never fetch or embed remote
                    // images (privacy-first) and never see the src.
                    if (c.children && c.children.length) {
                        this._emitRuns(c.children, runs, stack, link, depth + 1);
                    } else if (c.content) {
                        push(c.content);
                    }
                    break;
                case 'html_inline':
                    // Unreachable with html:false; literal text if it ever is.
                    push(c.content);
                    break;
                default:
                    if (c.content) push(c.content);
            }
        }
    }

    _pop(stack, kind) {
        const idx = stack.lastIndexOf(kind);
        if (idx !== -1) stack.splice(idx, 1);
    }

    _styleFromStack(stack) {
        return {
            bold: stack.includes('bold'),
            italic: stack.includes('italic'),
            strike: stack.includes('strike')
        };
    }
}

window.MarkdownBlockTokenizer = MarkdownBlockTokenizer;
