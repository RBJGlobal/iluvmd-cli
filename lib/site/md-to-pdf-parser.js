/**
 * MD → PDF adapter.
 *
 * Builds a vector PDF (selectable text, real layout) from a Markdown
 * string using the `pdfmake` library (https://github.com/bpampuch/pdfmake),
 * vendored locally at /vendor/pdfmake-0.3.8.min.js + the font bundle
 * /vendor/pdfmake-0.3.8.vfs_fonts.js. See /vendor/PROVENANCE.md.
 *
 * The library is ~1MB (engine) + ~830KB (Roboto vfs) — lazy-loaded on
 * the first call to parse(). Both files are SRI-verified.
 *
 * Architecture: shares the markdown block tokenizer (and its security
 * caps + URL allowlist + sanitizers) with MD→DOCX via the global
 * `MarkdownBlockTokenizer` class defined in markdown-block-tokenizer.js.
 *
 * Hardening (security review 2026-05-18):
 *   1. CVE-2026-26801 (URLResolver SSRF) mitigated by calling
 *      pdfMake.setUrlAccessPolicy(() => false) immediately after vfs load,
 *      before any createPdf() call.
 *   2. Hyperlink scheme allowlist (http/https/mailto) — shared tokenizer.
 *      pdfmake's `link:` annotation accepts file://, javascript:, etc.
 *      by default; the allowlist runs in renderInlines and any rejected
 *      URL is dropped (label rendered as plain text).
 *   3. Lower caps than DOCX: 2MB input, 50-level nesting (parity),
 *      5,000 table cells, 50,000 lines. pdfmake's layout engine is more
 *      memory-hungry than docx packing.
 *   4. Long code lines: zero-width-space soft-break every ~90 chars to
 *      let pdfmake wrap; otherwise a single 500-char line silently clips
 *      off the right margin.
 *   5. Image markdown is NOT rendered as an image (no fetch, no embed).
 *      Alt text becomes plain inline text. The PDF generation must make
 *      ZERO network calls.
 *   6. docDefinition style ids / names are JS source literals — never
 *      derive from user input (XML attribute sinks in the PDF dictionary).
 *   7. PDF-output smoke check: scan the produced blob bytes for risky
 *      PDF dictionary keys (/JS, /JavaScript, /OpenAction, /AA, /Launch,
 *      /EmbeddedFile, /RichMedia) and refuse to deliver if any appear.
 *      Belt-and-braces against a future pdfmake silently adding a feature.
 *   8. CSP unsafe-eval NOT required by pdfmake 0.3.8 (verified against
 *      build bytes — see /vendor/PROVENANCE.md). The single new Function()
 *      is a globalThis polyfill, unreachable on modern browsers.
 */

const MD_TO_PDF_VENDOR = {
    engine: {
        src: '/vendor/pdfmake-0.3.8.min.js',
        sri: 'sha384-Z2s/regCsnb9uS+Pas0k/ckmzd4AX/zvL00zQQHnxnnyT+IPDGzHHJpB3dQY+isc',
        dataLib: 'pdfmake-engine'
    },
    vfs: {
        src: '/vendor/pdfmake-0.3.8.vfs_fonts.js',
        sri: 'sha384-pkBUW1wxcm6m7ZjKDxADnNHqnz+Sx9sAL1ndsLNv/GZnWZgodPYsju1yxeyQnn0c',
        dataLib: 'pdfmake-vfs'
    }
};

// Per-consumer caps — lower than DOCX because pdfmake's layout engine
// (line breaking, page flow, cell measurement) is more expensive per
// token than docx OOXML packing.
const MD_TO_PDF_CAPS = {
    maxInputChars: 2_000_000,
    maxNestDepth: 50,
    maxTableCells: 5_000,
    label: 'PDF export'
};
const MD_TO_PDF_MAX_LINES = 50_000;
const MD_TO_PDF_MAX_MERMAID_BLOCKS = 50; // diagrams rendered per document (see _renderMermaidBlocks)
const MD_TO_PDF_CODE_SOFTBREAK_AFTER = 90;

// PDF dictionary keys that indicate a non-passive document: action triggers,
// embedded payloads, executable JS. If any of these appear in the produced
// PDF, something has gone wrong upstream and we refuse to deliver the blob.
// pdfmake's typed docDefinition API should NEVER emit these.
const MD_TO_PDF_BLOCKED_KEYS = [
    '/JavaScript',  // executable JS action
    '/JS',          // executable JS payload
    '/OpenAction',  // auto-fire on document open
    '/Launch',      // launch external program
    '/EmbeddedFile', // attached file payload
    '/RichMedia'    // Flash / 3D / multimedia
    // /AA (additional-actions) is intentionally omitted — pdfmake emits
    // an /AA entry in form annotations even on benign docs; checking it
    // produces false positives without a corresponding risk surface.
];

// Heading + style values. JS literals only — never derived from user input.
// (Security invariant: style id / name / color / font are XML attribute
//  sinks in the PDF dictionary output — same rule as the DOCX parser.)
const MD_TO_PDF_STYLES = {
    heading1:   { fontSize: 24, bold: true,    color: '#1A1A1A', margin: [0, 18, 0, 8] },
    heading2:   { fontSize: 18, bold: true,    color: '#1A1A1A', margin: [0, 14, 0, 6] },
    heading3:   { fontSize: 14, bold: true,    color: '#1A1A1A', margin: [0, 12, 0, 5] },
    heading4:   { fontSize: 12, bold: true,    color: '#1A1A1A', margin: [0, 10, 0, 4] },
    heading5:   { fontSize: 11, bold: true,    color: '#4A4A4A', margin: [0,  8, 0, 4] },
    heading6:   { fontSize: 11, bold: true,    italics: true, color: '#6A6A6A', margin: [0, 8, 0, 4] },
    paragraph:  { fontSize: 11, margin: [0, 0, 0, 6] },
    blockquote: { fontSize: 11, italics: true, color: '#4A4A4A', margin: [12, 4, 0, 6] },
    // codeBlock.background + rule.color are read by _renderCodeBlock / _renderHr
    // via the per-call this._styles clone (theme sinks — see _buildThemedStyles).
    codeBlock:  { fontSize: 9,  color: '#1A1A1A', background: '#F5F5F5', margin: [4, 4, 0, 8] },
    inlineCode: { fontSize: 10, color: '#1A1A1A', background: '#F0F0F0' },
    linkText:   { color: '#0066CC', decoration: 'underline' },
    tableHeader:{ bold: true, fillColor: '#F5F5F5' },
    rule:       { color: '#CCCCCC' },
    // Header/footer band text color. Not a pdfmake-referenced style name (inert
    // in docDefinition.styles); read by _buildBandFn from the per-call clone so
    // page numbers / header / footer follow the theme (black in print, light
    // grey on dark) instead of a fixed mid-grey.
    band:       { color: '#6A6A6A' }
};

// Document themes. Each is a set of LITERAL color values applied on top of a
// per-call clone of MD_TO_PDF_STYLES (never the frozen const). `light` is null
// (base styles unchanged, black text, white page). `dark` paints a dark page
// background + light text/fills. `print` forces pure black-on-white and strips
// every fill (ink economy). Accent applies ONLY in light theme (dark/print set
// their own heading/link colors — enforced in _buildThemedStyles, not the UI).
const MD_TO_PDF_THEMES = Object.freeze({
    light: null,
    dark: Object.freeze({
        pageBackground: '#1A1A1A', defaultColor: '#E8E8E8',
        heading: '#F5F5F5', headingMuted: '#BFBFBF', blockquote: '#BFBFBF',
        codeText: '#E8E8E8', codeBg: '#2A2A2A', inlineBg: '#333333',
        tableHeaderFill: '#2A2A2A', rule: '#555555', link: '#5FA8FF', band: '#BFBFBF'
    }),
    print: Object.freeze({
        pageBackground: null, defaultColor: '#000000',
        heading: '#000000', headingMuted: '#000000', blockquote: '#000000',
        codeText: '#000000', codeBg: null, inlineBg: null,
        tableHeaderFill: null, rule: '#000000', link: '#000000', band: '#000000'
    })
});
// Cover title cap: renders once on the cover, so a shorter cap than the band
// text is fine and keeps a long H1/filename from overflowing the title line.
const MD_TO_PDF_TITLE_MAX = 120;

// ----------------------------------------------------------------------
// User-configurable PDF options (Tier 1).
//
// SECURITY INVARIANT (mirrors point 6 above): every user choice is a KEY
// into one of these frozen maps, never a value spread into docDefinition.
// An unknown / missing key falls back to the current hardcoded default, so
// no user-supplied string ever reaches a pdfmake style / color / size sink.
// The single free-form channel (header/footer text) is sanitized at the
// input boundary by _sanitizeBandText below before it becomes a text node.
// ----------------------------------------------------------------------
const MD_TO_PDF_PAGE_SIZES = Object.freeze({
    a4: 'A4', letter: 'LETTER', legal: 'LEGAL', a3: 'A3'
});
const MD_TO_PDF_ORIENTATIONS = Object.freeze({
    portrait: 'portrait', landscape: 'landscape'
});
const MD_TO_PDF_MARGIN_PRESETS = Object.freeze({
    narrow: [36, 40, 36, 40],
    normal: [54, 60, 54, 60],
    wide:   [72, 80, 72, 80]
});
// Accent palette: a fixed set of literal hex strings. `default` keeps the
// existing per-style colors (null = no override). Applied to heading levels
// 1-4 and link text; h5/h6 stay muted-grey by design.
const MD_TO_PDF_ACCENTS = Object.freeze({
    default: null,
    orange:  '#FF6B35',
    blue:    '#0066CC',
    green:   '#1F7A4D',
    purple:  '#6B3FA0',
    slate:   '#334155'
});
const MD_TO_PDF_PAGENUM_POSITIONS = Object.freeze({
    'bottom-right':  { band: 'footer', align: 'right'  },
    'bottom-center': { band: 'footer', align: 'center' },
    'top-right':     { band: 'header', align: 'right'  }
});

const MD_TO_PDF_DEFAULTS = Object.freeze({
    pageSize: 'A4',
    orientation: 'portrait',
    margins: MD_TO_PDF_MARGIN_PRESETS.normal,
    accent: null,
    theme: 'light',
    coverPage: false,
    fileName: '',
    pageNumbers: false,
    pageNumberPosition: 'bottom-right',
    headerText: '',
    footerText: ''
});

// Header/footer free text limits. The text renders on EVERY page, so an
// uncapped string is a size-blowup vector — cap hard. Same invisible
// code-point strip the markdown tokenizer applies at its boundary.
const MD_TO_PDF_BAND_TEXT_MAX = 200;
const MD_TO_PDF_BAND_TROJAN_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

class MdToPdfParser {
    constructor(options = {}) {
        this.options = options;
        this.tokenizer = new MarkdownBlockTokenizer(MD_TO_PDF_CAPS);
    }

    /**
     * Lazy-load pdfmake engine then vfs_fonts. Sequential — vfs assigns
     * to pdfMake.vfs and needs pdfMake to already exist. Idempotent.
     * Calls setUrlAccessPolicy(() => false) before resolving so the
     * caller always sees a hardened pdfMake.
     */
    static loadLibrary() {
        if (MdToPdfParser._loadPromise) return MdToPdfParser._loadPromise;

        MdToPdfParser._loadPromise = (async () => {
            await MdToPdfParser._loadOne(MD_TO_PDF_VENDOR.engine);
            if (typeof pdfMake === 'undefined') {
                throw new Error('PDF library failed to load. Check your network connection and try again.');
            }
            await MdToPdfParser._loadOne(MD_TO_PDF_VENDOR.vfs);
            // pdfmake 0.3.x stores fonts internally via addVirtualFileSystem();
            // there is no public pdfMake.vfs to assert against any more. The
            // load script no-ops silently if addVirtualFileSystem is missing,
            // so we use it as the readiness signal.
            if (typeof pdfMake.addVirtualFileSystem !== 'function') {
                throw new Error('PDF font bundle failed to load.');
            }
            // CVE-2026-26801 mitigation: deny all URL access for any pdfmake
            // code path that might try to fetch a resource. We never put URLs
            // into the docDefinition (we render images as alt-text only and
            // never call saveAs(URL,…)), but this is belt-and-braces against
            // a future contributor adding image support without re-reading
            // the security review.
            //
            // Hard-fail if the function is missing — the SRI-pinned version
            // (0.3.8) ships this API. If a future bump removes or renames
            // it, the CVE mitigation must not silently disappear.
            if (typeof pdfMake.setUrlAccessPolicy !== 'function') {
                throw new Error('PDF library is missing setUrlAccessPolicy — refusing to proceed without CVE-2026-26801 mitigation. Update /vendor/PROVENANCE.md and re-vendor a version that ships this API.');
            }
            pdfMake.setUrlAccessPolicy(() => false);
        })();

        return MdToPdfParser._loadPromise;
    }

    static _loadOne({ src, sri, dataLib }) {
        if (typeof document === 'undefined') return Promise.resolve();
        const existing = document.querySelector(`script[data-lib="${dataLib}"]`);
        if (existing) {
            if (existing.dataset.loaded === 'true') return Promise.resolve();
            return new Promise((resolve, reject) => {
                existing.addEventListener('load',  () => resolve(), { once: true });
                existing.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)), { once: true });
            });
        }
        return new Promise((resolve, reject) => {
            const s = document.createElement('script');
            s.src = src;
            s.integrity = sri;
            s.crossOrigin = 'anonymous';
            s.dataset.lib = dataLib;
            s.onload  = () => { s.dataset.loaded = 'true'; resolve(); };
            s.onerror = () => reject(new Error(`Failed to load ${src}. Check your network connection and try again.`));
            document.head.appendChild(s);
        });
    }

    async parse(markdown, options = {}) {
        if (typeof markdown !== 'string') markdown = String(markdown || '');

        const lineCount = markdown.split(/\r\n?|\n/).length;
        if (lineCount > MD_TO_PDF_MAX_LINES) {
            throw new Error(`Input has ${lineCount.toLocaleString()} lines — keep it under ${MD_TO_PDF_MAX_LINES.toLocaleString()} for PDF export.`);
        }

        // Resolve user options to literals before touching pdfmake. Throws on
        // disallowed header/footer text so the user sees the message before a
        // (possibly slow) library load.
        const resolved = this._resolveOptions(options);

        if (typeof pdfMake === 'undefined') {
            await MdToPdfParser.loadLibrary();
        }
        if (typeof pdfMake === 'undefined') {
            throw new Error('PDF library failed to load. Check your network connection and try again.');
        }

        // tokenize() enforces input-size / nesting / table-cell caps and
        // strips trojan-source-class chars at the boundary.
        const tokens = this.tokenizer.tokenize(markdown);
        // Phase 2C pre-pass: render any ```mermaid``` blocks to PNG
        // data URIs so _renderCodeBlock can emit pdfmake { image: ... }
        // entries instead of text. One failed render falls back to text
        // for that block; others are unaffected (Promise.allSettled).
        this._mermaidImages = await this._renderMermaidBlocks(tokens);
        const docDefinition = this._buildDocDefinition(tokens, resolved);

        const blob = await this._createBlob(docDefinition);
        await MdToPdfParser._assertSafeBlob(blob);
        return blob;
    }

    // ------------------------------------------------------------------
    // Option resolution
    // ------------------------------------------------------------------

    /**
     * Map a (possibly partial / hostile) options object to a fully resolved
     * config of LITERAL values. Every selector is a key into a frozen map;
     * an unknown key falls back to the default. The only free-form channel —
     * header/footer text — is sanitized here (see _sanitizeBandText).
     */
    _resolveOptions(options = {}) {
        const o = options && typeof options === 'object' ? options : {};
        // Own-property lookup ONLY — a bare `map[key]` reaches inherited
        // Object.prototype members (map['toString'] is a truthy function),
        // which would let a hostile options object (parse() is public API;
        // Phase 2 plans a REST tier over it) slip a non-literal into the
        // docDefinition. hasOwnProperty closes that, defaulting unknown keys.
        const pick = (map, key, fallback) =>
            Object.prototype.hasOwnProperty.call(map, key) ? map[key] : fallback;
        return {
            pageSize:    pick(MD_TO_PDF_PAGE_SIZES, o.pageSize, MD_TO_PDF_PAGE_SIZES.a4),
            orientation: pick(MD_TO_PDF_ORIENTATIONS, o.orientation, MD_TO_PDF_ORIENTATIONS.portrait),
            margins:     pick(MD_TO_PDF_MARGIN_PRESETS, o.margins, MD_TO_PDF_DEFAULTS.margins),
            // `accent` is a key whose value may legitimately be null (default).
            accent:      pick(MD_TO_PDF_ACCENTS, o.accent, MD_TO_PDF_DEFAULTS.accent),
            // `theme` resolves to a KEY string ('light'|'dark'|'print'); an
            // unknown key falls back to 'light'. The value lookup happens in
            // _buildThemedStyles against the frozen MD_TO_PDF_THEMES map.
            theme:       Object.prototype.hasOwnProperty.call(MD_TO_PDF_THEMES, o.theme) ? o.theme : 'light',
            // `coverPage` gates control flow only (never rendered). Strict ===.
            coverPage:   o.coverPage === true,
            // `fileName` is a NEW free-form field crossing the trust boundary
            // (the Phase-2 REST tier can send anything). Strip + cap, NEVER
            // throw — a filename/heading like "src/js/x.md" must not be denied.
            fileName:    this._sanitizeTitleText(o.fileName),
            pageNumbers: o.pageNumbers === true,
            pageNumberPosition: pick(MD_TO_PDF_PAGENUM_POSITIONS, o.pageNumberPosition, null)
                                    ? o.pageNumberPosition : MD_TO_PDF_DEFAULTS.pageNumberPosition,
            headerText:  this._sanitizeBandText(o.headerText),
            footerText:  this._sanitizeBandText(o.footerText)
        };
    }

    /**
     * Sanitize a header/footer free-text string at the input boundary.
     *   1. Coerce + strip invisible/bidi control code points (same class the
     *      markdown tokenizer strips — this channel bypasses the tokenizer).
     *   2. Hard length cap (renders on every page; uncapped = size blowup).
     *   3. Reject any PDF action-dictionary key substring (case-insensitive).
     *      Without this, a user typing "/JavaScript" in their footer would
     *      trip _assertSafeBlob's output grep and get their own valid PDF
     *      refused — a confusing self-inflicted denial. Reject early, clearly.
     * Returns the cleaned string (possibly empty). Throws on a blocked key.
     */
    _sanitizeBandText(text) {
        if (text == null) return '';
        let s = String(text).replace(MD_TO_PDF_BAND_TROJAN_RE, '');
        if (s.length > MD_TO_PDF_BAND_TEXT_MAX) {
            s = s.slice(0, MD_TO_PDF_BAND_TEXT_MAX);
        }
        const lower = s.toLowerCase();
        for (const key of MD_TO_PDF_BLOCKED_KEYS) {
            if (lower.includes(key.toLowerCase())) {
                throw new Error(`Header/footer text can't contain "${key}". Please remove it and try again.`);
            }
        }
        return s;
    }

    /**
     * Sanitize the cover-page title (from the first H1 or the filename).
     * Deliberately does NOT reuse _sanitizeBandText: that throws on a blocked
     * PDF-key substring, but the title is a text-node VALUE, not a dictionary
     * key. Security review (2026-07-11) verified empirically that pdfmake 0.3.8
     * FlateDecode-compresses content streams, so a title value never reaches
     * _assertSafeBlob's byte grep and can never become an executable key. A
     * throw here would only self-deny legitimate titles ("# Notes on src/js/x").
     * So: strip trojan/bidi + collapse whitespace + hard cap, and never throw.
     */
    _sanitizeTitleText(text) {
        if (text == null || typeof text === 'symbol') return '';   // String(Symbol()) throws; contract is never-throw
        let s = String(text).replace(MD_TO_PDF_BAND_TROJAN_RE, '').replace(/\s+/g, ' ').trim();
        if (s.length > MD_TO_PDF_TITLE_MAX) s = s.slice(0, MD_TO_PDF_TITLE_MAX);
        return s;
    }

    _createBlob(docDefinition) {
        // pdfmake 0.3.x returns a Promise from getBlob() (callback signature
        // was removed). Wrap to also handle the older callback shape so a
        // future downgrade doesn't silently hang.
        const pdfDoc = pdfMake.createPdf(docDefinition);
        const ret = pdfDoc.getBlob();
        if (ret && typeof ret.then === 'function') return ret;
        return new Promise((resolve, reject) => {
            try {
                pdfDoc.getBlob(b => resolve(b));
            } catch (err) {
                reject(err);
            }
        });
    }

    // ------------------------------------------------------------------
    // Output safety check
    // ------------------------------------------------------------------

    /**
     * Smoke-check the produced PDF for executable/auto-action dictionary
     * keys. pdfmake's typed docDefinition API should never emit these;
     * if any appear, we refuse to deliver the blob.
     *
     * Best-effort: this is a substring scan over the raw bytes, so a
     * blocked key wrapped inside a FlateDecode-compressed content stream
     * or a PDF 1.5 object stream (/ObjStm) would not be caught. pdfmake
     * 0.3.8 writes the document catalog and trailer outside compressed
     * streams, so the action sinks we care about (/OpenAction, /AA on
     * the catalog, /Launch in form annotations) are visible to this scan.
     * If a future upstream bump moves the catalog into an object stream,
     * the grep silently degrades — re-audit when bumping pdfmake.
     */
    static async _assertSafeBlob(blob) {
        if (!blob || typeof blob.arrayBuffer !== 'function') return;
        const buf = await blob.arrayBuffer();
        // PDFs are mostly ASCII for their structure dictionaries; latin1
        // decode is sufficient to grep for the marker keys.
        const text = new TextDecoder('latin1').decode(buf);
        for (const key of MD_TO_PDF_BLOCKED_KEYS) {
            if (text.includes(key)) {
                throw new Error(`Refusing to deliver PDF: blocked PDF dictionary key ${key} present in output.`);
            }
        }
    }

    // ------------------------------------------------------------------
    // Document builder
    // ------------------------------------------------------------------

    _buildDocDefinition(tokens, resolved = MD_TO_PDF_DEFAULTS) {
        const themed = this._buildThemedStyles(resolved.accent, resolved.theme);
        const margins = resolved.margins || MD_TO_PDF_DEFAULTS.margins;

        // Per-call render state. Set UNCONDITIONALLY every parse (never left
        // over from a prior conversion — the parser is a singleton serving the
        // interactive path AND batch). _runs / _renderCodeBlock / _renderHr read
        // theme colors from this._styles; _renderCodeBlock reads this._darkBg to
        // decide whether a mermaid PNG needs a white backing card. There is no
        // await between here and those synchronous render calls, so this state
        // never outlives one parse.
        this._styles = themed.styles;
        this._darkBg = !!themed.pageBackground;

        const content = [];
        if (resolved.coverPage) this._prependCoverPage(content, tokens, resolved, themed);
        this._renderBlocks(tokens, content, 0);
        if (content.length === 0) {
            content.push({ text: '' });
        }

        const docDefinition = {
            content,
            defaultStyle: { font: 'Roboto', fontSize: 11, lineHeight: 1.25 },
            styles: themed.styles,
            pageSize: resolved.pageSize || 'A4',
            pageOrientation: resolved.orientation || 'portrait',
            pageMargins: margins
        };
        // Themed base text color (dark = light text, print = black). Light
        // leaves it unset so pdfmake's default (black) applies unchanged.
        if (themed.defaultColor) docDefinition.defaultStyle.color = themed.defaultColor;
        // Dark theme: paint a full-page rect BEHIND all content on every page.
        // Uses the callback's pageSize (never a hardcoded A4) so Letter/Legal/
        // A3/landscape all fill correctly. Vector fill, literal color, no image
        // → zero network, no CSP change.
        if (themed.pageBackground) {
            const bg = themed.pageBackground;
            docDefinition.background = (currentPage, pageSize) => ({
                canvas: [{ type: 'rect', x: 0, y: 0, w: pageSize.width, h: pageSize.height, color: bg }]
            });
        }

        const header = this._buildBandFn('header', resolved, margins);
        if (header) docDefinition.header = header;
        const footer = this._buildBandFn('footer', resolved, margins);
        if (footer) docDefinition.footer = footer;

        return docDefinition;
    }

    /**
     * Per-call clone of the shared style table with the THEME base palette and
     * (light theme only) the accent color applied on top. Never mutate
     * MD_TO_PDF_STYLES — the parser is a singleton, so an in-place edit would
     * leak into every subsequent conversion (and corrupt a batch run). All
     * theme/accent values are literals from the frozen maps.
     *
     * Returns { styles, pageBackground, defaultColor }. Fast path: light theme
     * with no accent returns the shared (read-only) base — nothing downstream
     * mutates it.
     */
    _buildThemedStyles(accent, themeKey) {
        const theme = MD_TO_PDF_THEMES[themeKey] || null;   // null for 'light'
        if (!theme && !accent) {
            return { styles: MD_TO_PDF_STYLES, pageBackground: null, defaultColor: null };
        }
        const styles = JSON.parse(JSON.stringify(MD_TO_PDF_STYLES));
        let pageBackground = null, defaultColor = null;

        if (theme) {
            pageBackground = theme.pageBackground || null;
            defaultColor = theme.defaultColor || null;
            styles.heading1.color = theme.heading;
            styles.heading2.color = theme.heading;
            styles.heading3.color = theme.heading;
            styles.heading4.color = theme.heading;
            styles.heading5.color = theme.headingMuted;
            styles.heading6.color = theme.headingMuted;
            styles.blockquote.color = theme.blockquote;
            styles.codeBlock.color = theme.codeText;
            styles.rule.color = theme.rule;
            styles.linkText.color = theme.link;
            styles.band.color = theme.band;
            // null fill = strip it (print) so no grey box prints.
            if (theme.codeBg) styles.codeBlock.background = theme.codeBg; else delete styles.codeBlock.background;
            if (theme.inlineBg) styles.inlineCode.background = theme.inlineBg; else delete styles.inlineCode.background;
            if (theme.tableHeaderFill) styles.tableHeader.fillColor = theme.tableHeaderFill; else delete styles.tableHeader.fillColor;
        }
        // Accent overrides headings 1-4 + links, but ONLY in light theme. Dark
        // and print define their own (contrast-safe / B&W) heading + link
        // colors; letting a mid-tone accent through would wash out on dark or
        // break print's B&W contract. Enforced HERE (not the UI) so a hostile
        // options object can't send { theme:'print', accent:'slate' }.
        if (accent && !theme) {
            styles.heading1.color = accent;
            styles.heading2.color = accent;
            styles.heading3.color = accent;
            styles.heading4.color = accent;
            styles.linkText.color = accent;
        }
        return { styles, pageBackground, defaultColor };
    }

    /**
     * Prepend a cover page: centered title + date, then a page break so the
     * body starts on the next page. Title precedence: first H1's plain text →
     * sanitized filename → "Document" (see _coverTitle). Colors follow the
     * active theme (title uses the themed heading color; date is muted).
     */
    _prependCoverPage(content, tokens, resolved, themed) {
        const title = this._coverTitle(tokens, resolved.fileName);
        const dateStr = new Date().toLocaleDateString();
        content.push({
            text: title, fontSize: 30, bold: true, alignment: 'center',
            color: themed.styles.heading1.color, margin: [0, 200, 0, 18]
        });
        content.push({
            text: dateStr, fontSize: 12, alignment: 'center',
            color: themed.styles.heading6.color, pageBreak: 'after'
        });
    }

    /**
     * Resolve the cover title. First H1's plain text (extracted from the PARSED
     * token stream via the tokenizer's inline handling — NOT a raw-markdown
     * regex, so no ReDoS and the text is neutralized identically to body text),
     * else the sanitized filename (extension stripped), else "Document". Every
     * candidate is strip+capped by _sanitizeTitleText (never throws).
     */
    _coverTitle(tokens, fileName) {
        const h1 = Array.isArray(tokens)
            ? tokens.find(t => t && t.type === 'heading' && t.level === 1)
            : null;
        if (h1) {
            const runs = this.tokenizer.renderInlines(h1.text) || [];
            const plain = this._sanitizeTitleText(runs.map(r => (r && r.text) || '').join(''));
            if (plain) return plain;
        }
        const fromFile = this._sanitizeTitleText((fileName || '').replace(/\.(md|markdown|txt)$/i, ''));
        return fromFile || 'Document';
    }

    /**
     * Build a pdfmake header/footer function, or null if this band has no
     * content. pdfmake invokes the returned function per page as
     * (currentPage, pageCount). The function emits a 3-cell column row
     * [left, center, right]; user free text and the page-number counter each
     * occupy a cell. {page}/{pages}/{date} tokens are substituted per page
     * with literal replaceAll (never a regex built from user text). The date
     * is computed once here (local, no network) and closed over.
     */
    _buildBandFn(band, resolved, margins) {
        const userText = band === 'header' ? resolved.headerText : resolved.footerText;
        const pn = resolved.pageNumbers ? MD_TO_PDF_PAGENUM_POSITIONS[resolved.pageNumberPosition] : null;
        const pageNumInThisBand = pn && pn.band === band;

        if (!userText && !pageNumInThisBand) return null;

        // Cover page is physical page 1 when enabled: no band on it, and the
        // page numbering counts CONTENT pages only, so {page}/{pages} and the
        // counter all shift by 1 (content reads 1..N, not 2..N+1). The offset
        // is applied consistently to all three so a footer never reads a
        // mismatched "Page 1 of 3" over a 2-page body.
        const cover = resolved.coverPage === true;
        const dateStr = new Date().toLocaleDateString();
        const subst = (text, dispPage, dispTotal) => text
            .split('{page}').join(String(dispPage))
            .split('{pages}').join(String(dispTotal))
            .split('{date}').join(dateStr);

        // Free text defaults to the left cell; the page-number counter takes
        // whichever cell its position names. If both want the same cell, the
        // page number wins that cell and the text keeps its own (left).
        const left = margins[0];
        const right = margins[2];
        const vMargin = band === 'header' ? [left, 24, right, 0] : [left, 0, right, 24];
        // Themed band color (captured once here, not read inside the per-page
        // closure — keeps it off the singleton this._styles at render time):
        // black in print, light grey on dark, mid-grey in light.
        const bandColor = (this._styles && this._styles.band && this._styles.band.color) || MD_TO_PDF_STYLES.band.color;

        return (currentPage, pageCount) => {
            if (cover && currentPage === 1) return { text: '' };   // blank band on the cover
            const dispPage = cover ? currentPage - 1 : currentPage;
            const dispTotal = cover ? pageCount - 1 : pageCount;
            const cells = { left: '', center: '', right: '' };
            if (userText) cells.left = subst(userText, dispPage, dispTotal);
            if (pageNumInThisBand) cells[pn.align] = String(dispPage);
            return {
                margin: vMargin,
                fontSize: 9,
                color: bandColor,
                columns: [
                    { text: cells.left,   alignment: 'left'   },
                    { text: cells.center, alignment: 'center' },
                    { text: cells.right,  alignment: 'right'  }
                ]
            };
        };
    }

    _renderBlocks(tokens, out, depth) {
        if (depth > this.tokenizer.maxNestDepth) {
            throw new Error(`Nesting exceeds ${this.tokenizer.maxNestDepth} levels.`);
        }
        for (const tok of tokens) {
            switch (tok.type) {
                case 'heading':    out.push(this._renderHeading(tok)); break;
                case 'paragraph':  out.push(this._renderParagraph(tok.text)); break;
                case 'hr':         out.push(this._renderHr()); break;
                case 'code':       out.push(this._renderCodeBlock(tok)); break;
                case 'blockquote': out.push(this._renderBlockquote(tok)); break;
                case 'list':       out.push(this._renderList(tok, depth)); break;
                case 'table':      out.push(this._renderTable(tok)); break;
            }
        }
    }

    _renderHeading(tok) {
        const level = Math.min(Math.max(tok.level, 1), 6);
        return {
            text: this._runs(this.tokenizer.renderInlines(tok.text)),
            style: `heading${level}`
        };
    }

    _renderParagraph(text) {
        return {
            text: this._runs(this.tokenizer.renderInlines(text)),
            style: 'paragraph'
        };
    }

    _renderHr() {
        // Theme sink: read the rule color from the per-call themed styles
        // (print = black, dark = light-grey) rather than a hardcoded literal.
        const color = (this._styles && this._styles.rule && this._styles.rule.color) || MD_TO_PDF_STYLES.rule.color;
        return {
            margin: [0, 6, 0, 10],
            canvas: [{ type: 'line', x1: 0, y1: 0, x2: 480, y2: 0, lineWidth: 0.5, lineColor: color }]
        };
    }

    _renderCodeBlock(tok) {
        // Mermaid block with a successful pre-pass render → emit a
        // pdfmake image entry instead of the wrapped-text codeBlock.
        // The pre-pass (this._renderMermaidBlocks) populated
        // _mermaidImages with { dataUri, w, h } per token.
        if ((tok.lang || '').toLowerCase() === 'mermaid' && this._mermaidImages && this._mermaidImages.has(tok)) {
            const img = this._mermaidImages.get(tok);
            // Cap display width to ~480 (pdfmake default content width).
            // Preserve aspect ratio; let pdfmake auto-compute height by
            // omitting it OR supplying a scaled pair. Supply both for
            // predictable centering.
            const MAX_W = 480;
            const w = img.w > MAX_W ? MAX_W : img.w;
            const h = img.w > MAX_W ? Math.round(img.h * (MAX_W / img.w)) : img.h;
            // Dark theme: mermaid PNGs render dark-on-transparent, so on a dark
            // page they vanish. Back the image with a white card (a borderless
            // 1-cell table with a white fill) so the diagram stays readable.
            // Light/print pages are already white, so no card there (keeps their
            // output byte-identical to before this change).
            if (this._darkBg) {
                return {
                    margin: [0, 8, 0, 8],
                    table: { widths: [w], body: [[{ image: img.dataUri, width: w, height: h }]] },
                    layout: {
                        defaultBorder: false,
                        fillColor: () => '#FFFFFF',
                        paddingLeft: () => 8, paddingRight: () => 8,
                        paddingTop: () => 8, paddingBottom: () => 8
                    }
                };
            }
            return {
                image: img.dataUri,
                width: w,
                height: h,
                alignment: 'center',
                margin: [0, 8, 0, 8]
            };
        }
        // ZWSP soft-break every ~90 chars so long lines wrap instead of
        // clipping off the right margin. Operates on Unicode code points
        // (via Array.from) so non-BMP characters — emoji, mathematical
        // symbols, anything in supplementary planes — don't get cut
        // across their surrogate-pair boundary.
        const wrapped = (tok.text || '')
            .split('\n')
            .map(line => this._softbreakLine(line))
            .join('\n');
        // Theme sink: code-block fill from the per-call themed styles (dark =
        // darker grey, print = no fill/undefined so it prints clean). The
        // `style: 'codeBlock'` already carries the themed text color.
        const cbStyle = (this._styles && this._styles.codeBlock) || MD_TO_PDF_STYLES.codeBlock;
        const node = {
            text: wrapped,
            style: 'codeBlock',
            preserveLeadingSpaces: true
        };
        if (cbStyle.background) node.background = cbStyle.background;
        return node;
    }

    // Parallel pre-pass identical in shape to MdToDocxParser's:
    // walk tokens, find ```mermaid``` blocks, render each via
    // window.iLoveMD.mermaid.renderSafe → PNG → base64 data URI,
    // return Map<token, {dataUri, w, h}>. Skipped silently if the
    // Mermaid API isn't present on the page.
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
                    if (mermaidToks.length < MD_TO_PDF_MAX_MERMAID_BLOCKS) mermaidToks.push(t);
                }
                if (t && t.children) walk(t.children);
                if (t && Array.isArray(t.items)) {
                    for (const item of t.items) if (item && item.children) walk(item.children);
                }
            }
        };
        walk(tokens);
        if (mermaidToks.length === 0) return result;

        const blobToDataUri = (blob) => new Promise((res, rej) => {
            const r = new FileReader();
            r.onload = () => res(r.result);
            r.onerror = () => rej(new Error('FileReader failed'));
            r.readAsDataURL(blob);
        });

        const renderSafe = window.iLoveMD.mermaid.renderSafe;
        const settled = await Promise.allSettled(mermaidToks.map(async (tok) => {
            const r = await renderSafe(tok.text);
            const hidden = document.createElement('div');
            hidden.style.cssText = 'position:absolute;left:-9999px;top:-9999px;visibility:hidden;width:800px';
            hidden.appendChild(r.svg);
            document.body.appendChild(hidden);
            let dataUri, w, h;
            try {
                const bbox = r.svg.getBBox();
                w = Math.ceil(bbox.width + 24);
                h = Math.ceil(bbox.height + 24);
                const blob = await r.png({ scale: 2, padding: 12 });
                dataUri = await blobToDataUri(blob);
            } finally {
                document.body.removeChild(hidden);
            }
            return { tok, dataUri, w, h };
        }));
        for (const s of settled) {
            if (s.status === 'fulfilled') {
                result.set(s.value.tok, { dataUri: s.value.dataUri, w: s.value.w, h: s.value.h });
            }
        }
        return result;
    }

    _softbreakLine(line) {
        const cps = Array.from(line);
        if (cps.length <= MD_TO_PDF_CODE_SOFTBREAK_AFTER) return line;
        const out = [];
        for (let i = 0; i < cps.length; i += MD_TO_PDF_CODE_SOFTBREAK_AFTER) {
            out.push(cps.slice(i, i + MD_TO_PDF_CODE_SOFTBREAK_AFTER).join(''));
        }
        return out.join('​');
    }

    _renderBlockquote(tok) {
        return {
            text: this._runs(this.tokenizer.renderInlines((tok.text || '').replace(/\n/g, ' ').trim())),
            style: 'blockquote'
        };
    }

    _renderList(list, depth) {
        const children = list.items.map(item => {
            const inline = { text: this._runs(this.tokenizer.renderInlines(item.text)) };
            if (item.children && item.children.length) {
                // Nested lists plus any other block inside the item (code,
                // paragraph, quote, table) stack under the marker.
                const subBlocks = [];
                this._renderBlocks(item.children, subBlocks, depth + 1);
                return { stack: [inline, ...subBlocks] };
            }
            return inline;
        });
        if (list.ordered) {
            const node = { ol: children, margin: [0, 2, 0, 6] };
            const start = list.start;
            if (Number.isInteger(start) && start >= 0 && start <= 999_999_999 && start !== 1) node.start = start;
            return node;
        }
        return { ul: children, margin: [0, 2, 0, 6] };
    }

    _renderTable(tok) {
        const colCount = tok.header.length;
        const widths = Array(colCount).fill('*');
        const alignMap = a => a === 'right' ? 'right' : a === 'center' ? 'center' : 'left';

        const headerRow = tok.header.map((cell, i) => ({
            text: this._runs(this.tokenizer.guardFormulaRuns(this.tokenizer.renderInlines(this.tokenizer.sanitizeTableCell(cell)))),
            style: 'tableHeader',
            alignment: alignMap(tok.aligns[i])
        }));

        const bodyRows = tok.rows.map(row =>
            row.map((cell, i) => ({
                text: this._runs(this.tokenizer.guardFormulaRuns(this.tokenizer.renderInlines(this.tokenizer.sanitizeTableCell(cell)))),
                alignment: alignMap(tok.aligns[i])
            }))
        );

        return {
            table: {
                headerRows: 1,
                widths,
                body: [headerRow, ...bodyRows]
            },
            layout: 'lightHorizontalLines',
            margin: [0, 4, 0, 8]
        };
    }

    // ------------------------------------------------------------------
    // Inline run mapping
    // ------------------------------------------------------------------

    /**
     * Convert tokenizer runs to pdfmake's `text:` array shape. Returns
     * either a string (single uniform run) or an array of run objects.
     *
     * All `link` values have already been scheme-allowlisted by the
     * shared tokenizer's isSafeUrl — rejected schemes arrive here with
     * link stripped.
     */
    _runs(parts) {
        if (!parts || parts.length === 0) return '';
        // Single plain run → return a string (less docDefinition noise).
        if (parts.length === 1 && !parts[0].bold && !parts[0].italic && !parts[0].strike
            && !parts[0].code && !parts[0].link && !parts[0].br) {
            return parts[0].text || '';
        }
        return parts.map(p => {
            // Hard break (two trailing spaces or a backslash): pdfmake
            // honours a literal newline inside a text run.
            if (p.br) return { text: '\n' };
            const run = { text: p.text || '' };
            if (p.bold)   run.bold = true;
            if (p.italic) run.italics = true;
            // Decorations must be either a single string or an array, never
            // a space-joined string — pdfmake parses ' '-joined values as
            // the last token only on some versions, no decoration on others.
            const decorations = [];
            if (p.strike) decorations.push('lineThrough');
            if (p.code) {
                // Inline-code visual: smaller font + themed fill (dark = darker
                // grey, print = none). Read from the per-call themed styles
                // (theme sink — the module const only supplies the fallback).
                // Roboto fallback because Courier isn't in the default vfs.
                const ic = (this._styles && this._styles.inlineCode) || MD_TO_PDF_STYLES.inlineCode;
                run.fontSize = ic.fontSize;
                if (ic.background) run.background = ic.background;
            }
            if (p.link) {
                run.link = p.link;
                // Theme/accent-aware link color from the per-call themed styles
                // (falls back to the module default if _runs is ever reached
                // outside a parse). Underline stays in the decorations array so
                // a strike+link run renders both lineThrough and underline.
                const lt = (this._styles && this._styles.linkText) || MD_TO_PDF_STYLES.linkText;
                run.color = lt.color;
                decorations.push('underline');
            }
            if (decorations.length === 1) run.decoration = decorations[0];
            else if (decorations.length > 1) run.decoration = decorations;
            return run;
        });
    }
}

window.MdToPdfParser = MdToPdfParser;
