/**
 * DOCX → Markdown adapter (V2.1).
 *
 * V1 wrapped mammoth's DEPRECATED markdown writer: no tables (dropped
 * outright), no markdown escaping of document text, and hyperlink rel targets
 * emitted verbatim into the raw .md (a crafted docx could plant a live
 * javascript: link, Copy/Download bypasses DOMPurify).
 *
 * V2 routes mammoth's FIRST-CLASS output through the shared hardened pipeline:
 *   mammoth.convertToHtml  →  HtmlToMarkdownParser
 * DOCX becomes the fourth consumer of html-to-md (with the direct tool, EPUB,
 * and Evernote), inheriting its entire standard: GFM tables WITH alignment +
 * escaped cells, markdown-escaped text (a doc containing "[x](javascript:…)"
 * as literal text stays literal), link scheme allowlist + href percent-encode
 * + title drop, dynamic code fences, CTRL/BIDI strip, output cap.
 *
 * V2.1 adds two features, both STRICTLY ADDITIVE and gated (a docx with no
 * notes and no core.xml metadata is byte-identical to V2):
 *  - Metadata frontmatter: docProps/core.xml (title/author/created) becomes a
 *    YAML frontmatter block. JSZip is lazy-loaded (mammoth exposes no arbitrary
 *    zip-part API) and runs in PARALLEL with the mammoth call; a metadata
 *    failure is swallowed (never fatal to the body conversion).
 *  - Native footnotes/endnotes: mammoth already converts notes (inline refs +
 *    a trailing numbered list), but the "#footnote-N" anchors are dead links in
 *    plain .md. We rewrite them to Pandoc [^label] / [^label]: syntax that real
 *    renderers auto-link, by transforming mammoth's HTML (unambiguous id/href
 *    structure) BEFORE it reaches html-to-md, not the markdown (where a note
 *    list is indistinguishable from a user's own numbered list).
 *
 * Security decisions (pre-impl review, V2 + V2.1):
 * - Images: alt-text only via a convertImage handler that never calls
 *   el.read(), no base64 data: URIs are even generated (they would be denied
 *   downstream anyway; svg-in-data: can carry script). Matches epub/enex.
 * - includeEmbeddedStyleMap: false, attacker-embedded style maps are free
 *   attack surface; only our own conservative map below is honored.
 * - 50 MB input gate here on COMPRESSED bytes; fronts BOTH mammoth and the
 *   JSZip metadata read. Covers the batch path automatically.
 * - Metadata is a NEW raw sink (YAML at the top of the .md). Values are
 *   attacker-controlled (core.xml). The grammar to be safe against is YAML, not
 *   Markdown: emit each as a double-quoted flow scalar with \r\n\t collapsed
 *   (kills the structural-breakout vector), CTRL/BIDI stripped, length-capped,
 *   and \\ then " escaped (yamlScalar). Do NOT entity-encode (that is the
 *   Markdown-body rule; it would corrupt "A & B" semantically). Empty fields
 *   are omitted; an all-empty block is suppressed entirely.
 * - core.xml is parsed with the xlsx XXE guard (DOCTYPE reject + application/xml
 *   + parsererror bail; browser DOMParser resolves no EXTERNAL entities, the
 *   DOCTYPE reject kills INTERNAL entity-expansion DoS). Only the fixed part
 *   docProps/core.xml is read; no relationship Target is ever followed.
 * - JSZip: same-origin vendored + SRI, injected <script> keeps script-src 'self'.
 * - Footnote transform: only the WRAPPER (ref sup + list scaffolding) is
 *   rewritten; note CONTENT still flows through html-to-md and stays escaped.
 *   Refs become PUA sentinels in the HTML (html-to-md would escape a literal
 *   [^x]) and are swapped to [^label] AFTER conversion. Labels are derived from
 *   the numeric docx id (never user text) and prefixed by note type (fn/en) so
 *   footnote-2 and endnote-2 can't collide.
 * - No convertToMarkdown fallback: silently downgrading to the unescaped,
 *   table-less writer would be a security regression wearing a reliability
 *   costume. If the shared parser is missing, the deploy is broken: fail loud.
 *
 * Style map: Word BUILT-IN style names only (near-zero false positives;
 * non-English docs simply no-op to plain paragraphs, the safe failure mode).
 */
(function () {
    'use strict';

    // Vendored JSZip (identical asset + SRI as xlsx/epub/pptx; keep in lockstep).
    var JSZIP_SRC = '/vendor/jszip/jszip-3.10.1.min.js';
    var JSZIP_SRI = 'sha384-+mbV2IY1Zk/X1p/nWllGySJSUN8uMs+gUAN10Or95UBH0fpj6GfKgPmgC5EXieXG';
    var DOCTYPE_RE = /<!DOCTYPE/i;
    // control + bidi (Trojan-Source) strip, xlsx superset (incl U+061C, LRM/RLM).
    // NB: intentionally omits \x09/\x0A/\x0D; the separate \r\n\t collapse in
    // yamlScalar is what removes the YAML newline-injection vector.
    var CTRL_BIDI_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
    var MAX_META_CHARS = 512;                 // per metadata value
    var MAX_CORE_XML_BYTES = 1024 * 1024;     // core.xml is normally < 4 KB
    var MSG_NO_TEXT = 'This Word document has no readable text.';

    // User-safe notice (userMessage === true): app.js shows it in the preview
    // and never downloads it as the .md (an empty string used to download
    // an empty file).
    function userErr(msg) { var e = new Error(msg); e.userMessage = true; return e; }
    var DC_NS = 'http://purl.org/dc/elements/1.1/';
    var DCTERMS_NS = 'http://purl.org/dc/terms/';
    // Private-Use-Area sentinels: survive html-to-md untouched (verified), so a
    // footnote ref can be marked in the HTML and swapped to [^label] after the
    // conversion escapes the surrounding text.
    var FN_START = '\uE000', FN_END = '\uE001';

    // ---- JSZip loader (lazy, injected <script> + SRI, stays script-src 'self') -
    var jszipPromise = null;
    function loadJSZip() {
        if (jszipPromise) return jszipPromise;
        if (typeof window.JSZip !== 'undefined') {
            jszipPromise = Promise.resolve(window.JSZip);
            return jszipPromise;
        }
        jszipPromise = new Promise(function (resolve, reject) {
            var s = document.createElement('script');
            s.src = JSZIP_SRC;
            s.integrity = JSZIP_SRI;
            s.crossOrigin = 'anonymous';
            s.onload = function () {
                if (typeof window.JSZip === 'undefined') { reject(new Error('JSZip undefined after load')); return; }
                resolve(window.JSZip);
            };
            s.onerror = function () { jszipPromise = null; reject(new Error('Failed to load JSZip')); };
            document.head.appendChild(s);
        });
        return jszipPromise;
    }

    // ---- guarded XML parse (mirrors xlsx-parser.js) ---------------------------
    function parseXml(str) {
        if (str == null) return null;
        if (DOCTYPE_RE.test(str)) return null;               // kill entity-expansion DoS
        var doc;
        try { doc = new DOMParser().parseFromString(str, 'application/xml'); }
        catch (e) { return null; }
        if (!doc || doc.doctype) return null;
        if (doc.getElementsByTagName('parsererror').length) return null;
        return doc;
    }

    // ---- YAML double-quoted flow scalar (injection-proof) ---------------------
    function yamlScalar(s) {
        s = String(s == null ? '' : s)
            .replace(CTRL_BIDI_RE, '')        // strip C0/C1 + bidi (Trojan-Source)
            .replace(/[\r\n\t]+/g, ' ');       // collapse newlines -> space (kills YAML breakout)
        if (s.length > MAX_META_CHARS) s = s.slice(0, MAX_META_CHARS);
        s = s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');   // backslash FIRST, then quote
        return '"' + s + '"';
    }

    // ---- metadata: docProps/core.xml -> YAML frontmatter (best-effort) --------
    // Returns a Promise<string>: a "---\n...\n---\n\n" block, or '' (no fields /
    // no core.xml / any failure). Never throws to the caller (caught upstream).
    function extractMetadata(arrayBuffer) {
        return loadJSZip()
            .then(function (JSZip) { return JSZip.loadAsync(arrayBuffer); })
            .then(function (zip) {
                var f = zip.file('docProps/core.xml');
                if (!f) return '';
                return f.async('string').then(function (xml) {
                    if (!xml || xml.length > MAX_CORE_XML_BYTES) return '';
                    var doc = parseXml(xml);
                    if (!doc) return '';
                    var getNS = function (ns, local) {
                        var els = doc.getElementsByTagNameNS(ns, local);
                        return (els && els.length && els[0].textContent) ? els[0].textContent.trim() : '';
                    };
                    var title = getNS(DC_NS, 'title');
                    var author = getNS(DC_NS, 'creator');
                    var created = getNS(DCTERMS_NS, 'created');
                    var lines = [];
                    if (title) lines.push('title: ' + yamlScalar(title));
                    if (author) lines.push('author: ' + yamlScalar(author));
                    if (created) lines.push('date: ' + yamlScalar(created));
                    if (!lines.length) return '';
                    return '---\n' + lines.join('\n') + '\n---\n\n';
                });
            });
    }

    // ---- native footnote / endnote transform ----------------------------------
    // mammoth emits refs as <sup><sup><a href="#footnote-N" id="footnote-ref-N">
    // [k]</a></sup></sup> and definitions as <li id="footnote-N"><p>… <a
    // href="#footnote-ref-N">↑</a></p></li> (footnotes + endnotes share one <ol>).
    // Rewrite the WRAPPER only; content still flows through html-to-md.
    // Returns { bodyHtml, definitions }. Gated: no notes -> original html, no defs.
    var REF_ID_RE = /^(footnote|endnote)-ref-(\d+)$/;
    var DEF_ID_RE = /^(footnote|endnote)-(\d+)$/;
    function labelFor(type, n) { return (type === 'endnote' ? 'en' : 'fn') + n; }

    function transformNotes(html) {
        // Strip any body-planted sentinel chars up front (ALL paths, incl. the
        // no-note early return) so applyNoteSentinels downstream can only ever
        // act on sentinels WE inserted, never a spurious [^label] minted from
        // attacker document text. U+E000/E001 are private-use, no real glyph.
        html = html.replace(/[\uE000\uE001]/g, '');
        var doc;
        try { doc = new DOMParser().parseFromString('<!doctype html><body>' + html + '</body>', 'text/html'); }
        catch (e) { return { bodyHtml: html, definitions: '' }; }
        var body = doc.body;
        if (!body) return { bodyHtml: html, definitions: '' };

        // Gate: only touch the DOM if genuine note anchors are present.
        if (!body.querySelector('a[id^="footnote-ref-"], a[id^="endnote-ref-"], li[id^="footnote-"], li[id^="endnote-"]')) {
            return { bodyHtml: html, definitions: '' };
        }

        // 1) Refs -> PUA sentinel text nodes (replace the outermost <sup> wrapper).
        var refs = body.querySelectorAll('a[id^="footnote-ref-"], a[id^="endnote-ref-"]');
        Array.prototype.forEach.call(refs, function (a) {
            var m = REF_ID_RE.exec(a.id || '');
            if (!m) return;
            var node = a;
            while (node.parentNode && node.parentNode.nodeType === 1 &&
                   node.parentNode.tagName.toLowerCase() === 'sup') {
                node = node.parentNode;
            }
            if (node.parentNode) {
                node.parentNode.replaceChild(doc.createTextNode(FN_START + labelFor(m[1], m[2]) + FN_END), node);
            }
        });

        // 2) Definitions -> [^label]: content ; drop backlinks; remove the list.
        var HtmlToMd = window.HtmlToMarkdownParser;
        var defs = [];
        var parents = [];
        var lis = body.querySelectorAll('li[id^="footnote-"], li[id^="endnote-"]');
        Array.prototype.forEach.call(lis, function (li) {
            var m = DEF_ID_RE.exec(li.id || '');
            if (!m) return;
            var backs = li.querySelectorAll('a[href^="#footnote-ref-"], a[href^="#endnote-ref-"]');
            Array.prototype.forEach.call(backs, function (b) { if (b.parentNode) b.parentNode.removeChild(b); });
            // Content converted via a FRESH parser so it stays escaped by html-to-md.
            var content = HtmlToMd ? new HtmlToMd().parse(li.innerHTML).trim() : (li.textContent || '').trim();
            content = content.replace(/\n(?=[^\n])/g, '\n    '); // Pandoc 4-space continuation indent (blank lines stay blank)
            defs.push('[^' + labelFor(m[1], m[2]) + ']: ' + content);
            if (li.parentNode && parents.indexOf(li.parentNode) === -1) parents.push(li.parentNode);
            if (li.parentNode) li.parentNode.removeChild(li);
        });
        // Remove any note-list container left empty by the extraction.
        parents.forEach(function (p) {
            if (p.parentNode && !p.querySelector('li')) p.parentNode.removeChild(p);
        });

        return { bodyHtml: body.innerHTML, definitions: defs.join('\n\n') };
    }

    // Swap ref sentinels for Pandoc markers (linear, bounded; label is [a-z]+\d+).
    function applyNoteSentinels(md) {
        return md.replace(/\uE000([a-z]+\d+)\uE001/g, '[^$1]');
    }

    class DocxToMarkdownParser {
        constructor(options = {}) {
            this.options = options;
        }

        async parse(arrayBuffer) {
            if (typeof mammoth === 'undefined') {
                throw new Error('mammoth.js failed to load. Check your network connection and try again.');
            }
            if (typeof window.HtmlToMarkdownParser === 'undefined') {
                throw new Error('The HTML conversion module failed to load. Please refresh and try again.');
            }

            var MAX_INPUT_BYTES = 50 * 1024 * 1024;
            var byteLength = arrayBuffer && (arrayBuffer.byteLength != null ? arrayBuffer.byteLength : arrayBuffer.length);
            if (!byteLength) throw userErr('This .docx file is empty.');
            if (byteLength > MAX_INPUT_BYTES) {
                // Throw a user-safe Error (xlsx userErr precedent): a returned
                // sentence would be downloaded as the .md by the heavy-file flow.
                var limitErr = new Error('This .docx is over the ' + Math.round(MAX_INPUT_BYTES / 1048576) +
                    ' MB limit for in-browser conversion.');
                limitErr.userMessage = true;
                throw limitErr;
            }

            // Body conversion (mammoth) and metadata (JSZip -> core.xml) run in
            // parallel. Metadata is best-effort: a failure degrades to no
            // frontmatter, never a failed conversion.
            var pair = await Promise.all([
                mammoth.convertToHtml({ arrayBuffer }, {
                    includeDefaultStyleMap: true,
                    includeEmbeddedStyleMap: false,
                    styleMap: [
                        "p[style-name='Quote'] => blockquote > p:fresh",
                        "p[style-name='Intense Quote'] => blockquote > p:fresh",
                        "p[style-name='HTML Preformatted'] => pre",
                        "r[style-name='HTML Code'] => code",
                        "r[style-name='Code'] => code"
                    ],
                    // Alt-text only: never read image bytes, never emit a src.
                    convertImage: mammoth.images.imgElement(function (image) {
                        return Promise.resolve({ alt: (image.altText || '').trim() || 'image' });
                    })
                }),
                extractMetadata(arrayBuffer).catch(function () { return ''; })
            ]);
            var result = pair[0];
            var frontmatter = pair[1] || '';

            // mammoth surfaces non-fatal issues (unrecognized styles, dropped
            // content) on result.messages, log them for debugging but don't
            // fail the conversion. Console is device-local; nothing leaves.
            if (result.messages && result.messages.length) {
                console.debug('mammoth messages:', result.messages);
            }

            const html = (result.value || '').trim();
            if (!html) throw userErr(MSG_NO_TEXT);

            // Gated note rewrite (no notes -> bodyHtml === html, no definitions).
            const notes = transformNotes(html);

            let markdown = new window.HtmlToMarkdownParser().parse(notes.bodyHtml).trim();
            if (!markdown && !notes.definitions) {
                // Empty markdown from non-empty HTML is EITHER a legitimately-blank
                // document (mammoth emits "<p> </p>" for whitespace-only docs) OR a
                // real conversion failure. Only the latter is an error: probe the
                // ORIGINAL html for actual rendered content before throwing. Empty
                // doc -> return '' (no orphan frontmatter, keep V2 semantics). A
                // notes-only doc (empty body but extracted definitions) is NOT
                // empty, so it skips this throw and emits the definitions below.
                var probe = new DOMParser().parseFromString(html, 'text/html');
                var hasContent = (probe.body && probe.body.textContent.trim()) ||
                    probe.querySelector('table, img, hr');
                if (hasContent) {
                    throw new Error('The document could not be converted to Markdown. Please try re-saving it in Word and converting again.');
                }
                throw userErr(MSG_NO_TEXT);
            }

            // Swap ref sentinels across BOTH body and definitions: a nested note
            // ref lands a legit sentinel INSIDE a definition, which the body-only
            // swap would leak as raw PUA. Spacing guard keeps a notes-only doc
            // (empty body) from leading with a blank line.
            var combined = notes.definitions
                ? (markdown ? markdown + '\n\n' : '') + notes.definitions
                : markdown;
            return frontmatter + applyNoteSentinels(combined);
        }
    }

    window.DocxToMarkdownParser = DocxToMarkdownParser;
})();
