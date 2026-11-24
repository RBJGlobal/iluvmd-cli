/**
 * HTML to Markdown Parser (V2)
 * Converts HTML content into clean, faithful Markdown.
 *
 * Shared path: the /html-to-md tool feeds RAW user HTML straight in, while the
 * EPUB and Evernote converters pre-sanitize their content and then call parse()
 * for the same chapter/note body. So every hardening here (scheme allow-list,
 * href encoding, title drop, markdown escaping, control/bidi strip, table pipe
 * escaping) protects all three consumers, and must not regress any of them.
 *
 * Security model: the emitted Markdown is a RAW sink. Copy/Download hands the
 * string to the user, who pastes it into other renderers (GitHub, VS Code,
 * another site's Markdown engine) that bypass our DOMPurify. So we cannot rely
 * on the preview's sanitizer here; the string itself must be safe:
 *   - link/image URLs pass a null-proto scheme allow-list (http/https/mailto),
 *     ALL data: denied (svg can carry script), control/space stripped before
 *     sniffing so `java\tscript:` can't slip through;
 *   - surviving URLs are percent-encoded so a crafted destination can't break
 *     out of `](...)` and mint a second link; the title attribute is dropped;
 *   - text nodes are markdown-escaped (backslash for structural chars, entity
 *     for the HTML-injection class < > &) so source prose can't become live
 *     formatting or an injected `[x](javascript:...)` link on round-trip;
 *   - control/bidi (Trojan-Source) chars are stripped from the final output.
 *
 * DOMParser('text/html') is inert (no script exec, no resource loads), so the
 * old regex script/style strip was cosmetic, not a security control; it is now
 * done structurally after parse (and it no longer collapses significant
 * whitespace inside <pre>).
 */
(function () {
    'use strict';

    // Above the consumers' per-unit caps (enex/epub cap each note/chapter at
    // 4 MB before calling us) so a legitimate sub-document is never double-cut.
    var MAX_INPUT_CHARS = 30 * 1024 * 1024;

    // --- URL safety ---------------------------------------------------------
    // Null-proto so inherited names (constructor, toString) never read as allowed.
    var LINK_SCHEMES = Object.assign(Object.create(null), { http: 1, https: 1, mailto: 1 });
    var SCHEME_RE = /^([a-z][a-z0-9+.\-]*):/i;
    // Strip control + space before sniffing the scheme (defeats java\tscript:).
    var URL_CTRL_RE = /[\u0000-\u0020]+/g;
    // Chars that would let a destination break out of `[text](href)` / titles.
    var HREF_UNSAFE_RE = /[\s()\[\]"<>]/g;

    // Trojan-Source / control-char strip for the final Markdown. Keeps \t \n \r.
    // Built from \x / \u escapes only (never literal bytes) per house rule.
    var CTRL_BIDI_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

    // Whitespace-only text nodes are insignificant when their parent is a block
    // container (space between <p>/<li>/<tr> etc.), significant inside phrasing.
    var BLOCK_PARENTS = Object.assign(Object.create(null), {
        html: 1, body: 1, div: 1, section: 1, article: 1, main: 1, header: 1,
        footer: 1, nav: 1, aside: 1, figure: 1, form: 1, fieldset: 1,
        ul: 1, ol: 1, dl: 1, table: 1, thead: 1, tbody: 1, tfoot: 1, tr: 1,
        blockquote: 1
    });

    // Return a control/bidi-stripped URL if its scheme is allowed (or it is
    // relative / an anchor), else null. The probe strip must be a SUPERSET of
    // the final CTRL_BIDI strip: otherwise a bidi/format char planted mid-scheme (e.g. java + U+200E + script:)
    // hides the scheme here, passes as "relative", then cleanMarkdown removes the
    // char and reconstitutes a live scheme. So strip CTRL_BIDI from the URL up
    // front, and strip the wider whitespace range for scheme sniffing only.
    function safeUrl(raw) {
        if (raw == null) return null;
        var s = String(raw).replace(CTRL_BIDI_RE, '');   // clean the URL itself
        var probe = s.replace(URL_CTRL_RE, '');           // + whitespace for the sniff
        var m = SCHEME_RE.exec(probe);
        if (m && !LINK_SCHEMES[m[1].toLowerCase()]) return null;
        return s;   // keeps space/tab so encodeUrl percent-encodes them
    }

    // Percent-encode the breakout-dangerous chars. `%` is not in the set, so an
    // already-encoded URL is not double-encoded (matches the enex convention).
    function encodeUrl(url) {
        return String(url).replace(HREF_UNSAFE_RE, function (c) {
            var code = c.charCodeAt(0);
            if (code < 256) return '%' + ('0' + code.toString(16).toUpperCase()).slice(-2);
            return encodeURIComponent(c);
        });
    }

    // --- Markdown escaping --------------------------------------------------
    // Prose text-node escaping. Entity-encode the HTML-injection class (& first),
    // backslash-escape structural markdown (verified honored by the vendored
    // markdown-it under our config), and neutralize line-start block markers.
    // Over-escaping is safe (renders literally); under-escaping corrupts.
    function escapeText(text) {
        text = text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
        // Escape backslash first, then the inline structural set. Note `_` is
        // escaped even intraword: markdown-it does not treat intraword `_` as
        // emphasis, so this is deliberate belt-and-suspenders over-escaping (a
        // pasted `file\_name` is harmless), not a bug to "fix" later.
        text = text.replace(/\\/g, '\\\\');
        text = text.replace(/([*_`~\[\]])/g, '\\$1');
        // Line-start constructs (m flag; up to a few leading spaces tolerated).
        // `>` is already entity-encoded, so no blockquote-marker rule is needed.
        text = text
            .replace(/^(\s*)(#{1,6})(\s|$)/gm, '$1\\$2$3')         // ATX heading
            .replace(/^(\s*)([+-])(\s)/gm, '$1\\$2$3')             // bullet - +
            .replace(/^(\s*)(\d{1,9})([.)])(\s)/gm, '$1$2\\$3$4')  // ordered list
            .replace(/^(\s{0,3})(=+|-+)(\s*)$/gm, '$1\\$2$3');     // hr / setext underline (1+)
        return text;
    }

    // Table cell: the content arrives ALREADY markdown-escaped from processNode,
    // so we must NOT re-run escapeText (that would turn `**bold**` into
    // `\*\*bold\*\*`). Only the cell-specific transforms: flatten to one physical
    // line and escape the `|` delimiter (raw `|` from a text node is left alone by
    // escapeText, so it is caught here).
    function escapeCell(text) {
        // Newlines (including the two-space hard break a <br> emits) become a
        // single space: a GFM cell is one physical line.
        return String(text).replace(/[ \t]*\r?\n+[ \t]*/g, ' ').replace(/\|/g, '\\|');
    }

    // Alt / plain-attribute text: escape brackets so a `]` can't break out of
    // ![alt](src); reuse the full prose escaper (harmless, and covers < > &).
    function escapeInlineText(text) {
        return escapeText(String(text)).replace(/\r?\n+/g, ' ');
    }

    // Smallest backtick fence that safely wraps `code` (longest run + 1, min 3).
    function backtickFence(code) {
        var runs = code.match(/`+/g);
        var max = 0;
        if (runs) for (var i = 0; i < runs.length; i++) if (runs[i].length > max) max = runs[i].length;
        var n = max + 1;
        if (n < 3) n = 3;
        var f = '';
        while (f.length < n) f += '`';
        return f;
    }

    // Inline code span with backtick-run-aware delimiter + CommonMark padding
    // when the content begins or ends with a backtick. Newlines are flattened
    // FIRST: an inline emitter must stay single-line, or a blank line inside the
    // code splits the paragraph, leaves the backticks unclosed, and lets content
    // after the gap re-parse as live Markdown (a code-span breakout). This is the
    // same single-line invariant the text-node, cell, alt, and link-text paths
    // hold; keep every inline emitter single-line.
    function inlineCode(raw) {
        raw = String(raw).replace(/\r?\n+/g, ' ');
        if (!raw) return '';
        var runs = raw.match(/`+/g);
        var max = 0;
        if (runs) for (var i = 0; i < runs.length; i++) if (runs[i].length > max) max = runs[i].length;
        var t = '';
        for (var k = 0; k <= max; k++) t += '`';
        var pad = (/^`|`$/.test(raw)) ? ' ' : '';
        return t + pad + raw + pad + t;
    }

    // Wrap inline content in a delimiter with "flanking whitespace" pulled
    // OUTSIDE the markers, so `a<b> c </b>d` -> `a **c** d` (no word-merge) and
    // an all-whitespace/empty span never emits an empty `** **`.
    function wrapDelim(content, delim) {
        // Block content (a <pre> inside <strong>, say) cannot be wrapped: the
        // delimiter would glue onto the fence opener and un-fence the code.
        // Return it as is.
        if (content.indexOf('\n') !== -1 || content.indexOf('\x00') !== -1) return content;
        var m = /^(\s*)([\s\S]*?)(\s*)$/.exec(content);
        if (!m || !m[2]) return content;
        return m[1] + delim + m[2] + delim + m[3];
    }

    class HtmlToMarkdownParser {
        constructor(options = {}) {
            this.options = {
                preserveFormatting: true,
                cleanOutput: true,
                handleTables: true,
                preserveLinks: true,
                stripEmptyElements: true,
                ...options
            };
        }

        updateOptions(options) {
            this.options = { ...this.options, ...options };
        }

        /**
         * Convert HTML to Markdown. Synchronous; NEVER throws (a pathological
         * fragment, e.g. deeply nested elements overflowing the recursion, must
         * not abort a consumer's batch: epub/enex call parse() per chapter/note).
         */
        parse(html) {
            if (!html || typeof html !== 'string') return '';
            if (html.length > MAX_INPUT_CHARS) {
                return 'This HTML is over the ' + Math.round(MAX_INPUT_CHARS / 1048576) +
                    ' MB limit for in-browser conversion.';
            }

            try {
                // Strip control/bidi at the input boundary too. Besides the
                // Trojan-Source angle, this guarantees no NUL survives into the
                // DOM, so the NUL-delimited code placeholders below cannot be
                // forged by page content (entities cannot produce NUL either:
                // the HTML parser maps &#0; to U+FFFD).
                html = html.replace(CTRL_BIDI_RE, '');
                // Per-call stash of fenced-code bodies. cleanMarkdown() tidies
                // prose (trailing spaces, blank-line runs) and must never touch
                // code, so <pre> emits a placeholder and the body is spliced
                // back in afterwards.
                this._codeStash = [];
                // DOMParser('text/html') is inert and wraps fragments in <body> for us.
                var doc = new DOMParser().parseFromString(html, 'text/html');

                // Structural removal of non-rendered content (replaces the old fragile
                // regex, and does NOT touch significant whitespace inside <pre>).
                var kill = doc.querySelectorAll('script, style, noscript, template, head');
                for (var i = 0; i < kill.length; i++) {
                    if (kill[i] && kill[i].parentNode) kill[i].parentNode.removeChild(kill[i]);
                }

                var body = doc.body || doc.documentElement;
                var md = this.processNode(body, {}).trim();
                return this.cleanMarkdown(md);
            } catch (e) {
                return '';
            }
        }

        /**
         * Process a DOM node into Markdown.
         */
        processNode(node, context) {
            if (!node) return '';
            context = context || {};

            // Text node (nodeType 3)
            if (node.nodeType === 3) {
                var raw = node.textContent || '';
                if (context.preserveWhitespace) return raw; // inside <pre>/<code>: literal
                if (/^\s*$/.test(raw)) {
                    var pt = node.parentNode && node.parentNode.tagName
                        ? node.parentNode.tagName.toLowerCase() : '';
                    return BLOCK_PARENTS[pt] ? '' : ' ';
                }
                return escapeText(raw.replace(/\s+/g, ' '));
            }

            // Element node (nodeType 1)
            if (node.nodeType === 1) {
                return this.processElement(node, context);
            }

            return '';
        }

        /**
         * Process an HTML element.
         */
        processElement(element, context) {
            var tagName = element.tagName.toLowerCase();
            var childContext = { ...context, ...this.getContextForTag(tagName) };

            var children = Array.from(element.childNodes);
            var childContent = children
                .map((child) => this.processNode(child, childContext))
                .join('');

            // Inside a <pre> code fence, inline formatting elements are literal
            // text (their text children already come through raw via
            // preserveWhitespace); don't wrap them in **/*/`/link syntax.
            if (context.inPre) {
                switch (tagName) {
                    case 'strong': case 'b': case 'em': case 'i':
                    case 'del': case 's': case 'strike': case 'a': case 'code':
                        return childContent;
                }
            }

            switch (tagName) {
                case 'h1': case 'h2': case 'h3':
                case 'h4': case 'h5': case 'h6': {
                    // Flatten any inner <br>/newline: a heading is one line.
                    var hText = this.expandCode(childContent).replace(/\r?\n+/g, ' ').trim();
                    return '\n\n' + '######'.slice(0, +tagName.charAt(1)) + ' ' + hText + '\n\n';
                }

                case 'p': {
                    var pContent = childContent.trim();
                    return pContent ? '\n\n' + pContent + '\n\n' : '';
                }

                case 'strong':
                case 'b':
                    return wrapDelim(childContent, '**');

                case 'em':
                case 'i':
                    return wrapDelim(childContent, '*');

                case 'del':
                case 's':
                case 'strike':
                    return wrapDelim(childContent, '~~');

                case 'code':
                    // Inside <pre> the parent renders the fence; here we emit a span.
                    return context.inPre ? childContent : inlineCode(element.textContent || '');

                case 'pre': {
                    if (context.inPre) return childContent; // nested <pre>: literal
                    var codeElement = element.querySelector('code');
                    var language = codeElement ? this.extractLanguage(codeElement) : '';
                    var code = childContent.replace(/^\n+|\n+$/g, '');
                    var fence = backtickFence(code);
                    var slot = this._codeStash.length;
                    this._codeStash.push(code);
                    return '\n\n' + fence + language + '\n' + '\x00' + slot + '\x00' + '\n' + fence + '\n\n';
                }

                case 'blockquote': {
                    // Two adjacent <pre> leave "fence\n\n\n\nfence" between
                    // them. Collapse only the blank runs that touch a STILL
                    // STASHED block (fence line next to its \x00N\x00 slot), so
                    // code a nested list already expanded keeps its own blank
                    // lines. Runs before the opener and after the closer.
                    var bq = childContent
                        .replace(/\n{3,}(?=(?:`{3,}|~{3,})[^\n]*\n\x00\d{1,9}\x00\n)/g, '\n\n')
                        .replace(/(\x00\d{1,9}\x00\n(?:`{3,}|~{3,}))\n{3,}/g, '$1\n\n');
                    return '\n\n' + this.expandCode(bq).trim().split('\n')
                        .map((line) => (line.trim() ? '> ' + line : '>'))
                        .join('\n') + '\n\n';
                }

                case 'ul':
                case 'ol': {
                    // Nested lists (inside an <li>) stay tight with single-newline
                    // separation; top-level lists get blank-line block boundaries.
                    var listSep = context.inListItem ? '\n' : '\n\n';
                    return listSep + this.processList(element, tagName === 'ol', childContext) + listSep;
                }

                case 'li':
                    return childContent;

                case 'a': {
                    var linkText = this.expandCode(childContent).replace(/\r?\n+/g, ' ').trim();
                    if (!this.options.preserveLinks) return linkText;
                    var href = safeUrl(element.getAttribute('href'));
                    if (href) return '[' + linkText + '](' + encodeUrl(href) + ')'; // title dropped
                    return linkText; // denied/absent href -> keep text
                }

                case 'img': {
                    var alt = element.getAttribute('alt') || '';
                    var src = safeUrl(element.getAttribute('src'));
                    if (src) return '![' + escapeInlineText(alt) + '](' + encodeUrl(src) + ')';
                    return escapeInlineText(alt); // denied/absent src -> alt as text
                }

                case 'table':
                    return this.options.handleTables
                        ? '\n\n' + this.processTable(element) + '\n\n'
                        : childContent;

                case 'hr':
                    return '\n\n---\n\n';

                case 'br':
                    return '  \n';

                case 'div':
                case 'section':
                case 'article':
                case 'main':
                case 'header':
                case 'footer':
                case 'nav':
                case 'aside':
                case 'figure':
                case 'figcaption':
                case 'dl':
                case 'dt':
                case 'dd': {
                    // Generic block containers separate their content like a
                    // paragraph would; otherwise <div>a</div><div>b</div> runs
                    // together as "ab". Inside <pre> everything stays literal.
                    if (context.inPre) return childContent;
                    var bContent = childContent.trim();
                    return bContent ? '\n\n' + bContent + '\n\n' : '';
                }

                case 'span':
                case 'body':
                case 'html':
                    return childContent;

                default:
                    return childContent;
            }
        }

        /**
         * Extract programming language from a code element's class list.
         */
        extractLanguage(codeElement) {
            var className = codeElement.className || '';
            var matches = className.match(/language-([\w+-]+)/);
            return matches ? matches[1] : '';
        }

        /**
         * Per-tag processing context.
         */
        getContextForTag(tagName) {
            switch (tagName) {
                case 'pre':
                    return { inPre: true, preserveWhitespace: true };
                case 'code':
                    return { inCode: true, preserveWhitespace: true };
                default:
                    return {};
            }
        }

        /**
         * Process ul/ol. Nested lists compound automatically: a child list is
         * emitted inside its <li> and every continuation line is indented by the
         * parent marker width, so depth accumulates through the recursion.
         */
        processList(listElement, ordered, context) {
            var start = 1;
            if (ordered) {
                var s = parseInt(listElement.getAttribute('start'), 10);
                if (!isNaN(s)) start = s;
            }

            var items = [];
            var kids = listElement.childNodes;
            for (var i = 0; i < kids.length; i++) {
                if (kids[i].nodeType === 1 && kids[i].tagName.toLowerCase() === 'li') {
                    items.push(kids[i]);
                }
            }

            var itemContext = { ...context, inListItem: true };
            var out = [];
            for (var j = 0; j < items.length; j++) {
                var marker = ordered ? (start + j) + '.' : '-';
                var content = this.expandCode(this.processNode(items[j], itemContext))
                    .replace(/^\n+/, '')   // drop leading blank lines
                    .replace(/\s+$/, '');  // and trailing whitespace
                var lines = content.split('\n');
                var indent = new Array(marker.length + 2).join(' '); // marker width + 1
                var first = lines.shift() || '';
                var rest = lines
                    .map((line) => (line.length ? indent + line : ''))
                    .join('\n');
                out.push(marker + ' ' + first + (rest ? '\n' + rest : ''));
            }
            return out.join('\n');
        }

        /**
         * Process a table into a GFM pipe table with column alignment, cell
         * pipe-escaping, and an optional caption line above it.
         */
        processTable(element) {
            var caption = element.querySelector('caption');
            var captionMd = caption
                ? this.expandCode(this.processNode(caption, {})).replace(/\r?\n+/g, ' ').trim()
                : '';

            var rows = Array.from(element.querySelectorAll('tr'));
            if (rows.length === 0) return captionMd ? captionMd + '\n' : '';

            // Build a cell matrix; remember the header row's alignment.
            var matrix = [];
            var aligns = [];
            for (var r = 0; r < rows.length; r++) {
                var cells = Array.from(rows[r].children).filter((c) => {
                    var t = c.tagName ? c.tagName.toLowerCase() : '';
                    return t === 'td' || t === 'th';
                });
                var rowCells = [];
                for (var c2 = 0; c2 < cells.length; c2++) {
                    rowCells.push(escapeCell(this.expandCode(this.processNode(cells[c2], {})).trim()) || ' ');
                    if (r === 0) aligns.push(this.cellAlign(cells[c2]));
                }
                matrix.push(rowCells);
            }

            // Column count = widest row (not just the header): guards against a
            // header-less first <tr> yielding cols=0 and a negative slice below.
            var cols = 0;
            for (var cc = 0; cc < matrix.length; cc++) {
                if (matrix[cc].length > cols) cols = matrix[cc].length;
            }
            if (cols === 0) return captionMd ? captionMd + '\n' : '';
            while (aligns.length < cols) aligns.push('');

            for (var m = 0; m < matrix.length; m++) {
                while (matrix[m].length < cols) matrix[m].push(' ');
                if (matrix[m].length > cols) {
                    // extra cells (e.g. a stray colspan) merged into the last column
                    matrix[m] = matrix[m].slice(0, cols - 1)
                        .concat([matrix[m].slice(cols - 1).join(' ')]);
                }
            }

            var lines = [];
            if (captionMd) lines.push(captionMd, '');
            lines.push('| ' + matrix[0].join(' | ') + ' |');
            lines.push('| ' + aligns.map(this.alignSep).join(' | ') + ' |');
            for (var d = 1; d < matrix.length; d++) {
                lines.push('| ' + matrix[d].join(' | ') + ' |');
            }
            return lines.join('\n') + '\n';
        }

        /**
         * Column alignment from a cell's align attribute or text-align style.
         */
        cellAlign(cell) {
            var a = (cell.getAttribute('align') || '').toLowerCase();
            if (!a) {
                var style = (cell.getAttribute('style') || '').toLowerCase();
                var mm = style.match(/text-align\s*:\s*(left|right|center)/);
                if (mm) a = mm[1];
            }
            return (a === 'left' || a === 'right' || a === 'center') ? a : '';
        }

        alignSep(a) {
            if (a === 'left') return ':---';
            if (a === 'right') return '---:';
            if (a === 'center') return ':---:';
            return '---';
        }

        /**
         * Final tidy. Prose segments: strip control/bidi (always, for safety),
         * trim trailing whitespace except a two-space hard break, drop
         * whitespace-only lines, collapse blank-line runs. Fenced code bodies
         * were stashed by the <pre> case behind NUL-delimited placeholders and
         * are spliced back untouched (control/bidi strip only), so blank lines
         * and trailing spaces inside code survive. Placeholders cannot be
         * forged: NUL is stripped from the input and the HTML parser never
         * yields it from an entity. An unknown or repeated slot is dropped.
         */
        cleanMarkdown(markdown) {
            var stash = this._codeStash || [];
            var parts = String(markdown).split(/\x00(\d{1,9})\x00/);
            var out = '';
            for (var i = 0; i < parts.length; i++) {
                if (i % 2 === 0) {
                    out += this.cleanProse(parts[i]);
                } else {
                    var slot = parseInt(parts[i], 10);
                    if (slot < stash.length && stash[slot] != null) {
                        out += stash[slot].replace(CTRL_BIDI_RE, '');
                        stash[slot] = null;
                    }
                }
            }
            return out.trim();
        }

        /**
         * Splice stashed code back into `text` where a container is about to
         * rewrite its child content line by line (blockquote prefixes, list
         * indents, table-cell flattening, heading/link flattening). Without
         * this the placeholder is one line and the code body would land
         * OUTSIDE the container after cleanMarkdown (security review
         * 2026-11-13: a <pre> in a blockquote leaked its lines as live HTML).
         * Code expanded here loses the blank-line protection, exactly as
         * before the stash existed; only top-level code keeps it.
         */
        expandCode(text) {
            var stash = this._codeStash;
            if (!stash || !stash.length || text.indexOf('\x00') === -1) return text;
            return String(text).replace(/\x00(\d{1,9})\x00/g, function (m, d) {
                var slot = parseInt(d, 10);
                if (slot < stash.length && stash[slot] != null) {
                    var code = stash[slot];
                    stash[slot] = null;
                    return code;
                }
                return '';
            });
        }

        cleanProse(text) {
            text = text.replace(CTRL_BIDI_RE, '');
            if (this.options.cleanOutput === false) return text;
            return text
                .replace(/([^ \t\n])[ \t]{2,}$/gm, '$1  ')  // 2+ trailing spaces: a hard break, keep two
                .replace(/([^ \t\n])[ \t]$/gm, '$1')        // a single trailing space is noise
                .replace(/^[ \t]+$/gm, '')
                .replace(/\n{3,}/g, '\n\n');
        }
    }

    // Pure helpers for the Node test harness (no DOM needed to exercise the
    // security/fidelity-critical string logic). Not part of the public API, and
    // NOT attached in a real browser (gated to the DOM-less test environment)
    // so nothing internal is exposed on the production window.
    if (typeof document === 'undefined') {
        HtmlToMarkdownParser.__test = {
            escapeText: escapeText,
            escapeCell: escapeCell,
            escapeInlineText: escapeInlineText,
            safeUrl: safeUrl,
            encodeUrl: encodeUrl,
            backtickFence: backtickFence,
            inlineCode: inlineCode,
            wrapDelim: wrapDelim,
            CTRL_BIDI_RE: CTRL_BIDI_RE
        };
    }

    window.HtmlToMarkdownParser = HtmlToMarkdownParser;
})();
