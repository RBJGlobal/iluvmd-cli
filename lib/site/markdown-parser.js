/**
 * Markdown -> HTML renderer (V2, rewritten 2026-07-06)
 *
 * This is the SHARED renderer for the whole app: every tool's preview, the
 * Markdown Reader, and the HTML baked into md-to-html / md-to-email / md-to-anki
 * exports. Public interface is UNCHANGED so every consumer keeps working with
 * zero churn: `new MarkdownParser()`, synchronous `parse(markdown) -> string`,
 * `window.MarkdownParser`.
 *
 * WHY THE REWRITE: the v1 engine was a sequential regex-replace pipeline whose
 * inline rules ran over the WHOLE document (including inside code blocks), and
 * which failed on GFM tables (dropped empty cells, ignored alignment, required
 * outer pipes), intraword emphasis (snake_case, a*b*c), inline code containing
 * a tag, task lists, autolinks, reference links, nested lists, and turned every
 * soft newline into <br>. Those are architectural, not patchable. V2 replaces
 * the ENGINE with vendored markdown-it (CommonMark + GFM reference quality,
 * /vendor/markdown-it/, SRI-pinned, see vendor/PROVENANCE.md) and keeps the
 * EXISTING DOMPurify sanitize call as the unchanged trust boundary. Only the
 * string PRODUCER changed; every downstream sink is identical.
 *
 * TRUST BOUNDARY (unchanged contract): parse() ALWAYS returns
 * DOMPurify.sanitize(markdownit.render(input)). The markdown-it instance is
 * PRIVATE to this module (never on window), so no sink can reach unsanitized
 * output. Two independent fail-safes: if markdown-it is missing OR DOMPurify is
 * missing, parse() HTML-entity-escapes the raw markdown and returns it (fail
 * safe to inert text, never raw HTML, never a throw).
 *
 * markdown-it config (set 2026-07-06):
 *   html:true       - a .md may contain intentional inline HTML; render it,
 *                     DOMPurify makes it safe (matches v1 behavior).
 *   linkify:true    - GFM bare-URL autolinks. markdown-it's own validateLink
 *                     blocks javascript:/vbscript:/file:/non-image data:; the
 *                     DOMPurify <a> hook is the second layer.
 *   breaks:false    - CommonMark soft breaks (fixes v1's every-\n-> <br> bug).
 *   typographer:false - faithful to source; no silent quote/dash rewriting
 *                     (also keeps user output free of injected em/en-dashes).
 *   maxNesting:20   - markdown-it default; DoS guard, kept.
 *
 * Custom rules on the singleton (all in-wrapper, no extra vendored plugins):
 *   - Mermaid fence: ```mermaid emits the byte-exact placeholder div that
 *     mermaid-parser.js's resolver swaps for a rendered PNG; every other fence
 *     delegates to markdown-it's DEFAULT fence renderer (correct escaping +
 *     language- class, and leaves a clean seam for a future highlight hook).
 *   - Table alignment -> CLASS: markdown-it emits GFM alignment as inline
 *     style="text-align:...", but our DOMPurify config FORBIDs style app-wide,
 *     which would strip alignment. We rewrite it to class="md-align-*" (CSS in
 *     styles.css / the standalone-HTML template / the email rules).
 *   - Heading anchors: a slug id="" only (deep-linkable + TOC-ready), no
 *     visible "#" link (that would leak into the baked email/anki/standalone
 *     artifacts). Security: user-derived ids enable DOM clobbering, so parse()
 *     sets DOMPurify SANITIZE_NAMED_PROPS:true, which prefixes every id/name
 *     with `user-content-`. This also closes a PRE-EXISTING gap where raw-HTML
 *     ids in a .md passed through unprefixed.
 *   - Task lists: - [ ] / - [x] -> a disabled checkbox <input> (survives the
 *     DOMPurify config; only <form> is forbidden).
 *
 * A ~1 MB input cap runs before render (the shared boundary must be as
 * protected as the md-to-email / md-to-anki bakers, which already cap).
 */
(function () {
    'use strict';

    var MAX_INPUT_CHARS = 1024 * 1024; // ~1 MB, matches the downstream bakers
    // Appended AFTER sanitizing when the input was cut at the cap. A literal
    // constant (never user text) so it is safe to concatenate into the
    // sanitized HTML. The truncation used to be silent: a 1.1 MB document
    // lost its tail mid-word with no sign in preview or download.
    var TRUNC_NOTICE = '<p class="iluvmd-truncated"><em>Output truncated: the input is larger than the 1 MB this converter handles. Split it into smaller files.</em></p>';

    // ---- lazy, private markdown-it singleton --------------------------------
    var mdInstance = null;
    var mdTried = false;

    function slugify(s) {
        // Unicode-aware: letters and digits in any script survive, so a
        // Cyrillic or CJK heading gets a real id instead of "section-N" and a
        // TOC link [x](#заголовок) still resolves.
        return String(s == null ? '' : s).trim().toLowerCase()
            .replace(/[^\p{L}\p{N}\s_-]/gu, '')   // drop punctuation (keep letters, digits, space, -, _)
            .replace(/[\s_]+/g, '-')
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '') || 'section';
    }

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function buildMd() {
        if (typeof window === 'undefined' || typeof window.markdownit === 'undefined') return null;
        var md = window.markdownit({
            html: true,
            linkify: true,
            breaks: false,
            typographer: false
            // maxNesting: 20 is the default; kept.
        });

        // --- mermaid fence (byte-exact placeholder) + default delegation -----
        var defaultFence = md.renderer.rules.fence ||
            function (tokens, idx, options, env, self) { return self.renderToken(tokens, idx, options); };
        md.renderer.rules.fence = function (tokens, idx, options, env, self) {
            var token = tokens[idx];
            var info = token.info ? token.info.trim().split(/\s+/)[0].toLowerCase() : '';
            if (info === 'mermaid') {
                var code = token.content.replace(/\n$/, '');
                var b64 = '';
                try { b64 = btoa(unescape(encodeURIComponent(code))); } catch (e) { b64 = ''; }
                return '<div class="iluvmd-mermaid-block" data-mermaid-src="' + b64 +
                    '"><pre><code class="language-mermaid">' + escapeHtml(code) + '</code></pre></div>';
            }
            return defaultFence(tokens, idx, options, env, self);
        };

        // --- table alignment: inline style -> class (style is DOMPurify-forbidden)
        function alignToClass(token) {
            if (!token.attrs) return;
            var si = token.attrIndex('style');
            if (si < 0) return;
            var m = /text-align:\s*(left|center|right)/i.exec(token.attrs[si][1] || '');
            token.attrs.splice(si, 1); // drop the style attr regardless
            if (m) token.attrJoin('class', 'md-align-' + m[1].toLowerCase());
        }
        md.renderer.rules.td_open = function (t, i, o, e, self) { alignToClass(t[i]); return self.renderToken(t, i, o); };
        md.renderer.rules.th_open = function (t, i, o, e, self) { alignToClass(t[i]); return self.renderToken(t, i, o); };

        // --- heading anchors: slug ID ONLY (linkable + TOC-ready). We do NOT
        // emit a visible clickable "#" link: it would leak as a stray "#" into
        // the baked artifacts (md-to-email / md-to-anki / standalone HTML),
        // whose contexts strip the hover-hide CSS. The id carries all the value
        // (deep-linking, future TOC). DOMPurify prefixes the id with
        // `user-content-` (SANITIZE_NAMED_PROPS) to prevent DOM clobbering.
        var defaultHeadingOpen = md.renderer.rules.heading_open ||
            function (t, i, o, e, self) { return self.renderToken(t, i, o); };
        md.renderer.rules.heading_open = function (tokens, idx, options, env, self) {
            var inline = tokens[idx + 1];
            var slug = slugify(inline && inline.content ? inline.content : '');
            env.__slugs = env.__slugs || Object.create(null);
            if (env.__slugs[slug] != null) { env.__slugs[slug] += 1; slug = slug + '-' + env.__slugs[slug]; }
            else env.__slugs[slug] = 0;
            tokens[idx].attrSet('id', slug);
            return defaultHeadingOpen(tokens, idx, options, env, self);
        };

        // --- task lists: - [ ] / - [x] -> disabled checkbox ------------------
        md.core.ruler.after('inline', 'iluvmd_task_lists', function (state) {
            var tokens = state.tokens;
            for (var i = 2; i < tokens.length; i++) {
                if (tokens[i].type !== 'inline') continue;
                if (tokens[i - 1].type !== 'paragraph_open') continue;
                if (tokens[i - 2].type !== 'list_item_open') continue;
                var inline = tokens[i];
                if (!inline.children || !inline.children.length) continue;
                var first = inline.children[0];
                if (first.type !== 'text') continue;
                var m = /^\[([ xX])\]\s+/.exec(first.content);
                if (!m) continue;
                var checked = m[1] === 'x' || m[1] === 'X';
                first.content = first.content.slice(m[0].length);
                var box = new state.Token('html_inline', '', 0);
                box.content = '<input class="task-list-checkbox" type="checkbox" disabled' +
                    (checked ? ' checked' : '') + '> ';
                inline.children.unshift(box);
                tokens[i - 2].attrJoin('class', 'task-list-item');
            }
        });

        // --- math delimiters (math-rule.js). Inert unless a render call
        // passes env.math === true, so pages that do not load the file and
        // callers that do not ask for math get the same output as before.
        if (window.iLoveMD && window.iLoveMD.mathRule &&
            typeof window.iLoveMD.mathRule.install === 'function') {
            window.iLoveMD.mathRule.install(md);
        }

        return md;
    }

    function getMd() {
        if (mdInstance) return mdInstance;
        if (mdTried) return null;
        mdTried = true;
        try { mdInstance = buildMd(); } catch (e) { mdInstance = null; }
        return mdInstance;
    }

    // ---- DOMPurify config (unchanged boundary + SANITIZE_NAMED_PROPS) -------
    var PURIFY_CONFIG = {
        USE_PROFILES: { html: true },
        ADD_ATTR: ['target'],
        // Markdown never legitimately emits these; explicit deny closes mXSS
        // vectors a future contributor could re-open (unchanged from v1).
        FORBID_TAGS: ['style', 'form', 'svg', 'math', 'iframe', 'object', 'embed'],
        FORBID_ATTR: ['style'],
        // Prefix every id/name with `user-content-` so a heading slug (or a raw
        // HTML id in a .md) can never shadow an app global via DOM clobbering.
        SANITIZE_NAMED_PROPS: true
    };

    function MarkdownParser() {}

    // options.math === true (own property) turns the math delimiters into
    // placeholders that math-resolver.js renders. Only md-to-html and the
    // reader pass it.
    MarkdownParser.prototype.parse = function (markdown, options) {
        if (markdown == null) return '';
        var wantMath = options != null && typeof options === 'object' &&
            Object.prototype.hasOwnProperty.call(options, 'math') && options.math === true;
        var text = String(markdown);
        if (!text) return '';
        var truncated = false;
        if (text.length > MAX_INPUT_CHARS) {
            // Cut at the last line break before the cap so no word or
            // construct is split in half, then say so in the output.
            var cut = text.lastIndexOf('\n', MAX_INPUT_CHARS);
            // Only honour the line break if it is near the cap: a document
            // that is one huge line (or a long table row) must not lose most
            // of its content to the cut.
            if (cut < MAX_INPUT_CHARS - 65536) cut = MAX_INPUT_CHARS;
            text = text.slice(0, cut);
            truncated = true;
        }

        var md = getMd();
        if (!md) {
            // Fail-safe: markdown-it did not load. Never render raw; escape.
            console.error('markdown-it missing; escaping output as fallback');
            return escapeHtml(text);
        }

        if (typeof DOMPurify === 'undefined') {
            // Fail-safe: sanitizer did not load. Escape rather than emit HTML.
            console.error('DOMPurify missing; escaping output as fallback');
            return escapeHtml(text);
        }

        // render + sanitize share one try/catch so ANY throw (render OR
        // sanitize) degrades to inert escaped text: parse() never throws and
        // never returns unsanitized HTML (fail-closed on both axes).
        try {
            // fresh env per render (slug de-dup, math count)
            var html = md.render(text, wantMath ? { math: true } : {});
            var safe = DOMPurify.sanitize(html, PURIFY_CONFIG);
            return truncated ? safe + TRUNC_NOTICE : safe;
        } catch (e) {
            return escapeHtml(text);
        }
    };

    // Module-level hook: force target=_blank + rel=noopener on OUTBOUND <a>
    // (clipboard / full-screen / standalone-HTML land in another origin). Skip
    // in-page anchors (href starting with #) so heading-anchor clicks navigate
    // in place instead of opening a blank tab. Guarded against double-register.
    if (typeof DOMPurify !== 'undefined' && !DOMPurify.__iluvmdHookInstalled) {
        DOMPurify.addHook('afterSanitizeAttributes', function (node) {
            if (node.tagName === 'A') {
                var href = node.getAttribute('href') || '';
                if (href.charAt(0) === '#') {
                    // In-page fragment link: keep it in place (no target/rel).
                    // SANITIZE_NAMED_PROPS prefixes every heading id to
                    // `user-content-*`, so a user's TOC link [x](#x) must be
                    // prefixed to match, or it would navigate nowhere (this
                    // bakes into the exported standalone HTML too). Skip a bare
                    // "#" and anything already prefixed.
                    if (href.length > 1 && href.lastIndexOf('#user-content-', 0) !== 0) {
                        // markdown-it percent-encodes non-ASCII in hrefs
                        // (#caf%C3%A9) while heading ids keep the characters
                        // (café); decode so the two match. Malformed escapes
                        // stay as typed.
                        var frag = href.slice(1);
                        try {
                            var dec = decodeURIComponent(frag);
                            // Accept the decoded form only if it is a plain
                            // slug (letters, digits, - _), so decoding can
                            // never reintroduce characters DOMPurify already
                            // vetted the encoded form for.
                            if (/^[\p{L}\p{N}_-]+$/u.test(dec)) frag = dec;
                        } catch (e) { /* keep raw */ }
                        node.setAttribute('href', '#user-content-' + frag);
                    }
                    return;
                }
                node.setAttribute('target', '_blank');
                node.setAttribute('rel', 'noopener noreferrer');
            }
        });
        DOMPurify.__iluvmdHookInstalled = true;
    }

    window.MarkdownParser = MarkdownParser;
})();
