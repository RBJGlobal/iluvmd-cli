/**
 * Markdown → Plain Text Parser (V2)
 * Strips all Markdown formatting and returns clean, copy-pasteable plain text.
 * Designed for pasting into Slack, email bodies, embedding pipelines, ChatGPT
 * inputs, and any other context that doesn't render Markdown.
 *
 * V2 architecture: renders plain text from the markdown-it TOKEN STREAM (the
 * same vendored engine the preview uses, loaded on every page since the
 * MD→HTML V2). One grammar, two renderers: what the preview shows as a
 * heading, this tool emits as a heading. The token walk structurally removes
 * the whole v1 sequential-regex bug class (code-block content mutated by later
 * rules, intraword `_` mangling, autolink URLs eaten by the tag strip).
 *
 * The markdown-it instance here is PRIVATE and BARE (no custom rules): the
 * shared renderer's mermaid/task-list/anchor rules are HTML concerns and one
 * of them injects synthetic html_inline tokens that would leak markup into
 * text output.
 *
 * Security model: output is plain text into text-only sinks — the preview is
 * `pre.textContent` (NEVER innerHTML / mdParser.parse — that is a contract:
 * entity decoding is correct plain-text semantics ONLY because the output is
 * never rendered as HTML in-app), copy is writeText, download is text/plain.
 *   - html_block/html_inline tokens carry RAW attacker HTML: text is extracted
 *     via inert DOMParser (no browsing context: scripts never execute) with
 *     script/style/noscript/template removed first — never emitted verbatim,
 *     never regex-stripped.
 *   - Control/bidi (Trojan-Source) chars are stripped from the final output
 *     (regex built from \u escapes only, never literal bytes).
 *   - 1 MB input cap (matches the shared renderer); the legacy regex path is
 *     kept ONLY as a no-markdown-it failsafe, frozen, with its quadratic
 *     table-separator regex fixed and entity decoding removed.
 */
(function () {
    'use strict';

    var MAX_INPUT_CHARS = 1024 * 1024;              // matches markdown-parser.js
    var MAX_OUTPUT_CHARS = 4 * MAX_INPUT_CHARS;     // amplification budget: deep
    // lazy-continuation blockquotes repeat the "> " prefix per line per depth
    // (measured 91x on a hostile 1MB doc) — cap output before normalization.
    var MAX_UNDERLINE = 80;            // setext underline length cap

    // Trojan-Source / control strip (keeps \t \n \r). \u-escapes only.
    var CTRL_BIDI_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

    // --- private, bare markdown-it singleton (lazy) --------------------------
    var md = null, mdTried = false;
    function getMd() {
        if (!mdTried) {
            mdTried = true;
            if (typeof window !== 'undefined' && typeof window.markdownit === 'function') {
                try {
                    md = window.markdownit({ html: true, linkify: true, breaks: false, typographer: false });
                } catch (e) { md = null; }
            }
        }
        return md;
    }

    // html_block / html_inline content is RAW user HTML. Extract text through
    // an inert DOMParser document (scripts never execute, nothing loads);
    // script/style/noscript/template are removed so their source never leaks
    // into the text; <br>/<p>/<div> boundaries become newlines.
    function htmlToText(html) {
        try {
            var doc = new DOMParser().parseFromString(String(html), 'text/html');
            var kill = doc.querySelectorAll('script, style, noscript, template');
            for (var i = 0; i < kill.length; i++) {
                if (kill[i].parentNode) kill[i].parentNode.removeChild(kill[i]);
            }
            var brs = doc.querySelectorAll('br');
            for (var j = 0; j < brs.length; j++) {
                brs[j].parentNode.replaceChild(doc.createTextNode('\n'), brs[j]);
            }
            var blocks = doc.querySelectorAll('p, div, li, tr, h1, h2, h3, h4, h5, h6');
            for (var k = 0; k < blocks.length; k++) {
                blocks[k].appendChild(doc.createTextNode('\n'));
            }
            return doc.body ? doc.body.textContent : '';
        } catch (e) {
            return ''; // no DOM (or hostile parse failure): drop, never emit raw
        }
    }

    // Compare a link label to its href ignoring scheme/mailto/trailing slash,
    // so autolinks and linkified bare URLs emit ONCE, not "x.com (http://x.com)".
    function normUrl(s) {
        return String(s).replace(/^https?:\/\//i, '').replace(/^mailto:/i, '').replace(/\/+$/, '');
    }
    function linkText(label, href) {
        label = label.trim();
        if (!href) return label;
        if (href.charAt(0) === '#') return label;          // in-page anchor: label only
        var shownHref = href.replace(/^mailto:/i, '');
        if (!label) return shownHref;
        // Equivalent label/href (autolinks, linkified bare URLs): keep the
        // LABEL — it is what the author typed (www.x.com, not http://www.x.com).
        if (normUrl(label) === normUrl(href)) return label;
        return label + ' (' + shownHref + ')';
    }

    function repeatChar(ch, n) {
        if (n > MAX_UNDERLINE) n = MAX_UNDERLINE;
        var s = '';
        while (s.length < n) s += ch;
        return s;
    }

    // Prefix every line (empty lines get the bare marker, "> " -> ">").
    function prefixLines(text, prefix) {
        var bare = prefix.replace(/\s+$/, '');
        return text.split('\n').map(function (l) { return l ? prefix + l : bare; }).join('\n');
    }

    function indentLines(text, spaces) {
        var pad = repeatChar(' ', spaces);
        return text.split('\n').map(function (l, i) { return (i === 0 || !l) ? l : pad + l; }).join('\n');
    }

    class MarkdownToTextParser {
        parse(markdown) {
            if (!markdown) return '';
            var text = String(markdown);
            if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
            if (text.length > MAX_INPUT_CHARS) text = text.slice(0, MAX_INPUT_CHARS);

            var out;
            var engine = getMd();
            if (engine) {
                try {
                    var tokens = engine.parse(this.stripFrontmatter(text), {});
                    out = this.renderBlocks(tokens, 0, tokens.length).join('\n\n');
                } catch (e) {
                    out = this.fallbackParse(text);
                }
            } else {
                out = this.fallbackParse(text);
            }
            if (out.length > MAX_OUTPUT_CHARS) out = out.slice(0, MAX_OUTPUT_CHARS);

            // Final normalization: strip control/bidi (both paths), trim line
            // trailing whitespace, collapse 3+ newlines, trim.
            out = out.replace(CTRL_BIDI_RE, '');
            out = out.split('\n').map(function (l) { return l.replace(/[ \t]+$/, ''); }).join('\n');
            out = out.replace(/\n{3,}/g, '\n\n');
            return out.trim();
        }

        // YAML frontmatter is metadata, not content; without this pre-pass the
        // engine renders it as hr + accidental setext headings. The negative
        // lookahead rejects a blank line right after the opening --- : real
        // frontmatter never starts blank, while a document that OPENS with a
        // decorative horizontal rule usually does — without the guard, a doc
        // shaped "---\n\nIntro\n\n---\n\nBody" silently lost the Intro.
        stripFrontmatter(text) {
            if (text.lastIndexOf('---\n', 0) !== 0 && text.lastIndexOf('---\r\n', 0) !== 0) return text;
            var m = /^---\r?\n(?![ \t]*\r?\n)[\s\S]*?\r?\n(?:---|\.\.\.)[ \t]*(?:\r?\n|$)/.exec(text);
            return m ? text.slice(m[0].length) : text;
        }

        // Find the *_close matching tokens[i] (an *_open) at the same level.
        matchClose(tokens, i) {
            var closeType = tokens[i].type.replace('_open', '_close');
            var level = tokens[i].level;
            for (var j = i + 1; j < tokens.length; j++) {
                if (tokens[j].type === closeType && tokens[j].level === level) return j;
            }
            return tokens.length - 1;
        }

        // Walk block-level tokens in [from, to); return an array of block strings.
        renderBlocks(tokens, from, to) {
            var out = [];
            var i = from;
            while (i < to) {
                var t = tokens[i];
                switch (t.type) {
                    case 'paragraph_open': {
                        var pc = this.matchClose(tokens, i);
                        var ptxt = this.inlineBetween(tokens, i, pc);
                        if (ptxt) out.push(ptxt);
                        i = pc + 1; break;
                    }
                    case 'heading_open': {
                        var hc = this.matchClose(tokens, i);
                        var htxt = this.inlineBetween(tokens, i, hc).replace(/\s*\n\s*/g, ' ').trim();
                        if (htxt) {
                            if (t.tag === 'h1') out.push(htxt + '\n' + repeatChar('=', htxt.length));
                            else if (t.tag === 'h2') out.push(htxt + '\n' + repeatChar('-', htxt.length));
                            else out.push(htxt);
                        }
                        i = hc + 1; break;
                    }
                    case 'fence':
                    case 'code_block': {
                        // Code survives VERBATIM (the core v1 fix). Info string dropped.
                        var code = t.content.replace(/\n+$/, '');
                        if (code) out.push(code);
                        i++; break;
                    }
                    case 'blockquote_open': {
                        var bc = this.matchClose(tokens, i);
                        var inner = this.renderBlocks(tokens, i + 1, bc).join('\n\n');
                        if (inner) out.push(prefixLines(inner, '> '));
                        i = bc + 1; break;
                    }
                    case 'bullet_list_open':
                    case 'ordered_list_open': {
                        var lc = this.matchClose(tokens, i);
                        var listTxt = this.renderList(tokens, i, lc);
                        if (listTxt) out.push(listTxt);
                        i = lc + 1; break;
                    }
                    case 'table_open': {
                        var tc = this.matchClose(tokens, i);
                        var tbl = this.renderTable(tokens, i, tc);
                        if (tbl) out.push(tbl);
                        i = tc + 1; break;
                    }
                    case 'html_block': {
                        var htext = htmlToText(t.content).replace(/\n{3,}/g, '\n\n').trim();
                        if (htext) out.push(htext);
                        i++; break;
                    }
                    case 'hr':
                        i++; break; // blank separation stands in for the rule
                    case 'inline': {
                        // Shouldn't appear at block level, but never drop content.
                        var itxt = this.renderInline(t.children || []);
                        if (itxt) out.push(itxt);
                        i++; break;
                    }
                    default:
                        i++;
                }
            }
            return out;
        }

        // Concatenate the inline tokens strictly between an open/close pair.
        inlineBetween(tokens, openIdx, closeIdx) {
            var s = '';
            for (var k = openIdx + 1; k < closeIdx; k++) {
                if (tokens[k].type === 'inline') s += this.renderInline(tokens[k].children || []);
            }
            return s;
        }

        renderInline(children) {
            var out = '';
            var linkStack = [];
            for (var i = 0; i < children.length; i++) {
                var tok = children[i];
                switch (tok.type) {
                    case 'text':
                        out += tok.content; break;
                    case 'code_inline':
                        // single-line invariant: inline emitters never carry \n
                        out += tok.content.replace(/\r?\n+/g, ' '); break;
                    case 'softbreak':
                    case 'hardbreak':
                        out += '\n'; break;
                    case 'link_open':
                        linkStack.push({ href: tok.attrGet ? (tok.attrGet('href') || '') : '', start: out.length });
                        break;
                    case 'link_close': {
                        var l = linkStack.pop();
                        if (l) {
                            var label = out.slice(l.start);
                            out = out.slice(0, l.start) + linkText(label, l.href);
                        }
                        break;
                    }
                    case 'image': {
                        // alt text only; empty-alt images vanish
                        var alt = tok.children && tok.children.length
                            ? this.renderInline(tok.children) : (tok.content || '');
                        out += alt;
                        break;
                    }
                    case 'html_inline':
                        // <br> is a hard line break — the single most common
                        // inline HTML in real markdown. Everything else flattens
                        // (an inline fragment is not a block boundary).
                        if (/^<br[\s/>]/i.test(tok.content) || /^<br$/i.test(tok.content)) {
                            out += '\n';
                        } else {
                            out += htmlToText(tok.content).replace(/\r?\n+/g, ' ');
                        }
                        break;
                    default:
                        // em/strong/s open+close and anything unknown: markers drop,
                        // any carried content is kept.
                        if (tok.content && tok.type.indexOf('_open') === -1 &&
                            tok.type.indexOf('_close') === -1) {
                            out += tok.content;
                        }
                }
            }
            return out;
        }

        renderList(tokens, openIdx, closeIdx) {
            var t = tokens[openIdx];
            var ordered = t.type === 'ordered_list_open';
            var start = 1;
            if (ordered && t.attrGet) {
                var s = parseInt(t.attrGet('start'), 10);
                if (!isNaN(s)) start = s;
            }
            var items = [];
            var n = 0;
            var j = openIdx + 1;
            while (j < closeIdx) {
                if (tokens[j].type === 'list_item_open' && tokens[j].level === t.level + 1) {
                    var ic = this.matchClose(tokens, j);
                    var innerBlocks = this.renderBlocks(tokens, j + 1, ic);
                    // Tight lists (hidden paragraphs) read better single-spaced.
                    var inner = innerBlocks.join('\n');
                    var marker = ordered ? (start + n) + '. ' : '• ';
                    // Task list: markdown-it (no plugin) leaves "[ ] " / "[x] "
                    // as literal text at the start — promote it to the marker.
                    // Unordered only: "1. [x] step" keeps its number (GitHub
                    // renders numbered checkboxes; the number is content).
                    if (!ordered) {
                        var tm = /^\[( |x|X)\](?:\s+|$)/.exec(inner);
                        if (tm) {
                            marker = tm[1] === ' ' ? '[ ] ' : '[x] ';
                            inner = inner.slice(tm[0].length);
                        }
                    }
                    items.push(marker + indentLines(inner, marker.length));
                    n++;
                    j = ic + 1;
                } else {
                    j++;
                }
            }
            return items.join('\n');
        }

        renderTable(tokens, openIdx, closeIdx) {
            var rows = [];
            var cells = null;
            for (var j = openIdx + 1; j < closeIdx; j++) {
                var tk = tokens[j];
                if (tk.type === 'tr_open') cells = [];
                else if (tk.type === 'tr_close') { if (cells) rows.push(cells.join(' | ')); cells = null; }
                else if ((tk.type === 'th_open' || tk.type === 'td_open') && cells) {
                    // cell content is the next inline token (may be absent = empty)
                    var cell = '';
                    if (tokens[j + 1] && tokens[j + 1].type === 'inline') {
                        cell = this.renderInline(tokens[j + 1].children || [])
                            .replace(/\s*\n\s*/g, ' ').trim();
                    }
                    cells.push(cell); // empty cells preserved
                }
            }
            return rows.join('\n');
        }

        // ------------------------------------------------------------------
        // FAILSAFE ONLY (window.markdownit absent). Frozen v1 regex body: do
        // not extend. Changes from v1: quadratic table-separator regex made
        // linear; entity decoding REMOVED (its &amp;-first order re-armed
        // author-escaped tags: &amp;lt;script&amp;gt; ended up as <script>).
        // ------------------------------------------------------------------
        fallbackParse(markdown) {
            let text = markdown;
            text = text.replace(/```[\w]*\n?([\s\S]*?)```/g, (_, code) => code.trimEnd());
            text = text.replace(/`([^`]+)`/g, '$1');
            text = text.replace(/!\[([^\]]*)\]\([^)]*\)/g, (_, alt) => alt || '');
            text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, url) => {
                if (label === url) return url;
                return `${label} (${url})`;
            });
            text = text.replace(/^[ \t]*\[[^\]]+\]:[ \t]*\S+.*$/gm, '');
            text = text.replace(/^#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$/gm, '$1');
            text = text.replace(/^(.+)\n=+[ \t]*$/gm, '$1');
            text = text.replace(/^(.+)\n-{3,}[ \t]*$/gm, '$1');
            text = text.replace(/^[ \t]*[-*_]{3,}[ \t]*$/gm, '');
            text = text.replace(/^>[ \t]?/gm, '');
            text = text.replace(/^([ \t]*)[-*+][ \t]+/gm, '$1• ');
            text = text.replace(/\*\*\*([^*]+)\*\*\*/g, '$1');
            text = text.replace(/___([^_]+)___/g, '$1');
            text = text.replace(/\*\*([^*]+)\*\*/g, '$1');
            text = text.replace(/__([^_]+)__/g, '$1');
            text = text.replace(/\*([^*]+)\*/g, '$1');
            text = text.replace(/_([^_]+)_/g, '$1');
            text = text.replace(/~~([^~]+)~~/g, '$1');
            // Table separator rows: single quantified class (linear, no
            // overlapping-quantifier backtracking), dash requirement in code.
            text = text.replace(/^[ \t]*[|\-: \t]+$/gm, (line) =>
                line.indexOf('-') !== -1 ? '' : line);
            text = text.replace(/^[ \t]*\|(.+)\|[ \t]*$/gm, (_, row) => {
                return row.split('|').map(c => c.trim()).filter(Boolean).join('\t');
            });
            text = text.replace(/<[^>]+>/g, '');
            text = text.replace(/\n{3,}/g, '\n\n');
            return text;
        }
    }

    window.MarkdownToTextParser = MarkdownToTextParser;
})();
