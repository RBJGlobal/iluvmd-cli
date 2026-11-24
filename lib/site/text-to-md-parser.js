/**
 * Text to Markdown Parser (V2, rewritten 2026-07-05)
 *
 * Converts plain text notes to Markdown. 100% client-side, zero dependency,
 * synchronous. Public interface unchanged from v1: `new TextToMarkdownParser()`,
 * `updateOptions(opts)`, `parse(text) -> string`, `window.TextToMarkdownParser`.
 *
 * ARCHITECTURE (three passes over a block model; per-parse context, no
 * instance state; v1's per-line design was the root cause of its defects):
 *   1. segment  - normalize (CRLF -> LF, CTRL/bidi strip), split ONCE into
 *                 lines, tag each with cheap lexical flags, group into raw
 *                 blocks (paragraph, quote, list, code, hr, setext, md-atx,
 *                 fence passthrough) at blank lines + structural boundaries.
 *   2. classify - document census (heading style map, wrap-column stats),
 *                 then resolve blocks: heading levels are a function of the
 *                 STYLE CLASS present in the doc (never per-line weights), so
 *                 sibling sections always share a level; multi-line paragraph
 *                 blocks try aligned-column table -> key:value table ->
 *                 paragraph, all fail-safe to passthrough.
 *   3. emit     - one emitter per block type. All escaping happens here and
 *                 only here (single-pipeline ordering: no pass ever re-scans
 *                 a prior pass's output, so escape gadgets are structurally
 *                 impossible).
 *
 * IDEMPOTENCY: a document-level Markdown gate (high-precision signals only:
 * fences, ATX headings, [t](u) links, |---| rows, **bold** pairs, backslash
 * escapes) short-circuits to normalize-only. Everything the emitters produce
 * is either a gate signal or a construct the segmenter passes through
 * natively, making parse(parse(x)) === parse(x) a tested invariant
 * (tests/run-text-to-md.js enforces it on every fixture).
 *
 * TABLE DETECTION (the differentiator): whitespace-occupancy projection over
 * consecutive plain lines. Column separators = char columns with ZERO
 * non-space occupancy across all rows (runs >= 2 wide, within the shortest
 * row). Tabs short-circuit (same tab count on every row). A dashed underline
 * row is consumed as the header signal and its dash runs are authoritative
 * boundaries. Indented blocks need the STRONG signals (tabs or dashed
 * underline) because misreading code as a table destroys code; non-indented
 * blocks fail safe to paragraph passthrough. Zero regex, O(rows x width),
 * both capped.
 *
 * SECURITY MODEL (pre-impl review 2026-07-05, architect + security):
 *   - Caps: MAX_INPUT_CHARS (truncate at a line boundary + note), analysis
 *     caps per line/block so a 10 MB single line or a 100k-line "table"
 *     degrades to passthrough, never to quadratic work.
 *   - Every regex is per-line, anchored, bounded or single-char-class linear.
 *     v1's polynomial caps-run regex is gone; caps-bolding is a word-split
 *     loop. The table/reflow algorithms are regex-free.
 *   - Autolink builds targets by construction: https?:// kept, www. gets
 *     https:// (never protocol-relative), emails get mailto:. Target chars
 *     outside a strict URL set are never captured, and ( ) [ ] < > " ` \ and
 *     whitespace are excluded from capture so a target can never break the
 *     [text](url) frame. Display text always equals the captured token.
 *   - Generated table cells: | escaped, whitespace runs collapsed, per-cell
 *     cap. Rows padded to the detected column count.
 *   - CTRL/bidi (Trojan Source) stripped at the input boundary, AFTER CRLF
 *     normalization and BEFORE any column math (offsets must match output).
 *     Regex uses \u escapes only (house rule; never literal bidi in source).
 *   - Tag-like < is ENTITY-ENCODED to &lt; on every output path, outside
 *     fenced code and code spans (house raw-sink standard: Copy/Download hand
 *     out raw text, so a .txt containing <b> or <script> must not emit live
 *     HTML for any downstream renderer). Entity form, not a backslash, so the
 *     guarantee does not depend on how a downstream engine treats escapes
 *     (the vendored markdown-it does honour backslash escapes; v1's engine
 *     did not). Bare & and non-tag < are inert and untouched.
 *     Block classification owns everything else (structure can't fire
 *     accidentally because structure is decided by the segmenter, not by
 *     downstream renderers). \| in table cells is the one backslash escape
 *     kept (the engine honors it there).
 *   - parse() snapshots options and keeps ALL state in a per-call context:
 *     a hostile document cannot poison the next parse (v1 leaked instance
 *     state and options between the interactive and batch paths).
 *
 * CONSERVATIVE DEFAULTS: never mutate content by default.
 * ALL-CAPS words are NOT bolded and _underscores_ are NOT converted unless
 * the emphasis option is explicitly enabled. ALL-CAPS headings keep their
 * case (v1's forced Title Case mangled acronyms and is gone).
 */
(function () {
    'use strict';

    // ---- caps ---------------------------------------------------------------
    var MAX_INPUT_CHARS = 25 * 1024 * 1024;  // ~25 MB; truncate + note
    var MAX_ANALYSIS_LINE = 4000;            // longer lines skip classification
    var TABLE_MAX_ROWS = 800;                // projection row cap
    var TABLE_MAX_WIDTH = 1000;              // projection column cap
    var MAX_CELL_CHARS = 32768;              // per emitted table cell
    var MAX_HEADING_LEN = 60;

    // ---- character hygiene ----------------------------------------------------
    // Control + bidi (Trojan Source) strip. \u escapes ONLY (house rule).
    // Excludes \t \n \r (handled by normalization) and ZWJ (emoji sequences).
    var CTRL_BIDI_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

    // ---- line-level patterns (all anchored, per-line, linear) ----------------
    var RULE_RE = /^(-{3,}|={3,}|\*{3,}|_{3,})\s*$/;
    var ATX_RE = /^#{1,6}\s/;
    var FENCE_RE = /^(`{3,}|~{3,})/;
    var BULLET_RE = /^([-*+•◦▪▸►○●·])\s+(\S.*)$/;
    var OBULLET_RE = /^o\s+\S/;                                  // Word-style; indented only
    var ORDERED_RE = /^(\d{1,4})[.)]\s+(\S.*)$/;
    var PAREN_NUM_RE = /^\((\d{1,4})\)\s+(\S.*)$/;
    var LETTER_RE = /^([A-Za-z])[.)]\s+(\S.*)$/;
    var ROMAN_RE = /^([ivxlc]{1,7}|[IVXLC]{1,7})[.)]\s+(\S.*)$/;
    var QUOTE_RE = /^((?:>[ ]?)+)(.*)$/;
    var KV_RE = /^([A-Za-z0-9][A-Za-z0-9 _.\/&()'-]{0,29}):[ \t]+(\S.*)$/;
    var COLON_TERM_RE = /^([A-Za-z][^:]{0,58}):$/;
    var WROTE_RE = /^On\b.{0,280}\b(wrote|said):\s*$/;
    var SIG_RE = /^--\s*$/;
    var NUM_SECTION_RE = /^(\d{1,3})\.\s+[A-Z]/;
    var ROMAN_SECTION_RE = /^([IVXLC]{1,7})\.\s+[A-Z]/;
    var SENTENCE_END_RE = /[.!?:]$/;

    // Existing markdown links: bounded, per-line (used to skip autolinking).
    var MDLINK_RE = /\[[^\]\n]{0,200}\]\([^()\n]{0,400}\)/g;
    // URL charset EXCLUDES ( ) [ ] < > " ` \ and whitespace by construction,
    // so a captured target can never break the [text](url) frame (v1 allowed
    // parens -> content spillover).
    var URL_RE = /https?:\/\/[A-Za-z0-9\-._~:/?#@!$&'*+,;=%]+/g;
    var WWW_RE = /(^|[\s(])((?:www\.)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}(?:\/[A-Za-z0-9\-._~:/?#@!$&'*+,;=%]*)?)/g;
    // Lookahead permits a trailing sentence period ("email x@y.com.") - the
    // TLD group already requires an alnum after each dot, so the period stays
    // outside the captured address.
    var EMAIL_RE = /(^|[\s(<])([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8})(?![A-Za-z0-9_-])/g;
    var TRAIL_PUNCT_RE = /[.,;:!?]+$/;
    // Tag-like < : <letter, </, <! (a .txt containing <b> is content, not markup).
    var TAG_LIKE_RE = /<(?=[A-Za-z\/!?])/g;
    // Fence opener/closer, matched the way markdown-it does: up to 3 spaces of
    // indent, 3+ backticks or tildes; a backtick fence's info string may not
    // contain a backtick; the closer uses the same character, is at least as
    // long and has nothing but whitespace after it.
    var FENCE_OPEN_RE = /^ {0,3}(`{3,}|~{3,})(.*)$/;
    var FENCE_CLOSE_RE = /^ {0,3}(`{3,}|~{3,})[ \t]*$/;
    var TASK_BLOCK_RE = /^\[[ xX]\][ \t]+(?:`{3,}|~{3,}|>|(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$))/;
    var DISPUTED_CLOSE_RE = /^(?:[ \t]*(?:`+~|~+`)[`~]*[ \t]*|[ \t]*[`~]+ *\t[ \t]*| *\t[ \t]*[`~]+[ \t]*)$/;

    var TRUNC_NOTE = '\n\n> _Input truncated: this text is larger than the in-browser converter handles. Split it into smaller files._';

    // ---- Markdown gate signals (high precision; bullets/1. are NOT signals) ---
    var GATE_ATX_RE = ATX_RE;
    var GATE_LINK_RE = /\[[^\]\n]{0,200}\]\([^()\s]{1,400}\)/;
    var GATE_TABLE_SEP_RE = /^\s*\|?[\s:|-]*-{3,}[\s:|-]*\|[\s:|-]*$/;
    var GATE_BOLD_RE = /\*\*[^*\n]{1,200}\*\*/;
    var GATE_ESCAPE_RE = /\\[#*_\[\]>|<`-]/;

    function TextToMarkdownParser(options) {
        this.options = {
            detectHeaders: true,
            detectLists: true,
            detectUrls: true,
            detectEmphasis: false,      // V2 default OFF: bolding mutates prose
            preserveBreaks: true,       // checked = keep breaks; unchecked = reflow
            detectQuotes: true,
            insertHorizontalRules: true,
            detectTables: true,         // NEW: aligned columns + key:value
        };
        if (options) this.updateOptions(options);
    }

    TextToMarkdownParser.prototype.updateOptions = function (options) {
        for (var k in options) {
            if (Object.prototype.hasOwnProperty.call(options, k)) this.options[k] = options[k];
        }
    };

    // ======================================================================
    // NORMALIZATION + GATE
    // ======================================================================

    function normalize(text) {
        // Order matters: CRLF first, then CTRL/bidi (regex excludes \t\n\r),
        // then nothing else touches offsets before classification.
        return text.replace(/\r\n?/g, '\n').replace(CTRL_BIDI_RE, '');
    }

    // High-precision "this is already Markdown" gate. When it fires, we
    // return normalize(text) untouched: converting Markdown would double it
    // (v1's `# # Real Heading` defect) and escaping it would mutate it.
    function isMarkdownDoc(lines) {
        var nonBlank = 0, atx = 0, signals = 0;
        for (var i = 0; i < lines.length; i++) {
            var t = lines[i];
            if (t.length > MAX_ANALYSIS_LINE) { nonBlank++; continue; }
            var trimmed = t.trim();
            if (!trimmed) continue;
            nonBlank++;
            if (FENCE_RE.test(trimmed)) return true;            // fence = instant gate
            var hit = false;
            if (GATE_ATX_RE.test(trimmed)) { atx++; hit = true; }
            else if (GATE_TABLE_SEP_RE.test(trimmed)) hit = true;
            else if (GATE_LINK_RE.test(trimmed)) hit = true;
            else if (GATE_BOLD_RE.test(trimmed)) hit = true;
            else if (GATE_ESCAPE_RE.test(trimmed)) hit = true;
            if (hit) signals++;
        }
        if (atx >= 2) return true;
        return nonBlank > 0 && signals / nonBlank >= 0.10;
    }

    // ======================================================================
    // PASS 1: LINE ANALYSIS + SEGMENTATION
    // ======================================================================

    function indentWidth(line) {
        var w = 0;
        for (var i = 0; i < line.length; i++) {
            var c = line.charCodeAt(i);
            if (c === 32) w++;
            else if (c === 9) w += 8 - (w % 8);
            else break;
        }
        return w;
    }

    function analyzeLine(raw) {
        var info = { raw: raw, trimmed: raw.trim() };
        info.blank = info.trimmed === '';
        if (info.blank) return info;
        info.indent = indentWidth(raw);
        info.long = raw.length > MAX_ANALYSIS_LINE;
        if (info.long) return info; // long lines: paragraph text, no analysis
        var t = info.trimmed;
        info.rule = RULE_RE.test(t) ? t[0] : null;
        info.atx = ATX_RE.test(t);
        info.fence = FENCE_RE.test(t);
        var q = QUOTE_RE.exec(t);
        if (q && !info.rule) {
            info.quoteDepth = (q[1].match(/>/g) || []).length;
            info.quoteText = q[2];
        }
        var m;
        if (!info.rule) {
            if ((m = BULLET_RE.exec(t))) info.bullet = { text: m[2] };
            else if (info.indent >= 2 && OBULLET_RE.test(t)) info.bullet = { text: t.slice(2).trim() };
            else if ((m = ORDERED_RE.exec(t))) info.ordered = { kind: 'num', val: parseInt(m[1], 10), text: m[2] };
            else if ((m = PAREN_NUM_RE.exec(t))) info.ordered = { kind: 'num', val: parseInt(m[1], 10), text: m[2] };
            else if ((m = ROMAN_RE.exec(t)) && romanVal(m[1]) > 0) info.ordered = { kind: 'roman', val: romanVal(m[1]), raw: m[1], text: m[2] };
            else if ((m = LETTER_RE.exec(t))) info.ordered = { kind: 'letter', val: letterVal(m[1]), raw: m[1], text: m[2] };
        }
        if ((m = KV_RE.exec(t))) info.kv = { key: m[1], val: m[2] };
        info.colonTerm = COLON_TERM_RE.test(t);
        info.wrote = WROTE_RE.test(t);
        info.sig = SIG_RE.test(t);
        info.indented = info.indent >= 4;
        return info;
    }

    function romanVal(s) {
        var map = { i: 1, v: 5, x: 10, l: 50, c: 100 };
        s = s.toLowerCase();
        var total = 0, prev = 0;
        for (var i = s.length - 1; i >= 0; i--) {
            var v = map[s[i]];
            if (!v) return 0;
            if (v < prev) total -= v; else { total += v; prev = v; }
        }
        return total > 0 && total <= 400 ? total : 0;
    }

    function letterVal(ch) {
        var c = ch.toLowerCase().charCodeAt(0) - 96; // a=1
        return c >= 1 && c <= 26 ? c : 1;
    }

    // Group lines into raw blocks. Block: { type, lines: [info], gap }.
    // Types here are STRUCTURAL only; paragraphs resolve further in classify.
    function segment(infos) {
        var blocks = [];
        var i = 0, gap = 0, n = infos.length;

        function push(b) { b.gap = gap; gap = 0; blocks.push(b); }

        while (i < n) {
            var inf = infos[i];
            if (inf.blank) { gap++; i++; continue; }

            // Fenced code in the input (gate usually catches these docs, but a
            // lone fence must still pass through intact).
            if (inf.fence) {
                var fence = [infos[i]]; i++;
                while (i < n) { fence.push(infos[i]); if (infos[i].fence) { i++; break; } i++; }
                push({ type: 'raw', lines: fence });
                continue;
            }

            // Existing markdown ATX heading: passthrough (idempotency layer 2).
            if (inf.atx) { push({ type: 'mdatx', lines: [inf] }); i++; continue; }

            // Standalone rule line -> hr (setext is handled from the text line).
            if (inf.rule) { push({ type: 'hr', lines: [inf] }); i++; continue; }

            // Quote block: consecutive quote-prefixed lines.
            if (inf.quoteDepth) {
                var qlines = [];
                while (i < n && !infos[i].blank && infos[i].quoteDepth) { qlines.push(infos[i]); i++; }
                push({ type: 'quote', lines: qlines });
                continue;
            }

            // Signature: "-- " line plus everything to the next blank.
            if (inf.sig) {
                var slines = [inf]; i++;
                while (i < n && !infos[i].blank) { slines.push(infos[i]); i++; }
                push({ type: 'sig', lines: slines });
                continue;
            }

            // Lone letter/roman marker guard (S2, post-impl review): "E. coli
            // is a bacterium" is prose, not list item 5. A single-letter or
            // roman marker only STARTS a list when it is the sequence start
            // (a/A/i/I, val 1) or the very next line continues the same kind.
            if (inf.ordered && (inf.ordered.kind === 'letter' || inf.ordered.kind === 'roman') &&
                inf.ordered.val !== 1 &&
                !(i + 1 < n && infos[i + 1].ordered && infos[i + 1].ordered.kind === inf.ordered.kind)) {
                inf.ordered = null; // demote to plain text; may still census as
                                    // a numbered-section heading (para path)
            }

            // List block: items + their indented continuation lines.
            if (inf.bullet || inf.ordered) {
                var litems = [];
                while (i < n && !infos[i].blank) {
                    var li = infos[i];
                    if (li.bullet || li.ordered) {
                        litems.push({ info: li, cont: [] });
                        i++;
                    } else if (litems.length && li.indent >= 2 && !li.rule && !li.atx && !li.fence) {
                        // Continuation of the previous item (defect 6 fix: this
                        // is tried BEFORE any code interpretation).
                        litems[litems.length - 1].cont.push(li);
                        i++;
                    } else break;
                }
                push({ type: 'list', items: litems, lines: [] });
                continue;
            }

            // Indented block: code candidate (may become a table in classify
            // ONLY with strong signals; may span internal blank lines).
            if (inf.indented) {
                var clines = [];
                while (i < n) {
                    if (infos[i].blank) {
                        // keep blank runs INSIDE the code block, stop at the end
                        var j = i; while (j < n && infos[j].blank) j++;
                        if (j < n && infos[j].indented) { for (; i < j; i++) clines.push(infos[i]); continue; }
                        break;
                    }
                    if (!infos[i].indented) break;
                    clines.push(infos[i]); i++;
                }
                push({ type: 'indented', lines: clines });
                continue;
            }

            // Paragraph run: consume plain lines; single line + rule = setext.
            var plines = [inf]; i++;
            if (i < n && infos[i].rule && (infos[i].rule === '=' || infos[i].rule === '-')) {
                push({ type: 'setext', lines: plines, double: infos[i].rule === '=', underlineRaw: infos[i].raw.replace(/\s+$/, '') });
                i++; // consume the underline
                continue;
            }
            while (i < n) {
                var pi = infos[i];
                if (pi.blank || pi.rule || pi.atx || pi.fence || pi.quoteDepth ||
                    pi.bullet || pi.ordered || pi.indented || pi.sig) break;
                plines.push(pi); i++;
            }
            push({ type: 'para', lines: plines });
        }
        return { blocks: blocks, trailingGap: gap };
    }

    // ======================================================================
    // PASS 2: CENSUS + CLASSIFICATION
    // ======================================================================

    function isAllCapsHeading(t) {
        if (t.length < 2 || t.length > MAX_HEADING_LEN) return false;
        if (SENTENCE_END_RE.test(t) && !/:$/.test(t)) return false;
        if (!/[A-Z]{2}/.test(t)) return false;
        if (t.split(/\s+/).length > 8) return false;
        return /^[A-Z0-9][A-Z0-9\s&.,'()\/-]*$/.test(t);
    }

    // Heading style census. A heading's level is a function of its STYLE
    // (sibling consistency by construction, defect 5 fix). Style precedence:
    var STYLE_ORDER = ['setext2', 'setext1', 'allcaps', 'numsec', 'colon'];

    function isNumSectionLine(raw) {
        return (NUM_SECTION_RE.test(raw) || ROMAN_SECTION_RE.test(raw)) &&
            raw.length <= MAX_HEADING_LEN && !/[.!?]$/.test(raw);
    }

    function headingCensus(blocks) {
        var found = {};
        var numsecCandidates = [];
        for (var i = 0; i < blocks.length; i++) {
            var b = blocks[i];
            if (b.type === 'setext') { found[b.double ? 'setext2' : 'setext1'] = true; continue; }

            // Numbered-section heading candidate ("1. Introduction"): the
            // segmenter reads decimal ones as one-item ordered lists; demoted
            // lone romans ("IV. Appendix") arrive as single-line paragraphs.
            // Candidates COMMIT only if the style occurs >= 2 times in the doc
            // (S1, post-impl review: a lone "1. Buy milk" is a list, not a
            // section heading - real numbered-section docs have several).
            if (b.type === 'list' && b.items.length === 1 && !b.items[0].cont.length) {
                var it = b.items[0].info;
                if (it.ordered && (it.indent || 0) < 2 && isNumSectionLine(it.trimmed)) {
                    numsecCandidates.push(b);
                }
                continue;
            }

            if (b.type !== 'para' || b.lines.length !== 1) continue;
            var inf = b.lines[0];
            if (inf.long || inf.indent >= 2) continue;
            var t = inf.trimmed;
            var next = nextBlockType(blocks, i);
            if (isAllCapsHeading(t)) { b.headingStyle = 'allcaps'; found.allcaps = true; continue; }
            if (isNumSectionLine(t) && /^[\dIVXLC]/.test(t)) { numsecCandidates.push(b); continue; }
            // Colon-terminal heading: no value after the colon (kv lines are
            // exempt -> defect 4 fix) and must introduce list/para/code/table
            // content. NOT a quote (the "On ... wrote:" case) (defect 1 fix).
            if (inf.colonTerm && !inf.kv && !inf.wrote &&
                (next === 'list' || next === 'para' || next === 'indented')) {
                b.headingStyle = 'colon'; found.colon = true; continue;
            }
        }
        if (numsecCandidates.length >= 2) {
            found.numsec = true;
            for (i = 0; i < numsecCandidates.length; i++) numsecCandidates[i].headingStyle = 'numsec';
        }
        // Compress the styles present to consecutive levels starting at H1.
        var level = {};
        var l = 0;
        for (var s = 0; s < STYLE_ORDER.length; s++) {
            if (found[STYLE_ORDER[s]]) level[STYLE_ORDER[s]] = Math.min(++l, 6);
        }
        return level;
    }

    function nextBlockType(blocks, i) {
        return i + 1 < blocks.length ? blocks[i + 1].type : null;
    }

    // ---- aligned-column table detection (regex-free) ----------------------

    function isDashRow(cells) {
        for (var i = 0; i < cells.length; i++) {
            var c = cells[i];
            if (!c) return false;
            for (var j = 0; j < c.length; j++) if (c[j] !== '-') return false;
        }
        return true;
    }

    function expandTabs(s) {
        if (s.indexOf('\t') === -1) return s;
        var out = '';
        for (var i = 0; i < s.length; i++) {
            if (s[i] === '\t') { do { out += ' '; } while (out.length % 8 !== 0); }
            else out += s[i];
        }
        return out;
    }

    // Try to read a block of plain lines as an aligned-column table.
    // Returns { header, rows, consumedDash } or null. Fail-safe: any doubt -> null.
    function tryAlignedTable(rawLines, requireStrong) {
        if (rawLines.length < 2 || rawLines.length > TABLE_MAX_ROWS) return null;
        var i, j;
        for (i = 0; i < rawLines.length; i++) {
            if (rawLines[i].length > MAX_ANALYSIS_LINE) return null;
        }

        // --- tab path: identical tab count on every row (strong signal) ---
        var tabCount = -1, tabsOk = true;
        for (i = 0; i < rawLines.length; i++) {
            var tc = 0;
            for (j = 0; j < rawLines[i].length; j++) if (rawLines[i][j] === '\t') tc++;
            if (i === 0) tabCount = tc;
            else if (tc !== tabCount) { tabsOk = false; break; }
        }
        if (tabsOk && tabCount >= 1) {
            var trows = rawLines.map(function (l) {
                return l.split('\t').map(function (c) { return c.trim(); });
            });
            return finishTable(trows);
        }

        // --- occupancy projection over tab-expanded lines ---
        var lines = rawLines.map(expandTabs).map(function (l) { return l.replace(/\s+$/, ''); });
        var minLen = Infinity, maxLen = 0;
        for (i = 0; i < lines.length; i++) {
            if (lines[i].length < minLen) minLen = lines[i].length;
            if (lines[i].length > maxLen) maxLen = lines[i].length;
        }
        if (minLen < 3 || maxLen > TABLE_MAX_WIDTH) return null;

        // Dashed underline row (row 1) = authoritative boundaries + header signal.
        var dashRow = -1;
        if (lines.length >= 3) {
            var d = lines[1], isDash = d.length > 0;
            for (j = 0; j < d.length; j++) if (d[j] !== '-' && d[j] !== ' ') { isDash = false; break; }
            if (isDash && d.indexOf('-') !== -1) dashRow = 1;
        }

        var boundaries = null; // array of [start, end) column gaps
        if (dashRow !== -1) {
            boundaries = [];
            var inGap = true, gs = 0;
            var dl = lines[dashRow];
            for (j = 0; j <= dl.length; j++) {
                var isSp = j === dl.length ? false : dl[j] === ' ';
                if (isSp && !inGap) { inGap = true; gs = j; }
                else if (!isSp && inGap) { if (j - gs >= 1 && gs > 0) boundaries.push([gs, j]); inGap = false; }
            }
            if (boundaries.length < 1) return null;
            // NEVER slice through content (B1, post-impl review): every
            // non-dash row must be all-space inside every boundary interval,
            // or slicing would silently DELETE the overlapping characters.
            // Any bleed -> not a table -> passthrough.
            for (i = 0; i < lines.length; i++) {
                if (i === dashRow) continue;
                var Lb = lines[i];
                for (j = 0; j < boundaries.length; j++) {
                    for (var col = boundaries[j][0]; col < boundaries[j][1] && col < Lb.length; col++) {
                        if (Lb[col] !== ' ') return null;
                    }
                }
            }
        } else {
            if (requireStrong) return null; // indented blocks need tabs or dashes
            // Zero-occupancy projection within the shortest row.
            var occ = new Array(minLen).fill(0);
            for (i = 0; i < lines.length; i++) {
                var L = lines[i];
                for (j = 0; j < minLen; j++) if (L[j] !== ' ') occ[j]++;
            }
            boundaries = [];
            var runStart = -1;
            for (j = 0; j < minLen; j++) {
                if (occ[j] === 0) { if (runStart === -1) runStart = j; }
                else if (runStart !== -1) {
                    if (j - runStart >= 2 && runStart > 0) boundaries.push([runStart, j]);
                    runStart = -1;
                }
            }
            if (boundaries.length < 1) return null;
        }

        // Slice every row at the boundaries.
        var rows = [];
        for (i = 0; i < lines.length; i++) {
            if (i === dashRow) continue;
            var L2 = lines[i], cells = [], prev = 0;
            for (j = 0; j < boundaries.length; j++) {
                cells.push(L2.slice(prev, boundaries[j][0]).trim());
                prev = boundaries[j][1];
            }
            cells.push(L2.slice(prev).trim());
            rows.push(cells);
        }
        // Confirmation: >= 2 rows x >= 2 cols (sparsity checked in finishTable
        // so the tab path is covered too).
        if (rows.length < 2 || rows[0].length < 2) return null;
        return finishTable(rows);
    }

    function finishTable(rows) {
        if (rows.length < 2 || rows[0].length < 2) return null;
        var width = rows[0].length;
        for (var i = 0; i < rows.length; i++) {
            while (rows[i].length < width) rows[i].push('');
            if (rows[i].length > width) rows[i] = rows[i].slice(0, width);
        }
        // A pure-dash second row (tab path) is a header separator: consume it.
        if (rows.length >= 3 && isDashRow(rows[1])) rows.splice(1, 1);
        // Sparsity: a mostly-empty grid is not a table (both paths).
        var emptyCells = 0, totalCells = 0;
        for (i = 0; i < rows.length; i++) {
            for (var j = 0; j < rows[i].length; j++) { totalCells++; if (!rows[i][j]) emptyCells++; }
        }
        if (emptyCells / totalCells > 0.25) return null;
        return { header: rows[0], rows: rows.slice(1) };
    }

    // key: value block -> 2-col table. All lines must be kv, >= 2 of them.
    function tryKvTable(blockLines) {
        if (blockLines.length < 2) return null;
        var pairs = [];
        for (var i = 0; i < blockLines.length; i++) {
            var inf = blockLines[i];
            if (!inf.kv) return null;
            pairs.push([inf.kv.key, inf.kv.val]);
        }
        return pairs;
    }

    // ---- reflow census ------------------------------------------------------

    function reflowCensus(blocks) {
        var lens = [];
        for (var i = 0; i < blocks.length; i++) {
            var b = blocks[i];
            if (b.type !== 'para' || b.tableData || b.kvData || b.headingStyle || b.lines.length < 2) continue;
            for (var j = 0; j < b.lines.length - 1; j++) lens.push(b.lines[j].raw.length);
        }
        if (lens.length < 3) return 0;
        var wrapCol = 0;
        for (i = 0; i < lens.length; i++) if (lens[i] > wrapCol) wrapCol = lens[i];
        if (wrapCol < 60 || wrapCol > 100) return 0;
        var near = 0;
        for (i = 0; i < lens.length; i++) if (lens[i] >= wrapCol - 15) near++;
        return near / lens.length >= 0.6 ? wrapCol : 0; // evidence gate
    }

    // ======================================================================
    // PASS 3: EMIT
    // ======================================================================

    // Neutralize a tag-like < by ENTITY-ENCODING it (house standard for raw
    // Copy/Download sinks; an entity holds in every downstream renderer,
    // whether or not it honours backslash escapes - post-impl security review
    // 2026-07-06). Entity encoding is idempotent by
    // construction: the output contains no raw tag-like <, so a re-parse has
    // nothing left to encode (no gate reliance, no \\< accumulation).
    // Deliberately narrow: bare & and non-tag < ("5 < 10") are inert in every
    // markdown/HTML context and stay untouched (prose fidelity).
    function escTagLike(s) {
        return s.replace(TAG_LIKE_RE, '&lt;');
    }

    function escCell(s) {
        if (s.length > MAX_CELL_CHARS) s = s.slice(0, MAX_CELL_CHARS);
        // \| is the one backslash escape the shared engine honors (table
        // cells); skip-if-escaped keeps it idempotent.
        s = s.replace(/\\?\|/g, function (m) { return m.length === 2 ? m : '\\|'; });
        return escTagLike(s.replace(/[\r\n\t]+/g, ' ')).trim();
    }

    function escProse(s) {
        // Tag-like < only: block classification owns structure, so the only
        // remaining accident class in prose is raw-HTML passthrough. Same-line
        // code spans keep their < (encodeTagsOutsideCode, the final guard on
        // every return path, recognises the same spans).
        return escTagLikeOutsideSpans(s);
    }

    // Code-span ranges of ONE line under same-line pairing (a backtick run
    // closed by the next run of the same length), as a flat [start, end, ...]
    // list. Returns null when the line cannot be trusted on its own:
    //   - a run is left open: any reader that joins this line to another
    //     (lazy continuation, a disputed container) would pair it across
    //     lines and shift every span after it;
    //   - a backslash sits before a backtick (it escapes only the first
    //     backtick of a run);
    //   - the line has "](" (a backtick inside a link destination belongs to
    //     the link, not to a span).
    // Linear: each run's closer comes from a right-to-left "next run of the
    // same length" table.
    function spanRanges(line) {
        if (line.indexOf('`') === -1) return [];
        if (line.indexOf('](') !== -1) return null;
        var runs = [], n = line.length, p = 0;
        while (p < n) {
            var j = line.indexOf('`', p);
            if (j === -1) break;
            if (j > 0 && line.charAt(j - 1) === '\\') return null;
            var k = j; while (k < n && line.charAt(k) === '`') k++;
            runs.push(j, k);
            p = k;
        }
        var count = runs.length / 2, next = new Array(count), last = Object.create(null), r;
        for (r = count - 1; r >= 0; r--) {
            var len = runs[2 * r + 1] - runs[2 * r];
            next[r] = last[len] === undefined ? -1 : last[len];
            last[len] = r;
        }
        var out = [];
        for (r = 0; r < count; r++) {
            if (next[r] === -1) return null;
            // A span opener glued to a word is not read the same everywhere:
            // marked takes "~`" as text and GFM autolink literals swallow a
            // backtick that follows a URL. Only whitespace, or a short run of
            // ( * _ " ' after whitespace, may come before the opening run.
            // A span may also follow an earlier accepted span through / + , -
            // ("`a`/`b`"): the word then holds no letters outside spans, so
            // no URL can be read there.
            var w = runs[2 * r], ko = out.length;
            for (;;) {
                while (w > 0 && '(*_"\''.indexOf(line.charAt(w - 1)) !== -1) w--;
                var w2 = w;
                while (w2 > 0 && '/+,-'.indexOf(line.charAt(w2 - 1)) !== -1) w2--;
                // One hop is enough (eighth pass): every span already in out
                // was accepted, so the earlier one is anchored. Walking the
                // whole chain was quadratic on a long line.
                if (ko >= 2 && w2 < w && w2 === out[ko - 1]) { w = 0; break; }
                break;
            }
            if (w > 0 && line.charAt(w - 1) !== ' ' && line.charAt(w - 1) !== '\t') return null;
            // Emphasis and link-label characters inside a multi-backtick
            // span are paired across the span by marked. (The single-backtick
            // case costs too much fidelity as a rule and is left to the
            // second-oracle work. Pipes and tildes in spans are
            // handled per run in encodePass.)
            if (runs[2 * r + 1] - runs[2 * r] > 1 && /[*_\[\]]/.test(line.slice(runs[2 * r + 1], runs[2 * next[r]]))) return null;
            out.push(runs[2 * r], runs[2 * next[r] + 1]);
            r = next[r];
        }
        return out;
    }

    // Encode tag-like < in one line, keeping the code spans in `ranges`
    // (from spanRanges; computed here when not passed). A span that contains
    // a pipe is encoded as well: a GFM table splits cells at a pipe even
    // inside a code span, which would put the span's content outside it.
    // When in doubt, encode: over-encoding renders as a literal "&lt;",
    // under-encoding would be live HTML.
    function escTagLikeOutsideSpans(line, ranges) {
        if (ranges === undefined) ranges = spanRanges(line);
        if (!ranges || !ranges.length) return escTagLike(line);
        var out = '', from = 0;
        for (var i = 0; i < ranges.length; i += 2) {
            var span = line.slice(ranges[i], ranges[i + 1]);
            out += escTagLike(line.slice(from, ranges[i])) + (span.indexOf('|') === -1 ? span : escTagLike(span));
            from = ranges[i + 1];
        }
        return out + escTagLike(line.slice(from));
    }

    // Final raw-sink guard applied to EVERY return path (gate passthrough,
    // normal emit, truncation and the catch backstop): no tag-like < may
    // leave this module outside a region CommonMark treats as code. Fenced
    // blocks are recognised exactly as markdown-it recognises them (see
    // FENCE_OPEN_RE / FENCE_CLOSE_RE); everything else is encoded. Encoding
    // is idempotent by construction (the result has no tag-like < left to
    // encode and fence detection is stable), so parse(parse(x)) === parse(x)
    // still holds. Security pre-review 2026-11-13: headings, signature blocks,
    // detector-off branches and the gate all skipped the prose encoder.
    //
    // Two passes (post-review 2026-11-14). The optimistic pass keeps < inside
    // same-line code spans. But markdown-it pairs backtick runs across the
    // lines of one paragraph, so a run left open on line N can close on line
    // N+1 and a "span" the per-line model trusted is really prose. The only
    // exact judge of paragraph boundaries is markdown-it itself: the result
    // is parsed with html:true and if ANY html_inline / html_block token
    // appears (or markdown-it is not available), the strict pass runs
    // instead, which encodes every tag-like < outside fenced code, spans
    // included. The strict result is checked the same way: where the fence
    // model and markdown-it disagree (security re-review 2026-11-14: a new
    // sibling list item closes an item fence in markdown-it), a third pass
    // encodes every tag-like < in the whole text, fences included. A literal
    // "&lt;" inside a code block is the safe direction. Every outcome has no
    // tag-like < left that the next parse would treat differently, so
    // parse(parse(x)) === parse(x) holds for all three.
    function encodeTagsOutsideCode(text) {
        if (text.indexOf('<') === -1) return text;
        var out = encodePass(text, false);
        if (!TAG_LIKE_TEST_RE.test(out) || oracleSeesNoHtml(out)) return out;
        out = encodePass(text, true);
        if (!TAG_LIKE_TEST_RE.test(out) || oracleSeesNoHtml(out)) return out;
        return escTagLike(text);
    }

    var TAG_LIKE_TEST_RE = /<(?=[A-Za-z\/!?])/;
    var _oracle = null;
    function oracleSeesNoHtml(md) {
        if (!_oracle) {
            var factory = (typeof window !== 'undefined' && window.markdownit) ||
                (typeof globalThis !== 'undefined' && globalThis.markdownit) || null;
            if (!factory) return false; // fail closed: strict pass
            try { _oracle = factory({ html: true, linkify: false, typographer: false }); } catch (e) { return false; }
        }
        // Any throw (markdown-it itself, or memory on a hostile paste) means
        // "not proven clean": the caller falls through to the stricter pass.
        // So does a shape markdown-it cannot parse in reasonable time.
        if (nestedLazyCount(md) > ORACLE_MAX_NESTED_LAZY) return false;
        try {
            var tokens = _oracle.parse(md, {});
            var stack = tokens.slice();
            while (stack.length) {
                var t = stack.pop();
                if (!t) continue;
                if (t.type === 'html_inline' || t.type === 'html_block') return false;
                var kids = t.children;
                if (kids && kids.length) {
                    // A loop, not push.apply: one paragraph can hold more
                    // children than the argument limit allows.
                    for (var k = 0; k < kids.length; k++) stack.push(kids[k]);
                }
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    // markdown-it 14.3.0 takes quadratic time on one shape: a line at quote
    // depth 2+ followed by a shallower line that is indented 4+ columns or
    // starts with a tab (256 KiB of it ran for 26 s; security re-review
    // 2026-11-14). Count those transitions; above the limit the oracle is
    // not asked and the caller takes its fail-closed path.
    var ORACLE_MAX_NESTED_LAZY = 100;
    function nestedLazyCount(text) {
        if (text.indexOf('>') === -1) return 0;
        var lines = text.split('\n'), prevQ = 0, count = 0;
        for (var i = 0; i < lines.length; i++) {
            var parts = splitContainerPrefix(lines[i]);
            if (/^[ \t]*$/.test(parts.rest)) { prevQ = parts.quotes; continue; }
            if (prevQ >= 2 && parts.quotes < prevQ && (parts.indent >= 4 || parts.rest.charAt(0) === '\t')) count++;
            prevQ = parts.quotes;
        }
        return count;
    }

    // One pass over the lines. Fenced code is kept raw; every other line is
    // encoded: all of it (strict), or outside its code spans (optimistic).
    //
    // Optimistic span trust is decided per RUN of consecutive non-blank
    // lines, not per line (security re-review 2026-11-14: markdown-it reads
    // a 4+ column lazy line after a nested quote as code where CommonMark
    // reads paragraph text, so "is this line in the same paragraph" cannot
    // be left to any one renderer). A run keeps its spans only when every
    // line in it pairs all of its backtick runs on that same line
    // (spanRanges); then no reading of the block structure can pair a
    // backtick across lines. A fence whose opener is not at columns 0-3 of
    // a plain line (list-item or 4+ column fences, which other renderers
    // may read as paragraph text) joins the run and takes its span trust
    // away. Only a blank line (spaces and tabs only) or an undisputed fence
    // ends a run.
    function encodePass(text, strict) {
        var lines = text.split('\n'), out = [], fence = null, prevBlank = true;
        var items = [], itemQuotes = 0;   // content columns of the open list items
        var itemKeys = [];                // marker column + delimiter of each open item
        var cls = [], gap = [], deep = [], seg = [];           // per line: 0 hard fence, 1 prose, 2 soft fence; run-ending blank
        var dead = -1;                    // first line of a disputed fence close, or -1
        var prevQuotes = 0, curQuotes = 0, quoteOk = true; // quote depth of the previous line
        var prevCode = false;
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i];
            var parts = splitContainerPrefix(line);   // { quotes, indent, rest, item, late }
            if (parts.tab) { dead = i; break; }
            // A fence opener is trusted only in a quote run (a stretch of
            // lines at one quote depth) that began at the start of the text
            // or right after an empty line: marked pulls "> ```" into a list
            // item that precedes the quote without an empty line.
            prevQuotes = curQuotes; curQuotes = parts.quotes;
            if (/^ *$/.test(line)) quoteOk = true;
            else if (curQuotes !== prevQuotes) quoteOk = i === 0 || /^ *$/.test(lines[i - 1]);
            var blank = parts.rest.trim() === '' && line.indexOf('\t') === -1;
            out.push(line);
            gap.push(/^ *$/.test(line));
            deep.push(parts.quotes > 0 || parts.indent > 0 || parts.item >= 0);
            seg.push(false);

            // Disputed close (security review 2026-11-14, third pass): inside
            // a fence, a line made only of backticks and tildes that begins
            // with the fence character and mixes in the other one ("```~~")
            // closes the fence in marked but not in markdown-it or micromark.
            // A closer-shaped line with a tab before or after the run closes
            // in markdown-it and micromark but not in marked. No fence state
            // after either is common to all renderers, so every line from
            // here to the end of the text is encoded.
            if (fence && DISPUTED_CLOSE_RE.test(parts.rest) &&
                parts.rest.replace(/^[ \t]+/, '').charAt(0) === fence.ch) {
                dead = i;
                break;
            }
            // Open link reference definition (fourth pass): marked lets a
            // definition's label, or its quoted or parenthesised title, run
            // across later lines and swallow a fence opener. A line that
            // starts with "[" and never closes the label, or a definition
            // with an unbalanced title character on its line or the next two,
            // ends all trust from that line on.
            if (!fence && openDefinition(lines, i, parts.rest)) {
                dead = i;
                break;
            }
            // Task box before a block start (seventh pass): marked strips
            // "[ ]" on an item line and reads what follows as a new block, so
            // a fence there opens in marked only.
            if (!fence && parts.item >= 0 && TASK_BLOCK_RE.test(parts.rest)) {
                dead = i;
                break;
            }
            // A second list marker on an item line (eighth pass): only the
            // first marker is read here, so a fence or task box behind the
            // second ("- - ```", "- - [ ] ~~~") would go unseen while marked
            // opens it.
            if (!fence && parts.item >= 0 && /^(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)/.test(parts.rest)) {
                dead = i;
                break;
            }

            // Inside a fence, trust ends at: a line at another quote depth
            // (unless the whole line is empty: a quote-only ">" line is not
            // blank for micromark), any list-marker line (marked accepts
            // "1) ```" as a closer), and, for a fence in a list item or 4+
            // columns in, a line indented less than the fence (markdown-it
            // reads a less-indented closer as a new opener).
            if (fence && (parts.quotes !== fence.quotes ? !/^ *$/.test(line) : (!blank && parts.item >= 0))) { dead = i; break; }
            if (fence && !blank && (fence.soft || fence.inItem) && parts.indent < fence.indent) { dead = i; break; }
            if (fence) {
                if (parts.quotes >= fence.quotes) {
                    var c = FENCE_CLOSE_RE.exec(parts.rest);
                    if (c && parts.quotes === fence.quotes && c[1].charAt(0) === fence.ch &&
                        c[1].length >= fence.len && parts.indent <= fence.indent + 3) {
                        cls.push(fence.soft ? 2 : 0);
                        fence = null;
                        prevBlank = blank;
                        continue;
                    }
                    if (blank || fence.indent === 0 || parts.indent >= fence.indent) {
                        cls.push(fence.soft ? 2 : 0);
                        prevBlank = blank;
                        continue;
                    }
                }
                dead = i; break; // container ended: no shared fence state after this
            }

            // List context (code review 2026-11-14): a fence opener written
            // under a list item sits at the item's content column, often 4+
            // columns in, with no blank line before it. Track the content
            // column of each open item: a marker line closes deeper items and
            // siblings and opens its own; any other non-blank line closes the
            // items it is not indented into. A marker more than 3 columns
            // past its parent is not a list item (paragraph continuation),
            // and an ordered marker other than 1 cannot START a list right
            // after a non-blank line (CommonMark: it cannot interrupt a
            // paragraph; renderers differ at container edges, so it is never
            // trusted there).
            var isItem = false;
            if (!blank) {
                if (parts.quotes !== itemQuotes) { items = []; itemKeys = []; itemQuotes = parts.quotes; }
                // sibling: an open ordered item with the same marker column
                // and delimiter (looked up before siblings are closed). Only
                // then may an ordered marker other than 1 follow a non-blank
                // line or sit nested in another item: micromark reads it as
                // paragraph text otherwise. Without a sibling it starts a
                // list only at the top level after a blank line.
                var sibling = parts.late && itemKeys.indexOf(parts.item + parts.delim) !== -1;
                var edge = parts.item >= 0 ? parts.item : parts.indent;
                while (items.length && items[items.length - 1] > edge) { items.pop(); itemKeys.pop(); }
                isItem = parts.item >= 0 && parts.item <= (items.length ? items[items.length - 1] : 0) + 3 &&
                    !(parts.late && !sibling && (!prevBlank || prevCode || parts.item > 0 || items.length > 0));
                if (isItem) { items.push(parts.indent); itemKeys.push(parts.item + parts.delim); }
            }
            var top = items.length ? items[items.length - 1] : -1;

            var o = FENCE_OPEN_RE.exec(parts.rest);
            // An opener indented 4+ columns is a fence when it follows a blank
            // line (markdown-it reads it as a list-item fence or an indented
            // code block, both code) or when it sits within 3 columns of the
            // open list item's content column. After a prose line outside a
            // list it would be paragraph continuation, so it is NOT trusted.
            // An opener on a marker line needs that marker to be a list item.
            if (o && !(o[1].charAt(0) === '`' && o[2].indexOf('`') !== -1) &&
                (parts.item < 0 || isItem) &&
                quoteOk &&
                (parts.indent <= 3 || prevBlank || (top >= 0 && parts.indent >= top && parts.indent <= top + 3))) {
                fence = { ch: o[1].charAt(0), len: o[1].length, indent: parts.indent, quotes: parts.quotes,
                    soft: parts.item >= 0 || parts.indent > 3, inItem: top >= 0 };
                out[out.length - 1] = escTagLike(line);
                cls.push(fence.soft ? 2 : 0);
                prevBlank = false;
                continue;
            }
            if (o && !(o[1].charAt(0) === '`' && o[2].indexOf('`') !== -1)) { dead = i; break; }
            // A top-level list item line (marker at column 0, no quote,
            // previous line unquoted too) starts a new block in every
            // renderer: a new span-trust segment. Nested and quoted items
            // are not cut: marked reads some of them as continuation text.
            if (isItem && parts.item === 0 && parts.quotes === 0 && prevQuotes === 0) seg[i] = true;
            cls.push(1);
            prevBlank = blank;
            if (!blank) prevCode = !items.length && (parts.indent >= 4 || /^ {0,3}\t/.test(line));
        }

        var n = lines.length, a = 0, tabFrom = -1;
        for (var tq = 0; tq < lines.length; tq++) if (/^[ >]*\t/.test(lines[tq])) { tabFrom = tq; break; }
        if (dead >= 0) {
            for (var d = dead; d < n; d++) out[d] = escTagLike(lines[d]);
            n = dead;
        }
        // taint: a run with an unpaired backtick run was seen, and every run
        // since began indented, quoted or on a list marker. marked joins a
        // list item's text across blank lines in some shapes, so that
        // backtick can pair with a span opener in a later run.
        var taint = false;
        while (a < n) {
            if (cls[a] === 0 || gap[a]) { a++; continue; }
            var b, table = false, odd = false;
            if (!deep[a]) taint = false;
            for (b = a; b < n && cls[b] !== 0 && !gap[b]; b++) {
                // A GFM delimiter row anywhere in the run makes it a table.
                if (lines[b].indexOf('|') !== -1 && /^[ \t>|:-]*-[ \t>|:-]*$/.test(lines[b])) table = true;
                var ticks = lines[b].match(/`+/g), seen = {};
                for (var tk = 0; ticks && tk < ticks.length; tk++) seen[ticks[tk].length] = !seen[ticks[tk].length];
                for (var sl in seen) if (seen[sl]) odd = true;
            }
            // Span trust is decided per segment: the run is cut at each line
            // that starts a list item in every renderer (seg), because no
            // renderer pairs a backtick across two items. A segment keeps its
            // spans only if every line in it pairs all its backtick runs.
            var s0 = a;
            while (s0 < b) {
                var e = s0 + 1;
                while (e < b && !seg[e]) e++;
                var trust = !strict && !taint, ranges = [], tilde = false;
                for (var q = s0; q < e; q++) {
                    var rg = null;
                    if (cls[q] === 2 || (tabFrom >= 0 && q >= tabFrom)) trust = false;
                    else if (trust) { rg = spanRanges(lines[q]); if (rg === null) trust = false; }
                    // A pipe inside a span splits a GFM table cell there, and
                    // marked's strikethrough runs from an earlier tilde
                    // outside a span into a later span, so the spans after
                    // it pair differently.
                    var from = 0;
                    for (var sp = 0; rg && trust && sp < rg.length; sp += 2) {
                        if (lines[q].slice(from, rg[sp]).indexOf('~') !== -1) tilde = true;
                        var inner = lines[q].slice(rg[sp], rg[sp + 1]);
                        if (table && inner.indexOf('|') !== -1) trust = false;
                        if (tilde && inner.indexOf('~') !== -1) trust = false;
                        from = rg[sp + 1];
                    }
                    if (lines[q].slice(rg ? from : 0).indexOf('~') !== -1) tilde = true;
                    ranges.push(rg);
                }
                for (var m = s0; m < e; m++) {
                    if (cls[m] === 1) out[m] = trust ? escTagLikeOutsideSpans(lines[m], ranges[m - s0]) : escTagLike(lines[m]);
                }
                s0 = e;
            }
            if (odd) taint = true;
            a = b;
        }
        return out.join('\n');
    }

    // Split a line into its blockquote markers, the indent after them and
    // the remaining text: `>  > ___code` -> { quotes: 2, indent: 3, rest }.
    function openDefinition(lines, i, rest) {
        var t = rest.replace(/^[ \t]+/, '');
        if (t.charAt(0) !== '[') return false;
        var close = -1;
        for (var p = 1; p < t.length; p++) {
            var ch = t.charAt(p);
            if (ch === '\\') { p++; continue; }
            if (ch === ']') { close = p; break; }
        }
        if (close === -1) return true;
        if (t.charAt(close + 1) !== ':') return false;
        // Only the plain one-line shapes keep trust: [label]: dest, or the
        // same with a complete title on that line (no backslash, no nested
        // title character); without a title the next line must not start one.
        // marked reads escaped quotes, title characters in the destination
        // and titles on later lines differently from markdown-it.
        var dm = /^\[[^\]\\]+\]:[ \t]+[^\s"'()<>\\]+([ \t]+(?:"[^"\\]*"|'[^'\\]*'|\([^()\\]*\)))?[ \t]*$/.exec(t);
        if (!dm) return true;
        if (!dm[1] && i + 1 < lines.length) {
            var nx = lines[i + 1].replace(/^[ \t>]+/, '');
            if (/^["'(]/.test(nx)) return true;
        }
        return false;
    }
    function splitContainerPrefix(line) {
        var quotes = 0, i = 0, n = line.length;
        for (;;) {
            var j = i, sp = 0;
            while (j < n && line.charAt(j) === ' ' && sp < 3) { j++; sp++; }
            if (j < n && line.charAt(j) === '>') {
                quotes++;
                i = j + 1;
                // A tab right after ">" hides a marker or fence from this scan.
                if (line.charAt(i) === '\t') return { quotes: quotes, indent: 99, rest: '', item: -1, late: false, tab: true };
                if (i < n && line.charAt(i) === ' ') i++;
                continue;
            }
            break;
        }
        var k = i;
        while (k < n && line.charAt(k) === ' ') k++;
        // A list marker on the same line (`- ```` or `1. ~~~`) opens the fence
        // inside the item in markdown-it; count the marker as indent so the
        // closer on the next, item-indented line pairs with it.
        if (/^(?:[-*+]|\d{1,9}[.)]) *\t/.test(line.slice(k))) return { quotes: quotes, indent: 99, rest: '', item: -1, late: false, tab: true };
        var lm = /^([-*_])(?:[ \t]*\1){2,}[ \t]*$/.test(line.slice(k)) ? null : /^([-*+]|\d{1,9}[.)])( {1,4})(?=\S)/.exec(line.slice(k));
        // item: the column of the list marker (-1 when the line has none).
        var item = lm ? k - i : -1;
        // late: an ordered marker with a number other than 1.
        var late = !!lm && lm[1].length > 1 && lm[1] !== '1.' && lm[1] !== '1)';
        if (lm) k += lm[0].length;
        // delim: '.' or ')' for an ordered marker, '' for a bullet.
        var delim = lm && lm[1].length > 1 ? lm[1].charAt(lm[1].length - 1) : '';
        return { quotes: quotes, indent: k - i, rest: line.slice(k), item: item, late: late, delim: delim };
    }

    function encodeTarget(url) {
        // Belt-and-braces: capture charset already excludes these, but the
        // www/email builders concatenate, so encode the md-breaking set.
        return url.replace(/[\s()\[\]"<>`\\]/g, function (c) {
            var cp = c.charCodeAt(0);
            return '%' + ('0' + cp.toString(16).toUpperCase()).slice(-2);
        });
    }

    function linkifySegment(s) {
        // http(s) URLs
        s = s.replace(URL_RE, function (url) {
            var trail = TRAIL_PUNCT_RE.exec(url);
            var clean = trail ? url.slice(0, -trail[0].length) : url;
            if (!/^https?:\/\/./.test(clean)) return url; // no bare-scheme links
            return '[' + clean + '](' + encodeTarget(clean) + ')' + (trail ? trail[0] : '');
        });
        // www. (https:// by construction; never protocol-relative)
        s = s.replace(WWW_RE, function (all, pre, host) {
            var trail = TRAIL_PUNCT_RE.exec(host);
            var clean = trail ? host.slice(0, -trail[0].length) : host;
            return pre + '[' + clean + '](https://' + encodeTarget(clean) + ')' + (trail ? trail[0] : '');
        });
        // emails -> mailto:
        s = s.replace(EMAIL_RE, function (all, pre, addr) {
            return pre + '[' + addr + '](mailto:' + encodeTarget(addr) + ')';
        });
        return s;
    }

    function linkify(line) {
        // Token-level: skip spans already inside [text](url) (v1 skipped the
        // whole line, which a decoy link could steer).
        MDLINK_RE.lastIndex = 0;
        var out = '', last = 0, m;
        while ((m = MDLINK_RE.exec(line))) {
            out += linkifySegment(line.slice(last, m.index)) + m[0];
            last = m.index + m[0].length;
        }
        return out + linkifySegment(line.slice(last));
    }

    // Opt-in emphasis (default OFF): ALL-CAPS word bolding via a word-split
    // loop (regex-free; v1's nested-quantifier regex was polynomial), plus
    // _underscore_ -> *italic* normalization.
    var CAPS_SKIP = { THE: 1, AND: 1, FOR: 1, BUT: 1, NOT: 1, WITH: 1, FROM: 1, THAT: 1, THIS: 1, WILL: 1, HAVE: 1, BEEN: 1, WERE: 1, THEY: 1, THEIR: 1, WHAT: 1, WHEN: 1, WHERE: 1, WHICH: 1, ABOUT: 1 };
    function applyEmphasis(line) {
        var parts = line.split(' ');
        for (var i = 0; i < parts.length; i++) {
            var w = parts[i];
            if (w.length >= 5 && w.length <= 40 && !CAPS_SKIP[w] && /^[A-Z]{5,40}$/.test(w)) {
                parts[i] = '**' + w + '**';
            }
        }
        line = parts.join(' ');
        line = line.replace(/(^|[^_\w])_([^_\s][^_]{0,200}?)_(?=[^_\w]|$)/g, '$1*$2*');
        return line;
    }

    function emitProseLine(text, opt) {
        var s = escProse(text);
        if (opt.detectUrls) s = linkify(s);
        if (opt.detectEmphasis) s = applyEmphasis(s);
        return s;
    }

    function emitTableMd(header, rows, opt) {
        // Cells are linkified like prose (B3, post-impl review: unlinkified
        // cells got linkified on RE-parse, breaking idempotency; linkify is
        // itself idempotent via MDLINK_RE skipping, so doing it here closes
        // the loop AND makes URL handling consistent across block types).
        var cell = function (c) {
            var s = escCell(c);
            if (opt && opt.detectUrls) s = linkify(s);
            return s || ' ';
        };
        var out = [];
        out.push('| ' + header.map(cell).join(' | ') + ' |');
        out.push('|' + header.map(function () { return ' --- '; }).join('|') + '|');
        for (var i = 0; i < rows.length; i++) {
            out.push('| ' + rows[i].map(cell).join(' | ') + ' |');
        }
        return out;
    }

    function headingText(b) {
        // numsec headings live in one-item LIST blocks (the segmenter reads
        // "1. Introduction" as an ordered item); everything else is line 0.
        var t = b.type === 'list' ? b.items[0].info.trimmed : b.lines[0].trimmed;
        if (b.headingStyle === 'colon') t = t.replace(/:$/, '');
        if (b.headingStyle === 'numsec') t = t.replace(/^([IVXLC]{1,7}|\d{1,3})\.\s+/, '');
        // Case preserved exactly (v1's Title Case mangled acronyms - gone).
        return escProse(t);
    }

    function listLevels(items) {
        // Distinct indents -> nesting levels (handles 2/3/4-space styles).
        var indents = [];
        for (var i = 0; i < items.length; i++) {
            var ind = items[i].info.indent || 0;
            if (indents.indexOf(ind) === -1) indents.push(ind);
        }
        indents.sort(function (a, b) { return a - b; });
        for (i = 0; i < items.length; i++) {
            items[i].level = indents.indexOf(items[i].info.indent || 0);
        }
    }

    function emitList(b, opt, out) {
        listLevels(b.items);
        var counters = [];
        for (var i = 0; i < b.items.length; i++) {
            var it = b.items[i], inf = it.info;
            var lvl = it.level;
            counters.length = lvl + 1;
            var pad = new Array(lvl + 1).join('    ');
            var marker, text;
            if (inf.ordered) {
                // Letter/roman/paren lists become real ordered lists (defect 7
                // fix: a. b. c. -> 1. 2. 3.). Letter/roman markers are numbered
                // BY POSITION at their level ('c' is ambiguous between letter 3
                // and roman 100; authors write these in order). Only explicit
                // decimal markers keep the author's own number.
                var num;
                if (inf.ordered.kind === 'num' && inf.ordered.val > 0) num = inf.ordered.val;
                else num = (counters[lvl] || 0) + 1;
                counters[lvl] = num;
                marker = num + '. ';
                text = inf.ordered.text;
            } else {
                counters[lvl] = 0;
                marker = '- ';
                text = inf.bullet.text;
            }
            out.push(pad + marker + emitProseLine(text, opt));
            for (var c = 0; c < it.cont.length; c++) {
                out.push(pad + new Array(marker.length + 1).join(' ') + emitProseLine(it.cont[c].trimmed, opt));
            }
        }
    }

    function emitQuote(b, opt, out) {
        for (var i = 0; i < b.lines.length; i++) {
            var inf = b.lines[i];
            var depth = inf.quoteDepth || 1;
            var prefix = new Array(depth + 1).join('>');
            var text = inf.quoteText || '';
            out.push(text ? prefix + ' ' + emitProseLine(text, opt) : prefix);
        }
    }

    function emitCode(lines, out) {
        // Dynamic fence longer than any backtick run inside (house pattern).
        var longest = 0;
        for (var i = 0; i < lines.length; i++) {
            var runs = lines[i].match(/`+/g);
            if (runs) for (var r = 0; r < runs.length; r++) if (runs[r].length > longest) longest = runs[r].length;
        }
        var fence = new Array(Math.max(3, longest + 1) + 1).join('`');
        out.push(fence);
        // Strip the common 4-space/tab indent, keep deeper indentation.
        for (i = 0; i < lines.length; i++) out.push(lines[i].replace(/^(\t|    )/, ''));
        while (out.length && out[out.length - 1] === '') out.pop(); // no trailing blank in fence
        out.push(fence);
    }

    function reflowParagraph(lines, wrapCol) {
        var out = [], buf = '';
        for (var i = 0; i < lines.length; i++) {
            var t = lines[i].trimmed;
            if (!buf) { buf = t; continue; }
            var prev = lines[i - 1].trimmed;
            // Guard: deliberately short sentence-final line = intentional break.
            if (SENTENCE_END_RE.test(prev) && /^[A-Z]/.test(t) && prev.length < wrapCol - 15) {
                out.push(buf); buf = t; continue;
            }
            buf += ' ' + t;
        }
        if (buf) out.push(buf);
        return out;
    }

    // ======================================================================
    // MAIN
    // ======================================================================

    // ======================================================================
    // LINK-SCHEME GUARD (ported 2026-11-16 from ai-chat-to-md-parser.js; the
    // two copies are verbatim and tests/run-escaper-parity.js pins them)
    //
    // Copy and Download hand this Markdown out raw. A destination with a
    // javascript:, vbscript:, file: or non-image data: scheme is made inert
    // by rewriting its colon to "%3A", wherever a renderer could read one:
    // after "](", "]:" and "<", on every line, code included.
    // ======================================================================
    var BAD_SCHEMES = ['javascript', 'vbscript', 'file', 'data'];
    var GOOD_DATA_RE = /^data:image\/(png|jpeg|gif|webp)[;,]/;
    var LOCAL_FILE_RE = /^file:\/\/\/[a-z0-9]/;
    // In a local file path: a dot segment in any spelling, or a backslash
    // (both can turn "file:///a/..//srv" into a network share).
    var FILE_TRICK_RE = /\/(\.|%2e){2}([\/?#]|$)|\\|%5c/;
    var FILE_END_RE = /^[ \t)>"']$/;
    var LOCAL_FILE_RAW_RE = /[Ff][Ii][Ll][Ee]:\/\/\/[A-Za-z0-9][A-Za-z0-9._~!$*+,;=:@%\/?#-]*/y;
    var FILE_DOTS_RE = /\/(\.|%2e){2}([\/?#]|$)/i;
    // What vanishes() drops, as one pattern.
    var VANISH_RE = /[\x00-\x20\s]+/g;
    var CRUDE_SCHEME_RE = /(javascript|vbscript|file|data)[ \t]*(:|&colon;|&#0*58;|&#[xX]0*3[aA];)/gi;
    var CRUDE_FILE_RE = /(file)[ \t]*(:|&colon;|&#0*58;|&#[xX]0*3[aA];)/gi;
    // Local file links kept: the input is the user's own text (decided 2026-11-19).
    var LOCAL_FILE_LINKS = true;
    var NAMED_ENTITY_RE = /^&([A-Za-z][A-Za-z0-9]{1,31})\\?;/;
    var ASCII_PUNCT_RE = /^[!-\/:-@\[-`{-~]$/;
    var NAMED_ENTITIES = { colon: ':', Tab: '\t', NewLine: '\n', nbsp: String.fromCharCode(0xA0) };
    var NOT_A_LETTER = String.fromCharCode(0xFFFD);

    // Blockquote prefix, leading whitespace and body of one line.
    function lineShape(line) {
        var quotes = 0, i = 0, n = line.length;
        for (;;) {
            var j = i, sp = 0;
            while (j < n && line.charAt(j) === ' ' && sp < 3) { j++; sp++; }
            if (j < n && line.charAt(j) === '>') {
                quotes++;
                i = j + 1;
                if (i < n && line.charAt(i) === ' ') i++;
                continue;
            }
            break;
        }
        var k = i, w = 0;
        while (k < n) {
            var c = line.charAt(k);
            if (c === ' ') w++;
            else if (c === '\t') w += 4 - (w % 4);
            else break;
            k++;
        }
        return { quotes: quotes, prefix: line.slice(0, i), lead: w, leadStr: line.slice(i, k), body: line.slice(k) };
    }

    // The character reference at s[q] ("&..."), read the way a browser reads
    // one inside an attribute value: { dec, len } or null. marked copies
    // "&..." from a destination into href/src as written, so the browser's
    // rules decide, not CommonMark's (security review 2026-11-16): a numeric
    // reference may have any number of digits and needs no ";". marked
    // also drops a backslash before punctuation first, so "&\#58;" and
    // "&colon\;" reach the browser as "&#58;" and "&colon;": a backslash
    // before the "#" or the ";" is read as absent (second security pass).
    function readEntity(s, q) {
        var n = s.length, i = q + 1;
        if (s.charAt(i) === '\\' && s.charAt(i + 1) === '#') i++;
        if (s.charAt(i) === '#') {
            i++;
            var hex = s.charAt(i) === 'x' || s.charAt(i) === 'X';
            if (hex) i++;
            var start = i, code = 0;
            while (i < n) {
                var d = s.charCodeAt(i), v;
                if (d >= 48 && d <= 57) v = d - 48;
                else if (hex && d >= 97 && d <= 102) v = d - 87;
                else if (hex && d >= 65 && d <= 70) v = d - 55;
                else break;
                code = code * (hex ? 16 : 10) + v;
                if (code > 0x10FFFF) code = 0x110000;   // out of range, stays there
                i++;
            }
            if (i === start) return null;
            if (s.charAt(i) === ';') i++;
            else if (s.charAt(i) === '\\' && s.charAt(i + 1) === ';') i += 2;
            var bad = code === 0 || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF);
            return { dec: bad ? NOT_A_LETTER : String.fromCodePoint(code), len: i - q };
        }
        var m = NAMED_ENTITY_RE.exec(s.slice(q, q + 40));
        if (!m) return null;
        return {
            dec: Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, m[1]) ? NAMED_ENTITIES[m[1]] : NOT_A_LETTER,
            len: m[0].length
        };
    }

    function vanishes(ch) {
        // Whitespace and controls that URL parsing or markdown-it trimming
        // would drop (raw or entity-encoded).
        return ch.length === 1 && (ch.charCodeAt(0) <= 32 || /\s/.test(ch));
    }

    function isSchemePrefix(clean) {
        for (var i = 0; i < BAD_SCHEMES.length; i++) if (BAD_SCHEMES[i].indexOf(clean) === 0) return true;
        return false;
    }

    // Decide on the cleaned, lowercased destination text "scheme:rest".
    // Where LOCAL_FILE_LINKS is on, a local file link ("file:///Users/...",
    // "file:///C:/...") passes: three slashes, then a letter or digit. A
    // host, a fourth slash or a backslash ("file://server/share",
    // "file:////server", "file:///\\server") is still rewritten: on Windows
    // those open a network share and can send the login to it. The same
    // test sees the raw text here and markdown-it's encoded href in
    // isBadHref ("\\" becomes "%5C"), so the two agree.
    function isBadClean(clean) {
        var colon = clean.indexOf(':');
        if (colon === -1) return false;
        var scheme = clean.slice(0, colon);
        if (BAD_SCHEMES.indexOf(scheme) === -1) return false;
        if (scheme === 'file') return !(LOCAL_FILE_LINKS && LOCAL_FILE_RE.test(clean) && !FILE_TRICK_RE.test(clean));
        return scheme !== 'data' || !GOOD_DATA_RE.test(clean);
    }

    // At position p, decode what markdown-it (and a browser) would read as
    // the start of a URL: backslash escapes, entities, dropped whitespace,
    // case. If it is a forbidden scheme, return the patch { rep, end }:
    // everything from p up to `end` (the raw text that produced the colon)
    // is to be replaced by rep ("scheme%3A"). Else null. Callers collect the
    // pieces and join once: rebuilding the line per link was quadratic on a
    // long line (security review 2026-11-14).
    function neutralizeAt(s, p) {
        var clean = '', colonEnd = -1, q = p, n = s.length, e;
        while (q < n && clean.length < 40) {
            var ch = s.charAt(q), dec = ch, adv = 1;
            // A file: destination ends here as written. Without this, text
            // after the link ("[a](file:///a.md)... see ../up") would read
            // as part of its path below.
            if (colonEnd !== -1 && FILE_END_RE.test(ch) && clean.slice(0, 5) === 'file:') break;
            if (ch === '\\' && q + 1 < n && ASCII_PUNCT_RE.test(s.charAt(q + 1))) {
                dec = s.charAt(q + 1); adv = 2;
                // marked drops the backslash and writes the "&#58;" behind
                // it into the attribute, where the browser decodes it.
                if (dec === '&' && (e = readEntity(s, q + 1)) !== null) { dec = e.dec; adv = 1 + e.len; }
            } else if (ch === '&') {
                if ((e = readEntity(s, q)) !== null) { dec = e.dec; adv = e.len; }
            }
            q += adv;
            if (vanishes(dec)) continue;
            if (colonEnd === -1) {
                if (dec === ':') {
                    if (!clean || BAD_SCHEMES.indexOf(clean) === -1) return null;
                    // "data::Item" is a namespace path in code (C++, Rust),
                    // and as a URL it is inert: the media type ":Item" is
                    // not a valid MIME type, so a browser reads text/plain.
                    // Rewriting it damaged code blocks (found 2026-11-16).
                    // Only the two colons as written, side by side: any
                    // other spelling is rewritten (security review).
                    if (clean === 'data' && ch === ':' && s.charAt(q) === ':') return null;
                    colonEnd = q; clean += ':';
                    continue;
                }
                dec = dec.toLowerCase();
                if (!/^[a-z]$/.test(dec) || !isSchemePrefix(clean + dec)) return null;
                clean += dec;
            } else {
                clean += dec.toLowerCase();
            }
        }
        if (colonEnd === -1) return null;
        // A file: link is kept only as written plainly (localFileAt); every
        // other spelling of it is rewritten, whatever its path decodes to.
        if (clean.slice(0, 5) === 'file:') {
            if (LOCAL_FILE_LINKS && localFileAt(s, p)) return null;
        } else if (!isBadClean(clean)) {
            return null;
        }
        // Keep the letters as written ("File%3A") when the raw text is just
        // the scheme and its colon; entity, escape and whitespace forms get
        // the cleaned lowercase scheme.
        var raw = s.slice(p, colonEnd);
        var word = /^[A-Za-z]+:$/.test(raw) ? raw.slice(0, -1) : clean.slice(0, clean.indexOf(':'));
        return { rep: word + '%3A', start: p, end: colonEnd, scheme: clean.slice(0, clean.indexOf(':')) };
    }

    // A local file link written plainly at p: "file:///" (any case), a
    // letter or digit, then only path characters (no "&", backslash,
    // brackets, parentheses or quotes, so no entity, escape or nesting can
    // change what it reads as), no dot segment, no "%5c" or "%2f" (an app
    // that decodes before it normalizes reads them as separators), ending at the
    // end of the line, ")" or ">", or at a space followed by nothing or a
    // title. Linear: a match never contains "](", "]:" or "<", so two
    // matches never overlap.
    function localFileAt(s, p) {
        LOCAL_FILE_RAW_RE.lastIndex = p;
        var m = LOCAL_FILE_RAW_RE.exec(s);
        if (m === null || FILE_DOTS_RE.test(m[0]) || /%5c|%2f/i.test(m[0])) return false;
        var e = p + m[0].length, c = s.charAt(e);
        if (c === '' || c === ')' || c === '>' || c === '\n' || c === '\r') return true;
        if (c !== ' ' && c !== '\t') return false;
        var t = s.charAt(skipSpaces(s, e));
        return t === '' || t === '"' || t === "'" || t === '(' || t === '\n' || t === '\r';
    }

    function skipSpaces(s, p) {
        while (p < s.length && (s.charAt(p) === ' ' || s.charAt(p) === '\t')) p++;
        return p;
    }

    // Try a destination at p, also past a "<" (pointy destination).
    //
    // afterColon: the destination follows "]:" (a reference definition).
    // "[ERROR]: File: config.yaml", a footnote "[^1]: Data: from the survey"
    // and "rows[1:]:" with "data: dict = ..." on the next line are prose or
    // code, not definitions: a definition's destination ends at the first
    // space, and only a title in quotes or parentheses (or nothing) may
    // follow it. So when the scheme's colon is followed by a raw space or
    // tab and then by anything that cannot open a title, nothing is
    // rewritten (code review 2026-11-16). Raw space and tab only: an
    // entity-encoded space or a no-break space stays part of the
    // destination in markdown-it. The pointy form and "](" keep the strict
    // rule, and so do javascript: and vbscript: (rare in prose, and some
    // renderers outside CommonMark may allow a space in a definition's
    // destination; second security pass).
    function neutralizeDest(s, p, afterColon) {
        var r = neutralizeAt(s, p);
        if (r !== null && afterColon && (r.scheme === 'data' || r.scheme === 'file')) {
            var c = s.charAt(r.end);
            if (c === ' ' || c === '\t') {
                var t = s.charAt(skipSpaces(s, r.end));
                if (t !== '' && t !== '"' && t !== "'" && t !== '(') return null;
            }
        }
        if (r === null && s.charAt(p) === '<') r = neutralizeAt(s, skipSpaces(s, p + 1));
        return r;
    }

    // Destinations on one line: after "](" (inline link / image), after "]:"
    // (reference definition, also mid-line for multi-line labels) and after
    // "<" (autolink). When "](" or "]:" ends the line, the destination may
    // start the next line (markdown-it allows one newline): pending, 1 after
    // "](" and 2 after "]:".
    function neutralizeLine(line, pending) {
        var s = line, out = '', from = 0, i = 0, r;
        if (pending) {
            var sh = lineShape(s);
            r = neutralizeDest(s, sh.prefix.length + sh.leadStr.length, pending === 2);
            if (r !== null) { out = s.slice(0, r.start) + r.rep; from = i = r.end; }
        }
        var pendingOut = 0;
        while (i < s.length) {
            var c = s.charAt(i), p = -1, nx = s.charAt(i + 1);
            if (c === ']' && (nx === '(' || nx === ':')) p = i + 2;
            else if (c === '<') p = i + 1;
            if (p === -1) { i++; continue; }
            var q = skipSpaces(s, p);
            if (q >= s.length && c === ']') { pendingOut = nx === ':' ? 2 : 1; break; }
            r = neutralizeDest(s, q, c === ']' && nx === ':');
            if (r !== null) { out += s.slice(from, r.start) + r.rep; from = i = r.end; }
            else i = p;
        }
        return { line: from ? out + s.slice(from) : s, pending: pendingOut };
    }

    function neutralizeLines(text) {
        var lines = text.split('\n'), pending = 0;
        for (var i = 0; i < lines.length; i++) {
            var r = neutralizeLine(lines[i], pending);
            lines[i] = r.line; pending = r.pending;
        }
        return lines.join('\n');
    }

    // Last resort: any position that starts a word (or an entity / escape)
    // and decodes to a forbidden scheme. Only used when markdown-it still
    // reports a forbidden link after the line rules ran on every line.
    function neutralizeEverywhere(text) {
        var out = '', from = 0;
        for (var i = 0; i < text.length; i++) {
            var c = text.charAt(i);
            if (!/[jvfdJVFD&]/.test(c)) continue;
            if (i > 0 && /[A-Za-z0-9]/.test(text.charAt(i - 1))) continue;
            // A reference to a character that vanishes is never a start:
            // the scan from the next letter or reference finds the same
            // scheme. Without this, a long run of them made the sweep
            // quadratic (security review 2026-11-16).
            if (c === '&') {
                var ent = readEntity(text, i);
                if (ent === null || vanishes(ent.dec)) continue;
            }
            var r = neutralizeAt(text, i);
            if (r !== null) { out += text.slice(from, i) + r.rep; from = r.end; i = r.end - 1; }
        }
        return from ? out + text.slice(from) : text;
    }

    function isBadHref(href) {
        if (typeof href !== 'string') return false;
        var h = href.replace(/%(0[0-9a-fA-F]|1[0-9a-fA-F]|20)/g, '');
        var clean = '';
        for (var i = 0; i < h.length && clean.length < 40; i++) {
            if (!vanishes(h.charAt(i))) clean += h.charAt(i).toLowerCase();
        }
        // A file: href is read whole: a dot segment can sit anywhere in it.
        // One pass (growing "clean" per character and slicing it was
        // quadratic on a long path).
        if (clean.slice(0, 5) === 'file:') clean = h.toLowerCase().replace(VANISH_RE, '');
        if (clean.slice(0, 6) === 'data::') return false;   // inert, see neutralizeAt
        return isBadClean(clean);
    }

    // markdown-it as the judge, with validateLink switched off so that every
    // destination becomes a token we can inspect (by default markdown-it
    // silently drops these schemes, which other renderers do not).
    // Returns true (clean), false (a forbidden link) or null (no markdown-it).
    var _linkOracle = null;
    function linkOracleClean(md) {
        if (!_linkOracle) {
            var factory = (typeof window !== 'undefined' && window.markdownit) ||
                (typeof globalThis !== 'undefined' && globalThis.markdownit) || null;
            if (!factory) return null;
            try {
                _linkOracle = factory({ html: true, linkify: false, typographer: false });
                _linkOracle.validateLink = function () { return true; };
            } catch (e) { _linkOracle = null; return null; }
        }
        if (nestedLazyCount(md) > ORACLE_MAX_NESTED_LAZY) return null;   // as if absent
        try {
            var stack = _linkOracle.parse(md, {}).slice();
            while (stack.length) {
                var t = stack.pop();
                if (!t) continue;
                if ((t.type === 'link_open' && isBadHref(t.attrGet('href'))) ||
                    (t.type === 'image' && isBadHref(t.attrGet('src')))) return false;
                var kids = t.children;
                if (kids && kids.length) for (var k = 0; k < kids.length; k++) stack.push(kids[k]);
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    // Steps 5 + 6 together. The link judge must see the FINAL text: raw HTML
    // in the pre-guard text (say "<?php ... ![i](data:...)") is an html_block
    // that hides the image from markdown-it, and only after the tag guard
    // encodes it does the image become live. So every candidate is
    // tag-guarded first and judged as shipped. The link rules never add a
    // "<", and the tag guard is idempotent, so encodeTagsOutsideCode is
    // still the last thing applied on every path.
    function guardLinksAndTags(text) {
        // The link rules run on EVERY line, code included: renderers disagree
        // about what is a fence (security re-review 2026-11-14: a link inside
        // a list-item "fence" was live in one of them), and the rules only
        // fire after "](", "]:" and "<" on a forbidden scheme.
        var out = encodeTagsOutsideCode(neutralizeLines(text));
        var verdict = linkOracleClean(out);
        if (verdict === true) return out;
        // No judge: the line rules see 40 characters of a destination, too
        // few to vouch for a whole file: path. Rewrite every file: link.
        if (verdict === null) return LOCAL_FILE_LINKS ? encodeTagsOutsideCode(out.replace(CRUDE_FILE_RE, '$1%3A')) : out;
        // markdown-it still reports a forbidden link: sweep the whole text.
        var swept = encodeTagsOutsideCode(neutralizeEverywhere(out));
        // Still one (a path the sweep cannot read the way markdown-it does,
        // or a dot segment past its 40 characters): the plain pattern.
        if (linkOracleClean(swept) !== true) swept = encodeTagsOutsideCode(swept.replace(CRUDE_SCHEME_RE, '$1%3A'));
        return swept;
    }

    // For the two exits that have no try of their own around them (the
    // Markdown passthrough gate and the backstop): parse() must never throw.
    // If the link rules throw, a plain pattern does the same job crudely.
    function guardLinksAndTagsSafe(text) {
        try {
            return guardLinksAndTags(text);
        } catch (e) {
            return encodeTagsOutsideCode(String(text).replace(/(javascript|vbscript|file|data)[ \t]*(:|&colon;|&#0*58;|&#[xX]0*3[aA];)/gi, '$1%3A'));
        }
    }

    TextToMarkdownParser.prototype.parse = function (text) {
        if (text == null) return '';
        text = String(text);
        if (!text) return '';

        // Snapshot options: per-call state only (a document must never poison
        // the next parse; the shared instance serves interactive AND batch).
        var opt = {};
        for (var k in this.options) {
            if (Object.prototype.hasOwnProperty.call(this.options, k)) opt[k] = this.options[k];
        }

        var truncated = false;
        if (text.length > MAX_INPUT_CHARS && text.length <= 2 * MAX_INPUT_CHARS &&
            text.slice(-TRUNC_NOTE.length) === TRUNC_NOTE) {
            // Our own truncated output, pasted back in. Encoding and hard
            // breaks make the output longer than the input, so it can be
            // over the cap again; cutting it a second time would break
            // parse(parse(x)) === parse(x). Take the note off, convert the
            // rest whole and put the note back. Twice the cap bounds the work.
            text = text.slice(0, -TRUNC_NOTE.length);
            truncated = true;
        } else if (text.length > MAX_INPUT_CHARS) {
            var cut = text.lastIndexOf('\n', MAX_INPUT_CHARS);
            text = text.slice(0, cut > 0 ? cut : MAX_INPUT_CHARS);
            truncated = true;
        }

        text = normalize(text);
        var hadTrailingNL = /\n$/.test(text);
        var rawLines = text.split('\n');
        if (hadTrailingNL) rawLines.pop();

        // Document gate: already Markdown -> normalize-only (idempotency),
        // still subject to the raw-sink guard (tag-like < outside code).
        if (isMarkdownDoc(rawLines)) {
            var guarded = guardLinksAndTagsSafe(text);
            if (guarded === text) return guarded + (truncated ? TRUNC_NOTE : '');
            // The guard changed the text, and may have rewritten the very
            // escape that made it count as Markdown ("\<b>" becomes
            // "\&lt;b>", "&\#58;" becomes "%3A"). If the guarded text no
            // longer passes the gate, a second parse would convert it, so
            // convert it now: parse(parse(x)) === parse(x) must hold.
            var guardedLines = guarded.split('\n');
            if (hadTrailingNL) guardedLines.pop();
            if (isMarkdownDoc(guardedLines)) return guarded + (truncated ? TRUNC_NOTE : '');
            text = guarded;
            rawLines = guardedLines;
        }

        try {
            var infos = rawLines.map(analyzeLine);
            var seg = segment(infos);
            var blocks = seg.blocks;

            // Census: heading style -> level map (consistent by construction).
            var levelMap = opt.detectHeaders ? headingCensus(blocks) : {};

            // Table / kv resolution on paragraph + indented blocks.
            if (opt.detectTables) {
                for (var bi = 0; bi < blocks.length; bi++) {
                    var b = blocks[bi];
                    if (b.type === 'para' && b.lines.length >= 2 && !b.headingStyle) {
                        var kv = tryKvTable(b.lines);
                        if (kv) { b.kvData = kv; continue; }
                        var t = tryAlignedTable(b.lines.map(function (l) { return l.raw; }), false);
                        if (t) b.tableData = t;
                    } else if (b.type === 'indented' && b.lines.length >= 2) {
                        // Indented: strong signals only (misreading code as a
                        // table destroys code; the reverse is passthrough).
                        var ti = tryAlignedTable(b.lines.map(function (l) { return l.raw; }), true);
                        if (ti) b.tableData = ti;
                    }
                }
            }

            var wrapCol = (!opt.preserveBreaks) ? reflowCensus(blocks) : 0;

            // ---- emit ----
            var out = [];
            var firstHeadingSeen = false;

            var emitHeading = function (hb, level) {
                var md = new Array(level + 1).join('#') + ' ' + headingText(hb);
                if (opt.insertHorizontalRules && level <= 2 && firstHeadingSeen) {
                    out.push('---'); out.push('');
                }
                firstHeadingSeen = true;
                out.push(md);
            };

            for (bi = 0; bi < blocks.length; bi++) {
                b = blocks[bi];
                for (var g = 0; g < b.gap; g++) out.push('');

                switch (b.type) {
                    case 'raw':
                    case 'mdatx':
                        for (var li = 0; li < b.lines.length; li++) out.push(b.lines[li].raw.replace(/\s+$/, ''));
                        break;

                    case 'hr':
                        // A rule right under a text line would be read as a
                        // setext heading underline on a second pass: keep a
                        // blank line between them.
                        if (out.length && out[out.length - 1].trim() !== '') out.push('');
                        if (opt.insertHorizontalRules) out.push('---');
                        else out.push(b.lines[0].trimmed);
                        break;

                    case 'setext': {
                        var style = b.double ? 'setext2' : 'setext1';
                        if (!opt.detectHeaders) {
                            out.push(b.lines[0].raw.replace(/\s+$/, ''));
                            out.push(b.underlineRaw); // raw underline (S3: detector off = raw lines)
                            break;
                        }
                        b.headingStyle = style;
                        emitHeading(b, levelMap[style] || (b.double ? 1 : 2));
                        break;
                    }

                    case 'quote':
                        if (opt.detectQuotes) emitQuote(b, opt, out);
                        else for (li = 0; li < b.lines.length; li++) out.push(b.lines[li].raw.replace(/\s+$/, ''));
                        break;

                    case 'sig':
                        for (li = 0; li < b.lines.length; li++) out.push(b.lines[li].raw.replace(/\s+$/, ''));
                        break;

                    case 'list':
                        if (b.headingStyle && levelMap[b.headingStyle]) {
                            emitHeading(b, levelMap[b.headingStyle]); // numsec ("1. Introduction")
                        } else if (opt.detectLists) emitList(b, opt, out);
                        else for (li = 0; li < b.items.length; li++) {
                            out.push(b.items[li].info.raw.replace(/\s+$/, ''));
                            for (var ci = 0; ci < b.items[li].cont.length; ci++) out.push(b.items[li].cont[ci].raw.replace(/\s+$/, ''));
                        }
                        break;

                    case 'indented':
                        if (b.tableData) {
                            Array.prototype.push.apply(out, emitTableMd(b.tableData.header, b.tableData.rows, opt));
                        } else {
                            emitCode(b.lines.map(function (l) { return l.raw; }), out);
                        }
                        break;

                    case 'para':
                        if (b.headingStyle && levelMap[b.headingStyle]) {
                            emitHeading(b, levelMap[b.headingStyle]);
                        } else if (b.tableData) {
                            Array.prototype.push.apply(out, emitTableMd(b.tableData.header, b.tableData.rows, opt));
                        } else if (b.kvData) {
                            var kvRows = b.kvData.map(function (p) { return [p[0], p[1]]; });
                            Array.prototype.push.apply(out, emitTableMd(['Field', 'Value'], kvRows, opt));
                        } else {
                            var canReflow = wrapCol > 0;
                            if (canReflow) {
                                // Column-shaped text (interior 2+ space runs)
                                // must never be rejoined - covers failed table
                                // candidates and tables with detection off.
                                for (li = 0; li < b.lines.length; li++) {
                                    if (b.lines[li].trimmed.indexOf('  ') !== -1) { canReflow = false; break; }
                                }
                            }
                            var plines = canReflow
                                ? reflowParagraph(b.lines, wrapCol)
                                : b.lines.map(function (l) { return l.trimmed; });
                            // "Preserve line breaks" (decided 2026-11-14,
                            // option a): emit a two-space hard break on every
                            // line of a multi-line paragraph except the last,
                            // so renderers keep the breaks instead of joining
                            // the lines (an address block stayed on one line
                            // before). Idempotent: lines are re-read trimmed
                            // and the breaks are re-added. Lists, quotes,
                            // tables and key:value blocks are unaffected.
                            var hardBreak = opt.preserveBreaks && plines.length > 1;
                            for (li = 0; li < plines.length; li++) {
                                var pl = emitProseLine(plines[li], opt);
                                out.push(hardBreak && li < plines.length - 1 && pl ? pl + '  ' : pl);
                            }
                        }
                        break;
                }
            }

            // Preserve trailing blank lines (passthrough fidelity).
            for (var tg = 0; tg < seg.trailingGap; tg++) out.push('');

            var result = guardLinksAndTags(out.join('\n'));
            if (hadTrailingNL) result += '\n';
            if (truncated) result += TRUNC_NOTE;
            return result;
        } catch (e) {
            // Backstop: degrade to normalized passthrough, never a throw, and
            // never a raw tag or a forbidden link either.
            return guardLinksAndTagsSafe(text) + (truncated ? TRUNC_NOTE : '');
        }
    };

    if (typeof window !== 'undefined') window.TextToMarkdownParser = TextToMarkdownParser;
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { TextToMarkdownParser: TextToMarkdownParser };
    }
})();
