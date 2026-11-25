/**
 * PDF to Markdown Parser
 * Extracts the text layer from PDF files using PDF.js and converts to Markdown.
 *
 * Security model (V2 hardening, 2026-07-07): the extracted text is a RAW sink.
 * Copy/Download hand the markdown string to the user, who pastes it into other
 * renderers (GitHub, VS Code, another engine) that bypass our DOMPurify. So the
 * extracted TEXT is markdown-escaped at emit time and control/bidi chars are
 * stripped from the final output:
 *   - escapeText() mirrors html-to-md's raw-sink escaper (entity-encode < > &,
 *     backslash structural, line-start heading/list/hr neutralization) with ONE
 *     deliberate addition: it also escapes `|`. As of Tier 3 there IS a table
 *     path (GFM tables), and the `|` escaping serves BOTH: in prose a stray `|`
 *     must not forge a row, and in a table CELL `\|` renders as a literal pipe
 *     (so a cell cannot break the column structure WE own). Table cells go
 *     through formatCell() = newline-collapse + escapeText (reused verbatim, so
 *     the 3-way escaper-parity guard stays green).
 *   - escape happens BEFORE any bold/italic wrapping (a literal asterisk in the
 *     PDF becomes an escaped asterisk, so our delimiters stay intact); structure
 *     detection runs on RAW text, only the content is escaped.
 *   - CTRL_BIDI_RE (incl U+061C) strips Trojan-Source chars from the final join.
 *   - 50 MB byte gate + a 30 MB output-char cap enforced DURING accumulation.
 *     PDF text streams are FlateDecode-compressed, so a small file can decompress
 *     into a huge text layer. Extraction materializes the whole text layer before
 *     the output cap runs, so the 50 MB byte gate is the effective PEAK-MEMORY
 *     ceiling; the output-char cap bounds the emitted string (not peak memory).
 *     Both bound a decompression bomb, which in a client-side app can only DoS
 *     the user's own tab (no amplification, no second victim).
 * The escaper is intentionally self-contained (family convention: every hardened
 * parser carries its own copy). Keep it in sync with html-to-md's escapeText;
 * the only difference is the `|`.
 *
 * NOTE: this change is post-extraction string formatting only. It does NOT touch
 * library loading, GlobalWorkerOptions.workerSrc, or the vendored same-origin
 * pdf.worker (version-matched to pdf.js 3.11.174).
 */
(function () {
    'use strict';

    var MAX_PDF_BYTES = 50 * 1024 * 1024;     // matches xlsx/pptx binary-container gate
    var MAX_OUTPUT_CHARS = 30 * 1024 * 1024;  // anti-bomb cap, enforced during accumulation

    // --- Tier 3 table detection tuning (all grounded in real pdf.js geometry) ---
    // Precision-FIRST posture: a missed table falls back to the Tier 1+2 prose
    // path (today's output, zero regression); a FALSE table scrambles a clean
    // document (the daily-driver regression we guard). So every gate is a
    // conjunction and biased to reject when unsure.
    var CELL_GAP_EM = 0.9;        // horizontal gap > this*fontSize starts a new cell
    var MIN_CELL_GAP_PX = 6;      // ...but never below this (tiny fonts)
    var COL_TOL_EM = 0.6;         // cell-start x within this*fontSize joins a column cluster
    var MIN_TABLE_ROWS = 3;       // need >=3 aligned rows to call it a table
    var MIN_TABLE_COLS = 3;       // MVP: >=3 columns. 2-col / label:value tables are a
                                  // documented deferral (they fall back to prose) \u2014 a 2-col
                                  // gate collides with 2-column prose; cell-fill tuning to
                                  // unlock them is the named fast-follow.
    var MAX_TABLE_COLS = 20;      // beyond this it is not a table (bail to prose)
    var MAX_TABLE_CELLS = 20000;  // rows*cols cap before materializing a grid (anti-amplification)
    var FILL_MAX = 0.7;           // mean cell-fill ratio (cellWidth/columnPitch) must be BELOW
                                  // this: real table cells are short with wide gaps (~0.35),
                                  // prose "cells" fill their column (~0.9). THE discriminator.

    // --- Tier 3 Cycle 2: multi-column reading-order detection -------------------
    // Same precision-FIRST posture: a false column split SCRAMBLES a single-column
    // doc (the daily-driver regression). Only split on a confident full-height
    // central gutter with balanced columns; otherwise -> single column (today's
    // exact path). MVP handles a 2-column split; 3+ columns are a deferral.
    var MIN_COL_ITEMS = 12;       // too few text items -> not a column layout (title page)
    var COL_CENTRAL_LO = 0.30;    // the gutter must sit in the central [30%,70%] of
    var COL_CENTRAL_HI = 0.70;    //   the content x-range (not a margin)
    var COL_CROSS_FRAC = 0.06;    // <= this fraction of items may cross the gutter (tolerates
    var COL_CROSS_ABS = 3;        //   a full-width title/footer); or this absolute count
    var COL_BALANCE_FRAC = 0.15;  // each column must hold >= this share of items
    var COL_HEIGHT_FRAC = 0.55;   // each column's y-extent must cover >= this of the total
    var COL_MIN_GUTTER_PX = 8;    // the gutter must be a real whitespace band this wide

    // Trojan-Source / control strip (keeps \t \n \r). \u escapes only.
    var CTRL_BIDI_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

    // --- Readability pass (fonts, paragraphs, page furniture) -----------------
    var MAX_FONT_PASSES = 200;    // pages that may get an operator-list pass to learn
                                  // real font names; beyond it unknown fonts are regular
    var MAX_FONT_MS = 10000;      // ...and the total time those passes may take
    var MIN_LEADING_SAMPLES = 8;  // body-line gaps a page needs to set its own leading
    var PARA_GAP = 1.3;           // a baseline gap above this * typical leading starts a
                                  // new paragraph
    var SMALL_HEADING_RATIO = 1.05; // a fully bold line this much larger than body text
                                  // (but under the h4 ratio) is a small heading
    var SEG_GAP_EM = 0.6;         // same-baseline items closer than this * font size (and
                                  // never under COL_MIN_GUTTER_PX) are one segment for
                                  // column detection
    var PAGE_NUM_RE = /^(?:page\s+)?(\d{1,4})(?:\s*(?:of|\/)\s*\d{1,4})?$/i;
    var BULLET = String.fromCharCode(0x2022);
    var ELLIPSIS = String.fromCharCode(0x2026);
    // Emphasis sentinels. They are private-use code points, which cleanGlyphs
    // removes from every extracted item, so PDF text can never contain one.
    var MARK_BOLD = String.fromCharCode(0xE001);
    var MARK_ITALIC = String.fromCharCode(0xE002);
    var MARK_BOTH = String.fromCharCode(0xE003);
    var MARKS = ['', MARK_BOLD, MARK_ITALIC, MARK_BOTH];

    // Remove private-use code points (icon fonts, Symbol/Wingdings leftovers):
    // outside their font they render as empty boxes. The two that Word-made
    // PDFs use for list bullets become a real bullet.
    // Control and bidi characters go here too, BEFORE any structure detection
    // or escaping: removed later, a hidden character in front of "# " or "1. "
    // would shield it from the escaper and then vanish, leaving real Markdown
    // structure behind. (The strip of the final string stays as a backstop.)
    function cleanGlyphs(str) {
        if (!str) return str;
        str = str.replace(CTRL_BIDI_RE, '');
        var out = null;
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c === 10 || c === 13 || c === 0x2028 || c === 0x2029) {
                // An item is one line. A line break inside it (a font can map one
                // glyph to any string) would put text at a new line start that the
                // escaper and the lone-marker guard never see as one.
                if (out === null) out = str.slice(0, i);
                out += ' ';
            } else if (c === 0x200B || c === 0x2060 || c === 0xFEFF) {
                // Zero-width characters: invisible, and they could shield a marker
                // from the escaper for a later tool that strips them.
                if (out === null) out = str.slice(0, i);
            } else if (c >= 0xE000 && c <= 0xF8FF) {
                if (out === null) out = str.slice(0, i);
                if (c === 0xF0B7 || c === 0xF0A7) out += BULLET;
                else if (c === 0xF001) out += 'fi';   // legacy Adobe ligature slots
                else if (c === 0xF002) out += 'fl';
                else out += ' ';   // an icon between two words must not join them
            } else if (out !== null) {
                out += str.charAt(i);
            }
        }
        return out === null ? str : out;
    }

    function collapseSpaces(text) {
        return text.replace(/[ \t]{2,}/g, ' ');
    }

    function pushRun(runs, text, bold, italic) {
        var last = runs.length ? runs[runs.length - 1] : null;
        if (last && last.bold === bold && last.italic === italic) last.text += text;
        else runs.push({ text: text, bold: bold, italic: italic });
    }

    // Items on one baseline normally arrive left to right. When they do not
    // (a list number drawn after its text), order them by x and join them by
    // the measured gaps. Right-to-left lines keep the order they came in.
    function reorderLine(line) {
        var parts = line.parts;
        if (line.rtl || !parts || parts.length < 2) return;
        var mono = true;
        for (var i = 1; i < parts.length; i++) {
            if (parts[i].x < parts[i - 1].x - 1) { mono = false; break; }
        }
        if (mono) return;
        var sorted = parts.slice().sort(function (a, b) { return a.x - b.x; });
        var fs = line.fontSize || 10;
        var spaces = line.spaces || [];
        var text = '', runs = [], prevEnd = 0;
        for (var k = 0; k < sorted.length; k++) {
            var p = sorted[k];
            var sep = '';
            if (k > 0) {
                if (p.x - prevEnd > fs * 0.15) sep = ' ';
                else {
                    // A tight gap that the file fills with a space item.
                    for (var sp = 0; sp < spaces.length; sp++) {
                        if (spaces[sp] >= prevEnd - 1 && spaces[sp] <= p.x + 1) { sep = ' '; break; }
                    }
                }
            }
            text += sep + p.str;
            pushRun(runs, sep + p.str, !!p.bold, !!p.italic);
            prevEnd = k === 0 ? p.x + p.w : Math.max(prevEnd, p.x + p.w);
        }
        line.text = text;
        line.runs = runs;
        line.parts = sorted;
        line.x = sorted[0].x;
    }

    function hasStyledRun(line, noBold, noItalic) {
        var runs = line.runs;
        if (!runs) return false;
        for (var i = 0; i < runs.length; i++) {
            if ((runs[i].bold && !noBold) || (runs[i].italic && !noItalic)) return true;
        }
        return false;
    }

    // When most of a document is set in a "bold" (or italic) face, that face is
    // simply its body text: marking it up would wrap every line. Returns which
    // styles to ignore.
    function dominantStyle(pages) {
        var total = 0, bold = 0, italic = 0;
        for (var p = 0; p < pages.length; p++) {
            var lines = pages[p].lines || [];
            for (var i = 0; i < lines.length; i++) {
                var runs = lines[i].runs;
                if (runs) {
                    for (var r = 0; r < runs.length; r++) {
                        var n = runs[r].text.length;
                        total += n;
                        if (runs[r].bold) bold += n;
                        if (runs[r].italic) italic += n;
                    }
                } else {
                    var len = String(lines[i].text || '').length;
                    total += len;
                    if (lines[i].isBold) bold += len;
                    if (lines[i].isItalic) italic += len;
                }
            }
        }
        return { noBold: total > 0 && bold > total * 0.5, noItalic: total > 0 && italic > total * 0.5 };
    }

    // Build a line's text from its runs with a sentinel on each side of every
    // bold/italic stretch, skipping the first `skip` characters (a list marker).
    // The sentinels sit tight against non-space text. The caller escapes the
    // whole string ONCE and only then turns sentinels into ** and *, so the
    // delimiters are always ours and the line-start rules of escapeText see the
    // real start of the line.
    function markRuns(runs, skip, noBold, noItalic) {
        var segs = [];
        for (var i = 0; i < runs.length; i++) {
            var t = runs[i].text;
            if (skip > 0) {
                if (skip >= t.length) { skip -= t.length; continue; }
                t = t.slice(skip);
                skip = 0;
            }
            var s = (runs[i].bold && !noBold ? 1 : 0) + (runs[i].italic && !noItalic ? 2 : 0);
            if (segs.length && segs[segs.length - 1].s === s) segs[segs.length - 1].t += t;
            else segs.push({ t: t, s: s });
        }
        var out = '';
        var lastCh = '';               // last character written (reading it back from
                                       // the growing string is slow on huge lines)
        var prevStyledTight = false;   // the last thing written was a closing mark
        for (var j = 0; j < segs.length; j++) {
            var seg = segs[j];
            var core = seg.s ? seg.t.trim() : '';
            if (!core) {
                out += seg.t;
                if (seg.t) { prevStyledTight = false; lastCh = seg.t.charAt(seg.t.length - 1); }
                continue;
            }
            var lead = seg.t.length - seg.t.replace(/^\s+/, '').length;
            var tail = seg.t.slice(lead + core.length);
            var before = lead > 0 ? ' ' : lastCh;
            var after = tail ? ' ' : (j + 1 < segs.length ? segs[j + 1].t.charAt(0) : '');
            // Markdown only reads ** as emphasis when it hugs a word. Where a
            // stretch starts or ends with punctuation in the middle of a word,
            // or touches another marked stretch, leave it plain.
            var opens = !isPunct(core.charAt(0)) || before === '' || isSpace(before) || isPunct(before);
            var closes = !isPunct(core.charAt(core.length - 1)) || after === '' || isSpace(after) || isPunct(after);
            if (opens && closes && !(prevStyledTight && lead === 0)) {
                out += seg.t.slice(0, lead) + MARKS[seg.s] + core + MARKS[seg.s] + tail;
                prevStyledTight = !tail;
                lastCh = tail ? tail.charAt(tail.length - 1) : MARKS[seg.s];
            } else {
                out += seg.t;
                prevStyledTight = false;
                lastCh = seg.t.charAt(seg.t.length - 1);
            }
        }
        return out;
    }

    function isSpace(ch) { return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r'; }
    function isPunct(ch) {
        if (!ch) return false;
        var c = ch.charCodeAt(0);
        return (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) ||
            (c >= 123 && c <= 126) || (c >= 0x2000 && c <= 0x206F) || (c >= 0xE000 && c <= 0xF8FF);
    }

    // escapeText (kept identical to html-to-md's) needs whitespace after a list
    // marker before it escapes it. A line that is ONLY "+" or "12." would still
    // read as an empty list item once it stands in its own paragraph.
    function escapeLine(text) {
        var e = escapeText(text);
        if (e === '+') return '\\+';
        var m = /^(\d{1,9})([.)])$/.exec(e);
        return m ? m[1] + '\\' + m[2] : e;
    }

    function unmark(escaped) {
        return escaped.split(MARK_BOTH).join('***').split(MARK_BOLD).join('**').split(MARK_ITALIC).join('*');
    }

    // "Title ........ 12": a table-of-contents entry. Returns {title, page} or
    // null. Walks back from the end (no regex over the dot run).
    function splitTocEntry(text, minDots) {
        var end = text.length, i = end;
        while (i > 0 && text.charCodeAt(i - 1) >= 48 && text.charCodeAt(i - 1) <= 57) i--;
        var digits = end - i;
        if (digits < 1 || digits > 4) return null;
        var page = text.slice(i);
        var dots = 0;
        while (i > 0) {
            var ch = text.charAt(i - 1);
            if (ch === '.') dots++;
            else if (ch !== ' ' && ch !== '\t') break;
            i--;
        }
        if (dots < minDots) return null;
        var title = text.slice(0, i).trim();
        if (!title) return null;
        return { title: title, page: page };
    }

    // Drop page numbers and running headers/footers: the top-most or bottom-most
    // line of a page, when most pages carry one. Page numbers must also count
    // up with the pages, so a column of figures is never taken for them.
    function stripPageFurniture(pages) {
        var picks = [], edges = [], nonEmpty = 0, p;
        for (p = 0; p < pages.length; p++) {
            var lines = pages[p].lines || [];
            var top = null, bot = null;
            for (var i = 0; i < lines.length; i++) {
                var y = lines[i].y;
                if (typeof y !== 'number' || !isFinite(y)) continue;
                if (!top || y > top.y) top = lines[i];
                if (!bot || y < bot.y) bot = lines[i];
            }
            picks.push(null);
            edges.push([]);
            if (!top) continue;
            nonEmpty++;
            var cand = top === bot ? [top] : [bot, top];
            for (var c = 0; c < cand.length; c++) {
                var t = String(cand[c].text || '').trim();
                if (!t || t.length > 120) continue;
                var m = t.length <= 20 ? PAGE_NUM_RE.exec(t) : null;
                if (m) { if (!picks[p]) picks[p] = { line: cand[c], num: parseInt(m[1], 10) }; }
                else edges[p].push({ line: cand[c], key: (cand[c] === top ? 't' : 'b') + collapseSpaces(t) });
            }
        }
        var drop = [];
        // Page numbers.
        var count = 0, offsets = {}, bestOff = null, bestN = 0;
        for (p = 0; p < picks.length; p++) {
            if (!picks[p]) continue;
            count++;
            var off = picks[p].num - p;
            offsets[off] = (offsets[off] || 0) + 1;
            if (offsets[off] > bestN) { bestN = offsets[off]; bestOff = off; }
        }
        if (count >= 3 && count >= nonEmpty * 0.5 && bestN >= count * 0.6) {
            for (p = 0; p < picks.length; p++) {
                if (picks[p] && picks[p].num - p === bestOff) drop.push(picks[p].line);
            }
        }
        // Running headers and footers.
        var seen = {};
        for (p = 0; p < edges.length; p++) {
            for (var e = 0; e < edges[p].length; e++) {
                var k = '$' + edges[p][e].key;
                seen[k] = (seen[k] || 0) + 1;
            }
        }
        var needRepeat = Math.max(4, nonEmpty * 0.6);
        var kept = {};   // the first occurrence stays, so the words are never lost
        for (p = 0; p < edges.length; p++) {
            for (var f = 0; f < edges[p].length; f++) {
                var rk = '$' + edges[p][f].key;
                if (seen[rk] < needRepeat) continue;
                if (kept[rk]) drop.push(edges[p][f].line);
                else kept[rk] = true;
            }
        }
        if (!drop.length) return pages;
        var dropSet = new Set(drop);
        return pages.map(function (page) {
            return { lines: (page.lines || []).filter(function (l) { return !dropSet.has(l); }) };
        });
    }

    // The most common baseline gap between consecutive body-size lines, as
    // {gap, n}. Gaps under 0.8 * body size are not line spacing (a raised or
    // lowered piece of the same line) and are not counted.
    function typicalLeading(pages, bodyFontSize) {
        var counts = {}, best = 0, bestN = 0, floor = bodyFontSize * 0.8;
        for (var p = 0; p < pages.length; p++) {
            var lines = pages[p].lines || [];
            for (var i = 1; i < lines.length; i++) {
                var a = lines[i - 1], b = lines[i];
                if (a.fontSize !== bodyFontSize || b.fontSize !== bodyFontSize) continue;
                var gap = Math.round(a.y - b.y);
                if (!(gap >= floor) || gap > bodyFontSize * 3) continue;
                counts[gap] = (counts[gap] || 0) + 1;
                if (counts[gap] > bestN) bestN = counts[gap];
            }
        }
        // Line spacing is the SMALLEST gap that is common (at least half as
        // frequent as the most frequent one): in a short document or a list-heavy
        // page the most frequent gap can be the one between paragraphs or items.
        var gaps = Object.keys(counts).map(Number).sort(function (x, y) { return x - y; });
        for (var g = 0; g < gaps.length; g++) {
            if (counts[gaps[g]] * 2 >= bestN) { best = gaps[g]; break; }
        }
        return { gap: best, n: bestN };
    }

    // Raw-sink markdown escaper. Mirrors html-to-md's escapeText (keep in sync)
    // PLUS `|` (pdf has no table-cell path; every pipe here is prose).
    function escapeText(text) {
        text = String(text)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        text = text.replace(/\\/g, '\\\\');
        text = text.replace(/([*_`~\[\]|])/g, '\\$1');
        text = text
            .replace(/^(\s*)(#{1,6})(\s|$)/gm, '$1\\$2$3')         // ATX heading
            .replace(/^(\s*)([+-])(\s)/gm, '$1\\$2$3')             // bullet - +
            .replace(/^(\s*)(\d{1,9})([.)])(\s)/gm, '$1$2\\$3$4')  // ordered list
            .replace(/^(\s{0,3})(=+|-+)(\s*)$/gm, '$1\\$2$3');     // hr / setext underline
        return text;
    }

    // ======================================================================
    // TIER 3 PURE CORE — geometry only, no DOM/PDF.js. Node __test surface.
    // Operates on `parts` = [{x, w, str}] (normalized pdf.js items) that
    // extractPageStructure now attaches to each line.
    // ======================================================================

    // A GFM table cell (RAW sink). Reuse escapeText VERBATIM (keeps the 3-way
    // escaper-parity guard green) and add ONLY a newline-collapse pre-step: a
    // cell must be single-line or an embedded newline closes the row early and
    // leaks the remainder into free markdown. Escape exactly ONCE.
    function formatCell(text) {
        return escapeText(String(text == null ? '' : text).replace(/[\r\n]+/g, ' ').trim());
    }

    // Split a line's parts into CELLS by horizontal gaps. Word spaces inside a
    // cell are small (~0.25em); a column boundary is a wide gap (many em). Parts
    // are sorted by x (pdf.js order is usually l->r but don't assume).
    function splitLineIntoCells(parts, fontSize) {
        if (!parts || !parts.length) return [];
        var fs = fontSize || 10;
        var gapThresh = Math.max(fs * CELL_GAP_EM, MIN_CELL_GAP_PX);
        var sorted = parts.slice().sort(function (a, b) { return a.x - b.x; });
        var cells = [];
        var cur = { startX: sorted[0].x, endX: sorted[0].x + sorted[0].w, text: String(sorted[0].str) };
        for (var i = 1; i < sorted.length; i++) {
            var p = sorted[i];
            var gap = p.x - cur.endX;
            if (gap > gapThresh) {
                cells.push(cur);
                cur = { startX: p.x, endX: p.x + p.w, text: String(p.str) };
            } else {
                // same cell: join, inserting a space only across a real word gap
                cur.text += (gap > fs * 0.15 ? ' ' : '') + String(p.str);
                cur.endX = Math.max(cur.endX, p.x + p.w);
            }
        }
        cells.push(cur);
        return cells;
    }

    // 1-D clustering of cell-start x's into column centers. Sort + single linear
    // pass (near-linear; no O(n^2) pairwise). Returns sorted cluster means.
    function clusterPositions(xs, tol) {
        if (!xs.length) return [];
        var sorted = xs.slice().sort(function (a, b) { return a - b; });
        var clusters = [];
        var start = sorted[0], sum = sorted[0], n = 1;
        for (var i = 1; i < sorted.length; i++) {
            if (sorted[i] - start <= tol) { sum += sorted[i]; n++; }
            else { clusters.push(sum / n); start = sorted[i]; sum = sorted[i]; n = 1; }
        }
        clusters.push(sum / n);
        return clusters;
    }

    function nearestCol(cols, x, tol) {
        var best = -1, bestD = Infinity;
        for (var i = 0; i < cols.length; i++) {
            var d = Math.abs(cols[i] - x);
            if (d < bestD) { bestD = d; best = i; }
        }
        return bestD <= tol ? best : -1;
    }

    function median(arr) {
        if (!arr.length) return 0;
        var s = arr.slice().sort(function (a, b) { return a - b; });
        return s[Math.floor(s.length / 2)];
    }

    // Given a run of consecutive >=2-cell rows, decide if it is a real table.
    // The CONJUNCTION (all must hold): >=MIN_TABLE_COLS consistent column
    // clusters, every row fits those columns with >=2 cells and no collision,
    // >=MIN_TABLE_ROWS rows, and cells are short (mean fill < FILL_MAX). Returns
    // {grid} of cell strings, or null (-> the run stays prose).
    function tryBuildTable(runRows, bodyFontSize) {
        return tryBuildTableByStart(runRows, bodyFontSize) || tryBuildTableByAnchor(runRows, bodyFontSize);
    }

    // Second chance for tables with right-aligned or centred columns (figures,
    // percentages), whose cell STARTS do not line up. Stricter than the first
    // path: every row must have the same number of cells, each column must line
    // up on its left edge, right edge or centre, columns must not overlap, and
    // the same brevity gate applies.
    function tryBuildTableByAnchor(runRows, bodyFontSize) {
        var fs = bodyFontSize || 10;
        var tol = Math.max(fs * COL_TOL_EM, 3);
        if (runRows.length < MIN_TABLE_ROWS) return null;
        var n = runRows[0].cells.length;
        if (n < MIN_TABLE_COLS || n > MAX_TABLE_COLS) return null;
        if (runRows.length * n > MAX_TABLE_CELLS) return null;
        var r, c;
        for (r = 0; r < runRows.length; r++) if (runRows[r].cells.length !== n) return null;
        var centers = [], prevMaxEnd = -Infinity, fillSum = 0, fillN = 0;
        for (c = 0; c < n; c++) {
            var sLo = Infinity, sHi = -Infinity, eLo = Infinity, eHi = -Infinity, mLo = Infinity, mHi = -Infinity, mSum = 0;
            for (r = 0; r < runRows.length; r++) {
                var cell = runRows[r].cells[c];
                var mid = (cell.startX + cell.endX) / 2;
                if (cell.startX < sLo) sLo = cell.startX;
                if (cell.startX > sHi) sHi = cell.startX;
                if (cell.endX < eLo) eLo = cell.endX;
                if (cell.endX > eHi) eHi = cell.endX;
                if (mid < mLo) mLo = mid;
                if (mid > mHi) mHi = mid;
                mSum += mid;
            }
            if (sHi - sLo > tol && eHi - eLo > tol && mHi - mLo > tol) return null;  // not aligned
            if (sLo <= prevMaxEnd) return null;                                      // columns overlap
            prevMaxEnd = eHi;
            centers.push(mSum / runRows.length);
        }
        var pitches = [];
        for (c = 0; c < n - 1; c++) pitches.push(centers[c + 1] - centers[c]);
        var medPitch = median(pitches) || 1;
        for (r = 0; r < runRows.length; r++) {
            for (c = 0; c < n; c++) {
                var pitch = c < n - 1 ? pitches[c] : medPitch;
                if (pitch <= 0) continue;
                var cl = runRows[r].cells[c];
                fillSum += Math.min((cl.endX - cl.startX) / pitch, 2);
                fillN++;
            }
        }
        if (!fillN || fillSum / fillN >= FILL_MAX) return null;
        return { grid: runRows.map(function (row) { return row.cells.map(function (x) { return x.text; }); }) };
    }

    function tryBuildTableByStart(runRows, bodyFontSize) {
        var fs = bodyFontSize || 10;
        var tol = Math.max(fs * COL_TOL_EM, 3);
        var allX = [];
        for (var r = 0; r < runRows.length; r++)
            for (var c = 0; c < runRows[r].cells.length; c++)
                allX.push(runRows[r].cells[c].startX);
        var cols = clusterPositions(allX, tol);
        if (cols.length < MIN_TABLE_COLS || cols.length > MAX_TABLE_COLS) return null;
        if (runRows.length * cols.length > MAX_TABLE_CELLS) return null;

        var grid = [];             // grid[row][col] = cell object | null
        for (var i = 0; i < runRows.length; i++) {
            var rowCells = new Array(cols.length).fill(null);
            var placed = 0;
            var cells = runRows[i].cells;
            for (var k = 0; k < cells.length; k++) {
                var ci = nearestCol(cols, cells[k].startX, tol);
                if (ci < 0) return null;               // a cell fits no column -> not a clean table
                if (rowCells[ci] !== null) return null; // two cells in one column -> not a clean row
                rowCells[ci] = cells[k];
                placed++;
            }
            if (placed < 2) return null;               // every row must span >=2 columns
            grid.push(rowCells);
        }
        if (grid.length < MIN_TABLE_ROWS) return null;

        // Brevity gate (THE discriminator): table cells fill a small fraction of
        // the column pitch; prose fills its column.
        var pitches = [];
        for (var p = 0; p < cols.length - 1; p++) pitches.push(cols[p + 1] - cols[p]);
        var medPitch = median(pitches) || 1;
        var fillSum = 0, fillN = 0;
        for (var g = 0; g < grid.length; g++) {
            for (var col = 0; col < cols.length; col++) {
                var cell = grid[g][col];
                if (!cell) continue;
                var pitch = (col < cols.length - 1) ? (cols[col + 1] - cols[col]) : medPitch;
                if (pitch <= 0) continue;
                fillSum += Math.min((cell.endX - cell.startX) / pitch, 2);
                fillN++;
            }
        }
        if (!fillN) return null;
        if (fillSum / fillN >= FILL_MAX) return null;   // cells too wide -> prose, not a table

        var textGrid = grid.map(function (row) {
            return row.map(function (cell) { return cell ? cell.text : ''; });
        });
        return { grid: textGrid };
    }

    // Scan a page's lines for table regions. Returns [{startIdx,endIdx,grid}]
    // (indices into `lines`), non-overlapping, in order. Pure over line.parts.
    function detectTables(lines, bodyFontSize) {
        var rows = lines.map(function (l, idx) {
            return { idx: idx, cells: splitLineIntoCells(l.parts, l.fontSize || bodyFontSize) };
        });
        var tables = [];
        var i = 0;
        while (i < rows.length) {
            if (rows[i].cells.length < 2) { i++; continue; }
            var j = i;
            while (j + 1 < rows.length && rows[j + 1].cells.length >= 2) j++;
            if (j - i + 1 >= MIN_TABLE_ROWS) {
                var region = tryBuildTable(rows.slice(i, j + 1), bodyFontSize);
                if (region) tables.push({ startIdx: i, endIdx: j, grid: region.grid });
            }
            i = j + 1;
        }
        return tables;
    }

    // Percentile of a numeric array (already-unsorted ok). p in [0,1].
    function percentile(arr, p) {
        if (!arr.length) return 0;
        var s = arr.slice().sort(function (a, b) { return a - b; });
        var idx = Math.max(0, Math.min(s.length - 1, Math.round(p * (s.length - 1))));
        return s[idx];
    }

    // Detect a 2-column layout and return band ranges [{lo,hi}] left->right, or
    // null (=> single column, today's exact path). Operates on raw pdf.js items
    // ({str, width, transform}); the content x-range is derived from item
    // percentiles (robust to margins) so no page-viewport bounds are needed.
    // Precision-first: every gate must pass or we bail to single column.
    // detectTables runs over the concatenated bands (page lines) rather than
    // per-band, so a table run could in principle merge across the left/right
    // band seam; tryBuildTable's x-consistency gate makes that unlikely.
    // MEASURED (Cycle 3, 2026-07-08): a per-band refactor was evaluated against a
    // trap-weighted 11-PDF / ~380-page corpus (IRS forms, annual report, federal
    // budget, NIST standards, 3 multi-column papers). Zero detected tables
    // straddled a band seam across 258 pages, INCLUDING docs with heavy
    // column+table overlap (BERT: 14 multi-col pages + 12 tables). Per-band would
    // change no output, so it was deliberately NOT built. Do not resurrect it
    // without new corpus evidence that a real cross-seam merge occurs.
    function mergeSegments(real) {
        var sorted = real.slice().sort(function (a, b) { return b.y - a.y; });
        var out = [], i = 0;
        while (i < sorted.length) {
            var j = i;
            while (j + 1 < sorted.length && Math.abs(sorted[j + 1].y - sorted[i].y) <= 2) j++;
            var row = sorted.slice(i, j + 1).sort(function (a, b) { return a.x - b.x; });
            var cur = { x: row[0].x, x2: row[0].x2, y: row[0].y, h: row[0].h, items: [row[0].item] };
            for (var k = 1; k < row.length; k++) {
                var limit = Math.max(COL_MIN_GUTTER_PX, SEG_GAP_EM * Math.max(cur.h, row[k].h));
                if (row[k].x - cur.x2 < limit) {
                    if (row[k].x2 > cur.x2) cur.x2 = row[k].x2;
                    cur.items.push(row[k].item);
                } else {
                    out.push(cur);
                    cur = { x: row[k].x, x2: row[k].x2, y: row[k].y, h: row[k].h, items: [row[k].item] };
                }
            }
            out.push(cur);
            i = j + 1;
        }
        return out;
    }

    function detectColumns(items) {
        var real = [];
        for (var a = 0; a < items.length; a++) {
            var it = items[a];
            if (!it.str || !it.str.trim()) continue;
            if (!it.transform) continue;
            // Rotated / skewed text: the shear terms are non-trivial. Today's code
            // ignores rotation; column geometry would mis-cluster it -> bail.
            if (Math.abs(it.transform[1]) > 0.01 || Math.abs(it.transform[2]) > 0.01) return null;
            var x = it.transform[4], w = it.width || 0, y = it.transform[5];
            real.push({ x: x, x2: x + w, y: y, h: Math.abs(it.transform[0]) || it.height || 10, item: it });
        }
        // Judge the layout on SEGMENTS (same-baseline items joined across word
        // gaps), not raw items: a PDF that carries one item per word would
        // otherwise inflate the crossing allowance below and let a single
        // column with few long lines pass for two columns.
        real = mergeSegments(real);
        if (real.length < MIN_COL_ITEMS) return null;

        // Robust content x-range (percentiles drop footer/margin outliers).
        var xs = real.map(function (r) { return r.x; });
        var x2s = real.map(function (r) { return r.x2; });
        var contentLo = percentile(xs, 0.02);
        var contentHi = percentile(x2s, 0.98);
        var span = contentHi - contentLo;
        if (span <= 0) return null;

        // Scan interior positions; a position is "open" (a gutter) if crossed by
        // few items (<= crossCap tolerates a full-width title/footer spanning it).
        // Group consecutive open positions into distinct gutter bands. Require
        // EXACTLY ONE central gutter: 0 => single column, >=2 => a 3+-column
        // layout (a documented deferral -> bail to prose, don't half-split it).
        var crossCap = Math.max(COL_CROSS_ABS, Math.floor(COL_CROSS_FRAC * real.length));
        var scanLo = contentLo + 0.12 * span, scanHi = contentHi - 0.12 * span;
        var step = Math.max(2, Math.round(span / 160));
        var gutters = [], inGut = false, gStart = 0;
        for (var g = scanLo; g <= scanHi; g += step) {
            var cross = 0;
            for (var k = 0; k < real.length; k++) {
                if (real[k].x < g && real[k].x2 > g) { cross++; if (cross > crossCap) break; }
            }
            var open = cross <= crossCap;
            if (open && !inGut) { inGut = true; gStart = g; }
            else if (!open && inGut) { inGut = false; gutters.push((gStart + (g - step)) / 2); }
        }
        if (inGut) gutters.push((gStart + scanHi) / 2);
        // Keep only gutters whose centre sits in the central band (a real column
        // gutter is not at the margin).
        var cenLo = contentLo + COL_CENTRAL_LO * span, cenHi = contentLo + COL_CENTRAL_HI * span;
        var central = gutters.filter(function (c) { return c >= cenLo && c <= cenHi; });
        if (central.length !== 1) return null;
        var bestG = central[0];

        // Split by item CENTER; require balance + both columns near full height.
        // A segment that crosses the gutter (a tolerated full-width line) belongs
        // to neither column: counted, it could lend a column the height or the
        // share it does not have.
        var left = [], right = [];
        for (var m = 0; m < real.length; m++) {
            if (real[m].x < bestG && real[m].x2 > bestG) continue;
            var cx = (real[m].x + real[m].x2) / 2;
            (cx < bestG ? left : right).push(real[m]);
        }
        var need = COL_BALANCE_FRAC * real.length;
        if (left.length < need || right.length < need) return null;

        // A true gutter is a real whitespace band. Measure it from items ENTIRELY
        // on one side of g: a full-width title/footer that crosses g is the
        // tolerated exception and must NOT collapse the measured gap.
        var leftMaxX2 = -Infinity, rightMinX = Infinity;
        for (var p = 0; p < real.length; p++) {
            if (real[p].x2 <= bestG && real[p].x2 > leftMaxX2) leftMaxX2 = real[p].x2;
            if (real[p].x >= bestG && real[p].x < rightMinX) rightMinX = real[p].x;
        }
        if (leftMaxX2 === -Infinity || rightMinX === Infinity) return null;
        if (rightMinX - leftMaxX2 < COL_MIN_GUTTER_PX) return null;

        // Both columns must span most of the total vertical text extent (a table's
        // short right cells fail this; real columns run nearly full height).
        var allY = real.map(function (r) { return r.y; });
        var totalH = percentile(allY, 0.98) - percentile(allY, 0.02);
        if (totalH <= 0) return null;
        var lY = left.map(function (r) { return r.y; });
        var rY = right.map(function (r) { return r.y; });
        var leftH = percentile(lY, 0.98) - percentile(lY, 0.02);
        var rightH = percentile(rY, 0.98) - percentile(rY, 0.02);
        if (leftH < COL_HEIGHT_FRAC * totalH || rightH < COL_HEIGHT_FRAC * totalH) return null;

        // The gates above classify by `bestG`; the emitted bands split at `mid`
        // (the gutter centre). Both lie inside the whitespace gutter, which holds
        // no item centres except a crossing full-width line, so at most that one
        // item could fall on a different side than the gates assumed — benign.
        var mid = (leftMaxX2 + rightMinX) / 2;
        var bands = [{ lo: -Infinity, hi: mid }, { lo: mid, hi: Infinity }];
        // Which band each item goes to, decided per SEGMENT: a full-width line
        // made of one item per word must land in one band whole, not be cut at
        // the gutter.
        var side = new Map();
        for (var q = 0; q < real.length; q++) {
            var b = ((real[q].x + real[q].x2) / 2) < mid ? 0 : 1;
            for (var z = 0; z < real[q].items.length; z++) side.set(real[q].items[z], b);
        }
        bands.side = side;
        return bands;
    }

    class PdfToMdParser {
        constructor() {
            this.pdfjsLib = null;
        }

        /**
         * Ensure PDF.js library is loaded
         */
        async ensureLibrary() {
            if (this.pdfjsLib) return;

            if (window.pdfjsLib) {
                this.pdfjsLib = window.pdfjsLib;
                // Worker vendored same-origin (it parses the user's raw PDF bytes) —
                // pinned in vendor/PROVENANCE.md, governed by worker-src/connect-src
                // 'self'. Must stay version-matched to the pdf.js <script> (3.11.174).
                this.pdfjsLib.GlobalWorkerOptions.workerSrc =
                    '/vendor/pdf/pdf.worker-3.11.174.min.js';
                return;
            }

            throw new Error('PDF.js library not loaded. Please check your internet connection.');
        }

        /**
         * Parse a PDF file (ArrayBuffer) and return Markdown text.
         * @param {ArrayBuffer} arrayBuffer - The PDF file data
         * @returns {Promise<string>} - Markdown output
         */
        async parse(arrayBuffer) {
            var bytes = (arrayBuffer && arrayBuffer.byteLength) || 0;
            if (bytes > MAX_PDF_BYTES) {
                // Throw a user-safe Error (xlsx userErr precedent) rather than
                // return the sentence: a returned sentence was downloaded as the
                // .md. The throw lands in the caller's catch BEFORE the OCR
                // threshold check, so it cannot trigger the OCR fallback.
                var limitErr = new Error('This PDF is over the ' + Math.round(MAX_PDF_BYTES / 1048576) +
                    ' MB limit for in-browser conversion.');
                limitErr.userMessage = true;
                throw limitErr;
            }
            await this.ensureLibrary();

            // This document is read for its text only: no font from the file is
            // added to the page, no code is generated from the file, and images
            // are never decoded (maxImageSize 0 drops every image).
            const task = this.pdfjsLib.getDocument({
                data: arrayBuffer,
                disableFontFace: true,
                isEvalSupported: false,
                useSystemFonts: false,
                maxImageSize: 0
            });
            const pages = [];
            const fontNames = Object.create(null);
            const fontState = { passes: 0, ms: 0 };
            let pdf = null;
            let totalPages = 0;

            try {
                pdf = await task.promise;
                totalPages = pdf.numPages;
                for (let i = 1; i <= totalPages; i++) {
                    const page = await pdf.getPage(i);
                    const textContent = await page.getTextContent();
                    await this.resolveFontNames(page, textContent.items, fontNames, fontState);
                    const pageData = this.extractPageStructure(textContent, fontNames);
                    pages.push(pageData);
                    try { if (typeof page.cleanup === 'function') page.cleanup(); } catch (e) { /* best effort */ }
                }
            } finally {
                // Also runs when the file could not be opened at all.
                try { if (pdf && typeof pdf.destroy === 'function') await pdf.destroy(); } catch (e) { /* best effort */ }
                try { if (task && typeof task.destroy === 'function') await task.destroy(); } catch (e) { /* best effort */ }
            }

            return this.convertToMarkdown(pages, totalPages);
        }

        /**
         * Extract structured lines from a page's text content. Tier 3 Cycle 2:
         * if a confident multi-column layout is detected, partition items into
         * column bands FIRST (which also fixes shared-baseline columns that the
         * y-only grouping would interleave), group each band top-to-bottom, and
         * concatenate left-to-right. No columns detected -> groupIntoLines over
         * all items = byte-identical to Tier 1+2.
         */
        /**
         * pdf.js names fonts by an internal id (g_d0_f2), which says nothing
         * about bold or italic. The real name is known once the page's operator
         * list has been built. That pass is only made for a page that brings a
         * font id not seen before, and at most MAX_FONT_PASSES times; a font
         * that stays unknown counts as regular. The name is only ever tested for
         * "bold"/"italic" words and is never written to the output.
         */
        async resolveFontNames(page, items, fontNames, state) {
            let missing = false;
            for (const item of items) {
                if (item.fontName && !(item.fontName in fontNames)) { missing = true; break; }
            }
            if (!missing) return;
            let loaded = false;
            if (state.passes < MAX_FONT_PASSES && state.ms < MAX_FONT_MS &&
                typeof page.getOperatorList === 'function') {
                state.passes++;
                const t0 = Date.now();
                // annotationMode 0 = DISABLE: form and annotation drawings are not built.
                try { await page.getOperatorList({ annotationMode: 0 }); loaded = true; } catch (e) { loaded = false; }
                state.ms += Date.now() - t0;
            }
            for (const item of items) {
                const id = item.fontName;
                if (!id || id in fontNames) continue;
                let name = '';
                if (loaded) {
                    try {
                        const font = page.commonObjs.has(id) ? page.commonObjs.get(id) : null;
                        if (font && typeof font.name === 'string') name = font.name;
                    } catch (e) { name = ''; }
                }
                fontNames[id] = name;
            }
        }

        extractPageStructure(textContent, fontNames) {
            const items = textContent.items;
            let bands = null;
            try { bands = detectColumns(items); } catch (e) { bands = null; }
            if (!bands) return { lines: this.groupIntoLines(items, fontNames) };

            // Every item goes to the band of its segment. A space item has no
            // segment: it follows the text item before it, so a full-width line
            // keeps its spaces on both sides of the gutter.
            const perBand = bands.map(() => []);
            let lastBand = -1;
            for (const it of items) {
                if (!it.transform) continue;
                let bi = -1;
                if (bands.side && bands.side.has(it)) bi = bands.side.get(it);
                else if (bands.side && lastBand !== -1 && (!it.str || !it.str.trim())) bi = lastBand;
                else {
                    const cx = it.transform[4] + (it.width || 0) / 2;
                    for (let k = 0; k < bands.length; k++) if (cx >= bands[k].lo && cx < bands[k].hi) { bi = k; break; }
                }
                if (bi === -1) continue;
                lastBand = bi;
                perBand[bi].push(it);
            }
            const lines = [];
            for (let bi = 0; bi < bands.length; bi++) {
                const bandItems = perBand[bi];
                const bl = this.groupIntoLines(bandItems, fontNames);
                for (let z = 0; z < bl.length; z++) lines.push(bl[z]);
            }
            return { lines };
        }

        /**
         * Group a run of pdf.js text items into lines by y-baseline. This is the
         * Tier 1+2 grouping loop VERBATIM; extracting it lets Cycle 2 call it
         * per-column-band without changing single-column behavior.
         */
        groupIntoLines(itemArray, fontNames) {
            const lines = [];
            let currentLine = null;
            let lastY = null;

            for (const item of itemArray) {
                const str = cleanGlyphs(item.str);
                if (!str || str.trim() === '') {
                    if (currentLine && str === ' ') {
                        currentLine.text += ' ';
                        currentLine.runs[currentLine.runs.length - 1].text += ' ';
                        // Where the space sits, for a line that has to be re-ordered.
                        if (item.transform) currentLine.spaces.push(item.transform[4]);
                    }
                    continue;
                }

                const y = Math.round(item.transform[5]);
                const x = Math.round(item.transform[4]);
                const fontSize = Math.round(item.transform[0]) || Math.round(item.height) || 12;
                // The real font name when it could be learned, else the id.
                const fontName = (fontNames && fontNames[item.fontName]) || item.fontName || '';
                const bold = this.isBoldFont(fontName);
                const italic = this.isItalicFont(fontName);

                if (lastY === null || Math.abs(y - lastY) > 2) {
                    // New line
                    if (currentLine) {
                        lines.push(currentLine);
                    }
                    currentLine = {
                        text: str,
                        x: x,
                        y: y,
                        fontSize: fontSize,
                        fontName: fontName,
                        isBold: bold,
                        isItalic: italic,
                        rtl: item.dir === 'rtl',
                        spaces: [],
                        items: [item],
                        // Normalized per-item geometry for Tier 3 table detection.
                        parts: [{ x: x, w: Math.round(item.width || 0), str: str, bold: bold, italic: italic }],
                        // The same text as stretches of one style, for inline emphasis.
                        runs: [{ text: str, bold: bold, italic: italic }]
                    };
                    lastY = y;
                } else {
                    // Same line - append text
                    const gap = x - (currentLine.x + this.estimateTextWidth(currentLine.text, currentLine.fontSize));
                    const piece = (gap > fontSize * 0.5 ? '  ' : '') + str;
                    currentLine.text += piece;
                    pushRun(currentLine.runs, piece, bold, italic);
                    if (item.dir === 'rtl') currentLine.rtl = true;
                    currentLine.items.push(item);
                    currentLine.parts.push({ x: x, w: Math.round(item.width || 0), str: str, bold: bold, italic: italic });
                    // Bold/italic only if EVERY item on the line qualifies, so
                    // one larger bold word doesn't bold the whole paragraph
                    // (the v1 false positive). Track the largest font size
                    // separately, for heading detection.
                    currentLine.isBold = currentLine.isBold && bold;
                    currentLine.isItalic = currentLine.isItalic && italic;
                    if (fontSize > currentLine.fontSize) {
                        currentLine.fontSize = fontSize;
                        currentLine.fontName = fontName;
                    }
                }
            }

            if (currentLine) {
                lines.push(currentLine);
            }

            for (const line of lines) reorderLine(line);
            return lines;
        }

        /**
         * Check if a font name indicates bold.
         */
        isBoldFont(fontName) {
            const lower = fontName.toLowerCase();
            // "Medium" is the bold face of several font families (Roboto among
            // them). Where a whole document is set in it, dominantStyle() ignores it.
            return lower.includes('bold') || lower.includes('heavy') || lower.includes('black') ||
                lower.includes('demi') || lower.includes('medium');
        }

        /**
         * Check if a font name indicates italic.
         */
        isItalicFont(fontName) {
            const lower = fontName.toLowerCase();
            // Adobe names shorten italic to a final "It" (MinionPro-It, -BoldIt).
            return lower.includes('italic') || lower.includes('oblique') || /[a-z-]It$/.test(fontName);
        }

        /**
         * Rough estimate of text width for gap detection.
         */
        estimateTextWidth(text, fontSize) {
            return text.length * fontSize * 0.5;
        }

        /**
         * Determine the heading level based on font size relative to body text.
         */
        getHeadingLevel(fontSize, bodyFontSize) {
            if (bodyFontSize === 0) return 0;
            const ratio = fontSize / bodyFontSize;

            if (ratio >= 2.0) return 1;
            if (ratio >= 1.6) return 2;
            if (ratio >= 1.3) return 3;
            if (ratio >= 1.15) return 4;
            return 0;
        }

        /**
         * Convert extracted page data into Markdown. Text content is escaped at
         * emit time (raw sink); structural markers (##, -, **, ---) are ours.
         * Blank pages are filtered so they do not leave stray `---` separators.
         */
        convertToMarkdown(pages, totalPages) {
            pages = stripPageFurniture(pages);

            // Determine the most common (body) font size across all pages
            const fontSizeCounts = {};
            for (const page of pages) {
                for (const line of page.lines) {
                    const fs = line.fontSize;
                    fontSizeCounts[fs] = (fontSizeCounts[fs] || 0) + 1;
                }
            }

            let bodyFontSize = 12;
            let maxCount = 0;
            for (const [size, count] of Object.entries(fontSizeCounts)) {
                if (count > maxCount) {
                    maxCount = count;
                    bodyFontSize = parseFloat(size);
                }
            }

            const style = dominantStyle(pages);
            const docLeading = typicalLeading(pages, bodyFontSize).gap;
            const pageBlocks = [];
            const budget = { outChars: 0, truncated: false };

            for (let p = 0; p < pages.length && !budget.truncated; p++) {
                const page = pages[p];
                // A page with enough body lines uses its own line spacing (a
                // double-spaced page in a single-spaced document).
                const own = typicalLeading([page], bodyFontSize);
                style.leading = own.n >= MIN_LEADING_SAMPLES ? own.gap : docLeading;
                const segments = this.buildPageSegments(page.lines, bodyFontSize, budget, style);
                let pageMd = segments.filter(Boolean).join('\n\n').replace(/\n{3,}/g, '\n\n').trim();
                if (pageMd) pageBlocks.push(pageMd);
            }

            let result = pageBlocks.join('\n\n---\n\n');
            if (budget.truncated) {
                result += '\n\n> _Output truncated: this PDF is larger than the in-browser converter handles._';
            }
            // Trojan-Source strip on the final string (covers synthesized table rows).
            result = result.replace(CTRL_BIDI_RE, '').replace(/\n{3,}/g, '\n\n').trim();
            return result ? result + '\n' : '';
        }

        /**
         * Split a page's lines into ordered segments: prose runs (Tier 1+2) and
         * detected tables (Tier 3). A page with NO detected table is one prose
         * segment -> emitLines over all lines -> byte-identical to Tier 1+2.
         * detectTables is wrapped: any error degrades to prose (never throws,
         * so a table bug can't wrongly trip the OCR fallback).
         */
        buildPageSegments(lines, bodyFontSize, budget, style) {
            let tables = [];
            try { tables = detectTables(lines, bodyFontSize); }
            catch (e) { tables = []; }
            if (!tables.length) return [this.emitLines(lines, bodyFontSize, budget, style)];

            const segs = [];
            let cursor = 0;
            for (const t of tables) {
                if (budget.truncated) break;
                if (t.startIdx > cursor) {
                    segs.push(this.emitLines(lines.slice(cursor, t.startIdx), bodyFontSize, budget, style));
                }
                if (budget.truncated) break;
                segs.push(this.emitTable(t.grid, budget));
                cursor = t.endIdx + 1;
            }
            if (!budget.truncated && cursor < lines.length) {
                segs.push(this.emitLines(lines.slice(cursor), bodyFontSize, budget, style));
            }
            return segs;
        }

        /**
         * Emit a run of lines as prose (headings/lists/emphasis/paragraphs).
         * This is the Tier 1+2 per-line loop, VERBATIM, with the output budget
         * threaded via a shared object. A no-table page routes entirely through
         * here, so its output is unchanged from Tier 1+2 (locked by a Node
         * byte-identity golden test).
         */
        emitLines(lines, bodyFontSize, budget, style) {
            const mdLines = [];
            let prevLineBlank = true;
            let inList = false;   // the block being written started with a list item
            let inToc = false;    // the line before was a table-of-contents entry
            let prev = null;
            const noBold = !!(style && style.noBold), noItalic = !!(style && style.noItalic);
            const leading = (style && style.leading) || 0;

            for (let i = 0; i < lines.length; i++) {
                if (budget.truncated) break;
                const line = lines[i];
                const rawText = String(line.text == null ? '' : line.text);
                const text = collapseSpaces(rawText.trim());

                if (!text) {
                    if (!prevLineBlank) {
                        mdLines.push('');
                        prevLineBlank = true;
                    }
                    continue;
                }

                // Structure is detected on the RAW text; only content is escaped.
                // Right after an entry, two leader dots are enough (a long title
                // leaves little room for dots).
                const tocEntry = splitTocEntry(text, inToc ? 2 : 4);
                inToc = !!tocEntry;
                const lineBold = !noBold && !!line.isBold, lineItalic = !noItalic && !!line.isItalic;
                const styled = hasStyledRun(line, noBold, noItalic);
                const listMatch = tocEntry ? null : rawText.trim().match(/^(\d+[\.\)]\s|[-•●◦▪▸►]\s)/);
                const isItem = !!(tocEntry || listMatch);

                // A wide vertical gap (or a jump back up the page: a new column)
                // starts a new paragraph. List items that follow each other stay
                // one list.
                if (prev && leading > 0 && !prevLineBlank) {
                    const gap = prev.y - line.y;
                    const scale = Math.max(1, Math.max(prev.fontSize || 0, line.fontSize || 0) / (bodyFontSize || 1));
                    if ((gap > leading * PARA_GAP * scale || gap < -leading) && !(isItem && inList)) {
                        mdLines.push('');
                        prevLineBlank = true;
                        inList = false;
                    }
                }
                prev = line;

                let emitted;
                let headingLevel = this.getHeadingLevel(line.fontSize, bodyFontSize);
                // A short, fully bold line a little larger than body text that
                // starts its own block and does not end like a sentence.
                if (headingLevel === 0 && lineBold && !isItem && prevLineBlank && text.length < 120 &&
                    bodyFontSize > 0 && line.fontSize / bodyFontSize >= SMALL_HEADING_RATIO &&
                    !/[.:;,]$/.test(text)) {
                    headingLevel = 5;
                }

                if (headingLevel > 0 && text.length < 200) {
                    const h = `${'#'.repeat(headingLevel)} ${escapeText(text)}`; // "# " in front: no line-start risk
                    if (!prevLineBlank) mdLines.push('');
                    mdLines.push(h);
                    mdLines.push('');
                    prevLineBlank = true;
                    inList = false;
                    emitted = h; // count real length toward the output budget
                } else {
                    if (tocEntry) {
                        emitted = `- ${escapeText(tocEntry.title)} ${ELLIPSIS} ${tocEntry.page}`;
                        inList = true;
                    } else if (listMatch) {
                        const prefix = listMatch[0];
                        const skip = (rawText.length - rawText.replace(/^\s+/, '').length) + prefix.length;
                        const content = styled
                            ? unmark(escapeLine(collapseSpaces(markRuns(line.runs, skip, noBold, noItalic)).trim()))
                            : escapeLine(collapseSpaces(rawText.trim().slice(prefix.length)).trim());
                        emitted = /^\d+[\.\)]/.test(prefix)
                            ? `${prefix.trim()} ${content}`
                            : `- ${content}`;
                        inList = true;
                    } else if (styled) {
                        // Escape FIRST (once, over the whole line), then turn the
                        // sentinels into ** and * (so a literal * can't break our
                        // delimiters).
                        emitted = unmark(escapeLine(collapseSpaces(markRuns(line.runs, 0, noBold, noItalic)).trim()));
                    } else {
                        // Lines without run data (older captures): whole-line flags.
                        const flagged = lineBold || lineItalic;
                        const safe = flagged ? escapeText(text) : escapeLine(text);
                        if (lineBold && lineItalic) emitted = `***${safe}***`;
                        else if (lineBold) emitted = `**${safe}**`;
                        else if (lineItalic) emitted = `*${safe}*`;
                        else emitted = safe;
                    }
                    mdLines.push(emitted);
                    prevLineBlank = false;
                }

                // Output-char budget (anti-bomb): count what we just pushed.
                budget.outChars += (emitted != null ? emitted.length : 0) + 1;
                if (budget.outChars > MAX_OUTPUT_CHARS) { budget.truncated = true; break; }
            }

            return mdLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
        }

        /**
         * Emit a detected grid as a GFM table. WE own every structural `|`, the
         * leading/trailing pipes, the header separator (fixed dash pattern), and
         * the column count (each row padded/truncated to the header width). Cell
         * text goes through formatCell (newline-collapse + escapeText), so a cell
         * containing `|`, `---`, or `<img>` cannot forge structure or inject.
         */
        emitTable(grid, budget) {
            const ncols = grid[0].length;
            const rowMd = (cells) => {
                const c = cells.slice(0, ncols);
                while (c.length < ncols) c.push('');
                return '| ' + c.map(formatCell).join(' | ') + ' |';
            };
            const out = [rowMd(grid[0])];
            out.push('| ' + new Array(ncols).fill('---').join(' | ') + ' |');
            for (let r = 1; r < grid.length; r++) out.push(rowMd(grid[r]));
            const md = out.join('\n');
            // Count synthesized cells toward the anti-bomb budget.
            budget.outChars += md.length + 1;
            if (budget.outChars > MAX_OUTPUT_CHARS) budget.truncated = true;
            return md;
        }
    }

    window.PdfToMdParser = PdfToMdParser;

    // Node-only test surface for the Tier 3 pure core + the pure convertToMarkdown
    // path. Gated on the absence of `document` so it never attaches in a browser.
    if (typeof document === 'undefined') {
        window.__pdfTest = {
            splitLineIntoCells: splitLineIntoCells,
            clusterPositions: clusterPositions,
            detectTables: detectTables,
            tryBuildTable: tryBuildTable,
            detectColumns: detectColumns,
            formatCell: formatCell,
            escapeText: escapeText
        };
    }
})();
