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
            real.push({ x: x, x2: x + w, y: y });
        }
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
        var left = [], right = [];
        for (var m = 0; m < real.length; m++) {
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
        return [{ lo: -Infinity, hi: mid }, { lo: mid, hi: Infinity }];
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

            const pdf = await this.pdfjsLib.getDocument({ data: arrayBuffer }).promise;
            const totalPages = pdf.numPages;
            const pages = [];

            for (let i = 1; i <= totalPages; i++) {
                const page = await pdf.getPage(i);
                const textContent = await page.getTextContent();
                const pageData = this.extractPageStructure(textContent);
                pages.push(pageData);
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
        extractPageStructure(textContent) {
            const items = textContent.items;
            let bands = null;
            try { bands = detectColumns(items); } catch (e) { bands = null; }
            if (!bands) return { lines: this.groupIntoLines(items) };

            const lines = [];
            for (const band of bands) {
                const bandItems = items.filter((it) => {
                    if (!it.transform) return false;
                    const cx = it.transform[4] + (it.width || 0) / 2;
                    return cx >= band.lo && cx < band.hi;
                });
                const bl = this.groupIntoLines(bandItems);
                for (let z = 0; z < bl.length; z++) lines.push(bl[z]);
            }
            return { lines };
        }

        /**
         * Group a run of pdf.js text items into lines by y-baseline. This is the
         * Tier 1+2 grouping loop VERBATIM; extracting it lets Cycle 2 call it
         * per-column-band without changing single-column behavior.
         */
        groupIntoLines(itemArray) {
            const lines = [];
            let currentLine = null;
            let lastY = null;

            for (const item of itemArray) {
                if (!item.str || item.str.trim() === '') {
                    if (currentLine && item.str === ' ') {
                        currentLine.text += ' ';
                    }
                    continue;
                }

                const y = Math.round(item.transform[5]);
                const x = Math.round(item.transform[4]);
                const fontSize = Math.round(item.transform[0]) || Math.round(item.height) || 12;
                const fontName = item.fontName || '';

                if (lastY === null || Math.abs(y - lastY) > 2) {
                    // New line
                    if (currentLine) {
                        lines.push(currentLine);
                    }
                    currentLine = {
                        text: item.str,
                        x: x,
                        y: y,
                        fontSize: fontSize,
                        fontName: fontName,
                        isBold: this.isBoldFont(fontName),
                        isItalic: this.isItalicFont(fontName),
                        items: [item],
                        // Normalized per-item geometry for Tier 3 table detection.
                        // Additive: the prose path never reads `parts`.
                        parts: [{ x: x, w: Math.round(item.width), str: item.str }]
                    };
                    lastY = y;
                } else {
                    // Same line - append text
                    const gap = x - (currentLine.x + this.estimateTextWidth(currentLine.text, currentLine.fontSize));
                    if (gap > fontSize * 0.5) {
                        currentLine.text += '  ' + item.str;
                    } else {
                        currentLine.text += item.str;
                    }
                    currentLine.items.push(item);
                    currentLine.parts.push({ x: x, w: Math.round(item.width), str: item.str });
                    // Bold/italic only if EVERY item on the line qualifies, so
                    // one larger bold word doesn't bold the whole paragraph
                    // (the v1 false positive). Track the largest font size
                    // separately, for heading detection.
                    currentLine.isBold = currentLine.isBold && this.isBoldFont(fontName);
                    currentLine.isItalic = currentLine.isItalic && this.isItalicFont(fontName);
                    if (fontSize > currentLine.fontSize) {
                        currentLine.fontSize = fontSize;
                        currentLine.fontName = fontName;
                    }
                }
            }

            if (currentLine) {
                lines.push(currentLine);
            }

            return lines;
        }

        /**
         * Check if a font name indicates bold.
         */
        isBoldFont(fontName) {
            const lower = fontName.toLowerCase();
            return lower.includes('bold') || lower.includes('heavy') || lower.includes('black');
        }

        /**
         * Check if a font name indicates italic.
         */
        isItalicFont(fontName) {
            const lower = fontName.toLowerCase();
            return lower.includes('italic') || lower.includes('oblique');
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

            const pageBlocks = [];
            const budget = { outChars: 0, truncated: false };

            for (let p = 0; p < pages.length && !budget.truncated; p++) {
                const page = pages[p];
                const segments = this.buildPageSegments(page.lines, bodyFontSize, budget);
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
        buildPageSegments(lines, bodyFontSize, budget) {
            let tables = [];
            try { tables = detectTables(lines, bodyFontSize); }
            catch (e) { tables = []; }
            if (!tables.length) return [this.emitLines(lines, bodyFontSize, budget)];

            const segs = [];
            let cursor = 0;
            for (const t of tables) {
                if (budget.truncated) break;
                if (t.startIdx > cursor) {
                    segs.push(this.emitLines(lines.slice(cursor, t.startIdx), bodyFontSize, budget));
                }
                if (budget.truncated) break;
                segs.push(this.emitTable(t.grid, budget));
                cursor = t.endIdx + 1;
            }
            if (!budget.truncated && cursor < lines.length) {
                segs.push(this.emitLines(lines.slice(cursor), bodyFontSize, budget));
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
        emitLines(lines, bodyFontSize, budget) {
            const mdLines = [];
            let prevLineBlank = true;

            for (let i = 0; i < lines.length; i++) {
                if (budget.truncated) break;
                const line = lines[i];
                const text = line.text.trim();

                if (!text) {
                    if (!prevLineBlank) {
                        mdLines.push('');
                        prevLineBlank = true;
                    }
                    continue;
                }

                let emitted;
                const headingLevel = this.getHeadingLevel(line.fontSize, bodyFontSize);

                if (headingLevel > 0 && text.length < 200) {
                    const h = `${'#'.repeat(headingLevel)} ${escapeText(text)}`;
                    if (!prevLineBlank) mdLines.push('');
                    mdLines.push(h);
                    mdLines.push('');
                    prevLineBlank = true;
                    emitted = h; // count real length toward the output budget
                } else {
                    // Detect list markers on the RAW text; escape only content.
                    const listMatch = text.match(/^(\d+[\.\)]\s|[-•●◦▪▸►]\s)/);
                    if (listMatch) {
                        const prefix = listMatch[0];
                        const content = escapeText(text.slice(prefix.length));
                        emitted = /^\d+[\.\)]/.test(prefix)
                            ? `${prefix.trim()} ${content}`
                            : `- ${content}`;
                    } else {
                        // Escape FIRST, then wrap emphasis (so a literal * can't
                        // break our **/* delimiters).
                        const safe = escapeText(text);
                        if (line.isBold && line.isItalic) emitted = `***${safe}***`;
                        else if (line.isBold) emitted = `**${safe}**`;
                        else if (line.isItalic) emitted = `*${safe}*`;
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
