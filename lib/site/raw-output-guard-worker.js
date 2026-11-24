/*
 * Second oracle for the raw-output guard (added 2026-11-15).
 *
 * Runs in a Web Worker. The page sends Markdown that text-to-md or
 * ai-chat-to-md already guarded with markdown-it as the first oracle; this
 * file asks a second, independent parser (marked, vendored and pinned) the
 * same question: "does any token in this text carry raw HTML?", plus one
 * about marked itself: "would any image alt text break out of its
 * attribute?" (marked does not escape alt text).
 *
 * The answer is a boolean and nothing else. The text never leaves the
 * device: the worker is same-origin, loads one same-origin script, and
 * makes no network call.
 *
 * Everything here fails closed. A throw (marked itself, a stack overflow on
 * deep nesting, memory) answers "not clean". A hang is the page's problem
 * to solve: it holds the deadline and terminates this worker
 * (raw-output-guard.js).
 *
 * Also loadable in Node for tests: `require()` returns { seesNoHtml }.
 */
(function (root) {
    'use strict';

    var MARKED_URL = '/vendor/marked/marked-15.0.12.umd.js';
    // Same pattern as the guard and both parsers (tests pin it).
    var TAG_LIKE_TEST_RE = /<(?=[A-Za-z\/!?])/;

    // True only when marked finds no html token anywhere in the tree, under
    // both the GFM and the plain CommonMark reading (tables and autolinks
    // change how a line is split, so both are asked).
    function seesNoHtml(marked, text) {
        if (!marked || typeof marked.Lexer !== 'function') return false;
        try {
            return lexClean(marked, text, true) && lexClean(marked, text, false);
        } catch (e) {
            return false;
        }
    }

    function lexClean(marked, text, gfm) {
        var lexer = new marked.Lexer({ gfm: gfm, breaks: false, pedantic: false });
        var tokens = lexer.lex(text);
        // An explicit stack, not recursion: token trees from hostile input
        // are deep. Every array and every object reachable from the tree is
        // visited (tokens, items, header, rows and whatever a later marked
        // version adds), so no container shape can hide an html token.
        var stack = [tokens], seen = 0;
        while (stack.length) {
            var node = stack.pop();
            if (!node || typeof node !== 'object') continue;
            if (++seen > 5000000) return false; // not provable in bounded work
            if (Array.isArray(node)) {
                for (var i = 0; i < node.length; i++) {
                    if (node[i] && typeof node[i] === 'object') stack.push(node[i]);
                }
                continue;
            }
            if (node.type === 'html') return false;
            // marked 15 writes image alt text into alt="..." without
            // escaping it (security reviews 2026-11-15). A double quote in
            // the alt ends the attribute: what follows becomes attributes
            // or, with a ">" and a "<" from separate tokens, an element,
            // with no html token and no tag-like "<" anywhere in the text.
            // An image is never clean when its alt holds a double quote
            // (in the source or as marked renders it) or its source holds
            // a tag-like "<".
            if (node.type === 'image' && !imageClean(marked, node)) return false;
            for (var key in node) {
                if (!Object.prototype.hasOwnProperty.call(node, key)) continue;
                var v = node[key];
                if (v && typeof v === 'object') stack.push(v);
            }
        }
        return true;
    }

    function imageClean(marked, node) {
        if (TAG_LIKE_TEST_RE.test(String(node.raw)) || TAG_LIKE_TEST_RE.test(String(node.text))) return false;
        if (String(node.text).indexOf('"') !== -1) return false;
        if (node.tokens) {
            // The alt exactly as marked's image renderer builds it.
            var parser = new marked.Parser();
            var alt = parser.parseInline(node.tokens, parser.textRenderer);
            if (String(alt).indexOf('"') !== -1) return false;
        }
        return true;
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { seesNoHtml: seesNoHtml };
        return;
    }

    // Worker context.
    var lib = null;
    try {
        root.importScripts(MARKED_URL);
        lib = root.marked || null;
    } catch (e) {
        lib = null; // every answer is "not clean"
    }

    root.onmessage = function (ev) {
        var data = ev && ev.data;
        if (!data || typeof data.id !== 'number') return;
        var clean = false;
        try {
            clean = typeof data.text === 'string' && seesNoHtml(lib, data.text) === true;
        } catch (e) {
            clean = false;
        }
        root.postMessage({ id: data.id, clean: clean });
    };
})(typeof self !== 'undefined' ? self : this);
