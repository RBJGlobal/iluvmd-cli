/*
 * Raw-output guard, page side (added 2026-11-15).
 *
 * text-to-md and ai-chat-to-md hand Markdown to Copy and Download as raw
 * text (no DOMPurify). Their parsers already entity-encode every tag-like
 * "<" that markdown-it would read as HTML. Other renderers read fences,
 * list markers and code spans differently, so this file asks a second
 * parser (marked, in raw-output-guard-worker.js) before the text leaves
 * the page:
 *
 *   finalize(text) resolves to
 *     - text, unchanged, when it has no tag-like "<" and no image opener
 *       "![" at all (no worker), or
 *       when the worker answers "clean" inside the deadline;
 *     - fullEncode(text) in every other case: marked saw HTML, the text is
 *       larger than MAX_ORACLE_CHARS, the worker missed the deadline,
 *       threw, could not start, or answered anything that is not exactly
 *       { clean: true }.
 *
 * fullEncode leaves no tag-like "<" anywhere, code included, and no image
 * opener. A literal "&lt;" inside a code block is the safe direction; no
 * renderer can read a tag out of text that has none. The result is stable: finalize of an
 * encoded text returns it as is.
 *
 * The promise never rejects and the text is never sent anywhere but the
 * same-origin worker.
 */
(function (root) {
    'use strict';

    // Same pattern as TAG_LIKE_RE / TAG_LIKE_TEST_RE in text-to-md-parser.js
    // and ai-chat-to-md-parser.js (tests/run-escaper-parity.js pins it).
    var TAG_LIKE_RE = /<(?=[A-Za-z\/!?])/g;
    var TAG_LIKE_TEST_RE = /<(?=[A-Za-z\/!?])/;
    var IMAGE_OPEN_RE = /!\[/g;

    var DEADLINE_MS = 2000;
    // marked's memory grows steeply with nesting depth (a 250 KB list
    // nested 500 deep: 0.5 s and about 200 MB; 1 MB: 3.6 s and 800 MB,
    // measured 2026-11-15). Above this size the worker is not asked and
    // the text is fully encoded.
    var MAX_ORACLE_CHARS = 256 * 1024;
    var WORKER_URL = 'raw-output-guard-worker.js?v=20261115a';

    // The fail-closed form: no tag-like "<" and no image opener "![" is
    // left. Without "![" no renderer builds an image, so marked's unescaped
    // alt attribute (see the worker) cannot be reached; the image shows as
    // its literal Markdown text instead.
    function fullEncode(text) {
        return String(text).replace(TAG_LIKE_RE, '&lt;').replace(IMAGE_OPEN_RE, '!&#91;');
    }

    // Text with neither needs no second check.
    function needsCheck(text) {
        return TAG_LIKE_TEST_RE.test(text) || text.indexOf('![') !== -1;
    }

    // deps (all optional, for tests): createWorker(), setTimeout,
    // clearTimeout, deadlineMs.
    function create(deps) {
        deps = deps || {};
        var setT = deps.setTimeout || function (fn, ms) { return setTimeout(fn, ms); };
        var clearT = deps.clearTimeout || function (h) { clearTimeout(h); };
        var deadlineMs = deps.deadlineMs || DEADLINE_MS;
        var createWorker = deps.createWorker || function () { return new Worker(WORKER_URL); };

        var worker = null;
        var nextId = 1;
        var flight = null;   // { id, text, promise, settle, timer }
        var last = null;     // { text, result } of the latest settled request

        function dropWorker() {
            if (!worker) return;
            var w = worker;
            worker = null;
            try { w.onmessage = null; w.onerror = null; w.onmessageerror = null; } catch (e) { /* ignore */ }
            try { w.terminate(); } catch (e) { /* ignore */ }
        }

        // Settle the request in flight. clean === true is the only value
        // that lets the text through unchanged. `remember` false is for a
        // request pushed aside by a newer one: nothing was learned about
        // its text, so the encoded result is not kept as the answer.
        function settle(f, clean, remember) {
            if (flight !== f) return;
            flight = null;
            clearT(f.timer);
            var result = clean === true ? f.text : fullEncode(f.text);
            if (remember !== false) last = { text: f.text, result: result };
            f.resolve(result);
        }

        function failClosed(f, remember) {
            // The worker is in an unknown state (hung, crashed, stale):
            // never reuse it.
            dropWorker();
            settle(f, false, remember);
        }

        function ensureWorker() {
            if (worker) return worker;
            var w = createWorker();
            w.onmessage = function (ev) {
                var f = flight, d = ev && ev.data;
                if (worker !== w || !f || !d || d.id !== f.id) return; // stale answer
                if (d.clean === true) settle(f, true); else failClosed(f);
            };
            w.onerror = function (ev) {
                if (ev && typeof ev.preventDefault === 'function') ev.preventDefault();
                if (worker === w && flight) failClosed(flight);
                else if (worker === w) dropWorker();
            };
            w.onmessageerror = w.onerror;
            worker = w;
            return w;
        }

        // Result already known for exactly this text, or null. Synchronous,
        // so a click handler can copy without waiting.
        function peek(text) {
            text = String(text);
            if (!needsCheck(text)) return text;
            if (text.length > MAX_ORACLE_CHARS) return fullEncode(text);
            if (last && last.text === text) return last.result;
            return null;
        }

        function finalize(text) {
            text = String(text);
            var known = peek(text);
            if (known !== null) return Promise.resolve(known);
            if (flight && flight.text === text) return flight.promise;
            // One request at a time. A different text in flight is stale
            // (the output changed): it settles fail closed and its worker
            // is replaced, so this request gets the whole deadline.
            if (flight) failClosed(flight, false);

            var f = { id: nextId++, text: text, promise: null, resolve: null, timer: null };
            f.promise = new Promise(function (resolve) { f.resolve = resolve; });
            flight = f;
            try {
                var w = ensureWorker();
                f.timer = setT(function () { if (flight === f) failClosed(f); }, deadlineMs);
                w.postMessage({ id: f.id, text: text });
            } catch (e) {
                failClosed(f);
            }
            return f.promise;
        }

        return { finalize: finalize, peek: peek, fullEncode: fullEncode };
    }

    var api = { create: create, fullEncode: fullEncode, DEADLINE_MS: DEADLINE_MS, MAX_ORACLE_CHARS: MAX_ORACLE_CHARS };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
        return;
    }
    root.iLoveMD = root.iLoveMD || {};
    var guard = create();
    root.iLoveMD.rawOutputGuard = {
        finalize: guard.finalize,
        peek: guard.peek,
        fullEncode: fullEncode
    };
})(typeof window !== 'undefined' ? window : this);
