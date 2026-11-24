'use strict';
const path = require('path');
const { Worker } = require('worker_threads');

const DEFAULT_TIMEOUT_MS = 60_000;
const HEAP_MB = 768;

// Runs one conversion in a worker thread of this (child) process. Resolves { text } or { bytes }; rejects
// with a plain Error on failure, timeout or memory exhaustion.
function runInThread(route, input, opts) {
  const timeoutMs = opts && opts.timeoutMs != null ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'worker.js'), {
      workerData: { route, input, opts: { title: opts && opts.title } },
      resourceLimits: { maxOldGenerationSizeMb: HEAP_MB, maxYoungGenerationSizeMb: 64, stackSizeMb: 8 },
      // Captured and never forwarded: converter or library output must not
      // reach this process's standard output.
      stdout: true,
      stderr: true,
    });
    // Drop whatever the libraries print.
    worker.stdout.resume();
    worker.stderr.resume();
    let done = false;
    const finish = (fn, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      worker.terminate();
      fn(value);
    };
    const timer = setTimeout(() => finish(reject,
      new Error('conversion stopped after ' + (timeoutMs / 1000) + ' s (use --timeout to allow more)')), timeoutMs);
    worker.on('message', (m) => {
      if (m.ok) finish(resolve, { text: m.text, bytes: m.bytes && Buffer.from(m.bytes) });
      else finish(reject, new Error(m.error));
    });
    worker.on('error', (e) => finish(reject,
      new Error(e && e.code === 'ERR_WORKER_OUT_OF_MEMORY' ? 'conversion ran out of memory (file too large or malformed)' : String((e && e.message) || e))));
    worker.on('exit', (code) => finish(reject, new Error('conversion stopped unexpectedly (code ' + code + ')')));
  });
}

module.exports = { runInThread, DEFAULT_TIMEOUT_MS, HEAP_MB };
