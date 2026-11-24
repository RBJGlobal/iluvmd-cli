'use strict';
// One conversion runs here, in a worker thread with a memory cap, so a
// hostile or huge file cannot take down the calling process.
const { parentPort, workerData } = require('worker_threads');
require('./netguard').install();
const { convert } = require('./engine');

convert(workerData.route, workerData.input, workerData.opts).then(
  (r) => parentPort.postMessage({ ok: true, text: r.text, bytes: r.bytes }),
  (e) => parentPort.postMessage({ ok: false, error: String((e && e.message) || e) })
);
