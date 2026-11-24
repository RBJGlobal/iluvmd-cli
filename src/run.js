'use strict';
const path = require('path');
const { fork } = require('child_process');
const { DEFAULT_TIMEOUT_MS, HEAP_MB } = require('./thread');

// The child gets only what a process needs to start, so settings such as
// NODE_OPTIONS in the caller's environment cannot change how it runs.
function childEnv() {
  const env = {};
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR']) {
    if (process.env[key] != null) env[key] = process.env[key];
  }
  return env;
}

// Runs one conversion in its own process (see child.js). Resolves { text }
// or { bytes }; rejects with a plain Error on failure, timeout, memory
// exhaustion or a crash. Nothing the child prints reaches this process.
function runConversion(route, input, opts) {
  const timeoutMs = opts && opts.timeoutMs != null ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    const child = fork(path.join(__dirname, 'child.js'), [], {
      serialization: 'advanced',
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      execArgv: ['--max-old-space-size=' + HEAP_MB],
      env: childEnv(),
    });
    let done = false;
    const finish = (fn, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { child.kill('SIGKILL'); } catch (e) { /* already gone */ }
      fn(value);
    };
    // The thread inside the child has the same limit; this one also covers a
    // child that stops answering.
    const timer = setTimeout(() => finish(reject,
      new Error('conversion stopped after ' + (timeoutMs / 1000) + ' s (use --timeout to allow more)')), timeoutMs + 2000);
    child.on('message', (m) => {
      if (m && m.ok) finish(resolve, { text: m.text, bytes: m.bytes && Buffer.from(m.bytes) });
      else finish(reject, new Error((m && m.error) || 'conversion failed'));
    });
    child.on('error', (e) => finish(reject, new Error('could not start the conversion: ' + ((e && e.code) || e))));
    child.on('exit', () => finish(reject, new Error('conversion ran out of memory or crashed (file too large or malformed)')));
    child.send({ route, input, timeoutMs, title: opts && opts.title }, (e) => {
      if (e) finish(reject, new Error('could not start the conversion: ' + ((e && e.code) || e)));
    });
  });
}

module.exports = { runConversion, DEFAULT_TIMEOUT_MS };
