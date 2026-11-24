'use strict';
// One conversion per process. The converter runs in a worker thread with a
// heap cap; this main thread stays free to watch total memory, which also
// counts the buffers a heap cap does not see (a decompression bomb grows
// those). If the conversion crashes the process, only this file is lost.
require('./netguard').install();
const { runInThread } = require('./thread');

const MAX_RSS = 2048 * 1024 * 1024;
const MAX_RESULT = 256 * 1024 * 1024;

const reply = (msg) => process.send(msg, () => process.exit(0));

process.once('message', (job) => {
  const watch = setInterval(() => {
    if (process.memoryUsage.rss() > MAX_RSS) {
      clearInterval(watch);
      reply({ ok: false, error: 'conversion used too much memory (file too large or built to expand)' });
    }
  }, 100);
  runInThread(job.route, Buffer.from(job.input), { timeoutMs: job.timeoutMs, title: job.title }).then(
    (r) => {
      clearInterval(watch);
      const size = r.bytes ? r.bytes.length : r.text.length;
      if (size > MAX_RESULT) reply({ ok: false, error: 'the result is too large (over 256 MB)' });
      else reply({ ok: true, text: r.text, bytes: r.bytes });
    },
    (e) => { clearInterval(watch); reply({ ok: false, error: String((e && e.message) || e) }); }
  );
});
