#!/usr/bin/env node
'use strict';
require('../src/netguard').install();
// A reader that stops early (for example "| head") is not an error.
process.stdout.on('error', (e) => { if (e && e.code === 'EPIPE') process.exit(process.exitCode || 0); else throw e; });
require('../src/cli').main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (err) => { process.stderr.write('iluvmd: ' + String((err && err.message) || err) + '\n'); process.exitCode = 1; }
);
