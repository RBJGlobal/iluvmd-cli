#!/usr/bin/env node
'use strict';
require('../src/netguard').install();
require('../src/cli').main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (err) => { process.stderr.write('iluvmd: ' + String((err && err.message) || err) + '\n'); process.exitCode = 1; }
);
