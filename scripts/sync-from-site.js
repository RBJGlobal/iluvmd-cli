#!/usr/bin/env node
// Copies the converter files this tool uses from a checkout of the iluvmd.com
// site, byte for byte, into lib/site/ and vendor/, and writes a SHA-256
// manifest. The site checkout is the source of truth; files under lib/site/
// and vendor/ are never edited here.
//
//   node scripts/sync-from-site.js <path-to-site-checkout>
//   node scripts/sync-from-site.js --check     (verify the manifest only)
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const MANIFEST = path.join(ROOT, 'lib', 'MANIFEST.sha256');

// [source path in the site checkout, destination path here]
const FILES = [
  ['text-to-md-parser.js', 'lib/site/text-to-md-parser.js'],
  ['markdown-block-tokenizer.js', 'lib/site/markdown-block-tokenizer.js'],
  ['md-to-docx-parser.js', 'lib/site/md-to-docx-parser.js'],
  ['md-to-text-parser.js', 'lib/site/md-to-text-parser.js'],
  ['markdown-parser.js', 'lib/site/markdown-parser.js'],
  ['html-to-md-parser.js', 'lib/site/html-to-md-parser.js'],
  ['docx-to-md-parser.js', 'lib/site/docx-to-md-parser.js'],
  ['vendor/markdown-it/markdown-it-14.3.0.min.js', 'vendor/markdown-it-14.3.0.min.js'],
  ['vendor/docx-9.6.1.umd.js', 'vendor/docx-9.6.1.umd.js'],
  ['vendor/jszip/jszip-3.10.1.min.js', 'vendor/jszip-3.10.1.min.js'],
];

// Words that must not appear in a synced converter file (vendor bundles are
// third-party and are not scanned).
const BANNED = /\b(founder|backlog|handoff|advisor)\b|CLAUDE\.md|HANDOVER/i;

const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function check() {
  if (!fs.existsSync(MANIFEST)) { console.error('No manifest. Run the sync first.'); return 1; }
  let bad = 0;
  for (const line of fs.readFileSync(MANIFEST, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    const [hash, rel] = line.split('  ');
    const file = path.join(ROOT, rel);
    const got = fs.existsSync(file) ? sha(fs.readFileSync(file)) : 'missing';
    if (got !== hash) { bad++; console.error('MISMATCH ' + rel); }
  }
  console.log(bad ? bad + ' file(s) differ from the manifest' : 'manifest OK');
  return bad ? 1 : 0;
}

function sync(site) {
  const lines = [];
  for (const [src, dest] of FILES) {
    const buf = fs.readFileSync(path.join(site, src));
    if (dest.startsWith('lib/site/')) {
      const hit = buf.toString('utf8').split('\n').findIndex((l) => BANNED.test(l));
      if (hit !== -1) throw new Error(src + ':' + (hit + 1) + ' contains a word that is not allowed in a published file');
    }
    const out = path.join(ROOT, dest);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, buf);
    lines.push(sha(buf) + '  ' + dest);
  }
  fs.writeFileSync(MANIFEST, lines.join('\n') + '\n');
  console.log('synced ' + FILES.length + ' files');
  return 0;
}

const arg = process.argv[2];
if (!arg) { console.error('usage: sync-from-site.js <site-checkout> | --check'); process.exit(2); }
process.exit(arg === '--check' ? check() : sync(path.resolve(arg)));
