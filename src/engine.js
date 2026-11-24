'use strict';
// Loads the converter files from lib/site/ unchanged and runs them under
// Node. Each file is evaluated with the handful of browser names it expects
// passed in as parameters. No global `document` is ever defined: several
// converters would try to add <script> tags if one existed.
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

function loadCjs(rel) {
  const mod = { exports: {} };
  new Function('module', 'exports', read(rel))(mod, mod.exports);
  return mod.exports;
}

function loadUmd(rel, globalName) {
  const g = {};
  const mod = { exports: {} };
  new Function('module', 'exports', 'window', 'self', 'globalThis', 'define', read(rel))
    .call(g, mod, mod.exports, g, g, g, undefined);
  const fromMod = mod.exports && (mod.exports[globalName] || (Object.keys(mod.exports).length ? mod.exports : null));
  return g[globalName] || fromMod || mod.exports;
}

// Replace exactly one occurrence, or fail loudly if the synced file changed.
function patchOnce(src, from, to, label) {
  const parts = src.split(from);
  if (parts.length !== 2) throw new Error('internal: expected one "' + label + '" in the converter source');
  return parts.join(to);
}

let cache = null;
function base() {
  if (cache) return cache;
  const win = { markdownit: loadCjs('vendor/markdown-it-14.3.0.min.js') };
  cache = { win };
  return cache;
}

const routes = {
  // Plain text to Markdown.
  'txt>md': async (input) => {
    const { win } = base();
    // Links to local files are not kept: the input may not be the user's own text.
    const src = patchOnce(read('lib/site/text-to-md-parser.js'),
      'var LOCAL_FILE_LINKS = true;', 'var LOCAL_FILE_LINKS = false;', 'LOCAL_FILE_LINKS');
    const mod = { exports: {} };
    new Function('window', 'module', 'exports', src)(win, mod, mod.exports);
    const Parser = mod.exports.TextToMarkdownParser;
    return { text: new Parser().parse(input.toString('utf8')) };
  },

  // Markdown to plain text.
  'md>txt': async (input, opts, dom) => {
    const { win } = base();
    new Function('window', 'DOMParser', read('lib/site/md-to-text-parser.js'))(win, dom && dom.DOMParser);
    return { text: new win.MarkdownToTextParser().parse(input.toString('utf8')) };
  },

  // Markdown to a Word document. Diagrams stay as code blocks.
  'md>docx': async (input) => {
    const { win } = base();
    if (!win.MarkdownBlockTokenizer) new Function('window', read('lib/site/markdown-block-tokenizer.js'))(win);
    const docx = loadUmd('vendor/docx-9.6.1.umd.js', 'docx');
    const Parser = new Function('window', 'docx', 'MarkdownBlockTokenizer',
      read('lib/site/md-to-docx-parser.js') + '\n;return MdToDocxParser;')(win, docx, win.MarkdownBlockTokenizer);
    const p = new Parser();
    const tokens = p.tokenizer.tokenize(input.toString('utf8'));
    p._mermaidImages = new Map();
    return { bytes: await docx.Packer.toBuffer(p._buildDocument(tokens)) };
  },
};

async function convert(route, input, opts) {
  const fn = routes[route];
  if (!fn) throw new Error('unsupported conversion: ' + route);
  return fn(Buffer.from(input), opts || {}, null);
}

module.exports = { convert, routes: Object.keys(routes) };
