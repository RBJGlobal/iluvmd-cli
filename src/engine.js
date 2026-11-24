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

// Converter files log to the console in a browser. Here that would corrupt
// piped output, so they get a silent console.
const quiet = { log() {}, debug() {}, info() {}, warn() {}, error() {} };

// An inert DOM for the converters that parse HTML or XML: scripts never run
// and nothing is ever loaded (jsdom's defaults, stated here on purpose).
let domCache = null;
function dom() {
  if (domCache) return domCache;
  const { JSDOM } = require('jsdom');
  const jsdom = new JSDOM('<!doctype html><html><body></body></html>', {
    url: 'about:blank', runScripts: undefined, resources: undefined, pretendToBeVisual: false,
  });
  domCache = { window: jsdom.window, DOMParser: jsdom.window.DOMParser };
  return domCache;
}

function htmlToMdParser() {
  const { win } = base();
  if (!win.HtmlToMarkdownParser) {
    new Function('window', 'DOMParser', 'console', read('lib/site/html-to-md-parser.js'))(win, dom().DOMParser, quiet);
  }
  return win.HtmlToMarkdownParser;
}

const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// True for an image address that would be fetched from somewhere else when
// the page is opened: anything with a scheme other than data:, or a
// protocol-relative address. Relative paths to local files are kept.
function isRemoteSrc(src) {
  const v = String(src).trim().replace(/[\\]/g, '/');
  if (v.startsWith('//')) return true;
  const m = /^([a-z][a-z0-9+.-]*):/i.exec(v);
  return !!m && m[1].toLowerCase() !== 'data';
}

// The page allows no scripts, no network and no remote images.
const PAGE_CSP = "default-src 'none'; img-src data: file:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";
const PAGE_CSS = [
  'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:800px;margin:0 auto;padding:40px 20px;line-height:1.6;color:#2c3e50}',
  'h1,h2,h3,h4,h5,h6{margin-top:1.5em}h1{border-bottom:2px solid #e1e8ed;padding-bottom:.3em}',
  'code{background:#f8f9fa;padding:2px 6px;border-radius:4px;font-size:.9em}',
  'pre{background:#f8f9fa;padding:15px;border-radius:8px;overflow-x:auto}pre code{background:transparent;padding:0}',
  'blockquote{border-left:4px solid #ccd3da;margin:1em 0;padding:10px 20px;background:#f8f9fa}',
  'table{border-collapse:collapse}th,td{border:1px solid #e1e8ed;padding:6px 12px}img{max-width:100%}',
].join('');

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
  'md>txt': async (input) => {
    const { win } = base();
    new Function('window', 'DOMParser', 'console', read('lib/site/md-to-text-parser.js'))(win, dom().DOMParser, quiet);
    return { text: new win.MarkdownToTextParser().parse(input.toString('utf8')) };
  },

  // Markdown to a standalone HTML page. The HTML is sanitized by DOMPurify
  // in a real DOM, exactly as on the site. Remote images become links.
  'md>html': async (input, opts) => {
    const { win } = base();
    const d = dom();
    const DOMPurify = require('dompurify')(d.window);
    if (!DOMPurify.isSupported) throw new Error('internal: the HTML sanitizer could not start');
    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
      if (node.tagName !== 'IMG') return;
      const src = node.getAttribute('src') || '';
      if (!isRemoteSrc(src)) return;
      const link = node.ownerDocument.createElement('a');
      link.setAttribute('href', src);
      link.setAttribute('rel', 'noopener noreferrer');
      link.textContent = node.getAttribute('alt') || src;
      if (node.parentNode) node.parentNode.replaceChild(link, node);
    });
    const btoa = (str) => Buffer.from(str, 'binary').toString('base64');
    new Function('window', 'DOMPurify', 'btoa', 'console', read('lib/site/markdown-parser.js'))(win, DOMPurify, btoa, quiet);
    const body = new win.MarkdownParser().parse(input.toString('utf8'));
    const page = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n' +
      '<meta http-equiv="Content-Security-Policy" content="' + PAGE_CSP + '">\n' +
      '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
      '<title>' + escapeHtml(opts.title || 'Document') + '</title>\n<style>' + PAGE_CSS + '</style>\n</head>\n<body>\n' +
      body + '\n</body>\n</html>\n';
    return { text: page };
  },

  // HTML to Markdown.
  'html>md': async (input) => {
    const Parser = htmlToMdParser();
    return { text: new Parser().parse(input.toString('utf8')) };
  },

  // Word document to Markdown. Images are kept as alt text only, and the
  // library is never allowed to read files the document links to.
  'docx>md': async (input) => {
    const { win } = base();
    htmlToMdParser();
    if (!win.JSZip) win.JSZip = loadUmd('vendor/jszip-3.10.1.min.js', 'JSZip');
    const real = require('mammoth');
    const mammoth = {
      images: real.images,
      convertToHtml: (src, options) => real.convertToHtml(
        { buffer: Buffer.from(src.arrayBuffer) },
        Object.assign({}, options, { externalFileAccess: false })),
    };
    if (!win.DocxToMarkdownParser) {
      new Function('window', 'DOMParser', 'mammoth', 'console', read('lib/site/docx-to-md-parser.js'))(win, dom().DOMParser, mammoth, quiet);
    }
    const bytes = new Uint8Array(input);
    return { text: await new win.DocxToMarkdownParser().parse(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)) };
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
  return fn(Buffer.from(input), opts || {});
}

module.exports = { convert, routes: Object.keys(routes) };
