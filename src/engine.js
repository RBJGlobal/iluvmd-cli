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

function loadUmd(rel, globalName, preset) {
  const g = Object.assign({}, preset);
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

// Text input must be UTF-8. A byte order mark at the start is dropped.
function decode(buf) {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch (e) {
    throw new Error('the input is not UTF-8 text');
  }
}

// Each site converter has an input limit. Over the limit some of them cut
// the text short or return a notice as if it were the result, which a
// script cannot tell from success. So the limit is checked here first, and
// the number is confirmed against the converter's own source: if a sync
// changes it, loading fails instead of drifting.
function limit(rel, literal, value, what, size, unit) {
  if (read(rel).split(literal).length !== 2) throw new Error('internal: input limit changed in ' + rel);
  if (size > value) {
    throw new Error('input is over the ' + what + ' limit of ' + value.toLocaleString('en-US') + ' ' + unit);
  }
}
const MB = 1024 * 1024;

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
    // On the site this converter never throws: over its limit it returns a
    // notice, and on a failure (for example nesting too deep) it returns
    // nothing. Written to a file, both would look like a result, so here
    // they are errors. This also covers the HTML a Word file expands to.
    let src = read('lib/site/html-to-md-parser.js');
    src = patchOnce(src, "return 'This HTML is over the '", "throw new Error('the content is over the 30 MB limit for conversion to Markdown'); return 'This HTML is over the '", 'HTML limit notice');
    src = patchOnce(src, "return this.cleanMarkdown(md);\n            } catch (e) {\n                return '';",
      "return this.cleanMarkdown(md);\n            } catch (e) {\n                throw new Error('the HTML could not be converted (it may be nested too deeply)');", 'HTML failure');
    new Function('window', 'DOMParser', 'console', src)(win, dom().DOMParser, quiet);
  }
  return win.HtmlToMarkdownParser;
}

const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// What an address in the page would load from when the page is opened from
// a local file. Resolved the way a browser does it, so tabs, control
// characters, backslashes and "//host" forms cannot hide a remote host.
// 'local' is a data: address or a file on this machine; 'web' is http(s);
// anything else (another scheme, or a file address that names a host or
// could be read as one, which is a network share) is 'other'.
function addressKind(value) {
  let u;
  try { u = new URL(String(value), 'file:///x/y'); } catch (e) { return 'other'; }
  if (u.protocol === 'data:') return 'local';
  // A path with an empty segment ("//host/share", however it was spelled)
  // can be read as a network share, so it is not local either.
  if (u.protocol === 'file:') return u.host === '' && !u.pathname.includes('//') ? 'local' : 'other';
  if (u.protocol === 'http:' || u.protocol === 'https:') return 'web';
  return 'other';
}

// Attributes that make a browser load something without a click.
const LOADING_ATTRS = ['srcset', 'poster', 'background', 'ping', 'lowsrc', 'dynsrc', 'data', 'action', 'formaction', 'manifest'];

// Runs on every element after sanitizing: nothing may be left that loads
// from another machine when the page is opened.
function stripRemoteLoads(node) {
  if (!node || typeof node.getAttribute !== 'function') return;
  for (const name of LOADING_ATTRS) if (node.hasAttribute(name)) node.removeAttribute(name);
  // A style attribute can load an image; only plain declarations are kept.
  const style = node.getAttribute('style');
  if (style != null && /[(\\@]/.test(style)) node.removeAttribute('style');
  for (const name of ['href', 'xlink:href']) {
    if (node.tagName !== 'A' && node.tagName !== 'AREA' && node.hasAttribute(name) && !String(node.getAttribute(name)).startsWith('#')) node.removeAttribute(name);
  }
  if (!node.hasAttribute('src')) return;
  const src = node.getAttribute('src');
  const kind = addressKind(src);
  if (kind === 'local') return;
  if (node.tagName !== 'IMG') { node.removeAttribute('src'); return; }
  // A remote image becomes a link (web addresses) or its alt text.
  const doc = node.ownerDocument;
  const label = node.getAttribute('alt') || (kind === 'web' ? src : 'image');
  let swap = doc.createTextNode(label);
  if (kind === 'web') {
    swap = doc.createElement('a');
    swap.setAttribute('href', new URL(src, 'file:///x/y').href);
    swap.setAttribute('rel', 'noopener noreferrer');
    swap.textContent = label;
  }
  if (node.parentNode) node.parentNode.replaceChild(swap, node);
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
  '.md-align-left{text-align:left}.md-align-center{text-align:center}.md-align-right{text-align:right}',
].join('');

// The site checks Markdown that leaves as raw text with a second parser
// (marked): if that parser would read any HTML out of it, every tag-like "<"
// and image opener is encoded. The same two files run here; the "worker" is
// a plain object, since each conversion already runs in its own thread.
let guardCache = null;
function rawOutputGuard() {
  if (guardCache) return guardCache;
  const marked = loadUmd('vendor/marked-15.0.12.umd.js', 'marked');
  const oracle = loadCjs('lib/site/raw-output-guard-worker.js');
  const createWorker = () => {
    const w = {
      onmessage: null,
      terminate() { w.onmessage = null; },
      postMessage(msg) {
        let ok = false;
        try { ok = oracle.seesNoHtml(marked, msg.text) === true; } catch (e) { ok = false; }
        queueMicrotask(() => { if (w.onmessage) w.onmessage({ data: { id: msg.id, clean: ok } }); });
      },
    };
    return w;
  };
  guardCache = loadCjs('lib/site/raw-output-guard.js').create({ createWorker });
  return guardCache;
}

// The PDF library is a browser bundle. It gets its own small set of browser
// names and nothing else; it attaches itself to that object.
let pdfCache = null;
function pdfMake() {
  if (pdfCache) return pdfCache;
  const g = {
    navigator: { userAgent: 'node', platform: 'node' },
    setTimeout, clearTimeout, setImmediate, Blob, URL, TextDecoder, TextEncoder, console: quiet,
  };
  g.window = g; g.self = g;
  new Function('window', 'self', 'globalThis', 'module', 'exports', 'define', 'navigator', 'console',
    read('vendor/pdfmake-0.3.8.min.js')).call(g, g, g, g, undefined, undefined, undefined, g.navigator, quiet);
  const lib = g.pdfMake;
  if (!lib || typeof lib.createPdf !== 'function') throw new Error('internal: the PDF library could not start');
  new Function('window', 'self', 'globalThis', 'pdfMake', 'module', 'exports', 'define',
    read('vendor/pdfmake-0.3.8.vfs_fonts.js')).call(g, g, g, g, lib, undefined, undefined, undefined);
  // The library may never fetch an address or read a local file.
  // This build has a setter for addresses and a plain property for files.
  if (typeof lib.setUrlAccessPolicy !== 'function' || !('localAccessPolicy' in lib)) {
    throw new Error('internal: the PDF library has no access policy; refusing to continue');
  }
  lib.setUrlAccessPolicy(() => false);
  lib.localAccessPolicy = () => false;
  pdfCache = lib;
  return lib;
}

// In Markdown made from HTML or Word, a link or image target that starts
// with two slashes or backslashes ("//host/...", "/\host", "\\host") would
// be read as a network share by a viewer showing a local file. Slash-only
// forms become https addresses; forms with a backslash become a "#" target
// that goes nowhere. Code is not skipped: deciding what is code differently
// from a viewer would reopen the hole. Each pattern scans in linear time.
function tameTargets(md) {
  return md.replace(/\]\([ \t\r\n]*(<[ \t]*)?([\\/]{2,})/g,
    (all, open, lead) => '](' + (open ? '<' : '') + (lead.includes('\\') ? '#' : 'https://'));
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
    const text = decode(input);
    limit('lib/site/text-to-md-parser.js', 'var MAX_INPUT_CHARS = 25 * 1024 * 1024;', 25 * MB, 'text to Markdown', text.length, 'characters');
    const md = new Parser().parse(text);
    return { text: await rawOutputGuard().finalize(md) };
  },

  // Markdown to plain text.
  'md>txt': async (input) => {
    const { win } = base();
    // Over its output limit the site converter cuts the text short; here that is an error.
    const src = patchOnce(read('lib/site/md-to-text-parser.js'), 'out = out.slice(0, MAX_OUTPUT_CHARS);',
      "throw new Error('the result is over the Markdown to text output limit');", 'text output limit');
    new Function('window', 'DOMParser', 'console', src)(win, dom().DOMParser, quiet);
    const text = decode(input);
    limit('lib/site/md-to-text-parser.js', 'var MAX_INPUT_CHARS = 1024 * 1024;', MB, 'Markdown to text', text.length, 'characters');
    return { text: new win.MarkdownToTextParser().parse(text) };
  },

  // Markdown to a standalone HTML page. The HTML is sanitized by DOMPurify
  // in a real DOM, exactly as on the site. Remote images become links.
  'md>html': async (input, opts) => {
    const { win } = base();
    const text = decode(input);
    limit('lib/site/markdown-parser.js', 'var MAX_INPUT_CHARS = 1024 * 1024;', MB, 'Markdown to HTML', text.length, 'characters');
    const d = dom();
    const DOMPurify = require('dompurify')(d.window);
    if (!DOMPurify.isSupported) throw new Error('internal: the HTML sanitizer could not start');
    DOMPurify.addHook('afterSanitizeAttributes', stripRemoteLoads);
    const btoa = (str) => Buffer.from(str, 'binary').toString('base64');
    new Function('window', 'DOMPurify', 'btoa', 'console', read('lib/site/markdown-parser.js'))(win, DOMPurify, btoa, quiet);
    const body = new win.MarkdownParser().parse(text);
    const page = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n' +
      '<meta http-equiv="Content-Security-Policy" content="' + PAGE_CSP + '">\n' +
      '<meta http-equiv="x-dns-prefetch-control" content="off">\n<meta name="referrer" content="no-referrer">\n' +
      '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
      '<title>' + escapeHtml(opts.title || 'Document') + '</title>\n<style>' + PAGE_CSS + '</style>\n</head>\n<body>\n' +
      body + '\n</body>\n</html>\n';
    return { text: page };
  },

  // HTML to Markdown.
  'html>md': async (input) => {
    const Parser = htmlToMdParser();
    const text = decode(input);
    limit('lib/site/html-to-md-parser.js', 'var MAX_INPUT_CHARS = 30 * 1024 * 1024;', 30 * MB, 'HTML to Markdown', text.length, 'characters');
    return { text: tameTargets(new Parser().parse(text)) };
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
    limit('lib/site/docx-to-md-parser.js', 'var MAX_INPUT_BYTES = 50 * 1024 * 1024;', 50 * MB, 'Word to Markdown', input.length, 'bytes');
    const bytes = new Uint8Array(input);
    return { text: tameTargets(await new win.DocxToMarkdownParser().parse(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength))) };
  },

  // PDF to Markdown: the text layer only (no OCR). The PDF library runs in
  // this thread, with code generation from the file's contents switched off
  // and no font or resource loading.
  'pdf>md': async (input) => {
    const { win } = base();
    // The library finds its parsing half on the object it is given, so no
    // real global is defined and no worker file is ever loaded by address.
    const pdfjsWorker = loadUmd('vendor/pdf.worker-3.11.174.min.js', 'pdfjsWorker');
    const lib = loadUmd('vendor/pdf-3.11.174.min.js', 'pdfjsLib', { pdfjsWorker });
    if (!lib || typeof lib.getDocument !== 'function') throw new Error('internal: the PDF reader could not start');
    const pdfjsLib = {
      GlobalWorkerOptions: {},
      getDocument: (o) => lib.getDocument({
        data: o.data, verbosity: 0, isEvalSupported: false, disableFontFace: true,
        useWorkerFetch: false, useSystemFonts: false, disableAutoFetch: true, disableStream: true, disableRange: true,
      }),
    };
    const scope = { pdfjsLib };
    // Over its output limit the site converter stops and adds a note; here that is an error.
    const src = patchOnce(read('lib/site/pdf-to-md-parser.js'), 'if (budget.truncated) {',
      "if (budget.truncated) { throw new Error('this PDF holds more text than the converter handles'); }\n            if (false) {", 'PDF output limit');
    new Function('window', 'console', src)(scope, quiet);
    limit('lib/site/pdf-to-md-parser.js', 'var MAX_PDF_BYTES = 50 * 1024 * 1024;', 50 * MB, 'PDF to Markdown', input.length, 'bytes');
    const bytes = new Uint8Array(input);
    const text = await new scope.PdfToMdParser().parse(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
    if (!text.trim()) throw new Error('no text found in this PDF (scanned pages have no text layer to read)');
    return { text };
  },

  // Markdown to PDF, through the site converter's own entry point, which
  // also refuses a PDF that carries an automatic action. Diagrams stay as
  // code blocks and images as their alt text.
  'md>pdf': async (input, opts) => {
    const { win } = base();
    if (!win.MarkdownBlockTokenizer) new Function('window', read('lib/site/markdown-block-tokenizer.js'))(win);
    const Parser = new Function('window', 'MarkdownBlockTokenizer', 'pdfMake', 'console',
      read('lib/site/md-to-pdf-parser.js') + '\n;return MdToPdfParser;')(win, win.MarkdownBlockTokenizer, pdfMake(), quiet);
    const text = decode(input);
    limit('lib/site/md-to-pdf-parser.js', 'maxInputChars: 2_000_000,', 2000000, 'Markdown to PDF', text.length, 'characters');
    limit('lib/site/md-to-pdf-parser.js', 'const MD_TO_PDF_MAX_LINES = 50_000;', 50000, 'Markdown to PDF', text.split(/\r\n?|\n/).length, 'lines');
    const blob = await new Parser().parse(text, { fileName: opts.title || '' });
    return { bytes: Buffer.from(await blob.arrayBuffer()) };
  },

  // Markdown to a Word document. Diagrams stay as code blocks.
  'md>docx': async (input) => {
    const { win } = base();
    if (!win.MarkdownBlockTokenizer) new Function('window', read('lib/site/markdown-block-tokenizer.js'))(win);
    const docx = loadUmd('vendor/docx-9.6.1.umd.js', 'docx');
    const Parser = new Function('window', 'docx', 'MarkdownBlockTokenizer', 'Blob', 'console',
      read('lib/site/md-to-docx-parser.js') + '\n;return MdToDocxParser;')(win, docx, win.MarkdownBlockTokenizer, Blob, quiet);
    const text = decode(input);
    limit('lib/site/md-to-docx-parser.js', 'maxInputChars: 5_000_000,', 5000000, 'Markdown to Word', text.length, 'characters');
    const blob = await new Parser().parse(text);
    return { bytes: Buffer.from(await blob.arrayBuffer()) };
  },
};

async function convert(route, input, opts) {
  const fn = routes[route];
  if (!fn) throw new Error('unsupported conversion: ' + route);
  return fn(Buffer.from(input), opts || {});
}

module.exports = { convert, routes: Object.keys(routes) };
