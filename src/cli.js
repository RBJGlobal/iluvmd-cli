'use strict';
const fs = require('fs');
const path = require('path');
const { clean, stripHidden, oneLine, safeJson } = require('./sanitize');
const { runConversion, DEFAULT_TIMEOUT_MS } = require('./run');
const { routes } = require('./engine');

const MAX_INPUT_BYTES = 100 * 1024 * 1024;

const KIND_BY_EXT = {
  '.md': 'md', '.markdown': 'md', '.mdown': 'md',
  '.txt': 'txt', '.text': 'txt',
  '.html': 'html', '.htm': 'html',
  '.docx': 'docx',
  '.pdf': 'pdf',
};
const EXT_BY_KIND = { md: '.md', txt: '.txt', html: '.html', docx: '.docx', pdf: '.pdf' };
const BINARY = new Set(['docx', 'pdf']);
const MAX_FILES = 5000;

const EXIT = { OK: 0, FAILED: 1, USAGE: 2, UNSUPPORTED: 3 };

const HELP = `iluvmd: convert documents to Markdown and Markdown to documents.
Everything runs on this machine. No uploads and no network calls.

Usage:
  iluvmd <file...>                 convert each file to Markdown
  iluvmd <file.md...> --to <fmt>   convert Markdown to docx, pdf, html or txt
  iluvmd <folder> [-r]             convert every supported file in a folder
  iluvmd - --from txt              read standard input, write standard output

Options:
  --to <fmt>       target format: md, docx, pdf, html, txt (default: md)
  --from <fmt>     read the input as this format instead of going by the file
                   name; needed for standard input
  -o, --output <path>  output file, or a folder when converting several files
                       (end the path with "/" to have it created);
                       "-" writes to standard output
  -r, --recursive  with a folder, include its subfolders
  --force          replace an output file that already exists
  --json           print one JSON result per file
  --raw            do not strip control characters from text written to
                   standard output
  --timeout <s>    seconds allowed per file (default ${DEFAULT_TIMEOUT_MS / 1000})
  -h, --help       show this help
  -v, --version    show the version

Exit codes: 0 all converted, 1 a file failed, 2 bad usage (nothing is
written), 3 the only failures were unsupported formats.
`;

class UsageError extends Error {}

function parseArgs(argv) {
  const o = { inputs: [], to: null, from: null, output: null, force: false, recursive: false, json: false, raw: false, timeoutMs: DEFAULT_TIMEOUT_MS, help: false, version: false };
  let literal = false;
  for (let i = 0; i < argv.length; i++) {
    let a = argv[i];
    if (literal || a === '-' || !a.startsWith('-')) { o.inputs.push(a); continue; }
    if (a === '--') { literal = true; continue; }
    // --name=value is the same as --name value.
    let inline = null;
    const eq = a.indexOf('=');
    if (a.startsWith('--') && eq !== -1) { inline = a.slice(eq + 1); a = a.slice(0, eq); }
    const value = () => {
      if (inline !== null) return inline;
      if (i + 1 >= argv.length) throw new UsageError(a + ' needs a value');
      const v = argv[++i];
      if (v.startsWith('-') && !(v === '-' && (a === '-o' || a === '--output'))) throw new UsageError(a + ' needs a value, but the next word is the option ' + v);
      return v;
    };
    const flag = () => { if (inline !== null) throw new UsageError(a + ' takes no value'); };
    if (a === '-h' || a === '--help') { flag(); o.help = true; }
    else if (a === '-v' || a === '--version') { flag(); o.version = true; }
    else if (a === '--to') o.to = value().toLowerCase();
    else if (a === '--from') o.from = value().toLowerCase();
    else if (a === '-o' || a === '--output') o.output = value();
    else if (a === '--force') { flag(); o.force = true; }
    else if (a === '-r' || a === '--recursive') { flag(); o.recursive = true; }
    else if (a === '--json') { flag(); o.json = true; }
    else if (a === '--raw') { flag(); o.raw = true; }
    else if (a === '--timeout') {
      const s = Number(value());
      if (!Number.isFinite(s) || s <= 0 || s > 3600) throw new UsageError('--timeout takes a number of seconds, up to 3600');
      o.timeoutMs = Math.max(1, Math.ceil(s * 1000));
    } else throw new UsageError('unknown option ' + a);
  }
  return o;
}

function isDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch (e) { return false; }
}
// Never follows a symbolic link at the target, and never replaces a file
// unless --force was given. With --force the new file is written beside the
// target and moved into place, so a failed write leaves the old file whole.
function writeOutput(target, data, force) {
  const c = fs.constants;
  // O_NOFOLLOW does not exist on Windows, so the link is also checked here.
  const NOFOLLOW = c.O_NOFOLLOW || 0;
  let st = null;
  try { st = fs.lstatSync(target); } catch (e) { /* does not exist yet */ }
  if (st && st.isSymbolicLink()) throw new Error('output is a symbolic link, not written: ' + target);
  if (st && !st.isFile()) throw new Error('output exists and is not a regular file: ' + target);
  const dest = force ? target + '.' + process.pid + '-' + Date.now().toString(36) + '.iluvmd-tmp' : target;
  let fd;
  try {
    // A file that replaces an existing one starts private and then takes
    // the old file's permissions.
    fd = fs.openSync(dest, c.O_WRONLY | c.O_CREAT | c.O_EXCL | NOFOLLOW, st ? 0o600 : 0o644);
  } catch (e) {
    if (e.code === 'EEXIST') throw new Error('output exists (use --force to replace): ' + target);
    if (e.code === 'ELOOP') throw new Error('output is a symbolic link, not written: ' + target);
    throw new Error('cannot write ' + target + ': ' + e.code);
  }
  try {
    try {
      fs.writeFileSync(fd, data);
      if (st) fs.fchmodSync(fd, st.mode & 0o7777);
    } finally { fs.closeSync(fd); }
    if (force) fs.renameSync(dest, target);
  } catch (e) {
    try { fs.unlinkSync(dest); } catch (e2) { /* nothing to remove */ }
    throw new Error('cannot write ' + target + ': ' + (e.code || e.message));
  }
}

// The files in a folder that can be converted to the target format, in name
// order. Symbolic links and names starting with a dot are skipped. A
// subfolder that cannot be read is reported and the rest continue.
function listFolder(root, toKind, recursive, problems) {
  const found = [];
  const walk = (dir, rel) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) {
      problems.push({ input: dir, error: 'cannot read folder: ' + e.code });
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (e.name.startsWith('.') || e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (recursive) walk(path.join(dir, e.name), path.join(rel, e.name)); continue; }
      if (!e.isFile()) continue;
      const kind = KIND_BY_EXT[path.extname(e.name).toLowerCase()];
      if (!kind || !routes.includes(kind + '>' + toKind)) continue;
      found.push({ input: path.join(dir, e.name), rel, fromFolder: true });
    }
  };
  walk(root, '');
  return found;
}

// Creates (if needed) and returns a subfolder of the output folder, one
// level at a time. A level that is a symbolic link or not a folder is
// refused before anything is created below it, so nothing lands outside
// the output folder.
function subfolder(outRoot, rel) {
  let dir = outRoot;
  for (const part of rel.split(path.sep)) {
    if (!part) continue;
    if (part === '..') throw new Error('output folder leaves ' + outRoot);
    dir = path.join(dir, part);
    let st = null;
    try { st = fs.lstatSync(dir); } catch (e) { /* does not exist yet */ }
    if (!st) {
      try { fs.mkdirSync(dir); } catch (e) { if (e.code !== 'EEXIST') throw new Error('cannot create folder ' + dir + ': ' + e.code); }
      st = fs.lstatSync(dir);
    }
    if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('output folder is a symbolic link or not a folder: ' + dir);
  }
  return dir;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    process.stdin.on('data', (c) => {
      size += c.length;
      if (size > MAX_INPUT_BYTES) { reject(new Error('input is larger than 100 MB')); process.stdin.destroy(); return; }
      chunks.push(c);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks)));
    process.stdin.on('error', reject);
  });
}

// Reads through one open handle, so the file that was checked is the file
// that is read. A file found by walking a folder must not be a symbolic
// link, even if it was swapped for one after the walk.
function readInput(file, noFollow) {
  const c = fs.constants;
  let fd;
  try { fd = fs.openSync(file, c.O_RDONLY | (noFollow ? (c.O_NOFOLLOW || 0) : 0) | (c.O_NONBLOCK || 0)); } catch (e) {
    throw new Error(e.code === 'ELOOP' ? 'is a symbolic link, skipped' : 'cannot read file: ' + e.code);
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new Error('not a file');
    if (st.size > MAX_INPUT_BYTES) throw new Error('file is larger than 100 MB');
    // The file can grow while it is read, so the limit is kept here too.
    const chunks = [];
    let total = 0;
    for (;;) {
      const chunk = Buffer.allocUnsafe(Math.min(Math.max(st.size - total, 0) + 65536, 8 * 1024 * 1024));
      const n = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (!n) break;
      total += n;
      if (total > MAX_INPUT_BYTES) throw new Error('file is larger than 100 MB');
      chunks.push(chunk.subarray(0, n));
    }
    return Buffer.concat(chunks, total);
  } finally { fs.closeSync(fd); }
}

// Two paths that name the same file on this system.
function fileKey(p) {
  let full = path.resolve(p);
  try { full = fs.realpathSync(full); } catch (e) {
    try { full = path.join(fs.realpathSync(path.dirname(full)), path.basename(full)); } catch (e2) { /* keep as is */ }
  }
  // macOS also treats two spellings of one accented name as the same file.
  if (process.platform === 'darwin') return full.normalize('NFC').toLowerCase();
  return process.platform === 'win32' ? full.toLowerCase() : full;
}

async function main(argv) {
  const err = (msg) => process.stderr.write(oneLine('iluvmd: ' + msg) + '\n');
  let o;
  try { o = parseArgs(argv); } catch (e) {
    if (e instanceof UsageError) { err(e.message + ' (see iluvmd --help)'); return EXIT.USAGE; }
    throw e;
  }
  if (o.help) { process.stdout.write(HELP); return EXIT.OK; }
  if (o.version) { process.stdout.write(require('../package.json').version + '\n'); return EXIT.OK; }

  // Everything is checked and every output path is decided before the first
  // conversion, so a wrong command writes nothing.
  let jobs;
  let toStdout;
  try {
    if (!o.inputs.length) throw new UsageError('no input file (see iluvmd --help)');
    const usesStdin = o.inputs.includes('-');
    if (usesStdin && o.inputs.length > 1) throw new UsageError('standard input cannot be combined with files');
    for (const k of [o.to, o.from]) {
      if (k && !EXT_BY_KIND[k]) throw new UsageError('unknown format "' + k + '"');
    }
    const toKind = o.to || 'md';
    toStdout = o.output === '-' || (usesStdin && !o.output);

    const problems = [];
    jobs = [];
    let folders = 0;
    for (const input of o.inputs) {
      if (input !== '-' && isDir(input)) {
        folders++;
        const files = listFolder(input, toKind, o.recursive, problems);
        if (!files.length) problems.push({ input, error: 'nothing to convert to ' + toKind + ' in this folder' });
        jobs = jobs.concat(files);
      } else jobs.push({ input, rel: '', fromFolder: false });
    }
    if (jobs.length > MAX_FILES) throw new UsageError('more than ' + MAX_FILES + ' files; convert the folders in smaller groups');
    const several = jobs.length > 1 || folders > 0;
    if (toStdout && several) throw new UsageError('several files cannot be written to standard output');
    if (toStdout && o.json) throw new UsageError('--json cannot be combined with output on standard output');

    let outDir = null;
    if (o.output && o.output !== '-') {
      const asFolder = o.output.endsWith('/') || o.output.endsWith(path.sep);
      if (isDir(o.output)) outDir = o.output;
      else if (asFolder) outDir = o.output;
      else if (several) throw new UsageError('with several files, --output must be a folder (end the path with "/" to create it)');
    }

    const seen = new Map();
    for (const job of jobs) {
      const { input } = job;
      job.name = input === '-' ? '(stdin)' : input;
      const ext = input === '-' ? '' : path.extname(input);
      const fromKind = (!job.fromFolder && o.from) || KIND_BY_EXT[ext.toLowerCase()]
        || (input === '-' ? (toKind !== 'md' ? 'md' : 'txt') : null);
      if (!fromKind) { job.unsupported = true; job.error = 'unsupported file type'; continue; }
      if (fromKind === toKind) {
        throw new UsageError(job.name + ': ' + (o.to ? 'the input is already ' + toKind : 'Markdown input needs --to (docx, pdf, html or txt)'));
      }
      job.route = fromKind + '>' + toKind;
      if (!routes.includes(job.route)) { job.unsupported = true; job.error = 'cannot convert ' + fromKind + ' to ' + toKind + ' yet'; continue; }
      if (toStdout) {
        if (BINARY.has(toKind) && process.stdout.isTTY) throw new UsageError('refusing to write a binary file to the terminal (use --output)');
        continue;
      }
      const base = input === '-' ? 'output' : path.basename(input, ext);
      job.title = input === '-' ? 'Document' : base;
      job.target = o.output && !outDir ? o.output
        : path.join(outDir ? path.join(outDir, job.rel) : path.dirname(input), base + EXT_BY_KIND[toKind]);
      job.outDir = outDir;
      const key = fileKey(job.target);
      if (seen.has(key)) throw new UsageError(seen.get(key) + ' and ' + job.name + ' would both be written to ' + job.target);
      seen.set(key, job.name);
      if (input !== '-' && fileKey(input) === key) throw new UsageError(job.name + ': the output would replace the input');
    }
    for (const job of jobs) if (job.title == null) job.title = job.input === '-' ? 'Document' : path.basename(job.input, path.extname(job.input));
    if (outDir && !isDir(outDir)) {
      try { fs.mkdirSync(outDir, { recursive: true }); } catch (e) { throw new UsageError('cannot create output folder ' + outDir + ': ' + e.code); }
    }
    jobs = problems.map((p) => ({ name: p.input, error: p.error })).concat(jobs);
  } catch (e) {
    if (e instanceof UsageError) { err(e.message); return EXIT.USAGE; }
    throw e;
  }

  let failed = 0;
  let unsupported = 0;
  for (const job of jobs) {
    const result = { input: job.name, output: null, ok: false };
    try {
      if (job.error) { if (job.unsupported) unsupported++; throw new Error(job.error); }
      const data = job.input === '-' ? await readStdin() : readInput(job.input, job.fromFolder);
      const out = await runConversion(job.route, data, { timeoutMs: o.timeoutMs, title: job.title });
      // Text output always ends with a newline.
      const text = out.bytes ? null : stripHidden(out.text);
      const payload = out.bytes ? out.bytes : (text.endsWith('\n') ? text : text + '\n');
      if (toStdout) {
        process.stdout.write(out.bytes || o.raw ? payload : clean(payload));
        result.output = '(stdout)';
      } else {
        if (job.outDir) subfolder(job.outDir, job.rel);
        writeOutput(job.target, payload, o.force);
        result.output = job.target;
      }
      result.ok = true;
    } catch (e) {
      result.error = clean(String((e && e.message) || e));
      failed++;
    }
    if (o.json) process.stdout.write(safeJson(result) + '\n');
    else if (!result.ok) err(result.input + ': ' + result.error);
    else if (!toStdout) process.stderr.write(oneLine(result.input + ' -> ' + result.output) + '\n');
  }
  if (!failed) return EXIT.OK;
  return unsupported === failed ? EXIT.UNSUPPORTED : EXIT.FAILED;
}

module.exports = { main, parseArgs, EXIT };
