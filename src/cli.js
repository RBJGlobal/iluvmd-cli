'use strict';
const fs = require('fs');
const path = require('path');
const { clean } = require('./sanitize');
const { runConversion, DEFAULT_TIMEOUT_MS } = require('./run');
const { routes } = require('./engine');

const MAX_INPUT_BYTES = 100 * 1024 * 1024;

const KIND_BY_EXT = {
  '.md': 'md', '.markdown': 'md', '.mdown': 'md',
  '.txt': 'txt', '.text': 'txt',
  '.html': 'html', '.htm': 'html',
  '.docx': 'docx',
};
const EXT_BY_KIND = { md: '.md', txt: '.txt', html: '.html', docx: '.docx' };
const BINARY = new Set(['docx']);

const EXIT = { OK: 0, FAILED: 1, USAGE: 2, UNSUPPORTED: 3 };

const HELP = `iluvmd: convert documents to Markdown and Markdown to documents.
Everything runs on this machine. No uploads and no network calls.

Usage:
  iluvmd <file...>                 convert each file to Markdown
  iluvmd <file.md...> --to <fmt>   convert Markdown to docx or txt
  iluvmd - --from txt              read standard input, write standard output

Options:
  --to <fmt>       target format: md, docx, txt (default: md)
  --from <fmt>     input format, needed only for standard input
  -o, --output <path>  output file, or a folder when converting several files;
                       "-" writes to standard output
  --force          replace an output file that already exists
  --json           print one JSON result per file
  --raw            do not strip control characters from text printed to
                   standard output
  --timeout <s>    seconds allowed per file (default ${DEFAULT_TIMEOUT_MS / 1000})
  -h, --help       show this help
  -v, --version    show the version

Exit codes: 0 all converted, 1 a file failed, 2 bad usage, 3 unsupported format.
`;

class UsageError extends Error {}

function parseArgs(argv) {
  const o = { inputs: [], to: null, from: null, output: null, force: false, json: false, raw: false, timeoutMs: DEFAULT_TIMEOUT_MS, help: false, version: false };
  let literal = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = (name) => {
      if (i + 1 >= argv.length) throw new UsageError(name + ' needs a value');
      return argv[++i];
    };
    if (literal || a === '-' || !a.startsWith('-')) { o.inputs.push(a); continue; }
    if (a === '--') { literal = true; continue; }
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a === '--to') o.to = value('--to').toLowerCase();
    else if (a === '--from') o.from = value('--from').toLowerCase();
    else if (a === '-o' || a === '--output') o.output = value(a);
    else if (a === '--force') o.force = true;
    else if (a === '--json') o.json = true;
    else if (a === '--raw') o.raw = true;
    else if (a === '--timeout') {
      const s = Number(value('--timeout'));
      if (!Number.isFinite(s) || s <= 0 || s > 3600) throw new UsageError('--timeout takes a number of seconds, up to 3600');
      o.timeoutMs = Math.round(s * 1000);
    } else throw new UsageError('unknown option ' + a);
  }
  return o;
}

function isDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch (e) { return false; }
}

// Never follows a symbolic link at the target, and never replaces a file
// unless --force was given.
function writeOutput(target, data, force) {
  const c = fs.constants;
  const flags = force
    ? c.O_WRONLY | c.O_CREAT | c.O_TRUNC | c.O_NOFOLLOW
    : c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_NOFOLLOW;
  let fd;
  try {
    fd = fs.openSync(target, flags, 0o644);
  } catch (e) {
    if (e.code === 'EEXIST') throw new Error('output exists (use --force to replace): ' + target);
    if (e.code === 'ELOOP') throw new Error('output is a symbolic link, not written: ' + target);
    throw new Error('cannot write ' + target + ': ' + e.code);
  }
  try { fs.writeFileSync(fd, data); } finally { fs.closeSync(fd); }
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

function readInput(file) {
  let st;
  try { st = fs.statSync(file); } catch (e) { throw new Error('cannot read ' + file + ': ' + e.code); }
  if (!st.isFile()) throw new Error('not a file: ' + file);
  if (st.size > MAX_INPUT_BYTES) throw new Error('file is larger than 100 MB: ' + file);
  return fs.readFileSync(file);
}

async function main(argv) {
  const err = (msg) => process.stderr.write(clean('iluvmd: ' + msg) + '\n');
  let o;
  try { o = parseArgs(argv); } catch (e) {
    if (e instanceof UsageError) { err(e.message + ' (see iluvmd --help)'); return EXIT.USAGE; }
    throw e;
  }
  if (o.help) { process.stdout.write(HELP); return EXIT.OK; }
  if (o.version) { process.stdout.write(require('../package.json').version + '\n'); return EXIT.OK; }
  if (!o.inputs.length) { err('no input file (see iluvmd --help)'); return EXIT.USAGE; }

  const usesStdin = o.inputs.includes('-');
  if (usesStdin && o.inputs.length > 1) { err('standard input cannot be combined with files'); return EXIT.USAGE; }
  for (const k of [o.to, o.from]) {
    if (k && !EXT_BY_KIND[k]) { err('unknown format "' + k + '"'); return EXIT.USAGE; }
  }
  const toStdout = o.output === '-' || (usesStdin && !o.output);
  if (toStdout && o.inputs.length > 1) { err('several files cannot be written to standard output'); return EXIT.USAGE; }
  if (toStdout && o.json) { err('--json cannot be combined with output on standard output'); return EXIT.USAGE; }
  const outIsDir = !!o.output && o.output !== '-' && (isDir(o.output) || /[\\/]$/.test(o.output));
  if (o.inputs.length > 1 && o.output && !outIsDir) { err('with several files, --output must be an existing folder'); return EXIT.USAGE; }
  if (outIsDir && !isDir(o.output)) { err('output folder does not exist: ' + o.output); return EXIT.USAGE; }

  let failed = 0;
  let unsupported = 0;
  for (const input of o.inputs) {
    const result = { input: input === '-' ? '(stdin)' : input, output: null, ok: false };
    try {
      const fromKind = input === '-'
        ? (o.from || (o.to && o.to !== 'md' ? 'md' : 'txt'))
        : (o.from || KIND_BY_EXT[path.extname(input).toLowerCase()]);
      if (!fromKind) { unsupported++; throw new Error('unsupported file type: ' + input); }
      const toKind = o.to || 'md';
      if (fromKind === toKind) throw new UsageError(fromKind === 'md'
        ? 'Markdown input needs --to (docx or txt)' : 'input and output formats are the same');
      const route = fromKind + '>' + toKind;
      if (!routes.includes(route)) { unsupported++; throw new Error('cannot convert ' + fromKind + ' to ' + toKind + ' yet'); }
      if (toStdout && BINARY.has(toKind) && process.stdout.isTTY) throw new UsageError('refusing to write a binary file to the terminal (use --output)');

      const data = input === '-' ? await readStdin() : readInput(input);
      const out = await runConversion(route, data, { timeoutMs: o.timeoutMs });
      // Text output always ends with a newline.
      const payload = out.bytes ? out.bytes : (out.text.endsWith('\n') ? out.text : out.text + '\n');

      if (toStdout) {
        process.stdout.write(out.bytes || o.raw ? payload : clean(payload));
        result.output = '(stdout)';
      } else {
        const name = input === '-' ? 'output' : path.basename(input, path.extname(input));
        const target = o.output && !outIsDir
          ? o.output
          : path.join(outIsDir ? o.output : path.dirname(input), name + EXT_BY_KIND[toKind]);
        writeOutput(target, payload, o.force);
        result.output = target;
      }
      result.ok = true;
    } catch (e) {
      if (e instanceof UsageError) { err(e.message); return EXIT.USAGE; }
      result.error = clean(String((e && e.message) || e));
      failed++;
    }
    if (o.json) process.stdout.write(JSON.stringify(result) + '\n');
    else if (!result.ok) err(result.error);
    else if (!toStdout) process.stderr.write(clean(result.input + ' -> ' + result.output) + '\n');
  }
  if (!failed) return EXIT.OK;
  return unsupported === failed ? EXIT.UNSUPPORTED : EXIT.FAILED;
}

module.exports = { main, parseArgs, EXIT };
