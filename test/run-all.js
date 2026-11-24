'use strict';
// End-to-end checks of the command line tool. Zero dependencies:
//   node test/run-all.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const BIN = path.join(__dirname, '..', 'bin', 'iluvmd.js');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iluvmd-test-'));
const cp = (...codes) => String.fromCodePoint(...codes);

let pass = 0;
let fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; return; }
  fail++;
  console.log('FAIL: ' + name + (extra != null ? '\n  ' + String(extra).slice(0, 400) : ''));
}
function run(args, input) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd: dir, input, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
const file = (name, text) => { fs.writeFileSync(path.join(dir, name), text); return name; };
const readOut = (name) => fs.readFileSync(path.join(dir, name), 'utf8');

// --- text to Markdown -------------------------------------------------------
file('notes.txt', ['WEEKLY NOTES', '', 'A paragraph.', '', cp(0x2022) + ' first point', cp(0x2022) + ' second point', '',
  'See https://example.com and file:///Users/x/secret.txt', ''].join('\n'));
let r = run(['notes.txt']);
ok('txt>md exits 0', r.code === 0, r.err);
let md = readOut('notes.md');
ok('txt>md heading', /^# WEEKLY NOTES$/m.test(md), md);
ok('txt>md bullets', /^- first point$/m.test(md), md);
ok('txt>md link', md.includes('[https://example.com](https://example.com)'), md);
ok('txt>md keeps no link to a local file', !/\]\(file:/.test(md), md);
ok('txt>md is idempotent', (() => {
  file('again.txt', md);
  run(['again.txt']);
  return readOut('again.md') === md;
})());

// --- overwrite and symlink rules -------------------------------------------
r = run(['notes.txt']);
ok('existing output is not replaced', r.code === 1 && /exists/.test(r.err), r.err);
r = run(['notes.txt', '--force']);
ok('--force replaces', r.code === 0, r.err);
const outside = path.join(dir, 'outside-target');
fs.symlinkSync(outside, path.join(dir, 'link.md'));
r = run(['notes.txt', '-o', 'link.md', '--force']);
ok('symlink target refused', r.code === 1 && /symbolic link/.test(r.err) && !fs.existsSync(outside), r.err);

// --- Markdown to Word -------------------------------------------------------
file('doc.md', '# Report\n\nA paragraph with *emphasis*.\n\n- one\n- two\n\n| a | b |\n| - | - |\n| 1 | 2 |\n');
r = run(['doc.md', '--to', 'docx', '--json']);
ok('md>docx exits 0', r.code === 0, r.err + r.out);
ok('md>docx json line', (() => { try { const j = JSON.parse(r.out); return j.ok && j.output === 'doc.docx'; } catch (e) { return false; } })(), r.out);
const docx = fs.readFileSync(path.join(dir, 'doc.docx'));
ok('md>docx is a zip', docx.subarray(0, 2).toString('latin1') === 'PK' && docx.length > 1000);
ok('md>docx has the document part', docx.includes(Buffer.from('word/document.xml')));

// --- Markdown to text, standard streams -------------------------------------
r = run(['doc.md', '--to', 'txt', '-o', '-']);
ok('md>txt to stdout', r.code === 0 && /Report/.test(r.out) && !/[#*]/.test(r.out.split('\n')[0]), r.out);
ok('text output ends with a newline', r.out.endsWith('\n'));
r = run(['-'], 'HELLO THERE\n');
ok('stdin to stdout', r.code === 0 && r.out === '# HELLO THERE\n', JSON.stringify(r.out));
const esc = cp(0x1b);
const hostile = 'a' + esc + '[31mred' + esc + '[0m ' + cp(0x202e) + 'evil' + cp(0x200b) + cp(0xe0041) + cp(0x9b) + '\n';
r = run(['-'], hostile);
ok('control characters stripped on stdout', r.code === 0 && ![0x1b, 0x202e, 0x200b, 0xe0041, 0x9b].some((c) => r.out.includes(cp(c))), JSON.stringify(r.out));
r = run(['-', '--raw'], 'plain' + cp(0x200b) + 'text here\n');
ok('--raw keeps them', r.out.includes(cp(0x200b)), JSON.stringify(r.out));

// --- Markdown to HTML -------------------------------------------------------
file('page.md', ['# Title <script>alert(1)</script>', '', 'Text **bold** [bad](javascript:alert(1)) [ok](https://example.com)', '',
  '![remote](https://tracker.example/p.png) ![proto](//tracker.example/q.png) ![local](./pic.png)', '',
  '<img src=x onerror=alert(1)>', '', '<iframe src="https://example.com"></iframe>', '',
  '| a | b |', '|---|---|', '| 1 | 2 |', ''].join('\n'));
r = run(['page.md', '--to', 'html']);
ok('md>html exits 0', r.code === 0, r.err);
let html = readOut('page.html');
ok('md>html is a full page with a title', html.startsWith('<!DOCTYPE html>') && html.includes('<title>page</title>'));
ok('md>html carries the content policy', /http-equiv="Content-Security-Policy" content="default-src 'none'/.test(html));
ok('md>html renders', html.includes('<strong>bold</strong>') && html.includes('<table>'), html);
ok('md>html has no script, handler or frame', !/<script|onerror|<iframe|javascript:alert\(1\)"/i.test(html), html);
ok('md>html has no remote image', !/<img[^>]+src="(https?:)?\/\//i.test(html), html);
ok('md>html turns a remote image into a link', html.includes('<a href="https://tracker.example/p.png"'), html);
ok('md>html keeps a local image', html.includes('<img src="./pic.png" alt="local">'), html);
file('a"b<c>.md', '# x\n');
r = run(['a"b<c>.md', '--to', 'html']);
ok('md>html escapes the title', r.code === 0 && readOut('a"b<c>.html').includes('<title>a&quot;b&lt;c&gt;</title>'), r.err);

// --- HTML to Markdown -------------------------------------------------------
file('in.html', '<h1>Hi</h1><p>Some <b>bold</b> and <a href="https://example.com">link</a><script>steal()</script></p>' +
  '<ul><li>one</li><li>two</li></ul><a href="javascript:alert(1)">bad</a><style>p{color:red}</style>');
r = run(['in.html']);
md = r.code === 0 ? readOut('in.md') : '';
ok('html>md converts', /^# Hi$/m.test(md) && md.includes('**bold**') && md.includes('[link](https://example.com)') && /^- one$/m.test(md), r.err + md);
ok('html>md drops script, style and script links', !/steal|color:red|javascript:/.test(md), md);
file('broken.html', '<div><p>unclosed <b>tags<table><tr><td>cell');
r = run(['broken.html', '-o', '-']);
ok('html>md accepts malformed HTML', r.code === 0 && /unclosed/.test(r.out) && /cell/.test(r.out), r.err + r.out);

// --- Word to Markdown -------------------------------------------------------
fs.copyFileSync(path.join(__dirname, 'fixtures', 'sample.docx'), path.join(dir, 'sample.docx'));
r = run(['sample.docx']);
md = r.code === 0 ? readOut('sample.md') : '';
ok('docx>md converts headings, lists and tables', /^# Quarterly Report$/m.test(md) && /^- First bullet$/m.test(md) && /^\| Name \|/m.test(md), r.err + md);
file('fake.docx', 'this is not a zip file');
r = run(['fake.docx']);
ok('docx>md fails cleanly on a broken file', r.code === 1 && r.err.length > 0 && !fs.existsSync(path.join(dir, 'fake.md')), r.err);
r = run(['sample.docx', '-o', '-']);
ok('docx>md prints nothing but Markdown on stdout', r.code === 0 && r.out.startsWith('# Quarterly Report'), r.out.slice(0, 80));

// --- Markdown to text keeps the text of raw HTML ----------------------------
file('raw.md', 'Before\n\n<div>inside <b>html</b></div>\n\nAfter\n');
r = run(['raw.md', '--to', 'txt', '-o', '-']);
ok('md>txt keeps text inside raw HTML', r.code === 0 && /inside html/.test(r.out) && !/<div>/.test(r.out), r.out);

// --- usage and unsupported --------------------------------------------------
ok('no input is a usage error', run([]).code === 2);
ok('unknown option is a usage error', run(['--nope']).code === 2);
ok('markdown without --to is a usage error', run(['doc.md']).code === 2);
ok('unsupported type exits 3', run(['x.xlsx']).code === 3);
ok('missing file exits 1', run(['missing.txt']).code === 1);
file('-dash.txt', 'TITLE\n');
ok('file name starting with a dash after --', run(['--', '-dash.txt']).code === 0 && fs.existsSync(path.join(dir, '-dash.md')));
r = run(['doc.md', 'notes.txt', '-o', 'one.md']);
ok('several files need a folder', r.code === 2, r.err);
ok('--help', run(['--help']).code === 0);

// --- limits -----------------------------------------------------------------
file('slow.txt', ('A plain line of text number ' + '\n').repeat(200000));
r = run(['slow.txt', '--timeout', '0.02']);
ok('timeout stops a long conversion', r.code === 1 && /stopped after/.test(r.err), r.err || 'finished within the limit');

// --- no network -------------------------------------------------------------
const guard = path.join(__dirname, '..', 'src', 'netguard.js');
for (const probe of ["fetch('https://example.com')", "require('https').get('https://example.com')",
  "require('http').request('http://example.com')", "require('net').connect(80, '192.0.2.1')",
  "require('dns').lookup('example.com', () => {})", "new WebSocket('wss://example.com')"]) {
  const p = spawnSync(process.execPath, ['-e', 'require(' + JSON.stringify(guard) + ').install(); ' + probe], { encoding: 'utf8' });
  ok('network blocked: ' + probe, p.status !== 0 && /makes no network calls/.test(p.stderr), p.stderr);
}

// --- synced files match the manifest ---------------------------------------
const m = spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'sync-from-site.js'), '--check'], { encoding: 'utf8' });
ok('manifest matches', m.status === 0, m.stdout + m.stderr);

// --- Markdown to PDF --------------------------------------------------------
file('report.md', '# Report\n\nSome **bold** text and a [link](https://example.com).\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n![pic](https://example.com/p.png)\n');
r = run(['report.md', '--to', 'pdf']);
ok('md>pdf exits 0', r.code === 0, r.err);
const pdf = fs.readFileSync(path.join(dir, 'report.pdf'));
ok('md>pdf is a PDF', pdf.slice(0, 5).toString('latin1') === '%PDF-' && pdf.length > 2000);
ok('md>pdf carries no automatic action', !/\/(OpenAction|AA|JS|JavaScript|Launch)\b/.test(pdf.toString('latin1')));
r = run(['report.md', '--to', 'pdf']);
ok('md>pdf does not replace an existing file', r.code === 1 && /exists/.test(r.err), r.err);

// --- PDF to Markdown --------------------------------------------------------
fs.copyFileSync(path.join(__dirname, 'fixtures', 'sample.pdf'), path.join(dir, 'paper.pdf'));
r = run(['paper.pdf']);
ok('pdf>md exits 0', r.code === 0, r.err);
md = readOut('paper.md');
ok('pdf>md heading and text', /^# Quarterly Report$/m.test(md) && md.includes('Plain appendix text.'), md);
ok('pdf>md leaves no tag-like "<"', !/<(?=[A-Za-z\/!?])/.test(md), md);
ok('pdf>md prints nothing on standard output', r.out === '', r.out);
file('broken.pdf', 'this is not a PDF');
r = run(['broken.pdf']);
ok('pdf>md reports a broken file', r.code === 1 && r.err.length > 0 && !fs.existsSync(path.join(dir, 'broken.md')), r.err);
fs.copyFileSync(path.join(dir, 'report.pdf'), path.join(dir, 'round.pdf'));
r = run(['round.pdf']);
ok('pdf>md reads a PDF this tool wrote', r.code === 0 && /Report/.test(readOut('round.md')), r.err);

// --- second check of raw Markdown output ------------------------------------
file('tags.txt', 'A line with <script>alert(1)</script> in it.\n\n<img src=x onerror=alert(1)>\n');
r = run(['tags.txt', '-o', '-']);
ok('txt>md leaves no tag-like "<"', r.code === 0 && !/<(?=[A-Za-z\/!?])/.test(r.out), r.out);

// --- folders ----------------------------------------------------------------
fs.mkdirSync(path.join(dir, 'tree', 'deep'), { recursive: true });
fs.mkdirSync(path.join(dir, 'treeout'));
file('tree/one.txt', 'one\n');
file('tree/deep/two.html', '<h1>Two</h1>\n');
file('tree/.hidden.txt', 'hidden\n');
file('tree/skip.md', '# already Markdown\n');
fs.symlinkSync(path.join(dir, 'notes.txt'), path.join(dir, 'tree', 'link.txt'));
r = run(['tree', '-o', 'treeout']);
ok('folder: converts the top level only', r.code === 0 && fs.existsSync(path.join(dir, 'treeout', 'one.md')) && !fs.existsSync(path.join(dir, 'treeout', 'deep')), r.err);
ok('folder: skips links, hidden files and Markdown', fs.readdirSync(path.join(dir, 'treeout')).join() === 'one.md');
r = run(['tree', '-r', '-o', 'treeout', '--force']);
ok('folder -r: keeps the subfolder', r.code === 0 && /^# Two/m.test(readOut('treeout/deep/two.md')), r.err);
r = run(['tree', '-o', 'single.md']);
ok('folder: needs an output folder', r.code === 2, r.err);
fs.mkdirSync(path.join(dir, 'empty'));
r = run(['empty']);
ok('folder: nothing to convert', r.code === 1 && /nothing to convert/.test(r.err), r.err);

fs.rmSync(dir, { recursive: true, force: true });
console.log(pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
