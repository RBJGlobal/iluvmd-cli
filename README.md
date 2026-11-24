# iluvmd

Convert documents to Markdown, and Markdown to documents, from the command
line. It is the command line version of [iLoveMD](https://iluvmd.com) and uses
the same converters as the site.

Everything runs on your machine. The tool makes no network calls, and your
files are never uploaded.

## Install

Node.js 22 or newer is needed.

```
npm install -g iluvmd
```

Or run it once without installing:

```
npx iluvmd notes.txt
```

## Use

```
iluvmd report.pdf                  # writes report.md next to the file
iluvmd letter.docx page.html       # several files at once
iluvmd notes.md --to docx          # Markdown to Word
iluvmd notes.md --to pdf           # Markdown to PDF
iluvmd notes.md --to html          # Markdown to a standalone HTML page
iluvmd docs/ -r -o out/            # a folder and its subfolders
cat notes.txt | iluvmd - --from txt   # standard input to standard output
```

## What it converts

| From | To |
|---|---|
| PDF (text layer) | Markdown |
| Word (.docx) | Markdown |
| HTML | Markdown |
| Plain text | Markdown |
| Markdown | Word (.docx), PDF, HTML, plain text |

## Options

| Option | Meaning |
|---|---|
| `--to <fmt>` | Target format: `md` (default), `docx`, `pdf`, `html`, `txt` |
| `--from <fmt>` | Input format. Needed only for standard input |
| `-o, --output <path>` | Output file, or a folder for several files. `-` writes to standard output |
| `-r, --recursive` | With a folder, include its subfolders |
| `--force` | Replace an output file that already exists |
| `--json` | Print one JSON result per file |
| `--raw` | Do not strip control characters from text printed to standard output |
| `--timeout <s>` | Seconds allowed per file (default 60) |

Exit codes: `0` all converted, `1` a file failed, `2` bad usage, `3`
unsupported format.

## Limits

- PDF to Markdown reads the text in the PDF. Scanned pages without a text
  layer give little or no output; there is no OCR.
- Images are not carried into Markdown, Word or PDF output. Their alt text is
  kept.
- Mermaid diagrams stay as code blocks in Word and PDF output.
- In HTML output, an image at a remote address becomes a link, so opening the
  page contacts nobody. Local images are kept.
- Input files are limited to 100 MB.

## Safety

The tool is built to be run on files you did not write, including by
scripts and AI agents.

- No network: every way to open a connection is blocked inside the process.
- Each file is converted in a separate thread with a memory cap and a time
  limit.
- Output files are never replaced without `--force`, a symbolic link at the
  output path is never followed, and folder output stays inside the output
  folder.
- HTML output is sanitized and carries a Content Security Policy that allows
  no scripts.
- Text printed to the terminal has control characters and invisible
  direction characters removed.

See [SECURITY.md](SECURITY.md) to report a problem.

## Development

```
npm install --ignore-scripts
node test/run-all.js
```

The converter files under `lib/site/` and the libraries under `vendor/` are
copies and are not edited here. `scripts/sync-from-site.js --check` verifies
them against `lib/MANIFEST.sha256`.

## License

MIT. Bundled libraries keep their own licenses, listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
