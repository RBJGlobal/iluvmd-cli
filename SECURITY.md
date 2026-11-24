# Security

## Reporting a problem

Email info@iluvmd.com with "iluvmd security" in the subject. Please include
the version (`iluvmd --version`), the command you ran and, if you can, a file
that shows the problem. Please do not open a public issue for a security
problem before it is fixed.

## What counts

The tool is meant to be safe to run on files from an unknown source. These
are treated as security problems:

- any network connection made by the tool;
- a file written outside the requested output path or folder, written through
  a symbolic link, or replaced without `--force`;
- reading a file other than the input files (for example through a link
  inside a document);
- output that runs a script or contacts a remote address when it is opened
  (HTML, PDF or Word output);
- text printed to the terminal that carries control sequences;
- an input that makes the tool run past its time limit or memory cap.

## How it is built

- Network functions (`fetch`, sockets, `http`, `https`, `dns` and the rest)
  are replaced with functions that throw, in the main process and in every
  conversion process.
- Each conversion runs in its own process, in a worker thread with a heap
  limit and a timeout, while the process watches its total memory.
- HTML and XML are parsed in a DOM where scripts never run and no resource is
  loaded.
- The PDF reader runs with code generation from file contents switched off.
- The PDF writer is denied both remote addresses and local files.
- HTML output keeps no attribute that loads from another machine, including
  addresses that name a network share.
- The package has no install scripts, and its dependencies are pinned to
  exact versions in `npm-shrinkwrap.json`.

## Supported versions

Only the latest published version receives fixes.
