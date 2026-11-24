'use strict';
// Removes characters that can drive a terminal or hide text from a reader:
// C0 and C1 controls (tab and newline are kept), bidirectional controls,
// zero-width spaces, the byte order mark and the Unicode tag block. The
// zero-width joiner and non-joiner are kept: emoji and several scripts
// need them, and they neither drive a terminal nor reorder text.
// Code points are listed as numbers so this file holds no control bytes.
const RANGES = [
  [0x00, 0x08], [0x0B, 0x0C], [0x0E, 0x1F], [0x7F, 0x9F],
  [0x061C, 0x061C], [0x200B, 0x200B], [0x200E, 0x200F], [0x202A, 0x202E],
  [0x2060, 0x2069], [0xFEFF, 0xFEFF], [0xE0000, 0xE007F], [0xE0100, 0xE01EF],
];

function isUnsafe(cp) {
  for (let i = 0; i < RANGES.length; i++) {
    if (cp >= RANGES[i][0] && cp <= RANGES[i][1]) return true;
  }
  return false;
}

function clean(text) {
  const s = String(text).split(String.fromCharCode(13, 10)).join(String.fromCharCode(10));
  let out = '';
  let start = 0;
  let i = 0;
  while (i < s.length) {
    const cp = s.codePointAt(i);
    const len = cp > 0xFFFF ? 2 : 1;
    // A lone carriage return lets later text overwrite earlier text on screen.
    if (cp === 13 || isUnsafe(cp)) {
      out += s.slice(start, i);
      start = i + len;
    }
    i += len;
  }
  return out + s.slice(start);
}

// Characters that render as nothing and can carry hidden text: the Unicode
// tag block and the supplementary variation selectors. Removed from every
// text result, in files too.
function stripHidden(text) {
  let out = '';
  let start = 0;
  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i);
    const len = cp > 0xFFFF ? 2 : 1;
    if ((cp >= 0xE0000 && cp <= 0xE007F) || (cp >= 0xE0100 && cp <= 0xE01EF)) { out += text.slice(start, i); start = i + len; }
    i += len;
  }
  return out + text.slice(start);
}

// One line for a message: clean, and no line breaks (a file name can hold
// them, and could otherwise fake a second message).
// The line and paragraph separators count as line breaks to some readers.
const isSeparator = (cp) => cp === 0x2028 || cp === 0x2029;

function oneLine(text) {
  return clean(text).split(String.fromCharCode(10)).join(' ')
    .split(String.fromCodePoint(0x2028)).join(' ').split(String.fromCodePoint(0x2029)).join(' ');
}

// JSON text with every unsafe character written as an escape, so a result
// line never carries a control or direction character.
function safeJson(value) {
  const json = JSON.stringify(value);
  let out = '';
  let i = 0;
  while (i < json.length) {
    const cp = json.codePointAt(i);
    const len = cp > 0xFFFF ? 2 : 1;
    const loneSurrogate = len === 1 && cp >= 0xD800 && cp <= 0xDFFF;
    if (isUnsafe(cp) || isSeparator(cp) || loneSurrogate) {
      for (let k = 0; k < len; k++) out += String.fromCharCode(92) + 'u' + json.charCodeAt(i + k).toString(16).padStart(4, '0');
    } else out += json.slice(i, i + len);
    i += len;
  }
  return out;
}

module.exports = { clean, isUnsafe, stripHidden, oneLine, safeJson };
