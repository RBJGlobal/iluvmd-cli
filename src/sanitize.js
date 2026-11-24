'use strict';
// Removes characters that can drive a terminal or hide text from a reader:
// C0 and C1 controls (tab and newline are kept), bidirectional controls,
// zero-width characters, the byte order mark and the Unicode tag block.
// Code points are listed as numbers so this file holds no control bytes.
const RANGES = [
  [0x00, 0x08], [0x0B, 0x0C], [0x0E, 0x1F], [0x7F, 0x9F],
  [0x061C, 0x061C], [0x200B, 0x200F], [0x202A, 0x202E],
  [0x2060, 0x2069], [0xFEFF, 0xFEFF], [0xE0000, 0xE007F],
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

module.exports = { clean, isUnsafe };
