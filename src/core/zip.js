'use strict';
// Bounded ZIP reader for APK, AAB, APKS and XAPK files. It reads the end record and the central directory only;
// an entry's bytes are read and unpacked when that entry is needed (manifest, DEX, certificate, hex view).
// Adapted from Archive Explorer's reader (factory/products/archive-explorer-vscode/src/core/zip.js), made
// synchronous on the bounded Source and using Node's zlib with a hard output cap instead of fflate.
const zlib = require('zlib');

const SIG_EOCD = 0x06054b50, SIG_Z64_LOC = 0x07064b50, SIG_Z64_EOCD = 0x06064b50, SIG_CEN = 0x02014b50, SIG_LOC = 0x04034b50;
const METHODS = { 0: 'Stored', 8: 'Deflate', 9: 'Deflate64', 12: 'BZIP2', 14: 'LZMA', 93: 'Zstandard', 95: 'XZ', 99: 'AES' };
const ZIP_LIMITS = { maxEntries: 200000, maxCentralDir: 64 * 1024 * 1024 };

class ZipError extends Error {
  constructor(message, code) { super(message); this.name = 'ZipError'; this.code = code || 'ZIP'; }
}

const UTF8 = new TextDecoder('utf-8', { fatal: false });
const CP437 = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';

function decodeName(bytes, isUtf8) {
  let ascii = true;
  for (const b of bytes) if (b > 0x7f) { ascii = false; break; }
  let s;
  if (ascii || isUtf8) s = UTF8.decode(bytes);
  else {
    try { s = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch {
      s = '';
      for (const b of bytes) s += b < 0x80 ? String.fromCharCode(b) : CP437[b - 0x80];
    }
  }
  // Control characters would break tables and reports: show them as \xNN.
  return s.replace(/[\x00-\x1f\x7f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)) + b[o + 3] * 0x1000000;
const u64 = (b, o) => u32(b, o) + u32(b, o + 4) * 0x100000000;

function findEnd(src) {
  const tail = Math.min(src.size, 22 + 65535 + 20);
  const start = src.size - tail;
  const b = src.bytesUpTo(start, tail);
  for (let i = b.length - 22; i >= 0; i--) {
    if (b[i] === 0x50 && u32(b, i) === SIG_EOCD) {
      const commentLen = u16(b, i + 20);
      if (i + 22 + commentLen > b.length) continue;
      return { pos: start + i, b, i };
    }
  }
  return null;
}

/**
 * Reads the central directory. Returns { entries, cdOffset, cdSize, eocdPos, zip64, problems }.
 * Each entry: { name, size, packed, method, methodName, crc, offset, dir, encrypted, supported, index }.
 */
function readZip(src, limits = {}) {
  const L = { ...ZIP_LIMITS, ...limits };
  if (src.size < 22) throw new ZipError('This file is too small to be an APK (an APK is a ZIP archive).', 'NOT_ZIP');
  const end = findEnd(src);
  if (!end) {
    const h = src.bytesUpTo(0, 4);
    if (h.length === 4 && u32(h, 0) === SIG_LOC) throw new ZipError('The file starts like a ZIP archive (an APK is one), but its end-of-archive record is missing: the file is cut short or damaged.', 'DAMAGED');
    throw new ZipError('This is not a ZIP archive, so it is not an APK: the end-of-archive record is missing.', 'NOT_ZIP');
  }
  const { b, i } = end;
  let count = u16(b, i + 10), cdSize = u32(b, i + 12), cdOffset = u32(b, i + 16);
  let zip64 = false;
  if (end.pos >= 20) {
    const loc = src.bytesUpTo(end.pos - 20, 20);
    if (loc.length === 20 && u32(loc, 0) === SIG_Z64_LOC) {
      const recOff = u64(loc, 8);
      const rec = src.bytesUpTo(recOff, 56);
      if (rec.length === 56 && u32(rec, 0) === SIG_Z64_EOCD) { zip64 = true; count = u64(rec, 32); cdSize = u64(rec, 40); cdOffset = u64(rec, 48); }
    }
  }
  const problems = [];
  if (count > L.maxEntries) throw new ZipError(`This archive lists ${count.toLocaleString('en-US')} entries. APK Analyzer reads up to ${L.maxEntries.toLocaleString('en-US')}.`, 'LIMIT');
  if (cdSize > L.maxCentralDir) throw new ZipError(`The central directory is ${Math.round(cdSize / 1048576)} MB, which is too large to read.`, 'LIMIT');
  if (cdOffset + cdSize > src.size) throw new ZipError('The central directory points past the end of the file. The file is cut short or damaged.', 'DAMAGED');
  const cd = src.bytes(cdOffset, cdSize);
  const entries = [];
  let p = 0;
  for (let n = 0; n < count || (count === 0xffff && p < cd.length); n++) {
    if (p + 46 > cd.length || u32(cd, p) !== SIG_CEN) {
      if (n < count) problems.push(`The central directory ends after ${n} of ${count} entries. The archive may be damaged.`);
      break;
    }
    if (entries.length >= L.maxEntries) { problems.push(`Only the first ${L.maxEntries} entries were read.`); break; }
    const flags = u16(cd, p + 8), method = u16(cd, p + 10), crc = u32(cd, p + 16);
    let packed = u32(cd, p + 20), size = u32(cd, p + 24);
    const nameLen = u16(cd, p + 28), extraLen = u16(cd, p + 30), commentLen = u16(cd, p + 32);
    let offset = u32(cd, p + 42);
    if (p + 46 + nameLen + extraLen + commentLen > cd.length) { problems.push(`Entry ${n + 1} runs past the end of the central directory.`); break; }
    const name = decodeName(cd.subarray(p + 46, p + 46 + nameLen), (flags & 0x800) !== 0);
    const extra = cd.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
    for (let e = 0; e + 4 <= extra.length;) {
      const id = u16(extra, e), len = u16(extra, e + 2), d = extra.subarray(e + 4, e + 4 + len);
      if (id === 0x0001) {
        let q = 0;
        if (size === 0xffffffff && q + 8 <= d.length) { size = u64(d, q); q += 8; }
        if (packed === 0xffffffff && q + 8 <= d.length) { packed = u64(d, q); q += 8; }
        if (offset === 0xffffffff && q + 8 <= d.length) { offset = u64(d, q); q += 8; }
      }
      e += 4 + len;
    }
    const dir = name.endsWith('/');
    entries.push({ name, size, packed, method, methodName: METHODS[method] || `method ${method}`, crc, offset, dir, encrypted: (flags & 1) !== 0, supported: dir || method === 0 || method === 8, index: n });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return { entries, cdOffset, cdSize, eocdPos: end.pos, zip64, problems };
}

/** Offset of an entry's data (after its local header). */
function dataOffset(src, entry) {
  const h = src.bytesUpTo(entry.offset, 30);
  if (h.length < 30 || u32(h, 0) !== SIG_LOC) throw new ZipError(`The local header of "${entry.name}" is missing. The archive may be damaged.`, 'DAMAGED');
  const start = entry.offset + 30 + u16(h, 26) + u16(h, 28);
  if (start + entry.packed > src.size) throw new ZipError(`"${entry.name}" runs past the end of the file. The file is cut short.`, 'DAMAGED');
  return start;
}

/** Reads and unpacks one entry, at most `limit` bytes of output (zip bomb guard). Checks the CRC. */
function readEntry(src, entry, limit) {
  if (entry.dir) return new Uint8Array(0);
  if (entry.encrypted) throw new ZipError(`"${entry.name}" is encrypted.`, 'ENTRY');
  if (!entry.supported) throw new ZipError(`"${entry.name}" uses ${entry.methodName} compression; Stored and Deflate are supported.`, 'ENTRY');
  if (entry.size > limit) throw new ZipError(`"${entry.name}" is ${fmtMB(entry.size)} unpacked; the limit is ${fmtMB(limit)}.`, 'LIMIT');
  const start = dataOffset(src, entry);
  const data = src.bytes(start, entry.packed);
  let out;
  if (entry.method === 0) {
    if (data.length !== entry.size) throw new ZipError(`"${entry.name}" has a stored size that does not match its header.`, 'DAMAGED');
    out = data;
  } else {
    try {
      out = zlib.inflateRawSync(data, { maxOutputLength: Math.max(1, Math.min(limit, entry.size + 1)) });
    } catch (e) {
      if (e && (e.code === 'ERR_BUFFER_TOO_LARGE' || /maxOutputLength|buffer/i.test(e.message))) throw new ZipError(`"${entry.name}" unpacks to more than the ${fmtMB(entry.size)} its header says. It was stopped as a possible zip bomb.`, 'BOMB');
      throw new ZipError(`"${entry.name}" could not be unpacked: ${e.message}`, 'DAMAGED');
    }
    out = new Uint8Array(out.buffer, out.byteOffset, out.length);
    if (out.length !== entry.size) throw new ZipError(`"${entry.name}" unpacked to ${out.length} bytes, but its header says ${entry.size}. The entry is damaged.`, out.length > entry.size ? 'BOMB' : 'DAMAGED');
  }
  if (crc32(out) !== entry.crc) throw new ZipError(`"${entry.name}" failed its CRC check. The entry is damaged.`, 'DAMAGED');
  return out;
}

function fmtMB(n) { return n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`; }

let TABLE = null;
function crc32(buf) {
  if (!TABLE) {
    TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; TABLE[n] = c >>> 0; }
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

module.exports = { readZip, readEntry, dataOffset, crc32, decodeName, ZipError, METHODS, ZIP_LIMITS };
