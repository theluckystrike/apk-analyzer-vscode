'use strict';
// Bounded random access to the bytes of a binary. Every read checks its range: a read past the end throws Trunc,
// which the parsers catch per table, so a cut or hostile file gives a warning and the rest of the structure.
// A file source reads 64 KB blocks with a small cache, so a 500 MB file costs only the blocks a parser touches.
// No vscode here: the parsers run in a worker thread and in plain Node tests.
const fs = require('fs');

const BLOCK = 1 << 16;
const MAX_BLOCKS = 256; // 16 MB of cache at most

class Trunc extends Error {
  constructor(off, n, size) {
    super(`needs ${n} byte${n === 1 ? '' : 's'} at 0x${Math.max(0, off).toString(16)}, past the end of the data (0x${size.toString(16)})`);
    this.name = 'Trunc';
  }
}

class Source {
  /** readBlock(k) returns the bytes of block k (BLOCK bytes, shorter at the end). base/limit make a window (fat slices). */
  constructor(size, readBlock, base = 0, limit = size) {
    this.total = size;
    this.base = base;
    this.size = Math.max(0, Math.min(limit, size - base));
    this.readBlock = readBlock;
    this.cache = new Map();
    this.reads = 0;
  }

  static fromBuffer(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    const s = new Source(b.length, null);
    s.buf = b;
    return s;
  }

  static fromFile(file) {
    const fd = fs.openSync(file, 'r');
    const size = fs.fstatSync(fd).size;
    const s = new Source(size, (k) => {
      const len = Math.min(BLOCK, size - k * BLOCK);
      const out = Buffer.alloc(Math.max(0, len));
      let got = 0;
      while (got < len) {
        const n = fs.readSync(fd, out, got, len - got, k * BLOCK + got);
        if (n <= 0) break;
        got += n;
      }
      return new Uint8Array(out.buffer, out.byteOffset, got);
    });
    s.fd = fd;
    return s;
  }

  close() { if (this.fd !== undefined) { try { fs.closeSync(this.fd); } catch { /* already closed */ } this.fd = undefined; } }

  /** A window of this source: offsets inside it start at 0 (used for the slices of a universal Mach-O). */
  slice(off, len) {
    const s = new Source(this.total, this.readBlock, this.base + off, Math.min(len, this.size - off));
    s.buf = this.buf; s.cache = this.cache; s.parent = this;
    return s;
  }

  check(off, n) {
    if (!Number.isSafeInteger(off) || off < 0 || n < 0 || off + n > this.size) throw new Trunc(Number.isSafeInteger(off) ? off : -1, n, this.size);
  }

  block(k) {
    if (this.parent) return this.parent.block(k);
    let b = this.cache.get(k);
    if (b) { this.cache.delete(k); this.cache.set(k, b); return b; }
    this.reads++;
    b = this.readBlock(k);
    this.cache.set(k, b);
    if (this.cache.size > MAX_BLOCKS) this.cache.delete(this.cache.keys().next().value);
    return b;
  }

  /** Exactly n bytes at off (throws Trunc when they are not all there). */
  bytes(off, n) {
    this.check(off, n);
    const a = this.base + off;
    if (this.buf) return this.buf.subarray(a, a + n);
    const k0 = Math.floor(a / BLOCK), k1 = Math.floor((a + n - 1) / BLOCK);
    if (n === 0) return new Uint8Array(0);
    if (k0 === k1) { const b = this.block(k0); const s = a - k0 * BLOCK; return b.subarray(s, s + n); }
    const out = new Uint8Array(n);
    let got = 0;
    for (let k = k0; k <= k1 && got < n; k++) {
      const b = this.block(k);
      const s = k === k0 ? a - k0 * BLOCK : 0;
      const take = Math.min(b.length - s, n - got);
      if (take <= 0) break;
      out.set(b.subarray(s, s + take), got);
      got += take;
    }
    return out;
  }

  /** Up to n bytes at off (shorter at the end, empty past it). */
  bytesUpTo(off, n) {
    if (!Number.isSafeInteger(off) || off < 0 || off >= this.size) return new Uint8Array(0);
    return this.bytes(off, Math.min(n, this.size - off));
  }

  u8(off) { return this.bytes(off, 1)[0]; }
  u16(off, le) { const b = this.bytes(off, 2); return le ? b[0] | (b[1] << 8) : (b[0] << 8) | b[1]; }
  u32(off, le) { const b = this.bytes(off, 4); return le ? (b[0] | (b[1] << 8) | (b[2] << 16)) + b[3] * 0x1000000 : b[0] * 0x1000000 + ((b[1] << 16) | (b[2] << 8) | b[3]); }
  i32(off, le) { const v = this.u32(off, le); return v >= 0x80000000 ? v - 0x100000000 : v; }
  /** 64-bit value as a BigInt (addresses can be above 2^53). */
  u64(off, le) {
    const lo = this.u32(off + (le ? 0 : 4), le), hi = this.u32(off + (le ? 4 : 0), le);
    return (BigInt(hi) << 32n) | BigInt(lo);
  }
  /** 32 or 64-bit unsigned value as BigInt. */
  word(off, le, is64) { return is64 ? this.u64(off, le) : BigInt(this.u32(off, le)); }

  /** NUL-terminated string at off, at most max bytes, decoded as UTF-8 (Latin-1 for bad bytes is not needed: U+FFFD is fine). */
  cstr(off, max = 4096) {
    if (!Number.isSafeInteger(off) || off < 0 || off >= this.size) throw new Trunc(off, 1, this.size);
    const b = this.bytesUpTo(off, max);
    let end = b.indexOf(0);
    if (end < 0) end = b.length;
    return decodeName(b.subarray(0, end));
  }

  /** Fixed-length name field (Mach-O segname, PE section name): stops at the first NUL. */
  fixed(off, n) {
    const b = this.bytes(off, n);
    let end = b.indexOf(0);
    if (end < 0) end = n;
    return decodeName(b.subarray(0, end));
  }
}

const UTF8 = new TextDecoder('utf-8', { fatal: false });
function decodeName(b) {
  // Control characters would break the table and the C header: show them as \xNN.
  return UTF8.decode(b).replace(/[\x00-\x1f\x7f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

/** BigInt or number to "0x..." (upper-case digits). */
function hex(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'bigint') return (v < 0n ? '-0x' + (-v).toString(16) : '0x' + v.toString(16)).toUpperCase().replace(/^(-?)0X/, '$10x');
  if (!Number.isFinite(v)) return String(v);
  return (v < 0 ? '-0x' + (-v).toString(16) : '0x' + v.toString(16)).toUpperCase().replace(/^(-?)0X/, '$10x');
}

/** BigInt to a safe Number, or null when it is too large to be a file offset. */
function safe(v) {
  if (typeof v === 'number') return Number.isSafeInteger(v) ? v : null;
  return v >= 0n && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : null;
}

/** Unsigned LEB128 at off: { value: BigInt, len }. At most 10 bytes. */
function uleb(src, off, end) {
  let result = 0n, shift = 0n, len = 0;
  for (;;) {
    if (off + len >= end || len >= 10) throw new Trunc(off + len, 1, end);
    const b = src.u8(off + len);
    result |= BigInt(b & 0x7f) << shift;
    len++;
    if (!(b & 0x80)) break;
    shift += 7n;
  }
  return { value: result, len };
}

module.exports = { Source, Trunc, hex, safe, uleb, decodeName, BLOCK };
