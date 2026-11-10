'use strict';
// DEX reader: header check, the id table counts, method references against the 65,536 limit, and the classes this
// file defines with their method and field counts, grouped by package. Every table is checked against the file
// size before it is read; counts that do not fit are clamped to what is there and named in a warning.

const DEX_LIMITS = { maxClasses: 200000, maxString: 4096 };
const METHOD_LIMIT = 65536;

class DexError extends Error { constructor(m) { super(m); this.name = 'DexError'; this.code = 'DEX'; } }

const UTF8 = new TextDecoder('utf-8', { fatal: false });

function uleb(b, p, end) {
  let v = 0, shift = 0;
  for (let i = 0; i < 5; i++) {
    if (p >= end) throw new RangeError('uleb128 past the end');
    const x = b[p++];
    v += (x & 0x7f) * 2 ** shift;
    if (!(x & 0x80)) return [v, p];
    shift += 7;
  }
  throw new RangeError('uleb128 longer than 5 bytes');
}

/** Lcom/foo/Bar; -> com.foo.Bar ; [I -> int[] */
function javaName(desc) {
  let d = String(desc || ''), dims = 0;
  while (d.startsWith('[') && dims < 255) { d = d.slice(1); dims++; }
  const prim = { V: 'void', Z: 'boolean', B: 'byte', S: 'short', C: 'char', I: 'int', J: 'long', F: 'float', D: 'double' };
  let n = d.startsWith('L') && d.endsWith(';') ? d.slice(1, -1).replace(/\//g, '.') : prim[d] || d;
  return n + '[]'.repeat(dims);
}
const packageOf = (cls) => { const i = cls.lastIndexOf('.'); return i < 0 ? '(default package)' : cls.slice(0, i); };

/**
 * Parses one DEX file. Returns { version, size, counts: { strings, types, protos, fields, methods, classes },
 * methodRefs, fieldRefs, classes: [{ name, pkg, methods, fields, access, super }], refsByPackage: Map, warnings }.
 * opts.strings: true to keep a string reader (for find).
 */
function parseDex(bytes, name = 'classes.dex', limits = {}) {
  const L = { ...DEX_LIMITS, ...limits };
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b.length < 0x70) throw new DexError(`${name} is ${b.length} bytes, shorter than a DEX header (112 bytes).`);
  const magic = String.fromCharCode(...b.subarray(0, 8));
  if (!/^dex\n0\d\d\0$/.test(magic)) throw new DexError(`${name} does not start with the DEX magic "dex\\n0NN".`);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u32 = (o) => dv.getUint32(o, true), u16 = (o) => dv.getUint16(o, true);
  const warnings = [];
  const warn = (w) => { if (warnings.length < 30 && !warnings.includes(w)) warnings.push(w); };
  if (u32(40) !== 0x12345678) warn(`${name}: the endian tag is 0x${u32(40).toString(16)}, not 0x12345678; values may be wrong.`);
  const fileSize = u32(32);
  if (fileSize !== b.length) warn(`${name}: the header says ${fileSize.toLocaleString('en-US')} bytes, the file has ${b.length.toLocaleString('en-US')}.`);
  const N = b.length;
  // [count, offset, item size] of each id table, clamped to the bytes that are there.
  const table = (label, at, item) => {
    let n = u32(at), off = u32(at + 4);
    if (n === 0) return { n: 0, off };
    if (off >= N) { warn(`${name}: the ${label} table starts past the end of the file (${n.toLocaleString('en-US')} listed); it was not read.`); return { n: 0, off, listed: n }; }
    const fit = Math.floor((N - off) / item);
    if (n > fit) { warn(`${name}: the header lists ${n.toLocaleString('en-US')} ${label}, but only ${fit.toLocaleString('en-US')} fit in the file; the rest were not read.`); return { n: fit, off, listed: n }; }
    return { n, off, listed: n };
  };
  const S = table('strings', 56, 4), T = table('types', 64, 4), P = table('prototypes', 72, 12), F = table('fields', 80, 8), M = table('methods', 88, 8), C = table('classes', 96, 32);
  const scache = new Map();
  const str = (i) => {
    if (!Number.isInteger(i) || i < 0 || i >= S.n) return '';
    let s = scache.get(i);
    if (s !== undefined) return s;
    s = '';
    try {
      const off = u32(S.off + i * 4);
      if (off < N) {
        const [, p] = uleb(b, off, N);
        let e = p; const lim = Math.min(N, p + L.maxString);
        while (e < lim && b[e] !== 0) e++;
        s = UTF8.decode(b.subarray(p, e));
      }
    } catch { s = ''; }
    if (scache.size < 300000) scache.set(i, s);
    return s;
  };
  const type = (i) => (i >= 0 && i < T.n ? str(u32(T.off + i * 4)) : '');
  const listed = (x) => (x.listed !== undefined ? x.listed : x.n);
  const counts = { strings: listed(S), types: listed(T), protos: listed(P), fields: listed(F), methods: listed(M), classes: listed(C) };
  // method references by package (what the 64K limit counts)
  const refsByPackage = new Map();
  const typePkg = new Map();
  const pkgOfType = (ti) => {
    let p = typePkg.get(ti);
    if (p === undefined) { p = packageOf(javaName(type(ti))); typePkg.set(ti, p); }
    return p;
  };
  for (let i = 0; i < M.n; i++) {
    const p = pkgOfType(u16(M.off + i * 8));
    refsByPackage.set(p, (refsByPackage.get(p) || 0) + 1);
  }
  const classes = [];
  const nClasses = Math.min(C.n, L.maxClasses);
  if (C.n > L.maxClasses) warn(`${name}: only the first ${L.maxClasses.toLocaleString('en-US')} classes are listed.`);
  let badData = 0;
  for (let i = 0; i < nClasses; i++) {
    const at = C.off + i * 32;
    const cname = javaName(type(u32(at)));
    const access = u32(at + 4), sup = u32(at + 8), dataOff = u32(at + 24);
    let methods = 0, fields = 0;
    if (dataOff) {
      try {
        if (dataOff >= N) throw new RangeError('past the end');
        let p = dataOff, sf, inf, dm, vm;
        [sf, p] = uleb(b, p, N); [inf, p] = uleb(b, p, N); [dm, p] = uleb(b, p, N); [vm, p] = uleb(b, p, N);
        methods = dm + vm; fields = sf + inf;
        if (methods > N || fields > N) throw new RangeError('counts larger than the file');
      } catch { badData++; methods = 0; fields = 0; }
    }
    classes.push({ name: cname, pkg: packageOf(cname), methods, fields, access: accessText(access), super: sup === 0xffffffff ? '' : javaName(type(sup)) });
  }
  if (badData) warn(`${name}: ${badData} class${badData === 1 ? '' : 'es'} have class data past the end of the file or with impossible counts; their method counts are shown as 0.`);
  const version = magic.slice(4, 7);
  return {
    name, version, size: N, counts, methodRefs: counts.methods, fieldRefs: counts.fields, classes, refsByPackage, warnings,
    // readers for find (used in the worker only)
    _r: { str, type, S, T, M, F, P, u16, u32 },
  };
}

function accessText(f) {
  const out = [];
  if (f & 0x1) out.push('public');
  if (f & 0x10) out.push('final');
  if (f & 0x200) out.push('interface');
  if (f & 0x400) out.push('abstract');
  if (f & 0x1000) out.push('synthetic');
  if (f & 0x2000) out.push('annotation');
  if (f & 0x4000) out.push('enum');
  return out.join(' ');
}

/** Search one parsed DEX: strings, classes (defined or referenced), method and field references. */
function findInDex(d, match, max = 5000) {
  const hits = [];
  const { str, type, S, T, M, F, P, u16, u32 } = d._r;
  const add = (kind, name, detail) => { if (hits.length < max) hits.push({ kind, name, dex: d.name, detail: detail || '' }); return hits.length < max; };
  const defined = new Set(d.classes.map((c) => c.name));
  for (let i = 0; i < T.n; i++) { const n = javaName(type(i)); if (match.test(n) && !add('class', n, defined.has(n) ? 'defined here' : 'referenced')) return hits; }
  const proto = (pi) => {
    if (pi >= P.n) return '()';
    const at = P.off + pi * 12;
    const ret = javaName(type(u32(at + 4)));
    const poff = u32(at + 8);
    const args = [];
    if (poff && poff + 4 <= d.size) { const n = Math.min(u32(poff), 64); for (let k = 0; k < n && poff + 4 + k * 2 + 2 <= d.size; k++) args.push(javaName(type(u16(poff + 4 + k * 2)))); }
    return `(${args.join(', ')}) ${ret}`;
  };
  for (let i = 0; i < M.n; i++) {
    const at = M.off + i * 8;
    const mname = str(u32(at + 4));
    const full = `${javaName(type(u16(at)))}.${mname}`;
    if (match.test(full) && !add('method', full, proto(u16(at + 2)))) return hits;
  }
  for (let i = 0; i < F.n; i++) {
    const at = F.off + i * 8;
    const full = `${javaName(type(u16(at)))}.${str(u32(at + 4))}`;
    if (match.test(full) && !add('field', full, javaName(type(u16(at + 2))))) return hits;
  }
  for (let i = 0; i < S.n; i++) { const s = str(i); if (s && match.test(s) && !add('string', s.length > 300 ? s.slice(0, 300) + '…' : s, '')) return hits; }
  return hits;
}

module.exports = { parseDex, findInDex, javaName, packageOf, DexError, METHOD_LIMIT, DEX_LIMITS };
