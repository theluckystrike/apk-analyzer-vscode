'use strict';
// Android binary XML (AXML) decoder for AndroidManifest.xml: string pool (UTF-8 and UTF-16), resource map,
// namespaces, elements and typed attribute values. Every count and offset is checked against its chunk, chunk sizes
// of 0 or past the end stop the walk, and element, attribute and output sizes are capped.

const RES_XML = 0x0003, STRING_POOL = 0x0001, RESOURCE_MAP = 0x0180;
const START_NS = 0x0100, END_NS = 0x0101, START_EL = 0x0102, END_EL = 0x0103, CDATA = 0x0104;
const AXML_LIMITS = { maxStrings: 500000, maxElements: 200000, maxAttrs: 4096, maxDepth: 512, maxXml: 8 * 1024 * 1024, maxString: 65536 };
const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

// Attribute names by resource id, used when a shrunk manifest has empty attribute name strings.
const ATTR_NAMES = {
  0x01010000: 'theme', 0x01010001: 'label', 0x01010002: 'icon', 0x01010003: 'name', 0x01010006: 'permission',
  0x01010007: 'readPermission', 0x01010008: 'writePermission', 0x01010009: 'protectionLevel', 0x0101000b: 'sharedUserId',
  0x0101000c: 'hasCode', 0x0101000e: 'enabled', 0x0101000f: 'debuggable', 0x01010010: 'exported', 0x01010011: 'process',
  0x01010018: 'authorities', 0x0101001b: 'grantUriPermissions', 0x0101001c: 'priority', 0x0101001d: 'launchMode',
  0x0101001e: 'screenOrientation', 0x01010020: 'description', 0x01010024: 'value', 0x01010025: 'resource',
  0x01010026: 'mimeType', 0x01010027: 'scheme', 0x01010028: 'host', 0x01010029: 'port', 0x0101002a: 'path',
  0x0101002b: 'pathPrefix', 0x0101002c: 'pathPattern', 0x0101020c: 'minSdkVersion', 0x0101021b: 'versionCode',
  0x0101021c: 'versionName', 0x01010270: 'targetSdkVersion', 0x01010271: 'maxSdkVersion', 0x01010272: 'testOnly',
  0x01010280: 'allowBackup', 0x0101028e: 'required', 0x010102b7: 'installLocation', 0x010104ea: 'extractNativeLibs',
  0x010104ec: 'usesCleartextTraffic', 0x01010527: 'networkSecurityConfig', 0x01010572: 'compileSdkVersion',
  0x01010573: 'compileSdkVersionCodename',
};

class AxmlError extends Error { constructor(m) { super(m); this.name = 'AxmlError'; this.code = 'AXML'; } }

const UTF8 = new TextDecoder('utf-8', { fatal: false });
const UTF16 = new TextDecoder('utf-16le', { fatal: false });

function rd(b) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return { u8: (o) => dv.getUint8(o), u16: (o) => dv.getUint16(o, true), u32: (o) => dv.getUint32(o, true), i32: (o) => dv.getInt32(o, true), f32: (o) => dv.getFloat32(o, true), len: b.byteLength };
}

/** Reads a string pool chunk at `at` (size `size`). Returns a function idx -> string ('' for bad indexes). */
function stringPool(b, r, at, size, L, warn) {
  const hdr = r.u16(at + 2);
  const count = r.u32(at + 8), flags = r.u32(at + 16), strStart = r.u32(at + 20);
  const utf8 = (flags & 0x100) !== 0;
  if (count > L.maxStrings) throw new AxmlError(`The string pool lists ${count.toLocaleString('en-US')} strings; the limit is ${L.maxStrings.toLocaleString('en-US')}.`);
  if (hdr < 28 || hdr + count * 4 > size) throw new AxmlError(`The string pool says it has ${count.toLocaleString('en-US')} strings, which do not fit in its ${size.toLocaleString('en-US')} bytes.`);
  if (strStart > size) throw new AxmlError('The string pool data starts past the end of its chunk.');
  const end = at + size;
  const cache = new Map();
  let bad = 0;
  const get = (i) => {
    if (!Number.isInteger(i) || i < 0 || i >= count) return null;
    if (cache.has(i)) return cache.get(i);
    let s = '';
    try {
      let p = at + strStart + r.u32(at + hdr + i * 4);
      if (utf8) {
        let n = r.u8(p++); if (n & 0x80) n = ((n & 0x7f) << 8) | r.u8(p++); // UTF-16 length (unused)
        let m = r.u8(p++); if (m & 0x80) m = ((m & 0x7f) << 8) | r.u8(p++);
        if (p + m > end) throw new RangeError('string past the pool');
        s = UTF8.decode(b.subarray(p, p + Math.min(m, L.maxString)));
      } else {
        let n = r.u16(p); p += 2; if (n & 0x8000) { n = ((n & 0x7fff) << 16) | r.u16(p); p += 2; }
        if (p + n * 2 > end) throw new RangeError('string past the pool');
        s = UTF16.decode(b.subarray(p, p + Math.min(n, L.maxString) * 2));
      }
    } catch { if (bad++ === 0) warn('Some strings in the manifest string pool point past its end; they are shown empty.'); s = ''; }
    if (cache.size < 100000) cache.set(i, s);
    return s;
  };
  get.count = count;
  get.utf8 = utf8;
  return get;
}

function complexToString(data, fraction) {
  const UNITS = fraction ? ['%', '%p'] : ['px', 'dp', 'sp', 'pt', 'in', 'mm'];
  const RADIX = [1 / (1 << 0), 1 / (1 << 7), 1 / (1 << 15), 1 / (1 << 23)];
  const mantissa = (data & 0xffffff00) >> 8; // signed 24 bit
  const v = mantissa * RADIX[(data >> 4) & 3];
  const unit = UNITS[data & 0xf] || '';
  return `${+(fraction ? v * 100 : v).toFixed(4)}${unit}`;
}

const hex8 = (n) => '0x' + (n >>> 0).toString(16).padStart(8, '0');

/** Typed value to text. Resource references keep their id: @0x7f0e001b. */
function typedValue(type, data, strings) {
  switch (type) {
    case 0x00: return data === 1 ? '@empty' : '';
    case 0x01: return data === 0 ? '@null' : '@' + hex8(data);
    case 0x02: return '?' + hex8(data);
    case 0x03: { const s = strings(data); return s === null ? '' : s; }
    case 0x04: { const f = new DataView(new Uint32Array([data]).buffer).getFloat32(0, true); return String(+f.toFixed(6)); }
    case 0x05: return complexToString(data, false);
    case 0x06: return complexToString(data, true);
    case 0x07: return '@' + hex8(data);
    case 0x10: return String(data | 0);
    case 0x11: return hex8(data);
    case 0x12: return data !== 0 ? 'true' : 'false';
    default:
      if (type >= 0x1c && type <= 0x1f) return '#' + (data >>> 0).toString(16).padStart(8, '0');
      return `(type 0x${type.toString(16)}) ${hex8(data)}`;
  }
}

const xmlEsc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, (c) => '&#x' + c.charCodeAt(0).toString(16) + ';');

/**
 * Decodes a binary XML document. Returns { root, xml, warnings, strings } where root is an element tree
 * { tag, ns, attrs: [{ ns, prefix, name, value, type, data, resId }], children } and xml is readable text.
 */
function decodeAxml(bytes, limits = {}) {
  const L = { ...AXML_LIMITS, ...limits };
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b.length < 8) throw new AxmlError('The manifest is too short to be binary XML.');
  const r = rd(b);
  const warnings = [];
  const warn = (w) => { if (warnings.length < 50 && !warnings.includes(w)) warnings.push(w); };
  const type0 = r.u16(0);
  if (type0 !== RES_XML) {
    if (b[0] === 0x3c) throw new AxmlError('The manifest is plain text XML, not compiled binary XML.');
    throw new AxmlError(`The manifest does not start with a binary XML header (type 0x${type0.toString(16)}). In an .aab bundle the manifest is a protocol buffer; that form is not decoded.`);
  }
  const total = Math.min(r.u32(4), b.length);
  if (r.u32(4) > b.length) warn('The manifest header says it is longer than the stored file; it was read up to the end.');
  let strings = () => null;
  strings.count = 0;
  let resMap = [];
  const nsStack = []; // { prefix, uri }
  const root = { tag: '#document', children: [] };
  const stack = [root];
  let elements = 0;
  let p = r.u16(2) || 8;
  if (p < 8) p = 8;
  let guard = 0;
  while (p + 8 <= total) {
    if (++guard > L.maxElements * 3) { warn('The manifest has too many chunks; the rest was not read.'); break; }
    const type = r.u16(p), hsize = r.u16(p + 2), size = r.u32(p + 4);
    if (size < 8 || hsize < 8 || hsize > size) { warn(`A chunk at byte ${p} has size ${size}, which is not valid; the manifest was read up to there.`); break; }
    if (p + size > total) { warn(`A chunk at byte ${p} runs past the end of the manifest; the manifest was read up to there.`); break; }
    try {
      if (type === STRING_POOL) strings = stringPool(b, r, p, size, L, warn);
      else if (type === RESOURCE_MAP) { const n = Math.min((size - hsize) >>> 2, L.maxStrings); resMap = new Array(n); for (let i = 0; i < n; i++) resMap[i] = r.u32(p + hsize + i * 4); }
      else if (type === START_NS) { if (size >= 24) nsStack.push({ prefix: strings(r.u32(p + 16)) || '', uri: strings(r.u32(p + 20)) || '' }); }
      else if (type === END_NS) { nsStack.pop(); }
      else if (type === START_EL) {
        if (size < 36) throw new AxmlError('an element chunk is too short');
        if (++elements > L.maxElements) { warn(`The manifest has more than ${L.maxElements.toLocaleString('en-US')} elements; the rest was not read.`); break; }
        if (stack.length > L.maxDepth) { warn(`Elements are nested more than ${L.maxDepth} deep; the rest was not read.`); break; }
        const ext = p + hsize;
        const nsIdx = r.u32(ext), nameIdx = r.u32(ext + 4), aStart = r.u16(ext + 8), aSize = r.u16(ext + 10), aCount = r.u16(ext + 12);
        const el = { tag: strings(nameIdx) || `element${elements}`, ns: strings(nsIdx) || '', attrs: [], children: [], nsDecl: nsStack.filter((n) => !n.declared).map((n) => { n.declared = true; return n; }) };
        if (aCount > L.maxAttrs) warn(`An element has ${aCount} attributes; the first ${L.maxAttrs} are shown.`);
        if (aSize < 20) throw new AxmlError('attribute records are shorter than 20 bytes');
        const n = Math.min(aCount, L.maxAttrs);
        if (ext + aStart + n * aSize > p + size) throw new AxmlError(`element "${el.tag}" says it has ${aCount} attributes, which do not fit in its chunk`);
        for (let k = 0; k < n; k++) {
          const a = ext + aStart + k * aSize;
          const ans = strings(r.u32(a)) || '', aname = r.u32(a + 4), raw = r.u32(a + 8), vtype = r.u8(a + 15), data = r.u32(a + 16);
          const resId = aname < resMap.length ? resMap[aname] : 0;
          let name = strings(aname) || '';
          if (!name) name = ATTR_NAMES[resId] || (resId ? `attr_${hex8(resId)}` : `attr${k}`);
          let value = raw !== 0xffffffff && vtype === 0x03 ? strings(raw) : typedValue(vtype, data, strings);
          if (value === null) value = '';
          if (raw !== 0xffffffff && vtype !== 0x03) { const rs = strings(raw); if (rs) value = rs; }
          const ns = nsStack.find((x) => x.uri === ans);
          el.attrs.push({ ns: ans, prefix: ns ? ns.prefix : (ans === ANDROID_NS ? 'android' : ''), name, value, type: vtype, data, resId });
        }
        stack[stack.length - 1].children.push(el);
        stack.push(el);
      } else if (type === END_EL) { if (stack.length > 1) stack.pop(); }
      else if (type === CDATA) {
        const t = strings(r.u32(p + hsize));
        if (t && stack.length > 1) stack[stack.length - 1].children.push({ text: t });
      }
      // other chunk types are skipped by their size
    } catch (e) {
      if (e instanceof AxmlError && /string pool/.test(e.message)) throw e;
      warn(`The manifest is damaged at byte ${p}: ${e.message}. It was read up to there.`);
      break;
    }
    p += size;
  }
  if (stack.length > 1) warn('The manifest ends before all its elements are closed.');
  const top = root.children.find((c) => c.tag);
  if (!top) throw new AxmlError('The manifest has no elements.');
  return { root: top, xml: toXml(top, L.maxXml, warn), warnings, strings: strings.count };
}

/** Element tree to indented XML text (capped). */
function toXml(top, max, warn) {
  const out = ['<?xml version="1.0" encoding="utf-8"?>'];
  let len = out[0].length;
  let cut = false;
  const walk = (el, ind) => {
    if (cut) return;
    if (el.text !== undefined) { out.push(ind + xmlEsc(el.text)); return; }
    const tag = el.tag;
    const attrs = [];
    for (const n of el.nsDecl || []) attrs.push(`xmlns${n.prefix ? ':' + n.prefix : ''}="${xmlEsc(n.uri)}"`);
    for (const a of el.attrs) attrs.push(`${a.prefix ? a.prefix + ':' : ''}${a.name}="${xmlEsc(a.value)}"`);
    const head = attrs.length <= 1 ? `${ind}<${tag}${attrs.length ? ' ' + attrs[0] : ''}` : `${ind}<${tag}\n${attrs.map((x) => ind + '    ' + x).join('\n')}`;
    const line = el.children.length ? `${head}>` : `${head} />`;
    len += line.length + 1;
    if (len > max) { cut = true; return; }
    out.push(line);
    if (el.children.length) {
      for (const c of el.children) walk(c, ind + '    ');
      out.push(`${ind}</${tag}>`);
    }
  };
  walk(top, '');
  if (cut) { out.push('<!-- the rest of the manifest is not shown: the text is longer than 8 MB -->'); warn('The decoded manifest is longer than 8 MB; the XML tab shows the first part.'); }
  return out.join('\n') + '\n';
}

/** First attribute of el named `name` (android namespace preferred). */
function attr(el, name) {
  if (!el || !el.attrs) return undefined;
  const a = el.attrs.find((x) => x.name === name && x.ns === ANDROID_NS) || el.attrs.find((x) => x.name === name);
  return a;
}

module.exports = { decodeAxml, typedValue, attr, AxmlError, ANDROID_NS, ATTR_NAMES, AXML_LIMITS, complexToString };
