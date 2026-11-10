'use strict';
// Builds APK test files byte by byte: binary XML manifests, DEX files, ZIP archives (stored and deflated), the APK
// Signing Block and a PKCS#7 signature file. No fixture files: every test makes what it needs.
const zlib = require('zlib');
const { crc32 } = require('../src/core/zip');
const { ATTR_NAMES, ANDROID_NS } = require('../src/core/axml');

const ATTR_IDS = Object.fromEntries(Object.entries(ATTR_NAMES).map(([id, n]) => [n, Number(id)]));
// A self-signed EC test certificate (CN=Zovo Test, O=Zovo, C=US), made once with openssl for these tests.
const TEST_CERT = Buffer.from('MIICQzCCAeoCCQDcEa4+cHUuOjAKBggqhkjOPQQDAjAwMRIwEAYDVQQDDAlab3ZvIFRlc3QxDTALBgNVBAoMBFpvdm8xCzAJBgNVBAYTAlVTMB4XDTI2MTExMDAzMTg0N1oXDTM2MTEwNzAzMTg0N1owMDESMBAGA1UEAwwJWm92byBUZXN0MQ0wCwYDVQQKDARab3ZvMQswCQYDVQQGEwJVUzCCAUswggEDBgcqhkjOPQIBMIH3AgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOETnSa3gZ9+kARBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////AAAAAP//////////vOb6racXnoTzucrC/GMlUQIBAQNCAASkIXAV5OGgdoyYycso9sHiHdnu+j+OcTz/qILcFLeH51nQF1qqAdWTZ5uLZ4eTLqw9ApB+YRclrstj4Ya73eUaMAoGCCqGSM49BAMCA0cAMEQCIBxHoDFR4pSBkiJaYYTEpEpaOwuSjqUNsFMpuLClBynEAiAOoCnK4cTh0PgoOTyx/USCiBfCQMsGwyJ3kpc9p2DbMw==', 'base64');
const TEST_CERT_SHA256 = 'fb7086f78e34b2e557215f10a88ed2e0219e3e39aef0591cfa6c9cc28fdd3297';

const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v & 0xffff); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
const u64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
const uleb = (v) => { const out = []; do { let x = v & 0x7f; v >>>= 7; if (v) x |= 0x80; out.push(x); } while (v); return Buffer.from(out); };

// ---------------- AXML ----------------

/** el(tag, attrs, children): attrs = [[name, value, type?, ns?]] with type 'str' (default), 'int', 'bool', 'ref', 'hex', 'dim'. */
const el = (tag, attrs = [], children = []) => ({ tag, attrs, children });

/**
 * Binary XML from an element tree. opts: { utf8, rawSize (override string pool count), extra(buf) hook }.
 */
function axml(root, opts = {}) {
  const strings = [];
  const idx = (s) => { let i = strings.indexOf(s); if (i < 0) { i = strings.length; strings.push(s); } return i; };
  // android attribute names first (resource map covers them)
  const androidNames = [];
  const walk = (e) => { for (const a of e.attrs) { const ns = a[3] === undefined ? ANDROID_NS : a[3]; if (ns === ANDROID_NS && !androidNames.includes(a[0])) androidNames.push(a[0]); } e.children.forEach(walk); };
  walk(root);
  for (const n of androidNames) idx(opts.blankNames ? '' + n : n);
  if (opts.blankNames) for (let i = 0; i < androidNames.length; i++) strings[i] = '';
  const nsPrefix = idx('android'), nsUri = idx(ANDROID_NS);
  const body = [];
  const chunk = (type, hsize, payload) => Buffer.concat([u16(type), u16(hsize), u32(8 + payload.length), payload]);
  body.push(chunk(0x0100, 16, Buffer.concat([u32(1), u32(0xffffffff), u32(nsPrefix), u32(nsUri)])));
  const elem = (e) => {
    const attrs = e.attrs.map((a) => {
      const [name, value, type = 'str', nsArg] = a;
      const ns = nsArg === undefined ? ANDROID_NS : nsArg;
      const nameIdx = ns === ANDROID_NS ? androidNames.indexOf(name) : idx(name);
      let raw = 0xffffffff, dt = 0x03, data = 0;
      if (type === 'str') { raw = idx(String(value)); data = raw; }
      else if (type === 'int') { dt = 0x10; data = value; }
      else if (type === 'hex') { dt = 0x11; data = value; }
      else if (type === 'bool') { dt = 0x12; data = value ? 0xffffffff : 0; }
      else if (type === 'ref') { dt = 0x01; data = value; }
      else if (type === 'dim') { dt = 0x05; data = value; }
      return Buffer.concat([u32(ns ? idx(ns) : 0xffffffff), u32(nameIdx), u32(raw), u16(8), Buffer.from([0, dt]), u32(data)]);
    });
    const n = opts.attrCount !== undefined && e === root ? opts.attrCount : attrs.length;
    body.push(chunk(0x0102, 16, Buffer.concat([u32(1), u32(0xffffffff), u32(0xffffffff), u32(idx(e.tag)), u16(20), u16(20), u16(n), u16(0), u16(0), u16(0), ...attrs])));
    e.children.forEach(elem);
    body.push(chunk(0x0103, 16, Buffer.concat([u32(1), u32(0xffffffff), u32(0xffffffff), u32(idx(e.tag))])));
  };
  elem(root);
  body.push(chunk(0x0101, 16, Buffer.concat([u32(1), u32(0xffffffff), u32(nsPrefix), u32(nsUri)])));
  // string pool
  const data = [];
  const offs = [];
  let off = 0;
  for (const s of strings) {
    let b;
    if (opts.utf8) { const raw = Buffer.from(s, 'utf8'); b = Buffer.concat([Buffer.from([s.length & 0x7f, raw.length & 0x7f]), raw, Buffer.from([0])]); }
    else { b = Buffer.concat([u16(s.length), Buffer.from(s, 'utf16le'), u16(0)]); }
    offs.push(off); off += b.length; data.push(b);
  }
  let sdata = Buffer.concat(data);
  while (sdata.length % 4) sdata = Buffer.concat([sdata, Buffer.from([0])]);
  const count = opts.rawSize !== undefined ? opts.rawSize : strings.length;
  const poolHdr = 28;
  const pool = Buffer.concat([u16(0x0001), u16(poolHdr), u32(poolHdr + offs.length * 4 + sdata.length), u32(count), u32(0), u32(opts.utf8 ? 0x100 : 0), u32(poolHdr + offs.length * 4), u32(0), ...offs.map(u32), sdata]);
  const resMap = chunk(0x0180, 8, Buffer.concat(androidNames.map((n) => u32(ATTR_IDS[n] || 0))));
  const all = Buffer.concat([pool, resMap, ...body]);
  return Buffer.concat([u16(0x0003), u16(8), u32(8 + all.length), all]);
}

/** A typical manifest. o: { pkg, versionCode, versionName, min, target, perms, debuggable, components } */
function manifest(o = {}) {
  const pkg = o.pkg || 'com.zovo.demo';
  const comps = o.components || [
    el('activity', [['name', '.MainActivity']], [el('intent-filter', [], [el('action', [['name', 'android.intent.action.MAIN']]), el('category', [['name', 'android.intent.category.LAUNCHER']])])]),
    el('activity', [['name', '.SettingsActivity'], ['exported', false, 'bool']]),
    el('service', [['name', 'com.zovo.demo.SyncService'], ['permission', 'android.permission.BIND_JOB_SERVICE']]),
    el('receiver', [['name', '.BootReceiver']], [el('intent-filter', [], [el('action', [['name', 'android.intent.action.BOOT_COMPLETED']])])]),
    el('provider', [['name', '.DataProvider'], ['authorities', 'com.zovo.demo.data'], ['exported', true, 'bool']]),
  ];
  const appAttrs = [['label', o.label === undefined ? 'Zovo Demo' : o.label, o.labelRef ? 'ref' : 'str'], ['allowBackup', true, 'bool']];
  if (o.debuggable) appAttrs.push(['debuggable', true, 'bool']);
  return axml(el('manifest', [['versionCode', o.versionCode || 7, 'int'], ['versionName', o.versionName || '1.2.3'], ['compileSdkVersion', o.compile || 34, 'int'], ['package', pkg, 'str', '']], [
    el('uses-sdk', [['minSdkVersion', o.min || 21, 'int'], ['targetSdkVersion', o.target || 30, 'int']]),
    ...(o.perms || ['android.permission.INTERNET', 'android.permission.CAMERA', 'android.permission.ACCESS_FINE_LOCATION', 'android.permission.SYSTEM_ALERT_WINDOW', 'com.zovo.demo.permission.C2D']).map((p) => el('uses-permission', [['name', p]])),
    el('application', appAttrs, comps),
  ]), o.axml || {});
}

// ---------------- DEX ----------------

/**
 * classes: [{ name: 'Lcom/zovo/A;', methods: ['run', 'stop'], fields: 1, super }]. refs: extra method refs [['Landroid/app/Activity;', 'onCreate']].
 * o.override: { offset: value } u32 patches after building (hostile counts).
 */
function dex(o = {}) {
  const classes = o.classes || [
    { name: 'Lcom/zovo/demo/MainActivity;', methods: ['onCreate', 'onResume', '<init>'], fields: 2, super: 'Landroid/app/Activity;' },
    { name: 'Lcom/zovo/demo/net/Api;', methods: ['get', 'post'], fields: 1 },
    { name: 'Lokhttp3/Call;', methods: ['execute'], fields: 0 },
  ];
  const refs = o.refs || [['Landroid/app/Activity;', 'onCreate'], ['Ljava/lang/Object;', '<init>']];
  const strings = [];
  const si = (s) => { let i = strings.indexOf(s); if (i < 0) { i = strings.length; strings.push(s); } return i; };
  const types = [];
  const ti = (d) => { si(d); let i = types.indexOf(d); if (i < 0) { i = types.length; types.push(d); } return i; };
  ti('V');
  for (const c of classes) { ti(c.name); if (c.super) ti(c.super); }
  for (const [c] of refs) ti(c);
  const methods = [];
  for (const c of classes) for (const mn of c.methods) methods.push([ti(c.name), si(mn)]);
  for (const [c, mn] of refs) methods.push([ti(c), si(mn)]);
  const fields = [];
  for (const c of classes) for (let k = 0; k < c.fields; k++) fields.push([ti(c.name), ti('V'), si(`f${k}`)]);
  for (const s of o.strings || []) si(s);
  const shorty = si('V');
  // layout
  const H = 0x70;
  const sOff = H, tOff = sOff + strings.length * 4, pOff = tOff + types.length * 4, fOff = pOff + 12, mOff = fOff + fields.length * 8, cOff = mOff + methods.length * 8;
  const dataOff = cOff + classes.length * 32;
  const data = [];
  let dpos = dataOff;
  const put = (buf) => { const at = dpos; data.push(buf); dpos += buf.length; return at; };
  const strOffs = strings.map((s) => put(Buffer.concat([uleb(s.length), Buffer.from(s, 'utf8'), Buffer.from([0])])));
  const classData = classes.map((c) => put(Buffer.concat([uleb(0), uleb(c.fields), uleb(c.methods.length), uleb(0), ...c.methods.map((_, k) => Buffer.concat([uleb(k === 0 ? 0 : 1), uleb(1), uleb(0)])), ...Array.from({ length: c.fields }, (_, k) => Buffer.concat([uleb(k === 0 ? 0 : 1), uleb(1)]))])));
  const body = Buffer.concat([
    ...strOffs.map(u32), ...types.map((t) => u32(si(t))),
    u32(shorty), u32(ti('V')), u32(0),
    ...fields.map(([c, t, n]) => Buffer.concat([u16(c), u16(t), u32(n)])),
    ...methods.map(([c, n]) => Buffer.concat([u16(c), u16(0), u32(n)])),
    ...classes.map((c, i) => Buffer.concat([u32(ti(c.name)), u32(1), u32(c.super ? ti(c.super) : 0xffffffff), u32(0), u32(0xffffffff), u32(0), u32(classData[i]), u32(0)])),
    ...data,
  ]);
  const total = H + body.length;
  const h = Buffer.alloc(H);
  h.write('dex\n035\0', 0, 'latin1');
  h.writeUInt32LE(total, 32); h.writeUInt32LE(H, 36); h.writeUInt32LE(0x12345678, 40);
  const tbl = [[56, strings.length, sOff], [64, types.length, tOff], [72, 1, pOff], [80, fields.length, fOff], [88, methods.length, mOff], [96, classes.length, cOff]];
  for (const [at, n, off] of tbl) { h.writeUInt32LE(n, at); h.writeUInt32LE(n ? off : 0, at + 4); }
  h.writeUInt32LE(total - dataOff, 104); h.writeUInt32LE(dataOff, 108);
  const out = Buffer.concat([h, body]);
  for (const [k, v] of Object.entries(o.override || {})) out.writeUInt32LE(v >>> 0, Number(k));
  return out;
}

// ---------------- ZIP and signing ----------------

/** files: [{ name, data, method (0|8), sizeOverride }]. o.sigBlock: bytes placed before the central directory. */
function zip(files, o = {}) {
  const locals = [], cds = [];
  let off = 0;
  for (const f of files) {
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data || '');
    const method = f.method === undefined ? 8 : f.method;
    const packed = method === 8 ? zlib.deflateRawSync(data) : data;
    const name = Buffer.from(f.name, 'utf8');
    const crc = f.crc !== undefined ? f.crc : crc32(data);
    const size = f.sizeOverride !== undefined ? f.sizeOverride : data.length;
    const lh = Buffer.concat([u32(0x04034b50), u16(20), u16(0x800), u16(method), u16(0), u16(0x21), u32(crc), u32(packed.length), u32(size), u16(name.length), u16(0), name]);
    locals.push(lh, packed);
    cds.push(Buffer.concat([u32(0x02014b50), u16(0x031e), u16(20), u16(0x800), u16(method), u16(0), u16(0x21), u32(crc), u32(packed.length), u32(size), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(off), name]));
    off += lh.length + packed.length;
  }
  const sig = o.sigBlock || Buffer.alloc(0);
  const cd = Buffer.concat(cds);
  const cdOff = off + sig.length;
  const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(o.countOverride !== undefined ? o.countOverride : files.length), u16(o.countOverride !== undefined ? o.countOverride : files.length), u32(cd.length), u32(cdOff), u16(0)]);
  return Buffer.concat([...locals, sig, cd, eocd]);
}

/** APK Signing Block from [[id, value]] pairs. */
function sigBlock(pairs) {
  const body = Buffer.concat(pairs.map(([id, v]) => Buffer.concat([u64(v.length + 4), u32(id), v])));
  const size = body.length + 8 + 16;
  return Buffer.concat([u64(size), body, u64(size), Buffer.from('APK Sig Block 42', 'latin1')]);
}
const lp = (...parts) => { const b = Buffer.concat(parts); return Buffer.concat([u32(b.length), b]); };
/** v2/v3 block value with one signer and the test certificate. */
function v2Value(cert = TEST_CERT) {
  const signedData = lp(lp(lp(u32(0x0103), lp(Buffer.alloc(32)))), lp(lp(cert)), lp());
  return lp(lp(signedData, lp(), lp(Buffer.alloc(16))));
}

// minimal DER
const der = (tag, ...parts) => {
  const b = Buffer.concat(parts);
  const len = b.length < 128 ? Buffer.from([b.length]) : b.length < 256 ? Buffer.from([0x81, b.length]) : Buffer.from([0x82, b.length >> 8, b.length & 255]);
  return Buffer.concat([Buffer.from([tag]), len, b]);
};
/** PKCS#7 SignedData holding the certificate (no signer info needed by the reader). */
function pkcs7(cert = TEST_CERT) {
  const oidSigned = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
  const oidData = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
  const sd = der(0x30, der(0x02, Buffer.from([1])), der(0x31), der(0x30, oidData), der(0xa0, cert), der(0x31));
  return der(0x30, oidSigned, der(0xa0, sd));
}

/** A whole test APK. o: manifest options, dex options, extra files, v1, v2, abis. */
function apk(o = {}) {
  const files = [
    { name: 'AndroidManifest.xml', data: o.manifestBytes || manifest(o.manifest) },
    { name: 'classes.dex', data: o.dexBytes || dex(o.dex) },
  ];
  if (o.dex2) files.push({ name: 'classes2.dex', data: dex(o.dex2) });
  files.push({ name: 'resources.arsc', data: Buffer.alloc(o.arsc || 4096, 1), method: 0 });
  files.push({ name: 'res/drawable/icon.png', data: Buffer.alloc(1500, 7), method: 0 });
  files.push({ name: 'res/layout/main.xml', data: Buffer.alloc(800, 3) });
  for (const abi of o.abis || ['arm64-v8a', 'x86_64']) files.push({ name: `lib/${abi}/libzovo.so`, data: Buffer.alloc(3000, abi.length) });
  for (const f of o.extra || []) files.push(f);
  if (o.v1 !== false) {
    files.push({ name: 'META-INF/MANIFEST.MF', data: 'Manifest-Version: 1.0\r\n' });
    files.push({ name: 'META-INF/CERT.SF', data: 'Signature-Version: 1.0\r\n' });
    files.push({ name: 'META-INF/CERT.RSA', data: pkcs7() });
  }
  const pairs = [];
  if (o.v2 !== false) pairs.push([0x7109871a, v2Value()]);
  if (o.v3) pairs.push([0xf05368c0, v2Value()]);
  return zip(files, { sigBlock: pairs.length ? sigBlock(pairs) : undefined });
}

module.exports = { el, axml, manifest, dex, zip, sigBlock, v2Value, pkcs7, apk, TEST_CERT, TEST_CERT_SHA256, u16, u32, uleb };
