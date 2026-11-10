'use strict';
// Readers: AXML, DEX, ZIP, signing and the APK model, on files built byte by byte (test/build.js), plus hostile input.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const B = require('./build');
const { Source } = require('../src/core/source');
const { decodeAxml, typedValue } = require('../src/core/axml');
const { parseDex, findInDex } = require('../src/core/dex');
const { readZip, readEntry } = require('../src/core/zip');
const { parseApk, parseApkFile, entryBytes } = require('../src/core/apk');
const { matcher } = require('../src/core/tools');

const parse = (buf, name = 'app.apk') => parseApk(Source.fromBuffer(buf), name);
const table = (m, id) => m.tables.find((t) => t.id === id);
const sum = (m, k) => (m.summary.find((s) => s[0] === k) || [])[1];

test('AXML: UTF-16 and UTF-8 string pools decode to the same XML with namespaces and typed values', () => {
  for (const utf8 of [false, true]) {
    const r = decodeAxml(B.manifest({ axml: { utf8 } }));
    assert.strictEqual(r.root.tag, 'manifest');
    assert.match(r.xml, /xmlns:android="http:\/\/schemas\.android\.com\/apk\/res\/android"/);
    assert.match(r.xml, /android:versionCode="7"/);
    assert.match(r.xml, /package="com\.zovo\.demo"/);
    assert.match(r.xml, /<uses-permission android:name="android\.permission\.CAMERA" \/>/);
    assert.match(r.xml, /android:exported="false"/);
    assert.deepStrictEqual(r.warnings, []);
  }
});

test('AXML: resource references keep their id; dimensions, colors and hex ints are readable', () => {
  assert.strictEqual(typedValue(0x01, 0x7f0e001b, () => ''), '@0x7f0e001b');
  assert.strictEqual(typedValue(0x01, 0, () => ''), '@null');
  assert.strictEqual(typedValue(0x02, 0x01010036, () => ''), '?0x01010036');
  assert.strictEqual(typedValue(0x05, (16 << 8) | 1, () => ''), '16dp');
  assert.strictEqual(typedValue(0x1c, 0xff112233, () => ''), '#ff112233');
  assert.strictEqual(typedValue(0x11, 0x30, () => ''), '0x00000030');
  assert.strictEqual(typedValue(0x12, 0, () => ''), 'false');
  const m = parse(B.apk({ manifest: { labelRef: true, label: 0x7f0e001b } }));
  assert.match(sum(m, 'App label'), /^@0x7f0e001b \(a string resource/);
  assert.match(m.manifestXml, /android:label="@0x7f0e001b"/);
});

test('AXML: shrunk manifests with empty attribute names get their names from the resource map', () => {
  const r = decodeAxml(B.manifest({ axml: { blankNames: true } }));
  assert.match(r.xml, /android:versionName="1\.2\.3"/);
  assert.match(r.xml, /android:minSdkVersion="21"/);
});

test('AXML hostile: string count over the chunk size, zero-size and oversized chunks, too many attributes', () => {
  assert.throws(() => decodeAxml(B.manifest({ axml: { rawSize: 0x7fffffff } })), /string pool/);
  assert.throws(() => decodeAxml(B.manifest({ axml: { rawSize: 400000 } })), /do not fit/);
  // zero-size chunk right after the header: no endless loop, a clear error
  const z = Buffer.from(B.manifest());
  z.writeUInt32LE(0, 8 + 4); // string pool size = 0
  assert.throws(() => decodeAxml(z), /no elements/);
  // a chunk that claims to run past the end
  const big = Buffer.from(B.manifest());
  const firstEl = big.indexOf(Buffer.from([0x02, 0x01, 0x10, 0x00]));
  big.writeUInt32LE(0x7ffffff0, firstEl + 4);
  assert.throws(() => decodeAxml(big), /no elements/);
  // attribute count larger than the chunk
  assert.throws(() => decodeAxml(B.manifest({ axml: { attrCount: 60000 } })), /no elements|do not fit/);
  // plain-text manifest
  assert.throws(() => decodeAxml(Buffer.from('<manifest/>')), /plain text XML/);
});

test('AXML hostile: every truncation of a manifest gives a result or a clear error, never a hang', () => {
  const full = B.manifest();
  const t0 = Date.now();
  for (let n = 0; n < full.length; n += 3) {
    try { const r = decodeAxml(full.subarray(0, n)); assert.ok(typeof r.xml === 'string'); } catch (e) { assert.ok(e.code === 'AXML', `cut at ${n}: ${e.message}`); }
  }
  assert.ok(Date.now() - t0 < 5000);
});

test('AXML hostile: deep nesting stops at the depth cap; HTML and control characters are escaped in the XML', () => {
  let e = B.el('leaf');
  for (let i = 0; i < 700; i++) e = B.el('n', [], [e]);
  const r = decodeAxml(B.axml(B.el('manifest', [], [e])));
  assert.ok(r.warnings.some((w) => /nested more than 512/.test(w)));
  const x = decodeAxml(B.axml(B.el('manifest', [['package', 'a"><script>alert(1)</script>\u0001', 'str', '']])));
  assert.match(x.xml, /package="a&quot;&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;&#x1;"/);
});

test('DEX: header, counts, classes by package, defined methods and method references', () => {
  const d = parseDex(B.dex(), 'classes.dex');
  assert.strictEqual(d.version, '035');
  assert.strictEqual(d.counts.classes, 3);
  assert.strictEqual(d.methodRefs, 8);
  const main = d.classes.find((c) => c.name === 'com.zovo.demo.MainActivity');
  assert.deepStrictEqual([main.pkg, main.methods, main.fields, main.super], ['com.zovo.demo', 3, 2, 'android.app.Activity']);
  assert.strictEqual(d.refsByPackage.get('android.app'), 1);
  assert.strictEqual(d.refsByPackage.get('okhttp3'), 1);
  assert.deepStrictEqual(d.warnings, []);
  const hits = findInDex(d, matcher('onCreate'));
  assert.deepStrictEqual(hits.filter((h) => h.kind === 'method').map((h) => h.name).sort(), ['android.app.Activity.onCreate', 'com.zovo.demo.MainActivity.onCreate']);
  assert.ok(hits.some((h) => h.kind === 'string' && h.name === 'onCreate'));
  assert.ok(findInDex(d, matcher('/^okhttp3\\./')).some((h) => h.kind === 'class' && h.detail === 'defined here'));
});

test('DEX hostile: counts over the file size are clamped with a warning; bad magic and short files are refused', () => {
  const big = B.dex({ override: { 56: 0x7fffffff, 88: 4000000, 96: 0xffffffff } });
  const t0 = Date.now();
  const d = parseDex(big);
  assert.ok(Date.now() - t0 < 2000);
  assert.ok(d.warnings.some((w) => /strings, but only/.test(w)));
  assert.ok(d.warnings.some((w) => /methods, but only/.test(w)));
  assert.ok(d.warnings.some((w) => /classes, but only/.test(w)));
  const past = parseDex(B.dex({ override: { 100: 0x7ffffff0 } }));
  assert.ok(past.warnings.some((w) => /classes table starts past the end/.test(w)));
  assert.throws(() => parseDex(Buffer.alloc(50)), /shorter than a DEX header/);
  assert.throws(() => parseDex(Buffer.alloc(200)), /DEX magic/);
  for (let n = 0x70; n < B.dex().length; n += 7) parseDex(B.dex().subarray(0, n)); // every cut parses
});

test('DEX hostile: class data with impossible counts shows 0 methods and a warning', () => {
  const b = B.dex();
  // point the first class's class_data_off past the end
  const cOff = b.readUInt32LE(100);
  b.writeUInt32LE(b.length + 100, cOff + 24);
  const d = parseDex(b);
  assert.strictEqual(d.classes[0].methods, 0);
  assert.ok(d.warnings.some((w) => /class data past the end/.test(w)));
});

test('ZIP: stored and deflated entries, CRC check, a zip bomb is stopped at the header size', () => {
  const z = B.zip([{ name: 'a.txt', data: 'hello', method: 0 }, { name: 'b.txt', data: 'x'.repeat(10000) }]);
  const src = Source.fromBuffer(z);
  const r = readZip(src);
  assert.deepStrictEqual(r.entries.map((e) => [e.name, e.method, e.size]), [['a.txt', 0, 5], ['b.txt', 8, 10000]]);
  assert.strictEqual(Buffer.from(readEntry(src, r.entries[1], 1 << 20)).toString(), 'x'.repeat(10000));
  const bad = B.zip([{ name: 'a.txt', data: 'hello', method: 0, crc: 1 }]);
  assert.throws(() => readEntry(Source.fromBuffer(bad), readZip(Source.fromBuffer(bad)).entries[0], 100), /CRC/);
  // 64 MB of zeros declared as 1 KB
  const bomb = B.zip([{ name: 'classes.dex', data: Buffer.alloc(64 * 1024 * 1024), sizeOverride: 1024 }]);
  const bs = Source.fromBuffer(bomb);
  assert.ok(bomb.length < 200 * 1024);
  assert.throws(() => readEntry(bs, readZip(bs).entries[0], 1 << 30), /zip bomb/);
  assert.throws(() => readEntry(bs, { ...readZip(bs).entries[0], size: 512 * 1024 * 1024 }, 128 * 1024 * 1024), /limit/);
});

test('ZIP hostile: not a ZIP, cut files, entry counts over the archive and names with HTML or control characters', () => {
  assert.throws(() => parse(Buffer.from('hello world, not a zip')), (e) => e.code === 'NOT_APK');
  assert.throws(() => parse(Buffer.alloc(0)), (e) => e.code === 'NOT_APK');
  const full = B.apk();
  for (let n = 0; n < full.length; n += Math.max(1, Math.floor(full.length / 400))) {
    try { const m = parse(full.subarray(0, n)); assert.ok(m.title); } catch (e) { assert.ok(['NOT_APK', 'DAMAGED'].includes(e.code), `cut ${n}: ${e.code} ${e.message}`); }
  }
  const many = B.zip([{ name: 'AndroidManifest.xml', data: B.manifest() }], { countOverride: 60000 });
  const m = parse(many);
  assert.ok(m.warnings.some((w) => /ends after 1 of 60000/.test(w)));
  const evil = parse(B.apk({ extra: [{ name: 'assets/<img src=x onerror=alert(1)>\u0007.txt', data: 'x' }] }));
  assert.ok(table(evil, 'files').rows.some((r) => r[0] === 'assets/<img src=x onerror=alert(1)>\\x07.txt'));
});

test('signing: v1 PKCS#7 and v2/v3 blocks give the certificate SHA-256, subject and validity', () => {
  const m = parse(B.apk({ v3: true }));
  assert.strictEqual(sum(m, 'Signing'), 'v1, v2, v3');
  assert.strictEqual(m.data.cert.sha256, B.TEST_CERT_SHA256);
  assert.strictEqual(m.data.cert.subject, 'CN=Zovo Test, O=Zovo, C=US');
  assert.strictEqual(m.data.cert.validFrom, '2026-11-10');
  const v2only = parse(B.apk({ v1: false }));
  assert.deepStrictEqual(v2only.data.schemes, ['v2']);
  assert.strictEqual(v2only.data.cert.sha256, B.TEST_CERT_SHA256, 'certificate from the v2 block');
  const none = parse(B.apk({ v1: false, v2: false }));
  assert.strictEqual(sum(none, 'Signing'), 'no signature found');
  assert.ok(table(none, 'signing').rows.some((r) => /none \(no v2 or v3/.test(r[1])));
});

test('signing hostile: a signing block with a pair past its end and a broken PKCS#7 give notes, not failures', () => {
  const blk = B.sigBlock([[0x7109871a, B.v2Value()]]);
  blk.writeUInt32LE(0x7ffffff0, 8); // first pair length
  const files = [{ name: 'AndroidManifest.xml', data: B.manifest() }, { name: 'META-INF/CERT.SF', data: 'x' }, { name: 'META-INF/CERT.RSA', data: Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]) }];
  const m = parse(B.zip(files, { sigBlock: blk }));
  assert.ok(m.warnings.some((w) => /runs past the block/.test(w)));
  assert.ok(m.warnings.some((w) => /CERT\.RSA/.test(w)));
  assert.strictEqual(m.data.package, 'com.zovo.demo');
});

test('APK model: summary, dangerous permissions, exported flags with reasons, ABIs, size tables, package tree', () => {
  const m = parse(B.apk({ dex2: { classes: [{ name: 'Lcom/zovo/demo/B;', methods: ['x'], fields: 0 }], refs: [] } }));
  assert.strictEqual(m.data.package, 'com.zovo.demo');
  assert.match(sum(m, 'Min SDK'), /^21 \(Android 5\.0\)/);
  assert.match(sum(m, 'Permissions'), /5 requested, 2 dangerous/);
  const perms = table(m, 'permissions').rows;
  assert.strictEqual(perms.find((r) => r[0].endsWith('CAMERA'))[1], 'dangerous');
  assert.strictEqual(perms.find((r) => r[0].endsWith('SYSTEM_ALERT_WINDOW'))[1], 'special access');
  assert.strictEqual(perms.find((r) => r[0].endsWith('INTERNET'))[1], 'normal or signature');
  const comps = table(m, 'components').rows;
  assert.deepStrictEqual(comps.find((r) => r[1] === 'com.zovo.demo.MainActivity').slice(2, 4), ['yes', 'implied by an intent filter (targetSdk 30 < 31); launcher activity']);
  assert.deepStrictEqual(comps.find((r) => r[1] === 'com.zovo.demo.SyncService').slice(2, 4), ['no', 'default (no intent filter)']);
  assert.deepStrictEqual(m.data.abis, ['arm64-v8a', 'x86_64']);
  assert.strictEqual(table(m, 'dex').rows.length, 2);
  assert.strictEqual(m.tree.refs, 8 + 1);
  const com = m.tree.kids.find((k) => k.n === 'com');
  assert.strictEqual(com.classes, 3);
  const res = table(m, 'folders').rows.find((r) => r[0] === 'res/');
  assert.deepStrictEqual(res.slice(1, 2), [2]);
  assert.ok(table(m, 'types').rows.some((r) => r[0] === 'dex' && r[1] === 2));
  assert.strictEqual(table(m, 'files').entries.length, table(m, 'files').rows.length);
});

test('APK model: targetSdk 31+ with an intent filter and no exported attribute is named as an install error', () => {
  const m = parse(B.apk({ manifest: { target: 33 } }));
  const r = table(m, 'components').rows.find((x) => x[1] === 'com.zovo.demo.BootReceiver');
  assert.strictEqual(r[2], 'not set');
  assert.match(r[3], /Android 12\+ refuses to install/);
});

test('APK model: debuggable is shown; a damaged manifest still gives files, DEX and signing', () => {
  assert.match(sum(parse(B.apk({ manifest: { debuggable: true } })), 'Debuggable'), /^yes/);
  const m = parse(B.apk({ manifestBytes: Buffer.from([3, 0, 8, 0, 0xff, 0xff, 0, 0, 1, 2]) }));
  assert.ok(m.warnings.some((w) => /AndroidManifest\.xml/.test(w)));
  assert.strictEqual(m.manifestXml, '');
  assert.strictEqual(table(m, 'dex').rows.length, 1);
  assert.strictEqual(m.data.cert.sha256, B.TEST_CERT_SHA256);
});

test('AAB: files, DEX counts and ABIs from base/, and a note that the protobuf manifest is not decoded', () => {
  const aab = B.zip([
    { name: 'base/manifest/AndroidManifest.xml', data: Buffer.from([0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]) },
    { name: 'base/dex/classes.dex', data: B.dex() },
    { name: 'base/lib/arm64-v8a/libz.so', data: Buffer.alloc(100) },
    { name: 'BundleConfig.pb', data: Buffer.alloc(10) },
  ]);
  const m = parse(aab, 'app.aab');
  assert.strictEqual(m.format, 'AAB');
  assert.match(m.manifestNote, /protocol buffer/);
  assert.strictEqual(table(m, 'dex').rows[0][0], 'base/dex/classes.dex');
  assert.deepStrictEqual(m.data.abis, ['arm64-v8a']);
  // the same bytes named .apk are recognised as a bundle
  assert.strictEqual(parse(aab, 'weird.apk').format, 'AAB');
});

test('XAPK and APKS: inner APKs listed, the base APK analysed (stored window or deflated), hex reads inner entries', () => {
  const base = B.apk();
  const xapk = B.zip([{ name: 'manifest.json', data: JSON.stringify({ package_name: 'com.zovo.demo' }) }, { name: 'com.zovo.demo.apk', data: base, method: 0 }, { name: 'config.arm64_v8a.apk', data: B.zip([{ name: 'lib/arm64-v8a/a.so', data: 'x' }]) }]);
  const m = parse(xapk, 'demo.xapk');
  assert.strictEqual(m.format, 'XAPK');
  assert.strictEqual(m.data.package, 'com.zovo.demo');
  assert.deepStrictEqual(table(m, 'inner').rows.map((r) => [r[0], r[3].startsWith('yes')]), [['com.zovo.demo.apk', true], ['config.arm64_v8a.apk', false]]);
  assert.match(m.title, /XAPK package · base com\.zovo\.demo\.apk/);
  const dexEntry = table(m, 'dex').entries[0];
  assert.strictEqual(dexEntry, 'com.zovo.demo.apk!/classes.dex');
  const bytes = entryBytes(Source.fromBuffer(xapk), dexEntry, 'demo.xapk', 1 << 20);
  assert.strictEqual(Buffer.from(bytes.subarray(0, 4)).toString('latin1'), 'dex\n');
  const apks = B.zip([{ name: 'toc.pb', data: 'x' }, { name: 'splits/base-master.apk', data: base }]);
  const s = parse(apks, 'demo.apks');
  assert.strictEqual(s.format, 'APKS');
  assert.strictEqual(s.data.package, 'com.zovo.demo');
  const empty = parse(B.zip([{ name: 'toc.pb', data: 'x' }, { name: 'splits/base-master.apk', data: 'not a zip' }]), 'bad.apks');
  assert.ok(empty.warnings.some((w) => /could not be read/.test(w)));
});

test('a 200 MB APK opens lazily: only the central directory, manifest, DEX and signature blocks are read', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'apk-big-'));
  try {
    const file = path.join(dir, 'big.apk');
    // a stored 200 MB asset written as a sparse region: local header, a hole, then the rest of the APK
    const small = B.apk();
    const src = Source.fromBuffer(small);
    const z = readZip(src);
    const SIZE = 200 * 1024 * 1024;
    const name = Buffer.from('assets/big.bin');
    const lh = Buffer.concat([B.u32(0x04034b50), B.u16(20), B.u16(0), B.u16(0), B.u16(0), B.u16(0x21), B.u32(0), B.u32(SIZE), B.u32(SIZE), B.u16(name.length), B.u16(0), name]);
    const head = small.subarray(0, z.cdOffset); // local entries and the signing block of the small APK
    const shift = lh.length + SIZE;
    const fd = fs.openSync(file, 'w');
    fs.writeSync(fd, lh, 0, lh.length, 0);
    fs.writeSync(fd, head, 0, head.length, shift);
    // central directory: shift every offset, add the big entry
    const cd = Buffer.from(small.subarray(z.cdOffset, z.eocdPos));
    for (let p = 0; p < cd.length;) { cd.writeUInt32LE(cd.readUInt32LE(p + 42) + shift, p + 42); p += 46 + cd.readUInt16LE(p + 28) + cd.readUInt16LE(p + 30) + cd.readUInt16LE(p + 32); }
    const bigCd = Buffer.concat([B.u32(0x02014b50), B.u16(20), B.u16(20), B.u16(0), B.u16(0), B.u16(0), B.u16(0x21), B.u32(0), B.u32(SIZE), B.u32(SIZE), B.u16(name.length), B.u16(0), B.u16(0), B.u16(0), B.u16(0), B.u32(0), B.u32(0), name]);
    const allCd = Buffer.concat([cd, bigCd]);
    const cdOff = shift + head.length;
    const n = z.entries.length + 1;
    const eocd = Buffer.concat([B.u32(0x06054b50), B.u16(0), B.u16(0), B.u16(n), B.u16(n), B.u32(allCd.length), B.u32(cdOff), B.u16(0)]);
    fs.writeSync(fd, Buffer.concat([allCd, eocd]), 0, allCd.length + eocd.length, cdOff);
    fs.closeSync(fd);
    assert.ok(fs.statSync(file).size > SIZE);
    const t0 = Date.now();
    const m = parseApkFile(file, 'big.apk');
    assert.ok(Date.now() - t0 < 3000, `took ${Date.now() - t0} ms`);
    assert.strictEqual(m.data.package, 'com.zovo.demo');
    assert.strictEqual(m.data.cert.sha256, B.TEST_CERT_SHA256, 'signing block found right before the shifted central directory');
    assert.strictEqual(table(m, 'files').rows[0][0], 'assets/big.bin');
    assert.ok(m.blocksRead <= 12, `read ${m.blocksRead} blocks of 64 KB`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('mutation fuzz: 1,500 damaged APKs each parse or fail with a clear code, fast', () => {
  const base = B.apk();
  let seed = 12345;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % n; };
  const t0 = Date.now();
  for (let i = 0; i < 1500; i++) {
    const b = Buffer.from(base);
    const k = 1 + rnd(12);
    for (let j = 0; j < k; j++) b[rnd(b.length)] = rnd(256);
    const t1 = Date.now();
    try { parse(b); } catch (e) { assert.ok(['NOT_APK', 'DAMAGED'].includes(e.code), `mutant ${i}: ${e.code} ${e.message}`); }
    assert.ok(Date.now() - t1 < 3000, `mutant ${i} took too long`);
  }
  assert.ok(Date.now() - t0 < 60000);
});

test('the walkthrough sample is a valid APK with 2 DEX files, 3 ABIs and 3 signing schemes', () => {
  const m = parseApkFile(path.join(__dirname, '..', 'samples', 'sample-zovo-notes.apk'), 'sample-zovo-notes.apk');
  assert.strictEqual(m.data.package, 'com.zovo.notes');
  assert.strictEqual(m.data.dex.length, 2);
  assert.deepStrictEqual(m.data.abis, ['arm64-v8a', 'armeabi-v7a', 'x86_64']);
  assert.deepStrictEqual(m.data.schemes, ['v1', 'v2', 'v3']);
  assert.deepStrictEqual(m.warnings, []);
});
