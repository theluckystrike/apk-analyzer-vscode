'use strict';
// Pro tool cores: export (JSON, Markdown, CSV), compare two APKs, the find matcher.
const test = require('node:test');
const assert = require('node:assert');
const B = require('./build');
const { Source } = require('../src/core/source');
const { parseApk } = require('../src/core/apk');
const T = require('../src/core/tools');

const parse = (buf, name = 'a.apk') => { const m = parseApk(Source.fromBuffer(buf), name); m.size = buf.length; return m; };
const A = parse(B.apk(), 'v1.apk');
const Bm = parse(B.apk({
  manifest: { versionCode: 8, versionName: '1.3.0', target: 33, perms: ['android.permission.INTERNET', 'android.permission.CAMERA', 'android.permission.RECORD_AUDIO'],
    components: [B.el('activity', [['name', '.MainActivity'], ['exported', true, 'bool']]), B.el('service', [['name', 'com.zovo.demo.SyncService'], ['exported', true, 'bool']]), B.el('activity', [['name', '.NewActivity'], ['exported', false, 'bool']])] },
  dex: { classes: [{ name: 'Lcom/zovo/demo/MainActivity;', methods: ['onCreate'], fields: 0 }, { name: 'Lokhttp3/Call;', methods: ['execute', 'cancel', 'clone'], fields: 0 }, { name: 'Lokio/Buffer;', methods: ['read'], fields: 0 }] },
  abis: ['arm64-v8a'], arsc: 9000,
}), 'v2.apk');

test('export: JSON has the facts, tables and manifest; Markdown has the sections; CSV quotes and guards cells', () => {
  const j = JSON.parse(T.toJson(A, 'v1.apk'));
  assert.strictEqual(j.facts.package, 'com.zovo.demo');
  assert.strictEqual(j.tables.permissions.length, 5);
  assert.strictEqual(j.tables.dex[0]['Method refs'], 8);
  assert.match(j.manifestXml, /<manifest/);
  const md = T.toMarkdown(A, 'v1.apk');
  for (const h of ['## Permissions', '## Components', '## DEX files', '## Method counts by package', '## Size by folder', '## Signing']) assert.ok(md.includes(h), h);
  assert.match(md, /\| android\.permission\.CAMERA \| dangerous \|/);
  const csv = T.toCsv(A, 'files');
  assert.match(csv.split('\r\n')[0], /^Path,Compressed,Size,Method,Ratio$/);
  assert.ok(csv.includes('AndroidManifest.xml,'));
  const pk = T.toCsv(A, 'packages');
  assert.match(pk, /^Package,Classes,Defined methods,Method refs\r\n/);
  const evil = parse(B.apk({ extra: [{ name: '=cmd|calc.txt', data: 'x' }, { name: 'a,"b".txt', data: 'y' }] }));
  const c2 = T.toCsv(evil, 'files');
  assert.ok(c2.includes(`"'=cmd|calc.txt"`), 'formula cell is quoted with a leading apostrophe');
  assert.ok(c2.includes('"a,""b"".txt"'));
  assert.strictEqual(T.toCsv(A, 'nope'), '');
});

test('compare: versions, SDK, permissions, components, exported changes, ABIs, folders and method refs per package', () => {
  const r = T.compareApks(A, Bm);
  const h = Object.fromEntries(r.header.map((x) => [x.name, [x.a, x.b]]));
  assert.deepStrictEqual(h['Version code'], ['7', '8']);
  assert.deepStrictEqual(h['Target SDK'], ['30', '33']);
  assert.deepStrictEqual(h['Native ABIs'], ['arm64-v8a, x86_64', 'arm64-v8a']);
  assert.deepStrictEqual(r.permissions.added, ['android.permission.RECORD_AUDIO']);
  assert.deepStrictEqual(r.permissions.removed, ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.SYSTEM_ALERT_WINDOW', 'com.zovo.demo.permission.C2D']);
  assert.ok(r.components.added.includes('activity com.zovo.demo.NewActivity'));
  assert.ok(r.components.removed.includes('provider com.zovo.demo.DataProvider'));
  assert.deepStrictEqual(r.components.exportChanged, [{ key: 'service com.zovo.demo.SyncService', a: 'no', b: 'yes' }]);
  assert.ok(r.files.some((f) => f.path === 'lib/x86_64/libzovo.so' && f.status === 'removed'));
  assert.ok(r.files.some((f) => f.path === 'resources.arsc' && f.delta === 4904));
  const ok = r.methods.find((m) => m.pkg === 'okhttp3');
  assert.deepStrictEqual([ok.a, ok.b, ok.delta], [1, 3, 2]);
  assert.ok(r.methods.some((m) => m.pkg === 'okio' && m.a === 0 && m.b === 1));
  const md = T.compareMarkdown(r, 'v1.apk', 'v2.apk');
  assert.match(md, /^# v1\.apk compared with v2\.apk/);
  assert.match(md, /- added: android\.permission\.RECORD_AUDIO/);
  assert.match(md, /\| okhttp3 \| 1 \| 3 \| \+2 \|/);
  assert.strictEqual(T.compareApks(A, A).same, true);
});

test('matcher: plain text any case, /regex/, nested repeats refused', () => {
  assert.ok(T.matcher('OKHTTP').test('okhttp3.Call'));
  assert.ok(T.matcher('/^okhttp3\\./').test('okhttp3.Call'));
  assert.ok(!T.matcher('/^okhttp3\\./').test('x.okhttp3.Call'));
  assert.throws(() => T.matcher('/(a+)+$/'), /repeated group/);
  assert.strictEqual(T.matcher('  '), null);
});
