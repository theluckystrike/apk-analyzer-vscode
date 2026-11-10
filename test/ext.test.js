'use strict';
// The extension host with a stub vscode: activation, opening files, hex of entries, no network, Pro tries, the panel.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const B = require('./build');
const { loadExtension, openInViewer } = require('./support/vscode-stub');
const { buildHtml } = require('../src/html');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'apk-ext-'));
const file = (name, buf) => { const p = path.join(dir, name); fs.writeFileSync(p, buf); return p; };
const APK = file('demo.apk', B.apk());
const APK2 = file('demo2.apk', B.apk({ manifest: { versionCode: 8, perms: ['android.permission.INTERNET', 'android.permission.RECORD_AUDIO'] } }));
const TXT = file('notes.apk', Buffer.from('hello, this is text and not an APK\n'));
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));
const VT = 'apkAnalyzer.any';

function trapNetwork() {
  const calls = [];
  const saved = { fetch: global.fetch, hr: http.request, hg: http.get, sr: https.request, sg: https.get, nc: net.connect, ncc: net.createConnection };
  global.fetch = async (u) => { calls.push(String(u)); throw new Error('network blocked in test'); };
  http.request = http.get = https.request = https.get = (...a) => { calls.push(String(a[0] && (a[0].href || a[0].host || a[0]))); throw new Error('network blocked in test'); };
  net.connect = net.createConnection = (...a) => { calls.push('net ' + JSON.stringify(a[0])); throw new Error('network blocked in test'); };
  return { calls, restore: () => { global.fetch = saved.fetch; http.request = saved.hr; http.get = saved.hg; https.request = saved.sr; https.get = saved.sg; net.connect = saved.nc; net.createConnection = saved.ncc; } };
}

test('activation and opening an APK and a text file make no network call and show no message', async () => {
  const nw = trapNetwork();
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    assert.ok(s.providers.has('apkAnalyzer.apk') && s.providers.has(VT));
    for (const c of ['apkAnalyzer.open', 'apkAnalyzer.openSample', 'apkAnalyzer.exportReport', 'apkAnalyzer.compare', 'apkAnalyzer.findInDex', 'apkAnalyzer.getPro', 'apkAnalyzer.enterLicenseKey', 'apkAnalyzer.payByCard']) assert.ok(s.commands.has(c), c);
    const a = await openInViewer(s, APK, VT);
    assert.strictEqual(a.posted[0].type, 'model');
    assert.match(a.posted[0].model.title, /Android APK · com\.zovo\.demo 1\.2\.3/);
    assert.deepStrictEqual(a.posted[0].pro.tries, { export: 3, compare: 3, find: 3 });
    const t = await openInViewer(s, TXT, VT);
    assert.strictEqual(t.posted[0].type, 'error');
    assert.strictEqual(t.posted[0].notApk, true);
    // hex of the whole file and of an unpacked entry
    await a.send({ type: 'hex', offset: 0, length: 16 });
    assert.deepStrictEqual(a.posted.at(-1).bytes.slice(0, 4), [0x50, 0x4b, 0x03, 0x04]);
    await a.send({ type: 'hexOpen', entry: 'classes.dex' });
    const tgt = a.posted.at(-1);
    assert.deepStrictEqual([tgt.type, tgt.entry, tgt.size > 100], ['hexTarget', 'classes.dex', true]);
    await a.send({ type: 'hex', entry: 'classes.dex', offset: 0, length: 8 });
    assert.strictEqual(Buffer.from(a.posted.at(-1).bytes).toString('latin1'), 'dex\n035\0');
    await a.send({ type: 'hexOpen', entry: 'no/such/entry' });
    assert.match(a.posted.at(-1).error, /There is no entry/);
    assert.deepStrictEqual(nw.calls, []);
    assert.deepStrictEqual([s.log.info.length, s.log.warn.length, s.log.error.length], [0, 0, 0], 'no message on open');
    assert.deepStrictEqual(s.log.external, []);
  } finally { nw.restore(); s.restore(); }
});

test('export: Escape keeps the try; JSON, Markdown and CSV use the 3 tries; the 4th click shows the CARD1 panel', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    const v = await openInViewer(s, APK, VT);
    s.ui.save.push(undefined);
    await v.send({ type: 'tool', tool: 'export:json' });
    assert.strictEqual((s.state.get('apkAnalyzer.proTrial') || {}).export, undefined, 'cancel uses no try');
    s.ui.quick.push(undefined);
    await s.vscode.commands.executeCommand('apkAnalyzer.exportReport');
    assert.strictEqual((s.state.get('apkAnalyzer.proTrial') || {}).export, undefined, 'Escape on the format pick uses no try');
    const kinds = [['export:json', 'r.json'], ['export:md', 'r.md'], ['export:csvMethods', 'r.csv']];
    for (let i = 0; i < 3; i++) {
      const out = path.join(dir, kinds[i][1]);
      s.ui.save.push(s.vscode.Uri.file(out));
      await v.send({ type: 'tool', tool: kinds[i][0] });
      assert.ok(fs.existsSync(out), `export ${i + 1} written`);
      assert.strictEqual(s.state.get('apkAnalyzer.proTrial').export, i + 1);
    }
    assert.strictEqual(JSON.parse(fs.readFileSync(path.join(dir, 'r.json'), 'utf8')).facts.package, 'com.zovo.demo');
    assert.match(fs.readFileSync(path.join(dir, 'r.md'), 'utf8'), /## Permissions/);
    assert.match(fs.readFileSync(path.join(dir, 'r.csv'), 'utf8'), /^Package,Classes/);
    assert.ok(s.log.status.some((t) => /free try 3 of 3/.test(t)));
    assert.strictEqual(s.log.info.length, 0, 'no panel while tries are left');
    s.ui.info.push(undefined); // Cancel
    await v.send({ type: 'tool', tool: 'export:json' });
    assert.strictEqual(s.log.info.length, 1);
    const panel = s.log.info[0];
    assert.match(panel.text, /Export the APK report \(JSON, Markdown or CSV\) is part of Zovo Pro/);
    assert.strictEqual(panel.opts.modal, true);
    assert.deepStrictEqual(panel.buttons, ['Pay by card (USD 19)', 'Get Zovo Pro with GitHub Sponsors', 'Pay with PayPal', 'Enter a key']);
    assert.match(panel.opts.detail, /You used the 3 free tries/);
    assert.match(panel.opts.detail, /Compare two APKs/);
    assert.ok(!/refund/i.test(panel.opts.detail));
    assert.strictEqual(s.log.saved.length, 3, 'nothing written after the tries');
    assert.deepStrictEqual(v.posted.filter((m) => m.type === 'pro').at(-1).pro.tries, { export: 0, compare: 3, find: 3 });
  } finally { s.restore(); }
});

test('the panel buttons open the USD 19 Sponsors tier and the card checkout, never the generic Sponsors page', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    s.state.set('apkAnalyzer.proTrial', { compare: 3, find: 3 });
    const v = await openInViewer(s, APK, VT);
    s.ui.info.push('Get Zovo Pro with GitHub Sponsors');
    await v.send({ type: 'tool', tool: 'compare' });
    assert.ok(s.log.external.map(String).includes('https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878'), s.log.external.join(' '));
    assert.ok(!s.log.external.map(String).includes('https://github.com/sponsors/theluckystrike'));
    s.ui.info.push('Pay by card (USD 19)');
    await v.send({ type: 'tool', tool: 'find' });
    assert.ok(s.log.external.map(String).some((u) => /^https:\/\/license\.zovo\.one\/buy\/zovo-pro\?client_reference_id=/.test(u)));
    assert.ok(!v.posted.some((m) => m.type === 'compare' || m.type === 'find'));
  } finally { s.restore(); }
});

test('compare: cancel keeps the try; a comparison on screen uses one; Open as Markdown', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    const v = await openInViewer(s, APK, VT);
    s.ui.open.push(undefined);
    await v.send({ type: 'tool', tool: 'compare' });
    assert.strictEqual((s.state.get('apkAnalyzer.proTrial') || {}).compare, undefined);
    s.ui.open.push([s.vscode.Uri.file(APK2)]);
    await v.send({ type: 'tool', tool: 'compare' });
    const c = v.posted.find((m) => m.type === 'compare');
    assert.ok(c);
    assert.deepStrictEqual(c.result.permissions.added, ['android.permission.RECORD_AUDIO']);
    assert.strictEqual(s.state.get('apkAnalyzer.proTrial').compare, 1);
    await v.send({ type: 'saveCompare' });
    assert.match(s.log.opened.at(-1).getText(), /^# demo\.apk compared with demo2\.apk/);
  } finally { s.restore(); }
});

test('find in DEX: no match uses no try; matches are listed and use one', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    const v = await openInViewer(s, APK, VT);
    s.ui.input.push('NoSuchName_xyz');
    await v.send({ type: 'tool', tool: 'find' });
    assert.strictEqual(v.posted.find((m) => m.type === 'find').results.length, 0);
    assert.strictEqual((s.state.get('apkAnalyzer.proTrial') || {}).find, undefined);
    s.ui.input.push('/^okhttp3\\./');
    await v.send({ type: 'tool', tool: 'find' });
    const r = v.posted.filter((m) => m.type === 'find').at(-1);
    assert.ok(r.results.some((x) => x.kind === 'class' && x.name === 'okhttp3.Call'));
    assert.ok(r.results.some((x) => x.kind === 'method' && x.name === 'okhttp3.Call.execute'));
    assert.strictEqual(r.summary.dexFiles, 1);
    assert.strictEqual(s.state.get('apkAnalyzer.proTrial').find, 1);
  } finally { s.restore(); }
});

test('the worker watchdog stops a job that runs too long, and the host keeps working', async () => {
  const { runJob } = require('../src/runner');
  // a find with a slow regex over many strings: idle timeout of 1 ms trips the watchdog before any answer
  await assert.rejects(runJob({ op: 'find', file: APK, query: 'x' }, { idleMs: 1 }), (e) => e.code === 'TIMEOUT');
  const m = await runJob({ op: 'parse', file: APK, name: 'demo.apk' });
  assert.strictEqual(m.data.package, 'com.zovo.demo');
});

test('webview HTML: nonce scripts, no remote origin, no connect-src', () => {
  const html = buildHtml({ cspSource: 'vscode-webview://x', scriptUri: 'vscode-webview://x/main.js', styleUri: 'vscode-webview://x/main.css', title: '<evil>"', nonce: 'abc' });
  const csp = /content="([^"]+)"/.exec(html)[1];
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'nonce-abc'/);
  assert.ok(!/https?:/.test(csp));
  assert.ok(!/connect-src/.test(csp));
  assert.ok(!/unsafe-inline/.test(csp));
  assert.ok(html.includes('&lt;evil&gt;&quot;'));
});

test('the webview script sets no innerHTML and loads nothing remote', () => {
  const js = fs.readFileSync(path.join(__dirname, '..', 'media', 'main.js'), 'utf8');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(js));
  assert.ok(!/https?:\/\//.test(js));
  assert.ok(/e\.style\.setProperty/.test(js));
  assert.ok(!/setAttribute\(\s*['"]style/.test(js));
});

test('showProTools false hides the tools in the webview state', async () => {
  const s = loadExtension();
  try {
    s.config.showProTools = false;
    s.ext.activate(s.context);
    const v = await openInViewer(s, APK, VT);
    assert.strictEqual(v.posted[0].pro.show, false);
  } finally { s.restore(); }
});

test('package.json: phrase-first name, engines ^1.90.0, Pro titles end in (Pro), 6 Zovo Pro palette commands, default editor for APK types', () => {
  const p = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.ok(p.displayName.startsWith('APK Analyzer & APK Viewer'));
  assert.ok(p.description.startsWith('APK analyzer and APK viewer'));
  assert.strictEqual(p.engines.vscode, '^1.90.0');
  assert.strictEqual(p.devDependencies['@types/vscode'], '~1.90.0');
  assert.ok(!p.dependencies);
  const pro = p.contributes.commands.filter((c) => /exportReport|compare|findInDex/.test(c.command));
  assert.strictEqual(pro.length, 3);
  for (const c of pro) assert.match(c.title, /\(Pro\)$/);
  assert.strictEqual(p.contributes.commands.filter((c) => c.category === 'Zovo Pro').length, 6);
  assert.deepStrictEqual(p.contributes.customEditors[0].selector.map((s) => s.filenamePattern), ['*.apk', '*.aab', '*.apks', '*.xapk']);
  assert.ok(p.keywords.length <= 30);
  for (const k of ['apk analyzer', 'apk viewer', 'dex method count', 'android manifest viewer']) assert.ok(p.keywords.includes(k), k);
});

test('rating wiring: a rendered APK counts as a good file once; a text file is neither a success nor a failure', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    const t = await openInViewer(s, TXT, VT);
    assert.strictEqual(t.posted[0].notApk, true);
    const st0 = s.state.get('zovo.rating.v2');
    assert.ok(!st0 || !st0.lastError, 'not a failure');
    const v = await openInViewer(s, APK, VT);
    await v.send({ type: 'rendered' });
    await v.send({ type: 'rendered' });
    const st = s.state.get('zovo.rating.v2');
    assert.ok(st && st.count === 1, `one good file counted once: ${JSON.stringify(st)}`);
  } finally { s.restore(); }
});
