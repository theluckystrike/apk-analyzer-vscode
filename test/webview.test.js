'use strict';
// Runs media/main.js in jsdom with a parsed APK model: tabs, the closed Export menu, columns through the CSSOM,
// filter, byte sizes, the package tree, the manifest as text, hex of an entry, hostile names as text. jsdom is not a
// dependency of this extension: the test uses JSDOM_PATH or the copy in a sibling product, and is skipped when there is none.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const B = require('./build');
const { Source } = require('../src/core/source');
const { parseApk } = require('../src/core/apk');

const candidates = [process.env.JSDOM_PATH, path.join(__dirname, '..', 'node_modules', 'jsdom'), path.join(__dirname, '..', '..', 'docx-viewer-vscode', 'node_modules', 'jsdom')].filter(Boolean);
let JSDOM = null;
for (const c of candidates) { try { ({ JSDOM } = require(c)); break; } catch { /* next */ } }
const script = fs.readFileSync(path.join(__dirname, '..', 'media', 'main.js'), 'utf8');
const model = (buf) => { const m = JSON.parse(JSON.stringify(parseApk(Source.fromBuffer(buf), 'demo.apk'))); m.size = buf.length; return m; };

function boot(m, size) {
  const dom = new JSDOM('<!DOCTYPE html><body><div id="app"></div><template id="zovo-footer"><div id="zovo-support">Rate</div></template></body>', { runScripts: 'outside-only', pretendToBeVisual: true });
  const sent = [];
  dom.window.acquireVsCodeApi = () => ({ postMessage: (x) => sent.push(JSON.parse(JSON.stringify(x))) });
  dom.window.eval(script);
  const send = (x) => dom.window.dispatchEvent(new dom.window.MessageEvent('message', { data: x }));
  send({ type: 'model', model: m, name: 'demo.apk', size, pro: { show: true, licensed: false, tries: { export: 3, compare: 2, find: 3 } } });
  return { dom, doc: dom.window.document, sent, send };
}

test('webview: tabs, overview cards, closed Export menu, grid through the CSSOM, filter, byte sizes, footer', { skip: !JSDOM && 'jsdom not found' }, async () => {
  const buf = B.apk();
  const { doc, sent, dom } = boot(model(buf), buf.length);
  assert.deepStrictEqual(sent.map((m) => m.type), ['ready', 'rendered']);
  const tabs = [...doc.querySelectorAll('.tab')].map((t) => t.dataset.tab);
  assert.deepStrictEqual(tabs, ['overview', 'manifest', 'permissions', 'components', 'dex', 'packages', 'classes', 'folders', 'types', 'files', 'natives', 'signing', 'hex']);
  assert.match(doc.querySelector('[data-card=permissions]').textContent, /5permissions, 2 dangerous/);
  assert.strictEqual(doc.querySelector('.menu').hidden, true, 'the Export menu starts closed');
  assert.match(doc.querySelector('[data-tool=compare]').title, /2 free tries left/);
  assert.ok(doc.getElementById('zovo-support'), 'footer');
  doc.querySelector('.tab[data-tab="files"]').click();
  const head = doc.querySelector('.thead');
  assert.match(head.style.getPropertyValue('grid-template-columns'), /minmax/, 'columns set with style.setProperty');
  assert.ok([...doc.querySelectorAll('.tr .td')].some((td) => /^\d+(\.\d)? KB$|^\d+ bytes$/.test(td.textContent)), 'sizes are formatted');
  const f = doc.querySelector('.filter');
  f.value = 'classes.dex';
  f.dispatchEvent(new dom.window.Event('input'));
  await new Promise((r) => setTimeout(r, 250));
  assert.match(doc.querySelector('.tools .muted').textContent, /^1 of 10 rows$/);
  doc.querySelector('[data-tool=export]').click();
  assert.strictEqual(doc.querySelector('.menu').hidden, false);
  doc.querySelector('[data-tool="export:md"]').click();
  assert.deepStrictEqual(sent.at(-1), { type: 'tool', tool: 'export:md' });
});

test('webview: package tree with totals, manifest as text, hex of an entry', { skip: !JSDOM && 'jsdom not found' }, async () => {
  const buf = B.apk();
  const { doc, sent, send } = boot(model(buf), buf.length);
  doc.querySelector('.tab[data-tab="packages"]').click();
  const rows = [...doc.querySelectorAll('.tree .tr')].map((r) => r.dataset.pkg);
  assert.ok(rows.includes('com') && rows.includes('com.zovo'), rows.join(','));
  doc.querySelector('.tab[data-tab="manifest"]').click();
  assert.match(doc.querySelector('pre.xml').textContent, /<manifest/);
  assert.strictEqual(doc.querySelectorAll('pre.xml *').length, 0, 'the XML is text, not markup');
  doc.querySelector('.tab[data-tab="files"]').click();
  await new Promise((r) => setTimeout(r, 50));
  const link = [...doc.querySelectorAll('.jump')].find((a) => /classes\.dex/.test(a.title));
  link.click();
  assert.deepStrictEqual(sent.at(-1), { type: 'hexOpen', entry: 'classes.dex' });
  send({ type: 'hexTarget', entry: 'classes.dex', size: 600 });
  await new Promise((r) => setTimeout(r, 50));
  assert.ok(sent.some((m) => m.type === 'hex' && m.entry === 'classes.dex' && m.offset === 0));
  send({ type: 'hex', entry: 'classes.dex', offset: 0, bytes: Array.from(Buffer.from('dex\n035\0')) });
  assert.match(doc.querySelector('.hrow').textContent, /^00000000646578/);
  assert.strictEqual(doc.querySelector('.hexname').textContent, 'classes.dex');
});

test('webview: hostile names stay text; a file that is not an APK shows the message and the footer', { skip: !JSDOM && 'jsdom not found' }, async () => {
  const buf = B.apk({ extra: [{ name: 'assets/<img src=x onerror=alert(1)>.png', data: 'x' }] });
  const { doc } = boot(model(buf), buf.length);
  doc.querySelector('.tab[data-tab="files"]').click();
  await new Promise((r) => setTimeout(r, 50));
  assert.strictEqual(doc.querySelectorAll('#app img').length, 0);
  assert.ok([...doc.querySelectorAll('.td')].some((td) => td.textContent.includes('<img src=x')));
  const dom = new JSDOM('<!DOCTYPE html><body><div id="app"></div><template id="zovo-footer"><div id="zovo-support">Rate</div></template></body>', { runScripts: 'outside-only' });
  dom.window.acquireVsCodeApi = () => ({ postMessage() {} });
  dom.window.eval(script);
  dom.window.dispatchEvent(new dom.window.MessageEvent('message', { data: { type: 'error', message: 'This is not a ZIP archive, so it is not an APK.', notApk: true } }));
  assert.match(dom.window.document.querySelector('h2').textContent, /Not an APK file/);
  assert.ok(dom.window.document.getElementById('zovo-support'));
});
