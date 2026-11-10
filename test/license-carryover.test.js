'use strict';
// EXEC14 tests: one unlock for all Zovo extensions (~/.zovo/pro.json), the XSELL2 move 1 carry-over, the panel lines,
// and the hidden refund / Gumroad parts. No network: fetch is never defined here and any call fails the test.
// Run: node --test test/carryover.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dir = fs.existsSync(path.join(__dirname, '..', 'index.js')) ? path.join(__dirname, '..') : path.join(__dirname, '..', 'src', 'license');
const lic = require(path.join(dir, 'license.js'));
const idx = require(path.join(dir, 'index.js'));
const { zovoTools, namesList, readSharedFile, writeSharedFile, paletteCommands } = idx;
// The EXEC14 tests below pin the panel without the card rail, whatever the build's config.js says (CARD1 tests pass
// cardBuyUrl themselves).
const createLicense = (o) => idx.createLicense({ cardBuyUrl: '', ...o });

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function sign(payload, key = privateKey) {
  const p = b64url(Buffer.from(JSON.stringify(payload)));
  return `${lic.KEY_PREFIX}${p}.${b64url(crypto.sign(null, Buffer.from(lic.SIG_CONTEXT + p), key))}`;
}
const base = { v: 1, sku: 'zovo-pro', eh: 'a'.repeat(24), sid: 'manual-exec14', iat: '2026-11-10', lm: true };
const NOW = Date.UTC(2026, 10, 10, 6);
const tick = () => new Promise((r) => setImmediate(r));

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zovo-exec14-'));
test.after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));
let n = 0;
const tmpFile = () => path.join(tmpRoot, `h${++n}`, '.zovo', 'pro.json');

// An installed extension as vscode.extensions.all shows it.
function ext(id, displayName, prefix, v2 = true) {
  const commands = prefix ? [{ command: `${prefix}.enterLicenseKey`, title: 'Enter Zovo Pro license key', ...(v2 ? { category: 'Zovo Pro' } : {}) }] : [];
  return { id, packageJSON: { displayName, contributes: { commands } } };
}

function fakeVscode(answers = {}, installed = []) {
  const log = { info: [], warn: [], opened: [], commands: {}, input: [], picks: [], exec: [], modal: [] };
  const vscode = {
    Uri: { parse: (s) => ({ toString: () => s, s }) },
    env: { openExternal: async (u) => { log.opened.push(u.s); return true; } },
    extensions: { all: installed },
    window: {
      showInformationMessage: async (msg, ...rest) => {
        if (rest[0] && rest[0].modal) log.modal.push({ msg, detail: rest[0].detail, buttons: rest.slice(1) }); else log.info.push({ msg, buttons: rest });
        return answers.info ? answers.info(msg, rest) : undefined;
      },
      showWarningMessage: async (msg) => { log.warn.push(msg); return undefined; },
      showInputBox: async (o) => { log.input.push(o); return typeof answers.input === 'function' ? answers.input(o) : answers.input; },
      showQuickPick: async (items) => { log.picks.push(items.map((i) => i.label)); return answers.pick ? items.find((i) => i.label === answers.pick) : undefined; },
      state: { focused: true },
      onDidChangeWindowState: (fn) => { log.win = fn; return { dispose() {} }; },
    },
    commands: {
      registerCommand: (id, fn) => { log.commands[id] = fn; return { dispose() {} }; },
      executeCommand: async (id, arg) => { log.exec.push({ id, arg }); return answers.exec ? answers.exec(id, arg) : { pro: true, reason: 'ok' }; },
    },
  };
  const secrets = new Map(); const global = new Map();
  const context = {
    subscriptions: [],
    extension: { id: 'zovo.pdf-viewer-dark' },
    secrets: { get: async (k) => secrets.get(k), store: async (k, v) => { secrets.set(k, v); }, delete: async (k) => { secrets.delete(k); }, onDidChange: () => ({ dispose() {} }) },
    globalState: { get: (k) => global.get(k), update: async (k, v) => { global.set(k, v); } },
  };
  return { vscode, context, log, secrets, global };
}
function fakeSponsors(st) {
  let pro = false; const ls = new Set();
  return {
    id: 'github-sponsors', ready: Promise.resolve(), isPro: () => pro,
    async unlock() { pro = true; for (const f of ls) f(pro); return { rail: 'github-sponsors', pro: true, reason: 'ok', kind: st.kind, login: st.login, message: 'Zovo Pro is on. Thank you.' }; },
    async remove() { pro = false; },
    state: () => (pro ? { v: 2, ...st, checkedAt: NOW, recheckAt: st.kind === 'monthly' ? NOW + 30 * 864e5 : 0 } : null),
    onDidChange(fn) { ls.add(fn); return { dispose: () => ls.delete(fn) }; },
  };
}
const mk = (f, extra = {}) => createLicense({ ...f, sku: 'pdf-pro', name: 'Zovo', product: 'PDF Viewer', publicKey: PUB, now: () => NOW, sharedFile: tmpFile(), ...extra });
const others = [
  ext('zovo.zovo-hex-viewer', 'Hex Viewer & Hex Editor (Binary Templates)', 'hexViewer'),
  ext('zovo.sqlite-table-viewer', 'SQLite Editor (Table Viewer)', 'sqliteViewer'),
  ext('zovo.pdf-viewer-dark', 'PDF Viewer', 'pdfViewer'),          // self
  ext('acme.pdf-tools', 'Acme PDF', 'acme'),                         // not Zovo
  ext('zovo.zovo-auto-rename-tag', 'Auto Rename Tag', null),         // Zovo, no Pro
];

// ---- XSELL2 move 1, the 6 tests ----

test('XSELL2 1: the list excludes self and non-zovo ids, and reads name and Pro prefix from package.json', () => {
  const f = fakeVscode({}, others);
  const t = zovoTools(f.vscode, 'zovo.pdf-viewer-dark');
  assert.deepEqual(t.map((x) => x.id), ['zovo.zovo-hex-viewer', 'zovo.sqlite-table-viewer', 'zovo.zovo-auto-rename-tag']);
  assert.deepEqual(t.map((x) => x.name), ['Hex Viewer', 'SQLite Editor', 'Auto Rename Tag']);
  assert.deepEqual(t.map((x) => x.proPrefix), ['hexViewer', 'sqliteViewer', null]);
});

test('XSELL2 2: no "already have" line when no other Zovo tool with Pro is installed', async () => {
  const f = fakeVscode({}, [ext('zovo.pdf-viewer-dark', 'PDF Viewer', 'pdfViewer'), ext('zovo.zovo-auto-rename-tag', 'Auto Rename Tag', null)]);
  const pro = mk(f);
  await pro.ready;
  await pro.requirePro('Merge PDFs', { detail: 'Joins PDFs.' });
  assert.doesNotMatch(f.log.modal[0].detail, /already have/);
  const g = fakeVscode({}, others);
  const p2 = mk(g);
  await p2.ready;
  await p2.requirePro('Merge PDFs', { detail: 'Joins PDFs.' });
  assert.match(g.log.modal[0].detail, /\n\nZovo Pro also turns on Pro tools in the Zovo extensions you already have: Hex Viewer and SQLite Editor\.$/);
});

test('XSELL2 3: at most 3 names, then "and N more"', () => {
  assert.equal(namesList(['A']), 'A');
  assert.equal(namesList(['A', 'B']), 'A and B');
  assert.equal(namesList(['A', 'B', 'C']), 'A, B and C');
  assert.equal(namesList(['A', 'B', 'C', 'D', 'E']), 'A, B, C and 2 more');
  const many = ['Hex Viewer', 'SQLite Editor', 'DOCX Viewer', 'PPTX Viewer', 'Tensor Viewer'].map((name, i) => ext(`zovo.t${i}`, name, `t${i}`));
  const f = fakeVscode({}, many);
  const pro = mk(f);
  assert.match(pro.panelDetail('Merge PDFs', { detail: 'x' }), /already have: Hex Viewer, SQLite Editor, DOCX Viewer and 2 more\.$/);
});

test('XSELL2 4: carry-over runs once, only after an unlock, never at activation; "Not now" is final', async () => {
  let answer = 'Turn on';
  const f = fakeVscode({ input: sign(base), info: (msg) => (msg.includes('Turn it on in your other Zovo tools') ? answer : undefined) }, others);
  const pro = mk(f, { commandPrefix: 'pdfViewer' });
  await pro.ready;
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick();
  assert.equal(f.log.info.length + f.log.exec.length + f.log.modal.length, 0, 'nothing at activation or on focus');
  const r = await f.log.commands['pdfViewer.enterLicenseKey']();
  assert.deepEqual(r, { pro: true, reason: 'ok' }, 'the command result carries no key');
  assert.equal(f.log.info[0].msg, 'Zovo Pro is on in PDF Viewer. Turn it on in your other Zovo tools too? (Hex Viewer and SQLite Editor)');
  assert.deepEqual(f.log.info[0].buttons, ['Turn on', 'Not now']);
  assert.deepEqual(f.log.exec.map((e) => e.id), ['hexViewer.enterLicenseKey', 'sqliteViewer.enterLicenseKey']);
  assert.deepEqual(f.log.exec[0].arg, { key: sign(base), carryOver: true });
  assert.equal(f.log.info[1].msg, 'Zovo Pro is on in 2 more Zovo tools.');
  // a second unlock in the same extension never asks again
  await pro.remove();
  await f.log.commands['pdfViewer.enterLicenseKey']();
  assert.equal(f.log.exec.length, 2);
  assert.ok(!f.log.info.slice(2).some((m) => /other Zovo tools/.test(m.msg)));
  // "Not now" in another extension: no command runs, and it is final
  answer = 'Not now';
  const g = fakeVscode({ input: sign(base), info: (msg) => (msg.includes('other Zovo tools') ? answer : undefined) }, others);
  const p2 = mk(g, { commandPrefix: 'pdfViewer' });
  await p2.ready;
  await g.log.commands['pdfViewer.enterLicenseKey']();
  assert.equal(g.log.exec.length, 0);
  assert.equal(g.global.get(idx.CARRY_KEY), true);
});

test('XSELL2 5: a carried key that fails verification falls back to the input box', async () => {
  const other = crypto.generateKeyPairSync('ed25519').privateKey;
  const bad = sign(base, other);
  const f = fakeVscode({ input: undefined }, others);
  const pro = mk(f, { commandPrefix: 'pdfViewer' });
  await pro.ready;
  const r = await f.log.commands['pdfViewer.enterLicenseKey']({ key: bad, carryOver: true });
  assert.equal(f.log.input.length, 1);
  assert.equal(f.log.input[0].value, bad);
  assert.equal(r.pro, false);
  assert.equal(pro.isPro(), false);
  // a good carried key: stored with no input box
  const g = fakeVscode({}, others);
  const p2 = mk(g, { commandPrefix: 'pdfViewer' });
  await p2.ready;
  assert.deepEqual(await g.log.commands['pdfViewer.enterLicenseKey']({ key: sign(base), carryOver: true }), { pro: true, reason: 'ok' });
  assert.equal(g.log.input.length, 0);
  assert.equal(g.log.info.length, 0, 'a carried key shows no message of its own');
  assert.equal(p2.isPro(), true);
});

test('XSELL2 6: a tool that is already Pro returns without UI', async () => {
  const f = fakeVscode({}, others);
  f.secrets.set(lic.SECRET_KEY, sign(base));
  const pro = mk(f, { commandPrefix: 'pdfViewer', rails: [fakeSponsors({ kind: 'lifetime', login: 'buyer', tierId: 'ST_kwDOAwq1PM4ACl_G' }), lic.createKeyRail({ ...f, sku: 'pdf-pro', publicKey: PUB, now: () => NOW })] });
  await pro.ready;
  assert.equal(pro.isPro(), true);
  for (const id of ['pdfViewer.enterLicenseKey', 'pdfViewer.unlockWithSponsors']) {
    assert.deepEqual(await f.log.commands[id]({ key: sign(base), carryOver: true }), { pro: true, reason: 'ok' });
  }
  assert.equal(f.log.info.length + f.log.warn.length + f.log.input.length + f.log.picks.length + f.log.exec.length, 0);
});

// ---- ~/.zovo/pro.json ----

test('pro.json: a key unlock writes the key (mode 600, folder 700, no token); a second extension is Pro at activation', async () => {
  const file = tmpFile();
  const f = fakeVscode({ input: sign(base) });
  const pro = mk(f, { sharedFile: file, commandPrefix: 'pdfViewer' });
  await pro.ready;
  assert.equal(fs.existsSync(file), false, 'nothing written before an unlock');
  await f.log.commands['pdfViewer.enterLicenseKey']();
  const st = fs.statSync(file);
  assert.equal(st.mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(Object.keys(j).sort(), ['key', 'updated', 'v']);
  assert.equal(j.key, sign(base));
  assert.doesNotMatch(fs.readFileSync(file, 'utf8'), /token|gho_|ghp_|@/i);
  const g = fakeVscode();
  g.context.extension = { id: 'zovo.sqlite-table-viewer' };
  const other = createLicense({ ...g, sku: 'sqlite-pro', name: 'Zovo', product: 'SQLite Editor', publicKey: PUB, now: () => NOW, sharedFile: file });
  await other.ready;
  assert.equal(other.isPro('sqlite-pro'), true, 'Pro with no second paste');
  assert.equal(g.log.input.length + g.log.info.length, 0);
});

test('pro.json: a Sponsors unlock writes login, tier and date only; lifetime counts, notemods tiers never', async () => {
  const file = tmpFile();
  const f = fakeVscode();
  const pro = mk(f, { sharedFile: file, rails: [fakeSponsors({ kind: 'lifetime', login: 'buyer-1', tierId: 'ST_kwDOAwq1PM4ACl_G' })] });
  await pro.ready;
  await pro.unlock('github-sponsors');
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(j.sponsors, { login: 'buyer-1', tierId: 'ST_kwDOAwq1PM4ACl_G', kind: 'lifetime', date: '2026-11-10' });
  assert.deepEqual(Object.keys(j).sort(), ['sponsors', 'updated', 'v']);
  const read = async (sponsors) => {
    const p = tmpFile();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify({ v: 1, sponsors }), { mode: 0o600 });
    const l = createLicense({ ...fakeVscode(), sku: 'pdf-pro', publicKey: PUB, now: () => NOW, sharedFile: p, rails: [] });
    await l.ready;
    return l.isPro();
  };
  assert.equal(await read({ login: 'b', tierId: 'ST_kwDOAwq1PM4ACl_G', kind: 'lifetime', date: '2026-11-10' }), true);
  assert.equal(await read({ login: 'b', tierId: 'ST_kwDOAwq1PM4ACioy', kind: 'lifetime', date: '2026-11-10' }), false, 'notemods $15 tier');
  assert.equal(await read({ login: 'b', tierId: 'ST_kwDOAwq1PM4ACcUj', kind: 'monthly', date: '2026-11-10', until: NOW + 1000 }), true);
  assert.equal(await read({ login: 'b', tierId: 'ST_kwDOAwq1PM4ACcUj', kind: 'monthly', date: '2026-10-01', until: NOW - 1000 }), false, 'month over');
});

test('pro.json: a key with a bad signature, a test-mode key or another product never unlocks', async () => {
  const other = crypto.generateKeyPairSync('ed25519').privateKey;
  const cases = [
    [sign(base, other), false],
    [sign(base).slice(0, -4) + 'AAAA', false],
    [sign({ ...base, lm: false }), false],
    [sign({ ...base, sku: 'hex-pro' }), false],
    [sign({ ...base, exp: '2026-01-01' }), false],
    [sign(base), true],
  ];
  for (const [key, want] of cases) {
    const p = tmpFile();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify({ v: 1, key }), { mode: 0o600 });
    const l = createLicense({ ...fakeVscode(), sku: 'pdf-pro', publicKey: PUB, now: () => NOW, sharedFile: p, rails: [] });
    await l.ready;
    assert.equal(l.isPro(), want, key.slice(0, 40));
  }
  const p = tmpFile();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, '{not json');
  assert.equal(await readSharedFile(p), null);
});

test('pro.json: picked up on the next Pro click and on window focus without a restart; Remove clears it', async () => {
  const file = tmpFile();
  const f = fakeVscode();
  const pro = mk(f, { sharedFile: file });
  await pro.ready;
  assert.equal(pro.isPro(), false);
  await writeSharedFile(file, { key: sign(base) });
  assert.equal(await pro.requirePro('Merge PDFs', { detail: 'x' }), true);
  assert.equal(f.log.modal.length, 0, 'no panel: Pro came from the shared file');
  const g = fakeVscode();
  const file2 = tmpFile();
  const p2 = mk(g, { sharedFile: file2 });
  await p2.ready;
  const seen = []; p2.onDidChange((x) => seen.push(x));
  await writeSharedFile(file2, { key: sign(base) });
  g.log.win({ focused: true });
  for (let i = 0; i < 100 && !seen.length; i++) await new Promise((r) => setTimeout(r, 5));
  assert.deepEqual(seen, [true]);
  await p2.remove();
  assert.equal(fs.existsSync(file2), false);
  assert.equal(p2.isPro(), false);
});

test('pro.json is off for unit tests and fakes unless a path is given (never the real home folder)', () => {
  const f = fakeVscode();
  const l = createLicense({ ...f, sku: 'pdf-pro', publicKey: PUB });
  assert.equal(l.sharedFile, '');
  assert.ok(!l.rails.some((r) => r.id === 'zovo-shared'));
});

// ---- hidden parts and the order ----

test('refund line hidden while refund_days is empty, shown with the owner value', async () => {
  const f = fakeVscode();
  const a = mk(f, { refundDays: '' });
  assert.doesNotMatch(a.panelDetail('Merge PDFs', { detail: 'x' }), /refund/i);
  const b = mk(f, { refundDays: '30' });
  assert.match(b.panelDetail('Merge PDFs', { detail: 'x' }), / Not happy\? Full refund within 30 days\. Everything that is free today stays free\./);
  const c = mk(f); // no config.js in the factory folder
  assert.doesNotMatch(c.panelDetail('Merge PDFs', { detail: 'x' }), /refund/i);
});

test('Gumroad hidden while gumroad_pro is empty: no rail, no button, no command, no request, key link ignored', async () => {
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = async () => { calls += 1; throw new Error('no network in tests'); };
  try {
    const f = fakeVscode({ info: () => 'Add key' });
    const pro = mk(f, { gumroadPro: '', gumroadUrl: '', commandPrefix: 'pdfViewer' });
    await pro.ready;
    assert.ok(!pro.rails.some((r) => r.id === 'gumroad'));
    assert.deepEqual(pro.buttons(), ['Get Zovo Pro, USD 19', 'Pay with PayPal', 'I already paid']);
    assert.ok(!('pdfViewer.payByCard' in f.log.commands));
    assert.equal(await pro.handleUri({ path: '/license', query: 'key=A1B2C3D4-E5F60718-293A4B5C-6D7E8F90' }), false);
    await pro.unlock();
    assert.ok(!f.log.picks[0].some((l) => /Gumroad/.test(l)));
    assert.equal(calls, 0);
    // with the owner's ids: the card button second, the Gumroad key in the paid pick, still no request until a click
    const g = fakeVscode();
    const on = mk(g, { gumroadPro: 'zovoPro123==', gumroadUrl: 'https://zovo.gumroad.com/l/pro', commandPrefix: 'pdfViewer' });
    await on.ready;
    assert.deepEqual(on.buttons(), ['Get Zovo Pro, USD 19', 'Pay by card', 'Pay with PayPal', 'I already paid']);
    assert.ok('pdfViewer.payByCard' in g.log.commands);
    await on.payByCard();
    assert.deepEqual(g.log.opened, ['https://zovo.gumroad.com/l/pro?wanted=true']);
    await on.unlock();
    assert.deepEqual(g.log.picks[0], ['Unlock with GitHub Sponsors', 'Enter a license key', 'Enter a Gumroad license key', 'I paid with PayPal and have no key yet']);
    assert.equal(calls, 0);
  } finally { global.fetch = realFetch; }
});

test('button order and the "I already paid" pick (EXEC14), every Pro link opens the tier', async () => {
  let pickPaid = 'I already paid';
  const f = fakeVscode({ info: (msg, rest) => (rest[0] && rest[0].modal ? pickPaid : undefined), pick: 'I paid with PayPal and have no key yet' });
  const pro = mk(f);
  await pro.ready;
  assert.equal(await pro.requirePro('Merge PDFs', { detail: 'x', triesUsed: 3 }), false);
  assert.deepEqual(f.log.modal[0].buttons, ['Get Zovo Pro, USD 19', 'Pay with PayPal', 'I already paid']);
  assert.deepEqual(f.log.picks[0], ['Unlock with GitHub Sponsors', 'Enter a license key', 'I paid with PayPal and have no key yet']);
  assert.match(f.log.opened[0], /zovo-pro-key\.yml/);
  pickPaid = 'Get Zovo Pro, USD 19';
  await pro.requirePro('Merge PDFs', { detail: 'x' });
  await pro.getPro();
  const s = fakeVscode({ pick: 'Zovo Pro: USD 19 once, unlocks the Pro tools in all Zovo extensions' });
  const sp = mk(s);
  await sp.supportDeveloper([{ label: 'GitHub Sponsors', url: 'https://github.com/sponsors/theluckystrike' }, { label: 'PayPal', url: 'https://www.paypal.com/paypalme/najzzz' }]);
  assert.deepEqual(s.log.picks[0], ['Zovo Pro: USD 19 once, unlocks the Pro tools in all Zovo extensions', 'GitHub Sponsors', 'PayPal']);
  for (const u of [...f.log.opened.slice(1), ...s.log.opened]) assert.equal(u, 'https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878');
});

test('palette: 5 commands, category "Zovo Pro", the same titles in every product', () => {
  const a = paletteCommands('pdfViewer');
  const b = paletteCommands('sqliteViewer');
  assert.deepEqual(a.map((c) => c.title), b.map((c) => c.title));
  assert.deepEqual(a.map((c) => c.title), [
    'Get Zovo Pro (USD 19 once, all 22 Zovo extensions)',
    'Pay for Zovo Pro with PayPal (USD 19, team of 5 USD 59)',
    'I already paid: unlock with GitHub Sponsors',
    'Enter Zovo Pro license key',
    'Remove Zovo Pro from this editor',
  ]);
  assert.ok(a.every((c) => c.category === 'Zovo Pro'));
  assert.deepEqual(a.map((c) => c.command), ['pdfViewer.getPro', 'pdfViewer.payWithPayPal', 'pdfViewer.unlockWithSponsors', 'pdfViewer.enterLicenseKey', 'pdfViewer.removeLicense']);
});
