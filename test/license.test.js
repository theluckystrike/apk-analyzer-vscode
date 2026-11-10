'use strict';
// Tests for the shared Zovo license module. No network. Run: node --test test/license.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const lic = require(fs.existsSync(path.join(__dirname, '..', 'license.js')) ? '../license.js' : '../src/license/license.js');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function sign(payload, key = privateKey) {
  const p = b64url(Buffer.from(JSON.stringify(payload)));
  const sig = crypto.sign(null, Buffer.from(lic.SIG_CONTEXT + p), key);
  return `${lic.KEY_PREFIX}${p}.${b64url(sig)}`;
}
const base = { v: 1, sku: 'hex-pro', eh: 'a'.repeat(24), sid: 'cs_live_abcdefghijklmnop', iat: '2026-11-09', lm: true };
const NOW = Date.UTC(2026, 10, 10);
const opts = { publicKey: PUB, now: NOW };

test('valid lifetime key', () => {
  const r = lic.checkKey(sign(base), 'hex-pro', opts);
  assert.equal(r.ok, true);
  assert.equal(r.license.sku, 'hex-pro');
  assert.equal(r.license.expires, null);
  assert.equal(r.license.seats, 1);
});

test('copy noise is tolerated: spaces, line breaks, quotes', () => {
  const k = sign(base);
  const noisy = ` "${k.slice(0, 30)}\n  ${k.slice(30, 60)}\r\n${k.slice(60)}" `;
  assert.equal(lic.checkKey(noisy, 'hex-pro', opts).ok, true);
});

test('tampered payload fails the signature', () => {
  const k = sign(base);
  const [p, s] = k.slice(lic.KEY_PREFIX.length).split('.');
  const forged = b64url(Buffer.from(JSON.stringify({ ...base, sku: 'zovo-pro' })));
  assert.equal(lic.verifyKey(`ZOVO1.${forged}.${s}`, opts).reason, 'signature');
  const flipped = p.slice(0, -2) + (p.at(-2) === 'A' ? 'B' : 'A') + p.at(-1);
  assert.equal(lic.verifyKey(`ZOVO1.${flipped}.${s}`, opts).reason, 'signature');
});

test('tampered signature or other signer fails', () => {
  const k = sign(base);
  const bad = k.slice(0, -3) + (k.at(-3) === 'A' ? 'B' : 'A') + k.slice(-2);
  assert.equal(lic.verifyKey(bad, opts).ok, false);
  const other = crypto.generateKeyPairSync('ed25519').privateKey;
  assert.equal(lic.verifyKey(sign(base, other), opts).reason, 'signature');
});

test('wrong sku is refused; bundle sku unlocks all', () => {
  assert.equal(lic.checkKey(sign(base), 'docx-pro', opts).reason, 'sku');
  const bundle = sign({ ...base, sku: 'zovo-pro' });
  assert.equal(lic.checkKey(bundle, 'docx-pro', opts).ok, true);
  assert.equal(lic.checkKey(bundle, 'hex-pro', opts).ok, true);
});

test('yearly key: valid through the exp day (UTC), expired after', () => {
  const k = sign({ ...base, exp: '2027-11-16' });
  assert.equal(lic.verifyKey(k, { publicKey: PUB, now: Date.UTC(2027, 10, 16, 23, 59) }).ok, true);
  const r = lic.verifyKey(k, { publicKey: PUB, now: Date.UTC(2027, 10, 17) });
  assert.equal(r.reason, 'expired');
  assert.equal(lic.renewUrl(r.license), 'https://license.zovo.one/claim?session_id=cs_live_abcdefghijklmnop');
});

test('test-mode key refused unless allowTest', () => {
  const k = sign({ ...base, lm: false, sid: 'cs_test_abcdefghijklmnop' });
  assert.equal(lic.verifyKey(k, { ...opts, allowTest: false }).reason, 'test');
  assert.equal(lic.verifyKey(k, { ...opts, allowTest: true }).ok, true);
});

test('garbage and wrong versions', () => {
  for (const g of ['', 'hello', 'ZOVO1.', 'ZOVO1.abc', 'ZOVO1.a.b.c', 'ZOVO1.!!!.???', 'ZOVO1.' + 'A'.repeat(20) + '.' + 'A'.repeat(86), 'ZOVO-' + 'A'.repeat(20) + '.' + 'A'.repeat(86)]) {
    assert.equal(lic.verifyKey(g, opts).ok, false, g);
  }
  assert.equal(lic.verifyKey(sign({ ...base, v: 2 }), opts).reason, 'version');
  assert.equal(lic.verifyKey(sign({ ...base, iat: 'yesterday' }), opts).reason, 'version');
  assert.equal(lic.verifyKey(sign({ ...base, sku: '' }), opts).reason, 'version');
});

test('embedded public key is a real Ed25519 SPKI key (not the placeholder)', () => {
  const k = crypto.createPublicKey({ key: Buffer.from(lic.PUBLIC_KEY_SPKI_B64, 'base64'), format: 'der', type: 'spki' });
  assert.equal(k.asymmetricKeyType, 'ed25519');
  // a key signed by the test key must NOT pass the embedded key
  assert.equal(lic.verifyKey(sign(base), { now: NOW }).reason, 'signature');
});

// --- VS Code side with a fake vscode API ---
const IDX = require(fs.existsSync(path.join(__dirname, '..', 'index.js')) ? '../index.js' : '../src/license/index.js');
// Older tests pin the panel without the card rail, whatever the build's config.js says; CARD1 tests pass cardBuyUrl.
const createLicense = (o) => IDX.createLicense({ cardBuyUrl: '', ...o });

function fakeVscode(answers = {}) {
  const log = { info: [], warn: [], opened: [], commands: {}, input: [], picks: [] };
  const vscode = {
    Uri: { parse: (s) => ({ toString: () => s, s }) },
    env: { openExternal: async (u) => { log.opened.push(u.s); return true; } },
    window: {
      showInformationMessage: async (msg, ...rest) => { log.info.push(msg); return answers.info ? answers.info(msg, rest) : undefined; },
      showWarningMessage: async (msg, ...rest) => { log.warn.push(msg); return answers.warn ? answers.warn(msg, rest) : undefined; },
      showErrorMessage: async (msg) => { log.warn.push(msg); },
      showInputBox: async (o) => { log.input.push(o); return typeof answers.input === 'function' ? answers.input(o) : answers.input; },
      showQuickPick: async (items, o) => { log.picks.push(items.map((i) => i.label)); return answers.pick ? items.find((i) => i.label === answers.pick) : undefined; },
      state: { focused: true },
      onDidChangeWindowState: (fn) => { log.win = fn; return { dispose() { log.win = null; } }; },
    },
    commands: { registerCommand: (id, fn) => { log.commands[id] = fn; return { dispose() {} }; } },
  };
  const secrets = new Map(); const global = new Map();
  const context = {
    subscriptions: [],
    secrets: { get: async (k) => secrets.get(k), store: async (k, v) => { secrets.set(k, v); }, delete: async (k) => { secrets.delete(k); }, onDidChange: () => ({ dispose() {} }) },
    globalState: { get: (k) => global.get(k), update: async (k, v) => { global.set(k, v); } },
  };
  return { vscode, context, log, secrets, global };
}

// A stand-in Sponsors rail (the real one is tested in sponsors.test.js).
function fakeSponsors(result) {
  let pro = false; const ls = new Set();
  return {
    id: 'github-sponsors', ready: Promise.resolve(), isPro: () => pro,
    async unlock() { pro = result.pro; for (const f of ls) f(pro); return { rail: 'github-sponsors', kind: pro ? 'lifetime' : 'none', login: 'x', ...result }; },
    async refresh() { this.refreshed = (this.refreshed || 0) + 1; return false; },
    async remove() { pro = false; for (const f of ls) f(pro); },
    state: () => (pro ? { kind: 'lifetime' } : null),
    onDidChange(fn) { ls.add(fn); return { dispose: () => ls.delete(fn) }; },
  };
}

const mk = (f, extra = {}) => createLicense({ ...f, sku: 'hex-pro', name: 'Hex Viewer', publicKey: PUB, now: () => NOW, ...extra });

test('key rail: offline unlock stores in SecretStorage, survives a restart, remove clears', async () => {
  const f = fakeVscode({ input: sign(base) });
  const rail = lic.createKeyRail({ ...f, sku: 'hex-pro', name: 'Hex Viewer', publicKey: PUB, now: () => NOW });
  await rail.ready;
  assert.equal(rail.isPro('hex-pro'), false);
  let events = 0; rail.onDidChange(() => events++);
  const r = await rail.unlock();
  assert.deepEqual({ ...r, message: undefined }, { rail: 'license-key', pro: true, reason: 'ok', kind: 'lifetime', login: '', message: undefined });
  assert.equal(rail.isPro('hex-pro'), true);
  assert.equal(rail.isPro('docx-pro'), false);
  assert.equal(events, 1);
  assert.equal(f.secrets.get(lic.SECRET_KEY), sign(base));
  assert.deepEqual(rail.state(), { sku: 'hex-pro', issued: '2026-11-09', expires: null, seats: 1, live: true }); // no key in state
  assert.equal(await rail.refresh(), false);
  const again = lic.createKeyRail({ ...f, sku: 'hex-pro', publicKey: PUB, now: () => NOW });
  await again.ready;
  assert.equal(again.isPro('hex-pro'), true);
  await again.remove();
  assert.equal(again.isPro('hex-pro'), false);
  assert.equal(f.secrets.size, 0);
  assert.equal(f.log.opened.length, 0);
});

test('key rail: wrong sku, tampered, test-mode and cancel return reasons and store nothing', async () => {
  const f = fakeVscode();
  const rail = lic.createKeyRail({ ...f, sku: 'hex-pro', publicKey: PUB, now: () => NOW });
  await rail.ready;
  assert.equal((await rail.saveKey(sign({ ...base, sku: 'docx-pro' }))).reason, 'wrong-sku');
  assert.equal((await rail.saveKey(sign(base).slice(0, -4) + 'AAAA')).reason, 'invalid-key');
  assert.equal((await rail.saveKey(sign({ ...base, lm: false }))).reason, 'invalid-key');
  assert.equal((await rail.unlock()).reason, 'cancelled');
  const exp = await rail.saveKey(sign({ ...base, exp: '2026-01-01' }));
  assert.equal(exp.reason, 'expired');
  assert.equal(exp.renewUrl, 'https://license.zovo.one/claim?session_id=cs_live_abcdefghijklmnop');
  assert.equal(f.secrets.size, 0);
});

test('facade: Pro when ANY rail says so; commands registered; change events', async () => {
  const sp = fakeSponsors({ pro: true, reason: 'ok', message: 'Zovo Pro is on. Thank you.' });
  const f = fakeVscode();
  const keyOnly = lic.createKeyRail({ ...f, sku: 'hex-pro', publicKey: PUB, now: () => NOW });
  const pro = mk(f, { rails: [sp, keyOnly], commandPrefix: 'hexViewer' });
  await pro.ready;
  assert.equal(pro.isPro(), false);
  assert.deepEqual(Object.keys(f.log.commands).sort(), ['hexViewer.enterLicenseKey', 'hexViewer.getPro', 'hexViewer.payWithPayPal', 'hexViewer.removeLicense', 'hexViewer.unlockWithSponsors']);
  const seen = []; pro.onDidChange((p) => seen.push(p));
  await f.log.commands['hexViewer.unlockWithSponsors']();
  assert.equal(pro.isPro('hex-pro'), true);
  assert.deepEqual(f.log.info, ['Zovo Pro is on. Thank you.']);
  assert.deepEqual(seen, [true]);
  await pro.remove();
  assert.equal(pro.isPro(), false);
  assert.deepEqual(seen, [true, false]);
});

test('facade default rails: Sponsors rail from sponsors.js + key rail; Enter key command unlocks', async () => {
  const f = fakeVscode({ input: sign({ ...base, sku: 'zovo-pro' }) });
  const pro = mk(f, { commandPrefix: 'hexViewer' });
  await pro.ready;
  assert.deepEqual(pro.rails.map((r) => r.id), ['github-sponsors', 'license-key']);
  await f.log.commands['hexViewer.enterLicenseKey']();
  assert.equal(pro.isPro('hex-pro'), true);
  assert.equal(pro.isPro('docx-pro'), true); // bundle
  assert.match(f.log.info[0], /^Zovo Pro is on\. Thank you/);
});

test('facade unlock() with no rail id: the "I already paid" quick pick, GitHub Sponsors first (EXEC14)', async () => {
  const g = fakeVscode({ pick: 'Enter a license key', input: sign(base) });
  const pro = mk(g);
  await pro.ready;
  const r = await pro.unlock();
  assert.deepEqual(g.log.picks[0], ['Unlock with GitHub Sponsors', 'Enter a license key', 'I paid with PayPal and have no key yet']);
  assert.equal(r.pro, true);
  assert.equal(pro.isPro(), true);
});

test('EXEC14 order: panel [Get Zovo Pro, USD 19] [Pay with PayPal] [I already paid]; the paid pick lists Sponsors, key, other rails', async () => {
  assert.equal(IDX.MODULE_VERSION, '2026-11-10.card1');
  const polar = { id: 'polar', label: 'Polar', ready: Promise.resolve(), isPro: () => false, unlock: async () => ({ pro: false, reason: 'cancelled' }) };
  let buttons;
  const f = fakeVscode({ info: (msg, rest) => { if (rest[0] && rest[0].modal) buttons = rest.slice(1); return undefined; } });
  const sp = fakeSponsors({ pro: false, reason: 'cancelled', message: '' });
  const key = lic.createKeyRail({ vscode: f.vscode, context: f.context, sku: 'hex-pro', name: 'Hex Viewer', publicKey: PUB });
  const pro = mk(f, { rails: [polar, key, sp] }); // given in the wrong order on purpose
  await pro.ready;
  await pro.unlock();
  assert.deepEqual(f.log.picks[0], ['Unlock with GitHub Sponsors', 'Enter a license key', 'Polar', 'I paid with PayPal and have no key yet']);
  await pro.requirePro('Checksums');
  assert.deepEqual(buttons, ['Get Zovo Pro, USD 19', 'Pay with PayPal', 'I already paid']);
  const g = fakeVscode({ info: (msg, rest) => { if (rest[0] && rest[0].modal) buttons = rest.slice(1); return undefined; } });
  const np = mk(g, { paypalUrl: '' });
  await np.ready;
  await np.unlock();
  assert.deepEqual(g.log.picks[0], ['Unlock with GitHub Sponsors', 'Enter a license key'], 'no PayPal link: no PayPal row');
  await np.requirePro('Checksums');
  assert.deepEqual(buttons, ['Get Zovo Pro, USD 19', 'I already paid']);
  const h = fakeVscode({ info: (msg, rest) => (rest[0] && rest[0].modal ? 'Get Zovo Pro, USD 19' : undefined) });
  const hp = mk(h);
  await hp.ready;
  assert.equal(await hp.requirePro('Checksums'), false);
  assert.deepEqual(h.log.opened, ['https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878'], 'the primary button opens the Zovo Pro tier');
});

test('Get Pro: Sponsors page by default; Stripe link gets a stable random install id; "" = not on sale', async () => {
  const a = fakeVscode();
  await mk(a).getPro();
  assert.deepEqual(a.log.opened, ['https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878']);
  assert.equal(a.global.size, 0); // no install id for the Sponsors page
  const b = fakeVscode();
  const pb = mk(b, { paymentUrl: lic.BUY_URL + 'hex-pro' });
  await pb.getPro(); await pb.getPro();
  assert.match(b.log.opened[0], /^https:\/\/license\.zovo\.one\/buy\/hex-pro\?client_reference_id=[0-9a-f-]{36}$/);
  assert.equal(b.log.opened[1], b.log.opened[0]);
  const c = fakeVscode();
  await mk(c, { paymentUrl: '' }).getPro();
  assert.equal(c.log.opened.length, 0);
  assert.match(c.log.info[0], /not on sale yet/);
});

test('requirePro: true when unlocked (and triggers rail refresh); explains with rail buttons when locked', async () => {
  const sp = fakeSponsors({ pro: true, reason: 'ok', message: 'on' });
  let buttons;
  const f = fakeVscode({ info: (msg, rest) => { if (rest[0] && rest[0].modal) buttons = rest.slice(1); return undefined; } });
  const pro = mk(f, { rails: [sp] });
  await pro.ready;
  assert.equal(await pro.requirePro('Binary templates'), false);
  assert.equal(f.log.info[0], 'Binary templates is part of Zovo Pro.');
  assert.deepEqual(buttons, ['Get Zovo Pro, USD 19', 'Pay with PayPal', 'I already paid']);
  await pro.unlock('github-sponsors');
  assert.equal(await pro.requirePro('Binary templates'), true);
  assert.equal(sp.refreshed, 1);
});

test('requirePro: "I already paid" then a license key unlocks and returns true', async () => {
  const f = fakeVscode({ info: (msg, rest) => (rest[0] && rest[0].modal ? 'I already paid' : undefined), pick: 'Enter a license key', input: sign(base) });
  const pro = mk(f);
  await pro.ready;
  assert.equal(await pro.requirePro('Checksums'), true);
});

test('expired yearly key: locked, Renew page offered and opened', async () => {
  const f = fakeVscode({ info: (msg, rest) => (rest.includes('Renew page') ? 'Renew page' : undefined) });
  f.secrets.set(lic.SECRET_KEY, sign({ ...base, exp: '2026-11-01' }));
  const pro = mk(f, { rails: undefined });
  await pro.ready;
  assert.equal(pro.isPro(), false);
  await pro.requirePro('Struct export');
  assert.deepEqual(f.log.opened, ['https://license.zovo.one/claim?session_id=cs_live_abcdefghijklmnop']);
});

test('yearly key runs out while the editor stays open', async () => {
  let now = Date.UTC(2027, 10, 16, 12);
  const f = fakeVscode();
  f.secrets.set(lic.SECRET_KEY, sign({ ...base, exp: '2027-11-16' }));
  const pro = mk(f, { now: () => now });
  await pro.ready;
  assert.equal(pro.isPro(), true);
  now = Date.UTC(2027, 10, 17, 1);
  assert.equal(pro.isPro(), false);
});

test('vscode:// license link asks first, then stores; declining stores nothing', async () => {
  const f = fakeVscode({ info: (msg) => (/^Add a/.test(msg) ? 'Add key' : undefined) });
  const pro = mk(f);
  await pro.ready;
  assert.equal(await pro.handleUri({ path: '/other', query: '' }), false);
  assert.equal(await pro.handleUri({ path: '/license', query: 'key=' + encodeURIComponent(sign(base)) }), true);
  assert.equal(pro.isPro(), true);
  const g = fakeVscode();
  const p2 = mk(g);
  assert.equal(await p2.handleUri({ path: '/license', query: 'key=' + encodeURIComponent(sign(base)) }), false);
  assert.equal(g.secrets.size, 0);
});

test('PRO1 compatibility: its PREFIX.payload.sig verifier accepts these keys', () => {
  const pro1 = path.join(__dirname, '..', '..', '..', '..', 'run-20261107', 'wave14', 'out', 'PRO1-work', 'hex', 'src', 'pro', 'license.js');
  if (!fs.existsSync(pro1)) return; // only on the factory Mac while PRO1-work exists
  const { verifyKey } = require(pro1);
  assert.equal(verifyKey(sign(base), 'hex-pro', [PUB], NOW).ok, true);
  assert.equal(verifyKey(sign({ ...base, sku: 'zovo-pro' }), 'hex-pro', [PUB], NOW).ok, true);
  assert.equal(verifyKey(sign({ ...base, sku: 'docx-pro' }), 'hex-pro', [PUB], NOW).ok, false);
  assert.equal(verifyKey(sign({ ...base, exp: '2027-11-16' }), 'hex-pro', [PUB], Date.UTC(2027, 10, 17, 1)).ok, false);
});

test('license.js and index.js make no network calls: no http/https/net/fetch', () => {
  for (const name of ['license.js', 'index.js']) {
    const p = fs.existsSync(path.join(__dirname, '..', name)) ? path.join(__dirname, '..', name) : path.join(__dirname, '..', 'src', 'license', name);
    const src = fs.readFileSync(p, 'utf8');
    assert.ok(!/require\(['"](https?|net|tls|dgram)['"]\)|\bfetch\(/.test(src), name);
  }
});

// EXEC3 (2026-11-09): the 5-seat team licence.
test('team licence: zovo-pro-team and zovo-pro + q=5 keys unlock every product and carry 5 seats', () => {
  assert.ok(lic.BUNDLE_SKUS.includes('zovo-pro-team'));
  for (const sku of ['zovo-pro-team', 'zovo-pro']) {
    const k = sign({ ...base, sku, sid: 'manual-paypal-TEAM1', q: 5 });
    for (const p of ['hex-pro', 'docx-pro', 'xlsx-pro', 'sql-client-pro']) assert.equal(lic.checkKey(k, p, opts).ok, true, `${sku} -> ${p}`);
    assert.equal(lic.verifyKey(k, opts).license.seats, 5);
    assert.equal(lic.renewUrl(lic.verifyKey(k, opts).license), null); // manual sale: no Stripe renew page
  }
  assert.equal(lic.checkKey(sign({ ...base, sku: 'zovo-pro-teams' }), 'hex-pro', opts).reason, 'sku'); // exact match only
});


// --- CONV2: the buy path (PayPal steps, back-from-browser message, failed GitHub unlock) ---
const tick = () => new Promise((r) => setImmediate(r));

test('EXEC14 panel text: tries, detail, the other Pro tools, the count, free stays free; no refund line, no How to buy', async () => {
  let detail, title;
  const f = fakeVscode({ info: (msg, rest) => { if (rest[0] && rest[0].modal) { title = msg; detail = rest[0].detail; } return undefined; } });
  const pro = createLicense({ ...f, sku: 'pdf-pro', name: 'Zovo', product: 'PDF Viewer', proTools: ['Page tools', 'Merge PDFs', 'Highlights of all PDFs'], publicKey: PUB, now: () => NOW });
  await pro.ready;
  await pro.requirePro('Merge PDFs', { detail: 'Joins PDFs into one new PDF.', triesUsed: 3 });
  assert.equal(title, 'Merge PDFs is part of Zovo Pro.');
  assert.equal(detail, 'You used the 3 free tries on this computer.\nJoins PDFs into one new PDF.\n\nZovo Pro is USD 19 once, for life. It turns on Page tools and Highlights of all PDFs here, and the Pro tools of all 22 Zovo extensions, including Hex, DOCX, PDF, SQLite and PPTX. Everything that is free today stays free.');
  assert.doesNotMatch(detail, /refund|How to buy|USD 69|USD 70|a month/i);
  const g = fakeVscode({ info: (msg, rest) => { if (rest[0] && rest[0].modal) detail = rest[0].detail; return undefined; } });
  await createLicense({ ...g, sku: 'hex-pro', name: 'Zovo' }).requirePro('Checksums', 'Computes CRC-32.');
  assert.equal(detail, 'Computes CRC-32.', 'a product that passes its own text (older pro.js) keeps it, without a 2nd price line');
});

test('CONV2 PayPal: steps modal, USD 19 and team USD 59 links with currency, transaction-id form prefilled', async () => {
  let pick = 'Pay USD 19 on PayPal'; let modal;
  const f = fakeVscode({ info: (msg, rest) => { if (rest[0] && rest[0].modal) { modal = { msg, detail: rest[0].detail, buttons: rest.slice(1) }; return pick; } return undefined; } });
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', product: 'Hex Viewer', publicKey: PUB, now: () => NOW });
  await pro.ready;
  assert.equal(await pro.payWithPayPal(), false);
  assert.equal(modal.msg, 'Pay for Zovo Pro with PayPal');
  assert.deepEqual(modal.buttons, ['Pay USD 19 on PayPal', 'Team of 5: USD 59', 'Send the transaction ID', 'Enter a license key']);
  assert.match(modal.detail, /USD 19 for one person, or USD 59 for a team of 5/);
  assert.match(modal.detail, /transaction ID from the PayPal receipt/);
  assert.match(modal.detail, /never your name or email/);
  assert.match(modal.detail, /email address of your PayPal account/);
  pick = 'Team of 5: USD 59'; await pro.payWithPayPal();
  pick = 'Send the transaction ID'; await pro.payWithPayPal();
  assert.deepEqual(f.log.opened, [
    'https://www.paypal.com/paypalme/najzzz/19USD',
    'https://www.paypal.com/paypalme/najzzz/59USD',
    'https://github.com/theluckystrike/zovo-plugin-factory/issues/new?template=zovo-pro-key.yml&title=Zovo%20Pro%20key%3A%20PayPal%20payment%20for%20Hex%20Viewer&product=Hex%20Viewer',
  ]);
  pick = 'Enter a license key'; f.log.opened.length = 0;
  const g = fakeVscode({ info: (msg, rest) => (rest[0] && rest[0].modal ? 'Enter a license key' : undefined), input: sign(base) });
  const p2 = createLicense({ ...g, sku: 'hex-pro', name: 'Zovo', publicKey: PUB, now: () => NOW });
  await p2.ready;
  assert.equal(await p2.payWithPayPal(), true);
  assert.equal(p2.isPro(), true);
  const off = createLicense({ ...fakeVscode(), sku: 'hex-pro', paypalUrl: '' });
  assert.equal(typeof off.payWithPayPal, 'function');
});

test('CONV2 requirePro "Pay with PayPal" button runs the PayPal steps', async () => {
  const f = fakeVscode({ info: (msg, rest) => (rest[0] && rest[0].modal ? (msg.startsWith('Pay for') ? 'Pay USD 19 on PayPal' : 'Pay with PayPal') : undefined) });
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', publicKey: PUB, now: () => NOW });
  await pro.ready;
  assert.equal(await pro.requirePro('Checksums'), false);
  assert.deepEqual(f.log.opened, ['https://www.paypal.com/paypalme/najzzz/19USD']);
});

test('CONV2 back from GitHub Sponsors: one message after blur+focus, Unlock runs the Sponsors rail; never twice', async () => {
  const sp = fakeSponsors({ pro: true, reason: 'ok', message: 'Zovo Pro is on. Thank you.' });
  const f = fakeVscode({ info: (msg, rest) => (msg.startsWith('Back from GitHub') ? 'Unlock with GitHub Sponsors' : undefined) });
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', rails: [sp], publicKey: PUB, now: () => NOW });
  await pro.ready;
  f.log.win && f.log.win({ focused: true });
  assert.equal(f.log.info.length, 0); // nothing armed, nothing shown
  await pro.getPro();
  assert.deepEqual(f.log.opened, ['https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878']);
  f.log.win({ focused: true }); await tick();
  assert.equal(f.log.info.length, 0); // focus without leaving first: no message
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick(); await tick();
  assert.match(f.log.info[0], /^Back from GitHub Sponsors\? If you paid for the "\$19 one time" tier, turn Zovo Pro on now/);
  assert.equal(pro.isPro(), true);
  const n = f.log.info.length;
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick();
  assert.equal(f.log.info.length, n); // shown once
});

test('CONV2 back-from-browser: silent when Pro already, or after 2 h', async () => {
  const sp = fakeSponsors({ pro: true, reason: 'ok', message: 'on' });
  const f = fakeVscode();
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', rails: [sp], publicKey: PUB, now: () => NOW });
  await pro.ready;
  await pro.getPro();
  await pro.unlock('github-sponsors'); // paid and unlocked from the palette meanwhile
  const n = f.log.info.length;
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick();
  assert.equal(f.log.info.length, n);
  const sp2 = fakeSponsors({ pro: false, reason: 'not-sponsor', message: 'no' });
  const g = fakeVscode();
  const p2 = createLicense({ ...g, sku: 'hex-pro', name: 'Zovo', rails: [sp2], publicKey: PUB, now: () => NOW });
  const realNow = Date.now;
  try {
    await p2.getPro();
    Date.now = () => realNow() + 2 * 60 * 60 * 1000 + 1;
    g.log.win({ focused: false }); g.log.win({ focused: true }); await tick();
    assert.equal(g.log.info.length, 0);
  } finally { Date.now = realNow; }
});

test('CONV2 back from PayPal: offers the transaction-id form', async () => {
  const f = fakeVscode({ info: (msg, rest) => (rest[0] && rest[0].modal ? 'Pay USD 19 on PayPal' : msg.startsWith('Back from PayPal') ? 'Send the transaction ID' : undefined) });
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', product: 'DOCX Viewer', publicKey: PUB, now: () => NOW });
  await pro.ready;
  await pro.payWithPayPal();
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick(); await tick();
  assert.equal(f.log.opened.length, 2);
  assert.match(f.log.opened[1], /zovo-pro-key\.yml&title=.*&product=DOCX%20Viewer$/);
});

test('CONV2 not a buyer yet: warning offers the tier page (arms the return message) and PayPal', async () => {
  const sp = fakeSponsors({ pro: false, reason: 'not-sponsor', message: 'This GitHub account has not bought Zovo Pro yet.' });
  let buttons;
  const f = fakeVscode({ warn: (msg, rest) => { buttons = rest; return 'Open the Zovo Pro tier'; } });
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', rails: [sp], publicKey: PUB, now: () => NOW });
  await pro.ready;
  await pro.unlock('github-sponsors');
  assert.deepEqual(buttons, ['Open the Zovo Pro tier', 'Pay with PayPal']);
  assert.deepEqual(f.log.opened, ['https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878']);
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick();
  assert.match(f.log.info.at(-1), /^Back from GitHub Sponsors\?/);
});

test('CONV2 no GitHub sign-in in this editor: offers PayPal and the license key', async () => {
  const sp = fakeSponsors({ pro: false, reason: 'no-session', message: 'No GitHub sign-in. Nothing changed.' });
  let buttons;
  const f = fakeVscode({ warn: (msg, rest) => { buttons = rest; return 'Enter a license key'; }, input: sign(base) });
  const keyOnly = lic.createKeyRail({ ...f, sku: 'hex-pro', publicKey: PUB, now: () => NOW });
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', rails: [sp, keyOnly], publicKey: PUB, now: () => NOW });
  await pro.ready;
  const r = await pro.unlock('github-sponsors');
  assert.match(f.log.warn[0], /No GitHub sign-in\. Nothing changed\. You can also pay with PayPal/);
  assert.deepEqual(buttons, ['Pay with PayPal', 'Enter a license key']);
  assert.equal(r.pro, true);
  assert.equal(pro.isPro(), true);
});

test('CONV2 no network and no message on activation', async () => {
  const f = fakeVscode();
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', commandPrefix: 'hexViewer', publicKey: PUB, now: () => NOW });
  await pro.ready;
  f.log.win && f.log.win({ focused: false }); f.log.win && f.log.win({ focused: true }); await tick();
  assert.equal(f.log.info.length + f.log.warn.length + f.log.opened.length, 0);
});

test('CONV2 sequence: PayPal return message, then Get Pro arms the Sponsors return message again', async () => {
  const sp = fakeSponsors({ pro: false, reason: 'not-sponsor', message: 'no' });
  const f = fakeVscode({ info: (msg, rest) => (rest[0] && rest[0].modal ? 'Pay USD 19 on PayPal' : msg.startsWith('Back from PayPal') ? 'Send the transaction ID' : msg.startsWith('Back from GitHub') ? 'Not yet' : undefined) });
  const keyOnly = lic.createKeyRail({ ...f, sku: 'hex-pro', publicKey: PUB, now: () => NOW });
  const pro = createLicense({ ...f, sku: 'hex-pro', name: 'Zovo', rails: [sp, keyOnly], commandPrefix: 'hexViewer', publicKey: PUB, now: () => NOW });
  await pro.ready;
  await f.log.commands['hexViewer.payWithPayPal']();
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick(); await tick();
  assert.match(f.log.info.at(-1), /^Back from PayPal\?/);
  await f.log.commands['hexViewer.getPro']();
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick(); await tick();
  assert.match(f.log.info.at(-1), /^Back from GitHub Sponsors\?/);
});

// ---- CARD1 (10 Nov): the Stripe card rail through the license Worker (funding.json card_buy_url) ----
const CARD = 'https://license.zovo.one/buy/zovo-pro';
const panelOf = (f, pickModal, more = {}) => fakeVscode({ info: (msg, rest) => { if (rest[0] && rest[0].modal) { f.buttons = rest.slice(1); return pickModal; } return more.info ? more.info(msg, rest) : undefined; }, ...more.answers });
function withClipboard(f, text) { f.vscode.env.clipboard = { readText: async () => { f.log.clipReads = (f.log.clipReads || 0) + 1; return text; } }; return f; }

test('CARD1 panel order with card_buy_url: Pay by card (USD 19), GitHub Sponsors, PayPal, Enter a key', async () => {
  const box = {};
  const f = panelOf(box, undefined);
  const pro = mk(f, { cardBuyUrl: CARD, commandPrefix: 'hexViewer' });
  await pro.ready;
  assert.equal(pro.cardBuyUrl, CARD);
  assert.deepEqual(pro.buttons(), ['Pay by card (USD 19)', 'Get Zovo Pro with GitHub Sponsors', 'Pay with PayPal', 'Enter a key']);
  assert.equal(await pro.requirePro('Checksums', { triesUsed: 3 }), false);
  assert.deepEqual(box.buttons, ['Pay by card (USD 19)', 'Get Zovo Pro with GitHub Sponsors', 'Pay with PayPal', 'Enter a key']);
  assert.ok('hexViewer.payByCard' in f.log.commands);
  assert.equal(f.log.opened.length, 0); // nothing opens until a click
  // no PayPal link: the PayPal button goes, the rest keep their order
  const np = mk(fakeVscode(), { cardBuyUrl: CARD, paypalUrl: '' });
  assert.deepEqual(np.buttons(), ['Pay by card (USD 19)', 'Get Zovo Pro with GitHub Sponsors', 'Enter a key']);
  // empty or foreign card_buy_url: the EXEC14 panel, no card command
  for (const u of ['', 'https://evil.example/buy/zovo-pro', 'http://license.zovo.one/buy/zovo-pro', 'https://license.zovo.one/claim?x=1']) {
    const g = fakeVscode();
    const p = mk(g, { cardBuyUrl: u, commandPrefix: 'hexViewer' });
    assert.deepEqual(p.buttons(), ['Get Zovo Pro, USD 19', 'Pay with PayPal', 'I already paid'], u);
    assert.ok(!('hexViewer.payByCard' in g.log.commands), u);
  }
});

test('CARD1 Pay by card opens card_buy_url with the stable random install id; arms the return message', async () => {
  const box = {};
  const f = panelOf(box, 'Pay by card (USD 19)');
  const pro = mk(f, { cardBuyUrl: CARD, commandPrefix: 'hexViewer' });
  await pro.ready;
  assert.equal(await pro.requirePro('Checksums'), false);
  assert.match(f.log.opened[0], /^https:\/\/license\.zovo\.one\/buy\/zovo-pro\?client_reference_id=[0-9a-f-]{36}$/);
  await f.log.commands['hexViewer.payByCard']();
  assert.equal(f.log.opened[1], f.log.opened[0], 'same install id on every click');
  assert.equal(f.global.size, 1); // only the random install id is stored
  // the other buttons
  const s = panelOf({}, 'Get Zovo Pro with GitHub Sponsors');
  await mk(s, { cardBuyUrl: CARD }).requirePro('Checksums');
  assert.deepEqual(s.log.opened, ['https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878']);
  const pp = panelOf({}, 'Pay with PayPal');
  await mk(pp, { cardBuyUrl: CARD }).requirePro('Checksums');
  assert.equal(pp.log.info.at(-1), 'Pay for Zovo Pro with PayPal'); // the PayPal steps modal
  // a Stripe Payment Link straight in card_buy_url works too
  const sl = fakeVscode();
  await mk(sl, { cardBuyUrl: 'https://buy.stripe.com/test_eVq3cw2oagsgeklaYZ43S0Q' }).payByCard();
  assert.match(sl.log.opened[0], /^https:\/\/buy\.stripe\.com\/test_eVq3cw2oagsgeklaYZ43S0Q\?client_reference_id=/);
});

test('CARD1 Enter a key: a ZOVO1 key on the clipboard turns Pro on at once (offline), read only after the click', async () => {
  const key = sign({ ...base, sku: 'zovo-pro' });
  const box = {};
  const f = withClipboard(panelOf(box, 'Enter a key'), `  ${key}\n`);
  const pro = mk(f, { cardBuyUrl: CARD, commandPrefix: 'hexViewer' });
  await pro.ready;
  assert.equal(f.log.clipReads || 0, 0, 'no clipboard read at activation');
  assert.equal(pro.isPro('hex-pro'), false);
  assert.equal(await pro.requirePro('Checksums'), true);
  assert.equal(f.log.clipReads, 1);
  assert.equal(f.log.input.length, 0, 'no input box: the key was valid');
  assert.equal(pro.isPro('hex-pro'), true);
  assert.equal(pro.isPro('docx-pro'), true);
  assert.equal(f.secrets.get(lic.SECRET_KEY), key);
  assert.match(f.log.info.at(-1), /^Zovo Pro is on\. Thank you/);
  assert.equal(f.log.opened.length, 0);
});

test('CARD1 Enter a key: damaged key on the clipboard opens the input box with it; no key there opens the pick, key first', async () => {
  const key = sign({ ...base, sku: 'zovo-pro' });
  const bad = key.slice(0, -4) + 'AAAA';
  const f = withClipboard(fakeVscode({ input: key }), bad);
  const pro = mk(f, { cardBuyUrl: CARD });
  await pro.ready;
  const r = await pro.enterKey();
  assert.equal(f.log.input[0].value, bad);
  assert.equal(r.pro, true);
  // clipboard holds something else: the quick pick, the license key first, then Sponsors and PayPal without a key
  const g = withClipboard(fakeVscode({ pick: 'Enter a license key', input: key }), 'some text the user copied');
  const p2 = mk(g, { cardBuyUrl: CARD });
  await p2.ready;
  assert.equal((await p2.enterKey()).pro, true);
  assert.deepEqual(g.log.picks[0], ['Enter a license key', 'Unlock with GitHub Sponsors', 'I paid with PayPal and have no key yet']);
  assert.equal(g.log.input[0].value, '', 'other clipboard text is never put in the box');
  // no clipboard API (old or web editor): the pick
  const h = fakeVscode({ pick: undefined });
  const p3 = mk(h, { cardBuyUrl: CARD });
  await p3.ready;
  assert.equal((await p3.enterKey()).pro, false);
  assert.equal(h.log.picks.length, 1);
});

test('CARD1 back from the card checkout: one message, "Enter a key" runs the key path; silent when Pro already', async () => {
  const key = sign({ ...base, sku: 'zovo-pro' });
  const f = withClipboard(fakeVscode({ info: (msg) => (msg.startsWith('Back from the checkout?') ? 'Enter a key' : undefined) }), key);
  const pro = mk(f, { cardBuyUrl: CARD });
  await pro.ready;
  await pro.payByCard();
  assert.equal(f.log.clipReads || 0, 0);
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick(); await tick(); await tick();
  assert.match(f.log.info[0], /^Back from the checkout\? Click "Copy key" on the license page, then "Enter a key" here/);
  assert.equal(pro.isPro('hex-pro'), true);
  f.log.win({ focused: false }); f.log.win({ focused: true }); await tick();
  assert.equal(f.log.info.filter((m) => m.startsWith('Back from')).length, 1, 'never twice');
});

test('CARD1 free path: no network, no clipboard read, no message on activation with the card rail on', async () => {
  const f = withClipboard(fakeVscode(), 'ZOVO1.x.y');
  const pro = mk(f, { cardBuyUrl: CARD, commandPrefix: 'hexViewer' });
  await pro.ready;
  f.log.win && f.log.win({ focused: false }); f.log.win && f.log.win({ focused: true }); await tick();
  assert.equal(f.log.info.length + f.log.warn.length + f.log.opened.length + (f.log.clipReads || 0), 0);
  assert.equal(pro.isPro('hex-pro'), false);
});

test('CARD1 the Worker key (Stripe test mode) passes the same check the extension runs', async () => {
  // A key from license-test.zovo.one is signed with the TEST pair: valid only with that public key and allowTest.
  const file = path.join(__dirname, '..', '..', 'pay', 'public-key-test.txt');
  if (!fs.existsSync(file)) return; // inside an extension repo: the factory file is not there
  const TESTPUB = fs.readFileSync(file, 'utf8').trim();
  assert.notEqual(TESTPUB, lic.PUBLIC_KEY_SPKI_B64, 'test and live pairs differ');
});
