'use strict';
// Tests for the Gumroad rail (wired by EXEC14 behind funding.json gumroad_pro). No network: fetch is mocked. Run: node --test test/gumroad.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const g = require(fs.existsSync(path.join(__dirname, '..', 'gumroad.js')) ? '../gumroad.js' : '../src/license/gumroad.js');

const PID = 'zovoPro123==';
const KEY = 'A1B2C3D4-E5F60718-293A4B5C-6D7E8F90';
const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.UTC(2026, 10, 10);

function purchase(extra = {}) {
  return { success: true, uses: 1, purchase: { product_id: PID, product_name: 'Zovo Pro', email: 'buyer@example.com', refunded: false, chargebacked: false, disputed: false, quantity: 1, license_key: KEY, ...extra } };
}
function fakeFetch(answers) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    const a = typeof answers === 'function' ? answers(calls.length) : answers;
    if (a === 'throw') throw new Error('offline');
    return { status: a.status, json: async () => a.json };
  };
  fn.calls = calls;
  return fn;
}
function fakeVscode(input) {
  const secrets = new Map();
  const global = new Map();
  const log = { input: [] };
  const vscode = { window: { showInputBox: async (o) => { log.input.push(o); return input; } } };
  const context = {
    subscriptions: [],
    secrets: { get: async (k) => secrets.get(k), store: async (k, v) => { secrets.set(k, v); }, delete: async (k) => { secrets.delete(k); }, onDidChange: () => ({ dispose() {} }) },
    globalState: { get: (k) => global.get(k), update: async (k, v) => { global.set(k, v); } },
  };
  return { vscode, context, secrets, global, log };
}
const mk = (f, fetch, extra = {}) => { let t = T0; const r = g.createGumroadRail({ vscode: f.vscode, context: f.context, productId: PID, name: 'Hex Viewer', fetch, now: () => t, ...extra }); r.setNow = (x) => { t = x; }; return r; };

test('evaluate: a good purchase, team quantity, refund, chargeback, dispute, ended, wrong product, unknown key', () => {
  assert.deepEqual(g.evaluate(200, purchase(), PID), { ok: true, reason: 'ok', final: true, seats: 1 });
  assert.equal(g.evaluate(200, purchase({ quantity: 5 }), PID).seats, 5);
  assert.equal(g.evaluate(200, purchase({ refunded: true }), PID).reason, 'refunded');
  assert.equal(g.evaluate(200, purchase({ chargebacked: true }), PID).reason, 'chargeback');
  assert.equal(g.evaluate(200, purchase({ disputed: true }), PID).reason, 'disputed');
  assert.equal(g.evaluate(200, purchase({ disputed: true, dispute_won: true }), PID).ok, true);
  assert.equal(g.evaluate(200, purchase({ subscription_ended_at: '2026-11-01T00:00:00Z' }), PID).reason, 'ended');
  assert.equal(g.evaluate(200, purchase({ product_id: 'other' }), PID).reason, 'wrong-product');
  assert.deepEqual(g.evaluate(404, { success: false, message: 'That license does not exist for the provided product.' }, PID), { ok: false, reason: 'not-found', final: true });
});

test('evaluate: errors are never final (offline, 5xx, 429, junk)', () => {
  for (const [s, j, why] of [[0, null, 'network'], [502, null, 'network'], [429, {}, 'rate-limit'], [200, null, 'bad-response'], [200, { success: true }, 'bad-response']]) {
    const r = g.evaluate(s, j, PID);
    assert.equal(r.ok, false); assert.equal(r.final, false); assert.equal(r.reason, why);
  }
});

test('key format: 4 groups of 8 hex digits, spaces and quotes removed', () => {
  assert.equal(g.looksLikeKey(KEY), true);
  assert.equal(g.looksLikeKey(` "${KEY.toLowerCase()}"\n`), true);
  assert.equal(g.looksLikeKey('ZOVO1.abc.def'), false);
  assert.equal(g.looksLikeKey('A1B2C3D4-E5F60718-293A4B5C'), false);
});

test('unlock: one POST to the verify endpoint with product_id, the key and increment_uses_count=false; Pro is cached', async () => {
  const f = fakeVscode(KEY);
  const fetch = fakeFetch({ status: 200, json: purchase() });
  const r = mk(f, fetch);
  await r.ready;
  assert.equal(r.isPro('hex-pro'), false);
  const u = await r.unlock();
  assert.equal(u.pro, true); assert.equal(u.reason, 'ok'); assert.equal(u.rail, 'gumroad');
  assert.match(u.message, /Hex Viewer Pro is on/);
  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0].url, 'https://api.gumroad.com/v2/licenses/verify');
  assert.equal(fetch.calls[0].init.method, 'POST');
  const body = new URLSearchParams(fetch.calls[0].init.body);
  assert.equal(body.get('product_id'), PID); assert.equal(body.get('license_key'), KEY); assert.equal(body.get('increment_uses_count'), 'false');
  assert.deepEqual([...body.keys()].sort(), ['increment_uses_count', 'license_key', 'product_id']);
  assert.equal(r.isPro('hex-pro'), true);
  assert.equal(r.isPro('docx-pro'), true, 'one Zovo Pro for every viewer');
  assert.equal(fetch.calls.length, 1, 'isPro never uses the network');
});

test('the stored record has no email and lives only in SecretStorage; a restart reads it with no network', async () => {
  const f = fakeVscode(KEY);
  const r = mk(f, fakeFetch({ status: 200, json: purchase() }));
  await r.ready; await r.unlock();
  const raw = f.secrets.get(g.SECRET_KEY);
  assert.ok(raw); assert.doesNotMatch(raw, /buyer@example\.com|email/);
  assert.equal(f.global.size, 0);
  const fetch2 = fakeFetch('throw');
  const r2 = mk(f, fetch2);
  await r2.ready;
  assert.equal(r2.isPro(), true);
  assert.equal(fetch2.calls.length, 0);
  assert.equal(r2.state().seats, 1); assert.equal('key' in r2.state(), false, 'state() has no secret');
});

test('unlock: wrong key, refund and network error give no Pro and a clear message', async () => {
  for (const [ans, reason] of [[{ status: 404, json: { success: false, message: 'That license does not exist for the provided product.' } }, 'not-found'], [{ status: 200, json: purchase({ refunded: true }) }, 'refunded'], ['throw', 'network'], [{ status: 429, json: {} }, 'rate-limit']]) {
    const f = fakeVscode(KEY);
    const r = mk(f, fakeFetch(ans));
    await r.ready;
    const u = await r.unlock();
    assert.equal(u.pro, false); assert.equal(u.reason, reason); assert.ok(u.message.length > 10);
    assert.equal(r.isPro(), false);
  }
});

test('unlock: cancelled input and a malformed key make no request', async () => {
  const fetch = fakeFetch({ status: 200, json: purchase() });
  const a = mk(fakeVscode(undefined), fetch); await a.ready;
  assert.equal((await a.unlock()).reason, 'cancelled');
  const b = mk(fakeVscode('not a key'), fetch); await b.ready;
  assert.equal((await b.unlock()).reason, 'invalid-key');
  assert.equal(fetch.calls.length, 0);
  const f = fakeVscode(KEY);
  const c = mk(f, fetch, { productId: '' }); await c.ready;
  assert.equal((await c.unlock()).reason, 'no-product');
  assert.equal(f.log.input.length, 0);
});

test('an error at unlock never removes Pro that was granted', async () => {
  const f = fakeVscode(KEY);
  const r = mk(f, fakeFetch((n) => (n === 1 ? { status: 200, json: purchase() } : 'throw')));
  await r.ready; await r.unlock();
  const u = await r.unlock();
  assert.equal(u.reason, 'network'); assert.equal(u.pro, true); assert.equal(r.isPro(), true);
});

test('30-day cache: refresh does nothing before day 30, rechecks after, and keeps Pro offline (retry in a day)', async () => {
  const f = fakeVscode(KEY);
  let mode = 'ok';
  const fetch = fakeFetch(() => (mode === 'ok' ? { status: 200, json: purchase() } : mode === 'down' ? { status: 503, json: null } : { status: 200, json: purchase({ refunded: true }) }));
  const r = mk(f, fetch);
  await r.ready; await r.unlock();
  r.setNow(T0 + 29 * DAY);
  assert.equal(await r.refresh(), false); assert.equal(fetch.calls.length, 1);
  r.setNow(T0 + 30 * DAY + 1);
  mode = 'down';
  assert.equal(await r.refresh(), true); assert.equal(r.isPro(), true, 'offline: Pro stays');
  assert.equal(r.state().recheckAt, T0 + 31 * DAY + 1, 'next try in a day');
  assert.equal(await r.refresh(), false, 'not again the same day');
  r.setNow(T0 + 31 * DAY + 2);
  mode = 'ok';
  assert.equal(await r.refresh(), true); assert.equal(r.state().recheckAt, T0 + 61 * DAY + 2);
  r.setNow(T0 + 62 * DAY);
  mode = 'refund';
  let seen = null; r.onDidChange((p) => { seen = p; });
  assert.equal(await r.refresh(), true);
  assert.equal(r.isPro(), false, 'a clear refund ends it'); assert.equal(seen, false);
  assert.equal(f.secrets.has(g.SECRET_KEY), false);
});

test('remove clears the key; a damaged record is ignored', async () => {
  const f = fakeVscode(KEY);
  const r = mk(f, fakeFetch({ status: 200, json: purchase() }));
  await r.ready; await r.unlock();
  await r.remove();
  assert.equal(r.isPro(), false); assert.equal(f.secrets.has(g.SECRET_KEY), false);
  f.secrets.set(g.SECRET_KEY, '{"v":1,"key":"junk"}');
  const r2 = mk(f, fakeFetch('throw')); await r2.ready;
  assert.equal(r2.isPro(), false);
});

test('a slow Gumroad times out as a network error (no Pro, no hang)', async () => {
  const f = fakeVscode(KEY);
  const slow = (url, init) => new Promise((res, rej) => { init.signal.addEventListener('abort', () => rej(new Error('aborted'))); });
  const r = mk(f, slow, { timeoutMs: 50 });
  await r.ready;
  const u = await r.unlock();
  assert.equal(u.reason, 'network'); assert.equal(r.isPro(), false);
});

test('wired only behind gumroad_pro (EXEC14): index.js loads gumroad.js only when the id is set; gumroad.js talks only to api.gumroad.com', () => {
  const dir = fs.existsSync(path.join(__dirname, '..', 'gumroad.js')) ? path.join(__dirname, '..') : path.join(__dirname, '..', 'src', 'license');
  const idx = fs.readFileSync(path.join(dir, 'index.js'), 'utf8');
  assert.match(idx, /if \(gumroadPro\) \{[\s\S]{0,200}require\('\.\/gumroad'\)/);
  assert.equal((idx.match(/require\('\.\/gumroad'\)/g) || []).length, 1);
  const src = fs.readFileSync(path.join(dir, 'gumroad.js'), 'utf8');
  const urls = src.match(/https?:\/\/[^\s'"`)]+/g) || [];
  assert.deepEqual([...new Set(urls)], ['https://api.gumroad.com/v2/licenses/verify']);
});

test('EXEC14 prefill: a Gumroad key from the license link skips the input box, one request', async () => {
  const f = fakeFetch({ status: 200, json: purchase() });
  const v = fakeVscode(undefined);
  const r = g.createGumroadRail({ vscode: v.vscode, context: v.context, productId: PID, fetch: f, now: () => T0 });
  const out = await r.unlock(KEY);
  assert.equal(out.pro, true);
  assert.equal(v.log.input.length, 0);
  assert.equal(f.calls.length, 1);
});
