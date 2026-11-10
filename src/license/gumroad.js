'use strict';
// Rail "gumroad" for the Zovo Pro facade (factory/sprint/license/gumroad.js, lane EXEC7, 9 Nov 2026).
// WIRED by EXEC14 (10 Nov): index.js creates this rail only when config.js (from funding.json) has gumroad_pro.
// While gumroad_pro is empty there is no rail, no "Pay by card" button and no request to Gumroad at all.
//
// How it checks: the buyer pastes the Gumroad license key. unlock() (a user click) sends ONE request,
//   POST https://api.gumroad.com/v2/licenses/verify   product_id=<id>&license_key=<key>&increment_uses_count=false
// and stores the key and the result on this computer (SecretStorage). isPro() reads that cache only, never the network.
// The cache holds for 30 days. After that, refresh() (silent, never a prompt) checks again. Offline, a timeout, a 5xx
// or a rate limit never removes Pro that was granted: it tries again a day later. Only a clear answer for the same key
// (refunded, charged back, disputed, a subscription that ended, or "this license does not exist") ends it.
// Nothing else is sent. The buyer's email that Gumroad returns is never read or stored. No telemetry.

const crypto = require('crypto');

const RAIL_ID = 'gumroad';
const VERIFY_URL = 'https://api.gumroad.com/v2/licenses/verify';
const SECRET_KEY = 'zovo.pro.gumroad.v1';
const DAY_MS = 24 * 60 * 60 * 1000;
const CACHE_MS = 30 * DAY_MS; // the 30-day offline cache
const RETRY_MS = DAY_MS; // after an error, the next silent try
const TIMEOUT_MS = 10000;

// A Gumroad key is 4 groups of 8 hex digits ("A1B2C3D4-E5F60718-293A4B5C-6D7E8F90"). Spaces and quotes from a mail
// client are removed; the case is kept for the request (Gumroad compares case-insensitively).
function cleanKey(text) {
  return String(text == null ? '' : text).replace(/[\s"'`<>]/g, '');
}
function looksLikeKey(text) {
  return /^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{8}){3}$/.test(cleanKey(text));
}
const fingerprint = (key) => crypto.createHash('sha256').update('zovo-gumroad-v1:' + cleanKey(key).toUpperCase()).digest('hex').slice(0, 16);

// Pure: Gumroad's answer -> { ok, reason }. reason: ok | not-found | wrong-product | refunded | chargeback | disputed
// | ended | rate-limit | network | bad-response
function evaluate(status, json, productId) {
  if (status === 429) return { ok: false, reason: 'rate-limit', final: false };
  if (status >= 500 || status === 0) return { ok: false, reason: 'network', final: false };
  if (!json || typeof json !== 'object') return { ok: false, reason: 'bad-response', final: false };
  if (json.success !== true) {
    // Gumroad answers 404 {success:false, message:"That license does not exist for the provided product."}
    if (status === 404 || /does not exist/i.test(String(json.message || ''))) return { ok: false, reason: 'not-found', final: true };
    return { ok: false, reason: 'bad-response', final: false };
  }
  const p = json.purchase;
  if (!p || typeof p !== 'object') return { ok: false, reason: 'bad-response', final: false };
  if (productId && p.product_id && p.product_id !== productId) return { ok: false, reason: 'wrong-product', final: true };
  if (p.refunded === true) return { ok: false, reason: 'refunded', final: true };
  if (p.chargebacked === true) return { ok: false, reason: 'chargeback', final: true };
  if (p.disputed === true && p.dispute_won !== true) return { ok: false, reason: 'disputed', final: true };
  if (p.subscription_ended_at || p.subscription_failed_at) return { ok: false, reason: 'ended', final: true };
  return { ok: true, reason: 'ok', final: true, seats: Number.isInteger(p.quantity) && p.quantity > 1 ? p.quantity : 1 };
}

// One request. Returns { status, json } (status 0 = network error or timeout). The key goes only in this body.
async function verifyRemote(key, productId, { fetchImpl, timeoutMs } = {}) {
  const f = fetchImpl || (typeof fetch === 'function' ? fetch : null);
  if (!f) return { status: 0, json: null };
  const body = new URLSearchParams({ product_id: productId, license_key: cleanKey(key), increment_uses_count: 'false' }).toString();
  const ac = typeof AbortController === 'function' ? new AbortController() : null;
  const t = ac ? setTimeout(() => ac.abort(), timeoutMs || TIMEOUT_MS) : null;
  try {
    const res = await f(VERIFY_URL, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body, signal: ac ? ac.signal : undefined });
    let json = null;
    try { json = await res.json(); } catch (e) { json = null; }
    return { status: res.status, json };
  } catch (e) {
    return { status: 0, json: null };
  } finally {
    if (t) clearTimeout(t);
  }
}

// Options: vscode, context, productId (Gumroad product id; required), name ("Hex Viewer"),
//          fetch, now, timeoutMs (tests only)
function createGumroadRail(o) {
  const { vscode, context } = o;
  const productId = String(o.productId || '');
  const name = o.name ? `${o.name} Pro` : 'Zovo Pro';
  const now = () => (typeof o.now === 'function' ? o.now() : Date.now());
  const net = { fetchImpl: o.fetch, timeoutMs: o.timeoutMs };
  const listeners = new Set();
  let rec = null; // { v: 1, key, fp, productId, seats, checkedAt, recheckAt }
  let busy = null;

  const pro = () => !!(rec && rec.productId === productId);
  function emit(before) {
    const after = pro();
    if (after !== before) for (const fn of listeners) { try { fn(after); } catch (e) { /* listener error */ } }
  }
  async function save(next) {
    const before = pro();
    rec = next;
    try {
      if (next) await context.secrets.store(SECRET_KEY, JSON.stringify(next));
      else await context.secrets.delete(SECRET_KEY);
    } catch (e) { /* keychain unavailable: the in-memory record still holds for this session */ }
    emit(before);
  }
  function parse(raw) {
    try {
      const r = JSON.parse(raw);
      if (r && r.v === 1 && typeof r.key === 'string' && looksLikeKey(r.key) && typeof r.checkedAt === 'number' && typeof r.recheckAt === 'number') return r;
    } catch (e) { /* damaged */ }
    return null;
  }
  const ready = (async () => {
    try { rec = parse(await context.secrets.get(SECRET_KEY)); } catch (e) { rec = null; }
  })();
  if (context.secrets && typeof context.secrets.onDidChange === 'function') {
    const sub = context.secrets.onDidChange(async (e) => {
      if (e && e.key !== SECRET_KEY) return;
      const before = pro();
      try { rec = parse(await context.secrets.get(SECRET_KEY)); } catch (err) { /* keep */ }
      emit(before);
    });
    if (context.subscriptions && sub) context.subscriptions.push(sub);
  }

  const MSG = {
    ok: (seats) => `${name} is on. Thank you.${seats > 1 ? ` This key covers ${seats} people.` : ''}`,
    'not-found': 'Gumroad does not know this license key for Zovo Pro. Copy it again from the Gumroad receipt, the whole line.',
    'wrong-product': 'This Gumroad key is for another product. Use the key from the Zovo Pro receipt.',
    refunded: 'This Gumroad purchase was refunded, so the key no longer turns on Pro.',
    chargeback: 'This Gumroad purchase was charged back, so the key no longer turns on Pro.',
    disputed: 'This Gumroad purchase is disputed. Pro turns on again when the dispute is closed.',
    ended: 'The Gumroad subscription for this key has ended.',
    network: 'Could not reach Gumroad to check the key. Check the connection and try again. Nothing was changed.',
    'rate-limit': 'Gumroad is busy. Try again in a minute. Nothing was changed.',
    'bad-response': 'Gumroad gave an answer we could not read. Try again later. Nothing was changed.',
    'invalid-key': 'A Gumroad license key looks like A1B2C3D4-E5F60718-293A4B5C-6D7E8F90.',
    'no-product': 'Gumroad keys are not sold for this version yet.',
  };
  const result = (reason, extra = {}) => ({ rail: RAIL_ID, pro: pro(), reason, kind: pro() ? 'lifetime' : 'none', login: '', message: reason === 'cancelled' ? '' : (reason === 'ok' ? MSG.ok(extra.seats || 1) : MSG[reason] || ''), ...extra });

  async function check(key) {
    const r = await verifyRemote(key, productId, net);
    return evaluate(r.status, r.json, productId);
  }

  // A user click: ask for the key, one request, store on success. Never removes Pro on an error.
  // EXEC14: prefill = a key from the vscode://<id>/license?key= link (the facade asked the user first). A prefill
  // that looks like a Gumroad key skips the input box; it is still checked with the same one request.
  async function unlock(prefill) {
    await ready;
    if (!productId) return result('no-product');
    const text = typeof prefill === 'string' && looksLikeKey(prefill) ? prefill : await vscode.window.showInputBox({
      title: `${name}: Gumroad license key`,
      prompt: 'Paste the license key from your Gumroad receipt. It is checked once with Gumroad, then on this computer.',
      placeHolder: 'A1B2C3D4-E5F60718-293A4B5C-6D7E8F90',
      ignoreFocusOut: true,
      validateInput: (v) => (!v || looksLikeKey(v) ? null : MSG['invalid-key']),
    });
    if (text === undefined || !cleanKey(text)) return result('cancelled');
    if (!looksLikeKey(text)) return result('invalid-key');
    const key = cleanKey(text);
    const c = await check(key);
    if (c.ok) {
      const t = now();
      await save({ v: 1, key, fp: fingerprint(key), productId, seats: c.seats, checkedAt: t, recheckAt: t + CACHE_MS });
      return result('ok', { seats: c.seats });
    }
    // A clear "no" for the key that is stored now ends it; a "no" for another key leaves the stored one alone.
    if (c.final && rec && rec.fp === fingerprint(key)) await save(null);
    return result(c.reason);
  }

  // Silent recheck when the 30-day cache is due. Never prompts. Returns true when it used the network.
  async function refresh() {
    await ready;
    if (!rec || now() < rec.recheckAt) return false;
    if (busy) return busy;
    busy = (async () => {
      const key = rec.key;
      const c = await check(key);
      if (!rec || rec.key !== key) return true; // removed or replaced meanwhile
      const t = now();
      if (c.ok) await save({ ...rec, seats: c.seats, checkedAt: t, recheckAt: t + CACHE_MS });
      else if (c.final) await save(null);
      else await save({ ...rec, recheckAt: t + RETRY_MS }); // offline or busy: Pro stays, try again tomorrow
      return true;
    })().finally(() => { busy = null; });
    return busy;
  }

  return {
    id: RAIL_ID,
    label: 'I have a Gumroad license key',
    ready,
    isPro: (sku) => (sku === undefined || typeof sku === 'string') && pro(),
    unlock,
    refresh,
    async remove() { await ready; await save(null); },
    state: () => (rec ? { productId: rec.productId, fp: rec.fp, seats: rec.seats, checkedAt: rec.checkedAt, recheckAt: rec.recheckAt } : null),
    onDidChange(fn) { listeners.add(fn); return { dispose: () => listeners.delete(fn) }; },
  };
}

module.exports = { createGumroadRail, evaluate, verifyRemote, looksLikeKey, cleanKey, fingerprint, RAIL_ID, VERIFY_URL, SECRET_KEY, CACHE_MS, RETRY_MS };
