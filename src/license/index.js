'use strict';
// Zovo Pro facade (factory/sprint/license/index.js, lane PAY1). Copy this folder's index.js, license.js, sponsors.js,
// gumroad.js and the generated config.js to src/license/ in an extension, unchanged (apply.sh does it). Contract and
// rails: API.md.
//
// One object for the extension: isPro(sku) is true when ANY rail says so (GitHub Sponsors, offline license key, the
// shared ~/.zovo/pro.json, later Gumroad). isPro reads local caches only: no network at activation, on file open or
// in isPro. Network happens only after a user click: a rail's unlock() (GitHub sign-in + one GraphQL call for
// Sponsors; the key rail never uses the network) and the buy buttons, which open a page in the browser. No telemetry.
//
//   const { createLicense } = require('./license');
//   const pro = createLicense({ vscode, context, sku: 'pdf-pro', name: 'Zovo', product: 'PDF Viewer',
//                               commandPrefix: 'pdfViewer', proTools: ['Page tools', 'Merge PDFs'] });
//   await pro.ready;
//   pro.isPro('pdf-pro');                                                      // sync
//   if (await pro.requirePro('Merge PDFs', { detail: '...', triesUsed: 3 })) runIt();
//
// Commands (registered when commandPrefix is set; package.json titles from PALETTE, category "Zovo Pro"):
//   <prefix>.getPro              "Get Zovo Pro (USD 19 once, all 22 Zovo extensions)"
//   <prefix>.payWithPayPal       "Pay for Zovo Pro with PayPal (USD 19, team of 5 USD 59)"
//   <prefix>.unlockWithSponsors  "I already paid: unlock with GitHub Sponsors"
//   <prefix>.enterLicenseKey     "Enter Zovo Pro license key"
//   <prefix>.removeLicense       "Remove Zovo Pro from this editor"
//   <prefix>.payByCard           only when funding.json card_buy_url is set, or gumroad_pro and gumroad_pro_url
//                                (palette.js then adds "Pay for Zovo Pro by card (USD 19)" to package.json)
//
// History: CONV2 (9 Nov) back-from-browser message and PayPal steps. EXEC7 (9 Nov, owner decision 22:16) GitHub
// Sponsors first, PayPal second.
//
// EXEC14 (10 Nov, buy path v2, CONV3 fixes 1, 4, 6, 7, XSELL2 move 1, MONEY5 #1):
// - The Pro panel: "<Feature> is part of Zovo Pro." with the tries, the feature, the other Pro tools of this extension,
//   the count of Zovo extensions with Pro, and 4 buttons: [Get Zovo Pro, USD 19] [Pay with PayPal] [I already paid]
//   [Cancel]. "I already paid" is a quick pick: GitHub Sponsors, a license key, or the PayPal transaction id.
//   The refund sentence shows only when funding.json refund_days is set (empty today). No anchor prices here.
// - One unlock for all Zovo extensions on this computer: after any successful unlock the signed ZOVO1 key or the
//   Sponsors result (login, tier, date; never a token) goes to ~/.zovo/pro.json (mode 600). Every Zovo extension reads
//   it at activation and checks it offline (Ed25519 for keys).
// - The panel names the user's other Zovo extensions with Pro (at most 3, then "and N more"), and after an unlock
//   one carry-over offer (once per extension; "Not now" is final). Never at activation, never on the free path, only
//   zovo.* extensions.
// - Gumroad (card checkout): the rail, the "Pay by card" button and the Gumroad key link exist only when
//   funding.json gumroad_pro is set. Empty today: no button and no request to Gumroad.
//
// CARD1 (10 Nov, card checkout without a GitHub account, CONV3: 4 of 6 paid rivals take a card in 1-3 clicks):
// - funding.json card_buy_url (https://license.zovo.one/buy/zovo-pro) turns on the Stripe card rail. The panel is then
//   [Pay by card (USD 19)] [Get Zovo Pro with GitHub Sponsors] [Pay with PayPal] [Enter a key] [Cancel].
//   "Pay by card" opens card_buy_url?client_reference_id=<random install id>. The Worker sends the buyer to the Stripe
//   Payment Link, and after paying the license page shows a ZOVO1 key with a Copy button (or, before the owner
//   switches Stripe live, a page with GitHub Sponsors and PayPal).
// - "Enter a key": after that click only, the clipboard is read once (local); a ZOVO1 key there is checked offline and
//   turns Pro on. Otherwise a quick pick: paste a key, unlock with GitHub Sponsors, or PayPal without a key yet.
// - card_buy_url empty: everything as in EXEC14. Gumroad stays as it is (hidden while gumroad_pro is empty).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createKeyRail, verifyKey, grants, KEY_PREFIX, INSTALL_ID_KEY } = require('./license');

// The Zovo Pro tier ("$19 one time", tier_id 679878) on GitHub Sponsors. Not the generic page: that one opens on the
// Monthly tab and also lists the notemods.com Obsidian tiers, which do not include Zovo Pro.
const SPONSORS_ONE_TIME = 'https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878';
// PayPal: the amount and currency are in the link (the account's main currency is USD; the suffix makes it explicit).
const PAYPAL_ME = 'https://www.paypal.com/paypalme/najzzz';
const PRICE = { one: 19, team: 59, seats: 5 };
// The public issue form where a PayPal buyer sends the transaction id (owner watches it; the key goes by email).
const KEY_REQUEST_URL = 'https://github.com/theluckystrike/zovo-plugin-factory/issues/new?template=zovo-pro-key.yml';
const RETURN_MS = 2 * 60 * 60 * 1000;
const MODULE_VERSION = '2026-11-10.card1';
const BRAND = 'Zovo Pro';
// Zovo VS Code listings with Pro tools (F, XSELL2 gallery read 2026-11-10 05:46). config.js pro_extensions overrides.
const PRO_EXTENSIONS = 22;
const CATEGORY = 'Zovo Pro';
const BUY_LABEL = `Get Zovo Pro, USD ${PRICE.one}`;
const CARD_LABEL = 'Pay by card';
// CARD1: the Stripe card rail (funding.json card_buy_url). Only our license Worker or a Stripe Payment Link.
const CARD_BUY_LABEL = `Pay by card (USD ${PRICE.one})`;
const SPONSORS_BUY_LABEL = 'Get Zovo Pro with GitHub Sponsors';
const ENTER_KEY_LABEL = 'Enter a key';
const CARD_BUY_RE = /^https:\/\/(license(-test)?\.zovo\.one\/buy\/[a-z0-9][a-z0-9-]{1,40}|buy\.stripe\.com\/[A-Za-z0-9_]{4,80})$/;
const PAYPAL_LABEL = 'Pay with PayPal';
const PAID_LABEL = 'I already paid';
const LABELS = {
  'github-sponsors': 'Unlock with GitHub Sponsors',
  'license-key': 'Enter a license key',
  gumroad: 'Enter a Gumroad license key',
  polar: 'Unlock with a Polar key',
};
const PAID_DESC = {
  'github-sponsors': 'you paid on GitHub Sponsors; VS Code asks you to sign in with GitHub',
  'license-key': 'a key that starts with ZOVO1., from the PayPal email or a team purchase',
  gumroad: 'the key from your Gumroad receipt',
};
const NO_KEY_LABEL = 'I paid with PayPal and have no key yet';
const SUPPORT_PRO_LABEL = 'Zovo Pro: USD 19 once, unlocks the Pro tools in all Zovo extensions';
const CARRY_KEY = 'zovo.carryover.asked';
const SHARED_ENV = 'ZOVO_PRO_FILE';
const SHARED_MAX_BYTES = 64 * 1024;

// The 5 palette commands, the same titles in every product (CONV3 fix 6). n = Zovo extensions with Pro.
function paletteCommands(prefix, n = PRO_EXTENSIONS) {
  return [
    { command: `${prefix}.getPro`, title: `Get Zovo Pro (USD ${PRICE.one} once, all ${n} Zovo extensions)`, category: CATEGORY },
    { command: `${prefix}.payWithPayPal`, title: `Pay for Zovo Pro with PayPal (USD ${PRICE.one}, team of ${PRICE.seats} USD ${PRICE.team})`, category: CATEGORY },
    { command: `${prefix}.unlockWithSponsors`, title: 'I already paid: unlock with GitHub Sponsors', category: CATEGORY },
    { command: `${prefix}.enterLicenseKey`, title: 'Enter Zovo Pro license key', category: CATEGORY },
    { command: `${prefix}.removeLicense`, title: 'Remove Zovo Pro from this editor', category: CATEGORY },
  ];
}

function loadConfig() {
  try {
    // eslint-disable-next-line global-require
    const c = require('./config');
    return c && typeof c === 'object' ? c : {};
  } catch (e) {
    return {}; // no config.js: every optional part stays hidden
  }
}
const str = (v) => (typeof v === 'string' ? v.trim() : typeof v === 'number' && Number.isFinite(v) ? String(v) : '');

function defaultSponsorsRail(vscode, context) {
  try {
    // eslint-disable-next-line global-require
    const { createSponsorsRail } = require('./sponsors');
    return createSponsorsRail({ vscode, context });
  } catch (e) {
    return null; // product ships without the Sponsors rail
  }
}

function sponsorsTiers() {
  try {
    // eslint-disable-next-line global-require
    const s = require('./sponsors');
    return { life: s.ZOVO_TIER_IDS, month: s.MONTHLY_TIER_IDS };
  } catch (e) {
    return { life: ['ST_kwDOAwq1PM4ACl_G'], month: [] };
  }
}

// ---- other Zovo extensions on this computer (XSELL2 move 1). Local: vscode.extensions.all, no network. ----
const shortName = (n) => String(n || '').split(' & ')[0].split('(')[0].trim();
function zovoTools(vscode, selfId) {
  let all = [];
  try { all = (vscode && vscode.extensions && vscode.extensions.all) || []; } catch (e) { all = []; }
  const self = String(selfId || '').toLowerCase();
  const out = [];
  const seen = new Set();
  for (const e of all) {
    const id = String((e && e.id) || '').toLowerCase();
    if (!/^zovo\.[a-z0-9][a-z0-9.-]*$/.test(id) || id === self || seen.has(id)) continue;
    seen.add(id);
    const pj = (e && e.packageJSON) || {};
    const cmds = pj.contributes && Array.isArray(pj.contributes.commands) ? pj.contributes.commands : [];
    const c = cmds.find((x) => x && typeof x.command === 'string' && x.command.endsWith('.enterLicenseKey'));
    let proPrefix = c ? c.command.slice(0, -'.enterLicenseKey'.length) : null;
    if (proPrefix && !/^[A-Za-z][\w.-]{0,80}$/.test(proPrefix)) proPrefix = null;
    out.push({ id, name: shortName(pj.displayName || pj.name || id) || id, proPrefix, v2: !!(c && c.category === CATEGORY) });
  }
  return out;
}

// "A", "A and B", "A, B and C", "A, B, C and 2 more"
function namesList(names, max = 3) {
  const n = names.filter(Boolean);
  if (n.length === 0) return '';
  if (n.length === 1) return n[0];
  if (n.length <= max) return `${n.slice(0, -1).join(', ')} and ${n[n.length - 1]}`;
  return `${n.slice(0, max).join(', ')} and ${n.length - max} more`;
}

// ---- ~/.zovo/pro.json: one unlock for all Zovo extensions on this computer (CONV3 fix 7) ----
// { v: 1, key?: "ZOVO1...", sponsors?: { login, tierId, kind: "lifetime"|"monthly", date: "YYYY-MM-DD", until? }, updated }
// Never a token, never an email. The key is checked with Ed25519 on every read; the Sponsors entry counts only for
// the Zovo tiers (lifetime) or a general monthly tier until its date.
function sharedFilePath(o = {}) {
  if (typeof o.sharedFile === 'string') return o.sharedFile; // '' = off
  if (process.env[SHARED_ENV]) return process.env[SHARED_ENV];
  return path.join(os.homedir(), '.zovo', 'pro.json');
}
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
function cleanShared(raw) {
  if (!raw || typeof raw !== 'object' || raw.v !== 1) return null;
  const out = { v: 1 };
  if (typeof raw.key === 'string' && raw.key.startsWith(KEY_PREFIX) && raw.key.length < 4096) out.key = raw.key;
  const s = raw.sponsors;
  if (s && typeof s === 'object' && typeof s.login === 'string' && /^[A-Za-z0-9-]{1,39}$/.test(s.login)
      && typeof s.tierId === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(s.tierId)
      && (s.kind === 'lifetime' || s.kind === 'monthly') && typeof s.date === 'string' && DATE_RE.test(s.date)) {
    out.sponsors = { login: s.login, tierId: s.tierId, kind: s.kind, date: s.date };
    if (s.kind === 'monthly') out.sponsors.until = typeof s.until === 'number' && Number.isFinite(s.until) ? s.until : 0;
  }
  if (typeof raw.updated === 'string' && raw.updated.length < 40) out.updated = raw.updated;
  return out;
}
async function readSharedFile(file) {
  if (!file) return null;
  try {
    const st = await fs.promises.stat(file);
    if (!st.isFile() || st.size > SHARED_MAX_BYTES) return null;
    return cleanShared(JSON.parse(await fs.promises.readFile(file, 'utf8')));
  } catch (e) {
    return null; // missing or damaged: no shared Pro
  }
}
// Merge `patch` (key / sponsors; null removes that part) and write with mode 600 (folder 700), via a temp file.
async function writeSharedFile(file, patch, now = Date.now()) {
  if (!file) return false;
  try {
    const cur = (await readSharedFile(file)) || { v: 1 };
    const next = cleanShared({ ...cur, ...patch, v: 1, updated: new Date(now).toISOString().slice(0, 10) }) || { v: 1 };
    for (const k of Object.keys(patch)) if (patch[k] === null) delete next[k];
    if (!next.key && !next.sponsors) {
      await fs.promises.unlink(file).catch(() => {});
      return true;
    }
    await fs.promises.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    await fs.promises.writeFile(tmp, JSON.stringify(next, null, 1) + '\n', { mode: 0o600, flag: 'wx' });
    await fs.promises.chmod(tmp, 0o600);
    await fs.promises.rename(tmp, file);
    await fs.promises.chmod(file, 0o600);
    return true;
  } catch (e) {
    return false; // read-only home or no space: the unlock in this extension still holds
  }
}

// Hidden rail "zovo-shared": Pro from ~/.zovo/pro.json. No button, no unlock of its own.
function createSharedRail(o) {
  const file = o.file;
  const tiers = sponsorsTiers();
  const listeners = new Set();
  const nowMs = () => (typeof o.now === 'function' ? o.now() : Date.now());
  let rec = null;
  let license = null; // verified key payload, or null
  let mtime = -1;
  const keyAlive = () => !!license && (!license.expires || nowMs() < Date.parse(license.expires + 'T00:00:00Z') + 86400000);
  const sponsorsOk = () => {
    const s = rec && rec.sponsors;
    if (!s) return false;
    if (s.kind === 'lifetime') return tiers.life.includes(s.tierId);
    return tiers.month.includes(s.tierId) && nowMs() < s.until;
  };
  const pro = (sku) => (keyAlive() && grants(license, sku)) || sponsorsOk();
  function set(next) {
    const before = pro(o.sku);
    rec = next;
    license = null;
    if (rec && rec.key) {
      const r = verifyKey(rec.key, { publicKey: o.publicKey, allowTest: o.allowTest, now: nowMs() });
      if (r.ok) license = r.license;
    }
    const after = pro(o.sku);
    if (after !== before) for (const fn of listeners) { try { fn(after); } catch (e) { /* listener error */ } }
  }
  async function reload(force) {
    if (!file) return false;
    let m = 0;
    try { m = (await fs.promises.stat(file)).mtimeMs; } catch (e) { m = 0; }
    if (!force && m === mtime) return false;
    mtime = m;
    set(m ? await readSharedFile(file) : null);
    return true;
  }
  return {
    id: 'zovo-shared',
    hidden: true,
    file,
    ready: reload(true),
    isPro(sku) { return pro(sku || o.sku); },
    reload,
    async write(patch) {
      const ok = await writeSharedFile(file, patch, nowMs());
      await reload(true);
      return ok;
    },
    async unlock() { await reload(true); return { rail: 'zovo-shared', pro: pro(o.sku), reason: pro(o.sku) ? 'ok' : 'cancelled', kind: pro(o.sku) ? 'lifetime' : 'none', login: '', message: '' }; },
    async refresh() { await reload(false); return false; },
    async remove() { await writeSharedFile(file, { key: null, sponsors: null }, nowMs()); await reload(true); },
    state() { return rec ? { key: !!rec.key, keyValid: !!license, sponsors: rec.sponsors ? { ...rec.sponsors } : null } : null; },
    onDidChange(fn) { listeners.add(fn); return { dispose: () => listeners.delete(fn) }; },
  };
}

// Options:
//   vscode, context, sku ("pdf-pro"), name (brand in older messages, usually "Zovo")
//   product        this extension's name for messages and the PayPal form, e.g. "PDF Viewer" (default: name)
//   proTools       the titles of this extension's Pro tools; the panel names the ones other than the current one
//   rails          optional array of rails (API.md). Default: [GitHub Sponsors, license key, Gumroad when configured]
//   paymentUrl     buy page for "Get Zovo Pro". Default: the Zovo Pro tier on GitHub Sponsors. '' = not on sale.
//   commandPrefix  registers the commands above
//   paypalUrl      PayPal.me base link (default PAYPAL_ME). '' = no PayPal option
//   keyRequestUrl  where a PayPal buyer sends the transaction id (default KEY_REQUEST_URL)
//   refundDays, gumroadPro, gumroadUrl, proExtensions   override config.js (funding.json) for tests
//   cardBuyUrl     override config.js card_buy_url ('' = no Stripe card rail)
//   sharedFile     path of the shared file ('' = off). Default ~/.zovo/pro.json (env ZOVO_PRO_FILE overrides).
//                  Off under `node --test` and without context.extension unless set, so product unit tests never
//                  touch the real home folder.
//   selfId         this extension's id (default context.extension.id)
//   publicKey, now, allowTest   passed to the key checks (tests only)
function createLicense(o) {
  const { vscode, context, sku } = o;
  const cfg = loadConfig();
  const pick1 = (opt, key) => (opt !== undefined ? str(opt) : str(cfg[key]));
  const refundDays = pick1(o.refundDays, 'refund_days');
  const gumroadPro = pick1(o.gumroadPro, 'gumroad_pro');
  const gumroadUrl = pick1(o.gumroadUrl, 'gumroad_pro_url');
  const cardBuyRaw = pick1(o.cardBuyUrl, 'card_buy_url');
  const cardBuyUrl = CARD_BUY_RE.test(cardBuyRaw) ? cardBuyRaw : '';
  const proCount = Number(pick1(o.proExtensions, 'pro_extensions')) || PRO_EXTENSIONS;
  const name = o.name || 'Zovo';
  const label = BRAND;
  const product = o.product || (name === 'Zovo' ? 'this extension' : name);
  const selfId = o.selfId || (context && context.extension && context.extension.id) || '';
  const proTools = Array.isArray(o.proTools) ? o.proTools.filter((t) => typeof t === 'string' && t) : [];
  const keyRail = createKeyRail({ vscode, context, sku, name: 'Zovo', publicKey: o.publicKey, now: o.now, allowTest: o.allowTest });
  let gumroadRail = null;
  if (gumroadPro) {
    try {
      // eslint-disable-next-line global-require
      const { createGumroadRail } = require('./gumroad');
      gumroadRail = createGumroadRail({ vscode, context, productId: gumroadPro, name: 'Zovo' });
    } catch (e) { gumroadRail = null; }
  }
  const baseRails = (o.rails || [defaultSponsorsRail(vscode, context), keyRail, gumroadRail]).filter(Boolean);
  // Off for unit tests and fakes unless a test passes sharedFile: under `node --test`, or without context.extension
  // (every real VS Code since 1.55 has it).
  const testRun = o.sharedFile === undefined && !process.env[SHARED_ENV] && (!!process.env.NODE_TEST_CONTEXT || !(context && context.extension));
  const file = testRun ? '' : sharedFilePath(o);
  const sharedRail = file ? createSharedRail({ file, sku, publicKey: o.publicKey, allowTest: o.allowTest, now: o.now }) : null;
  const rails = sharedRail ? [...baseRails, sharedRail] : baseRails;
  const visible = () => rails.filter((r) => !r.hidden);
  const byId = (id) => rails.find((r) => r.id === id);
  const paymentUrl = o.paymentUrl === undefined ? SPONSORS_ONE_TIME : o.paymentUrl;
  const paypalUrl = (o.paypalUrl === undefined ? PAYPAL_ME : o.paypalUrl || '').replace(/\/+$/, '');
  const keyRequestUrl = o.keyRequestUrl === undefined ? KEY_REQUEST_URL : o.keyRequestUrl;
  const cardUrl = gumroadRail && /^https:\/\/[A-Za-z0-9.-]*gumroad\.com\//.test(gumroadUrl) ? gumroadUrl : '';
  const sponsorsRail = () => byId('github-sponsors');
  const onSponsors = () => paymentUrl === SPONSORS_ONE_TIME || /^https:\/\/github\.com\/sponsors\//.test(paymentUrl);
  const listeners = new Set();
  let last = null;

  // EXEC7 order of the unlock ways: GitHub Sponsors, the license key, Gumroad, other rails. CARD1: with the card rail
  // on, the license key comes first (the card buyer has a key from the license page).
  const RAIL_ORDER = cardBuyUrl ? ['license-key', 'github-sponsors', 'gumroad'] : ['github-sponsors', 'license-key', 'gumroad'];
  const railRank = (r) => { const i = RAIL_ORDER.indexOf(r.id); return i < 0 ? RAIL_ORDER.length : i; };
  const CORE = ['github-sponsors', 'license-key', 'gumroad'];
  const railLabel = (r) => (CORE.includes(r.id) ? LABELS[r.id] : r.label || LABELS[r.id] || r.id);
  const sortedRails = () => visible().map((r, i) => ({ r, i })).sort((a, b) => railRank(a.r) - railRank(b.r) || a.i - b.i).map((x) => x.r);
  // The panel buttons in the one Zovo order (EXEC14): Get Zovo Pro, USD 19 / Pay by card (only with Gumroad) /
  // Pay with PayPal / I already paid. VS Code adds Cancel.
  // CARD1, with card_buy_url: Pay by card (USD 19) / Get Zovo Pro with GitHub Sponsors / Pay with PayPal / Enter a key.
  function buttons() {
    const out = [];
    if (cardBuyUrl) {
      out.push(CARD_BUY_LABEL);
      if (paymentUrl) out.push(onSponsors() ? SPONSORS_BUY_LABEL : BUY_LABEL);
      if (paypalUrl) out.push(PAYPAL_LABEL);
      out.push(ENTER_KEY_LABEL);
      return out;
    }
    if (paymentUrl) out.push(BUY_LABEL);
    if (cardUrl) out.push(CARD_LABEL);
    if (paypalUrl) out.push(PAYPAL_LABEL);
    out.push(PAID_LABEL);
    return out;
  }

  const isPro = (s) => rails.some((r) => { try { return r.isPro(s || sku); } catch (e) { return false; } });
  function changed() {
    const now = isPro();
    if (now === last) return;
    last = now;
    for (const fn of listeners) { try { fn(now); } catch (e) { /* listener error */ } }
  }
  for (const r of rails) if (typeof r.onDidChange === 'function') r.onDidChange(changed);

  function installId() {
    let id = context.globalState.get(INSTALL_ID_KEY);
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
      id = crypto.randomUUID();
      context.globalState.update(INSTALL_ID_KEY, id);
    }
    return id;
  }

  const open = (url) => vscode.env.openExternal(vscode.Uri.parse(url, true));
  const info = (...a) => vscode.window.showInformationMessage(...a);

  // Opens the buy page (the Zovo Pro tier on GitHub Sponsors). A Stripe link gets a random install id.
  async function getPro() {
    if (!paymentUrl) {
      await info(`${label} is not on sale yet. Everything you use today stays free.`);
      return false;
    }
    if (/^https:\/\/(buy\.stripe\.com|license(-test)?\.zovo\.one)\//.test(paymentUrl)) {
      const sep = paymentUrl.includes('?') ? '&' : '?';
      return open(`${paymentUrl}${sep}client_reference_id=${encodeURIComponent(installId())}`);
    }
    return openArmed(paymentUrl, onSponsors() && sponsorsRail() ? 'sponsors' : '');
  }

  // Card checkout. CARD1: Stripe through the license Worker when funding.json card_buy_url is set (a random install id
  // goes along as client_reference_id; no other data). Else Gumroad (MONEY5 #1) when gumroad_pro and _url are set.
  async function payByCard() {
    if (cardBuyUrl) {
      const sep = cardBuyUrl.includes('?') ? '&' : '?';
      await openArmed(`${cardBuyUrl}${sep}client_reference_id=${encodeURIComponent(installId())}`, 'card');
      return false;
    }
    if (!cardUrl) {
      await info(`${label} is not sold by card in this version. ${PAYPAL_LABEL} or GitHub Sponsors work today.`);
      return false;
    }
    const sep = cardUrl.includes('?') ? '&' : '?';
    await openArmed(`${cardUrl}${sep}wanted=true`, 'gumroad');
    return false;
  }

  // ---- back from the browser (CONV2) and the shared file ----
  // One message, the first time the window is focused again after the browser took the focus, within 2 h of the
  // click, only while still not Pro. It continues the purchase the user started; it never repeats.
  // On focus the shared file is re-read (a local stat, no network, no UI), so an unlock in another Zovo extension
  // shows here without a restart.
  let pending = null;
  let winSub = null;
  function watchWindow() {
    const w = vscode.window;
    if (winSub || !w || typeof w.onDidChangeWindowState !== 'function') return;
    winSub = w.onDidChangeWindowState((e) => { onWindow(e).catch(() => {}); });
    if (context.subscriptions && winSub) context.subscriptions.push(winSub);
  }
  function armReturn(kind) {
    const w = vscode.window;
    if (!w || typeof w.onDidChangeWindowState !== 'function') return;
    pending = { kind, at: Date.now(), blurred: !!(w.state && w.state.focused === false) };
    watchWindow();
  }
  // Arm first, then open: the browser can take the focus before openExternal resolves. A failed open disarms.
  async function openArmed(url, kind) {
    if (kind) armReturn(kind);
    try { return await open(url); } catch (e) { if (kind) pending = null; throw e; }
  }
  async function onWindow(e) {
    if (e && e.focused && sharedRail) { await sharedRail.reload(false); changed(); }
    if (!pending) return;
    if (Date.now() - pending.at > RETURN_MS) { pending = null; return; }
    if (!e || !e.focused) { pending.blurred = true; return; }
    if (!pending.blurred) return;
    const kind = pending.kind;
    pending = null;
    if (isPro()) return;
    if (kind === 'sponsors') {
      const u = LABELS['github-sponsors'];
      const pick = await info(`Back from GitHub Sponsors? If you paid for the "$${PRICE.one} one time" tier, turn ${label} on now: VS Code asks you to sign in with GitHub.`, u, 'Not yet');
      if (pick === u) await unlock('github-sponsors');
    } else if (kind === 'paypal') {
      const send = 'Send the transaction ID', key = LABELS['license-key'];
      const pick = await info(`Back from PayPal? Send the transaction ID from your PayPal receipt. The ${label} license key then comes to the email address of your PayPal account.`, send, key);
      if (pick === send) await sendTransactionId();
      else if (pick === key) await unlock('license-key');
    } else if (kind === 'card' && byId('license-key')) {
      const pick = await info(`Back from the checkout? Click "Copy key" on the license page, then "${ENTER_KEY_LABEL}" here to turn ${label} on.`, ENTER_KEY_LABEL, 'Not yet');
      if (pick === ENTER_KEY_LABEL) await enterKey();
    } else if (kind === 'gumroad' && byId('gumroad')) {
      const g = LABELS.gumroad;
      const pick = await info(`Back from Gumroad? Paste the license key from your receipt to turn ${label} on.`, g, 'Not yet');
      if (pick === g) await unlock('gumroad');
    }
  }

  function keyRequestLink() {
    if (!keyRequestUrl) return '';
    const sep = keyRequestUrl.includes('?') ? '&' : '?';
    const p = product === 'this extension' ? name : product;
    return `${keyRequestUrl}${sep}title=${encodeURIComponent(`Zovo Pro key: PayPal payment for ${p}`)}&product=${encodeURIComponent(p)}`;
  }

  async function sendTransactionId() {
    const link = keyRequestLink();
    if (!link) return false;
    await open(link);
    return true;
  }

  // PayPal (CONV2): the steps in one modal the user started. The owner checks the payment and emails the key.
  async function payWithPayPal() {
    if (!paypalUrl) {
      await info(`${label} is not sold by PayPal in this version.`);
      return false;
    }
    const one = `Pay USD ${PRICE.one} on PayPal`;
    const team = `Team of ${PRICE.seats}: USD ${PRICE.team}`;
    const send = 'Send the transaction ID';
    const key = LABELS['license-key'];
    const btns = [one, team];
    if (keyRequestUrl) btns.push(send);
    btns.push(key);
    const steps = [
      `1. Pay USD ${PRICE.one} for one person, or USD ${PRICE.team} for a team of ${PRICE.seats} (one key for ${PRICE.seats} people). PayPal opens in your browser with the amount filled in.`,
      keyRequestUrl
        ? '2. Copy the transaction ID from the PayPal receipt (17 letters and digits) and send it with "Send the transaction ID", a short form on GitHub. Post only the ID, never your name or email. No GitHub account? Write "Zovo Pro" in the PayPal note instead.'
        : '2. Write "Zovo Pro" in the PayPal note.',
      `3. The license key comes to the email address of your PayPal account. Paste it with "${key}". It is checked on your computer and works for life in every Zovo extension.`,
    ];
    const pick = await info(`Pay for ${label} with PayPal`, { modal: true, detail: steps.join('\n\n') }, ...btns);
    if (pick === one || pick === team) {
      await openArmed(`${paypalUrl}/${pick === one ? PRICE.one : PRICE.team}USD`, 'paypal');
      return false;
    }
    if (pick === send) { await sendTransactionId(); return false; }
    if (pick === key) return !!(await unlock('license-key')).pro && isPro();
    return false;
  }

  const none = () => ({ rail: '', pro: isPro(), reason: 'cancelled', kind: 'none', login: '', message: '' });

  // "I already paid": the ways to turn Pro on after paying. The old "How to buy" text lives here now.
  async function alreadyPaid() {
    const desc = (id) => (cardBuyUrl && id === 'license-key' ? 'a key that starts with ZOVO1., from the license page after paying by card, or the PayPal email' : PAID_DESC[id] || '');
    const items = sortedRails().map((r) => ({ label: railLabel(r), description: desc(r.id), id: r.id }));
    if (paypalUrl && keyRequestUrl) items.push({ label: NO_KEY_LABEL, description: 'send the transaction ID; the key comes by email', id: 'paypal-no-key' });
    const title = cardBuyUrl ? `${ENTER_KEY_LABEL}: turn ${label} on` : `${PAID_LABEL}: turn ${label} on`;
    const pick = await vscode.window.showQuickPick(items, { title, placeHolder: 'How did you pay?' });
    if (!pick) return none();
    if (pick.id === 'paypal-no-key') { await sendTransactionId(); return none(); }
    return unlock(pick.id);
  }

  // CARD1 "Enter a key": the user clicked it, so the clipboard is read once (local, never sent anywhere). A ZOVO1 key
  // there goes to the key rail: a valid key turns Pro on at once, any other ZOVO1 text opens the input box with it.
  // No ZOVO1 key on the clipboard: the quick pick (paste a key, GitHub Sponsors, PayPal without a key yet).
  async function enterKey() {
    let clip = '';
    try {
      const c = vscode.env && vscode.env.clipboard;
      if (c && typeof c.readText === 'function') clip = String((await c.readText()) || '').trim();
    } catch (e) { clip = ''; }
    if (clip.length < 4096 && clip.replace(/^["'\s]+/, '').startsWith(KEY_PREFIX) && byId('license-key')) {
      return unlock('license-key', { prefill: clip });
    }
    return alreadyPaid();
  }

  // ---- after a successful unlock: the shared file, then one carry-over offer (XSELL2 move 1) ----
  async function share(rail) {
    if (!sharedRail || !rail) return null;
    if (rail.id === 'license-key' && typeof rail.currentKey === 'function') {
      const key = rail.currentKey();
      if (key) { await sharedRail.write({ key }); return { kind: 'key', key }; }
    }
    if (rail.id === 'github-sponsors' && typeof rail.state === 'function') {
      const st = rail.state();
      if (st && (st.kind === 'lifetime' || st.kind === 'monthly') && st.login) {
        const t = typeof st.checkedAt === 'number' ? st.checkedAt : Date.now();
        const sp = { login: st.login, tierId: st.tierId || '', kind: st.kind, date: new Date(t).toISOString().slice(0, 10) };
        if (st.kind === 'monthly') sp.until = typeof st.recheckAt === 'number' ? st.recheckAt : 0;
        await sharedRail.write({ sponsors: sp });
        return { kind: 'sponsors' };
      }
    }
    return null;
  }
  // Other installed zovo.* tools with Pro that a carry-over can reach. A key goes only to tools on this module
  // version (their enterLicenseKey takes the key without an input box); Sponsors goes to all (VS Code asks each one
  // for GitHub access, its own rule).
  function carryTargets(kind) {
    return zovoTools(vscode, selfId).filter((t) => t.proPrefix && (kind !== 'key' || t.v2));
  }
  async function offerCarryOver(shared, message) {
    const g = context.globalState;
    const targets = shared ? carryTargets(shared.kind) : [];
    const exec = vscode.commands && typeof vscode.commands.executeCommand === 'function';
    if (!targets.length || !exec || (g && g.get(CARRY_KEY))) {
      if (message) await info(message);
      return false;
    }
    if (g) await g.update(CARRY_KEY, true); // asked once; "Not now" is final
    const on = 'Turn on';
    const pick = await info(`${label} is on in ${product}. Turn it on in your other Zovo tools too? (${namesList(targets.map((t) => t.name))})`, on, 'Not now');
    if (pick !== on) return false;
    let n = 0;
    for (const t of targets) {
      try {
        const cmd = shared.kind === 'key' ? `${t.proPrefix}.enterLicenseKey` : `${t.proPrefix}.unlockWithSponsors`;
        const arg = shared.kind === 'key' ? { key: shared.key, carryOver: true } : { carryOver: true };
        const r = await vscode.commands.executeCommand(cmd, arg);
        if (r && r.pro) n += 1;
      } catch (e) { /* that tool is gone or failed: skip it */ }
    }
    if (n) await info(`${label} is on in ${n} more Zovo ${n === 1 ? 'tool' : 'tools'}.`);
    return true;
  }
  // A carry-over call from another Zovo tool. No UI when Pro is on already (from the shared file or before).
  async function carryIn(kind, key) {
    if (sharedRail) await sharedRail.reload(true);
    changed();
    if (isPro()) return { pro: true, reason: 'ok' };
    let r = none();
    if (kind === 'key' && byId('license-key')) {
      r = await byId('license-key').unlock(typeof key === 'string' ? key : '');
      if (r && r.pro) await share(byId('license-key'));
    } else if (kind === 'sponsors' && sponsorsRail()) {
      r = await unlock('github-sponsors', { carryIn: true });
    }
    changed();
    return { pro: !!(r && r.pro) && isPro(), reason: (r && r.reason) || 'cancelled' };
  }

  // Run one rail's unlock and show its message. Returns the UnlockResult. No rail id: the "I already paid" pick.
  async function unlock(railId, opts = {}) {
    let rail = railId ? byId(railId) : null;
    if (!rail && !railId && visible().length === 1) rail = visible()[0];
    if (!rail) return railId ? none() : alreadyPaid();
    const r = await (rail.id === 'license-key' && typeof opts.prefill === 'string' ? rail.unlock(opts.prefill) : rail.unlock());
    if (r && r.pro && r.reason === 'ok') {
      changed();
      const shared = await share(rail);
      if (opts.carryIn) { if (r.message) await info(r.message); } else await offerCarryOver(shared, r.message);
      changed();
      return r;
    }
    if (r && r.message) {
      if (r.pro) await info(r.message);
      else if (r.reason === 'expired' && r.renewUrl) {
        if ((await vscode.window.showWarningMessage(r.message, 'Renew page')) === 'Renew page') await open(r.renewUrl);
      } else if (r.reason === 'not-sponsor' || r.reason === 'other-tier' || r.reason === 'below-minimum') {
        const btns = ['Open the Zovo Pro tier'];
        if (paypalUrl) btns.push(PAYPAL_LABEL);
        const pick = await vscode.window.showWarningMessage(r.message, ...btns);
        if (pick === btns[0]) await openArmed(SPONSORS_ONE_TIME, 'sponsors');
        else if (pick === PAYPAL_LABEL) await payWithPayPal();
      } else if (rail.id === 'github-sponsors' && ['no-session', 'auth', 'scope'].includes(r.reason) && (paypalUrl || byId('license-key'))) {
        // No GitHub sign-in in this editor (or it failed): offer the ways that need no GitHub.
        const btns = [];
        if (paypalUrl) btns.push(PAYPAL_LABEL);
        if (byId('license-key')) btns.push(LABELS['license-key']);
        const pick = await vscode.window.showWarningMessage(`${r.message} You can also pay with PayPal and get a license key by email.`, ...btns);
        if (pick === PAYPAL_LABEL) await payWithPayPal();
        else if (pick === LABELS['license-key']) { changed(); return unlock('license-key', opts); }
      } else if (r.reason !== 'cancelled') await vscode.window.showWarningMessage(r.message);
    }
    changed();
    return r;
  }

  // The panel text (CONV3 fix 4). detail: string, or { detail, triesUsed, tools }.
  function panelDetail(feature, d) {
    const legacy = typeof d === 'string' || d === undefined || d === null;
    const opt = legacy ? { detail: d || '' } : d;
    const parts = [];
    const head = [];
    if (Number.isInteger(opt.triesUsed) && opt.triesUsed > 0) head.push(`You used the ${opt.triesUsed} free ${opt.triesUsed === 1 ? 'try' : 'tries'} on this computer.`);
    if (opt.detail) head.push(opt.detail);
    if (head.length) parts.push(head.join('\n'));
    if (!legacy || !opt.detail) {
      const others = (Array.isArray(opt.tools) ? opt.tools : proTools).filter((t) => t && t !== feature);
      const here = others.length ? `${namesList(others, others.length)} here, and ` : '';
      const refund = /^\d{1,3}$/.test(refundDays) && Number(refundDays) > 0 ? ` Not happy? Full refund within ${Number(refundDays)} days.` : '';
      parts.push(`${label} is USD ${PRICE.one} once, for life. It turns on ${here}the Pro tools of all ${proCount} Zovo extensions, including Hex, DOCX, PDF, SQLite and PPTX.${refund} Everything that is free today stays free.`);
    }
    const mine = zovoTools(vscode, selfId).filter((t) => t.proPrefix).map((t) => t.name);
    if (mine.length) parts.push(`${label} also turns on Pro tools in the Zovo extensions you already have: ${namesList(mine)}.`);
    return parts.join('\n\n');
  }

  // For a Pro action the user started: true when unlocked. Otherwise one modal (user-started, so allowed by the
  // VS Code UX rules) that says what the feature is, with the 4 buttons. Never shown on its own.
  async function requirePro(feature, detail) {
    if (!isPro() && sharedRail) { await sharedRail.reload(false); changed(); }
    if (isPro()) {
      for (const r of rails) if (typeof r.refresh === 'function') r.refresh().catch(() => {}); // due monthly recheck only
      return true;
    }
    const btns = buttons();
    const renew = keyRail.renewUrl();
    if (renew) btns.push('Renew page');
    const pick = await info(`${feature} is part of ${label}.`, { modal: true, detail: panelDetail(feature, detail) }, ...btns);
    if (!pick) return false;
    if (pick === BUY_LABEL || pick === SPONSORS_BUY_LABEL) { await getPro(); return false; }
    if (pick === CARD_LABEL || pick === CARD_BUY_LABEL) { await payByCard(); return false; }
    if (pick === ENTER_KEY_LABEL) return !!(await enterKey()).pro && isPro();
    if (pick === PAYPAL_LABEL) return payWithPayPal();
    if (pick === 'Renew page') { await open(renew); return false; }
    if (pick === PAID_LABEL) return !!(await alreadyPaid()).pro && isPro();
    return false;
  }

  async function remove() {
    for (const r of rails) if (typeof r.remove === 'function') await r.remove();
    changed();
    await info(`${label} removed from this editor${sharedRail ? ' and from the shared Zovo Pro file on this computer' : ''}. Free features keep working.`);
  }

  // vscode://<publisher.name>/license?key=... from a license page or a receipt. Asks before it stores anything.
  // ZOVO1 keys are checked offline. Gumroad keys only when Gumroad is configured (one request, after the click).
  async function handleUri(uri) {
    if (!uri || !/\/license\/?$/.test(uri.path || '')) return false;
    const key = new URLSearchParams(uri.query || '').get('key');
    if (!key) return false;
    const zovo = String(key).trim().startsWith(KEY_PREFIX);
    const g = byId('gumroad');
    if (!zovo && !(g && /^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{8}){3}$/.test(String(key).trim()))) return false;
    const pick = await info(`Add a ${label} license key from the ${zovo ? 'license page' : 'Gumroad receipt'}?`, { modal: true }, 'Add key');
    if (pick !== 'Add key') return false;
    const r = zovo ? await keyRail.saveKey(key) : await g.unlock(String(key).trim());
    changed();
    if (r.pro) await offerCarryOver(await share(zovo ? keyRail : g), r.message);
    else if (r.message) await vscode.window.showWarningMessage(r.message);
    changed();
    return !!r.pro;
  }

  // The "Support the developer" quick pick (CONV3 fix 1): Zovo Pro first, then the plain links the product passes,
  // [{ label: 'GitHub Sponsors', url }, { label: 'PayPal', url }].
  async function supportDeveloper(links = []) {
    const items = [{ label: SUPPORT_PRO_LABEL, id: 'pro' }];
    for (const l of links) if (l && l.url) items.push({ label: l.label, detail: l.url, url: l.url });
    const pick = await vscode.window.showQuickPick(items, { placeHolder: 'Pick a way to support the developer' });
    if (!pick) return false;
    if (pick.id === 'pro') return getPro();
    return open(pick.url);
  }

  const outward = (r) => ({ pro: !!(r && r.pro), reason: (r && r.reason) || 'cancelled' }); // no key, no login
  function registerCommands(prefix) {
    const p = prefix || o.commandPrefix;
    const d = [
      vscode.commands.registerCommand(`${p}.enterLicenseKey`, async (arg) => (arg && arg.carryOver ? carryIn('key', arg.key) : outward(await unlock('license-key')))),
      vscode.commands.registerCommand(`${p}.getPro`, () => getPro()),
      vscode.commands.registerCommand(`${p}.removeLicense`, () => remove()),
    ];
    if (byId('github-sponsors')) d.push(vscode.commands.registerCommand(`${p}.unlockWithSponsors`, async (arg) => (arg && arg.carryOver ? carryIn('sponsors') : outward(await unlock('github-sponsors')))));
    if (paypalUrl) d.push(vscode.commands.registerCommand(`${p}.payWithPayPal`, () => payWithPayPal()));
    if (cardBuyUrl || cardUrl) d.push(vscode.commands.registerCommand(`${p}.payByCard`, () => payByCard()));
    context.subscriptions.push(...d);
    return d;
  }

  const api = {
    ready: Promise.all(rails.map((r) => Promise.resolve(r.ready).catch(() => {}))).then(() => { last = isPro(); if (sharedRail) watchWindow(); }),
    rails,
    isPro,
    unlock,
    alreadyPaid,
    getPro,
    payByCard,
    enterKey,
    payWithPayPal,
    sendTransactionId,
    requirePro,
    panelDetail,
    buttons,
    remove,
    handleUri,
    registerCommands,
    supportDeveloper,
    installId,
    cardBuyUrl,
    sharedFile: file,
    refresh: () => Promise.all(rails.map((r) => (typeof r.refresh === 'function' ? r.refresh().catch(() => false) : false))),
    state: () => Object.fromEntries(rails.map((r) => [r.id, typeof r.state === 'function' ? r.state() : null])),
    onDidChange(fn) { listeners.add(fn); return { dispose: () => listeners.delete(fn) }; },
  };
  if (o.commandPrefix) registerCommands(o.commandPrefix);
  return api;
}

module.exports = {
  createLicense, createSharedRail, zovoTools, namesList, paletteCommands, readSharedFile, writeSharedFile, sharedFilePath,
  SPONSORS_ONE_TIME, PAYPAL_ME, PRICE, KEY_REQUEST_URL, MODULE_VERSION, CATEGORY, PRO_EXTENSIONS, SUPPORT_PRO_LABEL,
  BUY_LABEL, CARD_LABEL, PAYPAL_LABEL, PAID_LABEL, LABELS, CARRY_KEY, SHARED_ENV,
  CARD_BUY_LABEL, SPONSORS_BUY_LABEL, ENTER_KEY_LABEL, CARD_BUY_RE,
};
