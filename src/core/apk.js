'use strict';
// APK, AAB, APKS and XAPK reader: builds the model the webview shows (summary, manifest XML, tables, package tree)
// and the plain facts the Pro tools use (compare, export, find). Only the central directory, the manifest, the DEX
// files and the signature files are read; the other entries are read only when the user opens them in the hex view.
const { Source } = require('./source');
const { Budget, Model } = require('./model');
const { readZip, readEntry, dataOffset, ZipError } = require('./zip');
const { decodeAxml, attr, ANDROID_NS } = require('./axml');
const { parseDex, packageOf } = require('./dex');
const { readSigningBlock, pkcs7Cert, schemeCert, certInfo } = require('./sign');

const APK_LIMITS = {
  maxManifest: 16 * 1024 * 1024, // unpacked AndroidManifest.xml
  maxDex: 128 * 1024 * 1024,     // one unpacked classes.dex
  maxDexTotal: 768 * 1024 * 1024,
  maxDexFiles: 200,
  maxNested: 300 * 1024 * 1024,  // a compressed inner APK of an .xapk or .apks is unpacked into memory up to this
  maxTreeNodes: 20000,
  maxCert: 1024 * 1024,
};

// Dangerous (runtime) permissions, from the Android permission reference (API 36).
const DANGEROUS = new Set(['READ_CALENDAR', 'WRITE_CALENDAR', 'CAMERA', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS', 'ACCESS_FINE_LOCATION',
  'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'RECORD_AUDIO', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE', 'ANSWER_PHONE_CALLS',
  'READ_CALL_LOG', 'WRITE_CALL_LOG', 'ADD_VOICEMAIL', 'USE_SIP', 'PROCESS_OUTGOING_CALLS', 'BODY_SENSORS', 'BODY_SENSORS_BACKGROUND', 'SEND_SMS',
  'RECEIVE_SMS', 'READ_SMS', 'RECEIVE_WAP_PUSH', 'RECEIVE_MMS', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'ACCESS_MEDIA_LOCATION',
  'ACCEPT_HANDOVER', 'ACTIVITY_RECOGNITION', 'UWB_RANGING', 'BLUETOOTH_SCAN', 'BLUETOOTH_ADVERTISE', 'BLUETOOTH_CONNECT', 'NEARBY_WIFI_DEVICES',
  'POST_NOTIFICATIONS', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO', 'READ_MEDIA_VISUAL_USER_SELECTED', 'RANGING']);
// Special access: granted in system settings, not by a runtime dialog.
const SPECIAL = new Set(['SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS', 'MANAGE_EXTERNAL_STORAGE', 'REQUEST_INSTALL_PACKAGES', 'SCHEDULE_EXACT_ALARM',
  'PACKAGE_USAGE_STATS', 'QUERY_ALL_PACKAGES', 'BIND_ACCESSIBILITY_SERVICE', 'BIND_NOTIFICATION_LISTENER_SERVICE', 'BIND_DEVICE_ADMIN',
  'MANAGE_MEDIA', 'USE_FULL_SCREEN_INTENT', 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS', 'ACCESS_NOTIFICATION_POLICY', 'BIND_VPN_SERVICE']);
const SDK = { 1: '1.0', 2: '1.1', 3: '1.5', 4: '1.6', 5: '2.0', 6: '2.0.1', 7: '2.1', 8: '2.2', 9: '2.3', 10: '2.3.3', 11: '3.0', 12: '3.1', 13: '3.2', 14: '4.0', 15: '4.0.3', 16: '4.1', 17: '4.2', 18: '4.3', 19: '4.4', 20: '4.4W', 21: '5.0', 22: '5.1', 23: '6.0', 24: '7.0', 25: '7.1', 26: '8.0', 27: '8.1', 28: '9', 29: '10', 30: '11', 31: '12', 32: '12L', 33: '13', 34: '14', 35: '15', 36: '16' };
const sdkText = (n) => (n === undefined || n === '' ? '' : SDK[n] ? `${n} (Android ${SDK[n]})` : String(n));
const COMPONENTS = ['activity', 'activity-alias', 'service', 'receiver', 'provider'];

const isDex = (n) => /^(?:[^/]+\/dex\/)?classes\d*\.dex$/.test(n);
const kindOf = (name) => {
  const n = name.toLowerCase();
  if (n.endsWith('.apks')) return 'APKS';
  if (n.endsWith('.xapk') || n.endsWith('.apkm')) return 'XAPK';
  if (n.endsWith('.aab')) return 'AAB';
  return 'APK';
};

/** Opens an archive: { src, zip, byName } */
function openZip(src, limits) {
  const zip = readZip(src, limits);
  const byName = new Map();
  for (const e of zip.entries) if (!byName.has(e.name)) byName.set(e.name, e);
  return { src, zip, byName };
}

/**
 * Source of an inner APK (inside .xapk / .apks): a window when the entry is stored, else unpacked into memory.
 */
function innerSource(src, entry, L) {
  if (entry.method === 0 && !entry.encrypted) { const off = dataOffset(src, entry); return src.slice(off, entry.size); }
  return Source.fromBuffer(readEntry(src, entry, L.maxNested));
}

function fmtBytes(n) {
  if (n < 1024) return `${n} bytes`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}
const yes = (v) => (v === 'true' ? 'yes' : v === 'false' ? 'no' : v);

/** Parse an APK-like file from a Source. fileName decides .aab/.apks/.xapk. */
function parseApk(src, fileName = 'app.apk', limits = {}) {
  const L = { ...APK_LIMITS, ...limits };
  const budget = new Budget(limits);
  let kind = kindOf(fileName);
  let arc;
  try { arc = openZip(src, limits); } catch (e) {
    const err = new Error(e.message); err.code = e.code === 'NOT_ZIP' ? 'NOT_APK' : 'DAMAGED'; throw err;
  }
  // A file named .apk that holds split APKs is an APK set.
  if (kind === 'APK' && !arc.byName.has('AndroidManifest.xml')) {
    if (arc.byName.has('base/manifest/AndroidManifest.xml')) kind = 'AAB';
    else if ([...arc.byName.keys()].some((n) => n.endsWith('.apk'))) kind = arc.byName.has('toc.pb') ? 'APKS' : 'XAPK';
  }
  if (kind === 'APKS' || kind === 'XAPK') return parseSet(src, arc, kind, fileName, L, budget);
  const m = buildModel(src, arc, kind, fileName, L, budget, '');
  return m.finish();
}

/** .xapk / .apks: list the inner APKs and analyse the base APK. */
function parseSet(src, arc, kind, fileName, L, budget) {
  const inner = arc.zip.entries.filter((e) => !e.dir && /\.apk$/i.test(e.name));
  let pkgName = '';
  const mj = arc.byName.get('manifest.json');
  if (mj && mj.size < 1048576) { try { pkgName = String(JSON.parse(Buffer.from(readEntry(src, mj, 1048576)).toString('utf8')).package_name || ''); } catch { /* not JSON */ } }
  const pick = inner.find((e) => /(^|\/)base(-master)?\.apk$/i.test(e.name)) || (pkgName && inner.find((e) => e.name === `${pkgName}.apk`)) || inner.slice().sort((a, b) => b.size - a.size)[0];
  let m;
  if (pick) {
    try {
      const isrc = innerSource(src, pick, L);
      const iarc = openZip(isrc, {});
      m = buildModel(isrc, iarc, 'APK', pick.name, L, budget, pick.name + '!/');
      m.title = `${kind === 'APKS' ? 'APK set (.apks)' : 'XAPK package'} · base ${pick.name} · ${m.title}`;
    } catch (e) {
      m = new Model(kind, budget);
      m.data = { kind, files: {}, permissions: [], components: [], dex: [], refsByPackage: {}, abis: [], schemes: [] };
      m.title = `${kind === 'APKS' ? 'APK set (.apks)' : 'XAPK package'}`;
      m.warn(`The base APK ${pick.name} could not be read: ${e.message}`);
    }
  } else {
    m = new Model(kind, budget);
    m.data = { kind, files: {}, permissions: [], components: [], dex: [], refsByPackage: {}, abis: [], schemes: [] };
    m.title = kind === 'APKS' ? 'APK set (.apks)' : 'XAPK package';
    m.warn('There is no .apk file inside this package.');
  }
  m.format = kind;
  // the outer archive: inner APKs and every outer entry (hex works on outer entries)
  const t = m.table('inner', 'APKs in this package', [['APK', 's'], ['Compressed', 'b'], ['Size', 'b'], ['Analysed', 's']]);
  t.entries = [];
  for (const e of inner) { m.row(t, [e.name, e.packed, e.size, e === pick ? 'yes (shown in the other tabs)' : 'no']); t.entries.push(e.name); }
  m.summary.unshift(['Package file', `${kind === 'APKS' ? 'APK set' : 'XAPK'} with ${inner.length} APK${inner.length === 1 ? '' : 's'}${pkgName ? `, package ${pkgName}` : ''}`]);
  m.data.set = { kind, apks: inner.map((e) => ({ name: e.name, size: e.size })), base: pick ? pick.name : '' };
  m.data.fileSize = src.size;
  return m.finish();
}

function buildModel(src, arc, kind, fileName, L, budget, prefix) {
  const m = new Model(kind, budget);
  const entries = arc.zip.entries;
  for (const p of arc.zip.problems) m.warn(p);
  const files = entries.filter((e) => !e.dir);
  const D = m.data = { kind, package: '', versionCode: '', versionName: '', minSdk: '', targetSdk: '', compileSdk: '', label: '', debuggable: false,
    permissions: [], components: [], abis: [], schemes: [], cert: null, dex: [], refsByPackage: {}, classesByPackage: {}, files: {}, fileSize: src.size };
  for (const e of files) D.files[e.name] = [e.packed, e.size];

  // ---- manifest ----
  let manifest = null;
  const mfName = kind === 'AAB' ? 'base/manifest/AndroidManifest.xml' : 'AndroidManifest.xml';
  const mfEntry = arc.byName.get(mfName);
  m.manifestXml = '';
  if (!mfEntry) m.warn(`There is no ${mfName} in this file.`);
  else if (kind === 'AAB') m.manifestNote = 'In an Android App Bundle (.aab) the manifest is stored as a protocol buffer. APK Analyzer decodes the binary XML manifest of APK files only; the files, sizes, DEX counts and signing of this bundle are shown in the other tabs.';
  else {
    m.part('AndroidManifest.xml', () => {
      const bytes = readEntry(src, mfEntry, L.maxManifest);
      const r = decodeAxml(bytes);
      manifest = r.root;
      m.manifestXml = r.xml;
      for (const w of r.warnings) m.warn(`AndroidManifest.xml: ${w}`);
    });
  }
  const permRows = [];
  if (manifest) readManifest(m, manifest, D, permRows);

  // ---- tables ----
  const comp = m.table('components', 'Activities, services, receivers and providers', [['Type', 's'], ['Name', 's'], ['Exported', 's'], ['Why', 's'], ['Permission', 's'], ['Intent filter actions', 's']]);
  for (const c of D.components) m.row(comp, [c.type, c.name, c.exported, c.why, c.permission, c.actions]);
  const perms = m.table('permissions', 'Permissions', [['Permission', 's'], ['Protection', 's'], ['Declared by', 's'], ['Max SDK', 's']]);
  for (const r of permRows) m.row(perms, r);

  // DEX
  const dexEntries = files.filter((e) => isDex(e.name)).slice(0, L.maxDexFiles);
  if (files.filter((e) => isDex(e.name)).length > L.maxDexFiles) m.warn(`Only the first ${L.maxDexFiles} DEX files were read.`);
  const dexT = m.table('dex', 'DEX files', [['File', 's'], ['Version', 's'], ['Size', 'b'], ['Classes', 'd'], ['Defined methods', 'd'], ['Method refs', 'd'], ['% of 65,536', 's'], ['Field refs', 'd'], ['Strings', 'd'], ['Types', 'd'], ['Protos', 'd']]);
  dexT.entries = [];
  const classT = m.table('classes', 'Classes defined in the DEX files', [['Class', 's'], ['Package', 's'], ['Methods', 'd'], ['Fields', 'd'], ['Access', 's'], ['Superclass', 's'], ['DEX', 's']]);
  const pk = new Map(); // package -> { classes, methods, refs }
  const P = (name) => { let x = pk.get(name); if (!x) { x = { classes: 0, methods: 0, refs: 0 }; pk.set(name, x); } return x; };
  let dexTotal = 0;
  for (const e of dexEntries) {
    if (!budget.ok()) break;
    m.part(e.name, () => {
      if (dexTotal + e.size > L.maxDexTotal) throw new Error(`skipped: the DEX files together are larger than ${fmtBytes(L.maxDexTotal)}`);
      dexTotal += e.size;
      const d = parseDex(readEntry(src, e, L.maxDex), e.name);
      for (const w of d.warnings) m.warn(w);
      const defined = d.classes.reduce((a, c) => a + c.methods, 0);
      const pct = ((d.methodRefs / 65536) * 100).toFixed(1) + '%';
      m.row(dexT, [e.name, d.version, e.size, d.classes.length, defined, d.methodRefs, pct, d.fieldRefs, d.counts.strings, d.counts.types, d.counts.protos]);
      dexT.entries.push(prefix + e.name);
      D.dex.push({ name: e.name, version: d.version, size: e.size, classes: d.classes.length, methods: defined, methodRefs: d.methodRefs, fieldRefs: d.fieldRefs, strings: d.counts.strings });
      if (d.methodRefs > 65536) m.warn(`${e.name} lists ${d.methodRefs.toLocaleString('en-US')} method references, more than the 65,536 a DEX file can address.`);
      for (const c of d.classes) {
        m.row(classT, [c.name, c.pkg, c.methods, c.fields, c.access, c.super, e.name]);
        const x = P(c.pkg); x.classes++; x.methods += c.methods;
      }
      for (const [p, n] of d.refsByPackage) P(p).refs += n;
    });
  }
  for (const [p, x] of pk) { D.refsByPackage[p] = x.refs; D.classesByPackage[p] = [x.classes, x.methods]; }
  const pkT = m.table('packages', 'Method counts by package', [['Package', 's'], ['Classes', 'd'], ['Defined methods', 'd'], ['Method refs', 'd']]);
  for (const [p, x] of [...pk].sort((a, b) => b[1].refs - a[1].refs)) m.row(pkT, [p, x.classes, x.methods, x.refs]);
  m.tree = packageTree(pk, L.maxTreeNodes, m);

  // size
  const folders = new Map(), types = new Map();
  const add = (map, k, e) => { let x = map.get(k); if (!x) { x = [0, 0, 0]; map.set(k, x); } x[0]++; x[1] += e.packed; x[2] += e.size; };
  let totPacked = 0, totSize = 0;
  for (const e of files) {
    totPacked += e.packed; totSize += e.size;
    const parts = e.name.split('/');
    if (parts.length === 1) add(folders, '(root files)', e);
    for (let i = 1; i < parts.length && i <= 6; i++) add(folders, parts.slice(0, i).join('/') + '/', e);
    const base = parts[parts.length - 1];
    const dot = base.lastIndexOf('.');
    add(types, dot > 0 ? base.slice(dot + 1).toLowerCase().slice(0, 16) : '(no extension)', e);
  }
  const pct = (n) => (totPacked ? ((n / totPacked) * 100).toFixed(1) + '%' : '');
  const fT = m.table('folders', 'Size by folder (subfolders included)', [['Folder', 's'], ['Files', 'd'], ['Compressed', 'b'], ['Size', 'b'], ['% of compressed', 's']]);
  for (const [k, x] of [...folders].sort((a, b) => b[1][1] - a[1][1])) m.row(fT, [k, x[0], x[1], x[2], pct(x[1])]);
  const tT = m.table('types', 'Size by file type', [['Type', 's'], ['Files', 'd'], ['Compressed', 'b'], ['Size', 'b'], ['% of compressed', 's']]);
  for (const [k, x] of [...types].sort((a, b) => b[1][1] - a[1][1])) m.row(tT, [k, x[0], x[1], x[2], pct(x[1])]);
  const fileT = m.table('files', 'Files', [['Path', 's'], ['Compressed', 'b'], ['Size', 'b'], ['Method', 's'], ['Ratio', 's']]);
  fileT.entries = [];
  const bySize = files.slice().sort((a, b) => b.packed - a.packed);
  for (const e of bySize) { if (!m.row(fileT, [e.name, e.packed, e.size, e.methodName + (e.encrypted ? ', encrypted' : ''), e.size ? ((e.packed / e.size) * 100).toFixed(0) + '%' : '']) ) break; fileT.entries.push(prefix + e.name); }

  // native libraries
  const libRe = kind === 'AAB' ? /^[^/]+\/lib\/([^/]+)\/([^/]+)$/ : /^lib\/([^/]+)\/([^/]+)$/;
  const abis = new Map();
  for (const e of files) { const r = libRe.exec(e.name); if (r) { let x = abis.get(r[1]); if (!x) { x = { files: 0, packed: 0, size: 0, names: [] }; abis.set(r[1], x); } x.files++; x.packed += e.packed; x.size += e.size; if (x.names.length < 40) x.names.push(r[2]); } }
  const nT = m.table('natives', 'Native libraries by ABI', [['ABI', 's'], ['Files', 'd'], ['Compressed', 'b'], ['Size', 'b'], ['Libraries', 's']]);
  for (const [k, x] of abis) m.row(nT, [k, x.files, x.packed, x.size, x.names.join(', ')]);
  D.abis = [...abis.keys()].sort();

  // signing
  const sT = m.table('signing', 'Signing', [['Item', 's'], ['Value', 's']]);
  sT.keepEmpty = true;
  const v1 = files.filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
  const sf = files.filter((e) => /^META-INF\/[^/]+\.SF$/i.test(e.name));
  if (v1.length && sf.length) D.schemes.push('v1');
  let certDer = null;
  m.part('APK Signing Block', () => {
    const blk = readSigningBlock(src, arc.zip.cdOffset);
    if (!blk) { m.row(sT, ['APK Signing Block', 'none (no v2 or v3 signature)']); return; }
    m.row(sT, ['APK Signing Block', `${fmtBytes(blk.size)} at 0x${blk.offset.toString(16).toUpperCase()}, ${blk.pairs.length} block${blk.pairs.length === 1 ? '' : 's'}`], prefix ? undefined : [blk.offset, blk.size]);
    for (const pr of blk.pairs) {
      m.row(sT, [`  ${pr.name}`, `${fmtBytes(pr.size)} (id 0x${pr.id.toString(16).padStart(8, '0')})`], prefix ? undefined : [pr.valueOff, pr.size]);
      if (pr.id === 0x7109871a) D.schemes.push('v2');
      if (pr.id === 0xf05368c0) D.schemes.push('v3');
      if (pr.id === 0x1b93ad61) D.schemes.push('v3.1');
      if (!certDer && (pr.id === 0x7109871a || pr.id === 0xf05368c0)) { try { certDer = schemeCert(src, pr); } catch { m.warn(`The ${pr.name} block could not be read for its certificate.`); } }
    }
    for (const p of blk.problems) m.warn(p);
  });
  m.row(sT, ['v1 (JAR) signature files', v1.length || sf.length ? [...sf, ...v1].map((e) => e.name).join(', ') : 'none']);
  if (v1.length) {
    m.part(v1[0].name, () => {
      if (v1[0].size > L.maxCert) throw new Error('the file is larger than 1 MB');
      const der = pkcs7Cert(readEntry(src, v1[0], L.maxCert));
      if (der) certDer = der;
      else m.warn(`${v1[0].name}: no certificate found in the PKCS#7 data.`);
    });
  }
  if (certDer) {
    const c = certInfo(certDer);
    D.cert = c;
    m.row(sT, ['Certificate SHA-256', c.sha256]);
    m.row(sT, ['Certificate SHA-1', c.sha1]);
    if (c.subject !== undefined) m.row(sT, ['Subject', c.subject]);
    if (c.issuer !== undefined) m.row(sT, ['Issuer', c.issuer]);
    if (c.validFrom) m.row(sT, ['Valid', `${c.validFrom} to ${c.validTo}`]);
    if (c.keyType) m.row(sT, ['Key', `${c.keyType}${c.signatureAlgorithm ? `, ${c.signatureAlgorithm}` : ''}`]);
    if (c.note) m.warn(c.note);
  }
  m.row(sT, ['Note', 'Read only: APK Analyzer shows the signature data; it does not verify signatures. v4 signatures live in a separate .idsig file.']);

  // ---- summary ----
  const lines = [];
  m.title = `${kind === 'AAB' ? 'Android App Bundle' : 'Android APK'}${D.package ? ` · ${D.package}` : ''}${D.versionName ? ` ${D.versionName}` : ''}`;
  if (kind !== 'AAB' || D.package) {
    lines.push(['Package', D.package || '(not found)']);
    lines.push(['Version', `${D.versionName || '-'} (versionCode ${D.versionCode || '-'})`]);
    if (D.label) lines.push(['App label', D.label]);
    lines.push(['Min SDK', sdkText(D.minSdk) || '1 (not set)']);
    lines.push(['Target SDK', sdkText(D.targetSdk) || '(not set: same as min SDK)']);
    if (D.compileSdk) lines.push(['Compile SDK', sdkText(D.compileSdk)]);
    lines.push(['Debuggable', D.debuggable ? 'yes (android:debuggable="true")' : 'no']);
    for (const [k, v] of D.appFlags || []) lines.push([k, v]);
    const dang = permRows.filter((r) => r[1] === 'dangerous' && !String(r[2]).startsWith('implied')).length;
    lines.push(['Permissions', `${D.permissions.length} requested${dang ? `, ${dang} dangerous` : ''}`]);
    const count = (t) => D.components.filter((c) => c.type === t || (t === 'activity' && c.type === 'activity-alias'));
    const exp = (l) => l.filter((c) => c.exported.startsWith('yes')).length;
    lines.push(['Components', ['activity', 'service', 'receiver', 'provider'].map((t) => `${count(t).length} ${t === 'activity' ? (count(t).length === 1 ? 'activity' : 'activities') : t + (count(t).length === 1 ? '' : 's')} (${exp(count(t))} exported)`).join(', ')]);
  }
  lines.push(['Native ABIs', D.abis.length ? D.abis.join(', ') : 'none (no native libraries)']);
  const refs = D.dex.reduce((a, d) => a + d.methodRefs, 0);
  const maxDex = D.dex.reduce((a, d) => (d.methodRefs > a.methodRefs ? d : a), { methodRefs: 0, name: '' });
  lines.push(['DEX', D.dex.length ? `${D.dex.length} file${D.dex.length === 1 ? '' : 's'}, ${D.dex.reduce((a, d) => a + d.classes, 0).toLocaleString('en-US')} classes, ${refs.toLocaleString('en-US')} method refs (most in one file: ${maxDex.methodRefs.toLocaleString('en-US')} of 65,536 in ${maxDex.name})` : 'no DEX files']);
  lines.push(['Signing', D.schemes.length ? D.schemes.join(', ') : 'no signature found']);
  if (D.cert) lines.push(['Certificate SHA-256', D.cert.sha256]);
  lines.push(['Size', `${fmtBytes(src.size)} file, ${fmtBytes(totSize)} unpacked, ${files.length.toLocaleString('en-US')} files`]);
  m.summary = lines;
  return m;
}

function readManifest(m, root, D, permRows) {
  const a = (el, n) => { const x = attr(el, n); return x ? x.value : ''; };
  const pkg = a(root, 'package');
  D.package = pkg; D.versionCode = a(root, 'versionCode'); D.versionName = a(root, 'versionName');
  D.compileSdk = a(root, 'compileSdkVersion') || (root.attrs.find((x) => x.name === 'platformBuildVersionCode') || {}).value || '';
  const sdk = root.children.find((c) => c.tag === 'uses-sdk');
  D.minSdk = sdk ? a(sdk, 'minSdkVersion') : '';
  D.targetSdk = sdk ? a(sdk, 'targetSdkVersion') : '';
  const target = Number(D.targetSdk || D.minSdk || 1);
  const app = root.children.find((c) => c.tag === 'application');
  if (app) {
    const label = attr(app, 'label');
    if (label) D.label = label.type === 0x01 ? `${label.value} (a string resource; resources.arsc is not read)` : label.value;
    D.debuggable = a(app, 'debuggable') === 'true';
    const flags = [];
    for (const [n, title] of [['allowBackup', 'Allow backup'], ['usesCleartextTraffic', 'Cleartext traffic'], ['testOnly', 'Test only'], ['extractNativeLibs', 'Extract native libs']]) {
      const v = a(app, n);
      if (v) flags.push([title, yes(v)]);
    }
    if (a(app, 'networkSecurityConfig')) flags.push(['Network security config', a(app, 'networkSecurityConfig')]);
    D.appFlags = flags;
  }
  const full = (n) => (n.startsWith('.') ? pkg + n : n.includes('.') || !n ? n : `${pkg}.${n}`);
  const seen = new Set();
  for (const c of root.children) {
    if (c.tag === 'uses-permission' || c.tag === 'uses-permission-sdk-23' || c.tag === 'uses-permission-sdk-m') {
      const n = a(c, 'name');
      if (!n || seen.has(n)) continue;
      seen.add(n);
      D.permissions.push(n);
      const short = n.startsWith('android.permission.') ? n.slice(19) : '';
      const prot = short && DANGEROUS.has(short) ? 'dangerous' : short && SPECIAL.has(short) ? 'special access' : short ? 'normal or signature' : 'defined by an app or library';
      permRows.push([n, prot, c.tag, a(c, 'maxSdkVersion')]);
    } else if (c.tag === 'permission') {
      permRows.push([a(c, 'name'), `declared here (${a(c, 'protectionLevel') || 'normal'})`, 'permission', '']);
    }
  }
  // Android grants READ_EXTERNAL_STORAGE with WRITE_EXTERNAL_STORAGE; aapt lists it as an implied permission.
  const w = permRows.find((r) => r[0] === 'android.permission.WRITE_EXTERNAL_STORAGE');
  if (w && !seen.has('android.permission.READ_EXTERNAL_STORAGE')) permRows.push(['android.permission.READ_EXTERNAL_STORAGE', 'dangerous', 'implied by WRITE_EXTERNAL_STORAGE', w[3]]);
  if (!app) return;
  for (const c of app.children) {
    if (!COMPONENTS.includes(c.tag)) continue;
    const name = c.tag === 'activity-alias' ? `${full(a(c, 'name'))} → ${full(a(c, 'targetActivity'))}` : full(a(c, 'name'));
    const filters = c.children.filter((x) => x.tag === 'intent-filter');
    const actions = [];
    let launcher = false;
    for (const f of filters) {
      const acts = f.children.filter((x) => x.tag === 'action').map((x) => a(x, 'name'));
      const cats = f.children.filter((x) => x.tag === 'category').map((x) => a(x, 'name'));
      if (acts.includes('android.intent.action.MAIN') && cats.includes('android.intent.category.LAUNCHER')) launcher = true;
      for (const x of acts) if (actions.length < 12 && !actions.includes(x)) actions.push(x);
    }
    const ex = a(c, 'exported');
    let exported, why;
    if (ex === 'true' || ex === 'false') { exported = ex === 'true' ? 'yes' : 'no'; why = 'set in the manifest'; }
    else if (filters.length) {
      if (target < 31) { exported = 'yes'; why = `implied by an intent filter (targetSdk ${target} < 31)`; }
      else { exported = 'not set'; why = 'has an intent filter but no android:exported; Android 12+ refuses to install this'; }
    } else if (c.tag === 'provider' && target <= 16) { exported = 'yes'; why = 'default for providers when targetSdk <= 16'; }
    else { exported = 'no'; why = 'default (no intent filter)'; }
    if (launcher) why += '; launcher activity';
    if (a(c, 'enabled') === 'false') why += '; disabled';
    D.components.push({ type: c.tag, name, exported, why, permission: a(c, 'permission'), actions: actions.join(', ') });
  }
}

/** Package tree with totals: [{ n, full, classes, methods, refs, kids }] (cumulative), capped. */
function packageTree(pk, max, m) {
  const root = { n: '', full: '', classes: 0, methods: 0, refs: 0, kids: new Map() };
  let nodes = 0, cut = false;
  for (const [p, x] of pk) {
    const parts = p === '(default package)' ? [p] : p.split('.');
    let node = root;
    root.classes += x.classes; root.methods += x.methods; root.refs += x.refs;
    for (let i = 0; i < parts.length; i++) {
      let k = node.kids.get(parts[i]);
      if (!k) {
        if (nodes >= max) { cut = true; break; }
        k = { n: parts[i], full: parts.slice(0, i + 1).join('.'), classes: 0, methods: 0, refs: 0, kids: new Map() }; node.kids.set(parts[i], k); nodes++;
      }
      k.classes += x.classes; k.methods += x.methods; k.refs += x.refs;
      node = k;
    }
  }
  if (cut) m.warn(`The package tree shows the first ${max.toLocaleString('en-US')} packages; the Packages table lists them all.`);
  const conv = (n) => ({ n: n.n, full: n.full, classes: n.classes, methods: n.methods, refs: n.refs, kids: [...n.kids.values()].sort((a, b) => b.refs - a.refs).map(conv) });
  return conv(root);
}

/** Reads one entry (path may be "inner.apk!/path" one level deep) for the hex view. */
function entryBytes(src, path, fileName, limit) {
  const arc = openZip(src, {});
  const bang = path.indexOf('!/');
  if (bang > 0) {
    const outer = arc.byName.get(path.slice(0, bang));
    if (!outer) throw new Error(`There is no entry ${path.slice(0, bang)}.`);
    const isrc = innerSource(src, outer, APK_LIMITS);
    return entryBytes(isrc, path.slice(bang + 2), outer.name, limit);
  }
  const e = arc.byName.get(path);
  if (!e) throw new Error(`There is no entry ${path}.`);
  return readEntry(src, e, limit);
}

function parseApkFile(file, fileName, limits) {
  const src = Source.fromFile(file);
  try { const m = parseApk(src, fileName || file, limits); m.size = src.size; m.blocksRead = src.reads; return m; } finally { src.close(); }
}

module.exports = { parseApk, parseApkFile, entryBytes, openZip, isDex, kindOf, DANGEROUS, SPECIAL, APK_LIMITS, sdkText, fmtBytes, ZipError, ANDROID_NS, packageOf };
