'use strict';
// The Pro tools' pure parts: export a report (JSON, Markdown, CSV), compare two APK models, and the matcher for find.
// No vscode and no file system, so they run in tests and in the worker.

const VERSION_NOTE = 'APK Analyzer & APK Viewer by Zovo';
const tableOf = (m, id) => (m.tables || []).find((t) => t.id === id) || null;

function fmtBytes(n) {
  const a = Math.abs(n);
  const s = a < 1024 ? `${a} B` : a < 1048576 ? `${(a / 1024).toFixed(1)} KB` : a < 1073741824 ? `${(a / 1048576).toFixed(2)} MB` : `${(a / 1073741824).toFixed(2)} GB`;
  return n < 0 ? `-${s}` : s;
}
const signed = (n, f = (x) => x.toLocaleString('en-US')) => (n > 0 ? `+${f(n)}` : n < 0 ? `-${f(-n)}` : '0');

// ---------- export ----------

function toJsonObject(model, fileName) {
  return {
    file: fileName || '', exportedBy: VERSION_NOTE, format: model.format, title: model.title,
    summary: Object.fromEntries(model.summary || []),
    facts: model.data ? { ...model.data, files: undefined } : {},
    tables: Object.fromEntries((model.tables || []).map((t) => [t.id, t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c.n, r[i]])))])),
    manifestXml: model.manifestXml || '',
    warnings: model.warnings || [],
  };
}
function toJson(model, fileName) { return JSON.stringify(toJsonObject(model, fileName), null, 2) + '\n'; }

const mdCell = (v) => String(v === undefined || v === null ? '' : v).replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').replace(/[<>]/g, (c) => (c === '<' ? '&lt;' : '&gt;'));
function mdTable(t, max = 50, cols) {
  if (!t || !t.rows.length) return [];
  const idx = cols || t.columns.map((_, i) => i);
  const cell = (r, i) => (t.columns[i].t === 'b' ? fmtBytes(r[i]) : r[i]);
  const out = [`| ${idx.map((i) => mdCell(t.columns[i].n)).join(' | ')} |`, `| ${idx.map((i) => (t.columns[i].t === 's' ? '---' : '---:')).join(' | ')} |`];
  for (const r of t.rows.slice(0, max)) out.push(`| ${idx.map((i) => mdCell(cell(r, i))).join(' | ')} |`);
  if (t.rows.length > max) out.push('', `${(t.rows.length - max).toLocaleString('en-US')} more rows are in the JSON and CSV exports.`);
  return out;
}

/** A readable Markdown report of the whole APK. */
function toMarkdown(model, fileName) {
  const out = [`# ${mdCell(fileName || 'APK')}: ${mdCell(model.title)}`, '', `Report by ${VERSION_NOTE}.`, '', '| | |', '|---|---|'];
  for (const [k, v] of model.summary || []) out.push(`| ${mdCell(k)} | ${mdCell(v)} |`);
  const sec = (title, id, max, cols) => { const t = tableOf(model, id); if (t && t.rows.length) out.push('', `## ${title}`, '', ...mdTable(t, max, cols)); };
  sec('Permissions', 'permissions', 500);
  sec('Components', 'components', 500);
  sec('DEX files', 'dex', 200);
  sec('Method counts by package (top 100 by method references)', 'packages', 100);
  sec('Size by folder (top 40)', 'folders', 40);
  sec('Size by file type', 'types', 60);
  sec('Largest files (top 40)', 'files', 40);
  sec('Native libraries', 'natives', 50);
  sec('APKs in this package', 'inner', 100);
  sec('Signing', 'signing', 50);
  if (model.warnings && model.warnings.length) out.push('', '## Notes', '', ...model.warnings.map((w) => `- ${mdCell(w)}`));
  return out.join('\n') + '\n';
}

const csvCell = (v) => { const s = String(v === undefined || v === null ? '' : v); return /[",\r\n]/.test(s) || /^[=+\-@\t]/.test(s) ? `"${(/^[=+\-@\t]/.test(s) ? "'" : '') + s.replace(/"/g, '""')}"` : s; };
/** CSV of one table: 'files' (sizes) or 'packages' (method counts) or any table id. */
function toCsv(model, id) {
  const t = tableOf(model, id);
  if (!t) return '';
  return [t.columns.map((c) => csvCell(c.n)).join(','), ...t.rows.map((r) => r.map(csvCell).join(','))].join('\r\n') + '\r\n';
}

// ---------- compare ----------

function setDiff(a, b) {
  const A = new Set(a), Bs = new Set(b);
  return { added: [...Bs].filter((x) => !A.has(x)).sort(), removed: [...A].filter((x) => !Bs.has(x)).sort(), same: [...A].filter((x) => Bs.has(x)).length };
}

/** Compares two parsed APK models. */
function compareApks(a, b) {
  const A = a.data || {}, B = b.data || {};
  const header = [];
  const field = (name, x, y) => { if (String(x ?? '') !== String(y ?? '')) header.push({ name, a: String(x ?? ''), b: String(y ?? '') }); };
  field('Package', A.package, B.package);
  field('Version name', A.versionName, B.versionName);
  field('Version code', A.versionCode, B.versionCode);
  field('Min SDK', A.minSdk, B.minSdk);
  field('Target SDK', A.targetSdk, B.targetSdk);
  field('Compile SDK', A.compileSdk, B.compileSdk);
  field('Debuggable', A.debuggable ? 'yes' : 'no', B.debuggable ? 'yes' : 'no');
  field('Native ABIs', (A.abis || []).join(', '), (B.abis || []).join(', '));
  field('Signing schemes', (A.schemes || []).join(', '), (B.schemes || []).join(', '));
  field('Certificate SHA-256', A.cert ? A.cert.sha256 : '', B.cert ? B.cert.sha256 : '');
  const sizeA = A.fileSize || a.size || 0, sizeB = B.fileSize || b.size || 0;
  const perms = setDiff(A.permissions || [], B.permissions || []);
  const ckey = (c) => `${c.type} ${c.name}`;
  const comps = setDiff((A.components || []).map(ckey), (B.components || []).map(ckey));
  const expA = new Map((A.components || []).map((c) => [ckey(c), c.exported]));
  const exportChanged = (B.components || []).filter((c) => expA.has(ckey(c)) && expA.get(ckey(c)) !== c.exported).map((c) => ({ key: ckey(c), a: expA.get(ckey(c)), b: c.exported }));
  // files
  const fa = A.files || {}, fb = B.files || {};
  const files = [];
  for (const k of new Set([...Object.keys(fa), ...Object.keys(fb)])) {
    const x = fa[k], y = fb[k];
    const pa = x ? x[0] : 0, pb = y ? y[0] : 0;
    if (!x || !y || x[0] !== y[0] || x[1] !== y[1]) files.push({ path: k, a: pa, b: pb, delta: pb - pa, status: !x ? 'added' : !y ? 'removed' : 'changed' });
  }
  files.sort((p, q) => Math.abs(q.delta) - Math.abs(p.delta) || p.path.localeCompare(q.path));
  const folderOf = (p) => (p.includes('/') ? p.split('/')[0] + '/' : '(root files)');
  const fold = new Map();
  const addF = (files, i) => { for (const [k, v] of Object.entries(files)) { const f = folderOf(k); let x = fold.get(f); if (!x) { x = [0, 0]; fold.set(f, x); } x[i] += v[0]; } };
  addF(fa, 0); addF(fb, 1);
  const folders = [...fold].map(([folder, [x, y]]) => ({ folder, a: x, b: y, delta: y - x })).filter((f) => f.delta !== 0).sort((p, q) => Math.abs(q.delta) - Math.abs(p.delta));
  // methods per package
  const ra = A.refsByPackage || {}, rb = B.refsByPackage || {};
  const methods = [];
  for (const k of new Set([...Object.keys(ra), ...Object.keys(rb)])) { const x = ra[k] || 0, y = rb[k] || 0; if (x !== y) methods.push({ pkg: k, a: x, b: y, delta: y - x }); }
  methods.sort((p, q) => Math.abs(q.delta) - Math.abs(p.delta) || p.pkg.localeCompare(q.pkg));
  const sum = (d, k) => (d || []).reduce((s, x) => s + (x[k] || 0), 0);
  const dex = { a: { files: (A.dex || []).length, refs: sum(A.dex, 'methodRefs'), classes: sum(A.dex, 'classes') }, b: { files: (B.dex || []).length, refs: sum(B.dex, 'methodRefs'), classes: sum(B.dex, 'classes') } };
  return {
    header, size: { a: sizeA, b: sizeB, delta: sizeB - sizeA },
    permissions: perms, components: { ...comps, exportChanged },
    files: files.slice(0, 2000), filesChanged: files.length, folders, methods: methods.slice(0, 2000), methodsChanged: methods.length, dex,
    same: !header.length && !perms.added.length && !perms.removed.length && !comps.added.length && !comps.removed.length && !files.length && !methods.length,
  };
}

/** Markdown report of a comparison. */
function compareMarkdown(r, nameA, nameB) {
  const out = [`# ${mdCell(nameA)} compared with ${mdCell(nameB)}`, '', `Report by ${VERSION_NOTE}. "+" means larger or added in ${mdCell(nameB)}.`, ''];
  out.push(`File size: ${fmtBytes(r.size.a)} → ${fmtBytes(r.size.b)} (${signed(r.size.delta, fmtBytes)}). DEX method references: ${r.dex.a.refs.toLocaleString('en-US')} → ${r.dex.b.refs.toLocaleString('en-US')} (${signed(r.dex.b.refs - r.dex.a.refs)}), classes ${r.dex.a.classes.toLocaleString('en-US')} → ${r.dex.b.classes.toLocaleString('en-US')}.`, '');
  if (r.same) out.push('The two files have the same manifest facts, files and method counts.', '');
  if (r.header.length) { out.push('## Manifest and signing', '', `| Field | ${mdCell(nameA)} | ${mdCell(nameB)} |`, '|---|---|---|'); for (const h of r.header) out.push(`| ${mdCell(h.name)} | ${mdCell(h.a)} | ${mdCell(h.b)} |`); out.push(''); }
  const list = (title, d) => { if (d.added.length || d.removed.length) { out.push(`## ${title}`, ''); for (const x of d.added) out.push(`- added: ${mdCell(x)}`); for (const x of d.removed) out.push(`- removed: ${mdCell(x)}`); out.push(''); } };
  list('Permissions', r.permissions);
  list('Components', r.components);
  if (r.components.exportChanged.length) { out.push('## Exported flag changed', ''); for (const c of r.components.exportChanged) out.push(`- ${mdCell(c.key)}: ${mdCell(c.a)} → ${mdCell(c.b)}`); out.push(''); }
  if (r.folders.length) { out.push('## Size by top folder (compressed)', '', '| Folder | Before | After | Change |', '|---|---:|---:|---:|'); for (const f of r.folders.slice(0, 40)) out.push(`| ${mdCell(f.folder)} | ${fmtBytes(f.a)} | ${fmtBytes(f.b)} | ${signed(f.delta, fmtBytes)} |`); out.push(''); }
  if (r.files.length) { out.push(`## Files (${r.filesChanged.toLocaleString('en-US')} added, removed or changed; largest changes first)`, '', '| File | Status | Before | After | Change |', '|---|---|---:|---:|---:|'); for (const f of r.files.slice(0, 100)) out.push(`| ${mdCell(f.path)} | ${f.status} | ${fmtBytes(f.a)} | ${fmtBytes(f.b)} | ${signed(f.delta, fmtBytes)} |`); out.push(''); }
  if (r.methods.length) { out.push(`## Method references by package (${r.methodsChanged.toLocaleString('en-US')} packages changed)`, '', '| Package | Before | After | Change |', '|---|---:|---:|---:|'); for (const m of r.methods.slice(0, 100)) out.push(`| ${mdCell(m.pkg)} | ${m.a.toLocaleString('en-US')} | ${m.b.toLocaleString('en-US')} | ${signed(m.delta)} |`); out.push(''); }
  return out.join('\n');
}

// ---------- find ----------

/** Plain text (any part, any case) or /regex/flags with a guard against nested repeats. */
function matcher(query) {
  const q = String(query || '').trim();
  if (!q) return null;
  const re = /^\/(.{1,200})\/([imsu]*)$/.exec(q);
  if (re) {
    if (/\([^)]*[+*}][^)]*\)[+*{]/.test(re[1])) throw new Error('This pattern has a repeated group inside a repeat; please write it without nesting.');
    const rx = new RegExp(re[1], re[2]);
    return { test: (s) => s.length <= 4096 && rx.test(s), label: q };
  }
  const low = q.toLowerCase();
  return { test: (s) => s.toLowerCase().includes(low), label: q };
}

module.exports = { toJson, toJsonObject, toMarkdown, toCsv, compareApks, compareMarkdown, matcher, fmtBytes, VERSION_NOTE };
