'use strict';
// APK Analyzer & APK Viewer: a read-only custom editor for Android APK, AAB, APKS and XAPK files.
// The readers run in a worker thread (runner.js) with a time and memory cap, so a hostile file cannot hang or crash
// the extension host. No network: the webview gets every byte by postMessage. Pro tools (pro.js) ask only when used.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { runJob } = require('./runner');
const tools = require('./core/tools');
const { buildHtml } = require('./html');
const { createPro } = require('./pro');
const { createRatingPrompt } = require('./rate');
const { registerSupport, commandUris, showLinks } = require('./support');

const EXT_ID = 'zovo.zovo-apk-analyzer';
const PREFIX = 'apkAnalyzer';
const VIEW_TYPES = ['apkAnalyzer.apk', 'apkAnalyzer.any'];
const MAX_REMOTE_BYTES = 256 * 1024 * 1024; // non-file URIs are read into memory, up to this size
const MAX_HEX_READ = 1 << 16;
const MAX_HEX_ENTRY = 256 * 1024 * 1024;
const EXPORTS = {
  json: { label: 'Full report as JSON', ext: 'json', filter: { JSON: ['json'] } },
  md: { label: 'Report as Markdown', ext: 'md', filter: { Markdown: ['md'] } },
  csvFiles: { label: 'File sizes as CSV', ext: 'sizes.csv', filter: { CSV: ['csv'] } },
  csvMethods: { label: 'Method counts by package as CSV', ext: 'methods.csv', filter: { CSV: ['csv'] } },
};

let rating = { success() {}, failure() {} };
let pro;
const viewers = new Set();
let active = null;

function setting(key, dflt) { try { return vscode.workspace.getConfiguration(PREFIX).get(key, dflt); } catch { return dflt; } }
const baseName = (uri) => path.posix.basename(uri.path) || uri.toString();

async function remoteBuffer(uri) {
  const st = await vscode.workspace.fs.stat(uri);
  if (st.size > MAX_REMOTE_BYTES) throw new Error(`This file is ${Math.round(st.size / 1048576)} MB on a remote or virtual file system; files there are read up to 256 MB.`);
  const data = await vscode.workspace.fs.readFile(uri);
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
}

/** Parse a file (or an in-memory copy for non-file URIs) in the worker. */
async function parseUri(uri) {
  const name = baseName(uri);
  if (uri.scheme === 'file') return runJob({ op: 'parse', file: uri.fsPath, name });
  const buf = await remoteBuffer(uri);
  return runJob({ op: 'parse', buffer: buf, name }, { transfer: [buf] });
}

async function readBytes(uri, offset, length) {
  length = Math.max(0, Math.min(length, MAX_HEX_READ));
  if (uri.scheme === 'file') {
    const fh = await fs.promises.open(uri.fsPath, 'r');
    try {
      const buf = Buffer.alloc(length);
      const { bytesRead } = await fh.read(buf, 0, length, offset);
      return buf.subarray(0, bytesRead);
    } finally { await fh.close(); }
  }
  const data = await vscode.workspace.fs.readFile(uri);
  return Buffer.from(data.subarray(offset, offset + length));
}

class Viewer {
  constructor(uri, panel, context) {
    this.uri = uri; this.panel = panel; this.context = context; this.model = null; this.name = baseName(uri); this.counted = false; this.entry = null;
  }
  post(msg) { return this.panel.webview.postMessage(msg).then(undefined, () => false); }
  async load() {
    try {
      this.model = await parseUri(this.uri);
      await this.post({ type: 'model', model: this.model, name: this.name, size: this.model.size, pro: proState() });
    } catch (e) {
      const notApk = e.code === 'NOT_APK';
      if (!notApk && e.code !== 'ENOENT') rating.failure();
      await this.post({ type: 'error', message: e.message || String(e), notApk, pro: proState() });
    }
  }
  /** Unpacks one entry in the worker and keeps it for the hex view (one entry at a time). */
  async openEntry(p) {
    if (this.entry && this.entry.path === p) return this.entry;
    const job = { op: 'entry', path: p, name: this.name, limit: MAX_HEX_ENTRY };
    let r;
    if (this.uri.scheme === 'file') r = await runJob({ ...job, file: this.uri.fsPath });
    else { const buf = await remoteBuffer(this.uri); r = await runJob({ ...job, buffer: buf }, { transfer: [buf] }); }
    this.entry = { path: p, bytes: Buffer.from(r.bytes) };
    return this.entry;
  }
  async onMessage(msg) {
    if (!msg || typeof msg.type !== 'string') return;
    switch (msg.type) {
      case 'ready': return this.load();
      case 'rendered':
        if (!this.counted && this.model) { this.counted = true; rating.success(this.uri); }
        return undefined;
      case 'hexOpen': {
        const p = String(msg.entry || '');
        if (!p) return this.post({ type: 'hexTarget', entry: '', size: this.model ? this.model.size : 0 });
        try { const e = await this.openEntry(p); return this.post({ type: 'hexTarget', entry: p, size: e.bytes.length }); } catch (e) { return this.post({ type: 'hexTarget', entry: p, error: e.message }); }
      }
      case 'hex': {
        const off = Number(msg.offset);
        if (!Number.isSafeInteger(off) || off < 0) return undefined;
        const len = Math.max(0, Math.min(Number(msg.length) || 4096, MAX_HEX_READ));
        const entry = String(msg.entry || '');
        try {
          let b;
          if (entry) { const e = await this.openEntry(entry); b = e.bytes.subarray(off, off + len); } else b = await readBytes(this.uri, off, len);
          return this.post({ type: 'hex', entry, offset: off, bytes: Array.from(b) });
        } catch (e) { return this.post({ type: 'hex', entry, offset: off, bytes: [], error: e.message }); }
      }
      case 'tool': return runTool(String(msg.tool), this, msg.arg);
      case 'copy': return vscode.env.clipboard.writeText(String(msg.text || '').slice(0, 20 << 20)).then(() => vscode.window.setStatusBarMessage(msg.what ? `Copied ${msg.what}.` : 'Copied.', 3000));
      case 'openXml': {
        if (!this.model || !this.model.manifestXml) return undefined;
        const doc = await vscode.workspace.openTextDocument({ language: 'xml', content: this.model.manifestXml });
        return vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
      }
      case 'saveCompare': return saveCompare(this);
      case 'settings': return vscode.commands.executeCommand('workbench.action.openSettings', `@ext:${EXT_ID}`);
      default: return undefined;
    }
  }
}

function proState() {
  return { show: setting('showProTools', true) !== false, licensed: !!(pro && pro.licensed), tries: pro ? pro.tries() : {} };
}

class Provider {
  constructor(context) { this.context = context; }
  openCustomDocument(uri) { return { uri, dispose() {} }; }
  resolveCustomEditor(document, panel) {
    const ctx = this.context;
    const media = vscode.Uri.joinPath(ctx.extensionUri, 'media');
    panel.webview.options = { enableScripts: true, enableCommandUris: commandUris(PREFIX), localResourceRoots: [media] };
    panel.webview.html = buildHtml({
      cspSource: panel.webview.cspSource,
      scriptUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(media, 'main.js')).toString(),
      styleUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(media, 'main.css')).toString(),
      title: baseName(document.uri),
      showSupportLinks: showLinks(vscode, PREFIX),
    });
    const v = new Viewer(document.uri, panel, ctx);
    viewers.add(v);
    if (panel.active) active = v;
    panel.onDidChangeViewState(() => { if (panel.active) active = v; else if (active === v && !panel.visible) active = null; });
    panel.onDidDispose(() => { viewers.delete(v); if (active === v) active = null; v.entry = null; });
    panel.webview.onDidReceiveMessage((m) => v.onMessage(m).then(undefined, (e) => v.post({ type: 'notice', text: String(e && e.message || e) })));
  }
}

// ---------------- Pro tools ----------------

async function viewerOrPick(arg, title) {
  if (arg instanceof Viewer) return arg;
  if (arg && arg.fsPath) return { uri: arg, name: baseName(arg), model: await parseUri(arg), detached: true };
  if (active) return active;
  const pick = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: title, title: `${title}: pick an APK, AAB, APKS or XAPK file`, filters: { 'Android packages': ['apk', 'aab', 'apks', 'xapk'], 'All files': ['*'] } });
  if (!pick || !pick[0]) return null;
  return { uri: pick[0], name: baseName(pick[0]), model: await parseUri(pick[0]), detached: true };
}

async function runTool(tool, from, arg) {
  if (tool.startsWith('export')) return exportReport(from, tool.slice(7) || undefined);
  if (tool === 'compare') return compare(from);
  if (tool === 'find') return findInDex(from, arg);
  return undefined;
}

async function exportReport(from, kind) {
  if (!(await pro.allowed('export'))) return;
  let v;
  try { v = await viewerOrPick(from, 'Export'); } catch (e) { vscode.window.showWarningMessage(`Could not read the file: ${e.message}`); return; }
  if (!v || !v.model) return;
  if (!EXPORTS[kind]) {
    const p = await vscode.window.showQuickPick(Object.entries(EXPORTS).map(([k, x]) => ({ label: x.label, k })), { title: `Export the report of ${v.name}` });
    if (!p) return; // cancelled: no try used
    kind = p.k;
  }
  const x = EXPORTS[kind];
  const base = v.uri.scheme === 'file' ? vscode.Uri.file(`${v.uri.fsPath.replace(/\.(apk|aab|apks|xapk)$/i, '')}.report.${x.ext}`) : undefined;
  const target = await vscode.window.showSaveDialog({ defaultUri: base, filters: x.filter, title: `${x.label}: ${v.name}` });
  if (!target) return; // cancelled: no try used
  let text;
  if (kind === 'json') text = tools.toJson(v.model, v.name);
  else if (kind === 'md') text = tools.toMarkdown(v.model, v.name);
  else text = tools.toCsv(v.model, kind === 'csvFiles' ? 'files' : 'packages');
  if (!text) { vscode.window.showWarningMessage(`${v.name} has no ${kind === 'csvMethods' ? 'DEX method counts' : 'rows'} to export.`); return; }
  await vscode.workspace.fs.writeFile(target, Buffer.from(text, 'utf8'));
  await pro.produced('export');
  if (!/csv$/.test(x.ext)) await vscode.window.showTextDocument(target, { preview: false, viewColumn: vscode.ViewColumn.Beside });
  else vscode.window.setStatusBarMessage(`Saved ${path.posix.basename(target.path)}.`, 5000);
  refreshPro();
}

async function compare(from) {
  if (!(await pro.allowed('compare'))) return;
  let a;
  try { a = await viewerOrPick(from, 'Compare'); } catch (e) { vscode.window.showWarningMessage(`Could not read the file: ${e.message}`); return; }
  if (!a || !a.model) return;
  const pick = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: 'Compare', title: `Compare ${a.name} with...`, defaultUri: a.uri.scheme === 'file' ? vscode.Uri.file(path.dirname(a.uri.fsPath)) : undefined, filters: { 'Android packages': ['apk', 'aab', 'apks', 'xapk'], 'All files': ['*'] } });
  if (!pick || !pick[0]) return; // cancelled: no try used
  let b;
  try { b = await parseUri(pick[0]); } catch (e) { vscode.window.showWarningMessage(`${baseName(pick[0])}: ${e.message}`); return; }
  const result = tools.compareApks(a.model, b);
  const nameB = baseName(pick[0]);
  if (a instanceof Viewer) {
    a.lastCompare = { result, nameA: a.name, nameB };
    await a.post({ type: 'compare', result, nameA: a.name, nameB });
    a.panel.reveal();
  } else {
    const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: tools.compareMarkdown(result, a.name, nameB) });
    await vscode.window.showTextDocument(doc, { preview: false });
  }
  await pro.produced('compare');
  refreshPro();
}

async function saveCompare(v) {
  if (!v.lastCompare) return;
  const { result, nameA, nameB } = v.lastCompare;
  const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: tools.compareMarkdown(result, nameA, nameB) });
  await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
}

async function findInDex(from, preset) {
  if (!(await pro.allowed('find'))) return;
  let v;
  try { v = await viewerOrPick(from, 'Find'); } catch (e) { vscode.window.showWarningMessage(`Could not read the file: ${e.message}`); return; }
  if (!v || !v.model) return;
  const query = typeof preset === 'string' && preset.trim() ? preset : await vscode.window.showInputBox({
    title: `Find a class, method or string in the DEX files of ${v.name}`,
    prompt: 'Plain text matches any part of a class, method, field or string; /regex/ works too.',
    placeHolder: 'for example okhttp3, onCreate, https:// or /^com\\.example\\..*Activity$/',
    validateInput: (s) => { try { tools.matcher(s); return null; } catch (e) { return e.message; } },
  });
  if (!query || !query.trim()) return; // cancelled: no try used
  const base = v.model.data && v.model.data.set ? v.model.data.set.base : '';
  let r;
  try {
    r = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `Finding "${query}" in ${v.name}`, cancellable: false }, async (progress) => {
      const job = { op: 'find', query, base };
      const onProgress = (p) => progress.report({ message: `DEX file ${p.index + 1} of ${p.of}, ${p.hits} match${p.hits === 1 ? '' : 'es'}` });
      if (v.uri.scheme === 'file') return runJob({ ...job, file: v.uri.fsPath }, { idleMs: 30000, onProgress });
      const buf = await remoteBuffer(v.uri);
      return runJob({ ...job, buffer: buf }, { idleMs: 30000, onProgress, transfer: [buf] });
    });
  } catch (e) { vscode.window.showWarningMessage(`Find stopped: ${e.message}`); return; }
  const summary = { query, file: v.name, dexFiles: r.dexFiles, matches: r.hits.length, capped: r.hits.length >= 5000 };
  if (v instanceof Viewer) {
    await v.post({ type: 'find', results: r.hits, summary });
    v.panel.reveal();
  } else if (r.hits.length) {
    const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: [`# "${query}" in ${v.name}`, '', ...r.hits.map((h) => `- ${h.kind}: \`${h.name}\` ${h.detail} (${h.dex})`)].join('\n') });
    await vscode.window.showTextDocument(doc, { preview: false });
  } else {
    vscode.window.showInformationMessage(`No match for "${query}" in the ${r.dexFiles} DEX file${r.dexFiles === 1 ? '' : 's'} of ${v.name}.`);
  }
  if (r.hits.length) { await pro.produced('find'); refreshPro(); } // a search with no match does not use a try
}

function refreshPro() { for (const v of viewers) v.post({ type: 'pro', pro: proState() }); }

// ---------------- activation ----------------

function activate(context) {
  rating = createRatingPrompt({ vscode, context, extensionId: EXT_ID, section: PREFIX, name: 'APK Analyzer' });
  registerSupport({ vscode, context, prefix: PREFIX, selfId: EXT_ID });
  pro = createPro({ vscode, context });
  context.subscriptions.push(pro.onDidChange(() => refreshPro()));
  const provider = new Provider(context);
  for (const vt of VIEW_TYPES) {
    context.subscriptions.push(vscode.window.registerCustomEditorProvider(vt, provider, { supportsMultipleEditorsPerDocument: true, webviewOptions: { retainContextWhenHidden: true } }));
  }
  const reg = (id, fn) => context.subscriptions.push(vscode.commands.registerCommand(id, fn));
  reg(`${PREFIX}.open`, async (uri) => {
    let target = uri && uri.scheme ? uri : null;
    if (!target) {
      const p = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: 'Open', title: 'Open an APK, AAB, APKS or XAPK file', filters: { 'Android packages': ['apk', 'aab', 'apks', 'xapk'], 'All files': ['*'] } });
      if (!p || !p[0]) return;
      target = p[0];
    }
    await vscode.commands.executeCommand('vscode.openWith', target, VIEW_TYPES[1]);
  });
  reg(`${PREFIX}.openSample`, async () => {
    await vscode.commands.executeCommand('vscode.openWith', vscode.Uri.joinPath(context.extensionUri, 'samples', 'sample-zovo-notes.apk'), VIEW_TYPES[1]);
  });
  reg(`${PREFIX}.openWalkthrough`, () => vscode.commands.executeCommand('workbench.action.openWalkthrough', `${EXT_ID}#apkAnalyzer.start`, false));
  reg(`${PREFIX}.exportReport`, (uri) => exportReport(uri && uri.fsPath ? uri : active));
  reg(`${PREFIX}.compare`, (uri) => compare(uri && uri.fsPath ? uri : active));
  reg(`${PREFIX}.findInDex`, (uri) => findInDex(uri && uri.fsPath ? uri : active));
  context.subscriptions.push(vscode.window.registerUriHandler({ handleUri: (uri) => pro.handleUri(uri) }));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((e) => { if (e.affectsConfiguration(`${PREFIX}.showProTools`)) refreshPro(); }));
}

function deactivate() {}

module.exports = { activate, deactivate };
