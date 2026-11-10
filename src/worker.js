'use strict';
// Runs the readers in a worker thread, so a hostile or huge APK can never block or crash the extension host.
// The host (runner.js) kills this worker when it takes too long or uses too much memory.
const { parentPort } = require('worker_threads');
const { Source } = require('./core/source');
const { parseApk, entryBytes, openZip, isDex } = require('./core/apk');
const { readEntry } = require('./core/zip');
const { parseDex, findInDex } = require('./core/dex');
const tools = require('./core/tools');

const MAX_ENTRY = 256 * 1024 * 1024;

function sourceOf(job) {
  if (job.buffer) return Source.fromBuffer(new Uint8Array(job.buffer));
  return Source.fromFile(job.file);
}

async function run(job, progress) {
  if (job.op === 'parse') {
    const src = sourceOf(job);
    try { const m = parseApk(src, job.name || job.file || 'app.apk', job.limits); m.size = src.size; m.blocksRead = src.reads; return m; } finally { src.close(); }
  }
  if (job.op === 'entry') {
    const src = sourceOf(job);
    try {
      const b = entryBytes(src, job.path, job.name, Math.min(job.limit || MAX_ENTRY, MAX_ENTRY));
      const copy = new Uint8Array(b.length); copy.set(b);
      return { bytes: copy.buffer, size: copy.length };
    } finally { src.close(); }
  }
  if (job.op === 'find') {
    const match = tools.matcher(job.query);
    const src = sourceOf(job);
    try {
      let arc = openZip(src, {});
      let inner = src;
      // .xapk / .apks: search the base APK
      if (!arc.byName.has('AndroidManifest.xml') && job.base) {
        const e = arc.byName.get(job.base);
        if (e) { inner = Source.fromBuffer(readEntry(src, e, 300 * 1024 * 1024)); arc = openZip(inner, {}); }
      }
      const dexes = arc.zip.entries.filter((e) => !e.dir && isDex(e.name));
      const hits = [];
      for (let i = 0; i < dexes.length && hits.length < 5000; i++) {
        const d = parseDex(readEntry(inner, dexes[i], 128 * 1024 * 1024), dexes[i].name);
        hits.push(...findInDex(d, match, 5000 - hits.length));
        progress({ index: i, of: dexes.length, hits: hits.length });
      }
      return { hits, dexFiles: dexes.length };
    } finally { src.close(); }
  }
  throw new Error(`unknown job ${job.op}`);
}

parentPort.on('message', async (msg) => {
  try {
    const result = await run(msg.job, (p) => parentPort.postMessage({ id: msg.id, progress: p }));
    const transfer = result && result.bytes instanceof ArrayBuffer ? [result.bytes] : [];
    parentPort.postMessage({ id: msg.id, ok: true, result }, transfer);
  } catch (e) {
    parentPort.postMessage({ id: msg.id, ok: false, error: String((e && e.message) || e), code: e && e.code });
  }
});
