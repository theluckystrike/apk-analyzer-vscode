'use strict';
// The shape every parser returns, and the limits that keep a hostile file from hanging or filling memory.
//
// model = {
//   format: 'ELF' | 'PE' | 'Mach-O' | 'Mach-O universal', title, template ('elf' | 'pe' | 'macho' | ''),
//   summary: [[label, value]], groups: [{ title, fields: [[name, value, offset?, size?]] }],
//   tables: [{ id, title, columns: [{ n, t }], rows: [[cell]], spans: [[offset, length] | null], key: [column indexes] }],
//   warnings: [text], slices: [{ arch, offset, size, model }] (universal Mach-O only)
// }
// Column types: 's' text, 'h' hex text ("0x1F"), 'd' decimal number.

const LIMITS = {
  maxRows: 100000,      // rows in one table (symbols of a big shared library fit; the rest is counted and named in a warning)
  maxSections: 20000,
  maxSegments: 4096,
  maxCommands: 8192,    // Mach-O load commands
  maxLibraries: 4096,
  maxThunks: 65536,     // PE import names per DLL
  maxSlices: 16,
  maxString: 4096,
  maxMs: 10000,         // parse time budget; the worker is killed at twice this
};

class Budget {
  constructor(limits = {}) {
    this.limits = { ...LIMITS, ...limits };
    this.t0 = Date.now();
    this.ticks = 0;
    this.timedOut = false;
  }
  /** True while there is time left. Checks the clock every 256 calls. */
  ok() {
    if (this.timedOut) return false;
    if ((++this.ticks & 255) === 0 && Date.now() - this.t0 > this.limits.maxMs) this.timedOut = true;
    return !this.timedOut;
  }
}

class Model {
  constructor(format, budget) {
    this.format = format;
    this.title = format;
    this.template = '';
    this.summary = [];
    this.groups = [];
    this.tables = [];
    this.warnings = [];
    this.budget = budget || new Budget();
  }
  warn(text) { if (this.warnings.length < 200 && !this.warnings.includes(text)) this.warnings.push(text); }
  group(title) { const g = { title, fields: [] }; this.groups.push(g); return g; }
  table(id, title, columns, key) {
    const t = { id, title, columns: columns.map(([n, t]) => ({ n, t })), rows: [], spans: [], key: key || [0], dropped: 0 };
    this.tables.push(t);
    return t;
  }
  /** Adds a row unless the table is full; returns false when the caller should stop adding. */
  row(t, cells, span) {
    if (t.rows.length >= this.budget.limits.maxRows) { t.dropped++; return false; }
    t.rows.push(cells);
    t.spans.push(span || null);
    return true;
  }
  /** Run one part of the parse; a Trunc or other error becomes a warning, the rest of the model stays. */
  part(name, fn) {
    try { fn(); } catch (e) { this.warn(`${name}: ${e && e.message ? e.message : String(e)}`); }
  }
  finish() {
    for (const t of this.tables) {
      if (t.dropped) this.warn(`${t.title}: showing the first ${t.rows.length.toLocaleString('en-US')} rows; ${t.dropped.toLocaleString('en-US')} more were not loaded.`);
    }
    if (this.budget.timedOut) this.warn(`Reading stopped after ${this.budget.limits.maxMs / 1000} seconds; the tables show what was read by then.`);
    delete this.budget;
    this.tables = this.tables.filter((t) => t.rows.length || t.keepEmpty);
    return this;
  }
}

/** Find a table of a model by id. */
function tableOf(model, id) { return (model.tables || []).find((t) => t.id === id) || null; }

module.exports = { LIMITS, Budget, Model, tableOf };
