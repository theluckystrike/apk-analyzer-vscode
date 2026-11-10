// APK Analyzer & APK Viewer webview. Every value is put on the page with textContent (never as HTML), so names from
// a hostile file stay text. Bytes come from the extension host on request; nothing here talks to the network.
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');
  const ROW_H = 22, HEX_ROW_H = 20, HEX_CHUNK = 4096, MAX_SPACER = 1000000;
  const S = { model: null, name: '', size: 0, tab: 'overview', filters: {}, sorts: {}, scroll: {}, hex: { entry: '', size: 0, top: 0, chunks: new Map(), pending: new Set(), mark: null, error: '' }, compare: null, find: null, open: new Set(['']), pro: { show: true, tries: {} } };

  const h = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    // Styles go through the CSSOM (style.setProperty): the CSP has no 'unsafe-inline', so a style attribute would be dropped.
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
      else if (k === 'style') { for (const decl of String(v).split(';')) { const i = decl.indexOf(':'); if (i > 0) e.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim()); } }
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return e;
  };
  const fmtInt = (n) => Number(n).toLocaleString('en-US');
  const fmtSize = (n) => (n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`);
  const fmtDelta = (n, f = fmtInt) => (n > 0 ? `+${f(n)}` : n < 0 ? `-${f(-n)}` : '0');
  const hex8 = (n) => n.toString(16).toUpperCase().padStart(8, '0');
  const post = (m) => vscode.postMessage(m);
  const cellText = (v, t) => (t === 'b' ? (v === '' ? '' : fmtSize(Number(v))) : t === 'd' && v !== '' ? fmtInt(v) : v === '' ? '' : String(v));

  // ---------- frame ----------

  function frame(main) {
    app.textContent = '';
    const m = S.model;
    const head = h('header', { class: 'top' },
      h('div', { class: 'title' }, h('span', { class: 'fname', text: S.name }), h('span', { class: 'desc', text: m ? `${m.title} · ${fmtSize(S.size)}` : '' })),
      h('div', { class: 'actions' }, S.pro.show && m ? proButtons() : null));
    const tabs = h('nav', { class: 'tabs', role: 'tablist' }, ...tabList().map(([id, label, count]) => h('button', {
      class: 'tab' + (S.tab === id ? ' on' : ''), role: 'tab', 'aria-selected': S.tab === id ? 'true' : 'false', 'data-tab': id,
      onclick: () => { S.tab = id; render(); },
    }, label, count !== undefined ? h('span', { class: 'count', text: fmtInt(count) }) : null)));
    const foot = document.getElementById('zovo-footer');
    app.append(head, tabs, h('main', { class: 'view', id: 'view' }, main), foot ? foot.content.cloneNode(true) : '');
  }

  function proButtons() {
    const tries = (f) => (S.pro.licensed ? 'Zovo Pro' : `Zovo Pro tool, ${S.pro.tries[f] ?? 3} free tr${(S.pro.tries[f] ?? 3) === 1 ? 'y' : 'ies'} left`);
    const item = (label, tool) => h('button', { text: label, 'data-tool': tool, onclick: () => { menu.hidden = true; post({ type: 'tool', tool }); } });
    const menu = h('div', { class: 'menu', hidden: true },
      item('Full report as JSON', 'export:json'), item('Report as Markdown', 'export:md'), item('File sizes as CSV', 'export:csvFiles'), item('Method counts as CSV', 'export:csvMethods'));
    const wrap = h('span', { class: 'drop' },
      h('button', { class: 'btn', 'data-tool': 'export', title: `Save the report as JSON, Markdown or CSV (${tries('export')})`, onclick: (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; } }, 'Export ▾'), menu);
    document.addEventListener('click', () => { menu.hidden = true; }, { once: true });
    return [wrap,
      h('button', { class: 'btn', 'data-tool': 'compare', title: `Compare with another APK (${tries('compare')})`, onclick: () => post({ type: 'tool', tool: 'compare' }) }, 'Compare…'),
      h('button', { class: 'btn', 'data-tool': 'find', title: `Find a class, method or string in the DEX files (${tries('find')})`, onclick: () => post({ type: 'tool', tool: 'find' }) }, 'Find in DEX…')];
  }

  const ORDER = ['permissions', 'components', 'dex', 'packages', 'classes', 'folders', 'types', 'files', 'natives', 'inner', 'signing'];
  const SHORT = { permissions: 'Permissions', components: 'Components', dex: 'DEX', packages: 'Packages', classes: 'Classes', folders: 'Size by folder', types: 'File types', files: 'Files', natives: 'Native libs', inner: 'APKs', signing: 'Signing' };
  function tabList() {
    const m = S.model;
    if (!m) return [['overview', 'Overview']];
    const out = [['overview', 'Overview'], ['manifest', 'Manifest']];
    const tables = [...(m.tables || [])].sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
    for (const t of tables) out.push([t.id, SHORT[t.id] || t.title, t.id === 'signing' ? undefined : t.rows.length]);
    out.push(['hex', 'Hex']);
    if (S.compare) out.push(['compare', 'Compare']);
    if (S.find) out.push(['find', 'Find']);
    return out;
  }
  const tableById = (id) => (S.model.tables || []).find((t) => t.id === id);

  // ---------- views ----------

  function render() {
    if (!S.model) return;
    const ids = tabList().map((t) => t[0]);
    if (!ids.includes(S.tab)) S.tab = 'overview';
    let main;
    if (S.tab === 'overview') main = overview();
    else if (S.tab === 'manifest') main = manifestView();
    else if (S.tab === 'hex') main = hexView();
    else if (S.tab === 'compare') main = compareView();
    else if (S.tab === 'find') main = findView();
    else if (S.tab === 'packages' && S.model.tree && S.model.tree.kids.length) main = packagesView();
    else main = tableView(tableById(S.tab));
    frame(main);
    // Draw right away: requestAnimationFrame does not run in a hidden or occluded window.
    if (S.tab === 'hex') drawHex();
    if (S.afterRender) { const f = S.afterRender; S.afterRender = null; f(); }
  }

  function kv(pairs) {
    return h('table', { class: 'kv' }, h('tbody', {}, ...pairs.map(([k, v]) => h('tr', {}, h('th', { text: k }), h('td', {}, h('span', { class: 'val', text: v }))))));
  }

  function warnings(list) {
    if (!list || !list.length) return null;
    return h('div', { class: 'notice', role: 'note' }, h('b', { text: `${list.length} note${list.length === 1 ? '' : 's'} about this file` }), h('ul', {}, ...list.slice(0, 50).map((w) => h('li', { text: w }))));
  }

  function overview() {
    const m = S.model, d = m.data || {};
    const perms = tableById('permissions');
    const dang = perms ? perms.rows.filter((r) => r[1] === 'dangerous').length : 0;
    const exported = (d.components || []).filter((c) => String(c.exported).startsWith('yes')).length;
    const refs = (d.dex || []).reduce((a, x) => a + x.methodRefs, 0);
    const maxRefs = (d.dex || []).reduce((a, x) => Math.max(a, x.methodRefs), 0);
    const card = (tab, big, label, warn) => (tableById(tab) || tab === 'manifest' ? h('button', { class: 'card' + (warn ? ' warn' : ''), 'data-card': tab, onclick: () => { S.tab = tab; render(); } }, h('b', { text: big }), h('span', { text: label })) : null);
    const meter = maxRefs ? h('div', { class: 'meter', title: `The fullest DEX file uses ${fmtInt(maxRefs)} of the 65,536 method references it can address` },
      h('div', { class: 'meterbar' }, h('div', { class: 'meterfill' + (maxRefs > 58982 ? ' hot' : ''), style: `width:${Math.min(100, (maxRefs / 65536) * 100).toFixed(1)}%` })),
      h('span', { class: 'muted', text: `Fullest DEX file: ${fmtInt(maxRefs)} of 65,536 method references (${((maxRefs / 65536) * 100).toFixed(1)}%)` })) : null;
    return h('div', { class: 'pad' },
      warnings(m.warnings),
      h('h2', { text: m.title }),
      h('div', { class: 'cards' },
        card('permissions', fmtInt(d.permissions ? d.permissions.length : 0), dang ? `permissions, ${dang} dangerous` : 'permissions', dang > 0),
        card('components', fmtInt((d.components || []).length), `components, ${exported} exported`),
        card('dex', fmtInt(refs), `method refs in ${(d.dex || []).length} DEX file${(d.dex || []).length === 1 ? '' : 's'}`),
        card('folders', fmtSize(S.size), 'file size'),
        card('natives', fmtInt((d.abis || []).length), 'native ABIs')),
      meter,
      kv(m.summary || []));
  }

  function manifestView() {
    const m = S.model;
    if (!m.manifestXml) return h('div', { class: 'pad' }, h('h3', { text: 'AndroidManifest.xml' }), h('p', { class: 'muted', text: m.manifestNote || 'The manifest could not be decoded. The notes on the Overview tab say why.' }));
    const lines = m.manifestXml.split('\n');
    return h('div', { class: 'tablewrap' },
      h('div', { class: 'tools' },
        h('b', { text: 'AndroidManifest.xml' }), h('span', { class: 'muted', text: `decoded from binary XML, ${fmtInt(lines.length)} lines` }),
        h('button', { class: 'btn small', onclick: () => post({ type: 'copy', what: 'the manifest', text: m.manifestXml }) }, 'Copy'),
        h('button', { class: 'btn small', onclick: () => post({ type: 'openXml' }) }, 'Open as XML document')),
      h('pre', { class: 'xml', tabindex: '0', text: m.manifestXml }));
  }

  // ---------- package tree ----------

  function packagesView() {
    const root = S.model.tree;
    const t = tableById('packages');
    const grid = 'grid-template-columns: minmax(240px, 4fr) minmax(80px, 1fr) minmax(110px, 1fr) minmax(110px, 1fr)';
    const box = h('div', { class: 'tbody plain tree' });
    const draw = () => {
      box.textContent = '';
      let shown = 0;
      const walk = (n, depth) => {
        for (const k of n.kids) {
          if (shown++ > 5000) return;
          const has = k.kids.length > 0, open = S.open.has(k.full);
          box.append(h('div', { class: 'tr' + (has ? ' link' : ''), style: grid, 'data-pkg': k.full, onclick: () => { if (!has) return; if (open) S.open.delete(k.full); else S.open.add(k.full); draw(); } },
            h('span', { class: 'td', style: `padding-left:${8 + depth * 16}px`, title: k.full }, has ? (open ? '▾ ' : '▸ ') : '  ', k.n),
            h('span', { class: 'td num', text: fmtInt(k.classes) }), h('span', { class: 'td num', text: fmtInt(k.methods) }), h('span', { class: 'td num', text: fmtInt(k.refs) })));
          if (has && open) walk(k, depth + 1);
        }
      };
      walk(root, 0);
    };
    draw();
    return h('div', { class: 'tablewrap' },
      h('div', { class: 'tools' }, h('b', { text: 'Method counts by package' }), h('span', { class: 'muted', text: `${fmtInt(root.refs)} method refs, ${fmtInt(root.methods)} defined methods, ${fmtInt(root.classes)} classes; totals include subpackages` }),
        h('button', { class: 'btn small', onclick: () => { const all = (n) => { for (const k of n.kids) { if (k.kids.length) { S.open.add(k.full); all(k); } } }; all(root); draw(); } }, 'Expand all'),
        h('button', { class: 'btn small', onclick: () => { S.open = new Set(['']); draw(); } }, 'Collapse'),
        t ? h('button', { class: 'btn small', title: 'Copy every package with its counts, tab separated', onclick: () => post({ type: 'copy', what: `${fmtInt(t.rows.length)} packages`, text: [t.columns.map((c) => c.n).join('\t'), ...t.rows.map((r) => r.join('\t'))].join('\n') }) }, 'Copy rows') : null),
      h('div', { class: 'thead', style: grid }, h('span', { class: 'th', text: 'Package' }), h('span', { class: 'th', text: 'Classes' }), h('span', { class: 'th', text: 'Defined methods' }), h('span', { class: 'th', text: 'Method refs' })),
      box);
  }

  // ---------- tables (virtual scroll, filter, sort) ----------

  function rowsOf(t) {
    const q = (S.filters[t.id] || '').trim().toLowerCase();
    let idx = t.rows.map((_, i) => i);
    if (q) idx = idx.filter((i) => t.rows[i].some((v) => String(v).toLowerCase().includes(q)));
    const s = S.sorts[t.id];
    if (s) {
      const ty = t.columns[s.col].t;
      const key = (v) => (ty === 'd' || ty === 'b' ? Number(v) : String(v).toLowerCase());
      idx.sort((a, b) => { const x = key(t.rows[a][s.col]), y = key(t.rows[b][s.col]); return (x < y ? -1 : x > y ? 1 : 0) * s.dir; });
    }
    return idx;
  }

  const WIDE = new Set(['Name', 'Path', 'Class', 'Permission', 'Package', 'Folder', 'Value', 'Why', 'Intent filter actions', 'Libraries', 'Superclass', 'APK']);
  function tableView(t) {
    if (!t) return h('p', { class: 'pad muted', text: 'Nothing here.' });
    const idx = rowsOf(t);
    const cols = t.columns;
    const hasSpan = t.spans.some(Boolean) || !!t.entries;
    const grid = `grid-template-columns: ${cols.map((c) => (c.t === 's' && WIDE.has(c.n) ? 'minmax(160px, 3fr)' : 'minmax(80px, 1fr)')).join(' ')}${hasSpan ? ' 64px' : ''}`;
    const filter = h('input', { type: 'search', class: 'filter', placeholder: `Filter ${fmtInt(t.rows.length)} rows`, 'aria-label': 'Filter rows', value: S.filters[t.id] || '' });
    const status = h('span', { class: 'muted', text: idx.length === t.rows.length ? `${fmtInt(t.rows.length)} rows` : `${fmtInt(idx.length)} of ${fmtInt(t.rows.length)} rows` });
    const copy = h('button', { class: 'btn small', title: 'Copy the rows shown, tab separated', onclick: () => post({ type: 'copy', what: `${fmtInt(idx.length)} rows`, text: [cols.map((c) => c.n).join('\t'), ...idx.map((i) => t.rows[i].join('\t'))].join('\n') }) }, 'Copy rows');
    const head = h('div', { class: 'thead', style: grid }, ...cols.map((c, ci) => {
      const s = S.sorts[t.id];
      return h('button', { class: 'th', title: `Sort by ${c.n}`, onclick: () => { S.sorts[t.id] = s && s.col === ci ? { col: ci, dir: -s.dir } : { col: ci, dir: c.t === 's' ? 1 : -1 }; S.scroll[t.id] = 0; render(); } }, c.n, s && s.col === ci ? (s.dir > 0 ? ' ▴' : ' ▾') : '');
    }), hasSpan ? h('span', { class: 'th' }) : null);
    const body = h('div', { class: 'tbody', tabindex: '0' });
    const spacer = h('div', { class: 'spacer', style: `height:${idx.length * ROW_H}px` });
    const layer = h('div', { class: 'layer' });
    body.append(spacer, layer);
    let selected = -1;
    const draw = () => {
      const top = body.scrollTop, hgt = body.clientHeight || 600;
      const first = Math.max(0, Math.floor(top / ROW_H) - 5), last = Math.min(idx.length, Math.ceil((top + hgt) / ROW_H) + 5);
      layer.textContent = '';
      layer.style.transform = `translateY(${first * ROW_H}px)`;
      for (let k = first; k < last; k++) {
        const i = idx[k], r = t.rows[i], span = t.spans[i], entry = t.entries ? t.entries[i] : null;
        let link = hasSpan ? h('span', {}) : null;
        if (entry) link = h('a', { class: 'jump', href: '#', title: `Show the bytes of ${entry}`, onclick: (e) => { e.preventDefault(); e.stopPropagation(); openHex(entry); } }, 'hex');
        else if (span) link = h('a', { class: 'jump', href: '#', title: `${fmtInt(span[1])} bytes at 0x${span[0].toString(16).toUpperCase()}`, onclick: (e) => { e.preventDefault(); e.stopPropagation(); showBytes(span[0], span[1]); } }, 'bytes');
        const row = h('div', { class: 'tr' + (k === selected ? ' sel' : '') + (t.id === 'permissions' && r[1] === 'dangerous' ? ' danger' : ''), style: grid, onclick: () => { selected = k; draw(); } },
          ...r.map((v, ci) => h('span', { class: 'td' + (cols[ci].t !== 's' ? ' num' : ''), title: String(v).length > 30 ? String(v) : null, text: cellText(v, cols[ci].t) })), link);
        layer.append(row);
      }
    };
    body.addEventListener('scroll', () => { S.scroll[t.id] = body.scrollTop; draw(); });
    body.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'c' && selected >= 0) { post({ type: 'copy', what: 'the row', text: t.rows[idx[selected]].join('\t') }); e.preventDefault(); }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { selected = Math.max(0, Math.min(idx.length - 1, selected + (e.key === 'ArrowDown' ? 1 : -1))); const y = selected * ROW_H; if (y < body.scrollTop) body.scrollTop = y; else if (y + ROW_H > body.scrollTop + body.clientHeight) body.scrollTop = y + ROW_H - body.clientHeight; draw(); e.preventDefault(); }
    });
    let timer;
    filter.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { S.filters[t.id] = filter.value; S.scroll[t.id] = 0; S.afterRender = () => { const f = document.querySelector('.filter'); if (f) { f.focus(); f.setSelectionRange(f.value.length, f.value.length); } }; render(); }, 150); });
    const prev = S.afterRender;
    S.afterRender = () => { if (prev) prev(); body.scrollTop = S.scroll[t.id] || 0; draw(); };
    return h('div', { class: 'tablewrap' }, h('div', { class: 'tools' }, filter, status, copy, t.title !== (SHORT[t.id] || '') ? h('span', { class: 'muted ttl', text: t.title }) : null), head, body);
  }

  // ---------- hex ----------

  function setHexTarget(entry, size) {
    S.hex = { entry, size, top: 0, chunks: new Map(), pending: new Set(), mark: null, error: '', loading: false };
  }
  function openHex(entry) {
    if (S.hex.entry !== entry || S.hex.loading) { setHexTarget(entry, 0); S.hex.loading = true; post({ type: 'hexOpen', entry }); }
    S.tab = 'hex';
    render();
  }
  function showBytes(off, len) {
    if (S.hex.entry !== '') setHexTarget('', S.size);
    S.hex.size = S.size;
    S.hex.mark = [off, Math.max(1, len)];
    S.hex.top = Math.max(0, Math.floor(off / 16) - 4);
    S.tab = 'hex';
    render();
  }

  function hexView() {
    if (S.hex.entry === '' && !S.hex.loading) S.hex.size = S.size;
    const size = S.hex.size;
    const rows = Math.max(1, Math.ceil(size / 16));
    const label = S.hex.entry ? S.hex.entry : `${S.name} (the whole file)`;
    const bar = h('div', { class: 'tools' },
      h('b', { class: 'hexname', text: label }),
      S.hex.entry ? h('button', { class: 'btn small', onclick: () => { setHexTarget('', S.size); render(); } }, 'Whole file') : h('span', { class: 'muted', text: 'Pick a file on the Files tab (hex link) to see its unpacked bytes.' }));
    if (S.hex.loading) return h('div', { class: 'tablewrap' }, bar, h('p', { class: 'pad muted', text: 'Unpacking the entry...' }));
    if (S.hex.error) return h('div', { class: 'tablewrap' }, bar, h('p', { class: 'pad', text: S.hex.error }));
    const goto = h('input', { class: 'goto', placeholder: 'Go to offset (0x1F00 or 7936)', 'aria-label': 'Go to offset' });
    goto.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      const s = goto.value.trim().replace(/_/g, '');
      const n = /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) : /^[0-9]+$/.test(s) ? parseInt(s, 10) : NaN;
      if (!Number.isFinite(n) || n < 0 || n >= Math.max(1, size)) { goto.classList.add('bad'); return; }
      goto.classList.remove('bad');
      S.hex.mark = [n, 1]; S.hex.top = Math.max(0, Math.floor(n / 16) - 4); drawHex();
    });
    const box = h('div', { class: 'hexbox', id: 'hexbox', tabindex: '0' }, h('div', { class: 'spacer', style: `height:${Math.min(rows * HEX_ROW_H, MAX_SPACER)}px` }), h('div', { class: 'layer hexlayer', id: 'hexlayer' }));
    let syncing = false;
    box.addEventListener('scroll', () => {
      if (syncing) { syncing = false; return; }
      const vis = Math.floor(box.clientHeight / HEX_ROW_H);
      const max = Math.max(0, rows - vis);
      const room = Math.max(1, box.scrollHeight - box.clientHeight);
      S.hex.top = Math.round((box.scrollTop / room) * max);
      drawHex(true);
    });
    box.addEventListener('wheel', (e) => {
      if (rows * HEX_ROW_H <= MAX_SPACER) return;
      e.preventDefault();
      S.hex.top = Math.max(0, Math.min(rows - 1, S.hex.top + Math.round(e.deltaY / HEX_ROW_H)));
      drawHex();
    }, { passive: false });
    box.addEventListener('keydown', (e) => {
      const vis = Math.floor(box.clientHeight / HEX_ROW_H);
      const step = { PageDown: vis, PageUp: -vis, ArrowDown: 1, ArrowUp: -1 }[e.key];
      if (e.key === 'Home') S.hex.top = 0; else if (e.key === 'End') S.hex.top = Math.max(0, rows - vis); else if (step) S.hex.top = Math.max(0, Math.min(rows - 1, S.hex.top + step)); else return;
      e.preventDefault(); drawHex();
    });
    box._sync = (top) => {
      const vis = Math.floor(box.clientHeight / HEX_ROW_H);
      const max = Math.max(1, rows - vis);
      const room = Math.max(0, box.scrollHeight - box.clientHeight);
      const want = Math.round((top / max) * room);
      if (Math.abs(box.scrollTop - want) > 1) { syncing = true; box.scrollTop = want; }
    };
    const mark = S.hex.mark ? h('span', { class: 'muted', text: `Marked: ${fmtInt(S.hex.mark[1])} byte${S.hex.mark[1] === 1 ? '' : 's'} at 0x${S.hex.mark[0].toString(16).toUpperCase()}` }) : null;
    bar.append(goto, h('span', { class: 'muted', text: `${fmtSize(size)}, ${fmtInt(rows)} rows of 16 bytes` }), mark || '');
    return h('div', { class: 'tablewrap' }, bar, box);
  }

  function drawHex(fromScroll) {
    const box = document.getElementById('hexbox'), layer = document.getElementById('hexlayer');
    if (!box || !layer) return;
    const size = S.hex.size;
    const vis = Math.ceil(box.clientHeight / HEX_ROW_H) + 1;
    const rows = Math.max(1, Math.ceil(size / 16));
    S.hex.top = Math.max(0, Math.min(S.hex.top, Math.max(0, rows - vis + 1)));
    if (!fromScroll) box._sync(S.hex.top);
    layer.style.transform = `translateY(${box.scrollTop}px)`;
    layer.textContent = '';
    const [m0, mlen] = S.hex.mark || [-1, 0];
    for (let r = S.hex.top; r < Math.min(rows, S.hex.top + vis); r++) {
      const off = r * 16;
      const line = h('div', { class: 'hrow' }, h('span', { class: 'hoff', text: hex8(off) }));
      const hexes = h('span', { class: 'hbytes' }), ascii = h('span', { class: 'hascii' });
      let missing = false;
      for (let i = 0; i < 16; i++) {
        const o = off + i;
        if (o >= size) { hexes.append(h('span', { class: 'hb', text: '  ' })); continue; }
        const b = byteAt(o);
        if (b === undefined) { missing = true; hexes.append(h('span', { class: 'hb muted', text: '..' })); ascii.append(h('span', { text: ' ' })); continue; }
        const on = o >= m0 && o < m0 + mlen;
        hexes.append(h('span', { class: 'hb' + (on ? ' mark' : '') + (b === 0 ? ' zero' : ''), text: b.toString(16).toUpperCase().padStart(2, '0') }));
        ascii.append(h('span', { class: on ? 'mark' : '', text: b >= 32 && b < 127 ? String.fromCharCode(b) : '.' }));
      }
      line.append(hexes, ascii);
      layer.append(line);
      if (missing) need(off);
    }
  }
  function byteAt(o) { const k = Math.floor(o / HEX_CHUNK); const c = S.hex.chunks.get(k); return c ? c[o - k * HEX_CHUNK] : undefined; }
  function need(off) {
    const k = Math.floor(off / HEX_CHUNK);
    if (S.hex.chunks.has(k) || S.hex.pending.has(k)) return;
    S.hex.pending.add(k);
    post({ type: 'hex', entry: S.hex.entry, offset: k * HEX_CHUNK, length: HEX_CHUNK });
  }

  // ---------- compare / find ----------

  function compareView() {
    const { result: r, nameA, nameB } = S.compare;
    const list = (title, d) => (d.added.length || d.removed.length ? h('section', {}, h('h3', { text: `${title}: ${d.added.length} added, ${d.removed.length} removed, ${fmtInt(d.same)} the same` }),
      d.added.length ? h('ul', { class: 'diff add' }, ...d.added.slice(0, 2000).map((k) => h('li', { text: k }))) : null,
      d.removed.length ? h('ul', { class: 'diff del' }, ...d.removed.slice(0, 2000).map((k) => h('li', { text: k }))) : null) : h('p', { class: 'muted', text: `${title}: the same (${fmtInt(d.same)}).` }));
    const grid4 = 'grid-template-columns: minmax(200px, 3fr) minmax(90px, 1fr) minmax(90px, 1fr) minmax(90px, 1fr)';
    const dtable = (title, rows, key, f) => (rows.length ? h('section', {}, h('h3', { text: title }),
      h('div', { class: 'thead', style: grid4 }, h('span', { class: 'th', text: key }), h('span', { class: 'th', text: nameA }), h('span', { class: 'th', text: nameB }), h('span', { class: 'th', text: 'Change' })),
      h('div', { class: 'tbody plain short' }, ...rows.slice(0, 300).map((x) => h('div', { class: 'tr', style: grid4 }, h('span', { class: 'td', text: x.folder || x.path || x.pkg }), h('span', { class: 'td num', text: f(x.a) }), h('span', { class: 'td num', text: f(x.b) }), h('span', { class: 'td num ' + (x.delta > 0 ? 'up' : 'down'), text: fmtDelta(x.delta, f) }))))) : null);
    return h('div', { class: 'pad' },
      h('div', { class: 'tools' }, h('b', { text: `${nameA} compared with ${nameB}` }), h('button', { class: 'btn small', onclick: () => post({ type: 'saveCompare' }) }, 'Open as Markdown')),
      h('p', { text: `File size ${fmtSize(r.size.a)} → ${fmtSize(r.size.b)} (${fmtDelta(r.size.delta, fmtSize)}). Method refs ${fmtInt(r.dex.a.refs)} → ${fmtInt(r.dex.b.refs)} (${fmtDelta(r.dex.b.refs - r.dex.a.refs)}).` }),
      r.header.length ? h('section', {}, h('h3', { text: 'Manifest and signing' }), h('table', { class: 'kv' }, h('tbody', {}, ...r.header.map((x) => h('tr', {}, h('th', { text: x.name }), h('td', { text: `${x.a || '(none)'} → ${x.b || '(none)'}` })))))) : h('p', { class: 'muted', text: 'Package, versions, SDK levels, ABIs and signing are the same.' }),
      list('Permissions', r.permissions), list('Components', r.components),
      r.components.exportChanged.length ? h('section', {}, h('h3', { text: 'Exported flag changed' }), h('ul', { class: 'diff' }, ...r.components.exportChanged.map((c) => h('li', { text: `${c.key}: ${c.a} → ${c.b}` })))) : null,
      dtable('Size by top folder (compressed)', r.folders, 'Folder', fmtSize),
      dtable(`Method refs by package (${fmtInt(r.methodsChanged)} changed)`, r.methods, 'Package', fmtInt),
      dtable(`Files (${fmtInt(r.filesChanged)} added, removed or changed)`, r.files, 'File', fmtSize));
  }

  function findView() {
    const { results, summary } = S.find;
    const grid = 'grid-template-columns: 80px minmax(220px, 4fr) minmax(120px, 2fr) 110px';
    const list = h('div', { class: 'tbody plain' }, ...results.slice(0, 5000).map((r) => h('div', { class: 'tr link', style: grid, title: r.kind === 'class' || r.kind === 'method' || r.kind === 'field' ? 'Show the class on the Classes tab' : 'Copy the string', onclick: () => {
      if (r.kind === 'string') { post({ type: 'copy', what: 'the string', text: r.name }); return; }
      const cls = r.kind === 'class' ? r.name : r.name.slice(0, r.name.lastIndexOf('.'));
      S.filters.classes = cls; S.tab = 'classes'; render();
    } }, h('span', { class: 'td', text: r.kind }), h('span', { class: 'td', text: r.name }), h('span', { class: 'td', text: r.detail }), h('span', { class: 'td', text: r.dex }))));
    return h('div', { class: 'tablewrap' }, h('div', { class: 'tools' },
      h('b', { text: `${fmtInt(summary.matches)} match${summary.matches === 1 ? '' : 'es'} for "${summary.query}"` }),
      h('span', { class: 'muted', text: `in ${fmtInt(summary.dexFiles)} DEX file${summary.dexFiles === 1 ? '' : 's'}${summary.capped ? ' (first 5,000 shown)' : ''}` }),
      h('button', { class: 'btn small', onclick: () => post({ type: 'copy', what: 'the matches', text: results.map((r) => [r.kind, r.name, r.detail, r.dex].join('\t')).join('\n') }) }, 'Copy')),
    h('div', { class: 'thead', style: grid }, h('span', { class: 'th', text: 'Kind' }), h('span', { class: 'th', text: 'Name' }), h('span', { class: 'th', text: 'Detail' }), h('span', { class: 'th', text: 'DEX' })), list);
  }

  // ---------- messages ----------

  window.addEventListener('message', (e) => {
    const m = e.data || {};
    if (m.pro) S.pro = m.pro;
    if (m.type === 'model') {
      S.model = m.model; S.name = m.name; S.size = m.size || 0;
      setHexTarget('', S.size);
      if (S.model.tree) for (const k of S.model.tree.kids.slice(0, 8)) S.open.add(k.full);
      render();
      post({ type: 'rendered' });
    } else if (m.type === 'error') {
      app.textContent = '';
      app.append(h('div', { class: 'pad' }, h('h2', { text: m.notApk ? 'Not an APK file' : 'This file could not be read' }), h('p', { text: m.message }),
        h('p', { class: 'muted', text: 'APK Analyzer reads Android APK files and, where it can, AAB bundles, APKS sets and XAPK packages. All of them are ZIP archives.' })));
      const foot = document.getElementById('zovo-footer'); if (foot) app.append(foot.content.cloneNode(true));
    } else if (m.type === 'hexTarget') {
      if (m.entry !== S.hex.entry) return;
      S.hex.loading = false;
      if (m.error) S.hex.error = m.error; else S.hex.size = m.size;
      if (S.tab === 'hex') render();
    } else if (m.type === 'hex') {
      if ((m.entry || '') !== S.hex.entry) return;
      const k = Math.floor(m.offset / HEX_CHUNK);
      S.hex.pending.delete(k);
      S.hex.chunks.set(k, Uint8Array.from(m.bytes || []));
      if (S.hex.chunks.size > 512) S.hex.chunks.delete(S.hex.chunks.keys().next().value);
      if (S.tab === 'hex') drawHex(true);
    } else if (m.type === 'compare') {
      S.compare = m; S.tab = 'compare'; render();
    } else if (m.type === 'find') {
      S.find = m; S.tab = 'find'; render();
    } else if (m.type === 'pro') {
      if (S.model) render();
    } else if (m.type === 'notice') {
      const v = document.getElementById('view');
      if (v) v.prepend(h('div', { class: 'notice', text: m.text }));
    }
  });
  window.addEventListener('resize', () => { if (S.tab === 'hex') drawHex(); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden && S.model) render(); });
  post({ type: 'ready' });
}());
