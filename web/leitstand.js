'use strict';
/* Priorität und Kategorien der Geräte, Kategorien verwalten, frei gestaltbarer Leitstand */

// ---------------------------------------------------------------------------
// Priorität und Kategorien: gemeinsame Helfer (Geräteliste, Gerät, Leitstand)
// ---------------------------------------------------------------------------

const PRIORITY = {
  high: { label: 'Wichtig', icon: 'star', rank: 0 },
  normal: { label: 'Normal', icon: 'circle-dashed', rank: 1 },
  low: { label: 'Unwichtig', icon: 'arrow-down', rank: 2 },
};
const prioRank = (p) => (PRIORITY[p] || PRIORITY.normal).rank;

const catsCache = { at: 0, list: [] };

/** Kategorien (höchstens einmal pro Minute neu laden) */
async function loadCategories(force = false) {
  if (force || Date.now() - catsCache.at > 60000) {
    catsCache.list = await api('/categories').catch(() => catsCache.list);
    catsCache.at = Date.now();
  }
  return catsCache.list;
}

const categoryById = (id) => catsCache.list.find((c) => c.id === id);

/**
 * Kategorie-Farben setzen: Die CSP verbietet style-Attribute im HTML, daher tragen Elemente die Farbe
 * als data-cat und bekommen sie hier per JavaScript (für alles, was neu ins Dokument kommt).
 */
function applyCatColors(root) {
  if (root.matches && root.matches('[data-cat]')) root.style.setProperty('--cat', root.dataset.cat);
  root.querySelectorAll('[data-cat]').forEach((el) => el.style.setProperty('--cat', el.dataset.cat));
}
new MutationObserver((mutations) => {
  mutations.forEach((m) => m.addedNodes.forEach((n) => { if (n.nodeType === 1) applyCatColors(n); }));
}).observe(document.documentElement, { childList: true, subtree: true });
/** Server liefert nur #rrggbb – trotzdem absichern, da der Wert in ein style-Attribut kommt */
const catColor = (c) => (c && /^#[0-9a-fA-F]{6}$/.test(c.color) ? c.color : '#64748b');

function categoryChip(d) {
  const c = categoryById(d.category_id);
  if (!c) return '';
  return `<span class="chip cat-chip" data-cat="${catColor(c)}" title="Kategorie${d.category_manual ? '' : ' (automatisch)'}">${icon(c.icon, 'i-sm')}${esc(c.name)}</span>`;
}

/** Stern vor dem Namen wichtiger Geräte */
const priorityMark = (d) => (d.priority === 'high' ? `<span class="prio prio-high" title="Wichtig">${icon('star', 'i-sm')}</span>` : '');
/** Hinweis hinter dem Namen unwichtiger Geräte */
const priorityChip = (d) => (d.priority === 'low' ? '<span class="chip prio-low" title="Unwichtig: Ausfall nur als Hinweis">unwichtig</span>' : '');

/** <option>-Liste der Kategorien; `auto`/`none` fügen „automatisch“ (0) bzw. „keine“ (-1) hinzu */
function categoryOptions(selected, { auto = false, none = false, autoLabel = 'Automatisch (nach Gerätetyp)' } = {}) {
  return `${auto ? `<option value="0"${selected === 0 ? ' selected' : ''}>${esc(autoLabel)}</option>` : ''}
    ${none ? `<option value="-1"${selected === -1 ? ' selected' : ''}>– keine –</option>` : ''}
    ${catsCache.list.map((c) => `<option value="${c.id}"${c.id === selected ? ' selected' : ''}>${esc(c.name)}</option>`).join('')}`;
}

const priorityOptions = (selected) => Object.entries(PRIORITY)
  .map(([k, p]) => `<option value="${k}"${k === selected ? ' selected' : ''}>${esc(p.label)}</option>`).join('');

// ---------------------------------------------------------------------------
// Kategorien verwalten
// ---------------------------------------------------------------------------

const CATEGORY_ICONS = ['category', 'server', 'server-2', 'database', 'network', 'router', 'switch-horizontal', 'access-point', 'wall',
  'device-desktop', 'device-laptop', 'device-mobile', 'device-tablet', 'wifi', 'bulb', 'device-cctv', 'camera', 'printer', 'device-tv',
  'device-speaker', 'device-gamepad-2', 'battery-charging', 'bolt', 'cpu', 'cloud', 'home-2', 'building', 'box', 'star', 'users', 'plug'];

async function viewCategories() {
  const manage = can('settings.manage');
  const render = async () => {
    const list = await loadCategories(true);
    view().innerHTML = `<div class="page-head"><p class="muted">Kategorien gruppieren Geräte, z. B. für den <a href="#/leitstand">Leitstand</a>.
        Neue Geräte landen automatisch in der Kategorie ihres Gerätetyps; am Gerät kann man das jederzeit von Hand ändern.</p>
        ${manage ? `<button type="button" id="cat-add">${icon('plus')}Kategorie anlegen</button>` : ''}</div>
      <div class="card table-wrap"><table><thead><tr><th>Kategorie</th><th>Automatisch für</th><th>Geräte</th><th></th></tr></thead>
      <tbody>${list.map((c, i) => `<tr>
        <td><span class="chip cat-chip" data-cat="${catColor(c)}">${icon(c.icon, 'i-sm')}${esc(c.name)}</span></td>
        <td class="small">${c.auto_types.length ? c.auto_types.map((t) => esc(typeInfo(t).label)).join(', ') : '<span class="muted">nur von Hand</span>'}</td>
        <td><a href="#/devices?category=${c.id}">${esc(c.device_count)}</a></td>
        <td class="actions">${manage ? `<button type="button" class="ghost sm" data-up="${i}" title="Nach oben"${i === 0 ? ' disabled' : ''}>${icon('arrow-up', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-down="${i}" title="Nach unten"${i === list.length - 1 ? ' disabled' : ''}>${icon('arrow-down', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-edit="${c.id}" title="Bearbeiten">${icon('edit', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-del="${c.id}" title="Löschen">${icon('trash', 'i-sm')}</button>` : ''}</td></tr>`).join('')}
      </tbody></table>${list.length ? '' : empty('Noch keine Kategorien.', 'category')}</div>`;
    $('#cat-add')?.addEventListener('click', () => categoryDialog(null, render));
    $$('[data-edit]').forEach((b) => b.addEventListener('click', () => categoryDialog(categoryById(Number(b.dataset.edit)), render)));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      const c = categoryById(Number(b.dataset.del));
      if (!confirm(`Kategorie „${c.name}“ löschen? Ihre Geräte bekommen wieder automatisch eine Kategorie.`)) return;
      attempt(async () => { await api(`/categories/${c.id}`, { method: 'DELETE' }); await render(); }, 'Kategorie gelöscht');
    }));
    const move = (from, to) => attempt(async () => {
      const ids = list.map((c) => c.id);
      const [id] = ids.splice(from, 1);
      ids.splice(to, 0, id);
      await api('/categories/order', { method: 'PUT', body: { ids } });
      await render();
    });
    $$('[data-up]').forEach((b) => b.addEventListener('click', () => move(Number(b.dataset.up), Number(b.dataset.up) - 1)));
    $$('[data-down]').forEach((b) => b.addEventListener('click', () => move(Number(b.dataset.down), Number(b.dataset.down) + 1)));
  };
  await render();
}

function categoryDialog(cat, after) {
  const c = cat || { name: '', icon: 'category', color: '#64748b', auto_types: [], position: (catsCache.list.length + 1) * 10 };
  // Gerätetypen, die schon eine andere Kategorie automatisch bekommt, markieren
  const owner = (t) => catsCache.list.find((x) => x.id !== c.id && x.auto_types.includes(t));
  const dlg = openModal(cat ? 'Kategorie bearbeiten' : 'Kategorie anlegen', `<form class="form" id="cat-form">
      <div class="form-row"><label>Name<input name="name" maxlength="60" required value="${esc(c.name)}" placeholder="z. B. Kameras"></label>
        <label>Farbe<input name="color" type="color" value="${esc(catColor(c))}"></label></div>
      <fieldset><legend>Symbol</legend><div class="icon-pick">${CATEGORY_ICONS.map((ic) => `<label title="${esc(ic)}"><input type="radio" name="icon" value="${esc(ic)}"${ic === c.icon ? ' checked' : ''}>${icon(ic)}</label>`).join('')}</div></fieldset>
      <fieldset><legend>Automatisch für diese Gerätetypen</legend><div class="check-grid">
        ${Object.entries(TYPES).sort((a, b) => a[1].label.localeCompare(b[1].label, 'de')).map(([k, t]) => {
          const o = owner(k);
          return `<label class="inline"><input type="checkbox" name="type" value="${k}"${c.auto_types.includes(k) ? ' checked' : ''}>
            <span>${esc(t.label)}${o ? ` <span class="muted small">(jetzt: ${esc(o.name)})</span>` : ''}</span></label>`;
        }).join('')}</div>
        <p class="hint">Ein Gerätetyp gehört automatisch zu höchstens einer Kategorie – wählst du ihn hier, wird er bei der anderen entfernt.
          Von Hand zugeordnete Geräte bleiben, wo sie sind.</p></fieldset>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
  $('#cat-form', dlg).addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const body = { name: f.get('name'), color: f.get('color'), icon: f.get('icon') || 'category', position: c.position || 0, auto_types: f.getAll('type') };
    attempt(async () => {
      await api(cat ? `/categories/${cat.id}` : '/categories', { method: cat ? 'PUT' : 'POST', body });
      dlg.close();
      await loadCategories(true);
      if (after) await after();
    }, 'Kategorie gespeichert');
  });
}

/** Priorität und/oder Kategorie für mehrere Geräte setzen */
function bulkDeviceDialog(ids, after) {
  const dlg = openModal(`${ids.length} ${ids.length === 1 ? 'Gerät' : 'Geräte'} bearbeiten`, `<form class="form" id="bulk-form">
      <label>Priorität<select name="priority"><option value="">– nicht ändern –</option>${priorityOptions('')}</select></label>
      <label>Kategorie<select name="category_id"><option value="">– nicht ändern –</option>${categoryOptions(null, { auto: true, none: true })}</select></label>
      <p class="hint">Wichtige Geräte stehen im Leitstand oben, ein Ausfall gilt als kritisch. Unwichtige Geräte melden einen Ausfall nur als Hinweis
        und machen die Sektor-Ampel nicht gelb.</p>
      <div class="actions"><button type="submit">${icon('check')}Übernehmen</button></div></form>`);
  $('#bulk-form', dlg).addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const body = { ids };
    if (f.get('priority')) body.priority = f.get('priority');
    if (f.get('category_id') !== '') body.category_id = Number(f.get('category_id'));
    if (!body.priority && body.category_id == null) { dlg.close(); return; }
    attempt(async () => {
      const r = await api('/devices/bulk-update', { method: 'POST', body });
      dlg.close();
      toast(`${r.changed} ${r.changed === 1 ? 'Gerät' : 'Geräte'} geändert`);
      if (after) await after();
    });
  });
}

// ---------------------------------------------------------------------------
// Leitstand: frei gestaltbar aus Blöcken
// ---------------------------------------------------------------------------

const LS_BLOCKS = {
  kpis: { title: 'Kennzahlen', icon: 'gauge' },
  sites: { title: 'Sektor-Ampel', icon: 'building' },
  group: { title: 'Gerätegruppe', icon: 'category' },
  problems: { title: 'Jetzt kaputt', icon: 'alert-triangle' },
};
const LS_DISPLAY = { tiles: 'Kacheln', list: 'Liste', dots: 'Ampelpunkte (kompakt)' };
const LS_CONN = { '': 'Alle Verbindungen', wireless: 'nur WLAN', wired: 'nur Kabel' };

/** Eingebaute Ansicht, solange nichts gespeichert ist */
function defaultLeitstand() {
  return [
    { type: 'kpis', width: 'full' },
    { type: 'sites', width: 'full' },
    { type: 'group', width: 'full', title: 'Wichtige Geräte', priorities: ['high'], categories: [], display: 'tiles', hide_empty: true },
    { type: 'problems', width: 'full' },
  ];
}

const blockTitle = (b) => b.title || (b.type === 'group' && b.categories && b.categories.length === 1
  ? (categoryById(b.categories[0]) || {}).name : null) || LS_BLOCKS[b.type].title;

async function viewLeitstand(_arg, params) {
  await Promise.all([loadSites(), loadCategories()]);
  const nav = state.nav;
  const kiosk = !!state.user.kiosk;
  let site = params.get('site') ? Number(params.get('site')) : null;
  let rotate = Number(params.get('rotate') || 0);
  let rotateTimer = null;
  let views = await api('/dashboards?kind=leitstand').catch(() => []);
  // Gewählte Ansicht: aus der Adresse, sonst zuletzt in diesem Browser gewählt, sonst die Standard-Ansicht
  const wanted = params.get('view') || readPref('np-ls-view', '');
  let current = views.find((v) => String(v.id) === String(wanted)) || (wanted === 'builtin' ? null : views.find((v) => v.is_default)) || null;
  let layout = current ? structuredClone(current.layout) : defaultLeitstand();
  let editing = false;
  let data = { status: null, problems: [], devices: [], uc: null };

  view().innerHTML = `<div class="ls">
    <div class="page-head ls-head">
      <div class="actions">
        <select id="ls-site" aria-label="Sektor">${siteOptions(site, { all: 'Alle Sektoren' })}</select>
        <select id="ls-view" aria-label="Ansicht"></select>
        <label class="inline small"><input type="checkbox" id="ls-rotate"${rotate ? ' checked' : ''}> Sektoren durchschalten</label>
      </div>
      <div class="actions">
        <span class="ls-clock" id="ls-clock"></span>
        <span id="ls-edit-actions"></span>
        <button type="button" class="ghost sm" id="ls-full" title="Vollbild">${icon('maximize', 'i-sm')}Vollbild</button>
      </div>
    </div>
    <div class="ls-grid" id="ls-grid"></div>
  </div>`;

  const renderViewSelect = () => {
    $('#ls-view').innerHTML = `<option value="builtin">Standard-Leitstand</option>
      ${views.map((v) => `<option value="${v.id}"${current && current.id === v.id ? ' selected' : ''}>${esc(v.name)}${v.is_default ? ' (Standard)' : ''}${v.shared ? '' : ' (privat)'}</option>`).join('')}`;
    if (!current) $('#ls-view').value = 'builtin';
    $('#ls-view').hidden = !views.length && kiosk;
  };

  const setHash = () => {
    const q = new URLSearchParams();
    if (site) q.set('site', site);
    if (rotate) q.set('rotate', rotate);
    if (current) q.set('view', current.id);
    history.replaceState(null, '', `#/leitstand${q.toString() ? `?${q}` : ''}`);
  };

  const needsDevices = () => layout.some((b) => b.type === 'group');
  const needsClients = () => layout.some((b) => b.type === 'group' && b.conn);

  const load = async () => {
    const q = site ? `?site=${site}` : '';
    const [status, problems, devices, uc] = await Promise.all([
      api(`/sites/status${q}`), api(`/problems${q}`),
      needsDevices() ? api(`/devices${q}`) : Promise.resolve([]),
      needsClients() ? loadUnifiClients() : Promise.resolve(null),
      loadCategories(),
    ]);
    data = { status, problems, devices, uc };
  };

  // ----- Blöcke -----
  const topSites = () => {
    const all = data.status.sites;
    return site ? all.filter((s) => s.id === site) : all.filter((s) => !all.some((p) => p.id === s.parent_id));
  };

  const renderKpis = () => {
    const top = topSites();
    const total = (path) => top.reduce((n, s) => n + (path.reduce((v, k) => (v ? v[k] : 0), s.rollup) || 0), 0);
    const critical = total(['alerts', 'critical']);
    const warning = total(['alerts', 'warning']);
    const down = total(['down']);
    const downRelevant = down - total(['down_low']);
    const box = (cls, value, label, ic) => `<div class="kpi ${cls}"><span class="kpi-icon">${icon(ic)}</span><div><div class="kpi-value">${esc(value)}</div><div class="kpi-label">${esc(label)}</div></div></div>`;
    return `<div class="kpis ls-kpis">
      ${box(critical ? 'k-down' : 'k-up', critical, 'kritische Alarme (offen)', 'alert-triangle')}
      ${box(warning ? 'k-warn' : 'k-up', warning, 'Warnungen (offen)', 'bell')}
      ${box(downRelevant ? 'k-down' : down ? 'k-warn' : 'k-up', `${down} / ${total(['monitored'])}`, down > downRelevant ? `Geräte offline (${down - downRelevant} unwichtig)` : 'Geräte offline', 'devices')}
      ${box(total(['checks', 'down']) ? 'k-down' : 'k-up', `${total(['checks', 'down'])} / ${total(['checks', 'total'])}`, 'Dienste gestört', 'world-www')}
      ${box('k-info', total(['alerts', 'acknowledged']), 'bestätigt, in Arbeit', 'user-check')}
    </div>`;
  };

  const renderSites = () => {
    const all = data.status.sites;
    // Bei Auswahl eines Sektors dessen direkte Unter-Sektoren (oder er selbst), sonst die obersten Sektoren
    let tiles = site ? all.filter((s) => s.parent_id === site) : all.filter((s) => !all.some((p) => p.id === s.parent_id));
    if (site && !tiles.length) tiles = all.filter((s) => s.id === site);
    if (!tiles.length) return empty('Keine Sektoren sichtbar.', 'building');
    return `<div class="ls-tiles">${tiles.map((s) => {
      const r = s.rollup;
      const own = s.own || {};
      const probe = own.probe ? `<span class="chip">${icon('antenna-bars-5', 'i-sm')}Probe ${own.probe.online ? 'online' : 'offline'}</span>` : '';
      const maint = (own.maintenance || []).length ? `<span class="chip">${icon('calendar-time', 'i-sm')}${esc(own.maintenance.join(', '))}</span>` : '';
      const hasChildren = all.some((c) => c.parent_id === s.id);
      return `<button type="button" class="ls-tile st-${esc(s.state)}" data-site="${s.id}"${hasChildren || !site ? '' : ' disabled'}>
        <span class="ls-light" aria-hidden="true"></span>
        <span class="ls-name">${esc(s.name)}</span>
        <span class="ls-state">${esc(STATE_LABEL[s.state] || s.state)}</span>
        <span class="ls-nums"><b>${r.up}</b> online · <b class="${r.down - (r.down_low || 0) ? 'down' : ''}">${r.down}</b> offline
          ${r.checks.total ? ` · Dienste ${r.checks.total - r.checks.down}/${r.checks.total}` : ''}</span>
        <span class="ls-alerts">${r.alerts.critical ? `<span class="badge sev-critical">${r.alerts.critical} kritisch</span>` : ''}
          ${r.alerts.warning ? `<span class="badge warn">${r.alerts.warning} Warnung</span>` : ''}
          ${r.alerts.acknowledged ? `<span class="badge info">${r.alerts.acknowledged} bestätigt</span>` : ''}
          ${own.avail_24h != null ? `<span class="chip">${esc(own.avail_24h)} % (24 h)</span>` : ''}${probe}${maint}</span>
      </button>`;
    }).join('')}</div>`;
  };

  const renderProblems = (b) => {
    const list = data.problems.filter((p) => !(b.hide_low && p.priority === 'low'));
    if (!list.length) return empty('Alles in Ordnung – nichts kaputt.', 'circle-check');
    const link = (p) => (kiosk ? esc(p.message) : p.device_id ? `<a href="#/device/${p.device_id}">${esc(p.message)}</a>` : p.check_id ? `<a href="#/checks">${esc(p.message)}</a>` : esc(p.message));
    return `<div class="table-wrap"><table class="ls-table">
      <thead><tr><th>Schwere</th><th>Sektor</th><th>Was</th><th>Seit</th><th>Bearbeitung</th></tr></thead>
      <tbody>${list.map((p) => `<tr class="${p.acknowledged_at ? 'acked' : `sev-${esc(p.severity)}`}">
        <td><span class="badge ${p.severity === 'critical' ? 'sev-critical' : p.severity === 'info' ? 'info' : 'warn'}">${esc(SEV_LABEL[p.severity] || p.severity)}</span></td>
        <td class="small">${esc(p.site || '–')}</td>
        <td>${p.priority === 'high' ? `<span class="prio prio-high" title="Wichtiges Gerät">${icon('star', 'i-sm')}</span>` : ''}${link(p)}
          ${p.rule ? `<div class="muted small">${esc(p.rule)}</div>` : ''}</td>
        <td class="small" title="${esc(fmtTime(p.since))}">${esc(fmtSince(p.since))}</td>
        <td>${p.kind === 'alert' && !kiosk ? ackCell({ ...p, resolved_at: null }) : p.acknowledged_at ? `<span class="badge info">${esc(p.acknowledged_by || 'bestätigt')}</span>` : ''}</td>
      </tr>`).join('')}</tbody></table></div>`;
  };

  /** Geräte, die zu einem Gerätegruppen-Block passen – gestörte zuerst, dann nach Priorität und Name */
  const groupDevices = (b) => {
    const cats = b.categories || [];
    const prios = b.priorities || [];
    return data.devices.filter((d) => {
      if (cats.length && !cats.includes(d.category_id ?? -1)) return false;
      if (prios.length && !prios.includes(d.priority)) return false;
      if (b.conn) {
        const c = data.uc && data.uc.byDevice.get(d.id);
        if (!c || c.type !== b.conn) return false;
      }
      if (b.only_problems && !(d.monitored && d.status === 'down')) return false;
      return true;
    }).sort((x, y) => (devState(x) === 'down' ? 0 : 1) - (devState(y) === 'down' ? 0 : 1)
      || prioRank(x.priority) - prioRank(y.priority) || deviceLabel(x).localeCompare(deviceLabel(y), 'de'));
  };
  const devState = (d) => (!d.monitored ? 'off' : d.paused ? 'paused' : d.status);
  const devLink = (d, inner, cls = '') => (kiosk ? `<div class="${cls}">${inner}</div>` : `<a class="${cls}" href="#/device/${d.id}">${inner}</a>`);

  const groupBody = (b, list) => {
    if (!list.length) return `<p class="muted small">${b.only_problems ? 'Alle Geräte in Ordnung.' : 'Keine passenden Geräte.'}</p>`;
    const display = LS_DISPLAY[b.display] ? b.display : 'tiles';
    if (display === 'dots') {
      return `<div class="ls-dots">${list.map((d) => devLink(d, `<span class="led ${esc(devState(d))}"></span><span class="ellipsis">${esc(deviceLabel(d))}</span>`,
        `ls-dot-dev st-${esc(devState(d))}${d.priority === 'high' ? ' is-high' : ''}`)).join('')}</div>`;
    }
    if (display === 'list') {
      return `<div class="table-wrap"><table class="ls-table"><thead><tr><th>Status</th><th>Gerät</th><th>IP</th><th>Kategorie</th><th>Seit</th></tr></thead><tbody>
        ${list.map((d) => `<tr class="${devState(d) === 'down' ? 'sev-critical' : ''}"><td>${statusBadge(d)}</td>
          <td>${priorityMark(d)}${kiosk ? esc(deviceLabel(d)) : `<a href="#/device/${d.id}">${esc(deviceLabel(d))}</a>`}${priorityChip(d)}</td>
          <td class="mono small">${esc(d.ip)}</td><td>${categoryChip(d)}</td>
          <td class="small">${esc(d.monitored ? fmtSince(d.status_since) : '–')}</td></tr>`).join('')}</tbody></table></div>`;
    }
    return `<div class="ls-devtiles">${list.map((d) => devLink(d, `
        <span class="led ${esc(devState(d))}"></span>${devIcon(d, 'sm')}
        <span class="ls-dt-name ellipsis">${esc(deviceLabel(d))}${priorityMark(d)}</span>
        <span class="ls-dt-sub mono">${esc(d.ip)}</span>
        <span class="ls-dt-state">${d.monitored ? `${d.status === 'down' ? 'offline' : d.status === 'up' ? esc(fmtMs(d.last_rtt_ms)) : 'unbekannt'} · ${esc(fmtSince(d.status_since))}` : 'nicht überwacht'}</span>`,
      `ls-devtile st-${esc(devState(d))}${d.priority === 'high' ? ' is-high' : ''}`)).join('')}</div>`;
  };

  const renderGroup = (b) => {
    const list = groupDevices(b);
    const down = list.filter((d) => devState(d) === 'down').length;
    const head = `<span class="muted small">${down ? `<b class="down">${down} offline</b> · ` : ''}${list.length} ${list.length === 1 ? 'Gerät' : 'Geräte'}</span>`;
    if (!b.split) return { head, body: groupBody(b, list), count: list.length };
    // Je Kategorie ein Abschnitt (in der Reihenfolge der Kategorien)
    const order = [...catsCache.list.map((c) => c.id), null];
    const parts = order.map((cid) => {
      const sub = list.filter((d) => (d.category_id ?? null) === cid);
      if (!sub.length) return '';
      const c = categoryById(cid);
      return `<div class="ls-sub"><h3>${c ? `<span class="chip cat-chip" data-cat="${catColor(c)}">${icon(c.icon, 'i-sm')}${esc(c.name)}</span>` : '<span class="chip">Ohne Kategorie</span>'}
        <span class="muted small">${sub.length}</span></h3>${groupBody(b, sub)}</div>`;
    }).join('');
    return { head, body: parts || groupBody(b, []), count: list.length };
  };

  const render = () => {
    if (nav !== state.nav || !data.status) return;
    const blocks = layout.map((b, i) => {
      if (!LS_BLOCKS[b.type]) return '';
      let head = '';
      let body;
      let count = 1;
      try {
        if (b.type === 'kpis') body = renderKpis();
        else if (b.type === 'sites') body = renderSites();
        else if (b.type === 'problems') {
          const n = data.problems.filter((p) => !(b.hide_low && p.priority === 'low')).length;
          head = n ? `<span class="muted small">${n} ${n === 1 ? 'Eintrag' : 'Einträge'}</span>` : '';
          body = renderProblems(b);
        } else ({ head, body, count } = renderGroup(b));
      } catch (e) { body = `<p class="error">${esc(e.message)}</p>`; }
      if (!editing && b.type === 'group' && b.hide_empty && !count) return '';
      const tools = editing ? `<div class="widget-tools">
          <button type="button" class="ghost" data-act="up" data-idx="${i}" title="Nach oben"${i === 0 ? ' disabled' : ''}>${icon('arrow-up', 'i-sm')}</button>
          <button type="button" class="ghost" data-act="down" data-idx="${i}" title="Nach unten"${i === layout.length - 1 ? ' disabled' : ''}>${icon('arrow-down', 'i-sm')}</button>
          <button type="button" class="ghost" data-act="width" data-idx="${i}" title="Breite umschalten">${b.width === 'half' ? '½' : 'ganz'}</button>
          ${b.type === 'group' || b.type === 'problems' ? `<button type="button" class="ghost" data-act="config" data-idx="${i}" title="Einstellen">${icon('settings', 'i-sm')}</button>` : ''}
          <button type="button" class="ghost" data-act="remove" data-idx="${i}" title="Entfernen">${icon('x', 'i-sm')}</button></div>` : '';
      // Kennzahlen und Sektor-Ampel ohne Rahmen (wie bisher), außer beim Gestalten
      const bare = !editing && (b.type === 'kpis' || b.type === 'sites');
      const title = `<h2>${icon(LS_BLOCKS[b.type].icon)}${esc(blockTitle(b))}</h2>`;
      return bare
        ? `<div class="ls-block ${b.width === 'half' ? 'half' : 'full'}" data-idx="${i}">${body}</div>`
        : `<section class="card ls-block ${b.width === 'half' ? 'half' : 'full'}" data-idx="${i}" draggable="${editing}">
            <header>${title}${editing ? tools : head}</header><div class="ls-block-body">${body}</div></section>`;
    }).join('');
    const grid = $('#ls-grid');
    grid.classList.toggle('editing', editing);
    grid.innerHTML = blocks || empty(editing ? 'Noch keine Blöcke – oben „Block hinzufügen“ wählen.' : 'Diese Ansicht ist leer.', 'layout-grid');
    renderEditActions();
    bindBlocks();
  };

  // ----- Gestalten -----
  const renderEditActions = () => {
    const slot = $('#ls-edit-actions');
    if (kiosk) { slot.innerHTML = ''; return; }
    slot.innerHTML = editing
      ? `<select id="ls-add" aria-label="Block hinzufügen"><option value="">+ Block hinzufügen …</option>
          ${Object.entries(LS_BLOCKS).map(([k, d]) => `<option value="${k}">${esc(d.title)}</option>`).join('')}</select>
         <button type="button" class="sm" id="ls-save">${icon('check', 'i-sm')}Speichern</button>
         <button type="button" class="ghost sm" id="ls-cancel">Abbrechen</button>
         ${current && current.editable ? `<button type="button" class="ghost sm danger-text" id="ls-delete" title="Ansicht löschen">${icon('trash', 'i-sm')}</button>` : ''}`
      : `<button type="button" class="ghost sm" id="ls-edit">${icon('layout-grid', 'i-sm')}Gestalten</button>`;
    $('#ls-edit')?.addEventListener('click', () => { editing = true; render(); });
    $('#ls-cancel')?.addEventListener('click', () => { editing = false; layout = current ? structuredClone(current.layout) : defaultLeitstand(); render(); });
    $('#ls-add')?.addEventListener('change', (ev) => {
      const type = ev.target.value;
      if (!type) return;
      const block = { type, width: 'full' };
      if (type === 'group') {
        groupDialog({ ...block, display: 'tiles', categories: [], priorities: [] }).then((cfg) => { if (cfg) layout.push(cfg); refresh().catch(() => {}); });
        return;
      }
      layout.push(block);
      render();
    });
    $('#ls-save')?.addEventListener('click', saveDialog);
    $('#ls-delete')?.addEventListener('click', () => {
      if (!confirm(`Ansicht „${current.name}“ löschen?`)) return;
      attempt(async () => {
        await api(`/dashboards/${current.id}`, { method: 'DELETE' });
        views = views.filter((v) => v.id !== current.id);
        current = null;
        layout = defaultLeitstand();
        editing = false;
        writePref('np-ls-view', '');
        renderViewSelect();
        setHash();
        await refresh();
      }, 'Ansicht gelöscht');
    });
  };

  const move = (from, to) => {
    if (to < 0 || to >= layout.length) return;
    const [b] = layout.splice(from, 1);
    layout.splice(to, 0, b);
  };

  const bindBlocks = () => {
    $$('#ls-grid [data-site]').forEach((btn) => btn.addEventListener('click', () => {
      if (editing) return;
      site = Number(btn.dataset.site);
      $('#ls-site').value = String(site);
      setHash();
      refresh().catch(() => {});
    }));
    bindAck($('#ls-grid'), refresh);
    if (!editing) return;
    $$('#ls-grid .widget-tools button').forEach((btn) => btn.addEventListener('click', () => {
      const i = Number(btn.dataset.idx);
      const act = btn.dataset.act;
      if (act === 'up') move(i, i - 1);
      if (act === 'down') move(i, i + 1);
      if (act === 'width') layout[i].width = layout[i].width === 'half' ? 'full' : 'half';
      if (act === 'remove') layout.splice(i, 1);
      if (act === 'config') {
        const dialog = layout[i].type === 'group' ? groupDialog(layout[i]) : problemsDialog(layout[i]);
        dialog.then(async (cfg) => {
          if (!cfg) return;
          layout[i] = cfg;
          if (needsDevices() && !data.devices.length) await load();
          if (needsClients() && !data.uc) await load();
          render();
        });
        return;
      }
      render();
    }));
    let dragIdx = null;
    $$('#ls-grid .ls-block').forEach((el) => {
      el.addEventListener('dragstart', () => { dragIdx = Number(el.dataset.idx); });
      el.addEventListener('dragover', (ev) => { ev.preventDefault(); el.classList.add('drag-over'); });
      el.addEventListener('dragleave', () => el.classList.remove('drag-over'));
      el.addEventListener('drop', (ev) => {
        ev.preventDefault();
        const target = Number(el.dataset.idx);
        if (dragIdx !== null && dragIdx !== target) { move(dragIdx, target); render(); }
      });
    });
  };

  const saveDialog = () => {
    const admin = can('settings.manage');
    const editable = current && current.editable;
    const dlg = openModal('Leitstand-Ansicht speichern', `<form class="form" id="lsv-form">
        <label>Name<input name="name" maxlength="80" required value="${esc(current ? current.name : 'Mein Leitstand')}" placeholder="z. B. Wandbildschirm Büro"></label>
        ${admin ? `<label class="inline"><input type="checkbox" name="shared"${!current || current.shared ? ' checked' : ''}> Für alle sichtbar</label>
          <label class="inline"><input type="checkbox" name="is_default"${!current || current.is_default ? ' checked' : ''}> Standard-Ansicht (öffnet sich beim Aufruf des Leitstands)</label>`
          : '<p class="hint">Die Ansicht ist nur für dich sichtbar. Teilen kann, wer Einstellungen verwalten darf.</p>'}
        <p class="hint">Für einen Wandbildschirm: Leitstand mit <code>?view=…</code> in der Adresse öffnen – die Adresse zeigt die Ansicht nach dem Speichern an.</p>
        <div class="actions">${editable ? `<button type="submit" name="mode" value="update">${icon('check')}Speichern</button>` : ''}
          <button type="submit" name="mode" value="new"${editable ? ' class="ghost"' : ''}>${icon('plus')}Als neue Ansicht speichern</button></div></form>`);
    $('#lsv-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      const asNew = (ev.submitter && ev.submitter.value) !== 'update';
      const body = { name: f.get('name'), layout, kind: 'leitstand', shared: f.get('shared') === 'on', is_default: f.get('is_default') === 'on', group_ids: [] };
      attempt(async () => {
        let id = current && current.id;
        if (asNew) id = (await api('/dashboards', { method: 'POST', body })).id;
        else await api(`/dashboards/${id}`, { method: 'PUT', body });
        dlg.close();
        views = await api('/dashboards?kind=leitstand');
        current = views.find((v) => v.id === id) || null;
        layout = current ? structuredClone(current.layout) : layout;
        editing = false;
        writePref('np-ls-view', current ? String(current.id) : '');
        renderViewSelect();
        setHash();
        render();
      }, 'Ansicht gespeichert');
    });
  };

  const refresh = async () => { await load(); render(); };

  // ----- Uhr, Durchschalten, Vollbild -----
  const tick = () => { const c = $('#ls-clock'); if (c) c.textContent = new Date().toLocaleString('de-DE', { weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
  tick();
  const clock = setInterval(tick, 1000);

  const startRotation = () => {
    clearInterval(rotateTimer);
    if (!rotate) return;
    rotateTimer = setInterval(() => {
      if (document.hidden || editing) return;
      const ids = [null, ...siteTree(sitesCache.list).filter(({ depth }) => depth === 0).map(({ site: s }) => s.id)];
      site = ids[(ids.indexOf(site) + 1) % ids.length];
      $('#ls-site').value = site ? String(site) : '';
      setHash();
      refresh().catch(() => {});
    }, rotate * 1000);
  };

  $('#ls-site').addEventListener('change', (ev) => { site = ev.target.value ? Number(ev.target.value) : null; setHash(); refresh().catch(() => {}); });
  $('#ls-view').addEventListener('change', (ev) => {
    if (editing && !confirm('Ungespeicherte Änderungen verwerfen?')) { renderViewSelect(); return; }
    current = views.find((v) => String(v.id) === ev.target.value) || null;
    layout = current ? structuredClone(current.layout) : defaultLeitstand();
    editing = false;
    writePref('np-ls-view', current ? String(current.id) : 'builtin');
    setHash();
    refresh().catch(() => {});
  });
  $('#ls-rotate').addEventListener('change', (ev) => { rotate = ev.target.checked ? 30 : 0; setHash(); startRotation(); });
  $('#ls-full').addEventListener('click', () => {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    else document.documentElement.requestFullscreen().catch(() => toast('Vollbild wird von diesem Browser nicht unterstützt', true));
  });

  renderViewSelect();
  setHash();
  await refresh();
  startRotation();
  // Statuswechsel, neue und bestätigte Alarme kommen live; zur Sicherheit alle 20 s neu laden
  let pending = null;
  const onLiveMsg = (msg) => {
    if (!['status', 'alert', 'ack', 'check'].includes(msg.type) || pending || editing) return;
    pending = setTimeout(() => { pending = null; refresh().catch(() => {}); }, 1500);
  };
  live.listeners.add(onLiveMsg);
  state.liveStops.push(() => { live.listeners.delete(onLiveMsg); clearInterval(clock); clearInterval(rotateTimer); clearTimeout(pending); });
  autoRefresh(async () => { if (!editing) await refresh(); }, 20);
}

/** Einstellungen eines Gerätegruppen-Blocks; liefert den neuen Block oder null */
function groupDialog(block) {
  return new Promise((resolve) => {
    const b = { categories: [], priorities: [], display: 'tiles', ...block };
    let result = null;
    const dlg = openModal('Gerätegruppe einstellen', `<form class="form" id="grp-form">
        <label>Überschrift<input name="title" maxlength="80" value="${esc(b.title || '')}" placeholder="leer = automatisch (z. B. Name der Kategorie)"></label>
        <fieldset><legend>Kategorien (keine gewählt = alle)</legend><div class="check-grid">
          ${catsCache.list.map((c) => `<label class="inline"><input type="checkbox" name="cat" value="${c.id}"${b.categories.includes(c.id) ? ' checked' : ''}>
            <span class="chip cat-chip" data-cat="${catColor(c)}">${icon(c.icon, 'i-sm')}${esc(c.name)}</span></label>`).join('')}
          <label class="inline"><input type="checkbox" name="cat" value="-1"${b.categories.includes(-1) ? ' checked' : ''}><span class="chip">Ohne Kategorie</span></label>
        </div><p class="hint"><a href="#/categories" target="_blank">Kategorien verwalten</a></p></fieldset>
        <fieldset><legend>Priorität (keine gewählt = alle)</legend><div class="stack-h">
          ${Object.entries(PRIORITY).map(([k, p]) => `<label class="inline"><input type="checkbox" name="prio" value="${k}"${b.priorities.includes(k) ? ' checked' : ''}>${esc(p.label)}</label>`).join('')}
        </div></fieldset>
        <div class="form-row"><label>Darstellung<select name="display">${Object.entries(LS_DISPLAY).map(([k, l]) => `<option value="${k}"${k === b.display ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
          <label>Verbindung<select name="conn">${Object.entries(LS_CONN).map(([k, l]) => `<option value="${k}"${k === (b.conn || '') ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select></label></div>
        <p class="hint">„Verbindung“ braucht eine Quelle für verbundene Geräte (UniFi, FRITZ!Box, OPNsense, MikroTik …).</p>
        <label class="inline"><input type="checkbox" name="only_problems"${b.only_problems ? ' checked' : ''}> Nur gestörte Geräte zeigen</label>
        <label class="inline"><input type="checkbox" name="split"${b.split ? ' checked' : ''}> Nach Kategorie unterteilen</label>
        <label class="inline"><input type="checkbox" name="hide_empty"${b.hide_empty ? ' checked' : ''}> Block ausblenden, wenn keine Geräte passen</label>
        <div class="actions"><button type="submit">${icon('check')}Übernehmen</button></div></form>`);
    $('#grp-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      result = {
        ...b,
        title: String(f.get('title') || '').trim() || undefined,
        categories: f.getAll('cat').map(Number),
        priorities: f.getAll('prio'),
        display: f.get('display'),
        conn: f.get('conn') || undefined,
        only_problems: f.get('only_problems') === 'on',
        split: f.get('split') === 'on',
        hide_empty: f.get('hide_empty') === 'on',
      };
      dlg.close();
    });
    dlg.addEventListener('close', () => resolve(result), { once: true });
  });
}

function problemsDialog(block) {
  return new Promise((resolve) => {
    let result = null;
    const dlg = openModal('„Jetzt kaputt“ einstellen', `<form class="form" id="prb-form">
        <label>Überschrift<input name="title" maxlength="80" value="${esc(block.title || '')}" placeholder="Jetzt kaputt"></label>
        <label class="inline"><input type="checkbox" name="hide_low"${block.hide_low ? ' checked' : ''}> Unwichtige Geräte ausblenden</label>
        <div class="actions"><button type="submit">${icon('check')}Übernehmen</button></div></form>`);
    $('#prb-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      result = { ...block, title: String(f.get('title') || '').trim() || undefined, hide_low: f.get('hide_low') === 'on' };
      dlg.close();
    });
    dlg.addEventListener('close', () => resolve(result), { once: true });
  });
}
