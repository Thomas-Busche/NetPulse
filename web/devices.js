'use strict';
/* Geräteliste und Geräte-Detailseite */

function readPref(key, fallback) {
  try { return localStorage.getItem(key) || fallback; } catch { return fallback; }
}
function writePref(key, value) {
  try { localStorage.setItem(key, value); } catch { /* egal */ }
}

// ---------------------------------------------------------------------------
// Geräteliste
// ---------------------------------------------------------------------------

/** Gerät von Hand anlegen – z. B. außerhalb der Scan-Netze, per VPN oder im Internet */
async function addDeviceDialog() {
  const [credentials] = await Promise.all([can('credentials.manage') ? api('/credentials').catch(() => []) : [], loadSites()]);
  const kindLabel = { snmp_v2c: 'SNMP v2c', snmp_v3: 'SNMP v3', ssh_password: 'SSH (Passwort)', ssh_key: 'SSH (Schlüssel)', http: 'HTTP / Shelly', unifi: 'UniFi', fritzbox: 'FRITZ!Box', opnsense: 'OPNsense', mikrotik: 'MikroTik' };
  const dlg = openModal('Gerät hinzufügen', `<form class="form" id="add-dev-form">
      <label>IP-Adresse oder Hostname<input name="address" required autofocus maxlength="253" placeholder="z. B. 192.168.1.20 oder nas.fritz.box"></label>
      <label>Name (optional)<input name="name" maxlength="100" placeholder="z. B. NAS im Keller"></label>
      <label>Sektor<select name="site_id"><option value="">automatisch (nach Netz)</option>${siteOptions(null, { perm: 'devices.manage' })}</select></label>
      <label>Gerätetyp<select name="device_type"><option value="auto">Automatisch erkennen</option>
        ${Object.entries(TYPES).filter(([k]) => k !== 'unknown').sort((a, b) => a[1].label.localeCompare(b[1].label))
          .map(([k, t]) => `<option value="${k}">${esc(t.label)}</option>`).join('')}</select></label>
      ${credentials.length ? `<fieldset><legend>Zugangsdaten für tiefe Abfragen (optional)</legend><div class="stack-v">
        ${credentials.map((c) => `<label class="inline"><input type="checkbox" name="cred" value="${c.id}">
          <span>${esc(c.name)} <span class="muted small">· ${esc(kindLabel[c.kind] || c.kind)}${c.username ? ` · ${esc(c.username)}` : ''}</span></span></label>`).join('')}
        </div></fieldset>` : ''}
      <label>Notizen (optional)<textarea name="notes" rows="2" maxlength="2000"></textarea></label>
      <label class="inline"><input type="checkbox" name="monitored" checked> Erreichbarkeit überwachen</label>
      <p class="hint">NetPulse untersucht das Gerät gleich danach wie beim Scan (offene Ports, Name, Hersteller, Shelly)
        und fragt es mit den gewählten Zugangsdaten ab. Das Gerät muss nicht in einem freigegebenen Netz liegen.</p>
      <div class="actions"><button type="submit">${icon('plus')}Hinzufügen</button></div></form>`);
  const form = $('#add-dev-form', dlg);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = form.elements;
    const body = {
      address: e.address.value.trim(),
      name: e.name.value.trim() || null,
      device_type: e.device_type.value,
      notes: e.notes.value.trim() || null,
      monitored: e.monitored.checked,
      credential_ids: $$('input[name="cred"]:checked', form).map((c) => Number(c.value)),
      site_id: e.site_id.value ? Number(e.site_id.value) : null,
    };
    const btn = form.querySelector('button[type="submit"]');
    btn.disabled = true;
    attempt(async () => {
      const r = await api('/devices', { method: 'POST', body });
      if (r.exists) {
        toast(r.error, true);
        dlg.close();
        location.hash = `#/device/${r.id}`;
        return;
      }
      dlg.close();
      toast(`Gerät ${r.ip} angelegt – wird jetzt untersucht …`);
      location.hash = `#/device/${r.id}`;
    }).finally(() => { btn.disabled = false; });
  });
}

const SOURCE_NAMES = { unifi: 'UniFi', mikrotik: 'MikroTik', fritzbox: 'FRITZ!Box', wifi: 'WLAN-Access-Point (SSH)', opnsense: 'OPNsense', switch: 'Switch (SNMP)', router: 'ARP/DHCP' };
const sourceName = (s) => SOURCE_NAMES[s] || s;

/** Verbundene Geräte je NetPulse-Gerät (leer, wenn keine Quelle eingebunden ist) */
async function loadUnifiClients() {
  try {
    const r = await api('/clients');
    const real = (c) => c.type === 'wireless' || c.type === 'wired' || c.uplink_name || c.down_bps != null;
    return { byDevice: new Map(r.clients.filter((c) => c.device_id && real(c)).map((c) => [c.device_id, c])), all: r.clients, controllers: r.controllers };
  } catch {
    return { byDevice: new Map(), all: [], controllers: [] };
  }
}

/** Kurzfassung der Verbindung (laut Controller/Router/Switch): woran, Signal, Datenrate */
function connSummary(c, compact = false) {
  if (!c) return '';
  const wired = c.type === 'wired';
  const via = esc(c.uplink_name || (wired ? 'Kabel' : c.type === 'wireless' ? 'WLAN' : c.source_label || 'Netz'));
  const port = c.port || (c.switch_port != null ? `Port ${c.switch_port}` : null);
  const detail = wired ? esc(port || '')
    : esc([c.ssid, c.band].filter(Boolean).join(' · '));
  const rate = c.down_bps != null || c.up_bps != null ? `↓ ${esc(fmtBps(c.down_bps))} ↑ ${esc(fmtBps(c.up_bps))}` : '';
  if (compact) {
    return `<div class="conn">${icon(wired ? 'plug-connected' : c.type === 'wireless' ? 'wifi' : 'network', 'i-sm')}<span class="ellipsis">${via}</span>
      ${!wired && c.signal_dbm != null ? signalBadge(c.signal_dbm) : ''}${rate ? `<span class="conn-rate">${rate}</span>` : ''}</div>`;
  }
  return `<div class="conn-cell">${icon(wired ? 'plug-connected' : c.type === 'wireless' ? 'wifi' : 'network', 'i-sm')}<div><div class="nowrap">${via}</div>
    ${detail ? `<div class="muted small nowrap">${detail}</div>` : ''}
    ${!wired && c.signal_dbm != null ? signalBadge(c.signal_dbm) : ''}${rate ? `<div class="small nowrap muted">${rate}</div>` : ''}</div></div>`;
}

async function viewDevices(_arg, params) {
  let [devices, uc, pulse] = await Promise.all([api('/devices'), loadUnifiClients(), api('/pulse').catch(() => null), loadSites()]);
  const filters = { q: (params.get('q') || '').toLowerCase(), status: params.get('status') || '', type: params.get('type') || '', conn: params.get('conn') || '',
    site: params.get('site') ? Number(params.get('site')) : null, tag: params.get('tag') || '' };
  // Sektor inkl. Unter-Sektoren
  const siteSet = (id) => { const out = [id]; for (let i = 0; i < out.length; i += 1) sitesCache.list.filter((x) => x.parent_id === out[i]).forEach((x) => { if (!out.includes(x.id)) out.push(x.id); }); return out; };
  const tagsPresent = [...new Set(devices.flatMap((d) => d.tags || []))].sort();
  let mode = readPref('np-dev-view', 'cards');

  const typesPresent = [...new Set(devices.map((d) => d.device_type))].sort((a, b) => typeInfo(a).label.localeCompare(typeInfo(b).label));
  view().innerHTML = `
    <div class="page-head">
      <div class="actions">
        <input id="q" type="search" placeholder="Filtern: Name, IP, MAC, Hersteller, Port …" aria-label="Filtern">
        <select id="status-filter" aria-label="Status">
          <option value="">Alle Status</option><option value="up">Online</option><option value="down">Offline</option>
          <option value="unknown">Unbekannt</option><option value="unmonitored">Nicht überwacht</option><option value="new">Neu (24 h)</option>
        </select>
        <select id="type-filter" aria-label="Gerätetyp"><option value="">Alle Typen</option>
          ${typesPresent.map((t) => `<option value="${esc(t)}">${esc(typeInfo(t).label)}</option>`).join('')}</select>
        ${sitesCache.list.length > 1 ? `<select id="site-filter" aria-label="Sektor">${siteOptions(filters.site, { all: 'Alle Sektoren' })}</select>` : ''}
        ${tagsPresent.length ? `<select id="tag-filter" aria-label="Tag"><option value="">Alle Tags</option>${tagsPresent.map((t) => `<option value="${esc(t)}"${t === filters.tag ? ' selected' : ''}>#${esc(t)}</option>`).join('')}</select>` : ''}
        <span id="conn-filter-slot"></span>
      </div>
      <div class="actions"><span class="muted" id="count"></span>
        ${canAny('devices.manage') ? `<button type="button" id="dev-add">${icon('plus')}Gerät hinzufügen</button>` : ''}
        <div class="seg"><button type="button" data-mode="cards" title="Karten">${icon('layout-grid')}</button>
        <button type="button" data-mode="table" title="Tabelle">${icon('list')}</button></div></div>
    </div>
    <div id="unifi-hint"></div>
    <div id="dev-list"></div>`;
  $('#q').value = filters.q;
  $('#status-filter').value = filters.status;
  $('#type-filter').value = filters.type;

  // Verbindungs-Filter (nur mit UniFi-Controller): WLAN, Kabel oder ein bestimmter Access Point/Switch
  const renderConnFilter = () => {
    if (!uc.controllers.length) { $('#conn-filter-slot').innerHTML = ''; return; }
    const ups = [...new Map(uc.all.filter((c) => c.uplink_mac).map((c) => [c.uplink_mac, c.uplink_name || c.uplink_mac])).entries()]
      .sort((a, b) => String(a[1]).localeCompare(String(b[1]), 'de'));
    $('#conn-filter-slot').innerHTML = `<select id="conn-filter" aria-label="Verbindung"><option value="">Alle Verbindungen</option>
        <option value="wireless">nur WLAN</option><option value="wired">nur Kabel</option>
        ${ups.length ? `<optgroup label="Access Point / Switch">${ups.map(([mac, name]) => `<option value="ap:${esc(mac)}">${esc(name)}</option>`).join('')}</optgroup>` : ''}</select>`;
    $('#conn-filter').value = filters.conn;
    $('#conn-filter').addEventListener('change', (ev) => { filters.conn = ev.target.value; render(); });
  };
  // Verbundene Geräte, die NetPulse noch nicht kennt (nur aus verlässlichen Quellen) und Aufräumen übernommener
  let candidates = [];
  let importedList = [];
  const loadImportInfo = async () => {
    if (!canAny('devices.manage')) return;
    const [p, i] = await Promise.all([api('/clients/import/preview').catch(() => ({ candidates: [] })), api('/devices/imported').catch(() => ({ devices: [] }))]);
    candidates = p.candidates;
    importedList = i.devices;
  };
  const renderHint = () => {
    const cleanup = importedList.filter((d) => !d.online || d.duplicate_of);
    $('#unifi-hint').innerHTML = [
      candidates.length ? `<div class="notice info">${icon('access-point')}<span>
        Router und Controller kennen <b>${esc(candidates.length)}</b> ${candidates.length === 1 ? 'Gerät, das' : 'Geräte, die'} hier noch fehlen
        (z. B. aus anderen Netzen/VLANs, die nicht gescannt werden).</span>
        <button type="button" class="sm" id="unifi-import">${icon('list', 'i-sm')}Ansehen &amp; auswählen</button></div>` : '',
      cleanup.length ? `<div class="notice warn">${icon('alert-triangle')}<span>
        <b>${esc(cleanup.length)}</b> übernommene ${cleanup.length === 1 ? 'Gerät ist' : 'Geräte sind'} offline oder doppelt.</span>
        <button type="button" class="sm" id="imported-cleanup">${icon('trash', 'i-sm')}Aufräumen</button></div>` : '',
    ].join('');
    $('#unifi-import')?.addEventListener('click', importDialog);
    $('#imported-cleanup')?.addEventListener('click', cleanupDialog);
  };
  const reloadAll = async () => {
    [devices, uc] = await Promise.all([api('/devices'), loadUnifiClients()]);
    await loadImportInfo();
    renderHint();
    render();
  };
  const importDialog = () => {
    const dlg = openModal('Geräte übernehmen', `<form class="form" id="imp-form">
        <p class="muted small">Nur Geräte mit echter Verbindungsangabe. <b>Mögliche Doppelte</b> (gleicher Name wie ein vorhandenes Gerät,
          z. B. Handy mit wechselnder „privater WLAN-Adresse“) sind nicht vorausgewählt.</p>
        <div class="imp-tools"><button type="button" class="ghost sm" data-all="1">Alle</button><button type="button" class="ghost sm" data-all="0">Keine</button></div>
        <div class="table-wrap imp-list"><table><thead><tr><th></th><th>Name</th><th>IP / MAC</th><th>Quelle</th><th>Hinweis</th></tr></thead><tbody>
        ${candidates.map((c, i) => `<tr><td><input type="checkbox" name="pick" value="${i}"${c.possible_duplicate ? '' : ' checked'}></td>
          <td>${esc(c.name || '–')}<div class="muted small">${esc(c.vendor || '')}</div></td>
          <td class="mono small">${esc(c.ip)}<div class="muted">${esc(c.mac)}</div></td>
          <td class="small">${esc(c.source_label || '')}${c.uplink_name ? `<div class="muted">${esc(c.uplink_name)}</div>` : ''}</td>
          <td class="small">${c.possible_duplicate ? `<a href="#/device/${c.possible_duplicate.id}">schon vorhanden als ${esc(c.possible_duplicate.ip)}?</a>` : ''}</td></tr>`).join('')}
        </tbody></table></div>
        <div class="actions"><button type="submit">${icon('plus')}Ausgewählte übernehmen</button></div></form>`);
    dlg.classList.add('wide');
    const form = $('#imp-form', dlg);
    $$('[data-all]', form).forEach((b) => b.addEventListener('click', () => { $$('input[name="pick"]', form).forEach((c) => { c.checked = b.dataset.all === '1'; }); }));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const macs = $$('input[name="pick"]:checked', form).map((c) => candidates[Number(c.value)].mac);
      if (!macs.length) { dlg.close(); return; }
      attempt(async () => {
        const r = await api('/clients/import', { method: 'POST', body: { macs } });
        dlg.close();
        toast(`${r.added} ${r.added === 1 ? 'Gerät' : 'Geräte'} übernommen`);
        await reloadAll();
      });
    });
  };
  const cleanupDialog = () => {
    const dlg = openModal('Übernommene Geräte aufräumen', `<form class="form" id="cl-form">
        <p class="muted small">Alle aus Routern/Controllern übernommenen Geräte. Vorausgewählt sind Geräte, die <b>offline</b> sind oder
          ein <b>Doppel</b> eines vorhandenen Geräts (gleicher Name oder gleiche MAC). Beim Löschen gehen nur deren eigene Messwerte verloren.</p>
        <div class="imp-tools"><button type="button" class="ghost sm" data-all="1">Alle</button><button type="button" class="ghost sm" data-all="0">Keine</button></div>
        <div class="table-wrap imp-list"><table><thead><tr><th></th><th>Gerät</th><th>IP / MAC</th><th>Status</th><th>Hinweis</th></tr></thead><tbody>
        ${importedList.map((d) => `<tr><td><input type="checkbox" name="pick" value="${d.id}"${!d.online || d.duplicate_of ? ' checked' : ''}></td>
          <td><a href="#/device/${d.id}">${esc(d.label)}</a><div class="muted small">übernommen ${esc(fmtAgo(d.first_seen))}</div></td>
          <td class="mono small">${esc(d.ip)}<div class="muted">${esc(d.mac || '')}</div></td>
          <td>${d.online ? '<span class="badge st-up">online</span>' : '<span class="badge st-down">offline</span>'}</td>
          <td class="small">${d.duplicate_of ? `<a href="#/device/${d.duplicate_of}">Doppel eines vorhandenen Geräts</a>` : ''}</td></tr>`).join('')}
        </tbody></table></div>
        <div class="actions"><button type="submit" class="danger">${icon('trash')}Ausgewählte löschen</button></div></form>`);
    dlg.classList.add('wide');
    const form = $('#cl-form', dlg);
    $$('[data-all]', form).forEach((b) => b.addEventListener('click', () => { $$('input[name="pick"]', form).forEach((c) => { c.checked = b.dataset.all === '1'; }); }));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const ids = $$('input[name="pick"]:checked', form).map((c) => Number(c.value));
      if (!ids.length) { dlg.close(); return; }
      if (!confirm(`${ids.length} ${ids.length === 1 ? 'Gerät' : 'Geräte'} löschen?`)) return;
      attempt(async () => {
        const r = await api('/devices/bulk-delete', { method: 'POST', body: { ids } });
        dlg.close();
        toast(`${r.deleted} ${r.deleted === 1 ? 'Gerät' : 'Geräte'} gelöscht`);
        await reloadAll();
      });
    });
  };

  const matches = (d) => {
    if (filters.type && d.device_type !== filters.type) return false;
    if (filters.site && !siteSet(filters.site).includes(d.site_id)) return false;
    if (filters.tag && !(d.tags || []).includes(filters.tag)) return false;
    if (filters.conn) {
      const c = uc.byDevice.get(d.id);
      if (!c) return false;
      if (filters.conn.startsWith('ap:') ? c.uplink_mac !== filters.conn.slice(3) : c.type !== filters.conn) return false;
    }
    if (filters.status === 'unmonitored' && d.monitored) return false;
    if (filters.status === 'new' && Date.now() - new Date(d.first_seen).getTime() > 86400000) return false;
    if (['up', 'down', 'unknown'].includes(filters.status) && (!d.monitored || d.status !== filters.status)) return false;
    if (!filters.q) return true;
    const c = uc.byDevice.get(d.id) || {};
    const hay = [d.name, d.reported_name, d.hostname, d.ip, d.mac, d.vendor, d.os, d.model, d.notes, typeInfo(d.device_type).label, d.site_name, ...(d.tags || []),
      c.uplink_name, c.ssid, c.network, ...(d.open_ports || []).map(portLabel)].join(' ').toLowerCase();
    return hay.includes(filters.q);
  };

  const card = (d) => {
    const p = (pulse && pulse.devices && pulse.devices[d.id]) || {};
    const ports = d.open_ports || [];
    const st = !d.monitored ? 'off' : d.paused ? 'paused' : d.status;
    return `
    <a class="dev-card st-${esc(st)}" href="#/device/${d.id}">
      <div class="top">${devIcon(d)}<div class="ellipsis"><div class="name">${esc(deviceLabel(d))}${inventoryWarn(d)}</div>
        <div class="sub mono">${esc(d.ip)}</div></div><span class="led ${esc(st)}" title="${esc(STATUS_LABEL[d.status] || d.status)}"></span></div>
      <div class="dc-facts">
        <span title="MAC-Adresse">${icon('binary-tree', 'i-sm')}<span class="mono">${esc(d.mac || '–')}</span></span>
        <span title="Hersteller / System">${icon('cpu', 'i-sm')}<span>${esc([d.vendor, d.os || d.model].filter(Boolean).join(' · ') || typeInfo(d.device_type).label)}</span></span>
        ${ports.length ? `<span title="Offene Ports">${icon('plug-connected', 'i-sm')}<span class="mono">${esc(ports.slice(0, 5).join(' · '))}${ports.length > 5 ? ` +${ports.length - 5}` : ''}</span></span>` : ''}
      </div>
      ${connSummary(uc.byDevice.get(d.id), true)}
      <div class="dc-stats">
        <div><label>RTT</label><b class="mono">${esc(fmtMs(d.last_rtt_ms))}</b></div>
        <div><label>24 h</label><b class="mono av-${availTone(p.avail_24h)}">${p.avail_24h != null ? `${Number(p.avail_24h).toFixed(1)} %` : '–'}</b></div>
        <div><label>${d.status === 'down' ? 'offline' : d.status === 'up' ? 'online' : 'Status'}</label><b class="mono">${esc(d.monitored ? fmtSince(d.status_since) : '–')}</b></div>
      </div>
      <div class="dc-spark" title="Antwortzeit der letzten 2 Stunden">${spark(p.rtt, { tone: d.status === 'down' ? 'down' : 'accent', min: 0 })}</div>
      <div class="meta">${statusBadge(d)}${liveWatt(d)}${d.flapping ? '<span class="badge warn" title="Wechselt häufig zwischen online und offline">flattert</span>' : ''}<span>${d.has_credentials ? `${icon('key', 'i-sm')} ` : ''}${typeInfo(d.device_type).label}</span></div>
      ${sitesCache.list.length > 1 || (d.tags || []).length ? `<div class="dc-tags">${sitesCache.list.length > 1 ? `<span class="chip">${icon('building', 'i-sm')}${esc(d.site_name)}</span>` : ''}${(d.tags || []).map((t) => `<span class="chip">#${esc(t)}</span>`).join('')}</div>` : ''}
    </a>`;
  };

  const row = (d) => `
    <tr class="clickable${d.monitored ? '' : ' unmonitored'}" data-id="${d.id}">
      <td><div class="cell-dev">${devIcon(d, 'sm')}<div class="ellipsis"><div>${esc(deviceLabel(d))}${inventoryWarn(d)} ${liveWatt(d)}</div>
        ${(d.reported_name || d.hostname) && deviceLabel(d) !== (d.reported_name || d.hostname) ? `<div class="muted small">${esc(d.reported_name || d.hostname)}</div>` : ''}</div></div></td>
      <td>${statusBadge(d)}</td>
      <td class="mono">${esc(d.ip)}${sitesCache.list.length > 1 ? `<div class="muted small">${esc(d.site_name)}</div>` : ''}</td>
      <td><div class="mono small">${esc(d.mac || '–')}</div><div class="muted small">${esc(d.vendor || '')}</div></td>
      <td class="small">${esc(d.os || typeInfo(d.device_type).label)}</td>
      ${hasConn() ? `<td class="small">${connSummary(uc.byDevice.get(d.id))}</td>` : ''}
      <td>${portChips(d.open_ports)}</td>
      <td>${esc(fmtMs(d.last_rtt_ms))}</td>
      <td title="${esc(fmtTime(d.last_seen))}">${esc(fmtAgo(d.last_seen))}</td>
    </tr>`;

  const hasConn = () => uc.byDevice.size > 0;

  const render = () => {
    const shown = devices.filter(matches);
    $$('.seg button').forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
    $('#count').textContent = `${shown.length} von ${devices.length} Geräten`;
    if (!shown.length) {
      $('#dev-list').innerHTML = `<div class="card">${empty(devices.length ? 'Keine Geräte passen zum Filter.' : 'Noch keine Geräte – unter „Netzwerke“ ein Netz freigeben oder oben „Gerät hinzufügen“.', 'devices')}</div>`;
    } else if (mode === 'cards') {
      $('#dev-list').innerHTML = `<div class="dev-grid">${shown.map(card).join('')}</div>`;
    } else {
      $('#dev-list').innerHTML = `<div class="card table-wrap"><table>
        <thead><tr><th>Gerät</th><th>Status</th><th>IP</th><th>MAC / Hersteller</th><th>System</th>${hasConn() ? '<th>Verbindung</th>' : ''}<th>Dienste</th><th>Antwort</th><th>Gesehen</th></tr></thead>
        <tbody>${shown.map(row).join('')}</tbody></table></div>`;
    }
  };

  $('#q').addEventListener('input', (ev) => { filters.q = ev.target.value.trim().toLowerCase(); render(); });
  $('#status-filter').addEventListener('change', (ev) => { filters.status = ev.target.value; render(); });
  $('#type-filter').addEventListener('change', (ev) => { filters.type = ev.target.value; render(); });
  $('#site-filter')?.addEventListener('change', (ev) => { filters.site = ev.target.value ? Number(ev.target.value) : null; render(); });
  $('#tag-filter')?.addEventListener('change', (ev) => { filters.tag = ev.target.value; render(); });
  $$('.seg button').forEach((b) => b.addEventListener('click', () => { mode = b.dataset.mode; writePref('np-dev-view', mode); render(); }));
  $('#dev-add')?.addEventListener('click', addDeviceDialog);
  if (params.get('add') === '1' && canAny('devices.manage')) addDeviceDialog();
  $('#dev-list').addEventListener('click', (ev) => {
    const tr = ev.target.closest('tr[data-id]');
    if (tr) location.hash = `#/device/${tr.dataset.id}`;
  });
  renderConnFilter();
  render();
  loadImportInfo().then(renderHint);
  autoRefresh(async () => { [devices, uc] = await Promise.all([api('/devices'), loadUnifiClients()]); render(); });
  // Nach jeder Minuten-Abfrage des UniFi-Controllers Signal und Datenraten nachführen
  onLive(async (msg) => {
    if (msg.type !== 'unifi' || isEditing()) return;
    uc = await loadUnifiClients();
    render();
  });
  // Leistung der Shellys laufend nachführen, ohne die Liste neu aufzubauen
  onLive((msg) => {
    if (msg.type !== 'shelly') return;
    (msg.devices || []).forEach((d) => {
      $$(`[data-watt="${d.id}"]`).forEach((el) => {
        el.textContent = d.ok && d.power_w != null ? fmtWatt(d.power_w) : '';
        el.classList.add('flash');
        setTimeout(() => el.classList.remove('flash'), 700);
      });
    });
  });
}

/** Warnsymbol, wenn die tiefe Abfrage zuletzt fehlschlug (Details im Tab „Diagnose“) */
function inventoryWarn(d) {
  return d.inventory_error ? ` <span class="warn-ic" title="${esc(d.inventory_error)}">${icon('alert-triangle', 'i-sm')}</span>` : '';
}

/** Aktuelle Leistung aus dem Live-Stream (nur Geräte mit Strommessung) */
function liveWatt(d) {
  if (d.integration !== 'shelly') return '';
  const l = live.devices.get(d.id);
  return `<span class="live-watt" data-watt="${d.id}">${l && l.ok && l.power_w != null ? esc(fmtWatt(l.power_w)) : ''}</span>`;
}

/** Was der UniFi-Controller über diesen Client weiß (Verbindung, WLAN, Datenraten) */
function unifiClientBlock(uc) {
  const wired = uc.type === 'wired';
  const via = uc.uplink_device_id ? `<a href="#/device/${uc.uplink_device_id}">${esc(uc.uplink_name || uc.uplink_mac)}</a>` : esc(uc.uplink_name || uc.uplink_mac || '–');
  const rows = [];
  const add = (label, html) => { if (html != null && html !== '') rows.push(`<dt>${esc(label)}</dt><dd>${html}</dd>`); };
  const port = uc.port || (uc.switch_port != null ? `Port ${uc.switch_port}` : null);
  if (uc.uplink_name || uc.uplink_mac) add('Verbunden über', `${via}${port ? ` · ${esc(port)}` : ''}`);
  if (!wired) {
    add('WLAN', esc([uc.ssid, uc.band, uc.channel != null ? `Kanal ${uc.channel}` : null, uc.wifi_standard].filter(Boolean).join(' · ')));
    add('Signal', uc.signal_pct != null ? `${signalBadge(uc.signal_dbm, true)} <span class="muted small">(${esc(uc.signal_pct)} % laut FRITZ!Box, dBm geschätzt)</span>`
      : uc.signal_dbm != null ? signalBadge(uc.signal_dbm, true) : null);
    add('Verbindungsqualität', uc.satisfaction != null ? `${esc(Math.round(uc.satisfaction))} % <span class="muted small">(Bewertung von UniFi)</span>` : null);
    add('Verbindungsgeschwindigkeit', uc.link_down_kbps != null ? `↓ ${esc(fmtBps(uc.link_down_kbps * 1000))} · ↑ ${esc(fmtBps((uc.link_up_kbps || 0) * 1000))}` : null);
  }
  add('Datenrate gerade', uc.down_bps != null || uc.up_bps != null ? `↓ ${esc(fmtBps(uc.down_bps))} · ↑ ${esc(fmtBps(uc.up_bps))}` : null);
  add('Übertragen (seit Verbindung)', uc.down_bytes != null ? `↓ ${esc(fmtBytes(uc.down_bytes))} · ↑ ${esc(fmtBytes(uc.up_bytes || 0))}` : null);
  add('Netz / VLAN', esc([uc.network, uc.vlan ? `VLAN ${uc.vlan}` : null, uc.guest ? 'Gastnetz' : null].filter(Boolean).join(' · ')));
  add('Verbunden seit', uc.connected_at ? esc(fmtTime(uc.connected_at)) : null);
  add('Name laut Netz', esc(uc.name || uc.hostname || ''));
  add('Quellen', (uc.sources || []).map((s) => esc(sourceName(s.source))).filter((v, i, a) => a.indexOf(v) === i).join(', '));
  const kind = wired ? 'Kabel-Verbindung' : uc.type === 'wireless' ? 'WLAN-Verbindung' : 'Im Netz';
  return `<header><h2>${icon(wired ? 'plug-connected' : uc.type === 'wireless' ? 'wifi' : 'network')}${kind} laut ${esc(uc.source_label || 'Netz')}</h2>
      ${uc.source_id ? `<a class="small" href="#/device/${uc.source_id}">Quelle</a>` : ''}</header>
    <dl class="details">${rows.join('')}</dl>`;
}

// ---------------------------------------------------------------------------
// Geräte-Detailseite
// ---------------------------------------------------------------------------

async function viewDevice(id) {
  let hours = 24;
  let tab = 'overview';
  const clientFilter = { q: '', kind: '', ap: '', sort: 'down', dir: -1 };
  let data = await api(`/devices/${encodeURIComponent(id)}?hours=${hours}`);
  // Rechte gelten je Sektor – maßgeblich ist der Sektor dieses Geräts
  const canDev = (perm) => can(perm, data.device.site_id);
  const credentials = can('credentials.manage') ? await api('/credentials').catch(() => []) : [];
  const allDevices = canDev('devices.manage') ? await api('/devices').catch(() => []) : [];
  await loadSites();

  const tabs = () => {
    const inv = data.inventory || {};
    const list = [['overview', 'Übersicht']];
    // Live: Shelly über den Echtzeit-Stream, sonst Datenraten per SNMP/SSH (Netzwerk-Schnittstellen)
    if (isShelly()) list.push(['live', 'Live']);
    else if (data.device.has_credentials && (inv.snmp || inv.ssh)) list.push(['live', 'Live']);
    if (inv.unifi) list.push(['unifi', 'UniFi']);
    if (inv.unifi || inv.netclients) list.push(['clients', 'Verbundene Geräte']);
    if (inv.ssh || inv.snmp || inv.shelly || data.unifi_device || data.net_client) list.push(['system', 'System']);
    if ((inv.ssh && inv.ssh.interfaces && inv.ssh.interfaces.length) || (inv.snmp && inv.snmp.interfaces)) list.push(['interfaces', 'Schnittstellen']);
    if ((inv.ssh && inv.ssh.disks && inv.ssh.disks.length) || (inv.snmp && inv.snmp.storage && inv.snmp.storage.length)) list.push(['storage', 'Speicher']);
    list.push(['history', 'Verlauf']);
    list.push(['events', 'Ereignisse']);
    if (canDev('devices.diagnose') && inv.snmp) list.push(['explorer', 'SNMP-Explorer']);
    list.push(['diagnose', 'Diagnose']);
    if (canDev('devices.diagnose')) list.push(['syslog', 'Protokoll']);
    if (canDev('devices.manage')) list.push(['settings', 'Einstellungen']);
    return list;
  };
  const isShelly = () => data.device.integration === 'shelly' || !!(data.inventory || {}).shelly;

  const render = () => {
    state.liveStops.forEach((stop) => stop());
    state.liveStops = [];
    const d = data.device;
    const t = typeInfo(d.device_type);
    view().innerHTML = `
      <div class="card">
        <div class="dev-hero">${devIcon(d, 'lg')}
          <div class="title"><h1>${esc(deviceLabel(d))} ${statusBadge(d)}</h1>
            <div class="badges"><span class="badge accent">${esc(t.label)}${d.device_type_manual ? ' (manuell)' : ''}</span>
              <span class="badge plain mono">${esc(d.ip)}</span>
              ${d.vendor ? `<span class="badge plain">${esc(d.vendor)}</span>` : ''}
              ${d.os ? `<span class="badge plain">${esc(d.os)}</span>` : ''}
              ${d.model ? `<span class="badge plain">${esc(d.model)}</span>` : ''}</div></div>
          <div class="actions"><a href="#/devices" class="btn ghost">${icon('chevron-left', 'i-sm')} Alle Geräte</a>
            ${canDev('devices.manage') ? `<button type="button" id="poll-now" class="ghost">${icon('refresh')}Jetzt abfragen</button>` : ''}</div>
        </div>
        <div class="fact-strip">
          ${[
    ['world', 'IP-Adresse', d.ip],
    ['binary-tree', 'MAC', d.mac || '–'],
    ['activity', 'Antwortzeit', fmtMs(d.last_rtt_ms)],
    ['clock', d.status === 'down' ? 'Offline seit' : 'Online seit', d.monitored ? fmtSince(d.status_since) : '–'],
    ['radar', 'Zuletzt gesehen', fmtAgo(d.last_seen)],
    ['plug-connected', 'Offene Ports', String((d.open_ports || []).length)],
    ['key', 'Zugang', d.has_credentials ? 'SNMP/SSH/API' : 'nur Ping'],
  ].map(([ic, label, val]) => `<div class="fact">${icon(ic, 'i-sm')}<span><label>${esc(label)}</label><b class="mono">${esc(val)}</b></span></div>`).join('')}
        </div>
        <div class="tabs">${tabs().map(([k, label]) => `<button type="button" data-tab="${k}" class="${k === tab ? 'active' : ''}">${esc(label)}</button>`).join('')}</div>
        <div id="tab-body"></div>
      </div>`;
    $$('.tabs button').forEach((b) => b.addEventListener('click', () => { tab = b.dataset.tab; render(); }));
    $('#poll-now')?.addEventListener('click', () => attempt(async () => {
      await api(`/devices/${id}/poll`, { method: 'POST' });
      setTimeout(reload, 8000);
    }, 'Abfrage gestartet – Ergebnisse erscheinen in wenigen Sekunden'));
    const body = $('#tab-body');
    const renderers = { overview: tabOverview, live: isShelly() ? tabShellyLive : tabLive, diagnose: tabDiagnose, syslog: () => '<div id="dev-syslog"><div class="empty">Lade …</div></div>', system: tabSystem, interfaces: tabInterfaces, storage: tabStorage, history: tabHistory, events: tabEvents, explorer: tabExplorer, settings: tabSettings, unifi: tabUnifi, clients: () => '<div id="uc-area"><div class="empty">Lade …</div></div>' };
    body.innerHTML = (renderers[tab] || tabOverview)();
    applyWidths(body);
    if (tab === 'settings') bindSettings();
    if (tab === 'live') { if (isShelly()) bindShellyLive(); else bindLive(); }
    if (tab === 'diagnose') bindDiagnose();
    if (tab === 'syslog') {
      api(`/remote-logs?device=${id}&hours=168&limit=300`).then((r) => {
        $('#dev-syslog').innerHTML = r.items.length
          ? `<div class="table-wrap"><table class="log-table"><thead><tr><th>Zeit</th><th>Stufe</th><th>Programm</th><th>Meldung</th></tr></thead>
             <tbody>${logRows(r.items, false)}</tbody></table></div><p class="muted small"><a href="#/syslog?device=${id}">Alle Meldungen mit Filter</a></p>`
          : empty(`Keine Syslog-Meldungen oder Traps von diesem Gerät in den letzten 7 Tagen. Gerät so einrichten, dass es an NetPulse sendet (UDP ${r.syslog_port}, Traps ${r.trap_port}).`, 'file-text');
      }).catch((e) => { $('#dev-syslog').innerHTML = `<p class="error">${esc(e.message)}</p>`; });
    }
    if (tab === 'interfaces') bindInterfaces();
    if (tab === 'unifi') bindUnifi();
    if (tab === 'clients') bindClients();
    if (tab === 'explorer') bindExplorer();
    $('#range')?.addEventListener('change', (ev) => { hours = Number(ev.target.value); reload(); });
    $('#goto-diagnose')?.addEventListener('click', (ev) => { ev.preventDefault(); tab = 'diagnose'; render(); });
  };

  const reload = async () => {
    data = await api(`/devices/${encodeURIComponent(id)}?hours=${hours}`);
    if (!['settings', 'live', 'explorer', 'diagnose', 'syslog'].includes(tab)) render();
  };

  /** Schnittstelle als Internet-Anschluss markieren (leer = automatisch erkennen) */
  const markWan = (name) => attempt(async () => {
    data.device = await api(`/devices/${id}`, { method: 'PATCH', body: { wan_interface: name } });
  }, name ? `${name} ist jetzt der Internet-Anschluss` : 'Internet-Anschluss wird wieder automatisch erkannt');

  // ----- Live -----
  function tabLive() {
    return `<div class="live-head"><span class="live-pulse" id="live-status">verbinde …</span>
        <label class="inline small"><input type="checkbox" id="live-all"> auch getrennte Schnittstellen zeigen</label></div>
      <div class="sys-live" id="sys-live" hidden>
        <div><span class="muted small">CPU</span><strong data-sys="cpu_pct">–</strong><div class="meter"><span data-bar="cpu_pct"></span></div></div>
        <div><span class="muted small">RAM</span><strong data-sys="mem_pct">–</strong><div class="meter"><span data-bar="mem_pct"></span></div></div>
        <div data-temp hidden><span class="muted small">Temperatur</span><strong data-sys="temp_c">–</strong></div>
        <div class="sys-spark" id="sys-spark"></div></div>
      <div class="if-grid" id="if-grid"></div>`;
  }

  function bindLive() {
    const grid = $('#if-grid');
    let showAll = false;
    let last = null;
    let lastHistory = {};
    const card = (i, wan) => `
      <div class="if-card${wan ? ' wan' : ''}${i.oper === 'down' ? ' down' : ''}" data-if="${esc(i.name)}">
        <header><span class="ellipsis" title="${esc(i.alias || i.name)}">${esc(i.name)}${i.alias ? ` <span class="muted small">· ${esc(i.alias)}</span>` : ''}</span>
          <span class="actions">${wan ? '<span class="badge accent">Internet</span>' : ''}<span class="dot ${i.oper === 'up' ? 'up' : ''}"></span></span></header>
        <div class="if-rates">
          <div><span class="inet-dir">${icon('arrow-down', 'i-sm')} Empfangen</span><strong data-rx>–</strong></div>
          <div><span class="inet-dir up">${icon('arrow-up', 'i-sm')} Gesendet</span><strong data-tx>–</strong></div>
        </div>
        ${flowLine('down')}${flowLine('up c1')}
        ${i.speed_mbps ? '<div class="meter" data-util><span></span></div>' : ''}
        <div data-spark>${sparkline([])}</div>
        <div class="muted small">${i.speed_mbps ? `Verbindung ${esc(linkLabel(i.speed_mbps))} · ` : ''}gesamt ↓ <span data-rxb></span> · ↑ <span data-txb></span></div>
        ${canDev('devices.manage') && !wan ? `<button type="button" class="ghost sm" data-mark-wan="${esc(i.name)}">${icon('world-www', 'i-sm')}Als Internet markieren</button>` : ''}
      </div>`;

    const cpuHistory = [];
    const update = (live, history) => {
      last = live;
      lastHistory = history;
      const sys = live.system || {};
      if (sys.cpu_pct != null || sys.mem_pct != null) {
        $('#sys-live').hidden = false;
        ['cpu_pct', 'mem_pct', 'temp_c'].forEach((k) => {
          const el = $(`[data-sys="${k}"]`);
          if (el && sys[k] != null) el.textContent = k === 'temp_c' ? `${Math.round(sys[k])} °C` : fmtPct(sys[k]);
          const bar = $(`[data-bar="${k}"]`);
          if (bar && sys[k] != null) bar.style.width = `${Math.min(100, sys[k])}%`;
        });
        $('[data-temp]').hidden = sys.temp_c == null;
        if (sys.cpu_pct != null) {
          cpuHistory.push(sys.cpu_pct);
          if (cpuHistory.length > HISTORY_POINTS) cpuHistory.shift();
          $('#sys-spark').innerHTML = valueSpark(cpuHistory, 44);
        }
      }
      $('#live-status').textContent = live.warming_up
        ? 'Erste Messung – die Raten erscheinen in 2 Sekunden …'
        : `Live per ${live.source} · ${new Date(live.time).toLocaleTimeString('de-DE')}`;
      const list = live.interfaces
        .filter((i) => showAll || i.oper === 'up' || (i.rx_bps || 0) + (i.tx_bps || 0) > 0)
        .sort((a, b) => (b.name === live.wan) - (a.name === live.wan));
      const keys = `${live.wan}|${list.map((i) => i.name).join('|')}`;
      if (grid.dataset.keys !== keys) {
        grid.innerHTML = list.map((i) => card(i, i.name === live.wan)).join('') || empty('Keine aktiven Schnittstellen.', 'plug-connected');
        grid.dataset.keys = keys;
        $$('[data-mark-wan]', grid).forEach((b) => b.addEventListener('click', () => markWan(b.dataset.markWan)));
      }
      list.forEach((i) => {
        const el = grid.querySelector(`[data-if="${CSS.escape(i.name)}"]`);
        if (!el) return;
        tweenNumber($('[data-rx]', el), i.rx_bps, fmtBps);
        tweenNumber($('[data-tx]', el), i.tx_bps, fmtBps);
        const [down, up] = $$('svg.flow', el);
        setFlow(down, i.rx_bps);
        setFlow(up, i.tx_bps);
        const util = $('[data-util]', el);
        if (util) {
          const value = (Math.max(i.rx_bps || 0, i.tx_bps || 0) / (i.speed_mbps * 1e6)) * 100;
          util.className = `meter ${value >= 90 ? 'crit' : value >= 70 ? 'warn' : ''}`;
          util.firstElementChild.style.width = `${Math.min(100, Math.max(0.5, value))}%`;
          util.title = `Auslastung ${value.toFixed(1)} %`;
        }
        $('[data-spark]', el).innerHTML = sparkline(history[i.name]);
        $('[data-rxb]', el).textContent = fmtBytes(i.rx_bytes);
        $('[data-txb]', el).textContent = fmtBytes(i.tx_bytes);
      });
    };
    $('#live-all').addEventListener('change', (ev) => { showAll = ev.target.checked; if (last) update(last, lastHistory); });
    startLive(id, update, (e) => {
      $('#live-status').textContent = 'Keine Live-Daten';
      grid.dataset.keys = '';
      grid.innerHTML = `<div class="notice">${icon('alert-triangle')}<span>${esc(e.message)}</span></div>`;
    });
  }

  // ----- SNMP-Explorer -----
  function tabExplorer() {
    const presets = [['System', 'system'], ['Schnittstellen', 'ifXTable'], ['Speicher', 'hrStorageTable'], ['Sensoren', 'entPhySensorTable'],
      ['IP/ARP', 'ipNetToMediaTable'], ['LLDP', 'lldpRemTable'], ['Herstellerbereich', 'enterprises']];
    return `<div class="explorer-tools">
        <input name="oid" id="ex-oid" value="system" placeholder="OID oder MIB-Name, z. B. 1.3.6.1.2.1.2.2, ifTable, unifiVapTable" aria-label="OID">
        <select id="ex-max" aria-label="Maximale Anzahl"><option>200</option><option selected>500</option><option>2000</option><option>5000</option></select>
        <button type="button" id="ex-go">${icon('binary-tree')}Lesen</button>
        <input id="ex-filter" type="search" placeholder="Ergebnis filtern …" aria-label="Filtern"></div>
      <div class="actions">${presets.map(([l, o]) => `<button type="button" class="ghost sm" data-preset="${o}">${esc(l)}</button>`).join('')}</div>
      <p class="hint" id="ex-info">Liest beliebige SNMP-Werte des Geräts – mit Namen aus rund 4.800 Standard- und Hersteller-MIBs.</p>
      <div id="ex-result"></div>`;
  }

  function bindExplorer() {
    let rows = [];
    const show = () => {
      const q = $('#ex-filter').value.trim().toLowerCase();
      const shown = q ? rows.filter((r) => `${r.name || ''} ${r.oid} ${r.value}`.toLowerCase().includes(q)) : rows;
      $('#ex-result').innerHTML = shown.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>OID</th><th>Typ</th><th>Wert</th></tr></thead>
        <tbody>${shown.map((r) => `<tr><td class="mono small">${esc(r.name || '–')}</td><td class="mono small muted">${esc(r.oid)}</td>
          <td class="small">${esc(r.type)}</td><td class="val mono small">${esc(r.value)}</td></tr>`).join('')}</tbody></table></div>`
        : empty('Keine Werte.', 'binary-tree');
    };
    const load = async () => {
      const oid = $('#ex-oid').value.trim();
      $('#ex-info').textContent = 'Lese …';
      try {
        const res = await api(`/devices/${id}/snmp?oid=${encodeURIComponent(oid)}&max=${$('#ex-max').value}`);
        rows = res.rows;
        $('#ex-info').textContent = `${rows.length} Werte ab ${res.base}${res.truncated ? ' (gekürzt – Maximum erhöhen)' : ''}`
          + (res.mib_names ? '' : ' · MIB-Namen werden gerade noch geladen');
        show();
      } catch (e) {
        $('#ex-info').textContent = e.message;
        rows = [];
        show();
      }
    };
    $('#ex-go').addEventListener('click', load);
    $('#ex-oid').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') load(); });
    $('#ex-filter').addEventListener('input', show);
    $$('[data-preset]').forEach((b) => b.addEventListener('click', () => { $('#ex-oid').value = b.dataset.preset; load(); }));
    load();
  }

  // ----- Übersicht -----
  function tabOverview() {
    const d = data.device;
    const last = data.stats[data.stats.length - 1] || {};
    const avail = availability(data.points);
    const gauges = [['cpu', 'CPU', last.cpu_pct, '%'], ['gauge', 'RAM', last.mem_pct, '%'], ['database', 'Speicher', last.disk_pct, '%'],
      ['temperature', 'Temperatur', last.temp_c, '°C'], ['bolt', 'Leistung', last.power_w, 'W'], ['antenna-bars-5', 'WLAN-Clients', last.clients, '']]
      .filter((g) => g[2] != null);
    return `<div class="grid">
      <section class="span-1"><h3>Details</h3><dl class="details">
        <dt>IP-Adresse</dt><dd class="mono">${esc(d.ip)}</dd>
        <dt>MAC-Adresse</dt><dd class="mono">${esc(d.mac || '–')}</dd>
        <dt>Hersteller</dt><dd>${esc(d.vendor || '–')}</dd>
        <dt>Hostname (DNS)</dt><dd>${esc(d.hostname || '–')}</dd>
        ${d.reported_name ? `<dt>Gerätename</dt><dd>${esc(d.reported_name)}</dd>` : ''}
        <dt>Antwortzeit</dt><dd>${esc(fmtMs(d.last_rtt_ms))}</dd>
        <dt>Status seit</dt><dd>${esc(fmtTime(d.status_since))}</dd>
        <dt>Erstmals gesehen</dt><dd>${esc(fmtTime(d.first_seen))}</dd>
        <dt>Zuletzt gesehen</dt><dd>${esc(fmtAgo(d.last_seen))}</dd>
        <dt>Dienste</dt><dd>${portChips(d.open_ports)}</dd>
        ${d.notes ? `<dt>Notizen</dt><dd>${esc(d.notes)}</dd>` : ''}
      </dl></section>
      <section class="span-2">
        ${gauges.length ? `<div class="gauges">${gauges.map(([ic, label, v, unit]) => `<div class="gauge"><div class="l">${icon(ic, 'i-sm')}${label}</div>
          <div class="v">${unit === 'W' ? esc(fmtWatt(v)) : `${Math.round(v)} ${unit}`}</div>${unit === '%' ? meter(v) : unit === '°C' ? meter(v, { warn: 70, crit: 85 }) : ''}</div>`).join('')}</div><br>` : ''}
        ${data.net_client && !data.unifi_device ? `<div class="uc-overview">${unifiClientBlock(data.net_client)}</div><br>` : ''}
        <h3>Antwortzeit ${avail != null ? `<span class="muted">· ${avail} % verfügbar (${hours} h)</span>` : ''}</h3>
        ${lineChart(data.points, { series: [{ key: 'rtt_ms', label: 'Antwortzeit' }], format: fmtMs, width: 760, outages: true })}
        ${inventoryStatus()}
      </section></div>`;
  }

  function inventoryStatus() {
    const d = data.device;
    if (d.inventory_error) {
      return `<div class="notice">${icon('alert-triangle')}<span>Tiefe Abfrage: ${esc(d.inventory_error)}
        <br><a href="#" id="goto-diagnose">Schritt für Schritt im Tab „Diagnose“ ansehen</a></span></div>`;
    }
    if (d.inventory_at && data.inventory) {
      const via = [data.inventory.ssh && 'SSH', data.inventory.snmp && 'SNMP', data.inventory.shelly && 'Shelly-API'].filter(Boolean).join(' + ');
      return `<p class="muted small">${icon('circle-check', 'i-sm')} Inventar per ${esc(via)} · ${esc(fmtAgo(d.inventory_at))}</p>`;
    }
    if (!d.has_credentials) {
      return `<div class="notice info">${icon('key')}<span>Für CPU, RAM, Festplatten, Schnittstellen & Co. unter
        ${canDev('devices.manage') ? '„Einstellungen“' : 'Einstellungen'} SNMP- oder SSH-Zugangsdaten zuordnen.</span></div>`;
    }
    return '';
  }

  // ----- Shelly live -----
  function shellyChannels(l) {
    const channels = (l && l.channels) || [];
    if (!channels.length) return '<p class="muted">Keine Kanäle</p>';
    return `<div class="ch-grid">${channels.map((c) => {
      const on = c.on === true || c.state === 'opening' || c.state === 'closing';
      const state = c.on === true ? 'an' : c.on === false ? 'aus' : (c.state || '');
      return `<div class="ch-tile${on ? ' on' : ''}">
        <span class="sh-top">${icon(CHANNEL_ICON[c.kind] || 'bolt', 'i-sm')}${esc(CHANNEL_LABEL[c.kind] || c.kind)} ${Number(c.id) + 1}</span>
        <strong>${c.power_w != null ? esc(fmtWatt(c.power_w)) : esc(state || '–')}</strong>
        <span class="muted small">${[c.power_w != null ? state : null, c.position != null ? `Position ${c.position} %` : null,
          c.brightness != null ? `Helligkeit ${c.brightness} %` : null, c.voltage != null ? `${Math.round(c.voltage)} V` : null,
          c.current != null ? `${c.current} A` : null, c.energy_kwh != null ? `${c.energy_kwh} kWh` : null].filter(Boolean).map(esc).join(' · ')}</span>
        ${c.position != null ? `<div class="progress"><span data-w="${c.position}"></span></div>` : ''}</div>`;
    }).join('')}</div>`;
  }

  function tabShellyLive() {
    const l = live.devices.get(Number(id));
    return `<div class="live-head"><span class="live-pulse" id="sh-state">${l ? (l.ok ? 'Live – aktualisiert sich automatisch' : esc(l.error || 'keine Antwort')) : 'Warte auf Live-Daten …'}</span></div>
      <div class="grid">
        <section class="card span-1"><header><h2>${icon(l && l.role === 'producer' ? 'sun' : 'bolt')}${l && l.role === 'producer' ? 'Erzeugung' : 'Leistung'}</h2><span class="live-tag">LIVE</span></header>
          <div class="power-total big" id="sh-watt" data-value="${(l && l.power_w) || 0}">${esc(l && l.power_w != null ? fmtWatt(l.power_w) : '–')}</div>
          <div id="sh-spark">${valueSpark(live.perDevice.get(Number(id)) || [])}</div>
          <p class="muted small" id="sh-extra"></p></section>
        <section class="card span-2"><header><h2>${icon('plug')}Kanäle</h2></header><div id="sh-channels">${shellyChannels(l)}</div></section>
      </div>`;
  }

  function bindShellyLive() {
    const update = () => {
      const l = live.devices.get(Number(id));
      if (!l) return;
      $('#sh-state').textContent = l.ok ? `Live – zuletzt ${new Date(l.time).toLocaleTimeString('de-DE')}` : (l.error || 'keine Antwort');
      $('#sh-state').classList.toggle('stale', !l.ok);
      tweenNumber($('#sh-watt'), l.ok ? l.power_w : null, fmtWatt);
      $('#sh-spark').innerHTML = valueSpark(live.perDevice.get(Number(id)) || []);
      $('#sh-extra').textContent = [l.temp_c != null ? `Temperatur ${l.temp_c} °C` : null, l.humidity_pct != null ? `Luftfeuchte ${l.humidity_pct} %` : null,
        l.battery_pct != null ? `Akku ${l.battery_pct} %` : null, l.rssi != null ? `WLAN ${l.rssi} dBm` : null].filter(Boolean).join(' · ');
      $('#sh-channels').innerHTML = shellyChannels(l);
      applyWidths($('#sh-channels'));
    };
    update();
    onLive((msg) => { if (msg.type === 'shelly' && (msg.full || (msg.devices || []).some((d) => d.id === Number(id)))) update(); });
  }

  // ----- Diagnose -----
  function tabDiagnose() {
    return `<section class="card"><header><h2>${icon('stethoscope')}Protokoll der letzten Abfrage</h2>
        ${canDev('devices.diagnose') ? `<button type="button" id="diag-run">${icon('player-play')}Jetzt abfragen und protokollieren</button>` : ''}</header>
      <p class="muted small">Zeigt Schritt für Schritt, welche Abfragen (SNMP, SSH, Shelly-API, UniFi) versucht wurden und woran es gescheitert ist.
        Passwörter erscheinen hier nie.</p>
      <div id="diag-body"><div class="empty">Lade …</div></div></section>`;
  }

  function diagnoseSteps(result) {
    if (!result.log || !(result.log.steps || []).length) {
      return empty('Noch kein Protokoll – das Gerät wurde seit dem Update nicht tief abgefragt. „Jetzt abfragen“ startet eine Abfrage.', 'stethoscope');
    }
    const t0 = new Date(result.log.steps[0].time).getTime();
    return `<p class="muted small">Abfrage vom ${esc(fmtTime(result.log.time))}</p>
      <ol class="diag">${result.log.steps.map((st) => {
        const cls = st.ok === true ? 'ok' : st.ok === false ? 'err' : 'info';
        const ic = st.ok === true ? 'circle-check' : st.ok === false ? 'circle-x' : 'info-circle';
        const ms = new Date(st.time).getTime() - t0;
        return `<li class="${cls}">${icon(ic, 'i-sm')}<span>${esc(st.text)}</span><span class="muted small mono">+${(ms / 1000).toFixed(1)} s</span></li>`;
      }).join('')}</ol>
      ${result.error ? `<div class="notice">${icon('alert-triangle')}<span>${esc(result.error)}</span></div>` : ''}`;
  }

  function bindDiagnose() {
    const body = $('#diag-body');
    api(`/devices/${id}/diagnose`).then((r) => { body.innerHTML = diagnoseSteps(r); }).catch((e) => { body.innerHTML = `<p class="error">${esc(e.message)}</p>`; });
    $('#diag-run')?.addEventListener('click', async (ev) => {
      const btn = ev.currentTarget;
      btn.disabled = true;
      body.innerHTML = `<div class="empty"><span class="live-pulse">Frage das Gerät ab … (bis zu 30 s)</span></div>`;
      try {
        const r = await api(`/devices/${id}/diagnose`, { method: 'POST' });
        body.innerHTML = diagnoseSteps(r);
        data = await api(`/devices/${encodeURIComponent(id)}?hours=${hours}`);
      } catch (e) {
        body.innerHTML = `<p class="error">${esc(e.message)}</p>`;
      } finally {
        btn.disabled = false;
      }
    });
  }

  // ----- UniFi -----
  function unifiCards() {
    const ud = data.unifi_device;
    const uc = data.net_client;
    let html = '';
    const state = (s) => (s === 'online' || s === 'connected'
      ? '<span class="badge st-up">online</span>' : `<span class="badge st-down">${esc(s || 'unbekannt')}</span>`);
    if (ud) {
      html += `<section class="card"><header><h2>${icon('access-point')}Laut UniFi-Controller</h2>${state(ud.state)}</header>
        <div class="gauges">${ud.cpu_pct != null ? `<div><span class="muted small">CPU</span>${meter(ud.cpu_pct)}</div>` : ''}
          ${ud.mem_pct != null ? `<div><span class="muted small">RAM</span>${meter(ud.mem_pct)}</div>` : ''}</div>
        <dl class="details">
          <dt>Name</dt><dd>${esc(ud.name || '–')}</dd><dt>Modell</dt><dd>${esc(ud.model || '–')}</dd>
          <dt>Firmware</dt><dd>${esc(ud.firmware || '–')}</dd><dt>Site</dt><dd>${esc(ud.site || '–')}</dd>
          <dt>Verbundene Clients</dt><dd>${esc(ud.clients ?? '–')}</dd>
          <dt>Uplink ↓ / ↑</dt><dd>${ud.rx_bps != null ? `${esc(fmtBps(ud.rx_bps))} / ${esc(fmtBps(ud.tx_bps))}` : '–'}</dd>
          <dt>Laufzeit</dt><dd>${ud.uptime_s != null ? esc(fmtDuration(ud.uptime_s)) : '–'}</dd></dl>
        <p class="muted small"><a href="#/device/${ud.controller_id}">Zum Controller</a></p></section>`;
    }
    if (uc && !ud) html += `<section class="card">${unifiClientBlock(uc)}</section>`;
    return html;
  }

  // ----- UniFi-Controller -----
  function tabUnifi() {
    const u = (data.inventory || {}).unifi;
    const known = new Map(allDevicesByMac().map((x) => [x.mac, x]));
    const devs = [...(u.devices || [])].sort((a, b) => String(a.name).localeCompare(String(b.name), 'de'));
    const stateBadge = (st) => (st === 'online' || st === 'connected'
      ? '<span class="badge st-up">online</span>' : `<span class="badge st-down">${esc(st || 'unbekannt')}</span>`);
    const devLink = (d) => {
      const k = d.mac && known.get(d.mac);
      return k ? `<a href="#/device/${k.id}">${esc(d.name || d.mac)}</a>` : esc(d.name || d.mac);
    };
    return `<section class="card"><header><h2>${icon('access-point')}UniFi-Controller</h2>
        <span class="badge plain">${esc(u.api === 'integration' ? 'API-Schlüssel' : 'lokales Konto')} · Port ${esc(u.port)} · aktualisiert jede Minute</span></header>
      <div class="kpis">
        <a class="kpi" href="#" data-goto-tab="unifi"><span class="kpi-icon ${u.devices_online < u.devices_total ? 'tone-warn' : 'tone-up'}">${icon('router')}</span>
          <span><div class="kpi-value">${esc(u.devices_online)}/${esc(u.devices_total)}</div><div class="kpi-label">UniFi-Geräte online</div></span></a>
        <a class="kpi" href="#" data-goto-tab="clients"><span class="kpi-icon tone-accent">${icon('devices')}</span>
          <span><div class="kpi-value">${esc(u.clients_total)}</div><div class="kpi-label">Clients anzeigen</div></span></a>
        <div class="kpi"><span class="kpi-icon tone-info">${icon('topology-star-3')}</span>
          <span><div class="kpi-value">${esc((u.sites || []).length)}</div><div class="kpi-label">${(u.sites || []).length === 1 ? 'Site' : 'Sites'}</div></span></div>
        <div class="kpi"><span class="kpi-icon tone-muted">${icon('box')}</span>
          <span><div class="kpi-value">${esc(u.version || '–')}</div><div class="kpi-label">Network-Version</div></span></div>
      </div>
      <div class="table-wrap"><table><thead><tr><th>Gerät</th><th>Status</th><th>Modell</th><th>IP</th><th class="num">Clients</th><th>CPU</th><th>RAM</th><th class="num">Uplink ↓ / ↑</th><th>Laufzeit</th><th>Firmware</th></tr></thead>
      <tbody>${devs.map((d) => `<tr><td>${devLink(d)}</td><td>${stateBadge(d.state)}</td><td>${esc(d.model || '')}</td>
        <td class="mono">${esc(d.ip || '')}</td>
        <td class="num">${d.clients ? `<a href="#" data-ap="${esc(d.mac)}" title="Clients an diesem Gerät zeigen">${esc(d.clients)}</a>` : esc(d.clients ?? '')}</td>
        <td class="uc-meter">${d.cpu_pct != null ? meter(d.cpu_pct) : ''}<span class="small">${esc(fmtPct(d.cpu_pct))}</span></td>
        <td class="uc-meter">${d.mem_pct != null ? meter(d.mem_pct) : ''}<span class="small">${esc(fmtPct(d.mem_pct))}</span></td>
        <td class="num small">${d.rx_bps != null || d.tx_bps != null ? `${esc(fmtBps(d.rx_bps))} / ${esc(fmtBps(d.tx_bps))}` : ''}</td>
        <td class="small">${d.uptime_s != null ? esc(fmtDuration(d.uptime_s)) : ''}</td><td class="small">${esc(d.firmware || '')}</td></tr>`).join('')
        || `<tr><td colspan="10">${empty('Keine UniFi-Geräte gemeldet', 'router')}</td></tr>`}</tbody></table></div>
      <p class="muted small">Namen, Modelle und Auslastung werden automatisch auf die passenden Geräte in NetPulse übertragen (Zuordnung über die MAC-Adresse).</p></section>`;
  }

  function allDevicesByMac() {
    return (allDevices || []).filter((x) => x.mac).map((x) => ({ id: x.id, mac: x.mac.toLowerCase() }));
  }

  function bindUnifi() {
    $$('[data-goto-tab]').forEach((a) => a.addEventListener('click', (ev) => { ev.preventDefault(); tab = a.dataset.gotoTab; render(); }));
    $$('[data-ap]').forEach((a) => a.addEventListener('click', (ev) => { ev.preventDefault(); clientFilter.ap = a.dataset.ap; tab = 'clients'; render(); }));
  }

  // ----- Clients des Controllers -----
  function bindClients() {
    const area = $('#uc-area');
    let r = null;
    const sorters = {
      name: (c) => String(c.device_label || c.name || c.hostname || c.mac || '').toLowerCase(),
      ip: (c) => (c.ip || '').split('.').map((n) => n.padStart(3, '0')).join('.'),
      via: (c) => String(c.uplink_name || '').toLowerCase(),
      signal: (c) => (c.signal_dbm == null ? -999 : c.signal_dbm),
      down: (c) => c.down_bps || 0,
      up: (c) => c.up_bps || 0,
      total: (c) => (c.down_bytes || 0) + (c.up_bytes || 0),
      since: (c) => (c.connected_at ? -new Date(c.connected_at).getTime() : 0),
    };
    const paint = () => {
      // Alles, was dieses Gerät gemeldet hat (auch wenn eine andere Quelle genauere Daten hat)
      const list = r.clients.filter((c) => (c.sources || []).some((s) => s.source_id === data.device.id));
      const aps = [...new Map(list.filter((c) => c.uplink_mac).map((c) => [c.uplink_mac, c.uplink_name || c.uplink_mac])).entries()]
        .sort((a, b) => String(a[1]).localeCompare(String(b[1]), 'de'));
      const q = clientFilter.q.toLowerCase();
      const shown = list.filter((c) => (!clientFilter.kind || c.type === clientFilter.kind)
          && (!clientFilter.ap || c.uplink_mac === clientFilter.ap)
          && (!q || [c.name, c.hostname, c.device_label, c.ip, c.mac, c.vendor, c.ssid, c.uplink_name, c.network].join(' ').toLowerCase().includes(q)))
        .sort((a, b) => {
          const va = sorters[clientFilter.sort](a);
          const vb = sorters[clientFilter.sort](b);
          return (va < vb ? -1 : va > vb ? 1 : 0) * clientFilter.dir;
        });
      const ctrl = r.controllers.find((x) => x.controller_id === data.device.id) || {};
      const details = ctrl.client_details || {};
      const sum = (k) => list.reduce((a, c) => a + (c[k] || 0), 0);
      const wifi = list.filter((c) => c.type === 'wireless');
      const wired = list.filter((c) => c.type === 'wired');
      const th = (key, label, cls = '') => `<th class="sortable ${cls}${clientFilter.sort === key ? ' sorted' : ''}" data-sort="${key}">${label}${clientFilter.sort === key ? (clientFilter.dir < 0 ? ' ↓' : ' ↑') : ''}</th>`;
      area.innerHTML = `
        ${ctrl.unifi && details.ok === false ? `<div class="notice info">${icon('info-circle')}<span><b>Datenraten und WLAN-Signal je Client fehlen.</b>
          Dein Controller gibt sie nicht mit dem API-Schlüssel heraus${details.reason ? ` (${esc(details.reason)})` : ''}. Abhilfe: in UniFi unter
          <i>Einstellungen → Admins &amp; Benutzer</i> ein Konto mit Rolle <b>„Nur ansehen“</b> und <b>„Auf lokalen Zugriff beschränken“</b> anlegen (ohne 2FA)
          und bei den NetPulse-Zugangsdaten <b>Benutzername und Passwort</b> statt des API-Schlüssels eintragen.</span></div>` : ''}
        <div class="kpis">
          <div class="kpi"><span class="kpi-icon tone-accent">${icon('devices')}</span><span><div class="kpi-value">${esc(list.length)}</div><div class="kpi-label">Clients</div></span></div>
          <div class="kpi"><span class="kpi-icon tone-info">${icon('wifi')}</span><span><div class="kpi-value">${esc(wifi.length)}</div><div class="kpi-label">im WLAN</div></span></div>
          <div class="kpi"><span class="kpi-icon tone-muted">${icon('plug-connected')}</span><span><div class="kpi-value">${esc(wired.length)}</div><div class="kpi-label">per Kabel${list.length - wifi.length - wired.length ? ` · ${esc(list.length - wifi.length - wired.length)} ohne Angabe` : ''}</div></span></div>
          ${details.ok !== false ? `<div class="kpi"><span class="kpi-icon tone-up">${icon('arrows-exchange')}</span><span><div class="kpi-value small-val">↓ ${esc(fmtBps(sum('down_bps')))}<br>↑ ${esc(fmtBps(sum('up_bps')))}</div><div class="kpi-label">alle Clients gerade</div></span></div>` : ''}
        </div>
        <div class="page-head uc-tools"><div class="actions">
          <input id="uc-q" type="search" placeholder="Suchen: Name, IP, MAC, Hersteller, SSID …" value="${esc(clientFilter.q)}" aria-label="Clients suchen">
          <select id="uc-kind" aria-label="Verbindung"><option value="">Alle Verbindungen</option><option value="wireless"${clientFilter.kind === 'wireless' ? ' selected' : ''}>nur WLAN</option><option value="wired"${clientFilter.kind === 'wired' ? ' selected' : ''}>nur Kabel</option></select>
          <select id="uc-ap" aria-label="Access Point / Switch"><option value="">Alle Access Points / Switches</option>
            ${aps.map(([mac, name]) => `<option value="${esc(mac)}"${clientFilter.ap === mac ? ' selected' : ''}>${esc(name)}</option>`).join('')}</select></div>
          <span class="muted small">${esc(shown.length)} von ${esc(list.length)} · aktualisiert jede Minute</span></div>
        <div class="table-wrap"><table class="uc-table"><thead><tr>
          ${th('name', 'Client')}${th('ip', 'IP / MAC')}${th('via', 'Verbunden über')}${th('signal', 'Signal')}${th('down', '↓ Download', 'num')}${th('up', '↑ Upload', 'num')}${th('total', 'Übertragen', 'num')}${th('since', 'Verbunden')}</tr></thead>
          <tbody>${shown.slice(0, 500).map((c) => `<tr>
            <td><div class="cell-dev">${icon(c.type === 'wired' ? 'plug-connected' : c.type === 'wireless' ? 'wifi' : 'network', 'i-sm')}<div class="ellipsis">${clientName(c)}
              <div class="muted small">${esc([c.vendor, c.hostname && c.hostname !== c.name ? c.hostname : null, c.network, c.guest ? 'Gast' : null].filter(Boolean).join(' · '))}</div></div></div></td>
            <td class="mono small">${esc(c.ip || '–')}<div class="muted">${esc(c.mac || '')}</div></td>
            <td class="small">${c.uplink_device_id ? `<a href="#/device/${c.uplink_device_id}">${esc(c.uplink_name || c.uplink_mac || '')}</a>` : esc(c.uplink_name || c.uplink_mac || '–')}
              <div class="muted">${esc(c.type === 'wired' ? (c.port || (c.switch_port != null ? `Port ${c.switch_port}` : 'Kabel'))
                : c.type === 'wireless' ? [c.ssid, c.band, c.channel != null ? `Kanal ${c.channel}` : null, c.wifi_standard].filter(Boolean).join(' · ')
                  : c.network || c.source_label || '')}</div></td>
            <td>${c.type === 'wired' ? '<span class="muted small">Kabel</span>' : c.type === 'wireless' ? signalBadge(c.signal_dbm) : '<span class="muted small">–</span>'}</td>
            <td class="num">${esc(c.down_bps != null ? fmtBps(c.down_bps) : '–')}</td>
            <td class="num">${esc(c.up_bps != null ? fmtBps(c.up_bps) : '–')}</td>
            <td class="num small">${c.down_bytes != null || c.up_bytes != null ? `↓ ${esc(fmtBytes(c.down_bytes || 0))}<br>↑ ${esc(fmtBytes(c.up_bytes || 0))}` : '–'}</td>
            <td class="small" title="${esc(fmtTime(c.connected_at))}">${esc(c.connected_at ? fmtAgo(c.connected_at).replace('vor ', 'seit ') : '–')}</td></tr>`).join('')
            || `<tr><td colspan="8">${empty('Keine Clients passen zum Filter.', 'devices')}</td></tr>`}</tbody></table></div>
        ${shown.length > 500 ? '<p class="muted small">Es werden die ersten 500 angezeigt – Filter oder Suche verwenden.</p>' : ''}`;
      const qInput = $('#uc-q');
      qInput.addEventListener('input', () => {
        clientFilter.q = qInput.value.trim();
        const pos = qInput.selectionStart;
        paint();
        const n = $('#uc-q');
        n.focus();
        n.setSelectionRange(pos, pos);
      });
      $('#uc-kind').addEventListener('change', (ev) => { clientFilter.kind = ev.target.value; paint(); });
      $('#uc-ap').addEventListener('change', (ev) => { clientFilter.ap = ev.target.value; paint(); });
      $$('[data-sort]', area).forEach((h) => h.addEventListener('click', () => {
        if (clientFilter.sort === h.dataset.sort) clientFilter.dir *= -1;
        else { clientFilter.sort = h.dataset.sort; clientFilter.dir = ['name', 'ip', 'via'].includes(h.dataset.sort) ? 1 : -1; }
        paint();
      }));
    };
    const load = async () => {
      try {
        r = await api('/clients');
        if (tab === 'clients' && $('#uc-area')) paint();
      } catch (e) {
        area.innerHTML = `<p class="error">${esc(e.message)}</p>`;
      }
    };
    load();
    // Nach jeder Minuten-Abfrage des Controllers neu laden (nicht, während in der Suche getippt wird)
    onLive((msg) => { if (msg.type === 'unifi' && msg.controller === data.device.id && document.activeElement?.id !== 'uc-q') load(); });
  }

  // ----- System -----
  function tabSystem() {
    const ssh = (data.inventory || {}).ssh;
    const snmp = (data.inventory || {}).snmp;
    const shelly = (data.inventory || {}).shelly;
    const rows = [];
    const add = (label, value) => { if (value != null && value !== '' && value !== false) rows.push(`<dt>${esc(label)}</dt><dd>${esc(value)}</dd>`); };
    if (ssh) {
      add('Betriebssystem', ssh.os);
      add('Version / Build', [ssh.version, ssh.build].filter(Boolean).join(' / '));
      add('Kernel', ssh.kernel);
      add('Architektur', ssh.arch);
      add('Laufzeit', ssh.uptime_s != null ? fmtDuration(ssh.uptime_s) : null);
      add('Hersteller', ssh.vendor);
      add('Modell / Board', ssh.model || ssh.board);
      add('Seriennummer', ssh.serial);
      add('BIOS', ssh.bios);
      add('Prozessor', ssh.cpu_model);
      add('Kerne', ssh.cpu_cores);
      add('Last (1/5/15 min)', ssh.load ? ssh.load.join(' / ') : null);
      add('Arbeitsspeicher', ssh.mem_total_kb ? fmtBytes(ssh.mem_total_kb * 1024) : null);
      add('Swap', ssh.swap_total_kb ? `${fmtBytes((ssh.swap_total_kb - (ssh.swap_free_kb || 0)) * 1024)} von ${fmtBytes(ssh.swap_total_kb * 1024)} belegt` : null);
      add('Domäne', ssh.domain);
      add('Letztes Windows-Update', ssh.last_hotfix);
      add('Gestoppte Autostart-Dienste', ssh.stopped_auto_services || null);
      add('Fehlgeschlagene Dienste (systemd)', ssh.failed_units || null);
      add('Laufende Container', ssh.containers);
      add('Neustart erforderlich', ssh.reboot_required ? 'ja' : null);
      add('Proxmox', ssh.proxmox);
      add('Synology-Modell', ssh.synology);
    }
    if (snmp) {
      add('Systembeschreibung (SNMP)', snmp.sys_descr);
      add('Systemname', snmp.sys_name);
      add('Standort', snmp.sys_location);
      add('Kontakt', snmp.sys_contact);
      if (!ssh) add('Laufzeit', snmp.uptime_s != null ? fmtDuration(snmp.uptime_s) : null);
      add('Modell', snmp.model);
      add('Seriennummer', snmp.serial);
      add('CPU-Last', snmp.cpu_pct != null ? `${Math.round(snmp.cpu_pct)} % (${snmp.cpu_cores} Kerne)` : null);
      add('LLDP-Nachbarn', snmp.lldp_neighbors ? snmp.lldp_neighbors.join(', ') : null);
      add('Prozesse', snmp.processes);
      add('Angemeldete Benutzer', snmp.users || null);
      add('Firewall-States (pf)', snmp.firewall ? snmp.firewall.states : null);
    }
    if (shelly) {
      add('Gerätename', shelly.name);
      add('Modell', shelly.model);
      add('Generation', shelly.generation ? `Gen${shelly.generation}` : null);
      add('Laufzeit', shelly.uptime_s != null ? fmtDuration(shelly.uptime_s) : null);
      add('WLAN', shelly.rssi != null ? `${shelly.ssid ? `${shelly.ssid}, ` : ''}${shelly.rssi} dBm` : null);
      add('Firmware-Update verfügbar', shelly.update);
    }
    const unifiHtml = unifiCards();
    let extra = '';
    if (shelly) {
      const kindLabel = { switch: 'Schalter', light: 'Licht', cover: 'Rollladen', em: 'Energiezähler', em1: 'Energiezähler', pm1: 'Strommesser' };
      extra += `<section class="card"><header><h2>${icon('bolt')}Shelly</h2>${shelly.power_w != null ? `<span class="badge accent">${esc(fmtWatt(shelly.power_w))}</span>` : ''}</header>
        <ul class="list">${(shelly.channels || []).map((c) => `<li><span class="lead">${icon(c.kind === 'cover' ? 'arrows-exchange' : c.kind === 'light' ? 'bulb' : 'bolt', 'i-sm')}
          <span>${esc(kindLabel[c.kind] || c.kind)} ${Number(c.id) + 1}
          ${c.on === true ? '<span class="badge st-up">an</span>' : c.on === false ? '<span class="badge plain">aus</span>' : ''}
          ${c.state ? `<span class="badge plain">${esc(c.state)}${c.position != null ? ` · ${esc(c.position)} %` : ''}</span>` : ''}</span></span>
          <span class="meta">${c.power_w != null ? esc(fmtWatt(c.power_w)) : ''}${c.energy_kwh != null ? ` · ${esc(c.energy_kwh)} kWh` : ''}${c.voltage != null ? ` · ${esc(Math.round(c.voltage))} V` : ''}</span></li>`).join('')
          || '<li class="muted">Keine Kanäle</li>'}</ul>
        ${shelly.temp_c != null || shelly.humidity_pct != null || shelly.battery_pct != null ? `<dl class="details">
          ${shelly.temp_c != null ? `<dt>Temperatur</dt><dd>${esc(shelly.temp_c)} °C</dd>` : ''}
          ${shelly.humidity_pct != null ? `<dt>Luftfeuchte</dt><dd>${esc(shelly.humidity_pct)} %</dd>` : ''}
          ${shelly.battery_pct != null ? `<dt>Akku</dt><dd>${esc(shelly.battery_pct)} %</dd>` : ''}</dl>` : ''}
        ${shelly.energy_kwh != null ? `<p class="muted small">Gesamtverbrauch seit Zählerstart: ${esc(shelly.energy_kwh)} kWh</p>` : ''}</section>`;
    }
    if (snmp && snmp.unifi) {
      const u = snmp.unifi;
      extra += `<section class="card"><header><h2>${icon('access-point')}UniFi-WLAN</h2><span class="badge accent">${esc(u.clients)} Clients</span></header>
        ${u.model ? `<p class="muted small">${esc(u.model)}${u.version ? ` · Firmware ${esc(u.version)}` : ''}</p>` : ''}
        ${(u.radios || []).map((r) => `<div class="meter-row"><span><div>${esc(r.band || r.name)}</div><div class="muted small">Kanalauslastung</div></span>
          ${meter(r.utilization_pct || 0, { warn: 50, crit: 75 })}<span class="small">${r.utilization_pct != null ? `${r.utilization_pct} %` : '–'}</span></div>`).join('')}
        ${(u.wlans || []).length ? `<div class="table-wrap"><table><thead><tr><th>WLAN</th><th>Funk</th><th>Kanal</th><th>Clients</th></tr></thead>
          <tbody>${u.wlans.map((w) => `<tr><td>${esc(w.ssid || '–')}</td><td class="small">${esc(w.radio || '')}</td><td>${esc(w.channel ?? '–')}</td>
            <td><b>${esc(w.clients ?? 0)}</b></td></tr>`).join('')}</tbody></table></div>` : ''}</section>`;
    }
    if (snmp && snmp.synology && (snmp.synology.disks || snmp.synology.volumes)) {
      const s = snmp.synology;
      extra += `<section class="card"><header><h2>${icon('database')}Festplatten &amp; Volumes</h2></header>
        ${(s.volumes || []).map((v) => `<div class="meter-row"><span><div>${esc(v.name)}</div><div class="muted small">${esc(v.status)}</div></span>
          ${meter(v.pct || 0)}<span class="small">${esc(fmtBytes(v.used_bytes))} / ${esc(fmtBytes(v.total_bytes))}</span></div>`).join('')}
        ${(s.disks || []).length ? `<ul class="list">${s.disks.map((d) => `<li><span class="lead">${icon('database', 'i-sm')}<span class="ellipsis">${esc(d.id)} <span class="muted small">${esc(d.model || '')}</span></span></span>
          <span class="meta">${d.status === 'normal' ? '<span class="badge st-up">normal</span>' : `<span class="badge sev-critical">${esc(d.status)}</span>`}
          ${d.temp_c != null ? ` ${esc(d.temp_c)} °C` : ''}</span></li>`).join('')}</ul>` : ''}</section>`;
    }
    if (snmp && snmp.mikrotik) {
      const m = snmp.mikrotik;
      extra += `<section class="card"><header><h2>${icon('router')}MikroTik</h2></header><dl class="details">
        <dt>RouterOS</dt><dd>${esc(m.version || '–')}</dd>
        <dt>Temperatur</dt><dd>${m.temp_c != null ? `${esc(m.temp_c)} °C` : '–'}${m.cpu_temp_c != null ? ` (CPU ${esc(m.cpu_temp_c)} °C)` : ''}</dd>
        <dt>Spannung</dt><dd>${m.voltage_v != null ? `${esc(m.voltage_v)} V` : '–'}</dd>
        <dt>WLAN-Clients</dt><dd>${esc(m.clients ?? 0)}</dd></dl></section>`;
    }
    if (snmp && snmp.sensors && snmp.sensors.length) {
      extra += `<section class="card"><header><h2>${icon('temperature')}Sensoren</h2></header><ul class="list">
        ${snmp.sensors.slice(0, 30).map((x) => `<li><span class="ellipsis">${esc(x.name || x.kind)}</span><span class="meta">${esc(x.value)} ${esc((x.kind.match(/\((.*)\)/) || [])[1] || '')}</span></li>`).join('')}</ul></section>`;
    }
    if (snmp && snmp.printer && snmp.printer.length) {
      extra += `<section class="card"><header><h2>${icon('printer')}Verbrauchsmaterial</h2></header>
        ${snmp.printer.map((s) => `<div class="meter-row"><span class="ellipsis">${esc(s.descr || 'Material')}</span>
          ${s.pct != null ? `<div class="meter ${s.pct <= 10 ? 'crit' : s.pct <= 25 ? 'warn' : ''}"><span data-w="${s.pct}"></span></div>` : '<span class="muted small">Füllstand unbekannt</span>'}
          <span class="small">${s.pct != null ? `${s.pct} %` : ''}</span></div>`).join('')}</section>`;
    }
    if (snmp && snmp.ups) {
      const u = snmp.ups;
      extra += `<section class="card"><header><h2>${icon('battery-charging')}USV</h2></header><dl class="details">
        <dt>Modell</dt><dd>${esc([u.manufacturer, u.model].filter(Boolean).join(' ') || '–')}</dd>
        <dt>Ladung</dt><dd>${esc(fmtPct(u.charge_pct))}</dd>
        <dt>Restlaufzeit</dt><dd>${u.runtime_min != null ? `${esc(u.runtime_min)} Min.` : '–'}</dd>
        <dt>Akku</dt><dd>${esc(u.battery_status)}</dd>
        <dt>Stromversorgung</dt><dd>${u.on_battery ? '<span class="badge sev-critical">Akkubetrieb</span>' : '<span class="badge st-up">Netzbetrieb</span>'}</dd></dl></section>`;
    }
    if (snmp && snmp.synology) {
      const s = snmp.synology;
      extra += `<section class="card"><header><h2>${icon('database')}Synology</h2></header><dl class="details">
        <dt>Modell</dt><dd>${esc(s.model)}</dd><dt>DSM</dt><dd>${esc(s.version || '–')}</dd>
        <dt>Seriennummer</dt><dd>${esc(s.serial || '–')}</dd><dt>Temperatur</dt><dd>${s.temp_c != null ? `${esc(s.temp_c)} °C` : '–'}</dd>
        <dt>Systemstatus</dt><dd>${s.status_ok ? '<span class="badge st-up">normal</span>' : '<span class="badge sev-critical">Fehler</span>'}</dd></dl></section>`;
    }
    // UniFi-Controller-Übersicht über die volle Breite; leere Bereiche weglassen
    const top = rows.length || extra
      ? `<div class="grid">${rows.length ? `<section class="${extra ? 'span-2' : 'span-3'}"><dl class="details">${rows.join('')}</dl></section>` : ''}
        ${extra ? `<div class="stack-v ${rows.length ? 'span-1' : 'span-3'}">${extra}</div>` : ''}</div>` : '';
    return `${top}${unifiHtml ? `<div class="stack-v${top ? ' gap-top' : ''}">${unifiHtml}</div>` : ''}` || empty('Keine Angaben', 'box');
  }

  // ----- Schnittstellen -----
  function tabInterfaces() {
    const inv = data.inventory || {};
    const list = (inv.snmp && inv.snmp.interfaces) || (inv.ssh && inv.ssh.interfaces) || [];
    const ips = (inv.ssh && inv.ssh.ips) || [];
    const nics = (inv.ssh && inv.ssh.nics) || [];
    const wan = data.device.wan_interface;
    const rows = list.filter((i) => i.type !== 24).map((i) => `<tr class="clickable" data-if="${esc(i.name)}">
      <td><div>${esc(i.name || i.descr)} ${i.name === wan ? `<span class="badge accent">Internet${data.device.wan_interface_manual ? '' : ' (erkannt)'}</span>` : ''}</div>
        ${i.alias ? `<div class="muted small">${esc(i.alias)}</div>` : ''}</td>
      <td>${i.oper === 'up' ? '<span class="badge st-up">verbunden</span>' : `<span class="badge plain">${esc(i.oper || '–')}</span>`}</td>
      <td>${esc(linkLabel(i.speed_mbps) || '–')}</td>
      <td class="mono small">${esc(i.mac || '–')}</td>
      <td>${esc(fmtBytes(i.rx_bytes))}</td><td>${esc(fmtBytes(i.tx_bytes))}</td></tr>`).join('');
    const ipRows = ips.map((a) => `<li><span class="mono">${esc(a.addr)}</span><span class="meta">${esc(a.iface)}</span></li>`)
      .concat(nics.map((n) => `<li><span><div>${esc(n.name)}</div><div class="mono small muted">${esc((n.ips || []).join(', '))}</div></span><span class="meta mono">${esc(n.mac || '')}</span></li>`));
    return `${rows ? `<p class="hint">Schnittstelle anklicken für den Verlauf der Datenrate.</p>
      <div class="table-wrap"><table><thead><tr><th>Schnittstelle</th><th>Status</th><th>Geschwindigkeit</th><th>MAC</th><th>Empfangen</th><th>Gesendet</th></tr></thead>
      <tbody>${rows}</tbody></table></div>` : ''}
      <div id="if-history"></div>
      ${ipRows.length ? `<br><h3>Adressen</h3><ul class="list">${ipRows.join('')}</ul>` : ''}`;
  }

  function bindInterfaces() {
    const showHistory = async (name, range = 24) => {
      const box = $('#if-history');
      box.innerHTML = '<p class="muted">Lade …</p>';
      const points = await api(`/devices/${id}/interfaces/history?name=${encodeURIComponent(name)}&hours=${range}`);
      const isWan = data.device.wan_interface === name;
      box.innerHTML = `<section class="card"><header><h2>${icon('chart-line')}${esc(name)}</h2>
          <div class="actions"><select id="if-range" aria-label="Zeitraum">${[[24, '24 Stunden'], [168, '7 Tage'], [720, '30 Tage']]
            .map(([h, l]) => `<option value="${h}"${h === range ? ' selected' : ''}>${l}</option>`).join('')}</select>
          ${canDev('devices.manage') ? (isWan
            ? `<button type="button" class="ghost sm" id="if-unwan">${icon('x', 'i-sm')}Internet-Markierung entfernen</button>`
            : `<button type="button" class="ghost sm" id="if-wan">${icon('world-www', 'i-sm')}Als Internet markieren</button>`) : ''}</div></header>
        ${lineChart(points, { series: [{ key: 'rx_bps', label: 'Empfangen' }, { key: 'tx_bps', label: 'Gesendet' }], format: fmtBps, width: 1100, height: 200 })}
        ${points.length ? '' : '<p class="muted small">Der Verlauf füllt sich mit jeder Abfrage (alle paar Minuten).</p>'}</section>`;
      $('#if-range').addEventListener('change', (ev) => showHistory(name, Number(ev.target.value)));
      $('#if-wan')?.addEventListener('click', async () => { if (await markWan(name)) render(); });
      $('#if-unwan')?.addEventListener('click', async () => { if (await markWan('')) render(); });
      box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    };
    $$('#tab-body tr[data-if]').forEach((tr) => tr.addEventListener('click', () => showHistory(tr.dataset.if).catch((e) => toast(e.message, true))));
  }

  // ----- Speicher -----
  function tabStorage() {
    const inv = data.inventory || {};
    let items = [];
    if (inv.ssh && inv.ssh.disks) items = inv.ssh.disks.map((d) => ({ name: d.mount, sub: [d.device, d.type].filter(Boolean).join(' · '), size: d.size_bytes, used: d.used_bytes, pct: d.pct }));
    else if (inv.snmp && inv.snmp.storage) items = inv.snmp.storage.filter((s) => s.kind === 'disk' || s.kind === 'ram').map((s) => ({ name: s.descr, sub: s.kind === 'ram' ? 'Arbeitsspeicher' : 'Datenträger', size: s.size_bytes, used: s.used_bytes, pct: s.pct }));
    if (!items.length) return empty('Keine Speicherangaben', 'database');
    return items.map((s) => `<div class="meter-row"><span class="ellipsis"><div>${esc(s.name)}</div><div class="muted small">${esc(s.sub)}</div></span>
      ${meter(s.pct)}<span class="small">${esc(fmtBytes(s.used))} / ${esc(fmtBytes(s.size))} · <b>${Math.round(s.pct)} %</b></span></div>`).join('');
  }

  // ----- Verlauf -----
  function tabHistory() {
    const s = data.stats;
    const has = (k) => s.some((p) => p[k] != null);
    const range = `<select id="range" aria-label="Zeitraum">${[[24, '24 Stunden'], [168, '7 Tage'], [720, '30 Tage'], [2160, '90 Tage']]
      .map(([h, l]) => `<option value="${h}"${h === hours ? ' selected' : ''}>${l}</option>`).join('')}</select>`;
    const pctSeries = [['cpu_pct', 'CPU'], ['mem_pct', 'RAM'], ['disk_pct', 'Speicher']].filter(([k]) => has(k)).map(([key, label]) => ({ key, label }));
    return `<div class="page-head"><h3>Messwerte</h3>${range}</div>
      <div class="grid">
        <section class="card span-3"><header><h2>${icon('clock')}Antwortzeit &amp; Ausfälle</h2></header>
          ${lineChart(data.points, { series: [{ key: 'rtt_ms', label: 'Antwortzeit' }], format: fmtMs, width: 1100, height: 200, outages: true })}</section>
        ${pctSeries.length ? `<section class="card span-3"><header><h2>${icon('gauge')}Auslastung</h2></header>
          ${lineChart(s, { series: pctSeries, format: (v) => `${Math.round(v)} %`, maxValue: 100, width: 1100, height: 200 })}</section>` : ''}
        ${has('power_w') ? `<section class="card span-3"><header><h2>${icon('bolt')}Leistung</h2></header>
          ${lineChart(s, { series: [{ key: 'power_w', label: 'Leistung' }], format: fmtWatt, width: 1100, height: 190 })}</section>` : ''}
        ${has('clients') ? `<section class="card span-3"><header><h2>${icon('antenna-bars-5')}WLAN-Clients</h2></header>
          ${lineChart(s, { series: [{ key: 'clients', label: 'Clients' }], width: 1100, height: 170 })}</section>` : ''}
        ${has('rx_bps') ? `<section class="card span-2"><header><h2>${icon('arrows-exchange')}${data.device.wan_interface ? `Internet (${esc(data.device.wan_interface)})` : data.net_client ? 'Datenverkehr laut UniFi' : 'Datenverkehr'}</h2></header>
          ${lineChart(s, { series: [{ key: 'rx_bps', label: data.net_client ? 'Download' : 'Empfangen' }, { key: 'tx_bps', label: data.net_client ? 'Upload' : 'Gesendet' }], format: fmtBps, width: 720 })}</section>` : ''}
        ${has('wifi_signal') ? `<section class="card span-3"><header><h2>${icon('wifi')}WLAN-Signal</h2><span class="muted small">besser als −67 dBm = gut, unter −75 dBm = schwach</span></header>
          ${lineChart(s.map((p) => ({ ...p, sig100: p.wifi_signal == null ? null : p.wifi_signal + 100 })), { series: [{ key: 'sig100', label: 'Signal' }], format: (v) => `${Math.round(v - 100)} dBm`, maxValue: 80, width: 1100, height: 170 })}</section>` : ''}
        ${has('temp_c') ? `<section class="card span-1"><header><h2>${icon('temperature')}Temperatur</h2></header>
          ${lineChart(s, { series: [{ key: 'temp_c', label: 'Temperatur' }], format: (v) => `${Math.round(v)} °C`, width: 360 })}</section>` : ''}
      </div>
      ${!s.length ? `<p class="muted small">CPU-, RAM- und Netzwerkverläufe erscheinen, sobald das Gerät per SNMP oder SSH abgefragt wird.</p>` : ''}`;
  }

  const tabEvents = () => eventList(data.events);

  // ----- Einstellungen -----
  function tabSettings() {
    const d = data.device;
    const assigned = new Set(data.credential_ids);
    const kindLabel = { snmp_v2c: 'SNMP v2c', snmp_v3: 'SNMP v3', ssh_password: 'SSH (Passwort)', ssh_key: 'SSH (Schlüssel)', http: 'HTTP / Shelly', unifi: 'UniFi', fritzbox: 'FRITZ!Box', opnsense: 'OPNsense', mikrotik: 'MikroTik' };
    const parent = allDevices.find((x) => x.id === d.parent_id);
    const parentOptions = allDevices.filter((x) => x.id !== d.id)
      .sort((a, b) => (['router', 'firewall', 'switch', 'access_point'].includes(b.device_type) - ['router', 'firewall', 'switch', 'access_point'].includes(a.device_type)) || deviceLabel(a).localeCompare(deviceLabel(b), 'de'))
      .map((x) => `<option value="${x.id}"${d.parent_manual && x.id === d.parent_id ? ' selected' : ''}>${esc(deviceLabel(x))} – ${esc(x.ip)}</option>`).join('');
    return `<div class="grid">
      <section class="span-1"><h3>Allgemein</h3><form class="form" id="dev-form">
        <label>Anzeigename<input name="name" maxlength="200" value="${esc(d.name || '')}" placeholder="${esc(d.hostname || d.ip)}"></label>
        <label>Gerätetyp<select name="device_type">
          <option value="auto">Automatisch erkennen${d.device_type_manual ? '' : ` (${esc(typeInfo(d.device_type).label)})`}</option>
          ${Object.entries(TYPES).map(([k, t]) => `<option value="${k}"${d.device_type_manual && d.device_type === k ? ' selected' : ''}>${esc(t.label)}</option>`).join('')}
        </select></label>
        <label>Notizen<textarea name="notes" maxlength="5000">${esc(d.notes || '')}</textarea></label>
        <div class="form-row"><label>Sektor<select name="site_id">${siteOptions(d.site_id, { perm: 'devices.manage' })}</select></label>
          <label>Tags (mit Komma getrennt)<input name="tags" maxlength="400" value="${esc((d.tags || []).join(', '))}" placeholder="z. B. kasse, kritisch"></label></div>
        <label class="inline"><input type="checkbox" name="monitored"${d.monitored ? ' checked' : ''}> Erreichbarkeit überwachen</label>
        <label>Hängt ab von (Switch, Access Point, Router)<select name="parent_id">
          <option value="-1"${!d.parent_manual ? ' selected' : ''}>Automatisch${!d.parent_manual && parent ? ` (${esc(deviceLabel(parent))})` : ' (aus UniFi)'}</option>
          <option value="0"${d.parent_manual && !d.parent_id ? ' selected' : ''}>– keins –</option>${parentOptions}</select></label>
        <p class="hint">Fällt das übergeordnete Gerät aus, kommt nur dafür ein Alarm – nicht zusätzlich für jedes Gerät dahinter.</p>
        ${d.integration === 'shelly' || (data.stats || []).some((p) => p.power_w != null) ? `<label>Strommessung<select name="energy_role">
          <option value="auto"${!d.energy_role ? ' selected' : ''}>Automatisch (Name mit „Balkon“, „Solar“, „PV“ … = Erzeugung)</option>
          <option value="consumer"${d.energy_role === 'consumer' ? ' selected' : ''}>Verbrauch</option>
          <option value="producer"${d.energy_role === 'producer' ? ' selected' : ''}>Erzeugung (Balkonkraftwerk, PV)</option>
          <option value="grid"${d.energy_role === 'grid' ? ' selected' : ''}>Netz-Zähler (+ Bezug, − Einspeisung)</option></select></label>` : ''}
        <div class="actions"><button type="submit">${icon('check')}Speichern</button></div>
      </form></section>
      <section class="span-1"><h3>Zugangsdaten für tiefe Abfragen</h3>
        ${!can('credentials.manage') ? '<p class="muted">Zugangsdaten zuordnen darf nur, wer Zugangsdaten verwalten darf.</p>' : credentials.length ? `<form class="form" id="cred-form"><div class="stack-v">
          ${credentials.map((c) => `<label class="inline"><input type="checkbox" name="cred" value="${c.id}"${assigned.has(c.id) ? ' checked' : ''}>
            <span>${esc(c.name)} <span class="muted small">· ${esc(kindLabel[c.kind] || c.kind)}${c.username ? ` · ${esc(c.username)}` : ''}</span></span></label>`).join('')}
          </div><div class="actions"><button type="submit">${icon('key')}Zuordnen &amp; abfragen</button></div></form>`
          : `<p class="muted">Noch keine Zugangsdaten angelegt. <a href="#/credentials">Jetzt anlegen</a></p>`}
        ${inventoryStatus()}
        ${data.ssh_host_key ? `<h3>SSH-Host-Schlüssel</h3><p class="mono small">${esc(data.ssh_host_key)}</p>` : ''}
        ${data.tls_pin ? `<h3>Gemerktes Zertifikat</h3><p class="mono small wrap-any">SHA-256 ${esc(data.tls_pin)}</p>` : ''}
        ${data.ssh_host_key || data.tls_pin ? `<button type="button" class="ghost sm" id="reset-key">${icon('refresh', 'i-sm')}Gemerkte Schlüssel vergessen</button>
          <p class="hint">Nur nach einer Neuinstallation des Geräts nötig – oder wenn die Diagnose „Zertifikat geändert“ meldet und du sicher bist, dass das Gerät neu aufgesetzt wurde.</p>` : ''}
      </section>
      <section class="span-1"><h3>Gerät entfernen</h3>
        <p class="muted small">Löscht das Gerät mit allen Messwerten und Ereignissen. Wird es beim nächsten Scan wieder gefunden, taucht es neu auf.</p>
        <button type="button" class="danger" id="dev-delete">${icon('trash')}Gerät löschen</button></section>
    </div>`;
  }

  function bindSettings() {
    makeSearchable($('#dev-form select[name="parent_id"]'), 'Übergeordnetes Gerät suchen …');
    $('#dev-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      attempt(async () => {
        data.device = await api(`/devices/${id}`, {
          method: 'PATCH',
          body: { name: f.get('name'), notes: f.get('notes'), monitored: f.get('monitored') === 'on', device_type: f.get('device_type'), parent_id: Number(f.get('parent_id')),
            site_id: Number(f.get('site_id')), tags: String(f.get('tags') || '').split(',').map((t) => t.trim()).filter(Boolean),
            ...(f.get('energy_role') ? { energy_role: f.get('energy_role') } : {}) },
        });
        render();
      }, 'Gespeichert');
    });
    $('#cred-form')?.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const ids = $$('input[name="cred"]:checked', ev.target).map((i) => Number(i.value));
      attempt(async () => {
        await api(`/devices/${id}/credentials`, { method: 'PUT', body: { ids } });
        data.credential_ids = ids;
        setTimeout(async () => { data = await api(`/devices/${id}?hours=${hours}`); render(); }, 10000);
      }, 'Zugeordnet – das Gerät wird jetzt abgefragt');
    });
    $('#reset-key')?.addEventListener('click', () => {
      if (!confirm('Gemerkten SSH-Schlüssel bzw. das Zertifikat vergessen? Beim nächsten Kontakt wird der dann gesendete Schlüssel übernommen.')) return;
      attempt(async () => { await api(`/devices/${id}/ssh-key`, { method: 'DELETE' }); await reload(); render(); }, 'Schlüssel zurückgesetzt');
    });
    $('#dev-delete').addEventListener('click', () => {
      if (!confirm('Gerät mit allen Messwerten und Ereignissen löschen?')) return;
      attempt(async () => { await api(`/devices/${id}`, { method: 'DELETE' }); location.hash = '#/devices'; }, 'Gerät gelöscht');
    });
  }

  render();
  autoRefresh(reload, 60);
}

// ---------------------------------------------------------------------------
// Dienste (Dienst-Checks)
// ---------------------------------------------------------------------------

const CHECK_KINDS = {
  http: { label: 'Webseite / HTTP(S)', icon: 'world-www', target: 'URL', placeholder: 'https://monitoring.example.de' },
  tcp: { label: 'Port (TCP)', icon: 'plug-connected', target: 'Host:Port', placeholder: '192.168.178.10:22' },
  dns: { label: 'DNS-Auflösung', icon: 'world', target: 'Name', placeholder: 'example.de' },
  tls: { label: 'TLS-Zertifikat', icon: 'shield-lock', target: 'Host:Port', placeholder: 'mail.example.de:993' },
};
const CHECK_STATUS = { up: ['ok', 'st-up'], down: ['Ausfall', 'st-down'], warn: ['Warnung', 'warn'], pending: ['prüft …', 'plain'], unknown: ['neu', 'plain'] };
const checkBadge = (c) => { if (c.paused) return `<span class="badge paused" title="Überwachung pausiert – ${esc(c.paused)}">pausiert</span>`; const [label, cls] = CHECK_STATUS[c.status] || CHECK_STATUS.unknown; return `<span class="badge ${cls}">${esc(label)}</span>`; };

function beats(list, count = 40) {
  const items = (list || []).slice(-count);
  const pad = count - items.length;
  return `<div class="beats" title="Letzte ${count} Prüfungen">${'<i></i>'.repeat(pad)}${items.map((ok) => `<i class="${ok ? 'ok' : 'bad'}"></i>`).join('')}</div>`;
}

const certDays = (c) => (c.cert_expires_at ? Math.floor((new Date(c.cert_expires_at) - Date.now()) / 86400000) : null);

function checkRow(c) {
  const kind = CHECK_KINDS[c.kind] || {};
  const days = certDays(c);
  return `<div class="check-row st-${esc(c.status)}${c.enabled ? '' : ' off'}" data-check="${c.id}">
    <span class="check-dot"></span>
    <div class="check-main"><div class="check-title">${icon(kind.icon || 'activity', 'i-sm')}<strong class="ellipsis">${esc(c.name)}</strong> ${checkBadge(c)}</div>
      <div class="muted small ellipsis">${esc(c.target)}${c.device_label ? ` · ${esc(c.device_label)}` : ''}</div>
      <div class="small ellipsis check-msg">${esc(c.last_message || (c.enabled ? 'noch nicht geprüft' : 'pausiert'))}</div></div>
    ${beats(c.beats)}
    <div class="check-nums"><strong>${c.uptime_24h != null ? `${esc(c.uptime_24h)} %` : '–'}</strong><span class="muted small">24 h</span></div>
    <div class="check-nums"><strong>${esc(fmtMs(c.last_ms))}</strong><span class="muted small">${days != null ? `Zert. ${days} T.` : 'Antwort'}</span></div>
  </div>`;
}

async function viewChecks() {
  let checks = await api('/checks');
  const paused = await pauseNotice();
  const render = () => {
    const count = (s) => checks.filter((c) => c.status === s).length;
    view().innerHTML = `
      <div class="page-head"><div class="kpis compact">
          ${kpi('Dienste', checks.length, 'world-www', 'tone-accent', '#/checks')}
          ${kpi('OK', count('up'), 'circle-check', 'tone-up', '#/checks')}
          ${kpi('Warnung', count('warn'), 'alert-triangle', count('warn') ? 'tone-warn' : 'tone-muted', '#/checks')}
          ${kpi('Ausfall', count('down'), 'circle-x', count('down') ? 'tone-down' : 'tone-muted', '#/checks')}</div>
        <div class="actions">${canAny('checks.manage') ? `<button type="button" id="check-add">${icon('plus')}Dienst hinzufügen</button>` : ''}</div></div>
      ${paused}
      <div class="card">${checks.length ? `<div class="check-list">${checks.map(checkRow).join('')}</div>`
        : empty('Noch keine Dienste. Beispiele: eigene Webseite (mit Suchwort), Zertifikat des Mailservers, DNS des Routers, SSH-Port des NAS.', 'world-www')}</div>`;
    $('#check-add')?.addEventListener('click', () => checkDialog(null));
    $$('[data-check]').forEach((row) => row.addEventListener('click', () => checkDetail(Number(row.dataset.check))));
  };

  async function checkDetail(id) {
    const h = await api(`/checks/${id}/history?hours=24`);
    const c = h.check;
    const days = certDays(c);
    const dlg = openModal(c.name, `<div class="check-detail">
      <p>${checkBadge(c)} <span class="muted">${esc((CHECK_KINDS[c.kind] || {}).label || c.kind)} · ${esc(c.target)} · alle ${esc(c.interval_s)} s</span></p>
      <p class="small">${esc(c.last_message || '')}</p>
      <div class="kpis compact">${h.uptime.map((u) => kpi(`Verfügbar ${u.label}`, u.value != null ? `${u.value} %` : '–', 'activity', 'tone-accent', '#/checks')).join('')}
        ${days != null ? kpi('Zertifikat', `${days} Tage`, 'shield-lock', days < 14 ? 'tone-warn' : 'tone-up', '#/checks') : ''}</div>
      ${lineChart(h.points, { series: [{ key: 'ms', label: 'Antwortzeit' }], format: fmtMs, height: 180, width: 720, outages: true })}
      ${beats(c.beats)}
      ${can('checks.manage', c.site_id) ? `<div class="actions"><button type="button" id="cd-run">${icon('refresh')}Jetzt prüfen</button>
        <button type="button" class="ghost" id="cd-edit">${icon('edit')}Bearbeiten</button>
        <button type="button" class="ghost" id="cd-del">${icon('trash')}Löschen</button></div>` : ''}</div>`);
    dlg.classList.add('wide');
    $('#cd-run', dlg)?.addEventListener('click', () => attempt(async () => {
      const r = await api(`/checks/${id}/run`, { method: 'POST' });
      toast(`${r.outcome.ok ? 'OK' : 'Fehler'}: ${r.outcome.message}`, !r.outcome.ok);
      dlg.close();
      checks = await api('/checks');
      render();
    }));
    $('#cd-edit', dlg)?.addEventListener('click', () => { dlg.close(); checkDialog(c); });
    $('#cd-del', dlg)?.addEventListener('click', () => {
      if (!confirm(`Dienst „${c.name}“ löschen? Der Verlauf wird ebenfalls gelöscht.`)) return;
      attempt(async () => { await api(`/checks/${id}`, { method: 'DELETE' }); dlg.close(); checks = await api('/checks'); render(); }, 'Dienst gelöscht');
    });
  }

  async function checkDialog(check) {
    const devices = await api('/devices');
    const c = check || { kind: 'http', interval_s: 60, timeout_s: 10, enabled: true, config: {} };
    const cfg = c.config || {};
    const dlg = openModal(check ? 'Dienst bearbeiten' : 'Dienst hinzufügen', `<form class="form" id="check-form">
      <label>Art<select name="kind">${Object.entries(CHECK_KINDS).map(([k, v]) => `<option value="${k}"${k === c.kind ? ' selected' : ''}>${esc(v.label)}</option>`).join('')}</select></label>
      <label><span id="target-label">Ziel</span><input name="target" required value="${esc(c.target || '')}"></label>
      <label>Name<input name="name" value="${esc(c.name || '')}" placeholder="z. B. Eigene Webseite"></label>
      <div data-k="http" class="form">
        <div class="form-row"><label>Suchwort im Inhalt (optional)<input name="keyword" value="${esc(cfg.keyword || '')}" placeholder="z. B. Willkommen"></label>
          <label>Erwarteter Status<input name="expect_status" value="${esc(cfg.expect_status || '')}" placeholder="Standard 200–399, z. B. 200,401"></label></div>
        <label class="inline"><input type="checkbox" name="keyword_invert"${cfg.keyword_invert ? ' checked' : ''}> Suchwort darf <b>nicht</b> vorkommen (z. B. „Fehler“)</label>
        <label>Methode<select name="method"><option value="GET">GET</option><option value="HEAD"${cfg.method === 'HEAD' ? ' selected' : ''}>HEAD (nur Kopfzeilen)</option></select></label>
        <label class="inline"><input type="checkbox" name="check_cert"${cfg.check_cert === false ? '' : ' checked'}> Bei HTTPS auch das Zertifikat überwachen</label>
      </div>
      <div data-k="dns" class="form"><div class="form-row">
        <label>DNS-Server (optional)<input name="server" value="${esc(cfg.server || '')}" placeholder="leer = System, z. B. 192.168.178.1"></label>
        <label>Eintrag<select name="record"><option value="A">A (IPv4)</option><option value="AAAA"${cfg.record === 'AAAA' ? ' selected' : ''}>AAAA (IPv6)</option></select></label></div>
        <label>Erwartete Adresse (optional)<input name="expect" value="${esc(cfg.expect || '')}" placeholder="z. B. 203.0.113.10"></label></div>
      <div data-k="http tls" class="form"><div class="form-row">
        <label>Warnen, wenn Zertifikat in weniger als … Tagen abläuft<input name="warn_days" type="number" min="1" max="365" value="${esc(cfg.warn_days ?? 14)}"></label>
        <label class="inline"><input type="checkbox" name="ignore_tls"${cfg.ignore_tls ? ' checked' : ''}> Selbst signierte Zertifikate akzeptieren</label></div></div>
      <div class="form-row">
        <label>Prüfen alle … Sekunden<input name="interval_s" type="number" min="10" max="86400" value="${esc(c.interval_s)}"></label>
        <label>Zeitlimit (s)<input name="timeout_s" type="number" min="1" max="60" value="${esc(c.timeout_s)}"></label>
        <label>Ausfall nach … Fehlversuchen<input name="retries" type="number" min="1" max="10" value="${esc(cfg.retries ?? 2)}"></label></div>
      <label>Sektor<select name="site_id">${can('checks.manage') ? '<option value="">übergreifend (z. B. Internet-Dienste)</option>' : ''}${siteOptions(c.site_id ?? null, { perm: 'checks.manage' })}</select></label>
      <label>Zugehöriges Gerät (optional – dann gilt dessen Sektor)<select name="device_id"><option value="">–</option>
        ${devices.map((d) => `<option value="${d.id}"${d.id === c.device_id ? ' selected' : ''}>${esc(deviceLabel(d))} – ${esc(d.ip)}</option>`).join('')}</select></label>
      <label class="inline"><input type="checkbox" name="enabled"${c.enabled ? ' checked' : ''}> Aktiv</label>
      <p class="hint">Alarm bei Ausfall oder ablaufendem Zertifikat: unter <a href="#/alerts?tab=rules">Alarme → Regeln</a> „Dienst ausgefallen“ bzw. „Zertifikat läuft ab“ anlegen.</p>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    dlg.classList.add('wide');
    const form = $('#check-form', dlg);
    const e = form.elements;
    const update = () => {
      const def = CHECK_KINDS[e.kind.value];
      $('#target-label', dlg).textContent = def.target;
      e.target.placeholder = def.placeholder;
      $$('[data-k]', form).forEach((el) => { el.hidden = !el.dataset.k.split(' ').includes(e.kind.value); });
    };
    e.kind.addEventListener('change', update);
    update();
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const k = e.kind.value;
      const config = { retries: Number(e.retries.value || 2) };
      if (k === 'http') Object.assign(config, { keyword: e.keyword.value.trim(), keyword_invert: e.keyword_invert.checked, expect_status: e.expect_status.value.trim(), method: e.method.value, check_cert: e.check_cert.checked });
      if (k === 'dns') Object.assign(config, { server: e.server.value.trim(), record: e.record.value, expect: e.expect.value.trim() });
      if (k === 'http' || k === 'tls') Object.assign(config, { warn_days: Number(e.warn_days.value || 14), ignore_tls: e.ignore_tls.checked });
      const body = { kind: k, target: e.target.value.trim(), name: e.name.value.trim(), config, interval_s: Number(e.interval_s.value),
        timeout_s: Number(e.timeout_s.value), device_id: e.device_id.value ? Number(e.device_id.value) : null, enabled: e.enabled.checked,
        site_id: e.site_id.value ? Number(e.site_id.value) : null };
      attempt(async () => {
        if (check) await api(`/checks/${check.id}`, { method: 'PATCH', body });
        else await api('/checks', { method: 'POST', body });
        dlg.close();
        checks = await api('/checks');
        render();
      }, 'Dienst gespeichert – wird gleich geprüft');
    });
  }

  render();
  // Ergebnisse kommen live über den Stream
  onLive((msg) => {
    if (msg.type !== 'check') return;
    const c = checks.find((x) => x.id === msg.id);
    if (!c) return;
    Object.assign(c, { status: msg.status, last_ms: msg.ms, last_message: msg.message, last_check: msg.time });
    c.beats = [...(c.beats || []), msg.ok].slice(-40);
    const row = $(`[data-check="${msg.id}"]`);
    if (row && !$('#modal').open) {
      row.outerHTML = checkRow(c);
      const fresh = $(`[data-check="${msg.id}"]`);
      fresh.classList.add('flash');
      fresh.addEventListener('click', () => checkDetail(msg.id));
    }
  });
  autoRefresh(async () => { if (!$('#modal').open) { checks = await api('/checks'); render(); } }, 60);
}

// ---------------------------------------------------------------------------
// Netzwerkkarte
// ---------------------------------------------------------------------------

const INFRA = ['router', 'firewall', 'switch', 'access_point', 'network'];

async function viewMap() {
  let nodes = await api('/topology');
  let hideLeaves = readPref('np-map-leaves', 'show') === 'hide';
  let zoom = 1;
  let filter = '';

  view().innerHTML = `
    <div class="page-head"><div class="actions">
        <input type="search" id="map-q" placeholder="Gerät hervorheben …" aria-label="Suchen">
        <label class="inline"><input type="checkbox" id="map-leaves"${hideLeaves ? ' checked' : ''}> Endgeräte zusammenfassen</label></div>
      <div class="actions"><button type="button" class="ghost sm" id="map-out" title="Verkleinern">−</button>
        <button type="button" class="ghost sm" id="map-in" title="Vergrößern">+</button></div></div>
    <div class="card map-card"><div class="map-scroll" id="map"></div>
      <p class="muted small">Linien: <b>durchgezogen</b> = bekannte Verbindung (aus UniFi oder von Hand), <b>gestrichelt</b> = vermutet (hängt vermutlich direkt am Router).
        Zuordnung ändern: beim Gerät unter „Einstellungen → Hängt ab von“.</p></div>`;

  const draw = () => {
    const byId = new Map(nodes.map((n) => [n.id, { ...n, children: [] }]));
    const gateways = [...byId.values()].filter((n) => !n.parent_id && (n.wan || n.device_type === 'firewall' || n.device_type === 'router'))
      .sort((a, b) => Number(b.wan) - Number(a.wan));
    const gateway = gateways[0];
    const internet = { id: 0, label: 'Internet', device_type: 'cloud', status: 'up', children: [], ip: '' };
    for (const n of byId.values()) {
      const parent = n.parent_id && byId.get(n.parent_id);
      if (parent) parent.children.push(n);
      else if (gateways.includes(n)) internet.children.push(n);
      else if (gateway) { n.guess = true; gateway.children.push(n); } else internet.children.push(n);
    }
    const order = (a, b) => (INFRA.includes(b.device_type) - INFRA.includes(a.device_type)) || (b.children.length - a.children.length)
      || String(a.label).localeCompare(String(b.label), 'de');
    // Layout von links nach rechts: Tiefe → x, Blätter untereinander
    const ROW = 30;
    const COL = 250;
    let row = 0;
    const placed = [];
    const edges = [];
    const layout = (n, depth) => {
      n.children.sort(order);
      let kids = n.children;
      if (hideLeaves && depth > 0) {
        const leaves = kids.filter((k) => !k.children.length && !INFRA.includes(k.device_type));
        if (leaves.length > 1) {
          kids = kids.filter((k) => !leaves.includes(k));
          const down = leaves.filter((l) => l.monitored && l.status === 'down').length;
          kids.push({ id: `sum-${n.id}`, summary: true, label: `+ ${leaves.length} Geräte${down ? ` (${down} offline)` : ''}`, device_type: 'devices',
            status: down ? 'down' : 'up', children: [], guess: leaves.every((l) => l.guess) });
        }
      }
      n.x = depth * COL;
      if (!kids.length) {
        n.y = row * ROW;
        row += 1;
      } else {
        kids.forEach((k) => { layout(k, depth + 1); edges.push([n, k]); });
        n.y = (kids[0].y + kids[kids.length - 1].y) / 2;
      }
      placed.push(n);
    };
    layout(internet, 0);
    const W = Math.max(...placed.map((n) => n.x)) + 260;
    const H = Math.max(ROW, row * ROW) + 20;
    const statusCls = (n) => (n.device_type === 'cloud' ? 'up' : !n.monitored && !n.summary ? 'off' : n.status);
    const svg = `<svg class="map" width="${W * zoom}" height="${H * zoom}" viewBox="-20 -15 ${W + 20} ${H + 10}">
      ${edges.map(([a, b]) => `<path class="edge${b.guess ? ' guess' : ''}${statusCls(b) === 'down' ? ' down' : ''}"
        d="M${a.x + 12},${a.y} C${a.x + COL / 2},${a.y} ${b.x - COL / 2},${b.y} ${b.x - 12},${b.y}"/>`).join('')}
      ${placed.map((n) => {
        const hit = filter && String(n.label).toLowerCase().includes(filter) || (filter && String(n.ip).includes(filter));
        const iconName = n.device_type === 'cloud' ? 'cloud' : n.summary ? 'devices' : typeInfo(n.device_type).icon;
        const inner = `<g class="node st-${esc(statusCls(n))}${hit ? ' hit' : ''}" transform="translate(${n.x},${n.y})">
          <circle r="12"/><use href="icons.svg?v=0.9.16#i-${esc(iconName)}" x="-7" y="-7" width="14" height="14"/>
          <text x="18" y="4">${esc(n.label)}</text>${n.ip ? `<text class="ip" x="18" y="15">${esc(n.ip)}</text>` : ''}</g>`;
        return typeof n.id === 'number' && n.id > 0 ? `<a href="#/device/${n.id}">${inner}</a>` : inner;
      }).join('')}</svg>`;
    $('#map').innerHTML = svg;
    const hit = $('#map .hit');
    if (hit) hit.scrollIntoView({ block: 'center', inline: 'center' });
  };

  $('#map-leaves').addEventListener('change', (ev) => { hideLeaves = ev.target.checked; writePref('np-map-leaves', hideLeaves ? 'hide' : 'show'); draw(); });
  $('#map-q').addEventListener('input', (ev) => { filter = ev.target.value.trim().toLowerCase(); draw(); });
  $('#map-in').addEventListener('click', () => { zoom = Math.min(2, zoom * 1.2); draw(); });
  $('#map-out').addEventListener('click', () => { zoom = Math.max(0.4, zoom / 1.2); draw(); });
  draw();
  onLive((msg) => {
    if (msg.type !== 'status') return;
    msg.devices.forEach((d) => { const n = nodes.find((x) => x.id === d.id); if (n) n.status = d.status; });
    draw();
  });
  autoRefresh(async () => { nodes = await api('/topology'); draw(); }, 60);
}
