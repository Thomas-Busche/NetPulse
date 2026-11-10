'use strict';
/* Sektoren, Leitstand, Benutzer/Gruppen/Rollen, API-Schlüssel, Alarm-Bestätigung */

// ---------------------------------------------------------------------------
// Sektoren: Zwischenspeicher und Auswahlfelder
// ---------------------------------------------------------------------------

const sitesCache = { at: 0, list: [] };

/** Sichtbare Sektoren (höchstens einmal pro Minute neu laden) */
async function loadSites(force = false) {
  if (force || Date.now() - sitesCache.at > 60000) {
    sitesCache.list = await api('/sites');
    sitesCache.at = Date.now();
  }
  return sitesCache.list;
}

const siteName = (id) => (sitesCache.list.find((s) => s.id === id) || {}).name || (id == null ? 'Alle Sektoren' : `Sektor ${id}`);

/** Sektoren als Baum sortiert, mit Einrückung für die Anzeige */
function siteTree(list) {
  const out = [];
  const add = (parent, depth) => {
    list.filter((s) => (s.parent_id ?? null) === parent).sort((a, b) => a.position - b.position || a.name.localeCompare(b.name))
      .forEach((s) => { if (!out.some((o) => o.site.id === s.id)) { out.push({ site: s, depth }); add(s.id, depth + 1); } });
  };
  add(null, 0);
  // Sektoren, deren Eltern-Sektor der Benutzer nicht sieht, oben anfügen
  list.filter((s) => !out.some((o) => o.site.id === s.id)).forEach((s) => { out.push({ site: s, depth: 0 }); add(s.id, 1); });
  return out;
}

/**
 * <option>-Liste der Sektoren. `perm`: nur Sektoren, in denen der Benutzer dieses Recht hat.
 * `all`: Eintrag für „alle Sektoren“ (Wert leer) voranstellen.
 */
function siteOptions(selected, { all = null, perm = null } = {}) {
  const rows = siteTree(sitesCache.list).filter(({ site }) => !perm || can(perm, site.id));
  return `${all ? `<option value="">${esc(all)}</option>` : ''}${rows.map(({ site, depth }) =>
    `<option value="${site.id}"${site.id === selected ? ' selected' : ''}>${'  '.repeat(depth)}${esc(site.name)}</option>`).join('')}`;
}

const STATE_LABEL = { red: 'Störung', yellow: 'Warnung', maintenance: 'Wartung', green: 'In Ordnung' };
const SEV_LABEL = { critical: 'Kritisch', warning: 'Warnung', info: 'Hinweis' };

// ---------------------------------------------------------------------------
// Alarm bestätigen
// ---------------------------------------------------------------------------

/** Dialog „Alarm bestätigen“; `after` wird nach Erfolg aufgerufen */
function ackDialog(alertId, after) {
  const dlg = openModal('Alarm bestätigen', `<form class="form" id="ack-form">
    <p class="muted">Bestätigen heißt: „Ich kümmere mich.“ Erinnerungen und die Eskalation für diesen Alarm entfallen, im Leitstand wird er gelb statt rot.</p>
    <label>Kommentar (optional)<input name="comment" maxlength="500" placeholder="z. B. Techniker ist unterwegs"></label>
    <div class="actions"><button type="submit">${icon('user-check')}Bestätigen</button></div></form>`);
  $('#ack-form', dlg).addEventListener('submit', (ev) => {
    ev.preventDefault();
    attempt(async () => {
      await api(`/alerts/${alertId}/ack`, { method: 'POST', body: { comment: ev.target.comment.value.trim() || null, acknowledge: true } });
      dlg.close();
      if (after) await after();
    }, 'Alarm bestätigt');
  });
}

function unack(alertId, after) {
  return attempt(async () => {
    await api(`/alerts/${alertId}/ack`, { method: 'POST', body: { acknowledge: false } });
    if (after) await after();
  }, 'Bestätigung zurückgenommen');
}

/** Bestätigungs-Info bzw. -Knopf für einen offenen Alarm */
function ackCell(a) {
  if (a.resolved_at) return '';
  if (a.acknowledged_at) {
    return `<span class="badge info" title="${esc(fmtTime(a.acknowledged_at))}${a.ack_comment ? ` – ${esc(a.ack_comment)}` : ''}">${icon('user-check', 'i-sm')}${esc(a.acknowledged_by || 'bestätigt')}</span>
      ${can('alerts.ack', a.site_id) ? `<button type="button" class="ghost sm" data-unack="${a.id}" title="Bestätigung zurücknehmen">${icon('x', 'i-sm')}</button>` : ''}`;
  }
  return can('alerts.ack', a.site_id) ? `<button type="button" class="sm" data-ack="${a.id}">${icon('user-check', 'i-sm')}Bestätigen</button>` : '';
}

function bindAck(root, after) {
  $$('[data-ack]', root).forEach((b) => b.addEventListener('click', () => ackDialog(b.dataset.ack, after)));
  $$('[data-unack]', root).forEach((b) => b.addEventListener('click', () => unack(b.dataset.unack, after)));
}

// ---------------------------------------------------------------------------
// Leitstand
// ---------------------------------------------------------------------------

async function viewLeitstand(_arg, params) {
  await loadSites();
  const nav = state.nav;
  let site = params.get('site') ? Number(params.get('site')) : null;
  let rotate = Number(params.get('rotate') || 0);
  let rotateTimer = null;

  view().innerHTML = `<div class="ls">
    <div class="page-head ls-head">
      <div class="actions">
        <select id="ls-site" aria-label="Sektor">${siteOptions(site, { all: 'Alle Sektoren' })}</select>
        <label class="inline small"><input type="checkbox" id="ls-rotate"${rotate ? ' checked' : ''}> Sektoren durchschalten</label>
      </div>
      <div class="actions">
        <span class="ls-clock" id="ls-clock"></span>
        <button type="button" class="ghost sm" id="ls-full" title="Vollbild">${icon('maximize', 'i-sm')}Vollbild</button>
      </div>
    </div>
    <div id="ls-kpis"></div>
    <div class="ls-tiles" id="ls-tiles"></div>
    <section class="card"><header><h2>${icon('alert-triangle')}Jetzt kaputt</h2><span class="muted small" id="ls-count"></span></header>
      <div id="ls-problems"><div class="empty">Lade …</div></div></section>
  </div>`;

  const setHash = () => {
    const q = new URLSearchParams();
    if (site) q.set('site', site);
    if (rotate) q.set('rotate', rotate);
    history.replaceState(null, '', `#/leitstand${q.toString() ? `?${q}` : ''}`);
  };

  const render = async () => {
    const q = site ? `?site=${site}` : '';
    const [status, problems] = await Promise.all([api(`/sites/status${q}`), api(`/problems${q}`)]);
    if (nav !== state.nav) return;
    const all = status.sites;
    // Kacheln: bei Auswahl eines Sektors dessen direkte Unter-Sektoren (oder er selbst), sonst die obersten Sektoren
    let tiles = site ? all.filter((s) => s.parent_id === site) : all.filter((s) => !all.some((p) => p.id === s.parent_id));
    if (site && !tiles.length) tiles = all.filter((s) => s.id === site);
    const top = site ? all.filter((s) => s.id === site) : tiles;
    const total = (path) => top.reduce((n, s) => n + (path.reduce((v, k) => (v ? v[k] : 0), s.rollup) || 0), 0);
    const critical = total(['alerts', 'critical']);
    const warning = total(['alerts', 'warning']);
    const kpi = (cls, value, label, ic) => `<div class="kpi ${cls}"><span class="kpi-icon">${icon(ic)}</span><div><div class="kpi-value">${esc(value)}</div><div class="kpi-label">${esc(label)}</div></div></div>`;
    $('#ls-kpis').innerHTML = `<div class="kpis ls-kpis">
      ${kpi(critical ? 'k-down' : 'k-up', critical, 'kritische Alarme (offen)', 'alert-triangle')}
      ${kpi(warning ? 'k-warn' : 'k-up', warning, 'Warnungen (offen)', 'bell')}
      ${kpi(total(['down']) ? 'k-down' : 'k-up', `${total(['down'])} / ${total(['monitored'])}`, 'Geräte offline', 'devices')}
      ${kpi(total(['checks', 'down']) ? 'k-down' : 'k-up', `${total(['checks', 'down'])} / ${total(['checks', 'total'])}`, 'Dienste gestört', 'world-www')}
      ${kpi('k-info', total(['alerts', 'acknowledged']), 'bestätigt, in Arbeit', 'user-check')}
    </div>`;
    $('#ls-tiles').innerHTML = tiles.length ? tiles.map((s) => {
      const r = s.rollup;
      const own = s.own || {};
      const probe = own.probe ? `<span class="chip">${icon('antenna-bars-5', 'i-sm')}Probe ${own.probe.online ? 'online' : 'offline'}</span>` : '';
      const maint = (own.maintenance || []).length ? `<span class="chip">${icon('calendar-time', 'i-sm')}${esc(own.maintenance.join(', '))}</span>` : '';
      const hasChildren = all.some((c) => c.parent_id === s.id);
      return `<button type="button" class="ls-tile st-${esc(s.state)}" data-site="${s.id}"${hasChildren || !site ? '' : ' disabled'}>
        <span class="ls-light" aria-hidden="true"></span>
        <span class="ls-name">${esc(s.name)}</span>
        <span class="ls-state">${esc(STATE_LABEL[s.state] || s.state)}</span>
        <span class="ls-nums"><b>${r.up}</b> online · <b class="${r.down ? 'down' : ''}">${r.down}</b> offline
          ${r.checks.total ? ` · Dienste ${r.checks.total - r.checks.down}/${r.checks.total}` : ''}</span>
        <span class="ls-alerts">${r.alerts.critical ? `<span class="badge sev-critical">${r.alerts.critical} kritisch</span>` : ''}
          ${r.alerts.warning ? `<span class="badge warn">${r.alerts.warning} Warnung</span>` : ''}
          ${r.alerts.acknowledged ? `<span class="badge info">${r.alerts.acknowledged} bestätigt</span>` : ''}
          ${own.avail_24h != null ? `<span class="chip">${esc(own.avail_24h)} % (24 h)</span>` : ''}${probe}${maint}</span>
      </button>`;
    }).join('') : empty('Keine Sektoren sichtbar.', 'building');
    $$('#ls-tiles [data-site]').forEach((b) => b.addEventListener('click', () => {
      site = Number(b.dataset.site);
      $('#ls-site').value = String(site);
      setHash();
      render().catch(() => {});
    }));
    $('#ls-count').textContent = problems.length ? `${problems.length} Einträge` : '';
    $('#ls-problems').innerHTML = problems.length ? `<div class="table-wrap"><table class="ls-table">
      <thead><tr><th>Schwere</th><th>Sektor</th><th>Was</th><th>Seit</th><th>Bearbeitung</th></tr></thead>
      <tbody>${problems.map((p) => `<tr class="${p.acknowledged_at ? 'acked' : `sev-${esc(p.severity)}`}">
        <td><span class="badge ${p.severity === 'critical' ? 'sev-critical' : p.severity === 'info' ? 'info' : 'warn'}">${esc(SEV_LABEL[p.severity] || p.severity)}</span></td>
        <td class="small">${esc(p.site || '–')}</td>
        <td>${p.device_id ? `<a href="#/device/${p.device_id}">${esc(p.message)}</a>` : p.check_id ? `<a href="#/checks">${esc(p.message)}</a>` : esc(p.message)}
          ${p.rule ? `<div class="muted small">${esc(p.rule)}</div>` : ''}</td>
        <td class="small" title="${esc(fmtTime(p.since))}">${esc(fmtSince(p.since))}</td>
        <td>${p.kind === 'alert' && !state.user.kiosk ? ackCell({ ...p, resolved_at: null }) : p.acknowledged_at ? `<span class="badge info">${esc(p.acknowledged_by || 'bestätigt')}</span>` : ''}</td>
      </tr>`).join('')}</tbody></table></div>` : empty('Alles in Ordnung – nichts kaputt.', 'circle-check');
    bindAck($('#ls-problems'), render);
  };

  const tick = () => { const c = $('#ls-clock'); if (c) c.textContent = new Date().toLocaleString('de-DE', { weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
  tick();
  const clock = setInterval(tick, 1000);

  const startRotation = () => {
    clearInterval(rotateTimer);
    if (!rotate) return;
    rotateTimer = setInterval(() => {
      if (document.hidden) return;
      const ids = [null, ...siteTree(sitesCache.list).filter(({ depth }) => depth === 0).map(({ site: s }) => s.id)];
      site = ids[(ids.indexOf(site) + 1) % ids.length];
      $('#ls-site').value = site ? String(site) : '';
      setHash();
      render().catch(() => {});
    }, rotate * 1000);
  };

  $('#ls-site').addEventListener('change', (ev) => { site = ev.target.value ? Number(ev.target.value) : null; setHash(); render().catch(() => {}); });
  $('#ls-rotate').addEventListener('change', (ev) => { rotate = ev.target.checked ? 30 : 0; setHash(); startRotation(); });
  $('#ls-full').addEventListener('click', () => {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    else document.documentElement.requestFullscreen().catch(() => toast('Vollbild wird von diesem Browser nicht unterstützt', true));
  });

  await render();
  startRotation();
  // Statuswechsel, neue und bestätigte Alarme kommen live; zur Sicherheit alle 20 s neu laden
  let pending = null;
  const onLive = (msg) => {
    if (!['status', 'alert', 'ack', 'check'].includes(msg.type) || pending) return;
    pending = setTimeout(() => { pending = null; render().catch(() => {}); }, 1500);
  };
  live.listeners.add(onLive);
  state.liveStops.push(() => { live.listeners.delete(onLive); clearInterval(clock); clearInterval(rotateTimer); clearTimeout(pending); });
  autoRefresh(render, 20);
}

// ---------------------------------------------------------------------------
// Sektoren verwalten
// ---------------------------------------------------------------------------

async function viewSites() {
  const manage = can('networks.manage');
  const render = async () => {
    const [sites, status] = await Promise.all([loadSites(true), api('/sites/status')]);
    const byId = Object.fromEntries(status.sites.map((s) => [s.id, s]));
    view().innerHTML = `<div class="page-head"><p class="muted">Sektoren gliedern das Netz in Standorte oder Bereiche (Firma → Gebäude → Etage).
      Netze, Geräte, Dienste und Alarmregeln gehören zu einem Sektor; Rechte können je Sektor vergeben werden und gelten auch für alle Unter-Sektoren.</p>
      ${manage ? `<button type="button" id="site-add">${icon('plus')}Sektor anlegen</button>` : ''}</div>
      <div class="card table-wrap"><table><thead><tr><th>Sektor</th><th>Zustand</th><th>Geräte</th><th>Netze</th><th>Probe</th><th></th></tr></thead>
      <tbody>${siteTree(sites).map(({ site: s, depth }) => {
        const st = byId[s.id] || {};
        return `<tr><td><span class="site-indent" data-depth="${depth}"></span><a href="#/leitstand?site=${s.id}">${esc(s.name)}</a>
            ${s.description ? `<div class="muted small">${esc(s.description)}</div>` : ''}</td>
          <td>${st.state ? `<span class="ls-dot st-${esc(st.state)}"></span>${esc(STATE_LABEL[st.state])}` : '–'}</td>
          <td><a href="#/devices?site=${s.id}">${s.device_count}</a></td><td>${s.network_count}</td>
          <td class="small">${s.probe ? esc(s.probe) : '<span class="muted">Server</span>'}</td>
          <td class="actions">${manage ? `<button type="button" class="ghost sm" data-move="${s.id}" title="Geräte hierher verschieben">${icon('arrows-exchange', 'i-sm')}</button>
            <button type="button" class="ghost sm" data-edit="${s.id}">${icon('edit', 'i-sm')}</button>
            ${s.id === 1 ? '' : `<button type="button" class="ghost sm" data-del="${s.id}">${icon('trash', 'i-sm')}</button>`}` : ''}</td></tr>`;
      }).join('')}</tbody></table></div>`;
    $$('.site-indent').forEach((el) => { el.style.paddingLeft = `${Number(el.dataset.depth) * 18}px`; });
    if (!manage) return;
    $('#site-add').addEventListener('click', () => siteDialog(null));
    $$('[data-edit]').forEach((b) => b.addEventListener('click', () => siteDialog(sites.find((s) => s.id === Number(b.dataset.edit)))));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      const s = sites.find((x) => x.id === Number(b.dataset.del));
      if (!confirm(`Sektor „${s.name}“ löschen? Das geht nur, wenn er leer ist (keine Geräte, Netze und Unter-Sektoren).`)) return;
      attempt(async () => { await api(`/sites/${s.id}`, { method: 'DELETE' }); await render(); }, 'Sektor gelöscht');
    }));
    $$('[data-move]').forEach((b) => b.addEventListener('click', () => moveDialog(sites.find((s) => s.id === Number(b.dataset.move)))));
  };

  function siteDialog(s) {
    const dlg = openModal(s ? 'Sektor bearbeiten' : 'Sektor anlegen', `<form class="form" id="site-form">
      <label>Name<input name="name" required maxlength="80" value="${esc(s ? s.name : '')}" placeholder="z. B. Filiale Nord, Gebäude B, Produktion"></label>
      <label>Beschreibung<input name="description" maxlength="300" value="${esc(s ? s.description : '')}"></label>
      <label>Gehört zu<select name="parent_id">${siteOptions(s ? s.parent_id : null, { all: '– oberste Ebene –' })}</select></label>
      <label>Reihenfolge<input name="position" type="number" value="${s ? s.position : 0}"></label>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    if (s) $$('#site-form select[name="parent_id"] option', dlg).forEach((o) => { if (Number(o.value) === s.id) o.disabled = true; });
    $('#site-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = ev.target.elements;
      const body = { name: f.name.value.trim(), description: f.description.value.trim(), parent_id: f.parent_id.value ? Number(f.parent_id.value) : null, position: Number(f.position.value || 0) };
      attempt(async () => {
        await api(s ? `/sites/${s.id}` : '/sites', { method: s ? 'PATCH' : 'POST', body });
        dlg.close();
        await render();
      }, 'Sektor gespeichert');
    });
  }

  async function moveDialog(target) {
    const devices = (await api('/devices')).filter((d) => d.site_id !== target.id);
    const dlg = openModal(`Geräte nach „${target.name}“ verschieben`, `<form class="form" id="move-form">
      <input type="search" class="select-search" id="move-q" placeholder="Filtern: Name, IP, Sektor …">
      <div class="move-list">${devices.map((d) => `<label class="inline" data-text="${esc(`${deviceLabel(d)} ${d.ip} ${d.site_name || ''}`.toLowerCase())}">
        <input type="checkbox" name="dev" value="${d.id}"> ${esc(deviceLabel(d))} <span class="muted small">${esc(d.ip)} · ${esc(d.site_name || '')}</span></label>`).join('') || '<p class="muted">Keine Geräte in anderen Sektoren.</p>'}</div>
      <p class="hint">Tipp: Neue Geräte landen automatisch im Sektor des Netzes, in dem sie gefunden werden.</p>
      <div class="actions"><button type="submit">${icon('arrows-exchange')}Verschieben</button></div></form>`);
    $('#move-q', dlg).addEventListener('input', (ev) => {
      const q = ev.target.value.trim().toLowerCase();
      $$('.move-list label', dlg).forEach((l) => { l.hidden = q && !l.dataset.text.includes(q); });
    });
    $('#move-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const ids = $$('input[name="dev"]:checked', dlg).map((c) => Number(c.value));
      if (!ids.length) { toast('Keine Geräte gewählt', true); return; }
      attempt(async () => {
        const r = await api(`/sites/${target.id}/devices`, { method: 'POST', body: { device_ids: ids } });
        dlg.close();
        toast(`${r.moved ?? ids.length} Gerät(e) verschoben`);
        await render();
      });
    });
  }

  await render();
}

// ---------------------------------------------------------------------------
// Benutzer, Gruppen, Rollen
// ---------------------------------------------------------------------------

/** Editor für Rollen-Zuweisungen: Liste aus (Rolle, Sektor) */
function assignmentsEditor(roles, list) {
  const row = (a = {}) => `<div class="form-row assign-row">
    <label>Rolle<select data-role>${roles.map((r) => `<option value="${r.id}"${r.id === a.role_id ? ' selected' : ''}>${esc(r.name)}</option>`).join('')}</select></label>
    <label>Gilt für<select data-site>${siteOptions(a.site_id ?? null, { all: 'Alle Sektoren' })}</select></label>
    <button type="button" class="ghost sm" data-remove title="Entfernen">${icon('trash', 'i-sm')}</button></div>`;
  return {
    html: `<fieldset><legend>Rollen</legend><div class="assign-list">${(list || []).map(row).join('')}</div>
      <button type="button" class="ghost sm" data-add-assign>${icon('plus', 'i-sm')}Rolle zuweisen</button>
      <p class="hint">Eine Rolle für einen Sektor gilt auch in allen seinen Unter-Sektoren. Verwaltungsrechte (Benutzer, Zugangsdaten, Sicherung …) wirken nur bei „Alle Sektoren“.</p></fieldset>`,
    bind(root) {
      const listEl = $('.assign-list', root);
      const bindRow = (el) => $('[data-remove]', el).addEventListener('click', () => el.remove());
      $$('.assign-row', listEl).forEach(bindRow);
      $('[data-add-assign]', root).addEventListener('click', () => {
        listEl.insertAdjacentHTML('beforeend', row());
        bindRow(listEl.lastElementChild);
      });
    },
    read(root) {
      return $$('.assign-row', root).map((el) => ({ role_id: Number($('[data-role]', el).value), site_id: $('[data-site]', el).value ? Number($('[data-site]', el).value) : null }));
    },
  };
}

const describeAssignments = (list) => (list || []).map((a) => `<span class="chip">${esc(a.role)}${a.site_id ? ` · ${esc(a.site)}` : ''}</span>`).join('') || '<span class="muted small">keine</span>';

async function viewUsers(_arg, params) {
  await loadSites();
  let tab = (params && params.get('tab')) || 'users';
  const render = async () => {
    const tabs = [['users', 'Benutzer'], ['groups', 'Gruppen'], ['roles', 'Rollen'], ['security', 'Anmeldung & Sicherheit']];
    view().innerHTML = `<div class="card"><div class="tabs">${tabs.map(([k, l]) => `<button type="button" data-tab="${k}" class="${k === tab ? 'active' : ''}">${esc(l)}</button>`).join('')}</div>
      <div id="users-body"><div class="empty">Lade …</div></div></div>`;
    $$('.tabs button').forEach((b) => b.addEventListener('click', () => { tab = b.dataset.tab; render(); }));
    const body = $('#users-body');
    if (tab === 'users') await renderUserList(body);
    else if (tab === 'groups') await renderGroups(body);
    else if (tab === 'roles') await renderRoles(body);
    else await renderSecurity(body);
  };

  async function renderUserList(body) {
    const [users, roles, groups] = await Promise.all([api('/users'), api('/roles'), api('/groups')]);
    const groupName = (id) => (groups.find((g) => g.id === id) || {}).name || '?';
    body.innerHTML = `<div class="page-head"><p class="muted">Rechte kommen über Rollen – direkt oder über Gruppen, für alle Sektoren oder nur für bestimmte.</p>
      <button type="button" id="user-add">${icon('plus')}Benutzer anlegen</button></div>
      <div class="table-wrap"><table><thead><tr><th>Benutzer</th><th>Rollen</th><th>Gruppen</th><th>2FA</th><th>Letzte Anmeldung</th><th></th></tr></thead>
      <tbody>${users.map((u) => `<tr class="${u.disabled ? 'muted-row' : ''}">
        <td><span class="cell-dev">${icon(u.is_admin ? 'shield-lock' : 'user', 'i-sm')}${esc(u.username)}</span>
          ${u.display_name ? `<div class="muted small">${esc(u.display_name)}</div>` : ''}
          ${u.disabled ? '<span class="badge plain">deaktiviert</span>' : ''}${u.auth_source === 'oidc' ? '<span class="badge info">zentral</span>' : ''}</td>
        <td>${describeAssignments(u.assignments)}${u.group_ids.length && u.roles.length ? `<div class="muted small">gesamt: ${esc(u.roles.join(', '))}</div>` : ''}</td>
        <td>${u.group_ids.map((g) => `<span class="chip">${esc(groupName(g))}</span>`).join('') || '<span class="muted small">–</span>'}</td>
        <td>${u.totp_enabled ? `<span class="badge st-up">aktiv</span>${u.id !== state.user.id ? ` <button class="ghost sm" data-totp="${u.id}" data-name="${esc(u.username)}" type="button" title="Zwei-Faktor zurücksetzen (z. B. Handy verloren)">${icon('refresh', 'i-sm')}</button>` : ''}`
          : u.auth_source === 'oidc' ? '<span class="muted small">beim Anmeldedienst</span>' : '<span class="badge warn">aus</span>'}</td>
        <td class="small">${esc(fmtTime(u.last_login))}</td>
        <td class="actions"><button class="ghost sm" data-edit="${u.id}" type="button" title="Bearbeiten">${icon('edit', 'i-sm')}</button>
          ${u.id === state.user.id ? '<span class="muted small">(du)</span>' : `<button class="ghost sm" data-kick="${u.id}" data-name="${esc(u.username)}" type="button" title="Überall abmelden">${icon('logout', 'i-sm')}</button>
          ${u.auth_source === 'local' ? `<button class="ghost sm" data-pw="${u.id}" data-name="${esc(u.username)}" type="button" title="Neues Passwort setzen">${icon('key', 'i-sm')}</button>` : ''}
          <button class="ghost sm" data-del="${u.id}" data-name="${esc(u.username)}" type="button" title="Löschen">${icon('trash', 'i-sm')}</button>`}</td></tr>`).join('')}
      </tbody></table></div>`;
    $('#user-add').addEventListener('click', () => userDialog(null, roles, groups));
    $$('[data-edit]', body).forEach((b) => b.addEventListener('click', () => userDialog(users.find((u) => u.id === Number(b.dataset.edit)), roles, groups)));
    $$('[data-kick]', body).forEach((btn) => btn.addEventListener('click', () => {
      if (!confirm(`„${btn.dataset.name}“ auf allen Geräten abmelden?`)) return;
      attempt(async () => { const r = await api(`/users/${btn.dataset.kick}/sessions`, { method: 'DELETE' }); toast(`${r.ended} Sitzung(en) beendet`); });
    }));
    $$('[data-totp]', body).forEach((btn) => btn.addEventListener('click', () => {
      if (!confirm(`Zwei-Faktor-Anmeldung von „${btn.dataset.name}“ zurücksetzen? Die Anmeldung geht danach nur mit Passwort, bis 2FA neu eingerichtet ist.`)) return;
      attempt(async () => { await api(`/users/${btn.dataset.totp}/totp`, { method: 'DELETE' }); await render(); }, 'Zwei-Faktor-Anmeldung zurückgesetzt');
    }));
    $$('[data-pw]', body).forEach((btn) => btn.addEventListener('click', () => {
      const dlg = openModal(`Neues Passwort für „${btn.dataset.name}“`, `<form class="form" id="pw-reset-form">
          <label>Neues Passwort (mind. 12 Zeichen)<input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
          <label>Wiederholen<input name="repeat" type="password" required minlength="12" autocomplete="new-password"></label>
          <p class="hint">Der Benutzer wird überall abgemeldet und sollte das Passwort danach unter „Mein Konto“ selbst ändern.</p>
          <div class="actions"><button type="submit">${icon('check')}Setzen</button></div></form>`);
      $('#pw-reset-form', dlg).addEventListener('submit', (ev) => {
        ev.preventDefault();
        const e = ev.target.elements;
        if (e.password.value !== e.repeat.value) { toast('Die Passwörter stimmen nicht überein', true); return; }
        attempt(async () => { await api(`/users/${btn.dataset.pw}/password`, { method: 'PUT', body: { password: e.password.value } }); dlg.close(); }, 'Passwort gesetzt');
      });
    }));
    $$('[data-del]', body).forEach((btn) => btn.addEventListener('click', () => {
      if (!confirm(`Benutzer „${btn.dataset.name}“ löschen?`)) return;
      attempt(async () => { await api(`/users/${btn.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Benutzer gelöscht');
    }));
  }

  function userDialog(u, roles, groups) {
    const editor = assignmentsEditor(roles, u ? u.assignments : [{ role_id: (roles.find((r) => r.name === 'Nur lesen') || roles[0] || {}).id, site_id: null }]);
    const dlg = openModal(u ? `Benutzer „${u.username}“` : 'Benutzer anlegen', `<form class="form" id="user-form">
      ${u ? '' : `<div class="form-row"><label>Benutzername<input name="username" required minlength="3" maxlength="64" autocomplete="off"></label>
        <label id="pw-field">Passwort (mind. 12 Zeichen)<input name="password" type="password" required minlength="12" autocomplete="new-password"></label></div>
        <label class="inline"><input type="checkbox" name="sso"> Anmeldung über den zentralen Anmeldedienst (kein eigenes Passwort)</label>`}
      <div class="form-row"><label>Anzeigename<input name="display_name" maxlength="100" value="${esc(u ? u.display_name || '' : '')}"></label>
        <label>E-Mail (für Gruppen-Benachrichtigungen)<input name="email" type="email" maxlength="200" value="${esc(u ? u.email || '' : '')}"></label></div>
      ${editor.html}
      <fieldset><legend>Gruppen</legend><div class="checks">${groups.length ? groups.map((g) => `<label class="inline"><input type="checkbox" name="grp" value="${g.id}"${u && u.group_ids.includes(g.id) ? ' checked' : ''}>${esc(g.name)}</label>`).join('')
        : '<span class="muted">Noch keine Gruppen.</span>'}</div></fieldset>
      ${u && u.id !== state.user.id ? `<label class="inline"><input type="checkbox" name="disabled"${u.disabled ? ' checked' : ''}> Deaktiviert (kann sich nicht anmelden)</label>` : ''}
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    editor.bind(dlg);
    const ssoBox = $('input[name="sso"]', dlg);
    ssoBox?.addEventListener('change', () => {
      $('#pw-field', dlg).hidden = ssoBox.checked;
      dlg.querySelector('input[name="password"]').required = !ssoBox.checked;
    });
    $('#user-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = ev.target.elements;
      const body = {
        display_name: f.display_name.value.trim() || null,
        email: f.email.value.trim() || null,
        assignments: editor.read(dlg),
        group_ids: $$('input[name="grp"]:checked', dlg).map((c) => Number(c.value)),
      };
      if (f.disabled) body.disabled = f.disabled.checked;
      attempt(async () => {
        if (u) await api(`/users/${u.id}`, { method: 'PATCH', body });
        else await api('/users', { method: 'POST', body: { ...body, username: f.username.value.trim(), password: f.sso.checked ? '' : f.password.value, sso: f.sso.checked } });
        dlg.close();
        await render();
      }, 'Benutzer gespeichert');
    });
  }

  async function renderGroups(body) {
    const [groups, users, roles] = await Promise.all([api('/groups'), api('/users'), api('/roles')]);
    const userName = (id) => (users.find((u) => u.id === id) || {}).username || '?';
    body.innerHTML = `<div class="page-head"><p class="muted">Gruppen bündeln Benutzer (z. B. „Team Nord“, „Bereitschaft“). Rollen einer Gruppe gelten für alle Mitglieder;
      Alarmregeln können Gruppen direkt benachrichtigen (App-Push und E-Mail).</p>
      <button type="button" id="group-add">${icon('plus')}Gruppe anlegen</button></div>
      ${groups.length ? `<div class="table-wrap"><table><thead><tr><th>Gruppe</th><th>Mitglieder</th><th>Rollen</th><th>Zentrale Gruppe</th><th></th></tr></thead>
      <tbody>${groups.map((g) => `<tr><td>${esc(g.name)}${g.description ? `<div class="muted small">${esc(g.description)}</div>` : ''}</td>
        <td>${g.member_ids.map((id) => `<span class="chip">${esc(userName(id))}</span>`).join('') || '<span class="muted small">–</span>'}</td>
        <td>${describeAssignments(g.assignments)}</td><td class="small mono">${esc(g.oidc_group || '–')}</td>
        <td class="actions"><button class="ghost sm" data-edit="${g.id}" type="button">${icon('edit', 'i-sm')}</button>
          <button class="ghost sm" data-del="${g.id}" data-name="${esc(g.name)}" type="button">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Gruppen.', 'users')}`;
    const dialog = (g) => {
      const editor = assignmentsEditor(roles, g ? g.assignments : []);
      const dlg = openModal(g ? `Gruppe „${g.name}“` : 'Gruppe anlegen', `<form class="form" id="group-form">
        <label>Name<input name="name" required maxlength="80" value="${esc(g ? g.name : '')}"></label>
        <label>Beschreibung<input name="description" maxlength="300" value="${esc(g ? g.description : '')}"></label>
        <label>Name der Gruppe beim zentralen Anmeldedienst (optional)<input name="oidc_group" maxlength="200" value="${esc(g ? g.oidc_group || '' : '')}" placeholder="z. B. netpulse-technik"></label>
        <fieldset><legend>Mitglieder</legend><div class="checks">${users.map((u) => `<label class="inline"><input type="checkbox" name="mem" value="${u.id}"${g && g.member_ids.includes(u.id) ? ' checked' : ''}>${esc(u.username)}</label>`).join('')}</div></fieldset>
        ${editor.html}
        <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
      editor.bind(dlg);
      $('#group-form', dlg).addEventListener('submit', (ev) => {
        ev.preventDefault();
        const f = ev.target.elements;
        const payload = { name: f.name.value.trim(), description: f.description.value.trim(), oidc_group: f.oidc_group.value.trim() || null,
          member_ids: $$('input[name="mem"]:checked', dlg).map((c) => Number(c.value)), assignments: editor.read(dlg) };
        attempt(async () => {
          await api(g ? `/groups/${g.id}` : '/groups', { method: g ? 'PATCH' : 'POST', body: payload });
          dlg.close();
          await render();
        }, 'Gruppe gespeichert');
      });
    };
    $('#group-add').addEventListener('click', () => dialog(null));
    $$('[data-edit]', body).forEach((b) => b.addEventListener('click', () => dialog(groups.find((g) => g.id === Number(b.dataset.edit)))));
    $$('[data-del]', body).forEach((b) => b.addEventListener('click', () => {
      if (!confirm(`Gruppe „${b.dataset.name}“ löschen? Die Mitglieder verlieren die Rechte dieser Gruppe.`)) return;
      attempt(async () => { await api(`/groups/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Gruppe gelöscht');
    }));
  }

  async function renderRoles(body) {
    const [roles, permissions] = await Promise.all([api('/roles'), api('/permissions')]);
    const label = (p) => (permissions.find((x) => x.name === p) || {}).label || p;
    body.innerHTML = `<div class="page-head"><p class="muted">Eine Rolle ist eine Liste von Rechten. Die eingebauten Rollen decken die üblichen Fälle ab; eigene Rollen lassen sich frei zusammenstellen.</p>
      <button type="button" id="role-add">${icon('plus')}Rolle anlegen</button></div>
      <div class="table-wrap"><table><thead><tr><th>Rolle</th><th>Rechte</th><th>Vergeben</th><th></th></tr></thead>
      <tbody>${roles.map((r) => `<tr><td>${esc(r.name)}${r.builtin ? ' <span class="badge plain">eingebaut</span>' : ''}<div class="muted small">${esc(r.description)}</div></td>
        <td>${r.all_permissions ? '<span class="badge accent">alle Rechte</span>' : r.permissions.map((p) => `<span class="chip" title="${esc(label(p))}">${esc(p)}</span>`).join('')}</td>
        <td>${r.used}</td>
        <td class="actions">${r.all_permissions ? '' : `<button class="ghost sm" data-edit="${r.id}" type="button">${icon('edit', 'i-sm')}</button>`}
          ${r.builtin ? '' : `<button class="ghost sm" data-del="${r.id}" data-name="${esc(r.name)}" type="button">${icon('trash', 'i-sm')}</button>`}</td></tr>`).join('')}</tbody></table></div>`;
    const dialog = (r) => {
      const dlg = openModal(r ? `Rolle „${r.name}“` : 'Rolle anlegen', `<form class="form" id="role-form">
        <label>Name<input name="name" required maxlength="60" value="${esc(r ? r.name : '')}"></label>
        <label>Beschreibung<input name="description" maxlength="300" value="${esc(r ? r.description : '')}"></label>
        <fieldset><legend>Rechte</legend>${permissions.map((p) => `<label class="inline perm-row"><input type="checkbox" name="perm" value="${esc(p.name)}"${r && r.permissions.includes(p.name) ? ' checked' : ''}>
          <span><b>${esc(p.label)}</b><br><span class="muted small">${esc(p.name)} · ${p.per_site ? 'je Sektor vergebbar' : 'nur für alle Sektoren'}</span></span></label>`).join('')}</fieldset>
        <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
      $('#role-form', dlg).addEventListener('submit', (ev) => {
        ev.preventDefault();
        const f = ev.target.elements;
        const payload = { name: f.name.value.trim(), description: f.description.value.trim(), permissions: $$('input[name="perm"]:checked', dlg).map((c) => c.value) };
        attempt(async () => {
          await api(r ? `/roles/${r.id}` : '/roles', { method: r ? 'PATCH' : 'POST', body: payload });
          dlg.close();
          await render();
        }, 'Rolle gespeichert');
      });
    };
    $('#role-add').addEventListener('click', () => dialog(null));
    $$('[data-edit]', body).forEach((b) => b.addEventListener('click', () => dialog(roles.find((r) => r.id === Number(b.dataset.edit)))));
    $$('[data-del]', body).forEach((b) => b.addEventListener('click', () => {
      if (!confirm(`Rolle „${b.dataset.name}“ löschen? Alle Zuweisungen dieser Rolle entfallen.`)) return;
      attempt(async () => { await api(`/roles/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Rolle gelöscht');
    }));
  }

  async function renderSecurity(body) {
    const sec = await api('/settings/security');
    const oidc = await api('/settings/oidc').catch(() => null);
    body.innerHTML = `<div class="grid">
      <section class="card span-1"><header><h2>${icon('shield-lock')}Zwei-Faktor-Pflicht</h2></header>
        <form class="form" id="sec-form">
          <label class="inline"><input type="checkbox" name="require"${sec.require_totp ? ' checked' : ''}${sec.forced_by_env ? ' disabled' : ''}>
            Alle Benutzer müssen 2FA nutzen</label>
          <p class="hint">${sec.forced_by_env ? 'Fest eingeschaltet über <code>REQUIRE_TOTP=true</code>.'
            : 'Wer 2FA noch nicht hat, muss sie nach der nächsten Anmeldung zuerst einrichten und kommt vorher an nichts anderes heran. Gilt nicht für Benutzer der zentralen Anmeldung – dort regelt das der Anmeldedienst.'}
            ${sec.users_without_totp ? `<br>Noch ohne 2FA: <b>${esc(sec.users_without_totp)}</b> Benutzer.` : ''}</p>
        </form></section>
      <section class="card span-2" id="oidc-box">${oidc ? oidcForm(oidc) : `<div class="empty">${icon('lock')}<span>Zentrale Anmeldung ist in dieser Version nicht verfügbar.</span></div>`}</section>
    </div>`;
    $('#sec-form input[name="require"]').addEventListener('change', (ev) => {
      const on = ev.target.checked;
      if (on && !confirm('2FA für alle Benutzer vorschreiben? Benutzer ohne 2FA müssen sie bei der nächsten Aktion zuerst einrichten.')) {
        ev.target.checked = false;
        return;
      }
      attempt(async () => { await api('/settings/security', { method: 'PUT', body: { require_totp: on } }); await render(); },
        on ? '2FA ist jetzt Pflicht' : '2FA-Pflicht aufgehoben').then((ok) => { if (!ok) ev.target.checked = !on; });
    });
    if (oidc) bindOidc();
  }

  function oidcForm(o) {
    return `<header><h2>${icon('users')}Zentrale Anmeldung (SSO)</h2>${o.enabled ? '<span class="badge st-up">aktiv</span>' : '<span class="badge plain">aus</span>'}</header>
      <form class="form" id="oidc-form">
        <p class="muted small">Anmeldung über Microsoft Entra ID, Keycloak, Authentik, Google Workspace o. ä. (OpenID Connect).
          ${o.redirect_uri ? `Beim Anmeldedienst als Rücksprung-Adresse eintragen: <code>${esc(o.redirect_uri)}</code>`
            : '<b>Zuerst <code>PUBLIC_URL</code> (bzw. <code>SITE_ADDRESS</code>) setzen</b> – daraus ergibt sich die Rücksprung-Adresse.'}</p>
        <label class="inline"><input type="checkbox" name="enabled"${o.enabled ? ' checked' : ''}> Zentrale Anmeldung einschalten</label>
        <div class="form-row"><label>Anzeigename auf der Anmeldeseite<input name="label" maxlength="60" value="${esc(o.label || 'Firmenkonto')}"></label>
          <label>Aussteller (Issuer-URL)<input name="issuer" type="url" value="${esc(o.issuer || '')}" placeholder="https://login.microsoftonline.com/…/v2.0"></label></div>
        <div class="form-row"><label>Client-ID<input name="client_id" value="${esc(o.client_id || '')}" autocomplete="off"></label>
          <label>Client-Secret${o.has_secret ? ' (gespeichert – leer lassen zum Behalten)' : ''}<input name="client_secret" type="password" autocomplete="new-password"></label></div>
        <div class="form-row"><label>Gruppen-Claim<input name="groups_claim" value="${esc(o.groups_claim || 'groups')}"></label>
          <label>Neue Benutzer automatisch anlegen<select name="auto_create"><option value="true"${o.auto_create !== false ? ' selected' : ''}>Ja – Rechte kommen über die Gruppen</option>
            <option value="false"${o.auto_create === false ? ' selected' : ''}>Nein – nur vorhandene Benutzer</option></select></label></div>
        <p class="hint">Gruppen werden bei jeder Anmeldung abgeglichen: Hat eine NetPulse-Gruppe unter „Name der Gruppe beim zentralen Anmeldedienst“ den gleichen Namen, wird der Benutzer Mitglied (und sonst entfernt).
          Verschachtelte Claims mit Punkt, z. B. <code>realm_access.roles</code> bei Keycloak. Vorhandene Konten werden nur verknüpft, wenn sie unter Benutzer als „zentral“ angelegt wurden.</p>
        <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`;
  }

  function bindOidc() {
    $('#oidc-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = ev.target.elements;
      const body = { enabled: f.enabled.checked, label: f.label.value.trim(), issuer: f.issuer.value.trim(), client_id: f.client_id.value.trim(),
        groups_claim: f.groups_claim.value.trim() || 'groups', auto_create: f.auto_create.value === 'true' };
      if (f.client_secret.value) body.client_secret = f.client_secret.value;
      attempt(async () => { await api('/settings/oidc', { method: 'PUT', body }); await render(); }, 'Zentrale Anmeldung gespeichert');
    });
  }

  await render();
}

// ---------------------------------------------------------------------------
// API-Schlüssel (Mein Konto)
// ---------------------------------------------------------------------------

async function renderTokens() {
  const box = $('#token-box');
  if (!box) return;
  const tokens = await api('/me/tokens');
  box.innerHTML = `<p class="muted small">Für Skripte (<code>Authorization: Bearer np_…</code>) und Leitstand-Bildschirme („Als Leitstand-Bildschirm anmelden“).
      Ein Schlüssel hat die Rechte deines Kontos; ein Leitstand-Bildschirm kann damit nur ansehen.</p>
    ${tokens.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Angelegt</th><th>Zuletzt benutzt</th><th>Gültig bis</th><th></th></tr></thead>
      <tbody>${tokens.map((t) => `<tr><td>${esc(t.name)}</td><td class="small">${esc(fmtTime(t.created_at))}</td><td class="small">${esc(fmtTime(t.last_used))}</td>
        <td class="small">${t.expires_at ? esc(fmtTime(t.expires_at)) : 'unbegrenzt'}</td>
        <td class="actions"><button type="button" class="ghost sm" data-tok-del="${t.id}">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}</tbody></table></div>` : ''}
    <form class="form-row" id="token-form"><label>Name<input name="name" required maxlength="60" placeholder="z. B. Bildschirm Leitwarte"></label>
      <label>Gültig (Tage, leer = unbegrenzt)<input name="days" type="number" min="1" max="3650"></label>
      <button type="submit">${icon('plus')}Schlüssel anlegen</button></form>`;
  $('#token-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = ev.target.elements;
    attempt(async () => {
      const r = await api('/me/tokens', { method: 'POST', body: { name: f.name.value.trim(), days: f.days.value ? Number(f.days.value) : null } });
      openModal('Neuer API-Schlüssel', `<p>Der Schlüssel wird nur jetzt angezeigt – bitte sicher ablegen:</p>
        <p><code class="token-show">${esc(r.token)}</code></p><p class="hint">Verloren? Einfach löschen und neu anlegen.</p>`);
      await renderTokens();
    });
  });
  $$('[data-tok-del]', box).forEach((b) => b.addEventListener('click', () => {
    if (!confirm('Schlüssel löschen? Skripte und Bildschirme mit diesem Schlüssel verlieren den Zugang.')) return;
    attempt(async () => { await api(`/me/tokens/${b.dataset.tokDel}`, { method: 'DELETE' }); await renderTokens(); }, 'Schlüssel gelöscht');
  }));
}
