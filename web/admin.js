'use strict';
/* Alarme, Ereignisse, Netzwerke, Zugangsdaten, Benachrichtigungen, Benutzer, Audit-Log, Konto */

// ---------------------------------------------------------------------------
// Alarme & Regeln
// ---------------------------------------------------------------------------

const RULE_KINDS = {
  device_down: { label: 'Gerät offline', icon: 'circle-x', unit: null, hint: 'Alarm, wenn ein Gerät länger als die angegebene Zeit nicht erreichbar ist.' },
  new_device: { label: 'Neues Gerät im Netz', icon: 'radar', unit: null, hint: 'Meldet jedes neu entdeckte Gerät – praktisch, um Fremdgeräte zu bemerken.' },
  mac_changed: { label: 'Sicherheitshinweis (MAC/SSH-Schlüssel geändert)', icon: 'shield-lock', unit: null, hint: 'Geänderte MAC-Adressen oder SSH-Host-Schlüssel können auf einen Angriff hindeuten.' },
  disk_usage: { label: 'Speicher fast voll', icon: 'database', unit: '%', hint: 'Höchste Belegung eines Datenträgers (SNMP/SSH nötig).' },
  cpu_usage: { label: 'CPU-Auslastung hoch', icon: 'cpu', unit: '%', hint: 'Durchschnittliche CPU-Last (SNMP/SSH nötig).' },
  mem_usage: { label: 'RAM-Auslastung hoch', icon: 'gauge', unit: '%', hint: 'Belegter Arbeitsspeicher (SNMP/SSH nötig).' },
  temperature: { label: 'Temperatur hoch', icon: 'temperature', unit: '°C', hint: 'Höchste gemeldete Temperatur (SSH/Synology-SNMP).' },
  syslog_match: { label: 'Protokollmeldung (Syslog/Trap)', icon: 'file-text', unit: null, syslog: true, hint: 'Alarm bei neuen Syslog-Meldungen oder SNMP-Traps, die den Suchtext enthalten und mindestens die gewählte Stufe haben (z. B. „Failed password“, „linkDown“). Mehrere Treffer werden je Gerät zusammengefasst.' },
  check_down: { label: 'Dienst ausgefallen', icon: 'world-www', unit: null, check: true, hint: 'Webseite, Port, DNS oder Zertifikat-Check schlägt fehl (unter „Dienste“ angelegt).' },
  job_failed: { label: 'Backup fehlgeschlagen', icon: 'database', unit: null, job: true, hint: 'Ein verbundenes Programm (z. B. Docker Backup Manager) meldet ein fehlgeschlagenes Backup. Optional nur für Container, deren Name den Suchtext enthält.' },
  job_missing: { label: 'Backup überfällig', icon: 'clock', unit: 'Stunden', job: true, hint: 'Ein regelmäßig gesicherter Container hatte seit X Stunden kein erfolgreiches Backup (z. B. 26 bei täglichen Backups). Optional nur für Container, deren Name den Suchtext enthält.' },
  cert_expiry: { label: 'Zertifikat läuft ab', icon: 'shield-lock', unit: 'Tage', check: true, hint: 'Alarm, wenn ein überwachtes Zertifikat in weniger als X Tagen abläuft.' },
};

/** Regel-Arten nach Themen – damit man z. B. die Dienst-Regeln sofort findet */
const RULE_GROUPS = [
  ['Geräte', ['device_down', 'cpu_usage', 'mem_usage', 'disk_usage', 'temperature']],
  ['Dienste (Webseiten, Ports, Zertifikate)', ['check_down', 'cert_expiry']],
  ['Protokolle', ['syslog_match']],
  ['Backups (verbundene Programme)', ['job_failed', 'job_missing']],
  ['Sicherheit & Netz', ['new_device', 'mac_changed']],
];

async function viewAlerts(_arg, params) {
  let tab = params.get('tab') || 'open';
  let site = params.get('site') ? Number(params.get('site')) : null;
  await loadSites();
  const render = async () => {
    const tabs = [['open', 'Aktiv'], ['history', 'Verlauf']];
    if (can('alerts.manage')) tabs.push(['rules', 'Regeln']);
    let body = '';
    if (tab === 'rules') body = await renderRules();
    else {
      const alerts = await api(`/alerts?${tab === 'open' ? 'open=true&' : ''}limit=300${site ? `&site=${site}` : ''}`);
      const sev = (a) => (a.resolved_at ? '<span class="badge sev-resolved">behoben</span>'
        : `<span class="badge ${a.severity === 'critical' ? 'sev-critical' : a.severity === 'info' ? 'info' : 'warn'}">${esc(SEV_LABEL[a.severity] || 'aktiv')}</span>`);
      body = `${sitesCache.list.length > 1 ? `<div class="actions filter-row"><select id="alert-site" aria-label="Sektor">${siteOptions(site, { all: 'Alle Sektoren' })}</select></div>` : ''}
        ${alerts.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Status</th><th>Meldung</th><th>Sektor</th><th>Regel</th><th>Ausgelöst</th><th>${tab === 'open' ? 'Bearbeitung' : 'Behoben'}</th></tr></thead>
        <tbody>${alerts.map((a) => `<tr class="${a.acknowledged_at && !a.resolved_at ? 'acked' : ''}">
          <td>${sev(a)}</td>
          <td>${a.device_id ? `<a href="#/device/${a.device_id}">${esc(a.message)}</a>` : esc(a.message)}
            ${a.ack_comment ? `<div class="muted small">${icon('user-check', 'i-sm')} ${esc(a.ack_comment)}</div>` : ''}</td>
          <td class="small">${esc(a.site_label || '–')}</td>
          <td class="small">${esc(a.rule_name)}</td>
          <td class="small" title="${esc(fmtTime(a.opened_at))}">${esc(fmtAgo(a.opened_at))}</td>
          <td class="small">${a.resolved_at ? esc(fmtTime(a.resolved_at)) : ackCell(a)}</td></tr>`).join('')}</tbody></table></div>`
        : empty(tab === 'open' ? 'Keine aktiven Alarme – alles im grünen Bereich.' : 'Noch keine Alarme ausgelöst.')}`;
    }
    view().innerHTML = `<div class="card">
      <div class="tabs">${tabs.map(([k, l]) => `<button type="button" data-tab="${k}" class="${k === tab ? 'active' : ''}">${esc(l)}</button>`).join('')}</div>
      ${body}</div>`;
    $$('.tabs button').forEach((b) => b.addEventListener('click', () => { tab = b.dataset.tab; render(); }));
    $('#alert-site')?.addEventListener('change', (ev) => { site = ev.target.value ? Number(ev.target.value) : null; render(); });
    bindAck(view(), render);
    if (tab === 'rules') bindRules();
  };

  async function renderRules() {
    const [rules, channels, groups] = await Promise.all([api('/alert-rules'), api('/channels'), api('/groups').catch(() => [])]);
    state.rulesCache = { rules, channels, groups };
    const chName = (id) => (channels.find((c) => c.id === id) || {}).name || '?';
    const groupName = (id) => (groups.find((g) => g.id === id) || {}).name || '?';
    const condition = (r) => {
      const k = RULE_KINDS[r.kind] || {};
      if (r.kind === 'device_down') return `länger als ${r.duration_min} Min.`;
      if (k.unit) return `über ${r.threshold} ${k.unit}${r.duration_min ? ` für ${r.duration_min} Min.` : ''}`;
      return 'sofort';
    };
    return `<div class="page-head"><p class="muted">Regeln bestimmen, wann du benachrichtigt wirst.
      ${channels.length ? '' : ' <b>Lege zuerst unter „Benachrichtigungen“ einen Kanal an.</b>'}</p>
      <button type="button" id="rule-add">${icon('plus')}Regel anlegen</button></div>
      ${rules.length ? `<div class="table-wrap"><table><thead><tr><th>Regel</th><th>Typ</th><th>Gilt für</th><th>Bedingung</th><th>Kanäle</th><th>Aktiv</th><th></th></tr></thead>
      <tbody>${rules.map((r) => `<tr>
        <td>${esc(r.name)}</td>
        <td><span class="cell-dev">${icon((RULE_KINDS[r.kind] || {}).icon || 'bell', 'i-sm')}${esc((RULE_KINDS[r.kind] || {}).label || r.kind)}</span></td>
        <td class="small">${esc(r.device_label || r.check_label || 'Alle')}${r.site_label ? `<div><span class="chip">${icon('building', 'i-sm')}${esc(r.site_label)}</span></div>` : ''}
          ${r.tag ? `<span class="chip">#${esc(r.tag)}</span>` : ''}${r.severity ? `<span class="chip">${esc(SEV_LABEL[r.severity])}</span>` : ''}</td>
        <td class="small">${esc(condition(r))}</td>
        <td class="small">${r.group_ids.length ? r.group_ids.map((g) => `<span class="chip">${icon('users', 'i-sm')}${esc(groupName(g))}</span>`).join('') : ''}
          ${r.escalate_after_min ? `<span class="chip" title="Eskalation">↑ ${esc(r.escalate_after_min)} Min.</span>` : ''}
          ${r.channel_ids.length || r.group_ids.length ? r.channel_ids.map((c) => `<span class="chip">${esc(chName(c))}</span>`).join('') : `<span class="ch-warn" title="Diese Regel meldet nur innerhalb von NetPulse – keine E-Mail, kein Push">${icon('alert-triangle', 'i-sm')} kein Kanal – nur in NetPulse</span>`}</td>
        <td><input type="checkbox" data-toggle="${r.id}"${r.enabled ? ' checked' : ''} aria-label="Aktiv"></td>
        <td class="actions"><button type="button" class="ghost sm" data-edit="${r.id}">${icon('edit', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-del="${r.id}">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Regeln. Tipp: „Gerät offline“ für wichtige Geräte wie Router, NAS und Server.', 'bell')}`;
  }

  function ruleToBody(r) {
    return { name: r.name, kind: r.kind, device_id: r.device_id, threshold: r.threshold, duration_min: r.duration_min,
      channel_ids: r.channel_ids, notify_recovery: r.notify_recovery, enabled: r.enabled, repeat_min: r.repeat_min, check_id: r.check_id,
      pattern: r.pattern, site_id: r.site_id, tag: r.tag, severity: r.severity, group_ids: r.group_ids,
      escalate_after_min: r.escalate_after_min, escalate_channel_ids: r.escalate_channel_ids, escalate_group_ids: r.escalate_group_ids };
  }

  function bindRules() {
    const { rules } = state.rulesCache;
    $('#rule-add').addEventListener('click', () => ruleDialog(null));
    $$('[data-edit]').forEach((b) => b.addEventListener('click', () => ruleDialog(rules.find((r) => r.id === Number(b.dataset.edit)))));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      if (!confirm('Regel löschen?')) return;
      attempt(async () => { await api(`/alert-rules/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Regel gelöscht');
    }));
    $$('[data-toggle]').forEach((c) => c.addEventListener('change', () => {
      const r = rules.find((x) => x.id === Number(c.dataset.toggle));
      attempt(async () => { await api(`/alert-rules/${r.id}`, { method: 'PATCH', body: { ...ruleToBody(r), enabled: c.checked } }); });
    }));
  }

  async function ruleDialog(rule) {
    const { channels, groups } = state.rulesCache;
    const [devices, checkList, tags] = await Promise.all([api('/devices'), api('/checks'), api('/devices/tags').catch(() => [])]);
    const r = { group_ids: [], escalate_channel_ids: [], escalate_group_ids: [], escalate_after_min: 0,
      ...(rule || { kind: 'device_down', duration_min: 5, channel_ids: channels.map((c) => c.id), notify_recovery: true, enabled: true }) };
    const boxes = (name, list, chosen) => list.map((x) => `<label class="inline"><input type="checkbox" name="${name}" value="${x.id}"${chosen.includes(x.id) ? ' checked' : ''}>${esc(x.name)}</label>`).join('');
    const dlg = openModal(rule ? 'Regel bearbeiten' : 'Regel anlegen', `<form class="form" id="rule-form">
      <label>Art der Regel<select name="kind"${rule ? ' disabled' : ''}>${RULE_GROUPS.map(([group, kinds]) => `<optgroup label="${esc(group)}">
        ${kinds.map((k) => `<option value="${k}"${k === r.kind ? ' selected' : ''}>${esc(RULE_KINDS[k].label)}</option>`).join('')}</optgroup>`).join('')}</select></label>
      <p class="hint" id="kind-hint"></p>
      <label>Name<input name="name" value="${esc(r.name || '')}" placeholder="z. B. NAS offline"></label>
      <div id="f-syslog" class="form-row"><label>Suchtext (leer = alle)<input name="pattern" value="${esc(r.pattern || '')}" placeholder="z. B. Failed password"></label>
        <label>Mindestens Stufe<select name="syslog_sev">${SYSLOG_SEV.map((s, i) => `<option value="${i}"${i === (r.threshold ?? 4) ? ' selected' : ''}>${esc(s)}${i ? ' oder schlimmer' : ''}</option>`).join('')}</select></label></div>
      <label id="f-job">Nur Container, deren Name dies enthält (leer = alle)<input name="job_pattern" value="${esc(r.pattern || '')}" placeholder="z. B. nextcloud"></label>
      <div id="f-check" class="form">${checkList.length ? `<label>Dienst<select name="check_id"><option value="">Alle Dienste</option>
        ${checkList.map((c) => `<option value="${c.id}"${c.id === r.check_id ? ' selected' : ''}>${esc(c.name)} – ${esc(c.target)}</option>`).join('')}</select></label>`
        : `<input type="hidden" name="check_id" value=""><div class="notice info">${icon('world-www')}<span>Noch keine Dienste angelegt. Unter
          <a href="#/checks">Dienste</a> z. B. eine Webseite, einen Port oder ein Zertifikat hinzufügen – danach hier auswählen
          (oder die Regel jetzt für „alle Dienste“ speichern).</span></div>`}</div>
      <label id="f-device">Gerät<select name="device_id"><option value="">Alle Geräte</option>
        ${devices.map((d) => `<option value="${d.id}"${d.id === r.device_id ? ' selected' : ''}>${esc(deviceLabel(d))} – ${esc(d.ip)}</option>`).join('')}</select></label>
      <div class="form-row">
        <label id="f-threshold"><span>Schwellwert <span id="unit"></span></span><input name="threshold" type="number" step="any" value="${r.threshold ?? ''}"></label>
        <label id="f-duration">Dauer in Minuten<input name="duration_min" type="number" min="0" max="10080" value="${r.duration_min ?? 0}"></label>
      </div>
      <div class="form-row" id="f-scope">
        <label>Sektor<select name="site_id">${siteOptions(r.site_id ?? null, { all: 'Alle Sektoren' })}</select></label>
        <label>Nur Geräte mit Tag<input name="tag" list="rule-tags" value="${esc(r.tag || '')}" placeholder="z. B. kasse"><datalist id="rule-tags">${tags.map(([t]) => `<option value="${esc(t)}">`).join('')}</datalist></label>
        <label>Schwere<select name="severity"><option value="">automatisch</option>${Object.entries(SEV_LABEL).map(([k, l]) => `<option value="${k}"${r.severity === k ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
      </div>
      <label id="f-repeat">Erinnern, solange der Alarm besteht und nicht bestätigt ist – alle … Minuten (0 = nie)<input name="repeat_min" type="number" min="0" max="10080" value="${r.repeat_min ?? 0}"></label>
      <fieldset><legend>Benachrichtigen über</legend><div class="checks">
        ${channels.length ? channels.map((c) => `<label class="inline"><input type="checkbox" name="ch" value="${c.id}"${r.channel_ids.includes(c.id) ? ' checked' : ''}>${esc(c.name)}</label>`).join('')
          : '<span class="muted">Noch keine Kanäle – unter „Benachrichtigungen“ anlegen.</span>'}</div>
        ${groups.length ? `<div class="muted small">Gruppen (App-Push und E-Mail an die Mitglieder)</div><div class="checks">${boxes('grp', groups, r.group_ids)}</div>` : ''}</fieldset>
      <fieldset id="f-escalate"><legend>Eskalation</legend>
        <label>Wenn nach … Minuten niemand bestätigt hat (0 = keine Eskalation)<input name="escalate_after_min" type="number" min="0" max="10080" value="${r.escalate_after_min || 0}"></label>
        <div class="checks">${boxes('esc_ch', channels, r.escalate_channel_ids)}${boxes('esc_grp', groups, r.escalate_group_ids)}</div>
        <p class="hint">Einmalige Meldung an diese Kanäle und Gruppen, z. B. an die Teamleitung.</p></fieldset>
      <label class="inline" id="f-recovery"><input type="checkbox" name="notify_recovery"${r.notify_recovery ? ' checked' : ''}> Entwarnung senden, wenn behoben</label>
      <label class="inline"><input type="checkbox" name="enabled"${r.enabled ? ' checked' : ''}> Regel aktiv</label>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    const form = $('#rule-form', dlg);
    makeSearchable(form.querySelector('select[name="device_id"]'), 'Gerät suchen: Name oder IP …');
    makeSearchable(form.querySelector('select[name="check_id"]'), 'Dienst suchen …');
    const update = () => {
      const k = form.kind.value;
      const def = RULE_KINDS[k];
      $('#kind-hint', dlg).textContent = def.hint;
      $('#f-threshold', dlg).hidden = !def.unit;
      $('#unit', dlg).textContent = def.unit ? `(${def.unit})` : '';
      $('#f-duration', dlg).hidden = !(k === 'device_down' || k === 'check_down' || (def.unit && k !== 'cert_expiry' && !def.job));
      $('#f-job', dlg).hidden = !def.job;
      $('#f-check', dlg).hidden = !def.check;
      $('#f-syslog', dlg).hidden = !def.syslog;
      $('#f-device', dlg).hidden = !!def.check || !!def.job;
      $('#f-recovery', dlg).hidden = !(k === 'device_down' || k === 'check_down' || def.unit);
      $('#f-repeat', dlg).hidden = !(k === 'device_down' || k === 'check_down' || def.unit);
      $('#f-escalate', dlg).hidden = $('#f-repeat', dlg).hidden;
      $('#f-scope', dlg).hidden = !!def.job;
      if (!rule && def.unit && !form.threshold.value) form.threshold.value = k === 'temperature' ? 70 : k === 'cert_expiry' ? 14 : k === 'job_missing' ? 26 : 90;
    };
    form.kind.addEventListener('change', update);
    update();
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const body = {
        name: form.elements.name.value.trim() || RULE_KINDS[form.kind.value].label,
        kind: form.kind.value,
        device_id: !RULE_KINDS[form.kind.value].check && !RULE_KINDS[form.kind.value].job && form.device_id.value ? Number(form.device_id.value) : null,
        check_id: RULE_KINDS[form.kind.value].check && form.check_id.value ? Number(form.check_id.value) : null,
        threshold: RULE_KINDS[form.kind.value].syslog ? Number(form.syslog_sev.value) : form.threshold.value === '' ? null : Number(form.threshold.value),
        pattern: RULE_KINDS[form.kind.value].syslog ? form.pattern.value.trim() : RULE_KINDS[form.kind.value].job ? form.job_pattern.value.trim() : null,
        duration_min: Number(form.duration_min.value || 0),
        channel_ids: $$('input[name="ch"]:checked', form).map((c) => Number(c.value)),
        notify_recovery: form.notify_recovery.checked,
        enabled: form.enabled.checked,
        repeat_min: Number(form.repeat_min.value || 0),
        site_id: !RULE_KINDS[form.kind.value].job && form.site_id.value ? Number(form.site_id.value) : null,
        tag: !RULE_KINDS[form.kind.value].job ? form.tag.value.trim().toLowerCase() || null : null,
        severity: form.severity.value || null,
        group_ids: $$('input[name="grp"]:checked', form).map((c) => Number(c.value)),
        escalate_after_min: Number(form.escalate_after_min.value || 0),
        escalate_channel_ids: $$('input[name="esc_ch"]:checked', form).map((c) => Number(c.value)),
        escalate_group_ids: $$('input[name="esc_grp"]:checked', form).map((c) => Number(c.value)),
      };
      attempt(async () => {
        if (rule) await api(`/alert-rules/${rule.id}`, { method: 'PATCH', body });
        else await api('/alert-rules', { method: 'POST', body });
        dlg.close();
        await render();
      }, 'Regel gespeichert');
    });
  }

  await render();
  autoRefresh(async () => { if (tab !== 'rules' && !$('#modal').open) await render(); });
}

// ---------------------------------------------------------------------------
// Ereignisse
// ---------------------------------------------------------------------------

async function viewEvents() {
  const render = async () => {
    const events = await api('/events?limit=300');
    view().innerHTML = `<div class="card table-wrap">${events.length ? `<table>
        <thead><tr><th>Zeit</th><th>Art</th><th>Meldung</th></tr></thead>
        <tbody>${events.map((e) => `<tr>
          <td class="small">${esc(fmtTime(e.time))}</td><td>${eventBadge(e.kind)}</td>
          <td>${e.device_id ? `<a href="#/device/${e.device_id}">${esc(e.message)}</a>` : esc(e.message)}</td></tr>`).join('')}</tbody></table>`
      : empty('Noch keine Ereignisse.', 'list-details')}</div>`;
  };
  await render();
  autoRefresh(render);
}

// ---------------------------------------------------------------------------
// Netzwerke
// ---------------------------------------------------------------------------

/** Eigener Such-Zeitplan eines Netzes als Formularfelder (leer = globaler Zeitplan) */
function netScheduleFields(sch) {
  const mode = sch ? sch.mode : '';
  return `<div class="form-row"><label>Such-Zeitplan<select name="sched_mode"><option value=""${!mode ? ' selected' : ''}>wie global eingestellt</option>
      <option value="daily"${mode === 'daily' ? ' selected' : ''}>täglich um …</option><option value="interval"${mode === 'interval' ? ' selected' : ''}>alle … Minuten</option>
      <option value="manual"${mode === 'manual' ? ' selected' : ''}>nur manuell</option></select></label>
    <label data-sched="daily">Uhrzeiten (z. B. 03:00, 13:00)<input name="sched_times" value="${esc(sch && sch.times ? sch.times.join(', ') : '03:00')}"></label>
    <label data-sched="interval">Abstand (Minuten)<input name="sched_interval" type="number" min="5" max="10080" value="${sch ? sch.interval_min || 60 : 60}"></label></div>`;
}

function bindNetSchedule(form) {
  const sync = () => $$('[data-sched]', form).forEach((el) => { el.hidden = el.dataset.sched !== form.sched_mode.value; });
  form.sched_mode.addEventListener('change', sync);
  sync();
}

function readNetSchedule(form) {
  const mode = form.sched_mode.value;
  if (!mode) return null;
  return { mode, interval_min: Number(form.sched_interval.value || 60), on_start: false,
    times: form.sched_times.value.split(/[,;\s]+/).map((t) => t.trim()).filter(Boolean) };
}

async function viewNetworks() {
  await loadSites();
  // Nur Netzliste und Scan-Fortschritt werden laufend aktualisiert – die Formulare bleiben beim Tippen unberührt
  view().innerHTML = `
    <div class="notice">${icon('shield-lock')}<span>Nur eigene oder ausdrücklich freigegebene Netze eintragen – das Scannen fremder
      Netze kann strafbar sein (§§ 202a ff. StGB). Pro Eintrag höchstens /16; kleinere Netze (z. B. /24) sind deutlich schneller.</span></div>
    <div id="scan-area"></div>
    <div class="grid">
      <section class="card span-2"><header><h2>${icon('topology-star-3')}Freigegebene Netze</h2>
        <button type="button" class="ghost sm" id="scan-all">${icon('radar', 'i-sm')}Alle scannen</button></header>
        <div id="net-list"><div class="empty">Lade …</div></div></section>
      <section class="card span-1"><header><h2>${icon('plus')}Netz hinzufügen</h2></header>
        <form class="form" id="net-form">
          <label>Netz (CIDR, IPv4 oder IPv6)<input name="cidr" placeholder="192.168.178.0/24" required></label>
          <label>Name<input name="name" placeholder="Heimnetz" maxlength="100" required></label>
          <label>Sektor<select name="site_id">${siteOptions(1, { perm: 'networks.manage' })}</select></label>
          <div class="form-row"><label>VLAN<input name="vlan_id" type="number" min="1" max="4094"></label>
            <label>Gateway<input name="gateway" placeholder="192.168.178.1"></label></div>
          <button type="submit">${icon('radar')}Hinzufügen &amp; sofort scannen</button>
          <p class="hint">Ein neues Netz wird sofort gescannt – auch wenn gerade ein anderer Scan läuft.</p>
        </form></section>
    </div>
    <div class="grid" id="sched-area"></div>`;

  let networks = [];
  const render = async () => {
    let scan;
    [networks, scan] = await Promise.all([api('/networks'), api('/scan/status')]);
    $('#scan-area').innerHTML = scanBanner(scan);
    $('#net-list').innerHTML = networks.length ? `<div class="table-wrap"><table><thead><tr><th>Netz</th><th>Sektor</th><th>Geräte</th><th>Letzter Scan</th><th></th></tr></thead>
      <tbody>${networks.map((n) => {
        const running = scan.running && scan.network === n.cidr;
        return `<tr><td><div class="mono">${esc(n.cidr)}</div><div class="muted small">${esc(n.name)}${n.vlan_id ? ` · VLAN ${esc(n.vlan_id)}` : ''}${n.gateway ? ` · GW ${esc(n.gateway)}` : ''}</div>
          ${n.description ? `<div class="muted small">${esc(n.description)}</div>` : ''}</td>
        <td class="small">${esc(n.site_name)}${n.probe ? `<div class="muted">über Probe ${esc(n.probe)}</div>` : ''}${n.schedule ? '<div class="muted">eigener Zeitplan</div>' : ''}${n.enabled ? '' : '<div><span class="badge plain">aus</span></div>'}</td>
        <td>${n.device_count}</td>
        <td class="small">${running ? `<span class="badge accent">läuft · ${pct(scan.done, scan.total)} %</span>`
          : n.last_scan_at ? `${esc(fmtAgo(n.last_scan_at))} · ${n.last_scan_found} aktiv · ${n.last_scan_duration_s} s` : '<span class="muted">noch nicht</span>'}</td>
        <td class="actions"><button class="ghost sm" data-scan="${n.id}" type="button" title="Jetzt scannen">${icon('refresh', 'i-sm')}</button>
          <button class="ghost sm" data-net-edit="${n.id}" type="button" title="Bearbeiten">${icon('edit', 'i-sm')}</button>
          <button class="ghost sm" data-del="${n.id}" data-cidr="${esc(n.cidr)}" type="button" title="Entfernen">${icon('trash', 'i-sm')}</button></td></tr>`;
      }).join('')}</tbody></table></div>` : empty('Noch keine Netze – rechts eines hinzufügen.', 'topology-star-3');
    applyWidths(view());
  };

  // Ereignisse einmal binden (Liste per Delegation, da sie neu aufgebaut wird)
  $('#scan-all').addEventListener('click', () => attempt(() => api('/scan', { method: 'POST' }), 'Scan aller Netze gestartet'));
  $('#net-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const form = ev.target;
    const f = new FormData(form);
    attempt(async () => {
      await api('/networks', { method: 'POST', body: { cidr: f.get('cidr'), name: f.get('name'), site_id: Number(f.get('site_id')) || null,
        vlan_id: f.get('vlan_id') ? Number(f.get('vlan_id')) : null, gateway: f.get('gateway').trim() || null } });
      form.reset();
      setTimeout(render, 1500);
    }, 'Netz hinzugefügt – Scan startet');
  });
  $('#net-list').addEventListener('click', (ev) => {
    const scanBtn = ev.target.closest('[data-scan]');
    if (scanBtn) {
      attempt(async () => { await api(`/networks/${scanBtn.dataset.scan}/scan`, { method: 'POST' }); setTimeout(render, 1500); }, 'Scan gestartet');
      return;
    }
    const edit = ev.target.closest('[data-net-edit]');
    if (edit) {
      const n = networks.find((x) => x.id === Number(edit.dataset.netEdit));
      const dlg = openModal(`Netz ${n.cidr}`, `<form class="form" id="net-edit">
        <label>Name<input name="name" required maxlength="100" value="${esc(n.name)}"></label>
        <label>Beschreibung<input name="description" maxlength="300" value="${esc(n.description || '')}"></label>
        <label>Sektor<select name="site_id">${siteOptions(n.site_id, { perm: 'networks.manage' })}</select></label>
        <div class="form-row"><label>VLAN<input name="vlan_id" type="number" min="1" max="4094" value="${n.vlan_id ?? ''}"></label>
          <label>Gateway<input name="gateway" value="${esc(n.gateway || '')}"></label></div>
        ${netScheduleFields(n.schedule)}
        <label class="inline"><input type="checkbox" name="enabled"${n.enabled ? ' checked' : ''}> Netz durchsuchen</label>
        <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
      const form = $('#net-edit', dlg);
      bindNetSchedule(form);
      form.addEventListener('submit', (e2) => {
        e2.preventDefault();
        const e = form.elements;
        const schedule = readNetSchedule(e);
        attempt(async () => {
          await api(`/networks/${n.id}`, { method: 'PATCH', body: { name: e.name.value.trim(), description: e.description.value.trim(), site_id: Number(e.site_id.value),
            vlan_id: e.vlan_id.value ? Number(e.vlan_id.value) : null, gateway: e.gateway.value.trim(), enabled: e.enabled.checked, schedule, schedule_global: !schedule } });
          dlg.close();
          await render();
        }, 'Netz gespeichert');
      });
      return;
    }
    const del = ev.target.closest('[data-del]');
    if (del) {
      if (!confirm(`Netz ${del.dataset.cidr} entfernen? Bereits gefundene Geräte bleiben erhalten.`)) return;
      attempt(async () => { await api(`/networks/${del.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Netz entfernt');
    }
  });
  await render();
  await renderSchedule();
  autoRefresh(render, 5);
}

const SCHEDULE_MODES = {
  daily: 'Täglich zu festen Uhrzeiten',
  interval: 'Regelmäßig im festen Abstand',
  manual: 'Nur manuell („Alle scannen“ bzw. neues Netz)',
};

/** Zeitplan der Geräte-Suche und Takt der Echtzeit-Abfrage */
async function renderSchedule() {
  const [disc, liveCfg] = await Promise.all([api('/settings/discovery'), api('/settings/live')]);
  const sch = disc.schedule;
  const nextLine = (d) => {
    const parts = [];
    parts.push(d.next_run ? `Nächste Suche: <b>${esc(fmtTime(d.next_run))}</b>` : 'Keine automatische Suche geplant');
    parts.push(d.last_run ? `letzte vollständige Suche ${esc(fmtAgo(d.last_run))}` : 'noch keine vollständige Suche');
    return `${parts.join(' · ')} <span class="muted">(Zeitzone ${esc(d.timezone)})</span>`;
  };
  $('#sched-area').innerHTML = `
    <section class="card span-2"><header><h2>${icon('calendar-time')}Zeitplan für die Geräte-Suche</h2></header>
      <form class="form" id="sched-form">
        <label>Automatisch nach neuen Geräten suchen<select name="mode">
          ${Object.entries(SCHEDULE_MODES).map(([k, label]) => `<option value="${k}"${k === sch.mode ? ' selected' : ''}>${esc(label)}</option>`).join('')}</select></label>
        <label data-mode="daily">Uhrzeiten (mehrere mit Komma trennen)<input name="times" value="${esc(sch.times.join(', '))}" placeholder="03:00, 13:30"></label>
        <label data-mode="interval">Abstand in Minuten (5 bis 10080)<input name="interval_min" type="number" min="5" max="10080" value="${sch.interval_min}"></label>
        <label class="inline"><input type="checkbox" name="on_start"${sch.on_start ? ' checked' : ''}> Zusätzlich bei jedem Start des Containers suchen</label>
        <p class="hint" id="sched-next">${nextLine(disc)}</p>
        <p class="hint">Die Suche (Ping-Sweep, Ports, Namen) belastet das Netz kurz. Die Überwachung bekannter Geräte läuft davon unabhängig ständig weiter.
          Ein verpasster Termin (Gerät war aus) wird beim nächsten Start einmal nachgeholt.</p>
        <div class="actions"><button type="submit">${icon('check')}Zeitplan speichern</button></div>
      </form></section>
    <section class="card span-1"><header><h2>${icon('bolt')}Echtzeit-Abfrage</h2></header>
      <form class="form" id="live-form">
        <label class="inline"><input type="checkbox" name="enabled"${liveCfg.enabled ? ' checked' : ''}> Shelly-Geräte live abfragen</label>
        <label>Takt in Sekunden (2 bis 300)<input name="interval_s" type="number" min="2" max="300" value="${liveCfg.interval_s}"></label>
        <p class="hint">Pro Gerät eine kleine Anfrage; die Werte gehen sofort an alle offenen Browser.
          In die Datenbank wird höchstens ein Messwert pro Minute geschrieben.</p>
        <div class="actions"><button type="submit">${icon('check')}Speichern</button></div>
      </form></section>`;
  const form = $('#sched-form');
  const syncMode = () => $$('[data-mode]', form).forEach((el) => { el.hidden = el.dataset.mode !== form.elements.mode.value; });
  form.elements.mode.addEventListener('change', syncMode);
  syncMode();
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = form.elements;
    attempt(async () => {
      const result = await api('/settings/discovery', {
        method: 'PUT',
        body: {
          mode: e.mode.value,
          interval_min: Number(e.interval_min.value) || 60,
          times: e.times.value.split(/[,;\s]+/).filter(Boolean),
          on_start: e.on_start.checked,
        },
      });
      $('#sched-next').innerHTML = nextLine(result);
      e.times.value = result.schedule.times.join(', ');
    }, 'Zeitplan gespeichert');
  });
  const liveForm = $('#live-form');
  liveForm.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = liveForm.elements;
    attempt(() => api('/settings/live', { method: 'PUT', body: { enabled: e.enabled.checked, interval_s: Number(e.interval_s.value) || 5 } }),
      'Echtzeit-Abfrage gespeichert');
  });
}

// ---------------------------------------------------------------------------
// Zugangsdaten
// ---------------------------------------------------------------------------

const CRED_KINDS = {
  snmp_v2c: { label: 'SNMP v2c', icon: 'network', port: 161 },
  snmp_v3: { label: 'SNMP v3 (empfohlen)', icon: 'shield-lock', port: 161 },
  ssh_key: { label: 'SSH mit Schlüssel (empfohlen)', icon: 'key', port: 22 },
  ssh_password: { label: 'SSH mit Passwort', icon: 'lock', port: 22 },
  http: { label: 'HTTP / Web-Anmeldung (z. B. Shelly)', icon: 'bolt', port: 80 },
  unifi: { label: 'UniFi-Controller (API-Schlüssel)', icon: 'access-point', port: '11443 / 443 / 8443' },
  fritzbox: { label: 'AVM FRITZ!Box (TR-064)', icon: 'router', port: 49000 },
  opnsense: { label: 'OPNsense (API-Schlüssel)', icon: 'wall', port: 443 },
  mikrotik: { label: 'MikroTik RouterOS (REST-API)', icon: 'router', port: '443 / 80' },
};
/** Nur fest einem Gerät zugeordnet, nie automatisch ausprobiert */
const DEVICE_ONLY_KINDS = ['unifi', 'fritzbox', 'opnsense', 'mikrotik'];

async function viewCredentials() {
  const render = async () => {
    const creds = await api('/credentials');
    view().innerHTML = `
      <div class="notice info">${icon('shield-lock')}<span>Zugangsdaten werden mit AES-256 verschlüsselt gespeichert und nie wieder angezeigt.
        Verwende auf den Geräten <b>eigene Konten mit reinen Leserechten</b> – NetPulse führt nur lesende Abfragen aus.
        Anleitungen für Router, NAS, Linux und Windows: <code>docs/ABFRAGEN.md</code>.</span></div>
      <div class="card"><header><h2>${icon('key')}Zugangsdaten</h2><button type="button" id="cred-add">${icon('plus')}Hinzufügen</button></header>
      ${creds.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Art</th><th>Benutzer</th><th>Port</th><th>Automatisch</th><th>Geräte</th><th></th></tr></thead>
      <tbody>${creds.map((c) => `<tr><td>${esc(c.name)}</td>
        <td><span class="cell-dev">${icon((CRED_KINDS[c.kind] || {}).icon || 'key', 'i-sm')}${esc((CRED_KINDS[c.kind] || {}).label || c.kind)}</span></td>
        <td>${esc(c.username || '–')}</td><td>${esc(c.port || (CRED_KINDS[c.kind] || {}).port)}</td>
        <td>${c.auto ? '<span class="badge accent">ja</span>' : '<span class="muted">nein</span>'}</td>
        <td>${c.device_count}</td>
        <td class="actions">
          <button type="button" class="ghost sm" data-test="${c.id}" title="An einem Gerät testen">${icon('player-play', 'i-sm')}Testen</button>
          <button type="button" class="ghost sm" data-assign="${c.id}" title="Geräte auswählen, testen und zuordnen">${icon('devices', 'i-sm')}Geräte</button>
          <button type="button" class="ghost sm" data-edit="${c.id}" title="Bearbeiten">${icon('edit', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-del="${c.id}" title="Löschen">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Zugangsdaten. Mit SNMP oder SSH liest NetPulse CPU, RAM, Festplatten, Schnittstellen, Toner und mehr aus.', 'key')}</div>`;
    $('#cred-add').addEventListener('click', () => credDialog(null));
    $$('[data-edit]').forEach((b) => b.addEventListener('click', () => credDialog(creds.find((c) => c.id === Number(b.dataset.edit)))));
    $$('[data-test]').forEach((b) => b.addEventListener('click', () => testDialog(creds.find((c) => c.id === Number(b.dataset.test)))));
    $$('[data-assign]').forEach((b) => b.addEventListener('click', () => assignDialog(creds.find((c) => c.id === Number(b.dataset.assign)))));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      if (!confirm('Zugangsdaten löschen? Zugeordnete Geräte werden dann nicht mehr tief abgefragt.')) return;
      attempt(async () => { await api(`/credentials/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Gelöscht');
    }));
  };

  function credDialog(cred) {
    const editing = !!cred;
    const keep = editing ? 'leer lassen = unverändert' : '';
    const dlg = openModal(editing ? 'Zugangsdaten bearbeiten' : 'Zugangsdaten hinzufügen', `<form class="form" id="cred-form">
      <label>Art<select name="kind"${editing ? ' disabled' : ''}>${Object.entries(CRED_KINDS).map(([k, v]) => `<option value="${k}"${cred && cred.kind === k ? ' selected' : ''}>${esc(v.label)}</option>`).join('')}</select></label>
      <label>Name<input name="name" required maxlength="100" value="${esc(cred ? cred.name : '')}" placeholder="z. B. Heimnetz SNMP"></label>
      <div class="form-row">
        <label data-for="snmp_v3 ssh_key ssh_password http unifi fritzbox opnsense mikrotik"><span id="user-label">Benutzername</span><input name="username" value="${esc(cred ? cred.username || '' : '')}" autocomplete="off"></label>
        <label>Port<input name="port" type="number" min="1" max="65535" value="${esc(cred ? cred.port || '' : '')}" placeholder="Standard"></label>
      </div>
      <label data-for="snmp_v2c">Community<input name="community" type="password" autocomplete="new-password" placeholder="${keep || 'z. B. public'}"></label>
      <div class="form-row" data-for="snmp_v3">
        <label>Authentifizierung<select name="auth_protocol"><option value="sha1">SHA-1</option><option value="sha256" selected>SHA-256</option>
          <option value="sha512">SHA-512</option><option value="md5">MD5 (veraltet)</option><option value="none">keine</option></select></label>
        <label>Auth-Passwort<input name="auth_password" type="password" autocomplete="new-password" placeholder="${keep}"></label>
      </div>
      <div class="form-row" data-for="snmp_v3">
        <label>Verschlüsselung<select name="priv_protocol"><option value="aes128" selected>AES-128</option><option value="aes256">AES-256</option>
          <option value="des">DES (veraltet)</option><option value="none">keine</option></select></label>
        <label>Verschlüsselungs-Passwort<input name="priv_password" type="password" autocomplete="new-password" placeholder="${keep}"></label>
      </div>
      <label data-for="ssh_password http unifi fritzbox opnsense mikrotik"><span id="pw-label">Passwort</span><input name="password" type="password" autocomplete="new-password" placeholder="${keep}"></label>
      <label data-for="ssh_key">Privater Schlüssel (OpenSSH-Format)<textarea name="private_key" class="mono" placeholder="${keep || '-----BEGIN OPENSSH PRIVATE KEY-----'}"></textarea></label>
      <label data-for="ssh_key">Passphrase (optional)<input name="passphrase" type="password" autocomplete="new-password" placeholder="${keep}"></label>
      <label class="inline" data-for="snmp_v2c snmp_v3 ssh_key http"><input type="checkbox" name="auto"${cred && cred.auto ? ' checked' : ''}> Automatisch bei allen passenden Geräten verwenden</label>
      <p class="hint" id="auto-hint"></p>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    const form = $('#cred-form', dlg);
    const update = () => {
      const kind = form.kind.value;
      $$('[data-for]', form).forEach((el) => { el.hidden = !el.dataset.for.split(' ').includes(kind); });
      $('#auto-hint', dlg).textContent = kind === 'snmp_v2c'
        ? 'Hinweis: Bei SNMP v2c wird die Community unverschlüsselt an jedes getestete Gerät gesendet. Für „automatisch“ besser SNMP v3.'
        : kind === 'ssh_password' ? 'SSH-Passwörter werden aus Sicherheitsgründen nie automatisch ausprobiert – bitte Geräte gezielt zuordnen.'
          : kind === 'http' ? 'Gilt für alle erkannten Shelly-Geräte (Benutzer bei Gen2+ immer „admin“). Das Passwort geht nur an Geräte, die sich '
            + 'vorher als Shelly ausgewiesen haben; bei Gen2+ wird es per Digest-Verfahren nie im Klartext übertragen.'
            : kind === 'unifi' ? 'Empfohlen: API-Schlüssel – funktioniert auch mit Zwei-Faktor-Anmeldung. Anlegen in UniFi Network unter '
              + 'Einstellungen → Control Plane → Integrations → „Create API Key“. Benutzername dann leer lassen. Alternativ ein lokales Konto '
              + 'ohne 2FA (Benutzer + Passwort). Port leer = 11443 (UniFi OS Server), 443 und 8443 werden probiert. Wird nur dem Controller zugeordnet.'
              : kind === 'fritzbox' ? 'In der FRITZ!Box: Heimnetz → Netzwerk → Netzwerkeinstellungen → „Zugriff für Anwendungen zulassen“ einschalten. '
                + 'Am besten einen eigenen FRITZ!Box-Benutzer anlegen (System → FRITZ!Box-Benutzer). Liefert alle Geräte mit Namen, LAN/WLAN, '
                + 'WLAN-Signal und Geschwindigkeit. Das Passwort wird per Digest-Verfahren nie im Klartext übertragen. Wird nur der FRITZ!Box zugeordnet.'
                : kind === 'opnsense' ? 'In OPNsense: System → Zugang → Benutzer → neuen Benutzer anlegen, Rechte nur lesend („Diagnostics: ARP Table“, '
                  + '„Reporting: Traffic“, „Services: DHCP … Leases“), dort unter „API-Schlüssel“ einen Schlüssel erzeugen. Schlüssel ins Feld '
                  + '„API-Schlüssel“, Secret ins Feld „API-Secret“. Liefert alle Geräte aller VLANs mit Namen und aktueller Datenrate.'
                  : kind === 'mikrotik' ? 'RouterOS 7: Benutzer mit Gruppe „read“ anlegen und unter IP → Services „www-ssl“ (Port 443) oder „www“ '
                    + '(Port 80, nur im LAN) einschalten. Liefert WLAN-Clients mit Signal und Datenrate, Bridge-Ports, ARP und DHCP-Namen.' : '';
      $('#user-label', dlg).textContent = kind === 'unifi' ? 'Benutzername (nur lokales Konto, sonst leer)' : kind === 'opnsense' ? 'API-Schlüssel' : 'Benutzername';
      $('#pw-label', dlg).textContent = kind === 'unifi' ? 'API-Schlüssel (oder Passwort des lokalen Kontos)' : kind === 'opnsense' ? 'API-Secret' : 'Passwort';
      if (kind === 'http' && !form.elements.username.value) form.elements.username.value = 'admin';
    };
    form.kind.addEventListener('change', update);
    update();
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const kind = form.kind.value;
      const v = (n) => form.elements[n].value.trim();
      const secret = {};
      ['community', 'password', 'private_key', 'passphrase', 'auth_password', 'priv_password'].forEach((n) => { if (form.elements[n].value) secret[n] = form.elements[n].value; });
      if (kind === 'snmp_v3') { secret.auth_protocol = v('auth_protocol'); secret.priv_protocol = v('priv_protocol'); }
      const body = { name: v('name'), kind, username: v('username'), port: v('port') ? Number(v('port')) : null,
        auto: !DEVICE_ONLY_KINDS.includes(kind) && form.auto.checked, secret };
      attempt(async () => {
        if (editing) {
          await api(`/credentials/${cred.id}`, { method: 'PATCH', body });
          dlg.close();
          await render();
        } else {
          const created = await api('/credentials', { method: 'POST', body });
          dlg.close();
          await render();
          assignDialog(created); // direkt Geräte auswählen und testen
        }
      }, 'Zugangsdaten gespeichert');
    });
  }

  /** Passt ein Gerät grundsätzlich zur Zugangsart? (für die Vorauswahl) */
  const suits = (cred, d) => {
    if (cred.kind === 'http') return d.integration === 'shelly';
    if (cred.kind === 'unifi') return (d.open_ports || []).some((p) => [11443, 8443].includes(p));
    if (cred.kind === 'fritzbox') return (d.open_ports || []).includes(49000) || /avm|fritz/i.test(`${d.vendor} ${d.hostname} ${d.model}`);
    if (cred.kind === 'opnsense') return /opnsense/i.test(`${d.os} ${d.hostname} ${d.model}`) || d.device_type === 'firewall';
    if (cred.kind === 'mikrotik') return /mikrotik|routerboard/i.test(`${d.vendor} ${d.model} ${d.os}`) || (d.open_ports || []).includes(8728);
    if (cred.kind.startsWith('ssh')) return (d.open_ports || []).includes(cred.port || 22);
    return d.monitored && d.status === 'up';
  };

  const resultCell = (r) => (r
    ? `<span class="${r.ok ? 'ok' : 'error'} small">${icon(r.ok ? 'circle-check' : 'circle-x', 'i-sm')} ${esc(r.message)}</span>`
    : '');

  async function testDialog(cred) {
    const devices = (await api('/devices')).sort((a, b) => suits(cred, b) - suits(cred, a));
    const dlg = openModal(`Testen: ${cred.name}`, `<div class="form">
      <label>Gerät<select id="t-device">${devices.map((d) => `<option value="${d.id}">${esc(deviceLabel(d))} – ${esc(d.ip)}${suits(cred, d) ? '' : ' (passt vermutlich nicht)'}</option>`).join('')}</select></label>
      <div class="actions"><button type="button" id="t-run">${icon('player-play')}Jetzt testen</button></div>
      <div id="t-result"></div>
      <p class="hint">Der Test ordnet nichts zu. Zum Zuordnen „Geräte“ verwenden.</p></div>`);
    $('#t-run', dlg).addEventListener('click', async () => {
      const box = $('#t-result', dlg);
      box.innerHTML = '<p class="muted">Teste …</p>';
      try {
        const r = await api(`/credentials/${cred.id}/test`, { method: 'POST', body: { device_id: Number($('#t-device', dlg).value) } });
        box.innerHTML = `<div class="notice ${r.ok ? 'info' : ''}">${icon(r.ok ? 'circle-check' : 'alert-triangle')}<span>${esc(r.message)}</span></div>`;
      } catch (e) {
        box.innerHTML = `<div class="notice">${icon('alert-triangle')}<span>${esc(e.message)}</span></div>`;
      }
    });
  }

  async function assignDialog(cred) {
    const [devices, assignedIds, job] = await Promise.all([api('/devices'), api(`/credentials/${cred.id}/devices`), api(`/credentials/${cred.id}/scan`)]);
    const assigned = new Set(assignedIds);
    // Vorauswahl: bereits zugeordnete plus alle passenden Geräte – ein Klick auf „Testen & zuordnen“ genügt
    const selected = new Set([...assignedIds, ...devices.filter((d) => suits(cred, d)).map((d) => d.id)]);
    const results = new Map((job.results || []).map((r) => [r.device_id, r]));
    const filters = { q: '', type: '', onlySuitable: true };
    const types = [...new Set(devices.map((d) => d.device_type))];
    const dlg = openModal(`Geräte zuordnen: ${cred.name}`, `<div class="form">
      <p class="hint">Häkchen setzen und <b>„Testen &amp; zuordnen“</b> – zugeordnet wird nur, wo die Anmeldung klappt. Ergebnis je Gerät erscheint rechts.</p>
      <div class="form-row"><input id="a-q" type="search" placeholder="Filtern: Name, IP, Hersteller …">
        <select id="a-type"><option value="">Alle Typen</option>${types.map((t) => `<option value="${esc(t)}">${esc(typeInfo(t).label)}</option>`).join('')}</select></div>
      <div class="actions"><label class="inline small"><input type="checkbox" id="a-suit" checked> nur passende Geräte zeigen</label>
        <button type="button" class="ghost sm" id="a-all">Alle sichtbaren auswählen</button>
        <button type="button" class="ghost sm" id="a-none">Auswahl leeren</button></div>
      <div class="table-wrap" id="a-list"></div>
      <div id="a-progress"></div>
      <div class="actions"><button type="button" id="a-scan">${icon('player-play')}Testen &amp; zuordnen</button>
        <button type="button" class="ghost" id="a-save">Ohne Test speichern</button><span class="muted small" id="a-count"></span></div></div>`);
    dlg.classList.add('wide');

    const visible = () => devices.filter((d) => {
      if (filters.onlySuitable && !suits(cred, d) && !assigned.has(d.id)) return false;
      if (filters.type && d.device_type !== filters.type) return false;
      const hay = `${deviceLabel(d)} ${d.ip} ${d.vendor || ''} ${d.hostname || ''}`.toLowerCase();
      return !filters.q || hay.includes(filters.q);
    });
    const draw = () => {
      const list = visible();
      $('#a-list', dlg).innerHTML = list.length ? `<table><tbody>${list.map((d) => `<tr>
        <td><input type="checkbox" data-id="${d.id}"${selected.has(d.id) ? ' checked' : ''} aria-label="auswählen"></td>
        <td><div class="cell-dev">${devIcon(d, 'sm')}<span class="ellipsis">${esc(deviceLabel(d))}</span>${assigned.has(d.id) ? ' <span class="badge accent">zugeordnet</span>' : ''}</div></td>
        <td class="mono small">${esc(d.ip)}</td><td>${resultCell(results.get(d.id))}</td></tr>`).join('')}</tbody></table>`
        : empty('Keine Geräte – Filter anpassen oder „nur passende“ abschalten.', 'devices');
      $$('#a-list input[data-id]', dlg).forEach((c) => c.addEventListener('change', () => {
        if (c.checked) selected.add(Number(c.dataset.id)); else selected.delete(Number(c.dataset.id));
        $('#a-count', dlg).textContent = `${selected.size} ausgewählt`;
      }));
      $('#a-count', dlg).textContent = `${selected.size} ausgewählt`;
    };
    const progress = (j) => {
      $('#a-progress', dlg).innerHTML = j.total ? `<p class="small">${j.running ? 'Teste' : 'Fertig:'} ${j.done} von ${j.total} Geräten ·
        <b class="ok">${j.found} erfolgreich</b>${j.done - j.found ? ` · ${j.done - j.found} ohne Erfolg` : ''}</p>
        <div class="progress"><span data-w="${pct(j.done, j.total)}"></span></div>` : '';
      applyWidths($('#a-progress', dlg));
    };
    progress(job);

    $('#a-q', dlg).addEventListener('input', (ev) => { filters.q = ev.target.value.trim().toLowerCase(); draw(); });
    $('#a-type', dlg).addEventListener('change', (ev) => { filters.type = ev.target.value; draw(); });
    $('#a-suit', dlg).addEventListener('change', (ev) => { filters.onlySuitable = ev.target.checked; draw(); });
    $('#a-all', dlg).addEventListener('click', () => { visible().forEach((d) => selected.add(d.id)); draw(); });
    $('#a-none', dlg).addEventListener('click', () => { selected.clear(); draw(); });
    $('#a-save', dlg).addEventListener('click', () => attempt(async () => {
      await api(`/credentials/${cred.id}/devices`, { method: 'PUT', body: { device_ids: [...selected] } });
      dlg.close();
      await render();
    }, 'Zuordnung gespeichert'));
    $('#a-scan', dlg).addEventListener('click', async () => {
      if (!selected.size) { toast('Bitte mindestens ein Gerät auswählen', true); return; }
      $('#a-scan', dlg).disabled = true;
      try {
        let j = await api(`/credentials/${cred.id}/scan`, { method: 'POST', body: { device_ids: [...selected] } });
        results.clear();
        while (j.running && dlg.open) {
          progress(j);
          await new Promise((r) => setTimeout(r, 1000));
          j = await api(`/credentials/${cred.id}/scan`);
          j.results.forEach((r) => { results.set(r.device_id, r); if (r.ok) assigned.add(r.device_id); });
          draw();
        }
        progress(j);
        toast(`Suchlauf fertig: ${j.found} von ${j.total} Geräten zugeordnet`);
        render();
      } catch (e) {
        toast(e.message, true);
      } finally {
        $('#a-scan', dlg).disabled = false;
      }
    });
    draw();
  }

  await render();
}

// ---------------------------------------------------------------------------
// Benachrichtigungskanäle
// ---------------------------------------------------------------------------

const CHANNEL_KINDS = {
  app: { label: 'NetPulse-App (Push aufs Handy)', icon: 'device-mobile', fields: [],
    hint: 'Sendet an alle Geräte, auf denen unter „Mein Konto“ Push aktiviert wurde. Voraussetzung: NetPulse ist per HTTPS mit gültigem '
      + 'Zertifikat erreichbar (z. B. über den eigenen Reverse-Proxy) und auf dem Handy als App installiert (iPhone: Teilen → „Zum Home-Bildschirm“).' },
  ntfy: { label: 'ntfy (Push aufs Handy)', icon: 'device-mobile', fields: [['server', 'Server', 'https://ntfy.sh'], ['topic', 'Thema (Topic)', 'z. B. netpulse-a8f3k2'], ['token', 'Zugriffstoken (optional)', '', 'password']],
    hint: 'App „ntfy“ installieren, dasselbe Thema abonnieren – fertig. Tipp: ein langes, zufälliges Thema wählen oder einen eigenen ntfy-Server nutzen.' },
  email: { label: 'E-Mail', icon: 'send', fields: [['to', 'Empfänger (mehrere mit Komma)', 'du@example.de'],
    ['subject', 'Betreff-Vorlage', '[NetPulse] {{schwere}}: {{titel}}'],
    ['template', 'Text-Vorlage', '{{meldung}}\n\nGerät: {{geraet}} {{ip}}\nRegel: {{regel}}\nWert: {{wert}}\nZeit: {{zeit}}', 'textarea'],
    ['-own', 'Eigener Server nur für diesen Kanal (sonst der zentrale E-Mail-Server)'],
    ['host', 'SMTP-Server', 'leer = zentraler Server'], ['port', 'Port', '587'], ['security', 'Verschlüsselung', '', 'select:starttls=STARTTLS (587),tls=TLS (465),none=keine (nur intern)'],
    ['username', 'Benutzername', ''], ['password', 'Passwort', '', 'password'], ['from', 'Absender', 'netpulse@example.de']],
    hint: 'Platzhalter: {{titel}} {{meldung}} {{schwere}} {{geraet}} {{ip}} {{regel}} {{wert}} {{zeit}} {{link}}. Zeilen ohne Wert (z. B. „Wert:“) werden weggelassen. '
      + 'Die Mail kommt als übersichtliche HTML-Nachricht mit Textfassung.' },
  telegram: { label: 'Telegram', icon: 'send', fields: [['bot_token', 'Bot-Token', '123456:ABC…', 'password'], ['chat_id', 'Chat-ID', '123456789']],
    hint: 'Bot über @BotFather anlegen, dem Bot schreiben und die Chat-ID z. B. über @userinfobot ermitteln.' },
  gotify: { label: 'Gotify', icon: 'bell', fields: [['url', 'Server-URL', 'https://gotify.example.de'], ['token', 'App-Token', '', 'password']] },
  discord: { label: 'Discord', icon: 'send', fields: [['webhook_url', 'Webhook-URL', 'https://discord.com/api/webhooks/…', 'password']] },
  teams: { label: 'Microsoft Teams', icon: 'users', fields: [['webhook_url', 'Workflow-Webhook-URL', 'https://…', 'password']],
    hint: 'In Teams: Kanal → Workflows → „Beim Empfang einer Webhookanforderung in einem Kanal posten“ und die URL hier einfügen.' },
  webhook: { label: 'Webhook (eigene Systeme)', icon: 'plug-connected', fields: [['url', 'URL', 'https://…', 'password'], ['secret', 'Geheimnis (Header X-NetPulse-Secret)', '', 'password']] },
};

/** Für alle Kanäle: Sammeln und Ruhezeiten */
const DELIVERY_FIELDS = [
  ['-delivery', 'Zustellung'],
  ['digest_min', 'Sammeln: Meldungen so viele Minuten bündeln (0 = sofort)', '0', 'number'],
  ['quiet_from', 'Ruhezeit von', '22:00', 'time'],
  ['quiet_to', 'Ruhezeit bis', '07:00', 'time'],
  ['quiet_critical', 'Kritische Alarme (z. B. Gerät offline) trotz Ruhezeit sofort senden', true, 'checkbox'],
];

async function renderSmtp() {
  const box = $('#smtp-box');
  const { config: c, configured } = await api('/settings/smtp');
  box.innerHTML = `<form class="form" id="smtp-form">
      <div class="form-row"><label>SMTP-Server<input name="host" value="${esc(c.host || '')}" placeholder="smtp.example.de"></label>
        <label>Port<input name="port" type="number" min="1" max="65535" value="${esc(c.port || '')}" placeholder="587"></label></div>
      <div class="form-row"><label>Verschlüsselung<select name="security">
          ${[['starttls', 'STARTTLS (Port 587)'], ['tls', 'TLS (Port 465)'], ['none', 'keine (nur im eigenen Netz)']].map(([v, l]) => `<option value="${v}"${(c.security || 'starttls') === v ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
        <label>Benutzername<input name="username" value="${esc(c.username || '')}" autocomplete="off"></label></div>
      <div class="form-row"><label>Passwort<input name="password" type="password" autocomplete="new-password" placeholder="${c.password ? 'gespeichert – leer lassen = unverändert' : ''}"></label>
        <label>Absender-Adresse<input name="from" value="${esc(c.from || '')}" placeholder="netpulse@example.de"></label></div>
      <label>Absender-Name<input name="from_name" value="${esc(c.from_name || '')}" placeholder="NetPulse"></label>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button>
        <input name="test_to" type="email" placeholder="Test an: du@example.de" aria-label="Test-Empfänger">
        <button type="button" class="ghost" id="smtp-test">${icon('send')}Test senden</button></div>
      <p class="hint">${configured ? 'Gilt für alle E-Mail-Kanäle ohne eigenen Server.' : 'Noch kein Server eingetragen – E-Mail-Kanäle können erst danach senden.'}
        Tipp: Bei Gmail/Outlook ein App-Passwort verwenden.</p></form>`;
  const form = $('#smtp-form');
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = form.elements;
    const body = { host: e.host.value.trim(), port: e.port.value ? Number(e.port.value) : null, security: e.security.value,
      username: e.username.value.trim(), from: e.from.value.trim(), from_name: e.from_name.value.trim() };
    if (e.password.value) body.password = e.password.value;
    attempt(async () => { await api('/settings/smtp', { method: 'PUT', body }); await renderSmtp(); }, 'E-Mail-Server gespeichert');
  });
  $('#smtp-test').addEventListener('click', (ev) => {
    const to = form.elements.test_to.value.trim();
    if (!to) { toast('Bitte eine Empfängeradresse für den Test eingeben', true); return; }
    ev.currentTarget.disabled = true;
    attempt(() => api('/settings/smtp/test', { method: 'POST', body: { to } }), `Test-Mail an ${to} gesendet`)
      .finally(() => { $('#smtp-test').disabled = false; });
  });
}

/** Zustellstatus eines Kanals: letzter Erfolg/Fehler, Nutzung durch Regeln, Push-Geräte */
function channelStatus(c) {
  const parts = [];
  if (c.last_error) parts.push(`<div class="ch-error">${icon('alert-triangle', 'i-sm')} ${esc(c.last_error)}<div class="muted">${esc(fmtAgo(c.last_attempt_at))}</div></div>`);
  else if (c.last_ok_at) parts.push(`<span class="badge st-up">zugestellt</span> <span class="muted">${esc(fmtAgo(c.last_ok_at))}</span>`);
  else parts.push('<span class="muted">noch nichts gesendet</span>');
  if (!c.rules) parts.push(`<div class="ch-warn">${icon('info-circle', 'i-sm')} von keiner Alarmregel verwendet – unter <a href="#/alerts?tab=rules">Regeln</a> auswählen</div>`);
  if (c.push_devices === 0) parts.push(`<div class="ch-warn">${icon('info-circle', 'i-sm')} auf keinem Gerät ist Push aktiviert – in der App unter „Mein Konto“ einschalten</div>`);
  else if (c.push_devices != null) parts.push(`<div class="muted">${esc(c.push_devices)} ${c.push_devices === 1 ? 'Gerät' : 'Geräte'} mit Push</div>`);
  return parts.join('');
}

async function viewChannels() {
  const render = async () => {
    const channels = await api('/channels');
    view().innerHTML = `
      <div class="card"><header><h2>${icon('send')}E-Mail-Server</h2></header><div id="smtp-box"><div class="empty">Lade …</div></div></div>
      <div class="card"><header><h2>${icon('send')}Benachrichtigungskanäle</h2><button type="button" id="ch-add">${icon('plus')}Kanal hinzufügen</button></header>
      ${channels.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Art</th><th>Aktiv</th><th>Zustellung</th><th></th></tr></thead>
      <tbody>${channels.map((c) => `<tr><td>${esc(c.name)}</td>
        <td><span class="cell-dev">${icon((CHANNEL_KINDS[c.kind] || {}).icon || 'send', 'i-sm')}${esc((CHANNEL_KINDS[c.kind] || {}).label || c.kind)}</span></td>
        <td>${c.enabled ? '<span class="badge st-up">aktiv</span>' : '<span class="badge plain">aus</span>'}</td>
        <td class="small">${channelStatus(c)}</td>
        <td class="actions"><button type="button" class="ghost sm" data-test="${c.id}">${icon('player-play', 'i-sm')}Test</button>
          <button type="button" class="ghost sm" data-edit="${c.id}">${icon('edit', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-del="${c.id}">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Kanäle. Am einfachsten: ntfy (kostenlose Push-App) oder E-Mail.', 'send')}</div>
      <p class="muted small">Wann benachrichtigt wird, legst du unter <a href="#/alerts?tab=rules">Alarme → Regeln</a> fest.</p>`;
    renderSmtp();
    $('#ch-add').addEventListener('click', () => channelDialog(null));
    $$('[data-edit]').forEach((b) => b.addEventListener('click', () => channelDialog(channels.find((c) => c.id === Number(b.dataset.edit)))));
    $$('[data-test]').forEach((b) => b.addEventListener('click', () => {
      b.disabled = true;
      attempt(async () => {
        const r = await api(`/channels/${b.dataset.test}/test`, { method: 'POST' });
        toast(r.sent != null ? `Testnachricht an ${r.sent} ${r.sent === 1 ? 'Gerät' : 'Geräte'} gesendet${r.failed ? ` – ${r.failed} fehlgeschlagen: ${r.errors.join('; ')}` : ''}` : 'Testnachricht gesendet', !!r.failed);
      }).finally(async () => { b.disabled = false; await render(); });
    }));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      if (!confirm('Kanal löschen?')) return;
      attempt(async () => { await api(`/channels/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Kanal gelöscht');
    }));
  };

  function channelDialog(channel) {
    const editing = !!channel;
    const fieldsHtml = (kind, config = {}) => {
      const def = CHANNEL_KINDS[kind];
      return [...def.fields, ...DELIVERY_FIELDS].map(([key, label, placeholder, type]) => {
        if (key.startsWith('-')) return `<h3 class="sub">${esc(label)}</h3>`;
        const value = config[key] ?? (key === 'server' && !editing ? 'https://ntfy.sh' : '');
        if (type === 'textarea') {
          return `<label>${esc(label)}<textarea name="cfg_${key}" rows="6" class="mono" placeholder="${esc(placeholder)}">${esc(value)}</textarea></label>`;
        }
        if (type === 'checkbox') {
          return `<label class="inline"><input type="checkbox" name="cfg_${key}"${(config[key] ?? placeholder) ? ' checked' : ''}> ${esc(label)}</label>`;
        }
        if (type === 'number' || type === 'time') {
          return `<label>${esc(label)}<input name="cfg_${key}" type="${type}" ${type === 'number' ? 'min="0" max="1440"' : ''} value="${esc(value)}" placeholder="${esc(placeholder)}"></label>`;
        }
        if (type && type.startsWith('select:')) {
          const opts = type.slice(7).split(',').map((o) => o.split('='));
          return `<label>${esc(label)}<select name="cfg_${key}">${opts.map(([v, l]) => `<option value="${v}"${value === v ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select></label>`;
        }
        return `<label>${esc(label)}<input name="cfg_${key}" type="${type === 'password' ? 'password' : 'text'}" autocomplete="off" value="${esc(value)}" placeholder="${esc(placeholder)}"></label>`;
      }).join('') + (def.hint ? `<p class="hint">${esc(def.hint)}</p>` : '');
    };
    const dlg = openModal(editing ? 'Kanal bearbeiten' : 'Kanal hinzufügen', `<form class="form" id="ch-form">
      <label>Art<select name="kind"${editing ? ' disabled' : ''}>${Object.entries(CHANNEL_KINDS).map(([k, v]) => `<option value="${k}"${channel && channel.kind === k ? ' selected' : ''}>${esc(v.label)}</option>`).join('')}</select></label>
      <label>Name<input name="name" required value="${esc(channel ? channel.name : '')}" placeholder="z. B. Handy"></label>
      <div class="form" id="ch-fields"></div>
      <div id="ch-preview"></div>
      <label class="inline"><input type="checkbox" name="enabled"${!channel || channel.enabled ? ' checked' : ''}> Aktiv</label>
      <div class="actions"><button type="button" class="ghost" id="ch-preview-btn">${icon('search')}Vorschau</button>
        <button type="submit">${icon('check')}Speichern</button></div></form>`);
    dlg.classList.add('wide');
    const form = $('#ch-form', dlg);
    const update = () => {
      $('#ch-fields', dlg).innerHTML = fieldsHtml(form.kind.value, channel ? channel.config : {});
      $('#ch-preview', dlg).innerHTML = '';
      $('#ch-preview-btn', dlg).hidden = form.kind.value !== 'email';
    };
    $('#ch-preview-btn', dlg).addEventListener('click', () => {
      const sample = { titel: 'Offline: NAS (192.168.178.10)', meldung: 'NAS (192.168.178.10) ist seit 5 Min. nicht erreichbar', schwere: 'Kritisch',
        geraet: 'NAS', ip: '(192.168.178.10)', regel: 'Server offline', wert: 'seit 5 Min. offline', zeit: new Date().toLocaleString('de-DE').slice(0, -3), link: location.origin + '/#/device/1' };
      const fill = (t) => t.replace(/\{\{(\w+)\}\}/g, (_, k) => sample[k] ?? '').split('\n')
        .filter((l) => !(/^[^:]{1,29}:$/.test(l.trim()))).join('\n').trim();
      const subject = fill(form.elements.cfg_subject.value || form.elements.cfg_subject.placeholder);
      const body = fill(form.elements.cfg_template.value || form.elements.cfg_template.placeholder);
      $('#ch-preview', dlg).innerHTML = `<div class="mail-preview"><div class="mail-bar"></div><div class="muted small">Betreff</div><strong>${esc(subject)}</strong>
        <pre>${esc(body)}</pre></div>`;
    });
    form.kind.addEventListener('change', update);
    update();
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const config = {};
      $$('[name^="cfg_"]', form).forEach((el) => {
        const key = el.name.slice(4);
        if (el.type === 'checkbox') config[key] = el.checked;
        else if (key === 'port' || el.type === 'number') config[key] = el.value ? Number(el.value) : null;
        else config[key] = el.tagName === 'TEXTAREA' ? el.value.replace(/\r/g, '') : el.value.trim();
      });
      const body = { name: form.elements.name.value.trim(), kind: form.kind.value, enabled: form.enabled.checked, config };
      attempt(async () => {
        if (editing) await api(`/channels/${channel.id}`, { method: 'PATCH', body });
        else await api('/channels', { method: 'POST', body });
        dlg.close();
        await render();
      }, 'Kanal gespeichert – jetzt mit „Test“ prüfen');
    });
  }

  await render();
}

// ---------------------------------------------------------------------------
// Benutzer, Audit-Log, Konto
// ---------------------------------------------------------------------------

const AUDIT_LABEL = {
  login: 'Anmeldung', login_failed: 'Fehlgeschlagene Anmeldung', password_change: 'Passwort geändert',
  device_update: 'Gerät geändert', device_delete: 'Gerät gelöscht', device_credentials: 'Zugangsdaten zugeordnet',
  ssh_key_reset: 'SSH-Schlüssel zurückgesetzt', network_add: 'Netz hinzugefügt', network_delete: 'Netz entfernt',
  scan_trigger: 'Scan gestartet', user_add: 'Benutzer angelegt', user_delete: 'Benutzer gelöscht',
  credential_add: 'Zugangsdaten angelegt', credential_update: 'Zugangsdaten geändert', credential_delete: 'Zugangsdaten gelöscht',
  channel_add: 'Kanal angelegt', channel_update: 'Kanal geändert', channel_delete: 'Kanal gelöscht',
  discovery_schedule: 'Such-Zeitplan geändert', live_settings: 'Echtzeit-Abfrage geändert',
  smtp_update: 'E-Mail-Server geändert', session_end: 'Sitzung beendet', session_end_others: 'Andere Sitzungen beendet', sessions_revoked: 'Benutzer überall abgemeldet', login_blocked: 'Anmeldung gesperrt', status_page: 'Statusseite geändert', maintenance_add: 'Wartung angelegt', maintenance_update: 'Wartung geändert', maintenance_delete: 'Wartung gelöscht', check_add: 'Dienst angelegt', check_update: 'Dienst geändert', check_delete: 'Dienst gelöscht', totp_enabled: '2FA eingeschaltet', totp_disabled: '2FA ausgeschaltet', totp_reset: '2FA zurückgesetzt', push_subscribe: 'Push-Gerät angemeldet',
  rule_add: 'Regel angelegt', rule_update: 'Regel geändert', rule_delete: 'Regel gelöscht',
  user_update: 'Benutzer geändert', role_add: 'Rolle angelegt', role_update: 'Rolle geändert', role_delete: 'Rolle gelöscht',
  group_add: 'Gruppe angelegt', group_update: 'Gruppe geändert', group_delete: 'Gruppe gelöscht', token_add: 'API-Schlüssel angelegt',
  token_delete: 'API-Schlüssel gelöscht', kiosk_login: 'Leitstand-Bildschirm angemeldet', site_add: 'Sektor angelegt', site_update: 'Sektor geändert',
  site_delete: 'Sektor gelöscht', devices_move: 'Geräte verschoben', alert_ack: 'Alarm bestätigt', alert_unack: 'Bestätigung zurückgenommen',
  network_update: 'Netz geändert', reauth: 'Erneut bestätigt', vault_rotate: 'Tresor-Schlüssel getauscht', probe_add: 'Probe angelegt',
  probe_delete: 'Probe gelöscht', oidc_settings: 'Zentrale Anmeldung geändert', login_oidc: 'Anmeldung (zentral)',
};

async function viewAudit(_arg, params) {
  await loadSites();
  const p = params || new URLSearchParams();
  const q = new URLSearchParams({ limit: '500' });
  ['user', 'action', 'q', 'site'].forEach((k) => { if (p.get(k)) q.set(k, p.get(k)); });
  const entries = await api(`/audit?${q}`);
  view().innerHTML = `<form class="card form-row audit-filter" id="audit-filter">
      <label>Benutzer<input name="user" value="${esc(p.get('user') || '')}"></label>
      <label>Aktion beginnt mit<input name="action" value="${esc(p.get('action') || '')}" placeholder="z. B. login, device_"></label>
      <label>Suchtext<input name="q" value="${esc(p.get('q') || '')}"></label>
      <label>Sektor<select name="site">${siteOptions(p.get('site') ? Number(p.get('site')) : null, { all: 'Alle' })}</select></label>
      <button type="submit">${icon('filter')}Filtern</button></form>
    <div class="card table-wrap"><table>
      <thead><tr><th>Zeit</th><th>Benutzer</th><th>Aktion</th><th>Details</th></tr></thead>
      <tbody>${entries.map((e) => `<tr><td class="small">${esc(fmtTime(e.time))}</td><td>${esc(e.username || '–')}</td>
        <td>${e.action === 'login_failed' ? `<span class="badge warn">${esc(AUDIT_LABEL[e.action])}</span>` : esc(AUDIT_LABEL[e.action] || e.action)}</td>
        <td class="mono small">${Object.keys(e.detail || {}).length ? esc(JSON.stringify(e.detail)) : ''}</td></tr>`).join('')
        || `<tr><td colspan="4">${empty('Keine Einträge.')}</td></tr>`}</tbody></table></div>`;
  $('#audit-filter').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const next = new URLSearchParams();
    for (const [k, v] of f.entries()) if (String(v).trim()) next.set(k, String(v).trim());
    location.hash = `#/audit${next.toString() ? `?${next}` : ''}`;
  });
}

// ---------------------------------------------------------------------------
// System-Log
// ---------------------------------------------------------------------------

const LOG_LEVELS = { debug: 'Alles (inkl. Details)', info: 'Info und wichtiger', warn: 'Warnungen und Fehler', error: 'Nur Fehler' };

async function viewLogs() {
  const filters = { level: 'info', q: '' };
  let lines = [];
  view().innerHTML = `
    <div class="page-head"><div class="actions">
        <select id="log-level" aria-label="Stufe">${Object.entries(LOG_LEVELS).map(([k, l]) => `<option value="${k}"${k === filters.level ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>
        <input id="log-q" type="search" placeholder="Suchen: IP, Gerätename, „Shelly“ …" aria-label="Suchen">
        <label class="inline"><input type="checkbox" id="log-auto" checked> live</label></div>
      <div class="actions"><span class="muted small" id="log-count"></span>
        <button type="button" class="ghost" id="log-save">${icon('cloud-download')}Als Datei speichern</button></div></div>
    <div class="notice info">${icon('file-text')}<span>Die letzten 5.000 Meldungen seit dem Start des Containers (nur im Speicher).
      Tipp: Für ein einzelnes Gerät zeigt der Tab „Diagnose“ auf der Geräteseite jeden Abfrageschritt.</span></div>
    <div class="card" id="sys-card"><header><h2>${icon('gauge')}Systemzustand von NetPulse</h2><span class="muted small" id="sys-note"></span></header>
      <div id="sys-body"><div class="empty">Lade …</div></div></div>
    <div class="card"><div class="log" id="log-body"><div class="empty">Lade …</div></div></div>`;

  const shortTarget = (t) => t.replace(/^netpulse::/, '');
  const renderSystem = async () => {
    const s = await api('/system');
    const p = s.process;
    const tasks = [...s.tasks].sort((a, b) => b.busy_pct - a.busy_pct);
    $('#sys-note').textContent = p.available ? `läuft seit ${fmtDuration(p.uptime_s)}` : '';
    $('#sys-body').innerHTML = `<div class="kpis">
        ${kpi('CPU jetzt', p.cpu_pct_now != null ? `${p.cpu_pct_now} %` : '…', 'cpu', p.cpu_pct_now > 50 ? 'tone-warn' : 'tone-up', '#/logs')}
        ${kpi('CPU Ø seit Start', p.available ? `${p.cpu_pct_avg} %` : '–', 'activity', 'tone-accent', '#/logs')}
        ${kpi('Arbeitsspeicher', p.available ? `${p.rss_mb} MB` : '–', 'stack-2', 'tone-info', '#/logs')}
        ${kpi('Datenbank', `${Math.round(s.db_mb)} MB`, 'database', 'tone-muted', '#/logs')}
        ${kpi('Offene Browser', s.browsers, 'device-desktop', 'tone-muted', '#/logs')}
      </div>
      <p class="muted small">${s.monitored} überwachte Geräte (Prüfung alle ${s.monitor_interval_s} s) · Inventar alle ${s.inventory_interval_min} Min. ·
        ${s.shellys} Shellys ${s.live_enabled ? `live alle ${s.live_interval_s} s` : '(Echtzeit aus)'} · ${s.checks} Dienst-Checks.
        CPU-Werte gelten für den NetPulse-Prozess (100 % = ein voller Prozessorkern).</p>
      ${tasks.length ? `<div class="table-wrap"><table><thead><tr><th>Aufgabe</th><th>Läufe/Min.</th><th>Ø Dauer</th><th>max.</th><th>zuletzt</th><th title="Anteil der Laufzeit, in der diese Aufgabe aktiv war (inkl. Wartezeit auf Geräte)">aktiv</th></tr></thead>
        <tbody>${tasks.map((t) => `<tr><td>${esc(t.name)}</td><td>${esc(t.per_min)}</td><td>${esc(fmtMs(t.avg_ms))}</td><td>${esc(fmtMs(t.max_ms))}</td>
          <td class="small">${esc(fmtAgo(t.last_at))}</td><td>${esc(t.busy_pct)} %</td></tr>`).join('')}</tbody></table></div>` : ''}`;
  };
  const render = async () => {
    renderSystem().catch(() => {});
    lines = await api(`/logs?level=${encodeURIComponent(filters.level)}&q=${encodeURIComponent(filters.q)}&limit=1000`);
    $('#log-count').textContent = `${lines.length} Einträge`;
    $('#log-body').innerHTML = lines.length ? lines.map((l) => `<div class="log-line lvl-${esc(l.level)}">
        <span class="mono muted">${esc(new Date(l.time).toLocaleString('de-DE'))}</span>
        <span class="lvl">${esc(l.level.toUpperCase())}</span>
        <span class="mono muted small ellipsis" title="${esc(l.target)}">${esc(shortTarget(l.target))}</span>
        <span class="msg">${esc(l.message)}</span></div>`).join('') : empty('Keine passenden Meldungen.', 'file-text');
  };
  let debounce = null;
  $('#log-level').addEventListener('change', (ev) => { filters.level = ev.target.value; render(); });
  $('#log-q').addEventListener('input', (ev) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { filters.q = ev.target.value.trim(); render(); }, 300);
  });
  const auto = () => { if ($('#log-auto').checked) autoRefresh(render, 3); else clearInterval(state.refreshTimer); };
  $('#log-auto').addEventListener('change', auto);
  $('#log-save').addEventListener('click', () => {
    const text = lines.slice().reverse().map((l) => `${l.time} ${l.level.toUpperCase().padEnd(5)} ${l.target}: ${l.message}`).join('\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `netpulse-log-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  await render();
  auto();
}

// ----- Zwei-Faktor-Anmeldung -----
async function renderTotp() {
  const box = $('#totp-box');
  const { enabled, required } = await api('/me/totp');
  if (enabled && required) {
    box.innerHTML = `<p><span class="badge st-up">aktiv</span> Bei der Anmeldung wird zusätzlich der Code aus der Authenticator-App abgefragt.</p>
      <p class="muted small">Für alle Benutzer vorgeschrieben – kann nicht ausgeschaltet werden.</p>`;
    return;
  }
  if (enabled) {
    box.innerHTML = `<p><span class="badge st-up">aktiv</span> Bei der Anmeldung wird zusätzlich der Code aus der Authenticator-App abgefragt.</p>
      <form class="form" id="totp-off"><label>Zum Ausschalten: Passwort<input name="password" type="password" required autocomplete="current-password"></label>
      <label>und aktueller Code aus der App<input name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="7" placeholder="123 456"></label>
      <button type="submit" class="ghost">Ausschalten</button></form>`;
    $('#totp-off').addEventListener('submit', (ev) => {
      ev.preventDefault();
      attempt(async () => { await api('/me/totp/disable', { method: 'POST', body: { password: ev.target.elements.password.value, code: ev.target.elements.code.value } }); await renderTotp(); },
        'Zwei-Faktor-Anmeldung ausgeschaltet');
    });
    return;
  }
  box.innerHTML = `<p class="muted">Schützt dein Konto zusätzlich mit einem 6-stelligen Code aus einer App wie Google/Microsoft Authenticator,
      Aegis, 2FAS oder Bitwarden. <b>Dringend empfohlen, wenn NetPulse aus dem Internet erreichbar ist.</b></p>
    <button type="button" id="totp-setup">${icon('shield-lock')}Einrichten</button>`;
  $('#totp-setup').addEventListener('click', () => attempt(async () => {
    const s = await api('/me/totp/setup', { method: 'POST' });
    box.innerHTML = `<ol class="steps"><li>QR-Code mit der Authenticator-App scannen</li><li>Den angezeigten Code eingeben</li></ol>
      <div class="qr">${s.qr_svg || ''}</div>
      <p class="muted small">Oder von Hand eintragen: <code class="mono">${esc(s.secret.replace(/(.{4})/g, '$1 ').trim())}</code></p>
      <form class="form" id="totp-on"><label>Code aus der App<input name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="7" placeholder="123 456"></label>
      <button type="submit">${icon('check')}Aktivieren</button></form>`;
    $('#totp-on').addEventListener('submit', (ev) => {
      ev.preventDefault();
      attempt(async () => {
        await api('/me/totp/enable', { method: 'POST', body: { code: ev.target.elements.code.value } });
        if (state.user.totp_setup_required) {
          // Sperre aufheben: App mit vollem Zugriff neu starten
          state.user = await api('/me');
          startApp();
          location.hash = '#/dashboard';
          return;
        }
        await renderTotp();
      }, 'Zwei-Faktor-Anmeldung ist aktiv');
    });
  }));
}

// ----- Alarmtöne -----
function renderSounds() {
  const box = $('#sound-box');
  const s = soundSettings();
  const options = (sel) => Object.entries(ALARM_SOUNDS).map(([k, v]) => `<option value="${k}"${k === sel ? ' selected' : ''}>${esc(v.label)}</option>`).join('');
  const row = (key, label) => `<div class="sound-row"><label>${label}<select name="${key}">${options(s[key])}</select></label>
      <button type="button" class="ghost sm" data-play="${key}" title="Probe hören">${icon('player-play', 'i-sm')}</button>
      <button type="button" class="ghost sm" data-wav="${key}" title="Als Tondatei speichern (für Android)">${icon('cloud-download', 'i-sm')}</button></div>`;
  box.innerHTML = `<form class="form" id="sound-form">
      <div class="sound-grid">${row('critical', 'Kritischer Alarm (z. B. Gerät offline)')}${row('warning', 'Warnung (z. B. CPU hoch, Dienst gestört)')}
        ${row('resolved', 'Entwarnung (Problem behoben)')}${row('info', 'Hinweis (z. B. neues Gerät)')}</div>
      <div class="form-row"><label>Lautstärke<input name="volume" type="range" min="0" max="1" step="0.05" value="${esc(s.volume)}"></label>
        <label class="inline"><input type="checkbox" name="repeat"${s.repeat ? ' checked' : ''}> Kritische Alarme alle 10 s wiederholen, bis der Hinweis geschlossen wird (höchstens 5 min)</label></div>
      <p class="hint">Die Töne spielt NetPulse, solange die Oberfläche bzw. App geöffnet ist – auch als Tab im Hintergrund. Die Auswahl gilt nur für
        dieses Gerät/diesen Browser.</p>
      <div class="notice info">${icon('device-mobile')}<span><b>Auch bei geschlossener App (Android):</b> Push-Nachrichten klingen immer mit dem Ton,
        den Android für NetPulse eingestellt hat – eine Web-App darf keinen eigenen Ton mitschicken. So wird es trotzdem dein Alarmton:
        <ol class="steps small">
          <li>Beim gewünschten Ton auf ${icon('cloud-download', 'i-sm')} tippen – die Datei <code>NetPulse-….wav</code> landet unter <i>Downloads</i>.</li>
          <li><i>Einstellungen → Apps → NetPulse → Benachrichtigungen</i> → Kategorie mit deiner Adresse antippen → <b>Ton</b>.</li>
          <li>Dort <b>„+“ / „Ton hinzufügen“ / „Vom Gerät“</b> wählen und die Datei aus <i>Downloads</i> auswählen.
            (Fehlt die Möglichkeit: die Datei mit der App <i>Dateien</i> in den Ordner <code>Notifications</code> verschieben, dann erscheint sie in der Liste.)</li>
        </ol>
        Android erlaubt einen Ton je App – nimm am besten den für kritische Alarme. Getrennte Töne je Schwere und einen Dauer-Alarm bei geschlossener App
        bietet die App <b>ntfy</b> (Kanal „ntfy“; kritisch = höchste Priorität, Warnung = hoch).</span></div></form>`;
  const form = $('#sound-form');
  const save = () => {
    const e = form.elements;
    saveSoundSettings({ critical: e.critical.value, warning: e.warning.value, resolved: e.resolved.value, info: e.info.value,
      volume: Number(e.volume.value), repeat: e.repeat.checked });
  };
  form.addEventListener('change', save);
  form.addEventListener('input', (ev) => { if (ev.target.name === 'volume') save(); });
  $$('[data-wav]', form).forEach((b) => b.addEventListener('click', () => attempt(async () => {
    save();
    const name = soundSettings()[b.dataset.wav];
    if (name === 'none') throw new Error('Für „Kein Ton“ gibt es keine Datei');
    // Kurze Töne zweimal hintereinander, damit sie als Benachrichtigung deutlich genug sind
    const blob = await soundWav(name, ALARM_SOUNDS[name].notes.reduce((m, n) => Math.max(m, n[0] + n[1]), 0) < 1 ? 2 : 1);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `NetPulse-${ALARM_SOUNDS[name].label.replace(/[^A-Za-zÄÖÜäöüß0-9]+/g, '-').replace(/-+$/, '')}.wav`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }, 'Tondatei gespeichert – jetzt in Android als NetPulse-Ton auswählen')));
  $$('[data-play]', form).forEach((b) => b.addEventListener('click', () => {
    save();
    const s2 = soundSettings();
    if (!playSound(s2[b.dataset.play], s2.volume) && s2[b.dataset.play] !== 'none') toast('Ton nicht abspielbar – Lautstärke des Geräts prüfen', true);
  }));
}

// ----- Sitzungen -----
function describeAgent(ua) {
  if (!ua) return 'Unbekanntes Gerät';
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows'
    : /Mac OS/.test(ua) ? 'Mac' : /Linux/.test(ua) ? 'Linux' : 'Gerät';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl|python/i.test(ua) ? 'Skript' : 'Browser';
  return `${os} · ${browser}`;
}

async function renderSessions() {
  const box = $('#sess-box');
  const list = await api('/me/sessions');
  box.innerHTML = `<div class="table-wrap"><table><thead><tr><th>Gerät</th><th>Adresse</th><th>Angemeldet</th><th>Zuletzt aktiv</th><th></th></tr></thead>
    <tbody>${list.map((x) => `<tr><td>${icon(/iPhone|Android|iPad/.test(x.user_agent || '') ? 'device-mobile' : 'device-desktop', 'i-sm')}
        ${esc(describeAgent(x.user_agent))} ${x.current ? '<span class="badge accent">dieses Gerät</span>' : ''}</td>
      <td class="mono small">${esc(x.ip || '–')}</td><td class="small">${esc(fmtTime(x.created_at))}</td>
      <td class="small">${esc(fmtAgo(x.last_seen || x.created_at))}</td>
      <td class="actions"><button type="button" class="ghost sm" data-end="${x.id}" data-current="${x.current}">${icon('logout', 'i-sm')}Abmelden</button></td></tr>`).join('')}</tbody></table></div>
    <p class="muted small">Unbekanntes Gerät dabei? Abmelden und sofort das Passwort ändern. Abgemeldete Geräte verlieren den Zugriff sofort.</p>`;
  $$('[data-end]', box).forEach((b) => b.addEventListener('click', () => {
    const current = b.dataset.current === 'true';
    if (current && !confirm('Dieses Gerät abmelden?')) return;
    attempt(async () => {
      await api(`/me/sessions/${b.dataset.end}`, { method: 'DELETE' });
      if (current) { showLogin(); return; }
      await renderSessions();
    }, 'Sitzung beendet');
  }));
}

// ----- NetPulse-App & Push -----
const b64ToBytes = (b64) => {
  const raw = atob(b64.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
};

function deviceName() {
  const ua = navigator.userAgent;
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows'
    : /Mac OS/.test(ua) ? 'Mac' : /Linux/.test(ua) ? 'Linux' : 'Gerät';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : '';
  const app = window.matchMedia('(display-mode: standalone)').matches ? ' (App)' : '';
  return `${os}${browser ? ` · ${browser}` : ''}${app}`;
}

async function currentSubscription() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return null;
  const reg = await navigator.serviceWorker.getRegistration();
  return reg ? reg.pushManager.getSubscription() : null;
}

async function renderPush() {
  const box = $('#push-box');
  const devices = await api('/push/devices');
  const supported = window.isSecureContext && 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  const iosBrowser = /iPhone|iPad/.test(navigator.userAgent) && !window.matchMedia('(display-mode: standalone)').matches;
  const sub = supported ? await currentSubscription() : null;
  let status;
  if (!window.isSecureContext || location.protocol !== 'https:') {
    status = `<div class="notice">${icon('alert-triangle')}<span>Push und App-Installation brauchen HTTPS mit einem gültigen Zertifikat –
      also den Aufruf über deine eigene Adresse (z. B. <code>https://monitoring.buschehome.de</code>) statt über die IP-Adresse.</span></div>`;
  } else if (iosBrowser) {
    status = `<div class="notice info">${icon('device-mobile')}<span>iPhone/iPad: Zuerst in Safari auf <b>Teilen → „Zum Home-Bildschirm“</b>
      tippen und NetPulse dann über das neue Symbol öffnen – erst dort erlaubt iOS Push-Nachrichten.</span></div>`;
  } else if (!supported) {
    status = `<div class="notice">${icon('alert-triangle')}<span>Dieser Browser unterstützt keine Push-Nachrichten.</span></div>`;
  } else if (Notification.permission === 'denied') {
    status = `<div class="notice">${icon('alert-triangle')}<span>Benachrichtigungen sind für NetPulse blockiert – in den Browser-/App-Einstellungen erlauben.</span></div>`;
  } else {
    const android = /Android/.test(navigator.userAgent);
    status = sub
      ? `<p><span class="badge st-up">aktiv</span> Dieses Gerät erhält Push-Nachrichten.</p>
         ${android ? `<div class="notice info">${icon('device-mobile')}<span><b>Pop-up mit Ton:</b> Android entscheidet das je App.
           Einmal einstellen: <i>Einstellungen → Apps → NetPulse</i> (bzw. <i>Chrome</i>) <i>→ Benachrichtigungen</i> → die Kategorie mit
           „netpulse“/deiner Adresse öffnen → <b>„Warnmeldung“ / „Standard mit Ton“</b> wählen und <b>„Als Pop-up anzeigen“</b> einschalten.
           Die Test-Nachricht verhält sich wie ein echter Alarm.</span></div>` : ''}
         <div class="actions"><button type="button" id="push-test">${icon('send')}Test-Nachricht</button>
         <button type="button" class="ghost" id="push-off">Auf diesem Gerät ausschalten</button></div>`
      : `<p class="muted">Alarme erscheinen als Nachricht auf diesem Gerät – auch wenn NetPulse geschlossen ist.</p>
         <button type="button" id="push-on">${icon('bell')}Push auf diesem Gerät aktivieren</button>`;
  }
  const hint = installHint();
  const install = `<div class="install-row"><div><b>App installieren</b><div class="muted small">${esc(hint.text)}</div></div>
    ${!isStandalone() ? `<button type="button" class="ghost" id="install-now"${hint.ok ? '' : ' disabled'}>${icon('device-mobile')}Installieren</button>` : ''}</div>`;
  box.innerHTML = `${install}${status}
    <p class="muted small">Damit Alarme als Push kommen: unter <b>Benachrichtigungen</b> einen Kanal „NetPulse-App“ anlegen und in den Alarmregeln auswählen.</p>
    ${devices.length ? `<h3 class="sub">Geräte mit Push-Nachrichten</h3><ul class="list">${devices.map((d) => `<li><span class="lead">${icon('device-mobile', 'i-sm')}
      <span>${esc(d.device || 'Gerät')}${sub && d.endpoint === sub.endpoint ? ' <span class="badge accent">dieses</span>' : ''}</span></span>
      <span class="meta">seit ${esc(fmtTime(d.created_at))}${d.last_ok_at ? ` · zuletzt zugestellt ${esc(fmtAgo(d.last_ok_at))}` : ' · noch nichts zugestellt'}
      ${d.last_shown_at ? ` · <b>auf dem Gerät angezeigt ${esc(fmtAgo(d.last_shown_at))}</b>` : ''}
      ${d.last_show_error ? `<span class="ch-error">${icon('alert-triangle', 'i-sm')} Anzeige auf dem Gerät fehlgeschlagen: ${esc(d.last_show_error)}</span>` : ''}
      ${d.last_ok_at && (!d.last_shown_at || new Date(d.last_shown_at) < new Date(d.last_ok_at) - 60000) && !d.last_show_error
    ? `<span class="ch-warn">${icon('info-circle', 'i-sm')} zugestellt, aber keine Rückmeldung vom Gerät – Android lässt die App im Hintergrund nicht laufen (Akku-Optimierung ausschalten) oder die App ist veraltet (einmal ganz schließen und neu öffnen)</span>` : ''}
      ${d.last_error && (!d.last_ok_at || new Date(d.last_error_at) > new Date(d.last_ok_at)) ? `<span class="ch-error">${icon('alert-triangle', 'i-sm')} ${esc(d.last_error)}</span>` : ''}
      <button class="ghost sm" type="button" data-unsub="${d.id}" title="Abmelden">${icon('x', 'i-sm')}</button></span></li>`).join('')}</ul>` : ''}`;
  $('#install-now')?.addEventListener('click', () => installApp().catch(() => {}));
  $('#push-on')?.addEventListener('click', () => attempt(async () => {
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') throw new Error('Benachrichtigungen wurden nicht erlaubt');
    const reg = await navigator.serviceWorker.register('/sw.js');
    await navigator.serviceWorker.ready;
    const { public_key: key } = await api('/push/key');
    const subscription = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToBytes(key) });
    const j = subscription.toJSON();
    await api('/push/subscribe', { method: 'POST', body: { endpoint: j.endpoint, keys: j.keys, device: deviceName() } });
    await renderPush();
  }, 'Push-Nachrichten aktiviert'));
  $('#push-test')?.addEventListener('click', () => attempt(async () => {
    const r = await api('/push/test', { method: 'POST' });
    if (!r.sent) throw new Error(`Keine Nachricht zugestellt${r.errors && r.errors.length ? `: ${r.errors.join('; ')}` : ''} – Push auf diesem Gerät aus- und wieder einschalten`);
    await renderPush();
  }, 'Test-Nachricht gesendet – sie sollte gleich erscheinen'));
  $('#push-off')?.addEventListener('click', () => attempt(async () => {
    const s = await currentSubscription();
    if (s) {
      await api('/push/unsubscribe', { method: 'POST', body: { endpoint: s.endpoint } });
      await s.unsubscribe();
    }
    await renderPush();
  }, 'Push auf diesem Gerät ausgeschaltet'));
  $$('[data-unsub]', box).forEach((b) => b.addEventListener('click', () => attempt(async () => {
    await api('/push/unsubscribe', { method: 'POST', body: { id: Number(b.dataset.unsub) } });
    await renderPush();
  }, 'Gerät abgemeldet')));
}

async function viewAccount() {
  view().innerHTML = `
    ${state.user.totp_setup_required ? `<div class="notice warn">${icon('shield-lock')}<span><b>Zwei-Faktor-Anmeldung ist Pflicht.</b>
      Bitte jetzt unten einrichten – danach ist NetPulse wieder vollständig nutzbar.</span></div>` : ''}
    <div class="grid">
      <section class="card span-1"><header><h2>${icon('user')}Angemeldet als</h2></header>
        <dl class="details"><dt>Benutzer</dt><dd>${esc(state.user.username)}</dd>
          <dt>Rollen</dt><dd>${esc((state.user.roles || []).join(', ') || 'keine')}</dd>
          <dt>Gilt für</dt><dd>${perms().global.length ? 'alle Sektoren' : esc(Object.keys(perms().sites).length ? `${Object.keys(perms().sites).length} Sektor(en)` : '–')}</dd></dl></section>
      <section class="card span-1"><header><h2>${icon('lock')}Passwort ändern</h2></header>
        <form class="form" id="pw-form">
          <label>Aktuelles Passwort<input name="old" type="password" required autocomplete="current-password"></label>
          <label>Neues Passwort (mind. 12 Zeichen)<input name="new" type="password" required minlength="12" autocomplete="new-password"></label>
          <label>Neues Passwort wiederholen<input name="repeat" type="password" required minlength="12" autocomplete="new-password"></label>
          <button type="submit">Passwort ändern</button>
          <p class="hint">Alle anderen Sitzungen werden dabei abgemeldet.</p>
        </form></section>
      <section class="card span-1"><header><h2>${icon('shield-lock')}Zwei-Faktor-Anmeldung</h2></header><div id="totp-box"><div class="empty">Lade …</div></div></section>
      <section class="card span-3"><header><h2>${icon('shield-lock')}Angemeldete Geräte (Sitzungen)</h2>
        <button type="button" class="ghost sm" id="sess-others">${icon('logout', 'i-sm')}Alle anderen abmelden</button></header><div id="sess-box"><div class="empty">Lade …</div></div></section>
      <section class="card span-3"><header><h2>${icon('device-mobile')}NetPulse-App &amp; Push-Nachrichten</h2></header><div id="push-box"><div class="empty">Lade …</div></div></section>
      <section class="card span-3"><header><h2>${icon('bell')}Alarmtöne auf diesem Gerät</h2></header><div id="sound-box"></div></section>
      <section class="card span-3"><header><h2>${icon('key')}API-Schlüssel</h2></header><div id="token-box"><div class="empty">Lade …</div></div></section>
    </div>`;
  renderTotp();
  renderSessions();
  renderPush();
  renderSounds();
  renderTokens().catch((e) => { $('#token-box').innerHTML = `<p class="muted">${esc(e.message)}</p>`; });
  $('#sess-others').addEventListener('click', () => {
    if (!confirm('Alle anderen Geräte abmelden? Dort muss man sich danach neu anmelden.')) return;
    attempt(async () => { const r = await api('/me/sessions/others', { method: 'DELETE' }); toast(`${r.ended} Sitzung(en) beendet`); await renderSessions(); });
  });
  $('#pw-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    if (f.get('new') !== f.get('repeat')) { toast('Die neuen Passwörter stimmen nicht überein', true); return; }
    attempt(async () => {
      await api('/me/password', { method: 'POST', body: { old_password: f.get('old'), new_password: f.get('new') } });
      ev.target.reset();
    }, 'Passwort geändert');
  });
}

// ---------------------------------------------------------------------------
// Wartungsfenster
// ---------------------------------------------------------------------------

const WEEKDAYS = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So'];

function describeWindow(w) {
  if (w.kind === 'once') return `${fmtTime(w.starts_at)} bis ${fmtTime(w.ends_at)}`;
  const days = w.days.length === 7 ? 'täglich' : w.days.map((d) => WEEKDAYS[d - 1]).join(', ');
  return `${days} ${w.time_from}–${w.time_to} Uhr`;
}

// ---------------------------------------------------------------------------
// Sicherung & Wiederherstellung
// ---------------------------------------------------------------------------

/** Datei vom Server holen und im Browser speichern (POST/GET mit CSRF-Header) */
async function downloadFile(path, body) {
  const res = await fetch('/api' + path, {
    method: body ? 'POST' : 'GET',
    headers: { 'Content-Type': 'application/json', 'X-NetPulse-Csrf': '1' },
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  if (!res.ok) {
    let msg = `Fehler ${res.status}`;
    try { msg = (await res.json()).error || msg; } catch { /* keine JSON-Antwort */ }
    throw new Error(msg);
  }
  const name = (/filename="([^"]+)"/.exec(res.headers.get('content-disposition') || '') || [])[1] || 'netpulse.npbackup';
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return name;
}

const REPORT_LABEL = { networks: 'Netze', devices: 'Geräte', credentials: 'Zugangsdaten', channels: 'Benachrichtigungskanäle', checks: 'Dienste',
  alert_rules: 'Alarm-Regeln', maintenance: 'Wartungsfenster', users: 'Benutzer', settings: 'Einstellungen', energy_days: 'Energie-Tageswerte' };

async function viewBackup() {
  view().innerHTML = `
    <div class="grid">
      <section class="card span-1"><header><h2>${icon('cloud-download')}Sicherung herunterladen</h2></header>
        <form class="form" id="bk-export">
          <p class="muted small">Enthält alles Eingestellte: Netze, Geräte mit Namen und Rollen, Zugangsdaten, Benachrichtigungen, Regeln, Dienste,
            Wartungsfenster, Benutzer, Dashboards, Statusseite und Energie-Tageswerte. Messverläufe und Protokolle sind nicht enthalten.</p>
          <label>Passwort für die Sicherung (mind. 12 Zeichen)<input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
          <label>Passwort wiederholen<input name="repeat" type="password" required minlength="12" autocomplete="new-password"></label>
          <label>Dein Konto-Passwort zur Bestätigung<input name="account" type="password" required autocomplete="current-password"></label>
          <button type="submit">${icon('cloud-download')}Herunterladen</button>
          <p class="hint"><b>Passwort gut aufheben</b> – ohne es lässt sich die Sicherung nicht öffnen. Die Datei enthält alle Zugangsdaten (verschlüsselt).</p>
        </form></section>
      <section class="card span-1"><header><h2>${icon('refresh')}Sicherung einspielen</h2></header>
        <form class="form" id="bk-restore">
          <label>Sicherungsdatei (.npbackup)<input name="file" type="file" accept=".npbackup,application/json" required></label>
          <label>Passwort der Sicherung<input name="password" type="password" required autocomplete="off"></label>
          <label>Dein Konto-Passwort zur Bestätigung<input name="account" type="password" required autocomplete="current-password"></label>
          <button type="submit">${icon('refresh')}Einspielen</button>
          <p class="hint">Einträge werden über IP, Name bzw. Netz zugeordnet und aktualisiert oder neu angelegt. Es wird nichts gelöscht,
            und der Messverlauf vorhandener Geräte bleibt erhalten. Benutzer aus der Sicherung bekommen ihr damaliges Passwort und ihre 2FA zurück.</p>
          <div id="bk-report"></div>
        </form></section>
      <section class="card span-1"><header><h2>${icon('calendar-time')}Automatische Sicherung</h2></header><div id="bk-auto"><div class="empty">Lade …</div></div></section>
      <section class="card span-3"><header><h2>${icon('database')}Gespeicherte Sicherungen</h2>
        <button type="button" class="ghost sm" id="bk-now">${icon('player-play', 'i-sm')}Jetzt sichern</button></header><div id="bk-files"></div></section>
    </div>`;

  $('#bk-export').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = ev.target.elements;
    if (e.password.value !== e.repeat.value) { toast('Die Passwörter stimmen nicht überein', true); return; }
    const btn = ev.target.querySelector('button');
    btn.disabled = true;
    attempt(async () => {
      const name = await downloadFile('/backup/export', { password: e.password.value, account_password: e.account.value });
      ev.target.reset();
      toast(`Sicherung „${name}“ heruntergeladen`);
    }).finally(() => { btn.disabled = false; });
  });

  $('#bk-restore').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = ev.target.elements;
    const f = e.file.files[0];
    if (!f) return;
    if (f.size > 60 * 1024 * 1024) { toast('Die Datei ist zu groß', true); return; }
    if (!confirm('Sicherung jetzt einspielen? Vorhandene Einstellungen mit gleichem Namen werden überschrieben.')) return;
    const btn = ev.target.querySelector('button');
    btn.disabled = true;
    attempt(async () => {
      let file;
      try { file = JSON.parse(await f.text()); } catch { throw new Error('Das ist keine NetPulse-Sicherung'); }
      const r = await api('/backup/restore', { method: 'POST', body: { file, password: e.password.value, account_password: e.account.value } });
      ev.target.reset();
      $('#bk-report').innerHTML = `<div class="notice ok">${icon('circle-check')}<span><b>Wiederhergestellt</b> (Sicherung vom ${esc(fmtTime(r.created_at))}):
        ${Object.entries(r.report).filter(([, n]) => n).map(([k, n]) => `${esc(n)} ${esc(REPORT_LABEL[k] || k)}`).join(', ') || 'nichts'}.</span></div>`;
      toast('Sicherung eingespielt');
    }).finally(() => { btn.disabled = false; });
  });

  const renderAuto = async () => {
    const a = await api('/backup/auto');
    $('#bk-auto').innerHTML = `<form class="form" id="bk-auto-form">
        <label class="inline"><input type="checkbox" name="enabled"${a.enabled ? ' checked' : ''}> Jeden Tag automatisch sichern</label>
        <div class="form-row"><label>Uhrzeit<select name="hour">${Array.from({ length: 24 }, (_, h) => `<option value="${h}"${h === a.hour ? ' selected' : ''}>${String(h).padStart(2, '0')}:00</option>`).join('')}</select></label>
          <label>Aufheben (Anzahl)<input name="keep" type="number" min="1" max="365" value="${esc(a.keep)}"></label></div>
        <label>${a.has_password ? 'Neues Passwort (leer = beibehalten)' : 'Passwort für die Sicherungen (mind. 12 Zeichen)'}
          <input name="password" type="password" minlength="12" autocomplete="new-password"${a.has_password ? '' : ' placeholder="wird zum Öffnen gebraucht"'}></label>
        <button type="submit">${icon('check')}Speichern</button>
        <p class="hint">Die Dateien liegen im Daten-Volume unter <code>${esc(a.directory)}</code>. Kopiere sie regelmäßig auf ein anderes Gerät
          (z. B. per Hyper Backup) – eine Sicherung nur auf demselben NAS schützt nicht vor einem Plattenausfall.</p></form>`;
    $('#bk-files').innerHTML = a.files.length ? `<div class="table-wrap"><table><thead><tr><th>Datei</th><th>Erstellt</th><th class="num">Größe</th><th></th></tr></thead><tbody>
        ${a.files.map((f) => `<tr><td class="mono small">${esc(f.name)}</td><td>${esc(fmtTime(f.time))}</td><td class="num">${esc(fmtBytes(f.size))}</td>
          <td class="actions"><button type="button" class="ghost sm" data-dl="${esc(f.name)}" title="Herunterladen">${icon('cloud-download', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-del="${esc(f.name)}" title="Löschen">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}
        </tbody></table></div>` : `<p class="muted">Noch keine gespeicherten Sicherungen.</p>`;
    $('#bk-auto-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const e = ev.target.elements;
      attempt(async () => {
        await api('/backup/auto', { method: 'PUT', body: { enabled: e.enabled.checked, hour: Number(e.hour.value), keep: Number(e.keep.value), password: e.password.value || null } });
        await renderAuto();
      }, 'Gespeichert');
    });
    $$('[data-dl]', $('#bk-files')).forEach((b) => b.addEventListener('click', () => attempt(() => downloadFile(`/backup/files/${encodeURIComponent(b.dataset.dl)}`))));
    $$('[data-del]', $('#bk-files')).forEach((b) => b.addEventListener('click', () => {
      if (!confirm(`Sicherung „${b.dataset.del}“ löschen?`)) return;
      attempt(async () => { await api(`/backup/files/${encodeURIComponent(b.dataset.del)}`, { method: 'DELETE' }); await renderAuto(); }, 'Gelöscht');
    }));
  };
  $('#bk-now').addEventListener('click', (ev) => {
    ev.currentTarget.disabled = true;
    const btn = ev.currentTarget;
    attempt(async () => { const r = await api('/backup/auto/run', { method: 'POST' }); toast(`Gespeichert: ${r.file}`); await renderAuto(); })
      .finally(() => { btn.disabled = false; });
  });
  await renderAuto();
}

async function viewMaintenance() {
  const [data, devices, checks] = await Promise.all([api('/maintenance'), api('/devices'), api('/checks'), loadSites()]);
  const manage = canAny('maintenance.manage');
  const nameOf = (list, id, label) => { const x = list.find((i) => i.id === id); return x ? label(x) : `#${id}`; };
  const targets = (w) => (!w.device_ids.length && !w.check_ids.length && !(w.site_ids || []).length ? 'alle Geräte und Dienste'
    : [...(w.site_ids || []).map((id) => `Sektor ${siteName(id)}`), ...w.device_ids.map((id) => nameOf(devices, id, deviceLabel)),
      ...w.check_ids.map((id) => nameOf(checks, id, (c) => c.name))].join(', '));
  view().innerHTML = `
    <div class="notice info">${icon('clock')}<span>Während eines Wartungsfensters werden keine Alarme verschickt (Überwachung und Verlauf laufen weiter).
      Praktisch für nächtliche Updates, geplante Neustarts oder Umbauten.</span></div>
    <div class="card"><header><h2>${icon('calendar-time')}Wartungsfenster</h2>${manage ? `<button type="button" id="mw-add">${icon('plus')}Hinzufügen</button>` : ''}</header>
      ${data.windows.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Wann</th><th>Betrifft</th><th>Status</th><th></th></tr></thead>
      <tbody>${data.windows.map((w) => `<tr><td>${esc(w.name)}</td><td class="small">${esc(describeWindow(w))}</td><td class="small">${esc(targets(w))}</td>
        <td>${!w.enabled ? '<span class="badge plain">aus</span>' : w.active ? '<span class="badge warn">aktiv</span>' : '<span class="badge plain">geplant</span>'}</td>
        <td class="actions">${manage ? `<button class="ghost sm" data-edit="${w.id}" type="button">${icon('edit', 'i-sm')}</button>
          <button class="ghost sm" data-del="${w.id}" type="button">${icon('trash', 'i-sm')}</button>` : ''}</td></tr>`).join('')}</tbody></table></div>`
      : empty('Keine Wartungsfenster.', 'calendar-time')}</div>`;
  $('#mw-add')?.addEventListener('click', () => windowDialog(null));
  $$('[data-edit]').forEach((b) => b.addEventListener('click', () => windowDialog(data.windows.find((w) => w.id === Number(b.dataset.edit)))));
  $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
    if (!confirm('Wartungsfenster löschen?')) return;
    attempt(async () => { await api(`/maintenance/${b.dataset.del}`, { method: 'DELETE' }); await viewMaintenance(); }, 'Gelöscht');
  }));

  function windowDialog(w) {
    const localInput = (iso) => { if (!iso) return ''; const d = new Date(iso); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
    const now = new Date();
    const m = w || { kind: 'weekly', days: [1, 2, 3, 4, 5, 6, 7], time_from: '03:00', time_to: '04:00', device_ids: [], check_ids: [], site_ids: [], enabled: true,
      starts_at: now.toISOString(), ends_at: new Date(now.getTime() + 3600000).toISOString() };
    const pick = (name, list, chosen, label) => `<div class="pick-list">${list.map((x) => `<label class="inline"><input type="checkbox" name="${name}" value="${x.id}"${chosen.includes(x.id) ? ' checked' : ''}>
      <span class="ellipsis">${esc(label(x))}</span></label>`).join('') || '<span class="muted small">keine</span>'}</div>`;
    const dlg = openModal(w ? 'Wartungsfenster bearbeiten' : 'Wartungsfenster anlegen', `<form class="form" id="mw-form">
      <label>Name<input name="name" required maxlength="100" value="${esc(m.name || '')}" placeholder="z. B. Nächtliche Updates"></label>
      <div class="seg"><label class="inline"><input type="radio" name="kind" value="weekly"${m.kind === 'weekly' ? ' checked' : ''}> wöchentlich</label>
        <label class="inline"><input type="radio" name="kind" value="once"${m.kind === 'once' ? ' checked' : ''}> einmalig</label></div>
      <div data-kind="weekly" class="form"><div class="checks">${WEEKDAYS.map((d, i) => `<label class="inline"><input type="checkbox" name="day" value="${i + 1}"${m.days.includes(i + 1) ? ' checked' : ''}> ${d}</label>`).join('')}</div>
        <div class="form-row"><label>von<input name="time_from" type="time" value="${esc(m.time_from || '03:00')}"></label>
          <label>bis<input name="time_to" type="time" value="${esc(m.time_to || '04:00')}"></label></div>
        <p class="hint">Über Mitternacht möglich, z. B. 23:00 bis 02:00.</p></div>
      <div data-kind="once" class="form-row"><label>Beginn<input name="starts_at" type="datetime-local" value="${localInput(m.starts_at)}"></label>
        <label>Ende<input name="ends_at" type="datetime-local" value="${localInput(m.ends_at)}"></label></div>
      <h3 class="sub">Betrifft (nichts gewählt = alles)</h3>
      <input type="search" id="mw-filter" placeholder="Geräte/Dienste filtern …">
      ${sitesCache.list.length > 1 || !can('maintenance.manage') ? `<div><div class="muted small">Ganze Sektoren</div>${pick('site', sitesCache.list.filter((x) => can('maintenance.manage', x.id)), m.site_ids || [], (x) => x.name)}</div>` : ''}
      <div class="form-row"><div><div class="muted small">Geräte</div>${pick('dev', devices.filter((d) => can('maintenance.manage', d.site_id)), m.device_ids, (d) => `${deviceLabel(d)} – ${d.ip}`)}</div>
        <div><div class="muted small">Dienste</div>${pick('chk', checks, m.check_ids, (c) => c.name)}</div></div>
      <label class="inline"><input type="checkbox" name="enabled"${m.enabled ? ' checked' : ''}> Aktiv</label>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    dlg.classList.add('wide');
    const form = $('#mw-form', dlg);
    const sync = () => { const k = form.elements.kind.value; $$('[data-kind]', form).forEach((el) => { el.hidden = el.dataset.kind !== k; }); };
    $$('input[name="kind"]', form).forEach((r) => r.addEventListener('change', sync));
    sync();
    $('#mw-filter', dlg).addEventListener('input', (ev) => {
      const q = ev.target.value.toLowerCase();
      $$('.pick-list label', dlg).forEach((l) => { l.hidden = q && !l.textContent.toLowerCase().includes(q); });
    });
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const e = form.elements;
      const ids = (n) => $$(`input[name="${n}"]:checked`, form).map((c) => Number(c.value));
      const body = { name: e.name.value.trim(), kind: e.kind.value, days: ids('day'), time_from: e.time_from.value, time_to: e.time_to.value,
        starts_at: e.starts_at.value ? new Date(e.starts_at.value).toISOString() : null, ends_at: e.ends_at.value ? new Date(e.ends_at.value).toISOString() : null,
        device_ids: ids('dev'), check_ids: ids('chk'), site_ids: ids('site'), enabled: e.enabled.checked };
      attempt(async () => {
        if (w) await api(`/maintenance/${w.id}`, { method: 'PATCH', body });
        else await api('/maintenance', { method: 'POST', body });
        dlg.close();
        await viewMaintenance();
      }, 'Wartungsfenster gespeichert');
    });
  }
}

// ---------------------------------------------------------------------------
// Öffentliche Statusseite
// ---------------------------------------------------------------------------

async function viewStatusPage() {
  const [cfg, devices, checks] = await Promise.all([api('/settings/status-page'), api('/devices'), api('/checks')]);
  let items = cfg.items.map((i) => ({ ...i }));
  const link = `${location.origin}/status.html#${cfg.token}`;
  const source = (i) => (i.kind === 'device' ? devices.find((d) => d.id === i.id) : checks.find((c) => c.id === i.id));
  const sourceLabel = (i) => {
    const x = source(i);
    if (!x) return '(gelöscht)';
    return i.kind === 'device' ? `${deviceLabel(x)} – ${x.ip}` : `${x.name} – ${x.target}`;
  };

  view().innerHTML = `
    <div class="notice info">${icon('world')}<span>Eine Seite ohne Anmeldung, z. B. für Familie oder Kollegen. Sie zeigt <b>nur</b> die unten gewählten Einträge
      mit dem Anzeigenamen, den du vergibst, ihren Status und die Verfügbarkeit – keine IP-Adressen, keine internen Namen, keine Bedienmöglichkeit.
      Details (Antwortzeit, Netzwerk-/Internetverkehr) nur dort, wo du sie einschaltest.</span></div>
    <div class="grid">
      <section class="card span-1"><header><h2>${icon('settings')}Einstellungen</h2></header><form class="form" id="sp-form">
        <label class="inline"><input type="checkbox" name="enabled"${cfg.enabled ? ' checked' : ''}> Statusseite eingeschaltet</label>
        <label>Titel<input name="title" maxlength="80" value="${esc(cfg.title)}"></label>
        <label>Beschreibung (optional)<textarea name="description" maxlength="500" rows="3">${esc(cfg.description || '')}</textarea></label>
        <label>Geheimer Link<input readonly value="${esc(link)}" id="sp-link"></label>
        <div class="actions"><button type="button" class="ghost" id="sp-copy">${icon('check')}Kopieren</button>
          <a class="btn ghost" href="${esc(link)}" target="_blank" rel="noopener">${icon('external-link')}Öffnen</a></div>
        <label class="inline"><input type="checkbox" name="new_token"> Neuen Link erzeugen (der alte funktioniert dann nicht mehr)</label>
        <button type="submit">${icon('check')}Speichern</button></form></section>
      <section class="card span-2"><header><h2>${icon('list-details')}Angezeigte Einträge</h2><span class="muted small">Reihenfolge = Reihenfolge auf der Seite</span></header>
        <div id="sp-items"></div>
        <h3 class="sub">Hinzufügen</h3>
        <div class="form-row"><select id="sp-add" aria-label="Eintrag hinzufügen"><option value="">Gerät oder Dienst wählen …</option>
          <optgroup label="Dienste">${checks.map((c) => `<option value="check:${c.id}">${esc(c.name)}</option>`).join('')}</optgroup>
          <optgroup label="Geräte">${devices.map((d) => `<option value="device:${d.id}">${esc(deviceLabel(d))} – ${esc(d.ip)}</option>`).join('')}</optgroup></select>
          <button type="button" class="ghost" id="sp-add-btn">${icon('plus')}Hinzufügen</button></div></section>
    </div>`;

  const renderItems = () => {
    $('#sp-items').innerHTML = items.length ? `<div class="sp-list">${items.map((i, n) => `<div class="sp-item" data-n="${n}">
        <div class="sp-src muted small">${icon(i.kind === 'device' ? 'devices' : 'world-www', 'i-sm')} ${esc(sourceLabel(i))}</div>
        <div class="sp-fields">
          <label>Anzeigename<input data-f="label" maxlength="80" value="${esc(i.label || '')}" placeholder="z. B. Internet, Heizung, Webseite" required></label>
          <label>Abschnitt<input data-f="group" maxlength="60" value="${esc(i.group || '')}" placeholder="z. B. Netzwerk"></label>
          <label class="inline"><input type="checkbox" data-f="details"${i.details ? ' checked' : ''}> Details (Verlauf)</label>
          <div class="actions"><button type="button" class="ghost sm" data-act="up" title="Nach oben">↑</button>
            <button type="button" class="ghost sm" data-act="down" title="Nach unten">↓</button>
            <button type="button" class="ghost sm" data-act="del" title="Entfernen">${icon('x', 'i-sm')}</button></div></div></div>`).join('')}</div>`
      : empty('Noch keine Einträge – unten Gerät oder Dienst hinzufügen.', 'list-details');
    $$('.sp-item').forEach((row) => {
      const n = Number(row.dataset.n);
      $$('[data-f]', row).forEach((el) => el.addEventListener('input', () => {
        items[n][el.dataset.f] = el.type === 'checkbox' ? el.checked : el.value;
      }));
      $$('[data-act]', row).forEach((b) => b.addEventListener('click', () => {
        if (b.dataset.act === 'del') items.splice(n, 1);
        if (b.dataset.act === 'up' && n > 0) [items[n - 1], items[n]] = [items[n], items[n - 1]];
        if (b.dataset.act === 'down' && n < items.length - 1) [items[n + 1], items[n]] = [items[n], items[n + 1]];
        renderItems();
      }));
    });
  };
  renderItems();
  makeSearchable($('#sp-add'), 'Gerät oder Dienst suchen …');

  $('#sp-add-btn').addEventListener('click', () => {
    const v = $('#sp-add').value;
    if (!v) return;
    const [kind, id] = v.split(':');
    if (items.some((i) => i.kind === kind && i.id === Number(id))) { toast('Ist schon auf der Seite'); return; }
    const x = source({ kind, id: Number(id) });
    // Vorschlag für den Anzeigenamen – bitte anpassen, er ist öffentlich sichtbar
    items.push({ kind, id: Number(id), label: kind === 'check' ? x.name : typeInfo(x.device_type).label, group: '', details: false });
    renderItems();
  });
  $('#sp-copy').addEventListener('click', () => {
    navigator.clipboard.writeText($('#sp-link').value).then(() => toast('Link kopiert'), () => { $('#sp-link').select(); });
  });
  $('#sp-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = ev.target.elements;
    if (items.some((i) => !String(i.label || '').trim())) { toast('Bitte jedem Eintrag einen Anzeigenamen geben', true); return; }
    attempt(async () => {
      await api('/settings/status-page', { method: 'PUT', body: { enabled: e.enabled.checked, title: e.title.value, description: e.description.value,
        items: items.map((i) => ({ kind: i.kind, id: i.id, label: i.label, group: i.group || null, details: !!i.details })), new_token: e.new_token.checked } });
      await viewStatusPage();
    }, 'Statusseite gespeichert');
  });
}

// ---------------------------------------------------------------------------
// Protokolle (Syslog & SNMP-Traps)
// ---------------------------------------------------------------------------

const SYSLOG_SEV = ['Notfall', 'Alarm', 'Kritisch', 'Fehler', 'Warnung', 'Hinweis', 'Info', 'Debug'];
const sevBadge = (s) => `<span class="badge sev-${s <= 2 ? 'critical' : s === 3 ? 'error' : s === 4 ? 'warn' : 'info'}">${esc(SYSLOG_SEV[s] || s)}</span>`;

function logRows(items, withDevice = true) {
  return items.map((m) => `<tr class="sev-row-${m.severity <= 3 ? 'bad' : m.severity === 4 ? 'warn' : 'ok'}">
    <td class="small mono nowrap">${esc(new Date(m.time).toLocaleString('de-DE'))}</td>
    ${withDevice ? `<td class="small">${m.device_id ? `<a href="#/device/${m.device_id}">${esc(m.device_label || m.source)}</a>` : esc(m.host || m.source)}
      <div class="muted mono small">${esc(m.source)}</div></td>` : ''}
    <td>${sevBadge(m.severity)}</td><td class="small">${m.app === 'snmp-trap' ? '<span class="badge accent">Trap</span>' : esc(m.app || '')}</td>
    <td class="small log-msg">${esc(m.message)}</td></tr>`).join('');
}

/** Zustand des Empfangs: läuft er, was kam an, wer wurde abgewiesen? */
function receiverBox(r) {
  const rc = r.receiver || {};
  const line = (label, l, rec, port) => {
    if (!port) return `<span class="muted">${label}: aus</span>`;
    const state = l && l.running ? `<span class="badge st-up">empfängt</span>` : `<span class="badge st-down">läuft nicht</span>`;
    const err = l && l.error ? ` <span class="small">(${esc(l.error)})</span>` : '';
    const got = rec && rec.count ? `${esc(rec.count)} seit Start, zuletzt ${esc(fmtAgo(rec.last))}` : 'seit Start nichts angekommen';
    return `<span>${label} UDP <b>${esc(port)}</b> ${state}${err} · ${got}</span>`;
  };
  const rejected = (rc.rejected || []);
  return `<div class="card sl-receiver"><div class="sl-recv-lines">
      ${line('Syslog', rc.syslog, rc.received_syslog, r.syslog_port)}
      ${line('SNMP-Traps', rc.trap, rc.received_trap, r.trap_port)}
      <button type="button" class="ghost sm" id="sl-test">${icon('send', 'i-sm')}Testmeldung senden</button></div>
    ${rejected.length ? `<div class="notice warn">${icon('alert-triangle')}<span><b>Abgewiesen</b> – diese Absender liegen in keinem erlaubten Netz:
      ${rejected.map((x) => `<br><code>${esc(x.ip)}</code> · ${esc(x.count)}× ${x.kind === 'trap' ? 'Trap' : 'Syslog'}, zuletzt ${esc(fmtAgo(x.last))}`).join('')}
      <br>${rc.allow_fixed ? `Erlaubt ist nur <code>SYSLOG_ALLOW=${esc(rc.allow_fixed)}</code> – dort das Netz ergänzen.`
        : 'Angenommen wird nur aus den Netzen unter <a href="#/networks">Netzwerke</a>. Netz dort freigeben oder in Portainer <code>SYSLOG_ALLOW</code> setzen (z. B. <code>10.10.10.0/24,172.16.0.0/12</code>).'}</span></div>` : ''}
  </div>`;
}

async function viewSyslog(_arg, params) {
  const devices = await api('/devices');
  const f = { device: params.get('device') || '', severity: '7', q: '', source: '', hours: '24' };
  view().innerHTML = `
    <div class="page-head"><div class="actions">
        <select id="sl-device" aria-label="Gerät"><option value="">Alle Geräte</option>
          ${devices.map((d) => `<option value="${d.id}"${String(d.id) === f.device ? ' selected' : ''}>${esc(deviceLabel(d))}</option>`).join('')}</select>
        <select id="sl-sev" aria-label="Schwere">${SYSLOG_SEV.map((s, i) => `<option value="${i}"${i === 7 ? ' selected' : ''}>${i === 7 ? 'Alle Stufen' : `${esc(s)} und schlimmer`}</option>`).join('')}</select>
        <select id="sl-src" aria-label="Quelle"><option value="">Syslog + Traps</option><option value="syslog">nur Syslog</option><option value="trap">nur SNMP-Traps</option></select>
        <select id="sl-hours" aria-label="Zeitraum"><option value="1">1 Stunde</option><option value="24" selected>24 Stunden</option><option value="168">7 Tage</option><option value="720">30 Tage</option></select>
        <input id="sl-q" type="search" placeholder="Suchen: Text, Programm …">
        <label class="inline"><input type="checkbox" id="sl-live" checked> live</label></div>
      <span class="muted small" id="sl-count"></span></div>
    <div id="sl-setup"></div>
    <div class="card table-wrap"><table class="log-table"><thead><tr><th>Zeit</th><th>Gerät</th><th>Stufe</th><th>Programm</th><th>Meldung</th></tr></thead>
      <tbody id="sl-body"><tr><td colspan="5"><div class="empty">Lade …</div></td></tr></tbody></table></div>`;

  let items = [];
  const matches = (m) => (!f.device || String(m.device_id) === f.device) && m.severity <= Number(f.severity)
    && (!f.source || (f.source === 'trap') === (m.app === 'snmp-trap'))
    && (!f.q || `${m.message} ${m.app || ''} ${m.host || ''}`.toLowerCase().includes(f.q.toLowerCase()));
  const paint = () => {
    $('#sl-body').innerHTML = items.length ? logRows(items) : `<tr><td colspan="5">${empty('Keine Meldungen im Zeitraum.', 'file-text')}</td></tr>`;
    $('#sl-count').textContent = `${items.length} Meldungen`;
  };
  const load = async () => {
    const qs = new URLSearchParams({ severity: f.severity, hours: f.hours, limit: '1000' });
    if (f.device) qs.set('device', f.device);
    if (f.q) qs.set('q', f.q);
    if (f.source) qs.set('source', f.source);
    const r = await api(`/remote-logs?${qs}`);
    items = r.items;
    $('#sl-setup').innerHTML = receiverBox(r) + (r.last_hour ? '' : `<div class="notice info">${icon('file-text')}<span>
      Noch keine Meldungen empfangen. So schicken Geräte ihre Protokolle an NetPulse (IP-Adresse des NetPulse-Hosts eintragen):<br>
      <b>OPNsense:</b> System → Einstellungen → Protokollierung → Remote → Ziel hinzufügen: UDP, Port <b>${esc(r.syslog_port)}</b><br>
      <b>UniFi:</b> Einstellungen → Control Plane → Integrations/System → „Remote Syslog Server“, Port ${esc(r.syslog_port)}<br>
      <b>Synology:</b> Protokoll-Center → Protokolle senden · <b>Linux:</b> rsyslog <code>*.* @IP:${esc(r.syslog_port)}</code><br>
      <b>SNMP-Traps:</b> Trap-Ziel = NetPulse, Port <b>${esc(r.trap_port)}</b> (v1/v2c).<br>
      <span class="muted">Wichtig: Port <b>${esc(r.syslog_port)}</b> statt des üblichen 514 eintragen.</span></span></div>`);
    paint();
  };
  let debounce;
  const on = (sel, key, ev = 'change') => $(sel).addEventListener(ev, (e) => {
    f[key] = e.target.value.trim();
    clearTimeout(debounce);
    debounce = setTimeout(load, ev === 'input' ? 300 : 0);
  });
  $('#sl-setup').addEventListener('click', (ev) => {
    if (!ev.target.closest('#sl-test')) return;
    attempt(async () => { await api('/remote-logs/test', { method: 'POST' }); setTimeout(() => load().catch(() => {}), 1500); },
      'Testmeldung gesendet – sie sollte gleich in der Liste erscheinen');
  });
  on('#sl-device', 'device'); on('#sl-sev', 'severity'); on('#sl-src', 'source'); on('#sl-hours', 'hours'); on('#sl-q', 'q', 'input');
  await load();
  onLive((msg) => {
    if (msg.type !== 'syslog' || !$('#sl-live').checked) return;
    const fresh = msg.items.map((m) => {
      const d = devices.find((x) => x.ip === m.source);
      return { ...m, device_id: d ? d.id : null, device_label: d ? deviceLabel(d) : null };
    }).filter(matches);
    if (!fresh.length) return;
    items = [...fresh, ...items].slice(0, 1000);
    paint();
  });
}
