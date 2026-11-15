'use strict';
/* Ein/Aus: Wake-on-LAN, Herunterfahren, Gerätegruppen und Zeitpläne */

const POWER_ACTION = { wake: 'Aufwecken', shutdown: 'Herunterfahren' };
const POWER_ICON = { wake: 'player-play', shutdown: 'power' };

function powerDays(days) {
  if (days.length === 7) return 'täglich';
  if (days.join() === '1,2,3,4,5') return 'Mo–Fr';
  if (days.join() === '6,7') return 'Sa, So';
  return days.map((d) => WEEKDAYS[d - 1]).join(', ');
}

/** Ergebnisliste nach einer Aktion für mehrere Geräte */
function powerResultsDialog(title, r) {
  const rows = (r.results || []).sort((a, b) => a.label.localeCompare(b.label, 'de'));
  openModal(title, `<p><b>${esc(r.summary)}</b></p>
    ${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Gerät</th><th>Ergebnis</th></tr></thead><tbody>
    ${rows.map((o) => `<tr><td><a href="#/device/${o.device_id}">${esc(o.label)}</a></td>
      <td class="small">${o.ok === true ? '<span class="badge st-up">ok</span>' : o.ok === false ? '<span class="badge st-down">Fehler</span>' : '<span class="badge plain">übersprungen</span>'}
      ${esc(o.message)}</td></tr>`).join('')}</tbody></table></div>` : ''}
    <p class="hint">Wake-on-LAN meldet nur, dass das Paket verschickt wurde – ob das Gerät hochfährt, zeigt der Status nach ein bis zwei Minuten.</p>`);
}

/** Knöpfe oben in der Geräteansicht */
function powerHeroButtons(d) {
  return `<button type="button" class="ghost" data-power="wake" title="Per Wake-on-LAN bzw. eingestelltem Aufruf einschalten">${icon('player-play')}Aufwecken</button>
    <button type="button" class="ghost" data-power="shutdown" title="Per SSH bzw. eingestelltem Aufruf herunterfahren">${icon('power')}Herunterfahren</button>`;
}

function bindPowerHero(d, after) {
  $$('[data-power]').forEach((b) => b.addEventListener('click', () => {
    const act = b.dataset.power;
    if (act === 'shutdown' && !confirm(`${deviceLabel(d)} jetzt herunterfahren?`)) return;
    b.disabled = true;
    api(`/devices/${d.id}/power/${act}`, { method: 'POST' }).then((o) => {
      toast(`${POWER_ACTION[act]}: ${o.message}`, o.ok === false);
      if (o.ok && after) setTimeout(after, act === 'wake' ? 60000 : 20000);
    }).catch((e) => toast(e.message, true)).finally(() => { b.disabled = false; });
  }));
}

/** Abschnitt „Ein/Aus“ im Reiter Einstellungen eines Geräts (lädt seine Daten selbst) */
function powerSettingsSection() {
  return `<section class="span-1"><h3>${icon('power', 'i-sm')} Ein/Aus</h3><div id="power-settings"><div class="empty">Lade …</div></div></section>`;
}

async function bindPowerSettings(d, credentials) {
  const box = $('#power-settings');
  if (!box) return;
  const [p, groups] = await Promise.all([api(`/devices/${d.id}/power`), api('/device-groups')]);
  const c = p.config || {};
  const wake = c.wake || 'wol';
  const shut = c.shutdown || 'ssh';
  const credManage = can('credentials.manage');
  const credOptions = (list, chosen, none) => `<option value="">${esc(none)}</option>${list.map((x) => `<option value="${x.id}"${x.id === chosen ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}`;
  const sshCreds = credentials.filter((x) => x.kind.startsWith('ssh'));
  const httpCreds = credentials.filter((x) => ['http', 'ssh_password', 'unifi', 'fritzbox', 'opnsense', 'mikrotik', 'http_basic'].includes(x.kind));
  const inGroup = new Set(p.groups.map((g) => g.id));
  // Was ohne Auswahl greift: zugeordnete Zugangsdaten, sonst automatische SSH-Schlüssel
  const sshAuto = p.ssh_credentials.length ? `automatisch: zugeordnet (${p.ssh_credentials.map((x) => x.name).join(', ')})`
    : p.auto_ssh_credentials.length ? `automatisch: SSH-Schlüssel ausprobieren (${p.auto_ssh_credentials.map((x) => x.name).join(', ')})`
    : 'automatisch (kein passender Zugang vorhanden)';
  // Greift automatisch nichts und gibt es genau einen SSH-Zugang, diesen gleich vorschlagen
  const sshChosen = c.ssh_credential_id || (!p.ssh_credentials.length && !p.auto_ssh_credentials.length && sshCreds.length === 1 ? sshCreds[0].id : null);
  box.innerHTML = `<form class="form" id="power-form">
    <label>Aufwecken<select name="wake">
      <option value="wol"${wake === 'wol' ? ' selected' : ''}>Wake-on-LAN (Magic Packet)</option>
      <option value="http"${wake === 'http' ? ' selected' : ''}>HTTP-Aufruf (z. B. Steckdose einschalten)</option>
      <option value="none"${wake === 'none' ? ' selected' : ''}>nicht möglich</option></select></label>
    <div data-show="wake:wol" class="form">
      <div class="form-row"><label>MAC-Adresse${!c.wol_mac && p.mac ? ' (erkannt)' : ''}<input name="wol_mac" maxlength="20" value="${esc(c.wol_mac || p.mac || '')}" placeholder="aa:bb:cc:dd:ee:ff"></label>
        <label>Port<input name="wol_port" type="number" min="1" max="65535" value="${esc(c.wol_port || 9)}"></label></div>
      <label>Zusätzliche Broadcast-Adresse (optional)<input name="wol_broadcast" maxlength="15" value="${esc(c.wol_broadcast || '')}" placeholder="z. B. 192.168.20.255 für ein anderes VLAN"></label>
      <p class="hint">Gesendet wird an: ${esc(p.wol_targets.join(', '))}. Im Gerät (BIOS/UEFI, Netzwerkkarte) muss Wake-on-LAN eingeschaltet sein.</p></div>
    <div data-show="wake:http"><label>Adresse zum Aufwecken<input name="wake_url" maxlength="2000" value="${esc(c.wake_url || '')}" placeholder="http://192.168.1.50/relay/0?turn=on"></label></div>
    <label>Herunterfahren<select name="shutdown">
      <option value="ssh"${shut === 'ssh' ? ' selected' : ''}>per SSH (Linux, NAS, Raspberry Pi, Windows mit OpenSSH)</option>
      <option value="http"${shut === 'http' ? ' selected' : ''}>HTTP-Aufruf (z. B. Home Assistant, eigenes Skript)</option>
      <option value="none"${shut === 'none' ? ' selected' : ''}>nicht möglich</option></select></label>
    <div data-show="shutdown:ssh" class="form">
      <label>SSH-Zugang<select name="ssh_credential_id"${credManage ? '' : ' disabled'}>${credOptions(sshCreds, sshChosen, sshAuto)}</select></label>
      ${sshChosen && !c.ssh_credential_id ? `<p class="hint">Vorgeschlagen, weil es dein einziger SSH-Zugang ist – mit „Speichern“ übernehmen.</p>` : ''}
      <label>Eigener Befehl (optional)<input name="shutdown_command" maxlength="1000" value="${esc(c.shutdown_command || '')}" placeholder="${/windows/i.test(p.os || '') ? 'shutdown /s /t 5 /f' : 'automatisch: shutdown -h now (als root oder per sudo)'}"></label>
      <p class="hint">Ohne Befehl nimmt NetPulse unter Linux <code>shutdown</code>/<code>poweroff</code> – als root oder mit sudo ohne Passwort für genau diesen Befehl,
        z. B. in <code>/etc/sudoers.d/netpulse</code>: <code>netpulse ALL=(root) NOPASSWD: /sbin/shutdown</code>. Unter Windows <code>shutdown /s</code> (Konto mit Admin-Rechten).</p></div>
    <div data-show="shutdown:http"><label>Adresse zum Herunterfahren<input name="shutdown_url" maxlength="2000" value="${esc(c.shutdown_url || '')}" placeholder="https://homeassistant.local:8123/api/webhook/pc-aus"></label></div>
    <div data-show="http" class="form-row"><label>HTTP-Methode<select name="http_method">${['POST', 'GET', 'PUT'].map((m) => `<option${(c.http_method || 'POST') === m ? ' selected' : ''}>${m}</option>`).join('')}</select></label>
      <label>Anmeldung (Benutzer/Passwort)<select name="http_credential_id"${credManage ? '' : ' disabled'}>${credOptions(httpCreds, c.http_credential_id, 'keine')}</select></label></div>
    <div><div class="muted small">Gruppen</div><div class="pick-list">${groups.map((g) => `<label class="inline"><input type="checkbox" name="group" value="${g.id}"${inGroup.has(g.id) ? ' checked' : ''}> <span class="ellipsis">${esc(g.name)}</span></label>`).join('') || '<span class="muted small">Noch keine Gruppen – unter <a href="#/power">Ein/Aus</a> anlegen.</span>'}</div></div>
    <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`;
  const form = $('#power-form');
  const sync = () => {
    const w = form.elements.wake.value;
    const s = form.elements.shutdown.value;
    $$('[data-show]', form).forEach((el) => {
      const [k, v] = el.dataset.show.split(':');
      el.hidden = k === 'http' ? !(w === 'http' || s === 'http') : (k === 'wake' ? w : s) !== v;
    });
  };
  form.elements.wake.addEventListener('change', sync);
  form.elements.shutdown.addEventListener('change', sync);
  sync();
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = form.elements;
    const num = (v) => (v ? Number(v) : null);
    // Erkannte Werte nicht fest speichern – so folgt NetPulse einer neuen MAC (z. B. nach Tausch der Netzwerkkarte)
    const macNorm = (m) => String(m || '').toLowerCase().replace(/[^0-9a-f]/g, '');
    const mac = macNorm(e.wol_mac.value) === macNorm(p.mac) ? '' : e.wol_mac.value;
    const port = Number(e.wol_port.value) === 9 ? null : num(e.wol_port.value);
    const body = { wake: e.wake.value, wol_mac: mac, wol_port: port, wol_broadcast: e.wol_broadcast.value, wake_url: e.wake_url.value,
      shutdown: e.shutdown.value, ssh_credential_id: num(e.ssh_credential_id.value), shutdown_command: e.shutdown_command.value, shutdown_url: e.shutdown_url.value,
      http_method: e.http_method.value, http_credential_id: num(e.http_credential_id.value) };
    const chosen = new Set($$('input[name="group"]:checked', form).map((x) => Number(x.value)));
    attempt(async () => {
      await api(`/devices/${d.id}/power`, { method: 'PUT', body });
      // Gruppenmitgliedschaft: nur geänderte Gruppen speichern
      for (const g of groups) {
        const was = g.device_ids.includes(d.id);
        if (was === chosen.has(g.id)) continue;
        const ids = was ? g.device_ids.filter((x) => x !== d.id) : [...g.device_ids, d.id];
        await api(`/device-groups/${g.id}`, { method: 'PATCH', body: { name: g.name, notes: g.notes, device_ids: ids } });
      }
    }, 'Ein/Aus gespeichert');
  });
}

// ---------------------------------------------------------------------------
// Seite „Ein/Aus“: Gruppen und Zeitpläne
// ---------------------------------------------------------------------------

async function viewPower() {
  const [sched, groups, devices] = await Promise.all([api('/power-schedules'), api('/device-groups'), api('/devices')]);
  const manage = canAny('devices.manage');
  const devName = (id) => { const d = devices.find((x) => x.id === id); return d ? deviceLabel(d) : `#${id}`; };
  const groupName = (id) => { const g = groups.find((x) => x.id === id); return g ? g.name : `Gruppe #${id}`; };
  const targets = (s) => [...s.group_ids.map((id) => `Gruppe ${groupName(id)}`), ...s.device_ids.map(devName)].join(', ') || '–';
  view().innerHTML = `
    <div class="notice info">${icon('power')}<span>Geräte per <b>Wake-on-LAN</b> aufwecken und per <b>SSH</b> oder HTTP-Aufruf herunterfahren –
      einzeln, als Gruppe oder nach Zeitplan (z. B. abends aus, morgens an). Die Art stellst du je Gerät unter Einstellungen → Ein/Aus ein.
      Zeitzone der Zeitpläne: ${esc(sched.timezone)}.</span></div>
    <div class="card"><header><h2>${icon('calendar-time')}Zeitpläne</h2>${manage ? `<button type="button" id="ps-add">${icon('plus')}Hinzufügen</button>` : ''}</header>
      ${sched.schedules.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Aktion</th><th>Wann</th><th>Betrifft</th><th>Nächster Lauf</th><th>Zuletzt</th><th></th></tr></thead>
      <tbody>${sched.schedules.map((s) => `<tr><td>${esc(s.name)}${s.enabled ? '' : ' <span class="badge plain">aus</span>'}</td>
        <td><span class="badge ${s.action === 'wake' ? 'st-up' : 'warn'}">${esc(POWER_ACTION[s.action])}</span></td>
        <td class="small">${esc(powerDays(s.days))} um ${esc(s.time)} Uhr</td>
        <td class="small">${esc(targets(s))}</td>
        <td class="small">${s.next_run ? esc(fmtTime(s.next_run)) : '–'}</td>
        <td class="small">${s.last_result ? `${esc(fmtAgo(s.last_run_at))}: ${esc(s.last_result)}` : '–'}</td>
        <td class="actions">${manage ? `<button class="ghost sm" data-run="${s.id}" type="button" title="Jetzt ausführen">${icon('player-play', 'i-sm')}</button>
          <button class="ghost sm" data-edit="${s.id}" type="button" title="Bearbeiten">${icon('edit', 'i-sm')}</button>
          <button class="ghost sm" data-del="${s.id}" type="button" title="Löschen">${icon('trash', 'i-sm')}</button>` : ''}</td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Zeitpläne.', 'calendar-time')}</div>
    <div class="card"><header><h2>${icon('category')}Gerätegruppen</h2>${manage ? `<button type="button" id="dg-add">${icon('plus')}Neue Gruppe</button>` : ''}</header>
      ${groups.length ? `<div class="table-wrap"><table><thead><tr><th>Gruppe</th><th>Geräte</th><th></th></tr></thead>
      <tbody>${groups.map((g) => `<tr><td><b>${esc(g.name)}</b>${g.notes ? `<div class="muted small">${esc(g.notes)}</div>` : ''}</td>
        <td class="small">${g.device_ids.length ? g.device_ids.map((id) => `<a href="#/device/${id}">${esc(devName(id))}</a>`).join(', ') : '<span class="muted">keine</span>'}
          ${g.hidden_members ? `<span class="muted"> + ${g.hidden_members} in anderen Sektoren</span>` : ''}</td>
        <td class="actions">${manage ? `<button class="ghost sm" data-gact="wake" data-g="${g.id}" type="button" title="Alle aufwecken">${icon('player-play', 'i-sm')}</button>
          <button class="ghost sm" data-gact="shutdown" data-g="${g.id}" type="button" title="Alle herunterfahren">${icon('power', 'i-sm')}</button>
          <button class="ghost sm" data-gedit="${g.id}" type="button" title="Bearbeiten">${icon('edit', 'i-sm')}</button>
          <button class="ghost sm" data-gdel="${g.id}" type="button" title="Löschen">${icon('trash', 'i-sm')}</button>` : ''}</td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Gruppen. Gruppen fassen Geräte zusammen, z. B. „Büro-PCs“ oder „Server im Keller“.', 'category')}</div>
    <div class="card"><header><h2>${icon('info-circle')}So klappt es</h2></header><ul class="small">
      <li><b>Wake-on-LAN</b> braucht die MAC-Adresse und im Gerät eingeschaltetes WOL (BIOS/UEFI, bei Windows zusätzlich in den Eigenschaften der Netzwerkkarte).
        NetPulse muss im selben Netz senden können – der Container läuft dafür im Host-Netz (<code>network_mode: host</code>, Standard in der Portainer-Vorlage).
        Für andere VLANs eine Broadcast-Adresse eintragen und am Router gerichtete Broadcasts erlauben.</li>
      <li><b>Herunterfahren per SSH</b> nutzt die Zugangsdaten aus dem Tresor (verschlüsselt). Das Konto braucht das Recht zum Ausschalten:
        root oder ein sudo-Eintrag ohne Passwort nur für <code>/sbin/shutdown</code>. Windows: OpenSSH-Server und ein Konto mit Admin-Rechten.</li>
      <li>Zeitpläne überspringen Geräte, die schon an bzw. aus sind. Ein verpasster Termin (NetPulse war aus) wird höchstens 15 Minuten nachgeholt.</li>
      <li>Jede Aktion steht unter <a href="#/events">Ereignisse</a> und im Audit-Log.</li></ul></div>`;

  $('#ps-add')?.addEventListener('click', () => scheduleDialog(null));
  $$('[data-edit]').forEach((b) => b.addEventListener('click', () => scheduleDialog(sched.schedules.find((s) => s.id === Number(b.dataset.edit)))));
  $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
    if (!confirm('Zeitplan löschen?')) return;
    attempt(async () => { await api(`/power-schedules/${b.dataset.del}`, { method: 'DELETE' }); await viewPower(); }, 'Gelöscht');
  }));
  $$('[data-run]').forEach((b) => b.addEventListener('click', () => {
    const s = sched.schedules.find((x) => x.id === Number(b.dataset.run));
    if (!confirm(`„${s.name}“ jetzt ausführen (${POWER_ACTION[s.action]})?`)) return;
    b.disabled = true;
    attempt(async () => { powerResultsDialog(`${POWER_ACTION[s.action]}: ${s.name}`, await api(`/power-schedules/${s.id}/run`, { method: 'POST' })); })
      .finally(() => { b.disabled = false; });
  }));
  $('#dg-add')?.addEventListener('click', () => groupDialog(null));
  $$('[data-gedit]').forEach((b) => b.addEventListener('click', () => groupDialog(groups.find((g) => g.id === Number(b.dataset.gedit)))));
  $$('[data-gdel]').forEach((b) => b.addEventListener('click', () => {
    if (!confirm('Gruppe löschen? Die Geräte bleiben erhalten, Zeitpläne verlieren den Verweis.')) return;
    attempt(async () => { await api(`/device-groups/${b.dataset.gdel}`, { method: 'DELETE' }); await viewPower(); }, 'Gruppe gelöscht');
  }));
  $$('[data-gact]').forEach((b) => b.addEventListener('click', () => {
    const g = groups.find((x) => x.id === Number(b.dataset.g));
    const act = b.dataset.gact;
    if (!confirm(`Alle Geräte der Gruppe „${g.name}“ ${act === 'wake' ? 'aufwecken' : 'herunterfahren'}?`)) return;
    b.disabled = true;
    attempt(async () => { powerResultsDialog(`${POWER_ACTION[act]}: ${g.name}`, await api(`/device-groups/${g.id}/power/${act}`, { method: 'POST' })); })
      .finally(() => { b.disabled = false; });
  }));

  const pick = (name, list, chosen, label) => `<div class="pick-list">${list.map((x) => `<label class="inline"><input type="checkbox" name="${name}" value="${x.id}"${chosen.includes(x.id) ? ' checked' : ''}>
    <span class="ellipsis">${esc(label(x))}</span></label>`).join('') || '<span class="muted small">keine</span>'}</div>`;
  const manageable = devices.filter((d) => can('devices.manage', d.site_id)).sort((a, b) => deviceLabel(a).localeCompare(deviceLabel(b), 'de'));
  const filterBox = (dlg) => $('[data-filter]', dlg).addEventListener('input', (ev) => {
    const q = ev.target.value.toLowerCase();
    $$('.pick-list.devs label', dlg).forEach((l) => { l.hidden = q && !l.textContent.toLowerCase().includes(q); });
  });

  function groupDialog(g) {
    const m = g || { name: '', notes: '', device_ids: [] };
    const dlg = openModal(g ? 'Gruppe bearbeiten' : 'Neue Gruppe', `<form class="form" id="dg-form">
      <label>Name<input name="name" required maxlength="100" value="${esc(m.name)}" placeholder="z. B. Büro-PCs"></label>
      <label>Notiz (optional)<input name="notes" maxlength="2000" value="${esc(m.notes || '')}"></label>
      <h3 class="sub">Geräte</h3><input type="search" data-filter placeholder="Geräte filtern …">
      <div class="devs-wrap">${pick('dev', manageable, m.device_ids, (d) => `${deviceLabel(d)} – ${d.ip}`).replace('pick-list', 'pick-list devs')}</div>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    dlg.classList.add('wide');
    filterBox(dlg);
    $('#dg-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = ev.target.elements;
      const body = { name: f.name.value.trim(), notes: f.notes.value, device_ids: $$('input[name="dev"]:checked', dlg).map((c) => Number(c.value)) };
      attempt(async () => {
        if (g) await api(`/device-groups/${g.id}`, { method: 'PATCH', body });
        else await api('/device-groups', { method: 'POST', body });
        dlg.close();
        await viewPower();
      }, 'Gruppe gespeichert');
    });
  }

  function scheduleDialog(s) {
    const m = s || { name: '', action: 'shutdown', days: [1, 2, 3, 4, 5], time: '22:00', device_ids: [], group_ids: [], enabled: true };
    const dlg = openModal(s ? 'Zeitplan bearbeiten' : 'Zeitplan anlegen', `<form class="form" id="ps-form">
      <label>Name<input name="name" required maxlength="100" value="${esc(m.name)}" placeholder="z. B. Büro abends aus"></label>
      <div class="seg"><label class="inline"><input type="radio" name="action" value="wake"${m.action === 'wake' ? ' checked' : ''}> Aufwecken</label>
        <label class="inline"><input type="radio" name="action" value="shutdown"${m.action === 'shutdown' ? ' checked' : ''}> Herunterfahren</label></div>
      <div class="checks">${WEEKDAYS.map((d, i) => `<label class="inline"><input type="checkbox" name="day" value="${i + 1}"${m.days.includes(i + 1) ? ' checked' : ''}> ${d}</label>`).join('')}</div>
      <label>Uhrzeit<input name="time" type="time" required value="${esc(m.time)}"></label>
      <h3 class="sub">Betrifft</h3>
      <div><div class="muted small">Gruppen</div>${pick('grp', groups, m.group_ids, (g) => `${g.name} (${g.device_ids.length})`)}</div>
      <div><div class="muted small">Einzelne Geräte</div><input type="search" data-filter placeholder="Geräte filtern …">
        ${pick('dev', manageable, m.device_ids, (d) => `${deviceLabel(d)} – ${d.ip}`).replace('pick-list', 'pick-list devs')}</div>
      <label class="inline"><input type="checkbox" name="enabled"${m.enabled ? ' checked' : ''}> Aktiv</label>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    dlg.classList.add('wide');
    filterBox(dlg);
    $('#ps-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = ev.target.elements;
      const ids = (n) => $$(`input[name="${n}"]:checked`, dlg).map((c) => Number(c.value));
      const body = { name: f.name.value.trim(), action: f.action.value, days: ids('day'), time: f.time.value,
        device_ids: ids('dev'), group_ids: ids('grp'), enabled: f.enabled.checked };
      attempt(async () => {
        if (s) await api(`/power-schedules/${s.id}`, { method: 'PATCH', body });
        else await api('/power-schedules', { method: 'POST', body });
        dlg.close();
        await viewPower();
      }, 'Zeitplan gespeichert');
    });
  }
}
