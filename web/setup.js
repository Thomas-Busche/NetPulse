/* NetPulse – Einrichtungs-Assistent: Netz kennenlernen, Router erkennen, Zugangsdaten (optional),
   Benachrichtigung (optional), Übersicht. Jeder Schritt lässt sich überspringen; alles bleibt später
   unter Netzwerke, Zugangsdaten und Benachrichtigungen änderbar. */

const SETUP_STEPS = [
  { key: 'net', title: 'Netz kennenlernen', icon: 'radar' },
  { key: 'router', title: 'Router erkennen', icon: 'router' },
  { key: 'creds', title: 'Zugangsdaten', icon: 'key' },
  { key: 'notify', title: 'Benachrichtigung', icon: 'send' },
  { key: 'done', title: 'Fertig', icon: 'circle-check' },
];

/** Gewählte Router-Familie je Gateway (falls von Hand geändert) – nur für diese Sitzung */
const setupFamilyChoice = {};
/** Ergebnis des Verbindungstests je Gerät */
const setupTestResult = {};

async function finishSetup(target = '#/dashboard') {
  await api('/setup', { method: 'PUT', body: { done: true } });
  location.hash = target;
}

/** Beim ersten Start einer neuen Installation direkt zum Assistenten */
async function maybeStartSetup() {
  if (!can('networks.manage') || state.user.kiosk) return false;
  if (location.hash && !['#/', '#/dashboard'].includes(location.hash)) return false;
  try {
    const s = await api('/setup');
    if (!s.done) {
      location.hash = '#/setup';
      return true;
    }
  } catch { /* egal – dann eben das Dashboard */ }
  return false;
}

async function viewSetup(_arg, params) {
  const step = Math.max(0, Math.min(SETUP_STEPS.length - 1, Number((params && params.get('step')) || 0)));
  const go = (n) => { location.hash = `#/setup?step=${n}`; };
  view().innerHTML = `<div class="card wizard">
      <header><h2>${icon('wand')}Einrichtung</h2>
        <button type="button" class="ghost sm" id="wz-skip-all" title="Assistent beenden – lässt sich unter Netzwerke erneut starten">Später einrichten</button></header>
      <ol class="wz-steps">${SETUP_STEPS.map((s, i) => `<li class="${i < step ? 'done' : i === step ? 'current' : ''}">
        <a href="#/setup?step=${i}">${icon(i < step ? 'check' : s.icon, 'i-sm')}<span>${esc(s.title)}</span></a></li>`).join('')}</ol>
      <div id="wz-body"><div class="empty">Lade …</div></div>
      <footer class="wz-foot">
        ${step > 0 ? `<button type="button" class="ghost" id="wz-back">${icon('chevron-left')}Zurück</button>` : '<span></span>'}
        ${step < SETUP_STEPS.length - 1
    ? `<button type="button" id="wz-next">Weiter${icon('chevron-right')}</button>`
    : `<button type="button" id="wz-finish">${icon('check')}Einrichtung abschließen</button>`}
      </footer></div>`;
  $('#wz-skip-all').addEventListener('click', () => attempt(() => finishSetup(), 'Assistent beendet – erneut starten unter Netzwerke'));
  if ($('#wz-back')) $('#wz-back').addEventListener('click', () => go(step - 1));
  if ($('#wz-next')) $('#wz-next').addEventListener('click', () => go(step + 1));
  if ($('#wz-finish')) $('#wz-finish').addEventListener('click', () => attempt(() => finishSetup(), 'Einrichtung abgeschlossen'));
  const body = $('#wz-body');
  const steps = [setupNetworks, setupRouter, setupCredentials, setupNotify, setupSummary];
  await steps[step](body, () => go(step + 1));
}

// ---------------------------------------------------------------------------
// 1. Netz kennenlernen
// ---------------------------------------------------------------------------

async function setupNetworks(body) {
  const [detect, networks] = await Promise.all([api('/networks/detect'), api('/networks')]);
  const fresh = detect.networks.filter((n) => !n.exists);
  body.innerHTML = `
    <p>NetPulse schaut nach, in welchen Netzen es selbst hängt und welcher Router dort das Gateway ist – egal ob FRITZ!Box,
      Speedport, UniFi oder Firewall. Gefundene Netze werden nach Geräten durchsucht.</p>
    <div class="notice">${icon('shield-lock')}<span>Nur eigene oder ausdrücklich freigegebene Netze durchsuchen.</span></div>
    ${detect.networks.length ? `<div class="table-wrap"><table><thead><tr><th></th><th>Netz</th><th>Schnittstelle</th><th>Router (Gateway)</th></tr></thead>
      <tbody>${detect.networks.map((n, i) => `<tr>
        <td><input type="checkbox" data-net="${i}"${n.exists ? ' checked disabled' : ' checked'} aria-label="${esc(n.cidr)} übernehmen"></td>
        <td><div class="mono">${esc(n.cidr)}</div><div class="muted small">eigene Adresse ${esc(n.address)}${n.narrowed ? ' · größeres Netz, auf /24 begrenzt' : ''}${n.exists ? ' · bereits eingetragen' : ''}</div></td>
        <td class="small">${esc(n.interface)}</td><td class="mono small">${esc(n.gateway || '–')}</td></tr>`).join('')}</tbody></table></div>`
    : empty('Kein Netz erkannt. Läuft NetPulse mit network_mode: host? Sonst unten von Hand eintragen.', 'search')}
    <form class="form-row wz-manual" id="wz-net-form">
      <label>Weiteres Netz (optional)<input name="cidr" placeholder="z. B. 10.0.20.0/24"></label>
      <label>Name<input name="name" placeholder="z. B. IoT-VLAN" maxlength="100"></label>
      <button type="submit" class="ghost">${icon('plus')}Hinzufügen</button>
    </form>
    <div class="actions">${fresh.length ? `<button type="button" id="wz-take">${icon('radar')}Ausgewählte übernehmen &amp; scannen</button>` : ''}
      ${networks.length ? `<button type="button" class="ghost" id="wz-rescan">${icon('refresh')}Jetzt scannen</button>` : ''}</div>
    <div id="wz-scan"></div>
    <p class="hint">Netze in anderen Standorten (Filialen, abgeschottete Netze) sucht eine Probe vor Ort ab – einzurichten unter Netzwerke → Probes.</p>`;

  const showScan = async () => {
    if (!$('#wz-scan')) return;
    const [scan, summary] = await Promise.all([api('/scan/status'), api('/summary')]);
    const box = $('#wz-scan');
    if (!box) return;
    box.innerHTML = scan.running ? scanBanner(scan)
      : `<div class="notice ok">${icon('circle-check')}<span>${summary.devices.total ? `${summary.devices.total} Geräte bekannt.`
          : networks.length ? 'Noch keine Geräte gefunden.' : 'Noch keine Geräte – zuerst ein Netz übernehmen.'}</span></div>`;
    applyWidths(box);
  };
  $$('#wz-take').forEach((b) => b.addEventListener('click', () => {
    const picked = $$('[data-net]:not(:disabled)', body).filter((c) => c.checked).map((c) => detect.networks[Number(c.dataset.net)]);
    if (!picked.length) { toast('Kein Netz ausgewählt', true); return; }
    attempt(async () => {
      for (const n of picked) {
        await api('/networks', { method: 'POST', body: { cidr: n.cidr, name: `Erkannt (${n.interface})`, site_id: detect.site_id, gateway: n.gateway || null } });
      }
      await setupNetworks(body);
    }, `${picked.length} ${picked.length === 1 ? 'Netz' : 'Netze'} übernommen – Scan läuft`);
  }));
  $$('#wz-rescan').forEach((b) => b.addEventListener('click', () => attempt(() => api('/scan', { method: 'POST' }), 'Scan gestartet')));
  $('#wz-net-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    if (!String(f.get('cidr')).trim()) return;
    attempt(async () => {
      await api('/networks', { method: 'POST', body: { cidr: f.get('cidr'), name: String(f.get('name')).trim() || 'Weiteres Netz' } });
      await setupNetworks(body);
    }, 'Netz hinzugefügt – Scan läuft');
  });
  await showScan();
  autoRefresh(showScan, 3);
}

// ---------------------------------------------------------------------------
// 2. Router erkennen
// ---------------------------------------------------------------------------

const familyOf = (setup, g) => setup.catalog.find((f) => f.key === setupFamilyChoice[`${g.site_id}/${g.ip}`]) || g.family;

function methodBadges(fam) {
  return fam.methods.length
    ? fam.methods.map((m, i) => `<span class="badge ${i === 0 ? 'accent' : 'plain'}">${esc((CRED_KINDS[m] || {}).label || m)}</span>`).join(' ')
    : '<span class="badge plain">nur Grundüberwachung</span>';
}

function routerName(g) {
  const d = g.device;
  if (!d) return g.ip;
  return d.name || d.hostname || d.vendor || g.ip;
}

async function setupRouter(body) {
  const setup = await api('/setup');
  const render = () => {
    body.innerHTML = `
      <p>Das Gateway eines Netzes ist sein Router – NetPulse erkennt das herstellerunabhängig und überwacht ihn ab sofort.
        Hier siehst du, um welchen Router es sich handelt und wie NetPulse ihn genauer abfragen kann. Stimmt die Erkennung nicht,
        wähle den richtigen Router aus der Liste.</p>
      ${setup.gateways.length ? setup.gateways.map((g) => {
    const fam = familyOf(setup, g);
    const key = `${g.site_id}/${g.ip}`;
    return `<section class="wz-router">
          <header><div><strong>${esc(routerName(g))}</strong> <span class="mono muted">${esc(g.ip)}</span>
            ${g.device ? `<span class="badge st-${esc(g.device.status || 'unknown')}">${esc(g.device.status === 'up' ? 'online' : g.device.status === 'down' ? 'offline' : 'unbekannt')}</span>` : '<span class="badge warn">noch nicht gefunden</span>'}
            ${setup.gateways.some((x) => x.site_id !== 1) ? `<span class="muted small"> · ${esc(g.site_name)}</span>` : ''}
            ${g.device && g.device.vendor ? `<div class="muted small">${esc(g.device.vendor)}${g.device.model ? ` · ${esc(g.device.model)}` : ''}</div>` : ''}</div>
          <label class="wz-family">Router<select data-family="${esc(key)}">${setup.catalog.map((f) => `<option value="${esc(f.key)}"${f.key === fam.key ? ' selected' : ''}>${esc(f.label)}</option>`).join('')}</select></label></header>
          <div class="wz-methods">${methodBadges(fam)}</div>
          <p class="small">${esc(fam.guide)}</p>
          ${g.credential_kinds.length ? `<div class="notice ok">${icon('circle-check')}<span>Bereits verbunden über ${esc(g.credential_kinds.map((k) => (CRED_KINDS[k] || {}).label || k).join(', '))}.</span></div>` : ''}
        </section>`;
  }).join('') : empty('Noch kein Router bekannt. Erst ein Netz übernehmen (Schritt 1) – das Gateway wird dabei automatisch erkannt.', 'router')}
      <p class="hint">Ohne Zugangsdaten überwacht NetPulse jeden Router trotzdem: Erreichbarkeit, Antwortzeit, Ausfälle und alle Geräte im Netz.</p>`;
    $$('[data-family]', body).forEach((sel) => sel.addEventListener('change', () => {
      setupFamilyChoice[sel.dataset.family] = sel.value;
      render();
    }));
  };
  render();
}

// ---------------------------------------------------------------------------
// 3. Zugangsdaten (optional)
// ---------------------------------------------------------------------------

async function setupCredentials(body) {
  if (!can('credentials.manage')) {
    body.innerHTML = empty('Zugangsdaten darf nur ein Benutzer mit dem Recht „Zugangsdaten verwalten“ anlegen – diesen Schritt einfach überspringen.', 'lock');
    return;
  }
  const setup = await api('/setup');
  const routers = setup.gateways.filter((g) => g.device);
  body.innerHTML = `
    <p>Optional: Mit einem Zugang liest NetPulse am Router mehr aus – je nach Router verbundene Geräte mit Namen, WLAN-Signal,
      Datenraten, Schnittstellen oder CPU-Last. Am besten ein eigenes Konto <b>nur mit Leserechten</b> anlegen.
      Die Daten werden verschlüsselt gespeichert und sofort getestet.</p>
    ${routers.length ? routers.map((g) => {
    const fam = familyOf(setup, g);
    const res = setupTestResult[g.device.id];
    return `<section class="wz-router">
        <header><div><strong>${esc(routerName(g))}</strong> <span class="mono muted">${esc(g.ip)}</span>
          <div class="muted small">${esc(fam.label)}</div></div></header>
        ${g.credential_kinds.length ? `<div class="notice ok">${icon('circle-check')}<span>Verbunden über ${esc(g.credential_kinds.map((k) => (CRED_KINDS[k] || {}).label || k).join(', '))}.</span></div>`
    : fam.methods.length ? `<div class="actions">${fam.methods.map((m, i) => `<button type="button" class="${i === 0 ? '' : 'ghost '}sm" data-connect="${g.device.id}" data-kind="${esc(m)}" data-label="${esc(fam.label)}">
              ${icon((CRED_KINDS[m] || {}).icon || 'key', 'i-sm')}${esc((CRED_KINDS[m] || {}).label || m)}</button>`).join('')}</div>
            <p class="small muted">${esc(fam.guide)}</p>`
      : `<p class="small muted">${esc(fam.guide)}</p>`}
        ${res ? `<div class="notice ${res.ok ? 'ok' : ''}">${icon(res.ok ? 'circle-check' : 'alert-triangle')}<span>${esc(res.message)}</span>
            ${res.ok || !res.credId ? '' : `<button type="button" class="ghost sm" data-discard="${res.credId}" data-dev="${g.device.id}">Verwerfen</button>`}</div>` : ''}
      </section>`;
  }).join('') : empty('Noch kein Router gefunden – Scan aus Schritt 1 abwarten.', 'router')}
    <p class="hint">Weitere Geräte (NAS, Switches, Server, Drucker) lassen sich jederzeit unter <a href="#/credentials">Zugangsdaten</a> per SNMP oder SSH anbinden.</p>`;

  $$('[data-connect]', body).forEach((b) => b.addEventListener('click', () => {
    const deviceId = Number(b.dataset.connect);
    const g = routers.find((x) => x.device.id === deviceId);
    credDialog(null, {
      kind: b.dataset.kind,
      name: `${b.dataset.label} ${g.ip}`,
      onSaved: async (created) => {
        if (!created) return;
        let result;
        try {
          result = await api(`/credentials/${created.id}/test`, { method: 'POST', body: { device_id: deviceId } });
        } catch (e) {
          result = { ok: false, message: e.message };
        }
        if (result.ok) {
          await api(`/credentials/${created.id}/devices`, { method: 'PUT', body: { device_ids: [deviceId] } });
          await api(`/devices/${deviceId}/poll`, { method: 'POST' }).catch(() => {});
        }
        setupTestResult[deviceId] = { ok: result.ok, message: result.ok ? `Verbindung klappt: ${result.message}` : `Anmeldung fehlgeschlagen: ${result.message}`, credId: created.id };
        await setupCredentials(body);
      },
    });
  }));
  $$('[data-discard]', body).forEach((b) => b.addEventListener('click', () => attempt(async () => {
    await api(`/credentials/${b.dataset.discard}`, { method: 'DELETE' });
    delete setupTestResult[Number(b.dataset.dev)];
    await setupCredentials(body);
  }, 'Zugangsdaten verworfen')));
}

// ---------------------------------------------------------------------------
// 4. Benachrichtigung (optional)
// ---------------------------------------------------------------------------

async function setupNotify(body) {
  if (!can('alerts.manage')) {
    body.innerHTML = empty('Benachrichtigungen darf nur ein Benutzer mit dem Recht „Alarme verwalten“ einrichten – diesen Schritt einfach überspringen.', 'lock');
    return;
  }
  const channels = await api('/channels');
  body.innerHTML = `
    <p>Optional: Wohin soll NetPulse melden, wenn ein Gerät ausfällt? Am einfachsten ist <b>ntfy</b> (kostenlose Push-App für Handy
      und PC), außerdem E-Mail, Telegram, Discord, Teams, Gotify oder ein Webhook.</p>
    ${channels.length ? `<div class="table-wrap"><table><tbody>${channels.map((c) => `<tr>
      <td>${icon((CHANNEL_KINDS[c.kind] || {}).icon || 'send', 'i-sm')} ${esc(c.name)}</td>
      <td class="small">${esc((CHANNEL_KINDS[c.kind] || {}).label || c.kind)}</td>
      <td class="small">${channelStatus(c)}</td>
      <td class="actions"><button type="button" class="ghost sm" data-test="${c.id}">${icon('player-play', 'i-sm')}Testnachricht</button></td></tr>`).join('')}</tbody></table></div>`
    : empty('Noch kein Kanal eingerichtet.', 'send')}
    <div class="actions"><button type="button" id="wz-ch-add">${icon('plus')}Kanal einrichten</button></div>
    <p class="hint">Wann gemeldet wird (z. B. erst nach 5 Minuten offline, nur kritische Geräte), legst du später unter
      <a href="#/alerts?tab=rules">Alarme → Regeln</a> fest.</p>`;
  $('#wz-ch-add').addEventListener('click', () => channelDialog(null, async (saved) => {
    await setupNotify(body);
    if (saved && saved.id) {
      await attempt(() => api(`/channels/${saved.id}/test`, { method: 'POST' }), 'Testnachricht gesendet – ist sie angekommen?');
      await setupNotify(body);
    }
  }));
  $$('[data-test]', body).forEach((b) => b.addEventListener('click', () => {
    b.disabled = true;
    attempt(() => api(`/channels/${b.dataset.test}/test`, { method: 'POST' }), 'Testnachricht gesendet')
      .finally(() => setupNotify(body));
  }));
}

// ---------------------------------------------------------------------------
// 5. Übersicht
// ---------------------------------------------------------------------------

async function setupSummary(body) {
  const [setup, devices] = await Promise.all([api('/setup'), api('/devices')]);
  const byType = {};
  devices.forEach((d) => { byType[d.device_type] = (byType[d.device_type] || 0) + 1; });
  const types = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  const c = setup.counts;
  const tile = (n, label, href) => `<a class="wz-tile" href="${href}"><b>${esc(n)}</b><span>${esc(label)}</span></a>`;
  body.innerHTML = `
    <p>Geschafft – NetPulse überwacht dein Netz jetzt laufend. Alles hier lässt sich später ändern; den Assistenten
      startest du jederzeit erneut unter <a href="#/networks">Netzwerke</a>.</p>
    <div class="wz-tiles">${tile(c.networks, c.networks === 1 ? 'Netz' : 'Netze', '#/networks')}${tile(c.devices, 'Geräte', '#/devices')}
      ${tile(setup.gateways.length, setup.gateways.length === 1 ? 'Router' : 'Router', '#/devices?type=router')}
      ${tile(c.credentials, 'Zugangsdaten', '#/credentials')}${tile(c.channels, c.channels === 1 ? 'Benachrichtigungskanal' : 'Benachrichtigungskanäle', '#/channels')}</div>
    ${types.length ? `<h3 class="sub">Gefundene Geräte</h3><div class="wz-types">${types.map(([t, n]) => `<a class="badge plain" href="#/devices?type=${encodeURIComponent(t)}">${icon(typeInfo(t).icon, 'i-sm')}${esc(typeInfo(t).label)} · ${n}</a>`).join('')}</div>` : ''}
    ${c.channels ? '' : `<div class="notice">${icon('bell')}<span>Noch kein Benachrichtigungskanal – Ausfälle siehst du dann nur in NetPulse selbst.</span></div>`}
    ${c.devices ? '' : `<div class="notice">${icon('radar')}<span>Noch keine Geräte – läuft der Scan noch? Fortschritt siehst du links unten.</span></div>`}`;
}
