'use strict';
/* Energie-Auswertung: Verbrauch, PV-Ertrag, Netzbezug, Einspeisung, Eigenverbrauch und Kosten je Tag/Monat/Jahr */

const MONTHS = ['Januar', 'Februar', 'März', 'April', 'Mai', 'Juni', 'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember'];
const MONTHS_SHORT = ['Jan', 'Feb', 'Mär', 'Apr', 'Mai', 'Jun', 'Jul', 'Aug', 'Sep', 'Okt', 'Nov', 'Dez'];
const ROLE_LABEL = { consumer: 'Verbrauch', producer: 'Erzeugung', grid: 'Netz' };

function enKwh(v) {
  if (v == null) return '–';
  const digits = v < 10 ? 2 : v < 100 ? 1 : 0;
  return `${v.toLocaleString('de-DE', { minimumFractionDigits: digits, maximumFractionDigits: digits })} kWh`;
}
const enEuro = (v) => (v == null ? '–' : v.toLocaleString('de-DE', { style: 'currency', currency: 'EUR' }));
const enPct = (v) => (v == null ? '–' : `${Math.round(v * 100)} %`);

/** Datum „2026-09-01“ → Date (lokal, ohne Zeitzonen-Verschiebung) */
const parseDay = (s) => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };

function periodLabel(r) {
  const from = parseDay(r.from);
  if (r.range === 'month') return `${MONTHS[from.getMonth()]} ${from.getFullYear()}`;
  if (r.range === 'year') return String(from.getFullYear());
  return 'Alle Jahre';
}

function bucketLabel(r, start, short = true) {
  const d = parseDay(start);
  if (r.unit === 'day') return short ? String(d.getDate()) : d.toLocaleDateString('de-DE', { weekday: 'short', day: 'numeric', month: 'long' });
  if (r.unit === 'month') return short ? MONTHS_SHORT[d.getMonth()] : `${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
  return String(d.getFullYear());
}

/** Nachbar-Zeitraum für die Pfeile */
function shiftPeriod(r, dir) {
  const d = parseDay(r.from);
  if (r.range === 'month') {
    const n = new Date(d.getFullYear(), d.getMonth() + dir, 1);
    return `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, '0')}`;
  }
  return String(d.getFullYear() + dir);
}

/**
 * Gestapeltes Balkendiagramm (SVG, nur Attribute – passt zur Content-Security-Policy).
 * series: [{ key, label, cls, value: (figures) => number|null }]
 */
function stackedBars(r, series, id) {
  // Breite passend zum Bildschirm, damit die Achsenschrift nicht mitschrumpft
  const W = Math.round(Math.max(300, Math.min(1200, (view().clientWidth || 720) - 70)));
  const H = W < 500 ? 180 : 220;
  const pad = { l: 40, r: 6, t: 10, b: 24 };
  const buckets = r.buckets;
  const totals = buckets.map((b) => series.reduce((a, s) => a + (s.value(b.figures) || 0), 0));
  const rawMax = Math.max(0, ...totals);
  if (!rawMax) return `<div class="empty small">Für diesen Zeitraum liegen noch keine Messwerte vor.</div>`;
  // „Schöne“ Achsenschritte
  const step = [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000].find((s) => rawMax / s <= 4) || 10000;
  const max = Math.ceil(rawMax / step) * step;
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;
  const slot = iw / buckets.length;
  const bw = Math.max(2, Math.min(36, slot * 0.7));
  const y = (v) => pad.t + ih - (v / max) * ih;
  let grid = '';
  for (let v = 0; v <= max + 1e-9; v += step) {
    grid += `<line class="en-grid-line" x1="${pad.l}" x2="${W - pad.r}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}"/>
      <text class="en-axis" x="${pad.l - 6}" y="${(y(v) + 4).toFixed(1)}" text-anchor="end">${esc(v.toLocaleString('de-DE'))}</text>`;
  }
  // Beschriftung nur so dicht, dass sie sich nicht berührt
  const labelEvery = [1, 2, 5, 7, 10].find((n) => slot * n >= 28) || 10;
  let bars = '';
  buckets.forEach((b, i) => {
    const x = pad.l + i * slot + (slot - bw) / 2;
    let base = 0;
    const parts = series.map((s) => ({ s, v: s.value(b.figures) || 0 })).filter((p) => p.v > 0);
    parts.forEach((p, pi) => {
      const top = y(base + p.v);
      const bottom = y(base);
      // 2px Abstand zwischen gestapelten Teilen, oberstes Teil mit runden Ecken
      const h = Math.max(1, bottom - top - (pi > 0 ? 2 : 0));
      const yy = top;
      const rr = pi === parts.length - 1 ? Math.min(4, bw / 2, h) : 0;
      const d = rr
        ? `M${x.toFixed(1)},${(yy + h).toFixed(1)} V${(yy + rr).toFixed(1)} Q${x.toFixed(1)},${yy.toFixed(1)} ${(x + rr).toFixed(1)},${yy.toFixed(1)} H${(x + bw - rr).toFixed(1)} Q${(x + bw).toFixed(1)},${yy.toFixed(1)} ${(x + bw).toFixed(1)},${(yy + rr).toFixed(1)} V${(yy + h).toFixed(1)} Z`
        : `M${x.toFixed(1)},${(yy + h).toFixed(1)} V${yy.toFixed(1)} H${(x + bw).toFixed(1)} V${(yy + h).toFixed(1)} Z`;
      bars += `<path class="${p.s.cls}" d="${d}"/>`;
      base += p.v;
    });
    // Unsichtbare, breitere Trefferfläche für den Tooltip
    bars += `<rect class="en-hit" data-i="${i}" x="${(pad.l + i * slot).toFixed(1)}" y="${pad.t}" width="${slot.toFixed(1)}" height="${ih}"/>`;
    if (i % labelEvery === 0) {
      bars += `<text class="en-axis" x="${(x + bw / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">${esc(bucketLabel(r, b.start))}</text>`;
    }
  });
  const legend = series.length > 1
    ? `<div class="legend small">${series.map((s) => `<span><i class="sw ${s.cls}"></i>${esc(s.label)}</span>`).join('')}</div>` : '';
  return `${legend}<div class="en-chart" id="${id}"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Balkendiagramm in kWh">
      ${grid}${bars}</svg><div class="en-tip" hidden></div></div>`;
}

/** Tooltip je Balken */
function bindTooltip(r, series, id) {
  const box = document.getElementById(id);
  if (!box) return;
  const tip = box.querySelector('.en-tip');
  box.addEventListener('mousemove', (ev) => {
    const hit = ev.target.closest('.en-hit');
    if (!hit) { tip.hidden = true; return; }
    const b = r.buckets[Number(hit.dataset.i)];
    const rows = series.map((s) => `<div><i class="sw ${s.cls}"></i>${esc(s.label)}<b>${esc(enKwh(s.value(b.figures)))}</b></div>`).join('');
    tip.innerHTML = `<strong>${esc(bucketLabel(r, b.start, false))}</strong>${b.has_data ? rows : '<div class="muted">keine Messwerte</div>'}`;
    tip.hidden = false;
    const rect = box.getBoundingClientRect();
    const left = Math.min(ev.clientX - rect.left + 12, rect.width - tip.offsetWidth - 4);
    tip.style.left = `${Math.max(0, left)}px`;
    tip.style.top = `${Math.max(0, ev.clientY - rect.top - tip.offsetHeight - 8)}px`;
  });
  box.addEventListener('mouseleave', () => { tip.hidden = true; });
}

function tile(iconName, label, value, sub = '', cls = '') {
  return `<div class="en-tile ${cls}"><span class="inet-dir">${icon(iconName, 'i-sm')} ${esc(label)}</span>
    <strong>${esc(value)}</strong>${sub ? `<span class="muted small">${sub}</span>` : ''}</div>`;
}

async function viewEnergy(_arg, params) {
  const range = ['month', 'year', 'all'].includes(params.get('range')) ? params.get('range') : 'month';
  const at = params.get('at') || '';
  const r = await api(`/energy?range=${range}${at ? `&at=${encodeURIComponent(at)}` : ''}`);
  const t = r.totals;
  const hasGrid = t.import != null;
  const hasProd = t.production != null;

  const consumptionSeries = hasGrid && hasProd
    ? [{ key: 'import', label: 'aus dem Netz', cls: 'en-c-grid', value: (f) => f.import },
      { key: 'self', label: 'aus eigener Erzeugung', cls: 'en-c-pv', value: (f) => f.self_use }]
    : [{ key: 'consumption', label: 'Verbrauch', cls: 'en-c-grid', value: (f) => f.consumption }];
  const productionSeries = hasGrid
    ? [{ key: 'self', label: 'selbst genutzt', cls: 'en-c-pv', value: (f) => f.self_use },
      { key: 'export', label: 'eingespeist', cls: 'en-c-export', value: (f) => f.export }]
    : [{ key: 'production', label: 'Erzeugung', cls: 'en-c-pv', value: (f) => f.production }];

  const seg = (key, label) => `<a class="${range === key ? 'active' : ''}" href="#/energy?range=${key}">${label}</a>`;
  const canNav = range !== 'all';
  const isCurrent = range === 'month' ? r.from.slice(0, 7) === r.today.slice(0, 7) : r.from.slice(0, 4) === r.today.slice(0, 4);
  const cfgMissing = r.settings.main_id == null && !r.meters.some((m) => m.role === 'grid');
  const tiles = [
    tile('bolt', 'Verbrauch', enKwh(t.consumption)),
    hasProd ? tile('sun', 'PV-Ertrag', enKwh(t.production), '', 'prod') : '',
    hasGrid ? tile('arrow-down', 'Netzbezug', enKwh(t.import), t.cost != null ? `Kosten ${esc(enEuro(t.cost))}` : '') : '',
    hasGrid && hasProd ? tile('arrow-up', 'Einspeisung', enKwh(t.export)) : '',
    t.autarky != null ? tile('home-2', 'Autarkie', enPct(t.autarky), 'Anteil des Verbrauchs aus eigener Erzeugung') : '',
    t.self_use_rate != null ? tile('plug-connected', 'Eigenverbrauch', enPct(t.self_use_rate), 'Anteil der Erzeugung selbst genutzt') : '',
    t.savings != null ? tile('star', 'Ersparnis', enEuro(t.savings), 'durch eigenen Strom und Einspeisung', 'prod') : '',
  ].join('');
  const maxDev = Math.max(1e-9, ...r.devices.map((d) => d.kwh));

  view().innerHTML = `
    <div class="page-head">
      <div class="actions"><div class="seg seg-links">${seg('month', 'Monat')}${seg('year', 'Jahr')}${seg('all', 'Gesamt')}</div>
        ${canNav ? `<a class="icon-btn" href="#/energy?range=${range}&at=${shiftPeriod(r, -1)}" title="Zurück">${icon('chevron-left')}</a>` : ''}
        <strong class="en-period">${esc(periodLabel(r))}</strong>
        ${canNav && !isCurrent ? `<a class="icon-btn" href="#/energy?range=${range}&at=${shiftPeriod(r, 1)}" title="Weiter">${icon('chevron-right')}</a>` : ''}</div>
      <div class="actions">${r.first_day ? `<span class="muted small">Daten seit ${esc(parseDay(r.first_day).toLocaleDateString('de-DE'))}</span>` : ''}</div>
    </div>
    ${cfgMissing && r.meters.length ? `<div class="notice info">${icon('info-circle')}<span>Tipp: Unten einen <b>Hauptzähler</b> wählen –
      dann zeigt NetPulse auch Netzbezug, Einspeisung, Eigenverbrauch und Kosten.</span></div>` : ''}
    ${!r.meters.length ? `<div class="card">${empty('Noch keine Strommessungen – z. B. einen Shelly mit Leistungsmessung einbinden.', 'bolt')}</div>` : `
    <div class="en-tiles">${tiles}</div>
    <div class="grid">
      <section class="card span-3"><header><h2>${icon('bolt')}Verbrauch</h2><span class="muted small">in kWh</span></header>${stackedBars(r, consumptionSeries, 'en-chart-c')}</section>
      ${hasProd ? `<section class="card span-3"><header><h2>${icon('sun')}Erzeugung</h2><span class="muted small">in kWh</span></header>${stackedBars(r, productionSeries, 'en-chart-p')}</section>` : ''}
      <section class="card span-2"><header><h2>${icon('plug')}Geräte im Zeitraum</h2></header>
        ${r.devices.length ? `<div class="table-wrap"><table><thead><tr><th>Gerät</th><th>Rolle</th><th class="num">Energie</th><th></th></tr></thead><tbody>
          ${r.devices.map((d) => `<tr><td><a href="#/device/${d.id}">${esc(d.label)}</a></td>
            <td>${d.main ? '<span class="badge accent">Hauptzähler</span>' : `<span class="badge plain">${esc(ROLE_LABEL[d.role] || d.role)}</span>`}</td>
            <td class="num">${d.main || d.role === 'grid' ? `↓ ${esc(enKwh(d.pos_kwh))}<br><span class="muted small">↑ ${esc(enKwh(d.neg_kwh))}</span>` : esc(enKwh(d.kwh))}</td>
            <td class="en-bar-cell"><span class="bar${d.role === 'producer' ? ' prod' : ''}" data-w="${Math.round((d.kwh / maxDev) * 100)}"></span></td></tr>`).join('')}
          </tbody></table></div>` : '<p class="muted">Keine Messwerte in diesem Zeitraum.</p>'}</section>
      <section class="card span-1"><header><h2>${icon('settings')}Einstellungen</h2></header><div id="en-settings"></div></section>
      <section class="card span-3"><details><summary>Werte als Tabelle</summary><div class="table-wrap"><table>
        <thead><tr><th>Zeitraum</th><th class="num">Verbrauch</th>${hasProd ? '<th class="num">Erzeugung</th>' : ''}${hasGrid ? '<th class="num">Bezug</th><th class="num">Einspeisung</th>' : ''}${t.cost != null ? '<th class="num">Kosten</th>' : ''}</tr></thead>
        <tbody>${r.buckets.filter((b) => b.has_data).map((b) => `<tr><td>${esc(bucketLabel(r, b.start, false))}</td><td class="num">${esc(enKwh(b.figures.consumption))}</td>
          ${hasProd ? `<td class="num">${esc(enKwh(b.figures.production))}</td>` : ''}
          ${hasGrid ? `<td class="num">${esc(enKwh(b.figures.import))}</td><td class="num">${esc(enKwh(b.figures.export))}</td>` : ''}
          ${t.cost != null ? `<td class="num">${esc(enEuro(b.figures.cost))}</td>` : ''}</tr>`).join('')}</tbody></table></div></details></section>
    </div>`}`;
  applyWidths(view());
  bindTooltip(r, consumptionSeries, 'en-chart-c');
  if (hasProd) bindTooltip(r, productionSeries, 'en-chart-p');
  if (r.meters.length) renderEnergySettings(r);
  autoRefresh(async () => { if (isCurrent || range === 'all') await route(); }, 600);
}

function renderEnergySettings(r) {
  const s = r.settings;
  const dis = can('settings.manage') ? '' : ' disabled';
  $('#en-settings').innerHTML = `<form class="form" id="en-form">
      <label>Hauptzähler (Hausanschluss)<select name="main_id"${dis}><option value="">– keiner –</option>
        ${r.meters.map((m) => `<option value="${m.id}"${m.id === s.main_id ? ' selected' : ''}>${esc(m.label)}</option>`).join('')}</select></label>
      <fieldset><legend>Was misst der Hauptzähler?</legend><div class="checks">
        <label class="inline"><input type="radio" name="mode" value="net"${s.main_mode !== 'gross' ? ' checked' : ''}${dis}> Saldierend: + Bezug, − Einspeisung</label>
        <label class="inline"><input type="radio" name="mode" value="gross"${s.main_mode === 'gross' ? ' checked' : ''}${dis}> Gesamtverbrauch des Hauses</label></div></fieldset>
      <div class="form-row"><label>Strompreis (ct/kWh)<input name="price" type="number" step="0.01" min="0" max="500" value="${esc(s.price_ct ?? '')}" placeholder="z. B. 32,5"${dis}></label>
        <label>Einspeisung (ct/kWh)<input name="feed" type="number" step="0.01" min="0" max="500" value="${esc(s.feed_in_ct ?? '')}" placeholder="z. B. 8,1"${dis}></label></div>
      ${can('settings.manage') ? `<button type="submit">${icon('check')}Speichern</button>` : '<p class="hint">Ändern braucht das Recht „Einstellungen verwalten“.</p>'}
      <p class="hint">Rollen der Geräte (Verbrauch/Erzeugung/Netz) stellst du beim Gerät unter „Einstellungen“ ein.</p></form>`;
  if (!can('settings.manage')) return;
  $('#en-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = ev.target.elements;
    const num = (v) => (v.trim() === '' ? null : Number(v.replace(',', '.')));
    attempt(async () => {
      await api('/energy/settings', { method: 'PUT', body: { main_id: e.main_id.value ? Number(e.main_id.value) : null, main_mode: e.mode.value, price_ct: num(e.price.value), feed_in_ct: num(e.feed.value) } });
      await route();
    }, 'Gespeichert');
  });
}
