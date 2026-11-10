'use strict';
/* Öffentliche Statusseite: zeigt nur die freigegebenen Einträge (Link: /status.html#<geheimer Schlüssel>).
 * Der Schlüssel bleibt im Fragment (#) und geht nur als Header an den Server – nie in Adressen oder Logs. */

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const $ = (s) => document.querySelector(s);
const icon = (name, cls = '') => `<svg class="i ${cls}"><use href="icons.svg?v=0.9.17#i-${name}"/></svg>`;

const LABEL = { ok: 'Funktioniert', degraded: 'Eingeschränkt', down: 'Störung', unknown: 'Unbekannt' };
const OVERALL = {
  ok: ['circle-check', 'Alle Systeme funktionieren'],
  degraded: ['alert-triangle', 'Einige Systeme sind eingeschränkt'],
  down: ['circle-x', 'Es liegt eine Störung vor'],
  unknown: ['help-circle', 'Status unbekannt'],
};

function fmtBps(b) {
  if (b == null) return '–';
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'];
  let v = b;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i += 1; }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}
const fmtMs = (v) => (v == null ? '–' : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`);

function days(list) {
  const cells = (list || []).map((v, i) => {
    const date = new Date(Date.now() - (29 - i) * 86400000).toLocaleDateString('de-DE');
    const cls = v == null ? '' : v >= 99.9 ? 'ok' : v >= 95 ? 'warn' : 'bad';
    return `<i class="${cls}" title="${esc(date)}: ${v == null ? 'keine Daten' : `${esc(v)} % verfügbar`}"></i>`;
  });
  return `<div class="beats days">${cells.join('')}</div><div class="days-legend muted small"><span>vor 30 Tagen</span><span>heute</span></div>`;
}

/** Kleines Liniendiagramm (nur SVG-Attribute – passt zur Content-Security-Policy) */
function chart(series, format) {
  const W = 320;
  const H = 90;
  const all = series.flatMap((s) => s.values).filter((v) => v != null);
  if (!all.length) return '<p class="muted small">Noch keine Messwerte.</p>';
  const max = Math.max(...all) * 1.15 || 1;
  const n = Math.max(...series.map((s) => s.values.length)) - 1 || 1;
  const x = (i) => (i / n) * W;
  const y = (v) => H - 4 - (v / max) * (H - 10);
  const paths = series.map((s, si) => {
    let d = '';
    let pen = false;
    s.values.forEach((v, i) => {
      if (v == null) { pen = false; return; }
      d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)} `;
      pen = true;
    });
    return `<path class="line c${si}" d="${d}"/>`;
  }).join('');
  return `<svg class="st-chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img">
      <line class="grid-line" x1="0" x2="${W}" y1="${y(max / 1.15 / 2).toFixed(1)}" y2="${y(max / 1.15 / 2).toFixed(1)}"/>${paths}</svg>
    <div class="st-axis muted small"><span>vor 24 h</span><span>max. ${esc(format(max / 1.15))}</span><span>jetzt</span></div>`;
}

function details(d, item) {
  if (!d) return '';
  const traffic = d.rx.some((v) => v != null) || d.tx.some((v) => v != null);
  return `<div class="st-details">
      <div class="st-panel"><div class="st-panel-head"><span>${icon('activity', 'i-sm')} Antwortzeit</span><strong>${esc(fmtMs(item.latency_ms))}</strong></div>
        ${chart([{ values: d.rtt }], fmtMs)}</div>
      ${traffic ? `<div class="st-panel"><div class="st-panel-head"><span>${icon(d.traffic_label === 'Internet' ? 'world-www' : 'arrows-exchange', 'i-sm')} ${esc(d.traffic_label)}</span>
        <strong>${d.live ? '<span class="st-live-dot" title="live"></span>' : ''}↓ ${esc(fmtBps(d.rx_now))} · ↑ ${esc(fmtBps(d.tx_now))}</strong></div>
        ${chart([{ values: d.rx }, { values: d.tx }], fmtBps)}
        <div class="legend small"><span><i class="bgc0"></i>Download</span><span><i class="bgc1"></i>Upload</span></div></div>` : ''}
    </div>`;
}

function itemHtml(i) {
  const dot = i.status === 'ok' ? 'up' : i.status === 'degraded' ? 'warn' : i.status;
  return `<article class="status-item st-${esc(i.status)}">
      <div class="status-line"><span class="check-dot st-${esc(dot)}"></span>
        <strong class="status-name">${esc(i.name)}</strong>
        <span class="status-label ${esc(i.status)}">${esc(LABEL[i.status] || '')}</span>
        <span class="status-uptime">${i.uptime_30d != null ? `<b>${esc(i.uptime_30d)} %</b> <span class="muted small">30 Tage</span>` : ''}</span></div>
      ${days(i.days)}
      ${details(i.details, i)}
    </article>`;
}

let lastOk = 0;

async function load() {
  const token = location.hash.slice(1);
  try {
    if (!token) throw new Error('Diese Statusseite gibt es nicht (mehr).');
    const res = await fetch('/api/public/status', { headers: { Accept: 'application/json', 'X-Status-Token': token }, cache: 'no-store' });
    if (!res.ok) throw new Error('Diese Statusseite gibt es nicht (mehr).');
    const s = await res.json();
    document.title = s.title || 'Status';
    $('#st-title').textContent = s.title || 'Status';
    $('#st-desc').textContent = s.description || '';
    const [ic, text] = OVERALL[s.overall] || OVERALL.unknown;
    const overall = $('#st-overall');
    overall.className = `status-overall ${s.overall}`;
    overall.innerHTML = `${icon(ic)}<div><strong>${esc(text)}</strong>
      <div class="small">${s.items.filter((i) => i.status === 'ok').length} von ${s.items.length} Einträgen ohne Probleme</div></div>`;
    // Nach Abschnitten gruppieren (Reihenfolge wie eingestellt)
    const groups = [];
    s.items.forEach((i) => {
      const key = i.group || '';
      let g = groups.find((x) => x.key === key);
      if (!g) { g = { key, items: [] }; groups.push(g); }
      g.items.push(i);
    });
    $('#st-items').innerHTML = s.items.length ? groups.map((g) => `<section class="status-group">
        ${g.key ? `<h2>${esc(g.key)}</h2>` : ''}<div class="card">${g.items.map(itemHtml).join('')}</div></section>`).join('')
      : '<div class="card"><p class="muted">Keine Einträge.</p></div>';
    $('#st-updated').textContent = new Date(s.updated).toLocaleString('de-DE');
    lastOk = Date.now();
    $('#st-live').classList.remove('off');
  } catch (e) {
    // Kurzer Aussetzer (z. B. WLAN): alte Anzeige stehen lassen, nur markieren
    if (lastOk && Date.now() - lastOk < 5 * 60000) {
      $('#st-live').classList.add('off');
      return;
    }
    $('#st-overall').className = 'status-overall unknown';
    $('#st-overall').textContent = e.message;
    $('#st-items').innerHTML = '';
  }
}

/** „aktualisiert vor X s“ – zeigt, dass die Seite lebt */
function tick() {
  const el = $('#st-age');
  if (!lastOk) return;
  const s = Math.round((Date.now() - lastOk) / 1000);
  el.textContent = s < 5 ? 'gerade eben' : `vor ${s} s`;
}

load();
setInterval(() => { if (!document.hidden) load(); }, 15000);
setInterval(tick, 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
window.addEventListener('hashchange', load);
