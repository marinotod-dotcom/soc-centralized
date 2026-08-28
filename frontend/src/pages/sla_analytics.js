import '../shared/theme.css';
import { highlightActiveNav } from '../shared/nav.js';
import { fetchJson } from '../shared/api.js';
import { fmtDateShort, renderError } from '../shared/dom.js';

const SEV_COLOR = { Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)' };
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low'];

async function loadDashboard() {
  try {
    const data = await fetchJson('/api/sla/dashboard');
    renderStats(data);
    renderSeverityChart(data.by_severity);
    renderMachinesDonut(data.machines_corrected, data.machines_total);
    renderTrend(data.validated_per_day);
    document.getElementById('subtitle').textContent =
      `Batch détecté du ${fmtDateShort(data.batch_week_start)} au ${fmtDateShort(data.batch_week_end)} · ` +
      `${data.total_validated} / ${data.total_cve} CVE validés (${data.pct_validated}%) · traitement en cours cette semaine`;
  } catch (err) {
    renderError(document.getElementById('stats'), err.message);
    document.getElementById('sevChart').innerHTML = '';
    document.getElementById('machinesChart').innerHTML = '';
    document.getElementById('trendChart').innerHTML = '';
  }
}

function renderStats(d) {
  document.getElementById('stats').innerHTML = `
    <div class="stat n-ok"><div class="n">${d.total_validated}</div><div class="l">CVE validés</div></div>
    <div class="stat n-accent"><div class="n">${d.pct_validated}%</div><div class="l">Taux de validation</div></div>
    <div class="stat"><div class="n">${d.total_cve}</div><div class="l">CVE suivis (total)</div></div>
    <div class="stat"><div class="n">${d.machines_corrected}/${d.machines_total}</div><div class="l">Machines corrigées</div></div>
  `;
}

function renderSeverityChart(bySeverity) {
  const bySeverityMap = Object.fromEntries(bySeverity.map((s) => [s.severity, s]));
  const maxTotal = Math.max(1, ...bySeverity.map((s) => s.total));
  const html = SEV_ORDER.filter((sev) => bySeverityMap[sev])
    .map((sev) => {
      const s = bySeverityMap[sev];
      const widthPct = (s.total / maxTotal) * 100;
      const validatedPct = s.total ? (s.validated / s.total) * 100 : 0;
      return `
        <div class="sev-row">
          <div class="sev-label" style="color:${SEV_COLOR[sev]}">${sev}</div>
          <div class="sev-bar-track" style="width:${widthPct}%">
            <div class="sev-bar-fill" style="width:${validatedPct}%;background:${SEV_COLOR[sev]}"></div>
          </div>
          <div class="sev-count"><b>${s.validated}</b> / ${s.total}</div>
        </div>`;
    })
    .join('');
  document.getElementById('sevChart').innerHTML = html || '<div class="load-msg">Aucune donnée.</div>';
}

function renderMachinesDonut(corrected, total) {
  const pct = total ? Math.round((corrected / total) * 100) : 0;
  const r = 52;
  const circumference = 2 * Math.PI * r;
  const dash = (pct / 100) * circumference;
  document.getElementById('machinesChart').innerHTML = `
    <div class="donut-wrap">
      <svg width="130" height="130" viewBox="0 0 130 130">
        <circle cx="65" cy="65" r="${r}" fill="none" stroke="#0b0d12" stroke-width="14"/>
        <circle cx="65" cy="65" r="${r}" fill="none" stroke="var(--ok)" stroke-width="14"
                stroke-dasharray="${dash} ${circumference}" stroke-linecap="round"
                transform="rotate(-90 65 65)"/>
        <text x="65" y="60" text-anchor="middle" font-size="22" font-weight="700" fill="var(--text)">${pct}%</text>
        <text x="65" y="78" text-anchor="middle" font-size="11" fill="var(--muted)">corrigées</text>
      </svg>
      <div class="donut-legend">
        <span class="n">${corrected} / ${total}</span>
        <span class="l">machines avec au moins un CVE validé</span>
      </div>
    </div>`;
}

function renderTrend(days) {
  const maxCount = Math.max(1, ...days.map((d) => d.count));
  const html = days
    .map((d) => {
      const heightPct = (d.count / maxCount) * 100;
      const label = new Date(d.day).toLocaleDateString('fr-FR', { weekday: 'short', day: 'numeric' });
      return `
        <div class="trend-col">
          <div class="trend-value">${d.count}</div>
          <div class="trend-bar-track"><div class="trend-bar-fill" style="height:${heightPct}%"></div></div>
          <div class="trend-day">${label}</div>
        </div>`;
    })
    .join('');
  document.getElementById('trendChart').innerHTML = `<div class="trend-bars">${html}</div>`;
}

highlightActiveNav();
loadDashboard();
