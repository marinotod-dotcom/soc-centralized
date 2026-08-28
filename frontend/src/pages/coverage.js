import '../shared/theme.css';
import { highlightActiveNav } from '../shared/nav.js';
import { escapeHtml } from '../shared/dom.js';

const SEVERITY_COLOR = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', unknown: 'var(--unknown)' };
const SEVERITY_LABEL = { critical: 'Jamais connecté', high: 'Inactif > 90j', medium: 'Inactif 60–90j', low: 'Inactif 30–60j', unknown: 'Inactif < 30j' };
const SEVERITY_WEIGHT = { critical: 100, high: 70, medium: 40, low: 15, unknown: 0 };
const NEVER_CONNECTED_SENTINEL_YEAR = 9999;

let allAgents = [];
let currentSort = 'score';

async function loadData() {
  document.getElementById('subtitle').textContent = 'Chargement de data.json…';
  try {
    const res = await fetch('data.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const json = await res.json();
    const agents = json?.agents;
    if (!agents) throw new Error('Structure inattendue : agents introuvable');

    allAgents = enrichAgents(agents);
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('table').style.display = '';
    populateFilterOptions();
    renderStats(json.meta);
    renderGrouped();
    sortAndRender();
  } catch (err) {
    document.getElementById('emptyReason').textContent = err.message;
    document.getElementById('emptyState').style.display = 'block';
    document.getElementById('table').style.display = 'none';
    document.getElementById('subtitle').textContent = 'data.json introuvable ou invalide';
  }
}

// ---------------------------------------------------------------
// Transform: raw Wazuh agent records -> rows with computed fields
// ---------------------------------------------------------------
function enrichAgents(agents) {
  const now = new Date();
  return agents.map((a) => {
    const lastKeepAlive = a.lastKeepAlive || null;
    const neverConnected = !lastKeepAlive || new Date(lastKeepAlive).getFullYear() >= NEVER_CONNECTED_SENTINEL_YEAR;
    const daysInactive = neverConnected || !lastKeepAlive ? null : Math.floor((now - new Date(lastKeepAlive)) / 86400000);

    let sevKey;
    if (neverConnected) sevKey = 'critical';
    else if (daysInactive >= 90) sevKey = 'high';
    else if (daysInactive >= 60) sevKey = 'medium';
    else if (daysInactive >= 30) sevKey = 'low';
    else sevKey = 'unknown';

    const groups = Array.isArray(a.group) ? a.group : a.group ? [a.group] : [];
    const os = a.os?.platform || a.os?.name || '—';

    return {
      id: a.id ?? '—',
      name: a.name || '—',
      ip: a.ip || '—',
      os,
      groups,
      dateAdd: a.dateAdd || null,
      lastKeepAlive,
      neverConnected,
      daysInactive,
      sevKey,
      score: (SEVERITY_WEIGHT[sevKey] ?? 0) + Math.min(daysInactive ?? 0, 365) / 10,
    };
  });
}

function actionLabel(a) {
  if (a.neverConnected) return { label: "Vérifier le déploiement de l'agent", muted: false };
  if (a.daysInactive >= 90) return { label: 'Investiguer / envisager la désinscription', muted: false };
  if (a.daysInactive >= 30) return { label: 'Surveiller la reconnexion', muted: true };
  return { label: 'Sous seuil', muted: true };
}

// ---------------------------------------------------------------
// Grouped-by-Wazuh-group detection
// ---------------------------------------------------------------
function computeGroupedAgents(list) {
  const byGroup = new Map();
  for (const a of list) {
    const groups = a.groups.length ? a.groups : ['(sans groupe)'];
    groups.forEach((g) => {
      if (!byGroup.has(g)) byGroup.set(g, []);
      byGroup.get(g).push(a);
    });
  }
  return Array.from(byGroup.entries())
    .filter(([, agentsInGroup]) => agentsInGroup.length > 1)
    .map(([group, agentsInGroup]) => ({
      group,
      agents: agentsInGroup,
      neverConnectedCount: agentsInGroup.filter((a) => a.neverConnected).length,
    }))
    .sort((a, b) => b.agents.length - a.agents.length);
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------
function renderStats(meta) {
  const neverConnected = allAgents.filter((a) => a.neverConnected).length;
  const over90 = allAgents.filter((a) => !a.neverConnected && a.daysInactive >= 90).length;
  const groups = computeGroupedAgents(allAgents);

  const lossRate = meta?.loss_rate_percent ?? null;
  const target = meta?.target_loss_rate_percent ?? 1;
  const lossColor =
    lossRate === null ? 'var(--muted)' : lossRate <= target ? '#4ade80' : lossRate <= target * 3 ? 'var(--medium)' : 'var(--critical)';
  const fleetLabel = meta?.reference_fleet_source === 'manual' ? `parc déclaré : ${meta.reference_fleet}` : `total Wazuh : ${meta?.reference_fleet ?? '—'}`;

  document.getElementById('stats').innerHTML = `
    <div class="stat" style="border-color:${lossColor}">
      <div class="n" style="color:${lossColor}">${lossRate !== null ? lossRate.toLocaleString('fr-FR') + ' %' : '—'}</div>
      <div class="l">Taux de perte (obj. ${target.toLocaleString('fr-FR')} %)</div>
    </div>
    <div class="stat n-critical"><div class="n">${allAgents.length}</div><div class="l">Agents inactifs</div></div>
    <div class="stat n-critical"><div class="n">${neverConnected}</div><div class="l">Jamais connectés</div></div>
    <div class="stat"><div class="n">${over90}</div><div class="l">Inactifs &gt; 90j</div></div>
    <div class="stat n-accent"><div class="n">${groups.length}</div><div class="l">Groupes concernés</div></div>
  `;
  document.getElementById('subtitle').textContent = `${allAgents.length} agents inactifs sur ${meta?.reference_fleet ?? '?'} (${fleetLabel})`;
}

function renderGrouped() {
  const groups = computeGroupedAgents(allAgents);
  const container = document.getElementById('grouped');
  document.getElementById('groupedEmpty').style.display = groups.length ? 'none' : 'block';
  container.innerHTML = groups
    .map(
      (g) => `
      <div class="gcard">
        <span class="pkg">${escapeHtml(g.group)}</span>
        <span class="count">${g.agents.length} agents</span>
        <p>${g.neverConnectedCount > 0 ? `<strong>${g.neverConnectedCount}</strong> jamais connecté${g.neverConnectedCount > 1 ? 's' : ''} · ` : ''}concentration à surveiller.</p>
      </div>
    `
    )
    .join('');
}

function populateFilterOptions() {
  const osSet = new Set();
  allAgents.forEach((a) => { if (a.os && a.os !== '—') osSet.add(a.os); });
  const assetSelect = document.getElementById('assetFilter');
  const current = assetSelect.value;
  assetSelect.innerHTML =
    '<option value="">Tous les OS</option>' +
    Array.from(osSet).sort().map((o) => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('');
  assetSelect.value = current;
}

function sortAndRender() {
  currentSort = document.getElementById('sortSelect').value;
  const sorters = {
    score: (a, b) => b.score - a.score,
    days: (a, b) => (b.daysInactive ?? 99999) - (a.daysInactive ?? 99999),
    dateAdd: (a, b) => new Date(a.dateAdd || 0) - new Date(b.dateAdd || 0),
    name: (a, b) => a.name.localeCompare(b.name),
  };
  const sorted = [...allAgents].sort(sorters[currentSort]);
  renderTable(sorted);
  filterRows();
}

function renderTable(rows) {
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = rows
    .map((a) => {
      const color = SEVERITY_COLOR[a.sevKey] || SEVERITY_COLOR.unknown;
      const action = actionLabel(a);
      const previewCount = 2;
      const groupsHtml =
        a.groups.slice(0, previewCount).map((g) => `<span class="asset">${escapeHtml(g)}</span>`).join('') +
        (a.groups.length > previewCount ? `<span class="asset more" data-agent-id="${escapeHtml(String(a.id))}">+${a.groups.length - previewCount}</span>` : '');
      const lastSeen = a.neverConnected ? 'Jamais' : a.lastKeepAlive ? `${a.lastKeepAlive.slice(0, 10)} (${a.daysInactive}j)` : '—';
      const searchText = [a.name, a.ip, a.os, ...a.groups].join(' ').toLowerCase();

      return `
      <tr data-sev="${a.sevKey}" data-assets="${escapeHtml(a.os)}" data-text="${escapeHtml(searchText)}">
        <td><span class="badge" style="background:${color}">${escapeHtml(SEVERITY_LABEL[a.sevKey])}</span></td>
        <td>
          ${escapeHtml(a.name)}
          <span class="sub">${escapeHtml(String(a.id))}</span>
        </td>
        <td>${escapeHtml(a.ip)}</td>
        <td>${escapeHtml(a.os)}</td>
        <td><div class="assets">${groupsHtml || '<span class="asset">—</span>'}</div></td>
        <td>${escapeHtml(lastSeen)}</td>
        <td class="fix ${action.muted ? 'muted' : ''}">${escapeHtml(action.label)}</td>
      </tr>`;
    })
    .join('');

  // Event delegation for the "+N" group pills, instead of inline onclick attrs.
  tbody.querySelectorAll('.asset.more').forEach((el) => {
    el.addEventListener('click', () => openModal(el.dataset.agentId));
  });
}

function filterRows() {
  const q = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  const os = document.getElementById('assetFilter').value;
  document.querySelectorAll('#table tbody tr').forEach((row) => {
    const text = row.dataset.text || '';
    const match = (!q || text.includes(q)) && (!sev || row.dataset.sev === sev) && (!os || row.dataset.assets === os);
    row.classList.toggle('row-hidden', !match);
  });
}

// ---------------------------------------------------------------
// Groups modal
// ---------------------------------------------------------------
function openModal(agentId) {
  const a = allAgents.find((x) => String(x.id) === String(agentId));
  if (!a) return;
  document.getElementById('modalTitle').textContent = `${a.name} — ${a.groups.length} groupes`;
  document.getElementById('modalBody').innerHTML = a.groups.map((g) => `<div class="modal-row"><span class="h">${escapeHtml(g)}</span></div>`).join('');
  document.getElementById('hostModal').classList.add('open');
}
function closeModal() {
  document.getElementById('hostModal').classList.remove('open');
}

// ---------------------------------------------------------------
// Export markdown
// ---------------------------------------------------------------
function exportMarkdown() {
  const rows = [...allAgents].sort((a, b) => b.score - a.score);
  let md = `# Couverture — Agents inactifs\n\n`;
  md += `| # | Agent | IP | OS | Groupe(s) | Statut | Dernière connexion |\n`;
  md += `|---|-------|----|----|-----------|--------|--------------------|\n`;
  rows.forEach((a, i) => {
    const lastSeen = a.neverConnected ? 'Jamais' : a.lastKeepAlive ? a.lastKeepAlive.slice(0, 10) : '—';
    md += `| ${i + 1} | ${a.name} | ${a.ip} | ${a.os} | ${a.groups.join(', ') || '—'} | ${SEVERITY_LABEL[a.sevKey]} | ${lastSeen} |\n`;
  });
  navigator.clipboard.writeText(md);
}

// ---------------------------------------------------------------
// Wire up event listeners (replaces inline onclick/oninput attrs)
// ---------------------------------------------------------------
document.getElementById('search').addEventListener('input', filterRows);
document.getElementById('sevFilter').addEventListener('change', filterRows);
document.getElementById('assetFilter').addEventListener('change', filterRows);
document.getElementById('sortSelect').addEventListener('change', sortAndRender);
document.getElementById('reloadBtn').addEventListener('click', loadData);
document.getElementById('exportBtn').addEventListener('click', exportMarkdown);
document.getElementById('hostModal').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeModal();
});
document.querySelector('#hostModal .modal-head button').addEventListener('click', closeModal);

highlightActiveNav();
loadData();
