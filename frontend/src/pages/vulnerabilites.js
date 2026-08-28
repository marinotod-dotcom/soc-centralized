import '../shared/theme.css';
import { highlightActiveNav } from '../shared/nav.js';
import { escapeHtml } from '../shared/dom.js';

const SEVERITY_COLOR = { Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)' };
const SEVERITY_WEIGHT = { Critical: 4, High: 3, Medium: 2, Low: 1 };

let allCves = [];
let allAgents = [];
let currentTab = 'cve';
let cveSort = { key: 'cvss', dir: -1 };
let agentSort = { key: 'cve_count', dir: -1 };
let meta = {};

async function loadData() {
  document.getElementById('subtitle').textContent = 'Chargement de data.json…';
  try {
    const res = await fetch('data.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const json = await res.json();
    const buckets = json?.aggregations?.vulnerabilities_by_agent?.buckets;
    if (!buckets) throw new Error('Structure inattendue : aggregations.vulnerabilities_by_agent.buckets introuvable');

    meta = json.meta || {};
    const { cves, agents } = transformBuckets(buckets);
    allCves = cves;
    allAgents = agents;

    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('content').style.display = 'block';
    renderStats();
    renderPeriod();
    renderRemediations();
    renderTab();
  } catch (err) {
    document.getElementById('emptyReason').textContent = err.message;
    document.getElementById('emptyState').style.display = 'block';
    document.getElementById('content').style.display = 'none';
    document.getElementById('subtitle').textContent = 'data.json introuvable ou invalide';
  }
}

// ---------------------------------------------------------------
// Transform: raw Wazuh vulnerabilities_by_agent buckets
// (one entry per paire CVE x agent) -> vue par CVE + vue par agent
// ---------------------------------------------------------------
function transformBuckets(buckets) {
  const cveMap = new Map();
  const agentMap = new Map();

  for (const b of buckets) {
    const cve = b?.key?.cve;
    const agentId = b?.key?.agent;
    const hit = b?.details?.hits?.hits?.[0]?._source;
    if (!cve || !agentId || !hit) continue;

    const agentName = hit.agent?.name || agentId;
    const vuln = hit.data?.vulnerability || {};
    const severity = vuln.severity || 'None';
    const pkgName = vuln.package?.name || '—';
    const pkgVersion = vuln.package?.version || '—';
    const title = vuln.title || cve;
    const cvssRaw = vuln.cvss?.cvss3?.base_score;
    const cvss = cvssRaw != null ? parseFloat(cvssRaw) : null;

    // --- CVE aggregation ---
    if (!cveMap.has(cve)) {
      cveMap.set(cve, { cve, severity, cvss, title, packages: new Set(), versions: new Set(), agents: [], agentIdsSeen: new Set() });
    }
    const c = cveMap.get(cve);
    if ((SEVERITY_WEIGHT[severity] ?? 0) > (SEVERITY_WEIGHT[c.severity] ?? 0)) c.severity = severity;
    if (cvss != null && (c.cvss == null || cvss > c.cvss)) c.cvss = cvss;
    c.packages.add(pkgName);
    c.versions.add(pkgVersion);
    if (!c.agentIdsSeen.has(agentId)) {
      c.agentIdsSeen.add(agentId);
      c.agents.push({ id: agentId, name: agentName, version: pkgVersion });
    }

    // --- Agent aggregation ---
    if (!agentMap.has(agentId)) {
      agentMap.set(agentId, { id: agentId, name: agentName, cves: new Map(), maxSeverity: 'None' });
    }
    const a = agentMap.get(agentId);
    const prevSev = a.cves.get(cve);
    if (!prevSev || (SEVERITY_WEIGHT[severity] ?? 0) > (SEVERITY_WEIGHT[prevSev] ?? 0)) a.cves.set(cve, severity);
    if ((SEVERITY_WEIGHT[severity] ?? 0) > (SEVERITY_WEIGHT[a.maxSeverity] ?? 0)) a.maxSeverity = severity;
  }

  const cves = Array.from(cveMap.values()).map((c) => ({
    cve: c.cve,
    severity: c.severity,
    cvss: c.cvss,
    title: c.title,
    packages: Array.from(c.packages).sort(),
    versions: Array.from(c.versions).sort(),
    agentCount: c.agents.length,
    agents: c.agents,
  }));

  const agents = Array.from(agentMap.values()).map((a) => ({
    id: a.id,
    name: a.name,
    maxSeverity: a.maxSeverity,
    cveCount: a.cves.size,
    cves: Array.from(a.cves.entries())
      .map(([cve, severity]) => ({ cve, severity }))
      .sort((x, y) => (SEVERITY_WEIGHT[y.severity] ?? 0) - (SEVERITY_WEIGHT[x.severity] ?? 0)),
  }));

  return { cves, agents };
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------
function renderPeriod() {
  if (meta.date_from && meta.date_to) {
    document.getElementById('period').textContent = `${meta.date_from.slice(0, 10)} → ${meta.date_to.slice(0, 10)}`;
  }
}

function renderStats() {
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  allCves.forEach((c) => { if (sevCounts[c.severity] !== undefined) sevCounts[c.severity]++; });

  document.getElementById('subtitle').textContent =
    `${allCves.length} CVE distinctes détectées sur ${allAgents.length} agents (${meta.total_buckets ?? '?'} occurrences)`;
  document.getElementById('stats').innerHTML = `
    <div class="stat n-accent"><div class="n">${allCves.length}</div><div class="l">CVE distinctes</div></div>
    <div class="stat n-accent"><div class="n">${allAgents.length}</div><div class="l">Agents touchés</div></div>
    <div class="stat n-critical"><div class="n">${sevCounts.Critical}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n">${sevCounts.High}</div><div class="l">High</div></div>
    <div class="stat"><div class="n">${sevCounts.Medium}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n">${sevCounts.Low}</div><div class="l">Low</div></div>
  `;
}

function buildRemediations() {
  const remediationMap = new Map();

  for (const cve of allCves) {
    for (const agent of cve.agents) {

      // Un correctif est regroupé par paquet + version
      for (const pkg of cve.packages) {

        const key = `${pkg}|${agent.version}`;

        if (!remediationMap.has(key)) {
          remediationMap.set(key, {
            package: pkg,
            version: agent.version,
            cves: new Set(),
            agents: new Set()
          });
        }

        const remediation = remediationMap.get(key);

        remediation.cves.add(cve.cve);
        remediation.agents.add(agent.id);
      }
    }
  }

  return Array.from(remediationMap.values())
    .filter(r => r.cves.size > 1)
    .sort((a, b) => {
      return b.cves.size - a.cves.size;
    });
}

function renderRemediations() {
  const track = document.getElementById('remediationTrack');

  if (!track) return;

  const remediations = buildRemediations();

  track.innerHTML = remediations
    .map((r) => {

      const cveCount = r.cves.size;
      const hostCount = r.agents.size;

      return `
        <article class="remediation-card">

          <div class="remediation-card-header">
            <h3>${escapeHtml(r.package)}</h3>

            <span class="cve-count">
              ${cveCount} CVE
            </span>
          </div>

          <p class="remediation-description">
            Un correctif sur
            <strong>${hostCount} host${hostCount > 1 ? 's' : ''}</strong>
            résout
            <strong>${cveCount} vulnérabilité${cveCount > 1 ? 's' : ''}</strong>
            d'un coup.
          </p>

          <div class="remediation-version">
            Version détectée :
            <strong>${escapeHtml(r.version)}</strong>
          </div>

          <div class="remediation-cves">
            ${Array.from(r.cves)
              .slice(0, 5)
              .map(cve => `
                <span class="remediation-cve">
                  ${escapeHtml(cve)}
                </span>
              `)
              .join('')}

            ${
              cveCount > 5
                ? `<span class="remediation-more">
                    +${cveCount - 5}
                  </span>`
                : ''
            }
          </div>

        </article>
      `;
    })
    .join('');

  initRemediationCarousel();
}

function initRemediationCarousel() {

  const track = document.getElementById('remediationTrack');
  const prev = document.getElementById('remediationPrev');
  const next = document.getElementById('remediationNext');

  if (!track || !prev || !next) return;

  const cards = track.querySelectorAll('.remediation-card');

  if (!cards.length) {
    prev.style.display = 'none';
    next.style.display = 'none';
    return;
  }

  let currentIndex = 0;

  function getCardsPerView() {
    if (window.innerWidth <= 700) return 1;
    if (window.innerWidth <= 1100) return 2;
    return 3;
  }

  function updateCarousel() {

    const cardsPerView = getCardsPerView();
    const maxIndex = Math.max(
      0,
      cards.length - cardsPerView
    );

    currentIndex = Math.min(currentIndex, maxIndex);

    const cardWidth = cards[0].getBoundingClientRect().width;
    const gap = 16;

    track.style.transform =
      `translateX(-${currentIndex * (cardWidth + gap)}px)`;

    prev.disabled = currentIndex === 0;
    next.disabled = currentIndex >= maxIndex;
  }

  prev.addEventListener('click', () => {
    if (currentIndex > 0) {
      currentIndex--;
      updateCarousel();
    }
  });

  next.addEventListener('click', () => {

    const cardsPerView = getCardsPerView();
    const maxIndex = Math.max(
      0,
      cards.length - cardsPerView
    );

    if (currentIndex < maxIndex) {
      currentIndex++;
      updateCarousel();
    }
  });

  window.addEventListener('resize', updateCarousel);

  updateCarousel();
}

function renderTab() {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === currentTab));
  if (currentTab === 'cve') renderCveTable();
  else renderAgentTable();
  filterRows();
}

// ---------------- Vue par CVE ----------------
function renderCveTable() {
  const thead = document.getElementById('thead');
  thead.innerHTML = `
    <tr>
      <th data-key="severity">Sévérité</th>
      <th data-key="cve">CVE</th>
      <th data-key="cvss">CVSS</th>
      <th>Paquet(s)</th>
      <th>Version(s)</th>
      <th data-key="agentCount">Agents touchés</th>
    </tr>`;
  thead.querySelectorAll('th[data-key]').forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.key;
      cveSort.dir = cveSort.key === key ? -cveSort.dir : -1;
      cveSort.key = key;
      renderCveTable();
    });
  });

  const sorted = [...allCves].sort((a, b) => {
    let av = a[cveSort.key];
    let bv = b[cveSort.key];
    if (cveSort.key === 'severity') { av = SEVERITY_WEIGHT[av] ?? 0; bv = SEVERITY_WEIGHT[bv] ?? 0; }
    if (typeof av === 'string') return av.localeCompare(bv) * cveSort.dir;
    return ((av ?? 0) - (bv ?? 0)) * cveSort.dir;
  });

  const previewCount = 3;
  document.getElementById('tbody').innerHTML = sorted
    .map((c) => {
      const color = SEVERITY_COLOR[c.severity] || 'var(--unknown)';
      const pkgPreview = c.packages.slice(0, 2).map(escapeHtml).join(', ') + (c.packages.length > 2 ? `, +${c.packages.length - 2}` : '');
      const versionPreview = c.versions.slice(0, 2).map(escapeHtml).join(', ') + (c.versions.length > 2 ? `, +${c.versions.length - 2}` : '');
      const agentChips =
        c.agents.slice(0, previewCount).map((a) => `<span class="asset">${escapeHtml(a.name)}</span>`).join('') +
        (c.agents.length > previewCount ? `<span class="asset more" data-cve="${escapeHtml(c.cve)}">+${c.agents.length - previewCount}</span>` : '');
      const searchText = [c.cve, c.title, ...c.packages, ...c.agents.map((a) => a.name)].join(' ').toLowerCase();

      return `
      <tr data-sev="${escapeHtml(c.severity)}" data-text="${escapeHtml(searchText)}">
        <td><span class="badge" style="background:${color}">${escapeHtml(c.severity)}</span></td>
        <td>${escapeHtml(c.cve)}<span class="sub">${escapeHtml(c.title)}</span></td>
        <td>${c.cvss != null ? c.cvss.toFixed(1) : '—'}</td>
        <td>${pkgPreview || '—'}</td>
        <td>${versionPreview || '—'}</td>
        <td><div class="assets">${agentChips || '<span class="asset">—</span>'}</div></td>
      </tr>`;
    })
    .join('');

  document.getElementById('tbody').querySelectorAll('.asset.more').forEach((el) => {
    el.addEventListener('click', () => openCveModal(el.dataset.cve));
  });
}

function openCveModal(cveId) {
  const c = allCves.find((x) => x.cve === cveId);
  if (!c) return;
  document.getElementById('modalTitle').textContent = `${c.cve} — ${c.agents.length} agents`;
  document.getElementById('modalBody').innerHTML = c.agents
    .map((a) => `<div class="modal-row"><span class="h">${escapeHtml(a.name)}</span><span class="c">${escapeHtml(a.id)} · v${escapeHtml(a.version)}</span></div>`)
    .join('');
  document.getElementById('vulnModal').classList.add('open');
}

// ---------------- Vue par agent ----------------
function renderAgentTable() {
  const thead = document.getElementById('thead');
  thead.innerHTML = `
    <tr>
      <th data-key="maxSeverity">Sévérité max</th>
      <th data-key="name">Agent</th>
      <th data-key="cveCount">Nb CVE</th>
      <th>CVE principales</th>
    </tr>`;
  thead.querySelectorAll('th[data-key]').forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.key;
      agentSort.dir = agentSort.key === key ? -agentSort.dir : -1;
      agentSort.key = key;
      renderAgentTable();
    });
  });

  const sorted = [...allAgents].sort((a, b) => {
    let av = a[agentSort.key];
    let bv = b[agentSort.key];
    if (agentSort.key === 'maxSeverity') { av = SEVERITY_WEIGHT[av] ?? 0; bv = SEVERITY_WEIGHT[bv] ?? 0; }
    if (typeof av === 'string') return av.localeCompare(bv) * agentSort.dir;
    return ((av ?? 0) - (bv ?? 0)) * agentSort.dir;
  });

  const previewCount = 3;
  document.getElementById('tbody').innerHTML = sorted
    .map((a) => {
      const color = SEVERITY_COLOR[a.maxSeverity] || 'var(--unknown)';
      const cvePreview =
        a.cves.slice(0, previewCount).map((c) => `<span class="asset">${escapeHtml(c.cve)}</span>`).join('') +
        (a.cves.length > previewCount ? `<span class="asset more" data-agent-id="${escapeHtml(a.id)}">+${a.cves.length - previewCount}</span>` : '');
      const searchText = [a.name, a.id, ...a.cves.map((c) => c.cve)].join(' ').toLowerCase();

      return `
      <tr data-sev="${escapeHtml(a.maxSeverity)}" data-text="${escapeHtml(searchText)}">
        <td><span class="badge" style="background:${color}">${escapeHtml(a.maxSeverity)}</span></td>
        <td>${escapeHtml(a.name)}<span class="sub">${escapeHtml(a.id)}</span></td>
        <td>${a.cveCount}</td>
        <td><div class="assets">${cvePreview}</div></td>
      </tr>`;
    })
    .join('');

  document.getElementById('tbody').querySelectorAll('.asset.more').forEach((el) => {
    el.addEventListener('click', () => openAgentModal(el.dataset.agentId));
  });
}

function openAgentModal(agentId) {
  const a = allAgents.find((x) => x.id === agentId);
  if (!a) return;
  document.getElementById('modalTitle').textContent = `${a.name} — ${a.cves.length} CVE`;
  document.getElementById('modalBody').innerHTML = a.cves
    .map((c) => `<div class="modal-row"><span class="h">${escapeHtml(c.cve)}</span><span class="c">${escapeHtml(c.severity)}</span></div>`)
    .join('');
  document.getElementById('vulnModal').classList.add('open');
}

// ---------------- Filtre / recherche ----------------
function filterRows() {
  const q = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  document.querySelectorAll('#table tbody tr').forEach((row) => {
    const text = row.dataset.text || '';
    const match = (!q || text.includes(q)) && (!sev || row.dataset.sev === sev);
    row.classList.toggle('row-hidden', !match);
  });
}

// ---------------- Export markdown ----------------
function exportMarkdown() {
  let md = `# Vulnérabilités — ${meta.date_from ? meta.date_from.slice(0, 10) : ''} → ${meta.date_to ? meta.date_to.slice(0, 10) : ''}\n\n`;
  md += `${allCves.length} CVE distinctes sur ${allAgents.length} agents.\n\n`;
  if (currentTab === 'cve') {
    md += `| CVE | Sévérité | CVSS | Paquet(s) | Version(s) | Agents touchés |\n|---|---|---|---|---|---|\n`;
    [...allCves].sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0)).forEach((c) => {
      md += `| ${c.cve} | ${c.severity} | ${c.cvss ?? '—'} | ${c.packages.join(', ')} | ${c.versions.join(', ')} | ${c.agentCount} |\n`;
    });
  } else {
    md += `| Agent | ID | Sévérité max | Nb CVE |\n|---|---|---|---|\n`;
    [...allAgents].sort((a, b) => b.cveCount - a.cveCount).forEach((a) => {
      md += `| ${a.name} | ${a.id} | ${a.maxSeverity} | ${a.cveCount} |\n`;
    });
  }
  navigator.clipboard.writeText(md);
}

// ---------------------------------------------------------------
// Wire up event listeners
// ---------------------------------------------------------------
document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => { currentTab = t.dataset.tab; renderTab(); }));
document.getElementById('search').addEventListener('input', filterRows);
document.getElementById('sevFilter').addEventListener('change', filterRows);
document.getElementById('reloadBtn').addEventListener('click', loadData);
document.getElementById('exportBtn').addEventListener('click', exportMarkdown);
document.getElementById('vulnModal').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
});
document.querySelector('#vulnModal .modal-head button').addEventListener('click', () => {
  document.getElementById('vulnModal').classList.remove('open');
});

highlightActiveNav();
loadData();

