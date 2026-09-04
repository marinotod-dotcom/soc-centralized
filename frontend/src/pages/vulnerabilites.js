import '../shared/theme.css';
import { initThemeToggle } from '../shared/theme-toggle.js';
import { highlightActiveNav } from '../shared/nav.js';
import { escapeHtml } from '../shared/dom.js';

const SEVERITY_COLOR = { Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)' };
const SEVERITY_WEIGHT = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const STATUS_LABELS = { nouveau: 'Nouveau', valide: 'Validé', rejete: 'Rejeté', traite: 'Traité' };

let allCves = [];
let allAgents = [];
let currentTab = 'cve';
let cveSort = { key: 'cvss', dir: -1 };
let agentSort = { key: 'cve_count', dir: -1 };
let meta = {};
let carouselResizeHandler = null;
let carouselAutoPlayInterval = null;

let currentUser = null;
let vulnStatusMap = new Map();

async function loadData() {
  document.getElementById('subtitle').textContent = 'Chargement…';
  try {
    const [res] = await Promise.all([
      fetch('/data/action_plan/latest.json', {
        credentials: 'include',
      }),
      fetchCurrentUser(),
    ]);
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
    populatePackageFilter();
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

async function fetchCurrentUser() {
  try {
    const res = await fetch('/api/me', { credentials: 'include' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    currentUser = await res.json();
  } catch (err) {
    console.error("Impossible de récupérer l'utilisateur connecté", err);
    currentUser = null;
  }
}

async function fetchVulnStatusesForCve(cveId, forceRefresh = false) {
  try {
    const res = await fetch(`/api/vulnerabilities/by-cve/${encodeURIComponent(cveId)}`, {
      credentials: 'include',
      headers: forceRefresh ? { 'X-Force-Refresh': '1' } : {},
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const rows = await res.json();
    rows.forEach((r) => vulnStatusMap.set(`${r.cve_id}|${r.agent_name}`, r));
  } catch (err) {
    console.error('Impossible de récupérer les statuts de suivi pour ' + cveId, err);
  }
}

async function treatVulnerabilityApi(cveId, agentName, comment) {
  const res = await fetch(
    `/api/vulnerabilities/${encodeURIComponent(cveId)}/${encodeURIComponent(agentName)}/treat`,
    {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ comment }),
    }
  );
  if (!res.ok) throw new Error(`HTTP ${res.status} ${await res.text().catch(() => '')}`);
  return res.json();
}

async function validateVulnerabilityApi(cveId, agentName, comment) {
  const url =
    `/api/vulnerabilities/` +
    `${encodeURIComponent(cveId)}/` +
    `${encodeURIComponent(agentName)}/validate`;

  const res = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ comment: comment || null }),
  });

  if (!res.ok) {
    let detail = '';
    try {
      const data = await res.json();
      detail = data.detail || '';
    } catch {
      detail = await res.text().catch(() => '');
    }
    const error = new Error(`HTTP ${res.status}${detail ? ` : ${detail}` : ''}`);
    error.status = res.status;
    throw error;
  }

  return res.json();
}

function canTreat() {
  return currentUser?.role === 'technicien';
}
function canValidate() {
  return currentUser?.role === 'admin_cyber';
}

function getStatus(cve, agentName) {
  const row = vulnStatusMap.get(`${cve}|${agentName}`);
  if (!row || !row.status) {
    return 'nouveau';
  }
  const status = row.status.toLowerCase();
  return STATUS_LABELS[status] ? status : 'nouveau';
}

// ---------------------------------------------------------------
// Commentaires : construits directement depuis les colonnes JSONB
// treatment_comment / validation_comment renvoyées par
// GET /api/vulnerabilities/by-cve/{cve_id} — plus de localStorage,
// la base est la seule source de vérité, partagée entre tous les rôles.
// ---------------------------------------------------------------
function buildCommentItems(trackingRow) {
  const items = [];
  (trackingRow?.treatment_comment || []).forEach((text) => {
    items.push({
      type: 'traitement',
      author: trackingRow.treated_by,
      text,
      date: trackingRow.treated_at,
    });
  });
  (trackingRow?.validation_comment || []).forEach((text) => {
    items.push({
      type: 'validation',
      author: trackingRow.validated_by,
      text,
      date: trackingRow.validated_at,
    });
  });
  return items;
}

function renderCommentsFromDb(trackingRow) {
  const items = buildCommentItems(trackingRow);
  if (!items.length) return '';
  return `
    <div class="modal-row-comments">
      ${items
        .map(
          (it) => `
        <div class="comment-item comment-${it.type}">
          <span class="comment-author">${escapeHtml(it.author || '—')}</span>
          <span class="comment-text">${escapeHtml(it.text)}</span>
          ${it.date ? `<span class="comment-date">${new Date(it.date).toLocaleString('fr-FR')}</span>` : ''}
        </div>`
        )
        .join('')}
    </div>`;
}

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
    const pkgCondition = vuln.package?.condition || '—';
    const title = vuln.title || cve;
    const cvssRaw = vuln.cvss?.cvss3?.base_score;
    const cvss = cvssRaw != null ? parseFloat(cvssRaw) : null;

    if (!cveMap.has(cve)) {
      cveMap.set(cve, { cve, severity, cvss, title, packages: new Set(), agents: [], agentIdsSeen: new Set() });
    }
    const c = cveMap.get(cve);
    if ((SEVERITY_WEIGHT[severity] ?? 0) > (SEVERITY_WEIGHT[c.severity] ?? 0)) c.severity = severity;
    if (cvss != null && (c.cvss == null || cvss > c.cvss)) c.cvss = cvss;
    c.packages.add(pkgName);
    if (!c.agentIdsSeen.has(agentId)) {
      c.agentIdsSeen.add(agentId);
      c.agents.push({ id: agentId, name: agentName, package: pkgName, condition: pkgCondition });
    }

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
      const key = `${agent.package}|${agent.condition}`;

      if (!remediationMap.has(key)) {
        remediationMap.set(key, {
          package: agent.package,
          condition: agent.condition,
          cves: new Set(),
          agents: new Set(),
        });
      }

      const remediation = remediationMap.get(key);
      remediation.cves.add(cve.cve);
      remediation.agents.add(agent.id);
    }
  }

  return Array.from(remediationMap.values())
    .filter((r) => r.cves.size > 1)
    .sort((a, b) => b.cves.size - a.cves.size);
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
            <span class="cve-count">${cveCount} CVE</span>
          </div>

          <p class="remediation-description">
            Un correctif sur
            <strong>${hostCount} host${hostCount > 1 ? 's' : ''}</strong>
            résout
            <strong>${cveCount} vulnérabilité${cveCount > 1 ? 's' : ''}</strong>
            d'un coup.
          </p>

          <div class="remediation-version">
            Condition détectée :
            <strong>${escapeHtml(r.condition)}</strong>
          </div>

          <div class="remediation-cves">
            ${Array.from(r.cves)
              .slice(0, 5)
              .map((cve) => `<span class="remediation-cve">${escapeHtml(cve)}</span>`)
              .join('')}
            ${cveCount > 5 ? `<span class="remediation-more">+${cveCount - 5}</span>` : ''}
          </div>
        </article>
      `;
    })
    .join('');

  initRemediationCarousel();
}

function initRemediationCarousel() {
  const track = document.getElementById('remediationTrack');
  let prev = document.getElementById('remediationPrev');
  let next = document.getElementById('remediationNext');

  if (!track || !prev || !next) return;

  const prevClone = prev.cloneNode(true);
  const nextClone = next.cloneNode(true);

  prev.replaceWith(prevClone);
  next.replaceWith(nextClone);

  prev = prevClone;
  next = nextClone;

  if (carouselResizeHandler) {
    window.removeEventListener('resize', carouselResizeHandler);
    carouselResizeHandler = null;
  }

  if (carouselAutoPlayInterval) {
    clearInterval(carouselAutoPlayInterval);
    carouselAutoPlayInterval = null;
  }

  const cards = track.querySelectorAll('.remediation-card');

  if (!cards.length) {
    prev.style.display = 'none';
    next.style.display = 'none';
    return;
  }

  prev.style.display = '';
  next.style.display = '';

  let currentIndex = 0;

  function getCardsPerView() {
    if (window.innerWidth <= 700) return 1;
    if (window.innerWidth <= 1100) return 2;
    return 3;
  }

  function updateCarousel() {
    const cardsPerView = getCardsPerView();
    const maxIndex = Math.max(0, cards.length - cardsPerView);

    currentIndex = Math.min(currentIndex, maxIndex);

    const cardWidth = cards[0].getBoundingClientRect().width;
    const gap = 16;

    track.style.transform = `translateX(-${currentIndex * (cardWidth + gap)}px)`;

    prev.disabled = currentIndex === 0;
    next.disabled = currentIndex >= maxIndex;
  }

  prev.addEventListener('click', () => {
    const cardsPerView = getCardsPerView();
    const maxIndex = Math.max(0, cards.length - cardsPerView);
    currentIndex = currentIndex > 0 ? currentIndex - 1 : maxIndex;
    updateCarousel();
  });

  next.addEventListener('click', () => {
    const cardsPerView = getCardsPerView();
    const maxIndex = Math.max(0, cards.length - cardsPerView);
    currentIndex = currentIndex < maxIndex ? currentIndex + 1 : 0;
    updateCarousel();
  });

  carouselResizeHandler = updateCarousel;
  window.addEventListener('resize', carouselResizeHandler);

  updateCarousel();

  const AUTO_PLAY_DELAY = 3000;

  carouselAutoPlayInterval = setInterval(() => {
    const cardsPerView = getCardsPerView();
    const maxIndex = Math.max(0, cards.length - cardsPerView);
    if (maxIndex === 0) return;
    currentIndex = currentIndex < maxIndex ? currentIndex + 1 : 0;
    updateCarousel();
  }, AUTO_PLAY_DELAY);
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
      const agentChips =
        c.agents.slice(0, previewCount).map((a) => `<span class="asset" data-cve="${escapeHtml(c.cve)}">${escapeHtml(a.name)}</span>`).join('') +
        (c.agents.length > previewCount ? `<span class="asset more" data-cve="${escapeHtml(c.cve)}">+${c.agents.length - previewCount}</span>` : '');
      const searchText = [c.cve, c.title, ...c.packages, ...c.agents.map((a) => a.name)].join(' ').toLowerCase();

      return `
      <tr data-sev="${escapeHtml(c.severity)}" data-packages="${escapeHtml(c.packages.join('|'))}" data-text="${escapeHtml(searchText)}">
        <td><span class="badge" style="background:${color}">${escapeHtml(c.severity)}</span></td>
        <td>${escapeHtml(c.cve)}<span class="sub">${escapeHtml(c.title)}</span></td>
        <td>${c.cvss != null ? c.cvss.toFixed(1) : '—'}</td>
        <td>${pkgPreview || '—'}</td>
        <td><div class="assets">${agentChips || '<span class="asset">—</span>'}</div></td>
      </tr>`;
    })
    .join('');

  document.getElementById('tbody').querySelectorAll('.asset[data-cve]').forEach((el) => {
      el.addEventListener('click', () => openCveModal(el.dataset.cve));
  });
}

async function openCveModal(cveId) {
  const c = allCves.find((x) => x.cve === cveId);
  if (!c) return;

  document.getElementById('modalTitle').textContent = `${c.cve} — ${c.agents.length} agents`;
  document.getElementById('modalSearch').value = '';
  document.getElementById('modalStatusFilter').value = '';
  document.getElementById('modalBody').innerHTML = '<div class="modal-loading">Chargement des statuts…</div>';
  document.getElementById('vulnModal').classList.add('open');

  await fetchVulnStatusesForCve(cveId);

  renderCveModalBody(c);
}

function renderCveModalBody(c) {
  const allowTreat = canTreat();
  const allowValidate = canValidate();

  document.getElementById('modalBody').innerHTML = c.agents
    .map((a) => {
      const status = getStatus(c.cve, a.name);
      const trackingRow = vulnStatusMap.get(`${c.cve}|${a.name}`);
      const searchText = `${a.name} ${a.id}`.toLowerCase();

      const trackingHtml = trackingRow
        ? `<div class="modal-row-tracking">
            ${trackingRow.treated_by ? `<span>Traité par ${escapeHtml(trackingRow.treated_by)}</span>` : ''}
            ${trackingRow.validated_by ? `<span>Validé par ${escapeHtml(trackingRow.validated_by)}</span>` : ''}
          </div>`
        : '';

      return `
      <div class="modal-row-detailed" data-status="${status}" data-search="${escapeHtml(searchText)}">
        <div class="modal-row-top">
          <span class="h">${escapeHtml(a.name)}</span>
          <span class="c">${escapeHtml(a.id)} · ${escapeHtml(a.condition)}</span>
          <span class="status-badge status-${status}">${STATUS_LABELS[status]}</span>
        </div>

        ${trackingHtml}
        ${renderCommentsFromDb(trackingRow)}

        <div class="modal-row-actions">
          <button
            class="btn-ghost"
            data-toggle-form="traite"
            ${allowTreat ? '' : 'disabled title="Réservé au rôle technicien"'}
          >Marquer traité</button>
          <button
            class="btn-primary"
            data-toggle-form="valide"
            ${allowValidate ? '' : 'disabled title="Réservé au rôle admin_cyber"'}
          >Valider</button>
        </div>

        <div class="modal-row-comment-form" data-form="traite" hidden>
          <textarea placeholder="Commentaire de traitement (obligatoire)..."></textarea>
          <div class="form-actions">
            <button class="btn-ghost" data-cancel-form>Annuler</button>
            <button class="btn-primary" data-submit-form="traite" data-cve="${escapeHtml(c.cve)}" data-agent="${escapeHtml(a.name)}">Enregistrer</button>
          </div>
        </div>

        <div class="modal-row-comment-form" data-form="valide" hidden>
          <textarea placeholder="Réponse de validation (optionnel)..."></textarea>
          <div class="form-actions">
            <button class="btn-ghost" data-cancel-form>Annuler</button>
            <button class="btn-primary" data-submit-form="valide" data-cve="${escapeHtml(c.cve)}" data-agent="${escapeHtml(a.name)}">Valider</button>
          </div>
        </div>
      </div>`;
    })
    .join('');

  wireCveModalRowEvents(c);
  filterModalRows();
}

function wireCveModalRowEvents(c) {
  const body = document.getElementById('modalBody');

  body.querySelectorAll('button[data-toggle-form]').forEach((btn) => {
    if (btn.disabled) return;
    btn.addEventListener('click', () => {
      const row = btn.closest('.modal-row-detailed');
      const formType = btn.dataset.toggleForm;
      const targetForm = row.querySelector(`.modal-row-comment-form[data-form="${formType}"]`);
      const wasHidden = targetForm.hidden;

      row.querySelectorAll('.modal-row-comment-form').forEach((f) => { f.hidden = true; });
      targetForm.hidden = !wasHidden;
      if (!targetForm.hidden) targetForm.querySelector('textarea')?.focus();
    });
  });

  body.querySelectorAll('[data-cancel-form]').forEach((btn) => {
    btn.addEventListener('click', () => {
      btn.closest('.modal-row-comment-form').hidden = true;
    });
  });

  body.querySelectorAll('[data-submit-form]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const { submitForm: action, cve, agent } = btn.dataset;

      if (action === 'traite' && !canTreat()) return;
      if (action === 'valide' && !canValidate()) return;

      const form = btn.closest('.modal-row-comment-form');
      const textarea = form.querySelector('textarea');
      const text = textarea.value.trim();

      if (action === 'traite' && !text) {
        textarea.classList.add('input-error');
        textarea.focus();
        return;
      }
      textarea.classList.remove('input-error');

      btn.disabled = true;
      const originalLabel = btn.textContent;
      btn.textContent = 'Envoi…';

      try {
        if (action === 'traite') {
          await treatVulnerabilityApi(cve, agent, text);

          await fetchVulnStatusesForCve(cve, true);
          renderCveModalBody(c);

        } else {
          try {
            await validateVulnerabilityApi(cve, agent, text || null);

            await fetchVulnStatusesForCve(cve, true);
            renderCveModalBody(c);

          } catch (err) {
            console.error('Validation refusée :', err);

            const key = `${cve}|${agent}`;
            const existingRow = vulnStatusMap.get(key);

            if (existingRow) {
              existingRow.status = 'rejete';
            } else {
              vulnStatusMap.set(key, {
                cve_id: cve,
                agent_name: agent,
                status: 'rejete',
                treated_by: null,
                treated_at: null,
                treatment_comment: [],
                validated_by: null,
                validated_at: null,
                validation_comment: [],
              });
            }

            renderCveModalBody(c);

            showNotification(
              'Wazuh détecte encore cette vulnérabilité',
              'error'
            );
          }
        }

      } catch (err) {
        console.error('Échec de l’action :', err);

        showNotification(
          `Échec de l'action : ${err.message}`,
          'error'
        );

      } finally {
        btn.disabled = false;
        btn.textContent = originalLabel;
      }
    });
  });
}

function showNotification(message, type = 'error') {
  let notification = document.getElementById('appNotification');

  if (!notification) {
    notification = document.createElement('div');
    notification.id = 'appNotification';

    Object.assign(notification.style, {
      position: 'fixed',
      top: '24px',
      right: '24px',
      zIndex: '99999',
      padding: '14px 20px',
      borderRadius: '8px',
      fontSize: '14px',
      fontWeight: '600',
      maxWidth: '400px',
      boxShadow: '0 8px 25px rgba(0, 0, 0, 0.2)',
      transition: 'opacity 0.3s ease',
    });

    document.body.appendChild(notification);
  }

  notification.textContent = message;
  notification.style.background = type === 'error' ? '#fee2e2' : '#dcfce7';
  notification.style.color = type === 'error' ? '#991b1b' : '#166534';
  notification.style.opacity = '1';

  clearTimeout(notification._timeout);

  notification._timeout = setTimeout(() => {
    notification.style.opacity = '0';
  }, 4000);
}

function filterModalRows() {
  const q = (document.getElementById('modalSearch')?.value || '').toLowerCase();
  const statusFilter = document.getElementById('modalStatusFilter')?.value || '';
  document.querySelectorAll('#modalBody .modal-row-detailed').forEach((row) => {
    const matchesQuery = !q || row.dataset.search.includes(q);
    const matchesStatus = !statusFilter || row.dataset.status === statusFilter;
    row.classList.toggle('row-hidden', !(matchesQuery && matchesStatus));
  });
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
        a.cves.slice(0, previewCount).map((c) => `<span class="asset" data-agent-id="${escapeHtml(a.id)}">${escapeHtml(c.cve)}</span>`).join('') +
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

  document.getElementById('tbody').querySelectorAll('.asset[data-agent-id]').forEach((el) => {
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
  const pkg = document.getElementById('paqFilter').value;

  document.querySelectorAll('#table tbody tr').forEach((row) => {
    const text = row.dataset.text || '';
    const rowPackages = row.dataset.packages ? row.dataset.packages.split('|') : [];

    const matchesQuery = !q || text.includes(q);
    const matchesSev = !sev || row.dataset.sev === sev;
    const matchesPkg = !pkg || currentTab !== 'cve' || rowPackages.includes(pkg);

    row.classList.toggle('row-hidden', !(matchesQuery && matchesSev && matchesPkg));
  });
}

function populatePackageFilter() {
  const pkgSet = new Set();
  allCves.forEach((c) => c.packages.forEach((p) => pkgSet.add(p)));
  const select = document.getElementById('paqFilter');
  if (!select) return;
  const current = select.value;
  select.innerHTML =
    '<option value="">Tous paquets</option>' +
    Array.from(pkgSet).sort().map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join('');
  select.value = current;
}

// ---------------------------------------------------------------
// Wire up event listeners
// ---------------------------------------------------------------
document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => { currentTab = t.dataset.tab; renderTab(); }));
document.getElementById('search').addEventListener('input', filterRows);
document.getElementById('sevFilter').addEventListener('change', filterRows);
document.getElementById('paqFilter').addEventListener('change', filterRows);
document.getElementById('reloadBtn').addEventListener('click', loadData);
document.getElementById('vulnModal').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
});
document.querySelector('#vulnModal .modal-head button').addEventListener('click', () => {
  document.getElementById('vulnModal').classList.remove('open');
});
document.getElementById('modalSearch').addEventListener('input', filterModalRows);
document.getElementById('modalStatusFilter').addEventListener('change', filterModalRows);

highlightActiveNav();
initThemeToggle();
loadData();