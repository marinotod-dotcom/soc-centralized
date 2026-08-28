// Commentaires de traitement/validation par paire (CVE, agent).
// Correspond à la table `comments` en base : id, cve, agent_id,
// type ('traitement'|'validation'), author, text, created_at.
//
// Aujourd'hui : persisté en localStorage.
// Demain : remplacer le corps de chaque fonction par un appel fetchJson
// (endpoints indiqués en commentaire), même forme de retour.

const COMMENTS_KEY = 'vulnComments';

function readAll() {
  try { return JSON.parse(localStorage.getItem(COMMENTS_KEY)) || {}; }
  catch { return {}; }
}
function writeAll(all) {
  localStorage.setItem(COMMENTS_KEY, JSON.stringify(all));
}
function keyOf(cve, agentId) {
  return `${cve}|${agentId}`;
}

// TODO backend: GET /api/vulnerabilities/comments?cve=...&agent=...
export function getComments(cve, agentId) {
  return readAll()[keyOf(cve, agentId)] || [];
}

// TODO backend: POST /api/vulnerabilities/comments { cve, agentId, type, text }
export function addComment(cve, agentId, { type, text, author }) {
  const all = readAll();
  const key = keyOf(cve, agentId);
  const comment = {
    id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
    cve,
    agentId,
    type, // 'traitement' | 'validation'
    text,
    author: author || (type === 'traitement' ? 'Technicien' : 'Admin'),
    createdAt: new Date().toISOString(),
  };
  all[key] = [...(all[key] || []), comment];
  writeAll(all);
  return comment;
}