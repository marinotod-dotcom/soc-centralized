// Escapes text before injecting it into innerHTML templates, preventing XSS
// from data coming out of the API (agent names, group names, etc.)
export function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}

// Formats an ISO date string as dd/mm (fr-FR), used in chart labels/subtitles.
export function fmtDateShort(isoDate) {
  return new Date(isoDate).toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' });
}

// Renders a generic error message into a container, reused by every page's
// catch block so the "Erreur de chargement" markup stays consistent.
export function renderError(container, message) {
  container.innerHTML = `<div class="error-msg">Erreur de chargement : ${escapeHtml(message)}</div>`;
}
