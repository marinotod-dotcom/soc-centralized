import '../shared/theme.css';
import { highlightActiveNav } from '../shared/nav.js';
import { fetchJson } from '../shared/api.js';
import { renderError } from '../shared/dom.js';

// TODO: cette page n'a pas été fournie dans le HTML d'origine.
// Structure de départ : suit le même pattern fetch -> render que les 2 autres pages.
// Remplacez l'URL et le rendu ci-dessous par la vraie logique du "Plan d'action".
async function loadActionPlan() {
  try {
    const data = await fetchJson('/api/sla/action_plan');
    document.getElementById('content').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  } catch (err) {
    renderError(document.getElementById('content'), err.message);
  }
}

highlightActiveNav();
loadActionPlan();
