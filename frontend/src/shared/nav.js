// Highlights the current page's link in the shared top nav,
// and wires up the shared logout button.
// Call this once on each page after the DOM is ready.
export function highlightActiveNav() {
  const path = window.location.pathname;
  document.querySelectorAll('nav.topnav a').forEach((link) => {
    const page = link.dataset.page;
    link.classList.toggle('active', path.includes(`/${page}`));
  });

  wireLogout();
}

function wireLogout() {
  const btn = document.querySelector('nav.topnav .logout');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });
    } catch (err) {
      console.error('Erreur lors de la déconnexion:', err);
    } finally {
      window.location.href = '/';
    }
  });
}