// Highlights the current page's link in the shared top nav.
// Call this once on each page after the DOM is ready.
export function highlightActiveNav() {
  const path = window.location.pathname;
  document.querySelectorAll('nav.topnav a').forEach((link) => {
    const page = link.dataset.page;
    link.classList.toggle('active', path.includes(`/${page}`));
  });
}
