/**
 * Fetch JSON from a URL with sane defaults (no-store cache, credentials included
 * for same-origin session cookies). Throws a readable Error on non-2xx responses
 * so callers can just try/catch.
 */
export async function fetchJson(url, options = {}) {
  const res = await fetch(url, {
    credentials: 'include',
    cache: 'no-store',
    ...options,
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  return res.json();
}
