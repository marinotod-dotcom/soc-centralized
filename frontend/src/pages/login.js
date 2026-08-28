import '../shared/theme.css';

const form = document.getElementById('loginForm');
const errorBox = document.getElementById('loginError');
const submitBtn = document.getElementById('loginBtn');

function showError(message) {
  errorBox.textContent = message;
  errorBox.style.display = 'block';
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBox.style.display = 'none';
  submitBtn.disabled = true;
  submitBtn.textContent = 'Connexion…';

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      const message = res.status === 401
        ? 'Identifiant ou mot de passe incorrect.'
        : `Erreur serveur (HTTP ${res.status}).`;
      throw new Error(message);
    }

    window.location.href = '/action_plan';
  } catch (err) {
    showError(err.message || 'Connexion impossible.');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Se connecter';
  }
});