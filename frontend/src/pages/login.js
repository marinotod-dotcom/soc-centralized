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

const username = document.getElementById('email').value.trim();
const password = document.getElementById('password').value;

try {
const formData = new URLSearchParams();

formData.append('username', username);
formData.append('password', password);

const res = await fetch('/api/auth/login', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: formData.toString(),
});

if (!res.ok) {
  let message;

  if (res.status === 401) {
    message = 'Identifiant ou mot de passe incorrect.';
  } else if (res.status === 422) {
    message = 'Données de connexion invalides.';
  } else {
    message = `Erreur serveur (HTTP ${res.status}).`;
  }

  throw new Error(message);
}

window.location.href = '/action_plan';

} catch (err) {
showError(err.message || 'Connexion impossible.');
submitBtn.disabled = false;
submitBtn.textContent = 'Se connecter';
}
});
