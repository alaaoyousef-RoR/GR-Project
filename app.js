const {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
} = SimpleWebAuthnBrowser;

const statusEl = document.getElementById('status');
const loginView = document.getElementById('login-view');
const registerView = document.getElementById('register-view');
const otpView = document.getElementById('otp-view');
const alertView = document.getElementById('alert-view');
const dashboardSection = document.getElementById('dashboard-section');
const dashboardMessage = document.getElementById('dashboard-message');

function showStatus(message, isSuccess = false) {
  statusEl.textContent = message;
  statusEl.className = isSuccess ? 'status success' : 'status';
}

function hideAllViews() {
  loginView.classList.add('hidden');
  registerView.classList.add('hidden');
  otpView.classList.add('hidden');
  alertView.classList.add('hidden');
  dashboardSection.classList.add('hidden');
  showStatus('');
}

function showLogin() {
  hideAllViews();
  loginView.classList.remove('hidden');
}

function showRegister() {
  hideAllViews();
  registerView.classList.remove('hidden');
}

function showOtpView(msg) {
  hideAllViews();
  otpView.classList.remove('hidden');
  if (msg) showStatus(msg);
}

function showAlertView(msg) {
  hideAllViews();
  alertView.classList.remove('hidden');
  if (msg) showStatus(msg);
}

function showDashboard(user) {
  hideAllViews();
  dashboardSection.classList.remove('hidden');
  dashboardMessage.textContent = `Welcome, ${user.firstName || user.first_name}! You are authenticated via FIDO2 Passkey.`;
}

// Browser Fingerprinting Module (Non-sensitive attributes)
function getBrowserFingerprint() {
  const data = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    screen.colorDepth,
    navigator.hardwareConcurrency || 4,
    new Date().getTimezoneOffset(),
  ].join('###');

  // Simple quick hash string
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    hash = (hash << 5) - hash + data.charCodeAt(i);
    hash |= 0;
  }
  return 'fp_' + Math.abs(hash).toString(16);
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`);
  return data;
}

async function checkSession() {
  try {
    const { user } = await api('/me');
    showDashboard(user);
  } catch {
    showLogin();
  }
}

// Navigation event listeners
document.getElementById('show-register').addEventListener('click', (e) => {
  e.preventDefault();
  showRegister();
});

document.getElementById('show-login').addEventListener('click', (e) => {
  e.preventDefault();
  showLogin();
});

document.getElementById('cancel-otp-btn').addEventListener('click', (e) => {
  e.preventDefault();
  showLogin();
});

document.getElementById('alert-back-btn').addEventListener('click', (e) => {
  e.preventDefault();
  showLogin();
});

// Registration Flow
document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showStatus('');

  const email = document.getElementById('register-email').value.trim();
  const username = document.getElementById('register-username').value.trim();
  const firstName = document.getElementById('register-first-name').value.trim();
  const lastName = document.getElementById('register-last-name').value.trim();
  const workStartHour = parseInt(document.getElementById('register-start-hour').value, 10);
  const workEndHour = parseInt(document.getElementById('register-end-hour').value, 10);

  try {
    if (!browserSupportsWebAuthn()) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    const fingerprint = getBrowserFingerprint();

    const options = await api('/auth/register/start', {
      method: 'POST',
      body: { email, username, firstName, lastName, workStartHour, workEndHour, fingerprint },
    });

    const credential = await startRegistration({ optionsJSON: options });

    await api('/auth/register/finish', {
      method: 'POST',
      body: { email, challenge: options.challenge, credential },
    });

    showStatus('Passkey enrolled successfully with RBA baseline! Please sign in.', true);
    document.getElementById('register-form').reset();
    showLogin();
  } catch (err) {
    showStatus(err.message || 'Registration failed');
  }
});

// Login Flow with RBA Decision Evaluation
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showStatus('');

  const identifier = document.getElementById('login-identifier').value.trim();
  if (!identifier) return showStatus('Please enter your username or email');

  try {
    if (!browserSupportsWebAuthn()) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    const options = await api('/auth/login/start', {
      method: 'POST',
      body: { identifier },
    });

    const credential = await startAuthentication({ optionsJSON: options });
    const currentSignals = {
      fingerprint: getBrowserFingerprint(),
      clientHour: new Date().getHours(),
    };

    const decision = await api('/auth/login/finish', {
      method: 'POST',
      body: { identifier, challenge: options.challenge, credential, currentSignals },
    });

    if (decision.riskLevel === 'LOW') {
      showStatus('Direct access granted via Passkey.', true);
      await checkSession();
    } else if (decision.riskLevel === 'MEDIUM') {
      showOtpView(decision.message + (decision.debugOtp ? ` [Test OTP: ${decision.debugOtp}]` : ''));
    }
  } catch (err) {
    if (err.message && err.message.includes('Security alert')) {
      showAlertView(err.message);
    } else {
      showStatus(err.message || 'Login failed');
    }
  }
});

// Verify Step-Up OTP
document.getElementById('otp-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const otpCode = document.getElementById('otp-input').value.trim();
  if (!otpCode) return showStatus('Please enter the OTP code');

  try {
    const res = await api('/auth/verify-step-up-otp', {
      method: 'POST',
      body: { otpCode },
    });

    showStatus(res.message, true);
    showDashboard(res.user);
  } catch (err) {
    showStatus(err.message || 'Invalid or expired OTP code');
  }
});

// Logout
document.getElementById('logout-btn').addEventListener('click', async () => {
  try {
    await api('/auth/logout', { method: 'POST' });
    showStatus('Logged out');
    showLogin();
  } catch (err) {
    showStatus(err.message || 'Logout failed');
  }
});

checkSession();