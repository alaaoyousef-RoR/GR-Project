require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const https = require('https');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const geoip = require('geoip-lite');
const db = require('./db');

const app = express();

const PORT = parseInt(process.env.PORT || '3000', 10);
const RP_NAME = process.env.RP_NAME || 'Passkey RBA Demo';
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET || 'rba-super-secret-key';
const TLS_KEY_PATH = process.env.TLS_KEY_PATH ? path.resolve(process.env.TLS_KEY_PATH) : undefined;
const TLS_CERT_PATH = process.env.TLS_CERT_PATH ? path.resolve(process.env.TLS_CERT_PATH) : undefined;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: IS_PRODUCTION },
}));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.url} ${res.statusCode} ${Date.now() - start}ms`);
  });
  next();
});

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  return res.status(401).json({ error: 'Not authenticated' });
}

function base64urlEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

function base64urlDecode(str) {
  return Buffer.from(str, 'base64url');
}

function generateUserHandle() {
  return base64urlEncode(crypto.randomBytes(16));
}

function getTransports(row) {
  try {
    return JSON.parse(row.transports || '[]');
  } catch {
    return [];
  }
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.ip || req.connection.remoteAddress || '127.0.0.1';
}

function getGeoLocation(ip) {
  if (!ip || ip === '127.0.0.1' || ip === '::1') {
    return { country: 'Saudi Arabia', city: 'Riyadh' };
  }
  const geo = geoip.lookup(ip);
  return {
    country: geo && geo.country ? geo.country : 'Saudi Arabia',
    city: geo && geo.city ? geo.city : 'Riyadh',
  };
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ----------------------
// RBA EVALUATION ENGINE
// ----------------------
function evaluateRBA({ user, currentFingerprint, currentCity, currentHour }) {
  const isFingerprintMatch = Boolean(user.baseline_fingerprint && currentFingerprint && user.baseline_fingerprint === currentFingerprint);
  const isCityMatch = Boolean(user.baseline_city && currentCity && user.baseline_city.toLowerCase() === currentCity.toLowerCase());

  const start = user.work_start_hour !== undefined ? user.work_start_hour : 8;
  const end = user.work_end_hour !== undefined ? user.work_end_hour : 17;
  const isWithinSchedule = currentHour >= start && currentHour <= end;

  let deviations = 0;
  if (!isFingerprintMatch) deviations++;
  if (!isCityMatch) deviations++;
  if (!isWithinSchedule) deviations++;

  let riskLevel = 'LOW';
  let message = 'Access granted within established baseline.';

  if (deviations === 0) {
    riskLevel = 'LOW';
    message = 'Consistent context signals. Direct access granted.';
  } else if (deviations === 1) {
    riskLevel = 'MEDIUM';
    message = 'Single context deviation detected. Step-Up Email OTP required.';
  } else {
    riskLevel = 'HIGH';
    message = 'Two or more contextual deviations detected. Access denied.';
  }

  return {
    riskLevel,
    message,
    deviations,
    signals: {
      fingerprintMatch: isFingerprintMatch,
      cityMatch: isCityMatch,
      withinSchedule: isWithinSchedule,
      currentHour,
      currentCity,
    },
  };
}

// Session info
app.get('/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const user = db.getUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });
  res.json({
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.first_name,
      lastName: user.last_name,
    },
  });
});

// Registration: Start
app.post('/auth/register/start', async (req, res) => {
  try {
    const { email, username, firstName, lastName, workStartHour, workEndHour, fingerprint } = req.body;
    if (!email || !username || !firstName || !lastName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanUsername = username.trim();
    const cleanFirst = firstName.trim();
    const cleanLast = lastName.trim();

    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }

    if (db.getUserByEmail(cleanEmail)) {
      return res.status(409).json({ error: 'Email already in use' });
    }
    if (db.getUserByUsername(cleanUsername)) {
      return res.status(409).json({ error: 'Username already in use' });
    }

    const clientIp = getClientIp(req);
    const geo = getGeoLocation(clientIp);

    const userHandle = generateUserHandle();
    const user = db.createUser({
      email: cleanEmail,
      username: cleanUsername,
      firstName: cleanFirst,
      lastName: cleanLast,
      userHandle,
      workStartHour: parseInt(workStartHour, 10) || 8,
      workEndHour: parseInt(workEndHour, 10) || 17,
      baselineFingerprint: fingerprint || null,
      baselineCity: geo.city,
    });

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: base64urlDecode(user.user_handle),
      userName: cleanEmail,
      userDisplayName: `${cleanFirst} ${cleanLast}`,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7, -257, -8],
    });

    db.createChallenge({ userId: user.id, challenge: options.challenge, purpose: 'registration' });

    res.json(options);
  } catch (err) {
    console.error('register/start error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Registration: Finish
app.post('/auth/register/finish', async (req, res) => {
  try {
    const { email, challenge, credential } = req.body;
    if (!email || !challenge || !credential) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const user = db.getUserByEmail(email.trim().toLowerCase());
    if (!user) return res.status(400).json({ error: 'User not found' });

    const consumed = db.consumeChallenge({
      userId: user.id,
      purpose: 'registration',
      challenge,
    });
    if (!consumed) {
      return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Registration verification failed' });
    }

    const { credential: credInfo, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    const clientIp = getClientIp(req);
    const geo = getGeoLocation(clientIp);

    db.createCredential({
      userId: user.id,
      credentialId: credInfo.id,
      publicKey: Buffer.from(credInfo.publicKey),
      signCount: credInfo.counter,
      transports: credInfo.transports,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      registeredIp: clientIp,
      registeredCountry: geo.country,
      registeredCity: geo.city,
    });

    req.session.userId = user.id;
    res.json({ ok: true });
  } catch (err) {
    console.error('register/finish error:', err);
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

// Login: Start
app.post('/auth/login/start', async (req, res) => {
  try {
    const { identifier } = req.body;
    if (!identifier || typeof identifier !== 'string' || identifier.trim().length === 0) {
      return res.status(400).json({ error: 'Username or email required' });
    }

    const user = db.getUserByIdentifier(identifier.trim());
    if (!user) return res.status(400).json({ error: 'User not found' });

    const credentials = db.getCredentialsByUserId(user.id);
    if (credentials.length === 0) {
      return res.status(400).json({ error: 'No passkeys registered for this user' });
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: credentials.map(c => ({
        id: c.credential_id,
        transports: getTransports(c),
      })),
      userVerification: 'required',
    });

    db.createChallenge({ userId: user.id, challenge: options.challenge, purpose: 'login' });

    res.json(options);
  } catch (err) {
    console.error('login/start error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login: Finish (RBA Engine Evaluation)
app.post('/auth/login/finish', async (req, res) => {
  try {
    const { identifier, challenge, credential, currentSignals } = req.body;
    if (!identifier || !challenge || !credential) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const user = db.getUserByIdentifier(identifier.trim());
    if (!user) return res.status(400).json({ error: 'User not found' });

    const credRow = db.getCredentialByCredentialId(credential.id);
    if (!credRow || credRow.user_id !== user.id) {
      return res.status(400).json({ error: 'Credential not found' });
    }

    const consumed = db.consumeChallenge({
      userId: user.id,
      purpose: 'login',
      challenge,
    });
    if (!consumed) {
      return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: credRow.credential_id,
        publicKey: credRow.public_key,
        counter: credRow.sign_count,
        transports: getTransports(credRow),
      },
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Authentication verification failed' });
    }

    const loginIp = getClientIp(req);
    const geo = getGeoLocation(loginIp);
    db.updateCredentialLoginInfo(credRow.credential_id, verification.authenticationInfo.newCounter, loginIp, geo.country);

    // Contextual evaluation
    const clientHour = currentSignals && currentSignals.clientHour !== undefined
      ? parseInt(currentSignals.clientHour, 10)
      : new Date().getHours();
    const clientFp = currentSignals ? currentSignals.fingerprint : '';
    const clientCity = (currentSignals && currentSignals.city) || geo.city;

    const rbaResult = evaluateRBA({
      user,
      currentFingerprint: clientFp,
      currentCity: clientCity,
      currentHour: clientHour,
    });

    console.log(`[RBA Evaluation] User=${user.email} Risk=${rbaResult.riskLevel} Deviations=${rbaResult.deviations}`);

    if (rbaResult.riskLevel === 'LOW') {
      req.session.userId = user.id;
      return res.json({
        ok: true,
        riskLevel: 'LOW',
        action: 'DIRECT_ACCESS',
        message: rbaResult.message,
      });
    }

    if (rbaResult.riskLevel === 'MEDIUM') {
      // Generate 6-digit OTP
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
      db.storeOtp(user.id, otpCode);
      req.session.pendingUserId = user.id;

      // In real deployment send via email. Here we also output to console and return for demo testing:
      console.log(`\n========================================`);
      console.log(`[STEP-UP OTP] Verification code for ${user.email}: >>> ${otpCode} <<<`);
      console.log(`========================================\n`);

      return res.json({
        ok: true,
        riskLevel: 'MEDIUM',
        action: 'STEP_UP_CHALLENGE',
        message: rbaResult.message,
        debugOtp: otpCode, // Provided for live committee demonstration
      });
    }

    // High risk: Deny access completely
    return res.status(403).json({
      error: 'Security alert: Access denied due to anomalous context mismatch.',
      riskLevel: 'HIGH',
      action: 'DENY_ACCESS',
      message: rbaResult.message,
    });

  } catch (err) {
    console.error('login/finish error:', err);
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

// Verify Step-Up OTP
app.post('/auth/verify-step-up-otp', (req, res) => {
  const userId = req.session.pendingUserId;
  const { otpCode } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'No pending authentication session found' });
  }
  if (!otpCode) {
    return res.status(400).json({ error: 'OTP code is required' });
  }

  const isValid = db.verifyOtp(userId, otpCode.trim());
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid or expired OTP code' });
  }

  req.session.userId = userId;
  delete req.session.pendingUserId;

  const user = db.getUserById(userId);
  res.json({
    ok: true,
    message: 'OTP verified successfully. Access granted.',
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.first_name,
      lastName: user.last_name,
    },
  });
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// Start server
const startServer = () => {
  app.listen(PORT, () => {
    console.log(`HTTP server running at ${ORIGIN || `http://localhost:${PORT}`}`);
  });
};

startServer();
