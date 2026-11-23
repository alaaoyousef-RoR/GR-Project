require('dotenv').config();

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DB_PATH ? path.resolve(__dirname, process.env.DB_PATH) : path.join(__dirname, 'passkeys.db');

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new Database(DB_PATH);

function tableExists(name) {
  const row = db.prepare(
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
  ).get(name);
  return !!row;
}

function getColumnInfo(tableName, columnName) {
  return db.prepare(`PRAGMA table_info(${tableName})`).all().find(c => c.name === columnName);
}

function addColumnIfNotExists(tableName, columnName, definition) {
  if (!getColumnInfo(tableName, columnName)) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
}

function initUsersTable() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      user_handle TEXT UNIQUE NOT NULL,
      work_start_hour INTEGER DEFAULT 8,
      work_end_hour INTEGER DEFAULT 17,
      baseline_fingerprint TEXT,
      baseline_city TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function initCredentialsTable() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      credential_id TEXT UNIQUE NOT NULL,
      public_key BLOB NOT NULL,
      sign_count INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      device_type TEXT,
      backed_up INTEGER,
      registered_ip TEXT,
      registered_country TEXT,
      registered_city TEXT,
      last_login_ip TEXT,
      last_login_country TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
}

function initChallengesTable() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS challenges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      challenge TEXT NOT NULL,
      purpose TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
}

function initOtpsTable() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      otp_code TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
}

initUsersTable();
initCredentialsTable();
initChallengesTable();
initOtpsTable();

// Ensure RBA columns exist for existing databases
addColumnIfNotExists('users', 'work_start_hour', 'INTEGER DEFAULT 8');
addColumnIfNotExists('users', 'work_end_hour', 'INTEGER DEFAULT 17');
addColumnIfNotExists('users', 'baseline_fingerprint', 'TEXT');
addColumnIfNotExists('users', 'baseline_city', 'TEXT');
addColumnIfNotExists('credentials', 'registered_city', 'TEXT');

function cleanExpiredChallenges() {
  db.prepare("DELETE FROM challenges WHERE created_at < datetime('now', '-5 minutes')").run();
}

function cleanExpiredOtps() {
  db.prepare("DELETE FROM otps WHERE expires_at < datetime('now')").run();
}

function createUser({ email, username, firstName, lastName, userHandle, workStartHour, workEndHour, baselineFingerprint, baselineCity }) {
  const result = db.prepare(
    `INSERT INTO users (
      email, username, first_name, last_name, user_handle, 
      work_start_hour, work_end_hour, baseline_fingerprint, baseline_city
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    email,
    username,
    firstName,
    lastName,
    userHandle,
    workStartHour !== undefined ? workStartHour : 8,
    workEndHour !== undefined ? workEndHour : 17,
    baselineFingerprint || null,
    baselineCity || null
  );
  return db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
}

function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

function getUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function getUserByIdentifier(identifier) {
  return identifier.includes('@') ? getUserByEmail(identifier) : getUserByUsername(identifier);
}

function createCredential({ userId, credentialId, publicKey, signCount, transports, deviceType, backedUp, registeredIp, registeredCountry, registeredCity }) {
  const result = db.prepare(
    `INSERT INTO credentials (
      user_id, credential_id, public_key, sign_count, transports, device_type, backed_up, registered_ip, registered_country, registered_city
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    userId,
    credentialId,
    publicKey,
    signCount,
    JSON.stringify(transports || []),
    deviceType,
    backedUp ? 1 : 0,
    registeredIp || null,
    registeredCountry || null,
    registeredCity || null
  );
  return result.lastInsertRowid;
}

function getCredentialByCredentialId(credentialId) {
  return db.prepare('SELECT * FROM credentials WHERE credential_id = ?').get(credentialId);
}

function getCredentialsByUserId(userId) {
  return db.prepare('SELECT * FROM credentials WHERE user_id = ?').all(userId);
}

function updateCredentialLoginInfo(credentialId, signCount, lastLoginIp, lastLoginCountry) {
  db.prepare(
    'UPDATE credentials SET sign_count = ?, last_login_ip = ?, last_login_country = ? WHERE credential_id = ?'
  ).run(signCount, lastLoginIp || null, lastLoginCountry || null, credentialId);
}

function createChallenge({ userId, challenge, purpose }) {
  cleanExpiredChallenges();
  const result = db.prepare(
    'INSERT INTO challenges (user_id, challenge, purpose) VALUES (?, ?, ?)'
  ).run(userId, challenge, purpose);
  return result.lastInsertRowid;
}

function consumeChallenge({ userId, purpose, challenge }) {
  cleanExpiredChallenges();
  const row = userId == null
    ? db.prepare('SELECT * FROM challenges WHERE user_id IS NULL AND purpose = ? AND challenge = ?').get(purpose, challenge)
    : db.prepare('SELECT * FROM challenges WHERE user_id = ? AND purpose = ? AND challenge = ?').get(userId, purpose, challenge);
  if (!row) return null;
  db.prepare('DELETE FROM challenges WHERE id = ?').run(row.id);
  return row;
}

// OTP Operations
function storeOtp(userId, otpCode) {
  cleanExpiredOtps();
  db.prepare('DELETE FROM otps WHERE user_id = ?').run(userId);
  db.prepare(
    "INSERT INTO otps (user_id, otp_code, expires_at) VALUES (?, ?, datetime('now', '+5 minutes'))"
  ).run(userId, otpCode);
}

function verifyOtp(userId, otpCode) {
  cleanExpiredOtps();
  const row = db.prepare(
    "SELECT * FROM otps WHERE user_id = ? AND otp_code = ? AND expires_at > datetime('now')"
  ).get(userId, otpCode);
  if (!row) return false;
  db.prepare('DELETE FROM otps WHERE id = ?').run(row.id);
  return true;
}

module.exports = {
  db,
  createUser,
  getUserByEmail,
  getUserByUsername,
  getUserById,
  getUserByIdentifier,
  createCredential,
  getCredentialByCredentialId,
  getCredentialsByUserId,
  updateCredentialLoginInfo,
  createChallenge,
  consumeChallenge,
  storeOtp,
  verifyOtp,
};