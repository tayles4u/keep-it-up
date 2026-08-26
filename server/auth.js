// auth.js — real password hashing (scrypt + per-user salt) and bearer tokens.
'use strict';
const crypto = require('node:crypto');

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPassword(password, salt, expectedHash) {
  const { hash } = hashPassword(password, salt);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(expectedHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b); // constant-time compare, avoids timing attacks
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function newId() {
  return crypto.randomUUID();
}

function newJoinCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 6; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

// Reset tokens are stored as a hash (like passwords) — never store the raw token server-side,
// so a database leak alone can't be replayed to take over accounts.
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { hashPassword, verifyPassword, newToken, newId, newJoinCode, hashToken };
