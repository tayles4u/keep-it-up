// server.js — Keep it up! backend. Pure Node.js (http + node:sqlite), no npm install required.
// Run with:  node server.js
// Requires Node.js 22.5+ for node:sqlite. See README.md for deployment notes.
'use strict';
const http = require('node:http');
const db = require('./db.js');
const { hashPassword, verifyPassword, newToken, newId, newJoinCode, hashToken } = require('./auth.js');

const PORT = process.env.PORT || 8787;
const MAX_BODY_BYTES = 8 * 1024 * 1024; // 8MB cap (mp3/wav uploads land here later; keep sane for now)
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*'; // lock this down to your real frontend URL once you're live
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const STRIPE_SECRET_KEY = (process.env.STRIPE_SECRET_KEY || '').trim();
const STRIPE_WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET || '').trim();

// ---------- rate limiting (in-memory — fine for a single instance; use Redis if you ever scale to several) ----------
const rateBuckets = new Map(); // key -> { count, resetAt }
function rateLimited(key, max, windowMs) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now > bucket.resetAt) { bucket = { count: 0, resetAt: now + windowMs }; rateBuckets.set(key, bucket); }
  bucket.count += 1;
  return bucket.count > max;
}
function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}
// Sweep old buckets every 10 minutes so this Map doesn't grow forever on a long-running server.
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) { if (now > bucket.resetAt) rateBuckets.delete(key); }
}, 10 * 60 * 1000);

// ---------- tiny helpers ----------
function sendNoBody(res, status) {
  res.writeHead(status, {
    'Access-Control-Allow-Origin': CORS_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS'
  });
  res.end(); // 204 must not have a body — some browsers reject CORS preflights that do
}
function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': CORS_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS'
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new Error('Body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}
function getAuthUser(req) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  const row = db.prepare(`
    SELECT u.* FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token = ?
  `).get(token);
  return row || null;
}
function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, provider: u.provider, joinCode: u.join_code, username: u.username || null };
}
function slugifyUsername(raw) {
  return String(raw || '').toLowerCase().trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 30) || 'user';
}
function generateUniqueUsername(base) {
  const slug = slugifyUsername(base);
  let candidate = slug;
  let n = 1;
  while (db.prepare('SELECT id FROM users WHERE username = ?').get(candidate)) {
    n += 1;
    candidate = slug + '-' + n;
  }
  return candidate;
}

// ---------- route handlers ----------
const routes = [];
function route(method, pattern, handler) {
  // pattern like '/api/shows/:id/end' -> regex + param names
  const paramNames = [];
  const regex = new RegExp('^' + pattern.replace(/:[^/]+/g, (m) => { paramNames.push(m.slice(1)); return '([^/]+)'; }) + '$');
  routes.push({ method, regex, paramNames, handler });
}

// ----- Stripe (raw REST calls via fetch — no npm dependency, same style as the rest of this server) -----
const STRIPE_API_VERSION = '2026-01-28.clover';
async function stripeRequestV2(method, path, body) {
  if (!STRIPE_SECRET_KEY) throw new Error('Stripe is not configured on this server yet.');
  const headers = {
    'Authorization': 'Basic ' + Buffer.from(STRIPE_SECRET_KEY + ':').toString('base64'),
    'Stripe-Version': STRIPE_API_VERSION,
    'Content-Type': 'application/json'
  };
  const res = await fetch('https://api.stripe.com' + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json();
  if (!res.ok) throw new Error((data.error && data.error.message) || 'Stripe request failed.');
  return data;
}
function requestOrigin(req) {
  const raw = req.headers.origin;
  return (raw && raw !== 'null' && /^https?:\/\//.test(raw)) ? raw : (process.env.WEB_URL || 'http://localhost:8787');
}

route('POST', '/api/stripe/connect', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  try {
    let accountId = user.stripe_account_id;
    if (!accountId) {
      // 'recipient' configuration = this account only ever receives transferred funds and gets paid out —
      // it never processes its own card charges, which keeps the onboarding form as short as possible.
      const account = await stripeRequestV2('POST', '/v2/core/accounts', {
        contact_email: user.email,
        display_name: user.name,
        dashboard: 'express',
        identity: { country: 'de' },
        configuration: {
          recipient: { capabilities: { stripe_balance: { stripe_transfers: { requested: true } } } }
        },
        defaults: {
          currency: 'eur',
          responsibilities: { fees_collector: 'application', losses_collector: 'application' },
          locales: ['de-DE']
        },
        include: ['configuration.recipient']
      });
      accountId = account.id;
      db.prepare('UPDATE users SET stripe_account_id=? WHERE id=?').run(accountId, user.id);
    }
    const origin = requestOrigin(req);
    const link = await stripeRequestV2('POST', '/v2/core/account_links', {
      account: accountId,
      use_case: {
        type: 'account_onboarding',
        account_onboarding: {
          configurations: ['recipient'],
          refresh_url: origin + '/?stripe_refresh=1',
          return_url: origin + '/?stripe_return=1'
        }
      }
    });
    sendJSON(res, 200, { url: link.url });
  } catch (e) { sendJSON(res, 500, { error: e.message }); }
});

route('GET', '/api/stripe/status', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  if (!user.stripe_account_id) return sendJSON(res, 200, { connected: false });
  try {
    const account = await stripeRequestV2('GET', '/v2/core/accounts/' + user.stripe_account_id + '?include[]=configuration.recipient&include[]=requirements');
    const recipientCap = account.configuration && account.configuration.recipient && account.configuration.recipient.capabilities;
    const transferStatus = recipientCap && recipientCap.stripe_balance && recipientCap.stripe_balance.stripe_transfers && recipientCap.stripe_balance.stripe_transfers.status;
    const payoutsEnabled = transferStatus === 'active';
    const currentlyDue = (account.requirements && account.requirements.currently_due) || [];
    db.prepare('UPDATE users SET stripe_payouts_enabled=? WHERE id=?').run(payoutsEnabled ? 1 : 0, user.id);
    sendJSON(res, 200, {
      connected: true,
      payoutsEnabled,
      chargesEnabled: payoutsEnabled,
      detailsSubmitted: currentlyDue.length === 0
    });
  } catch (e) { sendJSON(res, 500, { error: e.message }); }
});

// ----- auth -----
async function verifyGoogleIdToken(idToken) {
  const res = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken));
  if (!res.ok) throw new Error('Could not verify Google sign-in.');
  const payload = await res.json();
  if (payload.aud !== GOOGLE_CLIENT_ID) throw new Error('This Google sign-in was not issued for this app.');
  if (payload.email_verified !== 'true' && payload.email_verified !== true) throw new Error('Your Google email is not verified.');
  return payload;
}

route('POST', '/api/auth/google', async (req, res) => {
  if (!GOOGLE_CLIENT_ID) return sendJSON(res, 500, { error: 'Google sign-in is not configured on this server yet.' });
  if (rateLimited('google-auth:' + clientIp(req), 20, 15 * 60 * 1000)) {
    return sendJSON(res, 429, { error: 'Too many attempts. Try again later.' });
  }
  const body = await readBody(req);
  const idToken = String(body.credential || '');
  if (!idToken) return sendJSON(res, 400, { error: 'Missing Google credential.' });

  let payload;
  try { payload = await verifyGoogleIdToken(idToken); }
  catch (e) { return sendJSON(res, 401, { error: e.message || 'Could not verify Google sign-in.' }); }

  const email = String(payload.email || '').trim().toLowerCase();
  if (!email) return sendJSON(res, 400, { error: 'Google did not provide an email address.' });
  const name = String(payload.name || email.split('@')[0]).trim();

  let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    const username = generateUniqueUsername(name);
    user = { id: newId(), email, name, provider: 'google', join_code: newJoinCode(), username, created_at: Date.now() };
    db.prepare(`INSERT INTO users (id,email,password_hash,password_salt,name,provider,join_code,username,created_at)
                VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(user.id, user.email, null, null, user.name, user.provider, user.join_code, user.username, user.created_at);
  }
  const token = newToken();
  db.prepare('INSERT INTO tokens (token,user_id,created_at) VALUES (?,?,?)').run(token, user.id, Date.now());
  sendJSON(res, 200, { token, user: publicUser(user) });
});

route('POST', '/api/signup', async (req, res) => {
  if (rateLimited('signup:' + clientIp(req), 5, 60 * 60 * 1000)) {
    return sendJSON(res, 429, { error: 'Too many accounts created from this connection. Try again later.' });
  }
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const name = String(body.name || '').trim() || email.split('@')[0];
  if (!email || !password) return sendJSON(res, 400, { error: 'Email and password are required.' });
  if (password.length < 6) return sendJSON(res, 400, { error: 'Password must be at least 6 characters.' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return sendJSON(res, 409, { error: 'An account with that email already exists.' });
  const { hash, salt } = hashPassword(password);
  const username = generateUniqueUsername(name);
  const user = {
    id: newId(), email, name, provider: 'local',
    join_code: newJoinCode(), username, created_at: Date.now()
  };
  db.prepare(`INSERT INTO users (id,email,password_hash,password_salt,name,provider,join_code,username,created_at)
              VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(user.id, user.email, hash, salt, user.name, user.provider, user.join_code, user.username, user.created_at);
  const token = newToken();
  db.prepare('INSERT INTO tokens (token,user_id,created_at) VALUES (?,?,?)').run(token, user.id, Date.now());
  sendJSON(res, 201, { token, user: publicUser(user) });
});

route('POST', '/api/login', async (req, res) => {
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  if (rateLimited('login:' + clientIp(req), 10, 15 * 60 * 1000)) {
    return sendJSON(res, 429, { error: 'Too many login attempts. Wait a few minutes and try again.' });
  }
  const password = String(body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !user.password_hash) return sendJSON(res, 401, { error: 'Invalid email or password.' });
  if (!verifyPassword(password, user.password_salt, user.password_hash)) {
    return sendJSON(res, 401, { error: 'Invalid email or password.' });
  }
  const token = newToken();
  db.prepare('INSERT INTO tokens (token,user_id,created_at) VALUES (?,?,?)').run(token, user.id, Date.now());
  sendJSON(res, 200, { token, user: publicUser(user) });
});

route('POST', '/api/logout', async (req, res) => {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) db.prepare('DELETE FROM tokens WHERE token = ?').run(token);
  sendJSON(res, 200, { ok: true });
});

// ----- password reset -----
// Sends via a real provider if RESEND_API_KEY is set (see README); otherwise logs the link to
// the server console so the flow is fully testable without signing up for an email service.
async function sendPasswordResetEmail(toEmail, resetUrl) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.log('\n[password reset — no email provider configured, DEV MODE]');
    console.log('  To:', toEmail);
    console.log('  Link:', resetUrl, '\n');
    return;
  }
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: process.env.RESEND_FROM || 'Keep it up! <onboarding@resend.dev>',
        to: toEmail,
        subject: 'Reset your Keep it up! password',
        html: '<p>Someone requested a password reset for your Keep it up! account.</p>'
          + '<p><a href="' + resetUrl + '">Click here to set a new password</a> — this link expires in 1 hour.</p>'
          + '<p>If you did not request this, you can safely ignore this email — your password will not change.</p>'
      })
    });
  } catch (e) {
    console.error('Failed to send password reset email:', e.message);
    console.log('  Fallback — link was:', resetUrl);
  }
}

route('POST', '/api/request-password-reset', async (req, res) => {
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  if (rateLimited('pwreset:' + clientIp(req), 5, 60 * 60 * 1000)) {
    return sendJSON(res, 429, { error: 'Too many reset requests. Try again later.' });
  }
  // Always respond the same way whether or not the account exists — never let this endpoint
  // reveal which emails have accounts.
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (user && user.provider === 'local') {
    const rawToken = newToken();
    const tokenHash = hashToken(rawToken);
    const now = Date.now();
    db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(user.id); // old links stop working
    db.prepare('INSERT INTO password_resets (token_hash,user_id,created_at,expires_at,used) VALUES (?,?,?,?,0)')
      .run(tokenHash, user.id, now, now + 60 * 60 * 1000); // 1 hour
    const rawOrigin = req.headers.origin;
    const origin = (rawOrigin && rawOrigin !== 'null' && /^https?:\/\//.test(rawOrigin)) ? rawOrigin : (process.env.WEB_URL || 'http://localhost:8787');
    const resetUrl = origin + '/?reset=' + rawToken;
    await sendPasswordResetEmail(user.email, resetUrl);
  }
  sendJSON(res, 200, { ok: true, message: 'If that email has an account, a reset link is on its way.' });
});

route('POST', '/api/reset-password', async (req, res) => {
  const body = await readBody(req);
  const token = String(body.token || '');
  const newPassword = String(body.newPassword || '');
  if (!token) return sendJSON(res, 400, { error: 'Missing reset token.' });
  if (newPassword.length < 6) return sendJSON(res, 400, { error: 'Password must be at least 6 characters.' });
  const tokenHash = hashToken(token);
  const row = db.prepare('SELECT * FROM password_resets WHERE token_hash = ?').get(tokenHash);
  if (!row || row.used || Date.now() > row.expires_at) {
    return sendJSON(res, 400, { error: 'This reset link is invalid or has expired. Request a new one.' });
  }
  const { hash, salt } = hashPassword(newPassword);
  db.prepare('UPDATE users SET password_hash=?, password_salt=? WHERE id=?').run(hash, salt, row.user_id);
  db.prepare('UPDATE password_resets SET used=1 WHERE token_hash=?').run(tokenHash);
  db.prepare('DELETE FROM tokens WHERE user_id=?').run(row.user_id); // log out everywhere, for safety
  sendJSON(res, 200, { ok: true });
});

route('GET', '/api/me', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  sendJSON(res, 200, { user: publicUser(user) });
});

route('PATCH', '/api/me', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const body = await readBody(req);
  const name = String(body.name || '').trim();
  if (!name) return sendJSON(res, 400, { error: 'Enter a display name.' });
  let username = user.username;
  if (typeof body.username === 'string' && body.username.trim()) {
    const slug = slugifyUsername(body.username);
    if (slug.length < 3) return sendJSON(res, 400, { error: 'Username must be at least 3 characters.' });
    const existing = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(slug, user.id);
    if (existing) return sendJSON(res, 409, { error: 'That username is already taken.' });
    username = slug;
  }
  db.prepare('UPDATE users SET name = ?, username = ? WHERE id = ?').run(name, username, user.id);
  sendJSON(res, 200, { user: publicUser(Object.assign({}, user, { name, username })) });
});

// ----- shows (host side, requires auth) -----
route('POST', '/api/shows', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const already = db.prepare(`SELECT id FROM shows WHERE user_id = ? AND status = 'live'`).get(user.id);
  if (already) return sendJSON(res, 409, { error: 'You already have a live show. End it before starting a new one.' });
  const body = await readBody(req);
  const title = String(body.title || '').trim() || 'Untitled Session';
  const defaultSettings = { streamType: 'list', skipFee: 5, entryFeeEnabled: false, entryFee: 2, cap: null, skipsEnabled: true, acceptingSubmissions: true };
  const show = {
    id: newId(), user_id: user.id, title, status: 'live',
    settings_json: JSON.stringify(Object.assign(defaultSettings, body.settings || {})),
    started_at: Date.now(), ended_at: null, total_participants: 0
  };
  db.prepare(`INSERT INTO shows (id,user_id,title,status,settings_json,started_at,ended_at,total_participants)
              VALUES (?,?,?,?,?,?,?,?)`)
    .run(show.id, show.user_id, show.title, show.status, show.settings_json, show.started_at, show.ended_at, show.total_participants);
  sendJSON(res, 201, { show: showToJSON(show) });
});

route('GET', '/api/shows/current', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare(`SELECT * FROM shows WHERE user_id = ? AND status = 'live'`).get(user.id);
  if (!show) return sendJSON(res, 200, { show: null, queue: [] });
  const queue = db.prepare(`SELECT * FROM queue_items WHERE show_id = ? AND status='queued' ORDER BY position ASC`).all(show.id);
  const earn = db.prepare(`SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE show_id=? AND status!='payout'`).get(show.id).total;
  sendJSON(res, 200, { show: Object.assign(showToJSON(show), { earnings: earn }), queue: queue.map(queueToJSON) });
});

route('POST', '/api/shows/:id/end', async (req, res, params) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare('SELECT * FROM shows WHERE id = ? AND user_id = ?').get(params.id, user.id);
  if (!show) return sendJSON(res, 404, { error: 'Show not found.' });
  db.prepare(`UPDATE shows SET status='ended', ended_at=? WHERE id=?`).run(Date.now(), show.id);
  db.prepare(`UPDATE transactions SET status='available' WHERE show_id=? AND status='pending'`).run(show.id);
  sendJSON(res, 200, { ok: true });
});

route('GET', '/api/shows/history', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const rows = db.prepare(`SELECT * FROM shows WHERE user_id = ? AND status='ended' ORDER BY ended_at DESC`).all(user.id);
  const withEarnings = rows.map(s => {
    const earn = db.prepare(`SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE show_id=? AND status!='payout'`).get(s.id).total;
    const songs = db.prepare(`SELECT * FROM queue_items WHERE show_id=? AND status='played' ORDER BY joined_at ASC`).all(s.id);
    return Object.assign(showToJSON(s), {
      earnings: earn, songs: songs.map(queueToJSON),
      durationSec: s.ended_at ? Math.floor((s.ended_at - s.started_at) / 1000) : 0
    });
  });
  sendJSON(res, 200, { history: withEarnings });
});

// ----- Bracket Wars engine -----
function nextPowerOfTwo(n) { let p = 1; while (p < n) p *= 2; return p; }
function resolveByes(round) {
  round.forEach(m => { if (!m.winner) { if (m.a && !m.b) m.winner = m.a; else if (m.b && !m.a) m.winner = m.b; } });
}
function currentBracketMatch(bracket) {
  const round = bracket.rounds[bracket.roundIndex];
  for (let i = 0; i < round.length; i++) { if (!round[i].winner) return round[i]; }
  return null;
}
function advanceBracketIfRoundDone(bracket) {
  let round = bracket.rounds[bracket.roundIndex];
  while (round.every(m => !!m.winner)) {
    const winners = round.map(m => m.winner);
    if (winners.length === 1) { bracket.champion = winners[0]; return; }
    const nextRound = [];
    for (let i = 0; i < winners.length; i += 2) nextRound.push({ a: winners[i], b: winners[i + 1] || null, winner: null });
    resolveByes(nextRound);
    bracket.rounds.push(nextRound);
    bracket.roundIndex++;
    round = bracket.rounds[bracket.roundIndex];
  }
}

route('POST', '/api/shows/:id/bracket/start', async (req, res, params) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare('SELECT * FROM shows WHERE id=? AND user_id=?').get(params.id, user.id);
  if (!show) return sendJSON(res, 404, { error: 'Show not found.' });
  if (show.bracket_json) {
    const existing = JSON.parse(show.bracket_json);
    if (!existing.champion) return sendJSON(res, 409, { error: 'A bracket is already running — finish it or cancel it first.' });
    // previous bracket is done; archive its parked entries so they can't be confused with the new one
    db.prepare(`UPDATE queue_items SET status='bracket_done' WHERE show_id=? AND status='bracket'`).run(show.id);
  }
  const queue = db.prepare(`SELECT * FROM queue_items WHERE show_id=? AND status='queued' ORDER BY position ASC`).all(show.id);
  if (queue.length < 2) return sendJSON(res, 409, { error: 'Need at least 2 tracks queued to start a bracket.' });

  let entries = queue.map(queueToJSON);
  for (let i = entries.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); const tmp = entries[i]; entries[i] = entries[j]; entries[j] = tmp; }
  const size = nextPowerOfTwo(entries.length);
  while (entries.length < size) entries.push(null);
  const round0 = [];
  for (let i = 0; i < entries.length; i += 2) round0.push({ a: entries[i], b: entries[i + 1], winner: null });
  resolveByes(round0);
  const bracket = { rounds: [round0], roundIndex: 0, champion: null };
  advanceBracketIfRoundDone(bracket);

  db.prepare(`UPDATE queue_items SET status='bracket' WHERE show_id=? AND status='queued'`).run(show.id);
  db.prepare(`UPDATE shows SET bracket_json=? WHERE id=?`).run(JSON.stringify(bracket), show.id);
  sendJSON(res, 200, { bracket });
});

route('POST', '/api/shows/:id/bracket/pick', async (req, res, params) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare('SELECT * FROM shows WHERE id=? AND user_id=?').get(params.id, user.id);
  if (!show) return sendJSON(res, 404, { error: 'Show not found.' });
  if (!show.bracket_json) return sendJSON(res, 409, { error: 'No bracket running.' });
  const bracket = JSON.parse(show.bracket_json);
  if (bracket.champion) return sendJSON(res, 409, { error: 'Bracket already finished.' });
  const body = await readBody(req);
  const match = currentBracketMatch(bracket);
  if (!match) return sendJSON(res, 409, { error: 'No active match.' });
  const chosen = body.side === 'a' ? match.a : body.side === 'b' ? match.b : null;
  if (!chosen) return sendJSON(res, 400, { error: 'Invalid pick.' });
  match.winner = chosen;
  advanceBracketIfRoundDone(bracket);
  db.prepare(`UPDATE shows SET bracket_json=? WHERE id=?`).run(JSON.stringify(bracket), show.id);
  sendJSON(res, 200, { bracket });
});

route('POST', '/api/shows/:id/bracket/cancel', async (req, res, params) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare('SELECT * FROM shows WHERE id=? AND user_id=?').get(params.id, user.id);
  if (!show) return sendJSON(res, 404, { error: 'Show not found.' });
  const bracket = show.bracket_json ? JSON.parse(show.bracket_json) : null;
  if (bracket && !bracket.champion) {
    // unfinished — give everyone still parked in it their spot back in the live queue
    const parked = db.prepare(`SELECT * FROM queue_items WHERE show_id=? AND status='bracket' ORDER BY joined_at ASC`).all(show.id);
    const already = db.prepare(`SELECT COUNT(*) AS c FROM queue_items WHERE show_id=? AND status='queued'`).get(show.id).c;
    parked.forEach((item, i) => { db.prepare(`UPDATE queue_items SET status='queued', position=? WHERE id=?`).run(already + i, item.id); });
  } else {
    // already finished (or nothing running) — just archive any leftover rows, don't resurrect past participants
    db.prepare(`UPDATE queue_items SET status='bracket_done' WHERE show_id=? AND status='bracket'`).run(show.id);
  }
  db.prepare(`UPDATE shows SET bracket_json=NULL WHERE id=?`).run(show.id);
  sendJSON(res, 200, { ok: true });
});

// ----- queue management (host side) -----
route('POST', '/api/shows/:id/queue/:itemId/played', async (req, res, params) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare('SELECT * FROM shows WHERE id=? AND user_id=?').get(params.id, user.id);
  if (!show) return sendJSON(res, 404, { error: 'Show not found.' });
  db.prepare(`UPDATE queue_items SET status='played' WHERE id=? AND show_id=?`).run(params.itemId, show.id);
  sendJSON(res, 200, { ok: true });
});

route('DELETE', '/api/shows/:id/queue/:itemId', async (req, res, params) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare('SELECT * FROM shows WHERE id=? AND user_id=?').get(params.id, user.id);
  if (!show) return sendJSON(res, 404, { error: 'Show not found.' });
  db.prepare(`UPDATE queue_items SET status='removed' WHERE id=? AND show_id=?`).run(params.itemId, show.id);
  sendJSON(res, 200, { ok: true });
});

route('POST', '/api/shows/:id/queue/:itemId/ban', async (req, res, params) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare('SELECT * FROM shows WHERE id=? AND user_id=?').get(params.id, user.id);
  if (!show) return sendJSON(res, 404, { error: 'Show not found.' });
  const item = db.prepare('SELECT * FROM queue_items WHERE id=? AND show_id=?').get(params.itemId, show.id);
  if (!item) return sendJSON(res, 404, { error: 'Not found.' });
  db.prepare(`UPDATE queue_items SET status='removed' WHERE id=? AND show_id=?`).run(params.itemId, show.id);
  db.prepare(`INSERT INTO show_bans (id,show_id,name_lower,created_at) VALUES (?,?,?,?)`)
    .run(newId(), show.id, item.name.toLowerCase(), Date.now());
  sendJSON(res, 200, { ok: true });
});

route('PATCH', '/api/shows/:id/settings', async (req, res, params) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const show = db.prepare('SELECT * FROM shows WHERE id=? AND user_id=?').get(params.id, user.id);
  if (!show) return sendJSON(res, 404, { error: 'Show not found.' });
  const patch = await readBody(req);
  const settings = Object.assign(JSON.parse(show.settings_json), patch);
  db.prepare(`UPDATE shows SET settings_json=? WHERE id=?`).run(JSON.stringify(settings), show.id);
  sendJSON(res, 200, { settings });
});

// ----- finances (host side) -----
route('GET', '/api/transactions', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const rows = db.prepare(`
    SELECT t.*, s.title AS session_title FROM transactions t
    LEFT JOIN shows s ON s.id = t.show_id
    WHERE t.user_id = ? ORDER BY t.date DESC
  `).all(user.id);
  sendJSON(res, 200, { transactions: rows.map(tx => ({
    id: tx.id, date: tx.date, type: tx.type, amount: tx.amount, status: tx.status,
    sessionId: tx.show_id, sessionTitle: tx.session_title || '—'
  })) });
});

route('POST', '/api/payout', async (req, res) => {
  const user = getAuthUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
  const row = db.prepare(`SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE user_id=? AND status='available'`).get(user.id);
  const available = row.total;
  if (available <= 0) return sendJSON(res, 409, { error: 'Nothing ready to cash out yet.' });
  db.prepare(`UPDATE transactions SET status='paid_out' WHERE user_id=? AND status='available'`).run(user.id);
  db.prepare(`INSERT INTO transactions (id,user_id,show_id,type,amount,status,date) VALUES (?,?,?,?,?,?,?)`)
    .run(newId(), user.id, null, 'payout', -available, 'payout', Date.now());
  sendJSON(res, 200, { ok: true, amount: available });
});

// ----- public fan-facing endpoints (no auth; resolved via join code) -----
function findUserByCodeOrUsername(value) {
  return db.prepare('SELECT * FROM users WHERE join_code = ? OR username = ?').get(value, value);
}

route('GET', '/api/public/:joinCode', async (req, res, params) => {
  const user = findUserByCodeOrUsername(params.joinCode);
  if (!user) return sendJSON(res, 404, { error: 'Invalid link.' });
  const show = db.prepare(`SELECT * FROM shows WHERE user_id=? AND status='live'`).get(user.id);
  if (!show) return sendJSON(res, 200, { live: false });
  const settings = JSON.parse(show.settings_json);
  const queue = db.prepare(`SELECT * FROM queue_items WHERE show_id=? AND status='queued' ORDER BY position ASC`).all(show.id);
  const nowPlaying = queue[0] ? queueToJSON(queue[0]) : null;
  const url = new URL(req.url, `http://${req.headers.host}`);
  const participantId = url.searchParams.get('participant');
  let mine = null;
  if (participantId) {
    const idx = queue.findIndex(q => q.id === participantId);
    if (idx !== -1) {
      mine = { position: idx, isFirst: idx === 0, paidTotal: queue[idx].paid_total, leaderPaidTotal: queue[0].paid_total };
    }
  }
  sendJSON(res, 200, {
    live: true, title: show.title, queueCount: queue.length, nowPlaying,
    acceptingSubmissions: !!settings.acceptingSubmissions,
    entryFeeEnabled: !!settings.entryFeeEnabled, entryFee: settings.entryFee,
    skipsEnabled: !!settings.skipsEnabled, skipFee: settings.skipFee,
    cap: settings.cap, mine
  });
});

route('POST', '/api/public/:joinCode/join', async (req, res, params) => {
  const user = findUserByCodeOrUsername(params.joinCode);
  if (!user) return sendJSON(res, 404, { error: 'Invalid link.' });
  const show = db.prepare(`SELECT * FROM shows WHERE user_id=? AND status='live'`).get(user.id);
  if (!show) return sendJSON(res, 409, { error: 'This streamer is not live right now.' });
  const settings = JSON.parse(show.settings_json);
  if (!settings.acceptingSubmissions) return sendJSON(res, 409, { error: 'Submissions are paused right now.' });
  const count = db.prepare(`SELECT COUNT(*) AS c FROM queue_items WHERE show_id=? AND status='queued'`).get(show.id).c;
  if (settings.cap && count >= settings.cap) return sendJSON(res, 409, { error: 'Queue is full.' });

  const body = await readBody(req);
  const name = String(body.name || '').trim();
  const song = String(body.song || '').trim();
  const note = String(body.note || '').trim();
  if (!name) return sendJSON(res, 400, { error: 'A name is required.' });
  const banned = db.prepare(`SELECT id FROM show_bans WHERE show_id=? AND name_lower=?`).get(show.id, name.toLowerCase());
  if (banned) return sendJSON(res, 403, { error: 'You have been banned from this show.' });
  if (!song) return sendJSON(res, 400, { error: 'A link is required.' });
  if (!/^https?:\/\//i.test(song)) return sendJSON(res, 400, { error: 'That doesn\'t look like a working link — it needs to start with http:// or https://' });
  const entry = settings.entryFeeEnabled ? Number(settings.entryFee || 0) : 0;
  const item = { id: newId(), show_id: show.id, name, song, note, paid_total: entry, position: count, status: 'queued', joined_at: Date.now() };
  db.prepare(`INSERT INTO queue_items (id,show_id,name,song,note,paid_total,position,status,joined_at)
              VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(item.id, item.show_id, item.name, item.song, item.note, item.paid_total, item.position, item.status, item.joined_at);
  db.prepare(`UPDATE shows SET total_participants = total_participants + 1 WHERE id=?`).run(show.id);
  if (entry > 0) {
    db.prepare(`INSERT INTO transactions (id,user_id,show_id,type,amount,status,date) VALUES (?,?,?,?,?,?,?)`)
      .run(newId(), user.id, show.id, 'entry_fee', entry, 'pending', Date.now());
  }
  sendJSON(res, 201, { participantId: item.id });
});

route('POST', '/api/public/:joinCode/skip', async (req, res, params) => {
  const user = findUserByCodeOrUsername(params.joinCode);
  if (!user) return sendJSON(res, 404, { error: 'Invalid link.' });
  const show = db.prepare(`SELECT * FROM shows WHERE user_id=? AND status='live'`).get(user.id);
  if (!show) return sendJSON(res, 409, { error: 'Not live.' });
  const settings = JSON.parse(show.settings_json);
  if (!settings.skipsEnabled) return sendJSON(res, 409, { error: 'Skips are disabled.' });
  const body = await readBody(req);
  const queue = db.prepare(`SELECT * FROM queue_items WHERE show_id=? AND status='queued' ORDER BY position ASC`).all(show.id);
  const idx = queue.findIndex(q => q.id === body.participantId);
  if (idx === -1) return sendJSON(res, 404, { error: 'Not found.' });
  if (idx === 0) return sendJSON(res, 409, { error: "That song is already on stage — it can't be skipped." });
  if (idx === 1) return sendJSON(res, 409, { error: "You're already next in line." });
  const me = queue[idx];
  const cost = Number(settings.skipFee || 0);
  db.prepare(`UPDATE queue_items SET paid_total = paid_total + ? WHERE id=?`).run(cost, me.id);
  // Move to the very front of the on-deck line (position 1, right after whoever's on stage now) —
  // position 0 is never touched, so a payment can never interrupt the person currently playing.
  for (let i = idx - 1; i >= 1; i--) {
    db.prepare(`UPDATE queue_items SET position=? WHERE id=?`).run(i + 1, queue[i].id);
  }
  db.prepare(`UPDATE queue_items SET position=1 WHERE id=?`).run(me.id);
  db.prepare(`INSERT INTO transactions (id,user_id,show_id,type,amount,status,date) VALUES (?,?,?,?,?,?,?)`)
    .run(newId(), user.id, show.id, 'skip_fee', cost, 'pending', Date.now());
  sendJSON(res, 200, { ok: true, cost });
});

route('POST', '/api/public/:joinCode/jump', async (req, res, params) => {
  const user = findUserByCodeOrUsername(params.joinCode);
  if (!user) return sendJSON(res, 404, { error: 'Invalid link.' });
  const show = db.prepare(`SELECT * FROM shows WHERE user_id=? AND status='live'`).get(user.id);
  if (!show) return sendJSON(res, 409, { error: 'Not live.' });
  const settings = JSON.parse(show.settings_json);
  if (!settings.skipsEnabled) return sendJSON(res, 409, { error: 'Skips are disabled.' });
  const body = await readBody(req);
  const queue = db.prepare(`SELECT * FROM queue_items WHERE show_id=? AND status='queued' ORDER BY position ASC`).all(show.id);
  const idx = queue.findIndex(q => q.id === body.participantId);
  if (idx === -1) return sendJSON(res, 404, { error: 'Not found.' });
  if (idx === 0) return sendJSON(res, 409, { error: "That song is already on stage — it can't be skipped." });
  if (idx === 1) return sendJSON(res, 409, { error: "You're already next in line." });
  const me = queue[idx];
  const currentFirst = queue[1]; // whoever currently holds the front of the on-deck line, if anyone
  const skipFee = Number(settings.skipFee || 0);
  const cost = currentFirst
    ? Math.max(skipFee * 2, Math.round(((currentFirst.paid_total - me.paid_total) + skipFee * 2) * 2) / 2)
    : skipFee * 2;
  db.prepare(`UPDATE queue_items SET paid_total = paid_total + ? WHERE id=?`).run(cost, me.id);
  // Same rule as skip: only ever moves within on-deck (position 1+), position 0 stays untouched.
  for (let i = idx - 1; i >= 1; i--) {
    db.prepare(`UPDATE queue_items SET position=? WHERE id=?`).run(i + 1, queue[i].id);
  }
  db.prepare(`UPDATE queue_items SET position=1 WHERE id=?`).run(me.id);
  db.prepare(`INSERT INTO transactions (id,user_id,show_id,type,amount,status,date) VALUES (?,?,?,?,?,?,?)`)
    .run(newId(), user.id, show.id, 'overtake_fee', cost, 'pending', Date.now());
  sendJSON(res, 200, { ok: true, cost });
});

// ----- json helpers -----
function showToJSON(s) {
  return {
    id: s.id, title: s.title, status: s.status,
    settings: JSON.parse(s.settings_json),
    startedAt: s.started_at, endedAt: s.ended_at,
    totalParticipants: s.total_participants,
    bracket: s.bracket_json ? JSON.parse(s.bracket_json) : null
  };
}
function queueToJSON(q) {
  return { id: q.id, name: q.name, song: q.song, note: q.note, paidTotal: q.paid_total, position: q.position, status: q.status, joinedAt: q.joined_at };
}

route('GET', '/health', async (req, res) => { sendJSON(res, 200, { ok: true, time: Date.now() }); });

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return sendNoBody(res, 204);
  const url = new URL(req.url, `http://${req.headers.host}`);
  for (const r of routes) {
    if (r.method !== req.method) continue;
    const m = url.pathname.match(r.regex);
    if (!m) continue;
    const params = {};
    r.paramNames.forEach((name, i) => { params[name] = decodeURIComponent(m[i + 1]); });
    try {
      await r.handler(req, res, params);
    } catch (e) {
      console.error(e);
      sendJSON(res, 500, { error: 'Server error: ' + e.message });
    }
    return;
  }
  sendJSON(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`Keep it up! API listening on http://localhost:${PORT}`);
});

module.exports = server;
