// db.js — SQLite persistence layer, using Node's built-in node:sqlite (no npm install needed).
// Requires Node.js 22.5+. If your Node is older, see README.md for the better-sqlite3 swap.
'use strict';
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'keepitup.db');
const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    password_salt TEXT,
    name          TEXT NOT NULL,
    provider      TEXT NOT NULL DEFAULT 'local',
    join_code     TEXT UNIQUE NOT NULL,
    username      TEXT UNIQUE,
    created_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS shows (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title               TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'live', -- live | ended
    settings_json       TEXT NOT NULL,
    started_at          INTEGER NOT NULL,
    ended_at            INTEGER,
    total_participants  INTEGER NOT NULL DEFAULT 0,
    bracket_json        TEXT
  );

  CREATE TABLE IF NOT EXISTS queue_items (
    id         TEXT PRIMARY KEY,
    show_id    TEXT NOT NULL REFERENCES shows(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    song       TEXT,
    note       TEXT,
    paid_total REAL NOT NULL DEFAULT 0,
    position   INTEGER NOT NULL,
    status     TEXT NOT NULL DEFAULT 'queued', -- queued | played | removed | bracket
    joined_at  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS show_bans (
    id         TEXT PRIMARY KEY,
    show_id    TEXT NOT NULL REFERENCES shows(id) ON DELETE CASCADE,
    name_lower TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id       TEXT PRIMARY KEY,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    show_id  TEXT,
    type     TEXT NOT NULL,
    amount   REAL NOT NULL,
    status   TEXT NOT NULL,
    date     INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_shows_user ON shows(user_id);
  CREATE INDEX IF NOT EXISTS idx_queue_show ON queue_items(show_id);
  CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(user_id);
  CREATE INDEX IF NOT EXISTS idx_bans_show ON show_bans(show_id, name_lower);
  CREATE INDEX IF NOT EXISTS idx_reset_user ON password_resets(user_id);
`);

// Safe migration for databases created before bracket_json existed.
try { db.exec(`ALTER TABLE shows ADD COLUMN bracket_json TEXT`); } catch (e) { /* column already exists — fine */ }
// Safe migration for databases created before username existed.
try { db.exec(`ALTER TABLE users ADD COLUMN username TEXT`); } catch (e) { /* column already exists — fine */ }
// Safe migrations for real Stripe payments (Connect account, payout status, per-transaction payment intent for refunds).
try { db.exec(`ALTER TABLE users ADD COLUMN stripe_account_id TEXT`); } catch (e) { /* column already exists — fine */ }
try { db.exec(`ALTER TABLE users ADD COLUMN stripe_payouts_enabled INTEGER NOT NULL DEFAULT 0`); } catch (e) { /* column already exists — fine */ }
try { db.exec(`ALTER TABLE transactions ADD COLUMN stripe_payment_intent_id TEXT`); } catch (e) { /* column already exists — fine */ }

module.exports = db;
