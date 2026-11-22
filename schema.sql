-- =========================================================
-- NOOR PREMIUM — CLOUDFLARE D1 (SQLITE) SCHEMA
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS contents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'movie',
  release_year INTEGER NOT NULL DEFAULT 2026,
  genre TEXT NOT NULL DEFAULT 'Drama',
  language TEXT NOT NULL DEFAULT 'Bengali',
  rating REAL NOT NULL DEFAULT 8.0,
  synopsis TEXT NOT NULL DEFAULT '',
  stream_url TEXT NOT NULL DEFAULT '',
  poster_url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_key TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'movie',
  content_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_key, content_type, content_id)
);

CREATE TABLE IF NOT EXISTS watch_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_key TEXT NOT NULL,
  content_id TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'movie',
  title TEXT NOT NULL DEFAULT '',
  progress_percent INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_key, content_id)
);

CREATE INDEX IF NOT EXISTS idx_contents_status ON contents(status);
CREATE INDEX IF NOT EXISTS idx_watchlist_user ON watchlist(user_key);
CREATE INDEX IF NOT EXISTS idx_history_user_updated ON watch_history(user_key, updated_at DESC);
