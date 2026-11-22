-- =========================================================
-- NOOR PREMIUM — INITIAL CLOUDFLARE D1 (SQLITE) SCHEMA
-- Migration: 0001_initial_schema.sql
-- =========================================================

PRAGMA foreign_keys = ON;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 2. Sessions Table (HttpOnly Session Lookup by Token Hash)
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Movies Table
CREATE TABLE IF NOT EXISTS movies (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  original_title TEXT,
  synopsis TEXT NOT NULL DEFAULT '',
  release_year INTEGER,
  rating REAL DEFAULT 0,
  age_rating TEXT DEFAULT 'PG-13',
  runtime_minutes INTEGER,
  genres_json TEXT NOT NULL DEFAULT '[]',
  languages_json TEXT NOT NULL DEFAULT '[]',
  country TEXT,
  poster_url TEXT,
  backdrop_url TEXT,
  trailer_url TEXT,
  sources_json TEXT NOT NULL DEFAULT '[]',
  subtitles_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
  featured INTEGER NOT NULL DEFAULT 0 CHECK (featured IN (0, 1)),
  trending INTEGER NOT NULL DEFAULT 0 CHECK (trending IN (0, 1)),
  popular INTEGER NOT NULL DEFAULT 0 CHECK (popular IN (0, 1)),
  latest INTEGER NOT NULL DEFAULT 0 CHECK (latest IN (0, 1)),
  recommended INTEGER NOT NULL DEFAULT 0 CHECK (recommended IN (0, 1)),
  related_ids_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 4. Series Table
CREATE TABLE IF NOT EXISTS series (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  original_title TEXT,
  synopsis TEXT NOT NULL DEFAULT '',
  release_year INTEGER,
  rating REAL DEFAULT 0,
  age_rating TEXT DEFAULT 'TV-14',
  series_status TEXT NOT NULL DEFAULT 'ongoing' CHECK (series_status IN ('ongoing', 'completed')),
  genres_json TEXT NOT NULL DEFAULT '[]',
  languages_json TEXT NOT NULL DEFAULT '[]',
  country TEXT,
  poster_url TEXT,
  backdrop_url TEXT,
  trailer_url TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
  featured INTEGER NOT NULL DEFAULT 0 CHECK (featured IN (0, 1)),
  trending INTEGER NOT NULL DEFAULT 0 CHECK (trending IN (0, 1)),
  popular INTEGER NOT NULL DEFAULT 0 CHECK (popular IN (0, 1)),
  latest INTEGER NOT NULL DEFAULT 0 CHECK (latest IN (0, 1)),
  recommended INTEGER NOT NULL DEFAULT 0 CHECK (recommended IN (0, 1)),
  related_ids_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 5. Seasons Table
CREATE TABLE IF NOT EXISTS seasons (
  id TEXT PRIMARY KEY,
  series_id TEXT NOT NULL,
  season_number INTEGER NOT NULL,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (series_id) REFERENCES series(id) ON DELETE CASCADE,
  UNIQUE (series_id, season_number)
);

-- 6. Episodes Table
CREATE TABLE IF NOT EXISTS episodes (
  id TEXT PRIMARY KEY,
  season_id TEXT NOT NULL,
  episode_number INTEGER NOT NULL,
  title TEXT NOT NULL,
  synopsis TEXT NOT NULL DEFAULT '',
  runtime_minutes INTEGER,
  thumbnail_url TEXT,
  sources_json TEXT NOT NULL DEFAULT '[]',
  subtitles_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (season_id) REFERENCES seasons(id) ON DELETE CASCADE,
  UNIQUE (season_id, episode_number)
);

-- 7. Watchlist Table
CREATE TABLE IF NOT EXISTS watchlist (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  content_type TEXT NOT NULL CHECK (content_type IN ('movie', 'series')),
  content_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE (user_id, content_type, content_id)
);

-- 8. Watch History Table (Continue Watching)
CREATE TABLE IF NOT EXISTS watch_history (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  content_type TEXT NOT NULL CHECK (content_type IN ('movie', 'series')),
  content_id TEXT NOT NULL,
  episode_id TEXT,
  progress_seconds INTEGER NOT NULL DEFAULT 0,
  duration_seconds INTEGER NOT NULL DEFAULT 0,
  completed INTEGER NOT NULL DEFAULT 0 CHECK (completed IN (0, 1)),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE (user_id, content_type, content_id, episode_id)
);

-- Indexes for Query Performance
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_movies_status_year ON movies(status, release_year DESC);
CREATE INDEX IF NOT EXISTS idx_series_status_year ON series(status, release_year DESC);
CREATE INDEX IF NOT EXISTS idx_seasons_series_id ON seasons(series_id);
CREATE INDEX IF NOT EXISTS idx_episodes_season_id ON episodes(season_id);
CREATE INDEX IF NOT EXISTS idx_watchlist_user_id ON watchlist(user_id);
CREATE INDEX IF NOT EXISTS idx_watch_history_user_id ON watch_history(user_id, updated_at DESC);
