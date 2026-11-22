-- =========================================================
-- NOOR PREMIUM — FEEDBACK REPORTS & ADMIN AUDIT LOGS
-- Migration: 0003_feedback_and_audit.sql
-- =========================================================

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS feedback_reports (
  id TEXT PRIMARY KEY,
  sender_name TEXT NOT NULL DEFAULT 'Guest / Visitor',
  sender_email TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'মতামত ও সাজেশন',
  rating INTEGER NOT NULL DEFAULT 5 CHECK (rating BETWEEN 1 AND 5),
  message TEXT NOT NULL,
  source_page TEXT NOT NULL DEFAULT 'settings.html',
  platform TEXT NOT NULL DEFAULT 'Web',
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewed', 'resolved')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT,
  actor_role TEXT NOT NULL DEFAULT 'admin',
  action TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT '',
  target_id TEXT NOT NULL DEFAULT '',
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
