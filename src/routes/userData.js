/* =========================================================
   NOOR PREMIUM — WATCHLIST & HISTORY API ROUTES (PHASE 14)
   Authenticated User Watchlist & Continue Watching Endpoints
   ========================================================= */

import { jsonSuccess, jsonError, readJsonBody } from "../lib/http.js";
import { generateRandomToken } from "../lib/crypto.js";
import { verifyCsrfRequest } from "../lib/security.js";

export async function handleGetWatchlist(env, user) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const res = await env.DB.prepare(
    `SELECT id, content_type, content_id, created_at
     FROM watchlist
     WHERE user_id = ?1
     ORDER BY created_at DESC`
  )
    .bind(user.id)
    .all();

  const items = ((res && res.results) || []).map((row) => ({
    id: row.id,
    contentType: row.content_type,
    contentId: row.content_id,
    createdAt: row.created_at
  }));

  return jsonSuccess({ items }, 200, { total: items.length });
}

export async function handleAddWatchlist(request, env, user) {
  if (!verifyCsrfRequest(request)) {
    return jsonError("CSRF_INVALID", "Invalid or missing CSRF token", 403);
  }

  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonError("INVALID_JSON", parsed.error, 400);
  }

  const contentType = parsed.data.contentType;
  const contentId = typeof parsed.data.contentId === "string" ? parsed.data.contentId.trim() : "";

  if (contentType !== "movie" && contentType !== "series") {
    return jsonError("VALIDATION_ERROR", "contentType must be 'movie' or 'series'", 400);
  }

  if (!contentId) {
    return jsonError("VALIDATION_ERROR", "contentId is required", 400);
  }

  const id = `wl_${generateRandomToken(10)}`;

  await env.DB.prepare(
    `INSERT INTO watchlist (id, user_id, content_type, content_id)
     VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(user_id, content_type, content_id) DO NOTHING`
  )
    .bind(id, user.id, contentType, contentId)
    .run();

  return jsonSuccess(
    {
      item: {
        contentType,
        contentId
      }
    },
    201
  );
}

export async function handleRemoveWatchlist(request, env, user, contentType, contentId) {
  if (!verifyCsrfRequest(request)) {
    return jsonError("CSRF_INVALID", "Invalid or missing CSRF token", 403);
  }

  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  if (contentType !== "movie" && contentType !== "series") {
    return jsonError("VALIDATION_ERROR", "contentType must be 'movie' or 'series'", 400);
  }

  if (!contentId) {
    return jsonError("VALIDATION_ERROR", "contentId is required", 400);
  }

  await env.DB.prepare(
    `DELETE FROM watchlist
     WHERE user_id = ?1 AND content_type = ?2 AND content_id = ?3`
  )
    .bind(user.id, contentType, contentId)
    .run();

  return jsonSuccess({ removed: true, contentType, contentId }, 200);
}

export async function handleGetHistory(env, user) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const res = await env.DB.prepare(
    `SELECT id, content_type, content_id, episode_id, progress_seconds,
            duration_seconds, completed, updated_at
     FROM watch_history
     WHERE user_id = ?1
     ORDER BY updated_at DESC
     LIMIT 50`
  )
    .bind(user.id)
    .all();

  const items = ((res && res.results) || []).map((row) => ({
    id: row.id,
    contentType: row.content_type,
    contentId: row.content_id,
    episodeId: row.episode_id || null,
    progressSeconds: row.progress_seconds,
    durationSeconds: row.duration_seconds,
    completed: Boolean(row.completed),
    updatedAt: row.updated_at
  }));

  return jsonSuccess({ items }, 200, { total: items.length });
}

export async function handleUpsertHistory(request, env, user) {
  if (!verifyCsrfRequest(request)) {
    return jsonError("CSRF_INVALID", "Invalid or missing CSRF token", 403);
  }

  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonError("INVALID_JSON", parsed.error, 400);
  }

  const body = parsed.data;
  const contentType = body.contentType;
  const contentId = typeof body.contentId === "string" ? body.contentId.trim() : "";
  const episodeId = typeof body.episodeId === "string" && body.episodeId.trim()
    ? body.episodeId.trim()
    : null;
  const progressSeconds = Math.max(0, Math.floor(Number(body.progressSeconds) || 0));
  const durationSeconds = Math.max(0, Math.floor(Number(body.durationSeconds) || 0));
  const completed = body.completed ? 1 : 0;

  if (contentType !== "movie" && contentType !== "series") {
    return jsonError("VALIDATION_ERROR", "contentType must be 'movie' or 'series'", 400);
  }

  if (!contentId) {
    return jsonError("VALIDATION_ERROR", "contentId is required", 400);
  }

  const id = `wh_${generateRandomToken(10)}`;
  const nowIso = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO watch_history (
       id, user_id, content_type, content_id, episode_id,
       progress_seconds, duration_seconds, completed, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
     ON CONFLICT(user_id, content_type, content_id, episode_id) DO UPDATE SET
       progress_seconds = excluded.progress_seconds,
       duration_seconds = excluded.duration_seconds,
       completed = excluded.completed,
       updated_at = excluded.updated_at`
  )
    .bind(
      id,
      user.id,
      contentType,
      contentId,
      episodeId,
      progressSeconds,
      durationSeconds,
      completed,
      nowIso
    )
    .run();

  return jsonSuccess(
    {
      entry: {
        contentType,
        contentId,
        episodeId,
        progressSeconds,
        durationSeconds,
        completed: Boolean(completed),
        updatedAt: nowIso
      }
    },
    200
  );
}
