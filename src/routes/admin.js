/* =========================================================
   NOOR PREMIUM — ADMIN CMS & MEDIA ROUTES (PHASE 15)
   Role-Gated ('admin') Content CRUD, Status & Media Sources
   ========================================================= */

import { jsonSuccess, jsonError, readJsonBody } from "../lib/http.js";
import { generateRandomToken } from "../lib/crypto.js";
import { verifyCsrfRequest } from "../lib/security.js";

function requireAdmin(user) {
  if (!user) {
    return jsonError("UNAUTHORIZED", "Authentication required", 401);
  }
  if (user.role !== "admin") {
    return jsonError("FORBIDDEN", "Admin privileges required", 403);
  }
  return null;
}

function slugify(text) {
  return String(text || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function isAllowedMediaUrl(url) {
  if (typeof url !== "string" || !url.trim()) return false;
  const trimmed = url.trim();
  return (
    trimmed.startsWith("./") ||
    trimmed.startsWith("/") ||
    trimmed.startsWith("https://")
  );
}

function sanitizeSources(sources) {
  if (!Array.isArray(sources)) return [];
  return sources
    .filter((s) => s && typeof s.url === "string" && isAllowedMediaUrl(s.url))
    .map((s, idx) => ({
      label: typeof s.label === "string" && s.label.trim() ? s.label.trim() : `Source ${idx + 1}`,
      quality: typeof s.quality === "string" && s.quality.trim() ? s.quality.trim() : "HD",
      url: s.url.trim()
    }));
}

function sanitizeSubtitles(subtitles) {
  if (!Array.isArray(subtitles)) return [];
  return subtitles
    .filter((sub) => sub && typeof sub.url === "string" && isAllowedMediaUrl(sub.url))
    .map((sub, idx) => ({
      label: typeof sub.label === "string" && sub.label.trim() ? sub.label.trim() : `Track ${idx + 1}`,
      lang: typeof sub.lang === "string" && sub.lang.trim() ? sub.lang.trim() : "en",
      url: sub.url.trim()
    }));
}

export async function handleAdminListContent(env, user) {
  const denied = requireAdmin(user);
  if (denied) return denied;

  const moviesRes = await env.DB.prepare(
    `SELECT id, slug, title, release_year, rating, status, featured, trending, popular, latest, updated_at
     FROM movies ORDER BY updated_at DESC`
  ).all();

  const seriesRes = await env.DB.prepare(
    `SELECT id, slug, title, release_year, rating, series_status, status, featured, trending, popular, latest, updated_at
     FROM series ORDER BY updated_at DESC`
  ).all();

  const movies = ((moviesRes && moviesRes.results) || []).map((r) => ({ ...r, type: "movie" }));
  const series = ((seriesRes && seriesRes.results) || []).map((r) => ({ ...r, type: "series" }));
  const combined = [...movies, ...series];

  return jsonSuccess({ items: combined }, 200, { total: combined.length });
}

export async function handleAdminCreateContent(request, env, user) {
  const denied = requireAdmin(user);
  if (denied) return denied;

  if (!verifyCsrfRequest(request)) {
    return jsonError("CSRF_INVALID", "Invalid or missing CSRF token", 403);
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonError("INVALID_JSON", parsed.error, 400);
  }

  const body = parsed.data;
  const type = body.type === "series" ? "series" : "movie";
  const title = typeof body.title === "string" ? body.title.trim() : "";
  if (!title || title.length > 160) {
    return jsonError("VALIDATION_ERROR", "Title is required (max 160 chars)", 400);
  }

  const prefix = type === "series" ? "ser" : "mov";
  const id = typeof body.id === "string" && body.id.trim()
    ? body.id.trim()
    : `${prefix}_${generateRandomToken(6)}`;

  const baseSlug = slugify(body.slug || body.originalTitle || title) || id;
  const slug = `${baseSlug}-${generateRandomToken(3)}`;
  const synopsis = typeof body.synopsis === "string" ? body.synopsis.trim() : "";
  const releaseYear = Number.isFinite(Number(body.releaseYear))
    ? Math.floor(Number(body.releaseYear))
    : new Date().getUTCFullYear();
  const rating = Number.isFinite(Number(body.rating))
    ? Math.max(0, Math.min(10, Number(body.rating)))
    : 8.0;
  const ageRating = typeof body.ageRating === "string" && body.ageRating.trim()
    ? body.ageRating.trim()
    : (type === "series" ? "TV-14" : "PG-13");

  const status = ["draft", "published", "archived"].includes(body.status)
    ? body.status
    : "draft";

  const genresJson = JSON.stringify(Array.isArray(body.genres) ? body.genres : ["Drama"]);
  const languagesJson = JSON.stringify(Array.isArray(body.languages) ? body.languages : ["বাংলা"]);
  const sourcesJson = JSON.stringify(sanitizeSources(body.sources));
  const subtitlesJson = JSON.stringify(sanitizeSubtitles(body.subtitles));
  const relatedJson = JSON.stringify(Array.isArray(body.relatedIds) ? body.relatedIds : []);

  const featured = body.featured ? 1 : 0;
  const trending = body.trending ? 1 : 0;
  const popular = body.popular ? 1 : 0;
  const latest = body.latest ? 1 : 1;
  const recommended = body.recommended ? 1 : 0;

  if (type === "movie") {
    const runtimeMinutes = Number.isFinite(Number(body.runtimeMinutes))
      ? Math.max(1, Math.floor(Number(body.runtimeMinutes)))
      : 110;

    await env.DB.prepare(
      `INSERT INTO movies (
         id, slug, title, original_title, synopsis, release_year, rating, age_rating,
         runtime_minutes, genres_json, languages_json, country, poster_url, backdrop_url,
         trailer_url, sources_json, subtitles_json, status, featured, trending, popular,
         latest, recommended, related_ids_json
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
         ?9, ?10, ?11, ?12, ?13, ?14,
         ?15, ?16, ?17, ?18, ?19, ?20, ?21,
         ?22, ?23, ?24
       )`
    )
      .bind(
        id,
        slug,
        title,
        typeof body.originalTitle === "string" ? body.originalTitle.trim() : "",
        synopsis,
        releaseYear,
        rating,
        ageRating,
        runtimeMinutes,
        genresJson,
        languagesJson,
        typeof body.country === "string" ? body.country.trim() : "Bangladesh",
        isAllowedMediaUrl(body.posterUrl) ? body.posterUrl.trim() : "",
        isAllowedMediaUrl(body.backdropUrl) ? body.backdropUrl.trim() : "",
        isAllowedMediaUrl(body.trailerUrl) ? body.trailerUrl.trim() : "",
        sourcesJson,
        subtitlesJson,
        status,
        featured,
        trending,
        popular,
        latest,
        recommended,
        relatedJson
      )
      .run();
  } else {
    const seriesStatus = body.seriesStatus === "completed" ? "completed" : "ongoing";

    await env.DB.prepare(
      `INSERT INTO series (
         id, slug, title, original_title, synopsis, release_year, rating, age_rating,
         series_status, genres_json, languages_json, country, poster_url, backdrop_url,
         trailer_url, status, featured, trending, popular, latest, recommended, related_ids_json
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
         ?9, ?10, ?11, ?12, ?13, ?14,
         ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
       )`
    )
      .bind(
        id,
        slug,
        title,
        typeof body.originalTitle === "string" ? body.originalTitle.trim() : "",
        synopsis,
        releaseYear,
        rating,
        ageRating,
        seriesStatus,
        genresJson,
        languagesJson,
        typeof body.country === "string" ? body.country.trim() : "Bangladesh",
        isAllowedMediaUrl(body.posterUrl) ? body.posterUrl.trim() : "",
        isAllowedMediaUrl(body.backdropUrl) ? body.backdropUrl.trim() : "",
        isAllowedMediaUrl(body.trailerUrl) ? body.trailerUrl.trim() : "",
        status,
        featured,
        trending,
        popular,
        latest,
        recommended,
        relatedJson
      )
      .run();
  }

  return jsonSuccess({ id, slug, type, title, status }, 201);
}

export async function handleAdminUpdateStatus(request, env, user, type, id) {
  const denied = requireAdmin(user);
  if (denied) return denied;

  if (!verifyCsrfRequest(request)) {
    return jsonError("CSRF_INVALID", "Invalid or missing CSRF token", 403);
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonError("INVALID_JSON", parsed.error, 400);
  }

  const nextStatus = parsed.data.status;
  if (!["draft", "published", "archived"].includes(nextStatus)) {
    return jsonError("VALIDATION_ERROR", "Invalid status value", 400);
  }

  const table = type === "series" ? "series" : "movies";
  const nowIso = new Date().toISOString();

  const res = await env.DB.prepare(
    `UPDATE ${table} SET status = ?1, updated_at = ?2 WHERE id = ?3`
  )
    .bind(nextStatus, nowIso, id)
    .run();

  if (!res.meta || res.meta.changes === 0) {
    return jsonError("CONTENT_NOT_FOUND", "Content item not found", 404);
  }

  return jsonSuccess({ id, type, status: nextStatus }, 200);
}

export async function handleAdminUpdateMedia(request, env, user, type, id) {
  const denied = requireAdmin(user);
  if (denied) return denied;

  if (!verifyCsrfRequest(request)) {
    return jsonError("CSRF_INVALID", "Invalid or missing CSRF token", 403);
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonError("INVALID_JSON", parsed.error, 400);
  }

  const sources = sanitizeSources(parsed.data.sources);
  const subtitles = sanitizeSubtitles(parsed.data.subtitles);
  const nowIso = new Date().toISOString();

  if (type === "episode") {
    const res = await env.DB.prepare(
      `UPDATE episodes SET sources_json = ?1, subtitles_json = ?2 WHERE id = ?3`
    )
      .bind(JSON.stringify(sources), JSON.stringify(subtitles), id)
      .run();

    if (!res.meta || res.meta.changes === 0) {
      return jsonError("EPISODE_NOT_FOUND", "Episode not found", 404);
    }
    return jsonSuccess({ id, type: "episode", sources, subtitles }, 200);
  }

  const table = type === "series" ? "series" : "movies";
  const res = await env.DB.prepare(
    `UPDATE ${table} SET sources_json = ?1, subtitles_json = ?2, updated_at = ?3 WHERE id = ?4`
  )
    .bind(JSON.stringify(sources), JSON.stringify(subtitles), nowIso, id)
    .run();

  if (!res.meta || res.meta.changes === 0) {
    return jsonError("CONTENT_NOT_FOUND", "Content item not found", 404);
  }

  return jsonSuccess({ id, type, sources, subtitles }, 200);
}

export async function handleAdminDeleteContent(request, env, user, type, id) {
  const denied = requireAdmin(user);
  if (denied) return denied;

  if (!verifyCsrfRequest(request)) {
    return jsonError("CSRF_INVALID", "Invalid or missing CSRF token", 403);
  }

  const table = type === "series" ? "series" : "movies";
  const res = await env.DB.prepare(`DELETE FROM ${table} WHERE id = ?1`).bind(id).run();

  if (!res.meta || res.meta.changes === 0) {
    return jsonError("CONTENT_NOT_FOUND", "Content item not found", 404);
  }

  return jsonSuccess({ deleted: true, id, type }, 200);
}
