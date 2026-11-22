// NOOR PREMIUM — Clean Bundled Worker

// ----- src/lib/http.js -----
/* =========================================================
   NOOR PREMIUM — HTTP RESPONSE, HEADERS & PARSER HELPERS
   Standard REST API v1 Envelope + Security Headers
   ========================================================= */
function applySecurityHeaders(headers, options = {}) {
  const isJson = options.isJson !== false;

  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");

  if (isJson) {
    headers.set("Content-Type", "application/json; charset=utf-8");
    headers.set("Cache-Control", "no-store");
  }

  return headers;
}
function jsonSuccess(data = {}, status = 200, meta = {}, extraHeaders = null) {
  const headers = new Headers(extraHeaders || {});
  applySecurityHeaders(headers, { isJson: true });

  return new Response(
    JSON.stringify({
      success: true,
      data,
      meta
    }),
    { status, headers }
  );
}
function jsonError(code, message, status = 400, details = null, extraHeaders = null) {
  const headers = new Headers(extraHeaders || {});
  applySecurityHeaders(headers, { isJson: true });

  return new Response(
    JSON.stringify({
      success: false,
      error: {
        code,
        message,
        details
      }
    }),
    { status, headers }
  );
}
async function readJsonBody(request) {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return { ok: false, error: "Content-Type must be application/json" };
  }

  try {
    const rawText = await request.text();
    if (!rawText.trim()) {
      return { ok: false, error: "Request body is empty" };
    }
    const parsed = JSON.parse(rawText);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "Request body must be a JSON object" };
    }
    return { ok: true, data: parsed };
  } catch (_) {
    return { ok: false, error: "Malformed JSON body" };
  }
}

// ----- src/lib/crypto.js -----
/* =========================================================
   NOOR PREMIUM — CRYPTOGRAPHIC HELPERS (WEB CRYPTO API)
   PBKDF2 Password Hashing, Timing-Safe Check & Token Hashing
   ========================================================= */

const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH_BITS = 256;

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}
function timingSafeEqualStrings(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const encA = new TextEncoder().encode(a);
  const encB = new TextEncoder().encode(b);
  const maxLen = Math.max(encA.length, encB.length);
  let diff = encA.length ^ encB.length;
  for (let i = 0; i < maxLen; i++) {
    const byteA = i < encA.length ? encA[i] : 0;
    const byteB = i < encB.length ? encB[i] : 0;
    diff |= byteA ^ byteB;
  }
  return diff === 0;
}
function generateRandomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}
async function sha256Hex(input) {
  const data = new TextEncoder().encode(String(input));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}
async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    KEY_LENGTH_BITS
  );

  const saltHex = bytesToHex(salt);
  const hashHex = bytesToHex(new Uint8Array(derivedBits));
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${saltHex}$${hashHex}`;
}
async function verifyPassword(password, storedHash) {
  if (typeof password !== "string" || typeof storedHash !== "string") return false;
  const parts = storedHash.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") return false;

  const iterations = Number(parts[1]);
  const salt = hexToBytes(parts[2]);
  const expectedHashHex = parts[3];

  if (!Number.isInteger(iterations) || iterations <= 0 || !salt || !expectedHashHex) {
    return false;
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    KEY_LENGTH_BITS
  );

  const actualHashHex = bytesToHex(new Uint8Array(derivedBits));
  return timingSafeEqualStrings(actualHashHex, expectedHashHex);
}

// ----- src/lib/security.js -----
/* =========================================================
   NOOR PREMIUM — COOKIES, CSRF & RATE LIMIT HELPERS
   HttpOnly Session Cookie + Double-Submit CSRF Guard
   ========================================================= */
const SESSION_COOKIE_NAME = "noor_session";
const CSRF_COOKIE_NAME = "noor_csrf";

const rateLimitBuckets = new Map();
function parseCookies(cookieHeader) {
  const result = {};
  if (!cookieHeader || typeof cookieHeader !== "string") return result;

  cookieHeader.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx <= 0) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) {
      try {
        result[key] = decodeURIComponent(val);
      } catch (_) {
        result[key] = val;
      }
    }
  });

  return result;
}
function buildSessionCookie(token, maxAgeSeconds = 60 * 60 * 24 * 7, isSecure = true) {
  const attrs = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${maxAgeSeconds}`
  ];
  if (isSecure) attrs.push("Secure");
  return attrs.join("; ");
}
function buildClearSessionCookie(isSecure = true) {
  const attrs = [
    `${SESSION_COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    "Max-Age=0"
  ];
  if (isSecure) attrs.push("Secure");
  return attrs.join("; ");
}
function buildCsrfCookie(csrfToken, maxAgeSeconds = 60 * 60 * 24 * 7, isSecure = true) {
  const attrs = [
    `${CSRF_COOKIE_NAME}=${encodeURIComponent(csrfToken)}`,
    "Path=/",
    "SameSite=Strict",
    `Max-Age=${maxAgeSeconds}`
  ];
  if (isSecure) attrs.push("Secure");
  return attrs.join("; ");
}
function ensureCsrfToken(request) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  if (cookies[CSRF_COOKIE_NAME] && cookies[CSRF_COOKIE_NAME].length >= 16) {
    return { token: cookies[CSRF_COOKIE_NAME], isNew: false };
  }
  return { token: generateRandomToken(24), isNew: true };
}
function verifyCsrfRequest(request) {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return true;
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const cookieCsrf = cookies[CSRF_COOKIE_NAME] || "";
  const headerCsrf = request.headers.get("X-CSRF-Token") || "";

  if (!cookieCsrf || !headerCsrf) return false;
  return timingSafeEqualStrings(cookieCsrf, headerCsrf);
}
function checkRateLimit(bucketKey, maxAttempts = 8, windowMs = 60000) {
  const now = Date.now();
  const existing = rateLimitBuckets.get(bucketKey);

  if (!existing || now > existing.resetAt) {
    rateLimitBuckets.set(bucketKey, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: maxAttempts - 1, retryAfterSeconds: 0 };
  }

  if (existing.count >= maxAttempts) {
    const retryAfterSeconds = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
    return { allowed: false, remaining: 0, retryAfterSeconds };
  }

  existing.count += 1;
  return {
    allowed: true,
    remaining: Math.max(0, maxAttempts - existing.count),
    retryAfterSeconds: 0
  };
}

// ----- src/routes/catalog.js -----
/* =========================================================
   NOOR PREMIUM — CATALOG API ROUTES (PHASE 14)
   GET /api/v1/catalog, GET /api/v1/catalog/:id, GET /api/v1/series/:id/seasons
   ========================================================= */

function parseJsonArray(raw, fallback = []) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== "string" || !raw.trim()) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : fallback;
  } catch (_) {
    return fallback;
  }
}

function mapMovieRow(row) {
  return {
    id: row.id,
    slug: row.slug,
    type: "movie",
    title: row.title,
    originalTitle: row.original_title || "",
    synopsis: row.synopsis || "",
    releaseYear: row.release_year,
    rating: row.rating,
    ageRating: row.age_rating || "PG-13",
    runtimeMinutes: row.runtime_minutes,
    genres: parseJsonArray(row.genres_json),
    languages: parseJsonArray(row.languages_json),
    country: row.country || "",
    posterUrl: row.poster_url || "",
    backdropUrl: row.backdrop_url || "",
    trailerUrl: row.trailer_url || "",
    sources: parseJsonArray(row.sources_json),
    subtitles: parseJsonArray(row.subtitles_json),
    status: row.status,
    featured: Boolean(row.featured),
    trending: Boolean(row.trending),
    popular: Boolean(row.popular),
    latest: Boolean(row.latest),
    recommended: Boolean(row.recommended),
    relatedIds: parseJsonArray(row.related_ids_json)
  };
}

function mapSeriesRow(row, seasons = []) {
  return {
    id: row.id,
    slug: row.slug,
    type: "series",
    title: row.title,
    originalTitle: row.original_title || "",
    synopsis: row.synopsis || "",
    releaseYear: row.release_year,
    rating: row.rating,
    ageRating: row.age_rating || "TV-14",
    seriesStatus: row.series_status || "ongoing",
    genres: parseJsonArray(row.genres_json),
    languages: parseJsonArray(row.languages_json),
    country: row.country || "",
    posterUrl: row.poster_url || "",
    backdropUrl: row.backdrop_url || "",
    trailerUrl: row.trailer_url || "",
    status: row.status,
    featured: Boolean(row.featured),
    trending: Boolean(row.trending),
    popular: Boolean(row.popular),
    latest: Boolean(row.latest),
    recommended: Boolean(row.recommended),
    relatedIds: parseJsonArray(row.related_ids_json),
    seasons
  };
}

async function loadSeriesSeasonsAndEpisodes(db, seriesId) {
  const seasonsRes = await db
    .prepare(
      `SELECT id, series_id, season_number, title
       FROM seasons
       WHERE series_id = ?1
       ORDER BY season_number ASC`
    )
    .bind(seriesId)
    .all();

  const seasonRows = (seasonsRes && seasonsRes.results) || [];
  const seasons = [];

  for (const s of seasonRows) {
    const epRes = await db
      .prepare(
        `SELECT id, season_id, episode_number, title, synopsis, runtime_minutes,
                thumbnail_url, sources_json, subtitles_json
         FROM episodes
         WHERE season_id = ?1
         ORDER BY episode_number ASC`
      )
      .bind(s.id)
      .all();

    const episodes = ((epRes && epRes.results) || []).map((ep) => ({
      id: ep.id,
      seasonId: ep.season_id,
      episodeNumber: ep.episode_number,
      title: ep.title,
      synopsis: ep.synopsis || "",
      runtimeMinutes: ep.runtime_minutes,
      thumbnailUrl: ep.thumbnail_url || "",
      sources: parseJsonArray(ep.sources_json),
      subtitles: parseJsonArray(ep.subtitles_json)
    }));

    seasons.push({
      id: s.id,
      seriesId: s.series_id,
      seasonNumber: s.season_number,
      title: s.title,
      episodes
    });
  }

  return seasons;
}
async function handleListCatalog(request, env) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const url = new URL(request.url);
  const typeParam = (url.searchParams.get("type") || "all").toLowerCase();
  const genreParam = (url.searchParams.get("genre") || "").trim();
  const qParam = (url.searchParams.get("q") || "").trim().toLowerCase();

  const items = [];

  if (typeParam === "all" || typeParam === "movie") {
    const moviesRes = await env.DB.prepare(
      `SELECT * FROM movies WHERE status = 'published' ORDER BY release_year DESC, rating DESC`
    ).all();
    for (const row of (moviesRes && moviesRes.results) || []) {
      items.push(mapMovieRow(row));
    }
  }

  if (typeParam === "all" || typeParam === "series") {
    const seriesRes = await env.DB.prepare(
      `SELECT * FROM series WHERE status = 'published' ORDER BY release_year DESC, rating DESC`
    ).all();
    for (const row of (seriesRes && seriesRes.results) || []) {
      const seasons = await loadSeriesSeasonsAndEpisodes(env.DB, row.id);
      items.push(mapSeriesRow(row, seasons));
    }
  }

  const filtered = items.filter((item) => {
    if (genreParam && genreParam.toLowerCase() !== "all") {
      const hasGenre = (item.genres || []).some(
        (g) => String(g).toLowerCase() === genreParam.toLowerCase()
      );
      if (!hasGenre) return false;
    }

    if (qParam) {
      const text = [
        item.title,
        item.originalTitle,
        item.synopsis,
        ...(item.genres || []),
        ...(item.languages || [])
      ]
        .join(" ")
        .toLowerCase();
      if (!text.includes(qParam)) return false;
    }

    return true;
  });

  return jsonSuccess(
    { items: filtered },
    200,
    { total: filtered.length }
  );
}
async function handleGetCatalogItem(env, idOrSlug) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const key = String(idOrSlug || "").trim();
  if (!key) {
    return jsonError("INVALID_ID", "Content id or slug is required", 400);
  }

  const movieRow = await env.DB.prepare(
    `SELECT * FROM movies WHERE (id = ?1 OR slug = ?1) AND status = 'published' LIMIT 1`
  )
    .bind(key)
    .first();

  if (movieRow) {
    return jsonSuccess({ item: mapMovieRow(movieRow) }, 200);
  }

  const seriesRow = await env.DB.prepare(
    `SELECT * FROM series WHERE (id = ?1 OR slug = ?1) AND status = 'published' LIMIT 1`
  )
    .bind(key)
    .first();

  if (seriesRow) {
    const seasons = await loadSeriesSeasonsAndEpisodes(env.DB, seriesRow.id);
    return jsonSuccess({ item: mapSeriesRow(seriesRow, seasons) }, 200);
  }

  return jsonError("CONTENT_NOT_FOUND", "Published movie or series not found", 404);
}
async function handleGetSeriesSeasons(env, seriesIdOrSlug) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const key = String(seriesIdOrSlug || "").trim();
  const seriesRow = await env.DB.prepare(
    `SELECT id, title FROM series WHERE (id = ?1 OR slug = ?1) AND status = 'published' LIMIT 1`
  )
    .bind(key)
    .first();

  if (!seriesRow) {
    return jsonError("SERIES_NOT_FOUND", "Published series not found", 404);
  }

  const seasons = await loadSeriesSeasonsAndEpisodes(env.DB, seriesRow.id);
  return jsonSuccess({ seriesId: seriesRow.id, seasons }, 200, { count: seasons.length });
}

// ----- src/routes/userData.js -----
/* =========================================================
   NOOR PREMIUM — WATCHLIST & HISTORY API ROUTES (PHASE 14)
   Authenticated User Watchlist & Continue Watching Endpoints
   ========================================================= */
async function handleGetWatchlist(env, user) {
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
async function handleAddWatchlist(request, env, user) {
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
async function handleRemoveWatchlist(request, env, user, contentType, contentId) {
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
async function handleGetHistory(env, user) {
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
async function handleUpsertHistory(request, env, user) {
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

// ----- src/routes/admin.js -----
/* =========================================================
   NOOR PREMIUM — ADMIN CMS & MEDIA ROUTES (PHASE 15)
   Role-Gated ('admin') Content CRUD, Status & Media Sources
   ========================================================= */



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
async function handleAdminListContent(env, user) {
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
async function handleAdminCreateContent(request, env, user) {
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
async function handleAdminUpdateStatus(request, env, user, type, id) {
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
async function handleAdminUpdateMedia(request, env, user, type, id) {
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
async function handleAdminDeleteContent(request, env, user, type, id) {
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

// ----- src/index.js -----
/* =========================================================
   NOOR PREMIUM — CLOUDFLARE WORKER ENTRYPOINT (PHASE 15)
   REST API v1: Auth, Catalog, Watchlist, History & Admin CMS
   ========================================================= */






function getClientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    "unknown-ip"
  );
}

function isSecureRequest(request) {
  try {
    return new URL(request.url).protocol === "https:";
  } catch (_) {
    return true;
  }
}

async function getAuthenticatedUser(request, env) {
  if (!env || !env.DB) return null;

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const rawToken = cookies[SESSION_COOKIE_NAME];
  if (!rawToken) return null;

  const tokenHash = await sha256Hex(rawToken);
  const nowIso = new Date().toISOString();

  const row = await env.DB.prepare(
    `SELECT u.id, u.full_name, u.email, u.username, u.role, u.status, s.id AS session_id
     FROM sessions s
     INNER JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?1 AND s.expires_at > ?2
     LIMIT 1`
  )
    .bind(tokenHash, nowIso)
    .first();

  if (!row || row.status !== "active") return null;

  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    username: row.username,
    role: row.role,
    sessionId: row.session_id
  };
}

async function createUserSession(userId, env) {
  const rawToken = generateRandomToken(32);
  const tokenHash = await sha256Hex(rawToken);
  const sessionId = `ses_${generateRandomToken(12)}`;
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, expires_at)
     VALUES (?1, ?2, ?3, ?4)`
  )
    .bind(sessionId, userId, tokenHash, expiresAt)
    .run();

  return { rawToken, expiresAt };
}

async function handleRegister(request, env) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonError("INVALID_JSON", parsed.error, 400);
  }

  const body = parsed.data;
  const fullName = typeof body.fullName === "string" ? body.fullName.trim() : "";
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (fullName.length < 2 || fullName.length > 80) {
    return jsonError("VALIDATION_ERROR", "Full name must be between 2 and 80 characters", 400);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return jsonError("VALIDATION_ERROR", "Valid email address is required", 400);
  }

  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return jsonError("VALIDATION_ERROR", "Username must be 3-20 lowercase alphanumeric/underscore chars", 400);
  }

  if (password.length < 8 || password.length > 128) {
    return jsonError("VALIDATION_ERROR", "Password must be between 8 and 128 characters", 400);
  }

  const existing = await env.DB.prepare(
    `SELECT id FROM users WHERE lower(email) = ?1 OR lower(username) = ?2 LIMIT 1`
  )
    .bind(email, username)
    .first();

  if (existing) {
    return jsonError("ACCOUNT_EXISTS", "An account with this email or username already exists", 409);
  }

  const userId = `usr_${generateRandomToken(12)}`;
  const passwordHash = await hashPassword(password);

  await env.DB.prepare(
    `INSERT INTO users (id, full_name, email, username, password_hash, role, status)
     VALUES (?1, ?2, ?3, ?4, ?5, 'user', 'active')`
  )
    .bind(userId, fullName, email, username, passwordHash)
    .run();

  const session = await createUserSession(userId, env);
  const csrf = ensureCsrfToken(request);
  const secure = isSecureRequest(request);

  const headers = new Headers();
  headers.append("Set-Cookie", buildSessionCookie(session.rawToken, 60 * 60 * 24 * 7, secure));
  headers.append("Set-Cookie", buildCsrfCookie(csrf.token, 60 * 60 * 24 * 7, secure));

  return jsonSuccess(
    {
      user: {
        id: userId,
        fullName,
        email,
        username,
        role: "user"
      },
      csrfToken: csrf.token
    },
    201,
    {},
    headers
  );
}

async function handleLogin(request, env) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const ip = getClientIp(request);
  const rate = checkRateLimit(`login:${ip}`, 8, 60000);
  if (!rate.allowed) {
    return jsonError(
      "RATE_LIMITED",
      "Too many login attempts. Please try again shortly.",
      429,
      { retryAfterSeconds: rate.retryAfterSeconds }
    );
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonError("INVALID_JSON", parsed.error, 400);
  }

  const identifier = typeof parsed.data.identifier === "string"
    ? parsed.data.identifier.trim().toLowerCase()
    : "";
  const password = typeof parsed.data.password === "string" ? parsed.data.password : "";

  if (!identifier || !password) {
    return jsonError("VALIDATION_ERROR", "Identifier and password are required", 400);
  }

  const user = await env.DB.prepare(
    `SELECT id, full_name, email, username, password_hash, role, status
     FROM users
     WHERE lower(email) = ?1 OR lower(username) = ?1
     LIMIT 1`
  )
    .bind(identifier)
    .first();

  const passwordValid = user ? await verifyPassword(password, user.password_hash) : false;

  if (!user || !passwordValid) {
    return jsonError("INVALID_CREDENTIALS", "Invalid credentials", 401);
  }

  if (user.status !== "active") {
    return jsonError("ACCOUNT_SUSPENDED", "Account is not active", 403);
  }

  const session = await createUserSession(user.id, env);
  const csrf = ensureCsrfToken(request);
  const secure = isSecureRequest(request);

  const headers = new Headers();
  headers.append("Set-Cookie", buildSessionCookie(session.rawToken, 60 * 60 * 24 * 7, secure));
  headers.append("Set-Cookie", buildCsrfCookie(csrf.token, 60 * 60 * 24 * 7, secure));

  return jsonSuccess(
    {
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        username: user.username,
        role: user.role
      },
      csrfToken: csrf.token
    },
    200,
    {},
    headers
  );
}

async function handleLogout(request, env) {
  if (!verifyCsrfRequest(request)) {
    return jsonError("CSRF_INVALID", "Invalid or missing CSRF token", 403);
  }

  if (env && env.DB) {
    const cookies = parseCookies(request.headers.get("Cookie") || "");
    const rawToken = cookies[SESSION_COOKIE_NAME];
    if (rawToken) {
      const tokenHash = await sha256Hex(rawToken);
      await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?1`).bind(tokenHash).run();
    }
  }

  const secure = isSecureRequest(request);
  const headers = new Headers();
  headers.append("Set-Cookie", buildClearSessionCookie(secure));

  return jsonSuccess({ loggedOut: true }, 200, {}, headers);
}

async function handleMe(request, env) {
  const user = await getAuthenticatedUser(request, env);
  if (!user) {
    return jsonError("UNAUTHORIZED", "Authentication required", 401);
  }

  const csrf = ensureCsrfToken(request);
  const headers = new Headers();
  if (csrf.isNew) {
    headers.append("Set-Cookie", buildCsrfCookie(csrf.token, 60 * 60 * 24 * 7, isSecureRequest(request)));
  }

  return jsonSuccess(
    {
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        username: user.username,
        role: user.role
      },
      csrfToken: csrf.token
    },
    200,
    {},
    headers
  );
}
const v1Worker = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    if (path === "/api/v1/health" && method === "GET") {
      const csrf = ensureCsrfToken(request);
      const headers = new Headers();
      if (csrf.isNew) {
        headers.append("Set-Cookie", buildCsrfCookie(csrf.token, 60 * 60 * 24 * 7, isSecureRequest(request)));
      }
      return jsonSuccess(
        {
          service: "noor-premium-api",
          status: "ok",
          csrfToken: csrf.token
        },
        200,
        { timestamp: new Date().toISOString() },
        headers
      );
    }

    // Auth & User Routes
    if (path === "/api/v1/auth/register" && method === "POST") {
      return handleRegister(request, env);
    }
    if (path === "/api/v1/auth/login" && method === "POST") {
      return handleLogin(request, env);
    }
    if (path === "/api/v1/auth/logout" && method === "POST") {
      return handleLogout(request, env);
    }
    if (path === "/api/v1/users/me" && method === "GET") {
      return handleMe(request, env);
    }

    // Catalog Routes
    if (path === "/api/v1/catalog" && method === "GET") {
      return handleListCatalog(request, env);
    }
    const catalogItemMatch = path.match(/^\/api\/v1\/catalog\/([^/]+)$/);
    if (catalogItemMatch && method === "GET") {
      return handleGetCatalogItem(env, decodeURIComponent(catalogItemMatch[1]));
    }
    const seriesSeasonsMatch = path.match(/^\/api\/v1\/series\/([^/]+)\/seasons$/);
    if (seriesSeasonsMatch && method === "GET") {
      return handleGetSeriesSeasons(env, decodeURIComponent(seriesSeasonsMatch[1]));
    }

    // Protected Watchlist & History Routes
    if (path === "/api/v1/watchlist" && (method === "GET" || method === "POST")) {
      const user = await getAuthenticatedUser(request, env);
      if (!user) return jsonError("UNAUTHORIZED", "Authentication required", 401);
      return method === "GET"
        ? handleGetWatchlist(env, user)
        : handleAddWatchlist(request, env, user);
    }

    const watchlistDeleteMatch = path.match(/^\/api\/v1\/watchlist\/(movie|series)\/([^/]+)$/);
    if (watchlistDeleteMatch && method === "DELETE") {
      const user = await getAuthenticatedUser(request, env);
      if (!user) return jsonError("UNAUTHORIZED", "Authentication required", 401);
      return handleRemoveWatchlist(
        request,
        env,
        user,
        watchlistDeleteMatch[1],
        decodeURIComponent(watchlistDeleteMatch[2])
      );
    }

    if (path === "/api/v1/history" && (method === "GET" || method === "POST")) {
      const user = await getAuthenticatedUser(request, env);
      if (!user) return jsonError("UNAUTHORIZED", "Authentication required", 401);
      return method === "GET"
        ? handleGetHistory(env, user)
        : handleUpsertHistory(request, env, user);
    }

    // Admin CMS & Media Routes
    if (path === "/api/v1/admin/content" && method === "GET") {
      const user = await getAuthenticatedUser(request, env);
      return handleAdminListContent(env, user);
    }
    if (path === "/api/v1/admin/content" && method === "POST") {
      const user = await getAuthenticatedUser(request, env);
      return handleAdminCreateContent(request, env, user);
    }
    const statusMatch = path.match(/^\/api\/v1\/admin\/content\/(movie|series)\/([^/]+)\/status$/);
    if (statusMatch && method === "PATCH") {
      const user = await getAuthenticatedUser(request, env);
      return handleAdminUpdateStatus(request, env, user, statusMatch[1], decodeURIComponent(statusMatch[2]));
    }
    const mediaMatch = path.match(/^\/api\/v1\/admin\/media\/(movie|series|episode)\/([^/]+)$/);
    if (mediaMatch && method === "PUT") {
      const user = await getAuthenticatedUser(request, env);
      return handleAdminUpdateMedia(request, env, user, mediaMatch[1], decodeURIComponent(mediaMatch[2]));
    }
    const deleteMatch = path.match(/^\/api\/v1\/admin\/content\/(movie|series)\/([^/]+)$/);
    if (deleteMatch && method === "DELETE") {
      const user = await getAuthenticatedUser(request, env);
      return handleAdminDeleteContent(request, env, user, deleteMatch[1], decodeURIComponent(deleteMatch[2]));
    }

    return jsonError("NOT_FOUND", `Route not found: ${method} ${path}`, 404);
  }
};

// ----- worker.js -----
/* =========================================================
   NOOR PREMIUM — CLOUDFLARE WORKER API (D1 + RBAC + RATE LIMIT)
   ========================================================= */

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_AUTH = 20;
const rateBuckets = new Map();

function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization,X-CSRF-Token,X-Admin-Key",
      ...extraHeaders
    }
  });
}

function checkRateLimit(ipKey) {
  const now = Date.now();
  const entry = rateBuckets.get(ipKey);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateBuckets.set(ipKey, { windowStart: now, count: 1 });
    return { allowed: true };
  }
  entry.count += 1;
  if (entry.count > RATE_LIMIT_MAX_AUTH) {
    return { allowed: false, retryAfterSec: Math.ceil((RATE_LIMIT_WINDOW_MS - (now - entry.windowStart)) / 1000) };
  }
  return { allowed: true };
}

function sanitizeMediaUrl(raw) {
  const val = String(raw || "").trim();
  if (!val) return "";
  if (val.startsWith("/")) return val;
  try {
    const parsed = new URL(val);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      return parsed.toString();
    }
    return "";
  } catch (_) {
    return "";
  }
}

async function hashPasswordPbkdf2(password, saltHex = null) {
  const enc = new TextEncoder();
  const saltBytes = saltHex
    ? new Uint8Array(saltHex.match(/.{1,2}/g).map((b) => parseInt(b, 16)))
    : crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(String(password)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 100_000,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  const salt = Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const hash = Array.from(new Uint8Array(derivedBits))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return `${salt}:${hash}`;
}

async function verifyPasswordPbkdf2(password, storedValue) {
  const parts = String(storedValue || "").split(":");
  if (parts.length !== 2) return false;
  const [saltHex, expectedHash] = parts;
  const computed = await hashPasswordPbkdf2(password, saltHex);
  const [, actualHash] = computed.split(":");
  return actualHash === expectedHash;
}

function getUserKeyFromRequest(request) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ") && auth.length > 10) {
    return auth.slice(7).trim().slice(0, 64);
  }
  return "guest_user";
}

async function isAdminRequest(request, env) {
  const adminKey = request.headers.get("X-Admin-Key") || "";
  if (env.ADMIN_API_KEY && adminKey === env.ADMIN_API_KEY) return true;

  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return false;

  const token = auth.slice(7).trim();
  if (!token) return false;
  if (token.startsWith("np_admin_")) return true;

  const parts = token.split("_");
  const candidateUserId = parts.length >= 3 ? parts[2] : "";
  if (candidateUserId && env.DB) {
    const userRow = await env.DB
      .prepare("SELECT role FROM users WHERE id = ?")
      .bind(candidateUserId)
      .first();
    if (userRow && userRow.role === "admin") return true;
  }

  return false;
}

async function ensureTables(db) {
  if (!db) return;
  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `),
    db.prepare(`
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
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_key TEXT NOT NULL,
        content_type TEXT NOT NULL DEFAULT 'movie',
        content_id TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(user_key, content_type, content_id)
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS watch_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_key TEXT NOT NULL,
        content_id TEXT NOT NULL,
        content_type TEXT NOT NULL DEFAULT 'movie',
        title TEXT NOT NULL DEFAULT '',
        progress_percent INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(user_key, content_id)
      )
    `)
  ]);
}

function mapContentRow(row) {
  return {
    id: row.id,
    title: row.title,
    type: row.content_type || "movie",
    releaseYear: row.release_year || 2026,
    synopsis: row.synopsis || "",
    streamUrl: row.stream_url || "",
    posterUrl: row.poster_url || "",
    status: row.status || "draft"
  };
}
const legacyWorker = {
  async fetch(request, env, ctx) {
    const v1Res = await v1Worker.fetch(request, env, ctx);
    const url = new URL(request.url);
    const p = url.pathname;
    if (v1Res.status !== 404 || (!p.startsWith("/api/v1/contents") && !p.startsWith("/api/v1/feedback"))) {
      return v1Res;
    }
    return legacyFetch(request, env);
  }
};

async function legacyFetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    if (method === "OPTIONS") {
      return jsonResponse({ success: true }, 204);
    }

    if (path.startsWith("/api/v1/auth/")) {
      const ip = request.headers.get("CF-Connecting-IP") || "local";
      const rl = checkRateLimit(`${ip}:${path}`);
      if (!rl.allowed) {
        return jsonResponse(
          { success: false, error: `অনেক বেশি চেষ্টা করা হয়েছে। ${rl.retryAfterSec} সেকেন্ড পর চেষ্টা করুন।` },
          429,
          { "Retry-After": String(rl.retryAfterSec) }
        );
      }
    }

    if (path === "/api/v1/health" && method === "GET") {
      return jsonResponse({
        success: true,
        data: {
          app: env.APP_NAME || "NOOR PREMIUM",
          dbBound: Boolean(env.DB),
          timestamp: new Date().toISOString()
        }
      });
    }

    if (path === "/api/v1/auth/register" && method === "POST") {
      if (!env.DB) return jsonResponse({ success: false, error: "D1 DB not bound" }, 500);
      await ensureTables(env.DB);
      const body = await request.json().catch(() => ({}));
      const fullName = String(body.fullName || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const username = String(body.username || email.split("@")[0] || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!email || !username || password.length < 6) {
        return jsonResponse({ success: false, error: "সঠিক ইমেইল, ইউজারনেম ও কমপক্ষে ৬ অক্ষরের পাসওয়ার্ড দিন।" }, 400);
      }

      const existing = await env.DB
        .prepare("SELECT id FROM users WHERE email = ? OR username = ?")
        .bind(email, username)
        .first();

      if (existing) {
        return jsonResponse({ success: false, error: "এই ইমেইল বা ইউজারনেম দিয়ে ইতিমধ্যে অ্যাকাউন্ট আছে।" }, 409);
      }

      const id = `usr-${crypto.randomUUID().slice(0, 8)}`;
      const passwordHash = await hashPasswordPbkdf2(password);
      await env.DB
        .prepare("INSERT INTO users (id, full_name, email, username, password_hash, role) VALUES (?, ?, ?, ?, ?, 'user')")
        .bind(id, fullName || username, email, username, passwordHash)
        .run();

      const token = `np_tok_${id}_${crypto.randomUUID().slice(0, 12)}`;
      return jsonResponse({
        success: true,
        data: {
          token,
          user: { id, fullName: fullName || username, email, username, role: "user" }
        }
      });
    }

    if (path === "/api/v1/auth/login" && method === "POST") {
      if (!env.DB) return jsonResponse({ success: false, error: "D1 DB not bound" }, 500);
      await ensureTables(env.DB);
      const body = await request.json().catch(() => ({}));
      const identifier = String(body.identifier || "").trim().toLowerCase();
      const password = String(body.password || "");

      const user = await env.DB
        .prepare("SELECT id, full_name, email, username, password_hash, role FROM users WHERE email = ? OR username = ?")
        .bind(identifier, identifier)
        .first();

      if (!user || !(await verifyPasswordPbkdf2(password, user.password_hash))) {
        return jsonResponse({ success: false, error: "ইমেইল/ইউজারনেম অথবা পাসওয়ার্ড সঠিক নয়।" }, 401);
      }

      const prefix = user.role === "admin" ? "np_admin" : "np_tok";
      const token = `${prefix}_${user.id}_${crypto.randomUUID().slice(0, 12)}`;
      return jsonResponse({
        success: true,
        data: {
          token,
          user: {
            id: user.id,
            fullName: user.full_name,
            email: user.email,
            username: user.username,
            role: user.role
          }
        }
      });
    }

    if (path === "/api/v1/auth/logout" && method === "POST") {
      return jsonResponse({ success: true, data: { loggedOut: true } });
    }

    if (path === "/api/v1/catalog" && method === "GET") {
      if (!env.DB) return jsonResponse({ success: true, data: { items: [] } });
      await ensureTables(env.DB);
      const rows = await env.DB
        .prepare("SELECT * FROM contents WHERE status = 'published' ORDER BY rowid DESC")
        .all();
      return jsonResponse({
        success: true,
        data: { items: (rows.results || []).map(mapContentRow) }
      });
    }

    if (path.startsWith("/api/v1/catalog/") && method === "GET") {
      const id = decodeURIComponent(path.replace("/api/v1/catalog/", ""));
      if (!env.DB) return jsonResponse({ success: false, error: "Not found" }, 404);
      await ensureTables(env.DB);
      const row = await env.DB
        .prepare("SELECT * FROM contents WHERE id = ? AND status = 'published'")
        .bind(id)
        .first();
      if (!row) return jsonResponse({ success: false, error: "Content not found" }, 404);
      return jsonResponse({ success: true, data: { item: mapContentRow(row) } });
    }

    if (path === "/api/v1/watchlist") {
      if (!env.DB) return jsonResponse({ success: true, data: { items: [] } });
      await ensureTables(env.DB);
      const userKey = getUserKeyFromRequest(request);

      if (method === "GET") {
        const rows = await env.DB
          .prepare("SELECT content_type, content_id, created_at FROM watchlist WHERE user_key = ? ORDER BY id DESC")
          .bind(userKey)
          .all();
        return jsonResponse({
          success: true,
          data: {
            items: (rows.results || []).map((r) => ({
              contentType: r.content_type,
              contentId: r.content_id,
              addedAt: r.created_at
            }))
          }
        });
      }

      const body = await request.json().catch(() => ({}));
      const contentType = body.contentType === "series" ? "series" : "movie";
      const contentId = String(body.contentId || "").trim();
      if (!contentId) return jsonResponse({ success: false, error: "contentId required" }, 400);

      if (method === "POST") {
        await env.DB
          .prepare("INSERT OR IGNORE INTO watchlist (user_key, content_type, content_id) VALUES (?, ?, ?)")
          .bind(userKey, contentType, contentId)
          .run();
        return jsonResponse({ success: true });
      }

      if (method === "DELETE") {
        await env.DB
          .prepare("DELETE FROM watchlist WHERE user_key = ? AND content_id = ?")
          .bind(userKey, contentId)
          .run();
        return jsonResponse({ success: true });
      }
    }

    if (path === "/api/v1/history") {
      if (!env.DB) return jsonResponse({ success: true, data: { items: [] } });
      await ensureTables(env.DB);
      const userKey = getUserKeyFromRequest(request);

      if (method === "GET") {
        const rows = await env.DB
          .prepare("SELECT content_id, content_type, title, progress_percent, updated_at FROM watch_history WHERE user_key = ? ORDER BY updated_at DESC LIMIT 30")
          .bind(userKey)
          .all();
        return jsonResponse({
          success: true,
          data: {
            items: (rows.results || []).map((r) => ({
              contentId: r.content_id,
              contentType: r.content_type,
              title: r.title,
              progressPercent: r.progress_percent,
              updatedAt: r.updated_at
            }))
          }
        });
      }

      if (method === "POST") {
        const body = await request.json().catch(() => ({}));
        const contentId = String(body.contentId || "").trim();
        const contentType = body.contentType === "series" ? "series" : "movie";
        const title = String(body.title || contentId).trim();
        const progressPercent = Math.max(0, Math.min(100, Number(body.progressPercent) || 0));
        if (!contentId) return jsonResponse({ success: false, error: "contentId required" }, 400);

        await env.DB
          .prepare(`
            INSERT INTO watch_history (user_key, content_id, content_type, title, progress_percent, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(user_key, content_id) DO UPDATE SET
              title = excluded.title,
              progress_percent = excluded.progress_percent,
              updated_at = datetime('now')
          `)
          .bind(userKey, contentId, contentType, title, progressPercent)
          .run();

        return jsonResponse({ success: true });
      }
    }

    if (path.startsWith("/api/v1/admin/")) {
      if (!(await isAdminRequest(request, env))) {
        return jsonResponse({ success: false, error: "Admin authorization required" }, 401);
      }
      if (!env.DB) return jsonResponse({ success: false, error: "D1 DB not bound" }, 500);
      await ensureTables(env.DB);

      if (path === "/api/v1/admin/content" && method === "GET") {
        const rows = await env.DB.prepare("SELECT * FROM contents ORDER BY rowid DESC").all();
        return jsonResponse({ success: true, data: { items: (rows.results || []).map(mapContentRow) } });
      }

      if (path === "/api/v1/admin/content" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const id = String(body.id || `cnt-${crypto.randomUUID().slice(0, 6)}`).trim();
        const title = String(body.title || "").trim();
        const type = body.type === "series" ? "series" : "movie";
        const releaseYear = Number(body.releaseYear) || 2026;
        const synopsis = String(body.synopsis || "").trim();
        const streamUrl = sanitizeMediaUrl(body.streamUrl);
        const posterUrl = sanitizeMediaUrl(body.posterUrl);

        if (!title) return jsonResponse({ success: false, error: "Title required" }, 400);

        await env.DB
          .prepare(`
            INSERT INTO contents (id, title, content_type, release_year, synopsis, stream_url, poster_url, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'draft')
          `)
          .bind(id, title, type, releaseYear, synopsis, streamUrl, posterUrl)
          .run();

        return jsonResponse({
          success: true,
          data: {
            item: { id, title, type, releaseYear, synopsis, streamUrl, posterUrl, status: "draft" }
          }
        });
      }

      const statusMatch = path.match(/^\/api\/v1\/admin\/content\/([^/]+)\/status$/);
      if (statusMatch && method === "PATCH") {
        const id = decodeURIComponent(statusMatch[1]);
        const body = await request.json().catch(() => ({}));
        const nextStatus = body.status === "published" ? "published" : "draft";
        await env.DB
          .prepare("UPDATE contents SET status = ?, updated_at = datetime('now') WHERE id = ?")
          .bind(nextStatus, id)
          .run();
        return jsonResponse({ success: true, data: { id, status: nextStatus } });
      }

      const itemMatch = path.match(/^\/api\/v1\/admin\/content\/([^/]+)$/);
      if (itemMatch && method === "PATCH") {
        const id = decodeURIComponent(itemMatch[1]);
        const body = await request.json().catch(() => ({}));
        const existing = await env.DB.prepare("SELECT * FROM contents WHERE id = ?").bind(id).first();
        if (!existing) return jsonResponse({ success: false, error: "Not found" }, 404);

        const nextTitle = body.title !== undefined ? String(body.title).trim() : existing.title;
        const nextYear = body.releaseYear !== undefined ? Number(body.releaseYear) || existing.release_year : existing.release_year;
        const nextSynopsis = body.synopsis !== undefined ? String(body.synopsis).trim() : existing.synopsis;
        const nextStream = body.streamUrl !== undefined ? sanitizeMediaUrl(body.streamUrl) : existing.stream_url;
        const nextPoster = body.posterUrl !== undefined ? sanitizeMediaUrl(body.posterUrl) : existing.poster_url;

        await env.DB
          .prepare(`
            UPDATE contents
            SET title = ?, release_year = ?, synopsis = ?, stream_url = ?, poster_url = ?, updated_at = datetime('now')
            WHERE id = ?
          `)
          .bind(nextTitle, nextYear, nextSynopsis, nextStream, nextPoster, id)
          .run();

        return jsonResponse({ success: true });
      }

      if (itemMatch && method === "DELETE") {
        const id = decodeURIComponent(itemMatch[1]);
        await env.DB.prepare("DELETE FROM contents WHERE id = ?").bind(id).run();
        return jsonResponse({ success: true });
      }
    }

    return jsonResponse({ success: false, error: "Not found" }, 404);
  }
};


export default {
  async fetch(request, env, ctx) {
    if (typeof v1Worker !== "undefined" && v1Worker && typeof v1Worker.fetch === "function") {
      const res = await v1Worker.fetch(request, env, ctx);
      const url = new URL(request.url);
      const p = url.pathname;
      if (res.status !== 404 || (!p.startsWith("/api/v1/contents") && !p.startsWith("/api/v1/feedback"))) {
        return res;
      }
    }
    if (typeof legacyWorker !== "undefined" && legacyWorker && typeof legacyWorker.fetch === "function") {
      return legacyWorker.fetch(request, env, ctx);
    }
    return handleRequest(request, env, ctx);
  }
};
