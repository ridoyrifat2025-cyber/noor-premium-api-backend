/* =========================================================
   NOOR PREMIUM — CLOUDFLARE WORKER ENTRYPOINT (PHASE 15)
   REST API v1: Auth, Catalog, Watchlist, History & Admin CMS
   ========================================================= */

import { jsonSuccess, jsonError, readJsonBody } from "./lib/http.js";
import { hashPassword, verifyPassword, generateRandomToken, sha256Hex } from "./lib/crypto.js";
import {
  SESSION_COOKIE_NAME,
  parseCookies,
  buildSessionCookie,
  buildClearSessionCookie,
  buildCsrfCookie,
  ensureCsrfToken,
  verifyCsrfRequest,
  checkRateLimit
} from "./lib/security.js";
import {
  handleListCatalog,
  handleGetCatalogItem,
  handleGetSeriesSeasons
} from "./routes/catalog.js";
import {
  handleGetWatchlist,
  handleAddWatchlist,
  handleRemoveWatchlist,
  handleGetHistory,
  handleUpsertHistory
} from "./routes/userData.js";
import {
  handleAdminListContent,
  handleAdminCreateContent,
  handleAdminUpdateStatus,
  handleAdminUpdateMedia,
  handleAdminDeleteContent
} from "./routes/admin.js";

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
  const authHeader = request.headers.get("Authorization") || "";
  const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  const rawToken = cookies[SESSION_COOKIE_NAME] || bearerToken;
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

export default {
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
