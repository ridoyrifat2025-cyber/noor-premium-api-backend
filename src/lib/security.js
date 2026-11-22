/* =========================================================
   NOOR PREMIUM — COOKIES, CSRF & RATE LIMIT HELPERS
   HttpOnly Session Cookie + Double-Submit CSRF Guard
   ========================================================= */

import { generateRandomToken, timingSafeEqualStrings } from "./crypto.js";

export const SESSION_COOKIE_NAME = "noor_session";
export const CSRF_COOKIE_NAME = "noor_csrf";

const rateLimitBuckets = new Map();

export function parseCookies(cookieHeader) {
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

export function buildSessionCookie(token, maxAgeSeconds = 60 * 60 * 24 * 7, isSecure = true) {
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

export function buildClearSessionCookie(isSecure = true) {
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

export function buildCsrfCookie(csrfToken, maxAgeSeconds = 60 * 60 * 24 * 7, isSecure = true) {
  const attrs = [
    `${CSRF_COOKIE_NAME}=${encodeURIComponent(csrfToken)}`,
    "Path=/",
    "SameSite=Strict",
    `Max-Age=${maxAgeSeconds}`
  ];
  if (isSecure) attrs.push("Secure");
  return attrs.join("; ");
}

export function ensureCsrfToken(request) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  if (cookies[CSRF_COOKIE_NAME] && cookies[CSRF_COOKIE_NAME].length >= 16) {
    return { token: cookies[CSRF_COOKIE_NAME], isNew: false };
  }
  return { token: generateRandomToken(24), isNew: true };
}

export function verifyCsrfRequest(request) {
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

export function checkRateLimit(bucketKey, maxAttempts = 8, windowMs = 60000) {
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
