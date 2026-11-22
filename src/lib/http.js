/* =========================================================
   NOOR PREMIUM — HTTP RESPONSE, HEADERS & PARSER HELPERS
   Standard REST API v1 Envelope + Security Headers
   ========================================================= */

export function applySecurityHeaders(headers, options = {}) {
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

export function jsonSuccess(data = {}, status = 200, meta = {}, extraHeaders = null) {
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

export function jsonError(code, message, status = 400, details = null, extraHeaders = null) {
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

export async function readJsonBody(request) {
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
