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

export function timingSafeEqualStrings(a, b) {
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

export function generateRandomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

export async function sha256Hex(input) {
  const data = new TextEncoder().encode(String(input));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}

export async function hashPassword(password) {
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

export async function verifyPassword(password, storedHash) {
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
