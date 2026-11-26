import * as bcrypt from "bcryptjs";

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_PREFIX = "$pbkdf2-sha256$";

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Hashes a plaintext password using hardware-accelerated Web Crypto PBKDF2-SHA256
 * to avoid blocking the Cloudflare Worker isolate event loop.
 */
export async function hashPasswordPBKDF2(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
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
    256
  );
  const derivedBytes = new Uint8Array(derivedBits);
  return `${PBKDF2_PREFIX}${PBKDF2_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(derivedBytes)}`;
}

/**
 * Verifies a password against either native PBKDF2-SHA256 or legacy bcrypt hashes.
 * Signals `needsUpgrade = true` when a legacy bcrypt credential validates so callers
 * can transparently re-hash to PBKDF2 on login.
 */
export async function verifyPassword(
  password: string,
  storedHash: string
): Promise<{ valid: boolean; needsUpgrade: boolean }> {
  if (!password || !storedHash) {
    return { valid: false, needsUpgrade: false };
  }

  if (storedHash.startsWith(PBKDF2_PREFIX)) {
    try {
      const rest = storedHash.slice(PBKDF2_PREFIX.length);
      const parts = rest.split("$");
      if (parts.length !== 3) return { valid: false, needsUpgrade: false };
      const iterations = parseInt(parts[0], 10);
      if (!Number.isFinite(iterations) || iterations < 10000 || iterations > 1000000) {
        return { valid: false, needsUpgrade: false };
      }
      const salt = base64ToBytes(parts[1]);
      const expected = base64ToBytes(parts[2]);

      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
      );
      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: salt as BufferSource,
          iterations,
          hash: "SHA-256"
        },
        keyMaterial,
        expected.byteLength * 8
      );
      const actual = new Uint8Array(derivedBits);
      return { valid: constantTimeEqualBytes(actual, expected), needsUpgrade: false };
    } catch {
      return { valid: false, needsUpgrade: false };
    }
  }

  // Legacy bcrypt hash ($2a$ / $2b$ / $2y$)
  try {
    const valid = bcrypt.compareSync(password, storedHash);
    return { valid, needsUpgrade: valid };
  } catch {
    return { valid: false, needsUpgrade: false };
  }
}
