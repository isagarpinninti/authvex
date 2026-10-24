import { b64urlDecode, b64urlEncode, constantTimeEqual, randomBytes, toBytes, utf8, type Bytes } from "../util/bytes";

/* ───────────────────────── password vault ───────────────────────── */

export const PBKDF2_ITERATIONS = 210_000;
const SALT_BYTES = 16;
const HASH_BYTES = 32;
const MAX_ACCEPTED_ITERATIONS = 5_000_000;
const PREFIX = "$ath-pbkdf2$v=1$iter=";

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<Bytes> {
  const key = await globalThis.crypto.subtle.importKey("raw", utf8(password.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: toBytes(salt), iterations }, key, HASH_BYTES * 8)) as Bytes;
}

/** `$ath-pbkdf2$v=1$iter=210000$<salt>$<hash>`: PBKDF2-HMAC-SHA256 with a random 16-byte salt. */
export async function hashPassword(password: string, iterations = PBKDF2_ITERATIONS): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  return `${PREFIX}${iterations}$${b64urlEncode(salt)}$${b64urlEncode(await derive(password, salt, iterations))}`;
}

function parseHash(stored: string): { iterations: number; salt: Bytes; hash: Bytes } | null {
  if (!stored.startsWith(PREFIX)) return null;
  const [iter, salt, hash, ...extra] = stored.slice(PREFIX.length).split("$");
  if (extra.length > 0 || !iter || !salt || !hash || !/^[1-9][0-9]{0,8}$/.test(iter)) return null;
  const iterations = Number(iter);
  if (iterations > MAX_ACCEPTED_ITERATIONS) return null;
  try {
    const s = b64urlDecode(salt);
    const h = b64urlDecode(hash);
    return s.length >= 8 && h.length === HASH_BYTES ? { iterations, salt: s, hash: h } : null;
  } catch {
    return null;
  }
}

/**
 * Verifies a password against a stored hash with a constant-time comparison. A malformed hash still costs one derivation, so
 * "no such user" and "wrong password" cannot be told apart by timing.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parsed = parseHash(stored);
  const salt = parsed?.salt ?? new Uint8Array(SALT_BYTES);
  const derived = await derive(password, salt, parsed?.iterations ?? PBKDF2_ITERATIONS);
  return parsed !== null && constantTimeEqual(derived, parsed.hash);
}

/** True when the stored hash uses fewer iterations than today's default and should be re-hashed after a successful login. */
export function passwordNeedsRehash(stored: string): boolean {
  const parsed = parseHash(stored);
  return parsed === null || parsed.iterations < PBKDF2_ITERATIONS;
}

/** A hash that never verifies, for users who have no password (passkey-only accounts). */
export const NO_PASSWORD = "$ath-pbkdf2$v=1$iter=1$disabled$disabled";

/* ───────────────────────── Base32 (RFC 4648) ───────────────────────── */

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Bytes {
  const clean = input.replace(/[\s=]/g, "").toUpperCase();
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new TypeError(`"${ch}" is not a Base32 character`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out) as Bytes;
}

/* ───────────────────────── HOTP / TOTP (RFC 4226, RFC 6238) ───────────────────────── */

/** 20 random bytes (160 bits, the RFC 4226 recommendation) as Base32. */
export const generateTotpSecret = (): string => base32Encode(randomBytes(20));

export function buildOtpAuthUri(opts: { secretB32: string; account: string; issuer: string; digits?: number; period?: number }): string {
  const label = `${encodeURIComponent(opts.issuer)}:${encodeURIComponent(opts.account)}`;
  const q = new URLSearchParams({ secret: opts.secretB32, issuer: opts.issuer, algorithm: "SHA1", digits: String(opts.digits ?? 6), period: String(opts.period ?? 30) });
  return `otpauth://totp/${label}?${q.toString()}`;
}

/** RFC 4226 HOTP: HMAC-SHA1 over the 8-byte big-endian counter, dynamic truncation, `digits` decimal digits. */
export async function computeHotp(secret: Uint8Array, counter: number, digits = 6): Promise<string> {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError("counter must be a non-negative safe integer");
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter));
  const key = await globalThis.crypto.subtle.importKey("raw", toBytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, msg));
  const offset = (mac[19] as number) & 0x0f;
  const bin = (((mac[offset] as number) & 0x7f) << 24) | ((mac[offset + 1] as number) << 16) | ((mac[offset + 2] as number) << 8) | (mac[offset + 3] as number);
  return String(bin % 10 ** digits).padStart(digits, "0");
}

export interface TotpOptions {
  nowMs?: number;
  /** Seconds per code. Default 30. */
  step?: number;
  digits?: number;
}

export const totpCounter = (nowMs: number, step = 30): number => Math.floor(nowMs / 1000 / step);

export async function computeTotpCode(secretB32: string, opts: TotpOptions = {}): Promise<string> {
  return computeHotp(base32Decode(secretB32), totpCounter(opts.nowMs ?? Date.now(), opts.step), opts.digits ?? 6);
}

/**
 * Checks a code against the current time step and `window` steps either side (clock drift). Every candidate is compared in
 * constant time. `minCounter` rejects a code from a step at or before one already accepted, so a code works only once.
 */
export async function verifyTotpCode(
  secretB32: string,
  code: string,
  opts: TotpOptions & { window?: number; minCounter?: number } = {},
): Promise<{ ok: true; counter: number } | { ok: false }> {
  const digits = opts.digits ?? 6;
  if (!new RegExp(`^[0-9]{${digits}}$`).test(code)) return { ok: false };
  const secret = base32Decode(secretB32);
  const now = totpCounter(opts.nowMs ?? Date.now(), opts.step);
  const window = opts.window ?? 1;
  let matched: number | null = null;
  for (let c = now - window; c <= now + window; c++) {
    if (c < 0) continue;
    const expected = await computeHotp(secret, c, digits);
    if (constantTimeEqual(utf8(expected), utf8(code)) && matched === null && (opts.minCounter === undefined || c > opts.minCounter)) matched = c;
  }
  return matched === null ? { ok: false } : { ok: true, counter: matched };
}
