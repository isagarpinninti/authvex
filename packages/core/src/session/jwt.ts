import { b64urlDecode, b64urlEncode, constantTimeEqual, fromUtf8, sha256, utf8, type Bytes } from "../util/bytes";
import { importPublicKey, signBytes, verifyBytes, type IssuerKey, type PublicKeys } from "./tokens";

/** Standard compact JWTs signed with ES256 (RFC 7515, 7519), for the OpenID Connect ID token: any OIDC library can verify them. */
export async function signJwt(payload: Record<string, unknown>, issuer: IssuerKey, header: Record<string, unknown> = {}): Promise<string> {
  const h = b64urlEncode(utf8(JSON.stringify({ alg: "ES256", typ: "JWT", kid: issuer.kid, ...header })));
  const p = b64urlEncode(utf8(JSON.stringify(payload)));
  return `${h}.${p}.${b64urlEncode(await signBytes(issuer.privateKey, utf8(`${h}.${p}`)))}`;
}

export type JwtFailure = "malformed" | "unsupported_alg" | "unknown_key" | "bad_signature" | "expired" | "not_yet_valid" | "wrong_issuer" | "wrong_audience" | "wrong_nonce";

export type JwtResult = { ok: true; header: Record<string, unknown>; claims: Record<string, unknown> } | { ok: false; reason: JwtFailure; message: string };

/**
 * Verifies a compact ES256 JWT: structure, `alg` (only ES256: never "none", never a symmetric algorithm), signature against the key
 * named by `kid`, then the claims you ask about (`iss`, `aud`, `nonce`, `exp`, `nbf`).
 */
export async function verifyJwt(token: string, keys: PublicKeys, expect: { issuer?: string; audience?: string; nonce?: string; nowMs?: number; clockSkewSeconds?: number } = {}): Promise<JwtResult> {
  const fail = (reason: JwtFailure, message: string): JwtResult => ({ ok: false, reason, message });
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => !p)) return fail("malformed", "a JWT has three parts");
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  let sig: Bytes;
  try {
    header = JSON.parse(fromUtf8(b64urlDecode(parts[0] as string))) as Record<string, unknown>;
    claims = JSON.parse(fromUtf8(b64urlDecode(parts[1] as string))) as Record<string, unknown>;
    sig = b64urlDecode(parts[2] as string);
  } catch {
    return fail("malformed", "the JWT is not base64url JSON");
  }
  if (header === null || typeof header !== "object" || claims === null || typeof claims !== "object") return fail("malformed", "the JWT header and claims must be objects");
  if (header["alg"] !== "ES256") return fail("unsupported_alg", `alg ${String(header["alg"])} is not accepted (only ES256)`);
  const set = Array.isArray((keys as { keys?: unknown }).keys) ? (keys as { keys: ReadonlyArray<JsonWebKey & { kid?: string }> }).keys : null;
  let candidates: JsonWebKey[];
  if (!set) candidates = [keys as JsonWebKey];
  else if (typeof header["kid"] === "string") {
    candidates = set.filter((k) => k.kid === header["kid"]);
    if (candidates.length === 0) return fail("unknown_key", "no trusted key has that kid");
  } else candidates = set.slice(0, 8);
  let valid = false;
  for (const k of candidates) {
    if (await importPublicKey(k).then((key) => verifyBytes(key, sig, utf8(`${parts[0]}.${parts[1]}`))).catch(() => false)) {
      valid = true;
      break;
    }
  }
  if (!valid) return fail("bad_signature", "the signature does not verify");
  const now = Math.floor((expect.nowMs ?? Date.now()) / 1000);
  const skew = expect.clockSkewSeconds ?? 60;
  if (typeof claims["exp"] !== "number") return fail("malformed", "the JWT has no exp");
  if (now - skew >= (claims["exp"] as number)) return fail("expired", "the token has expired");
  if (typeof claims["nbf"] === "number" && now + skew < (claims["nbf"] as number)) return fail("not_yet_valid", "the token is not valid yet");
  if (expect.issuer !== undefined && claims["iss"] !== expect.issuer) return fail("wrong_issuer", "the issuer is not the expected one");
  if (expect.audience !== undefined) {
    const aud = claims["aud"];
    if (!(aud === expect.audience || (Array.isArray(aud) && aud.includes(expect.audience)))) return fail("wrong_audience", "the token was not issued for this audience");
  }
  if (expect.nonce !== undefined && (typeof claims["nonce"] !== "string" || !constantTimeEqual(utf8(claims["nonce"] as string), utf8(expect.nonce)))) return fail("wrong_nonce", "the nonce does not match");
  return { ok: true, header, claims };
}

/** `at_hash` / `c_hash`: the left half of the SHA-256 of the value, base64url (OpenID Connect Core 3.1.3.6). */
export async function halfHash(value: string): Promise<string> {
  return b64urlEncode((await sha256(value)).subarray(0, 16));
}

/* ───────────────────────── PKCE (RFC 7636) ───────────────────────── */

const VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;
export const isValidCodeVerifier = (v: string): boolean => VERIFIER.test(v);
/** S256: base64url(SHA-256(verifier)). A challenge is 43 base64url characters. */
export const pkceChallenge = async (verifier: string): Promise<string> => b64urlEncode(await sha256(verifier));
export const isValidCodeChallenge = (c: string): boolean => /^[A-Za-z0-9\-_]{43}$/.test(c);

export async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
  return isValidCodeVerifier(verifier) && isValidCodeChallenge(challenge) && constantTimeEqual(utf8(await pkceChallenge(verifier)), utf8(challenge));
}
