import { b64urlDecode, b64urlEncode, constantTimeEqual, fromUtf8, hex, randomBytes, sha256, utf8, type Bytes } from "../util/bytes";
import { TOKEN_PREFIX, computeJwkThumbprint, importPublicKey, randomId, signBytes, signToken, verifyBytes, verifySignedToken, type ExternalSigner, type IssuerKey, type PublicKeys } from "./tokens";

/* ───────────────────────── hardware-bound sessions (RFC 9449) ───────────────────────── */

export interface SessionClaims {
  v: 1;
  typ: "session";
  sub: string;
  tid: string;
  /** Refresh-token family this session belongs to. */
  fam: string;
  gen: number;
  jti: string;
  iat: number;
  exp: number;
  /** For an OIDC access token: the client it was issued to, and the space-separated scopes granted. */
  cid?: string;
  scp?: string;
  /** Confirmation (RFC 7800): the SHA-256 thumbprint of the client's DPoP public key. Absent for unbound sessions. */
  cnf?: { jkt: string };
}

export type FamilyStatus = "active" | "revoked_reuse_detected" | "revoked_manual" | "expired";

/** A login's chain of refresh tokens. Only hashes are kept, so a leaked store cannot be replayed. */
export interface SessionFamily {
  familyId: string;
  userId: string;
  tenantId: string;
  currentGeneration: number;
  activeRefreshTokenHash: string;
  consumedRefreshTokenHashes: string[];
  status: FamilyStatus;
  /** Thumbprint of the key the family is bound to, if any. */
  boundJkt?: string;
  /** Set for sessions issued to an OIDC client: which client, and the scopes granted. */
  clientId?: string;
  scope?: string;
  createdAtIso: string;
  lastRotatedAtIso: string;
  expiresAtIso: string;
  revokedAtIso?: string;
  device?: { name?: string; city?: string; ip?: string };
}

const nowSec = (nowMs: number): number => Math.floor(nowMs / 1000);
const refreshHash = async (token: string): Promise<string> => hex(await sha256(token));
const newRefreshToken = (): string => `${TOKEN_PREFIX.refresh}${b64urlEncode(randomBytes(32))}`;

async function signSession(issuer: IssuerKey, claims: SessionClaims): Promise<string> {
  return signToken(TOKEN_PREFIX.session, claims, issuer.privateKey, issuer.kid);
}

export interface IssueSessionOptions {
  issuer: IssuerKey;
  userId: string;
  tenantId: string;
  /** The client's DPoP public key. When given, the session is bound to it (`cnf.jkt`). */
  clientPublicKeyJwk?: JsonWebKey;
  accessTtlSeconds?: number;
  refreshTtlSeconds?: number;
  nowMs?: number;
  device?: SessionFamily["device"];
  /** Issue the session to an OIDC client with these scopes (they are carried in the access token and the family). */
  client?: { clientId: string; scope: string };
}

export interface SessionBundle {
  sessionToken: string;
  refreshToken: string;
  claims: SessionClaims;
  family: SessionFamily;
}

/** Starts a session family and returns its first access token (generation 1) and refresh token. */
export async function issueSessionBundle(opts: IssueSessionOptions): Promise<SessionBundle> {
  const nowMs = opts.nowMs ?? Date.now();
  const access = opts.accessTtlSeconds ?? 900;
  const refresh = opts.refreshTtlSeconds ?? 604_800;
  const boundJkt = opts.clientPublicKeyJwk ? await computeJwkThumbprint(opts.clientPublicKeyJwk) : undefined;
  const refreshToken = newRefreshToken();
  const family: SessionFamily = {
    familyId: randomId("fam_"),
    userId: opts.userId,
    tenantId: opts.tenantId,
    currentGeneration: 1,
    activeRefreshTokenHash: await refreshHash(refreshToken),
    consumedRefreshTokenHashes: [],
    status: "active",
    ...(boundJkt ? { boundJkt } : {}),
    createdAtIso: new Date(nowMs).toISOString(),
    lastRotatedAtIso: new Date(nowMs).toISOString(),
    expiresAtIso: new Date(nowMs + refresh * 1000).toISOString(),
    ...(opts.device ? { device: opts.device } : {}),
    ...(opts.client ? { clientId: opts.client.clientId, scope: opts.client.scope } : {}),
  };
  const claims: SessionClaims = { v: 1, typ: "session", sub: opts.userId, tid: opts.tenantId, fam: family.familyId, gen: 1, jti: randomId("jti_"), iat: nowSec(nowMs), exp: nowSec(nowMs) + access, ...(opts.client ? { cid: opts.client.clientId, scp: opts.client.scope } : {}), ...(boundJkt ? { cnf: { jkt: boundJkt } } : {}) };
  return { sessionToken: await signSession(opts.issuer, claims), refreshToken, claims, family };
}

/* ───────────────────────── DPoP proofs ───────────────────────── */

export interface DpopClaims {
  htm: string;
  htu: string;
  iat: number;
  jti: string;
  /** base64url SHA-256 of the access token this proof accompanies. */
  ath?: string;
}

/** Drops query and fragment (the URL parser already lowercases scheme and host), as RFC 9449 section 4.3 asks. */
export function normalizeHtu(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.host}${u.pathname}`;
}

/**
 * Signs `{ htm, htu, iat, jti, ath }` with the client's private key: proof it still holds the key the session is bound to. The result is a
 * standard RFC 9449 `dpop+jwt`, so any DPoP-aware server or library accepts it. `legacyPrefix` adds the `ath_dpop_` prefix older Authvex
 * versions used (the verifier accepts both).
 */
export async function createDpopProof(opts: { privateKey: CryptoKey | ExternalSigner; publicKeyJwk: JsonWebKey; method: string; url: string; sessionToken?: string; nowMs?: number; jti?: string; legacyPrefix?: boolean }): Promise<string> {
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: { kty: opts.publicKeyJwk.kty, crv: opts.publicKeyJwk.crv, x: opts.publicKeyJwk.x, y: opts.publicKeyJwk.y } };
  const claims: DpopClaims = {
    htm: opts.method.toUpperCase(),
    htu: normalizeHtu(opts.url),
    iat: nowSec(opts.nowMs ?? Date.now()),
    jti: opts.jti ?? randomId("dp_"),
    ...(opts.sessionToken ? { ath: b64urlEncode(await sha256(opts.sessionToken)) } : {}),
  };
  const h = b64urlEncode(utf8(JSON.stringify(header)));
  const p = b64urlEncode(utf8(JSON.stringify(claims)));
  return `${opts.legacyPrefix ? TOKEN_PREFIX.dpop : ""}${h}.${p}.${b64urlEncode(await signBytes(opts.privateKey, utf8(`${h}.${p}`)))}`;
}

/** Remembers proof ids so a captured proof cannot be replayed. Implementations may be shared between processes. */
export interface ReplayCache {
  /** True the first time an id is seen within the window, false on a replay. */
  claim(jti: string, nowMs: number): boolean | Promise<boolean>;
}

/** An in-memory `ReplayCache`: remembers proof ids for a short window. */
export class DpopReplayCache implements ReplayCache {
  private readonly seen = new Map<string, number>();
  constructor(private readonly ttlMs = 120_000) {}

  /** True the first time an id is seen within the window, false on a replay. */
  claim(jti: string, nowMs: number): boolean {
    for (const [k, exp] of this.seen) if (exp <= nowMs) this.seen.delete(k);
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, nowMs + this.ttlMs);
    return true;
  }
}

export type DpopFailure =
  | "malformed"
  | "bad_signature"
  | "key_mismatch"
  | "htm_mismatch"
  | "htu_mismatch"
  | "iat_out_of_window"
  | "ath_mismatch"
  | "replayed";

export type DpopProofResult = { ok: true; jkt: string; claims: DpopClaims } | { ok: false; reason: DpopFailure; message: string };

const dfail = (reason: DpopFailure, message: string): { ok: false; reason: DpopFailure; message: string } => ({ ok: false, reason, message });

/**
 * Verifies a DPoP proof on its own: the signature is by the key in the proof's own header, the method and URL are the ones
 * requested, the timestamp is fresh, the access-token hash matches, and the id has not been seen. Returns the key's thumbprint,
 * which the caller compares with the session's `cnf.jkt`.
 */
export async function verifyDpopProof(opts: {
  proof: string;
  method: string;
  url: string;
  sessionToken?: string;
  nowMs?: number;
  maxSkewSeconds?: number;
  replayCache?: ReplayCache;
}): Promise<DpopProofResult> {
  const raw = opts.proof.startsWith(TOKEN_PREFIX.dpop) ? opts.proof.slice(TOKEN_PREFIX.dpop.length) : opts.proof;
  const parts = raw.split(".");
  if (parts.length !== 3 || parts.some((p) => !p)) return dfail("malformed", "a DPoP proof has three parts");
  let header: { typ?: string; alg?: string; jwk?: JsonWebKey };
  let claims: Partial<DpopClaims>;
  let sig: Bytes;
  try {
    header = JSON.parse(fromUtf8(b64urlDecode(parts[0] as string))) as typeof header;
    claims = JSON.parse(fromUtf8(b64urlDecode(parts[1] as string))) as Partial<DpopClaims>;
    sig = b64urlDecode(parts[2] as string);
  } catch {
    return dfail("malformed", "the proof is not valid base64url JSON");
  }
  if (header.typ !== "dpop+jwt" || header.alg !== "ES256" || !header.jwk) return dfail("malformed", 'the header must be { typ: "dpop+jwt", alg: "ES256", jwk }');
  if (typeof claims.htm !== "string" || typeof claims.htu !== "string" || typeof claims.iat !== "number" || typeof claims.jti !== "string") return dfail("malformed", "the proof is missing htm, htu, iat or jti");
  let jkt: string;
  let valid: boolean;
  try {
    jkt = await computeJwkThumbprint(header.jwk);
    valid = await verifyBytes(await importPublicKey(header.jwk), sig, utf8(`${parts[0]}.${parts[1]}`));
  } catch {
    return dfail("malformed", "the proof's public key is not a usable P-256 key");
  }
  if (!valid) return dfail("bad_signature", "the proof is not signed by the key in its header");
  if (claims.htm !== opts.method.toUpperCase()) return dfail("htm_mismatch", `the proof is for ${claims.htm}, not ${opts.method.toUpperCase()}`);
  if (claims.htu !== normalizeHtu(opts.url)) return dfail("htu_mismatch", "the proof is for a different URL");
  const now = nowSec(opts.nowMs ?? Date.now());
  const skew = opts.maxSkewSeconds ?? 60;
  if (Math.abs(now - claims.iat) > skew) return dfail("iat_out_of_window", `the proof's timestamp is more than ${skew}s from now`);
  if (opts.sessionToken !== undefined) {
    const expected = b64urlEncode(await sha256(opts.sessionToken));
    if (typeof claims.ath !== "string" || !constantTimeEqual(utf8(claims.ath), utf8(expected))) return dfail("ath_mismatch", "the proof was not made for this access token");
  }
  if (opts.replayCache && !(await opts.replayCache.claim(claims.jti, opts.nowMs ?? Date.now()))) return dfail("replayed", "this proof has already been used");
  return { ok: true, jkt, claims: claims as DpopClaims };
}

export type SessionFailure = "malformed" | "bad_signature" | "unknown_key" | "expired" | "not_bound" | "dpop_missing" | DpopFailure | "key_mismatch";

export type SessionVerification =
  | { ok: true; claims: SessionClaims; bound: boolean }
  | { ok: false; reason: SessionFailure; message: string; claims?: SessionClaims };

/**
 * The resource server's check. The session token's signature and expiry are verified, and, for a bound session, the DPoP proof
 * must be signed by the very key whose thumbprint is in `cnf.jkt`. A stolen token without the private key stops here.
 */
export async function verifyDpopSessionRequest(opts: {
  sessionToken: string;
  dpopProof?: string;
  method: string;
  url: string;
  /** The issuer's public key, or its JWKS (`/.well-known/jwks.json`) to verify across key rotations. */
  issuerPublicKeyJwk: PublicKeys;
  nowMs?: number;
  replayCache?: ReplayCache;
  /** Refuse sessions that are not bound to a key. Default false. */
  requireBinding?: boolean;
}): Promise<SessionVerification> {
  const nowMs = opts.nowMs ?? Date.now();
  const t = await verifySignedToken<SessionClaims>(TOKEN_PREFIX.session, opts.sessionToken, opts.issuerPublicKeyJwk);
  if (!t.ok) return { ok: false, reason: t.reason, message: t.reason === "malformed" ? "not a session token" : t.reason === "unknown_key" ? "the session token was signed by a key this server does not trust (retired or revoked)" : "the session token's signature is invalid" };
  const claims = t.payload;
  if (claims.typ !== "session" || typeof claims.exp !== "number" || typeof claims.sub !== "string") return { ok: false, reason: "malformed", message: "the session payload is incomplete" };
  if (nowSec(nowMs) >= claims.exp) return { ok: false, reason: "expired", message: "the session token has expired", claims };
  if (!claims.cnf) {
    if (opts.requireBinding) return { ok: false, reason: "not_bound", message: "this tenant requires hardware-bound sessions", claims };
    return { ok: true, claims, bound: false };
  }
  if (!opts.dpopProof) return { ok: false, reason: "dpop_missing", message: "this session is bound to a key: a DPoP proof is required", claims };
  const proof = await verifyDpopProof({ proof: opts.dpopProof, method: opts.method, url: opts.url, sessionToken: opts.sessionToken, nowMs, ...(opts.replayCache ? { replayCache: opts.replayCache } : {}) });
  if (!proof.ok) return { ok: false, reason: proof.reason, message: proof.message, claims };
  if (!constantTimeEqual(utf8(proof.jkt), utf8(claims.cnf.jkt))) return { ok: false, reason: "key_mismatch", message: "the proof was signed by a different key than the session is bound to", claims };
  return { ok: true, claims, bound: true };
}

/* ───────────────────────── refresh-token families ───────────────────────── */

export type RotationResult =
  | { ok: true; family: SessionFamily; refreshToken: string; generation: number; graceUsed?: true }
  | { ok: false; reason: "reuse_detected" | "unknown_token" | "revoked" | "expired"; family: SessionFamily };

/**
 * Rotates a refresh token. The active token moves to the consumed list and a new one is issued. Presenting a token that was
 * already consumed means two parties hold it, so the whole family is revoked at once: the thief's token and the legitimate
 * one both stop working. The function is pure: it returns the new family state for the caller to store.
 */
export async function rotateRefreshTokenFamily(family: SessionFamily, presentedRefreshToken: string, nowMs = Date.now(), opts: { reuseGraceMs?: number } = {}): Promise<RotationResult> {
  if (family.status !== "active") return { ok: false, reason: "revoked", family };
  if (nowMs >= Date.parse(family.expiresAtIso)) return { ok: false, reason: "expired", family: { ...family, status: "expired" } };
  const presented = await refreshHash(presentedRefreshToken);
  let graceUsed = false;
  if (family.consumedRefreshTokenHashes.some((h) => constantTimeEqual(utf8(h), utf8(presented)))) {
    // Opt-in leeway for a client whose response was lost: the token spent most recently, presented again within the window, is
    // answered with a fresh rotation instead of treated as theft. Any older token, or a late one, still revokes the family.
    const last = family.consumedRefreshTokenHashes[family.consumedRefreshTokenHashes.length - 1];
    const within = (opts.reuseGraceMs ?? 0) > 0 && nowMs - Date.parse(family.lastRotatedAtIso) <= (opts.reuseGraceMs ?? 0);
    if (!(within && last !== undefined && constantTimeEqual(utf8(last), utf8(presented)))) {
      return { ok: false, reason: "reuse_detected", family: { ...family, status: "revoked_reuse_detected", revokedAtIso: new Date(nowMs).toISOString() } };
    }
    graceUsed = true;
  } else if (!constantTimeEqual(utf8(family.activeRefreshTokenHash), utf8(presented))) return { ok: false, reason: "unknown_token", family };
  const refreshToken = newRefreshToken();
  const generation = family.currentGeneration + 1;
  return {
    ok: true,
    refreshToken,
    generation,
    ...(graceUsed ? { graceUsed: true as const } : {}),
    family: {
      ...family,
      currentGeneration: generation,
      activeRefreshTokenHash: await refreshHash(refreshToken),
      consumedRefreshTokenHashes: [...family.consumedRefreshTokenHashes, family.activeRefreshTokenHash],
      lastRotatedAtIso: new Date(nowMs).toISOString(),
    },
  };
}

export function revokeFamily(family: SessionFamily, nowMs = Date.now()): SessionFamily {
  return family.status === "active" ? { ...family, status: "revoked_manual", revokedAtIso: new Date(nowMs).toISOString() } : family;
}

/** A fresh access token for the next generation of a family. */
export async function issueNextAccessToken(opts: { issuer: IssuerKey; family: SessionFamily; accessTtlSeconds?: number; nowMs?: number }): Promise<{ sessionToken: string; claims: SessionClaims }> {
  const nowMs = opts.nowMs ?? Date.now();
  const claims: SessionClaims = {
    v: 1, typ: "session", sub: opts.family.userId, tid: opts.family.tenantId, fam: opts.family.familyId, gen: opts.family.currentGeneration, jti: randomId("jti_"),
    iat: nowSec(nowMs), exp: nowSec(nowMs) + (opts.accessTtlSeconds ?? 900), ...(opts.family.clientId ? { cid: opts.family.clientId, scp: opts.family.scope ?? "" } : {}), ...(opts.family.boundJkt ? { cnf: { jkt: opts.family.boundJkt } } : {}),
  };
  return { sessionToken: await signSession(opts.issuer, claims), claims };
}
