import { constantTimeEqual, randomBytes, sha256, hex, utf8, b64urlEncode } from "../util/bytes";
import { TOKEN_PREFIX, randomId, signToken, verifySignedToken, type IssuerKey, type PublicKeys } from "../session/tokens";
import type { TenantPolicy, UserRecord } from "../schemas/identity";

/* ───────────────────────── RBAC ───────────────────────── */

/** `*` matches everything, `resource:*` any action on a resource, `*:action` an action on any resource. */
export function permissionMatches(granted: string, required: string): boolean {
  if (granted === "*" || granted === required) return true;
  const [gr, ga] = granted.split(":");
  const [rr, ra] = required.split(":");
  return ga !== undefined && ra !== undefined && (gr === "*" || gr === rr) && (ga === "*" || ga === ra);
}

export type PermissionDecision = { allowed: true; roleId: string } | { allowed: false; reason: "not_a_member" | "unknown_role" | "permission_missing"; message: string };

export function evaluatePermission(tenant: TenantPolicy, user: Pick<UserRecord, "orgMemberships">, required: string): PermissionDecision {
  const membership = user.orgMemberships.find((m) => m.tenantId === tenant.id);
  if (!membership) return { allowed: false, reason: "not_a_member", message: `not a member of ${tenant.id}` };
  const role = tenant.roles.find((r) => r.id === membership.roleId);
  if (!role) return { allowed: false, reason: "unknown_role", message: `role "${membership.roleId}" does not exist` };
  return role.permissions.some((p) => permissionMatches(p, required)) ? { allowed: true, roleId: role.id } : { allowed: false, reason: "permission_missing", message: `role "${role.id}" lacks ${required}` };
}

/** The full resource x action grid for a tenant's roles, for the visual matrix. */
export function buildPermissionMatrix(tenant: TenantPolicy): { permissions: string[]; rows: Array<{ roleId: string; name: string; cells: boolean[] }> } {
  const permissions = [...new Set(tenant.roles.flatMap((r) => r.permissions).filter((p) => !p.includes("*")))].sort();
  return { permissions, rows: tenant.roles.map((r) => ({ roleId: r.id, name: r.name, cells: permissions.map((p) => r.permissions.some((g) => permissionMatches(g, p))) })) };
}

/* ───────────────────────── scoped machine API keys ───────────────────────── */

export interface ApiKeyRecord {
  id: string;
  name: string;
  tenantId: string;
  /** `atk_live_<8 hex>`: safe to show and to index by. */
  keyPrefix: string;
  /** SHA-256 of the whole key. The key itself is shown once, at creation, and never stored. */
  sha256Hash: string;
  scopes: string[];
  rateLimitPerMin: number;
  createdAtIso: string;
  expiresAtIso?: string;
  revokedAtIso?: string;
}

const KEY_RE = /^atk_live_([0-9a-f]{8})_([A-Za-z0-9_-]{32})$/;

export async function mintScopedApiKey(opts: { tenantId: string; name: string; scopes: string[]; rateLimitPerMin?: number; ttlSeconds?: number; nowMs?: number }): Promise<{ key: string; record: ApiKeyRecord }> {
  const nowMs = opts.nowMs ?? Date.now();
  if (opts.scopes.length === 0) throw new RangeError("an API key needs at least one scope");
  const prefix = hex(randomBytes(4));
  const key = `${TOKEN_PREFIX.apiKey}${prefix}_${b64urlEncode(randomBytes(24))}`;
  return {
    key,
    record: {
      id: randomId("key_", 9), name: opts.name, tenantId: opts.tenantId, keyPrefix: `${TOKEN_PREFIX.apiKey}${prefix}`, sha256Hash: hex(await sha256(key)), scopes: opts.scopes,
      rateLimitPerMin: opts.rateLimitPerMin ?? 600, createdAtIso: new Date(nowMs).toISOString(), ...(opts.ttlSeconds ? { expiresAtIso: new Date(nowMs + opts.ttlSeconds * 1000).toISOString() } : {}),
    },
  };
}

/** Fixed one-minute window per key. */
export class ApiKeyRateLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  allow(keyId: string, limitPerMin: number, nowMs: number): { ok: true; remaining: number } | { ok: false; retryAfterMs: number } {
    const w = this.windows.get(keyId);
    if (!w || nowMs - w.start >= 60_000) {
      this.windows.set(keyId, { start: nowMs, count: 1 });
      return { ok: true, remaining: limitPerMin - 1 };
    }
    if (w.count >= limitPerMin) return { ok: false, retryAfterMs: 60_000 - (nowMs - w.start) };
    w.count++;
    return { ok: true, remaining: limitPerMin - w.count };
  }
}

export type ApiKeyFailure = "malformed" | "unknown" | "revoked" | "expired" | "scope_missing" | "rate_limited";
export type ApiKeyResult = { ok: true; record: ApiKeyRecord } | { ok: false; reason: ApiKeyFailure; message: string; retryAfterMs?: number };

/** Finds a key by its prefix and compares hashes in constant time. A key never reveals which part was wrong. */
export async function verifyScopedApiKey(key: string, records: readonly ApiKeyRecord[], opts: { nowMs?: number; requiredScope?: string; limiter?: ApiKeyRateLimiter } = {}): Promise<ApiKeyResult> {
  const nowMs = opts.nowMs ?? Date.now();
  const m = KEY_RE.exec(key);
  if (!m) return { ok: false, reason: "malformed", message: "not an Authvex API key" };
  const hash = hex(await sha256(key));
  const candidate = records.find((r) => r.keyPrefix === `${TOKEN_PREFIX.apiKey}${m[1]}`);
  const ok = candidate !== undefined && constantTimeEqual(utf8(candidate.sha256Hash), utf8(hash));
  if (!candidate || !ok) return { ok: false, reason: "unknown", message: "unknown API key" };
  if (candidate.revokedAtIso) return { ok: false, reason: "revoked", message: "this key was revoked" };
  if (candidate.expiresAtIso && nowMs >= Date.parse(candidate.expiresAtIso)) return { ok: false, reason: "expired", message: "this key has expired" };
  if (opts.requiredScope && !candidate.scopes.some((s) => permissionMatches(s, opts.requiredScope as string))) return { ok: false, reason: "scope_missing", message: `this key lacks the ${opts.requiredScope} scope` };
  if (opts.limiter) {
    const r = opts.limiter.allow(candidate.id, candidate.rateLimitPerMin, nowMs);
    if (!r.ok) return { ok: false, reason: "rate_limited", message: "rate limit exceeded", retryAfterMs: r.retryAfterMs };
  }
  return { ok: true, record: candidate };
}

/* ───────────────────────── break-glass impersonation ───────────────────────── */

export const MAX_IMPERSONATION_SECONDS = 900;

export interface ImpersonationClaims {
  v: 1;
  typ: "impersonation";
  /** The user being impersonated (the token's subject). */
  targetUserId: string;
  targetEmail: string;
  /** The admin acting as them (RFC 8693 `act`). */
  actorAdminId: string;
  actorEmail: string;
  tenantId: string;
  /** The support ticket or incident that justifies it. */
  reason: string;
  readOnly: boolean;
  issuedAtIso: string;
  expiresAtIso: string;
  jti: string;
}

/** A dual-subject seal: the target is `sub`, the admin is `act`, the reason is recorded, and it expires within 15 minutes. */
export async function mintImpersonationSeal(
  opts: { issuer: IssuerKey; target: Pick<UserRecord, "id" | "email">; actor: Pick<UserRecord, "id" | "email">; tenantId: string; reason: string; readOnly?: boolean; ttlSeconds?: number; nowMs?: number },
): Promise<{ token: string; claims: ImpersonationClaims }> {
  const reason = opts.reason.trim();
  if (reason.length < 8) throw new RangeError("a break-glass reason of at least 8 characters (a ticket number and a sentence) is required");
  const ttl = opts.ttlSeconds ?? 600;
  if (!Number.isInteger(ttl) || ttl < 30 || ttl > MAX_IMPERSONATION_SECONDS) throw new RangeError(`impersonation lasts 30 to ${MAX_IMPERSONATION_SECONDS} seconds`);
  if (opts.actor.id === opts.target.id) throw new RangeError("you cannot impersonate yourself");
  const nowMs = opts.nowMs ?? Date.now();
  const claims: ImpersonationClaims = {
    v: 1, typ: "impersonation", targetUserId: opts.target.id, targetEmail: opts.target.email, actorAdminId: opts.actor.id, actorEmail: opts.actor.email, tenantId: opts.tenantId, reason,
    readOnly: opts.readOnly ?? true, issuedAtIso: new Date(nowMs).toISOString(), expiresAtIso: new Date(nowMs + ttl * 1000).toISOString(), jti: randomId("imp_"),
  };
  return { token: await signToken(TOKEN_PREFIX.impersonation, claims, opts.issuer.privateKey, opts.issuer.kid), claims };
}

export type SealVerification =
  | { ok: true; claims: ImpersonationClaims; secondsLeft: number }
  | { ok: false; reason: "malformed" | "bad_signature" | "unknown_key" | "expired" | "invalid_claims"; message: string; claims?: ImpersonationClaims };

export async function verifyImpersonationSeal(token: string, issuerPublicKeyJwk: PublicKeys, nowMs = Date.now()): Promise<SealVerification> {
  const t = await verifySignedToken<ImpersonationClaims>(TOKEN_PREFIX.impersonation, token, issuerPublicKeyJwk);
  if (!t.ok) return { ok: false, reason: t.reason, message: t.reason === "malformed" ? "not an impersonation seal" : t.reason === "unknown_key" ? "the seal was signed by a key this server does not trust (retired or revoked)" : "the seal was altered or is not ours" };
  const c = t.payload;
  if (c.typ !== "impersonation" || typeof c.targetUserId !== "string" || typeof c.actorAdminId !== "string" || typeof c.reason !== "string" || typeof c.expiresAtIso !== "string" || typeof c.issuedAtIso !== "string") {
    return { ok: false, reason: "invalid_claims", message: "the seal's claims are incomplete" };
  }
  const left = Math.floor((Date.parse(c.expiresAtIso) - nowMs) / 1000);
  if (left <= 0) return { ok: false, reason: "expired", message: "the seal has expired", claims: c };
  return { ok: true, claims: c, secondsLeft: left };
}
