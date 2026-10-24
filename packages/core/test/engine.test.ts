import { beforeAll, describe, expect, it } from "vitest";
import {
  ApiKeyRateLimiter, TenantPolicySchema, UserRecordSchema, buildPermissionMatrix, checkWorkspace, evaluateAuthRiskGate, evaluatePermission, generateIssuerKey, haversineKm, mintImpersonationSeal, mintScopedApiKey,
  permissionMatches, verifyImpersonationSeal, verifyScopedApiKey, signToken, TOKEN_PREFIX, type GeoPoint, type IssuerKey, type RiskContext, type TenantPolicy,
} from "../src";

let issuer: IssuerKey;
beforeAll(async () => {
  issuer = await generateIssuerKey();
});

const policy: TenantPolicy = TenantPolicySchema.parse({
  id: "acme", name: "Acme", domain: "acme.test", requireDpopHardwareBinding: false,
  roles: [
    { id: "owner", name: "Owner", permissions: ["*"] },
    { id: "billing", name: "Billing", permissions: ["invoices:read", "invoices:write"] },
    { id: "viewer", name: "Viewer", permissions: ["invoices:read"] },
    { id: "support", name: "Support", permissions: ["users:impersonate", "invoices:*"] },
  ],
});
const HYD = { lat: 17.385, lon: 78.4867, city: "Hyderabad", ip: "1.1.1.1" };
const FRA = { lat: 50.1109, lon: 8.6821, city: "Frankfurt", ip: "2.2.2.2" };
const LON = { lat: 51.5074, lon: -0.1278, city: "London", ip: "3.3.3.3" };
const NOW = Date.parse("2026-10-23T12:00:00Z");
const geo = (p: typeof HYD, minutesAgo: number): GeoPoint => ({ ...p, timestampIso: new Date(NOW - minutesAgo * 60_000).toISOString() });
const base: RiskContext = {
  email: "ada@acme.test", nowMs: NOW, primaryFactorVerified: true, secondFactorVerified: true, isAdmin: false, failedAttemptsInWindow: 0,
  dpop: { presented: true, valid: true, keyMatchesSession: true },
};
const run = (over: Partial<RiskContext> = {}, p: TenantPolicy = policy) => evaluateAuthRiskGate({ ...base, ...over }, p);
const status = (r: ReturnType<typeof run>, code: string) => r.checks.find((c) => c.code === code)?.status;

describe("haversine", () => {
  it("matches known great-circle distances", () => {
    expect(haversineKm(HYD, FRA)).toBeGreaterThan(7050);
    expect(haversineKm(HYD, FRA)).toBeLessThan(7150);
    expect(haversineKm(LON, { lat: 40.7128, lon: -74.006 })).toBeCloseTo(5570, -2);
    expect(haversineKm(HYD, HYD)).toBe(0);
  });
  it("is symmetric and handles the antimeridian and the poles", () => {
    expect(haversineKm(HYD, LON)).toBeCloseTo(haversineKm(LON, HYD), 6);
    expect(haversineKm({ lat: 0, lon: 179.9 }, { lat: 0, lon: -179.9 })).toBeCloseTo(22.24, 1);
    expect(haversineKm({ lat: 90, lon: 0 }, { lat: -90, lon: 0 })).toBeCloseTo(20015, -1);
  });
});

describe("threat radar", () => {
  it("lets an ordinary login through with a perfect score", () => {
    const r = run({ lastLoginGeo: geo(HYD, 600), currentGeo: geo(HYD, 0) });
    expect(r).toMatchObject({ level: "LOW", score: 100 });
    expect(r.checks.map((c) => c.code)).toEqual(["AV-101", "AV-102", "AV-103", "AV-104", "AV-105", "AV-106", "AV-107", "AV-108"]);
  });

  it("AV-101: blocks a bad primary factor and steps up admins without a second factor", () => {
    expect(run({ primaryFactorVerified: false }).level).toBe("BLOCK");
    const r = run({ isAdmin: true, secondFactorVerified: false });
    expect(r).toMatchObject({ level: "STEP_UP_MFA" });
    expect(status(r, "AV-101")).toBe("warn");
    expect(run({ isAdmin: true, secondFactorVerified: false }, { ...policy, requireMfaForAdmins: false }).level).toBe("LOW");
  });

  it("AV-102: warns at half the limit and blocks at the limit", () => {
    expect(run({ failedAttemptsInWindow: 2 }).level).toBe("LOW");
    expect(run({ failedAttemptsInWindow: 3 })).toMatchObject({ level: "STEP_UP_MFA" });
    expect(run({ failedAttemptsInWindow: 5 })).toMatchObject({ level: "BLOCK" });
  });

  it("AV-103: Hyderabad to London in 12 minutes is blocked, with the arithmetic shown", () => {
    const r = run({ lastLoginGeo: geo(HYD, 12), currentGeo: geo(LON, 0) });
    expect(r.level).toBe("BLOCK");
    expect(status(r, "AV-103")).toBe("fail");
    expect(r.travel?.distanceKm).toBeGreaterThan(7700);
    expect(r.travel?.speedKmh).toBeGreaterThan(38_000);
    expect(r.checks.find((c) => c.code === "AV-103")?.message).toMatch(/Hyderabad to London: \d+(\.\d)? km in 0\.2 h = \d+ km\/h \(limit 900\)/);
  });
  it("AV-103: a fast but not absurd trip steps up; a normal flight passes; GPS noise is ignored", () => {
    expect(run({ lastLoginGeo: geo(HYD, 360), currentGeo: geo(LON, 0) }).level).toBe("STEP_UP_MFA");
    expect(status(run({ lastLoginGeo: geo(HYD, 60 * 14), currentGeo: geo(LON, 0) }), "AV-103")).toBe("pass");
    expect(status(run({ lastLoginGeo: geo({ ...HYD }, 0.1), currentGeo: geo({ ...HYD, lat: HYD.lat + 0.1 }, 0) }), "AV-103")).toBe("pass");
    expect(status(run({}), "AV-103")).toBe("skipped");
  });
  it("AV-103: two logins in the same second are not infinitely fast", () => {
    const r = run({ lastLoginGeo: geo(HYD, 0), currentGeo: geo(FRA, 0) });
    expect(Number.isFinite(r.travel?.speedKmh)).toBe(true);
    expect(r.level).toBe("BLOCK");
  });
  it("AV-103: a tenant can loosen the limit", () => {
    expect(run({ lastLoginGeo: geo(HYD, 360), currentGeo: geo(LON, 0) }, { ...policy, maxImpossibleTravelKmh: 5000 }).level).toBe("LOW");
  });

  it("AV-104: blocks a revoked family and a passkey counter regression", () => {
    expect(run({ familyStatus: "revoked_reuse_detected" }).level).toBe("BLOCK");
    expect(run({ passkeySignCountRegression: true }).level).toBe("BLOCK");
    expect(status(run({ familyStatus: "active" }), "AV-104")).toBe("pass");
  });

  it("AV-105: enforces hardware binding when the tenant requires it", () => {
    const strict = { ...policy, requireDpopHardwareBinding: true };
    expect(run({ dpop: { presented: false, valid: false, keyMatchesSession: false } }, strict).level).toBe("BLOCK");
    expect(run({ dpop: { presented: true, valid: false, keyMatchesSession: false } }, strict).level).toBe("BLOCK");
    expect(run({ dpop: { presented: true, valid: true, keyMatchesSession: false } }, strict).level).toBe("BLOCK");
    expect(run({}, strict).level).toBe("LOW");
    const loose = run({ dpop: { presented: false, valid: false, keyMatchesSession: false } });
    expect(status(loose, "AV-105")).toBe("warn");
    expect(loose.level).toBe("LOW");
    expect(run({ dpop: { presented: true, valid: false, keyMatchesSession: false } }).level).toBe("BLOCK");
  });

  it("AV-106: blocks disposable domains, steps up datacenter, headless and drifting devices", () => {
    expect(run({ email: "x@mailinator.com" }).level).toBe("BLOCK");
    expect(run({ email: "x@MAILINATOR.com" }).level).toBe("BLOCK");
    expect(run({ email: "x@mailinator.com" }, { ...policy, blockDisposableEmails: false }).level).toBe("LOW");
    expect(run({ asnKind: "datacenter" }).level).toBe("STEP_UP_MFA");
    expect(run({ asnKind: "headless" }).level).toBe("STEP_UP_MFA");
    expect(run({ deviceFingerprintDrift: true }).level).toBe("STEP_UP_MFA");
    expect(run({ asnKind: "residential" }).level).toBe("LOW");
  });

  it("AV-107: blocks a missing permission", () => {
    expect(run({ permission: { required: "invoices:write", allowed: false, message: "role viewer lacks invoices:write" } }).level).toBe("BLOCK");
    expect(status(run({ permission: { required: "invoices:read", allowed: true, message: "" } }), "AV-107")).toBe("pass");
  });

  it("AV-108: enforces reason, lifetime and a valid seal on impersonation", async () => {
    const seal = await mintImpersonationSeal({ issuer, actor: { id: "usr_root", email: "root@acme.test" }, target: { id: "usr_ada", email: "ada@acme.test" }, tenantId: "acme", reason: "TICKET-4411 customer cannot log in", nowMs: NOW });
    const verified = await verifyImpersonationSeal(seal.token, issuer.publicKeyJwk, NOW);
    expect(run({ impersonation: { present: true, reason: seal.claims.reason, ttlSeconds: 600, seal: verified } }).level).toBe("LOW");
    expect(run({ impersonation: { present: true, reason: "short", ttlSeconds: 600, seal: verified } }).level).toBe("BLOCK");
    expect(run({ impersonation: { present: true, reason: seal.claims.reason, ttlSeconds: 901, seal: verified } }).level).toBe("BLOCK");
    const bad = await verifyImpersonationSeal(seal.token + "x", issuer.publicKeyJwk, NOW);
    expect(run({ impersonation: { present: true, reason: seal.claims.reason, ttlSeconds: 600, seal: bad } }).level).toBe("BLOCK");
    expect(status(run({}), "AV-108")).toBe("skipped");
  });

  it("reports every problem at once and caps a blocked score", () => {
    const r = run({ primaryFactorVerified: false, failedAttemptsInWindow: 9, email: "x@yopmail.com", familyStatus: "revoked_reuse_detected" });
    expect(r.level).toBe("BLOCK");
    expect(r.checks.filter((c) => c.status === "fail").map((c) => c.code)).toEqual(["AV-101", "AV-102", "AV-104", "AV-106"]);
    expect(r.score).toBeLessThanOrEqual(39);
    expect(r.score).toBeGreaterThanOrEqual(0);
  });
  it("is deterministic", () => {
    const ctx = { lastLoginGeo: geo(HYD, 12), currentGeo: geo(FRA, 0), asnKind: "datacenter" as const };
    expect(run(ctx)).toEqual(run(ctx));
  });
});

describe("RBAC", () => {
  it("matches wildcards", () => {
    expect(permissionMatches("*", "a:b")).toBe(true);
    expect(permissionMatches("invoices:*", "invoices:write")).toBe(true);
    expect(permissionMatches("invoices:*", "users:write")).toBe(false);
    expect(permissionMatches("*:read", "users:read")).toBe(true);
    expect(permissionMatches("*:read", "users:write")).toBe(false);
    expect(permissionMatches("invoices:read", "invoices:readonly")).toBe(false);
  });
  it("evaluates a member's role in a tenant", () => {
    const user = (roleId: string) => ({ orgMemberships: [{ tenantId: "acme", roleId }] });
    expect(evaluatePermission(policy, user("owner"), "keys:manage")).toMatchObject({ allowed: true, roleId: "owner" });
    expect(evaluatePermission(policy, user("viewer"), "invoices:read").allowed).toBe(true);
    expect(evaluatePermission(policy, user("viewer"), "invoices:write")).toMatchObject({ allowed: false, reason: "permission_missing" });
    expect(evaluatePermission(policy, { orgMemberships: [] }, "invoices:read")).toMatchObject({ allowed: false, reason: "not_a_member" });
    expect(evaluatePermission(policy, user("ghost"), "invoices:read")).toMatchObject({ allowed: false, reason: "unknown_role" });
    expect(evaluatePermission(policy, { orgMemberships: [{ tenantId: "other", roleId: "owner" }] }, "x:y")).toMatchObject({ reason: "not_a_member" });
  });
  it("builds the role by permission matrix", () => {
    const m = buildPermissionMatrix(policy);
    expect(m.permissions).toEqual(["invoices:read", "invoices:write", "users:impersonate"]);
    expect(m.rows.find((r) => r.roleId === "viewer")?.cells).toEqual([true, false, false]);
    expect(m.rows.find((r) => r.roleId === "support")?.cells).toEqual([true, true, true]);
  });
});

describe("scoped API keys", () => {
  it("mints atk_live_ keys, stores only a hash, and verifies them", async () => {
    const { key, record } = await mintScopedApiKey({ tenantId: "acme", name: "ci", scopes: ["invoices:read"], nowMs: NOW });
    expect(key).toMatch(/^atk_live_[0-9a-f]{8}_[A-Za-z0-9_-]{32}$/);
    expect(record.keyPrefix).toBe(key.slice(0, 17));
    expect(JSON.stringify(record)).not.toContain(key.slice(18));
    expect(await verifyScopedApiKey(key, [record], { nowMs: NOW })).toMatchObject({ ok: true });
  });
  it("refuses unknown, tampered, revoked, expired and out-of-scope keys", async () => {
    const { key, record } = await mintScopedApiKey({ tenantId: "acme", name: "ci", scopes: ["invoices:read"], ttlSeconds: 60, nowMs: NOW });
    expect(await verifyScopedApiKey("nope", [record])).toMatchObject({ reason: "malformed" });
    expect(await verifyScopedApiKey(key.slice(0, 20) + (key[20] === "A" ? "B" : "A") + key.slice(21), [record], { nowMs: NOW })).toMatchObject({ reason: "unknown" });
    expect(await verifyScopedApiKey(key, [{ ...record, revokedAtIso: "2026-01-01T00:00:00Z" }], { nowMs: NOW })).toMatchObject({ reason: "revoked" });
    expect(await verifyScopedApiKey(key, [record], { nowMs: NOW + 61_000 })).toMatchObject({ reason: "expired" });
    expect(await verifyScopedApiKey(key, [record], { nowMs: NOW, requiredScope: "invoices:write" })).toMatchObject({ reason: "scope_missing" });
    expect(await verifyScopedApiKey(key, [record], { nowMs: NOW, requiredScope: "invoices:read" })).toMatchObject({ ok: true });
    await expect(mintScopedApiKey({ tenantId: "a", name: "x", scopes: [] })).rejects.toThrow(/scope/);
  });
  it("rate-limits per key per minute", async () => {
    const { key, record } = await mintScopedApiKey({ tenantId: "acme", name: "ci", scopes: ["*"], rateLimitPerMin: 3, nowMs: NOW });
    const limiter = new ApiKeyRateLimiter();
    for (let i = 0; i < 3; i++) expect((await verifyScopedApiKey(key, [record], { nowMs: NOW + i, limiter })).ok).toBe(true);
    expect(await verifyScopedApiKey(key, [record], { nowMs: NOW + 10, limiter })).toMatchObject({ ok: false, reason: "rate_limited" });
    expect((await verifyScopedApiKey(key, [record], { nowMs: NOW + 60_001, limiter })).ok).toBe(true);
  });
});

describe("break-glass impersonation seals", () => {
  const actor = { id: "usr_root", email: "root@acme.test" };
  const target = { id: "usr_ada", email: "ada@acme.test" };
  it("mints a dual-subject seal that verifies and counts down", async () => {
    const { token, claims } = await mintImpersonationSeal({ issuer, actor, target, tenantId: "acme", reason: "TICKET-1 cannot reset MFA", nowMs: NOW });
    expect(token.startsWith(TOKEN_PREFIX.impersonation)).toBe(true);
    expect(claims).toMatchObject({ targetUserId: "usr_ada", actorAdminId: "usr_root", readOnly: true });
    expect(await verifyImpersonationSeal(token, issuer.publicKeyJwk, NOW + 100_000)).toMatchObject({ ok: true, secondsLeft: 500 });
    expect(await verifyImpersonationSeal(token, issuer.publicKeyJwk, NOW + 601_000)).toMatchObject({ ok: false, reason: "expired" });
  });
  it("refuses short reasons, long lifetimes and self-impersonation", async () => {
    const o = { issuer, actor, target, tenantId: "acme", nowMs: NOW };
    await expect(mintImpersonationSeal({ ...o, reason: "help" })).rejects.toThrow(/reason/);
    await expect(mintImpersonationSeal({ ...o, reason: "TICKET-1 long", ttlSeconds: 901 })).rejects.toThrow(/seconds/);
    await expect(mintImpersonationSeal({ ...o, reason: "TICKET-1 short", ttlSeconds: 5 })).rejects.toThrow(/seconds/);
    await expect(mintImpersonationSeal({ ...o, target: actor, reason: "TICKET-1 myself" })).rejects.toThrow(/yourself/);
  });
  it("detects any tampering with the claims, and seals from another issuer", async () => {
    const { token } = await mintImpersonationSeal({ issuer, actor, target, tenantId: "acme", reason: "TICKET-1 read only", nowMs: NOW });
    const [body, sig] = token.slice(TOKEN_PREFIX.impersonation.length).split(".") as [string, string];
    const claims = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
    claims["readOnly"] = false;
    const forgedBody = btoa(JSON.stringify(claims)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyImpersonationSeal(`${TOKEN_PREFIX.impersonation}${forgedBody}.${sig}`, issuer.publicKeyJwk, NOW)).toMatchObject({ ok: false, reason: "bad_signature" });
    const other = await generateIssuerKey();
    expect(await verifyImpersonationSeal(token, other.publicKeyJwk, NOW)).toMatchObject({ ok: false, reason: "bad_signature" });
    const incomplete = await signToken(TOKEN_PREFIX.impersonation, { typ: "impersonation" }, issuer.privateKey);
    expect(await verifyImpersonationSeal(incomplete, issuer.publicKeyJwk, NOW)).toMatchObject({ ok: false, reason: "invalid_claims" });
  });
});

describe("schemas", () => {
  it("applies tenant defaults and rejects duplicate roles and bad permissions", () => {
    const t = TenantPolicySchema.parse({ id: "t1", name: "T", domain: "t.test", roles: [{ id: "a", name: "A", permissions: ["x:y"] }] });
    expect(t).toMatchObject({ sessionTtlSeconds: 900, refreshTtlSeconds: 604_800, maxImpossibleTravelKmh: 900, maxFailedAttemptsPerWindow: 5, blockDisposableEmails: true, requireMfaForAdmins: true });
    expect(TenantPolicySchema.safeParse({ ...t, roles: [t.roles[0], t.roles[0]] }).success).toBe(false);
    expect(TenantPolicySchema.safeParse({ ...t, roles: [{ id: "a", name: "A", permissions: ["nonsense"] }] }).success).toBe(false);
    expect(TenantPolicySchema.safeParse({ ...t, surprise: 1 }).success).toBe(false);
  });
  it("validates users and cross-checks memberships", () => {
    const u = UserRecordSchema.parse({ id: "usr_ada", email: "ada@acme.test", name: "Ada", orgMemberships: [{ tenantId: "acme", roleId: "owner" }] });
    expect(u.passkeys).toEqual([]);
    expect(checkWorkspace([policy], [u])).toEqual([]);
    const bad = UserRecordSchema.parse({ id: "usr_bob", email: "ADA@acme.test", name: "B", orgMemberships: [{ tenantId: "zzz", roleId: "owner" }, { tenantId: "acme", roleId: "ghost" }] });
    expect(checkWorkspace([policy], [u, bad]).join("\n")).toMatch(/email ADA@acme.test is used twice[\s\S]*unknown tenant "zzz"[\s\S]*role "ghost"/);
    expect(UserRecordSchema.safeParse({ id: "bad", email: "x", name: "" }).success).toBe(false);
  });
});
