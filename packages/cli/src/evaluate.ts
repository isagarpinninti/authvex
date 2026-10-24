import { z } from "zod";
import {
  evaluateAuthRiskGate, evaluatePermission, mintImpersonationSeal, verifyImpersonationSeal, type GeoPoint, type IssuerKey, type RiskContext, type RiskReport, type SealVerification, type TenantPolicy, type UserRecord,
} from "@authvex/core";

export const geoSchema = z.object({ lat: z.number().min(-90).max(90), lon: z.number().min(-180).max(180), city: z.string().max(80).default("Unknown"), ip: z.string().max(64).optional() }).strict();
export const asnSchema = z.enum(["residential", "mobile", "datacenter", "headless"]);

export class EvaluateError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

export const evalSchema = z
  .object({
    tenantId: z.string(),
    userId: z.string().optional(),
    email: z.string().max(200).optional(),
    primaryFactorVerified: z.boolean().default(true),
    secondFactorVerified: z.boolean().default(false),
    isAdmin: z.boolean().optional(),
    failedAttemptsInWindow: z.number().int().min(0).max(1000).default(0),
    lastLoginGeo: geoSchema.extend({ minutesAgo: z.number().min(0).max(525_600).default(60) }).optional(),
    currentGeo: geoSchema.optional(),
    familyStatus: z.enum(["active", "revoked_reuse_detected", "revoked_manual", "expired"]).optional(),
    passkeySignCountRegression: z.boolean().optional(),
    dpop: z.object({ presented: z.boolean(), valid: z.boolean(), keyMatchesSession: z.boolean() }).strict().default({ presented: true, valid: true, keyMatchesSession: true }),
    asnKind: asnSchema.optional(),
    deviceFingerprintDrift: z.boolean().optional(),
    permission: z.string().max(100).optional(),
    impersonation: z.object({ reason: z.string().max(300), ttlSeconds: z.number().int().min(1).max(86_400), tamper: z.boolean().default(false) }).strict().optional(),
  })
  .strict();
export type EvalInput = z.input<typeof evalSchema>;

const ADMIN_PERMISSIONS = ["tenant:admin", "keys:manage", "users:impersonate"];
export const isAdminUser = (t: TenantPolicy, u: Pick<UserRecord, "orgMemberships">): boolean => ADMIN_PERMISSIONS.some((p) => evaluatePermission(t, u, p).allowed);

/** Builds a risk context from a described scenario and runs the AV-101..108 gate. Used by the Studio's Threat Radar and `authvex evaluate`. */
export async function evaluateScenario(
  env: { tenants: Map<string, TenantPolicy>; users: Map<string, UserRecord>; issuer: IssuerKey; nowMs: number },
  raw: unknown,
): Promise<{ report: RiskReport }> {
  const parsed = evalSchema.safeParse(raw);
  if (!parsed.success) throw new EvaluateError(parsed.error.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; "), 400);
  const b = parsed.data;
  const tenant = env.tenants.get(b.tenantId);
  if (!tenant) throw new EvaluateError(`no tenant "${b.tenantId}"`, 404);
  const user = b.userId ? env.users.get(b.userId) : undefined;
  if (b.userId && !user) throw new EvaluateError(`no user "${b.userId}"`, 404);
  const now = env.nowMs;
  const at = (g: { lat: number; lon: number; city: string; ip?: string | undefined }, ts: number): GeoPoint => ({ lat: g.lat, lon: g.lon, city: g.city, ip: g.ip ?? "0.0.0.0", timestampIso: new Date(ts).toISOString() });

  let impersonation: RiskContext["impersonation"];
  if (b.impersonation) {
    const all = [...env.users.values()];
    const actor = all.find((u) => evaluatePermission(tenant, u, "users:impersonate").allowed);
    const target = user && user.id !== actor?.id ? user : all.find((u) => u.id !== actor?.id);
    let seal: SealVerification;
    if (!actor || !target) seal = { ok: false, reason: "invalid_claims", message: "the workspace has no admin and target to build a seal from" };
    else {
      try {
        const m = await mintImpersonationSeal({ issuer: env.issuer, actor, target, tenantId: tenant.id, reason: b.impersonation.reason.padEnd(8, "."), ttlSeconds: Math.min(Math.max(b.impersonation.ttlSeconds, 30), 900), nowMs: now });
        seal = await verifyImpersonationSeal(b.impersonation.tamper ? `${m.token.slice(0, -4)}AAAA` : m.token, env.issuer.publicKeyJwk, now);
      } catch (e) {
        seal = { ok: false, reason: "invalid_claims", message: e instanceof Error ? e.message : "cannot mint" };
      }
    }
    impersonation = { present: true, reason: b.impersonation.reason, ttlSeconds: b.impersonation.ttlSeconds, seal };
  }

  let permission: RiskContext["permission"];
  if (b.permission && user) {
    const d = evaluatePermission(tenant, user, b.permission);
    permission = { required: b.permission, allowed: d.allowed, message: d.allowed ? "" : d.message };
  }
  const ctx: RiskContext = {
    email: b.email ?? user?.email ?? "user@example.com", nowMs: now, primaryFactorVerified: b.primaryFactorVerified, secondFactorVerified: b.secondFactorVerified,
    isAdmin: b.isAdmin ?? (user ? isAdminUser(tenant, user) : false), failedAttemptsInWindow: b.failedAttemptsInWindow,
    lastLoginGeo: b.lastLoginGeo ? at(b.lastLoginGeo, now - b.lastLoginGeo.minutesAgo * 60_000) : user?.lastLoginGeo, currentGeo: b.currentGeo ? at(b.currentGeo, now) : undefined,
    familyStatus: b.familyStatus, passkeySignCountRegression: b.passkeySignCountRegression, dpop: b.dpop, asnKind: b.asnKind, deviceFingerprintDrift: b.deviceFingerprintDrift, permission, impersonation,
  };
  return { report: evaluateAuthRiskGate(ctx, tenant) };
}
