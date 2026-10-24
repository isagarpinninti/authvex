import type { GeoPoint, TenantPolicy } from "../schemas/identity";
import type { FamilyStatus } from "../session/dpopAndFamilies";
import { MAX_IMPERSONATION_SECONDS, type SealVerification } from "./rbacAndApiKeys";

export type RiskCode = "AV-101" | "AV-102" | "AV-103" | "AV-104" | "AV-105" | "AV-106" | "AV-107" | "AV-108";
export type RiskLevel = "LOW" | "STEP_UP_MFA" | "BLOCK";
export type CheckStatus = "pass" | "warn" | "fail" | "skipped";

export interface RiskCheck {
  code: RiskCode;
  name: string;
  status: CheckStatus;
  /** `fail` on a blocking check forces BLOCK; `warn` may force a step-up. */
  effect: "none" | "step_up" | "block";
  penalty: number;
  message: string;
}

export interface RiskReport {
  /** 0 (hostile) to 100 (nothing unusual). */
  score: number;
  level: RiskLevel;
  checks: RiskCheck[];
  /** Haversine facts for the travel check, when there was a previous login. */
  travel?: { distanceKm: number; hours: number; speedKmh: number };
}

export type AsnKind = "residential" | "mobile" | "datacenter" | "headless";

export interface RiskContext {
  email: string;
  /** Epoch ms of this attempt. */
  nowMs: number;
  /** The primary factor (a password or a passkey) checked out. */
  primaryFactorVerified: boolean;
  /** A second factor (TOTP or a passkey with user verification) checked out. */
  secondFactorVerified: boolean;
  /** Whether the user is an admin of the tenant (policy may require MFA for them). */
  isAdmin: boolean;
  /** Attempts that failed in the sliding window before this one. */
  failedAttemptsInWindow: number;
  lastLoginGeo?: GeoPoint | undefined;
  currentGeo?: GeoPoint | undefined;
  familyStatus?: FamilyStatus | undefined;
  /** The passkey's counter did not advance (a possible clone). */
  passkeySignCountRegression?: boolean | undefined;
  dpop: { presented: boolean; valid: boolean; keyMatchesSession: boolean };
  asnKind?: AsnKind | undefined;
  /** The device fingerprint differs from the ones seen for this user. */
  deviceFingerprintDrift?: boolean | undefined;
  /** `resource:action` the caller wants to perform, with the verdict of the RBAC evaluation. */
  permission?: { required: string; allowed: boolean; message: string } | undefined;
  impersonation?: { present: boolean; reason: string; ttlSeconds: number; seal: SealVerification } | undefined;
}

export const DISPOSABLE_DOMAINS: ReadonlySet<string> = new Set([
  "mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com", "yopmail.com", "trashmail.com", "throwawaymail.com", "sharklasers.com", "getnada.com", "dispostable.com", "temp-mail.org", "maildrop.cc",
]);

const EARTH_RADIUS_KM = 6371.0088;
const rad = (d: number): number => (d * Math.PI) / 180;

/** Great-circle distance in kilometres between two points (Haversine). */
export function haversineKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const dLat = rad(b.lat - a.lat);
  const dLon = rad(b.lon - a.lon);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1, Math.sqrt(h)));
}

/** Below this distance a "jump" is GPS or IP-geolocation noise, not travel. */
const NOISE_KM = 50;
/** Never divide by less than a minute: two logins in the same second would otherwise be infinitely fast. */
const MIN_HOURS = 1 / 60;

const check = (code: RiskCode, name: string, status: CheckStatus, message: string, penalty = 0, effect: RiskCheck["effect"] = "none"): RiskCheck => ({ code, name, status, effect, penalty, message });
const emailDomain = (email: string): string => email.slice(email.lastIndexOf("@") + 1).toLowerCase();

/**
 * Runs the eight checks AV-101 to AV-108 and returns a trust score, a level and every check's verdict. All eight always
 * run, so a report shows everything that is wrong at once. The function is pure: the same context and policy give the same report.
 */
export function evaluateAuthRiskGate(ctx: RiskContext, policy: TenantPolicy): RiskReport {
  const checks: RiskCheck[] = [];
  let travel: RiskReport["travel"];

  // AV-101: factors
  if (!ctx.primaryFactorVerified) checks.push(check("AV-101", "Credential and factor integrity", "fail", "the password or passkey did not verify", 60, "block"));
  else if ((policy.requireMfaForAdmins && ctx.isAdmin) && !ctx.secondFactorVerified) checks.push(check("AV-101", "Credential and factor integrity", "warn", "this tenant requires a second factor for admins", 15, "step_up"));
  else checks.push(check("AV-101", "Credential and factor integrity", "pass", ctx.secondFactorVerified ? "primary and second factor verified" : "primary factor verified"));

  // AV-102: brute-force velocity
  const max = policy.maxFailedAttemptsPerWindow;
  if (ctx.failedAttemptsInWindow >= max) checks.push(check("AV-102", "Brute-force velocity breaker", "fail", `${ctx.failedAttemptsInWindow} failed attempts in the window (limit ${max})`, 50, "block"));
  else if (ctx.failedAttemptsInWindow >= Math.ceil(max / 2)) checks.push(check("AV-102", "Brute-force velocity breaker", "warn", `${ctx.failedAttemptsInWindow} failed attempts in the window (limit ${max})`, 10, "step_up"));
  else checks.push(check("AV-102", "Brute-force velocity breaker", "pass", `${ctx.failedAttemptsInWindow} recent failures`));

  // AV-103: impossible travel
  if (!ctx.lastLoginGeo || !ctx.currentGeo) checks.push(check("AV-103", "Impossible-travel radar", "skipped", "no previous or current location to compare"));
  else {
    const km = haversineKm(ctx.lastLoginGeo, ctx.currentGeo);
    const hours = Math.max((ctx.nowMs - Date.parse(ctx.lastLoginGeo.timestampIso)) / 3_600_000, MIN_HOURS);
    const speed = km / hours;
    travel = { distanceKm: Math.round(km * 10) / 10, hours: Math.round(hours * 1000) / 1000, speedKmh: Math.round(speed) };
    const limit = policy.maxImpossibleTravelKmh;
    const route = `${ctx.lastLoginGeo.city} to ${ctx.currentGeo.city}: ${travel.distanceKm} km in ${travel.hours} h = ${travel.speedKmh} km/h (limit ${limit})`;
    if (km < NOISE_KM || speed <= limit) checks.push(check("AV-103", "Impossible-travel radar", "pass", km < NOISE_KM ? `same area (${travel.distanceKm} km)` : route));
    else if (speed > limit * 4) checks.push(check("AV-103", "Impossible-travel radar", "fail", route, 45, "block"));
    else checks.push(check("AV-103", "Impossible-travel radar", "warn", route, 25, "step_up"));
  }

  // AV-104: family reuse and clone guard
  if (ctx.familyStatus === "revoked_reuse_detected") checks.push(check("AV-104", "Refresh-family reuse and clone guard", "fail", "this session family was revoked after a refresh token was replayed", 60, "block"));
  else if (ctx.passkeySignCountRegression) checks.push(check("AV-104", "Refresh-family reuse and clone guard", "fail", "the passkey's signature counter went backwards: the authenticator may be cloned", 60, "block"));
  else if (ctx.familyStatus === undefined) checks.push(check("AV-104", "Refresh-family reuse and clone guard", "skipped", "no session family involved (a fresh login)"));
  else checks.push(check("AV-104", "Refresh-family reuse and clone guard", "pass", `family is ${ctx.familyStatus}`));

  // AV-105: DPoP hardware key binding
  if (policy.requireDpopHardwareBinding) {
    if (!ctx.dpop.presented) checks.push(check("AV-105", "DPoP hardware-key binding", "fail", "this tenant requires a DPoP proof and none was presented", 55, "block"));
    else if (!ctx.dpop.valid) checks.push(check("AV-105", "DPoP hardware-key binding", "fail", "the DPoP proof did not verify", 55, "block"));
    else if (!ctx.dpop.keyMatchesSession) checks.push(check("AV-105", "DPoP hardware-key binding", "fail", "the proof's key is not the key the session is bound to", 55, "block"));
    else checks.push(check("AV-105", "DPoP hardware-key binding", "pass", "proof verified and matches the session key"));
  } else if (ctx.dpop.presented && !(ctx.dpop.valid && ctx.dpop.keyMatchesSession)) checks.push(check("AV-105", "DPoP hardware-key binding", "fail", "a DPoP proof was presented and it is wrong", 55, "block"));
  else if (!ctx.dpop.presented) checks.push(check("AV-105", "DPoP hardware-key binding", "warn", "the session is not bound to a hardware key (not required by policy)", 8));
  else checks.push(check("AV-105", "DPoP hardware-key binding", "pass", "proof verified and matches the session key"));

  // AV-106: disposable domain, network and device reputation
  const domain = emailDomain(ctx.email);
  if (policy.blockDisposableEmails && DISPOSABLE_DOMAINS.has(domain)) checks.push(check("AV-106", "Disposable domain and network shield", "fail", `${domain} is a disposable email domain`, 40, "block"));
  else if (ctx.asnKind === "headless") checks.push(check("AV-106", "Disposable domain and network shield", "warn", "the request comes from a headless or automation network", 25, "step_up"));
  else if (ctx.asnKind === "datacenter") checks.push(check("AV-106", "Disposable domain and network shield", "warn", "the request comes from a datacenter network", 15, "step_up"));
  else if (ctx.deviceFingerprintDrift) checks.push(check("AV-106", "Disposable domain and network shield", "warn", "the device fingerprint differs from this user's known devices", 15, "step_up"));
  else checks.push(check("AV-106", "Disposable domain and network shield", "pass", "domain, network and device look ordinary"));

  // AV-107: RBAC
  if (!ctx.permission) checks.push(check("AV-107", "Tenant RBAC permission gate", "skipped", "no permission was requested"));
  else if (ctx.permission.allowed) checks.push(check("AV-107", "Tenant RBAC permission gate", "pass", `${ctx.permission.required} allowed`));
  else checks.push(check("AV-107", "Tenant RBAC permission gate", "fail", `${ctx.permission.required} refused: ${ctx.permission.message}`, 40, "block"));

  // AV-108: break-glass impersonation constraints
  const imp = ctx.impersonation;
  if (!imp?.present) checks.push(check("AV-108", "Break-glass impersonation constraint", "skipped", "not an impersonated session"));
  else if (imp.reason.trim().length < 8) checks.push(check("AV-108", "Break-glass impersonation constraint", "fail", "an impersonation needs a ticket reason of at least 8 characters", 60, "block"));
  else if (imp.ttlSeconds > MAX_IMPERSONATION_SECONDS) checks.push(check("AV-108", "Break-glass impersonation constraint", "fail", `the seal lasts ${imp.ttlSeconds}s; the limit is ${MAX_IMPERSONATION_SECONDS}s`, 60, "block"));
  else if (!imp.seal.ok) checks.push(check("AV-108", "Break-glass impersonation constraint", "fail", `the seal is not valid: ${imp.seal.message}`, 60, "block"));
  else checks.push(check("AV-108", "Break-glass impersonation constraint", "pass", `sealed by ${imp.seal.claims.actorEmail}, ${imp.seal.secondsLeft}s left`));

  const blocked = checks.some((c) => c.effect === "block" && c.status === "fail");
  const steppedUp = checks.some((c) => c.effect === "step_up" && c.status === "warn");
  const raw = 100 - checks.reduce((n, c) => n + (c.status === "pass" || c.status === "skipped" ? 0 : c.penalty), 0);
  const score = Math.max(0, Math.min(100, blocked ? Math.min(raw, 39) : raw));
  const level: RiskLevel = blocked ? "BLOCK" : steppedUp || score < 70 ? "STEP_UP_MFA" : "LOW";
  return { score, level, checks, ...(travel ? { travel } : {}) };
}
