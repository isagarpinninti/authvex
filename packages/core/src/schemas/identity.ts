import { z } from "zod";

/** `resource:action`, `resource:*`, `*:action` or `*`. */
const permission = z.string().regex(/^(\*|[a-z][a-z0-9_.-]*:(\*|[a-z][a-z0-9_.-]*)|\*:[a-z][a-z0-9_.-]*)$/, "use resource:action, resource:* or *");

export const RoleSchema = z.object({ id: z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/), name: z.string().min(1).max(60), permissions: z.array(permission).max(200) }).strict();
export type Role = z.infer<typeof RoleSchema>;

export const TenantPolicySchema = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9_-]{0,47}$/, "lowercase letters, digits, - and _"),
    name: z.string().min(1).max(80),
    domain: z.string().min(3).max(120),
    /** Access-token lifetime. */
    sessionTtlSeconds: z.number().int().min(60).max(86_400).default(900),
    /** Refresh-family lifetime. */
    refreshTtlSeconds: z.number().int().min(300).max(90 * 86_400).default(604_800),
    requireDpopHardwareBinding: z.boolean().default(false),
    requireMfaForAdmins: z.boolean().default(true),
    maxImpossibleTravelKmh: z.number().min(50).max(20_000).default(900),
    maxFailedAttemptsPerWindow: z.number().int().min(1).max(100).default(5),
    blockDisposableEmails: z.boolean().default(true),
    /** Let anyone create an account in this tenant (they get `signupRoleId`). Needs email to be configured. */
    allowSignup: z.boolean().default(false),
    signupRoleId: z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/).optional(),
    /** With `allowSignup`: let people sign up without a password. They get an emailed link, then register a passkey, and sign in with it. */
    allowPasskeyOnlySignup: z.boolean().default(false),
    /** Refuse sign-in until the user has followed the link in a verification email. */
    requireVerifiedEmail: z.boolean().default(false),
    /** Let users reset a forgotten password through an emailed link. */
    allowPasswordReset: z.boolean().default(true),
    /** Let users sign in through an emailed one-time link (a single factor, equal to a password). */
    allowMagicLinks: z.boolean().default(false),
    roles: z.array(RoleSchema).min(1).max(50),
  })
  .strict()
  .superRefine((t, ctx) => {
    const seen = new Set<string>();
    t.roles.forEach((r, i) => {
      if (seen.has(r.id)) ctx.addIssue({ code: "custom", path: ["roles", i, "id"], message: `role "${r.id}" is defined twice` });
      seen.add(r.id);
    });
    if (t.allowPasskeyOnlySignup && !t.allowSignup) ctx.addIssue({ code: "custom", path: ["allowPasskeyOnlySignup"], message: "allowPasskeyOnlySignup needs allowSignup" });
    if (t.allowSignup && !t.signupRoleId) ctx.addIssue({ code: "custom", path: ["signupRoleId"], message: "allowSignup needs a signupRoleId" });
    if (t.signupRoleId && !seen.has(t.signupRoleId)) ctx.addIssue({ code: "custom", path: ["signupRoleId"], message: `role "${t.signupRoleId}" is not defined in this tenant` });
    if (t.signupRoleId && t.roles.find((r) => r.id === t.signupRoleId)?.permissions.some((p) => p === "*" || p.startsWith("tenant:") || p === "keys:manage" || p === "users:impersonate")) {
      ctx.addIssue({ code: "custom", path: ["signupRoleId"], message: "the signup role must not carry admin permissions" });
    }
  });
export type TenantPolicy = z.infer<typeof TenantPolicySchema>;
export type TenantPolicyInput = z.input<typeof TenantPolicySchema>;

const geo = z.object({ lat: z.number().min(-90).max(90), lon: z.number().min(-180).max(180), city: z.string().max(80), ip: z.string().max(64), timestampIso: z.string().datetime() }).strict();
export type GeoPoint = z.infer<typeof geo>;

const jwk = z.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string(), y: z.string() }).passthrough();

/** What the authenticator proved about itself when the passkey was registered (see `verifyWebAuthnRegistration`). */
export const PasskeyAttestationSchema = z.object({ format: z.string().max(40), type: z.enum(["none", "self", "basic"]), trusted: z.boolean(), aaguid: z.string().regex(/^[0-9a-f]{32}$/), vendor: z.string().max(200).optional() }).strict();

export const PasskeySchema = z.object({ credentialId: z.string().min(1), publicKeyJwk: jwk, signCount: z.number().int().min(0), deviceName: z.string().max(80), createdAtIso: z.string().datetime(), attestation: PasskeyAttestationSchema.optional() }).strict();
export type PasskeyRecord = z.infer<typeof PasskeySchema>;

export const UserRecordSchema = z
  .object({
    id: z.string().regex(/^usr_[A-Za-z0-9_-]{3,40}$/),
    email: z.string().email().max(200),
    name: z.string().min(1).max(100),
    /** `$ath-pbkdf2$v=1$iter=210000$<salt>$<hash>`; omit for passkey-only users. */
    passwordHash: z.string().max(400).optional(),
    totpSecretB32: z.string().regex(/^[A-Z2-7]{16,64}$/).optional(),
    /** Set when the user followed a verification, reset or magic link sent to this address. */
    emailVerifiedAt: z.string().datetime().optional(),
    passkeys: z.array(PasskeySchema).max(20).default([]),
    orgMemberships: z.array(z.object({ tenantId: z.string(), roleId: z.string() }).strict()).max(100).default([]),
    lastLoginGeo: geo.optional(),
  })
  .strict();
export type UserRecord = z.infer<typeof UserRecordSchema>;
export type UserRecordInput = z.input<typeof UserRecordSchema>;

/** Cross-checks users against tenants: every membership must name a real tenant and role. */
export function checkWorkspace(tenants: TenantPolicy[], users: UserRecord[]): string[] {
  const problems: string[] = [];
  const byId = new Map(tenants.map((t) => [t.id, t]));
  const ids = new Set<string>();
  const emails = new Set<string>();
  for (const u of users) {
    if (ids.has(u.id)) problems.push(`user id ${u.id} is used twice`);
    ids.add(u.id);
    if (emails.has(u.email.toLowerCase())) problems.push(`email ${u.email} is used twice`);
    emails.add(u.email.toLowerCase());
    for (const m of u.orgMemberships) {
      const t = byId.get(m.tenantId);
      if (!t) problems.push(`${u.id}: membership in unknown tenant "${m.tenantId}"`);
      else if (!t.roles.some((r) => r.id === m.roleId)) problems.push(`${u.id}: role "${m.roleId}" does not exist in tenant "${m.tenantId}"`);
    }
  }
  return problems;
}
