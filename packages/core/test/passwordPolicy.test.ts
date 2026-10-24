import { describe, expect, it } from "vitest";
import { TenantPolicySchema, checkPasswordPolicy } from "../src";

describe("password policy", () => {
  it("accepts a long passphrase with no composition rules", () => {
    expect(checkPasswordPolicy("correct horse battery staple")).toEqual({ ok: true });
    expect(checkPasswordPolicy("alllowercaseletters")).toEqual({ ok: true });
  });
  it("counts characters, not bytes, and rejects short and over-long input", () => {
    expect(checkPasswordPolicy("pässwörd-ünïcode", { minLength: 12 })).toEqual({ ok: true });
    expect(checkPasswordPolicy("shortpass")).toMatchObject({ ok: false, reason: "too_short" });
    expect(checkPasswordPolicy("a".repeat(300))).toMatchObject({ ok: false, reason: "too_long" });
    expect(checkPasswordPolicy("🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂")).toMatchObject({ ok: false, reason: "too_repetitive" });
  });
  it("refuses common, demo, repetitive and email-derived passwords", () => {
    expect(checkPasswordPolicy("password1234567")).toMatchObject({ ok: false, reason: "too_common" });
    expect(checkPasswordPolicy("passwordpassword")).toMatchObject({ ok: false, reason: "too_common" });
    expect(checkPasswordPolicy("Qwerty-Qwerty-Qwerty")).toMatchObject({ ok: false });
    expect(checkPasswordPolicy("password-is-a-bad-start-but-this-is-long")).toEqual({ ok: true });
    expect(checkPasswordPolicy("Passw0rd", { minLength: 8 })).toMatchObject({ ok: false, reason: "too_common" });
    expect(checkPasswordPolicy("1234567890", { minLength: 8 })).toMatchObject({ ok: false, reason: "too_common" });
    expect(checkPasswordPolicy("demo-passphrase-1")).toMatchObject({ ok: false, reason: "demo_password" });
    expect(checkPasswordPolicy("aaaaaaaaaaaaaaaa")).toMatchObject({ ok: false, reason: "too_repetitive" });
    expect(checkPasswordPolicy("ada.lovelace-2026!!", { email: "ada.lovelace@acme.test" })).toMatchObject({ ok: false, reason: "contains_email" });
    expect(checkPasswordPolicy("my-ada-secret-phrase", { email: "ada@acme.test" })).toEqual({ ok: true });
  });
});

describe("tenant signup policy", () => {
  const base = { id: "t1", name: "T", domain: "t.test", roles: [{ id: "member", name: "Member", permissions: ["issues:read"] }, { id: "owner", name: "Owner", permissions: ["*"] }] };
  it("defaults to no signup, password reset on, magic links off", () => {
    expect(TenantPolicySchema.parse(base)).toMatchObject({ allowSignup: false, requireVerifiedEmail: false, allowPasswordReset: true, allowMagicLinks: false });
  });
  it("requires a defined, non-admin signup role", () => {
    expect(TenantPolicySchema.safeParse({ ...base, allowSignup: true }).success).toBe(false);
    expect(TenantPolicySchema.safeParse({ ...base, allowSignup: true, signupRoleId: "ghost" }).success).toBe(false);
    expect(TenantPolicySchema.safeParse({ ...base, allowSignup: true, signupRoleId: "owner" }).success).toBe(false);
    expect(TenantPolicySchema.safeParse({ ...base, allowSignup: true, signupRoleId: "member" }).success).toBe(true);
  });
});
