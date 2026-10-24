import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEMO, deviceKey, startHarness, type Harness } from "./helpers";
import { MemoryMailer, assertSafeMessage, buildMessage } from "../src/mail";

const LIN = "linear_ops_workspace";
const ACME = "acme_fintech_prod";
let h: Harness | undefined;
let mail: MemoryMailer;
afterEach(async () => {
  await h?.close();
  h = undefined;
});

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 40));
const tokenIn = (m: { text: string } | undefined): string => decodeURIComponent(/token=([^&\s]+)/.exec(m?.text ?? "")?.[1] ?? "");
async function boot(clock?: () => number): Promise<Harness> {
  mail = new MemoryMailer();
  h = await startHarness({}, { mailer: mail, ...(clock ? { now: clock } : {}) });
  return h;
}
async function patchTenant(id: string, patch: Record<string, unknown>): Promise<void> {
  const t = (await (h as Harness).call("GET", "/api/workspace")).body.tenants.find((x) => x.id === id) as unknown as Record<string, unknown>;
  const { matrix: _m, ...policy } = t;
  void _m;
  const r = await (h as Harness).call("PUT", `/api/tenants/${id}`, { ...policy, ...patch });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
}
const users = () => (h as Harness).users() as unknown as Array<{ id: string; email: string; emailVerifiedAt?: string; passwordHash?: string; orgMemberships: Array<{ tenantId: string; roleId: string }> }>;
const call = (path: string, body: unknown, opts?: Parameters<Harness["call"]>[3]) => (h as Harness).call("POST", path, body, opts);

describe("when email is not configured", () => {
  it("answers 501 to every email endpoint", async () => {
    h = await startHarness();
    for (const p of ["/api/auth/signup", "/api/auth/password-reset/request", "/api/auth/magic-link/request", "/api/auth/verify-email/resend"]) {
      expect((await call(p, { tenantId: LIN, email: "a@b.test", name: "A", password: "x".repeat(14) })).status, p).toBe(501);
    }
  });
});

describe("sign-up and email verification", () => {
  it("is closed unless the tenant opens it, and refuses an admin signup role", async () => {
    await boot();
    expect((await call("/api/auth/signup", { tenantId: LIN, email: "new@x.test", name: "New", password: "a long enough passphrase" })).status).toBe(403);
    const t = (await h!.call("GET", "/api/workspace")).body.tenants.find((x) => x.id === LIN) as unknown as Record<string, unknown>;
    const { matrix: _m, ...policy } = t;
    void _m;
    expect((await h!.call("PUT", `/api/tenants/${LIN}`, { ...policy, allowSignup: true, signupRoleId: "lead" })).status).toBe(400); // lead holds keys:manage, an admin permission
  });

  it("creates the user, emails a link, verifies on use, and the link works once", async () => {
    await boot();
    await patchTenant(LIN, { allowSignup: true, signupRoleId: "guest" });
    const r = await call("/api/auth/signup", { tenantId: LIN, email: "New.User@x.test", name: "New User", password: "a long enough passphrase" });
    expect(r).toMatchObject({ status: 202, body: { status: "check_your_email" } });
    await settle();
    const created = users().find((u) => u.email === "new.user@x.test");
    expect(created).toMatchObject({ orgMemberships: [{ tenantId: LIN, roleId: "guest" }] });
    expect(created?.emailVerifiedAt).toBeUndefined();
    const m = mail.lastTo("new.user@x.test");
    expect(m?.subject).toBe("Confirm your email address");
    expect(m?.text).toMatch(/https:\/\/app\.test\/auth#flow=verify&token=ath_ev_[0-9a-f]{64}&tenant=linear_ops_workspace/);
    const token = tokenIn(m);
    expect((await call("/api/auth/verify-email", { token })).body).toMatchObject({ status: "verified" });
    expect(users().find((u) => u.email === "new.user@x.test")?.emailVerifiedAt).toBeTruthy();
    expect((await call("/api/auth/verify-email", { token })).status).toBe(400);
    expect((await call("/api/auth/login", { tenantId: LIN, email: "new.user@x.test", password: "a long enough passphrase" })).status).toBe(200);
    expect((await h!.call("GET", "/api/ledger")).body.entries.map((e) => e.type)).toEqual(expect.arrayContaining(["user.signed_up", "user.email_verified", "mail.sent"]));
  });

  it("refuses weak passwords with a reason, before creating anything", async () => {
    await boot();
    await patchTenant(LIN, { allowSignup: true, signupRoleId: "guest" });
    const before = users().length;
    for (const [password, reason] of [["short", "too_short"], ["password1234567", "too_common"], ["demo-passphrase-1", "demo_password"], ["aaaaaaaaaaaaaaaaaa", "too_repetitive"]] as const) {
      const r = await call("/api/auth/signup", { tenantId: LIN, email: "weak@x.test", name: "W", password });
      expect(r.status).toBe(422);
      expect(r.body).toMatchObject({ status: "weak_password", reason });
    }
    expect(users()).toHaveLength(before);
    expect(mail.sent).toHaveLength(0);
  });

  it("does not reveal whether an address already has an account", async () => {
    await boot();
    await patchTenant(LIN, { allowSignup: true, signupRoleId: "guest" });
    const fresh = await call("/api/auth/signup", { tenantId: LIN, email: "brand-new@x.test", name: "N", password: "another long passphrase" });
    const taken = await call("/api/auth/signup", { tenantId: LIN, email: "margaret@linear-ops.test", name: "M", password: "another long passphrase" });
    expect({ status: taken.status, body: taken.body }).toEqual({ status: fresh.status, body: fresh.body });
    await settle();
    expect(mail.lastTo("margaret@linear-ops.test")?.subject).toBe("You already have an account");
    expect(users().filter((u) => u.email === "margaret@linear-ops.test")).toHaveLength(1);
    expect(users().find((u) => u.email === "margaret@linear-ops.test")?.orgMemberships).toEqual([{ tenantId: LIN, roleId: "member" }]);
  });

  it("holds back sign-in until the address is verified, when the tenant asks for that", async () => {
    await boot();
    await patchTenant(LIN, { allowSignup: true, signupRoleId: "guest", requireVerifiedEmail: true });
    await call("/api/auth/signup", { tenantId: LIN, email: "later@x.test", name: "L", password: "a long enough passphrase" });
    await settle();
    const blocked = await call("/api/auth/login", { tenantId: LIN, email: "later@x.test", password: "a long enough passphrase" });
    expect(blocked).toMatchObject({ status: 403, body: { status: "email_unverified" } });
    expect((await call("/api/auth/login", { tenantId: LIN, email: "later@x.test", password: "wrong wrong wrong" })).body.status).toBe("invalid_credentials");
    await call("/api/auth/verify-email", { token: tokenIn(mail.lastTo("later@x.test")) });
    expect((await call("/api/auth/login", { tenantId: LIN, email: "later@x.test", password: "a long enough passphrase" })).status).toBe(200);
  });

  it("resends a link for an unverified user only, and caps mail to one address at three an hour", async () => {
    await boot();
    await patchTenant(LIN, { allowSignup: true, signupRoleId: "guest" });
    await call("/api/auth/signup", { tenantId: LIN, email: "flood@x.test", name: "F", password: "a long enough passphrase" });
    for (let i = 0; i < 6; i++) await call("/api/auth/verify-email/resend", { tenantId: LIN, email: "flood@x.test" });
    await settle();
    expect(mail.sent.filter((m) => m.to === "flood@x.test")).toHaveLength(3);
    await call("/api/auth/verify-email/resend", { tenantId: LIN, email: "margaret@linear-ops.test" });
    await call("/api/auth/verify-email/resend", { tenantId: LIN, email: "ghost@x.test" });
    await settle();
    expect(mail.sent.filter((m) => m.to !== "flood@x.test")).toHaveLength(0);
  });

  it("expires a verification link after 24 hours", async () => {
    let clock = Date.parse("2026-11-01T00:00:00Z");
    await boot(() => clock);
    await patchTenant(LIN, { allowSignup: true, signupRoleId: "guest" });
    await call("/api/auth/signup", { tenantId: LIN, email: "slow@x.test", name: "S", password: "a long enough passphrase" });
    await settle();
    clock += 25 * 3600_000;
    expect((await call("/api/auth/verify-email", { token: tokenIn(mail.lastTo("slow@x.test")) })).status).toBe(400);
  });
});

describe("password reset", () => {
  it("gives the same answer for a known and an unknown address, and mails only the known one", async () => {
    await boot();
    const known = await call("/api/auth/password-reset/request", { tenantId: LIN, email: "margaret@linear-ops.test" });
    const unknown = await call("/api/auth/password-reset/request", { tenantId: LIN, email: "nobody@linear-ops.test" });
    expect({ status: unknown.status, body: unknown.body }).toEqual({ status: known.status, body: known.body });
    await settle();
    expect(mail.sent).toHaveLength(1);
    expect(mail.sent[0]).toMatchObject({ to: "margaret@linear-ops.test", subject: "Reset your password" });
    expect(mail.sent[0]?.text).toMatch(/flow=reset&token=ath_pr_/);
  });

  it("sets the new password, ends every old session, and the link works once", async () => {
    await boot();
    const s = (await call("/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).body;
    await call("/api/auth/password-reset/request", { tenantId: LIN, email: "margaret@linear-ops.test" });
    await settle();
    const token = tokenIn(mail.lastTo("margaret@linear-ops.test"));
    const weak = await call("/api/auth/password-reset/confirm", { token, newPassword: "short" });
    expect(weak).toMatchObject({ status: 422, body: { status: "weak_password" } });
    const done = await call("/api/auth/password-reset/confirm", { token, newPassword: "a brand new passphrase!" });
    expect(done).toMatchObject({ status: 200, body: { status: "password_changed", sessionsRevoked: 1 } });
    expect((await call("/api/auth/password-reset/confirm", { token, newPassword: "yet another passphrase" })).status).toBe(400);
    expect((await call("/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).status).toBe(401);
    expect((await call("/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: "a brand new passphrase!" })).status).toBe(200);
    expect((await call("/api/auth/rotate", { refreshToken: s.refreshToken })).status).toBe(401);
    expect(users().find((u) => u.email === "margaret@linear-ops.test")?.emailVerifiedAt).toBeTruthy();
    expect(readFileSync(h!.ledgerPath, "utf8")).not.toContain("a brand new passphrase");
    expect((await h!.call("GET", "/api/ledger")).body.entries.find((e) => e.type === "auth.password_reset")?.detail).toMatchObject({ familiesRevoked: 1 });
  });

  it("refuses an unknown, a wrong-purpose and an expired link, and respects the tenant switch", async () => {
    let clock = Date.parse("2026-11-01T00:00:00Z");
    await boot(() => clock);
    expect((await call("/api/auth/password-reset/confirm", { token: "ath_pr_nope", newPassword: "a brand new passphrase!" })).status).toBe(400);
    await call("/api/auth/password-reset/request", { tenantId: LIN, email: "margaret@linear-ops.test" });
    await settle();
    const token = tokenIn(mail.lastTo("margaret@linear-ops.test"));
    expect((await call("/api/auth/verify-email", { token })).status).toBe(400); // right secret, wrong purpose: and it is now spent
    expect((await call("/api/auth/password-reset/confirm", { token, newPassword: "a brand new passphrase!" })).status).toBe(400);
    await call("/api/auth/password-reset/request", { tenantId: LIN, email: "margaret@linear-ops.test" });
    await settle();
    const t2 = tokenIn(mail.sent.at(-1));
    clock += 31 * 60_000;
    expect((await call("/api/auth/password-reset/confirm", { token: t2, newPassword: "a brand new passphrase!" })).status).toBe(400);
    await patchTenant(LIN, { allowPasswordReset: false });
    expect((await call("/api/auth/password-reset/request", { tenantId: LIN, email: "margaret@linear-ops.test" })).status).toBe(403);
  });
});

describe("magic links", () => {
  it("are off unless the tenant turns them on", async () => {
    await boot();
    expect((await call("/api/auth/magic-link/request", { tenantId: LIN, email: "margaret@linear-ops.test" })).status).toBe(403);
  });

  it("sign a user in once, and mark the address verified", async () => {
    await boot();
    await patchTenant(LIN, { allowMagicLinks: true });
    expect((await call("/api/auth/magic-link/request", { tenantId: LIN, email: "margaret@linear-ops.test" })).status).toBe(202);
    expect((await call("/api/auth/magic-link/request", { tenantId: LIN, email: "ghost@linear-ops.test" })).status).toBe(202);
    await settle();
    expect(mail.sent).toHaveLength(1);
    const token = tokenIn(mail.sent[0]);
    expect(mail.sent[0]?.text).toMatch(/flow=magic&token=ath_ml_/);
    const r = await call("/api/auth/magic-link/consume", { token });
    expect(r).toMatchObject({ status: 200, body: { status: "ok", claims: { sub: "usr_margaret" } } });
    expect(users().find((u) => u.id === "usr_margaret")?.emailVerifiedAt).toBeTruthy();
    expect((await call("/api/auth/magic-link/consume", { token })).status).toBe(400);
    expect((await h!.call("GET", "/api/ledger")).body.entries.find((e) => e.type === "auth.login")?.detail).toMatchObject({ method: "magic-link" });
  });

  it("still runs the threat gate: a bound tenant needs a DPoP proof, and an admin still owes a second factor without losing the link", async () => {
    await boot();
    await patchTenant(ACME, { allowMagicLinks: true });
    await call("/api/auth/magic-link/request", { tenantId: ACME, email: "ada@acme-fintech.test" });
    await settle();
    const token = tokenIn(mail.lastTo("ada@acme-fintech.test"));
    expect((await call("/api/auth/magic-link/consume", { token })).status).toBe(403); // no DPoP proof on a tenant that requires one: the link is spent
    await call("/api/auth/magic-link/request", { tenantId: ACME, email: "ada@acme-fintech.test" });
    await settle();
    const t2 = tokenIn(mail.sent.at(-1));
    const key = await deviceKey();
    const step = await call("/api/auth/magic-link/consume", { token: t2 }, { dpop: key });
    expect(step).toMatchObject({ status: 401, body: { status: "step_up_required" } });
    const ok = await call("/api/auth/magic-link/consume", { token: t2, totp: await h!.totp("usr_ada") }, { dpop: key });
    expect(ok).toMatchObject({ status: 200, body: { status: "ok", tokenType: "DPoP" } });
    expect((await call("/api/auth/magic-link/consume", { token: t2 })).status).toBe(400);
  });
});

describe("failures of the mailer", () => {
  it("do not change the response, and are recorded without the address", async () => {
    await boot();
    mail.failWith = new Error("smtp is down");
    expect((await call("/api/auth/password-reset/request", { tenantId: LIN, email: "margaret@linear-ops.test" })).status).toBe(202);
    await settle();
    const e = (await h!.call("GET", "/api/ledger")).body.entries.find((x) => x.type === "mail.failed");
    expect(e?.detail).toMatchObject({ type: "reset" });
    expect(readFileSync(h!.ledgerPath, "utf8")).not.toContain("margaret@linear-ops.test");
  });
});

describe("the files on disk", () => {
  it("never hold a reset link's secret in the clear", async () => {
    await boot();
    await call("/api/auth/password-reset/request", { tenantId: LIN, email: "margaret@linear-ops.test" });
    await settle();
    await h!.restart();
    const secret = tokenIn(mail.sent[0]);
    expect(readFileSync(join(h!.dir, ".authvex", "state.json"), "utf8")).not.toContain(secret);
    expect(readFileSync(h!.ledgerPath, "utf8")).not.toContain(secret);
  });
});

describe("message building", () => {
  it("refuses header injection and bad addresses", () => {
    const ok = { to: "a@b.test", subject: "Hi", text: "x" };
    expect(() => assertSafeMessage("noreply@x.test", ok)).not.toThrow();
    expect(() => assertSafeMessage("noreply@x.test", { ...ok, subject: "Hi\r\nBcc: evil@x.test" })).toThrow(/line breaks/);
    expect(() => assertSafeMessage("noreply@x.test", { ...ok, to: "a@b.test\r\nBcc: evil@x.test" })).toThrow(/recipient/);
    expect(() => assertSafeMessage("noreply@x.test", { ...ok, to: "a@b.test, c@d.test" })).toThrow(/recipient/);
    expect(() => assertSafeMessage("bad", ok)).toThrow(/sender/);
    expect(() => assertSafeMessage("noreply@x.test", { ...ok, subject: "x".repeat(300) })).toThrow(/too long/);
  });
  it("builds a base64 UTF-8 body with an encoded non-ASCII subject", () => {
    const raw = buildMessage("noreply@x.test", { to: "a@b.test", subject: "Zurück zum Konto", text: ".\r\nQUIT\r\nSecret ünïcode" }, new Date("2026-11-01T00:00:00Z"), "id1");
    expect(raw).toContain("Subject: =?UTF-8?B?");
    expect(raw).toContain("Content-Transfer-Encoding: base64");
    expect(raw).toContain("Message-ID: <id1@x.test>");
    expect(raw).not.toMatch(/\r\nQUIT\r\n/);
    const body = raw.split("\r\n\r\n")[1] as string;
    expect(Buffer.from(body.replace(/\r\n/g, ""), "base64").toString("utf8")).toBe(".\r\nQUIT\r\nSecret ünïcode");
    expect(raw.split("\r\n").every((l) => l.length <= 998)).toBe(true);
  });
});
