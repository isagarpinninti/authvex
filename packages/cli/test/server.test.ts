import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDpopProof } from "@authvex/core";
import { DEMO, createSoftwareAuthenticator, deviceKey, startHarness, type Harness } from "./helpers";
import { verifyLedger } from "../src/ledger";

let h: Harness;
const T_ACME = "acme_fintech_prod";
const T_ZET = "zetechno_enterprise_sso";
const T_LIN = "linear_ops_workspace";

afterEach(async () => {
  await h?.close();
});

const login = (body: Record<string, unknown>, dpop?: Awaited<ReturnType<typeof deviceKey>>) => h.call("POST", "/api/auth/login", body, dpop ? { dpop } : {});
const ledgerTypes = (): string[] => JSON.parse(`[${readFileSync(h.ledgerPath, "utf8").trim().split("\n").join(",")}]`).map((e: { type: string }) => e.type);

describe("access", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  it("answers health publicly and needs an admin token for everything else", async () => {
    expect((await h.call("GET", "/api/health")).body).toMatchObject({ ok: true, version: "test" });
    expect((await h.call("GET", "/api/workspace", undefined, { token: "nope" })).status).toBe(401);
    expect((await h.call("GET", "/api/workspace", undefined, { token: "ath_adm_x.y" })).status).toBe(401);
    expect((await h.call("GET", "/api/keys", undefined, { token: "" })).status).toBe(401);
    const ws = await h.call("GET", "/api/workspace");
    expect(ws.status).toBe(200);
    expect(ws.body.tenants.map((t) => t.id)).toEqual([T_ACME, T_ZET, T_LIN].sort());
    expect(JSON.stringify(ws.body)).not.toContain("ath-pbkdf2");
    expect(JSON.stringify(ws.body)).not.toContain("totpSecretB32");
  });
  it("refuses an admin token signed by a different issuer, and a session token as an admin token", async () => {
    const other = await startHarness();
    try {
      expect((await h.call("GET", "/api/workspace", undefined, { token: other.admin })).status).toBe(401);
      const s = await login({ tenantId: T_LIN, email: "margaret@linear-ops.test", password: DEMO });
      expect(s.status).toBe(200);
      expect((await h.call("GET", "/api/workspace", undefined, { token: s.body.sessionToken })).status).toBe(401);
    } finally {
      await other.close();
    }
  });
  it("rejects malformed and oversized bodies and unknown endpoints", async () => {
    const r = await fetch(`${h.base}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: "{x" });
    expect(r.status).toBe(400);
    expect((await h.call("POST", "/api/auth/login", { tenantId: T_ACME, email: "a@b.test", password: "x".repeat(70_000) })).status).toBe(413);
    expect((await h.call("POST", "/api/auth/login", { tenantId: T_ACME, email: "not-an-email" })).status).toBe(400);
    expect((await h.call("POST", "/api/auth/login", { tenantId: T_ACME, email: "a@b.test", surprise: 1 })).status).toBe(400);
    expect((await h.call("GET", "/api/nope")).status).toBe(404);
  });
});

describe("password login and brute force", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  it("issues an unbound session on a tenant that does not require hardware binding", async () => {
    const r = await login({ tenantId: T_LIN, email: "margaret@linear-ops.test", password: DEMO });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ status: "ok", tokenType: "Bearer", report: { level: "LOW" }, claims: { sub: "usr_margaret", tid: T_LIN, gen: 1 } });
    expect(r.body.claims.cnf).toBeUndefined();
    expect(r.body.sessionToken.startsWith("ath_sess_")).toBe(true);
    expect(JSON.stringify(r.body)).not.toContain("ath-pbkdf2");
  });
  it("treats a wrong password, an unknown user, a wrong tenant and a missing password identically", async () => {
    const attempts = [
      { tenantId: T_LIN, email: "margaret@linear-ops.test", password: "wrong" },
      { tenantId: T_LIN, email: "nobody@linear-ops.test", password: DEMO },
      { tenantId: T_ZET, email: "margaret@linear-ops.test", password: DEMO },
      { tenantId: "ghost", email: "margaret@linear-ops.test", password: DEMO },
      { tenantId: T_LIN, email: "margaret@linear-ops.test" },
    ];
    const results = [];
    for (const a of attempts) results.push(await login(a));
    for (const r of results) expect(r).toMatchObject({ status: 401, body: { error: "invalid credentials", status: "invalid_credentials" } });
    expect(new Set(results.map((r) => JSON.stringify(r.body))).size).toBe(1);
  });
  it("blocks after too many failures, even with the right password", async () => {
    for (let i = 0; i < 8; i++) await login({ tenantId: T_LIN, email: "margaret@linear-ops.test", password: `bad${i}` });
    const r = await login({ tenantId: T_LIN, email: "margaret@linear-ops.test", password: DEMO });
    expect(r.status).toBe(403);
    expect(r.body.report.checks.find((c) => c.code === "AV-102")?.status).toBe("fail");
    expect(ledgerTypes()).toContain("auth.login.blocked");
  });
  it("records logins in the ledger without any secret", async () => {
    await login({ tenantId: T_LIN, email: "margaret@linear-ops.test", password: DEMO });
    await login({ tenantId: T_LIN, email: "margaret@linear-ops.test", password: "wrong" });
    const text = readFileSync(h.ledgerPath, "utf8");
    expect(ledgerTypes()).toEqual(expect.arrayContaining(["auth.login", "auth.login.failed"]));
    expect(text).not.toContain(DEMO);
    expect(text).not.toContain("ath_sess_");
    expect(text).not.toContain("ath_rt_");
    expect(verifyLedger(h.ledgerPath).ok).toBe(true);
  });
});

describe("hardware-bound sessions (DPoP)", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  const grace = { tenantId: T_ACME, email: "grace@acme-fintech.test", password: DEMO };

  it("blocks a login with no DPoP proof on a tenant that requires one (AV-105)", async () => {
    const r = await login(grace);
    expect(r.status).toBe(403);
    expect(r.body.report.checks.find((c) => c.code === "AV-105")).toMatchObject({ status: "fail" });
  });
  it("binds the session to the key that signed the login proof", async () => {
    const key = await deviceKey();
    const r = await login(grace, key);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ tokenType: "DPoP" });
    expect(r.body.claims.cnf?.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it("accepts the owner's proof and stops a thief who has only the token", async () => {
    const key = await deviceKey();
    const s = (await login(grace, key)).body;
    const url = `${h.base}/v1/invoices`;
    const proof = await createDpopProof({ ...key, method: "GET", url, sessionToken: s.sessionToken });
    expect(await h.call("POST", "/api/auth/dpop-verify", { sessionToken: s.sessionToken, dpopProof: proof, method: "GET", url })).toMatchObject({ status: 200, body: { valid: true, bound: true } });
    expect(await h.call("POST", "/api/auth/dpop-verify", { sessionToken: s.sessionToken, method: "GET", url })).toMatchObject({ status: 401, body: { valid: false, reason: "dpop_missing" } });
    const thief = await deviceKey();
    const forged = await createDpopProof({ ...thief, method: "GET", url, sessionToken: s.sessionToken });
    expect(await h.call("POST", "/api/auth/dpop-verify", { sessionToken: s.sessionToken, dpopProof: forged, method: "GET", url })).toMatchObject({ status: 401, body: { reason: "key_mismatch" } });
    expect(ledgerTypes().filter((t) => t === "auth.dpop.rejected")).toHaveLength(2);
  });
  it("refuses the same proof twice (replay)", async () => {
    const key = await deviceKey();
    const s = (await login(grace, key)).body;
    const url = `${h.base}/v1/invoices`;
    const proof = await createDpopProof({ ...key, method: "GET", url, sessionToken: s.sessionToken });
    expect((await h.call("POST", "/api/auth/dpop-verify", { sessionToken: s.sessionToken, dpopProof: proof, method: "GET", url })).status).toBe(200);
    expect(await h.call("POST", "/api/auth/dpop-verify", { sessionToken: s.sessionToken, dpopProof: proof, method: "GET", url })).toMatchObject({ status: 401, body: { reason: "replayed" } });
  });
  it("can also check a permission for the session's user", async () => {
    const key = await deviceKey();
    const s = (await login(grace, key)).body;
    const url = `${h.base}/v1/payouts`;
    const ask = async (perm: string) => h.call("POST", "/api/auth/dpop-verify", { sessionToken: s.sessionToken, dpopProof: await createDpopProof({ ...key, method: "GET", url, sessionToken: s.sessionToken }), method: "GET", url, requirePermission: perm });
    expect((await ask("invoices:write")).status).toBe(200);
    expect(await ask("keys:manage")).toMatchObject({ status: 403, body: { reason: "forbidden" } });
  });
});

describe("second factors and step-up", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  it("asks an admin for a second factor, and accepts a TOTP code once", async () => {
    const key = await deviceKey();
    const ada = { tenantId: T_ACME, email: "ada@acme-fintech.test", password: DEMO };
    const step = await login(ada, key);
    expect(step).toMatchObject({ status: 401, body: { status: "step_up_required", available: ["totp"] } });
    const code = await h.totp("usr_ada");
    const ok = await login({ ...ada, totp: code }, key);
    expect(ok).toMatchObject({ status: 200, body: { status: "ok" } });
    // The same code cannot be used again.
    const again = await login({ ...ada, totp: code }, key);
    expect(again.status).toBe(401);
    expect(again.body.status).toBe("step_up_required");
  });
  it("ignores a TOTP code when the password is wrong", async () => {
    const key = await deviceKey();
    const r = await login({ tenantId: T_ACME, email: "ada@acme-fintech.test", password: "bad", totp: await h.totp("usr_ada") }, key);
    expect(r).toMatchObject({ status: 401, body: { status: "invalid_credentials" } });
  });
});

describe("refresh rotation and the family kill-switch", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  const lin = { tenantId: T_LIN, email: "margaret@linear-ops.test", password: DEMO };

  it("rotates generation 1 -> 2 -> 3 on an unbound family", async () => {
    const s = (await login(lin)).body;
    const r2 = await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken });
    expect(r2).toMatchObject({ status: 200, body: { generation: 2, claims: { gen: 2, fam: s.familyId } } });
    const r3 = await h.call("POST", "/api/auth/rotate", { refreshToken: r2.body.refreshToken });
    expect(r3.body.generation).toBe(3);
  });
  it("revokes the whole family when an old token is replayed, including the legitimate session (AV-104)", async () => {
    const s = (await login(lin)).body;
    const r2 = (await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken })).body;
    const thief = await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken });
    expect(thief).toMatchObject({ status: 409, body: { status: "family_revoked", reason: "reuse_detected", familyId: s.familyId } });
    expect(thief.body.message).toContain("AV-104");
    expect((await h.call("POST", "/api/auth/rotate", { refreshToken: r2.refreshToken })).status).toBe(401);
    const check = await h.call("POST", "/api/auth/dpop-verify", { sessionToken: r2.sessionToken, method: "GET", url: `${h.base}/x` });
    expect(check).toMatchObject({ status: 401, body: { reason: "session_revoked" } });
    expect((await h.call("GET", "/api/workspace")).body.families.find((f) => f.familyId === s.familyId)?.status).toBe("revoked_reuse_detected");
    expect(ledgerTypes()).toContain("auth.family.reuse_detected");
  });
  it("needs proof of the key to refresh a bound family", async () => {
    const key = await deviceKey();
    const s = (await login({ tenantId: T_ACME, email: "grace@acme-fintech.test", password: DEMO }, key)).body;
    expect((await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken })).body.status).toBe("dpop_required");
    expect((await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken }, { dpop: await deviceKey() })).body.status).toBe("dpop_required");
    const ok = await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken }, { dpop: key });
    expect(ok).toMatchObject({ status: 200, body: { generation: 2, claims: { cnf: s.claims.cnf } } });
    // The owner's own device replaying an old token is still caught.
    const replay = await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken }, { dpop: key });
    expect(replay).toMatchObject({ status: 409, body: { status: "family_revoked" } });
  });
  it("can revoke a family from the admin API", async () => {
    const s = (await login(lin)).body;
    expect((await h.call("DELETE", `/api/families/${s.familyId}`)).status).toBe(200);
    expect((await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken })).status).toBe(401);
    expect((await h.call("DELETE", "/api/families/fam_nope")).status).toBe(404);
  });
  it("rejects an unknown refresh token", async () => {
    expect((await h.call("POST", "/api/auth/rotate", { refreshToken: "ath_rt_unknown" })).status).toBe(401);
  });
});

describe("passkeys", () => {
  beforeEach(async () => {
    h = await startHarness({ origins: [] });
  });
  const origin = (): string => h.base;
  async function enroll(userId: string) {
    const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: origin() });
    const ch = (await h.call("POST", "/api/users/passkeys/challenge", { userId })).body;
    const reg = await auth.register(ch.challenge);
    const r = await h.call("POST", "/api/users/passkeys", { challengeId: ch.challengeId, deviceName: "Test key", ...reg });
    return { auth, r };
  }
  const passkeyLogin = async (auth: Awaited<ReturnType<typeof createSoftwareAuthenticator>>, email: string, tenantId: string, over: { signCount?: number } = {}) => {
    const c = (await h.call("POST", "/api/auth/passkey/challenge", { tenantId, email })).body;
    return { c, r: await login({ tenantId, email, passkey: { challengeId: c.challengeId, credentialId: auth.credentialId, ...(await auth.assert(c.challenge, over)) } }) };
  };

  it("registers a passkey, then signs in with it (and a passkey counts as a second factor)", async () => {
    const { auth, r } = await enroll("usr_margaret");
    expect(r.status).toBe(201);
    const { c, r: res } = await passkeyLogin(auth, "margaret@linear-ops.test", T_LIN);
    expect(c.allowCredentials).toEqual([auth.credentialId]);
    expect(res).toMatchObject({ status: 200, body: { status: "ok" } });
    expect(h.users().find((u) => u.id === "usr_margaret")?.passkeys[0]?.signCount).toBe(1);
  });
  it("signs in an admin with only a passkey, since user verification is a second factor", async () => {
    const { auth } = await enroll("usr_ada");
    const { r } = await passkeyLogin(auth, "ada@acme-fintech.test", T_ACME);
    expect(r.status).toBe(403);
    expect(r.body.report.checks.find((c) => c.code === "AV-105")?.status).toBe("fail");
    const key = await deviceKey();
    const c = (await h.call("POST", "/api/auth/passkey/challenge", { tenantId: T_ACME, email: "ada@acme-fintech.test" })).body;
    const ok = await login({ tenantId: T_ACME, email: "ada@acme-fintech.test", passkey: { challengeId: c.challengeId, credentialId: auth.credentialId, ...(await auth.assert(c.challenge)) } }, key);
    expect(ok).toMatchObject({ status: 200, body: { status: "ok" } });
  });
  it("uses each challenge once", async () => {
    const { auth } = await enroll("usr_margaret");
    const c = (await h.call("POST", "/api/auth/passkey/challenge", { tenantId: T_LIN, email: "margaret@linear-ops.test" })).body;
    const body = { tenantId: T_LIN, email: "margaret@linear-ops.test", passkey: { challengeId: c.challengeId, credentialId: auth.credentialId, ...(await auth.assert(c.challenge)) } };
    expect((await login(body)).status).toBe(200);
    expect((await login(body)).status).toBe(401);
  });
  it("blocks a clone: the counter did not advance (AV-104)", async () => {
    const { auth } = await enroll("usr_margaret");
    expect((await passkeyLogin(auth, "margaret@linear-ops.test", T_LIN, { signCount: 7 })).r.status).toBe(200);
    const { r } = await passkeyLogin(auth, "margaret@linear-ops.test", T_LIN, { signCount: 7 });
    expect(r.status).toBe(403);
    expect(r.body.report.checks.find((c) => c.code === "AV-104")?.status).toBe("fail");
    expect(ledgerTypes()).toContain("auth.passkey.clone_suspected");
  });
  it("does not reveal which accounts exist when asked for a challenge", async () => {
    const known = (await h.call("POST", "/api/auth/passkey/challenge", { tenantId: T_LIN, email: "margaret@linear-ops.test" })).body;
    const unknown = (await h.call("POST", "/api/auth/passkey/challenge", { tenantId: T_LIN, email: "nobody@linear-ops.test" })).body;
    expect(Object.keys(unknown).sort()).toEqual(Object.keys(known).sort());
    expect(unknown.allowCredentials).toEqual([]);
  });
  it("refuses a registration for the wrong origin or a replayed challenge", async () => {
    const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: "https://evil.example" });
    const ch = (await h.call("POST", "/api/users/passkeys/challenge", { userId: "usr_margaret" })).body;
    const reg = await auth.register(ch.challenge);
    expect((await h.call("POST", "/api/users/passkeys", { challengeId: ch.challengeId, ...reg })).status).toBe(422);
    expect((await h.call("POST", "/api/users/passkeys", { challengeId: ch.challengeId, ...reg })).status).toBe(400);
  });
});

describe("impossible travel at login", () => {
  it("blocks Hyderabad then London within minutes when the server is told to trust client geo", async () => {
    h = await startHarness({ trustClientGeo: true });
    const first = await login({ tenantId: T_LIN, email: "ada@acme-fintech.test", password: DEMO, geo: { lat: 17.385, lon: 78.4867, city: "Hyderabad" } });
    expect(first.status).toBe(200);
    const second = await login({ tenantId: T_LIN, email: "ada@acme-fintech.test", password: DEMO, geo: { lat: 51.5074, lon: -0.1278, city: "London" } });
    expect(second.status).toBe(403);
    expect(second.body.report.checks.find((c) => c.code === "AV-103")?.status).toBe("fail");
    expect(second.body.report.travel?.speedKmh).toBeGreaterThan(10_000);
  });
  it("ignores a client-supplied location by default", async () => {
    h = await startHarness();
    await login({ tenantId: T_LIN, email: "ada@acme-fintech.test", password: DEMO, geo: { lat: 17.385, lon: 78.4867, city: "Hyderabad" } });
    const r = await login({ tenantId: T_LIN, email: "ada@acme-fintech.test", password: DEMO, geo: { lat: 51.5, lon: -0.12, city: "London" } });
    expect(r.status).toBe(200);
    expect(r.body.report.checks.find((c) => c.code === "AV-103")?.status).toBe("skipped");
  });
  it("reads the location from trusted edge headers when configured", async () => {
    h = await startHarness({ trustGeoHeaders: true });
    const r = await h.call("POST", "/api/auth/login", { tenantId: T_LIN, email: "ada@acme-fintech.test", password: DEMO }, { headers: { "x-authvex-geo": "51.5074,-0.1278,London", "x-authvex-asn": "datacenter" } });
    expect(r.body.report.checks.find((c) => c.code === "AV-106")?.status).toBe("warn");
  });
});

describe("threat evaluation endpoint", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  it("runs all eight checks for a scenario", async () => {
    const r = await h.call("POST", "/api/evaluate", { tenantId: T_ACME, userId: "usr_grace", currentGeo: { lat: 51.5074, lon: -0.1278, city: "London" }, lastLoginGeo: { lat: 17.385, lon: 78.4867, city: "Hyderabad", minutesAgo: 10 } });
    expect(r.status).toBe(200);
    expect(r.body.report.level).toBe("BLOCK");
    expect(r.body.report.checks).toHaveLength(8);
    expect(r.body.report.checks.find((c) => c.code === "AV-103")?.message).toContain("Hyderabad to London");
  });
  it("evaluates RBAC and impersonation scenarios, and refuses bad input", async () => {
    expect((await h.call("POST", "/api/evaluate", { tenantId: T_ACME, userId: "usr_grace", permission: "keys:manage" })).body.report.checks.find((c) => c.code === "AV-107")?.status).toBe("fail");
    expect((await h.call("POST", "/api/evaluate", { tenantId: T_ACME, userId: "usr_grace", impersonation: { reason: "TICKET-9 customer lockout", ttlSeconds: 600 } })).body.report.checks.find((c) => c.code === "AV-108")?.status).toBe("pass");
    expect((await h.call("POST", "/api/evaluate", { tenantId: T_ACME, userId: "usr_grace", impersonation: { reason: "TICKET-9 customer lockout", ttlSeconds: 600, tamper: true } })).body.report.checks.find((c) => c.code === "AV-108")?.status).toBe("fail");
    expect((await h.call("POST", "/api/evaluate", { tenantId: T_ACME, impersonation: { reason: "x", ttlSeconds: 600 } })).body.report.checks.find((c) => c.code === "AV-108")?.status).toBe("fail");
    expect((await h.call("POST", "/api/evaluate", { tenantId: "ghost" })).status).toBe(404);
    expect((await h.call("POST", "/api/evaluate", { tenantId: T_ACME, userId: "usr_ghost" })).status).toBe(404);
    expect((await h.call("POST", "/api/evaluate", { tenantId: T_ACME, failedAttemptsInWindow: -1 })).status).toBe(400);
  });
});

describe("break-glass impersonation", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  const body = { tenantId: T_ACME, actorId: "usr_root", targetUserId: "usr_grace", reason: "TICKET-4411 customer cannot see invoices" };
  it("mints a sealed, time-boxed token for a permitted admin, and records it", async () => {
    const r = await h.call("POST", "/api/auth/impersonate", body);
    expect(r.status).toBe(201);
    expect(r.body.claims).toMatchObject({ actorAdminId: "usr_root", targetUserId: "usr_grace", readOnly: true, reason: body.reason });
    const v = await h.call("POST", "/api/verify", { token: r.body.token });
    expect(v.body).toMatchObject({ kind: "impersonation", valid: true });
    expect(v.body.secondsLeft).toBeGreaterThan(590);
    const e = (await h.call("GET", "/api/ledger")).body.entries.find((x) => x.type === "impersonation.minted");
    expect(e).toMatchObject({ actor: "usr_root", subject: "usr_grace", detail: { reason: body.reason } });
    expect(JSON.stringify(e)).not.toContain("ath_imp_");
  });
  it("refuses an actor without users:impersonate (AV-107), a short reason, a long lifetime, and a non-member", async () => {
    expect((await h.call("POST", "/api/auth/impersonate", { ...body, actorId: "usr_grace", targetUserId: "usr_root" })).status).toBe(403);
    expect((await h.call("POST", "/api/auth/impersonate", { ...body, reason: "help" })).status).toBe(422);
    expect((await h.call("POST", "/api/auth/impersonate", { ...body, ttlSeconds: 3600 })).status).toBe(422);
    expect((await h.call("POST", "/api/auth/impersonate", { ...body, targetUserId: "usr_linus" })).status).toBe(422);
    expect((await h.call("POST", "/api/auth/impersonate", { ...body, targetUserId: "usr_root" })).status).toBe(422);
    expect(ledgerTypes().filter((t) => t === "impersonation.refused").length).toBeGreaterThanOrEqual(3);
  });
  it("detects a tampered seal", async () => {
    const r = await h.call("POST", "/api/auth/impersonate", body);
    const [head, sig] = (r.body.token as string).slice("ath_imp_".length).split(".") as [string, string];
    const claims = JSON.parse(Buffer.from(head, "base64url").toString()) as Record<string, unknown>;
    claims["readOnly"] = false;
    const forged = `ath_imp_${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${sig}`;
    expect((await h.call("POST", "/api/verify", { token: forged })).body).toMatchObject({ valid: false, reason: "bad_signature" });
  });
});

describe("machine API keys", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  it("mints a key shown once, stores only its hash, verifies scopes and revokes", async () => {
    const m = await h.call("POST", "/api/keys", { tenantId: T_ACME, name: "ci", scopes: ["invoices:read"], rateLimitPerMin: 100 });
    expect(m.status).toBe(201);
    expect(m.body.key).toMatch(/^atk_live_[0-9a-f]{8}_[A-Za-z0-9_-]{32}$/);
    const stored = readFileSync(join(h.dir, ".authvex", "keys.json"), "utf8");
    expect(stored).not.toContain(m.body.key.slice(18));
    expect(stored).toContain(m.body.record.keyPrefix);
    expect((await h.call("GET", "/api/keys")).body.keys).toHaveLength(1);
    expect(JSON.stringify((await h.call("GET", "/api/keys")).body)).not.toContain("sha256Hash");
    expect((await h.call("POST", "/api/verify", { token: m.body.key, scope: "invoices:read" })).body).toMatchObject({ kind: "apiKey", valid: true });
    expect((await h.call("POST", "/api/verify", { token: m.body.key, scope: "invoices:write" })).body).toMatchObject({ valid: false, reason: "scope_missing" });
    expect((await h.call("DELETE", `/api/keys/${m.body.record.id}`)).status).toBe(200);
    expect((await h.call("POST", "/api/verify", { token: m.body.key })).body).toMatchObject({ valid: false, reason: "revoked" });
    expect((await h.call("POST", "/api/keys", { tenantId: "ghost", name: "x", scopes: ["a"] })).status).toBe(404);
    expect((await h.call("POST", "/api/keys", { tenantId: T_ACME, name: "x", scopes: [] })).status).toBe(400);
    expect(ledgerTypes()).toEqual(expect.arrayContaining(["key.minted", "key.revoked"]));
  });
  it("rate limits a key per minute", async () => {
    const m = await h.call("POST", "/api/keys", { tenantId: T_ACME, name: "slow", scopes: ["*"], rateLimitPerMin: 2 });
    const v = () => h.call("POST", "/api/verify", { token: m.body.key });
    expect((await v()).body.valid).toBe(true);
    expect((await v()).body.valid).toBe(true);
    expect((await v()).body).toMatchObject({ valid: false, reason: "rate_limited" });
  });
});

describe("tenants, users and the ledger", () => {
  beforeEach(async () => {
    h = await startHarness();
  });
  it("updates a tenant's roles, persists them and rebuilds the matrix", async () => {
    const ws = (await h.call("GET", "/api/workspace")).body;
    const tenant = ws.tenants.find((t) => t.id === T_LIN) as unknown as { roles: Array<{ id: string; permissions: string[] }> } & Record<string, unknown>;
    const { matrix: _m, ...policy } = tenant;
    void _m;
    const next = { ...policy, roles: tenant.roles.map((r) => (r.id === "guest" ? { ...r, permissions: ["issues:read", "reports:read"] } : r)) };
    const r = await h.call("PUT", `/api/tenants/${T_LIN}`, next);
    expect(r.status).toBe(200);
    expect(r.body.matrix.permissions).toContain("reports:read");
    expect(JSON.parse(readFileSync(join(h.dir, "tenants", `${T_LIN}.json`), "utf8")).roles.find((x: { id: string }) => x.id === "guest").permissions).toEqual(["issues:read", "reports:read"]);
    expect((await h.call("PUT", `/api/tenants/${T_LIN}`, { ...next, id: "other" })).status).toBe(400);
    expect((await h.call("PUT", `/api/tenants/${T_LIN}`, { ...next, roles: next.roles.filter((x) => x.id !== "member") })).status).toBe(422);
    expect((await h.call("PUT", `/api/tenants/${T_LIN}`, { ...next, roles: [] })).status).toBe(400);
    expect(ledgerTypes()).toContain("tenant.updated");
  });
  it("enrols TOTP and returns the secret once", async () => {
    const r = await h.call("POST", "/api/users/totp", { userId: "usr_margaret" });
    expect(r.status).toBe(201);
    expect(r.body.secretB32).toMatch(/^[A-Z2-7]{32}$/);
    expect((await h.call("GET", "/api/workspace")).body.users.find((u) => u.id === "usr_margaret")?.hasTotp).toBe(true);
    expect(JSON.stringify((await h.call("GET", "/api/workspace")).body)).not.toContain(r.body.secretB32);
  });
  it("keeps a verifiable hash chain and spots tampering", async () => {
    await login({ tenantId: T_LIN, email: "margaret@linear-ops.test", password: DEMO });
    expect((await h.call("GET", "/api/ledger/verify")).body).toMatchObject({ ok: true });
    const lines = readFileSync(h.ledgerPath, "utf8").trim().split("\n");
    const e = JSON.parse(lines[0] as string);
    e.type = "forged";
    writeFileSync(h.ledgerPath, [JSON.stringify(e), ...lines.slice(1)].join("\n") + "\n");
    expect((await h.call("GET", "/api/ledger/verify")).body).toMatchObject({ ok: false, brokenAt: 1 });
  });
});

describe("static files", () => {
  it("serves the Studio directory and refuses to leave it", async () => {
    const { dir } = await (async () => {
      const x = await startHarness();
      await x.close();
      return x;
    })();
    void dir;
    h = await startHarness();
    const studio = join(h.dir, "studio");
    mkdirSync(join(studio, "_next", "static"), { recursive: true });
    writeFileSync(join(studio, "index.html"), "<html>studio</html>");
    writeFileSync(join(h.dir, "secret.txt"), "top secret");
    const { createAuthvexServer, loadWorkspace, loadOrCreateIssuerKey, staticKeyring, ConfigSchema } = await import("./testExports");
    const ws = loadWorkspace(h.dir);
    const s = createAuthvexServer({ workspace: { ...ws, config: ConfigSchema.parse({ port: 0 }) }, keyring: staticKeyring(await loadOrCreateIssuerKey(h.dir)), studioDir: studio });
    const { port } = await s.listen();
    try {
      expect(await (await fetch(`http://127.0.0.1:${port}/`)).text()).toContain("studio");
      for (const evil of ["/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt"]) {
        const r = await fetch(`http://127.0.0.1:${port}${evil}`);
        expect(await r.text(), evil).not.toContain("top secret");
      }
      expect((await fetch(`http://127.0.0.1:${port}/missing`)).status).toBe(404);
      expect((await fetch(`http://127.0.0.1:${port}/`, { method: "POST" })).status).toBe(405);
    } finally {
      await s.close();
    }
  });
});
