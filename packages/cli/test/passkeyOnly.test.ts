import { afterEach, describe, expect, it } from "vitest";
import { createDpopProof, createSoftwareAuthenticator } from "@authvex/core";
import { DEMO, deviceKey, startHarness, type Harness } from "./helpers";
import { MemoryMailer } from "../src/mail";

const LIN = "linear_ops_workspace";
let h: Harness | undefined;
let mail: MemoryMailer;
afterEach(async () => {
  await h?.close();
  h = undefined;
});

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 40));
const tokenIn = (m: { text: string } | undefined): string => decodeURIComponent(/token=([^&\s]+)/.exec(m?.text ?? "")?.[1] ?? "");
const call = (path: string, body: unknown, opts?: Parameters<Harness["call"]>[3]) => (h as Harness).call("POST", path, body, opts);
const record = (email: string) => (h as Harness).users().find((u) => u.email === email) as unknown as { id: string; passwordHash?: string; emailVerifiedAt?: string; passkeys: Array<{ credentialId: string; deviceName: string }> } | undefined;

async function boot(tenantPatch: Record<string, unknown> = { allowSignup: true, signupRoleId: "guest", allowPasskeyOnlySignup: true }): Promise<Harness> {
  mail = new MemoryMailer();
  h = await startHarness({}, { mailer: mail });
  const t = (await h.call("GET", "/api/workspace")).body.tenants.find((x) => x.id === LIN) as unknown as Record<string, unknown>;
  const { matrix: _m, ...policy } = t;
  void _m;
  const r = await h.call("PUT", `/api/tenants/${LIN}`, { ...policy, ...tenantPatch });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  return h;
}

/** A request to a /api/me route with the session in the Authorization header (and a proof if the session is bound). */
async function me(method: string, path: string, session: string, body?: unknown, key?: Awaited<ReturnType<typeof deviceKey>>) {
  const url = `${(h as Harness).base}${path}`;
  const r = await fetch(url, {
    method,
    headers: { "content-type": "application/json", authorization: `DPoP ${session}`, ...(key ? { dpop: await createDpopProof({ ...key, method, url, sessionToken: session }) } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, unknown> };
}

/** Signs up without a password and follows the emailed link: the way into a brand-new passkey-only account. */
async function signUpAndEnrol(email: string) {
  expect((await call("/api/auth/signup", { tenantId: LIN, email, name: "Pat Passkey" })).status).toBe(202);
  await settle();
  const link = mail.lastTo(email);
  expect(link?.subject).toBe("Set up your passkey");
  const consumed = await call("/api/auth/enrol/consume", { token: tokenIn(link) });
  return { link, consumed };
}

async function registerPasskey(session: string, auth: Awaited<ReturnType<typeof createSoftwareAuthenticator>>, extra: { password?: string; key?: Awaited<ReturnType<typeof deviceKey>>; deviceName?: string } = {}) {
  const ch = await me("POST", "/api/me/passkeys/challenge", session, extra.password ? { password: extra.password } : {}, extra.key);
  if (ch.status !== 200) return { ch, reg: ch };
  const reg = await me("POST", "/api/me/passkeys", session, { challengeId: ch.body["challengeId"], deviceName: extra.deviceName ?? "My laptop", ...(await auth.register(ch.body["challenge"] as string)) }, extra.key);
  return { ch, reg };
}

describe("passkey-only sign-up", () => {
  it("is off unless the tenant allows it: a password is required", async () => {
    await boot({ allowSignup: true, signupRoleId: "guest" });
    const r = await call("/api/auth/signup", { tenantId: LIN, email: "pat@x.test", name: "Pat" });
    expect(r.status).toBe(422);
    expect(r.body["status"]).toBe("password_required");
    expect(record("pat@x.test")).toBeUndefined();
  });

  it("needs allowSignup, and still takes a password when one is given", async () => {
    await boot({ allowSignup: false, signupRoleId: undefined });
    await expect(boot({ allowSignup: false, allowPasskeyOnlySignup: true })).rejects.toThrow();
    await boot();
    expect((await call("/api/auth/signup", { tenantId: LIN, email: "pw@x.test", name: "P", password: "a long enough passphrase" })).status).toBe(202);
    await settle();
    expect(mail.lastTo("pw@x.test")?.subject).toBe("Confirm your email address");
  });

  it("goes from a sign-up form to a signed-in passkey-only account, without ever setting a password", async () => {
    await boot();
    const { consumed } = await signUpAndEnrol("pat@x.test");
    expect(consumed.status).toBe(200);
    expect(consumed.body["status"]).toBe("ok");
    const created = record("pat@x.test");
    expect(created?.passwordHash).toBeUndefined();
    expect(created?.emailVerifiedAt).toBeDefined();
    const session = consumed.body["sessionToken"] as string;

    const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: h!.base });
    const { reg } = await registerPasskey(session, auth);
    expect(reg.status, JSON.stringify(reg.body)).toBe(201);
    expect(record("pat@x.test")?.passkeys).toHaveLength(1);

    // from now on the passkey signs in, and there is still no password
    const c = (await call("/api/auth/passkey/challenge", { tenantId: LIN, email: "pat@x.test" })).body;
    const login = await call("/api/auth/login", { tenantId: LIN, email: "pat@x.test", passkey: { challengeId: c["challengeId"], credentialId: auth.credentialId, ...(await auth.assert(c["challenge"])) } });
    expect(login.status, JSON.stringify(login.body)).toBe(200);
    expect(login.body["status"]).toBe("ok");
    expect((await call("/api/auth/login", { tenantId: LIN, email: "pat@x.test", password: DEMO })).status).toBe(401);
  });

  it("makes the link work once, and useless once the account has a credential", async () => {
    await boot();
    const { link, consumed } = await signUpAndEnrol("pat@x.test");
    expect(consumed.status).toBe(200);
    expect((await call("/api/auth/enrol/consume", { token: tokenIn(link) })).status).toBe(400);
    // a fresh link for an account that has since got a passkey is refused
    const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: h!.base });
    await registerPasskey(consumed.body["sessionToken"] as string, auth);
    await call("/api/auth/enrol/request", { tenantId: LIN, email: "pat@x.test" });
    await settle();
    expect(mail.sent.filter((m) => m.subject === "Set up your passkey")).toHaveLength(1);
  });

  it("can be asked for again if the first link expired, and says the same thing for unknown addresses", async () => {
    await boot();
    await call("/api/auth/signup", { tenantId: LIN, email: "pat@x.test", name: "Pat" });
    await settle();
    const known = await call("/api/auth/enrol/request", { tenantId: LIN, email: "pat@x.test" });
    const unknown = await call("/api/auth/enrol/request", { tenantId: LIN, email: "ghost@x.test" });
    expect(known.status).toBe(202);
    expect(unknown).toEqual(known);
    await settle();
    expect(mail.sent.filter((m) => m.to === "pat@x.test")).toHaveLength(2);
    expect(mail.sent.filter((m) => m.to === "ghost@x.test")).toHaveLength(0);
    // an ordinary account (with a password) cannot be sent an enrol link: it would be a second magic link
    await call("/api/auth/enrol/request", { tenantId: LIN, email: "margaret@linear-ops.test" });
    await settle();
    expect(mail.sent.filter((m) => m.to === "margaret@linear-ops.test")).toHaveLength(0);
    expect((await call("/api/auth/enrol/consume", { token: "ath_en_nonsense" })).status).toBe(400);
  });
});

describe("self-service passkeys", () => {
  it("refuses everything without a valid session, and an OpenID client's token", async () => {
    await boot();
    for (const [m, p] of [["GET", "/api/me/passkeys"], ["POST", "/api/me/passkeys/challenge"], ["POST", "/api/me/passkeys"], ["DELETE", "/api/me/passkeys/abc"]] as const) {
      expect((await fetch(`${h!.base}${p}`, { method: m, headers: { "content-type": "application/json" }, ...(m === "GET" ? {} : { body: "{}" }) })).status, `${m} ${p}`).toBe(401);
      expect((await me(m, p, "ath_sess_garbage.garbage", m === "GET" ? undefined : {})).status).toBe(401);
    }
  });

  it("lists, adds and removes passkeys for a user with a password, which must be re-entered unless the session is bound to a device", async () => {
    await boot();
    const ada = (await call("/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).body;
    const session = ada["sessionToken"] as string; // unbound
    expect((await me("GET", "/api/me/passkeys", session)).body).toMatchObject({ passkeys: [], hasPassword: true });
    const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: h!.base });

    // a stolen, unbound session cannot plant a passkey
    const stolen = await registerPasskey(session, auth);
    expect(stolen.ch.status).toBe(403);
    expect(stolen.ch.body["status"]).toBe("reauthentication_required");
    expect((await registerPasskey(session, auth, { password: "wrong password" })).ch.status).toBe(403);
    expect(record("margaret@linear-ops.test")?.passkeys).toHaveLength(0);

    const ok = await registerPasskey(session, auth, { password: DEMO, deviceName: "Work laptop" });
    expect(ok.reg.status, JSON.stringify(ok.reg.body)).toBe(201);
    const listed = (await me("GET", "/api/me/passkeys", session)).body["passkeys"] as Array<{ credentialId: string; deviceName: string }>;
    expect(listed).toMatchObject([{ deviceName: "Work laptop" }]);

    // removal needs the same proof of who is asking
    expect((await me("DELETE", `/api/me/passkeys/${encodeURIComponent(listed[0]!.credentialId)}`, session, {})).status).toBe(403);
    expect((await me("DELETE", `/api/me/passkeys/${encodeURIComponent(listed[0]!.credentialId)}`, session, { password: DEMO })).status).toBe(200);
    expect(record("margaret@linear-ops.test")?.passkeys).toHaveLength(0);
    expect((await me("DELETE", "/api/me/passkeys/nope", session, { password: DEMO })).status).toBe(404);
  });

  it("lets a session bound to a device key add a passkey without the password, but not with a proof from another device", async () => {
    await boot();
    const key = await deviceKey();
    const login = (await call("/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO }, { dpop: key })).body;
    const session = login["sessionToken"] as string;
    const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: h!.base });
    expect((await registerPasskey(session, auth, { key: await deviceKey() })).ch.status).toBe(401);
    expect((await registerPasskey(session, auth, { key })).reg.status).toBe(201);
  });

  it("will not let a passkey-only user remove their only way in", async () => {
    await boot();
    const { consumed } = await signUpAndEnrol("pat@x.test");
    const session = consumed.body["sessionToken"] as string;
    const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: h!.base });
    await registerPasskey(session, auth);
    const only = record("pat@x.test")?.passkeys[0]?.credentialId as string;
    const r = await me("DELETE", `/api/me/passkeys/${encodeURIComponent(only)}`, session, {});
    expect(r.status).toBe(409);
    expect(r.body["status"]).toBe("last_credential");
    expect(record("pat@x.test")?.passkeys).toHaveLength(1);
  });

  it("asks a passkey-only user for a device-bound session to add a second passkey (there is no password to re-enter)", async () => {
    await boot();
    const { consumed } = await signUpAndEnrol("pat@x.test");
    const first = await createSoftwareAuthenticator({ rpId: "localhost", origin: h!.base });
    await registerPasskey(consumed.body["sessionToken"] as string, first);
    // the enrolment session is unbound and the account now has a credential: a second one needs a bound session
    const second = await createSoftwareAuthenticator({ rpId: "localhost", origin: h!.base });
    expect((await registerPasskey(consumed.body["sessionToken"] as string, second)).ch.status).toBe(403);
    const key = await deviceKey();
    const c = (await call("/api/auth/passkey/challenge", { tenantId: LIN, email: "pat@x.test" })).body;
    const login = await call("/api/auth/login", { tenantId: LIN, email: "pat@x.test", passkey: { challengeId: c["challengeId"], credentialId: first.credentialId, ...(await first.assert(c["challenge"])) } }, { dpop: key });
    expect(login.status).toBe(200);
    expect((await registerPasskey(login.body["sessionToken"] as string, second, { key })).reg.status).toBe(201);
    expect(record("pat@x.test")?.passkeys).toHaveLength(2);
  });

  it("honours a revoked session at once", async () => {
    await boot();
    const login = (await call("/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).body;
    const fam = (login["claims"] as { fam: string }).fam;
    expect((await me("GET", "/api/me/passkeys", login["sessionToken"])).status).toBe(200);
    expect((await h!.call("DELETE", `/api/families/${fam}`)).status).toBe(200);
    expect((await me("GET", "/api/me/passkeys", login["sessionToken"])).status).toBe(401);
  });
});
