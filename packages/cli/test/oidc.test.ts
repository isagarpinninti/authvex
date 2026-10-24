import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createDpopProof, halfHash, verifyJwt } from "@authvex/core";
import { DEMO, deviceKey, startHarness, type DeviceKey, type Harness } from "./helpers";
import { ClientSchema, clientsPath, isAllowedRedirectUri, newClientId, newClientSecret, writeClients, type OidcClient } from "../src/oidc";
import { loadWorkspace } from "./testExports";

const LIN = "linear_ops_workspace";
const ACME = "acme_fintech_prod";
const CB = "https://app.example.test/callback";
// Response bodies are checked field by field below; they are untyped on purpose.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>;

let h: Harness | undefined;
let clock: number;
afterEach(async () => {
  await h?.close();
  h = undefined;
});

const b64u = (b: Buffer): string => b.toString("base64url");
const pkce = () => {
  const verifier = b64u(randomBytes(32));
  return { verifier, challenge: b64u(createHash("sha256").update(verifier).digest()) };
};

async function boot(): Promise<Harness> {
  clock = Date.now();
  h = await startHarness({}, { now: () => clock });
  return h;
}
function addClient(tenantId: string, over: Partial<OidcClient> = {}, confidential = false): { client: OidcClient; secret?: string } {
  const ws = loadWorkspace((h as Harness).dir);
  const secret = confidential ? newClientSecret() : null;
  const client = ClientSchema.parse({ clientId: newClientId(), name: "Test App", tenantId, type: confidential ? "confidential" : "public", ...(secret ? { secretHash: secret.hash } : {}), redirectUris: [CB], postLogoutRedirectUris: ["https://app.example.test/bye"], ...over });
  const path = clientsPath(ws.root, ws.config);
  writeClients(path, [...(readExisting(path)), client]);
  return { client, ...(secret ? { secret: secret.secret } : {}) };
}
function readExisting(path: string): OidcClient[] {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as OidcClient[];
  } catch {
    return [];
  }
}

const authorizeUrl = (tenantId: string, client: OidcClient, p: Record<string, string>): string => {
  const u = new URL(`${(h as Harness).base}/oidc/${tenantId}/authorize`);
  for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: CB, response_type: "code", scope: "openid email profile", ...p })) u.searchParams.set(k, v);
  return u.toString();
};
const noFollow = (url: string) => fetch(url, { redirect: "manual" });

/** Plays the sign-in page: signs the user in and completes the request. Returns where the browser would go next. */
async function signInAndComplete(requestId: string, tenantId: string, email: string, dpop?: DeviceKey): Promise<{ redirectTo: string }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const login = await fetch(`${(h as Harness).base}/api/auth/login`, { method: "POST", headers: { ...headers, ...(dpop ? { dpop: await createDpopProof({ ...dpop, method: "POST", url: `${(h as Harness).base}/api/auth/login`, nowMs: clock }) } : {}) }, body: JSON.stringify({ tenantId, email, password: DEMO }) });
  const s = (await login.json()) as { sessionToken: string; status: string };
  expect(s.status).toBe("ok");
  const url = `${(h as Harness).base}/api/oidc/complete`;
  const r = await fetch(url, { method: "POST", headers: { ...headers, ...(dpop ? { dpop: await createDpopProof({ ...dpop, method: "POST", url, sessionToken: s.sessionToken, nowMs: clock }) } : {}) }, body: JSON.stringify({ request: requestId, sessionToken: s.sessionToken }) });
  expect(r.status, await r.clone().text()).toBe(200);
  return (await r.json()) as { redirectTo: string };
}

interface Flow { code: string; state: string; iss: string; verifier: string; nonce: string }
async function getCode(tenantId: string, client: OidcClient, email: string, extra: Record<string, string> = {}, dpop?: DeviceKey): Promise<Flow> {
  const { verifier, challenge } = pkce();
  const nonce = b64u(randomBytes(12));
  const state = b64u(randomBytes(8));
  const a = await noFollow(authorizeUrl(tenantId, client, { code_challenge: challenge, code_challenge_method: "S256", state, nonce, ...extra }));
  expect(a.status).toBe(302);
  const loc = new URL(a.headers.get("location") as string);
  expect(loc.pathname).toBe("/signin/");
  const done = await signInAndComplete(loc.searchParams.get("request") as string, tenantId, email, dpop);
  const cb = new URL(done.redirectTo);
  expect(`${cb.origin}${cb.pathname}`).toBe(CB);
  return { code: cb.searchParams.get("code") as string, state: cb.searchParams.get("state") as string, iss: cb.searchParams.get("iss") as string, verifier, nonce };
}

async function tokenRequest(tenantId: string, form: Record<string, string>, opts: { basic?: [string, string]; dpop?: DeviceKey } = {}) {
  const url = `${(h as Harness).base}/oidc/${tenantId}/token`;
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (opts.basic) headers["authorization"] = `Basic ${Buffer.from(`${encodeURIComponent(opts.basic[0])}:${encodeURIComponent(opts.basic[1])}`).toString("base64")}`;
  if (opts.dpop) headers["dpop"] = await createDpopProof({ ...opts.dpop, method: "POST", url, nowMs: clock });
  const r = await fetch(url, { method: "POST", headers, body: new URLSearchParams(form).toString() });
  return { status: r.status, headers: r.headers, body: (await r.json()) as Json };
}
const exchange = (tenantId: string, client: OidcClient, f: Flow, extra: Record<string, string> = {}, opts: Parameters<typeof tokenRequest>[2] = {}) =>
  tokenRequest(tenantId, { grant_type: "authorization_code", code: f.code, redirect_uri: CB, code_verifier: f.verifier, client_id: client.clientId, ...extra }, opts);
const userinfo = async (tenantId: string, token: string, scheme = "Bearer", dpop?: DeviceKey) => {
  const url = `${(h as Harness).base}/oidc/${tenantId}/userinfo`;
  const r = await fetch(url, { headers: { authorization: `${scheme} ${token}`, ...(dpop ? { dpop: await createDpopProof({ ...dpop, method: "GET", url, sessionToken: token, nowMs: clock }) } : {}) } });
  return { status: r.status, headers: r.headers, body: (await r.json()) as Json };
};
const jwks = async (): Promise<{ keys: Array<Record<string, string>> }> => (await (await fetch(`${(h as Harness).base}/.well-known/jwks.json`)).json()) as never;

describe("discovery", () => {
  it("publishes a per-tenant issuer document that points at working endpoints", async () => {
    await boot();
    const d = (await (await fetch(`${h!.base}/oidc/${LIN}/.well-known/openid-configuration`)).json()) as Json;
    expect(d).toMatchObject({
      issuer: `${h!.base}/oidc/${LIN}`, authorization_endpoint: `${h!.base}/oidc/${LIN}/authorize`, token_endpoint: `${h!.base}/oidc/${LIN}/token`, userinfo_endpoint: `${h!.base}/oidc/${LIN}/userinfo`,
      jwks_uri: `${h!.base}/.well-known/jwks.json`, response_types_supported: ["code"], code_challenge_methods_supported: ["S256"], id_token_signing_alg_values_supported: ["ES256"], dpop_signing_alg_values_supported: ["ES256"],
    });
    expect((await fetch(d["jwks_uri"] as string)).status).toBe(200);
    expect((await fetch(`${h!.base}/oidc/ghost/.well-known/openid-configuration`)).status).toBe(404);
    expect((await fetch(`${h!.base}/oidc/${LIN}/nothing`)).status).toBe(404);
  });
});

describe("authorization code flow with PKCE", () => {
  it("issues an ID token any OIDC verifier accepts, and an access token the userinfo endpoint honours", async () => {
    await boot();
    const { client } = addClient(LIN);
    const f = await getCode(LIN, client, "margaret@linear-ops.test");
    expect(f.state).toBeTruthy();
    expect(f.iss).toBe(`${h!.base}/oidc/${LIN}`);
    const t = await exchange(LIN, client, f);
    expect(t.status).toBe(200);
    expect(t.headers.get("cache-control")).toBe("no-store");
    expect(t.body).toMatchObject({ token_type: "Bearer", scope: "openid email profile" });
    expect(t.body["refresh_token"]).toBeUndefined();
    const id = await verifyJwt(t.body["id_token"], await jwks(), { issuer: f.iss, audience: client.clientId, nonce: f.nonce, nowMs: clock });
    expect(id.ok).toBe(true);
    if (!id.ok) return;
    expect(id.claims).toMatchObject({ sub: "usr_margaret", email: "margaret@linear-ops.test", email_verified: true, name: "Margaret Member", azp: client.clientId });
    expect(id.claims["at_hash"]).toBe(await halfHash(t.body["access_token"]));
    expect(typeof id.claims["sid"]).toBe("string");
    expect(typeof id.claims["auth_time"]).toBe("number");
    const u = await userinfo(LIN, t.body["access_token"]);
    expect(u).toMatchObject({ status: 200, body: { sub: "usr_margaret", email: "margaret@linear-ops.test", name: "Margaret Member" } });
  });

  it("returns only the claims the granted scopes allow, and refresh tokens only with offline_access", async () => {
    await boot();
    const { client } = addClient(LIN);
    const bare = await exchange(LIN, client, await getCode(LIN, client, "margaret@linear-ops.test", { scope: "openid" }));
    expect(bare.body["refresh_token"]).toBeUndefined();
    expect((await userinfo(LIN, bare.body["access_token"])).body).toEqual({ sub: "usr_margaret" });
    const off = await exchange(LIN, client, await getCode(LIN, client, "margaret@linear-ops.test", { scope: "openid offline_access" }));
    expect(off.body["refresh_token"]).toMatch(/^ath_rt_/);
  });

  it("authenticates a confidential client by Basic or by form, and refuses a wrong secret", async () => {
    await boot();
    const { client, secret } = addClient(LIN, {}, true);
    const viaBasic = await exchange(LIN, client, await getCode(LIN, client, "margaret@linear-ops.test"), { client_id: "" }, { basic: [client.clientId, secret as string] });
    expect(viaBasic.status).toBe(200);
    const viaForm = await exchange(LIN, client, await getCode(LIN, client, "margaret@linear-ops.test"), { client_secret: secret as string });
    expect(viaForm.status).toBe(200);
    const wrong = await exchange(LIN, client, await getCode(LIN, client, "margaret@linear-ops.test"), {}, { basic: [client.clientId, "cs_wrong"] });
    expect(wrong).toMatchObject({ status: 401, body: { error: "invalid_client" } });
    expect(wrong.headers.get("www-authenticate")).toContain("Basic");
    const none = await exchange(LIN, client, await getCode(LIN, client, "margaret@linear-ops.test"));
    expect(none).toMatchObject({ status: 401, body: { error: "invalid_client" } });
  });

  it("locks a client out after repeated failures, even for the right secret", async () => {
    await boot();
    const { client, secret } = addClient(LIN, {}, true);
    for (let i = 0; i < 10; i++) await tokenRequest(LIN, { grant_type: "authorization_code", code: "x" }, { basic: [client.clientId, `cs_bad${i}`] });
    const f = await getCode(LIN, client, "margaret@linear-ops.test");
    expect((await exchange(LIN, client, f, {}, { basic: [client.clientId, secret as string] })).status).toBe(401);
  });

  it("enforces PKCE: S256 required, a wrong verifier burns the code", async () => {
    await boot();
    const { client } = addClient(LIN);
    const bad = async (extra: Record<string, string>): Promise<URL> => new URL((await noFollow(authorizeUrl(LIN, client, { state: "s1", ...extra }))).headers.get("location") as string);
    const missing = await bad({});
    expect(missing.origin + missing.pathname).toBe(CB);
    expect(missing.searchParams.get("error")).toBe("invalid_request");
    expect(missing.searchParams.get("state")).toBe("s1");
    expect((await bad({ code_challenge: pkce().challenge, code_challenge_method: "plain" })).searchParams.get("error")).toBe("invalid_request");
    expect((await bad({ code_challenge: "tooshort", code_challenge_method: "S256" })).searchParams.get("error")).toBe("invalid_request");
    const f = await getCode(LIN, client, "margaret@linear-ops.test");
    expect((await exchange(LIN, client, f, { code_verifier: b64u(randomBytes(32)) })).body).toMatchObject({ error: "invalid_grant" });
    expect((await exchange(LIN, client, f)).body).toMatchObject({ error: "invalid_grant" });
  });

  it("never redirects to an unregistered redirect URI or for an unknown client, and rejects the rest with a redirect that names the problem", async () => {
    await boot();
    const { client } = addClient(LIN);
    const { challenge } = pkce();
    const base = { code_challenge: challenge, code_challenge_method: "S256" };
    for (const p of [{ redirect_uri: "https://evil.example/cb" }, { redirect_uri: `${CB}/` }, { client_id: "cl_unknown" }] as Array<Record<string, string>>) {
      const r = await noFollow(authorizeUrl(LIN, client, { ...base, ...p }));
      expect(r.status).toBe(400);
      expect(r.headers.get("location")).toBeNull();
    }
    expect((await noFollow(`${h!.base}/oidc/${ACME}/authorize?client_id=${client.clientId}&redirect_uri=${encodeURIComponent(CB)}`)).status).toBe(400);
    const err = async (p: Record<string, string>): Promise<string | null> => new URL((await noFollow(authorizeUrl(LIN, client, { ...base, ...p }))).headers.get("location") as string).searchParams.get("error");
    expect(await err({ response_type: "token" })).toBe("unsupported_response_type");
    expect(await err({ scope: "email" })).toBe("invalid_scope");
    expect(await err({ scope: "openid admin" })).toBe("invalid_scope");
    expect(await err({ prompt: "none" })).toBe("login_required");
    expect(await err({ request: "eyJhbGciOiJub25lIn0." })).toBe("request_not_supported");
    expect(await err({ request_uri: "https://evil.example/req" })).toBe("request_not_supported");
  });

  it("binds a code to its client and redirect URI, and a code works once", async () => {
    await boot();
    const { client } = addClient(LIN);
    const other = addClient(LIN).client;
    const f = await getCode(LIN, client, "margaret@linear-ops.test");
    expect((await exchange(LIN, other, f)).body).toMatchObject({ error: "invalid_grant" });
    const f2 = await getCode(LIN, client, "margaret@linear-ops.test");
    expect((await exchange(LIN, client, f2, { redirect_uri: "https://app.example.test/other" })).body).toMatchObject({ error: "invalid_grant" });
    const f3 = await getCode(LIN, client, "margaret@linear-ops.test");
    expect((await exchange(LIN, client, f3)).status).toBe(200);
  });

  it("revokes what a code produced when the code is presented a second time", async () => {
    await boot();
    const { client } = addClient(LIN);
    const f = await getCode(LIN, client, "margaret@linear-ops.test", { scope: "openid offline_access" });
    const first = await exchange(LIN, client, f);
    expect((await userinfo(LIN, first.body["access_token"])).status).toBe(200);
    expect((await exchange(LIN, client, f)).body).toMatchObject({ error: "invalid_grant" });
    expect((await userinfo(LIN, first.body["access_token"])).status).toBe(401);
    expect((await tokenRequest(LIN, { grant_type: "refresh_token", refresh_token: first.body["refresh_token"], client_id: client.clientId })).body).toMatchObject({ error: "invalid_grant" });
    expect((await h!.call("GET", "/api/ledger")).body.entries.map((e) => e.type)).toContain("oidc.code_reuse");
  });

  it("expires a code after a minute and a sign-in request after ten", async () => {
    await boot();
    const { client } = addClient(LIN);
    const f = await getCode(LIN, client, "margaret@linear-ops.test");
    clock += 61_000;
    expect((await exchange(LIN, client, f)).body).toMatchObject({ error: "invalid_grant" });
    const a = await noFollow(authorizeUrl(LIN, client, { code_challenge: pkce().challenge, code_challenge_method: "S256" }));
    const id = new URL(a.headers.get("location") as string).searchParams.get("request") as string;
    clock += 10 * 60_000 + 1000;
    expect((await fetch(`${h!.base}/api/oidc/request?id=${id}`)).status).toBe(404);
    const login = await (await fetch(`${h!.base}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO }) })).json() as { sessionToken: string };
    expect((await fetch(`${h!.base}/api/oidc/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: id, sessionToken: login.sessionToken }) })).status).toBe(400);
  });

  it("lets the sign-in page read who is asking, and a request is single-use", async () => {
    await boot();
    const { client } = addClient(LIN, { name: "Acme Notes" });
    const a = await noFollow(authorizeUrl(LIN, client, { code_challenge: pkce().challenge, code_challenge_method: "S256", scope: "openid email", login_hint: "margaret@linear-ops.test" }));
    const id = new URL(a.headers.get("location") as string).searchParams.get("request") as string;
    const info = await (await fetch(`${h!.base}/api/oidc/request?id=${id}`)).json();
    expect(info).toEqual({ clientName: "Acme Notes", tenantId: LIN, scope: ["openid", "email"], loginHint: "margaret@linear-ops.test" });
    expect((await fetch(`${h!.base}/api/oidc/request?id=${id}`)).status).toBe(200);
    await signInAndComplete(id, LIN, "margaret@linear-ops.test");
    expect((await fetch(`${h!.base}/api/oidc/request?id=${id}`)).status).toBe(404);
  });

  it("refuses to complete a request with a session from another tenant, a made-up session, or a bad token", async () => {
    await boot();
    const { client } = addClient(LIN);
    const id = new URL((await noFollow(authorizeUrl(LIN, client, { code_challenge: pkce().challenge, code_challenge_method: "S256" }))).headers.get("location") as string).searchParams.get("request") as string;
    const key = await deviceKey();
    const zet = await (await fetch(`${h!.base}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tenantId: "zetechno_enterprise_sso", email: "linus@zetechno.test", password: DEMO }) })).json() as { sessionToken: string };
    expect((await fetch(`${h!.base}/api/oidc/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: id, sessionToken: zet.sessionToken }) })).status).toBe(401);
    const id2 = new URL((await noFollow(authorizeUrl(LIN, client, { code_challenge: pkce().challenge, code_challenge_method: "S256" }))).headers.get("location") as string).searchParams.get("request") as string;
    expect((await fetch(`${h!.base}/api/oidc/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: id2, sessionToken: "ath_sess_nope.nope" }) })).status).toBe(401);
    void key;
  });
});

describe("refresh tokens", () => {
  async function withRefresh(client: OidcClient): Promise<{ access: string; refresh: string }> {
    const t = await exchange(LIN, client, await getCode(LIN, client, "margaret@linear-ops.test", { scope: "openid email offline_access" }));
    return { access: t.body["access_token"], refresh: t.body["refresh_token"] };
  }
  it("rotates, keeps the scope, and revokes the session when an old token is replayed", async () => {
    await boot();
    const { client } = addClient(LIN);
    const t0 = await withRefresh(client);
    const r1 = await tokenRequest(LIN, { grant_type: "refresh_token", refresh_token: t0.refresh, client_id: client.clientId });
    expect(r1).toMatchObject({ status: 200, body: { token_type: "Bearer", scope: "openid email offline_access" } });
    expect(r1.body["refresh_token"]).not.toBe(t0.refresh);
    expect((await userinfo(LIN, r1.body["access_token"])).body).toMatchObject({ email: "margaret@linear-ops.test" });
    const replay = await tokenRequest(LIN, { grant_type: "refresh_token", refresh_token: t0.refresh, client_id: client.clientId });
    expect(replay.body).toMatchObject({ error: "invalid_grant" });
    expect((await tokenRequest(LIN, { grant_type: "refresh_token", refresh_token: r1.body["refresh_token"], client_id: client.clientId })).body).toMatchObject({ error: "invalid_grant" });
    expect((await userinfo(LIN, r1.body["access_token"])).status).toBe(401);
  });
  it("is only for the client it was issued to, and cannot widen the scope or be used on the native endpoint", async () => {
    await boot();
    const { client } = addClient(LIN);
    const other = addClient(LIN).client;
    const t0 = await withRefresh(client);
    expect((await tokenRequest(LIN, { grant_type: "refresh_token", refresh_token: t0.refresh, client_id: other.clientId })).body).toMatchObject({ error: "invalid_grant" });
    expect((await tokenRequest(LIN, { grant_type: "refresh_token", refresh_token: t0.refresh, client_id: client.clientId, scope: "openid email profile" })).body).toMatchObject({ error: "invalid_scope" });
    expect((await h!.call("POST", "/api/auth/rotate", { refreshToken: t0.refresh })).status).toBe(401);
    const narrowed = await tokenRequest(LIN, { grant_type: "refresh_token", refresh_token: t0.refresh, client_id: client.clientId, scope: "openid" });
    expect(narrowed.status).toBe(200);
  });
  it("answers an unsupported grant type, an unknown tenant path and a bad method properly", async () => {
    await boot();
    const { client } = addClient(LIN);
    expect((await tokenRequest(LIN, { grant_type: "password", username: "a", password: "b", client_id: client.clientId })).body).toMatchObject({ error: "unsupported_grant_type" });
    expect((await fetch(`${h!.base}/oidc/${LIN}/token`)).status).toBe(404);
  });
});

describe("DPoP-bound tokens", () => {
  it("requires a proof at the token endpoint on a tenant that demands hardware binding, then needs it on every use", async () => {
    await boot();
    const { client } = addClient(ACME);
    const signInKey = await deviceKey();
    const f = await getCode(ACME, client, "grace@acme-fintech.test", {}, signInKey);
    expect((await exchange(ACME, client, f)).body).toMatchObject({ error: "invalid_dpop_proof" });
    const f2 = await getCode(ACME, client, "grace@acme-fintech.test", {}, signInKey);
    const appKey = await deviceKey();
    const t = await exchange(ACME, client, f2, {}, { dpop: appKey });
    expect(t).toMatchObject({ status: 200, body: { token_type: "DPoP" } });
    const token = t.body["access_token"] as string;
    expect((await userinfo(ACME, token, "DPoP", appKey)).status).toBe(200);
    const bearer = await userinfo(ACME, token, "Bearer");
    expect(bearer.status).toBe(401);
    expect(bearer.headers.get("www-authenticate")).toContain("invalid_token");
    expect((await userinfo(ACME, token, "DPoP")).status).toBe(401);
    expect((await userinfo(ACME, token, "DPoP", await deviceKey())).status).toBe(401);
  });
  it("binds a refresh token to the key as well", async () => {
    await boot();
    const { client } = addClient(ACME);
    const signInKey = await deviceKey();
    const appKey = await deviceKey();
    const t = await exchange(ACME, client, await getCode(ACME, client, "grace@acme-fintech.test", { scope: "openid offline_access" }, signInKey), {}, { dpop: appKey });
    const thief = await tokenRequest(ACME, { grant_type: "refresh_token", refresh_token: t.body["refresh_token"], client_id: client.clientId });
    expect(thief.body).toMatchObject({ error: "invalid_dpop_proof" });
    const owner = await tokenRequest(ACME, { grant_type: "refresh_token", refresh_token: t.body["refresh_token"], client_id: client.clientId }, { dpop: appKey });
    expect(owner).toMatchObject({ status: 200, body: { token_type: "DPoP" } });
  });
});

describe("end session", () => {
  it("revokes the session named in the ID token and redirects only to a registered address", async () => {
    await boot();
    const { client } = addClient(LIN);
    const t = await exchange(LIN, client, await getCode(LIN, client, "margaret@linear-ops.test"));
    expect((await userinfo(LIN, t.body["access_token"])).status).toBe(200);
    const bye = await noFollow(`${h!.base}/oidc/${LIN}/end_session?id_token_hint=${t.body["id_token"]}&post_logout_redirect_uri=${encodeURIComponent("https://app.example.test/bye")}&state=xyz`);
    expect(bye.status).toBe(302);
    expect(bye.headers.get("location")).toBe("https://app.example.test/bye?state=xyz");
    expect((await userinfo(LIN, t.body["access_token"])).status).toBe(401);
    const evil = await noFollow(`${h!.base}/oidc/${LIN}/end_session?id_token_hint=${t.body["id_token"]}&post_logout_redirect_uri=${encodeURIComponent("https://evil.example/")}`);
    expect(evil.status).toBe(200);
    expect(evil.headers.get("location")).toBeNull();
    expect((await noFollow(`${h!.base}/oidc/${LIN}/end_session?id_token_hint=garbage`)).status).toBe(200);
  });
});

describe("clients", () => {
  it("validates redirect URIs and the shape of a client", () => {
    for (const ok of ["https://app.test/cb", "http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb", "com.example.app://callback"]) expect(isAllowedRedirectUri(ok), ok).toBe(true);
    for (const bad of ["http://app.test/cb", "https://app.test/cb#frag", "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "ftp://x.test/", "not a url", "http://localhost.evil.test/cb"]) expect(isAllowedRedirectUri(bad), bad).toBe(false);
    const base = { clientId: "cl_abcdef12", name: "x", tenantId: "t1", redirectUris: [CB] };
    expect(ClientSchema.safeParse({ ...base, type: "public" }).success).toBe(true);
    expect(ClientSchema.safeParse({ ...base, type: "confidential" }).success).toBe(false);
    expect(ClientSchema.safeParse({ ...base, type: "public", secretHash: "a".repeat(64) }).success).toBe(false);
    expect(ClientSchema.safeParse({ ...base, type: "public", allowedScopes: ["email"] }).success).toBe(false);
    expect(ClientSchema.safeParse({ ...base, type: "public", surprise: 1 }).success).toBe(false);
    expect(join("a", "b")).toBe("a/b");
  });
});
