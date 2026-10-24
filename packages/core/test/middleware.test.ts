import { describe, expect, it } from "vitest";
import {
  createDpopProof, createGuard, createJwksCache, expressGuard, fastifyGuard, generateIssuerKey, honoGuard, issueSessionBundle, withAuthvex,
  type GuardRequest, type IssuerKey, type SessionClaims,
} from "../src";

const API = "https://api.example.com";
const ISSUER = "https://id.example.com";
const T0 = Date.UTC(2030, 5, 1);

const jwk = (k: IssuerKey) => ({ ...k.publicKeyJwk, kid: k.kid, alg: "ES256", use: "sig" });
const device = async () => {
  const p = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const j = await globalThis.crypto.subtle.exportKey("jwk", p.publicKey);
  return { privateKey: p.privateKey, publicKeyJwk: { kty: j.kty, crv: j.crv, x: j.x, y: j.y } };
};

/** A fake Authvex server: a JWKS that can be rotated, and an introspection endpoint. */
function fakeIssuer(keys: IssuerKey[]) {
  const state = { keys, jwksCalls: 0, introspect: null as null | ((body: Record<string, unknown>) => { status: number; body: unknown }), down: false };
  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (state.down) throw new Error("connection refused");
    if (url === `${ISSUER}/.well-known/jwks.json`) {
      state.jwksCalls++;
      return Response.json({ keys: state.keys.map(jwk) });
    }
    if (url === `${ISSUER}/api/auth/dpop-verify` && state.introspect) {
      const r = state.introspect(JSON.parse(String(init?.body)));
      return Response.json(r.body, { status: r.status });
    }
    return new Response("nope", { status: 404 });
  }) as typeof globalThis.fetch;
  return { state, fetch };
}

const req = (method: string, path: string, headers: Record<string, string> = {}): GuardRequest => ({ method, path, header: (n) => headers[n.toLowerCase()] });
async function signed(issuer: IssuerKey, over: { tenantId?: string; bound?: boolean; ttl?: number; client?: { clientId: string; scope: string } } = {}) {
  const dev = await device();
  const b = await issueSessionBundle({ issuer, userId: "usr_a", tenantId: over.tenantId ?? "t1", nowMs: T0, ...(over.ttl ? { accessTtlSeconds: over.ttl } : {}), ...(over.bound === false ? {} : { clientPublicKeyJwk: dev.publicKeyJwk }), ...(over.client ? { client: over.client } : {}) });
  const call = async (method: string, path: string, nowMs = T0) => ({
    authorization: `DPoP ${b.sessionToken}`,
    dpop: await createDpopProof({ ...dev, method, url: `${API}${path}`, sessionToken: b.sessionToken, nowMs }),
  });
  return { dev, b, call };
}

describe("Guard (local mode)", () => {
  it("accepts a bound session with a proof for this very request", async () => {
    const issuer = await generateIssuerKey();
    const { fetch } = fakeIssuer([issuer]);
    const guard = createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => T0 });
    const s = await signed(issuer);
    const r = await guard.authenticate(req("GET", "/v1/invoices", await s.call("GET", "/v1/invoices")));
    expect(r).toMatchObject({ ok: true, bound: true, claims: { sub: "usr_a", tid: "t1" } });
  });

  it("refuses a stolen token (no proof), a proof for another URL or method, and a replayed proof", async () => {
    const issuer = await generateIssuerKey();
    const guard = createGuard({ issuer: ISSUER, fetch: fakeIssuer([issuer]).fetch, baseUrl: API, now: () => T0 });
    const s = await signed(issuer);
    const h = await s.call("GET", "/v1/invoices");
    expect(await guard.authenticate(req("GET", "/v1/invoices", { authorization: h.authorization }))).toMatchObject({ ok: false, status: 401, error: "dpop_missing" });
    expect(await guard.authenticate(req("GET", "/v1/other", h))).toMatchObject({ ok: false, status: 401 });
    expect(await guard.authenticate(req("DELETE", "/v1/invoices", h))).toMatchObject({ ok: false, status: 401 });
    expect((await guard.authenticate(req("GET", "/v1/invoices", h))).ok).toBe(true);
    expect(await guard.authenticate(req("GET", "/v1/invoices", h))).toMatchObject({ ok: false, status: 401, error: "replayed" });
  });

  it("refuses another device's proof for the same token", async () => {
    const issuer = await generateIssuerKey();
    const guard = createGuard({ issuer: ISSUER, fetch: fakeIssuer([issuer]).fetch, baseUrl: API, now: () => T0 });
    const s = await signed(issuer);
    const thief = await device();
    const proof = await createDpopProof({ ...thief, method: "GET", url: `${API}/x`, sessionToken: s.b.sessionToken, nowMs: T0 });
    expect(await guard.authenticate(req("GET", "/x", { authorization: `DPoP ${s.b.sessionToken}`, dpop: proof }))).toMatchObject({ ok: false, status: 401, error: "key_mismatch" });
  });

  it("answers a missing or malformed Authorization header with a challenge", async () => {
    const guard = createGuard({ issuer: ISSUER, fetch: fakeIssuer([]).fetch, baseUrl: API });
    for (const h of [{} as Record<string, string>, { authorization: "Basic abc" }, { authorization: "DPoP" }, { authorization: "Bearer a b" }]) {
      const r = await guard.authenticate(req("GET", "/x", h));
      expect(r).toMatchObject({ ok: false, status: 401, error: "missing_token" });
      expect((r as { wwwAuthenticate: string }).wwwAuthenticate).toMatch(/^DPoP /);
    }
    const bad = await guard.authenticate(req("GET", "/x", { authorization: "DPoP ath_sess_garbage.garbage" }));
    expect(bad).toMatchObject({ ok: false, status: 401 });
    expect((bad as { wwwAuthenticate: string }).wwwAuthenticate).toContain('error="invalid_token"');
  });

  it("refuses an expired session and a token from an issuer it does not trust", async () => {
    const issuer = await generateIssuerKey();
    const guard = createGuard({ issuer: ISSUER, fetch: fakeIssuer([issuer]).fetch, baseUrl: API, now: () => T0 + 120_000 });
    const s = await signed(issuer, { ttl: 60 });
    expect(await guard.authenticate(req("GET", "/x", await s.call("GET", "/x", T0 + 120_000)))).toMatchObject({ ok: false, error: "expired" });
    const foreign = await signed(await generateIssuerKey());
    expect(await guard.authenticate(req("GET", "/x", await foreign.call("GET", "/x", T0 + 120_000)))).toMatchObject({ ok: false, status: 401, error: "unknown_key" });
  });

  it("enforces tenants, scope and binding", async () => {
    const issuer = await generateIssuerKey();
    const { fetch } = fakeIssuer([issuer]);
    const s = await signed(issuer, { tenantId: "t9" });
    expect(await createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => T0, tenants: ["t1"] }).authenticate(req("GET", "/x", await s.call("GET", "/x")))).toMatchObject({ ok: false, status: 403, error: "wrong_tenant" });
    const oidc = await signed(issuer, { client: { clientId: "cl_1", scope: "openid email" } });
    const needs = createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => T0, scope: "invoices:read" });
    expect(await needs.authenticate(req("GET", "/x", await oidc.call("GET", "/x")))).toMatchObject({ ok: false, status: 403, error: "insufficient_scope" });
    expect((await createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => T0, scope: "email" }).authenticate(req("GET", "/x", await oidc.call("GET", "/x")))).ok).toBe(true);
    const unbound = await signed(issuer, { bound: false });
    const strict = createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => T0, requireBinding: true });
    expect(await strict.authenticate(req("GET", "/x", { authorization: `Bearer ${unbound.b.sessionToken}` }))).toMatchObject({ ok: false, status: 401, error: "not_bound" });
    expect((await createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => T0 }).authenticate(req("GET", "/x", { authorization: `Bearer ${unbound.b.sessionToken}` }))).ok).toBe(true);
  });

  it("works out the URL from baseUrl, the Host header, or trusted proxy headers", async () => {
    const issuer = await generateIssuerKey();
    const { fetch } = fakeIssuer([issuer]);
    const s = await signed(issuer);
    const h = { ...(await s.call("GET", "/x")) };
    const viaHost = createGuard({ issuer: ISSUER, fetch, now: () => T0 });
    expect(await viaHost.authenticate(req("GET", "/x", { ...h, host: "api.example.com" }))).toMatchObject({ ok: false }); // http://api.example.com/x is not https://…
    const s2 = await signed(issuer);
    const behindProxy = createGuard({ issuer: ISSUER, fetch, now: () => T0, trustProxy: true });
    expect((await behindProxy.authenticate(req("GET", "/x", { ...(await s2.call("GET", "/x")), host: "10.0.0.5:3000", "x-forwarded-host": "api.example.com", "x-forwarded-proto": "https" }))).ok).toBe(true);
    const s3 = await signed(issuer);
    const untrusting = createGuard({ issuer: ISSUER, fetch, now: () => T0 });
    expect(await untrusting.authenticate(req("GET", "/x", { ...(await s3.call("GET", "/x")), host: "10.0.0.5:3000", "x-forwarded-host": "api.example.com", "x-forwarded-proto": "https" }))).toMatchObject({ ok: false });
    expect(await createGuard({ issuer: ISSUER, fetch, now: () => T0 }).authenticate(req("GET", "/x", h))).toMatchObject({ ok: false, error: "invalid_request" });
  });

  it("follows a key rotation, but a flood of unknown key ids does not flood the issuer", async () => {
    const old = await generateIssuerKey();
    const fresh = await generateIssuerKey();
    const { state, fetch } = fakeIssuer([old]);
    let clock = T0;
    const guard = createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => clock, jwksMinRefetchMs: 30_000 });
    const a = await signed(old);
    expect((await guard.authenticate(req("GET", "/x", await a.call("GET", "/x")))).ok).toBe(true);
    expect(state.jwksCalls).toBe(1);
    state.keys = [fresh, old];
    const b = await signed(fresh);
    clock = T0 + 5_000;
    // The new key id is unknown to the cached set, but a refresh just happened less than 30 s ago: wait.
    expect(await guard.authenticate(req("GET", "/x", await b.call("GET", "/x", clock)))).toMatchObject({ ok: false, error: "unknown_key" });
    expect(state.jwksCalls).toBe(1);
    clock = T0 + 31_000;
    expect((await guard.authenticate(req("GET", "/x", await b.call("GET", "/x", clock)))).ok).toBe(true);
    expect(state.jwksCalls).toBe(2);
    const stranger = await signed(await generateIssuerKey());
    for (let i = 0; i < 20; i++) await guard.authenticate(req("GET", "/x", await stranger.call("GET", "/x", clock)));
    expect(state.jwksCalls).toBe(2); // just refreshed: twenty unknown key ids cost nothing
    clock += 31_000;
    for (let i = 0; i < 20; i++) await guard.authenticate(req("GET", "/x", await stranger.call("GET", "/x", clock)));
    expect(state.jwksCalls).toBe(3); // after the gap, one refresh for the whole flood
  });

  it("refreshes a stale key set, serves the old one briefly when the issuer is down, and says 502 when it never had one", async () => {
    const issuer = await generateIssuerKey();
    const { state, fetch } = fakeIssuer([issuer]);
    let clock = T0;
    const guard = createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => clock, jwksTtlMs: 60_000 });
    const s = await signed(issuer, { ttl: 100_000 });
    expect((await guard.authenticate(req("GET", "/x", await s.call("GET", "/x", clock)))).ok).toBe(true);
    clock = T0 + 90_000;
    state.down = true;
    expect((await guard.authenticate(req("GET", "/x", await s.call("GET", "/x", clock)))).ok).toBe(true); // stale but within 6 x ttl
    const cold = createGuard({ issuer: ISSUER, fetch, baseUrl: API, now: () => clock });
    expect(await cold.authenticate(req("GET", "/x", await s.call("GET", "/x", clock)))).toMatchObject({ ok: false, status: 502, error: "issuer_unreachable" });
  });

  it("shares one fetch between simultaneous requests", async () => {
    const issuer = await generateIssuerKey();
    const { state, fetch } = fakeIssuer([issuer]);
    const cache = createJwksCache({ issuer: ISSUER, fetch });
    await Promise.all(Array.from({ length: 25 }, () => cache.get()));
    expect(state.jwksCalls).toBe(1);
  });

  it("refuses a permission requirement it cannot enforce, and a bad issuer", () => {
    expect(() => createGuard({ issuer: ISSUER, permission: "a:b" })).toThrow(/introspect/);
    expect(() => createGuard({ issuer: "ftp://x" })).toThrow(/http/);
  });
});

describe("Guard (introspect mode)", () => {
  const claims: SessionClaims = { v: 1, typ: "session", sub: "usr_a", tid: "t1", fam: "fam_1", gen: 1, jti: "j", iat: 0, exp: 9_999_999_999 };

  it("sends the request to the issuer and trusts its answer, including revocation", async () => {
    const { state, fetch } = fakeIssuer([]);
    const seen: Array<Record<string, unknown>> = [];
    state.introspect = (b) => (seen.push(b), { status: 200, body: { valid: true, bound: true, claims } });
    const guard = createGuard({ issuer: ISSUER, fetch, baseUrl: API, mode: "introspect", permission: "invoices:read" });
    const ok = await guard.authenticate(req("POST", "/v1/invoices?x=1", { authorization: "DPoP tok", dpop: "proof" }));
    expect(ok).toMatchObject({ ok: true, claims: { sub: "usr_a" } });
    expect(seen[0]).toEqual({ sessionToken: "tok", dpopProof: "proof", method: "POST", url: `${API}/v1/invoices?x=1`, requirePermission: "invoices:read" });
    state.introspect = () => ({ status: 401, body: { valid: false, reason: "session_revoked", message: "the session family has been revoked" } });
    expect(await guard.authenticate(req("POST", "/x", { authorization: "DPoP tok", dpop: "proof" }))).toMatchObject({ ok: false, status: 401, error: "session_revoked" });
    state.introspect = () => ({ status: 403, body: { valid: false, reason: "forbidden", message: "role lacks permission" } });
    expect(await guard.authenticate(req("POST", "/x", { authorization: "DPoP tok", dpop: "proof" }))).toMatchObject({ ok: false, status: 403, error: "forbidden" });
  });

  it("does not turn the issuer's failures into logins", async () => {
    const { state, fetch } = fakeIssuer([]);
    const guard = createGuard({ issuer: ISSUER, fetch, baseUrl: API, mode: "introspect" });
    for (const status of [429, 500, 503]) {
      state.introspect = () => ({ status, body: {} });
      expect(await guard.authenticate(req("GET", "/x", { authorization: "DPoP tok" }))).toMatchObject({ ok: false, status: 502 });
    }
    state.down = true;
    expect(await guard.authenticate(req("GET", "/x", { authorization: "DPoP tok" }))).toMatchObject({ ok: false, status: 502, error: "issuer_unreachable" });
    state.down = false;
    state.introspect = () => ({ status: 200, body: { valid: true } }); // claims missing
    expect(await guard.authenticate(req("GET", "/x", { authorization: "DPoP tok" }))).toMatchObject({ ok: false });
  });
});

describe("adapters", () => {
  const claims: SessionClaims = { v: 1, typ: "session", sub: "usr_a", tid: "t1", fam: "fam_1", gen: 1, jti: "j", iat: 0, exp: 9_999_999_999 };
  const allow = { authenticate: async () => ({ ok: true as const, claims, bound: true }) };
  const deny = { authenticate: async () => ({ ok: false as const, status: 401 as const, error: "expired", message: "the session token has expired", wwwAuthenticate: 'DPoP algs="ES256", error="invalid_token"' }) };

  it("express: sets req.authvex and calls next, or answers 401 with a challenge and does not call next", async () => {
    const mk = () => ({ headers: {} as Record<string, string>, res: { statusCode: 200, h: {} as Record<string, string>, body: "", setHeader(n: string, v: string) { this.h[n] = v; }, end(c?: string) { this.body = c ?? ""; } } });
    const a = mk();
    const reqA = { method: "GET", url: "/x", originalUrl: "/api/x", headers: a.headers } as Parameters<ReturnType<typeof expressGuard>>[0];
    let called = 0;
    expressGuard(allow)(reqA, a.res, () => called++);
    await new Promise((r) => setTimeout(r, 5));
    expect(called).toBe(1);
    expect(reqA.authvex).toEqual(claims);
    const d = mk();
    const reqD = { method: "GET", url: "/x", headers: d.headers } as Parameters<ReturnType<typeof expressGuard>>[0];
    let calledD = 0;
    expressGuard(deny)(reqD, d.res, () => calledD++);
    await new Promise((r) => setTimeout(r, 5));
    expect(calledD).toBe(0);
    expect(d.res.statusCode).toBe(401);
    expect(d.res.h["www-authenticate"]).toContain("DPoP");
    expect(JSON.parse(d.res.body)).toEqual({ error: "expired", message: "the session token has expired" });
    // an error inside the guard goes to next(err), never to a hang
    let seen: unknown;
    expressGuard({ authenticate: async () => { throw new Error("boom"); } })(reqA, a.res, (e) => (seen = e));
    await new Promise((r) => setTimeout(r, 5));
    expect((seen as Error).message).toBe("boom");
  });

  it("fastify: decorates the request, or replies and stops", async () => {
    const reply = { status: 0, headers: {} as Record<string, string>, payload: undefined as unknown, code(s: number) { this.status = s; return this; }, header(n: string, v: string) { this.headers[n] = v; return this; }, send(p?: unknown) { this.payload = p; return this; } };
    const r1: { method: string; url: string; headers: Record<string, string>; authvex?: SessionClaims } = { method: "GET", url: "/x", headers: {} };
    expect(await fastifyGuard(allow)(r1, reply)).toBeUndefined();
    expect(r1.authvex).toEqual(claims);
    await fastifyGuard(deny)({ method: "GET", url: "/x", headers: {} }, reply);
    expect(reply.status).toBe(401);
    expect(reply.headers["www-authenticate"]).toContain("DPoP");
    expect(reply.payload).toEqual({ error: "expired", message: "the session token has expired" });
  });

  it("hono: sets the claims and continues, or returns the 401 response", async () => {
    let set: unknown;
    let nexted = 0;
    const c = { req: { method: "GET", url: `${API}/x`, header: () => undefined }, set: (_k: "authvex", v: SessionClaims) => (set = v), json: (b: unknown, s?: number, h?: Record<string, string>) => Response.json(b, { status: s ?? 200, ...(h ? { headers: h } : {}) }) };
    await honoGuard(allow)(c, async () => void nexted++);
    expect(set).toEqual(claims);
    expect(nexted).toBe(1);
    const res = (await honoGuard(deny)(c, async () => void nexted++)) as Response;
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("DPoP");
    expect(nexted).toBe(1);
  });

  it("fetch handlers (Next.js route handlers, Workers): pass claims to the handler, or return the failure", async () => {
    const handler = withAuthvex(allow, async (_req, c) => Response.json({ sub: c.sub }));
    expect(await (await handler(new Request(`${API}/x`))).json()).toEqual({ sub: "usr_a" });
    const refused = await withAuthvex(deny, async () => Response.json({ never: true }))(new Request(`${API}/x`));
    expect(refused.status).toBe(401);
    expect(await refused.json()).toEqual({ error: "expired", message: "the session token has expired" });
  });
});
