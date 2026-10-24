import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fc from "fast-check";
import { startHarness, type Harness } from "./helpers";
import { parsePgUrl } from "../src/pg";
import { ConfigSchema } from "./testExports";

const runs = Number(process.env["AUTHVEX_FUZZ_RUNS"] ?? 150);
const LIN = "linear_ops_workspace";

const POST = ["/api/auth/login", "/api/auth/rotate", "/api/auth/dpop-verify", "/api/auth/passkey/challenge", "/api/auth/impersonate", "/api/verify", "/api/evaluate", "/api/keys", "/api/users/totp", "/api/users/passkeys", "/api/users/passkeys/challenge", "/api/auth/signup", "/api/auth/verify-email", "/api/auth/verify-email/resend", "/api/auth/password-reset/request", "/api/auth/password-reset/confirm", "/api/auth/magic-link/request", "/api/auth/magic-link/consume", "/api/auth/enrol/request", "/api/auth/enrol/consume", "/api/me/passkeys/challenge", "/api/me/passkeys", "/api/oidc/complete", `/oidc/${LIN}/token`, `/oidc/${LIN}/userinfo`];
const GET = ["/api/me/passkeys", "/api/health", "/api/workspace", "/api/ledger", "/api/ledger/verify", "/.well-known/jwks.json", "/api/oidc/request", `/oidc/${LIN}/authorize`, `/oidc/${LIN}/userinfo`, `/oidc/${LIN}/end_session`, `/oidc/${LIN}/.well-known/openid-configuration`, "/", "/nope"];

const json: fc.Arbitrary<unknown> = fc.letrec((tie) => ({
  v: fc.oneof({ maxDepth: 4 }, fc.string(), fc.integer(), fc.double(), fc.boolean(), fc.constant(null), fc.array(tie("v") as fc.Arbitrary<unknown>, { maxLength: 4 }), fc.dictionary(fc.constantFrom("tenantId", "email", "password", "refreshToken", "token", "proof", "code", "userId", "scope", "role", "challenge", "__proto__", "constructor", "a", ""), tie("v") as fc.Arbitrary<unknown>, { maxKeys: 6 })),
})).v;
const rawBody = fc.oneof(json.map((v) => JSON.stringify(v)), fc.string(), fc.constant(""), fc.constant("{"), fc.constant("[[[[[[[[[[[[[[[[[[[[[[[[[[[[["), fc.constant('{"__proto__":{"admin":true}}'), fc.string({ minLength: 1000, maxLength: 3000 }));
const header = fc.oneof(fc.constant(undefined), fc.string({ maxLength: 60 }).map((s) => s.replace(/[^\x20-\x7e]/g, "")), fc.constantFrom("Bearer", "Bearer x", "DPoP x", "Basic !!!", "Basic Zm9vOmJhcg=="));

/** 501 is the deliberate "that feature is not configured" answer (no mail transport); anything else from 500 up is a fault. */
const serverFault = (status: number): boolean => status >= 500 && status !== 501;

let h: Harness;
beforeAll(async () => {
  h = await startHarness();
});
afterAll(async () => h?.close());

const hit = async (method: string, path: string, body: string | undefined, auth: string | undefined, dpop: string | undefined, admin: boolean): Promise<number> => {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (auth !== undefined) headers["authorization"] = auth;
  if (admin) headers["authorization"] = `Bearer ${h.admin}`;
  if (dpop !== undefined) headers["dpop"] = dpop;
  const r = await fetch(`${h.base}${path}`, { method, headers, ...(body !== undefined && method !== "GET" ? { body } : {}) });
  await r.arrayBuffer();
  return r.status;
};

describe("the HTTP server survives hostile input", () => {
  it("never answers 5xx to a POST with arbitrary body, auth and DPoP headers (with and without the admin token)", async () => {
    await fc.assert(fc.asyncProperty(fc.constantFrom(...POST), rawBody, header, header, fc.boolean(), async (path, body, auth, dpop, admin) => {
      const s = await hit("POST", path, body, auth, dpop, admin);
      expect(serverFault(s), `${path} ${s} ${body.slice(0, 80)}`).toBe(false);
    }), { numRuns: runs * 2 });
  }, 300_000);

  it("never answers 5xx to a GET with an arbitrary query string", async () => {
    await fc.assert(fc.asyncProperty(fc.constantFrom(...GET), fc.dictionary(fc.constantFrom("state", "nonce", "scope", "client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "request", "limit", "id_token_hint", "post_logout_redirect_uri", "x"), fc.string({ maxLength: 80 }), { maxKeys: 8 }), header, fc.boolean(), async (path, query, auth, admin) => {
      const qs = new URLSearchParams(query).toString();
      const s = await hit("GET", `${path}${qs ? `?${qs}` : ""}`, undefined, auth, undefined, admin);
      expect(serverFault(s), `${path}?${qs.slice(0, 80)} ${s}`).toBe(false);
    }), { numRuns: runs * 2 });
  }, 300_000);

  it("handles odd paths, methods and encodings without a 5xx", async () => {
    for (const p of ["/%00", "/%ff", "/api/%2e%2e/%2e%2e/etc/passwd", "/api/auth/login/../../health", `/oidc/%00/token`, `/oidc/${"a".repeat(5000)}/token`, "//api//health", "/api/auth/login?" + "a=1&".repeat(3000)]) {
      for (const m of ["GET", "POST", "DELETE", "PUT", "OPTIONS", "PATCH"]) {
        const s = await hit(m, p, m === "GET" ? undefined : "{}", undefined, undefined, false).catch(() => 0);
        expect(serverFault(s), `${m} ${p.slice(0, 40)} ${s}`).toBe(false);
      }
    }
  });

  it("refuses an oversized body with 413 and keeps serving", async () => {
    const r = await fetch(`${h.base}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: "x".repeat(200_000) });
    expect(r.status).toBe(413);
    expect((await fetch(`${h.base}/api/health`)).status).toBe(200);
  });

  it("does not let a prototype-pollution body change anything", async () => {
    await hit("POST", "/api/auth/login", '{"__proto__":{"isAdmin":true},"constructor":{"prototype":{"isAdmin":true}}}', undefined, undefined, false);
    expect(({} as Record<string, unknown>)["isAdmin"]).toBeUndefined();
    expect((await h.call("GET", "/api/workspace", undefined, { token: "" })).status).toBe(401);
  });

  it("is still healthy and its ledger intact after all of that", async () => {
    expect((await fetch(`${h.base}/api/health`)).status).toBe(200);
    const v = await h.call("GET", "/api/ledger/verify");
    expect(v.body["ok"]).toBe(true);
  });
});

describe("config and connection parsing never throw anything but a clear error", () => {
  it("connection URLs", () => {
    fc.assert(fc.property(fc.string(), (s) => {
      try { parsePgUrl(s); } catch (e) { expect(e).toBeInstanceOf(Error); }
    }), { numRuns: runs * 2 });
  });
  it("config files", () => {
    fc.assert(fc.property(json, (v) => {
      const r = ConfigSchema.safeParse(v);
      expect(typeof r.success).toBe("boolean");
    }), { numRuns: runs * 2 });
  });
});
