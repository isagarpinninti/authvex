/**
 * The framework adapters against the real frameworks (Express 5, Fastify 5, Hono 4 on Node) and a fetch-style handler, protecting an
 * API with sessions issued by a real Authvex server. The frameworks are root dev dependencies only; nothing here ships.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import Fastify from "fastify";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDpopProof, createGuard, expressGuard, fastifyGuard, honoGuard, withAuthvex, type Guard, type SessionClaims } from "../packages/core/dist/index.js";
import { ConfigSchema, DEMO_PASSWORD, FileKeyring, Ledger, createAuthvexServer, loadWorkspace, openStore, runInit, type AuthvexServer } from "../packages/cli/dist/index.js";

const LIN = "linear_ops_workspace";
let dir: string;
let authvex: AuthvexServer;
let issuer: string;
const closers: Array<() => Promise<void>> = [];

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "authvex-mw-"));
  await runInit(dir);
  const ws = loadWorkspace(dir);
  const cfg = ConfigSchema.parse({ ...ws.config, port: 0, ipRequestsPerMinute: 100_000, store: { kind: "memory" } });
  authvex = createAuthvexServer({ workspace: { ...ws, config: cfg }, keyring: await FileKeyring.open(dir), store: await openStore(cfg, dir), ledger: new Ledger(join(dir, ".authvex", "ledger.jsonl")) });
  issuer = `http://127.0.0.1:${(await authvex.listen()).port}`;
});
afterAll(async () => {
  for (const c of closers) await c();
  await authvex.close();
  rmSync(dir, { recursive: true, force: true });
});

interface Device { privateKey: CryptoKey; publicKeyJwk: JsonWebKey }
async function device(): Promise<Device> {
  const p = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const j = await crypto.subtle.exportKey("jwk", p.publicKey);
  return { privateKey: p.privateKey, publicKeyJwk: { kty: j.kty, crv: j.crv, x: j.x, y: j.y } };
}
async function signIn(dev: Device): Promise<{ sessionToken: string; refreshToken: string }> {
  const url = `${issuer}/api/auth/login`;
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json", dpop: await createDpopProof({ ...dev, method: "POST", url }) }, body: JSON.stringify({ tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO_PASSWORD }) });
  return (await r.json()) as { sessionToken: string; refreshToken: string };
}
const authed = async (dev: Device, token: string, method: string, url: string): Promise<Record<string, string>> => ({
  authorization: `DPoP ${token}`, dpop: await createDpopProof({ ...dev, method, url, sessionToken: token }),
});

type Starter = (guard: Guard) => Promise<{ base: string }>;
const listen = (s: Server): Promise<string> => new Promise((r) => s.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)));

const frameworks: Record<string, Starter> = {
  express: async (guard) => {
    const app = express();
    app.use("/api", expressGuard(guard));
    app.get("/api/me", (req, res) => void res.json({ sub: (req as unknown as { authvex: SessionClaims }).authvex.sub }));
    app.post("/api/echo", (req, res) => void res.json({ sub: (req as unknown as { authvex: SessionClaims }).authvex.sub }));
    app.get("/public", (_req, res) => void res.json({ open: true }));
    const server = createServer(app);
    closers.push(() => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))));
    return { base: await listen(server) };
  },
  fastify: async (guard) => {
    const app = Fastify();
    app.register(async (scope) => {
      scope.addHook("onRequest", fastifyGuard(guard));
      scope.get("/api/me", async (req) => ({ sub: (req as unknown as { authvex: SessionClaims }).authvex.sub }));
      scope.post("/api/echo", async (req) => ({ sub: (req as unknown as { authvex: SessionClaims }).authvex.sub }));
    });
    app.get("/public", async () => ({ open: true }));
    await app.listen({ port: 0, host: "127.0.0.1" });
    closers.push(() => app.close());
    return { base: `http://127.0.0.1:${(app.server.address() as AddressInfo).port}` };
  },
  hono: async (guard) => {
    const app = new Hono<{ Variables: { authvex: SessionClaims } }>();
    app.use("/api/*", honoGuard(guard));
    app.get("/api/me", (c) => c.json({ sub: c.get("authvex").sub }));
    app.post("/api/echo", (c) => c.json({ sub: c.get("authvex").sub }));
    app.get("/public", (c) => c.json({ open: true }));
    const server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }) as unknown as Server;
    await new Promise((r) => server.once("listening", r));
    closers.push(() => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))));
    return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
  },
  "fetch handlers (Next.js route handlers, Workers)": async (guard) => {
    const me = withAuthvex(guard, async (_req, c) => Response.json({ sub: c.sub }));
    const server = createServer((req, res) => {
      void (async () => {
        const url = `http://${req.headers.host}${req.url}`;
        if (req.url === "/public") return void res.writeHead(200, { "content-type": "application/json" }).end('{"open":true}');
        const body = req.method === "POST" ? await new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); }) : undefined;
        const headers = new Headers();
        for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
        const out = await me(new Request(url, { method: req.method ?? "GET", headers, ...(body !== undefined ? { body } : {}) }));
        res.writeHead(out.status, Object.fromEntries(out.headers)).end(await out.text());
      })();
    });
    closers.push(() => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))));
    return { base: await listen(server) };
  },
};

for (const [name, start] of Object.entries(frameworks)) {
  describe(`${name} guarded by Authvex`, () => {
    it("lets the owner in, keeps strangers, thieves and replays out, and leaves public routes alone", async () => {
      // Each server learns its own address after it starts, so the guard reads the Host header (a real proxy would set baseUrl).
      const guard = createGuard({ issuer });
      const { base } = await start(guard);
      const dev = await device();
      const s = await signIn(dev);

      expect((await fetch(`${base}/public`)).status).toBe(200);
      expect((await fetch(`${base}/api/me`)).status).toBe(401);
      const noAuth = await fetch(`${base}/api/me`);
      expect(noAuth.headers.get("www-authenticate")).toMatch(/^DPoP /);

      const url = `${base}/api/me`;
      const h = await authed(dev, s.sessionToken, "GET", url);
      const ok = await fetch(url, { headers: h });
      expect(ok.status).toBe(200);
      expect(await ok.json()).toEqual({ sub: "usr_margaret" });

      // the same proof again: replay
      expect((await fetch(url, { headers: h })).status).toBe(401);
      // the token alone: theft without the device key
      expect((await fetch(url, { headers: { authorization: `DPoP ${s.sessionToken}` } })).status).toBe(401);
      expect((await fetch(url, { headers: { authorization: `Bearer ${s.sessionToken}` } })).status).toBe(401);
      // a proof from another device
      const thief = await device();
      expect((await fetch(url, { headers: await authed(thief, s.sessionToken, "GET", url) })).status).toBe(401);
      // a proof made for another method or path
      expect((await fetch(url, { headers: await authed(dev, s.sessionToken, "POST", url) })).status).toBe(401);
      expect((await fetch(url, { headers: await authed(dev, s.sessionToken, "GET", `${base}/api/other`) })).status).toBe(401);
      // POST works with its own proof
      const post = `${base}/api/echo`;
      const p = await fetch(post, { method: "POST", headers: { ...(await authed(dev, s.sessionToken, "POST", post)), "content-type": "application/json" }, body: "{}" });
      expect(p.status).toBe(200);
    });

    it("sees a revoked session at once in introspect mode, while local mode waits for the token to expire", async () => {
      const local = await start(createGuard({ issuer }));
      const remote = await start(createGuard({ issuer, mode: "introspect" }));
      const dev = await device();
      const s = await signIn(dev);
      const call = async (b: string): Promise<number> => {
        const url = `${b}/api/me`;
        return (await fetch(url, { headers: await authed(dev, s.sessionToken, "GET", url) })).status;
      };
      expect(await call(local.base)).toBe(200);
      expect(await call(remote.base)).toBe(200);

      // The refresh token is rotated, then the old one is replayed: Authvex treats that as theft and revokes the whole session.
      const rotateUrl = `${issuer}/api/auth/rotate`;
      const rot = await fetch(rotateUrl, { method: "POST", headers: { "content-type": "application/json", dpop: await createDpopProof({ ...dev, method: "POST", url: rotateUrl }) }, body: JSON.stringify({ refreshToken: s.refreshToken }) });
      expect(rot.status).toBe(200);
      const reuse = await fetch(rotateUrl, { method: "POST", headers: { "content-type": "application/json", dpop: await createDpopProof({ ...dev, method: "POST", url: rotateUrl }) }, body: JSON.stringify({ refreshToken: s.refreshToken }) });
      expect(reuse.status).toBe(409);

      expect(await call(remote.base)).toBe(401);
      expect(await call(local.base)).toBe(200); // documented trade-off: the access token is still valid until it expires
    });

    it("enforces a permission through the tenant's roles in introspect mode", async () => {
      const allowed = await start(createGuard({ issuer, mode: "introspect", permission: "issues:read" }));
      const denied = await start(createGuard({ issuer, mode: "introspect", permission: "keys:manage" }));
      const dev = await device();
      const s = await signIn(dev);
      const hit = async (b: string): Promise<number> => {
        const url = `${b}/api/me`;
        return (await fetch(url, { headers: await authed(dev, s.sessionToken, "GET", url) })).status;
      };
      expect(await hit(allowed.base)).toBe(200);
      expect(await hit(denied.base)).toBe(403);
    });
  });
}
