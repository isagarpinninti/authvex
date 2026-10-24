import type { webcrypto } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOKEN_PREFIX, computeTotpCode, createDpopProof, createSoftwareAuthenticator, signToken, type SoftwareAuthenticator } from "@authvex/core";
import type { Mailer } from "../src/mail";
import { ConfigSchema, FileKeyring, Ledger, createAuthvexServer, loadWorkspace, openStore, runInit_, type AuthvexServer } from "./testExports";

export interface Harness {
  dir: string;
  /** The running server; replaced by `restart`. */
  server: AuthvexServer;
  keyring: FileKeyring;
  /** Stops the server and starts a new one on the same workspace and state, like a process restart. */
  restart(): Promise<void>;
  base: string;
  admin: string;
  ledgerPath: string;
  close(): Promise<void>;
  /** A JSON request. `dpop` signs a proof for it with the given key. */
  call(method: string, path: string, body?: unknown, opts?: { token?: string; dpop?: DeviceKey; headers?: Record<string, string> }): Promise<{ status: number; body: Body }>;
  totp(userId: string): Promise<string>;
  users(): Array<{ id: string; email: string; totpSecretB32?: string; passkeys: Array<{ signCount: number }> }>;
}

/** The response fields the tests read, typed loosely: a missing field fails the assertion that reads it. */
export interface Body {
  status: string; reason: string; message: string; error: string; valid: boolean; bound: boolean; token: string; key: string; sessionToken: string; refreshToken: string; familyId: string;
  generation: number; challengeId: string; challenge: string; rpId: string; allowCredentials: string[]; available: string[]; secretB32: string; sessionsRevoked: number; kind: string; ok: boolean; severed: number; attestation: string;
  report: { level: string; score: number; travel?: { speedKmh: number }; checks: Array<{ code: string; status: string; message: string }> };
  claims: { sub: string; exp: number; cnf?: { jkt: string }; fam: string; gen: number; reason: string; readOnly: boolean; actorAdminId: string; targetUserId: string; tid: string };
  key_: unknown; record: { id: string; keyPrefix: string; scopes: string[] }; keys: Array<{ id: string; revokedAtIso?: string }>; entries: Array<{ type: string; subject?: string; actor?: string; detail: Record<string, unknown> }>;
  entries_: number; head: string; brokenAt: number; secondsLeft: number; passkey: { credentialId: string }; tenant: { roles: Array<{ id: string; permissions: string[] }> }; matrix: { permissions: string[] };
  tenants: Array<{ id: string; matrix: { permissions: string[] } }>; users: Array<{ id: string; hasTotp: boolean; passkeys: unknown[] }>; families: Array<{ familyId: string; status: string; generation: number; bound: boolean }>; issuer: { kid: string };
}

type JsonWebKey = webcrypto.JsonWebKey;

export interface DeviceKey {
  privateKey: CryptoKey;
  publicKeyJwk: JsonWebKey;
}

export async function deviceKey(): Promise<DeviceKey> {
  const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey, publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}

export interface HarnessOptions {
  /** Use this clock for the server (tokens, expiry, windows). */
  now?: () => number;
  /** Reuse an existing workspace instead of creating one (it is not deleted on close). */
  dir?: string;
  /** Gives the server a mailer (and a `mail` config block), so the email flows are on. */
  mailer?: Mailer;
  /** Receives the server's log lines. */
  log?: (line: string) => void;
}

export async function startHarness(config: Record<string, unknown> = {}, opts: HarnessOptions = {}): Promise<Harness> {
  const dir = opts.dir ?? mkdtempSync(join(tmpdir(), "authvex-"));
  if (!opts.dir) await runInit_(dir);
  const ledgerPath = join(dir, ".authvex", "ledger.jsonl");
  // A Postgres store gets its own schema per harness (the same one across restarts) in the test database.
  const store = config["store"] as { kind?: string } | undefined;
  if (store?.kind === "postgres") config = { ...config, store: { urlEnv: "AUTHVEX_TEST_DATABASE_URL", schema: `h_${Math.random().toString(36).slice(2, 10)}`, ...store } };
  const keyring = await FileKeyring.open(dir);
  const boot = async (port = 0): Promise<{ server: AuthvexServer; base: string; port: number }> => {
    const ws = loadWorkspace(dir);
    const cfg = ConfigSchema.parse({ ...ws.config, port, ipRequestsPerMinute: 100_000, ...(opts.mailer ? { mail: { driver: "console", from: "noreply@authvex.test", linkBase: "https://app.test/auth" } } : {}), ...config });
    const server = createAuthvexServer({ workspace: { ...ws, config: cfg }, keyring, store: await openStore(cfg, dir), mailer: opts.mailer ?? null, ...(opts.log ? { log: opts.log } : {}), ledger: new Ledger(ledgerPath), version: "test", ...(opts.now ? { now: opts.now } : {}) });
    const addr = await server.listen();
    return { server, base: `http://127.0.0.1:${addr.port}`, port: addr.port };
  };
  let cur = await boot();
  const h: Harness = {
    dir, keyring, ledgerPath,
    get server() { return cur.server; },
    get base() { return cur.base; },
    get admin() { return cur.server.adminToken; },
    restart: async () => {
      const { port } = cur;
      await cur.server.close();
      cur = await boot(port); // same address, so a DPoP proof's URL still matches
    },
    call: async (method, path, body, o = {}) => {
      const headers: Record<string, string> = { "content-type": "application/json", ...(o.headers ?? {}) };
      // A fresh admin token each call, from the current signing key, so a rotated or revoked key or an advanced clock does not lock the test out.
      const at = opts.now ? opts.now() : Date.now();
      const active = (await keyring.get(at)).issuer;
      const token = o.token ?? (await signToken(TOKEN_PREFIX.admin, { v: 1, typ: "admin", sub: "test", iat: Math.floor(at / 1000), exp: Math.floor(at / 1000) + 600 }, active.privateKey, active.kid));
      if (token) headers["authorization"] = `Bearer ${token}`;
      if (o.dpop) headers["dpop"] = await createDpopProof({ ...o.dpop, method, url: `${cur.base}${path}`, ...(opts.now ? { nowMs: opts.now() } : {}) });
      const r = await fetch(`${cur.base}${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
      return { status: r.status, body: (await r.json().catch(() => ({}))) as Body };
    },
    users: () => JSON.parse(readFileSync(join(dir, "users.json"), "utf8")) as ReturnType<Harness["users"]>,
    totp: async (id) => computeTotpCode((JSON.parse(readFileSync(join(dir, "users.json"), "utf8")) as Array<{ id: string; totpSecretB32?: string }>).find((u) => u.id === id)?.totpSecretB32 as string, opts.now ? { nowMs: opts.now() } : {}),
    close: async () => {
      await cur.server.close();
      if (!opts.dir) rmSync(dir, { recursive: true, force: true });
    },
  };
  return h;
}

export const DEMO = "demo-passphrase-1";
export { createSoftwareAuthenticator, type SoftwareAuthenticator };
