import { monitorEventLoopDelay } from "node:perf_hooks";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync, readFileSync, statSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import type { webcrypto } from "node:crypto";

type JsonWebKey = webcrypto.JsonWebKey;
import { z } from "zod";
import {
  ApiKeyRateLimiter, MemoryStore, NO_PASSWORD, constantTimeEqualStr, parseCertificate, pemToDer, TOKEN_PREFIX, UserRecordSchema, TenantPolicySchema, buildPermissionMatrix, buildOtpAuthUri, checkWorkspace, evaluateAuthRiskGate, evaluatePermission, generateChallenge,
  checkPasswordPolicy, generateTotpSecret, hex, issueNextAccessToken, issueSessionBundle, mintImpersonationSeal, mintScopedApiKey, peekTokenPayload, revokeFamily, rotateRefreshTokenFamily, sha256, signToken, storeReplayCache, tokenKind,
  verifyDpopProof, verifyDpopSessionRequest, verifyImpersonationSeal, verifyScopedApiKey, verifySignedToken, verifyTotpCode, verifyWebAuthnAssertion, verifyWebAuthnRegistration,
  type AsnKind, type GeoPoint, type PasskeyRecord, type SessionClaims, type Store, type RiskContext, type RiskReport, type SessionFamily, type TenantPolicy, type UserRecord, type ApiKeyRecord,
} from "@authvex/core";
import { readKeys, writeJsonAtomic, writeKeys, keysFile, type Workspace } from "./config";
import { HttpError } from "./http";
import { createPasswordHasher } from "./passwords";
import { Registry, routeLabel } from "./metrics";
import { createOidcHandler } from "./oidc";
import type { KeyringSource } from "./keyring";
import type { Mailer } from "./mail";
import { verifyLedger, type Ledger } from "./ledger";
import { EvaluateError, asnSchema, evaluateScenario, geoSchema, isAdminUser } from "./evaluate";

export interface AuthvexServerOptions {
  workspace: Workspace;
  /** The issuer's signing keys: the active one signs, retiring ones still verify. */
  keyring: KeyringSource;
  /** Where sessions, the replay cache and other state live. Default: in memory, lost on restart. */
  store?: Store;
  /** Sends sign-up, reset and magic-link emails. Without one those endpoints answer 501. */
  mailer?: Mailer | null;
  ledger?: Ledger | null;
  studioDir?: string;
  version?: string;
  /** Receives log lines (plain text, or JSON objects when `logging.format` is `json`). */
  log?: (line: string) => void;
  now?: () => number;
  /** Where `metrics.tokenEnv` is read from. Default: `process.env`. */
  env?: NodeJS.ProcessEnv;
}

export interface AuthvexServer {
  readonly http: Server;
  /** Lets the Studio and the admin API in. Valid 24 hours. */
  readonly adminToken: string;
  readonly ledger: Ledger | null;
  listen(): Promise<{ port: number; host: string }>;
  close(): Promise<void>;
  url(): string;
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8", ".woff2": "font/woff2", ".map": "application/json",
};


const loginSchema = z
  .object({
    tenantId: z.string().max(60),
    email: z.string().email().max(200),
    password: z.string().max(1024).optional(),
    totp: z.string().max(12).optional(),
    passkey: z.object({ challengeId: z.string(), credentialId: z.string(), clientDataJSON: z.string(), authenticatorData: z.string(), signature: z.string() }).strict().optional(),
    geo: geoSchema.optional(),
    asn: asnSchema.optional(),
    deviceFingerprintDrift: z.boolean().optional(),
    deviceName: z.string().max(80).optional(),
  })
  .strict();

export function createAuthvexServer(options: AuthvexServerOptions): AuthvexServer {
  const ws = options.workspace;
  const cfg = ws.config;
  const emit = (level: "info" | "warn" | "error", msg: string, fields: Record<string, unknown> = {}): void => {
    if (!options.log) return;
    options.log(
      cfg.logging.format === "json"
        ? JSON.stringify({ ts: new Date(options.now ? options.now() : Date.now()).toISOString(), level, msg, ...fields })
        : `${level === "info" ? "" : `${level}: `}${msg}${Object.entries(fields).map(([k, v]) => ` ${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join("")}`,
    );
  };
  const nowMs = options.now ?? Date.now;
  const keyring = options.keyring;
  const store: Store = options.store ?? new MemoryStore();
  /** The signing key and the verifying key set as of now; re-read when the keyring file changes. */
  const K = (): ReturnType<KeyringSource["get"]> => keyring.get(nowMs());
  const ledger = options.ledger === undefined ? null : options.ledger;
  const startedAt = nowMs();

  // Root certificates passkey attestation must chain to (a PEM file next to the config). A bad file stops the server at start-up.
  const attestationAnchors = cfg.attestation.trustAnchors ? pemToDer(readFileSync(resolve(ws.root, cfg.attestation.trustAnchors), "utf8")) : [];
  if (cfg.attestation.trustAnchors && attestationAnchors.length === 0) throw new Error(`attestation.trustAnchors: no certificates found in ${cfg.attestation.trustAnchors}`);
  for (const a of attestationAnchors) parseCertificate(a);
  const hasher = createPasswordHasher(cfg.passwordHashing);
  const tenants = new Map<string, TenantPolicy>(ws.tenants.map((t) => [t.id, t]));
  const users = new Map<string, UserRecord>(ws.users.map((u) => [u.id, u]));
  const ipHits = new Map<string, number[]>();
  const replay = storeReplayCache(store);
  const limiter = new ApiKeyRateLimiter();
  let keysCache: { mtime: number; keys: ApiKeyRecord[] } = { mtime: -1, keys: [] };

  const publicBase = (): string => cfg.publicUrl?.replace(/\/$/, "") ?? server.url();
  const keys = (): ApiKeyRecord[] => {
    const f = keysFile(ws.root);
    const m = existsSync(f) ? statSync(f).mtimeMs : 0;
    if (m !== keysCache.mtime) keysCache = { mtime: m, keys: readKeys(ws.root) };
    return keysCache.keys;
  };
  const audit = (type: string, info: { tenantId?: string; actor?: string; subject?: string; detail?: Record<string, unknown> } = {}): void => {
    mAudit.inc({ type });
    ledger?.append({ type, ts: nowMs(), ...info });
  };
  const saveUsers = (): void => writeJsonAtomic(ws.usersFile, [...users.values()]);

  /* ───────── metrics ───────── */

  const env = options.env ?? process.env;
  const metricsToken = cfg.metrics.enabled ? env[cfg.metrics.tokenEnv] : undefined;
  if (cfg.metrics.enabled && (!metricsToken || metricsToken.length < 16)) throw new Error(`metrics.enabled needs a bearer token of at least 16 characters in the environment variable ${cfg.metrics.tokenEnv}`);
  const registry = new Registry();
  const mRequests = registry.counter("authvex_http_requests_total", "HTTP requests by method, route and status.");
  const mDuration = registry.histogram("authvex_http_request_duration_seconds", "HTTP request duration by route.", [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5]);
  const mAudit = registry.counter("authvex_audit_events_total", "Audit events by type (sign-ins, blocks, rotations, reuse, key changes, ...).");
  const loopDelay = monitorEventLoopDelay({ resolution: 20 });
  loopDelay.enable();
  registry.gauge("authvex_info", "Build information.", () => [{ labels: { version: options.version ?? "0.0.0", store: store.kind }, value: 1 }]);
  registry.gauge("authvex_uptime_seconds", "Seconds since the server started.", () => [{ value: (nowMs() - startedAt) / 1000 }]);
  registry.gauge("authvex_process_memory_bytes", "Process memory.", () => [{ labels: { kind: "rss" }, value: process.memoryUsage().rss }, { labels: { kind: "heap_used" }, value: process.memoryUsage().heapUsed }]);
  registry.gauge("authvex_event_loop_delay_seconds", "Event loop delay (p99 since the last scrape).", () => {
    const v = loopDelay.percentile(99) / 1e9;
    loopDelay.reset();
    return [{ value: Number.isFinite(v) ? v : 0 }];
  });
  registry.gauge("authvex_issuer_keys", "Issuer signing keys by status, and the age of the active one.", async () => {
    const summary = (await K()).summary;
    const by = new Map<string, number>();
    for (const k of summary) by.set(k.status, (by.get(k.status) ?? 0) + 1);
    const active = summary.find((k) => k.status === "active");
    return [...by].map(([status, n]) => ({ labels: { status }, value: n })).concat(active ? [{ labels: { status: "active_age_seconds" }, value: Math.max(0, (nowMs() - Date.parse(active.createdAtIso)) / 1000) }] : []);
  });
  const KNOWN_ROUTES = new Set([
    "/api/health", "/.well-known/jwks.json", "/api/auth/login", "/api/auth/rotate", "/api/auth/dpop-verify", "/api/auth/passkey/challenge", "/api/auth/impersonate", "/api/verify", "/api/evaluate",
    "/api/keys", "/api/workspace", "/api/me/passkeys", "/api/me/passkeys/challenge", "/api/ledger", "/api/ledger/verify", "/api/users/totp", "/api/users/passkeys", "/api/users/passkeys/challenge", "/api/oidc/request", "/api/oidc/complete", "/metrics",
  ]);
  const routeOf = (req: IncomingMessage): string => {
    const path = (req.url ?? "/").split("?")[0] ?? "/";
    return routeLabel(req.method ?? "GET", path, KNOWN_ROUTES);
  };

  /* ───────── helpers ───────── */

  const cors = (req: IncomingMessage): Record<string, string> => {
    const origin = req.headers.origin;
    if (!origin) return {};
    if (cfg.origins.length > 0 && !cfg.origins.includes(origin)) return {};
    return { "access-control-allow-origin": origin, vary: "Origin", "access-control-allow-headers": "authorization, content-type, dpop", "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS" };
  };
  const send = (req: IncomingMessage, res: ServerResponse, status: number, body: unknown): void => {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...cors(req) });
    res.end(JSON.stringify(body));
  };
  const readRaw = (req: IncomingMessage): Promise<string> =>
    new Promise((resolveBody, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let failed = false;
      req.on("data", (c: Buffer) => {
        if (failed) return;
        size += c.length;
        if (size > cfg.maxBodyBytes) {
          failed = true;
          reject(new HttpError(413, "request body too large"));
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => {
        if (!failed) resolveBody(Buffer.concat(chunks).toString("utf8"));
      });
      req.on("error", reject);
    });
  const readBody = async (req: IncomingMessage): Promise<unknown> => {
    const raw = await readRaw(req);
    if (raw.length === 0) return {};
    try {
      return JSON.parse(raw) as unknown;
    } catch {
      throw new HttpError(400, "body is not valid JSON");
    }
  };
  const parse = <T extends z.ZodType>(schema: T, value: unknown): z.infer<T> => {
    const r = schema.safeParse(value);
    if (!r.success) throw new HttpError(400, r.error.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; "));
    return r.data;
  };
  const requireAdmin = async (req: IncomingMessage): Promise<void> => {
    const h = req.headers.authorization ?? "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    const r = token.startsWith(TOKEN_PREFIX.admin) ? await verifySignedToken<{ typ?: string; exp?: number }>(TOKEN_PREFIX.admin, token, (await K()).keys) : null;
    if (!r?.ok || r.payload.typ !== "admin" || typeof r.payload.exp !== "number" || r.payload.exp * 1000 <= nowMs()) throw new HttpError(401, "an admin token is required (Authorization: Bearer ath_adm_…)");
  };
  const tenantOr404 = (id: string): TenantPolicy => {
    const t = tenants.get(id);
    if (!t) throw new HttpError(404, `no tenant "${id}"`);
    return t;
  };
  const userOr404 = (id: string): UserRecord => {
    const u = users.get(id);
    if (!u) throw new HttpError(404, `no user "${id}"`);
    return u;
  };
  const clientIp = (req: IncomingMessage): string => req.socket.remoteAddress ?? "unknown";
  const slide = (map: Map<string, number[]>, key: string, windowMs: number): number[] => {
    const now = nowMs();
    const list = (map.get(key) ?? []).filter((t) => now - t < windowMs);
    map.set(key, list);
    return list;
  };
  
  const familyView = (f: SessionFamily) => ({
    familyId: f.familyId, userId: f.userId, tenantId: f.tenantId, generation: f.currentGeneration, consumed: f.consumedRefreshTokenHashes.length, status: f.status, bound: f.boundJkt !== undefined,
    boundJkt: f.boundJkt, createdAtIso: f.createdAtIso, lastRotatedAtIso: f.lastRotatedAtIso, expiresAtIso: f.expiresAtIso, revokedAtIso: f.revokedAtIso, device: f.device,
  });
  const publicUser = (u: UserRecord) => ({
    id: u.id, email: u.email, name: u.name, emailVerified: u.emailVerifiedAt !== undefined, hasPassword: u.passwordHash !== undefined, hasTotp: u.totpSecretB32 !== undefined, orgMemberships: u.orgMemberships, lastLoginGeo: u.lastLoginGeo,
    passkeys: u.passkeys.map((p) => ({ credentialId: p.credentialId, deviceName: p.deviceName, signCount: p.signCount, createdAtIso: p.createdAtIso })),
  });
  const keyView = (k: ApiKeyRecord) => ({ id: k.id, name: k.name, tenantId: k.tenantId, keyPrefix: k.keyPrefix, scopes: k.scopes, rateLimitPerMin: k.rateLimitPerMin, createdAtIso: k.createdAtIso, expiresAtIso: k.expiresAtIso, revokedAtIso: k.revokedAtIso });

  const adminTokenPromise = K().then((k) => signToken(TOKEN_PREFIX.admin, { v: 1, typ: "admin", sub: "studio", iat: Math.floor(nowMs() / 1000), exp: Math.floor(nowMs() / 1000) + 24 * 3600 }, k.issuer.privateKey, k.issuer.kid));
  const studioDir = options.studioDir && existsSync(join(options.studioDir, "index.html")) ? resolve(options.studioDir) : null;

  /** The URL a client signed in its DPoP proof: the public base plus the request path. */
  const requestUrl = (req: IncomingMessage): string => `${cfg.publicUrl?.replace(/\/$/, "") ?? `http://${req.headers.host ?? "localhost"}`}${(req.url ?? "/").split("?")[0]}`;

  async function checkDpopHeader(req: IncomingMessage, sessionToken?: string): Promise<{ presented: boolean; valid: boolean; jkt?: string; jwkHeader?: JsonWebKey; message?: string }> {
    const proof = req.headers["dpop"];
    if (typeof proof !== "string" || proof === "") return { presented: false, valid: false };
    const r = await verifyDpopProof({ proof, method: req.method ?? "POST", url: requestUrl(req), nowMs: nowMs(), replayCache: replay, ...(sessionToken ? { sessionToken } : {}) });
    if (!r.ok) return { presented: true, valid: false, message: r.message };
    const header = JSON.parse(Buffer.from((proof.startsWith(TOKEN_PREFIX.dpop) ? proof.slice(TOKEN_PREFIX.dpop.length) : proof).split(".")[0] as string, "base64url").toString("utf8")) as { jwk: JsonWebKey };
    return { presented: true, valid: true, jkt: r.jkt, jwkHeader: header.jwk };
  }

  /* ───────── routes ───────── */

  const server: AuthvexServer = {
    http: createHttpServer((req, res) => {
      const t0 = performance.now();
      res.on("finish", () => {
        const label = routeOf(req);
        const seconds = (performance.now() - t0) / 1000;
        mRequests.inc({ method: req.method ?? "GET", route: label, status: String(res.statusCode) });
        mDuration.observe({ route: label }, seconds);
        if (cfg.logging.requests) emit("info", "request", { method: req.method, route: label, status: res.statusCode, ms: Math.round(seconds * 1000) });
      });
      route(req, res).catch((e: unknown) => {
        const status = e instanceof HttpError ? e.status : 500;
        if (status === 500) emit("error", "unhandled error", { error: e instanceof Error ? e.message : String(e), method: req.method, route: routeOf(req) });
        if (res.headersSent) return void res.destroy();
        send(req, res, status, { error: e instanceof HttpError ? e.message : "internal error", ...(e instanceof HttpError ? e.extra : {}) });
      });
    }),
    get adminToken(): string {
      return adminTokenCache;
    },
    ledger,
    listen: () =>
      adminTokenPromise.then(() => new Promise<{ port: number; host: string }>((resolveListen, reject) => {
        server.http.once("error", reject);
        server.http.listen(cfg.port, cfg.host, () => {
          server.http.off("error", reject);
          sweeper = setInterval(() => void store.sweep(nowMs()).catch(() => undefined), 60_000).unref();
          const a = server.http.address() as AddressInfo;
          resolveListen({ port: a.port, host: a.address });
        });
      })),
    close: () =>
      new Promise((resolveClose) => {
        if (sweeper) clearInterval(sweeper);
        server.http.close(() => void store.flush().then(() => resolveClose()));
        server.http.closeIdleConnections();
        setTimeout(() => server.http.closeAllConnections(), 1000).unref();
      }),
    url: () => {
      const a = server.http.address() as AddressInfo | null;
      return a ? `http://${a.address === "::" || a.address === "0.0.0.0" ? "localhost" : a.address}:${a.port}` : "";
    },
  };
  let sweeper: NodeJS.Timeout | null = null;
  let adminTokenCache = "";
  void adminTokenPromise.then((t) => (adminTokenCache = t));
  server.http.headersTimeout = 15_000;
  server.http.requestTimeout = 30_000;

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";
    if (method === "OPTIONS") {
      res.writeHead(204, cors(req));
      return void res.end();
    }
    if (!adminTokenCache) adminTokenCache = await adminTokenPromise;
    if (path === "/api/health") return send(req, res, 200, { ok: true, version: options.version ?? "0.0.0", uptimeMs: nowMs() - startedAt, tenants: tenants.size, issuerKid: (await K()).issuer.kid, store: store.kind });
    if (path === "/metrics" && cfg.metrics.enabled) {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
      if (!m || !constantTimeEqualStr(m[1] as string, metricsToken as string)) {
        res.writeHead(401, { "www-authenticate": 'Bearer realm="authvex-metrics"', "cache-control": "no-store" });
        return void res.end();
      }
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8", "cache-control": "no-store" });
      return void res.end(await registry.render());
    }
    if (path === "/.well-known/jwks.json") {
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=300", "x-content-type-options": "nosniff", ...cors(req) });
      return void res.end(JSON.stringify({ keys: (await K()).keys.keys }));
    }
    if (path.startsWith("/oidc/") || path.startsWith("/api/oidc/")) {
      if (await oidcHandle(req, res, path, method, url)) return;
      if (path.startsWith("/oidc/")) throw new HttpError(404, "no such endpoint");
    }
    if (path.startsWith("/api/")) return api(req, res, method, path, url);
    if (method !== "GET" && method !== "HEAD") throw new HttpError(405, "method not allowed");
    serveStatic(req, res, path);
  }


  /** Verifies a registration response against its challenge and stores the passkey. Shared by the admin route and self-service. */
  async function registerPasskey(u: UserRecord, ch: { challenge: string }, body: { deviceName: string; clientDataJSON: string; attestationObject: string }, actor: string): Promise<{ passkey: { credentialId: string; deviceName: string } }> {
    const r = await verifyWebAuthnRegistration({ expected: { challenge: ch.challenge, origin: expectedOrigins(), rpId: cfg.rpId }, response: { clientDataJSON: body.clientDataJSON, attestationObject: body.attestationObject }, attestation: { formats: cfg.attestation.formats, trustAnchors: attestationAnchors, requireTrusted: cfg.attestation.requireTrusted, nowMs: nowMs() } });
    if (!r.ok) throw new HttpError(422, `passkey registration refused: ${r.message}`, { reason: r.reason });
    if ([...users.values()].some((x) => x.passkeys.some((p) => p.credentialId === r.credentialId))) throw new HttpError(409, "that credential is already registered");
    const record: PasskeyRecord = { credentialId: r.credentialId, publicKeyJwk: r.publicKeyJwk as PasskeyRecord["publicKeyJwk"], signCount: r.signCount, deviceName: body.deviceName, createdAtIso: new Date(nowMs()).toISOString(), attestation: { format: r.attestation.format, type: r.attestation.type, trusted: r.attestation.trusted, aaguid: r.attestation.aaguid, ...(r.attestation.certificate?.subject["O"]?.[0] ? { vendor: r.attestation.certificate.subject["O"][0] } : {}) } };
    users.set(u.id, UserRecordSchema.parse({ ...(users.get(u.id) as UserRecord), passkeys: [...(users.get(u.id) as UserRecord).passkeys, record] }));
    saveUsers();
    audit("passkey.registered", { actor, subject: u.id, detail: { credentialId: record.credentialId.slice(0, 12), deviceName: record.deviceName, backedUp: r.flags.backupState, attestation: r.attestation.type, trusted: r.attestation.trusted } });
    return { passkey: { credentialId: record.credentialId, deviceName: record.deviceName } };
  }

  /**
   * Who is calling with their own session (for the `/api/me/...` routes). Not an OpenID Connect client's token, and the session
   * family must still be active, so revoking a session takes effect at once.
   */
  async function sessionUser(req: IncomingMessage): Promise<{ user: UserRecord; claims: SessionClaims }> {
    throttleIp(req);
    const m = /^(?:DPoP|Bearer) (\S+)$/i.exec(req.headers.authorization ?? "");
    if (!m) throw new HttpError(401, "sign in first: send your session token in the Authorization header");
    const proof = req.headers["dpop"];
    const v = await verifyDpopSessionRequest({ sessionToken: m[1] as string, method: req.method ?? "GET", url: requestUrl(req), issuerPublicKeyJwk: (await K()).keys, nowMs: nowMs(), replayCache: replay, ...(typeof proof === "string" ? { dpopProof: proof } : {}) });
    if (!v.ok) throw new HttpError(401, v.message, { reason: v.reason });
    const fam = await store.getFamily(v.claims.fam);
    const user = users.get(v.claims.sub);
    if (!fam || fam.status !== "active" || fam.clientId !== undefined || !user) throw new HttpError(401, "this session is no longer valid");
    return { user, claims: v.claims };
  }

  /**
   * Adding or removing a sign-in method is what an attacker with a stolen session would do to stay in. It therefore needs more than the
   * session: a session bound to a device key, the account's password, or (for a brand-new account with no credential yet) nothing more
   * than the emailed link that created the session.
   */
  async function assertMayChangeCredentials(user: UserRecord, claims: SessionClaims, password: string | undefined): Promise<void> {
    if (claims.cnf) return;
    if (!user.passwordHash && user.passkeys.length === 0) return;
    if (user.passwordHash && password !== undefined && (await hasher.verify(password, user.passwordHash))) return;
    throw new HttpError(403, user.passwordHash ? "enter your current password to change how you sign in (or use a session bound to this device)" : "use a session bound to this device to change how you sign in", { status: "reauthentication_required" });
  }

  const mePasskeys = (u: UserRecord): unknown => u.passkeys.map((p) => ({ credentialId: p.credentialId, deviceName: p.deviceName, createdAtIso: p.createdAtIso, ...(p.attestation ? { attestation: p.attestation } : {}) }));

  async function selfService(req: IncomingMessage, res: ServerResponse, method: string, path: string): Promise<boolean> {
    const ok = (body: unknown, status = 200): void => send(req, res, status, body);
    if (method === "GET" && path === "/api/me/passkeys") {
      const { user } = await sessionUser(req);
      ok({ passkeys: mePasskeys(user), hasPassword: user.passwordHash !== undefined });
      return true;
    }
    if (method === "POST" && path === "/api/me/passkeys/challenge") {
      const { user, claims } = await sessionUser(req);
      const body = parse(z.object({ password: z.string().max(1024).optional() }).strict(), await readBody(req));
      await assertMayChangeCredentials(user, claims, body.password);
      const challenge = generateChallenge();
      const id = `chl_${hex(globalThis.crypto.getRandomValues(new Uint8Array(8)))}`;
      await store.putChallenge(id, { challenge, purpose: "register", userId: user.id, expires: nowMs() + 120_000 });
      ok({ challengeId: id, challenge, rpId: cfg.rpId, rpName: "Authvex", user: { id: user.id, name: user.email, displayName: user.name }, excludeCredentials: user.passkeys.map((p) => p.credentialId), attestation: cfg.attestation.formats.every((f) => f === "none") ? "none" : "direct" });
      return true;
    }
    if (method === "POST" && path === "/api/me/passkeys") {
      const { user } = await sessionUser(req);
      const body = parse(z.object({ challengeId: z.string(), deviceName: z.string().max(80).default("Passkey"), clientDataJSON: z.string(), attestationObject: z.string() }).strict(), await readBody(req));
      const ch = await takeChallenge(body.challengeId, "register");
      if (ch.userId !== user.id) throw new HttpError(400, "that challenge was issued to someone else");
      ok(await registerPasskey(user, ch, body, user.id), 201);
      return true;
    }
    const del = /^\/api\/me\/passkeys\/([^/]+)$/.exec(path);
    if (method === "DELETE" && del) {
      const { user, claims } = await sessionUser(req);
      const body = parse(z.object({ password: z.string().max(1024).optional() }).strict(), await readBody(req));
      const id = decodeURIComponent(del[1] as string);
      if (!user.passkeys.some((p) => p.credentialId === id)) throw new HttpError(404, "no such passkey");
      if (!user.passwordHash && user.passkeys.length === 1) throw new HttpError(409, "this is your only way to sign in: add another passkey or set a password first", { status: "last_credential" });
      await assertMayChangeCredentials(user, claims, body.password);
      users.set(user.id, { ...user, passkeys: user.passkeys.filter((p) => p.credentialId !== id) });
      saveUsers();
      audit("passkey.removed", { actor: user.id, subject: user.id, detail: { credentialId: id.slice(0, 12) } });
      ok({ ok: true });
      return true;
    }
    return false;
  }

  async function api(req: IncomingMessage, res: ServerResponse, method: string, path: string, url: URL): Promise<void> {
    const ok = (body: unknown, status = 200): void => send(req, res, status, body);

    /* ── public: authentication ── */
    if (method === "POST" && path === "/api/auth/passkey/challenge") {
      const body = parse(z.object({ tenantId: z.string(), email: z.string().email() }).strict(), await readBody(req));
      throttleIp(req);
      const tenant = tenants.get(body.tenantId);
      const user = tenant ? [...users.values()].find((u) => u.email.toLowerCase() === body.email.toLowerCase() && u.orgMemberships.some((m) => m.tenantId === body.tenantId)) : undefined;
      const id = `chl_${hex(new Uint8Array(await sha256(`${Math.random()}${nowMs()}`)).subarray(0, 8))}`;
      const challenge = generateChallenge();
      if (user) await store.putChallenge(id, { challenge, purpose: "login", tenantId: body.tenantId, userId: user.id, expires: nowMs() + 120_000 });
      // An unknown user gets a challenge and an empty list like everyone else, so this endpoint does not reveal who has an account.
      return ok({ challengeId: id, challenge, rpId: cfg.rpId, allowCredentials: user?.passkeys.map((p) => p.credentialId) ?? [], userVerification: "required", timeoutMs: 120_000 });
    }
    if (method === "POST" && path === "/api/auth/login") return login(req, res);
    if (method === "POST" && path === "/api/auth/dpop-verify") {
      const body = parse(z.object({ sessionToken: z.string().max(4096), dpopProof: z.string().max(4096).optional(), method: z.string().max(10), url: z.string().url().max(2048), requirePermission: z.string().max(100).optional() }).strict(), await readBody(req));
      const t = await verifySignedToken<{ tid?: string; sub?: string; fam?: string }>(TOKEN_PREFIX.session, body.sessionToken, (await K()).keys);
      const tenant = t.ok && typeof t.payload.tid === "string" ? tenants.get(t.payload.tid) : undefined;
      const v = await verifyDpopSessionRequest({
        sessionToken: body.sessionToken, method: body.method, url: body.url, issuerPublicKeyJwk: (await K()).keys, nowMs: nowMs(), replayCache: replay,
        ...(body.dpopProof ? { dpopProof: body.dpopProof } : {}), ...(tenant?.requireDpopHardwareBinding ? { requireBinding: true } : {}),
      });
      if (!v.ok) {
        if (v.reason === "key_mismatch" || v.reason === "dpop_missing" || v.reason === "bad_signature") audit("auth.dpop.rejected", { ...(v.claims ? { tenantId: v.claims.tid, subject: v.claims.sub } : {}), detail: { reason: v.reason, fam: v.claims?.fam } });
        return ok({ valid: false, reason: v.reason, message: v.message }, 401);
      }
      const fam = await store.getFamily(v.claims.fam);
      if (!fam || fam.status !== "active") return ok({ valid: false, reason: "session_revoked", message: "the session family has been revoked" }, 401);
      if (body.requirePermission) {
        const u = users.get(v.claims.sub);
        const d = tenant && u ? evaluatePermission(tenant, u, body.requirePermission) : null;
        if (!d?.allowed) return ok({ valid: false, reason: "forbidden", message: d && !d.allowed ? d.message : "unknown user" }, 403);
      }
      return ok({ valid: true, bound: v.bound, claims: v.claims });
    }
    if (method === "POST" && path === "/api/auth/rotate") return rotate(req, res);
    if (method === "POST" && emailRoutes.has(path)) {
      requireMail();
      return (emailRoutes.get(path) as (req: IncomingMessage, res: ServerResponse) => Promise<void>)(req, res);
    }
    if (method === "POST" && path === "/api/verify") {
      const body = parse(z.object({ token: z.string().max(4096), scope: z.string().max(100).optional() }).strict(), await readBody(req));
      return ok(await verifyAnyToken(body.token, body.scope));
    }

    /* ── a signed-in user managing their own passkeys ── */
    if (path.startsWith("/api/me/") && (await selfService(req, res, method, path))) return;

    /* ── admin ── */
    await requireAdmin(req);

    if (method === "GET" && path === "/api/workspace") {
      return ok({
        version: options.version ?? "0.0.0", uptimeMs: nowMs() - startedAt, issuer: { kid: (await K()).issuer.kid, publicKeyJwk: (await K()).issuer.publicKeyJwk, keys: (await K()).summary },
        config: { rpId: cfg.rpId, origins: cfg.origins, trustClientGeo: cfg.trustClientGeo, ledger: ledger !== null, publicUrl: publicBase() },
        tenants: [...tenants.values()].map((t) => ({ ...t, matrix: buildPermissionMatrix(t) })), users: [...users.values()].map(publicUser),
        families: (await store.listFamilies()).map(familyView), keys: keys().map(keyView),
      });
    }
    if (method === "PUT" && /^\/api\/tenants\/[^/]+$/.test(path)) {
      const id = decodeURIComponent(path.split("/")[3] as string);
      const existing = tenantOr404(id);
      const next = parse(TenantPolicySchema, await readBody(req));
      if (next.id !== id) throw new HttpError(400, "the tenant id cannot be changed");
      const problems = checkWorkspace([...[...tenants.values()].filter((t) => t.id !== id), next], [...users.values()]);
      if (problems.length > 0) throw new HttpError(422, problems.join("; "));
      const file = ws.tenantFiles.get(id);
      if (file) writeJsonAtomic(file, next);
      tenants.set(id, next);
      audit("tenant.updated", { tenantId: id, actor: "studio", detail: { roles: next.roles.map((r) => `${r.id}:${r.permissions.length}`), before: existing.roles.length } });
      return ok({ tenant: next, matrix: buildPermissionMatrix(next) });
    }
    if (method === "POST" && path === "/api/evaluate") try {
        return ok(await evaluateScenario({ tenants, users, issuer: (await K()).issuer, nowMs: nowMs() }, await readBody(req)));
      } catch (e) {
        if (e instanceof EvaluateError) throw new HttpError(e.status, e.message);
        throw e;
      }
    if (method === "POST" && path === "/api/auth/impersonate") {
      const body = parse(z.object({ tenantId: z.string(), actorId: z.string(), targetUserId: z.string(), reason: z.string().max(300), ttlSeconds: z.number().int().optional(), readOnly: z.boolean().optional() }).strict(), await readBody(req));
      const tenant = tenantOr404(body.tenantId);
      const actor = userOr404(body.actorId);
      const target = userOr404(body.targetUserId);
      const perm = evaluatePermission(tenant, actor, "users:impersonate");
      if (!perm.allowed) {
        audit("impersonation.refused", { tenantId: tenant.id, actor: actor.id, subject: target.id, detail: { reason: perm.reason } });
        throw new HttpError(403, `AV-107: ${perm.message}`);
      }
      if (!target.orgMemberships.some((m) => m.tenantId === tenant.id)) throw new HttpError(422, `${target.email} is not a member of ${tenant.id}`);
      let minted;
      try {
        minted = await mintImpersonationSeal({ issuer: (await K()).issuer, actor, target, tenantId: tenant.id, reason: body.reason, ...(body.ttlSeconds !== undefined ? { ttlSeconds: body.ttlSeconds } : {}), ...(body.readOnly !== undefined ? { readOnly: body.readOnly } : {}), nowMs: nowMs() });
      } catch (e) {
        audit("impersonation.refused", { tenantId: tenant.id, actor: actor.id, subject: target.id, detail: { reason: e instanceof Error ? e.message : "invalid" } });
        throw new HttpError(422, `AV-108: ${e instanceof Error ? e.message : "invalid request"}`);
      }
      audit("impersonation.minted", { tenantId: tenant.id, actor: actor.id, subject: target.id, detail: { reason: minted.claims.reason, readOnly: minted.claims.readOnly, expiresAtIso: minted.claims.expiresAtIso, jti: minted.claims.jti } });
      return ok({ token: minted.token, claims: minted.claims }, 201);
    }
    if (path === "/api/keys") {
      if (method === "GET") return ok({ keys: keys().map(keyView) });
      if (method === "POST") {
        const body = parse(z.object({ tenantId: z.string(), name: z.string().min(1).max(80), scopes: z.array(z.string().min(1).max(100)).min(1).max(50), rateLimitPerMin: z.number().int().min(1).max(100_000).optional(), ttlSeconds: z.number().int().min(60).optional() }).strict(), await readBody(req));
        tenantOr404(body.tenantId);
        const { key, record } = await mintScopedApiKey({ ...body, nowMs: nowMs() });
        writeKeys(ws.root, [...keys(), record]);
        audit("key.minted", { tenantId: body.tenantId, actor: "studio", subject: record.id, detail: { name: body.name, keyPrefix: record.keyPrefix, scopes: body.scopes } });
        return ok({ key, record: keyView(record), note: "this is the only time the full key is shown" }, 201);
      }
    }
    const keyDelete = /^\/api\/keys\/([^/]+)$/.exec(path);
    if (method === "DELETE" && keyDelete) {
      const id = decodeURIComponent(keyDelete[1] as string);
      const all = keys();
      const k = all.find((x) => x.id === id);
      if (!k) throw new HttpError(404, "no such key");
      writeKeys(ws.root, all.map((x) => (x.id === id ? { ...x, revokedAtIso: new Date(nowMs()).toISOString() } : x)));
      audit("key.revoked", { tenantId: k.tenantId, actor: "studio", subject: id, detail: { keyPrefix: k.keyPrefix } });
      return ok({ ok: true });
    }
    const famDelete = /^\/api\/families\/([^/]+)$/.exec(path);
    if (method === "DELETE" && famDelete) {
      const id = decodeURIComponent(famDelete[1] as string);
      for (let attempt = 0; attempt < 5; attempt++) {
        const f = await store.getFamily(id);
        if (!f) throw new HttpError(404, "no such session family");
        const revoked = revokeFamily(f, nowMs());
        if (revoked === f || (await store.compareAndSetFamily(f, revoked))) {
          audit("auth.family.revoked", { tenantId: f.tenantId, actor: "studio", subject: f.userId, detail: { familyId: f.familyId } });
          return ok({ ok: true });
        }
      }
      throw new HttpError(503, "the session family is changing too quickly; try again");
    }
    if (method === "POST" && path === "/api/users/totp") {
      const body = parse(z.object({ userId: z.string() }).strict(), await readBody(req));
      const u = userOr404(body.userId);
      const secret = generateTotpSecret();
      users.set(u.id, { ...u, totpSecretB32: secret });
      saveUsers();
      audit("user.totp_enrolled", { actor: "studio", subject: u.id });
      return ok({ secretB32: secret, otpauthUri: buildOtpAuthUri({ secretB32: secret, account: u.email, issuer: "Authvex" }), note: "shown once: add it to an authenticator app" }, 201);
    }
    if (method === "POST" && path === "/api/users/passkeys/challenge") {
      const body = parse(z.object({ userId: z.string() }).strict(), await readBody(req));
      const u = userOr404(body.userId);
      const challenge = generateChallenge();
      const id = `chl_${hex(new Uint8Array(await sha256(`${Math.random()}${nowMs()}`)).subarray(0, 8))}`;
      await store.putChallenge(id, { challenge, purpose: "register", userId: u.id, expires: nowMs() + 120_000 });
      return ok({ challengeId: id, challenge, rpId: cfg.rpId, rpName: "Authvex", user: { id: u.id, name: u.email, displayName: u.name }, excludeCredentials: u.passkeys.map((p) => p.credentialId), attestation: cfg.attestation.formats.every((f) => f === "none") ? "none" : "direct" });
    }
    if (method === "POST" && path === "/api/users/passkeys") {
      const body = parse(z.object({ challengeId: z.string(), deviceName: z.string().max(80).default("Passkey"), clientDataJSON: z.string(), attestationObject: z.string() }).strict(), await readBody(req));
      const ch = await takeChallenge(body.challengeId, "register");
      return ok(await registerPasskey(userOr404(ch.userId), ch, body, "studio"), 201);
    }
    if (method === "GET" && path === "/api/ledger") return ok({ entries: ledger?.list(Math.min(500, Math.max(1, Number(url.searchParams.get("limit") ?? 100) || 100))) ?? [], enabled: ledger !== null });
    if (method === "GET" && path === "/api/ledger/verify") return ok(ledger ? verifyLedger(ledger.path) : { ok: true, entries: 0, head: "", note: "the ledger is disabled" });
    throw new HttpError(404, "no such endpoint");
  }

  function throttleIp(req: IncomingMessage): void {
    const hits = slide(ipHits, clientIp(req), 60_000);
    if (hits.length >= cfg.ipRequestsPerMinute) throw new HttpError(429, "too many requests from this address; try again in a minute");
    hits.push(nowMs());
  }
  /** Page origins whose passkey ceremonies are accepted. Unset, only this server's own address (and its localhost alias) qualify. */
  const expectedOrigins = (): string[] => {
    if (cfg.origins.length > 0) return cfg.origins;
    const base = publicBase();
    const u = new URL(base);
    return [...new Set([base, `${u.protocol}//localhost:${u.port}`, `${u.protocol}//127.0.0.1:${u.port}`])];
  };
  async function takeChallenge(id: string, purpose: "login" | "register") {
    const c = await store.takeChallenge(id, nowMs());
    if (!c || c.purpose !== purpose) throw new HttpError(400, "the challenge is unknown, used or expired");
    return c;
  }

  /* ───────── login ───────── */

  async function login(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = parse(loginSchema, await readBody(req));
    throttleIp(req);
    const now = nowMs();
    const tenant = tenants.get(body.tenantId);
    const user = tenant ? [...users.values()].find((u) => u.email.toLowerCase() === body.email.toLowerCase() && u.orgMemberships.some((m) => m.tenantId === body.tenantId)) : undefined;
    const ip = clientIp(req);
    const failKey = `${body.tenantId}|${body.email.toLowerCase()}`;
    const windowMs = cfg.failedAttemptWindowSeconds * 1000;
    const recentFails = Math.max(await store.countFailures(failKey, now, windowMs), await store.countFailures(`ip|${ip}`, now, windowMs));

    // Factors. A password is always hashed, even for an unknown user, so timing does not reveal who exists.
    let primary = false;
    let second = false;
    let passkeyRegression = false;
    let passkeyUsed: { record: PasskeyRecord; signCount: number } | null = null;
    if (body.passkey) {
      const ch = await store.takeChallenge(body.passkey.challengeId, now);
      const record = user?.passkeys.find((p) => p.credentialId === body.passkey?.credentialId);
      if (ch && ch.purpose === "login" && user && ch.userId === user.id && record) {
        const r = await verifyWebAuthnAssertion({ expected: { challenge: ch.challenge, origin: expectedOrigins(), rpId: cfg.rpId }, response: body.passkey, credential: { publicKeyJwk: record.publicKeyJwk, signCount: record.signCount } });
        if (r.ok) {
          primary = true;
          second = r.flags.userVerified;
          passkeyUsed = { record, signCount: r.signCount };
        } else if (r.reason === "sign_count_regression") passkeyRegression = true;
      }
    } else {
      const pwOk = await hasher.verify(body.password ?? "", user?.passwordHash ?? NO_PASSWORD);
      primary = pwOk && user !== undefined;
      // Upgrade a hash made with an older algorithm or weaker settings, now that the password is known to be right.
      if (primary && user?.passwordHash && hasher.needsRehash(user.passwordHash)) {
        users.set(user.id, { ...user, passwordHash: await hasher.hash(body.password ?? "") });
        saveUsers();
        audit("password.rehashed", { subject: user.id, detail: { algorithm: hasher.algorithm } });
      }
    }
    if (user?.totpSecretB32 && body.totp) {
      const last = await store.getTotpCounter(user.id);
      const t = await verifyTotpCode(user.totpSecretB32, body.totp, { nowMs: now, ...(last !== undefined ? { minCounter: last } : {}) });
      // The counter is advanced atomically, so two simultaneous uses of one code cannot both pass.
      if (t.ok && primary && (await store.advanceTotpCounter(user.id, t.counter))) second = true;
    }

    await finishAuth(req, res, {
      tenant, user, email: body.email, primary, second, passkeyRegression, passkeyUsed, method: body.passkey ? "passkey" : "password", recentFails, failKey, windowMs, now, ip,
      geo: body.geo, asn: body.asn, drift: body.deviceFingerprintDrift, deviceName: body.deviceName,
    });
  }

  interface AuthAttempt {
    tenant: TenantPolicy | undefined;
    user: UserRecord | undefined;
    email: string;
    primary: boolean;
    second: boolean;
    passkeyRegression: boolean;
    passkeyUsed: { record: PasskeyRecord; signCount: number } | null;
    method: "password" | "passkey" | "magic-link";
    recentFails: number;
    failKey: string;
    windowMs: number;
    now: number;
    ip: string;
    geo: z.infer<typeof geoSchema> | undefined;
    asn: AsnKind | undefined;
    drift: boolean | undefined;
    deviceName: string | undefined;
  }

  /** What every way of signing in has in common: build the gate's context, decide, and issue the session. */
  async function finishAuth(req: IncomingMessage, res: ServerResponse, a: AuthAttempt): Promise<void> {
    const { user, email, primary, second, passkeyRegression, passkeyUsed, recentFails, failKey, windowMs, now, ip } = a;
    const body = { geo: a.geo, asn: a.asn, deviceFingerprintDrift: a.drift, deviceName: a.deviceName, passkey: a.method === "passkey" ? true : undefined, email };
    const tenant = a.tenant;
    // Context for the gate.
    const proof = await checkDpopHeader(req);
    const trustGeo = cfg.trustClientGeo;
    const headerGeo = cfg.trustGeoHeaders ? parseGeoHeader(req) : undefined;
    const geoIn = trustGeo ? body.geo : headerGeo;
    const currentGeo: GeoPoint | undefined = geoIn ? { lat: geoIn.lat, lon: geoIn.lon, city: geoIn.city ?? "Unknown", ip: geoIn.ip ?? ip, timestampIso: new Date(now).toISOString() } : undefined;
    const asn = (trustGeo ? body.asn : undefined) ?? (cfg.trustGeoHeaders ? (req.headers["x-authvex-asn"] as AsnKind | undefined) : undefined);
    const policy = tenant;
    if (!policy) throw new HttpError(401, "invalid credentials", { status: "invalid_credentials" });

    const ctx: RiskContext = {
      email: body.email, nowMs: now, primaryFactorVerified: primary, secondFactorVerified: second, isAdmin: user ? isAdminUser(policy, user) : false, failedAttemptsInWindow: recentFails,
      lastLoginGeo: user?.lastLoginGeo, currentGeo, passkeySignCountRegression: passkeyRegression, dpop: { presented: proof.presented, valid: proof.valid, keyMatchesSession: proof.valid },
      asnKind: asn && asnSchema.safeParse(asn).success ? asn : undefined, deviceFingerprintDrift: trustGeo ? body.deviceFingerprintDrift : undefined,
    };
    const report = evaluateAuthRiskGate(ctx, policy);

    if (passkeyRegression && user) {
      audit("auth.passkey.clone_suspected", { tenantId: policy.id, subject: user.id, detail: { code: "AV-104", ip } });
      return send(req, res, 403, { status: "blocked", report: shapeReport(report) });
    }
    if (!primary) {
      await store.recordFailure(failKey, now, windowMs);
      await store.recordFailure(`ip|${ip}`, now, windowMs);
      audit("auth.login.failed", { tenantId: policy.id, subject: user?.id ?? "unknown", detail: { method: a.method, score: report.score, level: report.level, ip } });
      // The report is withheld: it would confirm whether the account exists.
      const throttled = report.checks.some((c) => c.code === "AV-102" && c.status === "fail");
      throw new HttpError(throttled ? 429 : 401, throttled ? "too many failed attempts; try again later" : "invalid credentials", { status: throttled ? "rate_limited" : "invalid_credentials" });
    }
    if (!user) throw new HttpError(401, "invalid credentials", { status: "invalid_credentials" });
    if (report.level === "BLOCK") {
      audit("auth.login.blocked", { tenantId: policy.id, subject: user.id, detail: { score: report.score, failed: report.checks.filter((c) => c.status === "fail").map((c) => c.code), ip } });
      return send(req, res, 403, { status: "blocked", report: shapeReport(report) });
    }
    if (report.level === "STEP_UP_MFA") {
      const available = [...(user.totpSecretB32 ? ["totp"] : []), ...(user.passkeys.length > 0 ? ["passkey"] : [])];
      audit("auth.login.step_up", { tenantId: policy.id, subject: user.id, detail: { score: report.score, available, ip } });
      return send(req, res, 401, { status: "step_up_required", available, report: shapeReport(report) });
    }

    if (policy.requireVerifiedEmail && !user.emailVerifiedAt && a.method !== "magic-link") {
      audit("auth.login.email_unverified", { tenantId: policy.id, subject: user.id, detail: { ip } });
      return send(req, res, 403, { status: "email_unverified", message: "confirm your email address first: follow the link we sent you, or ask for a new one" });
    }
    if (passkeyUsed) {
      const rec = passkeyUsed;
      users.set(user.id, { ...user, passkeys: user.passkeys.map((p) => (p.credentialId === rec.record.credentialId ? { ...p, signCount: rec.signCount } : p)) });
    }
    const device = { ...(body.deviceName ? { name: body.deviceName } : {}), ...(currentGeo ? { city: currentGeo.city } : {}), ip };
    const bundle = await issueSessionBundle({
      issuer: (await K()).issuer, userId: user.id, tenantId: policy.id, accessTtlSeconds: policy.sessionTtlSeconds, refreshTtlSeconds: policy.refreshTtlSeconds, nowMs: now, device,
      ...(proof.valid && proof.jwkHeader ? { clientPublicKeyJwk: proof.jwkHeader } : {}),
    });
    await store.createFamily(bundle.family);
    const cur = users.get(user.id) as UserRecord;
    if (currentGeo) users.set(user.id, { ...cur, lastLoginGeo: currentGeo });
    if (currentGeo || passkeyUsed) saveUsers();
    audit("auth.login", { tenantId: policy.id, subject: user.id, detail: { familyId: bundle.family.familyId, bound: bundle.family.boundJkt !== undefined, method: a.method, mfa: second, score: report.score, ip } });
    send(req, res, 200, {
      status: "ok", sessionToken: bundle.sessionToken, refreshToken: bundle.refreshToken, tokenType: bundle.claims.cnf ? "DPoP" : "Bearer", expiresIn: policy.sessionTtlSeconds,
      familyId: bundle.family.familyId, claims: bundle.claims, user: publicUser(users.get(user.id) as UserRecord), report: shapeReport(report),
    });
  }

  const shapeReport = (r: RiskReport): RiskReport => r;

  function parseGeoHeader(req: IncomingMessage): { lat: number; lon: number; city?: string; ip?: string } | undefined {
    const raw = req.headers["x-authvex-geo"];
    if (typeof raw !== "string") return undefined;
    const [lat, lon, ...city] = raw.split(",");
    const g = geoSchema.safeParse({ lat: Number(lat), lon: Number(lon), city: city.join(",").trim() || "Unknown" });
    return g.success ? g.data : undefined;
  }

  /* ───────── email flows: sign-up, verification, password reset, magic links ───────── */

  const mailer = options.mailer ?? null;
  const TTL = { verify: 24 * 3600_000, reset: 30 * 60_000, magic: 10 * 60_000, enrol: 30 * 60_000 } as const;
  type Flow = keyof typeof TTL;
  const TAG: Record<Flow, string> = { verify: "ev", reset: "pr", magic: "ml", enrol: "en" };
  const SUBJECT: Record<Flow, string> = { verify: "Confirm your email address", reset: "Reset your password", magic: "Your sign-in link", enrol: "Set up your passkey" };
  const LEAD: Record<Flow, string> = {
    verify: "Confirm this email address to finish setting up your account.",
    reset: "Someone asked to reset the password for your account. If that was you, use the link below. If not, you can ignore this message: nothing changes until the link is used.",
    magic: "Use this link to sign in. It works once.",
    enrol: "Follow this link to confirm your email address and register a passkey. You will not need a password.",
  };

  const requireMail = (): Mailer => {
    if (!mailer || !cfg.mail) throw new HttpError(501, "email is not configured on this server (set \"mail\" in authvex.config.json)");
    return mailer;
  };
  const normEmail = (e: string): string => e.trim().toLowerCase();
  const findByEmail = (email: string): UserRecord | undefined => [...users.values()].find((u) => u.email.toLowerCase() === normEmail(email));
  const findInTenant = (tenantId: string, email: string): UserRecord | undefined => [...users.values()].find((u) => u.email.toLowerCase() === normEmail(email) && u.orgMemberships.some((m) => m.tenantId === tenantId));
  const minutes = (ms: number): string => (ms >= 3600_000 ? `${Math.round(ms / 3600_000)} hours` : `${Math.round(ms / 60_000)} minutes`);

  /** Sends in the background so the response (and its timing) is the same whether or not the address belongs to anyone. */
  function sendInBackground(label: string, tenantId: string, userId: string, message: { to: string; subject: string; text: string }): void {
    const m = requireMail();
    void m.send(message).then(
      () => audit("mail.sent", { tenantId, subject: userId, detail: { type: label } }),
      (e: unknown) => {
        emit("warn", "mail failed", { label, error: e instanceof Error ? e.message : String(e) });
        audit("mail.failed", { tenantId, subject: userId, detail: { type: label, reason: e instanceof Error ? e.message.slice(0, 160) : "unknown" } });
      },
    );
  }

  /** At most three emails of one kind per address per hour, so the endpoint cannot be used to flood someone's inbox. */
  async function mailBudget(kind: string, email: string): Promise<boolean> {
    const key = `mail|${kind}|${normEmail(email)}`;
    if ((await store.countFailures(key, nowMs(), 3600_000)) >= 3) return false;
    await store.recordFailure(key, nowMs(), 3600_000);
    return true;
  }

  async function sendLink(flow: Flow, user: UserRecord, tenantId: string, extra: Record<string, unknown> = {}): Promise<void> {
    if (!(await mailBudget(flow, user.email))) return;
    const secret = `ath_${TAG[flow]}_${hex(globalThis.crypto.getRandomValues(new Uint8Array(32)))}`;
    await store.putOneTimeToken(hex(await sha256(secret)), { purpose: flow, userId: user.id, tenantId, expires: nowMs() + TTL[flow], data: { email: user.email, ...extra } });
    const link = `${(cfg.mail as { linkBase: string }).linkBase}#flow=${flow}&token=${encodeURIComponent(secret)}&tenant=${encodeURIComponent(tenantId)}`;
    sendInBackground(flow, tenantId, user.id, { to: user.email, subject: SUBJECT[flow], text: `${LEAD[flow]}\n\n${link}\n\nThis link works once and expires in ${minutes(TTL[flow])}.\n` });
  }

  const generic202 = (req: IncomingMessage, res: ServerResponse): void => send(req, res, 202, { status: "check_your_email", message: "If that address can use this, an email is on its way." });
  const tokenHash = async (t: string): Promise<string> => hex(await sha256(t));
  const BAD_LINK = "that link is invalid, already used or expired";

  const emailRoutes = new Map<string, (req: IncomingMessage, res: ServerResponse) => Promise<void>>([
    ["/api/auth/signup", async (req, res) => {
      const b = parse(z.object({ tenantId: z.string().max(60), email: z.string().email().max(200), name: z.string().min(1).max(100), password: z.string().max(1024).optional() }).strict(), await readBody(req));
      requireMail();
      throttleIp(req);
      const tenant = tenants.get(b.tenantId);
      if (!tenant?.allowSignup || !tenant.signupRoleId) throw new HttpError(403, "sign-up is not open for this tenant");
      if (b.password === undefined && !tenant.allowPasskeyOnlySignup) throw new HttpError(422, "a password is required to sign up here", { status: "password_required" });
      if (b.password !== undefined) {
        const policy = checkPasswordPolicy(b.password, { email: b.email });
        if (!policy.ok) throw new HttpError(422, policy.message, { status: "weak_password", reason: policy.reason });
      }
      const existing = findByEmail(b.email);
      if (existing) {
        // Do not reveal that the address is taken: send the owner a note instead, and answer exactly as for a new account.
        if (await mailBudget("exists", existing.email)) sendInBackground("signup_exists", b.tenantId, existing.id, { to: existing.email, subject: "You already have an account", text: "Someone tried to create an account with this email address, but you already have one. If it was you, sign in, or reset your password if you have forgotten it. If not, ignore this message.\n" });
        return generic202(req, res);
      }
      const user: UserRecord = UserRecordSchema.parse({ id: `usr_${hex(globalThis.crypto.getRandomValues(new Uint8Array(8)))}`, email: normEmail(b.email), name: b.name.trim(), ...(b.password !== undefined ? { passwordHash: await hasher.hash(b.password) } : {}), passkeys: [], orgMemberships: [{ tenantId: b.tenantId, roleId: tenant.signupRoleId }] });
      users.set(user.id, user);
      saveUsers();
      audit("user.signed_up", { tenantId: b.tenantId, subject: user.id, detail: { roleId: tenant.signupRoleId, passkeyOnly: b.password === undefined } });
      await sendLink(b.password === undefined ? "enrol" : "verify", user, b.tenantId);
      generic202(req, res);
    }],
    ["/api/auth/verify-email", async (req, res) => {
      const b = parse(z.object({ token: z.string().max(200) }).strict(), await readBody(req));
      throttleIp(req);
      const t = await store.takeOneTimeToken(await tokenHash(b.token), "verify", nowMs());
      const u = t ? users.get(t.userId) : undefined;
      if (!t || !u) throw new HttpError(400, BAD_LINK, { status: "invalid_link" });
      if (!u.emailVerifiedAt) {
        users.set(u.id, { ...u, emailVerifiedAt: new Date(nowMs()).toISOString() });
        saveUsers();
      }
      audit("user.email_verified", { tenantId: t.tenantId, subject: u.id });
      send(req, res, 200, { status: "verified" });
    }],
    ["/api/auth/verify-email/resend", async (req, res) => {
      const b = parse(z.object({ tenantId: z.string().max(60), email: z.string().email().max(200) }).strict(), await readBody(req));
      requireMail();
      throttleIp(req);
      const u = findInTenant(b.tenantId, b.email);
      if (u && !u.emailVerifiedAt) await sendLink("verify", u, b.tenantId);
      generic202(req, res);
    }],
    ["/api/auth/password-reset/request", async (req, res) => {
      const b = parse(z.object({ tenantId: z.string().max(60), email: z.string().email().max(200) }).strict(), await readBody(req));
      requireMail();
      throttleIp(req);
      const tenant = tenants.get(b.tenantId);
      if (tenant && !tenant.allowPasswordReset) throw new HttpError(403, "password reset is not enabled for this tenant");
      const u = findInTenant(b.tenantId, b.email);
      if (u && tenant) await sendLink("reset", u, b.tenantId);
      generic202(req, res);
    }],
    ["/api/auth/password-reset/confirm", async (req, res) => {
      const b = parse(z.object({ token: z.string().max(200), newPassword: z.string().max(1024) }).strict(), await readBody(req));
      throttleIp(req);
      const hash = await tokenHash(b.token);
      const t = await store.takeOneTimeToken(hash, "reset", nowMs());
      const u = t ? users.get(t.userId) : undefined;
      if (!t || !u) throw new HttpError(400, BAD_LINK, { status: "invalid_link" });
      const policy = checkPasswordPolicy(b.newPassword, { email: u.email });
      if (!policy.ok) {
        await store.putOneTimeToken(hash, t); // a weak password does not use up the link
        throw new HttpError(422, policy.message, { status: "weak_password", reason: policy.reason });
      }
      users.set(u.id, { ...u, passwordHash: await hasher.hash(b.newPassword), emailVerifiedAt: u.emailVerifiedAt ?? new Date(nowMs()).toISOString() });
      saveUsers();
      // Anyone who had the old password, or a session made with it, is shut out.
      let revoked = 0;
      for (const f of await store.listFamilies()) {
        if (f.userId !== u.id || f.status !== "active") continue;
        if (await store.compareAndSetFamily(f, revokeFamily(f, nowMs()))) revoked++;
      }
      audit("auth.password_reset", { tenantId: t.tenantId, subject: u.id, detail: { familiesRevoked: revoked } });
      send(req, res, 200, { status: "password_changed", sessionsRevoked: revoked });
    }],
    ["/api/auth/enrol/request", async (req, res) => {
      const b = parse(z.object({ tenantId: z.string().max(60), email: z.string().email().max(200) }).strict(), await readBody(req));
      requireMail();
      throttleIp(req);
      const tenant = tenants.get(b.tenantId);
      if (tenant && !tenant.allowPasskeyOnlySignup) throw new HttpError(403, "passkey-only sign-up is not enabled for this tenant");
      // Only for an account that has no way in yet; otherwise this would be a second kind of magic link.
      const u = findInTenant(b.tenantId, b.email);
      if (u && tenant && !u.passwordHash && u.passkeys.length === 0) await sendLink("enrol", u, b.tenantId);
      generic202(req, res);
    }],
    ["/api/auth/enrol/consume", async (req, res) => {
      const b = parse(z.object({ token: z.string().max(200), deviceName: z.string().max(80).optional() }).strict(), await readBody(req));
      throttleIp(req);
      const hash = await tokenHash(b.token);
      const t = await store.takeOneTimeToken(hash, "enrol", nowMs());
      const u = t ? users.get(t.userId) : undefined;
      const tenant = t ? tenants.get(t.tenantId) : undefined;
      // The link signs a brand-new account in once, so that it can register its first passkey. It is no use for an account that already has a credential.
      if (!t || !u || !tenant?.allowPasskeyOnlySignup || u.passwordHash || u.passkeys.length > 0) throw new HttpError(400, BAD_LINK, { status: "invalid_link" });
      const now = nowMs();
      users.set(u.id, { ...u, emailVerifiedAt: u.emailVerifiedAt ?? new Date(now).toISOString() });
      saveUsers();
      const ip = clientIp(req);
      const windowMs = cfg.failedAttemptWindowSeconds * 1000;
      const failKey = `${t.tenantId}|${u.email.toLowerCase()}`;
      await finishAuth(req, res, {
        tenant, user: users.get(u.id), email: u.email, primary: true, second: false, passkeyRegression: false, passkeyUsed: null, method: "magic-link",
        recentFails: Math.max(await store.countFailures(failKey, now, windowMs), await store.countFailures(`ip|${ip}`, now, windowMs)), failKey, windowMs, now, ip,
        geo: undefined, asn: undefined, drift: undefined, deviceName: b.deviceName,
      });
      if (res.statusCode === 401) await store.putOneTimeToken(hash, t);
    }],
    ["/api/auth/magic-link/request", async (req, res) => {
      const b = parse(z.object({ tenantId: z.string().max(60), email: z.string().email().max(200) }).strict(), await readBody(req));
      requireMail();
      throttleIp(req);
      const tenant = tenants.get(b.tenantId);
      if (tenant && !tenant.allowMagicLinks) throw new HttpError(403, "magic links are not enabled for this tenant");
      const u = findInTenant(b.tenantId, b.email);
      if (u && tenant) await sendLink("magic", u, b.tenantId);
      generic202(req, res);
    }],
    ["/api/auth/magic-link/consume", async (req, res) => {
      const b = parse(z.object({ token: z.string().max(200), totp: z.string().max(12).optional(), deviceName: z.string().max(80).optional() }).strict(), await readBody(req));
      throttleIp(req);
      const hash = await tokenHash(b.token);
      const t = await store.takeOneTimeToken(hash, "magic", nowMs());
      const u = t ? users.get(t.userId) : undefined;
      const tenant = t ? tenants.get(t.tenantId) : undefined;
      if (!t || !u || !tenant?.allowMagicLinks) throw new HttpError(400, BAD_LINK, { status: "invalid_link" });
      const now = nowMs();
      if (!u.emailVerifiedAt) {
        users.set(u.id, { ...u, emailVerifiedAt: new Date(now).toISOString() });
        saveUsers();
      }
      let second = false;
      if (u.totpSecretB32 && b.totp) {
        const last = await store.getTotpCounter(u.id);
        const v = await verifyTotpCode(u.totpSecretB32, b.totp, { nowMs: now, ...(last !== undefined ? { minCounter: last } : {}) });
        if (v.ok && (await store.advanceTotpCounter(u.id, v.counter))) second = true;
      }
      const ip = clientIp(req);
      const windowMs = cfg.failedAttemptWindowSeconds * 1000;
      const failKey = `${t.tenantId}|${u.email.toLowerCase()}`;
      await finishAuth(req, res, {
        tenant, user: users.get(u.id), email: u.email, primary: true, second, passkeyRegression: false, passkeyUsed: null, method: "magic-link",
        recentFails: Math.max(await store.countFailures(failKey, now, windowMs), await store.countFailures(`ip|${ip}`, now, windowMs)), failKey, windowMs, now, ip,
        geo: undefined, asn: undefined, drift: undefined, deviceName: b.deviceName,
      });
      // A step-up (an admin who still owes a second factor) does not use up the link: the user can try again with a code.
      if (res.statusCode === 401) await store.putOneTimeToken(hash, t);
    }],
  ]);
  for (const k of emailRoutes.keys()) KNOWN_ROUTES.add(k);

  /* ───────── refresh rotation ───────── */

  type RotateOutcome =
    | { kind: "ok"; family: SessionFamily; refreshToken: string; generation: number; tenant: TenantPolicy; user: UserRecord }
    | { kind: "reuse"; family: SessionFamily }
    | { kind: "dead"; reason: "unknown_token" | "revoked" | "expired" }
    | { kind: "dpop_required"; presented: boolean };

  /**
   * Rotates a refresh token. Read, decide, then write only if nobody changed the family meanwhile; otherwise decide again from the
   * new state. This is what stops two parallel uses of one token from both succeeding. `forClient` restricts it to families issued to
   * one OIDC client (and refuses those families when it is absent), so a client's refresh token cannot be used on the native endpoint.
   */
  async function rotateByToken(req: IncomingMessage, refreshToken: string, hint?: string, forClient?: string): Promise<RotateOutcome> {
    const hash = hex(await sha256(refreshToken));
    const familyId = (await store.familyIdForToken(hash)) ?? hint;
    if (!familyId) return { kind: "dead", reason: "unknown_token" };
    for (let attempt = 0; attempt < 5; attempt++) {
      const family = await store.getFamily(familyId);
      if (!family || family.clientId !== forClient) return { kind: "dead", reason: "unknown_token" };
      const tenant = tenants.get(family.tenantId);
      const user = users.get(family.userId);
      if (!tenant || !user) return { kind: "dead", reason: "unknown_token" };
      // A family bound to a key also needs proof of that key to refresh.
      if (family.boundJkt && family.status === "active") {
        const proof = await checkDpopHeader(req);
        if (!proof.valid || proof.jkt !== family.boundJkt) {
          audit("auth.rotate.dpop_rejected", { tenantId: family.tenantId, subject: family.userId, detail: { familyId: family.familyId, presented: proof.presented } });
          return { kind: "dpop_required", presented: proof.presented };
        }
      }
      const r = await rotateRefreshTokenFamily(family, refreshToken, nowMs(), { reuseGraceMs: family.boundJkt ? cfg.refreshReuseGraceSeconds * 1000 : 0 });
      if (r.family !== family && !(await store.compareAndSetFamily(family, r.family))) continue;
      if (!r.ok) {
        if (r.reason === "reuse_detected") {
          audit("auth.family.reuse_detected", { tenantId: family.tenantId, subject: family.userId, detail: { familyId: family.familyId, generation: family.currentGeneration, code: "AV-104", ...(family.clientId ? { clientId: family.clientId } : {}) } });
          return { kind: "reuse", family };
        }
        return { kind: "dead", reason: r.reason === "revoked" ? "revoked" : r.reason === "expired" ? "expired" : "unknown_token" };
      }
      if (r.graceUsed) audit("auth.rotate.grace_used", { tenantId: family.tenantId, subject: family.userId, detail: { familyId: family.familyId, generation: r.generation } });
      return { kind: "ok", family: r.family, refreshToken: r.refreshToken, generation: r.generation, tenant, user };
    }
    throw new HttpError(503, "the session family is changing too quickly; try again");
  }

  async function rotate(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = parse(z.object({ refreshToken: z.string().max(200), familyId: z.string().max(80).optional() }).strict(), await readBody(req));
    throttleIp(req);
    const r = await rotateByToken(req, body.refreshToken, body.familyId);
    if (r.kind === "dpop_required") throw new HttpError(401, r.presented ? "the DPoP proof is not from the key this session is bound to" : "this session is bound to a key: a DPoP proof is required", { status: "dpop_required" });
    if (r.kind === "reuse") return send(req, res, 409, { status: "family_revoked", reason: "reuse_detected", message: "AV-104: a refresh token that was already used was presented; every session in this family is now revoked", familyId: r.family.familyId });
    if (r.kind === "dead") throw new HttpError(401, r.reason === "revoked" ? "this session family has been revoked" : r.reason === "expired" ? "the session has expired" : "unknown refresh token", { status: r.reason });
    const next = await issueNextAccessToken({ issuer: (await K()).issuer, family: r.family, accessTtlSeconds: r.tenant.sessionTtlSeconds, nowMs: nowMs() });
    audit("auth.rotate", { tenantId: r.family.tenantId, subject: r.family.userId, detail: { familyId: r.family.familyId, generation: r.generation } });
    send(req, res, 200, { status: "ok", sessionToken: next.sessionToken, refreshToken: r.refreshToken, generation: r.generation, expiresIn: r.tenant.sessionTtlSeconds, claims: next.claims, family: familyView(r.family) });
  }

  const base = (req: IncomingMessage): string => cfg.publicUrl?.replace(/\/$/, "") ?? `http://${req.headers.host ?? "localhost"}`;
  const oidcHandle = createOidcHandler({
    cfg, root: ws.root, store, nowMs, K, tenants, users, base, requestUrl, send, cors, readRaw, readBody, throttleIp, audit, checkDpopHeader, rotateByToken, replay, clientIp,
  });

  /* ───────── generic token verification ───────── */

  async function verifyAnyToken(token: string, scope?: string): Promise<Record<string, unknown>> {
    const kind = tokenKind(token);
    if (kind === "apiKey") {
      const r = await verifyScopedApiKey(token, keys(), { nowMs: nowMs(), limiter, ...(scope ? { requiredScope: scope } : {}) });
      return r.ok ? { kind, valid: true, key: keyView(r.record) } : { kind, valid: false, reason: r.reason, message: r.message, ...(r.retryAfterMs ? { retryAfterMs: r.retryAfterMs } : {}) };
    }
    if (kind === "impersonation") {
      const v = await verifyImpersonationSeal(token, (await K()).keys, nowMs());
      return v.ok ? { kind, valid: true, claims: v.claims, secondsLeft: v.secondsLeft } : { kind, valid: false, reason: v.reason, message: v.message };
    }
    if (kind === "session" || kind === "admin") {
      const t = await verifySignedToken<{ exp?: number; fam?: string }>(TOKEN_PREFIX[kind], token, (await K()).keys);
      if (!t.ok) return { kind, valid: false, reason: t.reason, message: t.reason === "bad_signature" ? "the signature is not ours" : "malformed token" };
      if (typeof t.payload.exp === "number" && t.payload.exp * 1000 <= nowMs()) return { kind, valid: false, reason: "expired", message: "the token has expired", claims: t.payload };
      if (kind === "session") {
        const f = t.payload.fam ? await store.getFamily(t.payload.fam) : undefined;
        if (f && f.status !== "active") return { kind, valid: false, reason: "session_revoked", message: `the session family is ${f.status}`, claims: t.payload };
        return { kind, valid: true, claims: t.payload, note: "signature and expiry only: a bound session also needs a DPoP proof (POST /api/auth/dpop-verify)" };
      }
      return { kind, valid: true, claims: t.payload };
    }
    return { kind: kind ?? "unknown", valid: false, reason: "unverifiable", message: kind === "refresh" ? "refresh tokens are opaque and are checked by rotating them" : kind === "dpop" ? "a DPoP proof is checked with the request it accompanies" : "not an Authvex token", claims: peekTokenPayload(token) };
  }

  function serveStatic(req: IncomingMessage, res: ServerResponse, path: string): void {
    if (!studioDir) {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      return void res.end(`Authvex ${options.version ?? ""} is running.\nAPI: ${publicBase()}/api/health\nThe Studio is not bundled in this build.\n`);
    }
    let rel: string;
    try {
      rel = normalize(decodeURIComponent(path)).replace(/^[/\\]+/, "");
    } catch {
      throw new HttpError(400, "bad path");
    }
    if (rel === "" || rel.endsWith("/") || rel.endsWith("\\")) rel += "index.html";
    let file = resolve(studioDir, rel);
    if (file !== studioDir && !file.startsWith(studioDir + sep)) throw new HttpError(403, "forbidden");
    if (!existsSync(file) || !statSync(file).isFile()) {
      const alt = `${file}.html`;
      if (existsSync(alt) && statSync(alt).isFile()) file = alt;
      else {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        return void res.end("not found");
      }
    }
    const immutable = file.includes(`${sep}_next${sep}static${sep}`);
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream", "cache-control": immutable ? "public, max-age=31536000, immutable" : "no-cache", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" });
    res.end(req.method === "HEAD" ? undefined : readFileSync(file));
  }

  return server;
}
