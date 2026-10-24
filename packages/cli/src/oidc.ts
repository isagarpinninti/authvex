import { createHash, timingSafeEqual, type webcrypto } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { dirname, join } from "node:path";
import { z } from "zod";
import {
  hex, halfHash, issueNextAccessToken, issueSessionBundle, revokeFamily, sha256, signJwt, verifyDpopSessionRequest, verifyJwt, verifyPkce, isValidCodeChallenge,
  type ReplayCache, type SessionFamily, type Store, type TenantPolicy, type UserRecord,
} from "@authvex/core";
import { writeJsonAtomic, type AuthvexConfig } from "./config";
import { HttpError } from "./http";
import type { KeyringState } from "./keyring";

export const OIDC_SCOPES = ["openid", "profile", "email", "offline_access"] as const;
const FORBIDDEN_SCHEMES = new Set(["javascript:", "data:", "file:", "vbscript:", "blob:", "about:", "ftp:", "ws:", "wss:"]);

/** https, an http loopback address (native apps and local development), or a custom app scheme such as `myapp://callback`. No fragments. */
export function isAllowedRedirectUri(u: string): boolean {
  if (u.includes("#")) return false;
  let p: URL;
  try {
    p = new URL(u);
  } catch {
    return false;
  }
  if (p.protocol === "https:") return true;
  if (p.protocol === "http:") return ["localhost", "127.0.0.1", "[::1]"].includes(p.hostname);
  return !FORBIDDEN_SCHEMES.has(p.protocol);
}
const redirectUri = z.string().url().refine(isAllowedRedirectUri, "use https, an http loopback address, or a custom app scheme, without a fragment");

export const ClientSchema = z
  .object({
    clientId: z.string().regex(/^cl_[A-Za-z0-9_-]{6,40}$/),
    name: z.string().min(1).max(80),
    tenantId: z.string().regex(/^[a-z][a-z0-9_-]{0,47}$/),
    type: z.enum(["public", "confidential"]),
    /** SHA-256 of the client secret (the secret is shown once). Confidential clients only. */
    secretHash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
    redirectUris: z.array(redirectUri).min(1).max(20),
    allowedScopes: z.array(z.enum(OIDC_SCOPES)).min(1).default([...OIDC_SCOPES]),
    postLogoutRedirectUris: z.array(redirectUri).max(20).default([]),
  })
  .strict()
  .superRefine((c, ctx) => {
    if (c.type === "confidential" && !c.secretHash) ctx.addIssue({ code: "custom", path: ["secretHash"], message: "a confidential client needs a secret" });
    if (c.type === "public" && c.secretHash) ctx.addIssue({ code: "custom", path: ["secretHash"], message: "a public client has no secret" });
    if (!c.allowedScopes.includes("openid")) ctx.addIssue({ code: "custom", path: ["allowedScopes"], message: "openid must be allowed" });
  });
export type OidcClient = z.infer<typeof ClientSchema>;

export const clientsPath = (root: string, cfg: AuthvexConfig): string => join(root, cfg.oidc.clients);

export function readClients(path: string): OidcClient[] {
  if (!existsSync(path)) return [];
  const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (!Array.isArray(raw)) throw new Error(`${path}: expected an array of clients`);
  const seen = new Set<string>();
  return raw.map((c, i) => {
    const p = ClientSchema.safeParse(c);
    if (!p.success) throw new Error(`${path}[${i}]: ${p.error.issues.map((x) => `${x.path.join(".")}: ${x.message}`).join("; ")}`);
    if (seen.has(p.data.clientId)) throw new Error(`${path}: client ${p.data.clientId} is defined twice`);
    seen.add(p.data.clientId);
    return p.data;
  });
}

export function writeClients(path: string, clients: OidcClient[]): void {
  mkdirSync(dirname(path), { recursive: true });
  writeJsonAtomic(path, clients, 0o600);
}

const sha256hex = (s: string): string => createHash("sha256").update(s).digest("hex");

export function newClientSecret(): { secret: string; hash: string } {
  const secret = `cs_${hex(globalThis.crypto.getRandomValues(new Uint8Array(32)))}`;
  return { secret, hash: sha256hex(secret) };
}

export function newClientId(): string {
  return `cl_${hex(globalThis.crypto.getRandomValues(new Uint8Array(8)))}`;
}

const equalHex = (a: string, b: string): boolean => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export type RotateOutcome =
  | { kind: "ok"; family: SessionFamily; refreshToken: string; generation: number; tenant: TenantPolicy; user: UserRecord }
  | { kind: "reuse"; family: SessionFamily }
  | { kind: "dead"; reason: "unknown_token" | "revoked" | "expired" }
  | { kind: "dpop_required"; presented: boolean };

export interface OidcDeps {
  cfg: AuthvexConfig;
  root: string;
  store: Store;
  nowMs(): number;
  K(): Promise<KeyringState>;
  tenants: Map<string, TenantPolicy>;
  users: Map<string, UserRecord>;
  base(req: IncomingMessage): string;
  requestUrl(req: IncomingMessage): string;
  send(req: IncomingMessage, res: ServerResponse, status: number, body: unknown): void;
  cors(req: IncomingMessage): Record<string, string>;
  readRaw(req: IncomingMessage): Promise<string>;
  readBody(req: IncomingMessage): Promise<unknown>;
  throttleIp(req: IncomingMessage): void;
  audit(type: string, info?: { tenantId?: string; actor?: string; subject?: string; detail?: Record<string, unknown> }): void;
  checkDpopHeader(req: IncomingMessage): Promise<{ presented: boolean; valid: boolean; jkt?: string; jwkHeader?: JsonWebKey; message?: string }>;
  rotateByToken(req: IncomingMessage, token: string, hint?: string, forClient?: string): Promise<RotateOutcome>;
  replay: ReplayCache;
  clientIp(req: IncomingMessage): string;
}

type JsonWebKey = webcrypto.JsonWebKey;

const CODE_TTL_MS = 60_000;
const REQUEST_TTL_MS = 10 * 60_000;
const tokenOf = (prefix: string): string => `${prefix}${hex(globalThis.crypto.getRandomValues(new Uint8Array(32)))}`;
const hashOf = async (t: string): Promise<string> => hex(await sha256(t));
const NO_STORE = { "cache-control": "no-store", pragma: "no-cache" };

/**
 * An OpenID Connect provider per tenant: discovery, authorization (code flow with mandatory PKCE S256), token (authorization code and
 * refresh token, optionally DPoP-bound), userinfo, end-session and a JWKS. Issuer: `<base>/oidc/<tenantId>`.
 */
export function createOidcHandler(d: OidcDeps): (req: IncomingMessage, res: ServerResponse, path: string, method: string, url: URL) => Promise<boolean> {
  let cache: { mtime: number; clients: OidcClient[] } = { mtime: -1, clients: [] };
  const clients = (): OidcClient[] => {
    const p = clientsPath(d.root, d.cfg);
    const m = existsSync(p) ? statSync(p).mtimeMs : 0;
    if (m !== cache.mtime) cache = { mtime: m, clients: readClients(p) };
    return cache.clients;
  };
  const issuerOf = (req: IncomingMessage, tenantId: string): string => `${d.base(req)}/oidc/${tenantId}`;
  const signIn = (req: IncomingMessage): string => d.cfg.oidc.signInUrl ?? `${d.base(req)}/signin/`;

  const json = (req: IncomingMessage, res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void => {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff", ...NO_STORE, ...d.cors(req), ...extra });
    res.end(JSON.stringify(body));
  };
  const oauthError = (req: IncomingMessage, res: ServerResponse, status: number, error: string, description: string, extra: Record<string, string> = {}): void =>
    json(req, res, status, { error, error_description: description }, extra);
  const plainError = (res: ServerResponse, status: number, text: string): void => {
    res.writeHead(status, { "content-type": "text/plain; charset=utf-8", ...NO_STORE });
    res.end(text);
  };
  const redirect = (res: ServerResponse, to: string): void => {
    res.writeHead(302, { location: to, ...NO_STORE });
    res.end();
  };
  const withParams = (uri: string, params: Record<string, string | undefined>): string => {
    const u = new URL(uri);
    for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
    return u.toString();
  };

  async function authenticateClient(req: IncomingMessage, form: URLSearchParams, tenantId: string): Promise<{ client: OidcClient } | { error: "invalid_client"; basic: boolean }> {
    let id = form.get("client_id") ?? "";
    let secret = form.get("client_secret");
    const auth = req.headers.authorization;
    const basic = typeof auth === "string" && auth.startsWith("Basic ");
    if (basic) {
      const raw = Buffer.from((auth as string).slice(6), "base64").toString("utf8");
      const i = raw.indexOf(":");
      if (i > 0) {
        id = decodeURIComponent(raw.slice(0, i).replace(/\+/g, " "));
        secret = decodeURIComponent(raw.slice(i + 1).replace(/\+/g, " "));
      }
    }
    const client = clients().find((c) => c.clientId === id && c.tenantId === tenantId);
    const failKey = `oidc|client|${id}`;
    const now = d.nowMs();
    if ((await d.store.countFailures(failKey, now, 15 * 60_000)) >= 10) return { error: "invalid_client", basic };
    if (!client) {
      await d.store.recordFailure(failKey, now, 15 * 60_000);
      return { error: "invalid_client", basic };
    }
    if (client.type === "confidential") {
      const ok = secret !== null && secret !== undefined && client.secretHash !== undefined && equalHex(sha256hex(secret), client.secretHash);
      if (!ok) {
        await d.store.recordFailure(failKey, now, 15 * 60_000);
        return { error: "invalid_client", basic };
      }
    }
    return { client };
  }

  function userClaims(user: UserRecord, scope: string[]): Record<string, unknown> {
    return { sub: user.id, ...(scope.includes("email") ? { email: user.email, email_verified: user.emailVerifiedAt !== undefined } : {}), ...(scope.includes("profile") ? { name: user.name } : {}) };
  }

  return async function handle(req, res, path, method, url): Promise<boolean> {
    if (method === "OPTIONS") return false;

    /* ── sign-in page support (public) ── */
    if (path === "/api/oidc/request" && method === "GET") {
      const id = url.searchParams.get("id") ?? "";
      const hash = await hashOf(id);
      const t = await d.store.takeOneTimeToken(hash, "oidc_req", d.nowMs());
      if (!t) return void d.send(req, res, 404, { error: "that sign-in request is unknown, used or expired" }), true;
      await d.store.putOneTimeToken(hash, t);
      const client = clients().find((c) => c.clientId === t.data?.["clientId"]);
      d.send(req, res, 200, { clientName: client?.name ?? "an application", tenantId: t.tenantId, scope: String(t.data?.["scope"] ?? "").split(" "), loginHint: t.data?.["loginHint"] ?? null });
      return true;
    }
    if (path === "/api/oidc/complete" && method === "POST") {
      d.throttleIp(req);
      const b = z.object({ request: z.string().max(200), sessionToken: z.string().max(4096) }).strict().safeParse(await d.readBody(req));
      if (!b.success) throw new HttpError(400, "request and sessionToken are required");
      const now = d.nowMs();
      const t = await d.store.takeOneTimeToken(await hashOf(b.data.request), "oidc_req", now);
      if (!t) throw new HttpError(400, "that sign-in request is unknown, used or expired");
      const k = await d.K();
      const proof = req.headers["dpop"];
      const v = await verifyDpopSessionRequest({ sessionToken: b.data.sessionToken, method: "POST", url: d.requestUrl(req), issuerPublicKeyJwk: k.keys, nowMs: now, replayCache: d.replay, ...(typeof proof === "string" ? { dpopProof: proof } : {}) });
      if (!v.ok) throw new HttpError(401, v.message, { reason: v.reason });
      const fam = await d.store.getFamily(v.claims.fam);
      if (!fam || fam.status !== "active" || fam.clientId !== undefined || v.claims.tid !== t.tenantId) throw new HttpError(401, "that session cannot authorize this request");
      const code = tokenOf("ath_oc_");
      await d.store.putOneTimeToken(await hashOf(code), {
        purpose: "oidc_code", userId: v.claims.sub, tenantId: t.tenantId, expires: now + CODE_TTL_MS,
        data: { ...t.data, authTime: Math.floor(now / 1000) },
      });
      // The sign-in page's own session has done its job; it is not kept as a hidden single-sign-on session.
      await d.store.compareAndSetFamily(fam, revokeFamily(fam, now));
      d.audit("oidc.authorized", { tenantId: t.tenantId, subject: v.claims.sub, detail: { clientId: t.data?.["clientId"], scope: t.data?.["scope"] } });
      d.send(req, res, 200, { redirectTo: withParams(String(t.data?.["redirectUri"]), { code, state: t.data?.["state"] as string | undefined, iss: issuerOf(req, t.tenantId) }) });
      return true;
    }

    const m = /^\/oidc\/([a-z][a-z0-9_-]{0,47})(\/.*)?$/.exec(path);
    if (!m) return false;
    const tenantId = m[1] as string;
    const sub = m[2] ?? "";
    const tenant = d.tenants.get(tenantId);
    if (!tenant) return void plainError(res, 404, "no such tenant"), true;
    const iss = issuerOf(req, tenantId);

    /* ── discovery ── */
    if (sub === "/.well-known/openid-configuration" && method === "GET") {
      const b = d.base(req);
      json(req, res, 200, {
        issuer: iss, authorization_endpoint: `${iss}/authorize`, token_endpoint: `${iss}/token`, userinfo_endpoint: `${iss}/userinfo`, end_session_endpoint: `${iss}/end_session`, jwks_uri: `${b}/.well-known/jwks.json`,
        response_types_supported: ["code"], response_modes_supported: ["query"], grant_types_supported: ["authorization_code", "refresh_token"], subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"], scopes_supported: [...OIDC_SCOPES], token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
        code_challenge_methods_supported: ["S256"], dpop_signing_alg_values_supported: ["ES256"], claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "sid", "email", "email_verified", "name"],
        authorization_response_iss_parameter_supported: true, request_parameter_supported: false, request_uri_parameter_supported: false,
      }, { "cache-control": "public, max-age=300" });
      return true;
    }

    /* ── authorization ── */
    if (sub === "/authorize" && method === "GET") {
      const q = url.searchParams;
      const client = clients().find((c) => c.clientId === q.get("client_id") && c.tenantId === tenantId);
      const ru = q.get("redirect_uri");
      // Until the client and redirect URI are known to match, an error is shown here, never sent to a URI an attacker may have chosen.
      if (!client || !ru || !client.redirectUris.includes(ru)) return void plainError(res, 400, "invalid client_id or redirect_uri"), true;
      const state = q.get("state") ?? undefined;
      const fail = (error: string, description: string): true => (redirect(res, withParams(ru, { error, error_description: description, state, iss })), true);
      if (q.has("request") || q.has("request_uri")) return fail("request_not_supported", "request objects are not supported");
      if (q.get("response_type") !== "code") return fail("unsupported_response_type", "only response_type=code is supported");
      const scopes = (q.get("scope") ?? "").split(/\s+/).filter(Boolean);
      if (!scopes.includes("openid")) return fail("invalid_scope", "the openid scope is required");
      if (scopes.some((s) => !(client.allowedScopes as string[]).includes(s))) return fail("invalid_scope", "a requested scope is not allowed for this client");
      const challenge = q.get("code_challenge") ?? "";
      if (!challenge || (q.get("code_challenge_method") ?? "plain") !== "S256" || !isValidCodeChallenge(challenge)) return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
      if ((q.get("prompt") ?? "").split(" ").includes("none")) return fail("login_required", "there is no single-sign-on session: the user must sign in");
      const id = tokenOf("ath_oq_");
      await d.store.putOneTimeToken(await hashOf(id), {
        purpose: "oidc_req", userId: "", tenantId, expires: d.nowMs() + REQUEST_TTL_MS,
        data: { clientId: client.clientId, redirectUri: ru, scope: scopes.join(" "), codeChallenge: challenge, ...(state ? { state } : {}), ...(q.get("nonce") ? { nonce: q.get("nonce") } : {}), ...(q.get("login_hint") ? { loginHint: q.get("login_hint") } : {}) },
      });
      redirect(res, withParams(signIn(req), { request: id }));
      return true;
    }

    /* ── token ── */
    if (sub === "/token" && method === "POST") {
      d.throttleIp(req);
      const form = new URLSearchParams(await d.readRaw(req));
      const auth = await authenticateClient(req, form, tenantId);
      if ("error" in auth) return void oauthError(req, res, 401, "invalid_client", "client authentication failed", auth.basic ? { "www-authenticate": 'Basic realm="authvex"' } : {}), true;
      const client = auth.client;
      const now = d.nowMs();
      const grant = form.get("grant_type");

      if (grant === "authorization_code") {
        const code = form.get("code") ?? "";
        const hash = await hashOf(code);
        const rec = await d.store.takeOneTimeToken(hash, "oidc_code", now);
        if (!rec) {
          // A code used a second time means it may have been stolen: revoke what the first use produced (RFC 6749 section 4.1.2).
          const used = await d.store.takeOneTimeToken(`used:${hash}`, "oidc_code_used", now);
          const fam = used ? await d.store.getFamily(String(used.data?.["familyId"])) : undefined;
          if (fam && (await d.store.compareAndSetFamily(fam, revokeFamily(fam, now)))) d.audit("oidc.code_reuse", { tenantId, subject: fam.userId, detail: { clientId: client.clientId, familyId: fam.familyId } });
          return void oauthError(req, res, 400, "invalid_grant", "the authorization code is invalid, expired or already used"), true;
        }
        const data = rec.data ?? {};
        if (data["clientId"] !== client.clientId || data["redirectUri"] !== form.get("redirect_uri")) return void oauthError(req, res, 400, "invalid_grant", "the code was not issued to this client and redirect URI"), true;
        if (!(await verifyPkce(form.get("code_verifier") ?? "", String(data["codeChallenge"])))) return void oauthError(req, res, 400, "invalid_grant", "the PKCE code_verifier does not match"), true;
        const user = d.users.get(rec.userId);
        if (!user) return void oauthError(req, res, 400, "invalid_grant", "the user no longer exists"), true;
        const proof = await d.checkDpopHeader(req);
        if ((tenant.requireDpopHardwareBinding && !proof.valid) || (proof.presented && !proof.valid)) return void oauthError(req, res, 400, "invalid_dpop_proof", proof.presented ? `the DPoP proof is invalid: ${proof.message ?? "it did not verify"}` : "this tenant requires a DPoP proof at the token endpoint"), true;
        const scope = String(data["scope"]);
        const scopes = scope.split(" ");
        const k = await d.K();
        const bundle = await issueSessionBundle({
          issuer: k.issuer, userId: user.id, tenantId, accessTtlSeconds: tenant.sessionTtlSeconds, refreshTtlSeconds: tenant.refreshTtlSeconds, nowMs: now, client: { clientId: client.clientId, scope },
          device: { name: client.name, ip: d.clientIp(req) }, ...(proof.valid && proof.jwkHeader ? { clientPublicKeyJwk: proof.jwkHeader } : {}),
        });
        await d.store.createFamily(bundle.family);
        await d.store.putOneTimeToken(`used:${hash}`, { purpose: "oidc_code_used", userId: user.id, tenantId, expires: now + 10 * 60_000, data: { familyId: bundle.family.familyId } });
        const idToken = await signJwt(
          { iss, aud: client.clientId, azp: client.clientId, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + tenant.sessionTtlSeconds, auth_time: data["authTime"], ...(data["nonce"] ? { nonce: data["nonce"] } : {}), at_hash: await halfHash(bundle.sessionToken), sid: bundle.family.familyId, ...userClaims(user, scopes) },
          k.issuer,
        );
        d.audit("oidc.token_issued", { tenantId, subject: user.id, detail: { clientId: client.clientId, familyId: bundle.family.familyId, bound: bundle.family.boundJkt !== undefined, scope } });
        json(req, res, 200, { access_token: bundle.sessionToken, token_type: bundle.claims.cnf ? "DPoP" : "Bearer", expires_in: tenant.sessionTtlSeconds, id_token: idToken, scope, ...(scopes.includes("offline_access") ? { refresh_token: bundle.refreshToken } : {}) });
        return true;
      }

      if (grant === "refresh_token") {
        const presented = form.get("refresh_token") ?? "";
        // Check what is asked for before rotating: a refused request must not use up the client's refresh token.
        const known = await d.store.familyIdForToken(await hashOf(presented));
        const fam = known ? await d.store.getFamily(known) : undefined;
        const asked = (form.get("scope") ?? "").split(/\s+/).filter(Boolean);
        if (fam && fam.clientId === client.clientId && asked.some((s) => !(fam.scope ?? "").split(" ").includes(s))) return void oauthError(req, res, 400, "invalid_scope", "a refresh cannot widen the granted scope"), true;
        const r = await d.rotateByToken(req, presented, undefined, client.clientId);
        if (r.kind === "dpop_required") return void oauthError(req, res, 400, "invalid_dpop_proof", "this refresh token is bound to a key: send a DPoP proof from it"), true;
        if (r.kind === "reuse") return void oauthError(req, res, 400, "invalid_grant", "this refresh token was already used: the session has been revoked"), true;
        if (r.kind === "dead") return void oauthError(req, res, 400, "invalid_grant", "the refresh token is invalid, expired or revoked"), true;
        if (r.family.tenantId !== tenantId) return void oauthError(req, res, 400, "invalid_grant", "the refresh token belongs to another tenant"), true;
        const next = await issueNextAccessToken({ issuer: (await d.K()).issuer, family: r.family, accessTtlSeconds: tenant.sessionTtlSeconds, nowMs: now });
        d.audit("oidc.refreshed", { tenantId, subject: r.user.id, detail: { clientId: client.clientId, familyId: r.family.familyId, generation: r.generation } });
        json(req, res, 200, { access_token: next.sessionToken, token_type: next.claims.cnf ? "DPoP" : "Bearer", expires_in: tenant.sessionTtlSeconds, refresh_token: r.refreshToken, scope: r.family.scope });
        return true;
      }
      return void oauthError(req, res, 400, "unsupported_grant_type", "use authorization_code or refresh_token"), true;
    }

    /* ── userinfo ── */
    if (sub === "/userinfo" && (method === "GET" || method === "POST")) {
      const header = req.headers.authorization ?? "";
      const scheme = header.startsWith("DPoP ") ? "DPoP" : header.startsWith("Bearer ") ? "Bearer" : "";
      const bad = (status: number, error: string, description: string): true => (json(req, res, status, { error, error_description: description }, { "www-authenticate": `${scheme || "Bearer"} error="${error}", error_description="${description}"` }), true);
      if (!scheme) return bad(401, "invalid_request", "send the access token in the Authorization header");
      const token = header.slice(scheme.length + 1);
      const proof = req.headers["dpop"];
      const v = await verifyDpopSessionRequest({ sessionToken: token, method, url: d.requestUrl(req), issuerPublicKeyJwk: (await d.K()).keys, nowMs: d.nowMs(), replayCache: d.replay, ...(typeof proof === "string" ? { dpopProof: proof } : {}) });
      if (!v.ok) return bad(401, "invalid_token", v.message);
      if (v.bound && scheme !== "DPoP") return bad(401, "invalid_token", "a key-bound token must be sent with the DPoP scheme");
      const fam = await d.store.getFamily(v.claims.fam);
      if (!fam || fam.status !== "active" || v.claims.tid !== tenantId || !v.claims.cid) return bad(401, "invalid_token", "the token is not valid for this issuer");
      const scopes = (v.claims.scp ?? "").split(" ");
      if (!scopes.includes("openid")) return bad(403, "insufficient_scope", "the token has no openid scope");
      const user = d.users.get(v.claims.sub);
      if (!user) return bad(401, "invalid_token", "the user no longer exists");
      json(req, res, 200, userClaims(user, scopes));
      return true;
    }

    /* ── end session ── */
    if (sub === "/end_session" && method === "GET") {
      const q = url.searchParams;
      const hint = q.get("id_token_hint");
      let sid: string | undefined;
      let clientId: string | undefined;
      if (hint) {
        const r = await verifyJwt(hint, (await d.K()).keys, { issuer: iss, nowMs: d.nowMs(), clockSkewSeconds: 10 * 365 * 86_400 });
        if (r.ok) {
          sid = r.claims["sid"] as string | undefined;
          clientId = r.claims["aud"] as string | undefined;
        }
      }
      if (sid) {
        const fam = await d.store.getFamily(sid);
        if (fam && fam.tenantId === tenantId && fam.clientId === clientId && (await d.store.compareAndSetFamily(fam, revokeFamily(fam, d.nowMs())))) d.audit("oidc.logout", { tenantId, subject: fam.userId, detail: { clientId, familyId: fam.familyId } });
      }
      const client = clients().find((c) => c.clientId === clientId && c.tenantId === tenantId);
      const back = q.get("post_logout_redirect_uri");
      if (client && back && client.postLogoutRedirectUris.includes(back)) return redirect(res, withParams(back, { state: q.get("state") ?? undefined })), true;
      json(req, res, 200, { status: "signed_out" });
      return true;
    }
    return false;
  };
}
