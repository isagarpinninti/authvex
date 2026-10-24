import { DpopReplayCache, verifyDpopSessionRequest, type ReplayCache, type SessionClaims } from "../session/dpopAndFamilies";
import type { JwkSet } from "../session/tokens";

/**
 * Protects an API with Authvex sessions. This file is framework-free (only `fetch` and Web Crypto); `adapters.ts` has the thin
 * wrappers for Express, Fastify, Hono and fetch-style handlers (Next.js route handlers, Workers, Deno, Bun).
 *
 * Two ways to check a session:
 *  - `local` (default): verify the token's signature and expiry against the issuer's JWKS, and check the DPoP proof. Fast, no call per
 *    request. A session revoked on the server stays valid here until its access token expires (minutes).
 *  - `introspect`: ask the Authvex server on every request (`POST /api/auth/dpop-verify`). One round trip, but revocation and role
 *    changes take effect at once, and `permission` can be enforced against the tenant's RBAC.
 */

export interface GuardOptions {
  /** Base URL of the Authvex server, e.g. `https://id.example.com`. */
  issuer: string;
  mode?: "local" | "introspect";
  /** Reject sessions that are not bound to a client key. Default: false (the tenant's own setting still applies at sign-in). */
  requireBinding?: boolean;
  /** Only accept sessions of these tenants. */
  tenants?: string[];
  /** Require this scope in the token (OpenID Connect access tokens carry `scp`). */
  scope?: string;
  /** `introspect` mode only: a permission like `invoices:read` the user's role must grant in their tenant. */
  permission?: string;
  /**
   * The origin clients use to reach THIS API, e.g. `https://api.example.com`. A DPoP proof is bound to the exact URL the client
   * called, so behind a proxy set this rather than trusting the Host header.
   */
  baseUrl?: string;
  /** Trust `X-Forwarded-Proto` / `X-Forwarded-Host` when `baseUrl` is not set. Only behind a proxy you control. */
  trustProxy?: boolean;
  /** Remembers proofs already seen. Default: in memory (per process). Use a shared one when several instances serve the same API. */
  replayCache?: ReplayCache;
  /** How long a fetched JWKS is used before it is refreshed (default 5 minutes). */
  jwksTtlMs?: number;
  /** An unknown key id triggers a refresh, at most this often (default 30 seconds). */
  jwksMinRefetchMs?: number;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
}

export interface GuardRequest {
  method: string;
  /** The full URL the client called, if known. Otherwise `path` plus `baseUrl` (or the proxy headers) is used. */
  url?: string;
  /** Path and query, e.g. `/v1/invoices?limit=5`. */
  path: string;
  /** Case-insensitive header lookup. */
  header(name: string): string | undefined;
}

export type GuardFailure = { ok: false; status: 401 | 403 | 502; error: string; message: string; wwwAuthenticate: string };
export type GuardResult = { ok: true; claims: SessionClaims; bound: boolean } | GuardFailure;

export interface Guard {
  authenticate(req: GuardRequest): Promise<GuardResult>;
}

const failure = (status: 401 | 403 | 502, error: string, message: string): GuardFailure => ({
  ok: false, status, error, message,
  wwwAuthenticate: status === 401 ? `DPoP algs="ES256", error="${error === "missing_token" ? "invalid_request" : "invalid_token"}"${error === "missing_token" ? "" : `, error_description="${message.replace(/["\\]/g, " ").slice(0, 120)}"`}` : "",
});

/** Fetches and caches the issuer's JWKS, refreshing when a token names a key that is not in it (a rotation just happened). */
export function createJwksCache(opts: { issuer: string; fetch?: typeof globalThis.fetch; ttlMs?: number; minRefetchMs?: number; now?: () => number }) {
  const f = opts.fetch ?? globalThis.fetch;
  const now = opts.now ?? Date.now;
  const ttl = opts.ttlMs ?? 300_000;
  const minGap = opts.minRefetchMs ?? 30_000;
  const url = `${opts.issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
  let cached: { set: JwkSet; at: number } | null = null;
  let lastAttempt = 0;
  let inflight: Promise<JwkSet> | null = null;

  const load = async (): Promise<JwkSet> => {
    lastAttempt = now();
    const r = await f(url, { headers: { accept: "application/json" } });
    if (!r.ok) throw new Error(`JWKS fetch failed: ${r.status}`);
    const body = (await r.json()) as { keys?: unknown };
    if (!Array.isArray(body.keys)) throw new Error("JWKS has no keys array");
    cached = { set: { keys: body.keys as JwkSet["keys"] }, at: now() };
    return cached.set;
  };
  const refresh = (): Promise<JwkSet> => (inflight ??= load().finally(() => (inflight = null)));

  return {
    /** The key set to verify with. Pass the token's `kid` (if known) so an unknown one forces a bounded refresh. */
    async get(kid?: string): Promise<JwkSet> {
      if (!cached) return refresh();
      const stale = now() - cached.at > ttl;
      const unknown = kid !== undefined && !cached.set.keys.some((k) => k.kid === kid);
      if ((stale || unknown) && now() - lastAttempt >= (stale ? 0 : minGap)) {
        try {
          return await refresh();
        } catch (e) {
          if (stale && now() - cached.at > ttl * 6) throw e; // serve a stale set for a while rather than fail every request
        }
      }
      return cached.set;
    },
  };
}

const kidOf = (token: string): string | undefined => {
  try {
    const payload = token.split(".")[0]?.replace(/^ath_[a-z]+_/, "") ?? "";
    const json = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)))) as { kid?: unknown };
    return typeof json.kid === "string" ? json.kid : undefined;
  } catch {
    return undefined;
  }
};

export function createGuard(options: GuardOptions): Guard {
  const mode = options.mode ?? "local";
  const f = options.fetch ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const issuer = options.issuer.replace(/\/$/, "");
  const replay = options.replayCache ?? new DpopReplayCache();
  const jwks = createJwksCache({ issuer, ...(options.fetch ? { fetch: options.fetch } : {}), ...(options.jwksTtlMs !== undefined ? { ttlMs: options.jwksTtlMs } : {}), ...(options.jwksMinRefetchMs !== undefined ? { minRefetchMs: options.jwksMinRefetchMs } : {}), ...(options.now ? { now: options.now } : {}) });
  if (options.permission && mode !== "introspect") throw new Error('GuardOptions.permission needs mode "introspect": only the Authvex server knows the tenant\'s roles');
  if (!/^https?:\/\//.test(issuer)) throw new Error("GuardOptions.issuer must be an http(s) URL");

  const urlOf = (req: GuardRequest): string | null => {
    if (req.url) return req.url;
    if (options.baseUrl) return `${options.baseUrl.replace(/\/$/, "")}${req.path}`;
    const host = (options.trustProxy ? req.header("x-forwarded-host") : undefined) ?? req.header("host");
    const proto = (options.trustProxy ? req.header("x-forwarded-proto") : undefined) ?? "http";
    return host ? `${proto.split(",")[0]?.trim()}://${host.split(",")[0]?.trim()}${req.path}` : null;
  };

  return {
    async authenticate(req) {
      const auth = req.header("authorization");
      const m = auth ? /^(DPoP|Bearer) ([^\s]+)$/i.exec(auth) : null;
      if (!m) return failure(401, "missing_token", "send the session token as `Authorization: DPoP <token>` with a `DPoP` proof header");
      const token = m[2] as string;
      const proof = req.header("dpop");
      const url = urlOf(req);
      if (!url) return failure(401, "invalid_request", "cannot work out the URL the proof was made for; set `baseUrl`");

      if (mode === "introspect") {
        let r: Response;
        try {
          r = await f(`${issuer}/api/auth/dpop-verify`, {
            method: "POST", headers: { "content-type": "application/json" },
            body: JSON.stringify({ sessionToken: token, ...(proof ? { dpopProof: proof } : {}), method: req.method, url, ...(options.permission ? { requirePermission: options.permission } : {}) }),
          });
        } catch {
          return failure(502, "issuer_unreachable", "the identity server could not be reached");
        }
        const body = (await r.json().catch(() => ({}))) as { valid?: boolean; claims?: SessionClaims; bound?: boolean; reason?: string; message?: string };
        if (r.status >= 500) return failure(502, "issuer_error", "the identity server failed");
        if (r.status === 429) return failure(502, "issuer_busy", "the identity server is rate limiting this API");
        if (!body.valid || !body.claims) return failure(r.status === 403 ? 403 : 401, body.reason ?? "invalid_token", body.message ?? "the session is not valid");
        return check(body.claims, body.bound === true);
      }

      let keys: JwkSet;
      try {
        keys = await jwks.get(kidOf(token));
      } catch {
        return failure(502, "issuer_unreachable", "the identity server's keys could not be fetched");
      }
      const v = await verifyDpopSessionRequest({
        sessionToken: token, ...(proof ? { dpopProof: proof } : {}), method: req.method, url, issuerPublicKeyJwk: keys, nowMs: now(), replayCache: replay,
        ...(options.requireBinding ? { requireBinding: true } : {}),
      });
      if (!v.ok) return failure(401, v.reason, v.message);
      return check(v.claims, v.bound);
    },
  };

  function check(claims: SessionClaims, bound: boolean): GuardResult {
    if (options.tenants && !options.tenants.includes(claims.tid)) return failure(403, "wrong_tenant", "this session belongs to a tenant that may not use this API");
    if (options.scope && !(claims.scp ?? "").split(" ").includes(options.scope)) return failure(403, "insufficient_scope", `the token lacks the "${options.scope}" scope`);
    if (options.requireBinding && !bound) return failure(401, "not_bound", "this API requires a session bound to a client key");
    return { ok: true, claims, bound };
  }
}
