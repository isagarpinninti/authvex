# Protecting your API

`@authvex/core` ships a framework-free guard and thin adapters. Nothing here imports a framework.

```ts
import { createGuard } from "@authvex/core";

const guard = createGuard({
  issuer: "https://id.example.com",      // the Authvex server
  baseUrl: "https://api.example.com",    // the origin clients call; DPoP proofs are bound to the exact URL
  requireBinding: true,                  // refuse sessions not bound to a device key
});
```

## Adapters

| Framework | Use | Claims land in |
| --- | --- | --- |
| Express / Connect | `app.use("/api", expressGuard(guard))` | `req.authvex` |
| Fastify | `app.addHook("onRequest", fastifyGuard(guard))` | `request.authvex` |
| Hono (Workers, Deno, Bun, Node) | `app.use("/api/*", honoGuard(guard))` | `c.get("authvex")` |
| Fetch handlers (Next.js route handlers, Workers) | `export const GET = withAuthvex(guard, async (req, claims) => Response.json({ sub: claims.sub }))` | second argument |

A failure answers 401 (or 403 for tenant, scope or permission) with `{ error, message }` and a `WWW-Authenticate: DPoP` challenge. 502 means the identity server could not be reached; nothing is let through in that case.

## Two modes

- `mode: "local"` (default): verifies the token signature and expiry against the issuer's JWKS, and the DPoP proof. No call per request. The JWKS is cached (`jwksTtlMs`, default 5 minutes) and refreshed when a token names an unknown key, at most every `jwksMinRefetchMs` (30 s), so a key rotation is followed and a flood of bad key ids is not. A session revoked on the server stays valid here until its access token expires.
- `mode: "introspect"`: asks `POST /api/auth/dpop-verify` each request. Revocation and role changes apply at once, and `permission: "invoices:read"` is enforced against the tenant's roles. Costs a round trip and counts against the server's rate limit.

## Options

`tenants`, `scope` (for OpenID access tokens), `trustProxy` (read `X-Forwarded-*` when `baseUrl` is not set; only behind a proxy you control), `replayCache` (share one across instances), `fetch`, `now`.

## Replay

In local mode each guard instance remembers proofs in memory for the proof lifetime. Several API instances can each accept one replay unless you pass a shared `replayCache`. Introspection mode uses the server's cache.

Tested against Express 5, Fastify 5 and Hono 4 in `interop/middleware.interop.test.ts`.
