import type { Guard, GuardFailure, GuardRequest } from "./guard";
import type { SessionClaims } from "../session/dpopAndFamilies";

/** Thin wrappers that connect a `Guard` to a web framework. They only use the shapes below, so no framework is imported. */

const body = (f: GuardFailure): string => JSON.stringify({ error: f.error, message: f.message });
const headerOf = (h: Record<string, string | string[] | undefined> | undefined) => (name: string): string | undefined => {
  const v = h?.[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
};

/* ── Express and Connect ── */

interface NodeReq {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  authvex?: SessionClaims;
}
interface NodeRes {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(chunk?: string): unknown;
}

/** `app.use("/api", expressGuard(guard))`. On success `req.authvex` holds the session claims. */
export function expressGuard(guard: Guard) {
  return (req: NodeReq, res: NodeRes, next: (err?: unknown) => void): void => {
    const r: GuardRequest = { method: req.method ?? "GET", path: req.originalUrl ?? req.url ?? "/", header: headerOf(req.headers) };
    guard.authenticate(r).then(
      (out) => {
        if (out.ok) {
          req.authvex = out.claims;
          return next();
        }
        res.statusCode = out.status;
        if (out.wwwAuthenticate) res.setHeader("www-authenticate", out.wwwAuthenticate);
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.setHeader("cache-control", "no-store");
        res.end(body(out));
      },
      next,
    );
  };
}

/* ── Fastify ── */

interface FastifyReq {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  authvex?: SessionClaims;
}
interface FastifyReply {
  code(status: number): FastifyReply;
  header(name: string, value: string): FastifyReply;
  send(payload?: unknown): unknown;
}

/** `fastify.addHook("onRequest", fastifyGuard(guard))`. On success `request.authvex` holds the claims. */
export function fastifyGuard(guard: Guard) {
  return async (request: FastifyReq, reply: FastifyReply): Promise<unknown> => {
    const out = await guard.authenticate({ method: request.method, path: request.url, header: headerOf(request.headers) });
    if (out.ok) {
      request.authvex = out.claims;
      return undefined;
    }
    if (out.wwwAuthenticate) reply.header("www-authenticate", out.wwwAuthenticate);
    return reply.code(out.status).header("cache-control", "no-store").send({ error: out.error, message: out.message });
  };
}

/* ── Hono ── */

interface HonoContext {
  req: { method: string; url: string; header(name: string): string | undefined };
  set(key: "authvex", value: SessionClaims): void;
  json(body: unknown, status?: number, headers?: Record<string, string>): Response;
}

/** `app.use("/api/*", honoGuard(guard))`; read the claims with `c.get("authvex")`. Works on Workers, Deno, Bun and Node. */
export function honoGuard(guard: Guard) {
  return async (c: HonoContext, next: () => Promise<void>): Promise<Response | void> => {
    const out = await guard.authenticate({ method: c.req.method, url: c.req.url, path: "", header: (n) => c.req.header(n) });
    if (!out.ok) return c.json({ error: out.error, message: out.message }, out.status, { ...(out.wwwAuthenticate ? { "www-authenticate": out.wwwAuthenticate } : {}), "cache-control": "no-store" });
    c.set("authvex", out.claims);
    await next();
  };
}

/* ── fetch-style handlers: Next.js route handlers and middleware, Workers, Deno, Bun ── */

/**
 * `export const GET = withAuthvex(guard, async (req, claims) => Response.json({ hello: claims.sub }))`
 * Works with any `(Request) => Response` handler, including Next.js App Router route handlers.
 */
export function withAuthvex<Ctx = unknown>(guard: Guard, handler: (req: Request, claims: SessionClaims, ctx: Ctx) => Response | Promise<Response>) {
  return async (req: Request, ctx?: Ctx): Promise<Response> => {
    const out = await guard.authenticate({ method: req.method, url: req.url, path: "", header: (n) => req.headers.get(n) ?? undefined });
    if (!out.ok) return Response.json({ error: out.error, message: out.message }, { status: out.status, headers: { ...(out.wwwAuthenticate ? { "www-authenticate": out.wwwAuthenticate } : {}), "cache-control": "no-store" } });
    return handler(req, out.claims, ctx as Ctx);
  };
}
