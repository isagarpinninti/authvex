import { afterEach, describe, expect, it } from "vitest";
import { DEMO, deviceKey, startHarness, type Harness } from "./helpers";
import { Registry, routeLabel } from "../src/metrics";

const LIN = "linear_ops_workspace";
const TOKEN = "scrape-token-0123456789";
let h: Harness | undefined;
afterEach(async () => {
  await h?.close();
  h = undefined;
  delete process.env["AUTHVEX_METRICS_TOKEN"];
});

const scrape = async (token: string | null = TOKEN): Promise<{ status: number; text: string; type: string }> => {
  const r = await fetch(`${(h as Harness).base}/metrics`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { status: r.status, text: await r.text(), type: r.headers.get("content-type") ?? "" };
};

describe("Prometheus metrics", () => {
  it("are off by default, and a server that is told to serve them refuses to start without a token", async () => {
    h = await startHarness();
    const r = await scrape();
    expect(r.text).not.toContain("authvex_http_requests_total");
    await h.close();
    h = undefined;
    await expect(startHarness({ metrics: { enabled: true } })).rejects.toThrow(/AUTHVEX_METRICS_TOKEN/);
    process.env["AUTHVEX_METRICS_TOKEN"] = "short";
    await expect(startHarness({ metrics: { enabled: true } })).rejects.toThrow(/16 characters/);
  });

  it("need the scrape token, and nothing else opens them (not even the admin token)", async () => {
    process.env["AUTHVEX_METRICS_TOKEN"] = TOKEN;
    h = await startHarness({ metrics: { enabled: true } });
    expect((await scrape(null)).status).toBe(401);
    expect((await scrape("wrong-token-0123456789")).status).toBe(401);
    expect((await scrape(h.admin)).status).toBe(401);
    expect((await fetch(`${h.base}/metrics`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } })).status).toBe(405);
    expect((await scrape()).status).toBe(200);
  });

  it("count requests and audit events, in a valid exposition format", async () => {
    process.env["AUTHVEX_METRICS_TOKEN"] = TOKEN;
    h = await startHarness({ metrics: { enabled: true } });
    expect((await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).status).toBe(200);
    expect((await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: "nope nope nope" })).status).toBeGreaterThanOrEqual(400);
    const { text, type } = await scrape();
    expect(type).toContain("text/plain; version=0.0.4");
    expect(text).toContain('authvex_http_requests_total{method="POST",route="/api/auth/login",status="200"} 1');
    expect(text).toMatch(/authvex_audit_events_total\{type="auth\.login"\} 1/);
    expect(text).toMatch(/authvex_http_request_duration_seconds_count\{route="\/api\/auth\/login"\} 2/);
    expect(text).toMatch(/authvex_issuer_keys\{status="active"\} 1/);
    expect(text).toMatch(/authvex_info\{store="[a-z]+",version="test"\} 1/);
    for (const line of text.trim().split("\n")) {
      if (line.startsWith("#")) expect(line).toMatch(/^# (HELP|TYPE) authvex_[a-z_]+ .+/);
      else expect(line).toMatch(/^authvex_[a-z_]+(\{[a-z_]+="[^"\n]*"(,[a-z_]+="[^"\n]*")*\})? -?[0-9.e+-]+$/);
    }
  });

  it("cannot be flooded with series by random URLs", async () => {
    process.env["AUTHVEX_METRICS_TOKEN"] = TOKEN;
    h = await startHarness({ metrics: { enabled: true } });
    for (let i = 0; i < 60; i++) await fetch(`${h.base}/probe-${i}-${Math.random()}`);
    for (let i = 0; i < 20; i++) await fetch(`${h.base}/oidc/tenant${i}/token`, { method: "POST" });
    await fetch(`${h.base}/api/keys/${"x".repeat(20)}`);
    const { text } = await scrape();
    expect(text).not.toContain("probe-");
    expect(text).not.toContain("tenant5");
    expect(text).toContain('route="/oidc/:tenant/token"');
    expect(text.split("\n").length).toBeLessThan(150);
  });

  it("route labels are bounded", () => {
    const known = new Set(["/api/health"]);
    expect(routeLabel("GET", "/api/health", known)).toBe("/api/health");
    expect(routeLabel("GET", "/oidc/acme/authorize", known)).toBe("/oidc/:tenant/authorize");
    expect(routeLabel("GET", "/oidc/acme/whatever", known)).toBe("other");
    expect(routeLabel("GET", "/assets/app.js", known)).toBe("static");
    expect(routeLabel("POST", "/anything", known)).toBe("other");
    expect(routeLabel("GET", "/api/anything", known)).toBe("other");
  });

  it("registry escapes label values and folds runaway label sets", async () => {
    const r = new Registry();
    const c = r.counter("t_total", "t");
    c.inc({ a: 'x"y\\z\nw' });
    for (let i = 0; i < 600; i++) c.inc({ id: String(i) });
    const text = await r.render();
    expect(text).toContain('t_total{a="x\\"y\\\\z\\nw"} 1');
    expect(text).toContain('t_total{overflow="true"}');
    expect(text.split("\n").length).toBeLessThan(520);
  });
});

describe("structured logs", () => {
  it("write one JSON object per request, without query strings or secrets, and report unhandled errors", async () => {
    const lines: string[] = [];
    h = await startHarness({ logging: { format: "json", requests: true } }, { log: (l) => lines.push(l) });
    await fetch(`${h.base}/api/health?token=SECRET-IN-QUERY`);
    await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO });
    const parsed = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(parsed.length).toBeGreaterThanOrEqual(2);
    expect(parsed[0]).toMatchObject({ level: "info", msg: "request", method: "GET", route: "/api/health", status: 200 });
    expect(typeof parsed[0]?.["ts"]).toBe("string");
    expect(typeof parsed[0]?.["ms"]).toBe("number");
    const all = lines.join("\n");
    expect(all).not.toContain("SECRET-IN-QUERY");
    expect(all).not.toContain(DEMO);
    expect(all).not.toContain("margaret@");
  });

  it("stay quiet about requests unless asked, and use plain text by default", async () => {
    const lines: string[] = [];
    h = await startHarness({}, { log: (l) => lines.push(l) });
    await fetch(`${h.base}/api/health`);
    expect(lines).toEqual([]);
  });
});

describe("refresh reuse grace window (server)", () => {
  const rotate = (hh: Harness, key: Awaited<ReturnType<typeof deviceKey>> | undefined, refreshToken: string) => hh.call("POST", "/api/auth/rotate", { refreshToken }, key ? { dpop: key } : {});

  it("is off by default", async () => {
    h = await startHarness();
    const key = await deviceKey();
    const s = (await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO }, { dpop: key })).body;
    expect((await rotate(h, key, s.refreshToken)).status).toBe(200);
    expect((await rotate(h, key, s.refreshToken)).status).toBe(409);
  });

  it("lets a bound session retry a lost refresh once inside the window, never an unbound one, and never a stranger without the key", async () => {
    let clock = Date.now();
    h = await startHarness({ refreshReuseGraceSeconds: 10 }, { now: () => clock });
    const key = await deviceKey();
    const s = (await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO }, { dpop: key })).body;
    const first = await rotate(h, key, s.refreshToken);
    expect(first.status).toBe(200);
    // the answer was "lost": the client asks again with the same token
    const thief = await deviceKey();
    expect((await rotate(h, thief, s.refreshToken)).status).toBe(401); // another device cannot use the grace
    expect((await rotate(h, undefined, s.refreshToken)).status).toBe(401);
    clock += 3000;
    const retry = await rotate(h, key, s.refreshToken);
    expect(retry.status).toBe(200);
    expect(retry.body.generation).toBe(3);
    expect(retry.body.refreshToken).not.toBe(first.body.refreshToken);
    expect((await h.call("GET", "/api/ledger")).body["entries"]).toEqual(expect.arrayContaining([expect.objectContaining({ type: "auth.rotate.grace_used" })]));
    // after the window the same old token is treated as theft
    clock += 11_000;
    expect((await rotate(h, key, s.refreshToken)).status).toBe(409);

    // an unbound session gets no leeway
    const u = (await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).body;
    expect((await rotate(h, undefined, u.refreshToken)).status).toBe(200);
    expect((await rotate(h, undefined, u.refreshToken)).status).toBe(409);
  });
});
