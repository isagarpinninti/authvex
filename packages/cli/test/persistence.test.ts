import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createDpopProof, type SessionFamily } from "@authvex/core";
import { DEMO, deviceKey, startHarness, type Harness } from "./helpers";
import { ConfigSchema, FileKeyring, Ledger, SqliteStore, createAuthvexServer, loadWorkspace, openStore, sqliteAvailable } from "./testExports";

const hasSqlite = await sqliteAvailable();
const hasPg = process.env["AUTHVEX_TEST_DATABASE_URL"] !== undefined;
const kinds = [["file", true], ["sqlite", hasSqlite], ["postgres", hasPg]] as const;
const ACME = "acme_fintech_prod";
const LIN = "linear_ops_workspace";

let h: Harness | undefined;
afterEach(async () => {
  await h?.close();
  h = undefined;
});

const login = (tenantId: string, email: string, key?: Awaited<ReturnType<typeof deviceKey>>, extra: Record<string, unknown> = {}) =>
  (h as Harness).call("POST", "/api/auth/login", { tenantId, email, password: DEMO, ...extra }, key ? { dpop: key } : {});

for (const [kind, available] of kinds) {
  describe.skipIf(!available)(`state survives a restart (${kind} store)`, () => {
    const start = async (): Promise<Harness> => (h = await startHarness({ store: { kind } }));

    it("keeps a session: the latest refresh token still rotates, a spent one still revokes the family", async () => {
      await start();
      const s = (await login(LIN, "margaret@linear-ops.test")).body;
      const r2 = (await h!.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken })).body;
      expect(r2.generation).toBe(2);
      await h!.restart();
      expect((await h!.call("GET", "/api/health")).body).toMatchObject({ store: kind });
      const r3 = await h!.call("POST", "/api/auth/rotate", { refreshToken: r2.refreshToken });
      expect(r3).toMatchObject({ status: 200, body: { generation: 3 } });
      await h!.restart();
      const replay = await h!.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken });
      expect(replay).toMatchObject({ status: 409, body: { status: "family_revoked" } });
      await h!.restart();
      expect((await h!.call("POST", "/api/auth/rotate", { refreshToken: r3.body.refreshToken })).status).toBe(401);
      expect((await h!.call("GET", "/api/workspace")).body.families.find((f) => f.familyId === s.familyId)?.status).toBe("revoked_reuse_detected");
    });

    it("remembers a DPoP proof across a restart, so it cannot be replayed", async () => {
      await start();
      const key = await deviceKey();
      const s = (await login(ACME, "grace@acme-fintech.test", key)).body;
      const url = `${h!.base}/v1/invoices`;
      const proof = await createDpopProof({ ...key, method: "GET", url, sessionToken: s.sessionToken });
      const body = { sessionToken: s.sessionToken, dpopProof: proof, method: "GET", url };
      expect((await h!.call("POST", "/api/auth/dpop-verify", body)).status).toBe(200);
      await h!.restart();
      expect(await h!.call("POST", "/api/auth/dpop-verify", body)).toMatchObject({ status: 401, body: { reason: "replayed" } });
    });

    it("remembers a spent TOTP code and the failed-attempt window", async () => {
      await start();
      const key = await deviceKey();
      const ada = { tenantId: ACME, email: "ada@acme-fintech.test", password: DEMO };
      const code = await h!.totp("usr_ada");
      expect((await login(ACME, ada.email, key, { totp: code })).status).toBe(200);
      await h!.restart();
      expect((await login(ACME, ada.email, key, { totp: code })).body.status).toBe("step_up_required");
      for (let i = 0; i < 6; i++) await h!.call("POST", "/api/auth/login", { ...ada, password: `bad${i}` });
      await h!.restart();
      expect((await login(ACME, ada.email, key, { totp: await h!.totp("usr_ada") })).status).toBe(403);
    });

    it("keeps a revoked family revoked, and one-time challenges one-time", async () => {
      await start();
      const s = (await login(LIN, "margaret@linear-ops.test")).body;
      expect((await h!.call("DELETE", `/api/families/${s.familyId}`)).status).toBe(200);
      const c = (await h!.call("POST", "/api/auth/passkey/challenge", { tenantId: LIN, email: "margaret@linear-ops.test" })).body;
      await h!.restart();
      expect((await h!.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken })).status).toBe(401);
      expect((await h!.call("GET", "/api/workspace")).body.families.find((f) => f.familyId === s.familyId)?.status).toBe("revoked_manual");
      expect(c.challengeId).toBeTruthy();
    });

    it("lets exactly one of many parallel uses of a refresh token win, and revokes the family", async () => {
      await start();
      const s = (await login(LIN, "margaret@linear-ops.test")).body;
      const results = await Promise.all(Array.from({ length: 16 }, () => h!.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken })));
      const codes = results.map((r) => r.status);
      expect(codes.filter((c) => c === 200)).toHaveLength(1);
      expect(codes.filter((c) => c === 409).length).toBeGreaterThanOrEqual(1);
      expect(codes.every((c) => c === 200 || c === 409 || c === 401)).toBe(true);
      expect((await h!.call("GET", "/api/workspace")).body.families.find((f) => f.familyId === s.familyId)?.status).toBe("revoked_reuse_detected");
      const winner = results.find((r) => r.status === 200)!;
      expect((await h!.call("POST", "/api/auth/rotate", { refreshToken: winner.body.refreshToken })).status).toBe(401);
    });
  });
}

describe("the memory store", () => {
  it("is honest about losing state: a restart ends sessions", async () => {
    h = await startHarness({ store: { kind: "memory" } });
    const s = (await login(LIN, "margaret@linear-ops.test")).body;
    await h.restart();
    expect((await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken })).status).toBe(401);
  });
});

describe.skipIf(!hasSqlite)("two servers sharing one SQLite database", () => {
  it("agree on which refresh token was used first, even when raced across both", async () => {
    h = await startHarness({ store: { kind: "sqlite" } });
    const ws = loadWorkspace(h.dir);
    const cfg = ConfigSchema.parse({ ...ws.config, port: 0, ipRequestsPerMinute: 100_000, store: { kind: "sqlite" } });
    const second = createAuthvexServer({ workspace: { ...ws, config: cfg }, keyring: await FileKeyring.open(h.dir), store: await openStore(cfg, h.dir), ledger: new Ledger(h.ledgerPath), version: "second" });
    const { port } = await second.listen();
    try {
      const s = (await login(LIN, "margaret@linear-ops.test")).body;
      const urls = [h.base, `http://127.0.0.1:${port}`];
      const results = await Promise.all(Array.from({ length: 20 }, (_, i) => fetch(`${urls[i % 2]}/api/auth/rotate`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ refreshToken: s.refreshToken }) }).then((r) => r.status)));
      expect(results.filter((c) => c === 200)).toHaveLength(1);
      // The second server sees the first one's sessions and revocation.
      const fam = await fetch(`http://127.0.0.1:${port}/api/workspace`, { headers: { authorization: `Bearer ${second.adminToken}` } }).then((r) => r.json() as Promise<{ families: Array<{ familyId: string; status: string }> }>);
      expect(fam.families.find((f) => f.familyId === s.familyId)?.status).toBe("revoked_reuse_detected");
    } finally {
      await second.close();
    }
  });
});

describe.skipIf(!hasSqlite)("SqliteStore directly", () => {
  it("claims a proof id once across two connections, advances TOTP once, and refuses a stale compare-and-set", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authvex-sql-"));
    try {
      const a = await SqliteStore.open(join(dir, "s.db"));
      const b = await SqliteStore.open(join(dir, "s.db"));
      expect(await a.claimJti("j", 0, 1000)).toBe(true);
      expect(await b.claimJti("j", 500, 1000)).toBe(false);
      expect(await b.claimJti("j", 1000, 1000)).toBe(true);
      expect(await a.advanceTotpCounter("u", 5)).toBe(true);
      expect(await b.advanceTotpCounter("u", 5)).toBe(false);
      expect(await b.advanceTotpCounter("u", 6)).toBe(true);
      const f: SessionFamily = { familyId: "fam_1", userId: "u", tenantId: "t", currentGeneration: 1, activeRefreshTokenHash: "h1", consumedRefreshTokenHashes: [], status: "active", createdAtIso: "x", lastRotatedAtIso: "x", expiresAtIso: "y" };
      await a.createFamily(f);
      const next = { ...f, currentGeneration: 2, activeRefreshTokenHash: "h2", consumedRefreshTokenHashes: ["h1"] };
      expect(await b.compareAndSetFamily(f, next)).toBe(true);
      expect(await a.compareAndSetFamily(f, { ...f, status: "revoked_manual" as const })).toBe(false);
      expect(await a.familyIdForToken("h1")).toBe("fam_1");
      expect(await a.familyIdForToken("h2")).toBe("fam_1");
      expect((await a.getFamily("fam_1"))?.currentGeneration).toBe(2);
      await a.close();
      await b.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("throttling", () => {
  it("limits requests per address per minute, configurably", async () => {
    h = await startHarness({ ipRequestsPerMinute: 3, store: { kind: "memory" } });
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await h.call("POST", "/api/auth/passkey/challenge", { tenantId: LIN, email: "margaret@linear-ops.test" })).status);
    expect(codes).toEqual([200, 200, 200, 429, 429]);
  });
});
