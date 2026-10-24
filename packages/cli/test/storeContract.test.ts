import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryStore, type SessionFamily, type Store } from "@authvex/core";
import { FileStore, SqliteStore, sqliteAvailable } from "../src/stores";
import { PgStore } from "../src/pgStore";
import { PgConnection, PgError, parsePgUrl } from "../src/pg";

const hasSqlite = await sqliteAvailable();
const PG_URL = process.env["AUTHVEX_TEST_DATABASE_URL"];
const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const c of cleanups.splice(0)) await c();
});

const fam = (id: string, over: Partial<SessionFamily> = {}): SessionFamily => ({
  familyId: id, userId: "usr_a", tenantId: "t", currentGeneration: 1, activeRefreshTokenHash: `${id}-h1`, consumedRefreshTokenHashes: [], status: "active", createdAtIso: "2026-01-01T00:00:00Z", lastRotatedAtIso: "2026-01-01T00:00:00Z", expiresAtIso: "2027-01-01T00:00:00Z", ...over,
});
const next = (f: SessionFamily): SessionFamily => ({ ...f, currentGeneration: f.currentGeneration + 1, activeRefreshTokenHash: `${f.familyId}-h${f.currentGeneration + 1}`, consumedRefreshTokenHashes: [...f.consumedRefreshTokenHashes, f.activeRefreshTokenHash] });

type Make = () => Promise<Store>;
const stores: Array<[string, boolean, Make]> = [
  ["memory", true, async () => new MemoryStore()],
  ["file", true, async () => {
    const d = mkdtempSync(join(tmpdir(), "authvex-fs-"));
    cleanups.push(() => rmSync(d, { recursive: true, force: true }));
    return FileStore.open(join(d, "s.json"));
  }],
  ["sqlite", hasSqlite, async () => {
    const d = mkdtempSync(join(tmpdir(), "authvex-sq-"));
    cleanups.push(() => rmSync(d, { recursive: true, force: true }));
    return SqliteStore.open(join(d, "s.db"));
  }],
  ["postgres", PG_URL !== undefined, async () => PgStore.open(parsePgUrl(`${PG_URL}`), { schema: `t_${Math.random().toString(36).slice(2, 10)}` })],
];

for (const [name, available, make] of stores) {
  describe.skipIf(!available)(`the Store contract: ${name}`, () => {
    const open = async (): Promise<Store> => {
      const s = await make();
      cleanups.unshift(() => s.close());
      return s;
    };

    it("stores families, lists them and finds them by any refresh token they ever had", async () => {
      const s = await open();
      const f = fam("fam_1");
      await s.createFamily(f);
      expect(await s.getFamily("fam_1")).toEqual(f);
      expect(await s.getFamily("fam_nope")).toBeUndefined();
      const n = next(f);
      expect(await s.compareAndSetFamily(f, n)).toBe(true);
      expect(await s.getFamily("fam_1")).toEqual(n);
      expect(await s.familyIdForToken("fam_1-h1")).toBe("fam_1");
      expect(await s.familyIdForToken("fam_1-h2")).toBe("fam_1");
      expect(await s.familyIdForToken("nope")).toBeUndefined();
      await s.createFamily(fam("fam_2"));
      expect((await s.listFamilies()).map((x) => x.familyId).sort()).toEqual(["fam_1", "fam_2"]);
    });

    it("refuses a stale compare-and-set, and lets exactly one of many parallel ones win", async () => {
      const s = await open();
      const f = fam("fam_cas");
      await s.createFamily(f);
      expect(await s.compareAndSetFamily(f, { ...f, status: "revoked_manual" })).toBe(true);
      expect(await s.compareAndSetFamily(f, next(f))).toBe(false);
      const g = fam("fam_race");
      await s.createFamily(g);
      const wins = await Promise.all(Array.from({ length: 24 }, () => s.compareAndSetFamily(g, next(g))));
      expect(wins.filter(Boolean)).toHaveLength(1);
      expect((await s.getFamily("fam_race"))?.currentGeneration).toBe(2);
    });

    it("claims a proof id once per window, again after it lapses, and exactly once under a race", async () => {
      const s = await open();
      expect(await s.claimJti("j", 1000, 500)).toBe(true);
      expect(await s.claimJti("j", 1200, 500)).toBe(false);
      expect(await s.claimJti("j", 1500, 500)).toBe(true);
      const results = await Promise.all(Array.from({ length: 40 }, () => s.claimJti("race", 0, 60_000)));
      expect(results.filter(Boolean)).toHaveLength(1);
    });

    it("counts failures in a sliding window per key", async () => {
      const s = await open();
      for (const t of [0, 100, 200]) await s.recordFailure("k", t, 1000);
      await s.recordFailure("other", 100, 1000);
      expect(await s.countFailures("k", 300, 1000)).toBe(3);
      expect(await s.countFailures("k", 1150, 1000)).toBe(1);
      expect(await s.countFailures("k", 5000, 1000)).toBe(0);
      expect(await s.countFailures("other", 300, 1000)).toBe(1);
      expect(await s.countFailures("none", 0, 1000)).toBe(0);
    });

    it("hands a challenge out once, not after it expires, and only one of many takers gets it", async () => {
      const s = await open();
      const c = { challenge: "x", purpose: "login" as const, tenantId: "t", userId: "u", expires: 1000 };
      await s.putChallenge("c1", c);
      expect(await s.takeChallenge("c1", 500)).toEqual(c);
      expect(await s.takeChallenge("c1", 500)).toBeUndefined();
      await s.putChallenge("c2", c);
      expect(await s.takeChallenge("c2", 2000)).toBeUndefined();
      await s.putChallenge("c3", c);
      const got = await Promise.all(Array.from({ length: 20 }, () => s.takeChallenge("c3", 500)));
      expect(got.filter(Boolean)).toHaveLength(1);
    });

    it("hands a one-time token out once, only for its purpose, not after it expires, and to one of many takers", async () => {
      const s = await open();
      const t = { purpose: "reset", userId: "u", tenantId: "t", expires: 1000, data: { email: "a@b.test", n: 1, nested: { ok: true } } };
      await s.putOneTimeToken("h1", t);
      expect(await s.takeOneTimeToken("h1", "reset", 500)).toEqual(t);
      expect(await s.takeOneTimeToken("h1", "reset", 500)).toBeUndefined();
      await s.putOneTimeToken("h2", t);
      expect(await s.takeOneTimeToken("h2", "magic", 500)).toBeUndefined();
      expect(await s.takeOneTimeToken("h2", "reset", 500)).toBeUndefined();
      await s.putOneTimeToken("h3", t);
      expect(await s.takeOneTimeToken("h3", "reset", 2000)).toBeUndefined();
      await s.putOneTimeToken("h4", t);
      const got = await Promise.all(Array.from({ length: 20 }, () => s.takeOneTimeToken("h4", "reset", 500)));
      expect(got.filter(Boolean)).toHaveLength(1);
    });

    it("only ever moves a TOTP counter forward, and accepts one use of a counter under a race", async () => {
      const s = await open();
      expect(await s.getTotpCounter("u")).toBeUndefined();
      expect(await s.advanceTotpCounter("u", 10)).toBe(true);
      expect(await s.advanceTotpCounter("u", 10)).toBe(false);
      expect(await s.advanceTotpCounter("u", 9)).toBe(false);
      expect(await s.getTotpCounter("u")).toBe(10);
      const r = await Promise.all(Array.from({ length: 20 }, () => s.advanceTotpCounter("v", 5)));
      expect(r.filter(Boolean)).toHaveLength(1);
    });

    it("sweeps what has expired and keeps what has not", async () => {
      const s = await open();
      await s.claimJti("old", 0, 1000);
      await s.claimJti("new", 9000, 100_000);
      await s.putChallenge("c", { challenge: "x", purpose: "login", userId: "u", expires: 10 });
      await s.putOneTimeToken("h", { purpose: "p", userId: "u", tenantId: "t", expires: 10 });
      await s.putOneTimeToken("keep", { purpose: "p", userId: "u", tenantId: "t", expires: 99_999_999 });
      await s.sweep(5000);
      expect(await s.claimJti("old", 5000, 1000)).toBe(true);
      expect(await s.claimJti("new", 5000, 1000)).toBe(false);
      expect(await s.takeChallenge("c", 0)).toBeUndefined();
      expect(await s.takeOneTimeToken("h", "p", 0)).toBeUndefined();
      expect((await s.takeOneTimeToken("keep", "p", 0))?.purpose).toBe("p");
    });

    it("keeps strange text intact: quotes, unicode and SQL-looking strings are data, not code", async () => {
      const s = await open();
      const evil = "x'); DROP TABLE families; --";
      await s.createFamily(fam("fam_text", { activeRefreshTokenHash: evil, device: { name: "Zoë's 😀 phone \"quoted\"" } }));
      expect((await s.getFamily("fam_text"))?.device?.name).toBe("Zoë's 😀 phone \"quoted\"");
      expect(await s.familyIdForToken(evil)).toBe("fam_text");
      await s.recordFailure(evil, 0, 1000);
      expect(await s.countFailures(evil, 0, 1000)).toBe(1);
      expect((await s.listFamilies()).length).toBe(1);
    });
  });
}

describe.skipIf(!PG_URL)("the PostgreSQL client", () => {
  const url = (over = ""): string => `${PG_URL}${over}`;
  it("parses connection URLs, including a password with special characters", () => {
    expect(parsePgUrl("postgres://u:p%40ss%3Aword@db.example.test:6543/mydb?sslmode=verify-full")).toMatchObject({ host: "db.example.test", port: 6543, user: "u", password: "p@ss:word", database: "mydb", sslmode: "verify-full" });
    expect(parsePgUrl("postgresql://localhost/x")).toMatchObject({ port: 5432, sslmode: "prefer", user: "postgres" });
    expect(() => parsePgUrl("mysql://x")).toThrow(/postgres/);
    expect(() => parsePgUrl("postgres://x/y?sslmode=bogus")).toThrow(/sslmode/);
  });
  it("authenticates with SCRAM-SHA-256 and runs parameterised queries of several types", async () => {
    const c = await PgConnection.open({ ...parsePgUrl(url()), sslmode: "disable" });
    cleanups.push(() => c.close());
    const r = await c.query("SELECT $1::int AS n, $2::text AS t, $3::boolean AS b, $4::jsonb AS j, NULL::text AS z, $5::bigint AS big", [42, "héllo", true, '{"a":[1,2]}', 1_800_000_000_000]);
    expect(r.rows[0]).toEqual({ n: 42, t: "héllo", b: true, j: { a: [1, 2] }, z: null, big: 1_800_000_000_000 });
    expect((await c.query("SELECT generate_series(1, 3) AS i")).rows.map((x) => x["i"])).toEqual([1, 2, 3]);
  });
  it("falls back to plain text when the server has no TLS and sslmode is prefer, and refuses when TLS is required", async () => {
    const c = await PgConnection.open({ ...parsePgUrl(url("?sslmode=prefer")) });
    c.close();
    await expect(PgConnection.open({ ...parsePgUrl(url("?sslmode=require")) })).rejects.toThrow(/does not support TLS/);
  });
  it("rejects a wrong password with the server's error code, and reports SQL errors without breaking the connection", async () => {
    const bad = parsePgUrl(url());
    await expect(PgConnection.open({ ...bad, password: "wrong", sslmode: "disable" })).rejects.toMatchObject({ code: "28P01" });
    const c = await PgConnection.open({ ...bad, sslmode: "disable" });
    cleanups.push(() => c.close());
    await expect(c.query("SELECT * FROM table_that_does_not_exist")).rejects.toMatchObject({ code: "42P01" });
    await expect(c.query("SELECT $1::int", ["not a number"])).rejects.toBeInstanceOf(PgError);
    expect((await c.query("SELECT 1 AS ok")).rows[0]).toEqual({ ok: 1 });
  });
  it("treats a hostile parameter as a value", async () => {
    const c = await PgConnection.open({ ...parsePgUrl(url()), sslmode: "disable" });
    cleanups.push(() => c.close());
    const evil = "'; DROP SCHEMA public CASCADE; --";
    expect((await c.query("SELECT $1::text AS t", [evil])).rows[0]?.["t"]).toBe(evil);
    expect((await c.query("SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = 'public'")).rows[0]?.["n"]).toBe(1);
  });
  it("refuses a bad schema name, and survives two servers opening the same schema at once", async () => {
    await expect(PgStore.open(parsePgUrl(url()), { schema: "x; DROP TABLE y" })).rejects.toThrow(/not allowed/);
    const schema = `t_${Math.random().toString(36).slice(2, 10)}`;
    const both = await Promise.all([PgStore.open(parsePgUrl(url()), { schema }), PgStore.open(parsePgUrl(url()), { schema })]);
    cleanups.push(() => Promise.all(both.map((s) => s.close())).then(() => undefined));
    await both[0].createFamily(fam("shared"));
    expect((await both[1].getFamily("shared"))?.familyId).toBe("shared");
  });
});
