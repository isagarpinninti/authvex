import type { ChallengeRecord, OneTimeToken, SessionFamily, Store } from "@authvex/core";
import { PgConnection, PgPool, type PgOptions } from "./pg";

const SCHEMA_NAME = /^[a-z_][a-z0-9_]{0,40}$/;

const DDL = [
  "CREATE TABLE IF NOT EXISTS families (id text PRIMARY KEY, status text NOT NULL, generation integer NOT NULL, active_hash text NOT NULL, json jsonb NOT NULL)",
  "CREATE TABLE IF NOT EXISTS tokens (hash text PRIMARY KEY, family_id text NOT NULL)",
  "CREATE TABLE IF NOT EXISTS jtis (jti text PRIMARY KEY, expires bigint NOT NULL)",
  "CREATE TABLE IF NOT EXISTS failures (key text NOT NULL, ts bigint NOT NULL)",
  "CREATE INDEX IF NOT EXISTS failures_key ON failures (key, ts)",
  "CREATE TABLE IF NOT EXISTS challenges (id text PRIMARY KEY, json jsonb NOT NULL, expires bigint NOT NULL)",
  "CREATE TABLE IF NOT EXISTS totp (user_id text PRIMARY KEY, counter bigint NOT NULL)",
  "CREATE TABLE IF NOT EXISTS onetime (hash text PRIMARY KEY, purpose text NOT NULL, json jsonb NOT NULL, expires bigint NOT NULL)",
];

/**
 * State in PostgreSQL, so several servers on several hosts can share sessions. Every operation that must not race is a single
 * statement (an upsert with a WHERE, a DELETE ... RETURNING, an UPDATE ... WHERE on the expected state) or a short transaction, so
 * Postgres decides which of two concurrent requests came first. Tables live in their own schema (default `authvex`).
 */
export class PgStore implements Store {
  readonly kind = "postgres";
  private constructor(private readonly pool: PgPool) {}

  static async open(options: PgOptions, opts: { schema?: string; poolSize?: number } = {}): Promise<PgStore> {
    const schema = opts.schema ?? "authvex";
    if (!SCHEMA_NAME.test(schema)) throw new Error(`the schema name "${schema}" is not allowed (lower-case letters, digits and _ , starting with a letter or _)`);
    const setup = await PgConnection.open(options);
    try {
      await setup.query("BEGIN");
      await setup.query("SELECT pg_advisory_xact_lock(7243001)"); // two servers starting at once must not race to create the tables
      await setup.query(`CREATE SCHEMA IF NOT EXISTS "${schema}"`);
      await setup.query(`SET LOCAL search_path TO "${schema}"`);
      for (const sql of DDL) await setup.query(sql);
      await setup.query("COMMIT");
    } catch (e) {
      await setup.query("ROLLBACK").catch(() => undefined);
      throw e;
    } finally {
      setup.close();
    }
    return new PgStore(new PgPool({ ...options, parameters: { ...(options.parameters ?? {}), options: `-c search_path=${schema}` } }, opts.poolSize ?? 4));
  }

  async getFamily(id: string): Promise<SessionFamily | undefined> {
    const r = await this.pool.query("SELECT json FROM families WHERE id = $1", [id]);
    return r.rows[0] ? (r.rows[0]["json"] as SessionFamily) : undefined;
  }
  async listFamilies(): Promise<SessionFamily[]> {
    return (await this.pool.query("SELECT json FROM families")).rows.map((r) => r["json"] as SessionFamily);
  }
  async createFamily(f: SessionFamily): Promise<void> {
    await this.pool.tx(async (q) => {
      await q("INSERT INTO families (id, status, generation, active_hash, json) VALUES ($1, $2, $3, $4, $5::jsonb)", [f.familyId, f.status, f.currentGeneration, f.activeRefreshTokenHash, JSON.stringify(f)]);
      await q("INSERT INTO tokens (hash, family_id) VALUES ($1, $2) ON CONFLICT (hash) DO UPDATE SET family_id = EXCLUDED.family_id", [f.activeRefreshTokenHash, f.familyId]);
    });
  }
  async compareAndSetFamily(prev: SessionFamily, next: SessionFamily): Promise<boolean> {
    return this.pool.tx(async (q) => {
      const r = await q("UPDATE families SET status = $1, generation = $2, active_hash = $3, json = $4::jsonb WHERE id = $5 AND status = $6 AND generation = $7 AND active_hash = $8", [
        next.status, next.currentGeneration, next.activeRefreshTokenHash, JSON.stringify(next), prev.familyId, prev.status, prev.currentGeneration, prev.activeRefreshTokenHash,
      ]);
      if (r.rowCount !== 1) return false;
      await q("INSERT INTO tokens (hash, family_id) VALUES ($1, $2) ON CONFLICT (hash) DO UPDATE SET family_id = EXCLUDED.family_id", [next.activeRefreshTokenHash, next.familyId]);
      return true;
    });
  }
  async familyIdForToken(hash: string): Promise<string | undefined> {
    const r = await this.pool.query("SELECT family_id FROM tokens WHERE hash = $1", [hash]);
    return r.rows[0] ? (r.rows[0]["family_id"] as string) : undefined;
  }
  async claimJti(jti: string, nowMs: number, ttlMs: number): Promise<boolean> {
    const r = await this.pool.query("INSERT INTO jtis (jti, expires) VALUES ($1, $2) ON CONFLICT (jti) DO UPDATE SET expires = EXCLUDED.expires WHERE jtis.expires <= $3", [jti, nowMs + ttlMs, nowMs]);
    return r.rowCount === 1;
  }
  async countFailures(key: string, nowMs: number, windowMs: number): Promise<number> {
    return Number((await this.pool.query("SELECT count(*) AS n FROM failures WHERE key = $1 AND ts > $2", [key, nowMs - windowMs])).rows[0]?.["n"] ?? 0);
  }
  async recordFailure(key: string, nowMs: number, windowMs: number): Promise<void> {
    await this.pool.tx(async (q) => {
      await q("DELETE FROM failures WHERE key = $1 AND ts <= $2", [key, nowMs - windowMs]);
      await q("INSERT INTO failures (key, ts) VALUES ($1, $2)", [key, nowMs]);
    });
  }
  async putChallenge(id: string, c: ChallengeRecord): Promise<void> {
    await this.pool.query("INSERT INTO challenges (id, json, expires) VALUES ($1, $2::jsonb, $3) ON CONFLICT (id) DO UPDATE SET json = EXCLUDED.json, expires = EXCLUDED.expires", [id, JSON.stringify(c), c.expires]);
  }
  async takeChallenge(id: string, nowMs: number): Promise<ChallengeRecord | undefined> {
    const r = await this.pool.query("DELETE FROM challenges WHERE id = $1 RETURNING json", [id]);
    const c = r.rows[0] ? (r.rows[0]["json"] as ChallengeRecord) : undefined;
    return c && c.expires >= nowMs ? c : undefined;
  }
  async putOneTimeToken(hash: string, t: OneTimeToken): Promise<void> {
    await this.pool.query("INSERT INTO onetime (hash, purpose, json, expires) VALUES ($1, $2, $3::jsonb, $4) ON CONFLICT (hash) DO UPDATE SET purpose = EXCLUDED.purpose, json = EXCLUDED.json, expires = EXCLUDED.expires", [hash, t.purpose, JSON.stringify(t), t.expires]);
  }
  async takeOneTimeToken(hash: string, purpose: string, nowMs: number): Promise<OneTimeToken | undefined> {
    const r = await this.pool.query("DELETE FROM onetime WHERE hash = $1 RETURNING json", [hash]);
    const t = r.rows[0] ? (r.rows[0]["json"] as OneTimeToken) : undefined;
    return t && t.purpose === purpose && t.expires >= nowMs ? t : undefined;
  }
  async getTotpCounter(userId: string): Promise<number | undefined> {
    const r = await this.pool.query("SELECT counter FROM totp WHERE user_id = $1", [userId]);
    return r.rows[0] ? Number(r.rows[0]["counter"]) : undefined;
  }
  async advanceTotpCounter(userId: string, counter: number): Promise<boolean> {
    return (await this.pool.query("INSERT INTO totp (user_id, counter) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET counter = EXCLUDED.counter WHERE totp.counter < EXCLUDED.counter", [userId, counter])).rowCount === 1;
  }
  async sweep(nowMs: number): Promise<void> {
    await this.pool.query("DELETE FROM jtis WHERE expires <= $1", [nowMs]);
    await this.pool.query("DELETE FROM challenges WHERE expires < $1", [nowMs]);
    await this.pool.query("DELETE FROM onetime WHERE expires < $1", [nowMs]);
    await this.pool.query("DELETE FROM failures WHERE ts <= $1", [nowMs - 24 * 3600_000]);
  }
  async flush(): Promise<void> {}
  async close(): Promise<void> {
    await this.pool.close();
  }
}
