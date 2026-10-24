import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { MemoryStore, type ChallengeRecord, type OneTimeToken, type SessionFamily, type Store, type StoreSnapshot } from "@authvex/core";
import { STATE_DIR, type AuthvexConfig } from "./config";

/**
 * Memory plus a JSON file. Session and token changes are written at once; the replay cache, failures and challenges are written
 * within a fraction of a second (and on close), since losing a few of those in a crash only costs a user a retry. One process only:
 * two servers pointed at the same file would overwrite each other. Use the SQLite store to share state.
 */
export class FileStore extends MemoryStore {
  override readonly kind = "file";
  private dirty = false;
  private timer: NodeJS.Timeout | null = null;

  private constructor(private readonly path: string) {
    super();
  }

  static open(path: string): FileStore {
    mkdirSync(dirname(path), { recursive: true });
    const s = new FileStore(path);
    if (existsSync(path)) {
      const snap = JSON.parse(readFileSync(path, "utf8")) as StoreSnapshot;
      if (snap.version !== 1) throw new Error(`${path}: unsupported state file version ${String(snap.version)}`);
      s.restore(snap);
    }
    return s;
  }

  protected override changed(urgent: boolean): void {
    this.dirty = true;
    if (urgent) return this.write();
    this.timer ??= setTimeout(() => this.write(), 200).unref();
  }

  private write(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (!this.dirty) return;
    this.dirty = false;
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.snapshot()), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  override async flush(): Promise<void> {
    this.write();
  }
  override async close(): Promise<void> {
    this.write();
  }
}

/* ───────────────────────── SQLite (node:sqlite, Node 22.5 and later) ───────────────────────── */

interface Stmt {
  run(...p: unknown[]): { changes: number | bigint };
  get(...p: unknown[]): Record<string, unknown> | undefined;
  all(...p: unknown[]): Array<Record<string, unknown>>;
}
interface Db {
  exec(sql: string): void;
  prepare(sql: string): Stmt;
  close(): void;
}

/**
 * The module name is built at run time on purpose: bundlers rewrite a literal `import("node:sqlite")` to `import("sqlite")`, which does
 * not exist, and the built package would then refuse to open a SQLite store.
 */
const SQLITE_MODULE = ["node", "sqlite"].join(":");

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS families (id TEXT PRIMARY KEY, status TEXT NOT NULL, generation INTEGER NOT NULL, active_hash TEXT NOT NULL, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, family_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jtis (jti TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS failures (key TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS failures_key ON failures (key, ts);
CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, json TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS totp (user_id TEXT PRIMARY KEY, counter INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS onetime (hash TEXT PRIMARY KEY, purpose TEXT NOT NULL, json TEXT NOT NULL, expires INTEGER NOT NULL);
`;

/**
 * State in a SQLite database (WAL mode). Writes that must not race (rotation, replay claims, one-time challenges, TOTP counters) are
 * single statements or immediate transactions, so several processes can share one database file and still agree on which refresh
 * token was used first. Needs `node:sqlite`, which Node 22.5 and later ship.
 */
export class SqliteStore implements Store {
  readonly kind = "sqlite";
  private constructor(private readonly db: Db) {}

  static async open(path: string): Promise<SqliteStore> {
    let mod: { DatabaseSync: new (p: string) => Db };
    try {
      mod = (await import(SQLITE_MODULE)) as unknown as typeof mod;
    } catch {
      throw new Error("the sqlite store needs node:sqlite, which Node 22.5 or later provides (this is Node " + process.versions.node + "). Use store.kind \"file\" instead.");
    }
    mkdirSync(dirname(path), { recursive: true });
    const db = new mod.DatabaseSync(path);
    db.exec(SCHEMA);
    return new SqliteStore(db);
  }

  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  async getFamily(id: string): Promise<SessionFamily | undefined> {
    const r = this.db.prepare("SELECT json FROM families WHERE id = ?").get(id);
    return r ? (JSON.parse(r["json"] as string) as SessionFamily) : undefined;
  }
  async listFamilies(): Promise<SessionFamily[]> {
    return this.db.prepare("SELECT json FROM families").all().map((r) => JSON.parse(r["json"] as string) as SessionFamily);
  }
  async createFamily(f: SessionFamily): Promise<void> {
    this.tx(() => {
      this.db.prepare("INSERT INTO families (id, status, generation, active_hash, json) VALUES (?, ?, ?, ?, ?)").run(f.familyId, f.status, f.currentGeneration, f.activeRefreshTokenHash, JSON.stringify(f));
      this.db.prepare("INSERT OR REPLACE INTO tokens (hash, family_id) VALUES (?, ?)").run(f.activeRefreshTokenHash, f.familyId);
    });
  }
  async compareAndSetFamily(prev: SessionFamily, next: SessionFamily): Promise<boolean> {
    return this.tx(() => {
      const r = this.db
        .prepare("UPDATE families SET status = ?, generation = ?, active_hash = ?, json = ? WHERE id = ? AND status = ? AND generation = ? AND active_hash = ?")
        .run(next.status, next.currentGeneration, next.activeRefreshTokenHash, JSON.stringify(next), prev.familyId, prev.status, prev.currentGeneration, prev.activeRefreshTokenHash);
      if (Number(r.changes) !== 1) return false;
      this.db.prepare("INSERT OR REPLACE INTO tokens (hash, family_id) VALUES (?, ?)").run(next.activeRefreshTokenHash, next.familyId);
      return true;
    });
  }
  async familyIdForToken(hash: string): Promise<string | undefined> {
    return this.db.prepare("SELECT family_id FROM tokens WHERE hash = ?").get(hash)?.["family_id"] as string | undefined;
  }
  async claimJti(jti: string, nowMs: number, ttlMs: number): Promise<boolean> {
    return this.tx(() => {
      this.db.prepare("DELETE FROM jtis WHERE jti = ? AND expires <= ?").run(jti, nowMs);
      return Number(this.db.prepare("INSERT OR IGNORE INTO jtis (jti, expires) VALUES (?, ?)").run(jti, nowMs + ttlMs).changes) === 1;
    });
  }
  async countFailures(key: string, nowMs: number, windowMs: number): Promise<number> {
    return Number(this.db.prepare("SELECT COUNT(*) AS n FROM failures WHERE key = ? AND ts > ?").get(key, nowMs - windowMs)?.["n"] ?? 0);
  }
  async recordFailure(key: string, nowMs: number, windowMs: number): Promise<void> {
    this.tx(() => {
      this.db.prepare("DELETE FROM failures WHERE key = ? AND ts <= ?").run(key, nowMs - windowMs);
      this.db.prepare("INSERT INTO failures (key, ts) VALUES (?, ?)").run(key, nowMs);
    });
  }
  async putChallenge(id: string, c: ChallengeRecord): Promise<void> {
    this.db.prepare("INSERT OR REPLACE INTO challenges (id, json, expires) VALUES (?, ?, ?)").run(id, JSON.stringify(c), c.expires);
  }
  async takeChallenge(id: string, nowMs: number): Promise<ChallengeRecord | undefined> {
    return this.tx(() => {
      const r = this.db.prepare("SELECT json FROM challenges WHERE id = ?").get(id);
      if (!r) return undefined;
      this.db.prepare("DELETE FROM challenges WHERE id = ?").run(id);
      const c = JSON.parse(r["json"] as string) as ChallengeRecord;
      return c.expires >= nowMs ? c : undefined;
    });
  }
  async putOneTimeToken(hash: string, t: OneTimeToken): Promise<void> {
    this.db.prepare("INSERT OR REPLACE INTO onetime (hash, purpose, json, expires) VALUES (?, ?, ?, ?)").run(hash, t.purpose, JSON.stringify(t), t.expires);
  }
  async takeOneTimeToken(hash: string, purpose: string, nowMs: number): Promise<OneTimeToken | undefined> {
    return this.tx(() => {
      const r = this.db.prepare("SELECT json FROM onetime WHERE hash = ?").get(hash);
      if (!r) return undefined;
      this.db.prepare("DELETE FROM onetime WHERE hash = ?").run(hash);
      const t = JSON.parse(r["json"] as string) as OneTimeToken;
      return t.purpose === purpose && t.expires >= nowMs ? t : undefined;
    });
  }
  async getTotpCounter(userId: string): Promise<number | undefined> {
    const r = this.db.prepare("SELECT counter FROM totp WHERE user_id = ?").get(userId);
    return r ? Number(r["counter"]) : undefined;
  }
  async advanceTotpCounter(userId: string, counter: number): Promise<boolean> {
    return Number(this.db.prepare("INSERT INTO totp (user_id, counter) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET counter = excluded.counter WHERE excluded.counter > totp.counter").run(userId, counter).changes) === 1;
  }
  async sweep(nowMs: number): Promise<void> {
    this.tx(() => {
      this.db.prepare("DELETE FROM jtis WHERE expires <= ?").run(nowMs);
      this.db.prepare("DELETE FROM challenges WHERE expires < ?").run(nowMs);
      this.db.prepare("DELETE FROM onetime WHERE expires < ?").run(nowMs);
      this.db.prepare("DELETE FROM failures WHERE ts <= ?").run(nowMs - 24 * 3600_000);
    });
  }
  async flush(): Promise<void> {}
  async close(): Promise<void> {
    this.db.close();
  }
}

export const sqliteAvailable = async (): Promise<boolean> => import(SQLITE_MODULE).then(() => true, () => false);

/** Opens the store the config asks for. */
export async function openStore(config: AuthvexConfig, root: string, env: NodeJS.ProcessEnv = process.env): Promise<Store> {
  const path = (name: string): string => (config.store.path ? join(root, config.store.path) : join(root, STATE_DIR, name));
  if (config.store.kind === "memory") return new MemoryStore();
  if (config.store.kind === "sqlite") return SqliteStore.open(path("state.db"));
  if (config.store.kind === "postgres") {
    const url = env[config.store.urlEnv];
    if (!url) throw new Error(`store.kind is "postgres" but the environment variable ${config.store.urlEnv} is not set`);
    const { PgStore } = await import("./pgStore");
    const { parsePgUrl } = await import("./pg");
    return PgStore.open(parsePgUrl(url), { schema: config.store.schema, poolSize: config.store.poolSize });
  }
  return FileStore.open(path("state.json"));
}
