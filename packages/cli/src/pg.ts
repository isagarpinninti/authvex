import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";

/**
 * A small PostgreSQL client written against the frontend/backend protocol (version 3): startup, cleartext, MD5 and SCRAM-SHA-256
 * authentication, optional TLS, and the extended query protocol with text parameters (so values are never spliced into SQL). It
 * covers what the Authvex store needs and nothing more.
 */
export interface PgOptions {
  host: string;
  port: number;
  user: string;
  password?: string;
  database: string;
  /** `disable`, `prefer` (TLS if the server offers it), `require` (TLS, any certificate) or `verify-full` (TLS, certificate checked). */
  sslmode: "disable" | "prefer" | "require" | "verify-full";
  /** Extra parameters sent at startup, for example `search_path`. */
  parameters?: Record<string, string>;
  connectTimeoutMs?: number;
  ca?: string;
}

export class PgError extends Error {
  constructor(message: string, readonly code?: string, readonly detail?: string) {
    super(message);
    this.name = "PgError";
  }
}

export type PgRow = Record<string, unknown>;
export interface PgResult {
  rows: PgRow[];
  /** Rows affected by INSERT, UPDATE or DELETE; the number of rows for SELECT. */
  rowCount: number;
}

/** Parses `postgres://user:password@host:port/database?sslmode=require`. */
export function parsePgUrl(url: string): PgOptions {
  const u = new URL(url);
  if (u.protocol !== "postgres:" && u.protocol !== "postgresql:") throw new Error("the database URL must start with postgres:// or postgresql://");
  const mode = u.searchParams.get("sslmode") ?? "prefer";
  if (!["disable", "prefer", "require", "verify-full"].includes(mode)) throw new Error(`unsupported sslmode "${mode}" (use disable, prefer, require or verify-full)`);
  return {
    host: u.hostname || "localhost", port: u.port ? Number(u.port) : 5432, user: decodeURIComponent(u.username || "postgres"), ...(u.password ? { password: decodeURIComponent(u.password) } : {}),
    database: decodeURIComponent(u.pathname.replace(/^\//, "") || u.username || "postgres"), sslmode: mode as PgOptions["sslmode"],
  };
}

const i32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeInt32BE(n);
  return b;
};
const i16 = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeInt16BE(n);
  return b;
};
const cstr = (s: string): Buffer => Buffer.concat([Buffer.from(s, "utf8"), Buffer.from([0])]);
const msg = (type: string, ...parts: Buffer[]): Buffer => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from(type, "latin1"), i32(body.length + 4), body]);
};

const xor = (a: Buffer, b: Buffer): Buffer => Buffer.from(a.map((x, i) => x ^ (b[i] as number)));
const hmac = (key: Buffer, data: string | Buffer): Buffer => createHmac("sha256", key).update(data).digest();

/** Converts a text-format value by its type OID. Anything unrecognised stays a string. */
function decode(oid: number, text: string): unknown {
  switch (oid) {
    case 16:
      return text === "t";
    case 20:
    case 21:
    case 23:
    case 26:
    case 700:
    case 701:
    case 1700: {
      const n = Number(text);
      if (!Number.isSafeInteger(n) && (oid === 20 || oid === 21 || oid === 23)) throw new PgError(`the integer ${text} does not fit a JavaScript number`);
      return n;
    }
    case 114:
    case 3802:
      return JSON.parse(text) as unknown;
    default:
      return text;
  }
}

export class PgConnection {
  private buf = Buffer.alloc(0);
  private waiter: ((m: { type: string; body: Buffer }) => void) | null = null;
  private queue: Array<{ type: string; body: Buffer }> = [];
  private failure: Error | null = null;
  private failWaiter: ((e: Error) => void) | null = null;
  private constructor(private socket: Socket | TLSSocket, private readonly timeoutMs: number) {
    this.attach(socket);
  }

  private attach(s: Socket | TLSSocket): void {
    s.on("data", (d: Buffer) => {
      this.buf = Buffer.concat([this.buf, d]);
      while (this.buf.length >= 5) {
        const len = this.buf.readInt32BE(1);
        if (this.buf.length < len + 1) break;
        const m = { type: String.fromCharCode(this.buf[0] as number), body: this.buf.subarray(5, len + 1) };
        this.buf = this.buf.subarray(len + 1);
        if (this.waiter) {
          const w = this.waiter;
          this.waiter = null;
          w(m);
        } else this.queue.push(m);
      }
    });
    const die = (e: Error): void => {
      this.failure ??= e;
      this.failWaiter?.(e);
      this.failWaiter = null;
    };
    s.on("error", die);
    s.on("close", () => die(new PgError("the database connection closed")));
  }

  get broken(): boolean {
    return this.failure !== null;
  }

  private next(): Promise<{ type: string; body: Buffer }> {
    const q = this.queue.shift();
    if (q) return Promise.resolve(q);
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        const e = new PgError("the database did not answer in time");
        this.failure ??= e;
        this.socket.destroy();
        reject(e);
      }, this.timeoutMs);
      this.waiter = (m) => (clearTimeout(t), resolve(m));
      this.failWaiter = (e) => (clearTimeout(t), reject(e));
    });
  }

  private static async rawConnect(o: PgOptions): Promise<Socket | TLSSocket> {
    const timeout = o.connectTimeoutMs ?? 10_000;
    const sock = await new Promise<Socket>((resolve, reject) => {
      const s = netConnect({ host: o.host, port: o.port });
      s.setTimeout(timeout, () => s.destroy(new PgError("the database connection timed out")));
      s.once("connect", () => (s.setTimeout(0), resolve(s)));
      s.once("error", reject);
    });
    if (o.sslmode === "disable") return sock;
    sock.write(Buffer.concat([i32(8), i32(80877103)]));
    const answer = await new Promise<string>((resolve, reject) => {
      sock.once("data", (d: Buffer) => resolve(String.fromCharCode(d[0] as number)));
      sock.once("error", reject);
    });
    if (answer === "S") {
      const tls = tlsConnect({ socket: sock, servername: o.host, rejectUnauthorized: o.sslmode === "verify-full", ...(o.ca ? { ca: o.ca } : {}) });
      await new Promise<void>((resolve, reject) => {
        tls.once("secureConnect", () => resolve());
        tls.once("error", reject);
      });
      return tls;
    }
    if (o.sslmode === "prefer") return sock;
    sock.destroy();
    throw new PgError(`the server does not support TLS, and sslmode is "${o.sslmode}"`);
  }

  static async open(o: PgOptions): Promise<PgConnection> {
    const socket = await PgConnection.rawConnect(o);
    const c = new PgConnection(socket, 30_000);
    const params: Record<string, string> = { user: o.user, database: o.database, application_name: "authvex", client_encoding: "UTF8", ...(o.parameters ?? {}) };
    const body = Buffer.concat([i32(196608), ...Object.entries(params).flatMap(([k, v]) => [cstr(k), cstr(v)]), Buffer.from([0])]);
    socket.write(Buffer.concat([i32(body.length + 4), body]));
    await c.authenticate(o);
    return c;
  }

  private async authenticate(o: PgOptions): Promise<void> {
    interface Scram {
      clientNonce: string;
      clientFirstBare: string;
      salted?: Buffer;
      authMessage?: string;
    }
    let scram = null as Scram | null;
    for (;;) {
      const m = await this.next();
      if (m.type === "E") throw this.errorOf(m.body);
      if (m.type === "R") {
        const kind = m.body.readInt32BE(0);
        if (kind === 0) continue;
        if (kind === 3) {
          this.socket.write(msg("p", cstr(o.password ?? "")));
        } else if (kind === 5) {
          const salt = m.body.subarray(4, 8);
          const inner = createHash("md5").update((o.password ?? "") + o.user).digest("hex");
          this.socket.write(msg("p", cstr(`md5${createHash("md5").update(inner).update(salt).digest("hex")}`)));
        } else if (kind === 10) {
          const mechs = m.body.subarray(4).toString("latin1").split("\0").filter(Boolean);
          if (!mechs.includes("SCRAM-SHA-256")) throw new PgError(`the server offers only ${mechs.join(", ")}; SCRAM-SHA-256 is required`);
          const clientNonce = randomBytes(18).toString("base64");
          const clientFirstBare = `n=*,r=${clientNonce}`;
          scram = { clientNonce, clientFirstBare };
          const first = Buffer.from(`n,,${clientFirstBare}`);
          this.socket.write(msg("p", cstr("SCRAM-SHA-256"), i32(first.length), first));
        } else if (kind === 11 && scram) {
          const serverFirst = m.body.subarray(4).toString("utf8");
          const f = Object.fromEntries(serverFirst.split(",").map((p) => [p[0], p.slice(2)])) as Record<string, string>;
          if (!f["r"]?.startsWith(scram.clientNonce) || !f["s"] || !f["i"]) throw new PgError("the server's SCRAM challenge is malformed");
          const iterations = Number(f["i"]);
          if (!Number.isInteger(iterations) || iterations < 1 || iterations > 10_000_000) throw new PgError("the server asked for an unreasonable SCRAM iteration count");
          const salted = pbkdf2Sync(o.password ?? "", Buffer.from(f["s"], "base64"), iterations, 32, "sha256");
          const withoutProof = `c=biws,r=${f["r"]}`;
          const authMessage: string = `${scram.clientFirstBare},${serverFirst},${withoutProof}`;
          const clientKey = hmac(salted, "Client Key");
          const proof = xor(clientKey, hmac(createHash("sha256").update(clientKey).digest(), authMessage));
          scram = { ...scram, salted, authMessage };
          this.socket.write(msg("p", Buffer.from(`${withoutProof},p=${proof.toString("base64")}`)));
        } else if (kind === 12 && scram?.salted && scram.authMessage) {
          const v = /v=(.+)$/.exec(m.body.subarray(4).toString("utf8"))?.[1];
          const expected = hmac(hmac(scram.salted, "Server Key"), scram.authMessage);
          if (!v || Buffer.from(v, "base64").length !== expected.length || !timingSafeEqual(Buffer.from(v, "base64"), expected)) throw new PgError("the server could not prove it knows the password: refusing to continue");
        } else throw new PgError(`unsupported authentication method (${kind})`);
      } else if (m.type === "Z") return;
      // ParameterStatus ('S'), BackendKeyData ('K') and notices ('N') need no action.
    }
  }

  private errorOf(body: Buffer): PgError {
    const f: Record<string, string> = {};
    for (const part of body.toString("utf8").split("\0")) if (part.length > 1) f[part[0] as string] = part.slice(1);
    return new PgError(f["M"] ?? "database error", f["C"], f["D"]);
  }

  /** Runs one statement with text parameters through the extended protocol. `null` is SQL NULL. */
  async query(sql: string, params: ReadonlyArray<string | number | boolean | null> = []): Promise<PgResult> {
    const bind = Buffer.concat([cstr(""), cstr(""), i16(0), i16(params.length), ...params.map((p) => (p === null ? i32(-1) : Buffer.concat([i32(Buffer.byteLength(String(p))), Buffer.from(String(p), "utf8")]))), i16(0)]);
    this.socket.write(Buffer.concat([msg("P", cstr(""), cstr(sql), i16(0)), msg("B", bind), msg("D", Buffer.from("P"), cstr("")), msg("E", cstr(""), i32(0)), msg("S")]));
    const rows: PgRow[] = [];
    let cols: Array<{ name: string; oid: number }> = [];
    let tag = "";
    let err: PgError | null = null;
    for (;;) {
      const m = await this.next();
      if (m.type === "E") err ??= this.errorOf(m.body);
      else if (m.type === "T") {
        const n = m.body.readInt16BE(0);
        cols = [];
        let at = 2;
        for (let i = 0; i < n; i++) {
          const end = m.body.indexOf(0, at);
          const name = m.body.subarray(at, end).toString("utf8");
          at = end + 1;
          cols.push({ name, oid: m.body.readInt32BE(at + 6) });
          at += 18;
        }
      } else if (m.type === "D") {
        const n = m.body.readInt16BE(0);
        const row: PgRow = {};
        let at = 2;
        for (let i = 0; i < n; i++) {
          const len = m.body.readInt32BE(at);
          at += 4;
          const c = cols[i] as { name: string; oid: number };
          if (len === -1) row[c.name] = null;
          else {
            row[c.name] = decode(c.oid, m.body.subarray(at, at + len).toString("utf8"));
            at += len;
          }
        }
        rows.push(row);
      } else if (m.type === "C") tag = m.body.subarray(0, m.body.length - 1).toString("utf8");
      else if (m.type === "Z") {
        if (err) throw err;
        const n = Number(tag.split(" ").at(-1));
        return { rows, rowCount: /^(INSERT|UPDATE|DELETE|SELECT|MERGE|MOVE|FETCH|COPY)/.test(tag) && Number.isFinite(n) ? n : rows.length };
      }
    }
  }

  close(): void {
    try {
      this.socket.write(msg("X"));
    } catch {
      /* already closed */
    }
    this.socket.destroy();
  }
}

/** A few connections shared by callers. A broken connection is dropped and replaced on demand. */
export class PgPool {
  private readonly idle: PgConnection[] = [];
  private readonly waiting: Array<(c: PgConnection) => void> = [];
  private open = 0;
  private closed = false;

  constructor(private readonly options: PgOptions, private readonly size = 4) {}

  private async acquire(): Promise<PgConnection> {
    if (this.closed) throw new PgError("the pool is closed");
    for (;;) {
      const c = this.idle.pop();
      if (!c) break;
      if (!c.broken) return c;
      this.open--;
    }
    if (this.open < this.size) {
      this.open++;
      try {
        return await PgConnection.open(this.options);
      } catch (e) {
        this.open--;
        throw e;
      }
    }
    return new Promise((resolve) => this.waiting.push(resolve));
  }

  private release(c: PgConnection): void {
    if (c.broken) {
      this.open--;
      const w = this.waiting.shift();
      if (w) void this.acquire().then(w);
      return;
    }
    const w = this.waiting.shift();
    if (w) w(c);
    else this.idle.push(c);
  }

  async query(sql: string, params: ReadonlyArray<string | number | boolean | null> = []): Promise<PgResult> {
    const c = await this.acquire();
    try {
      return await c.query(sql, params);
    } finally {
      this.release(c);
    }
  }

  /** Runs `fn` inside a transaction on one connection; rolls back if it throws. */
  async tx<T>(fn: (q: PgConnection["query"]) => Promise<T>): Promise<T> {
    const c = await this.acquire();
    try {
      await c.query("BEGIN");
      try {
        const r = await fn((sql, p) => c.query(sql, p));
        await c.query("COMMIT");
        return r;
      } catch (e) {
        await c.query("ROLLBACK").catch(() => undefined);
        throw e;
      }
    } finally {
      this.release(c);
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const c of this.idle.splice(0)) c.close();
  }
}
