import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { z } from "zod";
import { TenantPolicySchema, UserRecordSchema, checkWorkspace, type TenantPolicy, type UserRecord, type ApiKeyRecord } from "@authvex/core";

export const CONFIG_FILE = "authvex.config.json";
export const STATE_DIR = ".authvex";
export const DEFAULT_PORT = 4320;

export const ConfigSchema = z
  .object({
    port: z.number().int().min(0).max(65535).default(DEFAULT_PORT),
    host: z.string().min(1).default("127.0.0.1"),
    /** The public base URL clients use (the DPoP `htu` is checked against it). Default: http://host:port. */
    publicUrl: z.string().url().optional(),
    /** Relying Party id for passkeys: the registrable domain of your app. */
    rpId: z.string().min(1).default("localhost"),
    /** Page origins allowed to use passkeys and to call the API from a browser. Empty allows any origin for the API only. */
    origins: z.array(z.string().url()).default([]),
    tenants: z.string().min(1).default("tenants"),
    users: z.string().min(1).default("users.json"),
    ledger: z.boolean().default(true),
    /** Accept a client-supplied location on login. Only for demos: a real deployment sets it from a trusted proxy header. */
    trustClientGeo: z.boolean().default(false),
    /** Read the location from `X-Authvex-Geo: lat,lon,city` and the network kind from `X-Authvex-Asn` (set by your edge, never by users). */
    trustGeoHeaders: z.boolean().default(false),
    /**
     * Opt-in leeway for lost refresh responses. A client that never received the answer to a refresh and retries with the same token
     * within this many seconds gets a fresh pair instead of having its session revoked as a suspected theft. Only for sessions bound to
     * a device key (a thief without the key cannot use the grace), only for the most recently spent token, and 0 (off) by default.
     */
    refreshReuseGraceSeconds: z.number().int().min(0).max(60).default(0),
    /** Failed-login sliding window. */
    failedAttemptWindowSeconds: z.number().int().min(30).default(900),
    /** Where sessions and the replay cache live: `file` (default; survives a restart, one process), `sqlite` (shareable between processes on one machine; Node 22.5+), `postgres` (shareable between hosts) or `memory`. */
    store: z
      .object({
        kind: z.enum(["memory", "file", "sqlite", "postgres"]).default("file"),
        path: z.string().min(1).optional(),
        /** For `postgres`: the NAME of the environment variable holding the connection URL (`postgres://user:password@host/db?sslmode=require`). The URL never goes in this file. */
        urlEnv: z.string().min(1).default("AUTHVEX_DATABASE_URL"),
        /** For `postgres`: the schema the tables live in. */
        schema: z.string().regex(/^[a-z_][a-z0-9_]{0,40}$/).default("authvex"),
        poolSize: z.number().int().min(1).max(100).default(4),
      })
      .strict()
      .default({ kind: "file", urlEnv: "AUTHVEX_DATABASE_URL", schema: "authvex", poolSize: 4 }),
    /**
     * Passkey attestation: proof of which authenticator model made a credential. The default asks browsers for none, which is what
     * most apps want. `packed` and `fido-u2f` can be verified against root certificates you supply (`trustAnchors`, a PEM file next to
     * this config, e.g. the vendor roots from the FIDO Metadata Service). `requireTrusted` refuses any credential whose attestation
     * does not chain to one of them. Revocation is not checked.
     */
    attestation: z
      .object({
        formats: z.array(z.enum(["none", "packed", "fido-u2f"])).min(1).default(["none"]),
        trustAnchors: z.string().min(1).optional(),
        requireTrusted: z.boolean().default(false),
      })
      .strict()
      .refine((a) => !a.requireTrusted || a.trustAnchors !== undefined, { message: "requireTrusted needs trustAnchors", path: ["trustAnchors"] })
      .default({ formats: ["none"], requireTrusted: false }),
    /**
     * How passwords are hashed. `pbkdf2` (default) needs nothing beyond Web Crypto. `scrypt` and `argon2id` are memory-hard and run on
     * Node's own crypto (`argon2id` needs Node 24.7+). Existing users keep working under their old hash and are upgraded at their
     * next successful sign-in.
     */
    passwordHashing: z
      .object({
        algorithm: z.enum(["pbkdf2", "scrypt", "argon2id"]).default("pbkdf2"),
        scrypt: z.object({ N: z.number().int().min(2 ** 14).max(2 ** 20).default(2 ** 17), r: z.number().int().min(1).max(32).default(8), p: z.number().int().min(1).max(16).default(1) }).strict().default({ N: 2 ** 17, r: 8, p: 1 }),
        argon2id: z.object({ memoryKiB: z.number().int().min(8192).max(1024 * 1024).default(65536), passes: z.number().int().min(1).max(20).default(3), parallelism: z.number().int().min(1).max(16).default(1) }).strict().default({ memoryKiB: 65536, passes: 3, parallelism: 1 }),
      })
      .strict()
      .default({ algorithm: "pbkdf2", scrypt: { N: 2 ** 17, r: 8, p: 1 }, argon2id: { memoryKiB: 65536, passes: 3, parallelism: 1 } }),
    /** Log format on stderr: `text` (default) or one JSON object per line. `requests` adds a line per HTTP request (route, status, duration; never the query string). */
    logging: z.object({ format: z.enum(["text", "json"]).default("text"), requests: z.boolean().default(false) }).strict().default({ format: "text", requests: false }),
    /**
     * Prometheus metrics at `GET /metrics`, off by default. When on, scrapers authenticate with `Authorization: Bearer <token>` where the
     * token is read from the environment variable named by `tokenEnv` (never from this file); the server refuses to start without it.
     */
    metrics: z.object({ enabled: z.boolean().default(false), tokenEnv: z.string().min(1).default("AUTHVEX_METRICS_TOKEN") }).strict().default({ enabled: false, tokenEnv: "AUTHVEX_METRICS_TOKEN" }),
    /** Email for sign-up confirmation, password reset and magic links. Without it those endpoints answer 501. */
    mail: z
      .object({
        driver: z.enum(["console", "file", "smtp"]),
        from: z.string().email(),
        /** Where the links in emails point: your app (or the Studio). The token travels in the URL fragment. */
        linkBase: z.string().url(),
        /** For the `file` driver: the outbox file, relative to the config (default `.authvex/outbox.jsonl`). */
        outbox: z.string().min(1).optional(),
        smtp: z
          .object({
            host: z.string().min(1),
            port: z.number().int().min(1).max(65535).default(587),
            /** TLS from the first byte (port 465). */
            secure: z.boolean().default(false),
            startTls: z.enum(["required", "opportunistic", "never"]).default("required"),
            user: z.string().optional(),
            /** The NAME of the environment variable holding the SMTP password: it never goes in this file. */
            passwordEnv: z.string().optional(),
            rejectUnauthorized: z.boolean().default(true),
            timeoutMs: z.number().int().min(1000).default(15_000),
          })
          .strict()
          .optional(),
      })
      .strict()
      .refine((m) => m.driver !== "smtp" || m.smtp !== undefined, { message: "driver smtp needs an smtp block", path: ["smtp"] })
      .optional(),
    /** OpenID Connect: clients are listed in a file managed by `authvex oidc client`. */
    oidc: z
      .object({
        clients: z.string().min(1).default("oidc-clients.json"),
        /** Where `/authorize` sends the user to sign in. Default: this server's own `/signin/` page. */
        signInUrl: z.string().url().optional(),
      })
      .strict()
      .default({ clients: "oidc-clients.json" }),
    /** Sign-in, challenge and refresh requests allowed per minute from one address. */
    ipRequestsPerMinute: z.number().int().min(1).max(100_000).default(30),
    maxBodyBytes: z.number().int().min(1024).max(4 * 1024 * 1024).default(64 * 1024),
  })
  .strict();
export type AuthvexConfig = z.infer<typeof ConfigSchema>;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const readJson = (path: string): unknown => {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (e) {
    throw new ConfigError(`${path}: ${e instanceof Error ? e.message : "cannot be read"}`);
  }
};

const describe = (where: string, error: z.ZodError): string => error.issues.map((i) => `${where}${i.path.length ? `: ${i.path.join(".")}` : ""}: ${i.message}`).join("\n");

export interface Workspace {
  root: string;
  configFile: string | null;
  config: AuthvexConfig;
  tenants: TenantPolicy[];
  tenantFiles: Map<string, string>;
  users: UserRecord[];
  usersFile: string;
}

export function loadTenants(dir: string): { tenants: TenantPolicy[]; files: Map<string, string> } {
  const tenants: TenantPolicy[] = [];
  const files = new Map<string, string>();
  if (!existsSync(dir)) return { tenants, files };
  for (const name of readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    const path = join(dir, name);
    const parsed = TenantPolicySchema.safeParse(readJson(path));
    if (!parsed.success) throw new ConfigError(describe(path, parsed.error));
    if (files.has(parsed.data.id)) throw new ConfigError(`${path}: tenant "${parsed.data.id}" is already defined in ${files.get(parsed.data.id)}`);
    files.set(parsed.data.id, path);
    tenants.push(parsed.data);
  }
  return { tenants, files };
}

export function loadWorkspace(cwd: string, options: { file?: string } = {}): Workspace {
  const root = resolve(cwd);
  const path = options.file ? resolve(root, options.file) : join(root, CONFIG_FILE);
  const has = existsSync(path);
  if (options.file && !has) throw new ConfigError(`${path}: no such file`);
  let config: AuthvexConfig;
  if (has) {
    const parsed = ConfigSchema.safeParse(readJson(path));
    if (!parsed.success) throw new ConfigError(describe(path, parsed.error));
    config = parsed.data;
  } else config = ConfigSchema.parse({});
  const { tenants, files } = loadTenants(resolve(root, config.tenants));
  const usersFile = resolve(root, config.users);
  let users: UserRecord[] = [];
  if (existsSync(usersFile)) {
    const raw = readJson(usersFile);
    if (!Array.isArray(raw)) throw new ConfigError(`${usersFile}: expected an array of users`);
    users = raw.map((u, i) => {
      const parsed = UserRecordSchema.safeParse(u);
      if (!parsed.success) throw new ConfigError(describe(`${usersFile}[${i}]`, parsed.error));
      return parsed.data;
    });
  }
  const problems = checkWorkspace(tenants, users);
  if (problems.length > 0) throw new ConfigError(problems.map((p) => `${usersFile}: ${p}`).join("\n"));
  return { root, configFile: has ? path : null, config, tenants, tenantFiles: files, users, usersFile };
}

/** Writes JSON atomically so a crash never leaves half a file. */
export function writeJsonAtomic(path: string, value: unknown, mode?: number): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, mode !== undefined ? { mode } : undefined);
  renameSync(tmp, path);
}

export const keysFile = (root: string): string => join(root, STATE_DIR, "keys.json");

export function readKeys(root: string): ApiKeyRecord[] {
  const f = keysFile(root);
  return existsSync(f) ? (readJson(f) as ApiKeyRecord[]) : [];
}

export function writeKeys(root: string, keys: ApiKeyRecord[]): void {
  mkdirSync(join(root, STATE_DIR), { recursive: true });
  writeJsonAtomic(keysFile(root), keys, 0o600);
}
