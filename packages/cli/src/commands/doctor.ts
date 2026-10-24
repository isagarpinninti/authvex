import { existsSync, readFileSync, statSync } from "node:fs";
import { connect } from "node:net";
import { resolve } from "node:path";
import { describeKeyring, parseCertificate, pemToDer, validateKeyring } from "@authvex/core";
import { ConfigError, STATE_DIR, keysFile, loadWorkspace, type Workspace } from "../config";
import { DEMO_PASSWORD } from "./init";
import { verifyLedger } from "../ledger";
import { keyringPath } from "../keyring";
import { argon2Available, createPasswordHasher } from "../passwords";
import { PgConnection, parsePgUrl } from "../pg";
import { sqliteAvailable } from "../stores";
import { runValidate } from "./validate";

export type CheckLevel = "ok" | "info" | "warn" | "fail";
export interface Check {
  id: string;
  level: CheckLevel;
  title: string;
  detail?: string;
}
export interface DoctorReport {
  ok: boolean;
  checks: Check[];
}

const DAY = 86_400_000;

/**
 * Looks at a workspace the way an operator would before going live: configuration, secrets on disk, the store and mail
 * transports, key age, the audit ledger. It only reads (it never creates keys or tables) and never prints a secret.
 * `fail` means do not run this in production; `warn` means you should know about it.
 */
export async function runDoctor(cwd: string, opts: { file?: string; env?: NodeJS.ProcessEnv; nowMs?: number; network?: boolean } = {}): Promise<DoctorReport> {
  const env = opts.env ?? process.env;
  const now = opts.nowMs ?? Date.now();
  const network = opts.network ?? true;
  const checks: Check[] = [];
  const add = (id: string, level: CheckLevel, title: string, detail?: string): void => void checks.push({ id, level, title, ...(detail ? { detail } : {}) });

  const major = Number(process.versions.node.split(".")[0]);
  if (major < 20) add("node", "fail", `Node.js ${process.versions.node} is too old`, "Authvex needs Node.js 20 or later");
  else add("node", "ok", `Node.js ${process.versions.node}`, `${major >= 22 ? "SQLite store available" : "SQLite store needs 22.5+"}; ${argon2Available() ? "Argon2id available" : "Argon2id needs 24.7+"}`);

  let ws: Workspace;
  try {
    ws = loadWorkspace(cwd, opts.file ? { file: opts.file } : {});
  } catch (e) {
    add("config", "fail", "Configuration cannot be loaded", e instanceof ConfigError || e instanceof Error ? e.message : String(e));
    return finish(checks);
  }
  const cfg = ws.config;
  add("config", ws.configFile ? "ok" : "warn", ws.configFile ? `Configuration loaded from ${ws.configFile}` : "No authvex.config.json: running on defaults", ws.configFile ? undefined : "run `authvex init`");
  add("workspace", ws.tenants.length > 0 && ws.users.length > 0 ? "ok" : "warn", `${ws.tenants.length} tenants, ${ws.users.length} users`);

  const v = runValidate(ws.root, opts.file);
  for (const e of v.errors) add("validate", "fail", e);
  for (const w of v.warnings) add("validate", "warn", w);

  // Secrets on disk
  if (process.platform !== "win32") {
    for (const [label, path] of [["issuer keyring", keyringPath(ws.root)], ["API keys", keysFile(ws.root)], ["users", ws.usersFile]] as const) {
      if (!existsSync(path)) continue;
      const mode = statSync(path).mode & 0o777;
      if (mode & 0o077) add("permissions", "warn", `${label} file is readable by others (mode ${mode.toString(8)})`, `run: chmod 600 ${path}`);
    }
  }

  // The published demo password must not survive into production.
  if (ws.users.length > 0 && ws.users.length <= 200) {
    const hasher = createPasswordHasher({ ...cfg.passwordHashing, algorithm: "pbkdf2" });
    const demo: string[] = [];
    for (const u of ws.users) if (u.passwordHash && (await hasher.verify(DEMO_PASSWORD, u.passwordHash))) demo.push(u.email);
    if (demo.length > 0) add("demo-users", "fail", `${demo.length} users still have the published demo password`, `${demo.slice(0, 3).join(", ")}${demo.length > 3 ? ", ..." : ""}: delete them or change their passwords before real use`);
    else add("demo-users", "ok", "No user has the published demo password");
  }

  // Addresses
  let publicHost: string | undefined;
  if (cfg.publicUrl) {
    try {
      const u = new URL(cfg.publicUrl);
      publicHost = u.hostname;
      const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
      if (u.protocol !== "https:" && !local) add("public-url", "warn", `publicUrl ${cfg.publicUrl} is not https`, "tokens and passwords would cross the network in clear text");
      else add("public-url", "ok", `publicUrl ${cfg.publicUrl}`);
      if (!local && cfg.rpId !== u.hostname && !u.hostname.endsWith(`.${cfg.rpId}`)) add("rp-id", "fail", `rpId "${cfg.rpId}" is not the host or a parent domain of publicUrl (${u.hostname})`, "passkeys cannot work: browsers refuse an rpId that is not a suffix of the page's domain");
    } catch {
      add("public-url", "fail", `publicUrl is not a valid URL: ${cfg.publicUrl}`);
    }
  } else if (!["127.0.0.1", "localhost", "::1"].includes(cfg.host)) add("public-url", "warn", `listening on ${cfg.host} without publicUrl`, "issuer URLs follow the request's Host header; set publicUrl to the address clients use");
  if (!["127.0.0.1", "localhost", "::1"].includes(cfg.host)) add("bind", "info", `listening on ${cfg.host}`, "put TLS in front of it");
  if (publicHost === undefined && cfg.origins.length === 0) add("origins", "warn", "origins is empty", "list your app origins so passkeys and CORS are restricted to them");

  // Signing keys
  const kp = keyringPath(ws.root);
  if (!existsSync(kp)) add("keys", "info", "No issuer keyring yet", "it is created on first start");
  else {
    try {
      const summary = describeKeyring(validateKeyring(JSON.parse(readFileSync(kp, "utf8"))), now);
      const active = summary.find((k) => k.status === "active");
      if (!active) add("keys", "fail", "No active signing key");
      else {
        const age = Math.floor((now - Date.parse(active.createdAtIso)) / DAY);
        add("keys", age > 180 ? "warn" : "ok", `Active signing key ${active.kid} is ${age} days old`, age > 180 ? "rotate it: authvex issuer rotate" : undefined);
      }
      const expired = summary.filter((k) => k.status === "retiring-expired").length;
      if (expired > 0) add("keys-prune", "info", `${expired} retired keys can be removed`, "authvex issuer prune");
    } catch (e) {
      add("keys", "fail", "The issuer keyring cannot be read", e instanceof Error ? e.message : String(e));
    }
  }

  // Store
  const kind = cfg.store.kind;
  if (kind === "memory") add("store", "warn", "Store is memory: sessions and the replay cache are lost on every restart");
  else if (kind === "file") add("store", "ok", "Store is file", "survives restarts; one server process only");
  else if (kind === "sqlite") add("store", (await sqliteAvailable()) ? "ok" : "fail", (await sqliteAvailable()) ? "Store is sqlite" : "Store is sqlite, but this Node.js has no node:sqlite", "needs Node.js 22.5+");
  else {
    const url = env[cfg.store.urlEnv];
    if (!url) add("store", "fail", `Store is postgres, but ${cfg.store.urlEnv} is not set`);
    else {
      try {
        const p = parsePgUrl(url);
        if (p.sslmode === "disable" && !["127.0.0.1", "localhost", "::1"].includes(p.host)) add("store-tls", "warn", `The database connection to ${p.host} does not use TLS`, "add ?sslmode=verify-full to the URL");
        if (!network) add("store", "info", "Store is postgres (connection not tested)");
        else {
          const c = await Promise.race([PgConnection.open(p), new Promise<never>((_, rej) => setTimeout(() => rej(new Error("timed out after 5 seconds")), 5000).unref())]);
          await c.query("SELECT 1");
          c.close();
          add("store", "ok", `Store is postgres at ${p.host}:${p.port}/${p.database}`, `schema ${cfg.store.schema}`);
        }
      } catch (e) {
        add("store", "fail", "Cannot reach the PostgreSQL database", e instanceof Error ? e.message : String(e));
      }
    }
  }

  // Password hashing
  const alg = cfg.passwordHashing.algorithm;
  if (alg === "argon2id" && !argon2Available()) add("hashing", "fail", "passwordHashing is argon2id, but this Node.js has no Argon2", "needs Node.js 24.7+; use scrypt or upgrade");
  else if (alg === "pbkdf2") add("hashing", "info", "Passwords use PBKDF2 (210,000 iterations)", 'works everywhere; scrypt or argon2id are memory-hard: set passwordHashing.algorithm');
  else add("hashing", "ok", `Passwords use ${alg}`);

  // Mail
  if (cfg.mail?.driver === "smtp" && cfg.mail.smtp && network) {
    const { host, port } = cfg.mail.smtp;
    const reachable = await new Promise<boolean>((done) => {
      const s = connect({ host, port, timeout: 4000 });
      s.once("connect", () => (s.destroy(), done(true)));
      s.once("timeout", () => (s.destroy(), done(false)));
      s.once("error", () => done(false));
    });
    add("mail", reachable ? "ok" : "warn", reachable ? `SMTP server ${host}:${port} is reachable` : `SMTP server ${host}:${port} is not reachable`, reachable ? undefined : "emails will fail");
    if (cfg.mail.smtp.passwordEnv && !env[cfg.mail.smtp.passwordEnv]) add("mail-auth", "fail", `SMTP password variable ${cfg.mail.smtp.passwordEnv} is not set`);
  }

  // Passkey attestation anchors
  if (cfg.attestation.trustAnchors) {
    try {
      const certs = pemToDer(readFileSync(resolve(ws.root, cfg.attestation.trustAnchors), "utf8")).map((d) => parseCertificate(d));
      const expired = certs.filter((c) => c.notAfterMs < now).length;
      const soon = certs.filter((c) => c.notAfterMs >= now && c.notAfterMs < now + 90 * DAY).length;
      add("attestation", expired > 0 ? "warn" : "ok", `${certs.length} attestation trust anchors${expired ? `, ${expired} expired` : ""}${soon ? `, ${soon} expire within 90 days` : ""}`);
    } catch (e) {
      add("attestation", "fail", "Attestation trust anchors cannot be read", e instanceof Error ? e.message : String(e));
    }
  }

  // Metrics
  if (cfg.metrics.enabled) {
    const t = env[cfg.metrics.tokenEnv];
    add("metrics", t && t.length >= 16 ? "ok" : "fail", t && t.length >= 16 ? "Metrics are on, with a scrape token" : `Metrics are on, but ${cfg.metrics.tokenEnv} is missing or shorter than 16 characters`);
  }

  // Ledger
  const ledgerPath = resolve(ws.root, STATE_DIR, "ledger.jsonl");
  if (cfg.ledger && existsSync(ledgerPath)) {
    const r = verifyLedger(ledgerPath);
    add("ledger", r.ok ? "ok" : "fail", r.ok ? `Audit ledger intact (${r.entries} entries)` : `Audit ledger is broken at entry ${r.brokenAt}`, r.ok ? undefined : r.reason);
  } else if (!cfg.ledger) add("ledger", "warn", "The audit ledger is switched off");

  return finish(checks);
}

const finish = (checks: Check[]): DoctorReport => ({ ok: !checks.some((c) => c.level === "fail"), checks });
