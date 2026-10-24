import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  TOKEN_PREFIX, mintImpersonationSeal, mintScopedApiKey, peekTokenPayload, tokenKind, verifyImpersonationSeal, verifyScopedApiKey, verifySignedToken, evaluatePermission, type TenantPolicy, type UserRecord,
} from "@authvex/core";
import { UsageError, flagBool, flagInt, flagString, parseArgs } from "./args";
import { runInit, DEMO_PASSWORD } from "./commands/init";
import { runDoctor } from "./commands/doctor";
import { runValidate } from "./commands/validate";
import { ConfigError, DEFAULT_PORT, STATE_DIR, loadWorkspace, readKeys, writeKeys } from "./config";
import { EvaluateError, evaluateScenario } from "./evaluate";
import { FileKeyring, loadOrCreateIssuerKey } from "./keyring";
import { createMailer } from "./mail";
import { OIDC_SCOPES, clientsPath, newClientId, newClientSecret, readClients, writeClients, type OidcClient } from "./oidc";
import { Ledger, verifyLedger } from "./ledger";
import { createAuthvexServer } from "./server";
import { openStore } from "./stores";

export interface Io {
  out(line: string): void;
  err(line: string): void;
  cwd: string;
}

export const version = (): string => {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    return (JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version: string }).version;
  } catch {
    return "0.0.0";
  }
};

const HELP = `authvex: a self-hosted hardware-bound identity, passkey and zero-trust session server

Usage: authvex <command> [options]

Commands:
  init [dir]                                   Scaffold authvex.config.json, demo tenants and users, and an issuer key
  validate [dir]                               Check config, tenant policies, RBAC matrices and users
  doctor [dir] [--strict] [--offline]          Check a workspace before going live: secrets, keys, store, mail, demo users (exit 1 on a failure)
  evaluate <tenantId> [options]                Run the AV-101..108 threat gate (exit 0 allow, 2 step-up or blocked)
      --user <id> --geo lat,lon,city --last-minutes <n> --failed <n> --asn <kind>
      --no-dpop --no-mfa --permission <resource:action> --family-reused --json
  key mint --tenant <id> --name <label> --scopes <s1,s2> [--rate <n>] [--ttl <seconds>]
  key list | key revoke <id>                   Manage machine API keys (atk_live_)
  impersonate --actor <userId> --target <userId> --tenant <id> --reason "<ticket>" [--ttl 600] [--write]
  issuer list | rotate [--overlap-hours n] | revoke <kid> | prune     Manage the signing keys (rotation keeps old tokens valid for the overlap)
  oidc client add --tenant <id> --name <label> --redirect <uri[,uri]> [--confidential] [--scopes s1,s2] [--logout-redirect <uri[,uri]>]
  oidc client list | remove <clientId> | rotate-secret <clientId>
  mail test <address>                          Send a test email with the configured mailer
  studio [dir] [--port ${DEFAULT_PORT}] [--host 127.0.0.1] [--no-studio] [--no-ledger] [--quiet]
                                               Start the identity server, API and Studio   (alias: start)
  ledger verify | ledger list [--limit n]      Check or read the hash-chained audit ledger
  token verify <token>                         Verify any ath_ or atk_ token against this workspace

Common options: --config <file>   --json   -h, --help   -v, --version
Exit codes: 0 success, 1 a check failed, 2 bad usage (evaluate: 2 means step-up or blocked).
`;

const BOOLEANS = ["json", "force", "no-ledger", "no-studio", "help", "version", "quiet", "strict", "offline", "no-dpop", "no-mfa", "family-reused", "write", "open"] as const;

const loadWs = (args: ReturnType<typeof parseArgs>, io: Io, dirArg?: string) => loadWorkspace(dirArg ? resolve(io.cwd, dirArg) : io.cwd, flagString(args, "config") ? { file: flagString(args, "config") as string } : {});

export async function main(argv: string[], io: Io, signal?: AbortSignal): Promise<number> {
  const args = parseArgs(argv, BOOLEANS);
  const [command, ...rest] = args.positional;
  const json = flagBool(args, "json");
  try {
    if (flagBool(args, "version") || command === "version" || argv.includes("-v")) return io.out(version()), 0;
    if (!command || flagBool(args, "help") || command === "help" || argv.includes("-h")) return io.out(HELP), 0;
    switch (command) {
      case "init": {
        const r = await runInit(resolve(io.cwd, rest[0] ?? "."), flagBool(args, "force"));
        if (json) io.out(JSON.stringify(r));
        else {
          for (const f of r.created) io.out(`created  ${f}`);
          for (const f of r.skipped) io.out(`kept     ${f} (already exists; use --force to overwrite)`);
          io.out(`\nDemo users all use the password "${DEMO_PASSWORD}". They are for local trials only: delete users.json before real use.`);
          io.out("Next: authvex validate && authvex studio");
        }
        return 0;
      }
      case "validate": {
        const r = runValidate(rest[0] ? resolve(io.cwd, rest[0]) : io.cwd, flagString(args, "config"));
        if (json) io.out(JSON.stringify(r, null, 2));
        else {
          for (const t of r.tenants) io.out(`ok  ${t.id}  ${t.roles} roles, ${t.permissions} permissions  dpop:${t.dpop ? "required" : "optional"}  admin-mfa:${t.mfaForAdmins ? "required" : "optional"}`);
          for (const w of r.warnings) io.out(`warn  ${w}`);
          for (const e of r.errors) io.err(`error  ${e}`);
          io.out(r.ok ? `\n${r.tenants.length} tenants and ${r.users} users valid.` : "\nInvalid.");
        }
        return r.ok ? 0 : 1;
      }
      case "doctor": {
        const r = await runDoctor(rest[0] ? resolve(io.cwd, rest[0]) : io.cwd, { ...(flagString(args, "config") ? { file: flagString(args, "config") as string } : {}), network: !flagBool(args, "offline") });
        const failed = !r.ok || (flagBool(args, "strict") && r.checks.some((c) => c.level === "warn"));
        if (json) io.out(JSON.stringify({ ...r, ok: !failed }, null, 2));
        else {
          const tag = { ok: "ok  ", info: "info", warn: "warn", fail: "FAIL" } as const;
          for (const c of r.checks) (c.level === "fail" ? io.err : io.out)(`${tag[c.level]}  ${c.title}${c.detail ? `\n      ${c.detail}` : ""}`);
          const n = (l: string): number => r.checks.filter((c) => c.level === l).length;
          io.out(`\n${n("fail")} failed, ${n("warn")} warnings. ${failed ? "Not ready for production." : "No blocking problems found."}`);
        }
        return failed ? 1 : 0;
      }
      case "evaluate": {
        const tenantId = rest[0];
        if (!tenantId) throw new UsageError("usage: authvex evaluate <tenantId> [--user id] [--geo lat,lon,city] ...");
        const ws = loadWs(args, io);
        const issuer = await loadOrCreateIssuerKey(ws.root);
        const geo = flagString(args, "geo");
        let currentGeo: { lat: number; lon: number; city: string } | undefined;
        if (geo) {
          const [lat, lon, ...city] = geo.split(",");
          currentGeo = { lat: Number(lat), lon: Number(lon), city: city.join(",").trim() || "Unknown" };
          if (!Number.isFinite(currentGeo.lat) || !Number.isFinite(currentGeo.lon)) throw new UsageError("--geo must look like 51.5074,-0.1278,London");
        }
        const asn = flagString(args, "asn");
        const user = flagString(args, "user");
        const lastMin = flagInt(args, "last-minutes", 0, 525_600);
        const last = user ? ws.users.find((u) => u.id === user)?.lastLoginGeo : undefined;
        const input = {
          tenantId, ...(user ? { userId: user } : {}), secondFactorVerified: !flagBool(args, "no-mfa"), failedAttemptsInWindow: flagInt(args, "failed", 0, 1000) ?? 0,
          ...(currentGeo ? { currentGeo } : {}), ...(last && lastMin !== undefined ? { lastLoginGeo: { lat: last.lat, lon: last.lon, city: last.city, minutesAgo: lastMin } } : {}),
          dpop: flagBool(args, "no-dpop") ? { presented: false, valid: false, keyMatchesSession: false } : { presented: true, valid: true, keyMatchesSession: true },
          ...(asn ? { asnKind: asn } : {}), ...(flagString(args, "permission") ? { permission: flagString(args, "permission") } : {}), ...(flagBool(args, "family-reused") ? { familyStatus: "revoked_reuse_detected" } : {}),
        };
        const { report } = await evaluateScenario({ tenants: new Map(ws.tenants.map((t) => [t.id, t])), users: new Map(ws.users.map((u) => [u.id, u])), issuer, nowMs: Date.now() }, input);
        if (json) io.out(JSON.stringify(report, null, 2));
        else {
          for (const c of report.checks) io.out(`${c.code}  ${c.status.toUpperCase().padEnd(7)} ${c.name}: ${c.message}`);
          io.out(`\ntrust score ${report.score}/100  ->  ${report.level}`);
        }
        return report.level === "LOW" ? 0 : 2;
      }
      case "key": {
        const ws = loadWs(args, io);
        const ledger = new Ledger(join(ws.root, STATE_DIR, "ledger.jsonl"));
        if (rest[0] === "mint") {
          const tenantId = flagString(args, "tenant");
          const name = flagString(args, "name");
          const scopes = flagString(args, "scopes")?.split(",").map((s) => s.trim()).filter(Boolean);
          if (!tenantId || !name || !scopes?.length) throw new UsageError("usage: authvex key mint --tenant <id> --name <label> --scopes <s1,s2>");
          if (!ws.tenants.some((t) => t.id === tenantId)) throw new UsageError(`no tenant "${tenantId}"`);
          const rate = flagInt(args, "rate", 1, 100_000);
          const ttl = flagInt(args, "ttl", 60, 365 * 86_400);
          const { key, record } = await mintScopedApiKey({ tenantId, name, scopes, ...(rate ? { rateLimitPerMin: rate } : {}), ...(ttl ? { ttlSeconds: ttl } : {}) });
          writeKeys(ws.root, [...readKeys(ws.root), record]);
          ledger.append({ type: "key.minted", tenantId, actor: "cli", subject: record.id, detail: { name, keyPrefix: record.keyPrefix, scopes } });
          if (json) io.out(JSON.stringify({ key, record }));
          else {
            io.out(key);
            io.err(`\nStore this key now: only its hash is kept, so it cannot be shown again. Prefix ${record.keyPrefix}, scopes ${scopes.join(", ")}.`);
          }
          return 0;
        }
        if (rest[0] === "list") {
          const ks = readKeys(ws.root);
          if (json) io.out(JSON.stringify(ks.map(({ sha256Hash: _h, ...k }) => k), null, 2));
          else for (const k of ks) io.out(`${k.id}  ${k.keyPrefix}  ${k.tenantId}  ${k.name}  [${k.scopes.join(",")}]${k.revokedAtIso ? "  REVOKED" : ""}`);
          return 0;
        }
        if (rest[0] === "revoke" && rest[1]) {
          const ks = readKeys(ws.root);
          const k = ks.find((x) => x.id === rest[1]);
          if (!k) throw new UsageError(`no key "${rest[1]}"`);
          writeKeys(ws.root, ks.map((x) => (x.id === k.id ? { ...x, revokedAtIso: new Date().toISOString() } : x)));
          ledger.append({ type: "key.revoked", tenantId: k.tenantId, actor: "cli", subject: k.id, detail: { keyPrefix: k.keyPrefix } });
          io.out(`revoked ${k.id}`);
          return 0;
        }
        throw new UsageError("usage: authvex key mint|list|revoke");
      }
      case "impersonate": {
        const ws = loadWs(args, io);
        const [actorId, targetId, tenantId, reason] = ["actor", "target", "tenant", "reason"].map((f) => flagString(args, f));
        if (!actorId || !targetId || !tenantId || !reason) throw new UsageError('usage: authvex impersonate --actor <id> --target <id> --tenant <id> --reason "TICKET-123 why"');
        const tenant = ws.tenants.find((t) => t.id === tenantId) as TenantPolicy | undefined;
        const actor = ws.users.find((u) => u.id === actorId) as UserRecord | undefined;
        const target = ws.users.find((u) => u.id === targetId) as UserRecord | undefined;
        if (!tenant || !actor || !target) throw new UsageError("unknown tenant, actor or target");
        const ledger = new Ledger(join(ws.root, STATE_DIR, "ledger.jsonl"));
        const perm = evaluatePermission(tenant, actor, "users:impersonate");
        if (!perm.allowed) {
          ledger.append({ type: "impersonation.refused", tenantId, actor: actorId, subject: targetId, detail: { reason: perm.reason } });
          io.err(`AV-107: ${perm.message}`);
          return 1;
        }
        const issuer = await loadOrCreateIssuerKey(ws.root);
        const minted = await mintImpersonationSeal({ issuer, actor, target, tenantId, reason, readOnly: !flagBool(args, "write"), ...(flagInt(args, "ttl", 30, 900) ? { ttlSeconds: flagInt(args, "ttl", 30, 900) as number } : {}) });
        ledger.append({ type: "impersonation.minted", tenantId, actor: actorId, subject: targetId, detail: { reason: minted.claims.reason, readOnly: minted.claims.readOnly, expiresAtIso: minted.claims.expiresAtIso, jti: minted.claims.jti } });
        if (json) io.out(JSON.stringify(minted));
        else {
          io.out(minted.token);
          io.err(`\nSealed in the ledger. Read-only: ${minted.claims.readOnly}. Expires ${minted.claims.expiresAtIso}.`);
        }
        return 0;
      }
      case "issuer": {
        const ws = loadWs(args, io);
        const keyring = await FileKeyring.open(ws.root);
        const ledger = new Ledger(join(ws.root, STATE_DIR, "ledger.jsonl"));
        if (rest[0] === "list") {
          const { summary } = await keyring.get(Date.now());
          if (json) io.out(JSON.stringify(summary, null, 2));
          else for (const k of summary) io.out(`${k.kid}  ${k.status.padEnd(16)} ${k.verifies ? "verifies" : "does not verify"}  created ${k.createdAtIso}${k.verifyUntilIso ? `  verifies until ${k.verifyUntilIso}` : ""}${k.retiredReason ? `  (${k.retiredReason})` : ""}`);
          return 0;
        }
        if (rest[0] === "rotate") {
          const hours = flagString(args, "overlap-hours") !== undefined ? Number(flagString(args, "overlap-hours")) : 25;
          if (!Number.isFinite(hours) || hours < 0 || hours > 24 * 90) throw new UsageError("--overlap-hours must be between 0 and 2160");
          const r = await keyring.rotate(Date.now(), hours * 3600);
          ledger.append({ type: "issuer.rotated", actor: "cli", detail: { newKid: r.newKid, oldKid: r.oldKid, overlapHours: hours } });
          if (json) io.out(JSON.stringify(r));
          else {
            io.out(`new signing key ${r.newKid}`);
            io.out(`${r.oldKid} still verifies for ${hours} hours, then stops; tokens it signed expire within that time.`);
            if (hours === 0) io.err("overlap 0: sessions signed by the old key stop working immediately.");
          }
          return 0;
        }
        if (rest[0] === "revoke" && rest[1]) {
          keyring.revoke(rest[1]);
          ledger.append({ type: "issuer.revoked", actor: "cli", detail: { kid: rest[1] } });
          io.out(`revoked ${rest[1]}: every token it signed is now refused`);
          return 0;
        }
        if (rest[0] === "prune") {
          const r = keyring.prune();
          if (r.expired.length + r.removed.length > 0) ledger.append({ type: "issuer.pruned", actor: "cli", detail: { ...r } });
          io.out(`retired ${r.expired.length}, removed ${r.removed.length}`);
          return 0;
        }
        throw new UsageError("usage: authvex issuer list | rotate [--overlap-hours n] | revoke <kid> | prune");
      }
      case "oidc": {
        if (rest[0] !== "client") throw new UsageError("usage: authvex oidc client add|list|remove|rotate-secret");
        const ws = loadWs(args, io);
        const path = clientsPath(ws.root, ws.config);
        const list = readClients(path);
        const ledger = new Ledger(join(ws.root, STATE_DIR, "ledger.jsonl"));
        const sub = rest[1];
        const split = (v: string | undefined): string[] => (v ?? "").split(",").map((x) => x.trim()).filter(Boolean);
        if (sub === "add") {
          const tenantId = flagString(args, "tenant");
          const name = flagString(args, "name");
          const redirects = split(flagString(args, "redirect"));
          if (!tenantId || !name || redirects.length === 0) throw new UsageError("usage: authvex oidc client add --tenant <id> --name <label> --redirect <uri[,uri]> [--confidential]");
          if (!ws.tenants.some((t) => t.id === tenantId)) throw new UsageError(`no tenant "${tenantId}"`);
          const confidential = flagBool(args, "confidential");
          const secret = confidential ? newClientSecret() : null;
          const scopes = split(flagString(args, "scopes"));
          const client: OidcClient = { clientId: newClientId(), name, tenantId, type: confidential ? "confidential" : "public", ...(secret ? { secretHash: secret.hash } : {}), redirectUris: redirects, allowedScopes: (scopes.length ? scopes : [...OIDC_SCOPES]) as OidcClient["allowedScopes"], postLogoutRedirectUris: split(flagString(args, "logout-redirect")) };
          const { ClientSchema } = await import("./oidc");
          const parsed = ClientSchema.safeParse(client);
          if (!parsed.success) throw new UsageError(parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
          writeClients(path, [...list, parsed.data]);
          ledger.append({ type: "oidc.client_added", tenantId, actor: "cli", subject: client.clientId, detail: { name, type: client.type, redirectUris: redirects } });
          if (json) io.out(JSON.stringify({ clientId: client.clientId, ...(secret ? { clientSecret: secret.secret } : {}), issuer: `<base>/oidc/${tenantId}` }));
          else {
            io.out(`client_id      ${client.clientId}`);
            if (secret) io.out(`client_secret  ${secret.secret}`);
            io.out(`issuer         <your public URL>/oidc/${tenantId}   (discovery: …/.well-known/openid-configuration)`);
            if (secret) io.err("\nStore the client secret now: only its hash is kept, so it cannot be shown again.");
          }
          return 0;
        }
        if (sub === "list") {
          if (json) io.out(JSON.stringify(list.map(({ secretHash: _s, ...c }) => c), null, 2));
          else for (const c of list) io.out(`${c.clientId}  ${c.type.padEnd(12)} ${c.tenantId}  ${c.name}  redirects: ${c.redirectUris.join(", ")}`);
          return 0;
        }
        if (sub === "remove" && rest[2]) {
          const c = list.find((x) => x.clientId === rest[2]);
          if (!c) throw new UsageError(`no client "${rest[2]}"`);
          writeClients(path, list.filter((x) => x.clientId !== c.clientId));
          ledger.append({ type: "oidc.client_removed", tenantId: c.tenantId, actor: "cli", subject: c.clientId, detail: { name: c.name } });
          io.out(`removed ${c.clientId}. Sessions it already holds keep working until they expire or are revoked.`);
          return 0;
        }
        if (sub === "rotate-secret" && rest[2]) {
          const c = list.find((x) => x.clientId === rest[2]);
          if (!c) throw new UsageError(`no client "${rest[2]}"`);
          if (c.type !== "confidential") throw new UsageError("a public client has no secret");
          const secret = newClientSecret();
          writeClients(path, list.map((x) => (x.clientId === c.clientId ? { ...x, secretHash: secret.hash } : x)));
          ledger.append({ type: "oidc.client_secret_rotated", tenantId: c.tenantId, actor: "cli", subject: c.clientId, detail: {} });
          io.out(secret.secret);
          io.err("\nThe old secret stopped working at once. Store this one now: it cannot be shown again.");
          return 0;
        }
        throw new UsageError("usage: authvex oidc client add|list|remove|rotate-secret");
      }
      case "mail": {
        if (rest[0] !== "test" || !rest[1]) throw new UsageError("usage: authvex mail test <address>");
        const ws = loadWs(args, io);
        const mailer = createMailer(ws.config, ws.root, process.env, (l) => io.out(l));
        if (!mailer) throw new UsageError("no \"mail\" block in authvex.config.json");
        await mailer.send({ to: rest[1], subject: "Authvex test message", text: "If you can read this, Authvex can send email through the configured mailer.\n" });
        io.out(`sent through the ${mailer.kind} mailer to ${rest[1]}`);
        return 0;
      }
      case "studio":
      case "start":
        return await runStudio(args, io, rest[0], signal);
      case "ledger": {
        const dir = resolve(io.cwd);
        const file = join(flagString(args, "config") ? loadWs(args, io).root : dir, STATE_DIR, "ledger.jsonl");
        if (rest[0] === "verify") {
          const r = verifyLedger(file);
          if (json) io.out(JSON.stringify(r));
          else if (r.ok) io.out(`ok  ${r.entries} entr${r.entries === 1 ? "y" : "ies"}, head ${r.head.slice(0, 16)}…`);
          else io.err(`BROKEN at entry ${r.brokenAt}: ${r.reason}`);
          return r.ok ? 0 : 1;
        }
        if (rest[0] === "list") {
          const entries = new Ledger(file).list(flagInt(args, "limit", 1, 10_000) ?? 50);
          if (json) io.out(JSON.stringify(entries));
          else for (const e of entries) io.out(`#${e.n}  ${new Date(e.ts).toISOString()}  ${e.type}${e.tenantId ? `  ${e.tenantId}` : ""}${e.actor ? `  by ${e.actor}` : ""}${e.subject ? `  on ${e.subject}` : ""}`);
          return 0;
        }
        throw new UsageError("usage: authvex ledger verify | list");
      }
      case "token": {
        if (rest[0] !== "verify" || !rest[1]) throw new UsageError("usage: authvex token verify <token>");
        const ws = loadWs(args, io);
        const { keys: issuerKeys } = await (await FileKeyring.open(ws.root)).get(Date.now());
        const token = rest[1];
        const kind = tokenKind(token);
        let out: Record<string, unknown>;
        if (kind === "apiKey") {
          const r = await verifyScopedApiKey(token, readKeys(ws.root));
          out = r.ok ? { kind, valid: true, key: { id: r.record.id, tenantId: r.record.tenantId, scopes: r.record.scopes } } : { kind, valid: false, reason: r.reason };
        } else if (kind === "impersonation") {
          const r = await verifyImpersonationSeal(token, issuerKeys);
          out = r.ok ? { kind, valid: true, claims: r.claims, secondsLeft: r.secondsLeft } : { kind, valid: false, reason: r.reason, message: r.message };
        } else if (kind === "session" || kind === "admin") {
          const r = await verifySignedToken<{ exp?: number }>(TOKEN_PREFIX[kind], token, issuerKeys);
          const expired = r.ok && typeof r.payload.exp === "number" && r.payload.exp * 1000 <= Date.now();
          out = r.ok ? { kind, valid: !expired, ...(expired ? { reason: "expired" } : {}), claims: r.payload } : { kind, valid: false, reason: r.reason };
        } else out = { kind: kind ?? "unknown", valid: false, reason: "unverifiable", claims: peekTokenPayload(token) };
        io.out(json ? JSON.stringify(out) : JSON.stringify(out, null, 2));
        return out["valid"] === true ? 0 : 1;
      }
      default:
        throw new UsageError(`unknown command "${command}". Run authvex --help`);
    }
  } catch (e) {
    if (e instanceof UsageError) return io.err(e.message), 2;
    if (e instanceof ConfigError || e instanceof EvaluateError) return io.err(e.message), 1;
    io.err(e instanceof Error ? e.message : String(e));
    return 1;
  }
}

async function runStudio(args: ReturnType<typeof parseArgs>, io: Io, dirArg: string | undefined, signal?: AbortSignal): Promise<number> {
  const ws = loadWs(args, io, dirArg);
  const keyring = await FileKeyring.open(ws.root);
  const port = flagInt(args, "port", 0, 65535);
  const host = flagString(args, "host");
  const cfg = { ...ws.config, ...(port !== undefined ? { port } : {}), ...(host ? { host } : {}) };
  const here = dirname(fileURLToPath(import.meta.url));
  const ledger = cfg.ledger && !flagBool(args, "no-ledger") ? new Ledger(join(ws.root, STATE_DIR, "ledger.jsonl")) : null;
  const studioDir = flagBool(args, "no-studio") ? undefined : join(here, "..", "studio");
  const store = await openStore(cfg, ws.root);
  const mailer = createMailer(cfg, ws.root, process.env, (l) => io.err(`[authvex] ${l}`));
  const server = createAuthvexServer({ workspace: { ...ws, config: cfg }, keyring, store, mailer, ledger, version: version(), ...(studioDir ? { studioDir } : {}), ...(flagBool(args, "quiet") ? {} : { log: (l: string) => io.err(cfg.logging.format === "json" ? l : `[authvex] ${l}`) }) });
  const addr = await server.listen();
  const base = server.url();
  ledger?.append({ type: "server.started", actor: "cli", detail: { version: version(), tenants: ws.tenants.length, users: ws.users.length, kid: (await keyring.get(Date.now())).issuer.kid, store: store.kind } });
  io.out(`Authvex ${version()} listening on ${base}`);
  io.out(`  API         ${base}/api/health`);
  io.out(`  Studio      ${base}/#token=${server.adminToken}`);
  io.out(`  Tenants     ${ws.tenants.map((t) => t.id).join(", ") || "(none; run authvex init)"}`);
  const state = await keyring.get(Date.now());
  io.out(`  Issuer kid  ${state.issuer.kid}`);
  io.out(`  JWKS        ${base}/.well-known/jwks.json`);
  io.out(`  Email       ${mailer ? mailer.kind : "not configured (sign-up, password reset and magic links are off)"}`);
  io.out(`  State       ${store.kind}${store.kind === "memory" ? " (sessions are lost on restart)" : ""}`);
  if (addr.host !== "127.0.0.1" && addr.host !== "::1") io.err(`warning: bound to ${addr.host}; the Studio link above carries an admin token, so put the server behind TLS and keep that link private.`);
  if (cfg.trustClientGeo) io.err("warning: trustClientGeo is on: clients can claim any location. Demo use only.");
  await new Promise<void>((done) => {
    const stop = (): void => done();
    signal?.addEventListener("abort", stop, { once: true });
    if (!signal) {
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
    }
  });
  io.out("\nshutting down…");
  await server.close();
  await store.close();
  return 0;
}
