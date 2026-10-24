import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { buildPermissionMatrix } from "@authvex/core";
import { ConfigError, loadWorkspace } from "../config";
import { clientsPath, readClients } from "../oidc";

export interface ValidateReport {
  ok: boolean;
  configFile: string | null;
  tenants: Array<{ id: string; roles: number; permissions: number; dpop: boolean; mfaForAdmins: boolean }>;
  users: number;
  errors: string[];
  warnings: string[];
}

export function runValidate(cwd: string, file?: string): ValidateReport {
  const r: ValidateReport = { ok: true, configFile: null, tenants: [], users: 0, errors: [], warnings: [] };
  try {
    const ws = loadWorkspace(cwd, file ? { file } : {});
    r.configFile = ws.configFile;
    r.users = ws.users.length;
    if (!ws.configFile) r.warnings.push("no authvex.config.json found; using defaults (run `authvex init`)");
    if (ws.tenants.length === 0) r.warnings.push(`no tenants in ${ws.config.tenants}/; nobody can sign in`);
    if (ws.config.trustClientGeo) r.warnings.push("trustClientGeo is on: clients can claim any location, which defeats impossible-travel detection. Use it for demos only");
    if (ws.config.origins.length === 0) r.warnings.push("origins is empty: passkeys will only accept the server's own URL as the page origin, and the API accepts calls from any origin");
    if (ws.config.rpId === "localhost") r.warnings.push('rpId is "localhost": set it to your app\'s registrable domain before real use');
    const oidcClients = readClients(clientsPath(ws.root, ws.config));
    for (const c of oidcClients) {
      if (!ws.tenants.some((t) => t.id === c.tenantId)) r.errors.push(`oidc client ${c.clientId}: unknown tenant "${c.tenantId}"`);
      if (c.redirectUris.some((u) => u.startsWith("http://"))) r.warnings.push(`oidc client ${c.clientId}: has an http redirect URI (loopback only is fine for development)`);
    }
    if (oidcClients.length > 0 && !ws.config.publicUrl) r.warnings.push("oidc clients exist but publicUrl is not set: the issuer URL follows the request's Host header. Set publicUrl to the address clients use");
    const mail = ws.config.mail;
    if (ws.config.metrics.enabled && !process.env[ws.config.metrics.tokenEnv]) r.warnings.push(`metrics are enabled but ${ws.config.metrics.tokenEnv} is not set in this environment: the server will not start without it`);
    if (ws.config.attestation.trustAnchors && !existsSync(resolve(ws.root, ws.config.attestation.trustAnchors))) r.errors.push(`attestation.trustAnchors: ${ws.config.attestation.trustAnchors} does not exist`);
    if (ws.config.refreshReuseGraceSeconds > 0) r.warnings.push("refreshReuseGraceSeconds is on: a device-bound session may retry a spent refresh token inside the window instead of being revoked");
    if (mail?.driver === "console") r.warnings.push("mail.driver is \"console\": emails (and their live links) are printed to the log. Development only");
    if (mail?.driver === "file") r.warnings.push("mail.driver is \"file\": emails (and their live links) are written to a file. Development only");
    if (mail?.driver === "smtp" && mail.smtp?.user !== undefined && !mail.smtp.passwordEnv) r.warnings.push("mail.smtp has a user but no passwordEnv: the server cannot authenticate");
    if (mail?.driver === "smtp" && mail.smtp?.startTls === "never" && !mail.smtp.secure) r.warnings.push("mail.smtp sends in clear text (startTls \"never\", secure false)");
    if (mail && !mail.linkBase.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(mail.linkBase)) r.warnings.push("mail.linkBase is not https: reset and sign-in links would travel in clear text");
    for (const t of ws.tenants) {
      if ((t.allowSignup || t.allowMagicLinks || t.requireVerifiedEmail) && !mail) r.warnings.push(`${t.id}: sign-up, magic links or verified email are on, but no "mail" block is configured, so they cannot work`);
      if (t.allowSignup && !t.requireVerifiedEmail) r.warnings.push(`${t.id}: anyone can sign up and sign in without confirming their email (requireVerifiedEmail is false)`);
      if (t.allowPasskeyOnlySignup && !mail) r.warnings.push(`${t.id}: passkey-only sign-up is on, but no "mail" block is configured, so nobody can finish signing up`);
      if (t.allowMagicLinks) r.warnings.push(`${t.id}: magic links are a single factor: anyone who can read the user's mail can sign in`);
      const m = buildPermissionMatrix(t);
      r.tenants.push({ id: t.id, roles: t.roles.length, permissions: m.permissions.length, dpop: t.requireDpopHardwareBinding, mfaForAdmins: t.requireMfaForAdmins });
      if (!t.requireDpopHardwareBinding) r.warnings.push(`${t.id}: sessions are not required to be hardware-bound (requireDpopHardwareBinding is false)`);
      if (!t.requireMfaForAdmins) r.warnings.push(`${t.id}: admins are not required to use a second factor`);
      if (t.roles.some((x) => x.permissions.includes("*") && x.id !== "owner" && x.id !== "admin")) r.warnings.push(`${t.id}: a role other than owner or admin holds "*"`);
      if (t.sessionTtlSeconds > 3600) r.warnings.push(`${t.id}: access tokens live ${t.sessionTtlSeconds}s; shorter is safer`);
    }
    const noAuth = ws.users.filter((u) => !u.passwordHash && u.passkeys.length === 0);
    for (const u of noAuth) r.warnings.push(`${u.id}: no password and no passkey, so this user cannot sign in`);
  } catch (e) {
    r.errors.push(e instanceof ConfigError || e instanceof Error ? e.message : String(e));
  }
  r.ok = r.errors.length === 0;
  return r;
}
