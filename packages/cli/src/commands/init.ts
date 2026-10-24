import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { generateTotpSecret, hashPassword, type TenantPolicyInput, type UserRecordInput } from "@authvex/core";
import { CONFIG_FILE, DEFAULT_PORT } from "../config";
import { loadOrCreateIssuerKey } from "../keyring";

export const DEMO_PASSWORD = "demo-passphrase-1";

const roles = {
  fintech: [
    { id: "owner", name: "Owner", permissions: ["*"] },
    { id: "billing", name: "Billing", permissions: ["invoices:read", "invoices:write", "payouts:read"] },
    { id: "analyst", name: "Analyst", permissions: ["invoices:read", "payouts:read", "reports:read"] },
    { id: "support", name: "Support", permissions: ["invoices:read", "users:read", "users:impersonate"] },
  ],
  enterprise: [
    { id: "admin", name: "Admin", permissions: ["tenant:admin", "users:*", "keys:manage", "sso:configure"] },
    { id: "engineer", name: "Engineer", permissions: ["deployments:read", "deployments:trigger", "logs:read"] },
    { id: "auditor", name: "Auditor", permissions: ["logs:read", "reports:read"] },
  ],
  workspace: [
    { id: "lead", name: "Lead", permissions: ["issues:*", "cycles:*", "keys:manage"] },
    { id: "member", name: "Member", permissions: ["issues:read", "issues:write", "cycles:read"] },
    { id: "guest", name: "Guest", permissions: ["issues:read"] },
  ],
};

export const demoTenants = (): TenantPolicyInput[] => [
  { id: "acme_fintech_prod", name: "Acme Fintech (production)", domain: "acme-fintech.test", requireDpopHardwareBinding: true, requireMfaForAdmins: true, maxImpossibleTravelKmh: 900, maxFailedAttemptsPerWindow: 5, blockDisposableEmails: true, sessionTtlSeconds: 900, refreshTtlSeconds: 604800, roles: roles.fintech },
  { id: "zetechno_enterprise_sso", name: "Zetechno Enterprise", domain: "zetechno.test", requireDpopHardwareBinding: false, requireMfaForAdmins: true, maxImpossibleTravelKmh: 1200, maxFailedAttemptsPerWindow: 4, blockDisposableEmails: true, sessionTtlSeconds: 1800, refreshTtlSeconds: 1209600, roles: roles.enterprise },
  { id: "linear_ops_workspace", name: "Linear Ops Workspace", domain: "linear-ops.test", requireDpopHardwareBinding: false, requireMfaForAdmins: false, maxImpossibleTravelKmh: 900, maxFailedAttemptsPerWindow: 8, blockDisposableEmails: false, sessionTtlSeconds: 900, refreshTtlSeconds: 604800, roles: roles.workspace },
];

/** Demo users. Every password is `DEMO_PASSWORD`. These are for trying Authvex locally; delete them before real use. */
export async function demoUsers(nowMs = Date.now()): Promise<UserRecordInput[]> {
  const hash = await hashPassword(DEMO_PASSWORD);
  const verified = new Date(nowMs).toISOString();
  const hyd = { lat: 17.385, lon: 78.4867, city: "Hyderabad", ip: "49.37.0.10", timestampIso: new Date(nowMs).toISOString() };
  return [
    { id: "usr_ada", email: "ada@acme-fintech.test", name: "Ada Lovelace", emailVerifiedAt: verified, passwordHash: hash, totpSecretB32: generateTotpSecret(), passkeys: [], orgMemberships: [{ tenantId: "acme_fintech_prod", roleId: "owner" }, { tenantId: "linear_ops_workspace", roleId: "lead" }], lastLoginGeo: hyd },
    { id: "usr_grace", email: "grace@acme-fintech.test", name: "Grace Hopper", emailVerifiedAt: verified, passwordHash: hash, passkeys: [], orgMemberships: [{ tenantId: "acme_fintech_prod", roleId: "billing" }] },
    { id: "usr_root", email: "root@acme-fintech.test", name: "Support Root", emailVerifiedAt: verified, passwordHash: hash, totpSecretB32: generateTotpSecret(), passkeys: [], orgMemberships: [{ tenantId: "acme_fintech_prod", roleId: "support" }, { tenantId: "zetechno_enterprise_sso", roleId: "admin" }] },
    { id: "usr_linus", email: "linus@zetechno.test", name: "Linus Engineer", emailVerifiedAt: verified, passwordHash: hash, passkeys: [], orgMemberships: [{ tenantId: "zetechno_enterprise_sso", roleId: "engineer" }] },
    { id: "usr_margaret", email: "margaret@linear-ops.test", name: "Margaret Member", emailVerifiedAt: verified, passwordHash: hash, passkeys: [], orgMemberships: [{ tenantId: "linear_ops_workspace", roleId: "member" }] },
  ];
}

export interface InitResult {
  created: string[];
  skipped: string[];
}

export async function runInit(dir: string, force = false): Promise<InitResult> {
  const root = resolve(dir);
  mkdirSync(join(root, "tenants"), { recursive: true });
  const created: string[] = [];
  const skipped: string[] = [];
  const write = (rel: string, body: unknown): void => {
    const path = join(root, rel);
    if (existsSync(path) && !force) return void skipped.push(rel);
    writeFileSync(path, `${JSON.stringify(body, null, 2)}\n`);
    created.push(rel);
  };
  write(CONFIG_FILE, { port: DEFAULT_PORT, host: "127.0.0.1", rpId: "localhost", origins: [], tenants: "tenants", users: "users.json", ledger: true, trustClientGeo: false, trustGeoHeaders: false, store: { kind: "file" } });
  for (const t of demoTenants()) write(`tenants/${t.id}.json`, t);
  if (!existsSync(join(root, "users.json")) || force) write("users.json", await demoUsers());
  else skipped.push("users.json");
  const had = existsSync(join(root, ".authvex", "issuers.json"));
  await loadOrCreateIssuerKey(root);
  if (!had) created.push(".authvex/issuers.json (ES256 signing keyring, owner-only)");
  const ignore = join(root, ".gitignore");
  const current = existsSync(ignore) ? readFileSync(ignore, "utf8") : "";
  if (!/^\.authvex\/?$/m.test(current)) {
    appendFileSync(ignore, `${current && !current.endsWith("\n") ? "\n" : ""}.authvex/\n`);
    created.push(".gitignore (.authvex/)");
  }
  return { created, skipped };
}
