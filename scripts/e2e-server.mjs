// Runs the real CLI server for the end-to-end tests on a throwaway copy of examples/demo, so the tests can enrol passkeys,
// edit roles and write the ledger without touching the repository.
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../packages/cli/dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dir = mkdtempSync(join(tmpdir(), "authvex-e2e-"));
cpSync(join(root, "examples", "demo"), dir, { recursive: true });
// The tests read this to find the workspace (issuer key, users.json) they need to mint admin tokens and TOTP codes.
writeFileSync(join(root, "e2e", ".workspace"), dir);
const port = process.env.AUTHVEX_E2E_PORT ?? "4378";
// Email goes to a file the tests can read, and one tenant opens sign-up and magic links.
const cfgPath = join(dir, "authvex.config.json");
const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
writeFileSync(cfgPath, JSON.stringify({ ...cfg, ipRequestsPerMinute: 10000, mail: { driver: "file", from: "noreply@authvex.test", linkBase: `http://localhost:${port}/` } }, null, 2));
// One public OpenID Connect client for the sign-in page test (a loopback redirect, so no real app is needed).
writeFileSync(join(dir, "oidc-clients.json"), JSON.stringify([{ clientId: "cl_e2e00001", name: "Notes App", tenantId: "linear_ops_workspace", type: "public", redirectUris: [`http://localhost:${port}/e2e-callback`], allowedScopes: ["openid", "profile", "email", "offline_access"], postLogoutRedirectUris: [] }], null, 2));
const tPath = join(dir, "tenants", "linear_ops_workspace.json");
writeFileSync(tPath, JSON.stringify({ ...JSON.parse(readFileSync(tPath, "utf8")), allowSignup: true, signupRoleId: "guest", allowMagicLinks: true, allowPasskeyOnlySignup: true }, null, 2));
const code = await main(["studio", "--port", port, "--quiet"], { out: (l) => console.log(l), err: (l) => console.error(l), cwd: dir });
process.exit(code);
