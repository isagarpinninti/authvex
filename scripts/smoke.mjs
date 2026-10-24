// Packs the three packages, installs the tarballs into a clean project, and drives the installed CLI and core over HTTP.
// This is what proves the published files are complete: nothing here touches the source tree.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = mkdtempSync(join(tmpdir(), "authvex-smoke-"));
const PORT = 4392;
let server;
let failed = false;
process.on("exit", () => server?.kill("SIGKILL"));
const step = (m) => console.log(`\n› ${m}`);
const check = (cond, msg) => {
  if (!cond) throw new Error(`FAILED: ${msg}`);
  console.log(`  ok  ${msg}`);
};
const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });

try {
  step("pack");
  const tarballs = {};
  for (const pkg of ["core", "react", "cli"]) {
    const dir = join(root, "packages", pkg);
    check(existsSync(join(dir, "dist")), `packages/${pkg}/dist is built`);
    const out = run("npm", ["pack", "--pack-destination", work, "--silent"], { cwd: dir }).trim().split("\n").at(-1);
    tarballs[pkg] = join(work, out);
  }
  check(existsSync(join(root, "packages/cli/studio/index.html")), "the Studio is bundled into the CLI package");

  step("install into a clean project");
  const proj = join(work, "project");
  run("mkdir", ["-p", proj]);
  writeFileSync(
    join(proj, "package.json"),
    JSON.stringify({
      name: "smoke", private: true, type: "module",
      dependencies: { "@authvex/core": `file:${tarballs.core}`, "@authvex/cli": `file:${tarballs.cli}`, "@authvex/react": `file:${tarballs.react}`, zod: "^4", react: "^19", "react-dom": "^19" },
      overrides: { "@authvex/core": "$@authvex/core" },
    }),
  );
  run("npm", ["install", "--no-audit", "--no-fund"], { cwd: proj, timeout: 240_000 });
  const bin = join(proj, "node_modules/.bin/authvex");
  check(existsSync(bin), "the authvex binary is linked");
  check(/^\d+\.\d+\.\d+/.test(run(bin, ["--version"], { cwd: proj }).trim()), "authvex --version prints a version");

  step("init, validate, evaluate");
  run(bin, ["init"], { cwd: proj });
  check(/3 tenants and 5 users valid/.test(run(bin, ["validate"], { cwd: proj })), "the scaffolded workspace validates");
  let code = 0;
  try {
    run(bin, ["evaluate", "linear_ops_workspace", "--user", "usr_ada", "--geo", "51.5074,-0.1278,London", "--last-minutes", "12"], { cwd: proj });
  } catch (e) {
    code = e.status;
  }
  check(code === 2, "impossible travel (Hyderabad to London in 12 minutes) exits 2");

  step("start the server");
  check(!(await fetch(`http://127.0.0.1:${PORT}/api/health`).then(() => true, () => false)), `port ${PORT} is free`);
  const base = `http://127.0.0.1:${PORT}`;
  let adminToken;
  const boot = async () => {
    server = spawn(bin, ["studio", "--port", String(PORT), "--quiet"], { cwd: proj, stdio: ["ignore", "pipe", "pipe"] });
    let log = "";
    server.stdout.on("data", (d) => (log += d));
    server.stderr.on("data", (d) => (log += d));
    for (let i = 0; i < 100 && !log.includes("State "); i++) await new Promise((r) => setTimeout(r, 100));
    adminToken = /#token=(ath_adm_[^\s]+)/.exec(log)?.[1];
    return log;
  };
  const stop = async () => {
    const exited = new Promise((r) => server.once("exit", r));
    server.kill("SIGTERM");
    await exited;
  };
  const log = await boot();
  check(log.includes(base), "the server announced itself");
  check(Boolean(adminToken), "the Studio link carries an admin token");
  check(log.includes("/.well-known/jwks.json"), "the JWKS address is announced");
  check((await (await fetch(`${base}/api/health`)).json()).store === "file", "state is kept in the file store by default");
  check((await (await fetch(`${base}/`)).text()).includes("Authvex"), "the Studio is served at /");

  step("a hardware-bound session, end to end, using the installed @authvex/core as the client");
  const core = await import(join(proj, "node_modules/@authvex/core/dist/index.js"));
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const key = { privateKey: pair.privateKey, publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
  const post = async (path, body, dpopKey) => {
    const headers = { "content-type": "application/json" };
    if (dpopKey) headers.dpop = await core.createDpopProof({ ...dpopKey, method: "POST", url: `${base}${path}` });
    const r = await fetch(`${base}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: r.status, body: await r.json() };
  };
  const login = await post("/api/auth/login", { tenantId: "acme_fintech_prod", email: "grace@acme-fintech.test", password: "demo-passphrase-1" }, key);
  check(login.status === 200 && login.body.tokenType === "DPoP", "login on a tenant that requires hardware binding succeeds with a DPoP proof");
  check((await post("/api/auth/login", { tenantId: "acme_fintech_prod", email: "grace@acme-fintech.test", password: "demo-passphrase-1" })).status === 403, "the same login without a proof is blocked (AV-105)");
  const url = `${base}/v1/invoices`;
  const proof = await core.createDpopProof({ ...key, method: "GET", url, sessionToken: login.body.sessionToken });
  check((await post("/api/auth/dpop-verify", { sessionToken: login.body.sessionToken, dpopProof: proof, method: "GET", url })).body.valid === true, "the owner's request verifies");
  const stolen = await post("/api/auth/dpop-verify", { sessionToken: login.body.sessionToken, method: "GET", url });
  check(stolen.status === 401 && stolen.body.reason === "dpop_missing", "a stolen token without the key is refused");

  step("refresh rotation and the kill-switch");
  const rotated = await post("/api/auth/rotate", { refreshToken: login.body.refreshToken }, key);
  check(rotated.status === 200 && rotated.body.generation === 2, "rotation advances to generation 2");
  const replay = await post("/api/auth/rotate", { refreshToken: login.body.refreshToken }, key);
  check(replay.status === 409 && replay.body.status === "family_revoked", "replaying the spent token revokes the family (AV-104)");
  check((await post("/api/auth/rotate", { refreshToken: rotated.body.refreshToken }, key)).status === 401, "the legitimate token is revoked too");

  step("sessions survive a restart");
  const l2 = await post("/api/auth/login", { tenantId: "acme_fintech_prod", email: "grace@acme-fintech.test", password: "demo-passphrase-1" }, key);
  const g2 = await post("/api/auth/rotate", { refreshToken: l2.body.refreshToken }, key);
  check(g2.status === 200, "a second session rotates to generation 2");
  await stop();
  await boot();
  const g3 = await post("/api/auth/rotate", { refreshToken: g2.body.refreshToken }, key);
  check(g3.status === 200 && g3.body.generation === 3, "after a restart the latest refresh token still rotates (generation 3)");
  const r3 = await post("/api/auth/rotate", { refreshToken: l2.body.refreshToken }, key);
  check(r3.status === 409, "after a restart a spent refresh token still revokes the family");

  step("the SQLite store, from the installed package");
  const cliPkg = await import(join(proj, "node_modules/@authvex/cli/dist/index.js"));
  if (await cliPkg.sqliteAvailable()) {
    const db = await cliPkg.SqliteStore.open(join(work, "smoke.db"));
    check((await db.claimJti("j1", 0, 1000)) === true && (await db.claimJti("j1", 1, 1000)) === false, "the installed SqliteStore claims a proof id once");
    await db.close();
  } else console.log("  skip  node:sqlite is not available on this Node, so the SQLite store is not exercised");

  step("issuer key rotation");
  const pre = await post("/api/auth/login", { tenantId: "linear_ops_workspace", email: "margaret@linear-ops.test", password: "demo-passphrase-1" });
  const jwks1 = await (await fetch(`${base}/.well-known/jwks.json`)).json();
  check(jwks1.keys.length === 1 && jwks1.keys[0].alg === "ES256", "the JWKS publishes the one signing key");
  check(/new signing key/.test(run(bin, ["issuer", "rotate", "--overlap-hours", "1"], { cwd: proj })), "authvex issuer rotate makes a new signing key");
  const jwks2 = await (await fetch(`${base}/.well-known/jwks.json`)).json();
  check(jwks2.keys.length === 2 && !JSON.stringify(jwks2).includes('"d"'), "the running server now publishes both public keys (and no private half)");
  check((await post("/api/verify", { token: pre.body.sessionToken })).body.valid === true, "a session signed before the rotation still verifies during the overlap");
  const oldKid = jwks1.keys[0].kid;
  run(bin, ["issuer", "revoke", oldKid], { cwd: proj });
  const revoked = await post("/api/verify", { token: pre.body.sessionToken });
  check(revoked.body.valid === false && revoked.body.reason === "unknown_key", "after revoking the old key its sessions are refused");

  step("audit");
  check(/ok/.test(run(bin, ["ledger", "verify"], { cwd: proj })), "authvex ledger verify reports an intact chain");
  const minted = run(bin, ["key", "mint", "--tenant", "acme_fintech_prod", "--name", "smoke", "--scopes", "invoices:read"], { cwd: proj }).trim().split("\n")[0];
  check(/^atk_live_[0-9a-f]{8}_/.test(minted), "authvex key mint prints an atk_live_ key");
  check((await post("/api/verify", { token: minted, scope: "invoices:read" })).body.valid === true, "the running server accepts the key minted by the CLI");
  check(/ok/.test(run(bin, ["ledger", "verify"], { cwd: proj })), "the ledger is still intact after the CLI and the server both wrote to it");

  step("the installed React package loads");
  writeFileSync(join(proj, "check.mjs"), `import { ZeroTrustLoginCard, ThreatRadarWorkbench, ActiveSessionsAndPasskeysPanel, TenantRbacAndImpersonationStudio } from "@authvex/react"; for (const c of [ZeroTrustLoginCard, ThreatRadarWorkbench, ActiveSessionsAndPasskeysPanel, TenantRbacAndImpersonationStudio]) if (typeof c !== "function") process.exit(1); console.log("loaded");`);
  check(run("node", ["check.mjs"], { cwd: proj }).trim() === "loaded", "@authvex/react exports its four components");
  console.log("\nSmoke test passed.");
} catch (e) {
  failed = true;
  console.error(`\n${e instanceof Error ? e.message : e}`);
} finally {
  server?.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 300));
  rmSync(work, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
