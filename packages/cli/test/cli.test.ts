import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { main, type Io } from "../src";

let dir: string;
let out: string[];
let err: string[];
const io = (): Io => ({ out: (l) => out.push(l), err: (l) => err.push(l), cwd: dir });
const run = (...argv: string[]): Promise<number> => main(argv, io());
const last = (): string => out.at(-1) as string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "authvex-cli-"));
  out = [];
  err = [];
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("init and validate", () => {
  it("scaffolds config, three tenants, demo users and a private issuer key, and validates", async () => {
    expect(await run("init")).toBe(0);
    for (const f of ["authvex.config.json", "tenants/acme_fintech_prod.json", "tenants/zetechno_enterprise_sso.json", "tenants/linear_ops_workspace.json", "users.json", ".authvex/issuers.json", ".gitignore"]) expect(existsSync(join(dir, f)), f).toBe(true);
    expect(readFileSync(join(dir, ".gitignore"), "utf8")).toContain(".authvex/");
    expect((await import("node:fs")).statSync(join(dir, ".authvex/issuers.json")).mode & 0o077).toBe(0);
    out.length = 0;
    expect(await run("validate")).toBe(0);
    expect(out.join("\n")).toMatch(/3 tenants and 5 users valid/);
  });
  it("does not overwrite existing files without --force, and never rotates the issuer key", async () => {
    await run("init");
    const key = readFileSync(join(dir, ".authvex/issuers.json"), "utf8");
    writeFileSync(join(dir, "authvex.config.json"), "{}");
    out.length = 0;
    await run("init", "--force");
    expect(readFileSync(join(dir, ".authvex/issuers.json"), "utf8")).toBe(key);
    out.length = 0;
    writeFileSync(join(dir, "authvex.config.json"), "{}");
    await run("init");
    expect(out.join("\n")).toContain("kept");
    expect(readFileSync(join(dir, "authvex.config.json"), "utf8")).toBe("{}");
  });
  it("reports a broken tenant, a bad membership and a duplicate with file names, exit 1", async () => {
    await run("init");
    const t = JSON.parse(readFileSync(join(dir, "tenants/linear_ops_workspace.json"), "utf8"));
    t.roles.push({ id: "guest", name: "dup", permissions: ["x:y"] });
    writeFileSync(join(dir, "tenants/linear_ops_workspace.json"), JSON.stringify(t));
    expect(await run("validate")).toBe(1);
    expect(err.join("\n")).toMatch(/linear_ops_workspace\.json.*roles\.3\.id.*defined twice/);
    err.length = 0;
    t.roles.pop();
    writeFileSync(join(dir, "tenants/linear_ops_workspace.json"), JSON.stringify(t));
    const users = JSON.parse(readFileSync(join(dir, "users.json"), "utf8"));
    users[0].orgMemberships.push({ tenantId: "acme_fintech_prod", roleId: "ghost" });
    writeFileSync(join(dir, "users.json"), JSON.stringify(users));
    expect(await run("validate")).toBe(1);
    expect(err.join("\n")).toMatch(/users\.json.*role "ghost" does not exist/);
    err.length = 0;
    writeFileSync(join(dir, "tenants/linear_ops_workspace.json"), "{oops");
    expect(await run("validate", "--json")).toBe(1);
    expect(JSON.parse(last()).errors[0]).toContain("linear_ops_workspace.json");
  });
  it("warns about risky settings", async () => {
    await run("init");
    writeFileSync(join(dir, "authvex.config.json"), JSON.stringify({ trustClientGeo: true }));
    out.length = 0;
    expect(await run("validate")).toBe(0);
    const text = out.join("\n");
    expect(text).toContain("trustClientGeo is on");
    expect(text).toContain("rpId");
    expect(text).toContain("requireDpopHardwareBinding is false");
  });
});

describe("evaluate", () => {
  beforeEach(async () => {
    await run("init");
    out.length = 0;
  });
  it("allows an ordinary request and exits 0", async () => {
    expect(await run("evaluate", "linear_ops_workspace", "--user", "usr_margaret")).toBe(0);
    expect(last()).toContain("LOW");
  });
  it("exits 2 and explains the travel arithmetic for Hyderabad to London in 12 minutes", async () => {
    expect(await run("evaluate", "linear_ops_workspace", "--user", "usr_ada", "--geo", "51.5074,-0.1278,London", "--last-minutes", "12")).toBe(2);
    const text = out.join("\n");
    expect(text).toMatch(/AV-103\s+FAIL\s+Impossible-travel radar: Hyderabad to London: \d+(\.\d)? km in 0\.2 h/);
    expect(text).toContain("BLOCK");
  });
  it("covers the other gates through flags, and prints JSON", async () => {
    expect(await run("evaluate", "acme_fintech_prod", "--user", "usr_grace", "--no-dpop")).toBe(2);
    expect(out.join("\n")).toMatch(/AV-105\s+FAIL/);
    out.length = 0;
    expect(await run("evaluate", "acme_fintech_prod", "--user", "usr_grace", "--permission", "keys:manage")).toBe(2);
    expect(out.join("\n")).toMatch(/AV-107\s+FAIL/);
    out.length = 0;
    expect(await run("evaluate", "linear_ops_workspace", "--failed", "9")).toBe(2);
    expect(await run("evaluate", "linear_ops_workspace", "--family-reused")).toBe(2);
    expect(await run("evaluate", "linear_ops_workspace", "--asn", "datacenter")).toBe(2);
    out.length = 0;
    expect(await run("evaluate", "linear_ops_workspace", "--json")).toBe(0);
    expect(JSON.parse(out.join("\n")).checks).toHaveLength(8);
  });
  it("rejects bad input with exit 2 or 1", async () => {
    expect(await run("evaluate")).toBe(2);
    expect(await run("evaluate", "linear_ops_workspace", "--geo", "x,y")).toBe(2);
    expect(await run("evaluate", "ghost")).toBe(1);
    expect(await run("evaluate", "linear_ops_workspace", "--user", "usr_ghost")).toBe(1);
  });
});

describe("keys, impersonation, ledger and tokens", () => {
  beforeEach(async () => {
    await run("init");
    out.length = 0;
  });
  it("mints a key shown once, lists it without the secret, verifies it and revokes it", async () => {
    expect(await run("key", "mint", "--tenant", "acme_fintech_prod", "--name", "ci", "--scopes", "invoices:read,reports:read", "--rate", "50")).toBe(0);
    const key = out[0] as string;
    expect(key).toMatch(/^atk_live_[0-9a-f]{8}_/);
    expect(readFileSync(join(dir, ".authvex/keys.json"), "utf8")).not.toContain(key.slice(18));
    out.length = 0;
    expect(await run("key", "list")).toBe(0);
    expect(out.join("\n")).toContain("ci");
    expect(out.join("\n")).not.toContain(key.slice(18));
    expect(await run("token", "verify", key)).toBe(0);
    const id = out.join("\n").match(/key_[A-Za-z0-9_-]+/)?.[0] ?? JSON.parse(readFileSync(join(dir, ".authvex/keys.json"), "utf8"))[0].id;
    expect(await run("key", "revoke", id)).toBe(0);
    out.length = 0;
    expect(await run("token", "verify", key)).toBe(1);
    expect(out.join("\n")).toContain("revoked");
    expect(await run("key", "mint", "--tenant", "ghost", "--name", "x", "--scopes", "a")).toBe(2);
    expect(await run("key", "mint", "--tenant", "acme_fintech_prod")).toBe(2);
    expect(await run("key", "revoke", "key_nope")).toBe(2);
    expect(await run("key", "frobnicate")).toBe(2);
  });
  it("mints a sealed impersonation token for a permitted admin and refuses everyone else", async () => {
    const base = ["impersonate", "--actor", "usr_root", "--target", "usr_grace", "--tenant", "acme_fintech_prod", "--reason", "TICKET-77 customer cannot sign in"];
    expect(await run(...base)).toBe(0);
    const token = out[0] as string;
    expect(token.startsWith("ath_imp_")).toBe(true);
    out.length = 0;
    expect(await run("token", "verify", token)).toBe(0);
    expect(JSON.parse(out.join("\n"))).toMatchObject({ kind: "impersonation", valid: true, claims: { readOnly: true, actorAdminId: "usr_root", targetUserId: "usr_grace" } });
    expect(await run("impersonate", "--actor", "usr_grace", "--target", "usr_root", "--tenant", "acme_fintech_prod", "--reason", "TICKET-78 not allowed")).toBe(1);
    expect(err.join("\n")).toContain("AV-107");
    expect(await run(...base.slice(0, -1), "help")).toBe(1);
    expect(await run(...base, "--ttl", "5000")).toBe(2);
    expect(await run("impersonate", "--actor", "usr_root")).toBe(2);
    expect(await run(...base, "--write")).toBe(0);
    expect(JSON.parse(readFileSync(join(dir, ".authvex/ledger.jsonl"), "utf8").trim().split("\n").filter((l) => l.includes("impersonation.minted")).at(-1) as string).detail.readOnly).toBe(false);
  });
  it("verifies the ledger and detects tampering and deletion", async () => {
    await run("key", "mint", "--tenant", "acme_fintech_prod", "--name", "a", "--scopes", "x:y");
    await run("key", "mint", "--tenant", "acme_fintech_prod", "--name", "b", "--scopes", "x:y");
    await run("key", "mint", "--tenant", "acme_fintech_prod", "--name", "c", "--scopes", "x:y");
    out.length = 0;
    expect(await run("ledger", "verify")).toBe(0);
    expect(last()).toMatch(/3 entries/);
    expect(await run("ledger", "list")).toBe(0);
    const path = join(dir, ".authvex/ledger.jsonl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const e = JSON.parse(lines[1] as string);
    e.detail.name = "forged";
    writeFileSync(path, [lines[0], JSON.stringify(e), lines[2]].join("\n") + "\n");
    expect(await run("ledger", "verify")).toBe(1);
    expect(err.join("\n")).toContain("BROKEN at entry 2");
    writeFileSync(path, [lines[0], lines[2]].join("\n") + "\n");
    err.length = 0;
    expect(await run("ledger", "verify")).toBe(1);
    expect(err.join("\n")).toContain("entry 2");
    expect(await run("ledger", "wat")).toBe(2);
  });
  it("shares the ledger between the CLI and a running server without forking the chain", async () => {
    const abort = new AbortController();
    const running = main(["studio", "--port", "0", "--quiet"], io(), abort.signal);
    for (let i = 0; i < 100 && !out.some((l) => l.includes("Studio")); i++) await new Promise((r) => setTimeout(r, 30));
    await run("key", "mint", "--tenant", "acme_fintech_prod", "--name", "while-running", "--scopes", "x:y");
    abort.abort();
    expect(await running).toBe(0);
    out.length = 0;
    expect(await run("ledger", "verify")).toBe(0);
  });
  it("rejects unverifiable and junk tokens", async () => {
    expect(await run("token", "verify", "ath_rt_abc")).toBe(1);
    expect(await run("token", "verify", "nonsense")).toBe(1);
    expect(await run("token", "verify", "ath_sess_a.b")).toBe(1);
    expect(await run("token", "verify")).toBe(2);
  });
});

describe("misc and studio", () => {
  it("prints help and the version, and rejects unknown commands", async () => {
    expect(await run("--help")).toBe(0);
    expect(out.join("\n")).toContain("Usage: authvex");
    out.length = 0;
    expect(await run("--version")).toBe(0);
    expect(out[0]).toMatch(/^\d+\.\d+\.\d+/);
    expect(await run("frobnicate")).toBe(2);
  });
  it("starts, answers /api/health with the issuer kid, and stops cleanly", async () => {
    await run("init");
    out.length = 0;
    const abort = new AbortController();
    const running = main(["studio", "--port", "0", "--quiet"], io(), abort.signal);
    let line: string | undefined;
    for (let i = 0; i < 100 && !(line = out.find((l) => l.includes("/api/health"))); i++) await new Promise((r) => setTimeout(r, 30));
    expect(line).toBeDefined();
    const base = /(http:\/\/[^\s]+)\/api\/health/.exec(line as string)?.[1] as string;
    const h = await (await fetch(`${base}/api/health`)).json();
    expect(h).toMatchObject({ ok: true, tenants: 3 });
    expect(out.join("\n")).toMatch(/Studio\s+http:\/\/[^\s]+\/#token=ath_adm_/);
    abort.abort();
    expect(await running).toBe(0);
    expect(readFileSync(join(dir, ".authvex/ledger.jsonl"), "utf8")).toContain("server.started");
  });
  it("fails with a clear message when nothing is configured", async () => {
    expect(await run("studio", "--port", "0", "--quiet", "--config", "missing.json")).toBe(1);
    expect(err.join("\n")).toContain("no such file");
  });
});
