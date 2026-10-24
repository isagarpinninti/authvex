import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashPassword } from "@authvex/core";
import { main, type Io } from "../src";
import { runDoctor } from "../src/commands/doctor";

let dir: string;
let out: string[];
let err: string[];
const io = (): Io => ({ out: (l) => out.push(l), err: (l) => err.push(l), cwd: dir });
const run = (...argv: string[]): Promise<number> => main(argv, io());

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "authvex-doc-"));
  out = [];
  err = [];
  await run("init");
  out = [];
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const editConfig = (over: Record<string, unknown>): void => {
  const p = join(dir, "authvex.config.json");
  writeFileSync(p, JSON.stringify({ ...JSON.parse(readFileSync(p, "utf8")), ...over }, null, 2));
};
/** Replaces every demo password, as an operator would before going live. */
const retirePasswords = async (): Promise<void> => {
  const p = join(dir, "users.json");
  const users = JSON.parse(readFileSync(p, "utf8")) as Array<{ passwordHash?: string }>;
  const h = await hashPassword("a-long-unique-production-passphrase");
  writeFileSync(p, JSON.stringify(users.map((u) => (u.passwordHash ? { ...u, passwordHash: h } : u))));
};
const level = async (id: string, opts: Parameters<typeof runDoctor>[1] = { network: false }) => (await runDoctor(dir, opts)).checks.filter((c) => c.id === id);

describe("authvex doctor", () => {
  it("fails a fresh demo workspace because the published demo password is still in use, and says who", async () => {
    expect(await run("doctor", "--offline")).toBe(1);
    const text = [...out, ...err].join("\n");
    expect(text).toContain("still have the published demo password");
    expect(text).toContain("Not ready for production");
  });

  it("passes once the demo passwords are gone, warns about what is left, and --strict turns warnings into a failure", async () => {
    await retirePasswords();
    expect(await run("doctor", "--offline")).toBe(0);
    expect(out.join("\n")).toContain("No blocking problems found");
    expect(await run("doctor", "--offline", "--strict")).toBe(1);
  });

  it("is read-only: it creates no keys, and prints no secrets", async () => {
    rmSync(join(dir, ".authvex"), { recursive: true, force: true });
    const r = await runDoctor(dir, { network: false });
    expect(existsSync(join(dir, ".authvex", "issuers.json"))).toBe(false);
    expect(r.checks.find((c) => c.id === "keys")?.level).toBe("info");
    await run("init", "--force");
    out = [];
    await run("doctor", "--offline", "--json");
    const text = out.join("\n");
    const users = JSON.parse(readFileSync(join(dir, "users.json"), "utf8")) as Array<{ passwordHash: string; totpSecretB32?: string }>;
    expect(text).not.toContain(users[0]?.passwordHash);
    for (const u of users) if (u.totpSecretB32) expect(text).not.toContain(u.totpSecretB32);
    expect(text).not.toContain('"d":');
  });

  it("flags files others can read", async () => {
    if (process.platform === "win32") return;
    chmodSync(join(dir, "users.json"), 0o644);
    const c = await level("permissions");
    expect(c).toHaveLength(1);
    expect(c[0]?.level).toBe("warn");
    expect(c[0]?.detail).toContain("chmod 600");
  });

  it("fails when the rpId could never work for the public URL, and warns about http", async () => {
    editConfig({ publicUrl: "https://id.example.com", rpId: "other.org" });
    expect((await level("rp-id"))[0]?.level).toBe("fail");
    editConfig({ publicUrl: "https://id.example.com", rpId: "example.com" });
    expect(await level("rp-id")).toHaveLength(0);
    editConfig({ publicUrl: "http://id.example.com", rpId: "example.com" });
    expect((await level("public-url"))[0]?.level).toBe("warn");
  });

  it("checks the store: memory warns, a missing or unreachable database fails", async () => {
    editConfig({ store: { kind: "memory" } });
    expect((await level("store"))[0]?.level).toBe("warn");
    editConfig({ store: { kind: "postgres" } });
    expect((await level("store"))[0]?.level).toBe("fail");
    const url = "postgres://u:p@127.0.0.1:1/x?sslmode=disable";
    const r = await level("store", { network: true, env: { AUTHVEX_DATABASE_URL: url } });
    expect(r[0]?.level).toBe("fail");
    expect(JSON.stringify(r)).not.toContain(":p@");
  });

  it("reaches a real PostgreSQL when one is available", async () => {
    const url = process.env["AUTHVEX_TEST_DATABASE_URL"];
    if (!url) return;
    editConfig({ store: { kind: "postgres" } });
    const r = await level("store", { network: true, env: { AUTHVEX_DATABASE_URL: url } });
    expect(r[0]?.level).toBe("ok");
    expect(JSON.stringify(r)).not.toContain("pw-test");
  });

  it("notices a tampered audit ledger", async () => {
    const { startHarness } = await import("./helpers");
    const h = await startHarness({}, { dir });
    await h.call("POST", "/api/auth/login", { tenantId: "linear_ops_workspace", email: "margaret@linear-ops.test", password: "demo-passphrase-1" });
    await h.close();
    expect((await level("ledger"))[0]?.level).toBe("ok");
    const p = join(dir, ".authvex", "ledger.jsonl");
    const lines = readFileSync(p, "utf8").trim().split("\n");
    lines[0] = (lines[0] as string).replace("auth.login", "auth.logon");
    writeFileSync(p, `${lines.join("\n")}\n`);
    expect((await level("ledger"))[0]?.level).toBe("fail");
  });

  it("reports a configuration that cannot be loaded instead of crashing", async () => {
    writeFileSync(join(dir, "authvex.config.json"), '{"store": {"kind": "oracle"}}');
    const r = await runDoctor(dir, { network: false });
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.id === "config")?.level).toBe("fail");
  });
});
