import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createDpopProof, generateIssuerKey, serializeIssuerKey, verifyDpopSessionRequest } from "@authvex/core";
import { main, type Io } from "../src";
import { DEMO, deviceKey, startHarness, type Harness } from "./helpers";
import { FileKeyring } from "./testExports";

const ACME = "acme_fintech_prod";
const LIN = "linear_ops_workspace";
let h: Harness | undefined;
const dirs: string[] = [];
afterEach(async () => {
  await h?.close();
  h = undefined;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const login = (tenantId: string, email: string, key?: Awaited<ReturnType<typeof deviceKey>>) => (h as Harness).call("POST", "/api/auth/login", { tenantId, email, password: DEMO }, key ? { dpop: key } : {});
const kidOf = (token: string): string => (JSON.parse(Buffer.from(token.split(".")[0]!.replace(/^ath_[a-z]+_/, ""), "base64url").toString()) as { kid: string }).kid;
const verify = (token: string) => (h as Harness).call("POST", "/api/verify", { token });

describe("rotating the issuer key on a running server", () => {
  it("keeps existing sessions valid through the overlap, signs new ones with the new key, and publishes both in the JWKS", async () => {
    h = await startHarness();
    const before = (await login(LIN, "margaret@linear-ops.test")).body;
    const oldKid = kidOf(before.sessionToken);
    expect((await h.call("GET", "/.well-known/jwks.json")).body).toMatchObject({ keys: [{ kid: oldKid }] });

    const { newKid } = await h.keyring.rotate(Date.now(), 3600);
    expect(newKid).not.toBe(oldKid);
    // No restart: the running server notices the new keyring file.
    const jwks = (await h.call("GET", "/.well-known/jwks.json")).body as unknown as { keys: Array<{ kid: string; d?: string; alg: string }> };
    expect(jwks.keys.map((k) => k.kid).sort()).toEqual([oldKid, newKid].sort());
    expect(JSON.stringify(jwks)).not.toContain('"d"');
    expect(jwks.keys.every((k) => k.alg === "ES256")).toBe(true);

    expect((await verify(before.sessionToken)).body).toMatchObject({ valid: true });
    const after = (await login(LIN, "margaret@linear-ops.test")).body;
    expect(kidOf(after.sessionToken)).toBe(newKid);
    const rotated = (await h.call("POST", "/api/auth/rotate", { refreshToken: before.refreshToken })).body;
    expect(kidOf(rotated.sessionToken)).toBe(newKid);
    expect((await verify(rotated.sessionToken)).body).toMatchObject({ valid: true });
  });

  it("serves the JWKS publicly with a cache header, and a resource server can verify offline against it", async () => {
    h = await startHarness();
    const key = await deviceKey();
    const s = (await login(ACME, "grace@acme-fintech.test", key)).body;
    await h.keyring.rotate(Date.now(), 3600);
    const r = await fetch(`${h.base}/.well-known/jwks.json`);
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toMatch(/max-age=\d+/);
    expect(r.headers.get("content-type")).toMatch(/json/);
    const jwks = await r.json();
    const url = "https://api.example.com/v1/x";
    const proof = await createDpopProof({ ...key, method: "GET", url, sessionToken: s.sessionToken });
    expect(await verifyDpopSessionRequest({ sessionToken: s.sessionToken, dpopProof: proof, method: "GET", url, issuerPublicKeyJwk: jwks })).toMatchObject({ ok: true, bound: true });
  });

  it("refuses everything the old key signed the moment it is revoked, and the admin link signed by it", async () => {
    h = await startHarness();
    const old = (await login(LIN, "margaret@linear-ops.test")).body;
    const oldKid = kidOf(old.sessionToken);
    const oldAdmin = h.server.adminToken;
    await h.keyring.rotate(Date.now(), 86_400);
    expect((await verify(old.sessionToken)).body.valid).toBe(true);
    expect((await h.call("GET", "/api/workspace", undefined, { token: oldAdmin })).status).toBe(200);
    h.keyring.revoke(oldKid);
    expect((await verify(old.sessionToken)).body).toMatchObject({ valid: false, reason: "unknown_key" });
    expect((await h.call("GET", "/api/workspace", undefined, { token: oldAdmin })).status).toBe(401);
    expect((await h.call("GET", "/.well-known/jwks.json")).body.keys).toHaveLength(1);
    // The refresh token is opaque, so the user can continue: they get a session from the new key.
    const again = (await h.call("POST", "/api/auth/rotate", { refreshToken: old.refreshToken })).body;
    expect(again.status).toBe("ok");
    expect(kidOf(again.sessionToken)).not.toBe(oldKid);
  });

  it("lets an expired overlap lapse by itself and prunes the retired key later", async () => {
    h = await startHarness();
    const old = (await login(LIN, "margaret@linear-ops.test")).body;
    const t0 = Date.now();
    await h.keyring.rotate(t0, 1);
    await new Promise((r) => setTimeout(r, 1200));
    expect((await verify(old.sessionToken)).body).toMatchObject({ valid: false, reason: "unknown_key" });
    expect(h.keyring.prune(t0 + 2000)).toMatchObject({ expired: [expect.any(String)], removed: [] });
    expect(h.keyring.prune(t0 + 2000 + 86_400_000 + 1)).toMatchObject({ removed: [expect.any(String)] });
    expect(h.keyring.read().keys).toHaveLength(1);
  });

  it("writes the keyring owner-only, with no private half for rotated-out keys", async () => {
    h = await startHarness();
    await h.keyring.rotate(Date.now(), 3600);
    const path = join(h.dir, ".authvex", "issuers.json");
    expect(statSync(path).mode & 0o077).toBe(0);
    const kr = JSON.parse(readFileSync(path, "utf8")) as { keys: Array<{ status: string; privateKeyJwk?: unknown }> };
    expect(kr.keys.map((k) => k.status)).toEqual(["retiring", "active"]);
    expect(kr.keys[0]?.privateKeyJwk).toBeUndefined();
    expect(kr.keys[1]?.privateKeyJwk).toBeDefined();
  });

  it("migrates a version 0.1.0 single-key file without changing the key", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authvex-mig-"));
    dirs.push(dir);
    const key = await generateIssuerKey();
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(dir, ".authvex"), { recursive: true });
    writeFileSync(join(dir, ".authvex", "issuer.json"), JSON.stringify(await serializeIssuerKey(key)));
    const kr = await FileKeyring.open(dir);
    expect((await kr.get(Date.now())).issuer.kid).toBe(key.kid);
    expect(existsSync(join(dir, ".authvex", "issuers.json"))).toBe(true);
    expect(existsSync(join(dir, ".authvex", "issuer.json"))).toBe(false);
    expect(existsSync(join(dir, ".authvex", "issuer.json.migrated"))).toBe(true);
    expect((await (await FileKeyring.open(dir)).get(Date.now())).issuer.kid).toBe(key.kid);
  });

  it("refuses a corrupt keyring instead of generating a new key over it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authvex-bad-"));
    dirs.push(dir);
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(dir, ".authvex"), { recursive: true });
    writeFileSync(join(dir, ".authvex", "issuers.json"), '{"version":2,"keys":[]}');
    await expect(FileKeyring.open(dir)).rejects.toThrow(/exactly one active/);
  });
});

describe("authvex issuer commands", () => {
  let out: string[];
  let err: string[];
  let dir: string;
  const io = (): Io => ({ out: (l) => out.push(l), err: (l) => err.push(l), cwd: dir });
  const run = (...argv: string[]): Promise<number> => main(argv, io());

  it("lists, rotates, revokes and prunes, and records each in the ledger", async () => {
    dir = mkdtempSync(join(tmpdir(), "authvex-issuer-"));
    dirs.push(dir);
    out = [];
    err = [];
    await run("init");
    expect(await run("issuer", "list", "--json")).toBe(0);
    const first = JSON.parse(out.at(-1) as string) as Array<{ kid: string; status: string }>;
    expect(first).toHaveLength(1);
    expect(first[0]?.status).toBe("active");

    expect(await run("issuer", "rotate", "--overlap-hours", "2")).toBe(0);
    expect(out.join("\n")).toContain("still verifies for 2 hours");
    out.length = 0;
    expect(await run("issuer", "list", "--json")).toBe(0);
    const second = JSON.parse(out.join("\n")) as Array<{ kid: string; status: string }>;
    expect(second.map((k) => k.status)).toEqual(["retiring", "active"]);

    expect(await run("issuer", "revoke", first[0]!.kid)).toBe(0);
    expect(await run("issuer", "revoke", second[1]!.kid)).toBe(1);
    expect(err.join("\n")).toContain("active key cannot be revoked");
    expect(await run("issuer", "revoke", "nope")).toBe(1);
    expect(await run("issuer", "prune")).toBe(0);
    expect(await run("issuer", "rotate", "--overlap-hours", "-1")).toBe(2);
    expect(await run("issuer", "frobnicate")).toBe(2);
    expect(await run("ledger", "verify")).toBe(0);
    const types = readFileSync(join(dir, ".authvex/ledger.jsonl"), "utf8").trim().split("\n").map((l) => (JSON.parse(l) as { type: string }).type);
    expect(types).toEqual(expect.arrayContaining(["issuer.rotated", "issuer.revoked"]));
  });
});
