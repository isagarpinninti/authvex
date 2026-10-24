import { describe, expect, it } from "vitest";
import { NO_PASSWORD, b64urlEncode, fromHex, hashPassword } from "@authvex/core";
import { argon2Available, createPasswordHasher, type PasswordHashingConfig } from "../src/passwords";
import { startHarness, DEMO, type Harness } from "./helpers";

const cfg = (over: Partial<PasswordHashingConfig>): PasswordHashingConfig => ({ algorithm: "scrypt", scrypt: { N: 16384, r: 8, p: 1 }, argon2id: { memoryKiB: 8192, passes: 3, parallelism: 1 }, ...over });
const SALT = b64urlEncode(fromHex("000102030405060708090a0b0c0d0e0f"));
const PW = "correct horse battery staple";
const hasArgon = argon2Available();

describe("password hashing agrees with OpenSSL's own command line", () => {
  // `openssl kdf -keylen 32 -kdfopt pass:… -kdfopt hexsalt:000102…0f …` (OpenSSL 4.0.3)
  it("scrypt N=16384 r=8 p=1", async () => {
    const stored = `$ath-scrypt$v=1$N=16384,r=8,p=1$${SALT}$${b64urlEncode(fromHex("d7590aca2c9801cf06eeba772a69dc31ce3862591d96522ac4e6bba6ad1f31a5"))}`;
    const h = createPasswordHasher(cfg({ algorithm: "scrypt" }));
    expect(await h.verify(PW, stored)).toBe(true);
    expect(await h.verify(`${PW}!`, stored)).toBe(false);
  });
  it.skipIf(!hasArgon)("argon2id m=8192 t=3 p=1", async () => {
    const stored = `$ath-argon2id$v=1$m=8192,t=3,p=1$${SALT}$${b64urlEncode(fromHex("947312f62e4ac86f63c9b622f147b0061846739f53dd00f2d2236cd03db413ac"))}`;
    const h = createPasswordHasher(cfg({ algorithm: "argon2id" }));
    expect(await h.verify(PW, stored)).toBe(true);
    expect(await h.verify(`${PW}!`, stored)).toBe(false);
  });
});

describe("the hasher", () => {
  for (const algorithm of ["pbkdf2", "scrypt", ...(hasArgon ? (["argon2id"] as const) : [])] as const) {
    it(`${algorithm}: hashes with a fresh salt, verifies, and normalises Unicode the way core does`, async () => {
      const h = createPasswordHasher(cfg({ algorithm }));
      const a = await h.hash("pässwörd-ok-123");
      const b = await h.hash("pässwörd-ok-123");
      expect(a).not.toBe(b);
      expect(await h.verify("pässwörd-ok-123", a)).toBe(true);
      expect(await h.verify("passwörd-ok-123", a)).toBe(false);
      expect(await h.verify("pässwörd-ok-123".replace("ö", "ö"), a)).toBe(true); // composed vs decomposed
      expect(await h.verify("anything", NO_PASSWORD)).toBe(false);
      expect(await h.verify("anything", "")).toBe(false);
      expect(await h.verify("anything", "$ath-scrypt$v=1$N=1,r=1,p=1$x$y")).toBe(false);
      expect(h.needsRehash(a)).toBe(false);
    });
  }

  it("keeps verifying older hashes after a switch, and says which need an upgrade", async () => {
    const old = await hashPassword(PW);
    const scrypt = createPasswordHasher(cfg({ algorithm: "scrypt" }));
    expect(await scrypt.verify(PW, old)).toBe(true);
    expect(scrypt.needsRehash(old)).toBe(true);
    const weaker = await createPasswordHasher(cfg({ algorithm: "scrypt", scrypt: { N: 1024, r: 8, p: 1 } })).hash(PW);
    expect(await scrypt.verify(PW, weaker)).toBe(true);
    expect(scrypt.needsRehash(weaker)).toBe(true);
    const back = createPasswordHasher(cfg({ algorithm: "pbkdf2" }));
    expect(back.needsRehash(await scrypt.hash(PW))).toBe(true);
    expect(await back.verify(PW, await scrypt.hash(PW))).toBe(true);
    expect(back.needsRehash(old)).toBe(false);
  });

  it("refuses stored parameters that would exhaust the server", async () => {
    const h = createPasswordHasher(cfg({ algorithm: "scrypt" }));
    const hash = b64urlEncode(new Uint8Array(32));
    for (const p of ["N=1073741824,r=8,p=1", "N=16384,r=1000,p=1", "N=16384,r=8,p=1000", "N=3,r=8,p=1", "N=0,r=8,p=1", "N=16384,r=8"]) {
      const t0 = performance.now();
      expect(await h.verify(PW, `$ath-scrypt$v=1$${p}$${SALT}$${hash}`)).toBe(false);
      expect(performance.now() - t0).toBeLessThan(3000);
    }
    for (const p of ["m=4000000000,t=3,p=1", "m=65536,t=1000,p=1", "m=1,t=1,p=8", "m=65536,t=3,p=0"]) expect(await h.verify(PW, `$ath-argon2id$v=1$${p}$${SALT}$${hash}`)).toBe(false);
  });

  it("will not start with settings it cannot honour", () => {
    expect(() => createPasswordHasher(cfg({ algorithm: "scrypt", scrypt: { N: 1000, r: 8, p: 1 } }))).toThrow(/power of two/);
    if (!hasArgon) expect(() => createPasswordHasher(cfg({ algorithm: "argon2id" }))).toThrow(/24\.7/);
  });

  it("takes about as long to turn away an unknown user as to check a real one", async () => {
    const h = createPasswordHasher(cfg({ algorithm: "scrypt", scrypt: { N: 2 ** 15, r: 8, p: 1 } }));
    const real = await h.hash(PW);
    const time = async (stored: string): Promise<number> => {
      const t0 = performance.now();
      for (let i = 0; i < 3; i++) await h.verify("wrong", stored);
      return (performance.now() - t0) / 3;
    };
    await time(real);
    const [a, b] = [await time(real), await time(NO_PASSWORD)];
    expect(b).toBeGreaterThan(a * 0.5);
    expect(b).toBeLessThan(a * 2);
  });
});

const hashOf = (h: Harness): { passwordHash: string } => h.users().find((u) => u.email === "margaret@linear-ops.test") as unknown as { passwordHash: string };

describe("the server upgrades hashes at sign-in", () => {
  const LIN = "linear_ops_workspace";
  const run = async (algorithm: "scrypt" | "argon2id"): Promise<void> => {
    const h: Harness = await startHarness({ passwordHashing: { algorithm, scrypt: { N: 16384, r: 8, p: 1 }, argon2id: { memoryKiB: 8192, passes: 2, parallelism: 1 } } });
    try {
      const before = hashOf(h);
      expect(before.passwordHash.startsWith("$ath-pbkdf2$")).toBe(true);
      const wrong = await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: "not the password" });
      expect(wrong.status).toBeGreaterThanOrEqual(400);
      expect(hashOf(h).passwordHash).toBe(before.passwordHash);
      expect((await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).status).toBe(200);
      const after = hashOf(h);
      expect(after.passwordHash.startsWith(`$ath-${algorithm}$`)).toBe(true);
      await h.restart();
      expect((await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).status).toBe(200);
      expect(hashOf(h).passwordHash).toBe(after.passwordHash);
      expect((await h.call("GET", "/api/ledger")).body["entries"]).toEqual(expect.arrayContaining([expect.objectContaining({ type: "password.rehashed" })]));
    } finally {
      await h.close();
    }
  };
  it("scrypt", () => run("scrypt"));
  it.skipIf(!hasArgon)("argon2id", () => run("argon2id"));
});
