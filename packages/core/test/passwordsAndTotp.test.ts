import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  PBKDF2_ITERATIONS, base32Decode, base32Encode, buildOtpAuthUri, computeHotp, computeTotpCode, constantTimeEqual, generateTotpSecret, hashPassword, passwordNeedsRehash, utf8, verifyPassword, verifyTotpCode, NO_PASSWORD,
} from "../src";

describe("password vault", () => {
  it("hashes to the documented format with a fresh salt each time", async () => {
    const a = await hashPassword("correct horse battery staple");
    const b = await hashPassword("correct horse battery staple");
    expect(a).toMatch(/^\$ath-pbkdf2\$v=1\$iter=210000\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/);
    expect(a).not.toBe(b);
  });
  it("verifies the right password and refuses a wrong one", async () => {
    const h = await hashPassword("s3cret-Passw0rd!");
    expect(await verifyPassword("s3cret-Passw0rd!", h)).toBe(true);
    expect(await verifyPassword("s3cret-Passw0rd", h)).toBe(false);
    expect(await verifyPassword("", h)).toBe(false);
  });
  it("normalises Unicode so the same password typed two ways matches", async () => {
    const h = await hashPassword("café");
    expect(await verifyPassword("café", h)).toBe(true);
  });
  it("refuses malformed, truncated and hostile hashes without throwing", async () => {
    for (const bad of ["", "plain", NO_PASSWORD, "$ath-pbkdf2$v=1$iter=0$aaaaaaaaaaaaaaaaaaaaaa$bbbb", "$ath-pbkdf2$v=1$iter=999999999999$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "$ath-pbkdf2$v=1$iter=1000$$", "$ath-pbkdf2$v=1$iter=1000$a$b$c"]) {
      expect(await verifyPassword("x", bad), bad).toBe(false);
    }
  });
  it("flags hashes with fewer iterations for re-hashing", async () => {
    expect(passwordNeedsRehash(await hashPassword("x"))).toBe(false);
    expect(passwordNeedsRehash(await hashPassword("x", 1000))).toBe(true);
    expect(passwordNeedsRehash("garbage")).toBe(true);
    expect(PBKDF2_ITERATIONS).toBe(210_000);
  });
  it("compares in constant time regardless of where bytes differ", () => {
    expect(constantTimeEqual(utf8("abc"), utf8("abc"))).toBe(true);
    expect(constantTimeEqual(utf8("abc"), utf8("abd"))).toBe(false);
    expect(constantTimeEqual(utf8("abc"), utf8("abcd"))).toBe(false);
    expect(constantTimeEqual(new Uint8Array(), new Uint8Array())).toBe(true);
  });
});

describe("Base32 (RFC 4648 test vectors)", () => {
  const vectors: Array<[string, string]> = [["", ""], ["f", "MY"], ["fo", "MZXQ"], ["foo", "MZXW6"], ["foob", "MZXW6YQ"], ["fooba", "MZXW6YTB"], ["foobar", "MZXW6YTBOI"]];
  it.each(vectors)("encodes %j as %s and back", (plain, enc) => {
    expect(base32Encode(utf8(plain))).toBe(enc);
    expect(new TextDecoder().decode(base32Decode(enc))).toBe(plain);
  });
  it("accepts padding, spaces and lower case, and rejects other characters", () => {
    expect(new TextDecoder().decode(base32Decode("mzxw 6ytb oi======"))).toBe("foobar");
    expect(() => base32Decode("MZXW1")).toThrow(/not a Base32/);
  });
  it("round-trips arbitrary bytes", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 64 }), (b) => {
      expect(base32Decode(base32Encode(b))).toEqual(b);
    }));
  });
});

const SECRET = utf8("12345678901234567890");

describe("HOTP (RFC 4226 Appendix D)", () => {
  const expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
  it.each(expected.map((c, i) => [i, c] as const))("counter %i gives %s", async (i, code) => {
    expect(await computeHotp(SECRET, i)).toBe(code);
  });
  it("rejects a negative or fractional counter", async () => {
    await expect(computeHotp(SECRET, -1)).rejects.toThrow();
    await expect(computeHotp(SECRET, 1.5)).rejects.toThrow();
  });
});

describe("TOTP (RFC 6238 Appendix B, SHA-1, 8 digits)", () => {
  const vectors: Array<[number, string]> = [[59, "94287082"], [1111111109, "07081804"], [1111111111, "14050471"], [1234567890, "89005924"], [2000000000, "69279037"], [20000000000, "65353130"]];
  const secretB32 = base32Encode(SECRET);
  it.each(vectors)("at t=%i the code is %s", async (t, code) => {
    expect(await computeTotpCode(secretB32, { nowMs: t * 1000, digits: 8 })).toBe(code);
  });
  it("makes 6-digit codes by default, zero-padded", async () => {
    expect(await computeTotpCode(secretB32, { nowMs: 1111111109 * 1000 })).toBe("081804");
  });
});

describe("TOTP verification", () => {
  const secret = generateTotpSecret();
  const t0 = 1_700_000_010_000;
  it("accepts the current code and one step of drift either way, not two", async () => {
    const at = (s: number): Promise<string> => computeTotpCode(secret, { nowMs: t0 + s * 1000 });
    expect((await verifyTotpCode(secret, await at(0), { nowMs: t0 })).ok).toBe(true);
    expect((await verifyTotpCode(secret, await at(-30), { nowMs: t0 })).ok).toBe(true);
    expect((await verifyTotpCode(secret, await at(30), { nowMs: t0 })).ok).toBe(true);
    expect((await verifyTotpCode(secret, await at(-60), { nowMs: t0 })).ok).toBe(false);
    expect((await verifyTotpCode(secret, await at(60), { nowMs: t0 })).ok).toBe(false);
  });
  it("refuses a code that was already used, via the counter it reports", async () => {
    const code = await computeTotpCode(secret, { nowMs: t0 });
    const first = await verifyTotpCode(secret, code, { nowMs: t0 });
    expect(first.ok).toBe(true);
    if (first.ok) expect((await verifyTotpCode(secret, code, { nowMs: t0, minCounter: first.counter })).ok).toBe(false);
  });
  it("refuses wrong, short, long and non-numeric codes", async () => {
    for (const c of ["000000x", "12345", "1234567", "abcdef", "", " 123456"]) expect((await verifyTotpCode(secret, c, { nowMs: t0 })).ok, c).toBe(false);
  });
  it("builds a standard otpauth URI", () => {
    const uri = buildOtpAuthUri({ secretB32: "JBSWY3DPEHPK3PXP", account: "ada@acme.test", issuer: "Acme Inc" });
    expect(uri).toBe("otpauth://totp/Acme%20Inc:ada%40acme.test?secret=JBSWY3DPEHPK3PXP&issuer=Acme+Inc&algorithm=SHA1&digits=6&period=30");
  });
  it("generates 160-bit secrets", () => {
    expect(base32Decode(generateTotpSecret())).toHaveLength(20);
  });
});
