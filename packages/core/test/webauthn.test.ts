import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  CborError, b64urlDecode, b64urlEncode, concat, createSoftwareAuthenticator, decodeCbor, decodeCborExact, derToRawSignature, encodeCbor, generateChallenge, hex, parseAuthenticatorData, rawToDerSignature, sha256, utf8,
  verifyWebAuthnAssertion, verifyWebAuthnRegistration, WebAuthnFormatError, type CborValue,
} from "../src";

const RP = "app.example.com";
const ORIGIN = "https://app.example.com";

describe("CBOR subset", () => {
  it("decodes the RFC 8949 Appendix A examples it supports", () => {
    expect(decodeCborExact(Uint8Array.from([0x00]))).toBe(0);
    expect(decodeCborExact(Uint8Array.from([0x18, 0x64]))).toBe(100);
    expect(decodeCborExact(Uint8Array.from([0x19, 0x03, 0xe8]))).toBe(1000);
    expect(decodeCborExact(Uint8Array.from([0x20]))).toBe(-1);
    expect(decodeCborExact(Uint8Array.from([0x38, 0x63]))).toBe(-100);
    expect(decodeCborExact(Uint8Array.from([0x63, 0x61, 0x62, 0x63]))).toBe("abc");
    expect(decodeCborExact(Uint8Array.from([0x43, 1, 2, 3]))).toEqual(Uint8Array.from([1, 2, 3]));
    expect(decodeCborExact(Uint8Array.from([0x83, 1, 2, 3]))).toEqual([1, 2, 3]);
    expect(decodeCborExact(Uint8Array.from([0xf5]))).toBe(true);
    expect([...(decodeCborExact(Uint8Array.from([0xa2, 0x01, 0x02, 0x03, 0x04])) as Map<number, number>)]).toEqual([[1, 2], [3, 4]]);
  });
  it("round-trips values it encodes", () => {
    const v = new Map<CborValue, CborValue>([["fmt", "none"], [1, -7], [-2, Uint8Array.from([9, 8, 7])], ["nested", [1, [true, null], new Map()]]]);
    expect(decodeCborExact(encodeCbor(v))).toEqual(v);
  });
  it("refuses indefinite lengths, truncation, duplicate keys, trailing bytes, floats and deep nesting", () => {
    expect(() => decodeCborExact(Uint8Array.from([0x9f, 0x01, 0xff]))).toThrow(CborError);
    expect(() => decodeCborExact(Uint8Array.from([0x44, 1, 2]))).toThrow(CborError);
    expect(() => decodeCborExact(Uint8Array.from([0xa2, 0x01, 0x02, 0x01, 0x03]))).toThrow(/duplicate/);
    expect(() => decodeCborExact(Uint8Array.from([0x00, 0x00]))).toThrow(/trailing/);
    expect(() => decodeCborExact(Uint8Array.from([0xfb, 0, 0, 0, 0, 0, 0, 0, 0]))).toThrow(CborError);
    expect(() => decodeCborExact(Uint8Array.from(Array(20).fill(0x81).concat([0])))).toThrow(/deep/);
    expect(() => decodeCborExact(Uint8Array.from([0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))).toThrow(CborError);
  });
  it("never throws anything but CborError on arbitrary input", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 80 }), (b) => {
      try {
        decodeCbor(b);
      } catch (e) {
        expect(e).toBeInstanceOf(CborError);
      }
    }), { numRuns: 500 });
  });
});

describe("authenticatorData", () => {
  it("decodes the 37-byte header: rpIdHash, flag bits and the big-endian counter", async () => {
    const rpHash = await sha256("example.com");
    const data = concat(rpHash, Uint8Array.from([0b0001_1101]), Uint8Array.from([0x00, 0x01, 0x02, 0x03]));
    const p = parseAuthenticatorData(data);
    expect(hex(p.rpIdHash)).toBe("a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947");
    expect(p.flags).toEqual({ userPresent: true, userVerified: true, backupEligible: true, backupState: true, attestedCredentialData: false, extensionData: false });
    expect(p.signCount).toBe(0x00010203);
  });
  it("reads each flag independently", async () => {
    const base = await sha256("x");
    const flags = (b: number) => parseAuthenticatorData(concat(base, Uint8Array.from([b]), new Uint8Array(4))).flags;
    expect(flags(0x01)).toMatchObject({ userPresent: true, userVerified: false });
    expect(flags(0x04)).toMatchObject({ userPresent: false, userVerified: true });
    expect(flags(0x08)).toMatchObject({ backupEligible: true, backupState: false });
    expect(() => flags(0x10)).toThrow(/backup-eligible/);
  });
  it("rejects short data and unexpected trailing bytes", async () => {
    expect(() => parseAuthenticatorData(new Uint8Array(36))).toThrow(WebAuthnFormatError);
    const hash = await sha256("x");
    expect(() => parseAuthenticatorData(concat(hash, Uint8Array.from([1]), new Uint8Array(5)))).toThrow(/unexpected bytes/);
  });
  it("never throws anything but WebAuthnFormatError", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 160 }), (b) => {
      try {
        parseAuthenticatorData(b);
      } catch (e) {
        expect(e).toBeInstanceOf(WebAuthnFormatError);
      }
    }), { numRuns: 500 });
  });
});

describe("ECDSA DER <-> raw", () => {
  it("round-trips, including values with leading zeros and high bits", () => {
    fc.assert(fc.property(fc.uint8Array({ minLength: 64, maxLength: 64 }), (raw) => {
      expect(derToRawSignature(rawToDerSignature(raw))).toEqual(raw);
    }), { numRuns: 300 });
    const edge = new Uint8Array(64);
    edge[0] = 0x80;
    edge[32] = 0x00;
    edge[63] = 0xff;
    expect(derToRawSignature(rawToDerSignature(edge))).toEqual(edge);
  });
  it("rejects malformed DER", () => {
    for (const bad of [[], [0x31, 0], [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01], [0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01], [0x30, 0x03, 0x02, 0x01, 0x01], [0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0xff]]) {
      expect(() => derToRawSignature(Uint8Array.from(bad)), JSON.stringify(bad)).toThrow(WebAuthnFormatError);
    }
  });
});

async function enrolled(extra: { backupEligible?: boolean } = {}) {
  const auth = await createSoftwareAuthenticator({ rpId: RP, origin: ORIGIN, ...extra });
  const challenge = generateChallenge();
  const reg = await verifyWebAuthnRegistration({ expected: { challenge, origin: ORIGIN, rpId: RP }, response: await auth.register(challenge) });
  if (!reg.ok) throw new Error(`registration failed: ${reg.message}`);
  return { auth, credential: { publicKeyJwk: reg.publicKeyJwk, signCount: reg.signCount }, reg };
}

describe("registration", () => {
  it("extracts the credential id and public key from the attestation object", async () => {
    const { auth, reg } = await enrolled({ backupEligible: true });
    expect(reg.credentialId).toBe(auth.credentialId);
    expect(reg.publicKeyJwk).toEqual(auth.publicKeyJwk);
    expect(reg.flags).toMatchObject({ userPresent: true, userVerified: true, backupEligible: true, attestedCredentialData: true });
  });
  it("refuses a wrong challenge, origin, RP id and an unsupported attestation format", async () => {
    const auth = await createSoftwareAuthenticator({ rpId: RP, origin: ORIGIN });
    const challenge = generateChallenge();
    const response = await auth.register(challenge);
    expect(await verifyWebAuthnRegistration({ expected: { challenge: generateChallenge(), origin: ORIGIN, rpId: RP }, response })).toMatchObject({ ok: false, reason: "challenge_mismatch" });
    expect(await verifyWebAuthnRegistration({ expected: { challenge, origin: "https://evil.example", rpId: RP }, response })).toMatchObject({ ok: false, reason: "origin_mismatch" });
    expect(await verifyWebAuthnRegistration({ expected: { challenge, origin: ORIGIN, rpId: "other.example.com" }, response })).toMatchObject({ ok: false, reason: "rp_id_mismatch" });
    const packed = b64urlEncode(encodeCbor(new Map<CborValue, CborValue>([["fmt", "packed"], ["attStmt", new Map()], ["authData", new Uint8Array(40)]])));
    expect(await verifyWebAuthnRegistration({ expected: { challenge, origin: ORIGIN, rpId: RP }, response: { clientDataJSON: response.clientDataJSON, attestationObject: packed } })).toMatchObject({ ok: false, reason: "unsupported_attestation" });
    expect(await verifyWebAuthnRegistration({ expected: { challenge, origin: ORIGIN, rpId: RP }, response: { clientDataJSON: response.clientDataJSON, attestationObject: "AAAA" } })).toMatchObject({ ok: false, reason: "malformed" });
  });
});

describe("assertion", () => {
  const expected = (challenge: string) => ({ challenge, origin: ORIGIN, rpId: RP });

  it("accepts a valid passkey sign-in and reports the new counter", async () => {
    const { auth, credential } = await enrolled();
    const challenge = generateChallenge();
    const r = await verifyWebAuthnAssertion({ expected: expected(challenge), response: await auth.assert(challenge), credential });
    expect(r).toMatchObject({ ok: true, signCount: 1 });
  });
  it("tracks the counter across sign-ins", async () => {
    const { auth, credential } = await enrolled();
    let stored = credential.signCount;
    for (let i = 1; i <= 3; i++) {
      const c = generateChallenge();
      const r = await verifyWebAuthnAssertion({ expected: expected(c), response: await auth.assert(c), credential: { ...credential, signCount: stored } });
      expect(r.ok).toBe(true);
      if (r.ok) stored = r.signCount;
    }
    expect(stored).toBe(3);
  });
  it("refuses a different challenge, origin and RP id", async () => {
    const { auth, credential } = await enrolled();
    const challenge = generateChallenge();
    const response = await auth.assert(challenge);
    expect(await verifyWebAuthnAssertion({ expected: expected(generateChallenge()), response, credential })).toMatchObject({ ok: false, reason: "challenge_mismatch" });
    expect(await verifyWebAuthnAssertion({ expected: { ...expected(challenge), origin: "https://phish.example" }, response, credential })).toMatchObject({ ok: false, reason: "origin_mismatch" });
    expect(await verifyWebAuthnAssertion({ expected: { ...expected(challenge), rpId: "phish.example" }, response, credential })).toMatchObject({ ok: false, reason: "rp_id_mismatch" });
  });
  it("refuses an assertion made for registration (type mismatch)", async () => {
    const { auth, credential } = await enrolled();
    const challenge = generateChallenge();
    const reg = await auth.register(challenge);
    const r = await verifyWebAuthnAssertion({ expected: expected(challenge), response: { clientDataJSON: reg.clientDataJSON, authenticatorData: (await auth.assert(challenge)).authenticatorData, signature: "AAAA" }, credential });
    expect(r).toMatchObject({ ok: false, reason: "type_mismatch" });
  });
  it("requires user verification unless told otherwise", async () => {
    const { auth, credential } = await enrolled();
    const challenge = generateChallenge();
    const response = await auth.assert(challenge, { userVerified: false });
    expect(await verifyWebAuthnAssertion({ expected: expected(challenge), response, credential })).toMatchObject({ ok: false, reason: "user_not_verified" });
    expect((await verifyWebAuthnAssertion({ expected: { ...expected(challenge), requireUserVerification: false }, response, credential })).ok).toBe(true);
  });
  it("detects a cloned authenticator when the counter does not advance", async () => {
    const { auth, credential } = await enrolled();
    const challenge = generateChallenge();
    const response = await auth.assert(challenge, { signCount: 5 });
    expect(await verifyWebAuthnAssertion({ expected: expected(challenge), response, credential: { ...credential, signCount: 5 } })).toMatchObject({ ok: false, reason: "sign_count_regression" });
    expect(await verifyWebAuthnAssertion({ expected: expected(challenge), response, credential: { ...credential, signCount: 9 } })).toMatchObject({ ok: false, reason: "sign_count_regression" });
    expect((await verifyWebAuthnAssertion({ expected: expected(challenge), response, credential: { ...credential, signCount: 4 } })).ok).toBe(true);
  });
  it("allows authenticators that always report a zero counter (synced passkeys)", async () => {
    const { auth, credential } = await enrolled({ backupEligible: true });
    const challenge = generateChallenge();
    const response = await auth.assert(challenge, { signCount: 0 });
    expect((await verifyWebAuthnAssertion({ expected: expected(challenge), response, credential })).ok).toBe(true);
  });
  it("refuses a signature from another key, and a tampered one", async () => {
    const { auth, credential } = await enrolled();
    const other = await createSoftwareAuthenticator({ rpId: RP, origin: ORIGIN });
    const challenge = generateChallenge();
    expect(await verifyWebAuthnAssertion({ expected: expected(challenge), response: await other.assert(challenge), credential })).toMatchObject({ ok: false, reason: "bad_signature" });
    const good = await auth.assert(challenge);
    const sig = b64urlDecode(good.signature);
    sig[sig.length - 1] = (sig[sig.length - 1] as number) ^ 1;
    expect(await verifyWebAuthnAssertion({ expected: expected(challenge), response: { ...good, signature: b64urlEncode(sig) }, credential })).toMatchObject({ ok: false });
  });
  it("refuses authenticator data that was altered after signing", async () => {
    const { auth, credential } = await enrolled();
    const challenge = generateChallenge();
    const good = await auth.assert(challenge);
    const data = b64urlDecode(good.authenticatorData);
    data[36] = (data[36] as number) + 1;
    expect(await verifyWebAuthnAssertion({ expected: expected(challenge), response: { ...good, authenticatorData: b64urlEncode(data) }, credential })).toMatchObject({ ok: false, reason: "bad_signature" });
  });
  it("reports garbage as malformed or invalid client data, never throws", async () => {
    const { credential } = await enrolled();
    const challenge = generateChallenge();
    expect(await verifyWebAuthnAssertion({ expected: expected(challenge), response: { clientDataJSON: "!!!", authenticatorData: "", signature: "" }, credential })).toMatchObject({ ok: false, reason: "client_data_invalid" });
    const cd = b64urlEncode(utf8(JSON.stringify({ type: "webauthn.get", challenge, origin: ORIGIN })));
    expect(await verifyWebAuthnAssertion({ expected: expected(challenge), response: { clientDataJSON: cd, authenticatorData: "AAAA", signature: "AAAA" }, credential })).toMatchObject({ ok: false, reason: "malformed" });
  });
});
