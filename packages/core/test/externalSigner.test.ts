import { describe, expect, it } from "vitest";
import {
  createDpopProof, derToRawSignature, externalIssuerKey, generateIssuerKey, issueSessionBundle, rawToDerSignature, serializeIssuerKey, signJwt, verifyDpopSessionRequest, verifyJwt, verifySignedToken,
  TOKEN_PREFIX, signToken, type ExternalSigner,
} from "../src";

/** A stand-in for a cloud KMS: the private key is non-extractable and sits behind `sign`, which answers in ASN.1 DER like AWS KMS does. */
async function fakeKms() {
  const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  const calls: number[] = [];
  const der: ExternalSigner = {
    async sign(data) {
      calls.push(data.length);
      return rawToDerSignature(new Uint8Array(await globalThis.crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, data as Uint8Array<ArrayBuffer>)));
    },
  };
  const raw: ExternalSigner = { sign: async (data) => derToRawSignature(await der.sign(data)) };
  return { publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey, der, raw, calls };
}

describe("an issuer key held outside the process (KMS / HSM)", () => {
  it("signs sessions, admin tokens, JWTs and impersonation-style tokens that verify like any other", async () => {
    const kms = await fakeKms();
    const issuer = await externalIssuerKey({ publicKeyJwk: kms.publicKeyJwk, signer: kms.raw });
    const dev = await generateIssuerKey();
    const b = await issueSessionBundle({ issuer, userId: "u", tenantId: "t", clientPublicKeyJwk: dev.publicKeyJwk });
    const keys = { keys: [{ ...issuer.publicKeyJwk, kid: issuer.kid }] };
    expect((await verifySignedToken(TOKEN_PREFIX.session, b.sessionToken, keys)).ok).toBe(true);
    const proof = await createDpopProof({ privateKey: dev.privateKey, publicKeyJwk: dev.publicKeyJwk, method: "GET", url: "https://a.test/x", sessionToken: b.sessionToken });
    expect(await verifyDpopSessionRequest({ sessionToken: b.sessionToken, dpopProof: proof, method: "GET", url: "https://a.test/x", issuerPublicKeyJwk: keys })).toMatchObject({ ok: true, bound: true });
    const admin = await signToken(TOKEN_PREFIX.admin, { v: 1, typ: "admin", exp: 9_999_999_999 }, issuer.privateKey, issuer.kid);
    expect((await verifySignedToken(TOKEN_PREFIX.admin, admin, keys)).ok).toBe(true);
    const jwt = await signJwt({ iss: "https://i", sub: "u", aud: "a", iat: 1, exp: 9_999_999_999 }, issuer);
    expect((await verifyJwt(jwt, keys, { issuer: "https://i", audience: "a", nowMs: 5000 })).ok).toBe(true);
    expect(kms.calls.length).toBe(4);
  });

  it("works with a signer that already returns raw r||s", async () => {
    const kms = await fakeKms();
    const issuer = await externalIssuerKey({ publicKeyJwk: kms.publicKeyJwk, signer: kms.raw });
    expect(issuer.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("is refused at start-up when the signer and the public key do not belong together", async () => {
    const a = await fakeKms();
    const b = await fakeKms();
    await expect(externalIssuerKey({ publicKeyJwk: a.publicKeyJwk, signer: b.raw })).rejects.toThrow(/does not verify/);
    await expect(externalIssuerKey({ publicKeyJwk: a.publicKeyJwk, signer: a.der })).rejects.toThrow(/64-byte|r\|\|s/); // DER not converted
    await expect(externalIssuerKey({ publicKeyJwk: { kty: "EC", crv: "P-384", x: "a", y: "b" }, signer: a.raw })).rejects.toThrow(/P-256/);
    await expect(externalIssuerKey({ publicKeyJwk: a.publicKeyJwk, signer: { sign: async () => new Uint8Array(64) } })).rejects.toThrow(/does not verify/);
  });

  it("cannot be exported, so a key file can never contain it", async () => {
    const kms = await fakeKms();
    await expect(serializeIssuerKey(await externalIssuerKey({ publicKeyJwk: kms.publicKeyJwk, signer: kms.raw }))).rejects.toThrow(/cannot be exported/);
  });

  it("reports a failing KMS as an error, not as a forged signature", async () => {
    const kms = await fakeKms();
    const issuer = await externalIssuerKey({ publicKeyJwk: kms.publicKeyJwk, signer: kms.raw });
    const down = { ...issuer, privateKey: { sign: async () => { throw new Error("KMS is unavailable"); } } };
    await expect(issueSessionBundle({ issuer: down, userId: "u", tenantId: "t" })).rejects.toThrow(/KMS is unavailable/);
  });
});
