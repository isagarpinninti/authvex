import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  CborError, TOKEN_PREFIX, WebAuthnFormatError, b64urlEncode, createDpopProof, decodeCborExact, derToRawSignature, generateIssuerKey, parseAuthenticatorData, peekTokenPayload,
  signToken, tokenKind, parseCertificate, pemToDer, X509Error, verifyDpopProof, verifyJwt, verifySignedToken, verifyWebAuthnAssertion, verifyWebAuthnRegistration, verifyPkce, normalizeHtu,
} from "../src";

import { ecLeaf as ecLeafPem } from "./fixtures/opensslCerts";

const runs = Number(process.env["AUTHVEX_FUZZ_RUNS"] ?? 300);
const junk = fc.oneof(fc.string(), fc.string({ unit: "binary" }), fc.stringMatching(/^[A-Za-z0-9_\-.]{0,120}$/), fc.constant(""), fc.constant("....."), fc.string().map((s) => `${s}.${s}.${s}`));
const bytes = fc.uint8Array({ maxLength: 300 });

describe("parsers never throw an unexpected error, whatever they are fed", () => {
  it("CBOR: either a value or a CborError", () => {
    fc.assert(fc.property(bytes, (b) => {
      try { decodeCborExact(b); } catch (e) { expect(e).toBeInstanceOf(CborError); }
    }), { numRuns: runs * 3 });
  });

  it("CBOR: a deeply nested or huge-length input is refused, not followed", () => {
    expect(() => decodeCborExact(new Uint8Array(5000).fill(0x81))).toThrow(CborError);
    expect(() => decodeCborExact(Uint8Array.from([0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))).toThrow(CborError);
    expect(() => decodeCborExact(Uint8Array.from([0x9b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff]))).toThrow(CborError);
  });

  it("X.509 certificates: a certificate or an X509Error, for random bytes and for a real certificate with bytes flipped", () => {
    const real = pemToDer(ecLeafPem)[0] as Uint8Array;
    fc.assert(fc.property(bytes, (b) => {
      try { parseCertificate(b); } catch (e) { expect(e).toBeInstanceOf(X509Error); }
    }), { numRuns: runs * 3 });
    fc.assert(fc.property(fc.integer({ min: 0, max: real.length - 1 }), fc.integer({ min: 1, max: 255 }), fc.integer({ min: 0, max: real.length }), (i, x, cut) => {
      const t = real.slice(0, cut > 0 && cut < real.length && cut % 3 === 0 ? cut : real.length);
      if (i < t.length) t[i] = (t[i] as number) ^ x;
      try { parseCertificate(t); } catch (e) { expect(e).toBeInstanceOf(X509Error); }
    }), { numRuns: runs * 4 });
  });

  it("authenticator data: a result or a WebAuthnFormatError", () => {
    fc.assert(fc.property(bytes, (b) => {
      try { parseAuthenticatorData(b); } catch (e) { expect(e).toBeInstanceOf(WebAuthnFormatError); }
    }), { numRuns: runs * 3 });
  });

  it("DER signatures: raw bytes or a WebAuthnFormatError", () => {
    fc.assert(fc.property(bytes, (b) => {
      try { expect(derToRawSignature(b)).toHaveLength(64); } catch (e) { expect(e).toBeInstanceOf(WebAuthnFormatError); }
    }), { numRuns: runs * 3 });
  });

  it("token helpers answer null or a kind for any string", () => {
    fc.assert(fc.property(junk, (s) => {
      peekTokenPayload(s);
      tokenKind(s);
      normalizeHtu(`https://x.test/${s.slice(0, 20).replace(/[^\w/.-]/g, "")}`);
    }), { numRuns: runs * 2 });
  });
});

describe("verifiers reject garbage with a reason instead of throwing, and accept nothing forged", async () => {
  const issuer = await generateIssuerKey();
  const other = await generateIssuerKey();
  const keys = issuer.publicKeyJwk;

  it("signed tokens", async () => {
    await fc.assert(fc.asyncProperty(junk, async (s) => {
      for (const prefix of Object.values(TOKEN_PREFIX)) {
        const r = await verifySignedToken(prefix, `${prefix}${s}`, keys);
        expect(r.ok).toBe(false);
      }
      expect((await verifySignedToken(TOKEN_PREFIX.session, s, keys)).ok).toBe(false);
    }), { numRuns: runs });
  });

  it("a token signed by a different key never verifies, and neither does a payload swapped under a valid signature", async () => {
    const good = await signToken(TOKEN_PREFIX.session, { v: 1, sub: "u", exp: 9_999_999_999 }, issuer.privateKey, issuer.kid);
    expect((await verifySignedToken(TOKEN_PREFIX.session, good, keys)).ok).toBe(true);
    const forged = await signToken(TOKEN_PREFIX.session, { v: 1, sub: "u", exp: 9_999_999_999 }, other.privateKey, issuer.kid);
    expect((await verifySignedToken(TOKEN_PREFIX.session, forged, keys)).ok).toBe(false);
    const sig = good.split(".")[1] as string;
    await fc.assert(fc.asyncProperty(fc.object(), async (obj) => {
      const swapped = `${TOKEN_PREFIX.session}${b64urlEncode(new TextEncoder().encode(JSON.stringify({ ...obj, kid: issuer.kid })))}.${sig}`;
      expect((await verifySignedToken(TOKEN_PREFIX.session, swapped, keys)).ok).toBe(false);
    }), { numRuns: runs });
  });

  it("any single changed character in a valid token breaks it (except base64 padding bits at the very end)", async () => {
    const good = await signToken(TOKEN_PREFIX.session, { v: 1, sub: "u", exp: 9_999_999_999 }, issuer.privateKey, issuer.kid);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    await fc.assert(fc.asyncProperty(fc.integer({ min: TOKEN_PREFIX.session.length, max: good.length - 2 }), fc.integer({ min: 0, max: 63 }), async (i, a) => {
      const c = alphabet[a] as string;
      if (good[i] === c || good[i] === ".") return;
      const t = good.slice(0, i) + c + good.slice(i + 1);
      expect((await verifySignedToken(TOKEN_PREFIX.session, t, keys)).ok).toBe(false);
    }), { numRuns: runs });
  });

  it("JWTs", async () => {
    await fc.assert(fc.asyncProperty(junk, async (s) => {
      expect((await verifyJwt(s, keys)).ok).toBe(false);
    }), { numRuns: runs });
  });

  it("DPoP proofs, with or without a session token and on any method or URL", async () => {
    await fc.assert(fc.asyncProperty(junk, junk, async (proof, tok) => {
      const r = await verifyDpopProof({ proof, method: "POST", url: "https://a.test/x", sessionToken: tok });
      expect(r.ok).toBe(false);
    }), { numRuns: runs });
  });

  it("DPoP proofs: the claims that were signed are the claims that count", async () => {
    const dev = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const jwk = await globalThis.crypto.subtle.exportKey("jwk", dev.publicKey);
    const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    const proof = await createDpopProof({ privateKey: dev.privateKey, publicKeyJwk: pub, method: "POST", url: "https://a.test/x" });
    expect((await verifyDpopProof({ proof, method: "POST", url: "https://a.test/x" })).ok).toBe(true);
    await fc.assert(fc.asyncProperty(fc.constantFrom("GET", "PUT", "DELETE", "post"), fc.webUrl(), async (m, u) => {
      if (m === "post" || u === "https://a.test/x") return;
      expect((await verifyDpopProof({ proof, method: m, url: u })).ok).toBe(false);
    }), { numRuns: runs });
  });

  it("WebAuthn assertions and registrations", async () => {
    const expected = { challenge: "abc", origin: "https://a.test", rpId: "a.test" };
    await fc.assert(fc.asyncProperty(junk, junk, junk, junk, async (a, b, c, d) => {
      const r = await verifyWebAuthnAssertion({ expected, response: { clientDataJSON: a, authenticatorData: b, signature: c } as never, credential: { publicKeyJwk: keys, signCount: 0 } });
      expect(r.ok).toBe(false);
      const g = await verifyWebAuthnRegistration({ expected, response: { clientDataJSON: a, attestationObject: d } });
      expect(g.ok).toBe(false);
    }), { numRuns: runs });
  });

  it("PKCE with any verifier and challenge", async () => {
    await fc.assert(fc.asyncProperty(junk, junk, async (v, c) => {
      expect(typeof (await verifyPkce(v, c))).toBe("boolean");
    }), { numRuns: runs });
  });
});
