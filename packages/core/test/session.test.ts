import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import {
  DpopReplayCache, TOKEN_PREFIX, b64urlEncode, computeJwkThumbprint, createDpopProof, generateIssuerKey, importIssuerKey, issueNextAccessToken, issueSessionBundle, normalizeHtu, peekTokenPayload,
  revokeFamily, rotateRefreshTokenFamily, serializeIssuerKey, sha256, tokenKind, utf8, verifyDpopProof, verifyDpopSessionRequest, verifySignedToken, type IssuerKey, type SessionBundle, type SessionFamily,
} from "../src";

let issuer: IssuerKey;
beforeAll(async () => {
  issuer = await generateIssuerKey();
});

async function clientKey() {
  const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey, publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey };
}

const URL_ = "https://api.acme.test/v1/invoices?page=2";
const T0 = 1_800_000_000_000;

async function bound(nowMs = T0): Promise<{ bundle: SessionBundle; key: Awaited<ReturnType<typeof clientKey>> }> {
  const key = await clientKey();
  return { key, bundle: await issueSessionBundle({ issuer, userId: "usr_ada", tenantId: "acme", clientPublicKeyJwk: key.publicKeyJwk, nowMs }) };
}

describe("thumbprint (RFC 7638)", () => {
  it("is SHA-256 over the canonical members, base64url", async () => {
    const jwk = { kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" };
    expect(await computeJwkThumbprint(jwk)).toBe(b64urlEncode(await sha256(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`)));
  });
  it("ignores private members and key order, and refuses non-P-256 keys", async () => {
    const a = await computeJwkThumbprint({ kty: "EC", crv: "P-256", x: "AA", y: "BB" });
    expect(await computeJwkThumbprint({ y: "BB", d: "secret", x: "AA", crv: "P-256", kty: "EC" })).toBe(a);
    await expect(computeJwkThumbprint({ kty: "RSA", n: "x", e: "AQAB" })).rejects.toThrow();
  });
});

describe("issuer keys", () => {
  it("survives serialisation, and a tampered key file is refused", async () => {
    const data = await serializeIssuerKey(issuer);
    const again = await importIssuerKey(data);
    expect(again.kid).toBe(issuer.kid);
    await expect(importIssuerKey({ ...data, kid: "nope" })).rejects.toThrow(/inconsistent/);
  });
});

describe("hardware-bound sessions", () => {
  it("issues a token carrying the key's thumbprint as cnf.jkt", async () => {
    const { bundle, key } = await bound();
    expect(bundle.sessionToken.startsWith(TOKEN_PREFIX.session)).toBe(true);
    expect(bundle.claims).toMatchObject({ sub: "usr_ada", tid: "acme", gen: 1, exp: T0 / 1000 + 900, cnf: { jkt: await computeJwkThumbprint(key.publicKeyJwk) } });
    expect(bundle.family).toMatchObject({ status: "active", currentGeneration: 1, boundJkt: bundle.claims.cnf?.jkt });
    expect(tokenKind(bundle.sessionToken)).toBe("session");
    expect(peekTokenPayload(bundle.sessionToken)).toMatchObject({ sub: "usr_ada" });
  });

  it("accepts a request carrying a proof from the bound key", async () => {
    const { bundle, key } = await bound();
    const proof = await createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: bundle.sessionToken, nowMs: T0 });
    const r = await verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, dpopProof: proof, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0 });
    expect(r).toMatchObject({ ok: true, bound: true });
  });

  it("stops a stolen token used without the private key", async () => {
    const { bundle } = await bound();
    const r = await verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0 });
    expect(r).toMatchObject({ ok: false, reason: "dpop_missing" });
  });

  it("stops a thief who signs a proof with their own key", async () => {
    const { bundle } = await bound();
    const thief = await clientKey();
    const proof = await createDpopProof({ ...thief, method: "GET", url: URL_, sessionToken: bundle.sessionToken, nowMs: T0 });
    const r = await verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, dpopProof: proof, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0 });
    expect(r).toMatchObject({ ok: false, reason: "key_mismatch" });
  });

  it("rejects a proof for another method, URL or token, and one with a stale timestamp", async () => {
    const { bundle, key } = await bound();
    const other = await bound();
    const req = (proof: string, over: Partial<{ method: string; url: string; nowMs: number }> = {}) =>
      verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, dpopProof: proof, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0, ...over });
    const good = await createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: bundle.sessionToken, nowMs: T0 });
    expect(await req(good, { method: "POST" })).toMatchObject({ reason: "htm_mismatch" });
    expect(await req(good, { url: "https://api.acme.test/v1/users" })).toMatchObject({ reason: "htu_mismatch" });
    expect(await req(await createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: other.bundle.sessionToken, nowMs: T0 }))).toMatchObject({ reason: "ath_mismatch" });
    expect(await req(await createDpopProof({ ...key, method: "GET", url: URL_, nowMs: T0 }))).toMatchObject({ reason: "ath_mismatch" });
    expect(await req(good, { nowMs: T0 + 61_000 })).toMatchObject({ reason: "iat_out_of_window" });
    expect(await req(await createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: bundle.sessionToken, nowMs: T0 - 61_000 }))).toMatchObject({ reason: "iat_out_of_window" });
    expect((await req(good, { url: "https://api.acme.test/v1/invoices?page=9#frag" })).ok).toBe(true);
  });

  it("rejects a replayed proof when a cache is supplied", async () => {
    const { bundle, key } = await bound();
    const cache = new DpopReplayCache();
    const proof = await createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: bundle.sessionToken, nowMs: T0, jti: "fixed" });
    const req = (nowMs: number) => verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, dpopProof: proof, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs, replayCache: cache });
    expect((await req(T0)).ok).toBe(true);
    expect(await req(T0 + 1000)).toMatchObject({ ok: false, reason: "replayed" });
  });

  it("rejects an expired, tampered or foreign-signed session token", async () => {
    const { bundle, key } = await bound();
    const proof = (tok: string) => createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: tok, nowMs: T0 + 901_000 });
    expect(await verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, dpopProof: await proof(bundle.sessionToken), method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0 + 901_000 })).toMatchObject({ ok: false, reason: "expired" });
    const [body, sig] = bundle.sessionToken.slice(TOKEN_PREFIX.session.length).split(".");
    const forgedClaims = { ...bundle.claims, sub: "usr_admin", cnf: undefined };
    const forged = `${TOKEN_PREFIX.session}${b64urlEncode(utf8(JSON.stringify(forgedClaims)))}.${sig}`;
    expect(await verifyDpopSessionRequest({ sessionToken: forged, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0 })).toMatchObject({ ok: false, reason: "bad_signature" });
    const foreign = await generateIssuerKey();
    expect(await verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, method: "GET", url: URL_, issuerPublicKeyJwk: foreign.publicKeyJwk, nowMs: T0 })).toMatchObject({ ok: false, reason: "bad_signature" });
    expect(body).toBeTruthy();
    for (const junk of ["", "ath_sess_", "ath_sess_a.b.c", "nope", `${TOKEN_PREFIX.session}!!.??`]) expect(await verifyDpopSessionRequest({ sessionToken: junk, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk })).toMatchObject({ ok: false });
  });

  it("allows unbound sessions unless binding is required", async () => {
    const b = await issueSessionBundle({ issuer, userId: "usr_ada", tenantId: "acme", nowMs: T0 });
    expect(b.claims.cnf).toBeUndefined();
    expect(await verifyDpopSessionRequest({ sessionToken: b.sessionToken, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0 })).toMatchObject({ ok: true, bound: false });
    expect(await verifyDpopSessionRequest({ sessionToken: b.sessionToken, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0, requireBinding: true })).toMatchObject({ ok: false, reason: "not_bound" });
  });

  it("rejects malformed proofs", async () => {
    const proof = async (mut: (h: Record<string, unknown>, c: Record<string, unknown>) => void) => {
      const k = await clientKey();
      const good = await createDpopProof({ ...k, method: "GET", url: URL_, nowMs: T0 });
      const [h, c, s] = good.split(".") as [string, string, string];
      const dec = (x: string) => JSON.parse(atob(x.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
      const hh = dec(h);
      const cc = dec(c);
      mut(hh, cc);
      return `${b64urlEncode(utf8(JSON.stringify(hh)))}.${b64urlEncode(utf8(JSON.stringify(cc)))}.${s}`;
    };
    const v = (p: string) => verifyDpopProof({ proof: p, method: "GET", url: URL_, nowMs: T0 });
    expect(await v(await proof((h) => (h["alg"] = "none")))).toMatchObject({ reason: "malformed" });
    expect(await v(await proof((h) => (h["typ"] = "jwt")))).toMatchObject({ reason: "malformed" });
    expect(await v(await proof((_h, c) => delete c["jti"]))).toMatchObject({ reason: "malformed" });
    expect(await v(await proof((_h, c) => (c["htm"] = "POST")))).toMatchObject({ reason: "bad_signature" });
    expect(await v("ath_dpop_a.b")).toMatchObject({ reason: "malformed" });
    expect(await v("a.b.c.d")).toMatchObject({ reason: "malformed" });
    expect(await v("Bearer x")).toMatchObject({ reason: "malformed" });
  });

  it("emits a standard dpop+jwt, and still accepts the older ath_dpop_ form", async () => {
    const { bundle, key } = await bound();
    const std = await createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: bundle.sessionToken, nowMs: T0 });
    expect(std.startsWith("ath_dpop_")).toBe(false);
    expect(JSON.parse(atob(std.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/")))).toMatchObject({ typ: "dpop+jwt", alg: "ES256" });
    const legacy = await createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: bundle.sessionToken, nowMs: T0, legacyPrefix: true });
    expect(legacy.startsWith("ath_dpop_")).toBe(true);
    for (const proof of [std, legacy]) {
      expect(await verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, dpopProof: proof, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0 })).toMatchObject({ ok: true });
    }
  });

  it("normalises the target URL", () => {
    expect(normalizeHtu("HTTPS://API.Acme.test/v1/x?y=1#z")).toBe("https://api.acme.test/v1/x");
  });
});

describe("refresh-token families", () => {
  async function fresh(): Promise<{ family: SessionFamily; token: string }> {
    const b = await issueSessionBundle({ issuer, userId: "usr_ada", tenantId: "acme", nowMs: T0 });
    return { family: b.family, token: b.refreshToken };
  }

  it("rotates generation 1 -> 2 -> 3 and keeps only hashes", async () => {
    let { family, token } = await fresh();
    expect(JSON.stringify(family)).not.toContain(token);
    for (const gen of [2, 3]) {
      const r = await rotateRefreshTokenFamily(family, token, T0 + gen * 1000);
      expect(r.ok).toBe(true);
      if (!r.ok) return;
      expect(r.generation).toBe(gen);
      expect(r.family.currentGeneration).toBe(gen);
      expect(r.family.consumedRefreshTokenHashes).toHaveLength(gen - 1);
      family = r.family;
      token = r.refreshToken;
    }
    const next = await issueNextAccessToken({ issuer, family, nowMs: T0 });
    expect(next.claims).toMatchObject({ gen: 3, fam: family.familyId });
  });

  it("revokes the whole family the moment a consumed token is replayed", async () => {
    const first = await fresh();
    const r2 = await rotateRefreshTokenFamily(first.family, first.token, T0 + 1000);
    if (!r2.ok) throw new Error("rotation failed");
    const replay = await rotateRefreshTokenFamily(r2.family, first.token, T0 + 2000);
    expect(replay).toMatchObject({ ok: false, reason: "reuse_detected", family: { status: "revoked_reuse_detected" } });
    // The legitimate holder's current token is dead too: that is the point.
    const legit = await rotateRefreshTokenFamily(replay.family, r2.refreshToken, T0 + 3000);
    expect(legit).toMatchObject({ ok: false, reason: "revoked" });
  });

  it("treats a token that was never issued as unknown, without revoking", async () => {
    const { family } = await fresh();
    const r = await rotateRefreshTokenFamily(family, "ath_rt_nope", T0);
    expect(r).toMatchObject({ ok: false, reason: "unknown_token" });
    expect(r.family.status).toBe("active");
  });

  it("expires and can be revoked by hand", async () => {
    const { family, token } = await fresh();
    expect(await rotateRefreshTokenFamily(family, token, T0 + 8 * 86_400_000)).toMatchObject({ ok: false, reason: "expired" });
    const revoked = revokeFamily(family, T0);
    expect(revoked.status).toBe("revoked_manual");
    expect(await rotateRefreshTokenFamily(revoked, token, T0)).toMatchObject({ ok: false, reason: "revoked" });
    expect(revokeFamily(revoked, T0 + 1)).toBe(revoked);
  });

  it("property: after any number of rotations, replaying any consumed token kills the family", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 6 }), fc.nat(), async (rotations, pick) => {
        let { family, token } = await fresh();
        const used: string[] = [];
        for (let i = 0; i < rotations; i++) {
          const r = await rotateRefreshTokenFamily(family, token, T0 + i);
          if (!r.ok) throw new Error("rotation failed");
          used.push(token);
          family = r.family;
          token = r.refreshToken;
        }
        const replayed = used[pick % used.length] as string;
        const r = await rotateRefreshTokenFamily(family, replayed, T0 + 100);
        expect(r).toMatchObject({ ok: false, reason: "reuse_detected" });
        expect(r.family.status).toBe("revoked_reuse_detected");
        expect((await rotateRefreshTokenFamily(r.family, token, T0 + 101)).ok).toBe(false);
      }),
      { numRuns: 25 },
    );
  });
});

describe("signed tokens", () => {
  it("round-trips and detects tampering", async () => {
    const { signToken } = await import("../src");
    const t = await signToken("ath_adm_", { x: 1 }, issuer.privateKey);
    expect(await verifySignedToken("ath_adm_", t, issuer.publicKeyJwk)).toMatchObject({ ok: true, payload: { x: 1 } });
    expect(await verifySignedToken("ath_adm_", t.slice(0, 12) + (t[12] === "A" ? "B" : "A") + t.slice(13), issuer.publicKeyJwk)).toMatchObject({ ok: false });
    expect(await verifySignedToken("ath_sess_", t, issuer.publicKeyJwk)).toMatchObject({ ok: false, reason: "malformed" });
    expect(tokenKind("atk_live_x")).toBe("apiKey");
    expect(tokenKind("zzz")).toBeNull();
  });
});
