import { describe, expect, it } from "vitest";
import {
  MemoryStore, activeIssuerKey, createKeyring, describeKeyring, generateKeyringEntry, issueSessionBundle, keyringFromLegacy, mintImpersonationSeal, pruneKeyring, revokeKey, rotateKeyring,
  rotateRefreshTokenFamily, serializeIssuerKey, signToken, storeReplayCache, validateKeyring, verifyDpopSessionRequest, verifyImpersonationSeal, verifySignedToken, verifiableKeys, generateIssuerKey, createDpopProof, TOKEN_PREFIX,
  type SessionFamily,
} from "../src";

const T0 = 1_800_000_000_000;
const URL_ = "https://api.acme.test/v1/x";

async function clientKey() {
  const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey, publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey };
}

describe("keyring lifecycle", () => {
  it("starts with one active key and publishes it as a JWKS", async () => {
    const kr = await createKeyring(undefined, T0);
    const jwks = verifiableKeys(kr, T0);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig", kid: kr.keys[0]?.kid });
    expect(JSON.stringify(jwks)).not.toContain('"d"');
    expect(validateKeyring(kr)).toBe(kr);
  });

  it("rotates: the new key signs, the old one verifies for the overlap, and its private half is dropped", async () => {
    const kr1 = await createKeyring(undefined, T0);
    const next = await generateKeyringEntry(T0);
    const kr2 = rotateKeyring(kr1, next, T0 + 1000, 3600);
    expect(kr2.keys.map((k) => k.status)).toEqual(["retiring", "active"]);
    expect(kr2.keys[0]?.privateKeyJwk).toBeUndefined();
    expect(kr2.keys[1]?.privateKeyJwk).toBeDefined();
    expect(verifiableKeys(kr2, T0 + 2000).keys.map((k) => k.kid)).toEqual([kr1.keys[0]?.kid, next.kid]);
    expect(verifiableKeys(kr2, T0 + 1000 + 3_600_000).keys.map((k) => k.kid)).toEqual([next.kid]);
    expect(describeKeyring(kr2, T0 + 1000 + 3_600_000).map((d) => d.status)).toEqual(["retiring-expired", "active"]);
  });

  it("keeps sessions signed by the old key valid through the overlap and refuses them after", async () => {
    const kr1 = await createKeyring(undefined, T0);
    const oldKey = await activeIssuerKey(kr1);
    const bundle = await issueSessionBundle({ issuer: oldKey, userId: "usr_a", tenantId: "t", nowMs: T0 });
    const kr2 = rotateKeyring(kr1, await generateKeyringEntry(T0), T0 + 1000, 3600);
    const check = (nowMs: number) => verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, method: "GET", url: URL_, issuerPublicKeyJwk: verifiableKeys(kr2, nowMs), nowMs });
    expect((await check(T0 + 5000)).ok).toBe(true);
    expect(await check(T0 + 3_700_000)).toMatchObject({ ok: false, reason: "unknown_key" });
    // New tokens come from the new key and carry its kid.
    const fresh = await issueSessionBundle({ issuer: await activeIssuerKey(kr2), userId: "usr_a", tenantId: "t", nowMs: T0 });
    expect(JSON.parse(atob(fresh.sessionToken.slice(TOKEN_PREFIX.session.length).split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/")))).toMatchObject({ kid: kr2.keys[1]?.kid });
  });

  it("revoking a retiring key refuses its tokens at once; the active key cannot be revoked", async () => {
    const kr1 = await createKeyring(undefined, T0);
    const old = kr1.keys[0]!.kid;
    const oldIssuer = await activeIssuerKey(kr1);
    const seal = await mintImpersonationSeal({ issuer: oldIssuer, actor: { id: "usr_root", email: "r@x.test" }, target: { id: "usr_a", email: "a@x.test" }, tenantId: "t", reason: "TICKET-1 testing revoke", nowMs: T0 });
    const kr2 = rotateKeyring(kr1, await generateKeyringEntry(T0), T0, 86_400);
    expect((await verifyImpersonationSeal(seal.token, verifiableKeys(kr2, T0 + 1000), T0 + 1000)).ok).toBe(true);
    const kr3 = revokeKey(kr2, old, T0 + 2000);
    expect(await verifyImpersonationSeal(seal.token, verifiableKeys(kr3, T0 + 2000), T0 + 2000)).toMatchObject({ ok: false, reason: "unknown_key" });
    expect(kr3.keys[0]).toMatchObject({ status: "retired", retiredReason: "revoked" });
    expect(() => revokeKey(kr3, kr3.keys[1]!.kid)).toThrow(/active key/);
    expect(() => revokeKey(kr3, "nope")).toThrow(/no key/);
  });

  it("prunes: retiring keys past their overlap retire, old retired keys are removed", async () => {
    let kr = await createKeyring(undefined, T0);
    kr = rotateKeyring(kr, await generateKeyringEntry(T0), T0, 100);
    const early = pruneKeyring(kr, T0 + 50_000);
    expect(early.expired).toEqual([]);
    const later = pruneKeyring(kr, T0 + 200_000);
    expect(later.expired).toHaveLength(1);
    expect(later.keyring.keys.map((k) => k.status)).toEqual(["retired", "active"]);
    const gone = pruneKeyring(later.keyring, T0 + 200_000 + 86_400_000);
    expect(gone.removed).toHaveLength(1);
    expect(gone.keyring.keys).toHaveLength(1);
  });

  it("refuses an invalid keyring, a duplicate kid and a negative overlap, and wraps a legacy key", async () => {
    expect(() => validateKeyring({ version: 1, keys: [] })).toThrow(/version 2/);
    const kr = await createKeyring(undefined, T0);
    expect(() => validateKeyring({ ...kr, keys: [] })).toThrow(/exactly one active/);
    expect(() => rotateKeyring(kr, kr.keys[0]!)).toThrow(/already/);
    expect(() => rotateKeyring(kr, { ...(kr.keys[0] as object), kid: "x" } as never, T0, -1)).toThrow(/overlap/);
    const legacy = await serializeIssuerKey(await generateIssuerKey());
    expect(validateKeyring(keyringFromLegacy(legacy, T0)).keys[0]?.kid).toBe(legacy.kid);
  });
});

describe("verifying with a key set", () => {
  it("picks the key by kid, refuses an unknown kid, and tries every key for a token with no kid", async () => {
    const a = await generateIssuerKey();
    const b = await generateIssuerKey();
    const set = { keys: [{ ...a.publicKeyJwk, kid: a.kid }, { ...b.publicKeyJwk, kid: b.kid }] };
    const withKid = await signToken("ath_adm_", { x: 1 }, b.privateKey, b.kid);
    const noKid = await signToken("ath_adm_", { x: 2 }, a.privateKey);
    expect(await verifySignedToken("ath_adm_", withKid, set)).toMatchObject({ ok: true, payload: { x: 1, kid: b.kid } });
    expect(await verifySignedToken("ath_adm_", noKid, set)).toMatchObject({ ok: true, payload: { x: 2 } });
    expect(await verifySignedToken("ath_adm_", withKid, { keys: [{ ...a.publicKeyJwk, kid: a.kid }] })).toMatchObject({ ok: false, reason: "unknown_key" });
    expect(await verifySignedToken("ath_adm_", withKid, { keys: [{ ...a.publicKeyJwk, kid: b.kid }] })).toMatchObject({ ok: false, reason: "bad_signature" });
    expect(await verifySignedToken("ath_adm_", withKid, b.publicKeyJwk)).toMatchObject({ ok: true });
    expect(await verifySignedToken("ath_adm_", noKid, { keys: [{ ...b.publicKeyJwk, kid: b.kid }] })).toMatchObject({ ok: false, reason: "bad_signature" });
  });
  it("cannot be tricked by editing the kid", async () => {
    const a = await generateIssuerKey();
    const b = await generateIssuerKey();
    const t = await signToken("ath_adm_", { x: 1 }, a.privateKey, a.kid);
    const [body, sig] = t.slice("ath_adm_".length).split(".") as [string, string];
    const forged = { ...(JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/"))) as object), kid: b.kid };
    const tok = `ath_adm_${btoa(JSON.stringify(forged)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}.${sig}`;
    expect(await verifySignedToken("ath_adm_", tok, { keys: [{ ...a.publicKeyJwk, kid: a.kid }, { ...b.publicKeyJwk, kid: b.kid }] })).toMatchObject({ ok: false, reason: "bad_signature" });
  });
});

describe("MemoryStore", () => {
  async function family(): Promise<SessionFamily> {
    const issuer = await generateIssuerKey();
    return (await issueSessionBundle({ issuer, userId: "usr_a", tenantId: "t", nowMs: T0 })).family;
  }

  it("stores families and finds them by refresh token hash", async () => {
    const s = new MemoryStore();
    const f = await family();
    await s.createFamily(f);
    expect(await s.getFamily(f.familyId)).toEqual(f);
    expect(await s.familyIdForToken(f.activeRefreshTokenHash)).toBe(f.familyId);
    expect(await s.familyIdForToken("nope")).toBeUndefined();
    expect(await s.listFamilies()).toHaveLength(1);
  });

  it("compare-and-set lets exactly one of several concurrent rotations win", async () => {
    const issuer = await generateIssuerKey();
    const b = await issueSessionBundle({ issuer, userId: "usr_a", tenantId: "t", nowMs: T0 });
    const s = new MemoryStore();
    await s.createFamily(b.family);
    const attempts = await Promise.all(Array.from({ length: 20 }, async () => {
      const r = await rotateRefreshTokenFamily(b.family, b.refreshToken, T0 + 1);
      return r.ok ? s.compareAndSetFamily(b.family, r.family) : false;
    }));
    expect(attempts.filter(Boolean)).toHaveLength(1);
    expect((await s.getFamily(b.family.familyId))?.currentGeneration).toBe(2);
  });

  it("refuses a stale write after a revoke", async () => {
    const s = new MemoryStore();
    const f = await family();
    await s.createFamily(f);
    expect(await s.compareAndSetFamily(f, { ...f, status: "revoked_manual" })).toBe(true);
    expect(await s.compareAndSetFamily(f, { ...f, currentGeneration: 2 })).toBe(false);
  });

  it("claims a proof id once per window, and again after it expires", async () => {
    const s = new MemoryStore();
    const cache = storeReplayCache(s, 1000);
    expect(await cache.claim("a", 0)).toBe(true);
    expect(await cache.claim("a", 500)).toBe(false);
    expect(await cache.claim("a", 1000)).toBe(true);
    expect(await cache.claim("b", 0)).toBe(true);
  });

  it("works as the replay cache of a real DPoP check", async () => {
    const issuer = await generateIssuerKey();
    const key = await clientKey();
    const b = await issueSessionBundle({ issuer, userId: "usr_a", tenantId: "t", clientPublicKeyJwk: key.publicKeyJwk, nowMs: T0 });
    const proof = await createDpopProof({ ...key, method: "GET", url: URL_, sessionToken: b.sessionToken, nowMs: T0, jti: "same" });
    const store = new MemoryStore();
    const req = () => verifyDpopSessionRequest({ sessionToken: b.sessionToken, dpopProof: proof, method: "GET", url: URL_, issuerPublicKeyJwk: issuer.publicKeyJwk, nowMs: T0, replayCache: storeReplayCache(store) });
    expect((await req()).ok).toBe(true);
    expect(await req()).toMatchObject({ ok: false, reason: "replayed" });
  });

  it("counts failures in a sliding window and forgets old ones", async () => {
    const s = new MemoryStore();
    for (const t of [0, 100, 200]) await s.recordFailure("k", t, 1000);
    expect(await s.countFailures("k", 300, 1000)).toBe(3);
    expect(await s.countFailures("k", 1150, 1000)).toBe(1);
    expect(await s.countFailures("k", 5000, 1000)).toBe(0);
    expect(await s.countFailures("other", 0, 1000)).toBe(0);
  });

  it("takes a challenge once, and not after it expires", async () => {
    const s = new MemoryStore();
    await s.putChallenge("c1", { challenge: "x", purpose: "login", userId: "u", expires: 1000 });
    await s.putChallenge("c2", { challenge: "y", purpose: "login", userId: "u", expires: 1000 });
    expect((await s.takeChallenge("c1", 500))?.challenge).toBe("x");
    expect(await s.takeChallenge("c1", 500)).toBeUndefined();
    expect(await s.takeChallenge("c2", 2000)).toBeUndefined();
  });

  it("accepts a TOTP counter only when it advances", async () => {
    const s = new MemoryStore();
    expect(await s.advanceTotpCounter("u", 10)).toBe(true);
    expect(await s.advanceTotpCounter("u", 10)).toBe(false);
    expect(await s.advanceTotpCounter("u", 9)).toBe(false);
    expect(await s.advanceTotpCounter("u", 11)).toBe(true);
    expect(await s.getTotpCounter("u")).toBe(11);
  });

  it("sweeps what has expired", async () => {
    const s = new MemoryStore();
    await s.claimJti("old", 0, 1000);
    await s.putChallenge("c", { challenge: "x", purpose: "login", userId: "u", expires: 10 });
    await s.sweep(5000);
    expect(await s.claimJti("old", 5000, 1000)).toBe(true);
    expect(await s.takeChallenge("c", 0)).toBeUndefined();
    expect(s.snapshot().version).toBe(1);
  });
});

describe("one-time tokens in MemoryStore", () => {
  it("are consumed on first take, only for their purpose, and not after they expire", async () => {
    const s = new MemoryStore();
    const t = { purpose: "reset", userId: "u", tenantId: "t", expires: 1000, data: { email: "a@b.test" } };
    await s.putOneTimeToken("h1", t);
    expect(await s.takeOneTimeToken("h1", "reset", 500)).toEqual(t);
    expect(await s.takeOneTimeToken("h1", "reset", 500)).toBeUndefined();
    await s.putOneTimeToken("h2", t);
    expect(await s.takeOneTimeToken("h2", "magic", 500)).toBeUndefined();
    expect(await s.takeOneTimeToken("h2", "reset", 500)).toBeUndefined();
    await s.putOneTimeToken("h3", t);
    expect(await s.takeOneTimeToken("h3", "reset", 2000)).toBeUndefined();
    await s.putOneTimeToken("h4", { ...t, expires: 10 });
    await s.sweep(5000);
    expect(s.snapshot().oneTime).toEqual([]);
  });
});
