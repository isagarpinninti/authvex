import { describe, expect, it } from "vitest";
import { b64urlEncode, generateIssuerKey, halfHash, isValidCodeChallenge, isValidCodeVerifier, issueSessionBundle, issueNextAccessToken, pkceChallenge, rotateRefreshTokenFamily, signJwt, utf8, verifyJwt, verifyPkce } from "../src";

describe("PKCE (RFC 7636)", () => {
  it("matches the RFC 7636 Appendix B vector", async () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    expect(await pkceChallenge(verifier)).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    expect(await verifyPkce(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")).toBe(true);
  });
  it("refuses a wrong verifier, a malformed one and a malformed challenge", async () => {
    const c = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(await verifyPkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXx", c)).toBe(false);
    expect(await verifyPkce("short", c)).toBe(false);
    expect(await verifyPkce("a".repeat(129), c)).toBe(false);
    expect(await verifyPkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "plain-text-challenge")).toBe(false);
    expect(isValidCodeVerifier("has spaces in it which are not allowed 12345678901234567")).toBe(false);
    expect(isValidCodeChallenge(c)).toBe(true);
    expect(isValidCodeChallenge(`${c}=`)).toBe(false);
  });
});

describe("JWT (ES256)", () => {
  it("signs and verifies, and the claims checks work", async () => {
    const k = await generateIssuerKey();
    const now = 1_800_000_000;
    const t = await signJwt({ iss: "https://id.test/oidc/t", sub: "usr_a", aud: "cl_1", iat: now, exp: now + 300, nonce: "n-123" }, k);
    const keys = { keys: [{ ...k.publicKeyJwk, kid: k.kid }] };
    const ok = await verifyJwt(t, keys, { issuer: "https://id.test/oidc/t", audience: "cl_1", nonce: "n-123", nowMs: now * 1000 });
    expect(ok).toMatchObject({ ok: true, header: { alg: "ES256", typ: "JWT", kid: k.kid }, claims: { sub: "usr_a" } });
    expect(await verifyJwt(t, keys, { issuer: "https://evil.test", nowMs: now * 1000 })).toMatchObject({ ok: false, reason: "wrong_issuer" });
    expect(await verifyJwt(t, keys, { audience: "cl_2", nowMs: now * 1000 })).toMatchObject({ ok: false, reason: "wrong_audience" });
    expect(await verifyJwt(t, keys, { nonce: "other", nowMs: now * 1000 })).toMatchObject({ ok: false, reason: "wrong_nonce" });
    expect(await verifyJwt(t, keys, { nowMs: (now + 400) * 1000 })).toMatchObject({ ok: false, reason: "expired" });
    expect(await verifyJwt(t, keys, { nowMs: (now + 350) * 1000, clockSkewSeconds: 60 })).toMatchObject({ ok: true }); // inside the 60 s allowance
    expect(await verifyJwt(t, keys, { nowMs: (now + 200) * 1000 })).toMatchObject({ ok: true });
  });
  it("refuses alg none, other algorithms, an unknown kid, a foreign key, tampering and junk", async () => {
    const k = await generateIssuerKey();
    const other = await generateIssuerKey();
    const now = Date.now();
    const t = await signJwt({ sub: "a", exp: Math.floor(now / 1000) + 300 }, k);
    const [h, p, s] = t.split(".") as [string, string, string];
    const none = `${b64urlEncode(utf8(JSON.stringify({ alg: "none", typ: "JWT" })))}.${p}.`;
    const hs = `${b64urlEncode(utf8(JSON.stringify({ alg: "HS256", typ: "JWT" })))}.${p}.${s}`;
    expect(await verifyJwt(none, k.publicKeyJwk)).toMatchObject({ ok: false });
    expect(await verifyJwt(hs, k.publicKeyJwk)).toMatchObject({ ok: false, reason: "unsupported_alg" });
    expect(await verifyJwt(t, { keys: [{ ...other.publicKeyJwk, kid: other.kid }] })).toMatchObject({ ok: false, reason: "unknown_key" });
    expect(await verifyJwt(t, other.publicKeyJwk)).toMatchObject({ ok: false, reason: "bad_signature" });
    const forgedClaims = b64urlEncode(utf8(JSON.stringify({ sub: "admin", exp: Math.floor(now / 1000) + 300 })));
    expect(await verifyJwt(`${h}.${forgedClaims}.${s}`, k.publicKeyJwk)).toMatchObject({ ok: false, reason: "bad_signature" });
    for (const junk of ["", "a.b", "a.b.c", "....", "x.y.z.w"]) expect(await verifyJwt(junk, k.publicKeyJwk)).toMatchObject({ ok: false });
    expect(await verifyJwt(await signJwt({ sub: "a" }, k), k.publicKeyJwk)).toMatchObject({ ok: false, reason: "malformed" });
  });
  it("computes at_hash as the left half of SHA-256 (OIDC Core appendix A.3 style)", async () => {
    const h = await halfHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");
    expect(h).toBe("77QmUPtjPfzWtF2AnpK9RQ");
  });
});

describe("sessions issued to a client", () => {
  it("carry the client and scopes in the family and the access token, through rotation", async () => {
    const issuer = await generateIssuerKey();
    const b = await issueSessionBundle({ issuer, userId: "usr_a", tenantId: "t", client: { clientId: "cl_web", scope: "openid email" }, nowMs: 1_800_000_000_000 });
    expect(b.family).toMatchObject({ clientId: "cl_web", scope: "openid email" });
    expect(b.claims).toMatchObject({ cid: "cl_web", scp: "openid email" });
    const r = await rotateRefreshTokenFamily(b.family, b.refreshToken, 1_800_000_001_000);
    if (!r.ok) throw new Error("rotation failed");
    expect((await issueNextAccessToken({ issuer, family: r.family, nowMs: 1_800_000_001_000 })).claims).toMatchObject({ cid: "cl_web", scp: "openid email", gen: 2 });
    expect((await issueSessionBundle({ issuer, userId: "u", tenantId: "t" })).claims.cid).toBeUndefined();
  });
});
