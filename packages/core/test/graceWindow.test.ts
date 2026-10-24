import { describe, expect, it } from "vitest";
import { generateIssuerKey, issueSessionBundle, rotateRefreshTokenFamily } from "../src";

const T0 = Date.UTC(2030, 0, 1);
const start = async () => issueSessionBundle({ issuer: await generateIssuerKey(), userId: "u", tenantId: "t", nowMs: T0 });

describe("refresh reuse grace window (opt-in)", () => {
  it("is off by default: any reuse revokes the family", async () => {
    const b = await start();
    const r1 = await rotateRefreshTokenFamily(b.family, b.refreshToken, T0 + 1000);
    if (!r1.ok) throw new Error("rotation failed");
    expect(await rotateRefreshTokenFamily(r1.family, b.refreshToken, T0 + 1001)).toMatchObject({ ok: false, reason: "reuse_detected" });
    expect(await rotateRefreshTokenFamily(r1.family, b.refreshToken, T0 + 1001, { reuseGraceMs: 0 })).toMatchObject({ ok: false, reason: "reuse_detected" });
  });

  it("answers the most recently spent token, inside the window, with a fresh pair and no revocation", async () => {
    const b = await start();
    const r1 = await rotateRefreshTokenFamily(b.family, b.refreshToken, T0 + 1000);
    if (!r1.ok) throw new Error("rotation failed");
    const retry = await rotateRefreshTokenFamily(r1.family, b.refreshToken, T0 + 3000, { reuseGraceMs: 5000 });
    expect(retry).toMatchObject({ ok: true, graceUsed: true, generation: 3, family: { status: "active", currentGeneration: 3 } });
    if (!retry.ok) throw new Error("unreachable");
    expect(retry.refreshToken).not.toBe(r1.refreshToken);
    // the token from the first answer is now spent, and is itself the most recent: usable once more inside the window
    expect(await rotateRefreshTokenFamily(retry.family, r1.refreshToken, T0 + 3500, { reuseGraceMs: 5000 })).toMatchObject({ ok: true, graceUsed: true });
    // the current token still rotates normally, with no grace flag
    const normal = await rotateRefreshTokenFamily(retry.family, retry.refreshToken, T0 + 4000, { reuseGraceMs: 5000 });
    expect(normal.ok && normal.graceUsed).toBeFalsy();
  });

  it("still revokes when the window has passed", async () => {
    const b = await start();
    const r1 = await rotateRefreshTokenFamily(b.family, b.refreshToken, T0 + 1000);
    if (!r1.ok) throw new Error("rotation failed");
    expect(await rotateRefreshTokenFamily(r1.family, b.refreshToken, T0 + 1000 + 5001, { reuseGraceMs: 5000 })).toMatchObject({ ok: false, reason: "reuse_detected", family: { status: "revoked_reuse_detected" } });
  });

  it("still revokes for a token older than the most recent one, even inside the window", async () => {
    const b = await start();
    const r1 = await rotateRefreshTokenFamily(b.family, b.refreshToken, T0 + 1000);
    if (!r1.ok) throw new Error("rotation failed");
    const r2 = await rotateRefreshTokenFamily(r1.family, r1.refreshToken, T0 + 1500, { reuseGraceMs: 5000 });
    if (!r2.ok) throw new Error("rotation failed");
    // b.refreshToken is two rotations old
    expect(await rotateRefreshTokenFamily(r2.family, b.refreshToken, T0 + 1600, { reuseGraceMs: 5000 })).toMatchObject({ ok: false, reason: "reuse_detected" });
  });

  it("does nothing for an unknown token or a revoked family", async () => {
    const b = await start();
    expect(await rotateRefreshTokenFamily(b.family, "ath_rt_nonsense", T0 + 1, { reuseGraceMs: 5000 })).toMatchObject({ ok: false, reason: "unknown_token" });
    const revoked = { ...b.family, status: "revoked_manual" as const };
    expect(await rotateRefreshTokenFamily(revoked, b.refreshToken, T0 + 1, { reuseGraceMs: 5000 })).toMatchObject({ ok: false, reason: "revoked" });
  });
});
