// Micro-benchmarks for the cryptographic hot paths, on Web Crypto. Budgets are generous: they catch a 10x regression, not noise.
// Set AUTHVEX_PERF_SCALE to loosen them on a slow machine (for example 5).
import { performance } from "node:perf_hooks";
import {
  DpopReplayCache, computeTotpCode, createDpopProof, createSoftwareAuthenticator, generateChallenge, generateIssuerKey, generateTotpSecret, hashPassword, issueSessionBundle, rotateRefreshTokenFamily,
  evaluateAuthRiskGate, MemoryStore, TenantPolicySchema, verifyDpopSessionRequest, verifyPassword, verifyTotpCode, verifyWebAuthnAssertion,
} from "../packages/core/dist/index.js";
import { SqliteStore, sqliteAvailable } from "../packages/cli/dist/index.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCALE = Number(process.env.AUTHVEX_PERF_SCALE ?? 1);
let failed = false;
const rate = async (name, n, fn, minPerSec) => {
  for (let i = 0; i < Math.min(20, n); i++) await fn(i);
  const t0 = performance.now();
  for (let i = 0; i < n; i++) await fn(i);
  const ms = performance.now() - t0;
  const perSec = n / (ms / 1000);
  const min = minPerSec === undefined ? undefined : minPerSec / SCALE;
  const ok = min === undefined || perSec >= min;
  if (!ok) failed = true;
  console.log(`${ok ? "ok  " : "FAIL"} ${name.padEnd(42)} ${perSec.toFixed(0).padStart(9)} /s  ${(ms / n).toFixed(3).padStart(8)} ms each${min !== undefined ? `  (budget >= ${min.toFixed(0)}/s)` : ""}`);
};

const issuer = await generateIssuerKey();
const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
const key = { privateKey: pair.privateKey, publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
const url = "https://api.example.com/v1/invoices";

const bundle = await issueSessionBundle({ issuer, userId: "usr_a", tenantId: "t", clientPublicKeyJwk: key.publicKeyJwk });
const proofs = await Promise.all(Array.from({ length: 1200 }, () => createDpopProof({ ...key, method: "GET", url, sessionToken: bundle.sessionToken })));
await rate("DPoP proof: sign", 1000, () => createDpopProof({ ...key, method: "GET", url, sessionToken: bundle.sessionToken }), 400);
await rate("DPoP session request: verify (token + proof)", 1000, (i) => verifyDpopSessionRequest({ sessionToken: bundle.sessionToken, dpopProof: proofs[i % proofs.length], method: "GET", url, issuerPublicKeyJwk: issuer.publicKeyJwk, replayCache: new DpopReplayCache() }), 300);
await rate("session bundle: issue (sign)", 600, () => issueSessionBundle({ issuer, userId: "usr_a", tenantId: "t", clientPublicKeyJwk: key.publicKeyJwk }), 300);

let fam = bundle.family;
let tok = bundle.refreshToken;
await rate("refresh-family rotation", 5000, async () => {
  const r = await rotateRefreshTokenFamily(fam, tok);
  if (!r.ok) throw new Error("rotation failed");
  fam = { ...r.family, consumedRefreshTokenHashes: [] };
  tok = r.refreshToken;
}, 3000);

const auth = await createSoftwareAuthenticator({ rpId: "app.example.com", origin: "https://app.example.com" });
const reg = await auth.register("c");
void reg;
const cred = { publicKeyJwk: auth.publicKeyJwk, signCount: 0 };
const asserts = [];
for (let i = 0; i < 400; i++) {
  const c = generateChallenge();
  asserts.push({ c, r: await auth.assert(c, { signCount: i + 1 }) });
}
await rate("WebAuthn assertion: verify", 400, (i) => verifyWebAuthnAssertion({ expected: { challenge: asserts[i % 400].c, origin: "https://app.example.com", rpId: "app.example.com" }, response: asserts[i % 400].r, credential: { ...cred, signCount: i % 400 } }), 200);

const secret = generateTotpSecret();
await rate("TOTP: compute", 3000, () => computeTotpCode(secret), 2000);
const code = await computeTotpCode(secret);
await rate("TOTP: verify (3-step window)", 2000, () => verifyTotpCode(secret, code), 1000);

const policy = TenantPolicySchema.parse({ id: "t", name: "T", domain: "t.test", roles: [{ id: "a", name: "A", permissions: ["x:y"] }] });
const ctx = { email: "a@b.test", nowMs: Date.now(), primaryFactorVerified: true, secondFactorVerified: true, isAdmin: false, failedAttemptsInWindow: 0, dpop: { presented: true, valid: true, keyMatchesSession: true } };
await rate("threat gate: evaluate AV-101..108", 200_000, () => evaluateAuthRiskGate(ctx, policy), 100_000);

// State stores: the operations every request touches.
{
  const mem = new MemoryStore();
  await rate("store (memory): claim a proof id", 50_000, (i) => mem.claimJti(`j${i}`, 0, 60_000), 50_000);
  if (await sqliteAvailable()) {
    const dir = mkdtempSync(join(tmpdir(), "authvex-bench-"));
    const db = await SqliteStore.open(join(dir, "s.db"));
    await rate("store (sqlite): claim a proof id", 3000, (i) => db.claimJti(`j${i}`, 0, 60_000), 1500);
    const fam = { familyId: "fam_b", userId: "u", tenantId: "t", currentGeneration: 1, activeRefreshTokenHash: "h0", consumedRefreshTokenHashes: [], status: "active", createdAtIso: "x", lastRotatedAtIso: "x", expiresAtIso: "y" };
    await db.createFamily(fam);
    let cur = fam;
    await rate("store (sqlite): compare-and-set a family", 2000, async (i) => {
      const next = { ...cur, currentGeneration: i + 2, activeRefreshTokenHash: `h${i + 1}`, consumedRefreshTokenHashes: [...cur.consumedRefreshTokenHashes.slice(-5), cur.activeRefreshTokenHash] };
      if (!(await db.compareAndSetFamily(cur, next))) throw new Error("cas failed");
      cur = next;
    }, 1000);
    await db.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

// Password hashing is deliberately slow: report it, and require it to stay in the range that resists guessing without hurting sign-in.
const h = await hashPassword("benchmark-password");
const t0 = performance.now();
for (let i = 0; i < 5; i++) await verifyPassword("benchmark-password", h);
const per = (performance.now() - t0) / 5;
const okPw = per >= 5 && per <= 1500 * SCALE;
if (!okPw) failed = true;
console.log(`${okPw ? "ok  " : "FAIL"} ${"password verify (PBKDF2, 210k iterations)".padEnd(42)} ${per.toFixed(0).padStart(9)} ms each  (expected 5 to ${1500 * SCALE} ms: slow on purpose)`);
process.exit(failed ? 1 : 0);
