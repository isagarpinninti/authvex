import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { afterAll, beforeAll, describe, it } from "vitest";
import { createDpopProof } from "@authvex/core";
import { DEMO, deviceKey, startHarness, type DeviceKey, type Harness } from "./helpers";
import { runInit_, sqliteAvailable } from "./testExports";

/**
 * Model-based test of the whole session machine. A random script of logins, rotations, replays of spent tokens, revocations, clock
 * jumps, process restarts and issuer-key rotations is run against the real server over HTTP, while a small independent model
 * predicts every answer. Any disagreement fails, and fast-check shrinks the script to the shortest one that still does.
 *
 * The properties it protects:
 *  - a revoked family never authenticates again, by access token or by refresh token, whatever happens afterwards (restart, key rotation);
 *  - replaying a spent refresh token revokes the family, except where a bound family stops the thief at the DPoP check first;
 *  - an access token verifies exactly when: its family is active, it has not expired, its signing key is still trusted, and (if bound)
 *    the proof comes from the session's own key;
 *  - none of the above changes across a restart;
 *  - the ledger agrees with what happened.
 */

const T0 = Date.parse("2026-11-01T00:00:00Z");
const ACME = "acme_fintech_prod";
const LIN = "linear_ops_workspace";
const REFRESH_TTL_MS = 604_800_000;

type Action =
  | { t: "login"; bound: boolean }
  | { t: "rotate"; s: number }
  | { t: "replay"; s: number; pick: number; withKey: boolean }
  | { t: "revoke"; s: number }
  | { t: "verify"; s: number; a: number; proof: "owner" | "none" | "thief" }
  | { t: "advance"; secs: number }
  | { t: "restart" }
  | { t: "rotateIssuer"; overlap: number }
  | { t: "revokeRetiring" };

const actions: fc.Arbitrary<Action> = fc.oneof(
  { weight: 3, arbitrary: fc.record({ t: fc.constant("login" as const), bound: fc.boolean() }) },
  { weight: 5, arbitrary: fc.record({ t: fc.constant("rotate" as const), s: fc.nat(5) }) },
  { weight: 4, arbitrary: fc.record({ t: fc.constant("replay" as const), s: fc.nat(5), pick: fc.nat(9), withKey: fc.boolean() }) },
  { weight: 1, arbitrary: fc.record({ t: fc.constant("revoke" as const), s: fc.nat(5) }) },
  { weight: 6, arbitrary: fc.record({ t: fc.constant("verify" as const), s: fc.nat(5), a: fc.nat(20), proof: fc.constantFrom("owner" as const, "none" as const, "thief" as const) }) },
  { weight: 3, arbitrary: fc.record({ t: fc.constant("advance" as const), secs: fc.constantFrom(30, 600, 1000, 4000, 100_000, 800_000) }) },
  { weight: 1, arbitrary: fc.constant({ t: "restart" as const }) },
  { weight: 1, arbitrary: fc.record({ t: fc.constant("rotateIssuer" as const), overlap: fc.constantFrom(0, 3600, 90_000) }) },
  { weight: 1, arbitrary: fc.constant({ t: "revokeRetiring" as const }) },
);

interface ModelSession {
  bound: boolean;
  key?: DeviceKey;
  famId: string;
  gen: number;
  refresh: string;
  spent: string[];
  /** Revoked by reuse, by hand, or found expired. */
  dead: boolean;
  expiresAt: number;
  access: Array<{ token: string; exp: number; kid: string }>;
}

const kidOf = (token: string): string => (JSON.parse(Buffer.from(token.split(".")[0]!.replace(/^ath_[a-z]+_/, ""), "base64url").toString()) as { kid: string }).kid;

let template: string;
beforeAll(async () => {
  template = mkdtempSync(join(tmpdir(), "authvex-template-"));
  await runInit_(template);
});
afterAll(() => rmSync(template, { recursive: true, force: true }));

async function runScript(storeKind: "file" | "sqlite" | "postgres", initialBound: boolean, script: Action[]): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "authvex-inv-"));
  cpSync(template, dir, { recursive: true });
  let clock = T0;
  const h: Harness = await startHarness({ store: { kind: storeKind } }, { dir, now: () => clock });
  try {
    const sessions: ModelSession[] = [];
    const keys = new Map<string, { state: "active" } | { until: number } | { revoked: true }>();
    keys.set((await h.keyring.get(clock)).issuer.kid, { state: "active" });
    let activeKid = [...keys.keys()][0] as string;
    let reuseDetections = 0;
    let rotations = 0;

    const keyTrusted = (kid: string): boolean => {
      const k = keys.get(kid);
      if (!k) return false;
      if ("state" in k) return true;
      if ("until" in k) return clock < k.until;
      return false;
    };
    const pick = <T>(list: T[], n: number): T | undefined => (list.length === 0 ? undefined : list[n % list.length]);
    const check = (cond: boolean, msg: string): void => {
      if (!cond) throw new Error(msg);
    };
    const hdr = async (s: ModelSession, withKey: boolean): Promise<{ dpop: DeviceKey } | Record<string, never>> => (s.bound && withKey && s.key ? { dpop: s.key } : {});

    const verifyToken = async (s: ModelSession, a: number, proof: "owner" | "none" | "thief"): Promise<void> => {
      const tok = pick(s.access, a);
      if (!tok) return;
      const url = `${h.base}/v1/x`;
      let dpopProof: string | undefined;
      if (s.bound && proof !== "none") dpopProof = await createDpopProof({ ...(proof === "owner" ? (s.key as DeviceKey) : await deviceKey()), method: "GET", url, sessionToken: tok.token, nowMs: clock });
      const r = await h.call("POST", "/api/auth/dpop-verify", { sessionToken: tok.token, method: "GET", url, ...(dpopProof ? { dpopProof } : {}) });
      const fresh = clock < tok.exp;
      const trusted = keyTrusted(tok.kid);
      const proofOk = !s.bound || proof === "owner";
      const expected = !s.dead && fresh && trusted && proofOk;
      check(r.body.valid === expected, `verify: expected valid=${expected} but got ${String(r.body.valid)} (${r.body.reason}); dead=${s.dead} fresh=${fresh} keyTrusted=${trusted} proofOk=${proofOk} bound=${s.bound}`);
      if (!expected && fresh && trusted && proofOk) check(r.body.reason === "session_revoked", `verify: a dead family must say session_revoked, said ${r.body.reason}`);
      if (!expected && fresh && !trusted) check(r.body.reason === "unknown_key", `verify: an untrusted key must say unknown_key, said ${r.body.reason}`);
    };

    for (const [i, a] of [{ t: "login", bound: initialBound } as Action, ...script].entries()) {
      const where = `step ${i} ${JSON.stringify(a)}`;
      try {
        switch (a.t) {
          case "login": {
            if (sessions.length >= 3) break;
            const key = a.bound ? await deviceKey() : undefined;
            const tenantId = a.bound ? ACME : LIN;
            const email = a.bound ? "grace@acme-fintech.test" : "margaret@linear-ops.test";
            const r = await h.call("POST", "/api/auth/login", { tenantId, email, password: DEMO }, key ? { dpop: key } : {});
            check(r.status === 200, `login should succeed, got ${r.status} ${JSON.stringify(r.body)}`);
            check(kidOf(r.body.sessionToken) === activeKid, "a new session must be signed by the active key");
            sessions.push({ bound: a.bound, ...(key ? { key } : {}), famId: r.body.familyId, gen: 1, refresh: r.body.refreshToken, spent: [], dead: false, expiresAt: clock + REFRESH_TTL_MS, access: [{ token: r.body.sessionToken, exp: r.body.claims.exp * 1000, kid: activeKid }] });
            break;
          }
          case "rotate": {
            const s = pick(sessions, a.s);
            if (!s) break;
            const r = await h.call("POST", "/api/auth/rotate", { refreshToken: s.refresh }, await hdr(s, true));
            if (s.dead) check(r.status === 401, `rotating a dead family must be refused, got ${r.status}`);
            else if (clock >= s.expiresAt) {
              check(r.status === 401, `rotating an expired family must be refused, got ${r.status}`);
              s.dead = true;
            } else {
              check(r.status === 200 && r.body.generation === s.gen + 1, `rotation should succeed to generation ${s.gen + 1}, got ${r.status} ${JSON.stringify(r.body)}`);
              check(kidOf(r.body.sessionToken) === activeKid, "a rotated access token must be signed by the active key");
              s.spent.push(s.refresh);
              s.refresh = r.body.refreshToken;
              s.gen++;
              rotations++;
              s.access.push({ token: r.body.sessionToken, exp: r.body.claims.exp * 1000, kid: activeKid });
            }
            break;
          }
          case "replay": {
            const s = pick(sessions, a.s);
            const old = s ? pick(s.spent, a.pick) : undefined;
            if (!s || !old) break;
            const r = await h.call("POST", "/api/auth/rotate", { refreshToken: old }, await hdr(s, a.withKey));
            if (s.dead) check(r.status === 401, `replaying into a dead family must be refused with 401, got ${r.status}`);
            else if (s.bound && !a.withKey) check(r.status === 401 && r.body.status === "dpop_required", `a bound family must stop a thief without the key at the proof check, got ${r.status} ${JSON.stringify(r.body)}`);
            else if (clock >= s.expiresAt) {
              check(r.status === 401, `replaying into an expired family must be refused, got ${r.status}`);
              s.dead = true;
            } else {
              check(r.status === 409 && r.body.status === "family_revoked", `replaying a spent token must revoke the family, got ${r.status} ${JSON.stringify(r.body)}`);
              s.dead = true;
              reuseDetections++;
            }
            break;
          }
          case "revoke": {
            const s = pick(sessions, a.s);
            if (!s) break;
            const r = await h.call("DELETE", `/api/families/${s.famId}`);
            check(r.status === 200, `revoking should succeed, got ${r.status}`);
            s.dead = true;
            break;
          }
          case "verify": {
            const s = pick(sessions, a.s);
            if (s) await verifyToken(s, a.a, a.proof);
            break;
          }
          case "advance":
            clock += a.secs * 1000;
            break;
          case "restart":
            await h.restart();
            break;
          case "rotateIssuer": {
            const r = await h.keyring.rotate(clock, a.overlap);
            keys.set(r.oldKid, { until: clock + a.overlap * 1000 });
            keys.set(r.newKid, { state: "active" });
            activeKid = r.newKid;
            break;
          }
          case "revokeRetiring": {
            const retiring = [...keys].find(([, v]) => "until" in v && clock < v.until);
            if (!retiring) break;
            h.keyring.revoke(retiring[0], clock);
            keys.set(retiring[0], { revoked: true });
            break;
          }
        }
      } catch (e) {
        throw new Error(`${where}: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
      }
    }

    // Final sweep: every token of every session, and every family's status, must agree with the model.
    for (const s of sessions) for (let ai = 0; ai < s.access.length; ai++) await verifyToken(s, ai, "owner");
    const fams = (await h.call("GET", "/api/workspace")).body.families;
    for (const s of sessions) {
      const f = fams.find((x) => x.familyId === s.famId);
      check(f !== undefined, `family ${s.famId} vanished`);
      check((f?.status === "active") === !s.dead, `family ${s.famId}: model says dead=${s.dead}, store says ${f?.status}`);
      check(f?.generation === s.gen, `family ${s.famId}: model generation ${s.gen}, store ${f?.generation}`);
    }
    const ledger = readFileSync(h.ledgerPath, "utf8").trim().split("\n").map((l) => JSON.parse(l) as { type: string });
    check(ledger.filter((e) => e.type === "auth.family.reuse_detected").length === reuseDetections, "the ledger must record every reuse detection and nothing else");
    check(ledger.filter((e) => e.type === "auth.rotate").length === rotations, "the ledger must record every successful rotation");
    check((await h.call("GET", "/api/ledger/verify")).body.ok === true, "the ledger chain must verify");
  } finally {
    await h.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const hasSqlite = await sqliteAvailable();
const runs = Number(process.env["AUTHVEX_INVARIANT_RUNS"] ?? 20);

describe("session machine invariants (random scripts against the real server)", () => {
  for (const [kind, available] of [["file", true], ["sqlite", hasSqlite], ["postgres", process.env["AUTHVEX_TEST_DATABASE_URL"] !== undefined]] as const) {
    it.skipIf(!available)(`holds under ${runs} random scripts (${kind} store)`, async () => {
      await fc.assert(
        fc.asyncProperty(fc.boolean(), fc.array(actions, { minLength: 4, maxLength: 24 }), (bound, script) => runScript(kind, bound, script)),
        { numRuns: runs, endOnFailure: false },
      );
    }, 600_000);
  }

  it("catches a planted bug: a model that expects replays to be ignored disagrees with the server", async () => {
    // A sanity check of the test itself: the same script with a deliberately wrong expectation must fail.
    let failed = false;
    try {
      await runScriptWithWrongModel();
    } catch {
      failed = true;
    }
    if (!failed) throw new Error("the invariant harness did not notice a wrong model: it is not testing anything");
  }, 120_000);
});

async function runScriptWithWrongModel(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "authvex-inv-"));
  cpSync(template, dir, { recursive: true });
  const h = await startHarness({ store: { kind: "file" } }, { dir });
  try {
    const s = (await h.call("POST", "/api/auth/login", { tenantId: LIN, email: "margaret@linear-ops.test", password: DEMO })).body;
    const r2 = (await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken })).body;
    const replay = await h.call("POST", "/api/auth/rotate", { refreshToken: s.refreshToken });
    // A wrong belief: "replaying a spent token is harmless and the current token keeps working".
    const cur = await h.call("POST", "/api/auth/rotate", { refreshToken: r2.refreshToken });
    if (replay.status !== 409 || cur.status !== 200) throw new Error("the server disagreed with the wrong model, as it should");
  } finally {
    await h.close();
    rmSync(dir, { recursive: true, force: true });
  }
}
