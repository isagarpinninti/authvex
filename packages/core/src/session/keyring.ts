import { generateIssuerKey, importIssuerKey, serializeIssuerKey, type IssuerKey, type JwkSet } from "./tokens";

/**
 * The issuer's signing keys over time. One key is **active** and signs. A key that was rotated out stays **retiring**, verify-only,
 * until `verifyUntilIso`: long enough for every token it signed to expire. After that it is retired and can be pruned. A key that is
 * compromised can be **revoked** at once, which makes every token it signed stop verifying.
 *
 * Everything here is a pure function from a keyring to a keyring: the caller stores the result.
 */
export type KeyStatus = "active" | "retiring" | "retired";

export interface KeyringEntry {
  kid: string;
  publicKeyJwk: JsonWebKey;
  /** Present only while the key is active: a rotated-out key can no longer sign, so its private half is dropped. */
  privateKeyJwk?: JsonWebKey;
  status: KeyStatus;
  createdAtIso: string;
  /** When it stopped signing. */
  rotatedAtIso?: string;
  /** Until when it still verifies (retiring keys). */
  verifyUntilIso?: string;
  retiredAtIso?: string;
  retiredReason?: "expired" | "revoked";
}

export interface SerializedKeyring {
  version: 2;
  keys: KeyringEntry[];
}

/** Default overlap: the longest token lifetime (admin tokens, 24 h) plus an hour of margin. */
export const DEFAULT_OVERLAP_SECONDS = 25 * 3600;

const iso = (ms: number): string => new Date(ms).toISOString();

export async function createKeyring(first?: IssuerKey, nowMs = Date.now()): Promise<SerializedKeyring> {
  const key = first ?? (await generateIssuerKey());
  const s = await serializeIssuerKey(key);
  return { version: 2, keys: [{ kid: s.kid, publicKeyJwk: s.publicKeyJwk, privateKeyJwk: s.privateKeyJwk, status: "active", createdAtIso: iso(nowMs) }] };
}

/** Wraps a pre-rotation single key file (`issuer.json`) as a keyring with one active key. */
export function keyringFromLegacy(legacy: { kid: string; publicKeyJwk: JsonWebKey; privateKeyJwk: JsonWebKey }, nowMs = Date.now()): SerializedKeyring {
  return { version: 2, keys: [{ kid: legacy.kid, publicKeyJwk: legacy.publicKeyJwk, privateKeyJwk: legacy.privateKeyJwk, status: "active", createdAtIso: iso(nowMs) }] };
}

export function validateKeyring(kr: unknown): SerializedKeyring {
  const k = kr as Partial<SerializedKeyring> | null;
  if (!k || k.version !== 2 || !Array.isArray(k.keys)) throw new Error("not an Authvex keyring (expected version 2)");
  const actives = k.keys.filter((e) => e.status === "active");
  if (actives.length !== 1) throw new Error(`a keyring has exactly one active key, found ${actives.length}`);
  if (!actives[0]?.privateKeyJwk) throw new Error("the active key has no private half");
  if (new Set(k.keys.map((e) => e.kid)).size !== k.keys.length) throw new Error("a keyring cannot hold the same kid twice");
  return k as SerializedKeyring;
}

export function activeEntry(kr: SerializedKeyring): KeyringEntry {
  return kr.keys.find((e) => e.status === "active") as KeyringEntry;
}

export async function activeIssuerKey(kr: SerializedKeyring): Promise<IssuerKey> {
  const a = activeEntry(kr);
  return importIssuerKey({ kid: a.kid, publicKeyJwk: a.publicKeyJwk, privateKeyJwk: a.privateKeyJwk as JsonWebKey });
}

const stillVerifies = (e: KeyringEntry, nowMs: number): boolean => e.status === "active" || (e.status === "retiring" && nowMs < Date.parse(e.verifyUntilIso ?? "0"));

/** The keys a verifier should trust right now, as a JWKS: the active key and any retiring key still inside its overlap. */
export function verifiableKeys(kr: SerializedKeyring, nowMs = Date.now()): JwkSet & { keys: Array<JsonWebKey & { kid: string; alg: "ES256"; use: "sig" }> } {
  return {
    keys: kr.keys.filter((e) => stillVerifies(e, nowMs)).map((e) => ({ kty: e.publicKeyJwk.kty, crv: e.publicKeyJwk.crv, x: e.publicKeyJwk.x, y: e.publicKeyJwk.y, kid: e.kid, alg: "ES256" as const, use: "sig" as const })),
  };
}

/** Starts signing with `next`. The old active key keeps verifying for `overlapSeconds`, so nobody is signed out. */
export function rotateKeyring(kr: SerializedKeyring, next: SerializedKeyring["keys"][number], nowMs = Date.now(), overlapSeconds = DEFAULT_OVERLAP_SECONDS): SerializedKeyring {
  if (kr.keys.some((e) => e.kid === next.kid)) throw new Error("that key is already in the keyring");
  if (!Number.isFinite(overlapSeconds) || overlapSeconds < 0) throw new RangeError("the overlap must be zero or more seconds");
  const keys = kr.keys.map((e): KeyringEntry => {
    if (e.status !== "active") return e;
    const { privateKeyJwk: _dropped, ...rest } = e;
    void _dropped;
    return { ...rest, status: "retiring", rotatedAtIso: iso(nowMs), verifyUntilIso: iso(nowMs + overlapSeconds * 1000) };
  });
  return { version: 2, keys: [...keys, { ...next, status: "active", createdAtIso: iso(nowMs) }] };
}

/** Emergency stop: the key stops verifying immediately, so every token it signed is refused. The active key cannot be revoked; rotate first. */
export function revokeKey(kr: SerializedKeyring, kid: string, nowMs = Date.now()): SerializedKeyring {
  const e = kr.keys.find((x) => x.kid === kid);
  if (!e) throw new Error(`no key "${kid}" in the keyring`);
  if (e.status === "active") throw new Error("the active key cannot be revoked: rotate to a new key first");
  return {
    version: 2,
    keys: kr.keys.map((x): KeyringEntry => (x.kid === kid ? { ...x, status: "retired", retiredAtIso: iso(nowMs), retiredReason: "revoked", verifyUntilIso: iso(nowMs) } : x)),
  };
}

/** Marks retiring keys whose overlap has passed as retired, and removes retired keys older than `keepRetiredSeconds` (default: keep them for a day, for the record). */
export function pruneKeyring(kr: SerializedKeyring, nowMs = Date.now(), keepRetiredSeconds = 86_400): { keyring: SerializedKeyring; expired: string[]; removed: string[] } {
  const expired: string[] = [];
  const removed: string[] = [];
  const aged = kr.keys.map((e): KeyringEntry => {
    if (e.status === "retiring" && nowMs >= Date.parse(e.verifyUntilIso ?? "0")) {
      expired.push(e.kid);
      return { ...e, status: "retired", retiredAtIso: iso(nowMs), retiredReason: "expired" };
    }
    return e;
  });
  const keys = aged.filter((e) => {
    const gone = e.status === "retired" && nowMs - Date.parse(e.retiredAtIso ?? iso(nowMs)) >= keepRetiredSeconds * 1000;
    if (gone) removed.push(e.kid);
    return !gone;
  });
  return { keyring: { version: 2, keys }, expired, removed };
}

export interface KeyringSummary {
  kid: string;
  status: KeyStatus | "retiring-expired";
  createdAtIso: string;
  verifyUntilIso?: string;
  retiredReason?: string;
  verifies: boolean;
}

export function describeKeyring(kr: SerializedKeyring, nowMs = Date.now()): KeyringSummary[] {
  return kr.keys.map((e) => ({
    kid: e.kid, status: e.status === "retiring" && !stillVerifies(e, nowMs) ? "retiring-expired" : e.status, createdAtIso: e.createdAtIso, ...(e.verifyUntilIso ? { verifyUntilIso: e.verifyUntilIso } : {}),
    ...(e.retiredReason ? { retiredReason: e.retiredReason } : {}), verifies: stillVerifies(e, nowMs),
  }));
}

/** A fresh P-256 signing key as a keyring entry, ready for `rotateKeyring`. */
export async function generateKeyringEntry(nowMs = Date.now()): Promise<KeyringEntry> {
  const k = await generateIssuerKey();
  const s = await serializeIssuerKey(k);
  return { kid: s.kid, publicKeyJwk: s.publicKeyJwk, privateKeyJwk: s.privateKeyJwk, status: "active", createdAtIso: iso(nowMs) };
}
