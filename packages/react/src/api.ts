import { computeJwkThumbprint, createDpopProof } from "@authvex/core";

export interface ApiOptions {
  /** Base URL of the Authvex server, e.g. `http://localhost:4320`. Empty means the same origin. */
  baseUrl: string;
  /** An admin token (`ath_adm_…`) for the admin endpoints. Public endpoints do not need it. */
  adminToken?: string;
}

export interface ApiResult<T> {
  status: number;
  body: T;
}

/** Calls the server and returns status and body without throwing on HTTP errors, which are normal answers here (401, 403, 409). */
export async function request<T = Record<string, unknown>>(api: ApiOptions, method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { ...extraHeaders };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (api.adminToken) headers["authorization"] = `Bearer ${api.adminToken}`;
  const res = await fetch(`${api.baseUrl.replace(/\/$/, "")}${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const parsed = (await res.json().catch(() => ({}))) as T;
  return { status: res.status, body: parsed };
}

/** The absolute URL a request will be sent to, as the DPoP proof must name it. */
export function absoluteUrl(api: ApiOptions, path: string): string {
  const base = api.baseUrl.replace(/\/$/, "") || (typeof location !== "undefined" ? location.origin : "");
  return `${base}${path}`;
}

/* ───────────────────────── the browser's hardware-bound key ───────────────────────── */

export interface DeviceKey {
  /** Non-extractable: scripts can use it to sign but can never read it out. */
  privateKey: CryptoKey;
  publicKeyJwk: JsonWebKey;
  /** RFC 7638 thumbprint: the `cnf.jkt` of a session bound to this key. */
  thumbprint: string;
}

export async function createDeviceKey(): Promise<DeviceKey> {
  const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  const publicKeyJwk: JsonWebKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  return { privateKey: pair.privateKey, publicKeyJwk, thumbprint: await computeJwkThumbprint(publicKeyJwk) };
}

const DB = "authvex-device-keys";

function idb<T>(run: (store: IDBObjectStore) => IDBRequest<T>, mode: IDBTransactionMode): Promise<T> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const req = run(open.result.transaction("keys", mode).objectStore("keys"));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    };
  });
}

const memory = new Map<string, DeviceKey>();

/**
 * Returns this browser's device key, creating it once. The CryptoKey object itself is stored in IndexedDB (structured clone
 * keeps it non-extractable), so it survives reloads without its bytes ever being readable. Without IndexedDB it lives in memory.
 */
export async function loadOrCreateDeviceKey(name = "default"): Promise<DeviceKey> {
  const cached = memory.get(name);
  if (cached) return cached;
  try {
    const stored = await idb<DeviceKey | undefined>((s) => s.get(name) as IDBRequest<DeviceKey | undefined>, "readonly");
    if (stored?.privateKey && stored.publicKeyJwk) {
      memory.set(name, stored);
      return stored;
    }
  } catch {
    /* no IndexedDB, or it is blocked: fall through to a memory-only key */
  }
  const key = await createDeviceKey();
  memory.set(name, key);
  try {
    await idb((s) => s.put(key, name), "readwrite");
  } catch {
    /* keep the in-memory key */
  }
  return key;
}

export async function dpopHeader(key: DeviceKey, method: string, url: string, sessionToken?: string): Promise<string> {
  return createDpopProof({ privateKey: key.privateKey, publicKeyJwk: key.publicKeyJwk, method, url, ...(sessionToken ? { sessionToken } : {}) });
}

/* ───────────────────────── shapes returned by the server ───────────────────────── */

export interface CheckView {
  code: string;
  name: string;
  status: "pass" | "warn" | "fail" | "skipped";
  effect: string;
  penalty: number;
  message: string;
}

export interface ReportView {
  score: number;
  level: "LOW" | "STEP_UP_MFA" | "BLOCK";
  checks: CheckView[];
  travel?: { distanceKm: number; hours: number; speedKmh: number };
}

export interface TenantView {
  id: string;
  name: string;
  domain: string;
  requireDpopHardwareBinding: boolean;
  requireMfaForAdmins: boolean;
  maxImpossibleTravelKmh: number;
  maxFailedAttemptsPerWindow: number;
  blockDisposableEmails: boolean;
  sessionTtlSeconds: number;
  refreshTtlSeconds: number;
  roles: Array<{ id: string; name: string; permissions: string[] }>;
  matrix: { permissions: string[]; rows: Array<{ roleId: string; name: string; cells: boolean[] }> };
}

export interface UserView {
  id: string;
  email: string;
  name: string;
  hasPassword: boolean;
  hasTotp: boolean;
  orgMemberships: Array<{ tenantId: string; roleId: string }>;
  passkeys: Array<{ credentialId: string; deviceName: string; signCount: number; createdAtIso: string }>;
}

export interface FamilyView {
  familyId: string;
  userId: string;
  tenantId: string;
  generation: number;
  consumed: number;
  status: string;
  bound: boolean;
  createdAtIso: string;
  lastRotatedAtIso: string;
  device?: { name?: string; city?: string; ip?: string };
}

export interface KeyView {
  id: string;
  name: string;
  tenantId: string;
  keyPrefix: string;
  scopes: string[];
  rateLimitPerMin: number;
  createdAtIso: string;
  expiresAtIso?: string;
  revokedAtIso?: string;
}

export interface WorkspaceView {
  version: string;
  issuer: { kid: string; keys: Array<{ kid: string; status: string; verifies: boolean; verifyUntilIso?: string }> };
  config: { rpId: string; origins: string[]; trustClientGeo: boolean; ledger: boolean; publicUrl: string };
  tenants: TenantView[];
  users: UserView[];
  families: FamilyView[];
  keys: KeyView[];
}

export interface LedgerEntryView {
  n: number;
  ts: number;
  type: string;
  tenantId?: string;
  actor?: string;
  subject?: string;
  detail: Record<string, unknown>;
  hash: string;
}

/** What a successful sign-in hands back, kept so other components can refresh, replay and verify. */
export interface AuthvexSession {
  tenantId: string;
  userId: string;
  email: string;
  sessionToken: string;
  refreshToken: string;
  familyId: string;
  tokenType: "DPoP" | "Bearer";
  claims: { sub: string; tid: string; fam: string; gen: number; exp: number; cnf?: { jkt: string } };
  deviceKey: DeviceKey | null;
  /** Refresh tokens this session has already used, newest last: what a thief who copied an old one would hold. */
  spentRefreshTokens: string[];
}
