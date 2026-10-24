import type { ReplayCache, SessionFamily } from "./session/dpopAndFamilies";

/** A pending WebAuthn challenge. */
export interface ChallengeRecord {
  challenge: string;
  purpose: "login" | "register";
  tenantId?: string;
  userId: string;
  expires: number;
}

/**
 * A single-use secret handed out by email or by the authorization endpoint (an email verification link, a password reset link,
 * a magic sign-in link, an OIDC authorization code). Only its hash is stored.
 */
export interface OneTimeToken {
  purpose: string;
  userId: string;
  tenantId: string;
  expires: number;
  /** Anything the purpose needs to remember (the email address, an OIDC client id and PKCE challenge, ...). */
  data?: Record<string, unknown>;
}

/**
 * Where a server keeps what must survive a restart or be shared: session families, the DPoP replay cache, failed-attempt windows,
 * challenges and TOTP counters. Every method is individually atomic. Rotation of a refresh token is a read, a computation and a
 * write, so it goes through `compareAndSetFamily`: the write succeeds only if nobody changed the family in between, which is what
 * keeps two parallel uses of one token (in one process or two) from both being accepted.
 */
export interface Store {
  readonly kind: string;
  getFamily(familyId: string): Promise<SessionFamily | undefined>;
  listFamilies(): Promise<SessionFamily[]>;
  /** Stores a new family and indexes its active refresh token. */
  createFamily(family: SessionFamily): Promise<void>;
  /**
   * Replaces `prev` with `next` only if the stored family still has `prev`'s status, generation and active token. Indexes `next`'s
   * active token. Returns false when someone else changed it first; the caller re-reads and decides again.
   */
  compareAndSetFamily(prev: SessionFamily, next: SessionFamily): Promise<boolean>;
  /** Which family a refresh token hash belongs to, active or already consumed. */
  familyIdForToken(tokenHash: string): Promise<string | undefined>;
  /** True the first time a proof id is seen within `ttlMs`, false on a replay. */
  claimJti(jti: string, nowMs: number, ttlMs: number): Promise<boolean>;
  countFailures(key: string, nowMs: number, windowMs: number): Promise<number>;
  recordFailure(key: string, nowMs: number, windowMs: number): Promise<void>;
  putChallenge(id: string, challenge: ChallengeRecord): Promise<void>;
  /** Returns and deletes the challenge, so it is used once. Expired ones are not returned. */
  takeChallenge(id: string, nowMs: number): Promise<ChallengeRecord | undefined>;
  /** Stores a single-use token under the hash of its secret. */
  putOneTimeToken(hash: string, token: OneTimeToken): Promise<void>;
  /** Returns and deletes the token if it exists, has this purpose and has not expired. A wrong purpose or an expired token is still consumed. */
  takeOneTimeToken(hash: string, purpose: string, nowMs: number): Promise<OneTimeToken | undefined>;
  getTotpCounter(userId: string): Promise<number | undefined>;
  /** Records `counter` as used if it is above the last accepted one. False means the code was already used. */
  advanceTotpCounter(userId: string, counter: number): Promise<boolean>;
  /** Drops expired proof ids, failures and challenges. */
  sweep(nowMs: number): Promise<void>;
  flush(): Promise<void>;
  close(): Promise<void>;
}

/** A `ReplayCache` backed by a store, so replay protection survives a restart and can be shared. */
export function storeReplayCache(store: Store, ttlMs = 120_000): ReplayCache {
  return { claim: (jti, nowMs) => store.claimJti(jti, nowMs, ttlMs) };
}

/** The data a `MemoryStore` holds; the file store writes exactly this to disk. */
export interface StoreSnapshot {
  version: 1;
  families: SessionFamily[];
  tokens: Array<[string, string]>;
  jtis: Array<[string, number]>;
  failures: Array<[string, number[]]>;
  challenges: Array<[string, ChallengeRecord]>;
  totp: Array<[string, number]>;
  oneTime?: Array<[string, OneTimeToken]>;
}

export class MemoryStore implements Store {
  readonly kind: string = "memory";
  protected families = new Map<string, SessionFamily>();
  protected tokens = new Map<string, string>();
  protected jtis = new Map<string, number>();
  protected failures = new Map<string, number[]>();
  protected challenges = new Map<string, ChallengeRecord>();
  protected totp = new Map<string, number>();
  protected oneTime = new Map<string, OneTimeToken>();
  /** Called after every change, so a subclass can persist. */
  protected changed(_urgent: boolean): void {}

  async getFamily(id: string): Promise<SessionFamily | undefined> {
    return this.families.get(id);
  }
  async listFamilies(): Promise<SessionFamily[]> {
    return [...this.families.values()];
  }
  async createFamily(family: SessionFamily): Promise<void> {
    this.families.set(family.familyId, family);
    this.tokens.set(family.activeRefreshTokenHash, family.familyId);
    this.changed(true);
  }
  async compareAndSetFamily(prev: SessionFamily, next: SessionFamily): Promise<boolean> {
    const cur = this.families.get(prev.familyId);
    if (!cur || cur.status !== prev.status || cur.currentGeneration !== prev.currentGeneration || cur.activeRefreshTokenHash !== prev.activeRefreshTokenHash) return false;
    this.families.set(next.familyId, next);
    this.tokens.set(next.activeRefreshTokenHash, next.familyId);
    this.changed(true);
    return true;
  }
  async familyIdForToken(hash: string): Promise<string | undefined> {
    return this.tokens.get(hash);
  }
  async claimJti(jti: string, nowMs: number, ttlMs: number): Promise<boolean> {
    const exp = this.jtis.get(jti);
    if (exp !== undefined && exp > nowMs) return false;
    this.jtis.set(jti, nowMs + ttlMs);
    this.changed(false);
    return true;
  }
  async countFailures(key: string, nowMs: number, windowMs: number): Promise<number> {
    return (this.failures.get(key) ?? []).filter((t) => nowMs - t < windowMs).length;
  }
  async recordFailure(key: string, nowMs: number, windowMs: number): Promise<void> {
    this.failures.set(key, [...(this.failures.get(key) ?? []).filter((t) => nowMs - t < windowMs), nowMs]);
    this.changed(false);
  }
  async putChallenge(id: string, c: ChallengeRecord): Promise<void> {
    this.challenges.set(id, c);
    this.changed(false);
  }
  async takeChallenge(id: string, nowMs: number): Promise<ChallengeRecord | undefined> {
    const c = this.challenges.get(id);
    if (!c) return undefined;
    this.challenges.delete(id);
    this.changed(false);
    return c.expires >= nowMs ? c : undefined;
  }
  async putOneTimeToken(hash: string, token: OneTimeToken): Promise<void> {
    this.oneTime.set(hash, token);
    this.changed(true);
  }
  async takeOneTimeToken(hash: string, purpose: string, nowMs: number): Promise<OneTimeToken | undefined> {
    const t = this.oneTime.get(hash);
    if (!t) return undefined;
    this.oneTime.delete(hash);
    this.changed(true);
    return t.purpose === purpose && t.expires >= nowMs ? t : undefined;
  }
  async getTotpCounter(userId: string): Promise<number | undefined> {
    return this.totp.get(userId);
  }
  async advanceTotpCounter(userId: string, counter: number): Promise<boolean> {
    const last = this.totp.get(userId);
    if (last !== undefined && counter <= last) return false;
    this.totp.set(userId, counter);
    this.changed(true);
    return true;
  }
  async sweep(nowMs: number): Promise<void> {
    for (const [k, exp] of this.jtis) if (exp <= nowMs) this.jtis.delete(k);
    for (const [k, c] of this.challenges) if (c.expires < nowMs) this.challenges.delete(k);
    for (const [k, t] of this.oneTime) if (t.expires < nowMs) this.oneTime.delete(k);
    for (const [k, list] of this.failures) {
      const keep = list.filter((t) => nowMs - t < 24 * 3600_000);
      if (keep.length === 0) this.failures.delete(k);
      else if (keep.length !== list.length) this.failures.set(k, keep);
    }
    this.changed(false);
  }
  async flush(): Promise<void> {}
  async close(): Promise<void> {}

  snapshot(): StoreSnapshot {
    return {
      version: 1, families: [...this.families.values()], tokens: [...this.tokens], jtis: [...this.jtis], failures: [...this.failures], challenges: [...this.challenges], totp: [...this.totp], oneTime: [...this.oneTime],
    };
  }
  protected restore(s: StoreSnapshot): void {
    this.families = new Map(s.families.map((f) => [f.familyId, f]));
    this.tokens = new Map(s.tokens);
    this.jtis = new Map(s.jtis);
    this.failures = new Map(s.failures);
    this.challenges = new Map(s.challenges);
    this.totp = new Map(s.totp);
    this.oneTime = new Map(s.oneTime ?? []);
  }
}
