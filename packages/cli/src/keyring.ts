import { existsSync, mkdirSync, readFileSync, renameSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  DEFAULT_OVERLAP_SECONDS, activeIssuerKey, createKeyring, describeKeyring, generateKeyringEntry, keyringFromLegacy, pruneKeyring, revokeKey, rotateKeyring, validateKeyring, verifiableKeys,
  type IssuerKey, type JwkSet, type KeyringSummary, type SerializedKeyring, type SerializedIssuerKey,
} from "@authvex/core";
import { STATE_DIR, writeJsonAtomic } from "./config";

export interface KeyringState {
  /** The key that signs new tokens. */
  issuer: IssuerKey;
  /** The keys a verifier should trust right now (the active key and any retiring key still inside its overlap). */
  keys: JwkSet;
  summary: KeyringSummary[];
}

/** Where the server gets its signing and verifying keys from. */
export interface KeyringSource {
  get(nowMs: number): Promise<KeyringState>;
}

/** A fixed single key, for tests and embedding. */
export function staticKeyring(issuer: IssuerKey): KeyringSource {
  const keys: JwkSet = { keys: [{ ...issuer.publicKeyJwk, kid: issuer.kid }] };
  return { get: async () => ({ issuer, keys, summary: [{ kid: issuer.kid, status: "active", createdAtIso: new Date(0).toISOString(), verifies: true }] }) };
}

export const keyringPath = (root: string): string => join(root, STATE_DIR, "issuers.json");
const legacyPath = (root: string): string => join(root, STATE_DIR, "issuer.json");

/**
 * The keyring stored in `.authvex/issuers.json` (owner-only). It is re-read when the file changes, so `authvex issuer rotate` takes
 * effect in a running server without a restart. A single-key `issuer.json` from version 0.1.0 is migrated on first open.
 */
export class FileKeyring implements KeyringSource {
  private cache: { mtime: number; kr: SerializedKeyring; issuer: IssuerKey } | null = null;

  private constructor(readonly root: string) {}

  static async open(root: string): Promise<FileKeyring> {
    const k = new FileKeyring(root);
    if (!existsSync(keyringPath(root))) {
      mkdirSync(join(root, STATE_DIR), { recursive: true });
      if (existsSync(legacyPath(root))) {
        const legacy = JSON.parse(readFileSync(legacyPath(root), "utf8")) as SerializedIssuerKey;
        writeJsonAtomic(keyringPath(root), keyringFromLegacy(legacy), 0o600);
        renameSync(legacyPath(root), `${legacyPath(root)}.migrated`);
      } else writeJsonAtomic(keyringPath(root), await createKeyring(), 0o600);
    }
    await k.load();
    return k;
  }

  private async load(): Promise<void> {
    const mtime = statSync(keyringPath(this.root)).mtimeMs;
    if (this.cache?.mtime === mtime) return;
    const kr = validateKeyring(JSON.parse(readFileSync(keyringPath(this.root), "utf8")));
    this.cache = { mtime, kr, issuer: await activeIssuerKey(kr) };
  }

  read(): SerializedKeyring {
    return validateKeyring(JSON.parse(readFileSync(keyringPath(this.root), "utf8")));
  }

  async get(nowMs: number): Promise<KeyringState> {
    await this.load();
    const { kr, issuer } = this.cache as NonNullable<FileKeyring["cache"]>;
    return { issuer, keys: verifiableKeys(kr, nowMs), summary: describeKeyring(kr, nowMs) };
  }

  /** Generates a new active key; the old one keeps verifying for `overlapSeconds`. */
  async rotate(nowMs = Date.now(), overlapSeconds = DEFAULT_OVERLAP_SECONDS): Promise<{ newKid: string; oldKid: string }> {
    const kr = this.read();
    const oldKid = kr.keys.find((e) => e.status === "active")?.kid as string;
    const entry = await generateKeyringEntry(nowMs);
    writeJsonAtomic(keyringPath(this.root), rotateKeyring(kr, entry, nowMs, overlapSeconds), 0o600);
    return { newKid: entry.kid, oldKid };
  }

  revoke(kid: string, nowMs = Date.now()): void {
    writeJsonAtomic(keyringPath(this.root), revokeKey(this.read(), kid, nowMs), 0o600);
  }

  prune(nowMs = Date.now()): { expired: string[]; removed: string[] } {
    const r = pruneKeyring(this.read(), nowMs);
    writeJsonAtomic(keyringPath(this.root), r.keyring, 0o600);
    return { expired: r.expired, removed: r.removed };
  }
}

/** Opens (creating if needed) the workspace keyring and returns its active key: what the commands that sign something use. */
export async function loadOrCreateIssuerKey(root: string, nowMs = Date.now()): Promise<IssuerKey> {
  return (await (await FileKeyring.open(root)).get(nowMs)).issuer;
}
