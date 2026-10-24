import * as nodeCrypto from "node:crypto";
import { NO_PASSWORD, b64urlDecode, b64urlEncode, constantTimeEqual, hashPassword as pbkdf2Hash, passwordNeedsRehash as pbkdf2NeedsRehash, verifyPassword as pbkdf2Verify } from "@authvex/core";

/**
 * Pluggable password hashing for the server. Core stays on Web Crypto (PBKDF2); here, where Node is the runtime, `scrypt` and
 * `argon2id` (Node 24.7+) are available, and both are memory-hard. Stored hashes name their algorithm and parameters, so
 * users hashed one way keep working after you switch, and are re-hashed to the configured way at their next successful sign-in.
 */

export type HashAlgorithm = "pbkdf2" | "scrypt" | "argon2id";

export interface PasswordHashingConfig {
  algorithm: HashAlgorithm;
  /** scrypt cost: N is a power of two. Defaults follow the OWASP minimum (N=2^17, r=8, p=1). */
  scrypt: { N: number; r: number; p: number };
  /** Argon2id: memory in KiB, passes, lanes. Defaults follow the OWASP minimum (19 MiB, t=2, p=1) rounded up to 64 MiB, t=3, p=1. */
  argon2id: { memoryKiB: number; passes: number; parallelism: number };
}

export interface PasswordHasher {
  readonly algorithm: HashAlgorithm;
  hash(password: string): Promise<string>;
  /** Constant-time check. Unknown or malformed hashes still cost one derivation, so timing does not reveal which accounts exist. */
  verify(password: string, stored: string): Promise<boolean>;
  /** True when `stored` is not the configured algorithm at the configured strength. */
  needsRehash(stored: string): boolean;
}

const SALT = 16;
const OUT = 32;
const SCRYPT_PREFIX = "$ath-scrypt$v=1$";
const ARGON_PREFIX = "$ath-argon2id$v=1$";
// What a stored hash may ask of the server. A tampered users.json must not be able to make one sign-in allocate gigabytes.
const MAX_SCRYPT_N = 2 ** 20;
const MAX_ARGON_KIB = 1024 * 1024;
const MAX_ARGON_PASSES = 20;

export const DEFAULT_PASSWORD_HASHING: PasswordHashingConfig = {
  algorithm: "pbkdf2",
  scrypt: { N: 2 ** 17, r: 8, p: 1 },
  argon2id: { memoryKiB: 65536, passes: 3, parallelism: 1 },
};

type Argon2Fn = (alg: "argon2id", params: { message: Uint8Array; nonce: Uint8Array; parallelism: number; tagLength: number; memory: number; passes: number }, cb: (err: Error | null, out: Uint8Array) => void) => void;
const argon2 = (nodeCrypto as unknown as { argon2?: Argon2Fn }).argon2;

/** True when this Node can do Argon2id (24.7 and later). */
export const argon2Available = (): boolean => typeof argon2 === "function";

const norm = (pw: string): Buffer => Buffer.from(pw.normalize("NFKC"), "utf8");

const scryptDerive = (pw: string, salt: Uint8Array, N: number, r: number, p: number): Promise<Uint8Array> =>
  new Promise((resolve, reject) => {
    nodeCrypto.scrypt(norm(pw), salt, OUT, { N, r, p, maxmem: 256 * N * r + 64 * 1024 * 1024 }, (e, key) => (e ? reject(e) : resolve(new Uint8Array(key))));
  });

const argonDerive = (pw: string, salt: Uint8Array, memory: number, passes: number, parallelism: number): Promise<Uint8Array> =>
  new Promise((resolve, reject) => {
    if (!argon2) return reject(new Error("this Node.js has no Argon2 (needs 24.7 or later)"));
    argon2("argon2id", { message: norm(pw), nonce: salt, parallelism, tagLength: OUT, memory, passes }, (e, out) => (e ? reject(e) : resolve(new Uint8Array(out))));
  });

interface Parsed {
  algorithm: "scrypt" | "argon2id";
  params: Record<string, number>;
  salt: Uint8Array;
  hash: Uint8Array;
}

function parse(stored: string): Parsed | null {
  const scrypt = stored.startsWith(SCRYPT_PREFIX);
  const argon = stored.startsWith(ARGON_PREFIX);
  if (!scrypt && !argon) return null;
  const [kv, salt, hash, ...extra] = stored.slice((scrypt ? SCRYPT_PREFIX : ARGON_PREFIX).length).split("$");
  if (extra.length > 0 || !kv || !salt || !hash) return null;
  const params: Record<string, number> = {};
  for (const part of kv.split(",")) {
    const m = /^([A-Za-z]{1,2})=([1-9][0-9]{0,9})$/.exec(part);
    if (!m) return null;
    params[m[1] as string] = Number(m[2]);
  }
  try {
    const s = b64urlDecode(salt);
    const h = b64urlDecode(hash);
    if (s.length < 8 || h.length !== OUT) return null;
    if (scrypt) {
      const { N, r, p } = params;
      if (!N || !r || !p || (N & (N - 1)) !== 0 || N < 2 || N > MAX_SCRYPT_N || r > 32 || p > 16) return null;
      return { algorithm: "scrypt", params, salt: s, hash: h };
    }
    const { m, t, p } = params;
    if (!m || !t || !p || m > MAX_ARGON_KIB || m < 8 * p || t > MAX_ARGON_PASSES || p > 16) return null;
    return { algorithm: "argon2id", params, salt: s, hash: h };
  } catch {
    return null;
  }
}

export function createPasswordHasher(config: PasswordHashingConfig = DEFAULT_PASSWORD_HASHING): PasswordHasher {
  const { algorithm, scrypt: sc, argon2id: ar } = config;
  if (algorithm === "argon2id" && !argon2Available()) throw new Error("passwordHashing.algorithm \"argon2id\" needs Node.js 24.7 or later; use \"scrypt\" or \"pbkdf2\" on this runtime");
  if (algorithm === "scrypt" && ((sc.N & (sc.N - 1)) !== 0 || sc.N < 2 || sc.N > MAX_SCRYPT_N)) throw new Error("passwordHashing.scrypt.N must be a power of two up to 2^20");

  const hash = async (password: string): Promise<string> => {
    if (algorithm === "pbkdf2") return pbkdf2Hash(password);
    const salt = nodeCrypto.randomBytes(SALT);
    if (algorithm === "scrypt") return `${SCRYPT_PREFIX}N=${sc.N},r=${sc.r},p=${sc.p}$${b64urlEncode(salt)}$${b64urlEncode(await scryptDerive(password, salt, sc.N, sc.r, sc.p))}`;
    return `${ARGON_PREFIX}m=${ar.memoryKiB},t=${ar.passes},p=${ar.parallelism}$${b64urlEncode(salt)}$${b64urlEncode(await argonDerive(password, salt, ar.memoryKiB, ar.passes, ar.parallelism))}`;
  };

  const verify = async (password: string, stored: string): Promise<boolean> => {
    const p = parse(stored);
    if (p?.algorithm === "scrypt") return constantTimeEqual(await scryptDerive(password, p.salt, p.params["N"] as number, p.params["r"] as number, p.params["p"] as number), p.hash);
    if (p?.algorithm === "argon2id") {
      if (!argon2Available()) return false;
      return constantTimeEqual(await argonDerive(password, p.salt, p.params["m"] as number, p.params["t"] as number, p.params["p"] as number), p.hash);
    }
    // No such user, or a user with no password: do the work a real check of the configured algorithm would, so timing says nothing.
    if (stored === NO_PASSWORD) {
      await dummy();
      return false;
    }
    // A hash from before a switch of algorithm, or an unreadable one (core still spends one derivation on it).
    if (stored.startsWith("$ath-pbkdf2$")) return pbkdf2Verify(password, stored);
    await dummy();
    return false;
  };

  /** The same work a real check of the configured algorithm costs. */
  const dummy = async (): Promise<void> => {
    if (algorithm === "pbkdf2") {
      await pbkdf2Verify(password0, "$ath-pbkdf2$v=1$iter=210000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
      return;
    }
    await hash(password0);
  };

  const needsRehash = (stored: string): boolean => {
    const p = parse(stored);
    if (algorithm === "pbkdf2") return p !== null || pbkdf2NeedsRehash(stored);
    if (p === null || p.algorithm !== algorithm) return true;
    if (algorithm === "scrypt") return (p.params["N"] as number) < sc.N || (p.params["r"] as number) < sc.r || (p.params["p"] as number) < sc.p;
    return (p.params["m"] as number) < ar.memoryKiB || (p.params["t"] as number) < ar.passes || (p.params["p"] as number) < ar.parallelism;
  };

  return { algorithm, hash, verify, needsRehash };
}

const password0 = "authvex-timing-equaliser";
