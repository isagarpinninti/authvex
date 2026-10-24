import { b64urlDecode, b64urlEncode, fromUtf8, randomBytes, sha256, toBytes, utf8, type Bytes } from "../util/bytes";

/** Token families. Every token is `<prefix><payload>.<ES256 signature>` (the DPoP proof has a header as well). */
export const TOKEN_PREFIX = {
  session: "ath_sess_",
  dpop: "ath_dpop_",
  impersonation: "ath_imp_",
  admin: "ath_adm_",
  refresh: "ath_rt_",
  apiKey: "atk_live_",
} as const;

export type SignedTokenKind = "session" | "impersonation" | "admin";

/**
 * A signing key that lives somewhere else: a cloud KMS, an HSM, a smart card, a signing service. Authvex never sees the private
 * half; it hands over the bytes to sign and gets a signature back.
 */
export interface ExternalSigner {
  /**
   * ECDSA with the P-256 curve and SHA-256 (the signer hashes `data` itself, as KMS "ECDSA_SHA_256" and PKCS#11 `CKM_ECDSA_SHA256`
   * do). Returns the raw 64-byte `r || s`. Services that return an ASN.1 DER signature (AWS KMS, Google Cloud KMS, Azure Key
   * Vault, most HSMs) need `derToRawSignature` applied to their answer.
   */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export const isExternalSigner = (k: CryptoKey | ExternalSigner): k is ExternalSigner => typeof (k as ExternalSigner).sign === "function";

export interface IssuerKey {
  /** A key held in this process, or an `ExternalSigner` for one held in a KMS or HSM. */
  privateKey: CryptoKey | ExternalSigner;
  publicKeyJwk: JsonWebKey;
  /** The RFC 7638 thumbprint of the public key. */
  kid: string;
}

/** A set of public keys in JWKS shape (RFC 7517), as published at `/.well-known/jwks.json`. */
export interface JwkSet {
  keys: ReadonlyArray<JsonWebKey & { kid?: string }>;
}

/** One public key, or a set to choose from by the token's `kid`. */
export type PublicKeys = JsonWebKey | JwkSet;

const isSet = (k: PublicKeys): k is JwkSet => Array.isArray((k as JwkSet).keys);

export interface SerializedIssuerKey {
  privateKeyJwk: JsonWebKey;
  publicKeyJwk: JsonWebKey;
  kid: string;
}

const ECDSA = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN = { name: "ECDSA", hash: "SHA-256" } as const;

/** RFC 7638: SHA-256 over the JWK's required members in lexicographic order, base64url. EC keys only (P-256). */
export async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new TypeError("only P-256 EC public keys are supported");
  return b64urlEncode(await sha256(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`));
}

const publicOnly = (jwk: JsonWebKey): JsonWebKey => ({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });

export async function generateIssuerKey(): Promise<IssuerKey> {
  const pair = await globalThis.crypto.subtle.generateKey(ECDSA, true, ["sign", "verify"]);
  const publicKeyJwk = publicOnly(await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey));
  return { privateKey: pair.privateKey, publicKeyJwk, kid: await computeJwkThumbprint(publicKeyJwk) };
}

export async function serializeIssuerKey(key: IssuerKey): Promise<SerializedIssuerKey> {
  if (isExternalSigner(key.privateKey)) throw new Error("this issuer key lives in an external signer (KMS or HSM) and cannot be exported");
  return { privateKeyJwk: await globalThis.crypto.subtle.exportKey("jwk", key.privateKey), publicKeyJwk: key.publicKeyJwk, kid: key.kid };
}

export async function importIssuerKey(data: SerializedIssuerKey): Promise<IssuerKey> {
  const privateKey = await globalThis.crypto.subtle.importKey("jwk", data.privateKeyJwk, ECDSA, false, ["sign"]);
  const kid = await computeJwkThumbprint(data.publicKeyJwk);
  if (kid !== data.kid) throw new Error("issuer key file is inconsistent: kid does not match the public key");
  return { privateKey, publicKeyJwk: publicOnly(data.publicKeyJwk), kid };
}

export async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey("jwk", publicOnly(jwk), ECDSA, false, ["verify"]);
}

export async function signBytes(privateKey: CryptoKey | ExternalSigner, data: Uint8Array): Promise<Bytes> {
  if (isExternalSigner(privateKey)) {
    const sig = new Uint8Array(await privateKey.sign(data)) as Bytes;
    if (sig.length !== 64) throw new Error(`the external signer returned ${sig.length} bytes; ES256 needs the raw 64-byte r||s (convert DER with derToRawSignature)`);
    return sig;
  }
  return new Uint8Array(await globalThis.crypto.subtle.sign(SIGN, privateKey, toBytes(data))) as Bytes;
}

/**
 * An issuer key whose private half is in a KMS or HSM. Pass the key's public half (export it from the service as a JWK, or convert
 * its SPKI) and the signer. The signature is checked once against the public key, so a wrong key id or a signer that returns DER
 * fails here, at start-up, and not on the first sign-in.
 */
export async function externalIssuerKey(opts: { publicKeyJwk: JsonWebKey; signer: ExternalSigner }): Promise<IssuerKey> {
  const publicKeyJwk = publicOnly(opts.publicKeyJwk);
  if (publicKeyJwk.kty !== "EC" || publicKeyJwk.crv !== "P-256") throw new Error("an external issuer key must be an EC P-256 key (ES256)");
  const probe = randomBytes(32);
  const sig = await signBytes(opts.signer, probe);
  if (!(await verifyBytes(await importPublicKey(publicKeyJwk), sig, probe))) throw new Error("the external signer's signature does not verify under the public key you gave: wrong key, or wrong signature format");
  return { privateKey: opts.signer, publicKeyJwk, kid: await computeJwkThumbprint(publicKeyJwk) };
}

export async function verifyBytes(publicKey: CryptoKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  if (signature.length !== 64) return false;
  return globalThis.crypto.subtle.verify(SIGN, publicKey, toBytes(signature), toBytes(data));
}

/** Signs a payload. With `kid`, the payload names the key that signed it, so a verifier holding several keys picks the right one. */
export async function signToken(prefix: string, payload: object, privateKey: CryptoKey | ExternalSigner, kid?: string): Promise<string> {
  const body = b64urlEncode(utf8(JSON.stringify(kid ? { ...payload, kid } : payload)));
  return `${prefix}${body}.${b64urlEncode(await signBytes(privateKey, utf8(body)))}`;
}

export type TokenFailure = "malformed" | "bad_signature" | "unknown_key";

/** Checks the signature and returns the payload. The payload is not trusted until this says ok; expiry is the caller's check. */
export async function verifySignedToken<T extends object>(prefix: string, token: string, publicKeys: PublicKeys): Promise<{ ok: true; payload: T } | { ok: false; reason: TokenFailure }> {
  if (!token.startsWith(prefix)) return { ok: false, reason: "malformed" };
  const parts = token.slice(prefix.length).split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return { ok: false, reason: "malformed" };
  let sig: Bytes;
  let payload: T;
  try {
    sig = b64urlDecode(parts[1]);
    payload = JSON.parse(fromUtf8(b64urlDecode(parts[0]))) as T;
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (payload === null || typeof payload !== "object") return { ok: false, reason: "malformed" };
  // The `kid` is read before the signature is checked, which is safe: it only chooses which key to try, and the signature must still verify.
  const kid = (payload as { kid?: unknown }).kid;
  let candidates: JsonWebKey[];
  if (!isSet(publicKeys)) candidates = [publicKeys];
  else if (typeof kid === "string") {
    candidates = publicKeys.keys.filter((k) => k.kid === kid);
    if (candidates.length === 0) return { ok: false, reason: "unknown_key" };
  } else candidates = publicKeys.keys.slice(0, 8);
  let valid = false;
  for (const k of candidates) {
    if (await importPublicKey(k).then((key) => verifyBytes(key, sig, utf8(parts[0] as string))).catch(() => false)) {
      valid = true;
      break;
    }
  }
  return valid ? { ok: true, payload } : { ok: false, reason: "bad_signature" };
}

/** Names the token family from its prefix, without trusting it. */
export function tokenKind(token: string): keyof typeof TOKEN_PREFIX | null {
  for (const [kind, prefix] of Object.entries(TOKEN_PREFIX)) if (token.startsWith(prefix)) return kind as keyof typeof TOKEN_PREFIX;
  return null;
}

/** Reads a signed token's payload without checking the signature (for display only). */
export function peekTokenPayload(token: string): Record<string, unknown> | null {
  const kind = tokenKind(token);
  if (!kind || kind === "apiKey" || kind === "refresh") return null;
  try {
    const body = token.slice(TOKEN_PREFIX[kind].length).split(".")[kind === "dpop" ? 1 : 0];
    return body ? (JSON.parse(fromUtf8(b64urlDecode(body))) as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export const randomId = (prefix: string, bytes = 12): string => `${prefix}${b64urlEncode(randomBytes(bytes))}`;
