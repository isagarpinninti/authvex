import { CborError, decodeCbor, decodeCborExact, encodeCbor, type CborValue } from "./cbor";
import { verifyAttestationStatement, type AttestationInfo, type AttestationPolicy } from "./attestation";
import { b64urlDecode, b64urlEncode, concat, constantTimeEqual, fromUtf8, randomBytes, sha256, toBytes, utf8, type Bytes } from "../util/bytes";

/** W3C WebAuthn Level 2, parsed from the raw bytes: no simplewebauthn, no CBOR or ASN.1 library. */

export interface AuthenticatorFlags {
  /** UP: the user was present (a touch or tap). */
  userPresent: boolean;
  /** UV: the user was verified (biometric or PIN). */
  userVerified: boolean;
  /** BE: the credential can be backed up (a synced passkey). */
  backupEligible: boolean;
  /** BS: the credential is currently backed up. */
  backupState: boolean;
  /** AT: attested credential data follows. */
  attestedCredentialData: boolean;
  /** ED: extension data follows. */
  extensionData: boolean;
}

export interface ParsedAuthenticatorData {
  rpIdHash: Bytes;
  flags: AuthenticatorFlags;
  signCount: number;
  attested?: { aaguid: Bytes; credentialId: Bytes; publicKeyJwk: JsonWebKey };
}

export class WebAuthnFormatError extends Error {}

/** COSE_Key (EC2, ES256, P-256) to a JWK. Anything else is refused. */
export function coseKeyToJwk(cose: CborValue): JsonWebKey {
  if (!(cose instanceof Map)) throw new WebAuthnFormatError("the public key is not a COSE map");
  const kty = cose.get(1);
  const alg = cose.get(3);
  const crv = cose.get(-1);
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (kty !== 2 || alg !== -7 || crv !== 1) throw new WebAuthnFormatError("only ES256 keys on P-256 are supported");
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) throw new WebAuthnFormatError("the P-256 coordinates must be 32 bytes");
  return { kty: "EC", crv: "P-256", x: b64urlEncode(x), y: b64urlEncode(y) };
}

export function jwkToCose(jwk: JsonWebKey): Map<CborValue, CborValue> {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) throw new WebAuthnFormatError("only P-256 keys are supported");
  return new Map<CborValue, CborValue>([[1, 2], [3, -7], [-1, 1], [-2, b64urlDecode(jwk.x)], [-3, b64urlDecode(jwk.y)]]);
}

/**
 * `authenticatorData`: bytes 0..31 are SHA-256(rpId), byte 32 holds the flags (UP bit 0, UV bit 2, BE bit 3, BS bit 4,
 * AT bit 6, ED bit 7), bytes 33..36 are the big-endian signature counter. With AT set, the AAGUID, credential id and COSE
 * public key follow.
 */
export function parseAuthenticatorData(data: Uint8Array): ParsedAuthenticatorData {
  if (data.length < 37) throw new WebAuthnFormatError("authenticatorData must be at least 37 bytes");
  const flagsByte = data[32] as number;
  const flags: AuthenticatorFlags = {
    userPresent: (flagsByte & 0x01) !== 0,
    userVerified: (flagsByte & 0x04) !== 0,
    backupEligible: (flagsByte & 0x08) !== 0,
    backupState: (flagsByte & 0x10) !== 0,
    attestedCredentialData: (flagsByte & 0x40) !== 0,
    extensionData: (flagsByte & 0x80) !== 0,
  };
  if (flags.backupState && !flags.backupEligible) throw new WebAuthnFormatError("a backed-up credential must be backup-eligible");
  const signCount = new DataView(data.buffer, data.byteOffset + 33, 4).getUint32(0);
  const out: ParsedAuthenticatorData = { rpIdHash: toBytes(data.subarray(0, 32)), flags, signCount };
  if (flags.attestedCredentialData) {
    if (data.length < 55) throw new WebAuthnFormatError("attested credential data is truncated");
    const idLen = new DataView(data.buffer, data.byteOffset + 53, 2).getUint16(0);
    if (idLen === 0 || idLen > 1023 || 55 + idLen > data.length) throw new WebAuthnFormatError("credential id length is invalid");
    try {
      const key = decodeCbor(data, 55 + idLen);
      out.attested = { aaguid: toBytes(data.subarray(37, 53)), credentialId: toBytes(data.subarray(55, 55 + idLen)), publicKeyJwk: coseKeyToJwk(key.value) };
      if (key.next !== data.length && !flags.extensionData) throw new WebAuthnFormatError("unexpected bytes after the credential public key");
    } catch (e) {
      if (e instanceof CborError) throw new WebAuthnFormatError(`credential public key: ${e.message}`);
      throw e;
    }
  } else if (data.length > 37 && !flags.extensionData) {
    throw new WebAuthnFormatError("unexpected bytes after authenticatorData");
  }
  return out;
}

/* ───────────────────────── ECDSA signature: ASN.1 DER <-> raw r||s ───────────────────────── */

/** WebAuthn gives a DER `SEQUENCE { INTEGER r, INTEGER s }`; Web Crypto verifies the raw 64-byte form. */
export function derToRawSignature(der: Uint8Array): Bytes {
  const bad = (m: string): never => {
    throw new WebAuthnFormatError(`signature is not a valid DER ECDSA signature: ${m}`);
  };
  let at = 0;
  const readLen = (): number => {
    const b = der[at++];
    if (b === undefined) return bad("truncated");
    if (b < 0x80) return b;
    if (b !== 0x81) return bad("unsupported length form");
    const n = der[at++];
    return n === undefined || n < 0x80 ? bad("non-minimal length") : n;
  };
  if (der[at++] !== 0x30) bad("not a SEQUENCE");
  if (readLen() !== der.length - at) bad("length mismatch");
  const readInt = (): Bytes => {
    if (der[at++] !== 0x02) return bad("not an INTEGER");
    const len = readLen();
    if (len === 0 || at + len > der.length) return bad("bad INTEGER length");
    let v = der.subarray(at, at + len);
    at += len;
    if ((v[0] as number) & 0x80) bad("negative INTEGER");
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) bad("INTEGER longer than 32 bytes");
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out as Bytes;
  };
  const r = readInt();
  const s = readInt();
  if (at !== der.length) bad("trailing bytes");
  return concat(r, s);
}

export function rawToDerSignature(raw: Uint8Array): Bytes {
  if (raw.length !== 64) throw new WebAuthnFormatError("a raw P-256 signature is 64 bytes");
  const int = (v: Uint8Array): number[] => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    const body = Array.from(v.subarray(i));
    if ((body[0] as number) & 0x80) body.unshift(0);
    return [0x02, body.length, ...body];
  };
  const body = [...int(raw.subarray(0, 32)), ...int(raw.subarray(32))];
  return toBytes(new Uint8Array([0x30, ...(body.length < 0x80 ? [body.length] : [0x81, body.length]), ...body]));
}

/* ───────────────────────── verification ───────────────────────── */

export interface WebAuthnExpectation {
  /** The challenge this server issued, base64url. */
  challenge: string;
  /** The exact origin of the page, e.g. `https://app.example.com`. */
  origin: string | string[];
  /** The Relying Party id (a registrable domain). */
  rpId: string;
  requireUserVerification?: boolean;
}

export interface AssertionResponse {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}

export type AssertionFailure =
  | "malformed"
  | "client_data_invalid"
  | "type_mismatch"
  | "challenge_mismatch"
  | "origin_mismatch"
  | "rp_id_mismatch"
  | "user_not_present"
  | "user_not_verified"
  | "sign_count_regression"
  | "bad_signature";

export type AssertionResult =
  | { ok: true; signCount: number; flags: AuthenticatorFlags; backedUp: boolean }
  | { ok: false; reason: AssertionFailure; message: string };

const fail = (reason: AssertionFailure, message: string): { ok: false; reason: AssertionFailure; message: string } => ({ ok: false, reason, message });

interface ClientData {
  type: string;
  challenge: string;
  origin: string;
}

function parseClientData(b64: string, type: "webauthn.get" | "webauthn.create", exp: WebAuthnExpectation): { ok: true; raw: Bytes } | ReturnType<typeof fail> {
  let raw: Bytes;
  let data: Partial<ClientData>;
  try {
    raw = b64urlDecode(b64);
    data = JSON.parse(fromUtf8(raw)) as Partial<ClientData>;
  } catch {
    return fail("client_data_invalid", "clientDataJSON is not valid base64url JSON");
  }
  if (data.type !== type) return fail("type_mismatch", `clientData.type must be "${type}"`);
  if (typeof data.challenge !== "string" || !constantTimeEqual(utf8(data.challenge), utf8(exp.challenge))) return fail("challenge_mismatch", "the challenge does not match the one issued");
  const origins = Array.isArray(exp.origin) ? exp.origin : [exp.origin];
  if (typeof data.origin !== "string" || !origins.includes(data.origin)) return fail("origin_mismatch", `origin "${String(data.origin)}" is not allowed`);
  return { ok: true, raw };
}

/**
 * Verifies a passkey sign-in: client data (type, challenge, origin), the RP id hash, the UP and UV flags, the signature
 * counter (a counter that did not advance means the authenticator may have been cloned), and the ECDSA P-256 signature over
 * `authenticatorData || SHA-256(clientDataJSON)`.
 */
export async function verifyWebAuthnAssertion(opts: {
  expected: WebAuthnExpectation;
  response: AssertionResponse;
  credential: { publicKeyJwk: JsonWebKey; signCount: number };
}): Promise<AssertionResult> {
  const { expected, response, credential } = opts;
  const client = parseClientData(response.clientDataJSON, "webauthn.get", expected);
  if (!client.ok) return client;
  let authData: Bytes;
  let parsed: ParsedAuthenticatorData;
  let sig: Bytes;
  try {
    authData = b64urlDecode(response.authenticatorData);
    parsed = parseAuthenticatorData(authData);
    sig = derToRawSignature(b64urlDecode(response.signature));
  } catch (e) {
    return fail("malformed", e instanceof Error ? e.message : "malformed response");
  }
  if (!constantTimeEqual(parsed.rpIdHash, await sha256(expected.rpId))) return fail("rp_id_mismatch", "the credential was not scoped to this relying party");
  if (!parsed.flags.userPresent) return fail("user_not_present", "the user-present flag is not set");
  if ((expected.requireUserVerification ?? true) && !parsed.flags.userVerified) return fail("user_not_verified", "the user-verified flag is not set");
  if (credential.signCount > 0 && parsed.signCount <= credential.signCount) return fail("sign_count_regression", `counter ${parsed.signCount} did not advance past ${credential.signCount}: the authenticator may be cloned`);
  const ok = await globalThis.crypto.subtle
    .importKey("jwk", credential.publicKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
    .then(async (key) => globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, concat(authData, await sha256(client.raw))))
    .catch(() => false);
  if (!ok) return fail("bad_signature", "the signature does not match the credential's public key");
  return { ok: true, signCount: parsed.signCount, flags: parsed.flags, backedUp: parsed.flags.backupState };
}

export type RegistrationResult =
  | { ok: true; credentialId: string; publicKeyJwk: JsonWebKey; signCount: number; flags: AuthenticatorFlags; attestation: AttestationInfo }
  | { ok: false; reason: AssertionFailure | "unsupported_attestation" | "attestation_invalid" | "attestation_untrusted" | "no_credential_data"; message: string };

/**
 * Checks a registration: client data, RP id, flags, and the attestation statement per `attestation` (default: only `none`, which
 * is what the server asks browsers for). It extracts the credential id and public key.
 */
export async function verifyWebAuthnRegistration(opts: { expected: WebAuthnExpectation; response: { clientDataJSON: string; attestationObject: string }; attestation?: AttestationPolicy }): Promise<RegistrationResult> {
  const client = parseClientData(opts.response.clientDataJSON, "webauthn.create", opts.expected);
  if (!client.ok) return client;
  let parsed: ParsedAuthenticatorData;
  let fmt: string;
  let attStmt: CborValue | undefined;
  let rawAuthData: Uint8Array;
  try {
    const obj = decodeCborExact(b64urlDecode(opts.response.attestationObject));
    if (!(obj instanceof Map)) return fail("malformed", "attestationObject is not a map");
    const f = obj.get("fmt");
    if (typeof f !== "string") return fail("malformed", "attestationObject has no fmt");
    fmt = f;
    if (!(opts.attestation?.formats ?? ["none"]).includes(f as never)) return { ok: false, reason: "unsupported_attestation", message: `attestation format "${f}" is not accepted here; the server asks for "none" unless attestation is configured` };
    attStmt = obj.get("attStmt");
    const authData = obj.get("authData");
    if (!(authData instanceof Uint8Array)) return fail("malformed", "attestationObject has no authData");
    rawAuthData = authData;
    parsed = parseAuthenticatorData(authData);
  } catch (e) {
    return fail("malformed", e instanceof Error ? e.message : "malformed attestation object");
  }
  if (!constantTimeEqual(parsed.rpIdHash, await sha256(opts.expected.rpId))) return fail("rp_id_mismatch", "the credential was not scoped to this relying party");
  if (!parsed.flags.userPresent) return fail("user_not_present", "the user-present flag is not set");
  if ((opts.expected.requireUserVerification ?? true) && !parsed.flags.userVerified) return fail("user_not_verified", "the user-verified flag is not set");
  if (!parsed.attested) return { ok: false, reason: "no_credential_data", message: "no attested credential data in the response" };
  const jwk = parsed.attested.publicKeyJwk;
  const att = await verifyAttestationStatement({
    fmt, attStmt, authData: rawAuthData, clientDataHash: await sha256(client.raw), aaguid: parsed.attested.aaguid, credentialId: parsed.attested.credentialId,
    credentialKey: { x: b64urlDecode(jwk.x as string), y: b64urlDecode(jwk.y as string) }, credentialJwk: jwk, rpIdHash: parsed.rpIdHash, policy: opts.attestation ?? {},
  });
  if (!att.ok) return att;
  return { ok: true, credentialId: b64urlEncode(parsed.attested.credentialId), publicKeyJwk: jwk, signCount: parsed.signCount, flags: parsed.flags, attestation: att.info };
}

export const generateChallenge = (): string => b64urlEncode(randomBytes(32));

/* ───────────────────────── a software authenticator (tests, demos) ───────────────────────── */

export interface SoftwareAuthenticator {
  readonly credentialId: string;
  readonly publicKeyJwk: JsonWebKey;
  signCount: number;
  register(challenge: string): Promise<{ clientDataJSON: string; attestationObject: string }>;
  assert(challenge: string, opts?: { userVerified?: boolean; signCount?: number }): Promise<AssertionResponse>;
}

/** A WebAuthn authenticator in software: enough for tests and the Studio's simulator. Real passkeys come from the browser. */
export async function createSoftwareAuthenticator(opts: { rpId: string; origin: string; backupEligible?: boolean }): Promise<SoftwareAuthenticator> {
  const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKeyJwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  const credId = randomBytes(32);
  const rpHash = await sha256(opts.rpId);
  const be = opts.backupEligible ? 0x08 : 0;
  const client = (type: string, challenge: string): Bytes => utf8(JSON.stringify({ type, challenge, origin: opts.origin, crossOrigin: false }));
  const counter = (n: number): Bytes => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n);
    return b as Bytes;
  };
  const auth: SoftwareAuthenticator = {
    credentialId: b64urlEncode(credId),
    publicKeyJwk: { kty: "EC", crv: "P-256", x: publicKeyJwk.x as string, y: publicKeyJwk.y as string },
    signCount: 0,
    async register(challenge) {
      const idLen = new Uint8Array(2);
      new DataView(idLen.buffer).setUint16(0, credId.length);
      const authData = concat(rpHash, new Uint8Array([0x01 | 0x04 | 0x40 | be]), counter(0), new Uint8Array(16), idLen, credId, encodeCbor(jwkToCose(auth.publicKeyJwk)));
      return { clientDataJSON: b64urlEncode(client("webauthn.create", challenge)), attestationObject: b64urlEncode(encodeCbor(new Map<CborValue, CborValue>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]))) };
    },
    async assert(challenge, o = {}) {
      auth.signCount = o.signCount ?? auth.signCount + 1;
      const authData = concat(rpHash, new Uint8Array([0x01 | (o.userVerified === false ? 0 : 0x04) | be]), counter(auth.signCount));
      const clientDataJSON = client("webauthn.get", challenge);
      const raw = new Uint8Array(await globalThis.crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, concat(authData, await sha256(clientDataJSON))));
      return { clientDataJSON: b64urlEncode(clientDataJSON), authenticatorData: b64urlEncode(authData), signature: b64urlEncode(rawToDerSignature(raw)) };
    },
  };
  return auth;
}
