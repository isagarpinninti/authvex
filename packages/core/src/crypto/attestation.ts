import { CborError, type CborValue } from "./cbor";
import { concat, constantTimeEqual, hex, type Bytes } from "../util/bytes";
import { X509Error, parseCertificate, verifyChain, verifyWithSpki, type Certificate } from "./x509";

/**
 * WebAuthn attestation statements (W3C WebAuthn Level 2, section 8): proof of WHICH authenticator made a credential.
 * Supported formats: `none`, `packed` (self attestation, and basic/AttCA with an `x5c` chain) and `fido-u2f`.
 * NOT supported (refused, never silently accepted): `tpm`, `android-key`, `android-safetynet`, `apple`, ECDAA, and
 * credentials whose key is not ES256. Revocation is not checked.
 */

export type AttestationFormat = "none" | "packed" | "fido-u2f";
export type AttestationType = "none" | "self" | "basic";

export interface AttestationPolicy {
  /** Formats you accept. Default: `["none"]`, which is what the server asks browsers for. */
  formats?: AttestationFormat[];
  /** DER certificates that attestation chains must lead to. */
  trustAnchors?: Uint8Array[];
  /** Refuse credentials whose attestation is not a chain to one of `trustAnchors` (this refuses `none` and self attestation). */
  requireTrusted?: boolean;
  /** Clock, for certificate validity. */
  nowMs?: number;
}

export interface AttestationInfo {
  format: string;
  type: AttestationType;
  /** True only when a certificate chain led to one of your trust anchors. */
  trusted: boolean;
  aaguid: string;
  /** Subject of the attestation certificate, when there was one. */
  certificate?: { subject: Record<string, string[]>; notAfter: string };
}

export type AttestationResult = { ok: true; info: AttestationInfo } | { ok: false; reason: "unsupported_attestation" | "attestation_invalid" | "attestation_untrusted"; message: string };

const COSE_ES256 = -7;
const refuse = (reason: "unsupported_attestation" | "attestation_invalid" | "attestation_untrusted", message: string): AttestationResult => ({ ok: false, reason, message });

function stmtField(stmt: CborValue | undefined, key: string): CborValue | undefined {
  return stmt instanceof Map ? stmt.get(key) : undefined;
}

/** Parses the certificates in `x5c`; the first is the attestation (leaf) certificate. */
function readX5c(stmt: CborValue | undefined): Certificate[] | null {
  const x5c = stmtField(stmt, "x5c");
  if (x5c === undefined) return null;
  if (!Array.isArray(x5c) || x5c.length === 0 || x5c.length > 6 || !x5c.every((c) => c instanceof Uint8Array)) throw new X509Error("x5c must be a short list of certificates");
  return (x5c as Uint8Array[]).map((c) => parseCertificate(c));
}

export async function verifyAttestationStatement(opts: {
  fmt: string;
  attStmt: CborValue | undefined;
  /** The raw `authData` bytes from the attestation object. */
  authData: Uint8Array;
  /** SHA-256 of the raw clientDataJSON. */
  clientDataHash: Uint8Array;
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  /** The credential public key, as a P-256 point `x`, `y` (32 bytes each). */
  credentialKey: { x: Uint8Array; y: Uint8Array };
  /** The credential public key as a JWK, used to check self attestation. */
  credentialJwk: JsonWebKey;
  rpIdHash: Uint8Array;
  policy: AttestationPolicy;
}): Promise<AttestationResult> {
  const { fmt, attStmt, authData, clientDataHash, aaguid, policy } = opts;
  const formats = policy.formats ?? ["none"];
  const nowMs = policy.nowMs ?? Date.now();
  const anchors: Certificate[] = [];
  for (const a of policy.trustAnchors ?? []) anchors.push(parseCertificate(a));
  const aaguidHex = hex(aaguid);
  if (!formats.includes(fmt as AttestationFormat)) return refuse("unsupported_attestation", `attestation format "${fmt}" is not accepted here`);
  if (fmt === "none") {
    if (policy.requireTrusted) return refuse("attestation_untrusted", "this server requires a verifiable attestation, and the authenticator gave none");
    return { ok: true, info: { format: "none", type: "none", trusted: false, aaguid: aaguidHex } };
  }
  try {
    const signed = concat(authData, clientDataHash);
    if (fmt === "packed") {
      const alg = stmtField(attStmt, "alg");
      const sig = stmtField(attStmt, "sig");
      if (alg !== COSE_ES256) return refuse("unsupported_attestation", `packed attestation with COSE algorithm ${String(alg)} is not supported (only ES256, -7)`);
      if (!(sig instanceof Uint8Array)) return refuse("attestation_invalid", "packed attestation has no signature");
      if (stmtField(attStmt, "ecdaaKeyId") !== undefined) return refuse("unsupported_attestation", "ECDAA attestation is not supported");
      const chain = readX5c(attStmt);
      if (!chain) {
        // Self attestation: the credential key signed its own registration. It proves the key exists, not what made it.
        if (!(await verifyWithSpki(await spkiOf(opts.credentialJwk), "ecdsa-sha256", signed, sig))) return refuse("attestation_invalid", "the self-attestation signature does not verify");
        if (policy.requireTrusted) return refuse("attestation_untrusted", "self attestation does not identify the authenticator");
        return { ok: true, info: { format: "packed", type: "self", trusted: false, aaguid: aaguidHex } };
      }
      const leaf = chain[0] as Certificate;
      if (leaf.keyType !== "ec-p256") return refuse("attestation_invalid", "the attestation certificate key is not P-256, which ES256 requires");
      if (!(await verifyWithSpki(leaf.spki, "ecdsa-sha256", signed, sig))) return refuse("attestation_invalid", "the attestation signature does not verify");
      const bad = checkPackedCertificate(leaf, aaguid);
      if (bad) return refuse("attestation_invalid", bad);
      return finishChain("packed", chain, anchors, nowMs, aaguidHex, policy);
    }
    if (fmt === "fido-u2f") {
      const sig = stmtField(attStmt, "sig");
      const chain = readX5c(attStmt);
      if (!(sig instanceof Uint8Array) || !chain || chain.length < 1) return refuse("attestation_invalid", "fido-u2f attestation needs sig and x5c");
      if (aaguid.some((b) => b !== 0)) return refuse("attestation_invalid", "a fido-u2f credential must have an all-zero AAGUID");
      const leaf = chain[0] as Certificate;
      if (leaf.keyType !== "ec-p256") return refuse("attestation_invalid", "the attestation certificate key is not P-256");
      const verificationData = concat(new Uint8Array([0x00]), opts.rpIdHash, clientDataHash, opts.credentialId, new Uint8Array([0x04]), opts.credentialKey.x, opts.credentialKey.y);
      if (!(await verifyWithSpki(leaf.spki, "ecdsa-sha256", verificationData, sig))) return refuse("attestation_invalid", "the fido-u2f attestation signature does not verify");
      return finishChain("fido-u2f", chain, anchors, nowMs, aaguidHex, policy);
    }
  } catch (e) {
    if (e instanceof X509Error || e instanceof CborError) return refuse("attestation_invalid", `the attestation certificate is malformed: ${e.message}`);
    throw e;
  }
  return refuse("unsupported_attestation", `attestation format "${fmt}" is not supported`);
}

/** WebAuthn 8.2.1: version 3, subject C/O/OU/CN with OU "Authenticator Attestation", not a CA, AAGUID extension (if any) equal to the credential's. */
function checkPackedCertificate(c: Certificate, aaguid: Uint8Array): string | null {
  if (c.version !== 3) return "the attestation certificate must be X.509 version 3";
  const s = c.subjectAttributes;
  if (!s["C"]?.length || !s["O"]?.length || !s["CN"]?.length) return "the attestation certificate subject needs C, O and CN";
  if (!s["OU"]?.includes("Authenticator Attestation")) return 'the attestation certificate subject OU must be "Authenticator Attestation"';
  if (c.isCa === true) return "the attestation certificate must not be a CA";
  if (c.aaguid && !constantTimeEqual(c.aaguid, aaguid)) return "the certificate's AAGUID does not match the credential's";
  return null;
}

async function finishChain(format: string, chain: Certificate[], anchors: Certificate[], nowMs: number, aaguid: string, policy: AttestationPolicy): Promise<AttestationResult> {
  const leaf = chain[0] as Certificate;
  const summary = { subject: leaf.subjectAttributes, notAfter: new Date(leaf.notAfterMs).toISOString() };
  if (anchors.length === 0) {
    if (policy.requireTrusted) return refuse("attestation_untrusted", "no trust anchors are configured, so this attestation cannot be trusted");
    return { ok: true, info: { format, type: "basic", trusted: false, aaguid, certificate: summary } };
  }
  const r = await verifyChain(chain, anchors, nowMs);
  if (!r.ok) {
    if (policy.requireTrusted) return refuse("attestation_untrusted", r.reason);
    return { ok: true, info: { format, type: "basic", trusted: false, aaguid, certificate: summary } };
  }
  return { ok: true, info: { format, type: "basic", trusted: true, aaguid, certificate: summary } };
}

async function spkiOf(jwk: JsonWebKey): Promise<Bytes> {
  const key = await globalThis.crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  return new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", key)) as Bytes;
}

export { parseCertificate, pemToDer, verifyChain } from "./x509";
export type { Certificate } from "./x509";
