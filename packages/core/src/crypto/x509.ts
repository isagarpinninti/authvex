import { concat, constantTimeEqual, type Bytes } from "../util/bytes";

/**
 * Just enough X.509 to check WebAuthn attestation: a strict DER reader, certificate fields, and chain validation.
 * Signatures: ecdsa-with-SHA256 (P-256), ecdsa-with-SHA384 (P-384) and sha256WithRSAEncryption.
 * NOT done: revocation (CRL/OCSP), name constraints, policy mapping, path-length limits. A chain accepted here is "signed by a
 * trust anchor you supplied and within its dates", nothing stronger.
 */

export class X509Error extends Error {}

const bad = (m: string): never => {
  throw new X509Error(m);
};

interface Tlv {
  tag: number;
  /** Start of the content. */
  start: number;
  end: number;
  /** Start of the whole element (tag byte). */
  head: number;
}

/** Reads one element at `at`. Only definite lengths up to 4 bytes; non-minimal lengths are refused. */
function read(b: Uint8Array, at: number, limit = b.length): Tlv {
  if (at + 2 > limit) return bad("truncated");
  const tag = b[at] as number;
  if ((tag & 0x1f) === 0x1f) return bad("high tag numbers are not supported");
  let len = b[at + 1] as number;
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0) return bad("indefinite length");
    if (n > 4) return bad("length too large");
    if (start + n > limit) return bad("truncated");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (b[start + i] as number);
    if (len < 0x80 || ((b[start] as number) === 0 && n > 1)) return bad("non-minimal length");
    start += n;
  }
  if (start + len > limit) return bad("element longer than its container");
  return { tag, start, end: start + len, head: at };
}

const children = (b: Uint8Array, t: Tlv): Tlv[] => {
  const out: Tlv[] = [];
  let at = t.start;
  while (at < t.end) {
    const c = read(b, at, t.end);
    out.push(c);
    at = c.end;
  }
  return out;
};

const expect = (t: Tlv | undefined, tag: number, what: string): Tlv => (t && t.tag === tag ? t : bad(`expected ${what}`));
const slice = (b: Uint8Array, t: Tlv): Bytes => b.slice(t.start, t.end) as Bytes;
const whole = (b: Uint8Array, t: Tlv): Bytes => b.slice(t.head, t.end) as Bytes;

function oidOf(b: Uint8Array, t: Tlv): string {
  expect(t, 0x06, "an OBJECT IDENTIFIER");
  if (t.end === t.start) return bad("empty OID");
  const parts: number[] = [];
  let v = 0;
  for (let i = t.start; i < t.end; i++) {
    const x = b[i] as number;
    v = v * 128 + (x & 0x7f);
    if (v > 2 ** 40) return bad("OID arc too large");
    if (!(x & 0x80)) {
      if (parts.length === 0) parts.push(Math.min(2, Math.floor(v / 40)), v - 40 * Math.min(2, Math.floor(v / 40)));
      else parts.push(v);
      v = 0;
    } else if (i === t.end - 1) return bad("truncated OID");
  }
  return parts.join(".");
}

function timeOf(b: Uint8Array, t: Tlv): number {
  const s = new TextDecoder().decode(b.subarray(t.start, t.end));
  const m = t.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : t.tag === 0x18 ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : null;
  if (!m) return bad("unsupported time format");
  let year = Number(m[1]);
  if (t.tag === 0x17) year += year >= 50 ? 1900 : 2000;
  const ms = Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  return Number.isNaN(ms) ? bad("invalid time") : ms;
}

const OID = {
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  rsaSha256: "1.2.840.113549.1.1.11",
  ecPublicKey: "1.2.840.10045.2.1",
  rsaEncryption: "1.2.840.113549.1.1.1",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  basicConstraints: "2.5.29.19",
  aaguid: "1.3.6.1.4.1.45724.1.1.4",
  nameC: "2.5.4.6",
  nameO: "2.5.4.10",
  nameOU: "2.5.4.11",
  nameCN: "2.5.4.3",
} as const;

export type SignatureAlgorithm = "ecdsa-sha256" | "ecdsa-sha384" | "rsa-sha256";

export interface Certificate {
  /** The whole certificate, DER. */
  der: Bytes;
  /** The signed part (`tbsCertificate`), DER. */
  tbs: Bytes;
  version: number;
  notBeforeMs: number;
  notAfterMs: number;
  /** `Name` DER of issuer and subject, compared byte for byte. */
  issuer: Bytes;
  subject: Bytes;
  /** Readable attributes of the subject (C, O, OU, CN). */
  subjectAttributes: Record<string, string[]>;
  /** The whole SubjectPublicKeyInfo, DER (importable with Web Crypto as `spki`). */
  spki: Bytes;
  keyType: "ec-p256" | "ec-p384" | "rsa";
  /** For `ec-p256`: the uncompressed point `04 || x || y`. */
  ecPoint?: Bytes;
  signatureAlgorithm: SignatureAlgorithm;
  signature: Bytes;
  /** `basicConstraints`: undefined if the extension is absent. */
  isCa?: boolean;
  /** The FIDO AAGUID extension, if present. */
  aaguid?: Bytes;
}

const SIG_ALGS: Record<string, SignatureAlgorithm> = { [OID.ecdsaSha256]: "ecdsa-sha256", [OID.ecdsaSha384]: "ecdsa-sha384", [OID.rsaSha256]: "rsa-sha256" };

function parseName(b: Uint8Array, name: Tlv): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const rdn of children(b, expect(name, 0x30, "a Name"))) {
    for (const atv of children(b, expect(rdn, 0x31, "an RDN"))) {
      const [o, v] = children(b, expect(atv, 0x30, "an attribute"));
      if (!o || !v) return bad("malformed attribute");
      const key = ({ [OID.nameC]: "C", [OID.nameO]: "O", [OID.nameOU]: "OU", [OID.nameCN]: "CN" } as Record<string, string>)[oidOf(b, o)];
      if (key && [0x0c, 0x13, 0x16, 0x14].includes(v.tag)) (out[key] ??= []).push(new TextDecoder().decode(b.subarray(v.start, v.end)));
    }
  }
  return out;
}

/** Parses a DER certificate. Refuses anything it cannot interpret exactly rather than guessing. */
export function parseCertificate(der: Uint8Array): Certificate {
  const b = der;
  const top = read(b, 0);
  if (top.tag !== 0x30 || top.end !== b.length) return bad("not a single DER certificate");
  const [tbsT, algT, sigT] = children(b, top);
  expect(tbsT, 0x30, "tbsCertificate");
  expect(algT, 0x30, "signatureAlgorithm");
  expect(sigT, 0x03, "signature");
  const tbs = children(b, tbsT as Tlv);
  let i = 0;
  let version = 1;
  if (tbs[i]?.tag === 0xa0) {
    const v = expect(children(b, tbs[i] as Tlv)[0], 0x02, "version");
    version = (b[v.start] as number) + 1;
    i++;
  }
  expect(tbs[i++], 0x02, "serialNumber");
  const inner = expect(tbs[i++], 0x30, "signature algorithm (tbs)");
  const issuerT = expect(tbs[i++], 0x30, "issuer");
  const validity = children(b, expect(tbs[i++], 0x30, "validity"));
  const subjectT = expect(tbs[i++], 0x30, "subject");
  const spkiT = expect(tbs[i++], 0x30, "subjectPublicKeyInfo");
  if (validity.length !== 2) bad("validity must have two times");
  const algOid = oidOf(b, (children(b, algT as Tlv)[0] as Tlv));
  const innerOid = oidOf(b, children(b, inner)[0] as Tlv);
  if (algOid !== innerOid) bad("the two signature algorithm fields disagree");
  const signatureAlgorithm = SIG_ALGS[algOid] ?? bad(`unsupported certificate signature algorithm ${algOid}`);

  const [keyAlg, keyBits] = children(b, spkiT);
  const keyAlgParts = children(b, expect(keyAlg, 0x30, "key algorithm"));
  const keyOid = oidOf(b, keyAlgParts[0] as Tlv);
  const bits = expect(keyBits, 0x03, "public key bits");
  let keyType: Certificate["keyType"];
  let ecPoint: Bytes | undefined;
  if (keyOid === OID.ecPublicKey) {
    const curve = oidOf(b, keyAlgParts[1] as Tlv);
    if (curve === OID.p256) keyType = "ec-p256";
    else if (curve === OID.p384) keyType = "ec-p384";
    else return bad(`unsupported curve ${curve}`);
    if (b[bits.start] !== 0) bad("public key has unused bits");
    ecPoint = b.slice(bits.start + 1, bits.end) as Bytes;
    if (ecPoint[0] !== 0x04 || ecPoint.length !== (keyType === "ec-p256" ? 65 : 97)) bad("not an uncompressed EC point");
  } else if (keyOid === OID.rsaEncryption) keyType = "rsa";
  else return bad(`unsupported public key algorithm ${keyOid}`);

  let isCa: boolean | undefined;
  let aaguid: Bytes | undefined;
  for (; i < tbs.length; i++) {
    const t = tbs[i] as Tlv;
    if (t.tag !== 0xa3) continue;
    for (const ext of children(b, expect(children(b, t)[0], 0x30, "extensions"))) {
      const parts = children(b, expect(ext, 0x30, "an extension"));
      const id = oidOf(b, parts[0] as Tlv);
      const value = expect(parts[parts.length - 1], 0x04, "extension value");
      if (id === OID.basicConstraints) {
        const seq = children(b, expect(read(b, value.start, value.end), 0x30, "basicConstraints"));
        isCa = seq[0]?.tag === 0x01 && b[(seq[0] as Tlv).start] !== 0;
      } else if (id === OID.aaguid) {
        const o = expect(read(b, value.start, value.end), 0x04, "aaguid");
        if (o.end - o.start !== 16) bad("aaguid extension is not 16 bytes");
        aaguid = slice(b, o);
      }
    }
  }

  const sigBytes = sigT as Tlv;
  if (b[sigBytes.start] !== 0) bad("signature has unused bits");
  return {
    der: b.slice() as Bytes, tbs: whole(b, tbsT as Tlv), version,
    notBeforeMs: timeOf(b, validity[0] as Tlv), notAfterMs: timeOf(b, validity[1] as Tlv),
    issuer: whole(b, issuerT), subject: whole(b, subjectT), subjectAttributes: parseName(b, subjectT),
    spki: whole(b, spkiT), keyType, ...(ecPoint ? { ecPoint } : {}), signatureAlgorithm,
    signature: b.slice(sigBytes.start + 1, sigBytes.end) as Bytes, ...(isCa !== undefined ? { isCa } : {}), ...(aaguid ? { aaguid } : {}),
  };
}

/** Reads one or more PEM `CERTIFICATE` blocks. */
export function pemToDer(pem: string): Bytes[] {
  const out: Bytes[] = [];
  for (const m of pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)) {
    const body = (m[1] as string).replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length % 4 !== 0) return bad("a PEM block is not valid base64");
    const raw = atob(body);
    out.push(Uint8Array.from(raw, (c) => c.charCodeAt(0)) as Bytes);
  }
  return out;
}

/** DER `SEQUENCE { INTEGER r, INTEGER s }` to the raw `r || s` that Web Crypto verifies. */
function ecdsaDerToRaw(der: Uint8Array, size: number): Bytes {
  const seq = read(der, 0);
  if (seq.tag !== 0x30 || seq.end !== der.length) return bad("malformed ECDSA signature");
  const ints = children(der, seq);
  if (ints.length !== 2) return bad("malformed ECDSA signature");
  const parts = ints.map((t) => {
    expect(t, 0x02, "an INTEGER");
    let v = der.subarray(t.start, t.end);
    if (v.length === 0 || (v[0] as number) & 0x80) return bad("bad ECDSA integer");
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length > size) return bad("ECDSA integer too long");
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  });
  return concat(parts[0] as Uint8Array, parts[1] as Uint8Array);
}

/** Verifies `signature` over `data` with the public key in `spki`, as the certificate's algorithm says. */
export async function verifyWithSpki(spki: Uint8Array, alg: SignatureAlgorithm, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const subtle = globalThis.crypto.subtle;
  try {
    if (alg === "rsa-sha256") {
      const key = await subtle.importKey("spki", spki as Bytes, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      return await subtle.verify("RSASSA-PKCS1-v1_5", key, signature as Bytes, data as Bytes);
    }
    const p384 = alg === "ecdsa-sha384";
    const key = await subtle.importKey("spki", spki as Bytes, { name: "ECDSA", namedCurve: p384 ? "P-384" : "P-256" }, false, ["verify"]);
    return await subtle.verify({ name: "ECDSA", hash: p384 ? "SHA-384" : "SHA-256" }, key, ecdsaDerToRaw(signature, p384 ? 48 : 32) as Bytes, data as Bytes);
  } catch {
    return false;
  }
}

/** Did `issuer` sign `cert`? Names must match byte for byte and the signature must verify. */
export async function isSignedBy(cert: Certificate, issuer: Certificate): Promise<boolean> {
  if (!constantTimeEqual(cert.issuer, issuer.subject)) return false;
  if (issuer.isCa === false) return false;
  const matches = (cert.signatureAlgorithm === "rsa-sha256") === (issuer.keyType === "rsa") && (cert.signatureAlgorithm !== "ecdsa-sha384" || issuer.keyType === "ec-p384") && (cert.signatureAlgorithm !== "ecdsa-sha256" || issuer.keyType === "ec-p256");
  return matches && (await verifyWithSpki(issuer.spki, cert.signatureAlgorithm, cert.tbs, cert.signature));
}

export type ChainResult = { ok: true; anchor: Certificate } | { ok: false; reason: string };

/**
 * `chain[0]` is the leaf; each certificate must be signed by the next, and the last by (or be) one of `anchors`.
 * Every certificate must be within its validity period at `nowMs`; every issuer must be a CA (when it says so at all).
 */
export async function verifyChain(chain: Certificate[], anchors: Certificate[], nowMs: number): Promise<ChainResult> {
  if (chain.length === 0) return { ok: false, reason: "empty certificate chain" };
  if (anchors.length === 0) return { ok: false, reason: "no trust anchors are configured" };
  for (const c of chain) if (nowMs < c.notBeforeMs || nowMs > c.notAfterMs) return { ok: false, reason: "a certificate in the chain is outside its validity period" };
  for (let i = 0; i + 1 < chain.length; i++) if (!(await isSignedBy(chain[i] as Certificate, chain[i + 1] as Certificate))) return { ok: false, reason: "a certificate in the chain is not signed by the next one" };
  const last = chain[chain.length - 1] as Certificate;
  for (const a of anchors) {
    if (constantTimeEqual(a.der, last.der) && nowMs >= a.notBeforeMs && nowMs <= a.notAfterMs) return { ok: true, anchor: a };
    if (nowMs >= a.notBeforeMs && nowMs <= a.notAfterMs && (await isSignedBy(last, a))) return { ok: true, anchor: a };
  }
  return { ok: false, reason: "the chain does not lead to a configured trust anchor" };
}
