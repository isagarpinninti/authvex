import { describe, expect, it } from "vitest";
import {
  b64urlDecode, b64urlEncode, concat, encodeCbor, generateChallenge, hex, jwkToCose, parseCertificate, pemToDer, rawToDerSignature, sha256, verifyChain, verifyWebAuthnRegistration, utf8,
  type CborValue,
} from "../src";
import { ecLeaf, ecRoot, rsaRoot, rsaSignedLeaf, selfSigned } from "./fixtures/opensslCerts";

const RP = "app.example.com";
const ORIGIN = "https://app.example.com";
const NOW = Date.UTC(2030, 0, 1);
const subtle = globalThis.crypto.subtle;

/* ── a small DER writer, to build the hostile certificates the tests need ── */
const len = (n: number): number[] => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const tlv = (tag: number, body: Uint8Array | number[]): Uint8Array => Uint8Array.from([tag, ...len(body.length), ...body]);
const cat = (...p: Array<Uint8Array | number[]>): Uint8Array => Uint8Array.from(p.flatMap((x) => Array.from(x)));
const seq = (...p: Array<Uint8Array>): Uint8Array => tlv(0x30, cat(...p));
const oid = (s: string): Uint8Array => {
  const a = s.split(".").map(Number);
  const out: number[] = [(a[0] as number) * 40 + (a[1] as number)];
  for (const v of a.slice(2)) {
    const chunk = [v & 0x7f];
    for (let x = v >> 7; x > 0; x >>= 7) chunk.unshift((x & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, out);
};
const str = (s: string): Uint8Array => tlv(0x0c, utf8(s));
const time = (ms: number): Uint8Array => tlv(0x18, utf8(new Date(ms).toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z"));
const name = (a: { C?: string; O?: string; OU?: string; CN?: string }): Uint8Array => {
  const ids = { C: "2.5.4.6", O: "2.5.4.10", OU: "2.5.4.11", CN: "2.5.4.3" } as const;
  return seq(...(Object.entries(a) as Array<[keyof typeof ids, string]>).map(([k, v]) => tlv(0x31, seq(oid(ids[k]), str(v)))));
};

interface Pair { privateKey: CryptoKey; publicKey: CryptoKey; spki: Uint8Array; jwk: JsonWebKey }
const ec = async (): Promise<Pair> => {
  const p = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: p.privateKey, publicKey: p.publicKey, spki: new Uint8Array(await subtle.exportKey("spki", p.publicKey)), jwk: await subtle.exportKey("jwk", p.publicKey) };
};
const sign = async (key: CryptoKey, data: Uint8Array): Promise<Uint8Array> => rawToDerSignature(new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data as Uint8Array<ArrayBuffer>)));

async function makeCert(o: { subject: Parameters<typeof name>[0]; issuer?: Parameters<typeof name>[0]; key: Pair; signer: Pair; ca?: boolean; aaguid?: Uint8Array; notBefore?: number; notAfter?: number; version?: number }): Promise<Uint8Array> {
  const sigAlg = seq(oid("1.2.840.10045.4.3.2"));
  const exts: Uint8Array[] = [];
  if (o.ca !== undefined) exts.push(seq(oid("2.5.29.19"), tlv(0x01, [0xff]), tlv(0x04, seq(...(o.ca ? [tlv(0x01, [0xff])] : [])))));
  if (o.aaguid) exts.push(seq(oid("1.3.6.1.4.1.45724.1.1.4"), tlv(0x04, tlv(0x04, o.aaguid))));
  const tbs = seq(
    ...((o.version ?? 3) === 3 ? [tlv(0xa0, tlv(0x02, [2]))] : []),
    tlv(0x02, [1, 2, 3]), sigAlg, o.issuer ? name(o.issuer) : name(o.subject), seq(time(o.notBefore ?? Date.UTC(2020, 0, 1)), time(o.notAfter ?? Date.UTC(2040, 0, 1))), name(o.subject), o.key.spki,
    ...(exts.length ? [tlv(0xa3, seq(...exts))] : []),
  );
  return seq(tbs, sigAlg, tlv(0x03, cat([0], await sign(o.signer.privateKey, tbs))));
}

const root = await ec();
const rootName = { C: "SE", O: "Test Vendor", CN: "Test Root" };
const vendor = { C: "SE", O: "Test Vendor", OU: "Authenticator Attestation", CN: "Token 1" };
const rootCert = await makeCert({ subject: rootName, key: root, signer: root, ca: true });

/* ── a credential and its registration, built by hand so the attestation statement can be varied ── */
async function registration(build: (c: { authData: Uint8Array; clientDataHash: Uint8Array; credId: Uint8Array; cred: Pair; aaguid: Uint8Array; rpIdHash: Uint8Array }) => Promise<[string, Map<CborValue, CborValue>]>, aaguid = new Uint8Array(16).fill(7)) {
  const cred = await ec();
  const credId = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const rpIdHash = await sha256(RP);
  const idLen = new Uint8Array(2);
  new DataView(idLen.buffer).setUint16(0, credId.length);
  const authData = concat(rpIdHash, new Uint8Array([0x45]), new Uint8Array(4), aaguid, idLen, credId, encodeCbor(jwkToCose({ kty: "EC", crv: "P-256", x: cred.jwk.x, y: cred.jwk.y })));
  const challenge = generateChallenge();
  const clientDataJSON = utf8(JSON.stringify({ type: "webauthn.create", challenge, origin: ORIGIN, crossOrigin: false }));
  const clientDataHash = await sha256(clientDataJSON);
  const [fmt, attStmt] = await build({ authData, clientDataHash, credId, cred, aaguid, rpIdHash });
  const response = { clientDataJSON: b64urlEncode(clientDataJSON), attestationObject: b64urlEncode(encodeCbor(new Map<CborValue, CborValue>([["fmt", fmt], ["attStmt", attStmt], ["authData", authData]]))) };
  return { challenge, response, cred };
}
const verify = (r: { challenge: string; response: { clientDataJSON: string; attestationObject: string } }, attestation: Parameters<typeof verifyWebAuthnRegistration>[0]["attestation"]) =>
  verifyWebAuthnRegistration({ expected: { challenge: r.challenge, origin: ORIGIN, rpId: RP }, response: r.response, attestation: { nowMs: NOW, ...attestation } });

const packedBasic = (leafOver: Partial<Parameters<typeof makeCert>[0]> = {}, chainExtra: Uint8Array[] = [], signData?: (d: Uint8Array) => Uint8Array) => async (c: Parameters<Parameters<typeof registration>[0]>[0]) => {
  const att = await ec();
  const leaf = await makeCert({ subject: vendor, issuer: rootName, key: att, signer: root, ca: false, aaguid: c.aaguid, ...leafOver });
  const data = concat(c.authData, c.clientDataHash);
  return ["packed", new Map<CborValue, CborValue>([["alg", -7], ["sig", await sign(att.privateKey, signData ? signData(data) : data)], ["x5c", [leaf, ...chainExtra]]])] as [string, Map<CborValue, CborValue>];
};

describe("the X.509 reader, checked against OpenSSL's own certificates", () => {
  it("reads subject, dates, key type and constraints", () => {
    const c = parseCertificate(pemToDer(selfSigned)[0] as Uint8Array);
    expect(c.version).toBe(3);
    expect(c.subjectAttributes).toEqual({ C: ["SE"], O: ["Test Vendor AB"], OU: ["Authenticator Attestation"], CN: ["Test Attestation 0001"] });
    expect(c.keyType).toBe("ec-p256");
    expect(c.isCa).toBe(false);
    expect(c.signatureAlgorithm).toBe("ecdsa-sha256");
    expect(new Date(c.notAfterMs).getUTCFullYear()).toBe(2126);
    expect(parseCertificate(pemToDer(ecRoot)[0] as Uint8Array).isCa).toBe(true);
  });
  it("verifies the chains that openssl verify accepts, EC and RSA, and refuses them against the wrong root", async () => {
    const [ecr, ecl, rsar, rsal] = [ecRoot, ecLeaf, rsaRoot, rsaSignedLeaf].map((p) => parseCertificate(pemToDer(p)[0] as Uint8Array));
    expect(await verifyChain([ecl!], [ecr!], NOW)).toMatchObject({ ok: true });
    expect(await verifyChain([rsal!], [rsar!], NOW)).toMatchObject({ ok: true });
    expect(await verifyChain([ecl!], [rsar!], NOW)).toMatchObject({ ok: false });
    expect(await verifyChain([rsal!], [ecr!], NOW)).toMatchObject({ ok: false });
    expect(await verifyChain([ecl!], [ecr!], Date.UTC(2300, 0, 1))).toMatchObject({ ok: false, reason: expect.stringContaining("validity") });
    expect(await verifyChain([ecl!], [ecr!], Date.UTC(2000, 0, 1))).toMatchObject({ ok: false });
    expect(await verifyChain([ecl!], [], NOW)).toMatchObject({ ok: false });
  });
  it("refuses a certificate with a changed byte anywhere in the signed part", async () => {
    const der = pemToDer(ecLeaf)[0] as Uint8Array;
    const ca = parseCertificate(pemToDer(ecRoot)[0] as Uint8Array);
    let accepted = 0;
    for (let i = 0; i < der.length; i += 7) {
      const t = der.slice();
      t[i] = (t[i] as number) ^ 0x01;
      try {
        if ((await verifyChain([parseCertificate(t)], [ca], NOW)).ok) accepted++;
      } catch {
        /* a parse error is a refusal too */
      }
    }
    expect(accepted).toBe(0);
  });
});

describe("packed attestation", () => {
  it("accepts self attestation and says it proves nothing about the authenticator", async () => {
    const r = await registration(async (c) => ["packed", new Map<CborValue, CborValue>([["alg", -7], ["sig", await sign(c.cred.privateKey, concat(c.authData, c.clientDataHash))]])]);
    expect(await verify(r, { formats: ["none", "packed"] })).toMatchObject({ ok: true, attestation: { format: "packed", type: "self", trusted: false } });
    expect(await verify(r, { formats: ["packed"], requireTrusted: true })).toMatchObject({ ok: false, reason: "attestation_untrusted" });
  });
  it("refuses self attestation signed by a different key", async () => {
    const other = await ec();
    const r = await registration(async (c) => ["packed", new Map<CborValue, CborValue>([["alg", -7], ["sig", await sign(other.privateKey, concat(c.authData, c.clientDataHash))]])]);
    expect(await verify(r, { formats: ["packed"] })).toMatchObject({ ok: false, reason: "attestation_invalid" });
  });
  it("accepts a chain to a trusted root, reports who made the authenticator, and records the AAGUID", async () => {
    const r = await registration(packedBasic());
    const res = await verify(r, { formats: ["packed"], trustAnchors: [rootCert], requireTrusted: true });
    expect(res).toMatchObject({ ok: true, attestation: { format: "packed", type: "basic", trusted: true, aaguid: hex(new Uint8Array(16).fill(7)), certificate: { subject: { O: ["Test Vendor"], CN: ["Token 1"] } } } });
  });
  it("follows an intermediate", async () => {
    const mid = await ec();
    const midName = { C: "SE", O: "Test Vendor", CN: "Test Intermediate" };
    const midCert = await makeCert({ subject: midName, issuer: rootName, key: mid, signer: root, ca: true });
    const r = await registration(async (c) => {
      const att = await ec();
      const leaf = await makeCert({ subject: vendor, issuer: midName, key: att, signer: mid, ca: false, aaguid: c.aaguid });
      return ["packed", new Map<CborValue, CborValue>([["alg", -7], ["sig", await sign(att.privateKey, concat(c.authData, c.clientDataHash))], ["x5c", [leaf, midCert]]])];
    });
    expect(await verify(r, { formats: ["packed"], trustAnchors: [rootCert], requireTrusted: true })).toMatchObject({ ok: true, attestation: { trusted: true } });
  });
  it("reports an unknown root as untrusted, and refuses it when trust is required", async () => {
    const stranger = await ec();
    const strangerCert = await makeCert({ subject: { CN: "Someone Else" }, key: stranger, signer: stranger, ca: true });
    const r = await registration(packedBasic());
    expect(await verify(r, { formats: ["packed"], trustAnchors: [strangerCert] })).toMatchObject({ ok: true, attestation: { trusted: false, type: "basic" } });
    expect(await verify(r, { formats: ["packed"], trustAnchors: [strangerCert], requireTrusted: true })).toMatchObject({ ok: false, reason: "attestation_untrusted" });
    expect(await verify(r, { formats: ["packed"], requireTrusted: true })).toMatchObject({ ok: false, reason: "attestation_untrusted" });
  });
  it("refuses an expired attestation certificate when trust is required", async () => {
    const r = await registration(packedBasic({ notAfter: Date.UTC(2025, 0, 1) }));
    expect(await verify(r, { formats: ["packed"], trustAnchors: [rootCert], requireTrusted: true })).toMatchObject({ ok: false, reason: "attestation_untrusted" });
  });
  it("refuses a signature over other data, and a leaf that breaks the packed rules", async () => {
    const wrongData = await registration(packedBasic({}, [], (d) => d.slice(1)));
    expect(await verify(wrongData, { formats: ["packed"], trustAnchors: [rootCert] })).toMatchObject({ ok: false, reason: "attestation_invalid" });
    const wrongOu = await registration(packedBasic({ subject: { ...vendor, OU: "Something Else" } }));
    expect(await verify(wrongOu, { formats: ["packed"], trustAnchors: [rootCert] })).toMatchObject({ ok: false, message: expect.stringContaining("Authenticator Attestation") });
    const aaguidMismatch = await registration(packedBasic({ aaguid: new Uint8Array(16).fill(9) }));
    expect(await verify(aaguidMismatch, { formats: ["packed"], trustAnchors: [rootCert] })).toMatchObject({ ok: false, message: expect.stringContaining("AAGUID") });
    const isCa = await registration(packedBasic({ ca: true }));
    expect(await verify(isCa, { formats: ["packed"], trustAnchors: [rootCert] })).toMatchObject({ ok: false, message: expect.stringContaining("must not be a CA") });
    const v1 = await registration(packedBasic({ version: 1 }));
    expect(await verify(v1, { formats: ["packed"], trustAnchors: [rootCert] })).toMatchObject({ ok: false });
  });
  it("refuses a malformed x5c with a reason instead of crashing", async () => {
    for (const x5c of [[new Uint8Array([1, 2, 3])], [], "text", [new Uint8Array(0)]]) {
      const r = await registration(async () => ["packed", new Map<CborValue, CborValue>([["alg", -7], ["sig", new Uint8Array(70)], ["x5c", x5c as CborValue]])]);
      expect(await verify(r, { formats: ["packed"] })).toMatchObject({ ok: false, reason: "attestation_invalid" });
    }
  });
  it("refuses algorithms it does not implement", async () => {
    const r = await registration(async () => ["packed", new Map<CborValue, CborValue>([["alg", -257], ["sig", new Uint8Array(70)]])]);
    expect(await verify(r, { formats: ["packed"] })).toMatchObject({ ok: false, reason: "unsupported_attestation" });
  });
});

describe("fido-u2f attestation", () => {
  const u2f = (over: { aaguid?: Uint8Array; tamper?: boolean } = {}) => async (c: Parameters<Parameters<typeof registration>[0]>[0]) => {
    const att = await ec();
    const leaf = await makeCert({ subject: { C: "SE", O: "Old Vendor", CN: "U2F 1" }, issuer: rootName, key: att, signer: root });
    const x = b64urlDecode(c.cred.jwk.x as string);
    const y = b64urlDecode(c.cred.jwk.y as string);
    const data = concat(new Uint8Array([0]), c.rpIdHash, c.clientDataHash, c.credId, new Uint8Array([4]), x, y);
    if (over.tamper) data[3] = (data[3] as number) ^ 1;
    return ["fido-u2f", new Map<CborValue, CborValue>([["sig", await sign(att.privateKey, data)], ["x5c", [leaf]]])] as [string, Map<CborValue, CborValue>];
  };
  it("accepts a valid statement with a zero AAGUID, trusted through the root", async () => {
    const r = await registration(u2f(), new Uint8Array(16));
    expect(await verify(r, { formats: ["fido-u2f"], trustAnchors: [rootCert], requireTrusted: true })).toMatchObject({ ok: true, attestation: { format: "fido-u2f", type: "basic", trusted: true } });
  });
  it("refuses a non-zero AAGUID and a signature over altered data", async () => {
    expect(await verify(await registration(u2f()), { formats: ["fido-u2f"] })).toMatchObject({ ok: false, message: expect.stringContaining("AAGUID") });
    expect(await verify(await registration(u2f({ tamper: true }), new Uint8Array(16)), { formats: ["fido-u2f"] })).toMatchObject({ ok: false, reason: "attestation_invalid" });
  });
});

describe("formats that are not accepted", () => {
  it("only accepts none unless told otherwise, and refuses formats it cannot verify even when asked", async () => {
    const packed = await registration(async (c) => ["packed", new Map<CborValue, CborValue>([["alg", -7], ["sig", await sign(c.cred.privateKey, concat(c.authData, c.clientDataHash))]])]);
    expect(await verify(packed, undefined)).toMatchObject({ ok: false, reason: "unsupported_attestation" });
    for (const fmt of ["tpm", "android-key", "android-safetynet", "apple"]) {
      const r = await registration(async () => [fmt, new Map<CborValue, CborValue>()]);
      expect(await verify(r, { formats: ["none", "packed", "fido-u2f", fmt as never] })).toMatchObject({ ok: false, reason: "unsupported_attestation" });
    }
  });
  it("a policy that requires trust refuses the plain 'none' attestation", async () => {
    const r = await registration(async () => ["none", new Map()]);
    expect(await verify(r, {})).toMatchObject({ ok: true, attestation: { type: "none", trusted: false } });
    expect(await verify(r, { requireTrusted: true })).toMatchObject({ ok: false, reason: "attestation_untrusted" });
  });
});
