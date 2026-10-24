/** Byte helpers on Web Crypto only, so the same code runs in Node 20+, edge runtimes and browsers. */

export type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const utf8 = (s: string): Bytes => encoder.encode(s) as Bytes;
export const fromUtf8 = (b: Uint8Array): string => decoder.decode(b);

/** A copy backed by a plain ArrayBuffer, which is what Web Crypto's types ask for. */
export const toBytes = (b: Uint8Array | ArrayBuffer): Bytes => new Uint8Array(b as ArrayBuffer) as Bytes;

export function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out as Bytes;
}

export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out as Bytes;
}

export function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict base64url: only the URL-safe alphabet, no padding. Throws on anything else. */
export function b64urlDecode(s: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new TypeError("not valid base64url");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out as Bytes;
}

export const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export function fromHex(s: string): Bytes {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(s)) throw new TypeError("not valid hex");
  return Uint8Array.from(s.match(/../g) ?? [], (h) => Number.parseInt(h, 16)) as Bytes;
}

export async function sha256(data: Uint8Array | string): Promise<Bytes> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", typeof data === "string" ? utf8(data) : toBytes(data))) as Bytes;
}

/** Compares two byte strings in time that depends only on their length, never on where they differ. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export const constantTimeEqualStr = (a: string, b: string): boolean => constantTimeEqual(utf8(a), utf8(b));
