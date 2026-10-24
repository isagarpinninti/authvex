import { toBytes, type Bytes } from "../util/bytes";

/** A deliberately small CBOR (RFC 8949) subset: what WebAuthn attestation objects and COSE keys use. */
export type CborValue = number | string | Uint8Array | boolean | null | CborValue[] | Map<CborValue, CborValue>;

const MAX_DEPTH = 8;

export class CborError extends Error {}

function readLength(b: Uint8Array, at: number, info: number): { len: number; next: number } {
  if (info < 24) return { len: info, next: at };
  const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
  if (size === 0) throw new CborError("indefinite or reserved length is not supported");
  if (at + size > b.length) throw new CborError("truncated length");
  let n = 0;
  for (let i = 0; i < size; i++) n = n * 256 + (b[at + i] as number);
  if (!Number.isSafeInteger(n)) throw new CborError("length too large");
  return { len: n, next: at + size };
}

/** Decodes one item starting at `offset`; returns the value and the offset just past it. */
export function decodeCbor(b: Uint8Array, offset = 0, depth = 0): { value: CborValue; next: number } {
  if (depth > MAX_DEPTH) throw new CborError("nesting too deep");
  if (offset >= b.length) throw new CborError("unexpected end of data");
  const initial = b[offset] as number;
  const major = initial >> 5;
  const info = initial & 0x1f;
  const { len, next } = readLength(b, offset + 1, info);
  switch (major) {
    case 0:
      return { value: len, next };
    case 1:
      return { value: -1 - len, next };
    case 2:
    case 3: {
      if (next + len > b.length) throw new CborError("truncated string");
      const slice = b.slice(next, next + len);
      if (major === 2) return { value: slice, next: next + len };
      try {
        return { value: new TextDecoder("utf-8", { fatal: true }).decode(slice), next: next + len };
      } catch {
        throw new CborError("text is not valid UTF-8");
      }
    }
    case 4: {
      if (len > b.length - next) throw new CborError("array longer than the data");
      const out: CborValue[] = [];
      let at = next;
      for (let i = 0; i < len; i++) {
        const item = decodeCbor(b, at, depth + 1);
        out.push(item.value);
        at = item.next;
      }
      return { value: out, next: at };
    }
    case 5: {
      if (len > b.length - next) throw new CborError("map longer than the data");
      const out = new Map<CborValue, CborValue>();
      let at = next;
      for (let i = 0; i < len; i++) {
        const k = decodeCbor(b, at, depth + 1);
        const v = decodeCbor(b, k.next, depth + 1);
        if (out.has(k.value)) throw new CborError("duplicate map key");
        out.set(k.value, v.value);
        at = v.next;
      }
      return { value: out, next: at };
    }
    case 7:
      if (info === 20) return { value: false, next };
      if (info === 21) return { value: true, next };
      if (info === 22) return { value: null, next };
      throw new CborError("unsupported simple value or float");
    default:
      throw new CborError(`unsupported major type ${major}`);
  }
}

export function decodeCborExact(b: Uint8Array): CborValue {
  const r = decodeCbor(b, 0);
  if (r.next !== b.length) throw new CborError("trailing bytes after the item");
  return r.value;
}

/* A matching encoder, used by the software authenticator and tests. Map keys keep insertion order. */

function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 0x100) return [(major << 5) | 24, n];
  if (n < 0x10000) return [(major << 5) | 25, n >> 8, n & 0xff];
  return [(major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

export function encodeCbor(v: CborValue): Bytes {
  const out: number[] = [];
  const put = (x: CborValue): void => {
    if (typeof x === "number") out.push(...(x >= 0 ? head(0, x) : head(1, -1 - x)));
    else if (typeof x === "string") {
      const u = new TextEncoder().encode(x);
      out.push(...head(3, u.length), ...u);
    } else if (x instanceof Uint8Array) out.push(...head(2, x.length), ...x);
    else if (typeof x === "boolean") out.push(x ? 0xf5 : 0xf4);
    else if (x === null) out.push(0xf6);
    else if (Array.isArray(x)) {
      out.push(...head(4, x.length));
      for (const i of x) put(i);
    } else {
      out.push(...head(5, x.size));
      for (const [k, val] of x) {
        put(k);
        put(val);
      }
    }
  };
  put(v);
  return toBytes(new Uint8Array(out));
}
