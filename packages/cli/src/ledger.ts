import { createHash } from "node:crypto";
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, appendFileSync } from "node:fs";
import { dirname } from "node:path";

/** One line of the security ledger. `hash` covers every other field, including the previous entry's hash. */
export interface LedgerEntry {
  n: number;
  ts: number;
  /** Dotted event type, e.g. `auth.login`, `auth.family.reuse_detected`, `key.minted`. */
  type: string;
  tenantId?: string;
  /** Who did it (a user id, `cli`, `studio`). */
  actor?: string;
  /** Who or what it was done to. */
  subject?: string;
  /** Non-secret facts. Never put a password, token or key here. */
  detail: Record<string, unknown>;
  prev: string;
  hash: string;
}

export const GENESIS = "0".repeat(64);
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

/** Stable JSON (sorted keys) so the same facts always hash the same. */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).filter((k) => obj[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

const entryHash = (e: Omit<LedgerEntry, "hash">): string => sha256(canonicalJson([e.n, e.ts, e.type, e.tenantId ?? null, e.actor ?? null, e.subject ?? null, e.detail, e.prev]));

/** The last complete line of a file, read from its tail so a large ledger costs one small read. */
function lastLine(path: string): string | null {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return null;
    let want = Math.min(size, 8192);
    for (;;) {
      const buf = Buffer.alloc(want);
      readSync(fd, buf, 0, want, size - want);
      const text = buf.toString("utf8").replace(/\n+$/, "");
      const nl = text.lastIndexOf("\n");
      if (nl >= 0 || want === size) return text.slice(nl + 1);
      want = Math.min(size, want * 2);
    }
  } finally {
    closeSync(fd);
  }
}

/**
 * An append-only, hash-chained log of security events. It re-reads the last entry before each append, so the CLI and a running
 * server can share one file without forking the chain. Editing, removing or reordering a line breaks the chain from there on.
 */
export class Ledger {
  constructor(readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
  }

  private tail(): { n: number; hash: string } {
    if (!existsSync(this.path)) return { n: 0, hash: GENESIS };
    const line = lastLine(this.path);
    if (!line) return { n: 0, hash: GENESIS };
    try {
      const e = JSON.parse(line) as LedgerEntry;
      return { n: e.n, hash: e.hash };
    } catch {
      throw new Error(`ledger ${this.path} is corrupt: its last line is not valid JSON`);
    }
  }

  append(info: { type: string; tenantId?: string; actor?: string; subject?: string; detail?: Record<string, unknown>; ts?: number }): LedgerEntry {
    const t = this.tail();
    const body: Omit<LedgerEntry, "hash"> = {
      n: t.n + 1, ts: info.ts ?? Date.now(), type: info.type, ...(info.tenantId ? { tenantId: info.tenantId } : {}), ...(info.actor ? { actor: info.actor } : {}), ...(info.subject ? { subject: info.subject } : {}),
      detail: info.detail ?? {}, prev: t.hash,
    };
    const entry: LedgerEntry = { ...body, hash: entryHash(body) };
    appendFileSync(this.path, `${JSON.stringify(entry)}\n`);
    return entry;
  }

  list(limit = 100): LedgerEntry[] {
    if (!existsSync(this.path)) return [];
    const lines = readFileSync(this.path, "utf8").split("\n").filter(Boolean);
    return lines.slice(-limit).map((l) => JSON.parse(l) as LedgerEntry);
  }
}

export type LedgerCheck = { ok: true; entries: number; head: string } | { ok: false; entries: number; head: string; brokenAt: number; reason: string };

export function verifyLedger(path: string): LedgerCheck {
  if (!existsSync(path)) return { ok: true, entries: 0, head: GENESIS };
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const at = i + 1;
    let e: LedgerEntry;
    try {
      e = JSON.parse(lines[i] as string) as LedgerEntry;
    } catch {
      return { ok: false, entries: i, head: prev, brokenAt: at, reason: "line is not valid JSON" };
    }
    if (e.n !== at) return { ok: false, entries: i, head: prev, brokenAt: at, reason: `expected entry ${at}, found ${String(e.n)} (an entry was removed or reordered)` };
    if (e.prev !== prev) return { ok: false, entries: i, head: prev, brokenAt: at, reason: "does not continue the previous entry" };
    const { hash, ...body } = e;
    if (entryHash(body) !== hash) return { ok: false, entries: i, head: prev, brokenAt: at, reason: "contents do not match their hash (the entry was edited)" };
    prev = hash;
  }
  return { ok: true, entries: lines.length, head: prev };
}
