"use client";

import { useEffect, useState, type ReactNode } from "react";
import { request, type ApiOptions, type LedgerEntryView } from "@authvex/react";

const TONE: Record<string, string> = { "auth.family.reuse_detected": "text-err-ink", "auth.login.blocked": "text-err-ink", "auth.dpop.rejected": "text-err-ink", "auth.passkey.clone_suspected": "text-err-ink", "impersonation.minted": "text-amber-ink", "auth.login": "text-ok-ink" };

export function LedgerFeed({ api }: { api: Required<ApiOptions> }): ReactNode {
  const [entries, setEntries] = useState<LedgerEntryView[]>([]);
  const [chain, setChain] = useState<{ ok: boolean; entries: number; brokenAt?: number; reason?: string } | null>(null);
  const [enabled, setEnabled] = useState(true);

  useEffect(() => {
    let live = true;
    const load = async (): Promise<void> => {
      if (document.visibilityState === "hidden") return;
      try {
        const [l, v] = await Promise.all([request<{ entries: LedgerEntryView[]; enabled: boolean }>(api, "GET", "/api/ledger?limit=60"), request<{ ok: boolean; entries: number; brokenAt?: number; reason?: string }>(api, "GET", "/api/ledger/verify")]);
        if (!live) return;
        if (l.status === 200) {
          setEntries(l.body.entries.slice().reverse());
          setEnabled(l.body.enabled);
        }
        if (v.status === 200) setChain(v.body);
      } catch {
        /* the next poll will try again */
      }
    };
    void load();
    const id = setInterval(() => void load(), 2000);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, [api]);

  return (
    <section aria-label="Security ledger" className="grid content-start gap-2">
      <div className="flex items-center justify-between gap-2">
        <h2 className="av-h2">Ledger</h2>
        {chain ? <span className={`av-badge ${chain.ok ? "av-badge-ok" : "av-badge-err"}`} role="status">{chain.ok ? `chain intact · ${chain.entries}` : `broken at #${chain.brokenAt}`}</span> : null}
      </div>
      {!enabled ? <p className="text-muted">The ledger is disabled on this server.</p> : null}
      <div className="max-h-[640px] overflow-auto" tabIndex={0} role="region" aria-label="Recent security events"><ol className="grid gap-1">
        {entries.length === 0 ? <li className="text-muted">No events yet.</li> : entries.map((e) => (
          <li key={e.n} className="rounded-md border border-line px-2 py-1.5">
            <div className="flex items-baseline justify-between gap-2"><span className={`av-mono text-[12.5px] font-semibold ${TONE[e.type] ?? ""}`}>{e.type}</span><span className="av-mono text-[11px] text-muted">#{e.n}</span></div>
            <div className="text-[12px] text-muted">{new Date(e.ts).toLocaleTimeString()}{e.tenantId ? ` · ${e.tenantId}` : ""}{e.actor ? ` · by ${e.actor}` : ""}{e.subject ? ` · on ${e.subject}` : ""}</div>
            {typeof e.detail["reason"] === "string" || typeof e.detail["code"] === "string" ? <div className="text-[12px]">{String(e.detail["code"] ?? "")} {String(e.detail["reason"] ?? "")}</div> : null}
          </li>
        ))}
      </ol></div>
    </section>
  );
}
