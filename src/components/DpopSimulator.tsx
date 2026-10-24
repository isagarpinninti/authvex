"use client";

import { useState, type ReactNode } from "react";
import { createDeviceKey, dpopHeader, request, type ApiOptions, type AuthvexSession } from "@authvex/react";

interface Result {
  label: string;
  http: number;
  valid: boolean;
  reason?: string;
  message?: string;
}

/**
 * The attack lab. A resource server asks Authvex "is this request really from the session's owner?". Send the same request
 * as the owner, as a thief with only the token, as a thief with a key of their own, and by replaying a captured proof.
 */
export function DpopSimulator({ api, session }: { api: Required<ApiOptions>; session: AuthvexSession | null }): ReactNode {
  const [results, setResults] = useState<Result[]>([]);
  const [busy, setBusy] = useState(false);
  const [captured, setCaptured] = useState<string | null>(null);
  const url = `${api.baseUrl.replace(/\/$/, "")}/v1/invoices`;

  const send = async (label: string, proof: string | null, tokenOverride?: string): Promise<void> => {
    if (!session) return;
    setBusy(true);
    try {
      const r = await request<{ valid?: boolean; reason?: string; message?: string }>({ baseUrl: api.baseUrl }, "POST", "/api/auth/dpop-verify", { sessionToken: tokenOverride ?? session.sessionToken, method: "GET", url, ...(proof ? { dpopProof: proof } : {}) });
      setResults((l) => [{ label, http: r.status, valid: r.body.valid === true, ...(r.body.reason ? { reason: r.body.reason } : {}), ...(r.body.message ? { message: r.body.message } : {}) }, ...l].slice(0, 8));
    } finally {
      setBusy(false);
    }
  };

  const owner = async (): Promise<void> => {
    if (!session?.deviceKey) return;
    const proof = await dpopHeader(session.deviceKey, "GET", url, session.sessionToken);
    setCaptured(proof);
    await send("The owner, signing with the device key", proof);
  };
  const thiefNoKey = (): Promise<void> => send("A thief with only the stolen token", null);
  const thiefOwnKey = async (): Promise<void> => {
    if (!session) return;
    const thief = await createDeviceKey();
    await send("A thief signing with their own key", await dpopHeader(thief, "GET", url, session.sessionToken));
  };
  const replayProof = async (): Promise<void> => {
    if (captured) await send("A thief replaying the owner's captured proof", captured);
  };

  const bound = session?.tokenType === "DPoP";
  return (
    <section aria-label="DPoP and token-replay simulator" className="av-card">
      <header className="av-card-head"><h3 className="av-h">Stolen-token lab</h3><span className="av-badge">RFC 9449</span></header>
      {!session ? <p className="av-muted">Sign in first (use a bound tenant such as Acme Fintech) to get a session to attack.</p> : (
        <div className="grid gap-3">
          <p className="av-muted">{bound ? "This session is bound to this browser's key. Whoever holds only the token should be refused." : "This session is a plain bearer token: anyone holding it wins. Sign in on a tenant that binds sessions to see the difference."}</p>
          <div className="av-row">
            <button type="button" className="av-btn av-btn-primary" onClick={() => void owner()} disabled={busy || !session.deviceKey}>Request as the owner</button>
            <button type="button" className="av-btn" onClick={() => void thiefNoKey()} disabled={busy}>Replay the stolen cookie (no key)</button>
            <button type="button" className="av-btn" onClick={() => void thiefOwnKey()} disabled={busy}>Thief with their own key</button>
            <button type="button" className="av-btn" onClick={() => void replayProof()} disabled={busy || !captured}>Replay a captured proof</button>
          </div>
          <ol className="grid gap-1.5" aria-label="Results" aria-live="polite">
            {results.length === 0 ? <li className="av-muted">No requests yet.</li> : results.map((r, i) => (
              <li key={i} className={`rounded-md border border-line border-l-4 px-3 py-1.5 ${r.valid ? "border-l-ok" : "border-l-err"}`}>
                <div className="font-medium">{r.label}</div>
                <div className={r.valid ? "av-ok-text" : "av-err-text"}><span aria-hidden="true">{r.valid ? "✓" : "✕"}</span> <span className="av-sr">{r.valid ? "Accepted" : "Refused"}: </span>{r.valid ? "accepted" : `refused (${r.reason ?? r.http})`}{r.message ? ` · ${r.message}` : ""}</div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}
