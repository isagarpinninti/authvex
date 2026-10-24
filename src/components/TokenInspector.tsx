"use client";

import { useState, type ReactNode } from "react";
import { request, type ApiOptions } from "@authvex/react";

export function TokenInspector({ api }: { api: Required<ApiOptions> }): ReactNode {
  const [token, setToken] = useState("");
  const [out, setOut] = useState<string | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);

  const check = async (): Promise<void> => {
    const r = await request<{ valid?: boolean; error?: string }>({ baseUrl: api.baseUrl }, "POST", "/api/verify", { token: token.trim() });
    setValid(r.body.valid ?? false);
    setOut(JSON.stringify(r.body, null, 2));
  };
  return (
    <section aria-label="Token inspector" className="grid content-start gap-2">
      <h2 className="av-h2">Token inspector</h2>
      <label className="av-field"><span>Paste an ath_ or atk_ token</span><textarea className="av-input av-mono min-h-20 text-[12px]" value={token} onChange={(e) => setToken(e.target.value)} spellCheck={false} /></label>
      <div><button type="button" className="av-btn" onClick={() => void check()} disabled={!token.trim()}>Verify</button></div>
      {out ? (
        <div role="status">
          <p className={valid ? "av-ok-text" : "av-err-text"}>{valid ? "Valid" : "Not valid"}</p>
          <pre className="av-mono max-h-56 overflow-auto rounded-md border border-line bg-bg p-2 text-[11.5px]" tabIndex={0}>{out}</pre>
        </div>
      ) : null}
    </section>
  );
}
