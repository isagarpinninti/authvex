"use client";

import { useState, type ReactNode } from "react";

function Snippet({ title, code }: { title: string; code: string }): ReactNode {
  const [copied, setCopied] = useState(false);
  return (
    <figure className="av-card grid gap-2">
      <figcaption className="flex items-center justify-between gap-2"><span className="av-h">{title}</span>
        <button type="button" className="av-btn av-btn-sm" onClick={() => { void navigator.clipboard?.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>{copied ? "Copied" : "Copy"}</button>
      </figcaption>
      <pre className="av-mono overflow-auto rounded-md border border-line bg-bg p-3 text-[12px] leading-relaxed" tabIndex={0}><code>{code}</code></pre>
    </figure>
  );
}

export function SdkView({ baseUrl, tenantId }: { baseUrl: string; tenantId: string }): ReactNode {
  const base = baseUrl.replace(/\/$/, "");
  return (
    <div className="grid gap-4">
      <p className="text-muted">Everything the Studio does goes through the same API and components your app uses.</p>
      <Snippet title="Embed the sign-in card" code={`import "@authvex/react/styles.css";
import { ZeroTrustLoginCard } from "@authvex/react";

export function SignIn() {
  return (
    <ZeroTrustLoginCard
      baseUrl="${base}"
      tenantId="${tenantId}"
      onSession={(s) => { /* keep s.sessionToken and s.refreshToken in memory */ }}
    />
  );
}`} />
      <Snippet title="Protect an API route (any language: it is one HTTP call)" code={`curl -X POST ${base}/api/auth/dpop-verify \\
  -H "content-type: application/json" \\
  -d '{
    "sessionToken": "'"$SESSION_TOKEN"'",
    "dpopProof":   "'"$DPOP_HEADER"'",
    "method": "GET",
    "url": "https://api.example.com/v1/invoices",
    "requirePermission": "invoices:read"
  }'
# 200 { "valid": true, "bound": true, "claims": { ... } }
# 401 { "valid": false, "reason": "dpop_missing" | "key_mismatch" | "replayed" | "session_revoked" | ... }`} />
      <Snippet title="Verify without the server (edge or worker)" code={`import { verifyDpopSessionRequest, DpopReplayCache } from "@authvex/core";

const replay = new DpopReplayCache();
const result = await verifyDpopSessionRequest({
  sessionToken, dpopProof: request.headers.get("dpop") ?? undefined,
  method: request.method, url: request.url,
  issuerPublicKeyJwk: ISSUER_PUBLIC_JWK, // GET ${base}/api/workspace -> issuer
  replayCache: replay, requireBinding: true,
});
if (!result.ok) return new Response(result.message, { status: 401 });`} />
      <Snippet title="Machine keys and break-glass from the shell" code={`authvex key mint --tenant ${tenantId} --name ci --scopes invoices:read --rate 120
curl -X POST ${base}/api/verify -d '{"token":"atk_live_…","scope":"invoices:read"}' -H 'content-type: application/json'

authvex impersonate --actor usr_root --target usr_grace --tenant ${tenantId} \\
  --reason "TICKET-4411 customer cannot see invoices" --ttl 600
authvex ledger verify`} />
    </div>
  );
}
