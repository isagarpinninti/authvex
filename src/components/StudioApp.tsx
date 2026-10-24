"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  ActiveSessionsAndPasskeysPanel, TenantRbacAndImpersonationStudio, ThreatRadarWorkbench, ZeroTrustLoginCard, request, useWorkspace, type AuthvexSession,
} from "@authvex/react";
import { AuthvexLogo } from "./brand/AuthvexLogo";
import { ConnectForm } from "./ConnectForm";
import { Directory } from "./Directory";
import { DpopSimulator } from "./DpopSimulator";
import { LedgerFeed } from "./LedgerFeed";
import { SdkView } from "./SdkView";
import { ThemeToggle } from "./ThemeToggle";
import { TokenInspector } from "./TokenInspector";
import { forgetConnection, guessBaseUrl, readConnection, saveConnection, type Connection } from "../lib/connection";
import { readFlow, type EmailFlow } from "../lib/flow";

type Tab = "lab" | "radar" | "rbac" | "sdk";
const TABS: Array<{ id: Tab; label: string }> = [
  { id: "lab", label: "Identity lab" },
  { id: "radar", label: "Threat radar" },
  { id: "rbac", label: "Roles and break-glass" },
  { id: "sdk", label: "SDK" },
];

export function StudioApp(): ReactNode {
  const [conn, setConn] = useState<Connection | null>(null);
  const [ready, setReady] = useState(false);
  const [problem, setProblem] = useState("");
  const [flow, setFlow] = useState<EmailFlow | null>(null);

  useEffect(() => {
    const f = readFlow();
    if (f) {
      setFlow(f);
      setReady(true);
      return;
    }
    const c = readConnection();
    if (c) {
      saveConnection(c);
      setConn(c);
    }
    setReady(true);
  }, []);

  if (!ready) return null;
  if (flow) return <EmailLinkScreen flow={flow} />;
  if (!conn) return <ConnectForm initialError={problem} onConnect={(c) => { saveConnection(c); setProblem(""); setConn(c); }} />;
  return <Studio conn={conn} onDisconnect={(why) => { forgetConnection(); setProblem(why); setConn(null); }} />;
}

function Studio({ conn, onDisconnect }: { conn: Connection; onDisconnect(reason: string): void }): ReactNode {
  const api = useMemo(() => ({ baseUrl: conn.baseUrl, adminToken: conn.token }), [conn]);
  const ws = useWorkspace(api, 5000);
  const [tab, setTab] = useState<Tab>("lab");
  const [tenantId, setTenantId] = useState("");
  const [session, setSession] = useState<AuthvexSession | null>(null);

  useEffect(() => {
    if (!tenantId && ws.data?.tenants[0]) setTenantId(ws.data.tenants.find((t) => t.requireDpopHardwareBinding)?.id ?? ws.data.tenants[0].id);
  }, [tenantId, ws.data]);

  useEffect(() => {
    const ctl = new AbortController();
    request<{ error?: string }>(api, "GET", "/api/ledger/verify").then(
      (r) => {
        if (r.status === 401 && !ctl.signal.aborted) onDisconnect("That token was refused. Admin tokens last 24 hours: restart `authvex studio` or open its latest link.");
      },
      () => undefined,
    );
    return () => ctl.abort();
  }, [api, onDisconnect]);

  return (
    <>
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-ink focus:px-3 focus:py-2 focus:text-bg">Skip to content</a>
      <div className="flex min-h-screen flex-col">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
          <div className="flex items-center gap-4">
            <AuthvexLogo />
            <span className="text-muted">Studio</span>
          </div>
          <div className="flex items-center gap-3">
            <span className={`av-badge ${ws.data ? "av-badge-ok" : ""}`} role="status">{ws.data ? `connected · issuer ${ws.data.issuer.kid.slice(0, 8)}` : ws.error ? "unreachable" : "connecting…"}</span>
            <ThemeToggle />
            <button type="button" className="av-btn" onClick={() => onDisconnect("")}>Disconnect</button>
          </div>
        </header>
        <div className="grid flex-1 gap-4 p-4 lg:grid-cols-[260px_minmax(0,1fr)_300px]">
          <div className="lg:sticky lg:top-4 lg:self-start">
            <Directory api={api} tenantId={tenantId} onTenant={(id) => { setTenantId(id); setSession(null); }} />
          </div>
          <main id="main" className="min-w-0">
            <div role="tablist" aria-label="Views" className="mb-4 flex flex-wrap gap-1 border-b border-line">
              {TABS.map((t) => (
                <button
                  key={t.id} role="tab" type="button" id={`tab-${t.id}`} aria-selected={tab === t.id} aria-controls={`panel-${t.id}`} tabIndex={tab === t.id ? 0 : -1} onClick={() => setTab(t.id)}
                  onKeyDown={(e) => {
                    const i = TABS.findIndex((x) => x.id === tab);
                    const n = e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 : e.key === "Home" ? 0 : e.key === "End" ? TABS.length - 1 : -1;
                    if (n < 0) return;
                    e.preventDefault();
                    const target = TABS[(n + TABS.length) % TABS.length];
                    if (target) {
                      setTab(target.id);
                      document.getElementById(`tab-${target.id}`)?.focus();
                    }
                  }}
                  className={`-mb-px border-b-2 px-3 py-2 ${tab === t.id ? "border-amber font-semibold text-ink" : "border-transparent text-muted hover:text-ink"}`}
                >
                  {t.label}
                </button>
              ))}
            </div>
            {/* The lab stays mounted (hidden) so a session survives a look at the other tabs. */}
            <div role="tabpanel" id="panel-lab" aria-labelledby="tab-lab" tabIndex={0} hidden={tab !== "lab"} className="grid gap-4">
              {tenantId ? (
                <>
                  <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
                    <ZeroTrustLoginCard key={tenantId} baseUrl={conn.baseUrl} tenantId={tenantId} onSession={setSession} features={{ passwordReset: true, magicLink: true, signUp: true, passkeyOnlySignUp: true }} />
                    <DpopSimulator api={api} session={session} />
                  </div>
                  <ActiveSessionsAndPasskeysPanel baseUrl={conn.baseUrl} adminToken={conn.token} session={session} onSessionChange={setSession} />
                </>
              ) : <p className="av-muted">Loading tenants…</p>}
            </div>
            {tab === "radar" ? <div role="tabpanel" id="panel-radar" aria-labelledby="tab-radar" tabIndex={0}><ThreatRadarWorkbench baseUrl={conn.baseUrl} adminToken={conn.token} {...(tenantId ? { tenantId } : {})} /></div> : null}
            {tab === "rbac" ? <div role="tabpanel" id="panel-rbac" aria-labelledby="tab-rbac" tabIndex={0}><TenantRbacAndImpersonationStudio baseUrl={conn.baseUrl} adminToken={conn.token} /></div> : null}
            {tab === "sdk" ? <div role="tabpanel" id="panel-sdk" aria-labelledby="tab-sdk" tabIndex={0}><SdkView baseUrl={conn.baseUrl} tenantId={tenantId || "your_tenant"} /></div> : null}
          </main>
          <aside aria-label="Audit" className="grid content-start gap-6">
            <LedgerFeed api={api} />
            <TokenInspector api={api} />
          </aside>
        </div>
      </div>
    </>
  );
}

/** What an emailed link opens: confirm an address, choose a new password, or finish a magic sign-in. No admin token involved. */
function EmailLinkScreen({ flow }: { flow: EmailFlow }): ReactNode {
  const title = flow.type === "reset" ? "Choose a new password" : flow.type === "verify" ? "Confirm your email" : flow.type === "enrol" ? "Set up your passkey" : "Finish signing in";
  return (
    <main className="mx-auto grid min-h-screen max-w-md content-center gap-6 px-4 py-10">
      <AuthvexLogo size="lg" />
      <ZeroTrustLoginCard baseUrl={guessBaseUrl()} tenantId={flow.tenantId} flow={{ type: flow.type, token: flow.token }} title={title} />
    </main>
  );
}
