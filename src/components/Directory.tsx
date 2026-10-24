"use client";

import type { ReactNode } from "react";
import { shortId, useWorkspace, type ApiOptions } from "@authvex/react";

export function Directory({ api, tenantId, onTenant }: { api: Required<ApiOptions>; tenantId: string; onTenant(id: string): void }): ReactNode {
  const ws = useWorkspace(api, 4000);
  const tenants = ws.data?.tenants ?? [];
  const tenant = tenants.find((t) => t.id === tenantId);
  const members = (ws.data?.users ?? []).filter((u) => u.orgMemberships.some((m) => m.tenantId === tenantId));
  return (
    <nav aria-label="Tenants and people" className="grid content-start gap-4">
      {ws.error ? <p role="alert" className="av-err-text">{ws.error}</p> : null}
      <label className="av-field"><span>Tenant</span>
        <select className="av-input" value={tenantId} onChange={(e) => onTenant(e.target.value)}>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
      </label>
      {tenant ? (
        <section aria-label="Tenant policy" className="grid gap-1.5">
          <h2 className="av-h2">Policy</h2>
          <ul className="grid gap-1 text-[13px]" role="list">
            <li><span className={`av-badge ${tenant.requireDpopHardwareBinding ? "av-badge-ok" : ""}`}>{tenant.requireDpopHardwareBinding ? "hardware-bound required" : "binding optional"}</span></li>
            <li><span className={`av-badge ${tenant.requireMfaForAdmins ? "av-badge-ok" : ""}`}>{tenant.requireMfaForAdmins ? "admin MFA required" : "admin MFA optional"}</span></li>
            <li className="text-muted">Travel limit {tenant.maxImpossibleTravelKmh} km/h · {tenant.maxFailedAttemptsPerWindow} failures per window</li>
            <li className="text-muted">Access token {Math.round(tenant.sessionTtlSeconds / 60)} min · refresh {Math.round(tenant.refreshTtlSeconds / 3600)} h</li>
          </ul>
        </section>
      ) : null}
      {ws.data ? (
        <section aria-label="Signing keys" className="grid gap-1.5">
          <h2 className="av-h2">Signing keys</h2>
          <ul className="grid gap-1 text-[13px]" role="list">
            {ws.data.issuer.keys.map((k) => (
              <li key={k.kid} className="flex items-center justify-between gap-2">
                <span className="av-mono text-[12px]" title={k.kid}>{shortId(k.kid, 8)}</span>
                <span className={`av-badge ${k.status === "active" ? "av-badge-ok" : k.verifies ? "" : "av-badge-err"}`}>{k.status === "active" ? "signing" : k.verifies ? "verify only" : k.status === "retired" ? "retired" : "lapsed"}</span>
              </li>
            ))}
          </ul>
          <p className="text-[12px] text-muted">Rotate with <code>authvex issuer rotate</code>; verifiers read <code>/.well-known/jwks.json</code>.</p>
        </section>
      ) : null}
      <section aria-label="People" className="grid gap-1.5">
        <h2 className="av-h2">People</h2>
        <ul className="grid gap-1" role="list">
          {members.map((u) => {
            const role = u.orgMemberships.find((m) => m.tenantId === tenantId)?.roleId;
            return (
              <li key={u.id} className="rounded-md border border-line px-2.5 py-1.5">
                <div className="flex items-baseline justify-between gap-2"><span className="font-medium">{u.name}</span><span className="av-badge">{role}</span></div>
                <div className="av-mono text-[12px] text-muted">{u.email}</div>
                <div className="text-[12px] text-muted">{u.hasTotp ? "TOTP · " : ""}{u.passkeys.length > 0 ? `${u.passkeys.length} passkey${u.passkeys.length === 1 ? "" : "s"} · ` : ""}<span className="av-mono">{shortId(u.id, 12)}</span></div>
              </li>
            );
          })}
        </ul>
        <p className="text-[12px] text-muted">Demo password for every user: <code>demo-passphrase-1</code></p>
      </section>
    </nav>
  );
}
