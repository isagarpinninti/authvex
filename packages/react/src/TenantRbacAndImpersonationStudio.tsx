import { useEffect, useMemo, useState, type ReactNode } from "react";
import { permissionMatches } from "@authvex/core";
import { request, type TenantView } from "./api";
import { useWorkspace } from "./hooks";

export interface TenantRbacAndImpersonationStudioProps {
  baseUrl: string;
  adminToken: string;
  className?: string;
}

interface Minted {
  token: string;
  claims: { reason: string; expiresAtIso: string; readOnly: boolean; targetEmail: string; actorEmail: string };
}

type Verdict = { valid: boolean; reason?: string; message?: string; secondsLeft?: number };

const stripMatrix = ({ matrix: _m, ...policy }: TenantView): Omit<TenantView, "matrix"> => (void _m, policy);

/**
 * Edit a tenant's role by permission matrix, and mint a break-glass impersonation seal: a signed, 15-minute-at-most token that
 * names who is acting as whom and why. Both go through the server, which checks RBAC and writes the audit ledger.
 */
export function TenantRbacAndImpersonationStudio({ baseUrl, adminToken, className }: TenantRbacAndImpersonationStudioProps): ReactNode {
  const api = { baseUrl, adminToken };
  const ws = useWorkspace(api, 0);
  const [tenantId, setTenantId] = useState("");
  const [draft, setDraft] = useState<TenantView | null>(null);
  const [newPerm, setNewPerm] = useState("");
  const [msg, setMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [actorId, setActorId] = useState("");
  const [targetId, setTargetId] = useState("");
  const [reason, setReason] = useState("");
  const [ttl, setTtl] = useState("600");
  const [readOnly, setReadOnly] = useState(true);
  const [minted, setMinted] = useState<Minted | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const tenants = useMemo(() => ws.data?.tenants ?? [], [ws.data]);
  const saved = tenants.find((t) => t.id === tenantId);
  useEffect(() => {
    if (!tenantId && tenants[0]) setTenantId(tenants[0].id);
  }, [tenantId, tenants]);
  useEffect(() => {
    if (saved) setDraft(saved);
  }, [saved?.id]); // eslint-disable-line react-hooks/exhaustive-deps -- reset only when the tenant changes, not on every poll
  useEffect(() => {
    if (!minted) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [minted]);

  const members = useMemo(() => (ws.data?.users ?? []).filter((u) => u.orgMemberships.some((m) => m.tenantId === tenantId)), [ws.data, tenantId]);
  useEffect(() => {
    if (!members.some((u) => u.id === actorId)) setActorId(members[0]?.id ?? "");
    if (!members.some((u) => u.id === targetId)) setTargetId(members[1]?.id ?? members[0]?.id ?? "");
  }, [members, actorId, targetId]);

  const permissions = useMemo(() => [...new Set((draft?.roles ?? []).flatMap((r) => r.permissions).filter((p) => !p.includes("*")))].sort(), [draft]);
  const dirty = draft !== null && saved !== undefined && JSON.stringify(stripMatrix(draft)) !== JSON.stringify(stripMatrix(saved));

  const toggle = (roleId: string, perm: string): void =>
    setDraft((d) => (d ? { ...d, roles: d.roles.map((r) => (r.id !== roleId ? r : { ...r, permissions: r.permissions.includes(perm) ? r.permissions.filter((p) => p !== perm) : [...r.permissions, perm].sort() })) } : d));

  const addPermission = (): void => {
    const p = newPerm.trim();
    if (!/^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_.-]*$/.test(p)) return setMsg({ tone: "err", text: "Use resource:action, for example reports:export." });
    setNewPerm("");
    setMsg(null);
    // A permission appears as a column once any role holds it, so the first role to hold it is the owner-like one with "*".
    setDraft((d) => (d ? { ...d, roles: d.roles.map((r, i) => (i === 0 && !r.permissions.includes(p) ? { ...r, permissions: [...r.permissions, p].sort() } : r)) } : d));
  };

  const save = async (): Promise<void> => {
    if (!draft) return;
    const r = await request<{ error?: string }>(api, "PUT", `/api/tenants/${encodeURIComponent(draft.id)}`, stripMatrix(draft));
    if (r.status === 200) {
      setMsg({ tone: "ok", text: "Saved. The server now enforces the new matrix and the change is in the ledger." });
      await ws.refresh();
    } else setMsg({ tone: "err", text: r.body.error ?? `Could not save (HTTP ${r.status}).` });
  };

  const mint = async (): Promise<void> => {
    setVerdict(null);
    const r = await request<Minted & { error?: string }>(api, "POST", "/api/auth/impersonate", { tenantId, actorId, targetUserId: targetId, reason, ttlSeconds: Number(ttl) || 600, readOnly });
    if (r.status === 201) {
      setMinted(r.body);
      setNow(Date.now());
      setMsg({ tone: "ok", text: "Seal minted and written to the ledger." });
      await ws.refresh();
    } else {
      setMinted(null);
      setMsg({ tone: "err", text: r.body.error ?? `Refused (HTTP ${r.status}).` });
    }
  };

  const verify = async (token: string): Promise<void> => {
    const r = await request<Verdict>({ baseUrl }, "POST", "/api/verify", { token });
    setVerdict(r.body);
  };
  const tamper = (): void => {
    if (!minted) return;
    const [head, sig] = minted.token.slice("ath_imp_".length).split(".") as [string, string];
    try {
      const claims = JSON.parse(atob(head.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
      claims["readOnly"] = false;
      claims["expiresAtIso"] = new Date(Date.now() + 86_400_000).toISOString();
      const forged = btoa(JSON.stringify(claims)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      void verify(`ath_imp_${forged}.${sig}`);
    } catch {
      setVerdict({ valid: false, reason: "malformed" });
    }
  };

  const left = minted ? Math.max(0, Math.floor((Date.parse(minted.claims.expiresAtIso) - now) / 1000)) : 0;
  const wildcardGrant = (roleId: string, perm: string): boolean => (draft?.roles.find((r) => r.id === roleId)?.permissions ?? []).some((g) => g.includes("*") && permissionMatches(g, perm));

  return (
    <section className={`av-card av-rbac${className ? ` ${className}` : ""}`} aria-label="Tenant RBAC and impersonation">
      <header className="av-card-head">
        <h3 className="av-h">Roles and break-glass</h3>
        <label className="av-field av-inline"><span className="av-sr">Tenant</span><select className="av-input" value={tenantId} onChange={(e) => setTenantId(e.target.value)}>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>
      </header>
      {msg ? <p role={msg.tone === "err" ? "alert" : "status"} className={msg.tone === "err" ? "av-err-text" : "av-ok-text"}>{msg.text}</p> : null}

      <h4 className="av-h2">Permission matrix</h4>
      <div className="av-scroll" tabIndex={0} role="region" aria-label="Role permission matrix">
        <table className="av-table av-matrix">
          <thead><tr><th scope="col">Role</th>{permissions.map((p) => <th key={p} scope="col" className="av-mono">{p}</th>)}</tr></thead>
          <tbody>
            {(draft?.roles ?? []).map((r) => (
              <tr key={r.id}>
                <th scope="row">{r.name}{r.permissions.includes("*") ? <span className="av-badge"> all</span> : null}</th>
                {permissions.map((p) => {
                  const wild = wildcardGrant(r.id, p);
                  return (
                    <td key={p}>
                      <input type="checkbox" checked={wild || r.permissions.includes(p)} disabled={wild} onChange={() => toggle(r.id, p)} aria-label={`${r.name} may ${p}${wild ? " (granted by a wildcard)" : ""}`} />
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="av-row">
        <label className="av-field av-grow"><span>Add a permission</span><input className="av-input av-mono" value={newPerm} placeholder="reports:export" onChange={(e) => setNewPerm(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addPermission(); } }} /></label>
        <button type="button" className="av-btn" onClick={addPermission}>Add</button>
        <button type="button" className="av-btn av-btn-primary" onClick={() => void save()} disabled={!dirty}>Save changes</button>
        <button type="button" className="av-btn" onClick={() => saved && setDraft(saved)} disabled={!dirty}>Discard</button>
      </div>

      <h4 className="av-h2">Break-glass support impersonation</h4>
      <div className="av-grid2">
        <div className="av-stack">
          <div className="av-row">
            <label className="av-field av-grow"><span>Acting admin</span><select className="av-input" value={actorId} onChange={(e) => setActorId(e.target.value)}>{members.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}</select></label>
            <label className="av-field av-grow"><span>Impersonate</span><select className="av-input" value={targetId} onChange={(e) => setTargetId(e.target.value)}>{members.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}</select></label>
          </div>
          <label className="av-field"><span>Ticket and reason (required)</span><input className="av-input" value={reason} placeholder="TICKET-4411 customer cannot see invoices" onChange={(e) => setReason(e.target.value)} /></label>
          <div className="av-row">
            <label className="av-field"><span>Lasts (30 to 900 seconds)</span><input className="av-input av-mono" inputMode="numeric" value={ttl} onChange={(e) => setTtl(e.target.value.replace(/\D/g, ""))} /></label>
            <label className="av-check-row"><input type="checkbox" checked={readOnly} onChange={(e) => setReadOnly(e.target.checked)} /> Read-only</label>
          </div>
          <div><button type="button" className="av-btn av-btn-primary" onClick={() => void mint()} disabled={!actorId || !targetId || reason.trim().length < 8}>Mint seal</button></div>
        </div>
        <div className="av-stack">
          {minted ? (
            <>
              <div className={`av-banner ${left > 0 ? "av-banner-warn" : "av-banner-err"}`} role="timer" aria-live="off">
                <strong>{left > 0 ? "Impersonation active" : "Seal expired"}</strong>
                <span>{minted.claims.actorEmail} acting as {minted.claims.targetEmail} · {minted.claims.readOnly ? "read-only" : "can write"} · {left > 0 ? `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} left` : "no longer valid"}</span>
              </div>
              <p className="av-muted">Reason on record: {minted.claims.reason}</p>
              <code className="av-mono av-key">{minted.token}</code>
              <div className="av-row">
                <button type="button" className="av-btn" onClick={() => void verify(minted.token)}>Verify seal</button>
                <button type="button" className="av-btn" onClick={tamper}>Tamper, then verify</button>
              </div>
              {verdict ? <p role="status" className={verdict.valid ? "av-ok-text" : "av-err-text"}>{verdict.valid ? `Valid: ${verdict.secondsLeft ?? 0}s left.` : `Rejected (${verdict.reason}): ${verdict.message ?? "the seal does not verify."}`}</p> : null}
            </>
          ) : <p className="av-muted">A seal names the admin who is acting, the user they act as, the reason, and an expiry of at most 15 minutes. It is signed by the server and recorded in the ledger.</p>}
        </div>
      </div>
    </section>
  );
}
