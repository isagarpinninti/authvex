import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { request, type ReportView } from "./api";
import { useWorkspace } from "./hooks";
import { ReportChecks, ScoreRing } from "./ReportChecks";

export interface ThreatRadarWorkbenchProps {
  baseUrl: string;
  adminToken: string;
  /** Start on this tenant (default: the first one). */
  tenantId?: string;
  className?: string;
}

interface Scenario {
  failedAttemptsInWindow: number;
  secondFactorVerified: boolean;
  asnKind: "" | "residential" | "datacenter" | "headless";
  dpop: "valid" | "missing" | "stolen";
  travel: "none" | "impossible" | "plausible";
  familyReused: boolean;
  disposable: boolean;
  permission: string;
}

const CLEAN: Scenario = { failedAttemptsInWindow: 0, secondFactorVerified: true, asnKind: "", dpop: "valid", travel: "none", familyReused: false, disposable: false, permission: "" };

const PRESETS: Array<{ id: string; label: string; hint: string; apply: Partial<Scenario> }> = [
  { id: "travel", label: "Simulate impossible travel (Hyderabad → Frankfurt in 10 min)", hint: "AV-103", apply: { travel: "impossible" } },
  { id: "stolen", label: "Simulate stolen cookie replay (without the DPoP key)", hint: "AV-105", apply: { dpop: "stolen" } },
  { id: "fork", label: "Simulate refresh-token family fork", hint: "AV-104", apply: { familyReused: true } },
  { id: "brute", label: "Simulate a brute-force burst", hint: "AV-102", apply: { failedAttemptsInWindow: 9 } },
  { id: "bot", label: "Simulate a headless disposable-mail signup", hint: "AV-106", apply: { asnKind: "headless", disposable: true } },
];

/**
 * Pick a tenant and a user, set up a situation (or press a preset) and see the trust score, the level and each of the eight
 * gates AV-101 to AV-108 that produced it. Every run is evaluated by the real server, not a copy of its logic.
 */
export function ThreatRadarWorkbench({ baseUrl, adminToken, tenantId, className }: ThreatRadarWorkbenchProps): ReactNode {
  const ws = useWorkspace({ baseUrl, adminToken }, 0);
  const [tenant, setTenant] = useState(tenantId ?? "");
  const [userId, setUserId] = useState("");
  const [s, setS] = useState<Scenario>(CLEAN);
  const [report, setReport] = useState<ReportView | null>(null);
  const [error, setError] = useState("");
  const [active, setActive] = useState<string | null>(null);

  const tenants = useMemo(() => ws.data?.tenants ?? [], [ws.data]);
  const members = useMemo(() => (ws.data?.users ?? []).filter((u) => u.orgMemberships.some((m) => m.tenantId === tenant)), [ws.data, tenant]);
  useEffect(() => {
    if (!tenant && tenants[0]) setTenant(tenants[0].id);
  }, [tenant, tenants]);
  useEffect(() => {
    if (members.length > 0 && !members.some((u) => u.id === userId)) setUserId(members[0]?.id ?? "");
  }, [members, userId]);

  const run = useCallback(async (): Promise<void> => {
    if (!tenant) return;
    const u = ws.data?.users.find((x) => x.id === userId);
    const body = {
      tenantId: tenant, ...(userId ? { userId } : {}), ...(s.disposable ? { email: "throwaway@mailinator.com" } : {}), secondFactorVerified: s.secondFactorVerified, failedAttemptsInWindow: s.failedAttemptsInWindow,
      ...(s.travel === "impossible" ? { lastLoginGeo: { lat: 17.385, lon: 78.4867, city: "Hyderabad", minutesAgo: 10 }, currentGeo: { lat: 50.1109, lon: 8.6821, city: "Frankfurt" } } : {}),
      ...(s.travel === "plausible" ? { lastLoginGeo: { lat: 17.385, lon: 78.4867, city: "Hyderabad", minutesAgo: 900 }, currentGeo: { lat: 50.1109, lon: 8.6821, city: "Frankfurt" } } : {}),
      dpop: s.dpop === "valid" ? { presented: true, valid: true, keyMatchesSession: true } : s.dpop === "missing" ? { presented: false, valid: false, keyMatchesSession: false } : { presented: true, valid: true, keyMatchesSession: false },
      ...(s.asnKind ? { asnKind: s.asnKind } : {}), ...(s.familyReused ? { familyStatus: "revoked_reuse_detected" } : {}), ...(s.permission && u ? { permission: s.permission } : {}),
    };
    const r = await request<{ report?: ReportView; error?: string }>({ baseUrl, adminToken }, "POST", "/api/evaluate", body);
    if (r.status === 200 && r.body.report) {
      setReport(r.body.report);
      setError("");
    } else setError(r.body.error ?? `HTTP ${r.status}`);
  }, [baseUrl, adminToken, tenant, userId, s, ws.data]);
  useEffect(() => {
    void run();
  }, [run]);

  const set = <K extends keyof Scenario>(k: K, v: Scenario[K]): void => {
    setActive(null);
    setS((p) => ({ ...p, [k]: v }));
  };

  return (
    <section className={`av-card av-radar${className ? ` ${className}` : ""}`} aria-label="Threat radar workbench">
      <header className="av-card-head">
        <h3 className="av-h">Threat radar</h3>
        <span className="av-muted">AV-101 to AV-108</span>
      </header>
      <div className="av-grid2">
        <div className="av-stack">
          <div className="av-row">
            <label className="av-field av-grow"><span>Tenant</span>
              <select className="av-input" value={tenant} onChange={(e) => setTenant(e.target.value)}>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
            </label>
            <label className="av-field av-grow"><span>User</span>
              <select className="av-input" value={userId} onChange={(e) => setUserId(e.target.value)}>{members.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}</select>
            </label>
          </div>
          <fieldset className="av-presets">
            <legend className="av-legend">Scenarios</legend>
            {PRESETS.map((p) => (
              <button key={p.id} type="button" className="av-btn av-btn-block" aria-pressed={active === p.id} onClick={() => { setS({ ...CLEAN, ...p.apply }); setActive(p.id); }}>
                <span>{p.label}</span> <span className="av-badge av-mono">{p.hint}</span>
              </button>
            ))}
            <button type="button" className="av-btn av-btn-block" onClick={() => { setS(CLEAN); setActive(null); }}>Reset to a clean sign-in</button>
          </fieldset>
          <fieldset className="av-presets">
            <legend className="av-legend">Adjust</legend>
            <label className="av-slider"><span>Failed attempts in window <span className="av-val" aria-hidden="true">{s.failedAttemptsInWindow}</span></span>
              <input type="range" min={0} max={12} value={s.failedAttemptsInWindow} aria-valuetext={`${s.failedAttemptsInWindow} failed attempts`} onChange={(e) => set("failedAttemptsInWindow", Number(e.target.value))} />
            </label>
            <label className="av-field"><span>Location</span>
              <select className="av-input" value={s.travel} onChange={(e) => set("travel", e.target.value as Scenario["travel"])}>
                <option value="none">No location data</option><option value="plausible">Hyderabad → Frankfurt after 15 hours</option><option value="impossible">Hyderabad → Frankfurt after 10 minutes</option>
              </select>
            </label>
            <label className="av-field"><span>DPoP proof</span>
              <select className="av-input" value={s.dpop} onChange={(e) => set("dpop", e.target.value as Scenario["dpop"])}>
                <option value="valid">Valid, from the bound key</option><option value="missing">None presented</option><option value="stolen">From a different key</option>
              </select>
            </label>
            <label className="av-field"><span>Network</span>
              <select className="av-input" value={s.asnKind} onChange={(e) => set("asnKind", e.target.value as Scenario["asnKind"])}>
                <option value="">Ordinary</option><option value="residential">Residential</option><option value="datacenter">Datacenter</option><option value="headless">Headless / automation</option>
              </select>
            </label>
            <label className="av-field"><span>Needs permission (resource:action)</span><input className="av-input av-mono" value={s.permission} placeholder="invoices:write" onChange={(e) => set("permission", e.target.value)} /></label>
            <label className="av-check-row"><input type="checkbox" checked={s.secondFactorVerified} onChange={(e) => set("secondFactorVerified", e.target.checked)} /> Second factor verified</label>
            <label className="av-check-row"><input type="checkbox" checked={s.familyReused} onChange={(e) => set("familyReused", e.target.checked)} /> Session family was revoked after a replay</label>
            <label className="av-check-row"><input type="checkbox" checked={s.disposable} onChange={(e) => set("disposable", e.target.checked)} /> Signing up with a disposable email</label>
          </fieldset>
        </div>
        <div className="av-stack" aria-live="polite">
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          {report ? (
            <>
              <div className="av-row av-center">
                <ScoreRing score={report.score} level={report.level} />
                <div>
                  <p className="av-level">{report.level === "LOW" ? "Allowed" : report.level === "BLOCK" ? "Blocked" : "Step-up required"}</p>
                  {report.travel ? <p className="av-muted av-mono">{report.travel.distanceKm} km in {report.travel.hours} h = {report.travel.speedKmh} km/h</p> : null}
                </div>
              </div>
              <ReportChecks report={report} />
            </>
          ) : <p className="av-muted">Evaluating…</p>}
        </div>
      </div>
    </section>
  );
}
