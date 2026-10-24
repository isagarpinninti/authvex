import { useState, type FormEvent, type ReactNode } from "react";
import { b64urlDecode, b64urlEncode, createSoftwareAuthenticator } from "@authvex/core";
import { absoluteUrl, dpopHeader, request, type AuthvexSession } from "./api";
import { shortId, useWorkspace } from "./hooks";

export interface ActiveSessionsAndPasskeysPanelProps {
  baseUrl: string;
  adminToken: string;
  /** The session the login card created, so the panel can rotate it and replay its old tokens. */
  session?: AuthvexSession | null;
  onSessionChange?(session: AuthvexSession | null): void;
  className?: string;
}

interface RotateBody {
  status?: string;
  message?: string;
  error?: string;
  reason?: string;
  sessionToken?: string;
  refreshToken?: string;
  generation?: number;
  claims?: AuthvexSession["claims"];
}

const when = (iso: string): string => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export function ActiveSessionsAndPasskeysPanel({ baseUrl, adminToken, session, onSessionChange, className }: ActiveSessionsAndPasskeysPanelProps): ReactNode {
  const api = { baseUrl, adminToken };
  const ws = useWorkspace(api, 3000);
  const [log, setLog] = useState<Array<{ tone: "ok" | "err" | "info"; text: string }>>([]);
  const [busy, setBusy] = useState(false);
  const [newKey, setNewKey] = useState<{ key: string; prefix: string } | null>(null);
  const [keyForm, setKeyForm] = useState({ tenantId: "", name: "", scopes: "invoices:read", rate: "600" });
  const [passkeyUser, setPasskeyUser] = useState("");
  const note = (tone: "ok" | "err" | "info", text: string): void => setLog((l) => [{ tone, text }, ...l].slice(0, 6));

  const tenants = ws.data?.tenants ?? [];
  const users = ws.data?.users ?? [];
  const user = users.find((u) => u.id === (passkeyUser || users[0]?.id));

  const rotate = async (opts: { token: string; withKey: boolean; label: string }): Promise<RotateBody & { http: number }> => {
    const headers: Record<string, string> = {};
    if (opts.withKey && session?.deviceKey) headers["dpop"] = await dpopHeader(session.deviceKey, "POST", absoluteUrl(api, "/api/auth/rotate"));
    const r = await request<RotateBody>({ baseUrl }, "POST", "/api/auth/rotate", { refreshToken: opts.token }, headers);
    await ws.refresh();
    return { ...r.body, http: r.status };
  };

  const doRotate = async (): Promise<void> => {
    if (!session) return;
    setBusy(true);
    try {
      const r = await rotate({ token: session.refreshToken, withKey: true, label: "rotate" });
      if (r.http === 200 && r.sessionToken && r.refreshToken && r.claims) {
        onSessionChange?.({ ...session, sessionToken: r.sessionToken, refreshToken: r.refreshToken, claims: r.claims, spentRefreshTokens: [...session.spentRefreshTokens, session.refreshToken] });
        note("ok", `Rotated to generation ${r.generation}. The previous refresh token is now spent.`);
      } else note("err", r.message ?? r.error ?? `Rotation failed (${r.status ?? r.http}).`);
    } finally {
      setBusy(false);
    }
  };

  const doReplay = async (withKey: boolean): Promise<void> => {
    const old = session?.spentRefreshTokens.at(-1);
    if (!session || !old) return;
    setBusy(true);
    try {
      const r = await rotate({ token: old, withKey, label: "replay" });
      if (r.http === 409) {
        note("err", `${r.message ?? "Family revoked."}`);
        onSessionChange?.(null);
      } else if (r.status === "dpop_required") note("info", `Stopped before the token was even checked: ${r.error ?? "a DPoP proof from the bound key is required"}. A thief holding only the token cannot refresh.`);
      else note("err", r.message ?? r.error ?? `Unexpected answer (${r.http}).`);
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (familyId: string): Promise<void> => {
    const r = await request(api, "DELETE", `/api/families/${encodeURIComponent(familyId)}`);
    note(r.status === 200 ? "ok" : "err", r.status === 200 ? `Revoked ${shortId(familyId, 12)}.` : "Could not revoke that family.");
    if (session?.familyId === familyId) onSessionChange?.(null);
    await ws.refresh();
  };

  const mintKey = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    const scopes = keyForm.scopes.split(",").map((s) => s.trim()).filter(Boolean);
    const r = await request<{ key?: string; record?: { keyPrefix: string }; error?: string }>(api, "POST", "/api/keys", { tenantId: keyForm.tenantId || tenants[0]?.id, name: keyForm.name, scopes, rateLimitPerMin: Number(keyForm.rate) || 600 });
    if (r.status === 201 && r.body.key && r.body.record) {
      setNewKey({ key: r.body.key, prefix: r.body.record.keyPrefix });
      setKeyForm((f) => ({ ...f, name: "" }));
      note("ok", "Key minted. Copy it now: it is never shown again.");
    } else note("err", r.body.error ?? "Could not mint the key.");
    await ws.refresh();
  };

  const revokeKey = async (id: string): Promise<void> => {
    await request(api, "DELETE", `/api/keys/${encodeURIComponent(id)}`);
    await ws.refresh();
  };

  const registerPasskey = async (simulated: boolean): Promise<void> => {
    if (!user || !ws.data) return;
    setBusy(true);
    try {
      const ch = await request<{ challengeId: string; challenge: string; rpId: string; user: { id: string; name: string; displayName: string }; excludeCredentials: string[]; attestation?: "none" | "direct"; error?: string }>(api, "POST", "/api/users/passkeys/challenge", { userId: user.id });
      if (ch.status !== 200) return note("err", ch.body.error ?? "Could not start the registration.");
      let payload: { clientDataJSON: string; attestationObject: string };
      if (simulated) {
        const auth = await createSoftwareAuthenticator({ rpId: ch.body.rpId, origin: absoluteUrl(api, "").replace(/\/$/, "") });
        payload = await auth.register(ch.body.challenge);
      } else {
        if (typeof PublicKeyCredential === "undefined" || !navigator.credentials) return note("err", "This browser does not support passkeys.");
        const cred = (await navigator.credentials.create({
          publicKey: {
            challenge: b64urlDecode(ch.body.challenge), rp: { id: ch.body.rpId, name: "Authvex" }, user: { id: new TextEncoder().encode(user.id), name: user.email, displayName: user.name },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }], attestation: ch.body.attestation === "direct" ? "direct" : "none", authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
            excludeCredentials: ch.body.excludeCredentials.map((id) => ({ type: "public-key" as const, id: b64urlDecode(id) })),
          },
        })) as PublicKeyCredential | null;
        if (!cred) return note("info", "No passkey was created.");
        const resp = cred.response as AuthenticatorAttestationResponse;
        payload = { clientDataJSON: b64urlEncode(new Uint8Array(resp.clientDataJSON)), attestationObject: b64urlEncode(new Uint8Array(resp.attestationObject)) };
      }
      const r = await request<{ error?: string }>(api, "POST", "/api/users/passkeys", { challengeId: ch.body.challengeId, deviceName: simulated ? "Simulated passkey" : "This device", ...payload });
      note(r.status === 201 ? "ok" : "err", r.status === 201 ? `Passkey registered for ${user.email}.` : (r.body.error ?? "The server refused the passkey."));
      await ws.refresh();
    } catch (e) {
      note("err", e instanceof Error ? e.message : "The passkey registration did not complete.");
    } finally {
      setBusy(false);
    }
  };

  const mine = session ? ws.data?.families.find((f) => f.familyId === session.familyId) : undefined;
  return (
    <section className={`av-card av-sessions${className ? ` ${className}` : ""}`} aria-label="Active sessions, keys and passkeys">
      <header className="av-card-head"><h3 className="av-h">Sessions, keys and passkeys</h3>{ws.error ? <span className="av-err-text">{ws.error}</span> : null}</header>

      <div className="av-grid2">
        <div className="av-stack">
          <h4 className="av-h2">Your session</h4>
          {session ? (
            <div className="av-box">
              <p><strong>{session.email}</strong> · generation <span className="av-mono">{mine?.generation ?? session.claims.gen}</span> · {session.tokenType === "DPoP" ? "hardware-bound" : "not bound"}</p>
              <div className="av-row">
                <button type="button" className="av-btn av-btn-primary" onClick={() => void doRotate()} disabled={busy}>Rotate token</button>
                <button type="button" className="av-btn" onClick={() => void doReplay(false)} disabled={busy || session.spentRefreshTokens.length === 0}>Replay old token as a thief</button>
                <button type="button" className="av-btn" onClick={() => void doReplay(true)} disabled={busy || session.spentRefreshTokens.length === 0}>Replay old token from this device</button>
              </div>
              {session.spentRefreshTokens.length === 0 ? <p className="av-muted">Rotate once first: replaying needs a spent token.</p> : null}
            </div>
          ) : <p className="av-muted">Sign in with the login card to get a session you can rotate and attack.</p>}
          <div role="log" aria-live="polite" aria-label="Session events" className="av-log">
            {log.length === 0 ? <p className="av-muted">Nothing yet.</p> : log.map((l, i) => <p key={i} className={`av-log-${l.tone}`}><span className="av-sr">{l.tone === "ok" ? "Success: " : l.tone === "err" ? "Problem: " : "Note: "}</span>{l.text}</p>)}
          </div>
          <h4 className="av-h2">Session families</h4>
          <div className="av-scroll" tabIndex={0} role="region" aria-label="Session families"><table className="av-table">
            <thead><tr><th scope="col">Family</th><th scope="col">User</th><th scope="col">Gen</th><th scope="col">State</th><th scope="col"><span className="av-sr">Actions</span></th></tr></thead>
            <tbody>
              {(ws.data?.families ?? []).length === 0 ? <tr><td colSpan={5} className="av-muted">No sessions yet.</td></tr> : (ws.data?.families ?? []).map((f) => (
                <tr key={f.familyId}>
                  <td className="av-mono" title={f.familyId}>{shortId(f.familyId, 12)}</td>
                  <td>{users.find((u) => u.id === f.userId)?.name ?? f.userId}</td>
                  <td className="av-mono">{f.generation}</td>
                  <td><span className={`av-badge ${f.status === "active" ? "av-badge-ok" : "av-badge-err"}`}>{f.status === "active" ? "active" : f.status.replace("revoked_", "revoked: ").replace("_", " ")}</span>{f.bound ? <span className="av-badge"> bound</span> : null} <span className="av-muted">{when(f.lastRotatedAtIso)}</span></td>
                  <td>{f.status === "active" ? <button type="button" className="av-btn av-btn-sm" onClick={() => void revoke(f.familyId)} aria-label={`Revoke family ${shortId(f.familyId, 12)}`}>Revoke</button> : null}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>

        <div className="av-stack">
          <h4 className="av-h2">Machine API keys</h4>
          <form className="av-stack" onSubmit={(e) => void mintKey(e)}>
            <div className="av-row">
              <label className="av-field av-grow"><span>Tenant</span><select className="av-input" value={keyForm.tenantId || tenants[0]?.id || ""} onChange={(e) => setKeyForm({ ...keyForm, tenantId: e.target.value })}>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>
              <label className="av-field av-grow"><span>Name</span><input className="av-input" value={keyForm.name} onChange={(e) => setKeyForm({ ...keyForm, name: e.target.value })} /></label>
            </div>
            <div className="av-row">
              <label className="av-field av-grow"><span>Scopes (comma separated)</span><input className="av-input av-mono" value={keyForm.scopes} onChange={(e) => setKeyForm({ ...keyForm, scopes: e.target.value })} /></label>
              <label className="av-field"><span>Requests / minute</span><input className="av-input av-mono" inputMode="numeric" value={keyForm.rate} onChange={(e) => setKeyForm({ ...keyForm, rate: e.target.value.replace(/\D/g, "") })} /></label>
            </div>
            <div><button type="submit" className="av-btn av-btn-primary" disabled={!keyForm.name.trim() || tenants.length === 0}>Mint key</button></div>
          </form>
          {newKey ? (
            <div className="av-box av-box-warn" role="status">
              <p><strong>Copy this key now.</strong> Only its hash is stored, so it cannot be shown again.</p>
              <code className="av-mono av-key">{newKey.key}</code>
              <div className="av-row"><button type="button" className="av-btn av-btn-sm" onClick={() => void navigator.clipboard?.writeText(newKey.key)}>Copy</button><button type="button" className="av-btn av-btn-sm" onClick={() => setNewKey(null)}>I have stored it</button></div>
            </div>
          ) : null}
          <ul className="av-list" role="list">
            {(ws.data?.keys ?? []).length === 0 ? <li className="av-muted">No keys.</li> : (ws.data?.keys ?? []).map((k) => (
              <li key={k.id} className="av-keyrow">
                <span><span className="av-mono">{k.keyPrefix}…</span> <strong>{k.name}</strong> <span className="av-muted">{k.scopes.join(", ")} · {k.rateLimitPerMin}/min</span></span>
                {k.revokedAtIso ? <span className="av-badge av-badge-err">revoked</span> : <button type="button" className="av-btn av-btn-sm" onClick={() => void revokeKey(k.id)} aria-label={`Revoke key ${k.name}`}>Revoke</button>}
              </li>
            ))}
          </ul>

          <h4 className="av-h2">Passkeys</h4>
          <label className="av-field"><span>User</span><select className="av-input" value={user?.id ?? ""} onChange={(e) => setPasskeyUser(e.target.value)}>{users.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}</select></label>
          <ul className="av-list" role="list">
            {(user?.passkeys ?? []).length === 0 ? <li className="av-muted">No passkeys for this user.</li> : user?.passkeys.map((p) => <li key={p.credentialId}>{p.deviceName} <span className="av-muted av-mono">{shortId(p.credentialId, 10)} · counter {p.signCount}</span></li>)}
          </ul>
          <div className="av-row">
            <button type="button" className="av-btn" onClick={() => void registerPasskey(true)} disabled={busy || !user}>Register a simulated passkey</button>
            <button type="button" className="av-btn" onClick={() => void registerPasskey(false)} disabled={busy || !user}>Register a passkey on this device</button>
          </div>
        </div>
      </div>
    </section>
  );
}
