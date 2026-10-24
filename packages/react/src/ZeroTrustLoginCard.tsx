import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { b64urlDecode, b64urlEncode, type SoftwareAuthenticator } from "@authvex/core";
import { absoluteUrl, dpopHeader, loadOrCreateDeviceKey, request, type ApiOptions, type AuthvexSession, type DeviceKey, type ReportView } from "./api";
import { ReportChecks } from "./ReportChecks";

export interface ZeroTrustLoginCardProps {
  baseUrl: string;
  tenantId: string;
  /** Called with the new session after a successful sign-in. */
  onSession?(session: AuthvexSession): void;
  /** Bind the session to this browser's non-extractable key (RFC 9449). Default true. */
  bindToDevice?: boolean;
  /** A software authenticator to use for the passkey button, for demos and tests. Without it the browser's WebAuthn is used. */
  softwareAuthenticator?: SoftwareAuthenticator;
  /** Open straight into an emailed link: confirm an address, choose a new password, or finish a magic sign-in. The link's `token` comes from the URL fragment. */
  flow?: { type: "reset" | "verify" | "magic" | "enrol"; token: string };
  /** Which self-service actions to offer. The server still decides whether the tenant allows them. */
  features?: { passwordReset?: boolean; magicLink?: boolean; signUp?: boolean; passkeyOnlySignUp?: boolean };
  title?: string;
  className?: string;
}

interface LoginBody {
  status?: string;
  error?: string;
  message?: string;
  available?: string[];
  report?: ReportView;
  sessionToken?: string;
  refreshToken?: string;
  familyId?: string;
  tokenType?: "DPoP" | "Bearer";
  claims?: AuthvexSession["claims"];
  user?: { id: string; email: string };
}

type Phase = { kind: "form" } | { kind: "enrol"; session: AuthvexSession } | { kind: "step_up"; available: string[]; report: ReportView } | { kind: "blocked"; report: ReportView } | { kind: "done"; session: AuthvexSession };

const b64 = (b: ArrayBuffer): string => b64urlEncode(new Uint8Array(b));

/**
 * Sign-in with a password or a passkey, a 6-digit TOTP step-up when the policy asks for one, and a session bound to this
 * browser's hardware-backed key. The card shows what it did: whether the session is bound, and which gates objected.
 */
export function ZeroTrustLoginCard({ baseUrl, tenantId, onSession, bindToDevice = true, softwareAuthenticator, flow, features, title = "Sign in", className }: ZeroTrustLoginCardProps): ReactNode {
  const api: ApiOptions = { baseUrl };
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [phase, setPhase] = useState<Phase>({ kind: "form" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [key, setKey] = useState<DeviceKey | null>(null);
  const [keyNote, setKeyNote] = useState("");
  const stepRef = useRef<HTMLInputElement>(null);
  // Sub-screens: the emailed-link flows and their requests.
  const [mode, setMode] = useState<"signin" | "forgot" | "magic" | "signup" | "link">(flow ? "link" : "signin");
  const [name, setName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [notice, setNotice] = useState("");
  const [verified, setVerified] = useState<"pending" | "ok" | "bad" | null>(flow?.type === "verify" ? "pending" : null);
  const canReset = features?.passwordReset !== false;

  useEffect(() => {
    if (!bindToDevice) return;
    let live = true;
    loadOrCreateDeviceKey("authvex-login").then(
      (k) => live && setKey(k),
      () => live && setKeyNote("This browser cannot create a hardware-backed key, so the session will not be bound."),
    );
    return () => {
      live = false;
    };
  }, [bindToDevice]);
  useEffect(() => {
    if (phase.kind === "step_up") stepRef.current?.focus();
  }, [phase.kind]);
  useEffect(() => {
    if (flow?.type !== "verify") return;
    let live = true;
    request<{ status?: string }>({ baseUrl }, "POST", "/api/auth/verify-email", { token: flow.token }).then(
      (r) => live && setVerified(r.status === 200 ? "ok" : "bad"),
      () => live && setVerified("bad"),
    );
    return () => {
      live = false;
    };
  }, [baseUrl, flow?.type, flow?.token]);

  const finish = async (b: LoginBody): Promise<void> => {
    const session: AuthvexSession = {
      tenantId, userId: b.user?.id ?? b.claims?.sub ?? "", email, sessionToken: b.sessionToken as string, refreshToken: b.refreshToken as string, familyId: b.familyId as string,
      tokenType: b.tokenType ?? "Bearer", claims: b.claims as AuthvexSession["claims"], deviceKey: key, spentRefreshTokens: [],
    };
    setPhase({ kind: "done", session });
    setPassword("");
    onSession?.(session);
  };

  const submit = async (extra: Record<string, unknown>): Promise<void> => {
    setBusy(true);
    setError("");
    try {
      const url = absoluteUrl(api, "/api/auth/login");
      const headers: Record<string, string> = key ? { dpop: await dpopHeader(key, "POST", url) } : {};
      const r = await request<LoginBody>(api, "POST", "/api/auth/login", { tenantId, email, ...extra }, headers);
      if (r.status === 200 && r.body.status === "ok") return await finish(r.body);
      if (r.status === 401 && r.body.status === "step_up_required" && r.body.report) return setPhase({ kind: "step_up", available: r.body.available ?? [], report: r.body.report });
      if (r.status === 403 && r.body.report) return setPhase({ kind: "blocked", report: r.body.report });
      setError(r.status === 429 ? "Too many attempts. Try again later." : r.body.status === "invalid_credentials" ? "That email and password do not match." : (r.body.error ?? r.body.message ?? `Sign-in failed (HTTP ${r.status}).`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "The server could not be reached.");
    } finally {
      setBusy(false);
    }
  };

  const passkeySignIn = async (): Promise<void> => {
    setBusy(true);
    setError("");
    try {
      const ch = await request<{ challengeId: string; challenge: string; rpId: string; allowCredentials: string[]; error?: string }>(api, "POST", "/api/auth/passkey/challenge", { tenantId, email });
      if (ch.status !== 200) return setError(ch.body.error ?? "Could not start the passkey sign-in.");
      let assertion: { credentialId: string; clientDataJSON: string; authenticatorData: string; signature: string };
      if (softwareAuthenticator) {
        const a = await softwareAuthenticator.assert(ch.body.challenge);
        assertion = { credentialId: softwareAuthenticator.credentialId, ...a };
      } else {
        if (typeof navigator === "undefined" || !navigator.credentials || typeof PublicKeyCredential === "undefined") return setError("This browser does not support passkeys.");
        const cred = (await navigator.credentials.get({
          publicKey: { challenge: b64urlDecode(ch.body.challenge), rpId: ch.body.rpId, userVerification: "required", allowCredentials: ch.body.allowCredentials.map((id) => ({ type: "public-key", id: b64urlDecode(id) })), timeout: 120_000 },
        })) as PublicKeyCredential | null;
        if (!cred) return setError("No passkey was chosen.");
        const resp = cred.response as AuthenticatorAssertionResponse;
        assertion = { credentialId: b64(cred.rawId), clientDataJSON: b64(resp.clientDataJSON), authenticatorData: b64(resp.authenticatorData), signature: b64(resp.signature) };
      }
      setBusy(false);
      await submit({ passkey: { challengeId: ch.body.challengeId, ...assertion } });
    } catch (e) {
      setError(e instanceof Error ? e.message : "The passkey sign-in did not complete.");
    } finally {
      setBusy(false);
    }
  };

  const post = async <T extends { status?: string; error?: string; message?: string; reason?: string }>(path: string, body: Record<string, unknown>, headers: Record<string, string> = {}): Promise<{ status: number; body: T }> => {
    setBusy(true);
    setError("");
    try {
      return await request<T>(api, "POST", path, body, headers);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The server could not be reached.");
      return { status: 0, body: {} as T };
    } finally {
      setBusy(false);
    }
  };
  const asked = (r: { status: number; body: { error?: string; message?: string } }): void => {
    if (r.status === 202) setNotice("If that address can use this, an email is on its way. The link works once and expires soon.");
    else if (r.status === 501) setError("Email is not set up on this server.");
    else if (r.status !== 0) setError(r.body.error ?? r.body.message ?? `The request failed (HTTP ${r.status}).`);
  };
  const requestReset = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    asked(await post("/api/auth/password-reset/request", { tenantId, email }));
  };
  const requestMagic = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    asked(await post("/api/auth/magic-link/request", { tenantId, email }));
  };
  const signUp = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    const r = await post<{ status?: string; error?: string }>("/api/auth/signup", { tenantId, email, name, ...(newPassword ? { password: newPassword } : {}) });
    if (r.status === 422) setError(r.body.error ?? "Choose a stronger password.");
    else asked(r);
  };
  const confirmReset = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    const r = await post<{ status?: string; error?: string }>("/api/auth/password-reset/confirm", { token: flow?.token ?? "", newPassword });
    if (r.status === 200) {
      setNewPassword("");
      setNotice("Your password was changed and your other sessions were signed out. You can sign in now.");
      setMode("signin");
    } else if (r.status === 422) setError(r.body.error ?? "Choose a stronger password.");
    else if (r.status === 400) setError("That link is invalid, already used or expired. Ask for a new one.");
    else if (r.status !== 0) setError(r.body.error ?? `The request failed (HTTP ${r.status}).`);
  };
  const consumeMagic = async (stepUp = false): Promise<void> => {
    const url = absoluteUrl(api, "/api/auth/magic-link/consume");
    const headers: Record<string, string> = key ? { dpop: await dpopHeader(key, "POST", url) } : {};
    const r = await post<LoginBody>("/api/auth/magic-link/consume", { token: flow?.token ?? "", ...(stepUp ? { totp } : {}) }, headers);
    if (r.status === 200 && r.body.status === "ok") return finish(r.body);
    if (r.status === 401 && r.body.status === "step_up_required" && r.body.report) return setPhase({ kind: "step_up", available: r.body.available ?? [], report: r.body.report });
    if (r.status === 403 && r.body.report) return setPhase({ kind: "blocked", report: r.body.report });
    if (r.status === 400) setError("That link is invalid, already used or expired. Ask for a new one.");
    else if (r.status !== 0) setError(r.body.error ?? r.body.message ?? `Sign-in failed (HTTP ${r.status}).`);
  };
  const sessionFrom = (b: LoginBody): AuthvexSession => ({
    tenantId, userId: b.user?.id ?? b.claims?.sub ?? "", email: b.user?.email ?? email, sessionToken: b.sessionToken as string, refreshToken: b.refreshToken as string, familyId: b.familyId as string,
    tokenType: b.tokenType ?? "Bearer", claims: b.claims as AuthvexSession["claims"], deviceKey: key, spentRefreshTokens: [],
  });
  const consumeEnrol = async (): Promise<void> => {
    const url = absoluteUrl(api, "/api/auth/enrol/consume");
    const headers: Record<string, string> = key ? { dpop: await dpopHeader(key, "POST", url) } : {};
    const r = await post<LoginBody>("/api/auth/enrol/consume", { token: flow?.token ?? "" }, headers);
    if (r.status === 200 && r.body.status === "ok") return setPhase({ kind: "enrol", session: sessionFrom(r.body) });
    if (r.status === 403 && r.body.report) return setPhase({ kind: "blocked", report: r.body.report });
    if (r.status === 400) setError("That link is invalid, already used or expired. Ask for a new one.");
    else if (r.status !== 0) setError(r.body.error ?? r.body.message ?? `Sign-in failed (HTTP ${r.status}).`);
  };
  /** Registers a passkey for the signed-in user through the self-service endpoints (their own session, not the admin token). */
  const createPasskey = async (session: AuthvexSession): Promise<void> => {
    setBusy(true);
    setError("");
    try {
      const authz = async (method: string, path: string): Promise<Record<string, string>> => ({
        authorization: `${session.tokenType} ${session.sessionToken}`,
        ...(session.deviceKey ? { dpop: await dpopHeader(session.deviceKey, method, absoluteUrl(api, path), session.sessionToken) } : {}),
      });
      const ch = await request<{ challengeId: string; challenge: string; rpId: string; user: { id: string; name: string; displayName: string }; excludeCredentials: string[]; attestation?: "none" | "direct"; error?: string }>(api, "POST", "/api/me/passkeys/challenge", {}, await authz("POST", "/api/me/passkeys/challenge"));
      if (ch.status !== 200) return setError(ch.body.error ?? "Could not start the passkey registration.");
      let payload: { clientDataJSON: string; attestationObject: string };
      if (softwareAuthenticator) payload = await softwareAuthenticator.register(ch.body.challenge);
      else {
        if (typeof PublicKeyCredential === "undefined" || !navigator.credentials) return setError("This browser does not support passkeys.");
        const cred = (await navigator.credentials.create({
          publicKey: {
            challenge: b64urlDecode(ch.body.challenge), rp: { id: ch.body.rpId, name: "Authvex" }, user: { id: new TextEncoder().encode(ch.body.user.id), name: ch.body.user.name, displayName: ch.body.user.displayName },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }], attestation: ch.body.attestation === "direct" ? "direct" : "none", authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
            excludeCredentials: ch.body.excludeCredentials.map((id) => ({ type: "public-key" as const, id: b64urlDecode(id) })),
          },
        })) as PublicKeyCredential | null;
        if (!cred) return setError("No passkey was created.");
        const resp = cred.response as AuthenticatorAttestationResponse;
        payload = { clientDataJSON: b64(resp.clientDataJSON), attestationObject: b64(resp.attestationObject) };
      }
      const done = await request<{ error?: string }>(api, "POST", "/api/me/passkeys", { challengeId: ch.body.challengeId, deviceName: "This device", ...payload }, await authz("POST", "/api/me/passkeys"));
      if (done.status !== 201) return setError(done.body.error ?? `The passkey could not be saved (HTTP ${done.status}).`);
      setPhase({ kind: "done", session });
      onSession?.(session);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The passkey was not created.");
    } finally {
      setBusy(false);
    }
  };
  const back = (): void => {
    setMode("signin");
    setError("");
    setNotice("");
  };

  const onPassword = (e: FormEvent): void => {
    e.preventDefault();
    void submit({ password });
  };
  const onTotp = (e: FormEvent): void => {
    e.preventDefault();
    if (flow?.type === "magic") void consumeMagic(true);
    else void submit({ password, totp });
  };

  return (
    <section className={`av-card av-login${className ? ` ${className}` : ""}`} aria-label={title}>
      <header className="av-card-head">
        <h3 className="av-h">{title}</h3>
        <span className={`av-badge ${key ? "av-badge-ok" : ""}`}>{key ? "hardware key ready" : bindToDevice ? "preparing key…" : "not bound"}</span>
      </header>

      {phase.kind === "done" ? (
        <div role="status" className="av-stack">
          <p className="av-ok-text">Signed in as <strong>{phase.session.email}</strong></p>
          <dl className="av-facts">
            <div><dt>Session</dt><dd>{phase.session.tokenType === "DPoP" ? "Bound to this device (DPoP)" : "Bearer: not bound to a key"}</dd></div>
            <div><dt>Family</dt><dd className="av-mono">{phase.session.familyId}</dd></div>
            {phase.session.claims.cnf ? <div><dt>cnf.jkt</dt><dd className="av-mono av-clip">{phase.session.claims.cnf.jkt}</dd></div> : null}
          </dl>
          <button type="button" className="av-btn" onClick={() => setPhase({ kind: "form" })}>Sign out</button>
        </div>
      ) : phase.kind === "enrol" ? (
        <div className="av-stack" role="status">
          <p className="av-ok-text">Your email address <strong>{phase.session.email}</strong> is confirmed.</p>
          <p>Create a passkey to finish setting up your account. You will sign in with it instead of a password.</p>
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          <div className="av-row"><button type="button" className="av-btn av-btn-primary" onClick={() => void createPasskey(phase.session)} disabled={busy}>Create a passkey</button></div>
        </div>
      ) : phase.kind === "blocked" ? (
        <div className="av-stack">
          <p role="alert" className="av-err-text">Sign-in blocked (trust score {phase.report.score}/100).</p>
          <ReportChecks report={phase.report} />
          <button type="button" className="av-btn" onClick={() => setPhase({ kind: "form" })}>Back</button>
        </div>
      ) : phase.kind === "step_up" ? (
        <form className="av-stack" onSubmit={onTotp}>
          <p role="status">This sign-in needs a second factor.</p>
          <ReportChecks report={phase.report} onlyProblems />
          {phase.available.includes("totp") ? (
            <label className="av-field">
              <span>6-digit code from your authenticator app</span>
              <input ref={stepRef} className="av-input av-mono" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={totp} onChange={(e) => setTotp(e.target.value.replace(/\D/g, ""))} />
            </label>
          ) : (
            <p className="av-muted">No authenticator app is set up for this account.</p>
          )}
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          <div className="av-row">
            <button type="submit" className="av-btn av-btn-primary" disabled={busy || totp.length !== 6}>Verify</button>
            {phase.available.includes("passkey") ? <button type="button" className="av-btn" onClick={() => void passkeySignIn()} disabled={busy}>Use a passkey</button> : null}
            <button type="button" className="av-btn" onClick={() => setPhase({ kind: "form" })}>Cancel</button>
          </div>
        </form>
      ) : mode === "link" && flow?.type === "verify" ? (
        <div className="av-stack" role="status" aria-live="polite">
          {verified === "pending" ? <p>Confirming your email address…</p> : verified === "ok" ? <p className="av-ok-text">Your email address is confirmed. You can sign in.</p> : <p role="alert" className="av-err-text">That link is invalid, already used or expired.</p>}
          <button type="button" className="av-btn av-btn-primary" onClick={back}>Go to sign in</button>
        </div>
      ) : mode === "link" && flow?.type === "reset" ? (
        <form className="av-stack" onSubmit={(e) => void confirmReset(e)}>
          <p>Choose a new password. Signing in anywhere else with the old one will stop working.</p>
          <label className="av-field"><span>New password (at least 12 characters)</span><input className="av-input" type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} /></label>
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          <div className="av-row"><button type="submit" className="av-btn av-btn-primary" disabled={busy || newPassword.length < 12}>Change password</button><button type="button" className="av-btn" onClick={back}>Cancel</button></div>
        </form>
      ) : mode === "link" && flow?.type === "enrol" ? (
        <div className="av-stack">
          <p>Finish setting up your account: we will confirm your email address and then ask you to create a passkey.</p>
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          <div className="av-row"><button type="button" className="av-btn av-btn-primary" onClick={() => void consumeEnrol()} disabled={busy}>Continue</button><button type="button" className="av-btn" onClick={back}>Cancel</button></div>
        </div>
      ) : mode === "link" && flow?.type === "magic" ? (
        <div className="av-stack">
          <p>Finish signing in with your email link.</p>
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          <div className="av-row"><button type="button" className="av-btn av-btn-primary" onClick={() => void consumeMagic()} disabled={busy}>Sign in</button><button type="button" className="av-btn" onClick={back}>Cancel</button></div>
        </div>
      ) : mode === "forgot" || mode === "magic" ? (
        <form className="av-stack" onSubmit={(e) => void (mode === "forgot" ? requestReset(e) : requestMagic(e))} noValidate>
          <p>{mode === "forgot" ? "Enter your email and we will send you a link to choose a new password." : "Enter your email and we will send you a link that signs you in once."}</p>
          <label className="av-field"><span>Email</span><input className="av-input" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          {notice ? <p role="status" className="av-ok-text">{notice}</p> : null}
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          <div className="av-row"><button type="submit" className="av-btn av-btn-primary" disabled={busy || !email}>{mode === "forgot" ? "Send reset link" : "Send sign-in link"}</button><button type="button" className="av-btn" onClick={back}>Back</button></div>
        </form>
      ) : mode === "signup" ? (
        <form className="av-stack" onSubmit={(e) => void signUp(e)} noValidate>
          <label className="av-field"><span>Name</span><input className="av-input" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label className="av-field"><span>Email</span><input className="av-input" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label className="av-field"><span>{features?.passkeyOnlySignUp ? "Password (optional: leave empty to use a passkey instead)" : "Password (at least 12 characters)"}</span><input className="av-input" type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} /></label>
          {notice ? <p role="status" className="av-ok-text">{notice}</p> : null}
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          <div className="av-row"><button type="submit" className="av-btn av-btn-primary" disabled={busy || !name || !email || (newPassword.length < 12 && !(features?.passkeyOnlySignUp && newPassword.length === 0))}>Create account</button><button type="button" className="av-btn" onClick={back}>Back</button></div>
        </form>
      ) : (
        <form className="av-stack" onSubmit={onPassword} noValidate>
          <label className="av-field"><span>Email</span><input className="av-input" type="email" autoComplete="username webauthn" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label className="av-field"><span>Password</span><input className="av-input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          {keyNote ? <p className="av-muted">{keyNote}</p> : null}
          {notice ? <p role="status" className="av-ok-text">{notice}</p> : null}
          {error ? <p role="alert" className="av-err-text">{error}</p> : null}
          <div className="av-row">
            <button type="submit" className="av-btn av-btn-primary" disabled={busy || !email || !password}>Sign in</button>
            <button type="button" className="av-btn" onClick={() => void passkeySignIn()} disabled={busy || !email}>Sign in with a passkey</button>
          </div>
          {canReset || features?.magicLink || features?.signUp ? (
            <div className="av-row av-links">
              {canReset ? <button type="button" className="av-link" onClick={() => { setMode("forgot"); setError(""); setNotice(""); }}>Forgot your password?</button> : null}
              {features?.magicLink ? <button type="button" className="av-link" onClick={() => { setMode("magic"); setError(""); setNotice(""); }}>Email me a sign-in link</button> : null}
              {features?.signUp ? <button type="button" className="av-link" onClick={() => { setMode("signup"); setError(""); setNotice(""); }}>Create an account</button> : null}
            </div>
          ) : null}
        </form>
      )}
    </section>
  );
}
