"use client";

import { useEffect, useState, type ReactNode } from "react";
import { ZeroTrustLoginCard, dpopHeader, request, type AuthvexSession } from "@authvex/react";
import { AuthvexLogo } from "./brand/AuthvexLogo";
import { guessBaseUrl } from "../lib/connection";

interface Info {
  clientName: string;
  tenantId: string;
  scope: string[];
  loginHint: string | null;
}

const WHAT: Record<string, string> = { openid: "know who you are", profile: "see your name", email: "see your email address", offline_access: "stay signed in for you" };

/**
 * Where an OpenID Connect client sends the user to sign in. `/authorize` made a one-time request and redirected here with its id;
 * the sign-in card signs the user in, and this page hands the session to the server to turn into an authorization code, then goes back
 * to the application.
 */
export function SignInPage(): ReactNode {
  const base = typeof location === "undefined" ? "" : guessBaseUrl();
  const [id, setId] = useState<string | null>(null);
  const [info, setInfo] = useState<Info | null>(null);
  const [problem, setProblem] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const request_ = new URLSearchParams(location.search).get("request");
    setId(request_);
    if (!request_) return setProblem("This page is opened by an application that wants you to sign in. Start from that application.");
    request<Info & { error?: string }>({ baseUrl: base }, "GET", `/api/oidc/request?id=${encodeURIComponent(request_)}`).then(
      (r) => (r.status === 200 ? setInfo(r.body) : setProblem("This sign-in request has expired or was already used. Go back to the application and start again.")),
      () => setProblem("The server could not be reached."),
    );
  }, [base]);

  const complete = async (s: AuthvexSession): Promise<void> => {
    if (!id) return;
    setBusy(true);
    try {
      const url = `${base}/api/oidc/complete`;
      const headers: Record<string, string> = s.tokenType === "DPoP" && s.deviceKey ? { dpop: await dpopHeader(s.deviceKey, "POST", url, s.sessionToken) } : {};
      const r = await request<{ redirectTo?: string; error?: string }>({ baseUrl: base }, "POST", "/api/oidc/complete", { request: id, sessionToken: s.sessionToken }, headers);
      if (r.status === 200 && r.body.redirectTo) location.assign(r.body.redirectTo);
      else setProblem(r.body.error ?? "The sign-in could not be completed. Go back to the application and try again.");
    } catch {
      setProblem("The server could not be reached.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto grid min-h-screen max-w-md content-center gap-6 px-4 py-10">
      <AuthvexLogo size="lg" />
      {problem ? (
        <p role="alert" className="av-card av-err-text">{problem}</p>
      ) : info ? (
        <>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Sign in to {info.clientName}</h1>
            <p className="mt-1 text-muted">
              {info.clientName} will be able to {info.scope.filter((s) => WHAT[s]).map((s) => WHAT[s]).join(", ")}.
            </p>
          </div>
          <ZeroTrustLoginCard baseUrl={base} tenantId={info.tenantId} onSession={(s) => void complete(s)} title="Sign in" features={{ passwordReset: true }} />
          {busy ? <p role="status" className="text-muted">Taking you back to {info.clientName}…</p> : null}
        </>
      ) : (
        <p role="status" className="text-muted">Loading…</p>
      )}
    </main>
  );
}
