"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import { AuthvexLogo } from "./brand/AuthvexLogo";
import { guessBaseUrl, validBaseUrl, type Connection } from "../lib/connection";

export function ConnectForm({ onConnect, initialError }: { onConnect(c: Connection): void; initialError?: string }): ReactNode {
  const [server, setServer] = useState(guessBaseUrl);
  const [token, setToken] = useState("");
  const [error, setError] = useState(initialError ?? "");

  const submit = (e: FormEvent): void => {
    e.preventDefault();
    const baseUrl = validBaseUrl(server);
    if (!baseUrl) return setError("The server address must start with http:// or https://");
    if (!token.trim().startsWith("ath_adm_")) return setError("Admin tokens start with ath_adm_. Open the link `authvex studio` prints; it carries one.");
    onConnect({ baseUrl, token: token.trim() });
  };

  return (
    <main className="mx-auto grid min-h-screen max-w-md content-center gap-6 px-4 py-10">
      <AuthvexLogo size="lg" />
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Connect to an Authvex server</h1>
        <p className="mt-1 text-muted">The Studio talks only to your own server.</p>
      </div>
      <form onSubmit={submit} className="av-card grid gap-4" noValidate>
        <label className="av-field"><span>Server</span><input className="av-input" value={server} onChange={(e) => setServer(e.target.value)} inputMode="url" autoComplete="off" spellCheck={false} /></label>
        <label className="av-field"><span>Admin token</span><input className="av-input" type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="ath_adm_…" autoComplete="off" spellCheck={false} /></label>
        {error ? <p role="alert" className="av-err-text">{error}</p> : null}
        <div><button type="submit" className="av-btn av-btn-primary">Connect</button></div>
      </form>
    </main>
  );
}
