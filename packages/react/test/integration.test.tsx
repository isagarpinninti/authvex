import { useState, type ReactNode } from "react";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { configure } from "@testing-library/dom";
// CI runners are slow: give async queries a generous bound (they return as soon as the element appears).
configure({ asyncUtilTimeout: 8000 });
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { ConfigSchema, DEMO_PASSWORD, Ledger, createAuthvexServer, loadOrCreateIssuerKey, loadWorkspace, runInit, staticKeyring, type AuthvexServer } from "@authvex/cli";
import { computeTotpCode, createSoftwareAuthenticator } from "@authvex/core";
import { ActiveSessionsAndPasskeysPanel, TenantRbacAndImpersonationStudio, ThreatRadarWorkbench, ZeroTrustLoginCard, type AuthvexSession } from "../src";

let dir: string;
let server: AuthvexServer;
let base: string;
let admin: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "authvex-react-"));
  await runInit(dir);
  const ws = loadWorkspace(dir);
  server = createAuthvexServer({ workspace: { ...ws, config: ConfigSchema.parse({ ...ws.config, port: 0 }) }, keyring: staticKeyring(await loadOrCreateIssuerKey(dir)), ledger: new Ledger(join(dir, ".authvex", "ledger.jsonl")) });
  const { port } = await server.listen();
  base = `http://127.0.0.1:${port}`;
  admin = server.adminToken;
});
afterAll(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});
afterEach(cleanup);

const type = (label: string | RegExp, value: string): void => void fireEvent.change(screen.getByLabelText(label), { target: { value } });

describe("zero-trust login card against a real server", () => {
  it("signs in, binds the session to the browser's key, and reports it", async () => {
    let session: AuthvexSession | null = null;
    render(<ZeroTrustLoginCard baseUrl={base} tenantId="acme_fintech_prod" onSession={(s) => (session = s)} />);
    await screen.findByText("hardware key ready");
    type("Email", "grace@acme-fintech.test");
    type("Password", DEMO_PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByText(/Bound to this device \(DPoP\)/);
    expect(session).toMatchObject({ tokenType: "DPoP", userId: "usr_grace", claims: { gen: 1, tid: "acme_fintech_prod" } });
    expect((session as AuthvexSession | null)?.claims.cnf?.jkt).toBe((session as AuthvexSession | null)?.deviceKey?.thumbprint);
  });

  it("refuses a tenant that requires a key when the card is told not to bind one, and shows why", async () => {
    render(<ZeroTrustLoginCard baseUrl={base} tenantId="acme_fintech_prod" bindToDevice={false} />);
    type("Email", "grace@acme-fintech.test");
    type("Password", DEMO_PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/blocked/i);
    expect(screen.getByText(/DPoP hardware-key binding/)).toBeTruthy();
    expect(screen.getByText(/requires a DPoP proof and none was presented/)).toBeTruthy();
  });

  it("asks an admin for a TOTP code and signs in with it", async () => {
    render(<ZeroTrustLoginCard baseUrl={base} tenantId="acme_fintech_prod" />);
    await screen.findByText("hardware key ready");
    type("Email", "ada@acme-fintech.test");
    type("Password", DEMO_PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByText("This sign-in needs a second factor.");
    const secret = (JSON.parse(readFileSync(join(dir, "users.json"), "utf8")) as Array<{ id: string; totpSecretB32?: string }>).find((u) => u.id === "usr_ada")?.totpSecretB32 as string;
    type(/6-digit code/, await computeTotpCode(secret));
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await screen.findByText(/Signed in as/);
  });

  it("says plainly that the email and password do not match, without hinting which part", async () => {
    render(<ZeroTrustLoginCard baseUrl={base} tenantId="linear_ops_workspace" bindToDevice={false} />);
    type("Email", "nobody@linear-ops.test");
    type("Password", "wrong-password");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect((await screen.findByRole("alert")).textContent).toBe("That email and password do not match.");
  });

  it("signs in with a passkey using a software authenticator", async () => {
    const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: base });
    const admin_ = { baseUrl: base, adminToken: admin };
    const ch = await (await fetch(`${base}/api/users/passkeys/challenge`, { method: "POST", headers: { authorization: `Bearer ${admin_.adminToken}`, "content-type": "application/json" }, body: JSON.stringify({ userId: "usr_margaret" }) })).json() as { challengeId: string; challenge: string };
    const reg = await fetch(`${base}/api/users/passkeys`, { method: "POST", headers: { authorization: `Bearer ${admin}`, "content-type": "application/json" }, body: JSON.stringify({ challengeId: ch.challengeId, deviceName: "t", ...(await auth.register(ch.challenge)) }) });
    expect(reg.status).toBe(201);
    render(<ZeroTrustLoginCard baseUrl={base} tenantId="linear_ops_workspace" bindToDevice={false} softwareAuthenticator={auth} />);
    type("Email", "margaret@linear-ops.test");
    fireEvent.click(screen.getByRole("button", { name: "Sign in with a passkey" }));
    await screen.findByText(/Signed in as/);
  });
});

describe("threat radar workbench against a real server", () => {
  it("scores a clean sign-in, then blocks impossible travel and explains the arithmetic", async () => {
    render(<ThreatRadarWorkbench baseUrl={base} adminToken={admin} tenantId="linear_ops_workspace" />);
    await waitFor(() => expect(screen.getByLabelText(/Trust score 100/)).toBeTruthy());
    expect(screen.getByText("Allowed")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /impossible travel/ }));
    await screen.findByText("Blocked");
    expect(screen.getAllByText(/km in .* h = \d+ km\/h/).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("list").some((l) => within(l).queryByText(/Hyderabad to Frankfurt/))).toBe(true);
    expect(screen.getByRole("button", { name: /impossible travel/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("covers stolen cookie, family fork and brute force, each tripping the right gate", async () => {
    render(<ThreatRadarWorkbench baseUrl={base} adminToken={admin} tenantId="linear_ops_workspace" />);
    await screen.findByText("Allowed");
    const gate = (code: string): HTMLElement => screen.getAllByText(code).map((el) => el.closest("li")).find((li): li is HTMLLIElement => li !== null) as HTMLElement;
    fireEvent.click(screen.getByRole("button", { name: /stolen cookie/ }));
    await waitFor(() => expect(gate("AV-105").textContent).toMatch(/fails/));
    fireEvent.click(screen.getByRole("button", { name: /family fork/ }));
    await waitFor(() => expect(gate("AV-104").textContent).toMatch(/fails/));
    fireEvent.click(screen.getByRole("button", { name: /brute-force/ }));
    await waitFor(() => expect(gate("AV-102").textContent).toMatch(/fails/));
    fireEvent.click(screen.getByRole("button", { name: /Reset to a clean/ }));
    await screen.findByText("Allowed");
  });
});

describe("sessions panel against a real server", () => {
  it("rotates a bound session, survives a thief without the key, and revokes everything on reuse", async () => {
    let session: AuthvexSession | null = null;
    render(<ZeroTrustLoginCard baseUrl={base} tenantId="acme_fintech_prod" onSession={(s) => (session = s)} />);
    await screen.findByText("hardware key ready");
    type("Email", "grace@acme-fintech.test");
    type("Password", DEMO_PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByText(/Signed in as/);
    cleanup();

    let current: AuthvexSession | null = session;
    function Harness(): ReactNode {
      const [s, setS] = useState<AuthvexSession | null>(current);
      return <ActiveSessionsAndPasskeysPanel baseUrl={base} adminToken={admin} session={s} onSessionChange={(n) => { current = n; setS(n); }} />;
    }
    render(<Harness />);
    await screen.findByText(/generation/);
    fireEvent.click(screen.getByRole("button", { name: "Rotate token" }));
    await waitFor(() => expect((current as AuthvexSession | null)?.claims.gen).toBe(2));
    expect(screen.getByRole("log").textContent).toMatch(/Rotated to generation 2/);

    fireEvent.click(screen.getByRole("button", { name: "Replay old token as a thief" }));
    await waitFor(() => expect(screen.getByRole("log").textContent).toMatch(/a thief holding only the token cannot refresh/i));
    expect(current).not.toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Replay old token from this device" }));
    await waitFor(() => expect(screen.getByRole("log").textContent).toMatch(/AV-104/));
    expect(current).toBeNull();
  });

  it("mints a key shown once, then revokes it, and registers a simulated passkey", async () => {
    render(<ActiveSessionsAndPasskeysPanel baseUrl={base} adminToken={admin} />);
    await waitFor(() => expect((screen.getByLabelText("Tenant") as HTMLSelectElement).options.length).toBeGreaterThan(0));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ci-pipeline" } });
    fireEvent.click(screen.getByRole("button", { name: "Mint key" }));
    const warn = await screen.findByText(/Copy this key now/);
    expect(warn.closest("div")?.textContent).toMatch(/atk_live_[0-9a-f]{8}_/);
    fireEvent.click(screen.getByRole("button", { name: "I have stored it" }));
    expect(screen.queryByText(/atk_live_[0-9a-f]{8}_[A-Za-z0-9_-]{32}/)).toBeNull();
    await screen.findByText("ci-pipeline");
    fireEvent.click(screen.getByRole("button", { name: "Revoke key ci-pipeline" }));
    await waitFor(() => expect(screen.getAllByText("revoked").length).toBeGreaterThan(0));

    fireEvent.click(screen.getByRole("button", { name: "Register a simulated passkey" }));
    await waitFor(() => expect(screen.getByRole("log").textContent).toMatch(/Passkey registered for/));
  });
});

describe("tenant RBAC and impersonation studio against a real server", () => {
  it("edits the matrix, saves it, and the server enforces the change", async () => {
    render(<TenantRbacAndImpersonationStudio baseUrl={base} adminToken={admin} />);
    await screen.findByRole("region", { name: "Role permission matrix" });
    await waitFor(() => expect((screen.getByLabelText("Tenant") as HTMLSelectElement).options.length).toBeGreaterThan(1));
    fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "linear_ops_workspace" } });
    const box = await screen.findByLabelText("Guest may issues:write");
    expect((box as HTMLInputElement).checked).toBe(false);
    expect((screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(box);
    expect((screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByText(/Saved\. The server now enforces/);
    const ws = await (await fetch(`${base}/api/workspace`, { headers: { authorization: `Bearer ${admin}` } })).json() as { tenants: Array<{ id: string; roles: Array<{ id: string; permissions: string[] }> }> };
    expect(ws.tenants.find((t) => t.id === "linear_ops_workspace")?.roles.find((r) => r.id === "guest")?.permissions).toContain("issues:write");
    expect((screen.getByLabelText("Lead may issues:write (granted by a wildcard)") as HTMLInputElement).disabled).toBe(true);
  });

  it("mints a sealed token with a countdown, verifies it, and shows a tampered copy rejected", async () => {
    render(<TenantRbacAndImpersonationStudio baseUrl={base} adminToken={admin} />);
    await screen.findByRole("region", { name: "Role permission matrix" });
    fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "acme_fintech_prod" } });
    await waitFor(() => expect((screen.getByLabelText("Acting admin") as HTMLSelectElement).options.length).toBeGreaterThan(1));
    fireEvent.change(screen.getByLabelText("Acting admin"), { target: { value: "usr_root" } });
    fireEvent.change(screen.getByLabelText("Impersonate"), { target: { value: "usr_grace" } });
    const mintBtn = screen.getByRole("button", { name: "Mint seal" }) as HTMLButtonElement;
    expect(mintBtn.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Ticket and reason (required)"), { target: { value: "TICKET-4411 customer cannot see invoices" } });
    expect(mintBtn.disabled).toBe(false);
    fireEvent.click(mintBtn);
    const banner = await screen.findByRole("timer");
    expect(banner.textContent).toMatch(/root@acme-fintech\.test acting as grace@acme-fintech\.test · read-only · (9|10):\d\d left/);
    fireEvent.click(screen.getByRole("button", { name: "Verify seal" }));
    await screen.findByText(/Valid: \d+s left\./);
    fireEvent.click(screen.getByRole("button", { name: "Tamper, then verify" }));
    await screen.findByText(/Rejected \(bad_signature\)/);
  });

  it("refuses an actor who lacks the permission, and says which gate", async () => {
    render(<TenantRbacAndImpersonationStudio baseUrl={base} adminToken={admin} />);
    await screen.findByRole("region", { name: "Role permission matrix" });
    fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "acme_fintech_prod" } });
    await waitFor(() => expect((screen.getByLabelText("Acting admin") as HTMLSelectElement).options.length).toBeGreaterThan(1));
    fireEvent.change(screen.getByLabelText("Acting admin"), { target: { value: "usr_grace" } });
    fireEvent.change(screen.getByLabelText("Impersonate"), { target: { value: "usr_root" } });
    fireEvent.change(screen.getByLabelText("Ticket and reason (required)"), { target: { value: "TICKET-1 trying my luck" } });
    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Mint seal" })));
    expect((await screen.findByRole("alert")).textContent).toContain("AV-107");
  });
});
