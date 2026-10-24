import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { configure } from "@testing-library/dom";
// CI runners are slow: give async queries a generous bound (they return as soon as the element appears).
configure({ asyncUtilTimeout: 8000 });
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { ConfigSchema, DEMO_PASSWORD, FileKeyring, Ledger, MemoryMailer, createAuthvexServer, loadWorkspace, openStore, runInit, type AuthvexServer } from "@authvex/cli";
import { ZeroTrustLoginCard } from "../src";

let dir: string;
let server: AuthvexServer;
let base: string;
let mail: MemoryMailer;
const LIN = "linear_ops_workspace";

const admin = (): string => server.adminToken;
async function patchTenant(id: string, patch: Record<string, unknown>): Promise<void> {
  const ws = (await (await fetch(`${base}/api/workspace`, { headers: { authorization: `Bearer ${admin()}` } })).json()) as { tenants: Array<Record<string, unknown>> };
  const { matrix: _m, ...policy } = ws.tenants.find((t) => t.id === id) as Record<string, unknown>;
  void _m;
  const r = await fetch(`${base}/api/tenants/${id}`, { method: "PUT", headers: { authorization: `Bearer ${admin()}`, "content-type": "application/json" }, body: JSON.stringify({ ...policy, ...patch }) });
  expect(r.status).toBe(200);
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "authvex-react-mail-"));
  await runInit(dir);
  mail = new MemoryMailer();
  const ws = loadWorkspace(dir);
  const cfg = ConfigSchema.parse({ ...ws.config, port: 0, ipRequestsPerMinute: 100_000, store: { kind: "memory" }, mail: { driver: "console", from: "noreply@authvex.test", linkBase: "https://app.test/auth" } });
  server = createAuthvexServer({ workspace: { ...ws, config: cfg }, keyring: await FileKeyring.open(dir), store: await openStore(cfg, dir), mailer: mail, ledger: new Ledger(join(dir, ".authvex", "ledger.jsonl")) });
  base = `http://127.0.0.1:${(await server.listen()).port}`;
  await patchTenant(LIN, { allowSignup: true, signupRoleId: "guest", allowMagicLinks: true });
});
afterAll(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});
afterEach(cleanup);

const type = (label: string | RegExp, value: string): void => void fireEvent.change(screen.getByLabelText(label), { target: { value } });
const tokenIn = (to: string): string => decodeURIComponent(/token=([^&\s]+)/.exec(mail.lastTo(to)?.text ?? "")?.[1] ?? "");

describe("email flows in the login card, against a real server", () => {
  it("forgot password: request a link, follow it, choose a new password, sign in with it", async () => {
    const { unmount } = render(<ZeroTrustLoginCard baseUrl={base} tenantId={LIN} bindToDevice={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Forgot your password?" }));
    type("Email", "margaret@linear-ops.test");
    fireEvent.click(screen.getByRole("button", { name: "Send reset link" }));
    expect((await screen.findByRole("status")).textContent).toMatch(/email is on its way/);
    await waitFor(() => expect(mail.lastTo("margaret@linear-ops.test")?.subject).toBe("Reset your password"));
    unmount();

    render(<ZeroTrustLoginCard baseUrl={base} tenantId={LIN} bindToDevice={false} flow={{ type: "reset", token: tokenIn("margaret@linear-ops.test") }} />);
    type(/New password/, "short");
    expect((screen.getByRole("button", { name: "Change password" }) as HTMLButtonElement).disabled).toBe(true);
    type(/New password/, "password1234567");
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/common/);
    type(/New password/, "a brand new passphrase!");
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect((await screen.findByRole("status")).textContent).toMatch(/password was changed/);
    type("Email", "margaret@linear-ops.test");
    type("Password", "a brand new passphrase!");
    fireEvent.click(screen.getByRole("button", { name: "Sign in", exact: true } as never));
    await screen.findByText(/Signed in as/);
  });

  it("a used reset link says so", async () => {
    render(<ZeroTrustLoginCard baseUrl={base} tenantId={LIN} bindToDevice={false} flow={{ type: "reset", token: "ath_pr_used" }} />);
    type(/New password/, "a brand new passphrase!");
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/invalid, already used or expired/);
  });

  it("magic link: ask for one, then finish signing in from it", async () => {
    const { unmount } = render(<ZeroTrustLoginCard baseUrl={base} tenantId={LIN} bindToDevice={false} features={{ magicLink: true }} />);
    fireEvent.click(screen.getByRole("button", { name: "Email me a sign-in link" }));
    type("Email", "ada@acme-fintech.test");
    fireEvent.click(screen.getByRole("button", { name: "Send sign-in link" }));
    await screen.findByRole("status");
    await waitFor(() => expect(mail.lastTo("ada@acme-fintech.test")?.subject).toBe("Your sign-in link"));
    unmount();
    render(<ZeroTrustLoginCard baseUrl={base} tenantId={LIN} bindToDevice={false} flow={{ type: "magic", token: tokenIn("ada@acme-fintech.test") }} />);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByText(/Signed in as/);
  });

  it("sign-up: create an account, then confirm the address from the email", async () => {
    const { unmount } = render(<ZeroTrustLoginCard baseUrl={base} tenantId={LIN} bindToDevice={false} features={{ signUp: true }} />);
    fireEvent.click(screen.getByRole("button", { name: "Create an account" }));
    type("Name", "Ivy Newcomer");
    type("Email", "ivy@newcomer.test");
    type(/Password/, "demo-passphrase-1");
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/demo password/);
    type(/Password/, "a long enough passphrase");
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect((await screen.findByRole("status")).textContent).toMatch(/email is on its way/);
    await waitFor(() => expect(mail.lastTo("ivy@newcomer.test")?.subject).toBe("Confirm your email address"));
    unmount();
    render(<ZeroTrustLoginCard baseUrl={base} tenantId={LIN} bindToDevice={false} flow={{ type: "verify", token: tokenIn("ivy@newcomer.test") }} />);
    expect((await screen.findByText(/Your email address is confirmed/)).textContent).toBeTruthy();
  });

  it("the plain sign-in screen still works and offers reset by default", async () => {
    render(<ZeroTrustLoginCard baseUrl={base} tenantId={LIN} bindToDevice={false} />);
    expect(screen.getByRole("button", { name: "Forgot your password?" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create an account" })).toBeNull();
    type("Email", "grace@acme-fintech.test");
    type("Password", DEMO_PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Sign in", exact: true } as never));
    expect((await screen.findByRole("alert")).textContent).toMatch(/do not match/);
  });
});
