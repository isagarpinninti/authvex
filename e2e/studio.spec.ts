import { readFileSync } from "node:fs";
import { join } from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { TOKEN_PREFIX, computeTotpCode, importIssuerKey, signToken } from "@authvex/core";
import { E2E_PORT } from "../playwright.config";

const shots = process.env["SCREENSHOTS"] === "1";
const workspace = (): string => readFileSync(join(__dirname, ".workspace"), "utf8").trim();
const DEMO = "demo-passphrase-1";

async function adminToken(): Promise<string> {
  const kr = JSON.parse(readFileSync(join(workspace(), ".authvex", "issuers.json"), "utf8")) as { keys: Array<{ status: string; kid: string; publicKeyJwk: JsonWebKey; privateKeyJwk: JsonWebKey }> };
  const active = kr.keys.find((k) => k.status === "active") as (typeof kr.keys)[number];
  const issuer = await importIssuerKey({ kid: active.kid, publicKeyJwk: active.publicKeyJwk, privateKeyJwk: active.privateKeyJwk });
  const now = Math.floor(Date.now() / 1000);
  return signToken(TOKEN_PREFIX.admin, { v: 1, typ: "admin", sub: "e2e", iat: now, exp: now + 600 }, issuer.privateKey, issuer.kid);
}
const totpSecret = (userId: string): string => (JSON.parse(readFileSync(join(workspace(), "users.json"), "utf8")) as Array<{ id: string; totpSecretB32?: string }>).find((u) => u.id === userId)?.totpSecretB32 as string;

async function open(page: Page): Promise<void> {
  await page.goto(`/#token=${await adminToken()}`);
  await expect(page.getByRole("status").filter({ hasText: /connected · issuer/ })).toBeVisible();
}
const card = (page: Page, name: string) => page.getByRole("region", { name });
async function selectTenant(page: Page, name: string): Promise<void> {
  await page.getByRole("navigation", { name: "Tenants and people" }).locator("select").selectOption({ label: name });
  await expect(card(page, "Sign in")).toBeVisible();
}
async function signIn(page: Page, email: string, password = DEMO): Promise<void> {
  const login = card(page, "Sign in");
  await expect(login.getByText("hardware key ready")).toBeVisible();
  await login.getByLabel("Email").fill(email);
  await login.getByLabel("Password").fill(password);
  await login.getByRole("button", { name: "Sign in", exact: true }).click();
}
const noSeriousViolations = async (page: Page, label: string): Promise<void> => {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze();
  const bad = r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => `${label}: ${v.id} (${v.nodes.length}) ${v.nodes[0]?.html.slice(0, 140)}`)).toEqual([]);
};

test("the admin link connects and the token leaves the address bar", async ({ page }) => {
  await open(page);
  expect(page.url()).not.toContain("token");
  await expect(page.getByRole("navigation", { name: "Tenants and people" }).getByText("Ada Lovelace")).toBeVisible();
});

test("the connect form refuses a malformed token, and a forged one lands back with a reason", async ({ page }) => {
  await page.goto("/");
  await noSeriousViolations(page, "connect form");
  await page.getByLabel("Admin token").fill("nope");
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.locator("p[role=alert]")).toContainText("start with ath_adm_");
  const forged = `ath_adm_${Buffer.from(JSON.stringify({ v: 1, typ: "admin", exp: 9999999999 })).toString("base64url")}.${Buffer.alloc(64).toString("base64url")}`;
  await page.goto(`/#token=${forged}`);
  await page.reload(); // a hash-only navigation does not restart the app
  await expect(page.getByRole("heading", { name: "Connect to an Authvex server" })).toBeVisible();
  await expect(page.locator("p[role=alert]")).toContainText("refused");
});

test("a bound session: the owner passes, a thief with only the token, a thief with their own key, and a replayed proof all fail", async ({ page }) => {
  await open(page);
  await signIn(page, "grace@acme-fintech.test");
  await expect(card(page, "Sign in").getByText(/Bound to this device \(DPoP\)/)).toBeVisible();
  const lab = card(page, "DPoP and token-replay simulator");
  const results = lab.getByRole("list", { name: "Results" });
  await lab.getByRole("button", { name: "Request as the owner" }).click();
  await expect(results.locator("li").first()).toContainText("accepted");
  await lab.getByRole("button", { name: "Replay the stolen cookie (no key)" }).click();
  await expect(results.locator("li").first()).toContainText("refused (dpop_missing)");
  await lab.getByRole("button", { name: "Thief with their own key" }).click();
  await expect(results.locator("li").first()).toContainText("refused (key_mismatch)");
  await lab.getByRole("button", { name: "Replay a captured proof" }).click();
  await expect(results.locator("li").first()).toContainText("refused (replayed)");
  await expect(card(page, "Security ledger")).toContainText("auth.dpop.rejected");
  if (shots) await page.screenshot({ path: "docs/screens/studio-lab.png" });
});

test("a wrong password gets the same answer whether or not the account exists", async ({ page }) => {
  await open(page);
  await selectTenant(page, "Linear Ops Workspace");
  await signIn(page, "nobody@linear-ops.test", "whatever-1234");
  await expect(card(page, "Sign in").locator("p[role=alert]")).toHaveText("That email and password do not match.");
});

test("an admin is asked for a second factor and signs in with a TOTP code", async ({ page }) => {
  await open(page);
  await signIn(page, "ada@acme-fintech.test");
  const login = card(page, "Sign in");
  await expect(login.getByText("This sign-in needs a second factor.")).toBeVisible();
  await login.getByLabel(/6-digit code/).fill(await computeTotpCode(totpSecret("usr_ada")));
  await login.getByRole("button", { name: "Verify" }).click();
  await expect(login.getByText(/Signed in as/)).toBeVisible();
});

test("rotating a session works, and replaying a spent refresh token revokes the whole family", async ({ page }) => {
  await open(page);
  await signIn(page, "grace@acme-fintech.test");
  const panel = card(page, "Active sessions, keys and passkeys");
  await panel.getByRole("button", { name: "Rotate token" }).click();
  await expect(panel.getByRole("log")).toContainText("Rotated to generation 2");
  await panel.getByRole("button", { name: "Replay old token as a thief" }).click();
  await expect(panel.getByRole("log")).toContainText(/thief holding only the token cannot refresh/i);
  await panel.getByRole("button", { name: "Replay old token from this device" }).click();
  await expect(panel.getByRole("log")).toContainText("AV-104");
  await expect(card(page, "Security ledger")).toContainText("auth.family.reuse_detected");
  await expect(card(page, "Security ledger").getByRole("status")).toContainText("chain intact");
  await expect(panel.getByText("revoked: reuse detected").first()).toBeVisible();
});

test("a real WebAuthn passkey registers and signs in (Chromium's virtual authenticator)", async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium", "drives Chromium's virtual authenticator over the DevTools protocol");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await open(page);
  await selectTenant(page, "Linear Ops Workspace");
  const panel = card(page, "Active sessions, keys and passkeys");
  await panel.getByLabel("User").selectOption({ label: "Margaret Member" });
  await panel.getByRole("button", { name: "Register a passkey on this device" }).click();
  await expect(panel.getByRole("log")).toContainText("Passkey registered for margaret@linear-ops.test");
  const login = card(page, "Sign in");
  await expect(login.getByText("hardware key ready")).toBeVisible();
  await login.getByLabel("Email").fill("margaret@linear-ops.test");
  await login.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(login.getByText(/Signed in as/)).toBeVisible();
  await expect(card(page, "Security ledger")).toContainText("passkey.registered");
});

test("the threat radar blocks impossible travel and shows the arithmetic", async ({ page }) => {
  await open(page);
  await page.getByRole("tab", { name: "Threat radar" }).click();
  const radar = card(page, "Threat radar workbench");
  await expect(radar.getByText("Allowed")).toBeVisible();
  await radar.getByRole("button", { name: /impossible travel/ }).click();
  await expect(radar.getByText("Blocked")).toBeVisible();
  await expect(radar.getByText(/Hyderabad to Frankfurt: [\d.]+ km in 0\.167 h/).first()).toBeVisible();
  await radar.getByRole("button", { name: /stolen cookie/ }).click();
  await expect(radar.locator("li", { hasText: "AV-105" }).first()).toContainText("fails");
  await radar.getByRole("button", { name: /family fork/ }).click();
  await expect(radar.locator("li", { hasText: "AV-104" }).first()).toContainText("fails");
  if (shots) {
    await radar.getByRole("button", { name: /impossible travel/ }).click();
    await expect(radar.getByText("Blocked")).toBeVisible();
    await page.screenshot({ path: "docs/screens/studio-radar.png" });
  }
});

test("editing the role matrix is saved by the server, and break-glass mints, verifies and rejects a tampered seal", async ({ page }) => {
  await open(page);
  await page.getByRole("tab", { name: "Roles and break-glass" }).click();
  const rbac = card(page, "Tenant RBAC and impersonation");
  await rbac.locator("header select").selectOption({ label: "Acme Fintech (production)" });
  const box = rbac.getByLabel("Analyst may invoices:write");
  await expect(box).not.toBeChecked();
  await box.check();
  await rbac.getByRole("button", { name: "Save changes" }).click();
  await expect(rbac.getByText(/Saved\. The server now enforces/)).toBeVisible();
  await rbac.getByLabel("Acting admin").selectOption({ label: "Support Root" });
  await rbac.getByLabel(/^Impersonate/).selectOption({ label: "Grace Hopper" });
  await rbac.getByLabel("Ticket and reason (required)").fill("TICKET-4411 customer cannot see invoices");
  await rbac.getByRole("button", { name: "Mint seal" }).click();
  await expect(rbac.getByRole("timer")).toContainText("root@acme-fintech.test acting as grace@acme-fintech.test");
  await rbac.getByRole("button", { name: "Verify seal" }).click();
  await expect(rbac.getByText(/Valid: \d+s left/)).toBeVisible();
  await rbac.getByRole("button", { name: "Tamper, then verify" }).click();
  await expect(rbac.getByText(/Rejected \(bad_signature\)/)).toBeVisible();
  await expect(card(page, "Security ledger")).toContainText("impersonation.minted");
  await expect(card(page, "Security ledger")).toContainText("tenant.updated");
  if (shots) await page.screenshot({ path: "docs/screens/studio-rbac.png" });
});

test("a machine key is shown once and can be revoked", async ({ page }) => {
  await open(page);
  const panel = card(page, "Active sessions, keys and passkeys");
  await panel.getByLabel("Name", { exact: true }).fill("ci-pipeline");
  await panel.getByRole("button", { name: "Mint key" }).click();
  const warn = panel.getByRole("status").filter({ hasText: "Copy this key now" });
  await expect(warn).toContainText(/atk_live_[0-9a-f]{8}_/);
  const key = (await warn.locator("code").textContent()) ?? "";
  await panel.getByRole("button", { name: "I have stored it" }).click();
  await expect(panel.getByText(key)).toHaveCount(0);
  await expect(panel.getByText("ci-pipeline")).toBeVisible();
  const inspector = page.getByRole("region", { name: "Token inspector" });
  await inspector.getByLabel(/Paste an ath_/).fill(key);
  await inspector.getByRole("button", { name: "Verify" }).click();
  await expect(inspector.getByRole("status")).toContainText("Valid");
  await panel.getByRole("button", { name: "Revoke key ci-pipeline" }).click();
  await inspector.getByRole("button", { name: "Verify" }).click();
  await expect(inspector.getByRole("status")).toContainText("Not valid");
});

const outbox = (): Array<{ to: string; subject: string; text: string }> => {
  try {
    return readFileSync(join(workspace(), ".authvex", "outbox.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
};
const linkTo = async (to: string, subject: string): Promise<string> => {
  let found: string | undefined;
  await expect.poll(() => (found = outbox().reverse().find((m) => m.to === to && m.subject === subject)?.text.match(/https?:\/\/\S+/)?.[0]), { timeout: 10_000 }).toBeTruthy();
  return found as string;
};

test("forgot password: the emailed link opens a reset page, and the new password signs in", async ({ page }) => {
  await open(page);
  await selectTenant(page, "Linear Ops Workspace");
  const login = card(page, "Sign in");
  await login.getByRole("button", { name: "Forgot your password?" }).click();
  await login.getByLabel("Email").fill("margaret@linear-ops.test");
  await login.getByRole("button", { name: "Send reset link" }).click();
  await expect(login.getByRole("status")).toContainText("email is on its way");
  const link = await linkTo("margaret@linear-ops.test", "Reset your password");
  expect(link).toContain("#flow=reset&token=ath_pr_");
  await page.goto(link);
  await page.reload();
  await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
  expect(page.url()).not.toContain("token=");
  const reset = card(page, "Choose a new password");
  await reset.getByLabel(/New password/).fill("a brand new passphrase!");
  await reset.getByRole("button", { name: "Change password" }).click();
  await expect(reset.getByRole("status")).toContainText("password was changed");
  await reset.getByLabel("Email").fill("margaret@linear-ops.test");
  await reset.getByLabel("Password").fill("a brand new passphrase!");
  await reset.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(reset.getByText(/Signed in as/)).toBeVisible();
});

test("magic link and sign-up confirmation work from the emailed links", async ({ page }) => {
  await open(page);
  await selectTenant(page, "Linear Ops Workspace");
  const login = card(page, "Sign in");
  await login.getByRole("button", { name: "Create an account" }).click();
  await login.getByLabel("Name").fill("Ivy Newcomer");
  await login.getByLabel("Email").fill("ivy@newcomer.test");
  await login.getByLabel(/Password/).fill("a long enough passphrase");
  await login.getByRole("button", { name: "Create account" }).click();
  await expect(login.getByRole("status")).toContainText("email is on its way");
  await page.goto(await linkTo("ivy@newcomer.test", "Confirm your email address"));
  await page.reload();
  await expect(page.getByText("Your email address is confirmed")).toBeVisible();
  await page.goto("about:blank"); // a fresh start: a hash-only navigation would not restart the app
  await open(page);
  await selectTenant(page, "Linear Ops Workspace");
  await card(page, "Sign in").getByRole("button", { name: "Email me a sign-in link" }).click();
  await card(page, "Sign in").getByLabel("Email").fill("margaret@linear-ops.test");
  await card(page, "Sign in").getByRole("button", { name: "Send sign-in link" }).click();
  await expect(card(page, "Sign in").getByRole("status")).toContainText("email is on its way");
  await page.goto(await linkTo("margaret@linear-ops.test", "Your sign-in link"));
  await page.reload();
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByText(/Signed in as/)).toBeVisible();
});

test("passkey-only sign-up: no password, an emailed link, a passkey made in the browser, and a sign-in with it", async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium", "drives Chromium's virtual authenticator over the DevTools protocol");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await open(page);
  await selectTenant(page, "Linear Ops Workspace");
  const login = card(page, "Sign in");
  await login.getByRole("button", { name: "Create an account" }).click();
  await login.getByLabel("Name").fill("Pat Passkey");
  await login.getByLabel("Email").fill("pat@passkey.test");
  await expect(login.getByLabel(/Password/)).toBeVisible();
  await login.getByRole("button", { name: "Create account" }).click();
  await expect(login.getByRole("status")).toContainText("email is on its way");
  const link = await linkTo("pat@passkey.test", "Set up your passkey");
  expect(link).toContain("#flow=enrol&token=ath_en_");
  await page.goto(link);
  await page.reload();
  const setup = card(page, "Set up your passkey");
  await expect(setup.getByRole("button", { name: "Continue" })).toBeVisible();
  expect(page.url()).not.toContain("token=");
  await setup.getByRole("button", { name: "Continue" }).click();
  await expect(setup.getByText("is confirmed")).toBeVisible();
  await setup.getByRole("button", { name: "Create a passkey" }).click();
  await expect(setup.getByText(/Signed in as/)).toBeVisible();
  // a fresh browser state signs in with the passkey alone
  await page.goto("about:blank");
  await open(page);
  await selectTenant(page, "Linear Ops Workspace");
  const again = card(page, "Sign in");
  await expect(again.getByText("hardware key ready")).toBeVisible();
  await again.getByLabel("Email").fill("pat@passkey.test");
  await again.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(again.getByText(/Signed in as/)).toBeVisible();
  await expect(card(page, "Security ledger")).toContainText("passkey.registered");
});

test("OpenID Connect: an app sends the user to the hosted sign-in page, and gets a code it can exchange for an ID token", async ({ page }) => {
  const { createHash, randomBytes } = await import("node:crypto");
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const base = `http://localhost:${E2E_PORT}`;
  const auth = new URL(`${base}/oidc/linear_ops_workspace/authorize`);
  for (const [k, v] of Object.entries({ client_id: "cl_e2e00001", redirect_uri: `${base}/e2e-callback`, response_type: "code", scope: "openid email profile", state: "st-123", nonce: "no-456", code_challenge: challenge, code_challenge_method: "S256" })) auth.searchParams.set(k, v);
  await page.goto(auth.toString());
  await expect(page.getByRole("heading", { name: "Sign in to Notes App" })).toBeVisible();
  await expect(page.getByText(/see your email address/)).toBeVisible();
  await noSeriousViolations(page, "hosted sign-in");
  const login = page.getByRole("region", { name: "Sign in" });
  await expect(login.getByText("hardware key ready")).toBeVisible();
  await login.getByLabel("Email").fill("ada@acme-fintech.test");
  await login.getByLabel("Password").fill(DEMO);
  await login.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/e2e-callback\?/);
  const back = new URL(page.url());
  expect(back.searchParams.get("state")).toBe("st-123");
  expect(back.searchParams.get("iss")).toBe(`${base}/oidc/linear_ops_workspace`);
  const t = await fetch(`${base}/oidc/linear_ops_workspace/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: back.searchParams.get("code") as string, redirect_uri: `${base}/e2e-callback`, code_verifier: verifier, client_id: "cl_e2e00001" }) });
  expect(t.status).toBe(200);
  const body = (await t.json()) as { id_token: string; access_token: string };
  const claims = JSON.parse(Buffer.from(body.id_token.split(".")[1] as string, "base64url").toString()) as Record<string, unknown>;
  expect(claims).toMatchObject({ sub: "usr_ada", email: "ada@acme-fintech.test", nonce: "no-456", aud: "cl_e2e00001" });
});

test("the hosted sign-in page explains a request that is missing, used or expired", async ({ page }) => {
  await page.goto("/signin/");
  await expect(page.locator("p[role=alert]")).toContainText("opened by an application");
  await page.goto("/signin/?request=ath_oq_unknown");
  await expect(page.locator("p[role=alert]")).toContainText("expired or was already used");
});

test("tabs follow the keyboard pattern", async ({ page }) => {
  await open(page);
  const tabs = page.getByRole("tablist", { name: "Views" });
  await tabs.getByRole("tab", { name: "Identity lab" }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(tabs.getByRole("tab", { name: "Threat radar" })).toBeFocused();
  await page.keyboard.press("End");
  await expect(tabs.getByRole("tab", { name: "SDK" })).toBeFocused();
  await page.keyboard.press("ArrowRight");
  await expect(tabs.getByRole("tab", { name: "Identity lab" })).toBeFocused();
});

for (const theme of ["light", "dark"] as const) {
  test(`no serious accessibility violations on any view (${theme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme });
    await page.addInitScript((t) => localStorage.setItem("authvex-theme", t), theme);
    await open(page);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    await signIn(page, "grace@acme-fintech.test");
    await expect(card(page, "Sign in").getByText(/Signed in as/)).toBeVisible();
    await noSeriousViolations(page, `lab/${theme}`);
    for (const tab of ["Threat radar", "Roles and break-glass", "SDK"]) {
      await page.getByRole("tab", { name: tab }).click();
      await page.waitForTimeout(400);
      await noSeriousViolations(page, `${tab}/${theme}`);
    }
    if (shots && theme === "light") {
      await page.getByRole("tab", { name: "Identity lab" }).click();
      await page.screenshot({ path: "docs/screens/studio-light.png" });
    }
    if (shots && theme === "dark") await page.screenshot({ path: "docs/screens/studio-dark.png" });
  });
}

test("the layout fits a phone with no sideways scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  await open(page);
  for (const tab of ["Identity lab", "Threat radar", "Roles and break-glass", "SDK"]) {
    await page.getByRole("tab", { name: tab }).click();
    await page.waitForTimeout(300);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `${tab} overflows by ${overflow}px`).toBeLessThanOrEqual(0);
  }
});
