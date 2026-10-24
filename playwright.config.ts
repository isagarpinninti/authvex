import { defineConfig, devices } from "@playwright/test";

export const E2E_PORT = 4378;

export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  workers: 1,
  reporter: [["list"]],
  // The real CLI serving the real Studio on a throwaway copy of examples/demo: nothing mocked. `localhost` (not 127.0.0.1) because
  // WebAuthn needs a domain as its relying-party id.
  webServer: { command: "node scripts/e2e-server.mjs", url: `http://localhost:${E2E_PORT}/api/health`, reuseExistingServer: false, timeout: 30_000 },
  use: { baseURL: `http://localhost:${E2E_PORT}`, viewport: { width: 1440, height: 1000 }, reducedMotion: "reduce", screenshot: "only-on-failure", colorScheme: "light" },
  // The same suite in all three engines. Run one project per invocation (see the e2e scripts): the tests change server state, so each engine needs a fresh server. Only the real-passkey test is Chromium-specific (it drives Chromium's virtual authenticator).
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } } },
    { name: "firefox", use: { ...devices["Desktop Firefox"], viewport: { width: 1440, height: 1000 } } },
    { name: "webkit", use: { ...devices["Desktop Safari"], viewport: { width: 1440, height: 1000 } } },
  ],
});
