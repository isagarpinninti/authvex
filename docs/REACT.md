# React components

```bash
npm install @authvex/react zod
```

```tsx
import "@authvex/react/styles.css";
```

`react` 18.2 or newer and `zod` are peer dependencies. Colours come from `--av-*` CSS variables and follow `prefers-color-scheme`, or `data-theme="light" | "dark"` on `<html>`: an alabaster canvas, night-blue ink, amber for the primary action, emerald for verified and rose for refused.

## The four components

| Component | Needs | What it does |
| --- | --- | --- |
| `ZeroTrustLoginCard` | `baseUrl`, `tenantId` | Password or passkey sign-in, TOTP step-up, and a session bound to this browser's non-extractable key. Calls `onSession(session)` |
| `ThreatRadarWorkbench` | `baseUrl`, `adminToken` | Pick a tenant and user, press a scenario or adjust inputs, see the trust score and all eight gates. The server does the evaluating |
| `ActiveSessionsAndPasskeysPanel` | `baseUrl`, `adminToken`, optional `session` | Rotate a session, replay a spent token (as a thief, or from the device), list and revoke families, mint and revoke machine keys, register passkeys |
| `TenantRbacAndImpersonationStudio` | `baseUrl`, `adminToken` | Edit the role matrix and save it; mint, verify and tamper with a break-glass seal |

`ZeroTrustLoginCard` is meant for your users. **The other three need an admin token and are tools for operators**: use them in an internal console, not in a page your users see.

```tsx
import { ZeroTrustLoginCard, type AuthvexSession } from "@authvex/react";

export function SignIn({ onDone }: { onDone(s: AuthvexSession): void }) {
  return <ZeroTrustLoginCard baseUrl="https://id.example.com" tenantId="acme_fintech_prod" onSession={onDone} />;
}
```

`ZeroTrustLoginCard` also takes `features` (`passwordReset`, `magicLink`, `signUp`, `passkeyOnlySignUp`) to offer the email flows, and `flow` (`{ type: "reset" | "verify" | "magic" | "enrol", token }`) to open straight into an emailed link; the token comes from the URL fragment (`#flow=…&token=…`). With `enrol`, the card confirms the address and then creates a passkey through the self-service endpoints. See [Email and sign-up](EMAIL_AND_SIGNUP.md).

Keep `session.sessionToken` and `session.refreshToken` in memory, not `localStorage`. Send API calls with `Authorization: DPoP <sessionToken>` and a `DPoP` header made by `dpopHeader(session.deviceKey, method, url, session.sessionToken)`.

## Helpers

| Export | Purpose |
| --- | --- |
| `loadOrCreateDeviceKey(name)` | This browser's P-256 key, created non-extractable and stored as a `CryptoKey` in IndexedDB (memory-only if IndexedDB is unavailable) |
| `dpopHeader(key, method, url, sessionToken?)` | A DPoP proof for one request |
| `request(api, method, path, body?, headers?)` | Calls the server; returns `{ status, body }` and does not throw on HTTP errors |
| `useWorkspace(api, pollMs)` | Tenants, users, families and keys, reloaded on a timer |

## Accessibility

The components are checked with axe in light and dark themes: every control has a label, status is shown with a symbol and a word (never colour alone), changes are announced in live regions, and scrollable regions are keyboard-focusable.

## Next.js

The package is marked `"use client"`. The device key is created in an effect, so server rendering a page that contains the login card is safe.
