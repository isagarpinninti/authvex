# @authvex/react

Embeddable React components for [Authvex](https://github.com/isagarpinninti/authvex): a sign-in card with passkeys, TOTP step-up and a session bound to the browser's non-extractable key, plus operator tools (threat radar, sessions and keys, roles and break-glass).

```bash
npm install @authvex/react zod
```

```tsx
import "@authvex/react/styles.css";
import { ZeroTrustLoginCard } from "@authvex/react";

<ZeroTrustLoginCard baseUrl="https://id.example.com" tenantId="acme_fintech_prod" onSession={(s) => keepInMemory(s)} />;
```

`ZeroTrustLoginCard` is for your users. `ThreatRadarWorkbench`, `ActiveSessionsAndPasskeysPanel` and `TenantRbacAndImpersonationStudio` need an admin token and belong in an internal console. Peer dependencies: `react` 18.2 or newer, `zod` 3.23 or 4. See the [React guide](https://github.com/isagarpinninti/authvex/blob/main/docs/REACT.md). MIT licensed.
