# @authvex/core

The identity engine behind [Authvex](https://github.com/isagarpinninti/authvex): PBKDF2 passwords, RFC 6238 TOTP, a W3C WebAuthn binary parser and verifier, RFC 9449 DPoP hardware-bound sessions, refresh-token families with a reuse kill-switch, an impossible-travel threat gate (`AV-101` to `AV-108`), RBAC, scoped API keys and sealed impersonation. **Web Crypto only**: no `jsonwebtoken`, `bcrypt`, `otplib` or `simplewebauthn`, and no `node:*` imports, so it runs on Node 20+, edge runtimes and in browsers.

```bash
npm install @authvex/core zod
```

```ts
import { createDpopProof, generateIssuerKey, issueSessionBundle, verifyDpopSessionRequest } from "@authvex/core";

const issuer = await generateIssuerKey();
const { sessionToken } = await issueSessionBundle({ issuer, userId: "usr_ada", tenantId: "acme", clientPublicKeyJwk: client.publicKeyJwk });

const proof = await createDpopProof({ ...client, method: "GET", url: "https://api.example.com/v1/x", sessionToken });
const result = await verifyDpopSessionRequest({ sessionToken, dpopProof: proof, method: "GET", url: "https://api.example.com/v1/x", issuerPublicKeyJwk: issuer.publicKeyJwk });
// result.ok, or result.reason: "dpop_missing" | "key_mismatch" | "replayed" | "expired" | ...
```

Every verifier returns a result with a stable reason code instead of throwing. Supports Zod `^3.23` and `^4`. See the [crypto spec](https://github.com/isagarpinninti/authvex/blob/main/docs/CRYPTO_DPOP_SPEC.md) and the [WebAuthn and TOTP notes](https://github.com/isagarpinninti/authvex/blob/main/docs/WEBAUTHN_AND_TOTP.md). MIT licensed.
