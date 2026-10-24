# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow [Semantic Versioning](https://semver.org/).

## 0.1.0

First release.

- `@authvex/core`: PBKDF2 password vault, RFC 4226 and 6238 HOTP and TOTP, W3C WebAuthn parser and verifier (counter clone detection), RFC 9449 DPoP sessions bound to a key thumbprint (standard `dpop+jwt`), refresh-token families with a reuse kill-switch, the AV-101 to AV-108 threat gate, RBAC, scoped machine API keys, sealed break-glass impersonation, issuer key rotation with JWKS, and a `Store` interface. Web Crypto only.
- `@authvex/cli`: the `authvex` command, the identity server and REST API, file/SQLite/PostgreSQL stores, a hash-chained audit ledger and the bundled Studio.
- `@authvex/react`: `ZeroTrustLoginCard`, `ThreatRadarWorkbench`, `ActiveSessionsAndPasskeysPanel` and `TenantRbacAndImpersonationStudio`, plus a non-extractable browser device key.
- Persistent sessions, issuer key rotation and a model-based invariant test that runs random scripts against the real server.

### Also in this release
- **Email flows.** Sign-up with email confirmation, password reset and magic links, through a from-scratch SMTP client (STARTTLS, implicit TLS, AUTH PLAIN) or a `console`/`file` driver for development. Enumeration-resistant answers, three emails per address per hour, tokens in the URL fragment and stored hashed. Config: `mail`.
- **OpenID Connect provider** per tenant (`/oidc/{tenant}/...`): authorization code flow with mandatory PKCE S256, ID tokens (ES256), refresh with `offline_access`, DPoP at the token and userinfo endpoints, `iss` response parameter (RFC 9207), end-session, a hosted `/signin/` page. `authvex oidc client add|list|remove|rotate-secret`. Checked against the independent `openid-client` library.
- **PostgreSQL store** (`store.kind: "postgres"`) over a from-scratch wire-protocol client (SCRAM-SHA-256, TLS modes). Several servers on several hosts can share sessions. One contract suite runs against every store, including races.
- **Passkey attestation** for `packed` (self and x5c) and `fido-u2f`, with a built-in X.509 reader and chain validation against trust anchors you supply (`attestation` in the config). Other formats are refused.
- **Passkey-only sign-up** (`allowPasskeyOnlySignup`) and **self-service passkeys** (`/api/me/passkeys`), where changing how you sign in needs a device-bound session or your password.
- **Pluggable password hashing**: `scrypt` and `argon2id` (Node 24.7+) beside PBKDF2, with automatic upgrade at the next successful sign-in (`passwordHashing`).
- **Operations:** Prometheus metrics (`metrics`, `GET /metrics`), JSON logs (`logging`), `authvex doctor`, a Dockerfile and compose example (not built by the maintainers: no Docker on their machine).
- **API middleware** in `@authvex/core`: `createGuard` (local JWKS verification or introspection) with adapters `expressGuard`, `fastifyGuard`, `honoGuard` and `withAuthvex` (fetch handlers, Next.js). Verified against real Express 5, Fastify 5 and Hono 4.
- **External signers** (`ExternalSigner`, `externalIssuerKey`): keep the issuer key in a KMS or HSM.
- Opt-in **refresh reuse grace window** (`refreshReuseGraceSeconds`, bound sessions only).
- Fuzz tests for the parsers and every route, a threat model (`docs/THREAT_MODEL.md`), a load and soak script (`npm run load`), Firefox and WebKit end-to-end projects, pinned GitHub Action SHAs, SBOMs and an `npm audit` gate.

### Not done
- No independent security audit. Real hardware authenticators, Firefox locally, Windows and Docker were not tested by the maintainers.
