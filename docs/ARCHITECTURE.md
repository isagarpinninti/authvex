# Architecture

```
 browser (non-extractable key) ──DPoP proof──▶ your API ──POST /api/auth/dpop-verify──┐
 browser ── login / rotate ───────────────────────────────────────────────────────────┤
                                                                                      ▼
                                       @authvex/cli server ──▶ @authvex/core
                                       ├ HTTP routes            ├ passwords, TOTP (RFC 6238)
                                       ├ Store: families, replay  ├ WebAuthn parser and verifier
                                       ├ users.json, tenants/   ├ DPoP and refresh families (RFC 9449)
                                       ├ keys.json (hashes)     ├ threat gate AV-101..108
                                       └ hash-chained ledger    └ RBAC, API keys, impersonation seals
```

## Packages

**`@authvex/core`** is pure TypeScript on Web Crypto and has no I/O: no files, no sockets, no `node:*` imports. The same code runs in Node 20+, edge runtimes and browsers, which is why the React package can create DPoP proofs with it and a worker can verify sessions with it. Its only dependency is a `zod` peer (`^3.23` or `^4`). Everything is a function from inputs to a result, with the clock passed in, so it is tested without mocks of time or randomness.

**`@authvex/cli`** adds what core deliberately leaves out: config and file loading, the HTTP server, per-address throttling, the in-memory stores (session families, challenges, failed-attempt windows, TOTP counters, DPoP replay cache), persistence of users and keys, the ledger, and the commands. It serves the Studio's static export.

Two seams make it durable and rotatable. The **`Store`** interface (defined in core, with a `MemoryStore`) holds everything that must survive a restart or be shared: session families, the refresh-token index, the DPoP replay cache, failure windows, challenges and TOTP counters. `FileStore` adds a JSON file; `SqliteStore` uses `node:sqlite` in WAL mode. Refresh rotation is a compare-and-set on the family, so two parallel uses of one token cannot both succeed, in one process or two. The **`Keyring`** (pure functions in core, a file in the CLI) holds the issuer keys with their life cycle, and the server re-reads it when the file changes.

**`@authvex/react`** is the four embeddable components plus the browser device key and a small API client. They call the same REST API your own code would.

**The Studio** (`src/`) is a Next.js static export bundled into the CLI package. It composes the React components and adds a directory, a ledger feed, a token inspector and the stolen-token lab.

## A login's path

1. The client sends credentials, and a `DPoP` header signed by its key.
2. The server finds the user in the tenant, verifies the password (always one derivation) or the passkey assertion, and a TOTP code if given.
3. It builds a risk context from those results, the failure window, the previous location and the DPoP check, and runs the eight gates.
4. `BLOCK` returns 403 with the report; `STEP_UP_MFA` returns 401 `step_up_required`; otherwise a session family is created, bound to the proof's key, and the access and refresh tokens are returned.
5. Each outcome is written to the ledger.

## Design decisions

- **Web Crypto only.** `jsonwebtoken`, `bcrypt`, `otplib` and `simplewebauthn` are not used and not allowed. Each primitive is small enough to read and to test against its RFC.
- **Pure verification functions.** `verifyDpopSessionRequest`, `verifyWebAuthnAssertion`, `rotateRefreshTokenFamily` and `evaluateAuthRiskGate` take everything as arguments and return a result object with a reason, never a thrown string, so the caller can log, count and explain every refusal.
- **Reasons, not booleans.** Every refusal has a stable code (`key_mismatch`, `sign_count_regression`, …) that the API returns and the ledger records.
- **Hash what you store.** Refresh tokens and API keys are kept as SHA-256 hashes; the ledger records hashes and facts, never secrets.
- **One writer discipline for the ledger.** It re-reads its last line before each append, so the CLI and a running server share a file without forking the chain.
- **Enumeration resistance.** Unknown user, wrong password, wrong tenant and missing password give one response and similar timing; passkey challenges have one shape.

## What it is not

Not a hosted identity product: no social login, no SAML or federation to other identity providers, no SMS, no compliance attestations. It is an OpenID Connect *provider* for your own apps, and it has a basic email client for sign-up, reset and magic links. It has not been independently audited ([threat model](THREAT_MODEL.md)).
