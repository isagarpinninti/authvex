# Threat model

This is the maintainers' own analysis. **It is not an independent security review.** No outside firm has audited Authvex; until one has, treat the claims here as engineering intent backed by the tests listed at the end, not as assurance. If you need assurance for a regulated product, commission a review and publish it.

## Assets, in order of value

1. **The issuer signing key** (`.authvex/issuers.json`, or your key backend). Whoever holds it can mint any session, admin or OIDC token.
2. **User secrets** (`users.json`): password hashes, TOTP secrets, passkey public keys.
3. **Live sessions**: refresh tokens (stored only as hashes), device bindings.
4. **The ledger**: the audit trail of who did what.
5. **The store** (file, SQLite or PostgreSQL): session families, replay cache, one-time tokens.

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
| --- | --- | --- |
| Network to server | Your TLS-terminating proxy | Everything that reaches it: browsers, bots, other tenants' users |
| Server to store | The database role you created for it | Anyone who can read the store files or the database |
| Server to mail relay | The SMTP relay you configured | Recipients, and anyone who can read their inbox |
| Relying application to Authvex | Tokens it verifies against the JWKS | Tokens it is shown |
| OIDC client to Authvex | Clients registered by an operator | Redirect URIs and parameters supplied at request time |

## Adversaries considered

- **Remote unauthenticated attacker** probing endpoints, guessing credentials, replaying captured traffic.
- **Authenticated low-privilege user** trying to reach another tenant or a higher role.
- **Token thief**: has one access token or one refresh token from a log, an extension or a proxy.
- **Phisher** with a convincing page and a captured password or TOTP code.
- **Malicious or curious database reader** (a leaked backup, an over-broad SQL role).
- **Malicious mail recipient** abusing reset and magic links.
- **Malicious OIDC client** or a victim tricked into starting a flow with attacker parameters.

Out of scope: a compromised host, a malicious operator with the issuer key, side channels in the runtime, denial of service by a network-level flood (use your edge), and any weakness in Node.js or the platform's Web Crypto.

## Threats by component

### Tokens and sessions
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Forged or altered token | ES256 signature; `kid` only selects a key; every verifier rejects unknown, retired or revoked keys | Compromise of the issuer key |
| `alg` confusion | The algorithm is fixed; a token naming another is refused | none known |
| Stolen access token | DPoP binding (RFC 9449), `ath`, `htm`, `htu`, `iat`, `jti` replay cache | Malware inside the legitimate browser |
| Stolen or replayed refresh token | Single use; reuse revokes the family; compare-and-set so parallel use has one winner | An unbound token used by the thief first is detected only at the owner's next refresh |
| Replay after restart or on a second node | Replay cache lives in the shared store | The `memory` store forgets on restart |
| Key compromise | Rotation, overlap window, revocation, JWKS | Verifiers cache the JWKS for up to 5 minutes |

### Passwords, TOTP, passkeys
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Credential stuffing | Per-account and per-address windows, uniform responses and timing | Distributed low-rate attacks stay under the windows |
| Offline cracking of a leaked `users.json` | PBKDF2-SHA256, 210,000 iterations, per-user salt | Not memory-hard; a pluggable scrypt/Argon2id hasher is available |
| TOTP replay | Counter persisted and only moves forward | A phished code used within its window by the attacker first |
| Passkey phishing | RP id and origin checked from signed client data; user presence/verification flags enforced | Attestation formats other than the supported ones are not verified |
| Cloned authenticator | Signature-counter regression blocks | Synced passkeys report 0 |

### Email flows
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Account enumeration | Identical 202 response and similar timing for known and unknown addresses | Timing differences under load are not guaranteed to be hidden |
| Mail bombing | 3 messages per address per hour; per-IP throttle | A relay that does not rate limit by itself |
| Link theft from referrers or logs | Token is in the URL fragment, stored as a hash, single use, short life | A mailbox the attacker controls |
| Header injection | Addresses and subjects are validated; CR/LF refused | none known |
| Reset as takeover | Reset revokes every session; password policy applies | A compromised mailbox is a compromised account |

### OIDC provider
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Code interception | PKCE S256 mandatory; codes single use and short lived; reuse revokes what the code issued | none known |
| Open redirect | Exact-match registered redirect URIs; unregistered ones never get a redirect | A registered URI that itself redirects |
| Mix-up | `iss` returned in the authorization response (RFC 9207) | none known |
| Client secret guessing | Hashed storage; lockout after repeated failures | A leaked secret until rotated |
| ID token misuse | `aud`, `nonce`, `at_hash`, `sid`; ES256 with the tenant issuer | Clients that skip validation |

### Server, store, ledger
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Oversized or malformed requests | 64 KiB body cap, strict schemas, JSON errors are 400 | Slow-body attacks need a proxy timeout |
| SQL injection | Parameterised queries only; schema name validated; fuzz and contract tests with hostile strings | none known |
| Cross-tenant access | Tenant id is part of every token and lookup; RBAC evaluated per tenant | Operator misconfiguration of roles |
| Admin API abuse | Signed admin bearer token, no cookies (no CSRF), 24 h life | Anyone who obtains that token |
| Ledger tampering | Hash chain, verified on demand | Tamper-evident, not tamper-proof: the last entries can be truncated by someone with file access |
| Leaked backups | Hashes only for refresh tokens and API keys; key file mode 0600 | `users.json` holds TOTP secrets in the clear: protect it |

## What the tests cover

- `packages/core/test/fuzz.test.ts`: random and mutated input to CBOR, authenticator data, DER, token, JWT, DPoP, PKCE and WebAuthn verifiers. Nothing may throw an unexpected error and nothing forged may verify.
- `packages/cli/test/fuzz.test.ts`: random bodies, headers, query strings, odd paths and methods against every route over real HTTP. Nothing may produce a 5xx (the deliberate 501 "not configured" aside). This found one real bug (malformed JSON to the OIDC sign-in completion returned 500).
- `packages/cli/test/invariants.test.ts`: a model of the session machine checked against the real server on random scripts, with a planted-bug check.
- `packages/cli/test/storeContract.test.ts`: one contract across every store, including races.
- `interop/`: an independent client library (`openid-client`) validating the OIDC provider.

## What nobody has checked

- Behaviour with real hardware authenticators across vendors.
- Safari, Firefox and Windows in production-like conditions (see `docs/DEVICE_TESTING.md`).
- Anything under hostile network conditions at scale.
- A line-by-line review by someone who did not write the code.
