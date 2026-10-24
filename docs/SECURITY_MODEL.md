# Security model

What Authvex defends against, what it assumes, and what is yours to do.

## Threats and what answers them

| Threat | Defence | Where it can still hurt |
| --- | --- | --- |
| Stolen access token (XSS, extension, log leak, proxy) | Sessions bound to a client key (DPoP, RFC 9449); each request needs a fresh proof | Malware controlling the original browser while it is open can still sign |
| Stolen refresh token | Single-use rotation; reuse revokes the family; bound families also need a proof to refresh | A leaked token used *before* its owner refreshes, on an unbound family, goes unnoticed until the owner's next refresh |
| Replayed proof | `jti` cache for 2 minutes (persisted with the file and SQLite stores); `iat` within 60 s; `htm`, `htu` and `ath` bound | With the `memory` store, proofs younger than 60 s could be replayed once after a restart |
| Credential stuffing and guessing | Per-account failure window, per-address throttle, PBKDF2 (210k iterations), constant-time compare, uniform responses | PBKDF2 is not memory-hard |
| Phishing | Passkeys are bound to the RP id and origin by the authenticator and re-checked by the server | Passwords and TOTP can still be phished; require passkeys for admins if that matters |
| Cloned passkey | Counter regression is a block | Synced passkeys report 0 and cannot be checked this way |
| Account enumeration | One response and timing for all "no" cases; one challenge shape | Registration and admin APIs are admin-only and do reveal existence |
| Forged tokens | ES256 signatures from the issuer key; constant-time comparisons; a forged `kid` only chooses which key to try | Whoever can read `.authvex/issuers.json` can mint any token |
| Compromised signing key | `authvex issuer rotate`, then `revoke` the old key: its tokens are refused at once | Verifiers that cache the JWKS keep accepting the key until the cache expires (default 5 minutes) |
| Parallel use of one refresh token | Compare-and-set on the family: one request wins, the rest revoke it | A client that retries a timed-out refresh with the same token loses its family |
| Stolen session used to add a passkey | Adding or removing a sign-in method needs a device-bound session or the account password | An unbound session on an account with no credential yet may add the first passkey (the emailed link just proved the mailbox) |
| Insider misuse | Break-glass seals: dual subject, reason, 15-minute cap, ledger entry, optional read-only | The ledger is tamper-evident, not tamper-proof |
| Leaked state files | Refresh tokens and API keys stored only as hashes; the ledger holds no secrets | `users.json` holds password hashes and TOTP secrets: protect it like a secret |

## Defaults

- The server binds `127.0.0.1`. Binding elsewhere prints a warning.
- Admin endpoints need `Authorization: Bearer ath_adm_…`; there are no cookies, so no CSRF surface. Admin tokens last 24 hours and are minted at start-up.
- The Studio's admin token is in the URL **fragment**, which browsers never send; the Studio keeps it in `sessionStorage` for the tab and removes it from the address bar.
- Request bodies are capped (64 KiB by default), challenges expire in 2 minutes and are single-use, and TOTP codes work once (the counters are persisted).
- `.authvex/issuers.json`, `keys.json` and `state.json` are written with mode `0600`. A rotated-out signing key's private half is deleted.
- No telemetry, no outbound connections.

## Assumptions

- TLS terminates in front of the server, and the proxy passes the real `Host` (or you set `publicUrl`).
- Clocks agree within a minute (NTP).
- The operator protects the machine, the issuer key and the files in `.authvex/` and `users.json`.
- Location and network hints come only from an edge you control (`trustGeoHeaders`), never from clients.

## Not implemented (so do not rely on it)

- Attestation formats other than `none`, `packed` and `fido-u2f`, and revocation checking of attestation certificates
- Algorithms other than ES256 / P-256
- Built-in KMS/HSM drivers: the `ExternalSigner` interface exists, you supply the adapter; the CLI itself reads a key file
- Redis; the PostgreSQL store is the network option, and it is unproven at scale
- Per-token revocation lists beyond family revocation
- SAML, social login, SMS
- An independent security audit (see [THREAT_MODEL.md](THREAT_MODEL.md))

## Reporting

See [SECURITY.md](../SECURITY.md).
