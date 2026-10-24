# Tenants, RBAC, API keys, break-glass, the threat gate and the CLI

## Tenants

One JSON file per tenant under `tenants/`. A user can belong to several tenants with a different role in each.

```json
{
  "id": "acme_fintech_prod",
  "name": "Acme Fintech (production)",
  "domain": "acme-fintech.test",
  "sessionTtlSeconds": 900,
  "refreshTtlSeconds": 604800,
  "requireDpopHardwareBinding": true,
  "requireMfaForAdmins": true,
  "maxImpossibleTravelKmh": 900,
  "maxFailedAttemptsPerWindow": 5,
  "blockDisposableEmails": true,
  "allowSignup": false,
  "allowPasskeyOnlySignup": false,
  "requireVerifiedEmail": false,
  "allowPasswordReset": true,
  "allowMagicLinks": false,
  "roles": [
    { "id": "owner", "name": "Owner", "permissions": ["*"] },
    { "id": "billing", "name": "Billing", "permissions": ["invoices:read", "invoices:write"] }
  ]
}
```

Unknown keys are an error. `authvex validate` also cross-checks users: every membership must name a real tenant and a role that exists in it, ids and emails must be unique.

A user is treated as an **admin** of a tenant when their role grants `tenant:admin`, `keys:manage` or `users:impersonate` (a `*` grants all three). That is what `requireMfaForAdmins` applies to.

## RBAC

A permission is `resource:action`. A grant may be `*` (everything), `resource:*` (any action on a resource) or `*:action`. A request needs one grant that matches.

```
evaluatePermission(tenant, user, "invoices:write")
  → { allowed: true, roleId } | { allowed: false, reason: "not_a_member" | "unknown_role" | "permission_missing" }
```

The Studio's **Roles and break-glass** tab shows the roles as a grid. Ticking a cell adds that exact permission to the role; cells covered by a wildcard are ticked and locked. **Save** sends the tenant to `PUT /api/tenants/:id`, which validates it, rewrites the tenant file, takes effect immediately and records `tenant.updated`. A change that would leave a user with a role that no longer exists is refused with 422.

Resource servers can ask for a permission in the same call that verifies a session: `POST /api/auth/dpop-verify { …, "requirePermission": "invoices:write" }` answers 403 `forbidden` when the session's user lacks it (gate `AV-107`).

## The threat gate: AV-101 to AV-108

`evaluateAuthRiskGate(context, policy)` is pure: the same inputs always give the same report. All eight checks always run, so a report shows everything wrong at once. Each check ends `pass`, `warn`, `fail` or `skipped`.

| Gate | Check | Result |
| --- | --- | --- |
| `AV-101` | Credential and factor integrity | Primary factor not verified: **block**. An admin on a tenant that requires MFA without a second factor: **step up** |
| `AV-102` | Brute-force velocity | Failures in the window ≥ the tenant limit: **block**. At half the limit: step up |
| `AV-103` | Impossible travel | Haversine distance and speed between the last and current login. Under 50 km: ignored (location noise). Faster than the limit: **step up**; faster than 4× the limit: **block** |
| `AV-104` | Refresh-family reuse and clone guard | Family revoked after a replay, or a passkey counter that did not advance: **block** |
| `AV-105` | DPoP hardware binding | Tenant requires it and the proof is missing, invalid or from another key: **block**. A proof that is present and wrong is blocked even when not required. Not bound and not required: a small penalty |
| `AV-106` | Disposable domain and network | Disposable email domain (when the tenant blocks them): **block**. Datacenter or headless network, or a new device fingerprint: step up |
| `AV-107` | RBAC | A requested permission the user lacks: **block** |
| `AV-108` | Break-glass constraints | Reason shorter than 8 characters, a lifetime over 900 s, or a seal that does not verify: **block** |

The report has a **trust score** from 0 to 100 (each non-passing check subtracts its penalty; a blocked report is capped at 39) and a **level**: `LOW` (allow), `STEP_UP_MFA` (a warning check, or a score under 70) or `BLOCK`.

Travel arithmetic: distance is the great-circle distance on a sphere of radius 6371.0088 km; time is at least one minute (two logins in the same second are not infinitely fast). Hyderabad to London in 12 minutes is about 7,720 km at about 38,600 km/h against a 900 km/h limit: a block.

### Where location and network come from

Authvex has no GeoIP database and does not guess. Location and network kind reach the gate only if you provide them:

- `trustGeoHeaders: true` reads `X-Authvex-Geo: lat,lon,city` and `X-Authvex-Asn: residential|mobile|datacenter|headless`. Only enable this when your edge sets them and strips any the client sends.
- `trustClientGeo: true` accepts them in the login body. That lets a client claim any location, so it is for demos and tests only; `authvex validate` warns about it.

With neither, `AV-103` is `skipped`.

## Machine API keys

`atk_live_<8 hex>_<32 characters>`. Only the prefix (`atk_live_…`) and the SHA-256 hash are stored, in `.authvex/keys.json`; the key itself is shown once. Each key has a tenant, scopes (the same `resource:action` grammar), a rate limit per minute and an optional expiry.

`POST /api/verify { "token": "atk_live_…", "scope": "invoices:read" }` answers `{ valid: true, key }` or `{ valid: false, reason }` where the reason is `malformed`, `unknown`, `revoked`, `expired`, `scope_missing` or `rate_limited` (with `retryAfterMs`). A key never reveals which part of it was wrong. The server re-reads `keys.json` when it changes, so a key minted with the CLI works at once on a running server.

## Break-glass impersonation

A support engineer who must see what a customer sees mints a **seal**: `ath_imp_<payload>.<signature>` with `targetUserId` (the subject), `actorAdminId` (RFC 8693 `act`), `tenantId`, `reason`, `readOnly`, `issuedAtIso`, `expiresAtIso` and a `jti`. Rules enforced when minting:

- the actor must hold `users:impersonate` in that tenant (`AV-107`);
- the target must belong to the tenant, and cannot be the actor;
- the reason must be at least 8 characters (a ticket number and a sentence);
- the lifetime is 30 to 900 seconds (default 600);
- read-only unless you ask otherwise.

Every mint, and every refusal, is written to the ledger. A seal altered after signing (a longer expiry, `readOnly: false`) fails verification with `bad_signature`. Your application decides what an impersonation seal may do; Authvex issues and verifies it, and keeps the record.

## The ledger

`.authvex/ledger.jsonl`: one line per security event, each with a hash over its contents and the previous entry's hash. Event types include `auth.login`, `auth.login.failed`, `auth.login.blocked`, `auth.login.step_up`, `auth.rotate`, `auth.family.reuse_detected`, `auth.family.revoked`, `auth.dpop.rejected`, `auth.passkey.clone_suspected`, `passkey.registered`, `user.totp_enrolled`, `key.minted`, `key.revoked`, `impersonation.minted`, `impersonation.refused`, `tenant.updated` and `server.started`. **No password, token, key or TOTP secret is ever written to it**; that is tested.

`authvex ledger verify` recomputes the chain and reports the first entry that was edited, removed or reordered. The CLI and a running server can append to the same file without forking the chain. It is tamper-*evident*: someone who can rewrite the whole file can rebuild a consistent chain, and truncating the end is undetectable from the file alone. Copy the head hash somewhere you trust on a schedule if that matters.

## Configuration: `authvex.config.json`

Every key is optional; unknown keys are an error.

| Key | Default | Meaning |
| --- | --- | --- |
| `port` | `4320` | Port (`0` picks a free one) |
| `host` | `127.0.0.1` | Interface to bind |
| `publicUrl` | `http://<Host header>` | The public base URL clients use; DPoP `htu` is checked against it |
| `rpId` | `localhost` | WebAuthn Relying Party id (your registrable domain) |
| `origins` | `[]` | Allowed page origins for passkeys and browser API calls |
| `tenants` / `users` | `tenants` / `users.json` | Where tenant files and users live |
| `ledger` | `true` | Write the audit ledger |
| `trustClientGeo` | `false` | Accept a client-supplied location (demos only) |
| `trustGeoHeaders` | `false` | Read location and network from edge headers |
| `failedAttemptWindowSeconds` | `900` | Sliding window for `AV-102` |
| `store` | `{ "kind": "file" }` | `file`, `sqlite`, `postgres` or `memory`; see [Operations](OPERATIONS.md) |
| `mail` | none | Email for sign-up, reset and magic links; see [Email and sign-up](EMAIL_AND_SIGNUP.md) |
| `oidc` | `{ "clients": "oidc-clients.json" }` | OpenID Connect clients file and optional `signInUrl`; see [OpenID Connect](OIDC.md) |
| `attestation` | formats `["none"]` | Passkey attestation formats, `trustAnchors` PEM file, `requireTrusted` |
| `passwordHashing` | `pbkdf2` | `pbkdf2`, `scrypt` or `argon2id` and their cost settings |
| `logging` | text, no request lines | `format: "json"`, `requests: true` |
| `metrics` | off | `enabled`, `tokenEnv` for `GET /metrics` |
| `refreshReuseGraceSeconds` | `0` | Retry leeway for lost refresh answers on device-bound sessions |
| `ipRequestsPerMinute` | `30` (max 100000) | Sign-in, challenge and refresh requests allowed per minute per address |
| `maxBodyBytes` | `65536` | Largest request body |

`users.json` holds users: `id` (`usr_…`), `email`, `name`, optional `passwordHash`, `totpSecretB32`, `passkeys`, `orgMemberships` and `lastLoginGeo`. The server rewrites it when a passkey counter, a passkey or a TOTP secret changes. **It is a file, not a database**: it suits a small directory; there is no user self-service sign-up.

## CLI reference

| Command | What it does | Exit codes |
| --- | --- | --- |
| `authvex init [dir]` | Scaffold the config, three demo tenants, five demo users (password `demo-passphrase-1`) and an issuer key; add `.authvex/` to `.gitignore` | 0 |
| `authvex validate [dir]` | Check config, tenants, RBAC and users; warn about risky settings | 0 ok, 1 invalid |
| `authvex evaluate <tenantId> [--user id] [--geo lat,lon,city] [--last-minutes n] [--failed n] [--asn kind] [--no-dpop] [--no-mfa] [--permission r:a] [--family-reused] [--json]` | Run the eight gates | 0 allow, 2 step-up or block |
| `authvex key mint --tenant id --name label --scopes a,b [--rate n] [--ttl s]` | Mint a key, shown once | 0 |
| `authvex key list` / `key revoke <id>` | Manage keys | 0 |
| `authvex impersonate --actor id --target id --tenant id --reason "…" [--ttl s] [--write]` | Mint a sealed token | 0, 1 refused |
| `authvex issuer list` / `rotate [--overlap-hours n]` / `revoke <kid>` / `prune` | Manage the signing keys; see [rotation](CRYPTO_DPOP_SPEC.md#issuer-key-rotation) | 0, 1 refused |
| `authvex studio [dir] [--port n] [--host h] [--no-studio] [--no-ledger] [--quiet]` | Run the server, API and Studio (alias `start`) | 0 |
| `authvex ledger verify` / `ledger list [--limit n]` | Check or read the ledger | 0 intact, 1 broken |
| `authvex token verify <token>` | Verify any `ath_` or `atk_` token against this workspace | 0 valid, 1 not |
| `authvex doctor [dir] [--strict] [--offline] [--json]` | Pre-flight check for production | 0 ok, 1 failed |
| `authvex oidc client add\|list\|remove\|rotate-secret` | OpenID Connect clients; see [OIDC](OIDC.md) | 0 |
| `authvex mail test <address>` | Send a test email | 0, 1 failed |

## REST API

Public endpoints need no token; everything else needs `Authorization: Bearer ath_adm_…` (printed by `authvex studio`).

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /api/health` | none | Version, uptime, tenants, issuer key id, store kind |
| `GET /.well-known/jwks.json` | none | The public keys to verify tokens with (JWKS) |
| `POST /api/auth/passkey/challenge` | none | Start a passkey sign-in |
| `POST /api/auth/login` | none | Password or passkey sign-in, optional `totp`, `DPoP` header. `200 ok`, `401 step_up_required` or `invalid_credentials`, `403 blocked`, `429 rate_limited` |
| `POST /api/auth/dpop-verify` | none | Verify a request's session token and DPoP proof; optional `requirePermission` |
| `POST /api/auth/rotate` | none (DPoP header if bound) | Rotate a refresh token. `409 family_revoked` on reuse |
| `POST /api/verify` | none | Verify an `ath_` token or an `atk_live_` key |
| `GET /api/workspace` | admin | Tenants with matrices, users (no secrets), families, keys, issuer key |
| `PUT /api/tenants/:id` | admin | Replace a tenant's policy |
| `POST /api/evaluate` | admin | Run the gate on a described scenario |
| `POST /api/auth/impersonate` | admin | Mint a break-glass seal |
| `GET/POST /api/keys`, `DELETE /api/keys/:id` | admin | Machine keys |
| `DELETE /api/families/:id` | admin | Revoke a session family |
| `POST /api/users/totp` | admin | Enrol TOTP (secret shown once) |
| `POST /api/users/passkeys/challenge`, `POST /api/users/passkeys` | admin | Register a passkey |
| `GET /api/ledger`, `GET /api/ledger/verify` | admin | Read and verify the ledger |
| `POST /api/auth/signup`, `/verify-email`, `/verify-email/resend`, `/password-reset/request`, `/password-reset/confirm`, `/magic-link/request`, `/magic-link/consume`, `/enrol/request`, `/enrol/consume` | none | Email flows; see [Email and sign-up](EMAIL_AND_SIGNUP.md) |
| `GET/POST /api/me/passkeys`, `POST /api/me/passkeys/challenge`, `DELETE /api/me/passkeys/:id` | the user's own session | Self-service passkeys |
| `/oidc/{tenant}/…`, `/api/oidc/request`, `/api/oidc/complete` | none | OpenID Connect provider; see [OIDC](OIDC.md) |
| `GET /metrics` | metrics bearer token | Prometheus metrics, when enabled |

Login throttling: 30 requests per minute per address on the sign-in, challenge and refresh endpoints, plus the per-account failure window. Failed logins give the same response and the same timing whether or not the account exists, and the gate's report is withheld unless the primary factor was verified.
