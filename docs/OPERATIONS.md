# Operations

## Choosing a store

| `store.kind` | Survives restart | Shared by | Notes |
| --- | --- | --- | --- |
| `memory` | No | one process | Tests and throwaways. `authvex doctor` warns |
| `file` (default) | Yes | one process | JSON file under `.authvex/` |
| `sqlite` | Yes | processes on one machine | `node:sqlite`, Node 22.5+ |
| `postgres` | Yes | many hosts | `"store": { "kind": "postgres", "urlEnv": "AUTHVEX_DATABASE_URL", "schema": "authvex", "poolSize": 4 }` |

The Postgres URL (`postgres://user:pass@host/db?sslmode=verify-full`) is read from the environment variable, never the config. Tables are created in their own schema on start-up under an advisory lock. Refresh rotation, proof-replay claims, one-time tokens and TOTP counters are single atomic statements, so servers on different hosts agree on who won a race. `users.json`, tenants and the ledger are still files; servers sharing a database must share those too (a shared volume, or deploy them with the same files). Tested against a real PostgreSQL 16 on one machine only.

## Docker

```bash
docker build -t authvex .
docker run --rm -v "$PWD/data:/data" authvex init
docker run -d -p 127.0.0.1:4320:4320 -v "$PWD/data:/data" authvex
```

`docker-compose.example.yml` adds PostgreSQL. **The maintainers have not built these files** (no Docker on their machine); they follow the same pack-and-install path `npm run smoke` checks. Put TLS in front, set `publicUrl` and `rpId`.

## Before going live

```bash
authvex doctor            # --offline skips network checks, --strict makes warnings fail, --json for tools
```

It checks Node version, config, file permissions, whether any user still has the published demo password, `rpId` against `publicUrl`, key age, the store (a real connection to PostgreSQL), SMTP reachability, attestation roots, the metrics token and the ledger chain. It only reads; it prints no secret.

## Metrics and logs

```json
"metrics": { "enabled": true, "tokenEnv": "AUTHVEX_METRICS_TOKEN" },
"logging": { "format": "json", "requests": true }
```

`GET /metrics` needs `Authorization: Bearer $AUTHVEX_METRICS_TOKEN` (16+ characters; the server will not start without it; the admin token does not open it). Series: `authvex_http_requests_total{method,route,status}`, `authvex_http_request_duration_seconds`, `authvex_audit_events_total{type}` (sign-ins, blocks, rotations, `auth.family.reuse_detected`, key changes), `authvex_issuer_keys{status}` (including active key age), process memory, event-loop delay, uptime, build info. Route labels are bounded so scanners cannot create series.

Useful alerts: a rise in `authvex_audit_events_total{type="auth.family.reuse_detected"}`; `auth.login.blocked` spikes; `rate(authvex_http_requests_total{status=~"5.."}[5m]) > 0`; active key age over your rotation policy.

Logs go to stderr, one JSON object per line when `format` is `json`. Request lines carry method, route template, status and milliseconds, never query strings, tokens or addresses.

## Password hashing

```json
"passwordHashing": { "algorithm": "argon2id", "argon2id": { "memoryKiB": 65536, "passes": 3, "parallelism": 1 } }
```

`pbkdf2` (default), `scrypt` (`N` 2^17, r 8, p 1) or `argon2id` (Node 24.7+; the server refuses to start without it). Existing hashes keep working and are replaced at the user's next successful password sign-in (ledger: `password.rehashed`). Stored hashes carry their parameters, and the server refuses parameters large enough to exhaust memory.

## Keys

`authvex issuer rotate` then `revoke`/`prune` as in the [crypto spec](CRYPTO_DPOP_SPEC.md). To keep the key in a KMS or HSM, build the server programmatically with `externalIssuerKey({ publicKeyJwk, signer })` and `staticKeyring(...)`: `signer.sign(data)` must return the raw 64-byte ES256 signature (`derToRawSignature` converts DER from AWS KMS, Google Cloud KMS, Azure Key Vault). A mismatched key or a signer returning DER fails at start-up. Rotation of an external key is done in the KMS; the CLI's key commands only manage the file keyring.

## Refresh grace window

`refreshReuseGraceSeconds` (0 to 60, default 0) lets a device-bound session retry a refresh whose answer was lost: the most recently spent token, presented again inside the window, gets a fresh pair instead of revoking the family. Older tokens, late retries and unbound sessions still revoke. Every use is recorded as `auth.rotate.grace_used`.

## Backups

Back up `users.json`, `tenants/`, `authvex.config.json`, `oidc-clients.json`, `.authvex/issuers.json` (secret), `.authvex/keys.json`, `.authvex/ledger.jsonl` and, for `postgres`, the database. Losing `issuers.json` invalidates every issued token.

## Load testing

```bash
npm run build && npm run load                       # about a minute, file store
AUTHVEX_LOAD_SECONDS=600 AUTHVEX_LOAD_STORE=sqlite npm run load
AUTHVEX_LOAD_STORE=postgres AUTHVEX_DATABASE_URL=postgres://… npm run load
```

It starts the real server in its own process and reports throughput by operation, latency percentiles, whether 64 parallel refreshes of one token yield exactly one winner and 200 parallel replays of one proof exactly one acceptance, and server memory over the soak. On one Apple M2 laptop (Node 24, file store, 16 clients): about 3,000 bound-session verifications per second, 250 rotations per second and 150 password sign-ins per second (PBKDF2 bound); p50 verify 5 ms. These numbers describe that laptop, not your deployment.
