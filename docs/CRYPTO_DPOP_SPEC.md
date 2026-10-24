# Hardware-bound sessions, DPoP and refresh families

This is what Authvex does to make a stolen session token useless, and exactly what it checks. Everything uses Web Crypto (`globalThis.crypto.subtle`): ECDSA P-256 with SHA-256 (ES256), SHA-256, HMAC-SHA-1 (TOTP only) and PBKDF2.

## The problem

A bearer token works for whoever holds it. If a cookie or an `Authorization` header leaks (a browser extension, an XSS bug, a log line, a compromised proxy), the thief *is* the user until it expires. Refresh tokens make this worse: they last for days.

## The two defences

1. **Bind the session to a key (RFC 9449 DPoP).** At sign-in the client proves it holds a private key; the session records that key's thumbprint. Every later request must carry a fresh proof signed by that key. The token alone is not enough.
2. **Detect refresh-token reuse.** Each refresh token works once. A second use of an old one means two parties hold it, so the whole family is revoked.

## Tokens

All Authvex tokens are `<prefix><payload>.<signature>`, where the payload is base64url JSON and the signature is ES256 over the payload part, made with the server's active issuer key. The payload carries a `kid` naming that key, so a verifier holding several keys (across a rotation) picks the right one; the signature must still verify, so a forged `kid` gains nothing. The keys live in `.authvex/issuers.json` (owner-only) and their public halves are published at `/.well-known/jwks.json`.

| Prefix | What | Lifetime |
| --- | --- | --- |
| `ath_sess_` | Access token | Tenant's `sessionTtlSeconds` (default 900) |
| *(none)* | DPoP proof: a standard RFC 9449 `dpop+jwt` (header, payload, signature) in the `DPoP` header. Older versions prefixed it `ath_dpop_`; both are accepted | 60 seconds of clock skew allowed |
| `ath_rt_` | Refresh token: 32 random bytes, opaque, only its SHA-256 is stored | Tenant's `refreshTtlSeconds` (default 7 days) |
| `ath_imp_` | Break-glass impersonation seal | 30 to 900 seconds |
| `ath_adm_` | Admin token for the REST API and the Studio | 24 hours |
| `atk_live_` | Machine API key (not signed: looked up by prefix and compared by hash) | Optional |

### Session claims

```json
{ "v": 1, "typ": "session", "sub": "usr_grace", "tid": "acme_fintech_prod", "fam": "fam_…", "gen": 2,
  "jti": "jti_…", "iat": 1790000000, "exp": 1790000900, "cnf": { "jkt": "<RFC 7638 thumbprint>" } }
```

`cnf.jkt` (RFC 7800) is the SHA-256 thumbprint, base64url, of the client's public key, computed over `{"crv":"P-256","kty":"EC","x":"…","y":"…"}` (RFC 7638). It is absent for unbound sessions.

## DPoP proofs

A proof is a JWT-shaped token: header `{ "typ": "dpop+jwt", "alg": "ES256", "jwk": <public key> }`, payload `{ htm, htu, iat, jti, ath? }`, signed with the client's private key.

| Claim | Meaning |
| --- | --- |
| `htm` | The HTTP method of the request being made |
| `htu` | The request URL without query or fragment |
| `iat` | When the proof was made (seconds) |
| `jti` | A unique id, remembered for 2 minutes so a captured proof cannot be replayed |
| `ath` | base64url SHA-256 of the access token the proof accompanies |

In a browser, the key is generated with `extractable: false`, so page scripts can use it to sign but can never read it; `@authvex/react` stores that `CryptoKey` object in IndexedDB so it survives reloads.

### What the server checks, in order

For `POST /api/auth/dpop-verify` (and `verifyDpopSessionRequest` in `@authvex/core`):

1. The session token has the right prefix, parses, and its signature verifies against the issuer key named by its `kid`. (`malformed`, `unknown_key`, `bad_signature`)
2. It has not expired. (`expired`)
3. If the session has no `cnf`: accepted as an unbound session, unless the tenant requires binding. (`not_bound`)
4. A proof is present. (`dpop_missing`)
5. The proof parses and has `typ: dpop+jwt`, `alg: ES256` and a P-256 `jwk`. (`malformed`)
6. The proof's signature verifies with the key in its own header. (`bad_signature`)
7. `htm` equals the request method; `htu` equals the request URL. (`htm_mismatch`, `htu_mismatch`)
8. `iat` is within 60 seconds of now. (`iat_out_of_window`)
9. `ath` equals the hash of this access token. (`ath_mismatch`)
10. The `jti` has not been seen in the last 2 minutes. (`replayed`)
11. **The proof's key thumbprint equals the session's `cnf.jkt`.** (`key_mismatch`) This is the step that stops a thief who signs a perfectly valid proof with their own key.
12. The refresh family is still active. (`session_revoked`)

Compared values use a constant-time comparison.

### At login and refresh

The `DPoP` request header on `POST /api/auth/login` makes the new session bound to the key in that proof. A tenant with `requireDpopHardwareBinding: true` blocks a login without one (gate `AV-105`). A bound family also needs a proof from the same key to refresh, so a thief with only the refresh token is stopped before the token is even examined.

### The `htu` your server expects

The proof's URL is compared with `publicUrl` from the config when set, otherwise `http://<Host header>`. Behind a TLS proxy, set `publicUrl` to the public `https://` address.

## Refresh-token families

A login starts a **family** (`fam_…`). Its state:

```json
{ "familyId": "fam_…", "currentGeneration": 3, "activeRefreshTokenHash": "<sha256 hex>",
  "consumedRefreshTokenHashes": ["…", "…"], "status": "active", "boundJkt": "…", "expiresAtIso": "…" }
```

`rotateRefreshTokenFamily(family, presentedToken)`:

- presented hash equals the active hash: the active hash moves to the consumed list, generation + 1, a new refresh token is issued;
- presented hash is in the consumed list: **`status` becomes `revoked_reuse_detected`** (gate `AV-104`). The thief's token and the legitimate holder's current token both stop working, because one of them is a copy and the server cannot tell which;
- anything else: `unknown_token`, with no change.

The function is pure and returns the new family; the server stores it, and writes `auth.family.reuse_detected` to the ledger. Because only hashes are stored, a leaked state file cannot be replayed.

## Issuer key rotation

Signing keys have a life cycle: **active** (signs), **retiring** (verifies only, until `verifyUntil`), **retired**.

- `authvex issuer rotate [--overlap-hours n]` generates a new active key. The old one stops signing, its private half is deleted from the file, and it keeps *verifying* for the overlap (default 25 hours: the longest token life, 24 hours for admin tokens, plus an hour). Nobody is signed out. Refresh tokens are opaque, not signed, so they are unaffected: the next rotation issues access tokens from the new key.
- `authvex issuer revoke <kid>` is the emergency stop: the key stops verifying at once, so every token it signed is refused (`unknown_key`) and those users refresh or sign in again. The active key cannot be revoked; rotate first.
- `authvex issuer prune` retires keys whose overlap has passed and removes long-retired ones.
- A running server notices a changed keyring file, so none of this needs a restart.

### Verifying without calling Authvex

`GET /.well-known/jwks.json` returns the keys a verifier should trust right now (the active key and any retiring key inside its overlap), in JWKS form with `kid`, `alg: "ES256"` and `use: "sig"`, never a private half, with `Cache-Control: public, max-age=300`. Pass it to `verifyDpopSessionRequest({ issuerPublicKeyJwk: jwks, … })`: the function accepts a single key or a key set. Cache it for at most a few minutes, and re-fetch when a token names an unknown `kid`. A revoked key disappears from the JWKS within the cache lifetime, so a verifier that caches for five minutes accepts a revoked key's tokens for up to five minutes unless it calls `POST /api/verify` or `dpop-verify` on the server.

## Concurrency and restarts

Rotating a refresh token is a read, a computation and a write. The server writes with **compare-and-set**: the update applies only if the family's status, generation and active token are still what it read. If two requests present the same token at once, one wins and the other re-reads, sees the token consumed, and revokes the family. This holds across processes with the SQLite store, and across a restart with the file or SQLite store, because consumed token hashes, the replay cache and TOTP counters are persisted. A client that retries a refresh request after a timeout, with the same token, is indistinguishable from a thief and will lose its family: retry with the *response* of the first attempt if you have it, otherwise sign in again.

## What this does not protect against

- Malware running in the user's browser *session* can ask the browser to sign proofs with the key while the page is open. DPoP stops theft and replay from another machine, not live control of the original one.
- A non-extractable key is as strong as the browser's key storage. It is not a hardware security module unless the platform puts it in one.
- Whoever can read `.authvex/issuers.json` can sign tokens. Keep it owner-only and out of backups you do not control.
