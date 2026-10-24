# Guide: from zero to a protected API

You will start a server, sign a user in with a hardware-bound session, protect an API route, watch a stolen token fail, and see it all in the audit ledger. Each step says what you should see.

## 1. Create a workspace

```bash
mkdir identity && cd identity
npx @authvex/cli init
npx @authvex/cli validate
```

`init` writes `authvex.config.json`, three tenants in `tenants/`, five demo users in `users.json` (every password is `demo-passphrase-1`) and an ES256 issuer key in `.authvex/` (owner-only; git-ignored). `validate` should print `3 tenants and 5 users valid`, with warnings you should read: they tell you what is not yet production-safe.

> The demo users are for trying things. Delete `users.json`'s contents before real use.

## 2. Start the server and open the Studio

```bash
npx @authvex/cli studio
```

It prints an API address, a Studio link with an admin token in the URL fragment, and the issuer key id. Open the link on **`http://localhost:4320`** (use `localhost`, not `127.0.0.1`, if you want to try a real passkey: browsers will not use an IP address as a passkey domain).

## 3. Sign in with a bound session

In **Identity lab**, with *Acme Fintech (production)* selected, sign in as `grace@acme-fintech.test` / `demo-passphrase-1`. You should see *Bound to this device (DPoP)* and a `cnf.jkt` value: the session now belongs to a key your browser holds and cannot export.

That tenant sets `requireDpopHardwareBinding: true`. Try the same sign-in from the command line without a proof and the server blocks it:

```bash
curl -s -X POST localhost:4320/api/auth/login -H 'content-type: application/json' \
  -d '{"tenantId":"acme_fintech_prod","email":"grace@acme-fintech.test","password":"demo-passphrase-1"}'
# 403 { "status": "blocked", "report": { ... "AV-105" fails ... } }
```

## 4. Attack your own session

In the **Stolen-token lab**: *Request as the owner* is accepted. Then try *Replay the stolen cookie (no key)*, *Thief with their own key* and *Replay a captured proof*. Each is refused with its own reason (`dpop_missing`, `key_mismatch`, `replayed`). This is the point of the project: **the token alone is worth nothing**. Watch the **Ledger** on the right record `auth.dpop.rejected`.

## 5. Rotate, replay, and watch the family die

In **Sessions, keys and passkeys**: *Rotate token* moves to generation 2. *Replay old token as a thief* is stopped because the family is bound to a key the thief lacks. *Replay old token from this device* simulates a leaked token being used twice: the whole family is revoked (`AV-104`), including the legitimate session. The ledger records `auth.family.reuse_detected`.

## 6. Protect a real API route

Your API receives `Authorization: DPoP <session token>` and a `DPoP: <proof>` header. Ask Authvex whether they belong together, and whether the user may do this:

```js
async function authorize(req, permission) {
  const r = await fetch("http://localhost:4320/api/auth/dpop-verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      sessionToken: req.headers.authorization?.replace(/^DPoP /, ""),
      dpopProof: req.headers.dpop,
      method: req.method,
      url: `https://api.example.com${req.originalUrl}`,   // exactly the URL the client signed
      requirePermission: permission,
    }),
  });
  const body = await r.json();
  return r.ok ? body.claims : null;                       // claims.sub is the user, claims.tid the tenant
}
```

Or verify locally, with no network call, using `@authvex/core` (it runs on Node, edge runtimes and workers); see the SDK tab for the snippet. Local verification needs the issuer's public key (`GET /api/workspace` → `issuer`) and your own replay cache.

## 7. Add a second factor and passkeys

- **TOTP:** `POST /api/users/totp {"userId":"usr_grace"}` (admin token) returns a secret and an `otpauth://` URI to put in an authenticator app. Admins on tenants with `requireMfaForAdmins` are then asked for a 6-digit code; each code works once.
- **Passkeys:** in the sessions panel pick a user and choose *Register a passkey on this device* (a real WebAuthn ceremony) or *Register a simulated passkey* (software, for demos). Then use *Sign in with a passkey* on the login card. A passkey with user verification satisfies the second-factor requirement.

## 8. Run the threat radar

Open **Threat radar** and press *Simulate impossible travel*. The server evaluates all eight gates and shows the trust score, the level, and the arithmetic: Hyderabad to Frankfurt in 10 minutes is about 7,100 km at about 42,600 km/h against a 900 km/h limit. The same from a terminal:

```bash
npx @authvex/cli evaluate linear_ops_workspace --user usr_ada --geo 50.1109,8.6821,Frankfurt --last-minutes 10
echo $?    # 2: blocked or step-up
```

## 9. Roles, keys and break-glass

- **Roles:** the *Roles and break-glass* tab edits the permission matrix; *Save* is enforced immediately.
- **Machine keys:** `authvex key mint --tenant acme_fintech_prod --name ci --scopes invoices:read` prints an `atk_live_…` key once. A service presents it to `POST /api/verify` with the scope it needs.
- **Break-glass:** `authvex impersonate --actor usr_root --target usr_grace --tenant acme_fintech_prod --reason "TICKET-4411 customer cannot see invoices"` mints a 10-minute read-only seal. Mint, tamper and verify one in the Studio to see a modified seal rejected.

## 10. Check the ledger

```bash
npx @authvex/cli ledger list
npx @authvex/cli ledger verify
```

`verify` prints the entry count and head hash, or the first entry that was edited, removed or reordered.

## 11. Rotate the signing key

Do this on a schedule (say every 90 days) and immediately if you suspect the key file leaked.

```bash
npx @authvex/cli issuer rotate           # new active key; the old one keeps verifying for 25 hours
npx @authvex/cli issuer list
curl -s localhost:4320/.well-known/jwks.json
```

Nobody is signed out: sessions signed by the old key keep working until they expire, and the next refresh issues access tokens from the new key. Your API, if it verifies locally, should fetch `/.well-known/jwks.json` (cache it a few minutes, re-fetch on an unknown `kid`) instead of hard-coding a key.

If the key leaked, do not wait:

```bash
npx @authvex/cli issuer rotate --overlap-hours 0
npx @authvex/cli issuer revoke <old kid>   # its sessions are refused now; users refresh or sign in again
```

## 12. Go to production

1. **Terminate TLS in front** (Caddy, nginx, a load balancer) and set `publicUrl` to the public `https://` address, or DPoP `htu` checks will fail.
2. **Set `rpId` and `origins`** to your real domain and page origins.
3. **Keep `trustClientGeo` off.** Provide location and network from your edge with `trustGeoHeaders: true`, and make sure the edge strips those headers from clients.
4. **Bind to loopback or a private network.** The admin API is only as private as the address you bind and the admin token you share.
5. **Choose where state lives** in `authvex.config.json`: `"store": { "kind": "file" }` (the default; sessions survive a restart) or `"sqlite"` (Node 22.5+; several processes on one machine can share it). `memory` loses everything on restart.
6. **Back up `.authvex/`** (the signing keyring, API key hashes, state, ledger), `users.json` and `tenants/`. Losing `issuers.json` invalidates every token.
7. **Plan for one host.** There is no network database backend yet.
8. **Replace the demo users.**

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `htu_mismatch` on every request | The URL the client signed differs from the one the server expects. Set `publicUrl`, or sign exactly the URL you send |
| `iat_out_of_window` | Client and server clocks differ by more than 60 seconds |
| `origin_mismatch` on passkeys | The page origin is not in `origins` (or you opened `127.0.0.1` when expecting `localhost`) |
| Passkey button says the browser does not support it | WebAuthn needs a secure context: `https://` or `http://localhost` |
| Login returns `403` with `AV-105` | The tenant requires a DPoP proof and none was sent |
| Everyone is signed out after a restart | The `memory` store is configured; use `file` or `sqlite` |
| `unknown_key` on a session that was fine yesterday | Its signing key was revoked or its overlap ended (`authvex issuer list`); the user refreshes or signs in again |
| `authvex ledger verify` says BROKEN | An entry was edited, removed or reordered; the message names the first one |
| Studio says the token was refused | Admin tokens last 24 hours; restart `authvex studio` for a new link |
