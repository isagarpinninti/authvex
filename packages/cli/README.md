# @authvex/cli

Run a self-hosted [Authvex](https://github.com/isagarpinninti/authvex) identity server: passkeys, TOTP, hardware-bound DPoP sessions, a refresh-family kill-switch, the threat gate, RBAC, scoped API keys, sealed break-glass impersonation, a hash-chained audit ledger and the Studio.

```bash
npx @authvex/cli init       # config, demo tenants and users, issuer key
npx @authvex/cli validate
npx @authvex/cli studio     # 127.0.0.1:4320, prints a Studio link
```

| Command | |
| --- | --- |
| `authvex init [dir]` / `validate [dir]` | Scaffold and check a workspace |
| `authvex studio` | Start the server, API and Studio |
| `authvex evaluate <tenant> [...]` | Run the AV-101..108 threat gate (exit 2 on step-up or block) |
| `authvex key mint\|list\|revoke` | Machine API keys (`atk_live_`) |
| `authvex impersonate --actor … --target … --reason "…"` | Sealed, time-boxed support impersonation |
| `authvex issuer list\|rotate\|revoke\|prune` | Rotate the signing key; verifiers read `/.well-known/jwks.json` |
| `authvex ledger verify\|list` | Verify or read the audit ledger |
| `authvex token verify <token>` | Verify any `ath_` or `atk_` token |

Binds to loopback by default; TLS is for your reverse proxy. Configuration, REST API and security notes: [docs](https://github.com/isagarpinninti/authvex/tree/main/docs). MIT licensed.
