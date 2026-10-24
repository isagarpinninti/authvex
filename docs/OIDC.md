# OpenID Connect provider

Each tenant is an issuer: `https://id.example.com/oidc/<tenantId>`. Discovery is at `/oidc/<tenantId>/.well-known/openid-configuration`; keys at `/.well-known/jwks.json`. Set `publicUrl` so the issuer URL does not follow the Host header.

## Clients

```bash
authvex oidc client add --tenant acme_fintech_prod --name "Notes app" --redirect https://notes.example.com/callback
authvex oidc client add --tenant acme_fintech_prod --name "Backend" --redirect https://api.example.com/cb --confidential   # prints the secret once
authvex oidc client list | remove <clientId> | rotate-secret <clientId>
```

Clients live in `oidc-clients.json` (secrets stored as SHA-256 hashes). Redirect URIs must be `https`, an `http` loopback address, or a custom app scheme, with no fragment; matching is exact. Scopes: `openid`, `profile`, `email`, `offline_access`.

## What is supported

| | |
| --- | --- |
| Flow | Authorization code only (`response_type=code`), PKCE `S256` mandatory, codes single use and valid 60 s |
| Endpoints | `/authorize`, `/token`, `/userinfo`, `/end_session` |
| ID token | ES256 with `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `at_hash`, `sid`, and `email`, `email_verified`, `name` per scope |
| Client auth | `client_secret_basic`, `client_secret_post`, `none` (public clients). Repeated wrong secrets lock the client out for a while |
| Refresh | With `offline_access`; single use with reuse detection, like native sessions. The client's refresh token cannot be used on the native endpoint |
| DPoP | Sender-constrained tokens at `/token` and `/userinfo` (standard `dpop+jwt`) |
| Mix-up defence | `iss` returned in the authorization response (RFC 9207) |
| Sign-in | `/authorize` redirects to the hosted `/signin/` page (or `oidc.signInUrl`), which uses `ZeroTrustLoginCard` and returns the user with a code |
| Reuse | Presenting a used authorization code revokes what it issued |

Not supported: implicit and hybrid flows, request objects, dynamic client registration, consent screens, `prompt`/`max_age` handling beyond sign-in, federation to other identity providers.

Access tokens are Authvex session tokens carrying `cid` and `scp`, so the [middleware](MIDDLEWARE.md) can require a scope (`scope: "email"`).

Checked against `openid-client` in `interop/oidc.interop.test.ts`.
