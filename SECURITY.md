# Security policy

## Reporting a vulnerability

Please report it privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue for something exploitable.

Include what you found, how to reproduce it, and the version of Authvex. You will get an acknowledgement within a few days. Fixes ship as a patch release and are credited if you wish.

## What counts

Authvex issues and verifies credentials, so the most serious reports are about:

- a session, refresh token, DPoP proof, impersonation seal or API key being accepted when it should not be (including one bound to a different key, replayed, expired or altered)
- a way to sign in without a valid factor, or to bypass the threat gate, a tenant's binding or MFA requirement, or an RBAC check
- account enumeration through responses or timing on the sign-in and passkey endpoints
- a way to forge a token or an admin token without the issuer key
- a password, token, key, TOTP secret or the issuer key appearing in a log, the ledger, an error message, a response or a file with loose permissions
- a request that crashes the server or makes it use unbounded memory or CPU
- the Studio exposing its admin token to a server, another site or a log
- a flaw in the WebAuthn, CBOR, DER or TOTP parsing that accepts malformed input

## How it is designed

See the [security model](docs/SECURITY_MODEL.md) for the threats, the defences, the assumptions and what is not implemented.

## Supported versions

The latest release receives fixes.
