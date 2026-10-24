# Email, sign-up and self-service passkeys

All of this is off until you add a `mail` block to `authvex.config.json`; without it the email endpoints answer 501.

```json
"mail": {
  "driver": "smtp",
  "from": "Authvex <noreply@example.com>",
  "linkBase": "https://app.example.com/auth",
  "smtp": { "host": "smtp.example.com", "port": 587, "startTls": "required", "user": "apikey", "passwordEnv": "SMTP_PASSWORD" }
}
```

Drivers: `smtp` (STARTTLS or implicit TLS with `secure: true`, AUTH PLAIN), `console` (prints messages and their live links, development only), `file` (appends to `.authvex/outbox.jsonl`, used by the tests). The SMTP password comes from the environment variable named by `passwordEnv`, never from the file. `authvex mail test <address>` sends a test message.

Links look like `<linkBase>#flow=<type>&token=<secret>&tenant=<id>`. The secret is in the fragment, so it is never sent to a server or a referrer; the Studio and `ZeroTrustLoginCard` read it and remove it from the address bar. Tokens are stored as hashes, work once, and expire (confirm 24 h, reset 30 min, magic 10 min, passkey set-up 30 min).

## Tenant switches

| Field | Meaning |
| --- | --- |
| `allowSignup`, `signupRoleId` | Anyone may create an account with that role. The role may not carry admin permissions |
| `allowPasskeyOnlySignup` | With `allowSignup`: sign up without a password |
| `requireVerifiedEmail` | Refuse sign-in until the address is confirmed |
| `allowPasswordReset` | Default true |
| `allowMagicLinks` | A sign-in link by email. This is a single factor equal to a password |

## Flows

- **Sign-up** `POST /api/auth/signup { tenantId, email, name, password? }` answers 202 whether or not the address exists (an existing owner gets a note instead). Passwords go through the password policy (length 12+, common and repeated patterns refused).
- **Confirm** `POST /api/auth/verify-email`, **resend** `/api/auth/verify-email/resend`.
- **Reset** `/api/auth/password-reset/request` and `/confirm`. A reset signs out every session of that user. A weak new password does not use up the link.
- **Magic link** `/api/auth/magic-link/request` and `/consume`. An admin who owes a second factor is asked for a TOTP code and the link survives that step.
- Each address may receive three emails of a kind per hour.

## Passkey-only accounts

With `allowPasskeyOnlySignup`, sign-up without `password` creates an account with no credential and emails a set-up link. `POST /api/auth/enrol/consume` signs that account in once (through the normal threat gate) so it can register its first passkey; it refuses any account that already has a password or a passkey, so it cannot be used as a second magic link. `POST /api/auth/enrol/request` sends a fresh link to an account that is still stuck.

## Self-service passkeys

For a signed-in user, with their own session in `Authorization: DPoP <token>` (and a proof when the session is bound):

| Endpoint | Purpose |
| --- | --- |
| `GET /api/me/passkeys` | List passkeys |
| `POST /api/me/passkeys/challenge` then `POST /api/me/passkeys` | Register one |
| `DELETE /api/me/passkeys/:credentialId` | Remove one |

Adding or removing a sign-in method needs a session bound to a device key, or the account password in the body (`{ "password": "…" }`). The only exception is the first passkey of a brand-new passkey-only account. A passkey-only user cannot remove their last passkey. Sessions issued to OpenID clients cannot use these routes.

## Attestation

By default the server asks browsers for no attestation. To record or require the authenticator model:

```json
"attestation": { "formats": ["none", "packed", "fido-u2f"], "trustAnchors": "attestation-roots.pem", "requireTrusted": true }
```

`trustAnchors` is a PEM file of root certificates (for example vendor roots from the FIDO Metadata Service) next to the config. `requireTrusted` refuses any credential whose attestation does not chain to one of them (this also refuses `none` and self attestation). Supported certificate signatures: ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, RSA PKCS#1 SHA-256. Not checked: revocation, name constraints, path length. Each passkey records `attestation: { format, type, trusted, aaguid, vendor }`.
