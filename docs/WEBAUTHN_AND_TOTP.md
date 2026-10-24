# Passkeys (WebAuthn) and TOTP

Both are implemented from the specifications, with no `simplewebauthn`, `otplib`, CBOR or ASN.1 library.

## WebAuthn

### Sign-in flow

1. `POST /api/auth/passkey/challenge { tenantId, email }` returns `{ challengeId, challenge, rpId, allowCredentials }`. The challenge is 32 random bytes, single-use, valid for 2 minutes. An unknown email gets the same shape with an empty `allowCredentials`, so the endpoint does not reveal who has an account.
2. The browser runs `navigator.credentials.get` with that challenge and `userVerification: "required"`.
3. `POST /api/auth/login { tenantId, email, passkey: { challengeId, credentialId, clientDataJSON, authenticatorData, signature } }`. The server verifies the assertion and then runs the risk gate like any other login.

A passkey used with user verification (a biometric or PIN) counts as a second factor, so an admin who signs in with one is not asked for a TOTP code.

### What `verifyWebAuthnAssertion` checks

| Step | Failure reason |
| --- | --- |
| `clientDataJSON` is base64url JSON | `client_data_invalid` |
| `type` is `webauthn.get` | `type_mismatch` |
| `challenge` equals the issued one (constant time) | `challenge_mismatch` |
| `origin` is one of the allowed origins | `origin_mismatch` |
| `authenticatorData`, the signature (DER) and the key parse | `malformed` |
| `rpIdHash` equals SHA-256 of the RP id | `rp_id_mismatch` |
| User Present flag is set | `user_not_present` |
| User Verified flag is set (unless disabled) | `user_not_verified` |
| The counter advanced (when either side is non-zero) | `sign_count_regression` |
| The ECDSA P-256 signature over `authenticatorData ‖ SHA-256(clientDataJSON)` verifies | `bad_signature` |

### The binary format

`authenticatorData` (W3C WebAuthn §6.1):

| Bytes | Field |
| --- | --- |
| 0 to 31 | `rpIdHash`: SHA-256 of the RP id |
| 32 | Flags: bit 0 UP, bit 2 UV, bit 3 BE (backup eligible), bit 4 BS (backed up), bit 6 AT (attested credential data follows), bit 7 ED (extensions follow) |
| 33 to 36 | `signCount`, big-endian unsigned 32-bit |
| 37 on, if AT | AAGUID (16 bytes), credential id length (2 bytes), credential id, COSE public key (CBOR) |

A backed-up credential must also be backup-eligible; the parser rejects the combination otherwise. Trailing bytes are rejected, and the parser throws only `WebAuthnFormatError` on any input (fuzzed in the tests).

The signature WebAuthn produces is ASN.1 DER (`SEQUENCE { INTEGER r, INTEGER s }`); Web Crypto verifies the raw 64-byte `r‖s`. `derToRawSignature` is strict: minimal lengths, no negative integers, no trailing data.

### Cloned authenticators

A hardware key increments its counter on every use. If a signature arrives with a counter that is not greater than the stored one, a copy of the key may exist. Authvex refuses it, writes `auth.passkey.clone_suspected` to the ledger and reports gate `AV-104`. **Synced passkeys** (iCloud Keychain, Google Password Manager) usually report a counter of 0 always; Authvex accepts that: the rule applies only when either value is non-zero.

### Registration

`POST /api/users/passkeys/challenge` then `POST /api/users/passkeys` (admin; users register their own through `/api/me/passkeys`, see [Email and sign-up](EMAIL_AND_SIGNUP.md)) with the `clientDataJSON` and `attestationObject` from `navigator.credentials.create`. Authvex accepts **attestation `none`** only: it extracts and stores the credential id, public key (JWK) and counter, and checks the RP id, origin, UP and UV. It does not verify attestation statements (`packed`, `tpm`, …), so it cannot tell you *which model* of authenticator was used.

### Relying Party settings

`rpId` in `authvex.config.json` must be your app's registrable domain (for example `example.com`), and `origins` the exact page origins (`https://app.example.com`). With `origins` empty, only the server's own address and its `localhost` alias are accepted, which is right for trying it out and wrong for production. Browsers will not use an IP address as an RP id, so open the Studio on `http://localhost:4320`, not `127.0.0.1`, to use a real passkey.

### Software authenticator

`createSoftwareAuthenticator({ rpId, origin })` is a WebAuthn authenticator in software, used by the tests and the demo ("Register a simulated passkey"). It is not a security feature.

## TOTP and HOTP

- RFC 4226 HOTP: HMAC-SHA-1 over the 8-byte big-endian counter, dynamic truncation (`offset = mac[19] & 0x0f`), `10^digits` modulus.
- RFC 6238 TOTP: counter = ⌊unix seconds / 30⌋. Verified against RFC 4226 Appendix D and RFC 6238 Appendix B test vectors (SHA-1), in the test suite.
- Base32 per RFC 4648 (decode accepts lower case, spaces and padding). Secrets are 20 random bytes (160 bits).
- `verifyTotpCode` accepts the current step and one either side by default, compares every candidate in constant time, and returns the matched counter. The server keeps the last accepted counter per user and refuses a code from that step or earlier, so **a code works once**.
- `buildOtpAuthUri` produces the `otpauth://totp/…` URI for authenticator apps. `POST /api/users/totp` enrols a user and returns the secret once.

SHA-1 here is HMAC-SHA-1 as RFC 6238 specifies and every authenticator app implements; it is not used for anything else.

## Passwords

PBKDF2-HMAC-SHA-256, 210,000 iterations, 16-byte random salt, stored as `$ath-pbkdf2$v=1$iter=210000$<salt>$<hash>` (base64url). Passwords are NFKC-normalised first, so the same password typed two ways matches. Verification always performs one derivation (with a dummy salt for a malformed or missing hash) and compares in constant time, so "no such user" and "wrong password" cost the same. `passwordNeedsRehash` tells you when a stored hash uses fewer iterations than today's default.

PBKDF2 is chosen because it is in Web Crypto everywhere (Node, edge runtimes, browsers). It is not memory-hard; the server can use scrypt or Argon2id instead (`passwordHashing`, see [Operations](OPERATIONS.md))..
