# Device testing

What is tested automatically, and the manual procedure for what cannot be.

## Automated (every CI run)

| Engine | What runs | Notes |
| --- | --- | --- |
| Chromium | The whole Studio suite, including a real WebAuthn registration and sign-in through Chromium's virtual authenticator | Also axe accessibility checks in light and dark, and the phone layout |
| WebKit (Safari's engine) | The same suite except the virtual-authenticator test | Passes locally on macOS |
| Firefox | The same suite except the virtual-authenticator test | Runs in CI only; it did not launch on the maintainer's machine, so it has not been seen passing locally |

A virtual authenticator is software. It proves the server accepts what a spec-compliant authenticator sends. It does not prove that a particular YubiKey, Windows Hello, Touch ID or Android phone does.

## Manual: the real-device matrix

Do this before relying on passkeys in production, on each device you care about. It takes about ten minutes per device.

1. Run Authvex on a domain with HTTPS (a tunnel such as `cloudflared tunnel` works) and set `publicUrl` and `webauthn.rpId` / `origins` to match. WebAuthn will not work on a bare IP.
2. Open the Studio's **Sign in** page on the device.
3. Register a passkey (Studio, Sessions and passkeys, Add passkey). Record: did the browser prompt, which authenticator it offered, did registration succeed.
4. Sign out. Sign in with the passkey. Record: success, and whether user verification (biometric/PIN) was asked.
5. Sign in again and check the account's passkey counter in the Studio: it should rise, or stay 0 for a synced passkey.
6. Rotate the session and let it expire; confirm refresh works and a replayed old refresh token revokes the session.
7. Add the result to the table below in a pull request.

| Device | Browser | Authenticator | Register | Sign in | Notes |
| --- | --- | --- | --- | --- | --- |
| _none recorded yet_ | | | | | |

Suggested coverage: a security key (USB/NFC), a platform authenticator on macOS, iOS, Android and Windows, and a phone used as a cross-device authenticator.
