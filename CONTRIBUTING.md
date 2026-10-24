# Contributing

Thanks for helping. Bug reports with a reproduction, and small focused pull requests, are the most useful.

## Setup

You need Node.js 20 or newer.

```bash
git clone https://github.com/isagarpinninti/authvex.git
cd authvex
npm install
npm run build
```

## The checks

```bash
npm run typecheck   # tsc for the root, core, react and cli
npm run lint
npm test            # core (also against Zod 3), react, cli
npm run e2e         # Playwright + axe against the real server and Studio (run `npx playwright install chromium` once)
npm run smoke       # pack, install into a clean project, drive the CLI and the API
npm run bench       # cryptographic hot-path budgets
npm run interop     # third-party clients and frameworks against the built packages
npm run load        # load and soak test (not part of the gates)
AUTHVEX_INVARIANT_RUNS=500 npm test -w @authvex/cli   # more random scripts through the model-based invariant test
npm run gates       # all of the above, in order
```

`npm run dev` starts the Studio on port 3000; open it with `?server=http://localhost:4320` while `authvex studio` runs.

Tests for the PostgreSQL store start a throwaway cluster if `initdb` and `pg_ctl` are installed, or use `AUTHVEX_TEST_DATABASE_URL`; without either they are skipped. Browser projects: `npx playwright install chromium webkit firefox`, then `npm run e2e:browsers`.

## Layout

| Path | What |
| --- | --- |
| `packages/core` | The engine. Web Crypto only: no `node:*` imports, no I/O |
| `packages/cli` | Server, REST API, ledger, commands |
| `packages/react` | The four components, device key, API client |
| `src/` | The Studio (Next.js, static export copied into the CLI) |
| `e2e/`, `scripts/` | Playwright tests, smoke and bench scripts |
| `examples/demo` | The workspace `authvex init` produces |

## Rules of the house

- **No auth or crypto libraries.** `jsonwebtoken`, `bcrypt`, `otplib`, `simplewebauthn` and the like are not allowed, even as dev dependencies of a package that ships. Use Web Crypto.
- **Third-party auth or web libraries are allowed only in root dev dependencies used by `interop/` tests** (`openid-client`, Express, Fastify, Hono), to check Authvex against independent implementations. They never ship.
- **No `any`, no `eval`, no TODOs** left in the tree.
- **A security behaviour comes with a test that tries to break it**, at the lowest level that can show it: against the RFC vector, the pure function, the HTTP API, then the browser.
- **Refusals have a reason code.** Return a stable reason (`key_mismatch`), never a bare `false` or a thrown string.
- **Never log or store a secret.** The ledger test checks that no password, token or key reaches it.
- **Keep it accessible.** The e2e suite runs axe on every Studio view in both themes.

## Pull requests

Describe what changed and why, and mention anything you could not test. CI runs the full set of checks.
