import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createGuard, derToRawSignature, externalIssuerKey, rawToDerSignature, type ExternalSigner } from "@authvex/core";
import { DEMO, deviceKey } from "./helpers";
import { ConfigSchema, Ledger, createAuthvexServer, loadWorkspace, openStore, staticKeyring } from "../src";
import { runInit_ } from "./testExports";
import { createDpopProof } from "@authvex/core";

let cleanup: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const c of cleanup.reverse()) await c();
  cleanup = [];
});

describe("a server whose signing key is in a KMS", () => {
  it("signs in, refreshes, serves the admin API and publishes the JWKS, with the private key never in the process", async () => {
    const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
    let signCalls = 0;
    const kms: ExternalSigner = {
      async sign(data) {
        signCalls++;
        const der = rawToDerSignature(new Uint8Array(await globalThis.crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, data as Uint8Array<ArrayBuffer>)));
        return derToRawSignature(der);
      },
    };
    const issuer = await externalIssuerKey({ publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, signer: kms });

    const dir = mkdtempSync(join(tmpdir(), "authvex-kms-"));
    cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
    await runInit_(dir);
    const ws = loadWorkspace(dir);
    const cfg = ConfigSchema.parse({ ...ws.config, port: 0, ipRequestsPerMinute: 100_000, store: { kind: "memory" } });
    const server = createAuthvexServer({ workspace: { ...ws, config: cfg }, keyring: staticKeyring(issuer), store: await openStore(cfg, dir), ledger: new Ledger(join(dir, ".authvex", "ledger.jsonl")) });
    cleanup.push(() => server.close());
    const base = `http://127.0.0.1:${(await server.listen()).port}`;

    const jwks = (await (await fetch(`${base}/.well-known/jwks.json`)).json()) as { keys: Array<{ kid: string }> };
    expect(jwks.keys.map((k) => k.kid)).toEqual([issuer.kid]);
    expect(JSON.stringify(jwks)).not.toContain('"d"');

    const dev = await deviceKey();
    const loginUrl = `${base}/api/auth/login`;
    const login = await fetch(loginUrl, { method: "POST", headers: { "content-type": "application/json", dpop: await createDpopProof({ ...dev, method: "POST", url: loginUrl }) }, body: JSON.stringify({ tenantId: "linear_ops_workspace", email: "margaret@linear-ops.test", password: DEMO }) });
    const s = (await login.json()) as { sessionToken: string; refreshToken: string };
    expect(login.status).toBe(200);

    // An API that only knows the issuer's URL accepts the KMS-signed session.
    const guard = createGuard({ issuer: base });
    const url = "https://api.example.test/x";
    const r = await guard.authenticate({ method: "GET", url, path: "/x", header: (n) => ({ authorization: `DPoP ${s.sessionToken}` } as Record<string, string>)[n.toLowerCase()] ?? undefined });
    expect(r).toMatchObject({ ok: false, error: "dpop_missing" });
    const proof = await createDpopProof({ ...dev, method: "GET", url, sessionToken: s.sessionToken });
    const ok = await guard.authenticate({ method: "GET", url, path: "/x", header: (n) => ({ authorization: `DPoP ${s.sessionToken}`, dpop: proof } as Record<string, string>)[n.toLowerCase()] ?? undefined });
    expect(ok).toMatchObject({ ok: true, claims: { sub: "usr_margaret" } });

    const rotateUrl = `${base}/api/auth/rotate`;
    const rot = await fetch(rotateUrl, { method: "POST", headers: { "content-type": "application/json", dpop: await createDpopProof({ ...dev, method: "POST", url: rotateUrl }) }, body: JSON.stringify({ refreshToken: s.refreshToken }) });
    expect(rot.status).toBe(200);

    expect((await fetch(`${base}/api/workspace`, { headers: { authorization: `Bearer ${server.adminToken}` } })).status).toBe(200);
    expect(signCalls).toBeGreaterThanOrEqual(3); // admin token, login, rotation
  });
});
