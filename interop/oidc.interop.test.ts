/**
 * Independent check: panva's `openid-client` (a widely used, certified-quality OIDC client) talks to the Authvex provider. It does its
 * own discovery, PKCE, state and nonce handling, ID-token validation, userinfo, refresh and DPoP. It is a root dev dependency only: it
 * is never part of a shipped package, and Authvex's own code does not use it.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as client from "openid-client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ClientSchema, ConfigSchema, DEMO_PASSWORD, FileKeyring, Ledger, createAuthvexServer, loadWorkspace, newClientId, newClientSecret, openStore, runInit, writeClients, type AuthvexServer,
} from "../packages/cli/dist/index.js";

let dir: string;
let server: AuthvexServer;
let base: string;
const LIN = "linear_ops_workspace";
const ACME = "acme_fintech_prod";
const CB = "https://app.example.test/callback";

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "authvex-interop-"));
  await runInit(dir);
  const ws = loadWorkspace(dir);
  const cfg = ConfigSchema.parse({ ...ws.config, port: 0, ipRequestsPerMinute: 100_000, store: { kind: "memory" } });
  server = createAuthvexServer({ workspace: { ...ws, config: cfg }, keyring: await FileKeyring.open(dir), store: await openStore(cfg, dir), ledger: new Ledger(join(dir, ".authvex", "ledger.jsonl")) });
  base = `http://127.0.0.1:${(await server.listen()).port}`;
});
afterAll(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

function register(tenantId: string, confidential: boolean): { clientId: string; secret?: string } {
  const ws = loadWorkspace(dir);
  const secret = confidential ? newClientSecret() : null;
  const c = ClientSchema.parse({ clientId: newClientId(), name: "Interop", tenantId, type: confidential ? "confidential" : "public", ...(secret ? { secretHash: secret.hash } : {}), redirectUris: [CB] });
  writeClients(join(ws.root, ws.config.oidc.clients), [c]);
  return { clientId: c.clientId, ...(secret ? { secret: secret.secret } : {}) };
}

/** What the browser does between the authorization URL and the redirect back to the app. */
async function browser(authUrl: URL, tenantId: string, email: string, dpop?: { key: CryptoKeyPair; jwk: JsonWebKey }): Promise<URL> {
  const a = await fetch(authUrl, { redirect: "manual" });
  expect(a.status).toBe(302);
  const request = new URL(a.headers.get("location") as string).searchParams.get("request") as string;
  const login = await (await fetch(`${base}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tenantId, email, password: DEMO_PASSWORD }) })).json() as { sessionToken: string; status: string };
  expect(login.status).toBe("ok");
  void dpop;
  const done = await (await fetch(`${base}/api/oidc/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request, sessionToken: login.sessionToken }) })).json() as { redirectTo: string };
  return new URL(done.redirectTo);
}

describe("openid-client against Authvex", () => {
  it("discovers the issuer, runs the code flow with PKCE, validates the ID token, calls userinfo, and refreshes (public client)", async () => {
    const { clientId } = register(LIN, false);
    const config = await client.discovery(new URL(`${base}/oidc/${LIN}`), clientId, undefined, client.None(), { execute: [client.allowInsecureRequests] });
    expect(config.serverMetadata().issuer).toBe(`${base}/oidc/${LIN}`);
    expect(config.serverMetadata().code_challenge_methods_supported).toEqual(["S256"]);

    const verifier = client.randomPKCECodeVerifier();
    const state = client.randomState();
    const nonce = client.randomNonce();
    const authUrl = client.buildAuthorizationUrl(config, { redirect_uri: CB, scope: "openid email profile offline_access", code_challenge: await client.calculatePKCECodeChallenge(verifier), code_challenge_method: "S256", state, nonce });
    const back = await browser(authUrl, LIN, "margaret@linear-ops.test");

    const tokens = await client.authorizationCodeGrant(config, back, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
    expect(tokens.token_type).toBe("bearer");
    const claims = tokens.claims();
    expect(claims).toMatchObject({ iss: `${base}/oidc/${LIN}`, sub: "usr_margaret", aud: clientId, email: "margaret@linear-ops.test", email_verified: true, name: "Margaret Member", nonce });
    const info = await client.fetchUserInfo(config, tokens.access_token, claims?.sub as string);
    expect(info).toMatchObject({ sub: "usr_margaret", email: "margaret@linear-ops.test" });

    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token as string);
    expect(refreshed.access_token).not.toBe(tokens.access_token);
    expect((await client.fetchUserInfo(config, refreshed.access_token, "usr_margaret")).sub).toBe("usr_margaret");
    await expect(client.refreshTokenGrant(config, tokens.refresh_token as string)).rejects.toThrow();
  });

  it("works for a confidential client using client_secret_basic and client_secret_post", async () => {
    for (const method of ["basic", "post"] as const) {
      const { clientId, secret } = register(LIN, true);
      const auth = method === "basic" ? client.ClientSecretBasic(secret as string) : client.ClientSecretPost(secret as string);
      const config = await client.discovery(new URL(`${base}/oidc/${LIN}`), clientId, undefined, auth, { execute: [client.allowInsecureRequests] });
      const verifier = client.randomPKCECodeVerifier();
      const authUrl = client.buildAuthorizationUrl(config, { redirect_uri: CB, scope: "openid email", code_challenge: await client.calculatePKCECodeChallenge(verifier), code_challenge_method: "S256", state: "s" });
      const tokens = await client.authorizationCodeGrant(config, await browser(authUrl, LIN, "margaret@linear-ops.test"), { pkceCodeVerifier: verifier, expectedState: "s" });
      expect(tokens.claims()?.sub).toBe("usr_margaret");
    }
  });

  it("rejects a wrong state and a wrong nonce on the client's side, and the server rejects a wrong verifier", async () => {
    const { clientId } = register(LIN, false);
    const config = await client.discovery(new URL(`${base}/oidc/${LIN}`), clientId, undefined, client.None(), { execute: [client.allowInsecureRequests] });
    const verifier = client.randomPKCECodeVerifier();
    const url = () => client.buildAuthorizationUrl(config, { redirect_uri: CB, scope: "openid", code_challenge: "" , code_challenge_method: "S256", state: "right", nonce: "n1" });
    void url;
    const challenge = await client.calculatePKCECodeChallenge(verifier);
    const mk = () => client.buildAuthorizationUrl(config, { redirect_uri: CB, scope: "openid", code_challenge: challenge, code_challenge_method: "S256", state: "right", nonce: "n1" });
    await expect(client.authorizationCodeGrant(config, await browser(mk(), LIN, "margaret@linear-ops.test"), { pkceCodeVerifier: verifier, expectedState: "wrong" })).rejects.toThrow();
    await expect(client.authorizationCodeGrant(config, await browser(mk(), LIN, "margaret@linear-ops.test"), { pkceCodeVerifier: verifier, expectedState: "right", expectedNonce: "other" })).rejects.toThrow();
    await expect(client.authorizationCodeGrant(config, await browser(mk(), LIN, "margaret@linear-ops.test"), { pkceCodeVerifier: client.randomPKCECodeVerifier(), expectedState: "right", expectedNonce: "n1" })).rejects.toThrow();
  });

  it("completes a DPoP-bound flow on a tenant that requires it: the library signs proofs for the token and userinfo endpoints", async () => {
    const { clientId } = register(ACME, false);
    const config = await client.discovery(new URL(`${base}/oidc/${ACME}`), clientId, undefined, client.None(), { execute: [client.allowInsecureRequests] });
    const keys = await client.randomDPoPKeyPair();
    const dpop = client.getDPoPHandle(config, keys);
    const verifier = client.randomPKCECodeVerifier();
    const authUrl = client.buildAuthorizationUrl(config, { redirect_uri: CB, scope: "openid email offline_access", code_challenge: await client.calculatePKCECodeChallenge(verifier), code_challenge_method: "S256", state: "s" });
    // The sign-in page itself needs a proof on this tenant (it logs in with its own key): stand in for it.
    const signInKey = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const { createDpopProof } = await import("@authvex/core");
    const jwk = await globalThis.crypto.subtle.exportKey("jwk", signInKey.publicKey);
    const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey;
    const a = await fetch(authUrl, { redirect: "manual" });
    const request = new URL(a.headers.get("location") as string).searchParams.get("request") as string;
    const loginUrl = `${base}/api/auth/login`;
    const login = await (await fetch(loginUrl, { method: "POST", headers: { "content-type": "application/json", dpop: await createDpopProof({ privateKey: signInKey.privateKey, publicKeyJwk: pub, method: "POST", url: loginUrl }) }, body: JSON.stringify({ tenantId: ACME, email: "grace@acme-fintech.test", password: DEMO_PASSWORD }) })).json() as { sessionToken: string; status: string };
    expect(login.status).toBe("ok");
    const completeUrl = `${base}/api/oidc/complete`;
    const done = await (await fetch(completeUrl, { method: "POST", headers: { "content-type": "application/json", dpop: await createDpopProof({ privateKey: signInKey.privateKey, publicKeyJwk: pub, method: "POST", url: completeUrl, sessionToken: login.sessionToken }) }, body: JSON.stringify({ request, sessionToken: login.sessionToken }) })).json() as { redirectTo: string };

    const tokens = await client.authorizationCodeGrant(config, new URL(done.redirectTo), { pkceCodeVerifier: verifier, expectedState: "s" }, undefined, { DPoP: dpop });
    expect(tokens.token_type).toBe("dpop");
    const info = await client.fetchUserInfo(config, tokens.access_token, "usr_grace", { DPoP: dpop });
    expect(info.email).toBe("grace@acme-fintech.test");
    await expect(client.fetchUserInfo(config, tokens.access_token, "usr_grace")).rejects.toThrow();
    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token as string, undefined, { DPoP: dpop });
    expect(refreshed.token_type).toBe("dpop");
    await expect(client.refreshTokenGrant(config, refreshed.refresh_token as string)).rejects.toThrow();
  });
});
