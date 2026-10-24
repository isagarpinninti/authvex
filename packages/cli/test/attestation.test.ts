import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createSoftwareAuthenticator } from "@authvex/core";
import { startHarness, type Harness } from "./helpers";
import { runInit_ } from "./testExports";
import { ecRoot } from "../../core/test/fixtures/opensslCerts";

let h: Harness | undefined;
const dirs: string[] = [];
afterEach(async () => {
  await h?.close();
  h = undefined;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const workspaceWithAnchors = async (pem: string): Promise<string> => {
  const dir = mkdtempSync(join(tmpdir(), "authvex-att-"));
  dirs.push(dir);
  await runInit_(dir);
  writeFileSync(join(dir, "anchors.pem"), pem);
  return dir;
};

async function register(harness: Harness) {
  const auth = await createSoftwareAuthenticator({ rpId: "localhost", origin: harness.base });
  const ch = (await harness.call("POST", "/api/users/passkeys/challenge", { userId: "usr_margaret" })).body;
  const reg = await auth.register(ch.challenge);
  return { ch, r: await harness.call("POST", "/api/users/passkeys", { challengeId: ch.challengeId, deviceName: "Key", ...reg }) };
}

describe("passkey attestation policy", () => {
  it("by default asks the browser for none and records what it got", async () => {
    h = await startHarness();
    const { ch, r } = await register(h);
    expect(ch.attestation).toBe("none");
    expect(r.status).toBe(201);
    const stored = h.users().find((u) => u.id === "usr_margaret");
    expect(JSON.stringify(stored)).toContain('"attestation":{"format":"none","type":"none","trusted":false');
  });

  it("asks for direct attestation when a verifiable format is allowed, and refuses a credential that cannot be trusted when that is required", async () => {
    const dir = await workspaceWithAnchors(ecRoot);
    h = await startHarness({ attestation: { formats: ["none", "packed"], trustAnchors: "anchors.pem", requireTrusted: true } }, { dir });
    const { ch, r } = await register(h);
    expect(ch.attestation).toBe("direct");
    expect(r.status).toBe(422);
    expect(r.body["reason"]).toBe("attestation_untrusted");
    expect(h.users().find((u) => u.id === "usr_margaret")?.passkeys ?? []).toHaveLength(0);
  });

  it("refuses a format that is not on the allowed list", async () => {
    h = await startHarness({ attestation: { formats: ["packed"] } });
    const { r } = await register(h);
    expect(r.status).toBe(422);
    expect(r.body["reason"]).toBe("unsupported_attestation");
  });

  it("will not start with trust anchors that are missing or not certificates", async () => {
    const empty = await workspaceWithAnchors("not a certificate");
    await expect(startHarness({ attestation: { formats: ["packed"], trustAnchors: "anchors.pem" } }, { dir: empty })).rejects.toThrow(/no certificates/);
    const gone = await workspaceWithAnchors(ecRoot);
    await expect(startHarness({ attestation: { formats: ["packed"], trustAnchors: "nope.pem" } }, { dir: gone })).rejects.toThrow();
  });

  it("rejects a config that requires trust without anchors", async () => {
    await expect(startHarness({ attestation: { formats: ["packed"], requireTrusted: true } })).rejects.toThrow(/trustAnchors/);
  });
});
