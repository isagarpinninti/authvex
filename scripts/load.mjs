// Load and soak test against the real server in its own process, over real HTTP. Not part of the gates: results depend on the machine,
// so it reports numbers and checks correctness under load (no 5xx, replay storms have exactly one winner, memory does not climb)
// rather than enforcing speeds.
//
//   npm run build && node --expose-gc scripts/load.mjs            # about a minute
//   AUTHVEX_LOAD_SECONDS=600 AUTHVEX_LOAD_STORE=sqlite node scripts/load.mjs
//   AUTHVEX_LOAD_STORE=postgres AUTHVEX_DATABASE_URL=postgres://... node scripts/load.mjs
import { spawn, execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { cpus, platform, release, tmpdir, totalmem } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createDpopProof } from "../packages/core/dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const SECONDS = Number(process.env.AUTHVEX_LOAD_SECONDS ?? 30);
const STORE = process.env.AUTHVEX_LOAD_STORE ?? "file";
const CONC = Number(process.env.AUTHVEX_LOAD_CONCURRENCY ?? 16);
const PORT = Number(process.env.AUTHVEX_LOAD_PORT ?? 4399);
const base = `http://127.0.0.1:${PORT}`;
const LIN = "linear_ops_workspace";

const dir = mkdtempSync(join(tmpdir(), "authvex-load-"));
cpSync(join(root, "examples", "demo"), dir, { recursive: true });
const cfgPath = join(dir, "authvex.config.json");
const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
writeFileSync(cfgPath, JSON.stringify({ ...cfg, ipRequestsPerMinute: 100_000, store: { kind: STORE } }, null, 2));
const users = JSON.parse(readFileSync(join(dir, "users.json"), "utf8"));
const user = users.find((u) => u.email === "margaret@linear-ops.test");
const { DEMO_PASSWORD: demoPw } = await import("../packages/cli/dist/index.js");

const child = spawn(process.execPath, [join(root, "packages/cli/dist/bin.js"), "studio", "--port", String(PORT), "--quiet"], { cwd: dir, stdio: ["ignore", "pipe", "pipe"], env: process.env });
let childErr = "";
child.stderr.on("data", (d) => (childErr += d));
const stop = () => { child.kill("SIGTERM"); rmSync(dir, { recursive: true, force: true }); };
process.on("exit", stop);
for (let i = 0; ; i++) {
  try { if ((await fetch(`${base}/api/health`)).ok) break; } catch { /* not up yet */ }
  if (i > 100) { console.error("the server did not start\n" + childErr); process.exit(1); }
  await new Promise((r) => setTimeout(r, 100));
}

const rss = () => Number(execFileSync("ps", ["-o", "rss=", "-p", String(child.pid)]).toString().trim()) / 1024;
const pct = (a, p) => a[Math.min(a.length - 1, Math.floor((p / 100) * a.length))];
const stats = new Map();
const faults = [];
const timed = async (name, fn) => {
  const t = performance.now();
  let status;
  try { status = await fn(); } catch (e) { status = -1; faults.push(`${name}: ${e.message}`); }
  const s = stats.get(name) ?? { ms: [], codes: new Map() };
  s.ms.push(performance.now() - t);
  s.codes.set(status, (s.codes.get(status) ?? 0) + 1);
  stats.set(name, s);
  if (status >= 500 || status === -1) faults.push(`${name} -> ${status}`);
  return status;
};
let connectRetries = 0;
// A burst of new connections can overflow the OS listen backlog (128 on macOS) before the server sees them. Such a request was never
// delivered, so retrying it is safe and says nothing about the server.
const post = async (path, body, headers = {}) => {
  for (let attempt = 0; ; attempt++) {
    try {
      const r = await fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
      return { status: r.status, body: await r.json().catch(() => ({})) };
    } catch (e) {
      const code = e.cause?.code;
      if (attempt < 5 && (code === "ECONNRESET" || code === "ECONNREFUSED") && e.cause?.syscall === "connect") { connectRetries++; await new Promise((r) => setTimeout(r, 20 * (attempt + 1))); continue; }
      throw e;
    }
  }
};
const keyPair = async () => {
  const p = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const j = await crypto.subtle.exportKey("jwk", p.publicKey);
  return { privateKey: p.privateKey, publicKeyJwk: { kty: j.kty, crv: j.crv, x: j.x, y: j.y } };
};
const login = async (key) => {
  const url = `${base}/api/auth/login`;
  const headers = key ? { dpop: await createDpopProof({ ...key, method: "POST", url }) } : {};
  return post("/api/auth/login", { tenantId: LIN, email: user.email, password: demoPw }, headers);
};
const pool = async (n, worker) => Promise.all(Array.from({ length: n }, (_, i) => worker(i)));

console.log(`Authvex load test  store=${STORE}  concurrency=${CONC}  soak=${SECONDS}s`);
console.log(`host: ${cpus().length} x ${cpus()[0]?.model.trim()}, ${(totalmem() / 2 ** 30).toFixed(0)} GiB, ${platform()} ${release()}, node ${process.version}`);
const probe = await login();
if (probe.status !== 200 && probe.status !== 202) { console.error("could not sign in as the demo user:", probe.status, JSON.stringify(probe.body)); process.exit(1); }
if (probe.body.mfaRequired || probe.body.status === "mfa_required") { console.error("the demo user needs a second factor; pick a user without one"); process.exit(1); }

const phase = async (title, seconds, fn) => {
  const end = Date.now() + seconds * 1000;
  const before = [...stats.values()].reduce((a, s) => a + s.ms.length, 0);
  await pool(CONC, async (i) => { while (Date.now() < end) await fn(i); });
  const done = [...stats.values()].reduce((a, s) => a + s.ms.length, 0) - before;
  console.log(`  ${title.padEnd(34)} ${(done / seconds).toFixed(0).padStart(7)} req/s`);
};

// 1. throughput by operation
console.log("\nthroughput");
await phase("sign in (password hash bound)", 5, () => timed("login", async () => (await login()).status));
const sessions = await Promise.all(Array.from({ length: CONC }, async () => { const key = await keyPair(); const s = (await login(key)).body; return { key, s }; }));
await phase("verify a bound session (DPoP)", 5, (i) => timed("verify", async () => {
  const { key, s } = sessions[i];
  const proof = await createDpopProof({ ...key, method: "GET", url: "https://api.example.test/x", sessionToken: s.sessionToken });
  return (await post("/api/auth/dpop-verify", { sessionToken: s.sessionToken, dpopProof: proof, method: "GET", url: "https://api.example.test/x" })).status;
}));
await phase("refresh-token rotation", 5, async (i) => timed("rotate", async () => {
  const sess = sessions[i];
  const url = `${base}/api/auth/rotate`;
  const r = await post("/api/auth/rotate", { refreshToken: sess.s.refreshToken }, { dpop: await createDpopProof({ ...sess.key, method: "POST", url }) });
  if (r.status === 200) sess.s = r.body;
  return r.status;
}));

// 2. correctness under contention
console.log("\ncontention");
{
  const key = await keyPair();
  const s = (await login(key)).body;
  const url = `${base}/api/auth/rotate`;
  const proofs = await Promise.all(Array.from({ length: 64 }, async () => createDpopProof({ ...key, method: "POST", url })));
  const results = await Promise.all(proofs.map((p) => post("/api/auth/rotate", { refreshToken: s.refreshToken }, { dpop: p }).then((r) => r.status)));
  const wins = results.filter((x) => x === 200).length;
  console.log(`  64 parallel refreshes of one token: ${wins} succeeded (must be 1)`);
  if (wins !== 1) faults.push(`parallel refresh had ${wins} winners`);

  const s2 = (await login(key)).body;
  const proof = await createDpopProof({ ...key, method: "GET", url: "https://api.example.test/x", sessionToken: s2.sessionToken });
  const rep = await Promise.all(Array.from({ length: 200 }, () => post("/api/auth/dpop-verify", { sessionToken: s2.sessionToken, dpopProof: proof, method: "GET", url: "https://api.example.test/x" }).then((r) => r.status)));
  const okc = rep.filter((x) => x === 200).length;
  console.log(`  200 parallel replays of one proof:  ${okc} accepted (must be 1)`);
  if (okc !== 1) faults.push(`replay storm accepted ${okc}`);
}

// 3. soak: mixed traffic, memory sampled every second
console.log(`\nsoak (${SECONDS}s mixed)`);
const samples = [];
const sampler = setInterval(() => samples.push(rss()), 1000);
const mixEnd = Date.now() + SECONDS * 1000;
await pool(CONC, async (i) => {
  const mine = sessions[i];
  let n = 0;
  while (Date.now() < mixEnd) {
    n++;
    if (n % 20 === 0) await timed("login", async () => (await login(mine.key)).status);
    else if (n % 5 === 0) {
      const url = `${base}/api/auth/rotate`;
      await timed("rotate", async () => {
        const r = await post("/api/auth/rotate", { refreshToken: mine.s.refreshToken }, { dpop: await createDpopProof({ ...mine.key, method: "POST", url }) });
        if (r.status === 200) mine.s = r.body;
        return r.status;
      });
    } else {
      await timed("verify", async () => {
        const proof = await createDpopProof({ ...mine.key, method: "GET", url: "https://api.example.test/x", sessionToken: mine.s.sessionToken });
        return (await post("/api/auth/dpop-verify", { sessionToken: mine.s.sessionToken, dpopProof: proof, method: "GET", url: "https://api.example.test/x" })).status;
      });
    }
  }
});
clearInterval(sampler);

console.log("\nlatency (ms) across the whole run");
for (const [name, s] of stats) {
  const a = s.ms.sort((x, y) => x - y);
  const codes = [...s.codes].map(([c, n]) => `${c}x${n}`).join(" ");
  console.log(`  ${name.padEnd(8)} n=${String(a.length).padStart(6)}  p50 ${pct(a, 50).toFixed(1).padStart(7)}  p95 ${pct(a, 95).toFixed(1).padStart(7)}  p99 ${pct(a, 99).toFixed(1).padStart(7)}  max ${a[a.length - 1].toFixed(0).padStart(5)}   [${codes}]`);
}

const third = Math.max(1, Math.floor(samples.length / 3));
const avg = (a) => a.reduce((x, y) => x + y, 0) / Math.max(1, a.length);
const early = avg(samples.slice(0, third)), late = avg(samples.slice(-third));
const growth = late - early;
console.log(`\nserver memory (RSS): start ${samples[0]?.toFixed(0)} MiB, early avg ${early.toFixed(0)}, late avg ${late.toFixed(0)}, peak ${Math.max(...samples).toFixed(0)} MiB`);
// Early in a run the JIT and caches are still filling, so a modest rise is normal. A real leak keeps climbing.
const leak = SECONDS >= 30 && growth > Math.max(50, early * 0.5);
if (leak) faults.push(`memory grew ${growth.toFixed(0)} MiB between the first and last third of the soak`);

if (faults.length) {
  console.log(`\nFAILED (${faults.length})`);
  for (const f of [...new Set(faults)].slice(0, 15)) console.log("  - " + f);
  process.exit(1);
}
console.log(`\n(${connectRetries} connection attempts were retried after the OS listen backlog overflowed)`);
console.log("\nok: no server errors, one winner in every race, memory flat");
