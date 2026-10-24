import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PgConnection } from "../src/pg";

/**
 * Gives the tests a PostgreSQL server. If AUTHVEX_TEST_DATABASE_URL is already set (a CI service container) it is used as it is.
 * Otherwise a throwaway cluster is created with whatever PostgreSQL binaries are installed (initdb and pg_ctl), on a free port, with
 * SCRAM authentication, and removed afterwards. With neither, the Postgres tests are skipped.
 */
function findBinDir(): string | null {
  const candidates: string[] = [];
  try {
    candidates.push(execFileSync("pg_config", ["--bindir"], { encoding: "utf8" }).trim());
  } catch {
    /* pg_config is not installed */
  }
  const which = spawnSync("which", ["initdb"], { encoding: "utf8" }).stdout.trim();
  if (which) candidates.push(which.replace(/\/initdb$/, ""));
  candidates.push("/opt/homebrew/bin", "/usr/local/bin");
  for (const root of ["/opt/homebrew/opt", "/usr/lib/postgresql", "/usr/local/opt"]) {
    try {
      for (const d of readdirSync(root).filter((x) => /postgres/i.test(x) || /^\d+$/.test(x))) candidates.push(join(root, d, "bin"), join(root, d));
    } catch {
      /* not there */
    }
  }
  return candidates.find((d) => existsSync(join(d, "initdb")) && existsSync(join(d, "pg_ctl"))) ?? null;
}

const freePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
    s.on("error", reject);
  });

export default async function setup(): Promise<(() => Promise<void>) | void> {
  if (process.env["AUTHVEX_TEST_DATABASE_URL"]) return;
  const bin = findBinDir();
  if (!bin) return;
  const dir = mkdtempSync(join(tmpdir(), "authvex-pg-"));
  const data = join(dir, "data");
  const port = await freePort();
  writeFileSync(join(dir, "pw"), "pw-test-123\n");
  const run = (cmd: string, args: string[]): void => void execFileSync(join(bin, cmd), args, { stdio: "ignore", timeout: 60_000 });
  try {
    run("initdb", ["-D", data, "-U", "authvex", "--auth=scram-sha-256", `--pwfile=${join(dir, "pw")}`, "-E", "UTF8"]);
    run("pg_ctl", ["-D", data, "-o", `-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=${dir} -c fsync=off`, "-w", "-l", join(dir, "log"), "start"]);
    const admin = await PgConnection.open({ host: "127.0.0.1", port, user: "authvex", password: "pw-test-123", database: "postgres", sslmode: "disable" });
    await admin.query("CREATE DATABASE authvex_test");
    admin.close();
  } catch (e) {
    try {
      run("pg_ctl", ["-D", data, "-m", "immediate", "stop"]);
    } catch {
      /* it never started */
    }
    rmSync(dir, { recursive: true, force: true });
    console.warn(`could not start a throwaway PostgreSQL (${e instanceof Error ? e.message : String(e)}); the Postgres tests will be skipped`);
    return;
  }
  process.env["AUTHVEX_TEST_DATABASE_URL"] = `postgres://authvex:pw-test-123@127.0.0.1:${port}/authvex_test`;
  return async () => {
    try {
      run("pg_ctl", ["-D", data, "-m", "immediate", "-w", "stop"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}
