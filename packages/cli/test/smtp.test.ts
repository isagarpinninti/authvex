import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TLSSocket, createServer as createTlsServer } from "node:tls";
import { afterEach, describe, expect, it } from "vitest";
import { SmtpMailer, type SmtpOptions } from "../src/mail";

interface Script {
  /** Lines advertised after EHLO (without the code). */
  caps?: string[];
  rejectRcpt?: boolean;
  /** Called for each command line the client sends. */
  onCommand?(line: string): void;
  starttls?: { key: string; cert: string };
  silent?: boolean;
}

interface Fake {
  server: Server;
  port: number;
  commands: string[];
  data: string[];
  close(): Promise<void>;
}

const cleanup: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const c of cleanup.splice(0)) await c();
});

async function fakeSmtp(script: Script = {}, tls?: { key: string; cert: string }): Promise<Fake> {
  const commands: string[] = [];
  const data: string[] = [];
  const handle = (socket: Socket | TLSSocket, greet = true): void => {
    let buf = "";
    let inData = false;
    let body = "";
    const say = (s: string): void => void socket.write(`${s}\r\n`);
    if (greet && !script.silent) say("220 fake.test ESMTP ready");
    socket.on("data", (d: Buffer) => {
      buf += d.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (inData) {
          if (line === ".") {
            inData = false;
            data.push(body);
            body = "";
            say("250 queued");
          } else body += `${line.startsWith("..") ? line.slice(1) : line}\n`;
          continue;
        }
        commands.push(line);
        script.onCommand?.(line);
        const verb = line.split(" ")[0]?.toUpperCase();
        if (verb === "EHLO") {
          const caps = script.caps ?? [];
          for (const [i, c] of ["fake.test", ...caps].entries()) say(`250${i === caps.length ? " " : "-"}${c}`);
        } else if (verb === "STARTTLS") {
          say("220 go ahead");
          const upgraded = new TLSSocket(socket as Socket, { isServer: true, key: script.starttls?.key as string, cert: script.starttls?.cert as string });
          handle(upgraded, false); // no new greeting after a TLS upgrade
          socket.removeAllListeners("data");
          return;
        } else if (verb === "AUTH") say("235 authenticated");
        else if (verb === "MAIL") say("250 ok");
        else if (verb === "RCPT") say(script.rejectRcpt ? "550 no such user" : "250 ok");
        else if (verb === "DATA") {
          inData = true;
          say("354 go on");
        } else if (verb === "QUIT") {
          say("221 bye");
          socket.end();
        } else say("500 what");
      }
    });
    socket.on("error", () => undefined);
  };
  const server = tls ? createTlsServer({ key: tls.key, cert: tls.cert }, handle) : createServer(handle);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const f: Fake = { server, port: (server.address() as { port: number }).port, commands, data, close: () => new Promise((r) => (server.close(() => r()), (server as Server & { closeAllConnections?: () => void }).closeAllConnections?.())) };
  cleanup.push(() => f.close());
  return f;
}

const opts = (port: number, over: Partial<SmtpOptions> = {}): SmtpOptions => ({ host: "127.0.0.1", port, from: "noreply@authvex.test", secure: false, startTls: "never", rejectUnauthorized: false, timeoutMs: 3000, ...over });
const msg = { to: "ada@example.test", subject: "Hello", text: "Line one\r\n.Line two starts with a dot\r\nQUIT" };

function selfSigned(): { key: string; cert: string } {
  const dir = mkdtempSync(join(tmpdir(), "authvex-tls-"));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], { stdio: "ignore" });
  return { key: readFileSync(join(dir, "k.pem"), "utf8"), cert: readFileSync(join(dir, "c.pem"), "utf8") };
}
let haveOpenssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  haveOpenssl = false;
}

describe("SMTP client", () => {
  it("delivers a message: EHLO, MAIL FROM, RCPT TO, DATA, QUIT, with the body intact and dot-stuffed", async () => {
    const f = await fakeSmtp();
    await new SmtpMailer(opts(f.port)).send(msg);
    expect(f.commands.map((c) => c.split(" ")[0])).toEqual(["EHLO", "MAIL", "RCPT", "DATA", "QUIT"]);
    expect(f.commands).toContain("MAIL FROM:<noreply@authvex.test>");
    expect(f.commands).toContain("RCPT TO:<ada@example.test>");
    const raw = f.data[0] as string;
    expect(raw).toContain("Subject: Hello");
    expect(raw).toContain("To: ada@example.test");
    const body = raw.split("\n\n")[1] as string;
    expect(Buffer.from(body.replace(/\n/g, ""), "base64").toString("utf8")).toBe(msg.text);
  });

  it("refuses to send a password over a connection that is not encrypted", async () => {
    const f = await fakeSmtp({ caps: ["AUTH PLAIN LOGIN"] });
    await expect(new SmtpMailer(opts(f.port, { user: "u", password: "secret" })).send(msg)).rejects.toThrow(/not encrypted/);
    expect(f.commands.some((c) => c.startsWith("AUTH"))).toBe(false);
  });

  it("refuses when STARTTLS is required but not offered, and does not fall back to clear text", async () => {
    const f = await fakeSmtp({ caps: ["AUTH PLAIN"] });
    await expect(new SmtpMailer(opts(f.port, { startTls: "required" })).send(msg)).rejects.toThrow(/STARTTLS/);
    expect(f.commands.some((c) => c.startsWith("MAIL"))).toBe(false);
  });

  it("reports a rejected recipient, a silent server and a refused connection as errors", async () => {
    const rej = await fakeSmtp({ rejectRcpt: true });
    await expect(new SmtpMailer(opts(rej.port)).send(msg)).rejects.toThrow(/RCPT TO: the server said 550/);
    const quiet = await fakeSmtp({ silent: true });
    await expect(new SmtpMailer(opts(quiet.port, { timeoutMs: 300 })).send(msg)).rejects.toThrow(/in time|timed out/);
    await expect(new SmtpMailer(opts(1)).send(msg)).rejects.toThrow();
  });

  it("refuses an injected header before it connects", async () => {
    const f = await fakeSmtp();
    await expect(new SmtpMailer(opts(f.port)).send({ ...msg, subject: "x\r\nBcc: evil@x.test" })).rejects.toThrow(/line breaks/);
    expect(f.commands).toHaveLength(0);
  });

  it.skipIf(!haveOpenssl)("upgrades with STARTTLS, authenticates with AUTH PLAIN, and sends the credentials only after the upgrade", async () => {
    const pair = selfSigned();
    const seen: string[] = [];
    const f = await fakeSmtp({ caps: ["STARTTLS", "AUTH PLAIN"], starttls: pair, onCommand: (l) => seen.push(l) });
    await new SmtpMailer(opts(f.port, { startTls: "required", user: "mailer", password: "s3cret" })).send(msg);
    expect(seen.map((l) => l.split(" ")[0])).toEqual(["EHLO", "STARTTLS", "EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"]);
    expect(Buffer.from((seen.find((l) => l.startsWith("AUTH")) as string).split(" ")[2] as string, "base64").toString("utf8")).toBe("\0mailer\0s3cret");
    expect(f.data).toHaveLength(1);
  });

  it.skipIf(!haveOpenssl)("connects with implicit TLS, and refuses an untrusted certificate unless told otherwise", async () => {
    const pair = selfSigned();
    const f = await fakeSmtp({}, pair);
    await new SmtpMailer(opts(f.port, { secure: true })).send(msg);
    expect(f.data).toHaveLength(1);
    await expect(new SmtpMailer(opts(f.port, { secure: true, rejectUnauthorized: true })).send(msg)).rejects.toThrow(/self[- ]signed|certificate|unable to verify/i);
    await new SmtpMailer(opts(f.port, { secure: true, rejectUnauthorized: true, tls: { ca: pair.cert } })).send(msg);
    expect(f.data).toHaveLength(2);
  });
});
