import { randomBytes } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { connect as netConnect, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { STATE_DIR, type AuthvexConfig } from "./config";

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

/** Sends transactional email. `send` resolves when the message was accepted for delivery and rejects when it was not. */
export interface Mailer {
  readonly kind: string;
  send(message: MailMessage): Promise<void>;
}

const ADDRESS = /^[^\s@<>"',;:\\\r\n]+@[A-Za-z0-9.-]+$/;

/** Header values and addresses must not carry line breaks: that is how a header-injection attack adds a Bcc line or a second message. */
export function assertSafeMessage(from: string, m: MailMessage): void {
  if (!ADDRESS.test(from)) throw new Error(`"${from}" is not a usable sender address`);
  if (!ADDRESS.test(m.to)) throw new Error(`"${m.to}" is not a usable recipient address`);
  if (/[\r\n]/.test(m.subject)) throw new Error("a subject cannot contain line breaks");
  if (m.subject.length > 200) throw new Error("the subject is too long");
}

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");
const wrap76 = (s: string): string => s.replace(/(.{76})/g, "$1\r\n");
/** RFC 2047 encoded-word for a non-ASCII subject. */
const encodeSubject = (s: string): string => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${b64(s)}?=`);

/** The complete RFC 5322 message, with a base64 UTF-8 body (so no body line can look like an SMTP command or a lone dot). */
export function buildMessage(from: string, m: MailMessage, now = new Date(), id = randomBytes(12).toString("hex")): string {
  assertSafeMessage(from, m);
  const domain = from.slice(from.indexOf("@") + 1);
  return [
    `From: ${from}`, `To: ${m.to}`, `Subject: ${encodeSubject(m.subject)}`, `Date: ${now.toUTCString().replace("GMT", "+0000")}`, `Message-ID: <${id}@${domain}>`, "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: base64", "", wrap76(b64(m.text)), "",
  ].join("\r\n");
}

/** Records messages in memory: for tests and for embedding. */
export class MemoryMailer implements Mailer {
  readonly kind = "memory";
  readonly sent: MailMessage[] = [];
  failWith: Error | null = null;
  async send(m: MailMessage): Promise<void> {
    if (this.failWith) throw this.failWith;
    this.sent.push(m);
  }
  /** The most recent message to an address. */
  lastTo(address: string): MailMessage | undefined {
    return [...this.sent].reverse().find((m) => m.to.toLowerCase() === address.toLowerCase());
  }
}

/** Prints each message to the log: handy while developing. Links in it are live: do not use it in production. */
export class ConsoleMailer implements Mailer {
  readonly kind = "console";
  constructor(private readonly log: (line: string) => void) {}
  async send(m: MailMessage): Promise<void> {
    this.log(`mail to ${m.to}: ${m.subject}\n${m.text}`);
  }
}

/** Appends each message to a JSON-lines file (owner-only). It holds live links, so treat it as a secret. */
export class FileMailer implements Mailer {
  readonly kind = "file";
  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
  }
  async send(m: MailMessage): Promise<void> {
    appendFileSync(this.path, `${JSON.stringify({ at: new Date().toISOString(), ...m })}\n`, { mode: 0o600 });
  }
}

export interface SmtpOptions {
  host: string;
  port: number;
  from: string;
  /** Connect with TLS from the first byte (port 465). */
  secure: boolean;
  /** For a plain connection: `required` refuses to continue without STARTTLS, `opportunistic` uses it when offered, `never` stays in clear text. */
  startTls: "required" | "opportunistic" | "never";
  user?: string;
  password?: string;
  rejectUnauthorized: boolean;
  timeoutMs: number;
  /** The name to introduce ourselves with in EHLO. */
  helo?: string;
  /** For tests: extra TLS options (such as a CA). */
  tls?: { ca?: string };
}

class SmtpError extends Error {
  constructor(message: string, readonly code?: number) {
    super(message);
  }
}

/** One SMTP conversation: a reader that yields complete replies (multi-line replies joined) and a writer. */
class Conversation {
  private buffer = "";
  private waiting: { resolve(r: { code: number; lines: string[] }): void; reject(e: Error): void } | null = null;
  private replies: Array<{ code: number; lines: string[] }> = [];
  private pending: string[] = [];
  private error: Error | null = null;

  constructor(private socket: Socket | TLSSocket, private readonly timeoutMs: number) {
    this.attach(socket);
  }

  private attach(s: Socket | TLSSocket): void {
    s.setEncoding("utf8");
    s.on("data", (d: string) => {
      this.buffer += d;
      let nl: number;
      while ((nl = this.buffer.indexOf("\r\n")) >= 0) {
        const line = this.buffer.slice(0, nl);
        this.buffer = this.buffer.slice(nl + 2);
        const m = /^(\d{3})([ -])/.exec(line);
        if (!m) return this.fail(new SmtpError(`unexpected server line: ${line.slice(0, 80)}`));
        this.pending.push(line.slice(4));
        if (m[2] === " ") {
          this.replies.push({ code: Number(m[1]), lines: this.pending });
          this.pending = [];
          this.flush();
        }
      }
    });
    s.on("error", (e) => this.fail(e));
    s.on("close", () => this.fail(new SmtpError("the connection closed unexpectedly")));
  }

  private fail(e: Error): void {
    this.error ??= e;
    this.waiting?.reject(e);
    this.waiting = null;
  }
  private flush(): void {
    const next = this.replies.shift();
    if (next && this.waiting) {
      const w = this.waiting;
      this.waiting = null;
      w.resolve(next);
    }
  }

  reply(): Promise<{ code: number; lines: string[] }> {
    if (this.replies.length > 0) return Promise.resolve(this.replies.shift() as { code: number; lines: string[] });
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new SmtpError("the server did not answer in time")), this.timeoutMs);
      this.waiting = { resolve: (r) => (clearTimeout(timer), resolve(r)), reject: (e) => (clearTimeout(timer), reject(e)) };
    });
  }

  async expect(codes: number[], what: string): Promise<{ code: number; lines: string[] }> {
    const r = await this.reply();
    if (!codes.includes(r.code)) throw new SmtpError(`${what}: the server said ${r.code} ${r.lines.join(" ").slice(0, 120)}`, r.code);
    return r;
  }

  write(data: string): void {
    this.socket.write(data);
  }

  async command(line: string, codes: number[], what: string): Promise<{ code: number; lines: string[] }> {
    this.write(`${line}\r\n`);
    return this.expect(codes, what);
  }

  /** Replaces the socket with a TLS one wrapped around it (after STARTTLS). */
  upgrade(tls: TLSSocket): void {
    this.socket.removeAllListeners("data");
    this.socket.removeAllListeners("close");
    this.socket = tls;
    this.buffer = "";
    this.replies = [];
    this.pending = [];
    this.error = null;
    this.attach(tls);
  }
  get current(): Socket | TLSSocket {
    return this.socket;
  }
  end(): void {
    this.socket.destroy();
  }
}

/** A small SMTP submission client (RFC 5321, STARTTLS per RFC 3207, AUTH PLAIN per RFC 4616). It refuses to send a password in clear text. */
export class SmtpMailer implements Mailer {
  readonly kind = "smtp";
  constructor(private readonly o: SmtpOptions) {}

  async send(m: MailMessage): Promise<void> {
    const o = this.o;
    const body = buildMessage(o.from, m);
    const tlsOpts = { host: o.host, servername: o.host, rejectUnauthorized: o.rejectUnauthorized, ...(o.tls?.ca ? { ca: o.tls.ca } : {}) };
    const socket: Socket | TLSSocket = o.secure ? tlsConnect({ ...tlsOpts, port: o.port }) : netConnect({ host: o.host, port: o.port });
    socket.setTimeout(o.timeoutMs, () => socket.destroy(new SmtpError("the connection timed out")));
    const c = new Conversation(socket, o.timeoutMs);
    const helo = o.helo ?? "authvex.local";
    try {
      await c.expect([220], "greeting");
      let caps = (await c.command(`EHLO ${helo}`, [250], "EHLO")).lines.map((l) => l.toUpperCase());
      let encrypted = o.secure;
      if (!encrypted && o.startTls !== "never") {
        if (caps.some((l) => l.startsWith("STARTTLS"))) {
          await c.command("STARTTLS", [220], "STARTTLS");
          const upgraded = tlsConnect({ ...tlsOpts, socket: c.current });
          await new Promise<void>((resolve, reject) => {
            upgraded.once("secureConnect", () => resolve());
            upgraded.once("error", reject);
          });
          c.upgrade(upgraded);
          encrypted = true;
          caps = (await c.command(`EHLO ${helo}`, [250], "EHLO after STARTTLS")).lines.map((l) => l.toUpperCase());
        } else if (o.startTls === "required") throw new SmtpError("the server does not offer STARTTLS, and startTls is \"required\"");
      }
      if (o.user !== undefined) {
        if (!encrypted) throw new SmtpError("refusing to send the SMTP password over a connection that is not encrypted");
        if (!caps.some((l) => l.startsWith("AUTH") && /\bPLAIN\b/.test(l))) throw new SmtpError("the server does not offer AUTH PLAIN");
        await c.command(`AUTH PLAIN ${b64(`\0${o.user}\0${o.password ?? ""}`)}`, [235], "authentication");
      }
      await c.command(`MAIL FROM:<${o.from}>`, [250], "MAIL FROM");
      await c.command(`RCPT TO:<${m.to}>`, [250, 251], "RCPT TO");
      await c.command("DATA", [354], "DATA");
      // Dot-stuffing: a line that starts with a dot gets another one. The base64 body has no such line, but headers could.
      c.write(`${body.replace(/^\./gm, "..")}\r\n.\r\n`);
      await c.expect([250], "message");
      await c.command("QUIT", [221], "QUIT").catch(() => undefined);
    } finally {
      c.end();
    }
  }
}

export function createMailer(config: AuthvexConfig, root: string, env: NodeJS.ProcessEnv, log: (line: string) => void): Mailer | null {
  const m = config.mail;
  if (!m) return null;
  if (m.driver === "console") return new ConsoleMailer(log);
  if (m.driver === "file") return new FileMailer(join(root, m.outbox ?? join(STATE_DIR, "outbox.jsonl")));
  const s = m.smtp;
  if (!s) throw new Error("mail.driver is \"smtp\" but mail.smtp is missing");
  const password = s.passwordEnv ? env[s.passwordEnv] : undefined;
  if (s.user !== undefined && s.passwordEnv && password === undefined) throw new Error(`mail.smtp.passwordEnv names ${s.passwordEnv}, which is not set`);
  return new SmtpMailer({ host: s.host, port: s.port, from: m.from, secure: s.secure, startTls: s.startTls, rejectUnauthorized: s.rejectUnauthorized, timeoutMs: s.timeoutMs, ...(s.user !== undefined ? { user: s.user } : {}), ...(password !== undefined ? { password } : {}) });
}
