/** A small Prometheus registry: counters, gauges and histograms, rendered in the text exposition format (version 0.0.4). */

type Labels = Record<string, string>;

const esc = (v: string): string => v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
const labelString = (l: Labels): string => {
  const keys = Object.keys(l).sort();
  return keys.length === 0 ? "" : `{${keys.map((k) => `${k}="${esc(l[k] as string)}"`).join(",")}}`;
};
const keyOf = (l: Labels): string => labelString(l);

/** A metric with labels can grow without bound if a label takes arbitrary values; past this many series new ones are folded into one. */
const MAX_SERIES = 500;

export class Counter {
  private readonly values = new Map<string, { labels: Labels; value: number }>();
  constructor(readonly name: string, readonly help: string) {}
  inc(labels: Labels = {}, by = 1): void {
    let k = keyOf(labels);
    let e = this.values.get(k);
    if (!e && this.values.size >= MAX_SERIES) {
      labels = { overflow: "true" };
      k = keyOf(labels);
      e = this.values.get(k);
    }
    if (e) e.value += by;
    else this.values.set(k, { labels, value: by });
  }
  render(): string {
    const lines = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} counter`];
    for (const { labels, value } of this.values.values()) lines.push(`${this.name}${labelString(labels)} ${value}`);
    if (this.values.size === 0) lines.push(`${this.name} 0`);
    return lines.join("\n");
  }
}

export class Histogram {
  private readonly series = new Map<string, { labels: Labels; counts: number[]; sum: number; count: number }>();
  constructor(readonly name: string, readonly help: string, readonly buckets: number[]) {}
  observe(labels: Labels, value: number): void {
    let k = keyOf(labels);
    let s = this.series.get(k);
    if (!s && this.series.size >= MAX_SERIES) {
      labels = { overflow: "true" };
      k = keyOf(labels);
      s = this.series.get(k);
    }
    if (!s) {
      s = { labels, counts: new Array<number>(this.buckets.length).fill(0), sum: 0, count: 0 };
      this.series.set(k, s);
    }
    for (let i = 0; i < this.buckets.length; i++) if (value <= (this.buckets[i] as number)) s.counts[i] = (s.counts[i] as number) + 1;
    s.sum += value;
    s.count++;
  }
  render(): string {
    const lines = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} histogram`];
    for (const s of this.series.values()) {
      this.buckets.forEach((b, i) => lines.push(`${this.name}_bucket${labelString({ ...s.labels, le: String(b) })} ${s.counts[i]}`));
      lines.push(`${this.name}_bucket${labelString({ ...s.labels, le: "+Inf" })} ${s.count}`, `${this.name}_sum${labelString(s.labels)} ${s.sum}`, `${this.name}_count${labelString(s.labels)} ${s.count}`);
    }
    return lines.join("\n");
  }
}

export interface GaugeSample {
  labels?: Labels;
  value: number;
}

/** A gauge whose value is read when the metrics are scraped. */
export class Gauge {
  constructor(readonly name: string, readonly help: string, private readonly read: () => GaugeSample[] | Promise<GaugeSample[]>) {}
  async render(): Promise<string> {
    const lines = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} gauge`];
    for (const s of await this.read()) lines.push(`${this.name}${labelString(s.labels ?? {})} ${Number.isFinite(s.value) ? s.value : 0}`);
    return lines.join("\n");
  }
}

export class Registry {
  private readonly items: Array<Counter | Histogram | Gauge> = [];
  counter(name: string, help: string): Counter {
    const c = new Counter(name, help);
    this.items.push(c);
    return c;
  }
  histogram(name: string, help: string, buckets: number[]): Histogram {
    const h = new Histogram(name, help, buckets);
    this.items.push(h);
    return h;
  }
  gauge(name: string, help: string, read: () => GaugeSample[] | Promise<GaugeSample[]>): Gauge {
    const g = new Gauge(name, help, read);
    this.items.push(g);
    return g;
  }
  async render(): Promise<string> {
    const out: string[] = [];
    for (const i of this.items) out.push(i instanceof Gauge ? await i.render() : i.render());
    return `${out.join("\n")}\n`;
  }
}

/**
 * A bounded name for a request path, so a scanner hitting random URLs cannot create unlimited series. Tenant ids in OIDC paths
 * become `:tenant`; anything that is not a known route is `other`.
 */
export function routeLabel(method: string, path: string, known: ReadonlySet<string>): string {
  if (path.startsWith("/oidc/")) {
    const m = /^\/oidc\/[^/]+(\/.*)?$/.exec(path);
    const sub = m?.[1] ?? "";
    return ["", "/authorize", "/token", "/userinfo", "/end_session", "/.well-known/openid-configuration"].includes(sub) ? `/oidc/:tenant${sub}` : "other";
  }
  if (known.has(path)) return path;
  if (/^\/api\/keys\/[^/]+$/.test(path)) return "/api/keys/:id";
  if (/^\/api\/me\/passkeys\/[^/]+$/.test(path)) return "/api/me/passkeys/:id";
  if (method === "GET" || method === "HEAD") return path.startsWith("/api/") ? "other" : "static";
  return "other";
}
