export interface ParsedArgs {
  positional: string[];
  flags: Map<string, string | true>;
}

/** Tiny `--flag value` / `--flag=value` / `--bool` parser. `booleans` lists flags that never take a value. */
export function parseArgs(argv: string[], booleans: readonly string[] = []): ParsedArgs {
  const flags = new Map<string, string | true>();
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === "--") {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq === -1 ? a.slice(2) : a.slice(2, eq);
      if (eq !== -1) flags.set(name, a.slice(eq + 1));
      else if (booleans.includes(name) || i + 1 >= argv.length || (argv[i + 1] as string).startsWith("--")) flags.set(name, true);
      else flags.set(name, argv[++i] as string);
    } else positional.push(a);
  }
  return { positional, flags };
}

export const flagString = (a: ParsedArgs, name: string): string | undefined => {
  const v = a.flags.get(name);
  return typeof v === "string" ? v : undefined;
};

export const flagBool = (a: ParsedArgs, name: string): boolean => a.flags.has(name) && a.flags.get(name) !== "false";

export function flagInt(a: ParsedArgs, name: string, min: number, max: number): number | undefined {
  const v = flagString(a, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new UsageError(`--${name} must be an integer from ${min} to ${max}`);
  return n;
}

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}
