/** A short list of the passwords attackers try first. It is a floor, not a breach corpus: check against Have I Been Pwned too if you can. */
const COMMON = new Set([
  "password", "123456", "12345678", "123456789", "1234567890", "qwerty", "qwertyuiop", "abc123", "111111", "123123", "password1", "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein", "football", "baseball",
  "master", "sunshine", "princess", "login", "passw0rd", "starwars", "trustno1", "whatever", "zaq12wsx", "qazwsx", "1q2w3e4r", "1qaz2wsx", "changeme", "secret", "administrator", "hunter2",
]);

export type PasswordPolicyResult = { ok: true } | { ok: false; reason: "too_short" | "too_long" | "too_common" | "contains_email" | "too_repetitive" | "demo_password"; message: string };

/**
 * Length first (NIST SP 800-63B): at least `minLength` characters, no composition rules. Refuses the most common passwords, the
 * user's own email name, one repeated character, and the demo password shipped by `authvex init`.
 */
export function checkPasswordPolicy(password: string, opts: { minLength?: number; email?: string } = {}): PasswordPolicyResult {
  const min = opts.minLength ?? 12;
  const chars = [...password.normalize("NFKC")];
  if (chars.length < min) return { ok: false, reason: "too_short", message: `use at least ${min} characters` };
  if (chars.length > 256) return { ok: false, reason: "too_long", message: "use at most 256 characters" };
  const lower = password.normalize("NFKC").toLowerCase();
  // A common word with digits or punctuation after it, or repeated, is as guessable as the word.
  const alnum = lower.replace(/[^a-z0-9]/g, "");
  const stem = alnum.replace(/[0-9]+$/, "");
  const repeatedCommon = alnum.length > 0 && [...COMMON].some((w) => w.length >= 4 && alnum.length % w.length === 0 && w.repeat(alnum.length / w.length) === alnum);
  if (COMMON.has(lower) || COMMON.has(alnum) || COMMON.has(stem) || repeatedCommon) return { ok: false, reason: "too_common", message: "that password is on the list of the most common ones" };
  if (lower === "demo-passphrase-1") return { ok: false, reason: "demo_password", message: "that is the demo password" };
  if (new Set(chars).size <= 2) return { ok: false, reason: "too_repetitive", message: "that password is too repetitive" };
  const local = opts.email?.split("@")[0]?.toLowerCase();
  if (local && local.length >= 4 && lower.includes(local)) return { ok: false, reason: "contains_email", message: "the password should not contain your email name" };
  return { ok: true };
}
