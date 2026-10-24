export interface EmailFlow {
  type: "reset" | "verify" | "magic" | "enrol";
  token: string;
  tenantId: string;
}

/**
 * Links in Authvex emails look like `…/#flow=reset&token=…&tenant=…`. The secret is in the fragment, which browsers do not send to
 * servers or put in referrers; it is read once and removed from the address bar.
 */
export function readFlow(): EmailFlow | null {
  const p = new URLSearchParams(location.hash.replace(/^#/, ""));
  const type = p.get("flow");
  const token = p.get("token");
  const tenantId = p.get("tenant");
  if ((type !== "reset" && type !== "verify" && type !== "magic" && type !== "enrol") || !token || !tenantId) return null;
  history.replaceState(null, "", location.pathname + location.search);
  return { type, token, tenantId };
}
