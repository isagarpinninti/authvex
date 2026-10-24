export interface Connection {
  baseUrl: string;
  token: string;
}

const KEY = "authvex-connection";

const clean = (url: string): string => url.trim().replace(/\/+$/, "");

export function validBaseUrl(raw: string): string | null {
  try {
    const u = new URL(clean(raw));
    return u.protocol === "http:" || u.protocol === "https:" ? clean(raw) : null;
  } catch {
    return null;
  }
}

/**
 * Where the Studio connects. The CLI prints a link like `http://localhost:4320/#token=ath_adm_…`: the token is read from
 * the fragment (which never reaches a server), kept for this tab only, and removed from the address bar.
 */
export function readConnection(): Connection | null {
  const params = new URLSearchParams(location.hash.replace(/^#/, ""));
  const fromHash = params.get("token");
  const server = new URLSearchParams(location.search).get("server");
  let saved: Partial<Connection> = {};
  try {
    saved = JSON.parse(sessionStorage.getItem(KEY) ?? "{}") as Partial<Connection>;
  } catch {
    /* ignore a corrupt value */
  }
  const token = fromHash ?? saved.token ?? "";
  const baseUrl = validBaseUrl(server ?? saved.baseUrl ?? location.origin);
  if (fromHash) history.replaceState(null, "", location.pathname + location.search);
  if (!token || !baseUrl) return null;
  return { baseUrl, token };
}

export function saveConnection(c: Connection): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(c));
  } catch {
    /* private mode: the connection simply is not remembered */
  }
}

export function forgetConnection(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* nothing to forget */
  }
}

export function guessBaseUrl(): string {
  return location.port === "3000" ? "http://127.0.0.1:4320" : location.origin;
}
