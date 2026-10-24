export type Theme = "dark" | "light";

const KEY = "authvex-theme";

/** Runs before first paint so the page never flashes the wrong theme. */
export const THEME_SCRIPT = `try{var t=localStorage.getItem("${KEY}");if(t!=="light"&&t!=="dark"){t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"}document.documentElement.dataset.theme=t}catch(e){}`;

export function readTheme(): Theme {
  return document.documentElement.dataset["theme"] === "light" ? "light" : "dark";
}

export function applyTheme(t: Theme): void {
  document.documentElement.dataset["theme"] = t;
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* storage can be blocked; the theme still applies for this visit */
  }
}
