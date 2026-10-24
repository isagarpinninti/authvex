"use client";

import { useEffect, useState, type ReactNode } from "react";
import { applyTheme, readTheme, type Theme } from "../lib/theme";

export function ThemeToggle(): ReactNode {
  const [theme, setTheme] = useState<Theme>("light");
  useEffect(() => setTheme(readTheme()), []);
  const next: Theme = theme === "dark" ? "light" : "dark";
  return (
    <button type="button" className="av-btn" onClick={() => { applyTheme(next); setTheme(next); }} aria-label={`Switch to ${next} theme`}>
      {theme === "dark" ? "Light" : "Dark"}
    </button>
  );
}
