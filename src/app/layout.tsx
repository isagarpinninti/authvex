import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import "@authvex/react/styles.css";
import { THEME_SCRIPT } from "../lib/theme";
import "./globals.css";

export const metadata: Metadata = {
  title: "Authvex Studio",
  description: "Watch sessions bind to hardware keys, replay stolen tokens, run the threat radar, edit roles and break glass, on your own Authvex server.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  colorScheme: "light dark",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0b1220" },
  ],
};

export default function RootLayout({ children }: { children: ReactNode }): ReactNode {
  return (
    <html lang="en" data-theme="light" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
