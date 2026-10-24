import type { NextConfig } from "next";

// `STUDIO_EXPORT=1 next build` writes a static site to ./out, which `scripts/copy-studio.mjs` bundles into the CLI.
const config: NextConfig = {
  ...(process.env["STUDIO_EXPORT"] ? { output: "export" as const, trailingSlash: true } : {}),
  images: { unoptimized: true },
  reactStrictMode: true,
  poweredByHeader: false,
  transpilePackages: ["@authvex/react"],
};

export default config;
