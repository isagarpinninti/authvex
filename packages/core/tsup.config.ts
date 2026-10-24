import { defineConfig } from "tsup";

export default defineConfig({
  // Web Crypto only, so one entry serves Node 20+, edge runtimes and browsers.
  entry: { index: "src/index.ts" },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "es2022",
  external: ["zod"],
});
