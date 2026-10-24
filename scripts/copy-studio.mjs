// Copies the static Studio export (./out) into the CLI package, which serves it at `/`.
import { cpSync, existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const from = join(root, "out");
const to = join(root, "packages", "cli", "studio");
if (!existsSync(join(from, "index.html"))) {
  console.error("No Studio export found at ./out. Run `STUDIO_EXPORT=1 next build` first.");
  process.exit(1);
}
rmSync(to, { recursive: true, force: true });
cpSync(from, to, { recursive: true });
console.log(`Studio copied to ${to}`);
