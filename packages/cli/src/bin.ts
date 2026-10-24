#!/usr/bin/env node
import { main } from "./cli";

main(process.argv.slice(2), { out: (l) => console.log(l), err: (l) => console.error(l), cwd: process.cwd() }).then(
  (code) => process.exit(code),
  (e: unknown) => {
    console.error(e instanceof Error ? e.message : String(e));
    process.exit(1);
  },
);
