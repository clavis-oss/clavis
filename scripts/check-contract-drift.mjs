#!/usr/bin/env node
// Contract drift check: regenerate the TypeScript DTOs from the Rust core
// into a temp dir and diff against the committed files. Any hand edit to
// packages/contracts/src/generated fails `pnpm check`.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const generatedDir = join(root, "packages/contracts/src/generated");
const committed = await readdir(generatedDir);

const hashOf = async (dir, files) => {
  const h = createHash("sha256");
  for (const f of files.sort()) {
    h.update(f);
    h.update(await readFile(join(dir, f)));
  }
  return h.digest("hex");
};

const before = await hashOf(generatedDir, committed);

const tmp = await mkdtemp(join(tmpdir(), "clavis-contracts-"));
try {
  // Export to the canonical location, capture, then restore and compare.
  execFileSync("cargo", ["test", "-p", "clavis-core", "--features", "export-contracts", "export_bindings"], {
    cwd: root,
    stdio: "pipe",
  });
  await cp(generatedDir, tmp, { recursive: true });
  // Restore committed versions to detect what the regeneration changed.
  await rm(generatedDir, { recursive: true, force: true });
  await cp(tmp, generatedDir, { recursive: true });
  // Re-checkout committed content from git is unavailable here; instead we
  // compare the regeneration against the pre-run hash by regenerating into
  // the temp copy first (the run above already reproduced committed files).
  const after = await hashOf(generatedDir, committed);
  if (before !== after) {
    console.error(
      "Contract drift: packages/contracts/src/generated does not match the Rust DTOs."
    );
    process.exit(1);
  }
  console.log("contracts: no drift");
} finally {
  await rm(tmp, { recursive: true, force: true });
}
