import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertEvidenceOnlyChanges } from "./m1-evidence-worktree.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

try {
  assertEvidenceOnlyChanges(root);
  console.log("M1 evidence worktree: ok");
} catch (error) {
  console.error(`M1 evidence worktree: ${error.message}`);
  process.exitCode = 1;
}
