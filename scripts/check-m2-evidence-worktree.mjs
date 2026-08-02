import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertEvidenceOnlyChanges } from "./m2-evidence-worktree.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

try {
  assertEvidenceOnlyChanges(root);
  console.log("M2 evidence worktree: ok");
} catch (error) {
  console.error(`M2 evidence worktree: ${error.message}`);
  process.exitCode = 1;
}
