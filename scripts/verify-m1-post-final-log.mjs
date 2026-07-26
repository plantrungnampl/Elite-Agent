import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const output = readFileSync(
  join(root, "artifacts", "verification", "m1", "post-final-contracts.log"),
  "utf8",
);
const required = [
  "M1 evidence is complete and internally consistent",
  "M1 verifier rejects modified captured output",
  "M1 verifier rejects a stale source commit",
  "M1 verifier rejects self-asserted fixture classifications",
  "M1 verifier rejects fixture evidence absent from captured output",
  "M1 verifier rejects dirty tracked source even when HEAD matches sourceCommit",
  "M1 evidence generation preflight rejects dirty tracked source",
];

try {
  if (/# SKIP/u.test(output)) throw new Error("approval-critical contract was skipped");
  for (const name of required) {
    if (!output.includes(`✔ ${name}`)) throw new Error(`missing passing contract: ${name}`);
  }
  console.log("M1 post-final contracts: ok");
} catch (error) {
  console.error(`M1 post-final contracts: ${error.message}`);
  process.exitCode = 1;
}
