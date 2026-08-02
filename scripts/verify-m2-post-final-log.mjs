import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const logArgument = process.argv.indexOf("--log");
const outputPath =
  logArgument === -1
    ? join(root, "artifacts", "verification", "m2", "post-final-contracts.log")
    : resolve(root, process.argv[logArgument + 1]);
const required = [
  "M2 evidence is complete and internally consistent",
  "M2 verifier rejects modified captured output",
  "M2 verifier rejects stale and non-ancestor source commits",
  "M2 verifier rejects missing, failed, and skipped commands",
  "M2 verifier rejects omitted containment cases",
  "M2 verifier rejects platform and toolchain drift",
  "M2 verifier rejects tampered review and limitations artifacts",
  "M2 verifier rejects dirty source and immutable design changes",
  "M2 evidence generation preflight rejects dirty source",
  "M2 post-final verifier rejects an absent log",
];

try {
  const output = readFileSync(outputPath, "utf8");
  if (/# SKIP/u.test(output)) throw new Error("approval-critical contract was skipped");
  for (const name of required) {
    if (!output.includes(`âœ” ${name}`) && !output.includes(`✔ ${name}`)) {
      throw new Error(`missing passing contract: ${name}`);
    }
  }
  console.log("M2 post-final contracts: ok");
} catch (error) {
  console.error(`M2 post-final contracts: ${error.message}`);
  process.exitCode = 1;
}
