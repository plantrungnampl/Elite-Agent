import { spawnSync } from "node:child_process";

const m2EvidencePath =
  /^artifacts\/verification\/m2\/(?:manifest\.json|review\.md|known-limitations\.md|toolchain\.txt|post-final-contracts\.log|outputs\/[a-z0-9-]+\.log)$/u;
const m3EvidencePath =
  /^artifacts\/verification\/m3\/(?:manifest\.json|review\.md|known-limitations\.md|\.generations\/[0-9]{13}-[0-9a-f]{24}\/(?:toolchain\.txt|outputs\/[a-z0-9-]+\.log))$/u;
const executionPlanPath = "docs/superpowers/plans/2026-07-23-m3-protocol-adapter.md";

export function isEvidenceOnlyPath(path) {
  const normalized = path.replaceAll("\\", "/");
  return (
    m2EvidencePath.test(normalized) ||
    m3EvidencePath.test(normalized) ||
    normalized === executionPlanPath
  );
}

export function assertEvidenceOnlyChanges(root) {
  const paths = new Set([
    ...gitPaths(root, ["diff", "--name-only", "-z"]),
    ...gitPaths(root, ["diff", "--cached", "--name-only", "-z"]),
    ...gitPaths(root, ["ls-files", "--others", "--exclude-standard", "-z"]),
  ]);
  const sourceChanges = [...paths].filter(
    (path) => path.length > 0 && !isEvidenceOnlyPath(path),
  );
  if (sourceChanges.length > 0) {
    throw new Error(`dirty tracked source: ${sourceChanges.sort().join(", ")}`);
  }
}

function gitPaths(root, arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`unable to inspect worktree: git ${arguments_.join(" ")}`);
  }
  return result.stdout.split("\0");
}
