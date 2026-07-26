import { spawnSync } from "node:child_process";

const evidenceOutput =
  /^artifacts\/verification\/m1\/(?:manifest\.json|review\.md|known-limitations\.md|toolchain\.txt|post-final-contracts\.log|outputs\/[a-z0-9-]+\.log)$/u;

export function assertEvidenceOnlyChanges(root) {
  const paths = new Set([
    ...gitPaths(root, ["diff", "--name-only", "-z"]),
    ...gitPaths(root, ["diff", "--cached", "--name-only", "-z"]),
    ...gitPaths(root, ["ls-files", "--others", "--exclude-standard", "-z"]),
  ]);
  const sourceChanges = [...paths].filter(
    (path) => path.length > 0 && !evidenceOutput.test(path.replaceAll("\\", "/")),
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
  if (result.status !== 0) throw new Error(`unable to inspect worktree: git ${arguments_.join(" ")}`);
  return result.stdout.split("\0");
}
