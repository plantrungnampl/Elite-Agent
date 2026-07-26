import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const option = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : resolve(root, process.argv[index + 1]);
};

try {
  const metadataPath = option("--metadata");
  const metadata = metadataPath
    ? JSON.parse(readFileSync(metadataPath, "utf8"))
    : JSON.parse(execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], { cwd: root, encoding: "utf8" }));
  verifyCargo(metadata);
  verifyReact(option("--fixture") ?? join(root, "apps", "desktop"));
  verifyAdapterConstruction();
  console.log("architecture contracts: ok");
} catch (error) {
  console.error(`architecture contracts: ${error.message}`);
  process.exitCode = 1;
}

function verifyCargo(metadata) {
  const packages = new Map(metadata.packages.map((pkg) => [pkg.name, pkg]));
  const workspace = new Set(
    (metadata.workspace_members ?? [...packages.keys()]).map((member) => {
      if (packages.has(member)) return member;
      return metadata.packages.find((pkg) => pkg.id === member)?.name ?? member;
    }),
  );
  const allDependencies = (name) => packages.get(name)?.dependencies ?? [];
  const dependencies = (name) =>
    (packages.get(name)?.dependencies ?? []).filter((dependency) => dependency.kind !== "dev");
  const domain = "local-agent-terminal-domain";
  const application = "local-agent-terminal-application";
  const domainAllowed = new Set(["serde", "serde_json"]);
  if (allDependencies(domain).some((dependency) => workspace.has(dependency.name))) {
    throw new Error("domain may not depend on workspace packages");
  }
  if (
    dependencies(domain).some(
      (dependency) => !workspace.has(dependency.name) && !domainAllowed.has(dependency.name),
    )
  ) {
    throw new Error("domain may depend only on justified general-purpose libraries");
  }
  const applicationAllowed = new Set([domain, "serde", "serde_json", "thiserror"]);
  if (
    allDependencies(application).some(
      (dependency) => workspace.has(dependency.name) && dependency.name !== domain,
    )
  ) {
    throw new Error(`${application} has an outward internal dependency`);
  }
  if (
    dependencies(application).some(
      (dependency) => !workspace.has(dependency.name) && !applicationAllowed.has(dependency.name),
    )
  ) {
    throw new Error("application may depend only on domain or general-purpose libraries");
  }
  const allowed = new Map([
    ["local-agent-terminal-storage-sqlite", new Set([application, domain])],
    ["local-agent-terminal-storage-files", new Set([application, domain])],
    ["local-agent-terminal-bootstrap", new Set([application, "local-agent-terminal-storage-sqlite", "local-agent-terminal-storage-files"])],
    ["local-agent-terminal-desktop", new Set(["local-agent-terminal-bootstrap"])],
  ]);
  for (const [name, targets] of allowed) {
    for (const dependency of dependencies(name)) {
      if (workspace.has(dependency.name) && !targets.has(dependency.name)) {
        throw new Error(`${name} has an outward internal dependency on ${dependency.name}`);
      }
    }
  }
  const visiting = new Set();
  const visited = new Set();
  const visit = (name) => {
    if (visiting.has(name)) throw new Error("workspace crate dependency cycle");
    if (visited.has(name)) return;
    visiting.add(name);
    for (const dependency of dependencies(name)) if (workspace.has(dependency.name)) visit(dependency.name);
    visiting.delete(name);
    visited.add(name);
  };
  for (const name of workspace) visit(name);
}

function verifyReact(appRoot) {
  const sourceRoot = join(appRoot, "src");
  for (const path of filesUnder(sourceRoot).filter((path) => /\.[tj]sx?$/.test(path))) {
    const source = readFileSync(path, "utf8");
    const local = relative(sourceRoot, path).replaceAll(sep, "/");
    if (/from\s+["'][^"']*\.rs["']|from\s+["'][^"']*(?:sqlite|\.sql)["']|node:(?:fs|path)/.test(source)) {
      throw new Error(`React source may not import Rust, SQL, or path handles: ${local}`);
    }
    if (!local.startsWith("api/") && /@tauri-apps\/api|\binvoke\s*\(/.test(source)) {
      throw new Error(`Tauri invoke is allowed only in src/api/: ${local}`);
    }
  }
}

function verifyAdapterConstruction() {
  const forbiddenRoots = [
    join(root, "crates", "domain", "src"),
    join(root, "crates", "application", "src"),
    join(root, "apps", "desktop", "src-tauri", "src"),
  ];
  for (const directory of forbiddenRoots) for (const path of filesUnder(directory)) {
    const source = readFileSync(path, "utf8");
    if (/\b(?:SqliteStore|ContentAddressedArtifactStore)\b/.test(source)) {
      throw new Error(`concrete adapters must be constructed only in bootstrap: ${relative(root, path)}`);
    }
  }
}

function filesUnder(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? filesUnder(path) : [path];
  });
}
