import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
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
  verifyTauriCommands(
    option("--tauri-fixture") ?? join(root, "apps", "desktop", "src-tauri", "src"),
  );
  verifyAdapterConstruction();
  verifyRepositoryAdapter(
    option("--repository-fixture") ?? join(root, "crates", "repository-git", "src"),
  );
  verifyM2Sources(option("--m2-source-fixture") ?? root);
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
  const repositoryGit = "local-agent-terminal-repository-git";
  const m2Adapters = new Map([
    ["local-agent-terminal-policy-engine", new Set([application, domain])],
    ["local-agent-terminal-tool-runtime", new Set([application, domain])],
    ["local-agent-terminal-platform-core", new Set([application, domain])],
    ["local-agent-terminal-platform-windows", new Set([application, domain])],
  ]);
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
  const applicationAllowed = new Set([
    domain,
    "serde",
    "serde_json",
    "serde_json_canonicalizer",
    "sha2",
    "thiserror",
  ]);
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
    [repositoryGit, new Set([application, domain])],
    ["local-agent-terminal-bootstrap", new Set([application, "local-agent-terminal-storage-sqlite", "local-agent-terminal-storage-files", repositoryGit, ...m2Adapters.keys()])],
    ["local-agent-terminal-desktop", new Set(["local-agent-terminal-bootstrap"])],
    ...m2Adapters,
  ]);
  for (const [name, targets] of allowed) {
    for (const dependency of dependencies(name)) {
      if (workspace.has(dependency.name) && !targets.has(dependency.name)) {
        throw new Error(`${name} has an outward internal dependency on ${dependency.name}`);
      }
    }
  }
  for (const [name] of m2Adapters) {
    if (
      dependencies(name).some((dependency) => /^(?:tauri|react)(?:-|$)/.test(dependency.name))
    ) {
      throw new Error(`${name} may not depend on Tauri or React`);
    }
  }
  if (
    [...workspace].some((name) =>
      /local-agent-terminal-(?:agent-protocol|agent-runtime|.*provider.*)/.test(name),
    )
  ) {
    throw new Error("M3 protocol or provider packages are out of scope for M2");
  }
  const repositoryPackage = packages.get(repositoryGit);
  if (repositoryPackage) {
    const repositoryExternalAllowed = new Set([
      "getrandom",
      "git2",
      "libgit2-sys",
      "sha2",
      "windows-sys",
    ]);
    for (const dependency of dependencies(repositoryGit)) {
      if (
        !workspace.has(dependency.name)
        && !repositoryExternalAllowed.has(dependency.name)
      ) {
        throw new Error(`${repositoryGit} has an unjustified external dependency`);
      }
    }
    const git2 = dependencies(repositoryGit).find((dependency) => dependency.name === "git2");
    const libgit2 = dependencies(repositoryGit).find(
      (dependency) => dependency.name === "libgit2-sys",
    );
    if (
      !git2
      || git2.uses_default_features
      || !git2.features.includes("vendored-libgit2")
      || !git2.features.includes("unstable-sha256")
      || git2.features.some((feature) => ["https", "ssh", "cred"].includes(feature))
    ) {
      throw new Error(`${repositoryGit} must use offline vendored git2 with SHA-256 support`);
    }
    if (
      !libgit2
      || libgit2.req !== "=0.18.4"
      || !libgit2.features.includes("vendored")
      || !libgit2.features.includes("unstable-sha256")
    ) {
      throw new Error(`${repositoryGit} must pin the reviewed libgit2-sys layout`);
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
    if (
      /@tauri-apps\/plugin-(?:fs|shell)|node:child_process|\bCommand\.create\s*\(/.test(source)
    ) {
      throw new Error(`React source may not invoke generic filesystem or process APIs: ${local}`);
    }
  }
}

function verifyTauriCommands(sourceRoot) {
  if (!existsSync(sourceRoot)) return;
  const forbidden = new Set(["shell", "git", "filesystem", "exec", "run_command"]);
  const command =
    /#\s*\[\s*tauri::command(?:\([^)]*\))?\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)/g;
  for (const path of filesUnder(sourceRoot).filter((path) => path.endsWith(".rs"))) {
    const source = readFileSync(path, "utf8");
    for (const match of source.matchAll(command)) {
      if (forbidden.has(match[1]) || /(?:^|_)(?:commit|finali[sz]e|finalization)(?:_|$)/.test(match[1])) {
        throw new Error(`generic Tauri command is forbidden: ${match[1]}`);
      }
    }
  }
}

function verifyM2Sources(sourceRoot) {
  const crates = join(sourceRoot, "crates");
  if (existsSync(crates)) {
    for (const entry of readdirSync(crates, { withFileTypes: true })) {
      if (
        entry.isDirectory()
        && /^(?:agent-protocol|agent-runtime|.*provider.*)$/.test(entry.name)
      ) {
        throw new Error("M3 protocol or provider packages are out of scope for M2");
      }
    }
  }

  const toolRuntime = join(crates, "tool-runtime", "src");
  const toolRuntimeFiles = filesUnderIfExists(toolRuntime).filter((path) => path.endsWith(".rs"));
  if (toolRuntimeFiles.length > 0) {
    const source = toolRuntimeFiles.map((path) => readFileSync(path, "utf8")).join("\n");
    if (
      /\bstd::process\b|\bCommand\b|\b(?:powershell|pwsh|cmd\.exe|shell\.raw)\b|\b(?:std::)?env::(?:var|var_os|vars|vars_os)\b|\bPATH\b|\bwindows(?:_sys)?::Win32::(?:System::Threading|Security|Storage::FileSystem)\b|\blocal_agent_terminal_repository_git\b/.test(
        source,
      )
    ) {
      throw new Error("tool-runtime may not construct or discover processes");
    }
    for (const port of ["ProcessLauncher", "CapabilityFilesystem", "StructuredGit"]) {
      if (!source.includes(port)) {
        throw new Error(`tool-runtime must receive the ${port} application port`);
      }
    }
  }

  const productionRoots = [
    ...(existsSync(crates)
      ? readdirSync(crates, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => join(crates, entry.name, "src"))
      : []),
    join(sourceRoot, "apps", "desktop", "src-tauri", "src"),
  ];
  for (const directory of productionRoots) {
    if (directory === join(crates, "platform-windows", "src") || directory === join(crates, "repository-git", "src")) continue;
    for (const path of filesUnderIfExists(directory).filter((path) => path.endsWith(".rs"))) {
      const source = withoutInlineTestModules(readFileSync(path, "utf8"));
      if (
        /\bstd::process::(?:Command|Stdio|Child)\b|\b(?:Command|Stdio)::(?:new|piped|inherit|null)\b|\b(?:powershell|pwsh|cmd\.exe)\b/i.test(
          source,
        )
      ) {
        throw new Error("process construction is allowed only in platform-windows");
      }
      if (
        /\b(?:windows_sys|windows)::Win32::(?:System::Threading|Security|Storage::FileSystem)\b|\b(?:CreateJobObject|OpenProcessToken|JobObject)\b|\bstd::os::windows::fs::(?:OpenOptionsExt|FileExt)\b/.test(
          source,
        )
      ) {
        throw new Error("Windows process and filesystem APIs are allowed only in platform-windows");
      }
      if (
        directory !== join(crates, "bootstrap", "src")
        && /\b(?:PolicyEngine|ToolRuntime|PlatformCore|PlatformWindows)\s*::\s*(?:new|default|build)\s*\(/.test(source)
      ) {
        throw new Error("concrete M2 adapters must be constructed only in bootstrap");
      }
    }
  }

  const frontend = join(sourceRoot, "apps", "desktop", "src");
  for (const path of filesUnderIfExists(frontend).filter((path) => /\.[tj]sx?$/.test(path))) {
    if (/\b(?:raw|absolute|os|filesystem)Path\s*[:?]\s*string\b/.test(readFileSync(path, "utf8"))) {
      throw new Error("raw path-bearing frontend DTOs are forbidden");
    }
  }
  verifyTauriCommands(join(sourceRoot, "apps", "desktop", "src-tauri", "src"));
}

function verifyAdapterConstruction() {
  const forbiddenRoots = [
    join(root, "crates", "domain", "src"),
    join(root, "crates", "application", "src"),
    join(root, "apps", "desktop", "src-tauri", "src"),
  ];
  for (const directory of forbiddenRoots) for (const path of filesUnder(directory)) {
    const source = readFileSync(path, "utf8");
    if (/\b(?:SqliteStore|ContentAddressedArtifactStore|GitRepositoryGateway)\b/.test(source)) {
      throw new Error(`concrete adapters must be constructed only in bootstrap: ${relative(root, path)}`);
    }
  }
}

function verifyRepositoryAdapter(sourceRoot) {
  for (const path of filesUnder(sourceRoot).filter((path) => path.endsWith(".rs"))) {
    const source = readFileSync(path, "utf8");
    const local = relative(sourceRoot, path).replaceAll(sep, "/");
    const standardLibraryImports = [
      ...source.matchAll(/\buse\s+std\b[\s\S]*?;/g),
      ...source.matchAll(/\bextern\s+crate\s+std\b[\s\S]*?;/g),
    ].map((match) => match[0]);
    if (
      standardLibraryImports.some(
        (statement) => /\bprocess\b/.test(statement) || /\bstd\s+as\b/.test(statement),
      )
      ||
      /\bstd::process\b|\bCommand\s*::|\b(?:powershell|pwsh|cmd\.exe)\b/i.test(source)
    ) {
      throw new Error(`repository adapter may not spawn a process: ${local}`);
    }
    if (
      standardLibraryImports.some(
        (statement) => /\benv\b/.test(statement) || /\bstd\s+as\b/.test(statement),
      )
      ||
      /(?:\b(?:std::)?env::(?:var|var_os)\s*\(\s*["']PATH["']|\b(?:std::)?env::vars(?:_os)?\s*\(\s*\)[\s\S]{0,160}["']PATH["']|(?:env|option_env)!\s*\(\s*["']PATH["']|\bwhich(?:::|!))/i.test(source)
    ) {
      throw new Error(`repository adapter may not inspect PATH: ${local}`);
    }
    if (local !== "unsafe_checkout.rs" && /\bunsafe\s*\{/.test(source)) {
      throw new Error(`repository adapter unsafe code is isolated to unsafe_checkout.rs: ${local}`);
    }
  }
}

function filesUnder(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? filesUnder(path) : [path];
  });
}

function filesUnderIfExists(directory) {
  return existsSync(directory) ? filesUnder(directory) : [];
}

function withoutInlineTestModules(source) {
  const mask = rustCodeMask(source);
  const testModule = /#\[cfg\(test\)\]\s*mod\s+\w+\s*\{/g;
  let output = "";
  let start = 0;
  for (const match of mask.matchAll(testModule)) {
    const openingBrace = match.index + match[0].lastIndexOf("{");
    const closingBrace = matchingBrace(mask, openingBrace);
    if (closingBrace === -1) return source;
    output += source.slice(start, match.index);
    start = closingBrace + 1;
  }
  return output + source.slice(start);
}

function matchingBrace(source, openingBrace) {
  let depth = 0;
  for (let index = openingBrace; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}" && --depth === 0) return index;
  }
  return -1;
}

function rustCodeMask(source) {
  const mask = source.split("");
  for (let index = 0; index < source.length; index += 1) {
    if (source.startsWith("//", index)) {
      const end = source.indexOf("\n", index);
      maskRange(mask, index, end === -1 ? source.length : end);
      index = end === -1 ? source.length : end;
      continue;
    }
    if (source.startsWith("/*", index)) {
      let depth = 1;
      let end = index + 2;
      for (; end < source.length && depth > 0; end += 1) {
        if (source.startsWith("/*", end)) {
          depth += 1;
          end += 1;
        } else if (source.startsWith("*/", end)) {
          depth -= 1;
          end += 1;
        }
      }
      if (depth === 0) {
        maskRange(mask, index, end);
        index = end - 1;
      }
      continue;
    }
    const raw = source.slice(index).match(/^(?:b)?r(#+)?"/);
    if (raw && !/[A-Za-z0-9_]/.test(source[index - 1] ?? "")) {
      const terminator = `"${raw[1] ?? ""}`;
      const end = source.indexOf(terminator, index + raw[0].length);
      if (end !== -1) {
        maskRange(mask, index, end + terminator.length);
        index = end + terminator.length - 1;
      }
      continue;
    }
    if (source[index] === '"' || isRustCharLiteral(source, index)) {
      const quote = source[index];
      let end = index + 1;
      for (; end < source.length && source[end] !== quote; end += 1) {
        if (source[end] === "\\") end += 1;
      }
      if (end < source.length) {
        maskRange(mask, index, end + 1);
        index = end;
      }
    }
  }
  return mask.join("");
}

function isRustCharLiteral(source, index) {
  return source[index] === "'" && (
    source[index - 1] === "b"
    || source[index + 1] === "\\"
    || source[index + 2] === "'"
    || !/[A-Za-z_]/.test(source[index + 1] ?? "")
  );
}

function maskRange(mask, start, end) {
  for (let index = start; index < end; index += 1) {
    if (mask[index] !== "\n" && mask[index] !== "\r") mask[index] = " ";
  }
}
