import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const preApprovalEffectAuthorityNames = [
  "ExecutorLeaseStore",
  "WorkspaceWriteCoordinator",
  "PrepareTaskWorkspace",
  "ProcessFenceAuthority",
  "RepositoryGateway",
  "ProcessLauncher",
  "ApprovedProcessExecutor",
  "StructuredToolExecutor",
  "ExecuteTool",
  "ExecuteDurableTool",
  "CapabilityFilesystem",
  "CapabilityFileWriteSessionFactory",
  "CapabilityFileWriteSession",
  "StructuredGit",
  "CreateWorktree",
  "DiscardWorktree",
  "AcquireLease",
  "AcquireExecutorLease",
  "RevokeLease",
  "AuthorizedFileWrite",
  "FileWriteRequest",
];
const option = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : resolve(root, process.argv[index + 1]);
};

try {
  const requireM4 = process.argv.includes("--require-m4");
  const metadataPath = option("--metadata");
  const metadata = metadataPath
    ? JSON.parse(readFileSync(metadataPath, "utf8"))
    : JSON.parse(execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], { cwd: root, encoding: "utf8" }));
  verifyCargo(metadata, process.argv.includes("--require-m3") || requireM4, requireM4);
  const appRoot = option("--fixture") ?? join(root, "apps", "desktop");
  verifyReact(appRoot);
  verifyM4Presentation(appRoot, requireM4);
  verifyTauriCommands(
    option("--tauri-fixture") ?? join(root, "apps", "desktop", "src-tauri", "src"),
  );
  const m2SourceFixture = option("--m2-source-fixture");
  const m3SourceFixture = option("--m3-source-fixture");
  const m4SourceFixture = option("--m4-source-fixture");
  const sourceRoot = m4SourceFixture ?? m3SourceFixture ?? m2SourceFixture ?? root;
  verifyAdapterConstruction(sourceRoot);
  verifyRepositoryAdapter(
    option("--repository-fixture") ?? join(root, "crates", "repository-git", "src"),
  );
  verifyM2Sources(sourceRoot, m2SourceFixture !== null);
  verifyM3Sources(sourceRoot);
  verifyM4Sources(sourceRoot, appRoot, requireM4);
  console.log("architecture contracts: ok");
} catch (error) {
  console.error(`architecture contracts: ${error.message}`);
  process.exitCode = 1;
}

function verifyCargo(metadata, requireM3, requireM4) {
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
  const agentProtocol = "local-agent-terminal-agent-protocol";
  const agentRuntime = "local-agent-terminal-agent-runtime";
  const providerOpenAi = "local-agent-terminal-provider-openai";
  const contextEngine = "local-agent-terminal-context-engine";
  const orchestration = "local-agent-terminal-orchestration";
  const providerAnthropic = "local-agent-terminal-provider-anthropic";
  const platformWindows = "local-agent-terminal-platform-windows";
  const externalDependenciesByPackage = new Map([
    ["local-agent-terminal-desktop", new Set(["tauri", "tauri-build"])],
    [
      "local-agent-terminal-bootstrap",
      new Set(["serde_json", "serde_json_canonicalizer", "sha2", "url"]),
    ],
    [agentRuntime, new Set(["chrono", "serde_json", "sha2"])],
    [
      agentProtocol,
      new Set([
        "chrono",
        "regress",
        "serde",
        "serde_json",
        "serde_json_canonicalizer",
        "sha2",
        "typify",
      ]),
    ],
    [
      application,
      new Set(["serde", "serde_json", "serde_json_canonicalizer", "sha2", "time"]),
    ],
    [domain, new Set(["serde", "serde_json", "serde_json_canonicalizer", "sha2"])],
    [contextEngine, new Set(["serde", "serde_json", "serde_json_canonicalizer", "sha2"])],
    [
      "local-agent-terminal-policy-engine",
      new Set(["serde", "serde_json", "serde_json_canonicalizer", "sha2"]),
    ],
    [providerOpenAi, new Set(["httpdate", "reqwest", "serde_json", "sha2", "url"])],
    [providerAnthropic, new Set(["reqwest", "serde_json", "sha2", "url"])],
    [
      repositoryGit,
      new Set(["getrandom", "git2", "libgit2-sys", "sha2", "windows-sys"]),
    ],
    [
      "local-agent-terminal-storage-files",
      new Set(["cap-fs-ext", "cap-std", "serde_json", "sha2"]),
    ],
    [
      "local-agent-terminal-storage-sqlite",
      new Set(["rusqlite", "serde_json", "serde_json_canonicalizer", "sha2"]),
    ],
    ["local-agent-terminal-tool-runtime", new Set(["sha2"])],
    ["local-agent-terminal-platform-core", new Set(["sha2"])],
    [
      platformWindows,
      new Set(["cap-fs-ext", "cap-std", "sha2", "winapi-util", "windows-sys"]),
    ],
  ]);
  const specialExternalDependencyOwners = new Map([
    ["git2", new Set([repositoryGit])],
    ["libgit2-sys", new Set([repositoryGit])],
    [
      "windows-sys",
      new Set([repositoryGit, platformWindows]),
    ],
  ]);
  for (const name of workspace) {
    const approved = externalDependenciesByPackage.get(name) ?? new Set();
    const forbidden = dependencies(name)
      .map((dependency) => dependency.name)
      .filter((dependency) => {
        if (dependency.startsWith("local-agent-terminal-")) return false;
        const specialOwners = specialExternalDependencyOwners.get(dependency);
        return (specialOwners && !specialOwners.has(name)) || !approved.has(dependency);
      });
    if (forbidden.length > 0) {
      throw new Error(
        `external dependencies outside provider crates must use the architecture-safe allowlist: external dependency is not approved for ${name}: ${forbidden.join(", ")}`,
      );
    }
  }
  const windowsSysFeaturesByPackage = new Map([
    [
      repositoryGit,
      new Set([
        "Wdk_Foundation",
        "Wdk_Storage_FileSystem",
        "Win32_Foundation",
        "Win32_Security",
        "Win32_Storage_FileSystem",
        "Win32_System_IO",
      ]),
    ],
    [
      platformWindows,
      new Set([
        "Wdk_Foundation",
        "Wdk_Storage_FileSystem",
        "Win32_Foundation",
        "Win32_Networking_WinSock",
        "Win32_Security",
        "Win32_Security_Authorization",
        "Win32_Security_Credentials",
        "Win32_Security_Cryptography",
        "Win32_Security_Isolation",
        "Win32_Storage_FileSystem",
        "Win32_System_Com",
        "Win32_System_IO",
        "Win32_System_JobObjects",
        "Win32_System_Pipes",
        "Win32_System_Registry",
        "Win32_System_Rpc",
        "Win32_System_SystemServices",
        "Win32_System_Threading",
        "Win32_System_WindowsProgramming",
      ]),
    ],
  ]);
  for (const [name, approvedFeatures] of windowsSysFeaturesByPackage) {
    const packageMetadata = packages.get(name);
    for (const dependency of matchingDependencies(packageMetadata, "windows-sys")) {
      const requestedFeatures = dependencyFeatures(packageMetadata, dependency);
      const forbiddenFeatures = requestedFeatures.filter(
        (feature) => !approvedFeatures.has(feature),
      );
      if (forbiddenFeatures.length > 0) {
        throw new Error(
          `windows-sys features are not approved for ${name}: ${forbiddenFeatures.join(", ")}`,
        );
      }
    }
  }
  const anthropicPackage = packages.get(providerAnthropic);
  const approvedReqwestFeatures = new Set(["blocking", "json", "rustls-tls"]);
  for (const dependency of matchingDependencies(anthropicPackage, "reqwest")) {
    const requestedFeatures = dependencyFeatures(anthropicPackage, dependency);
    if (
      dependency.uses_default_features !== false
      || !hasExactFeatures(requestedFeatures, approvedReqwestFeatures)
    ) {
      throw new Error(
        "provider-anthropic reqwest must disable default features and use exactly blocking, json, rustls-tls",
      );
    }
  }
  const m2Adapters = new Map([
    ["local-agent-terminal-policy-engine", new Set([application, domain])],
    ["local-agent-terminal-tool-runtime", new Set([application, domain])],
    ["local-agent-terminal-platform-core", new Set([application, domain])],
    [platformWindows, new Set([application, domain])],
  ]);
  const m3Adapters = new Map([
    [agentProtocol, new Set()],
    [agentRuntime, new Set([application, domain, agentProtocol])],
    [providerOpenAi, new Set([agentProtocol])],
  ]);
  const m4Dependencies = new Map([
    [contextEngine, new Set([application, domain])],
    [orchestration, new Set([application, domain])],
    [providerAnthropic, new Set([agentProtocol])],
  ]);
  verifyWorkspaceCycles(workspace, dependencies, () => true);
  // M0-M3 have dev-only integration-harness cycles; no M4 crate may join one.
  verifyWorkspaceCycles(
    workspace,
    allDependencies,
    (cycle) => cycle.some((name) => m4Dependencies.has(name)),
  );
  if (requireM3) {
    const missing = [agentProtocol, agentRuntime, providerOpenAi].filter(
      (name) => !workspace.has(name),
    );
    if (missing.length > 0) {
      throw new Error(`M3 workspace members are required: ${missing.join(", ")}`);
    }
  }
  if (requireM4) {
    const missing = [...m4Dependencies.keys()].filter((name) => !workspace.has(name));
    if (missing.length > 0) {
      throw new Error(`M4 workspace members are required: ${missing.join(", ")}`);
    }
    const deferredPackage =
      /^local-agent-terminal-(?:vector|embedding|repository-graph|candidate-tree|executor(?:-|$))/;
    if ([...workspace].some((name) => deferredPackage.test(name))) {
      throw new Error("M5 and M6 execution features are forbidden in M4");
    }
  }
  const domainAllowed = new Set([
    "serde",
    "serde_json",
    "serde_json_canonicalizer",
    "sha2",
  ]);
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
    "time",
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
    [
      "local-agent-terminal-bootstrap",
      new Set([
        application,
        "local-agent-terminal-storage-sqlite",
        "local-agent-terminal-storage-files",
        repositoryGit,
        ...m2Adapters.keys(),
        agentRuntime,
        providerOpenAi,
        ...m4Dependencies.keys(),
      ]),
    ],
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
  for (const [name, targets] of m3Adapters) {
    for (const dependency of allDependencies(name)) {
      if (workspace.has(dependency.name) && !targets.has(dependency.name)) {
        throw new Error(`${name} has an outward internal dependency on ${dependency.name}`);
      }
    }
  }
  for (const [name, targets] of m4Dependencies) {
    for (const dependency of allDependencies(name)) {
      if (workspace.has(dependency.name) && !targets.has(dependency.name)) {
        throw new Error(`${name} has an outward internal dependency on ${dependency.name}`);
      }
    }
  }
  const repositoryPackage = packages.get(repositoryGit);
  if (repositoryPackage) {
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
}

function matchingDependencies(packageMetadata, dependencyName) {
  return packageMetadata?.dependencies
    ?.filter((dependency) => dependency.name === dependencyName) ?? [];
}

function dependencyFeatures(packageMetadata, dependency) {
  const alias = dependency.rename ?? dependency.name;
  const forwarded = Object.values(packageMetadata?.features ?? {})
    .flat()
    .flatMap((entry) => {
      if (entry === `dep:${alias}`) return [];
      const match = entry.match(new RegExp(`^${escapeRegExp(alias)}\\??/(.+)$`));
      return match ? [match[1]] : [];
    });
  return [...new Set([...(dependency.features ?? []), ...forwarded])];
}

function hasExactFeatures(requestedFeatures, approvedFeatures) {
  return requestedFeatures.length === approvedFeatures.size
    && requestedFeatures.every((feature) => approvedFeatures.has(feature));
}

function verifyWorkspaceCycles(workspace, dependencyList, rejectsCycle) {
  const path = [];
  const positions = new Map();
  const visited = new Set();
  const visit = (name) => {
    if (positions.has(name)) {
      const cycle = path.slice(positions.get(name));
      if (rejectsCycle(cycle)) throw new Error("workspace crate dependency cycle");
      return;
    }
    if (visited.has(name)) return;
    positions.set(name, path.length);
    path.push(name);
    for (const dependency of dependencyList(name)) {
      if (workspace.has(dependency.name)) visit(dependency.name);
    }
    path.pop();
    positions.delete(name);
    visited.add(name);
  };
  for (const name of workspace) visit(name);
}

function verifyM4Presentation(appRoot, requireM4) {
  if (!requireM4) return;
  const api = join(appRoot, "src", "api", "deliberation.ts");
  const commands = [
    "get_deliberation_workspace",
    "get_context_package",
    "resolve_plan_approval",
  ];
  if (!existsSync(api)) {
    throw new Error("M4 desktop API module must route the deliberation commands");
  }
  const tokens = tokenizeTypeScript(readFileSync(api, "utf8"));
  const invokeBindings = tauriInvokeBindings(tokens).filter(
    (binding) => !hasShadowDeclaration(tokens, binding.name),
  );
  const routesCommand = (command) => invokeBindings.some(
    (binding) => hasInvokeCall(tokens, binding, command),
  );
  if (commands.some((command) => !routesCommand(command))) {
    throw new Error("M4 desktop API module must route the deliberation commands");
  }
}

function tokenizeTypeScript(source) {
  const tokens = [];
  for (let index = 0; index < source.length;) {
    const character = source[index];
    const next = source[index + 1];
    if (/\s/.test(character)) {
      index += 1;
    } else if (character === "/" && next === "/") {
      index = source.indexOf("\n", index + 2);
      if (index === -1) break;
    } else if (character === "/" && next === "*") {
      const closing = source.indexOf("*/", index + 2);
      index = closing === -1 ? source.length : closing + 2;
    } else if (character === '"' || character === "'" || character === "`") {
      const quote = character;
      let value = "";
      index += 1;
      while (index < source.length && source[index] !== quote) {
        if (source[index] === "\\" && index + 1 < source.length) {
          value += source[index + 1];
          index += 2;
        } else {
          value += source[index];
          index += 1;
        }
      }
      if (index < source.length) index += 1;
      tokens.push({ type: "string", value });
    } else if (/[A-Za-z_$]/.test(character)) {
      let end = index + 1;
      while (end < source.length && /[A-Za-z0-9_$]/.test(source[end])) end += 1;
      tokens.push({ type: "identifier", value: source.slice(index, end) });
      index = end;
    } else {
      const punctuation = source.startsWith("=>", index) ? "=>" : character;
      tokens.push({ type: "punctuation", value: punctuation });
      index += punctuation.length;
    }
  }
  return tokens;
}

function tauriInvokeBindings(tokens) {
  const bindings = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (!isToken(tokens[index], "identifier", "import")) continue;
    const statementEnd = tokens.findIndex(
      (token, tokenIndex) => tokenIndex > index && isToken(token, "punctuation", ";"),
    );
    const end = statementEnd === -1 ? tokens.length : statementEnd;
    const moduleIndex = tokens.findIndex(
      (token, tokenIndex) => tokenIndex > index
        && tokenIndex < end
        && isToken(token, "identifier", "from")
        && isToken(tokens[tokenIndex + 1], "string", "@tauri-apps/api/core"),
    );
    if (moduleIndex === -1 || isToken(tokens[index + 1], "identifier", "type")) continue;

    if (isToken(tokens[index + 1], "punctuation", "{")) {
      for (let cursor = index + 2; cursor < moduleIndex; cursor += 1) {
        if (
          isToken(tokens[cursor], "identifier", "invoke")
          && (
            isToken(tokens[cursor - 1], "punctuation", "{")
            || isToken(tokens[cursor - 1], "punctuation", ",")
          )
        ) {
          const alias = isToken(tokens[cursor + 1], "identifier", "as")
            ? tokens[cursor + 2]?.value
            : "invoke";
          if (alias) bindings.push({ kind: "named", name: alias });
        }
      }
    } else if (
      isToken(tokens[index + 1], "punctuation", "*")
      && isToken(tokens[index + 2], "identifier", "as")
      && tokens[index + 3]?.type === "identifier"
    ) {
      bindings.push({ kind: "namespace", name: tokens[index + 3].value });
    }
  }
  return bindings;
}

function hasShadowDeclaration(tokens, name) {
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      ["const", "let", "var"].some((keyword) => isToken(tokens[index], "identifier", keyword))
    ) {
      for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
        if (isToken(tokens[cursor], "punctuation", "=") || isToken(tokens[cursor], "punctuation", ";")) break;
        if (isToken(tokens[cursor], "identifier", name)) return true;
      }
    }
    if (["function", "catch"].some((keyword) => isToken(tokens[index], "identifier", keyword))) {
      const opening = tokens.findIndex(
        (token, tokenIndex) => tokenIndex > index && isToken(token, "punctuation", "("),
      );
      if (opening !== -1 && tokenGroupContains(tokens, opening, "(", ")", name)) return true;
    }
    if (
      tokens[index]?.type === "identifier"
      && !["if", "for", "while", "switch", "with"].includes(tokens[index].value)
      && isToken(tokens[index + 1], "punctuation", "(")
      && tokenGroupContains(tokens, index + 1, "(", ")", name, "{")
    ) return true;
    if (
      isToken(tokens[index], "identifier", name)
      && isToken(tokens[index + 1], "punctuation", "=>")
    ) return true;
    if (
      isToken(tokens[index], "punctuation", "(")
      && tokenGroupContains(tokens, index, "(", ")", name, "=>")
    ) return true;
  }
  return false;
}

function tokenGroupContains(tokens, opening, open, close, name, requiredAfter) {
  let depth = 0;
  for (let index = opening; index < tokens.length; index += 1) {
    if (isToken(tokens[index], "punctuation", open)) depth += 1;
    if (isToken(tokens[index], "punctuation", close)) {
      depth -= 1;
      if (depth === 0) {
        return (!requiredAfter || isToken(tokens[index + 1], "punctuation", requiredAfter))
          && tokens.slice(opening + 1, index).some((token) => isToken(token, "identifier", name));
      }
    }
  }
  return false;
}

function hasInvokeCall(tokens, binding, command) {
  for (let index = 0; index < tokens.length; index += 1) {
    let opening = index + 1;
    if (binding.kind === "named") {
      if (
        !isToken(tokens[index], "identifier", binding.name)
        || isToken(tokens[index - 1], "punctuation", ".")
      ) continue;
    } else {
      if (
        !isToken(tokens[index], "identifier", binding.name)
        || !isToken(tokens[index + 1], "punctuation", ".")
        || !isToken(tokens[index + 2], "identifier", "invoke")
      ) continue;
      opening = index + 3;
    }
    if (isToken(tokens[opening], "punctuation", "<")) {
      opening = tokenGroupEnd(tokens, opening, "<", ">") + 1;
    }
    if (
      isToken(tokens[opening], "punctuation", "(")
      && isToken(tokens[opening + 1], "string", command)
    ) return true;
  }
  return false;
}

function tokenGroupEnd(tokens, opening, open, close) {
  let depth = 0;
  for (let index = opening; index < tokens.length; index += 1) {
    if (isToken(tokens[index], "punctuation", open)) depth += 1;
    if (isToken(tokens[index], "punctuation", close)) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function isToken(token, type, value) {
  return token?.type === type && token.value === value;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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

function verifyM2Sources(sourceRoot, strictM2Scope) {
  const crates = join(sourceRoot, "crates");
  if (strictM2Scope && existsSync(crates)) {
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

function verifyM3Sources(sourceRoot) {
  const crates = join(sourceRoot, "crates");
  const providerRoots = [
    join(crates, "provider-openai", "src"),
    join(crates, "provider-anthropic", "src"),
  ];
  const productionRoots = [
    ...(existsSync(crates)
      ? readdirSync(crates, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => join(crates, entry.name, "src"))
      : []),
    join(sourceRoot, "apps", "desktop", "src-tauri", "src"),
  ];
  for (const directory of productionRoots) {
    for (const path of filesUnderIfExists(directory).filter((path) => path.endsWith(".rs"))) {
      const source = withoutInlineTestModules(readFileSync(path, "utf8"));
      const local = relative(sourceRoot, path).replaceAll(sep, "/");
      if (hasForbiddenEnvironmentAccess(source, local)) {
        throw new Error("provider credentials may not be read from environment");
      }
      if (/\b(?:debug|info|warn|error|trace|println|eprintln)!\s*\([^;]*\bAuthorization\b/i.test(source)) {
        throw new Error("Authorization values may not be logged");
      }
      const ownsProviderHttp = providerRoots.includes(directory);
      if (
        !ownsProviderHttp
        && /\b(?:windows_sys|windows)::Win32::Networking::WinHttp\b/.test(source)
      ) {
        throw new Error("WinHTTP APIs are allowed only in provider crates");
      }
      if (
        !ownsProviderHttp
        && /\b(?:reqwest|hyper|ureq|Tcp(?:Listener|Stream)|std::net|tokio::net|rustls|native_tls)\b/.test(source)
      ) {
        throw new Error(
          "provider HTTP and raw TCP/TLS are allowed only in provider-openai or provider-anthropic",
        );
      }
      if (hasLeakedProviderAdapterType(source, directory, crates)) {
        throw new Error("concrete M3 adapters must be constructed only in bootstrap");
      }
    }
  }

  for (const name of [
    "domain",
    "application",
    "agent-protocol",
    "policy-engine",
    "context-engine",
    "orchestration",
  ]) {
    for (const path of filesUnderIfExists(join(crates, name, "src")).filter((path) => path.endsWith(".rs"))) {
      if (hasProviderName(withoutInlineTestModules(readFileSync(path, "utf8")))) {
        if (name === "agent-protocol") {
          throw new Error("agent-protocol must remain provider-neutral");
        }
        if (name === "context-engine" || name === "orchestration") {
          throw new Error(
            "provider names are forbidden in domain, application, context, and orchestration policy",
          );
        }
        throw new Error(
          "provider names are forbidden in domain, application, and orchestration policy",
        );
      }
    }
  }
}

function verifyM4Sources(sourceRoot, appRoot, requireM4) {
  const crates = join(sourceRoot, "crates");
  const preApprovalRoots = ["context-engine", "orchestration"].map(
    (name) => join(crates, name, "src"),
  );
  const writeCapablePort = new RegExp(
    `\\b(?:${preApprovalEffectAuthorityNames.join("|")})\\b`,
  );
  const writeCapableCall =
    /\.(?:create_worktree|discard_worktree|acquire_lease|prepare_worktree|file_write)\s*\(/;
  for (const directory of preApprovalRoots) {
    for (const path of filesUnderIfExists(directory).filter((path) => path.endsWith(".rs"))) {
      const source = withoutInlineTestModules(readFileSync(path, "utf8"));
      if (writeCapablePort.test(source) || writeCapableCall.test(source)) {
        throw new Error("M4 pre-approval code may not access write-capable ports");
      }
    }
  }

  if (!requireM4) return;
  const productionRoots = existsSync(crates)
    ? readdirSync(crates, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => join(crates, entry.name, "src"))
    : [];
  productionRoots.push(join(appRoot, "src-tauri", "src"), join(appRoot, "src"));
  for (const directory of productionRoots) {
    for (const path of filesUnderIfExists(directory).filter((path) => /\.(?:rs|[cm]?[jt]sx?)$/.test(path))) {
      const source = path.endsWith(".rs")
        ? withoutInlineTestModules(readFileSync(path, "utf8"))
        : readFileSync(path, "utf8");
      if (hasProviderConditionalBranch(source, path.endsWith(".rs") ? "rust" : "typescript")) {
        throw new Error(
          `provider-name conditional branches are forbidden in M4 production code: ${relative(sourceRoot, path)}`,
        );
      }
    }
  }
  const deferredExecutionType =
    /\b(?:VectorStore|RepositoryGraph|EmbeddingProvider|CandidateTree)\b|\b(?:struct|enum|trait|type|class|interface)\s+LocalCommit\b/;
  const deferredExecutionFunction =
    /\b(?:vector_store|repository_graph|embedding_model|candidate_tree|create_candidate_tree|create_commit|finalize_commit)\b/i;
  for (const directory of productionRoots) {
    for (const path of filesUnderIfExists(directory).filter((path) => /\.(?:rs|[cm]?[jt]sx?)$/.test(path))) {
      const source = path.endsWith(".rs")
        ? withoutInlineTestModules(readFileSync(path, "utf8"))
        : readFileSync(path, "utf8");
      if (deferredExecutionType.test(source) || deferredExecutionFunction.test(source)) {
        throw new Error("M5 and M6 execution features are forbidden in M4");
      }
    }
  }

  const anthropicRoot = join(crates, "provider-anthropic", "src");
  const externalProcessTier =
    /\b(?:BrokeredProcess|IsolatedWorker)\b|["'](?:brokered_process|isolated_worker)["']/;
  for (const path of filesUnderIfExists(anthropicRoot).filter((path) => path.endsWith(".rs"))) {
    const source = withoutInlineTestModules(readFileSync(path, "utf8"));
    if (externalProcessTier.test(source)) {
      throw new Error("provider-anthropic must remain a built-in core_adapter");
    }
  }
}

function hasProviderConditionalBranch(source, language) {
  const code = language === "rust"
    ? (rustLexicalMask(source, false) ?? source)
    : withoutTypeScriptComments(source);
  const comparisonOperator = /(?:={2,3}|!={1,2}|<=|>=|&&|\|\|)/;
  const predicateMethod =
    /\.(?:eq|ne|eq_ignore_ascii_case|contains|starts_with|ends_with|includes|startsWith|endsWith)\s*\(/;
  const predicateName =
    /\b(?:is|matches?|supports?|uses?)[A-Za-z0-9_-]*(?:openai|anthropic|gemini|claude)[A-Za-z0-9_-]*\s*\(/i;
  const providerLogic = code.split(/[;{}]/).some((expression) => {
    if (!hasProviderName(expression)) return false;
    return (
      comparisonOperator.test(expression)
      || predicateMethod.test(expression)
      || /\bmatches?!\s*\(/.test(expression)
      || predicateName.test(expression)
    );
  });
  if (providerLogic) return true;

  const parenthesizedCondition = /\b(?:if|else\s+if|while)\s*\(([^)]*)\)/g;
  if ([...code.matchAll(parenthesizedCondition)].some((match) => hasProviderName(match[1]))) {
    return true;
  }

  const rustCondition = /\b(?:if|else\s+if|while)\s+([^{;]+)\s*\{/g;
  if ([...code.matchAll(rustCondition)].some((match) => hasProviderName(match[1]))) {
    return true;
  }

  for (const match of code.matchAll(/\b(?:match|switch)\b/g)) {
    const openingBrace = code.indexOf("{", match.index + match[0].length);
    if (openingBrace === -1 || openingBrace - match.index > 500) continue;
    const closingBrace = matchingBrace(code, openingBrace);
    const branch = code.slice(match.index, closingBrace === -1 ? openingBrace + 1_000 : closingBrace + 1);
    if (hasProviderName(branch)) return true;
  }

  if (language !== "typescript") return false;
  return code
    .split(/;/)
    .some((statement) => statement.includes("?") && /[!=]==?/.test(statement) && hasProviderName(statement));
}

function withoutTypeScriptComments(source) {
  let result = "";
  let quote = null;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (quote !== null) {
      result += character;
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
      result += character;
      continue;
    }
    if (character === "/" && next === "/") {
      result += "  ";
      index += 2;
      while (index < source.length && source[index] !== "\n") {
        result += " ";
        index += 1;
      }
      if (index < source.length) result += "\n";
      continue;
    }
    if (character === "/" && next === "*") {
      result += "  ";
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) {
        result += source[index] === "\n" ? "\n" : " ";
        index += 1;
      }
      if (index < source.length) {
        result += "  ";
        index += 1;
      }
      continue;
    }
    result += character;
  }
  return result;
}

function hasForbiddenEnvironmentAccess(source, local) {
  const code = maskReviewedEnvironmentAccesses(source, local);
  return hasRuntimeEnvironmentReference(code) || hasEnvironmentMacroReference(code);
}

function maskReviewedEnvironmentAccesses(source, local) {
  const code = rustCodeMask(source) ?? source;
  const mask = code.split("");
  maskReviewedMatches(mask, code, source, /\bstd::env::temp_dir\s*\(\s*\)/g);
  if (local === "crates/storage-sqlite/src/migrations.rs") {
    maskReviewedMatches(mask, code, source, /\benv!\s*\(\s*"CARGO_PKG_VERSION"\s*\)/g);
  }
  if (local === "crates/repository-git/src/paths.rs") {
    maskReviewedGitEnvironmentGuard(mask, code, source);
  }
  return mask.join("");
}

function maskReviewedMatches(mask, code, source, matcher) {
  for (const match of source.matchAll(matcher)) {
    if (code[match.index] === source[match.index]) {
      maskRange(mask, match.index, match.index + match[0].length);
    }
  }
}

function maskReviewedGitEnvironmentGuard(mask, code, source) {
  const guard = /fn\s+reject_git_environment\s*\(\s*\)\s*->\s*Result\s*<\s*\(\s*\)\s*,\s*PortError\s*>\s*\{\s*for\s*\(\s*name\s*,\s*_\s*\)\s*in\s*std::env::vars_os\s*\(\s*\)\s*\{\s*if\s+name\s*\.to_string_lossy\s*\(\s*\)\s*\.to_ascii_uppercase\s*\(\s*\)\s*\.starts_with\s*\(\s*"GIT_"\s*\)\s*\{\s*return\s+Err\s*\(\s*conflict\s*\(\s*\)\s*\)\s*;\s*\}\s*\}\s*Ok\s*\(\s*\(\s*\)\s*\)\s*\}/.exec(source);
  if (guard === null) return;
  const access = /\bstd::env::vars_os\s*\(\s*\)/.exec(guard[0]);
  if (access === null) return;
  const index = guard.index + access.index;
  if (code[index] === source[index]) maskRange(mask, index, index + access[0].length);
}

function hasRuntimeEnvironmentReference(code) {
  const aliases = [
    "std",
    ...standardLibraryAliases(code),
  ];
  const prefix = `(?:${aliases.join("|")})`;
  return (
    new RegExp(`\\b${prefix}\\s*::\\s*env\\b`).test(code)
    || new RegExp(`\\b${prefix}\\s*::\\s*\\{[^}]*\\benv\\b`).test(code)
  );
}

function standardLibraryAliases(code) {
  return [
    ...code.matchAll(/\b(?:use|extern\s+crate)\s+(?:::)?std\s+as\s+([A-Za-z_]\w*)/g),
    ...code.matchAll(/\buse\s+(?:::)?std\s*::\s*\{[^}]*\bself\s+as\s+([A-Za-z_]\w*)/g),
  ].map((match) => match[1]);
}

function hasEnvironmentMacroReference(code) {
  return (
    /\b(?:env|option_env)\s*!/.test(code)
    || /\b(?:pub(?:\([^)]*\))?\s+)?use\s+(?:(?:::)?(?:[A-Za-z_]\w*::)*)?(?:env|option_env)\b/.test(code)
    || /\b(?:pub(?:\([^)]*\))?\s+)?use\s*(?:(?:::)?(?:[A-Za-z_]\w*::)*)?\{[^}]*\b(?:env|option_env)\b/.test(code)
  );
}

function hasProviderName(source) {
  return source
    .split(/[^A-Za-z0-9_-]+/)
    .some((token) => /(?:openai|anthropic|gemini|claude)/.test(token.replace(/[_-]/g, "").toLowerCase()));
}

function hasLeakedProviderAdapterType(source, directory, crates) {
  const bootstrap = join(crates, "bootstrap", "src");
  if (directory === bootstrap) return false;
  const types = [
    ["ProtocolAgentRuntime", "agent-runtime"],
    ["OpenAiResponsesAdapter", "provider-openai"],
    ["OpenAIResponsesAdapter", "provider-openai"],
    ["AnthropicMessagesAdapter", "provider-anthropic"],
  ];
  return (
    types.some(([name, owner]) =>
      directory !== join(crates, owner, "src") && new RegExp(`\\b${name}\\b`).test(source))
    || (
      directory !== join(crates, "provider-anthropic", "src")
      && /\bAnthropic[A-Za-z0-9_]*Adapter\b/.test(source)
    )
  );
}

function verifyAdapterConstruction(sourceRoot) {
  const m4InnerRoots = new Set([
    join(sourceRoot, "crates", "context-engine", "src"),
    join(sourceRoot, "crates", "orchestration", "src"),
  ]);
  const forbiddenRoots = [
    join(sourceRoot, "crates", "domain", "src"),
    join(sourceRoot, "crates", "application", "src"),
    ...m4InnerRoots,
    join(sourceRoot, "apps", "desktop", "src-tauri", "src"),
  ];
  for (const directory of forbiddenRoots) for (const path of filesUnderIfExists(directory)) {
    const source = readFileSync(path, "utf8");
    if (/\b(?:SqliteStore|ContentAddressedArtifactStore|GitRepositoryGateway)\b/.test(source)) {
      throw new Error(`concrete adapters must be constructed only in bootstrap: ${relative(sourceRoot, path)}`);
    }
    if (
      m4InnerRoots.has(directory)
      && /\bPolicyEngine\b/.test(source)
    ) {
      throw new Error(`concrete adapters must be constructed only in bootstrap: ${relative(sourceRoot, path)}`);
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
  if (mask === null) return source;
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
  return rustLexicalMask(source, true);
}

function rustLexicalMask(source, maskStrings) {
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
      } else {
        return null;
      }
      continue;
    }
    const raw = source.slice(index).match(/^(?:b)?r(#+)?"/);
    if (raw && !/[A-Za-z0-9_]/.test(source[index - 1] ?? "")) {
      const terminator = `"${raw[1] ?? ""}`;
      const end = source.indexOf(terminator, index + raw[0].length);
      if (end !== -1) {
        if (maskStrings) maskRange(mask, index, end + terminator.length);
        index = end + terminator.length - 1;
      } else {
        return null;
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
        if (maskStrings) maskRange(mask, index, end + 1);
        index = end;
      } else {
        return null;
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
