import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

const run = (...args) =>
  execFileSync(process.execPath, args, { cwd: process.cwd(), encoding: "utf8" });
const fixture = (name) => `tests/contracts/fixtures/m4/${name}`;

test("architecture checker accepts the complete M4 inward dependency graph", () => {
  withMetadata(completeM4Metadata(), (metadataPath) => {
    assert.match(
      run("scripts/check-architecture.mjs", "--metadata", metadataPath),
      /architecture contracts: ok/,
    );
  });
});

test("architecture checker requires all M4 crates only for the final gate", () => {
  withM4Environment({}, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.match(
      run(
        "scripts/check-architecture.mjs",
        "--require-m4",
        "--metadata",
        metadataPath,
        "--m4-source-fixture",
        sourceRoot,
        "--fixture",
        appRoot,
      ),
      /architecture contracts: ok/,
    );
  });

  const metadata = completeM4Metadata();
  removePackage(metadata, "local-agent-terminal-provider-anthropic");
  withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.throws(
      () =>
        run(
          "scripts/check-architecture.mjs",
          "--require-m4",
          "--metadata",
          metadataPath,
          "--m4-source-fixture",
          sourceRoot,
          "--fixture",
          appRoot,
        ),
      /M4 workspace members are required: local-agent-terminal-provider-anthropic/,
    );
  });
});

test("architecture checker rejects outward M4 crate dependencies", () => {
  for (const [name, pattern] of [
    ["context-engine-outward-metadata.json", /context-engine has an outward internal dependency/],
    ["orchestration-outward-metadata.json", /orchestration has an outward internal dependency/],
    [
      "provider-anthropic-outward-metadata.json",
      /provider-anthropic has an outward internal dependency/,
    ],
  ]) {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--metadata", fixture(name)),
      pattern,
    );
  }
});

test("architecture checker rejects workspace crate cycles", () => {
  const metadata = {
    packages: [
      {
        name: "local-agent-terminal-cycle-a",
        dependencies: [{ name: "local-agent-terminal-cycle-b" }],
      },
      {
        name: "local-agent-terminal-cycle-b",
        dependencies: [{ name: "local-agent-terminal-cycle-a" }],
      },
    ],
    workspace_members: [
      "local-agent-terminal-cycle-a",
      "local-agent-terminal-cycle-b",
    ],
  };
  withMetadata(metadata, (metadataPath) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--metadata", metadataPath),
      /workspace crate dependency cycle/,
    );
  });
});

test("architecture checker rejects workspace dev-dependency cycles", () => {
  const metadata = {
    packages: [
      {
        name: "local-agent-terminal-context-engine",
        dependencies: [{ name: "local-agent-terminal-application", kind: "dev" }],
      },
      {
        name: "local-agent-terminal-application",
        dependencies: [{ name: "local-agent-terminal-context-engine", kind: "dev" }],
      },
    ],
    workspace_members: [
      "local-agent-terminal-context-engine",
      "local-agent-terminal-application",
    ],
  };
  withMetadata(metadata, (metadataPath) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--metadata", metadataPath),
      /workspace crate dependency cycle/,
    );
  });
});

test("architecture checker rejects provider-specific policy in inner M4 crates", () => {
  withM4Source({
    "crates/orchestration/src/lib.rs": readFileSync(fixture("provider-name-branch.rs"), "utf8"),
  }, (sourceRoot) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m4-source-fixture", sourceRoot),
      /provider names are forbidden in domain, application, context, and orchestration policy/,
    );
  });
});

test("agent protocol remains provider-neutral", () => {
  withM4Source({
    "crates/agent-protocol/src/lib.rs": "struct AnthropicRequestDto;\n",
  }, (sourceRoot) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m4-source-fixture", sourceRoot),
      /agent-protocol must remain provider-neutral/,
    );
  });
});

for (const [surface, path, source] of [
  [
    "bootstrap",
    "crates/bootstrap/src/lib.rs",
    "fn select(provider: &str) { if provider == \"anthropic\" { activate(); } }\n",
  ],
  [
    "desktop",
    "apps/desktop/src/features/provider.ts",
    "export const select = (provider: string) => provider === \"openai\" ? \"a\" : \"b\";\n",
  ],
]) {
  test(`final M4 gate rejects provider-name conditional branches in ${surface}`, () => {
    withM4Environment(
      { sourceFiles: { [path]: source } },
      ({ appRoot, metadataPath, sourceRoot }) => {
        assert.throws(
          () =>
            run(
              "scripts/check-architecture.mjs",
              "--require-m4",
              "--metadata",
              metadataPath,
              "--m4-source-fixture",
              sourceRoot,
              "--fixture",
              appRoot,
            ),
          /provider-name conditional branches are forbidden in M4 production code/,
        );
      },
    );
  });
}

for (const [surface, path, source] of [
  [
    "Rust",
    "crates/bootstrap/src/provider.rs",
    "fn is_anthropic(provider: &str) -> bool { provider == \"anthropic\" }\n",
  ],
  [
    "TypeScript",
    "apps/desktop/src/features/provider.ts",
    "export const isOpenAi = (provider: string) => provider !== \"openai\";\n",
  ],
]) {
  test(`final M4 gate rejects a provider comparison helper in ${surface}`, () => {
    withM4Environment(
      { sourceFiles: { [path]: source } },
      ({ appRoot, metadataPath, sourceRoot }) => {
        assert.throws(
          () =>
            run(
              "scripts/check-architecture.mjs",
              "--require-m4",
              "--metadata",
              metadataPath,
              "--m4-source-fixture",
              sourceRoot,
              "--fixture",
              appRoot,
            ),
          /provider-name conditional branches are forbidden in M4 production code/,
        );
      },
    );
  });
}

test("final M4 gate permits provider identifiers in composition data", () => {
  withM4Environment({
    sourceFiles: {
      "crates/bootstrap/src/lib.rs": [
        "fn compose() {",
        "    let anthropic = AnthropicMessagesAdapter::new();",
        "    registry.insert(\"anthropic\", anthropic);",
        "}",
        "",
      ].join("\n"),
    },
  }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.match(
      run(
        "scripts/check-architecture.mjs",
        "--require-m4",
        "--metadata",
        metadataPath,
        "--m4-source-fixture",
        sourceRoot,
        "--fixture",
        appRoot,
      ),
      /architecture contracts: ok/,
    );
  });
});

test("architecture checker confines provider HTTP and provider construction", () => {
  withM4Source({
    "crates/context-engine/src/lib.rs": "use reqwest::blocking::Client;\n",
  }, (sourceRoot) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m4-source-fixture", sourceRoot),
      /provider HTTP and raw TCP\/TLS are allowed only in provider-openai or provider-anthropic/,
    );
  });

  withM4Source({
    "crates/provider-anthropic/src/lib.rs": "use reqwest::blocking::Client;\n",
  }, (sourceRoot) => {
    assert.match(
      run("scripts/check-architecture.mjs", "--m4-source-fixture", sourceRoot),
      /architecture contracts: ok/,
    );
  });

  withM4Source({
    "crates/storage-files/src/lib.rs": "let adapter = AnthropicMessagesAdapter::new();\n",
  }, (sourceRoot) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m4-source-fixture", sourceRoot),
      /concrete M3 adapters must be constructed only in bootstrap/,
    );
  });
});

for (const [dependency, source] of [
  ["curl", "use curl::easy::Easy;\n"],
  ["isahc", "use isahc::HttpClient;\n"],
]) {
  test(`architecture checker rejects ${dependency} HTTP outside provider crates`, () => {
    const metadata = completeM4Metadata();
    metadata.packages
      .find(({ name }) => name === "local-agent-terminal-context-engine")
      .dependencies.push({ name: dependency });
    withM4Environment(
      {
        metadata,
        sourceFiles: { "crates/context-engine/src/lib.rs": source },
      },
      ({ appRoot, metadataPath, sourceRoot }) => {
        assert.throws(
          () =>
            run(
              "scripts/check-architecture.mjs",
              "--require-m4",
              "--metadata",
              metadataPath,
              "--m4-source-fixture",
              sourceRoot,
              "--fixture",
              appRoot,
            ),
          /external dependencies outside provider crates must use the architecture-safe allowlist/,
        );
      },
    );
  });
}

for (const [dependency, features, source] of [
  [
    "windows-sys",
    ["Win32_Networking_WinHttp"],
    "use windows_sys::Win32::Networking::WinHttp::WinHttpOpen;\n",
  ],
  ["git2", ["https"], "use git2::{Direction, Remote};\n"],
]) {
  test(`architecture checker rejects ${dependency} in context-engine`, () => {
    const metadata = completeM4Metadata();
    metadata.packages
      .find(({ name }) => name === "local-agent-terminal-context-engine")
      .dependencies.push({ name: dependency, features, uses_default_features: false });
    withM4Environment(
      {
        metadata,
        sourceFiles: { "crates/context-engine/src/lib.rs": source },
      },
      ({ appRoot, metadataPath, sourceRoot }) => {
        assert.throws(
          () =>
            run(
              "scripts/check-architecture.mjs",
              "--require-m4",
              "--metadata",
              metadataPath,
              "--m4-source-fixture",
              sourceRoot,
              "--fixture",
              appRoot,
            ),
          /external dependency is not approved for local-agent-terminal-context-engine/,
        );
      },
    );
  });
}

test("M4 provider dependencies fail closed outside the reviewed transport set", () => {
  const metadata = completeM4Metadata();
  metadata.packages
    .find(({ name }) => name === "local-agent-terminal-provider-anthropic")
    .dependencies.push({ name: "curl" });
  withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.throws(
      () =>
        run(
          "scripts/check-architecture.mjs",
          "--require-m4",
          "--metadata",
          metadataPath,
          "--m4-source-fixture",
          sourceRoot,
          "--fixture",
          appRoot,
        ),
      /external dependency is not approved for local-agent-terminal-provider-anthropic/,
    );
  });
});

test("platform-windows cannot enable unreviewed windows-sys network features", () => {
  const metadata = completeM4Metadata();
  metadata.packages.push({
    name: "local-agent-terminal-platform-windows",
    dependencies: [
      {
        name: "windows-sys",
        features: ["Win32_Networking_WinHttp"],
      },
    ],
  });
  metadata.workspace_members.push("local-agent-terminal-platform-windows");
  withM4Environment(
    {
      metadata,
      sourceFiles: {
        "crates/platform-windows/src/lib.rs": [
          "use windows_sys::Win32::Networking::WinHttp::WinHttpOpen;",
          "fn open() { unsafe { WinHttpOpen(core::ptr::null(), 0, core::ptr::null(), core::ptr::null(), 0); } }",
          "",
        ].join("\n"),
      },
    },
    ({ appRoot, metadataPath, sourceRoot }) => {
      assert.throws(
        () =>
          run(
            "scripts/check-architecture.mjs",
            "--require-m4",
            "--metadata",
            metadataPath,
            "--m4-source-fixture",
            sourceRoot,
            "--fixture",
            appRoot,
          ),
        /windows-sys features are not approved for local-agent-terminal-platform-windows/,
      );
    },
  );
});

test("platform-windows cannot import WinHTTP APIs without metadata evidence", () => {
  withM4Environment(
    {
      sourceFiles: {
        "crates/platform-windows/src/lib.rs":
          "use windows_sys::Win32::Networking::WinHttp::WinHttpOpen;\n",
      },
    },
    ({ appRoot, metadataPath, sourceRoot }) => {
      assert.throws(
        () =>
          run(
            "scripts/check-architecture.mjs",
            "--require-m4",
            "--metadata",
            metadataPath,
            "--m4-source-fixture",
            sourceRoot,
            "--fixture",
            appRoot,
          ),
        /WinHTTP APIs are allowed only in provider crates/,
      );
    },
  );
});

test("package features cannot forward unreviewed windows-sys features", () => {
  const metadata = completeM4Metadata();
  metadata.packages.push({
    name: "local-agent-terminal-platform-windows",
    dependencies: [{ name: "windows-sys", features: [] }],
    features: {
      unsafe_network: ["windows-sys/Win32_Networking_WinHttp"],
    },
  });
  metadata.workspace_members.push("local-agent-terminal-platform-windows");
  withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.throws(
      () =>
        run(
          "scripts/check-architecture.mjs",
          "--require-m4",
          "--metadata",
          metadataPath,
          "--m4-source-fixture",
          sourceRoot,
          "--fixture",
          appRoot,
        ),
      /windows-sys features are not approved for local-agent-terminal-platform-windows/,
    );
  });
});

test("renamed windows-sys package features cannot forward WinHTTP", () => {
  const metadata = completeM4Metadata();
  metadata.packages.push({
    name: "local-agent-terminal-platform-windows",
    dependencies: [{ name: "windows-sys", rename: "windows", features: [] }],
    features: {
      unsafe_network: [
        "dep:windows",
        "windows/Win32_Networking_WinHttp",
      ],
    },
  });
  metadata.workspace_members.push("local-agent-terminal-platform-windows");
  withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.throws(
      () =>
        run(
          "scripts/check-architecture.mjs",
          "--require-m4",
          "--metadata",
          metadataPath,
          "--m4-source-fixture",
          sourceRoot,
          "--fixture",
          appRoot,
        ),
      /windows-sys features are not approved for local-agent-terminal-platform-windows/,
    );
  });
});

test("windows-sys accepts a safe subset of approved features", () => {
  const metadata = completeM4Metadata();
  metadata.packages.push({
    name: "local-agent-terminal-platform-windows",
    dependencies: [{ name: "windows-sys", features: ["Win32_Foundation"] }],
  });
  metadata.workspace_members.push("local-agent-terminal-platform-windows");
  withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.equal(
      run(
        "scripts/check-architecture.mjs",
        "--require-m4",
        "--metadata",
        metadataPath,
        "--m4-source-fixture",
        sourceRoot,
        "--fixture",
        appRoot,
      ),
      "architecture contracts: ok\n",
    );
  });
});

for (const [caseName, usesDefaultFeatures, features] of [
  ["default features", true, ["blocking", "json", "rustls-tls"]],
  ["native TLS", false, ["blocking", "json", "rustls-tls", "native-tls"]],
  ["SOCKS", false, ["blocking", "json", "rustls-tls", "socks"]],
]) {
  test(`provider-anthropic rejects reqwest ${caseName}`, () => {
    const metadata = completeM4Metadata();
    metadata.packages
      .find(({ name }) => name === "local-agent-terminal-provider-anthropic")
      .dependencies.push({
        name: "reqwest",
        features,
        uses_default_features: usesDefaultFeatures,
      });
    withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
      assert.throws(
        () =>
          run(
            "scripts/check-architecture.mjs",
            "--require-m4",
            "--metadata",
            metadataPath,
            "--m4-source-fixture",
            sourceRoot,
            "--fixture",
            appRoot,
          ),
        /provider-anthropic reqwest must disable default features and use exactly blocking, json, rustls-tls/,
      );
    });
  });
}

test("provider-anthropic validates every target-specific reqwest entry", () => {
  const metadata = completeM4Metadata();
  metadata.packages
    .find(({ name }) => name === "local-agent-terminal-provider-anthropic")
    .dependencies.push(
      {
        name: "reqwest",
        features: ["blocking", "json", "rustls-tls"],
        uses_default_features: false,
      },
      {
        name: "reqwest",
        features: ["blocking", "json", "native-tls"],
        target: "cfg(windows)",
        uses_default_features: true,
      },
    );
  withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.throws(
      () =>
        run(
          "scripts/check-architecture.mjs",
          "--require-m4",
          "--metadata",
          metadataPath,
          "--m4-source-fixture",
          sourceRoot,
          "--fixture",
          appRoot,
        ),
      /provider-anthropic reqwest must disable default features and use exactly blocking, json, rustls-tls/,
    );
  });
});

test("provider-anthropic accepts the reviewed future reqwest shape", () => {
  const metadata = completeM4Metadata();
  metadata.packages
    .find(({ name }) => name === "local-agent-terminal-provider-anthropic")
    .dependencies.push({
      name: "reqwest",
      features: ["blocking", "json", "rustls-tls"],
      uses_default_features: false,
    });
  withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.equal(
      run(
        "scripts/check-architecture.mjs",
        "--require-m4",
        "--metadata",
        metadataPath,
        "--m4-source-fixture",
        sourceRoot,
        "--fixture",
        appRoot,
      ),
      "architecture contracts: ok\n",
    );
  });
});

test("context and orchestration cannot construct concrete adapters", () => {
  for (const [path, source] of [
    ["crates/context-engine/src/lib.rs", "let store = SqliteStore::open(path);\n"],
    ["crates/orchestration/src/lib.rs", "let repository = GitRepositoryGateway::open(path);\n"],
    ["crates/orchestration/src/policy.rs", "let policy = PolicyEngine::new(rules);\n"],
  ]) {
    withM4Source({ [path]: source }, (sourceRoot) => {
      assert.throws(
        () => run("scripts/check-architecture.mjs", "--m4-source-fixture", sourceRoot),
        /concrete adapters must be constructed only in bootstrap/,
      );
    });
  }
});

test("M4 code cannot reach write-capable ports before plan approval", () => {
  withM4Source({
    "crates/orchestration/src/lib.rs": readFileSync(fixture("preapproval-write.rs"), "utf8"),
  }, (sourceRoot) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m4-source-fixture", sourceRoot),
      /M4 pre-approval code may not access write-capable ports/,
    );
  });
});

for (const [authority, source] of [
  ["ProcessLauncher", "fn deliberate(launcher: &dyn ProcessLauncher) { launcher.execute(); }\n"],
  [
    "ApprovedProcessExecutor::execute",
    "fn deliberate(executor: &ApprovedProcessExecutor) { executor.execute(); }\n",
  ],
  [
    "CapabilityFileWriteSessionFactory::open",
    "fn deliberate(factory: &dyn CapabilityFileWriteSessionFactory) { factory.open(); }\n",
  ],
  [
    "CapabilityFileWriteSession::apply",
    "fn deliberate(session: &mut dyn CapabilityFileWriteSession) { session.apply(); }\n",
  ],
  [
    "AcquireExecutorLease::execute",
    "fn deliberate(acquire: &AcquireExecutorLease) { acquire.execute(); }\n",
  ],
  [
    "ExecuteTool::execute",
    "fn deliberate(execute: &ExecuteTool<'_>, request: ToolRequest) { execute.execute(request); }\n",
  ],
]) {
  test(`M4 pre-approval rejects ${authority}`, () => {
    withM4Source({ "crates/orchestration/src/lib.rs": source }, (sourceRoot) => {
      assert.throws(
        () => run("scripts/check-architecture.mjs", "--m4-source-fixture", sourceRoot),
        /M4 pre-approval code may not access write-capable ports/,
      );
    });
  });
}

test("architecture checker preserves desktop API routing", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--fixture",
        "tests/contracts/fixtures/architecture/frontend-invoke-outside-api",
      ),
    /Tauri invoke is allowed only in src\/api/,
  );

  withM4Environment(
    { desktopFiles: { "src/App.tsx": "export const App = () => null;\n" } },
    ({ appRoot, metadataPath, sourceRoot }) => {
      assert.throws(
        () =>
          run(
            "scripts/check-architecture.mjs",
            "--require-m4",
            "--metadata",
            metadataPath,
            "--m4-source-fixture",
            sourceRoot,
            "--fixture",
            appRoot,
          ),
        /M4 desktop API module must route the deliberation commands/,
      );
    },
  );

  withM4Environment(
    {
      desktopFiles: {
        "src/api/deliberation.ts": [
          "export const commands = [",
          "  \"get_deliberation_workspace\",",
          "  \"get_context_package\",",
          "  \"resolve_plan_approval\",",
          "];",
          "",
        ].join("\n"),
      },
    },
    ({ appRoot, metadataPath, sourceRoot }) => {
      assert.throws(
        () =>
          run(
            "scripts/check-architecture.mjs",
            "--require-m4",
            "--metadata",
            metadataPath,
            "--m4-source-fixture",
            sourceRoot,
            "--fixture",
            appRoot,
          ),
        /M4 desktop API module must route the deliberation commands/,
      );
    },
  );

  withM4Environment(
    {
      desktopFiles: {
        "src/api/deliberation.ts": [
          "// import { invoke } from \"@tauri-apps/api/core\";",
          "// invoke(\"get_deliberation_workspace\");",
          "// invoke(\"get_context_package\");",
          "// invoke(\"resolve_plan_approval\");",
          "",
        ].join("\n"),
      },
    },
    ({ appRoot, metadataPath, sourceRoot }) => {
      assert.throws(
        () =>
          run(
            "scripts/check-architecture.mjs",
            "--require-m4",
            "--metadata",
            metadataPath,
            "--m4-source-fixture",
            sourceRoot,
            "--fixture",
            appRoot,
          ),
        /M4 desktop API module must route the deliberation commands/,
      );
    },
  );
});

for (const [caseName, source] of [
  [
    "invoke text inside strings",
    [
      "import { invoke } from \"@tauri-apps/api/core\";",
      "export const examples = [",
      "  'invoke(\"get_deliberation_workspace\")',",
      "  'invoke(\"get_context_package\")',",
      "  'invoke(\"resolve_plan_approval\")',",
      "];",
      "",
    ].join("\n"),
  ],
  [
    "a shadowed invoke binding",
    [
      "import { invoke } from \"@tauri-apps/api/core\";",
      "export function route(invoke) {",
      "  invoke(\"get_deliberation_workspace\");",
      "  invoke(\"get_context_package\");",
      "  invoke(\"resolve_plan_approval\");",
      "}",
      "",
    ].join("\n"),
  ],
  [
    "a class method parameter that shadows invoke",
    [
      "import { invoke } from \"@tauri-apps/api/core\";",
      "class Router {",
      "  route(invoke) {",
      "    invoke(\"get_deliberation_workspace\");",
      "    invoke(\"get_context_package\");",
      "    invoke(\"resolve_plan_approval\");",
      "  }",
      "}",
      "",
    ].join("\n"),
  ],
  [
    "an object method parameter that shadows invoke",
    [
      "import { invoke } from \"@tauri-apps/api/core\";",
      "export const router = {",
      "  route(invoke) {",
      "    invoke(\"get_deliberation_workspace\");",
      "    invoke(\"get_context_package\");",
      "    invoke(\"resolve_plan_approval\");",
      "  },",
      "};",
      "",
    ].join("\n"),
  ],
  [
    "a different core export renamed to invoke",
    [
      "import { emit as invoke } from \"@tauri-apps/api/core\";",
      "invoke(\"get_deliberation_workspace\");",
      "invoke(\"get_context_package\");",
      "invoke(\"resolve_plan_approval\");",
      "",
    ].join("\n"),
  ],
]) {
  test(`desktop routing rejects ${caseName}`, () => {
    withM4Environment(
      { desktopFiles: { "src/api/deliberation.ts": source } },
      ({ appRoot, metadataPath, sourceRoot }) => {
        assert.throws(
          () =>
            run(
              "scripts/check-architecture.mjs",
              "--require-m4",
              "--metadata",
              metadataPath,
              "--m4-source-fixture",
              sourceRoot,
              "--fixture",
              appRoot,
            ),
          /M4 desktop API module must route the deliberation commands/,
        );
      },
    );
  });
}

test("provider conditional scanner rejects rustfmt multiline predicates", () => {
  withM4Environment(
    {
      sourceFiles: {
        "crates/provider-anthropic/src/provider.rs": [
          "fn select_provider(provider: &str) {",
          "    if provider",
          "        .eq(\"anthropic\")",
          "    {",
          "        activate();",
          "    }",
          "}",
          "",
        ].join("\n"),
      },
    },
    ({ appRoot, metadataPath, sourceRoot }) => {
      assert.throws(
        () =>
          run(
            "scripts/check-architecture.mjs",
            "--require-m4",
            "--metadata",
            metadataPath,
            "--m4-source-fixture",
            sourceRoot,
            "--fixture",
            appRoot,
          ),
        /provider-name conditional branches are forbidden/,
      );
    },
  );
});

for (const [path, environment] of [
  [
    "crates/provider-anthropic/src/provider.rs",
    {
      sourceFiles: {
        "crates/provider-anthropic/src/provider.rs":
          "// if provider == \"anthropic\" { activate(); }\nfn deliberate() {}\n",
      },
    },
  ],
  [
    "crates/provider-anthropic/src/lifetime.rs",
    {
      sourceFiles: {
        "crates/provider-anthropic/src/lifetime.rs": [
          "fn borrow(_: &'static str) {",
          "    let marker = r#\"/* literal, not a comment */\"#;",
          "    /* outer comment",
          "       /* if provider == \"anthropic\" { activate(); } */",
          "    */",
          "}",
          "",
        ].join("\n"),
      },
    },
  ],
  [
    "apps/desktop/src/api/deliberation.ts",
    {
      desktopFiles: {
        "src/api/deliberation.ts": [
          "import { invoke } from \"@tauri-apps/api/core\";",
          "/* if (provider === \"openai\") activate(); */",
          "export const getWorkspace = (taskId) => invoke(\"get_deliberation_workspace\", { taskId });",
          "export const getContext = (packageId) => invoke(\"get_context_package\", { packageId });",
          "export const resolveApproval = (request) => invoke(\"resolve_plan_approval\", request);",
          "",
        ].join("\n"),
      },
    },
  ],
]) {
  test(`provider conditional scanner ignores comments in ${path}`, () => {
    withM4Environment(
      environment,
      ({ appRoot, metadataPath, sourceRoot }) => {
        assert.equal(
          run(
            "scripts/check-architecture.mjs",
            "--require-m4",
            "--metadata",
            metadataPath,
            "--m4-source-fixture",
            sourceRoot,
            "--fixture",
            appRoot,
          ),
          "architecture contracts: ok\n",
        );
      },
    );
  });
}

test("final M4 gate rejects deferred M5 and M6 execution", () => {
  for (const [path, source] of [
    ["crates/context-engine/src/lib.rs", "struct VectorStore;\n"],
    ["crates/context-engine/src/lib.rs", "struct RepositoryGraph;\n"],
    ["crates/context-engine/src/lib.rs", "fn create_candidate_tree() {}\n"],
    ["crates/storage-files/src/lib.rs", "struct EmbeddingProvider;\n"],
  ]) {
    withM4Environment(
      { sourceFiles: { [path]: source } },
      ({ appRoot, metadataPath, sourceRoot }) => {
        assert.throws(
          () =>
            run(
              "scripts/check-architecture.mjs",
              "--require-m4",
              "--metadata",
              metadataPath,
              "--m4-source-fixture",
              sourceRoot,
              "--fixture",
              appRoot,
            ),
          /M5 and M6 execution features are forbidden in M4/,
        );
      },
    );
  }
});

for (const [surface, path, source] of [
  ["application", "crates/application/src/deliberation.rs", "struct CandidateTree;\n"],
  [
    "application LocalCommit declaration",
    "crates/application/src/local_commit.rs",
    "struct LocalCommit;\n",
  ],
  ["bootstrap", "crates/bootstrap/src/deliberation.rs", "struct CandidateTree;\n"],
  ["Tauri", "apps/desktop/src-tauri/src/deliberation.rs", "struct CandidateTree;\n"],
  ["React", "apps/desktop/src/features/deliberation.ts", "interface CandidateTree {}\n"],
]) {
  test(`final M4 gate rejects deferred execution in ${surface}`, () => {
    withM4Environment(
      { sourceFiles: { [path]: source } },
      ({ appRoot, metadataPath, sourceRoot }) => {
        assert.throws(
          () =>
            run(
              "scripts/check-architecture.mjs",
              "--require-m4",
              "--metadata",
              metadataPath,
              "--m4-source-fixture",
              sourceRoot,
              "--fixture",
              appRoot,
            ),
          /M5 and M6 execution features are forbidden in M4/,
        );
      },
    );
  });
}

test("final M4 gate rejects deferred execution crates", () => {
  const metadata = completeM4Metadata();
  metadata.packages.push({
    name: "local-agent-terminal-vector-store-embedded",
    dependencies: [{ name: "local-agent-terminal-application" }],
  });
  metadata.workspace_members.push("local-agent-terminal-vector-store-embedded");
  withM4Environment({ metadata }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.throws(
      () =>
        run(
          "scripts/check-architecture.mjs",
          "--require-m4",
          "--metadata",
          metadataPath,
          "--m4-source-fixture",
          sourceRoot,
          "--fixture",
          appRoot,
        ),
      /M5 and M6 execution features are forbidden in M4/,
    );
  });
});

test("Anthropic remains a contained built-in core adapter", () => {
  withM4Environment({
    sourceFiles: {
      "crates/provider-anthropic/src/lib.rs":
        "let trust_tier = TrustTier::BrokeredProcess;\n",
    },
  }, ({ appRoot, metadataPath, sourceRoot }) => {
    assert.throws(
      () =>
        run(
          "scripts/check-architecture.mjs",
          "--require-m4",
          "--metadata",
          metadataPath,
          "--m4-source-fixture",
          sourceRoot,
          "--fixture",
          appRoot,
        ),
      /provider-anthropic must remain a built-in core_adapter/,
    );
  });
});

test("normative workflow pins every M4 phase and required effect", () => {
  const workflow = JSON.parse(
    readFileSync(
      "docs/multi-agent-terminal-design/schemas/workflow-transitions.v1.json",
      "utf8",
    ),
  );
  assert.deepEqual(workflow.phases.slice(0, 8), [
    "Intake",
    "ContextBuild",
    "ParallelAnalysis",
    "CrossReview",
    "PrePlanVerification",
    "Synthesis",
    "FinalObjection",
    "AwaitingPlanApproval",
  ]);
  assert.deepEqual(
    workflow.phaseTransitions.slice(0, 10).map(({ from, event, to, effects }) => ({
      from,
      event,
      to,
      effects,
    })),
    [
      {
        from: "Intake",
        event: "task.validated",
        to: "ContextBuild",
        effects: ["persist_risk", "persist_base_identity"],
      },
      {
        from: "ContextBuild",
        event: "context.initial.ready",
        to: "ParallelAnalysis",
        effects: ["freeze_independent_inputs"],
      },
      {
        from: "ParallelAnalysis",
        event: "analysis.quorum.reached",
        to: "CrossReview",
        effects: ["publish_selected_proposals", "assign_review_edges"],
      },
      {
        from: "CrossReview",
        event: "review.complete",
        to: "PrePlanVerification",
        effects: ["freeze_material_claims"],
      },
      {
        from: "PrePlanVerification",
        event: "claims.checked",
        to: "Synthesis",
        effects: ["persist_claim_verification_set"],
      },
      {
        from: "Synthesis",
        event: "decision.draft.created",
        to: "FinalObjection",
        effects: ["publish_immutable_decision_draft"],
      },
      {
        from: "FinalObjection",
        event: "objection.severe.accepted",
        to: "CrossReview",
        effects: ["increment_review_round"],
      },
      {
        from: "FinalObjection",
        event: "objection.round.closed",
        to: "AwaitingPlanApproval",
        effects: ["create_plan_approval_request"],
      },
      {
        from: "AwaitingPlanApproval",
        event: "plan.revision.requested",
        to: "Synthesis",
        effects: ["supersede_decision_draft"],
      },
      {
        from: "AwaitingPlanApproval",
        event: "plan.approved",
        to: "Implementation",
        effects: ["persist_approved_plan_version", "allocate_executor_lease"],
      },
    ],
  );

  const beforeApproval = workflow.phaseTransitions
    .slice(0, 9)
    .flatMap(({ effects }) => effects);
  assert.ok(!beforeApproval.includes("allocate_executor_lease"));
  assert.ok(!beforeApproval.includes("create_candidate_tree"));
  assert.ok(!beforeApproval.includes("persist_commit"));
});

for (const [caseName, sourceChunks] of [
  [
    "SQL comments",
    "CREATE TABLE source_chunks (id TEXT -- REFERENCES source_documents(id)\n);",
  ],
  [
    "SQL string literals",
    "CREATE TABLE source_chunks (note TEXT DEFAULT 'REFERENCES source_documents(id)');",
  ],
]) {
  test(`SQLite relation checks ignore REFERENCES inside ${caseName}`, () => {
    const schema = [
      sourceChunks,
      "CREATE TABLE context_packages (task_id TEXT REFERENCES tasks(id), agent_id TEXT REFERENCES agent_descriptors(id));",
      "CREATE TABLE agent_runs (context_package_id TEXT REFERENCES context_packages(id));",
      "CREATE TABLE messages (run_id TEXT REFERENCES agent_runs(id), reply_to TEXT REFERENCES messages(id));",
      "CREATE TABLE approvals (task_id TEXT REFERENCES tasks(id), request_artifact_id TEXT REFERENCES artifacts(id));",
      "CREATE TABLE context_package_policy_decisions (package_id TEXT REFERENCES context_packages(id), policy_decision_id TEXT REFERENCES policy_decisions(id));",
    ].join("\n");

    assert.throws(
      () => assertM4SchemaRelations(schema),
      /source_chunks must reference source_documents/,
    );
  });
}

test("SQLite relation checks do not borrow foreign keys from later tables", () => {
  const schema = [
    "CREATE TABLE source_chunks (id TEXT);",
    "CREATE TABLE unrelated_source_relation (document_id TEXT REFERENCES source_documents(id));",
    "CREATE TABLE context_packages (task_id TEXT REFERENCES tasks(id), agent_id TEXT REFERENCES agent_descriptors(id));",
    "CREATE TABLE agent_runs (context_package_id TEXT REFERENCES context_packages(id));",
    "CREATE TABLE messages (run_id TEXT REFERENCES agent_runs(id), reply_to TEXT REFERENCES messages(id));",
    "CREATE TABLE approvals (task_id TEXT REFERENCES tasks(id), request_artifact_id TEXT REFERENCES artifacts(id));",
    "CREATE TABLE context_package_policy_decisions (package_id TEXT REFERENCES context_packages(id), policy_decision_id TEXT REFERENCES policy_decisions(id));",
  ].join("\n");

  assert.throws(
    () => assertM4SchemaRelations(schema),
    /source_chunks must reference source_documents/,
  );
});

test("normative SQLite schema pins source, context, message, and approval relations", () => {
  const schema = readFileSync(
    "docs/multi-agent-terminal-design/schemas/sqlite-v1.sql",
    "utf8",
  );
  assertM4SchemaRelations(schema);
});

test("normative M4 scope defers vector and graph execution and preserves containment", () => {
  const roadmap = readFileSync(
    "docs/multi-agent-terminal-design/11-mvp-roadmap.md",
    "utf8",
  );
  const milestone4 = roadmap.slice(
    roadmap.indexOf("## 6. Milestone 4"),
    roadmap.indexOf("## 7. Milestone 5"),
  );
  assert.doesNotMatch(milestone4, /vector|embedding|repository graph/i);
  assert.match(milestone4, /`brokered_process` that has passed[\s\S]*containment suite/);

  const containment = readFileSync(
    "docs/multi-agent-terminal-design/13-trust-sandbox-model.md",
    "utf8",
  );
  assert.match(containment, /no repository or user-profile ACL/);
  assert.match(containment, /no inherited secrets/);
  assert.match(containment, /only explicitly permitted network endpoints/);
  assert.match(
    containment,
    /cannot be enabled as `brokered_process` or[\s\S]*until a child test process fails all denied actions/,
  );
});

function assertM4SchemaRelations(schema) {
  const code = maskSqlCommentsAndStrings(schema);
  for (const [table, targets] of [
    ["source_chunks", ["source_documents"]],
    ["context_packages", ["tasks", "agent_descriptors"]],
    ["agent_runs", ["context_packages"]],
    ["messages", ["agent_runs", "messages"]],
    ["approvals", ["tasks", "artifacts"]],
    ["context_package_policy_decisions", ["context_packages", "policy_decisions"]],
  ]) {
    const body = sqliteTableBody(code, table);
    for (const target of targets) {
      assert.match(
        body,
        new RegExp(`\\bREFERENCES\\s+${target}\\s*\\(\\s*id\\s*\\)`, "i"),
        `${table} must reference ${target}`,
      );
    }
  }
}

function maskSqlCommentsAndStrings(schema) {
  const mask = schema.split("");
  for (let index = 0; index < schema.length; index += 1) {
    let end = index;
    if (schema.startsWith("--", index)) {
      end = schema.indexOf("\n", index + 2);
      if (end === -1) end = schema.length;
    } else if (schema.startsWith("/*", index)) {
      const closing = schema.indexOf("*/", index + 2);
      end = closing === -1 ? schema.length : closing + 2;
    } else if (schema[index] === "'" || schema[index] === '"') {
      const quote = schema[index];
      end = index + 1;
      while (end < schema.length) {
        if (schema[end] === quote && schema[end + 1] === quote) {
          end += 2;
        } else if (schema[end] === quote) {
          end += 1;
          break;
        } else {
          end += 1;
        }
      }
    }
    if (end === index) continue;
    for (let cursor = index; cursor < end; cursor += 1) {
      if (mask[cursor] !== "\n" && mask[cursor] !== "\r") mask[cursor] = " ";
    }
    index = end - 1;
  }
  return mask.join("");
}

function sqliteTableBody(schema, table) {
  const createTable = new RegExp(
    `\\bCREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?${table}\\s*\\(`,
    "i",
  );
  const declaration = createTable.exec(schema);
  assert.ok(declaration, `missing CREATE TABLE ${table}`);
  const openingParenthesis = declaration.index + declaration[0].lastIndexOf("(");
  let depth = 0;
  let quote = null;
  for (let index = openingParenthesis; index < schema.length; index += 1) {
    const character = schema[index];
    if (quote !== null) {
      if (character === quote) {
        if (schema[index + 1] === quote) {
          index += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
    } else if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) return schema.slice(openingParenthesis + 1, index);
    }
  }
  assert.fail(`unterminated CREATE TABLE ${table}`);
}

function completeM4Metadata() {
  const metadata = JSON.parse(
    readFileSync("tests/contracts/fixtures/m3/m3-valid-metadata.json", "utf8"),
  );
  const additions = [
    {
      name: "local-agent-terminal-context-engine",
      dependencies: [
        { name: "local-agent-terminal-application" },
        { name: "local-agent-terminal-domain" },
      ],
    },
    {
      name: "local-agent-terminal-orchestration",
      dependencies: [
        { name: "local-agent-terminal-application" },
        { name: "local-agent-terminal-domain" },
      ],
    },
    {
      name: "local-agent-terminal-provider-anthropic",
      dependencies: [{ name: "local-agent-terminal-agent-protocol" }],
    },
  ];
  metadata.packages.push(...additions);
  metadata.workspace_members.push(...additions.map(({ name }) => name));
  const bootstrap = metadata.packages.find(
    ({ name }) => name === "local-agent-terminal-bootstrap",
  );
  bootstrap.dependencies.push(...additions.map(({ name }) => ({ name })));
  return metadata;
}

function removePackage(metadata, name) {
  metadata.packages = metadata.packages.filter((pkg) => pkg.name !== name);
  metadata.workspace_members = metadata.workspace_members.filter((member) => member !== name);
  for (const pkg of metadata.packages) {
    pkg.dependencies = pkg.dependencies.filter((dependency) => dependency.name !== name);
  }
}

function withMetadata(metadata, callback) {
  withFiles({ "metadata.json": `${JSON.stringify(metadata, null, 2)}\n` }, (directory) => {
    callback(join(directory, "metadata.json"));
  }, "m4-metadata-");
}

function withM4Source(files, callback) {
  withFiles(files, callback, "m4-contracts-");
}

function withM4Environment(
  {
    metadata = completeM4Metadata(),
    sourceFiles = {},
    desktopFiles = {
      "src/api/deliberation.ts": [
        "import { invoke } from \"@tauri-apps/api/core\";",
        "export const getWorkspace = (taskId) => invoke(\"get_deliberation_workspace\", { taskId });",
        "export const getContext = (packageId) => invoke(\"get_context_package\", { packageId });",
        "export const resolveApproval = (request) => invoke(\"resolve_plan_approval\", request);",
        "",
      ].join("\n"),
    },
  },
  callback,
) {
  const files = {
    "metadata.json": `${JSON.stringify(metadata, null, 2)}\n`,
    ...sourceFiles,
    ...Object.fromEntries(
      Object.entries(desktopFiles).map(([path, source]) => [
        join("apps", "desktop", path),
        source,
      ]),
    ),
  };
  withFiles(files, (directory) => {
    callback({
      appRoot: join(directory, "apps", "desktop"),
      metadataPath: join(directory, "metadata.json"),
      sourceRoot: directory,
    });
  }, "m4-final-");
}

function withFiles(files, callback, prefix) {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  try {
    for (const [path, source] of Object.entries(files)) {
      const target = join(directory, path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, source, "utf8");
    }
    callback(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
