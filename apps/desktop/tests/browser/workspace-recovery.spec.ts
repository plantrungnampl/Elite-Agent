import axe from "axe-core";
import { expect, test, type Page } from "@playwright/test";

test("renders authoritative workspace state and guards recovery actions", async ({
  page,
}) => {
  await openReadyWorkspace(page);
  await loadProject(page);

  await expect(
    page.getByRole("heading", { name: "Repository health" }),
  ).toBeVisible();
  await expect(page.getByText("Ready for isolated tasks")).toBeVisible();
  await expect(page.getByText("Workspace dirty")).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("WorkspaceDirty");
  await expect(page.getByText("revoked", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /retry/i })).toHaveCount(0);

  await page.getByText("Exact worktree", { exact: true }).click();
  await expect(
    page.getByText("<managed-workspace>/worktree-task-1"),
  ).toBeVisible();
  await page.getByText("Timeline (1)").click();
  await expect(
    page.getByText("<script>alert('hostile')</script>"),
  ).toBeVisible();
  expect(await page.locator("script").count()).toBeGreaterThan(0);
  await expect(
    page.locator("main script", { hasText: "alert('hostile')" }),
  ).toHaveCount(0);

  const preserve = page.locator(".recovery-actions button").first();
  await preserve.click();
  await expect(preserve).toBeDisabled();
  await preserve.click({ force: true });
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (
            window as typeof window & {
              __workspaceCalls: Record<string, number>;
            }
          ).__workspaceCalls.preserve_workspace,
      ),
    )
    .toBe(1);
  await expect(
    page.getByRole("heading", { name: "Workspace status" }),
  ).toBeFocused();

  const discard = page.getByRole("button", {
    name: "Discard exact worktree",
  });
  await expect(discard).toBeDisabled();
  await page
    .getByRole("checkbox", {
      name: "Confirm discard of this exact managed worktree",
    })
    .check();
  await expect(discard).toBeEnabled();
});

test("supports keyboard flow, reduced motion, narrow reflow, and contrast", async ({
  browser,
}) => {
  const context = await browser.newContext({
    reducedMotion: "reduce",
    viewport: { width: 640, height: 900 },
  });
  const page = await context.newPage();
  await openReadyWorkspace(page);

  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to workspace" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("main")).toBeFocused();
  await loadProject(page);

  const durations = await page.getByRole("status").evaluate((element) => {
    const style = getComputedStyle(element);
    return [style.animationDuration, style.transitionDuration];
  });
  expect(Math.max(...durations.map(maxTimeMs))).toBeLessThanOrEqual(0.1);

  for (const width of [640, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const overflow = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
    }));
    expect(overflow.scroll).toBeLessThanOrEqual(overflow.client);
  }

  await page.addScriptTag({ content: axe.source });
  const results = await page.evaluate(async () => {
    const axeApi = (
      window as typeof window & {
        axe: {
          run: (
            context: Document,
            options: object,
          ) => Promise<{ violations: unknown[] }>;
        };
      }
    ).axe;
    return axeApi.run(document, {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
      },
      rules: { "color-contrast": { enabled: true } },
    });
  });
  expect(results.violations).toEqual([]);
  await context.close();
});

async function openReadyWorkspace(page: Page) {
  await page.addInitScript((dashboard) => {
    const calls: Record<string, number> = {};
    (
      window as typeof window & {
        __workspaceCalls: Record<string, number>;
        __TAURI_INTERNALS__: {
          invoke: (command: string) => Promise<unknown>;
        };
      }
    ).__workspaceCalls = calls;
    (
      window as typeof window & {
        __TAURI_INTERNALS__: {
          invoke: (command: string) => Promise<unknown>;
        };
      }
    ).__TAURI_INTERNALS__ = {
      invoke: async (command) => {
        calls[command] = (calls[command] ?? 0) + 1;
        if (command === "get_startup_status") {
          return { state: "ready", issues: [] };
        }
        if (command === "get_local_diagnostics") {
          return [];
        }
        if (command === "preserve_workspace") {
          await new Promise((resolve) => setTimeout(resolve, 1_000));
        }
        return dashboard;
      },
    };
  }, dashboardFixture());
  await page.goto("/");
  await expect(
    page.getByRole("heading", { level: 1, name: "Workspace recovery" }),
  ).toBeVisible();
}

async function loadProject(page: Page) {
  await page.getByLabel("Project ID").first().fill("project-1");
  await page.getByRole("button", { name: "Load project" }).click();
  await expect(
    page.getByRole("heading", { name: "Repository health" }),
  ).toBeVisible();
}

function dashboardFixture() {
  const fingerprint = {
    head: "a".repeat(40),
    indexDigest: `sha256:${"b".repeat(64)}`,
    statusDigest: `sha256:${"c".repeat(64)}`,
  };
  return {
    projectId: "project-1",
    repository: {
      repositoryId: "repository-1",
      health: "healthy",
      stableIdentity: "identity",
      defaultBranch: "main",
      baseCommit: "a".repeat(40),
      originalCheckout: "clean",
      hazards: [],
      fingerprint,
    },
    tasks: [
      {
        taskId: "task-1",
        projectId: "project-1",
        title: "Recover task",
        objective: "Preserve evidence",
        riskLevel: "high",
        phase: "WorkspaceDirty",
        condition: "Active",
        operationState: "Indeterminate",
        baseBranch: "main",
        baseCommit: "a".repeat(40),
        taskBranch: "codex/task-1",
        worktree: {
          worktreeId: "worktree-task-1",
          repositoryId: "repository-1",
          taskId: "task-1",
          branch: "codex/task-1",
          baseCommit: "a".repeat(40),
          targetPathDisplay: "<managed-workspace>/worktree-task-1",
          state: "present",
          expectedPresence: "present",
          fingerprint,
        },
        currentSequence: 9,
        workspaceVersion: 3,
        fencingEpoch: 4,
        leaseState: "revoked",
        recoveryCandidates: [
          {
            candidateId: "candidate-preserve",
            taskId: "task-1",
            expectedWorkspaceVersion: 3,
            reason: "indeterminate_non_repeatable",
            evidence: {
              summary: "Outcome remains indeterminate.",
              artifactId: "artifact-1",
            },
            actions: [
              {
                candidateId: "candidate-preserve",
                code: "preserve",
                label: "Preserve workspace",
              },
            ],
            expectedWorktree: null,
          },
          {
            candidateId: "candidate-discard",
            taskId: "task-1",
            expectedWorkspaceVersion: 3,
            reason: "exact_match",
            evidence: {
              summary: "Exact worktree evidence.",
              artifactId: "artifact-2",
            },
            actions: [
              {
                candidateId: "candidate-discard",
                code: "discard",
                label: "Discard exact worktree",
              },
            ],
            expectedWorktree: {
              worktreeId: "worktree-task-1",
              repositoryId: "repository-1",
              taskId: "task-1",
              branch: "codex/task-1",
              baseCommit: "a".repeat(40),
              targetPathDisplay: "<managed-workspace>/worktree-task-1",
              expectedPresence: "present",
            },
          },
        ],
        timeline: [
          {
            sequence: 9,
            eventType: "workspace.mutated",
            createdAt: "2026-07-26T00:00:00Z",
            summary: "<script>alert('hostile')</script>",
            evidence: null,
          },
        ],
      },
    ],
    recovery: [],
  };
}

function maxTimeMs(value: string) {
  return Math.max(
    ...value.split(",").map((duration) => {
      const trimmed = duration.trim();
      const amount = Number.parseFloat(trimmed);
      return trimmed.endsWith("ms") ? amount : amount * 1_000;
    }),
  );
}
