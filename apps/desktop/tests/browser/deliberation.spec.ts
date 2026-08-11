import axe from "axe-core";
import { expect, test, type Page } from "@playwright/test";

test("supports keyboard context inspection and a digest-bound plan decision", async ({
  page,
}) => {
  await openDeliberation(page);

  const skip = page.getByRole("link", { name: "Skip to deliberation" });
  await skip.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("main")).toBeFocused();
  await expect(
    page.getByRole("status").filter({ hasText: "Phase AwaitingPlanApproval" }),
  ).toBeVisible();

  const taskId = page.getByLabel("Task ID");
  await taskId.focus();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Load deliberation" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Refresh deliberation" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Inspect context for agent-cloud" }),
  ).toBeFocused();

  const contextTrigger = page.getByRole("button", {
    name: "Inspect context for agent-cloud",
  });
  await contextTrigger.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Context inspector" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("Redacted", { exact: true })).toBeVisible();
  const redactionRecords = dialog.getByText("redaction-report-1");
  await expect(redactionRecords).toHaveCount(2);
  await expect(redactionRecords.nth(0)).toBeVisible();
  await expect(redactionRecords.nth(1)).toBeVisible();
  for (let index = 0; index < 6; index += 1) {
    await page.keyboard.press("Tab");
    expect(await dialog.evaluate((element) => element.contains(document.activeElement))).toBe(
      true,
    );
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(contextTrigger).toBeFocused();
  const focusStyle = await contextTrigger.evaluate((element) => {
    const style = getComputedStyle(element);
    return { style: style.outlineStyle, width: Number.parseFloat(style.outlineWidth) };
  });
  expect(focusStyle.style).not.toBe("none");
  expect(focusStyle.width).toBeGreaterThanOrEqual(3);

  const approve = page.getByRole("button", { name: "Approve" });
  await expect(approve).toBeDisabled();
  const confirmation = page.getByRole("checkbox", {
    name: "Confirm approval of this exact plan digest",
  });
  await confirmation.focus();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Revise" })).toBeFocused();
  await confirmation.check();
  await page.keyboard.press("Tab");
  await expect(approve).toBeFocused();
  await approve.click();
  await expect(
    page.getByRole("status").filter({ hasText: "Plan approval recorded" }),
  ).toBeVisible();
  expect(await commandCalls(page, "resolve_plan_approval")).toEqual([
    {
      request: {
        approvalId: "approval-1",
        displayedDigest: `sha256:${"a".repeat(64)}`,
        expectedTaskVersion: 9,
        action: "approve",
      },
    },
  ]);
});

test("invalidates stale approval authority and passes reflow, targets, motion, contrast, and axe", async ({
  browser,
}) => {
  const initial = workspaceFixture();
  const changed = workspaceFixture();
  changed.approval = {
    ...changed.approval!,
    status: "digest_changed",
    operationDigest: `sha256:${"d".repeat(64)}`,
  };
  const context = await browser.newContext({
    reducedMotion: "reduce",
    viewport: { width: 1280, height: 720 },
  });
  const page = await context.newPage();
  await openDeliberation(page, [initial, changed]);
  await expect(page.getByText("Stale evidence", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("Focused tests passed before the source changed.")).toBeVisible();

  await page.getByRole("button", { name: "Refresh deliberation" }).click();
  await expect(page.getByText("Digest changed", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeDisabled();
  expect(await commandCalls(page, "resolve_plan_approval")).toEqual([]);

  const undersized = await page.locator("button, a, .confirmation-label").evaluateAll((elements) =>
    elements
      .filter((element) => {
        const rect = element.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0 && rect.height < 44;
      })
      .map((element) => `${element.tagName}:${element.getAttribute("aria-label") ?? element.textContent}`),
  );
  expect(undersized).toEqual([]);

  const durations = await page.getByRole("status").first().evaluate((element) => {
    const style = getComputedStyle(element);
    return [style.animationDuration, style.transitionDuration];
  });
  expect(Math.max(...durations.map(maxTimeMs))).toBeLessThanOrEqual(0.1);

  await page.evaluate(() => {
    document.documentElement.style.fontSize = "200%";
  });
  for (const width of [1280, 640, 320]) {
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
        axe: { run: (context: Document, options: object) => Promise<{ violations: unknown[] }> };
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

async function openDeliberation(
  page: Page,
  workspaces = [workspaceFixture()],
  contextPackage = contextFixture(),
) {
  await page.addInitScript(
    ({ workspaces, contextPackage }) => {
      const calls: Record<string, unknown[]> = {};
      let workspaceIndex = 0;
      (
        window as typeof window & {
          __deliberationCalls: Record<string, unknown[]>;
          __TAURI_INTERNALS__: {
            invoke: (command: string, args?: unknown) => Promise<unknown>;
          };
        }
      ).__deliberationCalls = calls;
      (
        window as typeof window & {
          __TAURI_INTERNALS__: {
            invoke: (command: string, args?: unknown) => Promise<unknown>;
          };
        }
      ).__TAURI_INTERNALS__ = {
        invoke: async (command, args) => {
          calls[command] = [...(calls[command] ?? []), args];
          if (command === "get_startup_status") {
            return { state: "ready", issues: [] };
          }
          if (command === "get_local_diagnostics") {
            return [];
          }
          if (command === "get_deliberation_workspace") {
            const workspace = workspaces[Math.min(workspaceIndex, workspaces.length - 1)];
            workspaceIndex += 1;
            return workspace;
          }
          if (command === "get_context_package") {
            return contextPackage;
          }
          if (command === "resolve_plan_approval") {
            return {
              approvalId: "approval-1",
              taskId: "task-1",
              taskVersion: 10,
              status: "resolved",
              action: "approve",
            };
          }
          return {};
        },
      };
    },
    { workspaces, contextPackage },
  );
  await page.goto("/");
  await page.getByRole("button", { name: "Deliberation" }).click();
  await page.getByLabel("Task ID").fill("task-1");
  await page.getByRole("button", { name: "Load deliberation" }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: "Deliberation workspace" }),
  ).toBeVisible();
  await expect(page.getByText("Authoritative state loaded")).toBeVisible();
}

async function commandCalls(page: Page, command: string) {
  return page.evaluate(
    (name) =>
      (
        window as typeof window & { __deliberationCalls: Record<string, unknown[]> }
      ).__deliberationCalls[name] ?? [],
    command,
  );
}

function workspaceFixture() {
  return {
    availability: "ready",
    taskId: "task-1",
    phase: "AwaitingPlanApproval",
    taskVersion: 9,
    statusMessage: "Authoritative state loaded",
    workflow: [
      {
        phaseId: "approval",
        label: "Awaiting plan approval",
        state: "current",
        detail: "Digest-bound user decision required",
        retryCount: 0,
        approvalGate: true,
      },
    ],
    agents: [
      {
        agentId: "agent-cloud",
        role: "critic",
        providerLabel: "Cloud agent",
        locality: "cloud",
        status: "Review complete",
        contextScope: "Read-only task evidence",
        contextPackageId: "context-1",
        usedTokens: 1200,
        costMicrounits: 4400,
        health: "Healthy",
        permissions: ["context.query"],
        trustTier: "Trusted core adapter",
        sandboxStatus: "Sandbox enforced",
        identityChanged: false,
      },
    ],
    cards: [
      {
        cardId: "evidence-1",
        kind: "evidence",
        title: "Verification result",
        summary: "Focused tests passed before the source changed.",
        actorId: "core",
        evidenceState: "verified",
        stale: true,
        artifactIds: ["artifact-evidence"],
      },
    ],
    thread: {
      threadId: "thread-1",
      summary: "Bounded discussion summary",
      messages: [{ messageId: "message-1", actorId: "agent-cloud", body: "Review complete" }],
      truncated: true,
    },
    evidence: [],
    approval: {
      approvalId: "approval-1",
      taskId: "task-1",
      status: "requested",
      selectedApproachId: "approach-a",
      selectedApproachLabel: "Use the typed application boundary",
      rejectedAlternatives: [],
      agreement: [{ agentId: "agent-cloud", position: "agree", summary: "Approved" }],
      unresolvedObjections: [],
      affectedFiles: ["apps/desktop/src/api/deliberation.ts"],
      plannedTools: ["cargo test"],
      verificationProfile: "M4 desktop gate",
      rollbackPlan: "Revert the Task 9 commit",
      securityImplications: ["No raw provider payload crosses the boundary"],
      estimatedCostMicrounits: 8000,
      estimatedDurationSeconds: 900,
      planVersion: 3,
      policySnapshotDigest: `sha256:${"b".repeat(64)}`,
      writableScopes: ["apps/desktop"],
      fencingEpoch: 7,
      operationDigest: `sha256:${"a".repeat(64)}`,
      expiresAt: "2026-08-12T12:00:00Z",
    },
  };
}

function contextFixture() {
  return {
    packageId: "context-1",
    taskId: "task-1",
    agentId: "agent-cloud",
    role: "critic",
    objective: "Review Task 9",
    artifactId: "artifact-context-1",
    contentDigest: `sha256:${"c".repeat(64)}`,
    policySnapshotDigest: `sha256:${"b".repeat(64)}`,
    policyDecisionIds: ["policy-decision:context-1"],
    versions: {
      promptTemplate: "prompt-v3",
      retrievalPipeline: "keyword-v1",
      tokenizer: "byte-token-v1",
    },
    budget: { maxTokens: 4000, reservedResponseTokens: 1000, usedInputTokens: 2200 },
    members: [
      {
        memberId: "member-1",
        content: "pub struct [REDACTED]",
        source: {
          projectId: "project-1",
          revision: "commit-1",
          pathIdentity: "src/secret.rs",
          contentHash: "sha256:source-content",
        },
        lineRange: { start: 4, end: 9 },
        symbol: "SecretBoundary",
        freshness: "current",
        disclosure: { kind: "redacted", stableReportId: "redaction-report-1" },
        policyDecisionIds: ["policy-decision:item-1"],
        provenance: ["artifact:source-1"],
        redactionReportIds: ["redaction-report-1"],
      },
    ],
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
