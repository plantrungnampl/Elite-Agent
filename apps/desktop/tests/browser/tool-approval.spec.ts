import axe from "axe-core";
import { expect, test, type Page } from "@playwright/test";

test("supports a digest-bound keyboard approval flow with focus restoration", async ({
  page,
}) => {
  await openToolActivity(page);
  const trigger = page.getByRole("button", {
    name: "Review approval for execution-approval",
  });
  await trigger.focus();
  await page.keyboard.press("Enter");

  const dialog = page.getByRole("dialog", { name: "Approve tool request" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("toolchain:git")).toBeVisible();
  await expect(dialog.getByText('["status"]')).toBeVisible();
  await expect(dialog.getByText(`sha256:${"a".repeat(64)}`)).toBeVisible();
  const approve = dialog.getByRole("button", { name: "Approve exact request" });
  await expect(approve).toBeDisabled();
  await dialog
    .getByRole("checkbox", { name: "Confirm approval of this exact digest" })
    .check();
  await expect(approve).toBeEnabled();

  for (let index = 0; index < 5; index += 1) {
    await page.keyboard.press("Tab");
    expect(
      await dialog.evaluate((element) => element.contains(document.activeElement)),
    ).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(trigger).toBeFocused();
  expect(await toolCallCount(page, "resolve_tool_approval")).toBe(0);
});

test("invalidates a replaced approval without resolving the stale digest", async ({
  page,
}) => {
  const initial = activityFixture();
  const replaced = activityFixture();
  replaced.entries[0].operationDigest = `sha256:${"b".repeat(64)}`;
  await openToolActivity(page, [initial, replaced]);
  const trigger = page.getByRole("button", {
    name: "Review approval for execution-approval",
  });
  await trigger.click();
  await expect(page.getByRole("dialog", { name: "Approve tool request" })).toBeVisible();

  await expect(page.getByRole("dialog", { name: "Approve tool request" })).toHaveCount(0, {
    timeout: 7_000,
  });
  await expect(page.getByRole("status")).toContainText(
    "Approval changed and must be reviewed again",
  );
  await expect(trigger).toBeFocused();
  expect(await toolCallCount(page, "resolve_tool_approval")).toBe(0);
});

test("confirms stop-all and passes reduced-motion, zoom, reflow, contrast, and axe", async ({
  browser,
}) => {
  const context = await browser.newContext({
    reducedMotion: "reduce",
    viewport: { width: 640, height: 900 },
  });
  const page = await context.newPage();
  await openToolActivity(page);

  const stop = page.getByRole("button", { name: "Stop all tools" });
  await expect(stop).toBeDisabled();
  await page
    .getByRole("checkbox", { name: "Confirm stopping every running tool" })
    .check();
  await stop.click();
  expect(await toolCallCount(page, "stop_all_tools")).toBe(1);

  await page.evaluate(() => {
    document.documentElement.style.fontSize = "200%";
  });
  for (const width of [640, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const overflow = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
    }));
    expect(overflow.scroll).toBeLessThanOrEqual(overflow.client);
  }

  const durations = await page.getByRole("status").evaluate((element) => {
    const style = getComputedStyle(element);
    return [style.animationDuration, style.transitionDuration];
  });
  expect(Math.max(...durations.map(maxTimeMs))).toBeLessThanOrEqual(0.1);

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

async function openToolActivity(
  page: Page,
  activities = [activityFixture()],
  approval = approvalFixture(),
) {
  await page.addInitScript(
    ({ activities, approval }) => {
      const calls: Record<string, number> = {};
      let activityIndex = 0;
      (
        window as typeof window & {
          __toolCalls: Record<string, number>;
          __TAURI_INTERNALS__: { invoke: (command: string) => Promise<unknown> };
        }
      ).__toolCalls = calls;
      (
        window as typeof window & {
          __TAURI_INTERNALS__: { invoke: (command: string) => Promise<unknown> };
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
          if (command === "get_tool_activity") {
            const activity = activities[Math.min(activityIndex, activities.length - 1)];
            activityIndex += 1;
            return activity;
          }
          if (command === "get_approval_request") {
            return approval;
          }
          if (command === "stop_all_tools") {
            return { receipts: [] };
          }
          return {};
        },
      };
    },
    { activities, approval },
  );
  await page.goto("/");
  await page.getByRole("button", { name: "Tool activity" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Tool activity" })).toBeVisible();
}

async function toolCallCount(page: Page, command: string) {
  return page.evaluate(
    (name) =>
      (
        window as typeof window & { __toolCalls: Record<string, number> }
      ).__toolCalls[name] ?? 0,
    command,
  );
}

function activityFixture() {
  return {
    availability: "ready",
    entries: [
      {
        executionId: "execution-approval",
        approvalId: "approval-1",
        toolName: "process.exec",
        status: "approval_required",
        executable: "toolchain:git",
        arguments: ["status"],
        cwdScope: "worktree:task-1",
        readScopes: [],
        writeScopes: [],
        actorId: "agent-local",
        effectiveRole: "implementer",
        reason: "Run the approved verification",
        operationDigest: `sha256:${"a".repeat(64)}`,
        policyDecisionId: "policy-1",
        policySnapshotDigest: `sha256:${"c".repeat(64)}`,
        environmentProfileDigest: "environment-safe",
        networkProfile: "denied",
        expiresAt: "2026-08-02T12:00:00Z",
        fencingToken: 7,
        policyRules: ["rule-tool-approval"],
        redactionState: "none",
        startedAt: null,
        completedAt: null,
      },
      {
        executionId: "execution-running",
        approvalId: null,
        toolName: "process.exec",
        status: "running",
        executable: "toolchain:git",
        arguments: ["status"],
        cwdScope: "worktree:task-1",
        readScopes: [],
        writeScopes: [],
        actorId: "agent-local",
        effectiveRole: "implementer",
        reason: "Run the approved verification",
        operationDigest: `sha256:${"b".repeat(64)}`,
        policyDecisionId: "policy-2",
        policySnapshotDigest: `sha256:${"c".repeat(64)}`,
        environmentProfileDigest: "environment-safe",
        networkProfile: "denied",
        expiresAt: null,
        fencingToken: 7,
        policyRules: ["rule-tool-allow"],
        redactionState: "none",
        startedAt: "2026-08-02T10:00:00Z",
        completedAt: null,
      },
    ],
  };
}

function approvalFixture() {
  return {
    approvalId: "approval-1",
    executionId: "execution-approval",
    executable: "toolchain:git",
    arguments: ["status"],
    cwdScope: "worktree:task-1",
    readScopes: [],
    writeScopes: [],
    operationDigest: `sha256:${"a".repeat(64)}`,
    expiresAt: "2026-08-02T12:00:00Z",
    actorId: "agent-local",
    reason: "Run the approved verification",
    environmentProfileDigest: "environment-safe",
    networkProfile: "denied",
    fencingToken: 7,
    policyRules: ["rule-tool-approval"],
    redactionState: "none",
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
