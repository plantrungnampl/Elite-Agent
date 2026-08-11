import * as axe from "axe-core";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ContextPackageDto } from "../../api/deliberation";
import { ContextInspector } from "./ContextInspector";

const deliberationApi = vi.hoisted(() => ({ getContextPackage: vi.fn() }));

vi.mock("../../api/deliberation", () => deliberationApi);

describe("ContextInspector", () => {
  beforeEach(() => {
    deliberationApi.getContextPackage.mockReset().mockResolvedValue(packageFixture());
  });

  it("shows the exact immutable package, redactions, provenance, versions, and policy IDs", async () => {
    const { container } = render(
      <ContextInspector packageId="context-1" expectedTaskId="task-1" onClose={vi.fn()} />,
    );

    const dialog = await screen.findByRole("dialog", { name: "Context inspector" });
    expect(within(dialog).getByText("context-1")).toBeVisible();
    expect(within(dialog).getByText("agent-cloud")).toBeVisible();
    expect(within(dialog).getByText("prompt-v3")).toBeVisible();
    expect(within(dialog).getByText("policy-decision:context-1")).toBeVisible();
    expect(within(dialog).getByText("src/secret.rs")).toBeVisible();
    expect(within(dialog).getByText("sha256:source-content")).toBeVisible();
    expect(within(dialog).getByText("Lines 4–9")).toBeVisible();
    expect(within(dialog).getByText("Redacted", { exact: true })).toBeVisible();
    expect(within(dialog).getByText("redaction-report-1")).toBeVisible();
    expect(within(dialog).getByText("Stale evidence", { exact: false })).toBeVisible();

    const result = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(result.violations).toEqual([]);
  });

  it("rejects a package belonging to another task and allows recovery", async () => {
    const user = userEvent.setup();
    deliberationApi.getContextPackage
      .mockResolvedValueOnce({ ...packageFixture(), taskId: "task-other" })
      .mockResolvedValueOnce(packageFixture());
    render(
      <ContextInspector packageId="context-1" expectedTaskId="task-1" onClose={vi.fn()} />,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Context package does not belong to this task.",
    );
    await user.click(screen.getByRole("button", { name: "Retry context load" }));
    expect(await screen.findByText("policy-decision:context-1")).toBeVisible();
  });

  it("supports an empty package and Escape close", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    deliberationApi.getContextPackage.mockResolvedValueOnce({
      ...packageFixture(),
      members: [],
    });
    render(
      <ContextInspector packageId="context-1" expectedTaskId="task-1" onClose={onClose} />,
    );
    expect(await screen.findByText("No context members disclosed.")).toBeVisible();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

function packageFixture(): ContextPackageDto {
  return {
    packageId: "context-1",
    taskId: "task-1",
    agentId: "agent-cloud",
    role: "critic",
    objective: "Review the exact Task 9 boundary",
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
        source: {
          projectId: "project-1",
          revision: "commit-1",
          pathIdentity: "src/secret.rs",
          contentHash: "sha256:source-content",
        },
        lineRange: { start: 4, end: 9 },
        symbol: "SecretBoundary",
        freshness: "stale",
        disclosure: { kind: "redacted", stableReportId: "redaction-report-1" },
      },
    ],
  };
}
