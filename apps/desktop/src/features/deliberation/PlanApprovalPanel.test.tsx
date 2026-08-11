import * as axe from "axe-core";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PlanApprovalDto } from "../../api/deliberation";
import { PlanApprovalPanel } from "./PlanApprovalPanel";

const deliberationApi = vi.hoisted(() => ({ resolvePlanApproval: vi.fn() }));

vi.mock("../../api/deliberation", () => deliberationApi);

describe("PlanApprovalPanel", () => {
  beforeEach(() => {
    deliberationApi.resolvePlanApproval.mockReset().mockResolvedValue({
      approvalId: "approval-1",
      taskId: "task-1",
      taskVersion: 10,
      status: "resolved",
      action: "approve",
    });
  });

  it("renders the exact selected plan, rejected alternatives, agreement, dissent, scope, risk, estimates, versions, and digest", async () => {
    const { container } = render(
      <PlanApprovalPanel approval={approvalFixture()} taskVersion={9} onResolved={vi.fn()} />,
    );

    for (const text of [
      "Use the typed application boundary",
      "Direct database access",
      "Leaks storage",
      "Boundary is narrow",
      "Recovery proof remains required",
      "apps/desktop/src/api/deliberation.ts",
      "cargo test",
      "No raw provider payload crosses the boundary",
      "8,000 microunits",
      "15 minutes",
      "Plan version 3",
      `sha256:${"b".repeat(64)}`,
      "apps/desktop",
      "Fencing epoch 7",
      `sha256:${"a".repeat(64)}`,
    ]) {
      expect(screen.getAllByText(text, { exact: false })[0]).toBeVisible();
    }
    expect(screen.getByRole("button", { name: "Approve" })).toHaveClass("primary-button");
    for (const action of ["Revise", "Reopen", "Add/replace agent", "Reject"]) {
      expect(screen.getByRole("button", { name: action })).toBeVisible();
    }

    const result = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(result.violations).toEqual([]);
  });

  it("requires digest confirmation and submits only immutable authority fields", async () => {
    const user = userEvent.setup();
    const onResolved = vi.fn();
    render(
      <PlanApprovalPanel approval={approvalFixture()} taskVersion={9} onResolved={onResolved} />,
    );
    const approve = screen.getByRole("button", { name: "Approve" });
    expect(approve).toBeDisabled();
    await user.click(
      screen.getByRole("checkbox", { name: "Confirm approval of this exact plan digest" }),
    );
    await user.click(approve);

    expect(deliberationApi.resolvePlanApproval).toHaveBeenCalledWith({
      approvalId: "approval-1",
      displayedDigest: `sha256:${"a".repeat(64)}`,
      expectedTaskVersion: 9,
      action: "approve",
    });
    expect(onResolved).toHaveBeenCalled();
    expect(screen.getByRole("status")).toHaveTextContent("Plan approval recorded");
  });

  it.each([
    ["Revise", "revise"],
    ["Reopen", "reopen"],
    ["Add/replace agent", "add_or_replace_agent"],
    ["Reject", "reject"],
  ] as const)("maps %s to its allowlisted action", async (label, action) => {
    const user = userEvent.setup();
    render(
      <PlanApprovalPanel approval={approvalFixture()} taskVersion={9} onResolved={vi.fn()} />,
    );
    await user.click(screen.getByRole("button", { name: label }));
    expect(deliberationApi.resolvePlanApproval).toHaveBeenCalledWith({
      approvalId: "approval-1",
      displayedDigest: `sha256:${"a".repeat(64)}`,
      expectedTaskVersion: 9,
      action,
    });
  });

  it.each(["expired", "digest_changed"] as const)(
    "disables stale authority when the approval is %s",
    (status) => {
      render(
        <PlanApprovalPanel
          approval={{ ...approvalFixture(), status }}
          taskVersion={9}
          onResolved={vi.fn()}
        />,
      );
      expect(
        screen.getAllByText(status === "expired" ? "Approval expired" : "Digest changed")[0],
      ).toBeVisible();
      expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled();
      expect(screen.getByRole("button", { name: "Revise" })).toBeDisabled();
    },
  );

  it("invalidates a stale displayed approval after a recoverable conflict", async () => {
    const user = userEvent.setup();
    deliberationApi.resolvePlanApproval.mockRejectedValueOnce({
      code: "conflict",
      message: "Approval changed and must be reviewed again.",
      retryable: true,
    });
    render(
      <PlanApprovalPanel approval={approvalFixture()} taskVersion={9} onResolved={vi.fn()} />,
    );
    await user.click(screen.getByRole("button", { name: "Revise" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Approval changed and must be reviewed again.",
    );
    expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled();
  });
});

function approvalFixture(): PlanApprovalDto {
  return {
    approvalId: "approval-1",
    taskId: "task-1",
    status: "requested",
    selectedApproachId: "approach-a",
    selectedApproachLabel: "Use the typed application boundary",
    rejectedAlternatives: [
      { approachId: "approach-b", label: "Direct database access", reason: "Leaks storage" },
    ],
    agreement: [
      { agentId: "agent-a", position: "agree", summary: "Boundary is narrow" },
      { agentId: "agent-b", position: "dissent", summary: "Recovery proof remains required" },
    ],
    unresolvedObjections: ["Recovery proof remains required"],
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
  };
}
