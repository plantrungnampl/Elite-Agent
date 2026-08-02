import * as axe from "axe-core";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  ToolActivityDto,
  ToolActivityEntryDto,
  ToolApprovalRequestDto,
} from "../../api/tools";
import { ToolActivityScreen } from "./ToolActivityScreen";

const toolsApi = vi.hoisted(() => ({
  getToolActivity: vi.fn(),
  getApprovalRequest: vi.fn(),
  resolveToolApproval: vi.fn(),
  cancelToolExecution: vi.fn(),
  stopAllTools: vi.fn(),
}));

vi.mock("../../api/tools", () => toolsApi);

describe("ToolActivityScreen", () => {
  beforeEach(() => {
    toolsApi.getToolActivity.mockReset().mockResolvedValue(activityFixture());
    toolsApi.getApprovalRequest
      .mockReset()
      .mockResolvedValue(approvalFixture());
    toolsApi.resolveToolApproval.mockReset().mockResolvedValue({
      approvalId: "approval-1",
      executionId: "execution-approval",
      status: "running",
    });
    toolsApi.cancelToolExecution.mockReset().mockResolvedValue({
      executionId: "execution-running",
      status: "terminated",
      cancelled: true,
    });
    toolsApi.stopAllTools.mockReset().mockResolvedValue({ receipts: [] });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows loading, empty, and unavailable-boundary states honestly", async () => {
    toolsApi.getToolActivity.mockReturnValueOnce(new Promise(() => undefined));
    const { unmount } = render(<ToolActivityScreen />);
    expect(screen.getByRole("main")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading authoritative tool activity",
    );

    unmount();
    toolsApi.getToolActivity.mockResolvedValueOnce({
      availability: "unavailable",
      entries: [],
    });
    render(<ToolActivityScreen />);

    expect(await screen.findByText("Tool boundary unavailable")).toBeVisible();
    expect(screen.getByText("No tool activity recorded.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Stop all tools" })).toBeDisabled();
  });

  it("renders every audited state with text, safe exact context, and controls", async () => {
    render(<ToolActivityScreen />);

    expect(await screen.findByRole("table", { name: "Tool activity" })).toBeVisible();
    for (const label of [
      "Denied",
      "Redacted",
      "Approval required",
      "Running",
      "Cancelling",
      "Terminated",
      "Failed",
      "Interrupted",
      "Indeterminate",
    ]) {
      expect(screen.getByText(label, { exact: true })).toBeVisible();
    }
    expect(screen.getAllByText("agent-local").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Run the approved verification").length).toBeGreaterThan(0);
    expect(screen.getAllByText(`sha256:${"a".repeat(64)}`).length).toBeGreaterThan(0);
    expect(screen.getAllByText("network: denied").length).toBeGreaterThan(0);
    expect(screen.queryByText(/D:\\|C:\\/)).not.toBeInTheDocument();
  });

  it("requires exact confirmation, traps focus, resolves by opaque ID, and restores focus", async () => {
    const user = userEvent.setup();
    render(<ToolActivityScreen />);
    const trigger = await screen.findByRole("button", {
      name: "Review approval for execution-approval",
    });
    await user.click(trigger);

    const dialog = await screen.findByRole("dialog", { name: "Approve tool request" });
    expect(within(dialog).getByText("toolchain:git")).toBeVisible();
    expect(within(dialog).getByText('["status"]')).toBeVisible();
    expect(within(dialog).getByText("agent-local")).toBeVisible();
    expect(within(dialog).getByText("Run the approved verification")).toBeVisible();
    expect(within(dialog).getByText("environment-safe")).toBeVisible();
    expect(within(dialog).getByText("denied", { exact: true })).toBeVisible();
    expect(within(dialog).getByText("rule-tool-approval")).toBeVisible();
    expect(within(dialog).getByText(`sha256:${"a".repeat(64)}`)).toBeVisible();

    const approve = within(dialog).getByRole("button", { name: "Approve exact request" });
    expect(approve).toBeDisabled();
    await user.click(
      within(dialog).getByRole("checkbox", {
        name: "Confirm approval of this exact digest",
      }),
    );
    expect(approve).toBeEnabled();

    await user.keyboard("{Tab}");
    await user.keyboard("{Tab}");
    expect(dialog).toContainElement(document.activeElement as HTMLElement | null);
    await user.click(approve);

    expect(toolsApi.resolveToolApproval).toHaveBeenCalledWith({
      approvalId: "approval-1",
      expectedOperationDigest: `sha256:${"a".repeat(64)}`,
      decision: "approve",
    });
    expect(trigger).toHaveFocus();
    expect(screen.getByRole("status")).toHaveTextContent("Approval recorded");
  });

  it("closes a stale dialog, restores focus, announces invalidation, and never resolves it", async () => {
    vi.useFakeTimers();
    const initial = activityFixture();
    const stale = activityFixture();
    const approval = stale.entries.find(
      (entry) => entry.executionId === "execution-approval",
    )!;
    approval.operationDigest = `sha256:${"b".repeat(64)}`;
    toolsApi.getToolActivity
      .mockResolvedValueOnce(initial)
      .mockResolvedValue(stale);
    render(<ToolActivityScreen pollIntervalMs={5_000} />);
    await act(async () => Promise.resolve());
    const trigger = screen.getByRole("button", {
      name: "Review approval for execution-approval",
    });
    act(() => trigger.click());
    await act(async () => Promise.resolve());
    expect(screen.getByRole("dialog")).toBeVisible();

    await act(async () => {
      vi.advanceTimersByTime(5_000);
      await Promise.resolve();
    });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Approval changed and must be reviewed again",
    );
    expect(toolsApi.resolveToolApproval).not.toHaveBeenCalled();
  });

  it("supports Escape, explicit stop-all confirmation, semantics, and axe", async () => {
    const user = userEvent.setup();
    const { container } = render(<ToolActivityScreen />);
    const trigger = await screen.findByRole("button", {
      name: "Review approval for execution-approval",
    });
    await user.click(trigger);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();

    const stop = screen.getByRole("button", { name: "Stop all tools" });
    expect(stop).toBeDisabled();
    await user.click(
      screen.getByRole("checkbox", {
        name: "Confirm stopping every running tool",
      }),
    );
    await user.click(stop);
    expect(toolsApi.stopAllTools).toHaveBeenCalledTimes(1);

    expect(screen.getByRole("banner")).toBeVisible();
    expect(screen.getByRole("main")).toHaveAttribute("id", "tool-activity-main");
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    const result = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(result.violations).toEqual([]);
  });
});

function activityFixture(): ToolActivityDto {
  const statuses: ToolActivityEntryDto["status"][] = [
    "denied",
    "succeeded",
    "approval_required",
    "running",
    "cancelling",
    "terminated",
    "failed",
    "interrupted",
    "indeterminate",
  ];
  return {
    availability: "ready",
    entries: statuses.map((status, index) => ({
      executionId:
        status === "approval_required"
          ? "execution-approval"
          : status === "running"
            ? "execution-running"
            : `execution-${status}`,
      approvalId: status === "approval_required" ? "approval-1" : null,
      toolName: "process.exec",
      status,
      executable: "toolchain:git",
      arguments: ["status"],
      cwdScope: "worktree:task-1",
      readScopes: [],
      writeScopes: [],
      actorId: "agent-local",
      effectiveRole: "implementer",
      reason: "Run the approved verification",
      operationDigest: `sha256:${"a".repeat(64)}`,
      policyDecisionId: `policy-${index}`,
      policySnapshotDigest: `sha256:${"c".repeat(64)}`,
      environmentProfileDigest: "environment-safe",
      networkProfile: "denied",
      expiresAt: status === "approval_required" ? "2026-08-02T12:00:00Z" : null,
      fencingToken: 7,
      policyRules: ["rule-tool-approval"],
      redactionState: status === "succeeded" ? "redacted" : "none",
      startedAt: status === "approval_required" ? null : "2026-08-02T10:00:00Z",
      completedAt: ["running", "cancelling", "approval_required"].includes(status)
        ? null
        : "2026-08-02T10:00:01Z",
    })),
  };
}

function approvalFixture(): ToolApprovalRequestDto {
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
