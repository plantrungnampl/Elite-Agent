import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  cancelToolExecution,
  getApprovalRequest,
  getToolActivity,
  resolveToolApproval,
  stopAllTools,
  type CancelToolExecutionRequestDto,
  type GetApprovalRequestDto,
  type ResolveToolApprovalRequestDto,
} from "./tools";

describe("tool Tauri API", () => {
  beforeEach(() => {
    invoke.mockReset().mockResolvedValue({});
  });

  it("uses only the five narrow tool commands and exact immutable inputs", async () => {
    const approval = { approvalId: "approval-1" };
    const resolution = {
      approvalId: "approval-1",
      expectedOperationDigest: `sha256:${"a".repeat(64)}`,
      decision: "approve" as const,
    };
    const cancellation = { executionId: "execution-1" };

    await getToolActivity();
    await getApprovalRequest(approval);
    await resolveToolApproval(resolution);
    await cancelToolExecution(cancellation);
    await stopAllTools();

    expect(invoke.mock.calls).toEqual([
      ["get_tool_activity"],
      ["get_approval_request", { request: approval }],
      ["resolve_tool_approval", { request: resolution }],
      ["cancel_tool_execution", { request: cancellation }],
      ["stop_all_tools"],
    ]);
  });

  it("rejects unknown fields before invoking a privileged command", () => {
    expect(() =>
      getApprovalRequest({
        approvalId: "approval-1",
        replacementOperation: "shell.raw",
      } as unknown as GetApprovalRequestDto),
    ).toThrow("exactly: approvalId");
    expect(() =>
      resolveToolApproval({
        approvalId: "approval-1",
        expectedOperationDigest: `sha256:${"a".repeat(64)}`,
        decision: "approve",
        executable: "cmd.exe",
      } as unknown as ResolveToolApprovalRequestDto),
    ).toThrow("exactly: approvalId, expectedOperationDigest, decision");
    expect(() =>
      cancelToolExecution({
        executionId: "execution-1",
        force: true,
      } as unknown as CancelToolExecutionRequestDto),
    ).toThrow("exactly: executionId");
    expect(invoke).not.toHaveBeenCalled();
  });

  it("rejects malformed opaque IDs, digests, and decisions", () => {
    expect(() => getApprovalRequest({ approvalId: "../approval" })).toThrow();
    expect(() =>
      resolveToolApproval({
        approvalId: "approval-1",
        expectedOperationDigest: "not-a-digest",
        decision: "approve",
      }),
    ).toThrow();
    expect(() =>
      resolveToolApproval({
        approvalId: "approval-1",
        expectedOperationDigest: `sha256:${"a".repeat(64)}`,
        decision: "replace" as "approve",
      }),
    ).toThrow();
    expect(invoke).not.toHaveBeenCalled();
  });
});
