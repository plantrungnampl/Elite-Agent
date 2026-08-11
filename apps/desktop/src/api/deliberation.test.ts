import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  getContextPackage,
  getDeliberationWorkspace,
  resolvePlanApproval,
  type GetContextPackageRequestDto,
  type GetDeliberationWorkspaceRequestDto,
  type ResolvePlanApprovalRequestDto,
} from "./deliberation";

describe("deliberation Tauri API", () => {
  beforeEach(() => {
    invoke.mockReset().mockResolvedValue({});
  });

  it("uses only the three narrow commands and immutable inputs", async () => {
    const workspace = { taskId: "task-1" };
    const context = { packageId: "context-1" };
    const resolution = {
      approvalId: "approval-1",
      displayedDigest: `sha256:${"a".repeat(64)}`,
      expectedTaskVersion: 9,
      action: "approve" as const,
    };

    await getDeliberationWorkspace(workspace);
    await getContextPackage(context);
    await resolvePlanApproval(resolution);

    expect(invoke.mock.calls).toEqual([
      ["get_deliberation_workspace", { request: workspace }],
      ["get_context_package", { request: context }],
      ["resolve_plan_approval", { request: resolution }],
    ]);
  });

  it("rejects replacement payloads before invoking a privileged command", () => {
    expect(() =>
      getDeliberationWorkspace({
        taskId: "task-1",
        workflow: { phase: "Implementation" },
      } as unknown as GetDeliberationWorkspaceRequestDto),
    ).toThrow("exactly: taskId");
    expect(() =>
      getContextPackage({
        packageId: "context-1",
        physicalPath: "D:\\repo\\secret.txt",
      } as unknown as GetContextPackageRequestDto),
    ).toThrow("exactly: packageId");
    expect(() =>
      resolvePlanApproval({
        approvalId: "approval-1",
        displayedDigest: `sha256:${"a".repeat(64)}`,
        expectedTaskVersion: 9,
        action: "approve",
        rawPlan: { tools: ["shell"] },
      } as unknown as ResolvePlanApprovalRequestDto),
    ).toThrow(
      "exactly: approvalId, displayedDigest, expectedTaskVersion, action",
    );
    for (const forbidden of [
      "providerPayload",
      "policy",
      "physicalPath",
      "event",
      "tool",
      "workflow",
    ]) {
      expect(() =>
        resolvePlanApproval({
          approvalId: "approval-1",
          displayedDigest: `sha256:${"a".repeat(64)}`,
          expectedTaskVersion: 9,
          action: "approve",
          [forbidden]: "untrusted",
        } as unknown as ResolvePlanApprovalRequestDto),
      ).toThrow("exactly: approvalId, displayedDigest, expectedTaskVersion, action");
    }
    expect(invoke).not.toHaveBeenCalled();
  });

  it("rejects malformed IDs, digest, task version, and action", () => {
    expect(() => getDeliberationWorkspace({ taskId: "../task" })).toThrow();
    expect(() => getContextPackage({ packageId: "context/1" })).toThrow();
    expect(() =>
      resolvePlanApproval({
        approvalId: "approval-1",
        displayedDigest: "not-a-digest",
        expectedTaskVersion: 9,
        action: "approve",
      }),
    ).toThrow();
    expect(() =>
      resolvePlanApproval({
        approvalId: "approval-1",
        displayedDigest: `sha256:${"a".repeat(64)}`,
        expectedTaskVersion: 0,
        action: "approve",
      }),
    ).toThrow();
    expect(() =>
      resolvePlanApproval({
        approvalId: "approval-1",
        displayedDigest: `sha256:${"a".repeat(64)}`,
        expectedTaskVersion: 9,
        action: "replace" as "approve",
      }),
    ).toThrow();
    expect(invoke).not.toHaveBeenCalled();
  });
});
