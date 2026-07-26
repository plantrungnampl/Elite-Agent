import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  createTaskWorkspace,
  discardWorkspace,
  getWorkspaceDashboard,
  onboardRepository,
  preserveWorkspace,
  reconcileWorkspace,
} from "./workspace";

describe("workspace Tauri API", () => {
  beforeEach(() => {
    invoke.mockReset().mockResolvedValue({});
  });

  it("uses only the six typed workspace commands", async () => {
    const dashboard = { projectId: "project-1" };
    const onboard = {
      projectId: "project-1",
      name: "Project",
      repositoryPath: "D:\\repo",
    };
    const task = {
      projectId: "project-1",
      taskId: "task-1",
      title: "Task",
      objective: "Objective",
      riskLevel: "low" as const,
    };
    const recovery = {
      candidateId: "candidate-1",
      projectId: "project-1",
      taskId: "task-1",
      expectedWorkspaceVersion: 2,
    };

    await getWorkspaceDashboard(dashboard);
    await onboardRepository(onboard);
    await createTaskWorkspace(task);
    await reconcileWorkspace(recovery);
    await preserveWorkspace(recovery);
    await discardWorkspace({ ...recovery, confirmed: true });

    expect(invoke.mock.calls).toEqual([
      ["get_workspace_dashboard", { request: dashboard }],
      ["onboard_repository", { request: onboard }],
      ["create_task_workspace", { request: task }],
      ["reconcile_workspace", { request: recovery }],
      ["preserve_workspace", { request: recovery }],
      ["discard_workspace", {
        request: { ...recovery, confirmed: true },
      }],
    ]);
  });
});
