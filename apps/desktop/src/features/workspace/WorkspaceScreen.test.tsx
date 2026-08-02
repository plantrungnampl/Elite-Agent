import * as axe from "axe-core";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { WorkspaceDashboardDto } from "../../api/workspace";
import { WorkspaceScreen } from "./WorkspaceScreen";

const workspaceApi = vi.hoisted(() => ({
  getWorkspaceDashboard: vi.fn(),
  onboardRepository: vi.fn(),
  createTaskWorkspace: vi.fn(),
  reconcileWorkspace: vi.fn(),
  preserveWorkspace: vi.fn(),
  discardWorkspace: vi.fn(),
}));

vi.mock("../../api/workspace", () => workspaceApi);

describe("WorkspaceScreen", () => {
  beforeEach(() => {
    const dashboard = dashboardFixture();
    workspaceApi.getWorkspaceDashboard.mockReset().mockResolvedValue(dashboard);
    workspaceApi.onboardRepository.mockReset();
    workspaceApi.createTaskWorkspace.mockReset();
    workspaceApi.reconcileWorkspace.mockReset().mockResolvedValue(dashboard);
    workspaceApi.preserveWorkspace.mockReset().mockResolvedValue(dashboard);
    workspaceApi.discardWorkspace.mockReset().mockResolvedValue(dashboard);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows honest loading and indeterminate IPC failure states", async () => {
    workspaceApi.getWorkspaceDashboard.mockReturnValueOnce(
      new Promise(() => undefined),
    );
    const { unmount } = render(
      <WorkspaceScreen initialProjectId="project-1" />,
    );

    expect(screen.getByRole("main")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading authoritative workspace state",
    );
    expect(screen.queryByText("Ready for isolated tasks")).not.toBeInTheDocument();

    unmount();
    workspaceApi.getWorkspaceDashboard.mockRejectedValueOnce({
      code: "unavailable",
      message: "Authoritative state is unavailable.",
      retryable: false,
    });
    render(<WorkspaceScreen initialProjectId="project-1" />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Authoritative state is unavailable.",
    );
    expect(screen.getByRole("status")).toHaveTextContent("No project loaded");
  });

  it("renders repository, exact worktree, dirty fencing, timeline, and hostile text as data", async () => {
    render(<WorkspaceScreen initialProjectId="project-1" />);

    expect(
      await screen.findByRole("heading", {
        level: 2,
        name: "Repository health",
      }),
    ).toBeVisible();
    expect(screen.getByText("main")).toBeVisible();
    expect(screen.getAllByText("a".repeat(40)).length).toBeGreaterThan(0);
    expect(screen.getByText("Workspace dirty")).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent("WorkspaceDirty");
    expect(screen.getByText("revoked")).toBeVisible();

    await userEvent.click(screen.getByText("Exact worktree"));
    expect(screen.getByText("<managed-workspace>/worktree-task-1")).toBeVisible();
    expect(screen.getByText("codex/task-1")).toBeVisible();

    await userEvent.click(screen.getByText("Timeline (1)"));
    expect(
      screen.getAllByText("<script>alert('timeline')</script>").length,
    ).toBeGreaterThan(0);
    expect(document.querySelector("script")).toBeNull();
    expect(screen.getByText("2026-07-26T00:00:00Z").tagName).toBe("TIME");
  });

  it("blocks task creation for unsafe repository state", async () => {
    const dashboard = dashboardFixture();
    dashboard.repository.health = "unsafe";
    dashboard.repository.hazards = [
      { reason: "hooks_configured", detail: "Unsafe hook configuration" },
    ];
    workspaceApi.getWorkspaceDashboard.mockResolvedValue(dashboard);
    render(<WorkspaceScreen initialProjectId="project-1" />);

    await screen.findByText("Task creation blocked");
    await userEvent.click(
      screen.getByText("Create an isolated task workspace"),
    );
    expect(
      screen.getByRole("button", { name: "Create task workspace" }),
    ).toBeDisabled();
    expect(screen.getByText("hooks_configured")).toBeVisible();
  });

  it("refreshes authoritative workspace state while the dashboard is open", async () => {
    vi.useFakeTimers();
    const initial = dashboardFixture();
    initial.tasks[0].phase = "Implementation";
    initial.tasks[0].leaseState = "active";
    const refreshed = dashboardFixture();
    refreshed.tasks[0].phase = "WorkspaceDirty";
    refreshed.tasks[0].leaseState = "revoked";
    workspaceApi.getWorkspaceDashboard
      .mockResolvedValueOnce(initial)
      .mockResolvedValue(refreshed);
    render(<WorkspaceScreen initialProjectId="project-1" />);
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByText("Workspace dirty")).not.toBeInTheDocument();

    await act(async () => {
      vi.advanceTimersByTime(5_000);
      await Promise.resolve();
    });

    expect(screen.getByText("Workspace dirty")).toBeVisible();
    expect(screen.getByText("revoked")).toBeVisible();
  });

  it("does not let an older poll overwrite a completed mutation", async () => {
    vi.useFakeTimers();
    const initial = dashboardFixture();
    const stalePoll = deferred<WorkspaceDashboardDto>();
    const mutationResult = dashboardFixture();
    mutationResult.tasks[0].title = "Fresh mutation result";
    const staleResult = dashboardFixture();
    staleResult.tasks[0].title = "Stale poll result";
    workspaceApi.getWorkspaceDashboard
      .mockResolvedValueOnce(initial)
      .mockReturnValueOnce(stalePoll.promise);
    workspaceApi.preserveWorkspace.mockResolvedValueOnce(mutationResult);
    render(<WorkspaceScreen initialProjectId="project-1" />);
    await act(async () => {
      await Promise.resolve();
    });

    await act(async () => {
      vi.advanceTimersByTime(5_000);
      await Promise.resolve();
    });
    expect(workspaceApi.getWorkspaceDashboard).toHaveBeenCalledTimes(2);

    act(() => {
      screen.getByRole("button", { name: "Preserve workspace" }).click();
    });
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.getAllByText("Fresh mutation result").length).toBeGreaterThan(
      0,
    );

    await act(async () => {
      stalePoll.resolve(staleResult);
      await stalePoll.promise;
    });

    expect(screen.queryByText("Stale poll result")).not.toBeInTheDocument();
    expect(screen.getAllByText("Fresh mutation result").length).toBeGreaterThan(
      0,
    );
  });

  it("renders only core recovery actions, guards double submit, confirms discard, and restores focus", async () => {
    const preserve = deferred<WorkspaceDashboardDto>();
    workspaceApi.preserveWorkspace.mockReturnValue(preserve.promise);
    render(<WorkspaceScreen initialProjectId="project-1" />);
    const preserveButton = await screen.findByRole("button", {
      name: "Preserve workspace",
    });

    expect(
      screen.queryByRole("button", { name: /retry/i }),
    ).not.toBeInTheDocument();
    act(() => {
      preserveButton.click();
      preserveButton.click();
    });
    expect(workspaceApi.preserveWorkspace).toHaveBeenCalledTimes(1);
    expect(preserveButton).toBeDisabled();

    await act(async () => {
      preserve.resolve(dashboardFixture());
      await preserve.promise;
    });
    expect(
      screen.getByRole("heading", { level: 2, name: "Workspace status" }),
    ).toHaveFocus();

    const discardButton = screen.getByRole("button", {
      name: "Discard exact worktree",
    });
    expect(discardButton).toBeDisabled();
    await userEvent.click(
      screen.getByRole("checkbox", {
        name: "Confirm discard of this exact managed worktree",
      }),
    );
    expect(discardButton).toBeEnabled();
    await userEvent.click(discardButton);
    expect(workspaceApi.discardWorkspace).toHaveBeenCalledWith({
      candidateId: "candidate-discard",
      projectId: "project-1",
      taskId: "task-1",
      expectedWorkspaceVersion: 3,
      confirmed: true,
    });
  });

  it("uses semantic landmarks, native controls, and has no obvious axe violations", async () => {
    const { container } = render(
      <WorkspaceScreen initialProjectId="project-1" />,
    );
    await screen.findByRole("heading", {
      level: 2,
      name: "Repository health",
    });

    expect(screen.getByRole("banner")).toBeVisible();
    expect(screen.getByRole("main")).toHaveAttribute("id", "workspace-main");
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.getAllByRole("definition").length).toBeGreaterThan(0);
    expect(container.querySelector("ol")).not.toBeNull();
    expect(container.querySelector("time")).not.toBeNull();
    expect(container.querySelector("details")).not.toBeNull();

    const result = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(result.violations).toEqual([]);
  });
});

function dashboardFixture(): WorkspaceDashboardDto {
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
      stableIdentity: "repository-identity",
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
        title: "<script>alert('timeline')</script>",
        objective: "Preserve recovery evidence",
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
            summary: "<script>alert('timeline')</script>",
            evidence: {
              artifactId: "artifact-1",
              contentHash: `sha256:${"d".repeat(64)}`,
              sizeBytes: 2,
            },
          },
        ],
      },
    ],
    recovery: [],
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}
