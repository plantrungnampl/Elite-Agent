import * as axe from "axe-core";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { DeliberationWorkspaceDto } from "../../api/deliberation";
import { DeliberationScreen } from "./DeliberationScreen";

const deliberationApi = vi.hoisted(() => ({
  getDeliberationWorkspace: vi.fn(),
  getContextPackage: vi.fn(),
  resolvePlanApproval: vi.fn(),
}));

vi.mock("../../api/deliberation", () => deliberationApi);

describe("DeliberationScreen", () => {
  beforeEach(() => {
    deliberationApi.getDeliberationWorkspace
      .mockReset()
      .mockResolvedValue(workspaceFixture());
    deliberationApi.getContextPackage.mockReset();
    deliberationApi.resolvePlanApproval.mockReset();
  });

  it("renders the workflow, roster, structured room, bounded thread, evidence, and approval", async () => {
    const { container } = render(
      <DeliberationScreen initialTaskId="task-1" pollIntervalMs={0} />,
    );

    expect(
      await screen.findByRole("heading", { level: 1, name: "Deliberation workspace" }),
    ).toBeVisible();
    expect(screen.getByRole("heading", { name: "Workflow" })).toBeVisible();
    expect(screen.getByText("Awaiting plan approval")).toBeVisible();
    expect(screen.getByRole("heading", { name: "Agent roster" })).toBeVisible();
    expect(screen.getByText("Cloud agent", { exact: true })).toBeVisible();
    expect(screen.getByText("Trusted core adapter")).toBeVisible();
    expect(screen.getByText("Sandbox enforced")).toBeVisible();
    for (const label of ["Proposal", "Review", "Evidence", "Objection", "Decision"]) {
      expect(screen.getAllByText(label, { exact: true })[0]).toBeVisible();
    }
    expect(screen.getAllByText("Stale evidence", { exact: false })[0]).toBeVisible();
    expect(screen.getByText("Thread is bounded; older messages are summarized.")).toBeVisible();
    expect(screen.getByRole("heading", { name: "Plan approval" })).toBeVisible();
    expect(screen.getByText(`sha256:${"a".repeat(64)}`)).toBeVisible();

    const result = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(result.violations).toEqual([]);
  });

  it("shows loading, empty, blocked, and rejected states without converting uncertainty", async () => {
    deliberationApi.getDeliberationWorkspace.mockReturnValueOnce(
      new Promise(() => undefined),
    );
    const loading = render(
      <DeliberationScreen initialTaskId="task-1" pollIntervalMs={0} />,
    );
    expect(screen.getByRole("main")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading authoritative deliberation state",
    );
    loading.unmount();

    deliberationApi.getDeliberationWorkspace.mockResolvedValueOnce({
      ...workspaceFixture(),
      agents: [],
      cards: [],
      thread: null,
      evidence: [],
      approval: null,
    });
    const empty = render(
      <DeliberationScreen initialTaskId="task-1" pollIntervalMs={0} />,
    );
    expect(await screen.findByText("No agents assigned.")).toBeVisible();
    expect(screen.getByText("No shared-room records.")).toBeVisible();
    expect(screen.getByText("No plan approval requested.")).toBeVisible();
    empty.unmount();

    deliberationApi.getDeliberationWorkspace.mockResolvedValueOnce({
      ...workspaceFixture(),
      availability: "blocked",
      statusMessage: "A severe objection blocks synthesis.",
      approval: { ...workspaceFixture().approval!, status: "rejected" },
    });
    render(<DeliberationScreen initialTaskId="task-1" pollIntervalMs={0} />);
    expect(await screen.findByText("Blocked", { exact: true })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "A severe objection blocks synthesis.",
    );
    expect(screen.getAllByText("Plan rejected", { exact: true })[0]).toBeVisible();
  });

  it("offers a recoverable retry after authoritative state is unavailable", async () => {
    const user = userEvent.setup();
    deliberationApi.getDeliberationWorkspace
      .mockRejectedValueOnce({
        code: "deliberation_runtime_unavailable",
        message: "Authoritative deliberation state is unavailable.",
        retryable: true,
      })
      .mockResolvedValueOnce(workspaceFixture());
    render(<DeliberationScreen initialTaskId="task-1" pollIntervalMs={0} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Authoritative deliberation state is unavailable.",
    );
    await user.click(screen.getByRole("button", { name: "Retry deliberation load" }));
    expect(
      await screen.findByText(/Authoritative state loaded\. Phase AwaitingPlanApproval\./),
    ).toBeVisible();
    expect(deliberationApi.getDeliberationWorkspace).toHaveBeenCalledTimes(2);
  });
});

function workspaceFixture(): DeliberationWorkspaceDto {
  return {
    availability: "ready",
    taskId: "task-1",
    phase: "AwaitingPlanApproval",
    taskVersion: 9,
    statusMessage: "Authoritative state loaded",
    workflow: [
      {
        phaseId: "proposal",
        label: "Independent proposals",
        state: "completed",
        detail: "Two proposals recorded",
        retryCount: 0,
        approvalGate: false,
      },
      {
        phaseId: "approval",
        label: "Awaiting plan approval",
        state: "current",
        detail: "Digest-bound user decision required",
        retryCount: 1,
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
    cards: (["proposal", "review", "evidence", "objection", "decision"] as const).map(
      (kind, index) => ({
        cardId: `card-${index}`,
        kind,
        title: `${kind} record`,
        summary: `${kind} summary`,
        actorId: index === 4 ? "core" : "agent-cloud",
        evidenceState: kind === "evidence" ? "verified" : "unverified",
        stale: kind === "evidence",
        artifactIds: [`artifact-${index}`],
      }),
    ),
    thread: {
      threadId: "thread-1",
      summary: "Reviewers converged after one bounded round.",
      messages: [
        { messageId: "message-1", actorId: "agent-cloud", body: "Check the rollback." },
      ],
      truncated: true,
    },
    evidence: [
      {
        artifactId: "artifact-evidence",
        label: "Focused test output",
        pathIdentity: "crates/application/tests/plan.rs",
        lineRange: { start: 10, end: 18 },
        state: "verified",
        freshness: "stale",
      },
    ],
    approval: {
      approvalId: "approval-1",
      taskId: "task-1",
      status: "requested",
      selectedApproachId: "approach-a",
      selectedApproachLabel: "Use the typed application boundary",
      rejectedAlternatives: [
        { approachId: "approach-b", label: "Direct database access", reason: "Leaks storage" },
      ],
      agreement: [
        { agentId: "agent-cloud", position: "agree", summary: "Boundary is narrow" },
      ],
      unresolvedObjections: ["Confirm recovery behavior"],
      affectedFiles: ["apps/desktop/src/api/deliberation.ts"],
      plannedTools: ["cargo test", "pnpm test"],
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
