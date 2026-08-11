import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  getDeliberationWorkspace,
  type AgentRosterEntryDto,
  type DeliberationCardDto,
  type DeliberationWorkspaceDto,
  type EvidenceItemDto,
} from "../../api/deliberation";
import { ContextInspector } from "./ContextInspector";
import {
  availabilityLabel,
  cardKindLabel,
  commandErrorMessage,
  evidenceStateLabel,
} from "./deliberation-model";
import { PlanApprovalPanel } from "./PlanApprovalPanel";

interface DeliberationScreenProps {
  initialTaskId?: string;
  pollIntervalMs?: number;
}

interface OpenContext {
  packageId: string;
  trigger: HTMLButtonElement;
}

export function DeliberationScreen({
  initialTaskId = "",
  pollIntervalMs = 5_000,
}: DeliberationScreenProps) {
  const [taskId, setTaskId] = useState(initialTaskId);
  const [workspace, setWorkspace] = useState<DeliberationWorkspaceDto | null>(null);
  const [loading, setLoading] = useState(initialTaskId !== "");
  const [error, setError] = useState<string | null>(null);
  const [openContext, setOpenContext] = useState<OpenContext | null>(null);
  const statusHeading = useRef<HTMLHeadingElement>(null);
  const requestGeneration = useRef(0);

  const loadWorkspace = useCallback(async (requestedTaskId: string, focusStatus = false) => {
    const normalizedTaskId = requestedTaskId.trim();
    if (normalizedTaskId === "") {
      setWorkspace(null);
      setError("Enter an opaque task ID.");
      return;
    }
    const generation = ++requestGeneration.current;
    setLoading(true);
    setError(null);
    try {
      const nextWorkspace = await getDeliberationWorkspace({ taskId: normalizedTaskId });
      if (nextWorkspace.taskId !== normalizedTaskId) {
        throw new Error("Deliberation workspace does not belong to the requested task.");
      }
      if (generation === requestGeneration.current) {
        setWorkspace(nextWorkspace);
        setTaskId(normalizedTaskId);
      }
    } catch (cause) {
      if (generation === requestGeneration.current) {
        setWorkspace(null);
        setError(
          commandErrorMessage(cause, "Authoritative deliberation state is unavailable."),
        );
      }
    } finally {
      if (generation === requestGeneration.current) {
        setLoading(false);
        if (focusStatus) {
          statusHeading.current?.focus();
        }
      }
    }
  }, []);

  useEffect(() => {
    if (initialTaskId !== "") {
      void loadWorkspace(initialTaskId);
    }
  }, [initialTaskId, loadWorkspace]);

  useEffect(() => {
    if (workspace === null || pollIntervalMs <= 0) {
      return;
    }
    const activeTaskId = workspace.taskId;
    const interval = window.setInterval(() => {
      void loadWorkspace(activeTaskId);
    }, pollIntervalMs);
    return () => window.clearInterval(interval);
  }, [loadWorkspace, pollIntervalMs, workspace?.taskId]);

  async function handleLoad(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    await loadWorkspace(String(data.get("taskId") ?? ""), true);
  }

  function closeContextInspector() {
    const trigger = openContext?.trigger ?? null;
    setOpenContext(null);
    window.queueMicrotask(() => trigger?.focus());
  }

  const statusText = loading
    ? "Loading authoritative deliberation state"
    : error !== null
      ? "Deliberation state unavailable"
      : workspace === null
        ? "No task loaded"
        : `${workspace.statusMessage}. Phase ${workspace.phase}.`;

  return (
    <>
      <header className="app-header">
        <div className="shell">
          <p className="product-name">Local Agent Terminal</p>
          <p className="product-scope">Context and deliberation control</p>
        </div>
      </header>
      <main
        className="shell deliberation-layout"
        id="deliberation-main"
        tabIndex={-1}
        aria-busy={loading}
      >
        <h1>Deliberation workspace</h1>
        <p className="lede">
          Inspect bounded agent deliberation, immutable context, evidence, and exact plan
          approval authority.
        </p>

        <form className="compact-form task-load-form" onSubmit={handleLoad}>
          <label>
            Task ID
            <input name="taskId" defaultValue={initialTaskId} autoComplete="off" required />
          </label>
          <button type="submit" disabled={loading}>Load deliberation</button>
          <button
            className="secondary-button"
            type="button"
            disabled={loading || taskId === ""}
            onClick={() => void loadWorkspace(taskId, true)}
          >
            Refresh deliberation
          </button>
        </form>

        <section className="status-panel deliberation-status" aria-labelledby="deliberation-status">
          <h2 id="deliberation-status" ref={statusHeading} tabIndex={-1}>
            Deliberation status
          </h2>
          <p role="status" aria-live="polite" aria-atomic="true" className="status-label">
            <span className="status-symbol" aria-hidden="true">
              {loading ? "…" : error !== null ? "!" : workspace === null ? "?" : "✓"}
            </span>
            {statusText}
          </p>
          {error !== null ? (
            <div className="error-panel" role="alert">
              <p>{error}</p>
              {taskId !== "" ? (
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => void loadWorkspace(taskId, true)}
                >
                  Retry deliberation load
                </button>
              ) : null}
            </div>
          ) : null}
          {workspace?.availability === "blocked" ? (
            <p role="alert">{workspace.statusMessage}</p>
          ) : null}
          {workspace !== null ? (
            <p>
              <span className={`state-pill state-${workspace.availability}`}>
                {availabilityLabel(workspace.availability)}
              </span>{" "}
              Phase {workspace.phase}; task version {workspace.taskVersion}
            </p>
          ) : null}
        </section>

        {workspace !== null ? (
          <WorkspaceContent
            workspace={workspace}
            onInspectContext={(packageId, trigger) => setOpenContext({ packageId, trigger })}
            onResolved={() => void loadWorkspace(workspace.taskId)}
          />
        ) : null}
      </main>

      {openContext !== null && workspace !== null ? (
        <ContextInspector
          packageId={openContext.packageId}
          expectedTaskId={workspace.taskId}
          onClose={closeContextInspector}
        />
      ) : null}
    </>
  );
}

function WorkspaceContent({
  workspace,
  onInspectContext,
  onResolved,
}: {
  workspace: DeliberationWorkspaceDto;
  onInspectContext: (packageId: string, trigger: HTMLButtonElement) => void;
  onResolved: () => void;
}) {
  return (
    <div className="deliberation-workspace-grid">
      <section className="panel workflow-panel" aria-labelledby="workflow-heading">
        <h2 id="workflow-heading">Workflow</h2>
        {workspace.workflow.length === 0 ? (
          <p>No workflow phases recorded.</p>
        ) : (
          <ol className="workflow-rail">
            {workspace.workflow.map((phase) => (
              <li key={phase.phaseId} className={`workflow-phase phase-${phase.state}`}>
                <div className="card-label-row">
                  <strong>{phase.label}</strong>
                  <span className={`state-pill state-${phase.state}`}>
                    {phase.state === "current"
                      ? "Current phase"
                      : phase.state === "completed"
                        ? "Completed"
                        : phase.state === "blocked"
                          ? "Blocked"
                          : "Pending"}
                  </span>
                </div>
                <p>{phase.detail}</p>
                <p>
                  Retries: {phase.retryCount}. Approval gate: {phase.approvalGate ? "Required" : "None"}.
                </p>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className="panel roster-panel" aria-labelledby="agent-roster-heading">
        <h2 id="agent-roster-heading">Agent roster</h2>
        {workspace.agents.length === 0 ? (
          <p>No agents assigned.</p>
        ) : (
          <ul className="agent-roster">
            {workspace.agents.map((agent) => (
              <AgentCard key={agent.agentId} agent={agent} onInspectContext={onInspectContext} />
            ))}
          </ul>
        )}
      </section>

      <section className="panel shared-room" aria-labelledby="shared-room-heading">
        <h2 id="shared-room-heading">Shared room</h2>
        {workspace.cards.length === 0 ? (
          <p>No shared-room records.</p>
        ) : (
          <ol className="deliberation-card-list">
            {workspace.cards.map((card) => (
              <DeliberationCard key={card.cardId} card={card} />
            ))}
          </ol>
        )}
      </section>

      <section className="panel thread-panel" aria-labelledby="thread-heading">
        <h2 id="thread-heading">Discussion thread</h2>
        {workspace.thread === null ? (
          <p>No bounded discussion thread.</p>
        ) : (
          <>
            <p>{workspace.thread.summary}</p>
            <ol className="thread-messages">
              {workspace.thread.messages.map((message) => (
                <li key={message.messageId}>
                  <strong>{message.actorId}</strong>: {message.body}
                </li>
              ))}
            </ol>
            {workspace.thread.truncated ? (
              <p className="state-note">Thread is bounded; older messages are summarized.</p>
            ) : null}
          </>
        )}
      </section>

      <section className="panel evidence-panel" aria-labelledby="evidence-heading">
        <h2 id="evidence-heading">Evidence</h2>
        {workspace.evidence.length === 0 ? (
          <p>No evidence records.</p>
        ) : (
          <ul className="evidence-list">
            {workspace.evidence.map((evidence) => (
              <EvidenceItem key={evidence.artifactId} evidence={evidence} />
            ))}
          </ul>
        )}
      </section>

      {workspace.approval === null ? (
        <section className="panel plan-approval-panel" aria-labelledby="plan-approval-empty">
          <h2 id="plan-approval-empty">Plan approval</h2>
          <p>No plan approval requested.</p>
        </section>
      ) : (
        <PlanApprovalPanel
          key={`${workspace.approval.approvalId}:${workspace.approval.operationDigest}:${workspace.approval.status}`}
          approval={workspace.approval}
          taskVersion={workspace.taskVersion}
          onResolved={onResolved}
        />
      )}
    </div>
  );
}

function AgentCard({
  agent,
  onInspectContext,
}: {
  agent: AgentRosterEntryDto;
  onInspectContext: (packageId: string, trigger: HTMLButtonElement) => void;
}) {
  return (
    <li className="agent-card">
      <div className="card-label-row">
        <h3>{agent.agentId}</h3>
        <span className="state-pill">
          {agent.locality === "cloud" ? "☁ Cloud agent" : "⌂ Local agent"}
        </span>
      </div>
      <dl className="detail-grid compact-details">
        <Detail label="Role" value={agent.role} />
        <Detail label="Provider / locality" value={agent.providerLabel} />
        <Detail label="Status" value={agent.status} />
        <Detail label="Context scope" value={agent.contextScope} />
        <Detail label="Token usage" value={String(agent.usedTokens)} />
        <Detail label="Cost" value={`${agent.costMicrounits.toLocaleString("en-US")} microunits`} />
        <Detail label="Health" value={agent.health} />
        <Detail label="Permissions" value={agent.permissions.join(", ") || "None"} />
        <Detail label="Trust tier" value={agent.trustTier} />
        <Detail label="Sandbox" value={agent.sandboxStatus} />
      </dl>
      {agent.identityChanged ? (
        <p role="alert" className="warning-panel">! Agent executable or manifest identity changed.</p>
      ) : null}
      {agent.contextPackageId !== null ? (
        <button
          className="secondary-button"
          type="button"
          onClick={(event) => onInspectContext(agent.contextPackageId!, event.currentTarget)}
        >
          Inspect context for {agent.agentId}
        </button>
      ) : (
        <p>No context package assigned.</p>
      )}
    </li>
  );
}

function DeliberationCard({ card }: { card: DeliberationCardDto }) {
  return (
    <li className={`deliberation-card card-${card.kind}`}>
      <div className="card-label-row">
        <span className="card-kind">{cardKindLabel(card.kind)}</span>
        <span className={`state-pill state-${card.evidenceState}`}>
          {evidenceStateLabel(card.evidenceState)}
        </span>
        {card.stale ? <span className="state-pill state-stale">! Stale evidence</span> : null}
      </div>
      <h3>{card.title}</h3>
      <p>{card.summary}</p>
      <p>Actor: {card.actorId}</p>
      <p>Artifacts: {card.artifactIds.join(", ") || "None"}</p>
    </li>
  );
}

function EvidenceItem({ evidence }: { evidence: EvidenceItemDto }) {
  const range =
    evidence.lineRange === null
      ? "Whole source"
      : `Lines ${evidence.lineRange.start}–${evidence.lineRange.end}`;
  return (
    <li>
      <div className="card-label-row">
        <strong>{evidence.label}</strong>
        <span className={`state-pill state-${evidence.state}`}>
          {evidenceStateLabel(evidence.state)}
        </span>
        <span className={`state-pill state-${evidence.freshness}`}>
          {evidence.freshness === "stale" ? "! Stale evidence" : "✓ Current evidence"}
        </span>
      </div>
      <p>{evidence.pathIdentity}; {range}; artifact {evidence.artifactId}</p>
    </li>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}
