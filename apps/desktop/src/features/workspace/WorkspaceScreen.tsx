import {
  type FormEvent,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  createTaskWorkspace,
  discardWorkspace,
  getWorkspaceDashboard,
  onboardRepository,
  preserveWorkspace,
  reconcileWorkspace,
} from "../../api/workspace";
import type {
  RecoveryActionDto,
  RecoveryCandidateDto,
  RepositorySnapshotDto,
  TaskSnapshotDto,
  WorkspaceDashboardDto,
} from "../../api/workspace";
import {
  canCreateTask,
  recoveryRequest,
  taskStatus,
} from "./workspace-model";

interface WorkspaceScreenProps {
  initialProjectId?: string;
}

export function WorkspaceScreen({
  initialProjectId = "",
}: WorkspaceScreenProps) {
  const [projectId, setProjectId] = useState(initialProjectId);
  const [dashboard, setDashboard] = useState<WorkspaceDashboardDto | null>(
    null,
  );
  const [loading, setLoading] = useState(initialProjectId !== "");
  const [error, setError] = useState<string | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const statusHeading = useRef<HTMLHeadingElement>(null);
  const mutationInFlight = useRef(false);
  const refreshInFlight = useRef(false);
  const dashboardGeneration = useRef(0);

  useEffect(() => {
    if (initialProjectId === "") {
      return;
    }
    const generation = ++dashboardGeneration.current;
    let active = true;
    getWorkspaceDashboard({ projectId: initialProjectId })
      .then((nextDashboard) => {
        if (active && generation === dashboardGeneration.current) {
          setDashboard(nextDashboard);
          setError(null);
        }
      })
      .catch((cause: unknown) => {
        if (active && generation === dashboardGeneration.current) {
          setError(commandErrorMessage(cause));
        }
      })
      .finally(() => {
        if (active && generation === dashboardGeneration.current) {
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [initialProjectId]);

  useEffect(() => {
    if (dashboard === null) {
      return;
    }
    let active = true;
    const activeProjectId = dashboard.projectId;
    const interval = window.setInterval(() => {
      if (mutationInFlight.current || refreshInFlight.current) {
        return;
      }
      refreshInFlight.current = true;
      const generation = dashboardGeneration.current;
      void getWorkspaceDashboard({ projectId: activeProjectId })
        .then((nextDashboard) => {
          if (
            active &&
            !mutationInFlight.current &&
            generation === dashboardGeneration.current
          ) {
            setDashboard(nextDashboard);
            setError(null);
          }
        })
        .catch((cause: unknown) => {
          if (active && generation === dashboardGeneration.current) {
            setError(commandErrorMessage(cause));
          }
        })
        .finally(() => {
          refreshInFlight.current = false;
        });
    }, 5_000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [dashboard?.projectId]);

  async function loadProject(nextProjectId: string) {
    if (mutationInFlight.current) {
      return;
    }
    mutationInFlight.current = true;
    dashboardGeneration.current += 1;
    setLoading(true);
    setError(null);
    try {
      setDashboard(
        await getWorkspaceDashboard({ projectId: nextProjectId.trim() }),
      );
      setProjectId(nextProjectId.trim());
    } catch (cause) {
      setDashboard(null);
      setError(commandErrorMessage(cause));
    } finally {
      mutationInFlight.current = false;
      setLoading(false);
      statusHeading.current?.focus();
    }
  }

  async function handleProjectLoad(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    await loadProject(String(data.get("projectId") ?? ""));
  }

  async function handleOnboard(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (mutationInFlight.current) {
      return;
    }
    const form = event.currentTarget;
    const data = new FormData(form);
    const request = {
      projectId: String(data.get("projectId") ?? "").trim(),
      name: String(data.get("name") ?? "").trim(),
      repositoryPath: String(data.get("repositoryPath") ?? "").trim(),
    };
    mutationInFlight.current = true;
    dashboardGeneration.current += 1;
    setBusyKey("onboard");
    setError(null);
    try {
      const project = await onboardRepository(request);
      setProjectId(project.projectId);
      setDashboard(
        await getWorkspaceDashboard({ projectId: project.projectId }),
      );
      form.reset();
    } catch (cause) {
      setError(commandErrorMessage(cause));
    } finally {
      mutationInFlight.current = false;
      setBusyKey(null);
      statusHeading.current?.focus();
    }
  }

  async function handleCreateTask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      mutationInFlight.current ||
      dashboard === null ||
      !canCreateTask(dashboard.repository)
    ) {
      return;
    }
    const form = event.currentTarget;
    const data = new FormData(form);
    mutationInFlight.current = true;
    dashboardGeneration.current += 1;
    setBusyKey("create-task");
    setError(null);
    try {
      await createTaskWorkspace({
        projectId: dashboard.projectId,
        taskId: String(data.get("taskId") ?? "").trim(),
        title: String(data.get("title") ?? "").trim(),
        objective: String(data.get("objective") ?? "").trim(),
        riskLevel: String(data.get("riskLevel") ?? "low") as
          | "low"
          | "medium"
          | "high"
          | "critical",
      });
      setDashboard(
        await getWorkspaceDashboard({ projectId: dashboard.projectId }),
      );
      form.reset();
    } catch (cause) {
      setError(commandErrorMessage(cause));
    } finally {
      mutationInFlight.current = false;
      setBusyKey(null);
      statusHeading.current?.focus();
    }
  }

  async function handleRecovery(
    action: RecoveryActionDto,
    candidate: RecoveryCandidateDto,
    confirmed: boolean,
  ) {
    if (mutationInFlight.current || dashboard === null) {
      return;
    }
    mutationInFlight.current = true;
    dashboardGeneration.current += 1;
    setBusyKey(`${candidate.candidateId}:${action.code}`);
    setError(null);
    const request = recoveryRequest(dashboard.projectId, candidate);
    try {
      const nextDashboard =
        action.code === "reconcile"
          ? await reconcileWorkspace(request)
          : action.code === "preserve"
            ? await preserveWorkspace(request)
            : confirmed
              ? await discardWorkspace({ ...request, confirmed: true })
              : null;
      if (nextDashboard !== null) {
        setDashboard(nextDashboard);
      }
    } catch (cause) {
      setError(commandErrorMessage(cause));
    } finally {
      mutationInFlight.current = false;
      setBusyKey(null);
      statusHeading.current?.focus();
    }
  }

  const stateLabel = loading
    ? "Loading authoritative workspace state"
    : dashboard === null
      ? "No project loaded"
      : "Authoritative workspace state loaded";

  return (
    <>
      <header className="app-header">
        <div className="shell">
          <p className="product-name">Local Agent Terminal</p>
          <p className="product-scope">Workspace recovery</p>
        </div>
      </header>
      <main
        className="shell workspace-layout"
        id="workspace-main"
        tabIndex={-1}
        aria-busy={loading}
      >
        <h1>Workspace recovery</h1>
        <p className="lede">
          Inspect repository state, isolated task worktrees, and recovery
          evidence.
        </p>

        <section
          className="status-panel workspace-status"
          aria-labelledby="workspace-status-heading"
        >
          <h2
            id="workspace-status-heading"
            ref={statusHeading}
            tabIndex={-1}
          >
            Workspace status
          </h2>
          <p role="status" aria-live="polite" aria-atomic="true">
            <span className="status-symbol" aria-hidden="true">
              {loading ? "…" : dashboard === null ? "?" : "✓"}
            </span>{" "}
            {stateLabel}
          </p>
          {error === null ? null : (
            <p className="error-message" role="alert">
              <span aria-hidden="true">!</span> {error}
            </p>
          )}

          <form className="compact-form" onSubmit={handleProjectLoad}>
            <label htmlFor="load-project-id">Project ID</label>
            <input
              id="load-project-id"
              name="projectId"
              value={projectId}
              onChange={(event) => setProjectId(event.currentTarget.value)}
              required
              maxLength={128}
            />
            <button type="submit" disabled={loading || busyKey !== null}>
              Load project
            </button>
          </form>
        </section>

        <details className="panel onboarding-panel">
          <summary>Onboard a local repository</summary>
          <form className="stacked-form" onSubmit={handleOnboard}>
            <label htmlFor="onboard-project-id">Project ID</label>
            <input
              id="onboard-project-id"
              name="projectId"
              required
              maxLength={128}
            />
            <label htmlFor="project-name">Project name</label>
            <input id="project-name" name="name" required maxLength={200} />
            <label htmlFor="repository-path">Repository path</label>
            <input
              id="repository-path"
              name="repositoryPath"
              required
              maxLength={32767}
            />
            <button type="submit" disabled={busyKey !== null}>
              {busyKey === "onboard"
                ? "Inspecting repository…"
                : "Onboard repository"}
            </button>
          </form>
        </details>

        {dashboard === null ? null : (
          <>
            <RepositorySummary repository={dashboard.repository} />
            <TaskCreationForm
              repository={dashboard.repository}
              busy={busyKey !== null}
              onSubmit={handleCreateTask}
            />
            <section
              className="workspace-section"
              aria-labelledby="task-workspaces-heading"
            >
              <h2 id="task-workspaces-heading">Task workspaces</h2>
              {dashboard.tasks.length === 0 ? (
                <p>No task workspaces exist for this project.</p>
              ) : (
                <ol className="task-list">
                  {dashboard.tasks.map((task) => (
                    <li key={task.taskId}>
                      <TaskCard
                        task={task}
                        busyKey={busyKey}
                        onRecovery={handleRecovery}
                      />
                    </li>
                  ))}
                </ol>
              )}
            </section>
          </>
        )}
      </main>
    </>
  );
}

function RepositorySummary({
  repository,
}: {
  repository: RepositorySnapshotDto;
}) {
  const safe = canCreateTask(repository);
  return (
    <section
      className="panel workspace-section"
      aria-labelledby="repository-health-heading"
    >
      <h2 id="repository-health-heading">Repository health</h2>
      <p className="state-line" data-safe={safe}>
        <span aria-hidden="true">{safe ? "✓" : "!"}</span>{" "}
        {safe ? "Ready for isolated tasks" : "Task creation blocked"}
      </p>
      <dl className="summary-list">
        <div>
          <dt>Health</dt>
          <dd>{repository.health}</dd>
        </div>
        <div>
          <dt>Default branch</dt>
          <dd>{repository.defaultBranch ?? "Unavailable"}</dd>
        </div>
        <div>
          <dt>Base commit</dt>
          <dd>
            <code>{repository.baseCommit ?? "Unavailable"}</code>
          </dd>
        </div>
        <div>
          <dt>Original checkout</dt>
          <dd>{repository.originalCheckout}</dd>
        </div>
      </dl>
      {repository.hazards.length === 0 ? null : (
        <>
          <h3>Blocking hazards</h3>
          <ul>
            {repository.hazards.map((hazard) => (
              <li key={`${hazard.reason}:${hazard.detail}`}>
                <strong>{hazard.reason}</strong>: {hazard.detail}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function TaskCreationForm({
  repository,
  busy,
  onSubmit,
}: {
  repository: RepositorySnapshotDto;
  busy: boolean;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const enabled = canCreateTask(repository);
  return (
    <details className="panel workspace-section">
      <summary>Create an isolated task workspace</summary>
      {enabled ? null : (
        <p role="alert">
          <span aria-hidden="true">!</span> Resolve repository health and
          hazards before creating a task.
        </p>
      )}
      <form className="stacked-form" onSubmit={onSubmit}>
        <label htmlFor="task-id">Task ID</label>
        <input id="task-id" name="taskId" required maxLength={128} />
        <label htmlFor="task-title">Title</label>
        <input id="task-title" name="title" required maxLength={200} />
        <label htmlFor="task-objective">Objective</label>
        <textarea
          id="task-objective"
          name="objective"
          required
          maxLength={4000}
        />
        <label htmlFor="task-risk">Risk</label>
        <select id="task-risk" name="riskLevel" defaultValue="low">
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
        <button type="submit" disabled={!enabled || busy}>
          Create task workspace
        </button>
      </form>
    </details>
  );
}

function TaskCard({
  task,
  busyKey,
  onRecovery,
}: {
  task: TaskSnapshotDto;
  busyKey: string | null;
  onRecovery: (
    action: RecoveryActionDto,
    candidate: RecoveryCandidateDto,
    confirmed: boolean,
  ) => Promise<void>;
}) {
  const status = taskStatus(task);
  return (
    <article className="task-card" aria-labelledby={`task-${task.taskId}`}>
      <h3 id={`task-${task.taskId}`}>{task.title}</h3>
      <p className="state-line">
        <span className="status-symbol" aria-hidden="true">
          {status.symbol}
        </span>{" "}
        {status.label}
      </p>
      {task.phase === "WorkspaceDirty" ? (
        <p className="dirty-warning" role="alert">
          <span aria-hidden="true">!</span> WorkspaceDirty: unexpected changes
          revoked the executor lease and require fresh verification.
        </p>
      ) : null}
      <dl className="summary-list">
        <div>
          <dt>Task ID</dt>
          <dd>{task.taskId}</dd>
        </div>
        <div>
          <dt>Workspace version</dt>
          <dd>{task.workspaceVersion}</dd>
        </div>
        <div>
          <dt>Fencing epoch</dt>
          <dd>{task.fencingEpoch}</dd>
        </div>
        <div>
          <dt>Executor lease</dt>
          <dd>{task.leaseState}</dd>
        </div>
      </dl>

      {task.worktree === null ? (
        <p>No worktree has been materialized.</p>
      ) : (
        <details>
          <summary>Exact worktree</summary>
          <dl className="summary-list">
            <div>
              <dt>Branch</dt>
              <dd>{task.worktree.branch}</dd>
            </div>
            <div>
              <dt>Base commit</dt>
              <dd>
                <code>{task.worktree.baseCommit}</code>
              </dd>
            </div>
            <div>
              <dt>Managed location</dt>
              <dd>{task.worktree.targetPathDisplay}</dd>
            </div>
            <div>
              <dt>State</dt>
              <dd>{task.worktree.state}</dd>
            </div>
          </dl>
        </details>
      )}

      {task.recoveryCandidates.map((candidate) => (
        <RecoveryPanel
          key={candidate.candidateId}
          candidate={candidate}
          busyKey={busyKey}
          onRecovery={onRecovery}
        />
      ))}

      <details>
        <summary>Timeline ({task.timeline.length})</summary>
        {task.timeline.length === 0 ? (
          <p>No task events are available.</p>
        ) : (
          <ol className="timeline">
            {task.timeline.map((entry) => (
              <li key={`${entry.sequence}:${entry.eventType}`}>
                <p>
                  <strong>{entry.summary}</strong>
                </p>
                <time dateTime={entry.createdAt}>{entry.createdAt}</time>
                {entry.evidence === null ? null : (
                  <details>
                    <summary>Evidence</summary>
                    <dl className="summary-list">
                      <div>
                        <dt>Artifact</dt>
                        <dd>{entry.evidence.artifactId}</dd>
                      </div>
                      <div>
                        <dt>Content hash</dt>
                        <dd>
                          <code>{entry.evidence.contentHash}</code>
                        </dd>
                      </div>
                    </dl>
                  </details>
                )}
              </li>
            ))}
          </ol>
        )}
      </details>
    </article>
  );
}

function RecoveryPanel({
  candidate,
  busyKey,
  onRecovery,
}: {
  candidate: RecoveryCandidateDto;
  busyKey: string | null;
  onRecovery: (
    action: RecoveryActionDto,
    candidate: RecoveryCandidateDto,
    confirmed: boolean,
  ) => Promise<void>;
}) {
  const [discardConfirmed, setDiscardConfirmed] = useState(false);
  return (
    <section
      className="recovery-panel"
      aria-labelledby={`recovery-${candidate.candidateId}`}
    >
      <h4 id={`recovery-${candidate.candidateId}`}>
        Recovery action required: {candidate.reason}
      </h4>
      <p>
        <span aria-hidden="true">?</span> {candidate.reason}
      </p>
      <details>
        <summary>Preserved evidence</summary>
        <p>{candidate.evidence.summary}</p>
        {candidate.evidence.artifactId === null ? null : (
          <p>Artifact: {candidate.evidence.artifactId}</p>
        )}
      </details>
      {candidate.actions.length === 0 ? (
        <p>No safe automated action is currently authorized.</p>
      ) : (
        <div className="recovery-actions">
          {candidate.actions.map((action) => {
            const busy = busyKey === `${candidate.candidateId}:${action.code}`;
            if (action.code === "discard") {
              const confirmationId = `confirm-discard-${candidate.candidateId}`;
              return (
                <div key={action.code} className="destructive-action">
                  <label htmlFor={confirmationId}>
                    <input
                      id={confirmationId}
                      type="checkbox"
                      checked={discardConfirmed}
                      onChange={(event) =>
                        setDiscardConfirmed(event.currentTarget.checked)
                      }
                    />{" "}
                    Confirm discard of this exact managed worktree
                  </label>
                  <button
                    type="button"
                    className="danger-button"
                    disabled={!discardConfirmed || busyKey !== null}
                    onClick={() =>
                      void onRecovery(action, candidate, discardConfirmed)
                    }
                  >
                    {busy ? "Discarding…" : action.label}
                  </button>
                </div>
              );
            }
            return (
              <button
                key={action.code}
                type="button"
                disabled={busyKey !== null}
                onClick={() => void onRecovery(action, candidate, false)}
              >
                {busy ? "Working…" : action.label}
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}

function commandErrorMessage(cause: unknown) {
  if (
    typeof cause === "object" &&
    cause !== null &&
    "message" in cause &&
    typeof cause.message === "string"
  ) {
    return cause.message;
  }
  return "Authoritative workspace state could not be read. No success was assumed.";
}
