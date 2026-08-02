import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";

import {
  cancelToolExecution,
  getApprovalRequest,
  getToolActivity,
  resolveToolApproval,
  stopAllTools,
  type ToolActivityDto,
  type ToolActivityEntryDto,
  type ToolApprovalRequestDto,
} from "../../api/tools";
import {
  canCancelTool,
  toolAvailabilityLabel,
  toolStatusLabel,
} from "./tool-model";

interface ToolActivityScreenProps {
  pollIntervalMs?: number;
}

export function ToolActivityScreen({
  pollIntervalMs = 5_000,
}: ToolActivityScreenProps) {
  const [activity, setActivity] = useState<ToolActivityDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const [approval, setApprovalState] = useState<ToolApprovalRequestDto | null>(
    null,
  );
  const [approvalConfirmed, setApprovalConfirmed] = useState(false);
  const [stopConfirmed, setStopConfirmed] = useState(false);
  const approvalDialog = useRef<HTMLDivElement>(null);
  const approvalTrigger = useRef<HTMLButtonElement | null>(null);
  const currentApproval = useRef<ToolApprovalRequestDto | null>(null);
  const requestGeneration = useRef(0);
  const busy = useRef(false);

  const closeApproval = useCallback((message?: string) => {
    const trigger = approvalTrigger.current;
    currentApproval.current = null;
    setApprovalState(null);
    setApprovalConfirmed(false);
    if (message !== undefined) {
      setAnnouncement(message);
    }
    trigger?.focus();
    queueMicrotask(() => trigger?.focus());
  }, []);

  const applyActivity = useCallback(
    (next: ToolActivityDto) => {
      const displayed = currentApproval.current;
      if (displayed !== null) {
        const current = next.entries.find(
          (entry) => entry.approvalId === displayed.approvalId,
        );
        if (
          current === undefined ||
          current.status !== "approval_required" ||
          current.operationDigest !== displayed.operationDigest
        ) {
          closeApproval("Approval changed and must be reviewed again.");
        }
      }
      setActivity(next);
      setError(null);
    },
    [closeApproval],
  );

  const refreshActivity = useCallback(async () => {
    const generation = ++requestGeneration.current;
    try {
      const next = await getToolActivity();
      if (generation === requestGeneration.current) {
        applyActivity(next);
      }
    } catch (cause) {
      if (generation === requestGeneration.current) {
        setError(commandErrorMessage(cause));
      }
    }
  }, [applyActivity]);

  useEffect(() => {
    void refreshActivity();
    const interval = window.setInterval(() => {
      if (!busy.current) {
        void refreshActivity();
      }
    }, pollIntervalMs);
    return () => window.clearInterval(interval);
  }, [pollIntervalMs, refreshActivity]);

  async function handleOpenApproval(
    entry: ToolActivityEntryDto,
    trigger: HTMLButtonElement,
  ) {
    if (entry.approvalId === null || busyKey !== null) {
      return;
    }
    approvalTrigger.current = trigger;
    const generation = ++requestGeneration.current;
    busy.current = true;
    setBusyKey(`approval:${entry.approvalId}`);
    setError(null);
    try {
      const detail = await getApprovalRequest({ approvalId: entry.approvalId });
      if (
        generation !== requestGeneration.current ||
        detail.operationDigest !== entry.operationDigest
      ) {
        setAnnouncement("Approval changed and must be reviewed again.");
        trigger.focus();
        return;
      }
      currentApproval.current = detail;
      setApprovalState(detail);
      setApprovalConfirmed(false);
    } catch (cause) {
      setError(commandErrorMessage(cause));
      trigger.focus();
    } finally {
      if (generation === requestGeneration.current) {
        busy.current = false;
        setBusyKey(null);
      }
    }
  }

  async function handleApprovalDecision(decision: "approve" | "deny") {
    const displayed = currentApproval.current;
    if (
      displayed === null ||
      busyKey !== null ||
      (decision === "approve" && !approvalConfirmed)
    ) {
      return;
    }
    ++requestGeneration.current;
    busy.current = true;
    setBusyKey(`resolve:${displayed.approvalId}`);
    setError(null);
    try {
      await resolveToolApproval({
        approvalId: displayed.approvalId,
        expectedOperationDigest: displayed.operationDigest,
        decision,
      });
      closeApproval(decision === "approve" ? "Approval recorded." : "Request denied.");
      await refreshActivity();
    } catch (cause) {
      closeApproval(
        isConflict(cause)
          ? "Approval changed and must be reviewed again."
          : undefined,
      );
      setError(isConflict(cause) ? null : commandErrorMessage(cause));
    } finally {
      busy.current = false;
      setBusyKey(null);
    }
  }

  async function handleCancel(executionId: string) {
    if (busyKey !== null) {
      return;
    }
    ++requestGeneration.current;
    busy.current = true;
    setBusyKey(`cancel:${executionId}`);
    setError(null);
    try {
      await cancelToolExecution({ executionId });
      setAnnouncement(`Cancellation requested for ${executionId}.`);
      await refreshActivity();
    } catch (cause) {
      setError(commandErrorMessage(cause));
    } finally {
      busy.current = false;
      setBusyKey(null);
    }
  }

  async function handleStopAll() {
    if (!stopConfirmed || busyKey !== null) {
      return;
    }
    ++requestGeneration.current;
    busy.current = true;
    setBusyKey("stop-all");
    setError(null);
    try {
      const result = await stopAllTools();
      setStopConfirmed(false);
      setAnnouncement(`Stopped ${result.receipts.length} tool executions.`);
      await refreshActivity();
    } catch (cause) {
      setError(commandErrorMessage(cause));
    } finally {
      busy.current = false;
      setBusyKey(null);
    }
  }

  function handleDialogKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      closeApproval();
      return;
    }
    if (event.key !== "Tab") {
      return;
    }
    const focusable = Array.from(
      approvalDialog.current?.querySelectorAll<HTMLElement>(
        "button:not(:disabled), input:not(:disabled)",
      ) ?? [],
    );
    if (focusable.length === 0) {
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  const loading = activity === null && error === null;
  const availability = activity?.availability ?? "unavailable";
  const stateLabel = loading
    ? "Loading authoritative tool activity"
    : toolAvailabilityLabel(availability);
  const hasRunningTools =
    activity?.entries.some((entry) =>
      ["running", "cancelling"].includes(entry.status),
    ) ?? false;

  return (
    <>
      <header className="app-header">
        <div className="shell">
          <p className="product-name">Local Agent Terminal</p>
          <p className="product-scope">Policy and tool activity</p>
        </div>
      </header>
      <main
        className="shell tool-layout"
        id="tool-activity-main"
        tabIndex={-1}
        aria-busy={loading}
      >
        <h1>Tool activity</h1>
        <p className="lede">
          Inspect policy-bound requests, approvals, cancellation, and durable
          execution outcomes.
        </p>

        <section className="status-panel tool-status" aria-labelledby="tool-status-heading">
          <h2 id="tool-status-heading">Tool boundary</h2>
          <p role="status" aria-live="polite" aria-atomic="true">
            <span className="status-symbol" aria-hidden="true">
              {loading ? "…" : availability === "ready" ? "✓" : "!"}
            </span>{" "}
            {announcement === "" ? stateLabel : announcement}
          </p>
          {error === null ? null : (
            <p className="error-message" role="alert">
              <span aria-hidden="true">!</span> {error}
            </p>
          )}
        </section>

        <section className="panel tool-controls" aria-labelledby="tool-controls-heading">
          <h2 id="tool-controls-heading">Emergency control</h2>
          <p>Stop-all closes dispatch before cancelling and joining active workers.</p>
          <label className="confirmation-label">
            <input
              type="checkbox"
              checked={stopConfirmed}
              onChange={(event) => setStopConfirmed(event.currentTarget.checked)}
              disabled={availability === "unavailable" || busyKey !== null}
            />
            Confirm stopping every running tool
          </label>
          <button
            className="danger-button"
            type="button"
            disabled={
              !stopConfirmed ||
              !hasRunningTools ||
              availability === "unavailable" ||
              busyKey !== null
            }
            onClick={() => void handleStopAll()}
          >
            {busyKey === "stop-all" ? "Stopping tools…" : "Stop all tools"}
          </button>
        </section>

        <section className="tool-activity" aria-labelledby="tool-activity-heading">
          <h2 id="tool-activity-heading">Audited requests</h2>
          {activity === null || activity.entries.length === 0 ? (
            <p>No tool activity recorded.</p>
          ) : (
            <div className="table-scroll" tabIndex={0}>
              <table aria-label="Tool activity">
                <thead>
                  <tr>
                    <th scope="col">Execution</th>
                    <th scope="col">Tool and context</th>
                    <th scope="col">State</th>
                    <th scope="col">Control</th>
                  </tr>
                </thead>
                <tbody>
                  {activity.entries.map((entry) => (
                    <ToolActivityRow
                      key={entry.executionId}
                      entry={entry}
                      busy={busyKey !== null && approval === null}
                      onApproval={handleOpenApproval}
                      onCancel={handleCancel}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>

      {approval === null ? null : (
        <div className="dialog-backdrop">
          <div
            ref={approvalDialog}
            className="approval-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="approval-dialog-heading"
            onKeyDown={handleDialogKeyDown}
          >
            <h2 id="approval-dialog-heading">Approve tool request</h2>
            <p className="dialog-warning">
              Approval is bound to the exact digest and expires automatically.
            </p>
            <dl className="approval-details">
              <Detail label="Executable" value={approval.executable} />
              <Detail label="Arguments" value={formatArguments(approval.arguments)} />
              <Detail label="Actor" value={approval.actorId} />
              <Detail label="Reason" value={approval.reason} />
              <Detail label="Working directory" value={approval.cwdScope} />
              <Detail label="Read scopes" value={approval.readScopes.join(", ")} />
              <Detail label="Write scopes" value={approval.writeScopes.join(", ")} />
              <Detail
                label="Environment profile"
                value={approval.environmentProfileDigest}
              />
              <Detail label="Network profile" value={approval.networkProfile} />
              <Detail label="Expires" value={approval.expiresAt} />
              <Detail
                label="Fencing token"
                value={approval.fencingToken?.toString() ?? "Not required"}
              />
              <Detail label="Policy rules" value={approval.policyRules.join(", ")} />
              <Detail label="Redaction" value={approval.redactionState} />
              <Detail label="Full operation digest" value={approval.operationDigest} />
            </dl>
            <label className="confirmation-label">
              <input
                type="checkbox"
                checked={approvalConfirmed}
                onChange={(event) => setApprovalConfirmed(event.currentTarget.checked)}
              />
              Confirm approval of this exact digest
            </label>
            <div className="dialog-actions">
              <button
                className="secondary-button"
                type="button"
                autoFocus
                disabled={busyKey !== null}
                onClick={() => closeApproval()}
              >
                Cancel
              </button>
              <button
                className="secondary-button"
                type="button"
                disabled={busyKey !== null}
                onClick={() => void handleApprovalDecision("deny")}
              >
                Deny request
              </button>
              <button
                type="button"
                disabled={!approvalConfirmed || busyKey !== null}
                onClick={() => void handleApprovalDecision("approve")}
              >
                Approve exact request
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

interface ToolActivityRowProps {
  entry: ToolActivityEntryDto;
  busy: boolean;
  onApproval: (entry: ToolActivityEntryDto, trigger: HTMLButtonElement) => void;
  onCancel: (executionId: string) => void;
}

function ToolActivityRow({
  entry,
  busy,
  onApproval,
  onCancel,
}: ToolActivityRowProps) {
  return (
    <tr>
      <th scope="row">
        <code>{entry.executionId}</code>
      </th>
      <td>
        <strong>{entry.toolName}</strong>
        <details>
          <summary>Inspect exact context</summary>
          <dl className="activity-details">
            <Detail label="Executable" value={entry.executable} />
            <Detail label="Arguments" value={formatArguments(entry.arguments)} />
            <Detail label="Actor" value={entry.actorId} />
            <Detail label="Role" value={entry.effectiveRole} />
            <Detail label="Reason" value={entry.reason} />
            <Detail label="Working directory" value={entry.cwdScope} />
            <Detail label="Read scopes" value={entry.readScopes.join(", ")} />
            <Detail label="Write scopes" value={entry.writeScopes.join(", ")} />
            <Detail
              label="Environment"
              value={`environment: ${entry.environmentProfileDigest}`}
            />
            <Detail label="Network" value={`network: ${entry.networkProfile}`} />
            <Detail label="Operation digest" value={entry.operationDigest} />
            <Detail label="Policy snapshot" value={entry.policySnapshotDigest} />
            <Detail label="Policy rules" value={entry.policyRules.join(", ")} />
            <Detail
              label="Fencing token"
              value={entry.fencingToken?.toString() ?? "Not required"}
            />
          </dl>
        </details>
      </td>
      <td>
        <span className={`state-badge state-${entry.status}`}>
          <span aria-hidden="true">{statusSymbol(entry.status)}</span>{" "}
          {toolStatusLabel(entry.status)}
        </span>
        {entry.redactionState === "redacted" ? (
          <span className="state-badge state-redacted">
            <span aria-hidden="true">◐</span> Redacted
          </span>
        ) : null}
      </td>
      <td>
        {entry.status === "approval_required" && entry.approvalId !== null ? (
          <button
            className="secondary-button"
            type="button"
            disabled={busy}
            onClick={(event) => onApproval(entry, event.currentTarget)}
          >
            Review approval for {entry.executionId}
          </button>
        ) : canCancelTool(entry) ? (
          <button
            className="secondary-button"
            type="button"
            disabled={busy}
            onClick={() => onCancel(entry.executionId)}
          >
            Cancel {entry.executionId}
          </button>
        ) : (
          <span>No action available</span>
        )}
      </td>
    </tr>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value === "" ? "None" : value}</dd>
    </div>
  );
}

function formatArguments(arguments_: string[]) {
  return JSON.stringify(arguments_);
}

function statusSymbol(status: ToolActivityEntryDto["status"]) {
  switch (status) {
    case "succeeded":
      return "✓";
    case "running":
    case "cancelling":
    case "approval_required":
      return "…";
    case "indeterminate":
    case "interrupted":
      return "?";
    default:
      return "!";
  }
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
  return "Authoritative tool state is unavailable.";
}

function isConflict(cause: unknown) {
  return (
    typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    cause.code === "conflict"
  );
}
