import { useState } from "react";

import {
  resolvePlanApproval,
  type PlanApprovalAction,
  type PlanApprovalDto,
  type PlanApprovalResolutionDto,
} from "../../api/deliberation";
import {
  approvalStatusLabel,
  commandErrorMessage,
  isConflict,
} from "./deliberation-model";

interface PlanApprovalPanelProps {
  approval: PlanApprovalDto;
  taskVersion: number;
  onResolved: (resolution: PlanApprovalResolutionDto) => void;
}

const secondaryActions: Array<{ label: string; action: PlanApprovalAction }> = [
  { label: "Revise", action: "revise" },
  { label: "Reopen", action: "reopen" },
  { label: "Add/replace agent", action: "add_or_replace_agent" },
  { label: "Reject", action: "reject" },
];

export function PlanApprovalPanel({
  approval,
  taskVersion,
  onResolved,
}: PlanApprovalPanelProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [invalidated, setInvalidated] = useState(false);
  const [feedback, setFeedback] = useState(approvalStatusLabel(approval.status));
  const [error, setError] = useState<string | null>(null);
  const actionable = approval.status === "requested" && !invalidated && !busy;

  async function handleAction(action: PlanApprovalAction) {
    if (!actionable || (action === "approve" && !confirmed)) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const resolution = await resolvePlanApproval({
        approvalId: approval.approvalId,
        displayedDigest: approval.operationDigest,
        expectedTaskVersion: taskVersion,
        action,
      });
      setFeedback(action === "approve" ? "Plan approval recorded" : "Plan action recorded");
      onResolved(resolution);
    } catch (cause) {
      if (isConflict(cause)) {
        setInvalidated(true);
        setConfirmed(false);
      }
      setError(commandErrorMessage(cause, "The plan action could not be recorded."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel plan-approval-panel" aria-labelledby="plan-approval-heading">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Digest-bound decision</p>
          <h2 id="plan-approval-heading">Plan approval</h2>
        </div>
        <span className={`state-pill state-${approval.status}`}>
          {approvalStatusLabel(approval.status)}
        </span>
      </div>

      <p role="status" aria-live="polite" aria-atomic="true">
        {feedback}
      </p>
      {error !== null ? <p role="alert" className="error-panel">{error}</p> : null}

      <div className="approval-overview">
        <section aria-labelledby="selected-approach-heading">
          <h3 id="selected-approach-heading">Selected proposal</h3>
          <p>
            <strong>{approval.selectedApproachLabel}</strong> ({approval.selectedApproachId})
          </p>
        </section>
        <section aria-labelledby="rejected-alternatives-heading">
          <h3 id="rejected-alternatives-heading">Rejected alternatives</h3>
          {approval.rejectedAlternatives.length === 0 ? (
            <p>None recorded.</p>
          ) : (
            <ul className="plain-list">
              {approval.rejectedAlternatives.map((alternative) => (
                <li key={alternative.approachId}>
                  <strong>{alternative.label}</strong> ({alternative.approachId}): {alternative.reason}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <div className="approval-grid">
        <ApprovalList
          heading="Agent agreement and dissent"
          values={approval.agreement.map(
            (entry) => `${entry.agentId}: ${entry.position} — ${entry.summary}`,
          )}
        />
        <ApprovalList heading="Unresolved objections" values={approval.unresolvedObjections} />
        <ApprovalList heading="Files expected to change" values={approval.affectedFiles} />
        <ApprovalList heading="Planned commands and tools" values={approval.plannedTools} />
        <ApprovalList heading="Security implications" values={approval.securityImplications} />
        <ApprovalList heading="Exact writable scope" values={approval.writableScopes} />
      </div>

      <dl className="detail-grid approval-authority">
        <Detail label="Verification profile" value={approval.verificationProfile} />
        <Detail label="Rollback plan" value={approval.rollbackPlan} />
        <Detail
          label="Estimated cost"
          value={
            approval.estimatedCostMicrounits === null
              ? "Not estimated"
              : `${approval.estimatedCostMicrounits.toLocaleString("en-US")} microunits`
          }
        />
        <Detail
          label="Estimated duration"
          value={formatDuration(approval.estimatedDurationSeconds)}
        />
        <Detail label="Plan version" value={`Plan version ${approval.planVersion}`} />
        <Detail label="Policy snapshot" value={approval.policySnapshotDigest} />
        <Detail label="Executor fencing" value={`Fencing epoch ${approval.fencingEpoch}`} />
        <Detail label="Approval expires" value={approval.expiresAt} />
        <Detail label="Approval operation digest" value={approval.operationDigest} />
      </dl>

      <label className="confirmation-label plan-confirmation">
        <input
          type="checkbox"
          checked={confirmed}
          disabled={!actionable}
          onChange={(event) => setConfirmed(event.currentTarget.checked)}
        />
        Confirm approval of this exact plan digest
      </label>
      <div className="approval-actions">
        <button
          className="primary-button"
          type="button"
          disabled={!actionable || !confirmed}
          onClick={() => void handleAction("approve")}
        >
          Approve
        </button>
        {secondaryActions.map(({ label, action }) => (
          <button
            key={action}
            className={action === "reject" ? "danger-button" : "secondary-button"}
            type="button"
            disabled={!actionable}
            onClick={() => void handleAction(action)}
          >
            {label}
          </button>
        ))}
      </div>
    </section>
  );
}

function ApprovalList({ heading, values }: { heading: string; values: string[] }) {
  return (
    <section>
      <h3>{heading}</h3>
      {values.length === 0 ? (
        <p>None recorded.</p>
      ) : (
        <ul className="plain-list">
          {values.map((value) => (
            <li key={value}>{value}</li>
          ))}
        </ul>
      )}
    </section>
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

function formatDuration(seconds: number | null) {
  if (seconds === null) {
    return "Not estimated";
  }
  if (seconds % 60 === 0) {
    return `${seconds / 60} minutes`;
  }
  return `${seconds} seconds`;
}
