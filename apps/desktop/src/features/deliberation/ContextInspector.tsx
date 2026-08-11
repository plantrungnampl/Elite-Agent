import { useCallback, useEffect, useRef, useState } from "react";

import {
  getContextPackage,
  type ContextPackageDto,
  type ContextPackageMemberDto,
} from "../../api/deliberation";
import { commandErrorMessage } from "./deliberation-model";

interface ContextInspectorProps {
  packageId: string;
  expectedTaskId: string;
  onClose: () => void;
}

export function ContextInspector({
  packageId,
  expectedTaskId,
  onClose,
}: ContextInspectorProps) {
  const [contextPackage, setContextPackage] = useState<ContextPackageDto | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);

  const loadPackage = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const nextPackage = await getContextPackage({ packageId });
      if (nextPackage.packageId !== packageId || nextPackage.taskId !== expectedTaskId) {
        throw new Error("Context package does not belong to this task.");
      }
      setContextPackage(nextPackage);
    } catch (cause) {
      setContextPackage(null);
      setError(
        commandErrorMessage(cause, "Authoritative context package is unavailable."),
      );
    } finally {
      setLoading(false);
    }
  }, [expectedTaskId, packageId]);

  useEffect(() => {
    void loadPackage();
  }, [loadPackage]);

  useEffect(() => {
    closeButton.current?.focus();
  }, []);

  function handleKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== "Tab" || dialog.current === null) {
      return;
    }
    const focusable = Array.from(
      dialog.current.querySelectorAll<HTMLElement>(
        "button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex='-1'])",
      ),
    );
    if (focusable.length === 0) {
      event.preventDefault();
      dialog.current.focus();
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

  return (
    <div className="dialog-backdrop">
      <div
        ref={dialog}
        className="approval-dialog context-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="context-inspector-title"
        aria-busy={loading}
        tabIndex={-1}
        onKeyDown={handleKeyDown}
      >
        <div className="dialog-heading">
          <div>
            <p className="eyebrow">Immutable outbound context</p>
            <h2 id="context-inspector-title">Context inspector</h2>
          </div>
          <button ref={closeButton} className="secondary-button" type="button" onClick={onClose}>
            Close context inspector
          </button>
        </div>

        <p role="status" aria-live="polite" aria-atomic="true">
          {loading
            ? "Loading exact context package"
            : error === null
              ? "Exact context package loaded"
              : "Context package unavailable"}
        </p>
        {error !== null ? (
          <div className="error-panel" role="alert">
            <p>{error}</p>
            <button className="secondary-button" type="button" onClick={() => void loadPackage()}>
              Retry context load
            </button>
          </div>
        ) : null}

        {contextPackage !== null ? <ContextPackageDetails contextPackage={contextPackage} /> : null}
      </div>
    </div>
  );
}

function ContextPackageDetails({ contextPackage }: { contextPackage: ContextPackageDto }) {
  return (
    <>
      <dl className="detail-grid context-package-summary">
        <Detail label="Package ID" value={contextPackage.packageId} />
        <Detail label="Task ID" value={contextPackage.taskId} />
        <Detail label="Agent" value={contextPackage.agentId} />
        <Detail label="Role" value={contextPackage.role} />
        <Detail label="Objective" value={contextPackage.objective} />
        <Detail label="Artifact" value={contextPackage.artifactId} />
        <Detail label="Content digest" value={contextPackage.contentDigest} />
        <Detail label="Policy snapshot" value={contextPackage.policySnapshotDigest} />
        <Detail label="Prompt template" value={contextPackage.versions.promptTemplate} />
        <Detail label="Retrieval pipeline" value={contextPackage.versions.retrievalPipeline} />
        <Detail label="Tokenizer" value={contextPackage.versions.tokenizer} />
        <Detail
          label="Token budget"
          value={`${contextPackage.budget.usedInputTokens} used / ${contextPackage.budget.maxTokens} maximum; ${contextPackage.budget.reservedResponseTokens} reserved`}
        />
      </dl>

      <section className="dialog-section" aria-labelledby="context-policy-decisions">
        <h3 id="context-policy-decisions">Policy decision IDs</h3>
        <TextList values={contextPackage.policyDecisionIds} empty="No policy decisions recorded." />
      </section>

      <section className="dialog-section" aria-labelledby="context-members">
        <h3 id="context-members">Disclosed context members</h3>
        {contextPackage.members.length === 0 ? (
          <p>No context members disclosed.</p>
        ) : (
          <ol className="context-member-list">
            {contextPackage.members.map((member) => (
              <ContextMember key={member.memberId} member={member} />
            ))}
          </ol>
        )}
      </section>
    </>
  );
}

function ContextMember({ member }: { member: ContextPackageMemberDto }) {
  const disclosure =
    member.disclosure.kind === "allowed"
      ? "Allowed"
      : member.disclosure.kind === "redacted"
        ? "Redacted"
        : "Denied";
  return (
    <li className="context-member">
      <div className="card-label-row">
        <strong>{member.memberId}</strong>
        <span className={`state-pill state-${member.disclosure.kind}`}>{disclosure}</span>
        {member.freshness === "stale" ? (
          <span className="state-pill state-stale">! Stale evidence</span>
        ) : (
          <span className="state-pill">✓ Current evidence</span>
        )}
      </div>
      <dl className="detail-grid compact-details">
        <Detail label="Project" value={member.source.projectId} />
        <Detail label="Revision" value={member.source.revision} />
        <Detail label="Logical path" value={member.source.pathIdentity} />
        <Detail label="Content hash" value={member.source.contentHash} />
        <Detail
          label="Range"
          value={
            member.lineRange === null
              ? "Whole source"
              : `Lines ${member.lineRange.start}–${member.lineRange.end}`
          }
        />
        <Detail label="Symbol" value={member.symbol ?? "None"} />
        <Detail
          label="Redaction report"
          value={member.disclosure.stableReportId ?? "None"}
        />
      </dl>
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

function TextList({ values, empty }: { values: string[]; empty: string }) {
  return values.length === 0 ? (
    <p>{empty}</p>
  ) : (
    <ul className="plain-list">
      {values.map((value) => (
        <li key={value}>{value}</li>
      ))}
    </ul>
  );
}
