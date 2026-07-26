import { useEffect, useRef, useState } from "react";

import {
  getLocalDiagnostics,
  getStartupStatus,
  retryStartupValidation,
} from "../../api/startup";
import type {
  LocalDiagnosticDto,
  StartupStatusDto,
} from "../../api/startup";
import { startupViewModel } from "./startup-model";

interface StartupScreenProps {
  onReady?: () => void;
}

export function StartupScreen({ onReady }: StartupScreenProps) {
  const [status, setStatus] = useState<StartupStatusDto | null>(null);
  const [diagnostics, setDiagnostics] = useState<LocalDiagnosticDto[]>([]);
  const [ipcFailed, setIpcFailed] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const mainContent = useRef<HTMLElement>(null);
  const statusHeading = useRef<HTMLHeadingElement>(null);
  const retryInFlight = useRef(false);
  const readyNotified = useRef(false);

  useEffect(() => {
    let active = true;

    Promise.all([getStartupStatus(), getLocalDiagnostics()])
      .then(([nextStatus, nextDiagnostics]) => {
        if (active) {
          setStatus(nextStatus);
          setDiagnostics(nextDiagnostics);
        }
      })
      .catch(() => {
        if (active) {
          setStatus(null);
          setDiagnostics([]);
          setIpcFailed(true);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (
      status?.state === "ready" &&
      !readyNotified.current &&
      onReady !== undefined
    ) {
      readyNotified.current = true;
      onReady();
    }
  }, [onReady, status]);

  const view = startupViewModel(status, ipcFailed, retrying);

  function handleSkipToContent() {
    mainContent.current?.focus();
  }

  async function handleRetry() {
    if (retryInFlight.current) {
      return;
    }

    retryInFlight.current = true;
    setRetrying(true);
    setIpcFailed(false);

    try {
      const nextStatus = await retryStartupValidation();
      const nextDiagnostics = await getLocalDiagnostics();
      setStatus(nextStatus);
      setDiagnostics(nextDiagnostics);
    } catch {
      setStatus(null);
      setDiagnostics([]);
      setIpcFailed(true);
    } finally {
      retryInFlight.current = false;
      setRetrying(false);
      statusHeading.current?.focus();
    }
  }

  return (
    <>
      <a
        className="skip-link"
        href="#main-content"
        onClick={handleSkipToContent}
      >
        Skip to startup status
      </a>
      <header className="app-header">
        <div className="shell">
          <p className="product-name">Local Agent Terminal</p>
          <p className="product-scope">Local startup health</p>
        </div>
      </header>
      <main
        ref={mainContent}
        className="shell startup-layout"
        id="main-content"
        tabIndex={-1}
        aria-busy={view.state === "loading"}
      >
        <h1>Startup health</h1>
        <p className="lede">
          Validate authoritative local storage before any project work begins.
        </p>

        <section
          className="status-panel"
          data-state={view.state}
          aria-labelledby="startup-status-heading"
        >
          <h2 id="startup-status-heading" ref={statusHeading} tabIndex={-1}>
            {view.heading}
          </h2>
          <div role="status" aria-live="polite" aria-atomic="true">
            <p className="status-label">
              <span className="status-symbol" aria-hidden="true">
                {view.symbol}
              </span>
              <span>Status: {view.label}</span>
            </p>
            <p>{view.message}</p>
          </div>

          {status !== null && status.issues.length > 0 ? (
            <ul className="issue-list" aria-label="Startup issues">
              {status.issues.map((issue) => (
                <li key={issue.code}>
                  <p>{issue.message}</p>
                  <code>{issue.code}</code>
                </li>
              ))}
            </ul>
          ) : null}

          {view.recoveryActions.length > 0 ? (
            <>
              <h3 className="recovery-heading">Recovery options</h3>
              <ul className="recovery-options" aria-label="Recovery options">
                {view.recoveryActions.map((action) => (
                  <li key={action.code}>
                    <span>{action.label}</span>
                    <code>{action.code}</code>
                  </li>
                ))}
              </ul>
            </>
          ) : null}

          {view.retryLabel !== null ? (
            <button type="button" disabled={retrying} onClick={handleRetry}>
              {view.retryLabel}
            </button>
          ) : null}
        </section>

        <details className="diagnostics">
          <summary tabIndex={0}>Local diagnostics ({diagnostics.length})</summary>
          <p className="diagnostics-note">
            Sanitized local observations only. Repository content and secrets are
            excluded.
          </p>
          {diagnostics.length > 0 ? (
            <div className="diagnostic-list">
              {diagnostics.map((diagnostic) => (
                <article
                  className="diagnostic"
                  key={`${diagnostic.code}-${diagnostic.component}`}
                >
                  <h3>{diagnostic.code}</h3>
                  <dl>
                    <div>
                      <dt>Component</dt>
                      <dd>{diagnostic.component}</dd>
                    </div>
                    <div>
                      <dt>Severity</dt>
                      <dd>{diagnostic.severity}</dd>
                    </div>
                    <div>
                      <dt>Trust</dt>
                      <dd>{diagnostic.trustLabel}</dd>
                    </div>
                    <div>
                      <dt>Observation</dt>
                      <dd>{diagnostic.observationClass}</dd>
                    </div>
                    {diagnostic.errorCategory !== null ? (
                      <div>
                        <dt>Error category</dt>
                        <dd>{diagnostic.errorCategory}</dd>
                      </div>
                    ) : null}
                    {diagnostic.correlationId !== null ? (
                      <div>
                        <dt>Correlation</dt>
                        <dd>{diagnostic.correlationId}</dd>
                      </div>
                    ) : null}
                  </dl>
                  <p>{diagnostic.detail}</p>
                </article>
              ))}
            </div>
          ) : (
            <p>No local diagnostics are available.</p>
          )}
        </details>
      </main>
    </>
  );
}
