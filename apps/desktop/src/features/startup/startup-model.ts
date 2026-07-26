import type { RecoveryActionDto, StartupStatusDto } from "../../api/startup";

interface StartupViewModel {
  heading: string;
  label: string;
  message: string;
  recoveryActions: RecoveryActionDto[];
  retryLabel: string | null;
  state: "loading" | "ready" | "recoverable" | "indeterminate";
  symbol: string;
}

export function startupViewModel(
  status: StartupStatusDto | null,
  ipcFailed: boolean,
  retrying: boolean,
): StartupViewModel {
  if (retrying) {
    return {
      heading: "Validation in progress",
      label: "Checking local services",
      message: "Retrying startup validation. Success has not been assumed.",
      recoveryActions: recoveryActions(status),
      retryLabel: retryLabel(status),
      state: "loading",
      symbol: "◌",
    };
  }

  if (ipcFailed) {
    return {
      heading: "Startup status unavailable",
      label: "Outcome indeterminate",
      message:
        "Local startup status could not be read. Success has not been assumed.",
      recoveryActions: [],
      retryLabel: null,
      state: "indeterminate",
      symbol: "?",
    };
  }

  if (status === null) {
    return {
      heading: "Validation in progress",
      label: "Checking local services",
      message:
        "Checking local startup health. No success is assumed while validation is running.",
      recoveryActions: [],
      retryLabel: null,
      state: "loading",
      symbol: "◌",
    };
  }

  if (status.state === "ready") {
    return {
      heading: "Local services are ready",
      label: "Ready",
      message: "Local startup validation completed successfully.",
      recoveryActions: [],
      retryLabel: null,
      state: "ready",
      symbol: "✓",
    };
  }

  if (status.state === "recoverableFailure") {
    return {
      heading: "Startup needs attention",
      label: "Recovery required",
      message: "Startup validation found a recoverable local problem.",
      recoveryActions: recoveryActions(status),
      retryLabel: retryLabel(status),
      state: "recoverable",
      symbol: "!",
    };
  }

  return {
    heading: "Startup outcome is indeterminate",
    label: "Outcome indeterminate",
    message:
      "Startup validation could not determine a safe outcome. Success has not been assumed.",
    recoveryActions: recoveryActions(status),
    retryLabel: retryLabel(status),
    state: "indeterminate",
    symbol: "?",
  };
}

function retryLabel(status: StartupStatusDto | null): string | null {
  for (const issue of status?.issues ?? []) {
    const retry = issue.recoveryActions.find(
      (action) => action.code === "retry_startup_validation",
    );
    if (retry !== undefined) {
      return retry.label;
    }
  }
  return null;
}

function recoveryActions(status: StartupStatusDto | null): RecoveryActionDto[] {
  const seen = new Set<string>();
  const actions: RecoveryActionDto[] = [];

  for (const issue of status?.issues ?? []) {
    for (const action of issue.recoveryActions) {
      if (action.code !== "retry_startup_validation" && !seen.has(action.code)) {
        seen.add(action.code);
        actions.push(action);
      }
    }
  }

  return actions;
}
