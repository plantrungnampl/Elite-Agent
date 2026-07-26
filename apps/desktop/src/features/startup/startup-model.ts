import type { StartupStatusDto } from "../../api/startup";

interface StartupViewModel {
  heading: string;
  label: string;
  message: string;
  retryLabel: string | null;
  state: "loading" | "ready" | "recoverable" | "indeterminate";
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
      retryLabel: retryLabel(status),
      state: "loading",
    };
  }

  if (ipcFailed) {
    return {
      heading: "Startup status unavailable",
      label: "Outcome indeterminate",
      message:
        "Local startup status could not be read. Success has not been assumed.",
      retryLabel: "Retry startup validation",
      state: "indeterminate",
    };
  }

  if (status === null) {
    return {
      heading: "Validation in progress",
      label: "Checking local services",
      message:
        "Checking local startup health. No success is assumed while validation is running.",
      retryLabel: null,
      state: "loading",
    };
  }

  if (status.state === "ready") {
    return {
      heading: "Local services are ready",
      label: "Ready",
      message: "Local startup validation completed successfully.",
      retryLabel: null,
      state: "ready",
    };
  }

  if (status.state === "recoverableFailure") {
    return {
      heading: "Startup needs attention",
      label: "Recovery required",
      message: "Startup validation found a recoverable local problem.",
      retryLabel: retryLabel(status),
      state: "recoverable",
    };
  }

  return {
    heading: "Startup outcome is indeterminate",
    label: "Outcome indeterminate",
    message:
      "Startup validation could not determine a safe outcome. Success has not been assumed.",
    retryLabel: retryLabel(status),
    state: "indeterminate",
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
