import * as axe from "axe-core";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  LocalDiagnosticDto,
  StartupStatusDto,
} from "../../api/startup";
import { StartupScreen } from "./StartupScreen";

const startupApi = vi.hoisted(() => ({
  getStartupStatus: vi.fn(),
  retryStartupValidation: vi.fn(),
  getLocalDiagnostics: vi.fn(),
}));

vi.mock("../../api/startup", () => startupApi);

const readyStatus: StartupStatusDto = {
  state: "ready",
  issues: [],
};

const recoverableStatus: StartupStatusDto = {
  state: "recoverableFailure",
  issues: [
    {
      code: "startup.database_unavailable",
      message: "The local database could not be opened.",
      recoveryActions: [
        {
          code: "retry_startup_validation",
          label: "Retry startup validation",
        },
        {
          code: "get_local_diagnostics",
          label: "View local diagnostics",
        },
      ],
    },
  ],
};

const indeterminateStatus: StartupStatusDto = {
  state: "indeterminate",
  issues: [
    {
      code: "startup.artifact_reconciliation_failed",
      message: "Artifact recovery could not determine a safe startup state.",
      recoveryActions: [
        {
          code: "retry_startup_validation",
          label: "Retry startup validation",
        },
        {
          code: "get_local_diagnostics",
          label: "View local diagnostics",
        },
      ],
    },
  ],
};

const restartRequiredStatus: StartupStatusDto = {
  state: "indeterminate",
  issues: [
    {
      code: "startup.internal_state_unavailable",
      message: "Startup state is unavailable and cannot be trusted.",
      recoveryActions: [
        {
          code: "restart_application",
          label: "Restart application",
        },
        {
          code: "get_local_diagnostics",
          label: "View local diagnostics",
        },
        {
          code: "get_local_diagnostics",
          label: "View local diagnostics",
        },
      ],
    },
  ],
};

const diagnostics: LocalDiagnosticDto[] = [
  {
    code: "startup.ready",
    component: "bootstrap",
    severity: "info",
    trustLabel: "trustedCore",
    observationClass: "coreObservation",
    errorCategory: null,
    correlationId: null,
    detail: "<script>alert('not markup')</script>",
  },
];

describe("StartupScreen", () => {
  beforeEach(() => {
    startupApi.getStartupStatus.mockReset().mockResolvedValue(readyStatus);
    startupApi.retryStartupValidation.mockReset().mockResolvedValue(readyStatus);
    startupApi.getLocalDiagnostics.mockReset().mockResolvedValue(diagnostics);
  });

  it("shows honest loading text without stealing initial focus", () => {
    startupApi.getStartupStatus.mockReturnValue(new Promise(() => undefined));
    startupApi.getLocalDiagnostics.mockReturnValue(new Promise(() => undefined));

    render(<StartupScreen />);

    expect(document.body).toHaveFocus();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Status: Checking local services",
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Checking local startup health. No success is assumed while validation is running.",
    );
    expect(
      screen.queryByText("Local startup validation completed successfully."),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("status").querySelector("[aria-hidden='true']"),
    ).toHaveTextContent("◌");
  });

  it.each([
    [
      "ready",
      readyStatus,
      "Local services are ready",
      "Status: Ready",
      "Local startup validation completed successfully.",
      "✓",
    ],
    [
      "recoverable failure",
      recoverableStatus,
      "Startup needs attention",
      "Status: Recovery required",
      "Startup validation found a recoverable local problem.",
      "!",
    ],
    [
      "indeterminate",
      indeterminateStatus,
      "Startup outcome is indeterminate",
      "Status: Outcome indeterminate",
      "Startup validation could not determine a safe outcome. Success has not been assumed.",
      "?",
    ],
  ])(
    "renders exact visible %s icon and text without color-only meaning",
    async (_name, status, heading, label, message, icon) => {
      startupApi.getStartupStatus.mockResolvedValue(status);

      render(<StartupScreen />);

      expect(
        await screen.findByRole("heading", { level: 2, name: heading }),
      ).toBeVisible();
      const liveStatus = screen.getByRole("status");
      expect(liveStatus).toHaveAttribute("aria-live", "polite");
      expect(liveStatus).toHaveAttribute("aria-atomic", "true");
      expect(liveStatus).toHaveTextContent(label);
      expect(liveStatus).toHaveTextContent(message);
      expect(
        liveStatus.querySelector("[aria-hidden='true']"),
      ).toHaveTextContent(icon);
      expect(screen.queryByText(/spinner/i)).not.toBeInTheDocument();
    },
  );

  it("turns an IPC rejection into an explicit indeterminate state", async () => {
    startupApi.getStartupStatus.mockRejectedValue(new Error("IPC unavailable"));

    render(<StartupScreen />);

    expect(
      await screen.findByRole("heading", {
        level: 2,
        name: "Startup status unavailable",
      }),
    ).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Status: Outcome indeterminate",
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Local startup status could not be read. Success has not been assumed.",
    );
    expect(screen.queryByText("Status: Ready")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Retry startup validation" }),
    ).not.toBeInTheDocument();
  });

  it("opens the workspace only after authoritative Ready", async () => {
    const onReady = vi.fn();
    startupApi.getStartupStatus.mockResolvedValue(recoverableStatus);
    const { unmount } = render(<StartupScreen onReady={onReady} />);

    await screen.findByRole("heading", {
      level: 2,
      name: "Startup needs attention",
    });
    expect(onReady).not.toHaveBeenCalled();

    unmount();
    startupApi.getStartupStatus.mockResolvedValue(readyStatus);
    render(<StartupScreen onReady={onReady} />);
    await screen.findByRole("heading", {
      level: 2,
      name: "Local services are ready",
    });
    await waitFor(() => expect(onReady).toHaveBeenCalledTimes(1));
  });

  it("shows deduplicated authoritative restart guidance without fabricating retry", async () => {
    startupApi.getStartupStatus.mockResolvedValue(restartRequiredStatus);

    render(<StartupScreen />);

    await screen.findByRole("heading", {
      level: 2,
      name: "Startup outcome is indeterminate",
    });
    const recovery = screen.getByRole("list", { name: "Recovery options" });
    expect(within(recovery).getByText("Restart application")).toBeVisible();
    expect(within(recovery).getByText("restart_application")).toBeVisible();
    expect(within(recovery).getAllByText("View local diagnostics")).toHaveLength(
      1,
    );
    expect(
      screen.queryByRole("button", { name: "Retry startup validation" }),
    ).not.toBeInTheDocument();
  });

  it("guards rapid retry, refreshes diagnostics afterward, and restores status focus", async () => {
    const retry = deferred<StartupStatusDto>();
    const order: string[] = [];
    startupApi.getStartupStatus.mockResolvedValue(recoverableStatus);
    startupApi.getLocalDiagnostics
      .mockResolvedValueOnce(diagnostics)
      .mockImplementationOnce(async () => {
        order.push("diagnostics");
        return diagnostics;
      });
    startupApi.retryStartupValidation.mockImplementation(() => {
      order.push("retry");
      return retry.promise.then((status) => {
        order.push("status");
        return status;
      });
    });

    render(<StartupScreen />);
    const retryButton = await screen.findByRole("button", {
      name: "Retry startup validation",
    });

    act(() => {
      retryButton.click();
      retryButton.click();
    });

    expect(startupApi.retryStartupValidation).toHaveBeenCalledTimes(1);
    expect(retryButton).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Retrying startup validation. Success has not been assumed.",
    );

    await act(async () => {
      retry.resolve(readyStatus);
      await retry.promise;
    });

    await screen.findByRole("heading", {
      level: 2,
      name: "Local services are ready",
    });
    expect(order).toEqual(["retry", "status", "diagnostics"]);
    expect(
      screen.getByRole("heading", {
        level: 2,
        name: "Local services are ready",
      }),
    ).toHaveFocus();
    expect(screen.getByRole("status")).toHaveTextContent("Status: Ready");
  });

  it("uses semantic landmarks and keyboard-reachable native diagnostics", async () => {
    const user = userEvent.setup();
    render(<StartupScreen />);

    await screen.findByRole("heading", {
      level: 2,
      name: "Local services are ready",
    });
    expect(screen.getByRole("banner")).toBeVisible();
    expect(screen.getByRole("main")).toHaveAttribute("id", "main-content");
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    const skipLink = screen.getByRole("link", {
      name: "Skip to startup status",
    });
    expect(skipLink).toHaveAttribute("href", "#main-content");

    const summary = screen.getByText("Local diagnostics (1)");
    expect(summary.tagName).toBe("SUMMARY");
    expect(document.body).toHaveFocus();
    await user.tab();
    expect(skipLink).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("main")).toHaveFocus();
    await user.tab();
    expect(summary).toHaveFocus();
    fireEvent.click(summary);
    expect(summary.closest("details")).toHaveAttribute("open");

    const details = summary.closest("details");
    expect(details).not.toBeNull();
    expect(within(details as HTMLElement).getByText("trustedCore")).toBeVisible();
    expect(
      within(details as HTMLElement).getByText(
        "<script>alert('not markup')</script>",
      ),
    ).toBeVisible();
    expect((details as HTMLElement).querySelector("script")).toBeNull();
  });

  it("has no obvious axe-core violations", async () => {
    const { container } = render(<StartupScreen />);
    await screen.findByRole("heading", {
      level: 2,
      name: "Local services are ready",
    });

    const result = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    });

    expect(result.violations).toEqual([]);
  });
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}
