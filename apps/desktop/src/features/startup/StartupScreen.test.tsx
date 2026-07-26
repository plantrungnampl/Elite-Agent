import * as axe from "axe-core";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  act,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  LocalDiagnosticDto,
  StartupStatusDto,
} from "../../api/startup";
import { StartupScreen } from "./StartupScreen";

const baseStyles = readFileSync(resolve("src/styles/base.css"), "utf8");

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

  it("shows honest loading text and intentionally focuses the page heading", () => {
    startupApi.getStartupStatus.mockReturnValue(new Promise(() => undefined));
    startupApi.getLocalDiagnostics.mockReturnValue(new Promise(() => undefined));

    render(<StartupScreen />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Startup health" }),
    ).toHaveFocus();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Status: Checking local services",
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Checking local startup health. No success is assumed while validation is running.",
    );
    expect(
      screen.queryByText("Local startup validation completed successfully."),
    ).not.toBeInTheDocument();
  });

  it.each([
    [
      "ready",
      readyStatus,
      "Local services are ready",
      "Status: Ready",
      "Local startup validation completed successfully.",
    ],
    [
      "recoverable failure",
      recoverableStatus,
      "Startup needs attention",
      "Status: Recovery required",
      "Startup validation found a recoverable local problem.",
    ],
    [
      "indeterminate",
      indeterminateStatus,
      "Startup outcome is indeterminate",
      "Status: Outcome indeterminate",
      "Startup validation could not determine a safe outcome. Success has not been assumed.",
    ],
  ])(
    "renders exact visible %s text without color-only meaning",
    async (_name, status, heading, label, message) => {
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
    expect(screen.getByRole("link", { name: "Skip to startup status" })).toHaveAttribute(
      "href",
      "#main-content",
    );

    const summary = screen.getByText("Local diagnostics (1)");
    expect(summary.tagName).toBe("SUMMARY");
    const skipLink = screen.getByRole("link", {
      name: "Skip to startup status",
    });
    skipLink.focus();
    expect(skipLink).toHaveFocus();
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

  it("keeps reduced-motion and zoom-safe responsive layout contracts", () => {
    expect(baseStyles).toContain("@media (prefers-reduced-motion: reduce)");
    expect(baseStyles).toContain("overflow-wrap: anywhere");
    expect(baseStyles).toMatch(/inline-size:\s*min\(calc\(100%/);
    expect(baseStyles).not.toMatch(/(?:min-)?height:\s*100vh/);
    expect(baseStyles).not.toMatch(/min-width:\s*\d/);
  });
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}
