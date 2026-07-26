import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  getLocalDiagnostics,
  getStartupStatus,
  retryStartupValidation,
} from "./startup";

describe("startup Tauri API", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("invokes only the three typed startup commands", async () => {
    invoke
      .mockResolvedValueOnce({ state: "ready", issues: [] })
      .mockResolvedValueOnce({ state: "recoverableFailure", issues: [] })
      .mockResolvedValueOnce([]);

    await getStartupStatus();
    await retryStartupValidation();
    await getLocalDiagnostics();

    expect(invoke).toHaveBeenNthCalledWith(1, "get_startup_status");
    expect(invoke).toHaveBeenNthCalledWith(2, "retry_startup_validation");
    expect(invoke).toHaveBeenNthCalledWith(3, "get_local_diagnostics");
    expect(invoke).toHaveBeenCalledTimes(3);
  });
});
