import type {
  ToolActivityEntryDto,
  ToolActivityStatus,
  ToolRuntimeAvailability,
} from "../../api/tools";

const statusLabels: Record<ToolActivityStatus, string> = {
  denied: "Denied",
  approval_required: "Approval required",
  running: "Running",
  cancelling: "Cancelling",
  succeeded: "Succeeded",
  terminated: "Terminated",
  failed: "Failed",
  interrupted: "Interrupted",
  indeterminate: "Indeterminate",
};

const availabilityLabels: Record<ToolRuntimeAvailability, string> = {
  ready: "Tool boundary ready",
  degraded_read_only: "Tool boundary degraded to read-only",
  unavailable: "Tool boundary unavailable",
};

export function toolStatusLabel(status: ToolActivityStatus) {
  return statusLabels[status];
}

export function toolAvailabilityLabel(availability: ToolRuntimeAvailability) {
  return availabilityLabels[availability];
}

export function canCancelTool(entry: ToolActivityEntryDto) {
  return entry.status === "running";
}
