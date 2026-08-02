import { invoke } from "@tauri-apps/api/core";

export type ToolRuntimeAvailability =
  | "ready"
  | "degraded_read_only"
  | "unavailable";

export type ToolActivityStatus =
  | "denied"
  | "approval_required"
  | "running"
  | "cancelling"
  | "succeeded"
  | "terminated"
  | "failed"
  | "interrupted"
  | "indeterminate";

export interface ToolActivityEntryDto {
  executionId: string;
  approvalId: string | null;
  toolName: string;
  status: ToolActivityStatus;
  summary: string;
  actorId: string;
  effectiveRole: string;
  reason: string;
  operationDigest: string;
  policyDecisionId: string | null;
  policySnapshotDigest: string;
  scopes: string[];
  environmentProfileDigest: string;
  networkProfile: string;
  expiresAt: string | null;
  fencingToken: number | null;
  policyRules: string[];
  redactionState: "none" | "redacted";
  startedAt: string | null;
  completedAt: string | null;
}

export interface ToolActivityDto {
  availability: ToolRuntimeAvailability;
  entries: ToolActivityEntryDto[];
}

export interface ToolApprovalRequestDto {
  approvalId: string;
  executionId: string;
  summary: string;
  operationDigest: string;
  expiresAt: string;
  scopes: string[];
  actorId: string;
  reason: string;
  environmentProfileDigest: string;
  networkProfile: string;
  fencingToken: number | null;
  policyRules: string[];
  redactionState: "none" | "redacted";
}

export interface GetApprovalRequestDto {
  approvalId: string;
}

export interface ResolveToolApprovalRequestDto {
  approvalId: string;
  expectedOperationDigest: string;
  decision: "approve" | "deny";
}

export interface CancelToolExecutionRequestDto {
  executionId: string;
}

export interface ToolApprovalResolutionDto {
  approvalId: string;
  executionId: string;
  status: ToolActivityStatus;
}

export interface ToolCancellationReceiptDto {
  executionId: string;
  status: ToolActivityStatus;
  cancelled: boolean;
}

export interface StopAllToolsReceiptDto {
  receipts: ToolCancellationReceiptDto[];
}

const OPAQUE_ID = /^[A-Za-z0-9_-]{1,256}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;

export function getToolActivity(): Promise<ToolActivityDto> {
  return invoke<ToolActivityDto>("get_tool_activity");
}

export function getApprovalRequest(
  request: GetApprovalRequestDto,
): Promise<ToolApprovalRequestDto> {
  exactKeys(request, ["approvalId"]);
  validOpaqueId(request.approvalId, "approvalId");
  return invoke<ToolApprovalRequestDto>("get_approval_request", { request });
}

export function resolveToolApproval(
  request: ResolveToolApprovalRequestDto,
): Promise<ToolApprovalResolutionDto> {
  exactKeys(request, ["approvalId", "expectedOperationDigest", "decision"]);
  validOpaqueId(request.approvalId, "approvalId");
  if (!SHA256.test(request.expectedOperationDigest)) {
    throw new TypeError("expectedOperationDigest must be a canonical SHA-256 digest");
  }
  if (request.decision !== "approve" && request.decision !== "deny") {
    throw new TypeError("decision must be approve or deny");
  }
  return invoke<ToolApprovalResolutionDto>("resolve_tool_approval", { request });
}

export function cancelToolExecution(
  request: CancelToolExecutionRequestDto,
): Promise<ToolCancellationReceiptDto> {
  exactKeys(request, ["executionId"]);
  validOpaqueId(request.executionId, "executionId");
  return invoke<ToolCancellationReceiptDto>("cancel_tool_execution", { request });
}

export function stopAllTools(): Promise<StopAllToolsReceiptDto> {
  return invoke<StopAllToolsReceiptDto>("stop_all_tools");
}

function exactKeys(value: object, expected: string[]) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new TypeError(`request fields must be exactly: ${expected.join(", ")}`);
  }
}

function validOpaqueId(value: string, field: string) {
  if (!OPAQUE_ID.test(value)) {
    throw new TypeError(`${field} must be an opaque identifier`);
  }
}
