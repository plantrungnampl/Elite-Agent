import { invoke } from "@tauri-apps/api/core";

export type DeliberationAvailability = "ready" | "blocked" | "unavailable";
export type DeliberationCardKind =
  | "proposal"
  | "review"
  | "evidence"
  | "objection"
  | "decision"
  | "status";
export type EvidenceState = "verified" | "unverified" | "inconclusive";
export type PlanApprovalAction =
  | "approve"
  | "revise"
  | "reject";

export interface WorkflowPhaseDto {
  phaseId: string;
  label: string;
  state: "completed" | "current" | "blocked" | "pending";
  detail: string;
  retryCount: number;
  approvalGate: boolean;
}

export interface AgentRosterEntryDto {
  agentId: string;
  role: string;
  providerLabel: string;
  locality: "local" | "cloud";
  status: string;
  contextScope: string;
  contextPackageId: string | null;
  usedTokens: number;
  costMicrounits: number;
  health: string;
  permissions: string[];
  trustTier: string;
  sandboxStatus: string;
  identityChanged: boolean;
}

export interface DeliberationCardDto {
  cardId: string;
  kind: DeliberationCardKind;
  title: string;
  summary: string;
  actorId: string;
  evidenceState: EvidenceState;
  stale: boolean;
  artifactIds: string[];
}

export interface ThreadMessageDto {
  messageId: string;
  actorId: string;
  body: string;
}

export interface DeliberationThreadDto {
  threadId: string;
  summary: string;
  messages: ThreadMessageDto[];
  truncated: boolean;
}

export interface EvidenceItemDto {
  artifactId: string;
  label: string;
  pathIdentity: string;
  lineRange: { start: number; end: number } | null;
  state: EvidenceState;
  freshness: "current" | "stale";
}

export interface RejectedAlternativeDto {
  approachId: string;
  label: string;
  reason: string;
}

export interface AgentAgreementDto {
  agentId: string;
  position: "agree" | "dissent" | "abstain";
  summary: string;
}

export interface PlanApprovalDto {
  approvalId: string;
  taskId: string;
  status:
    | "requested"
    | "resolved"
    | "rejected"
    | "expired"
    | "invalidated"
    | "digest_changed";
  selectedApproachId: string;
  selectedApproachLabel: string;
  rejectedAlternatives: RejectedAlternativeDto[];
  agreement: AgentAgreementDto[];
  unresolvedObjections: string[];
  affectedFiles: string[];
  plannedTools: string[];
  verificationProfile: string;
  rollbackPlan: string;
  securityImplications: string[];
  estimatedCostMicrounits: number | null;
  estimatedDurationSeconds: number | null;
  planVersion: number;
  policySnapshotDigest: string;
  writableScopes: string[];
  fencingEpoch: number;
  operationDigest: string;
  expiresAt: string;
}

export interface DeliberationWorkspaceDto {
  availability: DeliberationAvailability;
  taskId: string;
  phase: string;
  taskVersion: number;
  statusMessage: string;
  workflow: WorkflowPhaseDto[];
  agents: AgentRosterEntryDto[];
  cards: DeliberationCardDto[];
  thread: DeliberationThreadDto | null;
  evidence: EvidenceItemDto[];
  approval: PlanApprovalDto | null;
}

export interface ContextPackageMemberDto {
  memberId: string;
  content: string;
  source: {
    projectId: string;
    revision: string;
    pathIdentity: string;
    contentHash: string;
  };
  lineRange: { start: number; end: number } | null;
  symbol: string | null;
  freshness: "current" | "stale";
  disclosure: {
    kind: "allowed" | "redacted" | "denied";
    stableReportId: string | null;
  };
  policyDecisionIds: string[];
  provenance: string[];
  redactionReportIds: string[];
}

export interface ContextPackageDto {
  packageId: string;
  taskId: string;
  agentId: string;
  role: string;
  objective: string;
  artifactId: string;
  contentDigest: string;
  policySnapshotDigest: string;
  policyDecisionIds: string[];
  versions: {
    promptTemplate: string;
    retrievalPipeline: string;
    tokenizer: string;
  };
  budget: {
    maxTokens: number;
    reservedResponseTokens: number;
    usedInputTokens: number;
  };
  members: ContextPackageMemberDto[];
}

export interface GetDeliberationWorkspaceRequestDto {
  taskId: string;
}

export interface GetContextPackageRequestDto {
  packageId: string;
}

export interface ResumeDeliberationRequestDto {
  taskId: string;
}

export type DeliberationResumeAction =
  | "validate_intake"
  | "build_initial_context"
  | "await_independent_proposals"
  | "publish_quorum"
  | "persist_review_edges"
  | "freeze_material_claims"
  | "classify_material_claims"
  | "synthesize_decision"
  | "collect_final_objections"
  | "close_objection_round"
  | "await_plan_approval"
  | "post_approval";

export interface ResolvePlanApprovalRequestDto {
  approvalId: string;
  displayedDigest: string;
  expectedTaskVersion: number;
  action: PlanApprovalAction;
  feedback: string | null;
}

export interface PlanApprovalResolutionDto {
  approvalId: string;
  taskId: string;
  taskVersion: number;
  status: "resolved" | "rejected";
  action: PlanApprovalAction;
}

const OPAQUE_ID = /^[A-Za-z0-9_-]{1,256}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const PLAN_ACTIONS = new Set<PlanApprovalAction>([
  "approve",
  "revise",
  "reject",
]);

export function getDeliberationWorkspace(
  request: GetDeliberationWorkspaceRequestDto,
): Promise<DeliberationWorkspaceDto> {
  exactKeys(request, ["taskId"]);
  validOpaqueId(request.taskId, "taskId");
  return invoke<DeliberationWorkspaceDto>("get_deliberation_workspace", {
    request,
  });
}

export function getContextPackage(
  request: GetContextPackageRequestDto,
): Promise<ContextPackageDto> {
  exactKeys(request, ["packageId"]);
  validOpaqueId(request.packageId, "packageId");
  return invoke<ContextPackageDto>("get_context_package", { request });
}

export function resumeDeliberation(
  request: ResumeDeliberationRequestDto,
): Promise<DeliberationResumeAction> {
  exactKeys(request, ["taskId"]);
  validOpaqueId(request.taskId, "taskId");
  return invoke<DeliberationResumeAction>("resume_deliberation", { request });
}

export function resolvePlanApproval(
  request: ResolvePlanApprovalRequestDto,
): Promise<PlanApprovalResolutionDto> {
  exactKeys(request, [
    "approvalId",
    "displayedDigest",
    "expectedTaskVersion",
    "action",
    "feedback",
  ]);
  validOpaqueId(request.approvalId, "approvalId");
  if (!SHA256.test(request.displayedDigest)) {
    throw new TypeError("displayedDigest must be a canonical SHA-256 digest");
  }
  if (
    !Number.isSafeInteger(request.expectedTaskVersion) ||
    request.expectedTaskVersion < 1
  ) {
    throw new TypeError("expectedTaskVersion must be a positive safe integer");
  }
  if (!PLAN_ACTIONS.has(request.action)) {
    throw new TypeError("action is not an allowed plan approval action");
  }
  if (request.action === "revise") {
    if (
      request.feedback === null ||
      request.feedback.trim().length === 0 ||
      request.feedback.length > 16_384 ||
      request.feedback.includes("\0")
    ) {
      throw new TypeError("feedback is required for a revision");
    }
  } else if (request.feedback !== null) {
    throw new TypeError("feedback is only allowed for a revision");
  }
  return invoke<PlanApprovalResolutionDto>("resolve_plan_approval", { request });
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
