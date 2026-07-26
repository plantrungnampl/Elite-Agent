import { invoke } from "@tauri-apps/api/core";

export type RepositoryHealth = "healthy" | "dirty" | "unsafe" | "unsupported";
export type RecoveryActionCode = "reconcile" | "preserve" | "discard";

export interface CommandErrorDto {
  code: string;
  message: string;
  retryable: boolean;
}

export interface WorkspaceFingerprintDto {
  head: string;
  indexDigest: string;
  statusDigest: string;
}

export interface RepositorySnapshotDto {
  repositoryId: string;
  health: RepositoryHealth;
  stableIdentity: string;
  defaultBranch: string | null;
  baseCommit: string | null;
  originalCheckout: "clean" | "dirty" | "detached" | "unborn" | "unavailable";
  hazards: Array<{ reason: string; detail: string }>;
  fingerprint: WorkspaceFingerprintDto;
}

export interface WorktreeSnapshotDto {
  worktreeId: string;
  repositoryId: string;
  taskId: string;
  branch: string;
  baseCommit: string;
  targetPathDisplay: string;
  state: "planned" | "present" | "missing" | "conflict" | "discarded";
  expectedPresence: "absent" | "present";
  fingerprint: WorkspaceFingerprintDto;
}

export interface TimelineEntryDto {
  sequence: number;
  eventType: string;
  createdAt: string;
  summary: string;
  evidence: {
    artifactId: string;
    contentHash: string;
    sizeBytes: number;
  } | null;
}

export interface RecoveryActionDto {
  candidateId: string;
  code: RecoveryActionCode;
  label: string;
}

export interface RecoveryCandidateDto {
  candidateId: string;
  taskId: string;
  expectedWorkspaceVersion: number;
  reason: string;
  evidence: {
    summary: string;
    artifactId: string | null;
  };
  actions: RecoveryActionDto[];
  expectedWorktree: {
    worktreeId: string;
    repositoryId: string;
    taskId: string;
    branch: string;
    baseCommit: string;
    targetPathDisplay: string;
    expectedPresence: "absent" | "present";
  } | null;
}

export interface TaskSnapshotDto {
  taskId: string;
  projectId: string;
  title: string;
  objective: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  phase: string;
  condition: string;
  operationState: string;
  baseBranch: string;
  baseCommit: string;
  taskBranch: string | null;
  worktree: WorktreeSnapshotDto | null;
  currentSequence: number;
  workspaceVersion: number;
  fencingEpoch: number;
  leaseState: "none" | "active" | "released" | "expired" | "revoked" | "stale";
  recoveryCandidates: RecoveryCandidateDto[];
  timeline: TimelineEntryDto[];
}

export interface WorkspaceDashboardDto {
  projectId: string;
  repository: RepositorySnapshotDto;
  tasks: TaskSnapshotDto[];
  recovery: RecoveryCandidateDto[];
}

export interface ProjectSnapshotDto {
  projectId: string;
  name: string;
  repository: RepositorySnapshotDto;
  settings: {
    policyProfileId: string;
    artifactRootMode: "application_data" | "project_local";
  };
  repositoryEvidenceArtifactId: string | null;
  createdAt: string;
}

export interface WorkspaceDashboardRequestDto {
  projectId: string;
}

export interface OnboardRepositoryRequestDto {
  projectId: string;
  name: string;
  repositoryPath: string;
}

export interface CreateTaskWorkspaceRequestDto {
  projectId: string;
  taskId: string;
  title: string;
  objective: string;
  riskLevel: "low" | "medium" | "high" | "critical";
}

export interface RecoveryCandidateRequestDto {
  candidateId: string;
  projectId: string;
  taskId: string;
  expectedWorkspaceVersion: number;
}

export interface ConfirmDiscardWorkspaceRequestDto
  extends RecoveryCandidateRequestDto {
  confirmed: true;
}

export function getWorkspaceDashboard(
  request: WorkspaceDashboardRequestDto,
): Promise<WorkspaceDashboardDto> {
  return invoke<WorkspaceDashboardDto>("get_workspace_dashboard", { request });
}

export function onboardRepository(
  request: OnboardRepositoryRequestDto,
): Promise<ProjectSnapshotDto> {
  return invoke<ProjectSnapshotDto>("onboard_repository", { request });
}

export function createTaskWorkspace(
  request: CreateTaskWorkspaceRequestDto,
): Promise<TaskSnapshotDto> {
  return invoke<TaskSnapshotDto>("create_task_workspace", { request });
}

export function reconcileWorkspace(
  request: RecoveryCandidateRequestDto,
): Promise<WorkspaceDashboardDto> {
  return invoke<WorkspaceDashboardDto>("reconcile_workspace", { request });
}

export function preserveWorkspace(
  request: RecoveryCandidateRequestDto,
): Promise<WorkspaceDashboardDto> {
  return invoke<WorkspaceDashboardDto>("preserve_workspace", { request });
}

export function discardWorkspace(
  request: ConfirmDiscardWorkspaceRequestDto,
): Promise<WorkspaceDashboardDto> {
  return invoke<WorkspaceDashboardDto>("discard_workspace", { request });
}
