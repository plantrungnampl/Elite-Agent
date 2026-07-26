import type {
  RecoveryCandidateDto,
  RepositorySnapshotDto,
  TaskSnapshotDto,
} from "../../api/workspace";

export function canCreateTask(repository: RepositorySnapshotDto) {
  return (
    repository.health === "healthy" &&
    repository.defaultBranch !== null &&
    repository.baseCommit !== null &&
    repository.hazards.length === 0
  );
}

export function taskStatus(task: TaskSnapshotDto) {
  if (task.phase === "WorkspaceDirty") {
    return { label: "Workspace dirty", symbol: "!" };
  }
  if (task.operationState === "Indeterminate") {
    return { label: "Outcome indeterminate", symbol: "?" };
  }
  if (task.leaseState === "revoked" || task.leaseState === "stale") {
    return { label: "Executor fenced", symbol: "×" };
  }
  return { label: task.phase, symbol: "•" };
}

export function recoveryRequest(
  projectId: string,
  candidate: RecoveryCandidateDto,
) {
  return {
    candidateId: candidate.candidateId,
    projectId,
    taskId: candidate.taskId,
    expectedWorkspaceVersion: candidate.expectedWorkspaceVersion,
  };
}
