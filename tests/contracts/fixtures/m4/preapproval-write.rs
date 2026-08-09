fn dispatch_before_plan_approval(
    repository: &dyn RepositoryGateway,
    leases: &dyn ExecutorLeaseStore,
    tools: &dyn StructuredToolExecutor,
    worktree: CreateWorktree,
    write: FileWriteRequest,
) {
    let _ = repository.create_worktree(worktree);
    let _ = leases.acquire_lease();
    let _ = tools.file_write(write);
}
