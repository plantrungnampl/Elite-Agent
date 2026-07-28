#![forbid(unsafe_code)]

mod capability;
mod filesystem;
mod git;

use local_agent_terminal_application::{
    AuthorizedToolRequest, CancellationReceipt, CapabilityFileWriteSessionFactory,
    CapabilityFilesystem, CapabilityResolver, ExecutorLeaseStore, FileReadRequest,
    FileWriteEvidenceStore, FileWriteRecoveryStore, FileWriteRequest, GitDiffRequest,
    GitDiffResult, GitStatusRequest, GitStatusResult, PortError, ProcessLauncher, StructuredGit,
    StructuredToolExecutor, ToolExecutionId, ToolExecutionResult, VerifiedBytes, VerifiedWrite,
    WorkspaceWriteCoordinator,
};

pub struct ToolRuntime<'a> {
    resolver: &'a dyn CapabilityResolver,
    filesystem: &'a dyn CapabilityFilesystem,
    file_write_sessions: &'a dyn CapabilityFileWriteSessionFactory,
    git: &'a dyn StructuredGit,
    leases: &'a dyn ExecutorLeaseStore,
    process_launcher: &'a dyn ProcessLauncher,
    file_write_evidence: &'a dyn FileWriteEvidenceStore,
    file_write_recovery: &'a dyn FileWriteRecoveryStore,
    workspace_writes: &'a WorkspaceWriteCoordinator,
}

impl<'a> ToolRuntime<'a> {
    // Composition keeps each independently replaceable application port explicit.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        resolver: &'a dyn CapabilityResolver,
        filesystem: &'a dyn CapabilityFilesystem,
        file_write_sessions: &'a dyn CapabilityFileWriteSessionFactory,
        git: &'a dyn StructuredGit,
        leases: &'a dyn ExecutorLeaseStore,
        process_launcher: &'a dyn ProcessLauncher,
        file_write_evidence: &'a dyn FileWriteEvidenceStore,
        file_write_recovery: &'a dyn FileWriteRecoveryStore,
        workspace_writes: &'a WorkspaceWriteCoordinator,
    ) -> Self {
        Self {
            resolver,
            filesystem,
            file_write_sessions,
            git,
            leases,
            process_launcher,
            file_write_evidence,
            file_write_recovery,
            workspace_writes,
        }
    }

    pub fn read(&self, request: FileReadRequest) -> Result<VerifiedBytes, PortError> {
        filesystem::read(self.resolver, self.filesystem, request)
    }

    pub fn write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        filesystem::write(
            self.resolver,
            self.file_write_sessions,
            self.leases,
            self.file_write_evidence,
            self.file_write_recovery,
            self.workspace_writes,
            request,
        )
    }

    pub fn status(&self, request: GitStatusRequest) -> Result<GitStatusResult, PortError> {
        git::status(self.resolver, self.git, request)
    }

    pub fn diff(&self, request: GitDiffRequest) -> Result<GitDiffResult, PortError> {
        git::diff(self.resolver, self.git, request)
    }
}

impl StructuredToolExecutor for ToolRuntime<'_> {
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.process_launcher
            .execute(request.into_process_request())
            .map(|receipt| ToolExecutionResult { receipt })
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        self.process_launcher.cancel(execution_id)
    }

    fn file_read(&self, request: FileReadRequest) -> Result<VerifiedBytes, PortError> {
        self.read(request)
    }

    fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        self.write(request)
    }

    fn git_status(&self, request: GitStatusRequest) -> Result<GitStatusResult, PortError> {
        self.status(request)
    }

    fn git_diff(&self, request: GitDiffRequest) -> Result<GitDiffResult, PortError> {
        self.diff(request)
    }
}
