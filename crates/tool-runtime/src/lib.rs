#![forbid(unsafe_code)]

mod capability;
mod filesystem;
mod git;

use local_agent_terminal_application::{
    AuthorizedGitDiff, AuthorizedGitStatus, AuthorizedToolRequest, CancellationReceipt,
    CapabilityFilesystem, CapabilityResolver, ExecutorLeaseStore, FileReadRequest,
    FileWriteRequest, GitDiffResult, GitStatusResult, PortError, ProcessLauncher, StructuredGit,
    StructuredToolExecutor, ToolExecutionId, ToolExecutionResult, VerifiedBytes, VerifiedWrite,
    WorkspaceMutationStore,
};

pub struct ToolRuntime<'a> {
    resolver: &'a dyn CapabilityResolver,
    filesystem: &'a dyn CapabilityFilesystem,
    git: &'a dyn StructuredGit,
    leases: &'a dyn ExecutorLeaseStore,
    process_launcher: &'a dyn ProcessLauncher,
    workspace_mutations: &'a dyn WorkspaceMutationStore,
}

impl<'a> ToolRuntime<'a> {
    pub const fn new(
        resolver: &'a dyn CapabilityResolver,
        filesystem: &'a dyn CapabilityFilesystem,
        git: &'a dyn StructuredGit,
        leases: &'a dyn ExecutorLeaseStore,
        process_launcher: &'a dyn ProcessLauncher,
        workspace_mutations: &'a dyn WorkspaceMutationStore,
    ) -> Self {
        Self {
            resolver,
            filesystem,
            git,
            leases,
            process_launcher,
            workspace_mutations,
        }
    }

    pub fn read(&self, request: FileReadRequest) -> Result<VerifiedBytes, PortError> {
        filesystem::read(self.resolver, self.filesystem, request)
    }

    pub fn write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        filesystem::write(
            self.resolver,
            self.filesystem,
            self.leases,
            self.workspace_mutations,
            request,
        )
    }

    pub fn status(&self, request: AuthorizedGitStatus) -> Result<GitStatusResult, PortError> {
        git::status(self.resolver, self.git, request)
    }

    pub fn diff(&self, request: AuthorizedGitDiff) -> Result<GitDiffResult, PortError> {
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

    fn git_status(&self, request: AuthorizedGitStatus) -> Result<GitStatusResult, PortError> {
        self.status(request)
    }

    fn git_diff(&self, request: AuthorizedGitDiff) -> Result<GitDiffResult, PortError> {
        self.diff(request)
    }
}
