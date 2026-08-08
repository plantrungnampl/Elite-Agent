#![forbid(unsafe_code)]

mod agent_runtime;
mod logging;
#[cfg(windows)]
mod production_tools;
mod startup;
mod tool_runtime;
mod workspace_monitor;
mod workspace_runtime;

pub use agent_runtime::{OpenAiApiKey, OpenAiBootstrapConfig};
pub use local_agent_terminal_application::{
    ApprovalId, CancelToolExecutionRequestDto, CommandErrorDto, ConfirmDiscardWorkspaceRequestDto,
    CreateTaskWorkspaceRequestDto, GetApprovalRequestDto, LocalDiagnosticDto,
    OnboardRepositoryRequestDto, ProjectSnapshot, RecoveryCandidateRequestDto,
    ResolveToolApprovalRequestDto, StartupStateDto, StartupStatusDto, StopAllToolsReceiptDto,
    TaskSnapshot, ToolActivityDto, ToolApprovalDecisionDto, ToolApprovalRequestDto,
    ToolApprovalResolutionDto, ToolCancellationReceiptDto, ToolRuntimeAvailabilityDto,
    WorkspaceDashboardDto, WorkspaceDashboardRequestDto,
};
pub use startup::{Bootstrap, StartupConfig};
pub use tool_runtime::{
    SelfTestingToolExecutor, ToolArtifactPublisher, ToolBrokerConfig, ToolControlSelfTestStatus,
    ToolRuntime, ToolRuntimeAvailability, ToolStartupRecoveryReport,
};
pub use workspace_runtime::WorkspaceRuntime;
