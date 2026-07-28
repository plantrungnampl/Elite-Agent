#![forbid(unsafe_code)]

mod capability;
mod filesystem;
mod git;

use local_agent_terminal_application::{
    parse_policy_timestamp, AuthorizedToolRequest, CancellationReceipt,
    CapabilityFileWriteSessionFactory, CapabilityFilesystem, CapabilityResolver, Clock,
    DisclosureChannel, DisclosureContextProvider, DisclosureContextRequest, DisclosureOutcome,
    DisclosurePolicyEvaluator, DisclosureRequest, ExecutorLeaseStore, FileReadRequest,
    FileWriteEvidenceStore, FileWriteRecoveryStore, FileWriteRequest, GitDiffRequest,
    GitDiffResult, GitStatusRequest, GitStatusResult, PolicyBoundBytes, PolicyDecisionId,
    PolicyDecisionStore, PortError, ProcessLauncher, RawGitDiffResult, RawGitStatusResult,
    RecordedPolicyDecision, Retryability, SafeErrorClassification, StructuredGit,
    StructuredToolExecutor, ToolExecutionId, ToolExecutionResult, VerifiedBytes, VerifiedWrite,
    WorkspaceWriteCoordinator,
};
use local_agent_terminal_domain::{
    CapabilityRef, PolicyAction, PolicyEffect, PolicyRequest, PolicyResource, TaskId,
};
use sha2::{Digest, Sha256};

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
    disclosure_context: &'a dyn DisclosureContextProvider,
    disclosure_policy: &'a dyn DisclosurePolicyEvaluator,
    policy_decisions: &'a dyn PolicyDecisionStore,
    clock: &'a dyn Clock,
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
        disclosure_context: &'a dyn DisclosureContextProvider,
        disclosure_policy: &'a dyn DisclosurePolicyEvaluator,
        policy_decisions: &'a dyn PolicyDecisionStore,
        clock: &'a dyn Clock,
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
            disclosure_context,
            disclosure_policy,
            policy_decisions,
            clock,
        }
    }

    pub fn read(
        &self,
        request: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        let task_id = request.task_id.clone();
        let capability = request.capability.clone();
        let verified = filesystem::read(self.resolver, self.filesystem, request)?;
        self.disclose(task_id, capability, DisclosureChannel::FileRead, verified)
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

    pub fn status(
        &self,
        request: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        let task_id = request.task_id.clone();
        let capability = request.worktree.clone();
        let raw = git::status(self.resolver, self.git, request)?;
        if raw.path_scope != capability || digest_bytes(&raw.bytes) != raw.digest {
            return Err(integrity_failure());
        }
        let RawGitStatusResult {
            digest,
            bytes,
            repository_id,
            revision,
            path_scope,
            truncated,
        } = raw;
        self.disclose(
            task_id,
            capability,
            DisclosureChannel::GitStatus,
            VerifiedBytes { digest, bytes },
        )
        .map(|outcome| {
            outcome.map(|disclosure| GitStatusResult {
                disclosure,
                repository_id,
                revision,
                path_scope,
                truncated,
            })
        })
    }

    pub fn diff(
        &self,
        request: GitDiffRequest,
    ) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        let task_id = request.task_id.clone();
        let capability = request.worktree.clone();
        let raw = git::diff(self.resolver, self.git, request)?;
        if raw.path_scope != capability || digest_bytes(&raw.bytes) != raw.digest {
            return Err(integrity_failure());
        }
        let RawGitDiffResult {
            digest,
            bytes,
            repository_id,
            revision,
            path_scope,
            truncated,
        } = raw;
        self.disclose(
            task_id,
            capability,
            DisclosureChannel::GitDiff,
            VerifiedBytes { digest, bytes },
        )
        .map(|outcome| {
            outcome.map(|disclosure| GitDiffResult {
                disclosure,
                repository_id,
                revision,
                path_scope,
                truncated,
            })
        })
    }

    fn disclose(
        &self,
        task_id: TaskId,
        capability: CapabilityRef,
        channel: DisclosureChannel,
        verified: VerifiedBytes,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        let context = self.disclosure_context.context(DisclosureContextRequest {
            task_id: task_id.clone(),
            capability: capability.clone(),
            channel,
        })?;
        let evaluated_at = parse_policy_timestamp(&self.clock.now_utc()?)?;
        let action = PolicyAction::new("context.disclose").map_err(|_| integrity_failure())?;
        let policy_request = PolicyRequest {
            task_id,
            actor: context.actor,
            action,
            resource: PolicyResource {
                capability,
                content_digest: verified.digest.clone(),
                resource_class: context.resource_class,
            },
            task_risk: context.task_risk,
            workflow_phase: context.workflow_phase,
            purpose: context.purpose,
            policy_snapshot_digest: context.policy_snapshot_digest,
            evaluated_at,
        };
        let disclosure = self.disclosure_policy.disclose(DisclosureRequest {
            policy_request: policy_request.clone(),
            channel,
            bytes: verified.bytes,
        })?;
        if disclosure.original_digest != verified.digest
            || disclosure.channel != channel
            || disclosure.decision.draft.request() != &policy_request
        {
            return Err(integrity_failure());
        }
        let expected_decision_id = PolicyDecisionId::from_decision(&disclosure.decision);
        let policy_decision_id = self.policy_decisions.record(RecordedPolicyDecision {
            decision: disclosure.decision.clone(),
            recorded_at: evaluated_at,
        })?;
        if policy_decision_id != expected_decision_id {
            return Err(integrity_failure());
        }

        match disclosure.decision.draft.effect() {
            PolicyEffect::Deny => Ok(DisclosureOutcome::Denied),
            PolicyEffect::RequireApproval => {
                let binding = disclosure.approval_binding.ok_or_else(integrity_failure)?;
                let effective_digest = disclosure
                    .effective_digest
                    .as_ref()
                    .ok_or_else(integrity_failure)?;
                if binding.effective_payload_digest != *effective_digest
                    || binding.redaction_report_digest != disclosure.redaction_report_digest
                {
                    return Err(integrity_failure());
                }
                Ok(DisclosureOutcome::ApprovalRequired { binding })
            }
            PolicyEffect::Allow | PolicyEffect::AllowWithRedaction => {
                let bytes = disclosure.effective_bytes.ok_or_else(integrity_failure)?;
                let digest = disclosure.effective_digest.ok_or_else(integrity_failure)?;
                if digest_bytes(&bytes) != digest || disclosure.approval_binding.is_some() {
                    return Err(integrity_failure());
                }
                Ok(DisclosureOutcome::Disclosed(PolicyBoundBytes {
                    policy_decision_id,
                    original_digest: disclosure.original_digest,
                    redaction_report_digest: disclosure.redaction_report_digest,
                    digest,
                    bytes,
                }))
            }
        }
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

    fn file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        self.read(request)
    }

    fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        self.write(request)
    }

    fn git_status(
        &self,
        request: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        self.status(request)
    }

    fn git_diff(
        &self,
        request: GitDiffRequest,
    ) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        self.diff(request)
    }
}

fn digest_bytes(bytes: &[u8]) -> local_agent_terminal_domain::Sha256Digest {
    local_agent_terminal_domain::Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting always satisfies the domain invariant")
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
