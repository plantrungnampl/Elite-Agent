use local_agent_terminal_application::{
    validate_and_order_process_writes, ApprovedProcessExecutor, ApprovedProcessRequest,
    AuthoritativeProcessBinding, AuthorizedExpectedWrite, AuthorizedProcessRequest,
    CancellationReceipt, CapabilityRequest, CapabilityResolver, EnforcedNetworkProfile,
    EnvironmentProfileResolver, ExecutableProfileResolver, NetworkProfileVerifier, PortError,
    ProcessExecutionBindingStore, ProcessFenceAuthority, ProcessLauncher, ProcessLimits,
    ProcessReceipt, ProcessWorkingDirectory, Retryability, SafeErrorClassification,
    ToolControlSelfTest, ToolExecutionId,
};
use local_agent_terminal_domain::{
    CapabilityRef, ExpectedWrite, LeaseClaim, ProcessTrustTier, TaskId,
};

const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_OUTPUT_LIMIT_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_ACTIVE_PROCESSES: u32 = 64;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub struct ProcessRuntime<'a> {
    executables: &'a dyn ExecutableProfileResolver,
    environments: &'a dyn EnvironmentProfileResolver,
    networks: &'a dyn NetworkProfileVerifier,
    enforced_networks: Vec<EnforcedNetworkProfile>,
    resolver: &'a dyn CapabilityResolver,
    executor_fence: &'a ProcessFenceAuthority,
    launcher: &'a dyn ProcessLauncher,
    process_bindings: &'a dyn ProcessExecutionBindingStore,
}

impl<'a> ProcessRuntime<'a> {
    // Composition keeps each independently replaceable application port explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executables: &'a dyn ExecutableProfileResolver,
        environments: &'a dyn EnvironmentProfileResolver,
        networks: &'a dyn NetworkProfileVerifier,
        enforced_networks: Vec<EnforcedNetworkProfile>,
        resolver: &'a dyn CapabilityResolver,
        executor_fence: &'a ProcessFenceAuthority,
        launcher: &'a dyn ProcessLauncher,
        process_bindings: &'a dyn ProcessExecutionBindingStore,
    ) -> Result<Self, PortError> {
        for (index, profile) in enforced_networks.iter().enumerate() {
            networks.verify(profile)?;
            if enforced_networks[..index]
                .iter()
                .any(|registered| registered.profile == profile.profile)
            {
                return Err(invalid_input());
            }
        }
        Ok(Self {
            executables,
            environments,
            networks,
            enforced_networks,
            resolver,
            executor_fence,
            launcher,
            process_bindings,
        })
    }

    pub fn execute(
        &self,
        execution_id: ToolExecutionId,
        approved: ApprovedProcessRequest,
    ) -> Result<ProcessReceipt, PortError> {
        let process = approved.process();
        if process.trust_tier() != ProcessTrustTier::IsolatedWorker
            || !approved.expected_reads().is_empty()
            || process
                .argv()
                .iter()
                .any(|argument| argument.starts_with('@'))
        {
            return Err(permission_denied());
        }

        let executable_id = match process.executable() {
            CapabilityRef::Toolchain(executable) => executable.name(),
            _ => return Err(permission_denied()),
        };
        let executable = self.executables.resolve_registered(executable_id)?;
        if &executable != approved.approved_executable() {
            return Err(integrity_failure());
        }
        let binding = process.binding();
        let environment = self.environments.resolve(
            binding.environment_profile().name(),
            binding.environment_profile().digest(),
        )?;
        let network = self
            .enforced_networks
            .iter()
            .find(|profile| profile.profile == process.network())
            .cloned()
            .ok_or_else(permission_denied)?;
        self.networks.verify(&network)?;

        let resolved_cwd = self.resolver.resolve(CapabilityRequest {
            task_id: binding.task_id().clone(),
            capability: process.cwd().clone(),
        })?;
        if resolved_cwd.capability != *process.cwd()
            || resolved_cwd.capability.worktree_task_id() != Some(binding.task_id())
        {
            return Err(integrity_failure());
        }

        let fencing_token = process
            .executor_fencing_token()
            .ok_or_else(permission_denied)?;
        let executor_claim = LeaseClaim::new(
            binding.task_id().clone(),
            binding.run_id().clone(),
            fencing_token,
        );
        let limits = process_limits(&approved, binding.timeout_ms())?;
        let expected_writes = self.resolve_expected_writes(
            binding.task_id(),
            &resolved_cwd.root_identity,
            process.expected_writes(),
        )?;
        let authorized = AuthorizedProcessRequest {
            execution_id,
            trust_tier: process.trust_tier(),
            executable: executable.executable().clone(),
            argv: process.argv().to_vec(),
            cwd: ProcessWorkingDirectory::IsolatedWorktree(resolved_cwd),
            environment,
            network,
            timeout_ms: binding.timeout_ms(),
            limits,
            expected_writes,
            executor_claim: executor_claim.clone(),
            executor_fence: self.executor_fence.binding(),
        };

        let _retained_executable = self.executables.verify_and_retain(&authorized.executable)?;
        self.networks.verify(&authorized.network)?;
        self.executor_fence.assert_current(executor_claim)?;
        let authority = self
            .process_bindings
            .load_claimed_authority(&authorized.execution_id)?;
        if authority.execution_id() != &authorized.execution_id
            || authority.owner_run_id() != binding.run_id()
            || authority.executor_fencing_token() != Some(fencing_token)
        {
            return Err(integrity_failure());
        }
        let approved_writes = authorized.expected_writes.clone();
        let mut receipt = self
            .launcher
            .execute(authorized, &authority, self.process_bindings)?;
        receipt.observed_writes =
            validate_and_order_process_writes(&approved_writes, receipt.observed_writes)?;
        Ok(receipt)
    }

    pub fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        self.launcher.cancel(execution_id)
    }

    pub fn terminate_retained_process(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        self.launcher.terminate_retained_process(binding)
    }

    fn resolve_expected_writes(
        &self,
        task_id: &TaskId,
        cwd_root_identity: &local_agent_terminal_application::CapabilityRootIdentity,
        expected_writes: &[ExpectedWrite],
    ) -> Result<Vec<AuthorizedExpectedWrite>, PortError> {
        expected_writes
            .iter()
            .map(|expected| {
                let resolved = self.resolver.resolve(CapabilityRequest {
                    task_id: task_id.clone(),
                    capability: expected.capability().clone(),
                })?;
                let authorized = AuthorizedExpectedWrite::new(task_id, expected, resolved)
                    .map_err(|_| integrity_failure())?;
                if authorized.root_identity() != cwd_root_identity {
                    return Err(integrity_failure());
                }
                Ok(authorized)
            })
            .collect()
    }
}

impl ApprovedProcessExecutor for ProcessRuntime<'_> {
    fn execute(
        &self,
        execution_id: ToolExecutionId,
        request: ApprovedProcessRequest,
        _authority: Option<&local_agent_terminal_application::ToolExecutionClaimAuthority>,
    ) -> Result<ProcessReceipt, PortError> {
        Self::execute(self, execution_id, request)
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        Self::cancel(self, execution_id)
    }

    fn terminate_retained_process(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        Self::terminate_retained_process(self, binding)
    }
}

impl ToolControlSelfTest for ProcessRuntime<'_> {
    fn verify_controls(&self) -> Result<(), PortError> {
        self.executables.verify_controls()?;
        self.environments.verify_controls()?;
        for profile in &self.enforced_networks {
            self.networks.verify(profile)?;
        }
        self.launcher.verify_controls()
    }
}

fn process_limits(
    request: &ApprovedProcessRequest,
    timeout_ms: u64,
) -> Result<ProcessLimits, PortError> {
    let limits = ProcessLimits {
        memory_limit_bytes: request
            .memory_limit_bytes()
            .unwrap_or(DEFAULT_MEMORY_LIMIT_BYTES),
        cpu_time_limit_ms: request.cpu_time_limit_ms().unwrap_or(timeout_ms),
        max_stdout_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
        max_stderr_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
        max_active_processes: DEFAULT_MAX_ACTIVE_PROCESSES,
        disk_write_limit_bytes: request.disk_write_limit_bytes(),
    };
    if limits.memory_limit_bytes == 0
        || limits.cpu_time_limit_ms == 0
        || limits.max_stdout_bytes == 0
        || limits.max_stderr_bytes == 0
        || limits.max_active_processes == 0
        || limits.disk_write_limit_bytes == Some(0)
        || limits.memory_limit_bytes > MAX_SAFE_INTEGER
        || limits.cpu_time_limit_ms > MAX_SAFE_INTEGER
        || limits
            .disk_write_limit_bytes
            .is_some_and(|limit| limit > MAX_SAFE_INTEGER)
    {
        return Err(invalid_input());
    }
    Ok(limits)
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
