
pub fn bind_tool_approval_payload(
    payload: ToolApprovalPayloadV1,
    request: &ApprovedProcessRequest,
) -> Result<BoundToolApproval, PortError> {
    let payload = bind_process_request(payload, request)?;
    canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone()))?;
    Ok(BoundToolApproval {
        payload,
        request_binding_digest: canonical_tool_request_binding(request)?,
    })
}

fn bind_process_request(
    mut payload: ToolApprovalPayloadV1,
    request: &ApprovedProcessRequest,
) -> Result<ToolApprovalPayloadV1, PortError> {
    let process = &request.process;
    let binding = process.binding();
    payload.task_id = binding.task_id().as_str().to_owned();
    payload.operation = process_approval_operation(request)?;
    payload.workspace_version = binding.workspace_version().get();
    Ok(payload)
}

pub(crate) fn process_approval_operation(
    request: &ApprovedProcessRequest,
) -> Result<ToolApprovalOperationV1, PortError> {
    let process = request.process();
    let binding = process.binding();
    let approved_executable = approved_executable_identity(request)?;
    Ok(ToolApprovalOperationV1 {
        run_id: binding.run_id().as_str().to_owned(),
        plan_step_id: binding.plan_step_id().as_str().to_owned(),
        tool: "process.exec".to_owned(),
        executable_digest: Some(approved_executable.executable().sha256.as_str().to_owned()),
        arguments_digest: canonical_process_arguments_digest(process)?.to_string(),
        script_digest: None,
        cwd_capability: logical_capability(process.cwd()),
        environment_profile_digest: binding.environment_profile().digest().as_str().to_owned(),
        network_profile: network_profile(process.network()).to_owned(),
        expected_writes: process
            .expected_writes()
            .iter()
            .map(|write| logical_capability(write.capability()))
            .collect(),
        executor_fencing_token: process.executor_fencing_token().map(FencingToken::get),
    })
}

fn canonical_process_arguments_digest(
    request: &ProcessToolRequest,
) -> Result<Sha256Digest, PortError> {
    let value = json!({
        "schema": "process-argv.v1",
        "argv": request.argv(),
    });
    let canonical_bytes = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    Sha256Digest::new(sha256_digest(&canonical_bytes)).map_err(|_| invalid_input())
}

pub fn canonical_tool_request(request: &ToolRequest) -> Result<ImmutableToolRequest, PortError> {
    let wire = RawToolRequest::from(request);
    let canonical_bytes = serde_json_canonicalizer::to_vec(&wire).map_err(|_| invalid_input())?;
    immutable_tool_request(request.clone(), canonical_bytes)
}

pub fn parse_tool_request(bytes: &[u8]) -> Result<ImmutableToolRequest, PortError> {
    let wire: RawToolRequest = serde_json::from_slice(bytes).map_err(|_| invalid_input())?;
    let request = ToolRequest::try_from(wire)?;
    let canonical = canonical_tool_request(&request)?;
    if canonical.canonical_bytes() != bytes {
        return Err(invalid_input());
    }
    Ok(canonical)
}

fn immutable_tool_request(
    request: ToolRequest,
    canonical_bytes: Vec<u8>,
) -> Result<ImmutableToolRequest, PortError> {
    let digest = Sha256Digest::new(sha256_digest(&canonical_bytes)).map_err(|_| invalid_input())?;
    Ok(ImmutableToolRequest {
        request,
        canonical_bytes,
        binding_digest: ToolRequestBindingDigest(digest),
    })
}

fn canonical_tool_request_binding(
    request: &ApprovedProcessRequest,
) -> Result<ToolRequestBindingDigest, PortError> {
    validate_approved_process_request(request)?;
    let canonical_bytes = serde_json_canonicalizer::to_vec(&RawProcessRequest::from(request))
        .map_err(|_| invalid_input())?;
    Sha256Digest::new(sha256_digest(&canonical_bytes))
        .map(ToolRequestBindingDigest)
        .map_err(|_| invalid_input())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawToolRequest {
    schema: String,
    execution_id: String,
    process: RawProcessRequest,
    policy: RawPolicyContext,
}

impl From<&ToolRequest> for RawToolRequest {
    fn from(request: &ToolRequest) -> Self {
        Self {
            schema: "tool-request.v1".to_owned(),
            execution_id: request.execution_id().as_str().to_owned(),
            process: RawProcessRequest::from(request.process()),
            policy: RawPolicyContext::from(request.policy()),
        }
    }
}

impl TryFrom<RawToolRequest> for ToolRequest {
    type Error = PortError;

    fn try_from(raw: RawToolRequest) -> Result<Self, Self::Error> {
        if raw.schema != "tool-request.v1" {
            return Err(invalid_input());
        }
        Self::new(
            ToolExecutionId::new(raw.execution_id)?,
            ApprovedProcessRequest::try_from(raw.process)?,
            ToolPolicyContext::try_from(raw.policy)?,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawProcessRequest {
    schema: String,
    task_id: String,
    run_id: String,
    plan_step_id: String,
    workflow_phase: String,
    workspace_version: u64,
    environment_profile: RawEnvironmentProfile,
    timeout_ms: u64,
    executable: RawCapability,
    approved_executable: RawApprovedExecutable,
    argv: Vec<String>,
    cwd: RawCapability,
    trust_tier: String,
    network_profile: String,
    expected_reads: Vec<RawCapability>,
    expected_writes: Vec<RawCapability>,
    memory_limit_bytes: Option<u64>,
    cpu_time_limit_ms: Option<u64>,
    disk_write_limit_bytes: Option<u64>,
    executor_fencing_token: Option<u64>,
}

impl From<&ApprovedProcessRequest> for RawProcessRequest {
    fn from(request: &ApprovedProcessRequest) -> Self {
        let process = request.process();
        let binding = process.binding();
        let executable = request.approved_executable();
        Self {
            schema: "authorized-process-request.v1".to_owned(),
            task_id: binding.task_id().as_str().to_owned(),
            run_id: binding.run_id().as_str().to_owned(),
            plan_step_id: binding.plan_step_id().as_str().to_owned(),
            workflow_phase: binding.workflow_phase().as_str().to_owned(),
            workspace_version: binding.workspace_version().get(),
            environment_profile: RawEnvironmentProfile {
                name: binding.environment_profile().name().to_owned(),
                digest: binding.environment_profile().digest().to_string(),
            },
            timeout_ms: binding.timeout_ms(),
            executable: RawCapability::from(process.executable()),
            approved_executable: RawApprovedExecutable::from(executable),
            argv: process.argv().to_vec(),
            cwd: RawCapability::from(process.cwd()),
            trust_tier: trust_tier(process.trust_tier()).to_owned(),
            network_profile: network_profile(process.network()).to_owned(),
            expected_reads: request
                .expected_reads()
                .iter()
                .map(RawCapability::from)
                .collect(),
            expected_writes: process
                .expected_writes()
                .iter()
                .map(|write| RawCapability::from(write.capability()))
                .collect(),
            memory_limit_bytes: request.memory_limit_bytes(),
            cpu_time_limit_ms: request.cpu_time_limit_ms(),
            disk_write_limit_bytes: request.disk_write_limit_bytes(),
            executor_fencing_token: process.executor_fencing_token().map(FencingToken::get),
        }
    }
}

impl TryFrom<RawProcessRequest> for ApprovedProcessRequest {
    type Error = PortError;

    fn try_from(raw: RawProcessRequest) -> Result<Self, Self::Error> {
        if raw.schema != "authorized-process-request.v1"
            || raw.expected_writes.len() > MAX_PROCESS_WRITE_SCOPES
        {
            return Err(invalid_input());
        }
        let task_id = TaskId::new(raw.task_id).map_err(|_| invalid_input())?;
        let binding = ProcessBinding::new(
            task_id,
            RunId::new(raw.run_id).map_err(|_| invalid_input())?,
            PlanStepId::new(raw.plan_step_id).map_err(|_| invalid_input())?,
            Phase::from_str(&raw.workflow_phase).map_err(|_| invalid_input())?,
            WorkspaceVersion::new(raw.workspace_version),
            EnvironmentProfile::new(
                raw.environment_profile.name,
                Sha256Digest::new(raw.environment_profile.digest).map_err(|_| invalid_input())?,
            )
            .map_err(|_| invalid_input())?,
            raw.timeout_ms,
        )
        .map_err(|_| invalid_input())?;
        let expected_writes = raw
            .expected_writes
            .into_iter()
            .map(CapabilityRef::try_from)
            .map(|capability| {
                capability.and_then(|capability| {
                    ExpectedWrite::new(capability).map_err(|_| invalid_input())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let invocation = ProcessInvocation::new(
            CapabilityRef::try_from(raw.executable)?,
            raw.argv,
            CapabilityRef::try_from(raw.cwd)?,
            parse_process_trust_tier(&raw.trust_tier)?,
            parse_network_profile(&raw.network_profile)?,
            expected_writes,
            raw.executor_fencing_token
                .map(|token| FencingToken::new(token).map_err(|_| invalid_input()))
                .transpose()?,
        )
        .map_err(|_| invalid_input())?;
        let process = ProcessToolRequest::new(binding, invocation).map_err(|_| invalid_input())?;
        let expected_reads = raw
            .expected_reads
            .into_iter()
            .map(CapabilityRef::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            ApprovedExecutableIdentity::try_from(raw.approved_executable)?,
            process,
            expected_reads,
            raw.memory_limit_bytes,
            raw.cpu_time_limit_ms,
            raw.disk_write_limit_bytes,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEnvironmentProfile {
    name: String,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawApprovedExecutable {
    toolchain_id: String,
    version: String,
    canonical_path: String,
    sha256: String,
    file_identity: String,
}

impl From<&ApprovedExecutableIdentity> for RawApprovedExecutable {
    fn from(identity: &ApprovedExecutableIdentity) -> Self {
        let executable = identity.executable();
        Self {
            toolchain_id: executable.toolchain_id.clone(),
            version: identity.version().to_owned(),
            canonical_path: executable.canonical_path.to_string_lossy().into_owned(),
            sha256: executable.sha256.to_string(),
            file_identity: executable.file_identity.as_str().to_owned(),
        }
    }
}

impl TryFrom<RawApprovedExecutable> for ApprovedExecutableIdentity {
    type Error = PortError;

    fn try_from(raw: RawApprovedExecutable) -> Result<Self, Self::Error> {
        Self::new(
            ResolvedExecutable {
                canonical_path: PathBuf::from(raw.canonical_path),
                sha256: Sha256Digest::new(raw.sha256).map_err(|_| invalid_input())?,
                file_identity: ExecutableFileIdentity::new(raw.file_identity)?,
                toolchain_id: raw.toolchain_id,
            },
            raw.version,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum RawCapability {
    Source { revision: String, path: String },
    Artifact { artifact_id: String },
    Worktree { task_id: String, path: String },
    Toolchain { name: String },
}

impl From<&CapabilityRef> for RawCapability {
    fn from(capability: &CapabilityRef) -> Self {
        match capability {
            CapabilityRef::Source(value) => Self::Source {
                revision: value.revision().to_owned(),
                path: value.path().to_owned(),
            },
            CapabilityRef::Artifact(value) => Self::Artifact {
                artifact_id: value.artifact_id().as_str().to_owned(),
            },
            CapabilityRef::Worktree(value) => Self::Worktree {
                task_id: value.task_id().as_str().to_owned(),
                path: value.path().to_owned(),
            },
            CapabilityRef::Toolchain(value) => Self::Toolchain {
                name: value.name().to_owned(),
            },
        }
    }
}

impl TryFrom<RawCapability> for CapabilityRef {
    type Error = PortError;

    fn try_from(raw: RawCapability) -> Result<Self, Self::Error> {
        match raw {
            RawCapability::Source { revision, path } => Self::source(revision, path),
            RawCapability::Artifact { artifact_id } => {
                Self::artifact(ArtifactId::new(artifact_id).map_err(|_| invalid_input())?)
            }
            RawCapability::Worktree { task_id, path } => {
                Self::worktree(TaskId::new(task_id).map_err(|_| invalid_input())?, path)
            }
            RawCapability::Toolchain { name } => Self::toolchain(name),
        }
        .map_err(|_| invalid_input())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicyContext {
    actor: RawPolicyActor,
    action: String,
    resource: RawPolicyResource,
    task_risk: String,
    purpose: String,
    policy_snapshot_digest: String,
}

impl From<&ToolPolicyContext> for RawPolicyContext {
    fn from(policy: &ToolPolicyContext) -> Self {
        Self {
            actor: RawPolicyActor {
                connection_id: policy.actor().connection_id.clone(),
                agent_id: policy.actor().agent_id.clone(),
                trust_tier: actor_trust_tier(policy.actor().trust_tier).to_owned(),
                locality: actor_locality(policy.actor().locality).to_owned(),
            },
            action: policy.action().as_str().to_owned(),
            resource: RawPolicyResource {
                capability: RawCapability::from(&policy.resource().capability),
                content_digest: policy.resource().content_digest.to_string(),
                resource_class: resource_class(policy.resource().resource_class).to_owned(),
            },
            task_risk: task_risk(policy.task_risk()).to_owned(),
            purpose: policy.purpose().to_owned(),
            policy_snapshot_digest: policy.policy_snapshot_digest().to_string(),
        }
    }
}

impl TryFrom<RawPolicyContext> for ToolPolicyContext {
    type Error = PortError;

    fn try_from(raw: RawPolicyContext) -> Result<Self, Self::Error> {
        Self::new(
            PolicyActor {
                connection_id: raw.actor.connection_id,
                agent_id: raw.actor.agent_id,
                trust_tier: parse_actor_trust_tier(&raw.actor.trust_tier)?,
                locality: parse_actor_locality(&raw.actor.locality)?,
            },
            PolicyAction::new(raw.action).map_err(|_| invalid_input())?,
            PolicyResource {
                capability: CapabilityRef::try_from(raw.resource.capability)?,
                content_digest: Sha256Digest::new(raw.resource.content_digest)
                    .map_err(|_| invalid_input())?,
                resource_class: parse_resource_class(&raw.resource.resource_class)?,
            },
            parse_task_risk(&raw.task_risk)?,
            raw.purpose,
            Sha256Digest::new(raw.policy_snapshot_digest).map_err(|_| invalid_input())?,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicyActor {
    connection_id: String,
    agent_id: String,
    trust_tier: String,
    locality: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicyResource {
    capability: RawCapability,
    content_digest: String,
    resource_class: String,
}

const fn actor_trust_tier(value: TrustTier) -> &'static str {
    value.as_str()
}

const fn actor_locality(value: ActorLocality) -> &'static str {
    match value {
        ActorLocality::Local => "local",
        ActorLocality::Cloud => "cloud",
    }
}

const fn resource_class(value: ResourceClass) -> &'static str {
    match value {
        ResourceClass::Public => "public",
        ResourceClass::InternalCode => "internal_code",
        ResourceClass::Restricted => "restricted",
        ResourceClass::Secret => "secret",
    }
}

const fn task_risk(value: TaskRisk) -> &'static str {
    match value {
        TaskRisk::Low => "low",
        TaskRisk::Medium => "medium",
        TaskRisk::High => "high",
        TaskRisk::Critical => "critical",
    }
}

fn parse_process_trust_tier(value: &str) -> Result<ProcessTrustTier, PortError> {
    match value {
        "brokered_process" => Ok(ProcessTrustTier::BrokeredProcess),
        "isolated_worker" => Ok(ProcessTrustTier::IsolatedWorker),
        _ => Err(invalid_input()),
    }
}

fn parse_network_profile(value: &str) -> Result<NetworkProfile, PortError> {
    match value {
        "denied" => Ok(NetworkProfile::Denied),
        "provider_endpoint_only" => Ok(NetworkProfile::ProviderEndpointOnly),
        "approved_destinations" => Ok(NetworkProfile::ApprovedDestinations),
        _ => Err(invalid_input()),
    }
}

fn parse_actor_trust_tier(value: &str) -> Result<TrustTier, PortError> {
    match value {
        "core_adapter" => Ok(TrustTier::CoreAdapter),
        "brokered_process" => Ok(TrustTier::BrokeredProcess),
        "isolated_worker" => Ok(TrustTier::IsolatedWorker),
        "full_access_legacy" => Ok(TrustTier::FullAccessLegacy),
        _ => Err(invalid_input()),
    }
}

fn parse_actor_locality(value: &str) -> Result<ActorLocality, PortError> {
    match value {
        "local" => Ok(ActorLocality::Local),
        "cloud" => Ok(ActorLocality::Cloud),
        _ => Err(invalid_input()),
    }
}

fn parse_resource_class(value: &str) -> Result<ResourceClass, PortError> {
    match value {
        "public" => Ok(ResourceClass::Public),
        "internal_code" => Ok(ResourceClass::InternalCode),
        "restricted" => Ok(ResourceClass::Restricted),
        "secret" => Ok(ResourceClass::Secret),
        _ => Err(invalid_input()),
    }
}

fn parse_task_risk(value: &str) -> Result<TaskRisk, PortError> {
    match value {
        "low" => Ok(TaskRisk::Low),
        "medium" => Ok(TaskRisk::Medium),
        "high" => Ok(TaskRisk::High),
        "critical" => Ok(TaskRisk::Critical),
        _ => Err(invalid_input()),
    }
}

pub fn canonical_policy_binding_digest(
    request: &PolicyRequest,
) -> Result<PolicyRequestBindingDigest, PortError> {
    let value = json!({
        "schema": "policy-request-binding.v1",
        "taskId": request.task_id.as_str(),
        "actor": {
            "connectionId": request.actor.connection_id,
            "agentId": request.actor.agent_id,
            "trustTier": actor_trust_tier(request.actor.trust_tier),
            "locality": actor_locality(request.actor.locality),
        },
        "action": request.action.as_str(),
        "resource": {
            "capability": capability_value(&request.resource.capability),
            "contentDigest": request.resource.content_digest.as_str(),
            "resourceClass": resource_class(request.resource.resource_class),
        },
        "taskRisk": task_risk(request.task_risk),
        "workflowPhase": request.workflow_phase,
        "purpose": request.purpose,
        "policySnapshotDigest": request.policy_snapshot_digest.as_str(),
    });
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    Sha256Digest::new(sha256_digest(&canonical))
        .map(PolicyRequestBindingDigest::new)
        .map_err(|_| invalid_input())
}

fn approved_executable_identity(
    request: &ApprovedProcessRequest,
) -> Result<&ApprovedExecutableIdentity, PortError> {
    let CapabilityRef::Toolchain(toolchain) = request.process.executable() else {
        return Err(invalid_input());
    };
    if toolchain.name() != request.approved_executable.executable().toolchain_id {
        return Err(invalid_input());
    }
    Ok(&request.approved_executable)
}

fn validate_approved_process_request(request: &ApprovedProcessRequest) -> Result<(), PortError> {
    approved_executable_identity(request)?;
    validate_safe_integer_fields(request)?;
    if request.process.expected_writes().len() > MAX_PROCESS_WRITE_SCOPES
        || request.memory_limit_bytes == Some(0)
        || request.cpu_time_limit_ms == Some(0)
        || request.disk_write_limit_bytes == Some(0)
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn valid_registration_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && !value.contains(['\0', '/', '\\', ':', '\r', '\n'])
}

fn valid_canonical_executable_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    if text.contains('\0')
        || text
            .split(['/', '\\'])
            .any(|component| matches!(component, "." | ".."))
    {
        return false;
    }

    let mut components = path.components();
    #[cfg(windows)]
    {
        let Some(Component::Prefix(prefix)) = components.next() else {
            return false;
        };
        if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
            || !matches!(components.next(), Some(Component::RootDir))
        {
            return false;
        }
    }
    #[cfg(not(windows))]
    if !matches!(components.next(), Some(Component::RootDir)) {
        return false;
    }

    components.all(|component| match component {
        Component::Normal(name) => {
            #[cfg(windows)]
            {
                name.to_str().is_some_and(|name| !name.contains(':'))
            }
            #[cfg(not(windows))]
            {
                true
            }
        }
        _ => false,
    })
}

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_len && !value.contains('\0')
}

fn validate_safe_integer_fields(request: &ApprovedProcessRequest) -> Result<(), PortError> {
    let process = &request.process;
    let binding = process.binding();
    let unsafe_integer = [
        binding.workspace_version().get(),
        binding.timeout_ms(),
        process
            .executor_fencing_token()
            .map(FencingToken::get)
            .unwrap_or_default(),
        request.memory_limit_bytes.unwrap_or_default(),
        request.cpu_time_limit_ms.unwrap_or_default(),
        request.disk_write_limit_bytes.unwrap_or_default(),
    ]
    .into_iter()
    .any(|value| value > MAX_SAFE_INTEGER);
    if unsafe_integer {
        return Err(invalid_input());
    }
    Ok(())
}

fn capability_value(capability: &CapabilityRef) -> Value {
    match capability {
        CapabilityRef::Source(value) => {
            json!({"kind": "source", "revision": value.revision(), "path": value.path()})
        }
        CapabilityRef::Artifact(value) => {
            json!({"kind": "artifact", "artifactId": value.artifact_id().as_str()})
        }
        CapabilityRef::Worktree(value) => {
            json!({"kind": "worktree", "taskId": value.task_id().as_str(), "path": value.path()})
        }
        CapabilityRef::Toolchain(value) => {
            json!({"kind": "toolchain", "name": value.name()})
        }
    }
}

pub(crate) fn logical_capability(capability: &CapabilityRef) -> String {
    match capability {
        CapabilityRef::Source(value) => {
            format!("source:{}:{}", value.revision(), value.path())
        }
        CapabilityRef::Artifact(value) => format!("artifact:{}", value.artifact_id().as_str()),
        CapabilityRef::Worktree(value) if value.path() == "." => {
            format!("worktree:{}", value.task_id().as_str())
        }
        CapabilityRef::Worktree(value) => {
            format!("worktree:{}:{}", value.task_id().as_str(), value.path())
        }
        CapabilityRef::Toolchain(value) => format!("toolchain:{}", value.name()),
    }
}

const fn trust_tier(value: ProcessTrustTier) -> &'static str {
    match value {
        ProcessTrustTier::BrokeredProcess => "brokered_process",
        ProcessTrustTier::IsolatedWorker => "isolated_worker",
    }
}

const fn network_profile(value: NetworkProfile) -> &'static str {
    match value {
        NetworkProfile::Denied => "denied",
        NetworkProfile::ProviderEndpointOnly => "provider_endpoint_only",
        NetworkProfile::ApprovedDestinations => "approved_destinations",
    }
}
