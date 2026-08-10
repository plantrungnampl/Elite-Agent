#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::Write;

use local_agent_terminal_application::{
    bind_disclosure_channel, DisclosurePolicyEvaluator,
    DisclosureRequest as ApplicationDisclosureRequest, PolicyApprovalBinding,
    PolicyApprovedDisclosure, PolicyDecision, PolicyEvaluator, PortError, Retryability,
    SafeErrorClassification,
};
use local_agent_terminal_domain::{PolicyRequest, Sha256Digest};
use serde::Deserialize;
use sha2::{Digest, Sha256};

mod bundle;
mod classification;
mod redaction;

pub use classification::PolicyContextSourceClassifier;
pub use redaction::{RedactionEntry, RedactionReport};

use classification::PolicyRuleV1;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyBundleV1 {
    version: u16,
    rules: Vec<PolicyRuleV1>,
}

impl PolicyBundleV1 {
    fn validate(&self) -> Result<(), PortError> {
        if self.version != 1 || self.rules.is_empty() {
            return Err(invalid_input());
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty()
                || rule.id.len() > 256
                || rule.id.contains('\0')
                || rule.action.as_ref().is_some_and(|action| {
                    local_agent_terminal_domain::PolicyAction::new(action).is_err()
                })
                || !ids.insert(&rule.id)
                || rule
                    .redactions
                    .iter()
                    .any(|directive| directive != "secret_scanner")
            {
                return Err(invalid_input());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VersionedPolicyEngine {
    bundle: PolicyBundleV1,
    snapshot_digest: Sha256Digest,
    scan_failure: Option<ScanFailurePoint>,
}

impl VersionedPolicyEngine {
    pub fn from_json(raw: &str) -> Result<Self, PortError> {
        let (bundle, snapshot_digest) = bundle::parse_bundle(raw)?;
        Ok(Self {
            bundle,
            snapshot_digest,
            scan_failure: None,
        })
    }

    pub const fn snapshot_digest(&self) -> &Sha256Digest {
        &self.snapshot_digest
    }

    pub fn with_scan_failure_for_test(mut self, failure: ScanFailurePoint) -> Self {
        self.scan_failure = Some(failure);
        self
    }

    pub fn disclose(&self, request: DisclosureRequest) -> Result<EvaluatedDisclosure, PortError> {
        let original_digest = digest_bytes(&request.bytes)?;
        if request.policy_request.resource.content_digest != original_digest {
            return Err(denied());
        }
        let decision = self.evaluate(request.policy_request)?;
        if matches!(
            decision.draft.effect(),
            local_agent_terminal_domain::PolicyEffect::Deny
        ) {
            return Ok(EvaluatedDisclosure {
                decision,
                original_digest,
                effective_bytes: None,
                effective_digest: None,
                redaction_report: empty_report()?,
                approval_binding: None,
            });
        }

        let scan = self.scan(&request.bytes, ScanFailurePoint::Initial)?;
        let redacts = decision.draft.redactions().contains(&"secret_scanner");
        let (effective_bytes, redaction_report) = if scan.is_empty() {
            (request.bytes, empty_report()?)
        } else if redacts {
            redaction::redact(&request.bytes, scan)?
        } else {
            return Err(denied());
        };

        if !self
            .scan(&effective_bytes, ScanFailurePoint::FinalRescan)?
            .is_empty()
        {
            return Err(denied());
        }
        let effective_digest = digest_bytes(&effective_bytes)?;
        let approval_binding = matches!(
            decision.draft.effect(),
            local_agent_terminal_domain::PolicyEffect::RequireApproval
        )
        .then_some(ApprovalBinding {
            effective_payload_digest: effective_digest.clone(),
            redaction_report_digest: redaction_report.digest.clone(),
        });
        Ok(EvaluatedDisclosure {
            decision,
            original_digest,
            effective_bytes: Some(effective_bytes),
            effective_digest: Some(effective_digest),
            redaction_report,
            approval_binding,
        })
    }

    fn scan(
        &self,
        bytes: &[u8],
        point: ScanFailurePoint,
    ) -> Result<Vec<redaction::SecretMatch>, PortError> {
        if self.scan_failure == Some(point) {
            return Err(denied());
        }
        Ok(redaction::scan(bytes))
    }
}

impl PolicyEvaluator for VersionedPolicyEngine {
    fn evaluate(&self, request: PolicyRequest) -> Result<PolicyDecision, PortError> {
        if request.policy_snapshot_digest != self.snapshot_digest {
            return Err(denied());
        }
        self.bundle.evaluate(request)
    }
}

impl DisclosurePolicyEvaluator for VersionedPolicyEngine {
    fn disclose(
        &self,
        request: ApplicationDisclosureRequest,
    ) -> Result<PolicyApprovedDisclosure, PortError> {
        let application_channel = request.channel;
        let disclosure = VersionedPolicyEngine::disclose(
            self,
            DisclosureRequest::new(
                request.policy_request,
                match request.channel {
                    local_agent_terminal_application::DisclosureChannel::IndexMetadata => {
                        DisclosureChannel::ListMetadata
                    }
                    local_agent_terminal_application::DisclosureChannel::IndexContent => {
                        DisclosureChannel::Artifact
                    }
                    local_agent_terminal_application::DisclosureChannel::RetrievedItem => {
                        DisclosureChannel::DirectRead
                    }
                    local_agent_terminal_application::DisclosureChannel::FinalContextPackage => {
                        DisclosureChannel::FinalSerializedPayload
                    }
                    local_agent_terminal_application::DisclosureChannel::FileRead => {
                        DisclosureChannel::DirectRead
                    }
                    local_agent_terminal_application::DisclosureChannel::ListMetadata => {
                        DisclosureChannel::ListMetadata
                    }
                    local_agent_terminal_application::DisclosureChannel::GitStatus => {
                        DisclosureChannel::GitStatus
                    }
                    local_agent_terminal_application::DisclosureChannel::GitDiff => {
                        DisclosureChannel::GitDiff
                    }
                    local_agent_terminal_application::DisclosureChannel::Diagnostic => {
                        DisclosureChannel::Diagnostic
                    }
                    local_agent_terminal_application::DisclosureChannel::Artifact => {
                        DisclosureChannel::Artifact
                    }
                    local_agent_terminal_application::DisclosureChannel::Summary => {
                        DisclosureChannel::Summary
                    }
                    local_agent_terminal_application::DisclosureChannel::FinalSerializedPayload => {
                        DisclosureChannel::FinalSerializedPayload
                    }
                },
                request.bytes,
            ),
        )?;
        Ok(PolicyApprovedDisclosure {
            decision: bind_disclosure_channel(disclosure.decision, application_channel)?,
            channel: application_channel,
            original_digest: disclosure.original_digest,
            effective_bytes: disclosure.effective_bytes,
            effective_digest: disclosure.effective_digest,
            redaction_report_digest: disclosure.redaction_report.digest,
            approval_binding: disclosure
                .approval_binding
                .map(|binding| PolicyApprovalBinding {
                    effective_payload_digest: binding.effective_payload_digest,
                    redaction_report_digest: binding.redaction_report_digest,
                }),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureChannel {
    DirectRead,
    ListMetadata,
    GitDiff,
    GitStatus,
    Diagnostic,
    Artifact,
    Summary,
    FinalSerializedPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanFailurePoint {
    Initial,
    FinalRescan,
}

impl DisclosureChannel {
    pub const ALL: [Self; 8] = [
        Self::DirectRead,
        Self::ListMetadata,
        Self::GitDiff,
        Self::GitStatus,
        Self::Diagnostic,
        Self::Artifact,
        Self::Summary,
        Self::FinalSerializedPayload,
    ];
}

#[derive(Debug, Clone)]
pub struct DisclosureRequest {
    pub policy_request: PolicyRequest,
    pub channel: DisclosureChannel,
    pub bytes: Vec<u8>,
}

impl DisclosureRequest {
    pub fn new(policy_request: PolicyRequest, channel: DisclosureChannel, bytes: Vec<u8>) -> Self {
        Self {
            policy_request,
            channel,
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBinding {
    pub effective_payload_digest: Sha256Digest,
    pub redaction_report_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatedDisclosure {
    pub decision: PolicyDecision,
    pub original_digest: Sha256Digest,
    pub effective_bytes: Option<Vec<u8>>,
    pub effective_digest: Option<Sha256Digest>,
    pub redaction_report: RedactionReport,
    pub approval_binding: Option<ApprovalBinding>,
}

fn digest_bytes(bytes: &[u8]) -> Result<Sha256Digest, PortError> {
    Sha256Digest::new(sha256_digest(bytes)).map_err(|_| invalid_input())
}

fn empty_report() -> Result<RedactionReport, PortError> {
    let canonical = serde_json_canonicalizer::to_vec(&Vec::<serde_json::Value>::new())
        .map_err(|_| invalid_input())?;
    Ok(RedactionReport {
        entries: Vec::new(),
        digest: digest_bytes(&canonical)?,
    })
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

pub(crate) fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}
