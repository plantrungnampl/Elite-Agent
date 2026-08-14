use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use crate::{Effect, FencingToken, Sequence, WorkflowEvent, WorkspaceVersion};

macro_rules! workflow_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant)),+
                }
            }
        }

        impl FromStr for $name {
            type Err = ParseWorkflowValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|candidate| candidate.as_str() == value)
                    .ok_or_else(|| ParseWorkflowValueError {
                        kind: stringify!($name),
                        value: value.to_owned(),
                    })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum Phase {
    Intake,
    ContextBuild,
    ParallelAnalysis,
    CrossReview,
    PrePlanVerification,
    Synthesis,
    FinalObjection,
    AwaitingPlanApproval,
    Implementation,
    Verification,
    Repair,
    FinalReview,
    AwaitingDeliverableApproval,
    AwaitingWorkspaceApproval,
    AwaitingCommitApproval,
    RefPromotion,
    WorkspaceDirty,
    Completed,
    Cancelled,
    Failed,
}

impl Phase {
    pub const ALL: &'static [Self] = &[
        Self::Intake,
        Self::ContextBuild,
        Self::ParallelAnalysis,
        Self::CrossReview,
        Self::PrePlanVerification,
        Self::Synthesis,
        Self::FinalObjection,
        Self::AwaitingPlanApproval,
        Self::Implementation,
        Self::Verification,
        Self::Repair,
        Self::FinalReview,
        Self::AwaitingDeliverableApproval,
        Self::AwaitingWorkspaceApproval,
        Self::AwaitingCommitApproval,
        Self::RefPromotion,
        Self::WorkspaceDirty,
        Self::Completed,
        Self::Cancelled,
        Self::Failed,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intake => "Intake",
            Self::ContextBuild => "ContextBuild",
            Self::ParallelAnalysis => "ParallelAnalysis",
            Self::CrossReview => "CrossReview",
            Self::PrePlanVerification => "PrePlanVerification",
            Self::Synthesis => "Synthesis",
            Self::FinalObjection => "FinalObjection",
            Self::AwaitingPlanApproval => "AwaitingPlanApproval",
            Self::Implementation => "Implementation",
            Self::Verification => "Verification",
            Self::Repair => "Repair",
            Self::FinalReview => "FinalReview",
            Self::AwaitingDeliverableApproval => "AwaitingDeliverableApproval",
            Self::AwaitingWorkspaceApproval => "AwaitingWorkspaceApproval",
            Self::AwaitingCommitApproval => "AwaitingCommitApproval",
            Self::RefPromotion => "RefPromotion",
            Self::WorkspaceDirty => "WorkspaceDirty",
            Self::Completed => "Completed",
            Self::Cancelled => "Cancelled",
            Self::Failed => "Failed",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

impl FromStr for Phase {
    type Err = ParseWorkflowValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.as_str() == value)
            .ok_or_else(|| ParseWorkflowValueError {
                kind: "Phase",
                value: value.to_owned(),
            })
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

workflow_enum!(Condition {
    Active,
    Paused,
    Blocked,
    BudgetExhausted,
});

workflow_enum!(OperationState {
    None,
    AwaitingApproval,
    Running,
    Cancelling,
    Indeterminate,
});

workflow_enum!(WorkflowProfile {
    Quick,
    Standard,
    HighAssurance,
    ReadOnlyResearch,
});

workflow_enum!(TaskOutcomeMode {
    ReadOnlyDeliverable,
    WorkspaceChange,
    LocalCommit,
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWorkflowValueError {
    kind: &'static str,
    value: String,
}

impl fmt::Display for ParseWorkflowValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown {} value {:?}", self.kind, self.value)
    }
}

impl std::error::Error for ParseWorkflowValueError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowStateSnapshot {
    pub phase: Phase,
    pub condition: Condition,
    pub operation: OperationState,
    pub workflow_profile: WorkflowProfile,
    pub outcome_mode: TaskOutcomeMode,
    pub stream_version: u64,
    pub profile_revision: u64,
    pub workspace_version: u64,
    pub fencing_epoch: u64,
    pub last_transition_event_id: Option<String>,
    pub last_profile_revision_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowState {
    phase: Phase,
    condition: Condition,
    operation: OperationState,
    workflow_profile: WorkflowProfile,
    outcome_mode: TaskOutcomeMode,
    sequence: Sequence,
    profile_revision: u64,
    workspace_version: WorkspaceVersion,
    fencing_epoch: u64,
    last_transition_event_id: Option<String>,
    last_profile_revision_id: Option<String>,
}

impl WorkflowState {
    pub fn new(
        phase: Phase,
        condition: Condition,
        operation: OperationState,
        sequence: Sequence,
        workspace_version: WorkspaceVersion,
        fencing_token: FencingToken,
    ) -> Result<Self, WorkflowError> {
        Self::rehydrate(WorkflowStateSnapshot {
            phase,
            condition,
            operation,
            workflow_profile: WorkflowProfile::Standard,
            outcome_mode: TaskOutcomeMode::WorkspaceChange,
            stream_version: sequence.get(),
            profile_revision: 1,
            workspace_version: workspace_version.get(),
            fencing_epoch: fencing_token.get(),
            last_transition_event_id: None,
            last_profile_revision_id: None,
        })
    }

    pub fn rehydrate(snapshot: WorkflowStateSnapshot) -> Result<Self, WorkflowError> {
        let state = Self {
            phase: snapshot.phase,
            condition: snapshot.condition,
            operation: snapshot.operation,
            workflow_profile: snapshot.workflow_profile,
            outcome_mode: snapshot.outcome_mode,
            sequence: Sequence::new(snapshot.stream_version),
            profile_revision: snapshot.profile_revision,
            workspace_version: WorkspaceVersion::new(snapshot.workspace_version),
            fencing_epoch: snapshot.fencing_epoch,
            last_transition_event_id: snapshot.last_transition_event_id,
            last_profile_revision_id: snapshot.last_profile_revision_id,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn snapshot(&self) -> WorkflowStateSnapshot {
        WorkflowStateSnapshot {
            phase: self.phase,
            condition: self.condition,
            operation: self.operation,
            workflow_profile: self.workflow_profile,
            outcome_mode: self.outcome_mode,
            stream_version: self.sequence.get(),
            profile_revision: self.profile_revision,
            workspace_version: self.workspace_version.get(),
            fencing_epoch: self.fencing_epoch,
            last_transition_event_id: self.last_transition_event_id.clone(),
            last_profile_revision_id: self.last_profile_revision_id.clone(),
        }
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub const fn condition(&self) -> Condition {
        self.condition
    }

    pub const fn operation(&self) -> OperationState {
        self.operation
    }

    pub const fn workflow_profile(&self) -> WorkflowProfile {
        self.workflow_profile
    }

    pub const fn outcome_mode(&self) -> TaskOutcomeMode {
        self.outcome_mode
    }

    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    pub fn stream_version(&self) -> u64 {
        self.sequence.get()
    }

    pub const fn profile_revision(&self) -> u64 {
        self.profile_revision
    }

    pub const fn workspace_version(&self) -> WorkspaceVersion {
        self.workspace_version
    }

    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }

    pub fn last_transition_event_id(&self) -> Option<&str> {
        self.last_transition_event_id.as_deref()
    }

    pub fn last_profile_revision_id(&self) -> Option<&str> {
        self.last_profile_revision_id.as_deref()
    }

    pub(super) fn transition_phase(
        &self,
        phase: Phase,
        effects: &[Effect],
    ) -> Result<Self, WorkflowError> {
        let mut next = self.clone();
        next.phase = phase;
        next.apply_declared_effects(effects)?;
        if next.phase.is_terminal() {
            next.condition = Condition::Active;
            next.operation = OperationState::None;
        }
        next.increment_stream_version()?;
        Ok(next)
    }

    pub(super) fn transition_condition(&self, condition: Condition) -> Result<Self, WorkflowError> {
        let mut next = self.clone();
        next.condition = condition;
        next.increment_stream_version()?;
        Ok(next)
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        if self.phase.is_terminal()
            && (self.condition != Condition::Active || self.operation != OperationState::None)
        {
            return Err(WorkflowError::InvalidTerminalState {
                phase: self.phase,
                condition: self.condition,
                operation: self.operation,
            });
        }
        Ok(())
    }

    fn increment_stream_version(&mut self) -> Result<(), WorkflowError> {
        self.sequence =
            self.sequence
                .checked_increment()
                .ok_or(WorkflowError::VersionOverflow {
                    field: "stream version",
                })?;
        Ok(())
    }

    fn apply_declared_effects(&mut self, effects: &[Effect]) -> Result<(), WorkflowError> {
        if effects
            .iter()
            .any(|effect| effect.as_str() == "increment_workspace_version")
        {
            self.workspace_version = self.workspace_version.checked_increment().ok_or(
                WorkflowError::VersionOverflow {
                    field: "workspace version",
                },
            )?;
        }

        if effects.iter().any(|effect| {
            matches!(
                effect.as_str(),
                "increment_fencing_epoch"
                    | "allocate_executor_lease"
                    | "allocate_new_executor_token"
            )
        }) {
            self.fencing_epoch =
                self.fencing_epoch
                    .checked_add(1)
                    .ok_or(WorkflowError::VersionOverflow {
                        field: "fencing epoch",
                    })?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRequest {
    pub rule_id: String,
    pub event: WorkflowEvent,
    pub guard_evidence_kinds: BTreeSet<String>,
    pub effect_kinds: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    state: WorkflowState,
    effects: Vec<Effect>,
    rule_id: Option<String>,
}

impl Transition {
    pub fn state(&self) -> &WorkflowState {
        &self.state
    }

    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    pub fn rule_id(&self) -> Option<&str> {
        self.rule_id.as_deref()
    }

    pub(super) fn command(state: WorkflowState, effects: Vec<Effect>, rule_id: String) -> Self {
        Self {
            state,
            effects,
            rule_id: Some(rule_id),
        }
    }

    pub(super) fn condition(state: WorkflowState) -> Self {
        Self {
            state,
            effects: Vec::new(),
            rule_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowError {
    InvalidSpecification(String),
    InvalidState(String),
    InvalidTerminalState {
        phase: Phase,
        condition: Condition,
        operation: OperationState,
    },
    TerminalPhase {
        phase: Phase,
    },
    UnknownRuleId {
        rule_id: String,
    },
    RuleSourceMismatch {
        rule_id: String,
        phase: Phase,
    },
    RuleEventMismatch {
        rule_id: String,
        event: WorkflowEvent,
    },
    ProfileNotAllowed {
        rule_id: String,
        profile: WorkflowProfile,
    },
    OutcomeNotAllowed {
        rule_id: String,
        outcome: TaskOutcomeMode,
    },
    GuardEvidenceMismatch {
        rule_id: String,
    },
    EffectKindsMismatch {
        rule_id: String,
    },
    UndeclaredTransition {
        phase: Phase,
        condition: Condition,
        operation: OperationState,
        event: WorkflowEvent,
    },
    GuardNotEvaluated {
        guard: crate::GuardName,
    },
    GuardRejected {
        guard: crate::GuardName,
    },
    VersionOverflow {
        field: &'static str,
    },
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpecification(message) => {
                write!(formatter, "invalid workflow specification: {message}")
            }
            Self::InvalidState(message) => write!(formatter, "invalid workflow state: {message}"),
            Self::InvalidTerminalState {
                phase,
                condition,
                operation,
            } => write!(
                formatter,
                "terminal phase {phase} requires Active/None, got {condition}/{operation}"
            ),
            Self::TerminalPhase { phase } => {
                write!(formatter, "terminal phase {phase} cannot transition")
            }
            Self::UnknownRuleId { rule_id } => write!(formatter, "unknown workflow rule {rule_id}"),
            Self::RuleSourceMismatch { rule_id, phase } => {
                write!(formatter, "rule {rule_id} is not declared from {phase}")
            }
            Self::RuleEventMismatch { rule_id, event } => {
                write!(formatter, "rule {rule_id} does not accept event {event}")
            }
            Self::ProfileNotAllowed { rule_id, profile } => {
                write!(formatter, "rule {rule_id} does not allow profile {profile}")
            }
            Self::OutcomeNotAllowed { rule_id, outcome } => {
                write!(formatter, "rule {rule_id} does not allow outcome {outcome}")
            }
            Self::GuardEvidenceMismatch { rule_id } => {
                write!(
                    formatter,
                    "rule {rule_id} requires its exact guard evidence kinds"
                )
            }
            Self::EffectKindsMismatch { rule_id } => {
                write!(formatter, "rule {rule_id} requires its exact effect kinds")
            }
            Self::UndeclaredTransition {
                phase,
                condition,
                operation,
                event,
            } => write!(
                formatter,
                "event {event} is undeclared from {phase}/{condition}/{operation}"
            ),
            Self::GuardNotEvaluated { guard } => {
                write!(formatter, "guard {guard} was not evaluated")
            }
            Self::GuardRejected { guard } => write!(formatter, "guard {guard} rejected"),
            Self::VersionOverflow { field } => write!(formatter, "{field} overflow"),
        }
    }
}

impl std::error::Error for WorkflowError {}
