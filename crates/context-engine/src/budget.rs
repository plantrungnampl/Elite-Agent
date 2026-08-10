use std::collections::BTreeMap;

use local_agent_terminal_application::{PortError, Retryability, SafeErrorClassification};
use local_agent_terminal_domain::ContextBudget;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackageSegment {
    Instructions,
    Task,
    SharedDecisions,
    ActiveThread,
    Evidence,
}

impl PackageSegment {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Instructions => "instructions",
            Self::Task => "task",
            Self::SharedDecisions => "shared-decisions",
            Self::ActiveThread => "active-thread",
            Self::Evidence => "evidence",
        }
    }
}

pub struct ByteTokenV1;

impl ByteTokenV1 {
    pub fn units(value: &str) -> u64 {
        u64::try_from(value.len()).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone)]
pub struct RoleBudgetAllocation {
    input_limit: u64,
    segment_limits: BTreeMap<PackageSegment, u64>,
}

impl RoleBudgetAllocation {
    pub fn new(role: &str, budget: ContextBudget) -> Result<Self, PortError> {
        if role.trim().is_empty() || role.len() > 256 || role.contains('\0') {
            return Err(invalid());
        }
        let input_limit = budget
            .max_tokens()
            .checked_sub(budget.reserved_response_tokens())
            .ok_or_else(invalid)?;
        let percentages = match role.trim().to_ascii_lowercase().as_str() {
            "verifier" | "critic" | "security-critic" => [8, 12, 10, 15, 45],
            "lead" => [8, 12, 20, 25, 25],
            _ => [8, 12, 15, 20, 35],
        };
        let segments = [
            PackageSegment::Instructions,
            PackageSegment::Task,
            PackageSegment::SharedDecisions,
            PackageSegment::ActiveThread,
            PackageSegment::Evidence,
        ];
        let segment_limits = segments
            .into_iter()
            .zip(percentages)
            .map(|(segment, percentage)| (segment, input_limit.saturating_mul(percentage) / 100))
            .collect();
        Ok(Self {
            input_limit,
            segment_limits,
        })
    }

    pub const fn input_limit(&self) -> u64 {
        self.input_limit
    }

    pub fn segment_limit(&self, segment: PackageSegment) -> u64 {
        self.segment_limits.get(&segment).copied().unwrap_or(0)
    }

    pub fn total_segment_limit(&self) -> u64 {
        self.segment_limits.values().copied().sum()
    }
}

fn invalid() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
