use local_agent_terminal_domain::{FencingToken, LeaseClaim, RunId, TaskId};

use crate::PortError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    Active,
    Released,
    Expired,
    Revoked,
    Stale,
}

impl LeaseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Revoked | Self::Stale => "revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "released" => Some(Self::Released),
            "expired" => Some(Self::Expired),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireLease {
    pub task_id: TaskId,
    pub holder_run_id: RunId,
    pub expected_fencing_epoch: u64,
    pub acquired_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeLease {
    pub claim: LeaseClaim,
    pub revoked_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseSnapshot {
    pub task_id: TaskId,
    pub holder_run_id: RunId,
    pub token: FencingToken,
    pub state: LeaseState,
    pub acquired_at: String,
    pub expires_at: String,
    pub released_at: Option<String>,
}

pub trait ExecutorLeaseStore: Send + Sync {
    fn acquire(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError>;
    fn revoke(&self, request: RevokeLease) -> Result<(), PortError>;
    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError>;
    fn assert_current(&self, claim: LeaseClaim) -> Result<(), PortError>;
}

pub struct AcquireExecutorLease<'a> {
    leases: &'a dyn ExecutorLeaseStore,
}

impl<'a> AcquireExecutorLease<'a> {
    pub const fn new(leases: &'a dyn ExecutorLeaseStore) -> Self {
        Self { leases }
    }

    pub fn execute(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        self.leases.acquire(request)
    }
}
