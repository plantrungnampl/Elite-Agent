use std::fmt;

use crate::{FencingToken, RunId, TaskId, ValueError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitObjectId(String);

impl GitObjectId {
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if !matches!(value.len(), 40 | 64)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ValueError::Invalid {
                kind: "Git object ID",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskBranch(String);

impl TaskBranch {
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ValueError::Empty {
                kind: "task branch",
            });
        }
        let invalid_component = value.split('/').any(|component| {
            component.is_empty()
                || component.starts_with('.')
                || component.ends_with('.')
                || component.ends_with(".lock")
        });
        let invalid_character = value.bytes().any(|byte| {
            byte <= b' '
                || byte == 0x7f
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        });
        if invalid_component
            || invalid_character
            || value == "@"
            || value.contains("..")
            || value.contains("@{")
        {
            return Err(ValueError::Invalid {
                kind: "task branch",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TaskBranch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceFingerprint {
    head: GitObjectId,
    index_digest: String,
    status_digest: String,
}

impl WorkspaceFingerprint {
    pub fn new(
        head: GitObjectId,
        index_digest: impl Into<String>,
        status_digest: impl Into<String>,
    ) -> Result<Self, ValueError> {
        let index_digest = index_digest.into();
        let status_digest = status_digest.into();
        if !valid_sha256_digest(&index_digest) || !valid_sha256_digest(&status_digest) {
            return Err(ValueError::Invalid {
                kind: "workspace fingerprint",
            });
        }
        Ok(Self {
            head,
            index_digest,
            status_digest,
        })
    }

    pub const fn head(&self) -> &GitObjectId {
        &self.head
    }

    pub fn index_digest(&self) -> &str {
        &self.index_digest
    }

    pub fn status_digest(&self) -> &str {
        &self.status_digest
    }
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseClaim {
    task_id: TaskId,
    holder_run_id: RunId,
    token: FencingToken,
}

impl LeaseClaim {
    pub const fn new(task_id: TaskId, holder_run_id: RunId, token: FencingToken) -> Self {
        Self {
            task_id,
            holder_run_id,
            token,
        }
    }

    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn holder_run_id(&self) -> &RunId {
        &self.holder_run_id
    }

    pub const fn token(&self) -> FencingToken {
        self.token
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencedWriteError {
    LeaseNotActive,
    StaleFencingToken {
        current: FencingToken,
        supplied: FencingToken,
    },
}

impl fmt::Display for FencedWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseNotActive => formatter.write_str("executor lease is not active"),
            Self::StaleFencingToken { current, supplied } => write!(
                formatter,
                "stale fencing token: current {}, supplied {}",
                current.get(),
                supplied.get()
            ),
        }
    }
}

impl std::error::Error for FencedWriteError {}

pub fn authorize_fenced_write(
    current: Option<&LeaseClaim>,
    supplied: &LeaseClaim,
) -> Result<(), FencedWriteError> {
    let Some(current) = current else {
        return Err(FencedWriteError::LeaseNotActive);
    };
    if current.task_id != supplied.task_id || current.holder_run_id != supplied.holder_run_id {
        return Err(FencedWriteError::LeaseNotActive);
    }
    if current.token != supplied.token {
        return Err(FencedWriteError::StaleFencingToken {
            current: current.token,
            supplied: supplied.token,
        });
    }
    Ok(())
}
