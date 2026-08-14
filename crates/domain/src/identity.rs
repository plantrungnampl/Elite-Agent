use std::fmt;
use std::num::NonZeroU64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    Empty { kind: &'static str },
    Invalid { kind: &'static str },
    Negative { kind: &'static str, value: i64 },
    MustBePositive { kind: &'static str, value: i64 },
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { kind } => write!(formatter, "{kind} must not be empty"),
            Self::Invalid { kind } => write!(formatter, "{kind} is invalid"),
            Self::Negative { kind, value } => {
                write!(formatter, "{kind} must be nonnegative, got {value}")
            }
            Self::MustBePositive { kind, value } => {
                write!(formatter, "{kind} must be positive, got {value}")
            }
        }
    }
}

impl std::error::Error for ValueError {}

macro_rules! non_empty_id {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(ValueError::Empty { kind: $kind });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

non_empty_id!(TaskId, "task ID");
non_empty_id!(StreamId, "stream ID");
non_empty_id!(EventId, "event ID");
non_empty_id!(ActorId, "actor ID");
non_empty_id!(ProjectId, "project ID");
non_empty_id!(RunId, "run ID");
non_empty_id!(ArtifactId, "artifact ID");
non_empty_id!(RepositoryId, "repository ID");
non_empty_id!(WorktreeId, "worktree ID");

macro_rules! nonnegative_value {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub fn get(self) -> u64 {
                self.0
            }

            pub(crate) fn checked_increment(self) -> Option<Self> {
                self.0.checked_add(1).map(Self)
            }
        }

        impl TryFrom<i64> for $name {
            type Error = ValueError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                u64::try_from(value)
                    .map(Self)
                    .map_err(|_| ValueError::Negative { kind: $kind, value })
            }
        }
    };
}

nonnegative_value!(Sequence, "sequence");
nonnegative_value!(WorkspaceVersion, "workspace version");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if !valid_sha256_digest(&value) {
            return Err(ValueError::Invalid {
                kind: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub(crate) fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const fn from_unix_seconds(value: i64) -> Self {
        Self(value)
    }

    pub const fn unix_seconds(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FencingToken(NonZeroU64);

impl FencingToken {
    pub fn new(value: u64) -> Result<Self, ValueError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(ValueError::MustBePositive {
                kind: "fencing token",
                value: 0,
            })
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<i64> for FencingToken {
    type Error = ValueError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        let unsigned = u64::try_from(value).map_err(|_| ValueError::MustBePositive {
            kind: "fencing token",
            value,
        })?;
        Self::new(unsigned)
    }
}
