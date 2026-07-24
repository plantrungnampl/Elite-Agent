use std::collections::BTreeMap;
use std::fmt;

use crate::ValueError;

macro_rules! non_empty_name {
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

non_empty_name!(WorkflowEvent, "workflow event");
non_empty_name!(GuardName, "guard name");
non_empty_name!(Effect, "effect name");

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardEvaluations(BTreeMap<GuardName, bool>);

impl GuardEvaluations {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, guard: GuardName, satisfied: bool) {
        self.0.insert(guard, satisfied);
    }

    pub(crate) fn get(&self, guard: &GuardName) -> Option<bool> {
        self.0.get(guard).copied()
    }
}
