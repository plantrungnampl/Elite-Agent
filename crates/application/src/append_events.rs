use crate::{AppendEventsError, AppendOperation, AppendResult, EventStore};

pub struct AppendEvents<'a> {
    event_store: &'a dyn EventStore,
}

impl<'a> AppendEvents<'a> {
    pub const fn new(event_store: &'a dyn EventStore) -> Self {
        Self { event_store }
    }

    pub fn execute(&self, operation: AppendOperation) -> Result<AppendResult, AppendEventsError> {
        self.event_store.append(operation).map_err(Into::into)
    }
}
