
impl FileWriteRecoveryStore for SqliteStore {
    fn prepare(
        &self,
        _intent: FileWriteRecoveryIntent,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        file_write_authority_missing()
    }

    fn start(
        &self,
        _execution_id: &ToolExecutionId,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        file_write_authority_missing()
    }

    fn complete(
        &self,
        _completion: FileWriteRecoveryCompletion,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        file_write_authority_missing()
    }

    fn complete_recovery(
        &self,
        _completion: FileWriteRecoveryCompletion,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        file_write_authority_missing()
    }

    fn fail(
        &self,
        _execution_id: &ToolExecutionId,
        _failure: FileWriteRecoveryFailure,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        file_write_authority_missing()
    }

    fn mark_indeterminate(
        &self,
        _execution_id: &ToolExecutionId,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        file_write_authority_missing()
    }

    fn recover(&self) -> Result<Vec<FileWriteRecoverySnapshot>, PortError> {
        file_write_authority_missing()
    }
}

fn file_write_authority_missing<T>() -> Result<T, PortError> {
    // Normative v7 requires an exact policy-authorized operation attempt and an
    // immutable receipt artifact. The legacy file-write port carries neither.
    Err(integrity_failure())
}
