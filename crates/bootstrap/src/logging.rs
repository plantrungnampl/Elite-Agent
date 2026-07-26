use local_agent_terminal_application::{LocalDiagnosticDto, ObservationClassDto, TrustLabelDto};

pub struct LocalLog {
    secrets: Vec<String>,
    records: Vec<LocalDiagnosticDto>,
}

impl LocalLog {
    pub fn new(mut secrets: Vec<String>) -> Self {
        secrets.retain(|secret| !secret.is_empty());
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        Self {
            secrets,
            records: Vec::new(),
        }
    }

    pub fn push(&mut self, mut record: LocalDiagnosticDto) {
        if record.trust_label == TrustLabelDto::Untrusted {
            record.observation_class = ObservationClassDto::UntrustedClaim;
        }
        record.code = self.redact(&record.code);
        record.component = self.redact(&record.component);
        record.error_category = record
            .error_category
            .as_deref()
            .map(|value| self.redact(value));
        record.correlation_id = record
            .correlation_id
            .as_deref()
            .map(|value| self.redact(value));
        record.detail = self.redact(&record.detail);
        self.records.push(record);
    }

    pub fn records(&self) -> &[LocalDiagnosticDto] {
        &self.records
    }

    pub(crate) fn into_records(self) -> Vec<LocalDiagnosticDto> {
        self.records
    }

    fn redact(&self, value: &str) -> String {
        self.secrets
            .iter()
            .fold(value.to_owned(), |rendered, secret| {
                rendered.replace(secret, "[REDACTED]")
            })
    }
}
