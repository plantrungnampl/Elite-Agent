use local_agent_terminal_application::{LocalDiagnosticDto, ObservationClassDto, TrustLabelDto};

pub(crate) struct LocalLog {
    secrets: Vec<String>,
    records: Vec<LocalDiagnosticDto>,
}

impl LocalLog {
    pub(crate) fn new(mut secrets: Vec<String>) -> Self {
        secrets.retain(|secret| !secret.is_empty());
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        Self {
            secrets,
            records: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, mut record: LocalDiagnosticDto) {
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

    #[cfg(test)]
    fn records(&self) -> &[LocalDiagnosticDto] {
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

#[cfg(test)]
mod tests {
    use local_agent_terminal_application::{
        DiagnosticSeverityDto, LocalDiagnosticDto, ObservationClassDto, TrustLabelDto,
    };

    use super::LocalLog;

    #[test]
    fn redacts_every_string_and_downgrades_untrusted_observations() {
        let mut log = LocalLog::new(vec!["top-secret".to_owned()]);
        log.push(LocalDiagnosticDto {
            code: "code-top-secret".to_owned(),
            component: "component-top-secret".to_owned(),
            severity: DiagnosticSeverityDto::Error,
            trust_label: TrustLabelDto::Untrusted,
            observation_class: ObservationClassDto::CoreObservation,
            error_category: Some("error-top-secret".to_owned()),
            correlation_id: Some("correlation-top-secret".to_owned()),
            detail: "detail top-secret".to_owned(),
        });

        assert_eq!(
            log.records()[0].observation_class,
            ObservationClassDto::UntrustedClaim
        );
        assert!(!serde_json::to_string(log.records())
            .unwrap()
            .contains("top-secret"));
    }
}
