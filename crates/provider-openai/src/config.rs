use std::{fmt, time::Duration};

use local_agent_terminal_agent_protocol::ProtocolError;
use url::{Host, Url};

#[derive(Clone)]
pub struct OpenAiApiKey(String);

impl OpenAiApiKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self(value))
    }

    pub(crate) fn secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OpenAiApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiApiKey(REDACTED)")
    }
}

#[derive(Clone)]
pub struct OpenAiProviderConfig {
    endpoint: Url,
    api_key: OpenAiApiKey,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl OpenAiProviderConfig {
    pub fn new(
        endpoint: Url,
        api_key: OpenAiApiKey,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, ProtocolError> {
        if endpoint.scheme() != "https" || endpoint.host().is_none() {
            return Err(ProtocolError::InvalidRequest);
        }
        Self::with_timeouts(endpoint, api_key, connect_timeout, read_timeout)
    }

    /// Creates an HTTP configuration only for a literal-IP loopback test fixture.
    pub fn for_loopback_test(
        endpoint: Url,
        api_key: OpenAiApiKey,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, ProtocolError> {
        if endpoint.scheme() != "http" || !is_literal_loopback(&endpoint) {
            return Err(ProtocolError::InvalidRequest);
        }
        Self::with_timeouts(endpoint, api_key, connect_timeout, read_timeout)
    }

    fn with_timeouts(
        endpoint: Url,
        api_key: OpenAiApiKey,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, ProtocolError> {
        if connect_timeout.is_zero() || read_timeout.is_zero() {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            api_key,
            connect_timeout,
            read_timeout,
        })
    }

    pub(crate) fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub(crate) fn api_key(&self) -> &OpenAiApiKey {
        &self.api_key
    }

    pub(crate) fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub(crate) fn read_timeout(&self) -> Duration {
        self.read_timeout
    }
}

impl fmt::Debug for OpenAiProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiProviderConfig")
            .field("endpoint", &self.endpoint)
            .field("api_key", &self.api_key)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .finish()
    }
}

fn is_literal_loopback(endpoint: &Url) -> bool {
    match endpoint.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    }
}
