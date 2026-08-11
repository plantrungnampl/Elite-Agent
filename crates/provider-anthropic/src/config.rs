use std::{fmt, time::Duration};

use local_agent_terminal_agent_protocol::ProtocolError;
use reqwest::header::HeaderValue;
use url::{Host, Url};

#[derive(Clone)]
pub struct AnthropicApiKey(String);

impl AnthropicApiKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.trim().is_empty() || HeaderValue::from_str(&value).is_err() {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self(value))
    }

    pub(crate) fn secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AnthropicApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AnthropicApiKey(REDACTED)")
    }
}

#[derive(Clone)]
pub struct AnthropicProviderConfig {
    endpoint: Url,
    api_key: AnthropicApiKey,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl AnthropicProviderConfig {
    pub fn new(
        endpoint: Url,
        api_key: AnthropicApiKey,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, ProtocolError> {
        if endpoint.scheme() != "https"
            || endpoint.host().is_none()
            || endpoint.path() != "/v1/messages"
            || has_forbidden_url_components(&endpoint)
        {
            return Err(ProtocolError::InvalidRequest);
        }
        Self::with_timeouts(endpoint, api_key, connect_timeout, read_timeout)
    }

    /// Creates an HTTP configuration only for a literal-IP loopback test fixture.
    pub fn for_loopback_test(
        endpoint: Url,
        api_key: AnthropicApiKey,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, ProtocolError> {
        if endpoint.scheme() != "http"
            || !is_literal_loopback(&endpoint)
            || endpoint.path() != "/v1/messages"
            || has_forbidden_url_components(&endpoint)
        {
            return Err(ProtocolError::InvalidRequest);
        }
        Self::with_timeouts(endpoint, api_key, connect_timeout, read_timeout)
    }

    fn with_timeouts(
        endpoint: Url,
        api_key: AnthropicApiKey,
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

    pub(crate) fn api_key(&self) -> &AnthropicApiKey {
        &self.api_key
    }

    pub(crate) fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub(crate) fn read_timeout(&self) -> Duration {
        self.read_timeout
    }
}

impl fmt::Debug for AnthropicProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnthropicProviderConfig")
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

fn has_forbidden_url_components(endpoint: &Url) -> bool {
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return true;
    }

    let Some((_, authority_and_path)) = endpoint.as_str().split_once("://") else {
        return true;
    };
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());
    authority_and_path[..authority_end].contains('@')
}
