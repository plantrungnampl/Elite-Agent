//! OpenAI Responses API adapter for the provider-neutral protocol boundary.

mod adapter;
mod config;
mod request;
mod sse;

pub use adapter::{OpenAiDiagnostic, OpenAiResponsesAdapter};
pub use config::{OpenAiApiKey, OpenAiProviderConfig};
pub use request::MAX_PROMPT_BYTES;
pub use sse::MAX_SSE_EVENT_BYTES;
