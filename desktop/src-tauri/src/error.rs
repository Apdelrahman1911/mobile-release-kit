use serde::Serialize;

/// Deliberately contains no command line, stderr, request, or filesystem dump.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl BridgeError {
    pub fn new(code: &str, message: &str) -> Self {
        Self { code: code.into(), message: message.into(), retryable: false }
    }

    pub fn unavailable(message: &str) -> Self { Self::new("runtime_unavailable", message) }
    pub fn protocol() -> Self { Self::new("protocol_error", "The core returned an invalid or incomplete response.") }
    pub fn invalid() -> Self { Self::new("invalid_request", "The request exceeds the supported shape or size.") }
    pub fn shutdown() -> Self { Self::new("shutting_down", "The application is stopping its owned queries.") }
    pub fn timeout() -> Self { Self::new("query_timeout", "The read-only query exceeded its operation deadline.") }
    pub fn cleanup_unknown() -> Self {
        Self::new("cleanup_unknown", "Original query cleanup is unconfirmed. Further queries are disabled; the owner is retained.")
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}: {}", self.code, self.message) }
}
impl std::error::Error for BridgeError {}
