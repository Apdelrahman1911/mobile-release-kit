use serde::Serialize;

/// Deliberately contains no command line, stderr, request, or filesystem dump.
#[derive(Clone, Debug, Serialize)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[serde(skip)]
    linux_passive_cause: Option<LinuxPassiveCause>,
}

// Original returned facts only. These are neither public protocol fields nor
// custody/finality receipts. No path, request, handle or raw error is retained.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxPassiveCause {
    SelectionProfileClosed, SelectionCompileBinding, SelectionMethodOutsideProfile,
    Inspection(Option<crate::installed_runtime::AdmissionFailure>),
    AcquisitionEntryNotReleased, AcquisitionCustodyMissing, AcquisitionLock,
    Capability(crate::installed_runtime::AdmissionFailure),
    Preparation(crate::installed_runtime::AdmissionFailure),
    FinalClaimOwnerGate, FinalClaim(crate::installed_runtime::AdmissionFailure),
    ReturnedSpawn(LinuxSpawnFailure), EngineResponse,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxSpawnFailure {
    ProcessFdLimit, SystemFdLimit, Memory, ResourceUnavailable,
    PermissionDenied, NotFound, ExecFormat, Other,
}

// Diagnostic metadata must not change any existing equality-sensitive policy.
impl PartialEq for BridgeError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.message == other.message && self.retryable == other.retryable
    }
}
impl Eq for BridgeError {}

impl BridgeError {
    pub fn new(code: &str, message: &str) -> Self {
        Self { code: code.into(), message: message.into(), retryable: false,
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            linux_passive_cause: None,
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn with_linux_passive_cause(mut self, cause: Option<LinuxPassiveCause>) -> Self {
        self.linux_passive_cause = cause;
        self
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn linux_passive_cause(&self) -> Option<LinuxPassiveCause> {
        self.linux_passive_cause
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

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod tests {
    use super::*;
    #[test]
    fn passive_cause_is_cloned_but_never_changes_public_equality_or_serialization() {
        let plain = BridgeError::unavailable("inert public message");
        let cause = Some(LinuxPassiveCause::Inspection(Some(crate::installed_runtime::AdmissionFailure::Namespace)));
        let tagged = plain.clone().with_linux_passive_cause(cause);
        let moved = tagged.clone();
        assert_eq!(moved.linux_passive_cause(), cause);
        assert_eq!(plain.linux_passive_cause(), None);
        assert_eq!(plain, tagged);
        assert_eq!(tagged, plain.clone().with_linux_passive_cause(Some(LinuxPassiveCause::EngineResponse)));
        let expected = serde_json::json!({"code":"runtime_unavailable", "message":"inert public message", "retryable":false});
        assert_eq!(serde_json::to_value(&plain).unwrap(), expected);
        assert_eq!(serde_json::to_value(&tagged).unwrap(), expected);
        assert_eq!(plain.to_string(), tagged.to_string());
        let mut different = tagged.clone(); different.retryable = true;
        assert_ne!(plain, different);
        different = tagged.clone(); different.code = "other".into();
        assert_ne!(plain, different);
        different = tagged; different.message = "different".into();
        assert_ne!(plain, different);
    }
}
