use serde::{Deserialize, Serialize};

/// Deliberately contains no command line, stderr, request, or filesystem dump.
#[derive(Clone, Debug, Serialize)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[serde(skip)]
    linux_passive_cause: Option<LinuxPassiveCause>,
    #[serde(skip)]
    git_read_failure_provenance: Option<GitReadFailureProvenance>,
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation",
    not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"),
    target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    #[serde(skip)]
    installed_git_epoch_rejection: Option<InstalledGitEpochRejection>,
}

// Exact first rejected predicate from one original TRY-only epoch read.
// Nonshipping closed DATA; never a public error, epoch or admission grant.
#[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation",
    not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"),
    target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all="kebab-case")]
pub(crate) enum InstalledGitEpochRejection {
    BookWouldBlock, BookPoisoned, PublisherFinished, PublisherKind,
    ControlUnknown, CancelPending, OtherPublisherPending, PublisherMismatch,
}

// Closed facts at the producer of the winning original GitRead error. These
// are not public protocol, timing, child-entry or finality authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GitReadFailureProvenance {
    pub(crate) origin: GitReadFailureOrigin,
    // A later decode boundary can observe GO after the child's first failure.
    // Even true does not prove stdin delivery or child/Git entry. None means
    // this producer did not already have the original owner's GO flag.
    pub(crate) go_claimed_at_boundary: Option<bool>,
    pub(crate) command_failure: Option<GitReadCommandFailure>,
}

// Same first original child command error, after strict private-wire decoding.
// Diagnostic snapshots never grant dispatch, containment or finality authority.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GitReadCommandFailure {
    pub(crate) category: GitReadCommandCategory,
    pub(crate) reason: GitReadCommandReason,
    pub(crate) command: GitReadCommandKind,
    pub(crate) ordinal: u16,
    pub(crate) dispatched: Option<bool>,
    pub(crate) contained: Option<bool>,
    pub(crate) cleanup_complete: Option<bool>,
    pub(crate) failure_mask: Option<u8>,
    pub(crate) owner_finality: Option<[Option<u32>; 5]>,
}
impl GitReadCommandFailure {
    pub(crate) fn valid(&self) -> bool {
        (1..=256).contains(&self.ordinal)
            && self.failure_mask.is_none_or(|m| m == 32 || (48..=63).contains(&m))
            && self.owner_finality.is_none_or(|v| {
                v[0] == Some(1) && matches!(v[1], Some(0 | 1))
                    && v[2].is_some_and(|n| n <= if v[1] == Some(0) { 1023 } else { 1048575 })
                    && v[3].is_some_and(|n| n <= 15)
                    && v[4].is_none_or(|n| v[1] == Some(1) && (n == 0 || n == 32 || (48..=63).contains(&n)))
            })
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GitReadCommandCategory { Process, ProcessCleanup, ProcessOutcomeUnknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GitReadCommandReason {
    IncompleteOutput, OriginalDeadline, OutputBound, ProtocolOrOwnership,
    CommandFailedOrIncomplete, CleanupUnconfirmed, ExecRejected, StoppedBeforeExec,
    ParentEnded, ObserverEnded, FenceCollision, Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GitReadCommandKind { Configuration, Version, Revision, Index, Status, SymbolicRef, References, Diff, Walk, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GitReadFailureOrigin {
    ExplicitCancel, DocumentStop, Shutdown, DriverStop,
    SourceInspectOwnerFailed, SourceInspectStopFlag, SourceInspectExpired,
    SourcePostOwnerFailed, SourcePostStopFlag, SourcePostExpired,
    ChildTerminal,
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
            git_read_failure_provenance: None,
            #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation",
    not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"),
    target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
            installed_git_epoch_rejection: None,
        }
    }

    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation",
    not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"),
    target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    pub(crate) fn with_installed_git_epoch_rejection(mut self, rejection: Option<InstalledGitEpochRejection>) -> Self {
        self.installed_git_epoch_rejection = rejection; self
    }
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation",
    not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"),
    target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    pub(crate) fn installed_git_epoch_rejection(&self) -> Option<InstalledGitEpochRejection> {
        self.installed_git_epoch_rejection
    }

    pub(crate) fn with_git_read_failure_provenance(mut self, provenance: Option<GitReadFailureProvenance>) -> Self {
        self.git_read_failure_provenance = provenance;
        self
    }
    pub(crate) fn git_read_failure_provenance(&self) -> Option<GitReadFailureProvenance> {
        self.git_read_failure_provenance
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

#[cfg(test)]
mod git_read_tests {
    use super::*;
    #[test]
    fn git_read_provenance_is_cloned_but_not_public_or_equality_authority() {
        let plain = BridgeError::new("cancelled", "The original Git read was stopped.");
        let provenance = Some(GitReadFailureProvenance {
            origin: GitReadFailureOrigin::DocumentStop, go_claimed_at_boundary: Some(false), command_failure: None,
        });
        let tagged = plain.clone().with_git_read_failure_provenance(provenance);
        assert_eq!(tagged.clone().git_read_failure_provenance(), provenance);
        assert_eq!(plain.git_read_failure_provenance(), None);
        assert_eq!(plain, tagged);
        assert_eq!(tagged, plain.clone().with_git_read_failure_provenance(Some(GitReadFailureProvenance {
            origin: GitReadFailureOrigin::ChildTerminal, go_claimed_at_boundary: Some(true),
            command_failure: Some(serde_json::from_value(serde_json::json!({
                "category":"process", "reason":"incomplete-output", "command":"index", "ordinal":3,
                "dispatched":true, "contained":true, "cleanupComplete":true,
                "failureMask":52, "ownerFinality":[1,1,0,0,52],
            })).unwrap()),
        })));
        assert_eq!(serde_json::to_value(&tagged).unwrap(), serde_json::json!({
            "code":"cancelled", "message":"The original Git read was stopped.", "retryable":false,
        }));
        assert_eq!(serde_json::to_value(&plain).unwrap(), serde_json::to_value(&tagged).unwrap());
        assert_eq!(plain.to_string(), tagged.to_string());
    }
}

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
