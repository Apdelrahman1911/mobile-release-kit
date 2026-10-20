//! The named saved unsigned iOS archive observation. All values are redacted
//! DATA; no tool, material, native input, window or settlement authority.
pub use crate::agent_android_build::Version;
pub(crate) use crate::agent_build_requests::{
    Access, ClaimKind, Entry, Inbox, NativeLink, NativeScope,
};
pub use crate::agent_build_requests::{Prepare, Query, RequestState, Start, StartState};
pub use crate::agent_local_checks::{Config, Outcome};
use crate::service_protocol::{Error, Id, OperationState, Settlement};
use serde::{Deserialize, Serialize};
pub const CONSENT: &str = "agent-saved-ios-unsigned-archive-v1";
pub const REPORT_LIMIT: usize = 4096;
pub(crate) const FAMILY: crate::agent_build_requests::Family =
    crate::agent_build_requests::Family::IosArchive;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    SavedIosUnsignedArchive,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub mode: Mode,
    pub saved_config: Config,
    pub saved_version: Version,
}
impl Review {
    pub fn valid(&self) -> bool {
        self.saved_config.valid() && self.saved_version.valid()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    None,
    Cancelled,
    ContextChanged,
    DocumentLost,
    Shutdown,
    TimedOut,
    ProtocolError,
    RuntimeUnavailable,
    IntentExpired,
    StaleIntent,
    SavedConfigMissing,
    SavedConfigInvalid,
    SavedConfigChanged,
    SavedConfigSensitive,
    SavedConfigUnsafe,
    SavedConfigTooLarge,
    SavedVersionMissing,
    SavedVersionInvalid,
    SavedVersionChanged,
    SavedVersionSensitive,
    SavedVersionUnsafe,
    SavedVersionTooLarge,
    PlatformDisabled,
    ContainerRequired,
    SchemeRequired,
    ContainerMissing,
    ToolchainUnavailable,
    ToolchainMismatch,
    ProjectAdmissionRefused,
    CommandFailed,
    CommandIncomplete,
    ArtifactMissing,
    ArtifactUnsafe,
    ArtifactChanged,
    ArchiveValidationFailed,
    InputLimit,
    ResultLimit,
    WorkRetained,
    CleanupUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Accepted,
    InputsBound,
    CheckingXcode,
    Preparing,
    Archiving,
    Inspecting,
    DisposingSnapshot,
    DisposingWork,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    LocalUnsignedIosArchiveObservation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub scope: Scope,
    pub used_config: Config,
    pub used_version: Version,
    pub entries: u32,
    pub bytes: u64,
}
impl Report {
    pub fn valid(&self) -> bool {
        self.used_config.valid()
            && self.used_version.valid()
            && (1..=100_000).contains(&self.entries)
            && (1..=8 * 1024u64.pow(3)).contains(&self.bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotDisposition {
    NotCreated,
    Removed,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkDisposition {
    NotCreated,
    Removed,
    RetainedWork,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputDisposition {
    NotCreated,
    RetainedIncomplete,
    RetainedLocalResult,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disposition {
    pub snapshot: SnapshotDisposition,
    pub work: WorkDisposition,
    pub output: OutputDisposition,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub operation_id: Id,
    pub owner_generation: Id,
    pub status_revision: u32,
    pub state: OperationState,
    pub settlement: Settlement,
    pub outcome: Option<Outcome>,
    pub reason: Reason,
    pub stage: Option<Stage>,
    pub disposition: Option<Disposition>,
    pub result: Option<Report>,
}
impl Operation {
    pub fn valid(&self) -> bool {
        if self.status_revision == u32::MAX {
            return false;
        }
        if self.settlement == Settlement::Unknown {
            return self.state == OperationState::Unknown
                && self.outcome == Some(Outcome::Unknown)
                && self.reason == Reason::CleanupUnknown
                && self.stage.is_none()
                && self.disposition.is_none()
                && self.result.is_none();
        }
        if self.settlement == Settlement::Pending {
            return matches!(
                self.state,
                OperationState::Prepared
                    | OperationState::Running
                    | OperationState::CancellationRequested
            ) && self.outcome.is_none()
                && self.disposition.is_none()
                && self.result.is_none()
                && (self.state != OperationState::Prepared
                    || self.stage.is_none() && self.reason == Reason::None);
        }
        if self.reason == Reason::CleanupUnknown
            || self.disposition.as_ref().is_some_and(|d| {
                d.snapshot == SnapshotDisposition::Unknown
                    || d.work == WorkDisposition::Unknown
                    || d.output == OutputDisposition::Unknown
            })
        {
            return false;
        }
        match self.outcome {
            Some(Outcome::Complete) => {
                self.state == OperationState::Succeeded
                    && self.reason == Reason::None
                    && self.stage == Some(Stage::DisposingWork)
                    && self.result.as_ref().is_some_and(Report::valid)
                    && self.disposition.as_ref().is_some_and(|d| {
                        d.snapshot == SnapshotDisposition::Removed
                            && d.work == WorkDisposition::Removed
                            && d.output == OutputDisposition::RetainedLocalResult
                    })
            }
            Some(Outcome::Cancelled) => {
                self.state == OperationState::Cancelled
                    && self.result.is_none()
                    && matches!(
                        self.reason,
                        Reason::Cancelled
                            | Reason::ContextChanged
                            | Reason::DocumentLost
                            | Reason::Shutdown
                    )
            }
            Some(Outcome::Refused | Outcome::Failed | Outcome::TimedOut) => {
                self.state == OperationState::Failed
                    && self.reason != Reason::None
                    && self.result.is_none()
            }
            _ => false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub origin: Query,
    pub expected_observation_revision: u64,
    pub request_state: RequestState,
    pub start_state: StartState,
    pub review: Review,
    pub operation: Option<Operation>,
    pub history_available: bool,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0
            || !self.do_not_replay
            || !self.review.valid()
            || self.operation.as_ref().is_some_and(|o| {
                !o.valid()
                    || o.result.as_ref().is_some_and(|r| {
                        r.used_config != self.review.saved_config
                            || r.used_version != self.review.saved_version
                    })
            })
            || self.history_available && self.operation.is_none()
            || self.request_state == RequestState::OriginalAvailable && self.operation.is_none()
            || self.start_state != StartState::NotRequested && self.operation.is_none()
        {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

impl TryFrom<crate::agent_build_requests::Snapshot> for Status {
    type Error = Error;
    fn try_from(s: crate::agent_build_requests::Snapshot) -> Result<Self, Error> {
        let crate::agent_build_requests::Review::Ios(review) = s.review else {
            return Err(Error::Conflict);
        };
        let operation = s
            .operation
            .map(|o| match o {
                crate::agent_build_requests::Operation::Ios(o) => Ok(o),
                _ => Err(Error::Conflict),
            })
            .transpose()?;
        let result = Self {
            origin: s.origin,
            expected_observation_revision: s.expected_observation_revision,
            request_state: s.request_state,
            start_state: s.start_state,
            review,
            operation,
            history_available: s.history_available,
            do_not_replay: s.do_not_replay,
        };
        result.validate()?;
        Ok(result)
    }
}
