//! The single named, Desktop-approved Android build request. No executable,
//! path, credential, document, tool capability or finality receipt is decoded.
//! The installed client shares DATA only with the original Desktop owners.
pub use crate::agent_local_checks::{Config, Outcome};
use crate::service_protocol::{Error, Id, OperationState, Settlement};
use serde::{Deserialize, Serialize};
pub(crate) use crate::agent_build_requests::{Access, ClaimKind, Entry, Inbox, NativeLink, NativeScope};
use std::time::Duration;
#[cfg(test)]
use std::{sync::Arc, time::Instant};


#[path = "agent_android_signed.rs"]
pub mod signed;

pub const CONSENT: &str = "agent-saved-android-build-inspect-v1";
pub const LIMIT: usize = crate::agent_build_requests::LIMIT;
pub const START_WINDOW: Duration = crate::agent_build_requests::START_WINDOW;
pub const REPORT_LIMIT: usize = 24 * 1024;
// All finite request/scopes/reports plus original+claimed/public copies, the
// one current saved-input grant and codec scratch. Not a process RSS budget.
pub(crate) const DOCUMENT_BACKING: usize = crate::agent_build_requests::DOCUMENT_BACKING;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Version {
    pub bytes: u32,
    pub sha256: String,
    pub name: String,
    pub build: u32,
}
impl Version {
    pub fn valid(&self) -> bool {
        (1..=65536).contains(&self.bytes)
            && hash(&self.sha256)
            && (1..=64).contains(&self.name.len())
            && self
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".+-".contains(&c))
            && (1..=2_100_000_000).contains(&self.build)
    }
}
fn hash(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tools {
    pub instance: Id,
    pub catalog_generation: u32,
    pub record_sha256: String,
}
impl Tools {
    fn valid(&self) -> bool {
        (1..u32::MAX).contains(&self.catalog_generation) && hash(&self.record_sha256)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    SavedAndroidBuildStructureAndVersion,
    SavedAndroidLocalUploadKeySign,
    SavedAndroidCandidateInputs,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub mode: Mode,
    pub saved_config: Config,
    pub saved_version: Version,
    pub tools: Tools,
    #[serde(default, deserialize_with = "signed::present", skip_serializing_if = "Option::is_none")]
    pub signing: Option<signed::Selection>,
    #[serde(default, deserialize_with = "signed::present", skip_serializing_if = "Option::is_none")]
    pub upload_certificate_sha256: Option<String>,
}
impl Review {
    pub fn valid(&self) -> bool {
        self.saved_config.valid() && self.saved_version.valid() && self.tools.valid()
            && match self.mode {
                Mode::SavedAndroidBuildStructureAndVersion => self.signing.is_none() && self.upload_certificate_sha256.is_none(),
                Mode::SavedAndroidLocalUploadKeySign | Mode::SavedAndroidCandidateInputs => self.signing.as_ref().is_some_and(signed::Selection::valid)
                    && self.upload_certificate_sha256.as_ref().is_some_and(|v| hash(v)),
            }
    }
}
pub use crate::agent_build_requests::{Prepare, Query, Start, RequestState, StartState};
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
    ModuleRequired,
    ToolchainUnavailable,
    ToolchainMismatch,
    ProjectAdmissionRefused,
    CommandFailed,
    CommandIncomplete,
    ArtifactMissing,
    ArtifactAmbiguous,
    ArtifactUnsafe,
    ArtifactChanged,
    InputLimit,
    ResultLimit,
    WorkRetained,
    CleanupUnknown,
    SigningInputMissing,
    SigningInputInvalid,
    SigningValidationFailed,
    SigningCommandFailed,
    BuildInputsUnrestored,
    JournalUnavailable,
    RecoveryRequired,
    CandidateInputsUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Accepted,
    InputsBound,
    Building,
    Capturing,
    Inspecting,
    DisposingWork,
    ValidatingSigning,
    Signing,
    RestoringInputs,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingStatus {
    Pass,
    Fail,
    Missing,
    Blocked,
    Invalid,
    Skip,
    Manual,
    Configured,
    NotApplicable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Check {
    AabStructure,
    AabManifest,
    ApplicationId,
    BuildNumber,
    VersionName,
    ReleaseFlags,
    Signer,
    Signature,
    CoreLifecycle,
    OtherCoreFinding,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub ordinal: u32,
    pub check: Check,
    pub status: FindingStatus,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub total: u32,
    pub shown: u32,
    pub omitted: u32,
    pub counts: std::collections::BTreeMap<FindingStatus, u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    pub size: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    LocalPostBuildArtifactObservation,
    LocalAndroidCandidateInputs,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub scope: Scope,
    pub used_config: Config,
    pub used_version: Version,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub artifact: Artifact,
    #[serde(default, deserialize_with = "signed::present", skip_serializing_if = "Option::is_none")]
    pub signing: Option<signed::Report>,
    #[serde(default, deserialize_with = "signed::present", skip_serializing_if = "Option::is_none")]
    pub candidate: Option<crate::agent_candidate_build::Candidate>,
}
impl Report {
    pub fn valid(&self) -> bool {
        self.used_config.valid()
            && self.used_version.valid()
            && (1..=1024 * 1024 * 1024).contains(&self.artifact.size)
            && hash(&self.artifact.sha256)
            && match self.scope {
                Scope::LocalPostBuildArtifactObservation => self.candidate.is_none(),
                Scope::LocalAndroidCandidateInputs => self.signing.is_some() && self.candidate.as_ref().is_some_and(|c|
                    c.valid(crate::agent_candidate_build::ANDROID_PRIMARY_BYTES)
                        && c.primary_bytes == self.artifact.size && c.primary_sha256 == self.artifact.sha256),
            }
            && self.signing.as_ref().is_none_or(signed::Report::valid)
            && (self.signing.is_none() || self.findings.iter().filter(|r| r.check == Check::Signature && r.status == FindingStatus::Pass).count() == 1
                && self.findings.iter().filter(|r| r.check == Check::Signer && r.status == FindingStatus::Pass).count() == 1)
            && self.findings.len() <= 128
            && self.summary.shown as usize == self.findings.len()
            && self.summary.shown == self.summary.total
            && self.summary.omitted == 0
            && self.summary.total <= 128
            && self.summary.counts.len() == 9
            && self
                .summary
                .counts
                .values()
                .try_fold(0u32, |sum, n| sum.checked_add(*n))
                == Some(self.summary.total)
            && self.findings.iter().enumerate().all(|(n, row)| {
                row.ordinal == n as u32
                    && if self.signing.is_some() { matches!(row.status, FindingStatus::Pass | FindingStatus::NotApplicable) }
                        else { row.check != Check::Signature && (row.check != Check::Signer || row.status == FindingStatus::Skip) }
            })
            && self.summary.counts.iter().all(|(status, n)| {
                self.findings
                    .iter()
                    .filter(|row| row.status == *status)
                    .count() as u32
                    == *n
            })
    }
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
pub enum ArtifactDisposition {
    NotCreated,
    Removed,
    RetainedLocalResult,
    RetainedIncomplete,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disposition {
    pub work: WorkDisposition,
    pub artifacts: ArtifactDisposition,
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
                d.work == WorkDisposition::Unknown || d.artifacts == ArtifactDisposition::Unknown
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
                        d.work == WorkDisposition::Removed
                            && d.artifacts == ArtifactDisposition::RetainedLocalResult
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
impl Operation {
    pub(crate) fn valid_for(&self, review: &Review) -> bool {
        let candidate = review.mode == Mode::SavedAndroidCandidateInputs;
        let signed = matches!(review.mode, Mode::SavedAndroidLocalUploadKeySign | Mode::SavedAndroidCandidateInputs);
        self.valid() && review.valid()
            && (candidate || !matches!(self.reason, Reason::JournalUnavailable | Reason::RecoveryRequired | Reason::CandidateInputsUnavailable))
            && (signed || !matches!(self.reason, Reason::SigningInputMissing | Reason::SigningInputInvalid
                | Reason::SigningValidationFailed | Reason::SigningCommandFailed | Reason::BuildInputsUnrestored))
            && (signed || !matches!(self.stage, Some(Stage::ValidatingSigning | Stage::Signing | Stage::RestoringInputs)))
            && self.result.as_ref().is_none_or(|r| {
                r.used_config == review.saved_config && r.used_version == review.saved_version
                    && r.signing.is_some() == signed
                    && r.candidate.is_some() == candidate
                    && r.candidate.as_ref().is_none_or(|c| c.matches_operation(self.operation_id.as_str()))
                    && r.signing.as_ref().is_none_or(|s| Some(&s.upload_certificate_sha256) == review.upload_certificate_sha256.as_ref())
            })
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
            || self.operation.as_ref().is_some_and(|o| !o.valid_for(&self.review))
            || self.history_available && self.operation.is_none()
            || self.request_state == RequestState::OriginalAvailable && self.operation.is_none()
            || self.start_state != StartState::NotRequested && self.operation.is_none()
                && self.request_state != RequestState::AdmissionUnknown
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
        let crate::agent_build_requests::Review::Android(review) = s.review else { return Err(Error::Conflict) };
        let operation = s.operation.map(|o| match o {
            crate::agent_build_requests::Operation::Android(o) => Ok(o), _ => Err(Error::Conflict)
        }).transpose()?;
        let result = Self { origin:s.origin, expected_observation_revision:s.expected_observation_revision,
            request_state:s.request_state, start_state:s.start_state, review, operation,
            history_available:s.history_available, do_not_replay:s.do_not_replay };
        result.validate()?; Ok(result)
    }
}
pub(crate) const FAMILY: crate::agent_build_requests::Family = crate::agent_build_requests::Family::AndroidInspect;
#[cfg(test)]
#[path = "agent_android_build_tests.rs"]
mod tests;
