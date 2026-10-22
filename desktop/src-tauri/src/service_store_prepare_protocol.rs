//! A preparation is not Start, an installed Prepared is not retirement, and
//! a current-visible report is not a Store/version permission. Pure shared DATA.
use crate::{
    service_protocol::{Error, Id, Settlement},
    service_store_inventory_protocol::Inventory,
    service_store_protocol as store,
};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const RAW_LIMIT: usize = 8192;
// All closed Prepare shapes must fit below this existing strict-reader limit.
pub(crate) const RAW_NODES: usize = 128;
pub(crate) const RAW_DEPTH: usize = 8;
pub(crate) const STATUS_LIMIT: usize = store::STATUS_LIMIT;
pub(crate) const PREPARE_CONSENT: &str = "agent-store-native-prepare-once-v1";
pub(crate) type Submit = store::Submit;
pub(crate) type Query = store::Query;
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
// Absence preserves the original encodings. An explicitly present optional
// extension must contain its complete closed tuple, never null or a partial tuple.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    AndroidAccess,
    IosAccess,
    AndroidCandidate,
    IosCandidate,
    AndroidVersions,
    IosVersions,
    PairedVersions,
    AndroidExternalTesting,
    IosExternalTesting,
    AndroidProductionSubmit,
    IosProductionSubmit,
    AndroidCandidateUpload,
    IosCandidateUpload,
    AndroidExternalTestingExecute,
    IosExternalTestingExecute,
    AndroidProductionSubmitExecute,
    IosProductionSubmitExecute,
    AndroidCurrentInternal,
    IosCurrentInternal,
    AndroidRecoverySettlement,
    IosExternalReadiness,
}
impl Kind {
    pub fn inventory(self) -> bool {
        matches!(
            self,
            Self::AndroidVersions | Self::IosVersions | Self::PairedVersions
        )
    }
    pub fn candidate(self) -> bool {
        matches!(self, Self::AndroidCandidate | Self::IosCandidate)
    }
    pub fn stage(self) -> Option<(store::Platform, Stage)> {
        use store::Platform::{Android, Ios};
        match self {
            Self::AndroidExternalTesting => Some((Android, Stage::ExternalTesting)),
            Self::IosExternalTesting => Some((Ios, Stage::ExternalTesting)),
            Self::AndroidProductionSubmit => Some((Android, Stage::ProductionSubmit)),
            Self::IosProductionSubmit => Some((Ios, Stage::ProductionSubmit)),
            _ => None,
        }
    }
    pub fn prepares_intent(self) -> bool {
        self.candidate() || self.stage().is_some()
    }
    pub fn candidate_upload(self) -> Option<store::Platform> {
        match self {
            Self::AndroidCandidateUpload => Some(store::Platform::Android),
            Self::IosCandidateUpload => Some(store::Platform::Ios),
            _ => None,
        }
    }
    /// Only the eight additional lifecycle selections. Existing candidate
    /// upload and intent Prepare keep their original encodings and predicates.
    pub fn release_mode(self) -> Option<(store::Kind, store::Platform, store::release::Mode)> {
        use store::{Kind::{Execute, Reconcile}, Platform::{Android, Ios}, release::Mode};
        match self {
            Self::AndroidExternalTestingExecute => Some((Execute, Android, Mode::ExternalTesting)),
            Self::IosExternalTestingExecute => Some((Execute, Ios, Mode::ExternalTesting)),
            Self::AndroidProductionSubmitExecute => Some((Execute, Android, Mode::ProductionSubmit)),
            Self::IosProductionSubmitExecute => Some((Execute, Ios, Mode::ProductionSubmit)),
            Self::AndroidCurrentInternal => Some((Reconcile, Android, Mode::CurrentInternal)),
            Self::IosCurrentInternal => Some((Reconcile, Ios, Mode::CurrentInternal)),
            Self::AndroidRecoverySettlement => Some((Reconcile, Android, Mode::RecoverySettlement)),
            Self::IosExternalReadiness => Some((Reconcile, Ios, Mode::ExternalReadiness)),
            _ => None,
        }
    }
    pub fn native_kind(self) -> store::Kind {
        if let Some((kind, _, _)) = self.release_mode() {
            kind
        } else if self.candidate_upload().is_some() {
            store::Kind::Execute
        } else if self.prepares_intent() {
            store::Kind::CandidatePrepare
        } else {
            store::Kind::AccessCheck
        }
    }
    pub fn consent(self) -> &'static str {
        match self {
            Self::AndroidAccess => "agent-android-store-access-once-v1",
            Self::IosAccess => "agent-ios-store-access-once-v1",
            Self::AndroidCandidate => "agent-android-store-candidate-prepare-once-v1",
            Self::IosCandidate => "agent-ios-store-candidate-prepare-once-v1",
            Self::AndroidVersions => "agent-android-current-versions-edit-once-v1",
            Self::IosVersions => "agent-ios-current-versions-read-once-v1",
            Self::PairedVersions => "agent-paired-current-versions-edit-once-v1",
            Self::AndroidExternalTesting => "agent-android-external-testing-prepare-once-v1",
            Self::IosExternalTesting => "agent-ios-external-testing-prepare-once-v1",
            Self::AndroidProductionSubmit => "agent-android-production-submit-prepare-once-v1",
            Self::IosProductionSubmit => "agent-ios-production-submit-prepare-once-v1",
            Self::AndroidCandidateUpload => "agent-android-store-execute-candidate-upload-once-v1",
            Self::IosCandidateUpload => "agent-ios-store-execute-candidate-upload-once-v1",
            Self::AndroidExternalTestingExecute => "agent-android-store-execute-external-testing-once-v1",
            Self::IosExternalTestingExecute => "agent-ios-store-execute-external-testing-once-v1",
            Self::AndroidProductionSubmitExecute => "agent-android-store-execute-production-submit-once-v1",
            Self::IosProductionSubmitExecute => "agent-ios-store-execute-production-submit-once-v1",
            Self::AndroidCurrentInternal => "agent-android-store-reconcile-current-internal-once-v1",
            Self::IosCurrentInternal => "agent-ios-store-reconcile-current-internal-once-v1",
            Self::AndroidRecoverySettlement => "agent-android-store-reconcile-recovery-settlement-once-v1",
            Self::IosExternalReadiness => "agent-ios-store-reconcile-external-readiness-once-v1",
        }
    }
    pub fn action(self) -> crate::service_protocol::Action {
        self.native_kind().action()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage {
    ExternalTesting,
    ProductionSubmit,
}
impl Stage {
    pub fn prepared_head(self) -> u32 {
        match self {
            Self::ExternalTesting => 9,
            Self::ProductionSubmit => 13,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StageSelection {
    pub stage: Stage,
    pub predecessor_operation_id: String,
    pub predecessor_receipt_sha256: String,
}
fn uuid4(v: &str) -> bool {
    store::uuid(v) && v.as_bytes()[14] == b'4' && matches!(v.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}
impl StageSelection {
    fn valid_for(&self, candidate: &str) -> bool {
        uuid4(candidate)
            && uuid4(&self.predecessor_operation_id)
            && store::sha(&self.predecessor_receipt_sha256)
            && match self.stage {
                Stage::ExternalTesting => self.predecessor_operation_id == candidate,
                Stage::ProductionSubmit => self.predecessor_operation_id != candidate,
            }
    }
    fn bounded_capacity(&self) -> bool {
        self.predecessor_operation_id.capacity() <= 36
            && self.predecessor_receipt_sha256.capacity() <= 64
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExecuteSelection {
    pub intent_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub kind: Kind,
    pub saved_config: store::Content,
    pub saved_version: store::Version,
    #[serde(deserialize_with = "nullable")]
    pub candidate: Option<store::Candidate>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub later: Option<StageSelection>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub execute: Option<ExecuteSelection>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub release: Option<store::release::Review>,
}
impl Selection {
    pub fn valid(&self) -> bool {
        self.saved_config.valid()
            && self.saved_version.valid()
            && if let Some((kind, platform, mode)) = self.kind.release_mode() {
                self.later.is_none() && self.execute.is_none()
                    && self.release.as_ref().is_some_and(|r| r.mode == mode
                        && self.candidate.as_ref().is_some_and(|c| r.valid_for(kind, platform, c)))
            } else if self.kind.candidate_upload().is_some() {
                self.release.is_none() && self.later.is_none()
                    && self.execute.as_ref().is_some_and(|e| store::sha(&e.intent_sha256))
                    && self.candidate.as_ref().is_some_and(|c| {
                        store::uuid(&c.operation_id) && store::sha(&c.sha256)
                    })
            } else {
                self.release.is_none() && self.execute.is_none()
                    && match (&self.candidate, &self.later, self.kind.stage()) {
                        (Some(c), None, None) => {
                            self.kind.candidate() && store::uuid(&c.operation_id) && store::sha(&c.sha256)
                        }
                        (None, None, None) => !self.kind.prepares_intent(),
                        (Some(c), Some(later), Some((_, stage))) => {
                            later.stage == stage && store::sha(&c.sha256) && later.valid_for(&c.operation_id)
                        }
                        _ => false,
                    }
            }
    }
    pub(crate) fn bounded_capacity(&self) -> bool {
        self.valid()
            && self.saved_config.sha256.capacity() <= 64
            && self.saved_version.sha256.capacity() <= 64
            && self.saved_version.name.capacity() <= 64
            && self
                .candidate
                .as_ref()
                .is_none_or(|c| c.operation_id.capacity() <= 36 && c.sha256.capacity() <= 64)
            && self.later.as_ref().is_none_or(StageSelection::bounded_capacity)
            && self.execute.as_ref().is_none_or(|e| e.intent_sha256.capacity() <= 64)
            && self.release.as_ref().is_none_or(|r| {
                r.intent_sha256.capacity() <= 64
                    && r.stage_operation_id.as_ref().is_none_or(|id| id.capacity() <= 36)
                    && r.basis.as_ref().is_none_or(|b| b.operation_id.capacity() <= 36
                        && b.receipt_sha256.capacity() <= 64)
            })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub review_id: Id,
    pub operation: store::Operation,
}
impl Review {
    pub fn valid(&self) -> bool {
        (1..u32::MAX).contains(&self.operation.status_revision)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, rename_all_fields = "camelCase", deny_unknown_fields)]
pub(crate) enum StageDestination {
    Android { channel: String, release_status: String },
    IosExternal { channel: String },
    IosProduction { channel: String, automatic_release: bool },
}
impl StageDestination {
    fn valid_for(&self, platform: store::Platform, stage: Stage) -> bool {
        match (platform, stage, self) {
            (store::Platform::Android, Stage::ExternalTesting, Self::Android { channel, release_status }) => {
                !channel.trim().is_empty() && channel.chars().count() <= 100
                    && !channel.contains(['\0', '\r', '\n'])
                    && !matches!(channel.as_str(), "internal" | "production")
                    && release_status == "completed"
            }
            (store::Platform::Android, Stage::ProductionSubmit, Self::Android { channel, release_status }) => {
                channel == "production" && release_status == "draft"
            }
            (store::Platform::Ios, Stage::ExternalTesting, Self::IosExternal { channel }) => channel == "testflight-external",
            (store::Platform::Ios, Stage::ProductionSubmit, Self::IosProduction { channel, automatic_release }) => channel == "app-store-review" && !automatic_release,
            _ => false,
        }
    }
    fn bounded_capacity(&self) -> bool {
        match self {
            Self::Android { channel, release_status } => channel.capacity() <= 400 && release_status.capacity() <= 9,
            Self::IosExternal { channel } | Self::IosProduction { channel, .. } => channel.capacity() <= 18,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StageLimitation {
    NonPublishing,
    PrepareNotExecute,
    CurrentStoreSnapshotMayChange,
    OriginalBinaryReused,
    PriorNativeFinalityNotEstablished,
    SavedInputsNotAtomic,
}
pub(crate) const STAGE_LIMITATIONS: [StageLimitation; 6] = [
    StageLimitation::NonPublishing,
    StageLimitation::PrepareNotExecute,
    StageLimitation::CurrentStoreSnapshotMayChange,
    StageLimitation::OriginalBinaryReused,
    StageLimitation::PriorNativeFinalityNotEstablished,
    StageLimitation::SavedInputsNotAtomic,
];
// Pure DATA parity with the native UUID4 mapper, not native construction.
// Native projection separately compares against candidate_uuid(original ID).
pub(crate) fn stage_operation_matches(uuid: &str, operation: &Id) -> bool {
    uuid4(uuid) && uuid.bytes().filter(|b| *b != b'-').eq(operation.as_str().bytes())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StageReport {
    pub platform: store::Platform,
    pub stage: Stage,
    pub operation_id: String,
    pub head_sequence: u32,
    pub candidate_operation_id: String,
    pub candidate_sha256: String,
    pub predecessor_operation_id: String,
    pub predecessor_receipt_sha256: String,
    pub intent_sha256: String,
    pub store_precondition_sha256: String,
    pub destination: StageDestination,
    pub limitations: [StageLimitation; 6],
}
impl StageReport {
    fn valid_for(&self, s: &Selection, r: &Review) -> bool {
        let (Some(c), Some(later)) = (&s.candidate, &s.later) else { return false; };
        s.valid() && s.kind.stage() == Some((self.platform, self.stage)) && later.stage == self.stage
            && stage_operation_matches(&self.operation_id, &r.operation.operation_id)
            && self.operation_id != c.operation_id && self.operation_id != later.predecessor_operation_id
            && self.candidate_operation_id == c.operation_id && self.candidate_sha256 == c.sha256
            && self.predecessor_operation_id == later.predecessor_operation_id
            && self.predecessor_receipt_sha256 == later.predecessor_receipt_sha256
            && store::sha(&self.intent_sha256) && store::sha(&self.store_precondition_sha256)
            && (self.stage.prepared_head()..=511).contains(&self.head_sequence)
            && self.destination.valid_for(self.platform, self.stage)
            && self.limitations == STAGE_LIMITATIONS
    }
    fn bounded_capacity(&self) -> bool {
        [&self.operation_id, &self.candidate_operation_id, &self.predecessor_operation_id].iter().all(|v| v.capacity() <= 36)
            && [&self.candidate_sha256, &self.predecessor_receipt_sha256, &self.intent_sha256, &self.store_precondition_sha256].iter().all(|v| v.capacity() <= 64)
            && self.destination.bounded_capacity()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Report {
    Ordinary { report: store::Report },
    CurrentVersions { inventory: Inventory },
    StagePrepare { report: StageReport },
}
impl Report {
    pub(crate) fn bounded_capacity(&self) -> bool {
        match self {
            Self::StagePrepare { report } => report.bounded_capacity(),
            Self::CurrentVersions { inventory } => inventory.bounded_capacity(),
            Self::Ordinary { report } => match report {
                store::Report::AccessCheck {
                    findings,
                    limitations,
                } => findings.capacity() <= 16 && limitations.capacity() <= 8,
                store::Report::CandidatePrepare {
                    operation_id,
                    candidate_sha256,
                    intent_sha256,
                    store_precondition_sha256,
                    limitations,
                    ..
                } => {
                    operation_id.capacity() <= 36
                        && candidate_sha256.capacity() <= 64
                        && intent_sha256.capacity() <= 64
                        && store_precondition_sha256.capacity() <= 64
                        && limitations.capacity() <= 8
                }
                store::Report::Execute { release } | store::Report::Reconcile { release } => {
                    release.operation_id.capacity() <= 36
                        && release.candidate_operation_id.capacity() <= 36
                        && release.candidate_sha256.capacity() <= 64
                        && release.intent_sha256.capacity() <= 64
                        && release.receipt_sha256.capacity() <= 64
                        && release.basis.as_ref().is_none_or(|b| b.operation_id.capacity() <= 36
                            && b.receipt_sha256.capacity() <= 64)
                        && release.limitations.capacity() <= 8
                }
            },
        }
    }
    pub fn valid_for(&self, s: &Selection, r: &Review) -> bool {
        match self {
            Self::StagePrepare { report } => report.valid_for(s, r),
            Self::CurrentVersions { inventory } => {
                inventory.valid()
                    && matches!(
                        (s.kind, inventory),
                        (Kind::IosVersions, Inventory::Ios { .. })
                            | (Kind::AndroidVersions, Inventory::Android { .. })
                            | (Kind::PairedVersions, Inventory::Both { .. })
                    )
            }
            Self::Ordinary { report } => {
                ordinary_review(s, r).is_some_and(|r| report.valid_for(&r))
            }
        }
    }
}
pub(crate) fn ordinary_review(s: &Selection, r: &Review) -> Option<store::Review> {
    if !s.valid() {
        return None;
    }
    let (kind, platform) = if let Some((kind, platform, _)) = s.kind.release_mode() {
        (kind, platform)
    } else { match s.kind {
        Kind::AndroidAccess => (store::Kind::AccessCheck, store::Platform::Android),
        Kind::IosAccess => (store::Kind::AccessCheck, store::Platform::Ios),
        Kind::AndroidCandidate => (store::Kind::CandidatePrepare, store::Platform::Android),
        Kind::IosCandidate => (store::Kind::CandidatePrepare, store::Platform::Ios),
        Kind::AndroidCandidateUpload => (store::Kind::Execute, store::Platform::Android),
        Kind::IosCandidateUpload => (store::Kind::Execute, store::Platform::Ios),
        _ => return None,
    }};
    Some(store::Review {
        kind,
        platform,
        operation_id: r.operation.operation_id.clone(),
        owner_generation: r.operation.owner_generation.clone(),
        status_revision: r.operation.status_revision,
        saved_config: s.saved_config.clone(),
        saved_version: s.saved_version.clone(),
        candidate: s.candidate.clone(),
        release: s.release.clone().or_else(|| s.execute.as_ref().map(|e| store::release::Review {
            mode: store::release::Mode::CandidateUpload,
            intent_sha256: e.intent_sha256.clone(),
            stage_operation_id: None,
            basis: None,
        })),
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Queued,
    Preparing,
    Prepared,
    Starting,
    Running,
    Stopping,
    Finishing,
    Final,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub schema_version: u32,
    pub origin: Query,
    pub prepare_grant_id: Id,
    pub selection_id: Id,
    pub revision: u32,
    pub selection: Selection,
    pub phase: Phase,
    pub settlement: Settlement,
    pub reason: store::Reason,
    #[serde(deserialize_with = "nullable")]
    pub prepared: Option<Review>,
    #[serde(deserialize_with = "nullable")]
    pub operation: Option<store::Operation>,
    #[serde(deserialize_with = "nullable")]
    pub start_grant_id: Option<Id>,
    pub prepare_returned: bool,
    pub start_submitted: bool,
    #[serde(deserialize_with = "nullable")]
    pub outcome: Option<store::Outcome>,
    #[serde(deserialize_with = "nullable")]
    pub result: Option<Report>,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        let valid = self.schema_version == 1
            && self.do_not_replay
            && self.selection.valid()
            && (1..u32::MAX).contains(&self.revision)
            && self.prepared.as_ref().is_none_or(Review::valid)
            && self.operation.as_ref().is_none_or(|o| {
                self.prepared.as_ref().is_some_and(|r| {
                    o.operation_id == r.operation.operation_id
                        && o.owner_generation == r.operation.owner_generation
                        && (r.operation.status_revision..u32::MAX).contains(&o.status_revision)
                })
            })
            && (!self.start_submitted || self.prepared.is_some() && self.start_grant_id.is_some())
            && (self.start_grant_id.is_none() || self.prepared.is_some() && self.prepare_returned)
            && self.result.as_ref().is_none_or(|v| {
                self.prepared
                    .as_ref()
                    .is_some_and(|r| v.valid_for(&self.selection, r))
            })
            && match self.phase {
                Phase::Unknown => {
                    self.settlement == Settlement::Unknown
                        && self.outcome == Some(store::Outcome::Unknown)
                        && self.result.is_none()
                        && matches!(
                            self.reason,
                            store::Reason::CleanupUnknown | store::Reason::HistoryUnavailable
                        )
                }
                Phase::Final => {
                    self.settlement == Settlement::Settled
                        && self.prepare_returned
                        && match self.outcome {
                            Some(store::Outcome::Complete) => {
                                self.start_submitted
                                    && self.reason == store::Reason::None
                                    && self.result.is_some()
                                    && self.operation.is_some()
                            }
                            Some(
                                store::Outcome::Refused
                                | store::Outcome::Failed
                                | store::Outcome::Cancelled
                                | store::Outcome::TimedOut,
                            ) => {
                                !matches!(
                                    self.reason,
                                    store::Reason::None
                                        | store::Reason::CleanupUnknown
                                        | store::Reason::HistoryUnavailable
                                ) && self.result.is_none()
                                    && (self.prepared.is_none() || self.operation.is_some())
                            }
                            _ => false,
                        }
                }
                _ => {
                    self.settlement == Settlement::Pending
                        && self.outcome.is_none()
                        && self.result.is_none()
                        && !matches!(
                            self.reason,
                            store::Reason::CleanupUnknown | store::Reason::HistoryUnavailable
                        )
                        && (self.phase != Phase::Prepared
                            || (self.prepare_returned
                                && self.prepared.is_some()
                                && !self.start_submitted))
                }
            };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Permission {
    Prepare,
    Start,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Access {
    pub schema_version: u32,
    #[serde(deserialize_with = "nullable")]
    pub service_instance: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub project_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub permission: Option<Permission>,
    #[serde(deserialize_with = "nullable")]
    pub grant_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub review_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub selection: Option<Selection>,
    #[serde(deserialize_with = "nullable")]
    pub request_id: Option<Id>,
    pub enabled: bool,
    pub consumed: bool,
    pub pending: bool,
    pub unknown: bool,
    pub remaining_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub status: Option<Status>,
}
impl Access {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            service_instance: None,
            project_id: None,
            permission: None,
            grant_id: None,
            review_id: None,
            selection: None,
            request_id: None,
            enabled: false,
            consumed: false,
            pending: false,
            unknown: false,
            remaining_ms: 0,
            status: None,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.permission.is_none() {
            return if self == &Self::empty() {
                Ok(())
            } else {
                Err(Error::InvalidRequest)
            };
        }
        if self.schema_version != 1
            || self.service_instance.is_none()
            || self.project_id.is_none()
            || self.grant_id.is_none()
            || self.review_id.is_none()
            || !self.selection.as_ref().is_some_and(Selection::valid)
            || self.remaining_ms > store::INTENT_MS
            || self.enabled != (self.remaining_ms > 0)
            || self.enabled && (self.consumed || self.unknown)
            || self.status.as_ref().is_some_and(|s| {
                s.validate().is_err()
                    || self.request_id.as_ref() != Some(&s.origin.request_id)
                    || self.project_id.as_ref() != Some(&s.origin.project_id)
                    || self.service_instance.as_ref() != Some(&s.origin.service_instance)
                    || self.selection.as_ref() != Some(&s.selection)
                    || self.pending != (s.settlement != Settlement::Settled)
                    || self.unknown != (s.phase == Phase::Unknown)
            })
            || self.request_id.is_some() != self.status.is_some()
            || self.permission == Some(Permission::Start)
                && self.status.as_ref().is_none_or(|s| {
                    s.prepared
                        .as_ref()
                        .is_none_or(|r| Some(&r.review_id) != self.review_id.as_ref())
                        || s.start_grant_id.as_ref() != self.grant_id.as_ref()
                        || self.consumed != s.start_submitted
                        || self.enabled && s.phase != Phase::Prepared
                })
            || self.permission == Some(Permission::Prepare)
                && match &self.status {
                    Some(s) => {
                        !self.consumed
                            || Some(&s.prepare_grant_id) != self.grant_id.as_ref()
                            || Some(&s.selection_id) != self.review_id.as_ref()
                    }
                    None => self.consumed || self.pending,
                }
        {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}
