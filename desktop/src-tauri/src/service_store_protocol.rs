//! Closed original-bound Store delegation DATA. No decoded value owns a
//! Prepared, credential, source, native operation or release authorization.
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const REQUEST_LIMIT: usize = 32;
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 8192;
pub(crate) const INTENT_MS: u64 = 300_000;
pub(crate) const DOCUMENT_BACKING: usize = 2 * 1024 * 1024;
#[path = "service_store_release_protocol.rs"]
pub(crate) mod release;

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub(crate) fn sha(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn uuid(v: &str) -> bool {
    v.len() == 36
        && v.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && v != "00000000-0000-0000-0000-000000000000"
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    AccessCheck,
    CandidatePrepare,
    Execute,
    Reconcile,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Platform {
    Android,
    Ios,
}
impl Kind {
    fn basic_consent(self, platform: Platform) -> Option<&'static str> {
        match (self, platform) {
            (Self::AccessCheck, Platform::Android) => Some("agent-android-store-access-once-v1"),
            (Self::AccessCheck, Platform::Ios) => Some("agent-ios-store-access-once-v1"),
            (Self::CandidatePrepare, Platform::Android) => Some("agent-android-store-candidate-prepare-once-v1"),
            (Self::CandidatePrepare, Platform::Ios) => Some("agent-ios-store-candidate-prepare-once-v1"),
            _ => None,
        }
    }
    pub(crate) fn action(self) -> crate::service_protocol::Action {
        match self {
            Self::AccessCheck => crate::service_protocol::Action::ObserveProject,
            Self::CandidatePrepare | Self::Execute | Self::Reconcile => crate::service_protocol::Action::Release,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Version {
    pub(crate) bytes: u32,
    pub(crate) sha256: String,
    pub(crate) name: String,
    pub(crate) build: u32,
}
impl Version {
    pub(crate) fn valid(&self) -> bool {
        (1..=65536).contains(&self.bytes)
            && sha(&self.sha256)
            && (1..=64).contains(&self.name.len())
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            && (1..=2_100_000_000).contains(&self.build)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Content {
    pub(crate) bytes: u32,
    pub(crate) sha256: String,
}
impl Content {
    pub(crate) fn valid(&self) -> bool {
        (1..=524288).contains(&self.bytes) && sha(&self.sha256)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Candidate {
    pub(crate) operation_id: String,
    pub(crate) sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) kind: Kind,
    pub(crate) platform: Platform,
    pub(crate) operation_id: Id,
    pub(crate) owner_generation: Id,
    pub(crate) status_revision: u32,
    pub(crate) saved_config: Content,
    pub(crate) saved_version: Version,
    #[serde(deserialize_with = "nullable")]
    pub(crate) candidate: Option<Candidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) release: Option<release::Review>,
}
impl Review {
    pub(crate) fn consent(&self) -> Option<&'static str> {
        if !self.valid() { return None; }
        self.release.as_ref().map_or_else(|| self.kind.basic_consent(self.platform), |r| r.mode.consent(self.kind, self.platform))
    }
    pub(crate) fn valid(&self) -> bool {
        (1..u32::MAX).contains(&self.status_revision)
            && self.saved_config.valid()
            && self.saved_version.valid()
            && match (self.kind, &self.candidate, &self.release) {
                (Kind::AccessCheck, None, None) => true,
                (Kind::CandidatePrepare, Some(c), None) => uuid(&c.operation_id) && sha(&c.sha256),
                (Kind::Execute | Kind::Reconcile, Some(c), Some(r)) => r.valid_for(self.kind, self.platform, c),
                _ => false,
            }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Query {
    pub(crate) project_id: Id,
    pub(crate) service_instance: Id,
    pub(crate) request_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Submit {
    pub(crate) origin: Query,
    pub(crate) grant_id: Id,
    pub(crate) review_id: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum State {
    Queued,
    Starting,
    Running,
    Stopping,
    Finishing,
    Complete,
    Failed,
    Refused,
    Cancelled,
    Expired,
    Unknown,
}
impl State {
    pub(crate) fn terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Failed | Self::Refused | Self::Cancelled | Self::Expired
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    UserCancelled,
    PermissionRevoked,
    Expired,
    ContextChanged,
    Shutdown,
    Busy,
    Unavailable,
    NativeRefused,
    CommandFailed,
    CommandIncomplete,
    TimedOut,
    CleanupUnknown,
    HistoryUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    Complete,
    Failed,
    Refused,
    Cancelled,
    TimedOut,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Check {
    CredentialFormat,
    QueryPrerequisites,
    RuntimeUnavailable,
    BundleUnavailable,
    StoreAccess,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Finding {
    pub(crate) check: Check,
    pub(crate) status: crate::agent_local_checks::CoreStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Limitation {
    NonPublishing,
    NoProjectCommands,
    NoBuildOrSigning,
    NoReleaseReadiness,
    PointInTimeAccountAccess,
    SavedInputsNotAtomic,
    PrepareNotExecute,
    TemporaryEditMayExpire,
    CurrentAscSnapshotMayChange,
    CurrentBundleNotHistoricalFinality,
}
pub(crate) const ACCESS_LIMITATIONS: [Limitation; 6] = [
    Limitation::NonPublishing,
    Limitation::NoProjectCommands,
    Limitation::NoBuildOrSigning,
    Limitation::NoReleaseReadiness,
    Limitation::PointInTimeAccountAccess,
    Limitation::SavedInputsNotAtomic,
];
pub(crate) fn prepare_limitations(platform: Platform) -> [Limitation; 5] {
    [
        Limitation::NonPublishing,
        Limitation::PrepareNotExecute,
        if platform == Platform::Android {
            Limitation::TemporaryEditMayExpire
        } else {
            Limitation::CurrentAscSnapshotMayChange
        },
        Limitation::CurrentBundleNotHistoricalFinality,
        Limitation::SavedInputsNotAtomic,
    ]
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum Report {
    Execute { release: release::Receipt },
    Reconcile { release: release::Receipt },
    AccessCheck {
        findings: Vec<Finding>,
        limitations: Vec<Limitation>,
    },
    CandidatePrepare {
        head_sequence: u32,
        operation_id: String,
        candidate_sha256: String,
        intent_sha256: String,
        store_precondition_sha256: String,
        limitations: Vec<Limitation>,
    },
}
impl Report {
    pub(crate) fn valid_for(&self, r: &Review) -> bool {
        match (self, r.kind) {
            (Self::Execute { release }, Kind::Execute) | (Self::Reconcile { release }, Kind::Reconcile) => release.valid_for(r),
            (
                Self::AccessCheck {
                    findings,
                    limitations,
                },
                Kind::AccessCheck,
            ) => findings.len() <= 16 && limitations.as_slice() == ACCESS_LIMITATIONS,
            (
                Self::CandidatePrepare {
                    head_sequence,
                    operation_id,
                    candidate_sha256,
                    intent_sha256,
                    store_precondition_sha256,
                    limitations,
                },
                Kind::CandidatePrepare,
            ) => {
                (if r.platform == Platform::Ios { 5 } else { 1 }..=513).contains(head_sequence)
                    && r.candidate.as_ref().is_some_and(|c| {
                        c.operation_id == *operation_id && c.sha256 == *candidate_sha256
                    })
                    && sha(intent_sha256)
                    && sha(store_precondition_sha256)
                    && limitations.as_slice() == prepare_limitations(r.platform)
            }
            _ => false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Operation {
    pub(crate) operation_id: Id,
    pub(crate) owner_generation: Id,
    pub(crate) status_revision: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) origin: Query,
    pub(crate) grant_id: Id,
    pub(crate) review_id: Id,
    pub(crate) revision: u32,
    pub(crate) review: Review,
    pub(crate) state: State,
    pub(crate) settlement: Settlement,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) operation: Option<Operation>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) outcome: Option<Outcome>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) result: Option<Report>,
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !self.review.valid()
            || !(1..u32::MAX).contains(&self.revision)
            || self.operation.as_ref().is_some_and(|o| {
                o.operation_id != self.review.operation_id
                    || o.owner_generation != self.review.owner_generation
                    || !(self.review.status_revision..u32::MAX).contains(&o.status_revision)
            })
            || self
                .result
                .as_ref()
                .is_some_and(|r| !r.valid_for(&self.review))
        {
            return Err(Error::InvalidRequest);
        }
        let valid = if self.state == State::Unknown {
            self.settlement == Settlement::Unknown
                && self.outcome == Some(Outcome::Unknown)
                && self.result.is_none()
                && matches!(
                    self.reason,
                    Reason::CleanupUnknown | Reason::HistoryUnavailable
                )
        } else if self.state.terminal() {
            self.settlement == Settlement::Settled
                && self.operation.is_some()
                && match (self.state, self.outcome) {
                    (State::Complete, Some(Outcome::Complete)) => {
                        self.reason == Reason::None && self.result.is_some()
                    }
                    (State::Failed, Some(Outcome::Failed | Outcome::TimedOut))
                    | (State::Refused, Some(Outcome::Refused))
                    | (State::Expired, Some(Outcome::Refused))
                    | (State::Cancelled, Some(Outcome::Cancelled | Outcome::Refused)) => {
                        !matches!(
                            self.reason,
                            Reason::None | Reason::CleanupUnknown | Reason::HistoryUnavailable
                        ) && self.result.is_none()
                    }
                    _ => false,
                }
        } else {
            self.settlement == Settlement::Pending
                && self.outcome.is_none()
                && self.result.is_none()
                && self.reason != Reason::CleanupUnknown
                && self.reason != Reason::HistoryUnavailable
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Access {
    #[serde(deserialize_with = "nullable")]
    pub(crate) service_instance: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) project_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) grant_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) review_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) review: Option<Review>,
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    pub(crate) consumed: bool,
    pub(crate) pending: bool,
    pub(crate) unknown: bool,
    #[serde(deserialize_with = "nullable")]
    pub(crate) request_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) status: Option<Status>,
}
impl Access {
    pub(crate) fn empty() -> Self {
        Self {
            service_instance: None,
            project_id: None,
            grant_id: None,
            review_id: None,
            review: None,
            enabled: false,
            remaining_ms: 0,
            consumed: false,
            pending: false,
            unknown: false,
            request_id: None,
            status: None,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let fields = [
            self.service_instance.is_some(),
            self.project_id.is_some(),
            self.grant_id.is_some(),
            self.review_id.is_some(),
            self.review.is_some(),
        ];
        let present = fields.iter().all(|v| *v);
        if !present && fields.iter().any(|v| *v)
            || self.review.as_ref().is_some_and(|v| !v.valid())
            || self.remaining_ms > INTENT_MS
            || self.enabled
                != (present
                    && !self.consumed
                    && !self.pending
                    && !self.unknown
                    && self.remaining_ms > 0)
            || !self.enabled && self.remaining_ms != 0
            || self.consumed != self.request_id.is_some()
            || self.status.is_some() != self.consumed
            || !present && (self.pending || self.unknown || self.consumed)
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(s) = &self.status {
            s.validate()?;
            if Some(&s.origin.service_instance) != self.service_instance.as_ref()
                || Some(&s.origin.project_id) != self.project_id.as_ref()
                || Some(&s.origin.request_id) != self.request_id.as_ref()
                || Some(&s.grant_id) != self.grant_id.as_ref()
                || Some(&s.review_id) != self.review_id.as_ref()
                || Some(&s.review) != self.review.as_ref()
                || self.pending != (s.settlement != Settlement::Settled)
                || self.unknown != (s.state == State::Unknown)
            {
                return Err(Error::InvalidRequest);
            }
        }
        Ok(())
    }
}
