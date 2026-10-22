//! Closed IDs-only delegation DATA. No credential, URL, draft or native owner.
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Deserializer, Serialize};
#[path = "service_github_activity_protocol.rs"]
pub(crate) mod activity;
#[path = "service_github_dispatch_protocol.rs"]
pub(crate) mod dispatch;
#[path = "service_counter_enrollment_protocol.rs"]
pub(crate) mod enrollment;
pub(crate) const REQUEST_LIMIT: usize = 32;
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 2048;
pub(crate) const INTENT_MS: u64 = 120_000;
// All32 original rows/scopes/history remain, including tombstones and
// actual root/string capacity. The requests child checks real typed row and
// ancillary ceilings. Only the separately named IPC8 term is transferred.
pub(crate) const ROW_BACKING: usize = 16 * 1024;
pub(crate) const IPC_WORKER_BACKING: usize = 32 * 1024;
// Existing two unused/transition rows plus original MAIN scratch, not a new debit.
pub(crate) const MAIN_CALL_BACKING: usize = 2 * ROW_BACKING + 16 * 1024;
pub(crate) const DOCUMENT_BACKING: usize = REQUEST_LIMIT * ROW_BACKING + 2 * 128 * 1024;
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
pub(crate) fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    RepositoryCreate,
    DraftPrCreate,
    PrCreate,
    FailedJobsRetry,
    SetupPublish,
    SetupReconcile,
    ActivityOverview,
    PreflightPrepare,
    PreflightDispatch,
    PreflightPending,
    PreflightObserve,
    ReleasePrepare,
    ReleaseDispatch,
    ReleasePending,
    ReleaseObserve,
    SetupPrepare,
    CounterPrepare,
    CounterCreate,
    PublicationPending,
    CounterReconcile,
    CounterEnrollmentReview,
    CounterEnrollmentConnect,
}
impl Kind {
    pub(crate) fn enrollment_family(self) -> bool { matches!(self, Self::CounterEnrollmentReview | Self::CounterEnrollmentConnect) }
    pub(crate) fn dispatch_family(self)->bool { matches!(self,Self::PreflightPrepare | Self::PreflightDispatch | Self::PreflightPending | Self::PreflightObserve | Self::ReleasePrepare | Self::ReleaseDispatch | Self::ReleasePending | Self::ReleaseObserve | Self::SetupPrepare | Self::CounterPrepare | Self::CounterCreate | Self::PublicationPending | Self::CounterReconcile) }
    pub(crate) fn mutation(self)->bool { !matches!(self, Self::CounterEnrollmentReview | Self::SetupReconcile | Self::ActivityOverview | Self::PreflightPrepare | Self::PreflightPending | Self::PreflightObserve | Self::ReleasePrepare | Self::ReleasePending | Self::ReleaseObserve | Self::SetupPrepare | Self::CounterPrepare | Self::PublicationPending | Self::CounterReconcile) }
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Self::ActivityOverview => "github-activity-",
            Self::PreflightPrepare => "github-preflight-",
            Self::PreflightDispatch => "github-preflight-",
            Self::PreflightPending => "github-preflight-",
            Self::PreflightObserve => "github-preflight-",
            Self::ReleasePrepare => "github-release-",
            Self::ReleaseDispatch => "github-release-",
            Self::ReleasePending => "github-release-",
            Self::ReleaseObserve => "github-release-",
            Self::SetupPrepare => "github-publication-",
            Self::CounterPrepare => "github-publication-",
            Self::CounterCreate => "github-publication-",
            Self::PublicationPending => "github-publication-",
            Self::CounterReconcile => "github-publication-",
            Self::CounterEnrollmentReview | Self::CounterEnrollmentConnect => "version-enrollment-",

            Self::RepositoryCreate => "repository-create-",
            Self::DraftPrCreate | Self::PrCreate => "github-pull-request-",
            Self::FailedJobsRetry => "github-actions-retry-",
            Self::SetupPublish | Self::SetupReconcile => "github-publication-",
        }
    }
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::ActivityOverview => "agent-activity-overview-once-v1",
            Self::PreflightPrepare => "agent-preflight-prepare-once-v1",
            Self::PreflightDispatch => "agent-preflight-dispatch-once-v1",
            Self::PreflightPending => "agent-preflight-pending-once-v1",
            Self::PreflightObserve => "agent-preflight-observe-once-v1",
            Self::ReleasePrepare => "agent-release-prepare-once-v1",
            Self::ReleaseDispatch => "agent-release-dispatch-once-v1",
            Self::ReleasePending => "agent-release-pending-once-v1",
            Self::ReleaseObserve => "agent-release-observe-once-v1",
            Self::SetupPrepare => "agent-setup-prepare-once-v1",
            Self::CounterPrepare => "agent-counter-prepare-once-v1",
            Self::CounterCreate => "agent-counter-create-once-v1",
            Self::PublicationPending => "agent-publication-pending-once-v1",
            Self::CounterReconcile => "agent-counter-reconcile-once-v1",
            Self::CounterEnrollmentReview => "agent-counter-enrollment-review-once-v1",
            Self::CounterEnrollmentConnect => "agent-counter-enrollment-connect-once-v1",

            Self::RepositoryCreate => "agent-repository-create-once-v1",
            Self::DraftPrCreate => "agent-draft-pr-create-once-v1",
            Self::PrCreate => "agent-pr-create-once-v1",
            Self::FailedJobsRetry => "agent-failed-jobs-retry-once-v1",
            Self::SetupPublish => "agent-setup-publish-once-v1",
            Self::SetupReconcile => "agent-setup-reconcile-once-v1",
        }
    }
    pub(crate) fn action(self) -> crate::service_protocol::Action {
        match self {
            Self::ActivityOverview => crate::service_protocol::Action::GitHubActivityOverview,
            Self::PreflightPrepare => crate::service_protocol::Action::GitHubPreflightPrepare,
            Self::PreflightDispatch => crate::service_protocol::Action::GitHubPreflightDispatch,
            Self::PreflightPending => crate::service_protocol::Action::GitHubPreflightPending,
            Self::PreflightObserve => crate::service_protocol::Action::GitHubPreflightObserve,
            Self::ReleasePrepare => crate::service_protocol::Action::GitHubReleasePrepare,
            Self::ReleaseDispatch => crate::service_protocol::Action::GitHubReleaseDispatch,
            Self::ReleasePending => crate::service_protocol::Action::GitHubReleasePending,
            Self::ReleaseObserve => crate::service_protocol::Action::GitHubReleaseObserve,
            Self::SetupPrepare => crate::service_protocol::Action::GitHubSetupPrepare,
            Self::CounterPrepare => crate::service_protocol::Action::GitHubCounterPrepare,
            Self::CounterCreate => crate::service_protocol::Action::GitHubCounterCreate,
            Self::PublicationPending => crate::service_protocol::Action::GitHubPublicationPending,
            Self::CounterReconcile => crate::service_protocol::Action::GitHubCounterReconcile,
            Self::CounterEnrollmentReview => crate::service_protocol::Action::GitHubCounterEnrollmentReview,
            Self::CounterEnrollmentConnect => crate::service_protocol::Action::GitHubCounterEnrollmentConnect,

            Self::RepositoryCreate => crate::service_protocol::Action::GitHubRepositoryCreate,
            Self::DraftPrCreate => crate::service_protocol::Action::GitHubDraftPrCreate,
            Self::PrCreate => crate::service_protocol::Action::GitHubPrCreate,
            Self::FailedJobsRetry => crate::service_protocol::Action::GitHubFailedJobsRetry,
            Self::SetupPublish => crate::service_protocol::Action::GitHubSetupPublish,
            Self::SetupReconcile => crate::service_protocol::Action::GitHubSetupReconcile,
        }
    }
    pub(crate) fn initial_effect(self) -> Effect {
        if self.mutation() { Effect::NotSent } else { Effect::None }
    }
    pub(crate) fn go_effect(self) -> Effect {
        if self.mutation() { Effect::PotentiallyApplied } else { Effect::None }
    }
    pub(crate) fn operation(self, s: &str) -> bool {
        if self.enrollment_family() { return hex(s, 32); }
        s.strip_prefix(self.prefix()).is_some_and(|n| {
            !n.is_empty()
                && n.len() <= 20
                && !n.starts_with('0')
                && n.bytes().all(|c| c.is_ascii_digit())
                && n.parse::<u64>().is_ok()
        })
    }
}
// Separate typed payloads: the original three and setup Publish still encode
// their exact five fields. A GET-only original row has a marker/hash, NEVER a
// synthetic consentId. Newtype structs enforce duplicate/extra-field rejection;
// no optional-null placeholders, flatten or generic Value authority is used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PreparedReference {
    pub(crate) session_id: String,
    pub(crate) consent_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) prepared_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingReference {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) marker: String,
    pub(crate) record_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Review {
    RepositoryCreate(PreparedReference),
    DraftPrCreate(PreparedReference),
    PrCreate(PreparedReference),
    FailedJobsRetry(PreparedReference),
    SetupPublish(PreparedReference),
    SetupReconcile(PendingReference),
    ActivityOverview(activity::Reference),
    PreflightPrepare(dispatch::RequestReference),
    PreflightDispatch(PreparedReference),
    PreflightPending(dispatch::RequestReference),
    PreflightObserve(dispatch::RecordReference),
    ReleasePrepare(dispatch::RequestReference),
    ReleaseDispatch(PreparedReference),
    ReleasePending(dispatch::RequestReference),
    ReleaseObserve(dispatch::RecordReference),
    SetupPrepare(dispatch::RequestReference),
    CounterPrepare(dispatch::RequestReference),
    CounterCreate(PreparedReference),
    PublicationPending(dispatch::RequestReference),
    CounterReconcile(PendingReference),
    CounterEnrollmentReview(enrollment::ReviewReference),
    CounterEnrollmentConnect(enrollment::ConnectReference),

}
fn original(session: &str, revision: u32) -> bool {
    !session.is_empty() && session.len() <= 64
        && session.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        && (1..u32::MAX).contains(&revision)
}
impl Review {
    pub(crate) fn from_prepared(kind: Kind, value: PreparedReference) -> Option<Self> {
        Some(match kind {
            Kind::RepositoryCreate => Self::RepositoryCreate(value),
            Kind::DraftPrCreate => Self::DraftPrCreate(value),
            Kind::PrCreate => Self::PrCreate(value),
            Kind::FailedJobsRetry => Self::FailedJobsRetry(value),
            Kind::SetupPublish => Self::SetupPublish(value),
            Kind::PreflightDispatch => Self::PreflightDispatch(value),
            Kind::ReleaseDispatch => Self::ReleaseDispatch(value),
            Kind::CounterCreate => Self::CounterCreate(value),
            _ => return None,
        })
    }
    pub(crate) fn kind(&self) -> Kind {
        match self {
            Self::RepositoryCreate(_) => Kind::RepositoryCreate,
            Self::DraftPrCreate(_) => Kind::DraftPrCreate,
            Self::PrCreate(_) => Kind::PrCreate,
            Self::FailedJobsRetry(_) => Kind::FailedJobsRetry,
            Self::SetupPublish(_) => Kind::SetupPublish,
            Self::SetupReconcile(_) => Kind::SetupReconcile,
            Self::ActivityOverview(_) => Kind::ActivityOverview,
            Self::PreflightPrepare(_) => Kind::PreflightPrepare,
            Self::PreflightDispatch(_) => Kind::PreflightDispatch,
            Self::PreflightPending(_) => Kind::PreflightPending,
            Self::PreflightObserve(_) => Kind::PreflightObserve,
            Self::ReleasePrepare(_) => Kind::ReleasePrepare,
            Self::ReleaseDispatch(_) => Kind::ReleaseDispatch,
            Self::ReleasePending(_) => Kind::ReleasePending,
            Self::ReleaseObserve(_) => Kind::ReleaseObserve,
            Self::SetupPrepare(_) => Kind::SetupPrepare,
            Self::CounterPrepare(_) => Kind::CounterPrepare,
            Self::CounterCreate(_) => Kind::CounterCreate,
            Self::PublicationPending(_) => Kind::PublicationPending,
            Self::CounterReconcile(_) => Kind::CounterReconcile,
            Self::CounterEnrollmentReview(_) => Kind::CounterEnrollmentReview,
            Self::CounterEnrollmentConnect(_) => Kind::CounterEnrollmentConnect,

        }
    }
    pub(crate) fn prepared(&self) -> Option<&PreparedReference> {
        match self {
            Self::RepositoryCreate(v) | Self::DraftPrCreate(v) | Self::PrCreate(v) | Self::FailedJobsRetry(v) | Self::SetupPublish(v) | Self::PreflightDispatch(v) | Self::ReleaseDispatch(v) | Self::CounterCreate(v) => Some(v),
            _ => None,
        }
    }
    #[cfg(test)]
    pub(crate) fn prepared_mut(&mut self) -> Option<&mut PreparedReference> {
        match self {
            Self::RepositoryCreate(v) | Self::DraftPrCreate(v) | Self::PrCreate(v) | Self::FailedJobsRetry(v) | Self::SetupPublish(v) | Self::PreflightDispatch(v) | Self::ReleaseDispatch(v) | Self::CounterCreate(v) => Some(v),
            _ => None,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::ActivityOverview(v) => v.valid(),
            Self::CounterEnrollmentReview(v) => v.valid(),
            Self::CounterEnrollmentConnect(v) => v.valid(),
            Self::PreflightPrepare(v) | Self::PreflightPending(v) | Self::ReleasePrepare(v) | Self::ReleasePending(v) | Self::SetupPrepare(v) | Self::CounterPrepare(v) | Self::PublicationPending(v) => v.valid(),
            Self::PreflightObserve(v) | Self::ReleaseObserve(v) => v.valid(),
            Self::SetupReconcile(v) | Self::CounterReconcile(v) => original(&v.session_id, v.expected_revision) && hex(&v.marker, 32) && hex(&v.record_sha256, 64),
            _ => self.prepared().is_some_and(|v| original(&v.session_id, v.expected_revision) && hex(&v.consent_id, 32) && hex(&v.prepared_sha256, 64)),
        }
    }
    pub(crate) fn retained_fits(&self) -> bool {
        // Same exact three string-allocation bounds as the original profile.
        match self {
            Self::ActivityOverview(v) => v.retained_fits(),
            Self::CounterEnrollmentReview(v) => v.retained_fits(),
            Self::CounterEnrollmentConnect(v) => v.retained_fits(),
            Self::PreflightPrepare(v) | Self::PreflightPending(v) | Self::ReleasePrepare(v) | Self::ReleasePending(v) | Self::SetupPrepare(v) | Self::CounterPrepare(v) | Self::PublicationPending(v) => v.retained_fits(),
            Self::PreflightObserve(v) | Self::ReleaseObserve(v) => v.retained_fits(),
            Self::SetupReconcile(v) | Self::CounterReconcile(v) => v.session_id.capacity() <= 128 && v.marker.capacity() <= 64 && v.record_sha256.capacity() <= 128,
            _ => self.prepared().is_some_and(|v| v.session_id.capacity() <= 128 && v.consent_id.capacity() <= 64 && v.prepared_sha256.capacity() <= 128),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PreparedSelection {
    pub(crate) session_id: String,
    pub(crate) consent_id: String,
    pub(crate) expected_revision: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingSelection {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) marker: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Selection {
    RepositoryCreate(PreparedSelection),
    DraftPrCreate(PreparedSelection),
    PrCreate(PreparedSelection),
    FailedJobsRetry(PreparedSelection),
    SetupPublish(PreparedSelection),
    SetupReconcile(PendingSelection),
    ActivityOverview(activity::Selection),
}
impl Selection {
    pub(crate) fn kind(&self) -> Kind {
        match self {
            Self::RepositoryCreate(_) => Kind::RepositoryCreate,
            Self::DraftPrCreate(_) => Kind::DraftPrCreate,
            Self::PrCreate(_) => Kind::PrCreate,
            Self::FailedJobsRetry(_) => Kind::FailedJobsRetry,
            Self::SetupPublish(_) => Kind::SetupPublish,
            Self::SetupReconcile(_) => Kind::SetupReconcile,
            Self::ActivityOverview(_) => Kind::ActivityOverview,
        }
    }
    pub(crate) fn prepared(&self) -> Option<&PreparedSelection> {
        match self {
            Self::RepositoryCreate(v) | Self::DraftPrCreate(v) | Self::PrCreate(v) | Self::FailedJobsRetry(v) | Self::SetupPublish(v) => Some(v),
            Self::SetupReconcile(_) | Self::ActivityOverview(_) => None,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::ActivityOverview(v) => v.valid(),
            Self::SetupReconcile(v) => original(&v.session_id, v.expected_revision) && hex(&v.marker, 32),
            _ => self.prepared().is_some_and(|v| original(&v.session_id, v.expected_revision) && hex(&v.consent_id, 32)),
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
    CleanupUnknown,
    HistoryUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect {
    None,
    NotSent,
    PotentiallyApplied,
    AcknowledgedUnconfirmed,
    CreatedObserved,
    Unresolved,
    FoundUnattributed,
    AcceptedUnconfirmed,
    Accepted,
    AdvancedUnattributed,
    BranchObserved,
    DraftPrObserved,
    CounterObserved,
    LocalMappingObserved,
}
impl Effect {
    pub(crate) fn valid_for(self, k: Kind) -> bool {
        if k.enrollment_family() { return match self {
            Self::None => k == Kind::CounterEnrollmentReview,
            Self::NotSent | Self::PotentiallyApplied | Self::LocalMappingObserved => k == Kind::CounterEnrollmentConnect,
            _ => false,
        }; }
        if k.dispatch_family() { return match self {
            Self::None=>!k.mutation(),
            Self::NotSent|Self::PotentiallyApplied=>k.mutation(),
            Self::Accepted=>matches!(k,Kind::PreflightDispatch|Kind::ReleaseDispatch),
            Self::CounterObserved=>matches!(k,Kind::CounterCreate|Kind::CounterReconcile),
            Self::Unresolved=>k==Kind::CounterReconcile,
            _=>false,
        }; }
        match self {
            Self::CounterObserved | Self::LocalMappingObserved=>false,
            Self::None => matches!(k, Kind::SetupReconcile | Kind::ActivityOverview),
            Self::NotSent | Self::PotentiallyApplied => matches!(k, Kind::RepositoryCreate | Kind::DraftPrCreate | Kind::PrCreate | Kind::FailedJobsRetry | Kind::SetupPublish),
            Self::Unresolved => matches!(k, Kind::RepositoryCreate | Kind::DraftPrCreate | Kind::PrCreate | Kind::FailedJobsRetry | Kind::SetupReconcile),
            Self::CreatedObserved | Self::FoundUnattributed => matches!(k, Kind::RepositoryCreate | Kind::DraftPrCreate | Kind::PrCreate),
            Self::BranchObserved => k == Kind::SetupReconcile,
            Self::DraftPrObserved => matches!(k, Kind::SetupPublish | Kind::SetupReconcile),
            Self::AcknowledgedUnconfirmed => matches!(k, Kind::DraftPrCreate | Kind::PrCreate),
            Self::AcceptedUnconfirmed | Self::Accepted | Self::AdvancedUnattributed => {
                k == Kind::FailedJobsRetry
            }
        }
    }
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
    Refused,
    Cancelled,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) origin: Query,
    pub(crate) grant_id: Id,
    pub(crate) review: Review,
    pub(crate) revision: u32,
    pub(crate) state: State,
    pub(crate) settlement: Settlement,
    #[serde(deserialize_with = "nullable")]
    pub(crate) operation_id: Option<String>,
    pub(crate) reason: Reason,
    pub(crate) effect: Effect,
    pub(crate) never_admitted: bool,
    pub(crate) do_not_replay: bool,
    // Absent on all six original kinds, preserving their exact serialized bytes.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "activity::optional_snapshot")]
    pub(crate) snapshot: Option<activity::Snapshot>,
    #[serde(default, skip_serializing_if="Option::is_none", deserialize_with="dispatch::optional_snapshot")]
    pub(crate) result: Option<dispatch::Snapshot>,
}
impl Status {
    pub(crate) fn limit(&self) -> usize {
        if self.review.kind() == Kind::ActivityOverview || self.review.kind().dispatch_family() || self.review.kind().enrollment_family() { activity::RESPONSE_LIMIT } else { STATUS_LIMIT }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let snapshot_valid = match (&self.review, &self.snapshot) {
            (Review::ActivityOverview(reference), Some(snapshot)) => self.state == State::Complete
                && snapshot.valid() && snapshot.matches(reference),
            (Review::ActivityOverview(_), None) => self.state != State::Complete,
            (_, None) => true,
            _ => false,
        };
        let result_valid = match &self.result {
            Some(dispatch::Snapshot::Enrollment(result)) => self.snapshot.is_none()
                && result.valid_row(self.review.kind(), self.state, self.operation_id.as_deref(), self.effect),
            Some(result)=>self.snapshot.is_none() && self.state==State::Complete && result.valid_for(self.review.kind()),
            None=>self.state!=State::Complete || !dispatch::requires_result(self.review.kind()),
        };
        let terminal = matches!(
            self.state,
            State::Complete | State::Refused | State::Cancelled
        );
        if !result_valid || !snapshot_valid || !self.review.valid()
            || !(1..u32::MAX).contains(&self.revision)
            || !self.do_not_replay
            || !self.effect.valid_for(self.review.kind())
            || self.effect == Effect::LocalMappingObserved && self.state != State::Complete
            || self
                .operation_id
                .as_ref()
                .is_some_and(|s| !self.review.kind().operation(s))
            || terminal != (self.settlement == Settlement::Settled)
            || (self.state == State::Unknown) != (self.settlement == Settlement::Unknown)
            || self.never_admitted
                && (self.operation_id.is_some()
                    || self.effect != self.review.kind().initial_effect()
                    || !matches!(
                        self.state,
                        State::Finishing | State::Refused | State::Cancelled
                    ))
            || self.effect != self.review.kind().initial_effect() && self.operation_id.is_none()
            || self.state == State::Complete
                && (self.reason != Reason::None
                    || self.operation_id.is_none()
                    || self.never_admitted)
            || self.state == State::Unknown
                && !matches!(
                    self.reason,
                    Reason::CleanupUnknown | Reason::HistoryUnavailable
                )
            || self.state != State::Unknown
                && matches!(
                    self.reason,
                    Reason::CleanupUnknown | Reason::HistoryUnavailable
                )
            || matches!(self.state, State::Refused | State::Cancelled)
                && self.reason == Reason::None
            || crate::service_metadata_text_protocol::bounded(self, self.limit()).is_err()
        {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
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
    pub(crate) review: Option<Review>,
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    pub(crate) consumed: bool,
    pub(crate) pending: bool,
    pub(crate) unknown: bool,
    #[serde(deserialize_with = "nullable")]
    pub(crate) status: Option<Status>,
}
impl Access {
    pub(crate) fn empty() -> Self {
        Self {
            service_instance: None,
            project_id: None,
            grant_id: None,
            review: None,
            enabled: false,
            remaining_ms: 0,
            consumed: false,
            pending: false,
            unknown: false,
            status: None,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let fields = [
            self.service_instance.is_some(),
            self.project_id.is_some(),
            self.grant_id.is_some(),
            self.review.is_some(),
        ];
        let present = fields.iter().all(|v| *v);
        if !present && fields.iter().any(|v| *v)
            || self.review.as_ref().is_some_and(|r| !r.valid())
            || self.remaining_ms > INTENT_MS
            || self.enabled
                != (present
                    && !self.consumed
                    && !self.pending
                    && !self.unknown
                    && self.remaining_ms > 0)
            || !self.enabled && self.remaining_ms != 0
            || self.consumed != self.status.is_some()
            || !present && (self.pending || self.unknown || self.consumed)
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(s) = &self.status {
            s.validate()?;
            if Some(&s.origin.service_instance) != self.service_instance.as_ref()
                || Some(&s.origin.project_id) != self.project_id.as_ref()
                || Some(&s.grant_id) != self.grant_id.as_ref()
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

#[cfg(test)]
#[path = "service_github_action_protocol_tests.rs"]
mod tests;
