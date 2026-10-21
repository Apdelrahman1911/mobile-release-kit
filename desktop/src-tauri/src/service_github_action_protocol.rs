//! Closed IDs-only delegation DATA. No credential, URL, draft or native owner.
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Deserializer, Serialize};
pub(crate) const REQUEST_LIMIT: usize = 32;
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 2048;
pub(crate) const INTENT_MS: u64 = 120_000;
// 32 retained rows/scopes/native+history copies *16KiB +8 incremental typed/
// encoded worker copies *32KiB +128KiB fixed/transient backing <1MiB. Includes
// tombstones and full 4KiB root per row. Original IPC/native backing is separate.
pub(crate) const DOCUMENT_BACKING: usize = 1024 * 1024;
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
    FailedJobsRetry,
    SetupPublish,
    SetupReconcile,
}
impl Kind {
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Self::RepositoryCreate => "repository-create-",
            Self::DraftPrCreate => "github-pull-request-",
            Self::FailedJobsRetry => "github-actions-retry-",
            Self::SetupPublish | Self::SetupReconcile => "github-publication-",
        }
    }
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::RepositoryCreate => "agent-repository-create-once-v1",
            Self::DraftPrCreate => "agent-draft-pr-create-once-v1",
            Self::FailedJobsRetry => "agent-failed-jobs-retry-once-v1",
            Self::SetupPublish => "agent-setup-publish-once-v1",
            Self::SetupReconcile => "agent-setup-reconcile-once-v1",
        }
    }
    pub(crate) fn action(self) -> crate::service_protocol::Action {
        match self {
            Self::RepositoryCreate => crate::service_protocol::Action::GitHubRepositoryCreate,
            Self::DraftPrCreate => crate::service_protocol::Action::GitHubDraftPrCreate,
            Self::FailedJobsRetry => crate::service_protocol::Action::GitHubFailedJobsRetry,
            Self::SetupPublish => crate::service_protocol::Action::GitHubSetupPublish,
            Self::SetupReconcile => crate::service_protocol::Action::GitHubSetupReconcile,
        }
    }
    pub(crate) fn initial_effect(self) -> Effect {
        if self == Self::SetupReconcile { Effect::None } else { Effect::NotSent }
    }
    pub(crate) fn go_effect(self) -> Effect {
        if self == Self::SetupReconcile { Effect::None } else { Effect::PotentiallyApplied }
    }
    pub(crate) fn operation(self, s: &str) -> bool {
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
    FailedJobsRetry(PreparedReference),
    SetupPublish(PreparedReference),
    SetupReconcile(PendingReference),
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
            Kind::FailedJobsRetry => Self::FailedJobsRetry(value),
            Kind::SetupPublish => Self::SetupPublish(value),
            Kind::SetupReconcile => return None,
        })
    }
    pub(crate) fn kind(&self) -> Kind {
        match self {
            Self::RepositoryCreate(_) => Kind::RepositoryCreate,
            Self::DraftPrCreate(_) => Kind::DraftPrCreate,
            Self::FailedJobsRetry(_) => Kind::FailedJobsRetry,
            Self::SetupPublish(_) => Kind::SetupPublish,
            Self::SetupReconcile(_) => Kind::SetupReconcile,
        }
    }
    pub(crate) fn prepared(&self) -> Option<&PreparedReference> {
        match self {
            Self::RepositoryCreate(v) | Self::DraftPrCreate(v) | Self::FailedJobsRetry(v) | Self::SetupPublish(v) => Some(v),
            Self::SetupReconcile(_) => None,
        }
    }
    #[cfg(test)]
    pub(crate) fn prepared_mut(&mut self) -> Option<&mut PreparedReference> {
        match self {
            Self::RepositoryCreate(v) | Self::DraftPrCreate(v) | Self::FailedJobsRetry(v) | Self::SetupPublish(v) => Some(v),
            Self::SetupReconcile(_) => None,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::SetupReconcile(v) => original(&v.session_id, v.expected_revision) && hex(&v.marker, 32) && hex(&v.record_sha256, 64),
            _ => self.prepared().is_some_and(|v| original(&v.session_id, v.expected_revision) && hex(&v.consent_id, 32) && hex(&v.prepared_sha256, 64)),
        }
    }
    pub(crate) fn retained_fits(&self) -> bool {
        // Same exact three string-allocation bounds as the original profile.
        match self {
            Self::SetupReconcile(v) => v.session_id.capacity() <= 128 && v.marker.capacity() <= 64 && v.record_sha256.capacity() <= 128,
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
    FailedJobsRetry(PreparedSelection),
    SetupPublish(PreparedSelection),
    SetupReconcile(PendingSelection),
}
impl Selection {
    pub(crate) fn kind(&self) -> Kind {
        match self {
            Self::RepositoryCreate(_) => Kind::RepositoryCreate,
            Self::DraftPrCreate(_) => Kind::DraftPrCreate,
            Self::FailedJobsRetry(_) => Kind::FailedJobsRetry,
            Self::SetupPublish(_) => Kind::SetupPublish,
            Self::SetupReconcile(_) => Kind::SetupReconcile,
        }
    }
    pub(crate) fn prepared(&self) -> Option<&PreparedSelection> {
        match self {
            Self::RepositoryCreate(v) | Self::DraftPrCreate(v) | Self::FailedJobsRetry(v) | Self::SetupPublish(v) => Some(v),
            Self::SetupReconcile(_) => None,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
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
}
impl Effect {
    pub(crate) fn valid_for(self, k: Kind) -> bool {
        match self {
            Self::None => k == Kind::SetupReconcile,
            Self::NotSent | Self::PotentiallyApplied => matches!(k, Kind::RepositoryCreate | Kind::DraftPrCreate | Kind::FailedJobsRetry | Kind::SetupPublish),
            Self::Unresolved => matches!(k, Kind::RepositoryCreate | Kind::DraftPrCreate | Kind::FailedJobsRetry | Kind::SetupReconcile),
            Self::CreatedObserved | Self::FoundUnattributed => matches!(k, Kind::RepositoryCreate | Kind::DraftPrCreate),
            Self::BranchObserved => k == Kind::SetupReconcile,
            Self::DraftPrObserved => matches!(k, Kind::SetupPublish | Kind::SetupReconcile),
            Self::AcknowledgedUnconfirmed => k == Kind::DraftPrCreate,
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
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let terminal = matches!(
            self.state,
            State::Complete | State::Refused | State::Cancelled
        );
        if !self.review.valid()
            || !(1..u32::MAX).contains(&self.revision)
            || !self.do_not_replay
            || !self.effect.valid_for(self.review.kind())
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
            || serde_json::to_vec(self).map_or(true, |b| b.len() > STATUS_LIMIT)
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
