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
}
impl Kind {
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Self::RepositoryCreate => "repository-create-",
            Self::DraftPrCreate => "github-pull-request-",
            Self::FailedJobsRetry => "github-actions-retry-",
        }
    }
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::RepositoryCreate => "agent-repository-create-once-v1",
            Self::DraftPrCreate => "agent-draft-pr-create-once-v1",
            Self::FailedJobsRetry => "agent-failed-jobs-retry-once-v1",
        }
    }
    pub(crate) fn action(self) -> crate::service_protocol::Action {
        match self {
            Self::RepositoryCreate => crate::service_protocol::Action::GitHubRepositoryCreate,
            Self::DraftPrCreate => crate::service_protocol::Action::GitHubDraftPrCreate,
            Self::FailedJobsRetry => crate::service_protocol::Action::GitHubFailedJobsRetry,
        }
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) kind: Kind,
    pub(crate) session_id: String,
    pub(crate) consent_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) prepared_sha256: String,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        !self.session_id.is_empty()
            && self.session_id.len() <= 64
            && self
                .session_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            && hex(&self.consent_id, 32)
            && (1..u32::MAX).contains(&self.expected_revision)
            && hex(&self.prepared_sha256, 64)
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
    NotSent,
    PotentiallyApplied,
    AcknowledgedUnconfirmed,
    CreatedObserved,
    Unresolved,
    FoundUnattributed,
    AcceptedUnconfirmed,
    Accepted,
    AdvancedUnattributed,
}
impl Effect {
    pub(crate) fn valid_for(self, k: Kind) -> bool {
        match self {
            Self::NotSent | Self::PotentiallyApplied | Self::Unresolved => true,
            Self::CreatedObserved | Self::FoundUnattributed => k != Kind::FailedJobsRetry,
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
            || !self.effect.valid_for(self.review.kind)
            || self
                .operation_id
                .as_ref()
                .is_some_and(|s| !self.review.kind.operation(s))
            || terminal != (self.settlement == Settlement::Settled)
            || (self.state == State::Unknown) != (self.settlement == Settlement::Unknown)
            || self.never_admitted
                && (self.operation_id.is_some()
                    || self.effect != Effect::NotSent
                    || !matches!(
                        self.state,
                        State::Finishing | State::Refused | State::Cancelled
                    ))
            || self.effect != Effect::NotSent && self.operation_id.is_none()
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
