//! Closed enrollment comparison/result DATA in the existing GitHub32 family.
//! No native owner, credential, authority, path, ledger or write permit here.
use super::{hex, nullable, original, Kind};
use serde::{Deserialize, Serialize};

pub(crate) const NATIVE_BACKING: usize = 32 * 1024;
pub(crate) const SNAPSHOT_BACKING: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReviewSelection {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
}
impl ReviewSelection {
    pub(crate) fn valid(&self) -> bool {
        original(&self.session_id, self.expected_revision)
            && (1..u32::MAX).contains(&self.expected_connection_revision)
            && self.session_id.capacity() <= 128
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConnectSelection {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) review_id: String,
}
impl ConnectSelection {
    pub(crate) fn valid(&self) -> bool {
        original(&self.session_id, self.expected_revision)
            && (1..u32::MAX).contains(&self.expected_connection_revision)
            && hex(&self.review_id, 32)
            && self.session_id.capacity() <= 128
            && self.review_id.capacity() <= 64
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Input {
    CounterEnrollmentReview(ReviewSelection),
    CounterEnrollmentConnect(ConnectSelection),
}
impl Input {
    pub(crate) fn kind(&self) -> Kind {
        match self {
            Self::CounterEnrollmentReview(_) => Kind::CounterEnrollmentReview,
            Self::CounterEnrollmentConnect(_) => Kind::CounterEnrollmentConnect,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::CounterEnrollmentReview(v) => v.valid(),
            Self::CounterEnrollmentConnect(v) => v.valid(),
        }
    }
    pub(crate) fn session(&self) -> &str {
        match self {
            Self::CounterEnrollmentReview(v) => &v.session_id,
            Self::CounterEnrollmentConnect(v) => &v.session_id,
        }
    }
    pub(crate) fn revision(&self) -> u32 {
        match self {
            Self::CounterEnrollmentReview(v) => v.expected_revision,
            Self::CounterEnrollmentConnect(v) => v.expected_revision,
        }
    }
    pub(crate) fn connection_revision(&self) -> u32 {
        match self {
            Self::CounterEnrollmentReview(v) => v.expected_connection_revision,
            Self::CounterEnrollmentConnect(v) => v.expected_connection_revision,
        }
    }
    pub(crate) fn review_id(&self) -> Option<&str> {
        match self {
            Self::CounterEnrollmentReview(_) => None,
            Self::CounterEnrollmentConnect(v) => Some(&v.review_id),
        }
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        match self {
            Self::CounterEnrollmentReview(v) => Some(v.session_id.capacity()),
            Self::CounterEnrollmentConnect(v) => {
                v.session_id.capacity().checked_add(v.review_id.capacity())
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReviewReference {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) request_sha256: String,
}
impl ReviewReference {
    pub(crate) fn valid(&self) -> bool {
        original(&self.session_id, self.expected_revision)
            && (1..u32::MAX).contains(&self.expected_connection_revision)
            && hex(&self.request_sha256, 64)
    }
    pub(crate) fn retained_fits(&self) -> bool {
        self.session_id.capacity() <= 128 && self.request_sha256.capacity() <= 128
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConnectReference {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) review_id: String,
    pub(crate) review_sha256: String,
}
impl ConnectReference {
    pub(crate) fn valid(&self) -> bool {
        original(&self.session_id, self.expected_revision)
            && (1..u32::MAX).contains(&self.expected_connection_revision)
            && hex(&self.review_id, 32)
            && hex(&self.review_sha256, 64)
    }
    pub(crate) fn retained_fits(&self) -> bool {
        self.session_id.capacity() <= 128
            && self.review_id.capacity() <= 64
            && self.review_sha256.capacity() <= 128
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation {
    Review,
    Connect,
}
impl Operation {
    pub(crate) fn kind(self) -> Kind {
        match self {
            Self::Review => Kind::CounterEnrollmentReview,
            Self::Connect => Kind::CounterEnrollmentConnect,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Reviewed,
    Connected,
    Refused,
}
// The existing native closed reason roster, not provider messages. Kept pure
// so the installed CLI never imports the native enrollment/BridgeError graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OutcomeReason {
    None,
    CounterMissing,
    ProtectionUnavailable,
    ProtectionUnsupported,
    AuthorityChanged,
    AuthorityRewound,
    LedgerInvalid,
    ReviewChanged,
    InvalidInput,
    Unauthorized,
    Forbidden,
    NotFoundOrInaccessible,
    TargetChanged,
    RateLimited,
    NetworkUnavailable,
    TlsFailed,
    ResponseInvalid,
    ResponseLimit,
    Expired,
    Cancelled,
    Busy,
    NotConnected,
    RuntimeUnavailable,
    CleanupUnknown,
    StateUnavailable,
    StateTooLarge,
    Connected,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Version {
    pub(crate) name: String,
    pub(crate) build: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewView {
    pub(crate) id: String,
    pub(crate) repository: String,
    pub(crate) version: Version,
    pub(crate) reservations: u32,
}
impl ReviewView {
    pub(crate) fn valid(&self) -> bool {
        let part = |s: &str, max: usize, punctuation: &[u8]| {
            !s.is_empty()
                && s.len() <= max
                && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || punctuation.contains(&c))
        };
        hex(&self.id, 32)
            && self
                .repository
                .split_once('/')
                .is_some_and(|(a, b)| part(a, 39, b"-") && part(b, 100, b"._-"))
            && !self.version.name.is_empty()
            && self.version.name.len() <= 64
            && self
                .version
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".+-".contains(&c))
            && (1..=2_100_000_000).contains(&self.version.build)
            && self.reservations <= 64
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.id
            .capacity()
            .checked_add(self.repository.capacity())?
            .checked_add(self.version.name.capacity())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub(crate) operation: Operation,
    pub(crate) phase: Phase,
    pub(crate) reason: OutcomeReason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) review: Option<ReviewView>,
}
impl Snapshot {
    pub(crate) fn heap(&self) -> Option<usize> {
        self.review.as_ref().map_or(Some(0), ReviewView::heap)
    }
    pub(crate) fn valid_for(&self, kind: Kind) -> bool {
        if self.operation.kind() != kind
            || self
                .heap()
                .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
                .is_none_or(|n| n > SNAPSHOT_BACKING)
        {
            return false;
        }
        match self.phase {
            Phase::Reviewed => {
                self.operation == Operation::Review
                    && self.reason == OutcomeReason::None
                    && self.review.as_ref().is_some_and(ReviewView::valid)
            }
            Phase::Connected => {
                self.operation == Operation::Connect
                    && self.reason == OutcomeReason::Connected
                    && self.review.is_none()
            }
            Phase::Refused => {
                !matches!(
                    self.reason,
                    OutcomeReason::None | OutcomeReason::Connected | OutcomeReason::CleanupUnknown
                ) && self.review.is_none()
            }
        }
    }
    pub(crate) fn valid_row(
        &self,
        kind: Kind,
        state: super::State,
        operation: Option<&str>,
        effect: super::Effect,
    ) -> bool {
        if !self.valid_for(kind) || operation.is_none_or(|id| !hex(id, 32)) {
            return false;
        }
        match self.phase {
            Phase::Reviewed => {
                state == super::State::Complete
                    && effect == super::Effect::None
                    && self
                        .review
                        .as_ref()
                        .is_some_and(|r| Some(r.id.as_str()) == operation)
            }
            Phase::Connected => {
                state == super::State::Complete && effect == super::Effect::LocalMappingObserved
            }
            Phase::Refused => {
                matches!(state, super::State::Refused | super::State::Cancelled)
                    && effect != super::Effect::LocalMappingObserved
            }
        }
    }
}
