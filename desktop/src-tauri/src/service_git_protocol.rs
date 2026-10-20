//! Closed Stage/Unstage DATA. No Git executable, source reader, review owner,
//! publisher, document, filesystem capability or native receipt is decoded.
use crate::service_protocol::{Error, Id, OperationState, Settlement};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io, time::Duration};

pub const CONSENT: &str = "agent-local-git-index-once-v1";
pub const START_WINDOW: Duration = Duration::from_secs(900);
pub const REQUEST_LIMIT: usize = 32;
pub const PATH_LIMIT: usize = 64;
pub const SCOPE_BYTES: usize = 128 * 1024;
pub const STATUS_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Stage,
    Unstage,
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn native_id(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
// Same closed relative-path vocabulary as the original Git protocol. Native
// entry independently calls its own validator; this is only client DATA.
pub(crate) fn relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains('\\')
        && !value.chars().any(|c| c < ' ' || c == '\u{7f}')
        && value.split('/').count() <= 32
        && value
            .split('/')
            .all(|p| !p.is_empty() && p.len() <= 255 && !matches!(p, "." | ".." | ".git"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Summary {
    pub action: Action,
    pub repository_revision: String,
    pub path_count: u32,
    pub selection_sha256: String,
}
impl Summary {
    pub fn validate(&self) -> Result<(), Error> {
        if digest(&self.repository_revision)
            && digest(&self.selection_sha256)
            && (1..=PATH_LIMIT as u32).contains(&self.path_count)
        {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub summary: Summary,
    pub paths: Vec<String>,
}
fn selection_hash(action: Action, revision: &str, paths: &[String]) -> Result<String, Error> {
    if !digest(revision)
        || paths.is_empty()
        || paths.len() > PATH_LIMIT
        || paths.iter().any(|p| !relative(p))
        || paths.windows(2).any(|p| p[0] >= p[1])
    {
        return Err(Error::InvalidRequest);
    }
    let mut hash = Sha256::new();
    hash.update(b"mrk-agent-git-index-selection/1\0");
    hash.update(match action {
        Action::Stage => b"stage".as_slice(),
        Action::Unstage => b"unstage".as_slice(),
    });
    hash.update(revision.as_bytes());
    for path in paths {
        hash.update((path.len() as u32).to_be_bytes());
        hash.update(path.as_bytes());
    }
    Ok(crate::service_protocol::hex(&hash.finalize()))
}
impl Selection {
    pub(crate) fn new(action: Action, revision: String, paths: Vec<String>) -> Result<Self, Error> {
        let selection_sha256 = selection_hash(action, &revision, &paths)?;
        let summary = Summary {
            action,
            repository_revision: revision.into_boxed_str().into_string(),
            path_count: paths.len() as u32,
            selection_sha256,
        };
        let value = Self {
            summary,
            paths: paths
                .into_iter()
                .map(|p| p.into_boxed_str().into_string())
                .collect::<Vec<_>>()
                .into_boxed_slice()
                .into_vec(),
        };
        // Includes headroom for Scope and the service envelope; quote escaping
        // is counted by serde BEFORE allocating an encoded reply.
        encoded_bound(&value, SCOPE_BYTES - 2048)?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.summary.validate()?;
        if self.summary.path_count as usize != self.paths.len()
            || selection_hash(
                self.summary.action,
                &self.summary.repository_revision,
                &self.paths,
            )? != self.summary.selection_sha256
        {
            return Err(Error::InvalidRequest);
        }
        encoded_bound(self, SCOPE_BYTES - 2048)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub project_id: Id,
    pub service_instance: Id,
    pub request_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub origin: Query,
    pub grant_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Start {
    pub origin: Query,
    pub prepare_operation_id: String,
    pub review_id: String,
}
impl Start {
    pub fn validate(&self) -> Result<(), Error> {
        if native_id(&self.prepare_operation_id) && native_id(&self.review_id) {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    pub enabled: bool,
    pub remaining_ms: u64,
    pub consumed: bool,
    pub project_id: Option<Id>,
    pub grant_id: Option<Id>,
    pub selection: Option<Selection>,
}
impl Access {
    pub(crate) fn empty() -> Self {
        Self {
            enabled: false,
            remaining_ms: 0,
            consumed: false,
            project_id: None,
            grant_id: None,
            selection: None,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.remaining_ms > 900_000
            || self.enabled && (self.consumed || self.remaining_ms == 0)
            || !self.enabled && self.remaining_ms != 0
            || self.project_id.is_some() != self.grant_id.is_some()
            || self.grant_id.is_some() != self.selection.is_some()
            || (self.enabled || self.consumed) && self.grant_id.is_none()
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(v) = &self.selection {
            v.validate()?;
        }
        encoded_bound(self, SCOPE_BYTES - 1024)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub service_instance: Id,
    pub project_id: Id,
    pub access: Access,
}
impl Scope {
    pub fn validate(&self) -> Result<(), Error> {
        self.access.validate()?;
        if self
            .access
            .project_id
            .as_ref()
            .is_some_and(|id| id != &self.project_id)
        {
            return Err(Error::InvalidRequest);
        }
        encoded_bound(self, SCOPE_BYTES - 512)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Queued,
    Preparing,
    Prepared,
    StartQueued,
    Applying,
    Stopping,
    Refused,
    Cancelled,
    Expired,
    Finished,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    UserCancelled,
    PermissionRevoked,
    Expired,
    ContextChanged,
    DocumentLost,
    Shutdown,
    Busy,
    Unavailable,
    NativeRefused,
    RecoveryRequired,
    CleanupUnknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub review_id: String,
    pub expected_index: String,
    pub review_digest: String,
    pub document_revision: u32,
    pub registration_generation: u32,
}
impl Review {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if native_id(&self.review_id)
            && digest(&self.expected_index)
            && digest(&self.review_digest)
            && (1..u32::MAX).contains(&self.document_revision)
            && (1..u32::MAX).contains(&self.registration_generation)
        {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub origin: Query,
    pub grant_id: Id,
    pub selection: Summary,
    pub revision: u32,
    pub state: State,
    pub prepare_operation_id: Option<String>,
    pub apply_operation_id: Option<String>,
    pub review: Option<Review>,
    pub outcome: Option<OperationState>,
    pub settlement: Settlement,
    pub reason: Option<Reason>,
    pub history_available: bool,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        use State as S;
        self.selection.validate()?;
        if self.revision == 0
            || !self.do_not_replay
            || self
                .prepare_operation_id
                .as_deref()
                .is_some_and(|v| !native_id(v))
            || self
                .apply_operation_id
                .as_deref()
                .is_some_and(|v| !native_id(v))
            || self.apply_operation_id.is_some() && self.prepare_operation_id.is_none()
            || self.apply_operation_id.is_some()
                && self.apply_operation_id == self.prepare_operation_id
            || self.history_available && self.prepare_operation_id.is_none()
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(review) = &self.review {
            review.validate()?;
            if self.prepare_operation_id.is_none()
                || !matches!(self.state, S::Prepared | S::StartQueued)
            {
                return Err(Error::InvalidRequest);
            }
        }
        let valid = match self.state {
            S::Queued => {
                self.settlement == Settlement::Pending
                    && self.outcome.is_none()
                    && self.prepare_operation_id.is_none()
                    && self.apply_operation_id.is_none()
            }
            S::Preparing => {
                self.settlement == Settlement::Pending
                    && self.outcome.is_none()
                    && self.apply_operation_id.is_none()
            }
            S::StartQueued => {
                self.settlement == Settlement::Pending
                    && self.outcome.is_none()
                    && self.review.is_some()
                    && self.prepare_operation_id.is_some()
                    && self.apply_operation_id.is_none()
            }
            S::Applying => {
                self.settlement == Settlement::Pending
                    && self.outcome.is_none()
                    && self.prepare_operation_id.is_some()
            }
            S::Stopping => self.settlement == Settlement::Pending && self.outcome.is_none(),
            S::Prepared => {
                self.settlement == Settlement::Pending
                    && self.outcome.is_none()
                    && self.review.is_some()
                    && self.prepare_operation_id.is_some()
                    && self.apply_operation_id.is_none()
            }
            S::Refused | S::Cancelled | S::Expired => {
                self.settlement == Settlement::Settled
                    && self.review.is_none()
                    && matches!(
                        self.outcome,
                        Some(OperationState::Failed | OperationState::Cancelled)
                    )
            }
            S::Finished => {
                self.settlement == Settlement::Settled
                    && self.review.is_none()
                    && self.prepare_operation_id.is_some()
                    && matches!(
                        self.outcome,
                        Some(
                            OperationState::Succeeded
                                | OperationState::Failed
                                | OperationState::Cancelled
                                | OperationState::RecoveryRequired
                        )
                    )
            }
            S::Unknown => {
                self.settlement == Settlement::Unknown
                    && self.review.is_none()
                    && self.outcome == Some(OperationState::Unknown)
            }
        };
        if !valid {
            return Err(Error::InvalidRequest);
        }
        encoded_bound(self, STATUS_BYTES - 512)
    }
}

// Fixed reply counting only, not a new JSON traversal/parser. Serde performs
// escaping into a counter; encoded output is allocated only after this passes.
fn encoded_bound(value: &impl Serialize, limit: usize) -> Result<(), Error> {
    struct Count {
        count: usize,
        limit: usize,
    }
    impl io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.count = self
                .count
                .checked_add(bytes.len())
                .filter(|v| *v <= self.limit)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bounded Git DATA"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Count { count: 0, limit }, value).map_err(|_| Error::InvalidRequest)
}
pub(crate) fn response_bound(
    response: &crate::service_protocol::Response,
    scope: bool,
) -> Result<(), Error> {
    encoded_bound(response, if scope { SCOPE_BYTES } else { STATUS_BYTES })
}

#[cfg(test)]
#[path = "service_git_protocol_tests.rs"]
mod tests;
