//! Closed IDs and redacted DATA for ONE existing Desktop Apple Prepared.
//! No decoder creates a native intent, source loan, provider or save authority.
use crate::service_protocol::{CredentialReference, Error, Id, Settlement};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const REQUEST_LIMIT: usize = 32;
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 8192;
pub(crate) const REPORT_LIMIT: usize = 4096;
pub(crate) const INTENT_MS: u64 = 300_000;
// Fixed named backing: 32 immutable scopes/links and retained Row snapshots,
// one relay/history projection scratch and nonce book. The explicitly named
// IPC-only reply term is in the SAME8 mixed pool, never a per-mode pool.
// The native Saved/Asset/material/journal originals keep their own census.
pub(crate) const ROW_BACKING: usize = 24 * 1024;
pub(crate) const IPC_WORKER_BACKING: usize = 3 * STATUS_LIMIT + RAW_LIMIT;
pub(crate) const DOCUMENT_BACKING: usize = REQUEST_LIMIT * ROW_BACKING + 128 * 1024;

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub(crate) fn sha(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn resource(v: &str) -> bool {
    (1..=200).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    Review,
    Register,
    Reconcile,
    ProfileReview,
    ProfileReuse,
    ProfileCreate,
    ProfileReconcile,
    KeyReview,
    KeyPrepare,
    CertificateReview,
    CertificateCreate,
    CertificateReconcile,
    P12Review,
    P12Reuse,
    P12Save,
}
impl Mode {
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::Review => "agent-apple-review-once-v1",
            Self::Register => "agent-apple-register-once-v1",
            Self::Reconcile => "agent-apple-reconcile-once-v1",
            Self::ProfileReview => "agent-apple-profile-review-once-v1",
            Self::ProfileReuse => "agent-apple-profile-reuse-once-v1",
            Self::ProfileCreate => "agent-apple-profile-create-once-v1",
            Self::ProfileReconcile => "agent-apple-profile-reconcile-once-v1",
            Self::KeyReview => "agent-apple-key-review-once-v1",
            Self::KeyPrepare => "agent-apple-key-prepare-once-v1",
            Self::CertificateReview => "agent-apple-certificate-review-once-v1",
            Self::CertificateCreate => "agent-apple-certificate-create-once-v1",
            Self::CertificateReconcile => "agent-apple-certificate-reconcile-once-v1",
            Self::P12Review => "agent-apple-p12-review-once-v1",
            Self::P12Reuse => "agent-apple-p12-reuse-once-v1",
            Self::P12Save => "agent-apple-p12-save-once-v1",
        }
    }
    pub(crate) fn action(self) -> crate::service_protocol::Action {
        use crate::service_protocol::Action;
        match self {
            Self::Register | Self::ProfileCreate | Self::CertificateCreate => Action::Release,
            Self::KeyPrepare | Self::ProfileReuse | Self::P12Save => Action::GenerateCredential,
            _ => Action::ObserveProject,
        }
    }
    pub(crate) fn record_kind(self) -> Option<RecordKind> {
        match self {
            Self::ProfileReuse | Self::ProfileCreate => Some(RecordKind::AppleProfile),
            Self::KeyPrepare => Some(RecordKind::AppleDistributionKey),
            Self::P12Save => Some(RecordKind::AppleP12),
            _ => None,
        }
    }
    pub(crate) fn reconciles(self) -> bool {
        matches!(
            self,
            Self::Reconcile | Self::ProfileReconcile | Self::CertificateReconcile
        )
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
pub(crate) struct Review {
    pub(crate) mode: Mode,
    pub(crate) operation_id: Id,
    pub(crate) owner_generation: Id,
    pub(crate) status_revision: u32,
    pub(crate) saved_config: Content,
    pub(crate) saved_version: Version,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        (1..u32::MAX).contains(&self.status_revision)
            && self.saved_config.valid()
            && self.saved_version.valid()
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
pub(crate) enum RecordKind {
    AppleProfile,
    AppleDistributionKey,
    AppleP12,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecordAtCompletion {
    pub(crate) kind: RecordKind,
    pub(crate) reference: CredentialReference,
}
impl RecordAtCompletion {
    pub(crate) fn valid_for(&self, review: &Review) -> bool {
        review.mode.record_kind() == Some(self.kind)
            && self.reference.validate().is_ok()
            && self.reference.revision_counter == 1
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Comparison {
    SameResponse,
    DifferentResponse,
    Unattributed,
    NotReturned,
    Inconclusive,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Attempt {
    pub(crate) operation_id: Id,
    pub(crate) status: String,
    pub(crate) cancellation_requested: bool,
}
impl Attempt {
    fn valid_for(&self, r: &Review) -> bool {
        self.operation_id == r.operation_id
            && matches!(
                self.status.as_str(),
                "running"
                    | "cancellation_requested"
                    | "succeeded"
                    | "failed"
                    | "cancelled"
                    | "recovery_required"
                    | "unknown"
            )
            && matches!(r.mode, Mode::Register | Mode::CertificateCreate)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Report {
    pub(crate) decision: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) comparison: Option<Comparison>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) attempt: Option<Attempt>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) certificate_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) certificate_sha256: Option<String>,
    pub(crate) do_not_replay: bool,
    pub(crate) credential_ready: bool,
}
impl Report {
    pub(crate) fn valid_for(&self, r: &Review) -> bool {
        let decision = match r.mode {
            Mode::Review => matches!(
                self.decision.as_str(),
                "reuse" | "review-required" | "blocked"
            ),
            Mode::Register => matches!(
                self.decision.as_str(),
                "reuse"
                    | "review-required"
                    | "blocked"
                    | "registration-confirmed"
                    | "registration-unconfirmed"
            ),
            Mode::Reconcile | Mode::ProfileReconcile | Mode::CertificateReconcile => {
                self.decision == "comparison-only"
            }
            Mode::ProfileReview => matches!(
                self.decision.as_str(),
                "reuse-available" | "create-available" | "blocked"
            ),
            Mode::ProfileReuse | Mode::ProfileCreate => matches!(
                self.decision.as_str(),
                "download-returned" | "creation-unconfirmed" | "blocked"
            ),
            Mode::KeyReview => matches!(
                self.decision.as_str(),
                "prepare-review"
                    | "recover-existing-key"
                    | "reuse-existing-identity"
                    | "bundle-required"
                    | "blocked"
            ),
            Mode::KeyPrepare => matches!(self.decision.as_str(), "produced" | "blocked"),
            Mode::CertificateReview => matches!(
                self.decision.as_str(),
                "reuse" | "request-review" | "blocked"
            ),
            Mode::CertificateCreate => matches!(
                self.decision.as_str(),
                "reuse" | "request-confirmed" | "request-unconfirmed" | "blocked"
            ),
            Mode::P12Review => matches!(
                self.decision.as_str(),
                "assemble-review" | "reuse-review" | "blocked"
            ),
            Mode::P12Reuse => matches!(self.decision.as_str(), "reused" | "blocked"),
            Mode::P12Save => matches!(self.decision.as_str(), "assembled" | "blocked"),
        };
        decision
            && self.do_not_replay
            && !self.credential_ready
            && self.comparison.is_some() == r.mode.reconciles()
            && self.attempt.as_ref().is_none_or(|a| a.valid_for(r))
            && self.certificate_id.as_ref().is_none_or(|id| {
                resource(id)
                    && matches!(
                        r.mode,
                        Mode::CertificateReview
                            | Mode::CertificateCreate
                            | Mode::CertificateReconcile
                            | Mode::P12Review
                            | Mode::P12Reuse
                            | Mode::P12Save
                    )
            })
            && self.certificate_sha256.as_ref().is_none_or(|h| {
                sha(h) && matches!(r.mode, Mode::P12Review | Mode::P12Reuse | Mode::P12Save)
            })
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
    #[serde(deserialize_with = "nullable")]
    pub(crate) record_at_completion: Option<RecordAtCompletion>,
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self
            .record_at_completion
            .as_ref()
            .is_some_and(|r| !r.valid_for(&self.review))
            || (self.record_at_completion.is_some()
                && (!self.state.terminal() || self.settlement != Settlement::Settled))
            || !self.review.valid()
            || self.review_id != self.review.operation_id
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
            || self
                .review
                .as_ref()
                .is_some_and(|v| !v.valid() || self.review_id.as_ref() != Some(&v.operation_id))
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
