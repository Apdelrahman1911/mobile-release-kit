//! Fixed tool actions delegated by the real Desktop owners. Pure wire DATA:
//! this module is also compiled by the transport-only installed CLI.
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Deserializer, Serialize};
pub(crate) const REQUEST_LIMIT: usize = 32;
pub(crate) const CONSENT_LIMIT: usize = 32;
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 8192;
pub(crate) const REPORT_LIMIT: usize = 4096;
pub(crate) const INTENT_MS: u64 = 300_000;
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    Doctor,
    InspectRequirements,
    InspectSavedRequirements,
    AcquireMissing,
    AcquireReviewedMissing,
    InspectPickedSources,
    RegisterReviewedSources,
}
impl Kind {
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::Doctor => "agent-tool-doctor-once-v1",
            Self::InspectRequirements => "agent-tool-requirements-once-v1",
            Self::InspectSavedRequirements => "agent-tool-inspect-saved-once-v1",
            Self::AcquireMissing => "agent-tool-acquire-missing-once-v1",
            Self::AcquireReviewedMissing => "agent-tool-acquire-reviewed-missing-once-v1",
            Self::InspectPickedSources => "agent-tool-inspect-picked-once-v1",
            Self::RegisterReviewedSources => "agent-tool-register-reviewed-once-v1",
        }
    }
    pub(crate) fn action(self) -> crate::service_protocol::Action {
        match self {
            Self::AcquireMissing | Self::AcquireReviewedMissing | Self::RegisterReviewedSources => {
                crate::service_protocol::Action::PrepareTools
            }
            _ => crate::service_protocol::Action::ObserveProject,
        }
    }
    pub(crate) fn saved(self) -> bool {
        matches!(self, Self::InspectRequirements | Self::InspectSavedRequirements | Self::AcquireMissing | Self::AcquireReviewedMissing)
    }
    pub(crate) fn sources(self) -> bool {
        matches!(
            self,
            Self::InspectPickedSources | Self::RegisterReviewedSources
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform {
    Android,
    Ios,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) operation_id: Id,
    pub(crate) owner_generation: Id,
    pub(crate) status_revision: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Sources {
    pub(crate) registration_generation: u32,
    pub(crate) source_generation: u32,
    #[serde(deserialize_with = "present")]
    pub(crate) review_id: Option<Id>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) kind: Kind,
    pub(crate) platform: Platform,
    pub(crate) draft_revision: u32,
    pub(crate) baseline_generation: u32,
    #[serde(deserialize_with = "present")]
    pub(crate) prepared: Option<Prepared>,
    #[serde(deserialize_with = "present")]
    pub(crate) sources: Option<Sources>,
    // Omitted on every old kind; explicit null is not an acquisition selection.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "some_acquisition")]
    pub(crate) acquisition: Option<Acquisition>,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        self.draft_revision < u32::MAX
            && self.baseline_generation < u32::MAX
            && (self.kind == Kind::Doctor || self.platform == Platform::Android)
            && match (&self.acquisition, self.kind) {
                (Some(a), Kind::AcquireReviewedMissing) => a.valid(),
                (None, Kind::AcquireReviewedMissing) | (Some(_), _) => false,
                (None, _) => true,
            }
            && match (self.kind, &self.prepared, &self.sources) {
                (Kind::Doctor | Kind::InspectSavedRequirements | Kind::AcquireReviewedMissing, None, None) => true,
                (Kind::InspectRequirements | Kind::AcquireMissing, Some(p), None) => {
                    (1..u32::MAX).contains(&p.status_revision)
                }
                (Kind::InspectPickedSources, None, Some(s)) => {
                    s.registration_generation < u32::MAX
                        && s.source_generation < u32::MAX
                        && s.review_id.is_none()
                }
                (Kind::RegisterReviewedSources, None, Some(s)) => {
                    s.registration_generation < u32::MAX
                        && s.source_generation < u32::MAX
                        && s.review_id.is_some()
                }
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
    DeveloperSelection,
    Git,
    Java,
    Javac,
    Xcode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckStatus {
    Ok,
    Failed,
    Unavailable,
    Skipped,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Finding {
    pub(crate) check: Check,
    pub(crate) status: CheckStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Component {
    Jdk,
    Gradle,
    AndroidPlatform,
    AndroidBuildTools,
}
// Closed comparison DATA only. The native original Inspection remains authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Acquisition {
    pub(crate) operation_id: Id,
    pub(crate) owner_generation: Id,
    pub(crate) requirements_sha256: String,
    #[serde(deserialize_with = "acquisition_components")]
    pub(crate) missing: Vec<Component>,
    #[serde(deserialize_with = "acquisition_components")]
    pub(crate) compatible: Vec<Component>,
}
pub(crate) const ACQUISITION_HEAP_BYTES: usize = 128 + 8 * std::mem::size_of::<Component>();
fn acquisition_components<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Component>, D::Error> {
    struct Four;
    impl<'de> serde::de::Visitor<'de> for Four {
        type Value = Vec<Component>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most four tool components")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            // Streaming JSON has no exact size hint. Do not let the first
            // push grow this tiny enum's Vec beyond the admitted four slots.
            let mut values = Vec::with_capacity(4);
            while let Some(value) = seq.next_element::<Component>()? {
                if values.len() == 4 {
                    return Err(serde::de::Error::custom("too many tool components"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Four)
}
fn some_acquisition<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Acquisition>, D::Error> {
    Acquisition::deserialize(d).map(Some)
}
impl Acquisition {
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.operation_id.retained_bytes().checked_add(self.owner_generation.retained_bytes())?
            .checked_add(self.requirements_sha256.capacity())?
            .checked_add(self.missing.capacity().checked_mul(std::mem::size_of::<Component>())?)?
            .checked_add(self.compatible.capacity().checked_mul(std::mem::size_of::<Component>())?)
    }
    pub(crate) fn valid(&self) -> bool {
        const ALL: [Component; 4] = [Component::Jdk, Component::AndroidPlatform, Component::AndroidBuildTools, Component::Gradle];
        self.requirements_sha256.len() == 64
            && self.requirements_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.missing.capacity() <= 4 && self.compatible.capacity() <= 4
            && self.retained_bytes().is_some_and(|n| n <= ACQUISITION_HEAP_BYTES)
            && !self.missing.is_empty() && self.missing.len() + self.compatible.len() == 4
            && self.missing.iter().copied().eq(ALL.into_iter().filter(|v| self.missing.contains(v)))
            && self.compatible.iter().copied().eq(ALL.into_iter().filter(|v| self.compatible.contains(v)))
            && ALL.into_iter().all(|v| self.missing.contains(&v) != self.compatible.contains(&v))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CopyState {
    NotCreated,
    Published,
    RetainedPartial,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Role {
    Jdk,
    Sdk,
    Gradle,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Source {
    pub(crate) role: Role,
    pub(crate) logical_bytes: u32,
    pub(crate) files: u32,
    pub(crate) entries: u32,
    pub(crate) aliases: u32,
    pub(crate) complete: bool,
    pub(crate) compatible: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Report {
    // Summary only; successful execution need not mean every check passed.
    Doctor {
        checks: Vec<Finding>,
    },
    InspectRequirements {
        missing: Vec<Component>,
    },
    InspectSavedRequirements {
        missing: Vec<Component>,
    },
    AcquireMissing {
        staged: Vec<Component>,
    },
    AcquireReviewedMissing {
        staged: Vec<Component>,
    },
    InspectPickedSources {
        sources: Vec<Source>,
    },
    RegisterReviewedSources {
        copy: CopyState,
        sources: Vec<Source>,
    },
}
impl Report {
    pub(crate) fn valid_for(&self, r: &Review) -> bool {
        fn unique<T: PartialEq>(v: &[T], max: usize) -> bool {
            v.len() <= max && v.iter().enumerate().all(|(i, x)| !v[..i].contains(x))
        }
        fn sources(v: &[Source]) -> bool {
            v.len() <= 3
                && v.iter().enumerate().all(|(i, s)| {
                    !v[..i].iter().any(|x| x.role == s.role)
                        && s.logical_bytes <= 1024 * 1024 * 1024
                        && s.files <= 16384
                        && s.entries <= 32768
                        && s.aliases <= 128
                })
        }
        r.valid()
            && match (r.kind, self) {
                (Kind::Doctor, Self::Doctor { checks }) => {
                    checks.len() <= 5
                        && checks
                            .iter()
                            .enumerate()
                            .all(|(i, c)| !checks[..i].iter().any(|x| x.check == c.check))
                }
                (Kind::InspectRequirements, Self::InspectRequirements { missing })
                | (Kind::InspectSavedRequirements, Self::InspectSavedRequirements { missing }) => {
                    unique(missing, 4)
                }
                (Kind::AcquireMissing, Self::AcquireMissing { staged }) => {
                    !staged.is_empty() && unique(staged, 4)
                }
                (Kind::AcquireReviewedMissing, Self::AcquireReviewedMissing { staged }) => {
                    r.acquisition.as_ref().is_some_and(|a| staged == &a.missing)
                }
                (Kind::InspectPickedSources, Self::InspectPickedSources { sources: s }) => {
                    s.len() == 3 && sources(s)
                }
                (
                    Kind::RegisterReviewedSources,
                    Self::RegisterReviewedSources { sources: s, .. },
                ) => sources(s),
                _ => false,
            }
            && serde_json::to_vec(self).is_ok_and(|v| v.len() <= REPORT_LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Operation {
    pub(crate) operation_id: Id,
    #[serde(deserialize_with = "present")]
    pub(crate) owner_generation: Option<Id>,
    #[serde(deserialize_with = "present")]
    pub(crate) registration_generation: Option<u32>,
}
impl Operation {
    pub(crate) fn valid_for(&self, r: &Review) -> bool {
        if r.kind.sources() {
            self.owner_generation.is_none()
                && self.registration_generation.is_some_and(|g| {
                    g < u32::MAX
                        && r.sources
                            .as_ref()
                            .is_some_and(|s| s.registration_generation.checked_add(1) == Some(g))
                })
        } else {
            self.owner_generation.is_some()
                && self.registration_generation.is_none()
                && r.acquisition.as_ref().is_none_or(|a| self.operation_id != a.operation_id
                    && self.owner_generation.as_ref() != Some(&a.owner_generation))
                && r.prepared.as_ref().is_none_or(|p| {
                    p.operation_id == self.operation_id
                        && Some(&p.owner_generation) == self.owner_generation.as_ref()
                })
        }
    }
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
    #[serde(deserialize_with = "present")]
    pub(crate) operation: Option<Operation>,
    #[serde(deserialize_with = "present")]
    pub(crate) outcome: Option<Outcome>,
    #[serde(deserialize_with = "present")]
    pub(crate) result: Option<Report>,
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let ok = self.review.valid()
            && (1..u32::MAX).contains(&self.revision)
            && self
                .operation
                .as_ref()
                .is_none_or(|o| o.valid_for(&self.review))
            && self
                .result
                .as_ref()
                .is_none_or(|r| r.valid_for(&self.review))
            && if self.state == State::Unknown {
                self.settlement == Settlement::Unknown
                    && self.outcome == Some(Outcome::Unknown)
                    && self.result.is_none()
                    && matches!(
                        self.reason,
                        Reason::CleanupUnknown | Reason::HistoryUnavailable
                    )
            } else if self.state.terminal() {
                self.settlement == Settlement::Settled
                    && match (self.state, self.outcome) {
                        (State::Complete, Some(Outcome::Complete)) => {
                            self.operation.is_some()
                                && self.reason == Reason::None
                                && self.result.is_some()
                        }
                        (State::Refused | State::Expired, Some(Outcome::Refused))
                        | (State::Cancelled, Some(Outcome::Cancelled | Outcome::Refused))
                        | (State::Failed, Some(Outcome::Failed | Outcome::TimedOut)) => {
                            self.result.is_none()
                                && !matches!(
                                    self.reason,
                                    Reason::None
                                        | Reason::CleanupUnknown
                                        | Reason::HistoryUnavailable
                                )
                        }
                        _ => false,
                    }
            } else {
                self.settlement == Settlement::Pending
                    && self.outcome.is_none()
                    && self.result.is_none()
                    && !matches!(
                        self.reason,
                        Reason::CleanupUnknown | Reason::HistoryUnavailable
                    )
            };
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Access {
    #[serde(deserialize_with = "present")]
    pub(crate) service_instance: Option<Id>,
    #[serde(deserialize_with = "present")]
    pub(crate) project_id: Option<Id>,
    #[serde(deserialize_with = "present")]
    pub(crate) grant_id: Option<Id>,
    #[serde(deserialize_with = "present")]
    pub(crate) review_id: Option<Id>,
    #[serde(deserialize_with = "present")]
    pub(crate) review: Option<Review>,
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    pub(crate) consumed: bool,
    pub(crate) pending: bool,
    pub(crate) unknown: bool,
    #[serde(deserialize_with = "present")]
    pub(crate) request_id: Option<Id>,
    #[serde(deserialize_with = "present")]
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
            || self.review.as_ref().is_some_and(|r| !r.valid())
            || self.remaining_ms > INTENT_MS
            || self.enabled
                != (present
                    && !self.consumed
                    && !self.pending
                    && !self.unknown
                    && self.remaining_ms > 0)
            || !self.enabled && self.remaining_ms != 0
            || self.consumed != self.request_id.is_some()
            || self.consumed != self.status.is_some()
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

#[cfg(test)]
#[path = "service_tool_setup_protocol_tests.rs"]
mod tests;
