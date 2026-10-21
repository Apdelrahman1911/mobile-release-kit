//! A preparation is not Start, an installed Prepared is not retirement, and
//! a current-visible report is not a Store/version permission. Pure shared DATA.
use crate::{
    service_protocol::{Error, Id, Settlement},
    service_store_inventory_protocol::Inventory,
    service_store_protocol as store,
};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const RAW_LIMIT: usize = 8192;
// All seven closed Prepare shapes fit below this existing strict-reader limit.
pub(crate) const RAW_NODES: usize = 128;
pub(crate) const RAW_DEPTH: usize = 8;
pub(crate) const STATUS_LIMIT: usize = store::STATUS_LIMIT;
pub(crate) const PREPARE_CONSENT: &str = "agent-store-native-prepare-once-v1";
pub(crate) type Submit = store::Submit;
pub(crate) type Query = store::Query;
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
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
    pub fn consent(self) -> &'static str {
        match self {
            Self::AndroidAccess => "agent-android-store-access-once-v1",
            Self::IosAccess => "agent-ios-store-access-once-v1",
            Self::AndroidCandidate => "agent-android-store-candidate-prepare-once-v1",
            Self::IosCandidate => "agent-ios-store-candidate-prepare-once-v1",
            Self::AndroidVersions => "agent-android-current-versions-edit-once-v1",
            Self::IosVersions => "agent-ios-current-versions-read-once-v1",
            Self::PairedVersions => "agent-paired-current-versions-edit-once-v1",
        }
    }
    pub fn action(self) -> crate::service_protocol::Action {
        if self.candidate() {
            crate::service_protocol::Action::Release
        } else {
            crate::service_protocol::Action::ObserveProject
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub kind: Kind,
    pub saved_config: store::Content,
    pub saved_version: store::Version,
    #[serde(deserialize_with = "nullable")]
    pub candidate: Option<store::Candidate>,
}
impl Selection {
    pub fn valid(&self) -> bool {
        self.saved_config.valid()
            && self.saved_version.valid()
            && match &self.candidate {
                Some(c) => {
                    self.kind.candidate() && store::uuid(&c.operation_id) && store::sha(&c.sha256)
                }
                None => !self.kind.candidate(),
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
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Report {
    Ordinary { report: store::Report },
    CurrentVersions { inventory: Inventory },
}
impl Report {
    pub(crate) fn bounded_capacity(&self) -> bool {
        match self {
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
                _ => false, // Execute/Reconcile still use only their original facade.
            },
        }
    }
    pub fn valid_for(&self, s: &Selection, r: &Review) -> bool {
        match self {
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
    let (kind, platform) = match s.kind {
        Kind::AndroidAccess => (store::Kind::AccessCheck, store::Platform::Android),
        Kind::IosAccess => (store::Kind::AccessCheck, store::Platform::Ios),
        Kind::AndroidCandidate => (store::Kind::CandidatePrepare, store::Platform::Android),
        Kind::IosCandidate => (store::Kind::CandidatePrepare, store::Platform::Ios),
        _ => return None,
    };
    Some(store::Review {
        kind,
        platform,
        operation_id: r.operation.operation_id.clone(),
        owner_generation: r.operation.owner_generation.clone(),
        status_revision: r.operation.status_revision,
        saved_config: s.saved_config.clone(),
        saved_version: s.saved_version.clone(),
        candidate: s.candidate.clone(),
        release: None,
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
