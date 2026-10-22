//! Closed comparison DATA for the original Local History Prepared. READ can
//! request this comparison, never enroll, inspect a journal, or authorize Start.
//! This file is also compiled by the transport-only installed CLI.
use crate::{
    service_local_history_protocol as history,
    service_protocol::{Error, Settlement},
};
pub(crate) use history::{Kind, Platform, Query, Reason, Review};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const REQUEST_BYTES: usize = history::RAW_LIMIT;
pub(crate) const STATUS_BYTES: usize = history::STATUS_LIMIT;
pub(crate) const COMPARISON_BYTES: usize = 2048;
pub(crate) const REVIEWED_FILES_BYTES: usize = 2048;

fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub(crate) kind: Kind,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) platform: Option<Platform>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) candidate_operation_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) stage_operation_id: Option<String>,
}
impl Selection {
    pub(crate) fn valid(&self) -> bool {
        history::selection_valid(
            self.kind,
            self.platform,
            self.candidate_operation_id.as_deref(),
            self.stage_operation_id.as_deref(),
        )
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.candidate_operation_id
            .as_ref()
            .map_or(0, String::capacity)
            .checked_add(self.stage_operation_id.as_ref().map_or(0, String::capacity))
    }
    pub(crate) fn bounded(&self) -> bool {
        self.valid() && self.heap().is_some_and(|n| n <= 36)
    }
    pub(crate) fn matches(&self, r: &Review) -> bool {
        r.valid()
            && self.kind == r.kind
            && self.platform == r.platform
            && self.candidate_operation_id == r.candidate_operation_id
            && self.stage_operation_id == r.stage_operation_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) origin: Query,
    pub(crate) selection: Selection,
}
impl Request {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.selection.bounded() {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Queued,
    Preparing,
    Prepared,
    HandedOff,
    Refused,
    Cancelled,
    Expired,
    Unknown,
}

/// Settlement here describes the DATA preparation caller and its history
/// writer. Prepared is intentionally not retirement of the native intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) origin: Query,
    pub(crate) selection: Selection,
    pub(crate) revision: u32,
    pub(crate) phase: Phase,
    pub(crate) settlement: Settlement,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) review: Option<Review>,
    pub(crate) remaining_ms: u64,
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !self.selection.valid()
            || !(1..u32::MAX).contains(&self.revision)
            || self.remaining_ms > history::INTENT_MS
            || self
                .review
                .as_ref()
                .is_some_and(|r| !self.selection.matches(r))
        {
            return Err(Error::InvalidRequest);
        }
        let valid = match self.phase {
            Phase::Queued => {
                self.settlement == Settlement::Pending
                    && self.review.is_none()
                    && self.remaining_ms == 0
                    && self.reason == Reason::None
            }
            Phase::Preparing => {
                self.settlement == Settlement::Pending
                    && self.remaining_ms == 0
                    && !matches!(
                        self.reason,
                        Reason::CleanupUnknown | Reason::HistoryUnavailable
                    )
            }
            Phase::Prepared => {
                self.settlement == Settlement::Settled
                    && self.review.is_some()
                    && self.reason == Reason::None
                    && self.remaining_ms > 0
            }
            Phase::HandedOff => {
                self.settlement == Settlement::Settled
                    && self.review.is_some()
                    && self.reason == Reason::None
                    && self.remaining_ms == 0
            }
            Phase::Unknown => {
                self.settlement == Settlement::Unknown
                    && self.remaining_ms == 0
                    && matches!(
                        self.reason,
                        Reason::CleanupUnknown | Reason::HistoryUnavailable
                    )
            }
            Phase::Refused | Phase::Cancelled | Phase::Expired => {
                self.settlement == Settlement::Settled
                    && self.remaining_ms == 0
                    && !matches!(
                        self.reason,
                        Reason::None | Reason::CleanupUnknown | Reason::HistoryUnavailable
                    )
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}

/// Only the MAIN native adapter can pair this retained request with a fresh
/// comparison of its SAME still-installed Prepared. `live` is not a grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Comparison {
    // Registered Desktop ID, not the unrelated stable service origin ID.
    pub(crate) runtime_project_id: String,
    pub(crate) request: Status,
    #[serde(deserialize_with = "nullable")]
    pub(crate) live: Option<Review>,
}
impl Comparison {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.request.validate()?;
        if self.runtime_project_id.is_empty()
            || self.runtime_project_id.len() > 64
            || !self
                .runtime_project_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        {
            return Err(Error::InvalidRequest);
        }
        if self.live.as_ref().is_some_and(|live| {
            self.request.phase != Phase::Prepared
                || !self.request.selection.matches(live)
                || self.request.review.as_ref().is_none_or(|old| {
                    old.operation_id != live.operation_id
                        || old.owner_generation != live.owner_generation
                        || old.status_revision > live.status_revision
                })
        }) {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainAccess {
    #[serde(flatten)]
    pub(crate) access: history::Access,
    pub(crate) permission_revision: String,
    pub(crate) preparation: Option<Comparison>,
}
impl MainAccess {
    pub(crate) fn new(
        access: history::Access,
        revision: u64,
        preparation: Option<Comparison>,
    ) -> Self {
        Self {
            access,
            permission_revision: revision.to_string(),
            preparation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FilesKind {
    Prepared,
    Execution,
    Reconciliation,
    ExternalReadiness,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage {
    ExternalTesting,
    ProductionSubmit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FilesObservation {
    #[serde(rename = "current-prepared-files-only")]
    Prepared,
    #[serde(rename = "current-execution-files-only")]
    Execution,
    #[serde(rename = "current-recovery-files-only")]
    Reconciliation,
    #[serde(rename = "current-external-readiness-files-only")]
    ExternalReadiness,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PriorFinality {
    #[serde(rename = "not-established")]
    NotEstablished,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Destination {
    pub(crate) channel: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) release_status: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) automatic_release: Option<bool>,
}

/// A bounded summary of ALREADY validated current files, never a Store
/// authorization/receipt importer. No native module is linked into mrk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReviewedFiles {
    pub(crate) kind: FilesKind,
    pub(crate) operation_id: String,
    pub(crate) candidate_sha256: String,
    pub(crate) intent_sha256: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) receipt_sha256: Option<String>,
    pub(crate) source_commit: String,
    pub(crate) source_tree: String,
    pub(crate) application: String,
    pub(crate) version: history::Version,
    pub(crate) destination: Destination,
    #[serde(deserialize_with = "nullable")]
    pub(crate) stage: Option<Stage>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) candidate_operation_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) predecessor_operation_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) predecessor_receipt_sha256: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) execution_receipt_sha256: Option<String>,
    pub(crate) observation: FilesObservation,
    pub(crate) prior_finality: PriorFinality,
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
impl ReviewedFiles {
    pub(crate) fn valid_for(&self, r: &Review) -> bool {
        use history::Kind::*;
        let expected = match r.kind {
            ReviewPrepared | ReviewReconcile | ReviewStagePrepared => {
                (FilesKind::Prepared, FilesObservation::Prepared)
            }
            ReviewExecution | ReviewStageExecution => {
                (FilesKind::Execution, FilesObservation::Execution)
            }
            ReviewRecovery => (FilesKind::Reconciliation, FilesObservation::Reconciliation),
            ReviewExternalReadiness => (
                FilesKind::ExternalReadiness,
                FilesObservation::ExternalReadiness,
            ),
            _ => return false,
        };
        let ios = r.platform == Some(Platform::Ios);
        let stage = matches!(
            r.kind,
            ReviewStagePrepared | ReviewStageExecution | ReviewExternalReadiness
        );
        if !r.valid()
            || (self.kind, self.observation) != expected
            || Some(self.operation_id.as_str()) != r.selected_id()
            || !history::uuid(&self.operation_id)
            || !hex(&self.candidate_sha256, 64)
            || !hex(&self.intent_sha256, 64)
            || !hex(&self.source_commit, 40)
            || !hex(&self.source_tree, 40)
            || self.receipt_sha256.is_some() != (self.kind != FilesKind::Prepared)
            || self.receipt_sha256.as_deref().is_some_and(|s| !hex(s, 64))
            || self.application.len() > 255
            || self.application.split('.').count() < 2
            || !self.application.split('.').all(|v| {
                v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                    && v.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == if ios { b'-' } else { b'_' })
            })
            || !(1..=64).contains(&self.version.name.len())
            || !self
                .version
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".+-".contains(&c))
            || !(1..=2_100_000_000).contains(&self.version.build)
            || !self.destination_valid(ios)
            || self.stage.is_some() != stage
            || self.candidate_operation_id.is_some() != stage
            || self
                .candidate_operation_id
                .as_deref()
                .is_some_and(|s| !history::uuid(s) || s == self.operation_id)
        {
            return false;
        }
        if self.kind == FilesKind::ExternalReadiness {
            self.stage == Some(Stage::ExternalTesting)
                && ios
                && self.destination.channel == "testflight-external"
                && self.predecessor_operation_id.is_none()
                && self.predecessor_receipt_sha256.is_none()
                && self
                    .execution_receipt_sha256
                    .as_deref()
                    .is_some_and(|s| hex(s, 64))
        } else if stage {
            self.execution_receipt_sha256.is_none()
                && self
                    .predecessor_receipt_sha256
                    .as_deref()
                    .is_some_and(|s| hex(s, 64))
                && self
                    .predecessor_operation_id
                    .as_deref()
                    .is_some_and(|s| history::uuid(s) && s != self.operation_id)
                && (self.stage != Some(Stage::ExternalTesting)
                    || self.predecessor_operation_id == self.candidate_operation_id)
                && (self.stage != Some(Stage::ProductionSubmit)
                    || self.predecessor_operation_id != self.candidate_operation_id)
        } else {
            self.predecessor_operation_id.is_none()
                && self.predecessor_receipt_sha256.is_none()
                && self.execution_receipt_sha256.is_none()
        }
    }
    fn destination_valid(&self, ios: bool) -> bool {
        let d = &self.destination;
        match (ios, self.stage) {
            (false, None) => {
                d.channel == "internal"
                    && d.release_status.as_deref() == Some("completed")
                    && d.automatic_release.is_none()
            }
            (false, Some(Stage::ExternalTesting)) => {
                !d.channel.trim().is_empty()
                    && d.channel.chars().count() <= 100
                    && !d.channel.contains(['\0', '\r', '\n'])
                    && !matches!(d.channel.as_str(), "internal" | "production")
                    && d.release_status.as_deref() == Some("completed")
                    && d.automatic_release.is_none()
            }
            (false, Some(Stage::ProductionSubmit)) => {
                d.channel == "production"
                    && d.release_status.as_deref() == Some("draft")
                    && d.automatic_release.is_none()
            }
            (true, None) => {
                d.channel == "testflight-internal"
                    && d.release_status.is_none()
                    && d.automatic_release.is_none()
            }
            (true, Some(Stage::ExternalTesting)) => {
                d.channel == "testflight-external"
                    && d.release_status.is_none()
                    && d.automatic_release.is_none()
            }
            (true, Some(Stage::ProductionSubmit)) => {
                d.channel == "app-store-review"
                    && d.release_status.is_none()
                    && d.automatic_release == Some(false)
            }
        }
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        let mut n = 0usize;
        for s in [
            &self.operation_id,
            &self.candidate_sha256,
            &self.intent_sha256,
            &self.source_commit,
            &self.source_tree,
            &self.application,
            &self.version.name,
            &self.destination.channel,
        ] {
            n = n.checked_add(s.capacity())?;
        }
        for s in [
            &self.receipt_sha256,
            &self.destination.release_status,
            &self.candidate_operation_id,
            &self.predecessor_operation_id,
            &self.predecessor_receipt_sha256,
            &self.execution_receipt_sha256,
        ] {
            n = n.checked_add(s.as_ref().map_or(0, String::capacity))?;
        }
        Some(n)
    }
    pub(crate) fn bounded(&self, r: &Review) -> bool {
        self.valid_for(r)
            && self
                .heap()
                .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
                .is_some_and(|n| n <= REVIEWED_FILES_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const UUID: &str = "12345678-1234-4234-8234-123456789abc";
    #[test]
    fn sixteen_native_contexts_are_closed_without_abandon_or_platform_inference() {
        let mut accepted = 0;
        for kind in [
            Kind::Enroll,
            Kind::Verify,
            Kind::ReviewInputs,
            Kind::ReviewPrepared,
            Kind::ReviewExecution,
            Kind::ReviewReconcile,
            Kind::ReviewRecovery,
            Kind::ReviewStagePrepared,
            Kind::ReviewStageExecution,
            Kind::ReviewExternalReadiness,
        ] {
            for platform in [None, Some(Platform::Android), Some(Platform::Ios)] {
                let selected = Selection {
                    kind,
                    platform,
                    candidate_operation_id: (!matches!(kind, Kind::Enroll | Kind::Verify)
                        && !kind.stage())
                    .then(|| UUID.into()),
                    stage_operation_id: kind.stage().then(|| UUID.into()),
                };
                let expected = match kind {
                    Kind::Enroll | Kind::Verify | Kind::ReviewRecovery => platform.is_none(),
                    Kind::ReviewStagePrepared | Kind::ReviewStageExecution => platform.is_some(),
                    Kind::ReviewExternalReadiness => platform == Some(Platform::Ios),
                    _ => platform != Some(Platform::Android),
                };
                assert_eq!(selected.valid(), expected);
                accepted += usize::from(expected);
                if expected {
                    let mut raw = serde_json::to_value(&selected).unwrap();
                    raw["unexpected"] = json!(true);
                    assert!(serde_json::from_value::<Selection>(raw).is_err());
                }
            }
        }
        assert_eq!(accepted, 16);
        for raw in [
            json!({"kind":"abandon-inputs","candidateOperationId":UUID}),
            json!({"kind":"verify","platform":null}),
            json!({"kind":"review-inputs","candidateOperationId":null}),
        ] {
            assert!(serde_json::from_value::<Selection>(raw).is_err());
        }
        let bad = Selection {
            kind: Kind::ReviewInputs,
            platform: None,
            candidate_operation_id: Some(format!("{UUID}\n")),
            stage_operation_id: None,
        };
        assert!(!bad.valid());
    }
    #[test]
    fn old_selection_bytes_and_new_pending_are_not_start_or_native_retirement() {
        let selection = Selection {
            kind: Kind::Verify,
            platform: None,
            candidate_operation_id: None,
            stage_operation_id: None,
        };
        assert_eq!(
            serde_json::to_string(&selection).unwrap(),
            "{\"kind\":\"verify\"}"
        );
        let q = Query {
            project_id: crate::service_protocol::Id::parse(&"1".repeat(32)).unwrap(),
            service_instance: crate::service_protocol::Id::parse(&"2".repeat(32)).unwrap(),
            request_id: crate::service_protocol::Id::parse(&"3".repeat(32)).unwrap(),
        };
        let mut s = Status {
            origin: q,
            selection,
            revision: 1,
            phase: Phase::Queued,
            settlement: Settlement::Pending,
            reason: Reason::None,
            review: None,
            remaining_ms: 0,
        };
        assert!(s.validate().is_ok());
        s.phase = Phase::Prepared;
        assert!(s.validate().is_err());
        s.phase = Phase::Unknown;
        s.settlement = Settlement::Unknown;
        s.reason = Reason::CleanupUnknown;
        assert!(s.validate().is_ok());
        s.remaining_ms = 1;
        assert!(s.validate().is_err());
    }
}
