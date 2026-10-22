//! Closed DATA for the sixteen non-destructive local history contexts.
//! No config/Store requirement, key, journal parser, native consent or file bytes.
use crate::service_protocol::{Error, Id, Settlement};
pub(crate) use crate::service_store_protocol::{Outcome, Query, Reason, State, Submit};
use serde::{Deserialize, Deserializer, Serialize};
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const RAW_NODES: usize = 32;
pub(crate) const STATUS_LIMIT: usize = 24 * 1024;
pub(crate) const INTENT_MS: u64 = 300_000;
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    Enroll,
    Verify,
    ReviewInputs,
    ReviewPrepared,
    ReviewExecution,
    ReviewReconcile,
    ReviewRecovery,
    ReviewStagePrepared,
    ReviewStageExecution,
    ReviewExternalReadiness,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform {
    Android,
    Ios,
}
impl Kind {
    pub(crate) fn stage(self) -> bool {
        matches!(self, Self::ReviewStagePrepared | Self::ReviewStageExecution | Self::ReviewExternalReadiness)
    }
}
pub(crate) fn selection_valid(kind: Kind, platform: Option<Platform>, candidate: Option<&str>, stage: Option<&str>) -> bool {
    match kind {
        Kind::Enroll | Kind::Verify => platform.is_none() && candidate.is_none() && stage.is_none(),
        Kind::ReviewInputs | Kind::ReviewPrepared | Kind::ReviewExecution | Kind::ReviewReconcile =>
            platform != Some(Platform::Android) && candidate.is_some_and(uuid) && stage.is_none(),
        Kind::ReviewRecovery => platform.is_none() && candidate.is_some_and(uuid) && stage.is_none(),
        Kind::ReviewStagePrepared | Kind::ReviewStageExecution =>
            platform.is_some() && candidate.is_none() && stage.is_some_and(uuid),
        Kind::ReviewExternalReadiness => platform == Some(Platform::Ios) && candidate.is_none() && stage.is_some_and(uuid),
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub kind: Kind,
    pub operation_id: Id,
    pub owner_generation: Id,
    pub status_revision: u32,
    // Native platformless Enroll/Verify and Android ReviewInputs stay absent.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub platform: Option<Platform>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub candidate_operation_id: Option<String>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub stage_operation_id: Option<String>,
}
impl Review {
    pub fn valid(&self) -> bool {
        (1..u32::MAX).contains(&self.status_revision)
            && selection_valid(self.kind, self.platform, self.candidate_operation_id.as_deref(), self.stage_operation_id.as_deref())
    }
    pub(crate) fn selected_id(&self) -> Option<&str> {
        if self.kind.stage() { self.stage_operation_id.as_deref() } else { self.candidate_operation_id.as_deref() }
    }
    pub fn consent(&self) -> &'static str {
        match (self.kind, self.platform) {
            (Kind::Enroll, None) => "agent-local-history-enroll-once-v1",
            (Kind::Verify, None) => "agent-local-history-verify-once-v1",
            (Kind::ReviewInputs, None) => "agent-local-history-android-inputs-once-v1",
            (Kind::ReviewInputs, Some(Platform::Ios)) => "agent-local-history-ios-inputs-once-v1",
            (Kind::ReviewPrepared, None) => "agent-local-history-android-prepared-once-v1",
            (Kind::ReviewPrepared, Some(Platform::Ios)) => "agent-local-history-ios-prepared-once-v1",
            (Kind::ReviewExecution, None) => "agent-local-history-android-execution-once-v1",
            (Kind::ReviewExecution, Some(Platform::Ios)) => "agent-local-history-ios-execution-once-v1",
            (Kind::ReviewReconcile, None) => "agent-local-history-android-reconcile-files-once-v1",
            (Kind::ReviewReconcile, Some(Platform::Ios)) => "agent-local-history-ios-reconcile-files-once-v1",
            (Kind::ReviewRecovery, None) => "agent-local-history-android-recovery-files-once-v1",
            (Kind::ReviewStagePrepared, Some(Platform::Android)) => "agent-local-history-android-stage-prepared-once-v1",
            (Kind::ReviewStagePrepared, Some(Platform::Ios)) => "agent-local-history-ios-stage-prepared-once-v1",
            (Kind::ReviewStageExecution, Some(Platform::Android)) => "agent-local-history-android-stage-execution-once-v1",
            (Kind::ReviewStageExecution, Some(Platform::Ios)) => "agent-local-history-ios-stage-execution-once-v1",
            (Kind::ReviewExternalReadiness, Some(Platform::Ios)) => "agent-local-history-ios-readiness-files-once-v1",
            _ => "unsupported-local-history-context",
        }
    }
    pub fn action(&self) -> crate::service_protocol::Action {
        if self.kind == Kind::Enroll { crate::service_protocol::Action::LocalHistoryEnroll }
        else { crate::service_protocol::Action::LocalHistoryReview }
    }
    pub fn heap(&self) -> usize {
        self.candidate_operation_id.as_ref().map_or(0, String::capacity)
            .saturating_add(self.stage_operation_id.as_ref().map_or(0, String::capacity))
    }
}

pub(crate) fn uuid(v: &str) -> bool {
    crate::service_store_protocol::uuid(v)
        && v.as_bytes().get(14) == Some(&b'4')
        && v.as_bytes().get(19).is_some_and(|c| b"89ab".contains(c))
}
fn hex(v: &str, n: usize) -> bool {
    v.len() == n
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HistoryPhase {
    InputsPending,
    InputsReady,
    PreparePending,
    PromotionPending,
    Prepared,
    ExecutePending,
    SettledSuccess,
    SettledFailure,
    ReconciliationRequired,
    TargetReconciled,
    ExternalReady,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HistoryRow {
    pub operation_id: String,
    pub phase: HistoryPhase,
    pub recovery_required: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Limitation {
    NoStoreAuthority,
    NoBuildOrPublishing,
    KeychainIntactRollbackBoundary,
}
pub(crate) const LIMITATIONS: [Limitation; 3] = [
    Limitation::NoStoreAuthority,
    Limitation::NoBuildOrPublishing,
    Limitation::KeychainIntactRollbackBoundary,
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct File {
    pub file_name: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Version {
    pub name: String,
    pub build: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Archive {
    pub directory: String,
    pub entries: u32,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Inputs {
    pub operation_id: String,
    pub candidate_sha256: String,
    pub source_commit: String,
    pub source_tree: String,
    pub application: String,
    pub version: Version,
    pub files: [File; 3],
    #[serde(deserialize_with = "nullable")]
    pub archive: Option<Archive>,
    pub observation: String,
    pub prior_create_finality: String,
}
impl Inputs {
    fn valid(&self, r: &Review) -> bool {
        let ios = r.platform.is_some();
        let app = &self.application;
        self.operation_id == r.candidate_operation_id.as_deref().unwrap_or("")
            && uuid(&self.operation_id)
            && hex(&self.candidate_sha256, 64)
            && hex(&self.source_commit, 40)
            && hex(&self.source_tree, 40)
            && app.len() <= 255
            && app.split('.').count() >= 2
            && app.split('.').all(|s| {
                s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == if ios { b'-' } else { b'_' })
            })
            && (1..=64).contains(&self.version.name.len())
            && self
                .version
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            && (1..=2_100_000_000).contains(&self.version.build)
            && self.files.iter().all(|f| hex(&f.sha256, 64) && f.bytes > 0)
            && (if ios {
                self.files[0]
                    .file_name
                    .strip_prefix("export/")
                    .is_some_and(|n| {
                        !n.is_empty()
                            && n.len() <= 255
                            && n.ends_with(".ipa")
                            && !n.chars().any(|c| {
                                c < '\u{20}' || c == '\u{7f}' || matches!(c, '/' | '\\' | ':')
                            })
                    })
                    && self.files[0].bytes <= 4 * 1024u64.pow(3)
            } else {
                self.files[0].file_name == "app-release.aab"
                    && self.files[0].bytes <= 1024u64.pow(3)
            })
            && self.files[1].file_name == "store-metadata.zip"
            && self.files[1].bytes <= 512 * 1024u64.pow(2)
            && self.files[2].file_name == "validation-report.json"
            && self.files[2].bytes <= 65536
            && (match &self.archive {
                Some(a) => {
                    ios && a.directory == "archive.xcarchive"
                        && (1..=100_000).contains(&a.entries)
                        && (1..=8 * 1024u64.pow(3)).contains(&a.bytes)
                        && hex(&a.sha256, 64)
                }
                None => !ios,
            })
            && self.observation == "current-bundle-only"
            && self.prior_create_finality == "not-established"
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Report {
    pub enrolled: bool,
    pub head_sequence: u32,
    pub history: Vec<HistoryRow>,
    #[serde(deserialize_with = "nullable")]
    pub candidate_inputs: Option<Inputs>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub reviewed_files: Option<Box<crate::service_local_history_prepare_protocol::ReviewedFiles>>,
    pub limitations: [Limitation; 3],
}
impl Report {
    pub fn valid_for(&self, r: &Review) -> bool {
        if !r.valid()
            || !self.enrolled
            || !(1..=513).contains(&self.head_sequence)
            || self.history.len() > 64
            || self.history.len() >= self.head_sequence as usize
            || self.limitations != LIMITATIONS
        {
            return false;
        }
        if !self.history.iter().enumerate().all(|(i, row)| {
            uuid(&row.operation_id)
                && !self.history[..i]
                    .iter()
                    .any(|old| old.operation_id == row.operation_id)
                && row.recovery_required
                    != matches!(
                        row.phase,
                        HistoryPhase::SettledSuccess
                            | HistoryPhase::SettledFailure
                            | HistoryPhase::TargetReconciled
                            | HistoryPhase::ExternalReady
                    )
        }) {
            return false;
        }
        if matches!(r.kind, Kind::Enroll | Kind::Verify) {
            return self.candidate_inputs.is_none() && self.reviewed_files.is_none();
        }
        if r.kind != Kind::ReviewInputs {
            if self.candidate_inputs.is_some() { return false; }
            let Some(files) = &self.reviewed_files else { return false; };
            let Some(row) = self.history.iter().find(|v| Some(v.operation_id.as_str()) == r.selected_id()) else { return false; };
            let (head, phase) = match r.kind {
                Kind::ReviewPrepared => (5, row.phase == HistoryPhase::Prepared),
                Kind::ReviewExecution => (7, row.phase == HistoryPhase::SettledSuccess),
                Kind::ReviewReconcile => (6, self.history.last()==Some(row) && matches!(row.phase, HistoryPhase::ExecutePending | HistoryPhase::SettledSuccess | HistoryPhase::SettledFailure | HistoryPhase::ReconciliationRequired)),
                Kind::ReviewRecovery => (7, row.phase == HistoryPhase::TargetReconciled),
                Kind::ReviewStagePrepared => (if files.stage==Some(crate::service_local_history_prepare_protocol::Stage::ProductionSubmit){13}else{9}, row.phase == HistoryPhase::Prepared),
                Kind::ReviewStageExecution => (if files.stage==Some(crate::service_local_history_prepare_protocol::Stage::ProductionSubmit){15}else{11}, row.phase == HistoryPhase::SettledSuccess),
                Kind::ReviewExternalReadiness => (12, row.phase == HistoryPhase::ExternalReady),
                _ => return false,
            };
            return self.head_sequence >= head && phase && files.bounded(r);
        }
        if self.reviewed_files.is_some() { return false; }
        match self
            .history
            .iter()
            .find(|v| Some(v.operation_id.as_str()) == r.candidate_operation_id.as_deref())
        {
            Some(row) => match (row.phase, &self.candidate_inputs) {
                (HistoryPhase::InputsPending | HistoryPhase::SettledFailure, None) => true,
                (HistoryPhase::InputsReady, Some(c)) => c.valid(r),
                _ => false,
            },
            None => false,
        }
    }
    pub fn heap(&self) -> Option<usize> {
        let mut n = self
            .history
            .capacity()
            .checked_mul(std::mem::size_of::<HistoryRow>())?;
        for r in &self.history {
            n = n.checked_add(r.operation_id.capacity())?;
        }
        if let Some(c) = &self.candidate_inputs {
            for v in [
                &c.operation_id,
                &c.candidate_sha256,
                &c.source_commit,
                &c.source_tree,
                &c.application,
                &c.version.name,
                &c.observation,
                &c.prior_create_finality,
            ] {
                n = n.checked_add(v.capacity())?;
            }
            for f in &c.files {
                n = n
                    .checked_add(f.file_name.capacity())?
                    .checked_add(f.sha256.capacity())?;
            }
            if let Some(a) = &c.archive {
                n = n
                    .checked_add(a.directory.capacity())?
                    .checked_add(a.sha256.capacity())?;
            }
        }
        if let Some(files) = &self.reviewed_files {
            n = n.checked_add(std::mem::size_of_val(files.as_ref()))?.checked_add(files.heap()?)?;
        }
        Some(n)
    }
    pub fn bounded(&self, r: &Review) -> bool {
        self.valid_for(r)
            && self.history.capacity() <= 64
            && self
                .heap()
                .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
                .is_some_and(|n| n <= 8192)
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

#[cfg(test)]
mod tests {
    use super::*;
    fn id(c: char) -> Id {
        Id::parse(&c.to_string().repeat(32)).unwrap()
    }
    fn review() -> Review {
        Review {
            kind: Kind::ReviewInputs,
            stage_operation_id: None,
            operation_id: id('a'),
            owner_generation: id('b'),
            status_revision: 1,
            platform: Some(Platform::Ios),
            candidate_operation_id: Some("12345678-1234-4234-8234-123456789abc".into()),
        }
    }
    #[test]
    fn local_history_codec_closes_platformless_null_and_candidate_grammar() {
        let mut r = review();
        assert!(r.valid());
        let value = serde_json::to_value(&r).unwrap();
        assert_eq!(serde_json::from_value::<Review>(value.clone()).unwrap(), r);
        for field in ["platform", "candidateOperationId"] {
            let mut bad = value.clone();
            bad[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<Review>(bad).is_err());
        }
        let mut bad = value.clone();
        bad["platform"] = "android".into();
        assert!(serde_json::from_value::<Review>(bad).is_err());
        r.platform = None;
        assert!(r.valid());
        assert_eq!(r.consent(), "agent-local-history-android-inputs-once-v1");
        for kind in [Kind::Enroll, Kind::Verify] {
            r.kind = kind;
            assert!(!r.valid());
            r.candidate_operation_id = None;
            assert!(r.valid());
            let v = serde_json::to_value(&r).unwrap();
            assert!(v.get("platform").is_none());
            assert!(v.get("candidateOperationId").is_none());
            r.candidate_operation_id = Some("12345678-1234-4234-8234-123456789abc".into());
        }
        let mut v = serde_json::to_value(Access::empty()).unwrap();
        v.as_object_mut().unwrap().remove("status");
        assert!(serde_json::from_value::<Access>(v).is_err());
    }
    #[test]
    fn local_history_max_report_fits_typed_and_full_response_caps_without_authority() {
        let r = review();
        let hash = "a".repeat(64);
        let mut history = Vec::with_capacity(64);
        history.push(HistoryRow {
            operation_id: r.candidate_operation_id.clone().unwrap(),
            phase: HistoryPhase::InputsReady,
            recovery_required: true,
        });
        for i in 1..64 {
            history.push(HistoryRow {
                operation_id: format!("{i:08x}-1234-4234-8234-123456789abc"),
                phase: HistoryPhase::ReconciliationRequired,
                recovery_required: true,
            });
        }
        let report = Report {
            enrolled: true,
            reviewed_files: None,
            head_sequence: 513,
            history,
            candidate_inputs: Some(Inputs {
                operation_id: r.candidate_operation_id.clone().unwrap(),
                candidate_sha256: hash.clone(),
                source_commit: "a".repeat(40),
                source_tree: "b".repeat(40),
                application: format!("a.{}", "b".repeat(253)),
                version: Version {
                    name: "1".repeat(64),
                    build: 2_100_000_000,
                },
                files: [
                    File {
                        file_name: format!("export/{}.ipa", "a".repeat(251)),
                        bytes: 4 * 1024u64.pow(3),
                        sha256: hash.clone(),
                    },
                    File {
                        file_name: "store-metadata.zip".into(),
                        bytes: 512 * 1024u64.pow(2),
                        sha256: hash.clone(),
                    },
                    File {
                        file_name: "validation-report.json".into(),
                        bytes: 65536,
                        sha256: hash.clone(),
                    },
                ],
                archive: Some(Archive {
                    directory: "archive.xcarchive".into(),
                    entries: 100_000,
                    bytes: 8 * 1024u64.pow(3),
                    sha256: hash,
                }),
                observation: "current-bundle-only".into(),
                prior_create_finality: "not-established".into(),
            }),
            limitations: LIMITATIONS,
        };
        assert!(report.bounded(&r));
        let status = Status {
            origin: Query {
                project_id: id('1'),
                service_instance: id('2'),
                request_id: id('3'),
            },
            grant_id: id('4'),
            review_id: id('5'),
            revision: 5,
            review: r.clone(),
            state: State::Complete,
            settlement: Settlement::Settled,
            reason: Reason::None,
            operation: Some(Operation {
                operation_id: id('a'),
                owner_generation: id('b'),
                status_revision: 4,
            }),
            outcome: Some(Outcome::Complete),
            result: Some(report.clone()),
        };
        status.validate().unwrap();
        let access = Access {
            service_instance: Some(id('2')),
            project_id: Some(id('1')),
            grant_id: Some(id('4')),
            review_id: Some(id('5')),
            review: Some(r.clone()),
            enabled: false,
            remaining_ms: 0,
            consumed: true,
            pending: false,
            unknown: false,
            request_id: Some(id('3')),
            status: Some(status),
        };
        let response = crate::service_protocol::Response {
            version: 1,
            request_id: id('8'),
            service_instance: id('2'),
            client_id: id('6'),
            session_id: id('7'),
            response: crate::service_protocol::ResponseBody::LocalHistoryAccess(Box::new(access)),
        };
        let bytes = crate::service_protocol::encode_response(&response).unwrap();
        assert!(bytes.len() <= STATUS_LIMIT);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        fn count(v: &serde_json::Value) -> usize {
            1 + match v {
                serde_json::Value::Array(a) => a.iter().map(count).sum(),
                serde_json::Value::Object(m) => m.values().map(count).sum(),
                _ => 0,
            }
        }
        assert!(count(&value) <= 384);
        assert!(report.heap().unwrap() + std::mem::size_of::<Report>() <= 8192);
        let mut bad = report;
        bad.candidate_inputs.as_mut().unwrap().prior_create_finality = "complete".into();
        assert!(!bad.valid_for(&r));
        bad.candidate_inputs = None;
        assert!(!bad.valid_for(&r));
        bad.history[0].phase = HistoryPhase::InputsPending;
        assert!(bad.valid_for(&r));
        bad.history[0].phase = HistoryPhase::SettledFailure;
        bad.history[0].recovery_required = false;
        assert!(bad.valid_for(&r));
        bad.history[0].phase = HistoryPhase::Prepared;
        assert!(!bad.valid_for(&r));
    }
    #[test]
    fn local_history_partial_and_unknown_results_never_smuggle_completed_report() {
        let mut s = Status {
            origin: Query {
                project_id: id('1'),
                service_instance: id('2'),
                request_id: id('3'),
            },
            grant_id: id('4'),
            review_id: id('5'),
            revision: 1,
            review: Review {
                kind: Kind::Verify,
                platform: None,
                candidate_operation_id: None,
                ..review()
            },
            state: State::Queued,
            settlement: Settlement::Pending,
            reason: Reason::None,
            operation: None,
            outcome: None,
            result: None,
        };
        s.validate().unwrap();
        s.result = Some(Report {
            enrolled: true,
            reviewed_files: None,
            head_sequence: 1,
            history: vec![],
            candidate_inputs: None,
            limitations: LIMITATIONS,
        });
        assert!(s.validate().is_err());
        s.result = None;
        s.state = State::Unknown;
        s.settlement = Settlement::Unknown;
        s.outcome = Some(Outcome::Unknown);
        s.reason = Reason::CleanupUnknown;
        s.validate().unwrap();
        s.reason = Reason::None;
        assert!(s.validate().is_err());
    }
}
