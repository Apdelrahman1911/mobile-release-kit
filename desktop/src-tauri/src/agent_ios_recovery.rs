//! Closed, credential-free DATA for the recovery variant of the SAME iOS
//! build inbox. A report, session label or acknowledged ID pair is not an
//! IOSRecoveryObservation, a recovery permit, or native finality.
use crate::agent_build_requests::{Query, RequestState, StartState};
use crate::agent_local_checks::Outcome;
use crate::service_protocol::{Error, Id, OperationState, Settlement};
use serde::{Deserialize, Deserializer, Serialize};

pub const CONSENT: &str = "agent-local-ios-recovery-v1";
pub const ACCOUNT_CONFIRMATION: &str = "account-signing-is-idle-and-restore-owned-state";
pub const PROJECT_CONFIRMATION: &str = "project-build-inputs-are-idle-and-restore-owned-state";

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub(crate) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
fn session(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Inspect,
    Account,
    Project,
}
impl Action {
    pub fn confirmation(self) -> Option<&'static str> {
        match self {
            Self::Inspect => None,
            Self::Account => Some(ACCOUNT_CONFIRMATION),
            Self::Project => Some(PROJECT_CONFIRMATION),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Inspection {
    pub operation_id: Id,
    pub owner_generation: Id,
}
impl Inspection {
    pub(crate) fn heap_bytes(&self) -> Option<usize> {
        self.operation_id
            .retained_bytes()
            .checked_add(self.owner_generation.retained_bytes())
    }
}
/// MAIN supplies the displayed ORIGINAL inspection pair, never a session
/// chosen from a newly arrived report. Native derives the session itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub enum Selection {
    Inspect,
    Account { inspection: Inspection },
    Project { inspection: Inspection },
}
impl Selection {
    pub fn action(&self) -> Action {
        match self {
            Self::Inspect => Action::Inspect,
            Self::Account { .. } => Action::Account,
            Self::Project { .. } => Action::Project,
        }
    }
    pub fn inspection(&self) -> Option<&Inspection> {
        match self {
            Self::Inspect => None,
            Self::Account { inspection } | Self::Project { inspection } => Some(inspection),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    #[serde(rename = "local-ios-recovery")]
    LocalIosRecovery,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub enum Intent {
    Inspect,
    Account {
        inspection: Inspection,
        session: String,
    },
    Project {
        inspection: Inspection,
        session: String,
    },
}
impl Intent {
    pub fn action(&self) -> Action {
        match self {
            Self::Inspect => Action::Inspect,
            Self::Account { .. } => Action::Account,
            Self::Project { .. } => Action::Project,
        }
    }
    pub fn session(&self) -> Option<&str> {
        match self {
            Self::Inspect => None,
            Self::Account { session, .. } | Self::Project { session, .. } => Some(session),
        }
    }
    pub fn inspection(&self) -> Option<&Inspection> {
        match self {
            Self::Inspect => None,
            Self::Account { inspection, .. } | Self::Project { inspection, .. } => Some(inspection),
        }
    }
    pub fn selection(&self) -> Selection {
        match self {
            Self::Inspect => Selection::Inspect,
            Self::Account { inspection, .. } => Selection::Account {
                inspection: inspection.clone(),
            },
            Self::Project { inspection, .. } => Selection::Project {
                inspection: inspection.clone(),
            },
        }
    }
    pub(crate) fn heap_bytes(&self) -> Option<usize> {
        match self {
            Self::Inspect => Some(0),
            Self::Account {
                inspection,
                session,
            }
            | Self::Project {
                inspection,
                session,
            } => inspection.heap_bytes()?.checked_add(session.capacity()),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub mode: Mode,
    pub recovery: Intent,
}
impl Review {
    pub fn valid(&self) -> bool {
        self.recovery.session().is_none_or(session)
    }
    pub(crate) fn capacity_valid(&self) -> bool {
        self.valid() && self.recovery.heap_bytes().is_some_and(|n| n <= 3 * 32)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Idle,
    Pending,
    Busy,
    Conflict,
    ManualRequired,
    Recovered,
    RecoveredWithConflict,
    Absent,
    CleanupOnly,
    NotInspected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Next {
    None,
    Wait,
    Ordinary,
    Manual,
    Preserve,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub status: State,
    #[serde(deserialize_with = "nullable")]
    pub session: Option<String>,
    pub next: Next,
}
impl Row {
    fn valid(&self, account: bool) -> bool {
        use State as S;
        if self.session.as_deref().is_some_and(|s| !session(s))
            || account && matches!(self.status, S::CleanupOnly | S::NotInspected)
            || !account && self.status == S::RecoveredWithConflict
            || matches!(
                self.status,
                S::Pending
                    | S::CleanupOnly
                    | S::ManualRequired
                    | S::Recovered
                    | S::RecoveredWithConflict
                    | S::Absent
            ) && self.session.is_none()
            || matches!(self.status, S::Idle | S::NotInspected) && self.session.is_some()
        {
            return false;
        }
        match self.status {
            S::Idle | S::Recovered | S::Absent => self.next == Next::None,
            S::Busy => self.next == Next::Wait,
            S::ManualRequired => self.next == Next::Manual,
            S::Pending => matches!(self.next, Next::Ordinary | Next::Manual),
            S::CleanupOnly => self.next == Next::Ordinary,
            S::Conflict | S::RecoveredWithConflict | S::NotInspected => self.next == Next::Preserve,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Limitation {
    LocalRecoveryOnly,
    ManualRecoveryNotSupported,
    UserConfirmationIsNotWorkerFinality,
    NoStoreOperation,
}
pub const LIMITATIONS: [Limitation; 4] = [
    Limitation::LocalRecoveryOnly,
    Limitation::ManualRecoveryNotSupported,
    Limitation::UserConfirmationIsNotWorkerFinality,
    Limitation::NoStoreOperation,
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub schema_version: u32,
    pub scope: Mode,
    #[serde(deserialize_with = "nullable")]
    pub account: Option<Row>,
    #[serde(deserialize_with = "nullable")]
    pub project: Option<Row>,
    pub limitations: [Limitation; 4],
}
impl Report {
    pub fn valid_for(&self, review: &Review) -> bool {
        if !review.valid() || self.schema_version != 1 || self.limitations != LIMITATIONS {
            return false;
        }
        for (action, row) in [
            (Action::Account, &self.account),
            (Action::Project, &self.project),
        ] {
            if (review.recovery.action() == Action::Inspect || review.recovery.action() == action)
                != row.is_some()
            {
                return false;
            }
            if let Some(row) = row {
                if !row.valid(action == Action::Account) {
                    return false;
                }
                if review.recovery.action() == Action::Inspect {
                    if matches!(
                        row.status,
                        State::Recovered | State::RecoveredWithConflict | State::Absent
                    ) {
                        return false;
                    }
                } else if row.session.as_deref() != review.recovery.session()
                    || !matches!(
                        row.status,
                        State::Recovered
                            | State::RecoveredWithConflict
                            | State::Absent
                            | State::Busy
                            | State::Conflict
                            | State::ManualRequired
                    )
                {
                    return false;
                }
            }
        }
        true
    }
    pub(crate) fn heap_bytes(&self) -> Option<usize> {
        self.account
            .as_ref()
            .and_then(|r| r.session.as_ref())
            .map_or(0, String::capacity)
            .checked_add(
                self.project
                    .as_ref()
                    .and_then(|r| r.session.as_ref())
                    .map_or(0, String::capacity),
            )
    }
    pub(crate) fn compact(&mut self) {
        for row in [&mut self.account, &mut self.project].into_iter().flatten() {
            if let Some(s) = &mut row.session {
                *s = std::mem::take(s).into_boxed_str().into_string();
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    None,
    Cancelled,
    ContextChanged,
    DocumentLost,
    Shutdown,
    TimedOut,
    ProtocolError,
    RuntimeUnavailable,
    IntentExpired,
    StaleIntent,
    ProjectAdmissionRefused,
    AccountAdmissionRefused,
    CommandFailed,
    CommandIncomplete,
    InputLimit,
    ResultLimit,
    WorkRetained,
    RecoveryAttention,
    CleanupUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Accepted,
    RecoveringAccount,
    RecoveringProject,
    DisposingWork,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub operation_id: Id,
    pub owner_generation: Id,
    pub status_revision: u32,
    pub state: OperationState,
    pub settlement: Settlement,
    pub outcome: Option<Outcome>,
    pub reason: Reason,
    pub stage: Option<Stage>,
    pub report: Option<Report>,
}
impl Operation {
    pub fn valid_for(&self, review: &Review) -> bool {
        if !review.valid() || self.status_revision == u32::MAX {
            return false;
        }
        if self.settlement == Settlement::Unknown {
            return self.state == OperationState::Unknown
                && self.outcome == Some(Outcome::Unknown)
                && self.reason == Reason::CleanupUnknown
                && self.stage.is_none()
                && self.report.is_none();
        }
        if self.settlement == Settlement::Pending {
            return matches!(
                self.state,
                OperationState::Prepared
                    | OperationState::Running
                    | OperationState::CancellationRequested
            ) && self.outcome.is_none()
                && self.report.is_none()
                && (self.state != OperationState::Prepared
                    || self.reason == Reason::None && self.stage.is_none());
        }
        if self.reason == Reason::CleanupUnknown
            || self.report.as_ref().is_some_and(|r| !r.valid_for(review))
        {
            return false;
        }
        match self.outcome {
            Some(Outcome::Complete) => {
                self.state == OperationState::Succeeded
                    && self.reason == Reason::None
                    && self.stage == Some(Stage::DisposingWork)
                    && self.report.is_some()
            }
            Some(Outcome::Cancelled) => {
                self.state == OperationState::Cancelled
                    && matches!(
                        self.reason,
                        Reason::Cancelled
                            | Reason::ContextChanged
                            | Reason::DocumentLost
                            | Reason::Shutdown
                    )
            }
            Some(Outcome::TimedOut) => {
                self.state == OperationState::Failed && self.reason == Reason::TimedOut
            }
            Some(Outcome::Refused | Outcome::Failed) => {
                self.state == OperationState::Failed && self.reason != Reason::None
            }
            _ => false,
        }
    }
    pub(crate) fn heap_bytes(&self) -> Option<usize> {
        self.operation_id
            .retained_bytes()
            .checked_add(self.owner_generation.retained_bytes())?
            .checked_add(self.report.as_ref().map_or(Some(0), Report::heap_bytes)?)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub origin: Query,
    pub expected_observation_revision: u64,
    pub request_state: RequestState,
    pub start_state: StartState,
    pub review: Review,
    pub operation: Option<Operation>,
    pub history_available: bool,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0
            || !self.do_not_replay
            || !self.review.valid()
            || self
                .operation
                .as_ref()
                .is_some_and(|o| !o.valid_for(&self.review))
            || self.history_available && self.operation.is_none()
            || self.request_state == RequestState::OriginalAvailable && self.operation.is_none()
            || self.start_state != StartState::NotRequested
                && self.operation.is_none()
                && self.request_state != RequestState::AdmissionUnknown
        {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}
impl TryFrom<crate::agent_build_requests::Snapshot> for Status {
    type Error = Error;
    fn try_from(s: crate::agent_build_requests::Snapshot) -> Result<Self, Error> {
        let crate::agent_build_requests::Review::IosRecovery(review) = s.review else {
            return Err(Error::Conflict);
        };
        let operation = match s.operation {
            Some(crate::agent_build_requests::Operation::IosRecovery(o)) => Some(o),
            None => None,
            _ => return Err(Error::Conflict),
        };
        let value = Self {
            origin: s.origin,
            expected_observation_revision: s.expected_observation_revision,
            request_state: s.request_state,
            start_state: s.start_state,
            review,
            operation,
            history_available: s.history_available,
            do_not_replay: s.do_not_replay,
        };
        value.validate()?;
        Ok(value)
    }
}
/// The existing response name and old saved-build bytes are unchanged. The
/// recovery branch cannot decode as an archive, or acquire its config fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestStatus {
    Saved(super::Status),
    Recovery(Status),
}
impl RequestStatus {
    pub fn origin(&self) -> &Query {
        match self {
            Self::Saved(s) => &s.origin,
            Self::Recovery(s) => &s.origin,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Saved(s) => s.validate(),
            Self::Recovery(s) => s.validate(),
        }
    }
    pub fn request_state(&self) -> RequestState {
        match self {
            Self::Saved(s) => s.request_state,
            Self::Recovery(s) => s.request_state,
        }
    }
    pub fn native(&self) -> Option<(OperationState, Settlement)> {
        match self {
            Self::Saved(s) => s.operation.as_ref().map(|o| (o.state, o.settlement)),
            Self::Recovery(s) => s.operation.as_ref().map(|o| (o.state, o.settlement)),
        }
    }
}
impl TryFrom<crate::agent_build_requests::Snapshot> for RequestStatus {
    type Error = Error;
    fn try_from(s: crate::agent_build_requests::Snapshot) -> Result<Self, Error> {
        if matches!(
            &s.review,
            crate::agent_build_requests::Review::IosRecovery(_)
        ) {
            Status::try_from(s).map(Self::Recovery)
        } else {
            super::Status::try_from(s).map(Self::Saved)
        }
    }
}

/// Comparison-only MAIN readback from the original native observation AND
/// its exact acknowledged Build Entry. Deserializing it grants nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcknowledgedInspection {
    pub origin: Query,
    pub inspection: Inspection,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainAccess {
    #[serde(flatten)]
    pub(crate) access: crate::agent_build_requests::MainAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_inspection: Option<AcknowledgedInspection>,
}

impl MainAccess {
    pub(crate) fn new(access: crate::agent_build_requests::Access, revision: u64) -> Self {
        Self {
            access: crate::agent_build_requests::MainAccess::new(access, revision),
            recovery_inspection: None,
        }
    }
}
impl std::ops::Deref for MainAccess {
    type Target = crate::agent_build_requests::MainAccess;
    fn deref(&self) -> &Self::Target {
        &self.access
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn inspection() -> Inspection {
        Inspection {
            operation_id: Id::parse(&"a".repeat(32)).unwrap(),
            owner_generation: Id::parse(&"b".repeat(32)).unwrap(),
        }
    }
    fn inspect() -> Review {
        Review {
            mode: Mode::LocalIosRecovery,
            recovery: Intent::Inspect,
        }
    }
    fn report() -> Report {
        Report {
            schema_version: 1,
            scope: Mode::LocalIosRecovery,
            limitations: LIMITATIONS,
            account: Some(Row {
                status: State::Pending,
                session: Some("c".repeat(32)),
                next: Next::Ordinary,
            }),
            project: Some(Row {
                status: State::Idle,
                session: None,
                next: Next::None,
            }),
        }
    }
    #[test]
    fn recovery_selection_has_no_session_input_or_implicit_restore_confirmation() {
        let value = json!({"action":"account","inspection":inspection()});
        let selected: Selection = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(selected.action().confirmation(), Some(ACCOUNT_CONFIRMATION));
        assert_eq!(Action::Inspect.confirmation(), None);
        for field in [
            "session",
            "savedConfig",
            "password",
            "signing",
            "root",
            "manual",
        ] {
            let mut bad = value.clone();
            bad[field] = json!("not-authority");
            assert!(serde_json::from_value::<Selection>(bad).is_err());
        }
        for bad in [
            json!({"action":"inspect","inspection":inspection()}),
            json!({"action":"project"}),
            json!({"action":"account","inspection":null}),
            json!({"action":"manual","inspection":inspection()}),
        ] {
            assert!(serde_json::from_value::<Selection>(bad).is_err());
        }
    }
    #[test]
    fn recovery_review_is_configless_and_preserves_displayed_inspection_identity() {
        let old = json!({"mode":"saved-ios-unsigned-archive","savedConfig":{"bytes":2,"sha256":"a".repeat(64)},
            "savedVersion":{"bytes":3,"sha256":"b".repeat(64),"name":"1","build":1}});
        assert!(serde_json::from_value::<Review>(old).is_err());
        let review = Review {
            mode: Mode::LocalIosRecovery,
            recovery: Intent::Account {
                inspection: inspection(),
                session: "c".repeat(32),
            },
        };
        assert!(review.valid() && review.capacity_valid());
        assert_eq!(review.recovery.heap_bytes(), Some(96));
        let mut value = serde_json::to_value(&review).unwrap();
        value["savedConfig"] = Value::Null;
        assert!(serde_json::from_value::<Review>(value).is_err());
        let mut bad = review;
        if let Intent::Account { session, .. } = &mut bad.recovery {
            session.push('\n');
        }
        assert!(!bad.valid());
    }
    #[test]
    fn recovery_report_retains_pending_manual_and_conflict_without_fabricating_artifacts() {
        let r = report();
        assert!(r.valid_for(&inspect()));
        assert_eq!(r.heap_bytes(), Some(32));
        let mut recovered = r.clone();
        recovered.account.as_mut().unwrap().status = State::Recovered;
        recovered.account.as_mut().unwrap().next = Next::None;
        assert!(!recovered.valid_for(&inspect()));
        let review = Review {
            mode: Mode::LocalIosRecovery,
            recovery: Intent::Account {
                inspection: inspection(),
                session: "c".repeat(32),
            },
        };
        recovered.project = None;
        assert!(recovered.valid_for(&review));
        recovered.account.as_mut().unwrap().session = Some("d".repeat(32));
        assert!(!recovered.valid_for(&review));
        for field in [
            "artifact",
            "disposition",
            "ipa",
            "privateKey",
            "nativeJoined",
        ] {
            let mut value = serde_json::to_value(&r).unwrap();
            value[field] = json!(true);
            assert!(serde_json::from_value::<Report>(value).is_err());
        }
    }
    #[test]
    fn recovery_terminal_is_not_ready_and_unknown_never_retains_a_success_report() {
        let mut op = Operation {
            operation_id: inspection().operation_id,
            owner_generation: inspection().owner_generation,
            status_revision: 3,
            state: OperationState::Succeeded,
            settlement: Settlement::Settled,
            outcome: Some(Outcome::Complete),
            reason: Reason::None,
            stage: Some(Stage::DisposingWork),
            report: Some(report()),
        };
        assert!(op.valid_for(&inspect())); // Complete INSPECTION still says Pending.
        op.outcome = Some(Outcome::Failed);
        op.state = OperationState::Failed;
        op.reason = Reason::RecoveryAttention;
        assert!(op.valid_for(&inspect()));
        op.settlement = Settlement::Pending;
        assert!(!op.valid_for(&inspect()));
        op.settlement = Settlement::Unknown;
        op.state = OperationState::Unknown;
        op.outcome = Some(Outcome::Unknown);
        op.reason = Reason::CleanupUnknown;
        op.stage = None;
        assert!(!op.valid_for(&inspect()));
        op.report = None;
        assert!(op.valid_for(&inspect()));
    }
}
