//! One named, Desktop-authorized local-check request. These portable records
//! are DATA, not a document, native session, executable or finality receipt.
//! The installed client deliberately has no dependency on the Desktop owners.
use crate::service_protocol::{Error, Id, OperationState, Settlement};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};

pub const LIMIT: usize = 32;
pub const LIFETIME: Duration = Duration::from_secs(900);
pub const CONSENT: &str = "agent-saved-local-android-checks-v1";
pub const REPORT_LIMIT: usize = 64 * 1024;
// All 32 original request/scope/typed-report records, two public copies and
// the one current serialized report/claim. Not a process RSS allowance.
pub(crate) const DOCUMENT_BACKING: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub bytes: u32,
    pub sha256: String,
}
impl Config {
    pub fn valid(&self) -> bool {
        (1..=524288).contains(&self.bytes)
            && self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Submit {
    pub service_instance: Id,
    pub project_id: Id,
    pub request_id: Id,
    pub expected_observation_revision: u64,
}
impl Submit {
    pub fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0 {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
    pub fn query(&self) -> Query {
        Query {
            service_instance: self.service_instance.clone(),
            project_id: self.project_id.clone(),
            request_id: self.request_id.clone(),
        }
    }
}
/// This native-origin marker permits observation/STOP only in the GUI. It is
/// never accepted as Prepare/Start consent or as a worker-produced field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub service_instance: Id,
    pub project_id: Id,
    pub request_id: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequestState {
    Queued,
    Admitting,
    OriginalAvailable,
    RefusedBeforeAdmission,
    CancelledBeforeAdmission,
    Expired,
    AdmissionUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Complete,
    Refused,
    Cancelled,
    TimedOut,
    Failed,
    Unknown,
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
    SavedConfigMissing,
    SavedConfigInvalid,
    SavedConfigChanged,
    SavedConfigSensitive,
    SavedConfigUnsafe,
    SavedConfigTooLarge,
    PlatformDisabled,
    ProjectAdmissionRefused,
    InputLimit,
    ResultLimit,
    CommandIncomplete,
    CleanupUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoreStatus {
    Pass,
    Fail,
    Missing,
    Blocked,
    Invalid,
    Skip,
    Manual,
    Configured,
    NotApplicable,
}
const STATUSES: [CoreStatus; 9] = [
    CoreStatus::Pass,
    CoreStatus::Fail,
    CoreStatus::Missing,
    CoreStatus::Blocked,
    CoreStatus::Invalid,
    CoreStatus::Skip,
    CoreStatus::Manual,
    CoreStatus::Configured,
    CoreStatus::NotApplicable,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Check {
    VersionSource,
    PlatformSelection,
    AndroidModule,
    AndroidGradleWrapper,
    AndroidDebugIdentity,
    WorkspacePrivateOutput,
    AndroidArtifact,
    PreflightEarlyExit,
    ConfigurationPolicy,
    MetadataPolicy,
    ConfiguredProjectCheck,
    CoreLifecycle,
    OtherCoreFinding,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Limitation {
    SavedInputsNotAtomic,
    ProjectCodeEffectsPossible,
    NotNetworkIsolated,
    CoreBuildsDisabled,
    ArtifactValidationNotRequested,
    ToolkitSigningCredentialsStoreNotRequested,
    ReleaseReadinessNotAssessed,
}
const LIMITATIONS: [Limitation; 7] = [
    Limitation::SavedInputsNotAtomic,
    Limitation::ProjectCodeEffectsPossible,
    Limitation::NotNetworkIsolated,
    Limitation::CoreBuildsDisabled,
    Limitation::ArtifactValidationNotRequested,
    Limitation::ToolkitSigningCredentialsStoreNotRequested,
    Limitation::ReleaseReadinessNotAssessed,
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    pub ordinal: u32,
    pub check: Check,
    pub status: CoreStatus,
    pub message: Check,
    pub project_check_index: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub total: u32,
    pub shown: u32,
    pub omitted: u32,
    pub counts: BTreeMap<CoreStatus, u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub schema_version: u32,
    pub scope: String,
    pub used_config: Config,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub limitations: Vec<Limitation>,
}
impl Report {
    pub fn valid(&self) -> bool {
        let s = &self.summary;
        if self.schema_version != 1
            || self.scope != "saved-local-android-project-checks"
            || !self.used_config.valid()
            || self.limitations.as_slice() != LIMITATIONS
            || s.total > 4096
            || s.shown != s.total.min(128)
            || s.omitted != s.total - s.shown
            || self.findings.len() != s.shown as usize
            || s.counts.len() != 9
            || !STATUSES
                .iter()
                .all(|key| s.counts.get(key).is_some_and(|n| *n <= 4096))
            || s.counts.values().copied().sum::<u32>() != s.total
        {
            return false;
        }
        let mut shown = BTreeMap::<CoreStatus, u32>::new();
        for (i, f) in self.findings.iter().enumerate() {
            if f.ordinal as usize != i
                || f.message != f.check
                || f.project_check_index
                    .is_some_and(|n| f.check != Check::ConfiguredProjectCheck || n > 31)
            {
                return false;
            }
            *shown.entry(f.status).or_default() += 1;
        }
        shown
            .iter()
            .all(|(s, n)| self.summary.counts.get(s).is_some_and(|total| n <= total))
    }
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
    pub result: Option<Report>,
}
impl Operation {
    pub fn valid(&self) -> bool {
        if self.status_revision == 0 || self.operation_id == self.owner_generation {
            return false;
        }
        match self.settlement {
            Settlement::Pending => {
                matches!(
                    self.state,
                    OperationState::Prepared
                        | OperationState::Running
                        | OperationState::CancellationRequested
                ) && self.outcome.is_none()
                    && self.result.is_none()
            }
            Settlement::Unknown => {
                self.state == OperationState::Unknown
                    && self.outcome == Some(Outcome::Unknown)
                    && self.result.is_none()
            }
            Settlement::Settled => match (self.state, self.outcome) {
                (OperationState::Succeeded, Some(Outcome::Complete)) => {
                    self.reason == Reason::None && self.result.as_ref().is_some_and(Report::valid)
                }
                (OperationState::Cancelled, Some(Outcome::Cancelled)) => {
                    self.result.is_none() && self.reason != Reason::None
                }
                (
                    OperationState::Failed,
                    Some(Outcome::Failed | Outcome::Refused | Outcome::TimedOut),
                ) => self.result.is_none() && self.reason != Reason::None,
                _ => false,
            },
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub origin: Query,
    pub expected_observation_revision: u64,
    pub request_state: RequestState,
    pub operation: Option<Operation>,
    pub history_available: bool,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0
            || !self.do_not_replay
            || self.operation.as_ref().is_some_and(|v| !v.valid())
            || self.request_state == RequestState::OriginalAvailable && self.operation.is_none()
            || self.operation.is_some()
                && !matches!(
                    self.request_state,
                    RequestState::OriginalAvailable | RequestState::AdmissionUnknown
                )
            || self.history_available && self.operation.is_none()
        {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

/// Comparison only; the original Document independently retains/rechecks its
/// actual RegisteredRoot and SavedEditStamp. No serialized native scope exists.
pub(crate) struct NativeScope {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) root: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) registration: u32,
    pub(crate) input_revision: u64,
    pub(crate) document: Weak<()>,
    pub(crate) observation_revision: u64,
    pub(crate) config: Config,
    pub(crate) draft_revision: u32,
    pub(crate) baseline_generation: u32,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
}
impl NativeScope {
    fn valid(&self) -> bool {
        self.config.valid()
            && self.observation_revision != 0
            && self.inode != 0
            && self.registration != 0
            && self.input_revision != u64::MAX
            && self.draft_revision < u32::MAX
            && self.baseline_generation < u32::MAX
            && self.document.strong_count() != 0
            && (1..=64).contains(&self.runtime_id.len())
            && self.root.is_absolute()
            && self.root.as_os_str().len() <= 4096
    }
}
pub(crate) struct SavedPoint {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) root: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) revision: u64,
    pub(crate) fresh: bool,
    pub(crate) config: Option<Config>,
}
impl SavedPoint {
    pub(crate) fn matches(&self, s: &NativeScope) -> bool {
        self.project_id == s.project_id
            && self.runtime_id == s.runtime_id
            && self.root == s.root
            && self.device == s.device
            && self.inode == s.inode
            && self.fresh
            && self.revision == s.observation_revision
            && self.config.as_ref() == Some(&s.config)
    }
}
struct Lease {
    scope: Arc<NativeScope>,
    expires: Instant,
    revoked: OnceLock<Instant>,
    used: AtomicBool,
    failed: Arc<AtomicBool>,
}
impl Lease {
    fn stop_at(&self, now: Instant) -> Option<Instant> {
        let mut at = self.revoked.get().copied();
        if now >= self.expires {
            at = Some(at.map_or(self.expires, |old| old.min(self.expires)));
        }
        if self.failed.load(Ordering::Acquire) || self.scope.document.strong_count() == 0 {
            at = Some(at.unwrap_or(now));
        }
        at
    }
}
const QUEUED: u8 = 0;
const ADMITTING: u8 = 1;
const BOUND: u8 = 2;
const REFUSED: u8 = 3;
const CANCELLED: u8 = 4;
const EXPIRED: u8 = 5;
const UNKNOWN: u8 = 6;
struct Original {
    operation: Id,
    generation: Id,
    identity: Weak<()>,
}
struct Publication {
    acknowledged: Option<u32>,
    claim: Option<Operation>,
    failed: bool,
}
pub(crate) struct Entry {
    input: Submit,
    lease: Arc<Lease>,
    phase: AtomicU8,
    original: OnceLock<Original>,
    cancelled: OnceLock<Instant>,
    native_stop: OnceLock<tokio::sync::watch::Sender<bool>>,
    latest: Mutex<Option<Operation>>,
    publication: Mutex<Publication>,
}
impl Entry {
    pub(crate) fn input(&self) -> &Submit {
        &self.input
    }
    pub(crate) fn scope(&self) -> &NativeScope {
        &self.lease.scope
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Option<Instant> {
        match (self.lease.stop_at(now), self.cancelled.get().copied()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    pub(crate) fn admission_live(&self) -> bool {
        self.phase.load(Ordering::Acquire) == ADMITTING && self.stop_at(Instant::now()).is_none()
    }
    fn signal(&self) {
        if let Some(stop) = self.native_stop.get() {
            stop.send_replace(true);
        }
        self.scope().changes.send_modify(|_| {});
    }
    pub(crate) fn cancel(&self) {
        let _ = self.cancelled.set(Instant::now());
        let _ = self
            .phase
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire);
        self.signal();
    }
    pub(crate) fn refused(&self) {
        let _ =
            self.phase
                .compare_exchange(ADMITTING, REFUSED, Ordering::AcqRel, Ordering::Acquire);
    }
    pub(crate) fn unconfirmed(&self) {
        self.phase.store(UNKNOWN, Ordering::Release);
        self.cancel();
    }
    fn occupies(&self) -> bool {
        if self.phase.load(Ordering::Acquire) == QUEUED && self.stop_at(Instant::now()).is_some() {
            let _ =
                self.phase
                    .compare_exchange(QUEUED, EXPIRED, Ordering::AcqRel, Ordering::Acquire);
        }
        match self.phase.load(Ordering::Acquire) {
            QUEUED | ADMITTING | UNKNOWN => true,
            BOUND => self.latest.lock().map_or(true, |v| {
                v.as_ref()
                    .is_none_or(|v| v.settlement != Settlement::Settled)
            }),
            _ => false,
        }
    }
    fn observed_request_state(&self, has_operation: bool) -> RequestState {
        let phase = self.phase.load(Ordering::Acquire);
        let request_state = match phase {
            QUEUED => RequestState::Queued,
            ADMITTING => RequestState::Admitting,
            BOUND => RequestState::OriginalAvailable,
            REFUSED => RequestState::RefusedBeforeAdmission,
            CANCELLED => RequestState::CancelledBeforeAdmission,
            EXPIRED => RequestState::Expired,
            _ => RequestState::AdmissionUnknown,
        };
        if has_operation && matches!(request_state, RequestState::Queued | RequestState::Admitting) {
            RequestState::OriginalAvailable
        } else { request_state }
    }
    /// Compact DATA only; never clone a report or acquire a native owner.
    pub(crate) fn catalogue_metadata(&self) -> Result<crate::service_request_catalogue::Request, Error> {
        use crate::service_request_catalogue as data;
        self.occupies();
        let operation = {
            let latest = self.latest.lock().map_err(|_| Error::StateUnknown)?;
            latest.as_ref().map(|value| data::Operation {
                operation_id: value.operation_id.clone(), owner_generation: value.owner_generation.clone(),
                status_revision: value.status_revision, state: value.state, settlement: value.settlement,
            })
        }; // Same lock order as status: latest is released BEFORE publication.
        let request_state = self.observed_request_state(operation.is_some());
        let history = self.publication.lock().map_err(|_| Error::StateUnknown)?;
        let history_available = !history.failed && operation.as_ref()
            .is_some_and(|value| history.acknowledged == Some(value.status_revision));
        let row = data::Request {
            request_id: self.input.request_id.clone(),
            expected_observation_revision: self.input.expected_observation_revision,
            progress: data::Progress::LocalCheck { request_state }, operation, history_available,
        };
        row.validate().map_err(|_| Error::StateUnknown)?;
        Ok(row)
    }
    pub(crate) fn status(&self) -> Result<Status, Error> {
        self.occupies();
        let operation = self.latest.lock().map_err(|_| Error::StateUnknown)?.clone();
        let request_state = self.observed_request_state(operation.is_some());
        let history = self.publication.lock().map_err(|_| Error::StateUnknown)?;
        let history_available = operation
            .as_ref()
            .is_some_and(|op| history.acknowledged == Some(op.status_revision))
            && !history.failed;
        let status = Status {
            origin: self.input.query(),
            expected_observation_revision: self.input.expected_observation_revision,
            request_state,
            operation,
            history_available,
            do_not_replay: true,
        };
        status.validate()?;
        Ok(status)
    }
    /// The only production caller is the private SAME SavedCommandOwner child,
    /// before its Prepared publication. A failed bind is never a no-entry ACK.
    pub(crate) fn bind(
        self: &Arc<Self>,
        operation: Id,
        generation: Id,
        revision: u32,
    ) -> Result<Arc<NativeLink>, Error> {
        if !self.admission_live() {
            return Err(Error::AccessDenied);
        }
        let identity = Arc::new(());
        let original = Original {
            operation: operation.clone(),
            generation: generation.clone(),
            identity: Arc::downgrade(&identity),
        };
        if self.original.set(original).is_err() {
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        let link = Arc::new(NativeLink {
            entry: self.clone(),
            identity,
        });
        let data = Operation {
            operation_id: operation,
            owner_generation: generation,
            status_revision: revision,
            state: OperationState::Prepared,
            settlement: Settlement::Pending,
            outcome: None,
            reason: Reason::None,
            result: None,
        };
        if link.publish(data).is_err() {
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        self.phase.store(BOUND, Ordering::Release);
        Ok(link)
    }
    pub(crate) fn claim_history(&self) -> Result<Option<(bool, Operation)>, Error> {
        let latest = self.latest.lock().map_err(|_| Error::StateUnknown)?.clone();
        let Some(latest) = latest else {
            return Ok(None);
        };
        let mut p = self.publication.lock().map_err(|_| Error::StateUnknown)?;
        if p.failed {
            return Ok(None);
        }
        if p.claim.is_some() {
            return Err(Error::StateUnknown);
        }
        if p.acknowledged == Some(latest.status_revision) {
            return Ok(None);
        }
        let first = p.acknowledged.is_none();
        p.claim = Some(latest.clone());
        Ok(Some((first, latest)))
    }
    pub(crate) fn history_returned(
        &self,
        revision: u32,
        result: Result<(), Error>,
    ) -> Result<(), Error> {
        let mut p = self.publication.lock().map_err(|_| Error::StateUnknown)?;
        if p.claim
            .as_ref()
            .is_none_or(|c| c.status_revision != revision)
        {
            p.failed = true;
            return Err(Error::StateUnknown);
        }
        if let Err(error) = result {
            p.failed = true;
            return Err(error);
        }
        p.claim = None;
        p.acknowledged = Some(revision);
        Ok(())
    }
}
/// Retained by the actual Prepared, then SAME Session. The inbox holds only a
/// weak comparison identity; dropping a link cannot manufacture settlement.
pub(crate) struct NativeLink {
    entry: Arc<Entry>,
    identity: Arc<()>,
}
impl NativeLink {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn origin(&self) -> Query {
        self.entry.input.query()
    }
    pub(crate) fn expires(&self) -> Instant {
        self.entry.lease.expires
    }
    pub(crate) fn attach_stop(&self, stop: &tokio::sync::watch::Sender<bool>) -> Result<(), Error> {
        self.entry
            .native_stop
            .set(stop.clone())
            .map_err(|_| Error::StateUnknown)?;
        if self.entry.stop_at(Instant::now()).is_some() {
            self.entry.signal();
        }
        Ok(())
    }
    pub(crate) fn matches(&self, operation: &str, generation: &str) -> bool {
        self.entry.original.get().is_some_and(|o| {
            o.operation.as_str() == operation
                && o.generation.as_str() == generation
                && o.identity.as_ptr() == Arc::as_ptr(&self.identity)
        })
    }
    pub(crate) fn start_matches(&self, entry: Option<&Arc<Entry>>) -> bool {
        entry.is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
            && self.entry.phase.load(Ordering::Acquire) == BOUND
            && self.entry.stop_at(Instant::now()).is_none()
    }
    pub(crate) fn publish(&self, data: Operation) -> Result<(), Error> {
        if !data.valid()
            || !self.matches(data.operation_id.as_str(), data.owner_generation.as_str())
            || data
                .result
                .as_ref()
                .is_some_and(|r| r.used_config != self.entry.scope().config)
        {
            return Err(Error::StateUnknown);
        }
        let mut latest = self.entry.latest.lock().map_err(|_| Error::StateUnknown)?;
        if let Some(old) = latest.as_ref() {
            if old.settlement == Settlement::Unknown || *old == data {
                return Ok(());
            }
            if data.status_revision < old.status_revision
                || data.status_revision == old.status_revision && *old != data
                || old.settlement == Settlement::Settled && *old != data
            {
                return Err(Error::StateUnknown);
            }
        }
        // A returned native retirement may resolve a lost admission ACK. It
        // never clears a NATIVE Unknown (the absorbing check is above).
        if data.settlement == Settlement::Settled {
            self.entry.phase.store(BOUND, Ordering::Release);
        }
        *latest = Some(data);
        self.entry.scope().changes.send_modify(|_| {});
        Ok(())
    }
}

pub(crate) struct Claim {
    entry: Arc<Entry>,
    returned: bool,
}
impl Claim {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn returned(mut self, result: bool) {
        self.returned = true;
        if result && self.entry.original.get().is_some() {
            return;
        }
        if self.entry.original.get().is_none() && !result {
            self.entry.refused();
        } else if self.entry.latest.lock().is_ok_and(|v| {
            v.as_ref()
                .is_some_and(|p| p.settlement == Settlement::Settled)
        }) {
            // The SAME original already published its genuine no-start/final
            // retirement. A returned start refusal need not invent unknown.
            self.entry.phase.store(BOUND, Ordering::Release);
        } else {
            self.entry.unconfirmed();
        }
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unconfirmed();
        }
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Access {
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    pub(crate) project_id: Option<Id>,
    pub(crate) observation_revision: Option<u64>,
    pub(crate) consumed: bool,
}
struct Book {
    lease: Option<Arc<Lease>>,
    entries: Vec<Arc<Entry>>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: Arc<AtomicBool>,
}
impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                lease: None,
                entries: Vec::with_capacity(LIMIT),
                closed: false,
            }),
            failed: Arc::new(AtomicBool::new(false)),
        }
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Book>, Error> {
        self.book.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    pub(crate) fn allow(&self, scope: Arc<NativeScope>) -> Result<Access, Error> {
        if !scope.valid() {
            return Err(Error::InvalidRequest);
        }
        let mut b = self.lock()?;
        if b.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        if b.entries.iter().any(|e| e.occupies()) {
            return Err(Error::Busy);
        }
        let now = Instant::now();
        if let Some(old) = &b.lease {
            let _ = old.revoked.set(now);
        }
        b.lease = Some(Arc::new(Lease {
            scope,
            expires: now + LIFETIME,
            revoked: OnceLock::new(),
            used: AtomicBool::new(false),
            failed: self.failed.clone(),
        }));
        Ok(access(&b))
    }
    pub(crate) fn access(&self) -> Result<Access, Error> {
        let b = self.lock()?;
        Ok(access(&b))
    }
    pub(crate) fn revoke(&self) -> Result<Access, Error> {
        // Poison remains a veto, but cleanup never skips the original signal.
        let b = match self.book.lock() {
            Ok(b) => b,
            Err(e) => {
                self.failed.store(true, Ordering::Release);
                e.into_inner()
            }
        };
        if let Some(lease) = &b.lease {
            let _ = lease.revoked.set(Instant::now());
            lease.scope.changes.send_modify(|_| {});
        }
        for entry in &b.entries {
            entry.signal();
        }
        if self.failed.load(Ordering::Acquire) {
            Err(Error::StateUnknown)
        } else {
            Ok(access(&b))
        }
    }
    pub(crate) fn close(&self) {
        let _ = self.revoke();
        if let Ok(mut b) = self.lock() {
            b.closed = true;
        }
    }
    pub(crate) fn submit(&self, input: Submit, point: &SavedPoint) -> Result<Status, Error> {
        input.validate()?;
        let mut b = self.lock()?;
        if input.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(old) = b
            .entries
            .iter()
            .find(|e| e.input.request_id == input.request_id)
        {
            return if old.input == input {
                old.status()
            } else {
                Err(Error::Conflict)
            };
        }
        if b.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        if b.entries.len() == LIMIT || b.entries.iter().any(|e| e.occupies()) {
            return Err(Error::Busy);
        }
        let lease = b.lease.as_ref().ok_or(Error::AccessDenied)?.clone();
        if lease.stop_at(Instant::now()).is_some() {
            return Err(Error::Expired);
        }
        if lease.used.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        if input.project_id != lease.scope.project_id
            || input.expected_observation_revision != lease.scope.observation_revision
            || !point.matches(&lease.scope)
        {
            return Err(Error::Conflict);
        }
        let entry = Arc::new(Entry {
            input,
            lease: lease.clone(),
            phase: AtomicU8::new(QUEUED),
            original: OnceLock::new(),
            cancelled: OnceLock::new(),
            native_stop: OnceLock::new(),
            latest: Mutex::new(None),
            publication: Mutex::new(Publication {
                acknowledged: None,
                claim: None,
                failed: false,
            }),
        });
        b.entries.push(entry.clone());
        lease.used.store(true, Ordering::Release);
        lease.scope.changes.send_modify(|_| {});
        entry.status()
    }
    pub(crate) fn query(&self, q: &Query, cancel: bool) -> Result<Status, Error> {
        let b = self.lock()?;
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        let e = b
            .entries
            .iter()
            .find(|e| e.input.request_id == q.request_id && e.input.project_id == q.project_id)
            .ok_or(Error::Conflict)?;
        if cancel {
            e.cancel()
        }
        e.status()
    }
    pub(crate) fn claim(&self) -> Result<Option<Claim>, Error> {
        let b = self.lock()?;
        if b.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        for e in &b.entries {
            e.occupies();
            if e.phase
                .compare_exchange(QUEUED, ADMITTING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Some(Claim {
                    entry: e.clone(),
                    returned: false,
                }));
            }
        }
        Ok(None)
    }
    pub(crate) fn entries(&self) -> Result<Vec<Arc<Entry>>, Error> {
        Ok(self.lock()?.entries.clone())
    }
}
fn access(b: &Book) -> Access {
    let now = Instant::now();
    let lease = b.lease.as_ref();
    let consumed = lease.is_some_and(|l| l.used.load(Ordering::Acquire));
    let enabled = !b.closed && lease.is_some_and(|l| l.stop_at(now).is_none()) && !consumed;
    Access {
        enabled,
        remaining_ms: lease.filter(|_| enabled).map_or(0, |l| {
            l.expires
                .saturating_duration_since(now)
                .as_millis()
                .min(u64::MAX as u128) as u64
        }),
        project_id: lease.map(|l| l.scope.project_id.clone()),
        observation_revision: lease.map(|l| l.scope.observation_revision),
        consumed,
    }
}

#[cfg(test)]
#[path = "agent_local_checks_tests.rs"]
mod tests;
