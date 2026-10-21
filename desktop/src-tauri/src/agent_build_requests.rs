//! One finite memory inbox for two CLOSED build families. It does not execute,
//! deserialize authority, own a runner or turn projections into native finality.
//! The family is checked at every native admission and client query boundary.
use crate::{
    agent_android_build as android, agent_ios_archive as ios,
    agent_local_checks::Config,
    service_protocol::{Error, Id, OperationState, Settlement},
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};
#[path = "agent_build_permission.rs"]
mod permission;
pub(crate) use permission::{permission_next, permission_revision, MainAccess};

pub const LIMIT: usize = 32;
pub const START_WINDOW: Duration = Duration::from_secs(900);
// ONE shared32-row allocation (not32 per family). The full terminal report is
// immutable and shared by latest/history; an older distinct claim has no
// report. No tombstone, failed claim or native resource graph is discarded.
const ROW_BACKING: usize = 16 * 1024;
const ANCILLARY_BACKING: usize = 64 * 1024;
pub(crate) const STATUS_HEAP_BYTES: usize = 8 * 1024;
// Keep original native/incoming reports, compacting overlap and one off-IPC
// history DTO here. The original endpoint's eight IPC copies/encoders are
// covered by its shared peak, not eight independent workers per family.
pub(crate) const DOCUMENT_BACKING: usize =
    LIMIT * ROW_BACKING + ANCILLARY_BACKING + 4 * android::REPORT_LIMIT;
const ID_HEAP_BYTES: usize = 64;
const ROOT_HEAP_BYTES: usize = 4096;
// Same closed nine-entry enum/u32 map as the original report. Freshly rebuild
// it; at most nine std nodes, each bounded by512 for the pinned11/12-slot tree.
const SUMMARY_HEAP_BYTES: usize = 9 * 512;

fn compact_string(value: &mut String) {
    *value = std::mem::take(value).into_boxed_str().into_string();
}
fn compact_version(value: &mut android::Version) {
    compact_string(&mut value.sha256);
    compact_string(&mut value.name);
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    AndroidInspect,
    IosArchive,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Review {
    Android(android::Review),
    Ios(ios::Review),
    IosRecovery(ios::recovery::Review),
}
impl Review {
    pub(crate) fn family(&self) -> Family {
        match self {
            Self::Android(_) => Family::AndroidInspect,
            Self::Ios(_) | Self::IosRecovery(_) => Family::IosArchive,
        }
    }
    fn valid(&self) -> bool {
        match self {
            Self::Android(v) => v.valid(),
            Self::Ios(v) => v.valid(),
            Self::IosRecovery(v) => v.valid(),
        }
    }
    fn capacity_valid(&self) -> bool {
        let saved = |config: &Config, version: &android::Version| config.sha256.capacity() <= 64
            && version.sha256.capacity() <= 64 && version.name.capacity() <= 64;
        match self {
            Self::Android(v) => saved(&v.saved_config, &v.saved_version) && v.tools.record_sha256.capacity() <= 64
                && v.tools.instance.retained_bytes() <= ID_HEAP_BYTES
                && v.signing.as_ref().is_none_or(android::signed::Selection::capacity_valid)
                && v.upload_certificate_sha256.as_ref().is_none_or(|s| s.capacity() <= 64),
            Self::Ios(v) => saved(&v.saved_config, &v.saved_version) && v.signing.as_ref().is_none_or(ios::signed::Review::capacity_valid),
            Self::IosRecovery(v) => v.capacity_valid(),
        }
    }
    pub(crate) fn requires_original_read(&self) -> bool {
        match self {
            Self::Android(r) => r.mode == android::Mode::SavedAndroidLocalUploadKeySign,
            Self::Ios(r) => r.mode == ios::Mode::SavedIosSignedExport,
            Self::IosRecovery(_) => true,
        }
    }
    fn saved_config(&self) -> Option<&Config> {
        match self { Self::Android(v) => Some(&v.saved_config), Self::Ios(v) => Some(&v.saved_config), Self::IosRecovery(_) => None }
    }
    pub(crate) fn ios_recovery(&self) -> Option<&ios::recovery::Review> {
        if let Self::IosRecovery(v) = self { Some(v) } else { None }
    }
    pub(crate) fn android(&self) -> Option<&android::Review> {
        if let Self::Android(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn ios(&self) -> Option<&ios::Review> {
        if let Self::Ios(v) = self {
            Some(v)
        } else {
            None
        }
    }
}
impl From<android::Review> for Review {
    fn from(v: android::Review) -> Self {
        Self::Android(v)
    }
}
impl From<ios::Review> for Review {
    fn from(v: ios::Review) -> Self {
        Self::Ios(v)
    }
}
impl From<ios::recovery::Review> for Review { fn from(v: ios::recovery::Review) -> Self { Self::IosRecovery(v) } }
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Android(android::Operation),
    Ios(ios::Operation),
    IosRecovery(ios::recovery::Operation),
}
impl Operation {
    pub(crate) fn family(&self) -> Family {
        match self {
            Self::Android(_) => Family::AndroidInspect,
            Self::Ios(_) | Self::IosRecovery(_) => Family::IosArchive,
        }
    }
    pub(crate) fn operation_id(&self) -> &Id {
        match self {
            Self::Android(v) => &v.operation_id,
            Self::Ios(v) => &v.operation_id,
            Self::IosRecovery(v) => &v.operation_id,
        }
    }
    pub(crate) fn owner_generation(&self) -> &Id {
        match self {
            Self::Android(v) => &v.owner_generation,
            Self::Ios(v) => &v.owner_generation,
            Self::IosRecovery(v) => &v.owner_generation,
        }
    }
    pub(crate) fn status_revision(&self) -> u32 {
        match self {
            Self::Android(v) => v.status_revision,
            Self::Ios(v) => v.status_revision,
            Self::IosRecovery(v) => v.status_revision,
        }
    }
    pub(crate) fn state(&self) -> OperationState {
        match self {
            Self::Android(v) => v.state.clone(),
            Self::Ios(v) => v.state.clone(),
            Self::IosRecovery(v) => v.state.clone(),
        }
    }
    pub(crate) fn settlement(&self) -> Settlement {
        match self {
            Self::Android(v) => v.settlement.clone(),
            Self::Ios(v) => v.settlement.clone(),
            Self::IosRecovery(v) => v.settlement.clone(),
        }
    }
    fn valid_for(&self, review: &Review) -> bool {
        match (self, review) {
            (Self::Android(o), Review::Android(r)) => o.valid_for(r),
            (Self::Ios(o), Review::Ios(r)) => o.valid_for(r),
            (Self::IosRecovery(o), Review::IosRecovery(r)) => o.valid_for(r),
            _ => false,
        }
    }
    fn heap_bytes(&self) -> Option<usize> {
        let mut n = self.operation_id().retained_bytes()
            .checked_add(self.owner_generation().retained_bytes())?;
        match self {
            Self::Android(o) => if let Some(r) = &o.result {
                n = n.checked_add(r.used_config.sha256.capacity())?
                    .checked_add(r.used_version.sha256.capacity())?
                    .checked_add(r.used_version.name.capacity())?
                    .checked_add(r.artifact.sha256.capacity())?
                    .checked_add(r.findings.capacity().checked_mul(std::mem::size_of::<android::Finding>())?)?
                    .checked_add(SUMMARY_HEAP_BYTES)?;
                if let Some(s) = &r.signing { n = n.checked_add(s.upload_certificate_sha256.capacity())?; }
            },
            Self::Ios(o) => if let Some(r) = &o.result {
                n = n.checked_add(r.used_config.sha256.capacity())?
                    .checked_add(r.used_version.sha256.capacity())?
                    .checked_add(r.used_version.name.capacity())?;
            },
            Self::IosRecovery(o) => if let Some(r) = &o.report { n = n.checked_add(r.heap_bytes()?)?; },
        }
        Some(n)
    }
    fn compact(mut self) -> Result<Self, Error> {
        let report_limit = match self.family() {
            Family::AndroidInspect => android::REPORT_LIMIT,
            Family::IosArchive => ios::REPORT_LIMIT,
        };
        if self.operation_id().retained_bytes() > ID_HEAP_BYTES
            || self.owner_generation().retained_bytes() > ID_HEAP_BYTES
            || self.heap_bytes().is_none_or(|n| n > report_limit)
        {
            return Err(Error::StateUnknown);
        }
        match &mut self {
            Self::Android(o) => if let Some(r) = &mut o.result {
                compact_string(&mut r.used_config.sha256);
                compact_version(&mut r.used_version);
                compact_string(&mut r.artifact.sha256);
                if let Some(s) = &mut r.signing { compact_string(&mut s.upload_certificate_sha256); }
                r.findings = std::mem::take(&mut r.findings).into_boxed_slice().into_vec();
                r.summary.counts = std::mem::take(&mut r.summary.counts).into_iter().collect();
            },
            Self::Ios(o) => if let Some(r) = &mut o.result {
                compact_string(&mut r.used_config.sha256);
                compact_version(&mut r.used_version);
            },
            Self::IosRecovery(o) => if let Some(r) = &mut o.report { r.compact(); },
        }
        // Three Query IDs and the exact closed Review (including signing) coexist
        // with the public operation. Inline enums/DTOs are charged separately.
        if self.heap_bytes().is_none_or(|n| n > OPERATION_HEAP_CEILING)
            || self.heap_bytes().and_then(|n| n.checked_add(3 * ID_HEAP_BYTES + REVIEW_HEAP_CEILING))
            .is_none_or(|n| n > STATUS_HEAP_BYTES)
        {
            return Err(Error::StateUnknown);
        }
        Ok(self)
    }
    #[cfg(test)]
    pub(crate) fn android(&self) -> &android::Operation {
        match self {
            Self::Android(v) => v,
            _ => panic!("wrong fixed test family"),
        }
    }
    fn prepared(review: &Review, operation: Id, generation: Id, revision: u32) -> Self {
        match review {
            Review::Android(_) => Self::Android(android::Operation {
                operation_id: operation,
                owner_generation: generation,
                status_revision: revision,
                state: OperationState::Prepared,
                settlement: Settlement::Pending,
                outcome: None,
                reason: android::Reason::None,
                stage: None,
                disposition: None,
                result: None,
            }),
            Review::Ios(_) => Self::Ios(ios::Operation {
                operation_id: operation,
                owner_generation: generation,
                status_revision: revision,
                state: OperationState::Prepared,
                settlement: Settlement::Pending,
                outcome: None,
                reason: ios::Reason::None,
                stage: None,
                disposition: None,
                result: None,
            }),
            Review::IosRecovery(_) => Self::IosRecovery(ios::recovery::Operation {
                operation_id: operation, owner_generation: generation, status_revision: revision,
                state: OperationState::Prepared, settlement: Settlement::Pending, outcome: None,
                reason: ios::recovery::Reason::None, stage: None, report: None,
            }),
        }
    }
}
impl From<android::Operation> for Operation {
    fn from(v: android::Operation) -> Self {
        Self::Android(v)
    }
}
impl From<ios::Operation> for Operation {
    fn from(v: ios::Operation) -> Self {
        Self::Ios(v)
    }
}
impl From<ios::recovery::Operation> for Operation { fn from(v: ios::recovery::Operation) -> Self { Self::IosRecovery(v) } }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub service_instance: Id,
    pub project_id: Id,
    pub request_id: Id,
    pub expected_observation_revision: u64,
}
impl Prepare {
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
/// Closed family tag retained through SAME original native projection. Public
/// Query remains wire-compatible; a mapper must explicitly unwrap its family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    Android(Query),
    Ios(Query),
}
impl Origin {
    pub(crate) fn for_family(self, family: Family) -> Result<Query, Error> {
        match (self, family) {
            (Self::Android(q), Family::AndroidInspect) | (Self::Ios(q), Family::IosArchive) => {
                Ok(q)
            }
            _ => Err(Error::StateUnknown),
        }
    }
}
/// Native-only origin marker in the GUI projection. It never grants Start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub service_instance: Id,
    pub project_id: Id,
    pub request_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Start {
    pub origin: Query,
    pub operation_id: Id,
    pub owner_generation: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequestState {
    Queued,
    Preparing,
    OriginalAvailable,
    RefusedBeforePreparation,
    CancelledBeforePreparation,
    Expired,
    AdmissionUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartState {
    NotRequested,
    Queued,
    Admitting,
    Consumed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) origin: Query,
    pub(crate) expected_observation_revision: u64,
    pub(crate) request_state: RequestState,
    pub(crate) start_state: StartState,
    pub(crate) review: Review,
    pub(crate) operation: Option<Operation>,
    pub(crate) history_available: bool,
    pub(crate) do_not_replay: bool,
}
impl Snapshot {
    fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0
            || !self.do_not_replay
            || !self.review.valid()
            || self
                .operation
                .as_ref()
                .is_some_and(|o| !o.valid_for(&self.review))
            || self.history_available && self.operation.is_none()
            || self.request_state == RequestState::OriginalAvailable && self.operation.is_none()
            || self.start_state != StartState::NotRequested && self.operation.is_none()
                && self.request_state != RequestState::AdmissionUnknown
        {
            Err(Error::StateUnknown)
        } else {
            Ok(())
        }
    }
}
/// Configless recovery is a closed source, not absent saved-data wildcards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeInput { Saved { draft_revision: u32, baseline_generation: u32 }, Recovery }
/// Native constructor input only. CLI deserialization never constructs this.
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
    pub(crate) review: Review,
    pub(crate) read: Option<Arc<crate::service_version_reserve_requests::ReadPermission>>,
    pub(crate) input: NativeInput,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
}
impl NativeScope {
    fn valid(&self) -> bool {
        self.review.valid()
            && self.review.capacity_valid()
            && self.read.is_some() == self.review.requires_original_read()
            && self.read.as_ref().is_none_or(|r| matches!(r.stop(Instant::now()), Ok(None)))
            && self.observation_revision != 0
            && self.inode != 0
            && self.registration != 0
            && self.input_revision != u64::MAX
            && self.document.strong_count() != 0
            && match (&self.input, &self.review) {
                (NativeInput::Recovery, Review::IosRecovery(_)) => true,
                (NativeInput::Saved { draft_revision, baseline_generation }, Review::Android(_) | Review::Ios(_)) =>
                    *draft_revision < u32::MAX && *baseline_generation < u32::MAX,
                _ => false,
            }
            && (1..=64).contains(&self.runtime_id.len())
            && self.project_id.retained_bytes() <= ID_HEAP_BYTES
            && self.runtime_id.capacity() <= 64
            && self.root.is_absolute()
            && self.root.as_os_str().len() <= 4096
            && self.root.capacity() <= ROOT_HEAP_BYTES
    }
    pub(crate) fn saved_inputs(&self) -> Option<(u32, u32)> {
        match self.input { NativeInput::Saved { draft_revision, baseline_generation } => Some((draft_revision, baseline_generation)), NativeInput::Recovery => None }
    }
    pub(crate) fn matches_read(&self, read: &Arc<crate::service_version_reserve_requests::ReadPermission>) -> bool {
        match &self.read {
            Some(original) => Arc::ptr_eq(original, read) && matches!(original.stop(Instant::now()), Ok(None)),
            None => !self.review.requires_original_read(),
        }
    }
    pub(crate) fn matches(&self, point: &crate::agent_local_checks::SavedPoint) -> bool {
        self.project_id == point.project_id
            && self.runtime_id == point.runtime_id
            && self.root == point.root
            && self.device == point.device
            && self.inode == point.inode
            && self.observation_revision == point.revision
            && point.fresh
            && match (&self.input, &self.review) {
                (NativeInput::Recovery, Review::IosRecovery(_)) => true,
                (NativeInput::Saved { .. }, Review::Android(_) | Review::Ios(_)) => point.config.as_ref() == self.review.saved_config(),
                _ => false,
            }
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
    fn stop_at(&self, now: Instant, consumed: bool) -> Option<Instant> {
        let mut at = self.revoked.get().copied();
        if let Some(read) = &self.scope.read {
            match read.stop(now) {
                Ok(Some((_, stop))) => at = Some(at.map_or(stop, |v| v.min(stop))),
                Ok(None) => {},
                Err(_) => at = Some(at.unwrap_or(now)),
            }
        }
        if !consumed && now >= self.expires {
            at = Some(at.map_or(self.expires, |old| old.min(self.expires)));
        }
        if self.failed.load(Ordering::Acquire) || self.scope.document.strong_count() == 0 {
            at = Some(at.unwrap_or(now));
        }
        at
    }
}
const QUEUED: u8 = 0;
const PREPARING: u8 = 1;
const BOUND: u8 = 2;
const REFUSED: u8 = 3;
const CANCELLED: u8 = 4;
const EXPIRED: u8 = 5;
const UNKNOWN: u8 = 6;
const NO_START: u8 = 0;
const START_QUEUED: u8 = 1;
const START_ADMITTING: u8 = 2;
const START_CONSUMED: u8 = 3;
struct Original {
    operation: Id,
    generation: Id,
    identity: Weak<()>,
    expires: Instant,
}
struct Publication {
    acknowledged: Option<u32>,
    visible: Option<Arc<Operation>>,
    claim: Option<Arc<Operation>>,
    failed: bool,
}
pub(crate) struct Entry {
    input: Prepare,
    lease: Arc<Lease>,
    phase: AtomicU8,
    prepare_returned: AtomicBool,
    start_returned: AtomicBool,
    original: OnceLock<Original>,
    start: AtomicU8,
    start_at: OnceLock<Instant>,
    cancelled: OnceLock<Instant>,
    native_stop: OnceLock<tokio::sync::watch::Sender<bool>>,
    latest: Mutex<Option<Arc<Operation>>>,
    publication: Mutex<Publication>,
}
// Include three scalar operation cells but only one full terminal report graph.
// Actual monotone publish rejects every changed successor of a terminal value.
// Scope capacities are checked BEFORE Allow; compact report/public DTO bounds
// include all hashes/IDs/version text and the freshly rebuilt nine-entry map.
const REVIEW_HEAP_CEILING: usize = 5 * ID_HEAP_BYTES + android::signed::SELECTION_HEAP + 64;
const SCOPE_HEAP_CEILING: usize = ROOT_HEAP_BYTES + 2 * ID_HEAP_BYTES
    + REVIEW_HEAP_CEILING;
// One retained terminal payload, not a second copy of the complete public
// Status (whose query IDs and Review are already charged in Scope/Entry).
const OPERATION_HEAP_CEILING: usize = 2 * ID_HEAP_BYTES + 5 * 64
    + 128 * std::mem::size_of::<android::Finding>() + SUMMARY_HEAP_BYTES;
const PUBLIC_HEAP_CEILING: usize = 3 * ID_HEAP_BYTES + REVIEW_HEAP_CEILING
    + OPERATION_HEAP_CEILING;
// Each genuine current signing approval/pin is capacity-checked in its native
// child. Conservatively allow all four ancillary holders for BOTH platforms.
pub(crate) const SIGNED_BINDING_BYTES: usize = 2 * 1024;
pub(crate) const RECOVERY_BINDING_BYTES: usize = 1024;
const SIGNED_BINDINGS_BACKING: usize = 4 * (SIGNED_BINDING_BYTES + SIGNED_BINDING_BYTES);
// The nine standalone ID heaps are Prepare3 + Original2 + the two extra
// nonterminal Operation cells2*2. The remaining Operation's IDs/report are in
// OPERATION_HEAP_CEILING; Scope/Review heaps are counted separately in full.
const ROW_CEILING: usize = std::mem::size_of::<Entry>()
    + std::mem::size_of::<Lease>() + std::mem::size_of::<NativeScope>()
    + 3 * std::mem::size_of::<Operation>() + std::mem::size_of::<NativeLink>()
    + std::mem::size_of::<crate::service_version_reserve_requests::ReadPermission>()
    + 10 * 2 * std::mem::size_of::<usize>() + 2 * 512 + 9 * ID_HEAP_BYTES
    + SCOPE_HEAP_CEILING + OPERATION_HEAP_CEILING;
const ANCILLARY_CEILING: usize = std::mem::size_of::<Inbox>()
    + std::mem::size_of::<Book>() + 2 * LIMIT * std::mem::size_of::<Arc<Entry>>()
    + 4 * (std::mem::size_of::<Lease>() + std::mem::size_of::<NativeScope>()
        + SCOPE_HEAP_CEILING + 512)
    + 8 * (std::mem::size_of::<MainAccess>() + ID_HEAP_BYTES + 32) + 4096
    + SIGNED_BINDINGS_BACKING
    + 4 * RECOVERY_BINDING_BYTES
    + 8 * (std::mem::size_of::<ios::recovery::AcknowledgedInspection>() + 5 * ID_HEAP_BYTES);
const _: () = {
    assert!(3 * 32 <= REVIEW_HEAP_CEILING); // exact recovery session + displayed pair
    assert!(2 * ID_HEAP_BYTES + 2 * 32 <= OPERATION_HEAP_CEILING);
    assert!(PUBLIC_HEAP_CEILING <= STATUS_HEAP_BYTES);
    assert!(ROW_CEILING <= ROW_BACKING);
    assert!(ANCILLARY_CEILING <= ANCILLARY_BACKING);
};
impl Entry {
    pub(crate) fn family(&self) -> Family {
        self.scope().review.family()
    }
    pub(crate) fn scope(&self) -> &NativeScope {
        &self.lease.scope
    }
    pub(crate) fn input(&self) -> &Prepare {
        &self.input
    }
    pub(crate) fn start_at(&self) -> Option<Instant> {
        self.start_at.get().copied()
    }
    pub(crate) fn start_deadline(&self) -> Instant {
        self.original
            .get()
            .map_or(self.lease.expires, |o| o.expires.min(self.lease.expires))
    }
    pub(crate) fn read_end(&self) -> Option<Instant> { self.scope().read.as_ref().map(|r| r.end()) }
    pub(crate) fn read_stop(&self, now: Instant) -> Result<Option<Instant>, Error> {
        match &self.scope().read {
            Some(read) => read.stop(now).map(|v| v.map(|(_, at)| at)),
            None if !self.scope().review.requires_original_read() => Ok(None),
            None => Err(Error::StateUnknown),
        }
    }
    pub(crate) fn control_poll(&self) -> Option<Duration> {
        (self.scope().read.is_some() || self.scope().review.requires_original_read())
            .then_some(Duration::from_millis(5))
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Option<Instant> {
        let consumed = self.start.load(Ordering::Acquire) == START_CONSUMED;
        let mut at = self.lease.stop_at(now, consumed);
        match self.read_stop(now) {
            Ok(Some(read_at)) => at = Some(at.map_or(read_at, |v| v.min(read_at))),
            Ok(None) => {},
            Err(_) => { self.unconfirmed(); at = Some(at.unwrap_or(now)); },
        }
        if !consumed && now >= self.start_deadline() {
            at = Some(at.map_or(self.start_deadline(), |v| v.min(self.start_deadline())));
        }
        if let Some(cancelled) = self.cancelled.get() {
            at = Some(at.map_or(*cancelled, |v| v.min(*cancelled)));
        }
        at
    }
    pub(crate) fn prepare_live(&self) -> bool {
        self.phase.load(Ordering::Acquire) == PREPARING && self.stop_at(Instant::now()).is_none()
    }
    pub(crate) fn start_live(&self) -> bool {
        self.phase.load(Ordering::Acquire) == BOUND
            && self.start.load(Ordering::Acquire) == START_ADMITTING
            && self.start_at.get().is_some()
            && self.stop_at(Instant::now()).is_none()
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
    pub(crate) fn unconfirmed(&self) {
        self.phase.store(UNKNOWN, Ordering::Release);
        self.cancel();
    }
    fn callers_returned(&self) -> bool {
        self.prepare_returned.load(Ordering::Acquire)
            && (self.start.load(Ordering::Acquire) == NO_START
                || self.start_returned.load(Ordering::Acquire))
    }
    fn occupies(&self) -> bool {
        if self.phase.load(Ordering::Acquire) == QUEUED && self.stop_at(Instant::now()).is_some() {
            let _ = self.phase.compare_exchange(QUEUED, EXPIRED, Ordering::AcqRel, Ordering::Acquire);
        }
        match self.phase.load(Ordering::Acquire) {
            QUEUED | PREPARING | UNKNOWN => true,
            BOUND => {
                // Native retirement alone never releases a retained relay
                // Claim, nor a pending/failed original history write.
                let latest = match self.latest.lock() {
                    Ok(v) => v.clone(), Err(_) => return true,
                };
                let Some(latest) = latest else { return true; };
                let acknowledged = self.publication.lock().is_ok_and(|p| {
                    !p.failed && p.claim.is_none() && p.visible.as_ref()
                        .is_some_and(|v| Arc::ptr_eq(v, &latest))
                });
                latest.settlement() != Settlement::Settled || !acknowledged
                    || !self.callers_returned() || self.phase.load(Ordering::Acquire) == UNKNOWN
            }
            _ => false,
        }
    }
    /// A known candidate becomes public only after its actual writer ACK.
    /// Uncertainty bypasses that gate immediately and can never expose the
    /// previous Prepared/Complete as current usable authority.
    fn public_operation(&self) -> Result<(Option<Arc<Operation>>, bool, RequestState, StartState), Error> {
        let latest = self.latest.lock().map_err(|_| Error::StateUnknown)?.clone();
        let p = self.publication.lock().map_err(|_| Error::StateUnknown)?;
        let request_state = self.observed_request_state();
        let start_state = self.observed_start_state();
        if p.failed || request_state == RequestState::AdmissionUnknown
            || latest.as_ref().is_some_and(|o| o.settlement() == Settlement::Unknown)
        {
            return Ok((latest.filter(|o| o.settlement() == Settlement::Unknown), false,
                RequestState::AdmissionUnknown, start_state));
        }
        let request_state = if request_state == RequestState::OriginalAvailable && p.visible.is_none() {
            RequestState::Preparing
        } else { request_state };
        Ok((p.visible.clone(), p.visible.is_some(), request_state, start_state))
    }
    fn observed_request_state(&self) -> RequestState {
        let request_state = match self.phase.load(Ordering::Acquire) {
            QUEUED => RequestState::Queued,
            PREPARING => RequestState::Preparing,
            BOUND => RequestState::OriginalAvailable,
            REFUSED => RequestState::RefusedBeforePreparation,
            CANCELLED => RequestState::CancelledBeforePreparation,
            EXPIRED => RequestState::Expired,
            _ => RequestState::AdmissionUnknown,
        };
        request_state
    }
    fn observed_start_state(&self) -> StartState {
        let start_state = match self.start.load(Ordering::Acquire) {
            NO_START => StartState::NotRequested,
            START_QUEUED => StartState::Queued,
            START_ADMITTING => StartState::Admitting,
            _ => StartState::Consumed,
        };
        start_state
    }
    /// Same original metadata, with no Report, Review or tool binding clone.
    pub(crate) fn catalogue_metadata(&self) -> Result<crate::service_request_catalogue::Request, Error> {
        use crate::service_request_catalogue as data;
        self.occupies();
        let (visible, history_available, request_state, start_state) = self.public_operation()?;
        let operation = visible.as_ref().map(|value| data::Operation {
            operation_id: value.operation_id().clone(), owner_generation: value.owner_generation().clone(),
            status_revision: value.status_revision(), state: value.state(), settlement: value.settlement(),
        });
        let progress = match self.family() {
            Family::AndroidInspect => data::Progress::AndroidBuild { request_state, start_state },
            Family::IosArchive => data::Progress::IosArchive { request_state, start_state },
        };
        let row = data::Request {
            request_id: self.input.request_id.clone(),
            expected_observation_revision: self.input.expected_observation_revision,
            progress, operation, history_available,
        };
        row.validate().map_err(|_| Error::StateUnknown)?;
        Ok(row)
    }
    pub(crate) fn status(&self) -> Result<Snapshot, Error> {
        self.occupies();
        let (visible, history_available, request_state, start_state) = self.public_operation()?;
        let operation = visible.as_deref().cloned();
        let result = Snapshot {
            origin: self.input.query(),
            expected_observation_revision: self.input.expected_observation_revision,
            request_state, start_state,
            review: self.scope().review.clone(), history_available, operation, do_not_replay: true,
        };
        result.validate()?;
        Ok(result)
    }
    /// Only the SAME native owner calls this before its Prepared publication.
    pub(crate) fn bind(
        self: &Arc<Self>,
        family: Family,
        operation: Id,
        generation: Id,
        revision: u32,
        expires: Instant,
    ) -> Result<Arc<NativeLink>, Error> {
        if self.family() != family || !self.prepare_live() {
            return Err(Error::AccessDenied);
        }
        let identity = Arc::new(());
        if self
            .original
            .set(Original {
                operation: operation.clone(),
                generation: generation.clone(),
                identity: Arc::downgrade(&identity),
                expires,
            })
            .is_err()
        {
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        let link = Arc::new(NativeLink {
            entry: self.clone(),
            identity,
        });
        let op = Operation::prepared(&self.scope().review, operation, generation, revision);
        if link.publish(op).is_err() {
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        if self.phase.compare_exchange(PREPARING, BOUND, Ordering::AcqRel, Ordering::Acquire).is_err() {
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        Ok(link)
    }
    fn request_start(&self, input: &Start) -> Result<Snapshot, Error> {
        if input.origin != self.input.query()
            || self.original.get().is_none_or(|o| {
                o.operation != input.operation_id || o.generation != input.owner_generation
            })
        {
            return Err(Error::Conflict);
        }
        // Lost ACK/reconnect can only observe this same attempt. Never requeue.
        if self.start.load(Ordering::Acquire) != NO_START {
            return self.status();
        }
        if self.phase.load(Ordering::Acquire) != BOUND
            || self
                .original
                .get()
                .is_none_or(|o| o.identity.strong_count() == 0)
            || self.stop_at(Instant::now()).is_some()
        {
            return Err(Error::Expired);
        }
        {
            let latest = self.latest.lock().map_err(|_| Error::StateUnknown)?.clone();
            let p = self.publication.lock().map_err(|_| Error::StateUnknown)?;
            if !self.prepare_returned.load(Ordering::Acquire) || p.failed
                || latest.as_ref().is_none_or(|v| {
                    v.state() != OperationState::Prepared || v.settlement() != Settlement::Pending
                        || p.visible.as_ref().is_none_or(|a| !Arc::ptr_eq(a, v))
                }) {
                return Err(Error::Conflict);
            }
        }
        let _ = self.start_at.set(Instant::now()); // First original Start T, before relay/Doc/IO; never renewed.
        let _ = self.start.compare_exchange(
            NO_START,
            START_QUEUED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.scope().changes.send_modify(|_| {});
        self.status()
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
            p.failed = true;
            drop(p);
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        if latest.settlement() != Settlement::Unknown
            && (!self.callers_returned() || self.phase.load(Ordering::Acquire) == UNKNOWN)
        { return Ok(None); }
        if p.acknowledged == Some(latest.status_revision()) {
            return Ok(None);
        }
        let first = p.acknowledged.is_none();
        p.claim = Some(latest.clone());
        Ok(Some((first, latest.as_ref().clone())))
    }
    pub(crate) fn history_returned(
        &self,
        revision: u32,
        result: Result<(), Error>,
    ) -> Result<(), Error> {
        let mut p = self.publication.lock().map_err(|_| Error::StateUnknown)?;
        if p.failed || p.claim
            .as_ref()
            .is_none_or(|c| c.status_revision() != revision)
        {
            p.failed = true;
            drop(p);
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        if let Err(e) = result {
            p.failed = true;
            drop(p);
            self.unconfirmed();
            return Err(e);
        }
        p.visible = p.claim.take(); // SAME immutable claim, after actual writer return.
        p.acknowledged = Some(revision);
        drop(p);
        self.scope().changes.send_modify(|_| {});
        Ok(())
    }
    pub(crate) fn history_lost(&self) {
        if let Ok(mut p) = self.publication.lock() { p.failed = true; }
        self.unconfirmed(); // Claim remains retained; loss is never a returned write.
    }
}
/// Original Prepared -> SAME Session. A weak identity disappearing is NEVER
/// finality. No history/cache/status method can construct this native link.
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
    pub(crate) fn projection_origin(&self) -> Origin {
        match self.entry.family() {
            Family::AndroidInspect => Origin::Android(self.origin()),
            Family::IosArchive => Origin::Ios(self.origin()),
        }
    }
    pub(crate) fn matches(&self, operation: &str, generation: &str) -> bool {
        self.entry.original.get().is_some_and(|o| {
            o.operation.as_str() == operation
                && o.generation.as_str() == generation
                && o.identity.as_ptr() == Arc::as_ptr(&self.identity)
        })
    }
    pub(crate) fn start_matches(&self, family: Family, entry: Option<&Arc<Entry>>) -> bool {
        self.entry.family() == family
            && entry.is_some_and(|e| Arc::ptr_eq(e, &self.entry))
            && self.entry.start_live()
    }
    /// Called under the original Registry immediately BEFORE Prepared.take.
    /// Consumes only START authority, not native finality or a GO receipt.
    pub(crate) fn consume_start(&self, family: Family) -> Result<(), Error> {
        if self.entry.family() != family || !self.entry.start_live() {
            return Err(Error::Expired);
        }
        self.entry
            .start
            .compare_exchange(
                START_ADMITTING,
                START_CONSUMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| Error::Conflict)
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
    pub(crate) fn publish(&self, data: impl Into<Operation>) -> Result<(), Error> {
        let data = data.into();
        if !data.valid_for(&self.entry.scope().review)
            || !self.matches(
                data.operation_id().as_str(),
                data.owner_generation().as_str(),
            )
        {
            return Err(Error::StateUnknown);
        }
        let mut latest = self.entry.latest.lock().map_err(|_| Error::StateUnknown)?;
        if let Some(old) = latest.as_ref() {
            if old.settlement() == Settlement::Unknown || old.as_ref() == &data {
                return Ok(());
            }
            if data.status_revision() <= old.status_revision()
                || old.settlement() == Settlement::Settled
            {
                return Err(Error::StateUnknown);
            }
        }
        let data = data.compact()?;
        let unknown = data.settlement() == Settlement::Unknown;
        *latest = Some(Arc::new(data));
        drop(latest);
        if unknown { self.entry.unconfirmed(); }
        // A known late native return cannot heal a lost caller/history cut.
        self.entry.scope().changes.send_modify(|_| {});
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(crate) enum ClaimKind {
    Prepare,
    Start,
}
pub(crate) struct Claim {
    entry: Arc<Entry>,
    kind: ClaimKind,
    returned: bool,
}
impl Claim {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn kind(&self) -> ClaimKind {
        self.kind
    }
    pub(crate) fn returned(mut self, ok: bool) {
        self.returned = true;
        let flag = match self.kind {
            ClaimKind::Prepare => &self.entry.prepare_returned,
            ClaimKind::Start => &self.entry.start_returned,
        };
        if flag.swap(true, Ordering::AcqRel) {
            self.entry.unconfirmed();
            return;
        }
        if self.entry.original.get().is_none() && !ok {
            let _ = self.entry.phase.compare_exchange(PREPARING, REFUSED, Ordering::AcqRel, Ordering::Acquire);
        } else if !(ok && self.entry.original.get().is_some())
            && !self.entry.latest.lock().is_ok_and(|v| v.as_ref()
                .is_some_and(|o| o.settlement() == Settlement::Settled))
        {
            self.entry.unconfirmed();
        }
        self.entry.scope().changes.send_modify(|_| {});
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unconfirmed();
        }
    }
}
#[derive(Clone, Debug, Serialize)]
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
        let family = scope.review.family();
        let mut b = self.lock()?;
        if b.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        if b.entries.len() == LIMIT || b.entries.iter().any(|e| e.occupies()) {
            return Err(Error::Busy);
        }
        let now = Instant::now();
        if let Some(old) = &b.lease {
            let _ = old.revoked.set(now);
        }
        b.lease = Some(Arc::new(Lease {
            scope,
            expires: now + START_WINDOW,
            revoked: OnceLock::new(),
            used: AtomicBool::new(false),
            failed: self.failed.clone(),
        }));
        Ok(access(&b, family))
    }
    pub(crate) fn access(&self, family: Family) -> Result<Access, Error> {
        let b = self.lock()?;
        Ok(access(&b, family))
    }
    pub(crate) fn revoke(&self, family: Family) -> Result<Access, Error> {
        let b = match self.book.lock() {
            Ok(b) => b,
            Err(e) => {
                self.failed.store(true, Ordering::Release);
                e.into_inner()
            }
        };
        if let Some(lease) = b
            .lease
            .as_ref()
            .filter(|l| l.scope.review.family() == family)
        {
            let _ = lease.revoked.set(Instant::now());
            lease.scope.changes.send_modify(|_| {});
        }
        for entry in b.entries.iter().filter(|e| e.family() == family) {
            entry.signal();
        }
        if self.failed.load(Ordering::Acquire) {
            Err(Error::StateUnknown)
        } else {
            Ok(access(&b, family))
        }
    }
    pub(crate) fn close(&self) {
        let _ = self.revoke(Family::AndroidInspect);
        let _ = self.revoke(Family::IosArchive);
        if let Ok(mut b) = self.lock() {
            b.closed = true;
        }
    }
    pub(crate) fn prepare(
        &self,
        family: Family,
        input: Prepare,
        point: &crate::agent_local_checks::SavedPoint,
    ) -> Result<Snapshot, Error> {
        self.prepare_bound_read(family, input, point, None)
    }
    pub(crate) fn prepare_ios_read(&self, input: Prepare, point: &crate::agent_local_checks::SavedPoint,
        read: &Arc<crate::service_version_reserve_requests::ReadPermission>) -> Result<Snapshot, Error> {
        self.prepare_bound_read(Family::IosArchive, input, point, Some(read))
    }
    fn prepare_bound_read(&self, family: Family, input: Prepare, point: &crate::agent_local_checks::SavedPoint,
        read: Option<&Arc<crate::service_version_reserve_requests::ReadPermission>>) -> Result<Snapshot, Error> {
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
            return if old.family() == family && old.input == input {
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
        if lease.stop_at(Instant::now(), false).is_some() {
            return Err(Error::Expired);
        }
        if lease.used.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        if lease.scope.review.family() != family
            || input.project_id != lease.scope.project_id
            || input.expected_observation_revision != lease.scope.observation_revision
            || !lease.scope.matches(point)
            || lease.scope.review.ios_recovery().is_some() && read.is_none_or(|r| !lease.scope.matches_read(r))
        {
            return Err(Error::Conflict);
        }
        let entry = Arc::new(Entry {
            input,
            lease: lease.clone(),
            phase: AtomicU8::new(QUEUED),
            prepare_returned: AtomicBool::new(false),
            start_returned: AtomicBool::new(false),
            original: OnceLock::new(),
            start: AtomicU8::new(NO_START),
            start_at: OnceLock::new(),
            cancelled: OnceLock::new(),
            native_stop: OnceLock::new(),
            latest: Mutex::new(None),
            publication: Mutex::new(Publication {
                acknowledged: None,
                visible: None,
                claim: None,
                failed: false,
            }),
        });
        b.entries.push(entry.clone());
        lease.used.store(true, Ordering::Release);
        lease.scope.changes.send_modify(|_| {});
        entry.status()
    }
    fn find<'a>(&self, family: Family, b: &'a Book, q: &Query) -> Result<&'a Arc<Entry>, Error> {
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        b.entries
            .iter()
            .find(|e| {
                e.family() == family
                    && e.input.request_id == q.request_id
                    && e.input.project_id == q.project_id
            })
            .ok_or(Error::Conflict)
    }
    pub(crate) fn start(&self, family: Family, input: &Start) -> Result<Snapshot, Error> {
        let b = self.lock()?;
        let entry=self.find(family, &b, &input.origin)?;
        if entry.scope().review.ios_recovery().is_some() && entry.start.load(Ordering::Acquire)==NO_START { return Err(Error::AccessDenied); }
        entry.request_start(input)
    }
    pub(crate) fn start_ios_read(&self, input: &Start, point: &crate::agent_local_checks::SavedPoint,
        read: &Arc<crate::service_version_reserve_requests::ReadPermission>) -> Result<Snapshot, Error> {
        let b = self.lock()?;
        let entry = self.find(Family::IosArchive, &b, &input.origin)?;
        // Already-submitted IDs only observe their ORIGINAL. Own consume made
        // the point stale and must not be mistaken for permission to requeue.
        if entry.scope().review.ios_recovery().is_some() && entry.start.load(Ordering::Acquire) == NO_START
            && (!entry.scope().matches(point) || !entry.scope().matches_read(read)) { return Err(Error::Conflict); }
        entry.request_start(input)
    }
    pub(crate) fn query(
        &self,
        family: Family,
        query: &Query,
        cancel: bool,
    ) -> Result<Snapshot, Error> {
        let b = self.lock()?;
        let e = self.find(family, &b, query)?;
        if cancel {
            e.cancel();
        }
        e.status()
    }
    pub(crate) fn claim(&self, family: Family) -> Result<Option<Claim>, Error> {
        let b = self.lock()?;
        if b.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        for e in b.entries.iter().filter(|e| e.family() == family) {
            e.occupies();
            let kind = if e
                .phase
                .compare_exchange(QUEUED, PREPARING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                Some(ClaimKind::Prepare)
            } else if e.phase.load(Ordering::Acquire) == BOUND
                && e.start
                    .compare_exchange(
                        START_QUEUED,
                        START_ADMITTING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            {
                Some(ClaimKind::Start)
            } else {
                None
            };
            if let Some(kind) = kind {
                return Ok(Some(Claim {
                    entry: e.clone(),
                    kind,
                    returned: false,
                }));
            }
        }
        Ok(None)
    }
    pub(crate) fn entries(&self, family: Family) -> Result<Vec<Arc<Entry>>, Error> {
        Ok(self
            .lock()?
            .entries
            .iter()
            .filter(|e| e.family() == family)
            .cloned()
            .collect())
    }
}
fn access(b: &Book, family: Family) -> Access {
    let now = Instant::now();
    let l = b
        .lease
        .as_ref()
        .filter(|l| l.scope.review.family() == family);
    let consumed = l.is_some_and(|l| l.used.load(Ordering::Acquire));
    let enabled = !b.closed && !consumed && l.is_some_and(|l| l.stop_at(now, false).is_none());
    Access {
        enabled,
        remaining_ms: l.filter(|_| enabled).map_or(0, |l| {
            l.expires
                .saturating_duration_since(now)
                .as_millis()
                .min(u64::MAX as u128) as u64
        }),
        project_id: l.map(|l| l.scope.project_id.clone()),
        observation_revision: l.map(|l| l.scope.observation_revision),
        consumed,
    }
}

#[cfg(test)]
#[path = "agent_build_requests_tests.rs"]
mod tests;
