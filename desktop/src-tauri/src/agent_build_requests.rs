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
pub const LIMIT: usize = 32;
pub const START_WINDOW: Duration = Duration::from_secs(900);
// ONE shared32-row allocation (not32 per family) plus the two fixed small
// native grant comparisons. No native resource graph is duplicated.
pub(crate) const DOCUMENT_BACKING: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    AndroidInspect,
    IosArchive,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Review {
    Android(android::Review),
    Ios(ios::Review),
}
impl Review {
    pub(crate) fn family(&self) -> Family {
        match self {
            Self::Android(_) => Family::AndroidInspect,
            Self::Ios(_) => Family::IosArchive,
        }
    }
    fn valid(&self) -> bool {
        match self {
            Self::Android(v) => v.valid(),
            Self::Ios(v) => v.valid(),
        }
    }
    pub(crate) fn config(&self) -> &Config {
        match self {
            Self::Android(v) => &v.saved_config,
            Self::Ios(v) => &v.saved_config,
        }
    }
    pub(crate) fn version(&self) -> &android::Version {
        match self {
            Self::Android(v) => &v.saved_version,
            Self::Ios(v) => &v.saved_version,
        }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Android(android::Operation),
    Ios(ios::Operation),
}
impl Operation {
    pub(crate) fn family(&self) -> Family {
        match self {
            Self::Android(_) => Family::AndroidInspect,
            Self::Ios(_) => Family::IosArchive,
        }
    }
    pub(crate) fn operation_id(&self) -> &Id {
        match self {
            Self::Android(v) => &v.operation_id,
            Self::Ios(v) => &v.operation_id,
        }
    }
    pub(crate) fn owner_generation(&self) -> &Id {
        match self {
            Self::Android(v) => &v.owner_generation,
            Self::Ios(v) => &v.owner_generation,
        }
    }
    pub(crate) fn status_revision(&self) -> u32 {
        match self {
            Self::Android(v) => v.status_revision,
            Self::Ios(v) => v.status_revision,
        }
    }
    pub(crate) fn state(&self) -> OperationState {
        match self {
            Self::Android(v) => v.state.clone(),
            Self::Ios(v) => v.state.clone(),
        }
    }
    pub(crate) fn settlement(&self) -> Settlement {
        match self {
            Self::Android(v) => v.settlement.clone(),
            Self::Ios(v) => v.settlement.clone(),
        }
    }
    fn valid_for(&self, review: &Review) -> bool {
        match (self, review) {
            (Self::Android(o), Review::Android(r)) => {
                o.valid()
                    && o.result.as_ref().is_none_or(|v| {
                        v.used_config == r.saved_config && v.used_version == r.saved_version
                    })
            }
            (Self::Ios(o), Review::Ios(r)) => {
                o.valid()
                    && o.result.as_ref().is_none_or(|v| {
                        v.used_config == r.saved_config && v.used_version == r.saved_version
                    })
            }
            _ => false,
        }
    }
    #[cfg(test)]
    pub(crate) fn android(&self) -> &android::Operation {
        match self {
            Self::Android(v) => v,
            _ => panic!("wrong fixed test family"),
        }
    }
    fn prepared(family: Family, operation: Id, generation: Id, revision: u32) -> Self {
        match family {
            Family::AndroidInspect => Self::Android(android::Operation {
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
            Family::IosArchive => Self::Ios(ios::Operation {
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
        {
            Err(Error::StateUnknown)
        } else {
            Ok(())
        }
    }
}
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
    pub(crate) draft_revision: u32,
    pub(crate) baseline_generation: u32,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
}
impl NativeScope {
    fn valid(&self) -> bool {
        self.review.valid()
            && self.observation_revision != 0
            && self.inode != 0
            && self.registration != 0
            && self.input_revision != u64::MAX
            && self.document.strong_count() != 0
            && self.draft_revision < u32::MAX
            && self.baseline_generation < u32::MAX
            && (1..=64).contains(&self.runtime_id.len())
            && self.root.is_absolute()
            && self.root.as_os_str().len() <= 4096
    }
    pub(crate) fn matches(&self, point: &crate::agent_local_checks::SavedPoint) -> bool {
        self.project_id == point.project_id
            && self.runtime_id == point.runtime_id
            && self.root == point.root
            && self.device == point.device
            && self.inode == point.inode
            && self.observation_revision == point.revision
            && point.fresh
            && point.config.as_ref() == Some(self.review.config())
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
    claim: Option<Operation>,
    failed: bool,
}
pub(crate) struct Entry {
    input: Prepare,
    lease: Arc<Lease>,
    phase: AtomicU8,
    original: OnceLock<Original>,
    start: AtomicU8,
    start_at: OnceLock<Instant>,
    cancelled: OnceLock<Instant>,
    native_stop: OnceLock<tokio::sync::watch::Sender<bool>>,
    latest: Mutex<Option<Operation>>,
    publication: Mutex<Publication>,
}
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
    pub(crate) fn stop_at(&self, now: Instant) -> Option<Instant> {
        let consumed = self.start.load(Ordering::Acquire) == START_CONSUMED;
        let mut at = self.lease.stop_at(now, consumed);
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
    fn occupies(&self) -> bool {
        if self.phase.load(Ordering::Acquire) == QUEUED && self.stop_at(Instant::now()).is_some() {
            let _ =
                self.phase
                    .compare_exchange(QUEUED, EXPIRED, Ordering::AcqRel, Ordering::Acquire);
        }
        match self.phase.load(Ordering::Acquire) {
            QUEUED | PREPARING | UNKNOWN => true,
            BOUND => self.latest.lock().map_or(true, |v| {
                v.as_ref()
                    .is_none_or(|v| v.settlement() != Settlement::Settled)
            }),
            _ => false,
        }
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
        let operation = {
            let latest = self.latest.lock().map_err(|_| Error::StateUnknown)?;
            latest.as_ref().map(|value| data::Operation {
                operation_id: value.operation_id().clone(), owner_generation: value.owner_generation().clone(),
                status_revision: value.status_revision(), state: value.state(), settlement: value.settlement(),
            })
        }; // Never invert the existing latest -> publication order.
        let request_state = self.observed_request_state();
        let start_state = self.observed_start_state();
        let progress = match self.family() {
            Family::AndroidInspect => data::Progress::AndroidBuild { request_state, start_state },
            Family::IosArchive => data::Progress::IosArchive { request_state, start_state },
        };
        let history = self.publication.lock().map_err(|_| Error::StateUnknown)?;
        let history_available = !history.failed && operation.as_ref()
            .is_some_and(|value| history.acknowledged == Some(value.status_revision));
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
        let operation = self.latest.lock().map_err(|_| Error::StateUnknown)?.clone();
        let request_state = self.observed_request_state();
        let start_state = self.observed_start_state();
        let p = self.publication.lock().map_err(|_| Error::StateUnknown)?;
        let result = Snapshot {
            origin: self.input.query(),
            expected_observation_revision: self.input.expected_observation_revision,
            request_state,
            start_state,
            review: self.scope().review.clone(),
            history_available: !p.failed
                && operation
                    .as_ref()
                    .is_some_and(|o| p.acknowledged == Some(o.status_revision())),
            operation,
            do_not_replay: true,
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
        let op = Operation::prepared(family, operation, generation, revision);
        if link.publish(op).is_err() {
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        self.phase.store(BOUND, Ordering::Release);
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
            let latest = self.latest.lock().map_err(|_| Error::StateUnknown)?;
            if latest.as_ref().is_none_or(|v| {
                v.state() != OperationState::Prepared || v.settlement() != Settlement::Pending
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
            return Err(Error::StateUnknown);
        }
        if p.acknowledged == Some(latest.status_revision()) {
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
            .is_none_or(|c| c.status_revision() != revision)
        {
            p.failed = true;
            return Err(Error::StateUnknown);
        }
        if let Err(e) = result {
            p.failed = true;
            return Err(e);
        }
        p.claim = None;
        p.acknowledged = Some(revision);
        Ok(())
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
            if old.settlement() == Settlement::Unknown || *old == data {
                return Ok(());
            }
            if data.status_revision() <= old.status_revision()
                || old.settlement() == Settlement::Settled
            {
                return Err(Error::StateUnknown);
            }
        }
        // Actual same-owner retirement can resolve lost admission ACK, never
        // a native UNKNOWN. It cannot make the one-use Start available again.
        if data.settlement() == Settlement::Settled {
            self.entry.phase.store(BOUND, Ordering::Release);
        }
        *latest = Some(data);
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
        if ok && self.entry.original.get().is_some() {
            return;
        }
        if self.entry.original.get().is_none() && !ok {
            let _ = self.entry.phase.compare_exchange(
                PREPARING,
                REFUSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        } else if self.entry.latest.lock().is_ok_and(|v| {
            v.as_ref()
                .is_some_and(|o| o.settlement() == Settlement::Settled)
        }) {
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
        {
            return Err(Error::Conflict);
        }
        let entry = Arc::new(Entry {
            input,
            lease: lease.clone(),
            phase: AtomicU8::new(QUEUED),
            original: OnceLock::new(),
            start: AtomicU8::new(NO_START),
            start_at: OnceLock::new(),
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
        self.find(family, &b, &input.origin)?.request_start(input)
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
