//! A finite delegation inbox on the SAME service. No tool/source/process owner.
use crate::{
    service_protocol::{Error, Id, OperationState, Settlement},
    service_tool_setup_protocol as p,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, OnceLock, Weak,
    },
    time::{Duration, Instant},
};
pub(crate) const CONTROL_POLL: Duration = Duration::from_millis(5);
const ARC: usize = 2 * std::mem::size_of::<usize>();
// Fixed DATA backing only. Native sources/tasks retain their existing census.
// Each row can coexist with its immutable input, current native/report, a claimed
// history copy, status copy, weak read/scope/link and their allocator headers.
// One actual NativeScope is charged per retained Entry, not assumed shared away.
// Original picked source comparisons may retain four roots plus one context;
// retired Acquisition Intents may retain their small comparison too. Charge
// these native DATA fields for every retained row, even after current Grant
// replacement. The ONE actual Doctor Value/frames stay in the Doc dynamic quote.
const NATIVE_COMPARISONS: usize = 4 * 4096 + 8 * 64 + 128 * std::mem::size_of::<usize>();
const ROW: usize = NATIVE_COMPARISONS
    + std::mem::size_of::<Entry>()
    + std::mem::size_of::<NativeScope>()
    + std::mem::size_of::<NativeLink>()
    + std::mem::size_of::<Control>()
    + std::mem::size_of::<Lease>()
    + std::mem::size_of::<crate::service_version_reserve_requests::ReadPermission>()
    + 8 * ARC
    + 32 * 32
    + 4096
    + 64
    + 64
    + 4 * (p::REPORT_LIMIT + std::mem::size_of::<p::Report>());
// All native comparisons/rows/current consent remain; only IPC8 is pooled.
pub(crate) const IPC_WORKER_BACKING: usize = crate::service_protocol::REQUEST_BYTES + p::RAW_LIMIT + 2 * p::STATUS_LIMIT;
pub(crate) const DOCUMENT_BACKING: usize = std::mem::size_of::<Inbox>()
    + std::mem::size_of::<Book>()
    + 32
    + p::REQUEST_LIMIT * (ROW + std::mem::size_of::<Arc<Entry>>())
    + p::CONSENT_LIMIT * (std::mem::size_of::<Id>() + 32)
    + ROW;

pub(crate) struct Control {
    first: Mutex<Option<(p::Reason, Instant)>>,
    unknown: AtomicBool,
    wake: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}
impl Control {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            first: Mutex::new(None),
            unknown: AtomicBool::new(false),
            wake: Mutex::new(None),
        })
    }
    pub(crate) fn stop(&self, reason: p::Reason, at: Instant) {
        match self.first.lock() {
            Ok(mut v) => {
                if v.is_none_or(|(_, old)| at < old) {
                    *v = Some((reason, at));
                }
            }
            Err(_) => self.unknown.store(true, Ordering::Release),
        }
        match self.wake.lock() {
            Ok(w) => {
                if let Some(w) = w.as_ref() {
                    w.send_if_modified(|s| {
                        if !*s {
                            *s = true;
                            true
                        } else {
                            false
                        }
                    });
                }
            }
            Err(_) => self.unknown.store(true, Ordering::Release),
        }
    }
    pub(crate) fn unknown(&self, at: Instant) {
        self.unknown.store(true, Ordering::Release);
        self.stop(p::Reason::CleanupUnknown, at);
    }
    pub(crate) fn first(&self) -> Result<Option<(p::Reason, Instant)>, Error> {
        if self.unknown.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        self.first
            .lock()
            .map(|v| *v)
            .map_err(|_| Error::StateUnknown)
    }
    pub(crate) fn uncertain_at(&self, at: Instant) -> Instant {
        let f = match self.first.lock() {
            Ok(f) => f,
            Err(e) => e.into_inner(),
        };
        f.as_ref().map_or(at, |(_, t)| at.min(*t))
    }
    pub(crate) fn attach(&self, w: &tokio::sync::watch::Sender<bool>) -> Result<(), Error> {
        let mut s = self.wake.lock().map_err(|_| Error::StateUnknown)?;
        if s.is_some() {
            return Err(Error::Conflict);
        }
        *s = Some(w.clone());
        if self.first().map_or(true, |f| f.is_some()) {
            w.send_replace(true);
        }
        Ok(())
    }
    fn detach(&self) {
        if let Ok(mut w) = self.wake.lock() {
            w.take();
        } else {
            self.unknown.store(true, Ordering::Release);
        }
    }
}
pub(crate) struct NativeScope {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) review_id: Id,
    pub(crate) review: p::Review,
    pub(crate) root: std::path::PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) observation_revision: u64,
    pub(crate) saved_config: Option<crate::agent_local_checks::Config>,
    pub(crate) expires: Instant,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
    pub(crate) document: Weak<()>,
    pub(crate) control: Arc<Control>,
    pub(crate) retired: AtomicBool,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
}
impl NativeScope {
    pub(crate) fn matches(&self, p: &crate::agent_local_checks::SavedPoint) -> bool {
        p.project_id == self.project_id
            && p.runtime_id == self.runtime_id
            && p.root == self.root
            && p.device == self.device
            && p.inode == self.inode
            && p.revision == self.observation_revision
            && p.fresh
            && p.config == self.saved_config
    }
    pub(crate) fn current(&self, admitted: bool, now: Instant) -> Result<(), Error> {
        if self.document.strong_count() == 0 {
            self.control.stop(p::Reason::ContextChanged, now);
        }
        match self.read.stop(now) {
            Ok(Some((reason, at))) => self.control.stop(
                if reason == crate::service_version_reserve_protocol::Reason::Expired {
                    p::Reason::Expired
                } else {
                    p::Reason::PermissionRevoked
                },
                at,
            ),
            Err(_) => self.control.unknown(now),
            Ok(None) => {}
        }
        if !admitted && now >= self.expires {
            self.control.stop(p::Reason::Expired, self.expires);
        }
        if self.control.first()?.is_some() {
            return Err(Error::AccessDenied);
        }
        if !admitted && self.retired.load(Ordering::Acquire) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn valid(&self, now: Instant) -> bool {
        self.review.valid()
            && (self.review.kind == p::Kind::Doctor || self.saved_config.is_some())
            && (1..=64).contains(&self.runtime_id.len())
            && self
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && self.root.is_absolute()
            && self.root.as_os_str().len() <= 4096
            && self.inode > 0
            && self.observation_revision > 0
            && self.expires > now
            && self.expires <= self.read.end()
            && self.expires.saturating_duration_since(now).as_millis() <= u128::from(p::INTENT_MS)
            && self.current(false, now).is_ok()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeData {
    pub(crate) sequence: u32,
    pub(crate) operation: Option<p::Operation>,
    pub(crate) state: OperationState,
    pub(crate) reason: p::Reason,
    pub(crate) outcome: Option<p::Outcome>,
    pub(crate) result: Option<p::Report>,
    pub(crate) retired: bool,
}
impl NativeData {
    fn valid(&self, r: &p::Review) -> bool {
        (1..u32::MAX).contains(&self.sequence)
            && self.operation.as_ref().is_none_or(|o| o.valid_for(r))
            && self.result.as_ref().is_none_or(|v| v.valid_for(r))
            && if self.retired {
                match self.outcome {
                    Some(p::Outcome::Complete) => {
                        self.state == OperationState::Succeeded
                            && self.reason == p::Reason::None
                            && self.operation.is_some()
                            && self.result.is_some()
                    }
                    Some(p::Outcome::Cancelled) => {
                        self.state == OperationState::Cancelled
                            && self.reason != p::Reason::None
                            && self.result.is_none()
                    }
                    Some(p::Outcome::Refused | p::Outcome::Failed | p::Outcome::TimedOut) => {
                        self.state == OperationState::Failed
                            && !matches!(
                                self.reason,
                                p::Reason::None
                                    | p::Reason::CleanupUnknown
                                    | p::Reason::HistoryUnavailable
                            )
                            && self.result.is_none()
                    }
                    _ => false,
                }
            } else {
                self.outcome.is_none()
                    && self.result.is_none()
                    && matches!(
                        self.state,
                        OperationState::Prepared
                            | OperationState::Running
                            | OperationState::CancellationRequested
                    )
                    && !matches!(
                        self.reason,
                        p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable
                    )
            }
    }
}
/// Bounded callback DATA link. Only the three fixed native child modules call
/// it at their actual admission/retirement cuts; it cannot construct native
/// originals or infer a join. A cached result cannot complete a missing caller.
pub(crate) struct NativeLink {
    scope: Arc<NativeScope>,
    entry: OnceLock<Arc<Entry>>,
    latest: Mutex<Option<NativeData>>,
    consumed: AtomicBool,
    entered: AtomicBool,
}
impl NativeLink {
    pub(crate) fn new(scope: Arc<NativeScope>) -> Arc<Self> {
        Arc::new(Self {
            scope,
            entry: OnceLock::new(),
            latest: Mutex::new(None),
            consumed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
        })
    }
    pub(crate) fn scope(&self) -> &Arc<NativeScope> {
        &self.scope
    }
    pub(crate) fn attach(&self, e: &Arc<Entry>) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.scope, e.scope()) {
            return Err(Error::Conflict);
        }
        let last = self.latest.lock().map_err(|_| Error::StateUnknown)?;
        self.entry.set(e.clone()).map_err(|_| Error::Conflict)?;
        if let Some(n) = last.as_ref() {
            e.native(n.clone());
        }
        if self.scope.control.first().is_err() {
            e.unknown(p::Reason::CleanupUnknown);
        }
        Ok(())
    }
    pub(crate) fn matches(&self, e: &Arc<Entry>) -> bool {
        Arc::ptr_eq(&self.scope, e.scope())
            && self.entry.get().is_some_and(|old| Arc::ptr_eq(old, e))
            && !self.consumed.load(Ordering::Acquire)
    }
    pub(crate) fn consume(&self, e: &Arc<Entry>) -> Result<(), Error> {
        e.current()?;
        self.scope.current(false, Instant::now())?; // actual native admission, not queue time
        if self.scope.retired.load(Ordering::Acquire)
            || !self.matches(e)
            || self.consumed.swap(true, Ordering::AcqRel)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn entered(&self, operation: p::Operation) {
        if self.entered.swap(true, Ordering::AcqRel) {
            self.unknown();
            return;
        }
        self.publish(Some(operation), None, p::Reason::None, None, false);
    }
    pub(crate) fn caller_returned(&self) -> bool {
        self.entry
            .get()
            .is_none_or(|e| e.lock().is_ok_and(|r| r.caller_returned))
    }
    pub(crate) fn unentered_caller_returned(&self) -> bool {
        !self.has_entered()
            && self
                .entry
                .get()
                .is_none_or(|e| e.lock().is_ok_and(|r| !r.claimed || r.caller_returned))
    }
    pub(crate) fn has_entered(&self) -> bool {
        self.entered.load(Ordering::Acquire)
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Option<(p::Reason, Instant)> {
        if self.scope.retired.load(Ordering::Acquire) {
            return None;
        }
        let _ = self
            .scope
            .current(self.consumed.load(Ordering::Acquire), now);
        self.scope.control.first().unwrap_or_else(|_| {
            Some((
                p::Reason::CleanupUnknown,
                self.scope
                    .control
                    .uncertain_at(self.entry.get().map_or(now, |e| e.submitted_at())),
            ))
        })
    }
    pub(crate) fn unknown(&self) {
        self.scope.control.unknown(
            self.entry
                .get()
                .map_or_else(Instant::now, |e| e.submitted_at()),
        );
        if let Some(e) = self.entry.get() {
            e.unknown(p::Reason::CleanupUnknown);
        }
    }
    pub(crate) fn cancel(&self, reason: p::Reason, at: Instant) {
        self.scope.control.stop(reason, at);
        self.scope.changes.send_modify(|_| {});
    }
    pub(crate) fn publish(
        &self,
        operation: Option<p::Operation>,
        outcome: Option<p::Outcome>,
        reason: p::Reason,
        result: Option<p::Report>,
        retired: bool,
    ) {
        let Ok(mut last) = self.latest.lock() else {
            self.unknown();
            return;
        };
        if let Some(old) = last.as_ref() {
            if old.retired {
                return;
            }
            if old.operation.is_some() && old.operation != operation {
                drop(last);
                self.unknown();
                return;
            }
        }
        let sequence = last.as_ref().map_or(1, |d| d.sequence.saturating_add(1));
        let state = match outcome {
            Some(p::Outcome::Complete) => OperationState::Succeeded,
            Some(p::Outcome::Cancelled) => OperationState::Cancelled,
            Some(_) => OperationState::Failed,
            None if reason != p::Reason::None => OperationState::CancellationRequested,
            None if operation.is_some() => OperationState::Running,
            None => OperationState::Prepared,
        };
        let n = NativeData {
            sequence,
            operation,
            state,
            reason,
            outcome,
            result,
            retired,
        };
        if !n.valid(&self.scope.review) {
            drop(last);
            self.unknown();
            return;
        }
        if retired {
            self.scope.retired.store(true, Ordering::Release);
            self.scope.control.detach();
        }
        *last = Some(n.clone());
        if let Some(e) = self.entry.get() {
            e.native(n);
        }
    }
    // Caller is the exact original native/Doc refusal path, AFTER no-effect
    // admission objects have actually returned. Absence/timer never invokes it.
    pub(crate) fn refused_unentered(&self, reason: p::Reason) {
        if self.has_entered() {
            self.unknown();
        } else {
            self.publish(None, Some(p::Outcome::Refused), reason, None, true);
        }
    }
}
struct Row {
    revision: u32,
    claimed: bool,
    caller_returned: bool,
    native: Option<NativeData>,
    history_started: bool,
    history_acked: u32,
    history_claim: Option<NativeData>,
    unknown: Option<p::Reason>,
}
pub(crate) struct Entry {
    input: p::Submit,
    scope: Arc<NativeScope>,
    submitted: Instant,
    row: Mutex<Row>,
}
impl Entry {
    pub(crate) fn origin(&self) -> &p::Query {
        &self.input.origin
    }
    pub(crate) fn scope(&self) -> &Arc<NativeScope> {
        &self.scope
    }
    pub(crate) fn submitted_at(&self) -> Instant {
        self.submitted
    }
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.scope.control.unknown(self.submitted);
            Error::StateUnknown
        })
    }
    fn changed(&self, r: &mut Row) -> Result<(), Error> {
        r.revision = r
            .revision
            .checked_add(1)
            .filter(|v| *v < u32::MAX)
            .ok_or(Error::StateUnknown)?;
        self.scope.changes.send_modify(|_| {});
        Ok(())
    }
    fn settled(r: &Row) -> bool {
        r.unknown.is_none()
            && r.caller_returned
            && r.native.as_ref().is_some_and(|n| {
                n.retired && r.history_acked >= n.sequence && r.history_claim.is_none()
            })
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        self.scope.current(true, Instant::now())
    }
    pub(crate) fn pending(&self) -> bool {
        self.lock().map_or(true, |r| {
            !Self::settled(&r) || self.scope.control.first().is_err()
        })
    }
    pub(crate) fn cancel(&self, reason: p::Reason, at: Instant) {
        if self.lock().is_ok_and(|r| Self::settled(&r)) {
            return;
        }
        self.scope.control.stop(reason, at);
        self.scope.changes.send_modify(|_| {});
    }
    pub(crate) fn unknown(&self, reason: p::Reason) {
        self.scope.control.unknown(self.submitted);
        if let Ok(mut r) = self.lock() {
            r.unknown.get_or_insert(reason);
            let _ = self.changed(&mut r);
        }
    }
    pub(crate) fn native(&self, n: NativeData) {
        if !n.valid(&self.scope.review) {
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        let Ok(mut r) = self.lock() else {
            return;
        };
        if r.unknown.is_some() {
            return;
        }
        if let Some(old) = &r.native {
            if n.sequence < old.sequence {
                return;
            }
            if n.sequence == old.sequence {
                if n != *old {
                    drop(r);
                    self.unknown(p::Reason::CleanupUnknown);
                }
                return;
            }
            if old.retired || old.operation.is_some() && old.operation != n.operation {
                drop(r);
                self.unknown(p::Reason::CleanupUnknown);
                return;
            }
        }
        r.native = Some(n);
        if self.changed(&mut r).is_err() {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
        }
    }
    fn caller_returned(&self) {
        let Ok(mut r) = self.lock() else {
            return;
        };
        if !r.claimed || r.caller_returned {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        r.caller_returned = true;
        if self.changed(&mut r).is_err() {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
        }
    }
    pub(crate) fn claim_history(self: &Arc<Self>) -> Result<Option<History>, Error> {
        let mut r = self.lock()?;
        if r.unknown.is_some() || r.history_claim.is_some() {
            return Ok(None);
        }
        let Some(n) = r
            .native
            .as_ref()
            .filter(|n| n.sequence > r.history_acked && (!n.retired || r.caller_returned))
            .cloned()
        else {
            return Ok(None);
        };
        let first = !r.history_started;
        r.history_claim = Some(n.clone());
        Ok(Some(History {
            entry: self.clone(),
            data: n,
            first,
            returned: false,
        }))
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        let (claimed, settled) = {
            let r = self.lock()?;
            (r.claimed, Self::settled(&r))
        };
        if !settled {
            let _ = self.scope.current(claimed, Instant::now());
        }
        let mut r = self.lock()?;
        if self.scope.control.first().is_err() {
            r.unknown.get_or_insert(p::Reason::CleanupUnknown);
        }
        let stopped = self.scope.control.first().ok().flatten().map(|(v, _)| v);
        let n = r.native.as_ref();
        let (state, settlement, reason, outcome, result) = if let Some(why) = r.unknown {
            (
                p::State::Unknown,
                Settlement::Unknown,
                why,
                Some(p::Outcome::Unknown),
                None,
            )
        } else if Self::settled(&r) {
            let n = n.ok_or(Error::StateUnknown)?;
            let state = match n.outcome {
                Some(p::Outcome::Complete) => p::State::Complete,
                Some(p::Outcome::Cancelled) => p::State::Cancelled,
                Some(p::Outcome::Refused) if n.reason == p::Reason::Expired => p::State::Expired,
                Some(p::Outcome::Refused)
                    if matches!(
                        n.reason,
                        p::Reason::UserCancelled
                            | p::Reason::PermissionRevoked
                            | p::Reason::ContextChanged
                            | p::Reason::Shutdown
                    ) =>
                {
                    p::State::Cancelled
                }
                Some(p::Outcome::Refused) => p::State::Refused,
                Some(p::Outcome::Failed | p::Outcome::TimedOut) => p::State::Failed,
                _ => return Err(Error::StateUnknown),
            };
            (
                state,
                Settlement::Settled,
                n.reason,
                n.outcome,
                n.result.clone(),
            )
        } else {
            (
                if n.is_some_and(|n| n.retired) {
                    p::State::Finishing
                } else if stopped.is_some() {
                    p::State::Stopping
                } else if n.is_some() {
                    p::State::Running
                } else if claimed {
                    p::State::Starting
                } else {
                    p::State::Queued
                },
                Settlement::Pending,
                stopped.unwrap_or(p::Reason::None),
                None,
                None,
            )
        };
        let s = p::Status {
            origin: self.input.origin.clone(),
            grant_id: self.input.grant_id.clone(),
            review_id: self.input.review_id.clone(),
            revision: r.revision,
            review: self.scope.review.clone(),
            state,
            settlement,
            reason,
            operation: n.and_then(|n| n.operation.clone()),
            outcome,
            result,
        };
        s.validate().map_err(|_| Error::StateUnknown)?;
        Ok(s)
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
    pub(crate) fn returned(mut self) {
        self.entry.caller_returned();
        self.returned = true;
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::CleanupUnknown);
        }
    }
}
pub(crate) struct History {
    entry: Arc<Entry>,
    pub(crate) data: NativeData,
    pub(crate) first: bool,
    returned: bool,
}
impl History {
    pub(crate) fn settlement(&self) -> Settlement {
        if self.data.retired {
            Settlement::Settled
        } else {
            Settlement::Pending
        }
    }
    pub(crate) fn returned(mut self, result: Result<(), Error>) -> Result<(), Error> {
        if result.is_err() {
            self.entry.unknown(p::Reason::HistoryUnavailable);
            self.returned = true;
            return result;
        }
        let mut r = self.entry.lock()?;
        if r.history_claim.as_ref() != Some(&self.data) {
            drop(r);
            self.entry.unknown(p::Reason::HistoryUnavailable);
            self.returned = true;
            return Err(Error::StateUnknown);
        }
        r.history_acked = self.data.sequence;
        r.history_started = true;
        r.history_claim = None;
        self.entry.changed(&mut r)?;
        self.returned = true;
        Ok(())
    }
}
impl Drop for History {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::HistoryUnavailable);
        }
    }
}
struct Lease {
    id: Id,
    scope: Arc<NativeScope>,
    entry: Option<Weak<Entry>>,
}
struct Book {
    lease: Option<Lease>,
    entries: Vec<Arc<Entry>>,
    consents: Vec<Id>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: AtomicBool,
}
impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                lease: None,
                entries: Vec::with_capacity(p::REQUEST_LIMIT),
                consents: Vec::with_capacity(p::CONSENT_LIMIT),
                closed: false,
            }),
            failed: AtomicBool::new(false),
        }
    }
    fn lock(&self) -> Result<MutexGuard<'_, Book>, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        self.book.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    fn allow_ready(b: &Book, id: &Id) -> Result<(), Error> {
        if b.closed {
            return Err(Error::Unavailable);
        }
        if b.consents.contains(id) {
            return Err(Error::AccessDenied);
        }
        if b.entries.len() >= p::REQUEST_LIMIT
            || b.consents.len() >= p::CONSENT_LIMIT
            || b.entries.iter().any(|e| e.pending())
            || b.lease.as_ref().is_some_and(|l| {
                !l.scope.retired.load(Ordering::Acquire) || l.scope.control.first().is_err()
            })
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    pub(crate) fn can_allow(&self, id: &Id) -> Result<(), Error> {
        {
            let b = self.lock()?;
            Self::allow_ready(&b, id)
        }
    }
    pub(crate) fn allow(&self, scope: Arc<NativeScope>, id: Id) -> Result<p::Access, Error> {
        let now = Instant::now();
        if !scope.valid(now) {
            return Err(Error::Conflict);
        }
        let mut b = self.lock()?;
        Self::allow_ready(&b, &id)?;
        b.consents.push(id.clone());
        b.lease = Some(Lease {
            id,
            scope,
            entry: None,
        });
        self.access_locked(&b)
    }
    pub(crate) fn submit(&self, input: p::Submit, submitted: Instant) -> Result<p::Status, Error> {
        let mut b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(old) = b
            .entries
            .iter()
            .find(|e| e.input.origin.request_id == input.origin.request_id)
        {
            return if old.input == input {
                old.status()
            } else {
                Err(Error::Conflict)
            };
        }
        if b.entries.len() >= p::REQUEST_LIMIT || b.entries.iter().any(|e| e.pending()) {
            return Err(Error::Busy);
        }
        let lease = b.lease.as_mut().ok_or(Error::AccessDenied)?;
        if lease.id != input.grant_id
            || lease.scope.review_id != input.review_id
            || lease.scope.project_id != input.origin.project_id
            || lease.entry.is_some()
        {
            return Err(Error::AccessDenied);
        }
        lease.scope.current(false, Instant::now())?;
        if submitted >= lease.scope.expires {
            return Err(Error::Expired);
        }
        let e = Arc::new(Entry {
            input,
            scope: lease.scope.clone(),
            submitted,
            row: Mutex::new(Row {
                revision: 1,
                claimed: false,
                caller_returned: false,
                native: None,
                history_started: false,
                history_acked: 0,
                history_claim: None,
                unknown: None,
            }),
        });
        lease.entry = Some(Arc::downgrade(&e));
        b.entries.push(e.clone());
        e.scope.changes.send_modify(|_| {});
        e.status()
    }
    pub(crate) fn query(&self, q: &p::Query, cancel: bool) -> Result<p::Status, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        let e = b
            .entries
            .iter()
            .find(|e| e.input.origin == *q)
            .cloned()
            .ok_or(Error::Conflict)?;
        drop(b);
        if cancel {
            e.cancel(p::Reason::UserCancelled, Instant::now());
        }
        e.status()
    }
    pub(crate) fn claim(&self) -> Result<Option<Claim>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Ok(None);
        }
        for e in &b.entries {
            let mut r = e.lock()?;
            if !r.claimed && r.unknown.is_none() {
                r.claimed = true;
                e.changed(&mut r)?;
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
    fn access_locked(&self, b: &Book) -> Result<p::Access, Error> {
        let Some(l) = &b.lease else {
            return Ok(p::Access::empty());
        };
        let e = l.entry.as_ref().and_then(Weak::upgrade);
        let current = e.is_some() || l.scope.current(false, Instant::now()).is_ok();
        let s = e.as_ref().map(|e| e.status()).transpose()?;
        let unknown = s.as_ref().is_some_and(|s| s.state == p::State::Unknown)
            || s.is_none() && l.scope.control.first().is_err();
        let pending = s
            .as_ref()
            .is_some_and(|s| s.settlement != Settlement::Settled)
            || s.is_none() && !current && !l.scope.retired.load(Ordering::Acquire);
        let enabled = !b.closed && current && e.is_none() && !pending && !unknown;
        let ms = if enabled {
            l.scope
                .expires
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(u128::from(p::INTENT_MS)) as u64
        } else {
            0
        };
        let a = p::Access {
            service_instance: Some(self.instance.clone()),
            project_id: Some(l.scope.project_id.clone()),
            grant_id: Some(l.id.clone()),
            review_id: Some(l.scope.review_id.clone()),
            review: Some(l.scope.review.clone()),
            enabled: enabled && ms > 0,
            remaining_ms: ms,
            consumed: e.is_some(),
            pending,
            unknown,
            request_id: e.as_ref().map(|e| e.origin().request_id.clone()),
            status: s,
        };
        a.validate().map_err(|_| Error::StateUnknown)?;
        Ok(a)
    }
    pub(crate) fn access(&self) -> Result<p::Access, Error> {
        {
            let b = self.lock()?;
            self.access_locked(&b)
        }
    }
    pub(crate) fn revoke(&self, id: &Id, at: Instant) -> Result<p::Access, Error> {
        let mut b = self.lock()?;
        if !b.consents.contains(id) {
            if b.consents.len() >= p::CONSENT_LIMIT {
                return Err(Error::Busy);
            }
            b.consents.push(id.clone());
        }
        if let Some(l) = b.lease.as_ref().filter(|l| &l.id == id) {
            l.scope.control.stop(p::Reason::PermissionRevoked, at);
        }
        for e in b.entries.iter().filter(|e| &e.input.grant_id == id) {
            e.cancel(p::Reason::PermissionRevoked, at);
        }
        self.access_locked(&b)
    }
    pub(crate) fn revoke_all(&self, why: p::Reason, at: Instant) {
        let Ok(b) = self.lock() else {
            return;
        };
        if let Some(l) = &b.lease {
            l.scope.control.stop(why, at);
        }
        for e in &b.entries {
            e.cancel(why, at);
        }
    }
    pub(crate) fn close(&self, at: Instant) {
        self.revoke_all(p::Reason::Shutdown, at);
        if let Ok(mut b) = self.lock() {
            b.closed = true;
        }
    }
    pub(crate) fn fence(&self) {
        self.failed.store(true, Ordering::Release);
        let b = match self.book.lock() {
            Ok(b) => b,
            Err(e) => e.into_inner(),
        };
        if let Some(l) = &b.lease {
            l.scope.control.unknown(Instant::now());
        }
        for e in &b.entries {
            e.unknown(p::Reason::HistoryUnavailable);
        }
    }
    pub(crate) fn catalogue_requests(
        &self,
        instance: &Id,
        project: &Id,
    ) -> Result<Vec<crate::service_request_catalogue::AdditionalRequest>, Error> {
        let b = self.lock()?;
        if b.closed || instance != &self.instance {
            return Err(Error::Unavailable);
        }
        Ok(b.entries
            .iter()
            .filter(|e| &e.origin().project_id == project)
            .map(|e| crate::service_request_catalogue::AdditionalRequest {
                family: crate::service_request_catalogue::AdditionalFamily::ToolSetup,
                request_id: e.origin().request_id.clone(),
            })
            .collect())
    }
}
#[cfg(test)]
#[path = "service_tool_setup_requests_tests.rs"]
mod tests;
