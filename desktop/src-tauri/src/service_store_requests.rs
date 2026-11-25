//! ONE finite metadata inbox for the two fixed nonpublishing Store steps.
//! This has no native owner, credential, source, executor or journal.
use crate::{
    service_protocol::{Error, Id, OperationState, Settlement},
    service_store_protocol as p,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::Instant,
};

#[path = "service_store_prepare_requests.rs"]
pub(crate) mod preparation;
use preparation::{PreparationLease, StoredEntry};
#[path="service_local_history_requests.rs"]
pub(crate) mod history;

pub(crate) struct Control {
    stop: Mutex<Option<(p::Reason, Instant)>>,
    failed: AtomicBool,
    wake: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}
impl Control {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            stop: Mutex::new(None),
            failed: AtomicBool::new(false),
            wake: Mutex::new(None),
        })
    }
    pub(crate) fn stop(&self, reason: p::Reason, at: Instant) {
        match self.stop.lock() {
            Ok(mut before) => {
                if before.is_none_or(|(_, old)| at < old) {
                    *before = Some((reason, at));
                }
            }
            Err(_) => self.failed.store(true, Ordering::Release),
        }
        if let Ok(wake) = self.wake.lock() {
            if let Some(wake) = wake.as_ref() {
                wake.send_replace(true);
            }
        } else {
            self.failed.store(true, Ordering::Release);
        }
    }
    pub(crate) fn unknown(&self, at: Instant) {
        self.failed.store(true, Ordering::Release);
        self.stop(p::Reason::CleanupUnknown, at);
    }
    pub(crate) fn first(&self) -> Result<Option<(p::Reason, Instant)>, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        self.stop
            .lock()
            .map(|v| *v)
            .map_err(|_| Error::StateUnknown)
    }
    /// Uncertainty never moves the original cutoff forward. Poison recovery
    /// here reads only the first STOP time; it cannot grant work or finality.
    pub(crate) fn uncertain_at(&self, fallback: Instant) -> Instant {
        let stop = match self.stop.lock() {
            Ok(v) => v,
            Err(e) => e.into_inner(),
        };
        stop.as_ref()
            .map_or(fallback, |(_, at)| (*at).min(fallback))
    }
    pub(crate) fn attach(&self, wake: &tokio::sync::watch::Sender<bool>) -> Result<(), Error> {
        let mut slot = self.wake.lock().map_err(|_| Error::StateUnknown)?;
        if slot.is_some() {
            return Err(Error::Conflict);
        }
        *slot = Some(wake.clone());
        if self.failed.load(Ordering::Acquire) || self.stop.lock().map_or(true, |v| v.is_some()) {
            wake.send_replace(true);
        }
        Ok(())
    }
    pub(crate) fn detach_returned(&self) {
        if let Ok(mut v) = self.wake.lock() {
            v.take();
        } else {
            self.failed.store(true, Ordering::Release);
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
    pub(crate) expires: Instant,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
    pub(crate) document: Weak<()>,
    pub(crate) witness: Weak<()>,
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
            && p.config.as_ref().is_some_and(|c| {
                c.bytes == self.review.saved_config.bytes
                    && c.sha256 == self.review.saved_config.sha256
            })
    }
    pub(crate) fn current(&self, admitted: bool, now: Instant) -> Result<(), Error> {
        if self.document.strong_count() == 0 || self.witness.strong_count() == 0 {
            self.control.stop(p::Reason::ContextChanged, now);
        }
        match self.read.stop(now) {
            Ok(Some((_, at))) => self.control.stop(p::Reason::PermissionRevoked, at),
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
            && (1..=64).contains(&self.runtime_id.len())
            && self
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && self.expires > now
            && self.expires.saturating_duration_since(now).as_millis() <= p::INTENT_MS as u128
            && self.root.is_absolute()
            && self.root.as_os_str().len() <= 4096
            && self.observation_revision > 0
            && self.current(false, now).is_ok()
    }
}
struct Lease {
    id: Id,
    scope: Arc<NativeScope>,
    entry: Mutex<Option<Weak<Entry>>>,
}
struct Book {
    lease: Option<Arc<Lease>>,
    entries: Vec<StoredEntry>,
    preparation: Option<Arc<PreparationLease>>,
    history: Option<history::Allowed>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: AtomicBool,
}

/// Constructed only by the actual Saved owner facet, never deserialized. A
/// retired flag alone is insufficient: Entry separately requires the original
/// relay caller and the matching service-history writer to return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeData {
    pub(crate) operation: p::Operation,
    pub(crate) state: OperationState,
    pub(crate) reason: p::Reason,
    pub(crate) outcome: Option<p::Outcome>,
    pub(crate) result: Option<p::Report>,
    pub(crate) retired: bool,
}
impl NativeData {
    fn valid(&self, review: &p::Review) -> bool {
        self.operation.operation_id == review.operation_id
            && self.operation.owner_generation == review.owner_generation
            && (review.status_revision..u32::MAX).contains(&self.operation.status_revision)
            && self.result.as_ref().is_none_or(|v| v.valid_for(review))
            && if self.retired {
                match self.outcome {
                    Some(p::Outcome::Complete) => {
                        self.state == OperationState::Succeeded
                            && self.reason == p::Reason::None
                            && self.result.is_some()
                    }
                    Some(p::Outcome::Cancelled) => {
                        self.state == OperationState::Cancelled
                            && self.reason != p::Reason::None
                            && self.result.is_none()
                    }
                    Some(p::Outcome::Failed | p::Outcome::Refused | p::Outcome::TimedOut) => {
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
    fn settlement(&self) -> Settlement {
        if self.retired {
            Settlement::Settled
        } else {
            Settlement::Pending
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
    pub(crate) fn scope(&self) -> &Arc<NativeScope> {
        &self.scope
    }
    pub(crate) fn submitted_at(&self) -> Instant {
        self.submitted
    }
    pub(crate) fn origin(&self) -> &p::Query {
        &self.input.origin
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
            .filter(|n| *n < u32::MAX)
            .ok_or(Error::StateUnknown)?;
        self.scope.changes.send_modify(|_| {});
        Ok(())
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        self.scope.current(true, Instant::now())
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Option<Instant> {
        let _ = self.scope.current(true, now);
        self.scope
            .control
            .first()
            .map_or(Some(self.submitted), |v| v.map(|(_, at)| at))
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
    fn settled(r: &Row) -> bool {
        r.unknown.is_none()
            && r.caller_returned
            && r.native.as_ref().is_some_and(|n| {
                n.retired
                    && r.history_acked >= n.operation.status_revision
                    && r.history_claim.is_none()
            })
    }
    pub(crate) fn pending(&self) -> bool {
        self.lock().map_or(true, |r| {
            !Self::settled(&r) || self.scope.control.first().is_err()
        })
    }
    pub(crate) fn native(&self, value: NativeData) {
        if !value.valid(&self.scope.review) {
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
            if value.operation.status_revision < old.operation.status_revision {
                return;
            }
            if value.operation.status_revision == old.operation.status_revision {
                if &value != old {
                    drop(r);
                    self.unknown(p::Reason::CleanupUnknown);
                }
                return;
            }
            if old.retired {
                drop(r);
                self.unknown(p::Reason::CleanupUnknown);
                return;
            }
        }
        if value.retired {
            self.scope.retired.store(true, Ordering::Release);
            self.scope.control.detach_returned();
        }
        r.native = Some(value);
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
        let Some(data) = r
            .native
            .as_ref()
            .filter(|v| {
                v.operation.status_revision > r.history_acked && (!v.retired || r.caller_returned)
            })
            .cloned()
        else {
            return Ok(None);
        };
        let first = !r.history_started;
        r.history_claim = Some(data.clone());
        Ok(Some(History {
            entry: self.clone(),
            data,
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
        let native = r.native.as_ref();
        let stopped = self
            .scope
            .control
            .first()
            .ok()
            .flatten()
            .map(|(reason, _)| reason);
        let (state, settlement, outcome, reason, result) = if let Some(reason) = r.unknown {
            (
                p::State::Unknown,
                Settlement::Unknown,
                Some(p::Outcome::Unknown),
                reason,
                None,
            )
        } else if Self::settled(&r) {
            let n = native.ok_or(Error::StateUnknown)?;
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
                n.outcome,
                n.reason,
                n.result.clone(),
            )
        } else {
            let state = if native.is_some_and(|n| n.retired) {
                p::State::Finishing
            } else if stopped.is_some() {
                p::State::Stopping
            } else if native.is_some() {
                p::State::Running
            } else if r.claimed {
                p::State::Starting
            } else {
                p::State::Queued
            };
            (
                state,
                Settlement::Pending,
                None,
                stopped.unwrap_or(p::Reason::None),
                None,
            )
        };
        let status = p::Status {
            origin: self.input.origin.clone(),
            grant_id: self.input.grant_id.clone(),
            review_id: self.input.review_id.clone(),
            revision: r.revision,
            review: self.scope.review.clone(),
            state,
            settlement,
            reason,
            operation: native.map(|n| n.operation.clone()),
            outcome,
            result,
        };
        status.validate().map_err(|_| Error::StateUnknown)?;
        Ok(status)
    }
}
/// The existing synchronous relay calls returned only after its whole native
/// admission body returns. Drop is uncertainty, never an implied rejection.
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
        self.data.settlement()
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
        r.history_acked = self.data.operation.status_revision;
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

impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                lease: None,
                preparation: None,
                history: None,
                entries: Vec::with_capacity(p::REQUEST_LIMIT),
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
    pub(crate) fn can_allow(&self) -> Result<(), Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        if b.preparation.as_ref().is_some_and(|l| l.scope.occupied()) { return Err(Error::Busy); }
        if b.history.as_ref().is_some_and(|l|l.occupied()){return Err(Error::Busy);}
        if b.entries.len() >= p::REQUEST_LIMIT
            || b.entries.iter().any(|e| e.pending())
            || b.lease.as_ref().is_some_and(|l| {
                !l.scope.retired.load(Ordering::Acquire) || l.scope.control.first().is_err()
            })
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    pub(crate) fn allow(&self, scope: Arc<NativeScope>, id: Id) -> Result<p::Access, Error> {
        let now = Instant::now();
        if !scope.valid(now) {
            return Err(Error::Conflict);
        }
        let mut b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        if b.preparation.as_ref().is_some_and(|l| l.scope.occupied()) { return Err(Error::Busy); }
        if b.history.as_ref().is_some_and(|l|l.occupied()){return Err(Error::Busy);}
        if b.entries.len() >= p::REQUEST_LIMIT || b.entries.iter().any(|e| e.pending()) {
            return Err(Error::Busy);
        }
        if b.lease.as_ref().is_some_and(|l| {
            !l.scope.retired.load(Ordering::Acquire) || l.scope.control.first().is_err()
        }) {
            return Err(Error::Busy);
        }
        b.lease = Some(Arc::new(Lease {
            id,
            scope,
            entry: Mutex::new(None),
        }));
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
            .find(|e| e.origin().request_id == input.origin.request_id)
        {
            return match old.original() {
                Some(old) if old.input == input => old.status(),
                _ => Err(Error::Conflict),
            };
        }
        let lease = b.lease.as_ref().ok_or(Error::AccessDenied)?.clone();
        if lease.id != input.grant_id
            || lease.scope.review_id != input.review_id
            || lease.scope.project_id != input.origin.project_id
        {
            return Err(Error::AccessDenied);
        }
        if b.preparation.as_ref().is_some_and(|l| l.scope.occupied()) { return Err(Error::Busy); }
        if b.history.as_ref().is_some_and(|l|l.occupied()){return Err(Error::Busy);}
        if b.entries.len() >= p::REQUEST_LIMIT || b.entries.iter().any(|e| e.pending()) {
            return Err(Error::Busy);
        }
        lease.scope.current(false, Instant::now())?;
        let mut once = lease.entry.lock().map_err(|_| Error::StateUnknown)?;
        if once.is_some() {
            return Err(Error::AccessDenied);
        }
        let entry = Arc::new(Entry {
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
        *once = Some(Arc::downgrade(&entry));
        b.entries.push(StoredEntry::Original(entry.clone()));
        drop(once);
        lease.scope.changes.send_modify(|_| {});
        entry.status()
    }
    pub(crate) fn query(&self, q: &p::Query, cancel: bool) -> Result<p::Status, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        let e = b
            .entries
            .iter()
            .filter_map(StoredEntry::original)
            .find(|e| e.input.origin == *q)
            .ok_or(Error::Conflict)?
            .clone();
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
        for entry in b.entries.iter().filter_map(StoredEntry::original) {
            let mut r = entry.lock()?;
            if !r.claimed && r.unknown.is_none() {
                r.claimed = true;
                entry.changed(&mut r)?;
                return Ok(Some(Claim {
                    entry: entry.clone(),
                    returned: false,
                }));
            }
        }
        Ok(None)
    }
    pub(crate) fn entries(&self) -> Result<Vec<Arc<Entry>>, Error> {
        Ok(self.lock()?.entries.iter().filter_map(StoredEntry::original).cloned().collect())
    }
    pub(crate) fn access(&self) -> Result<p::Access, Error> {
        let b = self.lock()?;
        self.access_locked(&b)
    }
    fn access_locked(&self, b: &Book) -> Result<p::Access, Error> {
        let Some(l) = &b.lease else {
            return Ok(p::Access::empty());
        };
        let entry = l
            .entry
            .lock()
            .map_err(|_| Error::StateUnknown)?
            .as_ref()
            .and_then(Weak::upgrade);
        // Intent expiry belongs to the unused Prepared. It is not a fresh
        // execution deadline and cannot stop an already admitted 1200s owner.
        let current = entry.is_some() || l.scope.current(false, Instant::now()).is_ok();
        let status = entry.as_ref().map(|e| e.status()).transpose()?;
        let consumed = entry.is_some();
        let unknown = status
            .as_ref()
            .is_some_and(|s| s.state == p::State::Unknown)
            || status.is_none() && l.scope.control.first().is_err();
        let pending = status
            .as_ref()
            .is_some_and(|s| s.settlement != Settlement::Settled)
            || status.is_none() && !current && !l.scope.retired.load(Ordering::Acquire);
        let enabled = !b.closed && current && !consumed && !pending && !unknown;
        let remaining_ms = if enabled {
            u64::try_from(
                l.scope
                    .expires
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .unwrap_or(0)
            .min(p::INTENT_MS)
        } else {
            0
        };
        let out = p::Access {
            service_instance: Some(self.instance.clone()),
            project_id: Some(l.scope.project_id.clone()),
            grant_id: Some(l.id.clone()),
            review_id: Some(l.scope.review_id.clone()),
            review: Some(l.scope.review.clone()),
            enabled: enabled && remaining_ms > 0,
            remaining_ms,
            consumed,
            pending,
            unknown,
            request_id: entry.as_ref().map(|e| e.origin().request_id.clone()),
            status,
        };
        out.validate().map_err(|_| Error::StateUnknown)?;
        Ok(out)
    }
    pub(crate) fn revoke(&self, reason: p::Reason, at: Instant) -> Result<p::Access, Error> {
        let b = self.lock()?;
        if let Some(l) = &b.lease {
            l.scope.control.stop(reason, at);
        }
        if let Some(l) = &b.preparation { l.scope.control.stop(reason, at); }
        if let Some(l)=&b.history{l.stop(reason,at);}
        for e in &b.entries {
            if e.pending() {
                e.cancel(reason, at);
            }
        }
        self.access_locked(&b)
    }
    pub(crate) fn close(&self, at: Instant) {
        let _ = self.revoke(p::Reason::Shutdown, at);
        if let Ok(mut b) = self.lock() {
            b.closed = true;
        }
    }
    pub(crate) fn fence(&self) {
        self.failed.store(true, Ordering::Release);
        // STOP uses the original controls even after poisoning. No Host/Doc
        // IO and no new worker; poison recovery here grants no admission.
        let b = match self.book.lock() {
            Ok(b) => b,
            Err(e) => e.into_inner(),
        };
        let at = Instant::now();
        if let Some(l) = &b.lease {
            l.scope.control.unknown(at);
        }
        if let Some(l) = &b.preparation { l.scope.control.unknown(at); }
        if let Some(l)=&b.history{l.fence(at);}
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
                family: if matches!(e,StoredEntry::LocalHistory(_) | StoredEntry::LocalHistoryPreparation(_)){crate::service_request_catalogue::AdditionalFamily::LocalHistory}else{crate::service_request_catalogue::AdditionalFamily::Store},
                request_id: e.origin().request_id.clone(),
            })
            .collect())
    }
}

#[cfg(test)]
#[path = "service_store_tests.rs"]
mod tests;
