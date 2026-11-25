//! Closed local-history sibling in the SAME Store32 Book. Retained rows own
//! bounded DATA and weak native comparison, never the consent/source graph.
use super::preparation::StoredEntry;
pub(crate) use super::Control;
use super::{Book, Inbox};
use crate::{
    service_local_history_protocol as p,
    service_protocol::{Error, Id, OperationState, Settlement},
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::Instant,
};
#[path = "service_local_history_prepare_requests.rs"]
pub(crate) mod preparation;
pub(super) enum Allowed {
    Start(Arc<Lease>),
    Preparation(Arc<preparation::Entry>),
}
impl Allowed {
    pub(super) fn occupied(&self) -> bool {match self {Self::Start(l)=>l.occupied(),Self::Preparation(e)=>e.pending()}}
    pub(super) fn stop(&self, reason:p::Reason, at:Instant) {match self {Self::Start(l)=>l.scope.control.stop(reason,at),Self::Preparation(e)=>e.cancel(reason,at)}}
    pub(super) fn fence(&self, at:Instant) {match self {Self::Start(l)=>l.scope.control.unknown(at),Self::Preparation(e)=>e.unknown(p::Reason::HistoryUnavailable)}}
}
pub(crate) struct Scope {
    pub(crate) preparation: Option<Weak<preparation::Entry>>,
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
impl Scope {
    pub(crate) fn matches(&self, p: &crate::agent_identity_requests::SavedPoint) -> bool {
        p.project_id == self.project_id
            && p.runtime_id == self.runtime_id
            && p.root == self.root
            && p.device == self.device
            && p.inode == self.inode
            && p.revision == self.observation_revision
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
            && self.review.heap() <= 36
            && self.runtime_id.capacity() <= 64
            && self.root.capacity() <= 4096
            && (1..=64).contains(&self.runtime_id.len())
            && self
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && self.expires > now
            && self.expires.saturating_duration_since(now).as_millis() <= p::INTENT_MS as u128
            && self.root.is_absolute()
            && self.root.as_os_str().len() <= 4096
            && self.current(false, now).is_ok()
    }
}
pub(super) struct Lease {
    pub(super) id: Id,
    pub(super) scope: Arc<Scope>,
    entry: Mutex<Option<Weak<Entry>>>,
}
impl Lease {
    pub(super) fn occupied(&self) -> bool {
        !self.scope.retired.load(Ordering::Acquire) || self.scope.control.first().is_err()
    }
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
            && self.result.as_ref().is_none_or(|v| {
                v.bounded(review)
                    && v.heap()
                        .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
                        .is_some_and(|n| n <= 8192)
            })
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
    scope: Arc<Scope>,
    submitted: Instant,
    row: Mutex<Row>,
}
impl Entry {
    pub(crate) fn scope(&self) -> &Arc<Scope> {
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
    pub(crate) fn can_allow_history(&self) -> Result<(),Error> {self.can_allow_history_from(None)}
    pub(crate) fn can_allow_history_from(&self, preparation:Option<&Arc<preparation::Entry>>) -> Result<(), Error> {
        let b=self.lock()?;
        if b.closed{return Err(Error::Unavailable);}
        let except=preparation.filter(|e|preparation::excludes(&b,e,false));
        if preparation.is_some() && except.is_none(){return Err(Error::AccessDenied);}
        if b.preparation.as_ref().is_some_and(|l|l.scope.occupied())
            || b.lease.as_ref().is_some_and(|l|!l.scope.retired.load(Ordering::Acquire)||l.scope.control.first().is_err())
            || b.entries.len()>=super::p::REQUEST_LIMIT
            || b.entries.iter().any(|e|e.pending() && !except.is_some_and(|old|e.history_preparation().is_some_and(|e|Arc::ptr_eq(e,old))))
            || b.history.as_ref().is_some_and(|l|l.occupied())&&except.is_none(){return Err(Error::Busy);}
        Ok(())
    }
    pub(crate) fn allow_history(&self,scope:Arc<Scope>,id:Id)->Result<p::Access,Error>{
        if !scope.valid(Instant::now()){return Err(Error::Conflict);}
        let original=scope.preparation.as_ref().map(|e|e.upgrade().ok_or(Error::Conflict)).transpose()?;
        let mut b=self.lock()?;
        if b.closed{return Err(Error::Unavailable);}
        let except=original.as_ref().filter(|e|preparation::excludes(&b,e,true));
        if original.is_some()&&except.is_none(){return Err(Error::AccessDenied);}
        if b.preparation.as_ref().is_some_and(|l|l.scope.occupied())
            ||b.lease.as_ref().is_some_and(|l|!l.scope.retired.load(Ordering::Acquire)||l.scope.control.first().is_err())
            ||b.entries.len()>=super::p::REQUEST_LIMIT
            ||b.entries.iter().any(|e|e.pending()&&!except.is_some_and(|old|e.history_preparation().is_some_and(|e|Arc::ptr_eq(e,old))))
            ||b.history.as_ref().is_some_and(Allowed::occupied)&&except.is_none(){return Err(Error::Busy);}
        if let Some(e)=except {e.finish_handoff()?;}
        b.history=Some(Allowed::Start(Arc::new(Lease{id,scope,entry:Mutex::new(None)})));
        self.history_access_locked(&b)
    }
    pub(crate) fn submit_history(
        &self,
        input: p::Submit,
        submitted: Instant,
    ) -> Result<p::Status, Error> {
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
            return match old.history() {
                Some(old) if old.input == input => old.status(),
                _ => Err(Error::Conflict),
            };
        }
        let lease = match &b.history {Some(Allowed::Start(l))=>l.clone(),_=>return Err(Error::AccessDenied)};
        if lease.id != input.grant_id
            || lease.scope.review_id != input.review_id
            || lease.scope.project_id != input.origin.project_id
        {
            return Err(Error::AccessDenied);
        }
        if b.preparation.as_ref().is_some_and(|l| l.scope.occupied()) {
            return Err(Error::Busy);
        }
        if b.lease.as_ref().is_some_and(|l| {
            !l.scope.retired.load(Ordering::Acquire) || l.scope.control.first().is_err()
        }) {
            return Err(Error::Busy);
        }
        if b.entries.len() >= super::p::REQUEST_LIMIT || b.entries.iter().any(|e| e.pending()) {
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
        b.entries.push(StoredEntry::LocalHistory(entry.clone()));
        drop(once);
        lease.scope.changes.send_modify(|_| {});
        entry.status()
    }
    pub(crate) fn query_history(&self, q: &p::Query, cancel: bool) -> Result<p::Status, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        let e = b
            .entries
            .iter()
            .filter_map(StoredEntry::history)
            .find(|e| e.input.origin == *q)
            .ok_or(Error::Conflict)?
            .clone();
        drop(b);
        if cancel {
            e.cancel(p::Reason::UserCancelled, Instant::now());
        }
        e.status()
    }
    pub(crate) fn claim_local_history(&self) -> Result<Option<Claim>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Ok(None);
        }
        for entry in b.entries.iter().filter_map(StoredEntry::history) {
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
    pub(crate) fn history_entries(&self) -> Result<Vec<Arc<Entry>>, Error> {
        Ok(self
            .lock()?
            .entries
            .iter()
            .filter_map(StoredEntry::history)
            .cloned()
            .collect())
    }
    pub(crate) fn history_access(&self) -> Result<p::Access, Error> {
        let b = self.lock()?;
        self.history_access_locked(&b)
    }
    fn history_access_locked(&self, b: &Book) -> Result<p::Access, Error> {
        let Some(Allowed::Start(l)) = &b.history else {
            return Ok(p::Access::empty());
        };
        let entry = l
            .entry
            .lock()
            .map_err(|_| Error::StateUnknown)?
            .as_ref()
            .and_then(Weak::upgrade);
        // Intent expiry belongs to the unused Prepared. It is not a fresh
        // execution deadline and cannot stop an already admitted 60s original history owner.
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
}

// SAME original eight IPC workers, not eight new response reservations.
// Two typed Access/Status returns and their exact bounded result heaps cover
// dispatch/validation; common enum cells and small request decode are pooled.
pub(crate) const IPC_WORKER_BACKING: usize = p::STATUS_LIMIT
    + 2 * (std::mem::size_of::<p::Access>() + std::mem::size_of::<p::Status>() + 8192)
    + 4096;
const SCOPE_HEAP: usize = 4096 + 64 + 36 + 32 * 24 + 512;
const HISTORY_EXTRA: usize = 512 * 1024;
fn quoted_backing(entry: usize, scope: usize, control: usize, native: usize) -> Option<usize> {
    // Entry includes both inline Native cells. Heap copies (native, claimed
    // history, outgoing callback) remain independently reserved in joint32.
    if entry
        .checked_add(scope)?
        .checked_add(control)?
        .checked_add(SCOPE_HEAP)?
        > 8192
        || native > 8192
    {
        return None;
    }
    let rows = super::p::REQUEST_LIMIT.checked_mul(3 * 8192)?;
    // Keep every byte of the accepted StorePreparation proof: old replies are
    // NOT credited here just because History joins the separate shared8 max.
    let old_ipc =
        8usize.checked_mul(crate::service_protocol::REQUEST_BYTES + 2 * super::p::STATUS_LIMIT)?;
    let conversion = 2 * 65536 + 32768;
    let fixed = 128 * 1024;
    let old_gui = 3 * crate::service_store_prepare_protocol::RAW_NODES * 512
        + crate::service_store_prepare_protocol::RAW_LIMIT;
    let total = rows
        .checked_add(old_ipc)?
        .checked_add(conversion)?
        .checked_add(fixed)?
        .checked_add(old_gui)?
        .checked_add(HISTORY_EXTRA)?;
    // History's extra term includes two weak native grants (64KiB), three
    // public-return trees (<=384 typed nodes,256 bytes/node plus all24KiB text
    // and one8KiB report), and all three32-node RAW decode/validation copies.
    let history = 64 * 1024 + 3 * (384 * 256 + p::STATUS_LIMIT + 8192)
        + 3 * p::RAW_NODES * 512 + 3 * crate::service_local_history_prepare_protocol::COMPARISON_BYTES;
    (history <= HISTORY_EXTRA && total <= super::p::DOCUMENT_BACKING)
        .then_some(super::p::DOCUMENT_BACKING)
}
pub(crate) fn retained_document_backing() -> Option<usize> {
    preparation::cell_backing()?;
    quoted_backing(
        std::mem::size_of::<Entry>(),
        std::mem::size_of::<Scope>(),
        std::mem::size_of::<Control>(),
        std::mem::size_of::<NativeData>(),
    )
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    #[test]
    fn local_history_cell_quote_checks_real_types_and_overflow_without_crediting_old_pool() {
        assert_eq!(
            retained_document_backing(),
            Some(super::super::p::DOCUMENT_BACKING)
        );
        let actual = [
            std::mem::size_of::<Entry>(),
            std::mem::size_of::<Scope>(),
            std::mem::size_of::<Control>(),
            std::mem::size_of::<NativeData>(),
        ];
        for at in 0..4 {
            let mut bad = actual;
            bad[at] = usize::MAX;
            assert!(quoted_backing(bad[0], bad[1], bad[2], bad[3]).is_none());
        }
        assert!(quoted_backing(8192, actual[1], actual[2], actual[3]).is_none());
        assert_eq!(HISTORY_EXTRA, 512 * 1024);
    }
}
