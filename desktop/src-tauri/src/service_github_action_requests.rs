//! One finite three-kind inbox. Facts are not a native permit or retirement.
use crate::{
    service_github_action_protocol as p,
    service_protocol::{Error, Id, OperationState, Settlement},
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::Instant,
};
#[path = "service_github_action_memory.rs"]
mod memory;
#[path = "service_github_activity_requests.rs"]
mod activity;
#[path = "service_counter_enrollment_requests.rs"]
pub(crate) mod enrollment;
pub(crate) use memory::retained_document_backing;

pub(crate) struct NativeScope {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) root: std::path::PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) input_revision: u64,
    pub(crate) review: p::Review,
    pub(crate) identity: Arc<()>,
    pub(crate) expires: Instant,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
    pub(crate) document: Weak<()>,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
    stop: Mutex<Option<(p::Reason, Instant)>>,
    failed: AtomicBool,
    retired: AtomicBool,
}
impl NativeScope {
    pub(crate) fn new(
        project_id: Id,
        runtime_id: String,
        root: std::path::PathBuf,
        device: u64,
        inode: u64,
        input_revision: u64,
        review: p::Review,
        identity: Arc<()>,
        expires: Instant,
        read: Arc<crate::service_version_reserve_requests::ReadPermission>,
        document: Weak<()>,
        changes: tokio::sync::watch::Sender<u32>,
    ) -> Arc<Self> {
        Arc::new(Self {
            project_id,
            runtime_id,
            root,
            device,
            inode,
            input_revision,
            review,
            identity,
            expires,
            read,
            document,
            changes,
            stop: Mutex::new(None),
            failed: AtomicBool::new(false),
            retired: AtomicBool::new(false),
        })
    }
    pub(crate) fn revoke(&self, why: p::Reason, at: Instant) {
        match self.stop.lock() {
            Ok(mut s) => {
                if s.is_none_or(|(_, old)| at < old) {
                    *s = Some((why, at))
                }
            }
            Err(_) => self.failed.store(true, Ordering::Release),
        }
        self.changes.send_modify(|_| {});
    }
    pub(crate) fn unused_closed(&self) {
        self.revoke(p::Reason::ContextChanged, Instant::now());
        self.retired.store(true, Ordering::Release);
    }
    pub(crate) fn first(
        &self,
        entered: bool,
        now: Instant,
    ) -> Result<Option<(p::Reason, Instant)>, Error> {
        if self.document.strong_count() == 0 {
            self.revoke(p::Reason::ContextChanged, now)
        }
        match self.read.stop(now) {
            Ok(Some((_, at))) => self.revoke(p::Reason::PermissionRevoked, at),
            Ok(None) => {}
            Err(_) => self.failed.store(true, Ordering::Release),
        }
        if !entered && now >= self.expires {
            self.revoke(p::Reason::Expired, self.expires)
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        self.stop
            .lock()
            .map(|s| *s)
            .map_err(|_| Error::StateUnknown)
    }
    pub(crate) fn current(&self, entered: bool) -> Result<(), Error> {
        if self.first(entered, Instant::now())?.is_some()
            || !entered && self.retired.load(Ordering::Acquire)
        {
            Err(Error::AccessDenied)
        } else {
            Ok(())
        }
    }
    fn valid(&self) -> bool {
        let now = Instant::now();
        retained_document_backing().is_some()
            && self.review.valid()
            // These are new retained comparison copies, not new authority. A
            // short value with an oversized allocation cannot enter the fixed
            // row quote. Keep every old row; never borrow a retired-row credit.
            && self.project_id.retained_bytes() <= 64
            && self.runtime_id.capacity() <= 128
            && self.root.capacity() <= 8192
            && self.review.retained_fits()
            && !self.runtime_id.is_empty()
            && self.runtime_id.len() <= 64
            && self
                .runtime_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            && self.root.is_absolute()
            && self.root.as_os_str().len() <= 4096
            && self.input_revision > 0
            && self.expires > now
            && self.expires.duration_since(now).as_millis() <= p::INTENT_MS as u128
            && self.current(false).is_ok()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Running,
    Returned,
    NeverAdmitted,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fact {
    pub(crate) revision: u32,
    pub(crate) admission: Admission,
    pub(crate) reason: p::Reason,
    pub(crate) effect: p::Effect,
}
impl Fact {
    pub(crate) fn state(&self) -> OperationState {
        match (self.admission, self.reason) {
            (Admission::Running, _) => OperationState::Running,
            (_, p::Reason::None) => OperationState::Succeeded,
            (
                _,
                p::Reason::UserCancelled
                | p::Reason::PermissionRevoked
                | p::Reason::ContextChanged
                | p::Reason::Shutdown,
            ) => OperationState::Cancelled,
            _ => OperationState::Failed,
        }
    }
    pub(crate) fn settlement(&self) -> Settlement {
        if self.admission == Admission::Running {
            Settlement::Pending
        } else {
            Settlement::Settled
        }
    }
}
#[path="service_github_dispatch_requests.rs"]
mod dispatch;
struct Row {
    revision: u32,
    claimed: bool,
    entered: bool,
    operation: Option<String>,
    go: bool,
    caller_returned: bool,
    fact: Option<Fact>,
    history_started: bool,
    history_ack: u32,
    history_claim: Option<Fact>,
    unknown: Option<p::Reason>,
    observed_stop: Option<p::Reason>,
    snapshot: Option<Arc<dispatch::Snapshot>>,
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
    pub(crate) fn origin(&self) -> &p::Query {
        &self.input.origin
    }
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.scope.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    fn change(&self, r: &mut Row) -> Result<(), Error> {
        let Some(next) = r.revision.checked_add(1).filter(|n| *n < u32::MAX) else {
            self.scope.failed.store(true, Ordering::Release);
            r.unknown.get_or_insert(p::Reason::CleanupUnknown);
            self.scope.changes.send_modify(|_| {});
            return Err(Error::StateUnknown);
        };
        r.revision = next;
        self.scope.changes.send_modify(|_| {});
        Ok(())
    }
    fn ended(r: &Row) -> bool {
        r.unknown.is_none()
            && r.caller_returned
            && r.fact.as_ref().is_some_and(|f| {
                f.admission != Admission::Running
                    && r.history_ack >= f.revision
                    && r.history_claim.is_none()
            })
    }
    pub(crate) fn pending(&self) -> bool {
        self.lock().map_or(true, |r| {
            !Self::ended(&r) || self.scope.failed.load(Ordering::Acquire)
        })
    }
    pub(crate) fn unknown(&self, why: p::Reason) {
        self.scope.failed.store(true, Ordering::Release);
        if let Ok(mut r) = self.lock() {
            if r.unknown.is_none() {
                r.unknown = Some(why);
                let _ = self.change(&mut r);
            }
        }
    }
    pub(crate) fn cancel(&self, why: p::Reason, at: Instant) {
        if !self.lock().is_ok_and(|r| Self::ended(&r)) {
            self.scope.revoke(why, at)
        }
    }
    fn first(&self) -> Result<Option<(p::Reason, Instant)>, Error> {
        let entered = self.lock()?.entered;
        self.scope.first(entered, Instant::now())
    }
    pub(crate) fn first_reason(&self) -> Option<p::Reason> {
        self.first().ok().flatten().map(|(why, _)| why)
    }
    pub(crate) fn first_stop(&self) -> Option<(bool, Instant)> {
        match self.first() {
            Ok(Some((_, at))) => Some((false, at)),
            Ok(None) => None,
            Err(_) => Some((true, self.submitted)),
        }
    }
    pub(crate) fn current(&self, armed: bool) -> Result<(), Error> {
        let r = self.lock()?;
        if !r.claimed
            || r.unknown.is_some()
            || r.operation.is_some() != armed
            || r.fact
                .as_ref()
                .is_some_and(|f| f.admission != Admission::Running)
        {
            return Err(Error::Conflict);
        }
        let entered = r.entered;
        drop(r);
        self.scope.current(entered)
    }
    // Called immediately before entering the existing Supervisor admission, not
    // from its returned status. A failed/ambiguous admission is never NotSent.
    pub(crate) fn entering(&self) -> Result<(), Error> {
        self.current(false)?;
        let mut r = self.lock()?;
        if r.entered {
            return Err(Error::Conflict);
        }
        r.entered = true;
        self.change(&mut r)
    }
    pub(crate) fn arm(&self, id: &str) -> Result<(), Error> {
        self.current(false)?;
        let mut r = self.lock()?;
        if !r.entered || !self.scope.review.kind().operation(id) {
            return Err(Error::Conflict);
        }
        r.operation = Some(id.into());
        self.set_fact(
            &mut r,
            Admission::Running,
            p::Reason::None,
            self.scope.review.kind().initial_effect(),
        )
    }
    fn set_fact(
        &self,
        r: &mut Row,
        admission: Admission,
        reason: p::Reason,
        effect: p::Effect,
    ) -> Result<(), Error> {
        self.change(r)?;
        r.fact = Some(Fact {
            revision: r.revision,
            admission,
            reason,
            effect,
        });
        Ok(())
    }
    pub(crate) fn go(&self, id: &str) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.operation.as_deref() != Some(id) || r.go || r.unknown.is_some() {
            return Err(Error::StateUnknown);
        }
        r.go = true;
        self.set_fact(
            &mut r,
            Admission::Running,
            p::Reason::None,
            self.scope.review.kind().go_effect(),
        )
    }
    // ONLY the original typed Connection accept_* tail invokes this. Its actual
    // Supervisor receipt has returned; public status cannot call this method.
    pub(crate) fn returned_native(&self, id: &str, reason: p::Reason, effect: p::Effect) {
        self.returned_native_snapshot(id, reason, effect, None)
    }
    fn returned_native_snapshot(&self, id: &str, reason: p::Reason, effect: p::Effect,
        snapshot: Option<Arc<p::activity::Snapshot>>) {
        // Existing Activity call consumes its sole Arc; never keep both result types.
        let snapshot = snapshot.map(|s| Arc::new(dispatch::Snapshot::Activity(Arc::unwrap_or_clone(s))));
        self.returned_native_value(id,reason,effect,snapshot)
    }
    fn returned_native_value(&self,id:&str,reason:p::Reason,mut effect:p::Effect,snapshot:Option<Arc<dispatch::Snapshot>>) {
        let Ok(mut r) = self.lock() else { return };
        if r.unknown.is_some() {
            return;
        }
        if r.operation.as_deref() != Some(id)
            || r.fact
                .as_ref()
                .is_none_or(|f| f.admission != Admission::Running)
            || !effect.valid_for(self.scope.review.kind())
            || !dispatch::valid(&self.scope.review, reason, snapshot.as_deref())
            || (self.scope.review.kind() == p::Kind::ActivityOverview || self.scope.review.kind().dispatch_family() || self.scope.review.kind().enrollment_family() || self.scope.review.kind().operation_family()) && reason == p::Reason::None && !r.go
            || matches!(
                reason,
                p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable
            )
        {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        if r.go && effect == self.scope.review.kind().initial_effect() {
            effect = self.scope.review.kind().go_effect()
        }
        if self
            .set_fact(&mut r, Admission::Returned, reason, effect)
            .is_err()
        {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        r.snapshot = snapshot;
        self.scope.retired.store(true, Ordering::Release);
    }
    fn never_admitted(&self, why: p::Reason) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed
            || r.entered
            || r.operation.is_some()
            || r.fact.is_some()
            || r.unknown.is_some()
            || matches!(
                why,
                p::Reason::None | p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable
            )
        {
            return Err(Error::StateUnknown);
        }
        self.set_fact(&mut r, Admission::NeverAdmitted, why, self.scope.review.kind().initial_effect())?;
        self.scope.retired.store(true, Ordering::Release);
        Ok(())
    }
    fn caller_returned(&self) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed || r.caller_returned || !r.entered && r.fact.is_none() {
            return Err(Error::StateUnknown);
        }
        r.caller_returned = true;
        self.change(&mut r)
    }
    pub(crate) fn claim_history(self: &Arc<Self>) -> Result<Option<History>, Error> {
        let mut r = self.lock()?;
        if self.scope.failed.load(Ordering::Acquire) || r.unknown.is_some() || r.history_claim.is_some() {
            return Ok(None);
        }
        let Some(f) = r
            .fact
            .as_ref()
            .filter(|f| {
                f.revision > r.history_ack
                    && (f.admission == Admission::Running || r.caller_returned)
            })
            .cloned()
        else {
            return Ok(None);
        };
        let first = !r.history_started;
        r.history_claim = Some(f.clone());
        Ok(Some(History {
            entry: self.clone(),
            fact: f,
            first,
            returned: false,
        }))
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        let ended = self.lock().is_ok_and(|r| Self::ended(&r));
        if !ended {
            let _ = self.first();
        }
        let mut r = self.lock()?;
        if self.scope.failed.load(Ordering::Acquire) && r.unknown.is_none() {
            r.unknown = Some(p::Reason::CleanupUnknown);
            self.change(&mut r)?;
        }
        let stop = self
            .scope
            .stop
            .lock()
            .map_err(|_| Error::StateUnknown)?
            .map(|s| s.0);
        // A cancelled/expired READ is sampled on the SAME original. Changing
        // public STOP DATA must also advance its revision, without claiming a
        // native return or overwriting an already returned terminal fact.
        if !Self::ended(&r) && r.unknown.is_none() && r.observed_stop != stop {
            r.observed_stop = stop;
            self.change(&mut r)?;
        }
        let f = r.fact.as_ref();
        let (state, settlement, reason) = if let Some(why) = r.unknown {
            (p::State::Unknown, Settlement::Unknown, why)
        } else if Self::ended(&r) {
            let why = f.ok_or(Error::StateUnknown)?.reason;
            (
                if why == p::Reason::None {
                    p::State::Complete
                } else if matches!(
                    why,
                    p::Reason::UserCancelled
                        | p::Reason::PermissionRevoked
                        | p::Reason::ContextChanged
                        | p::Reason::Shutdown
                ) {
                    p::State::Cancelled
                } else {
                    p::State::Refused
                },
                Settlement::Settled,
                why,
            )
        } else {
            (
                if f.is_some_and(|f| f.admission != Admission::Running) {
                    p::State::Finishing
                } else if stop.is_some() {
                    p::State::Stopping
                } else if r.operation.is_some() {
                    p::State::Running
                } else if r.claimed {
                    p::State::Starting
                } else {
                    p::State::Queued
                },
                Settlement::Pending,
                stop.unwrap_or(p::Reason::None),
            )
        };
        let s = p::Status {
            origin: self.input.origin.clone(),
            grant_id: self.input.grant_id.clone(),
            review: self.scope.review.clone(),
            revision: r.revision,
            state,
            settlement,
            operation_id: r.operation.clone(),
            reason,
            effect: match f.map_or(self.scope.review.kind().initial_effect(), |f| f.effect) {
                // Retain the native fact, but expose the new success label only
                // after caller+history return. Unknown/Finishing remain honest
                // about a possibly applied CAS, never NotSent after real GO.
                p::Effect::LocalMappingObserved | p::Effect::SettingsReadbackObserved if state != p::State::Complete => p::Effect::PotentiallyApplied,
                effect => effect,
            },
            never_admitted: f.is_some_and(|f| f.admission == Admission::NeverAdmitted)
                && state != p::State::Unknown,
            do_not_replay: true,
            snapshot: if state == p::State::Complete { match r.snapshot.as_deref() { Some(dispatch::Snapshot::Activity(s))=>Some(s.clone()),_=>None } } else { None },
            result: match r.snapshot.as_deref() {
                Some(dispatch::Snapshot::Dispatch(s)) if state == p::State::Complete
                    || matches!(s, p::dispatch::Snapshot::Enrollment(_) | p::dispatch::Snapshot::RemoteSettings(_))
                       && matches!(state, p::State::Refused | p::State::Cancelled)
                    || matches!(s,p::dispatch::Snapshot::Operation(data) if data.valid_row(self.scope.review.kind(),state,reason,f.map_or(self.scope.review.kind().initial_effect(),|f|f.effect))) => Some(s.clone()),
                _ => None,
            },
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
    pub(crate) fn returned(mut self, result: Result<(), p::Reason>) {
        let r = match result {
            Ok(()) => Ok(()),
            Err(why) => self.entry.never_admitted(why),
        }
        .and_then(|_| self.entry.caller_returned());
        if r.is_err() {
            self.entry.unknown(p::Reason::CleanupUnknown)
        }
        self.returned = true
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::CleanupUnknown)
        }
    }
}
pub(crate) struct History {
    entry: Arc<Entry>,
    pub(crate) fact: Fact,
    pub(crate) first: bool,
    returned: bool,
}
impl History {
    pub(crate) fn returned(mut self, result: Result<(), Error>) -> Result<(), Error> {
        if let Err(e) = result {
            self.entry.unknown(p::Reason::HistoryUnavailable);
            self.returned = true;
            return Err(e);
        }
        let mut r = self.entry.lock()?;
        if r.history_claim.as_ref() != Some(&self.fact) {
            drop(r);
            self.entry.unknown(p::Reason::HistoryUnavailable);
            self.returned = true;
            return Err(Error::StateUnknown);
        }
        r.history_ack = self.fact.revision;
        r.history_started = true;
        r.history_claim = None;
        self.entry.change(&mut r)?;
        self.returned = true;
        Ok(())
    }
}
impl Drop for History {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::HistoryUnavailable)
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
    pub(crate) fn allow(&self, scope: Arc<NativeScope>, id: Id) -> Result<p::Access, Error> {
        if !scope.valid() {
            return Err(Error::Conflict);
        }
        let mut b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        if b.entries.len() >= p::REQUEST_LIMIT
            || b.entries.iter().any(|e| e.pending())
            || b.lease.as_ref().is_some_and(|l| {
                !l.scope.retired.load(Ordering::Acquire) || l.scope.failed.load(Ordering::Acquire)
            })
        {
            return Err(Error::Busy);
        }
        b.lease = Some(Lease {
            id,
            scope,
            entry: None,
        });
        self.access_locked(&b)
    }
    pub(crate) fn submit(&self, input: p::Submit) -> Result<p::Status, Error> {
        let mut b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(e) = b
            .entries
            .iter()
            .find(|e| e.origin().request_id == input.origin.request_id)
        {
            return if e.input == input {
                e.status()
            } else {
                Err(Error::Conflict)
            };
        }
        if b.entries.len() >= p::REQUEST_LIMIT || b.entries.iter().any(|e| e.pending()) {
            return Err(Error::Busy);
        }
        let l = b.lease.as_mut().ok_or(Error::AccessDenied)?;
        if l.id != input.grant_id
            || l.scope.project_id != input.origin.project_id
            || l.entry.is_some()
        {
            return Err(Error::AccessDenied);
        }
        l.scope.current(false)?;
        let e = Arc::new(Entry {
            input,
            scope: l.scope.clone(),
            submitted: Instant::now(),
            row: Mutex::new(Row {
                revision: 1,
                claimed: false,
                entered: false,
                operation: None,
                go: false,
                caller_returned: false,
                fact: None,
                history_started: false,
                history_ack: 0,
                history_claim: None,
                unknown: None,
                observed_stop: None,
                snapshot: None,
            }),
        });
        l.entry = Some(Arc::downgrade(&e));
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
            .find(|e| e.origin() == q)
            .cloned()
            .ok_or(Error::Conflict)?;
        drop(b);
        if cancel {
            e.cancel(p::Reason::UserCancelled, Instant::now())
        }
        e.status()
    }
    pub(crate) fn query_for_document(
        &self,
        q: &p::Query,
        document: &Arc<()>,
    ) -> Result<p::Status, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        let e = b
            .entries
            .iter()
            .find(|e| e.origin() == q)
            .cloned()
            .ok_or(Error::Conflict)?;
        drop(b);
        if e.scope
            .document
            .upgrade()
            .is_none_or(|d| !Arc::ptr_eq(&d, document))
        {
            return Err(Error::AccessDenied);
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
            // Foreground enrollment waits for its exact retained MAIN caller.
            // A stopped, never-claimed row can still receive a real closed
            // nonentry/caller/history return through this original relay.
            let enrollment_waits = !r.claimed && r.unknown.is_none()
                && e.scope.review.kind().enrollment_family()
                && e.scope.first(false, Instant::now())?.is_none();
            if !r.claimed && r.unknown.is_none() && !enrollment_waits {
                r.claimed = true;
                e.change(&mut r)?;
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
    pub(crate) fn scope(&self) -> Result<Option<Arc<NativeScope>>, Error> {
        Ok(self.lock()?.lease.as_ref().map(|l| l.scope.clone()))
    }
    pub(crate) fn access(&self) -> Result<p::Access, Error> {
        let book = self.lock()?;
        self.access_locked(&book)
    }
    fn access_locked(&self, b: &Book) -> Result<p::Access, Error> {
        let Some(l) = &b.lease else {
            return Ok(p::Access::empty());
        };
        let e = l.entry.as_ref().and_then(Weak::upgrade);
        let s = e.as_ref().map(|e| e.status()).transpose()?;
        let consumed = l.entry.is_some();
        if consumed && s.is_none() {
            return Err(Error::StateUnknown);
        }
        let pending = s
            .as_ref()
            .is_some_and(|s| s.settlement != Settlement::Settled)
            || !consumed
                && l.scope.current(false).is_err()
                && !l.scope.retired.load(Ordering::Acquire);
        let unknown = s.as_ref().is_some_and(|s| s.state == p::State::Unknown)
            || l.scope.failed.load(Ordering::Acquire);
        let enabled =
            !b.closed && !consumed && !pending && !unknown && l.scope.current(false).is_ok();
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
        let a = p::Access {
            service_instance: Some(self.instance.clone()),
            project_id: Some(l.scope.project_id.clone()),
            grant_id: Some(l.id.clone()),
            review: Some(l.scope.review.clone()),
            enabled: enabled && remaining_ms > 0,
            remaining_ms,
            consumed,
            pending,
            unknown,
            status: s,
        };
        a.validate().map_err(|_| Error::StateUnknown)?;
        Ok(a)
    }
    pub(crate) fn revoke(&self, why: p::Reason, at: Instant) -> Result<p::Access, Error> {
        let b = self.lock()?;
        if let Some(l) = &b.lease {
            l.scope.revoke(why, at)
        }
        for e in &b.entries {
            e.cancel(why, at)
        }
        self.access_locked(&b)
    }
    pub(crate) fn close(&self, at: Instant) {
        let _ = self.revoke(p::Reason::Shutdown, at);
        if let Ok(mut b) = self.lock() {
            b.closed = true
        }
    }
    pub(crate) fn fence(&self) {
        self.failed.store(true, Ordering::Release);
        let b = match self.book.lock() {
            Ok(v) => v,
            Err(e) => e.into_inner(),
        };
        if let Some(l) = &b.lease {
            l.scope.failed.store(true, Ordering::Release)
        }
        for e in &b.entries {
            e.unknown(p::Reason::HistoryUnavailable)
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
                family: crate::service_request_catalogue::AdditionalFamily::GitHubAction,
                request_id: e.origin().request_id.clone(),
            })
            .collect())
    }
}
#[cfg(test)]
#[path = "service_github_action_requests_tests.rs"]
mod tests;
