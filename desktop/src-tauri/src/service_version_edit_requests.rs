//! One immutable prepared-Apply lease and finite request metadata. No EditOwner,
//! source reader, executor, durable store or complete native projection here.
use crate::{
    agent_identity_requests::SavedPoint,
    service_protocol::{Error, Id, Settlement},
    service_version_edit_protocol as p,
    service_version_reserve_requests::ReadPermission,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::Instant,
};
use tokio::sync::{watch, Notify};

pub(crate) const DOCUMENT_BACKING: usize = 32
    * (2 * p::STATUS_BYTES + 8192 + std::mem::size_of::<Entry>())
    + 32 * 128
    + 8 * (crate::service_protocol::REQUEST_BYTES + p::REQUEST_BYTES + 4 * p::STATUS_BYTES)
    + 2 * p::STATUS_BYTES
    + crate::service_version_edit_prepare_requests::DOCUMENT_BACKING;

pub(crate) struct Scope {
    pub saved: SavedPoint,
    pub read: Arc<ReadPermission>,
}
struct LeaseState {
    revoked: Option<Instant>,
    spent: bool,
    claimed: bool,
    entry: Weak<Entry>,
}
pub(crate) struct Lease {
    pub id: Id,
    pub nonce: Id,
    pub scope: Scope,
    pub review: p::Review,
    pub end: Instant,
    wake: Weak<Notify>,
    state: Mutex<LeaseState>,
    failed: AtomicBool,
    preparation: std::sync::OnceLock<Weak<crate::service_version_edit_prepare_requests::Entry>>,
}
impl Lease {
    pub(crate) fn new(
        id: Id,
        nonce: Id,
        scope: Scope,
        review: p::Review,
        end: Instant,
        wake: Weak<Notify>,
    ) -> Result<Arc<Self>, Error> {
        review.validate()?;
        if scope.read.stop(Instant::now())?.is_some()
            || Instant::now() >= end
            || wake.strong_count() == 0
        {
            return Err(Error::Conflict);
        }
        Ok(Arc::new(Self {
            id,
            nonce,
            scope,
            review,
            end,
            wake,
            state: Mutex::new(LeaseState {
                revoked: None,
                spent: false,
                claimed: false,
                entry: Weak::new(),
            }),
            failed: AtomicBool::new(false),
            preparation: std::sync::OnceLock::new(),
        }))
    }
    fn lock(&self) -> Result<MutexGuard<'_, LeaseState>, Error> {
        self.state.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    pub(crate) fn wake(&self) {
        if let Some(w) = self.wake.upgrade() {
            w.notify_waiters();
        }
    }
    fn live_locked(&self, s: &LeaseState, now: Instant) -> Result<bool, Error> {
        Ok(!self.failed.load(Ordering::Acquire)
            && !s.spent
            && !s.claimed
            && s.revoked.is_none()
            && now < self.end
            && self.wake.strong_count() != 0
            && self.scope.read.stop(now)?.is_none())
    }
    pub(crate) fn live(&self, now: Instant) -> Result<bool, Error> {
        self.live_locked(&*self.lock()?, now)
    }
    pub(crate) fn revoke(&self, at: Instant) -> Result<(), Error> {
        let mut s = self.lock()?;
        s.revoked = Some(s.revoked.map_or(at, |old| old.min(at)));
        drop(s);
        self.wake();
        Ok(())
    }
    /// Ordinary GUI wins only before Submit. A withdrawn unused permission's
    /// subsequent expiry cannot STOP that ordinary original.
    pub(crate) fn gui_claim(&self) -> Result<(), Error> {
        let mut s = self.lock()?;
        if s.claimed || s.spent {
            return Err(Error::Busy);
        }
        if let Some(p) = self.preparation()? { p.gui_claim(&self.review)?; }
        s.spent = true;
        drop(s);
        self.wake();
        Ok(())
    }
    /// Serialize Submit against the original native final/Unknown publication.
    /// A late Submit must not land after that callback observed no Entry.
    pub(crate) fn seal(&self) -> Result<Option<Arc<Entry>>, Error> {
        let mut s = self.lock()?;
        s.spent = true;
        if s.claimed {
            s.entry.upgrade().map(Some).ok_or(Error::StateUnknown)
        } else {
            Ok(None)
        }
    }
    pub(crate) fn entry(&self) -> Result<Option<Arc<Entry>>, Error> {
        let s = self.lock()?;
        if !s.claimed {
            return Ok(None);
        }
        s.entry.upgrade().map(Some).ok_or(Error::StateUnknown)
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Result<Option<Instant>, Error> {
        let s = self.lock()?;
        if !s.claimed {
            return Ok(None);
        } // Includes GUI winner and unused revoked allowance.
        let entry = s.entry.upgrade().ok_or(Error::StateUnknown)?;
        let row = entry.lock()?;
        if row.returned {
            return Ok(None);
        }
        if self.failed.load(Ordering::Acquire) || self.wake.strong_count() == 0 {
            return Err(Error::StateUnknown);
        }
        let mut stop = row.stop;
        for at in [
            s.revoked,
            self.scope.read.stop(now)?.map(|(_, at)| at),
            (!row.preclaimed && now >= self.end).then_some(self.end),
        ]
        .into_iter()
        .flatten()
        {
            stop = Some(stop.map_or(at, |old| old.min(at)));
        }
        Ok(stop)
    }
    /// The same watchdog must resample a claimed original READ facet even
    /// while stopping: its replacement may publish an earlier captured F.
    /// The caller excludes Unknown; this never changes the original cutoff.
    pub(crate) fn cleanup_poll_end(&self, end: Instant, now: Instant) -> Instant {
        match self.lock() {
            Ok(s) if !s.claimed => end, // An unused allowance cannot alter a GUI winner.
            _ => end.min(now + std::time::Duration::from_millis(100)),
        }
    }
    pub(crate) fn associate(&self, entry:&Arc<crate::service_version_edit_prepare_requests::Entry>)->Result<(),Error>{
        if !entry.accepts_lease(self)?{return Err(Error::Conflict)}
        self.preparation.set(Arc::downgrade(entry)).map_err(|_|Error::Conflict)
    }
    pub(crate) fn preparation(&self)->Result<Option<Arc<crate::service_version_edit_prepare_requests::Entry>>,Error>{
        self.preparation.get().map(|w|w.upgrade().ok_or(Error::StateUnknown)).transpose()
    }
    fn submit(self: &Arc<Self>, input: p::Submit) -> Result<Arc<Entry>, Error> {
        let mut s = self.lock()?;
        if !self.live_locked(&s, Instant::now())?
            || input.grant_id != self.id
            || input.origin.project_id != self.scope.saved.project_id
            || input.session_id != self.review.original.session_id
            || input.plan_token != self.review.original.plan_token
        {
            return Err(Error::Conflict);
        }
        let entry = Arc::new(Entry {
            input,
            lease: self.clone(),
            row: Mutex::new(Row {
                revision: 1,
                phase: p::Phase::Queued,
                stop: None,
                preclaimed: false,
                enqueued: false,
                returned: false,
                result: None,
            }),
            failed: AtomicBool::new(false),
        });
        if let Some(p)=self.preparation()?{p.submitted(self,&entry.input.origin)?;}
        s.claimed = true;
        s.entry = Arc::downgrade(&entry);
        drop(s);
        self.wake();
        Ok(entry)
    }
}
struct Row {
    revision: u32,
    phase: p::Phase,
    stop: Option<Instant>,
    preclaimed: bool,
    enqueued: bool,
    returned: bool,
    result: Option<p::Final>,
}
pub(crate) struct Entry {
    input: p::Submit,
    pub lease: Arc<Lease>,
    row: Mutex<Row>,
    failed: AtomicBool,
}
impl Entry {
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    fn change(&self, row: &mut Row) -> Result<(), Error> {
        row.revision = row
            .revision
            .checked_add(1)
            .filter(|v| *v < u32::MAX)
            .ok_or_else(|| {
                self.failed.store(true, Ordering::Release);
                row.phase = p::Phase::Unknown;
                Error::StateUnknown
            })?;
        Ok(())
    }
    pub(crate) fn input(&self) -> &p::Submit {
        &self.input
    }
    pub(crate) fn cancel(&self, at: Instant) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.returned {
            return Ok(());
        }
        if r.stop.is_some_and(|old| old <= at) {
            return Ok(());
        }
        r.stop = Some(at);
        if r.phase != p::Phase::Unknown {
            r.phase = p::Phase::Stopping
        }
        self.change(&mut r)?;
        drop(r);
        self.lease.wake();
        Ok(())
    }
    pub(crate) fn unknown(&self) {
        self.failed.store(true, Ordering::Release);
        self.lease.wake();
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        let stop = self.lease.stop_at(Instant::now());
        if stop.is_err() {
            self.unknown()
        } else if let Ok(Some(at)) = stop {
            self.cancel(at)?;
        }
        let r = self.lock()?;
        let unknown = self.failed.load(Ordering::Acquire) || r.phase == p::Phase::Unknown;
        let status = p::Status {
            schema_version: 1,
            origin: self.input.origin.clone(),
            grant_id: self.input.grant_id.clone(),
            revision: r.revision,
            phase: if unknown { p::Phase::Unknown } else { r.phase },
            settlement: if unknown {
                Settlement::Unknown
            } else if r.returned {
                Settlement::Settled
            } else {
                Settlement::Pending
            },
            review: self.lease.review.clone(),
            cancel_requested: r.stop.is_some(),
            result: if unknown { None } else { r.result.clone() },
            do_not_replay: true,
        };
        status.validate()?;
        Ok(status)
    }
    pub(crate) fn pending(&self) -> Result<bool, Error> {
        let r = self.lock()?;
        Ok(
            !r.returned
                && !r.preclaimed
                && !self.failed.load(Ordering::Acquire)
                && r.stop.is_none(),
        )
    }
    pub(crate) fn occupied(&self) -> Result<bool, Error> {
        let r = self.lock()?;
        Ok(!r.returned || self.failed.load(Ordering::Acquire))
    }
    /// BEFORE any publisher. A second exact call observes only; it cannot enter
    /// a common error tail which would retire the winning native original.
    pub(crate) fn preclaim(&self) -> Result<bool, Error> {
        if self.lease.stop_at(Instant::now())?.is_some() {
            return Err(Error::Expired);
        }
        let mut r = self.lock()?;
        if r.preclaimed || r.returned {
            return Ok(false);
        }
        if self.failed.load(Ordering::Acquire) || r.stop.is_some() {
            return Err(Error::StateUnknown);
        }
        r.preclaimed = true;
        r.phase = p::Phase::Admitting;
        self.change(&mut r)?;
        Ok(true)
    }
    pub(crate) fn enqueue(&self) -> Result<(), Error> {
        if self.lease.stop_at(Instant::now())?.is_some() {
            return Err(Error::Expired);
        }
        let mut r = self.lock()?;
        if !r.preclaimed
            || r.enqueued
            || r.returned
            || r.stop.is_some()
            || self.failed.load(Ordering::Acquire)
        {
            return Err(Error::Conflict);
        }
        r.enqueued = true;
        r.phase = p::Phase::Applying;
        self.change(&mut r)
    }
    /// Only the real EditOwner retirement callback supplies this. No service
    /// or renderer status path calls it, even for an unentered Apply.
    pub(crate) fn retired(&self, result: Option<p::Final>) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.returned {
            return Err(Error::StateUnknown);
        }
        r.returned = true;
        match result {
            Some(v) if !self.failed.load(Ordering::Acquire) => {
                r.result = Some(v);
                r.phase = p::Phase::Final
            }
            _ => {
                r.phase = p::Phase::Unknown;
                self.failed.store(true, Ordering::Release);
            }
        }
        self.change(&mut r)
    }
}
enum Retained {
    Apply(Arc<Entry>),
    Preparation(Arc<crate::service_version_edit_prepare_requests::Entry>),
}
impl Retained {
    fn origin(&self)->&p::Query{match self{Self::Apply(e)=>&e.input.origin,Self::Preparation(e)=>&e.input.origin}}
    fn occupied(&self)->Result<bool,Error>{match self{Self::Apply(e)=>e.occupied(),Self::Preparation(e)=>e.occupied()}}
    fn excludes(&self,lease:&Lease)->bool{
        if !self.occupied().unwrap_or(true){return false}
        match self{Self::Preparation(e)=>!lease.preparation().ok().flatten().is_some_and(|p|Arc::ptr_eq(e,&p)&&e.accepts_lease(lease).unwrap_or(false)),Self::Apply(_)=>true}
    }
    fn cancel(&self,at:Instant)->Result<(),Error>{match self{Self::Apply(e)=>e.cancel(at),Self::Preparation(e)=>e.cancel(at)}}
}
struct Book {
    lease: Option<Arc<Lease>>,
    rows: Vec<Retained>,
    revoked: Vec<Id>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    changed: watch::Sender<u32>,
}
impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                lease: None,
                rows: Vec::new(),
                revoked: Vec::new(),
                closed: false,
            }),
            changed: watch::channel(0).0,
        }
    }
    fn lock(&self) -> Result<MutexGuard<'_, Book>, Error> {
        self.book.lock().map_err(|_| Error::StateUnknown)
    }
    fn notify(&self) {
        self.changed.send_modify(|v| *v = v.saturating_add(1));
    }
    pub(crate) fn fence(&self) {
        self.close(Instant::now());
    }
    pub(crate) fn receiver(&self) -> watch::Receiver<u32> {
        self.changed.subscribe()
    }
    pub(crate) fn install(
        &self,
        lease: Arc<Lease>,
        install: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut b = self.lock()?;
        if b.closed || b.revoked.contains(&lease.nonce) || b.revoked.len() >= p::REQUEST_LIMIT {
            return Err(Error::Conflict);
        }
        if b.rows.iter().any(|e| e.excludes(&lease))
            || b.lease
                .as_ref()
                .is_some_and(|l| l.live(Instant::now()).unwrap_or(true))
        {
            return Err(Error::Busy);
        }
        install()?;
        b.revoked.push(lease.nonce.clone());
        // Once the native install succeeded, retain that same lease even if
        // an original READ/revoke race refuses its metadata association.
        let association=lease.preparation().and_then(|p|p.map_or(Ok(()),|p|p.installed(&lease).map_err(|e|{p.unknown();e})));
        b.lease = Some(lease);
        drop(b);
        self.notify();
        association
    }
    pub(crate) fn revoke(&self, nonce: &Id, at: Instant) -> Result<(), Error> {
        let mut b = self.lock()?;
        if !b.revoked.contains(nonce) {
            if b.revoked.len() >= p::REQUEST_LIMIT {
                return Err(Error::Busy);
            }
            b.revoked.push(nonce.clone())
        }
        if let Some(l) = b.lease.as_ref().filter(|l| l.nonce == *nonce) {
            l.revoke(at)?
        }
        drop(b);
        self.notify();
        Ok(())
    }
    pub(crate) fn submit(&self, input: p::Submit) -> Result<p::Status, Error> {
        input.validate()?;
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        let mut b = self.lock()?;
        if let Some(old) = b
            .rows
            .iter()
            .find(|e| e.origin().request_id == input.origin.request_id)
        {
            let Retained::Apply(old)=old else{return Err(Error::Conflict)};
            if old.input != input {
                return Err(Error::Conflict);
            }
            return old.status();
        }
        if b.closed
            || b.rows.len() >= p::REQUEST_LIMIT
        {
            return Err(Error::Busy);
        }
        let lease = b.lease.as_ref().ok_or(Error::AccessDenied)?;
        if b.rows.iter().any(|e|e.excludes(lease)){return Err(Error::Busy)}
        let e = lease.submit(input)?;
        b.rows.push(Retained::Apply(e.clone()));
        drop(b);
        self.notify();
        e.status()
    }
    pub(crate) fn entry(&self, q: &p::Query) -> Result<Arc<Entry>, Error> {
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        self.lock()?
            .rows
            .iter()
            .find_map(|e|match e{Retained::Apply(e) if e.input.origin==*q=>Some(e.clone()),_=>None})
            .ok_or(Error::Conflict)
    }
    pub(crate) fn query(&self, q: &p::Query, cancel: bool) -> Result<p::Status, Error> {
        let e = self.entry(q)?;
        if cancel {
            e.cancel(Instant::now())?;
            self.notify()
        }
        e.status()
    }
    pub(crate) fn access(&self) -> Result<p::Access, Error> {
        let b = self.lock()?;
        let Some(l) = &b.lease else {
            return Ok(p::Access::empty());
        };
        let now = Instant::now();
        let live = !b.closed && l.live(now)?;
        let a = p::Access {
            schema_version: 1,
            service_instance: Some(self.instance.clone()),
            project_id: Some(l.scope.saved.project_id.clone()),
            grant_id: Some(l.id.clone()),
            nonce: Some(l.nonce.clone()),
            review: Some(l.review.clone()),
            live,
            remaining_ms: if live {
                l.end
                    .saturating_duration_since(now)
                    .as_millis()
                    .min(900_000) as u64
            } else {
                0
            },
            request: l.entry()?.map(|e| e.status()).transpose()?,
        };
        a.validate()?;
        Ok(a)
    }
    pub(crate) fn access_for(&self, q: &p::Query) -> Result<p::Access, Error> {
        let e = self.entry(q)?;
        let l = &e.lease;
        let a = p::Access {
            schema_version: 1,
            service_instance: Some(self.instance.clone()),
            project_id: Some(l.scope.saved.project_id.clone()),
            grant_id: Some(l.id.clone()),
            nonce: Some(l.nonce.clone()),
            review: Some(l.review.clone()),
            live: false,
            remaining_ms: 0,
            request: Some(e.status()?),
        };
        a.validate()?;
        Ok(a)
    }
    pub(crate) fn catalogue(&self, project: &Id) -> Result<Vec<Id>, Error> {
        Ok(self
            .lock()?
            .rows
            .iter()
            .filter(|e| e.origin().project_id == *project)
            .map(|e| e.origin().request_id.clone())
            .collect())
    }
    pub(crate) fn close(&self, at: Instant) {
        if let Ok(mut b) = self.lock() {
            b.closed = true;
            if let Some(l) = &b.lease {
                let _ = l.revoke(at);
            }
            for e in &b.rows {
                let _ = e.cancel(at);
            }
        }
        self.notify();
    }
    pub(crate) fn prepare(&self,input:crate::service_version_edit_prepare_protocol::Prepare,scope:Scope)->Result<crate::service_version_edit_prepare_protocol::Status,Error>{
        input.validate()?;if input.origin.service_instance!=self.instance{return Err(Error::Conflict)}
        let mut b=self.lock()?;
        if let Some(old)=b.rows.iter().find(|r|r.origin().request_id==input.origin.request_id){
            return match old{Retained::Preparation(e) if e.input==input=>e.status(),_=>Err(Error::Conflict)};
        }
        if b.closed||b.rows.len()>=p::REQUEST_LIMIT||b.rows.iter().any(|e|e.occupied().unwrap_or(true))
            ||b.lease.as_ref().is_some_and(|l|l.live(Instant::now()).unwrap_or(true)){return Err(Error::Busy)}
        let e=crate::service_version_edit_prepare_requests::Entry::new(input,scope)?;
        b.rows.push(Retained::Preparation(e.clone()));drop(b);self.notify();e.status()
    }
    pub(crate) fn preparation(&self,q:&p::Query)->Result<Arc<crate::service_version_edit_prepare_requests::Entry>,Error>{
        if q.service_instance!=self.instance{return Err(Error::Conflict)}
        self.lock()?.rows.iter().find_map(|e|match e{Retained::Preparation(e) if e.input.origin==*q=>Some(e.clone()),_=>None}).ok_or(Error::Conflict)
    }
    pub(crate) fn is_preparation(&self,q:&p::Query)->Result<bool,Error>{
        if q.service_instance!=self.instance{return Err(Error::Conflict)}
        self.lock()?.rows.iter().find(|e|e.origin()==q).map(|e|matches!(e,Retained::Preparation(_))).ok_or(Error::Conflict)
    }
    pub(crate) fn preparation_status(&self,q:Option<&p::Query>)->Result<Option<crate::service_version_edit_prepare_protocol::Status>,Error>{
        let e=if let Some(q)=q{Some(self.preparation(q)?)}else{self.lock()?.rows.iter().rev().find_map(|e|match e{Retained::Preparation(e)=>Some(e.clone()),_=>None})};
        e.map(|e|e.status()).transpose()
    }
}

#[cfg(test)]
#[path = "service_version_edit_requests_tests.rs"]
mod tests;
