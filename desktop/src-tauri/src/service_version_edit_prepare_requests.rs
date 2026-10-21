//! One combined preparation's immutable metadata in the EXISTING VersionEdit
//! Inbox. No reader, native executor or resource/finality receipt lives here.
use crate::{
    service_protocol::{Error, Id, Settlement},
    service_version_edit_prepare_protocol as p, service_version_edit_protocol as edit,
    service_version_edit_requests::{Lease, Scope},
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, MutexGuard, Weak,
};
use std::time::Instant;
use tokio::sync::Notify;

// SAME Book.rows<32 contains either Preparation or Apply. The parent
// charges32*max(actual row quotes), not two independent32-row pools. Keep
// this preparation's off-worker/relay scratch in addition to Apply's scratch.
pub(crate) const ROW_BACKING: usize = p::REQUEST_BYTES + 2 * p::STATUS_BYTES + 8192 + std::mem::size_of::<Entry>();
pub(crate) const NON_ROW_BACKING: usize = 2 * p::STATUS_BYTES;
pub(crate) const IPC_WORKER_BACKING: usize = p::REQUEST_BYTES + 2 * p::STATUS_BYTES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Open,
    Prepare,
}
impl Kind {
    fn index(self) -> usize {
        match self {
            Self::Open => 0,
            Self::Prepare => 1,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Caller {
    New,
    Pending,
    Returned,
}
struct Row {
    status: p::Status,
    callers: [Caller; 2],
    claimed: bool,
    marker: Option<Weak<Notify>>,
    counters: Option<(u32, u32)>,
    lease: Option<Weak<Lease>>,
    stop: Option<Instant>,
    retired: bool,
}
pub(crate) struct Entry {
    pub input: p::Prepare,
    pub scope: Scope,
    row: Mutex<Row>,
    failed: AtomicBool,
}
impl Entry {
    pub(crate) fn new(input: p::Prepare, scope: Scope) -> Result<Arc<Self>, Error> {
        input.validate()?;
        if input.origin.project_id != scope.saved.project_id
            || scope.read.stop(Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(Arc::new(Self {
            row: Mutex::new(Row {
                status: p::Status {
                    schema_version: 1,
                    origin: input.origin.clone(),
                    runtime_project_id: scope.saved.runtime_id.clone(),
                    selection: input.selection.clone(),
                    revision: 1,
                    phase: p::Phase::Queued,
                    settlement: Settlement::Pending,
                    original: None,
                    checkout: None,
                    proposed: None,
                    review: None,
                    apply_request: None,
                    gui_owned: false,
                    cancel_requested: false,
                    result: None,
                    do_not_replay: true,
                },
                callers: [Caller::New; 2],
                claimed: false,
                marker: None,
                counters: None,
                lease: None,
                stop: None,
                retired: false,
            }),
            input,
            scope,
            failed: AtomicBool::new(false),
        }))
    }
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    fn change(&self, r: &mut Row) -> Result<(), Error> {
        r.status.revision = r
            .status
            .revision
            .checked_add(1)
            .filter(|v| *v < u32::MAX)
            .ok_or_else(|| {
                self.failed.store(true, Ordering::Release);
                Error::StateUnknown
            })?;
        Ok(())
    }
    fn live_row(&self, r: &Row, now: Instant) -> Result<bool, Error> {
        Ok(!self.failed.load(Ordering::Acquire)
            && !r.retired
            && !r.status.gui_owned
            && r.stop.is_none()
            && self.scope.read.stop(now)?.is_none())
    }
    pub(crate) fn live(&self) -> bool {
        self.lock()
            .is_ok_and(|r| self.live_row(&r, Instant::now()).unwrap_or(false))
    }
    pub(crate) fn admitting(&self, kind: Kind) -> bool {
        self.lock().is_ok_and(|r| {
            r.callers[kind.index()] == Caller::Pending
                && self.live_row(&r, Instant::now()).unwrap_or(false)
        })
    }
    pub(crate) fn unclaimed_open(&self) -> bool {
        self.lock().is_ok_and(|r| {
            !r.claimed
                && r.callers[0] == Caller::Pending
                && self.live_row(&r, Instant::now()).unwrap_or(false)
        })
    }
    pub(crate) fn has_review(&self) -> bool {
        self.lock().is_ok_and(|r| r.status.review.is_some())
    }
    fn wake(&self) {
        if let Ok(r) = self.row.lock() {
            if let Some(w) = r.marker.as_ref().and_then(Weak::upgrade) {
                w.notify_waiters();
            }
        }
    }
    pub(crate) fn unknown(&self) {
        self.failed.store(true, Ordering::Release);
        self.wake();
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Result<Option<Instant>, Error> {
        let r = self.lock()?;
        // The original GUI preclaim owns all later work; an unused READ/CLI
        // request cannot cancel that separately authorized ordinary Save.
        if r.status.gui_owned || r.retired {
            return Ok(None);
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        Ok([r.stop, self.scope.read.stop(now)?.map(|(_, at)| at)]
            .into_iter()
            .flatten()
            .min())
    }
    pub(crate) fn cancel(&self, at: Instant) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.retired || r.status.gui_owned {
            return Ok(());
        }
        r.stop = Some(r.stop.map_or(at, |old| old.min(at)));
        r.status.cancel_requested = true;
        r.status.phase = p::Phase::Stopping;
        if r.callers[0] == Caller::New && !r.claimed {
            Self::finish_unentered(&mut r);
        }
        self.change(&mut r)?;
        drop(r);
        self.wake();
        Ok(())
    }
    fn finish_unentered(r: &mut Row) {
        r.retired = true;
        r.status.phase = p::Phase::Final;
        r.status.settlement = Settlement::Settled;
        r.status.result = Some(edit::Final {
            effect: edit::Effect::NotStarted,
            journal: edit::Journal::NotCreated,
            cancelled: true,
            apply_submitted: false,
        });
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        match self.stop_at(Instant::now()) {
            Ok(Some(at)) => self.cancel(at)?,
            Ok(None) => (),
            Err(_) => self.unknown(),
        }
        let r = self.lock()?;
        let mut v = r.status.clone();
        if self.failed.load(Ordering::Acquire) {
            v.phase = p::Phase::Unknown;
            v.settlement = Settlement::Unknown;
            v.result = None;
        }
        v.validate()?;
        Ok(v)
    }
    pub(crate) fn occupied(&self) -> Result<bool, Error> {
        let r = self.lock()?;
        Ok(!r.retired
            || r.callers.contains(&Caller::Pending)
            || self.failed.load(Ordering::Acquire))
    }
    pub(crate) fn gui_owned(&self) -> bool {
        self.lock().is_ok_and(|r| r.status.gui_owned)
    }
    pub(crate) fn begin(
        self: &Arc<Self>,
        kind: Kind,
        counters: Option<(u32, u32)>,
    ) -> Result<Option<Call>, Error> {
        let mut r = self.lock()?;
        if r.callers[kind.index()] != Caller::New {
            return Ok(None);
        }
        if !self.live_row(&r, Instant::now())? {
            return Err(Error::Expired);
        }
        match kind {
            Kind::Open if r.status.phase == p::Phase::Queued && counters.is_none() => (),
            Kind::Prepare
                if r.status.phase == p::Phase::Opened
                    && r.callers[0] == Caller::Returned
                    && counters.is_some_and(|(a, b)| a < u32::MAX && b < u32::MAX) =>
            {
                ()
            }
            _ => return Err(Error::Conflict),
        }
        r.callers[kind.index()] = Caller::Pending;
        r.counters = counters.or(r.counters);
        r.status.phase = match kind {
            Kind::Open => p::Phase::Opening,
            Kind::Prepare => p::Phase::Preparing,
        };
        self.change(&mut r)?;
        Ok(Some(Call {
            entry: self.clone(),
            kind,
            returned: false,
        }))
    }
    pub(crate) fn claim_open(&self) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.claimed || r.callers[0] != Caller::Pending || !self.live_row(&r, Instant::now())? {
            return Err(Error::Conflict);
        }
        r.claimed = true;
        self.change(&mut r)
    }
    pub(crate) fn bind(&self, original: p::Original, wake: Weak<Notify>) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed
            || r.status.original.is_some()
            || r.callers[0] != Caller::Pending
            || wake.strong_count() == 0
        {
            return Err(Error::StateUnknown);
        }
        r.status.original = Some(original);
        r.marker = Some(wake);
        self.change(&mut r)
    }
    pub(crate) fn bound(&self, session: &str, generation: &str) -> bool {
        self.lock().is_ok_and(|r| {
            r.status.original.as_ref().is_some_and(|o| {
                o.session_id.as_str() == session && o.owner_generation.as_str() == generation
            }) && r.marker.as_ref().is_some_and(|m| m.strong_count() > 0)
        })
    }
    pub(crate) fn opened(&self, checkout: p::Checkout, proposed: p::Values) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.status.checkout.is_some() {
            return if r.status.checkout.as_ref() == Some(&checkout)
                && r.status.proposed.as_ref() == Some(&proposed)
            {
                Ok(())
            } else {
                Err(Error::StateUnknown)
            };
        }
        if !r.claimed
            || r.status.original.is_none()
            || r.status.phase != p::Phase::Opening
            || !checkout.valid()
            || !proposed.valid()
        {
            return Err(Error::Conflict);
        }
        if let p::Selection::Manual { values } = &self.input.selection {
            if *values != proposed {
                return Err(Error::Conflict);
            }
        }
        r.status.checkout = Some(checkout);
        r.status.proposed = Some(proposed);
        r.status.phase = p::Phase::Opened;
        self.change(&mut r)
    }
    pub(crate) fn prepare_data(
        &self,
    ) -> Result<(p::Original, p::Checkout, p::Values, (u32, u32)), Error> {
        let r = self.lock()?;
        if r.callers[1] != Caller::Pending || !self.live_row(&r, Instant::now())? {
            return Err(Error::Conflict);
        }
        Ok((
            r.status.original.clone().ok_or(Error::Conflict)?,
            r.status.checkout.clone().ok_or(Error::Conflict)?,
            r.status.proposed.clone().ok_or(Error::Conflict)?,
            r.counters.ok_or(Error::Conflict)?,
        ))
    }
    pub(crate) fn prepared(&self, review: edit::Review) -> Result<(), Error> {
        let mut r = self.lock()?;
        if let Some(old) = &r.status.review {
            return if old == &review {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if r.callers[1] == Caller::New
            || r.status.phase != p::Phase::Preparing
            || !self.live_row(&r, Instant::now())?
        {
            return Err(Error::Conflict);
        }
        let mut next = r.status.clone();
        next.review = Some(review);
        next.phase = p::Phase::Reviewing;
        next.validate()?;
        r.status = next;
        self.change(&mut r)
    }
    pub(crate) fn ready(&self, review: &edit::Review) -> Result<bool, Error> {
        let r = self.lock()?;
        Ok(self.ready_row(&r, review)?)
    }
    fn ready_row(&self, r: &Row, review: &edit::Review) -> Result<bool, Error> {
        Ok(self.live_row(r, Instant::now())?
            && r.status.phase == p::Phase::Reviewing
            && r.callers == [Caller::Returned; 2]
            && r.status.review.as_ref() == Some(review)
            && r.marker.as_ref().is_some_and(|m| m.strong_count() > 0))
    }
    pub(crate) fn accepts_lease(&self, lease: &Lease) -> Result<bool, Error> {
        let r = self.lock()?;
        Ok(self.ready_row(&r, &lease.review)?
            && Arc::ptr_eq(&self.scope.read, &lease.scope.read)
            && self.scope.saved.project_id == lease.scope.saved.project_id
            && self.scope.saved.runtime_id == lease.scope.saved.runtime_id
            && self.scope.saved.root == lease.scope.saved.root
            && self.scope.saved.device == lease.scope.saved.device
            && self.scope.saved.inode == lease.scope.saved.inode
            && r.lease
                .as_ref()
                .is_none_or(|l| l.as_ptr() == lease as *const Lease))
    }
    pub(crate) fn installed(&self, lease: &Arc<Lease>) -> Result<(), Error> {
        if !self.accepts_lease(lease)? {
            return Err(Error::Conflict);
        }
        let mut r = self.lock()?;
        if r.lease.is_some() {
            return Err(Error::Conflict);
        }
        r.lease = Some(Arc::downgrade(lease));
        self.change(&mut r)
    }
    pub(crate) fn submitted(&self, lease: &Lease, q: &edit::Query) -> Result<(), Error> {
        if !self.accepts_lease(lease)? {
            return Err(Error::Conflict);
        }
        let mut r = self.lock()?;
        if r.status.apply_request.is_some()
            || r.lease
                .as_ref()
                .is_none_or(|l| l.as_ptr() != lease as *const Lease)
        {
            return Err(Error::Conflict);
        }
        r.status.apply_request = Some(q.clone());
        r.status.phase = p::Phase::Applying;
        self.change(&mut r)
    }
    pub(crate) fn gui_claim(&self, review: &edit::Review) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !self.ready_row(&r, review)? || r.status.apply_request.is_some() {
            return Err(Error::Conflict);
        }
        r.status.gui_owned = true;
        r.status.phase = p::Phase::Applying;
        self.change(&mut r)
    }
    pub(crate) fn retired(&self, result: Option<edit::Final>) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.retired {
            return Err(Error::StateUnknown);
        }
        r.retired = true;
        match result {
            Some(v) if !self.failed.load(Ordering::Acquire) => {
                r.status.phase = p::Phase::Final;
                r.status.settlement = Settlement::Settled;
                r.status.result = Some(v);
            }
            _ => {
                self.failed.store(true, Ordering::Release);
            }
        }
        self.change(&mut r)
    }
}
/// Retained before native admission. A missing original return never turns
/// into a reusable request or an unentered result from a later status.
pub(crate) struct Call {
    entry: Arc<Entry>,
    kind: Kind,
    returned: bool,
}
impl Call {
    pub(crate) fn finish(mut self, ok: bool) -> Result<(), Error> {
        let result = (|| {
            let mut r = self.entry.lock()?;
            if r.callers[self.kind.index()] != Caller::Pending {
                return Err(Error::StateUnknown);
            }
            r.callers[self.kind.index()] = Caller::Returned;
            if !ok && !r.retired {
                r.stop.get_or_insert_with(Instant::now);
                r.status.cancel_requested = true;
                r.status.phase = p::Phase::Stopping;
                if !r.claimed {
                    Entry::finish_unentered(&mut r);
                } else if r.status.original.is_none() {
                    self.entry.failed.store(true, Ordering::Release);
                }
            }
            self.entry.change(&mut r)
        })();
        self.returned = result.is_ok();
        if !self.returned {
            self.entry.unknown();
        }
        self.entry.wake();
        result
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown();
        }
    }
}

#[cfg(test)]
#[path = "service_version_edit_prepare_requests_tests.rs"]
mod tests;
