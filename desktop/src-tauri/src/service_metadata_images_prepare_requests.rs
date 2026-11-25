//! A typed row in Config's SAME32, not a native owner or image custodian.
//! The actual Session owns its identity anchor; this row retains only Weak.
use crate::{
    service_metadata_images_prepare_protocol as p, service_metadata_images_protocol as images,
    service_metadata_images_requests::{Entry as ApplyEntry, Scope},
    service_protocol::{Error, OperationState, Settlement},
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::Instant,
};
use tokio::sync::{watch, Notify};
pub(crate) const ROW_BYTES: usize = std::mem::size_of::<Entry>() + 16384;
pub(crate) const IPC_WORKER_BACKING: usize = 4 * p::REQUEST_BYTES + 4 * p::STATUS_BYTES + 4096;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Read,
    Prepare,
}
impl Kind {
    fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Prepare => 1,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Returned {
    New,
    Pending,
    Returned,
}
struct State {
    status: p::Status,
    input: Option<p::Prepare>,
    calls: [Returned; 2],
    anchor: Option<Weak<()>>,
    wake: Weak<Notify>,
    end: Instant,
    observed_revision: Option<u32>,
    claimed: bool,
    enqueued: bool,
    native_retired: bool,
    stop: Option<Instant>,
    transferred: bool,
    gui: bool,
    successor: Option<Weak<ApplyEntry>>,
    history_claimed: bool,
    history_returned: bool,
}
pub(crate) struct Entry {
    pub(crate) input: p::Read,
    pub(crate) scope: Scope,
    state: Mutex<State>,
    failed: Arc<AtomicBool>,
    changes: watch::Sender<u32>,
}
impl Entry {
    pub(crate) fn new(
        input: p::Read,
        scope: Scope,
        failed: Arc<AtomicBool>,
        changes: watch::Sender<u32>,
    ) -> Result<Arc<Self>, Error> {
        p::bounded(&input, p::REQUEST_BYTES)?;
        if scope.saved.root.capacity() > 4096
            || scope.saved.runtime_id.capacity() > 128
            || input.origin.project_id != scope.saved.project_id
            || scope.read.stop(Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        let status = p::Status {
            schema_version: 1,
            origin: input.origin.clone(),
            runtime_project_id: scope.saved.runtime_id.clone(),
            revision: 1,
            phase: p::Phase::QueuedRead,
            settlement: Settlement::Pending,
            observation: None,
            choices: None,
            review: None,
            remaining_ms: 0,
            cancel_requested: false,
            result: None,
            do_not_replay: true,
        };
        status.validate()?;
        let end = scope.read.end();
        Ok(Arc::new(Self {
            input,
            scope,
            failed,
            changes,
            state: Mutex::new(State {
                status,
                input: None,
                calls: [Returned::New; 2],
                anchor: None,
                wake: Weak::new(),
                end,
                observed_revision: None,
                claimed: false,
                enqueued: false,
                native_retired: false,
                stop: None,
                transferred: false,
                gui: false,
                successor: None,
                history_claimed: false,
                history_returned: false,
            }),
        }))
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>, Error> {
        self.state.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    fn bump(&self, s: &mut State) -> Result<(), Error> {
        s.status.revision = s
            .status
            .revision
            .checked_add(1)
            .filter(|n| *n < u32::MAX)
            .ok_or_else(|| {
                s.status.phase = p::Phase::Unknown;
                Error::StateUnknown
            })?;
        let mut good = true;
        self.changes.send_modify(|n| {
            if let Some(v) = n.checked_add(1).filter(|n| *n < u32::MAX) {
                *n = v
            } else {
                good = false
            }
        });
        if !good {
            self.failed.store(true, Ordering::Release);
            s.status.phase = p::Phase::Unknown;
            return Err(Error::StateUnknown);
        }
        Ok(())
    }
    fn set_unknown(&self, s: &mut State) {
        // The original watchdog creates Notified before sampling this row.
        // Only the first transition may publish/wake; sampling an absorbing
        // Unknown must not keep that same watchdog runnable forever.
        if !matches!(s.status.phase, p::Phase::Unknown | p::Phase::Final) {
            s.status.phase = p::Phase::Unknown;
            s.status.result = None;
            let _ = self.bump(s);
            if let Some(w) = s.wake.upgrade() {
                w.notify_waiters();
            }
        }
    }
    pub(crate) fn unknown(&self) {
        if let Ok(mut s) = self.lock() {
            self.set_unknown(&mut s);
        }
    }
    // Sampling original READ uncertainty is absorbing AT THIS CUT. In
    // particular, a prior ordinary STOP cannot hide later READ poison.
    fn stop_locked(&self, s: &mut State, now: Instant) -> Result<Option<Instant>, Error> {
        if s.transferred || s.status.phase == p::Phase::Final {
            return Ok(None);
        }
        if self.failed.load(Ordering::Acquire) || s.status.phase == p::Phase::Unknown {
            self.set_unknown(s);
            return Err(Error::StateUnknown);
        }
        let read = match self.scope.read.stop(now) {
            Ok(v) => v.map(|(_, t)| t),
            Err(e) => {
                self.set_unknown(s);
                return Err(e);
            }
        };
        Ok([s.stop, read, (now >= s.end).then_some(s.end)]
            .into_iter()
            .flatten()
            .min())
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Result<Option<Instant>, Error> {
        let mut s = self.lock()?;
        self.stop_locked(&mut s, now)
    }
    pub(crate) fn native_stop(&self, now: Instant) -> Result<Option<Instant>, Error> {
        let mut s = self.lock()?;
        if !s.claimed || s.transferred || s.native_retired {
            return Ok(None);
        }
        self.stop_locked(&mut s, now)
    }
    pub(crate) fn cancel(&self, at: Instant) -> Result<(), Error> {
        let mut s = self.lock()?;
        // Transfer withdraws ONLY this predecessor's control. A delayed
        // predecessor Cancel/READ cannot cancel the successor Apply or GUI.
        if s.transferred || s.status.phase == p::Phase::Final {
            return Ok(());
        }
        // A same/later STOP is observation, not another publication. A
        // genuinely earlier first-F still changes control even while Unknown.
        if s.stop.is_some_and(|old| old <= at) {
            return Ok(());
        }
        s.stop = Some(at);
        s.status.cancel_requested = true;
        if s.status.phase != p::Phase::Unknown {
            s.status.phase = p::Phase::Stopping;
        }
        self.bump(&mut s)?;
        if let Some(w) = s.wake.upgrade() {
            w.notify_waiters();
        }
        Ok(())
    }
    fn ready_to_finish(s: &State) -> bool {
        s.calls.iter().all(|c| *c != Returned::Pending)
            && s.status.phase != p::Phase::Unknown
            && (s.native_retired || !s.claimed && s.stop.is_some())
    }
    pub(crate) fn occupied(&self) -> Result<bool, Error> {
        if let Some(t) = self.stop_at(Instant::now())? {
            self.cancel(t)?;
        }
        let s = self.lock()?;
        Ok(s.status.phase == p::Phase::Unknown
            || !s.transferred && s.status.phase != p::Phase::Final)
    }
    pub(crate) fn pending(&self, kind: Kind) -> Result<bool, Error> {
        let mut s = self.lock()?;
        Ok(self.stop_locked(&mut s, Instant::now())?.is_none()
            && s.calls[kind.index()] == Returned::New
            && s.status.phase
                == match kind {
                    Kind::Read => p::Phase::QueuedRead,
                    Kind::Prepare => p::Phase::QueuedPrepare,
                })
    }
    pub(crate) fn caller(self: &Arc<Self>, kind: Kind) -> Result<Call, Error> {
        let mut s = self.lock()?;
        if self.stop_locked(&mut s, Instant::now())?.is_some()
            || s.calls[kind.index()] != Returned::New
            || s.status.phase
                != match kind {
                    Kind::Read => p::Phase::QueuedRead,
                    Kind::Prepare => p::Phase::QueuedPrepare,
                }
        {
            return Err(Error::Conflict);
        }
        s.calls[kind.index()] = Returned::Pending;
        s.status.phase = match kind {
            Kind::Read => p::Phase::Reading,
            Kind::Prepare => p::Phase::Preparing,
        };
        self.bump(&mut s)?;
        Ok(Call {
            entry: self.clone(),
            kind,
            returned: false,
        })
    }
    pub(crate) fn observed(
        &self,
        observation: p::Observation,
        anchor: &Arc<()>,
        wake: &Arc<Notify>,
        end: Instant,
    ) -> Result<(), Error> {
        observation.validate()?;
        observation_backing(&observation)?;
        let mut s = self.lock()?;
        if s.calls[0] != Returned::Pending
            || s.anchor.is_some()
            || s.claimed
            || self.stop_locked(&mut s, Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        s.status.observation = Some(observation);
        s.anchor = Some(Arc::downgrade(anchor));
        s.wake = Arc::downgrade(wake);
        s.end = s.end.min(end);
        self.bump(&mut s)
    }
    pub(crate) fn observation(&self) -> Result<p::Observation, Error> {
        self.lock()?
            .status
            .observation
            .clone()
            .ok_or(Error::Conflict)
    }
    pub(crate) fn bound(&self, anchor: &Arc<()>) -> bool {
        self.lock().is_ok_and(|s| {
            s.anchor
                .as_ref()
                .is_some_and(|a| a.as_ptr() == Arc::as_ptr(anchor) && a.strong_count() > 0)
        })
    }
    pub(crate) fn prepare(&self, input: p::Prepare) -> Result<p::Status, Error> {
        input.validate()?;
        let mut s = self.lock()?;
        if let Some(old) = &s.input {
            if old != &input {
                return Err(Error::Conflict);
            }
            drop(s);
            return self.status();
        }
        if self.stop_locked(&mut s, Instant::now())?.is_some()
            || s.status.phase != p::Phase::Editing
            || s.calls[0] != Returned::Returned
            || input.origin != self.input.origin
            || s.observed_revision != Some(input.observation_revision)
            || !s
                .status
                .observation
                .as_ref()
                .is_some_and(|o| input.matches(o))
        {
            return Err(Error::Conflict);
        }
        s.status.choices = Some(input.choices.clone());
        s.input = Some(input);
        s.status.phase = p::Phase::QueuedPrepare;
        self.bump(&mut s)?;
        drop(s);
        self.status()
    }
    pub(crate) fn proposal(&self) -> Result<p::Prepare, Error> {
        self.lock()?.input.clone().ok_or(Error::Conflict)
    }
    /// Called with the SAME native Registry held, immediately before installing
    /// the Session link. All fallible allocations are made before this cut.
    pub(crate) fn claim(&self, anchor: &Arc<()>) -> Result<(), Error> {
        let mut s = self.lock()?;
        if s.claimed
            || s.calls[1] != Returned::Pending
            || s.status.phase != p::Phase::Preparing
            || s.input.is_none()
            || !s
                .anchor
                .as_ref()
                .is_some_and(|a| a.as_ptr() == Arc::as_ptr(anchor) && a.strong_count() > 0)
            || self.stop_locked(&mut s, Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        s.claimed = true;
        self.bump(&mut s)
    }
    pub(crate) fn enqueued(&self) -> Result<(), Error> {
        let mut s = self.lock()?;
        if !s.claimed
            || s.enqueued
            || s.calls[1] != Returned::Pending
            || self.stop_locked(&mut s, Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        s.enqueued = true;
        self.bump(&mut s)
    }
    pub(crate) fn claimed(&self) -> bool {
        self.lock().is_ok_and(|s| s.claimed)
    }
    pub(crate) fn transferred(&self) -> bool {
        self.lock().is_ok_and(|s| s.transferred)
    }
    pub(crate) fn transferred_to(&self, next: Option<&Arc<ApplyEntry>>) -> bool {
        self.lock().is_ok_and(|s| {
            s.transferred
                && match next {
                    None => s.gui,
                    Some(e) => {
                        !s.gui
                            && s.successor.as_ref().is_some_and(|w| {
                                w.as_ptr() == Arc::as_ptr(e) && w.strong_count() > 0
                            })
                    }
                }
        })
    }
    pub(crate) fn native_prepared(&self, review: images::Review) -> Result<(), Error> {
        review.validate()?;
        let mut s = self.lock()?;
        if !s.claimed
            || !s.enqueued
            || s.status.review.is_some()
            || self.stop_locked(&mut s, Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        let mut checked = s.status.clone();
        checked.review = Some(review.clone());
        checked.validate()?;
        s.status.review = Some(review);
        if s.calls[1] == Returned::Returned {
            s.status.phase = p::Phase::Reviewing;
        }
        self.bump(&mut s)
    }
    pub(crate) fn reviewing(&self, review: &images::Review) -> bool {
        self.lock().is_ok_and(|mut s| {
            s.status.phase == p::Phase::Reviewing
                && s.calls[1] == Returned::Returned
                && !s.transferred
                && s.status.review.as_ref() == Some(review)
                && self
                    .stop_locked(&mut s, Instant::now())
                    .is_ok_and(|t| t.is_none())
        })
    }
    pub(crate) fn associates(
        &self,
        review: &images::Review,
        read: &Arc<crate::service_version_reserve_requests::ReadPermission>,
    ) -> bool {
        Arc::ptr_eq(read, &self.scope.read) && self.reviewing(review)
    }
    /// SAME Registry + row mutex: no predecessor cancellation can cross this
    /// transfer. The installed successor already carries its own SAME READ.
    pub(crate) fn transfer(
        &self,
        next: Option<&Arc<ApplyEntry>>,
        review: &images::Review,
    ) -> Result<(), Error> {
        let mut s = self.lock()?;
        if !s.claimed
            || s.transferred
            || s.status.phase != p::Phase::Reviewing
            || s.calls[1] != Returned::Returned
            || s.status.review.as_ref() != Some(review)
            || self.stop_locked(&mut s, Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        if let Some(e) = next {
            let g = e.grant.as_ref().ok_or(Error::Conflict)?;
            if !Arc::ptr_eq(&g.scope.read, &self.scope.read) || g.review != *review {
                return Err(Error::Conflict);
            }
        }
        s.successor = next.map(Arc::downgrade);
        s.transferred = true;
        s.gui = next.is_none();
        s.status.phase = p::Phase::Transferred;
        self.bump(&mut s)
    }
    pub(crate) fn retired(&self, known: bool) -> Result<(), Error> {
        let mut s = self.lock()?;
        if !s.claimed || s.native_retired {
            return Err(Error::Conflict);
        }
        s.native_retired = true;
        if !known {
            self.set_unknown(&mut s);
        }
        self.bump(&mut s)
    }
    pub(crate) fn history(&self) -> Result<Option<OperationState>, Error> {
        let mut s = self.lock()?;
        if s.history_claimed || !Self::ready_to_finish(&s) {
            return Ok(None);
        }
        s.history_claimed = true;
        Ok(Some(if s.status.review.is_some() {
            OperationState::Succeeded
        } else if s.stop.is_some() {
            OperationState::Cancelled
        } else {
            OperationState::Failed
        }))
    }
    pub(crate) fn history_returned(&self, ok: bool) -> Result<(), Error> {
        let mut s = self.lock()?;
        if !s.history_claimed || s.history_returned {
            return Err(Error::Conflict);
        }
        if !ok {
            self.set_unknown(&mut s);
            return Err(Error::StateUnknown);
        }
        s.history_returned = true;
        if Self::ready_to_finish(&s) {
            s.status.phase = p::Phase::Final;
            s.status.result = Some(p::Final {
                prepared: s.status.review.is_some(),
                transferred: s.transferred,
                gui: s.gui,
            });
        }
        self.bump(&mut s)
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        match self.stop_at(Instant::now()) {
            Ok(Some(t)) => self.cancel(t)?,
            Err(_) => self.unknown(),
            _ => {}
        }
        let s = self.lock()?;
        let mut status = s.status.clone();
        status.settlement = match status.phase {
            p::Phase::Final => Settlement::Settled,
            p::Phase::Unknown => Settlement::Unknown,
            _ => Settlement::Pending,
        };
        status.remaining_ms = if s.stop.is_none()
            && !s.transferred
            && !matches!(status.phase, p::Phase::Unknown | p::Phase::Final)
        {
            s.end
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(900000) as u64
        } else {
            0
        };
        status.validate()?;
        Ok(status)
    }
}
pub(crate) struct Call {
    entry: Arc<Entry>,
    kind: Kind,
    returned: bool,
}
impl Call {
    pub(crate) fn returned(mut self, ok: bool) -> Result<(), Error> {
        self.returned = true;
        let mut s = self.entry.lock()?;
        if s.calls[self.kind.index()] != Returned::Pending {
            return Err(Error::Conflict);
        }
        s.calls[self.kind.index()] = Returned::Returned;
        if !ok {
            s.stop.get_or_insert_with(Instant::now);
            s.status.cancel_requested = true;
            if s.status.phase != p::Phase::Unknown {
                s.status.phase = p::Phase::Stopping;
            }
        } else if s.stop.is_none() && s.status.phase != p::Phase::Unknown {
            match self.kind {
                Kind::Read if s.status.observation.is_some() => {
                    s.status.phase = p::Phase::Editing;
                }
                Kind::Prepare if s.enqueued => {
                    if s.status.review.is_some() {
                        s.status.phase = p::Phase::Reviewing;
                    }
                }
                _ => {
                    self.entry.set_unknown(&mut s);
                }
            }
        }
        self.entry.bump(&mut s)?;
        if self.kind == Kind::Read && s.status.phase == p::Phase::Editing {
            s.observed_revision = Some(s.status.revision);
        }
        if let Some(w) = s.wake.upgrade() {
            w.notify_waiters();
        }
        Ok(())
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown();
        }
    }
}
fn observation_backing(o: &p::Observation) -> Result<(), Error> {
    let mut n = o
        .items
        .capacity()
        .checked_mul(std::mem::size_of::<p::Item>())
        .ok_or(Error::Busy)?;
    for x in &o.items {
        for size in [
            x.item_id.retained_bytes(),
            x.display_name.capacity(),
            x.selected_sha256.capacity(),
            x.before_sha256.as_ref().map_or(0, String::capacity),
        ] {
            n = n.checked_add(size).ok_or(Error::Busy)?;
        }
    }
    for size in [
        o.locale.capacity(),
        o.asset_type.capacity(),
        o.opened_sha256.capacity(),
        o.original.session_id.retained_bytes(),
        o.original.owner_generation.retained_bytes(),
        o.original.revision.retained_bytes(),
    ] {
        n = n.checked_add(size).ok_or(Error::Busy)?;
    }
    if n > 8192 {
        Err(Error::Busy)
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use images::fixtures::*;
    pub(crate) fn copy_scope(scope: &Scope) -> Scope {
        Scope {
            saved: crate::agent_identity_requests::SavedPoint {
                project_id: scope.saved.project_id.clone(),
                runtime_id: scope.saved.runtime_id.clone(),
                root: scope.saved.root.clone(),
                device: scope.saved.device,
                inode: scope.saved.inode,
                revision: scope.saved.revision,
                fresh: scope.saved.fresh,
            },
            read: scope.read.clone(),
        }
    }
    pub(crate) fn entry() -> (Arc<Entry>, Arc<()>, Arc<Notify>) {
        let w = Arc::new(Notify::new());
        let scope = crate::service_metadata_images_requests::fixtures::grant(&w).scope;
        let (changes, _) = watch::channel(1);
        (
            Entry::new(
                p::Read { origin: query() },
                scope,
                Arc::new(AtomicBool::new(false)),
                changes,
            )
            .unwrap(),
            Arc::new(()),
            w,
        )
    }
    // DATA transition fixture only, not a native Session/registry/source proof.
    pub(crate) fn opened(e: &Arc<Entry>, a: &Arc<()>, w: &Arc<Notify>) {
        let call = e.caller(Kind::Read).unwrap();
        e.observed(p::fixtures::observation(), a, w, e.scope.read.end())
            .unwrap();
        call.returned(true).unwrap();
    }
    pub(crate) fn queued(e: &Arc<Entry>) {
        let r = e.status().unwrap().revision;
        e.prepare(p::fixtures::prepare(r)).unwrap();
    }
    pub(crate) fn reviewing(e: &Arc<Entry>, a: &Arc<()>, w: &Arc<Notify>) {
        opened(e, a, w);
        queued(e);
        let call = e.caller(Kind::Prepare).unwrap();
        e.claim(a).unwrap();
        e.enqueued().unwrap();
        e.native_prepared(review()).unwrap();
        call.returned(true).unwrap();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::*;
    use images::fixtures::*;
    #[test]
    fn inspection_is_not_cancellation_authority_and_prepare_requires_original_return() {
        let (e, a, w) = entry();
        let call = e.caller(Kind::Read).unwrap();
        e.observed(p::fixtures::observation(), &a, &w, e.scope.read.end())
            .unwrap();
        assert_eq!(e.status().unwrap().phase, p::Phase::Reading);
        assert!(e
            .prepare(p::fixtures::prepare(e.status().unwrap().revision))
            .is_err());
        assert_eq!(e.native_stop(Instant::now()).unwrap(), None);
        call.returned(true).unwrap();
        queued(&e);
        let call = e.caller(Kind::Prepare).unwrap();
        assert!(e.claim(&Arc::new(())).is_err());
        e.claim(&a).unwrap();
        e.enqueued().unwrap();
        e.native_prepared(review()).unwrap();
        assert!(!e.reviewing(&review()));
        assert!(e.transfer(None, &review()).is_err());
        call.returned(true).unwrap();
        assert!(e.reviewing(&review()));
        assert!(e.history().unwrap().is_none());
        assert!(e.caller(Kind::Prepare).is_err());
    }
    #[test]
    fn exact_duplicate_prepare_observes_and_changed_input_or_lost_caller_cannot_rearm() {
        let (e, a, w) = entry();
        opened(&e, &a, &w);
        let input = p::fixtures::prepare(e.status().unwrap().revision);
        e.prepare(input.clone()).unwrap();
        assert_eq!(
            e.prepare(input.clone()).unwrap().phase,
            p::Phase::QueuedPrepare
        );
        let mut changed = input;
        changed.choices[0].replace_existing = true;
        assert!(e.prepare(changed).is_err());
        drop(e.caller(Kind::Prepare).unwrap());
        assert_eq!(e.status().unwrap().settlement, Settlement::Unknown);
        e.cancel(Instant::now()).unwrap();
        assert!(e.history().unwrap().is_none());
        assert!(e.occupied().unwrap_or(true));
    }
    #[test]
    fn transfer_disarms_only_predecessor_and_retirement_is_not_the_prepare_reply() {
        for gui in [false, true] {
            let (e, a, w) = entry();
            reviewing(&e, &a, &w);
            let (app, keep) = crate::service_metadata_images_requests::fixtures::entry();
            let mut g = crate::service_metadata_images_requests::fixtures::grant(&keep);
            g.scope.read = e.scope.read.clone();
            let (changes, _) = watch::channel(1);
            let next = ApplyEntry::new(id('5'), Some(g), Arc::new(AtomicBool::new(false)), changes)
                .unwrap();
            drop(app);
            next.associate_preparation(&e).unwrap();
            if !gui {
                next.submit(crate::service_metadata_images_requests::fixtures::input())
                    .unwrap();
            }
            e.transfer(if gui { None } else { Some(&next) }, &review())
                .unwrap();
            assert!(e.transferred_to(if gui { None } else { Some(&next) }));
            let first = Instant::now();
            e.cancel(first).unwrap();
            e.scope.read.revoke(first);
            assert_eq!(e.native_stop(first).unwrap(), None);
            assert_eq!(e.stop_at(first).unwrap(), None);
            if !gui {
                assert_eq!(next.stop_at(first).unwrap(), Some(first));
            }
            assert!(e.history().unwrap().is_none());
            e.retired(true).unwrap();
            assert!(e.history().unwrap().is_some());
            assert_ne!(e.status().unwrap().phase, p::Phase::Final);
            e.history_returned(true).unwrap();
            assert_eq!(e.status().unwrap().phase, p::Phase::Final);
        }
    }
    #[test]
    fn earlier_stop_then_original_read_poison_is_absorbing_through_both_returns() {
        let (e, a, w) = entry();
        opened(&e, &a, &w);
        queued(&e);
        let c = e.caller(Kind::Prepare).unwrap();
        e.claim(&a).unwrap();
        e.enqueued().unwrap();
        let first = Instant::now();
        e.cancel(first).unwrap();
        crate::service_version_reserve_requests::tests::poison_original_read(&e.scope.read);
        assert!(e.native_stop(first).is_err());
        assert_eq!(e.lock().unwrap().stop, Some(first));
        c.returned(false).unwrap();
        e.retired(true).unwrap();
        assert_eq!(e.status().unwrap().settlement, Settlement::Unknown);
        assert!(e.history().unwrap().is_none());
    }
    #[test]
    fn repeated_unknown_and_stop_samples_do_not_self_wake_the_original_waiter() {
        use std::{
            future::Future,
            pin::pin,
            task::{Context, Waker},
            time::Duration,
        };
        let (e, a, w) = entry();
        reviewing(&e, &a, &w);
        let end = e.lock().unwrap().end;
        let mut changes = e.changes.subscribe();
        let mut cx = Context::from_waker(Waker::noop());
        let first = Instant::now();
        let initial = e.status().unwrap().revision;

        // Real Notified exists before the control query, as in watchdog.
        let mut stopped = pin!(w.notified());
        assert!(stopped.as_mut().poll(&mut cx).is_pending());
        e.cancel(first).unwrap();
        assert!(stopped.as_mut().poll(&mut cx).is_ready());
        assert!(changes.has_changed().unwrap());
        let _ = changes.borrow_and_update();
        assert_eq!(e.status().unwrap().revision, initial + 1);
        for _ in 0..3 {
            let mut quiet = pin!(w.notified());
            assert!(quiet.as_mut().poll(&mut cx).is_pending());
            e.cancel(first).unwrap();
            e.cancel(first + Duration::from_millis(1)).unwrap();
            assert_eq!(e.native_stop(first).unwrap(), Some(first));
            assert!(e.occupied().unwrap());
            assert_eq!(e.status().unwrap().revision, initial + 1);
            assert!(!changes.has_changed().unwrap());
            assert!(quiet.as_mut().poll(&mut cx).is_pending());
        }
        let earlier = first - Duration::from_millis(1);
        let mut tightened = pin!(w.notified());
        assert!(tightened.as_mut().poll(&mut cx).is_pending());
        e.cancel(earlier).unwrap();
        assert!(tightened.as_mut().poll(&mut cx).is_ready());
        assert!(changes.has_changed().unwrap());
        let _ = changes.borrow_and_update();
        assert_eq!(e.native_stop(first).unwrap(), Some(earlier));
        let before_unknown = e.status().unwrap().revision;

        let mut became_unknown = pin!(w.notified());
        assert!(became_unknown.as_mut().poll(&mut cx).is_pending());
        crate::service_version_reserve_requests::tests::poison_original_read(&e.scope.read);
        assert!(e.native_stop(first).is_err());
        e.unknown(); // Same cancellation_at error arm, not another transition.
        assert!(became_unknown.as_mut().poll(&mut cx).is_ready());
        assert!(changes.has_changed().unwrap());
        let _ = changes.borrow_and_update();
        let unknown = e.status().unwrap();
        assert_eq!(unknown.revision, before_unknown + 1);
        assert_eq!(unknown.settlement, Settlement::Unknown);
        for _ in 0..3 {
            let mut quiet = pin!(w.notified());
            assert!(quiet.as_mut().poll(&mut cx).is_pending());
            assert!(e.native_stop(first).is_err());
            e.unknown();
            e.cancel(earlier).unwrap();
            e.cancel(first).unwrap();
            assert_eq!(e.status().unwrap().revision, unknown.revision);
            assert!(!changes.has_changed().unwrap());
            assert!(quiet.as_mut().poll(&mut cx).is_pending());
        }
        // Unknown is absorbing, but a genuinely earlier STOP still wakes
        // once and preserves that earlier original control time.
        let earliest = earlier - Duration::from_millis(1);
        let mut earlier_unknown = pin!(w.notified());
        assert!(earlier_unknown.as_mut().poll(&mut cx).is_pending());
        e.cancel(earliest).unwrap();
        assert!(earlier_unknown.as_mut().poll(&mut cx).is_ready());
        assert!(changes.has_changed().unwrap());
        let _ = changes.borrow_and_update();
        let final_unknown = e.status().unwrap();
        assert_eq!(final_unknown.settlement, Settlement::Unknown);
        assert_eq!(final_unknown.revision, unknown.revision + 1);
        let mut quiet = pin!(w.notified());
        assert!(quiet.as_mut().poll(&mut cx).is_pending());
        e.cancel(earliest).unwrap();
        assert!(e.native_stop(first).is_err());
        e.unknown();
        assert_eq!(e.status().unwrap().revision, final_unknown.revision);
        assert!(!changes.has_changed().unwrap());
        assert!(quiet.as_mut().poll(&mut cx).is_pending());
        let s = e.lock().unwrap();
        assert_eq!(s.stop, Some(earliest));
        assert_eq!(s.end, end);
        assert!(!s.native_retired && !s.history_returned);
    }
    #[test]
    fn old_read_keeps_earliest_stop_and_row_capacity_overflow_never_reuses_permission() {
        let (e, a, w) = entry();
        reviewing(&e, &a, &w);
        let first = Instant::now();
        e.cancel(first).unwrap();
        e.scope
            .read
            .revoke(first - std::time::Duration::from_millis(1));
        assert_eq!(
            e.native_stop(first).unwrap(),
            Some(first - std::time::Duration::from_millis(1))
        );
        assert!(e.transfer(None, &review()).is_err());
        let (e, _, _) = entry();
        e.lock().unwrap().status.revision = u32::MAX - 1;
        assert!(e.cancel(first).is_err());
        assert_eq!(e.status().unwrap().settlement, Settlement::Unknown);
    }
}
