//! One compact row inside the ORIGINAL Configuration Book. This is not an
//! Inbox, native owner, runner or image custodian. A nonce reservation/tombstone
//! occupies the SAME32 budget and has no request origin until actual Submit.
use crate::{
    agent_identity_requests::SavedPoint,
    service_metadata_images_protocol as p,
    service_protocol::{Error, Id, OperationState, Settlement},
    service_version_reserve_requests::ReadPermission,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, OnceLock, Weak,
    },
    time::Instant,
};
use tokio::sync::{watch, Notify};

// Rows replace (never supplement) a Config32 slot. Include private source,
// review/IDs, watch/Arc/mutex cells and retained final/call metadata. No Values.
pub(crate) const ROW_BYTES: usize = std::mem::size_of::<Entry>() + 8192;
// ONE ordinary worker term joins the existing same-eight response maximum.
// Never add eight independent reply reservations for this sibling route.
pub(crate) const IPC_WORKER_BACKING: usize = 4 * p::REQUEST_BYTES + 4 * p::STATUS_BYTES + 4096;
pub(crate) struct Scope {
    pub saved: SavedPoint,
    pub read: Arc<ReadPermission>,
}
pub(crate) struct Grant {
    pub id: Id,
    pub scope: Scope,
    pub review: p::Review,
    pub end: Instant,
    pub wake: Weak<Notify>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum CallState {
    New,
    Pending,
    Returned,
}
struct State {
    revision: u32,
    revoked: Option<Instant>,
    stop: Option<Instant>,
    spent: bool,
    gui: bool,
    preclaimed: bool,
    enqueued: bool,
    call: CallState,
    native_retired: bool,
    native_result: Option<p::Final>,
    history_claimed: bool,
    history_returned: bool,
    unknown: bool,
}
pub(crate) struct Entry {
    pub nonce: Id,
    pub grant: Option<Grant>,
    input: OnceLock<p::Submit>,
    state: Mutex<State>,
    failed: Arc<AtomicBool>,
    changes: watch::Sender<u32>,
}
impl Entry {
    pub(crate) fn new(
        nonce: Id,
        grant: Option<Grant>,
        failed: Arc<AtomicBool>,
        changes: watch::Sender<u32>,
    ) -> Result<Arc<Self>, Error> {
        if let Some(g) = &grant {
            g.review.validate()?;
            // Bound real retained backing, not only serializable lengths.
            if g.scope.saved.root.capacity() > 4096
                || g.scope.saved.runtime_id.capacity() > 128
                || g.review.locale.capacity() > 32
                || g.review.asset_type.capacity() > 128
                || g.review.prepared_sha256.capacity() > 128
                || g.wake.strong_count() == 0
                || g.scope.read.stop(Instant::now())?.is_some()
                || Instant::now() >= g.end
            {
                return Err(Error::Conflict);
            }
        }
        let tombstone = grant.is_none();
        Ok(Arc::new(Self {
            nonce,
            grant,
            input: OnceLock::new(),
            state: Mutex::new(State {
                revision: 1,
                revoked: tombstone.then(Instant::now),
                stop: None,
                spent: tombstone,
                gui: false,
                preclaimed: false,
                enqueued: false,
                call: CallState::New,
                native_retired: false,
                native_result: None,
                history_claimed: false,
                history_returned: false,
                unknown: false,
            }),
            failed,
            changes,
        }))
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>, Error> {
        self.state.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    fn bump(&self, s: &mut State) -> Result<(), Error> {
        s.revision = s
            .revision
            .checked_add(1)
            .filter(|n| *n < u32::MAX)
            .ok_or_else(|| {
                s.unknown = true;
                Error::StateUnknown
            })?;
        let mut good = true;
        self.changes.send_modify(|n| {
            if let Some(next) = n.checked_add(1).filter(|n| *n < u32::MAX) {
                *n = next
            } else {
                good = false;
            }
        });
        if !good {
            self.failed.store(true, Ordering::Release);
            s.unknown = true;
            return Err(Error::StateUnknown);
        }
        Ok(())
    }
    pub(crate) fn wake(&self) {
        if let Some(w) = self.grant.as_ref().and_then(|g| g.wake.upgrade()) {
            w.notify_waiters();
        }
    }
    pub(crate) fn origin(&self) -> Option<&p::Query> {
        self.input.get().map(|v| &v.origin)
    }
    pub(crate) fn input(&self) -> Option<&p::Submit> {
        self.input.get()
    }
    fn complete(s: &State) -> bool {
        s.native_retired
            && s.history_returned
            && s.call != CallState::Pending
            && s.native_result.is_some()
            && !s.unknown
    }
    fn live_locked(&self, s: &State, now: Instant) -> Result<bool, Error> {
        let Some(g) = &self.grant else {
            return Ok(false);
        };
        Ok(!self.failed.load(Ordering::Acquire)
            && !s.unknown
            && !s.spent
            && !s.gui
            && !s.native_retired
            && s.revoked.is_none()
            && self.input.get().is_none()
            && now < g.end
            && g.wake.strong_count() > 0
            && g.scope.read.stop(now)?.is_none())
    }
    pub(crate) fn live(&self, now: Instant) -> Result<bool, Error> {
        self.live_locked(&*self.lock()?, now)
    }
    pub(crate) fn revoke(&self, at: Instant) -> Result<(), Error> {
        let mut s = self.lock()?;
        if s.revoked.is_some_and(|old| old <= at) {
            return Ok(());
        }
        s.revoked = Some(s.revoked.map_or(at, |old| old.min(at)));
        self.bump(&mut s)?;
        drop(s);
        self.wake();
        Ok(())
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Result<Option<Instant>, Error> {
        let s = self.lock()?;
        // A withdrawn unused grant is not STOP authority over a GUI winner.
        if self.input.get().is_none() || s.gui || s.native_retired {
            return Ok(None);
        }
        let g = self.grant.as_ref().ok_or(Error::StateUnknown)?;
        if s.unknown || self.failed.load(Ordering::Acquire) || g.wake.strong_count() == 0 {
            return Err(Error::StateUnknown);
        }
        let mut at = s.stop;
        for t in [
            s.revoked,
            g.scope.read.stop(now)?.map(|(_, at)| at),
            (!s.preclaimed && now >= g.end).then_some(g.end),
        ]
        .into_iter()
        .flatten()
        {
            at = Some(at.map_or(t, |old| old.min(t)));
        }
        Ok(at)
    }
    pub(crate) fn cancel(&self, at: Instant) -> Result<(), Error> {
        let mut s = self.lock()?;
        if s.native_retired || s.stop.is_some_and(|old| old <= at) {
            return Ok(());
        }
        s.stop = Some(s.stop.map_or(at, |old| old.min(at)));
        self.bump(&mut s)?;
        drop(s);
        self.wake();
        Ok(())
    }
    pub(crate) fn unknown(&self) {
        if let Ok(mut s) = self.lock() {
            if !Self::complete(&s) && !s.unknown {
                s.unknown = true;
                let _ = self.bump(&mut s);
            }
        }
        self.wake();
    }
    pub(crate) fn occupied(&self) -> Result<bool, Error> {
        if let Some(at) = self.stop_at(Instant::now())? {
            self.cancel(at)?;
        }
        let s = self.lock()?;
        Ok(s.unknown
            || self.input.get().is_some() && !Self::complete(&s)
            || self.live_locked(&s, Instant::now())?)
    }
    pub(crate) fn submit(&self, input: p::Submit) -> Result<p::Status, Error> {
        input.validate()?;
        let mut s = self.lock()?;
        let g = self.grant.as_ref().ok_or(Error::AccessDenied)?;
        if let Some(old) = self.input.get() {
            if old != &input {
                return Err(Error::Conflict);
            }
            drop(s);
            return self.status();
        }
        if input.grant_id != g.id
            || input.origin.project_id != g.scope.saved.project_id
            || !self.live_locked(&s, Instant::now())?
        {
            return Err(Error::Conflict);
        }
        self.input.set(input).map_err(|_| Error::Conflict)?;
        self.bump(&mut s)?;
        drop(s);
        self.wake();
        self.status()
    }
    /// CLI and ordinary GUI claims serialize on this SAME row, before native
    /// publication/plan consumption. An unused expired/revoked grant cannot
    /// inherit a later READ failure into an explicitly confirmed GUI winner.
    pub(crate) fn gui_claim(&self) -> Result<(), Error> {
        let mut s = self.lock()?;
        if self.input.get().is_some() || s.spent || s.native_retired || s.unknown {
            return Err(Error::Busy);
        }
        s.gui = true;
        s.spent = true;
        self.bump(&mut s)
    }
    pub(crate) fn gui_owned(&self) -> bool {
        self.lock()
            .is_ok_and(|s| s.gui && self.input.get().is_none())
    }
    pub(crate) fn pending(&self) -> Result<bool, Error> {
        let s = self.lock()?;
        Ok(self.input.get().is_some()
            && !s.preclaimed
            && !s.native_retired
            && !s.unknown
            && s.stop.is_none()
            && !self.failed.load(Ordering::Acquire))
    }
    pub(crate) fn caller(self: &Arc<Self>) -> Result<Call, Error> {
        let mut s = self.lock()?;
        if self.input.get().is_none() || s.call != CallState::New || s.native_retired || s.unknown {
            return Err(Error::Conflict);
        }
        s.call = CallState::Pending;
        self.bump(&mut s)?;
        Ok(Call {
            entry: self.clone(),
            returned: false,
        })
    }
    pub(crate) fn preclaim(&self) -> Result<bool, Error> {
        if self.stop_at(Instant::now())?.is_some() {
            return Err(Error::Expired);
        }
        let mut s = self.lock()?;
        if s.preclaimed || s.native_retired {
            return Ok(false);
        }
        if self.input.get().is_none()
            || s.call != CallState::Pending
            || s.unknown
            || s.stop.is_some()
            || self.failed.load(Ordering::Acquire)
        {
            return Err(Error::StateUnknown);
        }
        s.preclaimed = true;
        s.spent = true;
        self.bump(&mut s)?;
        Ok(true)
    }
    pub(crate) fn enqueue(&self) -> Result<(), Error> {
        if self.stop_at(Instant::now())?.is_some() {
            return Err(Error::Expired);
        }
        let mut s = self.lock()?;
        if !s.preclaimed
            || s.enqueued
            || s.native_retired
            || s.call != CallState::Pending
            || s.unknown
            || s.stop.is_some()
        {
            return Err(Error::Conflict);
        }
        s.enqueued = true;
        self.bump(&mut s)
    }
    /// Only the actual original EditOwner retirement supplies this. Seal first
    /// even without Submit, so a late request cannot land after that callback.
    pub(crate) fn retired(&self, result: Option<p::Final>) -> Result<(), Error> {
        let mut s = self.lock()?;
        if s.native_retired {
            return Err(Error::Conflict);
        }
        s.spent = true;
        s.native_retired = true;
        if result.is_none() {
            s.unknown = true;
        }
        if self.input.get().is_some() {
            if result
                .as_ref()
                .is_some_and(|v| v.apply_submitted != s.enqueued)
            {
                s.unknown = true;
            }
            if result.is_none() {
                s.unknown = true;
            }
            s.native_result = result;
        }
        self.bump(&mut s)
    }
    pub(crate) fn history(&self) -> Result<Option<(Id, OperationState, Settlement)>, Error> {
        let mut s = self.lock()?;
        let Some(input) = self.input.get() else {
            return Ok(None);
        };
        if !s.native_retired || s.call == CallState::Pending || s.history_claimed || s.unknown {
            return Ok(None);
        }
        let f = s.native_result.as_ref().ok_or(Error::StateUnknown)?;
        let state = if f.completed {
            OperationState::Succeeded
        } else if f.journal == p::Journal::RecoveryRequired {
            OperationState::RecoveryRequired
        } else if f.cancelled {
            OperationState::Cancelled
        } else {
            OperationState::Failed
        };
        s.history_claimed = true;
        Ok(Some((
            input.origin.request_id.clone(),
            state,
            Settlement::Settled,
        )))
    }
    pub(crate) fn history_returned(&self, ok: bool) -> Result<(), Error> {
        let mut s = self.lock()?;
        if !s.history_claimed || s.history_returned {
            return Err(Error::Conflict);
        }
        if ok {
            s.history_returned = true
        } else {
            s.unknown = true;
        }
        self.bump(&mut s)
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        match self.stop_at(Instant::now()) {
            Ok(Some(at)) => self.cancel(at)?,
            Err(_) => self.unknown(),
            _ => {}
        }
        let input = self.input.get().ok_or(Error::Conflict)?;
        let g = self.grant.as_ref().ok_or(Error::StateUnknown)?;
        let s = self.lock()?;
        let done = Self::complete(&s);
        let unknown = s.unknown || !done && self.failed.load(Ordering::Acquire);
        let status = p::Status {
            schema_version: 1,
            origin: input.origin.clone(),
            grant_id: g.id.clone(),
            revision: s.revision,
            phase: if unknown {
                p::Phase::Unknown
            } else if done {
                p::Phase::Final
            } else if s.stop.is_some() || s.revoked.is_some() {
                p::Phase::Stopping
            } else if s.enqueued {
                p::Phase::Applying
            } else if s.preclaimed {
                p::Phase::Admitting
            } else {
                p::Phase::Queued
            },
            settlement: if unknown {
                Settlement::Unknown
            } else if done {
                Settlement::Settled
            } else {
                Settlement::Pending
            },
            review: g.review.clone(),
            cancel_requested: s.stop.is_some() || s.revoked.is_some(),
            result: if done && !unknown {
                s.native_result.clone()
            } else {
                None
            },
            do_not_replay: true,
        };
        status.validate()?;
        Ok(status)
    }
    pub(crate) fn access(&self, instance: &Id) -> Result<p::Access, Error> {
        let Some(g) = &self.grant else {
            return Ok(p::Access::empty(instance.clone()));
        };
        let remaining = if self.live(Instant::now())? {
            g.end
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(900000) as u64
        } else {
            0
        };
        let a = p::Access {
            schema_version: 1,
            service_instance: instance.clone(),
            project_id: Some(g.scope.saved.project_id.clone()),
            grant_id: Some(g.id.clone()),
            nonce: Some(self.nonce.clone()),
            review: Some(g.review.clone()),
            live: remaining > 0,
            remaining_ms: remaining,
            request: self.input.get().map(|_| self.status()).transpose()?,
        };
        a.validate()?;
        Ok(a)
    }
}
pub(crate) struct Call {
    entry: Arc<Entry>,
    returned: bool,
}
impl Call {
    pub(crate) fn returned(mut self) -> Result<(), Error> {
        let mut s = self.entry.lock()?;
        if s.call != CallState::Pending {
            return Err(Error::Conflict);
        }
        s.call = CallState::Returned;
        self.entry.bump(&mut s)?;
        self.returned = true;
        Ok(())
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown();
            let _ = self.entry.cancel(Instant::now());
        }
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use p::fixtures::*;
    pub(crate) fn grant(wake: &Arc<Notify>) -> Grant {
        let end = Instant::now() + std::time::Duration::from_secs(300);
        Grant {
            id: id('4'),
            scope: Scope {
                saved: SavedPoint {
                    project_id: id('2'),
                    runtime_id: "project".into(),
                    root: "/never-opened-image-entry".into(),
                    device: 1,
                    inode: 2,
                    revision: 3,
                    fresh: true,
                },
                read: Arc::new(ReadPermission::new(end)),
            },
            review: review(),
            end,
            wake: Arc::downgrade(wake),
        }
    }
    pub(crate) fn entry() -> (Arc<Entry>, Arc<Notify>) {
        let wake = Arc::new(Notify::new());
        let (changes, _) = watch::channel(1);
        (
            Entry::new(
                id('5'),
                Some(grant(&wake)),
                Arc::new(AtomicBool::new(false)),
                changes,
            )
            .unwrap(),
            wake,
        )
    }
    pub(crate) fn input() -> p::Submit {
        p::Submit {
            origin: query(),
            grant_id: id('4'),
            reviewed: true,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::*;
    use p::fixtures::*;
    #[test]
    fn image_entry_needs_original_raw_native_and_history_returns_once() {
        for native_first in [false, true] {
            let (e, _wake) = entry();
            e.submit(input()).unwrap();
            let call = e.caller().unwrap();
            assert!(e.preclaim().unwrap());
            e.enqueue().unwrap();
            assert!(e.enqueue().is_err());
            assert!(e.history().unwrap().is_none());
            assert_eq!(e.status().unwrap().phase, p::Phase::Applying);
            if native_first {
                e.retired(Some(done())).unwrap();
                assert!(e.history().unwrap().is_none());
                call.returned().unwrap();
            } else {
                call.returned().unwrap();
                assert!(e.history().unwrap().is_none());
                e.retired(Some(done())).unwrap();
            }
            assert_ne!(e.status().unwrap().phase, p::Phase::Final);
            assert!(e.history().unwrap().is_some());
            assert!(e.history().unwrap().is_none());
            assert_ne!(e.status().unwrap().phase, p::Phase::Final);
            e.history_returned(true).unwrap();
            assert_eq!(e.status().unwrap().result, Some(done()));
            assert_eq!(e.submit(input()).unwrap().phase, p::Phase::Final);
            assert!(e.caller().is_err());
            assert!(!e.occupied().unwrap());
            assert!(e.retired(Some(done())).is_err());
            assert!(e.history_returned(true).is_err());
        }
    }
    #[test]
    fn image_lost_raw_or_history_failure_remains_unknown_never_replayed() {
        let (e, _wake) = entry();
        e.submit(input()).unwrap();
        let call = e.caller().unwrap();
        e.preclaim().unwrap();
        e.enqueue().unwrap();
        e.retired(Some(done())).unwrap();
        drop(call);
        assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
        assert!(e.occupied().unwrap());
        assert!(e.history().unwrap().is_none());
        assert!(e.status().unwrap().result.is_none());
        assert!(e.caller().is_err());
        let (e, _wake) = entry();
        e.submit(input()).unwrap();
        let call = e.caller().unwrap();
        e.preclaim().unwrap();
        e.enqueue().unwrap();
        call.returned().unwrap();
        e.retired(Some(done())).unwrap();
        assert!(e.history().unwrap().is_some());
        e.history_returned(false).unwrap();
        assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
        assert!(e.occupied().unwrap());
        assert!(e.history().unwrap().is_none());
        assert!(e.status().unwrap().result.is_none());
    }
    #[test]
    fn unused_image_lease_gui_winner_does_not_inherit_read_or_revoke_stop() {
        let (e, _wake) = entry();
        let at = Instant::now();
        e.revoke(at).unwrap();
        e.grant.as_ref().unwrap().scope.read.revoke(at);
        assert!(!e.live(Instant::now()).unwrap());
        e.gui_claim().unwrap();
        assert!(e.gui_owned());
        assert_eq!(e.stop_at(Instant::now()).unwrap(), None);
        assert!(e.submit(input()).is_err());
        assert!(e.origin().is_none());
        assert!(e.history().unwrap().is_none());
        assert!(e.gui_claim().is_err());
        let (e, _wake) = entry();
        e.submit(input()).unwrap();
        assert!(e.gui_claim().is_err());
    }
    #[test]
    fn image_original_earliest_read_stop_and_expired_grant_never_renew() {
        let (e, _wake) = entry();
        e.submit(input()).unwrap();
        let first = Instant::now();
        e.grant.as_ref().unwrap().scope.read.revoke(first);
        e.cancel(first + std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(e.stop_at(first).unwrap(), Some(first));
        assert!(e.preclaim().is_err());
        assert_eq!(e.status().unwrap().phase, p::Phase::Stopping);
        let (e, _wake) = entry();
        let end = e.grant.as_ref().unwrap().end;
        assert!(!e.live(end).unwrap());
        assert_eq!(e.grant.as_ref().unwrap().end, end);
        assert!(
            ROW_BYTES
                <= crate::service_configuration_protocol::STATUS_BYTES
                    + 8192
                    + std::mem::size_of::<crate::service_configuration_requests::Entry>()
        );
    }
    #[test]
    fn image_preapply_native_cancel_can_settle_but_missing_retirement_cannot() {
        let (e, _wake) = entry();
        e.submit(input()).unwrap();
        e.cancel(Instant::now()).unwrap();
        assert!(e.history().unwrap().is_none());
        assert!(e.status().unwrap().result.is_none());
        let f = p::Final {
            effect: p::Effect::NotStarted,
            journal: p::Journal::NotCreated,
            cancelled: true,
            apply_submitted: false,
            completed: false,
        };
        e.retired(Some(f.clone())).unwrap();
        assert!(e.history().unwrap().is_some());
        assert_eq!(e.status().unwrap().phase, p::Phase::Stopping);
        e.history_returned(true).unwrap();
        assert_eq!(e.status().unwrap().result, Some(f));
        assert!(e.caller().is_err());
        let (e, _wake) = entry();
        e.submit(input()).unwrap();
        e.retired(None).unwrap();
        assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
        assert!(e.history().unwrap().is_none());
    }
}
