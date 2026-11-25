//! One compact sibling in Config's SAME32. The real native Session owns the
//! writer and anchor. Calls, native retirement and history are independent cuts.
use crate::{
    service_configuration_requests::Source,
    service_workflow_edit_protocol as p,
    service_protocol::{Error, Id, OperationState, Settlement},
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
pub(crate) const ROW_BYTES: usize = std::mem::size_of::<Entry>() + 16 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Open,
    Prepare,
    Apply,
}
impl Kind {
    fn index(self) -> usize {
        match self {
            Self::Open => 0,
            Self::Prepare => 1,
            Self::Apply => 2,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Returned {
    New,
    Pending,
    Returned,
}
struct Row {
    status: p::Status,
    calls: [Returned; 3],
    dispatch: Option<Kind>,
    claimed: bool,
    native_retired: bool,
    result: Option<p::Final>,
    binding: Option<(Id, Id, Weak<()>)>,
    wake: Weak<Notify>,
    apply: Option<p::Apply>,
    permission_end: Option<Instant>,
    allow_claim: Option<u32>,
    apply_end: Option<Instant>,
    apply_entered: bool,
    stop: Option<Instant>,
    history_claimed: bool,
    history_returned: bool,
}
pub(crate) struct Entry {
    pub(crate) input: p::Prepare,
    pub(crate) source: Source,
    pub(crate) read: Arc<ReadPermission>,
    row: Mutex<Row>,
    failed: Arc<AtomicBool>,
    changes: watch::Sender<u32>,
}
impl Entry {
    pub(crate) fn new(
        input: p::Prepare,
        source: Source,
        read: Arc<ReadPermission>,
        failed: Arc<AtomicBool>,
        changes: watch::Sender<u32>,
    ) -> Result<Arc<Self>, Error> {
        input.validate()?;
        if source.root.capacity() > 4096
            || source.runtime_id.capacity() > 128
            || !p::runtime_id(&source.runtime_id)
            || source.observation_revision != input.expected_observation_revision
            || read.stop(Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        let status = p::Status {
            schema_version: 1,
            origin: input.origin.clone(),
            runtime_project_id: source.runtime_id.clone(),
            revision: 1,
            phase: p::Phase::QueuedOpen,
            settlement: Settlement::Pending,
            original: None,
            review: None,
            permission_available: false,
            permission_consumed: false,
            remaining_ms: 0,
            cancel_requested: false,
            result: None,
            do_not_replay: true,
        };
        status.validate()?;
        Ok(Arc::new(Self {
            input,
            source,
            read,
            failed,
            changes,
            row: Mutex::new(Row {
                status,
                calls: [Returned::New; 3],
                dispatch: None,
                claimed: false,
                native_retired: false,
                result: None,
                binding: None,
                wake: Weak::new(),
                apply: None,
                permission_end: None,
                allow_claim: None,
                apply_end: None,
                apply_entered: false,
                stop: None,
                history_claimed: false,
                history_returned: false,
            }),
        }))
    }
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    fn bump(&self, r: &mut Row) -> Result<(), Error> {
        let Some(next) = r.status.revision.checked_add(1).filter(|v| *v < u32::MAX) else {
            self.failed.store(true, Ordering::Release);
            r.status.phase = p::Phase::Unknown;
            return Err(Error::StateUnknown);
        };
        r.status.revision = next;
        let mut good = true;
        self.changes.send_modify(|n| {
            if let Some(v) = n.checked_add(1).filter(|v| *v < u32::MAX) {
                *n = v
            } else {
                good = false
            }
        });
        if let Some(w) = r.wake.upgrade() {
            w.notify_waiters();
        }
        if !good {
            self.failed.store(true, Ordering::Release);
            r.status.phase = p::Phase::Unknown;
            return Err(Error::StateUnknown);
        }
        Ok(())
    }
    fn unknown_locked(&self, r: &mut Row) {
        if !matches!(r.status.phase, p::Phase::Unknown | p::Phase::Final) {
            r.status.phase = p::Phase::Unknown;
            r.permission_end = None;
            r.allow_claim = None;
            r.result = None;
            let _ = self.bump(r);
        }
    }
    pub(crate) fn unknown(&self) {
        if let Ok(mut r) = self.lock() {
            self.unknown_locked(&mut r);
        }
    }
    fn stop_locked(&self, r: &mut Row, now: Instant) -> Result<Option<Instant>, Error> {
        if r.status.phase == p::Phase::Final {
            return Ok(None);
        }
        // Original READ poison is imported even after a prior STOP, not only
        // when a renderer asks for status. Unknown is absorbing immediately.
        if self.failed.load(Ordering::Acquire) || r.status.phase == p::Phase::Unknown {
            self.unknown_locked(r);
            return Err(Error::StateUnknown);
        }
        let read = match self.read.stop(now) {
            Ok(v) => v.map(|(_, at)| at),
            Err(e) => {
                self.unknown_locked(r);
                return Err(e);
            }
        };
        let approval = r.apply_end.filter(|end| !r.apply_entered && now >= *end);
        Ok([r.stop, read, approval].into_iter().flatten().min())
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Result<Option<Instant>, Error> {
        let mut r = self.lock()?;
        self.stop_locked(&mut r, now)
    }
    pub(crate) fn live(&self, now: Instant) -> bool {
        self.stop_at(now).is_ok_and(|v| v.is_none())
    }
    pub(crate) fn cancel(&self, at: Instant) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.status.phase == p::Phase::Final || r.stop.is_some_and(|old| old <= at) {
            return Ok(());
        }
        r.stop = Some(at);
        r.status.cancel_requested = true;
        r.permission_end = None;
        r.allow_claim = None;
        if r.status.phase != p::Phase::Unknown {
            r.status.phase = if r.claimed {
                p::Phase::Stopping
            } else {
                p::Phase::Refused
            };
        }
        self.bump(&mut r)
    }
    pub(crate) fn occupied(&self) -> Result<bool, Error> {
        match self.stop_at(Instant::now()) {
            Ok(Some(at)) => self.cancel(at)?,
            Err(_) => self.unknown(),
            _ => {}
        }
        Ok(self.lock()?.status.phase != p::Phase::Final)
    }
    pub(crate) fn queued(&self, kind: Kind) -> Result<bool, Error> {
        let mut r = self.lock()?;
        Ok(self.stop_locked(&mut r, Instant::now())?.is_none()
            && r.calls[kind.index()] == Returned::New
            && r.status.phase
                == match kind {
                    Kind::Open => p::Phase::QueuedOpen,
                    Kind::Prepare => p::Phase::Opened,
                    Kind::Apply => p::Phase::QueuedApply,
                })
    }
    pub(crate) fn caller(self: &Arc<Self>, kind: Kind) -> Result<Call, Error> {
        let mut r = self.lock()?;
        if self.stop_locked(&mut r, Instant::now())?.is_some()
            || r.dispatch.is_some()
            || r.calls[kind.index()] != Returned::New
            || r.status.phase
                != match kind {
                    Kind::Open => p::Phase::QueuedOpen,
                    Kind::Prepare => p::Phase::Opened,
                    Kind::Apply => p::Phase::QueuedApply,
                }
        {
            return Err(Error::Conflict);
        }
        r.calls[kind.index()] = Returned::Pending;
        r.dispatch = Some(kind);
        r.status.phase = match kind {
            Kind::Open => p::Phase::Opening,
            Kind::Prepare => p::Phase::Preparing,
            Kind::Apply => p::Phase::Applying,
        };
        self.bump(&mut r)?;
        Ok(Call {
            entry: self.clone(),
            kind,
            returned: false,
        })
    }
    pub(crate) fn admitting(&self, kind: Kind) -> bool {
        self.lock().is_ok_and(|mut r| {
            r.dispatch == Some(kind)
                && r.calls[kind.index()] == Returned::Pending
                && !r.native_retired
                && self
                    .stop_locked(&mut r, Instant::now())
                    .is_ok_and(|v| v.is_none())
        })
    }
    pub(crate) fn claim_open(&self) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.claimed
            || r.dispatch != Some(Kind::Open)
            || self.stop_locked(&mut r, Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        r.claimed = true;
        Ok(())
    }
    pub(crate) fn bind(
        &self,
        session: Id,
        generation: Id,
        marker: Weak<()>,
        wake: &Arc<Notify>,
    ) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed
            || r.binding.is_some()
            || marker.strong_count() == 0
            || r.dispatch != Some(Kind::Open)
        {
            return Err(Error::StateUnknown);
        }
        r.binding = Some((session, generation, marker));
        r.wake = Arc::downgrade(wake);
        r.dispatch = None;
        self.bump(&mut r)
    }
    pub(crate) fn bound(&self, session: &str, generation: &str) -> bool {
        self.lock().is_ok_and(|r| {
            r.binding.as_ref().is_some_and(|(s, g, m)| {
                s.as_str() == session && g.as_str() == generation && m.strong_count() > 0
            })
        })
    }
    pub(crate) fn claimed(&self) -> bool {
        self.lock().is_ok_and(|r| r.claimed)
    }
    pub(crate) fn consume(&self, kind: Kind) -> Result<(), Error> {
        let mut r = self.lock()?;
        if kind == Kind::Open
            || r.dispatch != Some(kind)
            || self.stop_locked(&mut r, Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        if kind == Kind::Apply {
            if !r.apply_end.is_some_and(|end| Instant::now() < end) || r.apply_entered {
                return Err(Error::Expired);
            }
            r.apply_entered = true;
        }
        r.dispatch = None;
        Ok(())
    }
    pub(crate) fn opened(&self, original: p::Original) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r
            .binding
            .as_ref()
            .is_some_and(|(s, g, _)| s == &original.session_id && g == &original.owner_generation)
        {
            return Err(Error::Conflict);
        }
        if let Some(prior) = &r.status.original {
            return if prior == &original {
                Ok(())
            } else {
                Err(Error::StateUnknown)
            };
        }
        r.status.original = Some(original);
        if r.status.phase == p::Phase::Opening && r.calls[0] == Returned::Returned {
            r.status.phase = p::Phase::Opened;
        }
        self.bump(&mut r)
    }
    pub(crate) fn prepared(&self, review: p::Review) -> Result<(), Error> {
        review.validate()?;
        // Typed private copies are native-constructed, and the only variable
        // public strings are normalized bounded coordinate strings.
        if !review.bounded_backing() {
            return Err(Error::Busy);
        }
        let mut r = self.lock()?;
        if let Some(prior) = &r.status.review {
            let mut compare = review;
            compare.native_status_revision = prior.native_status_revision;
            return if prior == &compare {
                Ok(())
            } else {
                Err(Error::StateUnknown)
            };
        }
        if r.status.original.is_none()
            || r.calls[1] == Returned::New
            || r.status.phase != p::Phase::Preparing
        {
            return Err(Error::Conflict);
        }
        r.status.review = Some(review);
        if r.calls[1] == Returned::Returned {
            r.status.phase = p::Phase::Reviewing;
        }
        self.bump(&mut r)
    }
    pub(crate) fn original(&self) -> Result<p::Original, Error> {
        self.lock()?.status.original.clone().ok_or(Error::Conflict)
    }
    pub(crate) fn review(&self) -> Result<p::Review, Error> {
        self.lock()?.status.review.clone().ok_or(Error::Conflict)
    }
    /// MAIN issued status revision is consumed BEFORE off-lock Host work. A
    /// later Allow cannot obtain a new stamp after a prior Revoke/Cancel.
    pub(crate) fn reserve_allow(&self, args: &p::Allow) -> Result<u32, Error> {
        args.validate()?;
        let mut r = self.lock()?;
        if self.stop_locked(&mut r, Instant::now())?.is_some()
            || r.status.phase != p::Phase::Reviewing
            || r.calls[1] != Returned::Returned
            || r.status.revision != args.expected_request_revision
            || r.permission_end.is_some()
            || r.allow_claim.is_some()
            || r.apply.is_some()
            || args.origin != self.input.origin
            || r.status.original.as_ref() != Some(&args.original)
            || !r.status.review.as_ref().is_some_and(|v| {
                v.plan_token == args.plan_token
                    && v.native_status_revision == args.expected_native_status_revision
            })
        {
            return Err(Error::Conflict);
        }
        self.bump(&mut r)?;
        let ticket = r.status.revision;
        r.allow_claim = Some(ticket);
        Ok(ticket)
    }
    pub(crate) fn allow(&self, ticket: u32, end: Instant) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.status.revision != ticket
            || r.allow_claim != Some(ticket)
            || r.status.phase != p::Phase::Reviewing
            || self.stop_locked(&mut r, Instant::now())?.is_some()
            || Instant::now() >= end
        {
            return Err(Error::Conflict);
        }
        r.allow_claim = None;
        r.permission_end = Some(end.min(self.read.end()));
        self.bump(&mut r)
    }
    pub(crate) fn apply(&self, input: p::Apply) -> Result<p::Status, Error> {
        p::bounded(&input, p::REQUEST_BYTES)?;
        let mut r = self.lock()?;
        if let Some(prior) = &r.apply {
            if prior != &input {
                return Err(Error::Conflict);
            }
            drop(r);
            return self.status();
        }
        if !input.reviewed
            || input.origin != self.input.origin
            || r.status.phase != p::Phase::Reviewing
            || r.status.original.as_ref() != Some(&input.original)
            || !r
                .status
                .review
                .as_ref()
                .is_some_and(|v| v.plan_token == input.plan_token)
            || self.stop_locked(&mut r, Instant::now())?.is_some()
            || !r.permission_end.is_some_and(|t| Instant::now() < t)
        {
            return Err(Error::AccessDenied);
        }
        r.apply_end = r.permission_end.take();
        r.apply = Some(input);
        r.status.phase = p::Phase::QueuedApply;
        self.bump(&mut r)?;
        drop(r);
        self.status()
    }
    /// Only original observe_final, after real resource joins and atomic native
    /// terminal adoption, calls this. A terminal frame/status is not retirement.
    pub(crate) fn retired(&self, result: Option<p::Final>) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed || r.native_retired {
            return Err(Error::Conflict);
        }
        r.native_retired = true;
        r.permission_end = None;
        r.allow_claim = None;
        if result.is_none() {
            self.unknown_locked(&mut r);
        } else if r.status.phase != p::Phase::Unknown {
            r.result = result;
        }
        self.bump(&mut r)
    }
    pub(crate) fn history(&self) -> Result<Option<(Id, OperationState, Settlement)>, Error> {
        let mut r = self.lock()?;
        if r.history_claimed || r.calls.contains(&Returned::Pending) {
            return Ok(None);
        }
        let unknown = r.status.phase == p::Phase::Unknown;
        if !unknown && !(r.native_retired || !r.claimed && r.stop.is_some()) {
            return Ok(None);
        }
        let state = if unknown {
            OperationState::Unknown
        } else if r.result.as_ref().is_some_and(p::Final::saved) {
            OperationState::Succeeded
        } else if r
            .result
            .as_ref()
            .is_some_and(|v| v.journal == p::Journal::RecoveryRequired)
        {
            OperationState::RecoveryRequired
        } else if r.status.cancel_requested || r.result.as_ref().is_some_and(|v| v.cancelled) {
            OperationState::Cancelled
        } else {
            OperationState::Failed
        };
        r.history_claimed = true;
        Ok(Some((
            self.input.origin.request_id.clone(),
            state,
            if unknown {
                Settlement::Unknown
            } else {
                Settlement::Settled
            },
        )))
    }
    pub(crate) fn history_returned(&self, ok: bool) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.history_claimed || r.history_returned {
            return Err(Error::Conflict);
        }
        r.history_returned = true;
        if !ok {
            self.unknown_locked(&mut r);
            return Err(Error::StateUnknown);
        }
        if r.status.phase != p::Phase::Unknown {
            if r.calls.contains(&Returned::Pending)
                || (!r.native_retired && (r.claimed || r.stop.is_none()))
            {
                self.unknown_locked(&mut r);
                return Err(Error::StateUnknown);
            }
            r.status.result = Some(r.result.clone().unwrap_or(p::Final {
                effect: p::Effect::NotStarted,
                journal: p::Journal::NotCreated,
                cancelled: r.status.cancel_requested,
                apply_submitted: false,
            }));
            r.status.phase = p::Phase::Final;
        }
        self.bump(&mut r)
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        match self.stop_at(Instant::now()) {
            Ok(Some(t)) => self.cancel(t)?,
            Err(_) => self.unknown(),
            _ => {}
        }
        let r = self.lock()?;
        let mut s = r.status.clone();
        s.settlement = match s.phase {
            p::Phase::Final => Settlement::Settled,
            p::Phase::Unknown => Settlement::Unknown,
            _ => Settlement::Pending,
        };
        s.permission_available = s.phase == p::Phase::Reviewing
            && r.permission_end.is_some_and(|end| Instant::now() < end)
            && r.stop.is_none();
        s.permission_consumed = r.apply.is_some();
        s.remaining_ms =
            if matches!(s.phase, p::Phase::Final | p::Phase::Unknown) || r.stop.is_some() {
                0
            } else {
                r.permission_end
                    .unwrap_or(self.read.end())
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(900000) as u64
            };
        s.validate()?;
        Ok(s)
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
        let mut r = self.entry.lock()?;
        if r.calls[self.kind.index()] != Returned::Pending {
            return Err(Error::Conflict);
        }
        r.calls[self.kind.index()] = Returned::Returned;
        if !ok {
            r.dispatch = None;
            r.permission_end = None;
            r.stop.get_or_insert_with(Instant::now);
            if r.claimed {
                self.entry.unknown_locked(&mut r);
            } else if r.status.phase != p::Phase::Unknown {
                r.status.phase = p::Phase::Refused;
            }
        } else if r.dispatch.is_some() {
            self.entry.unknown_locked(&mut r);
        } else if r.status.phase != p::Phase::Unknown && r.stop.is_none() {
            match self.kind {
                Kind::Open if r.status.original.is_some() => r.status.phase = p::Phase::Opened,
                Kind::Prepare if r.status.review.is_some() => r.status.phase = p::Phase::Reviewing,
                _ => {}
            }
        }
        self.entry.bump(&mut r)
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
#[path = "service_workflow_edit_requests_tests.rs"]
mod tests;
