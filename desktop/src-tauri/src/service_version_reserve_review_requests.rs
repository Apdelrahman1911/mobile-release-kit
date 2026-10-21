//! One Review row in the SAME Reserve32 book. No native owner, source, Store
//! payload, candidate, or executor is reconstructed from this metadata.
use crate::{
    agent_identity_requests::SavedPoint,
    service_protocol::{Error, Id, Settlement},
    service_version_reserve_protocol as reserve,
    service_version_reserve_requests::{NativeScope, ReadPermission},
    service_version_reserve_review_protocol as p,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::{Duration, Instant},
};
pub(crate) const ROW_BACKING: usize = p::REQUEST_BYTES
    + 2 * p::STATUS_BYTES
    + 8192
    + std::mem::size_of::<Entry>()
    + std::mem::size_of::<Row>();
pub(crate) const IPC_WORKER_BACKING: usize =
    crate::service_protocol::REQUEST_BYTES + 2 * p::STATUS_BYTES;
pub(crate) const NON_ROW_BACKING: usize = 16 * 1024;
/// SAME watchdog cleanup poll; never reschedules Unknown or a past endpoint.
pub(crate) fn poll_end(now: Instant, end: Instant, unknown: bool) -> Instant {
    if !unknown && now < end {
        end.min(now + Duration::from_millis(100))
    } else {
        end
    }
}
pub(crate) struct Scope {
    pub(crate) saved: SavedPoint,
    pub(crate) read: Arc<ReadPermission>,
}
struct Ready {
    view: p::Review,
    identity: Weak<()>,
    end: Instant,
}
struct Row {
    revision: u32,
    caller: bool,
    caller_returned: bool,
    bound: Option<Id>,
    native_returned: bool,
    ready: Option<Ready>,
    stop: Option<(reserve::Reason, Instant)>,
    reason: Option<reserve::Reason>,
    spent: bool,
}
pub(crate) struct Entry {
    pub(crate) input: p::Request,
    pub(crate) scope: Scope,
    pub(crate) started: Instant,
    row: Mutex<Row>,
    failed: AtomicBool,
}
impl Entry {
    pub(crate) fn new(
        input: p::Request,
        scope: Scope,
        started: Instant,
    ) -> Result<Arc<Self>, Error> {
        input.validate()?;
        if input.origin.project_id != scope.saved.project_id
            || !scope.saved.fresh
            || scope.saved.revision == 0
            || scope.saved.root.to_str().is_none_or(|s| s.len() > 4096)
            || scope.read.stop(Instant::now())?.is_some()
            || started
                .checked_add(Duration::from_secs(60))
                .is_none_or(|end| Instant::now() >= end)
        {
            return Err(Error::Conflict);
        }
        Ok(Arc::new(Self {
            input,
            scope,
            started,
            row: Mutex::new(Row {
                revision: 1,
                caller: false,
                caller_returned: false,
                bound: None,
                native_returned: false,
                ready: None,
                stop: None,
                reason: None,
                spent: false,
            }),
            failed: AtomicBool::new(false),
        }))
    }
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.unknown();
            Error::StateUnknown
        })
    }
    fn bump(&self, r: &mut Row) -> Result<(), Error> {
        r.revision = r
            .revision
            .checked_add(1)
            .filter(|n| *n < u32::MAX)
            .ok_or_else(|| {
                self.unknown();
                Error::StateUnknown
            })?;
        Ok(())
    }
    pub(crate) fn unknown(&self) {
        self.failed.store(true, Ordering::Release);
    }
    pub(crate) fn stop_at(
        &self,
        now: Instant,
    ) -> Result<Option<(reserve::Reason, Instant)>, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        let r = self.lock()?;
        if r.spent || r.native_returned && r.caller_returned {
            return Ok(None);
        }
        let mut first = r.stop;
        let read = self.scope.read.stop(now).map_err(|_| {
            // The original control read must retain uncertainty even if its
            // owner already has an earlier ordinary STOP/error. A later real
            // return cannot turn this poisoned observation into Refused.
            self.unknown();
            Error::StateUnknown
        })?;
        if let Some(v) = read {
            if first.is_none_or(|old| v.1 < old.1) {
                first = Some(v)
            }
        }
        let end = self
            .started
            .checked_add(Duration::from_secs(60))
            .ok_or(Error::StateUnknown)?;
        if now >= end && first.is_none_or(|v| end < v.1) {
            first = Some((reserve::Reason::Expired, end))
        }
        Ok(first)
    }
    pub(crate) fn cancel(&self, reason: reserve::Reason, at: Instant) {
        if self.failed.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut r) = self.lock() else { return };
        // A completed read is not a STOP handle for a later GUI/CLI Reserve.
        if r.spent || r.native_returned && r.caller_returned {
            return;
        }
        if r.stop.is_none_or(|old| at < old.1) {
            r.stop = Some((reason, at))
        }
        if !r.caller {
            r.native_returned = true;
            r.caller_returned = true;
            r.reason = Some(reason)
        }
        let _ = self.bump(&mut r);
    }
    pub(crate) fn holds_review(&self) -> bool {
        self.failed.load(Ordering::Acquire)
            || self.lock().map_or(true, |r| {
                !r.spent
                    && r.ready
                        .as_ref()
                        .is_some_and(|v| v.identity.strong_count() > 0 && Instant::now() < v.end)
            })
    }
    pub(crate) fn pending(&self) -> bool {
        if self.failed.load(Ordering::Acquire) {
            return true;
        }
        self.lock()
            .map_or(true, |r| !r.native_returned || !r.caller_returned)
    }
    pub(crate) fn admitting(&self) -> bool {
        self.stop_at(Instant::now()).is_ok_and(|s| s.is_none())
            && self
                .lock()
                .is_ok_and(|r| r.caller && !r.native_returned && !r.caller_returned)
    }
    pub(crate) fn begin(self: &Arc<Self>) -> Result<Caller, Error> {
        if self.stop_at(Instant::now())?.is_some() {
            return Err(Error::Expired);
        }
        let mut r = self.lock()?;
        if r.caller || r.native_returned || r.caller_returned {
            return Err(Error::Conflict);
        }
        r.caller = true;
        self.bump(&mut r)?;
        Ok(Caller {
            entry: self.clone(),
            returned: false,
        })
    }
    /// Called only at actual SOURCE installation, before its Supervisor GO.
    pub(crate) fn bind(&self, id: &str) -> Result<(), Error> {
        if !self.admitting() {
            return Err(Error::Conflict);
        }
        let mut r = self.lock()?;
        if r.bound.is_some() {
            return Err(Error::StateUnknown);
        }
        r.bound = Some(Id::parse(id)?);
        self.bump(&mut r)
    }
    /// Called under the original Doc after actual SOURCE wait/retirement and
    /// the existing private Review constructor, not from a parsed Status.
    pub(crate) fn native_ready(
        &self,
        id: &str,
        revision: u32,
        identity: &Arc<()>,
        end: Instant,
    ) -> Result<(), Error> {
        if !self.admitting() || end > self.scope.read.end() || revision == 0 || revision == u32::MAX
        {
            return Err(Error::Conflict);
        }
        let mut r = self.lock()?;
        if r.bound.as_ref().map(Id::as_str) != Some(id) || r.native_returned {
            return Err(Error::StateUnknown);
        }
        r.ready = Some(Ready {
            view: p::Review {
                id: Id::parse(id)?,
                revision,
            },
            identity: Arc::downgrade(identity),
            end,
        });
        r.native_returned = true;
        self.bump(&mut r)
    }
    pub(crate) fn native_refused(&self, reason: reserve::Reason) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.native_returned {
            return Err(Error::StateUnknown);
        }
        r.reason = Some(reason);
        r.native_returned = true;
        self.bump(&mut r)
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        match self.stop_at(Instant::now()) {
            Ok(Some((reason, at))) => self.cancel(reason, at),
            Err(_) => self.unknown(),
            _ => (),
        }
        let r = self.lock()?;
        let unknown = self.failed.load(Ordering::Acquire);
        let returned = r.native_returned && r.caller_returned;
        let ready = returned && r.ready.is_some() && !unknown;
        let phase = if unknown {
            p::Phase::Unknown
        } else if ready {
            p::Phase::ReviewReady
        } else if returned {
            p::Phase::Refused
        } else if r.stop.is_some() {
            p::Phase::Stopping
        } else if r.native_returned {
            p::Phase::Finishing
        } else if r.caller {
            p::Phase::Reading
        } else {
            p::Phase::Queued
        };
        let remaining = if ready && !r.spent && self.scope.read.stop(Instant::now())?.is_none() {
            r.ready
                .as_ref()
                .filter(|v| v.identity.strong_count() > 0)
                .map_or(0, |v| {
                    v.end
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(u128::from(reserve::REVIEW_MS)) as u64
                })
        } else {
            0
        };
        let out = p::Status {
            schema_version: 1,
            origin: self.input.origin.clone(),
            runtime_project_id: self.scope.saved.runtime_id.clone(),
            options: self.input.options.clone(),
            revision: r.revision,
            phase,
            settlement: if unknown {
                Settlement::Unknown
            } else if returned {
                Settlement::Settled
            } else {
                Settlement::Pending
            },
            operation_id: r.bound.clone(),
            review: if ready {
                r.ready.as_ref().map(|v| v.view.clone())
            } else {
                None
            },
            remaining_ms: remaining,
            reason: if unknown {
                Some(reserve::Reason::CleanupUnknown)
            } else if ready {
                None
            } else {
                r.stop.map(|v| v.0).or(r.reason)
            },
            do_not_replay: true,
        };
        out.validate()?;
        Ok(out)
    }
    /// No broad occupancy exception: a still-live private review from this
    /// request must be the SAME one captured by the real Reserve Allow/Submit.
    pub(crate) fn scope_compatible(&self, scope: &NativeScope) -> bool {
        if self.pending() {
            return false;
        }
        self.lock().is_ok_and(|r| {
            r.ready.as_ref().is_none_or(|ready| {
                if r.spent || ready.identity.strong_count() == 0 {
                    return true;
                }
                ready.identity.ptr_eq(&scope.review)
                    && ready.view.id == scope.review_id
                    && ready.view.revision == scope.review_revision
                    && self.input.origin.project_id == scope.project_id
                    && self.scope.saved.runtime_id == scope.runtime_id
                    && Arc::ptr_eq(&self.scope.read, &scope.read)
                    && ready.end == scope.review_end
            })
        })
    }
    pub(crate) fn ready_current(&self, identity: &Arc<()>, now: Instant) -> bool {
        !self.pending()
            && self.scope.read.stop(now).is_ok_and(|v| v.is_none())
            && self.lock().is_ok_and(|r| {
                !r.spent
                    && r.ready.as_ref().is_some_and(|v| {
                        v.identity.ptr_eq(&Arc::downgrade(identity)) && now < v.end
                    })
            })
    }
    pub(crate) fn consume_review(&self, identity: &Arc<()>) -> Result<(), Error> {
        if !self.ready_current(identity, Instant::now()) {
            return Err(Error::Conflict);
        }
        let mut r = self.lock()?;
        r.spent = true;
        self.bump(&mut r)
    }
}
pub(crate) struct Caller {
    entry: Arc<Entry>,
    returned: bool,
}
impl Caller {
    pub(crate) fn returned(mut self) -> Result<(), Error> {
        let mut r = self.entry.lock()?;
        if !r.caller
            || r.caller_returned
            || !r.native_returned
            || self.entry.failed.load(Ordering::Acquire)
        {
            return Err(Error::StateUnknown);
        }
        r.caller_returned = true;
        self.entry.bump(&mut r)?;
        drop(r);
        self.returned = true;
        Ok(())
    }
}
impl Drop for Caller {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown()
        }
    }
}

#[cfg(test)]
#[path = "service_version_reserve_review_requests_tests.rs"]
mod tests;
