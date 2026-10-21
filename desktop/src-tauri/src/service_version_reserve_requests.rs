//! One bounded memory-only Reserve inbox. Thirty-two immutable request rows,
//! ONE active grant/continuation; no Lane, Store, credential or runner here.
use crate::{
    service_protocol::{Error, Id, Settlement},
    service_version_reserve_protocol as p,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::{Duration, Instant},
};

// All metadata strings and old/current comparison scopes stay charged.
// Native SOURCE/Lane backing remains on its original owner. Only the explicit
// IPC term joins the SAME8 pool (including the initial4KiB before the1KiB gate).
pub(crate) const IPC_WORKER_BACKING: usize = crate::service_protocol::REQUEST_BYTES + 2 * p::STATUS_LIMIT;
pub(crate) const DOCUMENT_BACKING: usize = p::REQUEST_LIMIT * (4096 + std::mem::size_of::<Entry>())
    + 4 * 8192;

/// Read-only facet of the SAME original service Grant. The Grant's Drop
/// revokes this comparison; dropping an Arc facet cannot revoke or renew it.
/// No Doc/Host/IO callback is possible.
pub(crate) struct ReadPermission {
    end: Instant,
    revoked: Mutex<Option<Instant>>,
}
impl ReadPermission {
    pub(crate) fn new(end: Instant) -> Self {
        Self {
            end,
            revoked: Mutex::new(None),
        }
    }
    pub(crate) fn revoke(&self, at: Instant) {
        if let Ok(mut old) = self.revoked.lock() {
            if old.is_none_or(|v| at < v) {
                *old = Some(at);
            }
        }
    }
    pub(crate) fn end(&self) -> Instant { self.end }
    pub(crate) fn stop(&self, now: Instant) -> Result<Option<(p::Reason, Instant)>, Error> {
        let at = *self.revoked.lock().map_err(|_| Error::StateUnknown)?;
        Ok(match at {
            Some(at) if at <= self.end => Some((p::Reason::PermissionRevoked, at)),
            _ if now >= self.end => Some((p::Reason::Expired, self.end)),
            _ => None,
        })
    }
}
pub(crate) struct NativeScope {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) review_id: Id,
    pub(crate) review_revision: u32,
    pub(crate) review_end: Instant,
    pub(crate) read: Arc<ReadPermission>,
    pub(crate) document: Weak<()>,
    pub(crate) review: Weak<()>,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
}
impl NativeScope {
    fn valid(&self, now: Instant) -> bool {
        (1..=64).contains(&self.runtime_id.len())
            && self
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && (1..u32::MAX).contains(&self.review_revision)
            && self.review_end > now
            && self.read.stop(now).is_ok_and(|v| v.is_none())
            && self.review_end.saturating_duration_since(now) <= Duration::from_millis(p::REVIEW_MS)
            && self.document.strong_count() != 0
            && self.review.strong_count() != 0
    }
}
struct Lease {
    id: Id,
    scope: Arc<NativeScope>,
    revoked: AtomicBool,
    failed: Arc<AtomicBool>,
}
impl Lease {
    fn live(&self, now: Instant, admitted: bool) -> bool {
        !self.failed.load(Ordering::Acquire)
            && !self.revoked.load(Ordering::Acquire)
            && self.scope.read.stop(now).is_ok_and(|v| v.is_none())
            && (admitted || now < self.scope.review_end)
            && self.scope.document.strong_count() != 0
            && self.scope.review.strong_count() != 0
    }
}
struct Book {
    // Comparison reachability for the SAME original Service Grant, including
    // a point captured before any Reserve lease is installed. Never authority
    // to create a Grant; only Service's actual installation publishes it.
    current_read: Option<Weak<ReadPermission>>,
    read_epoch: u64,
    lease: Option<Arc<Lease>>,
    entries: Vec<Arc<Entry>>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: Arc<AtomicBool>,
}
struct Row {
    lease: Option<Arc<Lease>>,
    status: p::Status,
    claimed: bool,
    joined: bool,
    final_result: Option<Final>,
    stop: Option<(p::Reason, Instant)>,
}
pub(crate) struct Entry {
    input: p::Submit,
    row: Mutex<Row>,
    failed: AtomicBool,
}
pub(crate) enum Final {
    Reserved(p::Reservation),
    Refused,
}
fn change(row: &mut Row) -> Result<(), Error> {
    row.status.revision = row
        .status
        .revision
        .checked_add(1)
        .filter(|v| *v < u32::MAX)
        .ok_or(Error::StateUnknown)?;
    Ok(())
}
fn terminal(row: &Row) -> bool {
    row.joined && row.status.settlement == Settlement::Settled
}
fn finish_state(reason: Option<p::Reason>) -> p::State {
    match reason {
        Some(p::Reason::Expired) => p::State::Expired,
        Some(
            p::Reason::UserCancelled
            | p::Reason::PermissionRevoked
            | p::Reason::Shutdown
            | p::Reason::ContextChanged,
        ) => p::State::Cancelled,
        _ => p::State::Refused,
    }
}
impl Entry {
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        self.row.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    pub(crate) fn input(&self) -> &p::Submit {
        &self.input
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        self.expire(Instant::now());
        let result = self.lock()?.status.clone();
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn pending(&self) -> bool {
        self.lock().map_or(true, |r| !terminal(&r))
    }
    pub(crate) fn first_stop(&self) -> Result<Option<(p::Reason, Instant)>, Error> {
        Ok(self.lock()?.stop)
    }
    pub(crate) fn cancel(&self, reason: p::Reason, at: Instant) {
        let Ok(mut row) = self.lock() else {
            return;
        };
        if terminal(&row) || row.status.state == p::State::Unknown {
            return;
        }
        let scope = row.lease.as_ref().map(|v| v.scope.clone());
        let mut first = (reason, at);
        if let Some(scope) = &scope {
            match scope.read.stop(at) {
                Ok(Some(value)) if value.1 < first.1 => first = value,
                Err(_) => {
                    drop(row);
                    self.unknown();
                    return;
                }
                _ => {}
            }
            if row.status.operation_id.is_none()
                && scope.review_end <= at
                && scope.review_end < first.1
            {
                first = (p::Reason::Expired, scope.review_end);
            }
        }
        // Never renew an earlier observed STOP, including a delayed relay.
        if row.stop.is_none_or(|v| first.1 < v.1) {
            row.stop = Some(first);
        }
        row.status.reason = row.stop.map(|v| v.0);
        if row.claimed {
            row.status.state = p::State::Stopping;
        } else {
            row.status.state = finish_state(row.status.reason);
            row.status.settlement = Settlement::Settled;
            row.joined = true; // No continuation was ever registered/claimed.
            row.lease = None;
        }
        if change(&mut row).is_err() {
            self.failed.store(true, Ordering::Release);
        }
        drop(row);
        if let Some(scope) = scope {
            scope.changes.send_modify(|_| {});
        }
    }
    pub(crate) fn expire(&self, now: Instant) {
        let original = self.lock().ok().and_then(|r| {
            if terminal(&r) {
                None
            } else {
                r.lease
                    .as_ref()
                    .map(|l| (l.clone(), r.status.operation_id.is_some()))
            }
        });
        let Some((lease, admitted)) = original else {
            return;
        };
        if lease.failed.load(Ordering::Acquire) {
            self.unknown();
            return;
        }
        let mut first = match lease.scope.read.stop(now) {
            Ok(value) => value,
            Err(_) => {
                self.unknown();
                return;
            }
        };
        // A delayed read revoke cannot conceal an earlier pre-admission
        // Review expiry. An admitted native operation keeps its 60/70 clock.
        if !admitted
            && now >= lease.scope.review_end
            && first.is_none_or(|v| lease.scope.review_end < v.1)
        {
            first = Some((p::Reason::Expired, lease.scope.review_end));
        }
        if let Some((reason, at)) = first {
            self.cancel(reason, at);
        }
    }
    pub(crate) fn unknown(&self) {
        let mut row = match self.row.lock() {
            Ok(v) => v,
            Err(_) => {
                self.failed.store(true, Ordering::Release);
                return;
            }
        };
        if terminal(&row) || row.status.state == p::State::Unknown {
            return;
        }
        row.status.state = p::State::Unknown;
        row.status.settlement = Settlement::Unknown;
        row.status.reason = Some(p::Reason::CleanupUnknown);
        row.status.reservation = None;
        row.stop
            .get_or_insert((p::Reason::CleanupUnknown, Instant::now()));
        if change(&mut row).is_err() {
            self.failed.store(true, Ordering::Release);
        }
        let scope = row.lease.as_ref().map(|v| v.scope.clone());
        drop(row);
        if let Some(scope) = scope {
            scope.changes.send_modify(|_| {});
        }
    }
    /// Only the retained continuation slot invokes this AFTER awaiting its
    /// actual original handle. is_finished/child frames/GUI status do not call it.
    pub(crate) fn continuation_joined(&self, returned: bool) {
        if !returned {
            self.unknown();
            return;
        }
        self.expire(Instant::now());
        let Ok(mut row) = self.lock() else {
            return;
        };
        if row.joined || row.status.state == p::State::Unknown {
            return;
        }
        let Some(result) = row.final_result.take() else {
            drop(row);
            self.unknown();
            return;
        };
        row.joined = true;
        if row.stop.is_none() {
            if let Final::Reserved(value) = result {
                row.status.state = p::State::Reserved;
                row.status.reservation = Some(value);
                row.status.reason = None;
            } else {
                row.status.state = p::State::Refused;
                row.status.reason.get_or_insert(p::Reason::NativeRefused);
            }
        } else {
            row.status.state = finish_state(row.stop.map(|v| v.0));
            row.status.reason = row.stop.map(|v| v.0);
        }
        row.status.settlement = Settlement::Settled;
        row.lease = None; // Metadata only after this exact original joined.
        if change(&mut row).is_err() {
            self.failed.store(true, Ordering::Release);
        }
    }
    pub(crate) fn completed_operation(&self) -> Result<Option<Id>, Error> {
        let row = self.lock()?;
        Ok(
            if terminal(&row) && row.status.state == p::State::Reserved {
                row.status.operation_id.clone()
            } else {
                None
            },
        )
    }
}

/// Minted only by the original inbox claim. Arm binds the real Lane ID under
/// the SAME Doc lock before the private Review is taken or any GO is possible.
pub(crate) struct NativeLink {
    entry: Arc<Entry>,
    lease: Arc<Lease>,
    armed: AtomicBool,
}
impl NativeLink {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn scope(&self) -> &Arc<NativeScope> {
        &self.lease.scope
    }
    pub(crate) fn arm(&self, operation: &str) -> Result<bool, Error> {
        let operation = Id::parse(operation)?;
        self.entry.expire(Instant::now());
        let mut row = self.entry.lock()?;
        if self.armed.load(Ordering::Acquire)
            || !row.claimed
            || row.status.operation_id.is_some()
            || row
                .lease
                .as_ref()
                .is_none_or(|l| !Arc::ptr_eq(l, &self.lease))
        {
            return Err(Error::StateUnknown);
        }
        row.status.operation_id = Some(operation);
        self.armed.store(true, Ordering::Release);
        let current = row.stop.is_none() && self.lease.live(Instant::now(), false);
        if row.status.state != p::State::Unknown {
            row.status.state = if current {
                p::State::Reserving
            } else {
                p::State::Stopping
            };
        }
        change(&mut row)?;
        Ok(current)
    }
    pub(crate) fn current(&self, admitted: bool) -> Result<(), Error> {
        self.entry.expire(Instant::now());
        let row = self.entry.lock()?;
        if row.stop.is_some()
            || row.status.state == p::State::Unknown
            || row.joined
            || self.armed.load(Ordering::Acquire) != admitted
            || !self.lease.live(Instant::now(), admitted)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
pub(crate) struct Claim {
    link: Arc<NativeLink>,
    returned: bool,
}
impl Claim {
    pub(crate) fn link(&self) -> &Arc<NativeLink> {
        &self.link
    }
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.link.entry
    }
    /// Native child supplies only after actual reserve_finish and control
    /// return. Publication is still Pending until original continuation join.
    pub(crate) fn native_returned(&mut self, operation: &str, result: Final) -> Result<(), Error> {
        let mut row = self.entry().lock()?;
        if !self.link.armed.load(Ordering::Acquire)
            || row.status.operation_id.as_ref().map(Id::as_str) != Some(operation)
            || row.final_result.is_some()
            || row.joined
        {
            return Err(Error::StateUnknown);
        }
        if row.status.state == p::State::Unknown {
            return Err(Error::StateUnknown);
        }
        if let Final::Reserved(v) = &result {
            let mut check = row.status.clone();
            check.state = p::State::Reserved;
            check.settlement = Settlement::Settled;
            check.reason = None;
            check.reservation = Some(v.clone());
            check.validate()?;
        }
        row.final_result = Some(result);
        row.status.state = p::State::Finishing;
        change(&mut row)?;
        drop(row);
        self.returned = true;
        Ok(())
    }
    pub(crate) fn not_admitted(&mut self, error: Error) -> Result<(), Error> {
        if error == Error::StateUnknown {
            self.entry().unknown();
            return Err(error);
        }
        let mut row = self.entry().lock()?;
        if self.link.armed.load(Ordering::Acquire)
            || row.status.operation_id.is_some()
            || row.status.state == p::State::Unknown
            || row.final_result.is_some()
        {
            return Err(Error::StateUnknown);
        }
        row.status.reason.get_or_insert(match error {
            Error::Busy => p::Reason::Busy,
            Error::Unavailable | Error::UnsupportedPlatform => p::Reason::Unavailable,
            Error::Expired => p::Reason::Expired,
            _ => p::Reason::NativeRefused,
        });
        row.final_result = Some(Final::Refused);
        row.status.state = p::State::Finishing;
        change(&mut row)?;
        drop(row);
        self.returned = true;
        Ok(())
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.entry().unknown();
        }
    }
}

impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                current_read: None,
                read_epoch: 0,
                lease: None,
                entries: Vec::with_capacity(p::REQUEST_LIMIT),
                closed: false,
            }),
            failed: Arc::new(AtomicBool::new(false)),
        }
    }
    pub(crate) fn fence(&self) {
        self.failed.store(true, Ordering::Release);
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
    /// Discovery does not sample status, expire grants or stop a reservation.
    pub(crate) fn catalogue_requests(
        &self,
        instance: &Id,
        project: &Id,
    ) -> Result<Vec<crate::service_request_catalogue::AdditionalRequest>, Error> {
        use crate::service_request_catalogue::{AdditionalFamily, AdditionalRequest};
        let book = self.lock()?;
        if book.closed {
            return Err(Error::Unavailable);
        }
        if &self.instance != instance || book.entries.len() > p::REQUEST_LIMIT {
            return Err(Error::StateUnknown);
        }
        let mut rows = Vec::with_capacity(book.entries.len());
        for entry in &book.entries {
            if &entry.input.origin.service_instance != instance {
                return Err(Error::StateUnknown);
            }
            if &entry.input.origin.project_id == project {
                rows.push(AdditionalRequest {
                    family: AdditionalFamily::VersionReservation,
                    request_id: entry.input.origin.request_id.clone(),
                });
            }
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        Ok(rows)
    }
    /// READ-Allow captures this BEFORE its IO-capable Service lock. It is
    /// comparison DATA, not read consent or a native Reserve grant.
    pub(crate) fn read_permission_epoch(&self) -> Result<u64, Error> {
        let book = self.lock()?;
        if book.closed {
            return Err(Error::Unavailable);
        }
        if book.read_epoch == u64::MAX {
            return Err(Error::StateUnknown);
        }
        Ok(book.read_epoch)
    }
    /// Called while the original Service owns a newly constructed Grant, but
    /// BEFORE replacing its old Grant. On Err that uninstalled Grant drops;
    /// neither the old Grant nor this weak comparison slot is replaced.
    pub(crate) fn publish_read_permission(
        &self,
        read: &Arc<ReadPermission>,
        epoch: u64,
    ) -> Result<(), Error> {
        let mut book = self.lock()?;
        if book.closed {
            return Err(Error::Unavailable);
        }
        if epoch == u64::MAX || book.read_epoch == u64::MAX {
            return Err(Error::StateUnknown);
        }
        if book.read_epoch != epoch {
            return Err(Error::Conflict);
        }
        book.current_read = Some(Arc::downgrade(read));
        Ok(())
    }
    pub(crate) fn allow(&self, scope: Arc<NativeScope>, grant: Id) -> Result<p::Access, Error> {
        if !scope.valid(Instant::now()) {
            return Err(Error::Conflict);
        }
        let mut book = self.lock()?;
        if book.closed {
            return Err(Error::Unavailable);
        }
        if book.entries.len() >= p::REQUEST_LIMIT || book.entries.iter().any(|e| e.pending()) {
            return Err(Error::Busy);
        }
        if let Some(old) = &book.lease {
            old.revoked.store(true, Ordering::Release);
        }
        book.lease = Some(Arc::new(Lease {
            id: grant,
            scope,
            revoked: AtomicBool::new(false),
            failed: self.failed.clone(),
        }));
        self.access_locked(&book)
    }
    fn access_locked(&self, book: &Book) -> Result<p::Access, Error> {
        let Some(lease) = &book.lease else {
            return Ok(p::Access::empty());
        };
        let consumed = book.entries.iter().find(|e| e.input.grant_id == lease.id);
        let now = Instant::now();
        let remaining = lease
            .scope
            .review_end
            .min(lease.scope.read.end)
            .saturating_duration_since(now)
            .as_millis()
            .min(u128::from(p::REVIEW_MS)) as u64;
        let enabled = !book.closed && consumed.is_none() && lease.live(now, false) && remaining > 0;
        let value = p::Access {
            service_instance: Some(self.instance.clone()),
            project_id: Some(lease.scope.project_id.clone()),
            grant_id: Some(lease.id.clone()),
            review_id: Some(lease.scope.review_id.clone()),
            review_revision: Some(lease.scope.review_revision),
            enabled,
            remaining_ms: if enabled { remaining } else { 0 },
            consumed: consumed.is_some(),
            request_id: consumed.map(|e| e.input.origin.request_id.clone()),
            completed_operation_id: None,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn access(&self) -> Result<p::Access, Error> {
        let book = self.lock()?;
        self.access_locked(&book)
    }
    pub(crate) fn blocks_review(&self) -> Result<bool, Error> {
        let book = self.lock()?;
        Ok(book.entries.iter().any(|e| e.pending())
            || book.lease.as_ref().is_some_and(|l| {
                l.live(Instant::now(), false)
                    && !book.entries.iter().any(|e| e.input.grant_id == l.id)
            }))
    }
    pub(crate) fn revoke(&self, reason: p::Reason, at: Instant) -> Result<p::Access, Error> {
        let book = self.lock()?;
        if let Some(l) = &book.lease {
            l.revoked.store(true, Ordering::Release);
        }
        for entry in &book.entries {
            entry.cancel(reason, at);
        }
        self.access_locked(&book)
    }
    /// Original Service revoke/stop enters here BEFORE its IO-capable state
    /// mutex. Only the facet of the captured original Grant is affected; no
    /// Service callback, grant renewal or other-family operation occurs.
    pub(crate) fn read_revoked(&self, at: Instant) {
        if let Ok(mut book) = self.lock() {
            match book.read_epoch.checked_add(1).filter(|v| *v < u64::MAX) {
                Some(epoch) => book.read_epoch = epoch,
                None => {
                    book.read_epoch = u64::MAX;
                    self.failed.store(true, Ordering::Release);
                }
            }
            // This original can already be held by ReservePoint even though
            // no Inbox lease exists yet. Revoke it before Service IO waits.
            if let Some(read) = book.current_read.as_ref().and_then(Weak::upgrade) {
                read.revoke(at);
            }
            if let Some(lease) = &book.lease {
                lease.scope.read.revoke(at);
            }
            for entry in &book.entries {
                entry.cancel(p::Reason::PermissionRevoked, at);
            }
        }
    }
    pub(crate) fn close(&self, at: Instant) {
        if let Ok(mut book) = self.lock() {
            book.closed = true;
            if let Some(l) = &book.lease {
                l.revoked.store(true, Ordering::Release);
            }
            for entry in &book.entries {
                entry.cancel(p::Reason::Shutdown, at);
            }
        }
    }
    pub(crate) fn submit(&self, input: p::Submit) -> Result<p::Status, Error> {
        let mut book = self.lock()?;
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        // Exact retries observe even a consumed/closed/unknown original. No
        // second claim, grant, native ID or action is allocated.
        if let Some(old) = book
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
        if book.closed {
            return Err(Error::Unavailable);
        }
        if book.entries.len() >= p::REQUEST_LIMIT || book.entries.iter().any(|e| e.pending()) {
            return Err(Error::Busy);
        }
        let lease = book.lease.as_ref().ok_or(Error::AccessDenied)?.clone();
        if input.origin.project_id != lease.scope.project_id
            || input.review_id != lease.scope.review_id
            || input.grant_id != lease.id
            || !lease.live(Instant::now(), false)
            || book.entries.iter().any(|e| e.input.grant_id == lease.id)
        {
            return Err(Error::AccessDenied);
        }
        let status = p::Status {
            origin: input.origin.clone(),
            grant_id: input.grant_id.clone(),
            review_id: input.review_id.clone(),
            revision: 1,
            state: p::State::Queued,
            operation_id: None,
            settlement: Settlement::Pending,
            reason: None,
            reservation: None,
            do_not_replay: true,
        };
        let entry = Arc::new(Entry {
            input,
            failed: AtomicBool::new(false),
            row: Mutex::new(Row {
                lease: Some(lease.clone()),
                status: status.clone(),
                claimed: false,
                joined: false,
                final_result: None,
                stop: None,
            }),
        });
        book.entries.push(entry);
        lease.scope.changes.send_modify(|_| {});
        Ok(status)
    }
    pub(crate) fn query(&self, q: &p::Query, cancel: bool) -> Result<p::Status, Error> {
        let book = self.lock()?;
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        let entry = book
            .entries
            .iter()
            .find(|e| e.input.origin == *q)
            .ok_or(Error::Conflict)?;
        if cancel {
            entry.cancel(p::Reason::UserCancelled, Instant::now());
        }
        entry.status()
    }
    pub(crate) fn claim(&self) -> Result<Option<Claim>, Error> {
        let book = self.lock()?;
        if book.closed {
            return Ok(None);
        }
        for entry in &book.entries {
            entry.expire(Instant::now());
            let mut row = entry.lock()?;
            if row.claimed || row.stop.is_some() || row.status.state != p::State::Queued {
                continue;
            }
            let lease = row.lease.clone().ok_or(Error::StateUnknown)?;
            row.claimed = true;
            return Ok(Some(Claim {
                link: Arc::new(NativeLink {
                    entry: entry.clone(),
                    lease,
                    armed: AtomicBool::new(false),
                }),
                returned: false,
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
#[path = "service_version_reserve_requests_tests.rs"]
pub(crate) mod tests;
