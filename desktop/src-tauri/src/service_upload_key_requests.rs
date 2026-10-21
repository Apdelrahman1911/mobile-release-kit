//! One finite upload-key inbox on the existing Service. Memory only; no
//! credential, native scope factory, runtime, clock renewal or Store IO.
use crate::{
    service_protocol::{Error, Id, Settlement},
    service_upload_key_protocol as p,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, MutexGuard, Weak,
};
use std::time::{Duration, Instant};

// Every heap-bearing field has a closed bound: query/grant/key IDs, two native
// preparation IDs, one active scope/lease, and eight existing IPC copies. No
// private payload or per-row AssetStatus is retained. Native ownership is
// charged by its unchanged actual owner, not multiplied by these tombstones.
const ID_BYTES: usize = 32;
const ARC_HEADER: usize = 2 * std::mem::size_of::<usize>();
// Input query+grant (4), status query+grant (4), latched native key ref (4),
// projected status key ref (4), native preparation IDs (2), scope project,
// lease consent and lease request (3). Published native/status references
// coexist; sharing their meaning does not share their String allocations.
const ROW_STRINGS: usize = (4 + 4 + 4 + 4 + 2 + 3) * ID_BYTES;
const IPC_CONCURRENCY: usize = 8; // SAME existing installed IPC worker ceiling.
pub(crate) const DOCUMENT_BACKING: usize = std::mem::size_of::<Inbox>() + std::mem::size_of::<Book>() + ID_BYTES
    + p::CONSENT_LIMIT * (std::mem::size_of::<Id>() + ID_BYTES)
    + p::REQUEST_LIMIT * (std::mem::size_of::<Arc<Entry>>() + std::mem::size_of::<Entry>()
        + std::mem::size_of::<NativeScope>() + std::mem::size_of::<Lease>() + std::mem::size_of::<ReadPermission>()
        + 5 * ARC_HEADER + 64 + ROW_STRINGS)
    // One not-yet-submitted scope/lease and the old/current native-link cells.
    + std::mem::size_of::<Lease>() + std::mem::size_of::<NativeScope>() + std::mem::size_of::<ReadPermission>()
    + 4 * ARC_HEADER + 3 * (std::mem::size_of::<NativeLink>() + ARC_HEADER) + 64 + 3 * ID_BYTES
    + IPC_CONCURRENCY * (crate::service_protocol::REQUEST_BYTES + p::RAW_LIMIT + 2 * p::VIEW_LIMIT);

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
        if let Ok(mut v) = self.revoked.lock() {
            *v = Some(v.map_or(at, |old| old.min(at)));
        }
    }
    pub(crate) fn end(&self) -> Instant {
        self.end
    }
    fn stop(&self, now: Instant) -> Result<Option<(p::Reason, Instant)>, Error> {
        let old = *self.revoked.lock().map_err(|_| Error::StateUnknown)?;
        Ok(match old {
            Some(at) if at <= self.end => Some((p::Reason::PermissionRevoked, at)),
            _ if now >= self.end => Some((p::Reason::Expired, self.end)),
            _ => None,
        })
    }
}
/// Constructed only from the two real Document/Service cuts. Weak identity is
/// a comparison reachability check, not a preview or permission factory.
pub(crate) struct NativeScope {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) kind: p::Kind,
    pub(crate) end: Instant,
    pub(crate) read: Arc<ReadPermission>,
    pub(crate) identity: Weak<()>,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
}
struct Lease {
    id: Id,
    scope: Arc<NativeScope>,
    stopped: Mutex<Option<(p::Reason, Instant)>>,
    request: Mutex<Option<Id>>,
}
impl Lease {
    fn stop_at(&self, reason: p::Reason, at: Instant) {
        if let Ok(mut v) = self.stopped.lock() {
            if v.is_none_or(|(_, old)| at < old) {
                *v = Some((reason, at));
            }
        }
        self.scope.changes.send_modify(|_| {});
    }
    fn stop(&self, now: Instant, admitted: bool) -> Result<Option<(p::Reason, Instant)>, Error> {
        let mut first = *self.stopped.lock().map_err(|_| Error::StateUnknown)?;
        if let Some(v) = self.scope.read.stop(now)? {
            if first.is_none_or(|old| v.1 < old.1) {
                first = Some(v);
            }
        }
        if !admitted && now >= self.scope.end && first.is_none_or(|old| self.scope.end < old.1) {
            first = Some((p::Reason::Expired, self.scope.end));
        }
        if self.scope.identity.strong_count() == 0 && first.is_none() {
            first = Some((p::Reason::ContextChanged, now));
        }
        Ok(first)
    }
}
struct Book {
    current_read: Option<Weak<ReadPermission>>,
    read_epoch: u64,
    consents: Vec<Id>,
    lease: Option<Arc<Lease>>,
    entries: Vec<Arc<Entry>>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: AtomicBool,
}
struct Row {
    lease: Option<Arc<Lease>>,
    status: p::Status,
    claimed: bool,
    attempted: bool,
    installed: bool,
    preparation: Option<(Id, Id)>,
    caller_returned: bool,
    continuation_returned: bool,
    native: Option<(p::State, p::Reason, Option<p::KeyReference>)>,
    stop: Option<(p::Reason, Instant)>,
}
pub(crate) struct Entry {
    input: p::Submit,
    scope: Arc<NativeScope>,
    row: Mutex<Row>,
    failed: AtomicBool,
}
pub(crate) struct NativeLink {
    entry: Arc<Entry>,
}
pub(crate) struct Claim {
    link: Arc<NativeLink>,
    returned: bool,
}

impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                current_read: None,
                read_epoch: 0,
                consents: Vec::new(),
                lease: None,
                entries: Vec::new(),
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
    pub(crate) fn read_epoch(&self) -> Result<u64, Error> {
        Ok(self.lock()?.read_epoch)
    }
    pub(crate) fn publish_read(&self, read: &Arc<ReadPermission>, epoch: u64) -> Result<(), Error> {
        let mut b = self.lock()?;
        if b.closed || b.read_epoch == u64::MAX || b.read_epoch != epoch {
            return Err(Error::Conflict);
        }
        b.current_read = Some(Arc::downgrade(read));
        Ok(())
    }
    pub(crate) fn read_revoked(&self, at: Instant) {
        if let Ok(mut b) = self.lock() {
            b.read_epoch = b.read_epoch.saturating_add(1);
            if let Some(read) = b.current_read.take().and_then(|v| v.upgrade()) {
                read.revoke(at);
            }
            if let Some(lease) = &b.lease {
                lease.stop_at(p::Reason::PermissionRevoked, at);
            }
            for entry in &b.entries {
                entry.cancel(p::Reason::PermissionRevoked, at);
            }
        }
    }
    pub(crate) fn close(&self, at: Instant) {
        self.read_revoked(at);
        if let Ok(mut b) = self.lock() {
            b.closed = true;
        }
    }
    pub(crate) fn fence(&self) {
        self.failed.store(true, Ordering::Release);
        if let Ok(b) = self.book.try_lock() {
            for e in &b.entries {
                e.unknown();
            }
        }
    }
    pub(crate) fn allow(&self, scope: Arc<NativeScope>, id: Id) -> Result<p::Access, Error> {
        let now = Instant::now();
        let mut b = self.lock()?;
        if b.closed
            || scope.runtime_id.is_empty()
            || scope.runtime_id.len() > 64
            || scope.identity.strong_count() == 0
            || scope.end <= now
            || scope.end.duration_since(now) > Duration::from_secs(p::ALLOW_SECONDS)
            || scope.end > scope.read.end()
            || scope.read.stop(now)?.is_some()
            || b.current_read
                .as_ref()
                .is_none_or(|v| v.as_ptr() != Arc::as_ptr(&scope.read))
            || b.entries.iter().any(|v| v.pending())
            || b.read_epoch == u64::MAX
        {
            return Err(Error::Conflict);
        }
        if let Some(lease) = &b.lease {
            if lease.stop(now, false)?.is_none() {
                return Err(Error::Conflict);
            }
        }
        if b.consents.contains(&id) {
            return Err(Error::Conflict);
        }
        if b.consents.len() >= p::CONSENT_LIMIT {
            return Err(Error::Busy);
        }
        b.consents.try_reserve_exact(1).map_err(|_| Error::Busy)?;
        b.consents.push(id.clone());
        b.lease = Some(Arc::new(Lease {
            id,
            scope,
            stopped: Mutex::new(None),
            request: Mutex::new(None),
        }));
        self.access_locked(&b, now)
    }
    fn access_locked(&self, b: &Book, now: Instant) -> Result<p::Access, Error> {
        let Some(lease) = &b.lease else {
            return Ok(p::Access::empty());
        };
        let request = lease
            .request
            .lock()
            .map_err(|_| Error::StateUnknown)?
            .clone();
        let enabled = !b.closed && request.is_none() && lease.stop(now, false)?.is_none();
        let access = p::Access {
            schema_version: 1,
            service_instance: Some(self.instance.clone()),
            project_id: Some(lease.scope.project_id.clone()),
            grant_id: Some(lease.id.clone()),
            kind: Some(lease.scope.kind),
            consumed: request.is_some(),
            request_id: request,
            enabled,
            remaining_ms: if enabled {
                u64::try_from(lease.scope.end.saturating_duration_since(now).as_millis())
                    .unwrap_or(0)
                    .min(p::ALLOW_SECONDS * 1000)
            } else {
                0
            },
        };
        // A sub-millisecond remainder is expired DATA, never zero-ms enabled.
        let access = if access.enabled && access.remaining_ms == 0 {
            p::Access {
                enabled: false,
                ..access
            }
        } else {
            access
        };
        access.validate()?;
        Ok(access)
    }
    pub(crate) fn access(&self, project: Option<&Id>) -> Result<p::Access, Error> {
        let b = self.lock()?;
        if project.is_some_and(|p| b.lease.as_ref().is_some_and(|l| &l.scope.project_id != p)) {
            return Ok(p::Access::empty());
        }
        self.access_locked(&b, Instant::now())
    }
    pub(crate) fn blocks_action(&self) -> Result<bool, Error> {
        let b = self.lock()?;
        Ok(
            b.entries.iter().any(|e| e.pending())
                || self.access_locked(&b, Instant::now())?.enabled,
        )
    }
    pub(crate) fn revoke(&self, consent: &Id, at: Instant) -> Result<p::Access, Error> {
        let b = self.lock()?;
        if let Some(lease) = b.lease.as_ref().filter(|l| &l.id == consent) {
            lease.stop_at(p::Reason::PermissionRevoked, at);
            for e in b.entries.iter().filter(|e| &e.input.grant_id == consent) {
                e.cancel(p::Reason::PermissionRevoked, at);
            }
        }
        // A stale address never withdraws a replacement grant.
        self.access_locked(&b, Instant::now())
    }
    pub(crate) fn submit(&self, input: p::Submit) -> Result<p::Status, Error> {
        let mut b = self.lock()?;
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(old) = b
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
        if b.closed || b.entries.iter().any(|e| e.pending()) {
            return Err(Error::Busy);
        }
        if b.entries.len() >= p::REQUEST_LIMIT {
            return Err(Error::Busy);
        }
        let lease = b.lease.clone().ok_or(Error::AccessDenied)?;
        if lease.id != input.grant_id
            || lease.scope.project_id != input.origin.project_id
            || lease.stop(Instant::now(), false)?.is_some()
        {
            return Err(Error::AccessDenied);
        }
        let mut request = lease.request.lock().map_err(|_| Error::StateUnknown)?;
        if request.is_some() {
            return Err(Error::Conflict);
        }
        b.entries.try_reserve_exact(1).map_err(|_| Error::Busy)?;
        let status = p::Status {
            schema_version: 1,
            origin: input.origin.clone(),
            grant_id: input.grant_id.clone(),
            kind: lease.scope.kind,
            state: p::State::Queued,
            settlement: Settlement::Pending,
            reason: p::Reason::None,
            asset_operation_id: None,
            key: None,
            do_not_replay: true,
        };
        let e = Arc::new(Entry {
            input,
            scope: lease.scope.clone(),
            failed: AtomicBool::new(false),
            row: Mutex::new(Row {
                lease: Some(lease.clone()),
                status: status.clone(),
                claimed: false,
                attempted: false,
                installed: false,
                preparation: None,
                caller_returned: false,
                continuation_returned: false,
                native: None,
                stop: None,
            }),
        });
        *request = Some(e.input.origin.request_id.clone());
        b.entries.push(e);
        lease.scope.changes.send_modify(|_| {});
        Ok(status)
    }
    pub(crate) fn query(&self, q: &p::Query, cancel: bool) -> Result<p::Status, Error> {
        let b = self.lock()?;
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        let e = b
            .entries
            .iter()
            .find(|e| e.input.origin == *q)
            .ok_or(Error::Conflict)?;
        if cancel {
            e.cancel(p::Reason::PermissionRevoked, Instant::now());
        }
        e.status()
    }
    pub(crate) fn retained_ids(&self, project: &Id) -> Result<Vec<Id>, Error> {
        let b = self.lock()?; // No status/expiry/native query during catalogue copying.
        if b.closed {
            return Err(Error::Unavailable);
        }
        Ok(b.entries
            .iter()
            .filter(|e| &e.input.origin.project_id == project)
            .map(|e| e.input.origin.request_id.clone())
            .collect())
    }
    pub(crate) fn claim(&self) -> Result<Option<Claim>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Ok(None);
        }
        for e in &b.entries {
            let mut r = e.lock()?;
            if !r.claimed && r.status.settlement == Settlement::Pending {
                r.claimed = true;
                drop(r);
                return Ok(Some(Claim {
                    link: Arc::new(NativeLink { entry: e.clone() }),
                    returned: false,
                }));
            }
        }
        Ok(None)
    }
}
impl Entry {
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    pub(crate) fn scope(&self) -> &Arc<NativeScope> {
        &self.scope
    }
    pub(crate) fn grant_id(&self) -> &Id {
        &self.input.grant_id
    }
    pub(crate) fn pending(&self) -> bool {
        self.failed.load(Ordering::Acquire)
            || self.lock().map_or(true, |r| {
                matches!(
                    r.status.settlement,
                    Settlement::Pending | Settlement::Unknown
                )
            })
    }
    pub(crate) fn unknown(&self) {
        self.failed.store(true, Ordering::Release);
        self.scope.changes.send_modify(|_| {});
    }
    pub(crate) fn cancel(&self, reason: p::Reason, at: Instant) {
        if let Ok(mut r) = self.lock() {
            if r.status.settlement != Settlement::Pending {
                return;
            }
            if r.stop.is_none_or(|old| at < old.1) {
                r.stop = Some((reason, at));
            }
            r.status.state = p::State::StopRequested;
            r.status.reason = r.stop.map_or(reason, |v| v.0);
            // No claim/caller/owner was ever allocated. Closing this queued
            // request is not a fabricated join or a generation no-GO receipt.
            if !r.claimed {
                r.status.state = p::State::Cancelled;
                r.status.settlement = Settlement::Settled;
                r.lease = None;
            }
        }
        self.scope.changes.send_modify(|_| {});
    }
    pub(crate) fn first_stop(&self) -> Result<Option<(p::Reason, Instant)>, Error> {
        let r = self.lock()?;
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        let mut stop = r.stop;
        if let Some(lease) = &r.lease {
            if let Some(v) = lease.stop(Instant::now(), r.status.asset_operation_id.is_some())? {
                if stop.is_none_or(|old| v.1 < old.1) {
                    stop = Some(v);
                }
            }
        }
        Ok(stop)
    }
    fn publish(r: &mut Row) {
        if !r.caller_returned
            || !r.continuation_returned
            || r.status.settlement == Settlement::Unknown
        {
            return;
        }
        let Some((mut state, mut reason, mut key)) = r.native.clone() else {
            return;
        };
        if let Some((stop, _)) = r.stop {
            if state.success() {
                state = p::State::Cancelled;
                reason = stop;
                key = None;
            }
        }
        r.status.state = state;
        r.status.reason = reason;
        r.status.key = key;
        r.status.settlement = Settlement::Settled;
        r.lease = None;
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        match self.first_stop() {
            Ok(Some((reason, at))) => self.cancel(reason, at),
            Ok(None) => {}
            Err(_) => self.unknown(),
        }
        let r = self.lock()?;
        let mut value = r.status.clone();
        if self.failed.load(Ordering::Acquire) {
            value.state = p::State::Unknown;
            value.reason = p::Reason::CleanupUnknown;
            value.settlement = Settlement::Unknown;
            value.key = None;
        }
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn continuation_joined(&self, normal: bool) {
        if !normal {
            self.unknown();
            return;
        }
        if let Ok(mut r) = self.lock() {
            r.continuation_returned = true;
            Self::publish(&mut r);
        }
        self.scope.changes.send_modify(|_| {});
    }
    // Only asks whether the original fact was already latched. A later
    // context/record withdrawal must not reinterpret a finished historical row.
    pub(crate) fn needs_native_retirement(&self, id: u32) -> Result<bool, Error> {
        let r = self.lock()?;
        if self.failed.load(Ordering::Acquire)
            || r.status.asset_operation_id != Some(id)
            || !r.installed
        {
            return Err(Error::StateUnknown);
        }
        Ok(r.native.is_none())
    }
    // Fixed native adapter only, after its private original-retirement proof.
    // Kept DATA-only so the installed transport binary never imports Asset.
    pub(crate) fn native_retired(
        &self,
        id: u32,
        state: p::State,
        reason: p::Reason,
        key: Option<p::KeyReference>,
    ) {
        if let Ok(mut r) = self.lock() {
            let mut candidate = r.status.clone();
            candidate.state = state;
            candidate.reason = reason;
            candidate.key = key.clone();
            candidate.settlement = Settlement::Settled;
            let value = (state, reason, key);
            if r.status.asset_operation_id != Some(id)
                || !r.installed
                || candidate.validate().is_err()
                || r.native.as_ref().is_some_and(|old| *old != value)
            {
                self.unknown();
                return;
            }
            r.native = Some(value);
            Self::publish(&mut r);
        }
        self.scope.changes.send_modify(|_| {});
    }
}
impl NativeLink {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        if self.entry.first_stop()?.is_some() {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    pub(crate) fn attempted(&self) -> Result<(), Error> {
        self.current()?;
        let mut r = self.entry.lock()?;
        if r.attempted {
            return Err(Error::Conflict);
        }
        r.attempted = true;
        Ok(())
    }
    pub(crate) fn preparation(&self, operation: &str, generation: &str) -> Result<(), Error> {
        let mut r = self.entry.lock()?;
        if !r.attempted || r.preparation.is_some() {
            return Err(Error::Conflict);
        }
        r.preparation = Some((Id::parse(operation)?, Id::parse(generation)?));
        Ok(())
    }
    pub(crate) fn installed(&self, id: u32) -> Result<(), Error> {
        let mut r = self.entry.lock()?;
        if r.status.asset_operation_id != Some(id) {
            self.entry.unknown();
            return Err(Error::StateUnknown);
        }
        r.installed = true;
        Ok(())
    }
    pub(crate) fn arm(&self, id: u32) -> Result<(), Error> {
        self.current()?;
        let mut r = self.entry.lock()?;
        if !r.attempted || r.status.asset_operation_id.is_some() || !(1..u32::MAX).contains(&id) {
            return Err(Error::Conflict);
        }
        r.status.asset_operation_id = Some(id);
        r.status.state = p::State::Running;
        Ok(())
    }
}
impl Claim {
    pub(crate) fn link(&self) -> &Arc<NativeLink> {
        &self.link
    }
    pub(crate) fn returned(mut self, result: Result<(), Error>) {
        if let Ok(mut r) = self.link.entry.lock() {
            r.caller_returned = true;
            if result.is_err() && !r.installed {
                if r.attempted {
                    self.link.entry.unknown();
                } else {
                    r.native = Some((p::State::Refused, p::Reason::Refused, None));
                }
            }
            if result.is_ok() && !r.installed {
                self.link.entry.unknown();
            }
            Entry::publish(&mut r);
        } else {
            self.link.entry.unknown();
        }
        self.returned = true;
        self.link.entry.scope.changes.send_modify(|_| {});
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.link.entry.unknown();
        }
    }
}

#[cfg(test)]
#[path = "service_upload_key_requests_tests.rs"]
mod tests;
