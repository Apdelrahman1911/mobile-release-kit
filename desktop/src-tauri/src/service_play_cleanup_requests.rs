//! One metadata inbox on the existing service; no runner, credential or journal.
//! The only native linkage is minted at claim and armed by the real Supervisor.
use crate::{
    service_play_cleanup_protocol as p,
    service_protocol::{Error, Id, Settlement},
    service_version_reserve_requests::ReadPermission,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::{Duration, Instant},
};

pub(crate) const DOCUMENT_BACKING: usize = p::REQUEST_LIMIT * (4096 + std::mem::size_of::<Entry>())
    + 4 * 8192
    + 8 * (crate::service_protocol::REQUEST_BYTES + 2 * p::STATUS_LIMIT);

/// Issued only for the genuine retained prepared Consent, never a public view.
pub(crate) struct NativeScope {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) consent_id: Id,
    pub(crate) end: Instant,
    pub(crate) input_revision: u64,
    pub(crate) read: Arc<ReadPermission>,
    failed: Arc<AtomicBool>,
    pub(crate) document: Weak<()>,
    pub(crate) review: Weak<()>,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
    revoked: Mutex<Option<(p::Reason, Instant)>>,
}
impl NativeScope {
    fn new(
        project_id: Id,
        runtime_id: String,
        consent_id: Id,
        end: Instant,
        read: Arc<ReadPermission>,
        failed: Arc<AtomicBool>,
        document: Weak<()>,
        review: Weak<()>,
        changes: tokio::sync::watch::Sender<u32>,
        input_revision: u64,
    ) -> Self {
        Self {
            project_id,
            runtime_id,
            consent_id,
            end,
            read,
            failed,
            document,
            review,
            changes,
            input_revision,
            revoked: Mutex::new(None),
        }
    }
    pub(crate) fn revoke(&self, reason: p::Reason, at: Instant) {
        if let Ok(mut old) = self.revoked.lock() {
            if old.is_none_or(|v| at < v.1) {
                *old = Some((reason, at));
            }
        }
        self.changes.send_modify(|_| {});
    }
    fn stop(&self, now: Instant, armed: bool) -> Result<Option<(p::Reason, Instant)>, Error> {
        // No Host/Service lock or IO: original read facet + atomic history fence.
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        let mut first = *self.revoked.lock().map_err(|_| Error::StateUnknown)?;
        if let Some((reason, at)) = self.read.stop(now)? {
            let reason = match reason {
                crate::service_version_reserve_protocol::Reason::Expired => p::Reason::Expired,
                _ => p::Reason::PermissionRevoked,
            };
            if first.is_none_or(|v| at < v.1) {
                first = Some((reason, at));
            }
        }
        if !armed && now >= self.end && first.is_none_or(|v| self.end < v.1) {
            first = Some((p::Reason::Expired, self.end));
        }
        if (self.document.strong_count() == 0 || self.review.strong_count() == 0) && first.is_none()
        {
            first = Some((p::Reason::ContextChanged, now));
        }
        Ok(first)
    }
    fn valid(&self, now: Instant) -> bool {
        !self.runtime_id.is_empty()
            && self.runtime_id.len() <= 64
            && self
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            && self.input_revision != u64::MAX
            && self.end > now
            && self.end.duration_since(now) <= Duration::from_millis(p::REVIEW_MS)
            && self.stop(now, false).is_ok_and(|v| v.is_none())
    }
}
struct Row {
    status: p::Status,
    scope: Option<Arc<NativeScope>>,
    claimed: bool,
    armed: bool,
    joined: bool,
    first: Option<(p::Reason, Instant)>,
}
pub(crate) struct Entry {
    input: p::Submit,
    row: Mutex<Row>,
    failed: Arc<AtomicBool>,
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
fn ended(row: &Row) -> bool {
    row.joined && row.status.settlement == Settlement::Settled
}
fn terminal(reason: p::Reason) -> p::State {
    match reason {
        p::Reason::Expired => p::State::Expired,
        p::Reason::UserCancelled
        | p::Reason::PermissionRevoked
        | p::Reason::ContextChanged
        | p::Reason::Shutdown => p::State::Cancelled,
        _ => p::State::Refused,
    }
}
impl Entry {
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    pub(crate) fn input(&self) -> &p::Submit {
        &self.input
    }
    pub(crate) fn pending(&self) -> bool {
        self.lock().map_or(true, |r| !ended(&r))
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        self.expire(Instant::now());
        let result = self.lock()?.status.clone();
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn first_stop(&self) -> Result<Option<(p::Reason, Instant)>, Error> {
        self.expire(Instant::now());
        Ok(self.lock()?.first)
    }
    pub(crate) fn watchdog_stop(&self) -> Result<Option<(bool, Instant)>, Error> {
        self.expire(Instant::now());
        let row = self.lock()?;
        Ok(row
            .first
            .map(|(_, at)| (row.status.state == p::State::Unknown, at)))
    }
    pub(crate) fn cancel(&self, reason: p::Reason, at: Instant) {
        let Ok(mut row) = self.lock() else { return };
        if ended(&row) {
            return;
        }
        if row.first.is_some_and(|v| at >= v.1) {
            return; // A repeated observation neither renews F nor emits work.
        }
        row.first = Some((reason, at));
        let scope = row.scope.clone();
        if row.status.state != p::State::Unknown {
            row.status.reason = row.first.map(|v| v.0);
            if row.claimed {
                row.status.state = p::State::Stopping;
            } else {
                row.status.state = terminal(row.status.reason.unwrap_or(reason));
                row.joined = true;
                row.status.settlement = Settlement::Settled;
                row.scope = None;
            }
            if change(&mut row).is_err() {
                self.failed.store(true, Ordering::Release);
            }
        }
        drop(row);
        if let Some(scope) = scope {
            scope.changes.send_modify(|_| {});
        }
    }
    pub(crate) fn unknown(&self) {
        self.unknown_at(Instant::now());
    }
    fn unknown_at(&self, at: Instant) {
        let Ok(mut row) = self.lock() else { return };
        if ended(&row) {
            return;
        }
        // Native Unknown may arrive after the service saw a later STOP. Keep
        // the real earlier cut, never a newly observed timestamp in its place.
        if row.first.is_none_or(|(_, first)| at < first) {
            row.first = Some((p::Reason::CleanupUnknown, at));
        }
        if row.status.state == p::State::Unknown {
            return;
        }
        row.status.state = p::State::Unknown;
        row.status.settlement = Settlement::Unknown;
        row.status.reason = Some(p::Reason::CleanupUnknown);
        if change(&mut row).is_err() {
            self.failed.store(true, Ordering::Release);
        }
        if let Some(scope) = &row.scope {
            scope.changes.send_modify(|_| {});
        }
    }
    pub(crate) fn expire(&self, now: Instant) {
        let scope = self.lock().ok().and_then(|r| {
            if ended(&r) {
                None
            } else {
                r.scope.as_ref().map(|s| (s.clone(), r.armed))
            }
        });
        let Some((scope, armed)) = scope else { return };
        if self.failed.load(Ordering::Acquire) {
            self.unknown();
            return;
        }
        match scope.stop(now, armed) {
            Ok(Some((r, at))) => self.cancel(r, at),
            Ok(None) => {}
            Err(Error::StateUnknown) => self.unknown(),
            Err(_) => self.cancel(p::Reason::ContextChanged, now),
        }
    }
}
pub(crate) struct NativeLink {
    entry: Arc<Entry>,
    scope: Arc<NativeScope>,
}
impl NativeLink {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn scope(&self) -> &Arc<NativeScope> {
        &self.scope
    }
    /// Called at SAME owners-lock registration boundary, before spawn/GO.
    pub(crate) fn arm(&self, id: &str) -> Result<(), Error> {
        if !p::operation_id(id) {
            return Err(Error::InvalidRequest);
        }
        self.current(false)?;
        let mut row = self.entry.lock()?;
        if row.armed
            || row.status.operation_id.is_some()
            || !row.claimed
            || row.joined
            || row.first.is_some()
            || row.status.state == p::State::Unknown
            || self.entry.failed.load(Ordering::Acquire)
            || row
                .scope
                .as_ref()
                .is_none_or(|s| !Arc::ptr_eq(s, &self.scope))
            || self.scope.stop(Instant::now(), false)?.is_some()
        {
            return Err(Error::StateUnknown);
        }
        row.status.operation_id = Some(id.into());
        row.armed = true;
        row.status.state = p::State::Dispatching;
        change(&mut row)
    }
    pub(crate) fn current(&self, armed: bool) -> Result<(), Error> {
        self.entry.expire(Instant::now());
        let row = self.entry.lock()?;
        if self.entry.failed.load(Ordering::Acquire) || row.status.state == p::State::Unknown {
            return Err(Error::StateUnknown);
        }
        if row.armed != armed
            || !row.claimed
            || row.joined
            || row.first.is_some()
            || row
                .scope
                .as_ref()
                .is_none_or(|s| !Arc::ptr_eq(s, &self.scope))
            || self.scope.stop(Instant::now(), armed)?.is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Observation only, AFTER the original Supervisor GO claim and before
    /// returning its GO bytes. It grants no send/join permission. Late STOP or
    /// Unknown must not suppress a fact from this very same original owner.
    pub(crate) fn native_go(&self, id: &str) -> Result<(), Error> {
        let mut row = self.entry.lock()?;
        if !row.armed
            || !row.claimed
            || row.joined
            || row.status.operation_id.as_deref() != Some(id)
            || row
                .scope
                .as_ref()
                .is_none_or(|s| !Arc::ptr_eq(s, &self.scope))
        {
            return Err(Error::StateUnknown);
        }
        if row.status.effect == p::Effect::NotSent {
            row.status.effect = p::Effect::PotentiallyApplied;
            change(&mut row)?;
            self.scope.changes.send_modify(|_| {});
        }
        row.status.validate()
    }
    /// Called only by the actual native Unknown/ticket path, not by a public
    /// status parser. No receipt or later settlement is synthesized here.
    pub(crate) fn native_unknown(&self, id: &str, go: bool, at: Instant) -> Result<(), Error> {
        if go {
            self.native_go(id)?;
        } else {
            let row = self.entry.lock()?;
            if !row.armed
                || !row.claimed
                || row.joined
                || row.status.operation_id.as_deref() != Some(id)
                || row
                    .scope
                    .as_ref()
                    .is_none_or(|s| !Arc::ptr_eq(s, &self.scope))
            {
                return Err(Error::StateUnknown);
            }
        }
        self.entry.unknown_at(at);
        Ok(())
    }
    /// Only the actual native receipt path calls this, after its original
    /// C/A/W/runtime/IO/observer joins. No public status parser calls it.
    pub(crate) fn settled(
        &self,
        id: &str,
        effect: p::Effect,
        reason: Option<p::Reason>,
    ) -> Result<(), Error> {
        self.entry.expire(Instant::now());
        let mut row = self.entry.lock()?;
        if !row.armed
            || row.joined
            || row.status.operation_id.as_deref() != Some(id)
            || row.status.state == p::State::Unknown
            || self.entry.failed.load(Ordering::Acquire)
        {
            return Err(Error::StateUnknown);
        }
        // A real GO remains potentially applied even if a later refused reply
        // says not-sent. Only genuine acknowledgement may advance that fact.
        row.status.effect = match (row.status.effect, effect) {
            (p::Effect::AcknowledgedUnconfirmed, _) | (_, p::Effect::AcknowledgedUnconfirmed) => {
                p::Effect::AcknowledgedUnconfirmed
            }
            (p::Effect::PotentiallyApplied, _) | (_, p::Effect::PotentiallyApplied) => {
                p::Effect::PotentiallyApplied
            }
            _ => p::Effect::NotSent,
        };
        row.status.reason = row.first.map(|v| v.0).or(reason);
        row.status.state = match row.first {
            Some((why, _)) => terminal(why),
            None => p::State::Settled,
        };
        row.joined = true;
        row.status.settlement = Settlement::Settled;
        row.scope = None;
        change(&mut row)?;
        row.status.validate()
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
    pub(crate) fn handoff(mut self, id: &str) -> Result<(), Error> {
        {
            let row = self.link.entry.lock()?;
            if !row.armed || row.status.operation_id.as_deref() != Some(id) {
                return Err(Error::StateUnknown);
            }
        }
        self.returned = true;
        Ok(())
    }
    pub(crate) fn not_admitted(mut self, error: Error) -> Result<(), Error> {
        if error == Error::StateUnknown {
            self.link.entry.unknown();
            return Err(error);
        }
        {
            let mut row = self.link.entry.lock()?;
            if row.armed
                || row.status.operation_id.is_some()
                || row.status.state == p::State::Unknown
            {
                return Err(Error::StateUnknown);
            }
            row.first.get_or_insert((
                match error {
                    Error::Busy => p::Reason::Busy,
                    Error::Unavailable => p::Reason::Unavailable,
                    Error::Expired => p::Reason::Expired,
                    _ => p::Reason::NativeRefused,
                },
                Instant::now(),
            ));
            row.status.reason = row.first.map(|v| v.0);
            row.status.state = terminal(row.status.reason.unwrap());
            row.joined = true;
            row.status.settlement = Settlement::Settled;
            row.scope = None;
            change(&mut row)?;
        }
        self.returned = true;
        Ok(())
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.link.entry.unknown();
        }
    }
}
struct Book {
    scope: Option<Arc<NativeScope>>,
    entries: Vec<Arc<Entry>>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: Arc<AtomicBool>,
}
impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                scope: None,
                entries: Vec::with_capacity(p::REQUEST_LIMIT),
                closed: false,
            }),
            failed: Arc::new(AtomicBool::new(false)),
        }
    }
    fn lock(&self) -> Result<MutexGuard<'_, Book>, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        self.book.lock().map_err(|_| {
            self.fence();
            Error::StateUnknown
        })
    }
    pub(crate) fn fence(&self) {
        self.failed.store(true, Ordering::Release);
    }
    pub(crate) fn scope(
        &self,
        project_id: Id,
        runtime_id: String,
        consent_id: Id,
        end: Instant,
        read: Arc<ReadPermission>,
        document: Weak<()>,
        review: Weak<()>,
        changes: tokio::sync::watch::Sender<u32>,
        input_revision: u64,
    ) -> Arc<NativeScope> {
        Arc::new(NativeScope::new(
            project_id,
            runtime_id,
            consent_id,
            end,
            read,
            self.failed.clone(),
            document,
            review,
            changes,
            input_revision,
        ))
    }
    pub(crate) fn allow(&self, scope: Arc<NativeScope>) -> Result<p::Access, Error> {
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
        if book
            .entries
            .iter()
            .any(|e| e.input.consent_id == scope.consent_id)
        {
            return Err(Error::Conflict);
        }
        if let Some(old) = &book.scope {
            old.revoke(p::Reason::PermissionRevoked, Instant::now());
        }
        book.scope = Some(scope);
        self.access_locked(&book)?.ok_or(Error::StateUnknown)
    }
    fn access_locked(&self, book: &Book) -> Result<Option<p::Access>, Error> {
        let Some(scope) = &book.scope else {
            return Ok(None);
        };
        let now = Instant::now();
        let remaining = scope
            .end
            .saturating_duration_since(now)
            .as_millis()
            .min(u128::from(p::REVIEW_MS)) as u64;
        let enabled = remaining > 0
            && !book.closed
            && !book
                .entries
                .iter()
                .any(|e| e.input.consent_id == scope.consent_id)
            && scope.valid(now);
        let value = p::Access {
            service_instance: self.instance.clone(),
            project_id: scope.project_id.clone(),
            consent_id: scope.consent_id.clone(),
            enabled,
            remaining_ms: if enabled {
                scope
                    .end
                    .saturating_duration_since(now)
                    .as_millis()
                    .min(u128::from(p::REVIEW_MS)) as u64
            } else {
                0
            },
        };
        if !value.valid() {
            return Err(Error::StateUnknown);
        }
        Ok(Some(value))
    }
    pub(crate) fn scope_live(&self, original: &Arc<NativeScope>) -> Result<bool, Error> {
        let book = self.lock()?;
        Ok(!book.closed
            && book
                .scope
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, original))
            && original.stop(Instant::now(), false)?.is_none())
    }
    pub(crate) fn access(&self) -> Result<Option<p::Access>, Error> {
        let book = self.lock()?;
        self.access_locked(&book)
    }
    pub(crate) fn submit(&self, input: p::Submit) -> Result<p::Status, Error> {
        let mut book = self.lock()?;
        if book.closed {
            return Err(Error::Unavailable);
        }
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(old) = book
            .entries
            .iter()
            .find(|e| e.input.origin.request_id == input.origin.request_id)
        {
            if old.input != input {
                return Err(Error::Conflict);
            }
            return old.status();
        }
        if book.entries.len() >= p::REQUEST_LIMIT || book.entries.iter().any(|e| e.pending()) {
            return Err(Error::Busy);
        }
        let scope = book
            .scope
            .as_ref()
            .filter(|s| {
                s.project_id == input.origin.project_id
                    && s.consent_id == input.consent_id
                    && s.valid(Instant::now())
            })
            .ok_or(Error::AccessDenied)?
            .clone();
        if book
            .entries
            .iter()
            .any(|e| e.input.consent_id == input.consent_id)
        {
            return Err(Error::Conflict);
        }
        let status = p::Status {
            origin: input.origin.clone(),
            consent_id: input.consent_id.clone(),
            revision: 1,
            state: p::State::Queued,
            settlement: Settlement::Pending,
            operation_id: None,
            reason: None,
            effect: p::Effect::NotSent,
            do_not_replay: true,
        };
        status.validate()?;
        book.entries.push(Arc::new(Entry {
            input,
            row: Mutex::new(Row {
                status: status.clone(),
                scope: Some(scope.clone()),
                claimed: false,
                armed: false,
                joined: false,
                first: None,
            }),
            failed: self.failed.clone(),
        }));
        scope.changes.send_modify(|_| {});
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
            .ok_or(Error::Conflict)?
            .clone();
        drop(book);
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
            if row.claimed || row.joined || row.status.state == p::State::Unknown {
                continue;
            }
            let scope = row.scope.as_ref().ok_or(Error::StateUnknown)?.clone();
            row.claimed = true;
            return Ok(Some(Claim {
                link: Arc::new(NativeLink {
                    entry: entry.clone(),
                    scope,
                }),
                returned: false,
            }));
        }
        Ok(None)
    }
    pub(crate) fn close(&self, at: Instant) {
        // Do not infer native completion; only the real receipt settles armed work.
        if let Ok(mut book) = self.book.lock() {
            book.closed = true;
            if let Some(s) = &book.scope {
                s.revoke(p::Reason::Shutdown, at);
            }
            for e in &book.entries {
                e.cancel(p::Reason::Shutdown, at);
            }
        } else {
            self.fence();
        }
    }
}

#[cfg(test)]
#[path = "service_play_cleanup_requests_tests.rs"]
mod tests;
