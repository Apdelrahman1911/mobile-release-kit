//! Child of the original Apple Inbox. No extra row pool, execution owner or IO.
use super::*;
use crate::service_apple_provisioning_prepare_protocol as wire;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handoff {
    Waiting,
    Installing,
    Gui,
    Start,
    Retired,
}
struct ControlState {
    first: Option<(p::Reason, Instant)>,
    unknown: bool,
    handoff: Handoff,
    revision: u32,
}
impl ControlState {
    fn changed(&mut self) {
        match self.revision.checked_add(1).filter(|v| *v < u32::MAX) {
            Some(v) => self.revision = v,
            None => self.unknown = true,
        }
    }
}
pub(crate) struct Scope {
    pub(crate) project: crate::agent_local_checks::SavedPoint,
    pub(crate) id: Id,
    pub(crate) mode: p::Mode,
    pub(crate) expires: Instant,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
    pub(crate) document: Weak<()>,
    pub(crate) witness: Weak<()>,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
    state: Mutex<ControlState>,
}
impl Scope {
    pub(crate) fn new(
        mut project: crate::agent_local_checks::SavedPoint,
        id: Id,
        mode: p::Mode,
        expires: Instant,
        read: Arc<crate::service_version_reserve_requests::ReadPermission>,
        document: Weak<()>,
        witness: Weak<()>,
        changes: tokio::sync::watch::Sender<u32>,
    ) -> Result<Arc<Self>, Error> {
        let now = Instant::now();
        if !project.fresh
            || !project.config.as_ref().is_some_and(|c| c.valid())
            || !(1..=64).contains(&project.runtime_id.len())
            || !project
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !project.root.is_absolute()
            || project.root.as_os_str().len() > 4096
            || project.inode == 0
            || project.revision == 0
            || expires <= now
            || expires > read.end()
            || expires.saturating_duration_since(now).as_millis() > p::INTENT_MS as u128
        {
            return Err(Error::Conflict);
        }
        // Same exact values, compact owned metadata only. No path access,
        // private bytes, permission renewal or reconstructed native source.
        project.runtime_id = project.runtime_id.into_boxed_str().into_string();
        project.root = project.root.into_boxed_path().into_path_buf();
        if let Some(c) = project.config.as_mut() {
            c.sha256 = std::mem::take(&mut c.sha256).into_boxed_str().into_string();
        }
        let v = Arc::new(Self {
            project,
            id,
            mode,
            expires,
            read,
            document,
            witness,
            changes,
            state: Mutex::new(ControlState {
                first: None,
                unknown: false,
                handoff: Handoff::Waiting,
                revision: 1,
            }),
        });
        v.current(Instant::now())?;
        Ok(v)
    }
    pub(crate) fn stop(&self, reason: p::Reason, at: Instant) {
        if let Ok(mut s) = self.state.lock() {
            if matches!(s.handoff, Handoff::Gui | Handoff::Start) {
                return;
            }
            if s.first.is_none_or(|(_, old)| at < old) {
                s.first = Some((reason, at));
                s.changed();
                self.changes.send_modify(|_| {});
            }
        }
    }
    pub(crate) fn unknown(&self) {
        if let Ok(mut s) = self.state.lock() {
            if !s.unknown {
                s.unknown = true;
                s.changed();
                self.changes.send_modify(|_| {});
            }
        }
    }
    pub(crate) fn current(&self, now: Instant) -> Result<(), Error> {
        if self
            .state
            .lock()
            .map_err(|_| Error::StateUnknown)
            .is_ok_and(|s| matches!(s.handoff, Handoff::Gui | Handoff::Start) && !s.unknown)
        {
            return Ok(());
        }
        if self.document.strong_count() == 0 || self.witness.strong_count() == 0 {
            self.stop(p::Reason::ContextChanged, now);
        }
        if now >= self.expires {
            self.stop(p::Reason::Expired, self.expires);
        }
        match self.read.stop(now) {
            Ok(Some((_, at))) => self.stop(p::Reason::PermissionRevoked, at),
            Err(_) => self.unknown(),
            _ => {}
        }
        let s = self.state.lock().map_err(|_| Error::StateUnknown)?;
        if s.unknown {
            return Err(Error::StateUnknown);
        }
        if s.first.is_some() || s.handoff == Handoff::Retired {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    pub(crate) fn first(&self) -> Result<Option<(p::Reason, Instant)>, Error> {
        let s = self.state.lock().map_err(|_| Error::StateUnknown)?;
        if s.unknown {
            Err(Error::StateUnknown)
        } else {
            Ok(s.first)
        }
    }
    pub(crate) fn released(&self) -> bool {
        self.state.lock().is_ok_and(|s| {
            !s.unknown && matches!(s.handoff, Handoff::Gui | Handoff::Start | Handoff::Retired)
        })
    }
    pub(crate) fn start_handed_off(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|s| !s.unknown && s.handoff == Handoff::Start)
    }
    fn claim_handoff(&self, gui: bool) -> Result<(), Error> {
        self.current(Instant::now())?;
        let mut s = self.state.lock().map_err(|_| Error::StateUnknown)?;
        if s.unknown || s.first.is_some() || s.handoff != Handoff::Waiting {
            return Err(Error::Conflict);
        }
        s.handoff = if gui {
            Handoff::Gui
        } else {
            Handoff::Installing
        };
        s.changed();
        self.changes.send_modify(|_| {});
        if s.unknown {
            return Err(Error::StateUnknown);
        }
        Ok(())
    }
    fn installed(&self) -> Result<(), Error> {
        let mut s = self.state.lock().map_err(|_| Error::StateUnknown)?;
        if s.unknown || s.first.is_some() || s.handoff != Handoff::Installing {
            return Err(Error::Conflict);
        }
        s.handoff = Handoff::Start;
        s.changed();
        self.changes.send_modify(|_| {});
        if s.unknown {
            return Err(Error::StateUnknown);
        }
        Ok(())
    }
    pub(crate) fn retired(&self) {
        if let Ok(mut s) = self.state.lock() {
            if !matches!(s.handoff, Handoff::Gui | Handoff::Start | Handoff::Retired) {
                s.handoff = Handoff::Retired;
                s.changed();
                self.changes.send_modify(|_| {});
            }
        }
    }
}
pub(super) struct Lease {
    pub(super) id: Id,
    pub(crate) scope: Arc<Scope>,
    entry: Option<Weak<Entry>>,
    withdrawn: bool,
}
struct Progress {
    revision: u32,
    control_revision: u32,
    called: bool,
    host_entered: bool,
    returned: bool,
    constructed: Option<p::Review>,
    refused: bool,
    history_claim: bool,
    history_acked: bool,
    unknown: Option<p::Reason>,
}
pub(crate) struct Entry {
    input: wire::Submit,
    pub(crate) scope: Arc<Scope>,
    end: Instant,
    row: Mutex<Progress>,
}
impl Entry {
    pub(crate) fn origin(&self) -> &p::Query {
        &self.input.origin
    }
    pub(crate) fn end(&self) -> Instant {
        self.end
    }
    fn lock(&self) -> Result<MutexGuard<'_, Progress>, Error> {
        self.row.lock().map_err(|_| {
            self.scope.unknown();
            Error::StateUnknown
        })
    }
    fn changed(&self, r: &mut Progress) -> Result<(), Error> {
        r.revision = r
            .revision
            .checked_add(1)
            .filter(|n| *n < u32::MAX)
            .ok_or(Error::StateUnknown)?;
        self.scope.changes.send_modify(|_| {});
        Ok(())
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        let now = Instant::now();
        if now >= self.end && !self.lock()?.returned {
            self.scope.stop(p::Reason::TimedOut, self.end);
        }
        self.scope.current(now)
    }
    pub(crate) fn begin(self: &Arc<Self>) -> Result<Call, Error> {
        let mut r = self.lock()?;
        if r.called || r.unknown.is_some() {
            return Err(Error::Conflict);
        }
        r.called = true;
        self.changed(&mut r)?;
        Ok(Call {
            entry: self.clone(),
            returned: false,
        })
    }
    pub(crate) fn host_entered(&self) -> Result<(), Error> {
        self.current()?;
        let mut r = self.lock()?;
        if !r.called || r.returned {
            return Err(Error::Conflict);
        }
        r.host_entered = true;
        self.changed(&mut r)
    }
    pub(crate) fn constructed(&self, review: p::Review) -> Result<(), Error> {
        self.current()?;
        let mut r = self.lock()?;
        if !review.valid()
            || review.mode != self.scope.mode
            || self.scope.project.config.as_ref().is_none_or(|c| {
                c.bytes != review.saved_config.bytes || c.sha256 != review.saved_config.sha256
            })
            || !r.called
            || r.returned
            || r.constructed.is_some()
            || r.unknown.is_some()
        {
            return Err(Error::Conflict);
        }
        r.constructed = Some(review);
        self.changed(&mut r)
    }
    pub(crate) fn completed(&self) -> bool {
        self.lock().is_ok_and(|r| {
            r.returned
                && r.history_acked
                && !r.history_claim
                && r.constructed.is_some()
                && !r.refused
                && r.unknown.is_none()
        }) && self.scope.first().is_ok()
    }
    pub(crate) fn current_ready(&self) -> bool {
        self.completed() && self.scope.current(Instant::now()).is_ok() && !self.scope.released()
    }
    pub(crate) fn claim_gui(&self) -> Result<(), Error> {
        if !self.current_ready() {
            return Err(Error::Conflict);
        }
        self.scope.claim_handoff(true)
    }
    pub(crate) fn claim_start(&self) -> Result<(), Error> {
        if !self.current_ready() {
            return Err(Error::Conflict);
        }
        self.scope.claim_handoff(false)
    }
    pub(crate) fn pending(&self) -> bool {
        self.lock().map_or(true, |r| {
            !r.returned || !r.history_acked || r.history_claim || r.unknown.is_some()
        }) || self.scope.first().is_err()
    }
    pub(crate) fn unknown(&self, reason: p::Reason) {
        self.scope.unknown();
        if let Ok(mut r) = self.lock() {
            if r.unknown.is_none() {
                r.unknown = Some(reason);
                let _ = self.changed(&mut r);
            }
        }
    }
    pub(crate) fn status(&self) -> Result<wire::Status, Error> {
        if !self.scope.released() {
            let _ = self.current();
        }
        let mut r = self.lock()?;
        let stop = self.scope.first();
        let control_revision = self
            .scope
            .state
            .lock()
            .map_err(|_| Error::StateUnknown)?
            .revision;
        if r.control_revision != control_revision {
            r.control_revision = control_revision;
            self.changed(&mut r)?;
        }
        if stop.is_err() && r.unknown.is_none() {
            r.unknown = Some(p::Reason::CleanupUnknown);
            self.changed(&mut r)?;
        }
        let ready = r.returned && r.history_acked && !r.history_claim && r.unknown.is_none();
        let reason = r
            .unknown
            .unwrap_or_else(|| stop.ok().flatten().map_or(p::Reason::None, |(v, _)| v));
        let handed_off = self
            .scope
            .state
            .lock()
            .is_ok_and(|s| matches!(s.handoff, Handoff::Gui | Handoff::Start));
        let phase = if r.unknown.is_some() {
            wire::Phase::Unknown
        } else if ready && r.refused {
            wire::Phase::Refused
        } else if ready {
            wire::Phase::Prepared
        } else if r.returned {
            wire::Phase::Finishing
        } else if r.called {
            wire::Phase::Preparing
        } else {
            wire::Phase::Queued
        };
        let status = wire::Status {
            origin: self.input.origin.clone(),
            grant_id: self.input.grant_id.clone(),
            scope_id: self.input.scope_id.clone(),
            mode: self.scope.mode,
            revision: r.revision,
            phase,
            settlement: if r.unknown.is_some() {
                Settlement::Unknown
            } else if ready {
                Settlement::Settled
            } else {
                Settlement::Pending
            },
            reason: if phase == wire::Phase::Refused && reason == p::Reason::None {
                p::Reason::NativeRefused
            } else {
                reason
            },
            prepared: if ready && !r.refused {
                r.constructed.clone()
            } else {
                None
            },
            usable: ready && !r.refused && !self.scope.released() && reason == p::Reason::None,
            handed_off: ready && !r.refused && handed_off,
        };
        status.validate()?;
        Ok(status)
    }
    pub(crate) fn claim_history(self: &Arc<Self>) -> Result<Option<History>, Error> {
        let mut r = self.lock()?;
        if !r.returned || r.history_acked || r.history_claim || r.unknown.is_some() {
            return Ok(None);
        }
        if r.constructed.is_none() && !r.refused {
            return Err(Error::StateUnknown);
        }
        r.history_claim = true;
        Ok(Some(History {
            entry: self.clone(),
            refused: r.refused,
            returned: false,
        }))
    }
}
pub(crate) struct Call {
    entry: Arc<Entry>,
    returned: bool,
}
impl Call {
    pub(crate) fn returned(mut self, ok: bool) -> Result<bool, Error> {
        let mut r = self.entry.lock()?;
        if r.returned || !r.called {
            return Err(Error::StateUnknown);
        }
        r.returned = true;
        if !ok || r.constructed.is_none() {
            if r.host_entered || r.constructed.is_some() {
                r.unknown = Some(p::Reason::CleanupUnknown);
                self.entry.scope.unknown();
            } else {
                r.refused = true;
                self.entry.scope.retired();
            }
        }
        let refused = r.refused && r.unknown.is_none();
        self.entry.changed(&mut r)?;
        self.returned = true;
        Ok(refused)
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::CleanupUnknown);
        }
    }
}
pub(crate) struct History {
    entry: Arc<Entry>,
    pub(crate) refused: bool,
    returned: bool,
}
impl History {
    pub(crate) fn returned(mut self, result: Result<(), Error>) -> Result<(), Error> {
        if result.is_err() {
            self.entry.unknown(p::Reason::HistoryUnavailable);
            self.returned = true;
            return result;
        }
        let mut r = self.entry.lock()?;
        if !r.history_claim || r.history_acked {
            return Err(Error::StateUnknown);
        }
        r.history_claim = false;
        r.history_acked = true;
        self.entry.changed(&mut r)?;
        self.returned = true;
        Ok(())
    }
}
impl Drop for History {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::HistoryUnavailable);
        }
    }
}

impl Inbox {
    pub(crate) fn allow_preparation(
        &self,
        scope: Arc<Scope>,
        nonce: Id,
    ) -> Result<wire::Access, Error> {
        scope.current(Instant::now())?;
        let mut b = self.lock()?;
        if b.closed
            || b.entries.len() >= p::REQUEST_LIMIT
            || b.entries.iter().any(Stored::pending)
            || b.lease.as_ref().is_some_and(Allowed::occupied)
        {
            return Err(Error::Busy);
        }
        b.lease = Some(Allowed::Prepare(Lease {
            id: nonce,
            scope,
            entry: None,
            withdrawn: false,
        }));
        self.preparation_access_locked(&b)
    }
    pub(crate) fn submit_preparation(
        &self,
        input: wire::Submit,
        submitted: Instant,
    ) -> Result<wire::Status, Error> {
        let mut b = self.lock()?;
        if b.closed || input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(old) = b
            .entries
            .iter()
            .find(|e| e.origin().request_id == input.origin.request_id)
        {
            return match old {
                Stored::Prepare(e) if e.input == input => e.status(),
                _ => Err(Error::Conflict),
            };
        }
        if b.entries.len() >= p::REQUEST_LIMIT || b.entries.iter().any(Stored::pending) {
            return Err(Error::Busy);
        }
        let Some(Allowed::Prepare(l)) = b.lease.as_mut() else {
            return Err(Error::AccessDenied);
        };
        if l.withdrawn
            || l.entry.is_some()
            || l.id != input.grant_id
            || l.scope.id != input.scope_id
            || l.scope.project.project_id != input.origin.project_id
        {
            return Err(Error::AccessDenied);
        }
        l.scope.current(Instant::now())?;
        let end = submitted
            .checked_add(Duration::from_secs(wire::STARTUP_SECONDS))
            .ok_or(Error::StateUnknown)?
            .min(l.scope.expires);
        if Instant::now() >= end {
            return Err(Error::Expired);
        }
        let e = Arc::new(Entry {
            input,
            scope: l.scope.clone(),
            end,
            row: Mutex::new(Progress {
                revision: 1,
                control_revision: 1,
                called: false,
                host_entered: false,
                returned: false,
                constructed: None,
                refused: false,
                history_claim: false,
                history_acked: false,
                unknown: None,
            }),
        });
        l.entry = Some(Arc::downgrade(&e));
        b.entries.push(Stored::Prepare(e.clone()));
        e.scope.changes.send_modify(|_| {});
        e.status()
    }
    pub(crate) fn preparation(&self, q: &p::Query) -> Result<Arc<Entry>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        b.entries
            .iter()
            .find_map(|e| match e {
                Stored::Prepare(e) if e.origin() == q => Some(e.clone()),
                _ => None,
            })
            .ok_or(Error::Conflict)
    }
    pub(crate) fn preparation_entries(&self) -> Result<Vec<Arc<Entry>>, Error> {
        Ok(self
            .lock()?
            .entries
            .iter()
            .filter_map(|e| match e {
                Stored::Prepare(e) => Some(e.clone()),
                _ => None,
            })
            .collect())
    }
    pub(crate) fn preparation_access(&self) -> Result<wire::Access, Error> {
        let b = self.lock()?;
        self.preparation_access_locked(&b)
    }
    fn preparation_access_locked(&self, b: &Book) -> Result<wire::Access, Error> {
        let Some(Allowed::Prepare(l)) = &b.lease else {
            return Ok(wire::Access::empty());
        };
        let entry = l.entry.as_ref().and_then(Weak::upgrade);
        let remaining_ms = if !b.closed
            && !l.withdrawn
            && entry.is_none()
            && l.scope.current(Instant::now()).is_ok()
        {
            l.scope
                .expires
                .saturating_duration_since(Instant::now())
                .as_millis() as u64
        } else {
            0
        };
        let out = wire::Access {
            service_instance: Some(self.instance.clone()),
            project_id: Some(l.scope.project.project_id.clone()),
            grant_id: Some(l.id.clone()),
            scope_id: Some(l.scope.id.clone()),
            mode: Some(l.scope.mode),
            enabled: remaining_ms > 0,
            remaining_ms,
            status: entry.map(|e| e.status()).transpose()?,
        };
        out.validate()?;
        Ok(out)
    }
    pub(crate) fn withdraw_preparation(&self, id: &Id, at: Instant) -> Result<wire::Access, Error> {
        let mut b = self.lock()?;
        if let Some(Allowed::Prepare(l)) = b.lease.as_mut().filter(|v| v.id() == id) {
            l.withdrawn = true;
            l.scope.stop(p::Reason::PermissionRevoked, at);
            if l.entry.is_none() {
                l.scope.retired();
            }
        }
        self.preparation_access_locked(&b)
    }
    pub(crate) fn can_handoff_preparation(&self, e: &Arc<Entry>) -> Result<(), Error> {
        let b = self.lock()?;
        self.check_preparation_handoff(&b, e, false)
    }
    fn check_preparation_handoff(
        &self,
        b: &Book,
        e: &Arc<Entry>,
        installing: bool,
    ) -> Result<(), Error> {
        if b.closed || b.entries.len() >= p::REQUEST_LIMIT || b.entries.iter().any(Stored::pending)
        {
            return Err(Error::Busy);
        }
        let Some(Allowed::Prepare(l)) = &b.lease else {
            return Err(Error::Conflict);
        };
        if l.withdrawn
            || !Arc::ptr_eq(&l.scope, &e.scope)
            || l.entry
                .as_ref()
                .and_then(Weak::upgrade)
                .is_none_or(|old| !Arc::ptr_eq(&old, e))
            || !e.current_ready()
        {
            return Err(Error::Conflict);
        }
        if !e.scope.state.lock().is_ok_and(|s| {
            s.handoff
                == if installing {
                    Handoff::Installing
                } else {
                    Handoff::Waiting
                }
        }) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn allow_after_preparation(
        &self,
        e: &Arc<Entry>,
        scope: Arc<NativeScope>,
        nonce: Id,
    ) -> Result<p::Access, Error> {
        if !scope.valid(Instant::now()) {
            return Err(Error::Conflict);
        }
        let mut b = self.lock()?;
        self.check_preparation_handoff(&b, e, true)?;
        e.scope.installed()?;
        b.lease = Some(Allowed::Start(Arc::new(super::Lease {
            id: nonce,
            scope,
            entry: Mutex::new(None),
            withdrawn: AtomicBool::new(false),
        })));
        self.access_locked(&b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> Id {
        Id::parse(&format!("{n:032x}")).unwrap()
    }
    fn point() -> crate::agent_local_checks::SavedPoint {
        crate::agent_local_checks::SavedPoint {
            project_id: id(1),
            runtime_id: "p1".into(),
            root: "/inert/apple-prepare-never-opened".into(),
            device: 1,
            inode: 2,
            revision: 1,
            fresh: true,
            config: Some(crate::agent_local_checks::Config {
                bytes: 100,
                sha256: "a".repeat(64),
            }),
        }
    }
    fn review() -> p::Review {
        p::Review {
            mode: p::Mode::Review,
            operation_id: id(10),
            owner_generation: id(11),
            status_revision: 3,
            saved_config: p::Content {
                bytes: 100,
                sha256: "a".repeat(64),
            },
            saved_version: p::Version {
                bytes: 40,
                sha256: "b".repeat(64),
                name: "1.2.3".into(),
                build: 42,
            },
        }
    }
    struct Fixture {
        inbox: Inbox,
        doc: Arc<()>,
        witness: Arc<()>,
        scope: Arc<Scope>,
    }
    impl Fixture {
        fn new() -> Self {
            let doc = Arc::new(());
            let witness = Arc::new(());
            let scope = Self::scope(&doc, &witness, id(4));
            Self {
                inbox: Inbox::new(id(2)),
                doc,
                witness,
                scope,
            }
        }
        fn for_mode(mode: p::Mode) -> Self {
            let mut fixture = Self::new();
            Arc::get_mut(&mut fixture.scope).unwrap().mode = mode;
            fixture
        }
        fn scope(doc: &Arc<()>, witness: &Arc<()>, scope_id: Id) -> Arc<Scope> {
            let now = Instant::now();
            Scope::new(
                point(),
                scope_id,
                p::Mode::Review,
                now + Duration::from_secs(290),
                Arc::new(
                    crate::service_version_reserve_requests::ReadPermission::new(
                        now + Duration::from_secs(3600),
                    ),
                ),
                Arc::downgrade(doc),
                Arc::downgrade(witness),
                tokio::sync::watch::channel(0).0,
            )
            .unwrap()
        }
        fn input(&self) -> wire::Submit {
            wire::Submit {
                origin: p::Query {
                    project_id: id(1),
                    service_instance: id(2),
                    request_id: id(5),
                },
                grant_id: id(3),
                scope_id: id(4),
            }
        }
        fn submit(&self) -> Arc<Entry> {
            self.inbox
                .allow_preparation(self.scope.clone(), id(3))
                .unwrap();
            self.inbox
                .submit_preparation(self.input(), Instant::now())
                .unwrap();
            self.inbox.preparation(&self.input().origin).unwrap()
        }
        fn start_scope(&self) -> Arc<NativeScope> {
            let mut selected = review();
            selected.mode = self.scope.mode;
            Arc::new(NativeScope {
                project_id: id(1),
                runtime_id: "p1".into(),
                review_id: id(10),
                review: selected,
                root: point().root,
                device: 1,
                inode: 2,
                observation_revision: 1,
                expires: self.scope.expires,
                read: Arc::new(
                    crate::service_version_reserve_requests::ReadPermission::new(
                        Instant::now() + Duration::from_secs(3600),
                    ),
                ),
                document: Arc::downgrade(&self.doc),
                witness: Arc::downgrade(&self.witness),
                control: Control::new(),
                retired: AtomicBool::new(false),
                changes: tokio::sync::watch::channel(0).0,
            })
        }
    }
    // These are actual metadata methods/guards, not Host/Ready/native joins.
    fn constructed(entry: &Arc<Entry>) -> Call {
        let call = entry.begin().unwrap();
        entry.host_entered().unwrap();
        let mut selected = review();
        selected.mode = entry.scope.mode;
        entry.constructed(selected).unwrap();
        call
    }
    fn finish(entry: &Arc<Entry>, call: Call) {
        assert!(!call.returned(true).unwrap());
        entry
            .claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
    }

    #[test]
    fn prepare_original_construction_caller_and_history_are_three_distinct_cuts() {
        let f = Fixture::new();
        let e = f.submit();
        let call = constructed(&e);
        assert!(!e.current_ready());
        assert!(e.claim_history().unwrap().is_none());
        assert!(e.begin().is_err());
        assert!(!e.status().unwrap().usable);
        assert!(!call.returned(true).unwrap());
        assert_eq!(e.status().unwrap().phase, wire::Phase::Finishing);
        let history = e.claim_history().unwrap().unwrap();
        assert!(e.pending());
        assert!(!e.current_ready());
        history.returned(Ok(())).unwrap();
        assert!(e.current_ready());
        assert!(!e.pending());
        assert_eq!(e.status().unwrap().prepared, Some(review()));
        assert!(e.claim_history().unwrap().is_none());
    }
    #[test]
    fn prepare_lost_original_or_history_is_unknown_and_never_replayable() {
        prepare_lost_original_or_history_is_unknown_and_never_replayable_for_mode(p::Mode::Review);
        prepare_lost_original_or_history_is_unknown_and_never_replayable_for_mode(p::Mode::KeyRecover);
    }
    fn prepare_lost_original_or_history_is_unknown_and_never_replayable_for_mode(mode: p::Mode) {
        for original in [true, false] {
            let f = Fixture::for_mode(mode);
            let e = f.submit();
            let call = constructed(&e);
            if original {
                drop(call);
            } else {
                call.returned(true).unwrap();
                drop(e.claim_history().unwrap().unwrap());
            }
            assert_eq!(e.status().unwrap().phase, wire::Phase::Unknown);
            assert!(e.pending());
            assert!(e.begin().is_err());
            assert!(e.claim_gui().is_err());
            f.inbox
                .withdraw_preparation(&id(3), Instant::now())
                .unwrap();
            assert!(f.inbox.allow(f.start_scope(), id(6)).is_err());
        }
    }
    #[test]
    fn prepare_only_genuine_no_host_refusal_can_finish_without_prepared() {
        for host_entered in [false, true] {
            let f = Fixture::new();
            let e = f.submit();
            let call = e.begin().unwrap();
            if host_entered {
                e.host_entered().unwrap();
            }
            f.scope.stop(p::Reason::UserCancelled, Instant::now());
            assert_eq!(call.returned(false).unwrap(), !host_entered);
            if host_entered {
                assert_eq!(e.status().unwrap().phase, wire::Phase::Unknown);
                assert!(e.claim_history().unwrap().is_none());
            } else {
                let history = e.claim_history().unwrap().unwrap();
                assert!(history.refused);
                history.returned(Ok(())).unwrap();
                let s = e.status().unwrap();
                assert_eq!(s.phase, wire::Phase::Refused);
                assert_eq!(s.reason, p::Reason::UserCancelled);
                assert!(!s.usable);
            }
        }
    }
    #[test]
    fn prepare_exact_gui_or_separate_start_handoff_rejects_late_old_cancel() {
        prepare_exact_gui_or_separate_start_handoff_rejects_late_old_cancel_for_mode(p::Mode::Review);
        prepare_exact_gui_or_separate_start_handoff_rejects_late_old_cancel_for_mode(p::Mode::KeyRecover);
    }
    fn prepare_exact_gui_or_separate_start_handoff_rejects_late_old_cancel_for_mode(mode: p::Mode) {
        for gui in [true, false] {
            let f = Fixture::for_mode(mode);
            let e = f.submit();
            finish(&e, constructed(&e));
            assert!(f.inbox.can_allow().is_err());
            let start = f.start_scope();
            let mut held_claim = None;
            if gui {
                e.claim_gui().unwrap();
                assert!(e.claim_start().is_err());
            } else {
                f.inbox.can_handoff_preparation(&e).unwrap();
                e.claim_start().unwrap();
                assert!(!e.scope.released());
                assert!(e.claim_gui().is_err());
                f.inbox
                    .allow_after_preparation(&e, start.clone(), id(6))
                    .unwrap();
                let input = p::Submit {
                    origin: p::Query {
                        project_id: id(1),
                        service_instance: id(2),
                        request_id: id(7),
                    },
                    grant_id: id(6),
                    review_id: id(10),
                };
                f.inbox.submit(input, Instant::now()).unwrap();
                held_claim = f.inbox.claim().unwrap();
                assert!(held_claim.is_some());
            }
            f.inbox
                .withdraw_preparation(&id(3), Instant::now())
                .unwrap();
            f.scope.read.revoke(Instant::now());
            f.scope.stop(p::Reason::UserCancelled, Instant::now());
            assert_eq!(e.scope.first().unwrap(), None);
            let s = e.status().unwrap();
            assert!(s.handed_off && !s.usable);
            assert!(e.begin().is_err());
            assert_eq!(start.control.first().unwrap(), None);
            drop(held_claim); // No native return is manufactured for this DATA claim.
        }
    }
    #[test]
    fn prepare_failed_start_install_never_reopens_original_gui_claim() {
        let f = Fixture::new();
        let e = f.submit();
        finish(&e, constructed(&e));
        e.claim_start().unwrap();
        let mut foreign = f.start_scope();
        Arc::get_mut(&mut foreign).unwrap().review_id = id(31);
        assert!(f.inbox.allow_after_preparation(&e, foreign, id(6)).is_err());
        assert!(e.claim_start().is_err() && e.claim_gui().is_err());
        assert!(!e.scope.released());
        e.scope.stop(p::Reason::NativeRefused, Instant::now());
        assert!(!e.current_ready());
        assert!(f.inbox.can_allow().is_err());
    }
    #[test]
    fn prepare_original_receipt_read_and_scope_expiries_are_not_renewed() {
        prepare_original_receipt_read_and_scope_expiries_are_not_renewed_for_mode(p::Mode::Review);
        prepare_original_receipt_read_and_scope_expiries_are_not_renewed_for_mode(p::Mode::KeyRecover);
    }
    fn prepare_original_receipt_read_and_scope_expiries_are_not_renewed_for_mode(mode: p::Mode) {
        let f = Fixture::for_mode(mode);
        f.inbox.allow_preparation(f.scope.clone(), id(3)).unwrap();
        assert!(f
            .inbox
            .submit_preparation(f.input(), Instant::now() - Duration::from_secs(31))
            .is_err());
        assert!(f.inbox.preparation_entries().unwrap().is_empty());
        let at = Instant::now() - Duration::from_secs(2);
        f.inbox.submit_preparation(f.input(), at).unwrap();
        let e = f.inbox.preparation(&f.input().origin).unwrap();
        let mut changes = f.scope.changes.subscribe();
        assert_eq!(e.end(), at + Duration::from_secs(wire::STARTUP_SECONDS));
        let first = Instant::now();
        e.scope.read.revoke(first);
        e.scope
            .stop(p::Reason::UserCancelled, first + Duration::from_secs(1));
        assert!(e.current().is_err());
        assert_eq!(
            e.scope.first().unwrap(),
            Some((p::Reason::PermissionRevoked, first))
        );
        let revision = e.status().unwrap().revision;
        let _ = changes.borrow_and_update();
        e.status().unwrap();
        assert_eq!(e.status().unwrap().revision, revision);
        assert!(e.current().is_err());
        f.scope.stop(p::Reason::UserCancelled, first);
        assert!(!changes.has_changed().unwrap());
        // Earlier first-F is a real transition; polling the identical retained
        // stop is not and must not self-wake the original Document relay.
        let earlier = first - Duration::from_millis(1);
        f.scope.stop(p::Reason::TimedOut, earlier);
        assert_eq!(
            f.scope.first().unwrap(),
            Some((p::Reason::TimedOut, earlier))
        );
        assert!(changes.has_changed().unwrap());
        assert!(e.status().unwrap().revision > revision);
        f.scope.retired();
        let retired_revision = e.status().unwrap().revision;
        let _ = changes.borrow_and_update();
        f.scope.retired();
        assert_eq!(e.status().unwrap().revision, retired_revision);
        assert!(!changes.has_changed().unwrap());
        e.unknown(p::Reason::CleanupUnknown);
        let unknown = e.status().unwrap();
        assert_eq!(unknown.phase, wire::Phase::Unknown);
        let _ = changes.borrow_and_update();
        e.unknown(p::Reason::UserCancelled);
        f.scope.unknown();
        f.scope.retired();
        let repeated = e.status().unwrap();
        assert_eq!(repeated.revision, unknown.revision);
        assert_eq!(repeated.reason, p::Reason::CleanupUnknown);
        assert!(!changes.has_changed().unwrap());
        assert_eq!(e.end(), at + Duration::from_secs(wire::STARTUP_SECONDS));
        drop(f.doc);
        assert!(e.current().is_err());
    }
    #[test]
    fn prepare_scope_rejects_foreign_or_unbounded_metadata_before_retention() {
        let f = Fixture::new();
        for bad in 0..8 {
            let mut p = point();
            match bad {
                0 => p.fresh = false,
                1 => p.config = None,
                2 => p.config.as_mut().unwrap().sha256 = "z".repeat(64),
                3 => p.runtime_id = "p".repeat(65),
                4 => p.root = "relative".into(),
                5 => p.root = format!("/{}", "p".repeat(4096)).into(),
                6 => p.inode = 0,
                _ => p.revision = 0,
            }
            assert!(Scope::new(
                p,
                id(4),
                p::Mode::Review,
                f.scope.expires,
                f.scope.read.clone(),
                Arc::downgrade(&f.doc),
                Arc::downgrade(&f.witness),
                tokio::sync::watch::channel(0).0
            )
            .is_err());
        }
        let too_long = Instant::now() + Duration::from_secs(301);
        assert!(Scope::new(
            point(),
            id(4),
            p::Mode::Review,
            too_long,
            f.scope.read.clone(),
            Arc::downgrade(&f.doc),
            Arc::downgrade(&f.witness),
            tokio::sync::watch::channel(0).0
        )
        .is_err());
    }
    #[test]
    fn prepare_and_start_share_original_thirty_two_rows_and_id_domain() {
        let f = Fixture::new();
        let e = f.submit();
        assert!(f
            .inbox
            .submit(
                p::Submit {
                    origin: e.origin().clone(),
                    grant_id: id(3),
                    review_id: id(10)
                },
                Instant::now()
            )
            .is_err());
        let call = e.begin().unwrap();
        call.returned(false).unwrap();
        e.claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        for n in 1..p::REQUEST_LIMIT {
            let scope = Fixture::scope(&f.doc, &f.witness, id(100 + n as u32));
            let nonce = id(200 + n as u32);
            f.inbox
                .allow_preparation(scope.clone(), nonce.clone())
                .unwrap();
            let input = wire::Submit {
                origin: p::Query {
                    project_id: id(1),
                    service_instance: id(2),
                    request_id: id(300 + n as u32),
                },
                grant_id: nonce,
                scope_id: scope.id.clone(),
            };
            f.inbox
                .submit_preparation(input.clone(), Instant::now())
                .unwrap();
            let row = f.inbox.preparation(&input.origin).unwrap();
            row.begin().unwrap().returned(false).unwrap();
            row.claim_history()
                .unwrap()
                .unwrap()
                .returned(Ok(()))
                .unwrap();
        }
        assert_eq!(f.inbox.lock().unwrap().entries.len(), p::REQUEST_LIMIT);
        assert_eq!(
            f.inbox
                .preparation(e.origin())
                .unwrap()
                .status()
                .unwrap()
                .phase,
            wire::Phase::Refused
        );
        assert!(f.inbox.allow(f.start_scope(), id(500)).is_err());
        assert!(f
            .inbox
            .allow_preparation(Fixture::scope(&f.doc, &f.witness, id(501)), id(502))
            .is_err());
        assert_eq!(
            f.inbox
                .submit_preparation(f.input(), Instant::now())
                .unwrap()
                .origin,
            e.origin().clone()
        );
    }
    #[test]
    fn prepare_actual_row_metadata_and_two_snapshots_fit_existing_not_new_pool() {
        let f = Fixture::new();
        let e = f.submit();
        finish(&e, constructed(&e));
        let bytes = std::mem::size_of::<Entry>()
            + std::mem::size_of::<Scope>()
            + std::mem::size_of::<Lease>()
            + 2 * std::mem::size_of::<Stored>()
            + std::mem::size_of::<crate::service_version_reserve_requests::ReadPermission>()
            + 4096
            + 64
            + 64
            + 16 * 32
            + 3 * 64
            + 256
            + 2 * p::STATUS_LIMIT;
        println!(
            "Apple Prepare actual retained row={} existing row={} IPC={} mixedWorkers={}",
            bytes,
            p::ROW_BACKING,
            p::IPC_WORKER_BACKING,
            crate::installed_cli_ipc::CLIENTS
        );
        assert!(bytes <= p::ROW_BACKING);
        assert!(serde_json::to_vec(&e.status().unwrap()).unwrap().len() < p::STATUS_LIMIT);
        assert_eq!(
            f.scope.project.root.capacity(),
            f.scope.project.root.as_os_str().len()
        );
        assert_eq!(
            f.scope.project.runtime_id.capacity(),
            f.scope.project.runtime_id.len()
        );
        assert_eq!(
            p::DOCUMENT_BACKING,
            p::REQUEST_LIMIT * p::ROW_BACKING + 128 * 1024
        );
        assert_eq!(crate::installed_cli_ipc::CLIENTS, 8);
    }
}
