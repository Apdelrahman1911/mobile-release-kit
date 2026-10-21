//! Closed two-phase metadata inside the ORIGINAL Store Inbox. A preparation
//! occupies one of the SAME32 rows until actual Saved retirement + all entered
//! callers + the original history return. No provider or native owner here.
use super::*;
use crate::service_store_prepare_protocol as flow;
use std::sync::OnceLock;

pub(crate) struct Scope {
    pub project_id: Id,
    pub runtime_id: String,
    pub selection_id: Id,
    pub selection: flow::Selection,
    pub root: std::path::PathBuf,
    pub device: u64,
    pub inode: u64,
    pub observation_revision: u64,
    pub expires: Instant,
    pub read: Arc<crate::service_version_reserve_requests::ReadPermission>,
    pub document: Weak<()>,
    pub witness: Weak<()>,
    pub control: Arc<Control>,
    pub changes: tokio::sync::watch::Sender<u32>,
    entry: OnceLock<Weak<PrepareEntry>>,
}
impl Scope {
    pub(crate) fn new(
        project_id: Id,
        runtime_id: String,
        selection_id: Id,
        selection: flow::Selection,
        root: std::path::PathBuf,
        device: u64,
        inode: u64,
        observation_revision: u64,
        expires: Instant,
        read: Arc<crate::service_version_reserve_requests::ReadPermission>,
        document: Weak<()>,
        witness: Weak<()>,
        changes: tokio::sync::watch::Sender<u32>,
    ) -> Arc<Self> {
        Arc::new(Self {
            project_id,
            runtime_id,
            selection_id,
            selection,
            root,
            device,
            inode,
            observation_revision,
            expires,
            read,
            document,
            witness,
            changes,
            control: Control::new(),
            entry: OnceLock::new(),
        })
    }
    pub fn matches(&self, p: &crate::agent_local_checks::SavedPoint) -> bool {
        self.project_id == p.project_id
            && self.runtime_id == p.runtime_id
            && self.root == p.root
            && self.device == p.device
            && self.inode == p.inode
            && self.observation_revision == p.revision
            && p.fresh
            && p.config.as_ref().is_some_and(|c| {
                c.bytes == self.selection.saved_config.bytes
                    && c.sha256 == self.selection.saved_config.sha256
            })
    }
    pub fn current(&self, admitted: bool, now: Instant) -> Result<(), Error> {
        if self.document.strong_count() == 0 || self.witness.strong_count() == 0 {
            self.control.stop(p::Reason::ContextChanged, now);
        }
        match self.read.stop(now) {
            Ok(Some((_, at))) => self.control.stop(p::Reason::PermissionRevoked, at),
            Err(_) => self.control.unknown(now),
            Ok(None) => (),
        }
        if !admitted && now >= self.expires {
            self.control.stop(p::Reason::Expired, self.expires);
        }
        if self.control.first()?.is_some() {
            Err(Error::AccessDenied)
        } else {
            Ok(())
        }
    }
    fn valid(&self) -> bool {
        self.selection.bounded_capacity()
            && self.runtime_id.capacity() <= 64
            && !self.runtime_id.is_empty()
            && self
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && self.root.is_absolute()
            && self.root.capacity() <= 4096
            && self.observation_revision > 0
            && self.inode > 0
            && self
                .expires
                .saturating_duration_since(Instant::now())
                .as_millis()
                <= p::INTENT_MS as u128
            && self.current(false, Instant::now()).is_ok()
    }
    pub fn original(&self) -> Option<Arc<PrepareEntry>> {
        self.entry.get().and_then(Weak::upgrade)
    }
    pub fn occupied(&self) -> bool {
        self.original().map_or_else(
            || self.current(false, Instant::now()).is_ok() || self.control.first().is_err(),
            |e| e.pending(),
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Native {
    pub operation: p::Operation,
    pub state: OperationState,
    pub reason: p::Reason,
    pub outcome: Option<p::Outcome>,
    pub result: Option<flow::Report>,
    pub retired: bool,
}
impl Native {
    fn valid(&self, s: &flow::Selection, r: &flow::Review, started: bool) -> bool {
        self.operation.operation_id == r.operation.operation_id
            && self.operation.owner_generation == r.operation.owner_generation
            && (r.operation.status_revision..u32::MAX).contains(&self.operation.status_revision)
            && self
                .result
                .as_ref()
                .is_none_or(|v| v.valid_for(s, r) && v.bounded_capacity())
            && if self.retired {
                match self.outcome {
                    Some(p::Outcome::Complete) => {
                        started
                            && self.state == OperationState::Succeeded
                            && self.reason == p::Reason::None
                            && self.result.is_some()
                    }
                    Some(p::Outcome::Cancelled) => {
                        self.state == OperationState::Cancelled
                            && !matches!(
                                self.reason,
                                p::Reason::None
                                    | p::Reason::CleanupUnknown
                                    | p::Reason::HistoryUnavailable
                            )
                            && self.result.is_none()
                    }
                    Some(p::Outcome::Failed | p::Outcome::Refused | p::Outcome::TimedOut) => {
                        self.state == OperationState::Failed
                            && !matches!(
                                self.reason,
                                p::Reason::None
                                    | p::Reason::CleanupUnknown
                                    | p::Reason::HistoryUnavailable
                            )
                            && self.result.is_none()
                    }
                    _ => false,
                }
            } else {
                self.outcome.is_none()
                    && self.result.is_none()
                    && matches!(
                        self.state,
                        OperationState::Prepared
                            | OperationState::Running
                            | OperationState::CancellationRequested
                    )
                    && !matches!(
                        self.reason,
                        p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable
                    )
            }
    }
    pub fn settlement(&self) -> Settlement {
        if self.retired {
            Settlement::Settled
        } else {
            Settlement::Pending
        }
    }
}
struct StartCall {
    input: flow::Submit,
    at: Instant,
    claimed: bool,
    returned: bool,
}
struct PreparationRow {
    revision: u32,
    claimed: bool,
    returned: bool,
    installed: bool,
    review: Option<flow::Review>,
    intent_end: Option<Instant>,
    start_grant: Option<Id>,
    start: Option<StartCall>,
    native: Option<Native>,
    history_started: bool,
    history_acked: u32,
    history_claim: Option<Native>,
    unknown: Option<p::Reason>,
    unentered: Option<p::Reason>,
}
pub(crate) struct PrepareEntry {
    pub input: flow::Submit,
    pub scope: Arc<Scope>,
    submitted: Instant,
    row: Mutex<PreparationRow>,
}
impl PrepareEntry {
    fn lock(&self) -> Result<MutexGuard<'_, PreparationRow>, Error> {
        self.row.lock().map_err(|_| {
            self.scope.control.unknown(Instant::now());
            Error::StateUnknown
        })
    }
    fn changed(&self, r: &mut PreparationRow) -> Result<(), Error> {
        r.revision = r
            .revision
            .checked_add(1)
            .filter(|n| *n < u32::MAX)
            .ok_or(Error::StateUnknown)?;
        self.scope.changes.send_modify(|_| {});
        Ok(())
    }
    pub fn origin(&self) -> &p::Query {
        &self.input.origin
    }
    pub fn current(&self, admitted: bool) -> Result<(), Error> {
        self.scope.current(admitted, Instant::now())
    }
    pub fn unknown(&self, reason: p::Reason) {
        self.scope.control.unknown(Instant::now());
        if let Ok(mut r) = self.lock() {
            r.unknown.get_or_insert(reason);
            let _ = self.changed(&mut r);
        }
    }
    pub fn cancel(&self, reason: p::Reason, at: Instant) {
        if self.pending() {
            self.scope.control.stop(reason, at);
            self.scope.changes.send_modify(|_| {});
        }
    }
    fn settled(r: &PreparationRow) -> bool {
        r.unknown.is_none()
            && r.returned
            && r.start.as_ref().is_none_or(|s| s.returned)
            && (r.unentered.is_some()
                || r.native.as_ref().is_some_and(|n| {
                    n.retired
                        && r.history_acked >= n.operation.status_revision
                        && r.history_claim.is_none()
                }))
    }
    pub fn pending(&self) -> bool {
        self.lock().map_or(true, |r| {
            !Self::settled(&r) || self.scope.control.first().is_err()
        })
    }
    /// Called only in the original Saved construction, before publication.
    pub fn attach(&self, review: flow::Review, intent_end: Instant) -> Result<(), Error> {
        self.current(false)?;
        let mut r = self.lock()?;
        if !r.claimed
            || r.returned
            || r.review.is_some()
            || r.unknown.is_some()
            || !review.valid()
            || intent_end > self.scope.expires
            || intent_end <= Instant::now()
        {
            return Err(Error::Conflict);
        }
        r.review = Some(review);
        r.intent_end = Some(intent_end);
        self.changed(&mut r)
    }
    /// Exact native construction fact, not inferred from a Result or event.
    pub fn installed(&self) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.review.is_none() || r.installed || r.returned {
            return Err(Error::Conflict);
        }
        r.installed = true;
        self.changed(&mut r)
    }
    fn prepare_returned(&self, ok: bool) {
        let Ok(mut r) = self.lock() else {
            return;
        };
        if !r.claimed || r.returned || r.unknown.is_some() {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        r.returned = true;
        if ok != r.installed || !ok && r.review.is_some() {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        if !ok {
            r.unentered = Some(
                self.scope
                    .control
                    .first()
                    .ok()
                    .flatten()
                    .map_or(p::Reason::NativeRefused, |(reason, _)| reason),
            );
        }
        if self.changed(&mut r).is_err() {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
        }
    }
    pub fn installed_review(&self) -> Result<flow::Review, Error> {
        let r = self.lock()?;
        if !r.installed || !r.returned || r.unknown.is_some() {
            return Err(Error::Busy);
        }
        r.review.clone().ok_or(Error::Conflict)
    }
    pub fn needs_original(&self) -> bool {
        self.lock().map_or(true, |r| {
            r.installed && r.unknown.is_none() && r.native.as_ref().is_none_or(|n| !n.retired)
        })
    }
    pub fn constructed(&self) -> bool {
        self.lock()
            .map_or(true, |r| r.installed || r.review.is_some())
    }
    pub fn allow_start(&self, review: &flow::Review, grant: Id) -> Result<(), Error> {
        self.current(false)?;
        let mut r = self.lock()?;
        if !r.installed
            || !r.returned
            || r.review.as_ref() != Some(review)
            || r.unknown.is_some()
            || r.start.is_some()
            || r.start_grant.is_some()
            || r.intent_end.is_none_or(|end| Instant::now() >= end)
            || r.native.as_ref().is_some_and(|n| n.retired)
        {
            return Err(Error::Conflict);
        }
        r.start_grant = Some(grant);
        self.changed(&mut r)
    }
    pub fn submit_start(&self, input: flow::Submit, at: Instant) -> Result<flow::Status, Error> {
        let mut r = self.lock()?;
        if let Some(old) = &r.start {
            let same = old.input == input;
            drop(r);
            return if same {
                self.status()
            } else {
                Err(Error::Conflict)
            };
        }
        self.current(false)?;
        if input.origin != self.input.origin
            || r.start_grant.as_ref() != Some(&input.grant_id)
            || r.review
                .as_ref()
                .is_none_or(|v| v.review_id != input.review_id)
            || !r.installed
            || !r.returned
            || r.unknown.is_some()
            || r.intent_end.is_none_or(|end| Instant::now() >= end)
            || r.native.as_ref().is_some_and(|n| n.retired)
        {
            return Err(Error::AccessDenied);
        }
        r.start = Some(StartCall {
            input,
            at,
            claimed: false,
            returned: false,
        });
        self.changed(&mut r)?;
        drop(r);
        self.status()
    }
    pub fn start_at(&self) -> Result<Instant, Error> {
        let r = self.lock()?;
        r.start
            .as_ref()
            .filter(|s| s.claimed && !s.returned && r.unknown.is_none())
            .map(|s| s.at)
            .ok_or(Error::Conflict)
    }
    pub fn native(&self, data: Native) {
        let Ok(mut r) = self.lock() else {
            return;
        };
        if r.unknown.is_some() {
            return;
        }
        if !r.installed
            || !r.review.as_ref().is_some_and(|v| {
                data.valid(
                    &self.scope.selection,
                    v,
                    r.start.as_ref().is_some_and(|s| s.claimed),
                )
            })
        {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        if let Some(old) = &r.native {
            if data.operation.status_revision < old.operation.status_revision {
                return;
            }
            if data.operation.status_revision == old.operation.status_revision {
                if &data != old {
                    drop(r);
                    self.unknown(p::Reason::CleanupUnknown);
                }
                return;
            }
            if old.retired {
                drop(r);
                self.unknown(p::Reason::CleanupUnknown);
                return;
            }
        }
        if data.retired {
            self.scope.control.detach_returned();
        }
        r.native = Some(data);
        if self.changed(&mut r).is_err() {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
        }
    }
    pub fn status(&self) -> Result<flow::Status, Error> {
        let (pending, started) = {
            let r = self.lock()?;
            (!Self::settled(&r), r.start.is_some())
        };
        if pending {
            let _ = self.scope.current(started, Instant::now());
        }
        let r = self.lock()?;
        let stop = self.scope.control.first();
        let unknown = r
            .unknown
            .or_else(|| stop.is_err().then_some(p::Reason::CleanupUnknown));
        let stopped = stop.ok().flatten().map(|(reason, _)| reason);
        let settled = Self::settled(&r);
        let (phase, settlement, reason, outcome, result) = if let Some(reason) = unknown {
            (
                flow::Phase::Unknown,
                Settlement::Unknown,
                reason,
                Some(p::Outcome::Unknown),
                None,
            )
        } else if settled {
            match &r.native {
                Some(n) => (
                    flow::Phase::Final,
                    Settlement::Settled,
                    n.reason,
                    n.outcome,
                    n.result.clone(),
                ),
                None => (
                    flow::Phase::Final,
                    Settlement::Settled,
                    r.unentered.ok_or(Error::StateUnknown)?,
                    Some(p::Outcome::Refused),
                    None,
                ),
            }
        } else {
            let phase = if r.native.as_ref().is_some_and(|n| n.retired) {
                flow::Phase::Finishing
            } else if stopped.is_some() {
                flow::Phase::Stopping
            } else if r.start.is_some() {
                if r.native
                    .as_ref()
                    .is_some_and(|n| n.state == OperationState::Running)
                {
                    flow::Phase::Running
                } else {
                    flow::Phase::Starting
                }
            } else if r.installed && r.returned {
                flow::Phase::Prepared
            } else if r.claimed {
                flow::Phase::Preparing
            } else {
                flow::Phase::Queued
            };
            (
                phase,
                Settlement::Pending,
                stopped.unwrap_or(p::Reason::None),
                None,
                None,
            )
        };
        let s = flow::Status {
            schema_version: 1,
            origin: self.input.origin.clone(),
            prepare_grant_id: self.input.grant_id.clone(),
            selection_id: self.input.review_id.clone(),
            revision: r.revision,
            selection: self.scope.selection.clone(),
            phase,
            settlement,
            reason,
            prepared: r.review.clone(),
            operation: r.native.as_ref().map(|n| n.operation.clone()),
            start_grant_id: r.start_grant.clone(),
            prepare_returned: r.returned,
            start_submitted: r.start.is_some(),
            outcome,
            result,
            do_not_replay: true,
        };
        s.validate().map_err(|_| Error::StateUnknown)?;
        Ok(s)
    }
    pub fn claim_history(self: &Arc<Self>) -> Result<Option<PrepareHistory>, Error> {
        let mut r = self.lock()?;
        if r.unknown.is_some() || r.history_claim.is_some() {
            return Ok(None);
        }
        let Some(data) = r
            .native
            .as_ref()
            .filter(|n| {
                n.operation.status_revision > r.history_acked
                    && (!n.retired || r.returned && r.start.as_ref().is_none_or(|s| s.returned))
            })
            .cloned()
        else {
            return Ok(None);
        };
        let first = !r.history_started;
        r.history_claim = Some(data.clone());
        Ok(Some(PrepareHistory {
            entry: self.clone(),
            data,
            first,
            returned: false,
        }))
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Call {
    Prepare,
    Start,
}
pub(crate) struct PrepareClaim {
    pub entry: Arc<PrepareEntry>,
    pub call: Call,
    returned: bool,
}
impl PrepareClaim {
    pub fn returned(mut self, ok: bool) {
        match self.call {
            Call::Prepare => self.entry.prepare_returned(ok),
            Call::Start => {
                if let Ok(mut r) = self.entry.lock() {
                    if let Some(s) = r.start.as_mut().filter(|s| s.claimed && !s.returned) {
                        s.returned = true;
                        if self.entry.changed(&mut r).is_err() {
                            drop(r);
                            self.entry.unknown(p::Reason::CleanupUnknown);
                        }
                    } else {
                        drop(r);
                        self.entry.unknown(p::Reason::CleanupUnknown);
                    }
                }
            }
        }
        self.returned = true;
    }
}
impl Drop for PrepareClaim {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::CleanupUnknown);
        }
    }
}
pub(crate) struct PrepareHistory {
    pub entry: Arc<PrepareEntry>,
    pub data: Native,
    pub first: bool,
    returned: bool,
}
impl PrepareHistory {
    pub fn returned(mut self, result: Result<(), Error>) -> Result<(), Error> {
        if let Err(e) = result {
            self.entry.unknown(p::Reason::HistoryUnavailable);
            self.returned = true;
            return Err(e);
        }
        let mut r = self.entry.lock()?;
        if r.history_claim.as_ref() != Some(&self.data) {
            drop(r);
            self.entry.unknown(p::Reason::HistoryUnavailable);
            self.returned = true;
            return Err(Error::StateUnknown);
        }
        r.history_started = true;
        r.history_acked = self.data.operation.status_revision;
        r.history_claim = None;
        self.entry.changed(&mut r)?;
        self.returned = true;
        Ok(())
    }
}
impl Drop for PrepareHistory {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::HistoryUnavailable);
        }
    }
}

pub(super) struct PreparationLease {
    id: Id,
    pub(super) scope: Arc<Scope>,
}
pub(super) enum StoredEntry {
    Original(Arc<Entry>),
    Preparation(Arc<PrepareEntry>),
    LocalHistory(Arc<super::history::Entry>),
}
impl StoredEntry {
    pub fn origin(&self) -> &p::Query {
        match self {
            Self::Original(e) => e.origin(),
            Self::Preparation(e) => e.origin(),
            Self::LocalHistory(e) => e.origin(),
        }
    }
    pub fn pending(&self) -> bool {
        match self {
            Self::Original(e) => e.pending(),
            Self::Preparation(e) => e.pending(),
            Self::LocalHistory(e) => e.pending(),
        }
    }
    pub fn cancel(&self, reason: p::Reason, at: Instant) {
        match self {
            Self::Original(e) => e.cancel(reason, at),
            Self::Preparation(e) => e.cancel(reason, at),
            Self::LocalHistory(e) => e.cancel(reason, at),
        }
    }
    pub fn unknown(&self, reason: p::Reason) {
        match self {
            Self::Original(e) => e.unknown(reason),
            Self::Preparation(e) => e.unknown(reason),
            Self::LocalHistory(e) => e.unknown(reason),
        }
    }
    pub fn history(&self)->Option<&Arc<super::history::Entry>>{if let Self::LocalHistory(e)=self{Some(e)}else{None}}
    pub fn original(&self) -> Option<&Arc<Entry>> {
        if let Self::Original(e) = self {
            Some(e)
        } else {
            None
        }
    }
}
impl Inbox {
    pub(crate) fn allow_preparation(
        &self,
        scope: Arc<Scope>,
        id: Id,
    ) -> Result<flow::Access, Error> {
        if !scope.valid() {
            return Err(Error::Conflict);
        }
        let mut b = self.lock()?;
        if b.closed
            || b.entries.len() >= p::REQUEST_LIMIT
            || b.entries.iter().any(StoredEntry::pending)
            || b.lease.as_ref().is_some_and(|l| {
                !l.scope.retired.load(Ordering::Acquire) || l.scope.control.first().is_err()
            })
            || b.preparation.as_ref().is_some_and(|l| l.scope.occupied())
            || b.history.as_ref().is_some_and(|l|l.occupied())
        {
            return Err(Error::Busy);
        }
        b.preparation = Some(Arc::new(PreparationLease { id, scope }));
        self.preparation_access_locked(&b)
    }
    pub(crate) fn submit_preparation(
        &self,
        input: flow::Submit,
        at: Instant,
    ) -> Result<flow::Status, Error> {
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
                StoredEntry::Preparation(e) if e.input == input => e.status(),
                _ => Err(Error::Conflict),
            };
        }
        let l = b.preparation.as_ref().ok_or(Error::AccessDenied)?.clone();
        if input.grant_id != l.id
            || input.review_id != l.scope.selection_id
            || input.origin.project_id != l.scope.project_id
        {
            return Err(Error::AccessDenied);
        }
        l.scope.current(false, Instant::now())?;
        if b.entries.len() >= p::REQUEST_LIMIT
            || b.entries.iter().any(StoredEntry::pending)
            || b.history.as_ref().is_some_and(|l|l.occupied())
            || l.scope.entry.get().is_some()
        {
            return Err(Error::Busy);
        }
        let entry = Arc::new(PrepareEntry {
            input,
            scope: l.scope.clone(),
            submitted: at,
            row: Mutex::new(PreparationRow {
                revision: 1,
                claimed: false,
                returned: false,
                installed: false,
                review: None,
                intent_end: None,
                start_grant: None,
                start: None,
                native: None,
                history_started: false,
                history_acked: 0,
                history_claim: None,
                unknown: None,
                unentered: None,
            }),
        });
        l.scope
            .entry
            .set(Arc::downgrade(&entry))
            .map_err(|_| Error::StateUnknown)?;
        b.entries.push(StoredEntry::Preparation(entry.clone()));
        l.scope.changes.send_modify(|_| {});
        entry.status()
    }
    pub(crate) fn preparation_entry(&self, q: &p::Query) -> Result<Arc<PrepareEntry>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        b.entries
            .iter()
            .find_map(|e| match e {
                StoredEntry::Preparation(e) if e.origin() == q => Some(e.clone()),
                _ => None,
            })
            .ok_or(Error::Conflict)
    }
    pub(crate) fn find_preparation(
        &self,
        q: &p::Query,
    ) -> Result<Option<Arc<PrepareEntry>>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        Ok(b.entries.iter().find_map(|e| match e {
            StoredEntry::Preparation(e) if e.origin() == q => Some(e.clone()),
            _ => None,
        }))
    }
    pub(crate) fn preparation_entries(&self) -> Result<Vec<Arc<PrepareEntry>>, Error> {
        Ok(self
            .lock()?
            .entries
            .iter()
            .filter_map(|e| {
                if let StoredEntry::Preparation(e) = e {
                    Some(e.clone())
                } else {
                    None
                }
            })
            .collect())
    }
    pub(crate) fn claim_preparation(&self) -> Result<Option<PrepareClaim>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Ok(None);
        }
        for item in &b.entries {
            let StoredEntry::Preparation(e) = item else {
                continue;
            };
            let mut r = e.lock()?;
            if r.unknown.is_some() || Self::preparation_done(&r) {
                continue;
            }
            let call = if !r.claimed {
                r.claimed = true;
                Some(Call::Prepare)
            } else if let Some(s) = r.start.as_mut().filter(|s| !s.claimed) {
                s.claimed = true;
                Some(Call::Start)
            } else {
                None
            };
            if let Some(call) = call {
                e.changed(&mut r)?;
                return Ok(Some(PrepareClaim {
                    entry: e.clone(),
                    call,
                    returned: false,
                }));
            }
        }
        Ok(None)
    }
    fn preparation_done(r: &PreparationRow) -> bool {
        PrepareEntry::settled(r)
    }
    pub(crate) fn preparation_access(&self) -> Result<flow::Access, Error> {
        let b = self.lock()?;
        self.preparation_access_locked(&b)
    }
    fn preparation_access_locked(&self, b: &Book) -> Result<flow::Access, Error> {
        let Some(l) = &b.preparation else {
            return Ok(flow::Access::empty());
        };
        let entry = l.scope.original();
        let status = entry.as_ref().map(|e| e.status()).transpose()?;
        // Derive every public field from this ONE actual row snapshot. A
        // concurrent relay return/Start must not splice two revisions together.
        let (permission, grant, review, consumed) = if let Some(s) = &status {
            if let (Some(grant), Some(review)) = (&s.start_grant_id, &s.prepared) {
                (
                    flow::Permission::Start,
                    grant.clone(),
                    review.review_id.clone(),
                    s.start_submitted,
                )
            } else {
                (
                    flow::Permission::Prepare,
                    l.id.clone(),
                    l.scope.selection_id.clone(),
                    true,
                )
            }
        } else {
            (
                flow::Permission::Prepare,
                l.id.clone(),
                l.scope.selection_id.clone(),
                false,
            )
        };
        let unknown = status.as_ref().map_or_else(
            || l.scope.control.first().is_err(),
            |s| s.phase == flow::Phase::Unknown,
        );
        let pending = status
            .as_ref()
            .is_some_and(|s| s.settlement != Settlement::Settled);
        let enabled = !b.closed
            && !unknown
            && !consumed
            && l.scope.current(false, Instant::now()).is_ok()
            && (permission == flow::Permission::Prepare && !pending
                || permission == flow::Permission::Start
                    && status
                        .as_ref()
                        .is_some_and(|s| s.phase == flow::Phase::Prepared));
        let remaining_ms = if enabled {
            u64::try_from(
                l.scope
                    .expires
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .unwrap_or(0)
            .min(p::INTENT_MS)
        } else {
            0
        };
        let result = flow::Access {
            schema_version: 1,
            service_instance: Some(self.instance.clone()),
            project_id: Some(l.scope.project_id.clone()),
            permission: Some(permission),
            grant_id: Some(grant),
            review_id: Some(review),
            selection: Some(l.scope.selection.clone()),
            request_id: entry.as_ref().map(|e| e.origin().request_id.clone()),
            enabled: enabled && remaining_ms > 0,
            remaining_ms,
            consumed,
            pending,
            unknown,
            status,
        };
        result.validate().map_err(|_| Error::StateUnknown)?;
        Ok(result)
    }
}
