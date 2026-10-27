//! One bounded in-memory Stage/Unstage inbox. It never runs Git, holds a
//! Document lock, accesses Store, or reconstructs a native ReadyReview.
use crate::{
    service_git_protocol as p,
    service_git_commit_protocol::{Draft, Family},
    service_git_repository_protocol::{self as repository, shared},
    service_protocol::{Error, Id, OperationState, Settlement},
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::Instant,
};

// SAME thirty-two rows/one scope, not a second Remote inbox. ROW_HEAP names
// simultaneous Remote selection (<=2.5KiB), private/public/pending review
// summaries (<=3KiB each), final effect (<=1KiB) and transition copies. Local
// rows stay within that quote. The SAME eight IPC workers below reserve their
// typed+encoded scope/status copies in the common pool (SCOPE_BACKING
// exceeds Remote metadata). No row/source/draft debit is removed.
// Full native action/review/Connection runtime remains on its existing owners.
// Private Commit draft remains only in the original active scope/handoff.
const SCOPE_BACKING: usize = p::PATH_LIMIT * (1024 + std::mem::size_of::<String>()) + 8192;
pub(crate) const IPC_WORKER_BACKING: usize = p::SCOPE_BYTES + SCOPE_BACKING + p::STATUS_BYTES + 4096;
pub(crate) const DOCUMENT_BACKING: usize = p::REQUEST_LIMIT
    * (crate::service_git_remote_protocol::ROW_HEAP + std::mem::size_of::<Entry>() + std::mem::size_of::<Row>())
    + 2 * (SCOPE_BACKING + crate::service_git_commit_protocol::DRAFT_BACKING);

pub(crate) struct NativeScope {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) root: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) registration: u32,
    pub(crate) document_revision: u32,
    pub(crate) input_revision: u64,
    pub(crate) read_operation_id: Option<String>,
    pub(crate) document: Weak<()>,
    pub(crate) selection: shared::Selected,
    pub(crate) commit: Option<Draft>,
    pub(crate) changes: tokio::sync::watch::Sender<u32>,
}
impl NativeScope {
    fn valid(&self) -> bool {
        self.selection.validate().is_ok()
            && match (&self.commit, &self.selection) {
                (Some(draft), shared::Selected::Files(v)) if v.summary.action == p::Action::Commit => draft.valid(),
                (None, shared::Selected::Files(v)) => matches!(v.summary.action,p::Action::Stage|p::Action::Unstage),
                (None, shared::Selected::Repository(_) | shared::Selected::Remote(_)) => true,
                _ => false,
            }
            && match &self.selection {
                shared::Selected::Repository(v) if matches!(v.action,repository::Action::Initialize {}) => self.read_operation_id.is_none(),
                _ => self.read_operation_id.as_deref().is_some_and(p::native_id),
            }
            && (1..=64).contains(&self.runtime_id.len())
            && self.root.is_absolute()
            && self.root.as_os_str().len() <= 4096
            && self.inode != 0
            && (1..u32::MAX).contains(&self.registration)
            && (1..u32::MAX).contains(&self.document_revision)
            && self.input_revision != u64::MAX
            && self.document.strong_count() != 0
    }
}
struct Lease {
    id: Id,
    scope: Arc<NativeScope>,
    expires: Instant,
    revoked: AtomicBool,
    used: AtomicBool,
}
impl Lease {
    fn live(&self, now: Instant) -> bool {
        !self.revoked.load(Ordering::Acquire)
            && now < self.expires
            && self.scope.document.strong_count() != 0
    }
}
struct Book {
    lease: Option<Arc<Lease>>,
    entries: Vec<Arc<Entry>>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: AtomicBool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Prepare,
    Apply,
}
struct Row {
    lease: Option<Arc<Lease>>,
    status: shared::Status,
    claimed: Option<Phase>,
    prepare_joined: bool,
    apply_joined: bool,
    remote: Option<remote_requests::Retirement>,
    // Only actual native reconcile supplies this. It is removed by the SAME
    // original ReadyReview's retirement, never a status/EOF/socket assumption.
    review: Option<(shared::Reviewed, Instant)>,
    start: Option<p::Start>,
    stop: Option<(p::Reason, Instant)>,
    history_claim: Option<(u32, OperationState, Settlement)>,
    history_ack: Option<u32>,
    history_failed: bool,
}
pub(crate) struct Entry {
    input: p::Prepare,
    family: Family,
    runtime_id: String,
    row: Mutex<Row>,
    failed: AtomicBool,
}
fn change(row: &mut Row) -> Result<(), Error> {
    row.status.revision = row
        .status
        .revision
        .checked_add(1)
        .ok_or(Error::StateUnknown)?;
    row.status.history_available = false;
    Ok(())
}
fn ended(row: &Row) -> bool {
    row.status.settlement == Settlement::Settled
        && row.status.outcome != Some(OperationState::RecoveryRequired)
}
fn close(row: &mut Row, state: p::State, outcome: OperationState) -> Result<(), Error> {
    if row.status.state == p::State::Unknown {
        return Ok(());
    }
    row.status.state = state;
    row.status.outcome = Some(outcome);
    row.status.settlement = Settlement::Settled;
    row.status.review = None;
    row.review = None;
    if outcome != OperationState::RecoveryRequired {
        row.lease = None;
    }
    change(row)
}
fn stopped_state(reason: p::Reason) -> (p::State, OperationState) {
    match reason {
        p::Reason::Expired => (p::State::Expired, OperationState::Cancelled),
        p::Reason::Busy | p::Reason::Unavailable | p::Reason::NativeRefused => {
            (p::State::Refused, OperationState::Failed)
        }
        _ => (p::State::Cancelled, OperationState::Cancelled),
    }
}
fn stop_row(row: &mut Row, reason: p::Reason, at: Instant) -> Result<(), Error> {
    if row.status.settlement == Settlement::Settled
        || row.status.state == p::State::Unknown
        || row.stop.is_some()
    {
        return Ok(());
    }
    if row.stop.is_none() {
        row.stop = Some((reason, at));
        row.status.reason = Some(reason);
    }
    if row.claimed.is_none() && row.status.prepare_operation_id.is_none() {
        let (state, outcome) = stopped_state(row.stop.expect("retained first STOP").0);
        close(row, state, outcome)
    } else {
        row.status.state = p::State::Stopping;
        row.status.review = None;
        change(row)
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
    pub(crate) fn input(&self) -> &p::Prepare {
        &self.input
    }
    pub(crate) fn runtime_id(&self) -> &str {
        &self.runtime_id
    }
    pub(crate) fn scope(&self) -> Result<Arc<NativeScope>, Error> {
        self.lock()?
            .lease
            .as_ref()
            .map(|v| v.scope.clone())
            .ok_or(Error::Conflict)
    }
    pub(crate) fn stop_at(&self) -> Result<Option<(p::Reason, Instant)>, Error> {
        Ok(self.lock()?.stop)
    }
    pub(crate) fn cancel(&self, reason: p::Reason, at: Instant) {
        let Ok(mut row) = self.lock() else {
            return;
        };
        let scope = row.lease.as_ref().map(|l| l.scope.clone());
        if stop_row(&mut row, reason, at).is_err() {
            self.failed.store(true, Ordering::Release);
        }
        drop(row);
        if let Some(scope) = scope {
            scope.changes.send_modify(|_| {});
        }
    }
    pub(crate) fn expire(&self, now: Instant) {
        let Ok(mut row) = self.lock() else {
            return;
        };
        if row.status.apply_operation_id.is_some()
            || row.status.prepare_operation_id.is_some() && !row.prepare_joined
            || ended(&row)
            || row.status.state == p::State::Unknown
        {
            // The grant controls entry, not a new timeout for either native
            // phase. A joined Prepare still cannot yield a usable review once
            // the grant expired; ready() and the next original tick enforce it.
            return;
        }
        let at = row.lease.as_ref().map(|v| v.expires);
        let at = match (at, row.review.as_ref().map(|(_, at)| *at)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, _) => a,
        };
        if let Some(at) = at.filter(|at| now >= *at) {
            if row.stop.is_none() && stop_row(&mut row, p::Reason::Expired, at).is_err() {
                self.failed.store(true, Ordering::Release);
            }
        }
    }
    fn occupies(&self) -> bool {
        self.lock()
            .map_or(true, |r| !ended(&r) || r.claimed.is_some())
    }
    pub(crate) fn status(&self) -> Result<shared::Status, Error> {
        self.expire(Instant::now());
        let row = self.lock()?;
        let mut status = row.status.clone();
        status.history_available = !row.history_failed && row.history_ack == Some(status.revision);
        status.validate_shared()?;
        Ok(status)
    }
    pub(crate) fn unknown(&self) {
        let Ok(mut row) = self.row.lock() else {
            self.failed.store(true, Ordering::Release);
            return;
        };
        if row.status.state == p::State::Unknown {
            return;
        }
        row.status.state = p::State::Unknown;
        row.status.settlement = Settlement::Unknown;
        row.status.outcome = Some(OperationState::Unknown);
        row.status.reason = Some(p::Reason::CleanupUnknown);
        row.status.review = None;
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
    fn request_start(&self, input: &p::Start) -> Result<shared::Status, Error> {
        input.validate()?;
        self.expire(Instant::now());
        {
            let mut row = self.lock()?;
            if let Some(prior) = &row.start {
                if prior != input {
                    return Err(Error::Conflict);
                }
            } else {
                let now = Instant::now();
                if row.status.state != p::State::Prepared
                    || row.stop.is_some()
                    || row.lease.as_ref().is_none_or(|l| !l.live(now))
                    || row.status.prepare_operation_id.as_ref() != Some(&input.prepare_operation_id)
                    || row
                        .review
                        .as_ref()
                        .is_none_or(|(r, end)| r.id() != input.review_id || now >= *end || !r.can_apply())
                {
                    return Err(Error::Conflict);
                }
                row.start = Some(input.clone());
                row.status.state = p::State::StartQueued;
                change(&mut row)?;
                if let Some(l) = &row.lease {
                    l.scope.changes.send_modify(|_| {});
                }
            }
        }
        self.status()
    }
    pub(crate) fn claim_history(
        &self,
    ) -> Result<Option<(bool, u32, OperationState, Settlement)>, Error> {
        let mut row = self.lock()?;
        if row.status.prepare_operation_id.is_none()
            || row.history_failed
            || row.history_ack == Some(row.status.revision)
        {
            return Ok(None);
        }
        if row.history_claim.is_some() {
            row.history_failed = true;
            return Err(Error::StateUnknown);
        }
        let state = match row.status.state {
            p::State::Prepared | p::State::StartQueued => OperationState::Prepared,
            p::State::Stopping => OperationState::CancellationRequested,
            p::State::Unknown => OperationState::Unknown,
            p::State::Refused | p::State::Cancelled | p::State::Expired | p::State::Finished => {
                row.status.outcome.ok_or(Error::StateUnknown)?
            }
            _ => OperationState::Running,
        };
        let data = (row.status.revision, state, row.status.settlement);
        let first = row.history_ack.is_none();
        row.history_claim = Some(data);
        Ok(Some((first, data.0, data.1, data.2)))
    }
    pub(crate) fn history_returned(
        &self,
        revision: u32,
        result: Result<(), Error>,
    ) -> Result<(), Error> {
        let mut row = self.lock()?;
        if row.history_claim.as_ref().is_none_or(|v| v.0 != revision) {
            row.history_failed = true;
            return Err(Error::StateUnknown);
        }
        if let Err(e) = result {
            row.history_failed = true;
            return Err(e);
        }
        row.history_claim = None;
        row.history_ack = Some(revision);
        Ok(())
    }
}

/// Original native admission only. Neither deserialization nor querying an ID
/// can mint it; the existing Supervisor arms it before registering/spawning.
pub(crate) struct NativeLink {
    entry: Arc<Entry>,
    lease: Arc<Lease>,
    phase: Phase,
    armed: AtomicBool,
}
impl NativeLink {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
    pub(crate) fn scope(&self) -> &Arc<NativeScope> {
        &self.lease.scope
    }
    pub(crate) fn arm(&self, operation_id: &str) -> Result<(), Error> {
        if !p::native_id(operation_id) {
            return Err(Error::InvalidRequest);
        }
        let mut row = self.entry.lock()?;
        if self.armed.load(Ordering::Acquire)
            || row.claimed != Some(self.phase)
            || row.stop.is_some()
            || !self.lease.live(Instant::now())
            || row
                .lease
                .as_ref()
                .is_none_or(|v| !Arc::ptr_eq(v, &self.lease))
        {
            return Err(Error::Conflict);
        }
        match self.phase {
            Phase::Prepare => {
                if row.status.prepare_operation_id.is_some() {
                    return Err(Error::Conflict);
                }
                row.status.prepare_operation_id = Some(operation_id.into());
                row.status.state = p::State::Preparing;
            }
            Phase::Apply => {
                if row.status.apply_operation_id.is_some()
                    || row.status.prepare_operation_id.as_deref() == Some(operation_id)
                    || row
                        .review
                        .as_ref()
                        .is_none_or(|(_, end)| Instant::now() >= *end)
                {
                    return Err(Error::Conflict);
                }
                row.status.apply_operation_id = Some(operation_id.into());
                row.status.state = p::State::Applying;
                row.status.review = None;
            }
        }
        remote_requests::armed(&mut row,self.phase)?;
        self.armed.store(true, Ordering::Release);
        change(&mut row)
    }
    pub(crate) fn current(&self, operation_id: &str) -> Result<(), Error> {
        let row = self.entry.lock()?;
        let original = match self.phase {
            Phase::Prepare => &row.status.prepare_operation_id,
            Phase::Apply => &row.status.apply_operation_id,
        };
        // Expiration controls admission only. The original admitted operation
        // keeps its unchanged native work/cleanup endpoints.
        if !self.armed.load(Ordering::Acquire)
            || original.as_deref() != Some(operation_id)
            || row.stop.is_some()
            || self.lease.revoked.load(Ordering::Acquire)
            || self.lease.scope.document.strong_count() == 0
            || row.status.state == p::State::Unknown
        {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    pub(crate) fn stopped(&self) -> bool {
        self.entry.stop_at().map_or(true, |v| v.is_some())
    }
    pub(crate) fn same_request(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.entry, &other.entry) && Arc::ptr_eq(&self.lease, &other.lease)
    }
    pub(crate) fn ready(&self, review: impl Into<shared::Reviewed>, expires: Instant) -> Result<bool, Error> {
        if self.is_remote() { return Err(Error::StateUnknown); } // Remote needs actual Connection finish first.
        let review = review.into();
        let mut row = self.entry.lock()?;
        if !review.matches(&row.status.selection) { return Err(Error::InvalidRequest); }
        if self.phase != Phase::Prepare
            || !self.armed.load(Ordering::Acquire)
            || !row.prepare_joined
        {
            return Err(Error::StateUnknown);
        }
        if row.status.state == p::State::Unknown {
            return Ok(false);
        }
        if row.stop.is_some() || !self.lease.live(Instant::now()) || Instant::now() >= expires {
            let reason = row.stop.map_or(p::Reason::Expired, |v| v.0);
            row.status.reason = Some(reason);
            let (state, outcome) = stopped_state(reason);
            close(&mut row, state, outcome)?;
            return Ok(false);
        }
        if row.review.is_some() || row.status.apply_operation_id.is_some() {
            return Err(Error::StateUnknown);
        }
        row.review = Some((review.clone(), expires));
        row.status.review = Some(review);
        row.status.state = p::State::Prepared;
        change(&mut row)?;
        Ok(true)
    }
    /// Called only when the original Prepare receipt has really joined but
    /// native reconcile cannot retain a current usable review.
    pub(crate) fn no_review(&self) {
        if remote_requests::review_removed(self) {return;}
        if let Ok(mut row) = self.entry.lock() {
            if self.phase != Phase::Prepare
                || !row.prepare_joined
                || row.status.apply_operation_id.is_some()
            {
                return;
            }
            if ended(&row) || row.status.state == p::State::Unknown {
                return;
            }
            let reason = row.stop.map_or(p::Reason::ContextChanged, |v| v.0);
            row.status.reason = Some(reason);
            let (state, outcome) = stopped_state(reason);
            if close(&mut row, state, outcome).is_err() {
                self.entry.failed.store(true, Ordering::Release);
            }
        }
    }
    /// The actual ReadyReview is gone. This is NOT native-job settlement: a
    /// prepared operation must already have its original joined receipt, and
    /// an armed Apply remains live/unknown regardless of review retirement.
    pub(crate) fn review_removed(&self) {
        if remote_requests::review_removed(self) {return;}
        if let Ok(mut row) = self.entry.lock() {
            row.review = None;
            row.status.review = None;
            if row.status.apply_operation_id.is_some()
                || !row.prepare_joined
                || ended(&row)
                || row.status.state == p::State::Unknown
            {
                return;
            }
            let reason = row.stop.map_or(p::Reason::UserCancelled, |v| v.0);
            row.status.reason = Some(reason);
            let (state, outcome) = stopped_state(reason);
            if close(&mut row, state, outcome).is_err() {
                self.entry.failed.store(true, Ordering::Release);
            }
        }
    }
    /// The only callers are the original Supervisor receipt publications. The
    /// child terminal, socket EOF and public Status never call this method.
    pub(crate) fn retired(&self, result: OperationState) {
        if result == OperationState::Unknown {
            self.entry.unknown();
            return;
        }
        let Ok(mut row) = self.entry.lock() else {
            return;
        };
        if !self.armed.load(Ordering::Acquire) || row.status.state == p::State::Unknown {
            return;
        }
        let result = match result {
            OperationState::Succeeded
            | OperationState::Failed
            | OperationState::Cancelled
            | OperationState::RecoveryRequired => result,
            _ => {
                drop(row);
                self.entry.unknown();
                return;
            }
        };
        if self.is_remote() {drop(row);remote_requests::retired(self,result);return;}
        if self.phase == Phase::Prepare {
            if row.prepare_joined {
                drop(row);
                self.entry.unknown();
                return;
            }
            row.prepare_joined = true;
            if result == OperationState::Succeeded {
                return;
            } // SAME native reconcile must mint ReadyReview.
        } else {
            if row.apply_joined {
                drop(row);
                self.entry.unknown();
                return;
            }
            row.apply_joined = true;
        }
        if result == OperationState::RecoveryRequired {
            row.status.reason = Some(p::Reason::RecoveryRequired);
        }
        if close(&mut row, p::State::Finished, result).is_err() {
            self.entry.failed.store(true, Ordering::Release);
        }
    }
}

pub(crate) struct Claim {
    entry: Arc<Entry>,
    phase: Phase,
    link: Option<Arc<NativeLink>>,
    returned: bool,
}
impl Claim {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
    pub(crate) fn link(&mut self) -> Result<Arc<NativeLink>, Error> {
        if self.link.is_some() {
            return Err(Error::StateUnknown);
        }
        let row = self.entry.lock()?;
        let lease = row.lease.as_ref().ok_or(Error::Conflict)?.clone();
        if row.claimed != Some(self.phase) || row.stop.is_some() || !lease.live(Instant::now()) {
            return Err(Error::Conflict);
        }
        let link = Arc::new(NativeLink {
            entry: self.entry.clone(),
            lease,
            phase: self.phase,
            armed: AtomicBool::new(false),
        });
        self.link = Some(link.clone());
        Ok(link)
    }
    pub(crate) fn start(&self) -> Result<p::Start, Error> {
        self.entry.lock()?.start.clone().ok_or(Error::Conflict)
    }
    pub(crate) fn returned(mut self, result: Result<(), Error>) {
        self.returned = true;
        let Ok(mut row) = self.entry.lock() else {
            return;
        };
        if row.claimed != Some(self.phase) {
            drop(row);
            self.entry.unknown();
            return;
        }
        row.claimed = None;
        if result.is_ok()
            && self
                .link
                .as_ref()
                .is_none_or(|v| !v.armed.load(Ordering::Acquire))
        {
            drop(row);
            self.entry.unknown();
            return;
        }
        if let Err(error) = result {
            if error == Error::StateUnknown
                || self
                    .link
                    .as_ref()
                    .is_some_and(|v| v.armed.load(Ordering::Acquire))
            {
                drop(row);
                self.entry.unknown();
                return;
            }
            let reason = row.stop.map_or(
                match error {
                    Error::Busy => p::Reason::Busy,
                    Error::Expired => p::Reason::Expired,
                    Error::Unavailable | Error::UnsupportedPlatform => p::Reason::Unavailable,
                    _ => p::Reason::NativeRefused,
                },
                |v| v.0,
            );
            if self.phase == Phase::Prepare {
                row.status.reason = Some(reason);
                let (state, outcome) = stopped_state(reason);
                if close(&mut row, state, outcome).is_err() {
                    self.entry.failed.store(true, Ordering::Release);
                }
            } else if stop_row(&mut row, reason, Instant::now()).is_err() {
                self.entry.failed.store(true, Ordering::Release);
            }
        }
        if remote_requests::caller_returned(&mut row,self.phase).is_err() {drop(row);self.entry.unknown();}
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown();
        }
    }
}

impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                lease: None,
                entries: Vec::with_capacity(p::REQUEST_LIMIT),
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
    /// Discovery copies immutable IDs, never status/expiry, claims or drafts.
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
                    family: match entry.family {
                        Family::Index => AdditionalFamily::GitIndex,
                        Family::Commit => AdditionalFamily::GitCommit,
                        Family::Repository => AdditionalFamily::GitRepository,
                        Family::Remote => AdditionalFamily::GitRemote,
                    },
                    request_id: entry.input.origin.request_id.clone(),
                });
            }
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        Ok(rows)
    }
    #[cfg(test)]
    pub(crate) fn with_catalogue_book_locked<T>(&self, body: impl FnOnce() -> T) -> T {
        let _original = self.book.lock().unwrap();
        body()
    }
    pub(crate) fn allow(&self, scope: Arc<NativeScope>) -> Result<p::Access, Error> {
        self.allow_for(scope, Family::Index)?.files()
    }
    fn allow_for(&self, scope: Arc<NativeScope>, family: Family) -> Result<shared::Access, Error> {
        if !scope.valid() || scope.selection.family() != family {
            return Err(Error::InvalidRequest);
        }
        let mut book = self.lock()?;
        if book.closed {
            return Err(Error::Unavailable);
        }
        if book.entries.len() >= p::REQUEST_LIMIT || book.entries.iter().any(|e| e.occupies()) {
            return Err(Error::Busy);
        }
        let expires = Instant::now()
            .checked_add(p::START_WINDOW)
            .ok_or(Error::StateUnknown)?;
        let lease = Arc::new(Lease {
            id: Id::random()?,
            scope,
            expires,
            revoked: AtomicBool::new(false),
            used: AtomicBool::new(false),
        });
        if let Some(old) = &book.lease {
            old.revoked.store(true, Ordering::Release);
        }
        book.lease = Some(lease);
        access(&book, None, family)
    }
    pub(crate) fn access(&self) -> Result<p::Access, Error> {
        let book = self.lock()?;
        access(&book, None, Family::Index)?.files()
    }
    pub(crate) fn scope(&self, project: &Id) -> Result<p::Scope, Error> {
        let book = self.lock()?;
        Ok(p::Scope {
            service_instance: self.instance.clone(),
            project_id: project.clone(),
            access: access(&book, Some(project), Family::Index)?.files()?,
        })
    }
    pub(crate) fn revoke(&self) -> Result<p::Access, Error> {
        self.revoke_for(Family::Index)?.files()
    }
    fn revoke_for(&self, family: Family) -> Result<shared::Access, Error> {
        let book = self.lock()?;
        if let Some(lease) = &book.lease {
            lease.revoked.store(true, Ordering::Release);
        }
        for e in &book.entries {
            e.cancel(p::Reason::PermissionRevoked, Instant::now());
        }
        access(&book, None, family)
    }
    pub(crate) fn close(&self) {
        match self.book.lock() {
            Ok(mut book) => {
                book.closed = true;
                if let Some(lease) = &book.lease {
                    lease.revoked.store(true, Ordering::Release);
                }
                for e in &book.entries {
                    e.cancel(p::Reason::Shutdown, Instant::now());
                }
            }
            Err(_) => self.failed.store(true, Ordering::Release),
        }
    }
    fn find<'a>(&self, book: &'a Book, query: &p::Query, family: Family) -> Result<&'a Arc<Entry>, Error> {
        if query.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        book.entries
            .iter()
            .find(|e| e.input.origin == *query && e.family == family)
            .ok_or(Error::Conflict)
    }
    pub(crate) fn prepare(&self, input: p::Prepare) -> Result<p::Status, Error> {
        self.prepare_for(input, Family::Index)?.files()
    }
    fn prepare_for(&self, input: p::Prepare, family: Family) -> Result<shared::Status, Error> {
        let mut book = self.lock()?;
        if input.origin.service_instance != self.instance || book.closed {
            return Err(Error::Conflict);
        }
        if let Some(prior) = book
            .entries
            .iter()
            .find(|e| e.input.origin.request_id == input.origin.request_id)
        {
            return if prior.input == input && prior.family == family {
                prior.status()
            } else {
                Err(Error::Conflict)
            };
        }
        if book.entries.len() >= p::REQUEST_LIMIT || book.entries.iter().any(|e| e.occupies()) {
            return Err(Error::Busy);
        }
        let lease = book.lease.as_ref().ok_or(Error::AccessDenied)?.clone();
        if lease.scope.selection.family() != family
            || lease.id != input.grant_id
            || lease.scope.project_id != input.origin.project_id
            || !lease.live(Instant::now())
            || lease.used.load(Ordering::Acquire)
        {
            return Err(Error::AccessDenied);
        }
        let status = p::Status {
            origin: input.origin.clone(),
            grant_id: input.grant_id.clone(),
            selection: lease.scope.selection.summary(),
            revision: 1,
            state: p::State::Queued,
            prepare_operation_id: None,
            apply_operation_id: None,
            review: None,
            outcome: None,
            settlement: Settlement::Pending,
            reason: None,
            history_available: false,
            do_not_replay: true,
        };
        let entry = Arc::new(Entry {
            runtime_id: lease.scope.runtime_id.clone(),
            input,
            family,
            failed: AtomicBool::new(false),
            row: Mutex::new(Row {
                lease: Some(lease.clone()),
                status: status.clone(),
                claimed: None,
                prepare_joined: false,
                apply_joined: false,
                remote: if family==Family::Remote {Some(remote_requests::Retirement::new())} else {None},
                review: None,
                start: None,
                stop: None,
                history_claim: None,
                history_ack: None,
                history_failed: false,
            }),
        });
        lease.used.store(true, Ordering::Release);
        book.entries.push(entry);
        lease.scope.changes.send_modify(|_| {});
        Ok(status)
    }
    pub(crate) fn start(&self, input: &p::Start) -> Result<p::Status, Error> {
        let book = self.lock()?;
        self.find(&book, &input.origin, Family::Index)?.request_start(input)?.files()
    }
    pub(crate) fn query(&self, input: &p::Query, cancel: bool) -> Result<p::Status, Error> {
        let book = self.lock()?;
        let entry = self.find(&book, input, Family::Index)?;
        if cancel {
            entry.cancel(p::Reason::UserCancelled, Instant::now());
        }
        entry.status()?.files()
    }
    pub(crate) fn claim(&self) -> Result<Option<Claim>, Error> {
        let book = self.lock()?;
        if book.closed {
            return Err(Error::Unavailable);
        }
        for entry in &book.entries {
            entry.expire(Instant::now());
            let mut row = entry.lock()?;
            if row.claimed.is_some() || row.stop.is_some() {
                continue;
            }
            let phase = match row.status.state {
                p::State::Queued => Phase::Prepare,
                p::State::StartQueued => Phase::Apply,
                _ => continue,
            };
            row.claimed = Some(phase);
            row.status.state = if phase == Phase::Prepare {
                p::State::Preparing
            } else {
                p::State::Applying
            };
            if phase == Phase::Apply {
                row.status.review = None;
            }
            change(&mut row)?;
            return Ok(Some(Claim {
                entry: entry.clone(),
                phase,
                link: None,
                returned: false,
            }));
        }
        Ok(None)
    }
    pub(crate) fn entries(&self) -> Result<Vec<Arc<Entry>>, Error> {
        Ok(self.lock()?.entries.clone())
    }
}
fn access(book: &Book, project: Option<&Id>, family: Family) -> Result<shared::Access, Error> {
    let Some(lease) = book
        .lease
        .as_ref()
        .filter(|l| l.scope.selection.family() == family
            && project.is_none_or(|id| id == &l.scope.project_id))
    else {
        return Ok(shared::Access::empty_shared());
    };
    let now = Instant::now();
    let consumed = lease.used.load(Ordering::Acquire);
    let remaining = lease
        .expires
        .saturating_duration_since(now)
        .as_millis()
        .min(900_000) as u64;
    let enabled = !book.closed && !consumed && lease.live(now) && remaining > 0;
    let value = p::Access {
        enabled,
        remaining_ms: if enabled { remaining } else { 0 },
        consumed,
        project_id: Some(lease.scope.project_id.clone()),
        grant_id: Some(lease.id.clone()),
        selection: Some(lease.scope.selection.clone()),
    };
    value.validate_shared()?;
    Ok(value)
}

#[path = "service_git_remote_requests.rs"]
mod remote_requests;

#[path = "service_git_repository_requests.rs"]
mod repository_requests;

#[path = "service_git_commit_requests.rs"]
mod commit;

#[cfg(test)]
#[path = "service_git_requests_tests.rs"]
mod tests;

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
impl Entry {
    /// Nonshipping comparison of THIS retained original. It grants nothing and
    /// never substitutes public status/history for native or relay retirement.
    pub(crate) fn installed_cli_returned(&self, origin:&p::Query, family:Family, phase:Phase, revision:u32)->bool {
        self.installed_cli_returned_observed(origin,family,phase,revision,&mut None)
    }
    pub(crate) fn installed_cli_returned_observed(&self, origin:&p::Query, family:Family, phase:Phase, revision:u32,
        facts:&mut Option<InstalledCliReturnFacts>)->bool {
        if self.input.origin!=*origin || self.family!=family || !matches!(family,Family::Index|Family::Repository){return false;}
        let Ok(r)=self.lock() else{return false};
        *facts=Some(InstalledCliReturnFacts {state:r.status.state,reason:r.status.reason,claimed:r.claimed.is_some(),
            prepare_joined:r.prepare_joined,apply_joined:r.apply_joined,history_failed:r.history_failed,
            history_claimed:r.history_claim.is_some(),history_acknowledged:r.history_ack==Some(revision),
            stopped:r.stop.is_some(),review_present:r.review.is_some(),revision_matched:r.status.revision==revision});
        r.status.revision==revision && r.claimed.is_none() && r.prepare_joined
            && !r.history_failed && r.history_claim.is_none() && r.history_ack==Some(revision)
            && r.stop.is_none() && r.status.reason.is_none() && match phase {
                Phase::Prepare=>r.status.state==p::State::Prepared && r.review.is_some()
                    && !r.apply_joined && r.status.apply_operation_id.is_none(),
                Phase::Apply=>r.status.state==p::State::Finished && r.apply_joined
                    && r.status.settlement==Settlement::Settled && r.status.outcome==Some(OperationState::Succeeded)
                    && r.review.is_none() && r.status.apply_operation_id.is_some(),
            }
    }
}

#[cfg(all(test, debug_assertions, feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct InstalledCliReturnFacts {
    state:p::State,reason:Option<p::Reason>,claimed:bool,prepare_joined:bool,apply_joined:bool,
    history_failed:bool,history_claimed:bool,history_acknowledged:bool,stopped:bool,review_present:bool,revision_matched:bool,
}
