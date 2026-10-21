//! Finite request metadata, not an edit executor. One original Config session
//! at a time, 32 non-evicted launch tombstones. Original full JSON lives only in
//! EditOwner/the main window; rows contain the closed whitelisted projection.
use crate::{
    service_configuration_protocol as p,
    service_protocol::{Error, Id},
    service_version_reserve_requests::ReadPermission,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::{Duration, Instant},
};

// All 32 rows plus eight IPC input/output/typed comparison copies, roots and
// two main-window copies. Not RSS, not extra native owner credit. The existing
// config owner retains its original buffers; bounded derivation is charged
// separately at the native admission hook.
// ONLY the separate raw4KiB worker term is pooled. The +18 typed/native/GUI
// overlap is mixed ownership and remains charged in full.
pub(crate) const IPC_WORKER_BACKING: usize = crate::service_protocol::REQUEST_BYTES;
pub(crate) const DOCUMENT_BACKING: usize = (p::REQUEST_LIMIT + 18)
    * (p::STATUS_BYTES + 8192 + std::mem::size_of::<Entry>());
// The Images row replaces one of these SAME32 slots, including an unused
// grant or pre-Allow tombstone; never another pool or an IPC reservation.
const _: () = assert!(crate::service_metadata_images_requests::ROW_BYTES
    <= p::STATUS_BYTES + 8192 + std::mem::size_of::<Entry>());
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Read,
    Prepare,
    Apply,
}
pub(crate) struct Source {
    pub(crate) runtime_id: String,
    pub(crate) root: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) observation_revision: u64,
}
struct Row {
    status: p::Status,
    dispatch: Option<Kind>,
    claimed: bool,
    retired: bool,
    binding: Option<(Id, Id, Weak<()>)>,
    prepare: Option<p::Prepare>,
    apply: Option<p::Apply>,
    permission_end: Option<Instant>,
    apply_end: Option<Instant>,
    apply_entered: bool,
    stop: Option<Instant>,
    history_claimed: bool,
}
pub(crate) struct Entry {
    input: p::Read,
    pub(crate) source: Source,
    pub(crate) read: Arc<ReadPermission>,
    row: Mutex<Row>,
    failed: Arc<AtomicBool>,
    changes: tokio::sync::watch::Sender<u32>,
}
fn bump(
    row: &mut Row,
    changes: &tokio::sync::watch::Sender<u32>,
    failed: &AtomicBool,
) -> Result<(), Error> {
    row.status.revision = row.status.revision.checked_add(1).ok_or_else(|| {
        failed.store(true, Ordering::Release);
        Error::StateUnknown
    })?;
    let mut good = true;
    changes.send_modify(|revision| {
        if let Some(next) = revision.checked_add(1) {
            *revision = next
        } else {
            good = false
        }
    });
    if good {
        Ok(())
    } else {
        failed.store(true, Ordering::Release);
        Err(Error::StateUnknown)
    }
}
impl Entry {
    pub(crate) fn input(&self) -> &p::Read {
        &self.input
    }
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Result<Option<Instant>, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        let read = self.read.stop(now)?.map(|(_, at)| at);
        let row = self.lock()?;
        let approval = row
            .apply_end
            .filter(|end| !row.apply_entered && now >= *end);
        Ok([row.stop, read, approval].into_iter().flatten().min())
    }
    pub(crate) fn live(&self, now: Instant) -> bool {
        self.stop_at(now).is_ok_and(|v| v.is_none())
    }
    pub(crate) fn cancel(&self, at: Instant) -> Result<(), Error> {
        let mut row = self.lock()?;
        if row.retired {
            return Ok(()); // The original terminal result is immutable DATA.
        }
        if row.stop.is_none_or(|old| at < old) {
            row.stop = Some(at)
        }
        row.status.cancel_requested = true;
        row.permission_end = None;
        if !row.retired && row.status.phase != p::Phase::Unknown {
            row.status.phase = if row.claimed {
                p::Phase::Stopping
            } else {
                p::Phase::Refused
            };
        }
        bump(&mut row, &self.changes, &self.failed)
    }
    pub(crate) fn unknown(&self) {
        if let Ok(mut row) = self.row.lock() {
            row.status.phase = p::Phase::Unknown;
            row.status.result = None;
            row.permission_end = None;
            row.stop.get_or_insert_with(Instant::now);
            let _ = bump(&mut row, &self.changes, &self.failed);
        } else {
            self.failed.store(true, Ordering::Release)
        }
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        let now = Instant::now();
        if let Some(at) = self.stop_at(now)? {
            let needs = {
                let row = self.lock()?;
                !row.status.cancel_requested && !row.retired
            };
            if needs {
                self.cancel(at)?
            }
        }
        let row = self.lock()?;
        let mut status = row.status.clone();
        let ms = row
            .permission_end
            .filter(|_| {
                status.phase == p::Phase::Reviewing
                    && !status.apply_consumed
                    && !status.cancel_requested
            })
            .map_or(0, |end| {
                end.saturating_duration_since(now)
                    .as_millis()
                    .min(u128::from(p::REVIEW_MS)) as u64
            });
        status.permission_live = ms > 0;
        status.remaining_ms = ms;
        status.validate().map_err(|_| Error::StateUnknown)?;
        Ok(status)
    }
    pub(crate) fn prepare(&self, input: p::Prepare) -> Result<p::Status, Error> {
        input.change.validate()?;
        {
            let mut row = self.lock()?;
            if let Some(old) = &row.prepare {
                if old != &input {
                    return Err(Error::Conflict);
                }
                drop(row);
                return self.status(); // Exact retry is DATA, never another Prepare.
            }
            if !self.live_unlocked(&row, Instant::now())?
                || row.status.phase != p::Phase::Opened
                || row.status.original.as_ref() != Some(&input.original)
                || input.origin != self.input.origin
            {
                return Err(Error::Conflict);
            }
            row.status.change = Some(input.change.clone());
            row.prepare = Some(input);
            row.status.phase = p::Phase::QueuedPrepare;
            bump(&mut row, &self.changes, &self.failed)?;
        }
        self.status()
    }
    fn live_unlocked(&self, row: &Row, now: Instant) -> Result<bool, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        Ok(row.stop.is_none()
            && self.read.stop(now)?.is_none()
            && !row.retired
            && row.status.phase != p::Phase::Unknown)
    }
    pub(crate) fn apply(&self, input: p::Apply) -> Result<p::Status, Error> {
        {
            let mut row = self.lock()?;
            if let Some(old) = &row.apply {
                if old != &input {
                    return Err(Error::Conflict);
                }
                drop(row);
                return self.status();
            }
            let now = Instant::now();
            if !input.reviewed
                || !self.live_unlocked(&row, now)?
                || row.status.phase != p::Phase::Reviewing
                || row.status.original.as_ref() != Some(&input.original)
                || input.origin != self.input.origin
                || !row
                    .status
                    .review
                    .as_ref()
                    .is_some_and(|r| r.plan_token == input.plan_token)
                || !row.permission_end.is_some_and(|end| now < end)
                || row.status.apply_consumed
            {
                return Err(Error::AccessDenied);
            }
            row.apply = Some(input);
            row.status.apply_consumed = true;
            row.apply_end = row.permission_end;
            row.permission_end = None;
            row.status.phase = p::Phase::QueuedApply;
            bump(&mut row, &self.changes, &self.failed)?;
        }
        self.status()
    }
    /// Native capture/rematch and the real-window handler call this only for
    /// the exact immutable original prepared preview. Renewals are forbidden.
    pub(crate) fn allow(&self, input: &p::Allow, review_end: Instant) -> Result<p::Status, Error> {
        {
            let mut row = self.lock()?;
            let now = Instant::now();
            if input.consent_version != p::CONSENT
                || input.origin != self.input.origin
                || row.status.original.as_ref() != Some(&input.original)
                || row.status.phase != p::Phase::Reviewing
                || !row.status.review.as_ref().is_some_and(|r| {
                    r.plan_token == input.plan_token
                        && r.native_status_revision == input.expected_native_status_revision
                })
                || !self.live_unlocked(&row, now)?
                || row.status.apply_consumed
            {
                return Err(Error::Conflict);
            }
            if row.permission_end.is_none() {
                let end = review_end.min(self.read.end());
                if end <= now
                    || end.saturating_duration_since(now) > Duration::from_millis(p::REVIEW_MS)
                {
                    return Err(Error::Expired);
                }
                row.permission_end = Some(end);
                bump(&mut row, &self.changes, &self.failed)?;
            }
        }
        self.status()
    }
    pub(crate) fn queued(&self, kind: Kind) -> Result<bool, Error> {
        let row = self.lock()?;
        Ok(row.status.phase
            == match kind {
                Kind::Read => p::Phase::QueuedRead,
                Kind::Prepare => p::Phase::QueuedPrepare,
                Kind::Apply => p::Phase::QueuedApply,
            })
    }
    pub(crate) fn dispatch(&self, kind: Kind) -> Result<bool, Error> {
        let mut row = self.lock()?;
        let (queued, running) = match kind {
            Kind::Read => (p::Phase::QueuedRead, p::Phase::Opening),
            Kind::Prepare => (p::Phase::QueuedPrepare, p::Phase::Preparing),
            Kind::Apply => (p::Phase::QueuedApply, p::Phase::Applying),
        };
        if row.status.phase != queued {
            return Ok(false);
        }
        if !self.live_unlocked(&row, Instant::now())? {
            return Err(Error::Expired);
        }
        if row.dispatch.is_some() {
            return Err(Error::StateUnknown);
        }
        row.dispatch = Some(kind);
        row.status.phase = running;
        bump(&mut row, &self.changes, &self.failed)?;
        Ok(true)
    }
    pub(crate) fn admitting(&self, kind: Kind) -> bool {
        self.live(Instant::now())
            && self
                .lock()
                .is_ok_and(|r| r.dispatch == Some(kind) && !r.retired)
    }
    pub(crate) fn claim_open(&self) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.claimed || r.dispatch != Some(Kind::Read) || !self.live_unlocked(&r, Instant::now())? {
            return Err(Error::Conflict);
        }
        r.claimed = true;
        Ok(())
    }
    pub(crate) fn bind(&self, session: Id, generation: Id, marker: Weak<()>) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed
            || r.binding.is_some()
            || r.dispatch != Some(Kind::Read)
            || marker.strong_count() == 0
        {
            return Err(Error::StateUnknown);
        }
        r.status.operation_id = Some(session.clone());
        r.status.owner_generation = Some(generation.clone());
        r.binding = Some((session, generation, marker));
        r.dispatch = None;
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn bound(&self, session: &str, generation: &str) -> bool {
        self.lock().is_ok_and(|r| {
            r.binding.as_ref().is_some_and(|(s, g, m)| {
                s.as_str() == session && g.as_str() == generation && m.strong_count() > 0
            })
        })
    }
    pub(crate) fn consume(&self, kind: Kind) -> Result<(), Error> {
        let mut r = self.lock()?;
        if kind == Kind::Read
            || r.dispatch != Some(kind)
            || !self.live_unlocked(&r, Instant::now())?
        {
            return Err(Error::Conflict);
        }
        if kind == Kind::Apply {
            if !r.apply_end.is_some_and(|end| Instant::now() < end) {
                return Err(Error::Expired);
            }
            r.apply_entered = true;
        }
        r.dispatch = None;
        Ok(())
    }
    pub(crate) fn dispatch_failed(&self) {
        if let Ok(mut r) = self.row.lock() {
            if r.retired || r.status.phase == p::Phase::Unknown {
                return;
            }
            r.dispatch = None;
            r.permission_end = None;
            r.status.phase = if r.claimed {
                p::Phase::Unknown
            } else {
                p::Phase::Refused
            };
            r.stop.get_or_insert_with(Instant::now);
            let _ = bump(&mut r, &self.changes, &self.failed);
        } else {
            self.failed.store(true, Ordering::Release)
        }
    }
    pub(crate) fn opened(&self, original: p::Original, settings: p::Settings) -> Result<(), Error> {
        settings.validate()?;
        let mut r = self.lock()?;
        if !r
            .binding
            .as_ref()
            .is_some_and(|(s, g, _)| s == &original.session_id && g == &original.owner_generation)
        {
            return Err(Error::Conflict);
        }
        if let Some(prior) = &r.status.original {
            if prior != &original {
                return Err(Error::StateUnknown);
            }
            return Ok(());
        }
        r.status.original = Some(original);
        r.status.settings = Some(settings);
        if r.status.phase == p::Phase::Opening {
            r.status.phase = p::Phase::Opened
        }
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn prepared(&self, review: p::Review) -> Result<(), Error> {
        review.validate()?;
        let mut r = self.lock()?;
        if let Some(prior) = &r.status.review {
            // Subsequent native bumps do not renew or mutate this review.
            let mut compare = review;
            compare.native_status_revision = prior.native_status_revision;
            if prior != &compare {
                return Err(Error::StateUnknown);
            }
            return Ok(());
        }
        if r.status.change.is_none() || r.prepare.is_none() || r.status.phase != p::Phase::Preparing
        {
            return Err(Error::Conflict);
        }
        r.status.review = Some(review);
        r.status.phase = p::Phase::Reviewing;
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn change(&self) -> Result<p::Change, Error> {
        self.lock()?.status.change.clone().ok_or(Error::Conflict)
    }
    pub(crate) fn original(&self) -> Result<p::Original, Error> {
        self.lock()?.status.original.clone().ok_or(Error::Conflict)
    }
    pub(crate) fn review(&self) -> Result<p::Review, Error> {
        self.lock()?.status.review.clone().ok_or(Error::Conflict)
    }
    /// Only observe_final, after all real original joins and atomic terminal
    /// adoption, calls this. A terminal child message never releases the slot.
    pub(crate) fn retired(&self, result: Option<p::Final>) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed || r.retired {
            return Err(Error::Conflict);
        }
        r.retired = true;
        r.permission_end = None;
        if r.status.phase == p::Phase::Unknown || result.is_none() {
            r.status.phase = p::Phase::Unknown;
            r.status.result = None
        } else {
            r.status.phase = p::Phase::Final;
            r.status.result = result;
            if r.status.result.as_ref().is_some_and(p::Final::saved) {
                r.status.settings = r.status.review.as_ref().map(|review| review.after.clone());
            }
        }
        bump(&mut r, &self.changes, &self.failed)
    }
    fn occupied(&self) -> Result<bool, Error> {
        let r = self.lock()?;
        Ok(r.status.phase == p::Phase::Unknown
            || r.claimed && !r.retired
            || !matches!(r.status.phase, p::Phase::Refused | p::Phase::Final))
    }
    pub(crate) fn history(
        &self,
    ) -> Result<
        Option<(
            Id,
            crate::service_protocol::OperationState,
            crate::service_protocol::Settlement,
        )>,
        Error,
    > {
        use crate::service_protocol::{OperationState as S, Settlement as F};
        let mut r = self.lock()?;
        if r.history_claimed {
            return Ok(None);
        }
        let Some((id, _, _)) = &r.binding else {
            return Ok(None);
        };
        let id = id.clone();
        let outcome = if r.status.phase == p::Phase::Unknown {
            Some((S::Unknown, F::Unknown))
        } else if r.retired {
            r.status.result.as_ref().map(|v| {
                (
                    if v.saved() {
                        S::Succeeded
                    } else if v.journal == p::Journal::RecoveryRequired {
                        S::RecoveryRequired
                    } else if v.cancelled {
                        S::Cancelled
                    } else {
                        S::Failed
                    },
                    F::Settled,
                )
            })
        } else {
            None
        };
        if let Some((state, settlement)) = outcome {
            r.history_claimed = true;
            Ok(Some((id, state, settlement)))
        } else {
            Ok(None)
        }
    }
}
// One Book/mutex/32-row budget for all three fixed editor families.
enum SharedRow { Configuration(Arc<Entry>), MetadataText(Arc<crate::service_metadata_text_requests::Entry>), MetadataImages(Arc<crate::service_metadata_images_requests::Entry>) }
impl SharedRow {
    fn origin(&self)->Option<&p::Query> {match self{Self::Configuration(e)=>Some(&e.input.origin),Self::MetadataText(e)=>Some(&e.input().origin),Self::MetadataImages(e)=>e.origin()}}
    fn occupied(&self)->Result<bool,Error>{match self{Self::Configuration(e)=>{let _=e.status()?;e.occupied()},Self::MetadataText(e)=>{let _=e.status()?;e.occupied()},Self::MetadataImages(e)=>e.occupied()}}
    fn cancel(&self,at:Instant)->Result<(),Error>{match self{Self::Configuration(e)=>e.cancel(at),Self::MetadataText(e)=>e.cancel(at),Self::MetadataImages(e)=>e.revoke(at)}}
    fn images(&self)->Option<&Arc<crate::service_metadata_images_requests::Entry>>{match self{Self::MetadataImages(e)=>Some(e),_=>None}}
    fn configuration(&self)->Option<&Arc<Entry>>{match self{Self::Configuration(e)=>Some(e),_=>None}}
    fn metadata(&self)->Option<&Arc<crate::service_metadata_text_requests::Entry>>{match self{Self::MetadataText(e)=>Some(e),_=>None}}
}
struct Book {
    rows: Vec<SharedRow>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: Arc<AtomicBool>,
    changes: tokio::sync::watch::Sender<u32>,
}
impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        let (changes, _) = tokio::sync::watch::channel(1);
        Self {
            instance,
            book: Mutex::new(Book {
                rows: Vec::new(),
                closed: false,
            }),
            failed: Arc::new(AtomicBool::new(false)),
            changes,
        }
    }
    fn lock(&self) -> Result<MutexGuard<'_, Book>, Error> {
        self.book.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u32> {
        self.changes.subscribe()
    }
    pub(crate) fn read(
        &self,
        input: p::Read,
        source: Source,
        read: Arc<ReadPermission>,
    ) -> Result<p::Status, Error> {
        let mut book = self.lock()?;
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(old) = book
            .rows
            .iter()
            .find(|r| r.origin().is_some_and(|q|q.request_id == input.origin.request_id))
        {
            let old=old.configuration().ok_or(Error::Conflict)?;
            if old.input != input {
                return Err(Error::Conflict);
            }
            return old.status();
        }
        if book.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        if input.expected_observation_revision == 0
            || input.expected_observation_revision != source.observation_revision
            || read.stop(Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        for row in &book.rows {
            if row.occupied()? {
                return Err(Error::Busy);
            }
        }
        if book.rows.len() >= p::REQUEST_LIMIT {
            return Err(Error::Busy);
        }
        let status = p::Status {
            schema_version: 1,
            origin: input.origin.clone(),
            revision: 1,
            runtime_project_id: source.runtime_id.clone(),
            phase: p::Phase::QueuedRead,
            operation_id: None,
            owner_generation: None,
            original: None,
            settings: None,
            change: None,
            review: None,
            permission_live: false,
            remaining_ms: 0,
            apply_consumed: false,
            cancel_requested: false,
            result: None,
            do_not_replay: true,
        };
        status.validate()?;
        let entry = Arc::new(Entry {
            input,
            source,
            read,
            row: Mutex::new(Row {
                status,
                dispatch: None,
                claimed: false,
                retired: false,
                binding: None,
                prepare: None,
                apply: None,
                permission_end: None,
                apply_end: None,
                apply_entered: false,
                stop: None,
                history_claimed: false,
            }),
            failed: self.failed.clone(),
            changes: self.changes.clone(),
        });
        book.rows.push(SharedRow::Configuration(entry.clone()));
        {
            let mut row = entry.lock()?;
            bump(&mut row, &self.changes, &self.failed)?
        }
        entry.status()
    }
    pub(crate) fn entry(&self, q: &p::Query) -> Result<Arc<Entry>, Error> {
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        self.lock()?
            .rows
            .iter().filter_map(SharedRow::configuration)
            .find(|r| &r.input.origin == q)
            .cloned()
            .ok_or(Error::Conflict)
    }
    pub(crate) fn desktop(&self) -> Result<p::DesktopStatus, Error> {
        let book = self.lock()?;
        let request = book.rows.iter().rev().find_map(SharedRow::configuration).map(|r| r.status()).transpose()?;
        let result = p::DesktopStatus {
            service_instance: self.instance.clone(),
            revision: *self.changes.borrow(),
            request,
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn desktop_request(&self, q: &p::Query) -> Result<p::DesktopStatus, Error> {
        // The relay may coalesce a retired row into the next request. Explicit
        // inspection retrieves that SAME retained row, never the newest one.
        let request = self.entry(q)?.status()?;
        let result = p::DesktopStatus {
            service_instance: self.instance.clone(),
            revision: *self.changes.borrow(),
            request: Some(request),
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn entries(&self) -> Result<Vec<Arc<Entry>>, Error> {
        Ok(self.lock()?.rows.iter().filter_map(SharedRow::configuration).cloned().collect())
    }
    pub(crate) fn close(&self, at: Instant) {
        if let Ok(mut book) = self.book.lock() {
            book.closed = true;
            for row in &book.rows {
                let _ = row.cancel(at);
            }
        } else {
            self.failed.store(true, Ordering::Release)
        }
    }
    pub(crate) fn metadata_read(&self,input:crate::service_metadata_text_protocol::Read,source:Source,read:Arc<ReadPermission>)->Result<crate::service_metadata_text_protocol::Status,Error>{
        input.validate()?;let mut book=self.lock()?;
        if input.origin.service_instance!=self.instance{return Err(Error::Conflict)}
        if let Some(row)=book.rows.iter().find(|r|r.origin().is_some_and(|q|q.request_id==input.origin.request_id)){
            let old=row.metadata().ok_or(Error::Conflict)?;if old.input()!=&input{return Err(Error::Conflict)}return old.status();
        }
        if book.closed||self.failed.load(Ordering::Acquire){return Err(Error::Unavailable)}
        if input.expected_observation_revision!=source.observation_revision||read.stop(Instant::now())?.is_some(){return Err(Error::Conflict)}
        for row in &book.rows{if row.occupied()?{return Err(Error::Busy)}}
        if book.rows.len()>=p::REQUEST_LIMIT{return Err(Error::Busy)}
        let entry=Arc::new(crate::service_metadata_text_requests::Entry::new(input,source,read,self.failed.clone(),self.changes.clone())?);
        book.rows.push(SharedRow::MetadataText(entry.clone()));
        self.changes.send_modify(|n|if let Some(next)=n.checked_add(1){*n=next}else{self.failed.store(true,Ordering::Release)});
        entry.status()
    }
    pub(crate) fn metadata_entry(&self,q:&p::Query)->Result<Arc<crate::service_metadata_text_requests::Entry>,Error>{
        if q.service_instance!=self.instance{return Err(Error::Conflict)}
        self.lock()?.rows.iter().filter_map(SharedRow::metadata).find(|e|&e.input().origin==q).cloned().ok_or(Error::Conflict)
    }
    pub(crate) fn metadata_desktop(&self,q:Option<&p::Query>)->Result<crate::service_metadata_text_protocol::DesktopStatus,Error>{
        let request=if let Some(q)=q{Some(self.metadata_entry(q)?.status()?)}else{self.lock()?.rows.iter().rev().find_map(SharedRow::metadata).map(|e|e.status()).transpose()?};
        let s=crate::service_metadata_text_protocol::DesktopStatus{service_instance:self.instance.clone(),revision:*self.changes.borrow(),request};s.validate()?;Ok(s)
    }
    pub(crate) fn metadata_entries(&self)->Result<Vec<Arc<crate::service_metadata_text_requests::Entry>>,Error>{Ok(self.lock()?.rows.iter().filter_map(SharedRow::metadata).cloned().collect())}

    pub(crate) fn fence(&self) {
        self.failed.store(true, Ordering::Release);
    }
    pub(crate) fn catalogue(
        &self,
        project: &Id,
    ) -> Result<Vec<crate::service_request_catalogue::AdditionalRequest>, Error> {
        use crate::service_request_catalogue::{AdditionalFamily, AdditionalRequest};
        Ok(self
            .lock()?
            .rows
            .iter()
            .filter_map(|r|r.origin().filter(|q|&q.project_id==project).map(|q|AdditionalRequest {
                family: match r {SharedRow::Configuration(_)=>AdditionalFamily::Configuration,SharedRow::MetadataText(_)=>AdditionalFamily::MetadataText,SharedRow::MetadataImages(_)=>AdditionalFamily::MetadataImages},
                request_id:q.request_id.clone(),
            }))
            .collect())
    }
}

#[cfg(test)]
#[path = "service_configuration_requests_tests.rs"]
mod tests;

#[path="service_metadata_images_book.rs"]
mod images;
