//! Read-only preparation sibling of the original History lease in Store32.
//! This owns comparison DATA, not a native Prepared/Consent/Keychain graph.
use super::super::{preparation::StoredEntry, Book, Inbox};
use super::{Allowed, Control};
use crate::{
    agent_identity_requests::SavedPoint,
    service_local_history_prepare_protocol as p,
    service_protocol::{Error, OperationState, Settlement},
    service_version_reserve_requests::ReadPermission,
};
use std::{
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

pub(crate) struct Scope {
    pub(crate) saved: SavedPoint,
    pub(crate) read: Arc<ReadPermission>,
}
impl Scope {
    pub(crate) fn matches(&self, saved: &SavedPoint, read: &Arc<ReadPermission>) -> bool {
        self.saved.project_id == saved.project_id
            && self.saved.runtime_id == saved.runtime_id
            && self.saved.root == saved.root
            && self.saved.device == saved.device
            && self.saved.inode == saved.inode
            && self.saved.revision == saved.revision
            && Arc::ptr_eq(&self.read, read)
    }
    fn bounded(&self) -> bool {
        self.saved.root.is_absolute()
            && self.saved.root.capacity() <= 4096
            && (1..=64).contains(&self.saved.runtime_id.len())
            && self.saved.runtime_id.capacity() <= 64
            && self
                .saved
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Handoff {
    Waiting,
    Installing,
    HandedOff,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoryData {
    pub(crate) revision: u32,
    pub(crate) state: OperationState,
    pub(crate) settlement: Settlement,
}
struct Row {
    revision: u32,
    claimed: bool,
    caller_returned: bool,
    review: Option<p::Review>,
    witness: Weak<()>,
    expires: Instant,
    ended: Option<p::Reason>,
    handoff: Handoff,
    history_acked: u32,
    history_version: u32,
    history_started: bool,
    history_claim: Option<HistoryData>,
    unknown: Option<p::Reason>,
}
pub(crate) struct Entry {
    input: p::Request,
    scope: Scope,
    pub(crate) control: Arc<Control>,
    submitted: Instant,
    end: Instant,
    row: Mutex<Row>,
}
impl Entry {
    pub(crate) fn origin(&self) -> &p::Query {
        &self.input.origin
    }
    pub(crate) fn selection(&self) -> &p::Selection {
        &self.input.selection
    }
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub(crate) fn end(&self) -> Instant {
        self.end
    }
    pub(crate) fn submitted_at(&self) -> Instant {
        self.submitted
    }
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.control.unknown(self.submitted);
            Error::StateUnknown
        })
    }
    fn bump(&self, r: &mut Row) -> Result<(), Error> {
        match r.revision.checked_add(1).filter(|n| *n < u32::MAX) {
            Some(n) => {
                r.revision = n;
                r.history_version = n;
                Ok(())
            }
            None => {
                self.control.unknown(self.submitted);
                Err(Error::StateUnknown)
            }
        }
    }
    pub(crate) fn current(&self, now: Instant) -> Result<(), Error> {
        match self.scope.read.stop(now) {
            Ok(Some((_, at))) => self.control.stop(p::Reason::PermissionRevoked, at),
            Err(_) => self.control.unknown(self.submitted),
            Ok(None) => {}
        }
        if now >= self.end {
            self.control.stop(p::Reason::Expired, self.end);
        }
        let r = self.lock()?;
        if r.review.is_some()
            && r.handoff == Handoff::Waiting
            && r.ended.is_none()
            && r.witness.strong_count() == 0
        {
            self.control.unknown(self.submitted);
        }
        if r.unknown.is_some() {
            return Err(Error::StateUnknown);
        }
        if self.control.first()?.is_some() {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Option<(p::Reason, Instant)> {
        if self.handed_off() {
            return None;
        }
        let _ = self.current(now);
        self.control.first().unwrap_or_else(|_| {
            Some((
                p::Reason::CleanupUnknown,
                self.control.uncertain_at(self.submitted),
            ))
        })
    }
    pub(crate) fn cancel(&self, reason: p::Reason, at: Instant) {
        // A historical Prepare ID never cancels its distinct Start successor.
        if self
            .lock()
            .is_ok_and(|r| r.handoff == Handoff::HandedOff || Self::ended_settled(&r))
        {
            return;
        }
        self.control.stop(reason, at);
    }
    pub(crate) fn unknown(&self, reason: p::Reason) {
        self.control.unknown(self.submitted);
        if let Ok(mut r) = self.lock() {
            r.unknown.get_or_insert(reason);
            let _ = self.bump(&mut r);
        }
    }
    pub(crate) fn constructed(
        &self,
        review: p::Review,
        expires: Instant,
        witness: Weak<()>,
    ) -> Result<(), Error> {
        if !self.input.selection.matches(&review)
            || review.heap() > 36
            || expires > self.end
            || expires <= self.submitted
            || witness.strong_count() == 0
        {
            return Err(Error::Conflict);
        }
        let mut r = self.lock()?;
        if !r.claimed
            || r.caller_returned
            || r.review.is_some()
            || r.ended.is_some()
            || r.unknown.is_some()
        {
            return Err(Error::Conflict);
        }
        r.review = Some(review);
        r.expires = expires;
        r.witness = witness;
        self.bump(&mut r)
    }
    /// Called only for the actual pre-install refusal. An installed original
    /// must instead reach retired() from the SAME native Prepared retirement.
    pub(crate) fn refused(&self, reason: p::Reason) {
        let Ok(mut r) = self.lock() else {
            return;
        };
        if r.review.is_some() || r.ended.is_some() || !r.claimed {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        if matches!(
            reason,
            p::Reason::None | p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable
        ) {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        r.ended = Some(reason);
        let _ = self.bump(&mut r);
    }
    pub(crate) fn retired(&self, reason: p::Reason) {
        let Ok(mut r) = self.lock() else {
            return;
        };
        if r.handoff == Handoff::HandedOff {
            return;
        }
        if r.review.is_none()
            || r.handoff == Handoff::Installing
            || matches!(
                reason,
                p::Reason::None | p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable
            )
        {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        if r.ended.is_none() {
            r.ended = Some(reason);
            let _ = self.bump(&mut r);
        }
    }
    fn caller_returned(&self) {
        let Ok(mut r) = self.lock() else {
            return;
        };
        if !r.claimed || r.caller_returned || r.review.is_none() && r.ended.is_none() {
            drop(r);
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        r.caller_returned = true;
        let _ = self.bump(&mut r);
    }
    fn ended_settled(r: &Row) -> bool {
        r.unknown.is_none()
            && r.caller_returned
            && r.ended.is_some()
            && r.history_acked == r.history_version
            && r.history_claim.is_none()
    }
    fn live(r: &Row) -> bool {
        r.unknown.is_none()
            && r.caller_returned
            && r.review.is_some()
            && r.ended.is_none()
            && r.witness.strong_count() > 0
            && r.history_acked == r.history_version
            && r.history_claim.is_none()
    }
    pub(crate) fn ready(&self) -> bool {
        self.current(Instant::now()).is_ok()
            && self.lock().is_ok_and(|r| {
                Self::live(&r) && r.handoff == Handoff::Waiting && Instant::now() < r.expires
            })
    }
    pub(crate) fn handed_off(&self) -> bool {
        self.lock()
            .is_ok_and(|r| r.unknown.is_none() && r.handoff == Handoff::HandedOff)
    }
    pub(crate) fn installing(&self) -> bool {
        self.current(Instant::now()).is_ok()
            && self.lock().is_ok_and(|r| {
                Self::live(&r) && r.handoff == Handoff::Installing && Instant::now() < r.expires
            })
    }
    pub(crate) fn begin_handoff(&self, review: &p::Review) -> Result<(), Error> {
        self.current(Instant::now())?;
        let mut r = self.lock()?;
        if !Self::live(&r)
            || r.handoff != Handoff::Waiting
            || Instant::now() >= r.expires
            || r.review.as_ref().is_none_or(|old| {
                old.operation_id != review.operation_id
                    || old.owner_generation != review.owner_generation
                    || old.status_revision > review.status_revision
            })
            || !self.selection().matches(review)
        {
            return Err(Error::Conflict);
        }
        let original = r.history_version;
        self.bump(&mut r)?;
        r.history_version = original;
        r.handoff = Handoff::Installing;
        Ok(()) // same ACK'd construction proof, new comparison state
    }
    pub(crate) fn finish_handoff(&self) -> Result<(), Error> {
        self.current(Instant::now())?;
        let mut r = self.lock()?;
        if !Self::live(&r) || r.handoff != Handoff::Installing || Instant::now() >= r.expires {
            return Err(Error::Conflict);
        }
        let original = r.history_version;
        self.bump(&mut r)?;
        r.history_version = original;
        r.handoff = Handoff::HandedOff;
        Ok(())
    }
    pub(crate) fn pending(&self) -> bool {
        self.lock().map_or(true, |r| {
            r.unknown.is_some()
                || self.control.first().is_err()
                || r.handoff != Handoff::HandedOff && !Self::ended_settled(&r)
        })
    }
    pub(crate) fn claim_history(self: &Arc<Self>) -> Result<Option<History>, Error> {
        let mut r = self.lock()?;
        if !r.caller_returned
            || r.unknown.is_some()
            || r.history_claim.is_some()
            || r.handoff != Handoff::Waiting
            || r.history_acked == r.history_version
        {
            return Ok(None);
        }
        let (state, settlement) = if let Some(reason) = r.ended {
            (
                if matches!(
                    reason,
                    p::Reason::PermissionRevoked
                        | p::Reason::UserCancelled
                        | p::Reason::ContextChanged
                        | p::Reason::Shutdown
                ) {
                    OperationState::Cancelled
                } else {
                    OperationState::Failed
                },
                Settlement::Settled,
            )
        } else if r.review.is_some() {
            (OperationState::Prepared, Settlement::Settled)
        } else {
            return Ok(None);
        };
        let data = HistoryData {
            revision: r.history_version,
            state,
            settlement,
        };
        let first = !r.history_started;
        r.history_claim = Some(data.clone());
        Ok(Some(History {
            entry: self.clone(),
            data,
            first,
            returned: false,
        }))
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        if !self.handed_off() {
            let _ = self.current(Instant::now());
        }
        let r = self.lock()?;
        let stop = self.control.first();
        let unknown = r
            .unknown
            .or_else(|| stop.is_err().then_some(p::Reason::CleanupUnknown));
        let (phase, settlement, reason, remaining) = if let Some(reason) = unknown {
            (p::Phase::Unknown, Settlement::Unknown, reason, 0)
        } else if r.handoff == Handoff::HandedOff {
            (p::Phase::HandedOff, Settlement::Settled, p::Reason::None, 0)
        } else if Self::ended_settled(&r) {
            let reason = r.ended.ok_or(Error::StateUnknown)?;
            let phase = match reason {
                p::Reason::Expired => p::Phase::Expired,
                p::Reason::PermissionRevoked
                | p::Reason::UserCancelled
                | p::Reason::ContextChanged
                | p::Reason::Shutdown => p::Phase::Cancelled,
                _ => p::Phase::Refused,
            };
            (phase, Settlement::Settled, reason, 0)
        } else if Self::live(&r)
            && r.handoff == Handoff::Waiting
            && stop.as_ref().ok().is_some_and(|v| v.is_none())
            && Instant::now() < r.expires
        {
            (
                p::Phase::Prepared,
                Settlement::Settled,
                p::Reason::None,
                u64::try_from(
                    r.expires
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )
                .unwrap_or(0)
                .min(crate::service_local_history_protocol::INTENT_MS),
            )
        } else if !r.claimed && stop.as_ref().ok().is_some_and(|s| s.is_none()) {
            (p::Phase::Queued, Settlement::Pending, p::Reason::None, 0)
        } else {
            (
                p::Phase::Preparing,
                Settlement::Pending,
                stop.ok().flatten().map_or(p::Reason::None, |(r, _)| r),
                0,
            )
        };
        // A sub-millisecond end cannot issue a zero-duration usable comparison.
        let phase = if phase == p::Phase::Prepared && remaining == 0 {
            p::Phase::Preparing
        } else {
            phase
        };
        let settlement = if phase == p::Phase::Preparing {
            Settlement::Pending
        } else {
            settlement
        };
        let value = p::Status {
            origin: self.input.origin.clone(),
            selection: self.input.selection.clone(),
            revision: r.revision,
            phase,
            settlement,
            reason,
            review: r.review.clone(),
            remaining_ms: remaining,
        };
        value.validate().map_err(|_| Error::StateUnknown)?;
        Ok(value)
    }
}
pub(crate) struct Claim {
    entry: Arc<Entry>,
    returned: bool,
}
impl Claim {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn returned(mut self) {
        self.entry.caller_returned();
        self.returned = true;
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown(p::Reason::CleanupUnknown);
        }
    }
}
pub(crate) struct History {
    entry: Arc<Entry>,
    pub(crate) data: HistoryData,
    pub(crate) first: bool,
    returned: bool,
}
impl History {
    pub(crate) fn returned(mut self, result: Result<(), Error>) -> Result<(), Error> {
        self.returned = true;
        if result.is_err() {
            self.entry.unknown(p::Reason::HistoryUnavailable);
            return result;
        }
        let mut r = self.entry.lock()?;
        if r.history_claim.as_ref() != Some(&self.data) {
            drop(r);
            self.entry.unknown(p::Reason::HistoryUnavailable);
            return Err(Error::StateUnknown);
        }
        r.history_acked = self.data.revision;
        r.history_started = true;
        r.history_claim = None;
        let version = r.history_version;
        self.entry.bump(&mut r)?;
        r.history_version = version;
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
    pub(crate) fn prepare_history(
        &self,
        input: p::Request,
        scope: Scope,
        submitted: Instant,
    ) -> Result<p::Status, Error> {
        input.validate()?;
        if !scope.bounded() || input.origin.project_id != scope.saved.project_id {
            return Err(Error::Conflict);
        }
        let end = submitted
            .checked_add(Duration::from_millis(
                crate::service_local_history_protocol::INTENT_MS,
            ))
            .ok_or(Error::StateUnknown)?
            .min(scope.read.end());
        if Instant::now() >= end || scope.read.stop(Instant::now())?.is_some() {
            return Err(Error::AccessDenied);
        }
        let mut b = self.lock()?;
        if b.closed || input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(old) = b
            .entries
            .iter()
            .find(|e| e.origin().request_id == input.origin.request_id)
        {
            return match old.history_preparation() {
                Some(e) if e.input == input => e.status(),
                _ => Err(Error::Conflict),
            };
        }
        if b.entries.len() >= super::super::p::REQUEST_LIMIT
            || b.entries.iter().any(StoredEntry::pending)
            || b.history.as_ref().is_some_and(Allowed::occupied)
            || b.preparation.as_ref().is_some_and(|l| l.scope.occupied())
            || b.lease.as_ref().is_some_and(|l| {
                !l.scope.retired.load(std::sync::atomic::Ordering::Acquire)
                    || l.scope.control.first().is_err()
            })
        {
            return Err(Error::Busy);
        }
        let entry = Arc::new(Entry {
            input,
            scope,
            control: Control::new(),
            submitted,
            end,
            row: Mutex::new(Row {
                revision: 1,
                claimed: false,
                caller_returned: false,
                review: None,
                witness: Weak::new(),
                expires: end,
                ended: None,
                handoff: Handoff::Waiting,
                history_acked: 0,
                history_version: 1,
                history_started: false,
                history_claim: None,
                unknown: None,
            }),
        });
        b.entries
            .push(StoredEntry::LocalHistoryPreparation(entry.clone()));
        b.history = Some(Allowed::Preparation(entry.clone()));
        entry.status()
    }
    pub(crate) fn history_preparation(&self, q: &p::Query) -> Result<Arc<Entry>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        b.entries
            .iter()
            .find(|e| e.origin() == q)
            .and_then(StoredEntry::history_preparation)
            .cloned()
            .ok_or(Error::Conflict)
    }
    pub(crate) fn is_history_preparation(&self, q: &p::Query) -> Result<bool, Error> {
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        b.entries
            .iter()
            .find(|e| e.origin() == q)
            .map(|e| e.history_preparation().is_some())
            .ok_or(Error::Conflict)
    }
    pub(crate) fn selected_history_preparation(
        &self,
        q: Option<&p::Query>,
    ) -> Result<Option<Arc<Entry>>, Error> {
        if let Some(q) = q {
            return self.history_preparation(q).map(Some);
        }
        let b = self.lock()?;
        if b.closed {
            return Err(Error::Unavailable);
        }
        Ok(match &b.history {
            Some(Allowed::Preparation(e)) => Some(e.clone()),
            _ => None,
        })
    }
    pub(crate) fn history_preparations(&self) -> Result<Vec<Arc<Entry>>, Error> {
        Ok(self
            .lock()?
            .entries
            .iter()
            .filter_map(StoredEntry::history_preparation)
            .cloned()
            .collect())
    }
    pub(crate) fn claim_history_preparation(&self) -> Result<Option<Claim>, Error> {
        let b = self.lock()?;
        if b.closed {
            return Ok(None);
        }
        for e in b
            .entries
            .iter()
            .filter_map(StoredEntry::history_preparation)
        {
            let mut r = e.lock()?;
            if !r.claimed && r.unknown.is_none() {
                r.claimed = true;
                e.bump(&mut r)?;
                return Ok(Some(Claim {
                    entry: e.clone(),
                    returned: false,
                }));
            }
        }
        Ok(None)
    }
}
/// Exact only. At the initial can-Allow cut it is Waiting; the actual native
/// install reserves Installing before the Book replaces this one lease.
pub(super) fn excludes(b: &Book, e: &Arc<Entry>, installing: bool) -> bool {
    matches!(&b.history,Some(Allowed::Preparation(old)) if Arc::ptr_eq(old,e))
        && if installing {
            e.installing()
        } else {
            e.ready()
        }
}
fn cell_quote(entry: usize, allowed: usize, read: usize) -> Option<usize> {
    let n = entry
        .checked_add(allowed)?
        .checked_add(4096 + 64 + 36 + 3 * 32 + 512)?
        .checked_add(2usize.checked_mul(read)?)?;
    (n <= 8192).then_some(n)
}

pub(crate) fn cell_backing() -> Option<usize> {
    cell_quote(
        std::mem::size_of::<Entry>(),
        std::mem::size_of::<Allowed>(),
        std::mem::size_of::<ReadPermission>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_protocol::Id;
    fn id(n: u32) -> Id {
        Id::parse(&format!("{n:032x}")).unwrap()
    }
    fn input(n: u32) -> p::Request {
        p::Request {
            origin: p::Query {
                project_id: id(1),
                service_instance: id(2),
                request_id: id(n),
            },
            selection: p::Selection {
                kind: p::Kind::Verify,
                platform: None,
                candidate_operation_id: None,
                stage_operation_id: None,
            },
        }
    }
    fn scope(read: Arc<ReadPermission>) -> Scope {
        Scope {
            saved: SavedPoint {
                project_id: id(1),
                runtime_id: "p1".into(),
                root: "/inert/never-opened-history-preparation".into(),
                device: 1,
                inode: 2,
                revision: 0,
                fresh: false,
            },
            read,
        }
    }
    fn review() -> p::Review {
        p::Review {
            kind: p::Kind::Verify,
            platform: None,
            candidate_operation_id: None,
            stage_operation_id: None,
            operation_id: id(10),
            owner_generation: id(11),
            status_revision: 3,
        }
    }
    fn fixture() -> (Inbox, Arc<Entry>, Arc<ReadPermission>) {
        let inbox = Inbox::new(id(2));
        let read = Arc::new(ReadPermission::new(
            Instant::now() + Duration::from_secs(1000),
        ));
        inbox
            .prepare_history(input(5), scope(read.clone()), Instant::now())
            .unwrap();
        let entry = inbox.history_preparation(&input(5).origin).unwrap();
        (inbox, entry, read)
    }
    fn installed(inbox: &Inbox, e: &Arc<Entry>) -> (Claim, Arc<()>) {
        let claim = inbox.claim_history_preparation().unwrap().unwrap();
        let witness = Arc::new(());
        // Inert DATA at the same production fact cuts; not a native receipt.
        e.constructed(review(), e.end, Arc::downgrade(&witness))
            .unwrap();
        (claim, witness)
    }
    #[test]
    fn original_prepare_caller_and_history_ack_are_both_required_before_ready() {
        let (inbox, e, _read) = fixture();
        assert_eq!(e.status().unwrap().phase, p::Phase::Queued);
        let (claim, _witness) = installed(&inbox, &e);
        assert_eq!(e.status().unwrap().phase, p::Phase::Preparing);
        assert!(!e.ready());
        assert!(e.claim_history().unwrap().is_none());
        claim.returned();
        let pending = e.status().unwrap();
        let history = e.claim_history().unwrap().unwrap();
        assert!(!e.ready());
        assert!(e.pending());
        assert!(inbox.can_allow_history_from(Some(&e)).is_err());
        history.returned(Ok(())).unwrap();
        let ready = e.status().unwrap();
        assert!(e.ready() && e.pending());
        assert_eq!(ready.phase, p::Phase::Prepared);
        assert!(ready.revision > pending.revision);
        assert!(inbox.can_allow_history_from(Some(&e)).is_ok());
        assert!(inbox.can_allow_history().is_err());
        assert!(inbox.can_allow().is_err());
        assert!(inbox.claim_history_preparation().unwrap().is_none());
        let again = inbox
            .prepare_history(input(5), scope(e.scope.read.clone()), Instant::now())
            .unwrap();
        assert_eq!(again.origin, *e.origin());
        assert!(inbox.claim_history_preparation().unwrap().is_none());
    }
    #[test]
    fn lost_prepare_caller_history_or_witness_never_releases_original_or_rearms() {
        for cut in 0..4 {
            let (inbox, e, _read) = fixture();
            let (claim, witness) = installed(&inbox, &e);
            if cut == 0 {
                drop(claim);
            } else {
                claim.returned();
                let h = e.claim_history().unwrap().unwrap();
                if cut == 1 {
                    drop(h);
                } else if cut == 2 {
                    assert!(h.returned(Err(Error::Unavailable)).is_err());
                } else {
                    h.returned(Ok(())).unwrap();
                    drop(witness);
                }
            }
            assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
            assert!(e.pending());
            assert!(!e.ready());
            assert!(inbox.can_allow_history_from(Some(&e)).is_err());
            assert!(inbox.can_allow().is_err());
            e.retired(p::Reason::UserCancelled);
            assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
        }
    }
    #[test]
    fn read_context_is_original_configless_and_first_stop_is_never_renewed() {
        let (inbox, e, read) = fixture();
        assert!(!e.scope.saved.fresh && e.scope.saved.revision == 0);
        let same = scope(read.clone());
        assert!(e.scope.matches(&same.saved, &read));
        let different = Arc::new(ReadPermission::new(read.end()));
        assert!(!e.scope.matches(&same.saved, &different));
        let mut changed = scope(read.clone());
        changed.saved.root.push("other");
        assert!(!e.scope.matches(&changed.saved, &read));
        let first = Instant::now();
        read.revoke(first);
        e.cancel(p::Reason::UserCancelled, first + Duration::from_secs(1));
        assert_eq!(
            e.stop_at(first + Duration::from_secs(2)),
            Some((p::Reason::PermissionRevoked, first))
        );
        let c = inbox.claim_history_preparation().unwrap().unwrap();
        e.refused(p::Reason::PermissionRevoked);
        c.returned();
        assert!(e.pending());
        e.claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        assert_eq!(e.status().unwrap().phase, p::Phase::Cancelled);
        assert!(!e.pending());
    }
    #[test]
    fn exact_preparation_to_start_handoff_and_late_old_cancel_keep_same_joint_book() {
        let (inbox, e, read) = fixture();
        let (c, witness) = installed(&inbox, &e);
        c.returned();
        e.claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        let document = Arc::new(());
        let start = Arc::new(super::super::Scope {
            preparation: Some(Arc::downgrade(&e)),
            project_id: id(1),
            runtime_id: "p1".into(),
            review_id: id(4),
            review: review(),
            root: e.scope.saved.root.clone(),
            device: 1,
            inode: 2,
            observation_revision: 0,
            expires: e.end,
            read,
            document: Arc::downgrade(&document),
            witness: Arc::downgrade(&witness),
            control: Control::new(),
            retired: std::sync::atomic::AtomicBool::new(false),
            changes: tokio::sync::watch::channel(0).0,
        });
        // The ordinary Book install cannot skip the actual native handoff cut.
        assert!(inbox.allow_history(start.clone(), id(3)).is_err());
        inbox.can_allow_history_from(Some(&e)).unwrap();
        e.begin_handoff(&review()).unwrap();
        assert!(inbox.can_allow_history_from(Some(&e)).is_err());
        inbox.allow_history(start.clone(), id(3)).unwrap();
        assert_eq!(e.status().unwrap().phase, p::Phase::HandedOff);
        assert!(!e.pending());
        e.cancel(p::Reason::UserCancelled, Instant::now());
        assert_eq!(start.control.first().unwrap(), None);
        let submit = crate::service_local_history_protocol::Submit {
            origin: input(6).origin,
            grant_id: id(3),
            review_id: id(4),
        };
        inbox
            .submit_history(submit.clone(), Instant::now())
            .unwrap();
        assert_eq!(inbox.history_entries().unwrap().len(), 1);
        assert_eq!(inbox.history_preparations().unwrap().len(), 1);
        assert!(inbox.can_allow_history().is_err());
        assert!(inbox.can_allow_history_from(Some(&e)).is_err());
        let actual = inbox.claim_local_history().unwrap().unwrap();
        let original = actual.entry().clone();
        e.cancel(p::Reason::UserCancelled, Instant::now());
        assert_eq!(original.scope().control.first().unwrap(), None);
        drop(actual);
        assert!(original.pending());
        assert_eq!(
            original.status().unwrap().state,
            crate::service_local_history_protocol::State::Unknown
        );
    }
    #[test]
    fn cancelled_original_exact_lookup_survives_later_row_without_fallback() {
        let (inbox, e, read) = fixture();
        let c = inbox.claim_history_preparation().unwrap().unwrap();
        e.refused(p::Reason::NativeRefused);
        c.returned();
        e.claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        inbox
            .prepare_history(input(6), scope(read.clone()), Instant::now())
            .unwrap();
        assert_eq!(
            inbox
                .selected_history_preparation(None)
                .unwrap()
                .unwrap()
                .origin(),
            &input(6).origin
        );
        assert!(Arc::ptr_eq(
            &inbox
                .selected_history_preparation(Some(e.origin()))
                .unwrap()
                .unwrap(),
            &e
        ));
        let mut wrong = e.origin().clone();
        wrong.project_id = id(9);
        assert!(inbox.selected_history_preparation(Some(&wrong)).is_err());
        assert_eq!(e.status().unwrap().phase, p::Phase::Refused);
        let mut collision = input(5);
        collision.selection.kind = p::Kind::Enroll;
        assert!(inbox
            .prepare_history(collision, scope(read), Instant::now())
            .is_err());
        assert!(inbox
            .submit_history(
                crate::service_local_history_protocol::Submit {
                    origin: e.origin().clone(),
                    grant_id: id(3),
                    review_id: id(4)
                },
                Instant::now()
            )
            .is_err());
    }
    #[test]
    fn original_preparation_cells_use_real_types_and_checked_existing_row_budget() {
        assert!(cell_backing().is_some());
        let sizes = [
            std::mem::size_of::<Entry>(),
            std::mem::size_of::<Allowed>(),
            std::mem::size_of::<ReadPermission>(),
        ];
        for i in 0..3 {
            let mut bad = sizes;
            bad[i] = usize::MAX;
            assert!(cell_quote(bad[0], bad[1], bad[2]).is_none());
        }
        assert!(cell_quote(8192, sizes[1], sizes[2]).is_none());
        assert_eq!(
            super::super::retained_document_backing(),
            Some(2 * 1024 * 1024)
        );
        let (inbox, e, _read) = fixture();
        let (c, _witness) = installed(&inbox, &e);
        c.returned();
        e.claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        let s = e.status().unwrap();
        let comparison = p::Comparison {
            runtime_project_id: "p1".into(),
            request: s,
            live: Some(review()),
        };
        comparison.validate().unwrap();
        assert!(serde_json::to_vec(&comparison).unwrap().len() < p::COMPARISON_BYTES);
    }
}
