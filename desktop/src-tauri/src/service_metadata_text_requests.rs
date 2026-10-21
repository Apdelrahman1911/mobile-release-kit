//! One closed row kind in the ORIGINAL Configuration Inbox. No native execution
//! or second queue lives here. Payload is retained only by the one active row;
//! joined terminal rows retain IDs/digests/scalar results, not full text copies.
pub(crate) use crate::service_configuration_requests::Source;
use crate::{
    service_metadata_text_protocol as p,
    service_protocol::{Error, Id},
    service_version_reserve_requests::ReadPermission,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::{Duration, Instant},
};
pub(crate) const ROW_BACKING: usize =
    32 * (std::mem::size_of::<Entry>() + std::mem::size_of::<Row>() + 8192);
// ONE active observation/proposal plus relay and native conversion copies. The
// same8 socket callers' small inputs plus one admitted Metadata exchange are
// separately charged by IPC_BACKING; no worker duplication or old debit credit.
pub(crate) const ACTIVE_BACKING: usize = 4 * p::TYPED_INPUT_BYTES + 4 * p::READ_BYTES;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const IPC_CONTROL_BACKING: usize = crate::installed_cli_ipc::METADATA_CONTROL_BACKING;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const IPC_CONTROL_BACKING: usize = 0; // No installed IPC Endpoint on these targets.
pub(crate) const DOCUMENT_BACKING: usize = ROW_BACKING + ACTIVE_BACKING + p::IPC_BACKING + IPC_CONTROL_BACKING;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Read,
    Open,
    Prepare,
    Apply,
}
impl Kind {
    fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Open => 1,
            Self::Prepare => 2,
            Self::Apply => 3,
        }
    }
}
struct Row {
    status: p::Status,
    dispatch: Option<Kind>,
    calls: [u8; 4],
    load: Option<Arc<p::Observation>>,
    proposal: Option<Arc<p::Fields>>,
    read_claimed: bool,
    read_retired: bool,
    read_good: bool,
    claimed: bool,
    retired: bool,
    native_result: Option<p::Final>,
    binding: Option<(Id, Id, Weak<()>)>,
    apply: Option<p::Apply>,
    permission_end: Option<Instant>,
    permission_off: bool,
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
    r: &mut Row,
    changes: &tokio::sync::watch::Sender<u32>,
    failed: &AtomicBool,
) -> Result<(), Error> {
    r.status.revision = r.status.revision.checked_add(1).ok_or_else(|| {
        failed.store(true, Ordering::Release);
        Error::StateUnknown
    })?;
    let mut good = true;
    changes.send_modify(|n| {
        if let Some(next) = n.checked_add(1) {
            *n = next
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
    pub(crate) fn new(
        input: p::Read,
        source: Source,
        read: Arc<ReadPermission>,
        failed: Arc<AtomicBool>,
        changes: tokio::sync::watch::Sender<u32>,
    ) -> Result<Self, Error> {
        input.validate()?;
        let status = p::Status {
            schema_version: 1,
            origin: input.origin.clone(),
            revision: 1,
            runtime_project_id: source.runtime_id.clone(),
            platform: input.platform,
            locale: input.locale.clone(),
            phase: p::Phase::QueuedRead,
            observation: None,
            original: None,
            proposal_sha256: None,
            review: None,
            permission_live: false,
            remaining_ms: 0,
            apply_consumed: false,
            cancel_requested: false,
            result: None,
            do_not_replay: true,
        };
        status.validate()?;
        Ok(Self {
            input,
            source,
            read,
            failed,
            changes,
            row: Mutex::new(Row {
                status,
                dispatch: None,
                calls: [0; 4],
                load: None,
                proposal: None,
                read_claimed: false,
                read_retired: false,
                read_good: false,
                claimed: false,
                retired: false,
                native_result: None,
                binding: None,
                apply: None,
                permission_end: None,
                permission_off: false,
                apply_end: None,
                apply_entered: false,
                stop: None,
                history_claimed: false,
            }),
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, Row>, Error> {
        self.row.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    pub(crate) fn input(&self) -> &p::Read {
        &self.input
    }
    fn live_locked(&self, r: &Row, now: Instant) -> Result<bool, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        Ok(r.stop.is_none()
            && self.read.stop(now)?.is_none()
            && !r.retired
            && r.status.phase != p::Phase::Unknown)
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Result<Option<Instant>, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        let stop = self.read.stop(now)?.map(|(_, at)| at);
        let r = self.lock()?;
        Ok([
            stop,
            r.stop,
            r.apply_end.filter(|end| !r.apply_entered && now >= *end),
        ]
        .into_iter()
        .flatten()
        .min())
    }
    pub(crate) fn live(&self, now: Instant) -> bool {
        self.stop_at(now).is_ok_and(|s| s.is_none())
    }
    fn finish_locked(&self, r: &mut Row) {
        let returned = r.calls.iter().all(|n| *n != 1);
        if !returned || r.status.phase == p::Phase::Unknown {
            return;
        }
        if r.retired {
            r.status.phase = if r.native_result.is_some() {
                p::Phase::Final
            } else {
                p::Phase::Unknown
            };
            r.status.result = r.native_result.clone();
            r.load = None;
            r.proposal = None;
            r.permission_end = None;
        } else if r.read_retired && !r.claimed {
            if r.read_good && r.stop.is_none() && r.status.proposal_sha256.is_none() {
                r.status.phase = p::Phase::Loaded;
            } else if !r.read_good || r.stop.is_some() {
                r.status.phase = p::Phase::Refused;
                r.load = None;
                r.proposal = None;
            }
        } else if !r.read_claimed && !r.claimed && r.stop.is_some() {
            r.status.phase = p::Phase::Refused;
            r.load = None;
            r.proposal = None;
        }
    }
    pub(crate) fn cancel(&self, at: Instant) -> Result<(), Error> {
        let mut r = self.lock()?;
        if matches!(r.status.phase, p::Phase::Final | p::Phase::Refused) {
            return Ok(());
        }
        r.stop = Some(r.stop.map_or(at, |old| old.min(at)));
        r.status.cancel_requested = true;
        r.permission_end = None;
        r.permission_off = true;
        if r.status.phase != p::Phase::Unknown {
            r.status.phase = p::Phase::Stopping;
        }
        self.finish_locked(&mut r);
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn unknown(&self) {
        if let Ok(mut r) = self.row.lock() {
            r.status.phase = p::Phase::Unknown;
            r.status.result = None;
            r.permission_end = None;
            r.stop.get_or_insert_with(Instant::now);
            let _ = bump(&mut r, &self.changes, &self.failed);
        } else {
            self.failed.store(true, Ordering::Release)
        }
    }
    pub(crate) fn status(&self) -> Result<p::Status, Error> {
        let now = Instant::now();
        if let Some(at) = self.stop_at(now)? {
            if !self.lock()?.status.cancel_requested {
                self.cancel(at)?
            }
        }
        let r = self.lock()?;
        let mut s = r.status.clone();
        if s.phase == p::Phase::Loaded && r.stop.is_none() {
            s.observation = r.load.as_ref().map(|o| (**o).clone());
        }
        s.remaining_ms = r
            .permission_end
            .filter(|_| s.phase == p::Phase::Reviewing && !s.apply_consumed && !s.cancel_requested)
            .map_or(0, |e| {
                e.saturating_duration_since(now)
                    .as_millis()
                    .min(p::REVIEW_MS as u128) as u64
            });
        s.permission_live = s.remaining_ms > 0;
        s.validate()?;
        Ok(s)
    }
    pub(crate) fn occupied(&self) -> Result<bool, Error> {
        let r = self.lock()?;
        Ok(!matches!(r.status.phase, p::Phase::Final | p::Phase::Refused) || r.calls.contains(&1))
    }
    pub(crate) fn prepare(&self, input: p::Prepare) -> Result<p::Status, Error> {
        input.validate()?;
        let digest = input.proposal.digest()?;
        {
            let mut r = self.lock()?;
            if let Some(old) = &r.status.proposal_sha256 {
                if old != &digest || input.origin != self.input.origin {
                    return Err(Error::Conflict);
                }
                drop(r);
                return self.status();
            }
            if input.origin != self.input.origin
                || input.proposal.platform != self.input.platform
                || !self.live_locked(&r, Instant::now())?
                || r.status.phase != p::Phase::Loaded
                || !r.read_retired
                || r.calls[0] != 2
            {
                return Err(Error::Conflict);
            }
            r.proposal = Some(Arc::new(input.proposal));
            r.status.proposal_sha256 = Some(digest);
            r.status.phase = p::Phase::QueuedPrepare;
            bump(&mut r, &self.changes, &self.failed)?;
        }
        self.status()
    }
    pub(crate) fn apply(&self, input: p::Apply) -> Result<p::Status, Error> {
        {
            let mut r = self.lock()?;
            if let Some(old) = &r.apply {
                if old != &input {
                    return Err(Error::Conflict);
                }
                drop(r);
                return self.status();
            }
            let now = Instant::now();
            if !input.reviewed
                || input.origin != self.input.origin
                || !self.live_locked(&r, now)?
                || r.status.phase != p::Phase::Reviewing
                || r.status.original.as_ref() != Some(&input.original)
                || !r
                    .status
                    .review
                    .as_ref()
                    .is_some_and(|p| p.plan_token == input.plan_token)
                || r.status.apply_consumed
                || !r.permission_end.is_some_and(|end| now < end)
                || r.calls.contains(&1)
            {
                return Err(Error::AccessDenied);
            }
            r.apply = Some(input);
            r.status.apply_consumed = true;
            r.apply_end = r.permission_end.take();
            r.status.phase = p::Phase::QueuedApply;
            bump(&mut r, &self.changes, &self.failed)?;
        }
        self.status()
    }
    pub(crate) fn allow(&self, input: &p::Allow, end: Instant) -> Result<p::Status, Error> {
        {
            let mut r = self.lock()?;
            let now = Instant::now();
            if input.consent_version != p::CONSENT
                || input.origin != self.input.origin
                || r.status.original.as_ref() != Some(&input.original)
                || r.status.phase != p::Phase::Reviewing
                || !r.status.review.as_ref().is_some_and(|p| {
                    p.plan_token == input.plan_token
                        && p.native_status_revision == input.expected_native_status_revision
                })
                || r.permission_off
                || r.status.apply_consumed
                || r.calls.contains(&1)
                || !self.live_locked(&r, now)?
            {
                return Err(Error::Conflict);
            }
            if r.permission_end.is_none() {
                let e = end.min(self.read.end());
                if e <= now
                    || e.saturating_duration_since(now) > Duration::from_millis(p::REVIEW_MS)
                {
                    return Err(Error::Expired);
                }
                r.permission_end = Some(e);
                bump(&mut r, &self.changes, &self.failed)?;
            }
        }
        self.status()
    }
    fn queued_locked(r: &Row, kind: Kind) -> bool {
        match kind {
            Kind::Read => r.status.phase == p::Phase::QueuedRead,
            Kind::Open => r.status.phase == p::Phase::QueuedPrepare,
            Kind::Prepare => r.status.phase == p::Phase::Opened,
            Kind::Apply => r.status.phase == p::Phase::QueuedApply,
        }
    }
    pub(crate) fn queued(&self, k: Kind) -> Result<bool, Error> {
        let r = self.lock()?;
        Ok(Self::queued_locked(&r, k))
    }
    pub(crate) fn dispatch(&self, k: Kind) -> Result<bool, Error> {
        let mut r = self.lock()?;
        if !Self::queued_locked(&r, k) {
            return Ok(false);
        }
        if !self.live_locked(&r, Instant::now())?
            || r.dispatch.is_some()
            || r.calls.contains(&1)
            || r.calls[k.index()] != 0
        {
            return Err(Error::Conflict);
        }
        r.dispatch = Some(k);
        r.calls[k.index()] = 1;
        r.status.phase = match k {
            Kind::Read => p::Phase::Reading,
            Kind::Open => p::Phase::Opening,
            Kind::Prepare => p::Phase::Preparing,
            Kind::Apply => p::Phase::Applying,
        };
        bump(&mut r, &self.changes, &self.failed)?;
        Ok(true)
    }
    pub(crate) fn admitting(&self, k: Kind) -> bool {
        self.live(Instant::now())
            && self
                .lock()
                .is_ok_and(|r| r.dispatch == Some(k) && r.calls[k.index()] == 1 && !r.retired)
    }
    pub(crate) fn caller(self: &Arc<Self>, k: Kind) -> Result<Call, Error> {
        if !self.lock()?.dispatch.is_some_and(|d| d == k) {
            return Err(Error::Conflict);
        }
        Ok(Call {
            entry: self.clone(),
            kind: k,
            returned: false,
        })
    }
    pub(crate) fn read_claim(&self) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.read_claimed
            || r.dispatch != Some(Kind::Read)
            || !self.live_locked(&r, Instant::now())?
        {
            return Err(Error::Conflict);
        }
        r.read_claimed = true;
        r.dispatch = None;
        Ok(())
    }
    /// Called ONLY by the SAME passive Owner's retirement after all joins.
    pub(crate) fn read_retired(
        &self,
        result: Result<p::Observation, Error>,
        unknown: bool,
    ) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.read_claimed || r.read_retired {
            return Err(Error::Conflict);
        }
        r.read_retired = true;
        if unknown {
            r.status.phase = p::Phase::Unknown;
            r.stop.get_or_insert_with(Instant::now);
        } else if let Ok(o) = result {
            o.validate()?;
            if o.platform != self.input.platform || o.locale != self.input.locale {
                return Err(Error::Conflict);
            }
            r.load = Some(Arc::new(o));
            r.read_good = true;
        }
        self.finish_locked(&mut r);
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn load(&self) -> Result<Arc<p::Observation>, Error> {
        let r = self.lock()?;
        if !r.read_retired || r.calls[0] != 2 || !self.live_locked(&r, Instant::now())? {
            return Err(Error::Conflict);
        }
        r.load.clone().ok_or(Error::Conflict)
    }
    pub(crate) fn proposal(&self) -> Result<Arc<p::Fields>, Error> {
        self.lock()?.proposal.clone().ok_or(Error::Conflict)
    }
    pub(crate) fn claim_open(&self) -> Result<(), Error> {
        let mut r = self.lock()?;
        if r.claimed
            || r.dispatch != Some(Kind::Open)
            || !r.read_retired
            || r.calls[0] != 2
            || !self.live_locked(&r, Instant::now())?
        {
            return Err(Error::Conflict);
        }
        r.claimed = true;
        Ok(())
    }
    pub(crate) fn bind(&self, s: Id, g: Id, marker: Weak<()>) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed
            || r.binding.is_some()
            || r.dispatch != Some(Kind::Open)
            || marker.strong_count() == 0
        {
            return Err(Error::Conflict);
        }
        r.binding = Some((s, g, marker));
        r.dispatch = None;
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn bound(&self, s: &str, g: &str) -> bool {
        self.lock().is_ok_and(|r| {
            r.binding.as_ref().is_some_and(|(id, gen, m)| {
                id.as_str() == s && gen.as_str() == g && m.strong_count() > 0
            })
        })
    }
    pub(crate) fn consume(&self, k: Kind) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !matches!(k, Kind::Prepare | Kind::Apply)
            || r.dispatch != Some(k)
            || !self.live_locked(&r, Instant::now())?
        {
            return Err(Error::Conflict);
        }
        if k == Kind::Apply {
            if !r.apply_end.is_some_and(|e| Instant::now() < e) {
                return Err(Error::Expired);
            }
            r.apply_entered = true;
        }
        r.dispatch = None;
        Ok(())
    }
    pub(crate) fn opened(&self, o: p::Original) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r
            .binding
            .as_ref()
            .is_some_and(|(s, g, _)| s == &o.session_id && g == &o.owner_generation)
        {
            return Err(Error::Conflict);
        }
        if let Some(old) = &r.status.original {
            if old != &o {
                return Err(Error::StateUnknown);
            }
            return Ok(());
        }
        r.status.original = Some(o);
        if r.status.phase == p::Phase::Opening {
            r.status.phase = p::Phase::Opened;
        }
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn prepared(&self, review: p::Review) -> Result<(), Error> {
        review.validate(self.input.platform)?;
        let mut r = self.lock()?;
        if let Some(old) = &r.status.review {
            let mut compare = review;
            compare.native_status_revision = old.native_status_revision;
            if &compare != old {
                return Err(Error::StateUnknown);
            }
            return Ok(());
        }
        if r.status.phase != p::Phase::Preparing
            || r.status.proposal_sha256.as_ref() != Some(&review.proposal_sha256)
        {
            return Err(Error::Conflict);
        }
        r.status.review = Some(review);
        r.status.phase = p::Phase::Reviewing;
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn original(&self) -> Result<p::Original, Error> {
        self.lock()?.status.original.clone().ok_or(Error::Conflict)
    }
    pub(crate) fn review(&self) -> Result<p::Review, Error> {
        self.lock()?.status.review.clone().ok_or(Error::Conflict)
    }
    pub(crate) fn retired(&self, result: Option<p::Final>) -> Result<(), Error> {
        let mut r = self.lock()?;
        if !r.claimed || r.retired {
            return Err(Error::Conflict);
        }
        r.retired = true;
        r.native_result = result;
        if r.native_result.is_none() {
            r.status.phase = p::Phase::Unknown;
        }
        self.finish_locked(&mut r);
        bump(&mut r, &self.changes, &self.failed)
    }
    pub(crate) fn dispatch_failed(&self) {
        if let Ok(mut r) = self.lock() {
            if matches!(r.status.phase, p::Phase::Final | p::Phase::Unknown) {
                return;
            }
            r.dispatch = None;
            r.permission_end = None;
            r.stop.get_or_insert_with(Instant::now);
            if r.claimed || (r.read_claimed && !r.read_retired) {
                r.status.phase = p::Phase::Unknown
            } else {
                r.status.phase = p::Phase::Refused
            }
            let _ = bump(&mut r, &self.changes, &self.failed);
        }
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
        } else if r.status.phase == p::Phase::Final {
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
        if let Some((s, f)) = outcome {
            r.history_claimed = true;
            Ok(Some((id, s, f)))
        } else {
            Ok(None)
        }
    }
}
/// Retains the actual one admitted RAW continuation, not a DTO/renderer ACK.
/// Abandonment cannot create a return or free payload/another queue slot.
pub(crate) struct Call {
    entry: Arc<Entry>,
    kind: Kind,
    returned: bool,
}
impl Call {
    pub(crate) fn returned(mut self) -> Result<(), Error> {
        let mut r = self.entry.lock()?;
        if r.calls[self.kind.index()] != 1 {
            return Err(Error::StateUnknown);
        }
        r.calls[self.kind.index()] = 2;
        self.entry.finish_locked(&mut r);
        bump(&mut r, &self.entry.changes, &self.entry.failed)?;
        drop(r);
        self.returned = true;
        Ok(())
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unknown()
        }
    }
}

#[cfg(test)]
#[path = "service_metadata_text_requests_tests.rs"]
mod tests;
