//! Fixed non-mutating key-identity lookup, owned by asset_session::OriginalWork.
//!
//! No renderer/session command calls this phase. Endpoint/provider qualification,
//! and native qualification remain OFF. Only this private entry selects the
//! closed bounded wire profile; the legacy SDK fixtures are separate. Local
//! finality requires the maintained SDK's consumed original task/resource result;
//! a lookup, RemoveMatch or coordinator return alone is never a task join.

use std::{os::unix::ffi::OsStrExt, path::{Component, Path, PathBuf}, pin::Pin,
    sync::Arc, task::{Context, Poll}, time::Instant};
#[cfg(test)]
use std::future::Future;
use ordered_stream::{OrderedStream, PollResult};
use secret_service::checked_lookup;
use zbus::{connection::{LocalSettlement, OwnedConnectionAttempt},
    message::Type, names::UniqueName, zvariant::OwnedObjectPath,
    MatchRule, Message};

const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const SERVICE: &str = "org.freedesktop.secrets";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Problem {
    InvalidInput, Unavailable, InvalidReply, IdentityMismatch, OwnerChanged,
    StreamFailed, Interrupted, CleanupUnknown, Capacity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step { AddMatch, GetNameOwner, SearchItems, Attributes, RemoveMatch }
impl Step { pub(crate) fn cleanup(self) -> bool { self == Self::RemoveMatch } }
pub(crate) enum Next { Admit(Step), FirstPoll, AdmitShutdown, FirstPollShutdown, Settled }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Unstarted, Connecting, Admit(Step), Calling(Step), Holding }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Registration { Unsent, Possible, Registered, Removed, Unknown }

struct Query {
    collection: OwnedObjectPath, vault_id: Box<str>, generation_id: Box<str>,
}
impl Query {
    fn attributes(&self) -> [(&str, &str); 4] {
        [("application", "dev.mobile-release-kit.desktop"), ("purpose", "vault-wrapping-key-v1"),
            ("vault-id", &self.vault_id), ("generation-id", &self.generation_id)]
    }
}

/// Mechanical bounded backend input only, NOT endpoint/peer/provider admission.
/// A later reviewed profile must supply these reserved identities; no persistent
/// ID encoding or durable reservation is invented here.
pub(crate) struct LookupInput { endpoint: PathBuf, query: Arc<Query>, rule: Arc<MatchRule<'static>> }
impl LookupInput {
    pub(crate) fn new(endpoint: &Path, collection: &str, vault_id: &str, generation_id: &str) -> Result<Self, Problem> {
        let bytes = endpoint.as_os_str().as_bytes();
        if !endpoint.is_absolute() || bytes.is_empty() || bytes.len() > 107 || bytes.contains(&0)
            || endpoint.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            || collection == "/" || collection.len() > 512
            || [vault_id, generation_id].iter().any(|value| value.is_empty() || value.len() > 256 || value.contains('\0'))
        { return Err(Problem::InvalidInput); }
        let collection = OwnedObjectPath::try_from(collection.to_owned()).map_err(|_| Problem::InvalidInput)?;
        let rule = MatchRule::builder().msg_type(Type::Signal).sender(BUS).map_err(|_| Problem::InvalidInput)?
            .interface(BUS).map_err(|_| Problem::InvalidInput)?.path(BUS_PATH).map_err(|_| Problem::InvalidInput)?
            .member("NameOwnerChanged").map_err(|_| Problem::InvalidInput)?.arg(0, SERVICE).map_err(|_| Problem::InvalidInput)?.build();
        Ok(Self { endpoint: endpoint.to_path_buf(),
            query: Arc::new(Query { collection, vault_id: vault_id.into(), generation_id: generation_id.into() }), rule: Arc::new(rule) })
    }
}

#[cfg(test)]
type ConnectFuture = Pin<Box<dyn Future<Output = zbus::Result<()>> + Send>>;
#[cfg(test)]
type RpcFuture = Pin<Box<dyn Future<Output = zbus::Result<Message>> + Send>>;
enum ConnectOriginal { Native, #[cfg(test)] Data(ConnectFuture) }
enum RpcOriginal { Native, #[cfg(test)] Data(RpcFuture) }
enum Pending {
    Connect { future: ConnectOriginal, polled: bool, dispatch_end: Instant },
    Rpc { future: RpcOriginal, polled: bool, dispatch_end: Instant },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shutdown { Unrequested, Staged(Instant), Entered, Settled, Refused }

// Retain non-owning error facts after the actual raw error has been reconciled.
// In particular, a MethodError's Message may own received descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ErrorClass { Io(std::io::ErrorKind, Option<i32>), Remote, Handshake, Protocol, Other }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemovalReply { Confirmed, Failed(ErrorClass) }
fn error_class(error: &zbus::Error) -> ErrorClass {
    match error {
        zbus::Error::InputOutput(error) | zbus::Error::Connection(error, _) => ErrorClass::Io(error.kind(), error.raw_os_error()),
        zbus::Error::MethodError(..) => ErrorClass::Remote,
        zbus::Error::Handshake(_) => ErrorClass::Handshake,
        zbus::Error::InvalidReply | zbus::Error::InvalidField | zbus::Error::ExcessData
            | zbus::Error::MissingField | zbus::Error::InvalidSerial | zbus::Error::Variant(_)
            | zbus::Error::Names(_) => ErrorClass::Protocol,
        _ => ErrorClass::Other,
    }
}

pub(crate) enum Observation { Absent, Candidate(Arc<OwnedObjectPath>) }

pub(crate) struct LookupBook {
    entered: bool, constructor_refused: bool, cleanup_failed_seen: bool, charge: Option<crate::asset_session::KeyringMemoryAdmission>,
    phase: Phase, attempt: Option<OwnedConnectionAttempt>,
    stream_ended: bool, pending: Option<Pending>, first_poll_ready: bool, connect_failure: Option<zbus::Error>,
    raw: Option<zbus::Result<Message>>, raw_pending: bool, removal_reply: Option<RemovalReply>,
    owner: Option<Arc<UniqueName<'static>>>, query: Option<Arc<Query>>, rule: Option<Arc<MatchRule<'static>>>,
    candidate: Option<Arc<OwnedObjectPath>>, observation: Option<Observation>,
    problem: Option<Problem>, problem_at: Option<Instant>, registration: Registration,
    shutdown: Shutdown, shutdown_ready: bool, local_settlement: Option<LocalSettlement>,
    build_error: Option<ErrorClass>, raw_error: Option<ErrorClass>, cleanup_error: Option<ErrorClass>,
}
// App share of the SAME 64KiB whole-attempt control row. The document adds
// its fixed owner/slot/source cells and asserts the combined share <=16KiB.
// Query/path/string heap backing belongs to the separate 32KiB input-copy row.
pub(crate) const LOOKUP_CONTROL_BYTES: usize = std::mem::size_of::<LookupBook>()
    + std::mem::size_of::<LookupInput>() + std::mem::size_of::<Query>() + std::mem::size_of::<Pending>()
    + std::mem::size_of::<MatchRule<'static>>() + std::mem::size_of::<UniqueName<'static>>()
    + std::mem::size_of::<OwnedObjectPath>() + 32 * std::mem::size_of::<usize>();

impl LookupBook {
    pub(crate) fn new() -> Self {
        Self { entered: false, constructor_refused: false, cleanup_failed_seen: false, charge: None, phase: Phase::Unstarted, attempt: None,
            stream_ended: false, pending: None, first_poll_ready: false, connect_failure: None, raw: None, raw_pending: false, removal_reply: None,
            owner: None, query: None, rule: None, candidate: None, observation: None,
            problem: None, problem_at: None, registration: Registration::Unsent,
            shutdown: Shutdown::Unrequested, shutdown_ready: false, local_settlement: None,
            build_error: None, raw_error: None, cleanup_error: None }
    }
    pub(crate) fn resources_settled(&self) -> bool {
        !self.entered || ((self.constructor_refused && self.attempt.is_none()
            || self.shutdown == Shutdown::Settled && self.local_settlement.is_some())
            && self.pending.is_none() && !self.raw_pending && self.raw.is_none() && self.connect_failure.is_none())
    }
    pub(crate) fn memory_held(&self) -> bool { self.charge.is_some() }
    pub(crate) fn allocations_released(&self) -> bool {
        self.charge.is_none() && self.attempt.is_none() && self.pending.is_none() && self.raw.is_none()
            && self.connect_failure.is_none() && self.query.is_none() && self.rule.is_none()
            && self.owner.is_none() && self.candidate.is_none() && self.observation.is_none()
    }
    pub(crate) fn can_begin(&self) -> bool {
        !self.entered && self.phase == Phase::Unstarted && self.problem.is_none() && self.allocations_released()
            && self.shutdown == Shutdown::Unrequested && self.local_settlement.is_none()
    }
    // Called only by the original document's reconciliation after coordinator,
    // child/source and retirement joins/disposal. SDK settlement alone does not
    // refund: even its settled attempt and the query/rule/observation still own
    // backing. Retain the charge if any destructor fails, and all terminal facts
    // after success. This is never a fresh, retryable LookupBook.
    pub(crate) fn dispose_settled_storage(&mut self) -> bool {
        if !self.memory_held() || !self.resources_settled() { return false; }
        self.cleanup_failed_seen |= self.attempt.as_ref().is_some_and(OwnedConnectionAttempt::cleanup_failed);
        drop((self.attempt.take(), self.query.take(), self.rule.take(), self.owner.take(),
            self.candidate.take(), self.observation.take()));
        self.charge.take(); // Exactly once, AFTER actual charged holding disposal.
        true
    }
    pub(crate) fn started(&self) -> bool { self.entered }
    pub(crate) fn problem(&self) -> Option<Problem> { self.problem }
    pub(crate) fn problem_at(&self) -> Option<Instant> { self.problem_at }
    pub(crate) fn cleanup_unknown(&self) -> bool {
        self.cleanup_failed_seen || self.registration == Registration::Unknown || self.local_settlement.is_some_and(|result| !result.clean())
            || self.attempt.as_ref().is_some_and(OwnedConnectionAttempt::cleanup_failed)
    }
    pub(crate) fn observation(&self) -> Option<&Observation> {
        if self.problem.is_none() { self.observation.as_ref() } else { None }
    }
    fn fail(&mut self, problem: Problem) {
        if self.problem.is_none() { self.problem = Some(problem); self.problem_at = Some(Instant::now()); }
    }
    pub(crate) fn interrupt(&mut self) { self.fail(Problem::Interrupted); }

    pub(crate) fn begin(&mut self, input: LookupInput, dispatch_end: Instant,
        charge: crate::asset_session::KeyringMemoryAdmission) -> Result<(), Problem> {
        self.begin_constructed(input, dispatch_end, charge, OwnedConnectionAttempt::keyring_unix)
    }
    fn claim(&mut self, charge: crate::asset_session::KeyringMemoryAdmission) -> Result<(), Problem> {
        // Reject duplicates BEFORE allocating even an unpolled SDK constructor.
        if !self.can_begin() { return Err(Problem::CleanupUnknown); }
        // Permanent before construction/first poll. No cancellation, error,
        // coordinator return or eventual refund restores one-shot entry.
        self.entered = true; self.charge = Some(charge); Ok(())
    }
    fn begin_constructed(&mut self, input: LookupInput, dispatch_end: Instant,
        charge: crate::asset_session::KeyringMemoryAdmission,
        make: impl FnOnce(PathBuf) -> zbus::Result<OwnedConnectionAttempt>) -> Result<(), Problem> {
        self.claim(charge)?;
        let LookupInput { endpoint, query, rule } = input;
        self.query = Some(query); self.rule = Some(rule);
        match make(endpoint) {
            Ok(attempt) => {
                self.attempt = Some(attempt); self.phase = Phase::Connecting;
                self.pending = Some(Pending::Connect { future: ConnectOriginal::Native, polled: false, dispatch_end });
                Ok(())
            }
            Err(error) => {
                // No SDK attempt/task ever existed on THIS constructor refusal.
                // This is distinct from a failed original build future, whose
                // attempt and true shutdown/join roster remain mandatory.
                self.build_error = Some(error_class(&error)); drop(error);
                self.constructor_refused = true; self.phase = Phase::Holding;
                self.fail(Problem::Unavailable); Err(Problem::Unavailable)
            }
        }
    }
    #[cfg(test)]
    fn begin_with(&mut self, query: Arc<Query>, rule: Arc<MatchRule<'static>>, dispatch_end: Instant, future: ConnectFuture) -> Result<(), Problem> {
        self.claim(crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap())?;
        self.query = Some(query); self.rule = Some(rule); self.phase = Phase::Connecting;
        self.pending = Some(Pending::Connect { future: ConnectOriginal::Data(future), polled: false, dispatch_end });
        Ok(())
    }
    pub(crate) fn current_step(&self) -> Option<Step> {
        match self.phase { Phase::Calling(step) => Some(step), _ => None }
    }
    pub(crate) fn expected(&self, step: Step) -> bool {
        self.phase == Phase::Admit(step) && self.pending.is_none() && !self.raw_pending
    }
    pub(crate) fn admit(&mut self, step: Step, dispatch_end: Instant) -> Result<(), Problem> {
        self.admit_original(step, dispatch_end, Self::rpc)
    }
    // Single actual dispatch-registration seam. Tests inject a DATA future here,
    // not an alternate lifecycle model, fake connection or native-test bypass.
    #[cfg(test)]
    fn admit_with(&mut self, step: Step, dispatch_end: Instant, make: impl FnOnce(&Self, Step) -> Result<RpcFuture, Problem>) -> Result<(), Problem> {
        self.admit_original(step, dispatch_end, |book, step| make(book, step).map(RpcOriginal::Data))
    }
    fn admit_original(&mut self, step: Step, dispatch_end: Instant, make: impl FnOnce(&mut Self, Step) -> Result<RpcOriginal, Problem>) -> Result<(), Problem> {
        if !self.expected(step) || (!step.cleanup() && self.problem.is_some())
            || matches!(self.shutdown, Shutdown::Entered | Shutdown::Settled) {
            return Err(self.problem.unwrap_or(Problem::CleanupUnknown));
        }
        if step.cleanup() && !matches!(self.registration, Registration::Possible | Registration::Registered) {
            return Err(Problem::CleanupUnknown);
        }
        let future = make(self, step)?;
        // A preceding raw result stays retained through reconciliation and the
        // final stream/document gate, then this one successor replaces it.
        if let Some(Err(error)) = self.raw.as_ref() { self.raw_error.get_or_insert_with(|| error_class(error)); }
        self.raw = None; self.phase = Phase::Calling(step);
        self.pending = Some(Pending::Rpc { future, polled: false, dispatch_end });
        Ok(())
    }
    fn rpc(&mut self, step: Step) -> Result<RpcOriginal, Problem> {
        let attempt = self.attempt.as_mut().ok_or(Problem::CleanupUnknown)?;
        match step {
            Step::AddMatch | Step::RemoveMatch => {
                let rule = self.rule.clone().ok_or(Problem::CleanupUnknown)?;
                let method = if step == Step::AddMatch { "AddMatch" } else { "RemoveMatch" };
                attempt.start_raw_call(BUS.try_into().map_err(|_| Problem::InvalidInput)?,
                    BUS_PATH.try_into().map_err(|_| Problem::InvalidInput)?, BUS.try_into().map_err(|_| Problem::InvalidInput)?,
                    method.try_into().map_err(|_| Problem::InvalidInput)?, rule.as_ref().clone())
            }
            Step::GetNameOwner => attempt.start_raw_call(BUS.try_into().map_err(|_| Problem::InvalidInput)?,
                BUS_PATH.try_into().map_err(|_| Problem::InvalidInput)?, BUS.try_into().map_err(|_| Problem::InvalidInput)?,
                "GetNameOwner".try_into().map_err(|_| Problem::InvalidInput)?, SERVICE),
            Step::SearchItems => {
                let owner = self.owner.clone().ok_or(Problem::CleanupUnknown)?;
                let query = self.query.clone().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_search_items(attempt, owner.as_ref(), &query.collection, &query.attributes())
            }
            Step::Attributes => {
                let owner = self.owner.clone().ok_or(Problem::CleanupUnknown)?;
                let item = self.candidate.clone().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_attributes(attempt, owner.as_ref(), item.as_ref())
            }
        }.map_err(|_| Problem::Unavailable)?;
        Ok(RpcOriginal::Native)
    }
    fn cleanup_or_hold(&mut self) {
        if matches!(self.shutdown, Shutdown::Entered | Shutdown::Settled) {
            if matches!(self.registration, Registration::Possible | Registration::Registered) {
                self.registration = Registration::Unknown;
                self.fail(Problem::CleanupUnknown);
            }
            self.phase = Phase::Holding;
            return;
        }
        self.phase = if matches!(self.registration, Registration::Possible | Registration::Registered) {
            Phase::Admit(Step::RemoveMatch)
        } else { Phase::Holding };
    }
    pub(crate) fn admission_refused(&mut self, step: Step, problem: Problem) {
        self.fail(problem);
        if !self.expected(step) { return; }
        if step.cleanup() { self.registration = Registration::Unknown; self.phase = Phase::Holding; }
        else { self.cleanup_or_hold(); }
    }

    pub(crate) fn expected_shutdown(&self) -> bool {
        self.attempt.is_some() && self.shutdown == Shutdown::Unrequested && !self.never_polled()
            && (self.problem.is_some() || self.phase == Phase::Holding)
    }
    pub(crate) fn admit_shutdown(&mut self, dispatch_end: Instant) -> Result<(), Problem> {
        if !self.expected_shutdown() {
            self.commit_removal_reply();
            return Err(Problem::CleanupUnknown);
        }
        self.shutdown = Shutdown::Staged(dispatch_end);
        Ok(()) // No native cleanup is first-polled under the document mutex.
    }
    pub(crate) fn shutdown_admission_refused(&mut self, problem: Problem) {
        // Failed removal is deferred only through this local-stop admission,
        // never hidden after denial, expiry or an impossible ownership state.
        self.commit_removal_reply();
        if matches!(self.shutdown, Shutdown::Unrequested | Shutdown::Staged(_)) {
            self.shutdown = Shutdown::Refused;
            self.shutdown_ready = false;
            self.fail(problem);
        }
    }
    pub(crate) fn shutdown_waiting_first_poll(&self) -> bool {
        self.shutdown_ready && matches!(self.shutdown, Shutdown::Staged(_))
    }
    pub(crate) fn first_poll_shutdown(&mut self, cx: &mut Context<'_>,
        admission: Result<crate::asset_session::KeyringShutdownAdmission, Problem>) {
        if !std::mem::take(&mut self.shutdown_ready) {
            self.shutdown_admission_refused(Problem::CleanupUnknown);
            self.fail(Problem::CleanupUnknown); return;
        }
        let Shutdown::Staged(original_end) = self.shutdown else {
            self.shutdown_admission_refused(Problem::CleanupUnknown);
            self.fail(Problem::CleanupUnknown); return;
        };
        let end = match admission {
            Ok(admission) => original_end.min(admission.into_endpoint()),
            Err(problem) => { self.shutdown_admission_refused(problem); return; }
        };
        if Instant::now() >= end { self.shutdown_admission_refused(Problem::CleanupUnknown); return; }
        if self.attempt.is_none() { self.shutdown_admission_refused(Problem::CleanupUnknown); return; }
        self.commit_removal_reply();
        self.shutdown = Shutdown::Entered;
        self.poll_shutdown(cx);
        cx.waker().wake_by_ref();
    }
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) {
        if self.shutdown != Shutdown::Entered { return; }
        self.commit_removal_reply();
        if self.pending.is_none() && !self.raw_pending {
            // No original Message escapes this book. Retain non-owning error
            // facts, then consume raw/MethodError and handshake FD holdings.
            if let Some(error) = self.connect_failure.take() { self.build_error.get_or_insert_with(|| error_class(&error)); }
            if let Some(Err(error)) = self.raw.take() { self.raw_error.get_or_insert_with(|| error_class(&error)); }
            if self.attempt.as_mut().is_none_or(|attempt| attempt.release_stream().is_err()) {
                self.fail(Problem::CleanupUnknown);
            }
        }
        let Some(attempt) = self.attempt.as_mut() else { self.fail(Problem::CleanupUnknown); return; };
        let result = attempt.poll_local_shutdown(cx);
        let failed = attempt.cleanup_failed();
        if failed { self.cleanup_failed_seen = true; self.fail(Problem::CleanupUnknown); }
        if let Poll::Ready(result) = result {
            self.local_settlement = Some(result);
            self.shutdown = Shutdown::Settled;
            if !result.clean() { self.fail(Problem::CleanupUnknown); }
            if matches!(self.registration, Registration::Possible | Registration::Registered) {
                self.registration = Registration::Unknown;
                self.fail(Problem::CleanupUnknown);
            }
        }
    }

    /// One coordinator polls BOTH originals, bounded to one stream item and one
    /// future poll per turn. No observer owns/takes these holdings. A failed or
    /// poisoned coordinator retains Unknown holdings; it cannot keep driving.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Next> {
        let reconciling = self.raw_pending;
        let boundary = if reconciling { self.raw.as_ref().and_then(raw_message).map(Message::recv_position) } else { None };
        let turn = if self.removal_reply.is_some() {
            // This terminal raw result already consumed the original stream's
            // ordering evidence. Own shutdown must not sample a new EOF/error
            // and retroactively replace that result. Custody is still retained.
            StreamTurn::Reconciled
        } else { match self.attempt.as_mut() {
            Some(attempt) if !self.stream_ended => stream_turn(attempt, cx, boundary.as_ref()),
            _ => StreamTurn::Ended,
        } };
        self.advance(cx, turn)
    }

    fn never_polled(&self) -> bool {
        matches!(self.pending.as_ref(), Some(Pending::Connect { polled: false, .. } | Pending::Rpc { polled: false, .. }))
    }
    fn refuse_unpolled_pending(&mut self) -> Result<(), Problem> {
        match self.pending.as_ref() {
            Some(Pending::Connect { future: ConnectOriginal::Native, polled: false, .. }) =>
                self.attempt.as_mut().ok_or(Problem::CleanupUnknown)?.refuse_unpolled_build().map_err(|_| Problem::CleanupUnknown),
            Some(Pending::Rpc { future: RpcOriginal::Native, polled: false, .. }) =>
                self.attempt.as_mut().ok_or(Problem::CleanupUnknown)?.refuse_unpolled_call().map_err(|_| Problem::CleanupUnknown),
            #[cfg(test)]
            Some(Pending::Connect { future: ConnectOriginal::Data(_), polled: false, .. }
                | Pending::Rpc { future: RpcOriginal::Data(_), polled: false, .. }) => Ok(()),
            _ => Err(Problem::CleanupUnknown),
        }
    }
    /// Consume only this turn's readiness AFTER the final actual document gate.
    /// No stream poll, await, setup or lock acquisition may intervene between
    /// that gate's release and this method. The document-locked final admission
    /// is the local linearization point, not an instantaneous cancellation claim.
    pub(crate) fn first_poll(&mut self, cx: &mut Context<'_>, current_gate: Result<Instant, Problem>) {
        if !std::mem::take(&mut self.first_poll_ready) || !self.never_polled() {
            self.fail(Problem::CleanupUnknown);
            return; // Never poll without private, one-use stream readiness.
        }
        let refusal = if matches!(self.shutdown, Shutdown::Entered | Shutdown::Settled) {
            Some(Problem::CleanupUnknown)
        } else { match self.pending.as_mut() {
            Some(Pending::Connect { dispatch_end, .. } | Pending::Rpc { dispatch_end, .. }) => match current_gate {
                Err(problem) => Some(problem),
                Ok(current_end) => {
                    *dispatch_end = (*dispatch_end).min(current_end);
                    (Instant::now() >= *dispatch_end).then_some(if self.phase == Phase::Calling(Step::RemoveMatch) {
                        Problem::CleanupUnknown
                    } else { Problem::Interrupted })
                }
            },
            None => Some(Problem::CleanupUnknown),
        } };
        if let Some(problem) = refusal {
            self.fail(problem);
            if self.phase == Phase::Calling(Step::RemoveMatch) { self.registration = Registration::Unknown; }
            if self.refuse_unpolled_pending().is_ok() { self.pending = None; }
            else { self.fail(Problem::CleanupUnknown); }
            self.cleanup_or_hold(); cx.waker().wake_by_ref(); return;
        }
        self.poll_pending(cx);
    }

    // Kept separate only to drive this exact state machine with synthetic DATA
    // streams in unit tests. Production always supplies the original stream's
    // real recv_position boundary above, never a caller ordering receipt.
    fn advance(&mut self, cx: &mut Context<'_>, turn: StreamTurn) -> Poll<Next> {
        self.first_poll_ready = false; // Readiness cannot survive another stream turn.
        self.shutdown_ready = false;
        // Production no longer samples here after terminal reconciliation.
        // Exclude stale DATA turns at this same state-machine boundary too.
        let turn = if self.removal_reply.is_some() { StreamTurn::Reconciled } else { turn };
        let reconciling = self.raw_pending;
        let has_boundary = reconciling && self.raw.as_ref().and_then(raw_message).is_some();
        match turn {
            StreamTurn::Observed(Some(problem)) => self.fail(problem),
            StreamTurn::Failed => self.fail(Problem::StreamFailed),
            StreamTurn::Ended if self.entered && self.phase != Phase::Connecting && self.registration != Registration::Removed => {
                self.stream_ended = true; self.fail(Problem::StreamFailed);
            }
            _ => {}
        }

        // A never-polled future has dispatched nothing. After ONE native poll
        // its original is retained through STOP, owner/stream/observer loss.
        let skip_unpolled = self.problem.is_some() && (matches!(self.pending.as_ref(), Some(Pending::Connect { polled: false, .. }))
            || (matches!(self.pending.as_ref(), Some(Pending::Rpc { polled: false, .. }))
                && matches!(self.phase, Phase::Calling(step) if !step.cleanup())));
        if skip_unpolled {
            if self.refuse_unpolled_pending().is_ok() { self.pending = None; }
            else { self.fail(Problem::CleanupUnknown); }
            self.cleanup_or_hold(); cx.waker().wake_by_ref(); return Poll::Pending;
        }
        // Consume the actual raw boundary BEFORE even staging local shutdown.
        // In particular, never discard a genuine RemoveMatch NoneBefore turn
        // and let shutdown's own reader error substitute for it on a later poll.
        if reconciling {
            if !has_boundary || matches!(turn, StreamTurn::Failed | StreamTurn::Ended) {
                self.finish_reply(false); cx.waker().wake_by_ref();
            } else if matches!(turn, StreamTurn::Drained) {
                self.finish_reply(true); cx.waker().wake_by_ref();
            }
        }
        self.poll_shutdown(cx); // Already-entered cleanup is never gated anew.
        if self.resources_settled() && self.entered { return Poll::Ready(Next::Settled); }
        if matches!(self.shutdown, Shutdown::Staged(_)) {
            // Drive a retained original before the FINAL gate, never after it
            // and before the first shutdown poll. A stalled RPC cannot prevent
            // this independent local shutdown admission.
            if !self.never_polled() && self.poll_pending(cx) {
                // A newly returned original has not had its own boundary
                // sampled yet. Give it one next bounded stream turn before the
                // final gate; a still-Pending original never blocks shutdown.
                cx.waker().wake_by_ref(); return Poll::Pending;
            }
            self.shutdown_ready = true;
            return Poll::Ready(Next::FirstPollShutdown);
        }
        if self.expected_shutdown() { return Poll::Ready(Next::AdmitShutdown); }
        if matches!(self.pending.as_ref(), Some(Pending::Rpc { polled: false, .. }))
            && !(matches!(turn, StreamTurn::Idle)
                || (self.phase == Phase::Calling(Step::RemoveMatch) && matches!(turn, StreamTurn::Failed | StreamTurn::Ended)))
        {
            // A message that arrived after serialized admission may have another
            // owner event behind it. Finish the bounded nonblocking drain before
            // FIRST dispatch; already-polled originals below are always driven.
            if matches!(turn, StreamTurn::Observed(_)) { cx.waker().wake_by_ref(); }
            return Poll::Pending;
        }

        if self.never_polled() {
            // Stream work is finished. The caller now takes document -> book,
            // checks the actual current slot/cutoff, releases the document and
            // invokes first_poll immediately, with NO intervening stream work.
            self.first_poll_ready = true;
            return Poll::Ready(Next::FirstPoll);
        }
        if self.poll_pending(cx) { return Poll::Pending; }
        if reconciling && !self.raw_pending { return Poll::Pending; }

        if matches!(turn, StreamTurn::Observed(_)) { cx.waker().wake_by_ref(); }
        if let Phase::Admit(step) = self.phase {
            if matches!(self.shutdown, Shutdown::Entered | Shutdown::Settled) {
                self.cleanup_or_hold(); cx.waker().wake_by_ref(); return Poll::Pending;
            }
            if !step.cleanup() && self.problem.is_some() {
                self.cleanup_or_hold(); cx.waker().wake_by_ref(); return Poll::Pending;
            }
            // Idle here is a FINAL nonblocking drain, not an ordering receipt.
            // The caller now checks the real document/slot/stop before admit().
            if matches!(turn, StreamTurn::Idle) || (step.cleanup() && matches!(turn, StreamTurn::Failed | StreamTurn::Ended)) {
                return Poll::Ready(Next::Admit(step));
            }
        }
        // A nonterminal stream is pumped even in Holding. Only the consumed
        // maintained join/disposal result, never Holding or reconciliation
        // itself, can complete a book.
        Poll::Pending
    }

    // Called either with consumed final admission or an already-polled original.
    // In the latter case STOP/Unknown/cutoff never causes re-adoption/cancellation.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> bool {
        match self.pending.as_mut() {
            Some(Pending::Connect { future, polled, .. }) => { *polled = true;
                let result = match future {
                    ConnectOriginal::Native => match self.attempt.as_mut() {
                        Some(attempt) => attempt.poll_build(cx),
                        None => Poll::Ready(Err(zbus::Error::InvalidField)),
                    },
                    #[cfg(test)]
                    ConnectOriginal::Data(future) => future.as_mut().poll(cx),
                };
                match result {
                Poll::Pending => {},
                Poll::Ready(Ok(())) => {
                    // Connection/stream/task never leave the retained SDK
                    // attempt, including an original failed startup.
                    self.pending = None;
                    self.phase = if self.problem.is_none() { Phase::Admit(Step::AddMatch) } else { Phase::Holding };
                    cx.waker().wake_by_ref(); return true;
                }
                Poll::Ready(Err(error)) => {
                    self.connect_failure = Some(error); self.pending = None;
                    self.fail(Problem::Unavailable); self.phase = Phase::Holding;
                    return true; // This result alone is not the original reader join.
                }
            } },
            Some(Pending::Rpc { future, polled, .. }) => {
                if !*polled && self.phase == Phase::Calling(Step::AddMatch) { self.registration = Registration::Possible; }
                *polled = true;
                let result = match future {
                    RpcOriginal::Native => match self.attempt.as_mut() {
                        Some(attempt) => attempt.poll_raw_call(cx),
                        None => Poll::Ready(Err(zbus::Error::InvalidField)),
                    },
                    #[cfg(test)]
                    RpcOriginal::Data(future) => future.as_mut().poll(cx),
                };
                if let Poll::Ready(result) = result {
                    // Failure is known now, not at a later observer/drain tick.
                    // The raw result is nevertheless retained and reconciled.
                    if result.is_err() { self.fail(Problem::Unavailable); }
                    self.raw = Some(result); self.raw_pending = true; self.pending = None;
                    cx.waker().wake_by_ref(); return true;
                }
            }
            None => {}
        }
        false
    }

    fn finish_reply(&mut self, reconciled: bool) {
        self.raw_pending = false;
        let Phase::Calling(step) = self.phase else { self.fail(Problem::CleanupUnknown); self.phase = Phase::Holding; return; };
        let result = self.decode_reply(step, reconciled);
        if step.cleanup() {
            self.removal_reply = Some(if result.is_ok() {
                RemovalReply::Confirmed
            } else {
                let error = match self.raw.as_ref() {
                    Some(Err(error)) => error_class(error),
                    _ => ErrorClass::Protocol,
                };
                // Latch failure NOW, before another admission or observer tick.
                // The prior raw Err clock, if any, remains authoritative.
                self.fail(Problem::CleanupUnknown);
                RemovalReply::Failed(error)
            });
            // No successor can replace this final raw slot. Its owning Message
            // and private stream stay retained until admitted local disposal.
            // Defer only semantic Unknown while staging the local stop; prior
            // document/slot Unknown still forbids admission, unchanged.
            if matches!(self.shutdown, Shutdown::Entered | Shutdown::Settled | Shutdown::Refused) {
                self.commit_removal_reply();
            }
            self.phase = Phase::Holding; return;
        }
        if let Err(problem) = result { self.fail(problem); }
        if self.problem.is_some() { self.cleanup_or_hold(); return; }
        self.phase = match step {
            Step::AddMatch => Phase::Admit(Step::GetNameOwner),
            Step::GetNameOwner => Phase::Admit(Step::SearchItems),
            Step::SearchItems if self.candidate.is_some() => Phase::Admit(Step::Attributes),
            Step::SearchItems | Step::Attributes => Phase::Admit(Step::RemoveMatch),
            Step::RemoveMatch => Phase::Holding,
        };
    }
    fn commit_removal_reply(&mut self) {
        match self.removal_reply {
            Some(RemovalReply::Confirmed) => self.registration = Registration::Removed,
            Some(RemovalReply::Failed(error)) => {
                self.cleanup_error = Some(error);
                self.registration = Registration::Unknown;
                self.fail(Problem::CleanupUnknown);
            }
            None => {}
        }
    }
    fn decode_reply(&mut self, step: Step, reconciled: bool) -> Result<(), Problem> {
        let result = self.raw.as_ref().ok_or(Problem::CleanupUnknown)?;
        // Retain the original MethodError Message through the exact same stream
        // gate as success. Never FDO-convert/format it or invent a sequence.
        let message = result.as_ref().map_err(|_| Problem::Unavailable)?;
        if !reconciled { return Err(Problem::StreamFailed); }
        let body = message.body();
        match step {
            Step::AddMatch => {
                checked_lookup::check_empty_bus_reply(&body).map_err(|_| Problem::InvalidReply)?;
                self.registration = Registration::Registered;
            }
            Step::RemoveMatch => { checked_lookup::check_empty_bus_reply(&body).map_err(|_| Problem::InvalidReply)?; }
            _ if self.problem.is_some() => return Err(self.problem.unwrap_or(Problem::CleanupUnknown)),
            Step::GetNameOwner => {
                if self.owner.is_some() { return Err(Problem::CleanupUnknown); }
                let name = checked_lookup::decode_name_owner(&body).map_err(|_| Problem::InvalidReply)?;
                self.owner = Some(Arc::new(UniqueName::try_from(name.to_owned()).map_err(|_| Problem::InvalidReply)?));
            }
            Step::SearchItems => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                match checked_lookup::decode_item_path(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)? {
                    Some(path) => self.candidate = Some(Arc::new(OwnedObjectPath::try_from(path.to_owned()).map_err(|_| Problem::InvalidReply)?)),
                    None => self.observation = Some(Observation::Absent),
                }
            }
            Step::Attributes => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let query = self.query.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::check_attributes(&body, owner.as_ref(), &query.attributes()).map_err(|_| Problem::IdentityMismatch)?;
                self.observation = Some(Observation::Candidate(self.candidate.take().ok_or(Problem::CleanupUnknown)?));
            }
        }
        Ok(())
    }
}

fn raw_message(result: &zbus::Result<Message>) -> Option<&Message> {
    match result { Ok(message) | Err(zbus::Error::MethodError(_, _, message)) => Some(message), _ => None }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamTurn { Idle, Pending, Observed(Option<Problem>), Drained, Failed, Ended, Reconciled }

fn stream_turn<S>(stream: &mut S, cx: &mut Context<'_>, before: Option<&S::Ordering>) -> StreamTurn
where S: OrderedStream<Data = zbus::Result<Message>> + Unpin {
    match Pin::new(stream).poll_next_before(cx, before) {
        Poll::Pending if before.is_none() => StreamTurn::Idle,
        Poll::Pending => StreamTurn::Pending,
        Poll::Ready(PollResult::NoneBefore) if before.is_some() => StreamTurn::Drained,
        Poll::Ready(PollResult::NoneBefore) => StreamTurn::Failed,
        Poll::Ready(PollResult::Terminated) => StreamTurn::Ended,
        Poll::Ready(PollResult::Item { data: Err(_), .. }) => StreamTurn::Failed,
        Poll::Ready(PollResult::Item { data: Ok(message), .. }) => {
            // Do NOT discard Item merely because its ordering is >= before:
            // an already-observed later owner change refuses progression too.
            let header = message.header();
            if header.message_type() == Type::Signal && header.sender().map(|name| name.as_str()) == Some(BUS)
                && header.member().map(|name| name.as_str()) == Some("NameOwnerChanged") {
                StreamTurn::Observed(Some(if checked_lookup::decode_owner_changed(&message.body()).is_ok() {
                    Problem::OwnerChanged
                } else { Problem::InvalidReply }))
            } else {
                // Unrelated headers, including shared copies of RPC replies,
                // need no generic body/Structure/arg-filter allocation.
                StreamTurn::Observed(None)
            }
        }
    }
}

#[cfg(test)]
impl LookupBook {
    pub(crate) fn constructor_refusal_data() -> Self {
        // Actual constructor-refusal bookkeeping, with no SDK/native original.
        let input = LookupInput::new(Path::new("/inert/not-opened"), "/collection", "data-vault", "data-generation").unwrap();
        let mut book = Self::new();
        assert_eq!(book.begin_constructed(input, Instant::now(),
            crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap(),
            |_| Err(zbus::Error::InvalidReply)), Err(Problem::Unavailable));
        book
    }
    // Actual-driver DATA seam for the real DocumentState/OriginalWork gate
    // regression. No Connection, stream, task or native receipt is fabricated.
    pub(crate) fn cleanup_data(dispatch_end: Instant, future: impl Future<Output = zbus::Result<Message>> + Send + 'static) -> Self {
        let mut book = Self::new();
        book.claim(crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap()).unwrap();
        book.phase = Phase::Admit(Step::RemoveMatch); book.registration = Registration::Registered;
        book.admit_with(Step::RemoveMatch, dispatch_end, |_, _| Ok(Box::pin(future))).unwrap();
        book
    }
    pub(crate) fn idle_data_turn(&mut self, cx: &mut Context<'_>) -> Poll<Next> {
        self.advance(cx, StreamTurn::Idle)
    }
    pub(crate) fn shutdown_gate_data(dispatch_end: Instant) -> Self {
        // Only exercises the real document/one-use admission logic. There is
        // NO native attempt, task, connection or finality result in this book.
        let mut book = Self::new();
        book.claim(crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap()).unwrap();
        book.phase = Phase::Calling(Step::RemoveMatch);
        book.registration = Registration::Registered;
        book.raw = Some(Err(zbus::Error::InvalidReply)); book.raw_pending = true;
        book.shutdown = Shutdown::Staged(dispatch_end);
        book.finish_reply(false); // Real terminal failure, not a caller receipt.
        book
    }
}

#[cfg(test)]
mod bounded_wire_tests {
    use zbus::connection::owned_test_support;

    #[test]
    fn bounded_frames_refuse_before_allocation() { owned_test_support::bounded_wire_frames(); }
    #[test]
    fn bounded_headers_refuse_before_generic_decode() { owned_test_support::bounded_wire_headers(); }
    #[test]
    fn bounded_serializer_and_control_census() { owned_test_support::bounded_wire_capacity(); }
    #[test]
    fn bounded_authentication_and_hello() { owned_test_support::bounded_wire_authentication(); }
    #[test]
    fn errors_complete_only_original_registrations() { owned_test_support::bounded_wire_error_registration(); }
    #[test]
    #[ignore = "requires separately reviewed isolated Unix fixture admission"]
    fn bounded_unix_original_rights_disposal() { owned_test_support::bounded_wire_original_rights_disposal(); }
}

#[cfg(test)]
mod original_finality_tests {
    use std::{future::Future, time::Duration};
    use zbus::connection::owned_test_support;

    async fn finite(check: impl Future<Output = ()>) {
        // Expiration is a test FAILURE, never evidence of task termination.
        tokio::time::timeout(Duration::from_secs(10), check).await
            .expect("owned SDK fixture did not consume its original work");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn owned_task_join_outcomes() {
        finite(owned_test_support::original_task_join_outcomes()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_startup_error_roster() {
        finite(owned_test_support::original_startup_error_roster()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_startup_survives_observer_loss() {
        finite(owned_test_support::original_startup_survives_observer_loss()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_full_queue_reader_shutdown() {
        finite(owned_test_support::original_full_queue_reader_shutdown()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_raw_call_survives_observer_loss() {
        finite(owned_test_support::original_raw_call_survives_observer_loss()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_writer_close_failure() {
        finite(owned_test_support::original_writer_close_failure()).await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires separately reviewed isolated Unix fixture admission"]
    async fn owned_unix_pending_authentication_shutdown() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::PathBuf::from(std::env::var_os("MRK_OWNED_UNIX_FIXTURE_ROOT")
            .expect("the native test owner must supply a private fixture directory"));
        assert!(root.is_absolute());
        let metadata = std::fs::symlink_metadata(&root).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        // The admitted owner validates ancestor/identity/ownership and cleans
        // ONLY this newly created pathname. No default or host bus fallback.
        finite(owned_test_support::unix_pending_authentication_shutdown(root.join("owned-startup.sock"))).await;
    }
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires separately reviewed isolated Unix fixture admission"]
    async fn owned_unix_pending_write_and_received_fd_shutdown() {
        // LEGACY profile: the 8MiB write/received-FD fixture is deliberately
        // separate and is NOT evidence for the 64KiB/zero-FD Keyring profile.
        finite(owned_test_support::unix_pending_write_and_received_fd_shutdown()).await;
    }
}

#[cfg(test)]
mod tests {
    // DATA-only: no bus/socket/file/provider/task is opened or launched. Test
    // Message positions are zero; integer ordered fixtures prove this helper's
    // logic, NOT real connection ordering, transport capacity or native finality.
    use super::*;
    use std::{collections::VecDeque, sync::atomic::{AtomicBool, AtomicUsize, Ordering}, task::Waker};

    enum DataTurn { Item(u64, zbus::Result<Message>), Idle, Drained, Ended }
    struct DataStream(VecDeque<DataTurn>);
    impl OrderedStream for DataStream {
        type Ordering = u64;
        type Data = zbus::Result<Message>;
        fn poll_next_before(mut self: Pin<&mut Self>, _: &mut Context<'_>, _: Option<&u64>) -> Poll<PollResult<u64, Self::Data>> {
            match self.0.pop_front().unwrap_or(DataTurn::Idle) {
                DataTurn::Item(ordering, data) => Poll::Ready(PollResult::Item { ordering, data }),
                DataTurn::Idle => Poll::Pending,
                DataTurn::Drained => Poll::Ready(PollResult::NoneBefore),
                DataTurn::Ended => Poll::Ready(PollResult::Terminated),
            }
        }
    }
    fn data_deadline() -> Instant { Instant::now() + std::time::Duration::from_secs(60) }
    fn input() -> LookupInput {
        LookupInput::new(Path::new("/synthetic/never-opened/bus"), "/collection", "reserved-vault", "reserved-generation").unwrap()
    }
    fn data_book() -> LookupBook {
        // Seed only inert pre-call state. There is deliberately no Connection;
        // all RPCs below enter through the real admit_with dispatch seam.
        let input = input(); let mut book = LookupBook::new();
        book.claim(crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap()).unwrap();
        book.query = Some(input.query); book.rule = Some(input.rule);
        book.phase = Phase::Admit(Step::AddMatch); book
    }
    fn reply<T: serde::Serialize + zbus::zvariant::DynamicType>(sender: &'static str, data: &T) -> Message {
        let call = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
        Message::method_return(&call.header()).unwrap().sender(sender).unwrap().build(data).unwrap()
    }
    fn owner_event() -> Message {
        Message::signal(BUS_PATH, BUS, "NameOwnerChanged").unwrap().sender(BUS).unwrap()
            .build(&(SERVICE, ":1.23", ":1.24")).unwrap()
    }
    fn tick(book: &mut LookupBook, turn: DataTurn) -> Poll<Step> {
        let mut stream = DataStream(VecDeque::from([turn]));
        let mut cx = Context::from_waker(Waker::noop());
        let before = (book.raw_pending && book.raw.as_ref().and_then(raw_message).is_some()).then_some(10u64);
        let observed = stream_turn(&mut stream, &mut cx, before.as_ref());
        match book.advance(&mut cx, observed) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Next::Admit(step)) => Poll::Ready(step),
            Poll::Ready(Next::FirstPoll) => {
                // Lower-level DATA tests have no document. Actual slot/STOP
                // admission between these phases is tested in asset_session.
                book.first_poll(&mut cx, Ok(data_deadline()));
                Poll::Pending
            }
            Poll::Ready(Next::AdmitShutdown | Next::FirstPollShutdown | Next::Settled) =>
                panic!("DATA RPCs cannot manufacture a maintained SDK finality receipt"),
        }
    }
    fn call(book: &mut LookupBook, step: Step, result: zbus::Result<Message>, registered: &mut Vec<Step>) {
        assert_eq!(tick(book, DataTurn::Idle), Poll::Ready(step));
        book.admit_with(step, data_deadline(), |_, actual| { registered.push(actual); Ok(Box::pin(std::future::ready(result))) }).unwrap();
        assert!(tick(book, DataTurn::Idle).is_pending()); // original returned, raw retained
        assert!(book.raw_pending);
        assert!(tick(book, DataTurn::Drained).is_pending()); // actual state-machine reconciliation
        assert!(!book.raw_pending);
        // These lower-level DATA books have no native shutdown to admit. Apply
        // only the production semantic result; no SDK settlement is invented.
        if step.cleanup() { book.commit_removal_reply(); }
    }
    fn select_owner(book: &mut LookupBook, registered: &mut Vec<Step>) {
        call(book, Step::AddMatch, Ok(reply(BUS, &())), registered);
        call(book, Step::GetNameOwner, Ok(reply(BUS, &":1.23")), registered);
        assert_eq!(book.owner.as_ref().unwrap().as_str(), ":1.23");
    }
    #[test]
    fn lookup_charge_precedes_constructor_and_is_refunded_only_after_disposal() {
        let mut book = LookupBook::new(); let value = input();
        let query = Arc::downgrade(&value.query); let rule = Arc::downgrade(&value.rule);
        let charge = crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap();
        let calls = std::cell::Cell::new(0);
        assert_eq!(book.begin_constructed(value, data_deadline(), charge, |_| {
            calls.set(calls.get() + 1); Err(zbus::Error::InvalidReply)
        }), Err(Problem::Unavailable));
        assert_eq!(calls.get(), 1); assert!(book.started() && book.memory_held());
        assert!(book.resources_settled() && !book.allocations_released()); // no attempt was constructed
        assert!(query.upgrade().is_some() && rule.upgrade().is_some());
        let failed_at = book.problem_at(); book.interrupt();
        assert!(book.memory_held() && book.started());
        assert_eq!(book.begin_constructed(input(), data_deadline(),
            crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap(),
            |_| panic!("duplicate entry reached SDK construction")), Err(Problem::CleanupUnknown));
        assert!(book.dispose_settled_storage());
        assert!(!book.memory_held() && book.allocations_released() && book.started() && !book.can_begin());
        assert!(query.upgrade().is_none() && rule.upgrade().is_none());
        assert_eq!(book.problem(), Some(Problem::Unavailable)); assert_eq!(book.problem_at(), failed_at);
        assert!(!book.dispose_settled_storage()); // no second refund
    }
    #[test]
    fn lookup_charge_is_not_refunded_by_stop_raw_or_unjoined_original() {
        let value = input(); let mut book = LookupBook::new();
        book.begin_with(value.query, value.rule, data_deadline(), Box::pin(std::future::pending())).unwrap();
        book.interrupt(); assert!(book.memory_held() && !book.dispose_settled_storage());
        assert!(book.pending.is_some() && book.started());
        let mut raw = LookupBook::shutdown_gate_data(data_deadline());
        assert!(raw.memory_held() && raw.raw.is_some());
        assert!(!raw.dispose_settled_storage() && raw.memory_held());
        assert!(raw.raw.is_some() && raw.started());
    }
    #[test]
    fn lookup_driver_runs_only_fixed_search_attributes_and_one_cleanup() {
        for candidate in [false, true] {
            let mut book = data_book(); let mut registered = Vec::new();
            select_owner(&mut book, &mut registered);
            let path = zbus::zvariant::ObjectPath::try_from("/one").unwrap();
            let paths = [path];
            let selected = if candidate { &paths[..] } else { &paths[..0] };
            call(&mut book, Step::SearchItems, Ok(reply(":1.23", &selected)), &mut registered);
            if candidate {
                let attributes: std::collections::HashMap<_, _> = book.query.as_ref().unwrap().attributes().into_iter().collect();
                let message = reply(":1.23", &zbus::zvariant::as_value::Serialize(&attributes));
                drop(attributes);
                call(&mut book, Step::Attributes, Ok(message), &mut registered);
                assert!(matches!(book.observation(), Some(Observation::Candidate(path)) if path.as_str() == "/one"));
            } else { assert!(matches!(book.observation(), Some(Observation::Absent))); }
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            let expected = if candidate { vec![Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::Attributes, Step::RemoveMatch] }
                else { vec![Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::RemoveMatch] };
            assert_eq!(registered, expected);
            assert_eq!(book.registration, Registration::Removed);
            assert_eq!(book.phase, Phase::Holding);
            assert!(book.problem().is_none());
            assert!(!book.resources_settled()); // successful RPC/removal is not SDK joins
            let mut extra = 0;
            assert!(book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| { extra += 1; Ok(Box::pin(std::future::pending())) }).is_err());
            assert_eq!(extra, 0);
        }
    }
    #[test]
    fn lookup_refusal_never_registers_an_attribute_fanout_or_replacement_owner() {
        for paths in [vec!["/"], vec!["/one", "/two"]] {
            let mut book = data_book(); let mut registered = Vec::new();
            select_owner(&mut book, &mut registered);
            let paths: Vec<_> = paths.into_iter().map(|path| zbus::zvariant::ObjectPath::try_from(path).unwrap()).collect();
            call(&mut book, Step::SearchItems, Ok(reply(":1.23", &paths)), &mut registered);
            assert_eq!(book.problem(), Some(Problem::InvalidReply));
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            assert_eq!(registered, [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::RemoveMatch]);
            assert!(book.observation().is_none());
            assert_eq!(book.owner.as_ref().unwrap().as_str(), ":1.23");
        }
        let mut book = data_book(); let mut registered = Vec::new(); select_owner(&mut book, &mut registered);
        let path = [zbus::zvariant::ObjectPath::try_from("/one").unwrap()];
        call(&mut book, Step::SearchItems, Ok(reply(":1.23", &&path[..])), &mut registered);
        let mut attributes: std::collections::HashMap<_, _> = book.query.as_ref().unwrap().attributes().into_iter().collect();
        attributes.insert("vault-id", "another-vault");
        let message = reply(":1.23", &zbus::zvariant::as_value::Serialize(&attributes)); drop(attributes);
        call(&mut book, Step::Attributes, Ok(message), &mut registered);
        assert_eq!(book.problem(), Some(Problem::IdentityMismatch));
        assert!(book.observation().is_none());
        call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
        assert_eq!(registered, [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::Attributes, Step::RemoveMatch]);
    }
    #[test]
    fn earlier_and_already_observed_later_owner_events_refuse_the_same_original_result() {
        for ordering in [2u64, 20] {
            let mut book = data_book(); let mut registered = Vec::new();
            select_owner(&mut book, &mut registered);
            let paths = [zbus::zvariant::ObjectPath::try_from("/one").unwrap()];
            let message = reply(":1.23", &&paths[..]);
            book.admit_with(Step::SearchItems, data_deadline(), |_, step| { registered.push(step); Ok(Box::pin(std::future::ready(Ok(message)))) }).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert!(tick(&mut book, DataTurn::Item(ordering, Ok(owner_event()))).is_pending());
            assert_eq!(book.problem(), Some(Problem::OwnerChanged));
            assert!(book.raw_pending); // an Item is not the NoneBefore receipt
            assert!(tick(&mut book, DataTurn::Drained).is_pending());
            assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            assert_eq!(registered, [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::RemoveMatch]);
            assert!(book.observation().is_none() && !book.resources_settled());
        }
    }
    #[test]
    fn raw_method_errors_require_drain_and_stream_failures_never_supply_it() {
        for failure in [DataTurn::Item(12, Err(zbus::Error::InvalidReply)), DataTurn::Ended, DataTurn::Drained] {
            let mut book = data_book(); let mut registered = Vec::new();
            select_owner(&mut book, &mut registered);
            let call_message = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
            let message = Message::error(&call_message.header(), "org.example.Refused").unwrap().sender(":1.23").unwrap().build(&"detail").unwrap();
            let bytes = message.data().bytes().as_ptr();
            let original = zbus::Error::MethodError("org.example.Refused".try_into().unwrap(), None, message);
            book.admit_with(Step::SearchItems, data_deadline(), |_, _| Ok(Box::pin(std::future::ready(Err(original))))).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert_eq!(book.problem(), Some(Problem::Unavailable)); // Latched at the actual raw Err, before drain.
            let original_failure_at = book.problem_at().unwrap();
            assert_eq!(raw_message(book.raw.as_ref().unwrap()).unwrap().data().bytes().as_ptr(), bytes);
            assert!(tick(&mut book, DataTurn::Idle).is_pending()); // Pending with boundary is not drained
            assert!(book.raw_pending);
            assert!(tick(&mut book, failure).is_pending());
            assert!(!book.raw_pending);
            assert!(book.problem().is_some());
            assert_eq!(book.problem_at(), Some(original_failure_at));
            assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
            assert!(matches!(book.raw, Some(Err(zbus::Error::MethodError(_, _, _)))));
        }
        let mut stream = DataStream(VecDeque::from([DataTurn::Drained]));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(stream_turn(&mut stream, &mut cx, None), StreamTurn::Failed);
    }

    #[test]
    fn terminal_removal_reconciliation_precedes_shutdown_and_closes_stream_sampling() {
        #[derive(Clone, Copy)]
        enum ReplyKind { Valid, Malformed, MethodError }
        fn removal(result: zbus::Result<Message>) -> LookupBook {
            let mut book = data_book();
            book.phase = Phase::Admit(Step::RemoveMatch); book.registration = Registration::Registered;
            book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| Ok(Box::pin(std::future::ready(result)))).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert!(book.raw_pending && book.removal_reply.is_none());
            book
        }
        let mut cx = Context::from_waker(Waker::noop());
        for kind in [ReplyKind::Valid, ReplyKind::Malformed, ReplyKind::MethodError] {
            for staged in [false, true] {
                let raw = match kind {
                    ReplyKind::Valid => Ok(reply(BUS, &())),
                    ReplyKind::Malformed => Ok(reply(BUS, &"not an empty reply")),
                    ReplyKind::MethodError => {
                        let call = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
                        let message = Message::error(&call.header(), "org.example.Refused").unwrap()
                            .sender(BUS).unwrap().build(&"detail").unwrap();
                        Err(zbus::Error::MethodError("org.example.Refused".try_into().unwrap(), None, message))
                    }
                };
                let bytes = raw_message(&raw).unwrap().data().bytes().as_ptr();
                let mut book = removal(raw);
                let raw_failure_at = book.problem_at();
                assert_eq!(raw_failure_at.is_some(), matches!(kind, ReplyKind::MethodError));
                // Neither an earlier Item nor Pending proves this raw boundary.
                for turn in [StreamTurn::Observed(None), StreamTurn::Pending] {
                    assert!(book.advance(&mut cx, turn).is_pending());
                    assert!(book.raw_pending && book.removal_reply.is_none());
                }
                let end = data_deadline();
                if staged { book.shutdown = Shutdown::Staged(end); }
                let next = book.advance(&mut cx, StreamTurn::Drained);
                if staged { assert!(matches!(next, Poll::Ready(Next::FirstPollShutdown))); }
                else { assert!(next.is_pending()); }
                assert!(!book.raw_pending);
                let expected = match kind {
                    ReplyKind::Valid => RemovalReply::Confirmed,
                    ReplyKind::Malformed => RemovalReply::Failed(ErrorClass::Protocol),
                    ReplyKind::MethodError => RemovalReply::Failed(ErrorClass::Remote),
                };
                assert_eq!(book.removal_reply, Some(expected));
                assert_eq!(book.registration, Registration::Registered); // Not a local-stop receipt.
                let problem = book.problem(); let problem_at = book.problem_at();
                assert_eq!(problem.is_none(), matches!(kind, ReplyKind::Valid));
                if raw_failure_at.is_some() { assert_eq!(problem_at, raw_failure_at); }
                assert!(!book.cleanup_unknown()); // Only this bounded stop admission is pending.
                // A reader awakened by own shutdown may produce either turn.
                // Terminal reconciliation cannot be replaced by that later error.
                for stale in [StreamTurn::Failed, StreamTurn::Ended] {
                    let _ = book.advance(&mut cx, stale);
                    assert_eq!(book.removal_reply, Some(expected));
                    assert_eq!(book.problem(), problem); assert_eq!(book.problem_at(), problem_at);
                }
                // The real poll entry must skip sampling too, not only advance.
                // This DATA book has no stream: sampling it would yield Ended.
                let _ = book.poll(&mut cx);
                assert_eq!(book.problem(), problem); assert_eq!(book.problem_at(), problem_at);
                if staged { assert_eq!(book.shutdown, Shutdown::Staged(end)); }
                assert_eq!(raw_message(book.raw.as_ref().unwrap()).unwrap().data().bytes().as_ptr(), bytes);
                book.shutdown_admission_refused(Problem::Interrupted);
                assert_eq!(book.registration, if matches!(kind, ReplyKind::Valid) { Registration::Removed } else { Registration::Unknown });
                assert_eq!(book.cleanup_unknown(), !matches!(kind, ReplyKind::Valid));
                if problem_at.is_some() { assert_eq!(book.problem_at(), problem_at); }
                assert_eq!(raw_message(book.raw.as_ref().unwrap()).unwrap().data().bytes().as_ptr(), bytes);
                assert!(!book.resources_settled());
            }
        }
        for turn in [StreamTurn::Failed, StreamTurn::Ended] {
            let mut book = removal(Ok(reply(BUS, &())));
            book.shutdown = Shutdown::Staged(data_deadline());
            assert!(matches!(book.advance(&mut cx, turn), Poll::Ready(Next::FirstPollShutdown)));
            assert_eq!(book.removal_reply, Some(RemovalReply::Failed(ErrorClass::Protocol)));
            let problem_at = book.problem_at();
            book.shutdown_admission_refused(Problem::CleanupUnknown);
            assert!(book.cleanup_unknown() && !book.resources_settled());
            assert_eq!(book.problem_at(), problem_at); // Missing drain is NEVER Confirmed.
        }

        // If an entered original returns while shutdown is staged, its new raw
        // boundary gets one following turn. A still-stalled RPC does not block
        // the independent local-stop gate, nor is its original dropped.
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(AtomicBool::new(false));
        let mut book = data_book(); book.phase = Phase::Admit(Step::RemoveMatch); book.registration = Registration::Registered;
        book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), false))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        book.interrupt(); let problem_at = book.problem_at();
        let end = data_deadline(); book.shutdown = Shutdown::Staged(end);
        assert!(matches!(book.advance(&mut cx, StreamTurn::Pending), Poll::Ready(Next::FirstPollShutdown)));
        assert_eq!(polls.load(Ordering::SeqCst), 2); assert_eq!(drops.load(Ordering::SeqCst), 0);
        ready.store(true, Ordering::SeqCst);
        assert!(book.advance(&mut cx, StreamTurn::Idle).is_pending());
        assert!(book.raw_pending && !book.shutdown_waiting_first_poll());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(matches!(book.advance(&mut cx, StreamTurn::Drained), Poll::Ready(Next::FirstPollShutdown)));
        assert_eq!(book.removal_reply, Some(RemovalReply::Confirmed));
        assert_eq!(book.shutdown, Shutdown::Staged(end)); assert_eq!(book.problem_at(), problem_at);
        assert!(book.raw.is_some() && !book.resources_settled());

        // All invalid consumers commit failed removal, even if no document
        // grant can be obtained. The real token's denial/expiry/absent-attempt
        // consumption is additionally covered by the asset_session gate test.
        for invalid in 0..3 {
            let mut book = LookupBook::shutdown_gate_data(data_deadline());
            let problem_at = book.problem_at();
            match invalid {
                0 => book.first_poll_shutdown(&mut cx, Err(Problem::CleanupUnknown)), // Missing readiness.
                1 => {
                    book.shutdown = Shutdown::Unrequested; book.shutdown_ready = true;
                    book.first_poll_shutdown(&mut cx, Err(Problem::CleanupUnknown)); // Wrong stage.
                }
                _ => {
                    book.shutdown = Shutdown::Unrequested;
                    assert!(book.admit_shutdown(data_deadline()).is_err()); // Impossible attempt.
                }
            }
            assert!(book.cleanup_unknown() && !book.resources_settled());
            assert_eq!(book.problem_at(), problem_at); assert!(book.raw.is_some());
        }
    }

    struct HeldCall {
        polls: Arc<AtomicUsize>, drops: Arc<AtomicUsize>, ready: Arc<AtomicBool>,
        panic_on_poll: bool, result: Option<zbus::Result<Message>>,
    }
    impl Future for HeldCall {
        type Output = zbus::Result<Message>;
        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panic_on_poll, "synthetic original poll failure");
            if self.ready.load(Ordering::SeqCst) { Poll::Ready(self.result.take().unwrap()) } else { Poll::Pending }
        }
    }
    impl Drop for HeldCall { fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); } }
    fn held(polls: &Arc<AtomicUsize>, drops: &Arc<AtomicUsize>, ready: &Arc<AtomicBool>, result: zbus::Result<Message>, panic_on_poll: bool) -> RpcFuture {
        Box::pin(HeldCall { polls: polls.clone(), drops: drops.clone(), ready: ready.clone(), result: Some(result), panic_on_poll })
    }
    #[test]
    fn startup_owner_loss_and_stop_retain_original_calls_and_cleanup_errors() {
        let mut book = data_book();
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        book.admit_with(Step::AddMatch, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), false))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(tick(&mut book, DataTurn::Item(2, Ok(owner_event()))).is_pending());
        book.interrupt();
        let original_failure_at = book.problem_at();
        let observer = std::future::poll_fn(|cx| book.poll(cx)); drop(observer);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 3);
        assert_eq!(book.problem(), Some(Problem::OwnerChanged));
        ready.store(true, Ordering::SeqCst);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(tick(&mut book, DataTurn::Drained).is_pending());
        assert!(book.owner.is_none()); // startup cannot infer/re-resolve a baseline
        assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
        book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| Ok(Box::pin(std::future::ready(Err(zbus::Error::InvalidReply))))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert!(tick(&mut book, DataTurn::Idle).is_pending()); // transport error, no invented boundary
        book.commit_removal_reply(); // DATA has no local shutdown admission.
        assert!(book.cleanup_unknown());
        assert_eq!(book.phase, Phase::Holding);
        assert_eq!(book.problem(), Some(Problem::OwnerChanged));
        assert_eq!(book.problem_at(), original_failure_at);
        assert!(book.raw.is_some() && !book.resources_settled());
    }
    #[test]
    fn failed_build_and_coordinator_panic_never_reset_started_custody() {
        let input = input(); let mut book = LookupBook::new();
        book.begin_with(input.query, input.rule, data_deadline(), Box::pin(std::future::ready(Err(zbus::Error::InvalidReply)))).unwrap();
        assert!(book.started() && !book.resources_settled()); // before first build poll
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(book.poll(&mut cx), Poll::Ready(Next::FirstPoll)));
        book.first_poll(&mut cx, Ok(data_deadline()));
        assert!(book.connect_failure.is_some() && book.attempt.is_none());
        book.interrupt();
        assert_eq!(book.problem(), Some(Problem::Unavailable));
        assert!(!book.resources_settled());

        let mut book = data_book();
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        book.admit_with(Step::AddMatch, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), true))).unwrap();
        let retained = std::sync::Mutex::new(book);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut book = retained.lock().unwrap(); let _ = tick(&mut book, DataTurn::Idle);
        }));
        assert!(failure.is_err() && retained.is_poisoned());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let book = match retained.lock() { Err(error) => error.into_inner(), Ok(_) => panic!("synthetic panic must poison its book") };
        assert!(book.pending.is_some() && !book.resources_settled());
        // No repoll or native-finality claim after the original coordinator failed.
    }
    #[test]
    fn predispatch_interruption_never_polls_a_new_provider_or_resets_finality() {
        let mut book = data_book(); let mut registered = Vec::new(); select_owner(&mut book, &mut registered);
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        book.admit_with(Step::SearchItems, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(":1.23", &())), false))).unwrap();
        book.interrupt(); assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1); // only a never-polled future
        assert!(book.raw.is_none());
        assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
        assert!(!book.resources_settled());

        let mut book = data_book(); let mut registered = Vec::new(); select_owner(&mut book, &mut registered);
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        book.admit_with(Step::SearchItems, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(":1.23", &())), false))).unwrap();
        let unrelated = Message::signal("/other", "org.example.Other", "Changed").unwrap().sender(":1.9").unwrap().build(&()).unwrap();
        assert!(tick(&mut book, DataTurn::Item(1, Ok(unrelated))).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0); // another queued event must be drained before first send
        assert!(tick(&mut book, DataTurn::Item(2, Ok(owner_event()))).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(book.problem(), Some(Problem::OwnerChanged));
        assert!(book.raw.is_none() && !book.resources_settled());
    }
    #[test]
    fn cutoff_refuses_first_poll_but_never_drops_an_already_polled_original() {
        for step in [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::Attributes, Step::RemoveMatch] {
            let mut book = data_book(); book.phase = Phase::Admit(step);
            book.registration = if step == Step::AddMatch { Registration::Unsent } else { Registration::Registered };
            let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
            book.admit_with(step, Instant::now(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), false))).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(book.phase, if step.cleanup() || step == Step::AddMatch { Phase::Holding } else { Phase::Admit(Step::RemoveMatch) });
            assert!(!book.resources_settled());
        }
        let mut book = data_book(); book.phase = Phase::Admit(Step::RemoveMatch); book.registration = Registration::Registered;
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), false))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        if let Some(Pending::Rpc { dispatch_end, .. }) = book.pending.as_mut() { *dispatch_end = Instant::now(); }
        book.interrupt();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        ready.store(true, Ordering::SeqCst);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert!(tick(&mut book, DataTurn::Drained).is_pending());
        book.commit_removal_reply(); // DATA has no local shutdown admission.
        assert_eq!(book.registration, Registration::Removed); // late own removal, not overall success
        assert_eq!(book.problem(), Some(Problem::Interrupted));
        assert!(!book.resources_settled());
    }
    #[test]
    fn final_first_poll_requires_one_use_readiness_and_rechecks_effective_time() {
        let mut cx = Context::from_waker(Waker::noop());
        for readiness in [false, true] {
            let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
            let ready = Arc::new(AtomicBool::new(false));
            let mut book = LookupBook::cleanup_data(data_deadline(), held(&polls, &drops, &ready, Ok(reply(BUS, &())), false));
            if readiness { assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPoll))); }
            // Even a grant obtained before this instant cannot authorize a poll
            // after its now-expired effective end. Without readiness, no grant
            // is consumed and the original future is kept, never polled.
            book.first_poll(&mut cx, Ok(Instant::now()));
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), if readiness { 1 } else { 0 });
            assert_eq!(book.problem(), Some(Problem::CleanupUnknown));
            assert!(!book.resources_settled());
        }
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(AtomicBool::new(false));
        let mut book = LookupBook::cleanup_data(data_deadline(), held(&polls, &drops, &ready, Ok(reply(BUS, &())), false));
        assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPoll)));
        assert!(book.advance(&mut cx, StreamTurn::Observed(None)).is_pending());
        book.first_poll(&mut cx, Ok(data_deadline())); // Another stream turn invalidated readiness.
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        let mut book = LookupBook::cleanup_data(data_deadline(), held(&polls, &drops, &ready, Ok(reply(BUS, &())), false));
        let shorter_end = Instant::now() + std::time::Duration::from_secs(30);
        assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPoll)));
        book.first_poll(&mut cx, Ok(shorter_end));
        assert!(matches!(book.pending, Some(Pending::Rpc { dispatch_end, .. }) if dispatch_end == shorter_end));
        book.first_poll(&mut cx, Ok(data_deadline())); // The one-use readiness is spent.
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(book.idle_data_turn(&mut cx).is_pending()); // Still drive this already-polled original.
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
}
