//! Fixed non-mutating key-identity lookup, owned by asset_session::OriginalWork.
//!
//! No renderer/session command calls this phase. Endpoint/provider qualification,
//! pre-allocation limits and maintained SDK task joins are still missing. A
//! started book therefore NEVER grants finality, even when lookup/removal return.
//! Connection::close, graceful_shutdown and coordinator return are not joins.

use std::{future::Future, os::unix::ffi::OsStrExt, path::{Component, Path}, pin::Pin,
    sync::Arc, task::{Context, Poll}, time::Instant};
use ordered_stream::{OrderedStream, PollResult};
use secret_service::checked_lookup;
use zbus::{address::{transport::{Unix, UnixSocket}, Transport}, connection::Builder,
    message::Type, names::UniqueName, zvariant::OwnedObjectPath, Address, Connection,
    MatchRule, Message, MessageStream};

const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const SERVICE: &str = "org.freedesktop.secrets";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Problem {
    InvalidInput, Unavailable, InvalidReply, IdentityMismatch, OwnerChanged,
    StreamFailed, Interrupted, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step { AddMatch, GetNameOwner, SearchItems, Attributes, RemoveMatch }
impl Step { pub(crate) fn cleanup(self) -> bool { self == Self::RemoveMatch } }
pub(crate) enum Next { Admit(Step), FirstPoll }
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
pub(crate) struct LookupInput { address: Address, query: Arc<Query>, rule: Arc<MatchRule<'static>> }
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
        Ok(Self { address: Address::new(Transport::Unix(Unix::new(UnixSocket::File(endpoint.to_path_buf())))),
            query: Arc::new(Query { collection, vault_id: vault_id.into(), generation_id: generation_id.into() }), rule: Arc::new(rule) })
    }
}

type ConnectFuture = Pin<Box<dyn Future<Output = zbus::Result<Connection>> + Send>>;
type RpcFuture = Pin<Box<dyn Future<Output = zbus::Result<Message>> + Send>>;
enum Pending {
    Connect { future: ConnectFuture, polled: bool, dispatch_end: Instant },
    Rpc { future: RpcFuture, polled: bool, dispatch_end: Instant },
}

pub(crate) enum Observation { Absent, Candidate(Arc<OwnedObjectPath>) }

pub(crate) struct LookupBook {
    entered: bool, phase: Phase, connection: Option<Connection>, stream: Option<MessageStream>,
    stream_ended: bool, pending: Option<Pending>, first_poll_ready: bool, connect_failure: Option<zbus::Error>,
    raw: Option<zbus::Result<Message>>, raw_pending: bool,
    owner: Option<Arc<UniqueName<'static>>>, query: Option<Arc<Query>>, rule: Option<Arc<MatchRule<'static>>>,
    candidate: Option<Arc<OwnedObjectPath>>, observation: Option<Observation>,
    problem: Option<Problem>, problem_at: Option<Instant>, registration: Registration,
}
impl LookupBook {
    pub(crate) fn new() -> Self {
        Self { entered: false, phase: Phase::Unstarted, connection: None, stream: None,
            stream_ended: false, pending: None, first_poll_ready: false, connect_failure: None, raw: None, raw_pending: false,
            owner: None, query: None, rule: None, candidate: None, observation: None,
            problem: None, problem_at: None, registration: Registration::Unsent }
    }
    pub(crate) fn resources_settled(&self) -> bool { !self.entered }
    pub(crate) fn started(&self) -> bool { self.entered }
    pub(crate) fn problem(&self) -> Option<Problem> { self.problem }
    pub(crate) fn problem_at(&self) -> Option<Instant> { self.problem_at }
    pub(crate) fn cleanup_unknown(&self) -> bool { self.registration == Registration::Unknown }
    pub(crate) fn observation(&self) -> Option<&Observation> {
        if self.problem.is_none() { self.observation.as_ref() } else { None }
    }
    fn fail(&mut self, problem: Problem) {
        if self.problem.is_none() { self.problem = Some(problem); self.problem_at = Some(Instant::now()); }
    }
    pub(crate) fn interrupt(&mut self) { self.fail(Problem::Interrupted); }

    pub(crate) fn begin(&mut self, input: LookupInput, dispatch_end: Instant) -> Result<(), Problem> {
        let LookupInput { address, query, rule } = input;
        self.begin_with(query, rule, dispatch_end, Box::pin(async move {
            // Explicit local file socket only. No environment/session fallback,
            // method_timeout, registered names, proxies or server interfaces.
            Builder::address(address)?.max_queued(1).build().await
        }))
    }
    fn begin_with(&mut self, query: Arc<Query>, rule: Arc<MatchRule<'static>>, dispatch_end: Instant, future: ConnectFuture) -> Result<(), Problem> {
        if self.entered || self.phase != Phase::Unstarted || self.pending.is_some() || self.problem.is_some() {
            return Err(Problem::CleanupUnknown);
        }
        // Permanent BEFORE the first Builder::build poll, including failed build
        // and no returned Connection. Neither cancellation nor panic can reset it.
        self.entered = true;
        self.query = Some(query); self.rule = Some(rule);
        self.phase = Phase::Connecting; self.pending = Some(Pending::Connect { future, polled: false, dispatch_end });
        Ok(())
    }
    pub(crate) fn current_step(&self) -> Option<Step> {
        match self.phase { Phase::Calling(step) => Some(step), _ => None }
    }
    pub(crate) fn expected(&self, step: Step) -> bool {
        self.phase == Phase::Admit(step) && self.pending.is_none() && !self.raw_pending
    }
    pub(crate) fn admit(&mut self, step: Step, dispatch_end: Instant) -> Result<(), Problem> {
        self.admit_with(step, dispatch_end, Self::rpc)
    }
    // Single actual dispatch-registration seam. Tests inject a DATA future here,
    // not an alternate lifecycle model, fake connection or native-test bypass.
    fn admit_with(&mut self, step: Step, dispatch_end: Instant, make: impl FnOnce(&Self, Step) -> Result<RpcFuture, Problem>) -> Result<(), Problem> {
        if !self.expected(step) || (!step.cleanup() && self.problem.is_some()) {
            return Err(self.problem.unwrap_or(Problem::CleanupUnknown));
        }
        if step.cleanup() && !matches!(self.registration, Registration::Possible | Registration::Registered) {
            return Err(Problem::CleanupUnknown);
        }
        let future = make(self, step)?;
        // A preceding raw result stays retained through reconciliation and the
        // final stream/document gate, then this one successor replaces it.
        self.raw = None; self.phase = Phase::Calling(step);
        self.pending = Some(Pending::Rpc { future, polled: false, dispatch_end });
        Ok(())
    }
    fn rpc(&self, step: Step) -> Result<RpcFuture, Problem> {
        let connection = self.connection.as_ref().ok_or(Problem::CleanupUnknown)?.clone();
        match step {
            Step::AddMatch | Step::RemoveMatch => {
                let rule = self.rule.clone().ok_or(Problem::CleanupUnknown)?;
                let method = if step == Step::AddMatch { "AddMatch" } else { "RemoveMatch" };
                Ok(Box::pin(async move { connection.call_method(Some(BUS), BUS_PATH, Some(BUS), method, rule.as_ref()).await }))
            }
            Step::GetNameOwner => Ok(Box::pin(async move {
                connection.call_method(Some(BUS), BUS_PATH, Some(BUS), "GetNameOwner", &SERVICE).await
            })),
            Step::SearchItems => {
                let owner = self.owner.clone().ok_or(Problem::CleanupUnknown)?;
                let query = self.query.clone().ok_or(Problem::CleanupUnknown)?;
                Ok(Box::pin(async move {
                    checked_lookup::search_items_reply(&connection, owner.as_ref(), &query.collection, &query.attributes()).await
                }))
            }
            Step::Attributes => {
                let owner = self.owner.clone().ok_or(Problem::CleanupUnknown)?;
                let item = self.candidate.clone().ok_or(Problem::CleanupUnknown)?;
                Ok(Box::pin(async move { checked_lookup::attributes_reply(&connection, owner.as_ref(), item.as_ref()).await }))
            }
        }
    }
    fn cleanup_or_hold(&mut self) {
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

    /// One coordinator polls BOTH originals, bounded to one stream item and one
    /// future poll per turn. No observer owns/takes these holdings. A failed or
    /// poisoned coordinator retains Unknown holdings; it cannot keep driving.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Next> {
        let reconciling = self.raw_pending;
        let boundary = if reconciling { self.raw.as_ref().and_then(raw_message).map(Message::recv_position) } else { None };
        let turn = match self.stream.as_mut() {
            Some(stream) if !self.stream_ended => stream_turn(stream, cx, boundary.as_ref()),
            _ => StreamTurn::Ended,
        };
        self.advance(cx, turn)
    }

    fn never_polled(&self) -> bool {
        matches!(self.pending.as_ref(), Some(Pending::Connect { polled: false, .. } | Pending::Rpc { polled: false, .. }))
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
        let refusal = match self.pending.as_mut() {
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
        };
        if let Some(problem) = refusal {
            self.fail(problem);
            if self.phase == Phase::Calling(Step::RemoveMatch) { self.registration = Registration::Unknown; }
            self.pending = None; // A never-polled future made no native request.
            self.cleanup_or_hold(); cx.waker().wake_by_ref(); return;
        }
        self.poll_pending(cx);
    }

    // Kept separate only to drive this exact state machine with synthetic DATA
    // streams in unit tests. Production always supplies the original stream's
    // real recv_position boundary above, never a caller ordering receipt.
    fn advance(&mut self, cx: &mut Context<'_>, turn: StreamTurn) -> Poll<Next> {
        self.first_poll_ready = false; // Readiness cannot survive another stream turn.
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
            self.pending = None; // no remote request, no fabricated raw reply
            self.cleanup_or_hold(); cx.waker().wake_by_ref(); return Poll::Pending;
        }
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

        if reconciling {
            if !has_boundary || matches!(turn, StreamTurn::Failed | StreamTurn::Ended) {
                // Transport errors have no position. Stream errors/end are not
                // NoneBefore receipts. Only own-subscription cleanup may follow.
                self.finish_reply(false); cx.waker().wake_by_ref(); return Poll::Pending;
            }
            if matches!(turn, StreamTurn::Drained) {
                self.finish_reply(true); cx.waker().wake_by_ref(); return Poll::Pending;
            }
        }
        if matches!(turn, StreamTurn::Observed(_)) { cx.waker().wake_by_ref(); }
        if let Phase::Admit(step) = self.phase {
            if !step.cleanup() && self.problem.is_some() {
                self.cleanup_or_hold(); cx.waker().wake_by_ref(); return Poll::Pending;
            }
            // Idle here is a FINAL nonblocking drain, not an ordering receipt.
            // The caller now checks the real document/slot/stop before admit().
            if matches!(turn, StreamTurn::Idle) || (step.cleanup() && matches!(turn, StreamTurn::Failed | StreamTurn::Ended)) {
                return Poll::Ready(Next::Admit(step));
            }
        }
        // A live stream is pumped even in Holding. A started book deliberately
        // cannot complete before maintained actual-original joins are supplied.
        Poll::Pending
    }

    // Called either with consumed final admission or an already-polled original.
    // In the latter case STOP/Unknown/cutoff never causes re-adoption/cancellation.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> bool {
        match self.pending.as_mut() {
            Some(Pending::Connect { future, polled, .. }) => { *polled = true; match future.as_mut().poll(cx) {
                Poll::Pending => {},
                Poll::Ready(Ok(connection)) => {
                    // Store the Connection before stream activation can fail.
                    self.connection = Some(connection);
                    if let Some(connection) = &self.connection { self.stream = Some(MessageStream::from(connection)); }
                    self.pending = None;
                    self.phase = if self.problem.is_none() { Phase::Admit(Step::AddMatch) } else { Phase::Holding };
                    cx.waker().wake_by_ref(); return true;
                }
                Poll::Ready(Err(error)) => {
                    self.connect_failure = Some(error); self.pending = None;
                    self.fail(Problem::Unavailable); self.phase = Phase::Holding;
                    return true; // No returned Connection is not SDK task joins.
                }
            } },
            Some(Pending::Rpc { future, polled, .. }) => {
                if !*polled && self.phase == Phase::Calling(Step::AddMatch) { self.registration = Registration::Possible; }
                *polled = true;
                if let Poll::Ready(result) = future.as_mut().poll(cx) {
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
            if result.is_ok() {
                self.registration = Registration::Removed;
                // This PLAIN stream has no implicit asynchronous RemoveMatch.
                self.stream = None;
            } else {
                self.registration = Registration::Unknown;
                self.fail(Problem::CleanupUnknown);
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
enum StreamTurn { Idle, Pending, Observed(Option<Problem>), Drained, Failed, Ended }

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
    // Actual-driver DATA seam for the real DocumentState/OriginalWork gate
    // regression. No Connection, stream, task or native receipt is fabricated.
    pub(crate) fn cleanup_data(dispatch_end: Instant, future: impl Future<Output = zbus::Result<Message>> + Send + 'static) -> Self {
        let mut book = Self::new();
        book.entered = true; book.phase = Phase::Admit(Step::RemoveMatch); book.registration = Registration::Registered;
        book.admit_with(Step::RemoveMatch, dispatch_end, |_, _| Ok(Box::pin(future))).unwrap();
        book
    }
    pub(crate) fn idle_data_turn(&mut self, cx: &mut Context<'_>) -> Poll<Next> {
        self.advance(cx, StreamTurn::Idle)
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
        book.entered = true; book.query = Some(input.query); book.rule = Some(input.rule);
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
        }
    }
    fn call(book: &mut LookupBook, step: Step, result: zbus::Result<Message>, registered: &mut Vec<Step>) {
        assert_eq!(tick(book, DataTurn::Idle), Poll::Ready(step));
        book.admit_with(step, data_deadline(), |_, actual| { registered.push(actual); Ok(Box::pin(std::future::ready(result))) }).unwrap();
        assert!(tick(book, DataTurn::Idle).is_pending()); // original returned, raw retained
        assert!(book.raw_pending);
        assert!(tick(book, DataTurn::Drained).is_pending()); // actual state-machine reconciliation
        assert!(!book.raw_pending);
    }
    fn select_owner(book: &mut LookupBook, registered: &mut Vec<Step>) {
        call(book, Step::AddMatch, Ok(reply(BUS, &())), registered);
        call(book, Step::GetNameOwner, Ok(reply(BUS, &":1.23")), registered);
        assert_eq!(book.owner.as_ref().unwrap().as_str(), ":1.23");
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
            assert_eq!(raw_message(book.raw.as_ref().unwrap()).unwrap().data().bytes().as_ptr(), bytes);
            assert!(tick(&mut book, DataTurn::Idle).is_pending()); // Pending with boundary is not drained
            assert!(book.raw_pending);
            assert!(tick(&mut book, failure).is_pending());
            assert!(!book.raw_pending);
            assert!(book.problem().is_some());
            assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
            assert!(matches!(book.raw, Some(Err(zbus::Error::MethodError(_, _, _)))));
        }
        let mut stream = DataStream(VecDeque::from([DataTurn::Drained]));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(stream_turn(&mut stream, &mut cx, None), StreamTurn::Failed);
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
        assert!(book.connect_failure.is_some() && book.connection.is_none());
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
