//! Finite checks of the actual retained SDK originals, enabled only by the
//! explicit debug Linux application test graph. Nothing runs on import.
//!
//! Memory-only helpers use scripted messages or bounded byte halves and actual
//! Tokio Tasks; they are NOT native transport/authentication evidence. Helpers
//! using Unix sockets require separate explicit native fixture admission.
//! No ordinary Connection or MessageStream leaves this module.

// These thin DATA entry points exercise the same private SDK implementations as
// its unit tests, through the app's existing dev-only feature. No new harness or
// vendored-SDK dev dependency graph is needed, and no checks run on import.
pub fn bounded_wire_frames() { crate::keyring_wire::tests::keyring_fragmented_frames_refuse_before_oversized_allocation(); }
pub fn bounded_wire_headers() { crate::keyring_wire::tests::keyring_borrowed_header_and_signature_gate(); }
pub fn bounded_wire_capacity() {
    crate::keyring_wire::tests::keyring_capped_writer_and_fixed_control_budget();
    crate::message::keyring_serializer_cannot_outgrow_its_estimate();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    let activity = Arc::new(AtomicUsize::new(0));
    tracing::subscriber::with_default(BoundedTraceProbe(activity.clone()), || {
        // Positive controls: a disabled subscriber must not make silence pass.
        tracing::trace!("bounded fixture subscriber positive event");
        drop(tracing::trace_span!("bounded fixture subscriber positive span"));
        assert_eq!(activity.swap(0, Ordering::SeqCst), 2);
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), bounded_original_queue_and_write())
                .await.expect("bounded original fixture did not consume its original work");
        });
        assert_eq!(activity.load(Ordering::SeqCst), 0, "bounded work emitted a tracing span/event");
    });
}
pub fn bounded_wire_authentication() { crate::connection::handshake::keyring_authentication_and_hello_use_the_bounded_transport(); }
pub fn bounded_wire_error_registration() { crate::connection::pending_method_calls::keyring_error_completion_consumes_only_the_matching_registration(); }

/// NATIVE: only the separately admitted Linux unnamed-pair fixture may call it.
#[cfg(target_os = "linux")]
pub fn bounded_wire_original_rights_disposal() {
    crate::connection::socket::unix::keyring_tests::keyring_zero_control_refuses_and_disposes_original_rights();
}

use std::{
    collections::VecDeque,
    future::{pending, poll_fn},
    os::fd::AsFd,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use tokio::sync::{Notify, oneshot};

use super::*;
use crate::{
    Executor,
    connection::{handshake::Authenticated, socket::{BoxedSplit, WriteHalf}},
};

#[derive(Debug, Default)]
struct Counts {
    reads: AtomicUsize,
    read_drops: AtomicUsize,
    sends: AtomicUsize,
    closes: AtomicUsize,
    write_drops: AtomicUsize,
    read_changed: Notify,
}

#[derive(Debug)]
struct MemoryRead {
    messages: VecDeque<Message>,
    counts: Arc<Counts>,
}

impl Drop for MemoryRead {
    fn drop(&mut self) { self.counts.read_drops.fetch_add(1, Ordering::SeqCst); }
}

#[async_trait::async_trait]
impl ReadHalf for MemoryRead {
    async fn receive_message(
        &mut self, seq: u64, _: &mut Vec<u8>, _: &mut Vec<OwnedFd>,
    ) -> Result<Message> {
        if let Some(message) = self.messages.pop_front() {
            self.counts.reads.fetch_add(1, Ordering::SeqCst);
            self.counts.read_changed.notify_one();
            // Only fixture DATA supplies bytes here. The actual SocketReader
            // owns its sequence, queue, pending-call dispatch and task.
            Message::from_raw_parts(message.data().clone(), seq)
        } else {
            pending().await
        }
    }
}

#[derive(Debug)]
struct MemoryWrite {
    counts: Arc<Counts>,
    close_error: Option<io::ErrorKind>,
}

impl Drop for MemoryWrite {
    fn drop(&mut self) { self.counts.write_drops.fetch_add(1, Ordering::SeqCst); }
}

#[async_trait::async_trait]
impl WriteHalf for MemoryWrite {
    async fn send_message(&mut self, _: &Message) -> Result<()> {
        self.counts.sends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.counts.closes.fetch_add(1, Ordering::SeqCst);
        self.close_error.map_or(Ok(()), |kind| Err(kind.into()))
    }
}

// Install through the SAME Connection constructor, receiver setup, reader
// constructor and original reader slot as build_owned. Only socket input and
// handshake output are fixture DATA. This helper cannot qualify authentication.
async fn install_halves(shared: &Shared, read: Box<dyn ReadHalf>, write: Box<dyn WriteHalf>) -> Result<()> {
    let auth = Authenticated {
        socket_read: None,
        socket_write: write,
        server_guid: crate::Guid::try_from("0123456789abcdef0123456789abcdef")?.into(),
        cap_unix_fd: true,
        already_received_bytes: Vec::new(),
        already_received_fds: Vec::new(),
        unique_name: Some(":1.42".try_into()?),
    };
    let mut connection = Connection::new(auth, true, Executor::new(), None).await?;
    connection.set_max_queued(1);
    shared.install_connection(connection, read, Vec::new(), Vec::new())
}

fn unpolled_attempt() -> OwnedConnectionAttempt {
    // Every caller replaces this still-unpolled original before any poll.
    OwnedConnectionAttempt::unix(PathBuf::from("/synthetic/never-opened/bus")).unwrap()
}

fn memory_attempt(messages: VecDeque<Message>, close_error: Option<io::ErrorKind>, fail_after_reader: bool)
    -> (OwnedConnectionAttempt, Arc<Counts>)
{
    let mut attempt = unpolled_attempt();
    let shared = attempt.shared.clone();
    let counts = Arc::new(Counts::default());
    let read = MemoryRead { messages, counts: counts.clone() };
    let write = MemoryWrite { counts: counts.clone(), close_error };
    attempt.startup = Some(Box::pin(async move {
        install_halves(&shared, Box::new(read), Box::new(write)).await?;
        if fail_after_reader { Err(Error::InvalidReply) } else { Ok(()) }
    }));
    (attempt, counts)
}

// Count without formatting or retaining fields. This thread-local subscriber
// covers the current-thread fixture and its actual reader task, not other tests.
struct BoundedTraceProbe(Arc<AtomicUsize>);
impl tracing::Subscriber for BoundedTraceProbe {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(self.0.fetch_add(1, Ordering::SeqCst) as u64 + 1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[derive(Debug, Default)]
struct BoundedFixture {
    received_bytes: AtomicUsize,
    largest_receive: AtomicUsize,
    outbound_bytes: AtomicUsize,
    write_released: AtomicBool,
    release_write: Notify,
}

#[derive(Debug)]
struct BoundedByteRead {
    input: Arc<[u8]>,
    position: usize,
    counts: Arc<Counts>,
    fixture: Arc<BoundedFixture>,
}
impl Drop for BoundedByteRead {
    fn drop(&mut self) { self.counts.read_drops.fetch_add(1, Ordering::SeqCst); }
}
#[async_trait::async_trait]
impl ReadHalf for BoundedByteRead {
    fn is_keyring_wire(&self) -> bool { true }
    // Do NOT override receive_message: real bounded framing/preflight and all
    // erased transport-future gates must consume these fragmented fixture bytes.
    async fn recvmsg(&mut self, buffer: &mut [u8]) -> std::io::Result<(usize, Vec<OwnedFd>)> {
        if self.position == self.input.len() { return pending().await; }
        assert!(!buffer.is_empty());
        self.fixture.largest_receive.fetch_max(buffer.len(), Ordering::SeqCst);
        let count = buffer.len().min(47).min(self.input.len() - self.position);
        buffer[..count].copy_from_slice(&self.input[self.position..self.position + count]);
        self.position += count;
        self.fixture.received_bytes.store(self.position, Ordering::SeqCst);
        if self.position % crate::keyring_wire::FRAME_BYTES == 0 {
            self.counts.reads.fetch_add(1, Ordering::SeqCst);
            self.counts.read_changed.notify_one();
        }
        Ok((count, Vec::new()))
    }
}

#[derive(Debug)]
struct BoundedByteWrite {
    counts: Arc<Counts>,
    fixture: Arc<BoundedFixture>,
}
impl Drop for BoundedByteWrite {
    fn drop(&mut self) { self.counts.write_drops.fetch_add(1, Ordering::SeqCst); }
}
#[async_trait::async_trait]
impl WriteHalf for BoundedByteWrite {
    fn is_keyring_wire(&self) -> bool { true }
    // The real bounded serializer/default send_message retains its Message
    // through this Pending sendmsg; no prepared-message send override is used.
    async fn sendmsg(&mut self, buffer: &[u8], fds: &[std::os::fd::BorrowedFd<'_>]) -> io::Result<usize> {
        assert!(fds.is_empty());
        assert_eq!(buffer.len(), crate::keyring_wire::FRAME_BYTES);
        assert_eq!(buffer[1], 1); // Actual method call, not a fabricated reply.
        assert_eq!(buffer[buffer.len() - 1], 0x52);
        crate::keyring_wire::preflight(buffer).unwrap();
        assert_eq!(self.counts.sends.fetch_add(1, Ordering::SeqCst), 0);
        self.fixture.outbound_bytes.store(buffer.len(), Ordering::SeqCst);
        loop {
            let released = self.fixture.release_write.notified();
            if self.fixture.write_released.load(Ordering::SeqCst) { break; }
            released.await;
        }
        Err(io::ErrorKind::Interrupted.into())
    }
    async fn close(&mut self) -> io::Result<()> {
        assert!(self.fixture.write_released.load(Ordering::SeqCst));
        assert_eq!(self.counts.read_drops.load(Ordering::SeqCst), 1);
        assert_eq!(self.counts.closes.fetch_add(1, Ordering::SeqCst), 0);
        Ok(())
    }
}

fn bounded_signal_bytes(value: u8) -> Vec<u8> {
    let builder = || Message::signal("/fixture", "org.example.Fixture", "Changed").unwrap().keyring_wire(true);
    let overhead = builder().build(&Vec::<u8>::new()).unwrap().data().len();
    let message = builder().build(&vec![value; crate::keyring_wire::FRAME_BYTES - overhead]).unwrap();
    assert_eq!(message.data().len(), crate::keyring_wire::FRAME_BYTES);
    message.data().to_vec()
}

/// DATA only: actual bounded queues/futures/serialization and original joins.
/// The supplied Authenticated value and byte halves are NOT native transport or
/// authentication evidence. Fixture input/output backing is separate from the
/// attempted allowance; this does not measure allocator overhead or process RSS.
async fn bounded_original_queue_and_write() {
    use crate::keyring_wire::{FRAME_BYTES, future_fits};
    assert_eq!(Handle::current().runtime_flavor(), tokio::runtime::RuntimeFlavor::CurrentThread);
    let mut attempt = OwnedConnectionAttempt::keyring_unix(PathBuf::from("/synthetic/never-opened/bus")).unwrap();
    assert!(attempt.keyring_wire && !attempt.startup_polled);
    future_fits(attempt.startup.as_ref().unwrap().as_ref().get_ref()).unwrap();
    let shared = attempt.shared.clone();
    let counts = Arc::new(Counts::default());
    let fixture = Arc::new(BoundedFixture::default());
    let mut bytes = bounded_signal_bytes(0x31);
    bytes.extend_from_slice(&bounded_signal_bytes(0x32));
    let input: Arc<[u8]> = bytes.into();
    let input_lifetime = Arc::downgrade(&input);
    let read = BoundedByteRead { input, position: 0, counts: counts.clone(), fixture: fixture.clone() };
    let write = BoundedByteWrite { counts: counts.clone(), fixture: fixture.clone() };
    // Only the unpolled native connect is replaced. Keep the real constructor's
    // census/flags/runtime/Shared, then the ordinary Connection and reader path.
    attempt.startup = Some(Box::pin(async move {
        let auth = Authenticated {
            socket_read: None, socket_write: Box::new(write),
            server_guid: crate::Guid::try_from("0123456789abcdef0123456789abcdef")?.into(),
            cap_unix_fd: false, already_received_bytes: Vec::new(), already_received_fds: Vec::new(),
            unique_name: Some(":1.42".try_into()?),
        };
        let connection = Connection::new(auth, true, Executor::new(), None).await?;
        assert!(connection.inner.keyring_wire && !connection.inner.cap_unix_fd);
        assert_eq!(connection.inner.msg_receiver.capacity(), 1);
        shared.install_connection(connection, Box::new(read), Vec::new(), Vec::new())
    }));
    poll_fn(|cx| attempt.poll_build(cx)).await.unwrap();
    loop {
        let changed = counts.read_changed.notified();
        if counts.reads.load(Ordering::SeqCst) == 2 { break; }
        changed.await;
    }
    assert_eq!(fixture.received_bytes.load(Ordering::SeqCst), 2 * FRAME_BYTES);
    assert_eq!(fixture.largest_receive.load(Ordering::SeqCst), FRAME_BYTES - 16);
    let connection_lifetime = {
        let state = attempt.shared.lock().unwrap();
        let connection = state.connection.as_ref().unwrap();
        assert_eq!(state.stream.as_ref().unwrap().max_queued(), 1);
        assert_eq!(connection.inner.msg_receiver.len(), 1);
        assert!(mutex_held(&connection.inner.msg_senders, &mut Context::from_waker(std::task::Waker::noop())));
        Arc::downgrade(&connection.inner)
    };
    // First max frame is queued; the second has been assembled by the bounded
    // receive and parks the actual reader in broadcast, holding its queue lock.
    let overhead = Message::method_call("/fixture", "Check").unwrap().sender(":1.42").unwrap()
        .destination(":1.23").unwrap().interface("org.example.Fixture").unwrap()
        .keyring_wire(true).build(&Vec::<u8>::new()).unwrap().data().len();
    raw_call(&mut attempt, vec![0x52u8; FRAME_BYTES - overhead]).unwrap();
    future_fits(attempt.call.as_ref().unwrap().as_ref().get_ref()).unwrap();
    poll_fn(|cx| {
        assert!(attempt.poll_raw_call(cx).is_pending());
        if counts.sends.load(Ordering::SeqCst) == 1 { Poll::Ready(()) } else { Poll::Pending }
    }).await;
    assert_eq!(fixture.outbound_bytes.load(Ordering::SeqCst), FRAME_BYTES);
    assert!(attempt.call.is_some() && attempt.call_state == CallState::Entered);
    assert!(attempt.refuse_unpolled_call().is_err() && attempt.release_stream().is_err());
    {
        let state = attempt.shared.lock().unwrap();
        assert!(mutex_held(&state.connection.as_ref().unwrap().inner.socket_write,
            &mut Context::from_waker(std::task::Waker::noop())));
    }
    // No close/finality while the original serializer/send future is retained.
    // Join the REAL reader while both stream and Pending original RPC still live.
    let reader = poll_fn(|cx| {
        assert!(attempt.poll_local_shutdown(cx).is_pending());
        let state = attempt.shared.lock().unwrap();
        assert!(state.stopping && state.pending_failed && state.stream.is_some());
        match state.reader { ReaderSlot::Terminal(outcome) => Poll::Ready(outcome), _ => Poll::Pending }
    }).await;
    assert_eq!(reader, ReaderOutcome::RequestedCancellation);
    assert!(attempt.shutdown_entered && attempt.call.is_some());
    assert!(!fixture.write_released.load(Ordering::SeqCst));
    assert_eq!(counts.read_drops.load(Ordering::SeqCst), 1);
    assert!(input_lifetime.upgrade().is_none());
    assert_eq!(counts.closes.load(Ordering::SeqCst), 0);
    assert_eq!(counts.write_drops.load(Ordering::SeqCst), 0);
    // This fixture-only release follows the observed original shutdown, never
    // substitutes for it or produces a finality receipt. No native I/O occurs.
    fixture.write_released.store(true, Ordering::SeqCst);
    fixture.release_write.notify_one();
    let result = poll_fn(|cx| attempt.poll_raw_call(cx)).await;
    assert!(matches!(result, Err(Error::InputOutput(ref error)) if error.kind() == io::ErrorKind::Interrupted));
    drop(result);
    assert!(attempt.call.is_none() && attempt.call_state == CallState::Returned);
    let queued = match once(|cx| Pin::new(&mut attempt).poll_next_before(cx, None)).await {
        Poll::Ready(PollResult::Item { data: Ok(message), .. }) => message,
        _ => panic!("original capacity-one queue lost its first bounded frame"),
    };
    assert_eq!(queued.data().len(), FRAME_BYTES);
    assert_eq!(queued.data()[FRAME_BYTES - 1], 0x31);
    drop(queued);
    let result = settle(&mut attempt).await;
    assert_eq!(result.reader, reader);
    assert!(result.clean() && !attempt.cleanup_failed());
    assert_eq!(counts.reads.load(Ordering::SeqCst), 2);
    assert_eq!(counts.sends.load(Ordering::SeqCst), 1);
    assert_eq!(counts.closes.load(Ordering::SeqCst), 1);
    assert_eq!(counts.read_drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.write_drops.load(Ordering::SeqCst), 1);
    assert!(connection_lifetime.upgrade().is_none());
}

async fn once<T>(mut poll: impl FnMut(&mut Context<'_>) -> Poll<T>) -> Poll<T> {
    poll_fn(|cx| Poll::Ready(poll(cx))).await
}

fn mutex_held<T>(mutex: &crate::async_lock::Mutex<T>, cx: &mut Context<'_>) -> bool {
    // The SDK can compile either mutex backend. Polling this temporary lock
    // observer once avoids assuming their different try_lock return types.
    std::pin::pin!(mutex.lock()).as_mut().poll(cx).is_pending()
}

async fn settle(attempt: &mut OwnedConnectionAttempt) -> LocalSettlement {
    attempt.release_stream().unwrap();
    let result = poll_fn(|cx| attempt.poll_local_shutdown(cx)).await;
    let state = attempt.shared.lock().unwrap();
    assert!(state.connection.is_none() && state.stream.is_none() && state.control.is_none());
    assert!(matches!(state.reader, ReaderSlot::Terminal(_)));
    assert!(attempt.startup.is_none() && attempt.call.is_none() && attempt.close.is_none());
    drop(state);
    assert!(once(|cx| attempt.poll_local_shutdown(cx)).await.is_pending()); // No second receipt.
    result
}

fn raw_call<B: serde::Serialize + DynamicType + Send + Sync + 'static>(attempt: &mut OwnedConnectionAttempt, body: B) -> Result<()> {
    attempt.start_raw_call(":1.23".try_into()?, "/fixture".try_into()?,
        "org.example.Fixture".try_into()?, "Check".try_into()?, body)
}

struct DropWitness {
    drops: Arc<AtomicUsize>,
    changed: Option<oneshot::Sender<()>>,
}
impl Drop for DropWitness {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        if let Some(changed) = self.changed.take() { let _ = changed.send(()); }
    }
}

async fn stop_reader(task: Task<()>) -> ReaderOutcome {
    let shared = Shared::new();
    shared.lock().unwrap().reader = ReaderSlot::Running { task, cancellation_requested: false };
    poll_fn(|cx| {
        let mut state = shared.lock().unwrap();
        state.poll_reader_stop(cx).unwrap();
        match state.reader {
            ReaderSlot::Terminal(outcome) => Poll::Ready(outcome),
            _ => Poll::Pending,
        }
    }).await
}

/// Actual normal, Pending/cancelled, panic and already-cancelled joins.
pub async fn original_task_join_outcomes() {
    // These finite app wrappers intentionally use a current-thread runtime:
    // after a task's drop notification is received, that task's terminal turn
    // has finished before the observer can inspect its still-owned JoinHandle.
    assert_eq!(Handle::current().runtime_flavor(), tokio::runtime::RuntimeFlavor::CurrentThread);
    let drops = Arc::new(AtomicUsize::new(0));

    let (done, finished) = oneshot::channel();
    let witness = DropWitness { drops: drops.clone(), changed: Some(done) };
    let task = Executor::new().spawn(async move { drop(witness); }, "owned normal fixture");
    finished.await.unwrap();
    assert_eq!(stop_reader(task).await, ReaderOutcome::Returned);

    let (entered, started) = oneshot::channel();
    let witness = DropWitness { drops: drops.clone(), changed: None };
    let mut task = Executor::new().spawn(async move {
        let _witness = witness;
        entered.send(()).unwrap();
        pending::<()>().await;
    }, "owned pending fixture");
    started.await.unwrap();
    assert!(once(|cx| task.poll_tokio_join(cx)).await.is_pending());
    assert_eq!(stop_reader(task).await, ReaderOutcome::RequestedCancellation);

    let (done, finished) = oneshot::channel();
    let witness = DropWitness { drops: drops.clone(), changed: Some(done) };
    let payload_drops = Arc::new(AtomicUsize::new(0));
    let payload = DropWitness { drops: payload_drops.clone(), changed: None };
    let task = Executor::new().spawn(async move {
        let _witness = witness;
        std::panic::panic_any(payload);
    }, "owned panic fixture");
    finished.await.unwrap();
    assert_eq!(payload_drops.load(Ordering::SeqCst), 0); // Held by the actual JoinError.
    assert_eq!(stop_reader(task).await, ReaderOutcome::Panicked);
    assert_eq!(payload_drops.load(Ordering::SeqCst), 1); // Consumed, not retained as an opaque payload.

    let (done, finished) = oneshot::channel();
    let witness = DropWitness { drops: drops.clone(), changed: Some(done) };
    let mut task = Executor::new().spawn(async move {
        let _witness = witness;
        pending::<()>().await;
    }, "owned unexpected cancellation fixture");
    assert!(task.request_tokio_cancel()); // Deliberately NOT the owned reader stop request.
    finished.await.unwrap();
    assert_eq!(stop_reader(task).await, ReaderOutcome::UnexpectedCancellation);
    assert_eq!(drops.load(Ordering::SeqCst), 4);
}

/// A terminal startup Err accounts for its real pre/post-reader task roster.
pub async fn original_startup_error_roster() {
    let mut before = unpolled_attempt();
    before.startup = Some(Box::pin(async { Err(Error::InvalidReply) }));
    assert!(poll_fn(|cx| before.poll_build(cx)).await.is_err());
    assert!(matches!(before.shared.lock().unwrap().reader, ReaderSlot::Terminal(ReaderOutcome::NotStarted)));
    assert_eq!(settle(&mut before).await.reader, ReaderOutcome::NotStarted);

    let (mut after, counts) = memory_attempt(VecDeque::new(), None, true);
    assert!(poll_fn(|cx| after.poll_build(cx)).await.is_err());
    assert!(matches!(after.shared.lock().unwrap().reader, ReaderSlot::Running { .. }));
    assert_eq!(counts.write_drops.load(Ordering::SeqCst), 0);
    let result = settle(&mut after).await;
    assert_eq!(result.reader, ReaderOutcome::RequestedCancellation);
    assert!(result.clean());
    assert_eq!(counts.read_drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.write_drops.load(Ordering::SeqCst), 1);
}

/// Dropping an observer/starting stop cannot replace a Pending original startup.
pub async fn original_startup_survives_observer_loss() {
    let mut attempt = unpolled_attempt();
    let (finish, returned) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let witness = DropWitness { drops: drops.clone(), changed: None };
    attempt.startup = Some(Box::pin(async move {
        let _witness = witness;
        returned.await.unwrap()
    }));
    {
        let mut observer = Box::pin(poll_fn(|cx| attempt.poll_build(cx)));
        assert!(once(|cx| observer.as_mut().poll(cx)).await.is_pending());
    }
    assert!(attempt.refuse_unpolled_build().is_err());
    assert!(once(|cx| attempt.poll_local_shutdown(cx)).await.is_pending());
    assert!(attempt.startup.is_some() && !attempt.startup_consumed);
    assert!(matches!(attempt.shared.lock().unwrap().reader, ReaderSlot::BeforeStart));
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    finish.send(Err(Error::InvalidReply)).unwrap();
    assert!(poll_fn(|cx| attempt.poll_build(cx)).await.is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(settle(&mut attempt).await.reader, ReaderOutcome::NotStarted);
}

/// A real reader parked in a capacity-one broadcast is joined BEFORE queue locks.
pub async fn original_full_queue_reader_shutdown() {
    let signal = || Message::signal("/fixture", "org.example.Fixture", "Changed").unwrap().build(&()).unwrap();
    let (mut attempt, counts) = memory_attempt(VecDeque::from([signal(), signal()]), None, false);
    poll_fn(|cx| attempt.poll_build(cx)).await.unwrap();
    loop {
        let changed = counts.read_changed.notified();
        if counts.reads.load(Ordering::SeqCst) == 2 { break; }
        changed.await;
    }
    {
        let state = attempt.shared.lock().unwrap();
        assert_eq!(state.stream.as_ref().unwrap().max_queued(), 1);
        assert!(mutex_held(&state.connection.as_ref().unwrap().inner.msg_senders,
            &mut Context::from_waker(std::task::Waker::noop())));
    }
    // Keep the original stream alive. A stop implementation that first awaits
    // the queue mutex would deadlock here instead of consuming this real join.
    let outcome = poll_fn(|cx| {
        assert!(attempt.poll_local_shutdown(cx).is_pending());
        let state = attempt.shared.lock().unwrap();
        match state.reader {
            ReaderSlot::Terminal(outcome) => Poll::Ready(outcome),
            _ => Poll::Pending,
        }
    }).await;
    assert_eq!(outcome, ReaderOutcome::RequestedCancellation);
    assert_eq!(counts.closes.load(Ordering::SeqCst), 0);
    assert_eq!(counts.read_drops.load(Ordering::SeqCst), 1);
    assert!(settle(&mut attempt).await.clean());
    assert_eq!(counts.closes.load(Ordering::SeqCst), 1);
    assert_eq!(counts.write_drops.load(Ordering::SeqCst), 1);
}

/// Local stop fails the true pending reply, but only its original return clears it.
pub async fn original_raw_call_survives_observer_loss() {
    let (mut attempt, counts) = memory_attempt(VecDeque::new(), None, false);
    poll_fn(|cx| attempt.poll_build(cx)).await.unwrap();
    raw_call(&mut attempt, ()).unwrap();
    {
        let mut observer = Box::pin(poll_fn(|cx| attempt.poll_raw_call(cx)));
        assert!(once(|cx| observer.as_mut().poll(cx)).await.is_pending());
    }
    assert_eq!(counts.sends.load(Ordering::SeqCst), 1);
    assert!(attempt.refuse_unpolled_call().is_err());
    assert!(once(|cx| attempt.poll_local_shutdown(cx)).await.is_pending());
    assert!(attempt.call.is_some());
    assert!(attempt.release_stream().is_err());
    assert!(raw_call(&mut attempt, ()).is_err());
    let result = poll_fn(|cx| attempt.poll_raw_call(cx)).await;
    assert!(matches!(result, Err(Error::InputOutput(ref error)) if error.kind() == io::ErrorKind::Interrupted));
    drop(result);
    assert!(settle(&mut attempt).await.clean());
    assert_eq!(counts.sends.load(Ordering::SeqCst), 1);
    assert_eq!(counts.read_drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.write_drops.load(Ordering::SeqCst), 1);
}

/// An actual writer close error is a settled FAILURE, not successful cleanup.
pub async fn original_writer_close_failure() {
    let (mut attempt, counts) = memory_attempt(VecDeque::new(), Some(io::ErrorKind::PermissionDenied), false);
    poll_fn(|cx| attempt.poll_build(cx)).await.unwrap();
    let result = settle(&mut attempt).await;
    assert!(!result.clean() && attempt.cleanup_failed());
    assert_eq!(result.write_error, Some(LocalIoError { kind: io::ErrorKind::PermissionDenied, raw_os_error: None }));
    assert_eq!(counts.closes.load(Ordering::SeqCst), 1);
    assert_eq!(counts.read_drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.write_drops.load(Ordering::SeqCst), 1);
}

/// NATIVE, separately admitted: real nonblocking connect + ordinary client auth
/// waits on a silent private peer; same-socket shutdown wakes the original build.
/// `endpoint` must be absent inside the admitted private fixture directory. The
/// supervising test owner retains responsibility for its socket pathname cleanup.
pub async fn unix_pending_authentication_shutdown(endpoint: PathBuf) {
    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

    let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
    let mut attempt = OwnedConnectionAttempt::unix(endpoint).unwrap();
    let mut peer = None;
    let mut bytes = [0u8; 512];
    let mut received = 0;
    poll_fn(|cx| {
        if peer.is_none() {
            if let Poll::Ready(result) = listener.poll_accept(cx) { peer = Some(result.unwrap().0); }
        }
        assert!(attempt.poll_build(cx).is_pending(), "silent peer must leave the original handshake pending");
        if received == 0 {
            if let Some(peer) = peer.as_mut() {
                let mut buffer = ReadBuf::new(&mut bytes);
                if let Poll::Ready(result) = Pin::new(peer).poll_read(cx, &mut buffer) {
                    result.unwrap();
                    received = buffer.filled().len();
                    assert!(received > 0, "peer closed before ordinary SDK authentication activity");
                }
            }
        }
        if received > 0 && peer.is_some() && attempt.shared.lock().unwrap().control.is_some() { Poll::Ready(()) }
        else { Poll::Pending }
    }).await;
    assert!(once(|cx| attempt.poll_local_shutdown(cx)).await.is_pending());
    assert!(attempt.startup.is_some());
    assert!(poll_fn(|cx| attempt.poll_build(cx)).await.is_err());
    let result = settle(&mut attempt).await;
    assert_eq!(result.reader, ReaderOutcome::NotStarted);
    assert!(result.clean());
    let mut peer = peer.unwrap();
    loop {
        assert!(received < bytes.len(), "unexpectedly large fixture handshake");
        let count = peer.read(&mut bytes[received..]).await.unwrap();
        if count == 0 { break; }
        received += count;
    }
    assert!(received > 0, "ordinary SDK authentication bytes were never sent");
    drop(peer);
    drop(listener);
}

/// NATIVE, separately admitted: paired socket read/write wakeup, actual reader
/// join and received-FD disposition. Synthetic Authenticated is NOT auth proof.
/// The single 8MiB body is fixture data, not an aggregate-memory/bounds claim.
pub async fn unix_pending_write_and_received_fd_shutdown() {
    use std::io::Read;

    let (socket, peer) = tokio::net::UnixStream::pair().unwrap();
    let socket = socket.into_std().unwrap();
    let control = socket.try_clone().unwrap();
    let socket = tokio::net::UnixStream::from_std(socket).unwrap();
    let mut attempt = unpolled_attempt();
    let shared = attempt.shared.clone();
    assert!(!shared.install_control(control).unwrap());
    attempt.startup = Some(Box::pin(async move {
        let (read, write) = BoxedSplit::from(socket).take();
        install_halves(&shared, read, write).await
    }));
    poll_fn(|cx| attempt.poll_build(cx)).await.unwrap();
    eprintln!("MRK_UNIX2_STAGE=build-complete");
    let (mut peer_read, mut peer_write) = BoxedSplit::from(peer).take();

    raw_call(&mut attempt, ()).unwrap();
    assert!(once(|cx| attempt.poll_raw_call(cx)).await.is_pending());
    let request = {
        let mut bytes = Vec::new();
        let mut fds = Vec::new();
        let mut receive = std::pin::pin!(peer_read.receive_message(1, &mut bytes, &mut fds));
        // Pending does not mean the request was sent. Keep driving the same
        // retained call alongside one receive, preserving both across wakes.
        poll_fn(|cx| {
            assert!(attempt.poll_raw_call(cx).is_pending(),
                "fixture call returned before its peer received the request");
            receive.as_mut().poll(cx)
        }).await.unwrap()
    };
    eprintln!("MRK_UNIX2_STAGE=request-received");
    let (sent_fd, mut witness) = std::os::unix::net::UnixStream::pair().unwrap();
    witness.set_nonblocking(true).unwrap();
    let error_message = Message::error(&request.header(), "org.example.Refused").unwrap()
        .sender(":1.23").unwrap().build(&crate::zvariant::Fd::from(sent_fd.as_fd())).unwrap();
    peer_write.send_message(&error_message).await.unwrap();
    drop(error_message);
    drop(sent_fd);
    drop(request);
    eprintln!("MRK_UNIX2_STAGE=fd-error-sent");
    let raw_error = poll_fn(|cx| attempt.poll_raw_call(cx)).await.unwrap_err();
    let boundary = match &raw_error {
        Error::MethodError(_, _, message) => {
            assert_eq!(message.data().fds().len(), 1);
            message.recv_position()
        }
        _ => panic!("fixture did not return its actual FD-bearing MethodError"),
    };
    // Consume the actual same-stream copy through that raw error's boundary.
    loop {
        match poll_fn(|cx| Pin::new(&mut attempt).poll_next_before(cx, Some(&boundary))).await {
            PollResult::Item { data, .. } => drop(data),
            PollResult::NoneBefore => break,
            PollResult::Terminated => panic!("fixture stream ended before raw-error reconciliation"),
        }
    }
    let mut byte = [0u8; 1];
    assert_eq!(witness.read(&mut byte).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    eprintln!("MRK_UNIX2_STAGE=fd-error-reconciled");

    raw_call(&mut attempt, vec![0x41u8; 8 * 1024 * 1024]).unwrap();
    poll_fn(|cx| {
        assert!(attempt.poll_raw_call(cx).is_pending(), "fixture must park the original send");
        let state = attempt.shared.lock().unwrap();
        if mutex_held(&state.connection.as_ref().unwrap().inner.socket_write, cx) { Poll::Ready(()) }
        else { Poll::Pending }
    }).await;
    eprintln!("MRK_UNIX2_STAGE=pending-write-established");
    assert!(once(|cx| attempt.poll_local_shutdown(cx)).await.is_pending());
    assert!(attempt.call.is_some());
    assert!(poll_fn(|cx| attempt.poll_raw_call(cx)).await.is_err());
    eprintln!("MRK_UNIX2_STAGE=shutdown-call-consumed");
    let settlement = settle(&mut attempt).await;
    assert!(matches!(settlement.reader, ReaderOutcome::Returned | ReaderOutcome::RequestedCancellation));
    assert!(settlement.clean());
    // SDK local settlement intentionally does not include a transferred raw
    // Message. The app must consume it before its own resources_settled is true.
    assert_eq!(witness.read(&mut byte).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    drop(raw_error);
    assert_eq!(witness.read(&mut byte).unwrap(), 0);
    drop(witness);
    drop(peer_read);
    drop(peer_write);
}
