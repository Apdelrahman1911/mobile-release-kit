//! Finite checks of the actual retained SDK originals, enabled only by the
//! explicit debug Linux application test graph. Nothing runs on import.
//!
//! The first six helpers use memory-only socket halves and actual Tokio Tasks;
//! they are NOT transport/authentication evidence. The final two helpers use
//! isolated Unix sockets and must be selected separately after native admission.
//! No ordinary Connection or MessageStream leaves this module.

use std::{
    collections::VecDeque,
    future::{pending, poll_fn},
    os::fd::AsFd,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
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
