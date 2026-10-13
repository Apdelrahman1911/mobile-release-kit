//! A maintained fixed Tokio/Unix client with custody of its original tasks.
//!
//! This is deliberately not another general Connection API. It exposes only one
//! raw call at a time and the original ordered stream. It never exports an
//! ordinary Connection, MessageStream, executor, proxy or object server. Its
//! zero-or-one-reader roster therefore remains valid for the whole lifetime.

use std::{
    future::Future,
    io,
    net::Shutdown,
    os::{fd::OwnedFd, unix::{ffi::OsStrExt, net::UnixStream as Control}},
    path::{Component, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

use ordered_stream::{OrderedStream, PollResult};
use tokio::runtime::Handle;

use crate::{
    Connection, Error, Message, MessageStream, Result, Task,
    message::Sequence,
    names::{OwnedBusName, OwnedInterfaceName, OwnedMemberName},
    zvariant::{DynamicType, OwnedObjectPath},
};

use super::{Builder, socket::ReadHalf};

#[cfg(feature = "mrk-owned-test-support")]
#[doc(hidden)]
pub mod test_support;

type Startup = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
type Call = Pin<Box<dyn Future<Output = Result<Message>> + Send>>;
type Close = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// The result of consuming the actual reader JoinHandle, or of consuming an
/// exact terminal startup path which did not start a reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderOutcome {
    NotStarted,
    Returned,
    RequestedCancellation,
    UnexpectedCancellation,
    Panicked,
    JoinFailed,
}

impl ReaderOutcome {
    fn clean(self) -> bool {
        matches!(self, Self::NotStarted | Self::Returned | Self::RequestedCancellation)
    }
}

/// Non-owning diagnostics: retaining an arbitrary error/panic payload could
/// itself retain descriptors. The original error is consumed, never formatted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalIoError {
    pub kind: io::ErrorKind,
    pub raw_os_error: Option<i32>,
}

impl From<&io::Error> for LocalIoError {
    fn from(error: &io::Error) -> Self {
        Self { kind: error.kind(), raw_os_error: error.raw_os_error() }
    }
}

/// SDK-owned LOCAL resource settlement only. Returned raw Messages belong to
/// the caller and must also be reconciled/disposed before application finality.
/// This never certifies remote RemoveMatch, provider state or lookup success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalSettlement {
    pub reader: ReaderOutcome,
    pub control_error: Option<LocalIoError>,
    pub write_error: Option<LocalIoError>,
}

impl LocalSettlement {
    pub fn clean(self) -> bool {
        self.reader.clean() && self.control_error.is_none() && self.write_error.is_none()
    }
}

enum ReaderSlot {
    BeforeStart,
    Starting,
    Running { task: Task<()>, cancellation_requested: bool },
    Terminal(ReaderOutcome),
}

struct Retained {
    connection: Option<Connection>,
    stream: Option<MessageStream>,
    stream_released: bool,
    control: Option<Control>,
    control_attempted: bool,
    control_error: Option<LocalIoError>,
    reader: ReaderSlot,
    stopping: bool,
    pending_failed: bool,
}

#[derive(Clone)]
pub(super) struct Shared(Arc<Mutex<Retained>>);

fn state_error() -> Error { Error::Failure("owned client state is not reconciled".into()) }
fn stopped() -> Error { io::Error::from(io::ErrorKind::Interrupted).into() }

impl Shared {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Retained {
            connection: None, stream: None, stream_released: false,
            control: None, control_attempted: false, control_error: None,
            reader: ReaderSlot::BeforeStart, stopping: false, pending_failed: false,
        })))
    }

    fn lock(&self) -> Result<MutexGuard<'_, Retained>> {
        self.0.lock().map_err(|_| state_error())
    }

    fn install_control(&self, control: Control) -> Result<bool> {
        let mut state = self.lock()?;
        if state.control.is_some() || state.control_attempted { return Err(state_error()); }
        state.control = Some(control);
        // A late original connect inherits the already-entered shutdown. It
        // does not gain permission to start another Builder or cleanup lease.
        if state.stopping { state.shutdown_control(); }
        Ok(state.stopping)
    }

    pub(super) fn install_connection(
        &self,
        connection: Connection,
        socket_read: Box<dyn ReadHalf>,
        already_read: Vec<u8>,
        already_received_fds: Vec<OwnedFd>,
    ) -> Result<()> {
        let mut state = self.lock()?;
        if state.connection.is_some() || !matches!(state.reader, ReaderSlot::BeforeStart) {
            return Err(state_error());
        }
        // Retain the connection before stream setup or reader startup.
        state.connection = Some(connection.clone());
        if state.stopping { return Err(stopped()); }
        state.stream = Some(MessageStream::from(&connection));
        state.reader = ReaderSlot::Starting;
        // Nothing fallible is placed between obtaining the actual Task and
        // installation into the retained slot. A startup panic leaves Starting
        // or a poisoned state, never a fabricated NotStarted receipt.
        let reader = match connection.socket_reader(socket_read, already_read, already_received_fds)
            .spawn_owned(&connection.inner.executor) {
            Ok(task) => task,
            Err(error) => {
                // This refusal precedes the actual spawn. The same owner still
                // retains Connection/stream/control for original settlement.
                state.reader = ReaderSlot::Terminal(ReaderOutcome::NotStarted);
                return Err(error);
            }
        };
        state.reader = ReaderSlot::Running {
            task: reader,
            cancellation_requested: false,
        };
        Ok(())
    }
}

impl Retained {
    fn shutdown_control(&mut self) {
        if !self.control_attempted {
            if let Some(control) = self.control.as_ref() {
                self.control_attempted = true;
                if let Err(error) = control.shutdown(Shutdown::Both) {
                    self.control_error = Some(LocalIoError::from(&error));
                }
            }
        }
    }

    fn poll_reader_stop(&mut self, cx: &mut Context<'_>) -> Result<()> {
        let ReaderSlot::Running { task, cancellation_requested } = &mut self.reader else {
            return if matches!(self.reader, ReaderSlot::Starting) { Err(state_error()) } else { Ok(()) };
        };
        let result = match task.poll_tokio_join(cx) {
            Poll::Pending => {
                if !*cancellation_requested {
                    if !task.request_tokio_cancel() { return Err(state_error()); }
                    *cancellation_requested = true;
                }
                return Ok(());
            }
            Poll::Ready(result) => result,
        };
        let outcome = match result {
            Some(Ok(())) => ReaderOutcome::Returned,
            Some(Err(error)) if error.is_cancelled() => {
                if *cancellation_requested { ReaderOutcome::RequestedCancellation }
                else { ReaderOutcome::UnexpectedCancellation }
            }
            Some(Err(error)) if error.is_panic() => ReaderOutcome::Panicked,
            Some(Err(_)) => ReaderOutcome::JoinFailed,
            None => return Err(state_error()),
        };
        // The original JoinError/panic payload is consumed here too. Its exact
        // failure class is retained without potentially owning further FDs.
        self.reader = ReaderSlot::Terminal(outcome);
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallState { NeverCreated, Staged, Entered, Returned, Refused }

/// One non-cloneable original attempt. Its owner must keep driving already
/// entered startup/call/shutdown originals after cancellation or deadline.
/// Dropping it only requests cancellation through Task::Drop; drop is NOT join.
pub struct OwnedConnectionAttempt {
    shared: Shared,
    runtime: Handle,
    startup: Option<Startup>,
    startup_polled: bool,
    startup_consumed: bool,
    startup_succeeded: bool,
    call: Option<Call>,
    call_state: CallState,
    shutdown_entered: bool,
    close: Option<Close>,
    close_consumed: bool,
    write_error: Option<LocalIoError>,
    unreconciled: bool,
    settled: bool,
    keyring_wire: bool,
}

impl OwnedConnectionAttempt {
    /// No I/O/task is started here. The exact runtime and validated filesystem
    /// socket path are latched before the caller first polls this attempt.
    pub fn unix(endpoint: PathBuf) -> Result<Self> {
        Self::unix_profile(endpoint, false, None)
    }

    /// Application reservation for the fixed keyring wire profile, including
    /// every simultaneously retained SDK slot. Not a general process-RSS cap.
    pub const KEYRING_WIRE_BYTES: usize = crate::keyring_wire::ATTEMPT_BYTES;

    /// A zero-FD, 4-KiB SASL/header, 64-KiB frame client from its first byte.
    /// Like `unix`, construction does not start I/O or a task.
    pub fn keyring_unix(endpoint: PathBuf) -> Result<Self> {
        if !cfg!(target_os = "linux") { return Err(Error::Unsupported); }
        // The private application profile belongs to its own selected account.
        // Capture it before the future starts; do not infer it from a pathname
        // or SASL GUID. This is peer-UID checking, NOT provider attestation.
        Self::unix_profile(endpoint, true, Some(rustix::process::geteuid().as_raw()))
    }

    fn unix_profile(endpoint: PathBuf, keyring_wire: bool, expected_uid: Option<u32>) -> Result<Self> {
        if keyring_wire { Self::keyring_control_census()?; }
        let bytes = endpoint.as_os_str().as_bytes();
        if !endpoint.is_absolute() || bytes.is_empty() || bytes.len() > 107 || bytes.contains(&0)
            || endpoint.components().any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
        { return Err(Error::InvalidField); }
        let runtime = Handle::try_current().map_err(|_| Error::Unsupported)?;
        let shared = Shared::new();
        let startup_shared = shared.clone();
        let startup = async move {
            let socket = tokio::net::UnixStream::connect(endpoint).await?;
            let socket = socket.into_std()?;
            let control = socket.try_clone()?;
            // This same-socket duplicate is retained before from_std can panic,
            // and before the first poll of the original Builder/handshake.
            if startup_shared.install_control(control)? { return Err(stopped()); }
            let socket = tokio::net::UnixStream::from_std(socket)?;
            if let Some(expected_uid) = expected_uid {
                // Ordinary fixed SO_PEERCRED API: no NSS, process discovery,
                // task or authentication byte before this original-peer check.
                if socket.peer_cred()?.uid() != expected_uid {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
                }
            }
            Builder::unix_stream(socket).max_queued(1).build_owned(&startup_shared, keyring_wire).await
        };
        if keyring_wire { crate::keyring_wire::future_fits(&startup)?; }
        let startup = Box::pin(startup);
        Ok(Self {
            shared, runtime, startup: Some(startup), startup_polled: false,
            startup_consumed: false, startup_succeeded: false,
            call: None, call_state: CallState::NeverCreated,
            shutdown_entered: false, close: None, close_consumed: false,
            write_error: None, unreconciled: false, settled: false, keyring_wire,
        })
    }

    pub(crate) fn keyring_control_census() -> Result<crate::keyring_wire::control::FixedCensus> {
        use crate::keyring_wire::control::{self, LayoutInputs, TypeLayout};
        crate::keyring_wire::header_slot_bytes().ok_or(Error::Unsupported)?;
        let (keyring_read, keyring_write) = super::socket::unix::keyring_half_layouts();
        let [pending_mutex, reply_queue_entry, pending_map_entry, drained_sender] =
            super::pending_method_calls::keyring_control_layouts();
        control::fixed_census(LayoutInputs {
            retained_mutex: TypeLayout::of::<Mutex<Retained>>(),
            connection_inner: TypeLayout::of::<super::ConnectionInner>(),
            socket_status: TypeLayout::of::<super::SocketStatus>(),
            senders_mutex: TypeLayout::of::<crate::async_lock::Mutex<std::collections::HashMap<
                Option<crate::OwnedMatchRule>, super::MsgBroadcaster>>>(),
            pending_mutex,
            split_stream: TypeLayout::of::<tokio::net::UnixStream>(),
            keyring_read, keyring_write,
            owned_attempt: TypeLayout::of::<Self>(),
            unfiltered_queue_entry: TypeLayout::of::<(Result<Message>, usize)>(),
            reply_queue_entry,
            sender_map_entry: TypeLayout::of::<(Option<crate::OwnedMatchRule>, super::MsgBroadcaster)>(),
            pending_map_entry, drained_sender,
            command: super::handshake::keyring_command_layout(),
            local_error_backing_bytes: crate::keyring_wire::local_error_backing_bytes(),
        }).map_err(|_| Error::Unsupported)
    }

    pub fn poll_build(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let Some(startup) = self.startup.as_mut() else { return Poll::Ready(Err(state_error())); };
        // All native construction/spawning stays on the originally latched
        // Tokio backend even if a caller later polls from a different context.
        let _runtime = self.runtime.enter();
        self.startup_polled = true;
        let Poll::Ready(result) = startup.as_mut().poll(cx) else { return Poll::Pending; };
        self.startup = None; // Consume ONLY after the original future returned.
        let result = if self.keyring_wire { result.map_err(crate::keyring_wire::local_error) } else { result };
        let mut state = match self.shared.lock() {
            Ok(state) => state,
            Err(error) => { self.unreconciled = true; return Poll::Ready(Err(error)); }
        };
        match state.reader {
            ReaderSlot::BeforeStart if result.is_err() => state.reader = ReaderSlot::Terminal(ReaderOutcome::NotStarted),
            ReaderSlot::Running { .. } | ReaderSlot::Terminal(_) => {},
            _ => { self.unreconciled = true; return Poll::Ready(Err(state_error())); }
        }
        self.startup_consumed = true;
        self.startup_succeeded = result.is_ok();
        Poll::Ready(result)
    }

    /// The exact unpolled original made no native call. This is not available
    /// after even one Pending startup poll, and does not infer from empty state.
    pub fn refuse_unpolled_build(&mut self) -> Result<()> {
        if self.startup_polled || self.startup_consumed || self.startup.is_none() { return Err(state_error()); }
        self.startup = None;
        let mut state = self.shared.lock()?;
        if !matches!(state.reader, ReaderSlot::BeforeStart) || state.connection.is_some() || state.control.is_some() {
            self.unreconciled = true;
            return Err(state_error());
        }
        state.reader = ReaderSlot::Terminal(ReaderOutcome::NotStarted);
        self.startup_consumed = true;
        Ok(())
    }

    /// Stage one original raw call without polling it. All arguments are owned,
    /// so the owner can independently poll shutdown while this call is Pending.
    /// This forwards the ordinary SDK registration/send/reply implementation.
    pub fn start_raw_call<B>(
        &mut self,
        destination: OwnedBusName,
        path: OwnedObjectPath,
        interface: OwnedInterfaceName,
        member: OwnedMemberName,
        body: B,
    ) -> Result<()>
    where B: serde::Serialize + DynamicType + Send + Sync + 'static {
        if !self.startup_succeeded || self.call.is_some() || self.shutdown_entered || self.unreconciled {
            return Err(state_error());
        }
        let connection = {
            let state = self.shared.lock()?;
            if state.stopping { return Err(stopped()); }
            state.connection.as_ref().ok_or_else(state_error)?.clone()
        };
        let call = async move {
            connection.call_method(Some(destination), path, Some(interface), member, &body).await
        };
        if self.keyring_wire { crate::keyring_wire::future_fits(&call)?; }
        self.call = Some(Box::pin(call));
        self.call_state = CallState::Staged;
        Ok(())
    }

    pub fn poll_raw_call(&mut self, cx: &mut Context<'_>) -> Poll<Result<Message>> {
        let Some(call) = self.call.as_mut() else { return Poll::Ready(Err(state_error())); };
        let _runtime = self.runtime.enter();
        self.call_state = CallState::Entered;
        match call.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.call = None;
                self.call_state = CallState::Returned;
                Poll::Ready(if self.keyring_wire { result.map_err(crate::keyring_wire::local_error) } else { result })
            }
        }
    }

    pub fn refuse_unpolled_call(&mut self) -> Result<()> {
        if self.call_state != CallState::Staged || self.call.is_none() { return Err(state_error()); }
        self.call = None;
        self.call_state = CallState::Refused;
        Ok(())
    }

    /// Consume this actual plain stream after the caller has reconciled (or
    /// explicitly failed) its transferred raw results. No implicit RemoveMatch.
    pub fn release_stream(&mut self) -> Result<()> {
        if !self.startup_consumed || self.call.is_some() { return Err(state_error()); }
        let mut state = self.shared.lock()?;
        if let Some(stream) = state.stream.take() {
            // Consume through the ordinary SDK conversion, but keep the extra
            // Connection strictly internal and immediately dispose it. No
            // ordinary stream/connection or async-drop future escapes custody.
            let connection: Connection = stream.into();
            drop(connection);
        }
        state.stream_released = true;
        Ok(())
    }

    /// A failure indication, never a completion receipt. Poison/inconsistent
    /// state stays unfinal even when a caller can no longer drive the original.
    pub fn cleanup_failed(&self) -> bool {
        self.unreconciled || self.write_error.is_some() || match self.shared.lock() {
            Err(_) => true,
            Ok(state) => state.control_error.is_some()
                || matches!(state.reader, ReaderSlot::Terminal(outcome) if !outcome.clean()),
        }
    }

    /// The FIRST poll requires the application's current exact-slot, one-use
    /// cleanup admission. Once entered, this SAME original must keep being
    /// polled after STOP/Unknown/cutoff, along with already-entered build/RPCs.
    pub fn poll_local_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<LocalSettlement> {
        if self.settled { return Poll::Pending; } // A receipt is consumed once.
        let _runtime = self.runtime.enter();
        self.shutdown_entered = true;
        {
            let mut state = match self.shared.lock() {
                Ok(state) => state,
                Err(_) => { self.unreconciled = true; return Poll::Pending; }
            };
            state.stopping = true;
            // Do not await the writer or queue mutex before interrupting I/O
            // and consuming the reader join: either may be held by live work.
            state.shutdown_control();
            if !state.pending_failed {
                if let Some(connection) = state.connection.as_ref() {
                    connection.inner.pending_method_calls.fail_all(stopped());
                    state.pending_failed = true;
                }
            }
            if state.poll_reader_stop(cx).is_err() { self.unreconciled = true; }
            if self.unreconciled || !self.startup_consumed || self.call.is_some()
                || matches!(self.call_state, CallState::Staged | CallState::Entered)
                || !state.stream_released || state.stream.is_some()
                || !matches!(state.reader, ReaderSlot::Terminal(_))
            { return Poll::Pending; }
            if self.close.is_none() && !self.close_consumed {
                if let Some(connection) = state.connection.as_ref().cloned() {
                    let close = async move {
                        // The true reader join is already consumed. A reader
                        // parked in broadcast therefore cannot hold this lock.
                        connection.inner.msg_senders.lock().await.clear();
                        connection.close().await
                    };
                    if self.keyring_wire && crate::keyring_wire::future_fits(&close).is_err() {
                        self.unreconciled = true;
                        return Poll::Pending;
                    }
                    self.close = Some(Box::pin(close));
                } else {
                    self.close_consumed = true; // Exact terminal no-connection startup.
                }
            }
        }
        if let Some(close) = self.close.as_mut() {
            let Poll::Ready(result) = close.as_mut().poll(cx) else { return Poll::Pending; };
            self.close = None;
            self.close_consumed = true;
            if let Err(error) = result {
                // This exact close path returns I/O only. Do not keep an opaque
                // SDK error (which could contain an owning Message) in finality.
                match error {
                    Error::InputOutput(error) => self.write_error = Some(LocalIoError::from(error.as_ref())),
                    _ => { self.unreconciled = true; return Poll::Pending; }
                }
            }
        }
        if !self.close_consumed || self.unreconciled { return Poll::Pending; }
        let mut state = match self.shared.lock() {
            Ok(state) => state,
            Err(_) => { self.unreconciled = true; return Poll::Pending; }
        };
        let ReaderSlot::Terminal(reader) = state.reader else { self.unreconciled = true; return Poll::Pending; };
        state.connection = None;
        state.control = None;
        self.settled = true;
        Poll::Ready(LocalSettlement { reader, control_error: state.control_error, write_error: self.write_error })
    }
}

impl OrderedStream for OwnedConnectionAttempt {
    type Data = Result<Message>;
    type Ordering = Sequence;

    fn poll_next_before(
        self: Pin<&mut Self>, cx: &mut Context<'_>, before: Option<&Sequence>,
    ) -> Poll<PollResult<Sequence, Self::Data>> {
        let this = self.get_mut();
        match this.shared.lock() {
            Ok(mut state) => match state.stream.as_mut() {
                Some(stream) => Pin::new(stream).poll_next_before(cx, before),
                None => Poll::Ready(PollResult::Terminated),
            },
            Err(error) => {
                this.unreconciled = true;
                Poll::Ready(PollResult::Item { ordering: Sequence::LAST, data: Err(error) })
            }
        }
    }
}
