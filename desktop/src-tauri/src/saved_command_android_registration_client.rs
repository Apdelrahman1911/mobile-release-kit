//! Same-original Register client. Preparation is not source/payload GO.
//! Only the owning IPC worker borrows ClientBook; the coordinator can project
//! STOP/deadlines through Signal while that worker is in a native call.
use super::*;
use crate::android_registration_protocol::{self as transfer, preparation::{Hello, MetadataChunk},
    terminal::{TerminalCandidate, CandidateDisposition}};
use mrk_macos_installed_native::{android_registration as native,
    android_service_prepare as prepare, vault_helper_wire::ClockBridge};
use sha2::{Digest, Sha256};
use std::{sync::OnceLock, thread};

const HEARTBEAT: Duration = Duration::from_millis(2);
const PREPARING: usize = 0;
const COPYING: usize = 1;
const VERIFYING: usize = 2;
const SETTLING: usize = 3;
const TASK_STORAGE: usize = 64 * 1024;

/// Private one-use barriers, sent only by the admitted original coordinator.
pub(super) struct BeginPreparation;
struct ReadOnlyReproof<O = Operation> { original: Weak<O>, nonce: [u8; 16] }
struct Reproved<O = Operation> { original: Weak<O>, nonce: [u8; 16] }
struct TransferGo<O = Operation> { original: Weak<O>, nonce: [u8; 16] }
struct FinishAfterSourceJoin<O = Operation> { original: Weak<O> }
struct Ready<O = Operation> { original: Weak<O>, nonce: [u8; 16] }

#[derive(Default)]
struct FailureProjection {
    imported: Option<(u64, Instant, wire::Reason)>,
    exported: Option<(u64, wire::Reason)>,
}
struct OriginalClock {
    bridge: ClockBridge, bounds: native::Bounds,
    // Only short copied clock DATA lives here. Native/source entry and cleanup
    // do not hold this cell; a contended projection never parks the watchdog.
    projection: Mutex<FailureProjection>,
}
impl OriginalClock {
    fn capture(control: &Control, signal: &native::Signal) -> Option<Self> {
        let bridge = ClockBridge::capture()?;
        let origin = bridge.earlier_endpoint(control.admitted)?;
        let bounds = native::Bounds { origin, work: origin.checked_add(native::WORK_NS)?,
            hard: origin.checked_add(native::HARD_NS)? };
        if !bounds.valid() || bridge.earlier_endpoint(control.work) != Some(bounds.work)
            || bridge.earlier_endpoint(control.hard) != Some(bounds.hard)
            || signal.arm(bounds).is_err() { return None; }
        Some(Self { bridge, bounds, projection: Mutex::new(FailureProjection::default()) })
    }
    /// Same conservative mapping on both directions, without echoing a mapped
    /// imported F back through the bracket again on every heartbeat.
    fn synchronize(&self, control: &Control, signal: &native::Signal) {
        control.advance(Instant::now());
        let mut projection = match self.projection.try_lock() {
            Ok(value) => value,
            // Work/cleanup still check BOTH independent original gates below.
            // The other projector owns no native or application resource lock.
            Err(TryLockError::WouldBlock) => return,
            Err(TryLockError::Poisoned(_)) => {
                signal.clock_unknown(); control.poisoned(); return;
            }
        };
        let local = control.failure();
        if let Some((_, first)) = local {
            // A concurrent publisher may have captured F after synchronize
            // began. Observe AFTER reading it, not against an earlier `now`.
            if first > Instant::now() { signal.clock_unknown(); control.poisoned(); return; }
            // Do not echo an imported lower bound through the bracket. This
            // memo is serialized even when native callbacks publish earlier F
            // concurrently; a genuinely earlier local event is still exported.
            if projection.imported.is_none_or(|(_, bound, _)| first < bound) {
                signal.local_failure(&self.bridge, first, control.unknown.load(Ordering::SeqCst));
                projection.exported = self.bridge.earlier_endpoint(first).map(|raw| (raw, local.unwrap().0));
            }
        }
        if control.unknown.load(Ordering::SeqCst) {
            if let Some(first) = signal.first() { signal.failure_at(first, true); }
            else { signal.clock_unknown(); }
        }
        let frozen = signal.snapshot();
        if let Some(raw) = frozen.first {
            let Some(first) = self.bridge.earlier_instant_data(raw) else {
                signal.clock_unknown(); control.poisoned(); return;
            };
            let reason = projection.exported.filter(|(exported, _)| *exported == raw).map(|(_, reason)| reason)
                .or_else(|| projection.imported.filter(|(imported, _, _)| *imported == raw).map(|(_, _, reason)| reason))
                .unwrap_or(wire::Reason::RegistrationRefused);
            projection.imported = Some((raw, first, reason));
            control.stop_at(reason, first);
        }
        let cleanup = frozen.cleanup.and_then(|raw| self.bridge.earlier_instant_data(raw));
        if cleanup.is_none() {
            signal.clock_unknown(); control.poisoned(); return;
        }
        if let Some(end) = cleanup {
            control.audit.send_if_modified(|current| if end < *current { *current = end; true } else { false });
        }
        if frozen.unknown { control.mark_unknown(Instant::now()); }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlightState { Empty, Queued, InFlight, Acknowledged, Failed }
struct Flight {
    state: FlightState, kind: transfer::Kind, file: u32, offset: u64,
    expected_file_bytes: u64, bytes: Vec<u8>,
}
impl Flight {
    fn reserved() -> Option<Self> {
        let mut bytes = Vec::new(); bytes.try_reserve_exact(transfer::MAX_PAYLOAD).ok()?;
        if bytes.capacity() > transfer::MAX_PAYLOAD.checked_mul(2)? { return None; }
        Some(Self { state: FlightState::Empty, kind: transfer::Kind::Begin,
            file: 0, offset: 0, expected_file_bytes: 0, bytes })
    }
}
struct NativeOriginal {
    book: native::ClientBook, transfer: Option<transfer::Transfer>,
    frame_sequence: u32, envelope_sequence: u32, payload_bytes: u64, hello_entered: bool,
    terminal: Option<TerminalCandidate>, peer_final: bool,
}
pub(super) struct ClientOriginal {
    reviewed: Arc<Review>, signal: Arc<native::Signal>, clock: OnceLock<OriginalClock>,
    native: Mutex<Option<NativeOriginal>>, flight: Mutex<Flight>, phase: AtomicUsize,
    preparation:service_setup::Preparation,
    ipc: AsyncMutex<Option<JoinHandle<ClientReturn>>>,
    returned: Mutex<Option<Result<ClientReturn, tokio::task::JoinError>>>, joined: AtomicBool,
}
struct ClientReturn {
    known: bool, first: Option<(wire::Reason, Instant)>, entered: bool,
    hello_entered: bool, peer_final: bool, terminal: Option<TerminalCandidate>,
    retained_bytes: Option<usize>,
}
impl ClientOriginal {
    fn reserve(reviewed: Arc<Review>,gate:WorkGate,dispatcher:Arc<service_setup::Dispatcher>) -> Option<Self> {
        let signal = Arc::new(native::Signal::reserved());
        Some(Self { reviewed, signal, clock: OnceLock::new(), native: Mutex::new(None),
            preparation:service_setup::Preparation::for_registration(gate,dispatcher),
            flight: Mutex::new(Flight::reserved()?), phase: AtomicUsize::new(PREPARING),
            ipc: AsyncMutex::new(None), returned: Mutex::new(None), joined: AtomicBool::new(false) })
    }
    fn reservation_bytes() -> Option<usize> {
        // Fixed project-owned native high-water, not Foundation/RSS accounting.
        // Include simultaneous slot, protocol encoder, outer envelope, transfer
        // roster, terminal/status copies and all signal/handle/return cells.
        let native = native::ClientBook::allocation_requirements().admitted_upper_bound().ok()?;
        arc_bytes::<Self>()?.checked_add(arc_bytes::<native::Signal>()?)?
            .checked_add(native)?.checked_add(8usize.checked_mul(native::FRAME_BYTES)?)?
            .checked_add(transfer::MAX_FILES.checked_mul(std::mem::size_of::<transfer::File>())?.checked_mul(2)?)?
            .checked_add(std::mem::size_of::<transfer::Transfer>())?
            .checked_add(arc_bytes::<()>()?)?.checked_add(arc_bytes::<FinalWake>()?)?
            .checked_add(12usize.checked_mul(SIGNAL_STORAGE)?)?
            .checked_add(4usize.checked_mul(std::mem::size_of::<ClientReturn>())?)?
            .checked_add(4usize.checked_mul(native::STATUS_BYTES)?)?
            .checked_add(2usize.checked_mul(wire::STATUS_LIMIT)?)?.checked_add(TASK_STORAGE)
    }
    fn synchronize(&self, original: &Operation) {
        if let Some(clock) = self.clock.get() { clock.synchronize(&original.control, &self.signal); }
        else { original.control.advance(Instant::now()); }
    }
    fn work(&self, original: &Operation) -> bool {
        self.synchronize(original);
        original.control.failure().is_none() && !original.control.unknown.load(Ordering::SeqCst)
            && self.clock.get().is_some() && self.signal.admitted(false)
    }
    fn cleanup(&self, original: &Operation) -> bool {
        self.synchronize(original);
        Instant::now() < original.control.endpoint()
            && (self.clock.get().is_none() || self.signal.admitted(true))
    }
    fn fail(&self, original: &Operation, reason: wire::Reason) {
        original.control.stop_at(reason, Instant::now()); self.synchronize(original);
    }
    pub(super) fn phase(&self) -> wire::Phase {
        match self.phase.load(Ordering::SeqCst) {
            COPYING => wire::Phase::Copying, VERIFYING => wire::Phase::Verifying,
            SETTLING => wire::Phase::Settling, _ => wire::Phase::Preparing,
        }
    }
    pub(super) fn known_return(&self) -> bool {
        if !self.joined.load(Ordering::SeqCst) || self.signal.unknown() || !self.preparation.known_return() { return false; }
        let Ok(handle) = self.ipc.try_lock() else { return false; };
        let Ok(returned) = self.returned.try_lock() else { return false; };
        handle.is_none() && matches!(returned.as_ref(), Some(Ok(value)) if value.known
            && value.peer_final && value.retained_bytes.is_some())
    }
    pub(super) fn report(&self, original: &Operation) -> Option<(wire::Phase, wire::Reason, wire::Report)> {
        if !self.known_return() { return None; }
        let returned = self.returned.try_lock().ok()?;
        let Some(Ok(value)) = returned.as_ref() else { return None; };
        if value.first.is_some_and(|(_, first)| original.control.failure().is_none_or(|(_, at)| at > first)) {
            return None;
        }
        let sources = self.reviewed.source.sources();
        let failure = original.control.failure().map(|(reason, _)| reason);
        let (copy, accounting, problems, success) = if let Some(terminal) = &value.terminal {
            let map = |problem| match problem {
                transfer::terminal::Problem::Binding => wire::Problem::Binding,
                transfer::terminal::Problem::Bounds => wire::Problem::Bounds,
                transfer::terminal::Problem::SupplierUnavailable => wire::Problem::SupplierUnavailable,
                transfer::terminal::Problem::Inventory => wire::Problem::Inventory,
                transfer::terminal::Problem::Ownership => wire::Problem::Ownership,
                transfer::terminal::Problem::Collision => wire::Problem::Collision,
                transfer::terminal::Problem::Native => wire::Problem::Native,
                transfer::terminal::Problem::Stopped => wire::Problem::Stopped,
                transfer::terminal::Problem::Unknown => wire::Problem::Unknown,
                transfer::terminal::Problem::Transfer => wire::Problem::Transfer,
                transfer::terminal::Problem::Persist => wire::Problem::Persist,
                transfer::terminal::Problem::Admission => wire::Problem::Admission,
                transfer::terminal::Problem::Unavailable => wire::Problem::Unavailable,
            };
            let items: Vec<_> = terminal.error_prefix.iter().copied().map(map).collect();
            let problems = wire::Problems { recorded: terminal.recorded_error_count, shown: items.len().try_into().ok()?,
                omitted: terminal.omitted_recorded_errors(), first: items.first().copied(), items };
            let copy = if terminal.publication_applied { wire::ProtectedCopy::Published }
                else if value.hello_entered { wire::ProtectedCopy::RetainedPartial } else { wire::ProtectedCopy::NotCreated };
            (copy, Some(wire::Accounting { written_bytes: terminal.written_bytes.to_string(),
                observed_logical_bytes: terminal.accounting.observed_logical_bytes.to_string(),
                observed_allocated_bytes: terminal.accounting.observed_allocated_bytes.to_string(),
                complete: terminal.accounting.complete, content_files: terminal.content_files,
                content_aliases: terminal.content_aliases }), problems,
                terminal.disposition == CandidateDisposition::PreparedComplete && terminal.publication_applied)
        } else {
            // Positive same-ClientAttempt nonentry only, never guessed from
            // missing Hello, zero counters or an absent native terminal.
            if value.entered || value.hello_entered || failure.is_none() { return None; }
            (wire::ProtectedCopy::NotCreated, None, wire::Problems { recorded: 1, shown: 1, omitted: 0,
                first: Some(wire::Problem::Unavailable), items: vec![wire::Problem::Unavailable] }, false)
        };
        let reason = failure.unwrap_or(if success { wire::Reason::None } else { wire::Reason::RegistrationRefused });
        let phase = if reason == wire::Reason::None && success { wire::Phase::Complete }
            else if reason == wire::Reason::Cancelled { wire::Phase::Cancelled } else { wire::Phase::Refused };
        Some((phase, reason, wire::Report { sources, protected_copy: copy, accounting, problems }))
    }
    fn poll(&self, original: &Operation, slot: &mut Option<JoinHandle<ClientReturn>>,
        cx: &mut TaskContext<'_>, at: Instant) -> Poll<bool> {
        let mut returned = match self.returned.try_lock() {
            Ok(value) => value, Err(TryLockError::WouldBlock) => return Poll::Pending,
            Err(TryLockError::Poisoned(_)) => { original.control.mark_unknown(at); return Poll::Ready(false); }
        };
        if self.joined.load(Ordering::SeqCst) || returned.is_some() {
            original.control.mark_unknown(at); return Poll::Ready(false);
        }
        let Some(handle) = slot.as_mut() else { original.control.mark_unknown(at); return Poll::Ready(false); };
        let Poll::Ready(value) = Pin::new(handle).poll(cx) else { return Poll::Pending; };
        let known = matches!(&value, Ok(value) if value.known && value.peer_final && value.retained_bytes.is_some());
        *returned = Some(value); self.joined.store(true, Ordering::SeqCst); slot.take();
        if !known { original.control.mark_unknown(at); }
        Poll::Ready(known)
    }
    pub(super) fn finalize_preparation(&self,service:&mut service_setup::State)->bool{
        service.adopt_finalized_preparation(&self.preparation)
    }
    pub(super) fn observe_late(&self, original: &Operation) {
        self.preparation.tick(false);
        if self.joined.load(Ordering::SeqCst) { return; }
        if let Ok(mut handle) = self.ipc.try_lock() {
            if handle.is_some() {
                let waker = Waker::from(Arc::new(FinalWake(original.owner.clone())));
                let mut cx = TaskContext::from_waker(&waker);
                let _ = self.poll(original, &mut handle, &mut cx, Instant::now());
            }
        }
    }
}

fn original_client(original: &Operation) -> &ClientOriginal {
    original.client.as_ref().expect("only a registered Register original owns these workers")
}
fn matches_original<O>(candidate: &Weak<O>, original: &Arc<O>) -> bool {
    candidate.as_ptr() == Arc::as_ptr(original)
}
fn hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N.checked_mul(2)? { return None; }
    let mut bytes = [0; N];
    let digit = |v| match v { b'0'..=b'9' => Some(v-b'0'), b'a'..=b'f' => Some(v-b'a'+10), _ => None };
    for (out, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *out = digit(pair[0])?.checked_mul(16)?.checked_add(digit(pair[1])?)?;
    }
    (bytes != [0; N]).then_some(bytes)
}
fn receive<T>(receiver: &mut oneshot::Receiver<T>, original: &Operation, native_work: bool) -> Option<T> {
    let client = original_client(original);
    loop {
        match receiver.try_recv() {
            Ok(value) => return Some(value), Err(oneshot::error::TryRecvError::Closed) => return None,
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
        client.synchronize(original);
        if original.control.failure().is_some() || original.control.unknown.load(Ordering::SeqCst)
            || native_work && !client.work(original) { return None; }
        thread::park_timeout(HEARTBEAT);
    }
}
/// Nonblocking coordinator admission: a conditional pending publisher cannot
/// occupy the independently runnable watchdog. SourceSlots retains its existing
/// pending-aware blocking WorkGate; every payload/native entry is rechecked.
fn coordinator_work(original: &Operation) -> Option<bool> {
    WorkGate { slot: original.cohort.slot.clone(), control: original.control.clone() }.try_work()
}

/// Lifecycle/saved-binding invalidations reserve the same ControlSlot before
/// touching Document. Only short, nonblocking DATA locks are taken here, so a
/// busy application projection cannot park original deadline enforcement.
fn current_original(original: &Arc<Operation>) -> Option<bool> {
    let Some(owner) = original.owner.upgrade() else { return None; };
    if owner.poisoned.load(Ordering::SeqCst) || original.document.upgrade().is_none() { return None; }
    let document = match owner.android_document.try_lock() {
        Ok(value) => value, Err(TryLockError::WouldBlock) => return Some(false), Err(_) => return None,
    };
    if document.as_ref().is_none_or(|value| !Weak::ptr_eq(value, &original.document)) { return None; }
    let registry = match owner.registry.try_lock() {
        Ok(value) => value, Err(TryLockError::WouldBlock) => return Some(false), Err(_) => return None,
    };
    if registry.disabled || registry.exhausted || registry.stopping || registry.document_lost
        || !registry.android_sources.same_snapshot(&original.source)
        || !registry.android_registration.active.as_ref().is_some_and(|value| Arc::ptr_eq(value, original)) {
        return None;
    }
    Some(true)
}

struct Sink<'a> { original: &'a Arc<Operation>, file: u32, offset: u64, expected: u64, open: bool }
impl Sink<'_> {
    fn submit(&mut self, kind: transfer::Kind, bytes: &[u8]) -> Result<(), AdmissionFailure> {
        let client = original_client(self.original);
        let mut submitted = false;
        loop {
            if !client.work(self.original) { return Err(AdmissionFailure::Stopped); }
            match client.flight.try_lock() {
                Ok(mut slot) => {
                    if !submitted && slot.state == FlightState::Empty {
                        if bytes.len() > transfer::MAX_PAYLOAD || slot.bytes.capacity() < bytes.len() {
                            client.fail(self.original, wire::Reason::InputLimit); return Err(AdmissionFailure::Bounds);
                        }
                        slot.bytes.clear(); slot.bytes.extend_from_slice(bytes);
                        slot.kind = kind; slot.file = self.file; slot.offset = self.offset;
                        slot.expected_file_bytes = self.expected; slot.state = FlightState::Queued; submitted = true;
                    } else if submitted && slot.state == FlightState::Acknowledged {
                        slot.bytes.clear(); slot.state = FlightState::Empty; return Ok(());
                    } else if slot.state == FlightState::Failed {
                        return Err(AdmissionFailure::Stopped);
                    }
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Poisoned(_)) => {
                    client.fail(self.original, wire::Reason::CleanupUnknown); return Err(AdmissionFailure::Unknown);
                }
            }
            thread::park_timeout(HEARTBEAT);
        }
    }
}
impl crate::installed_runtime::AndroidRegistrationPayloadSink for Sink<'_> {
    fn begin(&mut self, ordinal: u32, bytes: u64) -> Result<(), AdmissionFailure> {
        if self.open || ordinal != self.file { return Err(AdmissionFailure::Inventory); }
        self.expected = bytes; self.offset = 0;
        self.submit(transfer::Kind::Begin, &[])?; self.open = true; Ok(())
    }
    fn chunk(&mut self, bytes: &[u8]) -> Result<(), AdmissionFailure> {
        if !self.open || bytes.is_empty() { return Err(AdmissionFailure::Inventory); }
        for part in bytes.chunks(transfer::MAX_PAYLOAD) {
            let next = self.offset.checked_add(part.len() as u64).filter(|next| *next <= self.expected)
                .ok_or(AdmissionFailure::Bounds)?;
            self.submit(transfer::Kind::Data, part)?; self.offset = next;
        }
        Ok(())
    }
    fn end(&mut self, ordinal: u32, bytes: u64) -> Result<(), AdmissionFailure> {
        if !self.open || ordinal != self.file || bytes != self.expected || self.offset != bytes {
            return Err(AdmissionFailure::Inventory);
        }
        self.submit(transfer::Kind::End, &[])?;
        self.open = false; self.file = self.file.checked_add(1).ok_or(AdmissionFailure::Bounds)?; Ok(())
    }
}
struct SourceInputs {
    reproof: oneshot::Receiver<ReadOnlyReproof>, reproved: oneshot::Sender<Reproved>,
    transfer: oneshot::Receiver<TransferGo>,
}
fn source_worker(original: Arc<Operation>, mut input: SourceInputs) -> SourceReturn {
    let client = original_client(&original);
    let mut sources = match original.sources.lock() {
        Ok(sources) => sources, Err(_) => {
            client.fail(&original, wire::Reason::CleanupUnknown);
            return SourceReturn { known: false, entered: false, first: original.control.failure(), retained_bytes: None, review: None };
        }
    };
    let permit = receive(&mut input.reproof, &original, false);
    let mut entered = false;
    if let Some(permit) = permit {
        if matches_original(&permit.original, &original) && client.work(&original) {
            entered = true;
            let mut publish = |failure, at| source_failure(&original.control, failure, at);
            let result = sources.reprove_once(original.source.roots(), &client.reviewed.source,
                original.supplier_reservation, original.control.work, &original.control.stop.subscribe(), &mut publish);
            if result.is_ok() && client.work(&original) {
                let nonce = permit.nonce;
                if input.reproved.send(Reproved { original: Arc::downgrade(&original), nonce }).is_ok() {
                    if let Some(go) = receive(&mut input.transfer, &original, true) {
                        if matches_original(&go.original, &original) && go.nonce == nonce && client.work(&original) {
                            // No PayloadSink exists during read-only reproof.
                            let mut sink = Sink { original: &original, file: 0, offset: 0, expected: 0, open: false };
                            if let Err(failure) = sources.stream_payloads(&client.reviewed.source,
                                original.control.work, &original.control.stop.subscribe(), &mut sink, &mut publish) {
                                let at = sources.first_failure().map_or_else(Instant::now, |(_, at)| at);
                                source_failure(&original.control, failure, at);
                            }
                        } else { client.fail(&original, wire::Reason::CleanupUnknown); }
                    }
                } else { client.fail(&original, wire::Reason::CleanupUnknown); }
            } else if let Err(failure) = result {
                let at = sources.first_failure().map_or_else(Instant::now, |(_, at)| at);
                source_failure(&original.control, failure, at);
            }
        } else { client.fail(&original, wire::Reason::CleanupUnknown); }
    }
    if original.control.failure().is_none() && !entered { client.fail(&original, wire::Reason::Cancelled); }
    let closed = sources.settle_originals(&mut |failure| {
        if let Some((failure, at)) = failure { source_failure(&original.control, failure, at); }
        client.synchronize(&original);
        WorkGate { slot: original.cohort.slot.clone(), control: original.control.clone() }.cleanup_expired(None)
    });
    if let Some((failure, at)) = sources.first_failure() { source_failure(&original.control, failure, at); }
    let known = closed == CloseOutcome::Settled && sources.settled();
    let retained_bytes = sources.retained_bytes();
    if !known || retained_bytes.is_none() || original.reservation.get().is_none_or(|reservation|
        retained_bytes.is_none_or(|bytes| bytes > reservation.source)) {
        client.fail(&original, wire::Reason::CleanupUnknown);
    }
    SourceReturn { known, entered, first: original.control.failure(), retained_bytes, review: None }
}

fn failure_reason(failure: native::Failure) -> wire::Reason {
    match failure {
        native::Failure::Bounds => wire::Reason::InputLimit,
        native::Failure::Binding | native::Failure::Sequence => wire::Reason::ProtocolError,
        native::Failure::Busy | native::Failure::Unavailable => wire::Reason::FreshServiceUnavailable,
        native::Failure::Stopped => wire::Reason::Cancelled,
        native::Failure::Native | native::Failure::Unknown => wire::Reason::CleanupUnknown,
    }
}
fn wait_work(original: &Operation) -> Result<(), wire::Reason> {
    let client = original_client(original);
    loop {
        if !client.work(original) { return Err(wire::Reason::Cancelled); }
        match coordinator_work(original) {
            Some(true) => return Ok(()), Some(false) => thread::park_timeout(HEARTBEAT),
            None => return Err(wire::Reason::Cancelled),
        }
    }
}
fn take_terminal(original: &Operation, state: &mut NativeOriginal, status: &native::Status) -> Result<bool, wire::Reason> {
    if !matches!(status.phase, native::Phase::Complete | native::Phase::Refused | native::Phase::Unknown) {
        return Ok(false);
    }
    if status.terminal.is_empty() {
        if status.phase == native::Phase::Unknown { return Err(wire::Reason::CleanupUnknown); }
        return Err(wire::Reason::ProtocolError);
    }
    let client = original_client(original);
    let terminal = TerminalCandidate::decode(&status.terminal).map_err(|_| wire::Reason::ProtocolError)?;
    let instance = hex::<16>(client.reviewed.source.instance()).ok_or(wire::Reason::ProtocolError)?;
    let nonce = state.book.prepared_nonce().ok_or(wire::Reason::CleanupUnknown)?;
    let correspondence = if state.hello_entered { terminal.matches_source_data(&nonce, &instance) }
        else { terminal.prehello_refusal_candidate() };
    if !correspondence || status.account != client.reviewed.source.account()
        || status.unknown || status.phase == native::Phase::Unknown
        || !terminal.pre_lease_dependencies_known { return Err(wire::Reason::CleanupUnknown); }
    let proposal = client.reviewed.source.proposal();
    if status.phase == native::Phase::Complete {
        if terminal.disposition != CandidateDisposition::PreparedComplete
            || !state.transfer.as_ref().is_some_and(transfer::Transfer::transfer_complete)
            || terminal.content_files as usize != proposal.payload_map().len()
            || terminal.content_aliases != proposal.alias_count()
            || terminal.written_bytes < proposal.payload_bytes().checked_add(proposal.metadata_bytes())
                .ok_or(wire::Reason::InputLimit)?
            || terminal.recorded_error_count != 0 || !terminal.publication_applied || !terminal.accounting.complete {
            return Err(wire::Reason::CleanupUnknown);
        }
    } else if terminal.disposition != CandidateDisposition::Refused {
        return Err(wire::Reason::CleanupUnknown);
    }
    if state.terminal.as_ref().is_some_and(|before| before != &terminal) { return Err(wire::Reason::CleanupUnknown); }
    // The native outer terminal is published only after the service's genuine
    // original worker/coordinator joins. The inner PRE-G candidate alone is
    // deliberately insufficient; app native/IPC/source joins are still owed.
    state.peer_final = true; state.terminal = Some(terminal); Ok(true)
}
/// One Push, never a retransmission. Only a matching authenticated *processed*
/// ACK advances Transfer or the single source slot; enqueued/Busy is not ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ack { Pending, Processed }
fn processed_ack(status: &native::Status, account: u32, nonce: [u8; 16],
    previous: u32, old_payload: u64, expected_payload: u64, finish: bool) -> Result<Ack, wire::Reason> {
    if account == 0 || account == u32::MAX || nonce == [0; 16]
        || status.account != account || status.nonce != nonce || expected_payload < old_payload {
        return Err(wire::Reason::ProtocolError);
    }
    if status.unknown || status.phase == native::Phase::Unknown { return Err(wire::Reason::CleanupUnknown); }
    if status.first.is_some() || status.phase == native::Phase::Refused { return Err(wire::Reason::RegistrationRefused); }
    // A Busy snapshot deliberately omits counters while the actual queue DATA
    // lock is owned. It proves neither processing nor permission to resend.
    if status.phase == native::Phase::Busy { return Ok(Ack::Pending); }
    let next = previous.checked_add(1).filter(|value| *value != u32::MAX).ok_or(wire::Reason::ProtocolError)?;
    if status.enqueued != next || !matches!(status.processed, value if value == previous || value == next)
        || !matches!(status.phase, native::Phase::Active | native::Phase::InputClosed | native::Phase::Complete)
        || matches!(status.phase, native::Phase::InputClosed | native::Phase::Complete)
            && (!finish || status.processed != next) {
        return Err(wire::Reason::ProtocolError);
    }
    if status.processed == previous {
        if status.payload_bytes != old_payload { return Err(wire::Reason::ProtocolError); }
        Ok(Ack::Pending)
    } else {
        if status.payload_bytes != expected_payload { return Err(wire::Reason::ProtocolError); }
        Ok(Ack::Processed)
    }
}
fn push(original: &Operation, state: &mut NativeOriginal, content: &[u8], expected_payload: u64, finish: bool)
    -> Result<(), wire::Reason> {
    let client = original_client(original);
    wait_work(original)?;
    let nonce = state.book.prepared_nonce().ok_or(wire::Reason::CleanupUnknown)?;
    if state.book.prepare_custody() != prepare::PeerCustody::Ready { return Err(wire::Reason::CleanupUnknown); }
    let next = state.envelope_sequence.checked_add(1).filter(|n| *n != u32::MAX).ok_or(wire::Reason::InputLimit)?;
    let raw = native::Envelope::encode(nonce, next, native::Verb::Push, content).map_err(failure_reason)?;
    // Hello is possibly entered from this exact call boundary, even if the
    // reply or queue observation is lost. Never infer nonentry from counters.
    if state.envelope_sequence == 0 { state.hello_entered = true; }
    let mut observed = state.book.exchange(&raw, false).map_err(failure_reason)?;
    loop {
        client.synchronize(original);
        if processed_ack(&observed, client.reviewed.source.account(), nonce, state.envelope_sequence,
            state.payload_bytes, expected_payload, finish)? == Ack::Processed {
            state.envelope_sequence = next; state.payload_bytes = expected_payload; return Ok(());
        }
        wait_work(original)?;
        thread::park_timeout(HEARTBEAT);
        let request = native::Envelope::encode(nonce, 0, native::Verb::Status, &[]).map_err(failure_reason)?;
        observed = state.book.exchange(&request, false).map_err(failure_reason)?;
    }
}
fn send_metadata(original: &Operation, state: &mut NativeOriginal, nonce: [u8; 16]) -> Result<(), wire::Reason> {
    let client = original_client(original);
    let proposal = client.reviewed.source.proposal();
    let documents = proposal.documents();
    let clock = client.clock.get().ok_or(wire::Reason::CleanupUnknown)?;
    let consent = serde_json::to_vec(&(&client.reviewed.public, &original.data.operation_id,
        original.source.registration, wire::CONSENT)).map_err(|_| wire::Reason::ProtocolError)?;
    if consent.len() > wire::STATUS_LIMIT { return Err(wire::Reason::InputLimit); }
    let source_consent: [u8; 32] = Sha256::digest(&consent).into();
    let hello = Hello { transaction: nonce, instance: hex::<16>(&original.instance).ok_or(wire::Reason::ProtocolError)?,
        origin: clock.bounds.origin, work: clock.bounds.work, hard: clock.bounds.hard,
        lengths: [u32::try_from(documents[0].len()).map_err(|_| wire::Reason::InputLimit)?,
            u32::try_from(documents[1].len()).map_err(|_| wire::Reason::InputLimit)?,
            u32::try_from(documents[2].len()).map_err(|_| wire::Reason::InputLimit)?],
        hashes: proposal.hashes(), source_consent, supplier_record: *proposal.supplier_record(),
        source_generation: original.source.generation, project_registration: original.source.registration };
    let raw = hello.encode().map_err(|_| wire::Reason::ProtocolError)?;
    let mut files = Vec::new();
    files.try_reserve_exact(proposal.payload_map().len()).map_err(|_| wire::Reason::InputLimit)?;
    if files.capacity() > transfer::MAX_FILES.checked_mul(2).ok_or(wire::Reason::InputLimit)? {
        return Err(wire::Reason::InputLimit);
    }
    for item in proposal.payload_map() {
        files.push(transfer::File { bytes: item.installed.size,
            sha256: hex::<32>(item.installed.sha256).ok_or(wire::Reason::ProtocolError)? });
    }
    let selected = files.len().checked_add(proposal.directory_count() as usize)
        .and_then(|n| n.checked_add(proposal.alias_count() as usize)).and_then(|n| n.checked_add(3))
        .ok_or(wire::Reason::InputLimit)?;
    state.transfer = Some(transfer::Transfer::new(transfer::Identity { transaction: nonce, inventory: hello.hashes[0] },
        files, selected).map_err(|_| wire::Reason::ProtocolError)?);
    push(original, state, &raw, 0, false)?;
    for (field, data) in documents.into_iter().enumerate() {
        let mut offset = 0u32;
        for bytes in data.chunks(transfer::MAX_FRAME - transfer::preparation::METADATA_HEADER) {
            let chunk = MetadataChunk::encode(field as u8, offset, bytes).map_err(|_| wire::Reason::ProtocolError)?;
            push(original, state, &chunk, 0, false)?;
            offset = offset.checked_add(bytes.len().try_into().map_err(|_| wire::Reason::InputLimit)?)
                .ok_or(wire::Reason::InputLimit)?;
        }
    }
    Ok(())
}
struct IpcInputs {
    preparation: oneshot::Receiver<BeginPreparation>, ready: Option<oneshot::Sender<Ready>>,
    transfer: oneshot::Receiver<TransferGo>, finish: oneshot::Receiver<FinishAfterSourceJoin>,
}
fn ipc_body(original: &Arc<Operation>, state: &mut NativeOriginal, input: &mut IpcInputs) -> Result<(), wire::Reason> {
    let client = original_client(original);
    receive(&mut input.preparation, original, false).ok_or(wire::Reason::Cancelled)?;
    // Fresh fixed signature/installed service Check on THIS original worker,
    // before ClientBook.begin/prepare and while the source is still barred.
    // No previous setup status is substituted for this actual native return.
    if !client.preparation.registration_ready(){return Err(wire::Reason::ServiceUnavailable);}
    // The immutable bridge still maps original T/W/H; capture after the Check
    // does NOT start another budget. No native peer entry predates this bridge.
    let clock = OriginalClock::capture(&original.control, &client.signal).ok_or(wire::Reason::CleanupUnknown)?;
    client.clock.set(clock).map_err(|_| wire::Reason::CleanupUnknown)?;
    client.synchronize(original);
    wait_work(original)?;
    state.book.begin().map_err(failure_reason)?;
    let nonce = loop {
        wait_work(original)?;
        let reply = state.book.prepare().map_err(failure_reason)?;
        client.synchronize(original);
        match reply.phase {
            prepare::Phase::Ready if state.book.prepare_custody() == prepare::PeerCustody::Ready
                && state.book.prepared_nonce() == Some(reply.nonce) => break reply.nonce,
            prepare::Phase::Pending => thread::park_timeout(HEARTBEAT),
            prepare::Phase::Busy | prepare::Phase::Refused if state.book.peer_nonentry_known() =>
                return Err(wire::Reason::FreshServiceUnavailable),
            _ => return Err(wire::Reason::CleanupUnknown),
        }
    };
    input.ready.take().ok_or(wire::Reason::CleanupUnknown)?.send(Ready { original: Arc::downgrade(original), nonce }).map_err(|_| wire::Reason::CleanupUnknown)?;
    let go = receive(&mut input.transfer, original, true).ok_or(wire::Reason::Cancelled)?;
    if !matches_original(&go.original, original) || go.nonce != nonce
        || state.book.prepare_custody() != prepare::PeerCustody::Ready || state.book.prepared_nonce() != Some(nonce) {
        return Err(wire::Reason::CleanupUnknown);
    }
    client.phase.store(COPYING, Ordering::SeqCst); original.control.changed();
    send_metadata(original, state, nonce)?;
    loop {
        wait_work(original)?;
        match input.finish.try_recv() {
            Ok(finish) => {
                let source_joined = joined_source_completed(&original.source_join_seen, &original.source_return);
                if !matches_original(&finish.original, original) || !source_joined {
                    return Err(wire::Reason::CleanupUnknown);
                }
                let slot = client.flight.try_lock().map_err(|_| wire::Reason::CleanupUnknown)?;
                if slot.state != FlightState::Empty || !slot.bytes.is_empty() { return Err(wire::Reason::CleanupUnknown); }
                drop(slot);
                let ledger = state.transfer.as_mut().ok_or(wire::Reason::CleanupUnknown)?;
                let frame = transfer::Frame { identity: transfer::Identity { transaction: nonce,
                    inventory: client.reviewed.source.proposal().hashes()[0] }, sequence: state.frame_sequence,
                    kind: transfer::Kind::Finish, file: client.reviewed.source.proposal().payload_map().len()
                        .try_into().map_err(|_| wire::Reason::InputLimit)?, offset: ledger.expected_bytes() };
                let permit = ledger.admit(frame, &[]).map_err(|_| wire::Reason::ProtocolError)?;
                let total = ledger.written();
                let raw = frame.encode(&[]).map_err(|_| wire::Reason::ProtocolError)?;
                push(original, state, &raw, total, true)?;
                state.transfer.as_mut().ok_or(wire::Reason::CleanupUnknown)?.acknowledge(permit)
                    .map_err(|_| wire::Reason::ProtocolError)?;
                client.phase.store(VERIFYING, Ordering::SeqCst); original.control.changed(); return Ok(());
            }
            Err(oneshot::error::TryRecvError::Closed) => return Err(wire::Reason::Cancelled),
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
        match client.flight.try_lock() {
            Ok(mut slot) if slot.state == FlightState::Queued => {
                if slot.kind == transfer::Kind::Finish { return Err(wire::Reason::ProtocolError); }
                let expected = client.reviewed.source.proposal().payload_map().get(slot.file as usize)
                    .ok_or(wire::Reason::ProtocolError)?;
                if slot.expected_file_bytes != expected.installed.size { return Err(wire::Reason::ProtocolError); }
                let frame = transfer::Frame { identity: transfer::Identity { transaction: nonce,
                    inventory: client.reviewed.source.proposal().hashes()[0] }, sequence: state.frame_sequence,
                    kind: slot.kind, file: slot.file, offset: slot.offset };
                let ledger = state.transfer.as_mut().ok_or(wire::Reason::CleanupUnknown)?;
                let expected_payload = ledger.written().checked_add(if slot.kind == transfer::Kind::Data {
                    slot.bytes.len() as u64 } else { 0 }).ok_or(wire::Reason::InputLimit)?;
                let permit = ledger.admit(frame, &slot.bytes).map_err(|_| wire::Reason::ProtocolError)?;
                let raw = frame.encode(&slot.bytes).map_err(|_| wire::Reason::ProtocolError)?;
                slot.state = FlightState::InFlight;
                // The coordinator never needs this slot or native-book lock to
                // publish STOP. Source waits with try_lock and its own cutoff.
                if let Err(reason) = push(original, state, &raw, expected_payload, false) {
                    slot.state = FlightState::Failed; return Err(reason);
                }
                state.transfer.as_mut().ok_or(wire::Reason::CleanupUnknown)?.acknowledge(permit)
                    .map_err(|_| wire::Reason::ProtocolError)?;
                state.frame_sequence = state.frame_sequence.checked_add(1).ok_or(wire::Reason::InputLimit)?;
                slot.state = FlightState::Acknowledged;
            }
            Ok(_) | Err(TryLockError::WouldBlock) => thread::park_timeout(HEARTBEAT),
            Err(TryLockError::Poisoned(_)) => return Err(wire::Reason::CleanupUnknown),
        }
    }
}
fn settle_peer(original: &Operation, state: &mut NativeOriginal) -> bool {
    let client = original_client(original);
    if state.book.peer_nonentry_known() { state.peer_final = true; return true; }
    let Some(nonce) = state.book.prepared_nonce() else {
        client.fail(original, wire::Reason::CleanupUnknown); return false;
    };
    let mut stopped = false;
    while client.cleanup(original) {
        let request = if original.control.failure().is_some() && !stopped {
            let Some(first) = client.signal.first() else { client.fail(original, wire::Reason::CleanupUnknown); return false; };
            stopped = true;
            native::Envelope::encode(nonce, 0, native::Verb::Stop, &first.to_be_bytes())
        } else { native::Envelope::encode(nonce, 0, native::Verb::Status, &[]) };
        let request = match request { Ok(request) => request, Err(_) => { client.fail(original, wire::Reason::CleanupUnknown); return false; } };
        let status = match state.book.exchange(&request, true) {
            Ok(status) => status, Err(failure) => { client.fail(original, failure_reason(failure)); return false; }
        };
        client.synchronize(original);
        match take_terminal(original, state, &status) {
            Ok(true) => return true, Ok(false) => {}
            Err(reason) => { client.fail(original, reason); return false; }
        }
        thread::park_timeout(HEARTBEAT);
    }
    client.fail(original, wire::Reason::CleanupUnknown); false
}
/// The actual worker always retires preparation and attempts its independent
/// native releases, including when body GO or peer finality is lost. These
/// private callbacks are immediate borrows, never stored or renderer inputs.
fn settle_after_body<S, P>(state: &mut S, body: Result<(), wire::Reason>,
    mut fail: impl FnMut(wire::Reason), preparation: impl FnOnce(),
    peer: impl FnOnce(&mut S) -> P, release: impl FnOnce(&mut S) -> bool) -> (P, bool) {
    if let Err(reason) = body { fail(reason); }
    preparation();
    let peer = peer(state);
    let closed = release(state);
    (peer, closed)
}
fn ipc_worker(original: Arc<Operation>, mut input: IpcInputs) -> ClientReturn {
    let client = original_client(&original);
    let mut native_slot = match client.native.lock() {
        Ok(state) => state, Err(_) => {
            client.fail(&original, wire::Reason::CleanupUnknown);
            return ClientReturn { known: false, first: original.control.failure(), entered: true,
                hello_entered: false, peer_final: false, terminal: None, retained_bytes: None };
        }
    };
    let Some(state) = native_slot.as_mut() else {
        client.fail(&original, wire::Reason::CleanupUnknown);
        return ClientReturn { known: false, first: original.control.failure(), entered: false,
            hello_entered: false, peer_final: false, terminal: None, retained_bytes: None };
    };
    let body = ipc_body(&original, state, &mut input);
    let ((entered, peer_final), closed) = settle_after_body(state, body,
        |reason| client.fail(&original, reason),
        || {
            // GO loss also retires the actual inert identity; no Drop proof.
            client.preparation.run_if_not_returned();
            client.phase.store(SETTLING, Ordering::SeqCst); original.control.changed();
        },
        |state| {
            let entered = !state.book.peer_nonentry_known();
            (entered, settle_peer(&original, state))
        },
        |state| {
            // Peer failure does not suppress an independent permitted release.
            client.synchronize(&original);
            let closed = state.book.release() && state.book.settled();
            client.synchronize(&original);
            closed
        });
    let retained_bytes = closed.then(||ClientOriginal::reservation_bytes()?.checked_add(client.preparation.retained_bytes()?)).flatten();
    let known = peer_final && closed && client.preparation.known_return() && retained_bytes.is_some();
    if !known { client.fail(&original, wire::Reason::CleanupUnknown); }
    ClientReturn { known, first: original.control.failure(), entered, hello_entered: state.hello_entered,
        peer_final, terminal: state.terminal.clone(), retained_bytes }
}

struct CoordinatorInputs<O = Operation> {
    begin: oneshot::Receiver<BeginPreparation>, prepare: Option<oneshot::Sender<BeginPreparation>>,
    ready: oneshot::Receiver<Ready<O>>, reproof: Option<oneshot::Sender<ReadOnlyReproof<O>>>,
    reproved: oneshot::Receiver<Reproved<O>>, source_go: Option<oneshot::Sender<TransferGo<O>>>,
    ipc_go: Option<oneshot::Sender<TransferGo<O>>>, finish: Option<oneshot::Sender<FinishAfterSourceJoin<O>>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage { AwaitPreparation, Preparing, Reproving, AwaitTransfer, Transferring, Finishing, Stopping }
/// The production coordinator's one-use channel cut, not a second model.
/// Generic owner identity permits inert DATA fixtures; production retains the
/// same Weak<Operation> and no callbacks/owners are stored in this structure.
struct CoordinatorBarriers<O = Operation> {
    input: CoordinatorInputs<O>, stage: Stage,
    ready_nonce: Option<[u8; 16]>, reproved_nonce: Option<[u8; 16]>,
}
impl<O> CoordinatorBarriers<O> {
    fn new(input: CoordinatorInputs<O>) -> Self {
        Self { input, stage: Stage::AwaitPreparation, ready_nonce: None, reproved_nonce: None }
    }
    fn tick(&mut self, original: &Arc<O>, control: &Control,
        work: impl FnMut() -> bool, admitted: impl FnMut() -> Option<bool>,
        current: impl FnMut() -> Option<bool>, mut fail: impl FnMut(wire::Reason)) {
        if let Err(reason) = self.advance(original, control, work, admitted, current) { fail(reason); }
    }
    fn advance(&mut self, original: &Arc<O>, control: &Control,
        mut work: impl FnMut() -> bool, mut admitted: impl FnMut() -> Option<bool>,
        mut current: impl FnMut() -> Option<bool>) -> Result<(), wire::Reason> {
        if control.failure().is_some() || control.unknown.load(Ordering::SeqCst) {
            self.stage = Stage::Stopping;
            // Closing barriers wakes only our already registered originals.
            self.input.prepare.take(); self.input.reproof.take(); self.input.source_go.take();
            self.input.ipc_go.take(); self.input.finish.take();
            return Ok(());
        }
        match self.stage {
            Stage::AwaitPreparation => match self.input.begin.try_recv() {
                Ok(_) => {
                    if self.input.prepare.take().is_none_or(|sender| sender.send(BeginPreparation).is_err()) {
                        return Err(wire::Reason::CleanupUnknown);
                    }
                    self.stage = Stage::Preparing;
                }
                Err(oneshot::error::TryRecvError::Closed) => return Err(wire::Reason::Cancelled),
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            Stage::Preparing => match self.input.ready.try_recv() {
                Ok(ready) if matches_original(&ready.original, original) && work() => {
                    self.ready_nonce = Some(ready.nonce);
                    if self.input.reproof.take().is_none_or(|sender| sender.send(ReadOnlyReproof {
                        original: Arc::downgrade(original), nonce: ready.nonce }).is_err()) {
                        return Err(wire::Reason::CleanupUnknown);
                    }
                    self.stage = Stage::Reproving;
                }
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => return Err(wire::Reason::CleanupUnknown),
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            Stage::Reproving => match self.input.reproved.try_recv() {
                Ok(reproved) if matches_original(&reproved.original, original) && self.ready_nonce == Some(reproved.nonce) => {
                    self.reproved_nonce = Some(reproved.nonce); self.stage = Stage::AwaitTransfer;
                }
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => return Err(wire::Reason::CleanupUnknown),
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            Stage::AwaitTransfer => if admitted() == Some(true) && work() {
                let current = current();
                if current.is_none() || self.ready_nonce != self.reproved_nonce || self.ready_nonce.is_none() {
                    return Err(wire::Reason::ContextChanged);
                } else if current == Some(true) && admitted() == Some(true) && work() {
                    let nonce = self.ready_nonce.expect("checked same original Ready");
                    let source = self.input.source_go.take().is_some_and(|sender| sender.send(TransferGo {
                        original: Arc::downgrade(original), nonce }).is_ok());
                    let ipc = self.input.ipc_go.take().is_some_and(|sender| sender.send(TransferGo {
                        original: Arc::downgrade(original), nonce }).is_ok());
                    if source && ipc { self.stage = Stage::Transferring; }
                    else { return Err(wire::Reason::CleanupUnknown); }
                }
            }
            Stage::Transferring | Stage::Finishing | Stage::Stopping => {}
        }
        Ok(())
    }
    fn finish_after_source_join(&mut self, original: &Arc<O>, control: &Control,
        source: &Option<JoinHandle<SourceReturn>>, joined: &AtomicBool,
        returned: &Mutex<Option<Result<SourceReturn, tokio::task::JoinError>>>) -> Result<(), wire::Reason> {
        if self.stage == Stage::Transferring && joined.load(Ordering::SeqCst)
            && control.failure().is_none() && !control.unknown.load(Ordering::SeqCst) {
            // The coordinator still holds its original source slot. Do not
            // replace the consumed handle with a worker-return notification.
            if !joined_source_completed(joined, returned) || source.is_some()
                || self.input.finish.take().is_none_or(|sender|
                    sender.send(FinishAfterSourceJoin { original: Arc::downgrade(original) }).is_err()) {
                return Err(wire::Reason::CleanupUnknown);
            }
            self.stage = Stage::Finishing;
        }
        Ok(())
    }
}
fn joined_source_completed(joined: &AtomicBool,
    returned: &Mutex<Option<Result<SourceReturn, tokio::task::JoinError>>>) -> bool {
    joined.load(Ordering::SeqCst) && returned.try_lock().is_ok_and(|returned|
        matches!(returned.as_ref(), Some(Ok(value)) if value.known && value.entered
            && value.first.is_none() && value.retained_bytes.is_some()))
}
async fn coordinate(original: Arc<Operation>, input: CoordinatorInputs) -> bool {
    let client = original_client(&original);
    let mut source = original.source_handle.lock().await;
    let mut ipc = client.ipc.lock().await;
    let mut barriers = CoordinatorBarriers::new(input);
    let waker = Waker::from(Arc::new(FinalWake(original.owner.clone())));
    loop {
        client.preparation.tick(true);
        client.synchronize(&original);
        let now = Instant::now();
        if now >= original.control.endpoint() {
            client.fail(&original, wire::Reason::CleanupUnknown); return false;
        }
        barriers.tick(&original, &original.control, || client.work(&original),
            || coordinator_work(&original), || current_original(&original), |reason| client.fail(&original, reason));
        // These are the original handles, not receipts sent by their workers.
        // No resource/native lock is acquired while independent deadlines run.
        {
        let mut context = TaskContext::from_waker(&waker);
        if !original.source_join_seen.load(Ordering::SeqCst) && source.is_some() {
            let _ = poll_source(&original, &mut source, &mut context, Instant::now());
        }
        if !client.joined.load(Ordering::SeqCst) && ipc.is_some() {
            let _ = client.poll(&original, &mut ipc, &mut context, Instant::now());
        }
        }
        if let Err(reason) = barriers.finish_after_source_join(&original, &original.control,
            &source, &original.source_join_seen, &original.source_return) {
            client.fail(&original, reason);
        }
        if original.source_join_seen.load(Ordering::SeqCst) && client.joined.load(Ordering::SeqCst) {
            drop(source); drop(ipc);
            client.synchronize(&original);
            return original.known_return() && Instant::now() < original.control.endpoint();
        }
        tokio::time::sleep(HEARTBEAT).await;
    }
}

pub(super) fn admit(owner: &SavedCommandOwner, document: &Arc<()>, registry: &mut Registry,
    checked: &Checked, current: crate::asset_session::ValidatedSavedInput,
    census: &crate::asset_session::AndroidRegistrationCensus<'_>, gate: android_wire::Availability,
    reviewed: Arc<Review>) -> Result<Admitted, BridgeError> {
    let snapshot = &checked.snapshot;
    if prerequisite(&registry.android_registration.service) != wire::Prerequisite::Ready
        || owner.inner.android_service_dispatcher.get().is_none()
        || snapshot.reviewed.as_ref().is_none_or(|before| !Arc::ptr_eq(before, &reviewed))
        || checked.instance != reviewed.source.instance() || checked.review_id != reviewed.public.review_id {
        return Err(wire::unavailable());
    }
    let supplier_reservation = crate::android_supplier_macos::max_working_reservation_bytes().map_err(|_| wire::unavailable())?;
    let source_reservation = AndroidRegistrationSourceSlots::working_reservation_bytes()
        .and_then(|bytes| bytes.checked_add(supplier_reservation)).ok_or_else(wire::unavailable)?;
    let work = snapshot.at.checked_add(WORK).ok_or_else(wire::unavailable)?;
    let hard = snapshot.at.checked_add(HARD).ok_or_else(wire::unavailable)?;
    let observed = Instant::now();
    if observed >= work || observed >= reviewed.expires || checked.id == reviewed.original.data.operation_id
        || checked.id == reviewed.public.review_id { return Err(wire::unavailable()); }
    let generation = match registry.android_registration.generation.checked_add(1).filter(|value| *value < u32::MAX) {
        Some(value) => value, None => {
            registry.android_registration.exhaust(observed); registry.disabled = true; owner.inner.bump(registry);
            return Err(BridgeError::cleanup_unknown());
        }
    };
    let previous = registration_retained_bytes(&owner.inner, registry, document, checked, census).ok_or_else(wire::unavailable)?;
    let executor = tokio::runtime::Handle::try_current().map_err(|_| wire::unavailable())?;
    let cohort = snapshot.cohort.lock().map_err(|_| wire::unconfirmed())?.take().ok_or_else(wire::invalid)?;
    if !owner.inner.android_registration_control.current_claim(&cohort) { return Err(wire::invalid()); }
    let (stop, _) = watch::channel(false); let (audit, audit_read) = watch::channel(hard);
    let control = Arc::new(Control { lane:ControlLane::Sources, owner: Arc::downgrade(&owner.inner), id: checked.id.clone(), generation,
        admitted: snapshot.at, work, hard, slot: Arc::downgrade(&owner.inner.android_registration_control),
        cohort: cohort.identity.clone(), epoch: cohort.epoch, first: Mutex::new(None),
        unknown: AtomicBool::new(false), dirty: AtomicBool::new(false), latches: AtomicUsize::new(0), stop, audit });
    let data = wire::Operation { operation_id: checked.id.clone(), registration_generation: generation,
        source_generation: snapshot.source.generation, kind: wire::Kind::Registration, context: snapshot.request.context().clone() };
    let client_bytes = ClientOriginal::reservation_bytes().ok_or_else(wire::unavailable)?;
    let dispatcher=owner.inner.android_service_dispatcher.get().cloned().ok_or_else(wire::unavailable)?;
    // Before genuine Ready the source slots are inert. The actual fixed Check
    // retires inspector storage and enforces its retained bound before native
    // begin/reproof. Reserve the larger genuine phase, never omit live storage.
    let phase_bytes=source_reservation.checked_add(service_setup::Preparation::SETTLED_BYTES)
        .map(|bytes|bytes.max(service_setup::Preparation::reservation_bytes().unwrap_or(usize::MAX)))
        .ok_or_else(wire::unavailable)?;
    let total = previous.checked_add(arc_bytes::<Operation>().ok_or_else(wire::unavailable)?)
        .and_then(|n| n.checked_add(operation_projection_bytes(&data)?))
        .and_then(|n| n.checked_add(checked.review_id.capacity()))
        .and_then(|n| n.checked_add(checked.instance.capacity()))
        .and_then(|n| n.checked_add(control.retained_bytes()?))
        .and_then(|n| n.checked_add(phase_bytes)).and_then(|n| n.checked_add(client_bytes))
        .and_then(|n| n.checked_add(3usize.checked_mul(wire::STATUS_LIMIT)?))
        .and_then(|n| n.checked_add(3usize.checked_mul(wire::REQUEST_LIMIT)?))
        .filter(|n| *n <= OWNED_LIMIT).ok_or_else(wire::unavailable)?;
    // The whole high-water, including bounded task/channel cells, is accepted
    // BEFORE allocating the flight buffer. ClientBook is not constructed until
    // control admission below, so failed DATA admission cannot leak its retained
    // ManuallyDrop Signal or invent cleanup in Drop.
    let client = ClientOriginal::reserve(reviewed,WorkGate{slot:owner.inner.android_registration_control.clone(),control:control.clone()},dispatcher).ok_or_else(wire::unavailable)?;
    let original = Arc::new(Operation { owner: Arc::downgrade(&owner.inner), document: Arc::downgrade(document),
        source: snapshot.source.clone(), data, saved: current, cohort, review_id: checked.review_id.clone(),
        instance: checked.instance.clone(), control: control.clone(), supplier_reservation,
        reservation: OnceLock::new(), settling: AtomicBool::new(false), source_handle: AsyncMutex::new(None),
        source_return: Mutex::new(None), source_join_seen: AtomicBool::new(false), coordinator: Mutex::new(None),
        coordinator_return: Mutex::new(None), final_seen: AtomicBool::new(false), joined_at: OnceLock::new(),
        accepted: AtomicBool::new(false), client: Some(client),
        sources: Mutex::new(AndroidRegistrationSourceSlots::new_registered(audit_read,
            WorkGate { slot: owner.inner.android_registration_control.clone(), control: control.clone() })) });
    let (release, begin) = oneshot::channel();
    let (prepare, preparation) = oneshot::channel(); let (ready_send, ready) = oneshot::channel();
    let (reproof_send, reproof) = oneshot::channel(); let (reproved_send, reproved) = oneshot::channel();
    let (source_go, source_transfer) = oneshot::channel(); let (ipc_go, ipc_transfer) = oneshot::channel();
    let (finish_send, finish) = oneshot::channel();
    let source_task = { let original = original.clone(); move || source_worker(original, SourceInputs {
        reproof, reproved: reproved_send, transfer: source_transfer }) };
    let ipc_task = { let original = original.clone(); move || ipc_worker(original, IpcInputs {
        preparation, ready: Some(ready_send), transfer: ipc_transfer, finish }) };
    let coordinator = coordinate(original.clone(), CoordinatorInputs { begin, prepare: Some(prepare), ready,
        reproof: Some(reproof_send), reproved, source_go: Some(source_go), ipc_go: Some(ipc_go), finish: Some(finish_send) });
    let task_bytes = std::mem::size_of_val(&source_task).checked_add(std::mem::size_of_val(&ipc_task))
        .and_then(|n| n.checked_add(std::mem::size_of_val(&coordinator)))
        .and_then(|n| n.checked_add(2usize.checked_mul(std::mem::size_of::<SourceReturn>())?))
        .and_then(|n| n.checked_add(std::mem::size_of::<Finalization>()))
        .ok_or_else(wire::unavailable)?;
    if task_bytes > TASK_STORAGE { return Err(wire::unavailable()); }
    original.reservation.set(Reservation { whole: total, source: source_reservation }).map_err(|_| wire::unavailable())?;
    let mut native_slot = original_client(&original).native.try_lock().map_err(|_| wire::unavailable())?;
    if native_slot.is_some() { return Err(wire::unavailable()); }
    if !owner.inner.android_registration_control.install(control, &original.cohort, snapshot.reviewed.as_ref()) {
        return Err(wire::unavailable());
    }
    *native_slot = Some(NativeOriginal { book: native::ClientBook::new(original_client(&original).signal.clone()),
        transfer: None, frame_sequence: 0, envelope_sequence: 0, payload_bytes: 0, hello_entered: false,
        terminal: None, peer_final: false });
    drop(native_slot);
    registry.android_registration.review = None;
    registry.android_registration.generation = generation;
    registry.android_registration.active = Some(original.clone());
    // Publication changes error semantics. From here, retain/settle originals
    // even on lost reply/GO; never fall back to pre-admission unavailable.
    let publish_handles = || -> Result<(), ()> {
        let mut source_slot = original.source_handle.try_lock().map_err(|_| ())?;
        let mut ipc_slot = original_client(&original).ipc.try_lock().map_err(|_| ())?;
        let mut coordinator_slot = original.coordinator.try_lock().map_err(|_| ())?;
        *source_slot = Some(executor.spawn_blocking(source_task));
        *ipc_slot = Some(executor.spawn_blocking(ipc_task));
        *coordinator_slot = Some(executor.spawn(coordinator));
        Ok(())
    };
    if publish_handles().is_err() {
        original.control.mark_unknown(observed); registry.disabled = true; owner.inner.bump(registry);
        return Err(wire::unconfirmed());
    }
    owner.inner.bump(registry);
    let status = owner.registration_status_locked(registry, gate, observed).map_err(|_| {
        original.control.stop_at(wire::Reason::ResultLimit, Instant::now()); wire::unconfirmed()
    })?;
    Ok(Admitted { status, release: Some(InvokeEntry::Registration(release)), original })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Closed observation DATA only. No IPC, source or service is entered.
    fn ack()->native::Status{native::Status{phase:native::Phase::Active,account:501,nonce:[1;16],
        enqueued:3,processed:2,payload_bytes:10,first:None,cleanup:None,unknown:false,terminal:Vec::new()}}
    fn observe(status:&native::Status,finish:bool)->Result<Ack,wire::Reason>{processed_ack(status,501,[1;16],2,10,20,finish)}
    #[test]
    fn enqueued_busy_and_processed_are_distinct_and_finish_never_precedes_its_ack(){
        let mut status=ack();assert_eq!(observe(&status,false),Ok(Ack::Pending));
        status.phase=native::Phase::Busy;status.enqueued=0;status.processed=0;status.payload_bytes=0;
        assert_eq!(observe(&status,false),Ok(Ack::Pending));
        status=ack();status.processed=3;status.payload_bytes=20;
        assert_eq!(observe(&status,false),Ok(Ack::Processed));
        for phase in [native::Phase::InputClosed,native::Phase::Complete]{
            status.phase=phase;
            assert_eq!(observe(&status,false),Err(wire::Reason::ProtocolError));
            assert_eq!(observe(&status,true),Ok(Ack::Processed));
            status.processed=2;assert_eq!(observe(&status,true),Err(wire::Reason::ProtocolError));status.processed=3;
        }
        // ACK is not parsed terminal/native/source/coordinator finality.
        assert!(status.terminal.is_empty());
    }
    #[test]
    fn ack_rejects_wrong_account_nonce_sequence_payload_and_earlier_failure(){
        let mut status=ack();status.account=502;assert_eq!(observe(&status,false),Err(wire::Reason::ProtocolError));
        status=ack();status.nonce=[2;16];assert_eq!(observe(&status,false),Err(wire::Reason::ProtocolError));
        for (enqueued,processed,bytes) in [(2,2,10),(4,2,10),(3,1,10),(3,4,20),(3,2,20),(3,3,10)]{
            status=ack();status.enqueued=enqueued;status.processed=processed;status.payload_bytes=bytes;
            assert_eq!(observe(&status,false),Err(wire::Reason::ProtocolError));
        }
        status=ack();status.first=Some(1);assert_eq!(observe(&status,false),Err(wire::Reason::RegistrationRefused));
        status.phase=native::Phase::Busy;assert_eq!(observe(&status,false),Err(wire::Reason::RegistrationRefused));
        status.unknown=true;assert_eq!(observe(&status,false),Err(wire::Reason::CleanupUnknown));
        status=ack();assert_eq!(processed_ack(&status,501,[1;16],u32::MAX-1,10,20,false),Err(wire::Reason::ProtocolError));
        assert_eq!(processed_ack(&status,501,[1;16],2,10,9,false),Err(wire::Reason::ProtocolError));
    }

    // These fixtures own only inert identity/control DATA and real one-use
    // channels. They do not construct an Operation, saved witness, source book,
    // ServiceManager or native registration authority.
    struct Peers {
        begin: Option<oneshot::Sender<BeginPreparation>>, prepare: oneshot::Receiver<BeginPreparation>,
        ready: Option<oneshot::Sender<Ready<()>>>, reproof: oneshot::Receiver<ReadOnlyReproof<()>>,
        reproved: Option<oneshot::Sender<Reproved<()>>>, source: oneshot::Receiver<TransferGo<()>>,
        ipc: Option<oneshot::Receiver<TransferGo<()>>>, finish: oneshot::Receiver<FinishAfterSourceJoin<()>>,
    }
    fn barrier_fixture() -> (CoordinatorBarriers<()>, Peers) {
        let (begin, begin_rx) = oneshot::channel(); let (prepare, prepare_rx) = oneshot::channel();
        let (ready, ready_rx) = oneshot::channel(); let (reproof, reproof_rx) = oneshot::channel();
        let (reproved, reproved_rx) = oneshot::channel(); let (source, source_rx) = oneshot::channel();
        let (ipc, ipc_rx) = oneshot::channel(); let (finish, finish_rx) = oneshot::channel();
        (CoordinatorBarriers::new(CoordinatorInputs { begin: begin_rx, prepare: Some(prepare), ready: ready_rx,
            reproof: Some(reproof), reproved: reproved_rx, source_go: Some(source), ipc_go: Some(ipc), finish: Some(finish) }),
        Peers { begin: Some(begin), prepare: prepare_rx, ready: Some(ready), reproof: reproof_rx,
            reproved: Some(reproved), source: source_rx, ipc: Some(ipc_rx), finish: finish_rx })
    }
    fn tick(barriers: &mut CoordinatorBarriers<()>, original: &Arc<()>, control: &Control,
        admitted: Option<bool>, current: Option<bool>) {
        barriers.tick(original, control, || control.failure().is_none() && !control.unknown.load(Ordering::SeqCst),
            || admitted, || current, |reason| control.stop_at(reason, Instant::now()));
    }
    fn to_reproof(barriers: &mut CoordinatorBarriers<()>, peers: &mut Peers, original: &Arc<()>, control: &Control) {
        assert!(peers.begin.take().unwrap().send(BeginPreparation).is_ok());
        tick(barriers, original, control, Some(true), Some(true));
        assert!(peers.prepare.try_recv().is_ok());
        assert!(peers.ready.take().unwrap().send(Ready { original: Arc::downgrade(original), nonce: [1; 16] }).is_ok());
        tick(barriers, original, control, Some(true), Some(true));
        let permit = peers.reproof.try_recv().unwrap();
        assert!(matches_original(&permit.original, original)); assert_eq!(permit.nonce, [1; 16]);
        assert_eq!(barriers.stage, Stage::Reproving);
    }
    fn to_transfer(barriers: &mut CoordinatorBarriers<()>, peers: &mut Peers, original: &Arc<()>, control: &Control) {
        to_reproof(barriers, peers, original, control);
        assert!(peers.reproved.take().unwrap().send(Reproved { original: Arc::downgrade(original), nonce: [1; 16] }).is_ok());
        tick(barriers, original, control, Some(true), Some(true));
        tick(barriers, original, control, Some(true), Some(true));
        assert_eq!(barriers.stage, Stage::Transferring);
    }
    #[test]
    fn same_original_ready_reproof_and_current_gates_precede_transfer() {
        let (_slot, control, _cohort, _gate) = lifecycle_book_tests::control_at(Instant::now());
        let original = Arc::new(()); let (mut barriers, mut peers) = barrier_fixture();
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        assert_eq!(barriers.stage, Stage::AwaitPreparation);
        assert!(matches!(peers.prepare.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(matches!(peers.reproof.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(peers.begin.take().unwrap().send(BeginPreparation).is_ok());
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        assert!(peers.prepare.try_recv().is_ok());
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        assert!(matches!(peers.reproof.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(matches!(peers.source.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(peers.ready.take().unwrap().send(Ready { original: Arc::downgrade(&original), nonce: [1; 16] }).is_ok());
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        let reproof = peers.reproof.try_recv().unwrap();
        assert!(matches_original(&reproof.original, &original)); assert_eq!(reproof.nonce, [1; 16]);
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        assert!(matches!(peers.source.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(matches!(peers.ipc.as_mut().unwrap().try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(peers.reproved.take().unwrap().send(Reproved { original: reproof.original, nonce: reproof.nonce }).is_ok());
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        assert_eq!(barriers.stage, Stage::AwaitTransfer);
        // Conditional pending and temporarily busy current DATA both wait,
        // without inventing ContextChanged or consuming either TransferGo.
        tick(&mut barriers, &original, &control, Some(false), Some(true));
        tick(&mut barriers, &original, &control, Some(true), Some(false));
        assert!(control.failure().is_none());
        assert!(matches!(peers.source.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(matches!(peers.ipc.as_mut().unwrap().try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        for go in [peers.source.try_recv().unwrap(), peers.ipc.as_mut().unwrap().try_recv().unwrap()] {
            assert!(matches_original(&go.original, &original)); assert_eq!(go.nonce, [1; 16]);
        }
        assert_eq!(barriers.stage, Stage::Transferring);
        assert!(barriers.input.source_go.is_none() && barriers.input.ipc_go.is_none());
        assert!(matches!(peers.finish.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
    }
    #[test]
    fn mismatched_reproof_lost_go_and_earlier_failure_close_original_barriers() {
        // The same production tick latches the returned channel failure before
        // cleanup. No replacement operation, new GO or native entry is made.
        for wrong_owner in [false, true] {
            let (_slot, control, _cohort, _gate) = lifecycle_book_tests::control_at(Instant::now());
            let original = Arc::new(()); let foreign = Arc::new(()); let (mut barriers, mut peers) = barrier_fixture();
            to_reproof(&mut barriers, &mut peers, &original, &control);
            let candidate = if wrong_owner { &foreign } else { &original };
            let nonce = if wrong_owner { [1; 16] } else { [2; 16] };
            assert!(peers.reproved.take().unwrap().send(Reproved { original: Arc::downgrade(candidate), nonce }).is_ok());
            tick(&mut barriers, &original, &control, Some(true), Some(true));
            assert_eq!(control.failure().unwrap().0, wire::Reason::CleanupUnknown);
            tick(&mut barriers, &original, &control, Some(true), Some(true));
            assert_eq!(barriers.stage, Stage::Stopping);
            assert!(matches!(peers.source.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
            assert!(matches!(peers.ipc.as_mut().unwrap().try_recv(), Err(oneshot::error::TryRecvError::Closed)));
        }
        {
            let (_slot, control, _cohort, _gate) = lifecycle_book_tests::control_at(Instant::now());
            let original = Arc::new(()); let (mut barriers, mut peers) = barrier_fixture();
            drop(peers.begin.take());
            tick(&mut barriers, &original, &control, Some(true), Some(true));
            assert_eq!(control.failure().unwrap().0, wire::Reason::Cancelled);
            tick(&mut barriers, &original, &control, Some(true), Some(true));
            assert!(matches!(peers.prepare.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
            assert!(matches!(peers.reproof.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
            assert!(matches!(peers.source.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
        }
        let (_slot, control, _cohort, _gate) = lifecycle_book_tests::control_at(Instant::now());
        let original = Arc::new(()); let (mut barriers, mut peers) = barrier_fixture();
        to_reproof(&mut barriers, &mut peers, &original, &control);
        assert!(peers.reproved.take().unwrap().send(Reproved { original: Arc::downgrade(&original), nonce: [1; 16] }).is_ok());
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        drop(peers.ipc.take()); // Source GO may publish, but peer GO is lost.
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        assert!(peers.source.try_recv().is_ok()); assert_ne!(barriers.stage, Stage::Transferring);
        assert_eq!(control.failure().unwrap().0, wire::Reason::CleanupUnknown);
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        assert!(matches!(peers.finish.try_recv(), Err(oneshot::error::TryRecvError::Closed)));

        let (_slot, control, _cohort, _gate) = lifecycle_book_tests::control_at(Instant::now());
        let (mut barriers, mut peers) = barrier_fixture(); let first = Instant::now();
        control.stop_at(wire::Reason::Cancelled, first);
        assert!(peers.begin.take().unwrap().send(BeginPreparation).is_ok());
        tick(&mut barriers, &original, &control, Some(true), Some(true));
        assert_eq!(control.failure(), Some((wire::Reason::Cancelled, first)));
        assert_eq!(barriers.stage, Stage::Stopping);
        assert!(matches!(peers.prepare.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
        assert!(matches!(peers.reproof.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
    }
    #[test]
    fn finish_requires_the_actual_source_handle_consumption_not_worker_return() {
        // Current-thread async DATA worker only; no threads/processes/native
        // resources or detached source work survive this private runtime.
        tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
            let (_slot, control, _cohort, _gate) = lifecycle_book_tests::control_at(Instant::now());
            let original = Arc::new(()); let (mut barriers, mut peers) = barrier_fixture();
            to_transfer(&mut barriers, &mut peers, &original, &control);
            let joined = AtomicBool::new(false); let returned = Mutex::new(None);
            let (release, enter) = oneshot::channel();
            let mut source = Some(tokio::spawn(async move {
                enter.await.unwrap();
                SourceReturn { known: true, entered: true, first: None, retained_bytes: Some(0), review: None }
            }));
            let waker = Waker::from(Arc::new(FinalWake(Weak::new())));
            let mut cx = TaskContext::from_waker(&waker);
            assert_eq!(poll_source_cells(&control, &joined, &returned, &mut source, &mut cx, Instant::now()), Poll::Pending);
            barriers.finish_after_source_join(&original, &control, &source, &joined, &returned).unwrap();
            assert!(matches!(peers.finish.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !source.as_ref().unwrap().is_finished() { tokio::task::yield_now().await; }
            }).await.unwrap();
            // This actual task has returned, but its original handle and return
            // value have not been consumed by the coordinator yet.
            assert!(!joined.load(Ordering::SeqCst)); assert!(returned.lock().unwrap().is_none());
            assert!(!joined_source_completed(&joined, &returned));
            barriers.finish_after_source_join(&original, &control, &source, &joined, &returned).unwrap();
            assert!(matches!(peers.finish.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
            assert_eq!(poll_source_cells(&control, &joined, &returned, &mut source, &mut cx, Instant::now()), Poll::Ready(true));
            assert!(source.is_none() && joined_source_completed(&joined, &returned));
            barriers.finish_after_source_join(&original, &control, &source, &joined, &returned).unwrap();
            let finish = peers.finish.try_recv().unwrap(); assert!(matches_original(&finish.original, &original));
            assert_eq!(barriers.stage, Stage::Finishing); assert!(barriers.input.finish.is_none());
            // Source completion is not IPC/coordinator/native/app finality.
            assert!(control.failure().is_none());
        });
    }
    #[test]
    fn go_loss_and_peer_failure_still_run_preparation_and_independent_native_release() {
        for peer_succeeds in [true, false] {
            let (_slot, control, _cohort, _gate) = lifecycle_book_tests::control_at(Instant::now());
            let events = std::cell::RefCell::new(Vec::new());
            let signal = Arc::new(native::Signal::reserved());
            let mut book = native::ClientBook::new(signal.clone());
            // Actual reserved ClientBook, no begin/prepare/connection/signature
            // call. false below injects peer-finality failure, not a peer receipt.
            let (peer_final, closed) = settle_after_body(&mut book, Err(wire::Reason::Cancelled),
                |reason| { events.borrow_mut().push("failure"); control.stop_at(reason, Instant::now()); },
                || { assert!(control.failure().is_some()); events.borrow_mut().push("preparation"); },
                |book| { events.borrow_mut().push("peer"); book.peer_nonentry_known() && peer_succeeds },
                |book| { events.borrow_mut().push("release"); book.release() && book.settled() });
            assert_eq!(*events.borrow(), ["failure", "preparation", "peer", "release"]);
            assert_eq!(peer_final, peer_succeeds); assert!(closed && book.settled());
            assert!(signal.bounds().is_none()); assert!(!signal.unknown());
            assert_eq!(Arc::strong_count(&signal), 1); assert_eq!(book.retained_bytes(), Some(0));
            assert_eq!(control.failure().unwrap().0, wire::Reason::Cancelled);
        }
    }
    #[test]
    fn native_clock_preserves_bidirectional_earliest_f_without_echo_or_renewal() {
        // macOS-native CLOCK_UPTIME_RAW bracket/Signal arm, not Linux DATA or
        // evidence of registration, signed installation, service or Store work.
        let (_slot, control, _cohort, _gate) = lifecycle_book_tests::control_at(Instant::now() - Duration::from_secs(2));
        let signal = native::Signal::reserved();
        let clock = OriginalClock::capture(&control, &signal).expect("same original Mac uptime bracket");
        let bounds = clock.bounds;
        assert_eq!(signal.bounds(), Some(bounds));
        assert_eq!(clock.bridge.earlier_endpoint(control.work), Some(bounds.work));
        assert_eq!(clock.bridge.earlier_endpoint(control.hard), Some(bounds.hard));
        let local = control.admitted + Duration::from_secs(1);
        control.stop_at(wire::Reason::Cancelled, local);
        clock.synchronize(&control, &signal);
        let raw = clock.bridge.earlier_endpoint(local).unwrap();
        let mapped = clock.bridge.earlier_instant_data(raw).unwrap();
        assert_eq!(signal.first(), Some(raw));
        assert_eq!(control.failure(), Some((wire::Reason::Cancelled, mapped)));
        let endpoint = control.endpoint();
        assert!(endpoint <= mapped + SETTLEMENT && endpoint <= control.hard);
        for _ in 0..8 {
            clock.synchronize(&control, &signal);
            assert_eq!(signal.first(), Some(raw)); assert_eq!(control.endpoint(), endpoint);
            assert_eq!(control.failure(), Some((wire::Reason::Cancelled, mapped)));
        }
        // A newly delivered earlier peer F still wins, but repeated importing
        // it must not run the bracket backwards at every heartbeat.
        let peer = raw - 100_000_000;
        signal.failure_at(peer, false); clock.synchronize(&control, &signal);
        let imported = clock.bridge.earlier_instant_data(peer).unwrap();
        assert_eq!(control.failure(), Some((wire::Reason::RegistrationRefused, imported)));
        let peer_endpoint = control.endpoint(); assert!(peer_endpoint < endpoint);
        for _ in 0..8 {
            clock.synchronize(&control, &signal);
            assert_eq!(signal.first(), Some(peer)); assert_eq!(control.endpoint(), peer_endpoint);
        }
        // Conversely, an even earlier local event must not be suppressed by
        // the anti-echo memo. Preserve its reason through the round trip.
        let earlier = imported - Duration::from_millis(100);
        control.stop_at(wire::Reason::ContextChanged, earlier); clock.synchronize(&control, &signal);
        let earlier_raw = clock.bridge.earlier_endpoint(earlier).unwrap();
        let earlier_mapped = clock.bridge.earlier_instant_data(earlier_raw).unwrap();
        assert_eq!(signal.first(), Some(earlier_raw));
        assert_eq!(control.failure(), Some((wire::Reason::ContextChanged, earlier_mapped)));
        let earliest_endpoint = control.endpoint(); assert!(earliest_endpoint < peer_endpoint);
        signal.failure_at(raw, false); control.stop_at(wire::Reason::Cancelled, local);
        for _ in 0..8 {
            clock.synchronize(&control, &signal);
            assert_eq!(signal.first(), Some(earlier_raw)); assert_eq!(control.endpoint(), earliest_endpoint);
            assert_eq!(control.failure(), Some((wire::Reason::ContextChanged, earlier_mapped)));
        }
        assert_eq!(signal.bounds(), Some(bounds));
        // Contended copied projection cannot park the independent watchdog.
        { let _held = clock.projection.lock().unwrap(); clock.synchronize(&control, &signal); }
        signal.clock_unknown(); clock.synchronize(&control, &signal);
        assert!(control.unknown.load(Ordering::SeqCst)); assert!(control.endpoint() <= control.admitted);
    }

}
