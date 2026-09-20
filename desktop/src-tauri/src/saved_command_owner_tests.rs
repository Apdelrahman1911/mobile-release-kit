//! Inert finite-domain/clock/decoder vectors. Invented DATA and memory IO below
//! are not runtime/tool/process custody, original native joins or qualification.
//! No test opens a file, inspects a runtime, launches a process or makes a permit.
use super::*;
use std::path::PathBuf;
use serde_json::{json, Value};

fn project() -> RegisteredRoot { RegisteredRoot { path: PathBuf::from("/unopened-saved-command-project"),
    identity: crate::asset_source::DirectoryIdentity::synthetic_evidence_identity() } }
fn application(domain: SavedCommandDomain) -> SavedCommandOwner {
    SavedCommandOwner::new(RuntimeConfig::packaged(PathBuf::from("/unopened-saved-command-runtime")), domain)
}
fn context(domain: SavedCommandDomain) -> Context { match domain {
    SavedCommandDomain::OfflinePreflight => Context::OfflinePreflight(wire::tests::context()),
    SavedCommandDomain::AndroidBuild => Context::AndroidBuild(android_wire::tests::context()),
} }
fn projection(domain: SavedCommandDomain) -> RunProjection { RunProjection {
    operation_id: "a".repeat(32), owner_generation: "b".repeat(32), context: context(domain),
    phase: Phase::AwaitingConsent, intent_usable: true, outcome: None, reason: Reason::None, result: None, stage: None,
} }
fn active(domain: SavedCommandDomain) -> (SavedCommandOwner, Arc<Session>) {
    let application = application(domain); let mut p = projection(domain);
    let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending);
    let (frames, receiver) = mpsc::channel(2);
    let profile = match domain { SavedCommandDomain::OfflinePreflight => Profile::OfflinePreflight(wire::Profile::LinuxX64),
        SavedCommandDomain::AndroidBuild => Profile::AndroidBuild(android_wire::Profile::LinuxX64) };
    let owner = Arc::new(Session { domain, id: p.operation_id.clone(), generation: p.owner_generation.clone(), context: p.context.clone(),
        profile, clocks: Clocks::new(domain, Instant::now()), registration: 1, project: project(), request: AsyncMutex::new(None),
        stop, pipes, frames, wake: Notify::new(), output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false),
        driver_done: AtomicBool::new(false), driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false),
        watchdog_joined: AtomicBool::new(false), watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false),
        startup: Mutex::new(Startup::default()), resources: AsyncMutex::new(Resources { frames: Some(receiver), ..Resources::default() }),
        input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())), error: Arc::new(AsyncMutex::new(Pipe::default())),
        driver: AsyncMutex::new(None), watchdog: Mutex::new(None), manager: AsyncMutex::new(None), observer: AsyncMutex::new(None),
        driver_return: Mutex::new(None), manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None),
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        fixture: None,
    });
    p.phase = Phase::Starting; p.intent_usable = false;
    application.inner.lock().active = Some(Active { owner: owner.clone(), projection: p, first_stop: None, work_expired: false,
        accepted: false, terminal: false, unknown: false, final_join_seen: false });
    (application, owner)
}
fn android_terminal(value: &Value) -> android_wire::Terminal {
    android_wire::terminal(value, &android_wire::tests::context()).unwrap()
}
fn frame(domain: SavedCommandDomain, sequence: u32, kind: &str, payload: Value) -> Vec<u8> {
    let protocol = match domain { SavedCommandDomain::OfflinePreflight => wire::PROTOCOL, SavedCommandDomain::AndroidBuild => android_wire::PROTOCOL };
    let mut bytes = serde_json::to_vec(&json!({"protocol":protocol,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
        "sequence":sequence,"kind":kind,"payload":payload})).unwrap(); bytes.push(b'\n'); bytes
}
fn accepted(domain: SavedCommandDomain) -> Vec<u8> {
    let context = match context(domain) { Context::OfflinePreflight(c) => serde_json::to_value(c).unwrap(),
        Context::AndroidBuild(c) => serde_json::to_value(c).unwrap() };
    frame(domain, 0, "accepted", json!({"schemaVersion":1,"context":context}))
}
fn complete_stream(domain: SavedCommandDomain, progress: bool) -> Vec<Vec<u8>> {
    let mut frames = vec![accepted(domain)];
    match domain {
        SavedCommandDomain::OfflinePreflight => {
            let wire::Frame::Terminal(terminal) = wire::tests::terminal_frame(&wire::tests::context()) else { panic!("offline DATA") };
            frames.push(frame(domain, 1, "terminal", serde_json::to_value(terminal).unwrap()));
        }
        SavedCommandDomain::AndroidBuild => {
            if progress { for stage in ["inputs-bound", "building", "capturing", "inspecting", "disposing-work"] {
                frames.push(frame(domain, frames.len() as u32, "progress", json!({"schemaVersion":1,"stage":stage})));
            } }
            frames.push(frame(domain, frames.len() as u32, "terminal", android_wire::tests::complete_with_failed_inspection()));
        }
    }
    frames
}

#[test]
fn two_domains_have_fixed_nonrenewable_clocks_and_distinct_limits() {
    let admitted = Instant::now();
    assert_eq!(INTENT, Duration::from_secs(300));
    for (domain, work, hard, request, frames) in [
        (SavedCommandDomain::OfflinePreflight, 1800, 1810, 16384, 2),
        (SavedCommandDomain::AndroidBuild, 3000, 3010, 32768, 8),
    ] {
        let c = Clocks::new(domain, admitted);
        assert_eq!(c.work, admitted + Duration::from_secs(work));
        assert_eq!(c.finality, admitted + Duration::from_secs(hard));
        assert_eq!(c.settlement(None), c.finality);
        assert_eq!(c.settlement(Some(admitted + Duration::from_secs(2))), admitted + Duration::from_secs(12));
        assert_eq!(c.settlement(Some(c.finality)), c.finality);
        assert_eq!((domain.request_limit(), domain.response_limit(), domain.frame_limit()), (request, 65536, frames));
    }
}

#[test]
fn typed_consent_cannot_cross_domains_and_android_burns_before_any_custody() {
    let owner = application(SavedCommandDomain::AndroidBuild);
    let offline = wire::prepare(&json!({"projectId":"inert-offline","draftRevision":2,"baselineGeneration":3,
        "savedConfig":{"bytes":512,"sha256":"c".repeat(64)}})).unwrap();
    let revision = owner.inner.lock().revision;
    assert!(owner.prepare_offline(offline, 1, project(), wire::Availability::Available).is_err());
    assert_eq!(owner.inner.lock().revision, revision);
    assert!(owner.inner.lock().prepared.is_none() && owner.inner.lock().active.is_none());
    assert!(!owner.inner.qualified());
    let wrong_consent = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":wire::CONSENT});
    assert!(android_wire::start(&wrong_consent).is_err());
    // Unacquired comparison DATA alone cannot arm Android. Inserting an inert
    // intent tests one-use refusal; it does not install a qualification permit.
    owner.inner.lock().prepared = Some(Prepared { projection: projection(SavedCommandDomain::AndroidBuild),
        expires: Instant::now() + INTENT, registration: 1, project: project() });
    assert!(owner.start_offline(wire::start(&wrong_consent).unwrap(), Instant::now(), Some((1, project())), wire::Availability::Available).is_err());
    assert!(owner.inner.lock().prepared.is_some());
    let request = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":android_wire::CONSENT});
    let status = owner.start_android(android_wire::start(&request).unwrap(), Instant::now(), Some((1, project())),
        android_wire::Availability::Available).unwrap().release();
    let p = status.operation.unwrap();
    assert_eq!((p.phase, p.outcome), (android_wire::Phase::Terminal, Some(android_wire::Outcome::Refused)));
    assert!(p.result.is_none() && p.activity.is_none() && p.disposition.is_none() && p.stage.is_none());
    assert!(owner.inner.lock().prepared.is_none() && owner.inner.lock().active.is_none());
    assert!(owner.start_android(android_wire::start(&request).unwrap(), Instant::now(), Some((1, project())),
        android_wire::Availability::Available).is_err());
}

#[test]
fn unsupported_android_without_originals_never_claims_document_loss() {
    let owner = application(SavedCommandDomain::AndroidBuild);
    owner.document_lost();
    let status = owner.status_android(android_wire::Availability::UnsupportedPlatform).unwrap();
    assert_eq!(status.availability, android_wire::Availability::UnsupportedPlatform);
    assert!(status.operation.is_none() && owner.can_exit());
}

#[tokio::test]
async fn missing_android_tool_custody_refuses_before_inspection_or_acquisition() {
    let (application, owner) = active(SavedCommandDomain::AndroidBuild);
    // The typed Android branch has no custody acquisition implementation. Even
    // a directly exercised inert Session cannot turn its DTO into authority.
    start_original(&application.inner, &owner).await;
    let book = owner.resources.lock().await;
    assert!(book.inspection.is_none() && book.acquisition.is_none() && book.child.is_none());
    assert!(book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none());
    assert!(!owner.startup.lock().unwrap().attempted && owner.request.lock().await.is_none());
    let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
    assert_eq!((a.projection.reason, a.projection.outcome), (Reason::ToolchainUnavailable, Some(Outcome::Refused)));
    assert!(a.first_stop.is_some() && !a.terminal && !a.final_join_seen && r.last.is_none());
}

#[test]
fn foreign_domain_frames_fail_closed_without_converting_any_result() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (application, owner) = active(domain);
        let foreign = match domain { SavedCommandDomain::OfflinePreflight => Frame::AndroidBuild(android_wire::Frame::Accepted),
            SavedCommandDomain::AndroidBuild => Frame::OfflinePreflight(wire::Frame::Accepted) };
        application.inner.accept_at(&owner, foreign, owner.clocks.admitted);
        let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert!(a.unknown && r.disabled && !a.accepted && !a.terminal);
        assert_eq!(a.projection.reason, Reason::ProtocolError);
        assert_eq!(a.projection.public().reason, Reason::CleanupUnknown);
        assert!(a.projection.public().result.is_none() && a.projection.stage.is_none());
    }
}

#[test]
fn android_complete_with_policy_fail_is_provisional_and_late_data_never_undoes_f() {
    for due in [ANDROID_WORK, ANDROID_HARD] { for clock_first in [false, true] {
        let (application, owner) = active(SavedCommandDomain::AndroidBuild); let t = owner.clocks.admitted;
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Accepted), t);
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Progress(android_wire::Stage::Inspecting)), t);
        let now = t + due;
        if clock_first { application.inner.advance_locked(&mut application.inner.lock(), &owner, now); }
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Terminal(
            android_terminal(&android_wire::tests::complete_with_failed_inspection()))), now);
        application.inner.advance_locked(&mut application.inner.lock(), &owner, now);
        let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert_eq!((a.first_stop, a.projection.reason, a.projection.outcome), (Some(owner.clocks.work), Reason::TimedOut, Some(Outcome::TimedOut)));
        assert_eq!(a.unknown, due == ANDROID_HARD);
        assert!(a.projection.public().result.is_none() && r.last.is_none());
    } }
    let (application, owner) = active(SavedCommandDomain::AndroidBuild); let t = owner.clocks.admitted;
    application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Accepted), t);
    application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Terminal(
        android_terminal(&android_wire::tests::complete_with_failed_inspection()))), t);
    let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
    assert!(a.first_stop.is_none() && a.projection.result.is_some() && !a.final_join_seen);
    let p = a.projection.public().android().unwrap();
    assert_eq!(p.stage, Some(android_wire::Stage::DisposingWork));
    assert!(p.outcome.is_none() && p.result.is_none() && p.activity.is_none() && p.disposition.is_none());
    assert!(owner.watchdog_return.lock().unwrap().is_none() && r.last.is_none());
}

#[test]
fn known_retained_work_preserves_failed_outcome_and_original_stop_reason() {
    for (reason, core_stop) in [(Reason::Cancelled, "cancelled"), (Reason::TimedOut, "timed-out")] {
        let (application, owner) = active(SavedCommandDomain::AndroidBuild); let t = owner.clocks.admitted;
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Accepted), t);
        application.inner.stop_locked(&mut application.inner.lock(), &owner, reason, t);
        let mut data = android_wire::tests::negative_terminal(7);
        data["reason"] = json!(core_stop); data["lifetime"]["stopObserved"] = json!(core_stop);
        data["disposition"]["work"] = json!("retained-work");
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Terminal(android_terminal(&data))), t);
        let mut r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert_eq!((a.first_stop, a.projection.reason, a.projection.outcome), (Some(t), reason, Some(Outcome::Failed)));
        assert!(a.projection.public().result.is_none() && !a.final_join_seen);
        // Projection-only predicate, NOT a filled native join or published
        // terminal: the active owner's physical records remain entirely empty.
        let mut projection = a.projection.clone(); projection.phase = Phase::Terminal;
        let p = projection.public().android().unwrap();
        assert_eq!(p.outcome, Some(android_wire::Outcome::Failed));
        assert_eq!(p.reason, reason.android());
        assert_eq!(p.disposition.as_ref().unwrap().work, android_wire::WorkDisposition::RetainedWork);
        let status = android_wire::Status { schema_version: 1, status_revision: 1,
            availability: android_wire::Availability::RuntimeUnqualified, operation: Some(p) };
        assert!(android_wire::status_bytes(&status).is_ok());
        application.inner.advance_locked(&mut r, &owner, t + SETTLEMENT);
        let p = r.active.as_ref().unwrap().projection.public().android().unwrap();
        assert_eq!((p.phase, p.reason), (android_wire::Phase::Unknown, android_wire::Reason::CleanupUnknown));
        assert!(p.activity.is_none() && p.disposition.is_none() && p.result.is_none());
        assert!(owner.watchdog_return.lock().unwrap().is_none() && r.last.is_none());
    }
}

#[test]
fn stdout_decoder_cannot_reopen_a_finished_domain_stream() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (_application, owner) = active(domain);
        let mut decoder = OutputDecoder::new(&owner).unwrap();
        for bytes in complete_stream(domain, true) { assert!(decoder.push(&bytes, &owner).is_ok()); }
        assert!(decoder.finish());
        assert!(decoder.push(&accepted(domain), &owner).is_err());
        assert!(!decoder.finish());
    }
}

struct MemoryControl { read: AtomicUsize, closes: AtomicUsize, fail_close: bool }
struct MemoryReader { bytes: Vec<u8>, at: usize, control: Arc<MemoryControl> }
impl AsyncRead for MemoryReader {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut TaskContext<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let count = buffer.remaining().min(self.bytes.len() - self.at); let at = self.at;
        buffer.put_slice(&self.bytes[at..at + count]); self.at += count;
        self.control.read.fetch_add(count, Ordering::SeqCst); Poll::Ready(Ok(()))
    }
}
impl OriginalClose for MemoryReader {
    fn original_close(self) -> Result<(), ()> {
        self.control.closes.fetch_add(1, Ordering::SeqCst); if self.control.fail_close { Err(()) } else { Ok(()) }
    }
}
fn memory(bytes: Vec<u8>, fail_close: bool) -> (Arc<AsyncMutex<Pipe<MemoryReader>>>, Arc<MemoryControl>) {
    let control = Arc::new(MemoryControl { read: AtomicUsize::new(0), closes: AtomicUsize::new(0), fail_close });
    (Arc::new(AsyncMutex::new(Pipe { io: Some(MemoryReader { bytes, at: 0, control: control.clone() }), close: Close::New })), control)
}

#[tokio::test]
async fn seven_android_frames_backpressure_two_slots_without_creating_native_finality() {
    let (application, owner) = active(SavedCommandDomain::AndroidBuild);
    assert_eq!(owner.frames.capacity(), 2);
    owner.pipes.send_replace(Pipes::Available);
    let mut receiver = owner.resources.lock().await.frames.take().unwrap();
    let frames = complete_stream(SavedCommandDomain::AndroidBuild, true);
    assert_eq!(frames.len(), 7);
    let bytes: Vec<u8> = frames.into_iter().flatten().collect(); let count = bytes.len();
    let (output, control) = memory(bytes, false);
    let reading = read_output(application.inner.clone(), owner.clone(), output, false, Guard::new(&application.inner, &owner));
    let consuming = async {
        for _ in 0..7 { application.inner.accept(&owner, receiver.recv().await.unwrap()); }
    };
    let (end, ()) = tokio::join!(reading, consuming);
    assert!(end.eof && end.closed && end.decoder_settled && !end.failed); assert_eq!(end.frames, 7);
    assert_eq!(control.read.load(Ordering::SeqCst), count); assert_eq!(control.closes.load(Ordering::SeqCst), 1);
    assert_eq!(owner.output_bytes.load(Ordering::SeqCst), count);
    { let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert!(a.accepted && a.terminal && !a.unknown && a.first_stop.is_none() && r.last.is_none());
        assert!(a.projection.public().result.is_none() && owner.watchdog_return.lock().unwrap().is_none()); }
    // No actual native final JoinHandle exists in this memory vector. Ordinary
    // status MUST veto the core terminal instead of promoting those DATA facts.
    let p = application.status_android(android_wire::Availability::Available).unwrap().operation.unwrap();
    assert_eq!(p.phase, android_wire::Phase::Unknown);
    assert!(p.result.is_none() && p.activity.is_none() && p.disposition.is_none());
    assert!(application.inner.lock().active.is_some() && !application.can_exit());
}

#[tokio::test]
async fn both_domains_drain_rejected_bytes_charge_stderr_and_never_retry_a_close() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        for fail_close in [false, true] {
            let (application, owner) = active(domain); owner.pipes.send_replace(Pipes::Available);
            let (error, error_control) = memory(vec![b'e'; 33000], false);
            let err = read_output(application.inner.clone(), owner.clone(), error, true, Guard::new(&application.inner, &owner)).await;
            let (output, output_control) = memory(vec![b'x'; 33000], fail_close);
            let end = read_output(application.inner.clone(), owner.clone(), output.clone(), false, Guard::new(&application.inner, &owner)).await;
            assert!(err.failed && err.eof && err.closed && end.failed && end.eof && !end.decoder_settled);
            assert_eq!(end.closed, !fail_close);
            assert_eq!(owner.output_bytes.load(Ordering::SeqCst), 66000);
            assert_eq!(error_control.read.load(Ordering::SeqCst), 33000);
            assert_eq!(output_control.read.load(Ordering::SeqCst), 33000);
            assert_eq!(close_original(&mut *output.lock().await), !fail_close);
            assert_eq!(output_control.closes.load(Ordering::SeqCst), 1);
            assert_eq!(error_control.closes.load(Ordering::SeqCst), 1);
            let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
            assert!(r.disabled && a.unknown && a.projection.public().result.is_none());
        }
    }
}

#[tokio::test]
async fn accepted_only_eof_is_not_a_settled_decoder_in_either_domain() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (application, owner) = active(domain); owner.pipes.send_replace(Pipes::Available);
        let (output, control) = memory(accepted(domain), false);
        let end = read_output(application.inner.clone(), owner.clone(), output, false, Guard::new(&application.inner, &owner)).await;
        assert!(end.failed && end.eof && end.closed && !end.decoder_settled); assert_eq!(end.frames, 1);
        assert_eq!(control.closes.load(Ordering::SeqCst), 1);
        assert!(application.inner.lock().active.as_ref().unwrap().unknown);
    }
}
