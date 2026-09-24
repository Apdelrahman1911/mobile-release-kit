//! Ordinary tests below are inert state/clock tests, never native evidence.
//! The separately ignored hosted submodule has its own closed source-bound
//! scope. The inert identity below is never sent to that submodule's runtime.
use super::*;
use crate::offline_preflight_owner::{OfflinePreflightOwner, unavailable};
use std::path::PathBuf;
use serde_json::json;

fn owner() -> OfflinePreflightOwner { OfflinePreflightOwner::new(RuntimeConfig::packaged(PathBuf::from("/unopened-runtime"))) }
fn project() -> RegisteredRoot { RegisteredRoot { path: PathBuf::from("/unopened-preflight-project"),
    identity: crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) } }
fn projection() -> RunProjection { RunProjection { operation_id: "a".repeat(32), owner_generation: "b".repeat(32),
    context: Context::OfflinePreflight(wire::tests::context()), phase: Phase::AwaitingConsent, intent_usable: true,
    outcome: None, reason: Reason::None, result: None, stage: None } }
fn prepared(owner: &OfflinePreflightOwner, expires: Instant) {
    owner.original_for_test().inner.lock().prepared = Some(Prepared { projection: projection(), expires, registration: 1, project: project() });
}
fn start_input(id: &str) -> wire::Start { wire::start(&json!({"operationId":id,"ownerGeneration":"b".repeat(32),"consentVersion":wire::CONSENT})).unwrap() }
fn active() -> (OfflinePreflightOwner, Arc<Session>) {
    let owner = owner(); let p = projection();
    let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending); let (frames, receiver) = mpsc::channel(2);
    let clocks = Clocks::new(SavedCommandDomain::OfflinePreflight, Instant::now());
    let (native_audit_cutoff, _) = watch::channel(clocks.work);
    let session = Arc::new(Session { domain: SavedCommandDomain::OfflinePreflight, id: p.operation_id.clone(), generation: p.owner_generation.clone(), context: p.context.clone(),
        profile: Profile::OfflinePreflight(wire::Profile::LinuxX64), clocks, registration: 1, project: project(), request: AsyncMutex::new(None),
        stop, pipes, frames, wake: Notify::new(), native_audit_cutoff, output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false),
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
    let p = RunProjection { operation_id: p.operation_id, owner_generation: p.owner_generation, context: p.context,
        phase: Phase::Starting, intent_usable: false, outcome: None, reason: Reason::None, result: None, stage: None };
    owner.original_for_test().inner.lock().active = Some(Active { owner: session.clone(), projection: p, first_stop: None, work_expired: false,
        accepted: false, terminal: false, unknown: false, final_join_seen: false });
    (owner, session)
}

fn offline_context(owner: &Session) -> &wire::Context {
    match &owner.context { Context::OfflinePreflight(context) => context, Context::AndroidBuild(_) => panic!("offline test context") }
}

pub(crate) fn qualification_is_closed_without_a_runtime_or_another_owners_permit() {
    let owner = owner(); assert!(!owner.original_for_test().inner.qualified());
    let status = owner.status(wire::Availability::Available).unwrap();
    assert!(matches!(status.availability, wire::Availability::RuntimeUnqualified | wire::Availability::UnsupportedPlatform));
    assert!(status.operation.is_none()); assert!(owner.can_exit());
    let input = wire::prepare(&json!({"projectId":"inert-project","draftRevision":2,"baselineGeneration":3,
        "savedConfig":{"bytes":123,"sha256":"c".repeat(64)}})).unwrap();
    assert!(owner.prepare(input, 1, project(), wire::Availability::Available).is_err());
    assert!(owner.original_for_test().inner.lock().prepared.is_none()); assert!(owner.original_for_test().inner.lock().active.is_none());
}

pub(crate) fn no_owner_startup_and_unsupported_status_do_not_claim_document_loss() {
    let owner = owner();
    let initial = owner.status(wire::Availability::Busy).unwrap();
    assert!(initial.operation.is_none());
    assert_eq!(initial.availability, if wire::Profile::current().is_some() { wire::Availability::Busy } else { wire::Availability::UnsupportedPlatform });
    let bound = owner.status(wire::Availability::Available).unwrap();
    assert_eq!(bound.availability, if wire::Profile::current().is_some() { wire::Availability::RuntimeUnqualified } else { wire::Availability::UnsupportedPlatform });
    assert!(bound.operation.is_none());
    if initial.availability != bound.availability { assert!(bound.status_revision > initial.status_revision); }
    owner.document_lost();
    let lost = owner.status(wire::Availability::DocumentLost).unwrap();
    assert_eq!(lost.availability, if wire::Profile::current().is_some() { wire::Availability::DocumentLost } else { wire::Availability::UnsupportedPlatform });
    assert!(lost.operation.is_none());
    // Supplied unsupported capability DATA only, never a host or runtime permit.
    let unsupported = owner.status(wire::Availability::UnsupportedPlatform).unwrap();
    assert_eq!(unsupported.availability, wire::Availability::UnsupportedPlatform);
    assert!(unsupported.operation.is_none()); assert!(owner.can_exit());
    if lost.availability != unsupported.availability { assert!(unsupported.status_revision > lost.status_revision); }
}

pub(crate) fn intent_expires_with_a_new_revision_and_cancel_never_creates_an_owner() {
    let owner = owner(); prepared(&owner, Instant::now() + INTENT);
    let before = owner.status(wire::Availability::Available).unwrap();
    assert!(before.operation.as_ref().unwrap().intent_usable);
    let expiry = Instant::now(); owner.original_for_test().inner.lock().prepared.as_mut().unwrap().expires = expiry;
    owner.original_for_test().inner.expire_prepared(&mut owner.original_for_test().inner.lock(), expiry);
    let after = owner.status(wire::Availability::Available).unwrap();
    assert!(after.status_revision > before.status_revision);
    let operation = after.operation.unwrap(); assert!(!operation.intent_usable);
    assert_eq!((operation.phase, operation.outcome, operation.reason), (wire::Phase::Terminal, Some(wire::Outcome::Refused), wire::Reason::IntentExpired));
    assert!(owner.original_for_test().inner.lock().active.is_none());
    prepared(&owner, Instant::now() + INTENT);
    let status = owner.cancel(&"a".repeat(32), &"b".repeat(32), wire::Availability::Available).unwrap();
    assert_eq!(status.operation.unwrap().outcome, Some(wire::Outcome::Cancelled));
    assert!(owner.original_for_test().inner.lock().prepared.is_none()); assert!(owner.original_for_test().inner.lock().active.is_none());
}

pub(crate) fn start_burns_before_unavailability_and_foreign_start_grants_nothing() {
    let owner = owner(); prepared(&owner, Instant::now() + INTENT);
    assert!(owner.start(start_input(&"f".repeat(32)), Instant::now(), Some((1, project())), wire::Availability::Available).is_err());
    assert!(owner.original_for_test().inner.lock().prepared.is_some());
    let status = owner.start(start_input(&"a".repeat(32)), Instant::now(), Some((1, project())), wire::Availability::Available).unwrap().release();
    assert!(owner.original_for_test().inner.lock().prepared.is_none()); assert!(owner.original_for_test().inner.lock().active.is_none());
    assert_eq!(status.operation.unwrap().outcome, Some(wire::Outcome::Refused));
    assert!(owner.start(start_input(&"a".repeat(32)), Instant::now(), Some((1, project())), wire::Availability::Available).is_err());
}

pub(crate) fn whole_run_endpoints_and_first_stop_never_renew() {
    let (owner, session) = active(); let t = session.clocks.admitted;
    assert_eq!(session.clocks.work, t + OFFLINE_WORK); assert_eq!(session.clocks.finality, t + OFFLINE_HARD);
    let first = t + Duration::from_secs(5);
    let mut r = owner.original_for_test().inner.lock();
    owner.original_for_test().inner.stop_locked(&mut r, &session, Reason::Cancelled, first);
    owner.original_for_test().inner.stop_locked(&mut r, &session, Reason::ProtocolError, first + Duration::from_secs(9));
    let a = r.active.as_ref().unwrap(); assert_eq!(a.first_stop, Some(first));
    assert_eq!(session.clocks.settlement(a.first_stop), first + SETTLEMENT);
    owner.original_for_test().inner.advance_locked(&mut r, &session, first + SETTLEMENT);
    let a = r.active.as_ref().unwrap(); assert!(a.unknown && r.disabled); assert_eq!(a.first_stop, Some(first));
    let p = a.projection.public(); assert_eq!((p.phase, p.outcome, p.reason), (Phase::Unknown, Some(Outcome::Unknown), Reason::CleanupUnknown));
    assert!(p.result.is_none());
}

pub(crate) fn complete_negative_is_provisional_and_not_first_failure() {
    let (owner, session) = active(); let t = session.clocks.admitted;
    owner.original_for_test().inner.accept_at(&session, Frame::OfflinePreflight(wire::Frame::Accepted), t);
    owner.original_for_test().inner.accept_at(&session, Frame::OfflinePreflight(wire::tests::terminal_frame(offline_context(&session))), t + Duration::from_secs(1));
    let mut r = owner.original_for_test().inner.lock();
    let a = r.active.as_ref().unwrap(); assert!(a.first_stop.is_none() && a.projection.result.is_some());
    let p = a.projection.public(); assert_eq!(p.phase, Phase::Stopping); assert!(p.outcome.is_none() && p.result.is_none());
    // An unjoined native result cannot win over a later original Cancel.
    owner.original_for_test().inner.stop_locked(&mut r, &session, Reason::Cancelled, t + Duration::from_secs(2));
    assert_eq!(r.active.as_ref().unwrap().projection.outcome, Some(Outcome::Cancelled));
}

pub(crate) fn late_terminal_never_reverses_timeout_or_unknown_in_either_delivery_order() {
    for due in [OFFLINE_WORK, OFFLINE_HARD] { for clock_first in [false, true] {
        let (owner, session) = active(); let now = session.clocks.admitted + due;
        owner.original_for_test().inner.accept_at(&session, Frame::OfflinePreflight(wire::Frame::Accepted), session.clocks.admitted);
        if clock_first { owner.original_for_test().inner.advance_locked(&mut owner.original_for_test().inner.lock(), &session, now); }
        owner.original_for_test().inner.accept_at(&session, Frame::OfflinePreflight(wire::tests::terminal_frame(offline_context(&session))), now);
        owner.original_for_test().inner.advance_locked(&mut owner.original_for_test().inner.lock(), &session, now);
        let r = owner.original_for_test().inner.lock(); let a = r.active.as_ref().unwrap();
        assert_eq!(a.projection.reason, Reason::TimedOut); assert_eq!(a.projection.outcome, Some(Outcome::TimedOut));
        assert_eq!(a.unknown, due == OFFLINE_HARD); assert!(a.projection.public().result.is_none()); assert!(r.last.is_none());
    } }
}

pub(crate) fn repeated_unknown_polling_does_not_publish_new_results_or_extend_clocks() {
    let (owner, session) = active();
    owner.original_for_test().inner.advance_locked(&mut owner.original_for_test().inner.lock(), &session, session.clocks.finality);
    let before = { let r = owner.original_for_test().inner.lock(); (r.revision, r.active.as_ref().unwrap().first_stop) };
    for _ in 0..8 {
        assert!(owner.original_for_test().inner.endpoint(&session).is_none());
        let r = owner.original_for_test().inner.lock(); let a = r.active.as_ref().unwrap();
        assert_eq!((r.revision, a.first_stop), before); assert!(a.unknown && r.disabled && r.last.is_none());
    }
}

// This entire, separately ignored owner-local fixture is absent from ordinary
// release/shell/unsupported builds. Shared helpers below carry DATA and IO, not
// another owner's qualification or a substitute launcher.
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
pub(crate) mod hosted {
    use super::*;
    use wire::{Context, Terminal, Phase, Outcome, Reason, Profile};
    use super::super::{Context as SavedContext, Terminal as SavedTerminal};
    use crate::{asset_session::DocumentBinding, bridge::DesktopBridge,
        environment_diagnostics_owner::hosted_tests::{BoundInputs, Check, anchored, bound_file, close_file,
            create_directory, create_private, end_check, hash, original_json, require}};
    use serde_json::{json, Value};
    use std::{fs::{self, File, Metadata, OpenOptions}, io::Write,
        os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt}, path::Path, sync::Weak};

    const SCOPE: &str = "offline-preflight-native-v1";
    const ORDER: [&str; 12] = ["PG01", "PV01", "PV02", "PF01", "PF02", "PF03", "PF04a", "PF04b", "PF05a", "PF05b", "PF06", "PF07"];
    const ROSTER: Duration = Duration::from_secs(180);
    const READY: Duration = Duration::from_secs(15);
    const SCRIPT: &str = r#"import os
import sys
import time

# Fixed configured project DATA, not an alternate bootstrap or process owner.
mode = sys.argv[1]
if mode not in ('pass', 'nonzero', 'active', 'later'):
    raise SystemExit(91)
path = 'later.trace' if mode == 'later' else 'script.trace'
fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    marker = {'pass': b'pass\n', 'nonzero': b'exit-7\n', 'active': b'active\n', 'later': b'forbidden-later\n'}[mode]
    if os.write(fd, marker) != len(marker):
        raise SystemExit(92)
finally:
    os.close(fd)
print('OFFLINE_FIXTURE_PRIVATE_OUTPUT ' + os.getcwd(), flush=True)
print('OFFLINE_FIXTURE_PRIVATE_ERROR ' + os.getcwd(), file=sys.stderr, flush=True)
if mode == 'active':
    while True:
        time.sleep(0.05)
raise SystemExit(7 if mode == 'nonzero' else 0)
"#;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Case { PG01, PF01, PF02, PF03, PF04a, PF04b, PF05a, PF05b, PF06, PF07 }
    impl Case {
        fn id(self) -> &'static str { match self { Self::PG01 => "PG01", Self::PF01 => "PF01", Self::PF02 => "PF02", Self::PF03 => "PF03",
            Self::PF04a => "PF04a", Self::PF04b => "PF04b", Self::PF05a => "PF05a", Self::PF05b => "PF05b", Self::PF06 => "PF06", Self::PF07 => "PF07" } }
        fn config_id(self) -> &'static str { if self == Self::PG01 { "PF01" } else { self.id() } }
    }
    struct Gate { entered: watch::Sender<bool>, released: watch::Sender<bool>, at: Mutex<Option<Instant>> }
    impl Gate {
        fn new() -> Self { let (entered, _) = watch::channel(false); let (released, _) = watch::channel(false);
            Self { entered, released, at: Mutex::new(None) } }
        async fn hold(&self) {
            if let Ok(mut at) = self.at.lock() { if at.is_none() { *at = Some(Instant::now()); } }
            self.entered.send_replace(true); let mut released = self.released.subscribe();
            while !*released.borrow_and_update() { if released.changed().await.is_err() { pending::<()>().await; } }
        }
        fn release(&self) { self.released.send_replace(true); }
    }
    pub(crate) struct RegistrationPermit { owner: Weak<Inner>, id: String, root: RegisteredRoot, generation: u32, case: Case }
    impl RegistrationPermit {
        pub(crate) fn validate(&self, owner: &OfflinePreflightOwner) -> Result<(&str, &RegisteredRoot, u32), BridgeError> {
            if owner.original_for_test().inner.domain == SavedCommandDomain::OfflinePreflight
                && self.owner.upgrade().is_some_and(|inner| inner.domain == SavedCommandDomain::OfflinePreflight
                    && Arc::ptr_eq(&inner, &owner.original_for_test().inner)) {
                Ok((&self.id, &self.root, self.generation))
            } else { Err(unavailable()) }
        }
        pub(crate) fn gate_evidence(&self) -> bool { self.case == Case::PG01
            && self.owner.upgrade().is_some_and(|inner| inner.domain == SavedCommandDomain::OfflinePreflight && inner.lock().active.is_none()) }
    }
    struct ObserverData { settled: bool, terminal: Option<Terminal>, first_stop: Option<Instant> }
    pub(in crate::saved_command_owner) struct Permit {
        inputs: Arc<BoundInputs>, owner: Weak<Inner>, session: Mutex<Option<Weak<Session>>>,
        admitted: Mutex<Option<Arc<Session>>>, claimed: AtomicBool, case: Case,
        registration: RegistrationPermit, context: Context, end: Instant, gate: Gate,
        observed: Mutex<Option<ObserverData>>, files: Mutex<CaseFiles>,
    }
    impl Permit {
        pub(in crate::saved_command_owner) fn permits(&self, inner: &Inner) -> bool {
            inner.domain == SavedCommandDomain::OfflinePreflight && self.inputs.data.scope == SCOPE
                && self.owner.upgrade().is_some_and(|owner| owner.domain == SavedCommandDomain::OfflinePreflight && std::ptr::eq(owner.as_ref(), inner))
                && wire::Profile::current().is_some_and(|p| matches!(p, Profile::LinuxX64 | Profile::MacosArm64))
        }
        pub(in crate::saved_command_owner) fn bind(&self, owner: &Arc<Session>) -> Result<(), BridgeError> {
            if owner.domain != SavedCommandDomain::OfflinePreflight
                || !matches!(&owner.context, SavedContext::OfflinePreflight(context) if context == &self.context)
                || !matches!(owner.profile, super::super::Profile::OfflinePreflight(_))
                || self.case == Case::PG01 || owner.project != self.registration.root
                || owner.registration != self.registration.generation || Instant::now() >= self.end
                || self.claimed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() { return Err(unavailable()); }
            let mut session = self.session.lock().map_err(|_| unavailable())?;
            let mut admitted = self.admitted.lock().map_err(|_| unavailable())?;
            if session.is_some() || admitted.is_some() { return Err(unavailable()); }
            *session = Some(Arc::downgrade(owner));
            // Retain even an exceptionally fast original until the caller can
            // recover it after discarding Start's DATA response.
            *admitted = Some(owner.clone()); Ok(())
        }
        fn original(&self, owner: &Session) -> bool {
            owner.domain == SavedCommandDomain::OfflinePreflight
                && self.session.lock().ok().and_then(|slot| slot.as_ref().and_then(Weak::upgrade))
                    .is_some_and(|session| session.domain == SavedCommandDomain::OfflinePreflight && std::ptr::eq(session.as_ref(), owner))
        }
        pub(in crate::saved_command_owner) fn prepare_spawn(&self, owner: &Session, runtime: &VerifiedRuntime) -> Check<()> {
            require(self.original(owner) && self.claimed.load(Ordering::SeqCst), "fixture_offline_original")?;
            self.inputs.recheck(self.end)?;
            let d = &self.inputs.data;
            require(runtime.python == d.python && runtime.core == d.source.join("src") && runtime.cwd == d.cwd
                && runtime.bootstrap == d.cwd.join("offline_preflight_bootstrap.py")
                && matches!(&owner.context, SavedContext::OfflinePreflight(context) if context == &self.context)
                && owner.project == self.registration.root
                && owner.registration == self.registration.generation, "fixture_offline_fixed_tuple")?;
            self.files.lock().map_err(|_| "fixture_file_record")?.before_start()?;
            end_check(self.end)
        }
        pub(in crate::saved_command_owner) async fn observer_return(&self, owner: &Session, settled: bool) {
            if !self.original(owner) { return; }
            if let Some(inner) = self.owner.upgrade().filter(|inner| inner.domain == SavedCommandDomain::OfflinePreflight) {
                let r = inner.lock();
                if let Some(active) = r.active.as_ref().filter(|a| std::ptr::eq(a.owner.as_ref(), owner)) {
                    if let Ok(mut slot) = self.observed.lock() {
                        if slot.is_none() { *slot = Some(ObserverData { settled, terminal: match &active.projection.result {
                            Some(SavedTerminal::OfflinePreflight(terminal)) => Some(terminal.clone()), _ => None,
                        }, first_stop: active.first_stop }); }
                    }
                }
            }
            // The hook is AFTER the actual manager/child/IO/core predicates.
            // It can hold this original return; it cannot manufacture a receipt.
            // PF06 also retains this final join through its synchronous
            // repeated-Cancel/writer-gate assertions, avoiding a fast-join race.
            // It releases immediately; only PF07 observes a timed hold.
            if matches!(self.case, Case::PF06 | Case::PF07) { self.gate.hold().await; }
            if let Some(inner) = self.owner.upgrade().filter(|inner| inner.domain == SavedCommandDomain::OfflinePreflight) {
                let r = inner.lock();
                if let Some(active) = r.active.as_ref().filter(|a| std::ptr::eq(a.owner.as_ref(), owner)) {
                    if let Ok(mut slot) = self.observed.lock() { if let Some(data) = slot.as_mut() { data.first_stop = active.first_stop; } }
                }
            }
        }
    }

    struct Marker { file: Option<File>, identity: Metadata, path: PathBuf, closed: bool }
    impl Marker {
        fn create(path: PathBuf, bytes: &[u8]) -> Check<Self> {
            write_new(&path, bytes)?;
            let (file, identity) = bound_file(&path, bytes.len() as u64)?;
            Ok(Self { file: Some(file), identity, path, closed: false })
        }
        fn before_start(&self) -> Check<()> {
            let original = self.file.as_ref().ok_or("fixture_marker_missing")?.metadata().map_err(|_| "fixture_marker_metadata")?;
            let named = fs::symlink_metadata(&self.path).map_err(|_| "fixture_marker_named")?;
            require(same_object(&original, &named) && same_object(&original, &self.identity), "fixture_marker_changed")
        }
        fn bytes(&self) -> Check<Vec<u8>> {
            // Original preowned reader only. In particular PF07's tail never
            // reopens the path or probes a source/runtime/tool after the hold.
            let file = self.file.as_ref().ok_or("fixture_marker_missing")?;
            let before = file.metadata().map_err(|_| "fixture_marker_metadata")?;
            require(same_object(&before, &self.identity) && before.is_file() && before.nlink() == 1 && before.len() <= 128,
                "fixture_marker_identity")?;
            let mut bytes = [0u8; 129]; let n = file.read_at(&mut bytes, 0).map_err(|_| "fixture_marker_read")?;
            require(n <= 128 && n as u64 == before.len() && file.metadata().map_err(|_| "fixture_marker_metadata")?.len() == before.len(),
                "fixture_marker_bound")?; Ok(bytes[..n].to_vec())
        }
        fn close(&mut self) -> Check<()> {
            if let Some(file) = self.file.take() { self.closed = close_file(file).is_ok(); }
            require(self.closed, "fixture_marker_close")
        }
    }
    fn same_object(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev() && a.ino() == b.ino() && a.uid() == b.uid() && a.gid() == b.gid() && a.mode() == b.mode()
    }
    fn write_new(path: &Path, bytes: &[u8]) -> Check<()> {
        let mut file = create_private(path)?;
        let written = file.write_all(bytes).map_err(|_| "fixture_data_write"); let closed = close_file(file);
        written?; closed
    }
    fn held_directory(path: &Path) -> Check<File> {
        anchored(path)?;
        OpenOptions::new().read(true).custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path).map_err(|_| "fixture_directory_original")
    }
    struct CaseFiles {
        root: Option<File>, case_root: Option<File>, project: PathBuf, script: Marker, later: Marker, pending: Option<Marker>,
        roots_closed: bool, setup_closed: bool,
    }
    impl CaseFiles {
        fn prepare(inputs: &BoundInputs, case: Case, end: Instant) -> Check<(Self, RegisteredRoot)> {
            end_check(end)?;
            let root_path = inputs.data.root.join("environment-native").join(case.id()); create_directory(&root_path)?;
            let case_root = held_directory(&root_path)?;
            let project = root_path.join("project"); create_directory(&project)?;
            let root = held_directory(&project)?;
            for relative in [".git", "app", "release", "release/store", "release/store/android", "release/store/android/en-US", "release/store/android/en-US/changelogs"] {
                create_directory(&project.join(relative))?;
            }
            for (relative, bytes) in [
                (".gitignore", b"/.mobile-release/\n".as_slice()),
                ("release/version.properties", b"VERSION_NAME=1.2.3\nBUILD_NUMBER=42\n".as_slice()),
                ("app/build.gradle.kts", b"plugins { id(\"com.android.application\") }\nandroid { namespace = \"com.example.reader\"; defaultConfig { applicationId = \"com.example.reader\" }; buildTypes { debug { applicationIdSuffix = \".debug\" } } }\n".as_slice()),
                ("gradlew", b"#!/bin/sh\nexit 93\n".as_slice()),
                ("release/store/android/en-US/title.txt", b"Reader\n".as_slice()),
                ("release/store/android/en-US/short_description.txt", b"Read safely on every device.\n".as_slice()),
                ("release/store/android/en-US/full_description.txt", b"A real application description.\n".as_slice()),
                ("release/store/android/en-US/changelogs/default.txt", b"Reliability improvements.\n".as_slice()),
                ("check.py", SCRIPT.as_bytes()),
            ] { write_new(&project.join(relative), bytes)?; }
            let config = inputs.data.saved_configs.as_ref().ok_or("fixture_saved_configs_missing")?.iter()
                .find(|row| row.case == case.config_id()).ok_or("fixture_saved_config_case")?;
            require(config.size == config.raw_text.len() && hash(config.raw_text.as_bytes()) == config.sha256, "fixture_saved_config_bytes")?;
            // These are exactly the raw bytes parsed by the predecessor CLI11
            // policy prelude, not a native serde parse/reserialize approximation.
            write_new(&project.join("release/mobile-release.json"), config.raw_text.as_bytes())?;
            let script = Marker::create(project.join("script.trace"), b"")?;
            let later = Marker::create(project.join("later.trace"), b"")?;
            let pending = if case == Case::PF04b { Some(Marker::create(project.join(".mobile-release-init"), b"inert-pending-init\n")?) } else { None };
            if case == Case::PF05a {
                let mut path = project.clone(); for _ in 0..34 { path.push("depth"); create_directory(&path)?; }
            }
            if case == Case::PF05b {
                let path = project.join("release/version.properties");
                let mut file = OpenOptions::new().write(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC).open(&path)
                    .map_err(|_| "fixture_version_original")?;
                let text = format!("VERSION_NAME={}\nBUILD_NUMBER=42\n", "v".repeat(16 * 1024 + 1));
                let written = file.write_all(text.as_bytes()).and_then(|_| file.set_len(text.len() as u64)).map_err(|_| "fixture_version_write");
                let closed = close_file(file); written?; closed?;
            }
            let registration = crate::asset_source::offline_fixture_root(&root, &project).map_err(|_| "fixture_real_root_identity")?;
            end_check(end)?;
            Ok((Self { root: Some(root), case_root: Some(case_root), project, script, later, pending, roots_closed: false, setup_closed: true }, registration))
        }
        fn before_start(&self) -> Check<()> {
            let root = self.root.as_ref().ok_or("fixture_root_missing")?;
            crate::asset_source::offline_fixture_root(root, &self.project).map_err(|_| "fixture_root_changed")?;
            self.script.before_start()?; self.later.before_start()?;
            if let Some(pending) = &self.pending { pending.before_start()?; } Ok(())
        }
        fn drift(&self) -> Check<()> {
            let mut file = OpenOptions::new().append(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(self.project.join("release/mobile-release.json")).map_err(|_| "fixture_drift_original")?;
            let written = file.write_all(b"\n").map_err(|_| "fixture_drift_write"); let closed = close_file(file); written?; closed
        }
        fn close(&mut self) -> Check<Value> {
            let mut okay = self.script.close().is_ok() & self.later.close().is_ok();
            if let Some(pending) = self.pending.as_mut() { okay &= pending.close().is_ok(); }
            let mut roots = true;
            if let Some(root) = self.root.take() { roots &= close_file(root).is_ok(); } else { roots &= self.roots_closed; }
            if let Some(root) = self.case_root.take() { roots &= close_file(root).is_ok(); } else { roots &= self.roots_closed; }
            self.roots_closed = roots;
            require(okay && roots && self.setup_closed, "fixture_owned_files_finality")?;
            Ok(json!({"setupClosed":self.setup_closed,"scriptClosed":self.script.closed,"laterClosed":self.later.closed,
                "pendingClosed":self.pending.as_ref().map(|p| p.closed),"rootsClosed":self.roots_closed}))
        }
    }

    struct Run { bridge: Arc<DesktopBridge>, document: DocumentBinding, permit: Arc<Permit>, session: Option<Arc<Session>>, intent: Option<wire::Projection> }
    impl Run {
        fn prepare(inputs: Arc<BoundInputs>, case: Case, end: Instant) -> Check<Self> {
            inputs.recheck(end)?;
            let (files, project) = CaseFiles::prepare(&inputs, case, end)?;
            let saved = inputs.data.saved_configs.as_ref().ok_or("fixture_saved_configs_missing")?.iter()
                .find(|row| row.case == case.config_id()).ok_or("fixture_saved_config_case")?;
            let bridge = Arc::new(DesktopBridge::new(inputs.data.root.join("unused-packaged-runtime")));
            let id = format!("offline-native-{}", case.id());
            let context = Context { project_id: id.clone(), draft_revision: 0, baseline_generation: 2,
                saved_config: wire::Content { bytes: saved.size as u32, sha256: saved.sha256.clone() },
                platform: wire::Platform::Android, operation: wire::Operation::OfflinePreflight };
            let permit = Arc::new(Permit { inputs, owner: Arc::downgrade(&bridge.preflight.original_for_test().inner), session: Mutex::new(None),
                admitted: Mutex::new(None), claimed: AtomicBool::new(false), case,
                registration: RegistrationPermit { owner: Arc::downgrade(&bridge.preflight.original_for_test().inner), id, root: project, generation: 2, case },
                context, end, gate: Gate::new(), observed: Mutex::new(None), files: Mutex::new(files) });
            *bridge.preflight.original_for_test().inner.fixture.lock().map_err(|_| "fixture_offline_permit_slot")? = Some(Arc::downgrade(&permit));
            // The same original permit is deliberately presented to Android's
            // otherwise empty registry. It must grant no qualification, intent
            // or resource, and must not consume the Offline one-use claim.
            let android = crate::android_build_owner::AndroidBuildOwner::new(RuntimeConfig::packaged(PathBuf::from("/unopened-android-runtime")), None);
            let android_inner = &android.original_for_test().inner;
            *android_inner.fixture.lock().map_err(|_| "fixture_android_permit_slot")? = Some(Arc::downgrade(&permit));
            require(!permit.permits(android_inner) && !android_inner.qualified()
                && !permit.claimed.load(Ordering::SeqCst)
                && permit.admitted.lock().map_err(|_| "fixture_admission_slot")?.is_none()
                && android_inner.lock().prepared.is_none() && android_inner.lock().active.is_none(), "fixture_offline_permit_is_not_android")?;

            let document = DocumentBinding::new(bridge.clone());
            require(document.navigation(true), "fixture_document_navigation")?;
            document.observe(|life| life.started(true)); document.hook_installed(); document.observe(|life| life.finished(true));
            document.offline_fixture_registration(&permit.registration).map_err(|_| "fixture_offline_registration")?;
            Ok(Self { bridge, document, permit, session: None, intent: None })
        }
        fn prepare_input(&self) -> wire::Prepare { let c = &self.permit.context;
            wire::Prepare { project_id: c.project_id.clone(), draft_revision: c.draft_revision, baseline_generation: c.baseline_generation, saved_config: c.saved_config.clone() } }
        fn consent(&mut self) -> Check<()> {
            end_check(self.permit.end)?;
            let status = self.document.prepare_offline_preflight(self.prepare_input()).map_err(|_| "fixture_prepare_refused")?;
            self.intent = status.operation;
            require(self.intent.as_ref().is_some_and(|p| p.intent_usable && p.context == self.permit.context && p.phase == Phase::AwaitingConsent), "fixture_original_intent")
        }
        fn start_input(&self) -> Check<wire::Start> { let p = self.intent.as_ref().ok_or("fixture_intent_missing")?;
            wire::start(&json!({"operationId":p.operation_id,"ownerGeneration":p.owner_generation,"consentVersion":wire::CONSENT})).map_err(|_| "fixture_start_input") }
        fn recover(&mut self) { if let Ok(mut slot) = self.permit.admitted.lock() { if let Some(owner) = slot.take() { self.session = Some(owner); } } }
        fn start(&mut self) -> Check<()> {
            end_check(self.permit.end)?;
            let result = self.document.start_offline_preflight(self.start_input()?); self.recover();
            // Discard the real Start reply before observing the same registry.
            drop(result.map_err(|_| "fixture_original_start")?);
            require(self.session.is_some(), "fixture_original_session")
        }
        fn original(&self) -> Check<&Arc<Session>> { self.session.as_ref().ok_or("fixture_original_missing") }
        fn cancel(&self) -> Check<()> { let s = self.original()?;
            self.document.cancel_offline_preflight(wire::Cancel { operation_id: s.id.clone(), owner_generation: s.generation.clone() })
                .map_err(|_| "fixture_matching_cancel")?; Ok(()) }
        fn stop(&self) -> Check<Option<Instant>> {
            let s = self.original()?; let r = self.bridge.preflight.original_for_test().inner.lock();
            Ok(r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, s)).and_then(|a| a.first_stop))
        }
        async fn entered(&self) -> Check<()> {
            let end = self.permit.end.min(Instant::now() + READY); let mut entered = self.permit.gate.entered.subscribe();
            loop { if *entered.borrow_and_update() { return Ok(()); }
                tokio::time::timeout_at(tokio::time::Instant::from_std(end), entered.changed()).await
                    .map_err(|_| "fixture_hold_not_entered")?.map_err(|_| "fixture_hold_watch_lost")?; }
        }
        async fn readiness(&self) -> Check<()> {
            let end = self.permit.end.min(Instant::now() + READY);
            loop { let ready = self.permit.files.lock().map_err(|_| "fixture_file_record")?.script.bytes()?;
                if ready == b"active\n" { require(self.stop()?.is_none(), "fixture_late_script_readiness")?; return Ok(()); }
                require(ready.is_empty(), "fixture_wrong_script_readiness")?; end_check(end)?;
                tokio::time::sleep(Duration::from_millis(5)).await; }
        }
        async fn settle(&self) -> Check<wire::Projection> {
            let s = self.original()?; let mut changes = self.bridge.preflight.subscribe();
            loop {
                let status = self.document.offline_preflight_status().map_err(|_| "fixture_status_lost")?;
                let settled = { let r = self.bridge.preflight.original_for_test().inner.lock();
                    if self.permit.case == Case::PF07 { r.disabled && r.active.as_ref().is_some_and(|a|
                        Arc::ptr_eq(&a.owner, s) && a.unknown && a.final_join_seen) } else { r.active.is_none() } };
                if settled { if let Some(p) = status.operation { if p.operation_id == s.id && p.owner_generation == s.generation {
                    if self.permit.case == Case::PF07 {
                        // Visible Unknown alone is not an actual final Ready observation.
                        require(p.phase == Phase::Unknown
                            && join_kind(&s.observer_return, |value| if *value { "ok-true" } else { "ok-false" })? == "ok-true"
                            && join_kind(&s.watchdog_return, |value| if *value { "ok-true" } else { "ok-false" })? == "ok-false"
                            && s.observer.try_lock().map_err(|_| "fixture_observer_busy")?.is_some()
                            && s.watchdog.lock().map_err(|_| "fixture_watchdog_busy")?.is_some()
                            && s.watchdog_joined.load(Ordering::SeqCst) && !s.watchdog_failed.load(Ordering::SeqCst),
                            "fixture_unknown_original_ready")?;
                    }
                    return Ok(p);
                } } }
                tokio::time::timeout_at(tokio::time::Instant::from_std(self.permit.end), changes.changed()).await
                    .map_err(|_| "fixture_originals_not_settled")?.map_err(|_| "fixture_original_watch_lost")?;
            }
        }
        fn terminal(&self) -> Check<Terminal> {
            let slot = self.permit.observed.lock().map_err(|_| "fixture_observer_record")?;
            let data = slot.as_ref().ok_or("fixture_observer_not_returned")?;
            require(data.settled, "fixture_observer_unsettled")?;
            data.terminal.clone().ok_or("fixture_terminal_missing")
        }
        fn close_files(&self) -> Check<Value> { self.permit.files.lock().map_err(|_| "fixture_file_record")?.close() }
    }

    fn close_state(value: Close) -> &'static str { match value { Close::New => "new", Close::Attempted => "attempted", Close::Settled => "settled", Close::Unknown => "unknown" } }
    fn join_kind<T>(record: &Mutex<Option<Result<T, tokio::task::JoinError>>>, okay: impl Fn(&T) -> &'static str) -> Check<&'static str> {
        Ok(match record.lock().map_err(|_| "fixture_join_record")?.as_ref() {
            Some(Ok(value)) => okay(value), Some(Err(error)) if error.is_panic() => "panic",
            Some(Err(error)) if error.is_cancelled() => "cancelled", _ => "not-joined",
        })
    }
    fn receipt(run: &Run) -> Check<Value> {
        let owner = run.original()?; let finality_unknown = run.permit.case == Case::PF07;
        // Called only after reconcile observed actual final Ready. try_lock
        // refuses a missing physical predicate instead of introducing a new wait.
        let book = owner.resources.try_lock().map_err(|_| "fixture_book_busy")?;
        let startup = owner.startup.lock().map_err(|_| "fixture_startup_record")?;
        let input = owner.input.try_lock().map_err(|_| "fixture_input_busy")?;
        let output = owner.output.try_lock().map_err(|_| "fixture_output_busy")?;
        let error = owner.error.try_lock().map_err(|_| "fixture_error_busy")?;
        let driver = join_kind(&owner.driver_return, |_| "ok-unit")?;
        let manager = join_kind(&owner.manager_return, |_| "ok-unit")?;
        let observer = join_kind(&owner.observer_return, |value| if *value { "ok-true" } else { "ok-false" })?;
        let watchdog = join_kind(&owner.watchdog_return, |value| if *value { "ok-true" } else { "ok-false" })?;
        let driver_retained = owner.driver.try_lock().map_err(|_| "fixture_driver_busy")?.is_some();
        let manager_retained = owner.manager.try_lock().map_err(|_| "fixture_manager_busy")?.is_some();
        let observer_retained = owner.observer.try_lock().map_err(|_| "fixture_observer_busy")?.is_some();
        let watchdog_retained = owner.watchdog.lock().map_err(|_| "fixture_watchdog_busy")?.is_some();
        require(driver == "ok-unit" && manager == "ok-unit" && observer == "ok-true"
            && watchdog == (if finality_unknown { "ok-false" } else { "ok-true" })
            && !driver_retained && !manager_retained && observer_retained == finality_unknown
            && watchdog_retained == finality_unknown, "fixture_original_task_finality")?;
        require(startup.attempted && startup.returned && !startup.failed && startup.child.is_none()
            && book.inspection.is_none() && book.inspection_joined && !book.inspection_failed
            && book.acquisition.is_none() && book.acquisition_joined && !book.acquisition_failed
            && book.child.is_some() && book.waited.is_some_and(|s| s.success()) && !book.wait_failed
            && book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
            && !book.write_failed && !book.out_failed && !book.err_failed
            && book.write_end.as_ref().is_some_and(|r| r.sent && r.closed && !r.failed)
            && book.out_end.as_ref().is_some_and(|r| r.frames == 2 && r.decoder_settled && r.eof && r.closed && !r.failed)
            && book.err_end.as_ref().is_some_and(|r| r.frames == 0 && r.eof && r.closed && !r.failed)
            && input.close == Close::Settled && output.close == Close::Settled && error.close == Close::Settled
            && input.io.is_none() && output.io.is_none() && error.io.is_none()
            && owner.driver_joined.load(Ordering::SeqCst) && owner.watchdog_joined.load(Ordering::SeqCst)
            && !owner.driver_failed.load(Ordering::SeqCst) && !owner.manager_failed.load(Ordering::SeqCst)
            && !owner.watchdog_failed.load(Ordering::SeqCst)
            && owner.resource_unknown.load(Ordering::SeqCst) == finality_unknown, "fixture_original_physical_finality")?;
        let active_retained = run.bridge.preflight.original_for_test().inner.lock().active.is_some();
        let disabled = run.bridge.preflight.disabled(); let can_exit = run.bridge.preflight.can_exit();
        require(active_retained == finality_unknown && disabled == finality_unknown && can_exit == !finality_unknown,
            "fixture_original_exit_gate")?;
        let terminal = run.terminal()?; require(terminal.lifetime.settled(), "fixture_core_original_finality")?;
        Ok(json!({"startup":{"attempted":startup.attempted,"returned":startup.returned,"failed":startup.failed},
            "inspection":{"joined":book.inspection_joined,"failed":book.inspection_failed,"retained":book.inspection.is_some()},
            "acquisition":{"joined":book.acquisition_joined,"failed":book.acquisition_failed,"retained":book.acquisition.is_some()},
            "child":{"present":book.child.is_some(),"waited":book.waited.is_some(),"code":book.waited.and_then(|s| s.code()),"waitFailed":book.wait_failed},
            "input":{"close":close_state(input.close),"retained":input.io.is_some()},
            "output":{"close":close_state(output.close),"retained":output.io.is_some()},
            "error":{"close":close_state(error.close),"retained":error.io.is_some()},
            "writer":{"joined":book.writer.is_none() && book.write_end.is_some(),"failed":book.write_failed,
                "end":book.write_end.as_ref().map(|r| json!({"sent":r.sent,"closed":r.closed,"failed":r.failed}))},
            "stdout":{"joined":book.stdout.is_none() && book.out_end.is_some(),"failed":book.out_failed,
                "end":book.out_end.as_ref().map(|r| json!({"frames":r.frames,"eof":r.eof,"closed":r.closed,"failed":r.failed}))},
            "stderr":{"joined":book.stderr.is_none() && book.err_end.is_some(),"failed":book.err_failed,
                "end":book.err_end.as_ref().map(|r| json!({"frames":r.frames,"eof":r.eof,"closed":r.closed,"failed":r.failed}))},
            "driver":{"receipt":driver,"retained":driver_retained},"manager":{"receipt":manager,"retained":manager_retained},
            "observer":{"receipt":observer,"retained":observer_retained},"watchdog":{"receipt":watchdog,"retained":watchdog_retained},
            "outputBytes":owner.output_bytes.load(Ordering::SeqCst),"resourceUnknown":owner.resource_unknown.load(Ordering::SeqCst),
            "activeRetained":active_retained,"disabled":disabled,"canExit":can_exit}))
    }
    fn no_original(run: &Run) -> Check<()> {
        let r = run.bridge.preflight.original_for_test().inner.lock();
        require(r.active.is_none() && !run.permit.claimed.load(Ordering::SeqCst)
            && run.permit.admitted.lock().map_err(|_| "fixture_admission_slot")?.is_none(), "fixture_gate_allocated_original")
    }
    fn gate_case(run: &mut Run) -> Check<Value> {
        let mut gates = Vec::new();
        for gate in ["retained-private", "existing-work", "recovery-attention"] {
            run.document.offline_fixture_gate(&run.permit.registration, gate, true).map_err(|_| "fixture_gate_install")?;
            let refusal = run.document.prepare_offline_preflight(run.prepare_input());
            require(refusal.is_err_and(|error| error.code == "offline_preflight_busy"), "fixture_gate_prepare")?; no_original(run)?;
            require(run.bridge.preflight.original_for_test().inner.lock().prepared.is_none(), "fixture_gate_prepared_anyway")?;
            run.document.offline_fixture_gate(&run.permit.registration, gate, false).map_err(|_| "fixture_gate_clear")?;
            run.consent()?;
            run.document.offline_fixture_gate(&run.permit.registration, gate, true).map_err(|_| "fixture_gate_reinstall")?;
            let refusal = run.document.start_offline_preflight(run.start_input()?).map_err(|_| "fixture_gate_start_reply")?;
            let p = refusal.operation.ok_or("fixture_gate_start_projection")?;
            require(p.outcome == Some(Outcome::Refused) && p.reason == Reason::StaleIntent && !p.intent_usable
                && p.result.is_none() && run.bridge.preflight.original_for_test().inner.lock().prepared.is_none(), "fixture_gate_burned_intent")?;
            no_original(run)?;
            require(run.document.start_offline_preflight(run.start_input()?).is_err(), "fixture_gate_replay")?;
            run.document.offline_fixture_gate(&run.permit.registration, gate, false).map_err(|_| "fixture_gate_final_clear")?;
            gates.push(json!({"gate":gate,"prepareRefused":true,"startRefused":true,"intentBurned":true,"originalAllocated":false}));
        }
        require(run.bridge.preflight.can_exit(), "fixture_gate_exit")?;
        Ok(json!({"id":"PG01","classification":"inert-document-gates","assertion":"passed","gates":gates,"files":run.close_files()?}))
    }
    fn reverse_gates(run: &Run) -> Check<Value> {
        let s = run.original()?;
        require(run.bridge.preflight.busy() && run.stop()?.is_none(), "fixture_reverse_not_active")?;
        let status = run.document.offline_preflight_status().map_err(|_| "fixture_recovered_status")?;
        require(status.operation.is_some_and(|p| p.operation_id == s.id && p.owner_generation == s.generation && p.result.is_none()), "fixture_same_owner_recovery")?;
        require(run.document.start_offline_preflight(run.start_input()?).is_err(), "fixture_replayed_start")?;
        let foreign = if s.generation == "f".repeat(32) { "e".repeat(32) } else { "f".repeat(32) };
        require(run.document.cancel_offline_preflight(wire::Cancel { operation_id: s.id.clone(), owner_generation: foreign }).is_err(), "fixture_foreign_cancel")?;
        let passive = run.document.passive_query(&run.bridge, crate::protocol::Method::Capabilities, json!({}));
        require(passive.is_err_and(|error| error.code == "offline_preflight_busy"), "fixture_reverse_passive")?;
        let diagnostics = run.document.start_environment_diagnostics(crate::environment_diagnostics_protocol::Start {
            project_id: run.permit.context.project_id.clone(), draft: json!({}), draft_revision: 0, baseline_generation: 2,
            platform: crate::environment_diagnostics_protocol::Platform::Android,
            operation: crate::environment_diagnostics_protocol::Operation::Build });
        // Its real ticket qualification check precedes the document Busy gate.
        // No diagnostics permit is lent to this fixture: observe refusal before
        // acquisition and keep qualified-diagnostics Busy attribution unexecuted.
        require(diagnostics.is_err_and(|error| error.code == "environment_diagnostics_unavailable"), "fixture_reverse_diagnostics")?;
        // Qualification stays false, and the real gate precedes even decoding
        // an input token. This proves refusal/no acquisition, not qualified-GH
        // Busy attribution. The latter remains explicitly unexecuted.
        require(run.document.github_connection_connect_token(&json!({})).is_err_and(|error| error.code == "github_connection_refused_unqualified")
            && run.document.github_connection_status().session.is_none(), "fixture_reverse_private")?;
        require(run.bridge.preflight.busy() && run.bridge.supervisor.can_exit() && !run.bridge.diagnostics.busy() && run.bridge.diagnostics.can_exit()
            && run.stop()?.is_none(), "fixture_reverse_no_acquisition")?;
        { let r = run.bridge.preflight.original_for_test().inner.lock(); require(r.active.as_ref().is_some_and(|a| Arc::ptr_eq(&a.owner, s)), "fixture_reverse_same_owner")?; }
        run.cancel()?; let first = run.stop()?.ok_or("fixture_cancel_missing_f")?;
        let reached_writer = AtomicBool::new(false);
        let writer: Result<(), BridgeError> = run.document.configuration_edit_admit(|_| { reached_writer.store(true, Ordering::SeqCst); Ok(()) });
        require(writer.is_err_and(|error| error.code == "offline_preflight_busy") && !reached_writer.load(Ordering::SeqCst), "fixture_reverse_writer")?;
        run.cancel()?;
        require(run.stop()? == Some(first), "fixture_repeated_cancel_renewed_f")?;
        Ok(json!({"sameOwnerRecovered":true,"replayRejected":true,"foreignCancelRejected":true,"passiveRefused":true,
            "diagnosticsRefusal":"unqualified","writerRefused":true,"githubRefusal":"unqualified","privateSessionAbsent":true,"firstStopUnchanged":true}))
    }
    async fn final_hold(run: &Run) -> Check<Value> {
        run.entered().await?;
        let s = run.original()?;
        let terminal = run.terminal()?;
        let core = serde_json::to_value(&terminal).map_err(|_| "fixture_terminal_encode")?;
        require(terminal.outcome == Outcome::Complete && terminal.reason == Reason::None && terminal.result.is_some()
            && run.stop()?.is_none() && core["lifetime"]["commands"].as_u64().is_some_and(|n| n > 0), "fixture_pf07_real_complete")?;
        require(run.permit.files.lock().map_err(|_| "fixture_file_record")?.script.bytes()? == b"pass\n", "fixture_pf07_real_script")?;
        require(s.driver_joined.load(Ordering::SeqCst) && join_kind(&s.manager_return, |_| "ok-unit")? == "ok-unit"
            && join_kind(&s.observer_return, |_| "unexpected")? == "not-joined"
            && join_kind(&s.watchdog_return, |_| "unexpected")? == "not-joined", "fixture_pf07_original_hold")?;
        run.cancel()?; let first = run.stop()?.ok_or("fixture_pf07_original_f")?;
        let end = run.permit.end.min(first + SETTLEMENT + Duration::from_secs(2));
        let mut changes = run.bridge.preflight.subscribe();
        let observed = loop {
            // Deliberately RAW observation: no status/endpoint/advance call.
            // Only the original watchdog drives F+10 while its child JoinHandle
            // remains held. This observation ceiling grants no application clock.
            let unknown = { let r = run.bridge.preflight.original_for_test().inner.lock();
                r.disabled && r.active.as_ref().is_some_and(|a| Arc::ptr_eq(&a.owner, s) && a.unknown && a.first_stop == Some(first)) };
            if unknown { break Instant::now(); }
            tokio::time::timeout_at(tokio::time::Instant::from_std(end), changes.changed()).await
                .map_err(|_| "fixture_pf07_autonomous_unknown_missing")?.map_err(|_| "fixture_pf07_watch_lost")?;
        };
        require(observed >= first + SETTLEMENT && observed <= end, "fixture_pf07_original_deadline")?;
        let held = run.permit.gate.at.lock().map_err(|_| "fixture_hold_clock")?.ok_or("fixture_hold_clock_missing")?;
        run.permit.gate.release();
        Ok(json!({"observerHeldNs":held.saturating_duration_since(s.clocks.admitted).as_nanos() as u64,
            "firstStopNs":first.saturating_duration_since(s.clocks.admitted).as_nanos() as u64,
            "unknownObservedNs":observed.saturating_duration_since(s.clocks.admitted).as_nanos() as u64,
            "completeBeforeHold":true,"originalWatchdogOnly":true}))
    }
    async fn native_case(run: &Run) -> Check<Value> {
        let case = run.permit.case;
        let reciprocal = if case == Case::PF06 { run.readiness().await?; let gates = reverse_gates(run)?;
            run.permit.gate.release(); gates } else { Value::Null };
        let held = if case == Case::PF07 { final_hold(run).await? } else { Value::Null };
        let projection = run.settle().await?;
        let native = receipt(run)?; let terminal = run.terminal()?;
        let core = serde_json::to_value(&terminal).map_err(|_| "fixture_terminal_encode")?;
        let first = run.permit.observed.lock().map_err(|_| "fixture_observer_record")?.as_ref()
            .ok_or("fixture_observer_not_returned")?.first_stop;
        let (marker, later, pending_preserved) = {
            let files = run.permit.files.lock().map_err(|_| "fixture_file_record")?;
            let marker = files.script.bytes()?; let later = files.later.bytes()?;
            let pending = if let Some(pending) = &files.pending {
                require(pending.bytes()? == b"inert-pending-init\n", "fixture_pending_marker_changed")?;
                require(matches!(fs::symlink_metadata(files.project.join(".mobile-release")), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                    "fixture_pending_private_created")?; true
            } else { false };
            (marker, later, pending)
        };
        require(later.is_empty(), "fixture_forbidden_second_check")?;
        let (outcome, reason, expected_marker) = match case {
            Case::PF01 => (Outcome::Complete, Reason::None, b"pass\n".as_slice()),
            Case::PF02 => (Outcome::Complete, Reason::None, b"exit-7\n".as_slice()),
            Case::PF03 => (Outcome::Failed, Reason::CommandIncomplete, b"".as_slice()),
            Case::PF04a => (Outcome::Refused, Reason::SavedConfigChanged, b"".as_slice()),
            Case::PF04b => (Outcome::Refused, Reason::ProjectAdmissionRefused, b"".as_slice()),
            Case::PF05a => (Outcome::Failed, Reason::InputLimit, b"".as_slice()),
            Case::PF05b => (Outcome::Failed, Reason::ResultLimit, b"".as_slice()),
            Case::PF06 => (Outcome::Cancelled, Reason::Cancelled, b"active\n".as_slice()),
            Case::PF07 => (Outcome::Complete, Reason::None, b"pass\n".as_slice()),
            Case::PG01 => return Err("fixture_gate_is_not_native"),
        };
        require(terminal.outcome == outcome && terminal.reason == reason && marker == expected_marker, "fixture_required_native_predicate")?;
        if outcome == Outcome::Complete {
            require(core["lifetime"]["commands"].as_u64().is_some_and(|n| n > 0)
                && core["lifetime"]["commandDispatched"] == true && core["lifetime"]["stopObserved"] == "none"
                && core["result"]["usedConfig"] == serde_json::to_value(&run.permit.context.saved_config).map_err(|_| "fixture_saved_encode")?, "fixture_real_configured_check")?;
            let checks = core["result"]["findings"].as_array().ok_or("fixture_finding_roster")?;
            let expected = if case == Case::PF02 { "FAIL" } else { "PASS" };
            require(checks.iter().filter(|row| row["check"] == "configured-project-check").count() == 1
                && checks.iter().any(|row| row["check"] == "configured-project-check" && row["projectCheckIndex"] == 0 && row["status"] == expected), "fixture_configured_check_finding")?;
            if case != Case::PF02 { require(core["result"]["summary"]["counts"]["FAIL"] == 0
                && core["result"]["summary"]["counts"]["MISSING"] == 0 && core["result"]["summary"]["counts"]["BLOCKED"] == 0
                && core["result"]["summary"]["counts"]["INVALID"] == 0, "fixture_success_policy")?; }
            if case != Case::PF07 { require(first.is_none(), "fixture_policy_negative_is_not_f")?; }
        } else {
            require(core["result"].is_null() && projection.result.is_none() && first.is_some(), "fixture_refusal_not_report")?;
            if matches!(case, Case::PF04a | Case::PF04b | Case::PF05a | Case::PF05b) {
                require(core["lifetime"]["commands"] == 0 && core["lifetime"]["commandDispatched"] == false, "fixture_zero_command_reason")?;
            }
        }
        if case == Case::PF07 {
            require(projection.phase == Phase::Unknown && projection.outcome == Some(Outcome::Unknown)
                && projection.reason == Reason::CleanupUnknown && projection.result.is_none() && run.bridge.preflight.disabled(), "fixture_unknown_sticky")?;
            require(run.document.prepare_offline_preflight(run.prepare_input()).is_err()
                && run.document.start_offline_preflight(run.start_input()?).is_err(), "fixture_unknown_no_reopen")?;
            let s = run.original()?; let r = run.bridge.preflight.original_for_test().inner.lock();
            require(first.is_some() && r.active.as_ref().is_some_and(|a| Arc::ptr_eq(&a.owner, s)
                && a.unknown && a.final_join_seen && a.first_stop == first) && r.prepared.is_none()
                && held["firstStopNs"].as_u64() == first.map(|at| at.saturating_duration_since(s.clocks.admitted).as_nanos() as u64),
                "fixture_unknown_retained_admission")?;
        } else { require(projection.phase == Phase::Terminal && projection.outcome == Some(outcome) && projection.reason == reason
            && !run.bridge.preflight.disabled(), "fixture_native_projection")?; }
        let encoded = serde_json::to_string(&json!({"core":core,"projection":projection})).map_err(|_| "fixture_redaction_encode")?;
        require(!encoded.contains("OFFLINE_FIXTURE_PRIVATE") && !encoded.contains("check.py")
            && !encoded.contains(run.permit.registration.root.path.to_str().ok_or("fixture_root_text")?), "fixture_redaction")?;
        let s = run.original()?;
        Ok(json!({"id":case.id(),"classification":"real-fixed-bootstrap","assertion":"passed",
            "projection":projection,"core":core,"native":native,"files":run.close_files()?,
            "script":{"marker":std::str::from_utf8(&marker).map_err(|_| "fixture_marker_text")?,"secondExecuted":false,
                "expectedExit":if case == Case::PF02 { Some(7) } else if matches!(case, Case::PF01 | Case::PF07) { Some(0) } else { None::<i32> },
                "pendingPreserved":pending_preserved,"redacted":true},
            "timing":{"workMs":OFFLINE_WORK.as_millis() as u64,"hardMs":OFFLINE_HARD.as_millis() as u64,"settlementMs":SETTLEMENT.as_millis() as u64,
                "firstStopNs":first.map(|at| at.saturating_duration_since(s.clocks.admitted).as_nanos() as u64),"hold":held},"reciprocal":reciprocal}))
    }

    struct MemoryControl { eof: AtomicBool, closes: AtomicUsize, read: AtomicUsize, wake: Mutex<Option<Waker>> }
    struct MemoryReader { bytes: Vec<u8>, at: usize, control: Arc<MemoryControl> }
    impl AsyncRead for MemoryReader {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            if self.at < self.bytes.len() {
                let count = buffer.remaining().min(self.bytes.len() - self.at); let at = self.at;
                buffer.put_slice(&self.bytes[at..at + count]); self.at += count; self.control.read.fetch_add(count, Ordering::SeqCst);
                return Poll::Ready(Ok(()));
            }
            if self.control.eof.load(Ordering::SeqCst) { return Poll::Ready(Ok(())); }
            if let Ok(mut wake) = self.control.wake.lock() { *wake = Some(cx.waker().clone()); }
            if self.control.eof.load(Ordering::SeqCst) { Poll::Ready(Ok(())) } else { Poll::Pending }
        }
    }
    impl OriginalClose for MemoryReader {
        fn original_close(self) -> Result<(), ()> { self.control.closes.fetch_add(1, Ordering::SeqCst); Ok(()) }
    }
    fn memory(bytes: Vec<u8>, eof: bool) -> (Arc<AsyncMutex<Pipe<MemoryReader>>>, Arc<MemoryControl>) {
        let control = Arc::new(MemoryControl { eof: AtomicBool::new(eof), closes: AtomicUsize::new(0), read: AtomicUsize::new(0), wake: Mutex::new(None) });
        (Arc::new(AsyncMutex::new(Pipe { io: Some(MemoryReader { bytes, at: 0, control: control.clone() }), close: Close::New })), control)
    }
    fn memory_frames(owner: &Session, total: Option<usize>) -> Check<Vec<u8>> {
        let SavedContext::OfflinePreflight(context) = &owner.context else { return Err("fixture_memory_domain"); };
        let wire::Frame::Terminal(terminal) = wire::tests::terminal_frame(context) else { return Err("fixture_memory_terminal"); };
        let mut first = serde_json::to_vec(&json!({"protocol":wire::PROTOCOL,"operationId":owner.id,"ownerGeneration":owner.generation,
            "sequence":0,"kind":"accepted","payload":{"schemaVersion":1,"context":context}})).map_err(|_| "fixture_memory_encode")?;
        let mut last = serde_json::to_vec(&json!({"protocol":wire::PROTOCOL,"operationId":owner.id,"ownerGeneration":owner.generation,
            "sequence":1,"kind":"terminal","payload":terminal})).map_err(|_| "fixture_memory_encode")?;
        if let Some(total) = total {
            require(total > first.len() + last.len() + 2 && first.pop() == Some(b'}'), "fixture_memory_pad")?;
            first.resize(total - last.len() - 3, b' '); first.push(b'}');
        }
        first.push(b'\n'); last.push(b'\n'); first.extend(last); Ok(first)
    }
    async fn cap_vector() -> Check<Value> {
        let (application, owner) = super::active(); owner.pipes.send_replace(Pipes::Available);
        let (error, error_count) = memory(vec![b'x'; 33000], true);
        let early = read_output(application.original_for_test().inner.clone(), owner.clone(), error, true, Guard::new(&application.original_for_test().inner, &owner)).await;
        let bytes = memory_frames(&owner, Some(33000))?; require(bytes.len() == 33000, "fixture_memory_pad_exact")?;
        let (output, output_count) = memory(bytes, true);
        let end = read_output(application.original_for_test().inner.clone(), owner.clone(), output, false, Guard::new(&application.original_for_test().inner, &owner)).await;
        let bytes = owner.output_bytes.load(Ordering::SeqCst);
        require(early.failed && early.closed && early.eof && end.failed && end.closed && end.eof && end.frames < 2
            && bytes == 66000 && output_count.read.load(Ordering::SeqCst) == 33000 && error_count.read.load(Ordering::SeqCst) == 33000
            && output_count.closes.load(Ordering::SeqCst) == 1 && error_count.closes.load(Ordering::SeqCst) == 1, "fixture_shared_64k_cap")?;
        let r = application.original_for_test().inner.lock();
        require(r.disabled && r.active.as_ref().is_some_and(|a| a.unknown && a.projection.public().result.is_none()), "fixture_cap_not_success")?;
        Ok(json!({"id":"PV01","classification":"synthetic-reader-vectors","assertion":"passed","aggregateBytes":bytes,
            "stdoutBytes":33000,"stderrBytes":33000,"stdoutFailed":end.failed,"stderrFailed":early.failed,
            "originalCloses":2,"unknown":true,"reportPublished":false}))
    }
    async fn terminal_vectors() -> Check<Value> {
        let (application, owner) = super::active(); owner.pipes.send_replace(Pipes::Available);
        let (output, output_count) = memory(memory_frames(&owner, None)?, true);
        let early = read_output(application.original_for_test().inner.clone(), owner.clone(), output, false, Guard::new(&application.original_for_test().inner, &owner)).await;
        drain(&mut *owner.resources.lock().await, &application.original_for_test().inner, &owner);
        require(early.frames == 2 && !early.failed && early.eof && early.closed
            && application.original_for_test().inner.lock().active.as_ref().is_some_and(|a| a.terminal && !a.unknown), "fixture_vector_terminal_first")?;
        let (error, error_count) = memory(vec![b'x'], true);
        let late = read_output(application.original_for_test().inner.clone(), owner.clone(), error, true, Guard::new(&application.original_for_test().inner, &owner)).await;
        require(late.failed && late.eof && late.closed && application.original_for_test().inner.lock().active.as_ref()
            .is_some_and(|a| a.unknown && a.projection.public().result.is_none()), "fixture_vector_late_stderr")?;
        let (unfinished, pending_owner) = super::active(); pending_owner.pipes.send_replace(Pipes::Available);
        let (pending_output, count) = memory(memory_frames(&pending_owner, None)?, false);
        let mut original = Box::pin(read_output(unfinished.original_for_test().inner.clone(), pending_owner.clone(), pending_output, false, Guard::new(&unfinished.original_for_test().inner, &pending_owner)));
        let was_pending = std::future::poll_fn(|cx| Poll::Ready(matches!(original.as_mut().poll(cx), Poll::Pending))).await;
        drain(&mut *pending_owner.resources.lock().await, &unfinished.original_for_test().inner, &pending_owner);
        let provisional = unfinished.original_for_test().inner.lock().active.as_ref().is_some_and(|a| a.terminal && !a.unknown && a.projection.public().result.is_none());
        let not_closed = count.closes.load(Ordering::SeqCst) == 0;
        // Always release/join the sole original memory reader before returning
        // an assertion failure. It is a synthetic EOF vector, not an OS fault.
        count.eof.store(true, Ordering::SeqCst);
        if let Ok(mut wake) = count.wake.lock() { if let Some(wake) = wake.take() { wake.wake(); } }
        let ended = original.await;
        require(was_pending && provisional && not_closed && ended.frames == 2 && !ended.failed && ended.closed && ended.eof
            && count.closes.load(Ordering::SeqCst) == 1 && output_count.closes.load(Ordering::SeqCst) == 1
            && error_count.closes.load(Ordering::SeqCst) == 1, "fixture_unfinished_eof_veto")?;
        Ok(json!({"id":"PV02","classification":"synthetic-reader-vectors","assertion":"passed","terminalBeforeStderr":true,
            "lateStderrUnknown":true,"unfinishedEofPending":was_pending,"unfinishedEofReportPublished":false,
            "originalReadersReturned":3,"originalCloses":3}))
    }

    struct Outputs { progress: Option<File>, result: Option<File> }
    impl Outputs {
        fn create(inputs: &BoundInputs) -> Check<Self> {
            Ok(Self { progress: Some(create_private(&inputs.data.root.join("environment-native-progress.json"))?),
                result: Some(create_private(&inputs.data.root.join("environment-native-result.json"))?) })
        }
        fn progress(&mut self, inputs: &BoundInputs, completed: usize, stage: &'static str, failure: Option<&'static str>) -> Check<()> {
            original_json(self.progress.as_mut().ok_or("fixture_progress_closed")?, &json!({"schemaVersion":1,"scope":SCOPE,
                "inputsSha256":inputs.digest,"sourceSha":inputs.data.source_sha,"platform":inputs.data.platform,
                "classification":"native-not-settled","completedCases":&ORDER[..completed],"nextCase":ORDER.get(completed),
                "stage":stage,"failureCode":failure}), 8192)
        }
        fn finish(&mut self, value: &Value) -> Check<()> {
            original_json(self.result.as_mut().ok_or("fixture_result_closed")?, value, 768 * 1024)?;
            let result = close_file(self.result.take().ok_or("fixture_result_missing")?);
            let progress = close_file(self.progress.take().ok_or("fixture_progress_missing")?);
            result?; progress
        }
    }
    struct CompletedFixture { value: Value, _originals: Vec<Run> }
    async fn schedule(inputs: Arc<BoundInputs>, outputs: &mut Outputs, started: Instant) -> Check<CompletedFixture> {
        let end = started + ROSTER; let mut rows = Vec::new(); let mut originals = Vec::new();
        outputs.progress(&inputs, 0, "document-gates", None)?;
        let mut gate = Run::prepare(inputs.clone(), Case::PG01, end)?;
        rows.push(gate_case(&mut gate)?); originals.push(gate);
        outputs.progress(&inputs, rows.len(), "reader-vectors", None)?; rows.push(cap_vector().await?);
        outputs.progress(&inputs, rows.len(), "reader-vectors", None)?; rows.push(terminal_vectors().await?);
        for case in [Case::PF01, Case::PF02, Case::PF03, Case::PF04a, Case::PF04b, Case::PF05a, Case::PF05b, Case::PF06, Case::PF07] {
            end_check(end)?;
            outputs.progress(&inputs, rows.len(), "native-admission", None)?;
            let mut run = Run::prepare(inputs.clone(), case, end)?;
            let admission = (|| -> Check<()> {
                run.consent()?;
                if case == Case::PF04a { run.permit.files.lock().map_err(|_| "fixture_file_record")?.drift()?; }
                run.start()
            })();
            let result = match admission {
                Ok(()) => match outputs.progress(&inputs, rows.len(), if case == Case::PF07 { "final-observer-hold" } else { "native-originals" }, None) {
                    Ok(()) => native_case(&run).await, Err(error) => Err(error),
                },
                Err(error) => Err(error),
            };
            match result {
                Ok(row) => { rows.push(row); originals.push(run); },
                Err(error) => {
                    let _ = outputs.progress(&inputs, rows.len(), "original-only-retirement", Some("required-predicate"));
                    run.recover();
                    if run.session.is_some() {
                        let _ = run.cancel(); run.permit.gate.release();
                        // No replacement readers/acquisition, no reset endpoint,
                        // no source/runtime/tool probe. If the actual originals
                        // cannot prove physical finality inside the roster bound,
                        // keep this runtime and all original roots alive forever.
                        if run.settle().await.is_err() || receipt(&run).is_err() {
                            let _ = outputs.progress(&inputs, rows.len(), "original-only-retirement", Some("original-physical-finality"));
                            pending::<()>().await;
                        }
                    }
                    if run.close_files().is_err() {
                        let _ = outputs.progress(&inputs, rows.len(), "original-only-retirement", Some("original-physical-finality"));
                        pending::<()>().await;
                    }
                    originals.push(run); return Err(error);
                },
            }
        }
        // PF07 is lane-last. Only already-owned bounded result DATA and original
        // closes follow; there is no post-tail source/tool probe or cleanup.
        // Its original Active/observer/watchdog stay retained through output
        // closes; neither those closes nor process disposal proves application
        // canExit or authorizes fixture-tree deletion/reuse.
        require(rows.len() == ORDER.len() && rows.iter().zip(ORDER).all(|(row, id)| row["id"] == id), "fixture_complete_roster")?;
        end_check(end)?; outputs.progress(&inputs, rows.len(), "result", None)?;
        let d = &inputs.data;
        let value = json!({"schemaVersion":1,"scope":SCOPE,"inputsSha256":inputs.digest,"invocationSha256":inputs.invocation_digest,
            "sourceSha":d.source_sha,"sourceTree":d.source_tree,"platform":d.platform,"target":d.target,"workflowSha":d.workflow_sha,
            "runId":d.run_id,"attempt":d.attempt,"caseOrder":ORDER,"cases":rows,
            "unexecuted":[{"case":"full-work-expiry","reason":"not-run"},
                {"case":"qualified-diagnostics-busy","reason":"qualification-disabled"},{"case":"qualified-github-busy","reason":"qualification-disabled"}],
            "classification":"finite-complete-with-expected-finality-unknown"});
        Ok(CompletedFixture { value, _originals: originals })
    }

    pub(crate) fn hosted_offline_preflight_original_resources() {
        let started = Instant::now(); // Original finite-roster infrastructure clock, never W/H/F.
        let result = (|| -> Check<()> {
            let inputs = Arc::new(BoundInputs::load_offline()?);
            let mut outputs = Outputs::create(&inputs)?;
            outputs.progress(&inputs, 0, "inputs", None)?;
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).max_blocking_threads(2).enable_all().build()
                .map_err(|_| "fixture_runtime_create")?;
            match runtime.block_on(schedule(inputs.clone(), &mut outputs, started)) {
                Ok(report) => outputs.finish(&report.value), // retain originals through both actual output closes
                Err(error) => {
                    if let Some(file) = outputs.result.take() { let _ = close_file(file); }
                    if let Some(file) = outputs.progress.take() { let _ = close_file(file); }
                    Err(error)
                },
            }
        })();
        assert!(result.is_ok(), "finite offline fixture rejected: {}", result.err().unwrap_or("unknown"));
    }
}
