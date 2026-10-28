//! Closed GitRead arm of the original Supervisor. No separate driver,
//! watchdog, process group, joiner, deadline renewal or source executor.
use super::*;
use crate::error::{GitReadFailureOrigin, GitReadFailureProvenance};
use crate::git_read_protocol as wire;

#[derive(Clone, Copy)]
pub(crate) struct Endpoints {
    pub(crate) work: Instant,
    pub(crate) hard: Instant,
}
impl Endpoints {
    pub(crate) fn at(start: Instant) -> Option<Self> {
        Some(Self {
            work: start.checked_add(Duration::from_secs(wire::WORK_SECONDS))?,
            hard: start.checked_add(Duration::from_secs(wire::HARD_SECONDS))?,
        })
    }
    pub(crate) fn first_failure(self, at: Instant) -> Instant {
        at.min(self.work)
            .checked_add(Duration::from_secs(10))
            .unwrap_or(self.hard)
            .min(self.hard)
    }
}
pub(crate) struct GitReadAdmission {
    pub(super) invocation: Invocation,
    pub(super) endpoints: Endpoints,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) slots: Arc<Mutex<crate::installed_runtime::GitReadRuntimeSlots>>,
}
pub(super) struct Invocation {
    pub(super) gate: crate::asset_session::GitReadGate,
    pub(super) context: wire::Context,
    pub(super) action: wire::Action,
    pub(super) receipt: Arc<Mutex<GitReadReceipt>>,
    request: Mutex<Option<Arc<wire::Request>>>,
    child_reply: Mutex<Option<wire::Terminal>>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) sources: Arc<Mutex<crate::asset_source::GitReadSources>>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    clock: Mutex<Option<mrk_macos_installed_native::vault_helper_wire::ClockBridge>>,
}
impl GitReadAdmission {
    // DATA allocation only, called within the same Document admission. Native
    // inspection/clock calls occur later on Resources.inspection, never here.
    pub(crate) fn reserve(gate: crate::asset_session::GitReadGate, action: wire::Action, admitted: Instant) -> Result<Self, BridgeError> {
        let endpoints = Endpoints::at(admitted).ok_or_else(BridgeError::timeout)?;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            let mut slots = crate::installed_runtime::GitReadRuntimeSlots::new();
            slots
                .reserve_once()
                .map_err(|_| BridgeError::unavailable("The original Git read storage was refused."))?;
            let context = gate.context();
            Ok(Self {
                invocation: Invocation {
                    gate,
                    context,
                    action,
                    receipt: Arc::new(Mutex::new(GitReadReceipt::Pending)),
                    request: Mutex::new(None),
                    child_reply: Mutex::new(None),
                    sources: Arc::new(Mutex::new(crate::asset_source::GitReadSources::new())),
                    clock: Mutex::new(None),
                },
                endpoints,
                slots: Arc::new(Mutex::new(slots)),
            })
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            let _ = (gate, action, endpoints);
            Err(BridgeError::unavailable("Read-only Git is unavailable on this installed runtime."))
        }
    }
    pub(crate) fn reservation_bytes() -> Option<usize> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            crate::installed_runtime::GitReadRuntimeSlots::working_reservation_bytes()?
                .checked_add(std::mem::size_of::<Self>() + std::mem::size_of::<Owner>() + std::mem::size_of::<Resources>())
                .and_then(|n| n.checked_add(std::mem::size_of::<crate::github_connection_session::LocalGitReadSession>()))
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            None
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) enum GitReadReceipt {
    Pending,
    RetainedUnknown,
    Settled {
        outcome: Result<wire::Terminal, BridgeError>,
        was_unknown: bool,
        failure_provenance: Option<GitReadFailureProvenance>,
    },
}
pub(crate) enum GitReadStop { ExplicitCancel, DocumentStop }
pub(crate) struct GitReadTicket {
    owner: Arc<Owner>,
    receipt: Arc<Mutex<GitReadReceipt>>,
}
impl GitReadTicket {
    #[cfg(test)]
    pub(crate) fn pending_display_fixture(supervisor: &Supervisor) -> Self {
        // Actual owner/roster/ticket bookkeeping, with no driver, native IO or
        // fabricated completion. This fixture cannot qualify an installed read.
        let mut owner = super::tests::inert_owner();
        owner.profile = Profile::GitRead;
        let endpoints = Endpoints::at(Instant::now()).unwrap();
        owner.git_read_endpoints = Some(endpoints);
        owner.state = Mutex::new(OwnerState::new(endpoints.work, None));
        let owner = Arc::new(owner);
        assert!(lock(&supervisor.inner.owners).insert(owner.key, owner.clone()).is_none());
        Self { owner, receipt: Arc::new(Mutex::new(GitReadReceipt::Pending)) }
    }
    #[cfg(test)]
    pub(crate) fn display_fixture_observation(&self) -> (Instant, Option<BridgeError>) {
        (self.owner.endpoint(), lock(&self.owner.state).error.clone())
    }
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn stop(&self, cause: GitReadStop) {
        let origin = match cause {
            GitReadStop::ExplicitCancel => GitReadFailureOrigin::ExplicitCancel,
            GitReadStop::DocumentStop => GitReadFailureOrigin::DocumentStop,
        };
        self.owner.fail(BridgeError::new("cancelled", "The original local Git read was stopped.")
            .with_git_read_failure_provenance(Some(boundary_provenance(&self.owner, origin))));
    }
    pub(crate) fn receipt(&self) -> GitReadReceipt {
        lock(&self.receipt).clone()
    }
    pub(crate) fn pending_phase(&self) -> wire::Phase {
        let state = lock(&self.owner.state);
        if state.unknown {
            wire::Phase::CleanupUnknown
        } else if state.error.is_some() {
            wire::Phase::Stopping
        } else if self.owner.preflight_go_claimed.load(Ordering::SeqCst) {
            wire::Phase::Running
        } else {
            wire::Phase::Starting
        }
    }
    pub(crate) fn settled(&self) -> bool {
        matches!(&*lock(&self.receipt), GitReadReceipt::Settled { was_unknown: false, .. })
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        GitReadAdmission::reservation_bytes()
    }
}
impl Supervisor {
    pub(crate) fn git_read_profile_available(&self) -> bool {
        selected(Profile::GitRead) && self.inner.runtime.git_read_profile_available()
    }
    pub(crate) fn start_git_read(&self, admission: GitReadAdmission) -> Result<GitReadTicket, BridgeError> {
        if !self.git_read_profile_available() {
            return Err(BridgeError::unavailable("The fixed read-only Git runtime is unavailable."));
        }
        let receipt = admission.invocation.receipt.clone();
        // Caller holds the genuine Document gate through this ORIGINAL roster
        // insertion. No fallible check follows the retained Supervisor claim.
        let owner = self.admit(AdmissionRequest::GitRead(admission), CompletionTarget::GitRead)?;
        Ok(GitReadTicket { owner, receipt })
    }
}
pub(super) fn selected(profile: Profile) -> bool {
    cfg!(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    )) && matches!(profile, Profile::GitRead)
}
pub(super) fn boundary_provenance(owner: &Owner, origin: GitReadFailureOrigin) -> GitReadFailureProvenance {
    GitReadFailureProvenance { origin, go_claimed_at_boundary: Some(owner.preflight_go_claimed.load(Ordering::SeqCst)), command_failure: None }
}
#[derive(Clone, Copy)]
enum SourcePhase { Inspect, Post }
fn source_checkpoint(owner: &Owner, stop: &watch::Receiver<bool>, phase: SourcePhase,
    first: &mut Option<GitReadFailureProvenance>) -> bool {
    use GitReadFailureOrigin as Origin;
    // Preserve the existing short-circuit order and its one expiry check.
    // Freeze the first true checkpoint BEFORE native failure forwarding can
    // change owner.failed(). Never infer this cause later from a stopped owner.
    let origin = if owner.failed() {
        Some(match phase { SourcePhase::Inspect => Origin::SourceInspectOwnerFailed, SourcePhase::Post => Origin::SourcePostOwnerFailed })
    } else if *stop.borrow() {
        Some(match phase { SourcePhase::Inspect => Origin::SourceInspectStopFlag, SourcePhase::Post => Origin::SourcePostStopFlag })
    } else if Instant::now() >= owner.endpoint() {
        Some(match phase { SourcePhase::Inspect => Origin::SourceInspectExpired, SourcePhase::Post => Origin::SourcePostExpired })
    } else {
        None
    };
    if let Some(origin) = origin {
        if first.is_none() { *first = Some(boundary_provenance(owner, origin)); }
        true
    } else { false }
}
fn source_error(reason: crate::asset_commands::Reason, checkpoint: Option<GitReadFailureProvenance>) -> BridgeError {
    use crate::asset_commands::Reason;
    match reason {
        Reason::CleanupUnknown => BridgeError::cleanup_unknown(),
        Reason::UserCancelled => BridgeError::new("cancelled", "The original Git read was stopped.")
            .with_git_read_failure_provenance(checkpoint),
        Reason::SourceChanged => BridgeError::new("git_stale_observation", "The original Git source changed."),
        _ => BridgeError::unavailable("The original Git source is not supported by this read-only profile."),
    }
}
impl Invocation {
    pub(super) fn request(&self) -> Result<Arc<wire::Request>, BridgeError> {
        self.request
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)
    }
    pub(super) fn unknown(&self) {
        *lock(&self.receipt) = GitReadReceipt::RetainedUnknown;
    }
    pub(super) fn retire(&self, outcome: Result<wire::Terminal, BridgeError>, was_unknown: bool) {
        let mut receipt = lock(&self.receipt);
        if was_unknown
            || !matches!(*receipt, GitReadReceipt::Pending)
            || outcome.as_ref().is_err_and(|error| error.code == "cleanup_unknown")
        {
            *receipt = GitReadReceipt::RetainedUnknown;
        } else {
            // Copy ONLY the winning original error, before a known child
            // refusal becomes Ok(Terminal). A later tagged failure must not
            // decorate an earlier untagged error or a successful child reply.
            let failure_provenance = outcome.as_ref().err().and_then(BridgeError::git_read_failure_provenance);
            // A known child refusal starts the original min-first-F cleanup.
            // Once that SAME owner genuinely retires, keep its closed reason,
            // not a generic error. Never resurrect a vetoed child success.
            let outcome = if outcome.as_ref().is_err_and(|error| error.code == "git_read_refused") {
                match self.child_reply.lock().ok().and_then(|value| value.clone()) {
                    Some(value) if value.status != wire::Outcome::Ok && value.child_declared_settled() => Ok(value),
                    _ => outcome,
                }
            } else {
                outcome
            };
            *receipt = GitReadReceipt::Settled {
                outcome,
                was_unknown: false,
                failure_provenance,
            };
        }
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) fn inspect(
        &self,
        runtime: &RuntimeConfig,
        owner: &Owner,
        slots: &Arc<Mutex<crate::installed_runtime::GitReadRuntimeSlots>>,
    ) -> Result<VerifiedRuntime, BridgeError> {
        let root = self.gate.check_current(&owner.id)?;
        let stop = owner.stop.subscribe();
        let selected = {
            let mut native = slots.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            let armed = native.arm_acl_once(owner.endpoint(), &stop);
            owner.observe_native_failure(native.first_failure());
            armed.map_err(|_| BridgeError::cleanup_unknown())?;
            let value = runtime.resolve_git_read_installed(&mut native, owner.endpoint(), &stop);
            owner.observe_native_failure(native.first_failure());
            value?
        };
        let snapshot = {
            let mut sources = self.sources.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            let mut checkpoint = None;
            let result = sources.inspect(
                &root,
                crate::installed_runtime::GitReadRuntimeSlots::source_runtime_fd_bound(),
                &mut || source_checkpoint(owner, &stop, SourcePhase::Inspect, &mut checkpoint),
            );
            observe_source_failure(owner, sources.first_failure());
            result.map_err(|reason| source_error(reason, checkpoint))?;
            sources.native_snapshot().map_err(|reason| source_error(reason, None))?.clone()
        };
        let endpoints = owner.git_read_endpoints.ok_or_else(BridgeError::cleanup_unknown)?;
        let mut clock = mrk_macos_installed_native::vault_helper_wire::ClockBridge::capture().ok_or_else(BridgeError::cleanup_unknown)?;
        let native_clock = wire::Clock {
            work_end_ns: clock.endpoint(endpoints.work).ok_or_else(BridgeError::cleanup_unknown)?,
            hard_end_ns: clock.endpoint(endpoints.hard).ok_or_else(BridgeError::cleanup_unknown)?,
        };
        let request = Arc::new(wire::Request::from_original(
            &owner.id,
            &self.action,
            &self.context,
            &snapshot,
            native_clock,
        )?);
        {
            let mut slot = self.request.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            let mut bridge = self.clock.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if slot.is_some() || bridge.is_some() {
                return Err(BridgeError::cleanup_unknown());
            }
            *slot = Some(request);
            *bridge = Some(clock);
        }
        self.gate.check_current(&owner.id)?;
        Ok(selected)
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) fn before_go(
        &self,
        owner: &Owner,
        slots: &Arc<Mutex<crate::installed_runtime::GitReadRuntimeSlots>>,
    ) -> Result<(), BridgeError> {
        self.gate.check_current(&owner.id)?;
        let stop = owner.stop.subscribe();
        {
            let mut native = slots.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            let result =
                native
                    .capability()
                    .map_err(|_| BridgeError::cleanup_unknown())?
                    .post_original(owner.endpoint(), &stop, &mut |f| owner.observe_native_failure(f));
            owner.observe_native_failure(native.first_failure());
            result.map_err(|_| BridgeError::cleanup_unknown())?;
        }
        let mut sources = self.sources.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut checkpoint = None;
        let result = sources.post(&mut || source_checkpoint(owner, &stop, SourcePhase::Post, &mut checkpoint));
        observe_source_failure(owner, sources.first_failure());
        result.map_err(|reason| source_error(reason, checkpoint))
    }
    pub(super) fn decode_before_close(
        &self,
        owner: &Owner,
        output: &ReadEnd,
        stderr: &ReadEnd,
        waited: bool,
    ) -> Result<wire::Terminal, BridgeError> {
        if !waited || !output.eof || output.overflow || !stderr.eof || stderr.overflow || !stderr.bytes.is_empty() {
            return Err(BridgeError::cleanup_unknown());
        }
        let request = self.request()?;
        // The reader removed and validated exactly one READY frame. What
        // remains is exactly one terminal, not a line chosen from arbitrary IO.
        let terminal = request.terminal(&output.bytes)?;
        if !terminal.child_declared_settled() {
            return Err(BridgeError::cleanup_unknown());
        }
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        if let Some(first) = terminal.first_failure_ns {
            let mut bridge = self.clock.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            let at = bridge
                .as_mut()
                .ok_or_else(BridgeError::cleanup_unknown)?
                .failure_bound(first)
                .ok_or_else(BridgeError::cleanup_unknown)?;
            let mut provenance = boundary_provenance(owner, GitReadFailureOrigin::ChildTerminal);
            provenance.command_failure = terminal.command_failure;
            let error = BridgeError::new("git_read_refused", "The original bounded Git read did not complete.")
                .with_git_read_failure_provenance(Some(provenance));
            lock(&owner.state).fail_at(error, at);
            owner.stop.send_replace(true);
            owner.changed.notify_waiters();
        }
        let mut slot = self.child_reply.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        *slot = Some(terminal.clone());
        Ok(terminal)
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
fn observe_source_failure(owner: &Owner, first: Option<(mrk_macos_installed_native::vault_filesystem::Failure, Instant)>) {
    use mrk_macos_installed_native::vault_filesystem::Failure;
    owner.observe_native_failure(first.map(|(failure, at)| {
        (
            match failure {
                Failure::Unknown => crate::installed_runtime::AdmissionFailure::Unknown,
                _ => crate::installed_runtime::AdmissionFailure::Ownership,
            },
            at,
        )
    }));
}

// Called in the EXISTING native_settlement task only after all original
// borrowers joined. Even a known child refusal cannot manufacture those joins.
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn settle(owner: &Owner, slots: &Arc<Mutex<crate::installed_runtime::GitReadRuntimeSlots>>) -> CloseOutcome {
    let Some(read) = owner.git_read.as_ref() else {
        return CloseOutcome::Unknown;
    };
    // Only the already-decoded outcome is needed during close. Keep the
    // bounded result in its original slot instead of allocating another copy.
    let declared = read.child_reply.lock().ok().and_then(|s| s.as_ref().map(|reply| reply.status));
    // Never acquire Document while holding either native/source mutex. The
    // original Document -> Supervisor registry -> owner ordering stays intact.
    if declared == Some(wire::Outcome::Ok) && !owner.failed() {
        if let Err(error) = read.gate.check_current(&owner.id) {
            owner.fail(error);
        }
    }
    let mut native = match slots.lock() {
        Ok(v) => v,
        Err(e) => {
            let mut v = e.into_inner();
            v.mark_interrupted();
            v
        }
    };
    let mut sources = match read.sources.lock() {
        Ok(v) => v,
        Err(e) => {
            let mut v = e.into_inner();
            v.mark_interrupted();
            v
        }
    };
    if declared.is_none() && !native.no_child_effect() {
        return CloseOutcome::Unknown;
    }
    if declared == Some(wire::Outcome::Ok) && !owner.failed() {
        // Check real current Document/source again before exposing successful
        // DATA. A stale source is a failure, not permission to adopt its edits.
        if !owner.failed() {
            let stop = owner.stop.subscribe();
            let mut checkpoint = None;
            let result = sources.post(&mut || source_checkpoint(owner, &stop, SourcePhase::Post, &mut checkpoint));
            observe_source_failure(owner, sources.first_failure());
            if let Err(reason) = result {
                owner.fail(source_error(reason, checkpoint));
            }
        }
    }
    let source_closed = sources
        .close(&mut |first| {
            observe_source_failure(owner, first);
            owner.native_cleanup_expired(None)
        })
        .is_ok();
    let runtime_closed = native.settle_originals(&mut |first| owner.native_cleanup_expired(first));
    if !source_closed || !sources.settled() || !matches!(runtime_closed, CloseOutcome::Settled) {
        CloseOutcome::Unknown
    } else {
        CloseOutcome::Settled
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    feature = "desktop-shell",
    feature = "custom-protocol",
    not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher")
))]
pub(super) fn acquire_original(
    inner: &Inner,
    owner: &Arc<Owner>,
    slots: &Arc<Mutex<crate::installed_runtime::GitReadRuntimeSlots>>,
) -> Result<Child, AcquisitionError> {
    let mut native = slots
        .lock()
        .map_err(|_| AcquisitionError::unsupported("Git read runtime custody unavailable"))?;
    let runtime = native.capability().map_err(AcquisitionError::capability)?;
    let stop = owner.stop.subscribe();
    let mut first = None;
    let selected = runtime
        .prepare_once_observed(owner.endpoint(), &stop, &mut |f| {
            first = f;
            owner.observe_native_failure(f);
        })
        .map_err(|e| AcquisitionError::preparation(e).with_macos_first_failure(first))?;
    let mut command = Command::new(&selected.python);
    command
        .args(["-I", "-S", "-B"])
        .arg(&selected.bootstrap)
        .arg(&selected.core)
        .current_dir(&selected.cwd)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    crate::runtime::macos_installed_environment(&mut command).map_err(AcquisitionError::from)?;
    let owners = lock(&inner.owners);
    let state = lock(&owner.state);
    if !preflight_claim_clear(
        owners.get(&owner.key).is_some_and(|v| Arc::ptr_eq(v, owner)),
        owner.profile,
        Profile::GitRead,
        &state,
        Instant::now(),
        inner.stopping.load(Ordering::SeqCst),
        inner.disabled.load(Ordering::SeqCst),
        *stop.borrow(),
    ) {
        return Err(AcquisitionError::unsupported("Original Git read claim changed"));
    }
    runtime.claim_once().map_err(AcquisitionError::final_claim)?;
    drop(state);
    drop(owners);
    command.spawn().map_err(AcquisitionError::returned_spawn)
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(all(
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    ))
))]
pub(super) fn acquire_original(
    _: &Inner,
    _: &Arc<Owner>,
    _: &Arc<Mutex<crate::installed_runtime::GitReadRuntimeSlots>>,
) -> Result<Child, AcquisitionError> {
    Err(AcquisitionError::unsupported("The fixed Git read runtime is unavailable"))
}

// Same writer/reader task slots and fault channel as all original Supervisor
// reads. Keep stdin open after GO: EOF means STOP to the fixed Python worker.
pub(super) async fn write(
    mut stdin: tokio::process::ChildStdin,
    request: Arc<wire::Request>,
    ready: oneshot::Receiver<Result<(), BridgeError>>,
    wait: oneshot::Receiver<()>,
    post: oneshot::Sender<oneshot::Sender<Result<(), BridgeError>>>,
    inner: Arc<Inner>,
    owner: Arc<Owner>,
    faults: mpsc::Sender<BridgeError>,
) -> WriteEnd {
    let mut stop = owner.stop.subscribe();
    if *stop.borrow() || owner.failed() || Instant::now() >= owner.endpoint() {
        return WriteEnd { complete: false };
    }
    let result =
        tokio::select! { biased; _=stop.changed()=>return WriteEnd{complete:false}, result=stdin.write_all(request.bytes())=>result };
    if result.is_err() {
        owner.fail(BridgeError::new("io_error", "The original Git request write failed."));
        return WriteEnd { complete: false };
    }
    let readied = tokio::select! { biased; _=stop.changed()=>return WriteEnd{complete:false}, value=ready=>value };
    if !matches!(readied, Ok(Ok(()))) {
        owner.fail(BridgeError::protocol());
        return WriteEnd { complete: false };
    }
    let (send, returned) = oneshot::channel();
    if post.send(send).is_err() {
        owner.fail(BridgeError::cleanup_unknown());
        return WriteEnd { complete: false };
    }
    let posted = tokio::select! { biased; _=stop.changed()=>return WriteEnd{complete:false}, value=returned=>value };
    if !matches!(posted, Ok(Ok(()))) {
        owner.fail(BridgeError::cleanup_unknown());
        return WriteEnd { complete: false };
    }
    let Some(read) = owner.git_read.as_ref() else {
        owner.fail(BridgeError::cleanup_unknown());
        return WriteEnd { complete: false };
    };
    if let Err(error) = read.gate.claim(&owner.id, || {
        claim_preflight_go(&inner, &owner, Profile::GitRead)
            .then_some(())
            .ok_or_else(BridgeError::cleanup_unknown)
    }) {
        owner.fail(error);
        return WriteEnd { complete: false };
    }
    let bytes = request.go();
    let sent = tokio::select! {biased; _=stop.changed()=>false, value=stdin.write_all(&bytes)=>value.is_ok()};
    if !sent {
        owner.fail(BridgeError::new("io_error", "The original Git read GO failed."));
        return WriteEnd { complete: false };
    }
    let waited = tokio::select! {biased; _=stop.changed()=>false, value=wait=>value.is_ok()};
    let closed = stdin.shutdown().await.is_ok();
    drop(stdin);
    if !closed {
        let error = BridgeError::new("io_error", "The original Git read control did not close.");
        owner.fail(error.clone());
        let _ = faults.try_send(error);
    }
    WriteEnd {
        complete: waited && closed,
    }
}
pub(super) async fn read<T: AsyncRead + Unpin>(
    mut stdout: T,
    request: Arc<wire::Request>,
    ready: oneshot::Sender<Result<(), BridgeError>>,
    faults: mpsc::Sender<BridgeError>,
) -> ReadEnd {
    let mut ready = Some(ready);
    let mut buffer = [0u8; 4096];
    let mut bytes = Vec::new();
    let mut eof = false;
    let mut overflow = false;
    let mut total = 0usize;
    loop {
        match stdout.read(&mut buffer).await {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(count) => {
                total = total.saturating_add(count);
                if total > wire::RESPONSE_LIMIT {
                    overflow = true;
                    let _ = faults.try_send(BridgeError::protocol());
                    continue;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(index) = bytes.iter().position(|v| *v == b'\n').filter(|_| ready.is_some()) {
                    let result = request.ready(&bytes[..=index]);
                    if result.is_err() {
                        overflow = true;
                        let _ = faults.try_send(BridgeError::protocol());
                    }
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(result);
                    }
                    bytes.drain(..=index);
                } else if ready.is_some() && bytes.len() > wire::READY_LIMIT {
                    overflow = true;
                    let _ = faults.try_send(BridgeError::protocol());
                }
            }
            Err(_) => {
                let _ = faults.try_send(BridgeError::new("io_error", "The original Git read output failed."));
                break;
            }
        }
    }
    if let Some(ready) = ready {
        let _ = ready.send(Err(BridgeError::protocol()));
    }
    ReadEnd { bytes, eof, overflow }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn git_read_ticket_stop_provenance_does_not_decorate_an_earlier_error() {
        // Bookkeeping only: the existing inert owner has no child or tasks.
        for (cause, origin) in [(GitReadStop::ExplicitCancel, GitReadFailureOrigin::ExplicitCancel),
            (GitReadStop::DocumentStop, GitReadFailureOrigin::DocumentStop)] {
            let owner = Arc::new(super::super::tests::inert_owner());
            let ticket = GitReadTicket { owner: owner.clone(), receipt: Arc::new(Mutex::new(GitReadReceipt::Pending)) };
            ticket.stop(cause);
            let first = lock(&owner.state).error.clone().unwrap();
            assert_eq!(first, BridgeError::new("cancelled", "The original local Git read was stopped."));
            assert_eq!(first.git_read_failure_provenance(), Some(GitReadFailureProvenance { origin, go_claimed_at_boundary: Some(false), command_failure: None }));
            owner.preflight_go_claimed.store(true, Ordering::SeqCst);
            ticket.stop(GitReadStop::DocumentStop);
            assert_eq!(lock(&owner.state).error.as_ref().unwrap().git_read_failure_provenance(), first.git_read_failure_provenance());
        }
        let owner = Arc::new(super::super::tests::inert_owner());
        owner.fail(BridgeError::timeout());
        let endpoint = lock(&owner.state).cleanup_endpoint;
        GitReadTicket { owner: owner.clone(), receipt: Arc::new(Mutex::new(GitReadReceipt::Pending)) }.stop(GitReadStop::ExplicitCancel);
        let state = lock(&owner.state);
        assert_eq!(state.error, Some(BridgeError::timeout()));
        assert_eq!(state.error.as_ref().unwrap().git_read_failure_provenance(), None);
        assert_eq!(state.cleanup_endpoint, endpoint);
    }
    #[test]
    fn git_read_source_provenance_freezes_the_actual_first_true_checkpoint() {
        use crate::asset_commands::Reason;
        use GitReadFailureOrigin as Origin;
        for (phase, origins) in [(SourcePhase::Inspect, [Origin::SourceInspectOwnerFailed, Origin::SourceInspectStopFlag, Origin::SourceInspectExpired]),
            (SourcePhase::Post, [Origin::SourcePostOwnerFailed, Origin::SourcePostStopFlag, Origin::SourcePostExpired])] {
            for (cause, origin) in origins.into_iter().enumerate() {
                let owner = super::super::tests::inert_owner();
                let stop = owner.stop.subscribe();
                let mut first = None;
                assert!(!source_checkpoint(&owner, &stop, phase, &mut first));
                assert_eq!(first, None);
                // Simultaneously expired/flagged data checks the original
                // owner-error -> stop-flag -> expiry short-circuit priority.
                lock(&owner.state).endpoint = Instant::now();
                if cause <= 1 { owner.stop.send_replace(true); }
                if cause == 0 { lock(&owner.state).error = Some(BridgeError::timeout()); }
                assert!(source_checkpoint(&owner, &stop, phase, &mut first));
                let expected = Some(GitReadFailureProvenance { origin, go_claimed_at_boundary: Some(false), command_failure: None });
                assert_eq!(first, expected);
                owner.preflight_go_claimed.store(true, Ordering::SeqCst);
                owner.fail(BridgeError::unavailable("inert later native forwarding"));
                assert!(source_checkpoint(&owner, &stop, phase, &mut first));
                assert_eq!(first, expected);
                assert_eq!(source_error(Reason::UserCancelled, first).git_read_failure_provenance(), expected);
                for other in [Reason::CleanupUnknown, Reason::SourceChanged, Reason::Deadline] {
                    assert_eq!(source_error(other, first).git_read_failure_provenance(), None);
                }
            }
        }
        assert_eq!(source_error(Reason::UserCancelled, None).git_read_failure_provenance(), None);
    }
    #[test]
    fn git_read_provenance_follows_the_original_min_first_failure_winner() {
        let start = Instant::now();
        let endpoints = Endpoints::at(start).unwrap();
        let mut state = OwnerState::new(endpoints.work, None);
        state.git_read_endpoints = Some(endpoints);
        let early = start + Duration::from_secs(2);
        let late = start + Duration::from_secs(5);
        let plain = BridgeError::new("cancelled", "inert original error");
        let child = BridgeError::new("git_read_refused", "inert child refusal")
            .with_git_read_failure_provenance(Some(GitReadFailureProvenance {
                origin: GitReadFailureOrigin::ChildTerminal, go_claimed_at_boundary: Some(true), command_failure: None,
            }));
        state.fail_at(plain.clone(), early);
        for at in [late, early] {
            state.fail_at(child.clone(), at);
            assert_eq!(state.error, Some(plain.clone()));
            assert_eq!(state.error.as_ref().unwrap().git_read_failure_provenance(), None);
            assert_eq!(state.cleanup_endpoint, Some(endpoints.first_failure(early)));
        }
        // A genuinely earlier child F may replace the observed winner. Its
        // metadata moves WITH that error, never onto the old or next error.
        state.fail_at(child.clone(), start);
        assert_eq!(state.error.as_ref().unwrap().git_read_failure_provenance(), child.git_read_failure_provenance());
        assert_eq!(state.cleanup_endpoint, Some(endpoints.first_failure(start)));
        state.fail_at(plain.clone(), late);
        assert_eq!(state.error.as_ref().unwrap().git_read_failure_provenance(), child.git_read_failure_provenance());
        state.fail_at(plain.clone(), start - Duration::from_secs(1));
        assert_eq!(state.error.as_ref().unwrap().git_read_failure_provenance(), None);
        state.terminal = true;
        state.fail_at(child, start - Duration::from_secs(2));
        assert_eq!(state.error, Some(plain));
        assert_eq!(state.error.as_ref().unwrap().git_read_failure_provenance(), None);
        assert_eq!(state.endpoint, endpoints.work);
    }
    #[test]
    fn git_read_retirement_shutdown_has_no_capture_time_go_claim() {
        let start = Instant::now();
        let endpoints = Endpoints::at(start).unwrap();
        for read in [false, true] {
            for earlier in [false, true] {
                let mut state = OwnerState::new(endpoints.work, None);
                state.git_read_endpoints = read.then_some(endpoints);
                state.driver_join = ManagementJoin::Returned;
                state.watchdog_join = ManagementJoin::Returned;
                state.driver_end = Some(DriverEnd::Ready(Err(BridgeError::protocol())));
                state.watchdog_end = Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned));
                if earlier { state.fail_at(BridgeError::timeout(), start); }
                let error = state.retirement_result(start + Duration::from_secs(1), true).unwrap().unwrap_err();
                assert_eq!(error, if earlier { BridgeError::timeout() } else { BridgeError::shutdown() });
                assert_eq!(error.git_read_failure_provenance(), (read && !earlier).then_some(GitReadFailureProvenance {
                    origin: GitReadFailureOrigin::Shutdown, go_claimed_at_boundary: None, command_failure: None,
                }));
            }
        }
    }
    #[test]
    fn git_read_uses_one_original_45_55_clock_and_first_failure_minimum() {
        let at = Instant::now();
        let e = Endpoints::at(at).unwrap();
        assert_eq!(e.work, at + Duration::from_secs(45));
        assert_eq!(e.hard, at + Duration::from_secs(55));
        assert_eq!(e.first_failure(at + Duration::from_secs(2)), at + Duration::from_secs(12));
        assert_eq!(e.first_failure(e.hard + Duration::from_secs(50)), e.hard);
        let original = e.first_failure(at + Duration::from_secs(2));
        assert_eq!(original.min(e.first_failure(at + Duration::from_secs(20))), original);
    }
}
