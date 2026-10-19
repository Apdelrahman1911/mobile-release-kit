//! Actual protected JDK + installed helper on ONE original SavedCommand Session.
//! This owns no second runner/clock. The existing M2 observation/ONE moved SH
//! tail and original child/IO joins remain mandatory after both keytool calls.
#![forbid(unsafe_code)]
use super::super::android_leased::AndroidObservations;
use super::*;
use crate::installed_runtime::{
    android_lease_admission_issue, LeasedAndroidToolchainSlots, UploadKeyRuntimeSlots,
};
use mrk_macos_installed_native::android_catalog_query::Role;

pub(in crate::saved_command_owner) struct UploadKeyNativeBooks {
    runtime: UploadKeyRuntimeSlots,
    tools: LeasedAndroidToolchainSlots,
    control: Arc<AndroidUseControl>,
    selection: Option<VerifiedRuntime>,
    pub(in crate::saved_command_owner) phase: NativePhase,
    failure: Option<(AdmissionFailure, Instant)>,
    settlement_started: bool,
    cleanup: watch::Receiver<Instant>,
    pre_go_reservation: Option<usize>,
}
impl UploadKeyNativeBooks {
    pub(in crate::saved_command_owner) fn new(
        selected: android_wire::MacToolchainSelection,
        audit: watch::Receiver<Instant>,
        cleanup: watch::Receiver<Instant>,
        clocks: Clocks,
    ) -> Self {
        let tools = LeasedAndroidToolchainSlots::new_upload_key(selected, audit);
        let control = AndroidUseControl::reserved(
            tools.original_identity(),
            tools.query_signal(),
            tools.original_clock_slot(),
            Role::GenerateUploadKey,
            clocks.admitted,
            clocks.work,
            clocks.finality,
        );
        let mut value = Self {
            runtime: UploadKeyRuntimeSlots::new(),
            tools,
            control,
            selection: None,
            phase: NativePhase::New,
            failure: None,
            settlement_started: false,
            cleanup,
            pre_go_reservation: None,
        };
        value.pre_go_reservation = value
            .retained_now()
            .and_then(|n| n.checked_add(std::mem::size_of::<Session>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<Resources>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<AndroidObservationSlot>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<AndroidObservations>()));
        value
    }
    pub(in crate::saved_command_owner) fn control(&self) -> Arc<AndroidUseControl> {
        self.control.clone()
    }
    pub(in crate::saved_command_owner) fn pre_go_bytes(&self) -> Option<usize> {
        self.pre_go_reservation
    }
    fn retained_now(&self) -> Option<usize> {
        let selected = self.selection.as_ref().map_or(Some(0), |s| {
            s.python
                .capacity()
                .checked_add(s.bootstrap.capacity())?
                .checked_add(s.core.capacity())?
                .checked_add(s.cwd.capacity())
        });
        std::mem::size_of::<Self>()
            .checked_add(selected?)?
            .checked_add(self.runtime.retained_bytes()?)?
            .checked_add(self.tools.retained_bytes()?)?
            .checked_add(AndroidUseControl::retained_control_charge()?)?
            .checked_add(AndroidCloseSlot::fixed_charge()?)
    }
    fn retained_before_tail(&self) -> Option<usize> {
        self.pre_go_reservation?
            .checked_add(self.retained_now()?)
            .filter(|bytes| *bytes > 0 && *bytes <= wire::INSPECTION_RESERVE)
    }
    pub(in crate::saved_command_owner) fn first_failure(
        &self,
    ) -> Option<(AdmissionFailure, Instant)> {
        [
            self.failure,
            self.runtime.first_failure(),
            self.tools.first_failure(),
        ]
        .into_iter()
        .flatten()
        .min_by_key(|(_, t)| *t)
    }
    fn fail(&mut self, failure: AdmissionFailure, owner: &Session) {
        owner.upload_key.native_bytes.store(0, Ordering::SeqCst);
        let now = Instant::now();
        let first = self.first_failure().unwrap_or((failure, now));
        if self.failure.is_none_or(|(_, at)| first.1 < at) {
            self.failure = Some(first);
        }
        self.control
            .local(first.1, now, failure == AdmissionFailure::Unknown);
        self.phase = NativePhase::Refused;
        owner.publish_native_failure(Some(first));
    }
    pub(in crate::saved_command_owner) fn interrupted(&mut self) {
        self.phase = NativePhase::Unknown;
        self.runtime.mark_interrupted();
        self.tools.mark_interrupted();
        self.control.mark_unknown();
    }
    pub(in crate::saved_command_owner) fn inspect_once(
        &mut self,
        runtime: &RuntimeConfig,
        owner: &Session,
    ) -> Result<VerifiedRuntime, BridgeError> {
        owner.upload_key.native_bytes.store(0, Ordering::SeqCst);
        if self.phase != NativePhase::New {
            return Err(BridgeError::cleanup_unknown());
        }
        self.phase = NativePhase::Inspecting;
        let stop = owner.stop.subscribe();
        // Both inspectors share ONE existing128MiB nonsecret peak reserve and
        // run sequentially. The M2 quote covers its typed parse/walk/SH peak,
        // not just a small constructor. No private fields are sent yet.
        if !self
            .retained_before_tail()
            .zip(self.tools.upload_key_inspection_peak())
            .is_some_and(|(retained, growing)| wire::inspection_peak_fits(retained, growing))
        {
            self.fail(AdmissionFailure::Bounds, owner);
            return Err(wire::unavailable());
        }
        let result = self.tools.inspect_upload_key_once(
            self.control.admitted,
            self.control.work,
            self.control.hard,
            self.control.data().local_first,
            &stop,
        );
        if let Err(issue) = result {
            self.fail(android_lease_admission_issue(issue), owner);
            return Err(wire::unavailable());
        }
        // M2's native parser has returned and released its temporary input.
        // Preserve every actual held tool original while pricing the runtime
        // parser/tree peak BEFORE starting that next inspector.
        if !self
            .retained_before_tail()
            .zip(UploadKeyRuntimeSlots::upload_key_inspection_peak())
            .is_some_and(|(retained, growing)| wire::inspection_peak_fits(retained, growing))
        {
            self.fail(AdmissionFailure::Bounds, owner);
            return Err(wire::unavailable());
        }
        if let Err(issue) = self.runtime.bind_upload_key_inspection() {
            self.fail(issue, owner);
            return Err(wire::unavailable());
        }
        if let Err(issue) = self.runtime.arm_acl_once(owner.clocks.work, &stop) {
            self.fail(issue, owner);
            return Err(wire::unavailable());
        }
        let selected =
            match runtime.resolve_upload_key_installed(&mut self.runtime, owner.clocks.work, &stop)
            {
                Ok(selected) => selected,
                Err(error) => {
                    self.fail(AdmissionFailure::Inventory, owner);
                    return Err(error);
                }
            };
        self.selection = Some(VerifiedRuntime {
            python: selected.python.clone(),
            bootstrap: selected.bootstrap.clone(),
            core: selected.core.clone(),
            cwd: selected.cwd.clone(),
        });
        self.phase = NativePhase::Ready;
        let Some(measured) = self.retained_before_tail() else {
            self.fail(AdmissionFailure::Bounds, owner);
            return Err(wire::unavailable());
        };
        owner
            .upload_key
            .native_bytes
            .store(measured, Ordering::SeqCst);
        Ok(selected)
    }
    fn selected(&self, expected: &VerifiedRuntime) -> Result<(), AdmissionFailure> {
        if self.phase != NativePhase::Ready
            || self.first_failure().is_some()
            || self.settlement_started
            || self.control.stopped()
        {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        let actual = self.selection.as_ref().ok_or(AdmissionFailure::Unknown)?;
        if (&actual.python, &actual.bootstrap, &actual.core, &actual.cwd)
            != (
                &expected.python,
                &expected.bootstrap,
                &expected.core,
                &expected.cwd,
            )
        {
            return Err(AdmissionFailure::Identity);
        }
        Ok(())
    }
    pub(in crate::saved_command_owner) fn request(
        &self,
        owner: &Session,
        runtime: &VerifiedRuntime,
    ) -> Result<Vec<u8>, BridgeError> {
        self.selected(runtime).map_err(|_| wire::invalid())?;
        let intent = owner.upload_key.intent.as_ref().ok_or_else(wire::invalid)?;
        if !intent.preparation.current() {
            return Err(wire::invalid());
        }
        let tool = self
            .tools
            .upload_key_binding_data()
            .map_err(|_| wire::invalid())?;
        let clock = self.control.data();
        let raw = clock
            .failure
            .filter(|c| !clock.unknown && !c.unknown && c.first.is_none())
            .ok_or_else(wire::invalid)?;
        if raw.original.role != Role::GenerateUploadKey || !raw.original.valid() {
            return Err(wire::invalid());
        }
        let bytes = wire::request(
            &owner.id,
            &owner.generation,
            &intent.preparation.context,
            &owner.project,
            &tool,
            raw.original.work,
            raw.original.hard,
        )?;
        intent.receive.bind_request(&bytes)?;
        Ok(bytes)
    }
    pub(in crate::saved_command_owner) fn settle_observations(
        &mut self,
        used: bool,
        owner: &Session,
    ) -> AndroidObservations {
        owner.upload_key.native_bytes.store(0, Ordering::SeqCst);
        if self.settlement_started
            || self.phase == NativePhase::Claimed && !used && !self.runtime.no_child_effect()
        {
            return AndroidObservations::unknown();
        }
        self.settlement_started = true;
        if self.phase == NativePhase::New
            && !used
            && self.runtime.never_started()
            && self.control.unarmed()
        {
            let bytes = self.retained_before_tail();
            self.phase = NativePhase::Settled;
            return AndroidObservations {
                entered: false,
                observations: bytes.is_some(),
                integrity: true,
                tail: None,
                retained_bytes: bytes,
            };
        }
        self.phase = NativePhase::Settling;
        owner.publish_native_failure(self.first_failure());
        let mut integrity = !used || self.first_failure().is_none();
        if used {
            let result = self
                .runtime
                .capability()
                .and_then(|c| c.check_before_settlement(&mut |f| owner.native_cleanup_expired(f)));
            if let Err(issue) = result {
                self.fail(issue, owner);
                integrity = false;
            }
            if let Err(issue) = self
                .tools
                .check_after_use(*owner.native_audit_cutoff.borrow())
            {
                self.fail(android_lease_admission_issue(issue), owner);
                integrity = false;
            }
        }
        let tools =
            self.tools
                .settle_observations(*self.cleanup.borrow(), &self.cleanup, &mut |f, t| {
                    owner.publish_native_failure(Some((f, t)))
                });
        let runtime = self
            .runtime
            .settle_originals(&mut |f| owner.native_cleanup_expired(f));
        owner.publish_native_failure(self.first_failure());
        let observations = tools == CloseOutcome::Settled
            && runtime == CloseOutcome::Settled
            && self.tools.observations_settled()
            && self.runtime.settled();
        let retained_bytes = self.retained_before_tail();
        if !observations || retained_bytes.is_none() {
            self.phase = NativePhase::Unknown;
            return AndroidObservations {
                entered: true,
                observations: false,
                integrity: false,
                tail: None,
                retained_bytes,
            };
        }
        let tail = self.tools.take_close_tail();
        self.phase = if tail.is_ok() {
            NativePhase::Settling
        } else {
            NativePhase::Unknown
        };
        match tail {
            Ok(tail) => AndroidObservations {
                entered: true,
                observations: true,
                integrity,
                tail: Some(tail),
                retained_bytes,
            },
            Err(_) => AndroidObservations {
                entered: true,
                observations: false,
                integrity: false,
                tail: None,
                retained_bytes,
            },
        }
    }
}

pub(in crate::saved_command_owner) fn spawn_original(
    inner: &Inner,
    owner: &Session,
    runtime: VerifiedRuntime,
    native: Option<Arc<Mutex<UploadKeyNativeBooks>>>,
) {
    owner.upload_key.native_bytes.store(0, Ordering::SeqCst);
    if owner.domain != SavedCommandDomain::GenerateUploadKey
        || inner.domain != owner.domain
        || !inner.qualified(None)
        || Profile::current(owner.domain) != Some(owner.profile)
    {
        inner.stop(owner, Reason::RuntimeUnavailable);
        return;
    }
    let Some(native) = native else {
        inner.stop(owner, Reason::RuntimeUnavailable);
        return;
    };
    let mut native = match native.lock() {
        Ok(native) => native,
        Err(_) => {
            inner.unknown(owner);
            return;
        }
    };
    if let Err(f) = native.selected(&runtime) {
        native.fail(f, owner);
        return;
    }
    let Some(intent) = owner.upload_key.intent.as_ref() else {
        inner.stop(owner, Reason::ContextChanged);
        return;
    };
    if !intent.preparation.current() {
        inner.stop(owner, Reason::ContextChanged);
        return;
    }
    let stop = owner.stop.subscribe();
    if let Err(f) = native.tools.check_before_spawn(owner.clocks.work, &stop) {
        native.fail(android_lease_admission_issue(f), owner);
        return;
    }
    if let Err(f) = native.runtime.transfer_once() {
        native.fail(f, owner);
        return;
    }
    let capability = match native.runtime.capability() {
        Ok(c) => c,
        Err(f) => {
            native.fail(f, owner);
            return;
        }
    };
    let selected = match capability.prepare_once_observed(owner.clocks.work, &stop, &mut |f| {
        owner.publish_native_failure(f)
    }) {
        Ok(v) => v,
        Err(_) => {
            inner.stop(owner, Reason::RuntimeUnavailable);
            return;
        }
    };
    let mut command = Command::new(&selected.python);
    command
        .args(["-I", "-S", "-B"])
        .arg(&selected.bootstrap)
        .arg(&selected.core)
        .current_dir(&selected.cwd)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    // No passwords/credential material in this helper's argv/environment.
    if crate::runtime::macos_installed_environment(&mut command).is_err() {
        capability.record_closed_spawn_gate();
        inner.stop(owner, Reason::RuntimeUnavailable);
        return;
    }
    if let Err(f) = capability
        .claim_once()
        .and_then(|()| capability.check_before_or_after_use(owner.clocks.work, &stop))
    {
        capability.record_closed_spawn_gate();
        owner.publish_native_failure(Some((f, Instant::now())));
        inner.stop(owner, Reason::RuntimeUnavailable);
        return;
    }
    let mut startup = match owner.startup.lock() {
        Ok(s) => s,
        Err(_) => {
            capability.record_closed_spawn_gate();
            inner.unknown(owner);
            return;
        }
    };
    let mut r = inner.lock();
    let now = Instant::now();
    inner.advance_locked(&mut r, owner, now);
    if !original_session(&r, owner)
        || r.disabled
        || r.exhausted
        || r.stopping
        || r.document_lost
        || *owner.stop.borrow()
        || now >= owner.clocks.work
    {
        capability.record_closed_spawn_gate();
        return;
    }
    if startup.attempted || startup.returned || startup.failed || startup.child.is_some() {
        capability.record_closed_spawn_gate();
        inner.unknown_locked(&mut r, owner);
        return;
    }
    // The password GO remains a later, durably reserved, fixed original writer
    // phase. Even helper spawn is ONE original claim, never repeated on error.
    startup.attempted = true;
    drop(r);
    native.phase = NativePhase::Claimed;
    match command.spawn() {
        Ok(child) => {
            startup.child = Some(child);
            startup.returned = true;
            if let Some(bytes) = native.retained_before_tail().filter(|n| *n > 0) {
                owner.upload_key.native_bytes.store(bytes, Ordering::SeqCst);
            } else {
                drop(startup);
                inner.stop(owner, Reason::ResourcesUnavailable);
            }
        }
        Err(_) => {
            startup.failed = true;
            owner.resource_unknown.store(true, Ordering::SeqCst);
            drop(startup);
            inner.stop(owner, Reason::RuntimeUnavailable);
            inner.unknown(owner);
        }
    }
}
