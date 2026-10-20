//! Original macOS runtime/source/cache custody for the fixed acquisition facet.
//! Every effect below is on the saved owner's registered blocking worker. The
//! cache tail runs only AFTER actual child/pipe/driver/manager/runtime joins.
use super::*;
use crate::installed_runtime::{ToolAcquisitionRuntimeSlots, AndroidRegistrationSourceSlots};
use wire::components::Partition;

pub(in crate::saved_command_owner) struct Original {
    runtime: ToolAcquisitionRuntimeSlots,
    pub(super) cache: cache::Book,
    selected: Option<VerifiedRuntime>,
    request: Option<Vec<u8>>,
    runtime_closed: bool,
    sources: Option<AndroidRegistrationSourceSlots>,
    picked: Option<(Partition, [u8; 32])>,
    sdk_copy: Option<wire::sdk::CopyInput>,
    unknown: bool,
}
impl Original {
    pub(super) fn new() -> Self {
        Self {
            runtime: ToolAcquisitionRuntimeSlots::new(),
            cache: cache::Book::new(),
            selected: None,
            request: None,
            runtime_closed: false,
            sources: None,
            picked: None,
            sdk_copy: None,
            unknown: false,
        }
    }
    pub(super) fn interrupted(&mut self) {
        self.unknown = true;
        self.runtime.mark_interrupted();
        self.cache.interrupted();
    }
    pub(super) fn settled(&self) -> bool {
        !self.unknown
            && self.runtime_closed
            && self.runtime.settled()
            && self.cache.settled()
            && self.sources.as_ref().is_none_or(|source| source.settled())
            && self.request.is_none()
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        if self.unknown {
            return None;
        }
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(self.runtime.retained_bytes()?)?
            .checked_add(self.cache.retained_bytes()?)?;
        if let Some(v) = &self.selected {
            for path in [&v.python, &v.bootstrap, &v.core, &v.cwd] {
                bytes = bytes.checked_add(path.capacity())?;
            }
        }
        if let Some(request) = &self.request {
            bytes = bytes.checked_add(request.capacity())?;
        }
        if let Some(source) = &self.sources { bytes = bytes.checked_add(source.retained_bytes()?)?; }
        if let Some(copy) = &self.sdk_copy { bytes = bytes.checked_add(copy.retained_bytes()?)?; }
        Some(bytes)
    }
    fn inspect_picked(&mut self, inner: &Arc<Inner>, owner: &Arc<Session>) -> Result<(), BridgeError> {
        let intent = owner.tools.intent.as_ref().ok_or_else(wire::invalid)?;
        let Context::ToolAcquisition(context) = &owner.context else { return Err(wire::invalid()); };
        if self.sources.is_some() || self.picked.is_some()
            || !intent.known.sources.matches_project(&context.project_id, owner.registration, &owner.project)
            || !intent.known.sources.originals_settled() || !context_current(inner, owner) { return Err(wire::invalid()); }
        if intent.known.catalog.empty().is_none() { return Ok(()); } // Existing selected protected tuple wins.
        if !intent.known.sources.has_picks() {
            self.picked = Some((Partition::missing_all(), [0; 32]));
            return Ok(());
        }
        let Profile::ToolAcquisition(profile) = owner.profile else { return Err(wire::invalid()); };
        let reservation = AndroidRegistrationSourceSlots::acquisition_reservation(profile.android()).ok_or_else(wire::invalid)?;
        let bound = reservation.acquisition_retained_bytes().ok_or_else(wire::invalid)?;
        let future = picked::future_bytes(&intent.known).ok_or_else(wire::invalid)?;
        // Include the original's already-retained empty runtime/cache/cells in
        // the SAME future reservation before reserving the full read peak.
        if self.retained_bytes().and_then(|bytes| bytes.checked_add(reservation.bytes()))
            .is_none_or(|bytes| bytes > future) {
            return Err(wire::invalid());
        }
        // Retain the actual original BEFORE its first allocation/native IO. The
        // same registered inspection task performs reads AND consuming closes.
        self.sources = Some(AndroidRegistrationSourceSlots::new_acquisition(owner.native_audit_cutoff.subscribe(),
            picked::SourceGate::new(inner, owner), reservation));
        let source = self.sources.as_mut().ok_or_else(wire::invalid)?;
        let result = source.acquisition_once(intent.known.sources.roots(), owner.clocks.work, &owner.stop.subscribe(),
            &mut |failure, at| owner.publish_native_failure(Some((failure, at))));
        let closed = source.settle_originals(&mut |first| owner.native_cleanup_expired(first));
        if closed != crate::installed_runtime::CloseOutcome::Settled || !source.settled() {
            self.unknown = true;
            return Err(BridgeError::cleanup_unknown());
        }
        result.map_err(|_| wire::invalid())?;
        if source.retained_bytes().is_none_or(|bytes| bytes > bound)
            || !intent.known.sources.originals_settled() || !context_current(inner, owner) { return Err(wire::invalid()); }
        self.picked = Some(source.acquisition_finding().ok_or_else(wire::invalid)?);
        if context.action == wire::Action::Acquire {
            if let Some(root) = intent.known.sources.roots()[1].as_ref() {
                // Same actually closed original records; a child will open NEW
                // read-only originals. No renderer path or revived native loan.
                self.sdk_copy = source.acquisition_sdk_copy_input(root).map_err(|_| wire::invalid())?;
            }
            if self.sdk_copy.as_ref().map(|copy| copy.component)
                != wire::sdk::Component::for_partition(self.picked.ok_or_else(wire::invalid)?.0) {
                return Err(wire::invalid());
            }
        }
        Ok(())
    }
    fn picked_finding(&self) -> Option<(Partition, [u8; 32])> {
        if self.unknown || !self.settled() { return None; }
        let finding = self.picked?;
        match &self.sources {
            Some(source) if source.acquisition_finding() == Some(finding) => Some(finding),
            None if finding == (Partition::missing_all(), [0; 32]) => Some(finding),
            _ => None,
        }
    }
    fn runtime_failure(&self, owner: &Session, returned: Option<AdmissionFailure>) {
        publish_macos_returned_failure(returned, || self.runtime.first_failure(), &mut |first| {
            owner.publish_native_failure(first)
        });
    }
    fn cache_failure(&mut self, owner: &Session, reason: wire::Reason) {
        self.cache.note(reason);
        publish_cache(owner, self.cache.first());
        if matches!(reason, wire::Reason::Unknown | wire::Reason::CleanupUnknown) {
            self.unknown = true;
        }
    }
}
fn publish_cache(owner: &Session, first: Option<(wire::Reason, Instant)>) {
    if let Some((reason, at)) = first {
        owner.observe_failure_at(
            Reason::from_tools(reason),
            at,
            matches!(reason, wire::Reason::Unknown | wire::Reason::CleanupUnknown),
        );
    }
}
fn stopped(owner: &Session) -> bool {
    *owner.stop.borrow()
        || owner.resource_unknown.load(Ordering::SeqCst)
        || Instant::now() >= owner.clocks.work
}
fn cleanup_expired(owner: &Session) -> bool {
    owner.native_cleanup_expired(None)
}
fn claim_clear(inner: &Inner, r: &super::super::Registry, owner: &Session) -> bool {
    let now = Instant::now();
    inner.tool_acquisition_selected()
        && owner.domain == SavedCommandDomain::ToolAcquisition
        && Profile::current(owner.domain) == Some(owner.profile)
        && final_clock_clear(r, owner, now)
        && !r.stopping
        && !r.document_lost
        && !inner.poisoned.load(Ordering::SeqCst)
        && !stopped(owner)
}
pub(super) fn context_current(inner: &Inner, owner: &Session) -> bool {
    owner
        .tools
        .intent
        .as_ref()
        .is_some_and(|intent| intent.current())
        && claim_clear(inner, &inner.lock(), owner)
}
/// Frozen read-only DATA from an already actually joined source producer.
/// No filesystem IO/continuing lease is claimed at this comparison boundary.
pub(super) fn picked_finding(owner: &Session) -> Option<(Partition, [u8; 32])> {
    if !original_joined(owner) { return None; }
    let resources = owner.resources.try_lock().ok()?;
    let original = resources.tools.original.as_ref()?.try_lock().ok()?;
    original.picked_finding()
}
fn copy_runtime(v: &VerifiedRuntime) -> VerifiedRuntime {
    VerifiedRuntime {
        python: v.python.clone(),
        bootstrap: v.bootstrap.clone(),
        core: v.core.clone(),
        cwd: v.cwd.clone(),
    }
}
fn same_runtime(a: &VerifiedRuntime, b: &VerifiedRuntime) -> bool {
    a.python == b.python && a.bootstrap == b.bootstrap && a.core == b.core && a.cwd == b.cwd
}
fn permits(profile: wire::Profile, inspection: &Inspection) -> bool {
    let Some(result) = &inspection.terminal.result else {
        return false;
    };
    let Ok(raw) = crate::edit_protocol::bounded(&result["requirements"], wire::CONTROL_LIMIT)
    else {
        return false;
    };
    let Ok((_, requirements)) = crate::tool_preparation_protocol::requirements(&raw) else {
        return false;
    };
    let Some(policies) = crate::android_supplier_macos::preparation_policies_for(profile.android())
    else {
        return false;
    };
    if policies.len() != 1 {
        return false;
    }
    policies.into_iter().any(|p| {
        crate::tool_preparation::Policy {
            host: crate::tool_preparation_adapters::current_host(),
            versions: crate::tool_preparation::Versions {
                jdk_vendor: p.versions.jdk_vendor,
                jdk: p.versions.jdk_version,
                gradle: p.versions.gradle_version,
                agp: p.versions.agp_version,
                sdk_platform: p.versions.sdk_platform,
                sdk_build_tools: p.versions.sdk_build_tools_version,
            },
            distribution: crate::tool_preparation::Distribution {
                url: p.distribution_url.into(),
                sha256: p.distribution_sha256.into(),
            },
        }
        .permits(&requirements)
    })
}
fn origins(intent: &Intent) -> Result<(Vec<cache::Origin>, Option<cache::Witness>), BridgeError> {
    if intent.producers.len() >= MAX_PRODUCERS {
        return Err(wire::invalid());
    }
    let mut values = Vec::new();
    let mut witness = None;
    for producer in &intent.producers {
        if !original_joined(producer) {
            return Err(BridgeError::cleanup_unknown());
        }
        let r = producer
            .resources
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let original = r
            .tools
            .original
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let (origin, current) = original
            .cache
            .origin()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if witness
            .as_ref()
            .is_some_and(|prior| !cache::same_witness(prior, &current))
        {
            return Err(BridgeError::cleanup_unknown());
        }
        witness = Some(current);
        values.push(origin);
    }
    Ok((values, witness))
}
pub(super) fn inspect(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    original: &Arc<Mutex<Original>>,
    runtime: &RuntimeConfig,
) -> Result<VerifiedRuntime, BridgeError> {
    if !context_current(inner, owner) {
        return Err(owner.domain.unavailable());
    }
    let Context::ToolAcquisition(context) = &owner.context else {
        return Err(wire::invalid());
    };
    let Profile::ToolAcquisition(profile) = owner.profile else {
        return Err(wire::invalid());
    };
    let intent = owner.tools.intent.as_ref().ok_or_else(wire::invalid)?;
    // The current selected protected tuple is read-only reuse. Do not even
    // arm a CA loan or touch a cache namespace for that inspection's selection.
    if !intent.known.catalog.permits_action(context.action) {
        return Err(wire::invalid());
    }
    let mut original = original
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    // Fresh same-picker proof precedes CA/cache intent/network admission. A
    // selected present-but-wrong tree refuses; it never becomes "missing".
    original.inspect_picked(inner, owner)?;
    if context.action == wire::Action::Acquire {
        let inspection = intent.inspection.as_ref().ok_or_else(wire::invalid)?;
        let parts = original.picked.ok_or_else(wire::invalid)?;
        if !inspection.matches(context, owner.registration, &owner.project) || !permits(profile, inspection)
            || !parts.0.needs_download() || picked_finding(&inspection.original) != Some(parts)
            || inspection.terminal.components() != Some(parts.0) { return Err(wire::invalid()); }
        let armed = original.runtime.arm_public_ca_once();
        original.runtime_failure(owner, armed.as_ref().err().copied());
        armed.map_err(|_| owner.domain.unavailable())?;
    }
    let stop = owner.stop.subscribe();
    let armed = original.runtime.arm_acl_once(owner.clocks.work, &stop);
    original.runtime_failure(owner, armed.as_ref().err().copied());
    armed.map_err(|_| owner.domain.unavailable())?;
    let selected =
        runtime.resolve_tool_acquisition_installed(&mut original.runtime, owner.clocks.work, &stop);
    original.runtime_failure(
        owner,
        selected.as_ref().err().map(|_| AdmissionFailure::Native),
    );
    let selected = selected?;
    if let Err(reason) = original.cache.arm(&mut || stopped(owner)) {
        original.cache_failure(owner, reason);
        return Err(owner.domain.unavailable());
    }
    if original
        .runtime
        .retained_original_count()
        .is_none_or(|n| n == 0)
        || original
            .retained_bytes()
            .is_none_or(|n| picked::future_bytes(&intent.known).is_none_or(|bound| n > bound))
    {
        original.cache_failure(owner, wire::Reason::Limit);
        return Err(wire::invalid());
    }
    // Prepare all private input under this SAME registered worker, not on a UI
    // thread or under Registry. Raw manifest/CA temporaries are then discarded.
    let prepared = (|| -> Result<Vec<u8>, wire::Reason> {
        if context.action == wire::Action::Inspect {
            return wire::request(
                &owner.id,
                &owner.generation,
                context,
                profile,
                &owner.project,
                &selected.cwd,
                None,
                None,
                None,
            )
            .map_err(|_| wire::Reason::Input);
        }
        let components = original.picked.ok_or(wire::Reason::Stale)?.0;
        let inspection = intent.inspection.as_ref().ok_or(wire::Reason::Stale)?;
        if !inspection.matches(context, owner.registration, &owner.project)
            || !permits(profile, inspection)
        {
            return Err(wire::Reason::Unsupported);
        }
        let footprint = inspection.footprint().map_err(|_| wire::Reason::Input)?;
        original
            .cache
            .capture_sources(&owner.project, &footprint, &mut || stopped(owner))?;
        let projection = crate::android_supplier_macos::acquisition::for_profile(profile.android())
            .ok_or(wire::Reason::Unsupported)?;
        if projection.profile != profile.android() {
            return Err(wire::Reason::Unsupported);
        }
        let public_ca = original
            .runtime
            .public_ca(owner.clocks.work, &stop)
            .map_err(|failure| {
                owner.publish_native_failure(Some((failure, Instant::now())));
                wire::Reason::RuntimeUnavailable
            })?;
        let (known, witness) = origins(intent).map_err(|_| wire::Reason::RecoveryRequired)?;
        // Hashes compare the actual current native inputs. They are not grants.
        let context_raw=crate::edit_protocol::bounded(&json!({"context":context,"profile":profile,"projectRegistration":owner.registration,
            "projectRoot":wire::native_path(&owner.project.path),"rootIdentity":owner.project.identity.posix().map_err(|_|wire::Reason::Input)?.preflight_identity(),
            "catalogGeneration":intent.known.catalog.generation(),"ownerRevision":intent.known.revision,
            "sourceGeneration":intent.known.source_generation,"registrationGeneration":intent.known.registration_generation,
            "components":components.data(),"pickedObservationSha256":hash(&original.picked.ok_or(wire::Reason::Stale)?.1),
            "sdkCopy":original.sdk_copy.as_ref().map(|copy|copy.data())}),wire::CONTROL_LIMIT).map_err(|_|wire::Reason::Limit)?;
        let expected = Expected {
            components,
            copied_sdk: original.sdk_copy.as_ref().map(|copy| copy.component),
            context_sha256: hash(&context_raw),
            reference_sha256: projection
                .reference_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            projection_sha256: projection
                .projection_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        };
        let pending = wire::intent_bytes(
            &owner.id,
            intent.generation,
            profile,
            &expected.context_sha256,
            &expected.reference_sha256,
            &expected.projection_sha256,
            components,
        )
        .map_err(|_| wire::Reason::Limit)?;
        let location = inner
            .tool_acquisition
            .get()
            .ok_or(wire::Reason::Unsupported)?
            .location
            .clone();
        // Complete declared known-set and exact source footprint rechecked
        // before any durable cache intent. This is not a whole-computer scan.
        if !context_current(inner, owner) {
            return Err(wire::Reason::Stale);
        }
        original.cache.prepare_cache(
            location,
            intent.document.roots(),
            witness.as_ref(),
            &known,
            &owner.id,
            pending,
            &mut || context_current(inner, owner),
            &mut || stopped(owner),
        )?;
        if !context_current(inner, owner) {
            return Err(wire::Reason::Stale);
        }
        let mut cache = original.cache.cache_data(
            u64::from(intent.generation),
            &expected.context_sha256,
            &expected.reference_sha256,
            &expected.projection_sha256,
            components,
        )?;
        if let Some(copy) = &original.sdk_copy {
            cache.as_object_mut().ok_or(wire::Reason::Input)?.insert("sdkCopy".into(),copy.data());
        }
        let bytes = wire::request(
            &owner.id,
            &owner.generation,
            context,
            profile,
            &owner.project,
            &selected.cwd,
            Some(&cache),
            Some(&projection.bytes),
            Some(&public_ca),
        )
        .map_err(|_| wire::Reason::Limit)?;
        let mut slot = owner
            .tools
            .expected
            .try_lock()
            .map_err(|_| wire::Reason::CleanupUnknown)?;
        if slot.is_some() {
            return Err(wire::Reason::AlreadyUsed);
        }
        *slot = Some(expected);
        Ok(bytes)
    })();
    let request = match prepared {
        Ok(bytes) => bytes,
        Err(reason) => {
            original.cache_failure(owner, reason);
            return Err(owner.domain.unavailable());
        }
    };
    if original.request.is_some() || original.selected.is_some() {
        original.interrupted();
        return Err(BridgeError::cleanup_unknown());
    }
    original.request = Some(request);
    original.selected = Some(copy_runtime(&selected));
    Ok(selected)
}
pub(super) fn request(
    owner: &Session,
    book: &super::super::Resources,
    context: &wire::Context,
    profile: wire::Profile,
    runtime: &VerifiedRuntime,
) -> Result<Vec<u8>, BridgeError> {
    if owner.context != Context::ToolAcquisition(context.clone())
        || owner.profile != Profile::ToolAcquisition(profile)
        || !book.inspection_joined
        || book.inspection_failed
        || book.inspection.is_some()
    {
        return Err(wire::invalid());
    }
    let original = book.tools.original.as_ref().ok_or_else(wire::invalid)?;
    let mut original = original
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if original
        .selected
        .as_ref()
        .is_none_or(|v| !same_runtime(v, runtime))
        || original.unknown
        || original.runtime_closed
    {
        return Err(wire::invalid());
    }
    original.request.take().ok_or_else(wire::invalid)
}
pub(super) fn transfer(
    book: &super::super::Resources,
    inner: &Inner,
    owner: &Session,
) -> Result<(), BridgeError> {
    if !book.tools.selected
        || !book.inspection_started
        || !book.inspection_joined
        || book.inspection_failed
        || book.inspection.is_some()
        || book.inspection_error.is_some()
        || book.acquisition_started
        || book.acquisition_joined
        || book.acquisition_failed
        || book.acquisition.is_some()
        || book.acquisition_error.is_some()
    {
        return Err(BridgeError::cleanup_unknown());
    }
    if !context_current(inner, owner) {
        return Err(wire::invalid());
    }
    let original = book.tools.original.as_ref().ok_or_else(wire::invalid)?;
    let mut original = original
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if original.request.is_some() || original.unknown || original.runtime_closed {
        return Err(wire::invalid());
    }
    let transferred = original.runtime.transfer_once();
    original.runtime_failure(owner, transferred.as_ref().err().copied());
    transferred.map_err(|_| wire::invalid())
}
pub(super) fn acquire(inner: &Inner, owner: &Session, original: &Arc<Mutex<Original>>) {
    if !context_current(inner, owner) {
        inner.stop(owner, Reason::ContextChanged);
        return;
    }
    let mut original = match original.try_lock() {
        Ok(o) => o,
        _ => {
            inner.unknown(owner);
            return;
        }
    };
    if let Err(reason) = original.cache.check_before_use(&mut || stopped(owner)) {
        original.cache_failure(owner, reason);
        return;
    }
    let stop = owner.stop.subscribe();
    let capability = match original.runtime.capability() {
        Ok(c) => c,
        Err(f) => {
            owner.publish_native_failure(Some((f, Instant::now())));
            return;
        }
    };
    let selected = match capability.prepare_once_observed(owner.clocks.work, &stop, &mut |first| {
        owner.publish_native_failure(first)
    }) {
        Ok(v) => v,
        Err(f) => {
            owner.publish_native_failure(Some((f, Instant::now())));
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
    if let Err(failure) = capability.claim_once() {
        owner.publish_native_failure(Some((failure, Instant::now())));
        return;
    }
    if crate::runtime::macos_installed_environment(&mut command).is_err() {
        capability.record_closed_spawn_gate();
        inner.stop(owner, Reason::RuntimeUnavailable);
        return;
    }
    if let Err(failure) = capability.check_before_or_after_use(owner.clocks.work, &stop) {
        capability.record_closed_spawn_gate();
        owner.publish_native_failure(Some((failure, Instant::now())));
        return;
    }
    // Runtime preparation can perform bounded native inspection. Recheck the
    // SAME held source/cache footprint afterwards, immediately before GO.
    if let Err(reason) = original.cache.check_before_use(&mut || stopped(owner)) {
        if let Ok(capability) = original.runtime.capability() {
            capability.record_closed_spawn_gate();
        }
        original.cache_failure(owner, reason);
        return;
    }
    let capability = match original.runtime.capability() {
        Ok(c) => c,
        Err(f) => {
            owner.publish_native_failure(Some((f, Instant::now())));
            return;
        }
    };
    // An explicit last currentness check covers the original native catalogue,
    // selected-source absence and registration generations, not private JSON.
    if !owner.tools.intent.as_ref().is_some_and(|i| i.current()) {
        capability.record_closed_spawn_gate();
        inner.stop(owner, Reason::ContextChanged);
        return;
    }
    let mut startup = match owner.startup.try_lock() {
        Ok(v) => v,
        _ => {
            capability.record_closed_spawn_gate();
            inner.unknown(owner);
            return;
        }
    };
    let mut r = inner.lock();
    inner.advance_locked(&mut r, owner, Instant::now());
    if !claim_clear(inner, &r, owner) {
        capability.record_closed_spawn_gate();
        return;
    }
    if startup.attempted || startup.returned || startup.failed || startup.child.is_some() {
        capability.record_closed_spawn_gate();
        inner.unknown_locked(&mut r, owner);
        return;
    }
    startup.attempted = true;
    drop(r);
    match command.spawn() {
        Ok(child) => {
            startup.child = Some(child);
            startup.returned = true;
        }
        Err(_) => {
            startup.failed = true;
            original.interrupted();
            drop(startup);
            inner.stop(owner, Reason::RuntimeUnavailable);
            inner.unknown(owner);
        }
    }
}
fn consumers_returned(
    book: &super::super::Resources,
    inner: &Inner,
    owner: &Session,
    original: &Original,
) -> bool {
    let Ok(startup) = owner.startup.try_lock() else {
        return false;
    };
    let r = inner.lock();
    offline_consumers_returned(book,&startup,original.runtime.no_child_effect())&&original_session(&r,owner)
        &&(!startup.attempted||r.active.as_ref().is_some_and(|a|a.accepted&&a.terminal
            &&matches!(a.projection.result.as_ref(),Some(Terminal::ToolAcquisition(t)) if t.lifetime.settled())))
}
pub(super) async fn settle_runtime(
    book: &mut super::super::Resources,
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
) {
    let Some(original) = book.tools.original.clone() else {
        inner.unknown(owner);
        return;
    };
    if !book.tools.runtime_started {
        let ready = original
            .try_lock()
            .is_ok_and(|o| consumers_returned(book, inner, owner, &o));
        if !book.tools.selected || !ready {
            inner.unknown(owner);
            return;
        }
        let original = original.clone();
        let operation = owner.clone();
        let (go, enter) = oneshot::channel();
        book.tools.runtime_started = true;
        book.tools.runtime_task = Some(tokio::task::spawn_blocking(move || {
            if enter.blocking_recv().is_err() {
                return false;
            }
            let mut o = match original.lock() {
                Ok(o) => o,
                Err(e) => {
                    let mut o = e.into_inner();
                    o.interrupted();
                    o
                }
            };
            let post = if o.runtime.no_child_effect() {
                Ok(())
            } else {
                o.runtime.capability().and_then(|c| {
                    c.check_before_settlement(&mut |first| operation.native_cleanup_expired(first))
                })
            };
            if let Err(failure) = post {
                operation.publish_native_failure(Some((failure, Instant::now())));
            }
            let closed = o
                .runtime
                .settle_originals(&mut |first| operation.native_cleanup_expired(first));
            o.runtime_closed = closed == CloseOutcome::Settled;
            // No cache receipt yet. This is only the actual runtime close tail.
            post.is_ok() && o.runtime_closed && o.runtime.settled() && !o.unknown
        }));
        let _ = go.send(());
    }
    if !book.tools.runtime_joined && !book.tools.runtime_failed {
        if book.tools.runtime_task.is_none() {
            inner.unknown(owner);
            return;
        }
        let result = join_with_clock(&mut book.tools.runtime_task, inner, owner).await;
        let joined = result.is_ok();
        if book.tools.runtime_return.is_some() {
            book.tools.runtime_failed = true;
        } else {
            book.tools.runtime_return = Some(result);
            book.tools.runtime_joined = joined;
            book.tools.runtime_failed = !joined;
        }
        if joined {
            book.tools.runtime_task.take();
        } else {
            worker_lost(book, owner);
        }
    }
    if !book.tools.runtime_joined() {
        owner.resource_unknown.store(true, Ordering::SeqCst);
        inner.unknown(owner);
    }
}
fn joined_before_cache(
    inner: &Inner,
    owner: &Session,
    book: &super::super::Resources,
    original: &Original,
) -> bool {
    owner.driver_joined.load(Ordering::SeqCst)
        && !owner.driver_failed.load(Ordering::SeqCst)
        && !owner.manager_failed.load(Ordering::SeqCst)
        && owner
            .driver_return
            .try_lock()
            .is_ok_and(|r| matches!(r.as_ref(), Some(Ok(()))))
        && owner
            .manager_return
            .try_lock()
            .is_ok_and(|r| matches!(r.as_ref(), Some(Ok(()))))
        && !owner.resource_unknown.load(Ordering::SeqCst)
        && book.tools.runtime_joined()
        && original.runtime_closed
        && original.runtime.settled()
        && consumers_returned(book, inner, owner, original)
}
pub(super) async fn settle_cache_after_manager(inner: &Arc<Inner>, owner: &Arc<Session>) {
    // This entry is called from observe_final only AFTER it actually joined
    // manager/driver. It deliberately does not require overall native_final:
    // the original cache lease/ACL/FD tail has not joined yet.
    let mut book = owner.resources.lock().await;
    let Some(original) = book.tools.original.clone() else {
        inner.unknown(owner);
        return;
    };
    if !book.tools.tail_started {
        let ready = original
            .try_lock()
            .is_ok_and(|o| joined_before_cache(inner, owner, &book, &o));
        if !ready {
            inner.unknown(owner);
            return;
        }
        let inspect = {
            let r = inner.lock();
            r.active
                .as_ref()
                .filter(|a| Arc::ptr_eq(&a.owner, owner))
                .and_then(|a| match &a.projection.result {
                    Some(Terminal::ToolAcquisition(t))
                        if t.context.action == wire::Action::Inspect
                            && t.outcome == wire::Outcome::Complete =>
                    {
                        t.result
                            .as_ref()
                            .and_then(|v| wire::footprint(&v["footprint"]).ok())
                    }
                    _ => None,
                })
        };
        let original = original.clone();
        let operation = owner.clone();
        let (go, enter) = oneshot::channel();
        book.tools.tail_started = true;
        book.tools.tail = Some(tokio::task::spawn_blocking(move || {
            if enter.blocking_recv().is_err() {
                return false;
            }
            let mut o = match original.lock() {
                Ok(o) => o,
                Err(e) => {
                    let mut o = e.into_inner();
                    o.interrupted();
                    o
                }
            };
            // Runtime/task/IO joins are original checked above. Now source POST,
            // durable settlement publication, one-close FD/ACL tail, then join.
            let post = (|| -> Result<(), wire::Reason> {
                if let Some(footprint) = inspect {
                    o.cache
                        .capture_sources(&operation.project, &footprint, &mut || {
                            cleanup_expired(&operation)
                        })?;
                }
                if !operation.tools.intent.as_ref().is_some_and(|i| i.current()) {
                    return Err(wire::Reason::Stale);
                }
                o.cache
                    .check_before_use(&mut || cleanup_expired(&operation))?;
                // An already failed acquisition/cache write is not repaired by
                // successful unrelated runtime cleanup or an absent target.
                if o.cache.first().is_none() {
                    o.cache
                        .record_settled(&mut || cleanup_expired(&operation))?;
                }
                o.cache
                    .post_application(&mut || cleanup_expired(&operation))?;
                Ok(())
            })();
            if let Err(reason) = post {
                o.cache_failure(&operation, reason);
            }
            // The writer has joined; any unused request is now safe to retire.
            o.request.take();
            let closed = o.cache.release(&mut || cleanup_expired(&operation));
            if !closed {
                o.unknown = true;
            }
            post.is_ok() && closed && o.settled()
        }));
        let _ = go.send(());
    }
    if !book.tools.tail_joined && !book.tools.tail_failed {
        if book.tools.tail.is_none() {
            inner.unknown(owner);
            return;
        }
        let result = join_with_clock(&mut book.tools.tail, inner, owner).await;
        let joined = result.is_ok();
        if book.tools.tail_return.is_some() {
            book.tools.tail_failed = true;
        } else {
            book.tools.tail_return = Some(result);
            book.tools.tail_joined = joined;
            book.tools.tail_failed = !joined;
        }
        if joined {
            book.tools.tail.take();
        } else {
            worker_lost(&book, owner);
        }
    }
    if !book.tools.tail_joined() {
        owner.resource_unknown.store(true, Ordering::SeqCst);
        inner.unknown(owner);
    }
}
