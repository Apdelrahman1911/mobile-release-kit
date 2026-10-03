//! Android's original source selections share the asset picker/coordinator.
//! Registry stores the SAME OriginalWork, not a second native or cleanup owner.
use super::*;
use crate::{android_tool_sources as wire, asset_session::OriginalWork};

/// Exactly the existing three public roles, with no heap-node census guess.
struct SelectedSet([(wire::Role, Option<Selected>); 3]);
impl SelectedSet {
    fn new() -> Self { Self([(wire::Role::Jdk, None), (wire::Role::Sdk, None), (wire::Role::Gradle, None)]) }
    fn iter(&self) -> impl Iterator<Item = (&wire::Role, &Selected)> {
        self.0.iter().filter_map(|(role, value)| value.as_ref().map(|value| (role, value)))
    }
    fn get(&self, role: wire::Role) -> Option<&Selected> { self.0.iter().find(|(key, _)| *key == role)?.1.as_ref() }
    fn is_empty(&self) -> bool { self.0.iter().all(|(_, value)| value.is_none()) }
    fn clear(&mut self) { for (_, value) in &mut self.0 { *value = None; } }
    fn insert(&mut self, role: wire::Role, selected: Selected) {
        let index = match role { wire::Role::Jdk => 0, wire::Role::Sdk => 1, wire::Role::Gradle => 2 };
        self.0[index].1 = Some(selected);
    }
}
/// Non-Serialize comparison/provenance snapshot, constructed only from the
/// owner's SAME selected roots and picker originals under its short lock.
pub(crate) struct SourceSnapshot {
    pub(super) project_id: String, pub(super) registration: u32,
    pub(super) project: RegisteredRoot, pub(super) generation: u32,
    roots: [RegisteredRoot; 3], originals: [Arc<OriginalWork>; 3],
}
impl SourceSnapshot {
    pub(crate) fn picker_originals(&self) -> &[Arc<OriginalWork>; 3] { &self.originals }
    pub(super) fn roots(&self) -> &[RegisteredRoot; 3] { &self.roots }
    /// Caller MUST release Document AND Registry before this actual proof.
    pub(crate) fn originals_settled(&self) -> bool {
        self.originals.iter().all(|original| original.android_source_selected_settled())
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.roots.iter().try_fold(std::mem::size_of::<Self>().checked_add(self.project_id.capacity())?
            .checked_add(self.project.path.capacity())?, |sum, root| sum.checked_add(root.path.capacity()))
    }
}

pub(super) struct Sources {
    generation: u32, capability: Option<Availability>, unknown: bool,
    binding: Option<(String, u32, RegisteredRoot)>, selected: SelectedSet,
    active: Option<Pick>, last: Option<wire::Operation>, phase: wire::Phase, reason: wire::Reason,
}
struct Selected { root: RegisteredRoot, original: Arc<OriginalWork> }
struct Pick { original: Arc<OriginalWork>, operation: wire::Operation, first: Option<(wire::Reason, Instant)> }
impl Default for Sources {
    fn default() -> Self { Self { generation: 0, capability: None, unknown: false, binding: None, selected: SelectedSet::new(),
        active: None, last: None, phase: wire::Phase::Idle, reason: wire::Reason::NotInspected } }
}
impl Sources {
    pub(super) fn snapshot(&self) -> Option<SourceSnapshot> {
        if self.unknown || self.active.is_some() || self.generation == 0 { return None; }
        let (project_id, registration, project) = self.binding.as_ref()?;
        let jdk = self.selected.get(wire::Role::Jdk)?;
        let sdk = self.selected.get(wire::Role::Sdk)?;
        let gradle = self.selected.get(wire::Role::Gradle)?;
        Some(SourceSnapshot { project_id: project_id.clone(), registration: *registration,
            project: project.clone(), generation: self.generation,
            roots: [jdk.root.clone(), sdk.root.clone(), gradle.root.clone()],
            originals: [jdk.original.clone(), sdk.original.clone(), gradle.original.clone()] })
    }
    pub(super) fn same_snapshot(&self, snapshot: &SourceSnapshot) -> bool {
        !self.unknown && self.active.is_none() && self.generation == snapshot.generation
            && self.binding.as_ref().is_some_and(|(project_id, registration, project)|
                project_id == &snapshot.project_id && *registration == snapshot.registration && project == &snapshot.project)
            && [wire::Role::Jdk, wire::Role::Sdk, wire::Role::Gradle].into_iter().enumerate().all(|(index, role)|
                self.selected.get(role).is_some_and(|selected| selected.root == snapshot.roots[index]
                    && Arc::ptr_eq(&selected.original, &snapshot.originals[index])))
    }
    pub(super) fn retained_data_bytes(&self) -> Option<usize> {
        // OriginalWork allocations are traversed through the Document's SAME
        // external-picker census. Only this registry's own inline/path DATA here.
        if self.unknown || self.active.is_some() { return None; }
        let mut bytes = std::mem::size_of::<Self>();
        if let Some((project_id, _, root)) = &self.binding {
            bytes = bytes.checked_add(project_id.capacity())?.checked_add(root.path.capacity())?;
        }
        self.selected.iter().try_fold(bytes, |sum, (_, selected)| sum.checked_add(selected.root.path.capacity()))
    }
    // The installation census cannot see these retained roots/original Arcs
    // through DocumentState. Empty fixed selection/None keep only control DATA.
    fn installation_custody_empty(&self) -> bool {
        !self.unknown && self.binding.is_none() && self.selected.is_empty() && self.active.is_none()
    }
    pub(super) fn busy(&self) -> bool { self.active.is_some() }
    pub(super) fn unknown(&self) -> bool { self.unknown }
    pub(super) fn registration_matches(&self, registration: u32) -> bool {
        self.binding.as_ref().is_none_or(|(_, generation, _)| *generation == registration)
    }
    // STOP records the first timestamp before waking the original. Document's
    // expire reducer consumes this exact timestamp; polling cannot renew it.
    pub(super) fn stop(&mut self, reason: wire::Reason, at: Instant) -> bool {
        let changed = !self.selected.is_empty() || self.active.is_some() || self.binding.is_some();
        self.selected.clear();
        if let Some(active) = &mut self.active {
            if active.first.is_none_or(|(_, before)| at < before) { active.first = Some((reason, at)); }
            active.original.request_android_source_stop();
            if !self.unknown { self.phase = wire::Phase::Stopping; self.reason = active.first.unwrap().0; }
        } else if changed { self.phase = wire::Phase::Refused; self.reason = reason; }
        self.binding = None;
        changed
    }
    pub(super) fn exhaust(&mut self) {
        self.stop(wire::Reason::CleanupUnknown, Instant::now());
        self.unknown = true; self.phase = wire::Phase::Unknown; self.reason = wire::Reason::CleanupUnknown;
    }
    fn same_original(&self, owner: &Arc<OriginalWork>) -> bool {
        self.active.as_ref().is_some_and(|pick| Arc::ptr_eq(&pick.original, owner))
    }
    fn status(&self, revision: u32, availability: android_wire::Availability) -> wire::Status {
        let redacted = self.unknown || matches!(availability, android_wire::Availability::DocumentLost | android_wire::Availability::Shutdown);
        wire::Status { schema_version: 1, status_revision: revision, source_generation: self.generation,
            project_id: if redacted { None } else { self.binding.as_ref().map(|(id, _, _)| id.clone()) }, availability,
            phase: self.phase, reason: self.reason,
            operation: self.active.as_ref().map(|pick| pick.operation.clone()).or_else(|| self.last.clone()),
            selections: if redacted { Vec::new() } else { self.selected.iter().map(|(role, selection)| wire::Selection {
                role: *role, display_name: wire::display_name(&selection.root.path) }).collect() },
            inspection: "not-run", protected_copy: "not-created" }
    }
}
impl SavedCommandOwner {
    /// Read-only admission precondition, not a memory/finality receipt. Called
    /// under the original Document gate: never block, reconcile, clear selected
    /// roots, borrow native books or infer empty custody from poison/contention.
    pub(crate) fn installation_source_custody_empty(&self) -> bool {
        self.inner.domain == SavedCommandDomain::AndroidBuild
            && !self.inner.poisoned.load(Ordering::SeqCst)
            && self.inner.registry.try_lock().is_ok_and(|registry| {
                !registry.disabled && !registry.exhausted && !registry.stopping
                    && !registry.document_lost && registry.android_sources.installation_custody_empty()
                    && registry.android_registration.installation_empty()
                    && self.inner.android_registration_control.empty()
            })
    }
    fn android_sources_gate(&self, registry: &Registry, gate: Availability) -> Availability {
        if registry.disabled || registry.exhausted || registry.android_sources.unknown() || registry.android_catalog.unknown()
            || registry.android_registration.unknown() || self.inner.android_registration_control.is_unknown()
            || self.inner.poisoned.load(Ordering::SeqCst) || gate == Availability::CleanupUnknown { return Availability::CleanupUnknown; }
        if registry.stopping || gate == Availability::Shutdown { return Availability::Shutdown; }
        if registry.document_lost || gate == Availability::DocumentLost { return Availability::DocumentLost; }
        if self.inner.domain != SavedCommandDomain::AndroidBuild || !cfg!(all(target_os="macos",target_arch="aarch64")) {
            return Availability::UnsupportedPlatform;
        }
        if !self.inner.android_runtime_selected(None) { return Availability::RuntimeUnqualified; }
        if registry.active.is_some() || registry.prepared.is_some() || registry.android_catalog.busy()
            || registry.android_sources.busy() || registry.android_registration.busy()
            || self.inner.android_registration_control.owns_work() || gate == Availability::Busy { return Availability::Busy; }
        gate
    }
    fn android_sources_snapshot(&self, registry: &mut Registry, gate: android_wire::Availability) -> Result<wire::Status, BridgeError> {
        let availability = self.android_sources_gate(registry, Availability::from_android(gate));
        if registry.android_sources.capability != Some(availability) {
            registry.android_sources.capability = Some(availability); self.inner.bump(registry);
        }
        if registry.exhausted || self.inner.poisoned.load(Ordering::SeqCst) { return Err(BridgeError::cleanup_unknown()); }
        let availability = availability.android();
        Ok(registry.android_sources.status(registry.revision, availability))
    }
    pub(crate) fn android_sources_status(&self, gate: android_wire::Availability) -> Result<wire::Status, BridgeError> {
        self.reconcile(); let mut registry = self.inner.lock(); self.android_sources_snapshot(&mut registry, gate)
    }
    /// The Document has already installed this inert original behind closed GO.
    /// No worker starts until its caller drops Document AND Registry, then GO.
    pub(crate) fn admit_android_source_pick(&self, document: &Arc<()>, input: &wire::Choose,
        registration: u32, project: RegisteredRoot, owner: Arc<OriginalWork>,
        publisher: &android_registration::Publisher, gate: android_wire::Availability) -> Result<(), BridgeError> {
        if !publisher.accepted() || !publisher.same_slot(&self.inner.android_registration_control) {
            self.inner.android_registration_control.poisoned(); return Err(BridgeError::cleanup_unknown());
        }
        let changed_at=publisher.at();
        let mut registry = self.inner.lock();
        if self.android_sources_gate(&registry, Availability::from_android(gate)) != Availability::Available
            || !self.inner.android_original_document_matches(Some(document)) || input.schema_version != 1
            || input.source_generation != registry.android_sources.generation { return Err(wire::unavailable()); }
        let generation = match registry.android_sources.generation.checked_add(1).filter(|next| *next < u32::MAX) {
            Some(next) => next,
            None => { registry.android_sources.exhaust(); registry.disabled = true; self.inner.bump(&mut registry); return Err(BridgeError::cleanup_unknown()); }
        };
        // These choices do not become a catalog selection. Any existing consent
        // must be deliberately prepared again after later tool registration.
        self.inner.retire_prepared(&mut registry, Reason::ContextChanged);
        registry.android_catalog.stop(crate::android_toolchain_catalog::Reason::CatalogChanged, changed_at);
        registry.android_registration.stop(crate::android_registration_app_protocol::Reason::SourceChanged,changed_at);
        let sources = &mut registry.android_sources;
        if !sources.binding.as_ref().is_some_and(|(id, current, root)| id == &input.project_id && *current == registration && root == &project) {
            sources.selected.clear();
        }
        sources.binding = Some((input.project_id.clone(), registration, project));
        sources.generation = generation;
        sources.phase = wire::Phase::Picking; sources.reason = wire::Reason::None;
        sources.active = Some(Pick { operation: wire::Operation { operation_id: owner.id, source_generation: generation, role: input.role },
            original: owner, first: None });
        self.inner.bump(&mut registry);
        if registry.exhausted { Err(BridgeError::cleanup_unknown()) } else { Ok(()) }
    }
    pub(crate) fn android_source_stop(&self, owner: &Arc<OriginalWork>) -> Option<(crate::asset_commands::Reason, Instant)> {
        use crate::asset_commands::Reason as A;
        let registry = self.inner.lock();
        registry.android_sources.active.as_ref().filter(|pick| Arc::ptr_eq(&pick.original, owner)).and_then(|pick| pick.first)
            .map(|(reason, at)| (match reason {
                wire::Reason::Cancelled => A::UserCancelled, wire::Reason::ContextChanged => A::ContextStale,
                wire::Reason::DocumentLost => A::DocumentLost, wire::Reason::Shutdown => A::Shutdown,
                wire::Reason::TimedOut => A::Deadline, wire::Reason::CleanupUnknown => A::CleanupUnknown, _ => A::SourceRefused,
            }, at))
    }
    /// Called by the actual Document publication after its positive original
    /// coordinator/child/native closes. Recheck before taking Registry, avoiding
    /// any GUI/Registry inversion. A DTO can never construct ProjectProbe.
    pub(crate) fn publish_android_source(&self, owner: &Arc<OriginalWork>, proof: crate::asset_source::ProjectProbe,
        publisher: &android_registration::Publisher) -> Result<(), BridgeError> {
        if !publisher.accepted() || !publisher.same_slot(&self.inner.android_registration_control) {
            self.inner.android_registration_control.poisoned(); return Err(BridgeError::cleanup_unknown());
        }
        if !owner.android_source_selected_settled() { return Err(BridgeError::cleanup_unknown()); }
        let mut registry = self.inner.lock();
        if self.inner.android_registration_control.is_unknown() || registry.disabled || registry.exhausted || registry.stopping || registry.document_lost
            || registry.android_sources.unknown || registry.android_registration.unknown() || registry.android_registration.busy()
            || !registry.android_sources.same_original(owner)
            || registry.android_sources.binding.is_none()
            || registry.android_sources.active.as_ref().is_some_and(|pick| pick.first.is_some()) { return Err(wire::unavailable()); }
        let pick = registry.android_sources.active.take().ok_or_else(wire::unavailable)?;
        registry.android_sources.selected.insert(pick.operation.role, Selected {
            root: RegisteredRoot { path: proof.path().to_path_buf(), identity: proof.identity() }, original: owner.clone() });
        registry.android_sources.last = Some(pick.operation);
        registry.android_sources.phase = wire::Phase::Selected; registry.android_sources.reason = wire::Reason::NotInspected;
        self.inner.bump(&mut registry);
        if registry.exhausted { Err(BridgeError::cleanup_unknown()) } else { Ok(()) }
    }
    pub(crate) fn observe_android_source(&self, owner: &Arc<OriginalWork>, phase: crate::asset_session::Phase,
        reason: crate::asset_commands::Reason, document_unknown: bool) {
        // No native/resource book is borrowed while Registry is held.
        let refused_settled = phase == crate::asset_session::Phase::Idle && owner.android_source_refusal_settled();
        let cancelled = refused_settled && reason == crate::asset_commands::Reason::UserCancelled && owner.android_source_cancel_settled();
        let mut registry = self.inner.lock();
        if !registry.android_sources.same_original(owner) { return; }
        let sources = &mut registry.android_sources;
        let before = (sources.phase, sources.reason);
        if document_unknown || phase == crate::asset_session::Phase::Unknown || sources.unknown {
            sources.unknown = true; sources.phase = wire::Phase::Unknown; sources.reason = wire::Reason::CleanupUnknown;
            sources.selected.clear();
        } else if refused_settled {
            if reason == crate::asset_commands::Reason::None {
                // A selected result must use publish_android_source, never an
                // idle bit or late worker completion as substitute publication.
                sources.unknown = true; sources.phase = wire::Phase::Unknown; sources.reason = wire::Reason::CleanupUnknown;
            } else {
                let pick = sources.active.take().unwrap(); sources.last = Some(pick.operation);
                sources.phase = if cancelled { wire::Phase::Cancelled } else { wire::Phase::Refused };
                sources.reason = if cancelled { wire::Reason::Cancelled } else if reason == crate::asset_commands::Reason::UserCancelled {
                    wire::Reason::SourceRefused
                } else { wire::reason(reason) };
            }
        } else if phase == crate::asset_session::Phase::Stopping { sources.phase = wire::Phase::Stopping; sources.reason = wire::reason(reason); }
        else if phase == crate::asset_session::Phase::Capturing { sources.phase = wire::Phase::Checking; }
        if before != (sources.phase, sources.reason) { self.inner.bump(&mut registry); }
    }
    pub(crate) fn cancel_android_source(&self, input: wire::Cancel, gate: android_wire::Availability) -> Result<wire::Status, BridgeError> {
        let mut registry = self.inner.lock();
        let sources = &mut registry.android_sources;
        let operation = sources.active.as_ref().map(|pick| &pick.operation).or(sources.last.as_ref()).ok_or_else(wire::invalid)?;
        if operation.operation_id != input.operation_id || operation.source_generation != input.source_generation { return Err(wire::invalid()); }
        if sources.active.is_some() {
            // Cancel preserves prior picked DATA. It never clears or replaces an
            // unresolved original. Context/loss/shutdown uses Sources::stop.
            let active = sources.active.as_mut().unwrap();
            let at = Instant::now();
            if active.first.is_none() { active.first = Some((wire::Reason::Cancelled, at)); }
            active.original.request_android_source_stop();
            if !sources.unknown { sources.phase = wire::Phase::Stopping; sources.reason = active.first.unwrap().0; }
            self.inner.bump(&mut registry);
        }
        self.android_sources_snapshot(&mut registry, gate)
    }
}
