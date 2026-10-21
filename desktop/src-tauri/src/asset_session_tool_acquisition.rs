//! Tool preparation uses the original Document, saved-input lane and saved
//! command owner. Comparison counters are DATA, never a new inventory grant.
use super::*;
use crate::{asset_source::RegisteredRoot, tool_acquisition_protocol as wire};

/// Constructed only below while holding the actual Document and Edit guard.
/// Retained by the SAME prepared Intent through its original native joins.
/// No renderer constructor, serialization, replacement lane or clock exists.
pub(crate) struct ToolAcquisitionDocumentInput {
    document: Weak<Inner>,
    context: wire::Context,
    registration: u32,
    root: RegisteredRoot,
    roots: Vec<RegisteredRoot>,
    saved: Arc<SavedObservationLane>,
}
impl ToolAcquisitionDocumentInput {
    pub(crate) fn source_picker_epoch(&self) -> u64 { self.saved.tool_source_epoch() }
    pub(crate) fn context(&self) -> &wire::Context {
        &self.context
    }
    pub(crate) fn roots(&self) -> &[RegisteredRoot] {
        &self.roots
    }
    /// No Document/Edit/owner Registry lock here. The original Doc admission
    /// and reciprocal gates cover mutation; the same control epoch and atomic
    /// native registration generation remain checked on the blocking worker.
    pub(crate) fn current(&self) -> bool {
        self.document.upgrade().is_some_and(|document| {
            self.saved.tool_acquisition_current(
                &document,
                self.registration,
                &self.root,
                &self.context.project_id,
            )
        })
    }
    pub(crate) fn same_document(&self, document: &Arc<()>) -> bool {
        self.document
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&original.session_identity, document))
    }
    pub(crate) fn matches(
        &self,
        context: &wire::Context,
        registration: u32,
        root: &RegisteredRoot,
    ) -> bool {
        self.context == *context
            && self.registration == registration
            && self.root == *root
            && self.current()
    }
    pub(crate) fn same_saved_binding(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.document, &other.document)
            && same_lane(&self.saved, &other.saved)
            && self.registration == other.registration
            && self.root == other.root
            && self.roots == other.roots
            && self.context.same_saved(&other.context)
            && self.current()
            && other.current()
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        // Shared backing may be conservatively charged again by Document D;
        // it must never disappear from this retained producer's T traversal.
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(self.context.project_id.capacity())?
            .checked_add(self.context.saved_config.sha256.capacity())?
            .checked_add(self.root.path.capacity())?
            .checked_add(
                self.roots
                    .capacity()
                    .checked_mul(std::mem::size_of::<RegisteredRoot>())?,
            )?
            .checked_add(std::mem::size_of::<SavedObservationLane>())?
            .checked_add(self.saved.retained_heap_bytes()?)?;
        if let Some(review) = &self.context.review {
            bytes = bytes
                .checked_add(review.operation_id.capacity())?
                .checked_add(review.owner_generation.capacity())?
                .checked_add(review.requirements_sha256.capacity())?;
        }
        for root in &self.roots {
            bytes = bytes.checked_add(root.path.capacity())?;
        }
        Some(bytes)
    }
}

fn same_lane<T>(before: &Arc<T>, current: &Arc<T>) -> bool {
    Arc::ptr_eq(before, current)
}
fn same_roster(
    original: &ToolAcquisitionDocumentInput,
    registration: u32,
    root: &RegisteredRoot,
    roster: &ProjectRoster,
) -> bool {
    same_roster_data(
        original.registration,
        &original.root,
        &original.roots,
        registration,
        root,
        roster,
    )
}
fn same_roster_data(
    expected_registration: u32,
    expected_root: &RegisteredRoot,
    expected_roots: &[RegisteredRoot],
    registration: u32,
    root: &RegisteredRoot,
    roster: &ProjectRoster,
) -> bool {
    expected_registration == registration
        && roster.generation == registration
        && expected_root == root
        && expected_roots == roster.roots
}
fn admission_error(gate: wire::Availability) -> BridgeError {
    match gate {
        wire::Availability::CleanupUnknown => BridgeError::cleanup_unknown(),
        wire::Availability::Shutdown => BridgeError::shutdown(),
        wire::Availability::Busy => BridgeError::new(
            "tool_acquisition_busy",
            "Finish or cancel the current operation before checking build tools.",
        ),
        _ => wire::invalid(),
    }
}
fn merge_application_roots(
    host: Option<RegisteredRoot>,
    cache: Option<RegisteredRoot>,
) -> Result<Option<RegisteredRoot>, AssetError> {
    match (host, cache) {
        (None, value) | (value, None) => Ok(value),
        (Some(host), Some(cache)) if host == cache => Ok(Some(host)),
        _ => Err(AssetError::new(Reason::ExclusionUnconfirmed)),
    }
}

impl DocumentBinding {
    /// Same original saved lane/stamp/root/complete registry, without reviving
    /// its old acquisition epoch. The exact source Publisher owns that check.
    pub(super) fn tool_source_nomination_current(&self, state: &DocumentState,
        nomination: &crate::saved_command_owner::ToolSourceNomination,
        registration: u32, root: &RegisteredRoot, admitted: Option<&Arc<OriginalWork>>) -> Result<(), BridgeError> {
        let input=nomination.document();
        let roster=self.inner.bridge.native_roster().map_err(|_| crate::android_tool_sources::invalid())?;
        if !input.document.upgrade().is_some_and(|document| Arc::ptr_eq(&document,&self.inner))
            || !same_roster(input,registration,root,&roster)
            || !state.saved_observation.as_ref().is_some_and(|lane| same_lane(lane,&input.saved)) {
            return Err(crate::android_tool_sources::invalid());
        }
        let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        if !input.saved.tool_source_matches(&self.inner,&edit,registration,root,&input.context.project_id)
            || !self.tool_source_saved_input_matches(state,&input.saved,&input.context,
                nomination.continuing() || admitted.is_some_and(|owner| nomination.admitted_to(owner))) {
            return Err(crate::android_tool_sources::invalid());
        }
        Ok(()) // Edit guard drops before any outer gate, GUI, IO, or GO.
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn tool_application_exclusion_root(
        &self,
        _state: &DocumentState,
    ) -> Result<Option<RegisteredRoot>, AssetError> {
        // Caller holds the SAME original Doc through picker admission. Each
        // owner remains mandatory and errors cannot be flattened into None.
        let host = self
            .inner
            .bridge
            .application_service
            .native_exclusion_root()
            .map_err(|error| {
                AssetError::new(if error == crate::service_protocol::Error::StateUnknown {
                    Reason::CleanupUnknown
                } else {
                    Reason::ExclusionUnconfirmed
                })
            })?;
        let cache = self
            .inner
            .bridge
            .tool_acquisition
            .tool_acquisition_native_exclusion_root()
            .map_err(|error| {
                AssetError::new(if error.code == "cleanup_unknown" {
                    Reason::CleanupUnknown
                } else {
                    Reason::ExclusionUnconfirmed
                })
            })?;
        merge_application_roots(host, cache)
    }
    /// Native shell setup only. The application-data path is not an IPC input.
    pub(crate) fn bind_tool_acquisition(
        &self,
        native_application_data: &std::path::Path,
    ) -> Result<(), BridgeError> {
        let _state = self.lock();
        self.inner.bridge.android_build.bind_tool_acquisition(
            &self.inner.bridge.tool_acquisition,
            &self.inner.session_identity,
            native_application_data,
        )
    }
    pub(crate) fn tool_acquisition_subscribe(&self) -> watch::Receiver<u32> {
        self.inner.bridge.tool_acquisition.subscribe()
    }
    pub(crate) fn tool_acquisition_relay_lost(&self) {
        let _state = self.lock();
        self.inner.bridge.tool_acquisition.document_lost();
    }
    fn tool_acquisition_gate(&self, state: &DocumentState) -> wire::Availability {
        use wire::Availability as A;
        let bridge = &self.inner.bridge;
        if state.unknown
            || state.exhausted
            || self.inner.android_registration_control.is_unknown()
            || bridge.supervisor.disabled()
            || bridge.edits.disabled()
            || bridge.diagnostics.disabled()
            || bridge.preflight.disabled()
            || bridge.local_store.disabled()
            || bridge.local_store_prepare.disabled()
            || bridge.local_store_reconcile.disabled()
            || bridge.local_store_execute.disabled()
            || bridge.local_history.disabled()
            || bridge.apple_provisioning.disabled()
            || bridge.android_build.disabled()
            || bridge.project_recovery.disabled()
            || bridge.ios_archive.disabled()
            || bridge.artifact_inspection.disabled()
        {
            return A::CleanupUnknown;
        }
        if state.stopping
            || bridge.supervisor.stopping()
            || bridge.edits.stopping()
            || bridge.diagnostics.stopping()
            || bridge.preflight.stopping()
            || bridge.local_store.stopping()
            || bridge.local_store_prepare.stopping()
            || bridge.local_store_reconcile.stopping()
            || bridge.local_store_execute.stopping()
            || bridge.local_history.stopping()
            || bridge.apple_provisioning.stopping()
            || bridge.android_build.stopping()
            || bridge.project_recovery.stopping()
            || bridge.ios_archive.stopping()
            || bridge.artifact_inspection.stopping()
        {
            return A::Shutdown;
        }
        if wire::Profile::current().is_none() {
            return A::UnsupportedPlatform;
        }
        if state.lost_observed {
            return A::DocumentLost;
        }
        if !state.lifetime.original_bound() {
            return A::Busy;
        }
        if !bridge
            .android_build
            .original_document_matches(&self.inner.session_identity)
        {
            return A::DocumentLost;
        }
        // Deliberately exclude this tool owner: its prepared Intent must not
        // self-block Start. The SAME owner's own gate handles its active work.
        // All of these calls run BEFORE acquiring the SavedEditGuard/census.
        if state.quit_pending
            || state.retiring
            || state.lock_pending
            || state.compatibility_picker_pending
            || state.maintenance.closed()
            || gh_auth::pending(state) || version_allocation::pending(state) || git_read::pending(state)
            || state
                .saved_observation
                .as_ref()
                .is_some_and(|l| !l.returned())
            || state
                .slot
                .as_ref()
                .is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled())
            || state.github.registration().is_some()
            || !bridge.edits.can_exit()
            || bridge.edits.preflight_attention()
            || !bridge.supervisor.can_exit()
            || bridge.diagnostics.busy()
            || bridge.preflight.busy()
            || bridge.local_store.busy()
            || bridge.local_store_prepare.busy()
            || bridge.local_store_reconcile.busy()
            || bridge.local_store_execute.busy()
            || bridge.local_history.busy()
            || bridge.apple_provisioning.busy()
            || bridge.android_build.busy()
            || bridge.project_recovery.busy()
            || bridge.ios_archive.busy()
            || bridge.artifact_inspection.busy()
        {
            return A::Busy;
        }
        A::Available
    }
    pub(crate) fn tool_acquisition_status(&self) -> Result<wire::Status, BridgeError> {
        let state = self.lock();
        if !self
            .inner
            .bridge
            .tool_acquisition
            .registration_matches(self.inner.bridge.registry_generation())
        {
            self.inner.bridge.tool_acquisition.context_changed();
        }
        self.inner
            .bridge
            .tool_acquisition
            .status_tool_acquisition(self.tool_acquisition_gate(&state))
    }
    pub(crate) fn prepare_tool_acquisition(
        &self,
        input: wire::Prepare,
    ) -> Result<wire::Status, BridgeError> {
        if !input.valid() {
            return Err(wire::invalid());
        }
        let mut state = self.lock();
        let gate = self.tool_acquisition_gate(&state);
        if gate != wire::Availability::Available {
            return Err(admission_error(gate));
        }
        let (registration, root) = self
            .registry_result(
                &mut state,
                self.inner.bridge.native_project(&input.project_id),
                None,
            )
            .map_err(|_| wire::invalid())?;
        let roster = self
            .registry_result(&mut state, self.inner.bridge.native_roster(), None)
            .map_err(|_| wire::invalid())?;
        if roster.generation != registration
            || roster.roots.len() > 64
            || !roster.roots.iter().any(|v| *v == root)
            || roster
                .roots
                .iter()
                .any(|v| v.path.as_os_str().len() > asset_source::PATH_LIMIT)
        {
            return Err(wire::invalid());
        }
        // This traversal can consult the Edit Registry. Never move it under
        // the SavedEditGuard or hold the tools Registry while visiting it.
        let census = self
            .inner
            .bridge
            .tool_acquisition
            .tool_acquisition_prepare_census(&self.inner.session_identity)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        let saved = match self.tool_acquisition_saved_lane(&state, &input, &edit, registration, &root) {
            Ok(saved) => saved,
            Err(error) => {
                // This exact check precedes owner.prepare. It is NOT a map
                // for generic invalid, busy, unknown or a Start rejection.
                drop(edit);
                if error.code != "release_version_changed" { return Err(error); }
                let gate = self.tool_acquisition_gate(&state);
                if gate != wire::Availability::Available { return Err(admission_error(gate)); }
                return Err(wire::prerequisite::Required::SavedInputs.error());
            }
        };
        let original = Arc::new(ToolAcquisitionDocumentInput {
            document: Arc::downgrade(&self.inner),
            context: input.clone(),
            registration,
            root: root.clone(),
            roots: roster.roots,
            saved,
        });
        self.inner.bridge.tool_acquisition.prepare_tool_acquisition(
            input,
            registration,
            root,
            gate,
            &census,
            original,
        )
    }
    pub(crate) fn start_tool_acquisition(
        &self,
        input: wire::Start,
    ) -> Result<wire::Status, BridgeError> {
        let admitted_at = Instant::now(); // BEFORE Doc/Registry/queue admission.
        let mut state = self.lock();
        let owner = &self.inner.bridge.tool_acquisition;
        let original = owner
            .prepared_tool_acquisition_document(&input.operation_id, &input.owner_generation)?;
        let gate = self.tool_acquisition_gate(&state);
        if gate != wire::Availability::Available {
            owner.context_changed();
            return Err(admission_error(gate));
        }
        let selected = self.registry_result(
            &mut state,
            self.inner
                .bridge
                .native_project(&original.context.project_id),
            None,
        );
        let roster = self.registry_result(&mut state, self.inner.bridge.native_roster(), None);
        let (registration, root, roster) = match (selected, roster) {
            (Ok((registration, root)), Ok(roster))
                if same_roster(&original, registration, &root, &roster) =>
            {
                (registration, root, roster)
            }
            _ => {
                owner.context_changed();
                return Err(wire::invalid());
            }
        };
        // Keep full roster current to the same locked admission. No synthetic
        // source census or saved renderer count is accepted by the owner.
        drop(roster);
        let census = match owner.tool_acquisition_census(&self.inner.session_identity) {
            Ok(value) => value,
            Err(error) => {
                owner.context_changed();
                return Err(error);
            }
        };
        let budget = match self.tool_acquisition_budget(&state, &census) {
            Ok(value) => value,
            Err(error) => {
                owner.context_changed();
                return Err(error);
            }
        };
        // All unrelated peer gates and memory traversals are now finished.
        let edit = match self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)
        {
            Ok(value) => value,
            Err(error) => {
                owner.context_changed();
                return Err(error);
            }
        };
        let current =
            self.tool_acquisition_saved_lane(&state, &original.context, &edit, registration, &root);
        if !current
            .as_ref()
            .is_ok_and(|lane| same_lane(&original.saved, lane))
            || !original.matches(&original.context, registration, &root)
            || !original.same_document(&self.inner.session_identity)
        {
            drop(edit);
            owner.context_changed();
            return Err(wire::invalid());
        }
        let admitted = owner.start_tool_acquisition(
            input,
            admitted_at,
            Some((registration, root)),
            gate,
            &census,
            &budget,
        )?;
        // Prepared-context validation, one-use consent and original roster
        // claim are atomic under BOTH guards. Worker GO is only after release.
        drop(edit);
        drop(budget);
        drop(state);
        Ok(admitted.release())
    }
    pub(crate) fn cancel_tool_acquisition(
        &self,
        input: wire::Cancel,
    ) -> Result<wire::Status, BridgeError> {
        let state = self.lock();
        // Loss, shutdown and Unknown never hide the original STOP or status.
        self.inner.bridge.tool_acquisition.cancel_tool_acquisition(
            &input.operation_id,
            &input.owner_generation,
            self.tool_acquisition_gate(&state),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn equal_saved_bytes_in_a_replacement_lane_are_not_the_original() {
        // Only equality/Arc DATA, no native SourceBook, saved stamp or grant.
        let original = Arc::new([7u8; 32]);
        let retained = original.clone();
        let replacement = Arc::new([7u8; 32]);
        assert!(same_lane(&original, &retained));
        assert_eq!(*original, *replacement);
        assert!(!same_lane(&original, &replacement));
    }
    #[test]
    fn independent_application_roots_must_match_all_native_metadata() {
        // Inert Windows identity DATA here also exercises complete equality,
        // without constructing a Mac authority, ProjectProbe or source book.
        let root = RegisteredRoot {
            path: "/comparison-only/application".into(),
            identity: asset_source::ProjectIdentity::Windows {
                volume: 1,
                file_id: [2; 16],
            },
        };
        assert!(
            merge_application_roots(Some(root.clone()), Some(root.clone()))
                .is_ok_and(|value| value == Some(root.clone()))
        );
        assert!(merge_application_roots(None, Some(root.clone()))
            .is_ok_and(|value| value == Some(root.clone())));
        let mut changed = root.clone();
        changed.path.push("changed");
        assert!(merge_application_roots(Some(root.clone()), Some(changed)).is_err());
        let mut changed = root.clone();
        changed.identity = asset_source::ProjectIdentity::Windows {
            volume: 2,
            file_id: [2; 16],
        };
        assert!(merge_application_roots(Some(root), Some(changed)).is_err());
        assert!(merge_application_roots(None, None).is_ok_and(|value| value.is_none()));
    }
    #[test]
    fn changed_selected_root_or_complete_roster_cannot_reuse_prepare() {
        let root = RegisteredRoot {
            path: "/comparison-only/project".into(),
            identity: asset_source::ProjectIdentity::Windows {
                volume: 1,
                file_id: [2; 16],
            },
        };
        let mut current = ProjectRoster {
            generation: 7,
            roots: vec![root.clone()],
        };
        assert!(same_roster_data(
            7,
            &root,
            &[root.clone()],
            7,
            &root,
            &current
        ));
        assert!(!same_roster_data(
            6,
            &root,
            &[root.clone()],
            7,
            &root,
            &current
        ));
        current.generation = 8;
        assert!(!same_roster_data(
            7,
            &root,
            &[root.clone()],
            7,
            &root,
            &current
        ));
        current.generation = 7;
        let mut changed = root.clone();
        changed.path.push("another");
        current.roots.push(changed.clone());
        assert!(!same_roster_data(
            7,
            &root,
            &[root.clone()],
            7,
            &root,
            &current
        ));
        current.roots.pop();
        assert!(!same_roster_data(
            7,
            &root,
            &[root.clone()],
            7,
            &changed,
            &current
        ));
    }
    #[test]
    fn document_tool_status_and_stop_do_not_enable_an_unbound_runtime() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/never-opened-tool-document-fixture",
        )));
        let document = DocumentBinding::new(bridge);
        let status = document.tool_acquisition_status().unwrap();
        assert_ne!(status.availability, wire::Availability::Available);
        let input = wire::Cancel {
            operation_id: "00000000000000000000000000000001".into(),
            owner_generation: "00000000000000000000000000000002".into(),
        };
        // No active owner can be manufactured by cancellation identifiers.
        assert!(document.cancel_tool_acquisition(input).is_err());
    }
}
