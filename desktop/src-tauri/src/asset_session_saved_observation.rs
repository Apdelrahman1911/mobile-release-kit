//! Private state of the SAME Document and original typed Supervisor return.
//! Not another observation runner, public authority DTO, or callback registry.
use super::*;

const RESERVED: u8 = 0;
const ARMED: u8 = 1;
const COMPLETING: u8 = 2;
const RETURNED: u8 = 3;
const UNKNOWN: u8 = 4;

pub(super) struct SavedObservationLane {
    project_id: String, registration: u32, root: asset_source::RegisteredRoot,
    stamp: crate::edit_owner::SavedEditStamp, epoch: u64,
    stage: std::sync::atomic::AtomicU8, completion_returned: AtomicBool,
}
impl SavedObservationLane {
    pub(super) fn returned(&self) -> bool {
        self.stage.load(Ordering::SeqCst) == RETURNED && self.completion_returned.load(Ordering::SeqCst)
    }
    pub(super) fn retained_heap_bytes(&self) -> Option<usize> {
        retained_field_heap_bytes(&self.project_id,&self.root)
    }
}
// Capacity-only expression: no SavedEditStamp, completion or saved-input grant.
pub(super) fn retained_field_heap_bytes(project_id:&String,root:&asset_source::RegisteredRoot)->Option<usize>{
    project_id.capacity().checked_add(root.path.capacity())?
        .checked_add(std::mem::size_of::<SavedObservationCompletion>())?
        .checked_add(crate::release_version_protocol::RESULT_LIMIT)?.checked_add(4 * 1024)
}
#[derive(Clone, Copy)]
struct SavedComparisonData {
    source: [u8; 512], source_len: u16, name: [u8; 64], name_len: u8, build: u32,
    config_bytes: u32, config_sha256: [u8; 32], version_bytes: u32, version_sha256: [u8; 32],
}
impl SavedComparisonData {
    fn digest(text: &str) -> Option<[u8; 32]> {
        if text.len() != 64 { return None; }
        fn digit(byte: u8) -> Option<u8> {
            match byte { b'0'..=b'9' => Some(byte-b'0'), b'a'..=b'f' => Some(byte-b'a'+10), _ => None }
        }
        let mut output = [0;32];
        for (target, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            *target = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Some(output)
    }
    fn from_observation(value: &crate::release_version_protocol::Observation) -> Option<Self> {
        let value = value.saved_comparison();
        if value.source.len() > 512 || value.name.len() > 64 { return None; }
        let mut source = [0;512]; let mut name = [0;64];
        source[..value.source.len()].copy_from_slice(value.source.as_bytes());
        name[..value.name.len()].copy_from_slice(value.name.as_bytes());
        Some(Self { source, source_len: value.source.len().try_into().ok()?, name,
            name_len: value.name.len().try_into().ok()?, build: value.build,
            config_bytes: value.config_bytes, config_sha256: Self::digest(value.config_sha256)?,
            version_bytes: value.version_bytes, version_sha256: Self::digest(value.version_sha256)? })
    }
    fn matches(&self, input: &crate::android_build_protocol::Prepare) -> bool {
        input.saved_config.bytes == self.config_bytes && Self::digest(&input.saved_config.sha256) == Some(self.config_sha256)
            && input.saved_version.bytes == self.version_bytes && Self::digest(&input.saved_version.sha256) == Some(self.version_sha256)
            && input.saved_version.source.as_bytes() == &self.source[..usize::from(self.source_len)]
            && input.saved_version.name.as_bytes() == &self.name[..usize::from(self.name_len)] && input.saved_version.build == self.build
    }
}
pub(super) struct SavedInputBinding { pub(super) lane: Arc<SavedObservationLane>, comparison: SavedComparisonData }

/// Move-only witness from original Document state. Prepare stays comparison DATA.
pub(crate) struct ValidatedSavedInput {
    document: Weak<Inner>, lane: Arc<SavedObservationLane>, comparison: SavedComparisonData, epoch: u64,
}
impl ValidatedSavedInput {
    pub(crate) fn matches(&self, document: &Arc<()>, registration: u32, root: &asset_source::RegisteredRoot,
        input: &crate::android_build_protocol::Prepare) -> bool {
        self.document.upgrade().is_some_and(|original| Arc::ptr_eq(&original.session_identity, document)
            && original.android_registration_control.matches_epoch(self.epoch))
            && self.lane.returned() && self.lane.registration == registration && &self.lane.root == root
            && self.lane.project_id == input.project_id && self.comparison.matches(input)
    }
    pub(crate) fn same_binding(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.document, &other.document) && Arc::ptr_eq(&self.lane, &other.lane) && self.epoch == other.epoch
    }
    pub(crate) fn epoch(&self) -> u64 { self.epoch }
}

/// Only the ORIGINAL Supervisor owns this typed return arm. No async invoke or
/// destructor may install a binding or manufacture an actual completion return.
pub(crate) struct SavedObservationCompletion { document: DocumentBinding, lane: Arc<SavedObservationLane> }
impl SavedObservationCompletion {
    pub(crate) fn arm(&self) -> Result<(), BridgeError> {
        self.lane.stage.compare_exchange(RESERVED, ARMED, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ()).map_err(|_| BridgeError::cleanup_unknown())
    }
    pub(crate) fn unknown(&self) {
        self.lane.stage.store(UNKNOWN, Ordering::SeqCst);
        self.document.inner.android_registration_control.poisoned();
    }
    pub(crate) fn complete(&mut self, observation: Option<&crate::release_version_protocol::Observation>,
        was_unknown: bool) -> Result<(), BridgeError> {
        if was_unknown || self.lane.stage.compare_exchange(ARMED, COMPLETING, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            self.unknown(); return Err(BridgeError::cleanup_unknown());
        }
        let mut state = self.document.lock();
        if !state.saved_observation.as_ref().is_some_and(|lane| Arc::ptr_eq(lane, &self.lane)) {
            self.unknown(); return Err(BridgeError::cleanup_unknown());
        }
        state.saved_input = None;
        // Known parse/helper refusal still runs and returns this completion.
        let Some(observation) = observation else { return Ok(()); };
        self.document.saved_observation_gate(&state, Some(&self.lane))?;
        let (registration, root) = self.document.inner.bridge.native_project(&self.lane.project_id).map_err(|_| stale())?;
        if registration != self.lane.registration || root != self.lane.root { return Err(stale()); }
        // Exact self is the ONLY lane exemption. Retain original Registry through
        // epoch/no-pending validation; no unconditional self.can_exit recursion.
        let edit = self.document.inner.bridge.edits.saved_registration_guard(&self.document.inner.session_identity)?;
        if !edit.matches(&self.lane.stamp)
            || !self.document.inner.android_registration_control.matches_epoch(self.lane.epoch) { return Err(stale()); }
        let comparison = SavedComparisonData::from_observation(observation).ok_or_else(BridgeError::protocol)?;
        state.saved_input = Some(SavedInputBinding { lane: self.lane.clone(), comparison });
        Ok(())
    }
    pub(crate) fn returned(&mut self) {
        // Only AFTER complete actually returned. The retained Document lane covers
        // the roster-removal gap and remains Unknown on a panic or early Unknown.
        self.lane.completion_returned.store(true, Ordering::SeqCst);
        let _ = self.lane.stage.compare_exchange(COMPLETING, RETURNED, Ordering::SeqCst, Ordering::SeqCst);
        self.document.inner.changes.send_modify(|_| {});
    }
}
impl Drop for SavedObservationCompletion {
    fn drop(&mut self) {
        if !matches!(self.lane.stage.load(Ordering::SeqCst), RESERVED | RETURNED) { self.unknown(); }
    }
}

/// Inert refusal/gate observations only. This never exposes an observation,
/// registered root, positive saved binding, native original or join receipt.
#[cfg(test)]
pub(crate) struct SavedObservationControlProbe {
    document: DocumentBinding, lane: Arc<SavedObservationLane>,
}
#[cfg(test)]
impl SavedObservationControlProbe {
    pub(crate) fn returned(&self) -> bool { self.lane.returned() }
    pub(crate) fn completion_returned(&self) -> bool { self.lane.completion_returned.load(Ordering::SeqCst) }
    pub(crate) fn unknown(&self) -> bool { self.lane.stage.load(Ordering::SeqCst) == UNKNOWN }
    pub(crate) fn has_binding(&self) -> bool { self.document.lock().saved_input.is_some() }
    pub(crate) fn gate_open(&self) -> bool {
        self.document.saved_observation_gate(&self.document.lock(), None).is_ok()
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) fn can_exit(&self) -> bool { self.document.can_exit() }
}
#[cfg(test)]
impl SavedObservationCompletion {
    pub(crate) fn control_fixture() -> (Self, SavedObservationControlProbe) {
        // Actual empty owners and their real Edit stamp. Constructors retain
        // their ordinary nonce generation; no source/process/native work starts.
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from("/never-opened-saved-control-fixture")));
        let document = DocumentBinding::new(bridge.clone());
        bridge.edits.initial_document("main").unwrap();
        let stamp = bridge.edits.saved_registration_guard(&document.inner.session_identity).unwrap().stamp().unwrap();
        let epoch = document.inner.android_registration_control.epoch().unwrap();
        let lane = Arc::new(SavedObservationLane {
            project_id: "never-registered-comparison".to_owned(), registration: 1,
            // Comparison DATA in this private lane ONLY. Never inserted into
            // the bridge project registry or passed as native root evidence.
            root: asset_source::RegisteredRoot {
                path: std::path::PathBuf::from("/never-registered-comparison-data"),
                identity: asset_source::ProjectIdentity::Windows { volume: 0, file_id: [0; 16] },
            },
            stamp, epoch, stage: std::sync::atomic::AtomicU8::new(RESERVED),
            completion_returned: AtomicBool::new(false),
        });
        {
            let mut state = document.lock();
            // Existing gate-only lifetime DATA pattern, not an actual native
            // document startup, quit, source completion or join receipt.
            state.lifetime.crash_hook_installed();
            state.lifetime.started(true);
            state.lifetime.finished(true);
            state.saved_observation = Some(lane.clone());
            assert!(state.saved_input.is_none());
        }
        (Self { document: document.clone(), lane: lane.clone() }, SavedObservationControlProbe { document, lane })
    }
}

fn stale() -> BridgeError {
    BridgeError::new("release_version_changed", "Observe the saved configuration and version again after the original change settles.")
}

#[cfg(test)]
mod saved_observation_control_tests {
    use super::*;

    #[test]
    fn exact_self_only_bypasses_pending_lane_and_refusal_never_installs_binding() {
        let (mut completion, probe) = SavedObservationCompletion::control_fixture();
        let (foreign, foreign_probe) = SavedObservationCompletion::control_fixture();
        completion.arm().unwrap();
        {
            let state = completion.document.lock();
            assert!(completion.document.saved_observation_gate(&state, None).is_err());
            assert!(completion.document.saved_observation_gate(&state, Some(&completion.lane)).is_ok());
            assert!(!Arc::ptr_eq(&completion.lane, &foreign.lane));
            assert!(completion.document.saved_observation_gate(&state, Some(&foreign.lane)).is_err());
        }
        completion.complete(None, false).unwrap();
        // The actual return wrapper must still record its returned edge; mere
        // completion-body success cannot release this retained lane.
        assert!(!probe.returned() && !probe.completion_returned() && !probe.gate_open());
        assert!(!probe.has_binding());
        completion.returned();
        assert!(probe.returned() && probe.completion_returned() && probe.gate_open());
        assert!(!probe.unknown() && !probe.has_binding());
        assert!(!foreign_probe.returned() && !foreign_probe.gate_open());
        // No accepted/returned Quit is fabricated to claim overall exit.
        #[cfg(feature = "desktop-shell")]
        assert!(!probe.can_exit());
    }
}

impl DocumentBinding {
    fn saved_observation_gate(&self, state: &DocumentState, exact: Option<&Arc<SavedObservationLane>>) -> Result<(), BridgeError> {
        passive_document_gate(state)?;
        if !state.lifetime.original_bound() || state.lost_observed { return Err(stale()); }
        if state.saved_observation.as_ref().is_some_and(|lane| !lane.returned()
            && !exact.is_some_and(|exact| Arc::ptr_eq(lane, exact))) {
            return Err(BridgeError::new("busy", "The original saved observation has not returned."));
        }
        if state.slot.as_ref().is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled())
            || state.github.registration().is_some() || !self.inner.bridge.supervisor.can_exit() {
            return Err(BridgeError::new("busy", "Finish the original native operation first."));
        }
        self.inner.bridge.preflight.ensure_idle()?; self.inner.bridge.android_build.ensure_idle()?;
        self.inner.bridge.project_recovery.ensure_idle()?; self.inner.bridge.ios_archive.ensure_idle()?;
        self.inner.bridge.diagnostics.ensure_idle()?;
        Ok(())
    }
    pub(crate) fn saved_observation(&self, bridge: &DesktopBridge, project_id: &str) -> Result<crate::supervisor::SavedObservationQuery, BridgeError> {
        let mut state = self.lock();
        if !std::ptr::eq(bridge, self.inner.bridge.as_ref()) { return Err(BridgeError::invalid()); }
        self.saved_observation_gate(&state, None)?;
        if !self.inner.android_registration_control.idle_for_saved_observation() {
            return Err(BridgeError::new("busy", "The original registration cohort still owns its lane."));
        }
        let (registration, root) = self.inner.bridge.native_project(project_id).map_err(|_| stale())?;
        let params = crate::release_version_protocol::params(&root.path)?;
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        let stamp = edit.stamp()?;
        let epoch = self.inner.android_registration_control.epoch()?;
        let lane = Arc::new(SavedObservationLane { project_id: project_id.to_owned(), registration, root, stamp, epoch,
            stage: std::sync::atomic::AtomicU8::new(RESERVED), completion_returned: AtomicBool::new(false) });
        state.saved_input = None; state.saved_observation = Some(lane.clone());
        drop(edit);
        let completion = SavedObservationCompletion { document: self.clone(), lane: lane.clone() };
        let result = self.inner.bridge.supervisor.start_saved_observation(params, completion);
        if result.is_err() && lane.stage.load(Ordering::SeqCst) == RESERVED {
            // Synchronous pre-roster Err only. Armed panic/Unknown is not nonentry.
            lane.completion_returned.store(true, Ordering::SeqCst);
            lane.stage.store(RETURNED, Ordering::SeqCst); state.saved_observation = None;
        }
        result
    }
    pub(super) fn validated_saved_input(&self, state: &DocumentState, input: &crate::android_build_protocol::Prepare) -> Result<ValidatedSavedInput, BridgeError> {
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        self.validated_saved_input_with_edit(state,input,&edit)
    }
    pub(super) fn validated_saved_input_with_edit(&self, state: &DocumentState, input: &crate::android_build_protocol::Prepare,
        edit:&crate::edit_owner::SavedEditGuard<'_>) -> Result<ValidatedSavedInput, BridgeError> {
        let binding = state.saved_input.as_ref().filter(|binding| binding.lane.returned()).ok_or_else(stale)?;
        let (registration, root) = self.inner.bridge.native_project(&input.project_id).map_err(|_| stale())?;
        if !edit.matches(&binding.lane.stamp) || registration != binding.lane.registration || root != binding.lane.root
            || binding.lane.project_id != input.project_id || !binding.comparison.matches(input)
            || !self.inner.android_registration_control.matches_epoch(binding.lane.epoch) { return Err(stale()); }
        Ok(ValidatedSavedInput { document: Arc::downgrade(&self.inner), lane: binding.lane.clone(),
            comparison: binding.comparison, epoch: binding.lane.epoch })
    }
}
