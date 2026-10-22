//! Original Doc currentness for the remote-settings facet. Weak pins retain only
//! the exact underlying native/source allocations, never a new material owner.
use super::*;
use crate::{github_connection_session::action_delegation as agent, github_setup_protocol as wire};
#[derive(Clone)]
pub(crate) struct RemoteSetupVariablePins {
    context: Weak<NativeContext>, payload: Weak<Payload>, fingerprint: [u8; 64],
}
impl PartialEq for RemoteSetupVariablePins {
    fn eq(&self, other: &Self) -> bool { self.context.ptr_eq(&other.context)
        && self.payload.ptr_eq(&other.payload) && self.fingerprint == other.fingerprint }
}
impl Eq for RemoteSetupVariablePins {}
impl RemoteSetupVariablePins {
    fn new(material: &Arc<GitHubVariableMaterial>) -> Result<Self, BridgeError> {
        let (context, payload) = material.census_parts();
        let fingerprint = material.source().material.sha256.as_bytes().try_into().map_err(|_| refused(wire::Reason::MaterialChanged))?;
        Ok(Self { context: Arc::downgrade(context), payload: Arc::downgrade(payload), fingerprint })
    }
    pub(crate) fn matches(&self, material: &Arc<GitHubVariableMaterial>) -> bool {
        let (context, payload) = material.census_parts();
        self.context.ptr_eq(&Arc::downgrade(context)) && self.payload.ptr_eq(&Arc::downgrade(payload))
            && self.fingerprint.as_slice() == material.source().material.sha256.as_bytes()
    }
    pub(crate) const fn backing() -> usize {
        // Weak keeps the Arc allocation even after the strong owner drops. The
        // original census owns live strings/bodies; charge these inline cells
        // and both headers conservatively here as well, not zero weak credit.
        std::mem::size_of::<NativeContext>() + std::mem::size_of::<Payload>() + 4 * std::mem::size_of::<usize>()
    }
}
fn refused(reason: wire::Reason) -> BridgeError { crate::github_setup_session::refused(reason) }
impl DocumentBinding {
    fn remote_variable_pins(&self, state: &DocumentState, material: &Arc<GitHubVariableMaterial>,
        project: &str, generation: u32, root: &asset_source::RegisteredRoot) -> Result<RemoteSetupVariablePins, BridgeError> {
        if !self.native_qualified() || !material.current(state, project, generation, root)
            || material.own_retained_heap_bytes().is_none_or(|n| n > agent::dispatch::ROOT_BACKING + 512)
        { return Err(refused(wire::Reason::MaterialChanged)); }
        RemoteSetupVariablePins::new(material)
    }
    pub(super) fn remote_setup_agent_review(&self, state: &DocumentState, input: agent::dispatch::Input,
        generation: u32, root: &asset_source::RegisteredRoot, edit: &crate::edit_owner::SavedEditGuard<'_>,
        now: Instant) -> Result<agent::Review, BridgeError> {
        let (project, original) = state.github.registration().ok_or_else(|| refused(wire::Reason::NotConnected))?;
        if original != generation { return Err(refused(wire::Reason::TargetChanged)); }
        self.remote_setup_main_admission(state)?;
        let material = match &input {
            agent::dispatch::Input::RemoteSetupPrepare(v) => match v.selection.native() {
                wire::Selection::Variable(v) => Some(self.review_github_variable_material(state, &v, project, generation, root)?),
                wire::Selection::Secret(_) => return Err(refused(wire::Reason::InvalidInput)),
                _ => None,
            },
            agent::dispatch::Input::RemoteSetupApply(_) => state.github.remote_agent_material().cloned(),
            _ => return Err(refused(wire::Reason::InvalidInput)),
        };
        let pins = material.as_ref().map(|v| self.remote_variable_pins(state, v, project, generation, root)).transpose()?;
        // The temporary wrapper drops before the next NativeProject capture:
        // its root replaces that phase's fifth root, never a sixth live root.
        state.github.remote_agent_review(input, generation, root, &github_setup_project_binding(root)?, edit, now, None, pins)
    }
    pub(super) fn remote_setup_agent_entry(&self, state: &mut DocumentState, command: &wire::Command,
        entry: Option<&Arc<crate::service_github_action_requests::Entry>>, project: &str, generation: u32,
        root: &asset_source::RegisteredRoot, binding: &str, edit: &crate::edit_owner::SavedEditGuard<'_>,
        now: Instant) -> Result<Option<Arc<GitHubVariableMaterial>>, BridgeError> {
        // Ordinary Save/Apply cannot take an installed delegate's private review.
        // Perform this BEFORE any loan/reservation or the original Consent.take.
        if entry.is_none() {
            state.github.remote_agent_entry(command, None, generation, root, binding, edit, now, None)?;
            return Ok(None);
        }
        self.remote_setup_main_admission(state)?;
        let material = match command {
            wire::Command::Prepare(a) => match &a.selection {
                wire::Selection::Secret(_) => return Err(refused(wire::Reason::InvalidInput)),
                wire::Selection::Variable(v) => Some(self.review_github_variable_material(state, v, project, generation, root)?),
                _ => None,
            },
            wire::Command::Apply(_) => state.github.remote_agent_material().cloned(),
            _ => return Err(refused(wire::Reason::InvalidInput)),
        };
        let pins = material.as_ref().map(|v| self.remote_variable_pins(state, v, project, generation, root)).transpose()?;
        state.github.remote_agent_entry(command, entry, generation, root, binding, edit, now, pins)?;
        // Prepare reuses THIS genuine re-proven loan. Apply will consume the
        // SAME Arc retained in the actual private Consent, not this clone.
        Ok(if matches!(command, wire::Command::Prepare(_)) { material } else { None })
    }
    pub(super) fn remote_setup_main_admission(&self, state: &DocumentState) -> Result<usize, BridgeError> {
        #[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {
            let retained = lookup_memory::retained_document_bytes(&self.inner, state)
                .map_err(|e| refused(if e == keyring::Problem::CleanupUnknown { wire::Reason::CleanupUnknown } else { wire::Reason::ResourcesUnavailable }))?;
            self.remote_setup_additional(state, retained, crate::service_github_action_protocol::MAIN_CALL_BACKING)
        }
        #[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
        { let _ = state; Err(refused(wire::Reason::Unqualified)) }
    }
    pub(super) fn remote_setup_additional(&self, state: &DocumentState, original: usize, extra: usize) -> Result<usize, BridgeError> {
        #[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {
        let additional = installation_memory::additional_document_bytes(self, state).map_err(|reason|
            refused(if reason == Reason::CleanupUnknown { wire::Reason::CleanupUnknown } else { wire::Reason::ResourcesUnavailable }))?;
        original.checked_add(additional).and_then(|n| n.checked_add(extra))
            .filter(|n| *n <= SESSION_BYTES).ok_or_else(|| refused(wire::Reason::ResourcesUnavailable))
        }
        #[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
        { let _ = (state, original, extra); Err(refused(wire::Reason::Unqualified)) }
    }
}

#[cfg(all(test,debug_assertions,any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
mod tests {
    use super::*;
    fn native() -> Arc<NativeContext> {
        Arc::new(NativeContext {execution_mode:commands::ExecutionMode::Github,revision:1,project_id:"data-project".into(),
            project:asset_source::RegisteredRoot {path:"/inert/project".into(),identity:asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity())},
            registry_generation:1,draft:Vec::with_capacity(97),platform:Platform::Android,stage:Stage::Candidate,purpose:Purpose::Signing})
    }
    fn payload() -> Arc<Payload> {
        Arc::new(Payload {kind:Kind::GoogleWif,material:None,fields:Some(commands::own_fields(Kind::GoogleWif,&serde_json::json!({
            "provider":"projects/123/locations/global/workloadIdentityPools/release/providers/github","serviceAccount":"release@example-project.iam.gserviceaccount.com"})).ok().unwrap())})
    }
    #[test]
    fn remote_variable_pins_compare_actual_original_allocations_not_identical_values() {
        // Existing inert loan constructor only; no private source/assigned/native receipt.
        let n=native();let p=payload();let requirement=wire::VariableRequirement::GoogleWifProvider;
        let first=github_variable::data_loan(n.clone(),p.clone(),requirement);
        let pins=RemoteSetupVariablePins::new(&first).unwrap();
        assert!(pins.matches(&first));
        assert!(pins.matches(&github_variable::data_loan(n.clone(),p.clone(),requirement)));
        assert!(!pins.matches(&github_variable::data_loan(native(),p.clone(),requirement)));
        assert!(!pins.matches(&github_variable::data_loan(n.clone(),payload(),requirement)));
        assert!(!pins.matches(&github_variable::data_loan(n,p,wire::VariableRequirement::GoogleServiceAccount)));
        let held=pins.context.as_ptr();drop(first);assert_eq!(pins.context.as_ptr(),held);
        assert!(pins.context.upgrade().is_none()); // Weak allocation remains charged, never current proof.
        assert_eq!(RemoteSetupVariablePins::backing(),std::mem::size_of::<NativeContext>()+std::mem::size_of::<Payload>()+4*std::mem::size_of::<usize>());
    }
    #[test]
    fn remote_main_uses_full_document_with_retained_payloads_evidence_and_failure_refusal() {
        let bridge=Arc::new(DesktopBridge::new("/never-opened-remote-settings-census".into()));
        let document=DocumentBinding::new(bridge.clone());bridge.edits.initial_document("main").unwrap();
        let mut state=document.lock();let baseline=document.remote_setup_main_admission(&state).unwrap();
        for (name,kind,file,capacity) in [("data-p12",Kind::AppleP12,credential_format::FileKind::AppleP12,4*1024*1024),("data-p8",Kind::AscP8,credential_format::FileKind::AscP8,16*1024)] {
            let observation=credential_format::inspect(file,&[],&mut||false).ok().unwrap();
            state.records.push(Record {key:RecordKey{id:Token(name.into()),revision:1},payload:Arc::new(Payload {kind,fields:None,material:Some(Arc::new(Material {
                origin:MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(Vec::with_capacity(capacity))),observation}))}),mutation_pending:false});
        }
        let mut selected="a".repeat(32);selected.reserve_exact(64*1024);let capacity=selected.capacity();let ptr=selected.as_ptr();
        state.evidence.phase=evidence_wire::Phase::Refused;
        state.evidence.operation=Some(EvidenceBinding{operation_id:1,kind:evidence_wire::OperationKind::Observe,selection_id:Some(selected),epoch:0,purpose:EvidencePurpose::Candidate});
        let retained=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
        let additional=installation_memory::additional_document_bytes(&document,&state).unwrap();
        let main=crate::service_github_action_protocol::MAIN_CALL_BACKING;
        let actual=retained.checked_add(additional).unwrap().checked_add(main).unwrap();
        eprintln!("RemoteSettings MAIN: base={baseline} lookup={retained} additional={additional} evidence={capacity} main={main} total={actual} cap={SESSION_BYTES}");
        assert_eq!(document.remote_setup_main_admission(&state).unwrap(),actual);
        assert!(actual>=baseline+4*1024*1024+16*1024+2*RECORD_METADATA_BYTES+capacity);
        assert!(actual<SESSION_BYTES); // Actual target layout, not a source-fit claim.
        assert!(document.remote_setup_additional(&state,usize::MAX,1).is_err());
        state.evidence.phase=evidence_wire::Phase::Unknown;assert!(document.remote_setup_main_admission(&state).is_err());
        state.evidence.phase=evidence_wire::Phase::Refused;
        assert_eq!(state.evidence.operation.as_ref().unwrap().selection_id.as_ref().unwrap().as_ptr(),ptr);
        let growth=SESSION_BYTES.checked_sub(actual).unwrap()+1;
        let payload=Arc::get_mut(&mut state.records[0].payload).unwrap();let material=Arc::get_mut(payload.material.as_mut().unwrap()).unwrap();
        let MaterialOrigin::Selected(source)=&mut material.origin else {panic!("inert original")};
        source.bytes.reserve_exact(source.bytes.capacity().checked_add(growth).unwrap());
        assert!(document.remote_setup_main_admission(&state).is_err());
        state.retiring=true;assert!(document.remote_setup_main_admission(&state).is_err());
    }
}
