//! Private immutable explicitly assigned borrowers for the SAME saved Android operation.
//! Memory records or authenticated vault loans; no native IO, credential JSON,
//! scalar clone, provider lookup or reopened file at Prepare/Start.
use super::*;
use crate::android_build_protocol as wire;
use sha2::{Digest, Sha256};

pub(crate) const MATERIAL_PREFIX: &[u8] = b"MRK-ANDROID-MATERIAL/1\n";
pub(crate) const MATERIAL_SUFFIX: &[u8] = b"\nMRK-ANDROID-MATERIAL-END\n";

pub(crate) struct AndroidSigningMaterial {
    context: wire::Context,
    native: Arc<NativeContext>,
    keys: Vec<RecordKey>,
    payloads: Vec<Arc<Payload>>,
}

fn invalid() -> BridgeError {
    BridgeError::new("android_build_signing_inputs", "Assign the current upload keystore, store/key passwords, alias and required Firebase file for this saved Android configuration, then review again.")
}

// One currentness seam for both private sources. Public assignment DATA alone
// never supplies bytes. The saved owner holds only immutable payload/context
// Arcs; it does not inherit vault mutation, key access or lease authority.
fn assigned_payload<'a>(state: &'a DocumentState, key: &RecordKey, kind: Kind,
    native: &Arc<NativeContext>) -> Option<&'a Arc<Payload>> {
    if state.stopping || state.unknown || state.exhausted || state.lock_pending || state.retiring || state.quit_pending
        || !state.lifetime.original_bound() || !state.context.as_ref().is_some_and(|context| Arc::ptr_eq(context, native))
        || !state.assignments.iter().any(|assignment| assignment.record_id == key.id && assignment.record_revision == key.revision
            && assignment.context_revision == native.revision && assignment.kind == kind
            && assignment.availability == AssignmentAvailability::Available) { return None; }
    if state.session && !encrypted_mode(state) {
        return state.records.iter().find(|record| record.key == *key && record.payload.kind == kind
            && !record.mutation_pending && record.payload.usable_source()).map(|record| &record.payload);
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    { vault::assigned_payload(state, key, kind, native) }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    { None }
}

impl AndroidSigningMaterial {
    pub(crate) fn matches(&self, context: &wire::Context, registration: u32, project: &asset_source::RegisteredRoot) -> bool {
        self.context == *context && self.native.registry_generation == registration && self.native.project == *project
            && self.native.project_id == context.project_id && self.native.platform == Platform::Android
            && self.native.stage == Stage::Candidate && self.native.purpose == Purpose::Signing
    }

    pub(crate) fn context_data(&self) -> wire::Content {
        wire::Content { bytes: self.native.draft.len() as u32, sha256: format!("{:x}", Sha256::digest(&self.native.draft)) }
    }

    /// Borrow slices from actual Arc<Payload> backing. No base64, files reopened
    /// by name, body Vec copy or values in the public/native request JSON.
    pub(crate) fn parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
        let mut result = Vec::new();
        result.try_reserve_exact(5).map_err(|_| invalid())?;
        for payload in &self.payloads {
            if !matches!(payload.kind, Kind::AndroidKeystore | Kind::AndroidFirebase) { return Err(invalid()); }
            let value = payload.material.as_ref().filter(|m| m.observation.is_observed()).ok_or_else(invalid)?;
            let maximum = if payload.kind == Kind::AndroidKeystore { 32 * 1024 * 1024 } else { 4 * 1024 * 1024 };
            if value.bytes().is_empty() || value.bytes().len() > maximum { return Err(invalid()); }
            result.push((payload.kind.name(), value.bytes()));
            if payload.kind == Kind::AndroidKeystore {
                for (field, role) in [("storePassword", "store-password"), ("keyAlias", "key-alias"), ("keyPassword", "key-password")] {
                    let value = payload.fields.as_ref().and_then(|fields| fields.borrow_value(field)).ok_or_else(invalid)?;
                    if value.is_empty() || value.len() > 8192 || value.contains('\0')
                        || role == "key-alias" && value.starts_with('-') { return Err(invalid()); }
                    result.push((role, value.as_bytes()));
                }
            }
        }
        let roles: Vec<_> = result.iter().map(|(name, _)| *name).collect();
        if !matches!(roles.as_slice(), ["android-keystore", "store-password", "key-alias", "key-password"]
            | ["android-keystore", "store-password", "key-alias", "key-password", "android-firebase"]) { return Err(invalid()); }
        Ok(result)
    }

    pub(crate) fn header(&self) -> Result<Vec<u8>, BridgeError> {
        let parts = self.parts()?;
        let files: Vec<_> = parts.iter().map(|(role, bytes)| serde_json::json!({"role":role,"bytes":bytes.len()})).collect();
        let mut header = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"files":files})).map_err(|_| invalid())?;
        header.push(b'\n');
        if header.len() > 1024 { return Err(invalid()); }
        Ok(header)
    }

    pub(super) fn current(&self, state: &DocumentState, registration: u32, project: &asset_source::RegisteredRoot) -> bool {
        self.matches(&self.context, registration, project) && self.keys.len() == self.payloads.len()
            && self.keys.iter().zip(&self.payloads).all(|(key, payload)|
                assigned_payload(state, key, payload.kind, &self.native).is_some_and(|current| Arc::ptr_eq(current, payload)))
    }
}

// DATA-only collection after native admission. Also exercised by focused
// synthetic borrower tests; those tests grant no native profile or store proof.
pub(super) fn borrow_material(state: &DocumentState, context: &wire::Context,
    registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<AndroidSigningMaterial>, BridgeError> {
    if !context.signed() { return Err(invalid()); }
    let native = state.context.as_ref().ok_or_else(invalid)?.clone();
    let policy = context.signing.as_ref().ok_or_else(invalid)?;
    if native.project_id != context.project_id || native.registry_generation != registration || native.project != *project
        || native.platform != Platform::Android || native.stage != Stage::Candidate || native.purpose != Purpose::Signing
        || native.draft.is_empty() || native.draft.len() > 512 * 1024 || !(1..=2).contains(&policy.assignments.len()) { return Err(invalid()); }
    let mut keys = Vec::new(); let mut payloads = Vec::new();
    keys.try_reserve_exact(policy.assignments.len()).map_err(|_| invalid())?;
    payloads.try_reserve_exact(policy.assignments.len()).map_err(|_| invalid())?;
    for required in &policy.assignments {
        if required.context_revision != native.revision { return Err(invalid()); }
        let assignment = state.assignments.iter().find(|a| a.kind.name() == required.kind.as_str()
            && a.record_id.0 == required.record_id && a.record_revision == required.record_revision
            && a.context_revision == required.context_revision && a.availability == AssignmentAvailability::Available).ok_or_else(invalid)?;
        let key = RecordKey { id: assignment.record_id.clone(), revision: assignment.record_revision };
        let payload = assigned_payload(state, &key, assignment.kind, &native).ok_or_else(invalid)?;
        if keys.iter().any(|previous: &RecordKey| previous.id == key.id) { return Err(invalid()); }
        keys.push(key); payloads.push(payload.clone());
    }
    let original = Arc::new(AndroidSigningMaterial { context: context.clone(), native, keys, payloads });
    original.parts()?;
    // Original draft DATA is canonical UTF-8, whereas saved_config identifies
    // raw file bytes. Core compares the same admitted parsed file against this
    // exact draft observation before receiving material or starting commands.
    if !original.current(state, registration, project) { return Err(invalid()); }
    Ok(original)
}

impl DocumentBinding {
    pub(super) fn review_android_material(&self, state: &DocumentState, context: &wire::Context,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<AndroidSigningMaterial>, BridgeError> {
        // Same actual document mutex. The existing saved-owner busy/disabled/
        // stopping gates exclude new asset allocation through its real finality.
        if !cfg!(all(target_os = "macos", target_arch = "aarch64")) || !self.native_qualified() || encrypted_mode(state) && !self.persistence_qualified() { return Err(invalid()); }
        borrow_material(state, context, registration, project)
    }

    pub(super) fn recheck_android_material(&self, state: &DocumentState, original: &Arc<AndroidSigningMaterial>,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<(), BridgeError> {
        if !cfg!(all(target_os = "macos", target_arch = "aarch64")) || !self.native_qualified() || encrypted_mode(state) && !self.persistence_qualified() || !original.current(state, registration, project) { return Err(invalid()); }
        original.parts()?; Ok(())
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod tests {
    // Only retained DATA. memory_data/format observations are not native source
    // custody, authentication, usable JKS material or permission to sign.
    use super::*;
    fn payload() -> Arc<Payload> {
        let bytes = vec![0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 0];
        let Ok(observation) = credential_format::inspect(credential_format::FileKind::AndroidKeystore, &bytes, &mut || false) else {
            panic!("inert Android keystore fixture inspection failed");
        };
        assert!(observation.is_observed());
        let Ok(fields) = commands::own_fields(Kind::AndroidKeystore, &serde_json::json!({
            "storePassword":"inert-store-secret","keyAlias":"inert-alias","keyPassword":"inert-key-secret"})) else {
            panic!("inert Android signing fields fixture failed");
        };
        Arc::new(Payload { kind: Kind::AndroidKeystore,
            material: Some(Arc::new(Material { origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(bytes)), observation })),
            fields: Some(fields) })
    }
    fn context(project: asset_source::RegisteredRoot) -> Arc<NativeContext> {
        Arc::new(NativeContext { revision: 2, project_id: "inert-android".into(), project, registry_generation: 7,
            draft: br#"{"android":{"applicationId":"org.example.app"}}"#.to_vec(),
            platform: Platform::Android, stage: Stage::Candidate, purpose: Purpose::Signing })
    }
    fn model() -> (DocumentState, wire::Context, asset_source::RegisteredRoot) {
        let mut state = super::super::tests::empty_state();
        state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
        let project = asset_source::RegisteredRoot { path: "/inert/android".into(),
            identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
        state.context = Some(context(project.clone()));
        let key = RecordKey { id: Token("e".repeat(32)), revision: 1 };
        state.records.push(Record { key: key.clone(), payload: payload(), mutation_pending: false });
        state.assignments.push(Assignment { kind: Kind::AndroidKeystore, record_id: key.id, record_revision: key.revision,
            context_revision: 2, availability: AssignmentAvailability::Available });
        (state, wire::tests::signed_context(), project)
    }

    #[test]
    fn material_parts_borrow_the_same_backing_and_raw_config_is_not_canonical_draft() {
        let (state, request, project) = model();
        let original = borrow_material(&state, &request, 7, &project).unwrap();
        assert!(original.current(&state, 7, &project));
        assert!(Arc::ptr_eq(&original.payloads[0], &state.records[0].payload));
        let parts = original.parts().unwrap();
        assert_eq!(parts.iter().map(|part| part.0).collect::<Vec<_>>(), ["android-keystore", "store-password", "key-alias", "key-password"]);
        assert_eq!(parts[0].1.as_ptr(), state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        assert_eq!(parts[1].1.as_ptr(), state.records[0].payload.fields.as_ref().unwrap().borrow_value("storePassword").unwrap().as_bytes().as_ptr());
        let header = String::from_utf8(original.header().unwrap()).unwrap();
        assert!(!header.contains("inert-store-secret") && !header.contains("inert-key-secret"));
        let canonical = original.context_data();
        assert_eq!(canonical.bytes as usize, state.context.as_ref().unwrap().draft.len());
        assert_ne!(canonical, request.saved_config); // Distinct byte domains, checked in core before receipt.
        assert!(!original.matches(&request, 8, &project));
    }

    #[test]
    fn equal_revisions_do_not_replace_original_payload_or_context_arcs_and_lock_retains_borrow() {
        for replace_context in [false, true] {
            let (mut state, request, project) = model();
            let original = borrow_material(&state, &request, 7, &project).unwrap();
            let weak = Arc::downgrade(&state.records[0].payload);
            if replace_context { state.context = Some(context(project.clone())); }
            else { state.records[0].payload = payload(); }
            assert!(!original.current(&state, 7, &project));
            state.lock_pending = true;
            assert!(borrow_material(&state, &request, 7, &project).is_err());
            drop(state); assert!(weak.upgrade().is_some());
            assert_eq!(original.parts().unwrap()[3].1, b"inert-key-secret");
            drop(original); assert!(weak.upgrade().is_none());
        }
    }

    #[test]
    fn unsigned_wrong_domain_missing_assignment_and_stale_native_revision_cannot_borrow() {
        for changed in 0..5 {
            let (mut state, mut request, project) = model();
            match changed {
                0 => request = wire::tests::context(),
                1 => Arc::get_mut(state.context.as_mut().unwrap()).unwrap().platform = Platform::Ios,
                2 => state.assignments.clear(),
                3 => state.assignments[0].record_revision += 1,
                _ => Arc::get_mut(state.context.as_mut().unwrap()).unwrap().revision += 1,
            }
            assert!(borrow_material(&state, &request, 7, &project).is_err());
        }
    }
}
