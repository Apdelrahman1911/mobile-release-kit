//! Private immutable explicitly assigned borrowers for the SAME saved iOS operation.
//! Memory records or authenticated vault loans; no native IO, credential JSON,
//! scalar clone, provider lookup or reopened file at Prepare/Start.
use super::*;
use crate::ios_archive_protocol as wire;
use sha2::{Digest, Sha256};

pub(crate) const MATERIAL_PREFIX: &[u8] = b"MRK-IOS-MATERIAL/1\n";
pub(crate) const MATERIAL_SUFFIX: &[u8] = b"\nMRK-IOS-MATERIAL-END\n";

pub(crate) struct IOSSigningMaterial {
    context: wire::Context,
    candidate_document:Option<std::sync::Weak<Inner>>,
    native: Arc<NativeContext>,
    keys: Vec<RecordKey>,
    payloads: Vec<Arc<Payload>>,
}

fn invalid() -> BridgeError {
    BridgeError::new("ios_archive_signing_inputs", "Assign the current P12, password, provisioning profile and required build inputs for this saved iOS configuration, then review again.")
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
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    { vault::assigned_payload(state, key, kind, native) }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))))]
    { None }
}

impl IOSSigningMaterial {
    pub(crate) fn matches(&self, context: &wire::Context, registration: u32, project: &asset_source::RegisteredRoot) -> bool {
        self.context == *context && self.native.registry_generation == registration && self.native.project == *project
            && self.native.project_id == context.project_id && self.native.platform == Platform::Ios
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
            match payload.kind {
                Kind::AppleP12 | Kind::AppleProfile | Kind::IosFirebase => {
                    let value = payload.material.as_ref().filter(|m| m.observation.is_observed()).ok_or_else(invalid)?;
                    let maximum = if payload.kind == Kind::AppleP12 { 32 * 1024 * 1024 } else { 4 * 1024 * 1024 };
                    if value.bytes().is_empty() || value.bytes().len() > maximum { return Err(invalid()); }
                    result.push((payload.kind.name(), value.bytes()));
                    if payload.kind == Kind::AppleP12 {
                        let value = payload.fields.as_ref().and_then(|f| f.borrow_value("password")).ok_or_else(invalid)?;
                        if value.is_empty() || value.len() > 8192 || value.contains('\0') { return Err(invalid()); }
                        result.push(("p12-password", value.as_bytes()));
                    }
                },
                Kind::ProjectReadToken => {
                    let value = payload.fields.as_ref().and_then(|f| f.borrow_value("token")).ok_or_else(invalid)?;
                    if value.is_empty() || value.len() > 8192 || value.contains('\0') { return Err(invalid()); }
                    result.push(("project-read-token", value.as_bytes()));
                },
                _ => return Err(invalid()),
            }
        }
        let roles: Vec<_> = result.iter().map(|(name, _)| *name).collect();
        if !matches!(roles.as_slice(), ["apple-p12", "p12-password", "apple-profile"]
            | ["apple-p12", "p12-password", "apple-profile", "ios-firebase"]
            | ["apple-p12", "p12-password", "apple-profile", "project-read-token"]
            | ["apple-p12", "p12-password", "apple-profile", "ios-firebase", "project-read-token"]) { return Err(invalid()); }
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

impl IOSSigningMaterial {
    fn candidate_matches(&self,document:&Arc<Inner>,state:&DocumentState,context:&wire::Context,
        registration:u32,root:&asset_source::RegisteredRoot)->bool{
        context.candidate() && self.context==*context && self.candidate_document.as_ref().and_then(std::sync::Weak::upgrade)
            .is_some_and(|original|Arc::ptr_eq(&original,document)) && !state.lost_observed&&!state.compatibility_picker_pending
            &&self.current(state,registration,root)&&document.bridge.registry_generation()==registration
            &&document.bridge.native_project(&context.project_id).is_ok_and(|(g,r)|g==registration&&r==*root)
    }
    pub(crate) fn candidate_current(&self,context:&wire::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool{
        let Some(document)=self.candidate_document.as_ref().and_then(std::sync::Weak::upgrade) else{return false;};
        let Ok(state)=document.state.lock() else{return false;};self.candidate_matches(&document,&state,context,registration,root)
    }
    pub(super) fn candidate_census(&self)->(&Arc<NativeContext>,&Vec<RecordKey>,&Vec<Arc<Payload>>,&wire::Context){
        (&self.native,&self.keys,&self.payloads,&self.context)
    }
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
impl IOSSigningMaterial {
    pub(crate) fn admit_candidate(&self,claim:crate::saved_command_owner::LocalHistoryClaim)
        ->Result<(crate::vault_keyring_macos::LocalInput,KeyringMemoryAdmission),BridgeError>{
        let document=self.candidate_document.as_ref().and_then(std::sync::Weak::upgrade).ok_or_else(invalid)?;
        let state=document.state.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let Some((material,context,g,r))=claim.ios_candidate_context() else{return Err(invalid());};
        if !std::ptr::eq(self,material.as_ref()) || !self.candidate_matches(&document,&state,context,g,r)
            ||!document.bridge.ios_archive.candidate_claim_matches(&claim)||!claim.current(){return Err(invalid());}
        let bytes=claim.own_backing().ok_or_else(BridgeError::cleanup_unknown)?;
        let admission=lookup_memory::local_ios_candidate_admission(&document,&state,self,bytes).map_err(|_|BridgeError::cleanup_unknown())?;
        Ok((crate::vault_keyring_macos::LocalInput::admitted(LocalHistoryKeyGrant{claim}),admission))
    }
    pub(crate) fn claim_candidate_helper(&self,claim:&crate::saved_command_owner::LocalHistoryHelperClaim,go:bool)->Result<(),crate::vault_keyring_macos::Problem>{
        use crate::vault_keyring_macos::Problem;
        let document=self.candidate_document.as_ref().and_then(std::sync::Weak::upgrade).ok_or(Problem::Unavailable)?;
        let state=document.state.lock().map_err(|_|Problem::CleanupUnknown)?;
        let Some((material,context,g,r))=claim.ios_candidate_context() else{return Err(Problem::Protocol);};
        if !std::ptr::eq(self,material.as_ref())||!self.candidate_matches(&document,&state,context,g,r)
            ||!document.bridge.ios_archive.candidate_helper_matches(claim){return Err(Problem::Interrupted);}
        claim.claim(go)
    }
}

// DATA-only collection after native admission. Also exercised by focused
// synthetic borrower tests; those tests grant no native profile or store proof.
pub(super) fn borrow_material(state: &DocumentState, context: &wire::Context,
    registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<IOSSigningMaterial>, BridgeError> {
    if !context.signed() { return Err(invalid()); }
    let native = state.context.as_ref().ok_or_else(invalid)?.clone();
    let policy = context.signing.as_ref().ok_or_else(invalid)?;
    if native.project_id != context.project_id || native.registry_generation != registration || native.project != *project
        || native.platform != Platform::Ios || native.stage != Stage::Candidate || native.purpose != Purpose::Signing
        || native.draft.is_empty() || native.draft.len() > 512 * 1024 || !(2..=4).contains(&policy.assignments.len()) { return Err(invalid()); }
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
    let original = Arc::new(IOSSigningMaterial { context: context.clone(), candidate_document:None, native, keys, payloads });
    original.parts()?;
    if !original.current(state, registration, project) { return Err(invalid()); }
    Ok(original)
}

impl DocumentBinding {
    pub(super) fn review_ios_material(&self, state: &DocumentState, context: &wire::Context,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<IOSSigningMaterial>, BridgeError> {
        // Same actual document mutex. The existing saved-owner busy/disabled/
        // stopping gates exclude new asset allocation through its real finality.
        if !self.native_qualified() || encrypted_mode(state) && !self.persistence_qualified() { return Err(invalid()); }
        let mut original=borrow_material(state,context,registration,project)?;
        if context.candidate(){Arc::get_mut(&mut original).ok_or_else(invalid)?.candidate_document=Some(Arc::downgrade(&self.inner));}
        Ok(original)
    }

    pub(super) fn recheck_ios_material(&self, state: &DocumentState, original: &Arc<IOSSigningMaterial>,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<(), BridgeError> {
        if !self.native_qualified() || encrypted_mode(state) && !self.persistence_qualified() || !original.current(state, registration, project) { return Err(invalid()); }
        if original.context.candidate()&&!original.candidate_matches(&self.inner,state,&original.context,registration,project){return Err(invalid());}
        original.parts()?; Ok(())
    }
}

#[cfg(test)]
mod candidate_tests {
    use super::*;
    #[test]
    fn ios_candidate_comparison_material_cannot_mint_document_grant(){
        let context=wire::tests::candidate_context();
        let root=asset_source::RegisteredRoot{path:"/inert/candidate".into(),identity:asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        let native=Arc::new(NativeContext{execution_mode:commands::ExecutionMode::Github,revision:2,
            project_id:context.project_id.clone(),project:root.clone(),registry_generation:7,draft:b"{}".to_vec(),
            platform:Platform::Ios,stage:Stage::Candidate,purpose:Purpose::Signing});
        let mut material=IOSSigningMaterial{context:context.clone(),candidate_document:None,native,keys:vec![],payloads:vec![]};
        assert!(material.matches(&context,7,&root));assert!(!material.candidate_current(&context,7,&root));
        material.candidate_document=Some(std::sync::Weak::new());assert!(!material.candidate_current(&context,7,&root));
        assert!(!material.matches(&context,8,&root));assert!(!material.matches(&wire::tests::signed_context(),7,&root));
        let mut other=root.clone();other.path="/inert/other".into();assert!(!material.matches(&context,7,&other));
    }
}
