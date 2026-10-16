//! A private loan of an assigned local ADC snapshot, never a renderer path or
//! environment map. This does not authorize Store execution or authenticate Google.
use super::*;

pub(crate) struct SelectedStoreMaterial {
    native: Arc<NativeContext>, key: RecordKey, payload: Arc<Payload>,
}
fn refused() -> BridgeError {
    BridgeError::new("local_store_credentials", "Select This Mac and assign the current Google Play service-account file for this release context, then review again.")
}
fn bytes(payload: &Payload) -> Option<&[u8]> {
    if payload.kind != Kind::GoogleServiceAccount { return None; }
    payload.material.as_ref().filter(|m| m.observation.is_observed()).map(|m| m.bytes())
        .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
}
impl SelectedStoreMaterial {
    pub(super) fn census_parts(&self) -> (&Arc<NativeContext>, &Arc<Payload>) { (&self.native, &self.payload) }
    pub(super) fn own_retained_heap_bytes(&self) -> usize { self.key.id.0.capacity() }
    pub(super) fn current(&self, state: &DocumentState, registration: u32, root: &asset_source::RegisteredRoot) -> bool {
        self.native.execution_mode == commands::ExecutionMode::Local && self.native.platform == Platform::Android
            && matches!(self.native.purpose, Purpose::Full | Purpose::Store)
            && self.native.registry_generation == registration && self.native.project == *root
            && github_secret::assigned(state, &self.key, Kind::GoogleServiceAccount, &self.native)
                .is_some_and(|current| Arc::ptr_eq(current, &self.payload)) && bytes(&self.payload).is_some()
    }
    // Only the same document's future owned ADC writer may use this callback.
    // Currentness is checked while its caller retains the actual document lock;
    // no free public accessor survives context switch, lock or record replacement.
    pub(super) fn with_bytes<T>(&self, state: &DocumentState, registration: u32,
        root: &asset_source::RegisteredRoot, writer: impl FnOnce(&'static str, &[u8]) -> Result<T, BridgeError>) -> Result<T, BridgeError> {
        if !self.current(state, registration, root) { return Err(refused()); }
        writer("GOOGLE_APPLICATION_CREDENTIALS", bytes(&self.payload).ok_or_else(refused)?)
    }
}
pub(super) fn borrow_material(state: &DocumentState, record: commands::RecordRef<'_>, context_revision: u32)
    -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
    if record.record_id.len() != 32 || !record.record_id.bytes().all(|b| b.is_ascii_hexdigit())
        || record.expected_revision == 0 || context_revision == 0 { return Err(refused()); }
    let native = state.context.as_ref().filter(|v| v.revision == context_revision
        && !v.project_id.is_empty() && !v.draft.is_empty() && v.draft.len() <= 512 * 1024).ok_or_else(refused)?.clone();
    let key = RecordKey { id: Token(record.record_id.into()), revision: record.expected_revision };
    let payload = github_secret::assigned(state, &key, Kind::GoogleServiceAccount, &native).ok_or_else(refused)?.clone();
    let original = Arc::new(SelectedStoreMaterial { native, key, payload });
    if !original.current(state, original.native.registry_generation, &original.native.project) { return Err(refused()); }
    Ok(original)
}
impl DocumentBinding {
    pub(super) fn review_store_material(&self, state: &DocumentState, record: commands::RecordRef<'_>, context_revision: u32)
        -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))
            || !self.native_qualified() || encrypted_mode(state) && !self.persistence_qualified() { return Err(refused()); }
        let original = borrow_material(state, record, context_revision)?;
        #[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        lookup_memory::store_admission_bytes(&self.inner, state, &original, 0).map_err(|_| refused())?;
        Ok(original)
    }
}

#[cfg(all(test,target_os="linux",target_arch="x86_64",target_env="gnu"))]
mod tests {
    use super::*;
    pub(super) fn sample() -> Vec<u8> {
        // Inert format-only envelope, not a usable RSA key or account.
        serde_json::to_vec(&serde_json::json!({"type":"service_account", "project_id":"example-project",
            "private_key_id":"a".repeat(40), "client_email":"release@example-project.iam.gserviceaccount.com",
            "client_id":"123456789012345678901", "token_uri":"https://oauth2.googleapis.com/token",
            "private_key":"-----BEGIN PRIVATE KEY-----\nMBUCAQAwDQYJKoZIhvcNAQEBBQAEAQE=\n-----END PRIVATE KEY-----\n"})).unwrap()
    }
    fn model() -> DocumentState {
        let mut state = super::super::tests::empty_state();
        state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
        let project = asset_source::RegisteredRoot { path:"/inert/local".into(),
            identity:asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
        state.context = Some(Arc::new(NativeContext { execution_mode:commands::ExecutionMode::Local, revision:2,
            project_id:"inert-project".into(), project, registry_generation:7, draft:b"{}".to_vec(),
            platform:Platform::Android,stage:Stage::Candidate,purpose:Purpose::Store }));
        let value = sample();
        let observation = credential_format::inspect(credential_format::FileKind::GoogleServiceAccount,&value,&mut || false).ok().unwrap();
        assert!(observation.is_observed());
        let key = RecordKey { id:Token("a".repeat(32)),revision:1 };
        state.records.push(Record { key:key.clone(),mutation_pending:false,payload:Arc::new(Payload {kind:Kind::GoogleServiceAccount,
            fields:None,material:Some(Arc::new(Material { observation,origin:MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(value)) })) }) });
        state.assignments.push(Assignment { kind:Kind::GoogleServiceAccount,record_id:key.id,record_revision:1,context_revision:2,
            availability:AssignmentAvailability::Available }); state
    }
    #[test]
    fn local_loan_uses_original_private_bytes_and_rejects_stale_context_or_assignment() {
        for change in 0..8 {
            let mut state = model();
            let loan = borrow_material(&state,commands::RecordRef { record_id:&"a".repeat(32),expected_revision:1 },2).unwrap();
            let root = loan.native.project.clone();
            loan.with_bytes(&state,7,&root,|role,value| {
                assert_eq!(role,"GOOGLE_APPLICATION_CREDENTIALS");
                assert_eq!(value.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr()); Ok(())
            }).unwrap();
            let retained = Arc::downgrade(&loan.payload);
            match change {
                0 => { let old=state.context.as_ref().unwrap(); state.context=Some(Arc::new(NativeContext {
                    execution_mode:commands::ExecutionMode::Github,revision:old.revision,project_id:old.project_id.clone(),project:old.project.clone(),
                    registry_generation:old.registry_generation,draft:old.draft.clone(),platform:old.platform,stage:old.stage,purpose:old.purpose })); },
                1 => state.lock_pending=true,
                2 => state.assignments[0].record_revision+=1,
                3 => state.assignments[0].context_revision+=1,
                4 => state.records[0].mutation_pending=true,
                5 => state.assignments[0].availability=AssignmentAvailability::Unavailable,
                6 => state.records[0].payload=model().records.remove(0).payload,
                _ => state.unknown=true,
            }
            assert!(!loan.current(&state,7,&root));
            let mut called=false;assert!(loan.with_bytes(&state,7,&root,|_,_|{called=true;Ok(())}).is_err()); assert!(!called);
            drop(state);assert!(retained.upgrade().is_some());drop(loan);assert!(retained.upgrade().is_none());
        }
        let state=model();
        assert!(borrow_material(&state,commands::RecordRef { record_id:&"a".repeat(32),expected_revision:2 },2).is_err());
        assert!(borrow_material(&state,commands::RecordRef { record_id:&"a".repeat(32),expected_revision:1 },3).is_err());
    }
}
