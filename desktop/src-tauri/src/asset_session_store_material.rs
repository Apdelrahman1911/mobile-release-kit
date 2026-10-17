//! A private loan of an assigned local ADC snapshot, never a renderer path or
//! environment map. This does not authorize Store execution or authenticate Google.
use super::*;
use crate::local_store_preflight_protocol as wire;
use sha2::{Digest, Sha256};

pub(crate) const MATERIAL_PREFIX: &[u8] = b"MRK-STORE-MATERIAL/1\n";
pub(crate) const MATERIAL_SUFFIX: &[u8] = b"\nMRK-STORE-MATERIAL-END\n";

pub(crate) struct SelectedStoreMaterial {
    native: Arc<NativeContext>, key: RecordKey, payload: Arc<Payload>,
    command: Option<StoreCommand>, prepare_document:Option<std::sync::Weak<Inner>>,
    execute_tools:Option<Arc<crate::saved_command_owner::ExecuteToolLoan>>,
}
#[derive(Clone,PartialEq,Eq)]
enum StoreCommand {Access(wire::Context),Prepare(crate::local_store_prepare_protocol::Context),Reconcile(crate::local_store_reconcile_protocol::Context),Execute(crate::local_store_execute_protocol::Context)}
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
    pub(super) fn own_retained_heap_bytes(&self) -> Option<usize> {
        let mut bytes = self.key.id.0.capacity();
        if let Some(command)=&self.command {
            let (common,extra)=match command {
                StoreCommand::Access(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[0;3]),
                StoreCommand::Prepare(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[c.candidate_operation_id.capacity(),c.candidate_sha256.capacity(),c.confirmation.capacity()]),
                StoreCommand::Reconcile(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[c.candidate_operation_id.capacity(),c.candidate_sha256.capacity(),c.confirmation.capacity()]),
                StoreCommand::Execute(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[c.candidate_operation_id.capacity(),c.candidate_sha256.capacity(),c.confirmation.capacity()]),
            };for n in common.into_iter().chain(extra){bytes=bytes.checked_add(n)?;}
        }
        if let Some(StoreCommand::Reconcile(c))=&self.command {bytes=bytes.checked_add(c.intent_sha256.capacity())?;}
        if let Some(StoreCommand::Execute(c))=&self.command {
            for n in [c.intent_sha256.capacity(),c.toolchain_selection.instance.capacity(),c.toolchain_selection.record_sha256.capacity(),c.toolchain_selection.inventory_sha256.capacity(),c.toolchain_selection.os_provider_sha256.capacity()] {bytes=bytes.checked_add(n)?;}
        }
        if let Some(loan)=&self.execute_tools{bytes=bytes.checked_add(loan.own_backing_bytes()?)?;}
        Some(bytes)
    }
    pub(crate) fn matches(&self, context: &wire::Context, registration: u32, root: &asset_source::RegisteredRoot) -> bool {
        matches!(self.command.as_ref(),Some(StoreCommand::Access(c)) if c==context) && self.native.registry_generation == registration && self.native.project == *root
            && self.native.project_id == context.project_id && self.native.revision == context.credential_context_revision
            && self.key.id.0 == context.record_id && self.key.revision == context.record_revision
            && self.native.execution_mode == commands::ExecutionMode::Local && self.native.platform == Platform::Android
            && matches!(self.native.purpose, Purpose::Full | Purpose::Store)
    }
    pub(crate) fn context_data(&self) -> Result<wire::Content, BridgeError> {
        if self.command.is_none() { return Err(refused()); }
        Ok(wire::Content { bytes: self.native.draft.len() as u32, sha256: format!("{:x}", Sha256::digest(&self.native.draft)) })
    }
    // Only the admitted original Session's private writer consumes these same
    // payload bytes; holding the Arc keeps them alive until all original joins.
    pub(crate) fn parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
        if self.command.is_none() { return Err(refused()); }
        let mut parts = Vec::new(); parts.try_reserve_exact(1).map_err(|_| refused())?;
        parts.push(("google-service-account", bytes(&self.payload).ok_or_else(refused)?));
        Ok(parts)
    }
    pub(crate) fn header(&self) -> Result<Vec<u8>, BridgeError> {
        let parts = self.parts()?;
        let mut header = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,
            "files":[{"role":"google-service-account","bytes":parts[0].1.len()}]})).map_err(|_| refused())?;
        header.push(b'\n'); if header.len() > 1024 { return Err(refused()); } Ok(header)
    }
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
    let original = Arc::new(SelectedStoreMaterial { native, key, payload, command: None,prepare_document:None,execute_tools:None });
    if !original.current(state, original.native.registry_generation, &original.native.project) { return Err(refused()); }
    Ok(original)
}
pub(super) fn borrow_preflight_material(state: &DocumentState, context: &wire::Context,
    registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
    let mut original = borrow_material(state, commands::RecordRef { record_id: &context.record_id,
        expected_revision: context.record_revision }, context.credential_context_revision)?;
    Arc::get_mut(&mut original).ok_or_else(refused)?.command = Some(StoreCommand::Access(context.clone()));
    if !original.matches(context, registration, project) || !original.current(state, registration, project) { return Err(refused()); }
    original.parts()?;
    Ok(original)
}

impl DocumentBinding {
    pub(super) fn review_store_preflight_material(&self, state: &DocumentState, context: &wire::Context,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))
            || !self.native_qualified() || encrypted_mode(state) && !self.persistence_qualified() { return Err(refused()); }
        borrow_preflight_material(state, context, registration, project)
    }
    pub(super) fn recheck_store_preflight_material(&self, state: &DocumentState, original: &Arc<SelectedStoreMaterial>,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<(), BridgeError> {
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))
            || !self.native_qualified() || encrypted_mode(state) && !self.persistence_qualified()
            || !original.current(state, registration, project) || !matches!(original.command,Some(StoreCommand::Access(_))) { return Err(refused()); }
        original.parts()?; Ok(())
    }
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

#[cfg(all(test,any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),
    all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
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
    fn store_command_loan_binds_canonical_context_and_retains_private_writer_bytes() {
        let mut state=model(); let root=state.context.as_ref().unwrap().project.clone();
        let value=serde_json::json!({"projectId":"inert-project","draftRevision":1,"baselineGeneration":1,
            "savedConfig":{"bytes":999,"sha256":"d".repeat(64)},
            "savedVersion":{"source":"release/version.properties","bytes":20,"sha256":"e".repeat(64),"name":"1.2.3","build":42},
            "credentialContextRevision":2,"recordId":"a".repeat(32),"recordRevision":1,"executionMode":"local"});
        let context=wire::prepare(&value).unwrap().context();
        let unscoped=borrow_material(&state,commands::RecordRef {record_id:&context.record_id,expected_revision:1},2).unwrap();
        assert!(unscoped.parts().is_err() && unscoped.context_data().is_err());
        let original=borrow_preflight_material(&state,&context,7,&root).unwrap();
        assert!(original.matches(&context,7,&root));
        let mut changed=context.clone();changed.draft_revision+=1;assert!(!original.matches(&changed,7,&root));
        changed=context.clone();changed.record_revision+=1;assert!(borrow_preflight_material(&state,&changed,7,&root).is_err());
        let canonical=original.context_data().unwrap();
        assert_eq!(canonical.bytes,2);assert_ne!(canonical,context.saved_config);
        let parts=original.parts().unwrap();
        assert_eq!(parts[0].0,"google-service-account");
        assert_eq!(parts[0].1.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        let header=String::from_utf8(original.header().unwrap()).unwrap();
        assert!(!header.contains("PRIVATE") && !header.contains("client_email"));
        let held=Arc::downgrade(&original.payload);
        state.lock_pending=true;assert!(!original.current(&state,7,&root));
        drop(unscoped);drop(state);assert!(held.upgrade().is_some());
        assert!(!original.parts().unwrap()[0].1.is_empty()); // Already-admitted writer, not a new Start.
        drop(original);assert!(held.upgrade().is_none());
    }

    #[test]
    fn local_prepare_comparison_and_private_bytes_do_not_mint_document_grant(){
        let state=model();let root=state.context.as_ref().unwrap().project.clone();
        let mut input=crate::local_store_prepare_protocol::tests::input();input["projectId"]=serde_json::json!("inert-project");
        input["credentialContextRevision"]=serde_json::json!(2);input["recordId"]=serde_json::json!("a".repeat(32));input["recordRevision"]=serde_json::json!(1);
        let context=crate::local_store_prepare_protocol::prepare(&input).unwrap().context();
        let mut original=borrow_material(&state,commands::RecordRef{record_id:&context.record_id,expected_revision:1},2).unwrap();
        assert!(!original.prepare_matches(&context,7,&root)&&original.prepare_context_data().is_err());
        // Comparison DATA may be shaped like the new command, but no native
        // Document minted its Weak/Arc binding. It cannot admit a key helper.
        Arc::get_mut(&mut original).unwrap().command=Some(StoreCommand::Prepare(context.clone()));
        assert!(original.prepare_matches(&context,7,&root));assert!(!original.prepare_current(&context,7,&root));
        let mut changed=context.clone();changed.candidate_sha256="e".repeat(64);assert!(!original.prepare_matches(&changed,7,&root));
        assert!(!original.matches(&wire::tests::context(),7,&root));
        assert_eq!(original.parts().unwrap()[0].1.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        assert!(original.own_retained_heap_bytes().unwrap()>=context.candidate_sha256.capacity()+context.confirmation.capacity());
    }

    #[test]
    fn local_reconcile_comparison_and_private_bytes_do_not_mint_document_grant(){
        let state=model();let root=state.context.as_ref().unwrap().project.clone();
        let mut input=crate::local_store_reconcile_protocol::tests::input();input["projectId"]=serde_json::json!("inert-project");
        input["credentialContextRevision"]=serde_json::json!(2);input["recordId"]=serde_json::json!("a".repeat(32));input["recordRevision"]=serde_json::json!(1);
        let context=crate::local_store_reconcile_protocol::prepare(&input).unwrap().context();
        let mut original=borrow_material(&state,commands::RecordRef{record_id:&context.record_id,expected_revision:1},2).unwrap();
        assert!(!original.reconcile_matches(&context,7,&root)&&original.reconcile_context_data().is_err());
        // Comparison DATA may be shaped like the new command, but no native
        // Document minted its Weak/Arc binding. It cannot admit a key helper.
        Arc::get_mut(&mut original).unwrap().command=Some(StoreCommand::Reconcile(context.clone()));
        assert!(original.reconcile_matches(&context,7,&root));assert!(!original.reconcile_current(&context,7,&root));
        let mut changed=context.clone();changed.candidate_sha256="e".repeat(64);assert!(!original.reconcile_matches(&changed,7,&root));
        assert!(!original.matches(&wire::tests::context(),7,&root));
        assert_eq!(original.parts().unwrap()[0].1.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        assert!(original.own_retained_heap_bytes().unwrap()>=context.candidate_sha256.capacity()+context.confirmation.capacity());
    }

    #[test]
    fn local_execute_comparison_cannot_replace_current_document_catalog_or_material(){
        let state=model();let root=state.context.as_ref().unwrap().project.clone();
        let mut context=crate::local_store_execute_protocol::tests::context();
        context.project_id="inert-project".into();context.credential_context_revision=2;
        context.record_id="a".repeat(32);context.record_revision=1;
        let mut original=borrow_material(&state,commands::RecordRef{record_id:&context.record_id,expected_revision:1},2).unwrap();
        assert!(!original.execute_matches(&context,7,&root)&&original.execute_context_data().is_err());
        Arc::get_mut(&mut original).unwrap().command=Some(StoreCommand::Execute(context.clone()));
        assert!(original.execute_matches(&context,7,&root));
        assert!(!original.execute_current(&context,7,&root));assert!(original.execute_selection().is_none());
        assert!(!original.execute_matches(&context,8,&root));
        let mut changed_root=root.clone();changed_root.path="/inert/other".into();assert!(!original.execute_matches(&context,7,&changed_root));
        for field in 0..4{let mut changed=context.clone();match field{
            0=>changed.intent_sha256="f".repeat(64),1=>changed.candidate_sha256="e".repeat(64),
            2=>changed.toolchain_selection.catalog_generation+=1,_=>changed.record_revision+=1,
        };assert!(!original.execute_matches(&changed,7,&root));}
        assert!(!original.prepare_matches(&crate::local_store_prepare_protocol::tests::context(),7,&root));
        assert_eq!(original.parts().unwrap()[0].1.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        assert!(original.own_retained_heap_bytes().unwrap()>=context.intent_sha256.capacity()+context.candidate_sha256.capacity());
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

impl SelectedStoreMaterial {
    pub(crate) fn prepare_matches(&self,context:&crate::local_store_prepare_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        matches!(self.command.as_ref(),Some(StoreCommand::Prepare(c)) if c==context)
            &&self.native.registry_generation==registration&&self.native.project==*root&&self.native.project_id==context.project_id
            &&self.native.revision==context.credential_context_revision&&self.key.id.0==context.record_id&&self.key.revision==context.record_revision
            &&self.native.execution_mode==commands::ExecutionMode::Local&&self.native.platform==Platform::Android&&self.native.stage==Stage::Candidate
            &&matches!(self.native.purpose,Purpose::Full|Purpose::Store)
    }
    fn prepare_document_matches(&self,document:&Arc<Inner>,state:&DocumentState,context:&crate::local_store_prepare_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        self.prepare_matches(context,registration,root)&&self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).is_some_and(|held|Arc::ptr_eq(&held,document))
            &&!state.lost_observed&&!state.compatibility_picker_pending&&self.current(state,registration,root)
            &&document.bridge.registry_generation()==registration&&document.bridge.native_project(&context.project_id).is_ok_and(|(g,r)|g==registration&&r==*root)
    }
    pub(crate) fn prepare_current(&self,context:&crate::local_store_prepare_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        let Some(document)=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade)else{return false;};
        let Ok(state)=document.state.lock()else{return false;};self.prepare_document_matches(&document,&state,context,registration,root)
    }
    pub(crate) fn prepare_context_data(&self)->Result<crate::local_store_prepare_protocol::Content,BridgeError>{
        if !matches!(self.command,Some(StoreCommand::Prepare(_))){return Err(refused());}
        let c=self.context_data()?;Ok(crate::local_store_prepare_protocol::Content{bytes:c.bytes,sha256:c.sha256})
    }
}
impl DocumentBinding {
    pub(super) fn review_store_prepare_material(&self,state:&DocumentState,context:&crate::local_store_prepare_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->Result<Arc<SelectedStoreMaterial>,BridgeError>{
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))||!self.native_qualified()
            ||encrypted_mode(state)&&!self.persistence_qualified(){return Err(refused());}
        let mut original=borrow_material(state,commands::RecordRef{record_id:&context.record_id,expected_revision:context.record_revision},context.credential_context_revision)?;
        let held=Arc::get_mut(&mut original).ok_or_else(refused)?;
        held.command=Some(StoreCommand::Prepare(context.clone()));held.prepare_document=Some(Arc::downgrade(&self.inner));
        if !original.prepare_document_matches(&self.inner,state,context,registration,root){return Err(refused());}original.parts()?;Ok(original)
    }
    pub(super) fn recheck_store_prepare_material(&self,state:&DocumentState,original:&Arc<SelectedStoreMaterial>,registration:u32,root:&asset_source::RegisteredRoot)->Result<(),BridgeError>{
        let Some(StoreCommand::Prepare(context))=&original.command else{return Err(refused());};
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))||!self.native_qualified()
            ||encrypted_mode(state)&&!self.persistence_qualified()||!original.prepare_document_matches(&self.inner,state,context,registration,root){return Err(refused());}
        original.parts()?;Ok(())
    }
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
impl SelectedStoreMaterial {
    pub(crate) fn admit_prepare(&self,claim:crate::saved_command_owner::LocalHistoryClaim)->Result<(crate::vault_keyring_macos::LocalInput,KeyringMemoryAdmission),BridgeError>{
        let document=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).ok_or_else(refused)?;
        let state=document.state.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let Some((material,context,g,r))=claim.prepare_context()else{return Err(refused());};
        if !std::ptr::eq(self,material.as_ref())||!self.prepare_document_matches(&document,&state,context,g,r)
            ||!document.bridge.local_store_prepare.claim_matches(&claim)||!claim.current(){return Err(refused());}
        let actual=claim.own_backing().ok_or_else(BridgeError::cleanup_unknown)?;
        let admission=lookup_memory::local_store_prepare_admission(&document,&state,self,actual).map_err(|_|BridgeError::cleanup_unknown())?;
        Ok((crate::vault_keyring_macos::LocalInput::admitted(LocalHistoryKeyGrant{claim}),admission))
    }
    pub(crate) fn claim_prepare_helper(&self,claim:&crate::saved_command_owner::LocalHistoryHelperClaim,go:bool)->Result<(),crate::vault_keyring_macos::Problem>{
        use crate::vault_keyring_macos::Problem;
        let document=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).ok_or(Problem::Unavailable)?;
        let state=document.state.lock().map_err(|_|Problem::CleanupUnknown)?;
        let Some((material,context,g,r))=claim.prepare_context()else{return Err(Problem::Protocol);};
        if !std::ptr::eq(self,material.as_ref())||!self.prepare_document_matches(&document,&state,context,g,r)
            ||!document.bridge.local_store_prepare.helper_matches(claim){return Err(Problem::Interrupted);}claim.claim(go)
    }
}

impl SelectedStoreMaterial {
    pub(crate) fn execute_matches(&self,context:&crate::local_store_execute_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        matches!(self.command.as_ref(),Some(StoreCommand::Execute(c)) if c==context)
            &&self.native.registry_generation==registration&&self.native.project==*root&&self.native.project_id==context.project_id
            &&self.native.revision==context.credential_context_revision&&self.key.id.0==context.record_id&&self.key.revision==context.record_revision
            &&self.native.execution_mode==commands::ExecutionMode::Local&&self.native.platform==Platform::Android&&self.native.stage==Stage::Candidate
            &&matches!(self.native.purpose,Purpose::Full|Purpose::Store)
    }
    fn execute_document_matches(&self,document:&Arc<Inner>,state:&DocumentState,context:&crate::local_store_execute_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        self.execute_matches(context,registration,root)&&self.execute_tools.as_ref().is_some_and(|v|v.selected_data()==Some(&context.toolchain_selection))&&self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).is_some_and(|held|Arc::ptr_eq(&held,document))
            &&!state.lost_observed&&!state.compatibility_picker_pending&&self.current(state,registration,root)
            &&document.bridge.registry_generation()==registration&&document.bridge.native_project(&context.project_id).is_ok_and(|(g,r)|g==registration&&r==*root)
    }
    pub(crate) fn execute_current(&self,context:&crate::local_store_execute_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        let Some(document)=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade)else{return false;};
        let Ok(state)=document.state.lock()else{return false;};self.execute_document_matches(&document,&state,context,registration,root)
    }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    pub(super) fn execute_census(&self)->Option<Option<(usize,[Option<Arc<OriginalWork>>;3])>>{
        match &self.command{Some(StoreCommand::Execute(_))=>Some(Some(self.execute_tools.as_ref()?.census()?)),_=>Some(None)}
    }
    pub(crate) fn execute_selection(&self)->Option<&crate::android_build_protocol::MacToolchainSelection>{
        let Some(StoreCommand::Execute(context))=&self.command else{return None;};
        self.execute_tools.as_ref()?.selected_data().filter(|v|*v==&context.toolchain_selection)
    }
    pub(crate) fn execute_context_data(&self)->Result<crate::local_store_execute_protocol::Content,BridgeError>{
        if !matches!(self.command,Some(StoreCommand::Execute(_))){return Err(refused());}
        let c=self.context_data()?;Ok(crate::local_store_execute_protocol::Content{bytes:c.bytes,sha256:c.sha256})
    }
}
impl DocumentBinding {
    pub(super) fn review_store_execute_material(&self,state:&DocumentState,context:&crate::local_store_execute_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->Result<Arc<SelectedStoreMaterial>,BridgeError>{
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))||!self.native_qualified()
            ||encrypted_mode(state)&&!self.persistence_qualified(){return Err(refused());}
        let tools=self.inner.bridge.android_build.execute_tool_loan(&self.inner.session_identity)?.ok_or_else(refused)?;
        if tools.selected_data()!=Some(&context.toolchain_selection){return Err(refused());}
        let mut original=borrow_material(state,commands::RecordRef{record_id:&context.record_id,expected_revision:context.record_revision},context.credential_context_revision)?;
        let held=Arc::get_mut(&mut original).ok_or_else(refused)?;
        held.execute_tools=Some(tools);held.command=Some(StoreCommand::Execute(context.clone()));held.prepare_document=Some(Arc::downgrade(&self.inner));
        if !original.execute_document_matches(&self.inner,state,context,registration,root){return Err(refused());}original.parts()?;Ok(original)
    }
    pub(super) fn recheck_store_execute_material(&self,state:&DocumentState,original:&Arc<SelectedStoreMaterial>,registration:u32,root:&asset_source::RegisteredRoot)->Result<(),BridgeError>{
        let Some(StoreCommand::Execute(context))=&original.command else{return Err(refused());};
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))||!self.native_qualified()
            ||encrypted_mode(state)&&!self.persistence_qualified()||!original.execute_document_matches(&self.inner,state,context,registration,root){return Err(refused());}
        original.parts()?;Ok(())
    }
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
impl SelectedStoreMaterial {
    pub(crate) fn admit_execute(&self,claim:crate::saved_command_owner::LocalHistoryClaim)->Result<(crate::vault_keyring_macos::LocalInput,KeyringMemoryAdmission),BridgeError>{
        let document=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).ok_or_else(refused)?;
        let state=document.state.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let Some((material,context,g,r))=claim.execute_context()else{return Err(refused());};
        if !std::ptr::eq(self,material.as_ref())||!self.execute_document_matches(&document,&state,context,g,r)
            ||!document.bridge.local_store_execute.claim_matches(&claim)||!claim.current(){return Err(refused());}
        let actual=claim.own_backing().ok_or_else(BridgeError::cleanup_unknown)?;
        let admission=lookup_memory::local_store_execute_admission(&document,&state,self,actual).map_err(|_|BridgeError::cleanup_unknown())?;
        Ok((crate::vault_keyring_macos::LocalInput::admitted(LocalHistoryKeyGrant{claim}),admission))
    }
    pub(crate) fn claim_execute_helper(&self,claim:&crate::saved_command_owner::LocalHistoryHelperClaim,go:bool)->Result<(),crate::vault_keyring_macos::Problem>{
        use crate::vault_keyring_macos::Problem;
        let document=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).ok_or(Problem::Unavailable)?;
        let state=document.state.lock().map_err(|_|Problem::CleanupUnknown)?;
        let Some((material,context,g,r))=claim.execute_context()else{return Err(Problem::Protocol);};
        if !std::ptr::eq(self,material.as_ref())||!self.execute_document_matches(&document,&state,context,g,r)
            ||!document.bridge.local_store_execute.helper_matches(claim){return Err(Problem::Interrupted);}claim.claim(go)
    }
}

impl SelectedStoreMaterial {
    pub(crate) fn reconcile_matches(&self,context:&crate::local_store_reconcile_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        matches!(self.command.as_ref(),Some(StoreCommand::Reconcile(c)) if c==context)
            &&self.native.registry_generation==registration&&self.native.project==*root&&self.native.project_id==context.project_id
            &&self.native.revision==context.credential_context_revision&&self.key.id.0==context.record_id&&self.key.revision==context.record_revision
            &&self.native.execution_mode==commands::ExecutionMode::Local&&self.native.platform==Platform::Android&&self.native.stage==Stage::Candidate
            &&matches!(self.native.purpose,Purpose::Full|Purpose::Store)
    }
    fn reconcile_document_matches(&self,document:&Arc<Inner>,state:&DocumentState,context:&crate::local_store_reconcile_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        self.reconcile_matches(context,registration,root)&&self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).is_some_and(|held|Arc::ptr_eq(&held,document))
            &&!state.lost_observed&&!state.compatibility_picker_pending&&self.current(state,registration,root)
            &&document.bridge.registry_generation()==registration&&document.bridge.native_project(&context.project_id).is_ok_and(|(g,r)|g==registration&&r==*root)
    }
    pub(crate) fn reconcile_current(&self,context:&crate::local_store_reconcile_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        let Some(document)=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade)else{return false;};
        let Ok(state)=document.state.lock()else{return false;};self.reconcile_document_matches(&document,&state,context,registration,root)
    }
    pub(crate) fn reconcile_context_data(&self)->Result<crate::local_store_reconcile_protocol::Content,BridgeError>{
        if !matches!(self.command,Some(StoreCommand::Reconcile(_))){return Err(refused());}
        let c=self.context_data()?;Ok(crate::local_store_reconcile_protocol::Content{bytes:c.bytes,sha256:c.sha256})
    }
}
impl DocumentBinding {
    pub(super) fn review_store_reconcile_material(&self,state:&DocumentState,context:&crate::local_store_reconcile_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->Result<Arc<SelectedStoreMaterial>,BridgeError>{
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))||!self.native_qualified()
            ||encrypted_mode(state)&&!self.persistence_qualified(){return Err(refused());}
        let mut original=borrow_material(state,commands::RecordRef{record_id:&context.record_id,expected_revision:context.record_revision},context.credential_context_revision)?;
        let held=Arc::get_mut(&mut original).ok_or_else(refused)?;
        held.command=Some(StoreCommand::Reconcile(context.clone()));held.prepare_document=Some(Arc::downgrade(&self.inner));
        if !original.reconcile_document_matches(&self.inner,state,context,registration,root){return Err(refused());}original.parts()?;Ok(original)
    }
    pub(super) fn recheck_store_reconcile_material(&self,state:&DocumentState,original:&Arc<SelectedStoreMaterial>,registration:u32,root:&asset_source::RegisteredRoot)->Result<(),BridgeError>{
        let Some(StoreCommand::Reconcile(context))=&original.command else{return Err(refused());};
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))||!self.native_qualified()
            ||encrypted_mode(state)&&!self.persistence_qualified()||!original.reconcile_document_matches(&self.inner,state,context,registration,root){return Err(refused());}
        original.parts()?;Ok(())
    }
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
impl SelectedStoreMaterial {
    pub(crate) fn admit_reconcile(&self,claim:crate::saved_command_owner::LocalHistoryClaim)->Result<(crate::vault_keyring_macos::LocalInput,KeyringMemoryAdmission),BridgeError>{
        let document=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).ok_or_else(refused)?;
        let state=document.state.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let Some((material,context,g,r))=claim.reconcile_context()else{return Err(refused());};
        if !std::ptr::eq(self,material.as_ref())||!self.reconcile_document_matches(&document,&state,context,g,r)
            ||!document.bridge.local_store_reconcile.claim_matches(&claim)||!claim.current(){return Err(refused());}
        let actual=claim.own_backing().ok_or_else(BridgeError::cleanup_unknown)?;
        let admission=lookup_memory::local_store_prepare_admission(&document,&state,self,actual).map_err(|_|BridgeError::cleanup_unknown())?;
        Ok((crate::vault_keyring_macos::LocalInput::admitted(LocalHistoryKeyGrant{claim}),admission))
    }
    pub(crate) fn claim_reconcile_helper(&self,claim:&crate::saved_command_owner::LocalHistoryHelperClaim,go:bool)->Result<(),crate::vault_keyring_macos::Problem>{
        use crate::vault_keyring_macos::Problem;
        let document=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).ok_or(Problem::Unavailable)?;
        let state=document.state.lock().map_err(|_|Problem::CleanupUnknown)?;
        let Some((material,context,g,r))=claim.reconcile_context()else{return Err(Problem::Protocol);};
        if !std::ptr::eq(self,material.as_ref())||!self.reconcile_document_matches(&document,&state,context,g,r)
            ||!document.bridge.local_store_reconcile.helper_matches(claim){return Err(Problem::Interrupted);}claim.claim(go)
    }
}
