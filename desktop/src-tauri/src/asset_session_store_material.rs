//! A private loan of an assigned local Store snapshot, never a renderer path or
//! environment map. This does not authorize Store execution or authenticate an account.
use super::*;
use crate::local_store_preflight_protocol as wire;
use sha2::{Digest, Sha256};
#[path="asset_session_apple_provisioning_material.rs"]
mod apple_provisioning;
#[path="asset_session_apple_profile_material.rs"]
mod apple_profile;
#[path="asset_session_store_versions.rs"]
mod store_versions;
#[path="asset_session_paired_store_material.rs"]
mod paired_material;
pub(crate) use store_versions::StoreVersionMaterial;

pub(crate) const MATERIAL_PREFIX: &[u8] = b"MRK-STORE-MATERIAL/1\n";
pub(crate) const MATERIAL_SUFFIX: &[u8] = b"\nMRK-STORE-MATERIAL-END\n";

pub(crate) struct SelectedStoreMaterial {
    native: Arc<NativeContext>, key: RecordKey, payload: Arc<Payload>,
    command: Option<StoreCommand>, prepare_document:Option<std::sync::Weak<Inner>>,
    execute_tools:Option<Arc<crate::saved_command_owner::ExecuteToolLoan>>,
    supplemental:[Option<(RecordKey,Arc<Payload>)>;3],
    profile_sources: Option<Arc<vault::profile_sources::AppleProfileSources>>,
}
#[derive(Clone,PartialEq,Eq)]
enum StoreCommand {Provisioning(crate::apple_provisioning_protocol::Context),Access(wire::Context),Prepare(crate::local_store_prepare_protocol::Context),Reconcile(crate::local_store_reconcile_protocol::Context),Execute(crate::local_store_execute_protocol::Context)}
impl StoreCommand {
    fn later(&self)->Option<&crate::local_store_prepare_protocol::LaterStage>{match self {Self::Prepare(c)=>c.later.as_ref(),Self::Execute(c)=>c.later.as_ref(),_=>None}}
    fn assignments(&self)->Option<&crate::local_store_prepare_protocol::StageAssignments>{match self {
        Self::Reconcile(c)=>c.readiness.as_ref().map(|r|&r.supplemental_assignments),
        _=>self.later().and_then(|s|s.supplemental_assignments.as_ref()),
    }}
    fn apple_material(&self)->bool {match self {
        Self::Provisioning(_)=>true,
        Self::Access(c)=>c.platform==wire::AccessPlatform::Ios,
        Self::Prepare(c)=>c.platform==crate::local_store_prepare_protocol::Platform::Ios,
        Self::Execute(c)=>c.platform==crate::local_store_execute_protocol::Platform::Ios,
        Self::Reconcile(c)=>c.platform==crate::local_store_reconcile_protocol::Platform::Ios,
    }}
}
fn refused() -> BridgeError {
    BridgeError::new("local_store_credentials", "Select This Mac and assign the current Store credential for this release context, then review again.")
}
fn bytes(payload: &Payload) -> Option<&[u8]> {
    if payload.kind != Kind::GoogleServiceAccount { return None; }
    payload.material.as_ref().filter(|m| m.observation.is_observed()).map(|m| m.bytes())
        .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
}
fn apple_parts(payload:&Payload)->Option<(&[u8],&[u8],&[u8])>{
    if payload.kind!=Kind::AscP8{return None;}
    let key=payload.material.as_ref().filter(|m|m.observation.is_observed())?.bytes();
    let fields=payload.fields.as_ref()?;
    let key_id=fields.borrow_value("keyId")?.as_bytes();let issuer=fields.borrow_value("issuerId")?.as_bytes();
    if key.is_empty()||key.len()>16*1024||key_id.len()!=10||!key_id.iter().all(|b|b.is_ascii_uppercase()||b.is_ascii_digit())
        ||issuer.len()!=36||!issuer.iter().enumerate().all(|(i,b)|if [8,13,18,23].contains(&i){*b==b'-'}else{b.is_ascii_hexdigit()}){return None;}
    Some((key,key_id,issuer))
}
impl SelectedStoreMaterial {
    pub(super) fn supplemental_census(&self)->impl Iterator<Item=(&RecordKey,&Arc<Payload>)>{self.supplemental.iter().flatten().map(|(k,p)|(k,p))}
    // Future extra stage-frame allocations, charged by the same Document census
    // before Start/Go. Two simultaneous parts() vectors (writer + header); stage
    // header rows are fixed stack DATA and serialization reserves exactly1024.
    // Payload/Fields originals are counted separately, never copied here.
    pub(super) fn supplemental_frame_bytes(&self)->usize {
        if self.paired_context().is_some() { return paired_material::FRAME_BYTES; }
        if self.profile_sources.is_some() { return 2*5*std::mem::size_of::<(&str,&[u8])>()+1024+5*std::mem::size_of::<(&str,usize)>(); }
        if self.apple_material()&&self.command.as_ref().and_then(StoreCommand::assignments).is_some(){
            2*11*std::mem::size_of::<(&str,&[u8])>()+1024+11*std::mem::size_of::<(&str,usize)>()
        }else{0}
    }
    pub(super) fn census_parts(&self) -> (&Arc<NativeContext>, &Arc<Payload>) { (&self.native, &self.payload) }
    pub(super) fn own_retained_heap_bytes(&self) -> Option<usize> {
        let mut bytes = self.key.id.0.capacity();
        if let Some(command)=&self.command {
            let (common,extra)=match command {
                StoreCommand::Provisioning(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[c.display_name.capacity(),c.reference.as_ref().map_or(0,|r|r.operation_id.capacity()),c.reference.as_ref().map_or(0,|r|r.owner_generation.capacity())]),
                StoreCommand::Access(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[c.ios_record.as_ref().map_or(0,|r|r.record_id.capacity()),0,0]),
                StoreCommand::Prepare(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[c.candidate_operation_id.capacity(),c.candidate_sha256.capacity(),c.confirmation.capacity()]),
                StoreCommand::Reconcile(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[c.candidate_operation_id.capacity(),c.candidate_sha256.capacity(),c.confirmation.capacity()]),
                StoreCommand::Execute(c)=>([c.project_id.capacity(),c.saved_config.sha256.capacity(),c.saved_version.source.capacity(),c.saved_version.sha256.capacity(),c.saved_version.name.capacity(),c.record_id.capacity()],[c.candidate_operation_id.capacity(),c.candidate_sha256.capacity(),c.confirmation.capacity()]),
            };for n in common.into_iter().chain(extra){bytes=bytes.checked_add(n)?;}
        }
        if let Some(StoreCommand::Reconcile(c))=&self.command {bytes=bytes.checked_add(c.intent_sha256.capacity())?;
            if let Some(r)=&c.readiness{bytes=bytes.checked_add(r.heap_bytes()?)?;}}
        if let Some(StoreCommand::Execute(c))=&self.command {
            bytes=bytes.checked_add(c.intent_sha256.capacity())?;
            if let Some(tools)=&c.toolchain_selection{for n in [tools.instance.capacity(),tools.record_sha256.capacity(),tools.inventory_sha256.capacity(),tools.os_provider_sha256.capacity()]{bytes=bytes.checked_add(n)?;}}
        }
        if let Some(later)=self.command.as_ref().and_then(StoreCommand::later){bytes=bytes.checked_add(later.heap_bytes()?)?;}
        if let Some(StoreCommand::Execute(c))=&self.command {if let Some(id)=&c.stage_operation_id{bytes=bytes.checked_add(id.capacity())?;}}
        for (key,_) in self.supplemental.iter().flatten(){bytes=bytes.checked_add(key.id.0.capacity())?;}
        if let Some(loan)=&self.execute_tools{bytes=bytes.checked_add(loan.own_backing_bytes()?)?;}
        if let Some(StoreCommand::Provisioning(c))=&self.command { bytes=bytes.checked_add(c.p12_record_id.as_ref().map_or(0,String::capacity))?; }
        Some(bytes)
    }
    fn apple_material(&self)->bool {self.command.as_ref().is_some_and(StoreCommand::apple_material)}
    pub(crate) fn accepts_access_consent(&self,input:&wire::Start)->bool {
        matches!(&self.command,Some(StoreCommand::Access(c)) if input.matches_context(c))
    }
    pub(crate) fn matches(&self, context: &wire::Context, registration: u32, root: &asset_source::RegisteredRoot) -> bool {
        matches!(self.command.as_ref(),Some(StoreCommand::Access(c)) if c==context) && self.native.registry_generation == registration && self.native.project == *root
            && self.native.project_id == context.project_id && self.native.revision == context.credential_context_revision
            && self.key.id.0 == context.record_id && self.key.revision == context.record_revision
            && self.native.execution_mode == commands::ExecutionMode::Local
            && self.access_scope(context)
    }
    pub(crate) fn context_data(&self) -> Result<wire::Content, BridgeError> {
        if self.command.is_none() { return Err(refused()); }
        Ok(wire::Content { bytes: self.native.draft.len() as u32, sha256: format!("{:x}", Sha256::digest(&self.native.draft)) })
    }
    // Only the admitted original Session's private writer consumes these same
    // payload bytes; holding the Arc keeps them alive until all original joins.
    pub(crate) fn parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
        if self.paired_context().is_some() { return self.pair_parts(); }
        if self.profile_sources.is_some() { return self.profile_parts(); }
        if self.command.is_none() { return Err(refused()); }
        let assignments=self.command.as_ref().and_then(StoreCommand::assignments);
        let count=if self.apple_material(){if let Some(a)=assignments{if a.review_demo.is_some(){11}else{9}}else{3}}else{1};
        let mut parts = Vec::new(); parts.try_reserve_exact(count).map_err(|_| refused())?;
        if self.apple_material(){
            let(key,key_id,issuer)=apple_parts(&self.payload).ok_or_else(refused)?;
            parts.extend([("asc-p8",key),("asc-key-id",key_id),("asc-issuer-id",issuer)]);
        }else{parts.push(("google-service-account", bytes(&self.payload).ok_or_else(refused)?));}
        if self.apple_material()&&assignments.is_some(){
            let field=|slot:usize,name:&str|->Result<&[u8],BridgeError>{self.supplemental[slot].as_ref().and_then(|(_,p)|p.fields.as_ref())
                .and_then(|fields|fields.borrow_value(name)).map(str::as_bytes).filter(|v|(1..=4096).contains(&v.len())).ok_or_else(refused)};
            for(role,name)in [("contact-first-name","contactFirstName"),("contact-last-name","contactLastName"),("contact-email","contactEmail"),("contact-phone","contactPhone")]{parts.push((role,field(0,name)?));}
            let key=field(1,"keyBase64")?;let version=field(1,"version")?;
            // Canonical 32-byte standard base64, no decoded secret allocation.
            let alphabet=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            if key.len()!=44||key[43]!=b'='||!key[..43].iter().all(|b|alphabet.contains(b))
                ||!alphabet.iter().position(|b|*b==key[42]).is_some_and(|n|n&3==0)
                ||version.len()>64||!version.iter().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(b)){return Err(refused());}
            parts.extend([("commitment-key-base64",key),("commitment-version",version)]);
            if assignments.is_some_and(|a|a.review_demo.is_some()){
                parts.extend([("demo-username",field(2,"demoUsername")?),("demo-password",field(2,"demoPassword")?)]);
            }
        }
        if parts.len()!=count||parts.iter().try_fold(0usize,|n,(_,v)|n.checked_add(v.len())).is_none_or(|n|n>41114){return Err(refused());}
        Ok(parts)
    }
    pub(crate) fn header(&self) -> Result<Vec<u8>, BridgeError> {
        let parts = self.parts()?;
        if self.paired_context().is_some() || self.apple_material()&&self.command.as_ref().and_then(StoreCommand::assignments).is_some(){
            // Fixed closed roster, not a per-field JSON Value/tree allocation.
            #[derive(Clone,Copy,serde::Serialize)] struct Row<'a>{bytes:usize,role:&'a str}
            #[derive(serde::Serialize)] struct Header<'a>{files:&'a [Row<'a>],#[serde(rename="schemaVersion")] schema_version:u8}
            let mut rows=[Row{bytes:0,role:""};11];
            for(row,(role,bytes))in rows.iter_mut().zip(&parts){*row=Row{bytes:bytes.len(),role};}
            let mut header=Vec::new();header.try_reserve_exact(1024).map_err(|_|refused())?;
            serde_json::to_writer(&mut header,&Header{files:&rows[..parts.len()],schema_version:1}).map_err(|_|refused())?;
            header.push(b'\n');if header.len()>1024{return Err(refused());}return Ok(header);
        }
        let mut header = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,
            "files":parts.iter().map(|(role,bytes)|serde_json::json!({"role":role,"bytes":bytes.len()})).collect::<Vec<_>>()})).map_err(|_| refused())?;
        header.push(b'\n'); if header.len() > 1024 { return Err(refused()); } Ok(header)
    }
    fn supplemental_current(&self,state:&DocumentState)->bool {
        if self.paired_context().is_some() { return self.pair_current(state); }
        let refs=self.command.as_ref().and_then(StoreCommand::assignments);
        let Some(refs)=refs else{return self.supplemental.iter().all(Option::is_none);};
        if !self.apple_material()||!refs.valid(&self.key.id.0){return false;}
        let selected=[Some(&refs.review_contact),Some(&refs.commitment),refs.review_demo.as_ref()];
        selected.into_iter().zip(self.supplemental.iter()).zip([Kind::AppleReviewContact,Kind::OperationCommitment,Kind::AppleReviewDemo])
            .all(|((r,held),kind)|match(r,held){(None,None)=>true,(Some(r),Some((key,payload)))=>key.id.0==r.record_id&&key.revision==r.record_revision
                &&payload.kind==kind&&payload.fields.is_some()&&github_secret::assigned(state,key,kind,&self.native).is_some_and(|p|Arc::ptr_eq(p,payload)),_=>false})
    }
    pub(super) fn current(&self, state: &DocumentState, registration: u32, root: &asset_source::RegisteredRoot) -> bool {
        if self.profile_sources.is_some() { return self.profile_current(state, registration, root); }
        let apple=self.apple_material();
        self.native.execution_mode == commands::ExecutionMode::Local
            && (if let Some(c)=self.paired_context(){self.access_scope(c)}else{self.native.platform==if apple{Platform::Ios}else{Platform::Android} && matches!(self.native.purpose,Purpose::Full|Purpose::Store)})
            && self.native.registry_generation == registration && self.native.project == *root
            && github_secret::assigned(state, &self.key, if apple{Kind::AscP8}else{Kind::GoogleServiceAccount}, &self.native)
                .is_some_and(|current| Arc::ptr_eq(current, &self.payload))
            && self.supplemental_current(state)
            && if apple{apple_parts(&self.payload).is_some()}else{bytes(&self.payload).is_some()}
    }
    // Only the same document's future owned ADC writer may use this callback.
    // Currentness is checked while its caller retains the actual document lock;
    // no free public accessor survives context switch, lock or record replacement.
    pub(super) fn with_bytes<T>(&self, state: &DocumentState, registration: u32,
        root: &asset_source::RegisteredRoot, writer: impl FnOnce(&'static str, &[u8]) -> Result<T, BridgeError>) -> Result<T, BridgeError> {
        if self.paired_context().is_some() || !self.current(state, registration, root) { return Err(refused()); }
        writer("GOOGLE_APPLICATION_CREDENTIALS", bytes(&self.payload).ok_or_else(refused)?)
    }
}
pub(super) fn borrow_material(state: &DocumentState, record: commands::RecordRef<'_>, context_revision: u32)
    -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
    borrow_selected_material(state,record,context_revision,None)
}
fn borrow_selected_material(state:&DocumentState,record:commands::RecordRef<'_>,context_revision:u32,command:Option<StoreCommand>)
    ->Result<Arc<SelectedStoreMaterial>,BridgeError>{
    if record.record_id.len() != 32 || !record.record_id.bytes().all(|b| b.is_ascii_hexdigit())
        || record.expected_revision == 0 || context_revision == 0 { return Err(refused()); }
    let native = state.context.as_ref().filter(|v| v.revision == context_revision
        && !v.project_id.is_empty() && !v.draft.is_empty() && v.draft.len() <= 512 * 1024).ok_or_else(refused)?.clone();
    let key = RecordKey { id: Token(record.record_id.into()), revision: record.expected_revision };
    let kind=if command.as_ref().is_some_and(StoreCommand::apple_material){Kind::AscP8}else{Kind::GoogleServiceAccount};
    let payload = github_secret::assigned(state, &key, kind, &native).ok_or_else(refused)?.clone();
    let mut supplemental:[Option<(RecordKey,Arc<Payload>)>;3]=std::array::from_fn(|_|None);
    paired_material::capture(state,&native,command.as_ref(),&mut supplemental)?;
    if let Some(refs)=command.as_ref().and_then(StoreCommand::assignments){
        if kind!=Kind::AscP8||!refs.valid(&key.id.0){return Err(refused());}
        for ((slot,selected),kind) in supplemental.iter_mut().zip([Some(&refs.review_contact),Some(&refs.commitment),refs.review_demo.as_ref()])
            .zip([Kind::AppleReviewContact,Kind::OperationCommitment,Kind::AppleReviewDemo]){
            if let Some(selected)=selected{
                let key=RecordKey{id:Token(selected.record_id.clone()),revision:selected.record_revision};
                let payload=github_secret::assigned(state,&key,kind,&native).ok_or_else(refused)?.clone();
                if payload.fields.is_none(){return Err(refused());}*slot=Some((key,payload));
            }
        }
    }
    let original = Arc::new(SelectedStoreMaterial { native, key, payload, command,prepare_document:None,execute_tools:None,supplemental,profile_sources:None });
    if !original.current(state, original.native.registry_generation, &original.native.project) { return Err(refused()); }
    Ok(original)
}
pub(super) fn borrow_preflight_material(state: &DocumentState, context: &wire::Context,
    registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
    let original = borrow_selected_material(state, commands::RecordRef { record_id: &context.record_id,
        expected_revision: context.record_revision }, context.credential_context_revision,Some(StoreCommand::Access(context.clone())))?;
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
    fn local_stage_apple_material_retains_every_original_scalar_and_assignment(){
        use crate::local_store_prepare_protocol as prepare;
        for demo in [false,true]{
            let mut state=apple_model();Arc::get_mut(state.context.as_mut().unwrap()).unwrap().stage=Stage::ExternalTesting;
            let mut input=prepare::tests::stage_input(true,false);input["projectId"]=serde_json::json!("inert-project");input["credentialContextRevision"]=serde_json::json!(2);
            input["recordId"]=serde_json::json!("a".repeat(32));input["recordRevision"]=serde_json::json!(1);
            if demo{input["supplementalAssignments"]["reviewDemo"]=serde_json::json!({"recordId":"b".repeat(32),"recordRevision":4});}
            let c=prepare::prepare(&input).unwrap().context();let root=state.context.as_ref().unwrap().project.clone();
            for(kind,id,revision,values)in [
                (Kind::AppleReviewContact,'e',2,serde_json::json!({"contactFirstName":"Fictional","contactLastName":"Reviewer","contactEmail":"review@example.invalid","contactPhone":"+15555550100"})),
                (Kind::OperationCommitment,'f',3,serde_json::json!({"keyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","version":"fixture-v1"})),
                (Kind::AppleReviewDemo,'b',4,serde_json::json!({"demoUsername":"fixture","demoPassword":"inert-password"}))]{
                if kind==Kind::AppleReviewDemo&&!demo{continue;}
                let key=RecordKey{id:Token(id.to_string().repeat(32)),revision};let payload=Arc::new(Payload{kind,material:None,fields:Some(commands::own_fields(kind,&values).ok().expect("fixed fixture refusal"))});
                state.records.push(Record{key:key.clone(),payload,mutation_pending:false});
                state.assignments.push(Assignment{kind,record_id:key.id,record_revision:revision,context_revision:2,availability:AssignmentAvailability::Available});
            }
            let original=borrow_selected_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2,Some(StoreCommand::Prepare(c.clone()))).unwrap();
            assert!(original.current(&state,7,&root)&&original.prepare_matches(&c,7,&root));assert!(!original.prepare_current(&c,7,&root));
            let parts=original.parts().unwrap();assert_eq!(parts.len(),if demo{11}else{9});
            assert_eq!(parts[3].0,"contact-first-name");assert_eq!(parts[3].1.as_ptr(),state.records[1].payload.fields.as_ref().unwrap().borrow_value("contactFirstName").unwrap().as_ptr());
            assert_eq!(parts[7].0,"commitment-key-base64");assert_eq!(parts[7].1.as_ptr(),state.records[2].payload.fields.as_ref().unwrap().borrow_value("keyBase64").unwrap().as_ptr());
            assert_eq!(original.supplemental_census().count(),if demo{3}else{2});
            let header=String::from_utf8(original.header().unwrap()).unwrap();assert!(!header.contains("Fictional")&&!header.contains("fixture-v1"));
            let expected=serde_json::json!({"schemaVersion":1,"files":parts.iter().map(|(role,bytes)|serde_json::json!({"role":role,"bytes":bytes.len()})).collect::<Vec<_>>()});
            assert_eq!(header,format!("{}\n",serde_json::to_string(&expected).unwrap()));
            assert!(original.supplemental_frame_bytes()>=2*parts.capacity()*std::mem::size_of::<(&str,&[u8])>()+1024);
            assert!(original.supplemental_frame_bytes()<4096);drop(parts);
            for index in 1..state.assignments.len(){state.assignments[index].record_revision+=1;assert!(!original.current(&state,7,&root));state.assignments[index].record_revision-=1;assert!(original.current(&state,7,&root));}
            let held:Vec<_>=original.supplemental_census().map(|(_,p)|Arc::downgrade(p)).collect();drop(state);assert!(held.iter().all(|p|p.upgrade().is_some()));
            drop(original);assert!(held.iter().all(|p|p.upgrade().is_none()));
        }
    }

    #[test]
    fn local_external_readiness_material_uses_original_supplemental_assignments_not_a_new_grant(){
        use crate::local_store_reconcile_protocol as reconcile;
        for demo in [false,true]{
            let mut state=apple_model();Arc::get_mut(state.context.as_mut().unwrap()).unwrap().stage=Stage::ExternalTesting;
            let mut v=reconcile::tests::readiness_input();v["projectId"]=serde_json::json!("inert-project");v["credentialContextRevision"]=serde_json::json!(2);
            v["recordId"]=serde_json::json!("a".repeat(32));v["recordRevision"]=serde_json::json!(1);
            if demo{v["supplementalAssignments"]["reviewDemo"]=serde_json::json!({"recordId":"b".repeat(32),"recordRevision":4});}
            let c=reconcile::prepare(&v).unwrap().context();let root=state.context.as_ref().unwrap().project.clone();
            for(kind,id,revision,values)in [
                (Kind::AppleReviewContact,'e',2,serde_json::json!({"contactFirstName":"Fictional","contactLastName":"Reviewer","contactEmail":"review@example.invalid","contactPhone":"+15555550100"})),
                (Kind::OperationCommitment,'f',3,serde_json::json!({"keyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","version":"fixture-v1"})),
                (Kind::AppleReviewDemo,'b',4,serde_json::json!({"demoUsername":"fixture","demoPassword":"inert-password"}))]{
                if kind==Kind::AppleReviewDemo&&!demo{continue;}
                let key=RecordKey{id:Token(id.to_string().repeat(32)),revision};let payload=Arc::new(Payload{kind,material:None,fields:Some(commands::own_fields(kind,&values).ok().expect("fixed fixture refusal"))});
                state.records.push(Record{key:key.clone(),payload,mutation_pending:false});
                state.assignments.push(Assignment{kind,record_id:key.id,record_revision:revision,context_revision:2,availability:AssignmentAvailability::Available});
            }
            let original=borrow_selected_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2,Some(StoreCommand::Reconcile(c.clone()))).unwrap();
            assert!(original.current(&state,7,&root)&&original.reconcile_matches(&c,7,&root));
            // Shaped comparison DATA and all original bytes still do not mint
            // the genuine Document weak grant used by the effect-capable owner.
            assert!(!original.reconcile_current(&c,7,&root));
            assert!(original.reconcile_accepts_consent(reconcile::READINESS_CONSENT));assert!(!original.reconcile_accepts_consent(reconcile::APPLE_CONSENT));
            let parts=original.parts().unwrap();assert_eq!(parts.len(),if demo{11}else{9});
            assert_eq!(parts[0].1.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
            assert_eq!(parts[3].1.as_ptr(),state.records[1].payload.fields.as_ref().unwrap().borrow_value("contactFirstName").unwrap().as_ptr());
            assert_eq!(parts[7].1.as_ptr(),state.records[2].payload.fields.as_ref().unwrap().borrow_value("keyBase64").unwrap().as_ptr());
            assert_eq!(original.supplemental_census().count(),if demo{3}else{2});assert!(original.supplemental_frame_bytes()>1024);
            let expected=serde_json::json!({"schemaVersion":1,"files":parts.iter().map(|(role,bytes)|serde_json::json!({"role":role,"bytes":bytes.len()})).collect::<Vec<_>>()});
            assert_eq!(String::from_utf8(original.header().unwrap()).unwrap(),format!("{}\n",serde_json::to_string(&expected).unwrap()));drop(parts);
            for index in 1..state.assignments.len(){state.assignments[index].record_revision+=1;assert!(!original.current(&state,7,&root));state.assignments[index].record_revision-=1;}
            let mut foreign=c.clone();foreign.readiness.as_mut().unwrap().execution_receipt_sha256="8".repeat(64);assert!(!original.reconcile_matches(&foreign,7,&root));
            let held:Vec<_>=original.supplemental_census().map(|(_,p)|Arc::downgrade(p)).collect();drop(state);assert!(held.iter().all(|p|p.upgrade().is_some()));
            drop(original);assert!(held.iter().all(|p|p.upgrade().is_none()));
        }
    }

    pub(super) fn apple_model()->DocumentState {
        let mut state=model();
        Arc::get_mut(state.context.as_mut().unwrap()).unwrap().platform=Platform::Ios;
        // Minimal canonical PKCS8 envelope with inert private octets, NOT a
        // usable private key. The bundled validator must still prove P256.
        let raw=b"\x30\x1b\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x01\x01".to_vec();
        let observation=credential_format::inspect(credential_format::FileKind::AscP8,&raw,&mut||false).ok().unwrap();
        assert!(observation.is_observed());
        state.records[0].payload=Arc::new(Payload{kind:Kind::AscP8,
            material:Some(Arc::new(Material{observation,origin:MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(raw))})),
            fields:Some(commands::own_fields(Kind::AscP8,&serde_json::json!({"keyId":"ABCDEFGHIJ","issuerId":"12345678-1234-1234-1234-123456789abc"})).ok().unwrap())});
        state.assignments[0].kind=Kind::AscP8;state
    }
    #[test]
    fn apple_access_loan_retains_exact_fields_and_never_lends_google_mutation_material(){
        let mut state=apple_model();let root=state.context.as_ref().unwrap().project.clone();
        let mut c=wire::tests::context();c.project_id="inert-project".into();c.credential_context_revision=2;c.record_id="a".repeat(32);c.record_revision=1;c.platform=wire::AccessPlatform::Ios;
        assert!(borrow_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2).is_err());
        let original=borrow_preflight_material(&state,&c,7,&root).unwrap();let parts=original.parts().unwrap();
        assert_eq!(parts.iter().map(|p|p.0).collect::<Vec<_>>(),vec!["asc-p8","asc-key-id","asc-issuer-id"]);
        assert_eq!(original.supplemental_frame_bytes(),0);
        let payload=&state.records[0].payload;
        assert_eq!(parts[0].1.as_ptr(),payload.material.as_ref().unwrap().bytes().as_ptr());
        assert_eq!(parts[1].1.as_ptr(),payload.fields.as_ref().unwrap().borrow_value("keyId").unwrap().as_ptr());
        assert_eq!(parts[2].1.as_ptr(),payload.fields.as_ref().unwrap().borrow_value("issuerId").unwrap().as_ptr());
        let header=String::from_utf8(original.header().unwrap()).unwrap();assert!(!header.contains("ABCDEFGHIJ")&&!header.contains("12345678"));
        let start=wire::start(&serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":wire::APPLE_CONSENT})).unwrap();
        assert!(original.accepts_access_consent(&start));
        let start=wire::start(&serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":wire::CONSENT})).unwrap();
        assert!(!original.accepts_access_consent(&start));
        let mut google=c.clone();google.platform=wire::AccessPlatform::Android;assert!(!original.matches(&google,7,&root));
        assert!(borrow_preflight_material(&state,&google,7,&root).is_err());
        assert!(original.with_bytes(&state,7,&root,|_,_|Ok(())).is_err());
        let held=Arc::downgrade(&original.payload);state.lock_pending=true;assert!(!original.current(&state,7,&root));
        drop(parts);drop(state);assert!(held.upgrade().is_some());assert_eq!(original.parts().unwrap().len(),3);
        drop(original);assert!(held.upgrade().is_none());
    }
    #[test]
    fn apple_execute_loan_is_original_asc_not_android_loan_or_document_authority(){
        use crate::local_store_execute_protocol as execute;
        let state=apple_model();let root=state.context.as_ref().unwrap().project.clone();
        let mut input=execute::tests::input();input.as_object_mut().unwrap().remove("toolchainSelection");
        input["platform"]=serde_json::json!("ios");input["confirmation"]=serde_json::json!("candidate:ios:1.2.3:42");
        input["projectId"]=serde_json::json!("inert-project");input["credentialContextRevision"]=serde_json::json!(2);input["recordId"]=serde_json::json!("a".repeat(32));input["recordRevision"]=serde_json::json!(1);
        let c=execute::prepare(&input).unwrap().context();
        let original=borrow_selected_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2,Some(StoreCommand::Execute(c.clone()))).unwrap();
        assert!(original.execute_matches(&c,7,&root)&&original.current(&state,7,&root));
        assert!(original.execute_ios()&&original.execute_tools_current()&&original.execute_selection().is_none());
        assert!(!original.execute_current(&c,7,&root)); // Real DocumentWeak is absent.
        let parts=original.parts().unwrap();assert_eq!(parts.iter().map(|p|p.0).collect::<Vec<_>>(),vec!["asc-p8","asc-key-id","asc-issuer-id"]);
        assert_eq!(parts[0].1.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        for token in [execute::CONSENT,execute::APPLE_CONSENT]{let start=execute::start(&serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":token})).unwrap();assert_eq!(original.accepts_execute_consent(&start),token==execute::APPLE_CONSENT);}
        assert!(original.with_bytes(&state,7,&root,|_,_|Ok(())).is_err());
        #[cfg(all(target_os="macos",not(feature="macos-android-registration-helper")))]
        assert!(matches!(original.execute_census(),Some(None)));
    }
    #[test]
    fn apple_reconcile_loan_is_original_asc_and_cannot_grant_android_settlement_or_document(){
        use crate::local_store_reconcile_protocol as reconcile;
        let mut state=apple_model();let root=state.context.as_ref().unwrap().project.clone();
        let mut c=reconcile::tests::ios_context();c.project_id="inert-project".into();c.credential_context_revision=2;c.record_id="a".repeat(32);c.record_revision=1;
        let original=borrow_selected_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2,Some(StoreCommand::Reconcile(c.clone()))).unwrap();
        assert!(original.reconcile_matches(&c,7,&root)&&original.current(&state,7,&root));assert!(!original.reconcile_current(&c,7,&root));
        assert!(original.reconcile_accepts_consent(reconcile::APPLE_CONSENT));
        for token in [reconcile::CONSENT,reconcile::SETTLEMENT_CONSENT,crate::local_store_execute_protocol::APPLE_CONSENT]{assert!(!original.reconcile_accepts_consent(token));}
        let parts=original.parts().unwrap();assert_eq!(parts.iter().map(|p|p.0).collect::<Vec<_>>(),vec!["asc-p8","asc-key-id","asc-issuer-id"]);
        assert_eq!(parts[0].1.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        assert_eq!(parts[1].1.as_ptr(),state.records[0].payload.fields.as_ref().unwrap().borrow_value("keyId").unwrap().as_ptr());
        assert_eq!(parts[2].1.as_ptr(),state.records[0].payload.fields.as_ref().unwrap().borrow_value("issuerId").unwrap().as_ptr());
        assert!(original.execute_tools.is_none());assert!(original.with_bytes(&state,7,&root,|_,_|Ok(())).is_err());
        assert!(borrow_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2).is_err());
        let mut android=c.clone();android.platform=reconcile::Platform::Android;android.confirmation="candidate:android:1.2.3:42".into();
        assert!(!original.reconcile_matches(&android,7,&root));
        assert!(borrow_selected_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2,Some(StoreCommand::Reconcile(android))).is_err());
        let mut settlement=c.clone();settlement.operation=reconcile::Operation::LocalStoreRecoverySettle;settlement.settlement=Some(reconcile::Settlement::RecordCurrentTarget);
        assert!(!original.reconcile_matches(&settlement,7,&root));
        assert!(original.own_retained_heap_bytes().unwrap()>=c.intent_sha256.capacity()+c.candidate_sha256.capacity());
        state.assignments[0].context_revision+=1;assert!(!original.current(&state,7,&root));
    }
    #[test]
    fn apple_prepare_loan_binds_original_command_and_consent_without_google_or_document_grant(){
        use crate::local_store_prepare_protocol as prepare;
        let mut state=apple_model();let root=state.context.as_ref().unwrap().project.clone();
        let mut input=prepare::tests::input();input["platform"]=serde_json::json!("ios");input["confirmation"]=serde_json::json!("candidate:ios:1.2.3:42");
        input["projectId"]=serde_json::json!("inert-project");input["credentialContextRevision"]=serde_json::json!(2);
        input["recordId"]=serde_json::json!("a".repeat(32));input["recordRevision"]=serde_json::json!(1);
        let c=prepare::prepare(&input).unwrap().context();
        let original=borrow_selected_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2,
            Some(StoreCommand::Prepare(c.clone()))).unwrap();
        assert!(original.prepare_matches(&c,7,&root)&&original.current(&state,7,&root));
        assert!(!original.prepare_current(&c,7,&root)); // No actual Document minted this comparison fixture.
        let parts=original.parts().unwrap();assert_eq!(parts.iter().map(|p|p.0).collect::<Vec<_>>(),vec!["asc-p8","asc-key-id","asc-issuer-id"]);
        assert_eq!(parts[0].1.as_ptr(),state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        assert_eq!(parts[1].1.as_ptr(),state.records[0].payload.fields.as_ref().unwrap().borrow_value("keyId").unwrap().as_ptr());
        assert_eq!(parts[2].1.as_ptr(),state.records[0].payload.fields.as_ref().unwrap().borrow_value("issuerId").unwrap().as_ptr());
        for token in [prepare::CONSENT,prepare::APPLE_CONSENT]{let start=prepare::start(&serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":token})).unwrap();
            assert_eq!(original.accepts_prepare_consent(&start),token==prepare::APPLE_CONSENT);}
        assert!(original.with_bytes(&state,7,&root,|_,_|Ok(())).is_err());
        assert!(borrow_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2).is_err());
        let mut android=c.clone();android.platform=prepare::Platform::Android;android.confirmation="candidate:android:1.2.3:42".into();
        assert!(!original.prepare_matches(&android,7,&root));
        assert!(borrow_selected_material(&state,commands::RecordRef{record_id:&c.record_id,expected_revision:1},2,Some(StoreCommand::Prepare(android))).is_err());
        assert!(original.own_retained_heap_bytes().unwrap()>=c.confirmation.capacity()+c.candidate_sha256.capacity());
        state.assignments[0].context_revision+=1;assert!(!original.current(&state,7,&root));
    }
    #[test]
    fn apple_access_key_and_scalar_bounds_refuse_before_private_writer(){
        let mut state=apple_model();let root=state.context.as_ref().unwrap().project.clone();
        let mut c=wire::tests::context();c.project_id="inert-project".into();c.credential_context_revision=2;c.record_id="a".repeat(32);c.record_revision=1;c.platform=wire::AccessPlatform::Ios;
        // Exact native capture may admit larger files, but this operation never
        // borrows beyond its existing16KiB private material bound.
        let payload=Arc::get_mut(&mut state.records[0].payload).unwrap();
        payload.fields=Some(commands::own_fields(Kind::AscP8,&serde_json::json!({"keyId":"too-short","issuerId":"12345678-1234-1234-1234-123456789abc"})).ok().unwrap());
        assert!(borrow_preflight_material(&state,&c,7,&root).is_err());
        payload_restore(&mut state);
        let payload=Arc::get_mut(&mut state.records[0].payload).unwrap();
        let old=payload.material.take().unwrap();
        // Reuse only the inert observed envelope DATA, not a native observation
        // claim about these overlarge bytes; rejection depends on byte bound.
        let observation=credential_format::inspect(credential_format::FileKind::AscP8,old.bytes(),&mut||false).ok().unwrap();
        payload.material=Some(Arc::new(Material{observation,origin:MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(vec![1;16*1024+1]))}));
        assert!(borrow_preflight_material(&state,&c,7,&root).is_err());
    }
    fn payload_restore(state:&mut DocumentState){
        Arc::get_mut(&mut state.records[0].payload).unwrap().fields=Some(commands::own_fields(Kind::AscP8,&serde_json::json!({"keyId":"ABCDEFGHIJ","issuerId":"12345678-1234-1234-1234-123456789abc"})).ok().unwrap());
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
        assert!(original.reconcile_accepts_consent(crate::local_store_reconcile_protocol::CONSENT));
        assert!(!original.reconcile_accepts_consent(crate::local_store_reconcile_protocol::SETTLEMENT_CONSENT));
        let mut settlement=context.clone();settlement.operation=crate::local_store_reconcile_protocol::Operation::LocalStoreRecoverySettle;
        settlement.settlement=Some(crate::local_store_reconcile_protocol::Settlement::RecordCurrentTarget);
        assert!(!original.reconcile_matches(&settlement,7,&root));
        Arc::get_mut(&mut original).unwrap().command=Some(StoreCommand::Reconcile(settlement.clone()));
        assert!(original.reconcile_accepts_consent(crate::local_store_reconcile_protocol::SETTLEMENT_CONSENT));
        assert!(!original.reconcile_accepts_consent(crate::local_store_reconcile_protocol::CONSENT));
        assert!(!original.reconcile_current(&settlement,7,&root));
        Arc::get_mut(&mut original).unwrap().command=Some(StoreCommand::Reconcile(context.clone()));
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
            2=>changed.toolchain_selection.as_mut().unwrap().catalog_generation+=1,_=>changed.record_revision+=1,
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
    pub(crate) fn accepts_prepare_consent(&self,input:&crate::local_store_prepare_protocol::Start)->bool {
        matches!(&self.command,Some(StoreCommand::Prepare(c)) if input.matches_context(c))
    }
    pub(crate) fn prepare_matches(&self,context:&crate::local_store_prepare_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        matches!(self.command.as_ref(),Some(StoreCommand::Prepare(c)) if c==context)
            &&self.native.registry_generation==registration&&self.native.project==*root&&self.native.project_id==context.project_id
            &&self.native.revision==context.credential_context_revision&&self.key.id.0==context.record_id&&self.key.revision==context.record_revision
            &&self.native.execution_mode==commands::ExecutionMode::Local
            &&self.native.platform==if context.platform==crate::local_store_prepare_protocol::Platform::Ios{Platform::Ios}else{Platform::Android}
            &&self.native.stage==context.asset_stage()&&matches!(self.native.purpose,Purpose::Full|Purpose::Store)
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
        let mut original=borrow_selected_material(state,commands::RecordRef{record_id:&context.record_id,expected_revision:context.record_revision},
            context.credential_context_revision,Some(StoreCommand::Prepare(context.clone())))?;
        let held=Arc::get_mut(&mut original).ok_or_else(refused)?;
        held.prepare_document=Some(Arc::downgrade(&self.inner));
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
            &&self.native.execution_mode==commands::ExecutionMode::Local&&self.native.platform==if context.platform==crate::local_store_execute_protocol::Platform::Ios{Platform::Ios}else{Platform::Android}
            &&self.native.stage==context.asset_stage()
            &&matches!(self.native.purpose,Purpose::Full|Purpose::Store)
    }
    pub(crate) fn accepts_execute_consent(&self,input:&crate::local_store_execute_protocol::Start)->bool{
        matches!(&self.command,Some(StoreCommand::Execute(c)) if input.matches_context(c))
    }
    fn execute_tools_match(&self,c:&crate::local_store_execute_protocol::Context)->bool{
        if c.later.is_some(){return c.toolchain_selection.is_none()&&self.execute_tools.is_none();}
        match(c.platform,c.toolchain_selection.as_ref(),self.execute_tools.as_ref()){
            (crate::local_store_execute_protocol::Platform::Android,Some(selection),Some(loan))=>loan.selected_data()==Some(selection),
            (crate::local_store_execute_protocol::Platform::Ios,None,None)=>true,_=>false,
        }
    }
    pub(crate) fn execute_tools_current(&self)->bool{
        matches!(&self.command,Some(StoreCommand::Execute(c)) if self.execute_tools_match(c))
    }
    pub(crate) fn execute_stage(&self)->bool{matches!(&self.command,Some(StoreCommand::Execute(c)) if c.later.is_some()&&self.execute_tools_match(c))}
    pub(crate) fn execute_ios(&self)->bool{
        matches!(&self.command,Some(StoreCommand::Execute(c)) if c.later.is_none()&&c.platform==crate::local_store_execute_protocol::Platform::Ios&&self.execute_tools_match(c))
    }
    fn execute_document_matches(&self,document:&Arc<Inner>,state:&DocumentState,context:&crate::local_store_execute_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        self.execute_matches(context,registration,root)&&self.execute_tools_match(context)&&self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade).is_some_and(|held|Arc::ptr_eq(&held,document))
            &&!state.lost_observed&&!state.compatibility_picker_pending&&self.current(state,registration,root)
            &&document.bridge.registry_generation()==registration&&document.bridge.native_project(&context.project_id).is_ok_and(|(g,r)|g==registration&&r==*root)
    }
    pub(crate) fn execute_current(&self,context:&crate::local_store_execute_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        let Some(document)=self.prepare_document.as_ref().and_then(std::sync::Weak::upgrade)else{return false;};
        let Ok(state)=document.state.lock()else{return false;};self.execute_document_matches(&document,&state,context,registration,root)
    }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    pub(super) fn execute_census(&self)->Option<Option<(usize,[Option<Arc<OriginalWork>>;3])>>{
        match &self.command{Some(StoreCommand::Execute(c))=>{if !self.execute_tools_match(c){return None;}
            if c.later.is_some(){return Some(None);}match c.platform{crate::local_store_execute_protocol::Platform::Android=>Some(Some(self.execute_tools.as_ref()?.census()?)),crate::local_store_execute_protocol::Platform::Ios=>Some(None)}},_=>Some(None)}
    }
    pub(crate) fn execute_selection(&self)->Option<&crate::android_build_protocol::MacToolchainSelection>{
        let Some(StoreCommand::Execute(context))=&self.command else{return None;};
        self.execute_tools.as_ref()?.selected_data().filter(|v|Some(*v)==context.toolchain_selection.as_ref())
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
        let tools=if context.later.is_some(){if context.toolchain_selection.is_some(){return Err(refused());}None}else{match(context.platform,context.toolchain_selection.as_ref()) {
            (crate::local_store_execute_protocol::Platform::Android,Some(selection))=>{
                let tools=self.inner.bridge.android_build.execute_tool_loan(&self.inner.session_identity)?.ok_or_else(refused)?;
                if tools.selected_data()!=Some(selection){return Err(refused());}Some(tools)
            },(crate::local_store_execute_protocol::Platform::Ios,None)=>None,_=>return Err(refused()),
        }};
        let mut original=borrow_selected_material(state,commands::RecordRef{record_id:&context.record_id,expected_revision:context.record_revision},context.credential_context_revision,Some(StoreCommand::Execute(context.clone())))?;
        let held=Arc::get_mut(&mut original).ok_or_else(refused)?;
        held.execute_tools=tools;held.prepare_document=Some(Arc::downgrade(&self.inner));
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
    pub(crate) fn reconcile_accepts_consent(&self,consent:&str)->bool {
        matches!(self.command.as_ref(),Some(StoreCommand::Reconcile(c)) if c.consent()==consent)
    }
    pub(crate) fn reconcile_matches(&self,context:&crate::local_store_reconcile_protocol::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool {
        matches!(self.command.as_ref(),Some(StoreCommand::Reconcile(c)) if c==context)
            &&self.native.registry_generation==registration&&self.native.project==*root&&self.native.project_id==context.project_id
            &&self.native.revision==context.credential_context_revision&&self.key.id.0==context.record_id&&self.key.revision==context.record_revision
            &&self.native.execution_mode==commands::ExecutionMode::Local&&self.native.platform==if context.platform==crate::local_store_reconcile_protocol::Platform::Ios{Platform::Ios}else{Platform::Android}&&self.native.stage==context.asset_stage()
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
        let mut original=borrow_selected_material(state,commands::RecordRef{record_id:&context.record_id,expected_revision:context.record_revision},
            context.credential_context_revision,Some(StoreCommand::Reconcile(context.clone())))?;
        let held=Arc::get_mut(&mut original).ok_or_else(refused)?;
        held.prepare_document=Some(Arc::downgrade(&self.inner));
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
