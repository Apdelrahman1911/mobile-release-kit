//! One current assigned field borrowed from this document, not a vault export.
//! Only this module constructs the loan. No serializer or plaintext Debug/Clone.
use super::*;
use crate::github_setup_protocol as wire;
use sha2::{Digest,Sha256};
use zeroize::Zeroizing;

pub(crate) struct GitHubSecretMaterial {
    native:Arc<NativeContext>,key:RecordKey,payload:Arc<Payload>,
    selection:wire::SecretSelection,source:wire::SecretSource,
}
// The full initialized allocation is retained and wiped, even for short frames.
pub(crate) struct GitHubSecretFrame {bytes:Zeroizing<Vec<u8>>,used:usize}
impl GitHubSecretFrame {
    pub(crate) fn bytes(&self)->&[u8]{&self.bytes[..self.used]}
    pub(crate) fn retained_heap_bytes(&self)->usize{self.bytes.capacity()}
}
fn refused(reason:wire::Reason)->BridgeError{crate::github_setup_session::refused(reason)}
pub(super) fn assigned<'a>(state:&'a DocumentState,key:&RecordKey,kind:Kind,native:&Arc<NativeContext>)->Option<&'a Arc<Payload>>{
    if state.stopping||state.unknown||state.exhausted||state.lock_pending||state.retiring||state.quit_pending
        ||!state.lifetime.original_bound()||!state.context.as_ref().is_some_and(|v|Arc::ptr_eq(v,native))
        ||!state.assignments.iter().any(|a|a.record_id==key.id&&a.record_revision==key.revision
            &&a.context_revision==native.revision&&a.kind==kind&&a.availability==AssignmentAvailability::Available){return None}
    if state.session&&!encrypted_mode(state){return state.records.iter().find(|r|r.key==*key&&r.payload.kind==kind
        &&!r.mutation_pending&&r.payload.usable_source()).map(|r|&r.payload)}
    #[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
    {vault::assigned_payload(state,key,kind,native)}
    #[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
    {None}
}
fn platform(value:Platform)->wire::SecretPlatform{match value{Platform::Android=>wire::SecretPlatform::Android,
    Platform::Ios=>wire::SecretPlatform::Ios,Platform::Project=>wire::SecretPlatform::Project}}
fn purpose(value:Purpose)->wire::SecretPurpose{match value{Purpose::Full=>wire::SecretPurpose::Full,
    Purpose::Signing=>wire::SecretPurpose::Signing,Purpose::Store=>wire::SecretPurpose::Store}}
fn stage(value:Stage)->wire::EnvironmentStage{match value{Stage::Candidate=>wire::EnvironmentStage::Candidate,
    Stage::ExternalTesting=>wire::EnvironmentStage::ExternalTesting,Stage::Production=>wire::EnvironmentStage::Production}}
fn encoded_size(length:usize,encoding:wire::SecretEncoding)->Option<usize>{match encoding{
    wire::SecretEncoding::Utf8=>(length<=wire::SECRET_PLAINTEXT_LIMIT).then_some(length),
    wire::SecretEncoding::Base64=>(length<=wire::SECRET_RAW_FILE_LIMIT).then(||length.checked_add(2)?.checked_div(3)?.checked_mul(4)).flatten(),
}}
fn field<'a>(payload:&'a Payload,requirement:wire::SecretRequirement)->Result<&'a [u8],BridgeError>{
    if payload.kind.name()!=requirement.record_kind(){return Err(refused(wire::Reason::MaterialUnavailable))}
    if requirement.encoding()==wire::SecretEncoding::Base64{
        payload.material.as_ref().filter(|m|m.observation.is_observed()).map(|m|m.bytes()).ok_or_else(||refused(wire::Reason::MaterialUnavailable))
    }else{payload.fields.as_ref().and_then(|f|f.borrow_value(requirement.field())).map(str::as_bytes)
        .ok_or_else(||refused(wire::Reason::MaterialUnavailable))}
}
impl GitHubSecretMaterial {
    pub(super) fn census_parts(&self)->(&Arc<NativeContext>,&Arc<Payload>){(&self.native,&self.payload)}
    pub(crate) fn source(&self)->&wire::SecretSource{&self.source}
    pub(crate) fn selection(&self)->&wire::SecretSelection{&self.selection}
    pub(super) fn current(&self,state:&DocumentState,project_id:&str,registration:u32,root:&asset_source::RegisteredRoot)->bool{
        self.native.project_id==project_id&&self.native.registry_generation==registration&&self.native.project==*root
            &&self.native.revision==self.selection.source.context_revision&&stage(self.native.stage)==self.selection.stage
            &&assigned(state,&self.key,self.payload.kind,&self.native).is_some_and(|p|Arc::ptr_eq(p,&self.payload))
            &&field(&self.payload,self.selection.requirement).ok().and_then(|v|encoded_size(v.len(),self.source.material.encoding))
                ==Some(self.source.material.plaintext_bytes as usize)
    }
    // Full backing is visited by the document's existing shared-Arc census;
    // this method reports only this loan's uniquely owned nonsecret allocations.
    pub(super) fn own_retained_heap_bytes(&self)->Option<usize>{self.key.id.0.capacity()
        .checked_add(self.selection.retained_heap_bytes())?.checked_add(self.source.retained_heap_bytes()?)}
    pub(crate) fn frame(&self,public_key:&[u8;32])->Result<GitHubSecretFrame,BridgeError>{
        let value=field(&self.payload,self.selection.requirement)?;
        let length=encoded_size(value.len(),self.source.material.encoding).filter(|n|*n>0
            &&*n==self.source.material.plaintext_bytes as usize).ok_or_else(||refused(wire::Reason::MaterialTooLarge))?;
        let mut bytes=Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(wire::SECRET_REQUEST_LIMIT).map_err(|_|refused(wire::Reason::ResourcesUnavailable))?;
        if bytes.capacity()>wire::SECRET_REQUEST_LIMIT{return Err(refused(wire::Reason::ResourcesUnavailable))}
        bytes.resize(wire::SECRET_REQUEST_LIMIT,0);
        bytes[..8].copy_from_slice(b"MRKSEAL1");bytes[8..12].copy_from_slice(&(length as u32).to_be_bytes());
        bytes[12..44].copy_from_slice(public_key);
        let out=&mut bytes[44..44+length];
        match self.source.material.encoding{
            wire::SecretEncoding::Utf8=>out.copy_from_slice(value),
            wire::SecretEncoding::Base64=>{
                // Standard padded encoding directly into its already charged
                // destination. No intermediate plaintext String/Vec/file.
                const ALPHABET:&[u8;64]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                for (input,output) in value.chunks(3).zip(out.chunks_exact_mut(4)){
                    let a=input[0];let b=input.get(1).copied().unwrap_or(0);let c=input.get(2).copied().unwrap_or(0);
                    output[0]=ALPHABET[(a>>2)as usize];output[1]=ALPHABET[(((a&3)<<4)|(b>>4))as usize];
                    output[2]=if input.len()>1{ALPHABET[(((b&15)<<2)|(c>>6))as usize]}else{b'='};
                    output[3]=if input.len()>2{ALPHABET[(c&63)as usize]}else{b'='};
                }
            }
        }
        Ok(GitHubSecretFrame{bytes,used:44+length})
    }
}
pub(super) fn borrow_material(state:&DocumentState,selection:&wire::SecretSelection,project_id:&str,registration:u32,
    root:&asset_source::RegisteredRoot)->Result<Arc<GitHubSecretMaterial>,BridgeError>{
    if !selection.valid(){return Err(refused(wire::Reason::InvalidInput))}
    let native=state.context.as_ref().ok_or_else(||refused(wire::Reason::MaterialUnavailable))?.clone();
    if native.project_id!=project_id||native.registry_generation!=registration||native.project!=*root||native.revision!=selection.source.context_revision
        ||stage(native.stage)!=selection.stage||platform(native.platform)!=selection.requirement.platform()
        ||native.draft.is_empty()||native.draft.len()>524288{return Err(refused(wire::Reason::MaterialChanged))}
    let key=RecordKey{id:Token(selection.source.record_id.clone()),revision:selection.source.record_revision};
    let assignment=state.assignments.iter().find(|a|a.record_id==key.id&&a.record_revision==key.revision
        &&a.context_revision==native.revision&&a.kind.name()==selection.requirement.record_kind()
        &&a.availability==AssignmentAvailability::Available).ok_or_else(||refused(wire::Reason::MaterialUnavailable))?;
    let payload=assigned(state,&key,assignment.kind,&native).ok_or_else(||refused(wire::Reason::MaterialUnavailable))?.clone();
    let raw=field(&payload,selection.requirement)?;
    let plaintext=encoded_size(raw.len(),selection.requirement.encoding()).filter(|n|*n>0)
        .ok_or_else(||refused(wire::Reason::MaterialTooLarge))?;
    let path=root.path.to_str().filter(|v|v.starts_with('/')&&v.len()<=4096&&!v.bytes().any(|b|b<32||b==127))
        .ok_or_else(||refused(wire::Reason::TargetChanged))?;
    let identity=root.identity.posix().map_err(|_|refused(wire::Reason::TargetChanged))?.preflight_identity();
    let source=wire::SecretSource{root:path.to_owned(),root_identity:wire::SecretRootIdentity{device:identity.device,inode:identity.inode,
        mode:identity.mode,uid:identity.uid,gid:identity.gid},draft:wire::SecretContent{bytes:native.draft.len()as u32,
        sha256:format!("{:x}",Sha256::digest(&native.draft))},platform:platform(native.platform),purpose:purpose(native.purpose),
        material:wire::SecretMaterialFacts{encoding:selection.requirement.encoding(),plaintext_bytes:plaintext as u32}};
    let result=Arc::new(GitHubSecretMaterial{native,key,payload,selection:selection.clone(),source});
    if !result.current(state,project_id,registration,root){return Err(refused(wire::Reason::MaterialChanged))}
    Ok(result)
}
impl DocumentBinding {
    pub(super) fn review_github_secret_material(&self,state:&DocumentState,selection:&wire::SecretSelection,
        project_id:&str,registration:u32,root:&asset_source::RegisteredRoot)->Result<Arc<GitHubSecretMaterial>,BridgeError>{
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))
            ||!self.native_qualified()||encrypted_mode(state)&&!self.persistence_qualified(){return Err(refused(wire::Reason::Unqualified))}
        borrow_material(state,selection,project_id,registration,root)
    }
}

#[cfg(test)]
pub(super) fn data_loan(native:Arc<NativeContext>,payload:Arc<Payload>)->Arc<GitHubSecretMaterial>{
    Arc::new(GitHubSecretMaterial{native,payload,key:RecordKey{id:Token("1".repeat(32)),revision:2},
        selection:wire::SecretSelection{mode:wire::SecretMode::Create,stage:wire::EnvironmentStage::Candidate,
            requirement:wire::SecretRequirement::AndroidStorePassword,
            source:wire::SecretRecord{record_id:"1".repeat(32),record_revision:2,context_revision:1}},
        source:wire::SecretSource{root:"/inert/project".into(),root_identity:wire::SecretRootIdentity{device:"1".into(),inode:"2".into(),mode:0o40700,uid:1,gid:1},
            draft:wire::SecretContent{bytes:27,sha256:"b".repeat(64)},platform:wire::SecretPlatform::Android,purpose:wire::SecretPurpose::Signing,
            material:wire::SecretMaterialFacts{encoding:wire::SecretEncoding::Utf8,plaintext_bytes:4}}})
}
