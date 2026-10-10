//! One current assigned NONSECRET field. No helper, export file or fake secret.
//! Only the existing document can construct it; shared registration stays in
//! asset_session and must include this actual Arc in consent/active census.
use super::*;
use crate::github_setup_protocol as wire;
use sha2::{Digest,Sha256};

pub(crate) struct GitHubVariableMaterial {
    native:Arc<NativeContext>,key:RecordKey,payload:Arc<Payload>,
    selection:wire::VariableSelection,source:wire::VariableSource,
}
fn refused(reason:wire::Reason)->BridgeError{crate::github_setup_session::refused(reason)}
fn stage(value:Stage)->wire::EnvironmentStage{match value{Stage::Candidate=>wire::EnvironmentStage::Candidate,
    Stage::ExternalTesting=>wire::EnvironmentStage::ExternalTesting,Stage::Production=>wire::EnvironmentStage::Production}}
fn platform(value:Platform)->wire::SecretPlatform{match value{Platform::Android=>wire::SecretPlatform::Android,
    Platform::Ios=>wire::SecretPlatform::Ios,Platform::Project=>wire::SecretPlatform::Project}}
fn purpose(value:Purpose)->wire::SecretPurpose{match value{Purpose::Full=>wire::SecretPurpose::Full,
    Purpose::Signing=>wire::SecretPurpose::Signing,Purpose::Store=>wire::SecretPurpose::Store}}
fn field(payload:&Payload,requirement:wire::VariableRequirement)->Result<&str,BridgeError>{
    if payload.kind.name()!=requirement.record_kind(){return Err(refused(wire::Reason::MaterialUnavailable))}
    let value=payload.fields.as_ref().and_then(|fields|fields.borrow_value(requirement.field()))
        .ok_or_else(||refused(wire::Reason::MaterialUnavailable))?;
    if !(1..=wire::VARIABLE_VALUE_LIMIT).contains(&value.len()){return Err(refused(wire::Reason::MaterialTooLarge))}
    // Exact original field: no strip, case change, Base64, replacement record,
    // arbitrary name or self-supplied format policy. Core checks requiredness.
    Ok(value)
}
impl GitHubVariableMaterial {
    pub(super) fn census_parts(&self)->(&Arc<NativeContext>,&Arc<Payload>){(&self.native,&self.payload)}
    pub(crate) fn source(&self)->&wire::VariableSource{&self.source}
    pub(crate) fn selection(&self)->&wire::VariableSelection{&self.selection}
    pub(crate) fn value(&self)->Result<&str,BridgeError>{
        let value=field(&self.payload,self.selection.requirement)?;
        if !self.source.material.matches(value){return Err(refused(wire::Reason::MaterialChanged))}Ok(value)
    }
    pub(super) fn current(&self,state:&DocumentState,project_id:&str,registration:u32,root:&asset_source::RegisteredRoot)->bool{
        self.native.project_id==project_id&&self.native.registry_generation==registration&&self.native.project==*root
            &&self.native.revision==self.selection.source.context_revision&&stage(self.native.stage)==self.selection.stage
            &&github_secret::assigned(state,&self.key,self.payload.kind,&self.native).is_some_and(|p|Arc::ptr_eq(p,&self.payload))
            &&self.value().is_ok()
    }
    // NativeContext/Payload original allocation is deduplicated in the SAME
    // document census. This counts this loan's unique owned backing only.
    pub(super) fn own_retained_heap_bytes(&self)->Option<usize>{self.key.id.0.capacity()
        .checked_add(self.selection.retained_heap_bytes())?.checked_add(self.source.retained_heap_bytes()?)}
    pub(crate) fn go_frame(&self,id:&str,digest:&str,token:&str)->Result<Vec<u8>,BridgeError>{
        wire::encode_variable_go(id,digest,token,self.value()?)
    }
    pub(crate) fn outcome_matches(&self,request:&wire::Request,outcome:&wire::Outcome)->bool{
        let wire::Selection::Variable(selection)=&request.target.selection else{return false};
        if selection!=&self.selection||self.value().is_err(){return false}
        match outcome.reason {
            wire::Reason::None=>match request.kind{
                wire::Kind::Prepare=>matches!(&outcome.prepared,Some(wire::Prepared::Variable(v)) if self.prepared_matches(v)),
                wire::Kind::Apply=>matches!(&request.prepared,Some(wire::Prepared::Variable(v)) if self.prepared_matches(v))
                    &&matches!(&outcome.observed,Some(wire::Observation::Variable(v)) if v.valid_for(selection)
                        &&v.value.as_ref().is_some_and(|v|self.value().is_ok_and(|text|v.matches(text)))),
            },
            wire::Reason::NoChange=>request.kind==wire::Kind::Prepare&&selection.mode==wire::VariableMode::Replace
                &&matches!(&outcome.observed,Some(wire::Observation::Variable(v)) if v.valid_for(selection)
                    &&v.value.as_ref().is_some_and(|v|self.value().is_ok_and(|text|v.matches(text)))),
            _=>true, // A failed closed reply grants no current observation or consent.
        }
    }
    pub(crate) fn prepared_matches(&self,prepared:&wire::VariablePrepared)->bool{
        let wire::Selection::Variable(selection)=&prepared.target.selection else{return false};
        selection==&self.selection&&prepared.valid()&&prepared.configuration.canonical_config==self.source.draft
            &&self.value().is_ok_and(|value|value==prepared.after.value.text)
    }
}
pub(super) fn borrow_material(state:&DocumentState,selection:&wire::VariableSelection,project_id:&str,registration:u32,
    root:&asset_source::RegisteredRoot)->Result<Arc<GitHubVariableMaterial>,BridgeError>{
    if !selection.valid(){return Err(refused(wire::Reason::InvalidInput))}
    let native=state.context.as_ref().ok_or_else(||refused(wire::Reason::MaterialUnavailable))?.clone();
    if native.project_id!=project_id||native.registry_generation!=registration||native.project!=*root
        ||native.revision!=selection.source.context_revision||stage(native.stage)!=selection.stage
        ||platform(native.platform)!=selection.requirement.platform()||native.draft.is_empty()||native.draft.len()>524288{
        return Err(refused(wire::Reason::MaterialChanged))}
    let key=RecordKey{id:Token(selection.source.record_id.clone()),revision:selection.source.record_revision};
    let assignment=state.assignments.iter().find(|a|a.record_id==key.id&&a.record_revision==key.revision
        &&a.context_revision==native.revision&&a.kind.name()==selection.requirement.record_kind()
        &&a.availability==AssignmentAvailability::Available).ok_or_else(||refused(wire::Reason::MaterialUnavailable))?;
    // This is the SAME existing lookup and all its custody/lock/retirement
    // guards, made pub(super) by the consciously composed shared source seam.
    let payload=github_secret::assigned(state,&key,assignment.kind,&native)
        .ok_or_else(||refused(wire::Reason::MaterialUnavailable))?.clone();
    let raw=field(&payload,selection.requirement)?;
    let path=root.path.to_str().filter(|v|v.starts_with('/')&&v.len()<=4096&&!v.chars().any(char::is_control))
        .ok_or_else(||refused(wire::Reason::TargetChanged))?;
    let identity=root.identity.posix().map_err(|_|refused(wire::Reason::TargetChanged))?.preflight_identity();
    let source=wire::VariableSource{root:path.to_owned(),root_identity:wire::SecretRootIdentity{device:identity.device,inode:identity.inode,
        mode:identity.mode,uid:identity.uid,gid:identity.gid},draft:wire::SecretContent{bytes:native.draft.len()as u32,
        sha256:format!("{:x}",Sha256::digest(&native.draft))},platform:platform(native.platform),purpose:purpose(native.purpose),
        material:wire::VariableFingerprint{bytes:raw.len()as u32,sha256:format!("{:x}",Sha256::digest(raw.as_bytes()))}};
    let result=Arc::new(GitHubVariableMaterial{native,key,payload,selection:selection.clone(),source});
    if !result.current(state,project_id,registration,root){return Err(refused(wire::Reason::MaterialChanged))}Ok(result)
}
#[cfg(test)]
pub(super) fn data_loan(native:Arc<NativeContext>,payload:Arc<Payload>,requirement:wire::VariableRequirement)->Arc<GitHubVariableMaterial>{
    // Inert original-storage DATA receiver for the existing census group, never
    // admitted to a document, runtime, consent or native operation.
    let value=field(&payload,requirement).unwrap();
    let fingerprint=wire::VariableFingerprint{bytes:value.len()as u32,sha256:format!("{:x}",Sha256::digest(value.as_bytes()))};
    Arc::new(GitHubVariableMaterial{native,payload,key:RecordKey{id:Token("1".repeat(32)),revision:2},
        selection:wire::VariableSelection{mode:wire::VariableMode::Replace,stage:wire::EnvironmentStage::Candidate,
            requirement,
            source:wire::SecretRecord{record_id:"1".repeat(32),record_revision:2,context_revision:1}},
        source:wire::VariableSource{root:"/inert/project".into(),root_identity:wire::SecretRootIdentity{device:"1".into(),inode:"2".into(),mode:0o40700,uid:1,gid:1},
            draft:wire::SecretContent{bytes:27,sha256:"b".repeat(64)},platform:wire::SecretPlatform::Android,
            purpose:wire::SecretPurpose::Signing,material:fingerprint}})
}
impl DocumentBinding {
    pub(super) fn review_github_variable_material(&self,state:&DocumentState,selection:&wire::VariableSelection,
        project_id:&str,registration:u32,root:&asset_source::RegisteredRoot)->Result<Arc<GitHubVariableMaterial>,BridgeError>{
        if !cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))
            ||!self.native_qualified()||encrypted_mode(state)&&!self.persistence_qualified(){return Err(refused(wire::Reason::Unqualified))}
        borrow_material(state,selection,project_id,registration,root)
    }
}
