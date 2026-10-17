//! The original Document, not a renderer locator, owns enrollment consent.
use super::*;
use crate::local_release_history_protocol as wire;

/// A private current-context loan. Its weak Document edge does not keep a lost
/// window alive or make a cycle through the retained Saved Session.
pub(crate) struct LocalHistoryConsent {
    document:std::sync::Weak<Inner>,pub(super) context:Option<Arc<NativeContext>>,action:wire::Action,platform:Option<wire::CandidatePlatform>,
    pub(super) project_id:String,pub(super) candidate_operation_id:Option<String>,registration:u32,pub(super) root:asset_source::RegisteredRoot,
}
impl LocalHistoryConsent {
    pub(crate) fn action(&self)->wire::Action{self.action}
    pub(crate) fn consent(&self)->&'static str{if self.platform==Some(wire::CandidatePlatform::Ios){wire::IOS_CANDIDATE_CONSENT}else{self.action.consent()}}
    fn matches_context(&self,context:&wire::Context)->bool{
        context.valid()&&self.platform==context.platform&&self.action==context.action&&self.project_id==context.project_id&&self.candidate_operation_id==context.candidate_operation_id
    }
    fn matches(&self,document:&Arc<Inner>,state:&DocumentState,registration:u32,root:&asset_source::RegisteredRoot)->bool{
        self.document.upgrade().is_some_and(|original|Arc::ptr_eq(&original,document))
            && self.selection_matches(state,registration,root)
    }
    fn selection_matches(&self,state:&DocumentState,registration:u32,root:&asset_source::RegisteredRoot)->bool{
        (match (&self.context,&state.context) {(None,None)=>true,(Some(a),Some(b))=>Arc::ptr_eq(a,b),_=>false})
            && self.registration==registration && self.root==*root
            && state.lifetime.original_bound() && !state.lost_observed && !state.unknown && !state.exhausted
            && !state.stopping && !state.quit_pending && !state.retiring && !state.lock_pending
    }
    pub(crate) fn current(&self,context:&wire::Context,registration:u32,root:&asset_source::RegisteredRoot)->bool{
        let Some(document)=self.document.upgrade() else{return false;};
        let Ok(state)=document.state.lock() else{return false;};
        self.matches_context(context) && self.matches(&document,&state,registration,root)
            && document.bridge.registry_generation()==registration
            && document.bridge.native_project(&context.project_id).is_ok_and(|(g,r)|g==registration&&r==*root)
    }
}
impl DocumentBinding {
    pub(crate) fn local_release_history_subscribe(&self)->watch::Receiver<u32>{self.inner.bridge.local_history.subscribe()}
    pub(crate) fn local_release_history_relay_lost(&self){let _state=self.lock();self.inner.bridge.local_history.document_lost();}
    pub(crate) fn local_release_history_status(&self)->Result<wire::Status,BridgeError>{
        let state=self.lock();
        if !self.inner.bridge.local_history.registration_matches(self.inner.bridge.registry_generation()){
            self.inner.bridge.local_history.context_changed();
        }
        self.inner.bridge.local_history.status(self.local_history_gate(&state))
    }
    pub(crate) fn prepare_local_release_history(&self,args:wire::Prepare)->Result<wire::Status,BridgeError>{
        let mut state=self.lock();let gate=self.local_history_gate(&state);
        if gate!=wire::Availability::Available{return Err(crate::local_release_history_owner::unavailable());}
        let selected=self.registry_result(&mut state,self.inner.bridge.native_project(&args.project_id),None);
        let(registration,root)=selected.map_err(|_|crate::local_release_history_owner::unavailable())?;
        // Enrollment has no asset draft/credential prerequisite. An optional
        // existing asset context is only a change snapshot, never local authority.
        let consent=Arc::new(LocalHistoryConsent{document:Arc::downgrade(&self.inner),context:state.context.clone(),
            action:args.action,platform:args.platform,project_id:args.project_id.clone(),candidate_operation_id:args.candidate_operation_id.clone(),registration,root:root.clone()});
        self.inner.bridge.local_history.prepare(args,registration,root,gate,consent)
    }
    pub(crate) fn start_local_release_history(&self,args:wire::Start)->Result<wire::Status,BridgeError>{
        let admitted_at=Instant::now();
        let mut state=self.lock();
        let original=self.inner.bridge.local_history.prepared_consent(&args.operation_id,&args.owner_generation)?;
        let project=self.inner.bridge.local_history.prepared_project(&args.operation_id,&args.owner_generation)?;
        let selected=self.registry_result(&mut state,self.inner.bridge.native_project(&project),None).ok();
        if !selected.as_ref().is_some_and(|(g,r)|original.matches(&self.inner,&state,*g,r)&&project==original.project_id){
            self.inner.bridge.local_history.context_changed();return Err(crate::local_release_history_owner::unavailable());
        }
        let admitted=self.inner.bridge.local_history.start(args,admitted_at,selected,self.local_history_gate(&state))?;
        drop(state);Ok(admitted.release())
    }
    pub(crate) fn cancel_local_release_history(&self,args:wire::Cancel)->Result<wire::Status,BridgeError>{
        let state=self.lock();self.inner.bridge.local_history.cancel(&args.operation_id,&args.owner_generation,self.local_history_gate(&state))
    }
    fn local_history_gate(&self,state:&DocumentState)->wire::Availability{
        use wire::Availability;
        if state.unknown || state.exhausted || self.inner.bridge.supervisor.disabled() || self.inner.bridge.edits.disabled()
            || self.inner.bridge.diagnostics.disabled() || self.inner.bridge.preflight.disabled() || (self.inner.bridge.local_store.disabled() || self.inner.bridge.local_store_prepare.disabled())
            || self.inner.bridge.android_build.disabled() || self.inner.bridge.project_recovery.disabled()
            || self.inner.bridge.ios_archive.disabled() || self.inner.bridge.artifact_inspection.disabled(){return Availability::CleanupUnknown;}
        if state.stopping || self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping()
            || self.inner.bridge.diagnostics.stopping() || self.inner.bridge.preflight.stopping() || (self.inner.bridge.local_store.stopping() || self.inner.bridge.local_store_prepare.stopping())
            || self.inner.bridge.android_build.stopping() || self.inner.bridge.project_recovery.stopping()
            || self.inner.bridge.ios_archive.stopping() || self.inner.bridge.artifact_inspection.stopping(){return Availability::Shutdown;}
        if wire::Profile::current().is_none(){return Availability::UnsupportedPlatform;}
        if state.lost_observed{return Availability::DocumentLost;}
        if !state.lifetime.original_bound(){return Availability::Busy;}
        if state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending || state.maintenance.closed()
            || state.saved_observation.as_ref().is_some_and(|lane|!lane.returned())
            || state.slot.as_ref().is_some_and(|slot|slot.phase!=Phase::Idle||!slot.owner.resources_settled())
            || state.github.registration().is_some() || !self.inner.bridge.edits.can_exit() || self.inner.bridge.edits.preflight_attention()
            || !self.inner.bridge.supervisor.can_exit() || self.inner.bridge.diagnostics.busy() || self.inner.bridge.preflight.busy()
            || (self.inner.bridge.local_store.busy() || self.inner.bridge.local_store_prepare.busy()) || self.inner.bridge.android_build.busy() || self.inner.bridge.project_recovery.busy()
            || self.inner.bridge.ios_archive.busy() || self.inner.bridge.artifact_inspection.busy(){return Availability::Busy;}
        Availability::Available
    }
}

#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(crate) struct LocalHistoryKeyGrant {pub(super) claim:crate::saved_command_owner::LocalHistoryClaim}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
impl LocalHistoryKeyGrant {
    pub(crate) fn into_parts(self)->(mrk_macos_installed_native::local_keychain_wire::Context,
        mrk_macos_installed_native::local_keychain_wire::Operation,zeroize::Zeroizing<[u8;32]>,
        Arc<mrk_macos_installed_native::local_project_lease::ProjectLease>){self.claim.into_input()}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
impl LocalHistoryConsent {
    pub(crate) fn admit_history(&self,claim:crate::saved_command_owner::LocalHistoryClaim)
        ->Result<(crate::vault_keyring_macos::LocalInput,KeyringMemoryAdmission),BridgeError>{
        let document=self.document.upgrade().ok_or_else(crate::local_release_history_owner::unavailable)?;
        let state=document.state.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let Some((c,g,r))=claim.context() else{return Err(crate::local_release_history_owner::unavailable());};
        if !claim.consent().is_some_and(|c|std::ptr::eq(self,c.as_ref()))||!self.matches(&document,&state,g,r)||!self.matches_context(c)||!document.bridge.local_history.claim_matches(&claim)||!claim.current(){return Err(crate::local_release_history_owner::unavailable());}
        let bytes=claim.own_backing().ok_or_else(BridgeError::cleanup_unknown)?;
        let admission=lookup_memory::local_history_admission(&document,&state,self,bytes).map_err(|_|BridgeError::cleanup_unknown())?;
        let input=crate::vault_keyring_macos::LocalInput::admitted(LocalHistoryKeyGrant{claim});Ok((input,admission))
    }
    pub(crate) fn claim_helper(&self,claim:&crate::saved_command_owner::LocalHistoryHelperClaim,go:bool)->Result<(),crate::vault_keyring_macos::Problem>{
        use crate::vault_keyring_macos::Problem;
        let document=self.document.upgrade().ok_or(Problem::Unavailable)?;
        let state=document.state.lock().map_err(|_|Problem::CleanupUnknown)?;
        let Some((c,g,r))=claim.context() else{return Err(Problem::Protocol);};
        if !claim.consent().is_some_and(|c|std::ptr::eq(self,c.as_ref()))||!self.matches(&document,&state,g,r)||!self.matches_context(c)||!document.bridge.local_history.helper_matches(claim){return Err(Problem::Interrupted);}
        claim.claim(go)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_release_history_needs_registered_project_not_credential_context() {
        // Actual DocumentState/consent predicates, inert registration DATA only.
        // No Document/RNG/native provider is constructed or called.
        let root=asset_source::RegisteredRoot{path:"/inert/project".into(),identity:asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        let mut state=super::super::tests::empty_state();
        state.lifetime.crash_hook_installed();state.lifetime.started(true);state.lifetime.finished(true);
        let mut consent=LocalHistoryConsent{document:std::sync::Weak::new(),context:None,action:wire::Action::Enroll,platform:None,
            project_id:"registered-project".into(),candidate_operation_id:None,registration:7,root:root.clone()};
        assert!(consent.selection_matches(&state,7,&root));
        let mut context=wire::Context{project_id:consent.project_id.clone(),execution_mode:wire::ExecutionMode::Local,
            action:wire::Action::ReviewInputs,platform:None,candidate_operation_id:Some("12345678-1234-4234-9234-123456789abc".into())};
        assert!(!consent.matches_context(&context));
        consent.action=wire::Action::ReviewInputs;consent.candidate_operation_id=context.candidate_operation_id.clone();
        assert!(consent.matches_context(&context));
        context.platform=Some(wire::CandidatePlatform::Ios);assert!(!consent.matches_context(&context));
        consent.platform=context.platform;assert!(consent.matches_context(&context));assert_eq!(consent.consent(),wire::IOS_CANDIDATE_CONSENT);
        assert!(!consent.current(&context,7,&root)); // Same DATA platform still lacks a Document owner.
        context.platform=None;assert!(!consent.matches_context(&context));consent.platform=None;
        context.candidate_operation_id=Some("12345678-1234-4234-9234-123456789abd".into());
        assert!(!consent.matches_context(&context));
        context.candidate_operation_id=consent.candidate_operation_id.clone();
        for action in [wire::Action::AbandonInputs,wire::Action::ReviewExecution,wire::Action::ReviewPrepared,wire::Action::ReviewReconcile,wire::Action::ReviewRecovery]{
            context.action=action;assert!(!consent.matches_context(&context));
        }
        // The foreign-action loop must not select this positive case implicitly.
        context.action=wire::Action::ReviewPrepared;
        consent.action=wire::Action::ReviewPrepared;
        assert!(consent.matches_context(&context));
        context.platform=Some(wire::CandidatePlatform::Ios);assert!(!consent.matches_context(&context));
        consent.platform=context.platform;assert!(!consent.matches_context(&context));assert_eq!(consent.consent(),wire::IOS_CANDIDATE_CONSENT);
        assert!(!consent.current(&context,7,&root)); // Same DATA platform still lacks a Document owner.
        context.platform=None;assert!(!consent.matches_context(&context));consent.platform=None;
        context.candidate_operation_id=Some("12345678-1234-4234-9234-123456789abd".into());
        assert!(!consent.matches_context(&context));
        context.candidate_operation_id=consent.candidate_operation_id.clone();
        assert!(!consent.current(&context,7,&root)); // Comparison DATA cannot mint a Document grant.
        context.action=wire::Action::ReviewExecution;assert!(!consent.matches_context(&context));
        consent.action=wire::Action::ReviewExecution;assert!(consent.matches_context(&context));
        context.action=wire::Action::ReviewReconcile;assert!(!consent.matches_context(&context));
        consent.action=wire::Action::ReviewReconcile;assert!(consent.matches_context(&context));
        assert!(!consent.current(&context,7,&root)); // Read-only summary DATA grants no Document.
        consent.action=wire::Action::Enroll;consent.candidate_operation_id=None;
        assert!(!consent.current(&wire::Context{project_id:"registered-project".into(),execution_mode:wire::ExecutionMode::Local,action:wire::Action::Enroll,platform:None,candidate_operation_id:None},7,&root)); // No synthetic Document grant.
        let context=Arc::new(NativeContext{revision:1,project_id:"unrelated-assets".into(),project:root.clone(),registry_generation:7,
            draft:Vec::new(),platform:Platform::Android,stage:Stage::Candidate,purpose:Purpose::Signing,execution_mode:commands::ExecutionMode::Github});
        state.context=Some(context.clone());
        assert!(!consent.selection_matches(&state,7,&root)); // None -> Some burns previous consent.
        consent.context=Some(context);
        assert!(consent.selection_matches(&state,7,&root)); // Github is only a change snapshot.
        assert!(!consent.selection_matches(&state,8,&root));
        let mut other=root.clone();other.path="/inert/other".into();
        assert!(!consent.selection_matches(&state,7,&other));
        state.context=None;assert!(!consent.selection_matches(&state,7,&root));
        consent.context=None;
        state.lost_observed=true;assert!(!consent.selection_matches(&state,7,&root));state.lost_observed=false;
        state.stopping=true;assert!(!consent.selection_matches(&state,7,&root));state.stopping=false;
        state.unknown=true;assert!(!consent.selection_matches(&state,7,&root));
    }
}
