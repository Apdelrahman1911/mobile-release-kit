//! Actual registration facades on the original Document. Renderer context is
//! comparison DATA; only this private saved-return/Edit witness admits work.
use super::*;
use crate::android_registration_app_protocol as wire;

impl DocumentBinding {
    pub(super) fn reconcile_android_registration_locked(&self,state:&DocumentState) {
        if let Some(finalization)=self.inner.bridge.android_build.service_finalization(){
            let gate=self.android_build_gate(state);
            let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity).ok();
            let current=edit.as_ref().and_then(|edit|self.validated_saved_input_with_edit(state,finalization.context(),edit).ok());
            self.inner.bridge.android_build.finalize_service(&finalization,current.as_ref(),gate);
            drop(edit);
        }
        let Some(finalization)=self.inner.bridge.android_build.registration_finalization() else{return;};
        let gate=self.android_build_gate(state);
        // Keep the ORIGINAL Edit Registry through Saved -> brief control-book
        // publication. No worker sources/native book is ever acquired here.
        let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity).ok();
        let current=edit.as_ref().and_then(|edit|
            self.validated_saved_input_with_edit(state,finalization.context(),edit).ok());
        self.inner.bridge.android_build.finalize_registration(&finalization,current.as_ref(),gate);
        drop(edit);
    }

    pub(crate) fn android_tool_registration_status(&self)->Result<wire::Status,BridgeError> {
        self.reconcile();
        let state=self.lock();
        self.inner.bridge.android_build.registration_status(self.android_build_gate(&state))
    }

    pub(crate) fn inspect_android_tool_sources(&self,input:wire::Inspect)->Result<wire::Status,BridgeError> {
        // The original budget includes snapshot, entropy, picker proof and both
        // lock acquisitions. No clock is renewed after async receiver/GO loss.
        let at=Instant::now();
        self.reconcile();
        let snapshot={
            let state=self.lock();
            let gate=self.android_build_gate(&state);
            if gate!=crate::android_build_protocol::Availability::Available{return Err(wire::unavailable());}
            let (registration,root)=self.inner.bridge.native_project(&input.context.project_id).map_err(|_|wire::unavailable())?;
            let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            let saved=self.validated_saved_input_with_edit(&state,&input.context,&edit)?;
            self.inner.bridge.android_build.inspection_snapshot(&self.inner.session_identity,at,input,registration,root,saved,gate)?
        };
        self.admit_checked_android_registration(snapshot.check_originals()?)
    }

    pub(crate) fn register_android_tool_sources(&self,input:wire::Register)->Result<wire::Status,BridgeError> {
        let at=Instant::now();
        self.reconcile();
        let snapshot={
            let state=self.lock();
            let gate=self.android_build_gate(&state);
            if gate!=crate::android_build_protocol::Availability::Available{return Err(wire::unavailable());}
            let (registration,root)=self.inner.bridge.native_project(&input.context.project_id).map_err(|_|wire::unavailable())?;
            let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            let saved=self.validated_saved_input_with_edit(&state,&input.context,&edit)?;
            self.inner.bridge.android_build.registration_snapshot(&self.inner.session_identity,at,input,registration,root,saved,gate)?
        };
        // The original owns preparation first. Ready and actual reproof, not this
        // facade or the copy-consent checkbox, authorize its later transfer.
        self.admit_checked_android_registration(snapshot.check_originals()?)
    }

    fn admit_checked_android_registration(&self,checked:crate::saved_command_owner::AndroidRegistrationChecked)
        ->Result<wire::Status,BridgeError> {
        let admitted={
            let state=self.lock();
            let gate=self.android_build_gate(&state);
            if gate!=crate::android_build_protocol::Availability::Available{return Err(wire::unavailable());}
            let (registration,root)=self.inner.bridge.native_project(&checked.context().project_id).map_err(|_|wire::unavailable())?;
            let census=installation_memory::android_registration_census(self,&state,checked.picker_originals())
                .map_err(|_|wire::unavailable())?;
            let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            let current=self.validated_saved_input_with_edit(&state,checked.context(),&edit)?;
            self.inner.bridge.android_build.admit_registration(&self.inner.session_identity,&checked,current,
                registration,&root,&census,gate)?
        };
        // All app guards are gone. The original source worker, not invoke,
        // performs the pending-aware GO checkpoint on its original W/H.
        admitted.release()
    }

    pub(crate) fn cancel_android_tool_registration(&self,input:wire::Cancel)->Result<wire::Status,BridgeError> {
        // Dedicated route reservation precedes F and Document contention. It
        // matches operationId + registrationGeneration, never reviewId.
        let publication=self.inner.android_registration_control.reserve_cancel(&input)?;
        let result={
            let state=self.lock();
            self.inner.bridge.android_build.cancel_registration(&input,publication.as_ref(),self.android_build_gate(&state))
        };
        if let Some(publication)=publication{publication.finish();}
        result
    }
}

impl DocumentBinding {
    #[cfg(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper")))]
    pub(crate) fn bind_android_service_dispatcher(&self,dispatcher:crate::saved_command_owner::AndroidServiceDispatcher)->bool{
        self.inner.bridge.android_build.bind_service_dispatcher(&self.inner.session_identity,dispatcher)
    }
    pub(crate) fn android_tool_service_status(&self)->Result<wire::ServiceStatus,BridgeError>{
        self.reconcile();let state=self.lock();self.inner.bridge.android_build.service_status(self.android_build_gate(&state))
    }
    pub(crate) fn android_tool_service_action(&self,input:wire::ServiceRequest)->Result<wire::ServiceStatus,BridgeError>{
        let at=Instant::now();self.reconcile();
        let snapshot={
            let state=self.lock();let gate=self.android_build_gate(&state);
            if gate!=crate::android_build_protocol::Availability::Available{return Err(wire::service_unavailable());}
            let(registration,root)=self.inner.bridge.native_project(&input.context.project_id).map_err(|_|wire::service_unavailable())?;
            let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity).map_err(|_|wire::service_unavailable())?;
            let saved=self.validated_saved_input_with_edit(&state,&input.context,&edit).map_err(|_|wire::service_invalid())?;
            self.inner.bridge.android_build.service_snapshot(&self.inner.session_identity,at,input,registration,root,saved,gate)?
        };
        let checked=snapshot.check_originals()?;
        let admitted={
            let state=self.lock();let gate=self.android_build_gate(&state);
            if gate!=crate::android_build_protocol::Availability::Available{return Err(wire::service_unavailable());}
            let(registration,root)=self.inner.bridge.native_project(&checked.context().project_id).map_err(|_|wire::service_unavailable())?;
            let census=installation_memory::android_service_setup_census(self,&state,checked.picker_originals()).map_err(|_|wire::service_unavailable())?;
            let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity).map_err(|_|wire::service_unavailable())?;
            let current=self.validated_saved_input_with_edit(&state,checked.context(),&edit).map_err(|_|wire::service_invalid())?;
            self.inner.bridge.android_build.admit_service(&self.inner.session_identity,&checked,current,registration,&root,&census,gate)?
        };
        admitted.release()
    }
    pub(crate) fn cancel_android_tool_service(&self,input:wire::ServiceCancel)->Result<wire::ServiceStatus,BridgeError>{
        let publication=self.inner.android_registration_control.reserve_service_cancel(&input)?;
        let result={let state=self.lock();self.inner.bridge.android_build.cancel_service(&input,publication.as_ref(),self.android_build_gate(&state))};
        if let Some(publication)=publication{publication.finish();}result
    }
}
