//! Private maintenance admission belongs to the original Document mutex.
//! Closing NEW work is separate from STOP and from the later ordinary Quit.
//! Normal IPC delegates to this original path; it adds no Installer capability
//! or alternate scheduler. Only the private Completion can request Quit.
use super::*;

#[derive(Default)]
pub(super) struct Closure {
    closed:bool,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    original:Option<crate::saved_command_owner::MacosMaintenanceHandle>,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    completion:Option<crate::saved_command_owner::MacosMaintenanceCompletion>,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    last:Option<crate::saved_command_owner::MacosMaintenanceStatus>,
}
impl Closure {
    pub(super) fn closed(&self)->bool{self.closed}
    /// A retained native original is never zero-byte census credit, even if a
    /// future erroneous transition were to clear only the presentation flag.
    pub(super) fn data_only(&self)->bool{
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        { !self.closed && self.original.is_none() && self.completion.is_none() }
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        { !self.closed }
    }
    pub(super) fn can_exit(&self)->bool{
        if self.data_only(){return true;}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {self.closed && self.original.as_ref().is_some_and(|original|original.can_exit())}
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {false}
    }
}

pub(super) fn unavailable()->BridgeError{
    BridgeError::new("macos_maintenance_unavailable",
        "Installed maintenance needs the original installed application and fully settled work.")
}

#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl DocumentBinding {
    fn macos_maintenance_gate(&self,state:&DocumentState)->Result<(),BridgeError>{
        passive_document_gate(state)?;
        if !state.maintenance.data_only() || !state.lifetime.original_bound() || state.lost_observed
            || !self.inner.bridge.android_build.original_document_matches(&self.inner.session_identity){return Err(unavailable());}
        // Do not call android_build.busy here: the second admission owns its
        // SAME unentered cohort. Its Saved snapshot/admit gates examine that
        // exact cohort and every Android original under the existing Registry.
        if self.inner.bridge.supervisor.disabled() || self.inner.bridge.edits.disabled()
            || self.inner.bridge.diagnostics.disabled() || self.inner.bridge.preflight.disabled()
            || self.inner.bridge.project_recovery.disabled() || self.inner.bridge.ios_archive.disabled()
            || self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping()
            || self.inner.bridge.diagnostics.stopping() || self.inner.bridge.preflight.stopping()
            || self.inner.bridge.project_recovery.stopping() || self.inner.bridge.ios_archive.stopping()
            || !self.inner.bridge.supervisor.can_exit() || !self.inner.bridge.edits.can_exit()
            || self.inner.bridge.edits.preflight_attention() || self.inner.bridge.diagnostics.busy()
            || self.inner.bridge.preflight.busy() || self.inner.bridge.project_recovery.busy()
            || self.inner.bridge.ios_archive.busy()
            || state.saved_observation.as_ref().is_some_and(|lane|!lane.returned())
            || state.slot.as_ref().is_some_and(|slot|slot.phase!=Phase::Idle || !slot.owner.resources_settled())
            || state.github.native_work_pending(){return Err(unavailable());}
        Ok(())
    }

    pub(crate) fn start_macos_maintenance(&self,confirmation:&str)
        ->Result<crate::saved_command_owner::MacosMaintenanceStatus,BridgeError>{
        if !crate::installation::preparation_profile_available(){return Err(unavailable());}
        // Consent, original T and entropy exist before the first Document wait.
        let request=crate::saved_command_owner::MacosMaintenanceRequest::confirmed(confirmation)?;
        self.reconcile();
        let snapshot={
            let state=self.lock();self.macos_maintenance_gate(&state)?;
            self.inner.bridge.android_build.maintenance_snapshot(&self.inner.session_identity,request)?
        };
        // Only proof on the actual zero-to-three selected originals, outside
        // BOTH app locks; no source/helper work starts at this point.
        let checked=snapshot.check_originals()?;
        let admitted={
            let mut state=self.lock();self.macos_maintenance_gate(&state)?;
            let census=installation_memory::macos_maintenance_census(self,&state,checked.picker_originals())
                .map_err(|_|unavailable())?;
            let admitted=self.inner.bridge.android_build.admit_maintenance(
                &self.inner.session_identity,&checked,&census)?;
            // The original tasks/Control already exist with GO closed. Install
            // this gate before releasing Document, including publication-error
            // cases retained by Saved. Do not publish STOP into our own Control.
            state.maintenance.closed=true;
            state.maintenance.original=Some(admitted.handle());
            state.maintenance.completion=None;state.maintenance.last=None;
            self.bump(&mut state);admitted
        };
        let original=admitted.handle();
        admitted.release()?;
        self.reconcile();let state=self.lock();
        // An immediately refused/reopened operation may race another explicit
        // caller. Never return that later caller's acknowledgement as this one.
        let own=self.inner.bridge.android_build.maintenance_status(&original);
        if let Some(current)=state.maintenance.original.as_ref(){
            if !current.same(&original){return Err(unavailable());}
            return Ok(state.maintenance.last.unwrap_or(own));
        }
        state.maintenance.last.filter(|last|last.operation==own.operation && last.generation==own.generation)
            .ok_or_else(unavailable)
    }

    pub(super) fn reconcile_macos_maintenance_locked(&self,state:&mut DocumentState){
        let Some(original)=state.maintenance.original.as_ref().cloned()else{return;};
        if state.maintenance.last.is_some(){return;}
        let live=state.lifetime.original_bound() && !state.lost_observed && !state.unknown
            && !state.exhausted && !state.stopping && !state.quit_pending && !state.retiring && !state.lock_pending;
        let Some(completion)=self.inner.bridge.android_build.finalize_maintenance(
            &self.inner.session_identity,&original,live)else{return;};
        // Completion has a private constructor at the actual consuming
        // worker/coordinator/native/main-callback final gate; Status cannot do
        // this transition. Unknown never supplies a Completion.
        state.maintenance.last=Some(completion.status());
        if completion.may_reopen() {
            state.maintenance.closed=false;
            state.maintenance.original=None;
            state.maintenance.completion=None;
        }else{
            // Started, ambiguous drain and even a cancelled ordinary Quit never
            // reopen launches or automatically register the helper again.
            state.maintenance.completion=Some(completion);
        }
        self.bump(state);
    }

    pub(crate) fn macos_maintenance_status(&self)->Option<crate::saved_command_owner::MacosMaintenanceStatus>{
        self.reconcile();let state=self.lock();
        state.maintenance.last.or_else(||state.maintenance.original.as_ref()
            .map(|original|self.inner.bridge.android_build.maintenance_status(original)))
    }

    #[cfg(feature="desktop-shell")]
    pub(crate) fn finish_macos_maintenance(&self,app:tauri::AppHandle){
        self.reconcile();
        let completion={self.lock().maintenance.completion.take()};
        // This consumes the actual final result, not an exit-ready flag or
        // copied DTO. The SAME final cutoff is sampled again immediately here.
        if let Some(completion)=completion {
            if completion.request_quit(){self.request_quit(app);}
        }
    }
}

impl DocumentBinding {
    pub(crate) fn installation_preparation_status(&self)->Result<crate::installation::PreparationStatus,BridgeError>{
        self.installation_preparation_view(None)
    }
    fn installation_preparation_view(&self,expected:Option<(&str,u32)>)->Result<crate::installation::PreparationStatus,BridgeError>{
        if !crate::installation::preparation_profile_available(){return Err(unavailable());}
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),feature="macos-installed-desktop-image",not(feature="macos-android-registration-helper")))]
        {
            use crate::installation::{PreparationStatus,PreparationPhase as P,PreparationReason as R};
            use crate::saved_command_owner::MacosMaintenancePhase as N;
            self.reconcile();let state=self.lock();
            let (available,ready)=self.inner.bridge.android_build.maintenance_readiness(&self.inner.session_identity);
            let ready=ready && self.macos_maintenance_gate(&state).is_ok();
            let original=state.maintenance.last.or_else(||state.maintenance.original.as_ref()
                .map(|original|self.inner.bridge.android_build.maintenance_status(original)));
            let Some(original)=original else {
                if expected.is_some() || state.maintenance.closed(){return Err(unavailable());}
                let reason=if !available{R::UnavailableProfile}else if state.unknown || state.exhausted{R::CleanupUnknown}
                    else if !state.lifetime.original_bound() || state.lost_observed || state.stopping || state.quit_pending{R::DocumentUnavailable}
                    else if !ready{R::Busy}else{R::None};
                return Ok(PreparationStatus::initial(available,ready,reason));
            };
            let phase=match original.phase {N::Preparing=>P::Preparing,N::Unregistering=>P::Unregistering,
                N::Settling=>P::Settling,N::Prepared=>P::Prepared,N::Refused=>P::Refused,N::Unknown=>P::Unknown};
            let id:String=original.operation.iter().map(|byte|format!("{byte:02x}")).collect();
            // Both the current original and closure are observed under this
            // SAME Document lock. A Start reply may not substitute a later one.
            if expected.is_some_and(|expected|expected!=(id.as_str(),original.generation)){return Err(unavailable());}
            Ok(PreparationStatus{schema_version:1,available,
                can_start:ready && phase==P::Refused && !state.maintenance.closed(),
                operation_id:Some(id),
                generation:Some(original.generation),phase,reason:crate::installation::preparation_reason(original.reason),
                new_work_closed:state.maintenance.closed(),assurance:"preparation-status-only"})
        }
        #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),feature="macos-installed-desktop-image",not(feature="macos-android-registration-helper"))))]
        {let _=expected;Err(unavailable())}
    }
    pub(crate) fn prepare_installation_quit(&self,confirmation:&str)->Result<crate::installation::PreparationStatus,BridgeError>{
        if !crate::installation::preparation_profile_available(){return Err(unavailable());}
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),feature="macos-installed-desktop-image",not(feature="macos-android-registration-helper")))]
        {
            let original=self.start_macos_maintenance(confirmation)?;
            let id:String=original.operation.iter().map(|byte|format!("{byte:02x}")).collect();
            self.installation_preparation_view(Some((id.as_str(),original.generation)))
        }
        #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),feature="macos-installed-desktop-image",not(feature="macos-android-registration-helper"))))]
        {let _=confirmation;Err(unavailable())}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_work_closure_is_not_stop_and_preserves_lock_and_quit_routes(){
        let mut state=super::super::tests::empty_state();
        state.lifetime.crash_hook_installed();state.lifetime.started(true);state.lifetime.finished(true);
        state.maintenance.closed=true; // Gate DATA only: no original/finality is fabricated.
        assert!(!state.stopping && !state.quit_pending && !state.lock_pending);
        assert!(passive_document_gate(&state).is_err());
        assert!(common_document_gate(&state,false,||Ok(())).is_err());
        assert!(credential_lock_gate(&state).is_ok());
        assert!(quit_question_admitted(&state));
        assert!(!state.maintenance.can_exit());
        assert!(!state.maintenance.data_only());
        // A Boolean presentation change alone cannot create a Prepared proof;
        // this test constructs no maintenance owner, completion or native book.
    }
}
