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
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    peer:Option<macos_removal::Handle>,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    hints:macos_removal::HintState,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    notice:Option<Arc<macos_removal::NoticeRuntime>>,
}
impl Closure {
    pub(super) fn closed(&self)->bool{self.closed}
    /// A retained native original is never zero-byte census credit, even if a
    /// future erroneous transition were to clear only the presentation flag.
    pub(super) fn data_only(&self)->bool{
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        { !self.closed && self.original.is_none() && self.completion.is_none() && self.peer.is_none() }
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        { !self.closed }
    }
    pub(super) fn can_exit(&self)->bool{
        if self.data_only(){return true;}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {
            if let Some(peer)=&self.peer{
                // Source/channel/main/worker/coordinator retirement is owed in
                // addition to Saved. Merely joining Saved cannot close a peer.
                return self.closed&&peer.can_exit()&&self.original.as_ref().is_none_or(|original|original.can_exit());
            }
            self.closed && self.original.as_ref().is_some_and(|original|original.can_exit())
        }
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {false}
    }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    pub(super) fn removal_matches(&self,peer:&macos_removal::Handle)->bool{
        self.closed&&self.peer.as_ref().is_some_and(|original|original.same(peer))
    }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    pub(super) fn notice_bytes(&self)->Option<usize>{self.notice.as_ref().map_or(Some(0),|notice|notice.retained_bytes())}
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
        self.macos_maintenance_common_gate(state)
    }
    fn macos_maintenance_common_gate(&self,state:&DocumentState)->Result<(),BridgeError>{
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

    fn macos_removal_saved_gate(&self,state:&DocumentState,peer:&macos_removal::Handle)->Result<(),BridgeError>{
        // Exact original exception, not a Boolean "ignore busy"/public gate.
        // The closure is never temporarily opened around this admission.
        passive_document_state_gate(state)?;
        if !state.maintenance.removal_matches(peer)||state.maintenance.original.is_some()
            ||state.maintenance.completion.is_some()||!state.lifetime.original_bound()||state.lost_observed
            ||!self.inner.bridge.android_build.original_document_matches(&self.inner.session_identity)
            ||!peer.work_ok(){return Err(unavailable());}
        self.macos_maintenance_common_gate(state)
    }

    /// Main-window startup owns one observer original. Store its bounded cell
    /// before native registration so a partial/Unknown start is never lost.
    pub(crate) fn install_macos_removal_notice(&self)->bool{
        if !cfg!(feature="macos-installed-desktop-image")||!mrk_macos_installed_native::main_thread(){return false;}
        let runtime=macos_removal::NoticeRuntime::reserved();
        {
            let mut state=self.lock();
            if state.maintenance.notice.is_some(){return false;}
            state.maintenance.notice=Some(runtime.clone());
        }
        runtime.install()
    }
    pub(crate) fn removal_notice_runtime(&self)->Option<Arc<macos_removal::NoticeRuntime>>{self.lock().maintenance.notice.clone()}

    /// Native id hint only. No caller supplies a path, deadline or credential.
    /// The original local read-only bootstrap is captured before any Doc wait.
    pub(crate) fn start_macos_removal_hint(&self,id:[u8;16])->Result<(),BridgeError>{
        let at=Instant::now();
        if !cfg!(feature="macos-installed-desktop-image")||id==[0;16]
            ||!crate::installation::preparation_profile_available(){return Err(unavailable());}
        self.reconcile();
        let snapshot={let state=self.lock();self.macos_maintenance_gate(&state)?;
            self.inner.bridge.android_build.removal_snapshot(&self.inner.session_identity)?};
        let checked=snapshot.check_originals()?;
        let admitted={
            let mut state=self.lock();self.macos_maintenance_gate(&state)?;
            if state.maintenance.notice.as_ref().and_then(|notice|notice.retained_bytes()).is_none(){return Err(unavailable());}
            let census=installation_memory::macos_maintenance_census(self,&state,checked.picker_originals()).map_err(|_|unavailable())?;
            let prior=self.inner.bridge.android_build.removal_admission_bytes(&self.inner.session_identity,&checked,&census).ok_or_else(unavailable)?;
            let dispatcher=self.inner.bridge.android_build.removal_dispatcher(&self.inner.session_identity).ok_or_else(unavailable)?;
            let generation=state.maintenance.hints.admit(id).ok_or_else(unavailable)?;
            let admitted=match macos_removal::reserve(self,id,generation,at,checked.picker_originals().clone(),
                checked.source_generation(),prior,dispatcher){Ok(admitted)=>admitted,Err(error)=>{
                    let _=state.maintenance.hints.retire(id,generation,true);return Err(error);
                }};
            state.maintenance.closed=true;state.maintenance.peer=Some(admitted.handle());
            state.maintenance.completion=None;state.maintenance.last=None;
            self.bump(&mut state);admitted
        };
        admitted.release().map_err(|_|unavailable())
    }

    fn start_macos_removal_saved(&self,peer:&macos_removal::Handle,confirmation:crate::saved_command_owner::MacosRemovalConfirmed)
        ->Result<(),BridgeError>{
        // Once-only actual native proof. The id notification cannot call this.
        let request=crate::saved_command_owner::MacosMaintenanceRequest::confirmed_removal(&confirmation)?;
        let snapshot={let state=self.lock();self.macos_removal_saved_gate(&state,peer)?;
            self.inner.bridge.android_build.maintenance_snapshot(&self.inner.session_identity,request)?};
        let checked=snapshot.check_originals()?;
        if !peer.sources_match(checked.picker_originals(),checked.source_generation()){return Err(unavailable());}
        let admitted={
            let mut state=self.lock();self.macos_removal_saved_gate(&state,peer)?;
            let census=installation_memory::macos_removal_census(self,&state,peer,checked.picker_originals()).map_err(|_|unavailable())?;
            let admitted=self.inner.bridge.android_build.admit_maintenance(&self.inner.session_identity,&checked,&census)?;
            let original=admitted.handle();
            state.maintenance.original=Some(original.clone());state.maintenance.completion=None;state.maintenance.last=None;
            if !peer.bind_saved(original){peer.poison();}
            self.bump(&mut state);admitted
        };
        if !peer.work_ok(){drop(admitted);return Err(unavailable());}
        admitted.release()
    }

    pub(super) fn reconcile_macos_removal_locked(&self,state:&mut DocumentState){
        let Some(peer)=state.maintenance.peer.as_ref().cloned()else{return;};
        let live=state.lifetime.original_bound()&&!state.lost_observed&&!state.unknown&&!state.exhausted
            &&!state.stopping&&!state.quit_pending&&!state.retiring&&!state.lock_pending;
        if !live&&!peer.can_exit(){peer.stop(crate::installed_runtime::AdmissionFailure::Stopped,Instant::now());}
        peer.reconcile();
        if peer.may_reopen()&&state.maintenance.original.as_ref().is_none_or(|original|original.can_exit()){
            if !state.maintenance.hints.retire(peer.id(),peer.generation(),true){peer.poison();return;}
            state.maintenance.peer=None;state.maintenance.original=None;state.maintenance.completion=None;
            state.maintenance.closed=false;self.bump(state);
        }
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
        if let Some(peer)=&state.maintenance.peer{
            // SAME operation/generation/cutoff result is stored before wake.
            // Even known refusal must wait for channel/source/main/task closure.
            peer.offer_completion(completion);self.bump(state);return;
        }
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
        let peer=self.lock().maintenance.peer.clone();
        if let Some(peer)=peer{
            if let Some(confirmation)=peer.take_confirmation(){
                if self.start_macos_removal_saved(&peer,confirmation).is_err(){
                    peer.stop(crate::installed_runtime::AdmissionFailure::Stopped,Instant::now());
                }
            }
            self.reconcile();
            let ready={let state=self.lock();
                if state.maintenance.removal_matches(&peer){peer.take_ready()}else{None}};
            if ready.is_some_and(|ready|ready.handle().same(&peer)&&ready.request_quit()){self.request_quit(app);}
            return;
        }
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
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
        {
            let notice=macos_removal::NoticeRuntime::reserved();let bytes=notice.retained_bytes().unwrap();
            state.maintenance.notice=Some(notice);assert_eq!(state.maintenance.notice_bytes(),Some(bytes));
            // The passive observer cannot circularly block coreQuitReady. It
            // still owes its separate main retirement BEFORE relay/exit_ready.
            state.maintenance.closed=false;assert!(state.maintenance.data_only());assert!(state.maintenance.can_exit());
            let generation=state.maintenance.hints.admit([1;16]).unwrap();
            assert!(state.maintenance.hints.admit([2;16]).is_none());
            assert!(!state.maintenance.hints.retire([1;16],generation,false));
            state.maintenance.closed=true;assert!(!state.maintenance.data_only());assert!(!state.maintenance.can_exit());
            assert!(credential_lock_gate(&state).is_ok());assert!(quit_question_admitted(&state));
        }
    }
}
