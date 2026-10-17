//! Closed Execute composition of the actual Store runtime and registered tools.
//! The original Saved Session owns both; this is not an Android build owner.
#![forbid(unsafe_code)]
use super::*;
use super::android_leased::AndroidObservations;
use crate::installed_runtime::{LeasedAndroidToolchainSlots,android_lease_admission_issue};
use mrk_macos_installed_native::android_catalog_query::Role;

pub(super) struct ExecuteNativeBooks {
    runtime:StoreRuntimeSlots,tools:LeasedAndroidToolchainSlots,selection:Option<VerifiedRuntime>,
    pub(super) phase:NativePhase,failure:Option<(AdmissionFailure,Instant)>,settlement_started:bool,
    cleanup:watch::Receiver<Instant>,pub(super) control:Arc<AndroidUseControl>,pre_go_reservation:Option<usize>,
}
impl ExecuteNativeBooks {
    pub(super) fn new(selected:android_wire::MacToolchainSelection,audit:watch::Receiver<Instant>,cleanup:watch::Receiver<Instant>,clocks:Clocks)->Self{
        let tools=LeasedAndroidToolchainSlots::new_execute(selected,audit);
        let control=AndroidUseControl::reserved(tools.original_identity(),tools.query_signal(),tools.original_clock_slot(),
            Role::LocalStoreExecute,clocks.admitted,clocks.work,clocks.finality);
        let mut value=Self{runtime:StoreRuntimeSlots::new(),tools,selection:None,phase:NativePhase::New,failure:None,
            settlement_started:false,cleanup,control,pre_go_reservation:None};
        value.pre_go_reservation=value.retained_now().and_then(|n|n.checked_add(std::mem::size_of::<Session>()))
            .and_then(|n|n.checked_add(std::mem::size_of::<Resources>()))
            .and_then(|n|n.checked_add(std::mem::size_of::<AndroidObservationSlot>()))
            .and_then(|n|n.checked_add(std::mem::size_of::<AndroidObservations>()));value
    }
    pub(super) fn pre_go_bytes(&self)->Option<usize>{self.pre_go_reservation}
    fn retained_now(&self)->Option<usize>{
        let selection=self.selection.as_ref().map_or(Some(0),|s|s.python.capacity().checked_add(s.bootstrap.capacity())?.checked_add(s.core.capacity())?.checked_add(s.cwd.capacity()));
        std::mem::size_of::<Self>().checked_add(selection?)?.checked_add(self.runtime.retained_bytes()?)?
            .checked_add(self.tools.retained_bytes()?)?.checked_add(AndroidUseControl::retained_control_charge()?)?
            .checked_add(AndroidCloseSlot::fixed_charge()?)
    }
    fn retained_before_tail(&self)->Option<usize>{self.pre_go_reservation?.checked_add(self.retained_now()?)}
    pub(super) fn execute_backing(&self)->Option<usize>{
        if !matches!(self.phase,NativePhase::Ready|NativePhase::Claimed)||self.settlement_started||self.first_failure().is_some()||self.control.stopped(){return None;}
        self.retained_now()
    }
    pub(super) fn execute_source_quote(&self)->Option<usize>{
        if self.phase!=NativePhase::Ready{return None;}
        self.execute_backing()?;self.runtime.retained_original_count()?;
        Some(crate::installed_runtime::LOCAL_EXECUTE_ORIGINAL_FDS)
    }
    pub(super) fn first_failure(&self)->Option<(AdmissionFailure,Instant)>{
        [self.failure,self.runtime.first_failure(),self.tools.first_failure()].into_iter().flatten().min_by_key(|(_,t)|*t)
    }
    fn fail(&mut self,failure:AdmissionFailure,owner:&Session){
        let now=Instant::now();let first=self.first_failure().unwrap_or((failure,now));
        if self.failure.is_none_or(|(_,t)|first.1<t){self.failure=Some(first);}
        self.control.local(first.1,now,failure==AdmissionFailure::Unknown);self.phase=NativePhase::Refused;
        owner.publish_native_failure(Some(first));
    }
    pub(super) fn interrupted(&mut self){self.phase=NativePhase::Unknown;self.runtime.mark_interrupted();self.tools.mark_interrupted();self.control.mark_unknown();}
    pub(super) fn inspect_once(&mut self,runtime:&RuntimeConfig,owner:&Session)->Result<VerifiedRuntime,BridgeError>{
        if self.phase!=NativePhase::New{return Err(BridgeError::cleanup_unknown());}self.phase=NativePhase::Inspecting;
        let stop=owner.stop.subscribe();let first=self.control.data().local_first;
        if let Err(issue)=self.tools.inspect_execute_once(self.control.admitted,self.control.work,self.control.hard,first,&stop){
            self.fail(android_lease_admission_issue(issue),owner);return Err(owner.domain.unavailable());
        }
        if let Err(issue)=self.runtime.arm_acl_once(owner.clocks.work,&stop){self.fail(issue,owner);return Err(owner.domain.unavailable());}
        let selected=match runtime.resolve_local_store_execute_installed(&mut self.runtime){Ok(v)=>v,Err(e)=>{self.fail(AdmissionFailure::Inventory,owner);return Err(e);}};
        self.selection=Some(VerifiedRuntime{python:selected.python.clone(),bootstrap:selected.bootstrap.clone(),core:selected.core.clone(),cwd:selected.cwd.clone()});
        self.phase=NativePhase::Ready;Ok(selected)
    }
    fn selected(&self,expected:&VerifiedRuntime)->Result<(),AdmissionFailure>{
        if self.phase!=NativePhase::Ready||self.first_failure().is_some()||self.settlement_started||self.control.stopped(){return Err(AdmissionFailure::AlreadyUsed);}
        let actual=self.selection.as_ref().ok_or(AdmissionFailure::Unknown)?;
        if (&actual.python,&actual.bootstrap,&actual.core,&actual.cwd)!=(&expected.python,&expected.bootstrap,&expected.core,&expected.cwd){return Err(AdmissionFailure::Identity);}Ok(())
    }
    pub(super) fn request_binding(&self,expected:&VerifiedRuntime)->Result<android_wire::ToolchainBinding,AdmissionFailure>{self.selected(expected)?;self.tools.binding_data().map_err(android_lease_admission_issue)}
    pub(super) fn settle_observations(&mut self,used:bool,owner:&Session)->AndroidObservations{
        if self.settlement_started||self.phase==NativePhase::Claimed&&!used&&!self.runtime.no_child_effect(){return AndroidObservations::unknown();}
        self.settlement_started=true;
        if self.phase==NativePhase::New&&!used&&self.runtime.never_started()&&self.control.unarmed(){
            let bytes=self.retained_before_tail();self.phase=NativePhase::Settled;
            return AndroidObservations{entered:false,observations:bytes.is_some(),integrity:true,tail:None,retained_bytes:bytes};
        }
        self.phase=NativePhase::Settling;owner.publish_native_failure(self.first_failure());
        let mut integrity=!used||self.first_failure().is_none();
        if used{
            if let Err(issue)=self.runtime.check_claimed_before_settlement(&mut|f|owner.native_cleanup_expired(f)){self.fail(issue,owner);integrity=false;}
            let audit_cutoff=*owner.native_audit_cutoff.borrow();
            if let Err(issue)=self.tools.check_after_use(audit_cutoff){self.fail(android_lease_admission_issue(issue),owner);integrity=false;}
        }
        // Independent consume even after the other original's failure.
        let cleanup_cutoff=*self.cleanup.borrow();
        let tools=self.tools.settle_observations(cleanup_cutoff,&self.cleanup,&mut|f,t|owner.publish_native_failure(Some((f,t))));
        let runtime=self.runtime.settle_originals(&mut|f|owner.native_cleanup_expired(f));
        owner.publish_native_failure(self.first_failure());
        let observations=tools==CloseOutcome::Settled&&runtime==CloseOutcome::Settled&&self.tools.observations_settled()&&self.runtime.settled();
        let retained_bytes=self.retained_before_tail();
        if !observations||retained_bytes.is_none(){self.phase=NativePhase::Unknown;return AndroidObservations{entered:true,observations:false,integrity:false,tail:None,retained_bytes};}
        // Last tool Book call. Frozen charge/return carries custody afterward.
        let tail=self.tools.take_close_tail();self.phase=if tail.is_ok(){NativePhase::Settling}else{NativePhase::Unknown};
        match tail{Ok(tail)=>AndroidObservations{entered:true,observations:true,integrity,tail:Some(tail),retained_bytes},
            Err(_)=>AndroidObservations{entered:true,observations:false,integrity:false,tail:None,retained_bytes}}
    }
}

pub(super) fn spawn_original(inner:&Inner,owner:&Session,runtime:VerifiedRuntime,native:Option<Arc<Mutex<ExecuteNativeBooks>>>){
    if owner.domain!=SavedCommandDomain::LocalStoreExecute||inner.domain!=owner.domain||!inner.qualified(None)||Profile::current(owner.domain)!=Some(owner.profile){inner.stop(owner,Reason::RuntimeUnavailable);return;}
    let Some(native)=native else{inner.stop(owner,Reason::RuntimeUnavailable);return;};
    let mut native=match native.lock(){Ok(n)=>n,Err(_)=>{inner.unknown(owner);return;}};
    if let Err(f)=native.selected(&runtime){native.fail(f,owner);return;}
    if let Err(f)=native.tools.check_before_spawn(owner.clocks.work,&owner.stop.subscribe()){native.fail(android_lease_admission_issue(f),owner);return;}
    if let Err(f)=native.runtime.transfer_once(){native.fail(f,owner);return;}
    let mut loan=match native.runtime.prepare_loan(&mut|f|owner.publish_native_failure(f)){Ok(v)=>v,Err(_)=>{inner.stop(owner,Reason::RuntimeUnavailable);return;}};
    let selected=loan.python_runtime();
    let mut command=Command::new(&selected.python);
    command.args(["-I","-S","-B"]).arg(&selected.bootstrap).arg(&selected.core).current_dir(&selected.cwd)
        .env_clear().env("LANG","C").env("LC_ALL","C").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    if local_history::execute_child(owner,&mut command).is_err(){loan.record_closed_spawn_gate();inner.stop(owner,Reason::ContextChanged);return;}
    if crate::runtime::macos_installed_environment(&mut command).is_err(){loan.record_closed_spawn_gate();inner.stop(owner,Reason::RuntimeUnavailable);return;}
    if let Err(f)=loan.check_before_or_after_use(){loan.record_closed_spawn_gate();owner.publish_native_failure(Some((f,Instant::now())));inner.stop(owner,Reason::RuntimeUnavailable);return;}
    let mut startup=match owner.startup.lock(){Ok(s)=>s,Err(_)=>{loan.record_closed_spawn_gate();inner.unknown(owner);return;}};
    let mut r=inner.lock();let now=Instant::now();inner.advance_locked(&mut r,owner,now);
    if !original_session(&r,owner)||r.disabled||r.exhausted||r.stopping||r.document_lost||*owner.stop.borrow()||now>=owner.clocks.work{
        loan.record_closed_spawn_gate();return;
    }
    if startup.attempted||startup.returned||startup.failed||startup.child.is_some(){loan.record_closed_spawn_gate();inner.unknown_locked(&mut r,owner);return;}
    // All private source/selection checks completed before this exact original GO.
    startup.attempted=true;drop(r);drop(loan);native.phase=NativePhase::Claimed;
    match command.spawn(){Ok(child)=>{startup.child=Some(child);startup.returned=true;},Err(_)=>{startup.failed=true;owner.resource_unknown.store(true,Ordering::SeqCst);drop(startup);inner.stop(owner,Reason::RuntimeUnavailable);inner.unknown(owner);}}
}
