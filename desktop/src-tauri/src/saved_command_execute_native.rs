//! Actual platform-selected tools and Store runtime on ONE original Execute Session.
#![forbid(unsafe_code)]
use super::*;
use super::android_leased::AndroidObservations;
use crate::installed_runtime::{LeasedAndroidToolchainSlots,android_lease_admission_issue};
use mrk_macos_installed_native::android_catalog_query::Role;

enum ExecuteTools {
    Android{original:LeasedAndroidToolchainSlots,control:Arc<AndroidUseControl>},
    Ios(IOSXcodeSlots),
}
pub(super) struct ExecuteNativeBooks {
    runtime:StoreRuntimeSlots,tools:ExecuteTools,selection:Option<VerifiedRuntime>,
    pub(super) phase:NativePhase,failure:Option<(AdmissionFailure,Instant)>,settlement_started:bool,
    cleanup:watch::Receiver<Instant>,pre_go_reservation:Option<usize>,
}
impl ExecuteNativeBooks {
    pub(super) fn new(selected:android_wire::MacToolchainSelection,audit:watch::Receiver<Instant>,cleanup:watch::Receiver<Instant>,clocks:Clocks)->Self {
        let original=LeasedAndroidToolchainSlots::new_execute(selected,audit);
        let control=AndroidUseControl::reserved(original.original_identity(),original.query_signal(),original.original_clock_slot(),
            Role::LocalStoreExecute,clocks.admitted,clocks.work,clocks.finality);
        Self::with_tools(ExecuteTools::Android{original,control},cleanup)
    }
    pub(super) fn new_ios(audit:watch::Receiver<Instant>,cleanup:watch::Receiver<Instant>)->Self {
        Self::with_tools(ExecuteTools::Ios(IOSXcodeSlots::new(audit)),cleanup)
    }
    fn with_tools(tools:ExecuteTools,cleanup:watch::Receiver<Instant>)->Self {
        let mut value=Self{runtime:StoreRuntimeSlots::new(),tools,selection:None,phase:NativePhase::New,failure:None,
            settlement_started:false,cleanup,pre_go_reservation:None};
        value.pre_go_reservation=value.retained_now().and_then(|n|n.checked_add(std::mem::size_of::<Session>()))
            .and_then(|n|n.checked_add(std::mem::size_of::<Resources>()))
            .and_then(|n|if value.ios(){n.checked_add(std::mem::size_of::<NativeSettlement>())}else{
                n.checked_add(std::mem::size_of::<AndroidObservationSlot>())?.checked_add(std::mem::size_of::<AndroidObservations>())});value
    }
    pub(super) fn ios(&self)->bool {matches!(self.tools,ExecuteTools::Ios(_))}
    pub(super) fn control(&self)->Option<Arc<AndroidUseControl>> {match &self.tools{ExecuteTools::Android{control,..}=>Some(control.clone()),_=>None}}
    fn stopped(&self)->bool{self.control().is_some_and(|c|c.stopped())}
    pub(super) fn pre_go_bytes(&self)->Option<usize>{self.pre_go_reservation}
    fn retained_now(&self)->Option<usize>{
        let selection=self.selection.as_ref().map_or(Some(0),|s|s.python.capacity().checked_add(s.bootstrap.capacity())?.checked_add(s.core.capacity())?.checked_add(s.cwd.capacity()));
        let tools=match &self.tools{ExecuteTools::Android{original,..}=>original.retained_bytes()?.checked_add(AndroidUseControl::retained_control_charge()?)?.checked_add(AndroidCloseSlot::fixed_charge()?)?,
            ExecuteTools::Ios(original)=>original.retained_bytes()?};
        std::mem::size_of::<Self>().checked_add(selection?)?.checked_add(self.runtime.retained_bytes()?)?.checked_add(tools)
    }
    fn retained_before_tail(&self)->Option<usize>{self.pre_go_reservation?.checked_add(self.retained_now()?)}
    pub(super) fn execute_backing(&self)->Option<usize>{
        if !matches!(self.phase,NativePhase::Ready|NativePhase::Claimed)||self.settlement_started||self.first_failure().is_some()||self.stopped(){return None;}self.retained_now()
    }
    pub(super) fn execute_source_quote(&self)->Option<usize>{
        if self.phase!=NativePhase::Ready{return None;}self.execute_backing()?;
        let runtime=self.runtime.retained_original_count()?;
        match &self.tools{ExecuteTools::Android{..}=>Some(crate::installed_runtime::LOCAL_EXECUTE_ORIGINAL_FDS),
            ExecuteTools::Ios(tools)=>runtime.checked_add(tools.retained_original_count()?)}
    }
    pub(super) fn first_failure(&self)->Option<(AdmissionFailure,Instant)>{
        let tools=match &self.tools{ExecuteTools::Android{original,..}=>original.first_failure(),ExecuteTools::Ios(original)=>original.first_failure()};
        [self.failure,self.runtime.first_failure(),tools].into_iter().flatten().min_by_key(|(_,t)|*t)
    }
    fn fail(&mut self,failure:AdmissionFailure,owner:&Session){
        let now=Instant::now();let first=self.first_failure().unwrap_or((failure,now));
        if self.failure.is_none_or(|(_,t)|first.1<t){self.failure=Some(first);}
        if let Some(control)=self.control(){control.local(first.1,now,failure==AdmissionFailure::Unknown);}self.phase=NativePhase::Refused;
        owner.publish_native_failure(Some(first));
    }
    pub(super) fn interrupted(&mut self){self.phase=NativePhase::Unknown;self.runtime.mark_interrupted();
        match &mut self.tools{ExecuteTools::Android{original,control}=>{original.mark_interrupted();control.mark_unknown();},ExecuteTools::Ios(original)=>original.mark_interrupted()}}
    pub(super) fn inspect_once(&mut self,runtime:&RuntimeConfig,owner:&Session)->Result<VerifiedRuntime,BridgeError>{
        if self.phase!=NativePhase::New{return Err(BridgeError::cleanup_unknown());}self.phase=NativePhase::Inspecting;
        let stop=owner.stop.subscribe();
        let inspected=match &mut self.tools {
            ExecuteTools::Android{original,control}=>original.inspect_execute_once(control.admitted,control.work,control.hard,control.data().local_first,&stop).map_err(android_lease_admission_issue),
            ExecuteTools::Ios(original)=>original.arm_acl_once(owner.clocks.work,&stop).and_then(|()|original.inspect_upload_once(owner.clocks.work,&stop)),
        };
        if let Err(issue)=inspected{self.fail(issue,owner);return Err(owner.domain.unavailable());}
        if let Err(issue)=self.runtime.arm_acl_once(owner.clocks.work,&stop){self.fail(issue,owner);return Err(owner.domain.unavailable());}
        let selected=match runtime.resolve_local_store_execute_installed(&mut self.runtime){Ok(v)=>v,Err(e)=>{self.fail(AdmissionFailure::Inventory,owner);return Err(e);}};
        self.selection=Some(VerifiedRuntime{python:selected.python.clone(),bootstrap:selected.bootstrap.clone(),core:selected.core.clone(),cwd:selected.cwd.clone()});
        self.phase=NativePhase::Ready;Ok(selected)
    }
    fn selected(&self,expected:&VerifiedRuntime)->Result<(),AdmissionFailure>{
        if self.phase!=NativePhase::Ready||self.first_failure().is_some()||self.settlement_started||self.stopped(){return Err(AdmissionFailure::AlreadyUsed);}
        let actual=self.selection.as_ref().ok_or(AdmissionFailure::Unknown)?;
        if (&actual.python,&actual.bootstrap,&actual.core,&actual.cwd)!=(&expected.python,&expected.bootstrap,&expected.core,&expected.cwd){return Err(AdmissionFailure::Identity);}Ok(())
    }
    pub(super) fn request_binding(&self,expected:&VerifiedRuntime)->Result<execute_wire::NativeTools,AdmissionFailure>{
        self.selected(expected)?;match &self.tools{ExecuteTools::Android{original,..}=>original.binding_data().map(execute_wire::NativeTools::Android).map_err(android_lease_admission_issue),
            ExecuteTools::Ios(original)=>original.upload_binding_data()}
    }
    fn check_tools_before_spawn(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<(),AdmissionFailure>{match &mut self.tools {
        ExecuteTools::Android{original,..}=>original.check_before_spawn(end,stop).map_err(android_lease_admission_issue),
        ExecuteTools::Ios(original)=>original.check_before_spawn(end,stop),
    }}
    // Android alone owns a service SH tail; IOS must never enter this ABI.
    pub(super) fn settle_observations(&mut self,used:bool,owner:&Session)->AndroidObservations{
        if self.ios()||self.settlement_started||self.phase==NativePhase::Claimed&&!used&&!self.runtime.no_child_effect(){return AndroidObservations::unknown();}
        self.settlement_started=true;
        if self.phase==NativePhase::New&&!used&&self.runtime.never_started()&&self.control().is_some_and(|c|c.unarmed()){
            let bytes=self.retained_before_tail();self.phase=NativePhase::Settled;
            return AndroidObservations{entered:false,observations:bytes.is_some(),integrity:true,tail:None,retained_bytes:bytes};
        }
        self.phase=NativePhase::Settling;owner.publish_native_failure(self.first_failure());
        let mut integrity=!used||self.first_failure().is_none();
        if used {
            if let Err(issue)=self.runtime.check_claimed_before_settlement(&mut|f|owner.native_cleanup_expired(f)){self.fail(issue,owner);integrity=false;}
            let audit_cutoff=*owner.native_audit_cutoff.borrow();
            let result=match &mut self.tools{ExecuteTools::Android{original,..}=>original.check_after_use(audit_cutoff),_=>unreachable!()};
            if let Err(issue)=result{self.fail(android_lease_admission_issue(issue),owner);integrity=false;}
        }
        let cleanup_cutoff=*self.cleanup.borrow();
        let tools=match &mut self.tools{ExecuteTools::Android{original,..}=>original.settle_observations(cleanup_cutoff,&self.cleanup,&mut|f,t|owner.publish_native_failure(Some((f,t)))),_=>unreachable!()};
        let runtime=self.runtime.settle_originals(&mut|f|owner.native_cleanup_expired(f));owner.publish_native_failure(self.first_failure());
        let observed=match &self.tools{ExecuteTools::Android{original,..}=>original.observations_settled(),_=>false};
        let observations=tools==CloseOutcome::Settled&&runtime==CloseOutcome::Settled&&observed&&self.runtime.settled();
        let retained_bytes=self.retained_before_tail();
        if !observations||retained_bytes.is_none(){self.phase=NativePhase::Unknown;return AndroidObservations{entered:true,observations:false,integrity:false,tail:None,retained_bytes};}
        let tail=match &mut self.tools{ExecuteTools::Android{original,..}=>original.take_close_tail(),_=>unreachable!()};self.phase=if tail.is_ok(){NativePhase::Settling}else{NativePhase::Unknown};
        match tail{Ok(tail)=>AndroidObservations{entered:true,observations:true,integrity,tail:Some(tail),retained_bytes},
            Err(_)=>AndroidObservations{entered:true,observations:false,integrity:false,tail:None,retained_bytes}}
    }
    // Same pre-rostered native_settlement worker as the existing IOS path.
    // No Android control, observation or tail is created/borrowed here.
    pub(super) fn settle_ios(&mut self,used:bool,end:Instant,
        expired:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool)->NativeSettlement {
        if !self.ios()||self.settlement_started||self.phase==NativePhase::Claimed&&!used&&!self.runtime.no_child_effect(){
            return NativeSettlement{originals_closed:false,integrity:false};}
        self.settlement_started=true;self.phase=NativePhase::Settling;let _=expired(self.first_failure());
        let mut integrity=!used||self.first_failure().is_none();
        if used {
            let runtime=self.runtime.check_claimed_before_settlement(expired);
            publish_macos_returned_failure(runtime.as_ref().err().copied(),||self.runtime.first_failure(),&mut|first|{let _=expired(first);});
            if let Err(issue)=runtime{self.failure.get_or_insert((issue,Instant::now()));integrity=false;}
            let result=match &self.tools{ExecuteTools::Ios(original)=>original.check_after_use(end),_=>unreachable!()};
            let tools_first=match &self.tools{ExecuteTools::Ios(original)=>original.first_failure(),_=>None};
            publish_macos_returned_failure(result.as_ref().err().copied(),||tools_first,&mut|first|{let _=expired(first);});
            if let Err(issue)=result{self.failure.get_or_insert((issue,Instant::now()));integrity=false;}
        }
        // Independent consuming calls, even if the first returns Unknown.
        let tools=match &mut self.tools{ExecuteTools::Ios(original)=>original.settle_originals(expired),_=>unreachable!()};
        let runtime=self.runtime.settle_originals(expired);let _=expired(self.first_failure());
        let originals_closed=tools==CloseOutcome::Settled&&runtime==CloseOutcome::Settled&&self.runtime.settled()
            &&matches!(&self.tools,ExecuteTools::Ios(original) if original.settled());
        self.phase=if originals_closed{NativePhase::Settled}else{NativePhase::Unknown};NativeSettlement{originals_closed,integrity}
    }
    pub(super) fn ios_settled(&self)->bool{self.ios()&&self.phase==NativePhase::Settled&&self.runtime.settled()&&matches!(&self.tools,ExecuteTools::Ios(t) if t.settled())}
}

pub(super) fn spawn_original(inner:&Inner,owner:&Session,runtime:VerifiedRuntime,native:Option<Arc<Mutex<ExecuteNativeBooks>>>){
    if owner.domain!=SavedCommandDomain::LocalStoreExecute||inner.domain!=owner.domain||!inner.qualified(None)||Profile::current(owner.domain)!=Some(owner.profile){inner.stop(owner,Reason::RuntimeUnavailable);return;}
    let Some(native)=native else{inner.stop(owner,Reason::RuntimeUnavailable);return;};
    let mut native=match native.lock(){Ok(n)=>n,Err(_)=>{inner.unknown(owner);return;}};
    if let Err(f)=native.selected(&runtime){native.fail(f,owner);return;}
    if let Err(f)=native.check_tools_before_spawn(owner.clocks.work,&owner.stop.subscribe()){native.fail(f,owner);return;}
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

#[cfg(test)]
mod ios_tests {
    use super::*;
    // Same production consume; no inspector/native handle is acquired here.
    #[test]
    fn local_ios_execute_independent_original_closes_never_create_android_tail(){
        for failure in 0..3 {
            let end=Instant::now()+Duration::from_secs(30);let(_audit,audit)=watch::channel(end);let(_cleanup,cleanup)=watch::channel(end);
            let mut native=ExecuteNativeBooks::new_ios(audit,cleanup);
            assert!(native.control().is_none()&&native.ios());assert!(native.pre_go_bytes().is_some());
            assert!(native.execute_source_quote().is_none()&&native.execute_backing().is_none());
            if failure==1{native.runtime.mark_interrupted();}
            if failure==2{if let ExecuteTools::Ios(tools)=&mut native.tools{tools.mark_interrupted();}}
            let mut calls=0;let result=native.settle_ios(false,end,&mut |_|{calls+=1;false});
            assert!(calls>0);assert_eq!(result.originals_closed,failure==0);assert_eq!(native.ios_settled(),failure==0);
            if failure!=1{assert!(native.runtime.settled());}
            if failure!=2{assert!(matches!(&native.tools,ExecuteTools::Ios(tools) if tools.settled()));}
            assert!(native.control().is_none());
            let again=native.settle_ios(false,end,&mut |_|panic!("same originals cannot be consumed twice"));assert!(!again.originals_closed);
        }
    }
}
