//! Document gate for one explicitly consented internal Store execution on the existing saved owner.
use super::*;
use crate::local_store_execute_protocol as wire;
// Borrowed from the SAME locked Document and original material census. No
// renderer/standalone constructor and no value can outlive that lock borrow.
pub(crate) struct ExecuteMemoryAdmission<'a>{remaining:usize,material:&'a Arc<SelectedStoreMaterial>,_state:&'a DocumentState}
impl ExecuteMemoryAdmission<'_>{
    pub(crate) fn accepts(&self,material:&Arc<SelectedStoreMaterial>,actual:usize)->bool{
        Arc::ptr_eq(self.material,material)&&actual<=self.remaining
    }
}
impl DocumentBinding {
    pub(crate) fn local_store_execute_subscribe(&self)->watch::Receiver<u32>{self.inner.bridge.local_store_execute.subscribe()}
    pub(crate) fn local_store_execute_relay_lost(&self){let _state=self.lock();self.inner.bridge.local_store_execute.document_lost();}
    pub(crate) fn local_store_execute_status(&self)->Result<wire::Status,BridgeError>{
        let state=self.lock();
        if !self.inner.bridge.local_store_execute.registration_matches(self.inner.bridge.registry_generation()){
            self.inner.bridge.local_store_execute.context_changed();
        }
        self.inner.bridge.local_store_execute.status(self.local_store_execute_gate(&state))
    }
    pub(crate) fn prepare_local_store_execute(&self,args:wire::Prepare)->Result<wire::Status,BridgeError>{
        let mut state=self.lock();let gate=self.local_store_execute_gate(&state);
        if gate!=wire::Availability::Available{return Err(crate::local_store_execute_owner::unavailable());}
        let selected=self.registry_result(&mut state,self.inner.bridge.native_project(&args.project_id),None);
        let(registration,root)=selected.map_err(|_|crate::local_store_execute_owner::unavailable())?;
        let material=self.review_store_execute_material(&state,&args.context(),registration,&root)?;
        self.store_execute_budget(&state,&material)?;
        self.inner.bridge.local_store_execute.prepare(args,registration,root,gate,material)
    }
    pub(crate) fn start_local_store_execute(&self,args:wire::Start)->Result<wire::Status,BridgeError>{
        let admitted_at=Instant::now(); // Original endpoint begins before lock/lookup/queue.
        let mut state=self.lock();
        let original=self.inner.bridge.local_store_execute.prepared_material(&args.operation_id,&args.owner_generation)?;
        let project=self.inner.bridge.local_store_execute.prepared_project(&args.operation_id,&args.owner_generation)?;
        let selected=self.registry_result(&mut state,self.inner.bridge.native_project(&project),None).ok();
        let current=selected.as_ref().is_some_and(|(registration,root)|
            self.recheck_store_execute_material(&state,&original,*registration,root).is_ok());
        if !current || !original.accepts_execute_consent(&args) {
            // Retire the actual intent, not a replacement loan. No private write/GO.
            self.inner.bridge.local_store_execute.context_changed();
            return Err(crate::local_store_execute_owner::unavailable());
        }
        let budget=match self.store_execute_budget(&state,&original){Ok(value)=>value,Err(error)=>{
            self.inner.bridge.local_store_execute.context_changed();return Err(error);
        }};
        let admitted=self.inner.bridge.local_store_execute.start(args,admitted_at,selected,self.local_store_execute_gate(&state),original.clone(),&budget)?;
        drop(state);Ok(admitted.release())
    }
    pub(crate) fn cancel_local_store_execute(&self,args:wire::Cancel)->Result<wire::Status,BridgeError>{
        let state=self.lock();self.inner.bridge.local_store_execute.cancel(&args.operation_id,&args.owner_generation,self.local_store_execute_gate(&state))
    }
    pub(super) fn store_execute_budget<'a>(&self,state:&'a DocumentState,loan:&'a Arc<SelectedStoreMaterial>)->Result<ExecuteMemoryAdmission<'a>,BridgeError>{
        #[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {
            let future=crate::saved_command_owner::store_execute_document_backing_bytes().ok_or_else(crate::local_store_execute_owner::unavailable)?;
            let actual=lookup_memory::store_preflight_admission_bytes(&self.inner,state,loan,future)
                .map_err(|_|crate::local_store_execute_owner::unavailable())?;
            let remaining=lookup_memory::execute_remaining_from_admitted_total(actual,std::mem::size_of::<ExecuteMemoryAdmission<'_>>())
                .ok_or_else(crate::local_store_execute_owner::unavailable)?;
            Ok(ExecuteMemoryAdmission{remaining,material:loan,_state:state})
        }
        #[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
        {let _=(state,loan);Err(crate::local_store_execute_owner::unavailable())}
    }
}
