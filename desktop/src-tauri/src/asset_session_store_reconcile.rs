//! Document gate for one nonpublishing Store target readback on the existing saved owner.
use super::*;
use crate::local_store_reconcile_protocol as wire;
impl DocumentBinding {
    pub(crate) fn local_store_reconcile_subscribe(&self)->watch::Receiver<u32>{self.inner.bridge.local_store_reconcile.subscribe()}
    pub(crate) fn local_store_reconcile_relay_lost(&self){let _state=self.lock();self.inner.bridge.local_store_reconcile.document_lost();}
    pub(crate) fn local_store_reconcile_status(&self)->Result<wire::Status,BridgeError>{
        let state=self.lock();
        if !self.inner.bridge.local_store_reconcile.registration_matches(self.inner.bridge.registry_generation()){
            self.inner.bridge.local_store_reconcile.context_changed();
        }
        self.inner.bridge.local_store_reconcile.status(self.local_store_reconcile_gate(&state))
    }
    pub(crate) fn prepare_local_store_reconcile(&self,args:wire::Prepare)->Result<wire::Status,BridgeError>{
        let mut state=self.lock();let gate=self.local_store_reconcile_gate(&state);
        if gate!=wire::Availability::Available{return Err(crate::local_store_reconcile_owner::unavailable());}
        let selected=self.registry_result(&mut state,self.inner.bridge.native_project(&args.project_id),None);
        let(registration,root)=selected.map_err(|_|crate::local_store_reconcile_owner::unavailable())?;
        let material=self.review_store_reconcile_material(&state,&args.context(),registration,&root)?;
        self.store_reconcile_budget(&state,&material)?;
        self.inner.bridge.local_store_reconcile.prepare(args,registration,root,gate,material)
    }
    pub(crate) fn start_local_store_reconcile(&self,args:wire::Start)->Result<wire::Status,BridgeError>{
        let admitted_at=Instant::now(); // Original endpoint begins before lock/lookup/queue.
        let mut state=self.lock();
        let original=self.inner.bridge.local_store_reconcile.prepared_material(&args.operation_id,&args.owner_generation)?;
        let project=self.inner.bridge.local_store_reconcile.prepared_project(&args.operation_id,&args.owner_generation)?;
        let selected=self.registry_result(&mut state,self.inner.bridge.native_project(&project),None).ok();
        let current=selected.as_ref().is_some_and(|(registration,root)|
            self.recheck_store_reconcile_material(&state,&original,*registration,root).is_ok());
        if !current || self.store_reconcile_budget(&state,&original).is_err(){
            // Retire the actual intent, not a replacement loan. No private write/GO.
            self.inner.bridge.local_store_reconcile.context_changed();
            return Err(crate::local_store_reconcile_owner::unavailable());
        }
        let admitted=self.inner.bridge.local_store_reconcile.start(args,admitted_at,selected,self.local_store_reconcile_gate(&state),original)?;
        drop(state);Ok(admitted.release())
    }
    pub(crate) fn cancel_local_store_reconcile(&self,args:wire::Cancel)->Result<wire::Status,BridgeError>{
        let state=self.lock();self.inner.bridge.local_store_reconcile.cancel(&args.operation_id,&args.owner_generation,self.local_store_reconcile_gate(&state))
    }
    fn store_reconcile_budget(&self,state:&DocumentState,loan:&Arc<SelectedStoreMaterial>)->Result<(),BridgeError>{
        #[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {
            let future=crate::saved_command_owner::store_reconcile_document_backing_bytes().ok_or_else(crate::local_store_reconcile_owner::unavailable)?;
            lookup_memory::store_preflight_admission_bytes(&self.inner,state,loan,future)
                .map_err(|_|crate::local_store_reconcile_owner::unavailable())?;Ok(())
        }
        #[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
        {let _=(state,loan);Err(crate::local_store_reconcile_owner::unavailable())}
    }
}
