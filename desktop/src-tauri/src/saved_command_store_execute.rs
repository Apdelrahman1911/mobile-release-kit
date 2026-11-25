//! Typed local Execute adapter; execution stays on the original Session.
use super::*;
impl SavedCommandOwner {
    pub(crate) fn local_store_execute(runtime: RuntimeConfig) -> Self {Self::new(runtime,SavedCommandDomain::LocalStoreExecute)}
    pub(crate) fn prepare_store_execute(&self,input:execute_wire::Prepare,registration:u32,project:RegisteredRoot,
        gate:execute_wire::Availability,material:Arc<SelectedStoreMaterial>)->Result<execute_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreExecute)?;
        self.prepare_bound(Context::LocalStoreExecute(input.context()),registration,project,Availability::from_store(gate),Some(PrivateSigningMaterial::Store(material)),None)?.execute()
    }
    pub(crate) fn prepared_store_execute_material(&self,operation:&str,generation:&str)->Result<Arc<SelectedStoreMaterial>,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreExecute)?;
        let registry=self.inner.lock();
        let prepared=registry.prepared.as_ref().filter(|p|p.projection.operation_id==operation&&p.projection.owner_generation==generation).ok_or_else(||self.inner.domain.invalid_owner())?;
        match &prepared.material{Some(PrivateSigningMaterial::Store(value))=>Ok(value.clone()),_=>Err(self.inner.domain.invalid_owner())}
    }
    pub(crate) fn start_store_execute(&self,input:execute_wire::Start,admitted_at:Instant,registered:Option<(u32,RegisteredRoot)>,
        gate:execute_wire::Availability,material:Arc<SelectedStoreMaterial>,budget:&crate::asset_session::ExecuteMemoryAdmission<'_>)->Result<crate::local_store_execute_owner::Admitted,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreExecute)?;
        if !material.accepts_execute_consent(&input){return Err(execute_wire::invalid());}
        let admitted=self.start_bound_checked(Start{operation_id:input.operation_id,owner_generation:input.owner_generation},admitted_at,registered,
            Availability::from_store(gate),Some(PrivateSigningMaterial::Store(material)),Some(budget))?;
        Ok(crate::local_store_execute_owner::Admitted::new(admitted.status.execute()?,admitted.release))
    }
    pub(crate) fn status_store_execute(&self,gate:execute_wire::Availability)->Result<execute_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreExecute)?;self.status(Availability::from_store(gate))?.execute()
    }
    pub(crate) fn cancel_store_execute(&self,operation:&str,generation:&str,gate:execute_wire::Availability)->Result<execute_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreExecute)?;self.cancel(operation,generation,Availability::from_store(gate))?.execute()
    }
}

pub(crate) fn document_backing_bytes()->Option<usize>{
    // Same six-frame Store envelope. Native concrete books are precharged by
    // their original Start constructor, before release of the same GO edge.
    store_prepare::document_backing_bytes()
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn local_execute_uses_separate_domain_with_original_store_clock_and_no_cross_reason(){
        let now=Instant::now();let c=Clocks::new(SavedCommandDomain::LocalStoreExecute,now);
        assert_eq!(c.work-now,Duration::from_secs(1200));assert_eq!(c.finality-now,Duration::from_secs(1210));
        assert_eq!(c.settlement(Some(now+Duration::from_secs(3))),now+Duration::from_secs(13));
        assert_eq!(SavedCommandDomain::LocalStoreExecute.frame_limit(),6);
        assert_eq!(SavedCommandDomain::LocalStoreExecute.response_limit(),64*1024);
        assert_eq!(Reason::ExecuteUnavailable.execute().unwrap(),execute_wire::Reason::ExecuteUnavailable);
        assert!(Reason::ExecuteUnavailable.prepare().is_err()&&Reason::ExecuteUnavailable.store().is_err()&&Reason::ExecuteUnavailable.android().is_err());
        assert!(Reason::PrepareUnavailable.execute().is_err());
        assert!(Context::LocalStoreExecute(execute_wire::tests::context()).requires_private_material());
        assert!(document_backing_bytes().unwrap()<1024*1024);
    }
}
