//! Typed local target-readback adapter; execution stays on the original Session.
use super::*;
impl SavedCommandOwner {
    pub(crate) fn local_store_reconcile(runtime: RuntimeConfig) -> Self {Self::new(runtime,SavedCommandDomain::LocalStoreReconcile)}
    pub(crate) fn prepare_store_reconcile(&self,input:reconcile_wire::Prepare,registration:u32,project:RegisteredRoot,
        gate:reconcile_wire::Availability,material:Arc<SelectedStoreMaterial>)->Result<reconcile_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreReconcile)?;
        self.prepare_bound(Context::LocalStoreReconcile(input.context()),registration,project,Availability::from_store(gate),Some(PrivateSigningMaterial::Store(material)),None)?.reconcile()
    }
    pub(crate) fn prepared_store_reconcile_material(&self,operation:&str,generation:&str)->Result<Arc<SelectedStoreMaterial>,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreReconcile)?;
        let registry=self.inner.lock();
        let prepared=registry.prepared.as_ref().filter(|p|p.projection.operation_id==operation&&p.projection.owner_generation==generation).ok_or_else(||self.inner.domain.invalid_owner())?;
        match &prepared.material{Some(PrivateSigningMaterial::Store(value))=>Ok(value.clone()),_=>Err(self.inner.domain.invalid_owner())}
    }
    pub(crate) fn start_store_reconcile(&self,input:reconcile_wire::Start,admitted_at:Instant,registered:Option<(u32,RegisteredRoot)>,
        gate:reconcile_wire::Availability,material:Arc<SelectedStoreMaterial>)->Result<crate::local_store_reconcile_owner::Admitted,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreReconcile)?;
        let admitted=self.start_bound(Start{operation_id:input.operation_id,owner_generation:input.owner_generation},admitted_at,registered,
            Availability::from_store(gate),Some(PrivateSigningMaterial::Store(material)))?;
        Ok(crate::local_store_reconcile_owner::Admitted::new(admitted.status.reconcile()?,admitted.release))
    }
    pub(crate) fn status_store_reconcile(&self,gate:reconcile_wire::Availability)->Result<reconcile_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreReconcile)?;self.status(Availability::from_store(gate))?.reconcile()
    }
    pub(crate) fn cancel_store_reconcile(&self,operation:&str,generation:&str,gate:reconcile_wire::Availability)->Result<reconcile_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStoreReconcile)?;self.cancel(operation,generation,Availability::from_store(gate))?.reconcile()
    }
}

pub(crate) fn document_backing_bytes()->Option<usize>{
    // Reuse the actual cells/ordinary buffers, adding only the fixed phase delta.
    store::document_backing_bytes()?.checked_add(6usize.checked_mul(reconcile_wire::RESPONSE_LIMIT.checked_sub(store_wire::RESPONSE_LIMIT)?)?)
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn local_reconcile_uses_original_store_clock_and_separate_frame_reason_limits(){
        let now=Instant::now();let c=Clocks::new(SavedCommandDomain::LocalStoreReconcile,now);
        assert_eq!(c.work-now,Duration::from_secs(1200));assert_eq!(c.finality-now,Duration::from_secs(1210));
        assert_eq!(c.settlement(Some(now+Duration::from_secs(3))),now+Duration::from_secs(13));
        assert_eq!(SavedCommandDomain::LocalStoreReconcile.frame_limit(),4);assert_eq!(SavedCommandDomain::LocalStorePreflight.frame_limit(),2);
        assert_eq!(SavedCommandDomain::LocalStoreReconcile.response_limit(),64*1024);assert_eq!(SavedCommandDomain::LocalStorePreflight.response_limit(),16*1024);
        assert_eq!(Reason::ReconcileUnavailable.reconcile().unwrap(),reconcile_wire::Reason::ReconcileUnavailable);
        assert!(Reason::ReconcileUnavailable.store().is_err()&&Reason::ReconcileUnavailable.android().is_err());
        assert!(document_backing_bytes().unwrap()>store::document_backing_bytes().unwrap());
        assert!(document_backing_bytes().unwrap()<1024*1024);
        assert!(Context::LocalStoreReconcile(reconcile_wire::tests::context()).requires_private_material());
    }
}
