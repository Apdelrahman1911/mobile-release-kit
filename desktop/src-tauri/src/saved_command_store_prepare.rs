//! Typed local Prepare adapter; execution stays on the original Session.
use super::*;
impl SavedCommandOwner {
    pub(crate) fn local_store_prepare(runtime: RuntimeConfig) -> Self {Self::new(runtime,SavedCommandDomain::LocalStorePrepare)}
    pub(crate) fn prepare_store_prepare(&self,input:prepare_wire::Prepare,registration:u32,project:RegisteredRoot,
        gate:prepare_wire::Availability,material:Arc<SelectedStoreMaterial>)->Result<prepare_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePrepare)?;
        self.prepare_bound(Context::LocalStorePrepare(input.context()),registration,project,Availability::from_store(gate),Some(PrivateSigningMaterial::Store(material)),None)?.prepare()
    }
    pub(crate) fn prepared_store_prepare_material(&self,operation:&str,generation:&str)->Result<Arc<SelectedStoreMaterial>,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePrepare)?;
        let registry=self.inner.lock();
        let prepared=registry.prepared.as_ref().filter(|p|p.projection.operation_id==operation&&p.projection.owner_generation==generation).ok_or_else(||self.inner.domain.invalid_owner())?;
        match &prepared.material{Some(PrivateSigningMaterial::Store(value))=>Ok(value.clone()),_=>Err(self.inner.domain.invalid_owner())}
    }
    pub(crate) fn start_store_prepare(&self,input:prepare_wire::Start,admitted_at:Instant,registered:Option<(u32,RegisteredRoot)>,
        gate:prepare_wire::Availability,material:Arc<SelectedStoreMaterial>)->Result<crate::local_store_prepare_owner::Admitted,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePrepare)?;
        let admitted=self.start_bound(Start{operation_id:input.operation_id,owner_generation:input.owner_generation},admitted_at,registered,
            Availability::from_store(gate),Some(PrivateSigningMaterial::Store(material)))?;
        Ok(crate::local_store_prepare_owner::Admitted::new(admitted.status.prepare()?,admitted.release))
    }
    pub(crate) fn status_store_prepare(&self,gate:prepare_wire::Availability)->Result<prepare_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePrepare)?;self.status(Availability::from_store(gate))?.prepare()
    }
    pub(crate) fn cancel_store_prepare(&self,operation:&str,generation:&str,gate:prepare_wire::Availability)->Result<prepare_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePrepare)?;self.cancel(operation,generation,Availability::from_store(gate))?.prepare()
    }
}

pub(crate) fn document_backing_bytes()->Option<usize>{
    // Reuse the actual cells/ordinary buffers, adding only the fixed phase delta.
    store::document_backing_bytes()?.checked_add(6usize.checked_mul(prepare_wire::RESPONSE_LIMIT.checked_sub(store_wire::RESPONSE_LIMIT)?)?)
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn local_prepare_uses_original_store_clock_and_separate_frame_reason_limits(){
        let now=Instant::now();let c=Clocks::new(SavedCommandDomain::LocalStorePrepare,now);
        assert_eq!(c.work-now,Duration::from_secs(1200));assert_eq!(c.finality-now,Duration::from_secs(1210));
        assert_eq!(c.settlement(Some(now+Duration::from_secs(3))),now+Duration::from_secs(13));
        assert_eq!(SavedCommandDomain::LocalStorePrepare.frame_limit(),6);assert_eq!(SavedCommandDomain::LocalStorePreflight.frame_limit(),2);
        assert_eq!(SavedCommandDomain::LocalStorePrepare.response_limit(),64*1024);assert_eq!(SavedCommandDomain::LocalStorePreflight.response_limit(),16*1024);
        assert_eq!(Reason::PrepareUnavailable.prepare().unwrap(),prepare_wire::Reason::PrepareUnavailable);
        assert!(Reason::PrepareUnavailable.store().is_err()&&Reason::PrepareUnavailable.android().is_err());
        assert!(document_backing_bytes().unwrap()>store::document_backing_bytes().unwrap());
        assert!(document_backing_bytes().unwrap()<1024*1024);
        assert!(Context::LocalStorePrepare(prepare_wire::tests::context()).requires_private_material());
    }
}
