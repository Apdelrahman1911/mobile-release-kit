//! Compare-only weak originals for a one-use preparation scope. No new loan.
use super::*;
use std::sync::Weak;
pub(crate) struct ApplePreparationMaterial {
    native: Weak<NativeContext>,
    payload: Weak<Payload>,
    key: RecordKey,
}
impl SelectedStoreMaterial {
    pub(crate) fn apple_preparation_material(
        &self,
    ) -> Result<ApplePreparationMaterial, BridgeError> {
        if !matches!(&self.command, Some(StoreCommand::Provisioning(_)))
            || apple_parts(&self.payload).is_none()
        {
            return Err(refused());
        }
        Ok(ApplePreparationMaterial {
            native: Arc::downgrade(&self.native),
            payload: Arc::downgrade(&self.payload),
            key: self.key.clone(),
        })
    }
}
impl ApplePreparationMaterial {
    pub(crate) fn matches(&self, other: &SelectedStoreMaterial) -> bool {
        self.native
            .upgrade()
            .is_some_and(|n| Arc::ptr_eq(&n, &other.native))
            && self
                .payload
                .upgrade()
                .is_some_and(|p| Arc::ptr_eq(&p, &other.payload))
            && self.key == other.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_comparison_never_keeps_retired_private_material_alive() {
        let context = crate::asset_session::AppleProvisioningDocumentInput::census_context(
            crate::apple_provisioning_protocol::Mode::Review,
        );
        let original = SelectedStoreMaterial::apple_census_data(&context, 32, 32, 0);
        assert!(original.apple_preparation_material().is_err()); // no real observed P8/fields in this fixture
                                                                 // Weak comparison DATA only, not a source/permission constructor.
        let comparison = ApplePreparationMaterial {
            native: Arc::downgrade(&original.native),
            payload: Arc::downgrade(&original.payload),
            key: original.key.clone(),
        };
        let foreign = SelectedStoreMaterial::apple_census_data(&context, 32, 32, 0);
        assert!(comparison.matches(&original));
        assert!(!comparison.matches(&foreign));
        let held_writer = original.clone();
        drop(original);
        assert!(comparison.payload.upgrade().is_some());
        assert!(comparison.matches(&held_writer));
        drop(held_writer);
        assert!(comparison.payload.upgrade().is_none() && comparison.native.upgrade().is_none());
        assert!(!comparison.matches(&foreign));
    }
}
