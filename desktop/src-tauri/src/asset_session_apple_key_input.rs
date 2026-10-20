//! Fixed key-only access through the original Apple Document input. A stopped
//! operation may preserve its already generated key, but cannot prepare a new
//! operation, refresh a review, change sources or admit a provider request.
use super::*;
use crate::{credential_setup::KeyReference, saved_command_owner::AppleKeySession};
use vault::{distribution_key::InventoryPoint, key_sources::AppleKeySources};

impl AppleProvisioningDocumentInput {
    pub(crate) fn key_sources(&self) -> Option<&Arc<AppleKeySources>> {
        self.material.key_sources()
    }
    pub(in crate::asset_session) fn retain_key_asset(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        if !self.context.mode.local_key() || self.key_sources().is_none() {
            return Err(wire::invalid());
        }
        let mut held = self
            .key_asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if held.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        *held = Some(original.clone());
        Ok(())
    }
    fn key_document(&self, original: &Arc<OriginalWork>) -> Result<DocumentBinding, BridgeError> {
        if !self.key_asset.try_lock().is_ok_and(|held| {
            held.as_ref()
                .is_some_and(|same| Arc::ptr_eq(same, original))
        }) {
            return Err(BridgeError::cleanup_unknown());
        }
        Ok(DocumentBinding {
            inner: self
                .document
                .upgrade()
                .ok_or_else(BridgeError::cleanup_unknown)?,
        })
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn check_key_before_pending(&self) -> Result<(), BridgeError> {
        let original = self
            .key_asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let document = self.key_document(&original)?;
        self.current()?;
        super::super::apple_key::recheck_before_pending(&document, &original).await?;
        self.current()
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn join_key_asset(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<Option<KeyReference>, BridgeError> {
        super::super::apple_key::joined(&self.key_document(original)?, original).await
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn retire_key_asset(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        super::super::apple_key::retired(&self.key_document(original)?, original).await?;
        let mut held = self
            .key_asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if held
            .as_ref()
            .is_none_or(|same| !Arc::ptr_eq(same, original))
        {
            return Err(BridgeError::cleanup_unknown());
        }
        // Only after actual release/source/retirement return, not an empty
        // status, the private-drained bit, or the receiver acknowledgement.
        held.take();
        Ok(())
    }
    pub(crate) fn key_scope(
        &self,
        parent: &AppleKeySession,
        review: Option<wire::KeyReviewData>,
    ) -> Result<wire::KeyScopeData, BridgeError> {
        if !self.context.mode.local_key() {
            return Err(wire::invalid());
        }
        let sources = self.key_sources().ok_or_else(wire::invalid)?;
        let original = sources.owner().ok_or_else(wire::invalid)?;
        let inventory = sources.inventory().ok_or_else(wire::invalid)?;
        if !sources.checked(&original, InventoryPoint::Initial) {
            return Err(wire::invalid());
        }
        let (records, keys) = inventory.counts();
        Ok(wire::KeyScopeData {
            source_p8: sources.reference(),
            source_key: None,
            destination: parent.destination_data()?,
            entitlements: serde_json::json!({}),
            review,
            vault_inventory: wire::KeyVaultInventory {
                records: u32::try_from(records).map_err(|_| wire::invalid())?,
                keys: u32::try_from(keys).map_err(|_| wire::invalid())?,
            },
        })
    }
    /// The sole key-prepare preservation check. Called OFF native IO books,
    /// before/after the existing retained journal job. It never calls the
    /// normal gate/assignment projection, which STOP correctly invalidates.
    /// The actual retained input, full source/roster and Host remain required.
    pub(crate) fn key_preservation_current(
        &self,
        parent: &AppleKeySession,
    ) -> Result<(), BridgeError> {
        let original = self
            .key_asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let binding = self.key_document(&original)?;
        let document = &binding.inner;
        let state = document
            .state
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if self.context.mode != wire::Mode::KeyPrepare
            || !parent.preservation_pending(&original)
            || !state.lifetime.original_bound()
            || state.lost_observed
            || state.unknown
            || state.exhausted
            || state.retiring
            || state.lock_pending
            || state.compatibility_picker_pending
            || state.maintenance.closed()
            || !state
                .apple_provisioning_ready
                .as_ref()
                .is_some_and(|ready| Arc::ptr_eq(ready, &self.state))
        {
            return Err(changed());
        }
        // No call below this guard recomputes the unrelated-owner gate or
        // takes Edit recursively. It compares the original saved lane only.
        let edit = document
            .bridge
            .edits
            .saved_registration_guard(&document.session_identity)?;
        if !self.saved.current_locked(
            document,
            &state,
            &edit,
            &self.context,
            self.registration,
            &self.root,
        ) || !self.material.key_preservation_current(
            &binding,
            &state,
            &original,
            parent,
            &self.context,
            self.registration,
            &self.root,
        ) {
            return Err(changed());
        }
        document
            .bridge
            .application_service
            .native_state_current(&self.state, &self.project(document)?)
            .map_err(startup_error)?;
        let (account, target) = self.material.provisioning_account_target(
            &self.context,
            self.registration,
            &self.root,
        )?;
        if account != self.account || target != self.target {
            return Err(changed());
        }
        Ok(())
    }
}

// Compile-only unavailable surface for the non-Desktop observer/CLI graph.
// No original lookup or Option::None is presented as native closure.
#[cfg(not(feature = "desktop-shell"))]
impl AppleProvisioningDocumentInput {
    pub(crate) async fn check_key_before_pending(&self) -> Result<(), BridgeError> {
        Err(BridgeError::unavailable(
            "Apple key preparation requires the desktop application.",
        ))
    }
    pub(crate) async fn join_key_asset(
        &self,
        _: &Arc<OriginalWork>,
    ) -> Result<Option<KeyReference>, BridgeError> {
        Err(BridgeError::cleanup_unknown())
    }
    pub(crate) async fn retire_key_asset(&self, _: &Arc<OriginalWork>) -> Result<(), BridgeError> {
        Err(BridgeError::cleanup_unknown())
    }
}
