//! Profile-only access through the SAME original Document input. Neither an
//! IPC record counter nor a historical journal row can construct these loans.
use super::*;
use crate::{credential_setup::KeyReference, saved_command_owner::AppleProfileSession};
use vault::profile_sources::{AppleProfileSources, CheckPoint};

impl AppleProvisioningDocumentInput {
    pub(crate) fn profile_sources(&self) -> Option<&Arc<AppleProfileSources>> {
        self.material.profile_sources()
    }
    pub(in crate::asset_session) fn retain_profile_asset(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        if !self.context.mode.profile() || self.profile_sources().is_none() {
            return Err(wire::invalid());
        }
        let mut held = self
            .profile_asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if held.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        *held = Some(original.clone());
        Ok(())
    }
    fn profile_document(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<DocumentBinding, BridgeError> {
        if !self.profile_asset.try_lock().is_ok_and(|held| {
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
    pub(crate) async fn check_profile_before_pending(&self) -> Result<(), BridgeError> {
        self.check_profile(CheckPoint::BeforePending).await
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn check_profile_before_save(&self) -> Result<(), BridgeError> {
        self.check_profile(CheckPoint::BeforeSave).await
    }
    #[cfg(feature = "desktop-shell")]
    async fn check_profile(&self, point: CheckPoint) -> Result<(), BridgeError> {
        let original = self
            .profile_asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let document = self.profile_document(&original)?;
        self.current()?;
        super::super::apple_profile::recheck(&document, &original, point).await?;
        self.current()
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn join_profile_asset(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<Option<KeyReference>, BridgeError> {
        super::super::apple_profile::joined(&self.profile_document(original)?, original).await
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn retire_profile_asset(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        super::super::apple_profile::retired(&self.profile_document(original)?, original).await?;
        let mut held = self
            .profile_asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if held
            .as_ref()
            .is_none_or(|same| !Arc::ptr_eq(same, original))
        {
            return Err(BridgeError::cleanup_unknown());
        }
        // The actual source/child/coordinator and retirement observers returned.
        // Dropping this comparison holding is not native closure evidence.
        held.take();
        Ok(())
    }
    pub(crate) fn profile_scope(
        &self,
        parent: &AppleProfileSession,
        review: Option<wire::ProfileReviewData>,
    ) -> Result<wire::ProfileScopeData, BridgeError> {
        let sources = self.profile_sources().ok_or_else(wire::invalid)?;
        if !self.context.mode.profile() {
            return Err(wire::invalid());
        }
        let selected = sources.p12();
        Ok(wire::ProfileScopeData {
            source_key: selected.reference(),
            destination: parent.destination_data()?,
            expected_certificate_sha256: crate::service_protocol::hex(
                &selected.expected_certificate_sha256(),
            ),
            p12_sha256: crate::service_protocol::hex(&selected.p12_sha256()),
            // No project/build execution or guessed capability synchronization.
            // This first flow checks the modern basic App-Store profile only;
            // later signed preflight still checks the actual app entitlements.
            entitlements: serde_json::json!({}),
            review,
            prior: None,
        })
    }
}

// The transport-only installed CLI still links the shared Saved owner, but it
// cannot enter the desktop-owned Asset jobs. Refusal is never a native join,
// a no-save result, or permission to release the original retained work.
#[cfg(not(feature = "desktop-shell"))]
impl AppleProvisioningDocumentInput {
    pub(crate) async fn check_profile_before_pending(&self) -> Result<(), BridgeError> {
        Err(BridgeError::unavailable(
            "Apple profile source checks require the desktop application.",
        ))
    }

    pub(crate) async fn check_profile_before_save(&self) -> Result<(), BridgeError> {
        Err(BridgeError::unavailable(
            "Apple profile source checks require the desktop application.",
        ))
    }

    pub(crate) async fn join_profile_asset(
        &self,
        _original: &Arc<OriginalWork>,
    ) -> Result<Option<KeyReference>, BridgeError> {
        Err(BridgeError::cleanup_unknown())
    }

    pub(crate) async fn retire_profile_asset(
        &self,
        _original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        Err(BridgeError::cleanup_unknown())
    }
}
