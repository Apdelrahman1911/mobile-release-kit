//! Fixed P12 checks on the original Apple Document input, never a new admission.
use super::*;
use crate::credential_setup::KeyReference;

impl AppleProvisioningDocumentInput {
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn check_p12_before_pending(&self) -> Result<(), BridgeError> {
        if self.context.mode != wire::Mode::P12Save {
            return Err(wire::invalid());
        }
        let original = self.p12_original()?;
        self.current()?;
        super::super::apple_key::p12::before_pending(&self.p12_document(&original)?, &original)
            .await?;
        self.current()
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn check_p12_after_worker(&self) -> Result<(), BridgeError> {
        if !self.context.mode.p12() {
            return Err(wire::invalid());
        }
        let original = self.p12_original()?;
        self.current()?;
        super::super::apple_key::p12::after_worker(&self.p12_document(&original)?, &original)
            .await?;
        self.current()
    }
    fn p12_original(&self) -> Result<Arc<OriginalWork>, BridgeError> {
        self.key_asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)
    }
    fn p12_document(&self, owner: &Arc<OriginalWork>) -> Result<DocumentBinding, BridgeError> {
        if !self
            .key_asset
            .try_lock()
            .is_ok_and(|held| held.as_ref().is_some_and(|same| Arc::ptr_eq(same, owner)))
        {
            return Err(BridgeError::cleanup_unknown());
        }
        Ok(DocumentBinding {
            inner: self
                .document
                .upgrade()
                .ok_or_else(BridgeError::cleanup_unknown)?,
        })
    }
    pub(crate) fn p12_reused_current(
        &self,
        reference: &KeyReference,
        leaf: &[u8; 32],
        p12: &[u8; 32],
    ) -> Result<(), BridgeError> {
        if !matches!(
            self.context.mode,
            wire::Mode::P12Review | wire::Mode::P12Reuse
        ) {
            return Err(wire::invalid());
        }
        let original = self.p12_original()?;
        let document = self.p12_document(&original)?;
        let state = document.lock();
        if !self.key_sources().is_some_and(|sources| {
            sources.reused_assignment_current(&document, &state, &original, reference, leaf, p12)
        }) {
            return Err(changed());
        }
        Ok(())
    }
    pub(crate) fn p12_scope(
        &self,
        parent: &crate::saved_command_owner::AppleKeySession,
        review: Option<wire::P12ReviewData>,
    ) -> Result<wire::P12ScopeData, BridgeError> {
        if !self.context.mode.p12() {
            return Err(wire::invalid());
        }
        let sources = self.key_sources().ok_or_else(wire::invalid)?;
        let original = sources.owner().ok_or_else(wire::invalid)?;
        if !sources.p12_checked(&original, vault::key_sources::p12::CheckPoint::BeforeWork) {
            return Err(wire::invalid());
        }
        let loan = sources.certificate_loan().ok_or_else(wire::invalid)?;
        let selected = sources.selected_p12();
        if selected.is_some() != sources.selected_p12_expected() {
            return Err(wire::invalid());
        }
        Ok(wire::P12ScopeData {
            source_p8: sources.reference(),
            source_key: loan.reference(),
            selected_p12: selected.as_ref().map(|loan| loan.reference()),
            expected_certificate_sha256: selected
                .as_ref()
                .map(|loan| crate::service_protocol::hex(&loan.expected_certificate_sha256())),
            p12_sha256: selected
                .as_ref()
                .map(|loan| crate::service_protocol::hex(&loan.p12_sha256())),
            destination: parent.p12_destination_data()?,
            review,
            previous: Vec::new(),
        })
    }
}

#[cfg(not(feature = "desktop-shell"))]
impl AppleProvisioningDocumentInput {
    pub(crate) async fn check_p12_before_pending(&self) -> Result<(), BridgeError> {
        Err(BridgeError::unavailable(
            "P12 setup requires the desktop application.",
        ))
    }
    pub(crate) async fn check_p12_after_worker(&self) -> Result<(), BridgeError> {
        Err(BridgeError::unavailable(
            "P12 setup requires the desktop application.",
        ))
    }
}
