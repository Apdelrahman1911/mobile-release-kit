//! Unsupported Windows Apple entry. No state/service/credential acquisition occurs.
use super::*;
use crate::{apple_provisioning_protocol as wire,apple_provisioning_journal::AccountRef,
    application_service_host::NativeStateReady};
pub(crate) enum AppleProvisioningDocumentInput {}
impl AppleProvisioningDocumentInput {
    pub(crate) fn census_assets(&self) -> Result<[Option<Arc<OriginalWork>>; 2], BridgeError> {match *self {}}
    pub(crate) fn context(&self) -> &wire::Context {match *self {}}
    pub(crate) fn material(&self) -> &Arc<SelectedStoreMaterial> {match *self {}}
    pub(crate) fn ready(&self) -> &Arc<NativeStateReady> {match *self {}}
    pub(crate) fn account(&self) -> &AccountRef {match *self {}}
    pub(crate) fn matches(
        &self,
        context: &wire::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {match *self {}}
    pub(crate) fn same_selection(&self, other: &Self) -> bool {match *self {}}
    pub(crate) fn current(&self) -> Result<(), BridgeError> {match *self {}}
    pub(crate) fn scope(
        &self,
        operation: &str,
        generation: &str,
        reviewed_at: Option<String>,
    ) -> Result<wire::ScopeData, BridgeError> {match *self {}}
}
impl DocumentBinding {
    pub(crate) fn apple_provisioning_subscribe(&self) -> watch::Receiver<u32> {self.inner.bridge.apple_provisioning.subscribe()}
    pub(crate) fn apple_provisioning_relay_lost(&self) {/* no Windows relay/native acquisition exists */}
    pub(crate) async fn prepare_apple_provisioning(
        &self,
        input: wire::Prepare,
        app_data: &std::path::Path,
    ) -> Result<wire::Status, BridgeError> {Err(BridgeError::new("unsupported_platform","Apple provisioning is unavailable on this platform."))}
    pub(crate) fn start_apple_provisioning(
        &self,
        input: wire::Start,
    ) -> Result<wire::Status, BridgeError> {Err(BridgeError::new("unsupported_platform","Apple provisioning is unavailable on this platform."))}
    pub(crate) fn status_apple_provisioning(&self) -> Result<wire::Status, BridgeError> {self.inner.bridge.apple_provisioning.status_apple_provisioning(wire::Availability::UnsupportedPlatform)}
    pub(crate) fn cancel_apple_provisioning(
        &self,
        input: wire::Cancel,
    ) -> Result<wire::Status, BridgeError> {Err(BridgeError::new("unsupported_platform","Apple provisioning is unavailable on this platform."))}
}
