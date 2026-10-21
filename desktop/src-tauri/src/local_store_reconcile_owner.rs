//! Typed LocalStoreReconcile adapter. The finite saved-command owner retains all originals.
//! No invoke future, DTO, sibling domain or caller gets resource custody here.
use std::{time::Instant,sync::Arc};
use crate::asset_session::SelectedStoreMaterial;
use tokio::sync::{oneshot, watch};
use crate::{asset_source::RegisteredRoot, local_store_reconcile_protocol::{Availability, Prepare, Start, Status},
    error::BridgeError, runtime::RuntimeConfig, saved_command_owner::SavedCommandOwner};

#[derive(Clone)]
pub(crate) struct LocalStoreReconcileOwner { saved: SavedCommandOwner }
pub(crate) struct Admitted { status: Status, release: Option<oneshot::Sender<()>> }
impl Admitted {
    pub(crate) fn new(status: Status, release: Option<oneshot::Sender<()>>) -> Self { Self { status, release } }
    /// Called ONLY after DocumentBinding unlocks. A dropped GO makes the
    /// original driver STOP; no new worker/cleanup owner is created by invoke.
    pub(crate) fn release(self) -> Status { if let Some(release) = self.release { let _ = release.send(()); } self.status }
}
impl LocalStoreReconcileOwner {
    pub(crate) fn new(runtime: RuntimeConfig) -> Self { Self { saved: SavedCommandOwner::local_store_reconcile(runtime) } }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn claim_matches(&self,c:&crate::saved_command_owner::LocalHistoryClaim)->bool{c.matches_owner(&self.saved)}
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn helper_matches(&self,c:&crate::saved_command_owner::LocalHistoryHelperClaim)->bool{c.matches_owner(&self.saved)}
    pub(crate) fn agent_store_original(&self) -> &SavedCommandOwner { &self.saved }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.saved.subscribe() }
    pub(crate) fn stopping(&self) -> bool { self.saved.stopping() }
    pub(crate) fn disabled(&self) -> bool { self.saved.disabled() }
    pub(crate) fn can_exit(&self) -> bool { self.saved.can_exit() }
    pub(crate) fn busy(&self) -> bool { self.saved.busy() }
    pub(crate) fn ensure_idle(&self) -> Result<(), BridgeError> { self.saved.ensure_idle() }
    pub(crate) fn prepared_project(&self, operation: &str, generation: &str) -> Result<String, BridgeError> {
        self.saved.prepared_project(operation, generation)
    }
    pub(crate) fn prepare(&self, input: Prepare, registration: u32, project: RegisteredRoot, gate: Availability, material: Arc<SelectedStoreMaterial>) -> Result<Status, BridgeError> {
        self.saved.prepare_store_reconcile(input, registration, project, gate, material)
    }
    pub(crate) fn start(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability, material: Arc<SelectedStoreMaterial>) -> Result<Admitted, BridgeError> {
        self.saved.start_store_reconcile(input, admitted_at, registered, gate, material)
    }
    pub(crate) fn prepared_material(&self, operation: &str, generation: &str)->Result<Arc<SelectedStoreMaterial>,BridgeError>{ self.saved.prepared_store_reconcile_material(operation,generation) }
    pub(crate) fn status(&self, gate: Availability) -> Result<Status, BridgeError> { self.saved.status_store_reconcile(gate) }
    pub(crate) fn cancel(&self, operation: &str, generation: &str, gate: Availability) -> Result<Status, BridgeError> {
        self.saved.cancel_store_reconcile(operation, generation, gate)
    }
    pub(crate) fn document_lost(&self) { self.saved.document_lost(); }
    pub(crate) fn context_changed(&self) { self.saved.context_changed(); }
    pub(crate) fn registration_matches(&self, registration: u32) -> bool { self.saved.registration_matches(registration) }
    pub(crate) fn known_existing_identity(&self, project_id: &str, registration: u32, root: &RegisteredRoot,
        platform: crate::project_identity_edit_protocol::Platform) -> Result<bool, BridgeError> {
        self.saved.known_existing_identity(project_id, registration, root, platform)
    }
    pub(crate) fn request_shutdown(&self) { self.saved.request_shutdown(); }
    pub(crate) async fn shutdown(&self) -> Result<(), BridgeError> { self.saved.shutdown().await }
    // Tests borrow this exact original owner. Inner/Session/handle fields remain
    // private in saved_command_owner; this creates no synthetic receipt/permit.
    #[cfg(test)]
    pub(crate) fn original_for_test(&self) -> &SavedCommandOwner { &self.saved }
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("local_store_reconcile_unavailable", "Local Store target readbacks are unavailable for this original document, host and runtime.")
}
