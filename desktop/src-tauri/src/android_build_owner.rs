//! Typed AndroidBuild adapter. The finite saved-command owner retains all originals.
//! No invoke future, DTO, sibling domain or caller gets resource custody here.
use std::time::Instant;
use tokio::sync::{oneshot, watch};
use crate::{asset_source::RegisteredRoot, android_build_protocol::{Availability, Prepare, Start, Status},
    error::BridgeError, runtime::RuntimeConfig, saved_command_owner::SavedCommandOwner};

#[derive(Clone)]
pub(crate) struct AndroidBuildOwner { saved: SavedCommandOwner }
pub(crate) struct Admitted { status: Status, release: Option<oneshot::Sender<()>> }
impl Admitted {
    pub(crate) fn new(status: Status, release: Option<oneshot::Sender<()>>) -> Self { Self { status, release } }
    /// Called ONLY after DocumentBinding unlocks. A dropped GO makes the
    /// original driver STOP; no new worker/cleanup owner is created by invoke.
    pub(crate) fn release(self) -> Status { if let Some(release) = self.release { let _ = release.send(()); } self.status }
}
impl AndroidBuildOwner {
    pub(crate) fn new(runtime: RuntimeConfig, toolchain: Option<crate::android_toolchain::AndroidToolchainProfile>) -> Self {
        Self { saved: SavedCommandOwner::android_build(runtime, toolchain) }
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn installed_android_identity(&self) -> std::sync::Weak<()> { self.saved.installed_android_identity() }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn admit_installed_observation(&self, token: crate::shell::installed_observation::commands::AndroidAdmission) -> Result<(), BridgeError> {
        self.saved.admit_installed_android_observation(token)
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn installed_observation_snapshot(&self) -> Option<crate::shell::installed_observation::commands::AndroidSnapshot> {
        self.saved.installed_android_snapshot()
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.saved.subscribe() }
    pub(crate) fn stopping(&self) -> bool { self.saved.stopping() }
    pub(crate) fn disabled(&self) -> bool { self.saved.disabled() }
    pub(crate) fn can_exit(&self) -> bool { self.saved.can_exit() }
    pub(crate) fn busy(&self) -> bool { self.saved.busy() }
    pub(crate) fn ensure_idle(&self) -> Result<(), BridgeError> { self.saved.ensure_idle() }
    pub(crate) fn prepared_project(&self, operation: &str, generation: &str) -> Result<String, BridgeError> {
        self.saved.prepared_project(operation, generation)
    }
    pub(crate) fn prepare(&self, input: Prepare, registration: u32, project: RegisteredRoot, gate: Availability) -> Result<Status, BridgeError> {
        self.saved.prepare_android(input, registration, project, gate)
    }
    pub(crate) fn start(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability) -> Result<Admitted, BridgeError> {
        self.saved.start_android(input, admitted_at, registered, gate)
    }
    pub(crate) fn status(&self, gate: Availability) -> Result<Status, BridgeError> { self.saved.status_android(gate) }
    pub(crate) fn cancel(&self, operation: &str, generation: &str, gate: Availability) -> Result<Status, BridgeError> {
        self.saved.cancel_android(operation, generation, gate)
    }
    pub(crate) fn document_lost(&self) { self.saved.document_lost(); }
    pub(crate) fn context_changed(&self) { self.saved.context_changed(); }
    pub(crate) fn registration_matches(&self, registration: u32) -> bool { self.saved.registration_matches(registration) }
    pub(crate) fn request_shutdown(&self) { self.saved.request_shutdown(); }
    pub(crate) async fn shutdown(&self) -> Result<(), BridgeError> { self.saved.shutdown().await }
    // Tests borrow this exact original owner. Inner/Session/handle fields remain
    // private in saved_command_owner; this creates no synthetic receipt/permit.
    #[cfg(test)]
    pub(crate) fn original_for_test(&self) -> &SavedCommandOwner { &self.saved }
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("android_build_unavailable", "Saved Android builds are unavailable for this original document, host, runtime and tool custody.")
}
