//! Typed OfflinePreflight adapter. The finite saved-command owner retains all originals.
//! No invoke future, DTO, sibling domain or caller gets resource custody here.
use std::time::Instant;
use tokio::sync::{oneshot, watch};
use crate::{asset_source::RegisteredRoot, offline_preflight_protocol::{Availability, Prepare, Start, Status},
    error::BridgeError, runtime::RuntimeConfig, saved_command_owner::SavedCommandOwner};

#[derive(Clone)]
pub(crate) struct OfflinePreflightOwner { saved: SavedCommandOwner }
pub(crate) struct Admitted { status: Status, release: Option<oneshot::Sender<()>> }
impl Admitted {
    pub(crate) fn new(status: Status, release: Option<oneshot::Sender<()>>) -> Self { Self { status, release } }
    /// Called ONLY after DocumentBinding unlocks. A dropped GO makes the
    /// original driver STOP; no new worker/cleanup owner is created by invoke.
    pub(crate) fn release(self) -> Status { if let Some(release) = self.release { let _ = release.send(()); } self.status }
}
impl OfflinePreflightOwner {
    pub(crate) fn new(runtime: RuntimeConfig) -> Self { Self { saved: SavedCommandOwner::offline_preflight(runtime) } }
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
        self.saved.prepare_offline(input, registration, project, gate)
    }
    pub(crate) fn start(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability) -> Result<Admitted, BridgeError> {
        self.saved.start_offline(input, admitted_at, registered, gate)
    }
    pub(crate) fn status(&self, gate: Availability) -> Result<Status, BridgeError> { self.saved.status_offline(gate) }
    pub(crate) fn cancel(&self, operation: &str, generation: &str, gate: Availability) -> Result<Status, BridgeError> {
        self.saved.cancel_offline(operation, generation, gate)
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
    BridgeError::new("offline_preflight_unavailable", "Saved offline checks are unavailable for this original document, host and runtime.")
}

// Keep the predecessor native harness selector and all eight inert selectors
// EXACT. The bodies borrow private original records in saved_command_owner;
// re-exporting a test function would NOT preserve its harness module name.
#[cfg(test)]
mod tests {
    #[test]
    fn qualification_is_closed_without_a_runtime_or_another_owners_permit() {
        crate::saved_command_owner::offline_tests::qualification_is_closed_without_a_runtime_or_another_owners_permit();
    }
    #[test]
    fn no_owner_startup_and_unsupported_status_do_not_claim_document_loss() {
        crate::saved_command_owner::offline_tests::no_owner_startup_and_unsupported_status_do_not_claim_document_loss();
    }
    #[test]
    fn intent_expires_with_a_new_revision_and_cancel_never_creates_an_owner() {
        crate::saved_command_owner::offline_tests::intent_expires_with_a_new_revision_and_cancel_never_creates_an_owner();
    }
    #[test]
    fn start_burns_before_unavailability_and_foreign_start_grants_nothing() {
        crate::saved_command_owner::offline_tests::start_burns_before_unavailability_and_foreign_start_grants_nothing();
    }
    #[test]
    fn whole_run_endpoints_and_first_stop_never_renew() {
        crate::saved_command_owner::offline_tests::whole_run_endpoints_and_first_stop_never_renew();
    }
    #[test]
    fn complete_negative_is_provisional_and_not_first_failure() {
        crate::saved_command_owner::offline_tests::complete_negative_is_provisional_and_not_first_failure();
    }
    #[test]
    fn late_terminal_never_reverses_timeout_or_unknown_in_either_delivery_order() {
        crate::saved_command_owner::offline_tests::late_terminal_never_reverses_timeout_or_unknown_in_either_delivery_order();
    }
    #[test]
    fn repeated_unknown_polling_does_not_publish_new_results_or_extend_clocks() {
        crate::saved_command_owner::offline_tests::repeated_unknown_polling_does_not_publish_new_results_or_extend_clocks();
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    mod hosted {
        #[test]
        #[ignore = "source-bound offline Linux/macOS native fixture; not local or production qualification"]
        fn hosted_offline_preflight_original_resources() {
            crate::saved_command_owner::offline_tests::hosted::hosted_offline_preflight_original_resources();
        }
    }
}
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
pub(crate) use crate::saved_command_owner::offline_tests::hosted::RegistrationPermit as OfflineRegistrationPermit;

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl OfflinePreflightOwner {
    pub(crate) fn admit_installed_observation(&self, token: crate::shell::installed_observation::commands::OfflineAdmission) -> Result<(), BridgeError> {
        self.saved.admit_installed_observation(token)
    }
    pub(crate) fn installed_observation_snapshot(&self) -> Option<crate::shell::installed_observation::commands::Snapshot> {
        self.saved.installed_observation_snapshot()
    }
}
