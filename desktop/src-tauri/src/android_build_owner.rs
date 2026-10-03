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
    pub(crate) fn registration_control(&self) -> std::sync::Arc<crate::saved_command_owner::AndroidRegistrationControl> {
        self.saved.android_registration_control()
    }
    pub(crate) fn bind_original_document(&self, identity: &std::sync::Arc<()>) {
        self.saved.bind_original_android_document(identity);
    }
    pub(crate) fn original_document_matches(&self, identity: &std::sync::Arc<()>) -> bool {
        self.saved.android_original_document_matches(identity)
    }
    pub(crate) fn normal_selected(&self, identity: &std::sync::Arc<()>) -> bool {
        self.saved.android_normal_selected(identity)
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn installed_android_identity(&self) -> std::sync::Weak<()> { self.saved.installed_android_identity() }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn admit_installed_observation(&self, document: &std::sync::Arc<()>, token: crate::shell::installed_observation::commands::AndroidAdmission) -> Result<(), BridgeError> {
        self.saved.admit_installed_android_observation(document, token)
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn installed_observation_snapshot(&self) -> Option<crate::shell::installed_observation::commands::AndroidSnapshot> {
        self.saved.installed_android_snapshot()
    }

    pub(crate) fn sources_status(&self, gate: Availability) -> Result<crate::android_tool_sources::Status, BridgeError> {
        self.saved.android_sources_status(gate)
    }
    pub(crate) fn admit_source(&self, document: &std::sync::Arc<()>, input: &crate::android_tool_sources::Choose,
        registration: u32, project: RegisteredRoot, owner: std::sync::Arc<crate::asset_session::OriginalWork>,
        publisher: &crate::saved_command_owner::AndroidRegistrationPublisher, gate: Availability) -> Result<(), BridgeError> {
        self.saved.admit_android_source_pick(document, input, registration, project, owner, publisher, gate)
    }
    pub(crate) fn source_stop(&self, owner: &std::sync::Arc<crate::asset_session::OriginalWork>) -> Option<(crate::asset_commands::Reason, Instant)> {
        self.saved.android_source_stop(owner)
    }
    pub(crate) fn publish_source(&self, owner: &std::sync::Arc<crate::asset_session::OriginalWork>, proof: crate::asset_source::ProjectProbe,
        publisher: &crate::saved_command_owner::AndroidRegistrationPublisher) -> Result<(), BridgeError> {
        self.saved.publish_android_source(owner, proof, publisher)
    }
    pub(crate) fn observe_source(&self, owner: &std::sync::Arc<crate::asset_session::OriginalWork>, phase: crate::asset_session::Phase,
        reason: crate::asset_commands::Reason, unknown: bool) {
        self.saved.observe_android_source(owner, phase, reason, unknown);
    }
    pub(crate) fn cancel_source(&self, input: crate::android_tool_sources::Cancel, gate: Availability) -> Result<crate::android_tool_sources::Status, BridgeError> {
        self.saved.cancel_android_source(input, gate)
    }

    pub(crate) fn registration_status(&self,gate:Availability)
        -> Result<crate::android_registration_app_protocol::Status,BridgeError> {
        self.saved.android_tool_registration_status(gate)
    }
    pub(crate) fn inspection_snapshot(&self,document:&std::sync::Arc<()>,at:Instant,
        input:crate::android_registration_app_protocol::Inspect,registration:u32,project:RegisteredRoot,saved:crate::asset_session::ValidatedSavedInput,gate:Availability)
        -> Result<crate::saved_command_owner::AndroidRegistrationSnapshot,BridgeError> {
        self.saved.snapshot_android_tool_inspection(document,at,input,registration,project,saved,gate)
    }
    pub(crate) fn registration_snapshot(&self,document:&std::sync::Arc<()>,at:Instant,
        input:crate::android_registration_app_protocol::Register,registration:u32,project:RegisteredRoot,saved:crate::asset_session::ValidatedSavedInput,gate:Availability)
        -> Result<crate::saved_command_owner::AndroidRegistrationSnapshot,BridgeError> {
        self.saved.snapshot_android_tool_registration(document,at,input,registration,project,saved,gate)
    }
    pub(crate) fn admit_registration(&self,document:&std::sync::Arc<()>,
        checked:&crate::saved_command_owner::AndroidRegistrationChecked,current:crate::asset_session::ValidatedSavedInput,
        registration:u32,project:&RegisteredRoot,census:&crate::asset_session::AndroidRegistrationCensus<'_>,gate:Availability)
        -> Result<crate::saved_command_owner::AndroidRegistrationAdmitted,BridgeError> {
        self.saved.admit_android_tool_registration(document,checked,current,registration,project,census,gate)
    }
    pub(crate) fn registration_finalization(&self)->Option<crate::saved_command_owner::AndroidRegistrationFinalization>{
        self.saved.android_registration_finalization()
    }
    pub(crate) fn finalize_registration(&self,request:&crate::saved_command_owner::AndroidRegistrationFinalization,
        current:Option<&crate::asset_session::ValidatedSavedInput>,gate:Availability){
        self.saved.finalize_android_registration(request,current,gate);
    }
    pub(crate) fn cancel_registration(&self,input:&crate::android_registration_app_protocol::Cancel,
        publication:Option<&crate::saved_command_owner::AndroidRegistrationCancelPublisher>,gate:Availability)
        -> Result<crate::android_registration_app_protocol::Status,BridgeError> {
        self.saved.cancel_android_tool_registration(input,publication,gate)
    }

    pub(crate) fn service_status(&self,gate:Availability)->Result<crate::android_registration_app_protocol::ServiceStatus,BridgeError>{
        self.saved.android_tool_service_status(gate)
    }
    pub(crate) fn service_snapshot(&self,document:&std::sync::Arc<()>,at:Instant,input:crate::android_registration_app_protocol::ServiceRequest,
        registration:u32,project:RegisteredRoot,saved:crate::asset_session::ValidatedSavedInput,gate:Availability)
        ->Result<crate::saved_command_owner::AndroidServiceSnapshot,BridgeError>{
        self.saved.snapshot_android_tool_service(document,at,input,registration,project,saved,gate)
    }
    pub(crate) fn admit_service(&self,document:&std::sync::Arc<()>,checked:&crate::saved_command_owner::AndroidServiceChecked,
        current:crate::asset_session::ValidatedSavedInput,registration:u32,project:&RegisteredRoot,
        census:&crate::asset_session::AndroidServiceSetupCensus<'_>,gate:Availability)->Result<crate::saved_command_owner::AndroidServiceAdmitted,BridgeError>{
        self.saved.admit_android_tool_service(document,checked,current,registration,project,census,gate)
    }
    pub(crate) fn service_finalization(&self)->Option<crate::saved_command_owner::AndroidServiceFinalization>{self.saved.android_service_finalization()}
    pub(crate) fn finalize_service(&self,request:&crate::saved_command_owner::AndroidServiceFinalization,
        current:Option<&crate::asset_session::ValidatedSavedInput>,gate:Availability){self.saved.finalize_android_service(request,current,gate);}
    pub(crate) fn cancel_service(&self,input:&crate::android_registration_app_protocol::ServiceCancel,
        publication:Option<&crate::saved_command_owner::AndroidRegistrationCancelPublisher>,gate:Availability)
        ->Result<crate::android_registration_app_protocol::ServiceStatus,BridgeError>{self.saved.cancel_android_tool_service(input,publication,gate)}
    #[cfg(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper")))]
    pub(crate) fn bind_service_dispatcher(&self,document:&std::sync::Arc<()>,dispatcher:crate::saved_command_owner::AndroidServiceDispatcher)->bool{
        self.saved.bind_android_service_dispatcher(document,dispatcher)
    }

    pub(crate) fn catalog_status(&self,gate:Availability) -> Result<crate::android_toolchain_catalog::Status,BridgeError> {
        self.saved.android_catalog_status(gate)
    }
    pub(crate) fn refresh_catalog(&self,document:&std::sync::Arc<()>,admitted:Instant,gate:Availability)
        -> Result<crate::saved_command_owner::AndroidCatalogAdmitted,BridgeError> {
        self.saved.refresh_android_catalog(document,admitted,gate)
    }
    pub(crate) fn recover_catalog(&self,document:&std::sync::Arc<()>,admitted:Instant,
        input:crate::android_toolchain_catalog::Recover,gate:Availability)
        -> Result<crate::saved_command_owner::AndroidCatalogAdmitted,BridgeError> {
        self.saved.recover_android_catalog(document,admitted,input,gate)
    }
    pub(crate) fn select_catalog(&self,input:crate::android_toolchain_catalog::Select,gate:Availability)
        -> Result<crate::android_toolchain_catalog::Status,BridgeError> {
        self.saved.select_android_catalog(input,gate)
    }
    pub(crate) fn cancel_catalog(&self,input:crate::android_toolchain_catalog::Cancel,gate:Availability)
        -> Result<crate::android_toolchain_catalog::Status,BridgeError> {
        self.saved.cancel_android_catalog(input,gate)
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.saved.subscribe() }
    pub(crate) fn stopping(&self) -> bool { self.saved.stopping() }
    pub(crate) fn disabled(&self) -> bool { self.saved.disabled() }
    pub(crate) fn can_exit(&self) -> bool { self.saved.can_exit() }
    pub(crate) fn busy(&self) -> bool { self.saved.busy() }
    pub(crate) fn ensure_idle(&self) -> Result<(), BridgeError> { self.saved.ensure_idle() }
    pub(crate) fn installation_source_custody_empty(&self) -> bool {
        self.saved.installation_source_custody_empty()
    }
    pub(crate) fn prepared_project(&self, operation: &str, generation: &str) -> Result<String, BridgeError> {
        self.saved.prepared_project(operation, generation)
    }
    pub(crate) fn prepare(&self, input: Prepare, registration: u32, project: RegisteredRoot, gate: Availability) -> Result<Status, BridgeError> {
        self.saved.prepare_android(input, registration, project, gate)
    }
    pub(crate) fn start(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability) -> Result<Admitted, BridgeError> {
        self.saved.start_android(input, admitted_at, registered, gate)
    }
    pub(crate) fn prepare_material(&self, input: Prepare, registration: u32, project: RegisteredRoot, gate: Availability,
        material: Option<std::sync::Arc<crate::asset_session::AndroidSigningMaterial>>) -> Result<Status, BridgeError> {
        self.saved.prepare_android_material(input, registration, project, gate, material)
    }
    pub(crate) fn prepared_material(&self, operation: &str, generation: &str) -> Result<Option<std::sync::Arc<crate::asset_session::AndroidSigningMaterial>>, BridgeError> {
        self.saved.prepared_android_material(operation, generation)
    }
    pub(crate) fn start_material(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability,
        material: Option<std::sync::Arc<crate::asset_session::AndroidSigningMaterial>>) -> Result<Admitted, BridgeError> {
        self.saved.start_android_material(input, admitted_at, registered, gate, material)
    }
    pub(crate) fn status(&self, gate: Availability) -> Result<Status, BridgeError> { self.saved.status_android(gate) }
    pub(crate) fn cancel(&self, operation: &str, generation: &str, gate: Availability) -> Result<Status, BridgeError> {
        self.saved.cancel_android(operation, generation, gate)
    }
    pub(crate) fn document_lost(&self) { self.saved.document_lost(); }
    pub(crate) fn context_changed(&self) { self.saved.context_changed(); }
    pub(crate) fn registration_matches(&self, registration: u32) -> bool { self.saved.registration_matches(registration) }
    pub(crate) fn request_shutdown(&self) { self.saved.request_shutdown(); }
    pub(crate) fn document_lost_published(&self,publisher:Option<&crate::saved_command_owner::AndroidRegistrationPublisher>) { self.saved.document_lost_published(publisher); }
    pub(crate) fn context_changed_published(&self,publisher:Option<&crate::saved_command_owner::AndroidRegistrationPublisher>) { self.saved.context_changed_published(publisher); }
    pub(crate) fn request_shutdown_published(&self,publisher:Option<&crate::saved_command_owner::AndroidRegistrationPublisher>) { self.saved.request_shutdown_published(publisher); }
    pub(crate) async fn shutdown(&self) -> Result<(), BridgeError> { self.saved.shutdown().await }
    // Tests borrow this exact original owner. Inner/Session/handle fields remain
    // private in saved_command_owner; this creates no synthetic receipt/permit.
    #[cfg(test)]
    pub(crate) fn original_for_test(&self) -> &SavedCommandOwner { &self.saved }
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("android_build_unavailable", "Saved Android builds are unavailable for this original document, host, runtime and tool custody.")
}
