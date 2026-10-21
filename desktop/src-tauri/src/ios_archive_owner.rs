//! Typed iOS build/recovery adapter. SavedCommandOwner keeps every original
//! resource and join; neither invoke futures nor DATA receipts become owners.
use std::{time::Instant, sync::Arc};
use tokio::sync::{oneshot, watch};
use crate::{asset_source::RegisteredRoot, error::BridgeError,
    ios_archive_protocol::{Availability, Prepare, Start, Status}, runtime::RuntimeConfig,
    saved_command_owner::SavedCommandOwner};

#[derive(Clone)]
pub(crate) struct IOSArchiveOwner { saved: SavedCommandOwner }
pub(crate) struct Admitted { status: Status, release: Option<oneshot::Sender<()>> }
impl Admitted {
    pub(crate) fn new(status: Status, release: Option<oneshot::Sender<()>>) -> Self { Self { status, release } }
    /// Publish GO only after the original document lock has been released.
    /// Dropping this sender makes the original driver stop, never start a peer.
    pub(crate) fn release(self) -> Status {
        if let Some(release) = self.release { let _ = release.send(()); } self.status
    }
}
impl IOSArchiveOwner {
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn candidate_claim_matches(&self,claim:&crate::saved_command_owner::LocalHistoryClaim)->bool{claim.matches_owner(&self.saved)}
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn candidate_helper_matches(&self,claim:&crate::saved_command_owner::LocalHistoryHelperClaim)->bool{claim.matches_owner(&self.saved)}

    pub(crate) fn new(runtime: RuntimeConfig) -> Self { Self { saved: SavedCommandOwner::ios_archive(runtime) } }
    pub(crate) fn approve_agent_ios_archive(&self,input:Prepare,document:&Arc<()>)->Result<Arc<crate::saved_command_owner::AgentIOSArchiveApproval>,BridgeError>{self.saved.approve_agent_ios_archive(input,document)}
    pub(crate) fn agent_ios_archive_approval_current(&self,approval:&crate::saved_command_owner::AgentIOSArchiveApproval,document:&Arc<()>)->bool{self.saved.agent_ios_archive_approval_current(approval,document)}
    pub(crate) fn prepare_agent_ios_archive(&self,entry:Arc<crate::agent_build_requests::Entry>,approval:Arc<crate::saved_command_owner::AgentIOSArchiveApproval>,registration:u32,root:RegisteredRoot,gate:Availability,material:Option<Arc<crate::asset_session::IOSSigningMaterial>>)->Result<Status,BridgeError>{self.saved.prepare_agent_ios_archive(entry,approval,registration,root,gate,material)}
    pub(crate) fn agent_ios_archive_prepared_material(&self,entry:&Arc<crate::agent_build_requests::Entry>)->Result<Option<Arc<crate::asset_session::IOSSigningMaterial>>,BridgeError>{self.saved.agent_ios_archive_prepared_material(entry)}
    pub(crate) fn start_agent_ios_archive(&self,entry:&Arc<crate::agent_build_requests::Entry>,registered:Option<(u32,RegisteredRoot)>,gate:Availability,material:Option<Arc<crate::asset_session::IOSSigningMaterial>>)->Result<Admitted,BridgeError>{self.saved.start_agent_ios_archive(entry,registered,gate,material)}
    pub(crate) fn approve_agent_ios_recovery(&self, project:String, selection:crate::agent_ios_archive::recovery::Selection,
        document:&Arc<()>, registration:u32, root:&RegisteredRoot)->Result<Arc<crate::saved_command_owner::AgentIOSRecoveryApproval>,BridgeError>{
        self.saved.approve_agent_ios_recovery(project,selection,document,registration,root)
    }
    pub(crate) fn agent_ios_recovery_approval_current(&self, approval:&crate::saved_command_owner::AgentIOSRecoveryApproval,
        document:&Arc<()>, scope:&crate::agent_build_requests::NativeScope, registration:u32, root:&RegisteredRoot)->bool{
        self.saved.agent_ios_recovery_approval_current(approval,document,scope,registration,root)
    }
    pub(crate) fn prepare_agent_ios_recovery(&self, entry:Arc<crate::agent_build_requests::Entry>,
        approval:Arc<crate::saved_command_owner::AgentIOSRecoveryApproval>, registration:u32, root:RegisteredRoot, gate:Availability)->Result<Status,BridgeError>{
        self.saved.prepare_agent_ios_recovery(entry,approval,registration,root,gate)
    }
    pub(crate) fn start_agent_ios_recovery(&self,entry:&Arc<crate::agent_build_requests::Entry>,registered:Option<(u32,RegisteredRoot)>,gate:Availability)->Result<Admitted,BridgeError>{
        self.saved.start_agent_ios_recovery(entry,registered,gate)
    }
    pub(crate) fn agent_ios_recovery_acknowledged(&self,document:&Arc<()>)->Option<crate::agent_ios_archive::recovery::AcknowledgedInspection>{
        self.saved.agent_ios_recovery_acknowledged(document)
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
        self.saved.prepare_ios(input, registration, project, gate)
    }
    pub(crate) fn prepare_material(&self, input: Prepare, registration: u32, project: RegisteredRoot, gate: Availability,
        material: Option<Arc<crate::asset_session::IOSSigningMaterial>>) -> Result<Status, BridgeError> {
        self.saved.prepare_ios_material(input, registration, project, gate, material)
    }
    pub(crate) fn prepared_material(&self, operation: &str, generation: &str) -> Result<Option<Arc<crate::asset_session::IOSSigningMaterial>>, BridgeError> {
        self.saved.prepared_ios_material(operation, generation)
    }
    pub(crate) fn start(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability) -> Result<Admitted, BridgeError> {
        self.saved.start_ios(input, admitted_at, registered, gate)
    }
    pub(crate) fn start_material(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability,
        material: Option<Arc<crate::asset_session::IOSSigningMaterial>>) -> Result<Admitted, BridgeError> {
        self.saved.start_ios_material(input, admitted_at, registered, gate, material)
    }
    pub(crate) fn status(&self, gate: Availability) -> Result<Status, BridgeError> { self.saved.status_ios(gate) }
    pub(crate) fn cancel(&self, operation: &str, generation: &str, gate: Availability) -> Result<Status, BridgeError> {
        self.saved.cancel_ios(operation, generation, gate)
    }
    pub(crate) fn document_lost(&self) { self.saved.document_lost(); }
    pub(crate) fn context_changed(&self) { self.saved.context_changed(); }
    pub(crate) fn registration_matches(&self, registration: u32) -> bool { self.saved.registration_matches(registration) }
    pub(crate) fn request_shutdown(&self) { self.saved.request_shutdown(); }
    pub(crate) async fn shutdown(&self) -> Result<(), BridgeError> { self.saved.shutdown().await }
    #[cfg(test)]
    pub(crate) fn original_for_test(&self) -> &SavedCommandOwner { &self.saved }
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
impl IOSArchiveOwner {
    pub(crate) fn installed_ios_identity(&self) -> std::sync::Weak<()> { self.saved.installed_ios_identity() }
    pub(crate) fn observe_installed_unsigned_selection(&self) -> Result<(), BridgeError> {
        self.saved.observe_installed_unsigned_selection()
    }
    pub(crate) fn admit_installed_ios_observation(&self, token: crate::shell::installed_observation::ios::Admission) -> Result<(), BridgeError> {
        self.saved.admit_installed_ios_observation(token)
    }
    pub(crate) fn installed_ios_snapshot(&self) -> Option<crate::shell::installed_observation::ios::Snapshot> {
        self.saved.installed_ios_snapshot()
    }
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("ios_archive_unavailable", "The selected local iOS action is unavailable for this original document, Mac and installed runtime qualification.")
}
