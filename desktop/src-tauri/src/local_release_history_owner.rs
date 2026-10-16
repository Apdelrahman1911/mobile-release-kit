//! Closed local enrollment/history adapter on the original saved Session.
use std::{sync::Arc,time::Instant};
use tokio::sync::{oneshot,watch};
use crate::{asset_source::RegisteredRoot,asset_session::LocalHistoryConsent,error::BridgeError,
    local_release_history_protocol::{Availability,Prepare,Start,Status},runtime::RuntimeConfig,saved_command_owner::SavedCommandOwner};
#[derive(Clone)]
pub(crate) struct LocalReleaseHistoryOwner {saved:SavedCommandOwner}
pub(crate) struct Admitted {status:Status,release:Option<oneshot::Sender<()>>}
impl Admitted {
    pub(crate) fn new(status:Status,release:Option<oneshot::Sender<()>>)->Self{Self{status,release}}
    pub(crate) fn release(self)->Status{if let Some(release)=self.release{let _=release.send(());}self.status}
}
impl LocalReleaseHistoryOwner {
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    pub(crate) fn claim_matches(&self,claim:&crate::saved_command_owner::LocalHistoryClaim)->bool{claim.matches_owner(&self.saved)}
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    pub(crate) fn helper_matches(&self,claim:&crate::saved_command_owner::LocalHistoryHelperClaim)->bool{claim.matches_owner(&self.saved)}
    pub(crate) fn new(runtime:RuntimeConfig)->Self{Self{saved:SavedCommandOwner::local_release_history(runtime)}}
    pub(crate) fn subscribe(&self)->watch::Receiver<u32>{self.saved.subscribe()}
    pub(crate) fn stopping(&self)->bool{self.saved.stopping()}
    pub(crate) fn disabled(&self)->bool{self.saved.disabled()}
    pub(crate) fn can_exit(&self)->bool{self.saved.can_exit()}
    pub(crate) fn busy(&self)->bool{self.saved.busy()}
    pub(crate) fn ensure_idle(&self)->Result<(),BridgeError>{self.saved.ensure_idle()}
    pub(crate) fn prepared_project(&self,operation:&str,generation:&str)->Result<String,BridgeError>{self.saved.prepared_project(operation,generation)}
    pub(crate) fn prepare(&self,input:Prepare,registration:u32,project:RegisteredRoot,gate:Availability,consent:Arc<LocalHistoryConsent>)->Result<Status,BridgeError>{
        self.saved.prepare_history(input,registration,project,gate,consent)
    }
    pub(crate) fn start(&self,input:Start,admitted:Instant,registered:Option<(u32,RegisteredRoot)>,gate:Availability)->Result<Admitted,BridgeError>{
        self.saved.start_history(input,admitted,registered,gate)
    }
    pub(crate) fn prepared_consent(&self,operation:&str,generation:&str)->Result<Arc<LocalHistoryConsent>,BridgeError>{self.saved.prepared_history_consent(operation,generation)}
    pub(crate) fn status(&self,gate:Availability)->Result<Status,BridgeError>{self.saved.status_history(gate)}
    pub(crate) fn cancel(&self,operation:&str,generation:&str,gate:Availability)->Result<Status,BridgeError>{self.saved.cancel_history(operation,generation,gate)}
    pub(crate) fn document_lost(&self){self.saved.document_lost()}
    pub(crate) fn context_changed(&self){self.saved.context_changed()}
    pub(crate) fn registration_matches(&self,registration:u32)->bool{self.saved.registration_matches(registration)}
    pub(crate) fn request_shutdown(&self){self.saved.request_shutdown()}
    pub(crate) async fn shutdown(&self)->Result<(),BridgeError>{self.saved.shutdown().await}
}
pub(crate) fn unavailable()->BridgeError{BridgeError::new("local_release_history_unavailable","Local release enrollment and history are unavailable for this original document and runtime.")}
