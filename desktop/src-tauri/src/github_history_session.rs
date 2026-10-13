//! One History projection in the existing ConnectionState. Actual Supervisor
//! ticket and registered source/edit originals remain the only lifecycle owner.
use std::sync::Arc;
use crate::{asset_source::RegisteredRoot,edit_owner::SavedEditStamp,error::BridgeError,
    github_history_protocol as wire,supervisor::{GitHubHistoryReceipt,GitHubHistoryTicket}};

// Constructed only from actual ConnectionState/Document source admission. No
// Deserialize, path from renderer, placeholder config hash or credential copy.
pub(crate) struct Nomination {
    pub(crate) session_id:String,pub(crate) project_id:String,pub(crate) generation:u32,
    pub(crate) root:RegisteredRoot,pub(crate) edit_stamp:SavedEditStamp,
    pub(crate) project_binding:String,pub(crate) repository:String,pub(crate) account_id:String,pub(crate) repository_id:String,
    pub(crate) tooling_sha:String,pub(crate) selection:wire::Selection,pub(crate) owner_generation:String,pub(crate) work_nonce:String,
}
impl Nomination {
    pub(crate) fn context(&self,actual_raw_sha:&str)->wire::Context{
        wire::Context{schema_version:1,project_binding:self.project_binding.clone(),config_sha256:actual_raw_sha.into(),
            repository:self.repository.clone(),repository_id:self.repository_id.clone(),account_id:self.account_id.clone(),
            tooling_repository:wire::TOOLING.into(),tooling_sha:self.tooling_sha.clone(),selection:self.selection.clone()}
    }
    pub(crate) fn matches(&self,context:&wire::Context)->bool {
        context.valid()&&self.project_binding==context.project_binding&&self.repository==context.repository
            &&self.account_id==context.account_id&&self.repository_id==context.repository_id&&self.tooling_sha==context.tooling_sha
            &&self.selection==context.selection
    }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{
        let mut n=self.root.path.capacity().checked_add(self.selection.retained_heap_bytes())?;
        for s in [&self.session_id,&self.project_id,&self.project_binding,&self.repository,&self.account_id,&self.repository_id,
            &self.tooling_sha,&self.owner_generation,&self.work_nonce]{n=n.checked_add(s.capacity())?;}Some(n)
    }
}
pub(crate) struct Active {pub(crate) ticket:GitHubHistoryTicket,pub(crate) nomination:Arc<Nomination>}
pub(crate) struct State {pub(crate) view:wire::Status,pub(crate) active:Option<Active>,pub(crate) exhausted:bool}
pub(crate) fn refused(reason:wire::Reason)->BridgeError{
    let name=serde_json::to_value(reason).ok().and_then(|v|v.as_str().map(str::to_owned)).unwrap_or_else(||"invalid-input".into());
    BridgeError::new(&format!("github_history_refused_{}",name.replace('-',"_")),match reason{
        wire::Reason::Busy=>"The original History read must settle before another read.",
        wire::Reason::CleanupUnknown=>"Original History cleanup is unconfirmed. Keep its current Status.",
        wire::Reason::ProviderUnavailable=>"The required bounded attestation provider is unavailable. No alternate tool is used.",
        wire::Reason::RuntimeUnavailable|wire::Reason::Unqualified=>"Authenticated History is unavailable in this installed application.",
        wire::Reason::TargetChanged=>"The original project, saved configuration or selected account/repository changed.",
        wire::Reason::NotConnected=>"Connect the registered project to GitHub before reading retained History.",
        _=>"The original History request was not admitted. Review its current Status before starting another read.",
    })
}
pub(crate) fn connection_reason(value:crate::github_connection_protocol::Reason)->wire::Reason{
    use crate::github_connection_protocol::Reason as R;
    match value {R::None=>wire::Reason::None,R::Unqualified=>wire::Reason::Unqualified,R::RuntimeUnavailable=>wire::Reason::RuntimeUnavailable,
        R::NotConnected=>wire::Reason::NotConnected,R::Busy=>wire::Reason::Busy,R::Expired=>wire::Reason::Expired,
        R::RateLimited=>wire::Reason::RateLimited,R::Cancelled=>wire::Reason::Cancelled,R::CleanupUnknown=>wire::Reason::CleanupUnknown,
        R::TargetChanged=>wire::Reason::TargetChanged,R::Unauthorized=>wire::Reason::Unauthorized,R::Forbidden=>wire::Reason::Forbidden,
        R::NotFoundOrInaccessible=>wire::Reason::NotFoundOrInaccessible,R::NetworkUnavailable=>wire::Reason::NetworkUnavailable,
        R::TlsFailed=>wire::Reason::TlsFailed,R::ResponseInvalid=>wire::Reason::ResponseInvalid,R::ResponseLimit=>wire::Reason::ResponseLimit,
        _=>wire::Reason::InvalidInput}
}
pub(crate) fn outcome_reason(error:&BridgeError)->wire::Reason{
    match error.code.as_str(){"cleanup_unknown"=>wire::Reason::CleanupUnknown,"protocol_error"|"io_error"=>wire::Reason::ResponseInvalid,
        "busy"=>wire::Reason::Busy,"invalid_request"=>wire::Reason::InvalidInput,
        "output_limit"|"stdout_limit"|"stderr_limit"=>wire::Reason::ResponseLimit,"cancelled"|"shutting_down"=>wire::Reason::Cancelled,
        "runtime_unavailable"|"unavailable"|"engine_failed"=>wire::Reason::RuntimeUnavailable,"history_provider_unavailable"=>wire::Reason::ProviderUnavailable,
        "history_provider_mismatch"=>wire::Reason::ProviderMismatch,"history_source_changed"=>wire::Reason::TargetChanged,
        "history_resources_unavailable"=>wire::Reason::ResourcesUnavailable,"query_timeout"|"deadline"|"timed_out"=>wire::Reason::Expired,
        _=>wire::Reason::NetworkUnavailable}
}
impl State {
    pub(crate) fn new()->Self{Self{view:wire::Status{schema_version:1,revision:1,session_id:None,available:false,
        reason:wire::Reason::NotConnected,operation:None,result:None},active:None,exhausted:false}}
    pub(crate) fn snapshot(&self)->wire::Status{self.view.clone()}
    pub(crate) fn native_work_pending(&self)->bool{self.active.is_some()}
    pub(crate) fn settled(&self)->bool{self.active.is_none()}
    pub(crate) fn receipt(&self)->Option<GitHubHistoryReceipt>{self.active.as_ref().map(|v|v.ticket.receipt())}
    pub(crate) fn finish(&mut self,before:wire::Status){
        if self.exhausted{self.view=before;return;}
        if self.view!=before{
            if before.revision>=wire::LAST_REVISION-1{self.view.revision=wire::LAST_REVISION;self.exhausted=true;self.unknown();}
            else{self.view.revision=before.revision+1;}
        }
    }
    pub(crate) fn unknown(&mut self){
        self.view.available=false;self.view.reason=wire::Reason::CleanupUnknown;
        if let Some(active)=&self.active{active.ticket.stop();}
        if let Some(op)=&mut self.view.operation{if op.phase!=wire::Phase::Settled{
            op.phase=wire::Phase::CleanupUnknown;op.reason=wire::Reason::CleanupUnknown;self.view.result=None;
        }}
    }
    pub(crate) fn stop(&mut self){
        if let Some(active)=&self.active{
            active.ticket.stop();self.view.available=false;
            if let Some(op)=&mut self.view.operation{if op.phase!=wire::Phase::CleanupUnknown{
                op.phase=wire::Phase::Stopping;op.reason=wire::Reason::Cancelled;
            }}
        }
    }
    pub(crate) fn start(&mut self,active:Active,before:wire::Status){
        self.view.result=None;self.view.operation=Some(wire::Operation{id:active.ticket.operation_id().into(),phase:wire::Phase::Running,
            reason:wire::Reason::None,selection:active.nomination.selection.clone()});
        self.view.session_id=Some(active.nomination.session_id.clone());self.view.available=false;self.view.reason=wire::Reason::Busy;
        self.active=Some(active);self.finish(before);
    }
    pub(crate) fn cancel(&mut self,id:&str)->Result<(),BridgeError>{
        if !self.active.as_ref().is_some_and(|active|active.ticket.operation_id()==id){return Err(refused(wire::Reason::InvalidInput));}
        let before=self.snapshot();self.stop();self.finish(before);Ok(())
    }
    // Called only after the same ticket's native/process/IO/management receipt
    // is known and the containing Document source check is complete. Unknown
    // originals stay active, never cleared by a frame/enum alone.
    pub(crate) fn publish_settled(&mut self,reply:Result<wire::Reply,BridgeError>,current:bool,was_unknown:bool){
        let before=self.snapshot();
        if self.active.is_none(){self.unknown();self.finish(before);return;}
        if was_unknown||self.view.reason==wire::Reason::CleanupUnknown{self.unknown();self.finish(before);return;}
        let (reason,result)=match reply{
            Ok(reply) if current=>(reply.reason,reply.result),
            Ok(_)=>(wire::Reason::TargetChanged,None),Err(error)=>(outcome_reason(&error),None),
        };
        if reason==wire::Reason::CleanupUnknown{self.unknown();self.finish(before);return;}
        if let Some(op)=&mut self.view.operation{op.phase=wire::Phase::Settled;op.reason=reason;}
        self.view.result=result;self.view.available=false;self.view.reason=if current{wire::Reason::Busy}else{wire::Reason::TargetChanged};
        self.active=None;self.finish(before);
    }
    pub(crate) fn retained_heap_bytes_if_quiescent(&self)->Option<usize>{
        if self.active.is_some()||self.exhausted||self.view.reason==wire::Reason::CleanupUnknown
            ||self.view.operation.as_ref().is_some_and(|op|op.phase!=wire::Phase::Settled||op.reason==wire::Reason::CleanupUnknown){return None;}
        self.view.retained_heap_bytes()
    }
}
#[cfg(test)]
pub(crate) fn history_session_data_checks(){
    let mut state=State::new();assert!(state.settled()&&!state.native_work_pending()&&state.view.fits_wire());
    for (error,reason) in [(BridgeError::timeout(),wire::Reason::Expired),(BridgeError::invalid(),wire::Reason::InvalidInput),
        (BridgeError::shutdown(),wire::Reason::Cancelled),(BridgeError::unavailable("fixed"),wire::Reason::RuntimeUnavailable),
        (BridgeError::new("busy","fixed"),wire::Reason::Busy)]{assert_eq!(outcome_reason(&error),reason);}
    assert!(state.cancel("foreign").is_err());
    state.view.session_id=Some("known-session".into());state.view.operation=Some(wire::Operation{id:"old-read".into(),phase:wire::Phase::Settled,
        reason:wire::Reason::ArtifactMissing,selection:wire::Selection{run_id:"1".into(),attempt:1,stage:wire::Stage::Candidate,platform:wire::Platform::Ios}});
    let original=state.view.operation.clone();let before=state.snapshot();state.unknown();state.finish(before);
    assert_eq!(state.view.operation,original);assert!(state.view.fits_wire());assert!(state.retained_heap_bytes_if_quiescent().is_none());
    let mut state=State::new();state.view.revision=wire::LAST_REVISION-1;let before=state.snapshot();state.view.reason=wire::Reason::ProviderUnavailable;
    state.finish(before);assert!(state.exhausted&&state.view.revision==wire::LAST_REVISION&&state.view.reason==wire::Reason::CleanupUnknown);
    let before=state.snapshot();state.view.reason=wire::Reason::None;state.finish(before.clone());assert_eq!(state.view,before);
}
