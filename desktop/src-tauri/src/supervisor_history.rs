//! Closed History extensions to the existing Supervisor. No driver, watchdog,
//! process registry, token owner or independently renewed deadline is added.
use super::*;
use crate::github_history_protocol as wire;

pub(crate) const WORK:Duration=Duration::from_secs(900);
pub(crate) const CLEANUP:Duration=Duration::from_secs(10);
#[derive(Clone,Copy)]
pub(crate) struct Endpoints { pub(crate) work:Instant,pub(crate) hard:Instant }
impl Endpoints {
    pub(crate) fn at(start:Instant,credential_end:Instant)->Option<Self>{
        let work=start.checked_add(WORK)?.min(credential_end);
        let hard=start.checked_add(WORK.checked_add(CLEANUP)?)?.min(credential_end);
        (start<work&&work<=hard).then_some(Self{work,hard})
    }
    pub(crate) fn first_failure(self,at:Instant)->Instant{
        at.min(self.work).checked_add(CLEANUP).unwrap_or(self.hard).min(self.hard)
    }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    pub(crate) fn bridge(self)->Result<wire::Clock,BridgeError>{
        let mut clock=mrk_macos_installed_native::vault_helper_wire::ClockBridge::capture()
            .ok_or_else(||BridgeError::unavailable("The original History clock is unavailable."))?;
        let work=clock.endpoint(self.work).ok_or_else(BridgeError::cleanup_unknown)?;
        let hard=clock.endpoint(self.hard).ok_or_else(BridgeError::cleanup_unknown)?;
        let value=wire::Clock{name:"CLOCK_UPTIME_RAW".into(),work_end_ns:work.to_string(),hard_end_ns:hard.to_string()};
        if !value.valid(){return Err(BridgeError::cleanup_unknown());}Ok(value)
    }
}
// Metadata allocation only, before original registration. The actual slot
// moves once into Resources; no source/native/file call is made by reserve.
pub(crate) struct GitHubHistoryAdmission {
    pub(super) nomination:Arc<crate::github_history_session::Nomination>,
    pub(super) gate:crate::asset_session::GitHubHistoryGoGate,
    pub(super) endpoints:Endpoints,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    pub(super) slots:Arc<Mutex<crate::installed_runtime::GitHubHistoryRuntimeSlots>>,
    bytes:usize,
}
impl GitHubHistoryAdmission {
    pub(crate) fn reserve(nomination:Arc<crate::github_history_session::Nomination>,gate:crate::asset_session::GitHubHistoryGoGate,
        credential_end:Instant)->Result<Self,BridgeError>{
        let endpoints=Endpoints::at(Instant::now(),credential_end).ok_or_else(BridgeError::timeout)?;
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        {
            let mut slots=crate::installed_runtime::GitHubHistoryRuntimeSlots::new();
            let source=slots.reserve_once().map_err(|_|BridgeError::new("history_resources_unavailable","The original History storage was not admitted."))?;
            let bytes=source.checked_add(nomination.retained_heap_bytes().ok_or_else(BridgeError::invalid)?)
                .and_then(|n|n.checked_add(std::mem::size_of::<Self>()+std::mem::size_of::<Owner>()+std::mem::size_of::<Resources>()+128*1024))
                .ok_or_else(BridgeError::invalid)?;
            Ok(Self{nomination,gate,endpoints,slots:Arc::new(Mutex::new(slots)),bytes})
        }
        #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {let _=(nomination,gate,endpoints);Err(BridgeError::unavailable("The fixed installed History runtime is unavailable."))}
    }
    pub(crate) fn bytes(&self)->usize{self.bytes}
}

#[derive(Clone,Debug)]
pub(crate) enum GitHubHistoryReceipt {
    Pending,RetainedUnknown,
    Settled{outcome:Result<wire::Reply,BridgeError>,settled_at:Instant,was_unknown:bool},
}
pub(crate) struct GitHubHistoryTicket {pub(super) owner:Arc<Owner>,pub(super) receipt:Arc<Mutex<GitHubHistoryReceipt>>}
impl GitHubHistoryTicket {
    pub(crate) fn operation_id(&self)->&str{&self.owner.id}
    pub(crate) fn stop(&self){self.owner.fail(BridgeError::new("cancelled","The local History read was stopped; no remote workflow is cancelled."));}
    pub(crate) fn receipt(&self)->GitHubHistoryReceipt{
        let receipt=lock(&self.receipt);
        if let GitHubHistoryReceipt::Settled{outcome:Ok(reply),..}=&*receipt{
            if reply.retained_heap_bytes().and_then(|n|n.checked_add(std::mem::size_of::<wire::Reply>())).is_none_or(|n|n>wire::RETAINED_REPLY_LIMIT){
                return GitHubHistoryReceipt::RetainedUnknown;
            }
        }
        receipt.clone()
    }
    pub(crate) fn go_claimed(&self)->bool{self.owner.preflight_go_claimed.load(Ordering::SeqCst)}
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{
        let nomination=self.owner.history_nomination.as_ref()?.retained_heap_bytes()?;
        match &*lock(&self.receipt){
            GitHubHistoryReceipt::Settled{outcome:Ok(reply),..}=>nomination.checked_add(reply.retained_heap_bytes()?),
            GitHubHistoryReceipt::Settled{outcome:Err(error),..}=>nomination.checked_add(error.code.capacity())?.checked_add(error.message.capacity()),
            _=>None,
        }
    }
}

// Explicit signal from the SAME driver's concurrently selected wait_original.
// A received signal means a real wait call returned, not that exit succeeded;
// driver finality still independently requires the actual known successful exit.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum ControlRelease { ChildWaitReturned, Stop }
pub(super) fn post_ack_data(joined:bool,posted:bool,failed:bool,stop:bool,now:Instant,end:Instant)->bool{
    joined&&posted&&!failed&&!stop&&now<end
}
fn writer_return_data(go_written:bool,release:Option<ControlRelease>,closed:bool)->bool{
    go_written&&release==Some(ControlRelease::ChildWaitReturned)&&closed
}
// Called before ANY consuming History source/native settlement after launch.
// A parse failure and an explicit unknown declaration both retain originals.
pub(super) fn child_custody_reply(result:Result<wire::Reply,BridgeError>)->Result<wire::Reply,BridgeError>{
    let reply=result?;
    if !reply.lifetime.originals_settled(){return Err(BridgeError::cleanup_unknown());}
    Ok(reply)
}

pub(super) async fn write_history(mut writer:tokio::process::ChildStdin,initial:Vec<u8>,
    ready:oneshot::Receiver<Result<(),BridgeError>>,wait_returned:oneshot::Receiver<()>,
    post_request:oneshot::Sender<oneshot::Sender<Result<(),BridgeError>>>,
    inner:Arc<Inner>,owner:Arc<Owner>,faults:mpsc::Sender<BridgeError>)->WriteEnd{
    let mut stop=owner.stop.subscribe();
    if *stop.borrow()||owner.failed()||Instant::now()>=owner.endpoint(){return WriteEnd{complete:false};}
    let digest=wire::request_digest(&initial);
    let result=tokio::select!{biased;
        _=stop.changed()=>return WriteEnd{complete:false},
        result=writer.write_all(&initial)=>result,
    };
    if result.is_err(){owner.fail(BridgeError::new("io_error","The original History request channel failed."));return WriteEnd{complete:false};}
    let ready=tokio::select!{biased;_=stop.changed()=>return WriteEnd{complete:false},ready=ready=>ready};
    if !matches!(ready,Ok(Ok(()))){owner.fail(BridgeError::protocol());return WriteEnd{complete:false};}
    // The driver already holds Resources. Request its single registered POST
    // original instead of reacquiring that mutex here (which would deadlock).
    let (reply,returned)=oneshot::channel();
    if post_request.send(reply).is_err(){owner.fail(BridgeError::cleanup_unknown());return WriteEnd{complete:false};}
    let posted=tokio::select!{biased;_=stop.changed()=>return WriteEnd{complete:false},result=returned=>result};
    match posted{Ok(Ok(()))=>{},Ok(Err(error))=>{owner.fail(error);return WriteEnd{complete:false};},Err(_)=>{owner.fail(BridgeError::cleanup_unknown());return WriteEnd{complete:false};}}
    let go=match (&owner.history_gate,&owner.history_nomination){
        (Some(gate),Some(nomination)) if matches!(owner.profile,Profile::GitHubHistory)=>
            gate.claim(&owner.id,&digest,nomination,||claim_preflight_go(&inner,&owner,Profile::GitHubHistory)),
        _=>Err(BridgeError::cleanup_unknown()),
    };
    let bytes=match go{Ok(bytes)=>bytes,Err(error)=>{owner.fail(error);return WriteEnd{complete:false};}};
    if *stop.borrow()||owner.failed()||Instant::now()>=owner.endpoint(){return WriteEnd{complete:false};}
    let written=tokio::select!{biased;_=stop.changed()=>return WriteEnd{complete:false},result=writer.write_all(&bytes)=>result};
    if written.is_err(){
        let error=BridgeError::new("io_error","The original History GO channel failed.");owner.fail(error.clone());let _=faults.try_send(error);
        return WriteEnd{complete:false};
    }
    // Do NOT shutdown after GO: EOF is the child's cancellation signal. Real
    // child wait is polled concurrently by drive, never after this writer.
    let release=tokio::select!{biased;
        _=stop.changed()=>Some(ControlRelease::Stop),
        returned=wait_returned=>if returned.is_ok(){Some(ControlRelease::ChildWaitReturned)}else{None},
    };
    let closed=writer.shutdown().await.is_ok();
    if !closed {let error=BridgeError::new("io_error","The original History control channel did not close.");owner.fail(error.clone());let _=faults.try_send(error);}
    // Drop the actual ChildStdin only here. Task return and original join are
    // still separately required; this bool cannot turn STOP into success.
    drop(writer);
    WriteEnd{complete:writer_return_data(true,release,closed)}
}

#[cfg(test)]
pub(crate) fn history_original_data_checks(){
    let start=Instant::now();let credential=start+Duration::from_secs(950);
    let ends=Endpoints::at(start,credential).unwrap();assert_eq!(ends.work,start+WORK);assert_eq!(ends.hard,start+WORK+CLEANUP);
    let clipped=Endpoints::at(start,start+Duration::from_secs(3)).unwrap();assert_eq!(clipped.work,clipped.hard);
    assert!(Endpoints::at(start,start).is_none());
    assert_eq!(ends.first_failure(start+Duration::from_secs(2)),start+Duration::from_secs(12));
    assert_eq!(ends.first_failure(ends.work+Duration::from_secs(8)),ends.hard);
    let original=ends.first_failure(start+Duration::from_secs(2));
    assert_eq!(original.min(ends.first_failure(start+Duration::from_secs(200))),original);
    assert!(!writer_return_data(true,None,true));assert!(!writer_return_data(true,Some(ControlRelease::Stop),true));
    assert!(!writer_return_data(false,Some(ControlRelease::ChildWaitReturned),true));
    assert!(!writer_return_data(true,Some(ControlRelease::ChildWaitReturned),false));
    assert!(writer_return_data(true,Some(ControlRelease::ChildWaitReturned),true));
    assert!(post_ack_data(true,true,false,false,start,ends.work));
    for (joined,posted,failed,stop) in [(false,true,false,false),(true,false,false,false),(true,true,true,false),(true,true,false,true)]{
        assert!(!post_ack_data(joined,posted,failed,stop,start,ends.work));
    }
    assert!(!post_ack_data(true,true,false,false,ends.work,ends.work));
    // Actual production retirement guard, not a forged successful child. The
    // inert DATA has a known refusal: complete=false/STOP may still be settled.
    let raw=serde_json::json!({"protocol":wire::PROTOCOL,"id":"data","requestSha256":"a".repeat(64),
        "result":null,"reason":"runtime-unavailable","lifetime":{"complete":false,"fatal":false,"contained":true,
        "commandDispatched":false,"commands":2,"verifierCalls":1,"inputClosed":true,"handlersRestored":true,
        "invocationClosed":true,"stopObserved":true}});
    let known:wire::Reply=serde_json::from_value(raw.clone()).unwrap();
    assert!(child_custody_reply(Ok(known)).is_ok());
    for (field,value) in [("fatal",serde_json::json!(true)),("contained",serde_json::json!(false)),
        ("commandDispatched",serde_json::Value::Null),("inputClosed",serde_json::json!(false)),
        ("handlersRestored",serde_json::json!(false)),("invocationClosed",serde_json::json!(false)),
        ("verifierCalls",serde_json::json!(3))]{
        let mut unsafe_reply=raw.clone();unsafe_reply["lifetime"][field]=value;
        assert!(child_custody_reply(Ok(serde_json::from_value(unsafe_reply).unwrap())).is_err());
    }
    assert!(child_custody_reply(Err(BridgeError::protocol())).is_err()); // malformed/missing frame
    let mut state=OwnerState::new(ends.work,None);state.history_endpoints=Some(ends);
    state.fail_at(BridgeError::timeout(),start+Duration::from_secs(2));
    assert_eq!(state.cleanup_endpoint,Some(start+Duration::from_secs(12)));
    state.fail_at(BridgeError::shutdown(),start+Duration::from_secs(200));
    assert_eq!(state.cleanup_endpoint,Some(start+Duration::from_secs(12)));
    let clean=OwnerState::new(ends.work,None);
    assert!(preflight_claim_clear(true,Profile::GitHubHistory,Profile::GitHubHistory,&clean,start,false,false,false));
    assert!(!preflight_claim_clear(true,Profile::GitHubSetup,Profile::GitHubHistory,&clean,start,false,false,false));
    assert!(!preflight_claim_clear(true,Profile::GitHubHistory,Profile::GitHubHistory,&state,start,false,false,false));
    crate::github_history_session::history_session_data_checks();
    crate::github_connection_session::github_history_connection_data_checks();
    crate::asset_session::github_history_document_data_checks();
}
