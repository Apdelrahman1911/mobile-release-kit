//! Three finite R journeys through the ordinary UI and existing relay/exit.
//! No alternate command, document, credential, process or deadline owner.
use std::sync::{Arc,Mutex,Weak,atomic::{AtomicBool,Ordering}};
use serde_json::{json,Value};
use tauri::Manager;
use tokio::sync::Mutex as AsyncMutex;
use crate::{error::BridgeError,github_connection_protocol as read,github_release_protocol as wire,
    runtime::GitHubReleaseObservationProfile as RuntimeProfile,supervisor::{Supervisor,
        github_release_native_observation::{InstalledPeer,ProductWitness,peer_sha256,callers,prepared_matches}}};
use super::{Observation,Case as ShellCase,Step as ShellStep,Pending,Boundary,github};
pub(crate) use crate::supervisor::github_release_native_observation::Case;

impl Case {
    pub(super) fn failure_leaf(self)->&'static str {match self {
        Self::NormalPending=>"shell-github-release-normal-pending-failure.labels",
        Self::ResponseLoss=>"shell-github-release-response-loss-failure.labels",
        Self::PreGoRevocation=>"shell-github-release-pre-go-revocation-failure.labels",
    }}
    pub(super) fn verified_line(self)->&'static [u8] {match self {
        Self::NormalPending=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-release-normal-pending-verified\n",
        Self::ResponseLoss=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-release-response-loss-verified\n",
        Self::PreGoRevocation=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-release-pre-go-revocation-verified\n",
    }}
}
#[derive(Clone,Copy,PartialEq,Eq)]
pub(super) enum Step { Navigate,ReadGuidanceReload,ReloadGuidance,EnterRepository,Entry,EnterToken,Token,Connect,
    Connected,OpenReleases,Configure,Originals,Configured,Prepare,Prepared,ConfirmText,Confirm,Dispatch,Dispatched,
    ReloadPending,ReadPending,Reconcile,Reconciled,Status,ReadStatus,ReadyToRevoke,OpenGitHub,Disconnect,
    ConnectionRemoved,ReturnReleases,Refused,Disconnected }
impl Step {
    pub(super) fn failure_line(self)->&'static [u8] {match self {
        Self::Navigate=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseNavigate\n",
        Self::ReadGuidanceReload=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseGuidanceReady\n",
        Self::ReloadGuidance=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseGuidanceReload\n",
        Self::EnterRepository=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseRepository\n",
        Self::Entry=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseEntry\n",
        Self::EnterToken=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseToken\n",
        Self::Token=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseTokenReady\n",
        Self::Connect=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseConnect\n",
        Self::Connected=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseConnected\n",
        Self::OpenReleases=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseOpen\n",
        Self::Configure=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseConfigure\n",
        Self::Originals=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseOriginals\n",
        Self::Configured=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseConfigured\n",
        Self::Prepare=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleasePrepare\n",
        Self::Prepared=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleasePrepared\n",
        Self::ConfirmText=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseConfirmText\n",
        Self::Confirm=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseConfirm\n",
        Self::Dispatch=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseDispatch\n",
        Self::Dispatched=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseDispatched\n",
        Self::ReloadPending=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseReloadPending\n",
        Self::ReadPending=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseReadPending\n",
        Self::Reconcile=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseReconcile\n",
        Self::Reconciled=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseReconciled\n",
        Self::Status=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseStatus\n",
        Self::ReadStatus=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseReadStatus\n",
        Self::ReadyToRevoke=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseReadyToRevoke\n",
        Self::OpenGitHub=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseOpenGitHub\n",
        Self::Disconnect=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseDisconnect\n",
        Self::ConnectionRemoved=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseConnectionRemoved\n",
        Self::ReturnReleases=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseReturn\n",
        Self::Refused=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseRefused\n",
        Self::Disconnected=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReleaseDisconnected\n",
    }}
    fn shared(self)->Option<github::Step> {Some(match self {
        Self::Navigate|Self::OpenGitHub=>github::Step::Navigate,Self::ReadGuidanceReload=>github::Step::ReadGuidanceReload,
        Self::ReloadGuidance=>github::Step::ReloadGuidance,Self::EnterRepository=>github::Step::EnterRepository,
        Self::Entry=>github::Step::Entry,Self::EnterToken=>github::Step::EnterToken,Self::Token=>github::Step::Token,
        Self::Connect=>github::Step::Connect,Self::Disconnect=>github::Step::Disconnect,_=>return None,
    })}
}
fn expected_action(case:Case,index:usize)->Option<(&'static str,wire::Kind,[Step;2])> {
    let kind=case.kind(index.checked_add(1)?)?;
    let (command,steps)=match kind {
        wire::Kind::Prepare=>("github_release_prepare",[Step::Prepare,Step::Prepared]),
        wire::Kind::Dispatch=>("github_release_dispatch",[Step::Dispatch,
            if case==Case::PreGoRevocation{Step::ReadyToRevoke}else{Step::Dispatched}]),
        wire::Kind::Pending=>("github_release_pending",[Step::ReloadPending,Step::ReadPending]),
        wire::Kind::Reconcile=>("github_release_reconcile",[Step::Reconcile,Step::Reconciled]),
        wire::Kind::Track=>return None,
    };Some((command,kind,steps))
}
#[derive(Default)]
struct Record {
    attached:bool,setup_claimed:bool,peer_ready:bool,project_id:Option<String>,session_id:Option<String>,
    read:Option<read::Status>,release:Option<wire::Status>,prepared:Option<wire::Prepared>,
    connect:u8,disconnect:u8,actions:Vec<String>,explicit_status:bool,token_cleared:bool,
    review_visible:bool,typed:bool,confirmed:bool,dispatch_effect:Option<wire::Effect>,dispatch_reason:Option<wire::Reason>,
    pending_reloaded:bool,run_observed:bool,connection_removed:bool,retirement_before:Option<wire::Status>,
    retired_without_authority:bool,close_ready:bool,physical_final:bool,final_checked:bool,peer_receipt:Option<Value>,
}
pub(crate) struct Control {
    case:Case,original:Mutex<Option<Weak<Observation>>>,failed:AtomicBool,record:Mutex<Record>,
    peer:AsyncMutex<InstalledPeer>,product:Arc<ProductWitness>,
}
impl Control {
    pub(super) fn new(case:Case)->Arc<Self> {Arc::new(Self{case,original:Mutex::new(None),failed:AtomicBool::new(false),
        record:Mutex::new(Record::default()),peer:AsyncMutex::new(InstalledPeer::new(case)),product:ProductWitness::new(case)})}
    pub(super) fn profile(&self)->Option<RuntimeProfile> {self.case.profile()}
    fn original(&self)->Option<Arc<Observation>> {self.original.lock().ok()?.as_ref()?.upgrade()}
    fn fail(&self) {self.failed.store(true,Ordering::SeqCst);self.product.fail();if let Some(q)=self.original(){q.fail();}}
    fn record(&self)->Option<std::sync::MutexGuard<'_,Record>> {
        match self.record.lock(){Ok(record)=>Some(record),Err(_)=>{self.fail();None}}
    }
    pub(super) fn attach(&self,q:&Arc<Observation>,supervisor:&Supervisor)->Result<(),BridgeError> {
        let mut slot=self.original.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if slot.is_some()||!super::route()||q.case!=ShellCase::GitHubRelease(self.case)||q.failed.load(Ordering::SeqCst)
            ||!q.release.as_ref().is_some_and(|c|std::ptr::eq(c.as_ref(),self)){return Err(BridgeError::invalid());}
        *slot=Some(Arc::downgrade(q));drop(slot);
        self.product.attach(supervisor).map_err(|_|BridgeError::invalid())?;
        let mut r=self.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if r.attached{return Err(BridgeError::invalid());}r.attached=true;Ok(())
    }
    pub(super) fn read_status(&self,status:&read::Status) {
        if self.failed.load(Ordering::SeqCst){return;}
        let Some(mut r)=self.record() else{return;};
        if r.read.as_ref().is_none_or(|old|old.revision<=status.revision){r.read=Some(status.clone());}
    }
    pub(super) fn status(&self,status:&wire::Status) {
        if self.failed.load(Ordering::SeqCst){return;}
        let Some(mut r)=self.record() else{return;};
        if r.session_id.is_some()&&status.session_id.is_some()&&r.session_id!=status.session_id{self.fail();return;}
        if r.release.as_ref().is_none_or(|old|old.revision<=status.revision){r.release=Some(status.clone());}
    }
    pub(super) fn read_result(&self,command:github::Command,result:&Result<read::Status,BridgeError>) {
        let Some(q)=self.original() else{self.fail();return;};if q.failed.load(Ordering::SeqCst){return;}
        let Ok(status)=result else{self.fail();return;};self.read_status(status);
        let Some(mut r)=self.record() else{return;};
        match command {
            github::Command::Status=>{},
            github::Command::Connect=>{
                let Some(session)=status.session.as_ref() else{self.fail();return;};
                if r.connect!=0||session.target_repository!="owner/app"||session.state!=read::SessionState::Checking
                    ||r.project_id.as_deref()!=Some(session.project_id.as_str())||r.session_id.is_some()
                    ||!status.operation.as_ref().is_some_and(|o|o.kind==read::OperationKind::Connect&&o.phase==read::Phase::Running
                        &&o.reason==read::Reason::None){self.fail();return;}
                r.connect=1;r.session_id=Some(session.id.clone());
            },
            github::Command::Disconnect=>{
                if r.disconnect!=0{self.fail();return;}r.disconnect=1;
                if self.case==Case::PreGoRevocation {
                    let same=status.session.as_ref().is_some_and(|s|Some(&s.id)==r.session_id.as_ref()&&s.state==read::SessionState::Disconnecting)
                        &&status.operation.as_ref().is_some_and(|o|o.kind==read::OperationKind::Disconnect&&o.phase==read::Phase::Running);
                    drop(r);
                    // Real revocation admission, not full retirement. Original
                    // stop precedes releasing only its retained writer sender.
                    if !same||self.product.revoked().is_err(){self.fail();}return;
                }
            },
            github::Command::Refresh=>self.fail(),
        }
    }
    pub(super) fn result(&self,command:&str,result:&Result<wire::Status,BridgeError>) {
        let Some(q)=self.original() else{self.fail();return;};if q.failed.load(Ordering::SeqCst){return;}
        let Ok(status)=result else{self.fail();return;};self.status(status);
        let Some(shell)=q.record_at(Boundary::Result) else{return;};let step=shell.step;
        let Some(mut r)=self.record() else{return;};
        if command=="github_release_status" {
            if matches!(step,ShellStep::GitHubRelease(Step::Status|Step::ReadStatus)) {
                if r.explicit_status{self.fail();return;}r.explicit_status=true;
            }return;
        }
        let Some(expected)=expected_action(self.case,r.actions.len()) else{self.fail();return;};
        let Some(operation)=status.operation.as_ref() else{self.fail();return;};
        if command!=expected.0||operation.kind!=expected.1||operation.phase!=wire::Phase::Running||operation.reason!=wire::Reason::None
            ||!expected.2.iter().any(|expected|step==ShellStep::GitHubRelease(*expected))
            ||r.session_id!=status.session_id||r.actions.contains(&operation.id){self.fail();return;}
        r.actions.push(operation.id.clone());
    }
    pub(super) async fn relay(&self,_app:&tauri::AppHandle) {
        let Some(q)=self.original() else{self.fail();return;};if q.failed.load(Ordering::SeqCst){self.fail();return;}
        let step=match q.record(){Some(r)=>r.step,None=>return};
        if step==ShellStep::GitHubRelease(Step::Connect) {
            let start=match self.record(){Some(mut r) if !r.setup_claimed=>{r.setup_claimed=true;true},_=>false};
            if start {
                let Some(root)=super::control_root() else{self.fail();return;};
                let mut peer=self.peer.lock().await;
                if peer.prepare(root,q.end).is_err()||peer.start().await.is_err(){self.fail();return;}
                if let Some(mut r)=self.record(){r.peer_ready=true;}
            }
        }
        if self.product.observe_retired(q.end).await.is_err(){self.fail();}
    }
    pub(super) fn tick(&self,app:&tauri::AppHandle,step:Step)->bool {
        let Some(q)=self.original() else{self.fail();return false;};
        let Some(shell)=q.record() else{return false;};
        if !shell.snapshot_visible||shell.project_witness.is_none(){self.fail();return false;}
        let project=shell.project.as_ref().map(|p|p.id.clone());drop(shell);
        let Some(mut r)=self.record() else{return false;};if r.project_id.is_none(){r.project_id=project;}
        let Some(read)=r.read.as_ref() else{return false;};
        if step==Step::Entry{return read.capability.read_only_session_available&&read.session.is_none();}
        if step==Step::Connect{return r.peer_ready;}
        if step==Step::Connected{return r.connect==1&&read.session.as_ref().is_some_and(|s|s.state==read::SessionState::Connected)
            &&read.operation.as_ref().is_some_and(|o|o.phase==read::Phase::Settled&&o.reason==read::Reason::None)&&self.product.evidence().len()==1;}
        let Some(status)=r.release.as_ref() else{return false;};
        let state=app.state::<super::super::ShellState>();
        let settled=|kind|status.operation.as_ref().is_some_and(|o|o.kind==kind&&o.phase==wire::Phase::Settled);
        match step {
            Step::Configured|Step::ReloadPending=>status.available&&status.session_id==r.session_id,
            Step::Prepared=>r.actions.len()==1&&settled(wire::Kind::Prepare)
                &&status.operation.as_ref().is_some_and(|o|o.reason==wire::Reason::None)
                &&status.prepared.as_ref().is_some_and(|p|prepared_matches(self.case,p))&&self.product.evidence().len()==2,
            Step::Dispatched=>self.case==Case::ResponseLoss&&r.actions.len()==2&&settled(wire::Kind::Dispatch)
                &&status.pending.len()==1&&self.product.evidence().len()==3,
            Step::ReadyToRevoke=>self.case==Case::PreGoRevocation&&r.actions.len()==2&&self.product.ready_held()
                &&status.operation.as_ref().is_some_and(|o|o.kind==wire::Kind::Dispatch&&o.phase==wire::Phase::Running&&o.effect==wire::Effect::NotSent),
            Step::ReadPending=>self.case!=Case::PreGoRevocation&&settled(wire::Kind::Pending)
                &&status.operation.as_ref().is_some_and(|o|o.reason==wire::Reason::None&&o.effect==wire::Effect::None)
                &&r.actions.len()==(if self.case==Case::NormalPending{1}else{3})
                &&self.product.evidence().len()==r.actions.len()+1,
            Step::Reconciled=>self.case==Case::ResponseLoss&&r.actions.len()==4&&settled(wire::Kind::Reconcile)
                &&status.operation.as_ref().is_some_and(|o|o.reason==wire::Reason::None)&&status.run.is_some()
                &&self.product.complete(&state.bridge.supervisor),
            Step::ReadStatus=>r.explicit_status,
            Step::ConnectionRemoved=>r.disconnect==1&&read.session.is_none()&&read.operation.is_none()
                &&self.product.complete(&state.bridge.supervisor),
            Step::Refused=>self.case==Case::PreGoRevocation&&r.connection_removed&&r.actions.len()==2&&settled(wire::Kind::Dispatch)
                &&status.operation.as_ref().is_some_and(|o|o.effect==wire::Effect::NotSent&&o.reason==wire::Reason::Cancelled)
                &&status.pending.is_empty()&&self.product.complete(&state.bridge.supervisor),
            Step::Disconnected=>r.connection_removed&&r.retirement_before.as_ref().is_some_and(|before|retired_data(before,status))
                &&self.product.complete(&state.bridge.supervisor),
            _=>true,
        }
    }
    pub(super) fn dom(&self,step:Step,value:&Value) {
        let Some(q)=self.original() else{self.fail();return;};let Some(mut shell)=q.record_at(Boundary::Dom) else{return;};
        if shell.step!=ShellStep::GitHubRelease(step)||shell.pending.take()!=Some(Pending::Dom(ShellStep::GitHubRelease(step))){self.fail();return;}
        if step==Step::ReloadGuidance&&!shell.github_guidance.click_returned(value){self.fail();return;}
        let Some(object)=value.as_object() else{self.fail();return;};
        if value["state"]=="wait" {if object.len()!=1&&!(step==Step::Entry&&object.len()==9){self.fail();}return;}
        if value["state"]!="ready"{self.fail();return;}
        let Some(mut r)=self.record() else{return;};
        let next=match step {
            Step::Navigate=>Step::ReadGuidanceReload,Step::ReadGuidanceReload=>Step::ReloadGuidance,Step::ReloadGuidance=>Step::EnterRepository,
            Step::EnterRepository=>Step::Entry,
            Step::Entry=>{if object.len()!=9||value["entryAvailable"]!=true||value["helpPresent"]!=true{self.fail();return;}Step::EnterToken},
            Step::EnterToken=>Step::Token,Step::Token=>{if object.len()!=2||value["supplied"]!=true{self.fail();return;}Step::Connect},
            Step::Connect=>Step::Connected,
            Step::Connected=>{if object.len()!=2||value["tokenEmpty"]!=true{self.fail();return;}r.token_cleared=true;Step::OpenReleases},
            Step::OpenReleases=>if self.case==Case::NormalPending{Step::ReloadPending}else{Step::Configure},
            Step::Configure=>if self.case==Case::ResponseLoss{Step::Originals}else{Step::Configured},
            Step::Originals=>Step::Configured,
            Step::Configured=>{
                let production=self.case==Case::ResponseLoss;
                if object.len()!=6||value["stage"]!=(if production{"production-submit"}else{"candidate"})
                    ||value["platform"]!=(if production{"ios"}else{"android"})||value["branch"]!=(if production{"production"}else{"main"})
                    ||value["help"]!=true||value["originals"]!=(if production{json!(["101","102","f".repeat(40),"1.2.3","42"])}else{json!([])})
                    {self.fail();return;}Step::Prepare
            },
            Step::Prepare=>Step::Prepared,
            Step::Prepared=>{
                let Some(p)=r.release.as_ref().and_then(|s|s.prepared.as_ref()) else{self.fail();return;};
                if r.prepared.is_some()||!prepared_matches(self.case,p)||!review_matches(value,p){self.fail();return;}
                let p=p.clone();r.prepared=Some(p);r.review_visible=true;Step::ConfirmText
            },
            Step::ConfirmText=>Step::Confirm,
            Step::Confirm=>{
                if object.len()!=3||value["confirmed"]!=true||r.confirmed
                    ||!r.prepared.as_ref().is_some_and(|p|value["typedText"]==p.confirmation){self.fail();return;}
                r.typed=true;r.confirmed=true;Step::Dispatch
            },
            Step::Dispatch=>if self.case==Case::PreGoRevocation{Step::ReadyToRevoke}else{Step::Dispatched},
            Step::ReadyToRevoke=>{
                if object.len()!=3||!r.release.as_ref().and_then(|s|s.operation.as_ref()).is_some_and(|o|value["operationId"]==o.id)
                    ||value["notSent"]!=true||!self.product.ready_held(){self.fail();return;}Step::OpenGitHub
            },
            Step::Dispatched=>{
                let Some(status)=r.release.as_ref() else{self.fail();return;};let Some(op)=status.operation.as_ref() else{self.fail();return;};
                if self.case!=Case::ResponseLoss||object.len()!=5||value["operationId"]!=op.id||value["effect"]!="potentially-applied"
                    ||value["noSecondDispatch"]!=true||value["reconcileReady"]!=true||op.effect!=wire::Effect::PotentiallyApplied
                    ||op.reason!=wire::Reason::TlsFailed||status.pending.len()!=1||status.pending[0].run_id.is_some()
                    ||Some(&status.pending[0].prepared)!=r.prepared.as_ref(){self.fail();return;}
                r.dispatch_effect=Some(wire::Effect::PotentiallyApplied);r.dispatch_reason=Some(wire::Reason::TlsFailed);Step::ReloadPending
            },
            Step::ReloadPending=>{if r.pending_reloaded||self.case==Case::PreGoRevocation{self.fail();return;}Step::ReadPending},
            Step::ReadPending=>{
                let Some(status)=r.release.as_ref() else{self.fail();return;};
                if r.pending_reloaded||!pending_dom(value,status,self.case)||self.case==Case::ResponseLoss
                    &&Some(&status.pending[0].prepared)!=r.prepared.as_ref(){self.fail();return;}
                r.pending_reloaded=true;if self.case==Case::NormalPending{Step::Status}else{Step::Reconcile}
            },
            Step::Reconcile=>Step::Reconciled,
            Step::Reconciled=>{
                let Some(status)=r.release.as_ref() else{self.fail();return;};
                if self.case!=Case::ResponseLoss||!run_dom(value,status){self.fail();return;}
                r.run_observed=true;Step::Status
            },
            Step::Status=>Step::ReadStatus,
            Step::ReadStatus=>{
                let Some(status)=r.release.as_ref() else{self.fail();return;};
                if !r.explicit_status||!match self.case{Case::NormalPending=>pending_dom(value,status,self.case),
                    Case::ResponseLoss=>run_dom(value,status),Case::PreGoRevocation=>negative_dom(value,status)}{self.fail();return;}
                r.retirement_before=Some(status.clone());if r.connection_removed{Step::Disconnected}else{Step::OpenGitHub}
            },
            Step::OpenGitHub=>Step::Disconnect,Step::Disconnect=>Step::ConnectionRemoved,
            Step::ConnectionRemoved=>{
                if object.len()!=3||value["tokenEmpty"]!=true||value["noSession"]!=true||r.connection_removed{self.fail();return;}
                r.connection_removed=true;Step::ReturnReleases
            },
            Step::ReturnReleases=>if self.case==Case::PreGoRevocation{Step::Refused}else{Step::Disconnected},
            Step::Refused=>{
                let Some(status)=r.release.as_ref() else{self.fail();return;};let originals=self.product.evidence();
                if !negative_dom(value,status)||!originals.last().is_some_and(|v|v["negative"]==true&&v["reason"]=="cancelled"
                    &&v["effect"]=="not-sent"&&v["operationId"]==value["operationId"]){self.fail();return;}
                r.dispatch_effect=Some(wire::Effect::NotSent);r.dispatch_reason=Some(wire::Reason::Cancelled);Step::Status
            },
            Step::Disconnected=>{
                let Some(status)=r.release.as_ref() else{self.fail();return;};
                if !r.retirement_before.as_ref().is_some_and(|before|retired_data(before,status))||!retired_dom(value,status){self.fail();return;}
                r.retired_without_authority=true;r.close_ready=true;shell.step=ShellStep::Close;return;
            },
        };
        if matches!(step,Step::Navigate|Step::ReadGuidanceReload|Step::ReloadGuidance|Step::EnterRepository|Step::EnterToken|Step::Connect
            |Step::OpenReleases|Step::Configure|Step::Originals|Step::Prepare|Step::ConfirmText|Step::Dispatch|Step::ReloadPending
            |Step::Reconcile|Step::Status|Step::OpenGitHub|Step::Disconnect|Step::ReturnReleases)&&object.len()!=1 {self.fail();return;}
        shell.step=ShellStep::GitHubRelease(next);
    }
    pub(super) fn ready_to_close(&self)->bool {!self.failed.load(Ordering::SeqCst)&&self.record().is_some_and(|r|r.close_ready)}
    pub(super) async fn settle_for_exit(&self,app:&tauri::AppHandle)->bool {
        let Some(q)=self.original() else{self.fail();return false;};let state=app.state::<super::super::ShellState>();
        // Actual accepted Quit belongs here, never in the pre-Quit UI gates.
        if !state.document.can_exit(){return false;}if self.record().is_some_and(|r|r.physical_final){return true;}
        let product=self.product.observe_retired(q.end).await.is_ok_and(|seen|seen&&self.product.complete(&state.bridge.supervisor));
        let success=product&&!q.failed.load(Ordering::SeqCst)&&self.ready_to_close();
        let mut peer=self.peer.lock().await;let physical=peer.settle(success,q.end).await;
        let marker=self.product.marker();let checked=success&&physical&&peer.validate(marker.as_deref()).is_ok();
        if !checked{self.fail();}let Some(mut r)=self.record() else{return false;};
        r.physical_final=physical;r.final_checked=checked;if checked{r.peer_receipt=Some(peer.evidence());}physical
    }
    pub(super) fn complete(&self)->bool {
        !self.failed.load(Ordering::SeqCst)&&self.record().is_some_and(|r|r.attached&&r.setup_claimed&&r.peer_ready&&r.connect==1&&r.disconnect==1
            &&r.actions.len()==self.case.action_count()&&r.pending_reloaded==(self.case!=Case::PreGoRevocation)
            &&r.explicit_status&&r.token_cleared&&r.review_visible==(self.case!=Case::NormalPending)
            &&r.typed==r.review_visible&&r.confirmed==r.review_visible&&r.run_observed==(self.case==Case::ResponseLoss)
            &&r.connection_removed&&r.retired_without_authority&&r.close_ready&&r.physical_final&&r.final_checked&&r.peer_receipt.is_some()
            &&self.product.evidence().iter().skip(1).zip(&r.actions).all(|(original,id)|original["operationId"].as_str()==Some(id.as_str())))
    }
    pub(super) fn report(&self)->Option<Vec<u8>> {
        if !self.complete(){return None;}let q=self.original()?;let shell=q.record()?;let r=self.record()?;
        if !shell.exit||!shell.originals_final||!shell.relay_joined||!shell.github_guidance.complete(){return None;}
        serde_json::to_vec(&json!({"schemaVersion":1,"fixture":"github-release-installed-v1","case":self.case.name(),
            "sourceCommit":option_env!("GITHUB_SHA")?,"normalManifestSha256":crate::runtime::PassiveInstalledProfile::MANIFEST,
            "productManifestSha256":self.case.manifest(),"connectionManifestSha256":RuntimeProfile::MANIFEST,
            "protocolSha256":"083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5",
            "toolingSha":RuntimeProfile::TOOLING_SHA,"callerSha256":callers(),"peerSha256":peer_sha256(),
            "project":{"cancelSettled":shell.cancelled&&shell.pickers[0].settled(false),"registered":shell.selected&&shell.pickers[1].settled(true)
                &&shell.project_witness.is_some(),"snapshot":shell.snapshot&&shell.snapshot_visible},
            "nativeSession":{"connect":r.connect,"prepare":u8::from(r.review_visible),"dispatch":u8::from(r.confirmed),
                "pending":u8::from(r.pending_reloaded),"reconcile":u8::from(r.run_observed),"disconnect":r.disconnect,"retainedStatus":r.explicit_status,
                "pendingReloaded":r.pending_reloaded,"tokenFieldCleared":r.token_cleared,"reviewVisible":r.review_visible,"typedConfirmation":r.typed,
                "consentObserved":r.confirmed,"originalDeclarationsDistinct":self.case==Case::ResponseLoss&&r.prepared.as_ref().is_some_and(|p|prepared_matches(self.case,p)),
                "dispatchEffect":r.dispatch_effect,"dispatchReason":r.dispatch_reason,"runObserved":r.run_observed,
                "retirement":{"mode":"disconnected","authorityRemoved":r.retired_without_authority,
                    "terminalPreserved":r.retired_without_authority,"recoveryPreserved":r.retired_without_authority}},
            "scheduling":self.product.timeline(),"originals":self.product.evidence(),"peer":r.peer_receipt,
            "quit":{"originalsFinal":shell.originals_final,"relayJoined":shell.relay_joined,
                "gtkSettled":shell.gtk_returned&&shell.destroyed&&shell.released,"exit":shell.exit},
            "notProven":["real-github-release-dispatch","real-github-release-job-names","delivered-production-tooling",
                "macos-github-release","windows-github-release","kernel-close-error-injection"]
        })).ok().filter(|raw|raw.len()<=32768)
    }
}
fn retired_data(before:&wire::Status,after:&wire::Status)->bool {
    before.session_id.is_some()&&before.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::Settled)
        &&after.revision>=before.revision&&after.session_id==before.session_id&&after.operation==before.operation
        &&after.pending==before.pending&&after.run==before.run&&!after.available&&after.reason==wire::Reason::NotConnected
        &&after.prepared.is_none()&&after.consent_expires_at.is_none()
}
fn records_dom(value:&Value,status:&wire::Status)->bool {
    value.as_array().is_some_and(|rows|rows.len()==status.pending.len()&&rows.iter().zip(&status.pending).all(|(row,record)|
        super::keys(row,&["codes","heading","text"])&&row["codes"]==json!([record.prepared.source_sha,record.prepared.display_title])
            &&row["heading"]==format!("{} · {}",match record.prepared.target.selection.stage {
                wire::Stage::Candidate=>"Internal candidate",wire::Stage::ExternalTesting=>"External testing",wire::Stage::ProductionSubmit=>"Production submission"},record.prepared.target.platform.text())
            &&row["text"].as_str().is_some_and(|text|text.contains(&format!("{} · {}",record.prepared.target.repository,record.prepared.target.branch))
                &&text.contains(&format!("Run {} · original attempt 1.",record.run_id.as_deref().unwrap_or("not yet resolved"))))))
}
fn pending_dom(value:&Value,status:&wire::Status,case:Case)->bool {
    let Some(op)=status.operation.as_ref() else{return false;};let normal=case==Case::NormalPending;
    super::keys(value,&["state","operationId","records","emptyWarning","reconcileReady"])
        &&value["state"]=="ready"&&value["operationId"]==op.id&&op.kind==wire::Kind::Pending&&op.phase==wire::Phase::Settled
        &&op.reason==wire::Reason::None&&op.effect==wire::Effect::None&&status.run.is_none()
        &&records_dom(&value["records"],status)&&value["emptyWarning"]==normal&&value["reconcileReady"]==!normal
        &&(if normal{status.pending.is_empty()}else{case==Case::ResponseLoss&&status.pending.len()==1&&status.pending[0].run_id.is_none()})
}
fn run_dom(value:&Value,status:&wire::Status)->bool {
    let Some(run)=status.run.as_ref() else{return false;};let Some(op)=status.operation.as_ref() else{return false;};
    super::keys(value,&["state","operationId","runId","jobs","notReleaseEvidence"])
        &&value["state"]=="ready"&&value["operationId"]==op.id&&op.kind==wire::Kind::Reconcile&&op.phase==wire::Phase::Settled
        &&op.reason==wire::Reason::None&&value["runId"]=="9001"&&value["jobs"]==json!(["input-guard: completed · success","ios: completed · success"])
        &&value["notReleaseEvidence"]==true&&run.id=="9001"&&run.attempt==1
        &&run.conclusion==Some(wire::Conclusion::Success)&&status.pending.len()==1&&status.pending[0].run_id.as_deref()==Some("9001")
}
fn negative_dom(value:&Value,status:&wire::Status)->bool {
    let Some(op)=status.operation.as_ref() else{return false;};
    super::keys(value,&["state","operationId","effect","message","noSecondDispatch","noRun","records","newWorkDenied"])
        &&value["state"]=="ready"&&value["operationId"]==op.id&&value["effect"]=="not-sent"
        &&op.kind==wire::Kind::Dispatch&&op.phase==wire::Phase::Settled&&op.reason==wire::Reason::Cancelled&&op.effect==wire::Effect::NotSent
        &&value["message"].as_str().is_some_and(|message|message.ends_with("The local action was stopped. A workflow already accepted by GitHub may still be running."))
        &&["noSecondDispatch","noRun","newWorkDenied"].iter().all(|key|value[*key]==true)
        &&status.pending.is_empty()&&records_dom(&value["records"],status)&&status.run.is_none()&&!status.available
        &&status.prepared.is_none()&&status.consent_expires_at.is_none()
}
fn retired_dom(value:&Value,status:&wire::Status)->bool {
    let Some(op)=status.operation.as_ref() else{return false;};
    let run=status.run.as_ref().map(|run|json!({"title":format!("Run {} · attempt 1",run.id),
        "jobs":["input-guard: completed · success","ios: completed · success"],"url":run.url}));
    super::keys(value,&["state","operationId","effect","records","run","noReview","selectionEmpty","actionsDisabled"])
        &&value["state"]=="ready"&&value["operationId"]==op.id
        &&value["effect"]==(if op.kind==wire::Kind::Dispatch{json!(op.effect)}else{Value::Null})
        &&records_dom(&value["records"],status)&&value["run"]==json!(run)
        &&["noReview","selectionEmpty","actionsDisabled"].iter().all(|key|value[*key]==true)
}
fn review_matches(value:&Value,p:&wire::Prepared)->bool {
    let mut codes=vec![p.expected_ref.as_str(),p.source_sha.as_str(),p.source_tree.as_str(),p.config_sha256.as_str(),
        p.version_source.as_str(),p.version_sha256.as_str(),p.workflow_path.as_str(),p.caller_sha256.as_str(),p.target.tooling_sha.as_str()];
    if let Some(source)=&p.target.selection.original_source_sha{codes.push(source);}
    codes.push(&p.display_title);
    let original=p.target.selection.original_version.as_ref().map(|v|format!("{} · build {}",v.name,v.build))
        .unwrap_or_else(||"Fresh candidate: uses the current committed version.".into());
    super::keys(value,&["state","codes","currentVersion","originalVersion","producerIds","confirmation","unchecked","dispatchDisabled","help"])
        &&value["state"]=="ready"&&value["codes"]==json!(codes)&&value["currentVersion"]==format!("{} · build {}",p.current_version.name,p.current_version.build)
        &&value["originalVersion"]==original&&value["producerIds"]==format!("Candidate: {} · external: {} · recovery: {}",
            p.target.selection.candidate_run_id.as_deref().unwrap_or("none"),p.target.selection.external_run_id.as_deref().unwrap_or("none"),
            p.target.selection.recovery_run_id.as_deref().unwrap_or("none"))
        &&value["confirmation"]==p.confirmation&&value["unchecked"]==true&&value["dispatchDisabled"]==true&&value["help"]==true
}
// Translate only this R reservation into the existing one-use guidance owner.
pub(super) fn guidance_reload_scope(step:ShellStep,pending:Option<Pending>,live:bool)->github::GuidanceReloadScope {
    if !live{return github::GuidanceReloadScope::Outside;}
    match (step,pending) {
        (ShellStep::GitHubRelease(Step::ReloadGuidance),Some(Pending::Dom(ShellStep::GitHubRelease(Step::ReloadGuidance))))=>github::GuidanceReloadScope::ClickPending,
        (ShellStep::GitHubRelease(Step::EnterRepository),None)=>github::GuidanceReloadScope::AwaitReplies,
        _=>github::GuidanceReloadScope::Outside,
    }
}
pub(super) fn assert_contracts() {
    use github::GuidanceReloadScope::{ClickPending,AwaitReplies,Outside};
    let click=ShellStep::GitHubRelease(Step::ReloadGuidance);let replies=ShellStep::GitHubRelease(Step::EnterRepository);
    assert!(guidance_reload_scope(click,Some(Pending::Dom(click)),true)==ClickPending);
    assert!(guidance_reload_scope(replies,None,true)==AwaitReplies);
    for (step,pending,live) in [(click,None,true),(click,Some(Pending::Dom(replies)),true),(replies,Some(Pending::Dom(replies)),true),
        (click,Some(Pending::Dom(click)),false),(replies,None,false),
        (ShellStep::GitHubReadOnly(github::Step::EnterRepository),None,true),
        (ShellStep::GitHubPreflight(super::preflight::Step::EnterRepository),None,true)] {
        assert!(guidance_reload_scope(step,pending,live)==Outside);
    }
    assert!(github::guidance_reload_scope(click,Some(Pending::Dom(click)),true)==Outside);
    assert!(super::preflight::guidance_reload_scope(replies,None,true)==Outside);
    for case in Case::ALL {
        for index in 0..case.action_count(){assert_eq!(Some(expected_action(case,index).unwrap().1),case.kind(index+1));}
        assert!(expected_action(case,case.action_count()).is_none());assert!(expected_action(case,usize::MAX).is_none());
    }
    assert!(expected_action(Case::NormalPending,0).unwrap().2==[Step::ReloadPending,Step::ReadPending]);
    assert!(expected_action(Case::PreGoRevocation,1).unwrap().2==[Step::Dispatch,Step::ReadyToRevoke]);
    // Pure preservation DATA; no synthetic session or native receipt.
    let before=wire::Status{schema_version:1,revision:10,session_id:Some("github-session-1".into()),available:true,reason:wire::Reason::None,
        operation:Some(wire::Operation{id:"original-pending-1".into(),kind:wire::Kind::Pending,phase:wire::Phase::Settled,
            reason:wire::Reason::None,effect:wire::Effect::None}),prepared:None,consent_expires_at:None,pending:vec![],run:None};
    let mut after=before.clone();after.revision+=1;after.available=false;after.reason=wire::Reason::NotConnected;
    assert!(retired_data(&before,&after));
    let value=json!({"state":"ready","operationId":"original-pending-1","records":[],"emptyWarning":true,"reconcileReady":false});
    assert!(pending_dom(&value,&before,Case::NormalPending));assert!(!pending_dom(&value,&before,Case::ResponseLoss));
    let mut wrong=after.clone();wrong.operation=None;assert!(!retired_data(&before,&wrong));
    wrong=after.clone();wrong.session_id=None;assert!(!retired_data(&before,&wrong));
    wrong=after.clone();wrong.available=true;assert!(!retired_data(&before,&wrong));
    wrong=after.clone();wrong.revision=9;assert!(!retired_data(&before,&wrong));
    wrong=after.clone();wrong.consent_expires_at=Some("2026-09-27T01:00:00Z".into());assert!(!retired_data(&before,&wrong));
    let mut surplus=value.clone();surplus["runId"]=json!("9001");assert!(!pending_dom(&surplus,&before,Case::NormalPending));
    crate::supervisor::github_release_native_observation::assert_contracts();
}
pub(super) fn script(step:Step,case:Case)->Option<String> {
    if let Some(shared)=step.shared(){return github::script(shared);}
    let production=case==Case::ResponseLoss;let stage=if production{"production-submit"}else{"candidate"};
    let platform=if production{"ios"}else{"android"};let branch=if production{"production"}else{"main"};
    let body=match step {
        Step::Connected=>r#"const c=connection(),token=c?.querySelector('input[type="password"]');if(!c)return {state:'wait'};
            return {state:'ready',tokenEmpty:!token||token.value===''};"#,
        Step::OpenReleases|Step::ReturnReleases=>r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Releases"]');
            if(!b||b.disabled)return {state:'wait'};show(b);b.click();return {state:'ready'};"#,
        Step::Configure=>r#"const c=card(),s=field('Release step'),p=field('Release platform'),b=field('Dispatch branch');
            if(!c||!s||!p||!b||s.disabled||p.disabled||b.disabled)return {state:'wait'};select(s,stage);select(p,platform);edit(b,branch);return {state:'ready'};"#,
        Step::Originals=>r#"const rows=originalFields.map(field);if(rows.some(f=>!f||f.disabled))return {state:'wait'};
            const values=['101','102','f'.repeat(40),'1.2.3','42'];rows.forEach((f,i)=>edit(f,values[i]));return {state:'ready'};"#,
        Step::Configured=>r#"const c=card(),s=field('Release step'),p=field('Release platform'),b=field('Dispatch branch'),prepare=button('Prepare release review · read GitHub only');
            if(!c||!s||!p||!b||!prepare||prepare.disabled)return {state:'wait'};show(c);return {state:'ready',stage:s.value,platform:p.value,branch:b.value,
                help:['Release step','Release platform','Dispatch branch','GitHub release access'].every(label=>c.querySelector(`button[aria-label="Help: ${label}"]`)),
                originals:stage==='production-submit'?originalFields.map(label=>field(label)?.value):[]};"#,
        Step::Prepare=>r#"return click('Prepare release review · read GitHub only');"#,
        Step::Prepared=>r#"const c=card()?.querySelector('[aria-label="Exact protected release review"]');if(!c)return {state:'wait'};show(c);
            const check=c.querySelector('input[type="checkbox"]'),b=button('Dispatch this protected release request once'),confirmation=c.querySelector(':scope > p > code');
            if(!check||!b||!confirmation)throw 0;const fact=name=>[...c.querySelectorAll('dl > div')].find(row=>text(row.querySelector('dt'))===name)?.querySelector('dd');
            const line=n=>{if(!n)throw 0;let t='';for(const child of n.childNodes){if(child.nodeName==='BR')break;t+=child.textContent;}return t.trim();};
            return {state:'ready',codes:[...c.querySelectorAll('dl code')].map(text),
                currentVersion:line(fact('Current committed version (not necessarily original artifact version)')),
                originalVersion:line(fact('Declared original artifact')),producerIds:text(fact('Declared original producer IDs')),confirmation:text(confirmation),
                unchecked:!check.checked,dispatchDisabled:b.disabled,help:!!c.querySelector('button[aria-label="Help: One-use Store-impacting workflow confirmation"]')};"#,
        Step::ConfirmText=>r#"const c=card()?.querySelector('[aria-label="Exact protected release review"]'),input=field('Type this exact release confirmation'),value=c?.querySelector(':scope > p > code');
            if(!c||!input||input.disabled||!value)return {state:'wait'};edit(input,text(value));return {state:'ready'};"#,
        Step::Confirm=>r#"const c=card()?.querySelector('[aria-label="Exact protected release review"]'),check=c?.querySelector('input[type="checkbox"]'),input=field('Type this exact release confirmation');
            if(!check||check.disabled||!input)return {state:'wait'};if(check.checked)throw 0;show(check);check.click();return {state:'ready',confirmed:check.checked,typedText:input.value};"#,
        Step::Dispatch=>r#"return click('Dispatch this protected release request once');"#,
        Step::Dispatched=>r#"const c=card(),op=operation(),b=button('Reconcile exact request · read GitHub'),dispatch=button('Dispatch this protected release request once');
            if(!c||!op||!text(op).startsWith('dispatch · settled')||!b||b.disabled||text(op.querySelector('strong'))!=='potentially-applied')return {state:'wait'};
            show(c);if(!op.querySelector('code'))throw 0;return {state:'ready',operationId:text(op.querySelector('code')),effect:text(op.querySelector('strong')),
                noSecondDispatch:!dispatch||dispatch.disabled,reconcileReady:!b.disabled};"#,
        Step::ReadyToRevoke=>r#"const c=card(),op=operation();if(!c||!op||!text(op).startsWith('dispatch · running')
            ||text(op.querySelector('strong'))!=='not-sent')return {state:'wait'};show(c);if(!op.querySelector('code'))throw 0;
            return {state:'ready',operationId:text(op.querySelector('code')),notSent:true};"#,
        Step::ReloadPending=>r#"return click('Load this project’s release requests · local only');"#,
        Step::ReadPending=>r#"return pending();"#,
        Step::Reconcile=>r#"return click('Reconcile exact request · read GitHub');"#,
        Step::Reconciled=>r#"return runView();"#,
        Step::Status=>r#"return click('Read local Status');"#,
        Step::ReadStatus if case==Case::NormalPending=>r#"return pending();"#,
        Step::ReadStatus if case==Case::ResponseLoss=>r#"return runView();"#,
        Step::ReadStatus|Step::Refused=>r#"return negative();"#,
        Step::ConnectionRemoved=>r#"const c=connection();if(!c)return {state:'wait'};show(c);
            const row=[...c.querySelectorAll(':scope > p.save-note')].find(p=>/^(Original native|Retained \/ stale original) status/.test(text(p))),token=c.querySelector('input[type="password"]');
            if(!row||row.querySelector('code')||[...c.querySelectorAll(':scope > p.save-note')].some(p=>/^Original (connect|refresh|disconnect):/.test(text(p))))return {state:'wait'};
            return {state:'ready',tokenEmpty:!token||token.value==='',noSession:true};"#,
        Step::Disconnected=>r#"const c=card(),op=operation();if(!c||!op||!/^(pending|dispatch|reconcile) · settled/.test(text(op)))return {state:'wait'};
            const s=field('Release step'),p=field('Release platform'),b=field('Dispatch branch'),run=c.querySelector('[aria-label="Original protected workflow observation"]'),effect=op.querySelector('strong'),
                noReview=!c.querySelector('[aria-label="Exact protected release review"]'),selectionEmpty=!!s&&!!p&&!!b&&s.value===''&&p.value===''&&b.value==='',actionsDisabled=denied();
            if(!noReview||!selectionEmpty||!actionsDisabled)return {state:'wait'};show(c);if(!op.querySelector('code'))throw 0;
            return {state:'ready',operationId:text(op.querySelector('code')),effect:effect?text(effect):null,records:records(),
                run:run?{title:text(run.querySelector('h4')),jobs:[...run.querySelectorAll('li')].map(text),url:text(run.querySelector('code'))}:null,
                noReview,selectionEmpty,actionsDisabled};"#,
        _=>return None,
    };
    Some(format!(r#"(()=>{{try{{
        const text=n=>n?.textContent?.trim()??'',card=()=>{{if(!document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Releases"][aria-current="page"]'))return null;
            const rows=document.querySelectorAll('section[aria-label="Protected release workflows"]');if(rows.length>1)throw 0;return rows[0];}},
            connection=()=>document.querySelector('[aria-label="GitHub connection and observations"]'),stage={stage:?},platform={platform:?},branch={branch:?};
        const originalFields=['Candidate evidence producer run ID','External-testing evidence producer run ID','Original artifact source commit','Original marketing version','Original build number'];
        const show=n=>{{n.scrollIntoView({{block:'center'}});const r= n.getBoundingClientRect();if(r.width<=0||r.height<=0||getComputedStyle(n).visibility!=='visible')throw 0;}};
        const field=name=>{{const rows=[...(card()?.querySelectorAll('label[for]')??[])].filter(n=>text(n)===name);if(rows.length>1)throw 0;return rows[0]?document.getElementById(rows[0].htmlFor):null;}};
        const button=name=>{{const rows=[...(card()?.querySelectorAll('button')??[])].filter(b=>text(b)===name);if(rows.length>1)throw 0;return rows[0];}};
        const click=name=>{{const b=button(name);if(!b||b.disabled)return {{state:'wait'}};show(b);b.click();return {{state:'ready'}};}};
        const operation=()=>[...(card()?.querySelectorAll(':scope > p.save-note[role="status"]')??[])].find(p=>p.querySelector('code'));
        const denied=()=>['Prepare release review · read GitHub only','Dispatch this protected release request once','Load this project’s release requests · local only',
            'Track original run · read GitHub','Reconcile exact request · read GitHub'].every(name=>{{const b=button(name);return !b||b.disabled;}});
        const records=()=>[...(card()?.querySelectorAll(':scope > article.github-environment:not([aria-label])')??[])].filter(record=>text(record.querySelector('h4'))!=='Original artifact declarations')
            .map(record=>({{codes:[...record.querySelectorAll('code')].map(text),heading:text(record.querySelector('h4')),text:text(record)}}));
        const pending=()=>{{const c=card(),op=operation(),b=button('Reconcile exact request · read GitHub');if(!c||!op||!text(op).startsWith('pending · settled'))return {{state:'wait'}};
            show(c);return {{state:'ready',operationId:text(op.querySelector('code')),records:records(),
                emptyWarning:text(c).includes('No record is currently displayed. This does not prove that no remote release or Store effect exists.'),reconcileReady:!!b&&!b.disabled}};}};
        const runView=()=>{{const run=card()?.querySelector('[aria-label="Original protected workflow observation"]'),op=operation();if(!run||!op||!text(op).startsWith('reconcile · settled'))return {{state:'wait'}};
            show(run);if(text(run.querySelector('h4'))!=='Run 9001 · attempt 1')throw 0;return {{state:'ready',operationId:text(op.querySelector('code')),runId:'9001',jobs:[...run.querySelectorAll('li')].map(text),
                notReleaseEvidence:text(run).includes('not authenticated artifact evidence, complete release history or production readiness')}};}};
        const negative=()=>{{const c=card(),op=operation(),dispatch=button('Dispatch this protected release request once');
            if(!c||!op||!text(op).startsWith('dispatch · settled')||text(op.querySelector('strong'))!=='not-sent')return {{state:'wait'}};show(c);
            return {{state:'ready',operationId:text(op.querySelector('code')),effect:text(op.querySelector('strong')),message:text(op),
                noSecondDispatch:!dispatch||dispatch.disabled,noRun:!c.querySelector('[aria-label="Original protected workflow observation"]'),records:records(),newWorkDenied:denied()}};}};
        const edit=(input,value)=>{{show(input);input.focus();input.select();if(!document.execCommand('insertText',false,value))throw 0;}};
        const select=(input,value)=>{{show(input);Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(input,value);input.dispatchEvent(new Event('change',{{bubbles:true}}));}};
        {body}
    }}catch{{return {{state:'error'}};}}}})()"#))
}
