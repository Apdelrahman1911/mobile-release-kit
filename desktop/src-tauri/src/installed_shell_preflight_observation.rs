//! Finite ordinary-UI preflight observations. The existing relay/exit drive
//! this adapter; it creates no replacement command, worker or lifecycle owner.
use std::sync::{Arc,Mutex,Weak,atomic::{AtomicBool,Ordering}};
use serde_json::{json,Value};
use tauri::Manager;
use tokio::sync::Mutex as AsyncMutex;
use crate::{error::BridgeError,github_connection_protocol as read,github_preflight_protocol as wire,
    runtime::GitHubPreflightObservationProfile as RuntimeProfile,supervisor::{Supervisor,
        github_preflight_native_observation::{InstalledPeer,ProductWitness,peer_sha256}}};
use super::{Observation,Case as ShellCase,Step as ShellStep,Pending,Boundary,github};
pub(crate) use crate::supervisor::github_preflight_native_observation::Case;

impl Case {
    pub(super) fn failure_leaf(self)->&'static str {match self {
        Self::Success=>"shell-github-preflight-success-failure.labels",
        Self::ResponseLoss=>"shell-github-preflight-response-loss-failure.labels",
        Self::PreGoRevocation=>"shell-github-preflight-pre-go-revocation-failure.labels",
        Self::JournalCollision=>"shell-github-preflight-journal-collision-failure.labels",
        Self::FinalityRefusal=>"shell-github-preflight-finality-refusal-failure.labels",
    }}
    pub(super) fn verified_line(self)->&'static [u8] {match self {
        Self::Success=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-preflight-success-verified\n",
        Self::ResponseLoss=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-preflight-response-loss-verified\n",
        Self::PreGoRevocation=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-preflight-pre-go-revocation-verified\n",
        Self::JournalCollision=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-preflight-journal-collision-verified\n",
        Self::FinalityRefusal=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-preflight-finality-refusal-verified\n",
    }}
}
#[derive(Clone,Copy,PartialEq,Eq)]
pub(super) enum Step { Navigate,ReadGuidanceReload,ReloadGuidance,EnterRepository,Entry,EnterToken,Token,Connect,
    Connected,Configure,Configured,Prepare,Prepared,Confirm,Dispatch,Dispatched,ReloadPending,ReadPending,
    ObserveRun,ObservedRun,Status,ReadStatus,Disconnect,Disconnected,ReadyToRevoke,Refused,Cancel,Unknown,LateRetired }
impl Step {
    pub(super) fn failure_line(self)->&'static [u8] {match self {
        Self::Navigate=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightNavigate\n",
        Self::ReadGuidanceReload=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightGuidanceReady\n",
        Self::ReloadGuidance=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightGuidanceReload\n",
        Self::EnterRepository=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightRepository\n",
        Self::Entry=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightEntry\n",
        Self::EnterToken=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightToken\n",
        Self::Token=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightTokenReady\n",
        Self::Connect=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightConnect\n",
        Self::Connected=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightConnected\n",
        Self::Configure=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightConfigure\n",
        Self::Configured=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightConfigured\n",
        Self::Prepare=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightPrepare\n",
        Self::Prepared=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightPrepared\n",
        Self::Confirm=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightConfirm\n",
        Self::Dispatch=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightDispatch\n",
        Self::Dispatched=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightDispatched\n",
        Self::ReloadPending=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightReloadPending\n",
        Self::ReadPending=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightReadPending\n",
        Self::ObserveRun=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightObserveRun\n",
        Self::ObservedRun=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightObservedRun\n",
        Self::Status=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightStatus\n",
        Self::ReadStatus=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightReadStatus\n",
        Self::Disconnect=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightDisconnect\n",
        Self::Disconnected=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightDisconnected\n",
        Self::ReadyToRevoke=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightReadyToRevoke\n",
        Self::Refused=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightRefused\n",
        Self::Cancel=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightCancel\n",
        Self::Unknown=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightUnknown\n",
        Self::LateRetired=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=PreflightLateRetired\n",
    }}
    fn shared(self)->Option<github::Step> {Some(match self {
        Self::Navigate=>github::Step::Navigate,Self::ReadGuidanceReload=>github::Step::ReadGuidanceReload,
        Self::ReloadGuidance=>github::Step::ReloadGuidance,Self::EnterRepository=>github::Step::EnterRepository,
        Self::Entry=>github::Step::Entry,Self::EnterToken=>github::Step::EnterToken,Self::Token=>github::Step::Token,
        Self::Connect=>github::Step::Connect,Self::Disconnect=>github::Step::Disconnect,_=>return None,
    })}
}
fn expected_action(case:Case,index:usize)->Option<(&'static str,wire::Kind,[Step;2])> {
    let kind=case.kind(index.checked_add(1)?)?;
    let (command,steps)=match kind {
        wire::Kind::Prepare=>("github_preflight_prepare",[Step::Prepare,Step::Prepared]),
        wire::Kind::Dispatch=>("github_preflight_dispatch",[Step::Dispatch,match (case,index) {
            (Case::PreGoRevocation,1)=>Step::ReadyToRevoke,(Case::FinalityRefusal,1)=>Step::Cancel,
            (Case::JournalCollision,3)=>Step::Refused,_=>Step::Dispatched,
        }]),
        wire::Kind::Pending=>("github_preflight_pending",[Step::ReloadPending,Step::ReadPending]),
        wire::Kind::Track=>("github_preflight_track",[Step::ObserveRun,Step::ObservedRun]),
        wire::Kind::Reconcile=>("github_preflight_reconcile",[Step::ObserveRun,Step::ObservedRun]),
    };
    Some((command,kind,steps))
}

#[derive(Default)]
struct Record {
    attached:bool,setup_claimed:bool,peer_ready:bool,project_id:Option<String>,session_id:Option<String>,
    read:Option<read::Status>,preflight:Option<wire::Status>,prepared:Option<wire::Prepared>,
    connect:u8,disconnect:u8,actions:Vec<String>,explicit_status:bool,token_cleared:bool,
    review_visible:bool,confirmed:bool,dispatch_effect:Option<wire::Effect>,dispatch_reason:Option<wire::Reason>,
    pending_reloaded:bool,run_observed:bool,retired_without_authority:bool,close_ready:bool,physical_final:bool,final_checked:bool,peer_receipt:Option<Value>,
    reviews:u8,consents:u8,cancel:u8,unknown_dom:bool,late_retired:bool,retirement_before:Option<wire::Status>,
    // The renderer deliberately keeps its first Unknown snapshot. Native
    // late retirement may add recovery DATA, never success or new authority.
    unknown_snapshot:Option<wire::Status>,
}
pub(crate) struct Control {
    case:Case,original:Mutex<Option<Weak<Observation>>>,failed:AtomicBool,record:Mutex<Record>,
    peer:AsyncMutex<InstalledPeer>,product:Arc<ProductWitness>,
}
impl Control {
    pub(super) fn new(case:Case)->Arc<Self> {Arc::new(Self{case,original:Mutex::new(None),failed:AtomicBool::new(false),
        record:Mutex::new(Record::default()),peer:AsyncMutex::new(InstalledPeer::new(case)),product:ProductWitness::new(case)})}
    fn original(&self)->Option<Arc<Observation>> {self.original.lock().ok()?.as_ref()?.upgrade()}
    fn fail(&self) {self.failed.store(true,Ordering::SeqCst);self.product.fail();if let Some(q)=self.original(){q.fail();}}
    fn record(&self)->Option<std::sync::MutexGuard<'_,Record>> {
        match self.record.lock(){Ok(record)=>Some(record),Err(_)=>{self.fail();None}}
    }
    pub(super) fn attach(&self,q:&Arc<Observation>,supervisor:&Supervisor)->Result<(),BridgeError> {
        let mut slot=self.original.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if slot.is_some()||!super::route()||q.case!=ShellCase::GitHubPreflight(self.case)||q.failed.load(Ordering::SeqCst)
            ||!q.preflight.as_ref().is_some_and(|c|std::ptr::eq(c.as_ref(),self)){return Err(BridgeError::invalid());}
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
        if r.preflight.as_ref().is_none_or(|old|old.revision<=status.revision){r.preflight=Some(status.clone());}
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
                    // Admission/revocation reply, NOT full removal: the real
                    // writer must run its final claim before retirement can end.
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
        if command=="github_preflight_status" {
            if matches!(step,ShellStep::GitHubPreflight(Step::Status|Step::ReadStatus)) {
                if r.explicit_status{self.fail();return;}r.explicit_status=true;
            }
            return;
        }
        if command=="github_preflight_cancel" {
            if self.case!=Case::FinalityRefusal||r.cancel!=0||r.actions.len()!=2
                ||!matches!(step,ShellStep::GitHubPreflight(Step::Cancel|Step::Unknown))
                ||!status.operation.as_ref().is_some_and(|o|Some(&o.id)==r.actions.last()&&o.kind==wire::Kind::Dispatch
                    &&o.phase==wire::Phase::Running&&o.reason==wire::Reason::Cancelled){self.fail();return;}
            let id=status.operation.as_ref().unwrap().id.clone();r.cancel=1;drop(r);drop(shell);
            if self.product.cancelled(&id).is_err(){self.fail();}return;
        }
        let Some(expected)=expected_action(self.case,r.actions.len()) else{self.fail();return;};
        let Some(operation)=status.operation.as_ref() else{self.fail();return;};
        if command!=expected.0||operation.kind!=expected.1||operation.phase!=wire::Phase::Running||operation.reason!=wire::Reason::None
            ||!expected.2.iter().any(|expected|step==ShellStep::GitHubPreflight(*expected))
            ||r.session_id!=status.session_id||r.actions.contains(&operation.id){self.fail();return;}
        r.actions.push(operation.id.clone());
    }
    pub(super) async fn relay(&self,app:&tauri::AppHandle) {
        let Some(q)=self.original() else{self.fail();return;};if q.failed.load(Ordering::SeqCst){self.fail();return;}
        let step=match q.record(){Some(r)=>r.step,None=>return};
        if step==ShellStep::GitHubPreflight(Step::Connect) {
            let start=match self.record(){Some(mut r) if !r.setup_claimed=>{r.setup_claimed=true;true},_=>false};
            if start {
                let Some(root)=super::control_root() else{self.fail();return;};
                let mut peer=self.peer.lock().await;
                if peer.prepare(root,q.end).is_err()||peer.start().await.is_err(){self.fail();return;}
                if let Some(mut r)=self.record(){r.peer_ready=true;}
            }
        }
        if self.product.observe_retired(q.end).await.is_err(){self.fail();}
        let _=app; // The same existing relay owns this borrow and its return.
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
        let Some(status)=r.preflight.as_ref() else{return !matches!(step,Step::Configured|Step::Prepared|Step::Dispatched|Step::ReadPending|Step::ObservedRun|Step::ReadStatus|Step::Disconnected
            |Step::ReadyToRevoke|Step::Refused|Step::Cancel|Step::Unknown|Step::LateRetired);};
        let state=app.state::<super::super::ShellState>();
        match step {
            Step::Configured=>status.available&&status.session_id==r.session_id,
            Step::Prepared=>r.actions.len()==usize::from(r.reviews)*2+1&&status.operation.as_ref().is_some_and(|o|o.kind==wire::Kind::Prepare&&o.phase==wire::Phase::Settled
                &&o.reason==wire::Reason::None)&&status.prepared.as_ref().is_some_and(wire::Prepared::publisher_bound)&&self.product.evidence().len()==r.actions.len()+1,
            Step::Dispatched=>r.actions.len()==2
                &&status.operation.as_ref().is_some_and(|o|o.kind==wire::Kind::Dispatch&&o.phase==wire::Phase::Settled)
                &&status.pending.len()==1&&self.product.evidence().len()==r.actions.len()+1,
            Step::Refused=>matches!(self.case,Case::PreGoRevocation|Case::JournalCollision)&&r.actions.len()==self.case.action_count()
                &&status.operation.as_ref().is_some_and(|o|o.kind==wire::Kind::Dispatch&&o.phase==wire::Phase::Settled&&o.effect==wire::Effect::NotSent)
                &&status.pending.len()==(if self.case==Case::PreGoRevocation{0}else{1})&&self.product.evidence().len()==r.actions.len()+1,
            Step::ReadyToRevoke=>self.case==Case::PreGoRevocation&&r.actions.len()==2&&self.product.ready_held()
                &&status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::Running&&o.effect==wire::Effect::NotSent),
            Step::Cancel=>self.case==Case::FinalityRefusal&&r.actions.len()==2&&self.product.settlement_waiting()
                &&status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::Running&&o.kind==wire::Kind::Dispatch),
            Step::Unknown=>self.case==Case::FinalityRefusal&&r.cancel==1&&self.product.unknown_seen()
                &&status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::CleanupUnknown&&o.reason==wire::Reason::CleanupUnknown),
            Step::LateRetired=>self.case==Case::FinalityRefusal&&r.unknown_dom
                &&self.product.complete(&state.bridge.supervisor)
                &&r.unknown_snapshot.as_ref().is_some_and(|initial|late_unknown_data(initial,status,r.prepared.as_ref())),
            Step::ReadPending=>self.case==Case::ResponseLoss&&r.actions.len()==3
                &&status.operation.as_ref().is_some_and(|o|o.kind==wire::Kind::Pending&&o.phase==wire::Phase::Settled
                    &&o.reason==wire::Reason::None&&o.effect==wire::Effect::None)
                &&status.pending.len()==1&&status.pending[0].run_id.is_none()
                &&Some(&status.pending[0].prepared)==r.prepared.as_ref()&&self.product.evidence().len()==4,
            Step::ObservedRun=>r.actions.len()==self.case.action_count()&&status.operation.as_ref().is_some_and(|o|o.kind==self.case.final_kind()&&o.phase==wire::Phase::Settled
                &&o.reason==wire::Reason::None)&&status.run.is_some()&&self.product.complete(&state.bridge.supervisor),
            Step::ReadStatus=>r.explicit_status,
            Step::Disconnected=>r.disconnect==1&&read.session.is_none()&&read.operation.is_none()
                &&r.retirement_before.as_ref().is_some_and(|before|retired_data(before,status))
                &&self.product.complete(&state.bridge.supervisor),
            _=>true,
        }
    }
    pub(super) fn dom(&self,step:Step,value:&Value) {
        let Some(q)=self.original() else{self.fail();return;};let Some(mut shell)=q.record_at(Boundary::Dom) else{return;};
        if shell.step!=ShellStep::GitHubPreflight(step)||shell.pending.take()!=Some(Pending::Dom(ShellStep::GitHubPreflight(step))) {self.fail();return;}
        if step==Step::ReloadGuidance&&!shell.github_guidance.click_returned(value){self.fail();return;}
        let Some(object)=value.as_object() else{self.fail();return;};
        if value["state"]=="wait" {
            if object.len()!=1 && !(step==Step::Entry&&object.len()==9) {self.fail();} return;
        }
        if value["state"]!="ready"{self.fail();return;}
        let Some(mut r)=self.record() else{return;};
        let next=match step {
            Step::Navigate=>Step::ReadGuidanceReload,Step::ReadGuidanceReload=>Step::ReloadGuidance,Step::ReloadGuidance=>Step::EnterRepository,
            Step::EnterRepository=>Step::Entry,
            Step::Entry=>{if object.len()!=9||value["entryAvailable"]!=true||value["helpPresent"]!=true{self.fail();return;}Step::EnterToken},
            Step::EnterToken=>Step::Token,Step::Token=>{if object.len()!=2||value["supplied"]!=true{self.fail();return;}Step::Connect},
            Step::Connect=>Step::Connected,
            Step::Connected=>{if object.len()!=2||value["tokenEmpty"]!=true{self.fail();return;}r.token_cleared=true;Step::Configure},
            Step::Configure=>Step::Configured,
            Step::Configured=>{if object.len()!=4||value["branch"]!="main"||value["platform"]!="android"||value["help"]!=true{self.fail();return;}Step::Prepare},
            Step::Prepare=>Step::Prepared,
            Step::Prepared=>{
                let Some(status)=r.preflight.as_ref() else{self.fail();return;};let Some(prepared)=status.prepared.as_ref() else{self.fail();return;};
                if !review_matches(value,prepared)||r.reviews>0&&(self.case!=Case::JournalCollision||r.reviews!=1
                    ||!r.prepared.as_ref().is_some_and(|first|first.target==prepared.target)){self.fail();return;}
                let prepared=prepared.clone();if r.prepared.is_none(){r.prepared=Some(prepared);}
                r.reviews+=1;r.review_visible=true;Step::Confirm
            },
            Step::Confirm=>{if object.len()!=2||value["confirmed"]!=true||r.consents+1!=r.reviews{self.fail();return;}
                r.consents+=1;r.confirmed=true;Step::Dispatch},
            Step::Dispatch=>match self.case{Case::PreGoRevocation=>Step::ReadyToRevoke,Case::FinalityRefusal=>Step::Cancel,
                Case::JournalCollision if r.reviews==2=>Step::Refused,_=>Step::Dispatched},
            Step::ReadyToRevoke=>{
                let Some(status)=r.preflight.as_ref() else{self.fail();return;};
                if object.len()!=3||value["operationId"]!=status.operation.as_ref().map(|o|o.id.as_str()).unwrap_or("")
                    ||value["notSent"]!=true||!self.product.ready_held(){self.fail();return;}Step::Disconnect
            },
            Step::Cancel=>{if object.len()!=1||self.case!=Case::FinalityRefusal{self.fail();return;}Step::Unknown},
            Step::Unknown|Step::LateRetired=>{
                let Some(status)=r.preflight.as_ref() else{self.fail();return;};
                let shown=if step==Step::Unknown{Some(status)}else{r.unknown_snapshot.as_ref()};
                if self.case!=Case::FinalityRefusal||!shown.is_some_and(|shown|negative_dom(value,shown,true))
                    ||(if step==Step::Unknown{!unknown_data(status,None)}else{
                        !r.unknown_snapshot.as_ref().is_some_and(|initial|late_unknown_data(initial,status,r.prepared.as_ref()))}) {self.fail();return;}
                if step==Step::Unknown {
                    if r.unknown_dom||!self.product.unknown_seen(){self.fail();return;}
                    let snapshot=status.clone();r.unknown_snapshot=Some(snapshot);r.unknown_dom=true;
                    drop(r);drop(shell);
                    if self.product.release_after_unknown_dom().is_err(){self.fail();return;}
                    let Some(mut shell)=q.record_at(Boundary::Dom) else{return;};
                    shell.step=ShellStep::GitHubPreflight(Step::LateRetired);return;
                }
                r.late_retired=true;r.dispatch_effect=Some(wire::Effect::PotentiallyApplied);r.dispatch_reason=Some(wire::Reason::CleanupUnknown);Step::Status
            },
            Step::Dispatched|Step::Refused=>{
                let Some(status)=r.preflight.as_ref() else{self.fail();return;};let Some(op)=status.operation.as_ref() else{self.fail();return;};
                if step==Step::Refused {
                    let originals=self.product.evidence();let last=originals.last();
                    if !negative_dom(value,status,false)||op.effect!=wire::Effect::NotSent
                        ||!last.is_some_and(|v|v["negative"]==true&&v["operationId"]==op.id&&v["reason"]==json!(op.reason)&&v["effect"]==json!(op.effect))
                        ||status.prepared.is_some()||status.consent_expires_at.is_some()||status.run.is_some()
                        ||(if self.case==Case::PreGoRevocation{op.reason!=wire::Reason::Cancelled||!status.pending.is_empty()}
                          else{self.case!=Case::JournalCollision||status.pending.len()!=1||Some(&status.pending[0].prepared)!=r.prepared.as_ref()||status.pending[0].run_id.as_deref()!=Some("9001")})
                        {self.fail();return;}
                    let (effect,reason)=(op.effect,op.reason);r.dispatch_effect=Some(effect);r.dispatch_reason=Some(reason);
                    shell.step=ShellStep::GitHubPreflight(Step::Status);return;
                }
                let effect=if self.case==Case::ResponseLoss{wire::Effect::PotentiallyApplied}else{wire::Effect::Accepted};
                let reason=if self.case==Case::ResponseLoss{wire::Reason::TlsFailed}else{wire::Reason::None};
                if object.len()!=5||value["operationId"]!=op.id||value["effect"]!=json!(effect)||value["noSecondDispatch"]!=true
                    ||value["observeReady"]!=true||op.effect!=effect||op.reason!=reason||status.pending.len()!=1
                    ||Some(&status.pending[0].prepared)!=r.prepared.as_ref()
                    ||status.pending[0].run_id.as_deref()!=(if self.case==Case::ResponseLoss{None}else{Some("9001")}){self.fail();return;}
                r.dispatch_effect=Some(effect);r.dispatch_reason=Some(reason);
                if self.case==Case::JournalCollision{Step::Configure}else if self.case==Case::ResponseLoss {Step::ReloadPending} else {Step::ObserveRun}
            },
            Step::ReloadPending=>{
                if self.case!=Case::ResponseLoss||r.pending_reloaded {self.fail();return;}
                Step::ReadPending
            },
            Step::ReadPending=>{
                let Some(status)=r.preflight.as_ref() else{self.fail();return;};
                let Some(op)=status.operation.as_ref() else{self.fail();return;};
                let Some(prepared)=r.prepared.as_ref() else{self.fail();return;};
                if self.case!=Case::ResponseLoss||r.pending_reloaded||object.len()!=5
                    ||op.kind!=wire::Kind::Pending||op.phase!=wire::Phase::Settled||op.reason!=wire::Reason::None||op.effect!=wire::Effect::None
                    ||value["operationId"]!=op.id||Some(&op.id)!=r.actions.get(2)
                    ||value["codes"]!=json!([prepared.source_sha,prepared.display_title])||value["unresolved"]!=true||value["reconcileReady"]!=true
                    ||status.pending.len()!=1||status.pending[0].prepared!=*prepared||status.pending[0].run_id.is_some()
                    ||self.product.evidence().len()!=4{self.fail();return;}
                r.pending_reloaded=true;Step::ObserveRun
            },
            Step::ObserveRun=>Step::ObservedRun,
            Step::ObservedRun=>{
                let Some(status)=r.preflight.as_ref() else{self.fail();return;};let Some(run)=status.run.as_ref() else{self.fail();return;};
                if object.len()!=5||value["operationId"]!=status.operation.as_ref().map(|o|o.id.as_str()).unwrap_or("")
                    ||value["runId"]!="9001"||value["jobs"]!=json!(["input-guard: completed · success · job 9101","android: completed · success · job 9102"])
                    ||value["notReleaseEvidence"]!=true||run.id!="9001"||run.conclusion!=Some(wire::Conclusion::Success)
                    ||status.pending.len()!=1||status.pending[0].run_id.as_deref()!=Some("9001"){self.fail();return;}
                r.run_observed=true;Step::Status
            },
            Step::Status=>Step::ReadStatus,
            Step::ReadStatus=>{
                let Some(status)=r.preflight.as_ref() else{self.fail();return;};
                let shown=if self.case==Case::FinalityRefusal{r.unknown_snapshot.as_ref()}else{Some(status)};
                if !r.explicit_status||(if self.case.negative(){!shown.is_some_and(|shown|negative_dom(value,shown,self.case==Case::FinalityRefusal))}
                    else{object.len()!=2||value["runId"]!="9001"}){self.fail();return;}
                if self.case==Case::FinalityRefusal {
                    if !r.late_retired||!r.unknown_snapshot.as_ref().is_some_and(|initial|late_unknown_data(initial,status,r.prepared.as_ref())){self.fail();return;}
                    r.close_ready=true;shell.step=ShellStep::Close;return;
                }
                r.retirement_before=Some(status.clone());if r.disconnect==1{Step::Disconnected}else{Step::Disconnect}
            },
            Step::Disconnect=>if self.case==Case::PreGoRevocation{Step::Refused}else{Step::Disconnected},
            Step::Disconnected=>{
                let Some(status)=r.preflight.as_ref() else{self.fail();return;};
                if !r.retirement_before.as_ref().is_some_and(|before|retired_data(before,status))||!retired_dom(value,status){self.fail();return;}
                r.retired_without_authority=true;r.close_ready=true;shell.step=ShellStep::Close;return;
            },
        };
        if matches!(step,Step::Navigate|Step::ReadGuidanceReload|Step::ReloadGuidance|Step::EnterRepository|Step::EnterToken|Step::Connect
            |Step::Configure|Step::Prepare|Step::Dispatch|Step::ReloadPending|Step::ObserveRun|Step::Status|Step::Disconnect|Step::Cancel)&&object.len()!=1 {self.fail();return;}
        shell.step=ShellStep::GitHubPreflight(next);
    }
    pub(super) fn ready_to_close(&self)->bool {!self.failed.load(Ordering::SeqCst)&&self.record().is_some_and(|r|r.close_ready)}
    pub(super) async fn settle_for_exit(&self,app:&tauri::AppHandle)->bool {
        let Some(q)=self.original() else{self.fail();return false;};let state=app.state::<super::super::ShellState>();
        // can_exit includes actual accepted Quit; never use it to gate the
        // pre-Quit Disconnected/LateRetired UI steps (that would deadlock).
        if !state.document.can_exit(){return false;}if self.record().is_some_and(|r|r.physical_final){return true;}
        let product=self.product.observe_retired(q.end).await.is_ok_and(|final_seen|final_seen&&self.product.complete(&state.bridge.supervisor));
        let success=product&&!q.failed.load(Ordering::SeqCst)&&self.ready_to_close();
        let mut peer=self.peer.lock().await;let physical=peer.settle(success,q.end).await;
        let checked=success&&physical&&self.product.marker().is_some_and(|marker|peer.validate(&marker).is_ok());
        if !checked{self.fail();}let Some(mut r)=self.record() else{return false;};
        r.physical_final=physical;r.final_checked=checked;if checked{r.peer_receipt=Some(peer.evidence());}physical
    }
    pub(super) fn complete(&self)->bool {
        !self.failed.load(Ordering::SeqCst)&&self.record().is_some_and(|r|r.attached&&r.setup_claimed&&r.peer_ready&&r.connect==1
            &&r.disconnect==u8::from(self.case!=Case::FinalityRefusal)
            &&r.actions.len()==self.case.action_count()&&r.pending_reloaded==(self.case==Case::ResponseLoss)
            &&r.reviews==(if self.case==Case::JournalCollision{2}else{1})&&r.consents==r.reviews
            &&r.explicit_status&&r.token_cleared&&r.review_visible&&r.confirmed&&r.run_observed==!self.case.negative()
            &&(if self.case==Case::FinalityRefusal{r.unknown_dom&&r.late_retired&&r.cancel==1}else{r.retired_without_authority&&r.cancel==0})&&r.close_ready
            &&r.physical_final&&r.final_checked&&r.peer_receipt.is_some()
            &&self.product.evidence().iter().skip(1).zip(&r.actions).all(|(original,id)|original["operationId"].as_str()==Some(id.as_str())))
    }
    pub(super) fn report(&self)->Option<Vec<u8>> {
        if !self.complete(){return None;}let q=self.original()?;let shell=q.record()?;let r=self.record()?;
        if !shell.exit||!shell.originals_final||!shell.relay_joined||!shell.github_guidance.complete(){return None;}
        serde_json::to_vec(&json!({"schemaVersion":1,"fixture":if self.case.negative(){"github-preflight-installed-negative-v1"}else{"github-preflight-installed-v2"},"case":self.case.name(),
            "sourceCommit":option_env!("GITHUB_SHA")?,"normalManifestSha256":crate::runtime::PassiveInstalledProfile::MANIFEST,
            "productManifestSha256":RuntimeProfile::MANIFEST,"protocolSha256":"083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5",
            "toolingSha":RuntimeProfile::TOOLING_SHA,"callerSha256":RuntimeProfile::CALLER_SHA256,"peerSha256":peer_sha256(),
            "project":{"cancelSettled":shell.cancelled&&shell.pickers[0].settled(false),"registered":shell.selected&&shell.pickers[1].settled(true)
                &&shell.project_witness.is_some(),"snapshot":shell.snapshot&&shell.snapshot_visible},
            "nativeSession":{"connect":r.connect,"prepare":r.reviews,"dispatch":r.consents,"observe":usize::from(!self.case.negative()),"disconnect":r.disconnect,"retainedStatus":r.explicit_status,
                "pending":if self.case==Case::ResponseLoss{1}else{0},"pendingReloaded":r.pending_reloaded,
                "tokenFieldCleared":r.token_cleared,"reviewVisible":r.review_visible,"consentObserved":r.confirmed,
                "dispatchEffect":r.dispatch_effect,"dispatchReason":r.dispatch_reason,"runObserved":r.run_observed,
                "retirement":if self.case==Case::FinalityRefusal{json!({"mode":"late-unknown","unknownPreserved":r.unknown_dom&&r.late_retired,"newWorkDenied":true,
                    "initialDisplayedPending":0,"lateNativeRecoveryRetained":r.late_retired,"lateDisplayedPending":0})}
                    else{json!({"mode":"disconnected","authorityRemoved":r.retired_without_authority,"terminalPreserved":r.retired_without_authority,"recoveryPreserved":r.retired_without_authority})}},
            "scheduling":self.product.timeline(),
            "originals":self.product.evidence(),"peer":r.peer_receipt,"quit":{"originalsFinal":shell.originals_final,"relayJoined":shell.relay_joined,
                "gtkSettled":shell.gtk_returned&&shell.destroyed&&shell.released,"exit":shell.exit},
            "notProven":["real-github-api-dispatch","real-github-job-names","macos-github-preflight","windows-github-preflight","kernel-close-error-injection"]
        })).ok().filter(|raw|raw.len()<=32768)
    }
}
fn retired_data(before:&wire::Status,after:&wire::Status)->bool {
    before.session_id.is_some()&&before.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::Settled)
        &&after.session_id==before.session_id&&after.operation==before.operation&&after.pending==before.pending&&after.run==before.run
        &&!after.available&&after.reason==wire::Reason::NotConnected&&after.prepared.is_none()&&after.consent_expires_at.is_none()
}
fn unknown_data(status:&wire::Status,late_record:Option<&wire::Prepared>)->bool {
    status.session_id.is_some()&&!status.available&&status.reason==wire::Reason::CleanupUnknown
        &&status.prepared.is_none()&&status.consent_expires_at.is_none()&&status.run.is_none()
        &&(if let Some(first)=late_record{status.pending.len()==1&&status.pending[0].prepared==*first&&status.pending[0].run_id.is_none()}
            else{status.pending.is_empty()})
        &&status.operation.as_ref().is_some_and(|o|o.kind==wire::Kind::Dispatch&&o.phase==wire::Phase::CleanupUnknown
            &&o.reason==wire::Reason::CleanupUnknown&&o.effect==wire::Effect::PotentiallyApplied)
}
fn late_unknown_data(initial:&wire::Status,late:&wire::Status,first:Option<&wire::Prepared>)->bool {
    first.is_some()&&unknown_data(initial,None)&&unknown_data(late,first)&&initial.operation==late.operation
        &&initial.session_id==late.session_id&&initial.revision<late.revision
}
fn records_dom(value:&Value,status:&wire::Status)->bool {
    value.as_array().is_some_and(|rows|rows.len()==status.pending.len()&&rows.iter().zip(&status.pending).all(|(row,record)|
        super::keys(row,&["codes","text"])&&row["codes"]==json!([record.prepared.source_sha,record.prepared.display_title])
            &&row["text"].as_str().is_some_and(|text|text.starts_with(&format!("{} · {} · {}",record.prepared.target.repository,record.prepared.target.branch,record.prepared.target.platform.text()))
                &&text.contains(&format!("Run {} · original attempt 1 only.",record.run_id.as_deref().unwrap_or("not yet resolved"))))))
}
fn negative_help(reason:wire::Reason)->Option<&'static str> {Some(match reason {
    wire::Reason::Cancelled=>"The local action was stopped. A workflow already accepted by GitHub may still be running.",
    wire::Reason::CleanupUnknown=>"Original cleanup is unconfirmed. Keep the application open; no new work is authorized by a late response.",
    wire::Reason::NetworkUnavailable=>"The bounded operation did not complete. A dispatch may have applied; check its exact intent rather than repeating it.",
    wire::Reason::ResponseInvalid=>"The response did not match the closed protocol. Keep any pending intent; no successful result or automatic retry was inferred.",
    _=>return None,
})}
fn negative_dom(value:&Value,status:&wire::Status,unknown:bool)->bool {
    let Some(op)=status.operation.as_ref() else{return false;};
    super::keys(value,&["state","operationId","effect","message","noSecondDispatch","noRun","records","newWorkDenied"])
        &&value["state"]=="ready"&&value["operationId"]==op.id&&value["effect"]==json!(op.effect)
        &&op.phase==(if unknown{wire::Phase::CleanupUnknown}else{wire::Phase::Settled})
        &&value["message"].as_str().is_some_and(|message|negative_help(op.reason).is_some_and(|help|message.ends_with(help)))
        &&value["noSecondDispatch"]==true&&value["noRun"]==true&&records_dom(&value["records"],status)
        &&(if unknown{value["newWorkDenied"]==true}else{value["newWorkDenied"].is_boolean()})
}
fn retired_dom(value:&Value,status:&wire::Status)->bool {
    let Some(op)=status.operation.as_ref() else{return false;};
    let run=status.run.as_ref().map(|run|json!({"title":format!("Run {} · attempt 1",run.id),
        "jobs":["input-guard: completed · success · job 9101","android: completed · success · job 9102"],"url":run.url}));
    super::keys(value,&["state","operationId","effect","records","run","noReview","tokenEmpty","selectionEmpty","actionsDisabled"])
        &&value["state"]=="ready"&&value["operationId"]==op.id
        &&value["effect"]==(if op.kind==wire::Kind::Dispatch{json!(op.effect)}else{Value::Null})
        &&records_dom(&value["records"],status)&&value["run"]==json!(run)
        &&["noReview","tokenEmpty","selectionEmpty","actionsDisabled"].iter().all(|key|value[*key]==true)
}
fn review_matches(value:&Value,prepared:&wire::Prepared)->bool {
    super::keys(value,&["state","codes","confirmation","unchecked","dispatchDisabled","help"])
        &&value["state"]=="ready"&&value["codes"]==json!([prepared.target.repository_id,prepared.target.account_id,prepared.expected_ref,
            prepared.source_sha,prepared.target.tooling_sha,prepared.workflow_path,prepared.caller_sha256,prepared.display_title])
        &&value["confirmation"]==prepared.confirmation&&value["unchecked"]==true&&value["dispatchDisabled"]==true&&value["help"]==true
}
// Translate only this exact original preflight reservation into the already
// checked one-use guidance lifecycle; cross-family callbacks remain refused.
pub(super) fn guidance_reload_scope(step:ShellStep,pending:Option<Pending>,live:bool)->github::GuidanceReloadScope {
    if !live { return github::GuidanceReloadScope::Outside; }
    match (step,pending) {
        (ShellStep::GitHubPreflight(Step::ReloadGuidance),Some(Pending::Dom(ShellStep::GitHubPreflight(Step::ReloadGuidance))))
            =>github::GuidanceReloadScope::ClickPending,
        (ShellStep::GitHubPreflight(Step::EnterRepository),None)=>github::GuidanceReloadScope::AwaitReplies,
        _=>github::GuidanceReloadScope::Outside,
    }
}
pub(super) fn assert_contracts() {
    use github::GuidanceReloadScope::{ClickPending,AwaitReplies,Outside};
    let click=ShellStep::GitHubPreflight(Step::ReloadGuidance);
    let replies=ShellStep::GitHubPreflight(Step::EnterRepository);
    assert!(guidance_reload_scope(click,Some(Pending::Dom(click)),true)==ClickPending);
    assert!(guidance_reload_scope(replies,None,true)==AwaitReplies);
    for (step,pending,live) in [(click,None,true),(click,Some(Pending::Dom(replies)),true),
        (replies,Some(Pending::Dom(replies)),true),(click,Some(Pending::Dom(click)),false),(replies,None,false),
        (ShellStep::GitHubReadOnly(github::Step::ReloadGuidance),Some(Pending::Dom(click)),true),
        (ShellStep::GitHubReadOnly(github::Step::EnterRepository),None,true)] {
        assert!(guidance_reload_scope(step,pending,live)==Outside);
    }
    assert!(github::guidance_reload_scope(click,Some(Pending::Dom(click)),true)==Outside);
    assert!(github::guidance_reload_scope(replies,None,true)==Outside);
    for case in Case::ALL {
        for index in 0..case.action_count() {
            let (_,kind,steps)=expected_action(case,index).unwrap();
            assert_eq!(Some(kind),case.kind(index+1));
            if kind==wire::Kind::Pending {assert!(case==Case::ResponseLoss&&steps==[Step::ReloadPending,Step::ReadPending]);}
            else {assert!(steps.iter().all(|step|!matches!(step,Step::ReloadPending|Step::ReadPending)));}
        }
        assert!(expected_action(case,case.action_count()).is_none());assert!(expected_action(case,usize::MAX).is_none());
    }
    assert!(expected_action(Case::JournalCollision,1).unwrap().2==[Step::Dispatch,Step::Dispatched]);
    assert!(expected_action(Case::JournalCollision,3).unwrap().2==[Step::Dispatch,Step::Refused]);
    assert!(expected_action(Case::PreGoRevocation,1).unwrap().2==[Step::Dispatch,Step::ReadyToRevoke]);
    assert!(expected_action(Case::FinalityRefusal,1).unwrap().2==[Step::Dispatch,Step::Cancel]);
    // Supplied DATA for preservation/refusal, not a native receipt or grant.
    let target=wire::Target {project_binding:"b".repeat(64),repository:"owner/app".into(),account_id:"11".into(),repository_id:"22".into(),
        branch:"main".into(),tooling_repository:wire::TOOLING_REPOSITORY.into(),tooling_sha:RuntimeProfile::TOOLING_SHA.into(),
        platform:wire::Platform::Android,marker:"e".repeat(32)};
    let prepared=wire::Prepared {expected_ref:target.full_ref(),display_title:target.title(),target,source_sha:"a".repeat(40),
        workflow_id:"101".into(),workflow_path:wire::WORKFLOW_PATH.into(),caller_sha256:RuntimeProfile::CALLER_SHA256.into(),
        observed_at:"2026-09-27T01:00:00Z".into(),confirmation:format!(
            "Run credential-free android preflight for owner/app at {}? This may build project code, download dependencies, use GitHub-hosted minutes and upload diagnostic reports. The reviewed canonical workflow does not sign, upload to a Store or publish a release. GitHub dispatch uses this mutable branch, not an atomic commit lock. Authorized writers can replace its workflow after review; use a trusted protected branch.","a".repeat(40))};
    assert!(prepared.valid());
    let run=wire::Run {id:"9001".into(),attempt:1,status:wire::RunStatus::Completed,conclusion:Some(wire::Conclusion::Success),
        observed_at:"2026-09-27T01:00:01Z".into(),assurance:wire::ASSURANCE.into(),url:"https://github.com/owner/app/actions/runs/9001".into(),
        jobs:[("9101",wire::JobKind::InputGuard),("9102",wire::JobKind::Android)].map(|(id,kind)|wire::Job {
            id:id.into(),kind,status:wire::RunStatus::Completed,conclusion:Some(wire::Conclusion::Success)}).to_vec()};
    assert!(run.valid(&prepared));
    let before=wire::Status {schema_version:1,revision:10,session_id:Some("github-session-1".into()),available:true,reason:wire::Reason::None,
        operation:Some(wire::Operation{id:"native-operation-3".into(),kind:wire::Kind::Track,phase:wire::Phase::Settled,reason:wire::Reason::None,effect:wire::Effect::None}),
        prepared:None,consent_expires_at:None,pending:vec![wire::PendingRecord{prepared:prepared.clone(),run_id:Some("9001".into())}],run:Some(run)};
    let mut retired=before.clone();retired.revision+=1;retired.available=false;retired.reason=wire::Reason::NotConnected;
    assert!(retired_data(&before,&retired));
    let mut erased=retired.clone();erased.pending.clear();assert!(!retired_data(&before,&erased));
    erased=retired.clone();erased.run=None;assert!(!retired_data(&before,&erased));
    erased=retired.clone();erased.operation=None;assert!(!retired_data(&before,&erased));
    erased=retired.clone();erased.session_id=None;assert!(!retired_data(&before,&erased));
    erased=retired.clone();erased.pending[0].prepared.observed_at="2026-09-27T01:00:02Z".into();assert!(!retired_data(&before,&erased));
    erased=retired.clone();erased.available=true;assert!(!retired_data(&before,&erased));
    erased=retired.clone();erased.prepared=Some(prepared.clone());assert!(!retired_data(&before,&erased));
    erased=retired.clone();erased.consent_expires_at=Some("2026-09-27T01:00:02Z".into());assert!(!retired_data(&before,&erased));
    let records=json!([{"codes":[prepared.source_sha,prepared.display_title],"text":"owner/app · main · android Run 9001 · original attempt 1 only."}]);
    let visible=json!({"state":"ready","operationId":"native-operation-3","effect":null,"records":records,
        "run":{"title":"Run 9001 · attempt 1","jobs":["input-guard: completed · success · job 9101","android: completed · success · job 9102"],
            "url":"https://github.com/owner/app/actions/runs/9001"},"noReview":true,"tokenEmpty":true,"selectionEmpty":true,"actionsDisabled":true});
    assert!(retired_dom(&visible,&retired));
    for (key,value) in [("records",json!([])),("run",Value::Null),("operationId",json!("another-original")),
        ("effect",json!("accepted")),("noReview",json!(false)),("tokenEmpty",json!(false)),("selectionEmpty",json!(false)),("actionsDisabled",json!(false))] {
        let mut changed=visible.clone();changed[key]=value;assert!(!retired_dom(&changed,&retired));
    }
    let mut unknown=before.clone();unknown.available=false;unknown.reason=wire::Reason::CleanupUnknown;unknown.run=None;unknown.pending.clear();
    unknown.operation=Some(wire::Operation{id:"native-operation-2".into(),kind:wire::Kind::Dispatch,phase:wire::Phase::CleanupUnknown,
        reason:wire::Reason::CleanupUnknown,effect:wire::Effect::PotentiallyApplied});
    assert!(unknown_data(&unknown,None));assert!(!unknown_data(&unknown,Some(&prepared)));
    let mut late=unknown.clone();late.revision+=1;late.pending.push(wire::PendingRecord{prepared:prepared.clone(),run_id:None});
    assert!(late_unknown_data(&unknown,&late,Some(&prepared)));assert!(!late_unknown_data(&unknown,&unknown,Some(&prepared)));
    let mut changed=late.clone();changed.pending[0].run_id=Some("9001".into());assert!(!late_unknown_data(&unknown,&changed,Some(&prepared)));
    changed=late.clone();changed.operation.as_mut().unwrap().effect=wire::Effect::Accepted;assert!(!late_unknown_data(&unknown,&changed,Some(&prepared)));
    changed=late.clone();changed.operation.as_mut().unwrap().id="another-original".into();assert!(!late_unknown_data(&unknown,&changed,Some(&prepared)));
    let hidden=json!({"state":"ready","operationId":"native-operation-2","effect":"potentially-applied",
        "message":format!("dispatch · cleanup-unknown Original action native-operation-2. Submission: potentially-applied. {}",negative_help(wire::Reason::CleanupUnknown).unwrap()),
        "noSecondDispatch":true,"noRun":true,"records":[],"newWorkDenied":true});
    assert!(negative_dom(&hidden,&unknown,true));assert!(!negative_dom(&hidden,&late,true));assert!(!negative_dom(&hidden,&unknown,false));
    for (key,value) in [("newWorkDenied",json!(false)),("noSecondDispatch",json!(false)),("noRun",json!(false)),
        ("effect",json!("accepted")),("message",json!("Done")),("operationId",json!("another-original")),("records",records)] {
        let mut changed=hidden.clone();changed[key]=value;assert!(!negative_dom(&changed,&unknown,true));
    }
    let mut refused=unknown.clone();let op=refused.operation.as_mut().unwrap();op.phase=wire::Phase::Settled;op.reason=wire::Reason::Cancelled;op.effect=wire::Effect::NotSent;
    refused.reason=wire::Reason::NotConnected;let mut view=hidden.clone();view["effect"]=json!("not-sent");view["message"]=json!(negative_help(wire::Reason::Cancelled).unwrap());
    assert!(negative_dom(&view,&refused,false));assert!(!negative_dom(&view,&refused,true));
    let mut review=json!({"state":"ready","codes":[prepared.target.repository_id,prepared.target.account_id,prepared.expected_ref,
        prepared.source_sha,prepared.target.tooling_sha,prepared.workflow_path,prepared.caller_sha256,prepared.display_title],
        "confirmation":prepared.confirmation,"unchecked":true,"dispatchDisabled":true,"help":true});
    assert!(review_matches(&review,&prepared));review["dispatchDisabled"]=json!(false);assert!(!review_matches(&review,&prepared));
    crate::supervisor::github_preflight_native_observation::assert_contracts();
}
pub(super) fn script(step:Step,case:Case)->Option<String> {
    if let Some(shared)=step.shared(){return github::script(shared);}
    let observe=if case==Case::ResponseLoss{"Reconcile exact request · read GitHub"}else{"Track this run · read GitHub"};
    let dispatch_effect=if case==Case::ResponseLoss{"potentially-applied"}else{"accepted"};
    let body=match step {
        Step::Connected=>r#"const c=connection(),token=c?.querySelector('input[type="password"]');if(!c)return {state:'wait'};
            return {state:'ready',tokenEmpty:!token||token.value===''};"#,
        Step::Configure=>r#"const c=card(),branch=c?.querySelector('input[placeholder="main or release/next"]'),platform=c?.querySelector('select');
            if(!branch||!platform||branch.disabled||platform.disabled)return {state:'wait'};edit(branch,'main');show(platform);
            Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(platform,'android');platform.dispatchEvent(new Event('change',{bubbles:true}));return {state:'ready'};"#,
        Step::Configured=>r#"const c=card(),branch=c?.querySelector('input[placeholder="main or release/next"]'),platform=c?.querySelector('select'),b=button('Prepare workflow review · read only');
            if(!c||!branch||!platform||!b||b.disabled)return {state:'wait'};show(c);return {state:'ready',branch:branch.value,platform:platform.value,
                help:['Application branch','Platforms to check','GitHub preflight access'].every(label=>c.querySelector(`button[aria-label="Help: ${label}"]`))};"#,
        Step::Prepare=>r#"return click('Prepare workflow review · read only');"#,
        Step::Prepared=>r#"const c=card()?.querySelector('[aria-label="Exact workflow review"]');if(!c)return {state:'wait'};show(c);
            const p=[...c.querySelectorAll(':scope > p:not(.save-note)')],check=c.querySelector('input[type="checkbox"]'),b=button('Dispatch this preflight once');
            if(p.length!==1||!check||!b)throw 0;return {state:'ready',codes:[...c.querySelectorAll('dl code')].map(text),confirmation:text(p[0]),
                unchecked:!check.checked,dispatchDisabled:b.disabled,help:!!c.querySelector('button[aria-label="Help: One-use workflow confirmation"]')};"#,
        Step::Confirm=>r#"const c=card()?.querySelector('[aria-label="Exact workflow review"]'),check=c?.querySelector('input[type="checkbox"]');
            if(!check||check.disabled)return {state:'wait'};if(check.checked)throw 0;show(check);check.click();return {state:'ready',confirmed:check.checked};"#,
        Step::Dispatch=>r#"return click('Dispatch this preflight once');"#,
        Step::Dispatched=>r#"const c=card(),op=operation(),b=button(observeName),dispatch=button('Dispatch this preflight once');
            if(!c||!op||!text(op).startsWith('dispatch · settled')||!b||b.disabled)return {state:'wait'};show(c);const effect=op.querySelector('strong');
            if(text(effect)!==dispatchEffect)return {state:'wait'};
            if(!effect||!op.querySelector('code'))throw 0;return {state:'ready',operationId:text(op.querySelector('code')),effect:text(effect),
                noSecondDispatch:!dispatch||dispatch.disabled,observeReady:!b.disabled};"#,
        Step::ReadyToRevoke=>r#"const c=card(),op=operation();if(!c||!op||!text(op).startsWith('dispatch · running')
            ||text(op.querySelector('strong'))!=='not-sent')return {state:'wait'};show(c);if(!op.querySelector('code'))throw 0;
            return {state:'ready',operationId:text(op.querySelector('code')),notSent:true};"#,
        Step::Refused=>r#"return negative('settled','not-sent');"#,
        Step::Cancel=>r#"const op=operation();if(!op||!text(op).startsWith('dispatch · running'))return {state:'wait'};
            return click('Stop this local action');"#,
        Step::Unknown|Step::LateRetired=>r#"return negative('cleanup-unknown','potentially-applied');"#,
        Step::ReloadPending=>r#"return click('Load this project’s pending requests · local only');"#,
        Step::ReadPending=>r#"const c=card(),op=operation(),b=button('Reconcile exact request · read GitHub');
            if(!c||!op||!text(op).startsWith('pending · settled')||!b||b.disabled)return {state:'wait'};
            const record=b.closest('article');if(!record||record.parentElement!==c||text(record.querySelector('h4'))!=='owner/app · main · android')throw 0;
            show(record);return {state:'ready',operationId:text(op.querySelector('code')),codes:[...record.querySelectorAll('code')].map(text),
                unresolved:text(record).includes('Run not yet resolved · original attempt 1 only.'),reconcileReady:!b.disabled};"#,
        Step::ObserveRun=>r#"return click(observeName);"#,
        Step::ObservedRun=>r#"const run=card()?.querySelector('[aria-label="Original workflow run observation"]'),op=operation();
            if(!run||!op)return {state:'wait'};show(run);if(text(run.querySelector('h4'))!=='Run 9001 · attempt 1')throw 0;
            return {state:'ready',operationId:text(op.querySelector('code')),runId:'9001',jobs:[...run.querySelectorAll('li')].map(text),
                notReleaseEvidence:text(run).includes('not signed artifact evidence or release readiness')};"#,
        Step::Status=>r#"return click('Read local Status');"#,
        Step::ReadStatus if case==Case::FinalityRefusal=>r#"return negative('cleanup-unknown','potentially-applied');"#,
        Step::ReadStatus if case.negative()=>r#"return negative('settled','not-sent');"#,
        Step::ReadStatus=>r#"const run=card()?.querySelector('[aria-label="Original workflow run observation"]');if(!run)return {state:'wait'};
            if(text(run.querySelector('h4'))!=='Run 9001 · attempt 1')throw 0;return {state:'ready',runId:'9001'};"#,
        Step::Disconnected=>r#"const c=card(),op=operation(),token=connection()?.querySelector('input[type="password"]');if(!c||!op)return {state:'wait'};
            if(!/^(dispatch|track|reconcile) · settled/.test(text(op)))return {state:'wait'};
            const branch=c.querySelector('input[placeholder="main or release/next"]'),platform=c.querySelector('select'),
                run=c.querySelector('[aria-label="Original workflow run observation"]'),effect=op.querySelector('strong'),
                noReview=!c.querySelector('[aria-label="Exact workflow review"]'),tokenEmpty=!token||token.value==='',
                selectionEmpty=!!branch&&!!platform&&branch.value===''&&platform.value==='',actionsDisabled=denied();
            if(!noReview||!tokenEmpty||!selectionEmpty||!actionsDisabled)return {state:'wait'};show(c);if(!op.querySelector('code'))throw 0;
            return {state:'ready',operationId:text(op.querySelector('code')),effect:effect?text(effect):null,records:records(),
                run:run?{title:text(run.querySelector('h4')),jobs:[...run.querySelectorAll('li')].map(text),url:text(run.querySelector('code'))}:null,
                noReview,tokenEmpty,selectionEmpty,actionsDisabled};"#,
        _=>return None,
    };
    Some(format!(r#"(()=>{{try{{
        const text=n=>n?.textContent?.trim()??'',card=()=>document.querySelector('[aria-label="GitHub nonpublishing preflight"]'),
            connection=()=>document.querySelector('[aria-label="GitHub connection and observations"]'),observeName={observe:?},dispatchEffect={dispatch_effect:?};
        const show=n=>{{n.scrollIntoView({{block:'center'}});const r=n.getBoundingClientRect();if(r.width<=0||r.height<=0||getComputedStyle(n).visibility!=='visible')throw 0;}};
        const button=name=>{{const rows=[...(card()?.querySelectorAll('button')??[])].filter(b=>text(b)===name);if(rows.length>1)throw 0;return rows[0];}};
        const click=name=>{{const b=button(name);if(!b||b.disabled)return {{state:'wait'}};show(b);b.click();return {{state:'ready'}};}};
        const operation=()=>[...(card()?.querySelectorAll(':scope > p.save-note[role="status"]')??[])].find(p=>p.querySelector('code'));
        const denied=()=>['Prepare workflow review · read only','Dispatch this preflight once','Load this project’s pending requests · local only',
            'Track this run · read GitHub','Reconcile exact request · read GitHub'].every(name=>{{const b=button(name);return !b||b.disabled;}});
        const records=()=>[...(card()?.querySelectorAll(':scope > article.github-environment:not([aria-label])')??[])].map(record=>({{codes:[...record.querySelectorAll('code')].map(text),text:text(record)}}));
        const negative=(phase,expected)=>{{const c=card(),op=operation(),dispatch=button('Dispatch this preflight once');
            if(!c||!op||!text(op).startsWith('dispatch · '+phase)||text(op.querySelector('strong'))!==expected)return {{state:'wait'}};
            if(!op.querySelector('code'))throw 0;show(c);return {{state:'ready',operationId:text(op.querySelector('code')),effect:text(op.querySelector('strong')),
                message:text(op),noSecondDispatch:!dispatch||dispatch.disabled,noRun:!c.querySelector('[aria-label="Original workflow run observation"]'),records:records(),newWorkDenied:denied()}};}};
        const edit=(input,value)=>{{show(input);input.focus();input.select();if(!document.execCommand('insertText',false,value))throw 0;}};
        {body}
    }}catch{{return {{state:'error'}};}}}})()"#))
}
