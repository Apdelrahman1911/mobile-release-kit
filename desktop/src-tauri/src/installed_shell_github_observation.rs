//! Installed GitHub observations on the ordinary document, UI and Supervisor.
//! The existing relay/exit observer drive this bounded adapter. It creates no
//! replacement query, process owner, timer, picker or shutdown task.
use std::sync::{Arc, Mutex, Weak, atomic::{AtomicBool, Ordering}};
use serde_json::{json, Value};
use tauri::Manager;
use tokio::sync::Mutex as AsyncMutex;
use crate::{error::BridgeError, github_connection_protocol as wire, supervisor::{Supervisor,
    github_tls_peer_owner::installed::{InstalledPeer, ProductWitness, N, PEER_SHA}}};
use super::{Observation, Case as ShellCase, Step as ShellStep, Pending, Boundary};
pub(crate) use crate::supervisor::github_tls_peer_owner::installed::Case;
impl Case {
    pub(super) fn failure_leaf(self)->&'static str {match self {
        Self::ConnectRefresh=>"shell-github-connect-refresh-failure.labels",
        Self::RealCa=>"shell-github-real-ca-refusal-failure.labels",
        Self::WrongName=>"shell-github-wrong-name-failure.labels",
        Self::Expired=>"shell-github-expired-failure.labels",
        Self::Ragged=>"shell-github-ragged-failure.labels",
        Self::Length=>"shell-github-length-failure.labels",
        Self::Chunk=>"shell-github-chunk-failure.labels",
        Self::HeaderLimit=>"shell-github-header-limit-failure.labels",
        Self::BodyLimit=>"shell-github-body-limit-failure.labels",
        Self::ChunkLimit=>"shell-github-chunk-limit-failure.labels",
        Self::Unauthorized=>"shell-github-unauthorized-failure.labels",
        Self::Rate=>"shell-github-rate-failure.labels",
        Self::Identity=>"shell-github-identity-failure.labels",
        Self::Redirect=>"shell-github-redirect-failure.labels",
        Self::AmbientFixed=>"shell-github-ambient-fixed-failure.labels",
        Self::AmbientNoRescue=>"shell-github-ambient-no-rescue-failure.labels",
        Self::HandshakeDeadline=>"shell-github-handshake-deadline-failure.labels",
        Self::HeaderDeadline=>"shell-github-header-deadline-failure.labels",
        Self::BodyDeadline=>"shell-github-body-deadline-failure.labels",
        Self::Cancel=>"shell-github-cancel-failure.labels",
        Self::Quit=>"shell-github-quit-failure.labels",
        Self::Unknown=>"shell-github-unknown-failure.labels",
        Self::NormalNegative=>"shell-github-normal-negative-failure.labels",
        Self::DnsDeadline=>"shell-github-dns-deadline-failure.labels",Self::ConnectDeadline=>"shell-github-connect-deadline-failure.labels",
    }}
    pub(super) fn verified_line(self)->&'static [u8] {match self {
        Self::ConnectRefresh=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-connect-refresh-verified\n",
        Self::RealCa=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-real-ca-refusal-verified\n",
        Self::WrongName=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-wrong-name-verified\n",
        Self::Expired=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-expired-verified\n",
        Self::Ragged=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-ragged-verified\n",
        Self::Length=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-length-verified\n",
        Self::Chunk=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-chunk-verified\n",
        Self::HeaderLimit=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-header-limit-verified\n",
        Self::BodyLimit=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-body-limit-verified\n",
        Self::ChunkLimit=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-chunk-limit-verified\n",
        Self::Unauthorized=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-unauthorized-verified\n",
        Self::Rate=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-rate-verified\n",
        Self::Identity=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-identity-verified\n",
        Self::Redirect=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-redirect-verified\n",
        Self::AmbientFixed=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-ambient-fixed-verified\n",
        Self::AmbientNoRescue=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-ambient-no-rescue-verified\n",
        Self::HandshakeDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-handshake-deadline-verified\n",
        Self::HeaderDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-header-deadline-verified\n",
        Self::BodyDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-body-deadline-verified\n",
        Self::Cancel=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-cancel-verified\n",
        Self::Quit=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-quit-verified\n",
        Self::Unknown=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-unknown-verified\n",
        Self::NormalNegative=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-normal-negative-verified\n",
        Self::DnsDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-dns-deadline-verified\n",
        Self::ConnectDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-connect-deadline-verified\n",
    }}
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Step { Navigate, EnterRepository, Entry, EnterToken, Token, Connect, Observe,
    Refresh, ObserveRefresh, Status, ReadStatus, Disconnect, Disconnected, InjectUnknown, Unknown }
impl Step {
    pub(super) fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Navigate=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubNavigate\n",
            Self::EnterRepository=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubRepository\n",
            Self::Entry=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubEntry\n",
            Self::EnterToken=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubToken\n",
            Self::Token=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubTokenReady\n",
            Self::Connect=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubConnect\n",
            Self::Observe=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubObserve\n",
            Self::Refresh=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubRefresh\n",
            Self::ObserveRefresh=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubRefreshed\n",
            Self::Status=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubStatus\n",
            Self::ReadStatus=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubStatusRead\n",
            Self::Disconnect=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubDisconnect\n",
            Self::Disconnected=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubDisconnected\n",
            Self::InjectUnknown=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubUnknownInject\n",
            Self::Unknown=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubUnknown\n",
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Command { Status, Connect, Refresh, Disconnect }
#[derive(Default)]
struct Record {
    attached: bool, peer_started: bool, peer_ready: bool, setup_claimed: bool,
    project_id: Option<String>, session_id: Option<String>, operation_ids: Vec<String>,
    replies: [u8;3], explicit_status: bool, latest: Option<wire::Status>,
    entry: bool, token_supplied: bool, token_cleared: bool, running_visible: bool,
    outcomes: Vec<Value>, status_visible: bool, disconnected: bool, unknown_visible: bool,
    unknown_injected: bool, close_ready: bool, physical_final: bool, final_checked: bool,
    peer_receipt: Option<Value>,
}
pub(crate) struct Control {
    case: Case, original: Mutex<Option<Weak<Observation>>>, failed: AtomicBool,
    record: Mutex<Record>, peer: AsyncMutex<InstalledPeer>, product: Arc<ProductWitness>,
}
impl Control {
    pub(super) fn new(case:Case)->Arc<Self> {
        let peer=InstalledPeer::new(case);let product=ProductWitness::new(case,&peer);
        Arc::new(Self{case,original:Mutex::new(None),failed:AtomicBool::new(false),
            record:Mutex::new(Record::default()),peer:AsyncMutex::new(peer),product})
    }
    fn original(&self)->Option<Arc<Observation>> { self.original.lock().ok()?.as_ref()?.upgrade() }
    fn fail(&self) { self.failed.store(true,Ordering::SeqCst);if let Some(q)=self.original(){q.fail();} }
    fn record(&self)->Option<std::sync::MutexGuard<'_,Record>> {
        match self.record.lock(){Ok(record)=>Some(record),Err(_)=>{self.fail();None}}
    }
    pub(super) fn profile(&self)->crate::runtime::GitHubReadOnlyObservationProfile { self.case.profile() }
    pub(super) fn attach(&self,q:&Arc<Observation>,supervisor:&Supervisor)->Result<(),BridgeError> {
        let mut slot=self.original.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if slot.is_some() || !super::route() || q.case!=ShellCase::GitHub(self.case) || q.failed.load(Ordering::SeqCst)
            || !q.github.as_ref().is_some_and(|c|std::ptr::eq(c.as_ref(),self)) {return Err(BridgeError::invalid());}
        *slot=Some(Arc::downgrade(q));drop(slot);
        self.product.attach(supervisor).map_err(|_|BridgeError::invalid())?;
        let mut r=self.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if r.attached{return Err(BridgeError::invalid());}r.attached=true;Ok(())
    }
    pub(super) fn status(&self,status:&wire::Status) {
        if self.failed.load(Ordering::SeqCst){return;}
        // The exact public decoder protects the same bounded status contract.
        let valid=serde_json::to_vec(status).is_ok_and(|raw|wire::decode_status(&raw).is_ok());
        if !valid{self.fail();return;}
        let Some(mut r)=self.record() else{return;};
        if r.latest.as_ref().is_some_and(|old|old.revision>status.revision){return;}
        r.latest=Some(status.clone());
    }
    pub(super) fn result(&self,command:Command,result:&Result<wire::Status,BridgeError>) {
        let Some(q)=self.original() else{self.fail();return;};
        if q.failed.load(Ordering::SeqCst){return;}
        let Ok(status)=result else{self.fail();return;};
        self.status(status);
        let Some(shell)=q.record_at(Boundary::Result) else{return;};
        let step=shell.step;
        let Some(mut r)=self.record() else{return;};
        match command {
            Command::Status=>{
                if matches!(step,ShellStep::GitHubReadOnly(Step::Status|Step::ReadStatus)) {
                    if r.explicit_status || !r.latest.as_ref().is_some_and(|s|s==status){self.fail();return;}
                    r.explicit_status=true;
                }
            },
            Command::Connect|Command::Refresh=>{
                let index=usize::from(matches!(command,Command::Refresh));
                let kind=if index==0{wire::OperationKind::Connect}else{wire::OperationKind::Refresh};
                let Some(session)=status.session.as_ref() else{self.fail();return;};
                let Some(operation)=status.operation.as_ref() else{self.fail();return;};
                if r.replies[index]!=0 || index==1&&self.case!=Case::ConnectRefresh
                    || operation.kind!=kind || operation.phase!=wire::Phase::Running || operation.reason!=wire::Reason::None
                    || session.state!=wire::SessionState::Checking || session.target_repository!="owner/app"
                    || r.project_id.as_deref()!=Some(session.project_id.as_str())
                    || (index==0 && r.session_id.is_some()) || (index==1 && r.session_id.as_deref()!=Some(session.id.as_str()))
                    || r.operation_ids.iter().any(|old|old==&operation.id) {self.fail();return;}
                if index==0{r.session_id=Some(session.id.clone());}
                r.operation_ids.push(operation.id.clone());r.replies[index]+=1;
            },
            Command::Disconnect=>{
                if r.replies[2]!=0 || matches!(self.case,Case::Quit|Case::Unknown)
                    || status.session.as_ref().is_some_and(|s|Some(s.id.as_str())!=r.session_id.as_deref()
                        ||s.project_id!=r.project_id.as_deref().unwrap_or("")||s.target_repository!="owner/app")
                    {self.fail();return;}
                r.replies[2]=1;
            },
        }
    }
    // Called by the SAME existing async relay, never a nested block_on/task.
    pub(super) async fn relay(&self,app:&tauri::AppHandle) {
        let Some(q)=self.original() else{self.fail();return;};
        if q.failed.load(Ordering::SeqCst){return;}
        let step=match q.record(){Some(r)=>r.step,None=>return};
        let state=app.state::<super::super::ShellState>();
        if step==ShellStep::GitHubReadOnly(Step::Connect) {
            let start=match self.record(){Some(mut r) if !r.setup_claimed=>{r.setup_claimed=true;true},_=>false};
            if start {
                let Some(root)=super::control_root() else{self.fail();return;};
                let mut peer=self.peer.lock().await;
                if peer.prepare(root,q.end).is_err(){self.fail();return;}
                if let Some(mut r)=self.record(){r.peer_started=true;}
                if peer.start().await.is_err(){self.fail();return;}
                if let Some(mut r)=self.record(){r.peer_ready=true;}
            }
        }
        if step==ShellStep::GitHubReadOnly(Step::InjectUnknown) {
            let inject=match self.record(){Some(r)=>!r.unknown_injected,_=>return};
            if inject {
                if !self.peer.lock().await.first_get() || self.product.inject_unknown(&state.bridge.supervisor).is_err(){self.fail();return;}
                if let Some(mut r)=self.record(){r.unknown_injected=true;}
                let Some(mut shell)=q.record_at(Boundary::Settlement) else{return;};
                if shell.step!=step || shell.pending.is_some(){self.fail();return;}
                shell.step=ShellStep::GitHubReadOnly(Step::Unknown);
            }
        }
        if self.product.observe_retired(&state.bridge.supervisor,q.end).await.is_err(){self.fail();}
    }
    pub(super) fn tick(&self,app:&tauri::AppHandle,step:Step)->bool {
        let Some(q)=self.original() else{self.fail();return false;};
        let Some(shell)=q.record() else{return false;};
        let project=shell.project.as_ref().map(|p|p.id.clone());
        if !shell.snapshot_visible || shell.project_witness.is_none(){self.fail();return false;}
        drop(shell);
        let Some(mut r)=self.record() else{return false;};
        if r.project_id.is_none(){r.project_id=project;}
        let Some(status)=r.latest.as_ref() else{return false;};
        let state=app.state::<super::super::ShellState>();
        match step {
            Step::Entry=>status.capability.read_only_session_available && status.session.is_none(),
            Step::Connect=>r.peer_ready && r.token_supplied && r.replies[0]==0,
            Step::Observe if self.case.active_control()=>r.replies[0]==1
                && status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::Running)
                && self.peer.try_lock().is_ok_and(|p|p.first_get()),
            Step::Observe|Step::ObserveRefresh=>{
                let expected=if step==Step::ObserveRefresh{2}else{1};
                self.product.evidence().len()==expected && status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::Settled)
            },
            Step::ReadStatus=>r.explicit_status,
            Step::Disconnected=>r.replies[2]==1 && status.session.is_none() && status.operation.is_none()
                && self.product.complete(&state.bridge.supervisor),
            Step::Unknown=>r.unknown_injected && status.session.as_ref().is_some_and(|s|s.state==wire::SessionState::CleanupUnknown)
                && status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::CleanupUnknown)
                && self.product.complete(&state.bridge.supervisor),
            Step::InjectUnknown=>false,
            _=>true,
        }
    }
    pub(super) fn dom(&self,step:Step,value:&Value) {
        let Some(q)=self.original() else{self.fail();return;};
        let Some(mut shell)=q.record_at(Boundary::Dom) else{return;};
        if shell.step!=ShellStep::GitHubReadOnly(step)||shell.pending.take()!=Some(Pending::Dom(ShellStep::GitHubReadOnly(step))){self.fail();return;}
        let Some(object)=value.as_object() else{self.fail();return;};
        if value["state"]=="wait"&&object.len()==1{return;}
        if value["state"]!="ready"{self.fail();return;}
        let Some(mut r)=self.record() else{return;};
        if matches!(step,Step::Observe|Step::ObserveRefresh|Step::ReadStatus|Step::Disconnected|Step::Unknown) {
            let Some(status)=r.latest.as_ref() else{self.fail();return;};
            match dom_observation(value,status) {
                DomObservation::Stale=>return, // Render catches up; never advances this original step.
                DomObservation::Refused=>{self.fail();return;},
                DomObservation::Matches=>{},
            }
        }
        let valid=match step {
            Step::Entry=>object.len()==3&&value["entryAvailable"]==true&&value["helpPresent"]==true,
            Step::Token=>object.len()==2&&value["supplied"]==true,
            Step::Observe|Step::ObserveRefresh|Step::ReadStatus|Step::Disconnected|Step::Unknown=>true,
            _=>object.len()==1,
        };
        if !valid{self.fail();return;}
        let next=match step {
            Step::Navigate=>Step::EnterRepository,
            Step::EnterRepository=>Step::Entry,
            Step::Entry=>{r.entry=true;Step::EnterToken},
            Step::EnterToken=>Step::Token,
            Step::Token=>{r.token_supplied=true;Step::Connect},
            Step::Connect=>Step::Observe,
            Step::Observe if self.case.active_control()=>{
                if !value["tokenEmpty"].as_bool().unwrap_or(false)||value["phase"]!="running"{self.fail();return;}
                r.token_cleared=true;r.running_visible=true;
                match self.case {
                    Case::Cancel=>Step::Disconnect,
                    Case::Unknown=>Step::InjectUnknown,
                    Case::Quit=>{r.close_ready=true;shell.step=ShellStep::Close;return;},
                    _=>{self.fail();return;},
                }
            },
            Step::Observe|Step::ObserveRefresh=>{
                if value["phase"]!="settled"||value["tokenEmpty"]!=true{self.fail();return;}
                let Some(status)=r.latest.as_ref() else{self.fail();return;};
                if status.operation.as_ref().is_none_or(|o|o.reason!=ui_reason(self.case)){self.fail();return;}
                let summary=summary(status);r.outcomes.push(summary);r.token_cleared=true;
                if self.case==Case::ConnectRefresh && step==Step::Observe{Step::Refresh}else{Step::Status}
            },
            Step::Refresh=>Step::ObserveRefresh,
            Step::Status=>Step::ReadStatus,
            Step::ReadStatus=>{r.status_visible=true;Step::Disconnect},
            Step::Disconnect=>Step::Disconnected,
            Step::Disconnected=>{
                if value["sessionId"]!=Value::Null||value["tokenEmpty"]!=true{self.fail();return;}
                r.disconnected=true;r.close_ready=true;shell.step=ShellStep::Close;return;
            },
            Step::Unknown=>{
                if value["connectEnabled"]!=false||value["refreshEnabled"]!=false||value["tokenEmpty"]!=true{self.fail();return;}
                r.unknown_visible=true;r.close_ready=true;shell.step=ShellStep::Close;return;
            },
            _=>{self.fail();return;},
        };
        shell.step=ShellStep::GitHubReadOnly(next);
    }
    pub(super) fn ready_to_close(&self)->bool {
        !self.failed.load(Ordering::SeqCst)&&self.record().is_some_and(|r|r.close_ready)
    }
    // Existing exit observer only, after the real document's original Quit,
    // product cleanup and native dialog finality. Failure still settles peers
    // through their same original handles, without publishing a success byte.
    pub(super) async fn settle_for_exit(&self,app:&tauri::AppHandle)->bool {
        let Some(q)=self.original() else{self.fail();return false;};
        let state=app.state::<super::super::ShellState>();
        if !state.document.can_exit(){return false;}
        if self.record().is_some_and(|r|r.physical_final){return true;}
        let product=self.product.observe_retired(&state.bridge.supervisor,q.end).await
            .is_ok_and(|final_seen|final_seen&&self.product.complete(&state.bridge.supervisor));
        let success=product&&!q.failed.load(Ordering::SeqCst)&&self.ready_to_close();
        let mut peer=self.peer.lock().await;
        let physical=peer.settle(success,q.end).await;
        let checked=success&&physical&&peer.validate(self.product.endpoint()).is_ok();
        if !checked{self.fail();}
        let Some(mut r)=self.record() else{return false;};
        r.physical_final=physical;r.final_checked=checked;
        if checked{r.peer_receipt=Some(peer.evidence());}
        physical
    }
    pub(super) fn complete(&self)->bool {
        !self.failed.load(Ordering::SeqCst)&&self.record().is_some_and(|r|
            r.attached&&r.peer_started&&r.peer_ready&&r.entry&&r.token_supplied&&r.token_cleared&&r.close_ready
            &&r.physical_final&&r.final_checked&&r.replies[0]==1&&r.replies[1]==u8::from(self.case==Case::ConnectRefresh)
            &&r.operation_ids.len()==self.case.reads()&&r.peer_receipt.is_some()
            &&self.product.evidence().iter().zip(&r.operation_ids).all(|(original,id)|original["operationId"].as_str()==Some(id.as_str()))
            &&if self.case.active_control(){r.running_visible&&r.outcomes.is_empty()&&!r.status_visible&&!r.explicit_status
                &&match self.case{Case::Cancel=>r.disconnected&&r.replies[2]==1,
                    Case::Quit=>!r.disconnected&&r.replies[2]==0,
                    Case::Unknown=>r.unknown_injected&&r.unknown_visible&&!r.disconnected&&r.replies[2]==0,_=>false}}
            else{r.outcomes.len()==self.case.reads()&&r.explicit_status&&r.status_visible&&r.disconnected&&r.replies[2]==1})
    }
    pub(super) fn report(&self)->Option<Vec<u8>> {
        if !self.complete(){return None;}
        let q=self.original()?;let shell=q.record()?;let r=self.record()?;
        if !shell.exit||!shell.originals_final||!shell.relay_joined{return None;}
        serde_json::to_vec(&json!({
            "schemaVersion":1,"fixture":"github-readonly-installed-v1","case":self.case.name(),"sourceCommit":option_env!("GITHUB_SHA")?,
            "normalManifestSha256":N,"productManifestSha256":self.case.manifest(),
            "protocolSha256":"860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e",
            "peerSha256":if self.case.no_peer(){None}else{Some(PEER_SHA)},
            "project":{"cancelSettled":shell.cancelled&&shell.pickers[0].settled(false),
                "registered":shell.selected&&shell.pickers[1].settled(true)&&shell.project_witness.is_some(),
                "snapshot":shell.snapshot&&shell.snapshot_visible},
            "nativeSession":{"connect":r.replies[0],"refresh":r.replies[1],"disconnect":r.replies[2],
                "retainedStatus":r.status_visible&&r.explicit_status,"runningObserved":r.running_visible,
                "outcomes":r.outcomes,"cleared":r.disconnected,"unknownRetained":r.unknown_visible,
                "tokenFieldCleared":r.token_cleared},
            "originals":self.product.evidence(),"peer":r.peer_receipt,
            "quit":{"originalsFinal":shell.originals_final,"relayJoined":shell.relay_joined,
                "gtkSettled":shell.gtk_returned&&shell.destroyed&&shell.released,"exit":shell.exit},
            "notProven":self.case.not_proven()
        })).ok().filter(|raw|raw.len()<=32768)
    }
}
fn ui_reason(case:Case)->wire::Reason {
    use wire::Reason as R;
    match case {
        Case::ConnectRefresh|Case::AmbientFixed=>R::None,
        Case::RealCa|Case::WrongName|Case::Expired|Case::Ragged|Case::AmbientNoRescue=>R::TlsFailed,
        Case::HeaderLimit|Case::BodyLimit|Case::ChunkLimit=>R::ResponseLimit,
        Case::Unauthorized|Case::NormalNegative=>R::Unauthorized,Case::Identity=>R::TargetChanged,
        Case::HandshakeDeadline|Case::HeaderDeadline|Case::BodyDeadline|Case::DnsDeadline|Case::ConnectDeadline=>R::NetworkUnavailable,
        Case::Cancel|Case::Quit=>R::Cancelled,Case::Unknown=>R::CleanupUnknown,_=>R::ResponseInvalid,
    }
}
fn reason_help(reason:wire::Reason)->Option<&'static str> {
    use wire::Reason as R;
    Some(match reason{
        R::None=>"The reported observation is available, not release or mutation authority.",
        R::TlsFailed=>"TLS verification failed. Do not disable verification or supply alternate trust.",
        R::ResponseLimit=>"The bounded response limit was reached. No broader discovery is authorized.",
        R::ResponseInvalid=>"The original result did not satisfy the closed response contract.",
        R::Unauthorized=>"Authentication was refused. Retire the original request before explicitly authenticating again.",
        R::TargetChanged=>"The original account, repository or context identity changed. Do not adopt the replacement.",
        R::NetworkUnavailable=>"The bounded read failed. Raw service diagnostics are not displayed.",
        R::Cancelled=>"Local retirement was requested; actual original settlement must still be observed.",
        R::CleanupUnknown=>"Original cleanup is unknown. Further requests stay blocked even after late success.",
        _=>return None,
    })
}
fn summary(status:&wire::Status)->Value {
    json!({"revision":status.revision,"sessionId":status.session.as_ref().map(|s|&s.id),
        "projectId":status.session.as_ref().map(|s|&s.project_id),"target":status.session.as_ref().map(|s|&s.target_repository),
        "sessionState":status.session.as_ref().map(|s|s.state),"kind":status.operation.as_ref().map(|o|o.kind),
        "phase":status.operation.as_ref().map(|o|o.phase),"reason":status.operation.as_ref().map(|o|o.reason),
        "facts":[status.account.state,status.repository.state,status.automation.state],
        "accountId":status.account.value.as_ref().map(|a|&a.id),"repositoryId":status.repository.value.as_ref().map(|r|&r.id),
        "workflowRows":status.automation.value.as_ref().map_or(0,|a|a.workflows.len())})
}
fn dom_matches(value:&Value,status:&wire::Status)->bool {
    let summary=summary(status);
    let fields=["revision","sessionId","projectId","target","sessionState","kind","phase","facts","accountId","repositoryId","workflowRows"];
    value.as_object().is_some_and(|v|v.len()==18)
        &&fields.iter().all(|key|value.get(*key)==summary.get(*key))
        &&value["tokenEmpty"]==true&&value["remoteUnavailable"]==true
        &&value["reasonText"].as_str()==if let Some(op)=status.operation.as_ref(){reason_help(op.reason)}else{Some("")}
        &&(status.session.is_none()||value["connectEnabled"]==false)
        &&(status.session.as_ref().is_none_or(|s|s.state!=wire::SessionState::CleanupUnknown)||value["refreshEnabled"]==false)
}
#[derive(Debug, PartialEq, Eq)]
enum DomObservation { Stale, Matches, Refused }
fn dom_observation(value:&Value,status:&wire::Status)->DomObservation {
    if !super::keys(value,&["state","revision","sessionId","projectId","target","sessionState","kind","phase",
        "reasonText","facts","accountId","repositoryId","workflowRows","tokenEmpty","connectEnabled","refreshEnabled",
        "disconnectEnabled","remoteUnavailable"]) || value["state"]!="ready"
        || ["tokenEmpty","connectEnabled","refreshEnabled","disconnectEnabled","remoteUnavailable"].iter()
            .any(|key|!value[*key].is_boolean()) {return DomObservation::Refused;}
    match value["revision"].as_u64() {
        Some(revision) if revision>0 && revision<u64::from(status.revision)=>DomObservation::Stale,
        Some(revision) if revision==u64::from(status.revision) && dom_matches(value,status)=>DomObservation::Matches,
        _=>DomObservation::Refused,
    }
}
pub(super) fn assert_contracts() {
    crate::supervisor::github_tls_peer_owner::installed::assert_contracts();
    let mut status=crate::github_connection_session::ConnectionState::new().snapshot();
    status.revision=2;
    let mut value=summary(&status);
    let fields=value.as_object_mut().unwrap();fields.remove("reason");
    for (key,item) in [("state",json!("ready")),("reasonText",json!("")),("tokenEmpty",json!(true)),
        ("connectEnabled",json!(false)),("refreshEnabled",json!(false)),("disconnectEnabled",json!(false)),
        ("remoteUnavailable",json!(true))] {fields.insert(key.into(),item);}
    assert_eq!(dom_observation(&value,&status),DomObservation::Matches);
    let mut stale=value.clone();stale["revision"]=json!(1);
    assert_eq!(dom_observation(&stale,&status),DomObservation::Stale);
    for (key,item) in [("revision",json!(0)),("revision",json!(3)),("revision",json!(true)),
        ("accountId",json!("99")),("reasonText",json!("not the native reason")),("tokenEmpty",json!(false)),
        ("remoteUnavailable",json!(false)),("disconnectEnabled",json!("false")),("extra",json!(0))] {
        let mut changed=value.clone();changed[key]=item;
        assert_eq!(dom_observation(&changed,&status),DomObservation::Refused);
    }
    let mut unknown=status.clone();
    unknown.capability.read_only_session_available=false;unknown.capability.reason=wire::Reason::CleanupUnknown;
    unknown.session=Some(wire::Session{id:"github-session-1".into(),project_id:"project-1".into(),
        target_repository:"owner/app".into(),state:wire::SessionState::CleanupUnknown,expires_at:None});
    unknown.operation=Some(wire::Operation{id:"query-1".into(),kind:wire::OperationKind::Connect,
        phase:wire::Phase::CleanupUnknown,reason:wire::Reason::CleanupUnknown});
    for (state,reason) in [(&mut unknown.account.state,&mut unknown.account.reason),
        (&mut unknown.repository.state,&mut unknown.repository.reason),(&mut unknown.automation.state,&mut unknown.automation.reason)] {
        *state=wire::FactState::Unavailable;*reason=wire::Reason::CleanupUnknown;
    }
    assert!(wire::decode_status(&serde_json::to_vec(&unknown).unwrap()).is_ok());
    value["sessionId"]=json!("github-session-1");value["projectId"]=json!("project-1");value["target"]=json!("owner/app");
    value["sessionState"]=json!("cleanup-unknown");
    value["kind"]=json!("connect");value["phase"]=json!("cleanup-unknown");
    value["reasonText"]=json!(reason_help(wire::Reason::CleanupUnknown).unwrap());
    value["facts"]=json!(["unavailable","unavailable","unavailable"]);
    assert_eq!(dom_observation(&value,&unknown),DomObservation::Matches);
    value["connectEnabled"]=json!(true);
    assert_eq!(dom_observation(&value,&unknown),DomObservation::Refused);
    value["connectEnabled"]=json!(false);value["refreshEnabled"]=json!(true);
    assert_eq!(dom_observation(&value,&unknown),DomObservation::Refused);
}
pub(super) fn script(step:Step)->Option<String> {
    let body=match step{
        Step::Navigate=>r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="GitHub"]');
            if(!b||b.disabled)return {state:'wait'};show(b);b.click();return {state:'ready'};"#,
        Step::EnterRepository=>r#"if(!selected())return {state:'wait'};const input=card()?.querySelector('input[placeholder="OWNER/REPO"]');
            if(!input||input.disabled)return {state:'wait'};edit(input,'owner/app');return {state:'ready'};"#,
        Step::Entry=>r#"const c=card(),form=c?.querySelector('form.github-form'),b=form?.querySelector('button[type="submit"]');
            if(!selected()||!form||!b||b.disabled)return {state:'wait'};show(form);
            return {state:'ready',entryAvailable:true,helpPresent:!!c.querySelector('[aria-label="Core GitHub connection help"]')&&text(c).includes('No GitHub App registration is needed')};"#,
        Step::EnterToken=>r#"const input=card()?.querySelector('form.github-form input[type="password"]');
            if(!input||input.disabled)return {state:'wait'};edit(input,'INERT_NOT_A_CREDENTIAL');return {state:'ready'};"#,
        Step::Token=>r#"const input=card()?.querySelector('form.github-form input[type="password"]');
            if(!input)return {state:'wait'};return {state:'ready',supplied:input.value==='INERT_NOT_A_CREDENTIAL'};"#,
        Step::Connect=>r#"return click('Connect for read-only observations');"#,
        Step::Refresh=>r#"return click('Refresh observation');"#,
        Step::Status=>r#"return click('Read retained Status');"#,
        Step::Disconnect=>r#"return click('Disconnect original session');"#,
        Step::InjectUnknown=>return None,
        Step::Observe|Step::ObserveRefresh|Step::ReadStatus|Step::Disconnected|Step::Unknown=>r#"
            const c=card();if(!selected()||!c)return {state:'wait'};show(c);
            const paragraphs=[...c.querySelectorAll(':scope > p.save-note')],row=paragraphs.find(p=>/^(Original native|Retained \/ stale original) status/.test(text(p)));
            if(!row)return {state:'wait'};const codes=[...row.querySelectorAll('code')].map(text),native=text(row),revision=/revision ([1-9][0-9]*)\./.exec(native);
            if(!revision||![0,3].includes(codes.length))throw 0;
            const session=/:\s*(checking|connected|expired|disconnecting|failed|cleanup-unknown)\.$/.exec(native);
            const op=paragraphs.find(p=>/^Original (connect|refresh|disconnect):/.test(text(p))),operation=op?/^Original (connect|refresh|disconnect): (running|settled|cleanup-unknown)\./.exec(text(op)):null;
            if(op&&!operation||codes.length===3&&!session)throw 0;
            const facts=[...c.querySelectorAll(':scope > h3')].map(h=>text(h.nextElementSibling?.querySelector('.badge')));
            if(facts.length!==3)throw 0;
            const account=[...c.querySelectorAll(':scope > p')].find(p=>p.querySelector('strong')&&p.querySelector('code')),
                repository=c.querySelector('dl.github-facts > div:first-child code'),table=c.querySelector('table.review-table tbody');
            const token=c.querySelector('input[type="password"]'),connect=c.querySelector('form.github-form button[type="submit"]');
            return {state:'ready',revision:Number(revision[1]),sessionId:codes[0]??null,projectId:codes[1]??null,target:codes[2]??null,
                sessionState:session?.[1]??null,kind:operation?.[1]??null,phase:operation?.[2]??null,
                reasonText:operation?text(op).slice(operation[0].length).trim():'',
                facts,accountId:account?text(account.querySelector('code')):null,repositoryId:repository?text(repository):null,
                workflowRows:table?table.querySelectorAll('tr').length:0,tokenEmpty:!token||token.value==='',
                connectEnabled:!!connect&&!connect.disabled,refreshEnabled:!!button('Refresh observation')&&!button('Refresh observation').disabled,
                disconnectEnabled:!!button('Disconnect original session')&&!button('Disconnect original session').disabled,
                remoteUnavailable:text(document.querySelector('[aria-label="Remote GitHub setup unavailable"]')).includes('No remote mutations or workflow dispatch.')};"#,
    };
    Some(format!(r#"(()=>{{try{{
        const text=n=>n?.textContent?.trim()??'',card=()=>document.querySelector('[aria-label="GitHub connection and observations"]');
        const selected=()=>!!document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="GitHub"][aria-current="page"]');
        const show=n=>{{n.scrollIntoView({{block:'center'}});const r=n.getBoundingClientRect();if(r.width<=0||r.height<=0||getComputedStyle(n).visibility!=='visible')throw 0;}};
        const button=name=>{{const rows=[...(card()?.querySelectorAll('button')??[])].filter(b=>text(b)===name);if(rows.length>1)throw 0;return rows[0];}};
        const click=name=>{{const b=button(name);if(!b||b.disabled)return {{state:'wait'}};show(b);b.click();return {{state:'ready'}};}};
        const edit=(input,value)=>{{show(input);input.focus();input.select();if(!document.execCommand('insertText',false,value))throw 0;}};
        {body}
    }}catch{{return {{state:'error'}};}}}})()"#))
}
