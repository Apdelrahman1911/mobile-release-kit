//! Two positive and three separately typed negative installed preflight journeys.
//! Scheduling controls are not kernel/descriptor-close-error injection.
//! These witnesses borrow the existing
//! Supervisor and physical TLS Peer; neither owns another child or deadline.
//! Synthetic results never enable the ordinary action profile or qualify GitHub.
use super::*;
use std::path::{Path, PathBuf};
use serde_json::json;
use sha2::{Digest, Sha256};
use crate::runtime::GitHubPreflightObservationProfile as RuntimeProfile;
use github_tls_peer_owner::{Arrivals, Peer, PeerControl,
    installed::{domain_environment, fixed_input, N, PEER_SHA as SUPPORT_SHA}};

type Check<T> = Result<T, &'static str>;
fn require(value: bool, code: &'static str) -> Check<()> { if value { Ok(()) } else { Err(code) } }
fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len()==expected.len() && expected.iter().all(|key|v.contains_key(*key)))
}
const PEER_SOURCE: &[u8] = include_bytes!("../tests/fixtures/github_preflight_peer.py");
const SCOPE: &str = "github-preflight-installed-peer-v1";
pub(crate) fn peer_sha256() -> String { format!("{:x}", Sha256::digest(PEER_SOURCE)) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case { Success, ResponseLoss, PreGoRevocation, JournalCollision, FinalityRefusal }
impl Case {
    pub(crate) const ALL: [Self;5] = [Self::Success, Self::ResponseLoss, Self::PreGoRevocation, Self::JournalCollision, Self::FinalityRefusal];
    pub(crate) fn name(self) -> &'static str { match self {
        Self::Success=>"github-preflight-success", Self::ResponseLoss=>"github-preflight-response-loss",
        Self::PreGoRevocation=>"github-preflight-pre-go-revocation", Self::JournalCollision=>"github-preflight-journal-collision",
        Self::FinalityRefusal=>"github-preflight-finality-refusal",
    }}
    pub(crate) fn parse(value: &std::ffi::OsStr) -> Option<Self> {
        Self::ALL.into_iter().find(|case|value==std::ffi::OsStr::new(case.name()))
    }
    fn script(self) -> &'static str { match self {
        Self::Success=>"preflight-success", Self::ResponseLoss=>"preflight-response-loss",
        Self::PreGoRevocation=>"preflight-pre-go-revocation", Self::JournalCollision=>"preflight-journal-collision",
        Self::FinalityRefusal=>"preflight-finality-refusal",
    }}
    pub(crate) fn negative(self) -> bool { !matches!(self,Self::Success|Self::ResponseLoss) }
    fn requests(self) -> u64 { match self { Self::Success=>20, Self::ResponseLoss|Self::JournalCollision=>21, Self::PreGoRevocation=>10, Self::FinalityRefusal=>15 } }
    fn posts(self) -> u64 { if self==Self::PreGoRevocation {0} else {1} }
    pub(crate) fn before_go_failure(self,index:usize)->bool {
        (self==Self::PreGoRevocation&&index==2)||(self==Self::JournalCollision&&index==4)
    }
    pub(crate) fn final_kind(self) -> preflight_protocol::Kind { match self {
        Self::Success=>preflight_protocol::Kind::Track, Self::ResponseLoss=>preflight_protocol::Kind::Reconcile,
        Self::PreGoRevocation|Self::JournalCollision|Self::FinalityRefusal=>preflight_protocol::Kind::Dispatch,
    }}
    pub(crate) fn owner_count(self) -> usize { match self {Self::Success=>4,Self::ResponseLoss|Self::JournalCollision=>5,_=>3} }
    pub(crate) fn action_count(self) -> usize { self.owner_count()-1 }
    pub(crate) fn kind(self, index: usize) -> Option<preflight_protocol::Kind> { match index {
        1=>Some(preflight_protocol::Kind::Prepare), 2=>Some(preflight_protocol::Kind::Dispatch),
        3 if self==Self::Success=>Some(self.final_kind()),
        3 if self==Self::ResponseLoss=>Some(preflight_protocol::Kind::Pending),
        3 if self==Self::JournalCollision=>Some(preflight_protocol::Kind::Prepare),
        4 if self==Self::ResponseLoss||self==Self::JournalCollision=>Some(self.final_kind()), _=>None,
    }}
}

// This is an adapter over the same original Peer. Admission/POST checks never
// replace its acquired Child, readers, control writer or absolute16s endpoint.
pub(crate) struct InstalledPeer {
    case: Case, original: Peer, completion: Option<oneshot::Sender<()>>,
    root: Option<PathBuf>, environment: BTreeMap<String,String>, ready_frame: Option<Value>,
    materials_checked: bool, post_checked: bool, failed: bool,
}
impl InstalledPeer {
    pub(crate) fn new(case: Case) -> Self {
        let (sender,receiver)=oneshot::channel();
        let mut original=Peer::default();
        original.control=Some(PeerControl::new(receiver));
        original.progress=Some(Arc::new(Mutex::new(Arrivals::default())));
        Self {case,original,completion:Some(sender),root:None,environment:BTreeMap::new(),ready_frame:None,
            materials_checked:false,post_checked:false,failed:false}
    }
    fn inputs(&self, root: &Path, end: Instant) -> Check<()> {
        fixed_input(&PathBuf::from("/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu").join(N).join("python/bin/python3"),
            8247616,"9d13da55c5e3ec27d0e6a18e3960fa6af4ced7628afe2e63830e7e66d8c80d4f",0o555,end)?;
        let staged=root.join("github-peer");
        fixed_input(&staged.join("github_preflight_peer.py"),PEER_SOURCE.len() as u64,&peer_sha256(),0o444,end)?;
        fixed_input(&staged.join("github_tls_peer.py"),61665,SUPPORT_SHA,0o444,end)?;
        fixed_input(&staged.join("mobile-preflight.yml"),1498,RuntimeProfile::CALLER_SHA256,0o444,end)?;
        for (name,size,hash) in [
            ("api-valid.pem",786,"33f6acd10b8d466078525b80464a1c5938266b1084ea5aabf43b348bd7dca6f2"),
            ("server-key.pem",241,"33332bb26fd6e394d067f7e2df563d496f934e0a098de1e3039169fb8d4ee109"),
        ] { fixed_input(&staged.join("github_tls").join(name),size,hash,0o444,end)?; }
        Ok(())
    }
    pub(crate) fn prepare(&mut self, root: PathBuf, end: Instant) -> Check<()> {
        require(self.root.is_none()&&!self.materials_checked&&self.original.endpoint.is_none(),"preflight_peer_repeated_setup")?;
        self.root=Some(root.clone()); // A failed original admission cannot retry.
        let mut environment=domain_environment(&root,end)?;
        self.inputs(&root,end)?;
        let tag=format!("{:x}",Sha256::digest(format!("{}:{}:{}:{}",self.case.name(),
            root.display(),std::process::id(),option_env!("GITHUB_SHA").unwrap_or("")).as_bytes()))[..16].to_owned();
        environment.extend(BTreeMap::from([
            ("MRK_DESKTOP_HOSTED_CHECKS".into(),"github-preflight-installed-tls-v1".into()),
            ("GITHUB_ACTIONS".into(),"true".into()),("RUNNER_ENVIRONMENT".into(),"github-hosted".into()),
            ("MRK_PREFLIGHT_PEER_SHA256".into(),peer_sha256()),("MRK_TLS_PEER_OWNER_TAG".into(),tag.clone()),
        ]));
        let ready=ready_binding(self.case,&tag);
        self.original.ready_binding=Some(ready.clone());self.ready_frame=Some(ready);self.environment=environment;
        self.materials_checked=true;Ok(())
    }
    pub(crate) async fn start(&mut self) -> Check<()> {
        require(self.materials_checked&&self.original.endpoint.is_none(),"preflight_peer_setup")?;
        let root=self.root.as_ref().ok_or("preflight_peer_setup")?;
        let python=PathBuf::from("/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu").join(N).join("python/bin/python3");
        self.original.begin_paths(python,root.join("github-peer/github_preflight_peer.py"),self.environment.clone(),self.case.script())?;
        self.original.readiness(self.case.script()).await
    }
    pub(crate) async fn settle(&mut self, product_final: bool, end: Instant) -> bool {
        if self.post_checked { return self.original.settled; }
        if product_final { if let Some(sender)=self.completion.take(){let _=sender.send(());} }
        else { drop(self.completion.take());self.failed=true; }
        let settled=self.original.settle(self.case.script(),!product_final).await;
        self.failed|=!settled;
        if settled {
            let result=self.root.as_ref().ok_or("preflight_peer_setup").and_then(|root|self.inputs(root,end));
            self.post_checked=true;self.failed|=result.is_err();
        }
        settled&&self.post_checked
    }
    pub(crate) fn validate(&mut self, marker: &str) -> Check<()> {
        let peer=&mut self.original;
        require(peer.settled&&peer.ready&&peer.spawned&&!peer.expired&&!peer.stop_attempted
            &&peer.waited.as_ref().is_some_and(ExitStatus::success)&&self.post_checked&&!self.failed,"preflight_peer_final")?;
        let out=peer.out.as_ref().ok_or("preflight_peer_output")?;let err=peer.err.as_ref().ok_or("preflight_peer_output")?;
        require(out.eof&&err.eof&&!out.overflow&&!err.overflow&&err.bytes.is_empty(),"preflight_peer_output")?;
        let lines=out.bytes.split(|b|*b==b'\n').collect::<Vec<_>>();
        require(lines.len()==3&&lines[2].is_empty()&&protocol::strict_json(lines[0]).ok()==self.ready_frame,"preflight_peer_frames")?;
        let terminal=protocol::strict_json(lines[1]).map_err(|_|"preflight_peer_terminal")?;
        let ready=self.ready_frame.as_ref().ok_or("preflight_peer_binding")?;
        require(terminal_valid(&terminal,ready,self.case,marker),"preflight_peer_terminal")?;
        let control=peer.control.as_ref().ok_or("preflight_peer_control")?;
        let facts=control.evidence(peer.endpoint);
        require(facts["acquired"]==true&&facts["started"]==true&&facts["joined"]==true&&facts["writeComplete"]==true
            &&facts["shutdownComplete"]==true&&facts["productSettled"]==true&&facts["withinEndpoint"]==true
            &&facts["released"]==true&&facts["failed"]==false,"preflight_peer_control")?;
        let arrivals=peer.progress.as_ref().ok_or("preflight_peer_arrivals")?;let arrivals=lock(arrivals);
        require(!arrivals.invalid&&arrivals.frames.len()==2&&arrivals.observed_bytes==out.bytes.len()
            &&arrivals.frames.iter().all(|(_,at)|peer.endpoint.is_some_and(|end|*at<end)),"preflight_peer_arrivals")?;
        peer.terminal=Some(terminal);peer.protocol_checked=true;Ok(())
    }
    pub(crate) fn evidence(&self) -> Value { self.original.evidence() }
}
fn ready_binding(case:Case, tag:&str)->Value {
    json!({"schemaVersion":1,"scope":SCOPE,"case":case.script(),"state":"ready","ownerTag":tag,
        "manifestSha256":RuntimeProfile::MANIFEST,"peerSha256":peer_sha256(),"toolingSha":RuntimeProfile::TOOLING_SHA,
        "callerSha256":RuntimeProfile::CALLER_SHA256,"primaryPort":18443})
}
fn terminal_valid(terminal: &Value, ready: &Value, case: Case, marker: &str) -> bool {
    keys(terminal,&["schemaVersion","scope","case","state","ownerTag","manifestSha256","peerSha256","toolingSha",
        "callerSha256","primaryPort","status","requests","posts","decryptedBytes","intentBeforeResponse",
        "allSocketsClosed","inputsCheckedClosed","code","completion","journal"])
        && ["schemaVersion","scope","case","ownerTag","manifestSha256","peerSha256","toolingSha","callerSha256","primaryPort"]
            .iter().all(|key|terminal.get(*key)==ready.get(*key))
        && terminal["state"]=="finished"&&terminal["status"]=="passed"&&terminal["code"].is_null()
        && terminal["requests"]==case.requests()&&terminal["posts"]==case.posts()&&terminal["intentBeforeResponse"]==json!(case.posts()==1)
        && terminal["allSocketsClosed"]==true&&terminal["inputsCheckedClosed"]==true
        && terminal["decryptedBytes"].as_u64().is_some_and(|n|(1..=case.requests()*8192).contains(&n))
        && terminal["completion"]==json!({"bytes":1,"eof":true,"closed":true,"primaryEmpty":true,
            "primaryUnexpected":0,"primaryClosed":true,"redirect":null})
        && keys(&terminal["journal"],&["marker","intentBytes","intentSha256","runBytes","runSha256","runId","attempt","leafCount","runReadBeforeCollision"])
        && terminal["journal"]["marker"]==marker&&preflight_protocol::hex(marker,32)
        && terminal["journal"]["intentBytes"].as_u64().is_some_and(|n|(1..=8192).contains(&n))
        && terminal["journal"]["intentSha256"].as_str().is_some_and(|s|preflight_protocol::hex(s,64))
        && terminal["journal"]["runReadBeforeCollision"]==json!(case==Case::JournalCollision)
        && if case==Case::PreGoRevocation {
            terminal["journal"]["leafCount"]==1&&["runBytes","runSha256","runId","attempt"].iter().all(|key|terminal["journal"][*key].is_null())
        } else {
            terminal["journal"]["leafCount"]==2&&terminal["journal"]["runId"]=="9001"&&terminal["journal"]["attempt"]==1
                &&terminal["journal"]["runBytes"].as_u64().is_some_and(|n|(1..=512).contains(&n))
                &&terminal["journal"]["runSha256"].as_str().is_some_and(|s|preflight_protocol::hex(s,64))
        }
}

#[derive(Default)]
struct Handshake { ready: Option<Instant>, claim_at: Option<Instant>, claim_error: Option<String>, go_written: Option<Instant> }
#[derive(Default)]
struct Scheduling {
    writer_owner: Option<u64>, writer: Option<oneshot::Sender<()>>, revoked: Option<Instant>, writer_released: Option<Instant>,
    settlement_owner: Option<u64>, reserved: Option<Instant>, entered: Option<Instant>, settlement: Option<oneshot::Sender<()>>,
    cancelled: Option<Instant>, cleanup_endpoint: Option<Instant>, unknown: Option<Instant>, unknown_dom: Option<Instant>,
    settlement_released: Option<Instant>, marker_reused: bool,
}
fn marker_reuse_allowed(case:Case, owners:usize, results:usize, used:bool, same_document:bool, prior_final:bool)->bool {
    case==Case::JournalCollision&&owners==3&&results==3&&!used&&same_document&&prior_final
}
fn first_error_allowed(case:Case,index:usize,code:&str)->bool {
    match (case,index) {
        (Case::PreGoRevocation,2)|(Case::FinalityRefusal,2)=>code=="cancelled",
        (Case::JournalCollision,4)=>matches!(code,"protocol_error"|"engine_failed"|"io_error"), _=>false,
    }
}
fn ordered(points:&[Option<Instant>])->bool {
    points.iter().all(Option::is_some)&&points.windows(2).all(|pair|pair[0]<=pair[1])
}
fn revocation_order(ready:Option<Instant>,revoked:Option<Instant>,released:Option<Instant>,claim:Option<Instant>,
    cleanup:Instant,settled:Instant)->bool {
    ordered(&[ready,cleanup.checked_sub(CLEANUP_TIME),revoked,released,claim,Some(settled)])&&settled<cleanup
}
fn finality_order(s:&Scheduling,settled:Instant)->bool {
    ordered(&[s.reserved,s.entered,s.cleanup_endpoint.and_then(|end|end.checked_sub(CLEANUP_TIME)),s.cancelled,
        s.cleanup_endpoint,s.unknown,s.unknown_dom,s.settlement_released,Some(settled)])
}
// Exact original owner references and bounded observations only. Scheduling
// senders belong to the original tasks; they grant no native admission.
pub(crate) struct ProductWitness {
    case: Case, created: Instant, supervisor: Mutex<Option<std::sync::Weak<Inner>>>,
    owners: Mutex<Vec<Arc<Owner>>>, results: Mutex<Vec<Value>>, preparations: Mutex<Vec<preflight_protocol::Prepared>>,
    io_checked: Mutex<std::collections::BTreeSet<u64>>, handshake: Mutex<BTreeMap<u64,Handshake>>,
    scheduling: Mutex<Scheduling>, observing: AsyncMutex<()>, failed: AtomicBool,
}
impl ProductWitness {
    pub(crate) fn new(case: Case) -> Arc<Self> { Arc::new(Self {case,created:Instant::now(),supervisor:Mutex::new(None),
        owners:Mutex::new(Vec::new()),results:Mutex::new(Vec::new()),preparations:Mutex::new(Vec::new()),
        io_checked:Mutex::new(std::collections::BTreeSet::new()),handshake:Mutex::new(BTreeMap::new()),
        scheduling:Mutex::new(Scheduling::default()),observing:AsyncMutex::new(()),failed:AtomicBool::new(false)}) }
    pub(crate) fn attach(self: &Arc<Self>, supervisor: &Supervisor) -> Check<()> {
        require(supervisor.can_exit()&&!supervisor.disabled()&&!supervisor.stopping()&&lock(&self.owners).is_empty(),"preflight_witness_setup")?;
        require(lock(&supervisor.inner.native_test.github).is_none(),"preflight_witness_exclusive")?;
        let mut slot=lock(&supervisor.inner.native_test.github_preflight);
        require(slot.is_none()&&lock(&self.supervisor).is_none(),"preflight_witness_setup")?;
        *lock(&self.supervisor)=Some(Arc::downgrade(&supervisor.inner));*slot=Some(self.clone());Ok(())
    }
    pub(crate) fn fail(&self) {
        self.failed.store(true,Ordering::SeqCst);
        let held={let mut s=lock(&self.scheduling);[(s.writer_owner,s.writer.take()),(s.settlement_owner,s.settlement.take())]};
        let owners=lock(&self.owners).clone();
        // Dropping the settlement sender would skip settle_originals. Actively
        // release each original once, outside witness/state mutexes. Stop the
        // exact held original first so failure release cannot authorize GO;
        // Owner::fail preserves any earlier failure and its cleanup endpoint.
        for (key,sender) in held {
            if let Some(sender)=sender {
                if let Some(owner)=owners.iter().find(|owner|Some(owner.key)==key) {owner.fail(BridgeError::cleanup_unknown());}
                let _=sender.send(());
            }
        }
    }
    pub(super) fn register(&self, owner: &Arc<Owner>) {
        let valid={let mut owners=lock(&self.owners);let index=owners.len();
            let selected=if index==0 {matches!(owner.profile,Profile::GitHubReadOnly)&&owner.preflight_request.is_none()}
                else {matches!(owner.profile,Profile::GitHubPreflight)&&owner.preflight_request.as_ref().is_some_and(|r|Some(r.kind())==self.case.kind(index))};
            let valid=index<self.case.owner_count()&&selected&&!owners.iter().any(|old|old.key==owner.key)
                &&owners.last().is_none_or(|old|lock(&old.state).terminal);
            if valid{owners.push(owner.clone());}valid};
        if !valid {self.fail();}
    }
    // Cleanup identity remains available after observation failure. It is the
    // exact registered Arc, never an owner key or a newly looked-up operation.
    fn registered_original_index(&self, owner:&Arc<Owner>)->Option<usize> {
        lock(&self.owners).iter().position(|old|Arc::ptr_eq(old,owner))
    }
    fn original_index(&self, owner:&Arc<Owner>)->Option<usize> {
        if self.failed.load(Ordering::SeqCst){None}else{self.registered_original_index(owner)}
    }
    fn original(&self,owner:&Arc<Owner>)->bool {self.original_index(owner).is_some()}
    fn last_original(&self)->Option<Arc<Owner>> {lock(&self.owners).get(self.case.owner_count()-1).cloned()}
    pub(crate) fn prepare_marker(&self,supervisor:&Supervisor,gate:&crate::asset_session::GitHubPreflightGoGate,fresh:String)->Check<String> {
        let result=(||{
            require(!self.failed.load(Ordering::SeqCst)&&preflight_protocol::hex(&fresh,32)
                &&lock(&self.supervisor).as_ref().and_then(std::sync::Weak::upgrade).is_some_and(|v|Arc::ptr_eq(&v,&supervisor.inner)),"preflight_marker_origin")?;
            if self.case!=Case::JournalCollision{return Ok(fresh);}
            let owners=lock(&self.owners).clone();let results=lock(&self.results).len();
            if owners.len()==1&&results==1{return Ok(fresh);}
            let first=owners.get(1).ok_or("preflight_marker_original")?;
            let same=first.preflight_gate.as_ref().is_some_and(|old|gate.same_original_document(old));
            let prior=owners.last().is_some_and(|old|lock(&old.state).terminal&&old.observer.try_lock().is_ok_and(|s|s.is_none()))
                &&supervisor.can_exit()&&!supervisor.disabled()&&!supervisor.stopping();
            let marker=first.preflight_request.as_ref().and_then(|r|r.action.as_ref()).map(|a|a.target.marker.clone()).ok_or("preflight_marker_original")?;
            let mut s=lock(&self.scheduling);
            require(marker_reuse_allowed(self.case,owners.len(),results,s.marker_reused,same,prior),"preflight_marker_reuse")?;
            s.marker_reused=true;Ok(marker)
        })();
        if result.is_err(){self.fail();}result
    }
    pub(super) fn original_case(&self, owner: &Arc<Owner>) -> Option<installed_native_fixture::Case> {
        let index=self.original_index(owner)?;
        if index==0{return Some(installed_native_fixture::Case::GitHubPreflightConnect);}
        if self.case==Case::PreGoRevocation&&index==2{return Some(installed_native_fixture::Case::GitHubPreflightRevocation);}
        if self.case==Case::JournalCollision&&index==4{return Some(installed_native_fixture::Case::GitHubPreflightCollision);}
        Some(if owner.preflight_request.as_ref().is_some_and(|r|r.kind()==preflight_protocol::Kind::Pending) {
            installed_native_fixture::Case::GitHubPreflightPending
        } else {installed_native_fixture::Case::GitHubPreflight})
    }
    pub(super) fn ready(&self, owner: &Arc<Owner>) {
        let at=Instant::now();let original=self.original(owner)&&matches!(owner.profile,Profile::GitHubPreflight)
            &&!owner.preflight_go_claimed.load(Ordering::SeqCst)&&at<owner.endpoint();
        let valid={let mut h=lock(&self.handshake);let valid=original&&!h.contains_key(&owner.key);
            if valid{h.insert(owner.key,Handshake{ready:Some(at),..Handshake::default()});}valid};
        if !valid{self.fail();}
    }
    pub(super) fn hold_ready(&self,owner:&Arc<Owner>)->Option<oneshot::Receiver<()>> {
        if self.case!=Case::PreGoRevocation||self.registered_original_index(owner)!=Some(2){return None;}
        let (sender,receiver)=oneshot::channel();
        let ready=lock(&self.handshake).get(&owner.key).is_some_and(|h|h.ready.is_some())&&!owner.failed();
        let (valid,rejected)={let mut s=lock(&self.scheduling);let valid=!self.failed.load(Ordering::SeqCst)
            &&s.writer_owner.is_none()&&s.writer.is_none()&&ready;
            if valid{s.writer_owner=Some(owner.key);s.writer=Some(sender);(true,None)}else{(false,Some(sender))}};
        if let Some(sender)=rejected {
            owner.fail(BridgeError::cleanup_unknown());let _=sender.send(());
        }
        if valid{Some(receiver)}else{self.fail();None}
    }
    pub(crate) fn ready_held(&self)->bool {
        if self.failed.load(Ordering::SeqCst)||self.case!=Case::PreGoRevocation{return false;}
        let s=lock(&self.scheduling);s.writer_owner.is_some()&&s.writer.is_some()&&s.revoked.is_none()
    }
    pub(crate) fn revoked(&self)->Check<()> {
        let result=(||{
            let owner=self.last_original().ok_or("preflight_revocation_original")?;
            require(self.case==Case::PreGoRevocation&&self.original_index(&owner)==Some(2)&&*owner.stop.borrow(),"preflight_revocation_original")?;
            let state=lock(&owner.state);let at=Instant::now();
            require(state.error.as_ref().is_some_and(|e|e.code=="cancelled")&&!state.unknown&&!state.terminal
                &&state.cleanup_endpoint.is_some_and(|end|at<end)&&!owner.preflight_go_claimed.load(Ordering::SeqCst),"preflight_revocation_stop")?;
            drop(state);
            let sender={let mut s=lock(&self.scheduling);require(s.writer_owner==Some(owner.key)&&s.revoked.is_none()
                &&s.writer_released.is_none(),"preflight_revocation_repeated")?;
                let sender=s.writer.take().ok_or("preflight_revocation_writer")?;s.revoked=Some(at);s.writer_released=Some(Instant::now());sender};
            sender.send(()).map_err(|_|"preflight_revocation_release")
        })();if result.is_err(){self.fail();}result
    }
    pub(super) fn claim_returned(&self,owner:&Arc<Owner>,result:&Result<Vec<u8>,BridgeError>) {
        let at=Instant::now();let original=self.original(owner);
        let valid={let mut h=lock(&self.handshake);match h.get_mut(&owner.key) {
            Some(h) if original&&h.ready.is_some_and(|ready|ready<=at)&&h.claim_at.is_none()=>{
                h.claim_at=Some(at);h.claim_error=result.as_ref().err().map(|e|e.code.clone());true},_=>false}};
        if !valid{self.fail();}
    }
    pub(super) fn go_written(&self, owner: &Arc<Owner>) {
        let at=Instant::now();let original=self.original(owner)&&owner.preflight_go_claimed.load(Ordering::SeqCst)&&at<owner.endpoint();
        let valid={let mut h=lock(&self.handshake);match h.get_mut(&owner.key) {
            Some(h) if original&&h.ready.zip(h.claim_at).is_some_and(|(r,c)|r<=c&&c<=at)&&h.claim_error.is_none()&&h.go_written.is_none()=>{h.go_written=Some(at);true},_=>false}};
        if !valid {self.fail();}
    }
    pub(super) fn reserve_settlement(&self,owner:&Arc<Owner>,r:&Resources)->bool {
        if self.case!=Case::FinalityRefusal||self.registered_original_index(owner)!=Some(2){return false;}
        let valid={let state=lock(&owner.state);state.error.is_none()&&state.cleanup_endpoint.is_none()&&!state.unknown&&!state.terminal
            &&Instant::now()<state.endpoint&&r.waited.as_ref().is_some_and(ExitStatus::success)&&r.writer.is_none()&&r.stdout.is_none()&&r.stderr.is_none()
            &&r.failed_writer.is_none()&&r.failed_stdout.is_none()&&r.failed_stderr.is_none()&&r.write_end.is_some_and(|w|w.complete)
            &&r.out_end.as_ref().is_some_and(|r|r.eof&&!r.overflow&&!r.bytes.is_empty())
            &&r.err_end.as_ref().is_some_and(|r|r.eof&&!r.overflow&&r.bytes.is_empty())&&!r.native_started&&r.native_settlement.is_none()};
        let reserved={let mut s=lock(&self.scheduling);let good=!self.failed.load(Ordering::SeqCst)
            &&valid&&s.settlement_owner.is_none()&&s.reserved.is_none();
            if good{s.settlement_owner=Some(owner.key);s.reserved=Some(Instant::now());}good};
        if !reserved{owner.fail(BridgeError::cleanup_unknown());self.fail();}reserved
    }
    pub(super) fn settlement_entered(&self,owner:&Arc<Owner>) {
        let original=self.original_index(owner)==Some(2)&&self.case==Case::FinalityRefusal;
        let state=lock(&owner.state);let clean=state.error.is_none()&&state.cleanup_endpoint.is_none()&&!state.unknown&&Instant::now()<state.endpoint;drop(state);
        let valid={let mut s=lock(&self.scheduling);let good=original&&clean&&s.settlement_owner==Some(owner.key)&&s.reserved.is_some()&&s.entered.is_none();
            if good{s.entered=Some(Instant::now());}good};if !valid{self.fail();}
    }
    pub(super) fn retain_settlement_sender(&self,owner:&Arc<Owner>,sender:oneshot::Sender<()>) {
        let original=self.registered_original_index(owner)==Some(2)&&self.case==Case::FinalityRefusal;
        let rejected={let mut s=lock(&self.scheduling);
            if !self.failed.load(Ordering::SeqCst)&&original&&s.settlement_owner==Some(owner.key)
                &&s.settlement.is_none()&&s.settlement_released.is_none(){s.settlement=Some(sender);None}else{Some(sender)}};
        if let Some(sender)=rejected {
            if original{owner.fail(BridgeError::cleanup_unknown());}
            let _=sender.send(());self.fail();
        }
    }
    pub(crate) fn settlement_waiting(&self)->bool {
        if self.failed.load(Ordering::SeqCst)||self.case!=Case::FinalityRefusal{return false;}
        let s=lock(&self.scheduling);s.entered.is_some()&&s.settlement.is_some()&&s.cancelled.is_none()
    }
    pub(crate) fn cancelled(&self,id:&str)->Check<()> {
        let result=(||{
            let owner=self.last_original().ok_or("preflight_cancel_original")?;let at=Instant::now();
            require(self.case==Case::FinalityRefusal&&owner.id==id&&self.original_index(&owner)==Some(2),"preflight_cancel_original")?;
            let state=lock(&owner.state);let end=state.cleanup_endpoint.ok_or("preflight_cancel_endpoint")?;
            require(state.error.as_ref().is_some_and(|e|e.code=="cancelled")&&!state.unknown&&!state.terminal&&at<state.endpoint
                &&at<end&&*owner.stop.borrow(),"preflight_cancel_first_failure")?;drop(state);
            let mut s=lock(&self.scheduling);
            require(s.settlement_owner==Some(owner.key)&&s.settlement.is_some()&&s.cancelled.is_none()
                &&s.entered.is_some_and(|entered|end.checked_sub(CLEANUP_TIME).is_some_and(|first|entered<=first&&first<=at)),"preflight_cancel_first_endpoint")?;
            s.cancelled=Some(at);s.cleanup_endpoint=Some(end);Ok(())
        })();if result.is_err(){self.fail();}result
    }
    fn observe_unknown(&self,owner:&Arc<Owner>)->Check<()> {
        let at=Instant::now();let state=lock(&owner.state);let mut s=lock(&self.scheduling);
        require(self.case==Case::FinalityRefusal&&state.unknown&&!state.terminal
            &&state.error.as_ref().is_some_and(|e|e.code=="cancelled")&&state.cleanup_endpoint==s.cleanup_endpoint
            &&s.cleanup_endpoint.is_some_and(|end|at>=end)&&s.cancelled.is_some()&&s.entered.is_some()
            &&s.settlement_owner==Some(owner.key)
            &&(s.settlement.is_some()&&s.settlement_released.is_none()
                ||s.unknown.is_some()&&s.unknown_dom.is_some()&&s.settlement.is_none()&&s.settlement_released.is_some()),"preflight_genuine_unknown")?;
        if s.unknown.is_none(){s.unknown=Some(at);}Ok(())
    }
    pub(crate) fn unknown_seen(&self)->bool {!self.failed.load(Ordering::SeqCst)&&lock(&self.scheduling).unknown.is_some()}
    pub(crate) fn release_after_unknown_dom(&self)->Check<()> {
        let result=(||{
            let owner=self.last_original().ok_or("preflight_unknown_original")?;
            require(self.original_index(&owner)==Some(2)&&self.case==Case::FinalityRefusal
                &&owner.preflight_receipt.as_ref().is_some_and(|r|matches!(*lock(r),GitHubPreflightReceipt::RetainedUnknown)),"preflight_unknown_receipt")?;
            let sender={let mut s=lock(&self.scheduling);let at=Instant::now();
                require(s.unknown.is_some_and(|v|v<=at)&&s.unknown_dom.is_none()&&s.settlement_released.is_none(),"preflight_unknown_dom")?;
                let sender=s.settlement.take().ok_or("preflight_unknown_original_sender")?;
                s.unknown_dom=Some(at);s.settlement_released=Some(Instant::now());sender};
            sender.send(()).map_err(|_|"preflight_unknown_release")
        })();if result.is_err(){self.fail();}result
    }
    pub(super) fn observe_settled_io(&self, owner: &Arc<Owner>, resources: &Resources) {
        let index=self.original_index(owner);let before=index.is_some_and(|index|self.case.before_go_failure(index));
        let valid=index.is_some()&&resources.write_end.is_some_and(|w|w.complete!=before)
            &&resources.writer.is_none()&&resources.stdout.is_none()&&resources.stderr.is_none()
            &&resources.failed_writer.is_none()&&resources.failed_stdout.is_none()&&resources.failed_stderr.is_none()
            &&resources.waited.is_some()&&resources.child.is_some()
            &&resources.out_end.as_ref().is_some_and(|r|r.eof&&!r.overflow&&(!before||r.bytes.is_empty()))
            &&resources.err_end.as_ref().is_some_and(|r|r.eof&&!r.overflow&&(r.bytes.is_empty()
                ||before&&r.bytes==b"Mobile Release Kit private preflight action failed.\n"))
            &&lock(&self.io_checked).insert(owner.key);
        if !valid{self.fail();}
    }
    pub(crate) async fn observe_retired(&self, end: Instant) -> Check<bool> {
        let _observing=self.observing.lock().await;let result=self.observe_retired_inner(end).await;
        if result.is_err(){self.fail();}result
    }
    async fn observe_retired_inner(&self, end: Instant) -> Check<bool> {
        use std::os::unix::process::ExitStatusExt;
        require(!self.failed.load(Ordering::SeqCst),"preflight_witness_failed")?;
        let owners=lock(&self.owners).clone();let completed=lock(&self.results).len();
        for (index,owner) in owners.iter().enumerate().skip(completed) {
            let original_case=self.original_case(owner).ok_or("preflight_original_case")?;
            let negative=self.case.negative()&&index==self.case.owner_count()-1;
            let mut error_code:Option<String>=None;
            let (settled_at,was_unknown,reason,effect,marker)=if index==0 {
                let receipt=owner.github_receipt.as_ref().map(|r|lock(r).clone()).ok_or("preflight_connect_receipt")?;
                require(!matches!(receipt,GitHubReadReceipt::RetainedUnknown),"preflight_connect_unknown")?;
                let GitHubReadReceipt::Settled{outcome,settled_at,was_unknown}=receipt else{return Ok(false);};
                let outcome=outcome.map_err(|_|"preflight_connect_result")?;
                require(outcome.control.reason==github_protocol::Reason::None&&outcome.control.credential_expires_at.is_none()
                    &&outcome.control.cooldown_seconds.is_none()&&!outcome.control.cooldown_blocked
                    &&outcome.facts.account.value.as_ref().is_some_and(|a|a.id=="11"&&a.login=="owner")
                    &&outcome.facts.repository.value.as_ref().is_some_and(|r|r.id=="22"&&r.full_name=="owner/app"
                        &&r.permissions.push==github_protocol::Permission::ReportedAllowed),"preflight_connect_result")?;
                (settled_at,was_unknown,json!("none"),json!("none"),Value::Null)
            } else {
                let receipt=owner.preflight_receipt.as_ref().map(|r|lock(r).clone()).ok_or("preflight_action_receipt")?;
                if matches!(receipt,GitHubPreflightReceipt::RetainedUnknown){self.observe_unknown(owner)?;return Ok(false);}
                let GitHubPreflightReceipt::Settled{outcome,settled_at,was_unknown}=receipt else{return Ok(false);};
                let request=owner.preflight_request.as_ref().ok_or("preflight_action_request")?;
                require(request.valid()&&Some(request.kind())==self.case.kind(index),"preflight_action_request")?;
                if index>1&&request.kind()!=preflight_protocol::Kind::Prepare {
                    let dispatch=owners.get(2).and_then(|o|o.preflight_request.as_ref()).ok_or("preflight_action_original")?;
                    require(dispatch.home.is_some()&&request.home==dispatch.home,"preflight_action_home")?;
                }
                if negative {
                    let action=request.action.as_ref().ok_or("preflight_negative_request")?;
                    let prepared=lock(&self.preparations).last().cloned().ok_or("preflight_negative_prepared")?;
                    require(prepared.publisher_bound()&&action.prepared.as_ref()==Some(&prepared)&&action.target==prepared.target,"preflight_negative_prepared")?;
                    let error=outcome.err().ok_or("preflight_negative_unexpected_success")?;
                    require(if self.case==Case::FinalityRefusal{error.code=="cleanup_unknown"}else{first_error_allowed(self.case,index,&error.code)},"preflight_negative_error")?;
                    let expected=crate::github_preflight_session::outcome_reason(&error);error_code=Some(error.code);
                    (settled_at,was_unknown,json!(expected),json!(if self.case==Case::FinalityRefusal{preflight_protocol::Effect::PotentiallyApplied}else{preflight_protocol::Effect::NotSent}),
                        json!(action.target.marker))
                } else {
                    let reply=outcome.map_err(|_|"preflight_action_result")?;
                    if request.kind()==preflight_protocol::Kind::Pending {
                        let first=lock(&self.preparations).first().cloned().ok_or("preflight_action_original")?;
                        let records=reply.pending.as_ref().ok_or("preflight_pending_result")?;
                        require(reply.result.is_none()&&request.action.is_none()&&request.pending_scope.as_ref().is_some_and(|scope|scope.matches(&first.target))
                            &&records.len()==1&&records[0].valid()&&records[0].prepared==first&&records[0].run_id.is_none(),"preflight_pending_result")?;
                        (settled_at,was_unknown,json!("none"),json!("none"),json!(first.target.marker))
                    } else {
                        let result=reply.result.as_ref().ok_or("preflight_action_result")?;
                        require(reply.pending.is_none()&&result.valid(request)&&Some(result.action)==self.case.kind(index),"preflight_action_result")?;
                        let action=request.action.as_ref().ok_or("preflight_action_request")?;
                        let preparing=request.kind()==preflight_protocol::Kind::Prepare;
                        let prepared=if preparing{result.prepared.as_ref()}else{action.prepared.as_ref()}.ok_or("preflight_action_prepared")?;
                        require(prepared.publisher_bound()&&prepared.target==action.target&&prepared.source_sha=="a".repeat(40)&&prepared.workflow_id=="101"
                            &&prepared.target.repository=="owner/app"&&prepared.target.account_id=="11"&&prepared.target.repository_id=="22"
                            &&prepared.target.branch=="main"&&prepared.target.platform==preflight_protocol::Platform::Android,"preflight_action_binding")?;
                        {let mut preparations=lock(&self.preparations);
                            if preparing{require(preparations.is_empty()||self.case==Case::JournalCollision&&index==3&&preparations.len()==1
                                &&preparations[0].target==prepared.target&&lock(&self.scheduling).marker_reused,"preflight_prepare_sequence")?;preparations.push(prepared.clone());}
                            else{require(preparations.last()==Some(prepared),"preflight_action_original")?;}}
                        let lost=index==2&&self.case==Case::ResponseLoss;let dispatch=request.kind()==preflight_protocol::Kind::Dispatch;
                        require(result.reason==(if lost{preflight_protocol::Reason::TlsFailed}else{preflight_protocol::Reason::None})
                            &&result.effect==(if !dispatch{preflight_protocol::Effect::None}else if lost{preflight_protocol::Effect::PotentiallyApplied}else{preflight_protocol::Effect::Accepted})
                            &&result.run_id.as_deref()==(if preparing||lost{None}else{Some("9001")}),"preflight_action_outcome")?;
                        if matches!(request.kind(),preflight_protocol::Kind::Track|preflight_protocol::Kind::Reconcile) {
                            let run=result.run.as_ref().ok_or("preflight_action_run")?;
                            require(run.valid(prepared)&&run.id=="9001"&&run.conclusion==Some(preflight_protocol::Conclusion::Success)
                                &&run.jobs.len()==2&&run.jobs.iter().all(|j|j.status==preflight_protocol::RunStatus::Completed&&j.conclusion==Some(preflight_protocol::Conclusion::Success)),"preflight_action_run")?;
                        }
                        (settled_at,was_unknown,json!(result.reason),json!(result.effect),json!(action.target.marker))
                    }
                }
            };
            let mut observer=owner.observer.lock().await;let handle=observer.as_mut().ok_or("preflight_original_observer")?;
            let joined=tokio::time::timeout_at(end.into(),handle).await.map_err(|_|"preflight_observer_deadline")?;
            require(joined.is_ok(),"preflight_observer_join")?;observer.take();drop(observer);
            let resources=owner.resources.try_lock().map_err(|_|"preflight_original_resources")?;let state=lock(&owner.state);
            require(state.terminal&&state.driver_join==ManagementJoin::Returned&&state.watchdog_join==ManagementJoin::Returned
                &&lock(&owner.permit).is_none()&&owner.driver.try_lock().is_ok_and(|s|s.is_none())&&owner.watchdog.try_lock().is_ok_and(|s|s.is_none()),"preflight_management_final")?;
            let late=self.case==Case::FinalityRefusal&&negative;
            if negative {
                require(state.error.as_ref().is_some_and(|e|first_error_allowed(self.case,index,&e.code)),"preflight_first_error")?;
                let endpoint=state.cleanup_endpoint.ok_or("preflight_first_cleanup_endpoint")?;
                if late {
                    let s=lock(&self.scheduling);
                    require(state.unknown&&was_unknown&&s.cleanup_endpoint==Some(endpoint)&&finality_order(&s,settled_at)
                        &&matches!(state.watchdog_end,Some(WatchdogEnd::CleanupExpired{endpoint:e,observed_at}) if e==endpoint&&observed_at>=e),"preflight_late_finality")?;
                } else {
                    require(!state.unknown&&!was_unknown&&settled_at<endpoint&&settled_at<state.endpoint
                        &&error_code.as_deref()==state.error.as_ref().map(|e|e.code.as_str())
                        &&matches!(state.watchdog_end,Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))),"preflight_negative_settled")?;
                }
            } else {
                require(!state.unknown&&!was_unknown&&state.error.is_none()&&state.cleanup_endpoint.is_none()&&settled_at<state.endpoint
                    &&matches!(state.watchdog_end,Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))),"preflight_positive_settled")?;
            }
            let (ready,claim,go)=if index==0{(false,false,false)}else {
                let h=lock(&self.handshake);let h=h.get(&owner.key);
                if self.case==Case::JournalCollision&&negative {
                    require(h.is_none()&&!owner.preflight_go_claimed.load(Ordering::SeqCst),"preflight_collision_no_ready")?;(false,false,false)
                } else if self.case==Case::PreGoRevocation&&negative {
                    let h=h.ok_or("preflight_revocation_handshake")?;let s=lock(&self.scheduling);
                    require(state.cleanup_endpoint.is_some_and(|cleanup|revocation_order(h.ready,s.revoked,s.writer_released,h.claim_at,cleanup,settled_at))
                        &&h.claim_error.as_deref()==Some("github_preflight_refused_target_changed")&&h.go_written.is_none()
                        &&!owner.preflight_go_claimed.load(Ordering::SeqCst),"preflight_revocation_claim")?;(true,true,false)
                } else {
                    let h=h.ok_or("preflight_action_handshake")?;
                    require(owner.preflight_go_claimed.load(Ordering::SeqCst)&&h.ready.zip(h.claim_at).is_some_and(|(a,b)|a<=b)
                        &&h.claim_at.zip(h.go_written).is_some_and(|(a,b)|a<=b&&b<state.endpoint&&b<=settled_at)
                        &&h.claim_error.is_none(),"preflight_action_handshake")?;(true,true,true)
                }
            };
            let custody=if index==0{resources.github_readonly.as_ref().is_some_and(|s|lock(s).settled())&&resources.github_preflight.is_none()}
                else{resources.github_preflight.as_ref().is_some_and(|s|lock(s).settled())&&resources.github_readonly.is_none()};
            let before=self.case.before_go_failure(index);let exit=resources.waited.as_ref().ok_or("preflight_child_wait")?;
            require(if before{!exit.success()&&(exit.code()==Some(70)||resources.kill_attempted&&exit.signal()==Some(9))}else{exit.success()},"preflight_child_exit")?;
            require(custody&&resources.passive.is_none()&&resources.github_release.is_none()
                &&resources.inspection_return==Some(ManagementJoin::Returned)&&resources.inspection.is_none()&&resources.inspection_error.is_none()
                &&resources.acquisition_return==Some(ManagementJoin::Returned)&&resources.acquisition.is_none()&&resources.acquisition_error.is_none()
                &&resources.child.is_none()&&resources.writer.is_none()&&resources.stdout.is_none()&&resources.stderr.is_none()
                &&resources.failed_writer.is_none()&&resources.failed_stdout.is_none()&&resources.failed_stderr.is_none()
                &&resources.native_started&&resources.native_settlement.is_none()&&matches!(resources.native_return,Some(Ok(CloseOutcome::Settled)))
                &&resources.native_observation.is_none()&&resources.native_observation_return==Some(ManagementJoin::Returned)
                &&resources.native_observation_failure.is_none()&&resources.native_snapshots.len()==1
                &&installed_native_fixture::preflight_snapshot_clear(&resources.native_snapshots[0],original_case)
                &&resources.write_end.is_some_and(|w|w.complete!=before)&&resources.out_end.is_none()&&resources.err_end.is_none()
                &&lock(&self.io_checked).contains(&owner.key),"preflight_native_final")?;
            lock(&self.results).push(json!({"operationId":owner.id,"kind":if index==0{json!("connect")}else{json!(self.case.kind(index))},
                "manifestSha256":RuntimeProfile::MANIFEST,"reason":reason,"effect":effect,"marker":marker,
                "terminal":true,"originalObserverJoined":true,"nativeSettled":true,"environmentClear":true,
                "readyObserved":ready,"claimReturned":claim,"goWritten":go,"goClaimed":owner.preflight_go_claimed.load(Ordering::SeqCst),
                "negative":negative,"wasUnknown":was_unknown,"errorCode":error_code,"firstError":state.error.as_ref().map(|e|e.code.as_str()),
                "exitCode":exit.code(),"exitSignal":exit.signal(),"ownedStopAttempted":resources.kill_attempted,
                "settledNs":settled_at.duration_since(self.created).as_nanos(),
                "maps":installed_native_fixture::snapshot_value(&resources.native_snapshots[0])}));
        }
        Ok(lock(&self.results).len()==owners.len()&&!owners.is_empty())
    }
    pub(crate) fn complete(&self, supervisor: &Supervisor) -> bool {
        let owners=lock(&self.owners).len();let results=lock(&self.results).len();let io=lock(&self.io_checked).len();
        let handshakes=lock(&self.handshake).len();let schedule=lock(&self.scheduling);
        let clear=schedule.writer.is_none()&&schedule.settlement.is_none()
            &&schedule.marker_reused==(self.case==Case::JournalCollision)
            &&(if self.case==Case::FinalityRefusal{schedule.unknown.is_some()&&schedule.unknown_dom.is_some()&&schedule.settlement_released.is_some()}
              else if self.case==Case::PreGoRevocation{schedule.revoked.is_some()&&schedule.writer_released.is_some()}else{true});
        drop(schedule);
        !self.failed.load(Ordering::SeqCst)&&owners==self.case.owner_count()&&results==owners&&io==owners&&clear
            &&handshakes==self.case.action_count()-usize::from(self.case==Case::JournalCollision)
            &&supervisor.can_exit()&&supervisor.disabled()==(self.case==Case::FinalityRefusal)
    }
    pub(crate) fn evidence(&self) -> Vec<Value> {lock(&self.results).clone()}
    pub(crate) fn marker(&self) -> Option<String> {lock(&self.owners).get(1).and_then(|o|o.preflight_request.as_ref()?.action.as_ref().map(|a|a.target.marker.clone()))}
    pub(crate) fn timeline(&self)->Value {
        let ns=|at:Option<Instant>|at.map(|at|at.duration_since(self.created).as_nanos());
        let owner=lock(&self.owners).get(2).cloned();
        let h=owner.and_then(|o|lock(&self.handshake).get(&o.key).map(|h|(h.ready,h.claim_at)));
        let s=lock(&self.scheduling);
        json!({"mechanism":match self.case{Case::PreGoRevocation=>"original-writer-scheduling",Case::JournalCollision=>"same-original-marker",Case::FinalityRefusal=>"original-settlement-scheduling",_=>"none"},
            "kernelCloseFaultInjected":false,"readyNs":ns(h.and_then(|h|h.0)),"revocationReplyNs":ns(s.revoked),"writerReleasedNs":ns(s.writer_released),
            "claimReturnedNs":ns(h.and_then(|h|h.1)),"settlementReservedNs":ns(s.reserved),"settlementEnteredNs":ns(s.entered),
            "cancelReplyNs":ns(s.cancelled),"cleanupEndpointNs":ns(s.cleanup_endpoint),"unknownReceiptNs":ns(s.unknown),
            "unknownDomNs":ns(s.unknown_dom),"settlementReleasedNs":ns(s.settlement_released),"markerReused":s.marker_reused})
    }
}

// Closed receipt/mapping contract checks only; fixture DATA never grants an
// owner, a socket, a native-runtime profile or completed implementation evidence.
pub(crate) fn assert_contracts() {
    RuntimeProfile::assert_contracts();
    installed_native_fixture::assert_preflight_observation_roles();
    let marker="e".repeat(32);
    for case in Case::ALL {
        use preflight_protocol::Kind::{Prepare,Dispatch,Track,Pending,Reconcile};
        let expected=match case {
            Case::Success=>vec![Prepare,Dispatch,Track],Case::ResponseLoss=>vec![Prepare,Dispatch,Pending,Reconcile],
            Case::JournalCollision=>vec![Prepare,Dispatch,Prepare,Dispatch],_=>vec![Prepare,Dispatch],
        };
        assert_eq!(case.action_count(),expected.len());assert_eq!(case.owner_count(),expected.len()+1);
        assert_eq!((1..case.owner_count()).map(|index|case.kind(index).unwrap()).collect::<Vec<_>>(),expected);
        assert_eq!(case.kind(0),None);assert_eq!(case.kind(case.owner_count()),None);
        assert_eq!(Case::parse(std::ffi::OsStr::new(case.name())),Some(case));
        assert_eq!((0..case.owner_count()).filter(|index|case.before_go_failure(*index)).collect::<Vec<_>>(),match case {
            Case::PreGoRevocation=>vec![2],Case::JournalCollision=>vec![4],_=>vec![],
        });
        let ready=ready_binding(case,"0123456789abcdef");
        let journal=if case==Case::PreGoRevocation {
            json!({"marker":marker,"intentBytes":1024,"intentSha256":"b".repeat(64),"runBytes":null,"runSha256":null,
                "runId":null,"attempt":null,"leafCount":1,"runReadBeforeCollision":false})
        } else {
            json!({"marker":marker,"intentBytes":1024,"intentSha256":"b".repeat(64),"runBytes":164,"runSha256":"c".repeat(64),
                "runId":"9001","attempt":1,"leafCount":2,"runReadBeforeCollision":case==Case::JournalCollision})
        };
        let mut terminal=ready.clone();
        terminal.as_object_mut().unwrap().extend(serde_json::from_value::<serde_json::Map<String,Value>>(json!({
            "state":"finished","status":"passed","code":null,"requests":case.requests(),"posts":case.posts(),
            "decryptedBytes":4096,"intentBeforeResponse":case.posts()==1,"allSocketsClosed":true,"inputsCheckedClosed":true,
            "completion":{"bytes":1,"eof":true,"closed":true,"primaryEmpty":true,"primaryUnexpected":0,"primaryClosed":true,"redirect":null},
            "journal":journal
        })).unwrap());
        assert!(terminal_valid(&terminal,&ready,case,&marker));
        for key in ["allSocketsClosed","inputsCheckedClosed","intentBeforeResponse","journal","completion","ownerTag"] {
            let mut changed=terminal.clone();changed.as_object_mut().unwrap().remove(key);
            assert!(!terminal_valid(&changed,&ready,case,&marker));
        }
        for (key,value) in [("posts",json!(case.posts()+1)),("requests",json!(case.requests()+1)),("decryptedBytes",json!(0)),
            ("allSocketsClosed",json!(false)),("inputsCheckedClosed",json!(false)),("intentBeforeResponse",json!(case.posts()!=1)),
            ("status",json!("failed")),("code",json!("cleanup")),("ownerTag",json!("fedcba9876543210")),
            ("manifestSha256",json!(github_tls_peer_owner::installed::N)),("extra",json!(true))] {
            let mut changed=terminal.clone();changed[key]=value;
            assert!(!terminal_valid(&changed,&ready,case,&marker));
        }
        for (key,value) in [("marker",json!("d".repeat(32))),("runId",json!("9002")),("attempt",json!(2)),
            ("runBytes",json!(513)),("intentBytes",json!(8193)),("intentSha256",json!("not-a-digest")),("extra",json!(true)),
            ("leafCount",json!(3)),("runReadBeforeCollision",json!(case!=Case::JournalCollision))] {
            let mut changed=terminal.clone();changed["journal"][key]=value;
            assert!(!terminal_valid(&changed,&ready,case,&marker));
        }
        let mut wrong_roster=terminal.clone();wrong_roster["journal"]["leafCount"]=json!(if case==Case::PreGoRevocation{2}else{1});
        assert!(!terminal_valid(&wrong_roster,&ready,case,&marker));
        for (key,value) in [("bytes",json!(2)),("eof",json!(false)),("closed",json!(false)),("primaryEmpty",json!(false)),
            ("primaryUnexpected",json!(1)),("primaryClosed",json!(false)),("redirect",json!({}))] {
            let mut changed=terminal.clone();changed["completion"][key]=value;
            assert!(!terminal_valid(&changed,&ready,case,&marker));
        }
        for other in Case::ALL.into_iter().filter(|other|*other!=case) {
            assert!(!terminal_valid(&terminal,&ready_binding(other,"0123456789abcdef"),other,&marker));
        }
        assert_eq!(marker_reuse_allowed(case,3,3,false,true,true),case==Case::JournalCollision);
        for index in 0..=case.owner_count() {
            for code in ["cancelled","protocol_error","engine_failed","io_error","cleanup_unknown","runtime_unavailable","shutting_down"] {
                let expected=match (case,index,code) {
                    (Case::PreGoRevocation|Case::FinalityRefusal,2,"cancelled")=>true,
                    (Case::JournalCollision,4,"protocol_error"|"engine_failed"|"io_error")=>true,_=>false,
                };
                assert_eq!(first_error_allowed(case,index,code),expected);
            }
        }
    }
    assert!(Case::parse(std::ffi::OsStr::new("github-preflight-negative")).is_none());
    for (owners,results,used,same,finality) in [(2,3,false,true,true),(4,3,false,true,true),(3,2,false,true,true),
        (3,3,true,true,true),(3,3,false,false,true),(3,3,false,true,false)] {
        assert!(!marker_reuse_allowed(Case::JournalCollision,owners,results,used,same,finality));
    }
    for (code,reason) in [("protocol_error",preflight_protocol::Reason::ResponseInvalid),
        ("engine_failed",preflight_protocol::Reason::NetworkUnavailable),("io_error",preflight_protocol::Reason::NetworkUnavailable),
        ("cancelled",preflight_protocol::Reason::Cancelled),("cleanup_unknown",preflight_protocol::Reason::CleanupUnknown)] {
        assert_eq!(crate::github_preflight_session::outcome_reason(&BridgeError::new(code,"Supplied contract DATA.")),reason);
    }
    // Pure timestamps: receipt/DOM release order cannot substitute for the
    // original cleanup endpoint or grant success while settlement is pending.
    let at=Instant::now();let point=|millis|Some(at+Duration::from_millis(millis));
    assert!(revocation_order(point(0),point(2),point(3),point(4),at+CLEANUP_TIME+Duration::from_millis(1),at+Duration::from_millis(5)));
    assert!(!revocation_order(point(0),point(3),point(2),point(4),at+CLEANUP_TIME+Duration::from_millis(1),at+Duration::from_millis(5)));
    assert!(!revocation_order(point(0),point(2),point(3),None,at+CLEANUP_TIME+Duration::from_millis(1),at+Duration::from_millis(5)));
    let mut schedule=Scheduling{reserved:point(0),entered:point(1),cancelled:point(3),cleanup_endpoint:point(2002),
        unknown:point(2003),unknown_dom:point(2004),settlement_released:point(2005),..Scheduling::default()};
    assert!(finality_order(&schedule,at+Duration::from_millis(2006)));
    schedule.unknown=point(2001);assert!(!finality_order(&schedule,at+Duration::from_millis(2006)));schedule.unknown=point(2003);
    schedule.settlement_released=point(2003);assert!(!finality_order(&schedule,at+Duration::from_millis(2006)));
    schedule.settlement_released=None;assert!(!finality_order(&schedule,at+Duration::from_millis(2006)));
    let witness=ProductWitness::new(Case::FinalityRefusal);
    let (writer,mut write_wait)=oneshot::channel();let (settlement,mut close_wait)=oneshot::channel();
    {let mut s=lock(&witness.scheduling);s.writer=Some(writer);s.settlement=Some(settlement);}
    witness.fail();assert!(witness.failed.load(Ordering::SeqCst));
    assert_eq!(write_wait.try_recv(),Ok(()));assert_eq!(close_wait.try_recv(),Ok(()));
    {let s=lock(&witness.scheduling);assert!(s.writer.is_none()&&s.settlement.is_none());}
    // Pure descriptorless owners and real oneshot senders: no process, native
    // runtime, worker, timer or replacement operation is created by this check.
    let originals=|case| {
        let witness=ProductWitness::new(case);
        let owners=(1..=3).map(|key| {
            let mut owner=super::tests::inert_owner();owner.key=key;owner.id=format!("query-{key}");
            owner.profile=if key==1{Profile::GitHubReadOnly}else{Profile::GitHubPreflight};
            Arc::new(owner)
        }).collect::<Vec<_>>();
        let last=owners[2].clone();*lock(&witness.owners)=owners;(witness,last)
    };
    for failure_before_enqueue in [false,true] {
        let (witness,owner)=originals(Case::PreGoRevocation);witness.ready(&owner);
        if failure_before_enqueue{witness.fail();}
        let held=witness.hold_ready(&owner);
        if failure_before_enqueue{assert!(held.is_none());}
        else {let mut receiver=held.expect("original READY hold");witness.fail();assert_eq!(receiver.try_recv(),Ok(()));}
        assert!(owner.failed()&&*owner.stop.borrow());
        assert!(lock(&witness.scheduling).writer.is_none());
    }
    let (witness,owner)=originals(Case::FinalityRefusal);
    witness.fail();assert!(!witness.reserve_settlement(&owner,&Resources::default()));
    assert!(owner.failed()&&*owner.stop.borrow());
    for failure_before_enqueue in [false,true] {
        let (witness,owner)=originals(Case::FinalityRefusal);
        {let mut s=lock(&witness.scheduling);s.settlement_owner=Some(owner.key);s.reserved=Some(Instant::now());}
        if failure_before_enqueue{witness.fail();}
        let (sender,mut receiver)=oneshot::channel();witness.retain_settlement_sender(&owner,sender);
        if !failure_before_enqueue{witness.fail();}
        assert_eq!(receiver.try_recv(),Ok(()));assert!(owner.failed()&&*owner.stop.borrow());
        assert!(lock(&witness.scheduling).settlement.is_none());
    }
    let (witness,owner)=originals(Case::FinalityRefusal);
    owner.fail(BridgeError::new("cancelled","Pure original cancellation DATA."));
    let first={let s=lock(&owner.state);(s.error.clone(),s.cleanup_endpoint)};
    witness.fail();let (sender,mut receiver)=oneshot::channel();witness.retain_settlement_sender(&owner,sender);
    assert_eq!(receiver.try_recv(),Ok(()));
    {let s=lock(&owner.state);assert_eq!((s.error.clone(),s.cleanup_endpoint),first);}
    let (witness,original)=originals(Case::FinalityRefusal);
    let mut other=super::tests::inert_owner();other.key=original.key;let unrelated=Arc::new(other);
    let (sender,mut receiver)=oneshot::channel();witness.retain_settlement_sender(&unrelated,sender);
    assert_eq!(receiver.try_recv(),Ok(()));assert!(!unrelated.failed());
    assert!(witness.failed.load(Ordering::SeqCst));
}
