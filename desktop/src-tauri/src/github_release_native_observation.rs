//! Three scoped installed R observations; never a release dispatch to GitHub.
//! Witnesses borrow the original R slots, GO gate, Supervisor and physical
//! TLS Peer. They do not create a replacement owner, credential or deadline.
use super::*;
use std::path::{Path,PathBuf};
use serde_json::json;
use sha2::{Digest,Sha256};
use crate::runtime::GitHubReleaseObservationProfile as RuntimeProfile;
use github_tls_peer_owner::{Arrivals,Peer,PeerControl,installed::{domain_environment,fixed_input,N,PEER_SHA as SUPPORT_SHA}};
type Check<T> = Result<T,&'static str>;
fn require(value:bool,code:&'static str)->Check<()> {if value{Ok(())}else{Err(code)}}
fn keys(value:&Value,expected:&[&str])->bool {value.as_object().is_some_and(|v|v.len()==expected.len()&&expected.iter().all(|k|v.contains_key(*k)))}
const PEER_SOURCE:&[u8]=include_bytes!("../tests/fixtures/github_release_peer.py");
const SCOPE:&str="github-release-installed-peer-v1";
pub(crate) fn peer_sha256()->String {format!("{:x}",Sha256::digest(PEER_SOURCE))}
pub(crate) fn callers()->Value {json!({"candidate":RuntimeProfile::CANDIDATE_SHA256,
    "external-testing":RuntimeProfile::EXTERNAL_SHA256,"production-submit":RuntimeProfile::PRODUCTION_SHA256})}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum Case {NormalPending,ResponseLoss,PreGoRevocation}
impl Case {
    pub(crate) const ALL:[Self;3]=[Self::NormalPending,Self::ResponseLoss,Self::PreGoRevocation];
    pub(crate) fn name(self)->&'static str {match self {
        Self::NormalPending=>"github-release-normal-pending",Self::ResponseLoss=>"github-release-response-loss",
        Self::PreGoRevocation=>"github-release-pre-go-revocation",
    }}
    pub(crate) fn parse(value:&std::ffi::OsStr)->Option<Self> {Self::ALL.into_iter().find(|c|value==std::ffi::OsStr::new(c.name()))}
    fn script(self)->&'static str {self.name().strip_prefix("github-").unwrap()}
    pub(crate) fn manifest(self)->&'static str {if self==Self::NormalPending{N}else{RuntimeProfile::MANIFEST}}
    pub(crate) fn profile(self)->Option<RuntimeProfile> {if self==Self::NormalPending{None}else{Some(RuntimeProfile::Synthetic)}}
    pub(crate) fn owner_count(self)->usize {match self{Self::NormalPending=>2,Self::ResponseLoss=>5,Self::PreGoRevocation=>3}}
    pub(crate) fn action_count(self)->usize {self.owner_count()-1}
    fn requests(self)->u64 {match self{Self::NormalPending=>4,Self::ResponseLoss=>25,Self::PreGoRevocation=>14}}
    fn posts(self)->u64 {u64::from(self==Self::ResponseLoss)}
    pub(crate) fn before_go_failure(self,index:usize)->bool {self==Self::PreGoRevocation&&index==2}
    pub(crate) fn kind(self,index:usize)->Option<release_protocol::Kind> {
        use release_protocol::Kind::*;
        match (self,index) {
            (Self::NormalPending,1)=>Some(Pending),
            (Self::ResponseLoss|Self::PreGoRevocation,1)=>Some(Prepare),
            (Self::ResponseLoss|Self::PreGoRevocation,2)=>Some(Dispatch),
            (Self::ResponseLoss,3)=>Some(Pending),(Self::ResponseLoss,4)=>Some(Reconcile),_=>None,
        }
    }
    pub(crate) fn final_kind(self)->release_protocol::Kind {self.kind(self.owner_count()-1).unwrap()}
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
        fixed_input(&staged.join("github_release_peer.py"),PEER_SOURCE.len() as u64,&peer_sha256(),0o444,end)?;
        fixed_input(&staged.join("github_tls_peer.py"),61665,SUPPORT_SHA,0o444,end)?;
        for (name,size,hash) in [
            ("mobile-candidate.yml",2322,RuntimeProfile::CANDIDATE_SHA256),
            ("mobile-external-testing.yml",3098,RuntimeProfile::EXTERNAL_SHA256),
            ("mobile-production-submit.yml",3835,RuntimeProfile::PRODUCTION_SHA256),
        ] { fixed_input(&staged.join(name),size,hash,0o444,end)?; }
        for (name,size,hash) in [
            ("api-valid.pem",786,"33f6acd10b8d466078525b80464a1c5938266b1084ea5aabf43b348bd7dca6f2"),
            ("server-key.pem",241,"33332bb26fd6e394d067f7e2df563d496f934e0a098de1e3039169fb8d4ee109"),
        ] { fixed_input(&staged.join("github_tls").join(name),size,hash,0o444,end)?; }
        Ok(())
    }
    pub(crate) fn prepare(&mut self, root: PathBuf, end: Instant) -> Check<()> {
        require(self.root.is_none()&&!self.materials_checked&&self.original.endpoint.is_none(),"release_peer_repeated_setup")?;
        self.root=Some(root.clone()); // A failed original admission cannot retry.
        let mut environment=domain_environment(&root,end)?;
        self.inputs(&root,end)?;
        let tag=format!("{:x}",Sha256::digest(format!("{}:{}:{}:{}",self.case.name(),
            root.display(),std::process::id(),option_env!("GITHUB_SHA").unwrap_or("")).as_bytes()))[..16].to_owned();
        environment.extend(BTreeMap::from([
            ("MRK_DESKTOP_HOSTED_CHECKS".into(),"github-release-installed-tls-v1".into()),
            ("GITHUB_ACTIONS".into(),"true".into()),("RUNNER_ENVIRONMENT".into(),"github-hosted".into()),
            ("MRK_RELEASE_PEER_SHA256".into(),peer_sha256()),("MRK_TLS_PEER_OWNER_TAG".into(),tag.clone()),
        ]));
        let ready=ready_binding(self.case,&tag);
        self.original.ready_binding=Some(ready.clone());self.ready_frame=Some(ready);self.environment=environment;
        self.materials_checked=true;Ok(())
    }
    pub(crate) async fn start(&mut self) -> Check<()> {
        require(self.materials_checked&&self.original.endpoint.is_none(),"release_peer_setup")?;
        let root=self.root.as_ref().ok_or("release_peer_setup")?;
        let python=PathBuf::from("/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu").join(N).join("python/bin/python3");
        self.original.begin_paths(python,root.join("github-peer/github_release_peer.py"),self.environment.clone(),self.case.script())?;
        self.original.readiness(self.case.script()).await
    }
    pub(crate) async fn settle(&mut self, product_final: bool, end: Instant) -> bool {
        if self.post_checked { return self.original.settled; }
        if product_final { if let Some(sender)=self.completion.take(){let _=sender.send(());} }
        else { drop(self.completion.take());self.failed=true; }
        let settled=self.original.settle(self.case.script(),!product_final).await;
        self.failed|=!settled;
        if settled {
            let result=self.root.as_ref().ok_or("release_peer_setup").and_then(|root|self.inputs(root,end));
            self.post_checked=true;self.failed|=result.is_err();
        }
        settled&&self.post_checked
    }
    pub(crate) fn validate(&mut self, marker: Option<&str>) -> Check<()> {
        let peer=&mut self.original;
        require(peer.settled&&peer.ready&&peer.spawned&&!peer.expired&&!peer.stop_attempted
            &&peer.waited.as_ref().is_some_and(ExitStatus::success)&&self.post_checked&&!self.failed,"release_peer_final")?;
        let out=peer.out.as_ref().ok_or("release_peer_output")?;let err=peer.err.as_ref().ok_or("release_peer_output")?;
        require(out.eof&&err.eof&&!out.overflow&&!err.overflow&&err.bytes.is_empty(),"release_peer_output")?;
        let lines=out.bytes.split(|b|*b==b'\n').collect::<Vec<_>>();
        require(lines.len()==3&&lines[2].is_empty()&&protocol::strict_json(lines[0]).ok()==self.ready_frame,"release_peer_frames")?;
        let terminal=protocol::strict_json(lines[1]).map_err(|_|"release_peer_terminal")?;
        let ready=self.ready_frame.as_ref().ok_or("release_peer_binding")?;
        require(terminal_valid(&terminal,ready,self.case,marker),"release_peer_terminal")?;
        let control=peer.control.as_ref().ok_or("release_peer_control")?;
        let facts=control.evidence(peer.endpoint);
        require(facts["acquired"]==true&&facts["started"]==true&&facts["joined"]==true&&facts["writeComplete"]==true
            &&facts["shutdownComplete"]==true&&facts["productSettled"]==true&&facts["withinEndpoint"]==true
            &&facts["released"]==true&&facts["failed"]==false,"release_peer_control")?;
        let arrivals=peer.progress.as_ref().ok_or("release_peer_arrivals")?;let arrivals=lock(arrivals);
        require(!arrivals.invalid&&arrivals.frames.len()==2&&arrivals.observed_bytes==out.bytes.len()
            &&arrivals.frames.iter().all(|(_,at)|peer.endpoint.is_some_and(|end|*at<end)),"release_peer_arrivals")?;
        peer.terminal=Some(terminal);peer.protocol_checked=true;Ok(())
    }
    pub(crate) fn evidence(&self) -> Value { self.original.evidence() }
}
fn ready_binding(case:Case,tag:&str)->Value {
    json!({"schemaVersion":1,"scope":SCOPE,"case":case.script(),"state":"ready","ownerTag":tag,
        "manifestSha256":case.manifest(),"peerSha256":peer_sha256(),"toolingSha":RuntimeProfile::TOOLING_SHA,
        "callerSha256":callers(),"primaryPort":18443})
}
fn terminal_valid(t:&Value,ready:&Value,case:Case,marker:Option<&str>)->bool {
    let empty=case==Case::NormalPending;let recovered=case==Case::ResponseLoss;let journal=&t["journal"];
    keys(t,&["schemaVersion","scope","case","state","ownerTag","manifestSha256","peerSha256","toolingSha",
        "callerSha256","primaryPort","status","requests","posts","decryptedBytes","intentBeforeResponse",
        "allSocketsClosed","inputsCheckedClosed","code","completion","journal","otherJournalAbsent"])
        &&["schemaVersion","scope","case","ownerTag","manifestSha256","peerSha256","toolingSha","callerSha256","primaryPort"]
            .iter().all(|key|t.get(*key)==ready.get(*key))
        &&t["state"]=="finished"&&t["status"]=="passed"&&t["code"].is_null()
        &&t["requests"]==case.requests()&&t["posts"]==case.posts()&&t["intentBeforeResponse"]==json!(recovered)
        &&t["allSocketsClosed"]==true&&t["inputsCheckedClosed"]==true&&t["otherJournalAbsent"]==true
        &&t["decryptedBytes"].as_u64().is_some_and(|n|(1..=case.requests()*8192).contains(&n))
        &&t["completion"]==json!({"bytes":1,"eof":true,"closed":true,"primaryEmpty":true,"primaryUnexpected":0,"primaryClosed":true,"redirect":null})
        &&keys(journal,&["marker","intentBytes","intentSha256","runBytes","runSha256","runId","attempt","leafCount"])
        &&journal["marker"]==json!(marker)&&empty==marker.is_none()
        &&marker.is_none_or(|m|release_protocol::hex(m,32))
        &&journal["leafCount"]==json!(if empty{0}else if recovered{2}else{1})
        &&(if empty{journal["intentBytes"].is_null()&&journal["intentSha256"].is_null()}
            else{journal["intentBytes"].as_u64().is_some_and(|n|(1..=8192).contains(&n))
                &&journal["intentSha256"].as_str().is_some_and(|v|release_protocol::hex(v,64))})
        &&(if recovered{journal["runId"]=="9001"&&journal["attempt"]==1
            &&journal["runBytes"].as_u64().is_some_and(|n|(1..=512).contains(&n))
            &&journal["runSha256"].as_str().is_some_and(|v|release_protocol::hex(v,64))}
            else{["runBytes","runSha256","runId","attempt"].iter().all(|key|journal[*key].is_null())})
}
#[derive(Default)]
struct Handshake {ready:Option<Instant>,claim_at:Option<Instant>,claim_error:Option<String>,go_written:Option<Instant>,token_absent:Option<bool>}
#[derive(Default)]
struct Scheduling {writer_owner:Option<u64>,writer:Option<oneshot::Sender<()>>,revoked:Option<Instant>,
    writer_released:Option<Instant>,cleanup_endpoint:Option<Instant>}
fn revocation_order(h:&Handshake,s:&Scheduling,settled:Instant)->bool {
    let points=[h.ready,s.cleanup_endpoint.and_then(|e|e.checked_sub(CLEANUP_TIME)),s.revoked,s.writer_released,h.claim_at,Some(settled)];
    points.iter().all(Option::is_some)&&points.windows(2).all(|p|p[0]<=p[1])&&s.cleanup_endpoint.is_some_and(|e|settled<e)
}
pub(crate) struct ProductWitness {
    case:Case,created:Instant,supervisor:Mutex<Option<std::sync::Weak<Inner>>>,
    owners:Mutex<Vec<Arc<Owner>>>,results:Mutex<Vec<Value>>,prepared:Mutex<Option<release_protocol::Prepared>>,
    io_checked:Mutex<std::collections::BTreeSet<u64>>,handshake:Mutex<BTreeMap<u64,Handshake>>,
    scheduling:Mutex<Scheduling>,observing:AsyncMutex<()>,failed:AtomicBool,
}
impl ProductWitness {
    pub(crate) fn new(case:Case)->Arc<Self> {Arc::new(Self{case,created:Instant::now(),supervisor:Mutex::new(None),
        owners:Mutex::new(Vec::new()),results:Mutex::new(Vec::new()),prepared:Mutex::new(None),io_checked:Mutex::new(std::collections::BTreeSet::new()),
        handshake:Mutex::new(BTreeMap::new()),scheduling:Mutex::new(Scheduling::default()),observing:AsyncMutex::new(()),failed:AtomicBool::new(false)})}
    pub(crate) fn attach(self:&Arc<Self>,supervisor:&Supervisor)->Check<()> {
        require(supervisor.can_exit()&&!supervisor.disabled()&&!supervisor.stopping()&&lock(&self.owners).is_empty(),"release_witness_setup")?;
        require(lock(&supervisor.inner.native_test.github).is_none()&&lock(&supervisor.inner.native_test.github_preflight).is_none(),"release_witness_exclusive")?;
        let mut slot=lock(&supervisor.inner.native_test.github_release);
        require(slot.is_none()&&lock(&self.supervisor).is_none(),"release_witness_setup")?;
        *lock(&self.supervisor)=Some(Arc::downgrade(&supervisor.inner));*slot=Some(self.clone());Ok(())
    }
    pub(crate) fn fail(&self) {
        self.failed.store(true,Ordering::SeqCst);
        let (key,sender)={let mut s=lock(&self.scheduling);(s.writer_owner,s.writer.take())};
        let owner=lock(&self.owners).iter().find(|owner|Some(owner.key)==key).cloned();
        if let Some(sender)=sender {
            // Original stop first; send only after releasing every mutex.
            // Owner::fail preserves the original first error/cleanup endpoint.
            if let Some(owner)=owner {owner.fail(BridgeError::cleanup_unknown());}
            let _=sender.send(());
        }
    }
    pub(super) fn register(&self,owner:&Arc<Owner>) {
        let valid={let mut owners=lock(&self.owners);let index=owners.len();
            let selected=if index==0{matches!(owner.profile,Profile::GitHubReadOnly)&&owner.release_request.is_none()&&owner.preflight_request.is_none()}
                else{matches!(owner.profile,Profile::GitHubRelease)&&owner.preflight_request.is_none()&&owner.preflight_gate.is_none()
                    &&owner.release_gate.is_some()&&owner.release_request.as_ref().is_some_and(|r|Some(r.kind())==self.case.kind(index))};
            let valid=index<self.case.owner_count()&&selected&&!owners.iter().any(|old|old.key==owner.key)
                &&owners.last().is_none_or(|old|lock(&old.state).terminal);
            if valid{owners.push(owner.clone());}valid};
        if !valid{self.fail();}
    }
    fn registered_index(&self,owner:&Arc<Owner>)->Option<usize> {lock(&self.owners).iter().position(|old|Arc::ptr_eq(old,owner))}
    fn original_index(&self,owner:&Arc<Owner>)->Option<usize> {if self.failed.load(Ordering::SeqCst){None}else{self.registered_index(owner)}}
    pub(super) fn original_case(&self,owner:&Arc<Owner>)->Option<installed_native_fixture::Case> {
        let index=self.original_index(owner)?;
        use installed_native_fixture::Case::*;
        Some(if index==0{GitHubReleaseConnect}else if self.case==Case::NormalPending{GitHubReleaseNormalPending}
            else if self.case.before_go_failure(index){GitHubReleaseRevocation}
            else if self.case.kind(index)==Some(release_protocol::Kind::Pending){GitHubReleasePending}else{GitHubRelease})
    }
    pub(super) fn ready(&self,owner:&Arc<Owner>) {
        let at=Instant::now();let original=self.original_index(owner).is_some_and(|i|i>0)&&matches!(owner.profile,Profile::GitHubRelease)
            &&!owner.preflight_go_claimed.load(Ordering::SeqCst)&&at<owner.endpoint();
        let valid={let mut h=lock(&self.handshake);let valid=original&&!h.contains_key(&owner.key);
            if valid{h.insert(owner.key,Handshake{ready:Some(at),..Handshake::default()});}valid};
        if !valid{self.fail();}
    }
    pub(super) fn hold_ready(&self,owner:&Arc<Owner>)->Option<oneshot::Receiver<()>> {
        if !self.case.before_go_failure(self.registered_index(owner)?){return None;}
        let (sender,receiver)=oneshot::channel();
        let ready=lock(&self.handshake).get(&owner.key).is_some_and(|h|h.ready.is_some())&&!owner.failed();
        let rejected={let mut s=lock(&self.scheduling);
            if !self.failed.load(Ordering::SeqCst)&&s.writer_owner.is_none()&&s.writer.is_none()&&ready {
                s.writer_owner=Some(owner.key);s.writer=Some(sender);None
            }else{Some(sender)}};
        if let Some(sender)=rejected {owner.fail(BridgeError::cleanup_unknown());let _=sender.send(());self.fail();None}else{Some(receiver)}
    }
    pub(crate) fn ready_held(&self)->bool {
        if self.failed.load(Ordering::SeqCst)||self.case!=Case::PreGoRevocation{return false;}
        let s=lock(&self.scheduling);s.writer_owner.is_some()&&s.writer.is_some()&&s.revoked.is_none()
    }
    pub(crate) fn revoked(&self)->Check<()> {
        let result=(||{
            let owner=lock(&self.owners).get(2).cloned().ok_or("release_revocation_original")?;
            require(self.case==Case::PreGoRevocation&&self.original_index(&owner)==Some(2)&&*owner.stop.borrow(),"release_revocation_original")?;
            let state=lock(&owner.state);let at=Instant::now();
            let end=state.cleanup_endpoint.ok_or("release_revocation_endpoint")?;
            require(state.error.as_ref().is_some_and(|e|e.code=="cancelled")&&!state.unknown&&!state.terminal&&at<end
                &&!owner.preflight_go_claimed.load(Ordering::SeqCst),"release_revocation_stop")?;drop(state);
            let sender={let mut s=lock(&self.scheduling);
                require(s.writer_owner==Some(owner.key)&&s.revoked.is_none()&&s.writer_released.is_none(),"release_revocation_repeated")?;
                let sender=s.writer.take().ok_or("release_revocation_writer")?;
                s.cleanup_endpoint=Some(end);s.revoked=Some(at);s.writer_released=Some(Instant::now());sender};
            sender.send(()).map_err(|_|"release_revocation_release")
        })();if result.is_err(){self.fail();}result
    }
    pub(super) fn claim_returned(&self,owner:&Arc<Owner>,digest:&str,result:&Result<Vec<u8>,BridgeError>) {
        let at=Instant::now();let index=self.original_index(owner);let mut token_absent=None;
        let bytes_valid=match result {
            Err(_)=>index.is_some_and(|i|self.case.before_go_failure(i)),
            Ok(bytes)=>{
                // Inspect only this private test writer's actual fixed frame;
                // the sentinel/token is never retained in public evidence.
                let value=bytes.strip_suffix(b"\n").and_then(|raw|protocol::strict_json(raw).ok());
                let pending=owner.release_request.as_ref().is_some_and(|r|r.kind()==release_protocol::Kind::Pending);
                let valid=value.as_ref().is_some_and(|v|keys(v,&["protocol","id","go"])&&keys(&v["go"],&["requestSha256","token"])
                    &&v["protocol"]==release_protocol::PROTOCOL&&v["id"]==owner.id&&v["go"]["requestSha256"]==digest
                    &&v["go"]["token"]==(if pending{Value::Null}else{json!("INERT_NOT_A_CREDENTIAL")}));
                if valid{token_absent=Some(pending);}valid
            }
        };
        let valid={let mut h=lock(&self.handshake);match h.get_mut(&owner.key) {
            Some(h) if index.is_some()&&bytes_valid&&h.ready.is_some_and(|r|r<=at)&&h.claim_at.is_none()=>{
                h.claim_at=Some(at);h.claim_error=result.as_ref().err().map(|e|e.code.clone());h.token_absent=token_absent;true},_=>false}};
        if !valid{self.fail();}
    }
    pub(super) fn go_written(&self,owner:&Arc<Owner>) {
        let at=Instant::now();let original=self.original_index(owner).is_some()&&owner.preflight_go_claimed.load(Ordering::SeqCst)&&at<owner.endpoint();
        let valid={let mut h=lock(&self.handshake);match h.get_mut(&owner.key){
            Some(h) if original&&h.ready.zip(h.claim_at).is_some_and(|(r,c)|r<=c&&c<=at)
                &&h.claim_error.is_none()&&h.token_absent.is_some()&&h.go_written.is_none()=>{h.go_written=Some(at);true},_=>false}};
        if !valid{self.fail();}
    }
    pub(super) fn observe_settled_io(&self,owner:&Arc<Owner>,r:&Resources) {
        let index=self.original_index(owner);let before=index.is_some_and(|i|self.case.before_go_failure(i));
        let valid=index.is_some()&&r.write_end.is_some_and(|w|w.complete!=before)&&r.writer.is_none()&&r.stdout.is_none()&&r.stderr.is_none()
            &&r.failed_writer.is_none()&&r.failed_stdout.is_none()&&r.failed_stderr.is_none()&&r.waited.is_some()&&r.child.is_some()
            &&r.out_end.as_ref().is_some_and(|v|v.eof&&!v.overflow&&(!before||v.bytes.is_empty()))
            &&r.err_end.as_ref().is_some_and(|v|v.eof&&!v.overflow&&(v.bytes.is_empty()||before&&v.bytes==b"Mobile Release Kit private preflight action failed.\n"))
            &&lock(&self.io_checked).insert(owner.key);
        if !valid{self.fail();}
    }
    pub(crate) async fn observe_retired(&self,end:Instant)->Check<bool> {
        let _observing=self.observing.lock().await;let result=self.observe_retired_inner(end).await;
        if result.is_err(){self.fail();}result
    }
    async fn observe_retired_inner(&self,end:Instant)->Check<bool> {
        use std::os::unix::process::ExitStatusExt;
        require(!self.failed.load(Ordering::SeqCst),"release_witness_failed")?;
        let owners=lock(&self.owners).clone();let completed=lock(&self.results).len();
        for (index,owner) in owners.iter().enumerate().skip(completed) {
            let original_case=self.original_case(owner).ok_or("release_original_case")?;
            let negative=self.case.before_go_failure(index);let mut error_code:Option<String>=None;
            let (settled_at,was_unknown,reason,effect,marker)=if index==0 {
                let receipt=owner.github_receipt.as_ref().map(|r|lock(r).clone()).ok_or("release_connect_receipt")?;
                require(!matches!(receipt,GitHubReadReceipt::RetainedUnknown),"release_connect_unknown")?;
                let GitHubReadReceipt::Settled{outcome,settled_at,was_unknown}=receipt else{return Ok(false);};
                let outcome=outcome.map_err(|_|"release_connect_result")?;
                require(outcome.control.reason==github_protocol::Reason::None&&outcome.control.credential_expires_at.is_none()
                    &&outcome.control.cooldown_seconds.is_none()&&!outcome.control.cooldown_blocked
                    &&outcome.facts.account.value.as_ref().is_some_and(|a|a.id=="11"&&a.login=="owner")
                    &&outcome.facts.repository.value.as_ref().is_some_and(|r|r.id=="22"&&r.full_name=="owner/app"
                        &&r.permissions.push==github_protocol::Permission::ReportedAllowed),"release_connect_result")?;
                (settled_at,was_unknown,json!("none"),json!("none"),Value::Null)
            }else{
                let receipt=owner.release_receipt.as_ref().map(|r|lock(r).clone()).ok_or("release_action_receipt")?;
                require(!matches!(receipt,GitHubReleaseReceipt::RetainedUnknown),"release_action_unknown")?;
                let GitHubReleaseReceipt::Settled{outcome,settled_at,was_unknown}=receipt else{return Ok(false);};
                let request=owner.release_request.as_ref().ok_or("release_action_request")?;
                require(request.valid()&&Some(request.kind())==self.case.kind(index),"release_action_request")?;
                if index>1 {
                    let dispatch=owners.get(2).and_then(|o|o.release_request.as_ref()).ok_or("release_dispatch_original")?;
                    require(dispatch.home.is_some()&&request.home==dispatch.home,"release_original_home")?;
                }
                if negative {
                    let action=request.action.as_ref().ok_or("release_negative_request")?;
                    let prepared=lock(&self.prepared).clone().ok_or("release_negative_prepared")?;
                    require(prepared.publisher_bound()&&action.prepared.as_ref()==Some(&prepared)&&action.target==prepared.target,"release_negative_prepared")?;
                    let error=outcome.err().ok_or("release_negative_unexpected_success")?;
                    require(error.code=="cancelled","release_negative_error")?;error_code=Some(error.code);
                    (settled_at,was_unknown,json!("cancelled"),json!("not-sent"),json!(action.target.marker))
                }else{
                    let reply=outcome.map_err(|_|"release_action_result")?;
                    if request.kind()==release_protocol::Kind::Pending {
                        let records=reply.pending.as_ref().ok_or("release_pending_result")?;
                        let scope=request.pending_scope.as_ref().ok_or("release_pending_scope")?;
                        require(reply.result.is_none()&&request.action.is_none()&&scope.valid()&&scope.repository=="owner/app"
                            &&scope.account_id=="11"&&scope.repository_id=="22"&&request.home.is_some(),"release_pending_scope")?;
                        let marker=if self.case==Case::NormalPending {
                            require(records.is_empty()&&lock(&self.prepared).is_none(),"release_normal_empty")?;Value::Null
                        }else{
                            let first=lock(&self.prepared).clone().ok_or("release_pending_original")?;
                            require(scope.matches(&first.target)&&records.len()==1&&records[0].valid()
                                &&records[0].prepared==first&&records[0].run_id.is_none(),"release_pending_original")?;json!(first.target.marker)
                        };
                        (settled_at,was_unknown,json!("none"),json!("none"),marker)
                    }else{
                        let result=reply.result.as_ref().ok_or("release_action_result")?;
                        require(reply.pending.is_none()&&result.valid(request)&&Some(result.action)==self.case.kind(index),"release_action_result")?;
                        let action=request.action.as_ref().ok_or("release_action_request")?;
                        let preparing=request.kind()==release_protocol::Kind::Prepare;
                        let prepared=if preparing{result.prepared.as_ref()}else{action.prepared.as_ref()}.ok_or("release_action_prepared")?;
                        require(prepared_matches(self.case,prepared)&&prepared.target==action.target,"release_action_binding")?;
                        {let mut first=lock(&self.prepared);if preparing{require(first.is_none(),"release_prepare_repeated")?;*first=Some(prepared.clone());}
                            else{require(first.as_ref()==Some(prepared),"release_prepared_original")?;}}
                        let lost=index==2&&self.case==Case::ResponseLoss;
                        require(result.reason==(if lost{release_protocol::Reason::TlsFailed}else{release_protocol::Reason::None})
                            &&result.effect==(if lost{release_protocol::Effect::PotentiallyApplied}else{release_protocol::Effect::None})
                            &&result.run_id.as_deref()==(if preparing||lost{None}else{Some("9001")}),"release_action_outcome")?;
                        if request.kind()==release_protocol::Kind::Reconcile {
                            let run=result.run.as_ref().ok_or("release_reconcile_run")?;
                            require(run.valid(prepared)&&run.id=="9001"&&run.attempt==1
                                &&run.conclusion==Some(release_protocol::Conclusion::Success)&&run.jobs.len()==2
                                &&run.jobs[0].kind==release_protocol::JobKind::InputGuard&&run.jobs[1].kind==release_protocol::JobKind::Ios
                                &&run.jobs.iter().all(|j|j.status==release_protocol::RunStatus::Completed&&j.conclusion==Some(release_protocol::Conclusion::Success)),"release_reconcile_run")?;
                        }
                        (settled_at,was_unknown,json!(result.reason),json!(result.effect),json!(action.target.marker))
                    }
                }
            };
            let mut observer=owner.observer.lock().await;let handle=observer.as_mut().ok_or("release_original_observer")?;
            let joined=tokio::time::timeout_at(end.into(),handle).await.map_err(|_|"release_observer_deadline")?;
            require(joined.is_ok(),"release_observer_join")?;observer.take();drop(observer);
            let r=owner.resources.try_lock().map_err(|_|"release_original_resources")?;let state=lock(&owner.state);
            require(state.terminal&&state.driver_join==ManagementJoin::Returned&&state.watchdog_join==ManagementJoin::Returned
                &&lock(&owner.permit).is_none()&&owner.driver.try_lock().is_ok_and(|s|s.is_none())
                &&owner.watchdog.try_lock().is_ok_and(|s|s.is_none())&&!state.unknown&&!was_unknown&&settled_at<state.endpoint
                &&matches!(state.watchdog_end,Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))),"release_management_final")?;
            if negative {
                require(state.error.as_ref().is_some_and(|e|e.code=="cancelled")&&error_code.as_deref()==Some("cancelled")
                    &&state.cleanup_endpoint==lock(&self.scheduling).cleanup_endpoint
                    &&state.cleanup_endpoint.is_some_and(|e|settled_at<e),"release_first_error_preserved")?;
            }else{require(state.error.is_none()&&state.cleanup_endpoint.is_none(),"release_success_final")?;}
            let (ready,claim,go,token_absent)=if index==0{(false,false,false,None)}else{
                let hs=lock(&self.handshake);let h=hs.get(&owner.key).ok_or("release_handshake")?;
                if negative {
                    let s=lock(&self.scheduling);
                    require(revocation_order(h,&s,settled_at)&&h.claim_error.as_deref()==Some("github_release_refused_target_changed")
                        &&h.go_written.is_none()&&h.token_absent.is_none()&&!owner.preflight_go_claimed.load(Ordering::SeqCst),"release_revocation_claim")?;
                    (true,true,false,None)
                }else{
                    require(owner.preflight_go_claimed.load(Ordering::SeqCst)&&h.ready.zip(h.claim_at).is_some_and(|(a,b)|a<=b)
                        &&h.claim_at.zip(h.go_written).is_some_and(|(a,b)|a<=b&&b<state.endpoint&&b<=settled_at)
                        &&h.claim_error.is_none()&&h.token_absent==Some(self.case.kind(index)==Some(release_protocol::Kind::Pending)),"release_handshake")?;
                    (true,true,true,h.token_absent)
                }
            };
            let custody=if index==0{r.github_readonly.as_ref().is_some_and(|s|lock(s).settled())&&r.github_release.is_none()}
                else{r.github_release.as_ref().is_some_and(|s|lock(s).settled())&&r.github_readonly.is_none()};
            let exit=r.waited.as_ref().ok_or("release_child_wait")?;
            require(if negative{!exit.success()&&(exit.code()==Some(70)||r.kill_attempted&&exit.signal()==Some(9))}else{exit.success()},"release_child_exit")?;
            require(custody&&r.passive.is_none()&&r.github_preflight.is_none()
                &&r.inspection_return==Some(ManagementJoin::Returned)&&r.inspection.is_none()&&r.inspection_error.is_none()
                &&r.acquisition_return==Some(ManagementJoin::Returned)&&r.acquisition.is_none()&&r.acquisition_error.is_none()
                &&r.child.is_none()&&r.writer.is_none()&&r.stdout.is_none()&&r.stderr.is_none()
                &&r.failed_writer.is_none()&&r.failed_stdout.is_none()&&r.failed_stderr.is_none()
                &&r.native_started&&r.native_settlement.is_none()&&matches!(r.native_return,Some(Ok(CloseOutcome::Settled)))
                &&r.native_observation.is_none()&&r.native_observation_return==Some(ManagementJoin::Returned)&&r.native_observation_failure.is_none()
                &&r.native_snapshots.len()==1&&installed_native_fixture::release_snapshot_clear(&r.native_snapshots[0],original_case)
                &&r.write_end.is_some_and(|w|w.complete!=negative)&&r.out_end.is_none()&&r.err_end.is_none()
                &&lock(&self.io_checked).contains(&owner.key),"release_native_final")?;
            lock(&self.results).push(json!({"operationId":owner.id,"kind":if index==0{json!("connect")}else{json!(self.case.kind(index))},
                "manifestSha256":if index==0{RuntimeProfile::MANIFEST}else{self.case.manifest()},"reason":reason,"effect":effect,"marker":marker,
                "terminal":true,"originalObserverJoined":true,"nativeSettled":true,"environmentClear":true,
                "readyObserved":ready,"claimReturned":claim,"goWritten":go,"goClaimed":owner.preflight_go_claimed.load(Ordering::SeqCst),
                "tokenAbsent":token_absent,"negative":negative,"wasUnknown":was_unknown,"errorCode":error_code,
                "firstError":state.error.as_ref().map(|e|e.code.as_str()),"exitCode":exit.code(),"exitSignal":exit.signal(),
                "ownedStopAttempted":r.kill_attempted,"settledNs":settled_at.duration_since(self.created).as_nanos(),
                "maps":installed_native_fixture::snapshot_value(&r.native_snapshots[0])}));
        }
        Ok(lock(&self.results).len()==owners.len()&&!owners.is_empty())
    }
    pub(crate) fn complete(&self,supervisor:&Supervisor)->bool {
        let owners=lock(&self.owners).len();let s=lock(&self.scheduling);
        let clear=s.writer.is_none()&&(if self.case==Case::PreGoRevocation{s.revoked.is_some()&&s.writer_released.is_some()&&s.cleanup_endpoint.is_some()}
            else{s.writer_owner.is_none()&&s.revoked.is_none()&&s.writer_released.is_none()&&s.cleanup_endpoint.is_none()});
        !self.failed.load(Ordering::SeqCst)&&clear&&owners==self.case.owner_count()&&lock(&self.results).len()==owners
            &&lock(&self.io_checked).len()==owners&&lock(&self.handshake).len()==self.case.action_count()
            &&supervisor.can_exit()&&!supervisor.disabled()
    }
    pub(crate) fn evidence(&self)->Vec<Value> {lock(&self.results).clone()}
    pub(crate) fn marker(&self)->Option<String> {lock(&self.prepared).as_ref().map(|p|p.target.marker.clone())}
    pub(crate) fn timeline(&self)->Value {
        let ns=|at:Option<Instant>|at.map(|at|at.duration_since(self.created).as_nanos());
        let owner=(self.case==Case::PreGoRevocation).then(||lock(&self.owners).get(2).cloned()).flatten();
        let h=owner.and_then(|o|lock(&self.handshake).get(&o.key).map(|h|(h.ready,h.claim_at)));
        let s=lock(&self.scheduling);
        json!({"mechanism":if self.case==Case::PreGoRevocation{"original-writer-scheduling"}else{"none"},
            "readyNs":ns(h.and_then(|h|h.0)),"revocationReplyNs":ns(s.revoked),"writerReleasedNs":ns(s.writer_released),
            "claimReturnedNs":ns(h.and_then(|h|h.1)),"cleanupEndpointNs":ns(s.cleanup_endpoint),"kernelCloseFaultInjected":false})
    }
}
pub(crate) fn prepared_matches(case:Case,p:&release_protocol::Prepared)->bool {
    let production=case==Case::ResponseLoss;let selection=&p.target.selection;
    p.publisher_bound()&&p.target.repository=="owner/app"&&p.target.account_id=="11"&&p.target.repository_id=="22"
        &&p.target.branch==(if production{"production"}else{"main"})
        &&p.target.platform==(if production{release_protocol::Platform::Ios}else{release_protocol::Platform::Android})
        &&selection.stage==(if production{release_protocol::Stage::ProductionSubmit}else{release_protocol::Stage::Candidate})
        &&p.source_sha=="a".repeat(40)&&p.source_tree=="e".repeat(40)&&p.workflow_id=="33"
        &&p.current_version.name=="2.0.0"&&p.current_version.build==99&&p.version_source=="release/version.properties"
        &&p.destination.application_id=="org.fixture.app"&&selection.recovery_run_id.is_none()
        &&(if production{selection.candidate_run_id.as_deref()==Some("101")&&selection.external_run_id.as_deref()==Some("102")
            &&selection.original_source_sha.as_deref()==Some("f".repeat(40).as_str())
            &&selection.original_version.as_ref().is_some_and(|v|v.name=="1.2.3"&&v.build==42)
            &&p.confirmation=="production-submit:ios:1.2.3:42"&&p.destination.destination=="App Review; manual release"}
           else{selection.candidate_run_id.is_none()&&selection.external_run_id.is_none()&&selection.original_source_sha.is_none()
            &&selection.original_version.is_none()&&p.confirmation=="candidate:android:2.0.0:99"&&p.destination.destination=="internal"})
}
pub(crate) fn assert_contracts() {
    RuntimeProfile::assert_contracts();installed_native_fixture::assert_release_observation_roles();
    for case in Case::ALL {
        use release_protocol::Kind::*;
        let expected=match case{Case::NormalPending=>vec![Pending],Case::ResponseLoss=>vec![Prepare,Dispatch,Pending,Reconcile],
            Case::PreGoRevocation=>vec![Prepare,Dispatch]};
        assert_eq!((1..case.owner_count()).map(|i|case.kind(i).unwrap()).collect::<Vec<_>>(),expected);
        assert_eq!(case.kind(0),None);assert_eq!(case.kind(case.owner_count()),None);
        assert_eq!(Case::parse(std::ffi::OsStr::new(case.name())),Some(case));
        assert_eq!(case.requests(),[4,25,14][Case::ALL.iter().position(|c|*c==case).unwrap()]);
        assert_eq!(case.posts(),u64::from(case==Case::ResponseLoss));
    }
    for unknown in ["github-release-success","github-preflight-response-loss","github-release-finality-refusal",""] {
        assert!(Case::parse(std::ffi::OsStr::new(unknown)).is_none());
    }
    // Fictional protocol DATA, not successful physical-peer receipts. Exercise
    // the actual terminal parser rather than duplicate its acceptance rules.
    for case in Case::ALL {
        let marker=if case==Case::NormalPending{None}else{Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
        let ready=ready_binding(case,"bbbbbbbbbbbbbbbb");let mut terminal=ready.clone();
        let recovered=case==Case::ResponseLoss;let empty=case==Case::NormalPending;
        for (key,value) in json!({"state":"finished","status":"passed","code":null,
            "requests":case.requests(),"posts":case.posts(),"decryptedBytes":512,"intentBeforeResponse":recovered,
            "allSocketsClosed":true,"inputsCheckedClosed":true,"otherJournalAbsent":true,
            "completion":{"bytes":1,"eof":true,"closed":true,"primaryEmpty":true,"primaryUnexpected":0,"primaryClosed":true,"redirect":null},
            "journal":{"marker":marker,"intentBytes":if empty{None}else{Some(123)},
                "intentSha256":if empty{None}else{Some("c".repeat(64))},"runBytes":if recovered{Some(128)}else{None},
                "runSha256":if recovered{Some("d".repeat(64))}else{None},"runId":if recovered{Some("9001")}else{None},
                "attempt":if recovered{Some(1)}else{None},"leafCount":if empty{0}else if recovered{2}else{1}}})
            .as_object().unwrap(){terminal[key]=value.clone();}
        assert!(terminal_valid(&terminal,&ready,case,marker));
        for (key,value) in [("requests",json!(case.requests()+1)),("posts",json!(case.posts()+1)),
            ("allSocketsClosed",json!(false)),("inputsCheckedClosed",json!(false)),("otherJournalAbsent",json!(false)),
            ("callerSha256",json!({"candidate":RuntimeProfile::CANDIDATE_SHA256})),("status",json!("failed")),
            ("manifestSha256",json!(if empty{RuntimeProfile::MANIFEST}else{N})),("decryptedBytes",json!(0))] {
            let mut changed=terminal.clone();changed[key]=value;assert!(!terminal_valid(&changed,&ready,case,marker),"{key}");
        }
        for key in ["eof","closed","primaryEmpty","primaryClosed"] {
            let mut changed=terminal.clone();changed["completion"][key]=json!(false);
            assert!(!terminal_valid(&changed,&ready,case,marker),"{key}");
        }
        let mut changed=terminal.clone();changed["journal"]["leafCount"]=json!(3);
        assert!(!terminal_valid(&changed,&ready,case,marker));
        let mut changed=terminal.clone();changed["journal"]["runId"]=json!("9002");
        assert!(!terminal_valid(&changed,&ready,case,marker));
        let mut changed=terminal.clone();changed["scope"]=json!("github-preflight-installed-peer-v1");
        assert!(!terminal_valid(&changed,&ready,case,marker));
    }
    let begin=Instant::now();let endpoint=begin+Duration::from_secs(3);
    let handshake=Handshake{ready:Some(begin),claim_at:Some(begin+Duration::from_millis(1300)),..Handshake::default()};
    let mut schedule=Scheduling{revoked:Some(begin+Duration::from_millis(1100)),
        writer_released:Some(begin+Duration::from_millis(1200)),cleanup_endpoint:Some(endpoint),..Scheduling::default()};
    let settled=begin+Duration::from_millis(1400);
    assert!(revocation_order(&handshake,&schedule,settled));
    assert!(!revocation_order(&handshake,&schedule,endpoint));
    schedule.writer_released=Some(begin+Duration::from_millis(1050));
    assert!(!revocation_order(&handshake,&schedule,settled));
    schedule.writer_released=Some(begin+Duration::from_millis(1350));
    assert!(!revocation_order(&handshake,&schedule,settled));
    schedule.writer_released=None;assert!(!revocation_order(&handshake,&schedule,settled));
    // Real descriptorless original Arcs and one-use senders, not native evidence.
    for failure_before_enqueue in [false,true] {
        let witness=ProductWitness::new(Case::PreGoRevocation);
        let owners=(1..=3).map(|key|{let mut o=super::tests::inert_owner();o.key=key;o.id=format!("release-{key}");
            o.profile=if key==1{Profile::GitHubReadOnly}else{Profile::GitHubRelease};Arc::new(o)}).collect::<Vec<_>>();
        let owner=owners[2].clone();*lock(&witness.owners)=owners;witness.ready(&owner);
        if failure_before_enqueue{witness.fail();}
        let held=witness.hold_ready(&owner);
        if failure_before_enqueue{assert!(held.is_none());}
        else {
            owner.fail(BridgeError::new("cancelled","Inert original cancellation DATA."));
            let first={let s=lock(&owner.state);(s.error.clone(),s.cleanup_endpoint)};
            let mut held=held.unwrap();witness.fail();assert_eq!(held.try_recv(),Ok(()));
            let s=lock(&owner.state);assert_eq!((s.error.clone(),s.cleanup_endpoint),first);
        }
        assert!(owner.failed()&&*owner.stop.borrow());assert!(lock(&witness.scheduling).writer.is_none());
    }
}
