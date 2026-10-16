//! Closed LOCAL phases, executed by the original Saved stdin writer. Every
//! blocking helper is retained before entry and joined before its reply/credit.
use super::*;
use crate::{asset_source::LocalHistorySources,vault_keyring_macos as keyring};
use mrk_macos_installed_native::{local_keychain_wire as keywire,local_project_lease::ProjectLease,vault_helper_wire::ClockBridge};
use zeroize::{Zeroize,Zeroizing};
use sha2::{Digest,Sha256};
use hmac::{Hmac,KeyInit,Mac};
use std::path::Path;

pub(super) struct State {
    source:Option<Box<LocalHistorySources>>,runtime:Option<Arc<Mutex<LocalHistoryRuntimeSlots>>>,
    attempts:Vec<Arc<Attempt>>,key:Option<Zeroizing<[u8;32]>>,locator:[u8;32],
    enrollment:Option<serde_json::Value>,finished:bool,failed:bool,acquire_refused:bool,closure_ok:bool,
}
struct Attempt {book:Mutex<keyring::LookupBook>,handle:AsyncMutex<Option<JoinHandle<Result<(),keyring::Problem>>>>,
    joined:AtomicBool,failed:AtomicBool,step:Step}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Step {KeyAbsent,GenesisAbsent,KeyRead,KeyAdd,AnchorAdd,AnchorRead,NextAbsent}
impl State {pub(super) fn new()->Self{Self{source:None,runtime:None,attempts:Vec::new(),key:None,locator:[0;32],enrollment:None,finished:false,failed:false,acquire_refused:false,closure_ok:false}}}
fn consent(owner:&Session)->Result<&Arc<crate::asset_session::LocalHistoryConsent>,BridgeError>{
    let Context::LocalReleaseHistory(context)=&owner.context else{return Err(BridgeError::protocol());};
    let c=owner.local_history_consent.as_ref().ok_or_else(BridgeError::protocol)?;
    if !c.current(context,owner.registration,&owner.project)
        || *owner.stop.borrow() || Instant::now()>=owner.clocks.work || owner.resource_unknown.load(Ordering::SeqCst){return Err(owner.domain.unavailable());}
    Ok(c)
}
pub(super) fn acquire_sources(owner:&Session,runtime:&Arc<Mutex<LocalHistoryRuntimeSlots>>)->Result<(),BridgeError>{
    consent(owner)?;
    let live=runtime.lock().map_err(|_|BridgeError::cleanup_unknown())?.retained_original_count().ok_or_else(BridgeError::cleanup_unknown)?;
    let mut n=owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    if n.source.is_some()||n.runtime.is_some()||n.finished||n.failed{return Err(BridgeError::protocol());}
    n.runtime=Some(runtime.clone());n.source=Some(Box::new(LocalHistorySources::new()));
    let result=n.source.as_mut().unwrap().acquire(&owner.project,live,&mut||*owner.stop.borrow()||Instant::now()>=owner.clocks.work);
    if result.is_err(){n.failed=true;n.acquire_refused=true;return Err(owner.domain.unavailable());}
    let source=n.source.as_ref().unwrap();let lease=source.lease().map_err(|_|owner.domain.unavailable())?;
    let(_,root)=lease.checked().map_err(|_|owner.domain.unavailable())?;
    let path=owner.project.path.to_str().ok_or_else(BridgeError::protocol)?;
    let mut hash=Sha256::new();hash.update(b"MRK-LOCAL-PROJECT-LOCATOR/1\0");hash.update(root.uid.to_be_bytes());
    hash.update((path.len() as u32).to_be_bytes());hash.update(path.as_bytes());n.locator=hash.finalize().into();Ok(())
}
pub(super) fn request(owner:&Session,context:&history_wire::Context,profile:history_wire::Profile,runtime:&VerifiedRuntime)->Result<Vec<u8>,BridgeError>{
    consent(owner)?;
    let n=owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    let source=n.source.as_ref().ok_or_else(BridgeError::protocol)?;
    let lease=source.lease().map_err(|_|owner.domain.unavailable())?;
    let(_,root)=lease.checked().map_err(|_|owner.domain.unavailable())?;
    let clock=ClockBridge::capture().ok_or_else(BridgeError::protocol)?;
    let mut nonce=[0;16];getrandom::fill(&mut nonce).map_err(|_|BridgeError::protocol())?;
    let original=history_wire::request(&owner.id,&owner.generation,context,profile,&owner.project,&runtime.cwd,
        Path::new(source.home().map_err(|_|owner.domain.unavailable())?),root.descriptor,nonce,
        clock.endpoint(owner.clocks.work).ok_or_else(BridgeError::protocol)?,
        clock.endpoint(owner.clocks.finality).ok_or_else(BridgeError::protocol)?)?;
    let mut r=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    if r.original.is_some()||r.failed{return Err(BridgeError::protocol());}
    r.original=Some((original.nonce,original.sha256));Ok(original.bytes)
}
fn lease(owner:&Session)->Result<Arc<ProjectLease>,BridgeError>{
    owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?.source.as_ref().ok_or_else(BridgeError::protocol)?
        .lease().map_err(|_|owner.domain.unavailable())
}
pub(super) fn child_command(owner:&Session,command:&mut Command)->Result<(),BridgeError>{
    consent(owner)?;mrk_macos_installed_native::local_project_lease::inherit_command(command.as_std_mut(),lease(owner)?)
        .map_err(|_|owner.domain.unavailable())
}
pub(super) fn check_source(owner:&Session)->Result<(),BridgeError>{
    consent(owner)?;
    owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?.source.as_mut().ok_or_else(BridgeError::protocol)?
        .post(&mut||*owner.stop.borrow()||Instant::now()>=owner.clocks.work).map_err(|_|owner.domain.unavailable())
}
/// Private actual-original claim. Document alone turns this into key admission;
/// no renderer value, journal row, bool or test-only DATA constructor can do so.
pub(crate) struct Claim {owner:Arc<Session>,attempt:Arc<Attempt>,context:keywire::Context,
    operation:keywire::Operation,value:Zeroizing<[u8;32]>,lease:Arc<ProjectLease>}
impl Claim {
    pub(crate) fn consent(&self)->&Arc<crate::asset_session::LocalHistoryConsent>{self.owner.local_history_consent.as_ref().unwrap()}
    pub(crate) fn context(&self)->(&history_wire::Context,u32,&RegisteredRoot){
        let Context::LocalReleaseHistory(c)=&self.owner.context else{unreachable!()};(c,self.owner.registration,&self.owner.project)
    }
    pub(crate) fn current(&self)->bool{
        let r=match self.owner.history.route.lock(){Ok(r)=>r,Err(_)=>return false};
        if r.failed||r.original.is_none()||r.received!=r.completed+1||r.pending.is_some()||r.reply_writing{return false;}
        let n=match self.owner.history.native.lock(){Ok(n)=>n,Err(_)=>return false};
        !n.failed&&!n.finished&&n.attempts.last().is_some_and(|a|Arc::ptr_eq(a,&self.attempt))
            && self.lease.checked().is_ok_and(|(_,root)|root==self.context.project())
            && !*self.owner.stop.borrow()&&Instant::now()<self.owner.clocks.work&&!self.owner.resource_unknown.load(Ordering::SeqCst)
    }
    pub(crate) fn own_backing(&self)->Option<usize>{
        let n=self.owner.history.native.try_lock().ok()?;
        let runtime=n.runtime.as_ref()?.try_lock().ok()?;
        let mut bytes=runtime.retained_bytes()?.checked_add(n.source.as_ref()?.retained_bytes()?)?;
        for attempt in &n.attempts {bytes=bytes.checked_add(attempt.book.try_lock().ok()?.retained_bytes()?)?;}
        // Explicit simultaneous closed control allocations: 8 frames (32KiB
        // aggregate) + decoding/public projections, request/private reply, and
        // original Session/Registry/async task cells. No native frame hidden.
        for size in [std::mem::size_of::<Session>(),std::mem::size_of::<Registry>(),std::mem::size_of::<Resources>(),
            std::mem::size_of::<State>(),8*history_wire::RESPONSE_LIMIT,4*history_wire::STATUS_LIMIT,
            2*history_wire::REQUEST_LIMIT,4*history_wire::IPC_LIMIT,64*1024] {bytes=bytes.checked_add(size)?;}
        Some(bytes)
    }
    pub(crate) fn into_input(self)->(keywire::Context,keywire::Operation,Zeroizing<[u8;32]>,Arc<ProjectLease>){
        (self.context,self.operation,self.value,self.lease)
    }
}
fn cleanup(owner:&Session,failure:Option<(keyring::Problem,Instant)>)->Result<Option<Instant>,keyring::Problem>{
    if let Some((p,at))=failure{owner.observe_failure_at(if p==keyring::Problem::CleanupUnknown{Reason::CleanupUnknown}else{Reason::CredentialsUnavailable},at,p==keyring::Problem::CleanupUnknown);}
    let end=*owner.native_cleanup_cutoff.borrow();
    if owner.resource_unknown.load(Ordering::SeqCst){return Err(keyring::Problem::CleanupUnknown);}
    // Some is a real F contraction in LookupBook, NOT a nominal deadline.
    // Returning H on a healthy owner would manufacture F=H-2 and erase every
    // otherwise successful native result in finish_driver.
    history_wire::helper_cleanup_projection(Instant::now(),owner.clocks.finality,end,
        failure.is_some() || *owner.stop.borrow() || end<owner.clocks.finality)
        .map_err(|_|keyring::Problem::CleanupUnknown)
}
fn execute(owner:&Arc<Session>,attempt:&Arc<Attempt>)->Result<(),keyring::Problem>{
    let mut b=attempt.book.lock().map_err(|_|keyring::Problem::CleanupUnknown)?;
    b.enter_driver()?;let _=b.prepare(&mut||*owner.stop.borrow()||Instant::now()>=owner.clocks.work);drop(b);
    let c=owner.local_history_consent.as_ref().ok_or(keyring::Problem::Unavailable)?;
    let claim=HelperClaim{owner:owner.clone(),attempt:attempt.clone()};
    if check_source(owner).is_ok() && c.claim_helper(&claim,false).is_ok(){
        let spawned=attempt.book.lock().map_err(|_|keyring::Problem::CleanupUnknown)?.spawn_original();
        if spawned.is_ok(){
            if check_source(owner).is_err(){attempt.book.lock().map_err(|_|keyring::Problem::CleanupUnknown)?.interrupt();}
            else if let Err(p)=c.claim_helper(&claim,true){attempt.book.lock().map_err(|_|keyring::Problem::CleanupUnknown)?.fail(p);}
        }
    }else{attempt.book.lock().map_err(|_|keyring::Problem::CleanupUnknown)?.interrupt();}
    loop{
        let current=consent(owner).is_ok();
        let mut b=attempt.book.lock().map_err(|_|keyring::Problem::CleanupUnknown)?;
        if !current{b.interrupt();}
        if let Err(p)=cleanup(owner,b.problem().zip(b.problem_at())){b.fail(p);}
        let done=b.pump();let delay=b.turn_delay();drop(b);if done{break;}std::thread::sleep(delay);
    }
    attempt.book.lock().map_err(|_|keyring::Problem::CleanupUnknown)?.finish_driver(
        &mut||*owner.stop.borrow(),&mut|failure|cleanup(owner,failure))
}

pub(crate) struct HelperClaim {owner:Arc<Session>,attempt:Arc<Attempt>}
impl HelperClaim {
    pub(crate) fn consent(&self)->&Arc<crate::asset_session::LocalHistoryConsent>{self.owner.local_history_consent.as_ref().unwrap()}
    pub(crate) fn context(&self)->(&history_wire::Context,u32,&RegisteredRoot){let Context::LocalReleaseHistory(c)=&self.owner.context else{unreachable!()};(c,self.owner.registration,&self.owner.project)}
    pub(crate) fn matches_owner(&self,saved:&SavedCommandOwner)->bool{
        let r=saved.inner.lock();original_session(&r,&self.owner)&&!r.disabled&&!r.stopping&&!r.document_lost
            && r.active.as_ref().is_some_and(|a|a.accepted&&!a.terminal&&!a.unknown&&a.first_stop.is_none())
    }
    pub(crate) fn claim(&self,go:bool)->Result<(),keyring::Problem>{
        if *self.owner.stop.borrow()||Instant::now()>=self.owner.clocks.work||self.owner.resource_unknown.load(Ordering::SeqCst){return Err(keyring::Problem::Interrupted);}
        let r=self.owner.history.route.try_lock().map_err(|_|keyring::Problem::CleanupUnknown)?;
        if r.failed||r.original.is_none()||r.pending.is_some()||r.received!=r.completed+1||r.reply_writing{return Err(keyring::Problem::Protocol);}
        let n=self.owner.history.native.try_lock().map_err(|_|keyring::Problem::CleanupUnknown)?;
        if n.failed||n.finished||!n.attempts.last().is_some_and(|a|Arc::ptr_eq(a,&self.attempt)){return Err(keyring::Problem::Protocol);}
        n.source.as_ref().ok_or(keyring::Problem::Unavailable)?.lease().map_err(|_|keyring::Problem::Unavailable)?;
        let mut b=self.attempt.book.try_lock().map_err(|_|keyring::Problem::CleanupUnknown)?;
        if go{b.claim_go()}else{b.claim_launch()}
    }
}
impl Claim {pub(crate) fn matches_owner(&self,saved:&SavedCommandOwner)->bool{HelperClaim{owner:self.owner.clone(),attempt:self.attempt.clone()}.matches_owner(saved)}}

// Closed action-specific actual helper roster; no phase may select an arbitrary
// operation or enroll/replace a key while reviewing or abandoning inputs.
fn helper_step(action:history_wire::Action,index:usize)->Option<Step>{
    use history_wire::Action;
    match(action,index){
        (Action::Enroll,0)=>Some(Step::KeyAbsent),(Action::Enroll,1)=>Some(Step::GenesisAbsent),
        (Action::Enroll,2)=>Some(Step::KeyAdd),(Action::Enroll,3)=>Some(Step::AnchorAdd),
        (Action::Verify|Action::ReviewInputs|Action::AbandonInputs,0)=>Some(Step::KeyRead),
        (Action::Verify|Action::ReviewInputs|Action::AbandonInputs,1)=>Some(Step::AnchorRead),
        (Action::Verify|Action::ReviewInputs|Action::AbandonInputs,2)=>Some(Step::NextAbsent),
        (Action::AbandonInputs,3)=>Some(Step::AnchorAdd),_=>None,
    }
}

async fn helper(owner:&Arc<Session>,step:Step,sequence:u32,digest:Option<[u8;32]>)->Result<keyring::LocalResult,BridgeError>{
    check_source(owner)?;
    let (context,operation,value,loan,attempt)={
        let mut n=owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let Context::LocalReleaseHistory(context)=&owner.context else{return Err(BridgeError::protocol());};
        let expected=helper_step(context.action,n.attempts.len()).ok_or_else(BridgeError::protocol)?;
        if expected!=step||n.failed||n.finished||n.attempts.iter().any(|a|!a.joined.load(Ordering::SeqCst)||a.failed.load(Ordering::SeqCst)){
            return Err(BridgeError::protocol());
        }
        let loan=n.source.as_ref().ok_or_else(BridgeError::protocol)?.lease().map_err(|_|owner.domain.unavailable())?;
        let(_,root)=loan.checked().map_err(|_|owner.domain.unavailable())?;
        let purpose=if matches!(step,Step::KeyAbsent|Step::KeyRead|Step::KeyAdd){keywire::Purpose::LocalJournalKey}else{keywire::Purpose::LocalCheckpoint};
        let context=keywire::Context::new(n.locator,purpose,sequence,root).ok_or_else(BridgeError::protocol)?;
        let operation=match step{Step::KeyAbsent|Step::GenesisAbsent|Step::NextAbsent=>keywire::Operation::ProbeAbsent,
            Step::KeyRead|Step::AnchorRead=>keywire::Operation::ReadRequired,Step::KeyAdd|Step::AnchorAdd=>keywire::Operation::AddRead};
        let mut value=Zeroizing::new([0;32]);
        if step==Step::KeyAdd{value.copy_from_slice(n.key.as_ref().ok_or_else(BridgeError::protocol)?.as_ref());}
        else if step==Step::AnchorAdd{value.copy_from_slice(&digest.ok_or_else(BridgeError::protocol)?);}
        let attempt=Arc::new(Attempt{book:Mutex::new(keyring::LookupBook::new()),handle:AsyncMutex::new(None),joined:AtomicBool::new(false),failed:AtomicBool::new(false),step});
        n.attempts.push(attempt.clone());(context,operation,value,loan,attempt)
    };
    let claim=Claim{owner:owner.clone(),attempt:attempt.clone(),context,operation,value,lease:loan};
    let c=claim.consent().clone();let (input,admission)=c.admit_history(claim)?;
    let end=owner.clocks.work.min(Instant::now()+Duration::from_secs(10));
    attempt.book.lock().map_err(|_|BridgeError::cleanup_unknown())?.begin_local(input,end,admission).map_err(|_|owner.domain.unavailable())?;
    let original=owner.clone();let worker=attempt.clone();let (release,enter)=oneshot::channel();
    let mut handle=attempt.handle.lock().await;
    *handle=Some(tokio::task::spawn_blocking(move||{
        if enter.blocking_recv().is_err(){return Err(keyring::Problem::CleanupUnknown);}
        execute(&original,&worker)
    }));let _=release.send(());
    let mut cutoff=owner.native_cleanup_cutoff.subscribe();
    let result=loop {
        let end=*cutoff.borrow_and_update();
        tokio::select!{biased;
            _=tokio::time::sleep_until(tokio::time::Instant::from_std(end))=>break Err(()),
            value=handle.as_mut().unwrap()=>break Ok(value),
            changed=cutoff.changed()=>if changed.is_err(){break Err(());},
        }
    };
    let actual=match result{Ok(Ok(actual))=>actual,_=>{attempt.failed.store(true,Ordering::SeqCst);owner.resource_unknown.store(true,Ordering::SeqCst);return Err(BridgeError::cleanup_unknown());}};
    handle.take();drop(handle);
    let mut b=attempt.book.lock().map_err(|_|BridgeError::cleanup_unknown())?;b.child_joined(actual);
    attempt.joined.store(true,Ordering::SeqCst);
    let result=b.consume_settled_local(|r|r);let closed=b.dispose_settled_storage();
    if !closed||!b.resources_settled(){attempt.failed.store(true,Ordering::SeqCst);owner.resource_unknown.store(true,Ordering::SeqCst);return Err(BridgeError::cleanup_unknown());}
    if result.is_err(){attempt.failed.store(true,Ordering::SeqCst);}
    let value=result.map_err(|_|owner.domain.unavailable())?;
    match &value {
        keyring::LocalResult::Absent(absent) if operation==keywire::Operation::ProbeAbsent && absent.matches(context)=>{},
        keyring::LocalResult::Checkpoint(v) if matches!(step,Step::AnchorAdd|Step::AnchorRead)&&v.matches(context,&digest.ok_or_else(BridgeError::protocol)?)=>{},
        keyring::LocalResult::Key(_) if matches!(step,Step::KeyRead|Step::KeyAdd)=>{},
        _=>return Err(owner.domain.unavailable()),
    }
    drop(b);check_source(owner)?;Ok(value)
}
fn fixed_uuid(key:&[u8;32],domain:&[u8],locator:&[u8;32])->Result<String,BridgeError>{
    let mut mac=Hmac::<sha2_11::Sha256>::new_from_slice(key).map_err(|_|BridgeError::protocol())?;mac.update(domain);mac.update(locator);
    let mut bytes:[u8;16]=mac.finalize().into_bytes()[..16].try_into().unwrap();bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;
    Ok(format!("{}-{}-{}-{}-{}",hex(&bytes[..4]),hex(&bytes[4..6]),hex(&bytes[6..8]),hex(&bytes[8..10]),hex(&bytes[10..])))
}
fn hex(bytes:&[u8])->String{bytes.iter().map(|v|format!("{v:02x}")).collect()}
fn digest(value:&str)->Result<[u8;32],BridgeError>{
    if value.len()!=64{return Err(BridgeError::protocol());}let mut result=[0;32];
    for(i,byte)in result.iter_mut().enumerate(){*byte=u8::from_str_radix(&value[i*2..i*2+2],16).map_err(|_|BridgeError::protocol())?;}Ok(result)
}
fn enrollment(owner:&Session)->Result<serde_json::Value,BridgeError>{
    let mut n=owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    let key=n.key.as_ref().ok_or_else(BridgeError::protocol)?;let root=n.source.as_ref().ok_or_else(BridgeError::protocol)?.lease().map_err(|_|owner.domain.unavailable())?;
    let(_,root)=root.checked().map_err(|_|owner.domain.unavailable())?;
    let mut hash=Sha256::new();hash.update(b"MRK-LOCAL-PROJECT-BINDING/1\0");hash.update(n.locator);
    hash.update(root.device.to_be_bytes());hash.update(root.inode.to_be_bytes());hash.update(root.mode.to_be_bytes());hash.update(root.uid.to_be_bytes());hash.update(root.gid.to_be_bytes());
    let value=serde_json::json!({"projectLocator":hex(&n.locator),"projectBinding":hex(&hash.finalize()),
        "projectId":fixed_uuid(key,b"MRK-LOCAL-PROJECT-ID/1\0",&n.locator)?,
        "keyId":fixed_uuid(key,b"MRK-LOCAL-JOURNAL-KEY-ID/1\0",&n.locator)?,"keyRevision":1});
    n.enrollment=Some(value.clone());Ok(value)
}
async fn write_reply(owner:&Session,writer:&mut ChildStdin,kind:&str,step:u8,payload:serde_json::Value,key:bool)->Result<(),BridgeError>{
    check_source(owner)?;
    let mut bytes={let r=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let(nonce,hash)=r.original.as_ref().ok_or_else(BridgeError::protocol)?;
        if r.received!=step||r.completed+1!=step||r.pending.is_some()||r.failed{return Err(BridgeError::protocol());}
        let value=serde_json::json!({"protocol":history_wire::PROTOCOL,"operationId":owner.id,"ownerGeneration":owner.generation,
            "nonce":nonce,"requestSha256":hash,"kind":kind,"step":step,"payload":payload});
        let mut bytes=Zeroizing::new(crate::edit_protocol::bounded(&value,if key{1900}else{1023})?);bytes.push(b'\n');bytes};
    if key{let n=owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        bytes.extend_from_slice(b"MRK-LOCAL-KEY/1\n");bytes.extend_from_slice(n.key.as_ref().ok_or_else(BridgeError::protocol)?.as_ref());bytes.extend_from_slice(b"\nMRK-LOCAL-KEY-END\n");}
    if bytes.len()>2048{return Err(BridgeError::protocol());}
    owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?.reply_writing=true;
    let mut stop=owner.stop.subscribe();
    let result=tokio::select!{biased;_=stop.changed()=>Err(BridgeError::protocol()),
        result=tokio::time::timeout_at(tokio::time::Instant::from_std(owner.clocks.work),writer.write_all(&bytes))=>
            match result{Ok(Ok(()))=>Ok(()),_=>Err(BridgeError::protocol())}};
    bytes.zeroize();result?;check_source(owner)?;
    let mut r=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;r.completed=step;r.reply_writing=false;Ok(())
}
pub(super) async fn write_phases(_inner:&Arc<Inner>,owner:&Arc<Session>,writer:&mut ChildStdin)->Result<(),BridgeError>{
    let Context::LocalReleaseHistory(context)=&owner.context else{return Err(BridgeError::protocol());};
    let total=if matches!(context.action,history_wire::Action::Enroll|history_wire::Action::AbandonInputs){3}else{2};let mut stop=owner.stop.subscribe();
    let mut verified_head:Option<history_wire::Head>=None;
    for step in 1..=total{
        let event=loop{
            let notified=owner.history.changed.notified();
            if let Some(event)=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?.pending.take(){break event;}
            tokio::select!{biased;_=stop.changed()=>return Err(owner.domain.unavailable()),
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(owner.clocks.work))=>return Err(owner.domain.unavailable()),_=notified=>{}}
        };
        match (context.action,step,event){
            (action,1,history_wire::Event::LeaseReady)=>{
                if action==history_wire::Action::Enroll{
                    helper(owner,Step::KeyAbsent,0,None).await?;helper(owner,Step::GenesisAbsent,1,None).await?;
                    let mut key=Zeroizing::new([0;32]);getrandom::fill(key.as_mut()).map_err(|_|BridgeError::protocol())?;
                    if *key==[0;32]{return Err(BridgeError::protocol());}owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?.key=Some(key);
                }else{
                    let keyring::LocalResult::Key(key)=helper(owner,Step::KeyRead,0,None).await? else{return Err(owner.domain.unavailable());};
                    let value=key.consume(|_,bytes|Zeroizing::new(*bytes));owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?.key=Some(value);
                }
                let data=enrollment(owner)?;write_reply(owner,writer,"key-material",step,data,true).await?;
            },
            (history_wire::Action::Enroll,2,history_wire::Event::EmptyJournalReady)=>{
                let keyring::LocalResult::Key(key)=helper(owner,Step::KeyAdd,0,None).await? else{return Err(owner.domain.unavailable());};
                let same={let n=owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?;
                    let expected=n.key.as_ref().ok_or_else(BridgeError::protocol)?;
                    key.consume(|_,bytes|bytes.iter().zip(expected.iter()).fold(0u8,|n,(a,b)|n|(a^b))==0)};
                if !same{return Err(owner.domain.unavailable());}write_reply(owner,writer,"key-enrolled",step,serde_json::json!({}),false).await?;
            },
            (history_wire::Action::Enroll,3,history_wire::Event::DurableGenesis(head))=>{
                helper(owner,Step::AnchorAdd,1,Some(digest(&head.sha256)?)).await?;
                write_reply(owner,writer,"checkpoint-settled",step,serde_json::json!({}),false).await?;
            },
            (history_wire::Action::Verify|history_wire::Action::ReviewInputs|history_wire::Action::AbandonInputs,2,history_wire::Event::HistoryHead(head))=>{
                if context.action==history_wire::Action::AbandonInputs&&head.sequence==513{return Err(BridgeError::protocol());}
                helper(owner,Step::AnchorRead,head.sequence,Some(digest(&head.sha256)?)).await?;
                if head.sequence<513{helper(owner,Step::NextAbsent,head.sequence+1,None).await?;}
                if context.action==history_wire::Action::AbandonInputs{verified_head=Some(head);}
                write_reply(owner,writer,"checkpoint-settled",step,serde_json::json!({}),false).await?;
            },
            (history_wire::Action::AbandonInputs,3,history_wire::Event::AbandonedHead(head))=>{
                let previous=verified_head.take().ok_or_else(BridgeError::protocol)?;
                if previous.sequence>=513||head.sequence!=previous.sequence+1{return Err(BridgeError::protocol());}
                helper(owner,Step::AnchorAdd,head.sequence,Some(digest(&head.sha256)?)).await?;
                write_reply(owner,writer,"checkpoint-settled",step,serde_json::json!({}),false).await?;
            },_=>return Err(BridgeError::protocol()),
        }
    }
    owner.history.native.lock().map_err(|_|BridgeError::cleanup_unknown())?.key.take();Ok(())
}

pub(super) fn finish_sources(owner:&Session)->bool{
    let mut n=match owner.history.native.lock(){Ok(n)=>n,Err(_)=>return false};
    if n.finished{return false;}
    n.key.take();n.enrollment.take(); // Secret erasure does not refund an FD/native loan.
    // There is no credit for a pending/unknown blocking join, even if a helper
    // terminal or PID wait was already observed. Keep every lease loan intact.
    for a in &n.attempts{if !a.close_ready(){return false;}}
    let result=n.source.as_mut().map_or(Ok(()),|source|source.close(&mut||owner.native_cleanup_expired(None)));
    n.finished=true;if result.is_err(){n.failed=true;}
    // A policy/busy refusal during original source acquire happened before
    // Python/helper use. Preserve that refusal, but do not turn its positively
    // closed unused originals into permanent application cleanup-unknown.
    // Any later POST/close failure still requires exact success here.
    n.closure_ok=n.source.as_ref().is_none_or(|s|s.settled()) && (result.is_ok() || n.acquire_refused && matches!(result,Err(crate::asset_commands::Reason::SourceChanged)));
    n.closure_ok
}
pub(super) fn sources_final(owner:&Session)->bool{
    owner.history.native.try_lock().is_ok_and(|n|n.untouched() || n.finished&&n.closure_ok&&n.source.as_ref().is_none_or(|s|s.settled())
        &&n.attempts.iter().all(|a|a.close_ready()))
}

impl State {
    fn untouched(&self)->bool{
        !self.finished && !self.failed && !self.acquire_refused && !self.closure_ok && self.source.is_none()
            && self.runtime.is_none() && self.attempts.is_empty() && self.key.is_none() && self.enrollment.is_none()
            && self.locator==[0;32]
    }
}
impl Attempt {
    fn close_ready(&self)->bool{
        let Ok(handle)=self.handle.try_lock() else{return false;};
        let Ok(book)=self.book.try_lock() else{return false;};
        // Registration precedes Document admission. A refused admission can
        // leave a genuinely untouched book; no worker ever existed to join.
        // Do not fabricate child_joined or accept a begun/pending/unknown book.
        handle.is_none() && book.resources_settled() && book.allocations_released()
            && (self.joined.load(Ordering::SeqCst) || !self.failed.load(Ordering::SeqCst) && book.can_begin())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_release_history_candidate_helper_rosters_never_enroll(){
        use history_wire::Action;
        for action in [Action::Verify,Action::ReviewInputs,Action::AbandonInputs]{
            assert_eq!(helper_step(action,0),Some(Step::KeyRead));
            assert_eq!(helper_step(action,1),Some(Step::AnchorRead));
            assert_eq!(helper_step(action,2),Some(Step::NextAbsent));
            assert_eq!(helper_step(action,3),if action==Action::AbandonInputs{Some(Step::AnchorAdd)}else{None});
            assert_eq!(helper_step(action,4),None);
        }
        assert_eq!(helper_step(Action::Enroll,0),Some(Step::KeyAbsent));
        assert_eq!(helper_step(Action::Enroll,1),Some(Step::GenesisAbsent));
        assert_eq!(helper_step(Action::Enroll,2),Some(Step::KeyAdd));
        assert_eq!(helper_step(Action::Enroll,3),Some(Step::AnchorAdd));
        assert_eq!(helper_step(Action::Enroll,4),None);
    }
    #[test]
    fn local_release_history_pre_admission_refusal_has_no_worker_to_join(){
        let mut state=State::new();assert!(state.untouched());state.failed=true;assert!(!state.untouched());
        let attempt=Attempt{book:Mutex::new(keyring::LookupBook::new()),handle:AsyncMutex::new(None),
            joined:AtomicBool::new(false),failed:AtomicBool::new(false),step:Step::KeyAbsent};
        assert!(attempt.close_ready());assert!(!attempt.joined.load(Ordering::SeqCst));
        attempt.failed.store(true,Ordering::SeqCst);assert!(!attempt.close_ready());
        attempt.failed.store(false,Ordering::SeqCst);attempt.book.lock().unwrap().interrupt();assert!(!attempt.close_ready());
    }
}
