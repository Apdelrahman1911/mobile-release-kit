//! The one fixed helper main. It is not an application worker, provider service,
//! configurable command runner, or a second operation/deadline owner.
#[path = "vault_helper_startup.rs"]
mod startup;
use std::{ffi::c_void,mem::ManuallyDrop,os::fd::{FromRawFd,OwnedFd},
    panic::{catch_unwind,AssertUnwindSafe},ptr::NonNull};
use nix::{fcntl::{fcntl,FcntlArg,OFlag},unistd};
use zeroize::{Zeroize,Zeroizing};
use crate::{vault_helper_filesystem::CodeOriginals,vault_helper_wire::{self as wire,Operation,Terminal},
    local_keychain_wire::{self as local,RequestEnvelope},
    wrapping_keychain::{self as wrapping,transport,Admission,Checkpoint}};

unsafe extern "C" {
    fn mrk_vault_control_begin(nonce:*const u8,work:u64,cleanup:u64)->i32;
    fn mrk_vault_control_admit(cleanup:u32)->u32;
    fn mrk_vault_control_failure();
    fn mrk_vault_control_failure_at(first:u64);
    fn mrk_vault_control_snapshot(first:*mut u64,cleanup:*mut u64,effect:*mut u32,valid:*mut u32)->i32;
    fn mrk_vault_control_input_retiring()->i32;
    fn mrk_vault_control_input_closed()->i32;
    fn mrk_vault_control_terminal_start()->i32;
    fn mrk_vault_auth_bytes()->usize;
    fn mrk_vault_auth_new()->*mut c_void;
    fn mrk_vault_auth_begin(book:*mut c_void)->i32;
    fn mrk_vault_auth_parent_current(book:*mut c_void)->i32;
    fn mrk_vault_auth_recheck(book:*mut c_void)->i32;
    fn mrk_vault_auth_read(book:*mut c_void,facts:*mut AuthFacts)->i32;
    fn mrk_vault_auth_release_one(book:*mut c_void,slot:u32)->i32;
    fn mrk_vault_auth_retire(book:*mut c_void)->i32;
}
fn fail(){unsafe{mrk_vault_control_failure();}}
fn local_failure(clock:&mut Option<wire::ClockBridge>,failure:Option<std::time::Instant>){
    if let Some(at)=failure{
        let first=clock.as_mut().and_then(|clock|clock.local_failure(at)).unwrap_or(0);
        // Zero explicitly poisons unknown mapping; never substitute receipt-now.
        unsafe{mrk_vault_control_failure_at(first);}
    }
}
fn admission(cleanup:bool)->Admission {match unsafe{mrk_vault_control_admit(u32::from(cleanup))}{
    1=>Admission::Continue,2=>Admission::Cutoff,_=>Admission::Unknown}}
pub(crate) fn cleanup_admission()->Admission{admission(true)}

#[repr(C)]
#[derive(Clone,Copy,Default)]
struct AuthFacts{version:u32,entered:u32,admitted:u32,rechecked:u32,failed:u32,unknown:u32,state:[u32;18],
    calls:u32,returned:u32,first_call:u32,first_status:i32}
const _:()=assert!(std::mem::size_of::<AuthFacts>()==112);
impl AuthFacts{
    fn valid(&self)->bool{self.version==1 && [self.entered,self.admitted,self.rechecked,self.failed,self.unknown].iter().all(|v|*v<=1)
        && self.state.iter().all(|v|*v<=5) && self.calls<=64 && self.returned<=self.calls && self.calls-self.returned<=1
        && self.first_call<=self.calls && self.admitted<=self.entered && self.rechecked<=self.admitted}
    fn settled(&self)->bool{self.valid() && self.unknown==0 && self.calls==self.returned && self.state.iter().all(|s|matches!(*s,0|4))}
}
struct AuthBook{pointer:Option<NonNull<c_void>>,facts:AuthFacts,entered:bool,retired:bool,poisoned:bool,in_call:bool}
impl AuthBook{
    fn new()->Self{
        let bytes=unsafe{mrk_vault_auth_bytes()};
        let pointer=if (1..=8192).contains(&bytes){NonNull::new(unsafe{mrk_vault_auth_new()})}else{None};
        Self{pointer,facts:AuthFacts{version:1,..AuthFacts::default()},entered:false,retired:false,poisoned:false,in_call:false}
    }
    fn pointer(&self)->*mut c_void{self.pointer.map_or(std::ptr::null_mut(),NonNull::as_ptr)}
    fn refresh(&mut self)->bool{
        let mut facts=AuthFacts::default();
        if self.pointer.is_none() || unsafe{mrk_vault_auth_read(self.pointer(),&mut facts)}!=1 || !facts.valid(){
            self.poisoned=true;fail();return false;
        }
        // Call/reference observations only move forward; losing a positive
        //original or its actual return is an absorbing malformed native result.
        if facts.calls<self.facts.calls || facts.returned<self.facts.returned
            || facts.admitted<self.facts.admitted || facts.rechecked<self.facts.rechecked
            || facts.failed<self.facts.failed || facts.unknown<self.facts.unknown
            || self.facts.state.iter().zip(&facts.state).any(|(old,new)|new<old) {
            self.poisoned=true;fail();return false;
        }
        self.facts=facts;true
    }
    fn begin(&mut self)->bool{
        if self.entered || self.pointer.is_none(){fail();return false;}
        self.entered=true;self.in_call=true;let returned=unsafe{mrk_vault_auth_begin(self.pointer())};self.in_call=false;
        self.refresh() && returned==1 && self.facts.admitted==1 && self.facts.failed==0 && self.facts.unknown==0
    }
    fn current(&mut self)->bool{
        if self.in_call || self.poisoned || self.retired || !self.entered{return false;}
        let returned=unsafe{mrk_vault_auth_parent_current(self.pointer())};
        if returned!=1{let _=self.refresh();false}else{true}
    }
    fn recheck(&mut self)->bool{
        if !self.current(){return false;}self.in_call=true;
        let returned=unsafe{mrk_vault_auth_recheck(self.pointer())};self.in_call=false;
        self.refresh() && returned==1 && self.facts.rechecked==1 && self.facts.failed==0 && self.facts.unknown==0
    }
    fn release(&mut self)->bool{
        if self.retired{return self.pointer.is_none() && self.facts.settled();}
        if self.in_call || self.poisoned{return false;}
        if self.pointer.is_none(){self.retired=true;return !self.entered;}
        for slot in (0..18).rev(){
            if self.facts.state[slot]!=2{continue;}
            if cleanup_admission()!=Admission::Continue{fail();break;}
            self.in_call=true;let returned=unsafe{mrk_vault_auth_release_one(self.pointer(),slot as u32)};self.in_call=false;
            if !self.refresh(){break;}
            if returned!=1{fail();} // Other independently known originals still close.
            if cleanup_admission()!=Admission::Continue{fail();break;}
        }
        if !self.poisoned && self.facts.settled() && cleanup_admission()==Admission::Continue{
            self.in_call=true;let returned=unsafe{mrk_vault_auth_retire(self.pointer())};self.in_call=false;
            if returned==1{self.pointer=None;self.retired=true;}else{self.poisoned=true;fail();}
            if cleanup_admission()!=Admission::Continue{self.poisoned=true;fail();}
        }
        self.retired && self.pointer.is_none() && !self.poisoned && self.facts.settled()
    }
}
/// Exclusive inherited pipe originals. No buffered stdio, duplicate handles,
// hidden reader threads, retry after close error, or implicit Drop-as-evidence.
struct Pipes{fd:[Option<ManuallyDrop<OwnedFd>>;3],state:[u8;3]}
impl Pipes{
    fn inherited()->Self{
        Self{fd:std::array::from_fn(|i|Some(ManuallyDrop::new(
            // SAFETY: this dedicated main is the sole owner of its three
            //inherited pipe descriptors; it never constructs stdio wrappers.
            unsafe{OwnedFd::from_raw_fd(i as i32)}))),state:[1;3]}
    }
    fn descriptor(&self,i:usize)->Option<&OwnedFd>{self.fd[i].as_ref().map(|fd|&**fd)}
    fn read_request(&self,b:&mut[u8;wire::REQUEST_BYTES])->bool{
        let Some(fd)=self.descriptor(0) else{return false;};let mut used=0;
        while used<b.len(){
            match unistd::read(fd,&mut b[used..]){Ok(0)|Err(_)=>return false,Ok(n)=>used+=n}
        }
        true
    }
    fn nonblocking(&self)->bool{
        for i in 0..3{
            let Some(fd)=self.descriptor(i) else{return false;};
            let Ok(flags)=fcntl(fd,FcntlArg::F_GETFL) else{return false;};
            let Some(flags)=OFlag::from_bits(flags) else{return false;};
            if fcntl(fd,FcntlArg::F_SETFL(flags|OFlag::O_NONBLOCK)).is_err(){return false;}
        }true
    }
    fn close(&mut self,i:usize)->bool{
        if self.state[i]!=1{return self.state[i]==3;}
        self.state[i]=2;
        let original=self.fd[i].take().map(ManuallyDrop::into_inner);
        let closed=match original.map(unistd::close){Some(Ok(()))=>{self.state[i]=3;true},_=>{self.state[i]=4;fail();false}};
        // Input's borrow ended before consume; terminal_start already ended
        //notices before stdout consume. Post-check cannot reuse a spent pipe.
        if cleanup_admission()!=Admission::Continue{fail();}
        closed // Actual successful-close receipt, not a timing/finality claim.
    }
    fn write_terminal(&self,b:&[u8],success:bool)->bool{
        let Some(fd)=self.descriptor(1) else{return false;};let mut sent=0;
        while sent<b.len(){
            if admission(!success)!=Admission::Continue{return false;}
            match unistd::write(fd,&b[sent..]){
                Ok(0)=>return false,Ok(n)=>sent+=n,
                Err(nix::errno::Errno::EAGAIN)=>{
                    // Bounded poll of this inherited original only. No timer is
                    //started; the next iteration checks inherited absolute bounds.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                },Err(_)=>return false,
            }
        }true
    }
}
struct Work{pipes:Pipes,filesystem:Option<CodeOriginals>,auth:Option<AuthBook>,clock:Option<wire::ClockBridge>,
    request:Option<RequestEnvelope>,add:Option<wrapping::NativeResult<()>>,lookup:Option<wrapping::NativeResult<wrapping::WrappingKeyCandidate>>,
    probe:Option<wrapping::NativeResult<()>>,absent:bool,
    key:Zeroizing<[u8;32]>,consumed:bool,panic:[Option<Box<dyn std::any::Any+Send>>;2]}
const _:()=assert!(std::mem::size_of::<Work>()+wire::REQUEST_BYTES+local::TERMINAL_BYTES<=wire::HELPER_CONTROL_ALLOWANCE);
impl Work{
    fn new()->Self{Self{pipes:Pipes::inherited(),filesystem:None,auth:None,clock:None,request:None,add:None,lookup:None,
        probe:None,absent:false,key:Zeroizing::new([0;32]),consumed:false,panic:[None,None]}}
    fn run(&mut self)->bool{
        let mut input=Zeroizing::new([0;wire::REQUEST_BYTES]);
        if !self.pipes.read_request(&mut input){return false;}
        self.request=RequestEnvelope::decode(&*input);input.zeroize();
        let Some(request)=self.request.as_ref() else{return false;};
        if !self.pipes.nonblocking() || unsafe{mrk_vault_control_begin(request.nonce().as_ptr(),request.work(),request.maximum_cleanup())}!=1{return false;}
        // One retained bridge for subsequent Rust filesystem F; no clock or
        //deadline is restarted when a later cleanup callback reports that F.
        self.clock=wire::ClockBridge::capture();if self.clock.is_none(){fail();return false;}
        self.filesystem=Some(CodeOriginals::new());self.auth=Some(AuthBook::new());
        let filesystem=self.filesystem.as_mut().unwrap();
        if filesystem.acquire(&mut ||admission(false)!=Admission::Continue).is_err(){
            local_failure(&mut self.clock,filesystem.first_failure().map(|(_,at)|at));fail();return false;
        }
        let auth=self.auth.as_mut().unwrap();if !auth.begin(){fail();return false;}
        let mut forward=|checkpoint:Checkpoint,_facts:&wrapping::Facts|->Admission{
            // Native original-only closes use cleanup admission; an earlier
            //forward callback failure cannot re-enter/poison restore slots3/4.
            let cleanup=checkpoint==Checkpoint::BeforeRelease;
            let gate=admission(cleanup);if gate!=Admission::Continue{return gate;}
            if !cleanup && !auth.current(){fail();return Admission::Unknown;}Admission::Continue
        };
        match request {
            RequestEnvelope::Vault(request)=>{
                let context=wrapping::Context::new(request.vault,request.generation).unwrap();
                if request.operation==Operation::Initialize {
                    let mut result=wrapping::helper_add(&context,&request.initial_key,&mut forward);
                    let added=result.take_value().is_some();self.add=Some(result);
                    if !added {fail();return false;}
                }
                self.lookup=Some(wrapping::helper_lookup(&context,&mut forward));
            },
            RequestEnvelope::Local(request)=>{
                if request.operation==local::Operation::AddRead {
                    let mut result=wrapping::helper_local_add(&request.context,&request.value,&mut forward);
                    let added=result.take_value().is_some();self.add=Some(result);
                    if !added {fail();return false;}
                }
                if request.operation==local::Operation::ProbeAbsent {
                    let mut result=wrapping::helper_local_probe(&request.context,&mut forward);
                    self.absent=result.take_value().is_some();self.probe=Some(result);
                    if !self.absent {fail();return false;}
                } else {self.lookup=Some(wrapping::helper_local_lookup(&request.context,&mut forward));}
            },
        }
        // Native cleanup and frame consumption precede output. Absence has no
        // candidate cell and cannot be turned into a key by an empty receipt.
        if admission(false)!=Admission::Continue {return false;}
        if !request.is_probe() {
            let Some(candidate)=self.lookup.as_mut().and_then(|result|result.take_value()) else {fail();return false;};
            candidate.consume(|key|self.key.copy_from_slice(key));self.consumed=true;
            if let RequestEnvelope::Local(request)=request {
                if request.operation==local::Operation::AddRead {
                    let difference=self.key.iter().zip(request.value.iter()).fold(0u8,|n,(a,b)|n|(a^b));
                    if difference!=0 {self.key.zeroize();fail();return false;}
                }
            }
        }
        if !auth.recheck(){fail();return false;}
        if filesystem.recheck(&mut ||admission(false)!=Admission::Continue).is_err(){
            local_failure(&mut self.clock,filesystem.first_failure().map(|(_,at)|at));fail();return false;
        }
        admission(false)==Admission::Continue
    }
    fn finish(&mut self,success:bool)->bool{
        // A prior Rust filesystem F is published BEFORE auth/native cleanup too.
        local_failure(&mut self.clock,self.filesystem.as_ref().and_then(CodeOriginals::first_failure).map(|(_,at)|at));
        let auth_ok=self.auth.as_mut().is_some_and(AuthBook::release);
        let clock=&mut self.clock;
        let fs_ok=self.filesystem.as_mut().is_some_and(|filesystem|filesystem.release(&mut |failure|{
            local_failure(clock,failure.map(|(_,at)|at));
            cleanup_admission()!=Admission::Continue
        }));
        let input_ok=if cleanup_admission()==Admission::Continue
            && unsafe{mrk_vault_control_input_retiring()}==1{
            self.pipes.close(0) && unsafe{mrk_vault_control_input_closed()}==1
        }else{false};
        let stderr_ok=cleanup_admission()==Admission::Continue && self.pipes.close(2);
        if !auth_ok || !fs_ok || !input_ok || !stderr_ok{fail();}
        let Some(request)=self.request.as_ref()else{return false;};
        let mut terminal=Terminal{first:0,cleanup:request.maximum_cleanup(),effect:0,valid:false,
            add:self.add.as_ref().map(|r|transport::Receipt::observe(r.facts(),false)),
            lookup:self.lookup.as_ref().map(|r|transport::Receipt::observe(r.facts(),self.consumed))
                .or_else(||self.probe.as_ref().map(|r|transport::Receipt::observe(r.facts(),false))),
            auth_settled:auth_ok,filesystem_settled:fs_ok,input_closed:input_ok,candidate:false};
        // Resolve every pre-output decision before reading the terminal clock
        //cell. A newly stamped failure must not leave a stale success-shaped
        //first/cleanup/valid envelope when its optional early notice was lost.
        let native_ready=if request.is_probe() {
            self.absent && !self.consumed && terminal.add.is_none()
                && terminal.lookup.as_ref().is_some_and(transport::Receipt::local_absent)
        } else {self.consumed && !self.absent
            && terminal.lookup.as_ref().is_some_and(transport::Receipt::candidate_consumed)
            && if request.is_add() {terminal.add.as_ref().is_some_and(transport::Receipt::added)} else {terminal.add.is_none()}};
        let ready=success && self.panic.iter().all(Option::is_none) && native_ready && stderr_ok
            && auth_ok && fs_ok && input_ok && admission(false)==Admission::Continue;
        if !ready{fail();}
        // Closing notice publication cannot renew or disable admission. It
        //merely prevents a later diagnostic frame from splicing the terminal.
        if unsafe{mrk_vault_control_terminal_start()}!=1{self.key.zeroize();return false;}
        let mut valid=0;
        let snapshot=unsafe{mrk_vault_control_snapshot(&mut terminal.first,&mut terminal.cleanup,&mut terminal.effect,&mut valid)}==1;
        terminal.valid=snapshot && valid==1 && terminal.effect<=3;
        let mut published=ready && terminal.first==0 && terminal.valid;
        terminal.candidate=published && !request.is_probe();
        let result=if !published {local::ResultKind::None} else if request.is_probe() {local::ResultKind::Absent} else {local::ResultKind::Value};
        let mut envelope=match request {
            RequestEnvelope::Vault(_)=>local::TerminalEnvelope::Vault(terminal),
            RequestEnvelope::Local(_)=>local::TerminalEnvelope::Local(local::Terminal{common:terminal,result}),
        };
        if published && !envelope.success_for(request) {
            published=false;fail();
            let terminal=match &mut envelope {local::TerminalEnvelope::Vault(t)=>t,
                local::TerminalEnvelope::Local(t)=>{t.result=local::ResultKind::None;&mut t.common}};
            terminal.candidate=false;
            let refreshed=unsafe{mrk_vault_control_snapshot(&mut terminal.first,&mut terminal.cleanup,&mut terminal.effect,&mut valid)}==1;
            terminal.valid=refreshed && valid==1 && terminal.effect<=3;
        }
        if !envelope.candidate {self.key.zeroize();}
        let mut output=Zeroizing::new([0;local::TERMINAL_BYTES]);
        let value=envelope.candidate.then_some(&*self.key);
        let encoded=match (request,&envelope) {
            (RequestEnvelope::Vault(r),local::TerminalEnvelope::Vault(t))=>wire::terminal_encode(r,t,value,
                (&mut output[..wire::TERMINAL_BYTES]).try_into().unwrap()),
            (RequestEnvelope::Local(r),local::TerminalEnvelope::Local(t))=>local::terminal_encode(r,t,value,&mut output),
            _=>false,
        };
        if !encoded {self.key.zeroize();return false;}
        let written=self.pipes.write_terminal(&output[..request.terminal_bytes()],published);
        self.key.zeroize();output.zeroize();
        // stdout close is deliberately NOT claimed by the preceding envelope.
        let closed=cleanup_admission()==Admission::Continue && self.pipes.close(1);
        written && closed && published && admission(false)==Admission::Continue
    }
}
/// Caller is only helpers/macos-vault-helper/src/main.rs. Ordinary application
/// add_only/lookup remain unsupported even though it shares the DATA types.
unsafe extern "C"{fn mrk_vault_helper_gate_admit(descriptor:i32,parent_pid:i32)->i32;}
// Conservative closed startup-control allowance, including the <=1024B C gate
// book (C static assertion), fixed ancestors/scalars and bounded gate bytes.
// This is not a bound on opaque allocator/native/process-RSS storage.
const GATE_STARTUP_CONTROL_BYTES:usize=8192;
const _:()=assert!(GATE_STARTUP_CONTROL_BYTES+std::mem::size_of::<Work>()
    +wire::REQUEST_BYTES+local::TERMINAL_BYTES<=wire::HELPER_CONTROL_ALLOWANCE);
pub fn main_entry()->i32{
    std::panic::set_hook(Box::new(|_|{})); // Before any credentials; no panic output.
    // Keep empty parent-supplied env; only the bounded same-real-UID CF
    // preference is admitted after framework startup, never arbitrary entries.
    // std snapshots/copies remain unbounded by iterator/value limits; neither
    // this parsed-input hygiene nor a CF name establishes origin or auth.
    // Shape refusal precedes environment/UID and never constructs FD ownership.
    let Some(handoff)=startup::gate_handoff(std::env::args_os())else{return 64;};
    if let Some(code)=startup::refusal(4,||std::env::vars_os(),||unistd::getuid().as_raw()){return code;}
    if std::env::current_exe().ok().as_deref()!=Some(std::path::Path::new(crate::vault_helper_filesystem::HELPER_BINARY)){
        return 67;
    }
    // SAFETY: bounded scalar handoff, not an OwnedFd conversion. C validates
    // the real main/account/parent and exact original gate before retaining it;
    // no unadmitted descriptor is closed or cloned. It remains until kernel exit.
    if unsafe{mrk_vault_helper_gate_admit(handoff.descriptor,handoff.parent_pid)}!=0{return 67;}
    let mut work=Work::new();
    let ran=match catch_unwind(AssertUnwindSafe(||work.run())){
        Ok(value)=>value,Err(payload)=>{work.panic[0]=Some(payload);fail();false}
    };
    if !ran{fail();}
    let finished=match catch_unwind(AssertUnwindSafe(||work.finish(ran))){
        Ok(value)=>value,Err(payload)=>{work.panic[1]=Some(payload);fail();false}
    };
    // Unknown native originals/panic payloads are deliberately retained, not
    //dropped into another cleanup attempt at process exit. Exit is never a
    //receipt of CF/policy restoration, a wipe of OS copies or add rollback.
    work.key.zeroize();if let Some(request)=work.request.as_mut(){request.wipe_value();}
    let result=if finished{0}else{1};std::mem::forget(work);result
}
