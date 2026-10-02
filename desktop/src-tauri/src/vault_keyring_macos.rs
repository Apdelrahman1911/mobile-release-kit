//! One OriginalWork-owned Mac helper attempt. No detached runner, launch retry,
//! selector, ambient environment, discovery cleanup, secret logging or UI key API.
#![forbid(unsafe_code)]
use std::{mem::ManuallyDrop,os::fd::OwnedFd,process::{Child,Command,ExitStatus,Stdio},time::{Duration,Instant}};
use nix::{fcntl::{fcntl,FcntlArg,OFlag},unistd};
use zeroize::{Zeroize,Zeroizing};
use mrk_macos_installed_native::{vault_helper_wire::{self as wire,ClockBridge,Request,Terminal},
    vault_helper_filesystem::{HELPER_BINARY,FIXED_CWD},wrapping_keychain::{Outcome}};
use crate::{asset_session::KeyringMemoryAdmission,installed_runtime::VaultHelperSlots,vault_format as format};

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum Problem{Interrupted,CleanupUnknown,Capacity,Locked,MissingKey,Denied,UnsupportedProvider,Unavailable,InvalidInput,IdentityMismatch,Crypto,Protocol}
pub(crate) struct LookupInput{identity:format::Identity,proposal:Option<crate::vault_crypto::InitializationKey>}
impl LookupInput{
    pub(crate) fn unlock(identity:format::Identity)->Result<Self,Problem>{
        format::Identity::new(identity.vault,identity.generation).map_err(|_|Problem::InvalidInput)?;
        Ok(Self{identity,proposal:None})
    }
    pub(crate) fn initialize(admission:crate::asset_session::KeyringInitializationAdmission,
        proposal:crate::vault_crypto::InitializationKey)->Result<Self,Problem>{
        let identity=admission.into_identity();format::Header::parse(proposal.header(),identity).map_err(|_|Problem::IdentityMismatch)?;
        Ok(Self{identity,proposal:Some(proposal)})
    }
}
/// Constructed here only after native+pipe+process+blocking-child finality.
// No Clone/Debug/serde, key getter, async callback or deserialization constructor.
pub(crate) struct WrappingKeyCandidate{bytes:Zeroizing<[u8;32]>}
impl WrappingKeyCandidate{
    pub(crate) fn retained_bytes(&self)->usize{std::mem::size_of::<Self>()}
    pub(crate) fn consume<R>(self,authenticate:impl FnOnce(&[u8;32])->R)->R{authenticate(&self.bytes)}
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Launch{Unstarted,Claimed,Entered,Returned,Failed}
#[derive(Clone,Copy,PartialEq,Eq)]
enum PipeState{Reserved,Held,Closing,Closed,Unknown}
struct Pipe{fd:Option<ManuallyDrop<OwnedFd>>,state:PipeState,eof:bool,failed:bool}
impl Pipe{
    fn new()->Self{Self{fd:None,state:PipeState::Reserved,eof:false,failed:false}}
    fn original(&self)->Option<&OwnedFd>{self.fd.as_ref().map(|fd|&**fd)}
    fn retain(&mut self,fd:Option<OwnedFd>)->bool{
        if self.state!=PipeState::Reserved{return false;}
        match fd{Some(fd)=>{self.fd=Some(ManuallyDrop::new(fd));self.state=PipeState::Held;true},
            None=>{self.state=PipeState::Unknown;self.failed=true;false}}
    }
    fn nonblocking(&mut self)->bool{
        let Some(fd)=self.original()else{return false;};
        let Ok(flags)=fcntl(fd,FcntlArg::F_GETFL)else{return false;};
        let Some(flags)=OFlag::from_bits(flags)else{return false;};
        fcntl(fd,FcntlArg::F_SETFL(flags|OFlag::O_NONBLOCK)).is_ok()
    }
    fn close(&mut self)->bool{
        if self.state==PipeState::Reserved{self.state=PipeState::Closed;return true;}
        if self.state!=PipeState::Held{return self.state==PipeState::Closed;}
        self.state=PipeState::Closing;let original=self.fd.take().map(ManuallyDrop::into_inner);
        match original.map(unistd::close){Some(Ok(()))=>{self.state=PipeState::Closed;true},
            _=>{self.state=PipeState::Unknown;self.failed=true;false}}
    }
    fn settled(&self)->bool{self.state==PipeState::Closed && self.fd.is_none() && !self.failed}
}
pub(crate) struct LookupBook{
    entered:bool,driver_entered:bool,driver_returned:bool,joined:bool,driver_result:Option<Result<(),Problem>>,
    charge:Option<KeyringMemoryAdmission>,input:Option<LookupInput>,slots:Option<VaultHelperSlots>,
    command:Option<Command>,launch:Launch,child:Option<ManuallyDrop<Child>>,exit:Option<ExitStatus>,
    wait_entered:bool,wait_failed:bool,kill_attempted:bool,kill_failed:bool,pipes:[Pipe;3],
    clock:Option<ClockBridge>,request:Option<Request>,request_bytes:Zeroizing<[u8;wire::REQUEST_BYTES]>,
    go:bool,write_attempted:bool,request_sent:bool,stop_attempted:bool,stop_sent:bool,
    output:Zeroizing<[u8;wire::RESPONSE_LIMIT+1]>,used:usize,notice_seen:bool,terminal_start:usize,
    terminal:Option<Terminal>,terminal_seen:bool,output_failed:bool,stderr_seen:bool,
    work:Option<Instant>,cleanup:Option<Instant>,first:Option<(Problem,Instant)>,uncertain:bool,effect:u32,
    candidate:Option<WrappingKeyCandidate>,disposed:bool,postchecked:bool,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
    qualification: QualificationBook,
}
pub(crate) const LOOKUP_CONTROL_BYTES:usize=std::mem::size_of::<LookupBook>()+std::mem::size_of::<LookupInput>()
    + std::mem::size_of::<VaultHelperSlots>() + 8192;
// Census reserves both fixed native operation frames, both bounded ACL
//adapter allocations, the authentication book, helper control storage and the
//two private transports before entry. Opaque live native allocations still
//return None; this is not a process-RSS or complete OS allocation promise.
pub(crate) const LOOKUP_WIRE_BYTES:usize=2*wire::RESPONSE_LIMIT+2*wire::REQUEST_BYTES
    +2*mrk_macos_installed_native::wrapping_keychain::MAX_NATIVE_FRAME_BYTES
    +2*16*1024+8192+wire::HELPER_CONTROL_ALLOWANCE;
impl LookupBook{
    pub(crate) fn new()->Self{Self{entered:false,driver_entered:false,driver_returned:false,joined:false,driver_result:None,
        charge:None,input:None,slots:None,command:None,launch:Launch::Unstarted,child:None,exit:None,wait_entered:false,wait_failed:false,
        kill_attempted:false,kill_failed:false,pipes:std::array::from_fn(|_|Pipe::new()),clock:None,request:None,request_bytes:Zeroizing::new([0;wire::REQUEST_BYTES]),
        go:false,write_attempted:false,request_sent:false,stop_attempted:false,stop_sent:false,output:Zeroizing::new([0;wire::RESPONSE_LIMIT+1]),
        used:0,notice_seen:false,terminal_start:0,terminal:None,terminal_seen:false,output_failed:false,stderr_seen:false,
        work:None,cleanup:None,first:None,uncertain:false,effect:0,candidate:None,disposed:false,postchecked:false,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        qualification: QualificationBook::default()}}
    pub(crate) fn started(&self)->bool{self.entered}
    pub(crate) fn memory_held(&self)->bool{self.charge.is_some()}
    pub(crate) fn problem(&self)->Option<Problem>{self.first.map(|(p,_)|p)}
    pub(crate) fn problem_at(&self)->Option<Instant>{self.first.map(|(_,at)|at)}
    fn latch_failure(first:&mut Option<(Problem,Instant)>,cleanup:&mut Option<Instant>,uncertain:&mut bool,p:Problem,at:Instant){
        if first.is_none_or(|(old_p,old)|at<old || at==old && old_p==Problem::Unavailable && p!=Problem::Unavailable){*first=Some((p,at));}
        let earlier=at.checked_add(Duration::from_secs(2));
        *cleanup=match(*cleanup,earlier){(Some(a),Some(b))=>Some(a.min(b)),_=>{*uncertain=true;None}};
        if p==Problem::CleanupUnknown{*uncertain=true;}
    }
    pub(crate) fn fail_at(&mut self,p:Problem,at:Instant){
        Self::latch_failure(&mut self.first,&mut self.cleanup,&mut self.uncertain,p,at);
        self.candidate=None;
        if let Some(request)=self.request.as_mut(){request.initial_key.zeroize();}
        if let Some(input)=self.input.as_mut(){input.proposal=None;}
        if !self.request_sent{self.request_bytes.zeroize();}
    }
    pub(crate) fn fail(&mut self,p:Problem){self.fail_at(p,Instant::now());}
    pub(crate) fn interrupt(&mut self){if self.first.is_none(){self.fail(Problem::Interrupted);}}
    pub(crate) fn constrain_cleanup_endpoint(&mut self,first:Instant,end:Instant){
        if end<first || end.duration_since(first)>Duration::from_secs(2){self.fail(Problem::CleanupUnknown);return;}
        self.fail_at(self.problem().unwrap_or(Problem::Interrupted),first);
        self.cleanup=self.cleanup.map(|old|old.min(end)); // Unknown never reopens.
    }
    pub(crate) fn can_begin(&self)->bool{!self.entered && self.allocations_released() && self.first.is_none()}
    pub(crate) fn begin(&mut self,input:LookupInput,end:Instant,charge:KeyringMemoryAdmission)->Result<(),Problem>{
        if !self.can_begin(){return Err(Problem::CleanupUnknown);}self.entered=true;self.charge=Some(charge);
        self.input=Some(input);self.work=Some(end);self.cleanup=end.checked_add(Duration::from_secs(2));
        // Inert fixed slots are retained before the registered blocking child.
        //The child arms the native frame after its original start barrier.
        self.slots=Some(VaultHelperSlots::new());
        if self.cleanup.is_none(){self.fail(Problem::CleanupUnknown);return Err(Problem::CleanupUnknown);}Ok(())
    }
    pub(crate) fn dispatch_ready(&self)->bool{self.entered && !self.driver_entered && !self.driver_returned && !self.joined
        && self.launch==Launch::Unstarted && self.slots.is_some() && self.memory_held()}
    pub(crate) fn enter_driver(&mut self)->Result<(),Problem>{
        if !self.dispatch_ready(){self.fail(Problem::CleanupUnknown);return Err(Problem::CleanupUnknown);}
        self.driver_entered=true;Ok(())
    }
    pub(crate) fn prepare(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Problem>{
        if !self.driver_entered || self.command.is_some() || self.first.is_some(){return Err(Problem::CleanupUnknown);}
        let result=(||{
            self.slots.as_mut().ok_or(Problem::CleanupUnknown)?.inspect_once(stop).map_err(|_|Problem::UnsupportedProvider)?;
            if stop(){return Err(Problem::Interrupted);}
            let clock=ClockBridge::capture().ok_or(Problem::CleanupUnknown)?;
            let work=clock.endpoint(self.work.ok_or(Problem::CleanupUnknown)?).ok_or(Problem::Interrupted)?;
            let maximum_cleanup=clock.endpoint(self.cleanup.ok_or(Problem::CleanupUnknown)?).ok_or(Problem::Interrupted)?;
            let input=self.input.take().ok_or(Problem::CleanupUnknown)?;
            let mut nonce=[0;16];getrandom::fill(&mut nonce).map_err(|_|Problem::Crypto)?;
            if nonce==[0;16]{return Err(Problem::Crypto);}
            let operation=if input.proposal.is_some(){wire::Operation::Initialize}else{wire::Operation::Lookup};
            let mut initial_key=Zeroizing::new([0;32]);
            if let Some(proposal)=input.proposal{proposal.consume_for_transport(|key|initial_key.copy_from_slice(key));}
            let request=Request{operation,nonce,vault:*input.identity.vault.bytes(),generation:*input.identity.generation.bytes(),
                work,maximum_cleanup,initial_key};
            self.clock=Some(clock);self.request=Some(request);
            if !self.request.as_ref().unwrap().encode(&mut self.request_bytes){return Err(Problem::InvalidInput);}
            let mut command=Command::new(HELPER_BINARY);
            command.env_clear().current_dir(FIXED_CWD).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            self.command=Some(command);Ok(())
        })();
        if let Err(p)=result{
            let at=self.slots.as_ref().and_then(VaultHelperSlots::first_failure).map(|(_,at)|at).unwrap_or_else(Instant::now);
            self.fail_at(p,at);
        }result
    }
    /// Called only under the actual document/current-slot gate. No IO here.
    pub(crate) fn claim_launch(&mut self)->Result<(),Problem>{
        if self.first.is_some() || self.launch!=Launch::Unstarted || !self.driver_entered || self.command.is_none()
            || self.work.is_none_or(|end|Instant::now()>=end){return Err(Problem::Interrupted);}
        self.slots.as_mut().ok_or(Problem::CleanupUnknown)?.claim_once().map_err(|_|Problem::CleanupUnknown)?;
        self.launch=Launch::Claimed;Ok(())
    }
    pub(crate) fn spawn_original(&mut self)->Result<(),Problem>{
        if self.launch!=Launch::Claimed{return Err(Problem::CleanupUnknown);}self.launch=Launch::Entered;
        // Registration/state precedes the synchronous spawn. Unreturned launch
        //or Err is Unknown, never a fabricated no-child/implicit-close receipt.
        let result=self.command.as_mut().ok_or(Problem::CleanupUnknown)?.spawn();
        match result{
            Err(_)=>{self.launch=Launch::Failed;self.fail(Problem::CleanupUnknown);return Err(Problem::CleanupUnknown);}
            Ok(child)=>{self.child=Some(ManuallyDrop::new(child));self.launch=Launch::Returned;}
        }
        let child=self.child.as_mut().unwrap();
        let originals=[child.stdin.take().map(OwnedFd::from),child.stdout.take().map(OwnedFd::from),child.stderr.take().map(OwnedFd::from)];
        let mut ready=true;
        for (pipe,fd) in self.pipes.iter_mut().zip(originals){ready &= pipe.retain(fd);if pipe.state==PipeState::Held{ready &= pipe.nonblocking();}}
        if !ready{self.fail(Problem::CleanupUnknown);return Err(Problem::CleanupUnknown);}Ok(())
    }
    /// Fresh post-spawn document gate; no earlier launch claim authorizes GO.
    pub(crate) fn claim_go(&mut self)->Result<(),Problem>{
        if self.first.is_some() || self.go || self.launch!=Launch::Returned || self.child.is_none()
            || self.pipes.iter().any(|p|p.state!=PipeState::Held)
            || self.work.is_none_or(|end|Instant::now()>=end){return Err(Problem::Interrupted);}
        self.go=true;Ok(())
    }
    fn apply_effect(&mut self,new:u32)->bool{
        if new>3 || self.request.as_ref().is_some_and(|r|r.operation==wire::Operation::Lookup) && new!=0{return false;}
        match(self.effect,new){
            (0,_)|(3,1|2|3)|(1,1)|(2,2)=>{self.effect=new;true},_=>false,
        }
    }
    fn consume_frames(&mut self){
        let Some(request)=self.request.as_ref()else{self.fail(Problem::Protocol);return;};
        if !self.notice_seen && self.used>=8 && &self.output[..8]==b"MRKVKN01"{
            if self.used<wire::NOTICE_BYTES{return;}
            let Some(notice)=wire::Notice::decode(&self.output[..wire::NOTICE_BYTES],request)else{self.fail(Problem::Protocol);self.output_failed=true;return;};
            self.notice_seen=true;self.terminal_start=wire::NOTICE_BYTES;
            let bound=self.clock.as_mut().and_then(|clock|clock.failure_bound(notice.first));
            if !self.apply_effect(notice.effect){self.fail(Problem::Protocol);self.output_failed=true;return;}
            match bound{Some(at)=>self.fail_at(if notice.valid{Problem::Unavailable}else{Problem::CleanupUnknown},at),None=>self.fail(Problem::CleanupUnknown)}
        }
        if self.terminal_seen{
            if self.used!=self.terminal_start+wire::TERMINAL_BYTES{
                self.output_failed=true;self.fail(Problem::Protocol);
            }
            return;
        }
        let start=self.terminal_start;
        if self.used<start+8{return;}
        if &self.output[start..start+8]!=b"MRKVKT01"{self.fail(Problem::Protocol);self.output_failed=true;return;}
        if self.used<start+wire::TERMINAL_BYTES{return;}
        let request=self.request.as_ref().unwrap();
        let Some(terminal)=Terminal::decode(&self.output[start..start+wire::TERMINAL_BYTES],request)else{self.fail(Problem::Protocol);self.output_failed=true;return;};
        if !self.apply_effect(terminal.effect){self.fail(Problem::Protocol);self.output_failed=true;return;}
        if terminal.first!=0{
            let bound=self.clock.as_mut().and_then(|clock|clock.failure_bound(terminal.first));
            let reason=terminal.lookup.as_ref().or(terminal.add.as_ref()).map(|r|match r.facts().outcome(){
                Outcome::Missing=>Problem::MissingKey,Outcome::Locked=>Problem::Locked,
                Outcome::AuthenticationFailed|Outcome::InteractionRequired|Outcome::UserCanceled=>Problem::Denied,
                Outcome::Unsupported=>Problem::UnsupportedProvider,_=>Problem::Unavailable,
            }).unwrap_or(Problem::Unavailable);
            match bound{Some(at)=>self.fail_at(reason,at),None=>self.fail(Problem::CleanupUnknown)}
        }
        let terminal_success=terminal.success(self.request.as_ref().unwrap().operation);
        if !terminal.valid{self.fail(Problem::CleanupUnknown);}
        else if !terminal_success && self.first.is_none(){self.fail(Problem::Unavailable);}
        self.terminal=Some(terminal);self.terminal_seen=true;
        if self.used!=start+wire::TERMINAL_BYTES{self.output_failed=true;self.fail(Problem::Protocol);}
    }
    fn needs_stop_control(&self)->bool{
        // Only a real request-bound decoded terminal can retire this route.
        // It says nothing about EOF, wait, close, join or operation success.
        let input_retired=self.request.is_some() && self.terminal_seen
            && self.terminal.as_ref().is_some_and(|t|t.valid && t.input_closed);
        self.first.is_some() && self.request_sent && !self.stop_attempted && self.exit.is_none() && !input_retired
    }
    fn write_control(&mut self){
        if self.go && !self.write_attempted && self.first.is_none(){
            self.write_attempted=true;
            let result=match self.pipes[0].original(){Some(fd)=>unistd::write(fd,&*self.request_bytes),None=>{self.fail(Problem::CleanupUnknown);return;}};
            match result{
                Ok(n) if n==wire::REQUEST_BYTES=>{self.request_sent=true;},
                // No retry or GO reconstruction after ambiguous/partial write.
                _=>{self.fail(Problem::CleanupUnknown);}
            }
            self.request_bytes.zeroize();if let Some(request)=self.request.as_mut(){request.initial_key.zeroize();}
        }
        // A stopped child that never received a complete GO must not wait for
        //the cleanup deadline merely because its blocking request read lacks
        //EOF. Closing this one retained parent input is ordinary cleanup; it
        //does not assert that a partial/ambiguous GO was harmless.
        if self.first.is_some() && !self.request_sent && self.pipes[0].state==PipeState::Held {
            if !self.pipes[0].close(){self.fail(Problem::CleanupUnknown);}
        }
        if self.needs_stop_control(){
            self.stop_attempted=true;
            let encoded=(||{
                let clock=self.clock.as_ref()?;let first=clock.earlier_endpoint(self.first?.1)?;
                let cleanup=clock.earlier_endpoint(self.cleanup?)?;
                wire::Stop{first,cleanup}.encode(&self.request.as_ref()?.nonce)
            })();
            if let Some(frame)=encoded{
                self.stop_sent=self.pipes[0].original().is_some_and(|fd|unistd::write(fd,&frame).is_ok_and(|n|n==wire::STOP_BYTES));
            }
            if !self.stop_sent{self.fail(Problem::CleanupUnknown);}
        }
    }
    fn read_pipes(&mut self){
        if self.pipes[1].state==PipeState::Held && !self.pipes[1].eof && !self.output_failed{
            // One bounded read per turn; no unbounded drain hides the cutoff.
            let max=(self.used+4096).min(self.output.len());
            if self.used==self.output.len(){self.output_failed=true;self.fail(Problem::Capacity);}
            else{
                let result=unistd::read(self.pipes[1].original().unwrap(),&mut self.output[self.used..max]);
                match result{
                    Ok(0)=>{
                        self.pipes[1].eof=true;
                        if self.request_sent && (!self.terminal_seen || self.used!=self.terminal_start+wire::TERMINAL_BYTES){
                            self.output_failed=true;self.fail(Problem::Protocol);
                        }
                    },
                    Ok(n)=>{self.used+=n;if self.used>wire::RESPONSE_LIMIT{self.output_failed=true;self.fail(Problem::Capacity);}else{self.consume_frames();}},
                    Err(nix::errno::Errno::EAGAIN)=>{},
                    Err(_)=>{self.pipes[1].failed=true;self.output_failed=true;self.fail(Problem::CleanupUnknown);}
                }
            }
        }
        if self.pipes[2].state==PipeState::Held && !self.pipes[2].eof && !self.pipes[2].failed{
            let mut discard=[0;64];match unistd::read(self.pipes[2].original().unwrap(),&mut discard){
                Ok(0)=>self.pipes[2].eof=true,Ok(_)=>{self.stderr_seen=true;self.fail(Problem::Protocol);},
                Err(nix::errno::Errno::EAGAIN)=>{},Err(_)=>{self.pipes[2].failed=true;self.fail(Problem::CleanupUnknown);}
            }discard.zeroize();
        }
    }
    fn observe_exit(&mut self){
        if self.exit.is_some() || self.wait_failed{return;}
        if let Some(child)=self.child.as_mut(){
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
            { self.qualification.try_wait_entered = true; self.qualification.try_wait_returned = false; }
            let result = child.try_wait();
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
            { self.qualification.try_wait_returned = true; }
            match result{Ok(Some(exit))=>{
                    self.exit=Some(exit);if !exit.success(){self.fail(Problem::Unavailable);}
                },Ok(None)=>{},
                Err(_)=>{self.wait_failed=true;self.fail(Problem::CleanupUnknown);}}
        }
    }
    pub(crate) fn cleanup_expired(&self)->bool{self.cleanup.is_none_or(|end|Instant::now()>=end)}
    /// Returns true only when no further original process pump is pending.
    pub(crate) fn pump(&mut self)->bool{
        if self.work.is_some_and(|end|Instant::now()>=end) && self.first.is_none(){self.fail_at(Problem::Interrupted,self.work.unwrap());}
        if self.launch!=Launch::Returned{return true;}
        if !self.cleanup_expired(){self.write_control();self.read_pipes();self.observe_exit();}
        if self.exit.is_some(){
            if !self.pipes[1].eof || !self.pipes[2].eof{if !self.cleanup_expired(){return false;}}
            return true;
        }
        if self.cleanup_expired(){
            // Force only the retained actual Child, once. No process-ID/group,
            //name/account search, securityd operation or guessed ownership.
            self.fail(Problem::CleanupUnknown);
            if !self.kill_attempted && !self.wait_failed{
                self.kill_attempted=true;
                self.kill_failed=self.child.as_mut().is_none_or(|child|child.kill().is_err());
                // The registered worker retains this original wait. A blocked/
                //late return remains visible to OriginalWork's existing watchdog.
                if !self.kill_failed{
                    self.wait_entered=true;
                    match self.child.as_mut().unwrap().wait(){Ok(exit)=>self.exit=Some(exit),Err(_)=>self.wait_failed=true}
                }
            }return true;
        }
        false
    }
    fn project_cleanup(first:&mut Option<(Problem,Instant)>,cleanup:&mut Option<Instant>,uncertain:&mut bool,
        incoming:Option<(Problem,Instant)>,project:&mut dyn FnMut(Option<(Problem,Instant)>)->Result<Option<Instant>,Problem>)->bool{
        if let Some((p,at))=incoming{Self::latch_failure(first,cleanup,uncertain,p,at);}
        // The callback publishes F to the original owner's small projection,
        //then rereads actual Slot::stop contraction without taking document locks.
        match project(*first){
            Ok(Some(end))=>match end.checked_sub(Duration::from_secs(2)){
                Some(at)=>{
                    let p=first.map_or(Problem::Interrupted,|(p,_)|p);
                    Self::latch_failure(first,cleanup,uncertain,p,at);
                    *cleanup=cleanup.map(|old|old.min(end));
                },
                None=>{Self::latch_failure(first,cleanup,uncertain,Problem::CleanupUnknown,Instant::now());*cleanup=None;return false;}
            },
            Ok(None) if first.is_none()=>{},
            _=>{Self::latch_failure(first,cleanup,uncertain,Problem::CleanupUnknown,Instant::now());*cleanup=None;return false;}
        }
        cleanup.is_some_and(|end|Instant::now()<end)
    }
    pub(crate) fn finish_driver(&mut self,stopped:&mut dyn FnMut()->bool,
        project:&mut dyn FnMut(Option<(Problem,Instant)>)->Result<Option<Instant>,Problem>)->Result<(),Problem>{
        // Only the real helper process is quiescent before post-use native
        //admission IO. Never block the pipe pump on hashing/revalidation.
        if self.launch==Launch::Unstarted || self.launch==Launch::Claimed || self.exit.is_some(){
            if self.first.is_none(){
                let end=self.work;
                self.postchecked=self.slots.as_mut().is_some_and(|slots|slots.check_after_use(&mut ||
                    stopped() || end.is_none_or(|e|Instant::now()>=e)).is_ok());
                if !self.postchecked{
                    let at=self.slots.as_ref().and_then(VaultHelperSlots::first_failure).map_or_else(Instant::now,|(_,at)|at);
                    self.fail_at(Problem::UnsupportedProvider,at);
                }
            }
        }
        Self::project_cleanup(&mut self.first,&mut self.cleanup,&mut self.uncertain,None,project);
        if let Some(slots)=self.slots.as_mut(){
            let (first,cleanup,uncertain)=(&mut self.first,&mut self.cleanup,&mut self.uncertain);
            let settled=slots.settle_originals(&mut |failure|!Self::project_cleanup(first,cleanup,uncertain,
                failure.map(|(_,at)|(Problem::UnsupportedProvider,at)),project));
            if !settled{*uncertain=true;}
            let failure=slots.first_failure().map(|(_,at)|(Problem::UnsupportedProvider,at));
            Self::project_cleanup(first,cleanup,uncertain,failure,project);
        }
        for i in 0..3{
            if Self::project_cleanup(&mut self.first,&mut self.cleanup,&mut self.uncertain,None,project){
                // A returned close error is stamped BEFORE another original
                //pipe can consume. Unknown never fabricates a successful close.
                if !self.pipes[i].close(){self.fail(Problem::CleanupUnknown);}
                Self::project_cleanup(&mut self.first,&mut self.cleanup,&mut self.uncertain,None,project);
            }else if self.pipes[i].state!=PipeState::Closed{self.uncertain=true;}
        }
        if let Some((p,at))=self.first{self.fail_at(p,at);} // Retire private forward inputs too.
        if self.request_sent && (!self.terminal_seen || self.output_failed || !self.pipes[1].eof || !self.pipes[2].eof || self.stderr_seen){self.fail(Problem::Protocol);}
        if !self.request_sent && self.write_attempted{self.uncertain=true;}
        if self.first.is_none() && !self.transport_success(){self.fail(Problem::Unavailable);}
        Self::project_cleanup(&mut self.first,&mut self.cleanup,&mut self.uncertain,None,project);
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        { self.qualification.driver_before_cleanup = self.cleanup.is_some_and(|end| Instant::now() < end); }
        self.driver_returned=true;
        let result=if self.uncertain{Err(Problem::CleanupUnknown)}else if let Some(p)=self.problem(){Err(p)}else{Ok(())};
        self.driver_result=Some(result);result
    }
    fn native_settled(&self)->bool{
        if !self.write_attempted{return true;}
        self.terminal.as_ref().is_some_and(|t|t.valid && t.auth_settled && t.filesystem_settled && t.input_closed
            && t.add.as_ref().is_none_or(|r|r.settled()) && t.lookup.as_ref().is_none_or(|r|r.settled()))
    }
    fn transport_success(&self)->bool{
        self.request_sent && self.first.is_none() && !self.uncertain && !self.output_failed && !self.stderr_seen && self.postchecked
            && self.work.is_some_and(|end|Instant::now()<end)
            && self.exit.is_some_and(|s|s.success()) && !self.wait_failed && !self.kill_attempted
            && self.pipes.iter().all(Pipe::settled) && self.pipes[1].eof && self.pipes[2].eof
            && self.slots.as_ref().is_some_and(VaultHelperSlots::settled)
            && self.request.as_ref().is_some_and(|r|self.terminal.as_ref().is_some_and(|t|t.success(r.operation)))
            && self.used==self.terminal_start+wire::TERMINAL_BYTES
    }
    pub(crate) fn child_joined(&mut self,actual:Result<(),Problem>){
        if self.joined || !self.driver_returned || self.driver_result!=Some(actual){self.fail(Problem::CleanupUnknown);return;}
        self.joined=true;
        if self.first.is_none() && self.work.is_some_and(|end|Instant::now()>=end){
            self.fail_at(Problem::Interrupted,self.work.unwrap());
        }
        if actual.is_ok() && self.transport_success(){
            let mut bytes=Zeroizing::new([0;32]);
            let start=self.terminal_start+wire::TERMINAL_BYTES-32;bytes.copy_from_slice(&self.output[start..start+32]);
            self.candidate=Some(WrappingKeyCandidate{bytes});
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
            { self.qualification.application_constructed = true; }
        }
        self.output.zeroize();self.request_bytes.zeroize();
    }
    pub(crate) fn child_not_started(&mut self){
        // KeyringHelper is a cleanup-capable registered child: normal STOP
        //still runs its original-only retirement path and cannot grant GO.
        //A failed registration/join is NOT permission to execute native frame
        //cleanup on the coordinator or invent a real driver/join receipt.
        //Retain the prearmed frame and charge as Unknown for the same owner.
        self.fail(Problem::CleanupUnknown);
    }
    pub(crate) fn creation_possible(&self)->bool{self.effect!=0 || self.request.as_ref().is_some_and(|r|r.operation==wire::Operation::Initialize) && self.write_attempted}
    pub(crate) fn resources_settled(&self)->bool{
        if !self.entered{return true;}
        self.driver_returned && self.joined && !self.uncertain && !self.wait_failed && !self.kill_failed
            && matches!(self.launch,Launch::Unstarted|Launch::Claimed|Launch::Returned)
            && (self.launch!=Launch::Returned || self.exit.is_some())
            && self.pipes.iter().all(Pipe::settled) && self.native_settled()
            && self.slots.as_ref().is_none_or(VaultHelperSlots::settled)
    }
    pub(crate) fn cleanup_unknown(&self)->bool{self.uncertain || self.driver_returned &&
        (self.wait_failed || self.kill_failed || !self.native_settled() || self.pipes.iter().any(|p|!p.settled())
            || self.slots.as_ref().is_some_and(|s|!s.settled()))}
    pub(crate) fn local_cleanup_unknown(&self)->bool{self.cleanup_unknown()}
    pub(crate) fn document_cleanup_unknown(&self)->bool{self.cleanup_unknown()}
    pub(crate) fn allocations_released(&self)->bool{self.charge.is_none() && self.input.is_none() && self.request.is_none()
        && self.slots.is_none() && self.command.is_none() && self.child.is_none() && self.candidate.is_none()}
    pub(crate) fn consume_settled_key<R>(&mut self,authenticate:impl FnOnce(WrappingKeyCandidate)->R)->Result<R,Problem>{
        if !self.resources_settled() || !self.memory_held() || self.first.is_some() || !self.joined
            || self.work.is_none_or(|end|Instant::now()>=end){return Err(self.problem().unwrap_or(Problem::CleanupUnknown));}
        let candidate=self.candidate.take().ok_or(Problem::CleanupUnknown)?;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        { self.qualification.application_taken = true; }
        let result = authenticate(candidate);
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        { self.qualification.application_returned = true; }
        Ok(result)
    }
    pub(crate) fn dispose_settled_storage(&mut self)->bool{
        if self.disposed || !self.memory_held() || !self.resources_settled(){return false;}
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        { self.qualification.saved = self.qualification_snapshot(); }
        self.input=None;self.request=None;self.command=None;self.slots=None;
        if let Some(child)=self.child.take(){drop(ManuallyDrop::into_inner(child));}
        self.candidate=None;self.output.zeroize();self.request_bytes.zeroize();
        self.charge.take();self.disposed=true;true
    }
    /// Opaque native allocations while the helper or ACL call is pending are
    ///unknown, not a zero-byte refund of the preadmitted original charge.
    pub(crate) fn retained_bytes(&self)->Option<usize>{
        if self.launch==Launch::Entered || self.launch==Launch::Failed || self.launch==Launch::Returned && self.exit.is_none()
            || self.uncertain || !self.native_settled(){return None;}
        let native=self.slots.as_ref().map_or(Some(0),VaultHelperSlots::retained_bytes)?;
        LOOKUP_CONTROL_BYTES.checked_add(LOOKUP_WIRE_BYTES)?.checked_add(native)
    }
    pub(crate) fn turn_delay(&self)->Duration{
        self.cleanup.and_then(|end|end.checked_duration_since(Instant::now())).unwrap_or_default().min(Duration::from_millis(5))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // Closed DATA only: no helper, FD, Keychain, admission frame or credentials.
    fn request(operation:wire::Operation)->Request{
        Request{operation,nonce:[1;16],vault:[2;16],generation:[3;16],work:11,maximum_cleanup:12,
            initial_key:Zeroizing::new([0;32])}
    }
    fn failed_terminal(request:&Request)->[u8;wire::TERMINAL_BYTES]{
        let mut out=[0;wire::TERMINAL_BYTES];
        out[..8].copy_from_slice(b"MRKVKT01");out[8..12].copy_from_slice(&1u32.to_le_bytes());
        out[12..16].copy_from_slice(&request.operation.code().to_le_bytes());
        out[16..32].copy_from_slice(&request.nonce);out[32..48].copy_from_slice(&request.vault);
        out[48..64].copy_from_slice(&request.generation);
        out[64..72].copy_from_slice(&request.work.to_le_bytes());
        out[72..80].copy_from_slice(&request.maximum_cleanup.to_le_bytes());
        out[88..96].copy_from_slice(&request.maximum_cleanup.to_le_bytes());
        out[100..104].copy_from_slice(&1u32.to_le_bytes());
        out
    }
    #[test]
    fn only_valid_decoded_terminal_input_retirement_suppresses_stop_control(){
        let mut book=LookupBook::new();book.request=Some(request(wire::Operation::Initialize));
        book.request_sent=true;book.first=Some((Problem::Interrupted,Instant::now()));
        assert!(book.needs_stop_control()); // No terminal, regardless of notice/effect.
        book.notice_seen=true;book.effect=1;assert!(book.needs_stop_control());
        for (valid,closed) in [(false,false),(false,true),(true,false),(true,true)]{
            book.terminal=Some(Terminal{first:0,cleanup:12,effect:0,valid,add:None,lookup:None,
                auth_settled:false,filesystem_settled:false,input_closed:closed,candidate:false});
            book.terminal_seen=false;assert!(book.needs_stop_control());
            book.terminal_seen=true;assert_eq!(book.needs_stop_control(),!(valid && closed));
            assert!(!book.resources_settled());assert!(book.candidate.is_none());
            assert_eq!(book.problem(),Some(Problem::Interrupted));
        }
        book.request=None;assert!(book.needs_stop_control());
    }
    #[test]
    fn first_failure_contracts_once_and_never_erases_an_actual_add(){
        let start=Instant::now();let mut book=LookupBook::new();
        book.work=Some(start+Duration::from_secs(10));book.cleanup=Some(start+Duration::from_secs(12));
        book.request=Some(request(wire::Operation::Initialize));
        assert!(book.apply_effect(3));assert!(book.apply_effect(1));
        book.fail_at(Problem::Unavailable,start+Duration::from_secs(4));
        book.fail_at(Problem::Interrupted,start+Duration::from_secs(8));
        assert_eq!(book.cleanup,Some(start+Duration::from_secs(6)));
        book.fail_at(Problem::Denied,start+Duration::from_secs(1));
        assert_eq!(book.cleanup,Some(start+Duration::from_secs(3)));
        assert_eq!(book.problem_at(),Some(start+Duration::from_secs(1)));
        assert_eq!(book.effect,1);assert!(book.creation_possible());
        assert!(!book.apply_effect(0));assert!(!book.apply_effect(2));
    }
    #[test]
    fn refusal_never_fabricates_driver_return_join_native_cleanup_or_refund(){
        let mut book=LookupBook::new();book.entered=true;
        book.work=Some(Instant::now()+Duration::from_secs(10));
        book.cleanup=book.work.map(|end|end+Duration::from_secs(2));
        book.child_not_started();
        assert_eq!(book.problem(),Some(Problem::CleanupUnknown));
        assert!(!book.driver_entered && !book.driver_returned && !book.joined);
        assert!(!book.resources_settled());assert!(book.retained_bytes().is_none());
        assert!(!book.dispose_settled_storage());
    }
    #[test]
    fn terminal_failure_and_trailing_output_are_latched_when_parsed_not_after_close(){
        let mut book=LookupBook::new();book.entered=true;
        book.cleanup=Some(Instant::now()+Duration::from_secs(2));
        let request=request(wire::Operation::Lookup);let terminal=failed_terminal(&request);
        book.request=Some(request);
        book.output[..terminal.len()].copy_from_slice(&terminal);
        book.used=terminal.len()-1;book.consume_frames();assert!(!book.terminal_seen);
        book.used=terminal.len();book.consume_frames();
        assert!(book.terminal_seen);assert_eq!(book.problem(),Some(Problem::Unavailable));
        assert!(book.candidate.is_none());assert!(!book.resources_settled());
        let first=book.problem_at();let cleanup=book.cleanup;
        book.output[book.used]=1;book.used+=1;book.consume_frames();
        assert!(book.output_failed);assert_eq!(book.problem_at(),first);assert_eq!(book.cleanup,cleanup);
    }
    #[test]
    fn cleanup_projection_observes_a_stop_arriving_during_original_settlement(){
        let now=Instant::now();let mut first=None;let mut end=Some(now+Duration::from_secs(12));let mut uncertain=false;
        let mut inherited=None;
        assert!(LookupBook::project_cleanup(&mut first,&mut end,&mut uncertain,None,&mut |_|Ok(inherited)));
        inherited=Some(now); // Actual original mailbox now reports already-due cleanup.
        assert!(!LookupBook::project_cleanup(&mut first,&mut end,&mut uncertain,None,&mut |_|Ok(inherited)));
        assert_eq!(end,Some(now));assert!(first.is_some());
        assert!(!LookupBook::project_cleanup(&mut first,&mut end,&mut uncertain,None,&mut |_|Ok(Some(now+Duration::from_secs(9)))));
        assert_eq!(end,Some(now));
    }
    #[test]
    fn an_unknown_original_projection_cannot_reopen_cleanup_on_a_later_callback(){
        let now=Instant::now();let mut first=None;let mut end=Some(now+Duration::from_secs(12));let mut uncertain=false;
        assert!(!LookupBook::project_cleanup(&mut first,&mut end,&mut uncertain,None,&mut |_|Err(Problem::CleanupUnknown)));
        assert_eq!(end,None);assert!(uncertain);
        assert!(!LookupBook::project_cleanup(&mut first,&mut end,&mut uncertain,None,&mut |_|Ok(Some(now+Duration::from_secs(2)))));
        assert_eq!(end,None);
        let mut book=LookupBook::new();book.first=first;book.cleanup=end;book.uncertain=uncertain;
        book.constrain_cleanup_endpoint(now,now+Duration::from_secs(2));
        assert_eq!(book.cleanup,None);assert!(book.uncertain);
    }
    #[test]
    fn failed_pipe_close_publishes_first_before_the_next_original_consume(){
        for expire in [false,true]{
            let now=Instant::now();let mut book=LookupBook::new();
            book.work=Some(now+Duration::from_secs(10));book.cleanup=Some(now+Duration::from_secs(12));
            book.entered=true;book.launch=Launch::Returned; // Inert dispatch model; no Child/native slot.
            book.pipes[0].state=PipeState::Unknown; // No descriptor exists or is closed.
            let mut seen=false;
            let result=book.finish_driver(&mut ||false,&mut |failure|{
                if let Some((_,at))=failure{seen=true;Ok(Some(if expire{now}else{at+Duration::from_secs(2)}))}else{Ok(None)}
            });
            assert_eq!(result,Err(Problem::CleanupUnknown));assert!(seen);
            assert_eq!(book.pipes[1].state==PipeState::Closed,!expire);
            assert_eq!(book.pipes[2].state==PipeState::Closed,!expire);
            assert!(!book.resources_settled() && book.candidate.is_none());
        }
    }
    #[test]
    fn initialization_attempt_ambiguity_is_not_a_fabricated_added_effect(){
        let mut book=LookupBook::new();book.request=Some(request(wire::Operation::Initialize));
        assert!(!book.creation_possible());book.write_attempted=true;
        assert!(book.creation_possible());assert_eq!(book.effect,0);
        book.request=Some(request(wire::Operation::Lookup));
        assert!(!book.creation_possible());assert!(!book.apply_effect(1));
    }
}


#[cfg(test)]
impl LookupBook {
    pub(crate) fn constructor_refusal_data()->Self {
        // Common census/late-cleanup DATA sentinel: charged private storage
        //with NO entered helper/native/driver resource. No native constructor
        //or successful join receipt is simulated or claimed by this fixture.
        let mut book=Self::new();
        book.charge=Some(KeyringMemoryAdmission::data(0,0).unwrap());
        book.first=Some((Problem::Unavailable,Instant::now()));
        book
    }
}

// Observer DATA is absent from every normal app/helper profile. It is captured
// before disposal, and it never becomes an admission or cleanup token.
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
mod qualification {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    #[derive(Default)]
    pub(super) struct Book {
        pub(super) application_constructed: bool, pub(super) application_taken: bool, pub(super) application_returned: bool,
        pub(super) driver_before_cleanup: bool, pub(super) saved: Option<Snapshot>,
        pub(super) try_wait_entered: bool, pub(super) try_wait_returned: bool,
    }
    #[derive(Clone, Copy, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct Snapshot {
        pub(crate) go: bool, pub(crate) request_sent: bool, write_attempted: bool, stop_attempted: bool, stop_sent: bool,
        notice: bool, terminal: bool, pub(crate) successful_add_terminal: bool, output_failed: bool, stderr_seen: bool,
        terminal_success: bool, auth_settled: Option<bool>, filesystem_settled: Option<bool>, native_input_closed: Option<bool>,
        add_outcome: Option<&'static str>, add_settled: Option<bool>, lookup_settled: Option<bool>, add_effect: u32,
        add_item_calls_absent: Option<bool>, add_prerequisite_refused: Option<bool>,
        pub(crate) native_candidate_consumed: Option<bool>,
        try_wait_entered: bool, try_wait_returned: bool, wait_entered: bool, exit_observed: bool, exit_success: Option<bool>, wait_failed: bool, kill_attempted: bool, kill_failed: bool,
        stdout_eof: bool, stderr_eof: bool, pipe_closed: [bool; 3], helper_slots_settled: bool,
        driver_returned: bool, driver_before_cleanup: bool, blocking_child_joined: bool, resources_settled: bool, allocations_released: bool,
        first_failure: Option<&'static str>, cleanup_contracted: bool, cleanup_unknown: bool,
        pub(crate) application_candidate_constructed: bool, application_candidate_taken: bool, application_callback_returned: bool,
    }
    /// Original returned status and byte count only. No pipe bytes, native
    /// terminal, cleanup receipt or new process observation is manufactured.
    #[derive(Clone, Copy, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct TransportSnapshot {
        exit_code: Option<i32>, exit_signal: Option<i32>, response_bytes: usize,
    }
    fn outcome(value: Outcome) -> &'static str { match value {
        Outcome::Pending=>"pending",Outcome::Added=>"added",Outcome::Candidate=>"candidate",Outcome::Missing=>"missing",
        Outcome::Duplicate=>"duplicate",Outcome::Locked=>"locked",Outcome::InteractionRequired=>"interaction-required",
        Outcome::AuthenticationFailed=>"authentication-failed",Outcome::UserCanceled=>"user-canceled",Outcome::Unavailable=>"unavailable",
        Outcome::Unsupported=>"unsupported",Outcome::InvalidInput=>"invalid-input",Outcome::InvalidResult=>"invalid-result",
        Outcome::Allocation=>"allocation",Outcome::Stopped=>"stopped",Outcome::CustodyUnknown=>"custody-unknown",
        Outcome::NativeFailure=>"native-failure",Outcome::NativeException=>"native-exception",
    } }
    fn problem(value: Problem) -> &'static str { match value {
        Problem::Interrupted=>"interrupted",Problem::CleanupUnknown=>"cleanup-unknown",Problem::Capacity=>"capacity",
        Problem::Locked=>"locked",Problem::MissingKey=>"missing-key",Problem::Denied=>"denied",Problem::UnsupportedProvider=>"unsupported-provider",
        Problem::Unavailable=>"unavailable",Problem::InvalidInput=>"invalid-input",Problem::IdentityMismatch=>"identity-mismatch",
        Problem::Crypto=>"crypto",Problem::Protocol=>"protocol",
    } }
    impl Snapshot {
        pub(crate) fn value(&self) -> serde_json::Value { serde_json::json!(self) }
        pub(crate) fn final_settlement(&self) -> bool {
            self.driver_returned && self.driver_before_cleanup && self.blocking_child_joined && self.resources_settled
                && self.allocations_released && self.exit_observed && self.try_wait_entered && self.try_wait_returned
                && !self.wait_entered && !self.wait_failed && !self.kill_attempted && !self.kill_failed && !self.output_failed && !self.stderr_seen
                && self.stdout_eof && self.stderr_eof && self.pipe_closed == [true;3] && self.helper_slots_settled && !self.cleanup_unknown
                && (!self.write_attempted || self.terminal && self.auth_settled == Some(true) && self.filesystem_settled == Some(true)
                    && self.native_input_closed == Some(true) && self.add_settled.is_none_or(|v|v) && self.lookup_settled.is_none_or(|v|v))
        }
        pub(crate) fn successful_consumption(&self) -> bool {
            self.final_settlement() && self.go && self.request_sent && self.terminal_success && self.first_failure.is_none()
                && self.exit_success == Some(true) && self.native_candidate_consumed == Some(true)
                && self.application_candidate_constructed && self.application_candidate_taken && self.application_callback_returned
        }
        pub(crate) fn stopped_without_application_candidate(&self) -> bool {
            self.final_settlement() && self.first_failure == Some("interrupted") && self.cleanup_contracted
                && !self.application_candidate_constructed && !self.application_candidate_taken && !self.application_callback_returned
        }
        pub(crate) fn provider_negative(&self) -> bool {
            self.final_settlement() && self.go && self.request_sent && self.terminal && !self.terminal_success
                && matches!(self.add_outcome, Some("missing"|"locked"|"interaction-required"|"authentication-failed"|"unavailable"|"unsupported"|"native-failure"))
                && self.add_effect == 0 && self.add_settled == Some(true) && self.lookup_settled.is_none()
                && self.add_item_calls_absent == Some(true) && self.add_prerequisite_refused == Some(true)
                && self.first_failure.is_some() && self.first_failure != Some("interrupted")
                && self.native_candidate_consumed.is_none() && !self.application_candidate_constructed
                && !self.application_candidate_taken && !self.application_callback_returned
        }
    }
    pub(crate) fn data_checks() -> bool {
        // Predicate DATA only; no child/native receipt/key is constructed.
        let settled = Snapshot { go:true,request_sent:true,write_attempted:true,stop_attempted:false,stop_sent:false,
            notice:false,terminal:true,successful_add_terminal:true,terminal_success:true,output_failed:false,stderr_seen:false,
            auth_settled:Some(true),filesystem_settled:Some(true),native_input_closed:Some(true),
            add_outcome:Some("added"),add_settled:Some(true),lookup_settled:Some(true),add_effect:1,
            add_item_calls_absent:Some(false),add_prerequisite_refused:Some(false),native_candidate_consumed:Some(true),
            try_wait_entered:true,try_wait_returned:true,wait_entered:false,exit_observed:true,exit_success:Some(true),
            wait_failed:false,kill_attempted:false,kill_failed:false,stdout_eof:true,stderr_eof:true,pipe_closed:[true;3],
            helper_slots_settled:true,driver_returned:true,driver_before_cleanup:true,blocking_child_joined:true,
            resources_settled:true,allocations_released:true,first_failure:None,cleanup_contracted:false,cleanup_unknown:false,
            application_candidate_constructed:true,application_candidate_taken:true,application_callback_returned:true };
        if !settled.successful_consumption() { return false; }
        for field in 0..16 {
            let mut s=settled;
            match field {
                0=>s.try_wait_entered=false,1=>s.try_wait_returned=false,2=>s.exit_observed=false,
                3=>s.wait_entered=true,4=>s.wait_failed=true,5=>s.stdout_eof=false,6=>s.stderr_eof=false,
                7=>s.pipe_closed[0]=false,8=>s.helper_slots_settled=false,9=>s.driver_returned=false,
                10=>s.driver_before_cleanup=false,11=>s.blocking_child_joined=false,12=>s.resources_settled=false,
                13=>s.allocations_released=false,14=>s.output_failed=true,_=>s.stderr_seen=true,
            }
            if s.final_settlement() || s.successful_consumption() { return false; }
        }
        let mut stopped=settled;stopped.first_failure=Some("interrupted");stopped.cleanup_contracted=true;
        stopped.application_candidate_constructed=false;stopped.application_candidate_taken=false;stopped.application_callback_returned=false;
        if !stopped.stopped_without_application_candidate() || stopped.successful_consumption() { return false; }
        for field in 0..5 {
            let mut s=stopped;
            match field {0=>s.application_candidate_constructed=true,1=>s.application_candidate_taken=true,
                2=>s.application_callback_returned=true,3=>s.cleanup_contracted=false,_=>s.cleanup_unknown=true}
            if s.stopped_without_application_candidate() { return false; }
        }
        let mut negative=stopped;negative.first_failure=Some("locked");negative.terminal_success=false;
        negative.add_outcome=Some("locked");negative.add_effect=0;negative.lookup_settled=None;
        negative.native_candidate_consumed=None;negative.add_item_calls_absent=Some(true);negative.add_prerequisite_refused=Some(true);
        if !negative.provider_negative() { return false; }
        for field in 0..5 {
            let mut s=negative;
            match field {0=>s.add_effect=3,1=>s.add_item_calls_absent=Some(false),2=>s.add_prerequisite_refused=Some(false),
                3=>s.lookup_settled=Some(true),_=>s.native_candidate_consumed=Some(true)}
            if s.provider_negative() { return false; }
        }
        // Inert DATA statuses, not an executed helper or native exit receipt.
        let mut book=LookupBook::new();
        if book.qualification_transport_snapshot().is_some() { return false; }
        book.entered=true;
        let Some(empty)=book.qualification_transport_snapshot() else { return false; };
        if empty.exit_code.is_some() || empty.exit_signal.is_some() || empty.response_bytes!=0 { return false; }
        book.exit=Some(ExitStatus::from_raw(64 << 8));book.used=wire::RESPONSE_LIMIT+1;
        let Some(refused)=book.qualification_transport_snapshot() else { return false; };
        if refused.exit_code!=Some(64) || refused.exit_signal.is_some() || refused.response_bytes!=16385 { return false; }
        book.exit=Some(ExitStatus::from_raw(9));
        let Some(signaled)=book.qualification_transport_snapshot() else { return false; };
        if signaled.exit_code.is_some() || signaled.exit_signal!=Some(9) { return false; }
        true
    }
    impl LookupBook {
        pub(crate) fn qualification_transport_snapshot(&self) -> Option<TransportSnapshot> {
            // Both fields stay in this original book after settled storage
            // disposal; do not inspect the already-zeroized output buffer.
            self.entered.then(|| TransportSnapshot {
                exit_code:self.exit.as_ref().and_then(ExitStatus::code),
                exit_signal:self.exit.as_ref().and_then(ExitStatusExt::signal),response_bytes:self.used,
            })
        }
        pub(crate) fn qualification_before_go(&self) -> bool {
            self.driver_entered && self.launch == Launch::Returned && !self.go && !self.write_attempted && !self.request_sent
                && self.first.is_none() && !self.uncertain && !self.joined
                && self.request.as_ref().is_some_and(|r|r.operation == wire::Operation::Initialize)
        }
        pub(crate) fn qualification_added_checkpoint(&self) -> bool {
            // Notice always denotes F; only the actual successful decoded
            // Initialize terminal can satisfy this checkpoint, including EOF.
            self.driver_entered && self.go && self.request_sent && self.first.is_none() && !self.uncertain && !self.joined
                && self.candidate.is_none() && !self.qualification.application_constructed
                && self.request.as_ref().is_some_and(|r| r.operation == wire::Operation::Initialize
                    && self.terminal.as_ref().is_some_and(|t|t.success(r.operation) && t.add.as_ref().is_some_and(|a|a.added())))
        }
        pub(crate) fn qualification_snapshot(&self) -> Option<Snapshot> {
            if !self.entered { return None; }
            if let Some(mut saved) = self.qualification.saved {
                // Disposal removes only storage. Later failure/finality facts
                // remain actual and cannot be hidden by this retained history.
                saved.allocations_released = self.allocations_released();
                saved.resources_settled &= self.resources_settled();
                saved.blocking_child_joined &= self.joined;
                saved.driver_returned &= self.driver_returned;
                saved.output_failed |= self.output_failed; saved.stderr_seen |= self.stderr_seen;
                saved.wait_failed |= self.wait_failed; saved.kill_failed |= self.kill_failed;
                saved.first_failure = self.first.map(|(p,_)|problem(p));
                saved.cleanup_contracted = self.first.is_some_and(|(_,at)|self.cleanup.is_some_and(|end|
                    at.checked_add(Duration::from_secs(2)).is_some_and(|maximum|end <= maximum)));
                saved.cleanup_unknown |= self.cleanup_unknown();
                return Some(saved);
            }
            let terminal = self.terminal.as_ref();
            Some(Snapshot { go:self.go,request_sent:self.request_sent,write_attempted:self.write_attempted,
                stop_attempted:self.stop_attempted,stop_sent:self.stop_sent,notice:self.notice_seen,terminal:self.terminal_seen,
                output_failed:self.output_failed,stderr_seen:self.stderr_seen,
                successful_add_terminal:terminal.is_some_and(|t|t.success(wire::Operation::Initialize) && t.add.as_ref().is_some_and(|a|a.added())),
                terminal_success:self.request.as_ref().is_some_and(|r|terminal.is_some_and(|t|t.success(r.operation))),
                auth_settled:terminal.map(|t|t.auth_settled),filesystem_settled:terminal.map(|t|t.filesystem_settled),
                native_input_closed:terminal.map(|t|t.input_closed),
                add_outcome:terminal.and_then(|t|t.add.as_ref()).map(|r|outcome(r.facts().outcome())),
                add_settled:terminal.and_then(|t|t.add.as_ref()).map(|r|r.settled()),
                lookup_settled:terminal.and_then(|t|t.lookup.as_ref()).map(|r|r.settled()),add_effect:self.effect,
                add_item_calls_absent:terminal.and_then(|t|t.add.as_ref()).map(|r|r.facts().security_calls()
                    .is_some_and(|calls|calls.iter().all(|c|!matches!(c.phase,10|11)))),
                add_prerequisite_refused:terminal.and_then(|t|t.add.as_ref()).map(|r|matches!(r.facts().first_refusal_phase(),
                    Some(2|3|4|5|6|17|18|19))),
                native_candidate_consumed:terminal.and_then(|t|t.lookup.as_ref()).map(|r|r.candidate_consumed()),
                try_wait_entered:self.qualification.try_wait_entered,try_wait_returned:self.qualification.try_wait_returned,
                wait_entered:self.wait_entered,exit_observed:self.exit.is_some(),exit_success:self.exit.map(|e|e.success()),
                wait_failed:self.wait_failed,kill_attempted:self.kill_attempted,kill_failed:self.kill_failed,
                stdout_eof:self.pipes[1].eof,stderr_eof:self.pipes[2].eof,pipe_closed:self.pipes.each_ref().map(|p|p.settled()),
                helper_slots_settled:self.slots.as_ref().is_some_and(VaultHelperSlots::settled),
                driver_returned:self.driver_returned,driver_before_cleanup:self.qualification.driver_before_cleanup,
                blocking_child_joined:self.joined,resources_settled:self.resources_settled(),allocations_released:self.allocations_released(),
                first_failure:self.first.map(|(p,_)|problem(p)),
                cleanup_contracted:self.first.is_some_and(|(_,at)|self.cleanup.is_some_and(|end|
                    at.checked_add(Duration::from_secs(2)).is_some_and(|maximum|end <= maximum))),
                cleanup_unknown:self.cleanup_unknown(),application_candidate_constructed:self.qualification.application_constructed,
                application_candidate_taken:self.qualification.application_taken,application_callback_returned:self.qualification.application_returned })
        }
    }
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
use qualification::Book as QualificationBook;
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
pub(crate) use qualification::Snapshot as QualificationSnapshot;

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
pub(crate) use qualification::TransportSnapshot as QualificationTransportSnapshot;

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
pub(crate) use qualification::data_checks as qualification_data_checks;
