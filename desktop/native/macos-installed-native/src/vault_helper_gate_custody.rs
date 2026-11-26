//! Explicit no-GO Darwin custody control, not another shipping process runner.
//! Requires Root's reviewed exact installed-source/original-owner admission.
//! Select this ONE ignored test, never a raw/all-ignored historical suite.
//! EX baseline must succeed: an ordinary app-entry SH makes this unavailable.
//! Parent-reference close is NOT actual parent disappearance/direct-loader proof.
use super::*;
use crate::vault_helper_launch::FixedCommand;
use std::{process::{Child,ExitStatus},time::Duration};
use nix::errno::Errno;

struct Cutoff{work:Instant,hard:Instant,first:Option<(&'static str,Instant)>}
impl Cutoff{
    fn new()->Option<Self>{let now=Instant::now();Some(Self{work:now.checked_add(Duration::from_secs(20))?,
        hard:now.checked_add(Duration::from_secs(22))?,first:None})}
    fn fail_at(&mut self,stage:&'static str,at:Instant){
        if self.first.is_none_or(|(_,old)|at<old){self.first=Some((stage,at));}
    }
    fn fail(&mut self,stage:&'static str){self.fail_at(stage,Instant::now());}
    fn absorb(&mut self,failure:Option<(Failure,Instant)>){
        if let Some((_,at))=failure{self.fail_at("native-original",at);}
    }
    fn work_expired(&mut self)->bool{
        if Instant::now()>=self.work{self.fail_at("work-deadline",self.work);}
        self.first.is_some()
    }
    fn end(&self)->Option<Instant>{match self.first{Some((_,at))=>at.checked_add(Duration::from_secs(2)).map(|end|end.min(self.hard)),None=>Some(self.hard)}}
    fn cleanup_expired(&mut self,failure:Option<(Failure,Instant)>)->bool{
        self.absorb(failure);self.end().is_none_or(|end|Instant::now()>=end)
    }
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Probe{Available,Busy}
// Each probe is a SEPARATELY opened original. Its offset is not shared with the
// helper participant. EX is released by consuming close, never LOCK_UN/Drop.
fn probe(want:Probe,identity:Option<Identity>,clock:&mut Cutoff)->Option<Identity>{
    let mut original=CodeOriginals::new();original.entered=true;original.gate.requested=true;
    let result=(||{
        let mut stop=||clock.work_expired();
        original.arm_acl(&mut stop)?;
        for i in 0..4{original.open_code_original(i,&mut stop)?;}
        original.open_gate(&mut stop)?;CodeOriginals::check(&mut stop)?;
        let found=original.gate.original.identity.ok_or(Failure::Unknown)?;
        if identity.is_some_and(|expected|expected!=found){return Err(Failure::Identity);}
        original.gate.lock_entered=true;
        #[allow(deprecated)]
        let result=fcntl::flock(original.gate_fd()?.as_raw_fd(),fcntl::FlockArg::LockExclusiveNonblock);
        original.gate.lock_returned=true;
        let actual=match result{Ok(())=>{original.gate.locked=true;Probe::Available},
            Err(Errno::EWOULDBLOCK)=>Probe::Busy,Err(_)=>return Err(Failure::Native)};
        if actual!=want{return Err(Failure::Ownership);}
        CodeOriginals::check(&mut stop)?;original.inspect_gate(&mut stop)?;Ok(found)
    })();
    if let Err(problem)=result{original.fail(problem);}
    clock.absorb(original.first_failure());
    let code=original.release_code(&mut |failure|clock.cleanup_expired(failure));
    let gate=original.release_worker_gate(&mut |failure|clock.cleanup_expired(failure));
    clock.absorb(original.first_failure());
    if !code || !gate || clock.cleanup_expired(None){clock.fail("probe-finality");}
    // Unknown native/descriptor records stay retained for the owning process;
    // no RAII close/retry manufactures a probe result on this path.
    if !original.settled(){std::mem::forget(original);}
    if clock.first.is_none(){result.ok()}else{None}
}
struct Pipe{original:Record,eof:bool,failed:bool,nonblocking_known:bool}
impl Pipe{
    fn new()->Self{Self{original:Record::new(),eof:false,failed:false,nonblocking_known:false}}
    fn retain(&mut self,fd:Option<OwnedFd>)->bool{match fd{
        Some(fd)=>{self.original.fd=Some(ManuallyDrop::new(fd));self.original.state=State::Held;true},
        None=>{self.original.state=State::Unknown;self.failed=true;false}
    }}
    fn nonblocking(&mut self)->bool{
        let Some(fd)=self.original.fd.as_ref()else{return false;};
        let Ok(flags)=fcntl::fcntl(&**fd,fcntl::FcntlArg::F_GETFL)else{return false;};
        let Some(flags)=OFlag::from_bits(flags)else{return false;};
        self.nonblocking_known=fcntl::fcntl(&**fd,fcntl::FcntlArg::F_SETFL(flags|OFlag::O_NONBLOCK)).is_ok();
        self.nonblocking_known
    }
    fn observe_empty(&mut self)->bool{
        if self.eof{return true;}
        if self.failed || !self.nonblocking_known{self.failed=true;return false;}
        let Some(fd)=self.original.fd.as_ref()else{self.failed=true;return false;};
        let mut byte=[0u8;1];match unistd::read(&**fd,&mut byte){
            Ok(0)=>{self.eof=true;true},Err(Errno::EAGAIN)=>true,
            _=>{self.failed=true;false}, // No bytes are permitted without GO.
        }
    }
    fn close(&mut self)->bool{
        if self.original.state==State::Vacant{self.original.state=State::Closed;return true;}
        if self.original.state!=State::Held{return self.original.state==State::Closed;}
        self.original.state=State::Closing;
        match self.original.fd.take().map(ManuallyDrop::into_inner).map(unistd::close){
            Some(Ok(()))=>{self.original.state=State::Closed;true},
            _=>{self.original.state=State::Unknown;self.failed=true;false}
        }
    }
    fn settled(&self)->bool{self.original.state==State::Closed && self.original.fd.is_none() && !self.failed}
}
struct Control{
    originals:CodeOriginals,command:FixedCommand,child:Option<ManuallyDrop<Child>>,pipes:[Pipe;3],
    launch_entered:bool,exit:Option<ExitStatus>,wait_failed:bool,kill_entered:bool,kill_failed:bool,
    parent_close_entered:bool,parent_closed:bool,baseline:Option<Identity>,child_only_busy:bool,
}
impl Control{
    fn new()->Self{Self{originals:CodeOriginals::new(),command:FixedCommand::new(),child:None,
        pipes:std::array::from_fn(|_|Pipe::new()),launch_entered:false,exit:None,wait_failed:false,
        kill_entered:false,kill_failed:false,parent_close_entered:false,parent_closed:false,
        baseline:None,child_only_busy:false}}
    fn observe_exit(&mut self,clock:&mut Cutoff){
        if self.exit.is_some() || self.wait_failed{return;}
        if let Some(child)=self.child.as_mut(){match child.try_wait(){
            Ok(exit)=>self.exit=exit,Err(_)=>{self.wait_failed=true;clock.fail("original-wait");}
        }}
    }
    fn attempt(&mut self,clock:&mut Cutoff)->Result<(),&'static str>{
        self.baseline=probe(Probe::Available,None,clock);
        if self.baseline.is_none(){return Err("exclusive-baseline");}
        self.originals.acquire_for_helper_launch(&mut ||clock.work_expired()).map_err(|_|"participant-admission")?;
        if self.originals.gate.original.identity!=self.baseline{return Err("same-gate-identity");}
        self.command.prepare(&mut self.originals).map_err(|_|"fixed-preparation")?;
        if clock.work_expired(){return Err("before-spawn");}
        self.launch_entered=true; // Returned Err remains an entered/unknown launch.
        let child=self.command.spawn_once(&mut self.originals).map_err(|_|"fixed-spawn")?;
        self.child=Some(ManuallyDrop::new(child));
        let child=self.child.as_mut().ok_or("original-child")?;
        let pipes=[child.stdin.take().map(OwnedFd::from),child.stdout.take().map(OwnedFd::from),child.stderr.take().map(OwnedFd::from)];
        let mut ready=true;
        for (slot,fd) in self.pipes.iter_mut().zip(pipes){ready &= slot.retain(fd);}
        for slot in &mut self.pipes[1..]{ready &= slot.nonblocking();}
        if !ready{return Err("original-pipes");}
        if clock.work_expired(){return Err("after-spawn");}
        let fd=self.originals.gate_fd().map_err(|_|"parent-gate")?;
        if fcntl::fcntl(fd,fcntl::FcntlArg::F_GETFD).ok()!=Some(fcntl::FdFlag::FD_CLOEXEC.bits()){
            return Err("parent-cloexec");
        }
        self.observe_exit(clock);
        if self.wait_failed || self.exit.is_some() || clock.work_expired(){return Err("child-before-reference-close");}
        // ONLY this nonshipping test consumes the parent reference early. It
        // does not call or weaken the shipping close-last API or invent its
        // postcheck. The existing exact Child/three originals remain retained.
        self.parent_close_entered=true;self.originals.gate.original.state=State::Closing;
        let original=self.originals.gate.original.fd.take().map(ManuallyDrop::into_inner);
        match original.map(unistd::close){
            Some(Ok(()))=>{self.parent_closed=true;self.originals.gate.original.state=State::Closed;self.originals.gate.retired=true;},
            _=>{self.originals.gate.original.state=State::Unknown;self.originals.gate.unknown=true;return Err("parent-reference-close");}
        }
        if clock.work_expired(){return Err("after-parent-reference-close");}
        self.child_only_busy=probe(Probe::Busy,self.baseline,clock).is_some();
        self.observe_exit(clock);
        if !self.child_only_busy || self.wait_failed || self.exit.is_some(){return Err("live-child-only-shared-custody");}
        Ok(()) // No request, GO, nonce, credential or Keychain operation exists.
    }
    fn finish(&mut self,clock:&mut Cutoff)->bool{
        clock.absorb(self.originals.first_failure());self.command.retire_prepared_storage();
        // EOF on the one original stdin is the normal no-GO helper retirement.
        if !clock.cleanup_expired(None) && !self.pipes[0].close(){clock.fail("stdin-close");}
        while self.child.is_some() && !self.wait_failed && !clock.cleanup_expired(None){
            self.observe_exit(clock);
            for slot in &mut self.pipes[1..]{if !slot.observe_empty(){clock.fail("nonempty-helper-output");}}
            if self.exit.is_some() && self.pipes[1..].iter().all(|p|p.eof || p.failed){break;}
            clock.work_expired();
            // Failure-only termination of this retained Child, once, before the
            // original cleanup cutoff. No IDs/scans/groups/other task processes.
            let force=clock.first.is_some_and(|(_,at)|Instant::now().saturating_duration_since(at)>=Duration::from_secs(1));
            if force && self.exit.is_none() && !self.kill_entered && !clock.cleanup_expired(None){
                self.kill_entered=true;
                self.kill_failed=self.child.as_mut().is_none_or(|child|child.kill().is_err());
                if self.kill_failed{clock.fail("original-kill");}
            }
            if let Some(end)=clock.end(){std::thread::sleep(end.saturating_duration_since(Instant::now()).min(Duration::from_millis(5)));}
        }
        let child_known=if self.launch_entered{self.child.is_some() && self.exit.is_some() && !self.wait_failed && !self.kill_failed}else{self.child.is_none()};
        if !child_known{clock.fail("child-finality");}
        if self.exit.is_some() && !self.parent_close_entered && !self.wait_failed{
            if self.originals.check_worker_gate_after_exit(&mut ||clock.cleanup_expired(None)).is_err(){clock.fail("gate-postcheck");}
        }
        let code=self.originals.release_code(&mut |failure|clock.cleanup_expired(failure));
        if !code{clock.fail("code-finality");}
        for slot in &mut self.pipes{if !clock.cleanup_expired(None) && !slot.close(){clock.fail("pipe-close");}}
        let pipes=self.pipes.iter().all(Pipe::settled);
        let gate=if self.parent_close_entered{
            self.parent_closed && self.originals.gate.original.state==State::Closed && self.originals.gate.original.fd.is_none()
        }else if child_known && pipes && code{
            self.originals.release_worker_gate(&mut |failure|clock.cleanup_expired(failure))
        }else{false};
        if !gate || !pipes || clock.cleanup_expired(None){clock.fail("control-finality");}
        // Successful no-GO shipping main returns1, not startup-refusal64..67,
        // signal termination, a forced kill, or a fabricated successful release.
        let no_go=self.exit.as_ref().and_then(ExitStatus::code)==Some(1)
            && !self.kill_entered && self.pipes[1].eof && self.pipes[2].eof;
        if !no_go{clock.fail("actual-no-go-exit");}
        let available=if clock.first.is_none() && child_known && gate && code && pipes{
            probe(Probe::Available,self.baseline,clock).is_some()
        }else{false};
        if child_known && self.exit.is_some(){
            if let Some(child)=self.child.take(){drop(ManuallyDrop::into_inner(child));}
        }
        child_known && gate && code && pipes && no_go && available && clock.first.is_none()
    }
}

#[test]
#[ignore="requires admitted protected installation, isolated native owner and exact shipping helper; no raw suite"]
fn shipping_helper_retains_gate_after_parent_reference_close_until_actual_exit(){
    let mut clock=Cutoff::new().expect("bounded control clock before any native admission");
    let mut control=Control::new();
    if let Err(stage)=control.attempt(&mut clock){clock.absorb(control.originals.first_failure());clock.fail(stage);}
    let positive=control.finish(&mut clock);
    let first=clock.first.map(|(stage,_)|stage);
    // Unknown originals are retained, not recycled through destructor cleanup.
    // The admitted containing native owner treats failure/late return as failed
    // and owns the original test process; this test never proves its own join.
    std::mem::forget(control);
    assert!(positive,"no-GO gate custody control failed: {:?}",first);
}
