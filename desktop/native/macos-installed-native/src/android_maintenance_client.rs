//! Private maintenance over the original ClientBook. No additional IPC/reader
//! thread, native manager, Signal, request arena, PID scan or reconnect.
use crate::{android_registration::{ClientBook,Signal,Failure,FrozenFailure},
    android_maintenance_wire::{self as wire,Binding,Frame,Kind,Code,Identity},
    android_service_client_data::TailCapture,vault_helper_wire::{ClockBridge,uptime}};
use std::{mem::ManuallyDrop,sync::Arc,time::Instant};
/// Owning, non-Clone admission. Only the real no-F client path constructs it.
/// Dropping an uncertain capture does not pretend same-DATA settlement.
pub struct TailAdmission { binding:Binding,cutoff:Instant,capture:TailCapture }
impl TailAdmission {
    pub fn cutoff(&self)->Instant{self.cutoff}
    pub fn operation(&self)->[u8;16]{self.binding.operation}
    pub fn retire(self){self.capture.retire();}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Drain { Started, Busy, Refused }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Progress { Pending, TailReceived, Exited }
#[cfg(feature = "e2-native-fixture")]
#[derive(Default)]
struct FixtureTrace { challenge:Option<Binding>, watch_registered:bool, missing_b_refused:bool }
/// Comparison DATA copied from this same Client, never an owning admission.
#[cfg(feature = "e2-native-fixture")]
#[derive(Clone,Copy)]
pub(crate) struct FixtureClientObservation {
    pub binding:Option<Binding>, pub tail:Option<[u8;wire::BYTES]>,
    pub watch_registered:bool, pub refused:bool, pub admission_issued:bool,
    pub eof:bool, pub exited:bool, pub custody:crate::android_registration::FixtureClientCustody,
}
pub struct Client {
    book:ClientBook,signal:ManuallyDrop<Arc<Signal>>,request:Binding,binding:Option<Binding>,
    tail:Option<wire::Tail>,buffer:[u8;wire::BYTES+1],used:usize,last:u64,
    begun:bool,drain_entered:bool,receipt_sent:bool,admission_issued:bool,eof:bool,exited:bool,retired:bool,
    #[cfg(feature = "e2-native-fixture")]
    fixture:FixtureTrace,
}
impl Client {
    pub fn new(signal:Arc<Signal>,operation:[u8;16])->Option<Self>{
        let bounds=signal.bounds()?;
        if signal.removal_cutoff().is_some() && !signal.admitted(false){return None;}
        let identity=Identity::build()?;
        let request=Binding::request(identity,operation,wire::Bounds{origin:bounds.origin,work:bounds.work,hard:bounds.hard})?;
        Some(Self{book:ClientBook::new_maintenance(signal.clone()),signal:ManuallyDrop::new(signal),
            request,binding:None,tail:None,buffer:[0;wire::BYTES+1],used:0,last:bounds.origin,begun:false,
            drain_entered:false,receipt_sent:false,admission_issued:false,eof:false,exited:false,retired:false,
            #[cfg(feature = "e2-native-fixture")]
            fixture:FixtureTrace::default(),
        })
    }
    pub fn requirements()->crate::android_service_budget::ClientRequirements{ClientBook::allocation_requirements()}
    pub fn project_owned_upper_bound()->Option<usize>{
        Self::requirements().known_bytes()?.checked_add(std::mem::size_of::<Self>())?
            .checked_add(crate::android_service_budget::maintenance_wire_high_water()?)
    }
    pub fn retained_bytes(&self)->Option<usize>{self.settled().then_some(std::mem::size_of::<Self>())}
    fn now(&mut self)->Result<u64,Failure>{
        let now=uptime().unwrap_or(0);
        if now<self.last || now>wire::MAX_RAW{self.signal.clock_unknown();return Err(Failure::Unknown);}
        self.last=now;Ok(now)
    }
    fn removal_cut(&mut self,cleanup:bool)->Result<(),Failure>{
        if self.signal.removal_cutoff().is_none(){return Ok(());}
        let now=self.now()?;
        if self.signal.admitted_at(cleanup,now){Ok(())}
        else{Err(if self.signal.unknown(){Failure::Unknown}else{Failure::Stopped})}
    }
    fn failed(&self,kind:Failure)->Failure{
        self.signal.failure_now(matches!(kind,Failure::Unknown|Failure::Native|Failure::Binding|Failure::Sequence));kind
    }
    fn call(&mut self,method:u32,frame:Frame,reply:Kind)->Result<Frame,Failure>{
        let input=frame.encode().ok_or_else(||self.failed(Failure::Binding))?;
        self.removal_cut(false)?;
        let raw=self.book.maintenance_exchange(method,&input)?;
        let now=self.now()?;
        let value=Frame::decode(&raw).filter(|value|value.kind==reply).ok_or_else(||self.failed(Failure::Binding))?;
        if value.binding.acceptance>now{return Err(self.failed(Failure::Binding));}
        // ClientBook already retained this real decoded return before its
        // native/clock POST. This local value grants no binding after a veto;
        // the owning book keeps the observation without declaring success.
        self.removal_cut(false)?;
        Ok(value)
    }
    fn challenge_and_watch(&mut self)->Result<Frame,Failure>{
        if self.begun || self.retired{return Err(self.failed(Failure::Sequence));}
        self.removal_cut(false)?;self.begun=true;
        self.book.begin()?;
        let a=self.call(3,Frame{kind:Kind::ChallengeA,code:Code::Accepted,binding:self.request,tail:None},Kind::ChallengeAReply)?;
        if a.code!=Code::Accepted || !a.binding.matches_request(self.request,self.book.maintenance_account()){
            return Err(self.failed(Failure::Binding));
        }
        #[cfg(feature = "e2-native-fixture")]
        { self.fixture.challenge=Some(a.binding); }
        // Actual SAME connection's processIdentifier and original NOTE_EXIT
        // registration/noninheritance complete before B enters.
        self.book.maintenance_watch()?;
        self.removal_cut(false)?;
        #[cfg(feature = "e2-native-fixture")]
        { self.fixture.watch_registered=true; }
        Ok(a)
    }
    pub fn begin(&mut self)->Result<Drain,Failure>{
        let a=self.challenge_and_watch()?;
        let b=self.call(4,Frame{kind:Kind::ChallengeB,code:Code::Accepted,binding:a.binding,tail:None},Kind::ChallengeBReply)?;
        if b.code!=Code::Accepted || b.binding!=a.binding{return Err(self.failed(Failure::Binding));}
        self.drain_entered=true; // possible entry remains latched even on reply loss
        let result=self.call(5,Frame{kind:Kind::BeginDrain,code:Code::Accepted,binding:b.binding,tail:None},Kind::BeginDrainReply)?;
        if !result.binding.same_challenge(b.binding){return Err(self.failed(Failure::Binding));}
        match result.code{
            Code::Busy|Code::Refused=>{
                // A refusal plus an unexpected handle is ambiguous custody,
                // never a known no-drain result that reopens new launches.
                if !self.book.maintenance_endpoint_absent(){return Err(self.failed(Failure::Unknown));}
                self.drain_entered=false;return Ok(if result.code==Code::Busy{Drain::Busy}else{Drain::Refused});
            }
            Code::Unknown=>return Err(self.failed(Failure::Unknown)),
            Code::Accepted=>{},
        }
        if !result.binding.started_valid(){return Err(self.failed(Failure::Binding));}
        self.binding=Some(result.binding);
        let now=self.now()?;
        if !self.signal.narrow_maintenance(result.binding.cutoff,now){return Err(Failure::Stopped);}
        self.book.maintenance_receive()?;
        let receipt=Frame{kind:Kind::TailReceived,code:Code::Accepted,binding:result.binding,tail:None}
            .encode().ok_or_else(||self.failed(Failure::Binding))?;
        self.receipt_sent=true; // exactly one possibly-entered send, never retry
        self.removal_cut(false)?;
        self.book.maintenance_exchange(7,&receipt)?;
        self.removal_cut(false)?;
        Ok(Drain::Started)
    }
    /// Fixed missing-B negative on the same A/watch original. No phase3, B,
    /// forged refusal or replacement connection exists on this path.
    #[cfg(feature = "e2-native-fixture")]
    pub(crate) fn fixture_begin_missing_b(&mut self)->Result<(),Failure> {
        let a=self.challenge_and_watch()?;
        let input=Frame { kind:Kind::BeginDrain,code:Code::Accepted,binding:a.binding,tail:None }
            .encode().ok_or_else(||self.failed(Failure::Binding))?;
        self.drain_entered=true; // Possible entry only, never proof of selector/reply.
        let raw=self.book.fixture_missing_b(&input)?;
        let now=self.now()?;
        let reply=Frame::decode(&raw).filter(|reply|reply.kind==Kind::BeginDrainReply)
            .ok_or_else(||self.failed(Failure::Binding))?;
        if reply.code!=Code::Refused || reply.binding!=a.binding || reply.binding.acceptance>now
            || !self.book.maintenance_endpoint_absent() {
            return Err(self.failed(Failure::Binding));
        }
        // A genuine decoded Refused with the FULL unchanged A/no-cut binding
        // and actual absent endpoint proves the native negative, not the marker.
        self.drain_entered=false; self.fixture.missing_b_refused=true;
        Ok(())
    }
    #[cfg(feature = "e2-native-fixture")]
    pub(crate) fn fixture_no_tail_exit(&mut self)->Result<bool,Failure> {
        if !self.fixture.missing_b_refused || self.retired || self.receipt_sent
            || self.tail.is_some() || self.admission_issued || self.eof {
            return Err(self.failed(Failure::Sequence));
        }
        self.exited|=self.book.fixture_no_tail_exit()?;
        self.now()?;
        Ok(self.exited)
    }
    #[cfg(feature = "e2-native-fixture")]
    pub(crate) fn fixture_observation(&self)->FixtureClientObservation {
        let tail=if self.tail.is_some() && self.used==wire::BYTES {
            let mut raw=[0;wire::BYTES]; raw.copy_from_slice(&self.buffer[..wire::BYTES]); Some(raw)
        } else { None };
        FixtureClientObservation {
            binding:self.binding.or(self.fixture.challenge), tail,
            watch_registered:self.fixture.watch_registered, refused:self.fixture.missing_b_refused,
            admission_issued:self.admission_issued, eof:self.eof, exited:self.exited,
            custody:self.book.fixture_custody(),
        }
    }
    #[cfg(feature = "e2-native-fixture")]
    pub(crate) fn fixture_identity_custody(&self)->crate::android_registration::FixtureIdentityCustody {
        self.book.fixture_identity_custody()
    }
    #[cfg(feature = "e2-native-fixture")]
    pub(crate) fn fixture_identity_facts(&self)->crate::android_registration::FixtureIdentityFacts {
        self.book.fixture_identity_facts()
    }
    pub fn step(&mut self)->Result<Progress,Failure>{
        if !self.receipt_sent || self.retired || self.used>wire::BYTES{return Err(self.failed(Failure::Sequence));}
        self.removal_cut(true)?;
        let (bytes,eof,exited)=self.book.maintenance_step(&mut self.buffer[self.used..])?;
        self.used+=bytes;self.eof|=eof;self.exited|=exited;
        let now=self.now()?;
        // Preserve actual byte/EOF/exit observations even when returned late.
        self.removal_cut(true)?;
        if self.used>wire::BYTES{return Err(self.failed(Failure::Binding));}
        if self.tail.is_none(){
            if self.used<wire::BYTES{
                if eof || exited{return Err(self.failed(Failure::Binding));}return Ok(Progress::Pending);
            }
            let frame=Frame::decode(&self.buffer[..wire::BYTES]).filter(|frame|
                frame.kind==Kind::Tail && Some(frame.binding)==self.binding)
                .ok_or_else(||self.failed(Failure::Binding))?;
            let tail=frame.tail.ok_or_else(||self.failed(Failure::Binding))?;
            if now<tail.write_entered || now>=tail.cutoff{return Err(self.failed(Failure::Binding));}
            self.tail=Some(tail);
            // A genuine quiesced-but-failed tail is valid DATA, NOT permission.
            // Import F first; the application imports this same original sample
            // into its Control before it asks Preparation to queue the main action.
            if !self.signal.maintenance_tail(tail.first,tail.cutoff,now){return Err(Failure::Stopped);}
            if eof || exited{return Err(self.failed(Failure::Binding));}
            return Ok(Progress::TailReceived);
        }
        if self.eof && self.exited{Ok(Progress::Exited)}else{Ok(Progress::Pending)}
    }
    pub fn take_tail_admission(&mut self,clock:&ClockBridge)->Option<TailAdmission>{
        if self.admission_issued || self.retired || self.eof || self.exited{return None;}
        let tail=self.tail?;let binding=self.binding?;let now=self.now().ok()?;
        if !self.signal.maintenance_tail(tail.first,tail.cutoff,now){return None;}
        let cutoff=match clock.earlier_instant_data(tail.cutoff){Some(at) if at>Instant::now()=>at,
            _=>{self.signal.clock_unknown();return None;}};
        let capture=self.book.tail_capture()?;
        self.admission_issued=true;Some(TailAdmission{binding,cutoff,capture})
    }
    pub fn failure(&self)->Option<FrozenFailure>{(!self.retired).then(||self.signal.snapshot())}
    pub fn started_or_uncertain(&self)->bool{self.drain_entered}
    pub fn genuine_tail_received(&self)->bool{self.tail.is_some()}
    pub fn final_observed(&self)->bool{self.admission_issued && self.eof && self.exited && self.tail.is_some()}
    pub fn release(&mut self)->bool{
        if self.retired{return true;}
        if self.removal_cut(true).is_err(){return false;}
        if !self.book.release(){return false;}
        if self.removal_cut(true).is_err(){return false;}
        self.retired=true;
        // Actual book, handles, request backing AND owning tail capture have
        // all settled before the last local Signal handle is consumed.
        unsafe{ManuallyDrop::drop(&mut self.signal);}true
    }
    pub fn settled(&self)->bool{self.retired && self.book.settled()}
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn genuine_resident_failure_never_issues_main_permission_and_r_is_not_f(){
        let signal=Signal::reserved();
        let origin=uptime().unwrap();
        signal.arm(crate::android_registration::Bounds{origin,work:origin+wire::WORK_NS,hard:origin+wire::HARD_NS}).unwrap();
        let cut=origin+1;
        assert!(signal.narrow_maintenance(cut+wire::CLEANUP_NS,cut));
        assert_eq!(signal.first(),None);
        assert!(!signal.maintenance_tail(origin+1,cut+wire::CLEANUP_NS,origin+2));
        assert_eq!(signal.first(),Some(origin+1));
        assert!(!signal.maintenance_tail(0,cut+wire::CLEANUP_NS,origin+3));
        let narrowed=Signal::reserved();
        narrowed.arm(crate::android_registration::Bounds{origin,work:origin+wire::WORK_NS,hard:origin+wire::HARD_NS}).unwrap();
        assert!(narrowed.narrow_maintenance(origin+10,origin+1));
        assert!(!narrowed.narrow_maintenance(origin+20,origin+10));
        assert_eq!(narrowed.cleanup(),Some(origin+10));
        assert_eq!(narrowed.first(),Some(origin+10));
    }
}
