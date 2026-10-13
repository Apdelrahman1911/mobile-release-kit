//! Closed authenticated read-only Android query transport. The callbacks own
//! bounded DATA only. The same service role, original clock and actual worker
//! join remain compulsory; no entry result is a lease or Start capability.
use std::{
    ffi::{c_int,c_void},mem::ManuallyDrop,ptr::NonNull,
    sync::{Arc,Mutex,OnceLock,TryLockError,atomic::{AtomicBool,AtomicU64,Ordering}},
    time::Instant,
};
pub use crate::android_catalog_query_wire::{
    Bounds,Role,Kind,Request,Reply,Phase,Payload,EntryCode,Presence,ScanRow,
    REQUEST_BYTES,REPLY_BYTES,PAYLOAD_BYTES,ENTRY_LIMIT,MAX_RAW,CLEANUP_NS,
};
use crate::{android_registration::{Failure,NativeFacts},
    vault_helper_wire::{uptime,ClockBridge}};
use crate::android_service_prepare as prepare;
use crate::android_service_client_data::{self as client_data,ClientData,DataOwner};

const UNKNOWN:u64=1_u64<<61;
const CLOCK_UNKNOWN:u64=1_u64<<62;
const FROZEN:u64=1_u64<<63;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct FrozenFailure {pub bounds:Option<Bounds>,pub first:Option<u64>,pub cleanup:Option<u64>,pub unknown:bool}
/// The sole role-bound first-F mailbox. No filesystem/owner/Document lock is
/// taken here. The app retains its own Arc through finality; a retired native
/// client must not be re-entered even to retrieve this DATA.
pub struct Signal {bounds:OnceLock<Bounds>,state:AtomicU64}
impl Signal {
    pub fn reserved()->Self {Self{bounds:OnceLock::new(),state:AtomicU64::new(0)}}
    fn change(&self,first:Option<u64>,flags:u64){
        let mut previous=self.state.load(Ordering::SeqCst);
        loop {
            if previous&FROZEN!=0{return;}
            let held=previous&MAX_RAW;
            let earliest=first.map_or(held,|value|if held==0{value}else{held.min(value)});
            let next=(previous&!MAX_RAW)|earliest|flags;
            match self.state.compare_exchange_weak(previous,next,Ordering::SeqCst,Ordering::SeqCst){
                Ok(_)=>return,Err(actual)=>previous=actual,
            }
        }
    }
    pub fn clock_unknown(&self){self.change(None,UNKNOWN|CLOCK_UNKNOWN);}
    pub fn bounds(&self)->Option<Bounds>{self.bounds.get().copied()}
    pub fn arm_at(&self,bounds:Bounds,now:u64)->Result<(),Failure>{
        if !bounds.valid() || now<bounds.origin || now>=bounds.work
            || self.bounds.set(bounds).is_err() || self.state.load(Ordering::SeqCst)&FROZEN!=0{
            self.clock_unknown();return Err(Failure::Unknown);
        }
        if self.first().is_some_and(|first|!bounds.accepts_event(first,now,now)){
            self.clock_unknown();return Err(Failure::Unknown);
        }Ok(())
    }
    pub fn arm(&self,bounds:Bounds)->Result<(),Failure>{
        self.arm_at(bounds,uptime().ok_or_else(||{self.clock_unknown();Failure::Unknown})?)
    }
    /// Trusted actual same-clock observation, not deserialized remote input.
    pub fn failure_at(&self,at:u64,unknown:bool){
        if at==0 || at>MAX_RAW || self.bounds().is_some_and(|bounds|at<bounds.origin){
            self.clock_unknown();return;
        }
        self.change(Some(at),if unknown{UNKNOWN}else{0});
    }
    pub fn failure_now(&self,unknown:bool){self.failure_at(uptime().unwrap_or(0),unknown);}
    pub fn local_failure(&self,clock:&ClockBridge,event:Instant,unknown:bool){
        self.failure_at(clock.earlier_endpoint(event).unwrap_or(0),unknown);
    }
    pub fn first(&self)->Option<u64>{let at=self.state.load(Ordering::SeqCst)&MAX_RAW;(at!=0).then_some(at)}
    fn word(&self,state:u64)->FrozenFailure{
        let bounds=self.bounds();let at=state&MAX_RAW;let first=(at!=0).then_some(at);
        FrozenFailure{bounds,first,cleanup:if state&CLOCK_UNKNOWN!=0{None}else{bounds.and_then(|b|b.cleanup(first))},
            unknown:state&UNKNOWN!=0}
    }
    pub fn snapshot(&self)->FrozenFailure{self.word(self.state.load(Ordering::SeqCst))}
    pub fn admitted_at(&self,cleanup:bool,now:u64)->bool{
        let Some(bounds)=self.bounds()else{return false;};
        if now<bounds.origin || now>MAX_RAW{self.clock_unknown();return false;}
        let state=self.state.load(Ordering::SeqCst);
        if state&(CLOCK_UNKNOWN|FROZEN)!=0{return false;}
        if !cleanup && now>=bounds.work{self.failure_at(bounds.work,false);}
        let frozen=self.snapshot();
        if cleanup{frozen.cleanup.is_some_and(|end|now<end)}
        else{!frozen.unknown && frozen.first.is_none() && now<bounds.work}
    }
    pub fn admitted(&self,cleanup:bool)->bool{
        match uptime(){Some(now)=>self.admitted_at(cleanup,now),None=>{self.clock_unknown();false}}
    }
    /// Caller supplies its own serial last observation, not another thread's
    /// arrival order. Late reports of EARLIER F may shorten, never renew, time.
    pub fn accept_remote(&self,first:Option<u64>,cleanup:Option<u64>,unknown:bool,now:u64,last:u64)->bool{
        let valid=self.bounds().is_some_and(|bounds|now>=last && now>=bounds.origin && now<=MAX_RAW
            && first.is_none_or(|at|bounds.accepts_event(at,now,last))
            && (cleanup==bounds.cleanup(first) || unknown && cleanup.is_none()));
        if !valid{self.clock_unknown();return false;}
        if let Some(first)=first{self.failure_at(first,unknown);}
        else if unknown{self.failure_at(now,true);}
        true
    }
    fn freeze(&self)->FrozenFailure{self.word(self.state.fetch_or(FROZEN,Ordering::SeqCst)|FROZEN)}
}

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Candidate {
    pub payload:Payload,pub instance:[u8;16],pub code:EntryCode,pub presence:Presence,pub bytes:Vec<u8>,
}
impl Candidate {
    pub fn empty()->Self{Self{payload:Payload::None,instance:[0;16],code:EntryCode::Observed,presence:Presence::default(),bytes:Vec::new()}}
    fn fits(&self,request:Request)->bool{
        if self.bytes.len()>PAYLOAD_BYTES || self.bytes.capacity()>PAYLOAD_BYTES || !self.presence.valid(){return false;}
        match request.kind{
            Kind::Scan=>self.payload==Payload::Scan && self.instance==[0;16]
                && self.code==EntryCode::Observed && self.presence==Presence::default()
                && crate::android_catalog_query_wire::decode_scan(&self.bytes).is_some(),
            Kind::ReadIntent=>self.payload==Payload::Intent && self.instance==request.instance
                && if self.code==EntryCode::Observed{!self.bytes.is_empty() && self.presence.known==7}else{self.bytes.is_empty()},
            Kind::Finish=>*self==Self::empty(),
            _=>false,
        }
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct Binding{account:u32,nonce:[u8;16],bounds:Bounds}
struct Flow {
    queued:Option<Request>,pending:Option<u32>,processed:u32,enqueued:u32,
    candidate:Candidate,phase:Phase,visited:[[u8;16];ENTRY_LIMIT],visits:usize,last:u64,
}
/// One slot, one immutable query identity and <=32 lifetime row keys.
pub struct Ingress {
    identity:Arc<()>,binding:OnceLock<Binding>,flow:Mutex<Flow>,
    signal:Arc<Signal>,closed:AtomicBool,terminal:AtomicBool,
}
pub struct Packet{identity:Arc<()>,request:Request,account:u32}
impl Packet {
    pub fn request(&self)->Request{self.request}
    pub fn account(&self)->u32{self.account}
}
impl Ingress {
    #[cfg(feature="android-registration-helper")]
    pub(crate) fn service_high_water()->Option<usize>{
        #[repr(C)] struct ArcCell<T>{counts:[usize;2],data:T}
        std::mem::size_of::<ArcCell<Self>>().checked_add(std::mem::size_of::<ArcCell<Signal>>())?
            .checked_add(std::mem::size_of::<ArcCell<()>>())?
            .checked_add(2*PAYLOAD_BYTES)?.checked_add(REPLY_BYTES)?.checked_add(std::mem::size_of::<Reply>())
    }
    pub fn new()->Self{
        Self{identity:Arc::new(()),binding:OnceLock::new(),signal:Arc::new(Signal::reserved()),
            flow:Mutex::new(Flow{queued:None,pending:None,processed:0,enqueued:0,candidate:Candidate::empty(),
                phase:Phase::Working,visited:[[0;16];ENTRY_LIMIT],visits:0,last:0}),
            closed:AtomicBool::new(false),terminal:AtomicBool::new(false)}
    }
    pub fn signal(&self)->&Arc<Signal>{&self.signal}
    pub fn bound_account(&self)->Option<u32>{self.binding.get().map(|value|value.account)}
    /// The service's immutable prepare admission; never first Scan/Read/Status.
    pub(crate) fn prepare_binding(&self,account:u32,nonce:[u8;16],bounds:Bounds,now:u64)->bool{
        if account==0 || account==u32::MAX || !prepare::nonce_valid(&nonce)
            || self.closed.load(Ordering::SeqCst) || self.binding.get().is_some()
            || self.binding.set(Binding{account,nonce,bounds}).is_err(){
            self.signal.failure_at(now,true);return false;
        }
        self.signal.arm_at(bounds,now).is_ok()
    }
    pub fn take(&self)->Result<Option<Packet>,Failure>{
        let mut flow=self.flow.try_lock().map_err(|error|match error{
            TryLockError::WouldBlock=>Failure::Busy,
            TryLockError::Poisoned(_)=>{self.signal.failure_now(true);Failure::Unknown},
        })?;
        let Some(request)=flow.queued.take()else{return Ok(None);};
        let binding=*self.binding.get().ok_or(Failure::Unknown)?;
        if flow.pending!=Some(request.sequence){self.signal.failure_now(true);return Err(Failure::Unknown);}
        Ok(Some(Packet{identity:self.identity.clone(),request,account:binding.account}))
    }
    /// Candidate DATA ACK only; still requires Finish, all original readers/SH
    /// settlement, and the service coordinator's actual matching worker join.
    pub fn acknowledge(&self,packet:Packet,candidate:Candidate)->Result<(),Failure>{
        if !Arc::ptr_eq(&self.identity,&packet.identity) || !candidate.fits(packet.request){
            self.signal.failure_now(true);return Err(Failure::Unknown);
        }
        let request=packet.request;drop(packet);
        let mut flow=self.flow.lock().map_err(|_|{self.signal.failure_now(true);Failure::Unknown})?;
        if flow.pending!=Some(request.sequence) || flow.queued.is_some()
            || flow.processed.checked_add(1)!=Some(request.sequence){
            self.signal.failure_now(true);return Err(Failure::Unknown);
        }
        flow.candidate=candidate;flow.processed=request.sequence;flow.pending=None;
        flow.phase=if request.kind==Kind::Finish{Phase::InputClosed}else{Phase::Candidate};
        Ok(())
    }
    pub fn seal(&self)->bool{
        self.closed.store(true,Ordering::SeqCst);
        match self.flow.lock(){
            Ok(mut flow) if flow.pending.is_none() && flow.queued.is_none()=>{
                flow.phase=Phase::InputClosed;flow.candidate=Candidate::empty();true
            }
            _=>{self.signal.failure_now(true);false},
        }
    }
    pub fn retire_failed_input(&self,packet:Option<Packet>)->bool{
        self.closed.store(true,Ordering::SeqCst);
        let Ok(mut flow)=self.flow.lock()else{self.signal.failure_now(true);return false;};
        if let Some(packet)=packet{
            if !Arc::ptr_eq(&self.identity,&packet.identity) || flow.pending!=Some(packet.request.sequence)
                || flow.queued.is_some(){self.signal.failure_now(true);return false;}
            drop(packet);flow.pending=None;
        }else if flow.queued.is_some(){flow.queued=None;flow.pending=None;}
        else if flow.pending.is_some(){self.signal.failure_now(true);return false;}
        flow.candidate=Candidate::empty();flow.phase=Phase::InputClosed;true
    }
    pub fn stop_new_input(&self){self.closed.store(true,Ordering::SeqCst);}
    pub fn input_settled(&self)->bool{
        self.closed.load(Ordering::SeqCst) && self.flow.try_lock()
            .is_ok_and(|flow|flow.pending.is_none() && flow.queued.is_none())
    }
    pub fn publish_joined(&self,success:bool,known:bool)->bool{
        if !self.input_settled() || self.terminal.load(Ordering::SeqCst){self.signal.failure_now(true);return false;}
        let Ok(mut flow)=self.flow.lock()else{self.signal.failure_now(true);return false;};
        if flow.pending.is_some() || flow.queued.is_some() || self.terminal.load(Ordering::SeqCst){
            self.signal.failure_now(true);return false;
        }
        let frozen=self.signal.freeze();
        flow.phase=if success && known && !frozen.unknown && frozen.first.is_none(){Phase::Complete}
            else if known && !frozen.unknown{Phase::Refused}else{Phase::Unknown};
        flow.candidate=Candidate::empty();
        self.terminal.store(true,Ordering::SeqCst);true
    }
    fn snapshot(&self)->Option<Reply>{
        let binding=*self.binding.get()?;
        let frozen=self.signal.snapshot();
        let flow=self.flow.try_lock().ok()?;
        let c=&flow.candidate;
        let reply=Reply{bounds:binding.bounds,phase:if frozen.unknown && !self.terminal.load(Ordering::SeqCst){Phase::Unknown}else{flow.phase},
            account:binding.account,nonce:binding.nonce,processed:flow.processed,enqueued:flow.enqueued,
            payload:c.payload,code:c.code,instance:c.instance,presence:c.presence,bytes:c.bytes.clone(),
            first:frozen.first,cleanup:frozen.cleanup,unknown:frozen.unknown,joined:self.terminal.load(Ordering::SeqCst)};
        reply.valid().then_some(reply)
    }
    pub(crate) fn exchange(&self,account:u32,raw:&[u8],now:u64)->Option<[u8;REPLY_BYTES]>{
        let Some(request)=Request::decode(raw)else{self.signal.failure_at(now,false);return None;};
        if account==0 || account==u32::MAX{return None;}
        let binding=Binding{account,nonce:request.nonce,bounds:request.bounds};
        // Payload sequence never creates worker/Signal custody. Prepared
        // account/nonce/role/bounds are compared even before first Scan/Read.
        if self.binding.get()!=Some(&binding){return None;}
        if self.terminal.load(Ordering::SeqCst){return self.snapshot()?.encode();}
        // The earliest remote failure is latched BEFORE the contended DATA queue.
        if request.kind==Kind::Stop{
            if !request.bounds.accepts_event(request.first,now,now){self.signal.clock_unknown();}
            else{self.signal.failure_at(request.first,false);}
            self.closed.store(true,Ordering::SeqCst);
        }
        let Ok(mut flow)=self.flow.try_lock()else{self.signal.failure_at(now,true);return None;};
        if now<flow.last || now<request.bounds.origin || now>MAX_RAW{
            self.signal.clock_unknown();drop(flow);return self.snapshot()?.encode();
        }
        flow.last=now;
        if !request.kind.work(){drop(flow);return self.snapshot()?.encode();}
        if self.closed.load(Ordering::SeqCst) || !self.signal.admitted_at(false,now)
            || flow.queued.is_some() || flow.pending.is_some()
            || flow.enqueued.checked_add(1)!=Some(request.sequence){
            self.signal.failure_at(now,false);drop(flow);return self.snapshot()?.encode();
        }
        if request.kind==Kind::ReadIntent{
            if flow.visits==ENTRY_LIMIT || flow.visited[..flow.visits].contains(&request.instance){
                self.signal.failure_at(now,false);drop(flow);return self.snapshot()?.encode();
            }
            let slot=flow.visits;flow.visited[slot]=request.instance;flow.visits+=1;
        }
        if request.kind==Kind::Finish{self.closed.store(true,Ordering::SeqCst);}
        flow.queued=Some(request);flow.pending=Some(request.sequence);flow.enqueued=request.sequence;
        flow.candidate=Candidate::empty();flow.phase=Phase::Working;
        drop(flow);self.snapshot()?.encode()
    }
}

/// Separate original native context, same fixed authenticated public transport.
/// No registration context/Signal reuse and no new per-row connection.
pub struct ClientBook {
    pointer:Option<NonNull<c_void>>,signal:ManuallyDrop<Arc<Signal>>,facts:NativeFacts,
    started:bool,retired:bool,poisoned:bool,in_call:bool,bytes:usize,account:u32,last:u64,
    prepare:Option<prepare::ClientAttempt>,data:Option<DataOwner>,
}
unsafe impl Send for ClientBook {}
unsafe extern "C"{
    fn mrk_android_query_client_new(context:*const c_void,
        notify:unsafe extern "C" fn(*const c_void,u64,u32),
        admit:unsafe extern "C" fn(*const c_void,u32)->u32,data:*const client_data::Api)->*mut c_void;
}
unsafe extern "C" fn notify(context:*const c_void,first:u64,unknown:u32){
    if let Some(signal)=unsafe{context.cast::<Signal>().as_ref()}{signal.failure_at(first,unknown!=0);}
}
unsafe extern "C" fn admit(context:*const c_void,cleanup:u32)->u32{
    if context.is_null() || cleanup>1{return 0;}
    u32::from(unsafe{&*context.cast::<Signal>()}.admitted(cleanup==1))
}
impl ClientBook {
    pub fn new(signal:Arc<Signal>)->Self{
        Self{pointer:None,signal:ManuallyDrop::new(signal),facts:NativeFacts{version:1,..NativeFacts::default()},
            started:false,retired:false,poisoned:false,in_call:false,bytes:0,account:0,last:0,prepare:None,data:None}
    }
    fn ptr(&self)->*mut c_void{self.pointer.map_or(std::ptr::null_mut(),NonNull::as_ptr)}
    fn refresh(&mut self)->bool{
        let mut facts=NativeFacts::default();
        if self.pointer.is_none() || unsafe{crate::android_registration::mrk_android_client_facts(self.ptr(),&mut facts)}!=1
            || !facts.valid() || facts.calls<self.facts.calls || facts.returns<self.facts.returns
            || facts.callbacks<self.facts.callbacks || facts.callback_returns<self.facts.callback_returns{
            self.poisoned=true;self.signal.failure_now(true);return false;
        }
        self.facts=facts;if facts.unknown!=0{self.signal.failure_now(true);}true
    }
    pub fn begin(&mut self)->Result<(),Failure>{
        if self.started || self.retired || self.pointer.is_some(){return Err(Failure::Unknown);}
        self.started=true;
        if Self::allocation_requirements().admitted_upper_bound().is_err(){
            self.signal.failure_now(false);return Err(Failure::Unavailable);
        }
        if !self.signal.admitted(false){return Err(Failure::Stopped);}
        self.account=crate::real_user().map_err(|_|{self.signal.failure_now(false);Failure::Unavailable})?;
        if !self.signal.admitted(false){return Err(Failure::Stopped);}
        if !crate::android_registration::ClientBook::identity_available(){
            self.signal.failure_now(false);return Err(Failure::Unavailable);
        }
        self.in_call=true;let bytes=unsafe{crate::android_registration::mrk_android_client_bytes()};self.in_call=false;
        if !(1..=16_384).contains(&bytes){self.poisoned=true;self.signal.failure_now(true);return Err(Failure::Bounds);}
        self.in_call=true;
        self.data=Some(DataOwner::new(ClientData::query(Arc::clone(&self.signal))));
        let context=self.data.as_ref().map_or(std::ptr::null(),DataOwner::pointer);
        self.pointer=NonNull::new(unsafe{mrk_android_query_client_new(context,client_data::notify,client_data::admit,&client_data::API)});
        self.in_call=false;
        if self.pointer.is_none(){self.signal.failure_now(false);return Err(Failure::Native);}
        self.bytes=bytes;self.in_call=true;
        let returned=unsafe{crate::android_registration::mrk_android_client_begin(self.ptr())};self.in_call=false;
        if !self.refresh() || returned!=1 || !self.facts.quiescent(){
            self.signal.failure_now(self.poisoned);return Err(Failure::Native);
        }
        if !self.signal.admitted(false){return Err(Failure::Stopped);}Ok(())
    }
    pub fn allocation_requirements()->crate::android_service_budget::ClientRequirements{
        crate::android_service_budget::client_requirements()
    }
    pub fn prepare_custody(&self)->prepare::PeerCustody{
        self.prepare.as_ref().map_or(prepare::PeerCustody::PrepareNotEntered,prepare::ClientAttempt::state)
    }
    pub fn prepared_nonce(&self)->Option<[u8;16]>{
        self.prepare.as_ref().and_then(prepare::ClientAttempt::nonce)
    }
    pub fn peer_nonentry_known(&self)->bool{
        self.prepare.as_ref().is_none_or(prepare::ClientAttempt::peer_nonentry_known)
    }
    fn request_available(&self,cleanup:bool)->bool{
        loop{
            let Some(data)=self.data.as_ref()else{return false;};
            if data.idle_known(){return self.signal.admitted(cleanup);}
            if data.uncertain() || !self.signal.admitted(cleanup){return false;}
            std::thread::park_timeout(std::time::Duration::from_millis(2));
        }
    }
    pub fn prepare(&mut self)->Result<prepare::Reply,Failure>{
        if !self.started || self.retired || self.poisoned || self.in_call || !self.facts.quiescent()
            || !self.signal.admitted(false){return Err(Failure::Stopped);}
        if !self.request_available(false){return Err(Failure::Stopped);}
        let bounds=self.signal.bounds().ok_or(Failure::Unknown)?;
        let role=match bounds.role{Role::Catalog=>prepare::Role::Catalog,Role::Start=>prepare::Role::Start};
        let request=prepare::Request{bounds:prepare::Bounds{role,origin:bounds.origin,work:bounds.work,hard:bounds.hard}};
        let input=request.encode().ok_or(Failure::Bounds)?;
        if self.prepare.is_none(){self.prepare=prepare::ClientAttempt::new(request);}
        let attempt=self.prepare.as_mut().ok_or(Failure::Unknown)?;
        if attempt.request()!=request || !attempt.enter_native(){return Err(Failure::Binding);}
        let mut raw=[0;prepare::BYTES];self.in_call=true;
        let returned=unsafe{crate::android_registration::mrk_android_client_prepare(
            self.ptr(),input.as_ptr(),raw.as_mut_ptr())};
        self.in_call=false;
        let reply=if self.refresh() && returned==1 && self.facts.quiescent() && self.facts.peer==0{
            prepare::Reply::decode(&raw)
        }else{None};
        let observed=uptime();
        let valid=match(reply,observed){
            (Some(value),Some(now)) if value.bounds==request.bounds
                && value.bounds.accepts_observation(value.first,now,self.last)=>{
                    let accepted=self.signal.accept_remote(value.first,value.bounds.cleanup(value.first),value.unknown,now,self.last);
                    self.last=now;accepted
                },
            _=>false,
        };
        if !valid{
            if let Some(attempt)=self.prepare.as_mut(){attempt.lost_reply();}
            self.signal.failure_now(true);return Err(Failure::Unknown);
        }
        let reply=reply.ok_or(Failure::Unknown)?;
        if !self.prepare.as_mut().is_some_and(|attempt|attempt.accept_authenticated(reply)){
            self.signal.failure_now(true);return Err(Failure::Unknown);
        }
        if !self.signal.admitted(false){return Err(Failure::Stopped);}
        Ok(reply)
    }
    pub fn exchange(&mut self,request:Request,cleanup:bool)->Result<Reply,Failure>{
        let input=request.encode().ok_or(Failure::Bounds)?;
        if self.signal.bounds()!=Some(request.bounds) || cleanup && request.kind.work(){return Err(Failure::Bounds);}
        if self.prepared_nonce()!=Some(request.nonce) || self.peer_nonentry_known()
            || request.kind.work() && self.prepare_custody()!=prepare::PeerCustody::Ready{
            return Err(Failure::Binding);
        }
        if !self.started || self.retired || self.poisoned || self.in_call || !self.facts.quiescent()
            || !self.signal.admitted(cleanup){return Err(Failure::Stopped);}
        if !self.request_available(cleanup){return Err(Failure::Stopped);}
        let mut raw=[0;REPLY_BYTES];self.in_call=true;
        let returned=unsafe{crate::android_registration::mrk_android_client_exchange(
            self.ptr(),input.as_ptr(),input.len(),u32::from(cleanup),raw.as_mut_ptr())};
        self.in_call=false;
        if !self.refresh() || returned!=1 || !self.facts.quiescent() || self.facts.peer!=0{
            self.signal.failure_now(true);return Err(Failure::Unknown);
        }
        let reply=Reply::decode(&raw).ok_or_else(||{self.signal.failure_now(true);Failure::Unknown})?;
        if reply.bounds!=request.bounds || reply.account!=self.account || reply.nonce!=request.nonce{
            self.signal.failure_now(true);return Err(Failure::Binding);
        }
        let now=uptime().ok_or_else(||{self.signal.clock_unknown();Failure::Unknown})?;
        if !self.signal.accept_remote(reply.first,reply.cleanup,reply.unknown,now,self.last){return Err(Failure::Unknown);}
        self.last=now;
        if !self.signal.admitted(cleanup){return Err(Failure::Stopped);}Ok(reply)
    }
    pub fn release(&mut self)->bool{
        if self.retired{return self.settled();}
        if self.in_call || self.poisoned{self.signal.failure_now(true);return false;}
        if self.facts.entered!=0 && !self.signal.admitted(true){return false;}
        if self.pointer.is_none(){
            if self.data.as_mut().is_some_and(|data|!data.settle()){return false;}
            self.data=None;self.retired=true;unsafe{ManuallyDrop::drop(&mut self.signal);}return true;
        }
        if !self.signal.admitted(true) || !self.refresh(){return false;}
        for slot in[7,6,4,5,3,2,1,0]{
            if self.facts.slots[slot]!=2{continue;}
            if !self.signal.admitted(true){return false;}
            self.in_call=true;
            let returned=unsafe{crate::android_registration::mrk_android_client_release_one(self.ptr(),slot as u32)};
            self.in_call=false;if !self.refresh(){return false;}
            if returned!=1{self.signal.failure_now(true);}
        }
        if !self.facts.settled() || !self.request_available(true){return false;}
        self.in_call=true;let retired=unsafe{crate::android_registration::mrk_android_client_retire(self.ptr())};self.in_call=false;
        if retired!=1{self.poisoned=true;self.signal.failure_now(true);return false;}
        self.pointer=None;self.bytes=0;
        if !self.signal.admitted(true) || self.data.as_mut().is_none_or(|data|!data.settle()){return false;}
        self.data=None;self.retired=true;unsafe{ManuallyDrop::drop(&mut self.signal);}true
    }
    pub fn settled(&self)->bool{
        self.retired && self.pointer.is_none() && self.data.is_none()
            && !self.in_call && !self.poisoned && self.facts.settled()
    }
    pub fn retained_bytes(&self)->Option<usize>{
        if self.settled() || !self.started{Some(0)}else{None}
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    fn bounds(role:Role)->Bounds{let origin=10;Bounds{role,origin,work:origin+role.work_ns(),hard:origin+role.hard_ns()}}
    fn request(kind:Kind,sequence:u32)->Request{Request{bounds:bounds(Role::Catalog),kind,sequence,nonce:prepare::nonce_for_counter(1).unwrap(),
        instance:if kind==Kind::ReadIntent{[2;16]}else{[0;16]},first:0}}
    #[test]
    fn role_specific_original_bounds_and_prearrival_failure_never_renew(){
        for role in[Role::Catalog,Role::Start]{
            let signal=Signal::reserved();signal.failure_at(12,false);signal.arm_at(bounds(role),20).unwrap();
            assert_eq!(signal.snapshot().cleanup,Some(12+CLEANUP_NS));
            signal.failure_at(16,false);assert_eq!(signal.first(),Some(12));
            assert!(signal.accept_remote(Some(11),Some(11+CLEANUP_NS),false,30,29));
            assert_eq!(signal.first(),Some(11));
            assert!(!signal.accept_remote(Some(9),Some(9+CLEANUP_NS),false,31,30));
            assert!(signal.snapshot().unknown);assert_eq!(signal.snapshot().cleanup,None);
        }
    }
    #[test]
    fn prepared_stop_status_precede_scan_and_wrong_role_never_rearms(){
        let ingress=Ingress::new();let status=request(Kind::Status,0);
        assert!(ingress.prepare_binding(501,status.nonce,status.bounds,19));
        let observed=Reply::decode(&ingress.exchange(501,&status.encode().unwrap(),20).unwrap()).unwrap();
        assert_eq!((observed.account,observed.nonce,observed.enqueued,observed.joined),(501,status.nonce,0,false));
        let changed=Request{bounds:bounds(Role::Start),..status};
        assert!(ingress.exchange(501,&changed.encode().unwrap(),21).is_none());
        assert_eq!(ingress.signal().bounds(),Some(status.bounds));
        let stop=Request{kind:Kind::Stop,first:22,..status};
        ingress.exchange(501,&stop.encode().unwrap(),23).unwrap();
        assert_eq!(ingress.signal().first(),Some(22));
        assert!(ingress.take().unwrap().is_none());
        ingress.exchange(501,&request(Kind::Scan,1).encode().unwrap(),24).unwrap();
        assert!(ingress.take().unwrap().is_none());
    }
    #[test]
    fn query_slot_requires_same_original_ack_and_never_reuses_a_row_or_role(){
        let ingress=Ingress::new();let scan=request(Kind::Scan,1);
        assert!(ingress.prepare_binding(501,scan.nonce,scan.bounds,19));
        let raw=scan.encode().unwrap();
        assert_eq!(Reply::decode(&ingress.exchange(501,&raw,20).unwrap()).unwrap().enqueued,1);
        let packet=ingress.take().unwrap().unwrap();
        let candidate=Candidate{payload:Payload::Scan,instance:[0;16],code:EntryCode::Observed,presence:Presence::default(),
            bytes:crate::android_catalog_query_wire::encode_scan(&[ScanRow{instance:[2;16],occupants:7}]).unwrap()};
        ingress.acknowledge(packet,candidate).unwrap();
        let read=request(Kind::ReadIntent,2);let raw=read.encode().unwrap();
        ingress.exchange(501,&raw,22).unwrap();
        let packet=ingress.take().unwrap().unwrap();
        let negative=Candidate{payload:Payload::Intent,instance:[2;16],code:EntryCode::Busy,presence:Presence::default(),bytes:Vec::new()};
        ingress.acknowledge(packet,negative).unwrap();
        assert!(ingress.signal.first().is_none()); // Safe row-negative is NOT owner F.
        let repeated=request(Kind::ReadIntent,3);
        ingress.exchange(501,&repeated.encode().unwrap(),24).unwrap();
        assert_eq!(ingress.signal.first(),Some(24));
        let foreign=Ingress::new();assert!(foreign.acknowledge(ingress.take().unwrap().unwrap_or_else(||Packet{
            identity:ingress.identity.clone(),request:repeated,account:501}),Candidate::empty()).is_err());
        assert!(foreign.signal.snapshot().unknown);
    }
}
