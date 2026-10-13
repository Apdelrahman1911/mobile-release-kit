//! Resident fixed-service DATA and native control boundary. Native callbacks
//! never receive a publisher, filesystem book, descriptor, or worker handle.
use std::{cell::UnsafeCell, ffi::{c_int,c_void}, mem::ManuallyDrop, ptr::NonNull,
    sync::{Arc,Weak,Mutex,TryLockError,atomic::{AtomicBool,AtomicU8,AtomicU64,Ordering}},
    thread::JoinHandle};
use crate::{android_registration::{self as registration,Failure},
    android_catalog_query as query,android_service_prepare as prepare,android_maintenance_wire as maintenance,
    android_service_control::{self as control,CallSummary,ControlWindow,Decision,FirstPrepare,NonceCounter,PayloadReservation,WindowData},
    android_service_lease::BackingLease,vault_helper_wire::uptime};

pub const SUPERVISOR_STACK:usize=1_048_576;
pub const PAYLOAD_STACK:usize=2_097_152;
pub const COORDINATOR_STACK:usize=1_048_576;
const NATIVE_FIXED_MAX:usize=16_384;
const CAPTURES_PER_CONTEXT:usize=512;
const LANES:usize=4; // accept, response, native retirement, no-payload endpoint receipt
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ServiceRole{Registration,ReadOnlyQuery}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum NativeReturn{NotStarted,Entered,Returned,Unknown}
#[derive(Clone,Copy)]
struct JoinObservation{
    spawn:u8,spawn_entered:Option<u64>,spawn_returned:Option<u64>,
    entered:Option<u64>,returned:Option<u64>,known:bool,
}
impl JoinObservation{
    fn reserved()->Self{Self{spawn:0,spawn_entered:None,spawn_returned:None,entered:None,returned:None,known:false}}
    fn ended(&self)->bool{self.spawn==0 || self.spawn==4 || self.spawn==3 && self.known}
    fn valid_with(&self,window:WindowData)->bool{
        if !self.ended(){return false;}
        if self.spawn==0{return self.spawn_entered.is_none() && self.spawn_returned.is_none()
            && self.entered.is_none() && self.returned.is_none();}
        let Some(start)=self.spawn_entered else{return false;};
        let Some(created)=self.spawn_returned else{return false;};
        if start<window.acceptance || created<start || !window.cutoff().is_some_and(|end|created<end){return false;}
        if self.spawn==4{return self.entered.is_none() && self.returned.is_none();}
        let Some(entered)=self.entered else{return false;};
        let Some(returned)=self.returned else{return false;};
        self.spawn==3 && entered>=created && returned>=entered
            && window.cutoff().is_some_and(|end|returned<end)
    }
}
#[derive(Clone,Copy)]
struct MaintenanceChallenge{binding:maintenance::Binding,phase:u8}
struct Preparation{first:FirstPrepare,taken:bool,setup_failed:bool,maintenance:Option<MaintenanceChallenge>}
/// Original native BODY return observations, independent of the response arena.
/// An endpoint receipt can overlap the BeginDrain reply without stealing it.
struct TailProgress{begin:AtomicU8,receipt:AtomicU8,accepted:AtomicBool,closed:AtomicBool}
impl TailProgress{fn new()->Self{Self{begin:AtomicU8::new(0),receipt:AtomicU8::new(0),
    accepted:AtomicBool::new(false),closed:AtomicBool::new(false)}}}
struct Ledger{
    calls:[CallSummary;LANES],worker:JoinObservation,coordinator:JoinObservation,
    native_enter:Option<u64>,native_return:Option<u64>,payload_known:bool,reservation_released:bool,
}

/// Every possible native DATA borrower retains this same Arc. Window is NOT a
/// second independently retained Arc. The Weak backlink is to the SAME original
/// Registry allocation, never to a native object or a second admission owner.
pub struct ServiceDomain{
    slot:usize,number:u64,account:u32,nonce:[u8;16],registry:Weak<ServiceRegistry>,
    reservation:Arc<PayloadReservation>,registration:Arc<registration::Ingress>,query:Arc<query::Ingress>,
    window:ControlWindow,prepare:Mutex<Preparation>,ledger:Mutex<Ledger>,
    native:AtomicU8,reply:BackingLease,response:UnsafeCell<Box<[u8;query::REPLY_BYTES]>>,tail:TailProgress,
}
// SAFETY: response is written only under the one exclusive reply lease. Native
// NSData keeps the same domain Arc and immutable backing until all lease facts.
// All other asynchronous fields are immutable, atomic or bounded DATA locks.
unsafe impl Sync for ServiceDomain{}
impl ServiceDomain{
    fn new(slot:usize,number:u64,account:u32,now:u64,reservation:Arc<PayloadReservation>,registry:Weak<ServiceRegistry>)->Option<Self>{
        Some(Self{slot,number,account,nonce:prepare::nonce_for_counter(number)?,registry,reservation,
            registration:Arc::new(registration::Ingress::new()),query:Arc::new(query::Ingress::new()),
            window:ControlWindow::new(now)?,prepare:Mutex::new(Preparation{first:FirstPrepare::new(),taken:false,setup_failed:false,maintenance:None}),
            ledger:Mutex::new(Ledger{calls:std::array::from_fn(|_|CallSummary::new()),
                worker:JoinObservation::reserved(),coordinator:JoinObservation::reserved(),
                native_enter:None,native_return:None,payload_known:false,reservation_released:false}),
            native:AtomicU8::new(0),reply:BackingLease::reserved(),response:UnsafeCell::new(Box::new([0;query::REPLY_BYTES])),tail:TailProgress::new()})
    }
    pub fn maintenance_binding(&self)->MaintenanceBinding{
        MaintenanceBinding{slot:self.slot,number:self.number,account:self.account,nonce:self.nonce}
    }
    pub fn number(&self)->u64{self.number}
    pub fn slot(&self)->usize{self.slot}
    pub fn account(&self)->u32{self.account}
    pub fn registration(&self)->&Arc<registration::Ingress>{&self.registration}
    pub fn query(&self)->&Arc<query::Ingress>{&self.query}
    pub fn bounds(&self)->Option<prepare::Bounds>{self.window.prepared()}
    pub fn role(&self)->Option<ServiceRole>{
        self.bounds().map(|bounds|if bounds.role==prepare::Role::Registration{ServiceRole::Registration}else{ServiceRole::ReadOnlyQuery})
    }
    pub fn failure_at(&self,first:u64,unknown:bool){
        // Earliest native F reaches nonfreezing control and BOTH reserved payload
        // Signals before any potentially contended preparation/ledger lock.
        self.window.failure_at(first,unknown);self.relay_control();
    }
    pub fn failure_now(&self,unknown:bool){self.failure_at(uptime().unwrap_or(0),unknown);}
    pub fn retire_at(&self,first:u64){
        self.window.retire_at(first);self.relay_control();
    }
    /// Publish the ORIGINAL control observations, without replacing their clock
    /// with this relay's arrival time. Only atomics/OnceLock reads are entered.
    fn relay_control(&self)->WindowData{
        let window=self.window.snapshot();
        if let Some(first)=window.retirement.filter(|_|self.window.maintenance().is_none()){
            self.registration.signal().failure_at(first,false);self.query.signal().failure_at(first,false);
        }
        if let Some(first)=window.first{
            self.registration.signal().failure_at(first,window.unknown);self.query.signal().failure_at(first,window.unknown);
        }
        if window.clock_unknown{
            self.registration.signal().clock_unknown();self.query.signal().clock_unknown();
        }
        if window.retirement.is_some() || window.first.is_some() || window.unknown{
            self.registration.stop_new_input();self.query.stop_new_input();
        }
        window
    }
    pub fn watch(&self)->bool{
        let now=uptime().unwrap_or(0);self.window.watch(now);
        let window=self.relay_control(); // BEFORE any route/book/ledger lock.
        // Time alone does not turn an already timely native return/join into
        // Unknown while only documented backing/DATA exclusivity is outstanding.
        // Actual original entry/return methods independently enforce this cutoff.
        window.admits(now,true)
    }
    pub fn control_data(&self)->WindowData{self.window.snapshot()}
    pub fn route_retiring(&self)->bool{
        let data=self.window.snapshot();data.retirement.is_some() || data.first.is_some() || data.unknown
    }
    pub fn native_return(&self)->NativeReturn{
        match self.native.load(Ordering::SeqCst){0=>NativeReturn::NotStarted,1=>NativeReturn::Entered,
            2=>NativeReturn::Returned,_=>NativeReturn::Unknown}
    }
    fn native_entered(&self,now:u64)->bool{
        self.window.watch(now);
        if !self.window.snapshot().admits(now,true)
            || self.native.compare_exchange(0,1,Ordering::SeqCst,Ordering::SeqCst).is_err(){return false;}
        match self.ledger.try_lock(){Ok(mut ledger)=>{ledger.native_enter=Some(now);true},
            Err(_)=>{self.failure_at(now,true);self.native.store(3,Ordering::SeqCst);false}}
    }
    fn native_returned(&self,now:u64,known:bool){
        self.window.watch(now);
        let valid=known && self.window.snapshot().admits(now,true);
        match self.ledger.try_lock(){
            Ok(mut ledger)=>{
                ledger.native_return=Some(now);
                if ledger.native_enter.is_none_or(|at|now<at){self.failure_at(now,true);self.native.store(3,Ordering::SeqCst);return;}
            }
            Err(_)=>{self.failure_at(now,true);self.native.store(3,Ordering::SeqCst);return;}
        }
        self.native.store(if valid{2}else{3},Ordering::SeqCst);
        if !valid{self.failure_at(now,true);}
    }
    fn prepared_reply(&self,input:prepare::Request,now:u64)->Option<[u8;prepare::BYTES]>{
        // All setup/GO authorization uses RegistrySlots -> prepare -> ledger.
        // The temporary strong upgrade ends on this function's return; no native
        // call, arbitrary closure, or blocking thread creation holds this guard.
        let registry=self.registry.upgrade()?;
        let slots=registry.slots.try_lock().ok()?;
        if !registry.work_open_locked(&slots,self){return None;}
        self.window.watch(now);
        let mut state=match self.prepare.try_lock(){Ok(state)=>state,Err(_)=>{self.failure_at(now,true);return None;}};
        if state.maintenance.is_some(){self.failure_at(now,false);return None;}
        if state.first.request().is_none(){
            let open=self.window.work_open(now) && input.bounds.work_admitted(now);
            let decision=state.first.decide(input,self.number,open,&self.reservation);
            if matches!(decision,Decision::BindingRefused){self.failure_at(now,false);return None;}
            // Even immutable NoEntry carries exactly the caller's bounds. Only
            // the selected Pending context binds payload ingress before GO.
            if open && !self.window.bind(input.bounds,now){state.first.unknown();state.setup_failed=true;self.failure_at(now,true);return None;}
            if matches!(decision,Decision::FirstPending){
                let bounds=input.bounds;
                let bound=if bounds.role==prepare::Role::Registration{
                    self.registration.prepare_binding(self.account,self.nonce,
                        registration::Bounds{origin:bounds.origin,work:bounds.work,hard:bounds.hard},now)
                }else{
                    let role=if bounds.role==prepare::Role::Catalog{query::Role::Catalog}else{query::Role::Start};
                    self.query.prepare_binding(self.account,self.nonce,query::Bounds{role,origin:bounds.origin,work:bounds.work,hard:bounds.hard},now)
                };
                if !bound{state.first.unknown();state.setup_failed=true;self.failure_at(now,true);}
            }
        }else if state.first.request()!=Some(input){
            // Changed prepare is not a fresh admission or a misleading NoEntry.
            self.failure_at(now,false);return None;
        }
        let phase=state.first.phase();
        let failure=if input.bounds.role==prepare::Role::Registration{self.registration.signal().first()}else{self.query.signal().first()};
        prepare::Reply{phase,bounds:input.bounds,nonce:self.nonce,first:failure,
            unknown:phase==prepare::Phase::Unknown}.encode()
    }
    fn maintenance_response(&self,kind:u32,input:maintenance::Frame,now:u64)->Option<[u8;maintenance::BYTES]>{
        use maintenance::{Code,Frame,Kind};
        let expected=match kind{3=>Kind::ChallengeA,4=>Kind::ChallengeB,5=>Kind::BeginDrain,_=>return None};
        if input.kind!=expected || input.code!=Code::Accepted || input.tail.is_some(){return None;}
        let registry=self.registry.upgrade()?;
        if kind==5{
            let caller=registry.context(self.slot)?;
            if !std::ptr::eq(Arc::as_ptr(&caller),self){return None;}
            let (result,started)=registry.begin_bound_at(&caller,self.maintenance_binding(),now,Some(input.binding));
            let code=match result{MaintenanceAdmission::Started=>Code::Accepted,MaintenanceAdmission::Busy=>Code::Busy,
                MaintenanceAdmission::Refused=>Code::Refused,MaintenanceAdmission::Unknown=>Code::Unknown};
            return Frame{kind:Kind::BeginDrainReply,code,binding:started.unwrap_or(input.binding),tail:None}.encode();
        }
        let slots=registry.slots.try_lock().ok()?;
        if !registry.work_open_locked(&slots,self) || !self.window.work_open(now){return None;}
        let identity=registry.image_identity?;
        let mut state=self.prepare.try_lock().ok()?;
        let binding=if kind==3{
            if state.first.request().is_some() || state.maintenance.is_some() || !input.binding.request_valid()
                || !input.binding.identity().same_build(identity)
                || !self.window.bind_maintenance(input.binding.bounds(),now){return None;}
            let binding=maintenance::Binding{instance:identity.instance,nonce:self.nonce,number:self.number,
                account:self.account,slot:self.slot as u32,acceptance:self.window.snapshot().acceptance,..input.binding};
            if !binding.challenge_valid(){self.failure_at(now,true);return None;}
            state.maintenance=Some(MaintenanceChallenge{binding,phase:1});binding
        }else{
            let challenge=state.maintenance.as_mut()?;
            if challenge.phase!=1 || challenge.binding!=input.binding{return None;}
            challenge.phase=2;challenge.binding
        };
        Frame{kind:if kind==3{Kind::ChallengeAReply}else{Kind::ChallengeBReply},code:Code::Accepted,binding,tail:None}.encode()
    }
    fn tail_body(&self,kind:u32,returning:bool,now:u64,known:bool)->bool{
        let field=match kind{5=>&self.tail.begin,7=>&self.tail.receipt,_=>{self.failure_at(now,true);return false;}};
        let allowed=self.window.snapshot().admits(now,returning || kind==7);
        if !allowed || !known || field.compare_exchange(if returning{1}else{0},
            if returning{2}else{1},Ordering::SeqCst,Ordering::SeqCst).is_err(){
            field.store(3,Ordering::SeqCst);self.failure_at(now,true);return false;
        }
        true
    }
    fn tail_binding(&self)->Option<maintenance::Binding>{
        let state=self.prepare.try_lock().ok()?;
        state.maintenance.filter(|value|value.phase==3).map(|value|value.binding)
    }
    fn tail_receipt(&self,input:&[u8],now:u64)->bool{
        let accepted=maintenance::Frame::decode(input).is_some_and(|frame|
            frame.kind==maintenance::Kind::TailReceived && self.tail_binding()==Some(frame.binding))
            && self.tail.receipt.load(Ordering::SeqCst)==1
            && matches!(self.tail.begin.load(Ordering::SeqCst),1|2)
            && self.window.snapshot().admits(now,true)
            && self.tail.accepted.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_ok();
        if !accepted{self.failure_at(now,true);}accepted
    }
    fn tail_ready(&self)->i32{
        if self.window.snapshot().unknown{return -1;}
        let begin=self.tail.begin.load(Ordering::SeqCst);
        let receipt=self.tail.receipt.load(Ordering::SeqCst);
        if begin==3 || receipt==3{return -1;}
        if begin==1 || receipt==1{return 0;}
        let Ok(state)=self.prepare.try_lock()else{return 0;};
        if state.maintenance.is_none_or(|challenge|challenge.phase!=3){return 1;}
        i32::from(begin==2 && receipt==2 && self.tail.accepted.load(Ordering::SeqCst))
    }
    fn tail_closed(&self,now:u64,known:bool)->bool{
        let valid=known && self.tail_ready()==1 && self.tail_binding().is_some()
            && self.window.snapshot().admits(now,true)
            && self.tail.closed.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_ok();
        if !valid{self.failure_at(now,true);}valid
    }
    fn tail_settled(&self,state:&Preparation)->bool{
        if state.maintenance.is_none_or(|challenge|challenge.phase!=3){
            return matches!(self.tail.begin.load(Ordering::SeqCst),0|2)
                && self.tail.receipt.load(Ordering::SeqCst)==0;
        }
        self.tail.begin.load(Ordering::SeqCst)==2 && self.tail.receipt.load(Ordering::SeqCst)==2
            && self.tail.accepted.load(Ordering::SeqCst) && self.tail.closed.load(Ordering::SeqCst)
    }
    pub fn take_setup(&self)->Option<prepare::Bounds>{
        let registry=self.registry.upgrade()?;
        let slots=registry.slots.try_lock().ok()?;
        if !registry.work_open_locked(&slots,self){return None;}
        let mut state=self.prepare.try_lock().ok()?;
        if state.taken || state.setup_failed || state.first.phase()!=prepare::Phase::Pending{return None;}
        if !self.work_signals_open_at(uptime().unwrap_or(0)){
            state.setup_failed=true;state.first.unknown();self.failure_now(false);return None;
        }
        state.taken=true;state.first.request().map(|request|request.bounds)
    }
    pub fn work_admitted(&self)->bool{self.work_admitted_at(uptime().unwrap_or(0))}
    fn work_admitted_at(&self,now:u64)->bool{
        let Some(registry)=self.registry.upgrade()else{return false;};
        let Ok(slots)=registry.slots.try_lock()else{return false;};
        registry.work_open_locked(&slots,self) && self.work_signals_open_at(now)
    }
    fn work_signals_open_at(&self,now:u64)->bool{
        if !self.window.work_open(now){return false;}
        match self.role(){
            Some(ServiceRole::Registration)=>self.registration.signal().admitted_at(false,now),
            Some(ServiceRole::ReadOnlyQuery)=>self.query.signal().admitted_at(false,now),None=>false,
        }
    }
    /// Fixed CLOSED(0)->GO(1), plus Ready, under the original RegistrySlots cut.
    /// No caller-supplied function can run under the guard. Both actual original
    /// handle creations have already returned before this entry.
    pub fn publish_go_and_ready(&self,barrier:&AtomicU8)->bool{
        self.publish_go_and_ready_at(barrier,uptime().unwrap_or(0))
    }
    fn publish_go_and_ready_at(&self,barrier:&AtomicU8,now:u64)->bool{
        let Some(registry)=self.registry.upgrade()else{return false;};
        let Ok(slots)=registry.slots.try_lock()else{return false;};
        if !registry.work_open_locked(&slots,self) || !self.work_signals_open_at(now){return false;}
        let Ok(mut state)=self.prepare.try_lock()else{self.failure_at(now,true);return false;};
        let Ok(ledger)=self.ledger.try_lock()else{self.failure_at(now,true);return false;};
        if !state.taken || state.setup_failed || state.first.phase()!=prepare::Phase::Pending
            || ledger.worker.spawn!=2 || ledger.coordinator.spawn!=2{return false;}
        if barrier.compare_exchange(0,1,Ordering::SeqCst,Ordering::SeqCst).is_err(){return false;}
        let ready=state.first.ready();
        if !ready{self.failure_at(now,true);}
        ready
    }
    pub fn setup_failed(&self,unknown:bool){
        self.failure_now(unknown);
        if let Ok(mut state)=self.prepare.try_lock(){state.setup_failed=true;state.first.unknown();}
        else{self.failure_now(true);}
    }
    pub fn spawn_entered(&self,coordinator:bool)->bool{
        let now=uptime().unwrap_or(0);
        let Some(registry)=self.registry.upgrade()else{return false;};
        let Ok(slots)=registry.slots.try_lock()else{return false;};
        if !registry.work_open_locked(&slots,self) || !self.work_signals_open_at(now){return false;}
        let Ok(state)=self.prepare.try_lock()else{self.failure_at(now,true);return false;};
        if !state.taken || state.setup_failed || state.first.phase()!=prepare::Phase::Pending{return false;}
        let Ok(mut ledger)=self.ledger.try_lock()else{self.failure_at(now,true);return false;};
        let target=if coordinator{&mut ledger.coordinator}else{&mut ledger.worker};
        if target.spawn!=0{self.failure_at(now,true);return false;}
        // The creation itself occurs after this guard is released. If the cut
        // wins next, that already-entered creation must still actually settle.
        target.spawn=1;target.spawn_entered=Some(now);true
    }
    pub fn spawn_returned(&self,coordinator:bool,created:bool){
        let now=uptime().unwrap_or(0);
        let Ok(mut ledger)=self.ledger.try_lock()else{self.failure_at(now,true);return;};
        let target=if coordinator{&mut ledger.coordinator}else{&mut ledger.worker};
        if target.spawn!=1{self.failure_at(now,true);return;}
        target.spawn=if created{2}else{4};target.spawn_returned=Some(now);
        if target.spawn_entered.is_none_or(|start|now<start) || !self.window.snapshot().admits(now,true){
            self.failure_at(now,true);
        }
    }
    pub fn join_entered(&self,coordinator:bool)->bool{
        let now=uptime().unwrap_or(0);
        let Ok(mut ledger)=self.ledger.try_lock()else{self.failure_at(now,true);return false;};
        let target=if coordinator{&mut ledger.coordinator}else{&mut ledger.worker};
        self.window.watch(now);
        if target.spawn!=2 || target.entered.is_some()
            || target.spawn_returned.is_none_or(|start|now<start) || !self.window.snapshot().admits(now,true){
            self.failure_at(now,true);return false;
        }
        target.entered=Some(now);true
    }
    pub fn join_returned(&self,coordinator:bool,known:bool){
        let now=uptime().unwrap_or(0);
        let Ok(mut ledger)=self.ledger.try_lock()else{self.failure_at(now,true);return;};
        let target=if coordinator{&mut ledger.coordinator}else{&mut ledger.worker};
        let valid=target.spawn==2 && target.entered.is_some_and(|at|now>=at)
            && self.window.snapshot().admits(now,true);
        target.spawn=3;target.returned=Some(now);target.known=known&&valid;
        if !valid || !known{self.failure_at(now,true);}
    }
    /// Coordinator's actual original-worker result, not wire input. No book/FD
    /// lookup follows a moved payload close tail.
    pub fn payload_settled(&self,known:bool){
        if let Ok(mut ledger)=self.ledger.try_lock(){
            // Only once, after the actual worker result or positive NeverCreated.
            if ledger.payload_known || !known{if !known{self.failure_now(true);}return;}
            ledger.payload_known=true;
        }else{self.failure_now(true);}
    }
    pub fn release_payload_if_settled(&self)->bool{
        let Ok(state)=self.prepare.try_lock()else{return false;};
        let Ok(mut ledger)=self.ledger.try_lock()else{return false;};
        if ledger.reservation_released{return true;}
        if !ledger.payload_known || !ledger.worker.ended() || !ledger.coordinator.ended(){return false;}
        if state.first.admitted() && !self.reservation.release_settled(self.number){self.failure_now(true);return false;}
        ledger.reservation_released=true;true
    }
    pub fn no_payload_created(&self)->bool{
        let state=self.prepare.try_lock().ok();
        let Some(state)=state else{return false;};
        // Provisional, still-open contexts may later prepare. They are NOT
        // settled NeverCreated and cannot receive early reservation credit.
        let immutable_no_entry=!state.first.admitted()
            && (state.first.request().is_some() || self.route_retiring());
        let no_owner=immutable_no_entry || state.setup_failed || self.route_retiring() && !state.taken;
        no_owner && self.ledger.try_lock().is_ok_and(|ledger|
            matches!(ledger.worker.spawn,0|4) && matches!(ledger.coordinator.spawn,0|4))
    }
    fn entered_call(&self,lane:usize,cleanup:bool,now:u64)->u64{
        if lane>=LANES{self.failure_at(now,true);return 0;}
        self.window.watch(now);self.relay_control();
        let ticket=match self.ledger.try_lock(){Ok(mut ledger)=>ledger.calls[lane].enter(&self.window,now,cleanup).unwrap_or(0),
            Err(_)=>{self.failure_at(now,true);0}};
        // CallSummary may itself publish earlier CF/clock loss. Its original
        // ledger borrow is gone before propagating the same immutable sample.
        self.relay_control();ticket
    }
    fn returned_call(&self,lane:usize,ticket:u64,now:u64,known:bool)->bool{
        if lane>=LANES{self.failure_at(now,true);return false;}
        self.window.watch(now);self.relay_control();
        let returned=match self.ledger.try_lock(){Ok(mut ledger)=>ledger.calls[lane].returned(&self.window,ticket,now,known),
            Err(_)=>{self.failure_at(now,true);false}};
        self.relay_control();returned
    }
    fn reclaim_prerequisites(&self)->bool{
        if self.native_return()!=NativeReturn::Returned || !self.reply.idle_known(){return false;}
        let Ok(state)=self.prepare.try_lock()else{return false;};
        let Ok(ledger)=self.ledger.try_lock()else{return false;};
        let no_payload=!state.first.admitted() || state.setup_failed && matches!(ledger.worker.spawn,0|4);
        self.tail_settled(&state) && (no_payload || ledger.payload_known) && ledger.worker.ended() && ledger.coordinator.ended()
    }
    fn final_known(mut self)->Option<WindowData>{
        // Caller has ACTUALLY unwrapped this exact domain Arc. There is no
        // callback producer able to race the final CF/R snapshot anymore.
        let tail_known=self.prepare.get_mut().is_ok_and(|state|{
            if state.maintenance.is_none_or(|challenge|challenge.phase!=3){
                matches!(self.tail.begin.load(Ordering::SeqCst),0|2) && self.tail.receipt.load(Ordering::SeqCst)==0
            }else{self.tail.begin.load(Ordering::SeqCst)==2 && self.tail.receipt.load(Ordering::SeqCst)==2
                && self.tail.accepted.load(Ordering::SeqCst) && self.tail.closed.load(Ordering::SeqCst)}
        });
        let window=self.window.into_final();
        let ledger=match self.ledger.into_inner(){Ok(ledger)=>ledger,Err(_)=>return None};
        let preparation=match self.prepare.into_inner(){Ok(state)=>state,Err(_)=>return None};
        let no_payload=!preparation.first.admitted() || preparation.setup_failed
            && matches!(ledger.worker.spawn,0|4);
        let payload=no_payload || ledger.payload_known;
        (tail_known && payload && (!preparation.first.admitted() || ledger.reservation_released)
            && self.native.load(Ordering::SeqCst)==2 && self.reply.idle_known()
            && window.cutoff().is_some() && !window.unknown
            && ledger.native_enter.is_some_and(|at|at>=window.acceptance)
            && ledger.native_return.is_some_and(|at|ledger.native_enter.is_some_and(|start|at>=start)
                && window.cutoff().is_some_and(|end|at<end))
            && ledger.worker.valid_with(window) && ledger.coordinator.valid_with(window)
            && ledger.calls.iter().all(|summary|summary.known_with(window))).then_some(window)
    }
}

enum Cell{Empty,Live(Arc<ServiceDomain>),Reclaiming(u64),Tombstone}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Admission{Reserved,Open,Closed}
#[derive(Clone,Copy,PartialEq,Eq)]
enum LoanState{Idle,Entered,ReturnedKnown,Unknown}
struct ListenerLoan{closed:bool,state:LoanState,ticket:u64,entered:u64,returned:u64}
impl ListenerLoan{
    fn reserved()->Self{Self{closed:false,state:LoanState::Idle,ticket:0,entered:0,returned:0}}
    fn idle_known(&self)->bool{matches!(self.state,LoanState::Idle|LoanState::ReturnedKnown)}
}
/// Connection-local binding only. It is not ChallengeA/B, facade-instance,
/// tail-transfer, unregister authority, or a portable completion receipt.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct MaintenanceBinding{pub slot:usize,pub number:u64,pub account:u32,pub nonce:[u8;16]}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum MaintenanceAdmission{Started,Busy,Refused,Unknown}
struct Maintenance{binding:MaintenanceBinding,cut:u64,final_window:Option<WindowData>,protocol:Option<maintenance::Binding>}
const MAIN_LANE:usize=0;
const CONTROL_LANE:usize=1;
const JOIN_LANE:usize=2;
const TAIL_LANE:usize=3;
const LIFE_LANES:usize=4;
const OP_NEW:u32=1;
const OP_BIND:u32=2;
const OP_BEGIN:u32=3;
const OP_PUMP:u32=4;
const OP_CLOSE_LISTENER:u32=5;
const OP_CLOSE_MAIN:u32=6;
const OP_RETIRE_CONTROL:u32=7;
const OP_CONSUME_BOOK:u32=8;
const OP_CONTEXT_READY:u32=9;
const OP_CLOSE_CONTEXT:u32=10;
const OP_RECLAIM_CONTEXT:u32=11;
const OP_JOIN:u32=12;
const OP_DEALLOC:u32=13;
const OP_TAIL_PROGRESS:u32=14;
/// Lifetime prefix may predate the maintenance caller's acceptance. No new
/// deadline is manufactured for it: all actual returns, including an enclosing
/// pump already entered at the cut, must reconcile against the final SAME
/// caller window. A pending call never becomes a returned call by report bits.
struct LifetimeCalls{
    entered:u64,returned:u64,pending:Option<(u64,u32)>,last:u64,latest:Option<u64>,unknown:bool,
}
impl LifetimeCalls{
    fn new()->Self{Self{entered:0,returned:0,pending:None,last:0,latest:None,unknown:false}}
    fn enter(&mut self,operation:u32,now:u64)->Option<u64>{
        if self.unknown || self.pending.is_some() || now==0 || now>prepare::MAX_RAW || now<self.last{
            self.unknown=true;return None;
        }
        let Some(ticket)=self.entered.checked_add(1)else{self.unknown=true;return None;};
        self.entered=ticket;self.pending=Some((ticket,operation));self.last=now;Some(ticket)
    }
    fn actual_return(&mut self,ticket:u64,operation:u32,now:u64)->bool{
        if self.pending!=Some((ticket,operation)) || now==0 || now>prepare::MAX_RAW || now<self.last{
            self.unknown=true;return false;
        }
        self.pending=None;self.last=now;self.latest=Some(self.latest.map_or(now,|old|old.max(now)));
        let Some(count)=self.returned.checked_add(1)else{self.unknown=true;return false;};
        self.returned=count;true
    }
    fn known_with(&self,window:WindowData)->bool{
        !self.unknown && self.pending.is_none() && self.entered==self.returned
            && self.latest.is_none_or(|last|window.cutoff().is_some_and(|end|last<end))
    }
}
struct RegistrySlots{
    admission:Admission,cells:[Cell;control::LIVE_CONTEXTS],loan:ListenerLoan,maintenance:Option<Maintenance>,
    calls:[LifetimeCalls;LIFE_LANES],main_closed:bool,control_retired:bool,supervisor_joined:bool,book_consumed:bool,
}
pub struct ServiceRegistry{
    slots:Mutex<RegistrySlots>,counter:NonceCounter,reservation:Arc<PayloadReservation>,
    accepting:AtomicBool,unknown:AtomicBool,first:AtomicU64,clock_unknown:AtomicBool,fixed_bytes:usize,image_identity:Option<maintenance::Identity>,
}
// Nonshipping identity checkpoints borrow the SAME original native-entry ticket.
// No RegistrySlots lock is reacquired from entered C and no lock spans a call.
#[cfg(feature="e2-native-fixture")]
enum FixtureResidentWindow { Unbound,Live(Arc<ServiceDomain>),Final(WindowData) }
#[cfg(feature="e2-native-fixture")]
impl FixtureResidentWindow {
    fn capture(slots:&RegistrySlots)->Option<Self> {
        let Some(maintenance)=slots.maintenance.as_ref()else{return Some(Self::Unbound);};
        if let Some(window)=maintenance.final_window {return Some(Self::Final(window));}
        match slots.cells.get(maintenance.binding.slot) {
            Some(Cell::Live(domain)) if domain.maintenance_binding()==maintenance.binding=>
                Some(Self::Live(Arc::clone(domain))),
            _=>None,
        }
    }
    fn snapshot(&self)->Option<WindowData> {
        match self {Self::Unbound=>None,Self::Live(domain)=>Some(domain.control_data()),Self::Final(data)=>Some(*data)}
    }
}
#[cfg(feature="e2-native-fixture")]
struct FixtureResidentAdmission<'a> {
    registry:&'a ServiceRegistry,ticket:u64,operation:u32,entered:u64,last:u64,
    calls:u32,returns:u32,pending:Option<(u32,u32)>,unknown:bool,
    // This extra DATA handle can defer exclusive reclaim, never establish it.
    // An unknown return deliberately retains it; there is no destructor cleanup.
    window:ManuallyDrop<FixtureResidentWindow>,
}
#[cfg(feature="e2-native-fixture")]
impl FixtureResidentAdmission<'_> {
    fn fail(&mut self,now:u64) {
        self.unknown=true;self.registry.publish_failure(now); // atomics only
        if let FixtureResidentWindow::Live(domain)=&*self.window {domain.failure_at(now,true);}
    }
    fn allowed(&self,now:u64,cleanup:bool)->bool {
        now!=0 && now<=prepare::MAX_RAW && now>=self.entered && now>=self.last
            && !self.registry.unknown.load(Ordering::SeqCst)
            && !self.registry.clock_unknown.load(Ordering::SeqCst)
            && self.window.snapshot().is_none_or(|window|
                !window.unknown && !window.clock_unknown && window.admits(now,cleanup))
    }
    fn point(&mut self,phase:u32,edge:u32,cleanup:u32,now:u64,outcome:u32)->u32 {
        if self.unknown || !(1..=13).contains(&phase) || edge>1 || cleanup>1 || outcome>2
            || edge==0 && (outcome!=0 || self.pending.is_some() || self.calls>=131_072)
            || edge==1 && self.pending!=Some((phase,cleanup)) {
            self.fail(now);return 2;
        }
        if edge==1 {self.pending=None;self.returns+=1;}
        // The original failure stamp precedes any later provider phase or
        // optional DATA observation; never substitute callback arrival time.
        if outcome!=0 {self.fail(now);return if outcome==1{0}else{2};}
        if !self.allowed(now,cleanup==1 || edge==1) {self.fail(now);return 2;}
        self.last=now;
        if edge==0 {self.calls+=1;self.pending=Some((phase,cleanup));}
        1
    }
    fn api(&mut self)->registration::FixtureCheckpointApi {
        registration::FixtureCheckpointApi {context:(self as *mut Self).cast(),point:fixture_resident_identity_point}
    }
    fn finish(mut self,returned:u64,actual:bool)->bool {
        let known=actual && !self.unknown && self.pending.is_none() && self.calls==self.returns
            && matches!(self.operation,OP_NEW|OP_CLOSE_MAIN) && self.ticket!=0 && self.allowed(returned,true);
        if !known {self.fail(returned);return false;}
        // Only this actual same-ticket C return releases its temporary DATA
        // guard. A final copied window had no second allocation to release.
        drop(ManuallyDrop::into_inner(self.window));true
    }
}
#[cfg(feature="e2-native-fixture")]
unsafe extern "C" fn fixture_resident_identity_point(raw:*mut c_void,phase:u32,edge:u32,cleanup:u32,now:u64,outcome:u32)->u32 {
    let Some(admission)=(unsafe{raw.cast::<FixtureResidentAdmission<'_>>().as_mut()})else{return 2;};
    // No arbitrary FnMut here, but still never allow a future Rust panic to
    // cross C. Publication on this path also uses only the original atomics.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||admission.point(phase,edge,cleanup,now,outcome))) {
        Ok(value)=>value,Err(_)=>{admission.fail(now);2}
    }
}

fn arc_bytes<T>()->Option<usize>{
    // The recorded Rust Arc layout: two reference-count cells plus aligned T.
    #[repr(C)] struct Allocation<T>{counts:[usize;2],data:T}
    Some(std::mem::size_of::<Allocation<T>>())
}
impl ServiceRegistry{
    pub fn new(other_fixed:usize)->Option<Arc<Self>>{Self::new_bound(other_fixed,None)}
    pub fn new_image(other_fixed:usize,host:&crate::installed_image::AdmittedHost)->Option<Arc<Self>>{
        Self::new_bound(other_fixed,Some(host.identity()))
    }
    fn new_bound(other_fixed:usize,image_identity:Option<maintenance::Identity>)->Option<Arc<Self>>{
        let per_context=arc_bytes::<ServiceDomain>()?
            .checked_add(registration::Ingress::service_high_water()?)?
            .checked_add(query::Ingress::service_high_water()?)?
            .checked_add(query::REPLY_BYTES)?.checked_add(CAPTURES_PER_CONTEXT)?;
        let fixed_bytes=arc_bytes::<Self>()?.checked_add(arc_bytes::<PayloadReservation>()?)?
            .checked_add(NATIVE_FIXED_MAX)?.checked_add(SUPERVISOR_STACK)?
            .checked_add(per_context.checked_mul(control::LIVE_CONTEXTS)?)?.checked_add(other_fixed)?;
        #[cfg(feature="e2-native-fixture")]
        let fixed_bytes={
            let identity=crate::android_service_budget::FIXTURE_IDENTITY_PROVIDER_MAX
                .checked_add(std::mem::size_of::<FixtureResidentAdmission<'static>>())?
                .checked_add(std::mem::size_of::<registration::FixtureCheckpointApi>())?
                .checked_add(std::mem::size_of::<registration::FixtureIdentityFacts>())?
                .checked_add(1024)?; // statically bounded native listener adapter backing
            if identity>crate::android_service_budget::FIXTURE_IDENTITY_PROCESS_MAX {return None;}
            fixed_bytes.checked_add(identity)?
        };
        // Includes the inline Weak in each actual ServiceDomain and the original
        // Registry's loan/lifetime cells. No second Registry or window allocation.
        let full=fixed_bytes.checked_add(PAYLOAD_STACK)?.checked_add(COORDINATOR_STACK)?
            .checked_add(32*1024*1024)?;
        if full>control::CONTROL_LIMIT{return None;}
        Some(Arc::new(Self{slots:Mutex::new(RegistrySlots{
            admission:Admission::Reserved,cells:std::array::from_fn(|_|Cell::Empty),
            loan:ListenerLoan::reserved(),maintenance:None,calls:std::array::from_fn(|_|LifetimeCalls::new()),
            main_closed:false,control_retired:false,supervisor_joined:false,book_consumed:false,
        }),counter:NonceCounter::new(),reservation:Arc::new(PayloadReservation::new()),
            accepting:AtomicBool::new(false),unknown:AtomicBool::new(false),first:AtomicU64::new(0),
            clock_unknown:AtomicBool::new(false),fixed_bytes,image_identity}))
    }
    pub fn payload_control_cap(&self,role:ServiceRole)->Option<usize>{
        let remainder=control::CONTROL_LIMIT.checked_sub(self.fixed_bytes)?
            .checked_sub(PAYLOAD_STACK)?.checked_sub(COORDINATOR_STACK)?;
        Some(remainder.min(if role==ServiceRole::Registration{32*1024*1024}else{2*1024*1024}))
    }
    fn work_open_locked(&self,slots:&RegistrySlots,domain:&ServiceDomain)->bool{
        slots.admission==Admission::Open && !self.unknown.load(Ordering::SeqCst)
            && matches!(slots.cells.get(domain.slot),Some(Cell::Live(original))
                if std::ptr::eq(Arc::as_ptr(original),domain) && original.number==domain.number
                    && original.account==domain.account && original.nonce==domain.nonce)
    }
    fn open_admission_once(&self)->bool{
        match self.slots.try_lock(){
            Ok(mut slots)=>{
                if slots.admission!=Admission::Reserved || slots.loan.closed || self.unknown.load(Ordering::SeqCst){return false;}
                slots.admission=Admission::Open;self.accepting.store(true,Ordering::SeqCst);true
            }
            Err(_)=>{self.publish_failure(uptime().unwrap_or(0));false}
        }
    }
    /// R0 closure now also closes the same nonblocking listener loan gate.
    /// It remains DATA closure, never native settlement or maintenance admission.
    pub fn close_admission(&self)->bool{
        self.accepting.store(false,Ordering::SeqCst);
        match self.slots.try_lock(){
            Ok(mut slots)=>{slots.admission=Admission::Closed;slots.loan.closed=true;true}
            Err(_)=>{self.publish_failure(uptime().unwrap_or(0));false}
        }
    }
    pub fn empty_known(&self)->bool{
        self.slots.try_lock().is_ok_and(|slots|!self.unknown.load(Ordering::SeqCst)
            && slots.cells.iter().all(|cell|matches!(cell,Cell::Empty)))
    }
    fn publish_failure(&self,now:u64){
        self.unknown.store(true,Ordering::SeqCst);self.accepting.store(false,Ordering::SeqCst);
        if now==0 || now>prepare::MAX_RAW{self.clock_unknown.store(true,Ordering::SeqCst);return;}
        let _=self.first.fetch_update(Ordering::SeqCst,Ordering::SeqCst,|old|Some(if old==0{now}else{old.min(now)}));
    }
    fn failure_locked(&self,slots:&mut RegistrySlots,now:u64){
        self.publish_failure(now);slots.admission=Admission::Closed;slots.loan.closed=true;
        let first=if self.clock_unknown.load(Ordering::SeqCst){0}else{self.first.load(Ordering::SeqCst)};
        for cell in &slots.cells{if let Cell::Live(domain)=cell{domain.failure_at(first,true);}}
    }
    fn global_failure_at(&self,now:u64){
        // Publish original F before the contended registry guard, never substitute
        // a later relay time and never recursively acquire RegistrySlots.
        self.publish_failure(now);
        if let Ok(mut slots)=self.slots.try_lock(){self.failure_locked(&mut slots,now);}
    }
    fn global_failure(&self){self.global_failure_at(uptime().unwrap_or(0));}
    fn admission_failed_locked(&self,slots:&mut RegistrySlots){self.failure_locked(slots,uptime().unwrap_or(0));}
    fn reserve(self:&Arc<Self>,account:u32,now:u64)->Option<Arc<ServiceDomain>>{
        if account==0 || account==u32::MAX || !self.accepting.load(Ordering::SeqCst) || self.unknown.load(Ordering::SeqCst){return None;}
        let mut slots=self.slots.try_lock().ok()?;
        if slots.admission!=Admission::Open || self.unknown.load(Ordering::SeqCst){return None;}
        let index=slots.cells.iter().position(|cell|matches!(cell,Cell::Empty))?;
        let Some((number,_))=self.counter.reserve()else{self.admission_failed_locked(&mut slots);return None;};
        let domain=Arc::new(ServiceDomain::new(index,number,account,now,self.reservation.clone(),Arc::downgrade(self))?);
        slots.cells[index]=Cell::Live(domain.clone());Some(domain)
    }
    pub fn context(&self,index:usize)->Option<Arc<ServiceDomain>>{
        let slots=self.slots.try_lock().ok()?;
        match slots.cells.get(index)?{Cell::Live(domain)=>Some(domain.clone()),_=>None}
    }
    pub fn begin_maintenance(&self,caller:&Arc<ServiceDomain>,binding:MaintenanceBinding)->MaintenanceAdmission{
        self.begin_maintenance_at(caller,binding,uptime().unwrap_or(0))
    }
    fn begin_maintenance_at(&self,caller:&Arc<ServiceDomain>,binding:MaintenanceBinding,now:u64)->MaintenanceAdmission{
        self.begin_bound_at(caller,binding,now,None).0
    }
    fn begin_bound_at(&self,caller:&Arc<ServiceDomain>,binding:MaintenanceBinding,now:u64,
        protocol:Option<maintenance::Binding>)->(MaintenanceAdmission,Option<maintenance::Binding>){
        let mut slots=match self.slots.try_lock(){
            Ok(slots)=>slots,Err(TryLockError::WouldBlock)=>return (MaintenanceAdmission::Busy,None),
            Err(TryLockError::Poisoned(_))=>{self.publish_failure(now);return (MaintenanceAdmission::Unknown,None);}
        };
        if self.unknown.load(Ordering::SeqCst) || slots.loan.state==LoanState::Unknown{return (MaintenanceAdmission::Unknown,None);}
        if slots.admission!=Admission::Open || slots.maintenance.is_some(){return (MaintenanceAdmission::Refused,None);}
        if binding!=caller.maintenance_binding()
            || !matches!(slots.cells.get(binding.slot),Some(Cell::Live(original)) if Arc::ptr_eq(original,caller)){
            return (MaintenanceAdmission::Refused,None);
        }
        // No account has been authenticated for a body currently holding this
        // loan. Reclaiming/Tombstone is also unidentifiable, never caller-owned.
        // Every known Busy branch is before any gate/window/reservation write.
        if !slots.loan.idle_known() || slots.cells.iter().any(|cell|match cell{
            Cell::Live(domain)=>domain.account!=binding.account,
            Cell::Reclaiming(_)|Cell::Tombstone=>true,Cell::Empty=>false,
        }){return (MaintenanceAdmission::Busy,None);}
        if !caller.window.work_open(now) || !caller.control_data().admits(now,false)
            || now<slots.loan.returned{return (MaintenanceAdmission::Refused,None);}
        let mut prepared=if protocol.is_some(){
            match caller.prepare.try_lock(){Ok(state)=>Some(state),Err(TryLockError::WouldBlock)=>return (MaintenanceAdmission::Busy,None),
                Err(_)=>{self.publish_failure(now);return (MaintenanceAdmission::Unknown,None);}}
        }else{None};
        let started=if let Some(input)=protocol{
            let Some(state)=prepared.as_ref()else{return (MaintenanceAdmission::Refused,None);};
            if self.image_identity.is_none_or(|identity|identity!=input.identity())
                || state.first.request().is_some()
                || state.maintenance.is_none_or(|challenge|challenge.phase!=2 || challenge.binding!=input)
                || caller.window.maintenance()!=Some(input.bounds())
                || caller.tail.begin.load(Ordering::SeqCst)!=1{return (MaintenanceAdmission::Refused,None);}
            let Some(cutoff)=caller.control_data().cutoff().zip(now.checked_add(prepare::CLEANUP_NS))
                .map(|(hard,retired)|hard.min(retired))else{return (MaintenanceAdmission::Unknown,None);};
            let value=maintenance::Binding{cut:now,cutoff,..input};
            if !value.started_valid(){return (MaintenanceAdmission::Refused,None);}Some(value)
        }else{None};
        slots.admission=Admission::Closed;slots.loan.closed=true;self.accepting.store(false,Ordering::SeqCst);
        slots.maintenance=Some(Maintenance{binding,cut:now,final_window:None,protocol:started});
        if let (Some(state),Some(value))=(prepared.as_mut(),started){state.maintenance=Some(MaintenanceChallenge{binding:value,phase:3});}
        // RegistrySlots -> atomics only. No arbitrary callback, native call,
        // blocking prepare lock, or temporary strong caller owner under the cut.
        for cell in &slots.cells{if let Cell::Live(domain)=cell{domain.retire_at(now);}}
        (MaintenanceAdmission::Started,started)
    }
    fn loan_enter(&self,now:u64)->u64{
        let Ok(mut slots)=self.slots.try_lock()else{return 0;};
        if slots.admission!=Admission::Open || slots.loan.closed || self.unknown.load(Ordering::SeqCst)
            || !slots.loan.idle_known(){return 0;}
        if now==0 || now>prepare::MAX_RAW || now<slots.loan.returned{
            slots.loan.state=LoanState::Unknown;self.failure_locked(&mut slots,now);return 0;
        }
        let Some(ticket)=slots.loan.ticket.checked_add(1)else{
            slots.loan.state=LoanState::Unknown;self.failure_locked(&mut slots,now);return 0;
        };
        slots.loan.ticket=ticket;slots.loan.entered=now;slots.loan.state=LoanState::Entered;ticket
    }
    fn loan_return(&self,ticket:u64,now:u64,known:bool)->bool{
        let mut slots=match self.slots.try_lock(){Ok(slots)=>slots,Err(_)=>{self.publish_failure(now);return false;}};
        if !known || slots.loan.state!=LoanState::Entered || slots.loan.ticket!=ticket
            || now<slots.loan.entered || now==0 || now>prepare::MAX_RAW || self.unknown.load(Ordering::SeqCst){
            slots.loan.state=LoanState::Unknown;self.failure_locked(&mut slots,now);return false;
        }
        slots.loan.returned=now;slots.loan.state=LoanState::ReturnedKnown;true
    }
    fn listener_closed_known(&self)->bool{
        self.slots.try_lock().is_ok_and(|slots|slots.admission==Admission::Closed && slots.loan.closed
            && slots.loan.idle_known() && slots.maintenance.is_some() && !self.unknown.load(Ordering::SeqCst))
    }
    /// None while the exact caller Arc is being unwrapped is temporary, not an
    /// invented final clock. No new main/control native operation enters then.
    fn maintenance_window(slots:&RegistrySlots)->Option<WindowData>{
        let maintenance=slots.maintenance.as_ref()?;
        if let Some(final_window)=maintenance.final_window{return Some(final_window);}
        match slots.cells.get(maintenance.binding.slot){
            Some(Cell::Live(domain)) if domain.maintenance_binding()==maintenance.binding=>Some(domain.control_data()),
            _=>None,
        }
    }
    pub fn watch_maintenance(&self){
        let now=uptime().unwrap_or(0);
        let Ok(mut slots)=self.slots.try_lock()else{return;};
        if self.unknown.load(Ordering::SeqCst){
            let first=if self.clock_unknown.load(Ordering::SeqCst){0}else{self.first.load(Ordering::SeqCst)};
            self.failure_locked(&mut slots,first);return;
        }
        let Some(window)=Self::maintenance_window(&slots)else{return;};
        // The EXISTING supervisor watches a possibly blocked main call. There
        // is no watchdog thread/timer. Return methods independently sample time.
        if slots.calls.iter().any(|call|call.pending.is_some()) && !window.admits(now,true){
            self.failure_locked(&mut slots,now);
        }
    }
    fn native_enter(&self,lane:usize,operation:u32,now:u64)->Option<u64>{
        #[cfg(feature="e2-native-fixture")]
        {self.native_enter_captured(lane,operation,now,None)}
        #[cfg(not(feature="e2-native-fixture"))]
        {self.native_enter_captured(lane,operation,now)}
    }
    #[cfg(feature="e2-native-fixture")]
    fn fixture_native_enter(&self,lane:usize,operation:u32,now:u64)->Option<FixtureResidentAdmission<'_>> {
        if lane!=MAIN_LANE || !matches!(operation,OP_NEW|OP_CLOSE_MAIN) {return None;}
        let mut capture=None;
        self.native_enter_captured(lane,operation,now,Some(&mut capture))?;capture
    }
    fn native_enter_captured<'a>(&'a self,lane:usize,operation:u32,now:u64,
        #[cfg(feature="e2-native-fixture")] capture:Option<&mut Option<FixtureResidentAdmission<'a>>>
    )->Option<u64>{
        let mut slots=match self.slots.try_lock(){
            Ok(slots)=>slots,Err(TryLockError::WouldBlock)=>return None,
            Err(TryLockError::Poisoned(_))=>{self.publish_failure(now);return None;}
        };
        if lane>=LIFE_LANES || self.unknown.load(Ordering::SeqCst){return None;}
        // The four original teardown entries require the monotonic closed,
        // idle listener loan under THIS ticket guard. Never re-take this DATA
        // lock from an already-entered C operation: ordinary contention there
        // is not an unknown selector or a failed closure.
        if matches!(operation,OP_CLOSE_LISTENER|OP_CLOSE_MAIN|OP_RETIRE_CONTROL|OP_CONSUME_BOOK)
            && (slots.admission!=Admission::Closed || !slots.loan.closed
                || !slots.loan.idle_known() || slots.maintenance.is_none()){
            self.failure_locked(&mut slots,now);return None;
        }
        if slots.maintenance.is_some(){
            let window=Self::maintenance_window(&slots)?;
            if !window.admits(now,true){self.failure_locked(&mut slots,now);return None;}
        }
        #[cfg(feature="e2-native-fixture")]
        let window=if capture.is_some(){Some(FixtureResidentWindow::capture(&slots)?)}else{None};
        let ticket=slots.calls[lane].enter(operation,now);
        if ticket.is_none(){self.failure_locked(&mut slots,now);}
        #[cfg(feature="e2-native-fixture")]
        if let (Some(out),Some(window),Some(ticket))=(capture,window,ticket) {
            *out=Some(FixtureResidentAdmission{registry:self,ticket,operation,entered:now,last:now,
                calls:0,returns:0,pending:None,unknown:false,window:ManuallyDrop::new(window)});
        }
        ticket
    }
    fn begin_call_enter(&self,now:u64)->Option<u64>{
        let mut slots=match self.slots.try_lock(){
            Ok(slots)=>slots,Err(TryLockError::WouldBlock)=>return None,
            Err(TryLockError::Poisoned(_))=>{self.publish_failure(now);return None;}
        };
        if self.unknown.load(Ordering::SeqCst){return None;}
        if slots.admission!=Admission::Reserved || slots.loan.closed{
            self.failure_locked(&mut slots,now);return None;
        }
        let ticket=slots.calls[MAIN_LANE].enter(OP_BEGIN,now);
        if ticket.is_none(){self.failure_locked(&mut slots,now);return None;}
        // The same R0 Reserved->Open transition and the actual native-entry
        // reservation are serialized together; a deferred no-entry never opens
        // admission early or has to reopen it on the next pass.
        slots.admission=Admission::Open;self.accepting.store(true,Ordering::SeqCst);ticket
    }
    fn native_domain_close_enter(&self,domain:&ServiceDomain,now:u64)->Option<u64>{
        let mut slots=match self.slots.try_lock(){
            Ok(slots)=>slots,Err(TryLockError::WouldBlock)=>return None,
            Err(TryLockError::Poisoned(_))=>{self.publish_failure(now);return None;}
        };
        if self.unknown.load(Ordering::SeqCst){return None;}
        if slots.maintenance.is_some(){
            let window=Self::maintenance_window(&slots)?;
            if !window.admits(now,true){self.failure_locked(&mut slots,now);return None;}
        }
        // Fixed DATA-only RegistrySlots -> domain ledger ordering, never an
        // arbitrary callback/native operation. No Domain Entered fact precedes
        // a known no-entry Registry contention.
        if !domain.native_entered(now){return None;}
        let ticket=slots.calls[CONTROL_LANE].enter(OP_CLOSE_CONTEXT,now);
        if ticket.is_none(){
            domain.native.store(3,Ordering::SeqCst);self.failure_locked(&mut slots,now);
        }
        ticket
    }
    fn native_actual_return(&self,lane:usize,ticket:u64,operation:u32,now:u64)->bool{
        let mut slots=match self.slots.try_lock(){Ok(slots)=>slots,Err(_)=>{self.publish_failure(now);return false;}};
        if lane>=LIFE_LANES || !slots.calls[lane].actual_return(ticket,operation,now){
            self.failure_locked(&mut slots,now);return false;
        }
        if Self::maintenance_window(&slots).is_some_and(|window|!window.admits(now,true)){
            self.failure_locked(&mut slots,now);return false;
        }
        !self.unknown.load(Ordering::SeqCst)
    }
    fn tail_enter(&self,now:u64)->u64{
        let mut slots=match self.slots.try_lock(){Ok(slots)=>slots,Err(_)=>{self.publish_failure(now);return 0;}};
        if slots.admission!=Admission::Closed || !slots.loan.closed || !slots.loan.idle_known()
            || slots.maintenance.is_none() || self.unknown.load(Ordering::SeqCst){
            self.failure_locked(&mut slots,now);return 0;
        }
        // Foundation has already entered dealloc. Record that unavoidable
        // DATA-only tail even during the caller's temporary Reclaiming interval;
        // final same-Registry reconciliation rechecks its actual return.
        let ticket=slots.calls[TAIL_LANE].enter(OP_DEALLOC,now).unwrap_or(0);
        if ticket==0{self.failure_locked(&mut slots,now);}
        ticket
    }
    fn main_closed_returned(&self)->bool{
        let Ok(mut slots)=self.slots.try_lock()else{self.publish_failure(uptime().unwrap_or(0));return false;};
        if self.unknown.load(Ordering::SeqCst) || slots.main_closed || slots.calls[MAIN_LANE].pending.is_some(){return false;}
        slots.main_closed=true;true
    }
    pub fn control_ready_to_return(&self)->bool{
        self.slots.try_lock().is_ok_and(|slots|slots.admission==Admission::Closed && slots.loan.closed
            && slots.loan.idle_known() && slots.main_closed && !slots.control_retired
            && slots.maintenance.as_ref().is_some_and(|request|request.final_window.is_some())
            && slots.cells.iter().all(|cell|matches!(cell,Cell::Empty)) && !self.unknown.load(Ordering::SeqCst))
    }
    fn control_returned(&self)->bool{
        let Ok(mut slots)=self.slots.try_lock()else{self.publish_failure(uptime().unwrap_or(0));return false;};
        if !slots.main_closed || slots.control_retired || self.unknown.load(Ordering::SeqCst)
            || slots.calls[CONTROL_LANE].pending.is_some() || !slots.cells.iter().all(|cell|matches!(cell,Cell::Empty)){return false;}
        slots.control_retired=true;true
    }
    fn supervisor_joined(&self)->bool{
        let Ok(mut slots)=self.slots.try_lock()else{self.publish_failure(uptime().unwrap_or(0));return false;};
        if !slots.control_retired || slots.supervisor_joined || slots.calls[JOIN_LANE].pending.is_some()
            || self.unknown.load(Ordering::SeqCst){return false;}
        slots.supervisor_joined=true;true
    }
    fn book_consumed(&self)->bool{
        let Ok(mut slots)=self.slots.try_lock()else{self.publish_failure(uptime().unwrap_or(0));return false;};
        if !slots.supervisor_joined || slots.book_consumed || slots.calls[MAIN_LANE].pending.is_some()
            || self.unknown.load(Ordering::SeqCst){return false;}
        slots.book_consumed=true;true
    }
    fn take_for_reclaim(&self,index:usize,number:u64)->Option<Arc<ServiceDomain>>{
        let mut slots=self.slots.try_lock().ok()?;
        if !matches!(slots.cells.get(index),Some(Cell::Live(domain)) if domain.number==number){return None;}
        match std::mem::replace(&mut slots.cells[index],Cell::Reclaiming(number)){Cell::Live(domain)=>Some(domain),_=>None}
    }
    fn restore(&self,index:usize,number:u64,domain:Arc<ServiceDomain>){
        if let Ok(mut slots)=self.slots.try_lock(){
            if matches!(slots.cells.get(index),Some(Cell::Reclaiming(held)) if *held==number){slots.cells[index]=Cell::Live(domain);return;}
        }
        self.global_failure();std::mem::forget(domain);
    }
    fn caller_final_after_unwrap(&self,index:usize,number:u64,window:WindowData)->Option<bool>{
        let mut slots=match self.slots.try_lock(){
            Ok(slots)=>slots,Err(TryLockError::WouldBlock)=>return None,
            Err(TryLockError::Poisoned(_))=>{self.publish_failure(uptime().unwrap_or(0));return Some(false);}
        };
        if !matches!(slots.cells.get(index),Some(Cell::Reclaiming(held)) if *held==number){
            self.admission_failed_locked(&mut slots);return Some(false);
        }
        if let Some(request)=slots.maintenance.as_mut(){
            if request.binding.slot==index && request.binding.number==number{
                if request.final_window.is_some(){self.admission_failed_locked(&mut slots);return Some(false);}
                request.final_window=Some(window);
            }
        }
        Some(true)
    }
    fn finish_reclaim(&self,index:usize,number:u64,known:bool){
        match self.slots.try_lock(){
            Ok(mut slots)=>{
                if matches!(slots.cells.get(index),Some(Cell::Reclaiming(held)) if *held==number){
                    slots.cells[index]=if known{Cell::Empty}else{Cell::Tombstone};
                    if !known{self.admission_failed_locked(&mut slots);}
                }else{self.admission_failed_locked(&mut slots);}
            }
            Err(_)=>self.publish_failure(uptime().unwrap_or(0)),
        }
    }
    fn into_reclaimed(mut self,unwrapped_at:u64)->Result<ReclaimedRegistry,Self>{
        let registry_known=!self.unknown.load(Ordering::SeqCst) && !self.clock_unknown.load(Ordering::SeqCst);
        // Receives the ACTUAL same-Registry try_unwrap value and its immediately
        // sampled return time. Timely earlier native returns are not permission
        // to reclaim late after a final DATA holder delayed exclusivity.
        let accepted=match self.slots.get_mut(){
            Ok(slots)=>{
                let final_data=slots.maintenance.as_ref().and_then(|request|request.final_window.map(|window|(request,window)));
                final_data.and_then(|(request,window)|{
                    let last=slots.calls.iter().map(|call|call.last).max().unwrap_or(0)
                        .max(slots.loan.returned).max(request.cut);
                    (slots.admission==Admission::Closed && slots.loan.closed && slots.loan.idle_known()
                        && slots.cells.iter().all(|cell|matches!(cell,Cell::Empty))
                        && slots.main_closed && slots.control_retired && slots.supervisor_joined && slots.book_consumed
                        && registry_known
                        && !window.unknown && !window.clock_unknown && window.admits(request.cut,true)
                        && window.admits(unwrapped_at,true) && unwrapped_at>=last
                        && slots.calls.iter().all(|call|call.known_with(window)))
                        .then_some((request.binding,request.protocol,window,last))
                })
            }
            Err(_)=>None,
        };
        match accepted{
            Some((binding,protocol,window,last))=>{
                drop(self); // actual remaining Registry/reservation DATA consumption
                Ok(ReclaimedRegistry{binding,protocol,window,last,unwrapped_at})
            }
            None=>Err(self),
        }
    }
}

#[repr(C)]
#[derive(Clone,Copy)]
struct RegistryApi{
    retain:unsafe extern "C" fn(*const c_void)->*const c_void,
    release:unsafe extern "C" fn(*const c_void),
    loan_enter:unsafe extern "C" fn(*const c_void,u64)->u64,
    loan_return:unsafe extern "C" fn(*const c_void,u64,u64,u32)->c_int,
    closed:unsafe extern "C" fn(*const c_void)->c_int,
    tail_enter:unsafe extern "C" fn(*const c_void,u64)->u64,
    tail_return:unsafe extern "C" fn(*const c_void,u64,u64,u32)->c_int,
    failure:unsafe extern "C" fn(*const c_void,u64),
}
#[repr(C)]
struct ServiceApi{
    reserve:unsafe extern "C" fn(*const c_void,u32,u64,*mut u32,*mut u64)->*const c_void,
    retain:unsafe extern "C" fn(*const c_void)->*const c_void,release:unsafe extern "C" fn(*const c_void),
    notify:unsafe extern "C" fn(*const c_void,u64,u32),
    enter:unsafe extern "C" fn(*const c_void,u32,u32,u64)->u64,
    returned:unsafe extern "C" fn(*const c_void,u32,u64,u64,u32)->c_int,
    claim:unsafe extern "C" fn(*const c_void,u64)->u64,
    response:unsafe extern "C" fn(*const c_void,u64,u32,*const u8,usize,u64,*mut *mut u8,*mut usize)->c_int,
    backing:unsafe extern "C" fn(*const c_void,u64),
    finish:unsafe extern "C" fn(*const c_void,u64,u32),
    maintenance_body:unsafe extern "C" fn(*const c_void,u32,u32,u64,u32)->c_int,
    tail_binding:unsafe extern "C" fn(*const c_void,*mut maintenance::Binding)->c_int,
    tail_receipt:unsafe extern "C" fn(*const c_void,*const u8,usize,u64)->c_int,
    tail_ready:unsafe extern "C" fn(*const c_void)->c_int,
    tail_closed:unsafe extern "C" fn(*const c_void,u64,u32)->c_int,
    registry:RegistryApi,
}
static API:ServiceApi=ServiceApi{reserve:reserve_callback,retain:retain_callback,release:release_callback,notify:notify_callback,
    enter:enter_callback,returned:return_callback,claim:claim_callback,response:response_callback,
    backing:backing_callback,finish:finish_callback,
    maintenance_body:maintenance_body_callback,tail_binding:tail_binding_callback,tail_receipt:tail_receipt_callback,
    tail_ready:tail_ready_callback,tail_closed:tail_closed_callback,registry:RegistryApi{
        retain:registry_retain_callback,release:registry_release_callback,
        loan_enter:registry_loan_enter_callback,loan_return:registry_loan_return_callback,
        closed:registry_closed_callback,tail_enter:registry_tail_enter_callback,
        tail_return:registry_tail_return_callback,failure:global_callback,
    }};
unsafe extern "C" fn reserve_callback(context:*const c_void,account:u32,now:u64,slot:*mut u32,number:*mut u64)->*const c_void{
    if context.is_null() || slot.is_null() || number.is_null(){return std::ptr::null();}
    // The native wrapper already owns a Registry guard. This distinct temporary
    // strong loan permits Arc::downgrade of THAT same allocation; it is dropped
    // on every return here, never converted into another independent owner.
    let registry=unsafe{
        Arc::increment_strong_count(context.cast::<ServiceRegistry>());
        Arc::from_raw(context.cast::<ServiceRegistry>())
    };
    let Some(domain)=registry.reserve(account,now)else{return std::ptr::null();};
    unsafe{*slot=domain.slot as u32;*number=domain.number;}Arc::into_raw(domain).cast()
}
unsafe extern "C" fn retain_callback(context:*const c_void)->*const c_void{
    if !context.is_null(){unsafe{Arc::increment_strong_count(context.cast::<ServiceDomain>());}}context
}
unsafe extern "C" fn release_callback(context:*const c_void){
    if !context.is_null(){unsafe{drop(Arc::from_raw(context.cast::<ServiceDomain>()));}}
}
unsafe extern "C" fn notify_callback(context:*const c_void,now:u64,kind:u32){
    if let Some(domain)=unsafe{context.cast::<ServiceDomain>().as_ref()}{
        if kind==2{domain.retire_at(now);}else{domain.failure_at(now,kind!=0);}
    }
}
unsafe extern "C" fn enter_callback(context:*const c_void,lane:u32,cleanup:u32,now:u64)->u64{
    if cleanup>1{return 0;}
    unsafe{context.cast::<ServiceDomain>().as_ref()}.map_or(0,|domain|domain.entered_call(lane as usize,cleanup==1,now))
}
unsafe extern "C" fn return_callback(context:*const c_void,lane:u32,ticket:u64,now:u64,known:u32)->c_int{
    unsafe{context.cast::<ServiceDomain>().as_ref()}.map_or(0,|domain|i32::from(domain.returned_call(lane as usize,ticket,now,known==1)))
}
unsafe extern "C" fn claim_callback(context:*const c_void,now:u64)->u64{
    let Some(domain)=(unsafe{context.cast::<ServiceDomain>().as_ref()})else{return 0;};
    domain.window.watch(now);
    if !domain.window.snapshot().admits(now,true){domain.failure_at(now,false);return 0;}
    match domain.reply.claim(){Some(ticket)=>ticket,None=>{
        // No second original retain/pool/NSData allocation behind the old lease.
        domain.failure_at(now,domain.reply.is_unknown());0
    }}
}
unsafe extern "C" fn response_callback(context:*const c_void,ticket:u64,kind:u32,input:*const u8,count:usize,now:u64,
    out:*mut *mut u8,length:*mut usize)->c_int{
    if context.is_null() || input.is_null() || out.is_null() || length.is_null() || count==0 || count>registration::FRAME_BYTES{return 0;}
    let domain=unsafe{&*context.cast::<ServiceDomain>()};
    if !domain.reply.active(ticket){domain.failure_at(now,true);return 0;}
    let raw=unsafe{std::slice::from_raw_parts(input,count)};
    let cleanup=match kind{
        0=>false,
        1=>registration::Envelope::decode(raw).is_ok_and(|frame|frame.verb!=registration::Verb::Push),
        2=>query::Request::decode(raw).is_some_and(|request|!request.kind.work()),
        3..=5=>false,
        _=>{domain.failure_at(now,false);return 0;}
    };
    domain.window.watch(now);
    if !domain.window.snapshot().admits(now,cleanup){domain.failure_at(now,false);return 0;}
    let response=unsafe{&mut **domain.response.get()};
    let produced=match kind{
        3..=5 if count==maintenance::BYTES=>maintenance::Frame::decode(raw).and_then(|input|domain.maintenance_response(kind,input,now))
            .map(|frame|{response[..maintenance::BYTES].copy_from_slice(&frame);maintenance::BYTES}),
        0 if count==prepare::BYTES=>prepare::Request::decode(raw).and_then(|request|domain.prepared_reply(request,now))
            .map(|reply|{response[..prepare::BYTES].copy_from_slice(&reply);prepare::BYTES}),
        1 if (registration::ENVELOPE_BYTES..=registration::FRAME_BYTES).contains(&count)
            && domain.role()==Some(ServiceRole::Registration)=>{
                let phase=domain.prepare.try_lock().ok().map(|state|state.first.phase());
                if phase!=Some(prepare::Phase::Ready) && !cleanup{None}
                else{response[..registration::STATUS_BYTES].copy_from_slice(&domain.registration.exchange(domain.account,raw,now));Some(registration::STATUS_BYTES)}
            },
        2 if count==query::REQUEST_BYTES && domain.role()==Some(ServiceRole::ReadOnlyQuery)=>{
            let phase=domain.prepare.try_lock().ok().map(|state|state.first.phase());
            if phase!=Some(prepare::Phase::Ready) && !cleanup{None}else{
                domain.query.exchange(domain.account,raw,now).map(|reply|{response.copy_from_slice(&reply);query::REPLY_BYTES})
            }
        }
        _=>None,
    };
    let Some(bytes)=produced else{domain.failure_at(now,false);return 0;};
    unsafe{*out=response.as_mut_ptr();*length=bytes;}1
}
unsafe extern "C" fn maintenance_body_callback(context:*const c_void,kind:u32,returning:u32,now:u64,known:u32)->c_int{
    if returning>1 || known>1{return 0;}
    unsafe{context.cast::<ServiceDomain>().as_ref()}.map_or(0,|domain|i32::from(domain.tail_body(kind,returning==1,now,known==1)))
}
unsafe extern "C" fn tail_binding_callback(context:*const c_void,out:*mut maintenance::Binding)->c_int{
    if out.is_null(){return 0;}
    let Some(binding)=unsafe{context.cast::<ServiceDomain>().as_ref()}.and_then(ServiceDomain::tail_binding)else{return 0;};
    unsafe{out.write(binding);}1
}
unsafe extern "C" fn tail_receipt_callback(context:*const c_void,input:*const u8,count:usize,now:u64)->c_int{
    if input.is_null() || count!=maintenance::BYTES{return 0;}
    let Some(domain)=(unsafe{context.cast::<ServiceDomain>().as_ref()})else{return 0;};
    i32::from(domain.tail_receipt(unsafe{std::slice::from_raw_parts(input,count)},now))
}
unsafe extern "C" fn tail_ready_callback(context:*const c_void)->c_int{
    unsafe{context.cast::<ServiceDomain>().as_ref()}.map_or(-1,ServiceDomain::tail_ready)
}
unsafe extern "C" fn tail_closed_callback(context:*const c_void,now:u64,known:u32)->c_int{
    unsafe{context.cast::<ServiceDomain>().as_ref()}.map_or(0,|domain|i32::from(domain.tail_closed(now,known==1)))
}
unsafe extern "C" fn backing_callback(context:*const c_void,ticket:u64){
    if let Some(domain)=unsafe{context.cast::<ServiceDomain>().as_ref()}{
        if !domain.reply.backing_relinquished(ticket){domain.failure_now(true);}
    }
}
unsafe extern "C" fn finish_callback(context:*const c_void,ticket:u64,known:u32){
    if let Some(domain)=unsafe{context.cast::<ServiceDomain>().as_ref()}{
        if known>1 || !domain.reply.original_returns(ticket,known==1) || !domain.reply.borrow_ended(ticket){
            domain.reply.unknown();domain.failure_now(true);
        }
    }
}
unsafe extern "C" fn registry_retain_callback(context:*const c_void)->*const c_void{
    if !context.is_null(){unsafe{Arc::increment_strong_count(context.cast::<ServiceRegistry>());}}context
}
unsafe extern "C" fn registry_release_callback(context:*const c_void){
    if !context.is_null(){unsafe{drop(Arc::from_raw(context.cast::<ServiceRegistry>()));}}
}
unsafe extern "C" fn registry_loan_enter_callback(context:*const c_void,now:u64)->u64{
    unsafe{context.cast::<ServiceRegistry>().as_ref()}.map_or(0,|registry|registry.loan_enter(now))
}
unsafe extern "C" fn registry_loan_return_callback(context:*const c_void,ticket:u64,now:u64,known:u32)->c_int{
    unsafe{context.cast::<ServiceRegistry>().as_ref()}.map_or(0,|registry|i32::from(registry.loan_return(ticket,now,known==1)))
}
unsafe extern "C" fn registry_closed_callback(context:*const c_void)->c_int{
    unsafe{context.cast::<ServiceRegistry>().as_ref()}.map_or(0,|registry|i32::from(registry.listener_closed_known()))
}
unsafe extern "C" fn registry_tail_enter_callback(context:*const c_void,now:u64)->u64{
    unsafe{context.cast::<ServiceRegistry>().as_ref()}.map_or(0,|registry|registry.tail_enter(now))
}
unsafe extern "C" fn registry_tail_return_callback(context:*const c_void,ticket:u64,now:u64,known:u32)->c_int{
    let Some(registry)=(unsafe{context.cast::<ServiceRegistry>().as_ref()})else{return 0;};
    let actual=registry.native_actual_return(TAIL_LANE,ticket,OP_DEALLOC,now);
    if known!=1{registry.global_failure_at(now);return 0;}
    i32::from(actual)
}
unsafe extern "C" fn global_callback(context:*const c_void,now:u64){
    if let Some(registry)=unsafe{context.cast::<ServiceRegistry>().as_ref()}{registry.global_failure_at(now);}
}
#[repr(C)]
#[derive(Default)]
struct NativeReport{
    version:u32,operation:u32,known:u32,selectors_entered:u32,selectors_returned:u32,
    slots:[u32;3],listener_close:u32,control_state:u32,consumed:u32,run_result:u32,pool_generation:u64,
}
const POOL_MASK:u32=7;
const BEGIN_MASK:u32=511;
const PUMP_MASK:u32=POOL_MASK|(1<<9);
const CLOSE_LISTENER_MASK:u32=POOL_MASK|(1<<10);
const CLOSE_MAIN_MASK:u32=POOL_MASK|(1<<11)|(1<<12);
const FREE_MASK:u32=1<<13;
const ALLOCATE_MASK:u32=1<<14;
impl NativeReport{
    fn header(&self,operation:u32,mask:u32)->bool{
        self.version==1 && self.operation==operation && self.known==1
            && self.selectors_entered==mask && self.selectors_returned==mask
    }
    fn control(&self,operation:u32,state:u32)->bool{
        self.header(operation,0) && self.slots==[0;3] && self.listener_close==0
            && self.control_state==state && self.consumed==0 && self.run_result==0 && self.pool_generation==0
    }
    fn main(&self,operation:u32,mask:u32,generation:u64,slots:[u32;3],closed:u32)->bool{
        self.header(operation,mask) && self.pool_generation==generation && self.slots==slots
            && self.listener_close==closed && self.consumed==0 && self.run_result==0 && self.control_state==1
    }
}
unsafe extern "C"{
    #[cfg(not(feature="e2-native-fixture"))]
    fn mrk_android_service_new(context:*const c_void,api:*const ServiceApi,host:*const crate::installed_image::Host,report:*mut NativeReport)->*mut c_void;
    #[cfg(feature="e2-native-fixture")]
    fn mrk_android_e2_fixture_service_new(context:*const c_void,api:*const ServiceApi,host:*const crate::installed_image::Host,
        identity_api:*const registration::FixtureCheckpointApi,report:*mut NativeReport)->*mut c_void;
    fn mrk_android_service_tail_progress(book:*mut c_void,slot:u32,number:u64,domain:*const c_void)->c_int;
    fn mrk_android_service_bind_control(book:*mut c_void,report:*mut NativeReport);
    fn mrk_android_service_begin(book:*mut c_void,report:*mut NativeReport);
    fn mrk_android_service_close_context(book:*mut c_void,slot:u32,number:u64,domain:*const c_void)->c_int;
    fn mrk_android_service_context_ready(book:*mut c_void,slot:u32,number:u64)->c_int;
    fn mrk_android_service_reclaim_context(book:*mut c_void,slot:u32,number:u64)->c_int;
    fn mrk_android_service_pump_once(book:*mut c_void,report:*mut NativeReport);
    fn mrk_android_service_close_listener(book:*mut c_void,report:*mut NativeReport);
    #[cfg(not(feature="e2-native-fixture"))]
    fn mrk_android_service_close_main_references(book:*mut c_void,report:*mut NativeReport);
    #[cfg(feature="e2-native-fixture")]
    fn mrk_android_e2_fixture_service_close_main_references(book:*mut c_void,
        identity_api:*const registration::FixtureCheckpointApi,report:*mut NativeReport);
    fn mrk_android_service_retire_control(book:*mut c_void,report:*mut NativeReport);
    fn mrk_android_service_consume_book(book:*mut *mut c_void,report:*mut NativeReport);
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum BookPhase{Fresh,Allocated,Begun,ListenerClosed,MainClosed,Consumed,Unknown}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum PumpReturn{Finished,Stopped,TimedOut,HandledSource,Unavailable}
/// Private finality object. Public ResidentReturn is an opaque owning adapter
/// only; no boolean/status constructor or unregister/transport API exists.
struct ProductQuiesced{binding:MaintenanceBinding,protocol:Option<maintenance::Binding>,window:WindowData,last:u64,returned_at:u64}
/// Owning return of actual Registry consumption, NOT positive completion. It
/// stays charged on a late/unknown post-consuming return, without recreating an
/// Arc or probing a consumed book. No native pointer or callback is retained.
struct ReclaimedRegistry{binding:MaintenanceBinding,protocol:Option<maintenance::Binding>,window:WindowData,last:u64,unwrapped_at:u64}
impl ReclaimedRegistry{
    fn return_is_timely(&self,returned_at:u64)->bool{
        !self.window.unknown && !self.window.clock_unknown && self.window.admits(returned_at,true)
            && returned_at>=self.unwrapped_at && returned_at>=self.last
    }
}
pub struct ResidentReturn(ProductQuiesced);
impl ResidentReturn{
    pub(crate) fn image_data(&self)->Option<(maintenance::Binding,WindowData,u64,u64)>{
        let value=&self.0;let binding=value.protocol?;
        if binding.number!=value.binding.number || binding.account!=value.binding.account
            || binding.slot as usize!=value.binding.slot || binding.nonce!=value.binding.nonce{return None;}
        Some((binding,value.window,value.last,value.returned_at))
    }
    pub fn into_exit_code(self)->i32{
        let ProductQuiesced{binding,..}=self.0;let _=binding;0
    }
}
/// Constructed only by consuming the original ServiceControl after its actual
/// last native return. Main must obtain it through its actual original join.
pub struct SupervisorReturn{address:usize,registry:ManuallyDrop<Arc<ServiceRegistry>>}
pub struct ServiceBook{
    pointer:Option<NonNull<c_void>>,registry:Option<ManuallyDrop<Arc<ServiceRegistry>>>,
    exclusive_unknown:Option<ManuallyDrop<ServiceRegistry>>,reclaimed_unknown:Option<ReclaimedRegistry>,phase:BookPhase,
    pool_generation:u64,joined:bool,consumed_address:usize,host:Option<crate::installed_image::AdmittedHost>,
}
struct PendingReclaim{index:usize,number:u64,window:WindowData,transferred:bool}
pub struct ServiceControl{
    pointer:NonNull<c_void>,registry:ManuallyDrop<Arc<ServiceRegistry>>,bind_entered:bool,bound:bool,
    pending_reclaim:Option<PendingReclaim>,
}
unsafe impl Send for ServiceControl{}
// SupervisorReturn contains only an address for comparison and original DATA.
// It exposes no pointer probe/native accessor on the main thread.
impl ServiceBook{
    pub fn new(registry:Arc<ServiceRegistry>)->Self{
        Self{pointer:None,registry:Some(ManuallyDrop::new(registry)),exclusive_unknown:None,reclaimed_unknown:None,
            phase:BookPhase::Fresh,pool_generation:0,joined:false,consumed_address:0,host:None}
    }
    pub fn new_image(registry:Arc<ServiceRegistry>,host:crate::installed_image::AdmittedHost)->Self{
        let mut book=Self::new(registry);book.host=Some(host);book
    }
    pub fn retain_unknown(&mut self){
        if let Some(registry)=self.registry.as_ref(){registry.global_failure();}
        self.phase=BookPhase::Unknown;
    }
    pub fn reserve_control(&mut self)->Result<ServiceControl,Failure>{
        if self.phase!=BookPhase::Fresh || self.pointer.is_some(){return Err(Failure::Unavailable);}
        #[cfg(not(feature="e2-native-fixture"))]
        if !registration::ClientBook::identity_available(){return Err(Failure::Unavailable);}
        let Some(held)=self.registry.as_ref()else{return Err(Failure::Unavailable);};
        let registry:&Arc<ServiceRegistry>=held;
        #[cfg(not(feature="e2-native-fixture"))]
        let Some(ticket)=registry.native_enter(MAIN_LANE,OP_NEW,uptime().unwrap_or(0))else{return Err(Failure::Native);};
        #[cfg(feature="e2-native-fixture")]
        let Some(mut admission)=registry.fixture_native_enter(MAIN_LANE,OP_NEW,uptime().unwrap_or(0))else{return Err(Failure::Native);};
        #[cfg(feature="e2-native-fixture")]
        let ticket=admission.ticket;
        self.phase=BookPhase::Unknown;
        let mut report=NativeReport::default();
        #[cfg(not(feature="e2-native-fixture"))]
        let raw=unsafe{mrk_android_service_new(Arc::as_ptr(registry).cast(),&API,
            self.host.as_ref().map_or(std::ptr::null(),crate::installed_image::AdmittedHost::pointer),&mut report)};
        #[cfg(feature="e2-native-fixture")]
        let raw=unsafe{mrk_android_e2_fixture_service_new(Arc::as_ptr(registry).cast(),&API,
            self.host.as_ref().map_or(std::ptr::null(),crate::installed_image::AdmittedHost::pointer),&admission.api(),&mut report)};
        let returned=uptime().unwrap_or(0); // actual FFI return BEFORE report decode
        self.pointer=NonNull::new(raw);
        let actual=registry.native_actual_return(MAIN_LANE,ticket,OP_NEW,returned);
        #[cfg(feature="e2-native-fixture")]
        let actual=admission.finish(returned,actual);
        if !actual || self.pointer.is_none() || !report.header(OP_NEW,ALLOCATE_MASK)
            || report.slots!=[0;3] || report.listener_close!=0 || report.control_state!=0
            || report.consumed!=0 || report.run_result!=0 || report.pool_generation!=0{
            registry.global_failure_at(returned);return Err(Failure::Native);
        }
        self.phase=BookPhase::Allocated;
        Ok(ServiceControl{pointer:self.pointer.expect("checked original allocation"),
            registry:ManuallyDrop::new(Arc::clone(registry)),bind_entered:false,bound:false,pending_reclaim:None})
    }
    pub fn begin(&mut self)->Result<bool,Failure>{
        if self.phase!=BookPhase::Allocated{return Err(Failure::Unavailable);}
        let (Some(pointer),Some(registry))=(self.pointer,self.registry.as_ref())else{return Err(Failure::Unavailable);};
        let Some(ticket)=registry.begin_call_enter(uptime().unwrap_or(0))else{
            return if registry.unknown.load(Ordering::SeqCst){Err(Failure::Native)}else{Ok(false)};
        };
        self.phase=BookPhase::Unknown;
        let mut report=NativeReport::default();
        unsafe{mrk_android_service_begin(pointer.as_ptr(),&mut report);}
        let returned=uptime().unwrap_or(0);
        let actual=registry.native_actual_return(MAIN_LANE,ticket,OP_BEGIN,returned);
        if !actual || !report.main(OP_BEGIN,BEGIN_MASK,1,[6,4,4],0){
            registry.global_failure_at(returned);return Err(Failure::Native);
        }
        self.pool_generation=1;self.phase=BookPhase::Begun;Ok(true)
    }
    pub fn pump_once(&mut self)->PumpReturn{
        if !matches!(self.phase,BookPhase::Begun|BookPhase::ListenerClosed|BookPhase::MainClosed){return PumpReturn::Unavailable;}
        let (Some(pointer),Some(registry))=(self.pointer,self.registry.as_ref())else{return PumpReturn::Unavailable;};
        let Some(next)=self.pool_generation.checked_add(1)else{registry.global_failure();self.phase=BookPhase::Unknown;return PumpReturn::Unavailable;};
        let Some(ticket)=registry.native_enter(MAIN_LANE,OP_PUMP,uptime().unwrap_or(0))else{return PumpReturn::Unavailable;};
        let mut report=NativeReport::default();
        unsafe{mrk_android_service_pump_once(pointer.as_ptr(),&mut report);}
        let returned=uptime().unwrap_or(0);
        let actual=registry.native_actual_return(MAIN_LANE,ticket,OP_PUMP,returned);
        let expected=if self.phase==BookPhase::MainClosed{[6,6,6]}else{[6,4,4]};
        let closed=if self.phase==BookPhase::Begun{0}else{2};
        let valid=report.header(OP_PUMP,PUMP_MASK) && report.slots==expected && report.pool_generation==next
            && report.listener_close==closed && report.consumed==0
            && (report.control_state==1 || self.phase==BookPhase::MainClosed && report.control_state==2);
        let result=match report.run_result{1=>PumpReturn::Finished,2=>PumpReturn::Stopped,
            3=>PumpReturn::TimedOut,4=>PumpReturn::HandledSource,_=>PumpReturn::Unavailable};
        if !actual || !valid || result==PumpReturn::Unavailable{
            registry.global_failure_at(returned);self.phase=BookPhase::Unknown;return PumpReturn::Unavailable;
        }
        self.pool_generation=next;result
    }
    fn close_listener(&mut self){
        if self.phase!=BookPhase::Begun{return;}
        let (Some(pointer),Some(registry))=(self.pointer,self.registry.as_ref())else{return;};
        if !registry.listener_closed_known(){return;}
        let Some(next)=self.pool_generation.checked_add(1)else{registry.global_failure();self.phase=BookPhase::Unknown;return;};
        let Some(ticket)=registry.native_enter(MAIN_LANE,OP_CLOSE_LISTENER,uptime().unwrap_or(0))else{return;};
        self.phase=BookPhase::Unknown;
        let mut report=NativeReport::default();
        unsafe{mrk_android_service_close_listener(pointer.as_ptr(),&mut report);}
        let returned=uptime().unwrap_or(0);
        let actual=registry.native_actual_return(MAIN_LANE,ticket,OP_CLOSE_LISTENER,returned);
        if !actual || !report.main(OP_CLOSE_LISTENER,CLOSE_LISTENER_MASK,next,[6,4,4],2){
            registry.global_failure_at(returned);return;
        }
        self.pool_generation=next;self.phase=BookPhase::ListenerClosed;
    }
    fn close_main_references(&mut self){
        if self.phase!=BookPhase::ListenerClosed{return;}
        let (Some(pointer),Some(registry))=(self.pointer,self.registry.as_ref())else{return;};
        let Some(next)=self.pool_generation.checked_add(1)else{registry.global_failure();self.phase=BookPhase::Unknown;return;};
        #[cfg(not(feature="e2-native-fixture"))]
        let Some(ticket)=registry.native_enter(MAIN_LANE,OP_CLOSE_MAIN,uptime().unwrap_or(0))else{return;};
        #[cfg(feature="e2-native-fixture")]
        let Some(mut admission)=registry.fixture_native_enter(MAIN_LANE,OP_CLOSE_MAIN,uptime().unwrap_or(0))else{return;};
        #[cfg(feature="e2-native-fixture")]
        let ticket=admission.ticket;
        self.phase=BookPhase::Unknown;
        let mut report=NativeReport::default();
        #[cfg(not(feature="e2-native-fixture"))]
        unsafe{mrk_android_service_close_main_references(pointer.as_ptr(),&mut report);}
        #[cfg(feature="e2-native-fixture")]
        unsafe{mrk_android_e2_fixture_service_close_main_references(pointer.as_ptr(),&admission.api(),&mut report);}
        let returned=uptime().unwrap_or(0);
        let actual=registry.native_actual_return(MAIN_LANE,ticket,OP_CLOSE_MAIN,returned);
        #[cfg(feature="e2-native-fixture")]
        let actual=admission.finish(returned,actual);
        if !actual || !report.main(OP_CLOSE_MAIN,CLOSE_MAIN_MASK,next,[6,6,6],2) || !registry.main_closed_returned(){
            registry.global_failure_at(returned);return;
        }
        self.pool_generation=next;self.phase=BookPhase::MainClosed;
    }
    pub fn ready_to_join(&self)->Option<bool>{
        if self.phase!=BookPhase::MainClosed || self.joined{return Some(false);}
        let Some(registry)=self.registry.as_ref()else{return Some(false);};
        if registry.unknown.load(Ordering::SeqCst){return Some(false);}
        match registry.slots.try_lock(){
            Ok(slots)=>Some(slots.control_retired),Err(TryLockError::WouldBlock)=>None,
            Err(TryLockError::Poisoned(_))=>{registry.publish_failure(uptime().unwrap_or(0));Some(false)}
        }
    }
    pub fn join_original_supervisor(&mut self,handle:JoinHandle<SupervisorReturn>)->Option<JoinHandle<SupervisorReturn>>{
        if self.phase!=BookPhase::MainClosed || self.joined{
            std::mem::forget(handle);self.retain_unknown();return None;
        }
        let (Some(pointer),Some(registry))=(self.pointer,self.registry.as_ref())else{
            std::mem::forget(handle);self.retain_unknown();return None;
        };
        let Some(ticket)=registry.native_enter(JOIN_LANE,OP_JOIN,uptime().unwrap_or(0))else{
            if !registry.unknown.load(Ordering::SeqCst){return Some(handle);} // same unentered original, no detach
            std::mem::forget(handle);self.phase=BookPhase::Unknown;return None;
        };
        // This consumes the EXACT retained handle. is_finished is never a join
        // receipt and cannot cover TLS destructors; actual join must return.
        let original=handle.join();
        let returned=uptime().unwrap_or(0);
        let actual=registry.native_actual_return(JOIN_LANE,ticket,OP_JOIN,returned);
        let end=match original{Ok(end)=>end,Err(_)=>{
            registry.global_failure_at(returned);self.phase=BookPhase::Unknown;return None;
        }};
        if !actual || end.address!=pointer.as_ptr() as usize || !Arc::ptr_eq(registry,&end.registry)
            || !registry.supervisor_joined(){
            std::mem::forget(end);registry.global_failure_at(returned);self.phase=BookPhase::Unknown;return None;
        }
        // The owning return's last temporary Registry strong loan actually ends
        // here, before any final same-allocation try_unwrap.
        drop(ManuallyDrop::into_inner(end.registry));self.joined=true;None
    }
    fn consume_book(&mut self){
        if self.phase!=BookPhase::MainClosed || !self.joined{return;}
        let Some(registry)=self.registry.as_ref()else{return;};
        let Some(ticket)=registry.native_enter(MAIN_LANE,OP_CONSUME_BOOK,uptime().unwrap_or(0))else{return;};
        let Some(pointer)=self.pointer.take()else{registry.global_failure();self.phase=BookPhase::Unknown;return;};
        self.consumed_address=pointer.as_ptr() as usize;self.phase=BookPhase::Unknown;
        let mut original=pointer.as_ptr();let mut report=NativeReport::default();
        unsafe{mrk_android_service_consume_book(&mut original,&mut report);}
        let returned=uptime().unwrap_or(0);
        // The stored pointer was removed BEFORE the sole consuming attempt.
        // Even a malformed report/clock cannot cause a freed-original probe,
        // retry, replacement book, or pointer reintroduction after this return.
        let actual=registry.native_actual_return(MAIN_LANE,ticket,OP_CONSUME_BOOK,returned);
        if !actual || !original.is_null() || !report.header(OP_CONSUME_BOOK,FREE_MASK)
            || report.slots!=[6,6,6] || report.listener_close!=2 || report.control_state!=2
            || report.consumed!=1 || report.run_result!=0 || report.pool_generation!=self.pool_generation
            || !registry.book_consumed(){
            registry.global_failure_at(returned);return;
        }
        self.phase=BookPhase::Consumed;
    }
    pub fn advance_teardown(&mut self){
        if let Some(registry)=self.registry.as_ref(){registry.watch_maintenance();}
        self.close_listener();self.close_main_references();self.consume_book();
    }
    pub fn has_consumed_book(&self)->bool{self.phase==BookPhase::Consumed}
    pub fn try_return(mut self)->Result<ResidentReturn,Self>{
        if self.phase!=BookPhase::Consumed || self.pointer.is_some() || !self.joined || self.consumed_address==0{return Err(self);}
        let Some(original)=self.registry.take()else{return Err(self);};
        let unwrapped=Arc::try_unwrap(ManuallyDrop::into_inner(original));
        let unwrapped_at=uptime().unwrap_or(0);
        match unwrapped{
            Err(same)=>{
                self.registry=Some(ManuallyDrop::new(same));Err(self)
            }
            Ok(registry)=>{
                let consumed=registry.into_reclaimed(unwrapped_at);
                let returned_at=uptime().unwrap_or(0); // AFTER actual Registry DATA consumption/return
                match consumed{
                    Ok(reclaimed) if reclaimed.return_is_timely(returned_at)=>
                        Ok(ResidentReturn(ProductQuiesced{binding:reclaimed.binding,protocol:reclaimed.protocol,
                            window:reclaimed.window,last:reclaimed.last,returned_at})),
                    Ok(reclaimed)=>{
                        self.reclaimed_unknown=Some(reclaimed);self.phase=BookPhase::Unknown;Err(self)
                    }
                    Err(exclusive)=>{
                        // No new Registry allocation on failed final reconciliation.
                        self.exclusive_unknown=Some(ManuallyDrop::new(exclusive));self.phase=BookPhase::Unknown;Err(self)
                    }
                }
            }
        }
    }
}
impl ServiceControl{
    pub fn bind(&mut self)->Option<bool>{
        if self.bind_entered{return Some(false);}
        let Some(ticket)=self.registry.native_enter(CONTROL_LANE,OP_BIND,uptime().unwrap_or(0))else{
            return if self.registry.unknown.load(Ordering::SeqCst){Some(false)}else{None};
        };
        self.bind_entered=true;
        let mut report=NativeReport::default();
        unsafe{mrk_android_service_bind_control(self.pointer.as_ptr(),&mut report);}
        let returned=uptime().unwrap_or(0);
        let actual=self.registry.native_actual_return(CONTROL_LANE,ticket,OP_BIND,returned);
        self.bound=actual && report.control(OP_BIND,1);
        if !self.bound{self.registry.global_failure_at(returned);}
        Some(self.bound)
    }
    pub fn retire(&mut self,domain:&Arc<ServiceDomain>){
        if !self.bound || !domain.route_retiring() || domain.native_return()!=NativeReturn::NotStarted{return;}
        // The same control thread is the only sender endpoint close owner.
        // This narrow precondition precedes, but never reverses, R3 retirement.
        if domain.tail_ready()==0{return;}
        let Some(ticket)=self.registry.native_enter(CONTROL_LANE,OP_TAIL_PROGRESS,uptime().unwrap_or(0))else{return;};
        let progressed=unsafe{mrk_android_service_tail_progress(self.pointer.as_ptr(),domain.slot as u32,domain.number,Arc::as_ptr(domain).cast())};
        let returned=uptime().unwrap_or(0);
        if !self.registry.native_actual_return(CONTROL_LANE,ticket,OP_TAIL_PROGRESS,returned) || !matches!(progressed,0|1){
            domain.failure_at(returned,true);self.registry.global_failure_at(returned);return;
        }
        if progressed==0{return;}
        let Some(ticket)=self.registry.native_enter(CONTROL_LANE,OP_CONTEXT_READY,uptime().unwrap_or(0))else{return;};
        let ready=unsafe{mrk_android_service_context_ready(self.pointer.as_ptr(),domain.slot as u32,domain.number)};
        let returned=uptime().unwrap_or(0);
        let actual=self.registry.native_actual_return(CONTROL_LANE,ticket,OP_CONTEXT_READY,returned);
        if !actual || !matches!(ready,0|1){domain.failure_at(returned,true);self.registry.global_failure_at(returned);return;}
        if ready==0{return;}
        let entered=uptime().unwrap_or(0);
        let Some(ticket)=self.registry.native_domain_close_enter(domain,entered)else{return;};
        // Retire native context references BEFORE waiting for worker/coordinator,
        // backing, or DATA exclusivity, as in the accepted resident predecessor.
        let result=unsafe{mrk_android_service_close_context(self.pointer.as_ptr(),domain.slot as u32,domain.number,Arc::as_ptr(domain).cast())};
        let returned=uptime().unwrap_or(0);
        let actual=self.registry.native_actual_return(CONTROL_LANE,ticket,OP_CLOSE_CONTEXT,returned);
        domain.native_returned(returned,actual && result==1);
        if result!=1{self.registry.global_failure_at(returned);}
    }
    pub fn reclaim(&mut self,index:usize,number:u64){
        if !self.bound || self.pending_reclaim.is_some(){return;}
        let Some(domain)=self.registry.take_for_reclaim(index,number)else{return;};
        if !domain.reclaim_prerequisites(){self.registry.restore(index,number,domain);return;}
        match Arc::try_unwrap(domain){
            Err(domain)=>self.registry.restore(index,number,domain),
            Ok(domain)=>{
                let Some(window)=domain.final_known()else{self.registry.finish_reclaim(index,number,false);return;};
                // Retain ONE scalar in this original control while the existing
                // Reclaiming cell awaits its bounded native reset. No replacement
                // Domain/Registry Arc, ninth context, or independent deadline.
                self.pending_reclaim=Some(PendingReclaim{index,number,window,transferred:false});
                self.progress_reclaim();
            }
        }
    }
    pub fn progress_reclaim(&mut self){
        let Some(pending)=self.pending_reclaim.as_mut()else{return;};
        if self.registry.unknown.load(Ordering::SeqCst){return;}
        if !pending.transferred{
            match self.registry.caller_final_after_unwrap(pending.index,pending.number,pending.window){
                Some(true)=>pending.transferred=true,None=>return,
                Some(false)=>{self.registry.finish_reclaim(pending.index,pending.number,false);return;}
            }
        }
        let entered=uptime().unwrap_or(0);
        if !pending.window.admits(entered,true){
            self.registry.global_failure_at(entered);self.registry.finish_reclaim(pending.index,pending.number,false);return;
        }
        let Some(ticket)=self.registry.native_enter(CONTROL_LANE,OP_RECLAIM_CONTEXT,entered)else{return;};
        let result=unsafe{mrk_android_service_reclaim_context(self.pointer.as_ptr(),pending.index as u32,pending.number)};
        let returned=uptime().unwrap_or(0);
        let actual=self.registry.native_actual_return(CONTROL_LANE,ticket,OP_RECLAIM_CONTEXT,returned);
        let known=actual && result==1 && returned>=entered && pending.window.admits(returned,true);
        self.registry.finish_reclaim(pending.index,pending.number,known);
        if !known{self.registry.global_failure_at(returned);return;}
        self.pending_reclaim=None;
    }
    pub fn retire_original(self)->Result<SupervisorReturn,Self>{
        if !self.bound || self.pending_reclaim.is_some() || !self.registry.control_ready_to_return(){return Err(self);}
        let Some(ticket)=self.registry.native_enter(CONTROL_LANE,OP_RETIRE_CONTROL,uptime().unwrap_or(0))else{return Err(self);};
        let mut report=NativeReport::default();
        unsafe{mrk_android_service_retire_control(self.pointer.as_ptr(),&mut report);}
        let returned=uptime().unwrap_or(0);
        let actual=self.registry.native_actual_return(CONTROL_LANE,ticket,OP_RETIRE_CONTROL,returned);
        if !actual || !report.control(OP_RETIRE_CONTROL,2) || !self.registry.control_returned(){
            self.registry.global_failure_at(returned);return Err(self);
        }
        // No book free: the actual original supervisor still has to return,
        // including its final DATA drops, and its original join must return.
        Ok(SupervisorReturn{address:self.pointer.as_ptr() as usize,registry:self.registry})
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    /// DATA fixture only; not a native-return receipt or runnable native test.
    fn local_control_data(domain:&ServiceDomain,start:u64,end:u64){
        let mut ledger=domain.ledger.lock().unwrap();
        ledger.native_enter=Some(start);ledger.native_return=Some(end);
        domain.native.store(2,Ordering::SeqCst);
    }
    #[test]
    fn call_summary_failure_reaches_both_original_payloads_before_polling(){
        let domain=ServiceDomain::new(0,1,501,100,Arc::new(PayloadReservation::new()),Weak::new()).unwrap();
        let ticket=domain.entered_call(0,false,101);assert_ne!(ticket,0);
        assert!(!domain.returned_call(0,ticket,102,false));
        assert_eq!(domain.control_data().first,Some(102));
        assert_eq!(domain.registration.signal().first(),Some(102));
        assert_eq!(domain.query.signal().first(),Some(102));
        assert!(domain.registration.signal().unknown() && domain.query.signal().snapshot().unknown);
        domain.window.failure_at(101,false);domain.relay_control();
        assert_eq!(domain.registration.signal().first(),Some(101));
        assert_eq!(domain.query.signal().first(),Some(101));
    }
    #[test]
    fn call_clock_loss_is_absorbing_without_an_invented_first_sample(){
        let domain=ServiceDomain::new(0,1,501,100,Arc::new(PayloadReservation::new()),Weak::new()).unwrap();
        assert_eq!(domain.entered_call(0,false,0),0);
        assert!(domain.control_data().clock_unknown);
        assert_eq!(domain.registration.signal().first(),None);
        assert_eq!(domain.query.signal().first(),None);
        assert!(domain.registration.signal().unknown() && domain.query.signal().snapshot().unknown);
        domain.relay_control();
        assert_eq!(domain.registration.signal().snapshot().cleanup,None);
        assert_eq!(domain.query.signal().snapshot().cleanup,None);
    }
    #[test]
    fn still_open_provisional_context_is_not_settled_never_created(){
        let domain=ServiceDomain::new(0,1,501,100,Arc::new(PayloadReservation::new()),Weak::new()).unwrap();
        assert!(!domain.no_payload_created());
        assert!(!domain.release_payload_if_settled());
        domain.retire_at(101);
        assert!(domain.no_payload_created());
        domain.payload_settled(true);assert!(domain.release_payload_if_settled());
        assert!(domain.release_payload_if_settled()); // idempotent same local reservation
    }
    #[test]
    fn closed_registry_never_reserves_or_reopens(){
        for opened in [false,true]{
            let registry=ServiceRegistry::new(0).unwrap();
            if opened{assert!(registry.open_admission_once());}
            assert!(registry.close_admission());
            for _ in 0..2{
                assert!(!registry.open_admission_once());
                assert!(registry.reserve(501,100).is_none());
                assert!(registry.close_admission());
            }
            assert!(!registry.accepting.load(Ordering::SeqCst));
            assert!(!registry.unknown.load(Ordering::SeqCst));
            assert!(registry.empty_known()); // momentary DATA emptiness only
        }
    }
    #[test]
    fn reserve_before_close_preserves_same_original_slot(){
        let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
        let original=registry.reserve(501,100).unwrap();
        let slot=original.slot();let number=original.number();let nonce=original.nonce;
        assert!(registry.close_admission());
        assert!(registry.reserve(501,100).is_none());assert!(!registry.open_admission_once());
        let retained=registry.context(slot).unwrap();
        assert!(Arc::ptr_eq(&original,&retained));assert_eq!(retained.number(),number);assert_eq!(retained.nonce,nonce);
        assert!(!registry.empty_known());assert!(!registry.unknown.load(Ordering::SeqCst));
    }
    #[test]
    fn contended_close_is_unknown_and_keeps_original_cells(){
        for with_original in [false,true]{
            let registry=ServiceRegistry::new(0).unwrap();
            let original=if with_original{
                assert!(registry.open_admission_once());Some(registry.reserve(501,100).unwrap())
            }else{None};
            let held=registry.slots.try_lock().unwrap();
            assert!(!registry.close_admission());
            assert!(registry.unknown.load(Ordering::SeqCst));assert!(!registry.accepting.load(Ordering::SeqCst));
            let expected=if with_original{Admission::Open}else{Admission::Reserved};assert!(held.admission==expected);
            for (index,cell) in held.cells.iter().enumerate(){
                match original.as_ref(){
                    Some(domain) if index==domain.slot()=>{
                        assert!(matches!(cell,Cell::Live(same) if Arc::ptr_eq(same,domain) && same.number()==domain.number()));
                    }
                    _=>assert!(matches!(cell,Cell::Empty)),
                }
            }
            drop(held);
            assert!(!registry.empty_known());assert!(!registry.open_admission_once());assert!(registry.reserve(501,100).is_none());
            // A later serialized close cannot clear the already absorbing Unknown.
            assert!(registry.close_admission());assert!(registry.unknown.load(Ordering::SeqCst));
            assert!(!registry.empty_known());assert!(!registry.open_admission_once());assert!(registry.reserve(501,100).is_none());
            if let Some(original)=original{
                let retained=registry.context(original.slot()).unwrap();assert!(Arc::ptr_eq(&original,&retained));
                assert_eq!(original.number(),retained.number());
            }
        }
    }
    #[test]
    fn stale_accepting_hint_cannot_bypass_closed_registry(){
        let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
        assert!(registry.close_admission());assert!(!registry.unknown.load(Ordering::SeqCst));
        registry.accepting.store(true,Ordering::SeqCst); // deliberately stale fixture hint
        assert!(registry.reserve(501,100).is_none());assert!(!registry.open_admission_once());
        assert!(registry.accepting.load(Ordering::SeqCst));assert!(!registry.unknown.load(Ordering::SeqCst));
        assert!(registry.slots.try_lock().unwrap().admission==Admission::Closed);
    }
    #[test]
    fn data_slot_limit_is_live_and_fresh_counter_can_exceed_eight(){
        let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
        for number in 1..=24{
            let domain=registry.reserve(501,100).unwrap();
            assert_eq!(domain.number(),number);assert_eq!(domain.nonce,prepare::nonce_for_counter(number).unwrap());
            domain.retire_at(101);local_control_data(&domain,102,103);
            let original=registry.take_for_reclaim(domain.slot(),number).unwrap();
            let slot=domain.slot();drop(domain);
            let data=match Arc::try_unwrap(original){Ok(data)=>data,Err(_)=>panic!("fixture has only registry DATA")};
            assert!(data.final_known().is_some());registry.finish_reclaim(slot,number,true);
        }
        let mut retained=Vec::new();
        for _ in 0..control::LIVE_CONTEXTS{retained.push(registry.reserve(501,100).unwrap());}
        assert!(registry.reserve(501,100).is_none());
        assert_eq!(retained.first().unwrap().number(),25);
    }
    #[test]
    fn last_data_holder_cannot_race_the_final_control_reconciliation(){
        let domain=Arc::new(ServiceDomain::new(0,1,501,100,Arc::new(PayloadReservation::new()),Weak::new()).unwrap());
        domain.retire_at(100+prepare::CLEANUP_NS);
        local_control_data(&domain,101,100+11_000_000_000);
        let callback=domain.clone();
        let original=match Arc::try_unwrap(domain){Err(same)=>same,Ok(_)=>panic!("retained original must block exclusivity")};
        assert!(Arc::ptr_eq(&original,&callback));
        callback.failure_at(102,false);drop(callback);
        let exclusive=match Arc::try_unwrap(original){Ok(data)=>data,Err(_)=>panic!("last DATA holder was dropped")};
        assert!(exclusive.final_known().is_none()); // earlier CF invalidates actual original return
    }
    #[test]
    fn unknown_spawn_and_late_join_do_not_equal_never_created(){
        let window=ControlWindow::new(100).unwrap();window.retire_at(101);
        let mut join=JoinObservation::reserved();join.spawn=1;join.spawn_entered=Some(102);
        assert!(!join.ended() && !join.valid_with(window.snapshot()));
        join.spawn=4;join.spawn_returned=Some(103);
        assert!(join.ended() && join.valid_with(window.snapshot()));
        join.spawn=3;join.known=true;join.entered=Some(104);
        join.returned=Some(101+prepare::CLEANUP_NS);
        assert!(!join.valid_with(window.snapshot()));
    }
    #[test]
    fn listener_body_busy_keeps_both_gates_and_closed_late_loan_never_enters(){
        let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
        let caller=registry.reserve(501,100).unwrap();let binding=caller.maintenance_binding();
        let loan=registry.loan_enter(101);assert_ne!(loan,0);
        assert_eq!(registry.begin_maintenance_at(&caller,binding,102),MaintenanceAdmission::Busy);
        {let slots=registry.slots.lock().unwrap();assert!(slots.admission==Admission::Open);
            assert!(!slots.loan.closed);assert!(slots.maintenance.is_none());}
        assert!(registry.accepting.load(Ordering::SeqCst));assert_eq!(caller.control_data().retirement,None);
        assert!(registry.loan_return(loan,103,true));
        assert_eq!(registry.begin_maintenance_at(&caller,binding,104),MaintenanceAdmission::Started);
        assert!(registry.listener_closed_known());assert_eq!(registry.loan_enter(105),0);
        assert!(registry.reserve(501,105).is_none());assert_eq!(caller.control_data().retirement,Some(104));
        assert!(!registry.control_ready_to_return()); // closure != native completion
    }
    #[test]
    fn foreign_and_unidentifiable_cells_cannot_be_stopped_to_make_drain_succeed(){
        for state in 0..3{
            let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
            let caller=registry.reserve(501,100).unwrap();let foreign=registry.reserve(502,100).unwrap();
            if state!=0{registry.slots.lock().unwrap().cells[foreign.slot()]=
                if state==1{Cell::Reclaiming(foreign.number())}else{Cell::Tombstone};}
            assert_eq!(registry.begin_maintenance_at(&caller,caller.maintenance_binding(),101),MaintenanceAdmission::Busy);
            let slots=registry.slots.lock().unwrap();assert!(slots.admission==Admission::Open);
            assert!(!slots.loan.closed);assert!(slots.maintenance.is_none());
            assert_eq!(caller.control_data().retirement,None);assert_eq!(foreign.control_data().retirement,None);
            assert!(registry.accepting.load(Ordering::SeqCst));assert!(!registry.unknown.load(Ordering::SeqCst));
        }
    }
    #[test]
    fn listener_mismatched_return_is_absorbing_unknown_not_later_known_idle(){
        let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
        let caller=registry.reserve(501,100).unwrap();let loan=registry.loan_enter(101);
        assert!(!registry.loan_return(loan+1,102,true));
        assert!(!registry.loan_return(loan,103,true));assert_eq!(registry.loan_enter(104),0);
        assert_eq!(registry.begin_maintenance_at(&caller,caller.maintenance_binding(),104),MaintenanceAdmission::Unknown);
        assert!(!registry.listener_closed_known());assert!(registry.unknown.load(Ordering::SeqCst));
        assert!(Arc::ptr_eq(&caller,&registry.context(caller.slot()).unwrap()));
    }
    #[test]
    fn maintenance_cut_serializes_fixed_go_ready_and_all_setup_admissions(){
        for cut_first in [true,false]{
            let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
            let caller=registry.reserve(501,100).unwrap();
            let role=prepare::Role::Registration;
            let request=prepare::Request{bounds:prepare::Bounds{role,origin:100,work:100+role.work_ns(),hard:100+role.hard_ns()}};
            assert!(caller.prepared_reply(request,101).is_some());
            // DATA fixture only. These scalar setup facts cannot manufacture a
            // ServiceControl/SupervisorReturn, original native call, or join.
            caller.prepare.lock().unwrap().taken=true;
            {let mut ledger=caller.ledger.lock().unwrap();ledger.worker.spawn=2;ledger.coordinator.spawn=2;}
            let barrier=AtomicU8::new(0);
            if cut_first{
                assert_eq!(registry.begin_maintenance_at(&caller,caller.maintenance_binding(),102),MaintenanceAdmission::Started);
                assert!(!caller.publish_go_and_ready_at(&barrier,103));assert_eq!(barrier.load(Ordering::SeqCst),0);
            }else{
                assert!(caller.publish_go_and_ready_at(&barrier,102));assert_eq!(barrier.load(Ordering::SeqCst),1);
                assert_eq!(registry.begin_maintenance_at(&caller,caller.maintenance_binding(),103),MaintenanceAdmission::Started);
            }
            assert!(caller.take_setup().is_none());assert!(!caller.spawn_entered(false));
            assert!(caller.prepared_reply(request,104).is_none());assert!(!caller.work_admitted_at(104));
            assert!(!caller.publish_go_and_ready_at(&AtomicU8::new(0),104));
        }
    }
    #[test]
    fn caller_final_window_moves_only_after_actual_same_domain_unwrap(){
        let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
        let caller=registry.reserve(501,100).unwrap();let slot=caller.slot();let number=caller.number();
        assert_eq!(registry.begin_maintenance_at(&caller,caller.maintenance_binding(),101),MaintenanceAdmission::Started);
        local_control_data(&caller,102,103);
        let callback=caller.clone();drop(caller);
        let original=registry.take_for_reclaim(slot,number).unwrap();
        let original=match Arc::try_unwrap(original){Err(same)=>same,Ok(_)=>panic!("callback still holds exact DATA")};
        assert!(registry.slots.lock().unwrap().maintenance.as_ref().unwrap().final_window.is_none());
        callback.failure_at(102,false);drop(callback);
        let domain=match Arc::try_unwrap(original){Ok(domain)=>domain,Err(_)=>panic!("fixture callback has actually ended")};
        let window=domain.final_known().unwrap();assert_eq!(window.first,Some(102));
        assert_eq!(registry.caller_final_after_unwrap(slot,number,window),Some(true));
        assert_eq!(registry.slots.lock().unwrap().maintenance.as_ref().unwrap().final_window,Some(window));
        // Still Reclaiming: this DATA test has not run/reclaimed any native book.
        assert!(!registry.empty_known());assert!(!registry.control_ready_to_return());
    }
    #[test]
    fn report_bits_and_partial_startup_cannot_construct_product_quiescence(){
        let window=ControlWindow::new(100).unwrap();window.retire_at(101);
        let mut calls=LifetimeCalls::new();let ticket=calls.enter(OP_PUMP,102).unwrap();
        let report=NativeReport{version:1,operation:OP_PUMP,known:1,selectors_entered:PUMP_MASK,
            selectors_returned:PUMP_MASK,..NativeReport::default()};
        assert!(report.header(OP_PUMP,PUMP_MASK));assert!(!calls.known_with(window.snapshot()));
        assert!(calls.actual_return(ticket,OP_PUMP,103));assert!(calls.known_with(window.snapshot()));
        window.failure_at(100,true);assert!(!window.snapshot().admits(104,false));
        for closed in [false,true]{
            let registry=ServiceRegistry::new(0).unwrap();
            if closed{assert!(registry.close_admission());}
            let exclusive=match Arc::try_unwrap(registry){Ok(value)=>value,Err(_)=>panic!("only fixture owner")};
            assert!(exclusive.into_reclaimed(102).is_err()); // no caller, C returns, or original join
        }
    }

    #[test]
    fn timely_native_prefix_does_not_authorize_late_final_registry_reclamation(){
        let window=ControlWindow::new(100).unwrap();window.retire_at(101);
        let mut calls=LifetimeCalls::new();let ticket=calls.enter(OP_CONSUME_BOOK,102).unwrap();
        assert!(calls.actual_return(ticket,OP_CONSUME_BOOK,103));assert!(calls.known_with(window.snapshot()));
        let cutoff=window.snapshot().cutoff().unwrap();
        // Scalar boundary fixture only: cannot construct SupervisorReturn or
        // execute ServiceBook's actual join/consume/try_unwrap path.
        let data=ReclaimedRegistry{binding:MaintenanceBinding{slot:0,number:1,account:501,nonce:[1;16]},
            window:window.snapshot(),last:103,unwrapped_at:104};
        assert!(data.return_is_timely(104));assert!(data.return_is_timely(cutoff-1));
        for at in [0,103,cutoff,cutoff+1]{assert!(!data.return_is_timely(at));}
        let late=ReclaimedRegistry{unwrapped_at:cutoff,..data};
        assert!(!late.return_is_timely(cutoff-1));assert!(!late.return_is_timely(cutoff));
        let unknown=ReclaimedRegistry{window:WindowData{unknown:true,..late.window},..late};
        assert!(!unknown.return_is_timely(cutoff-1));
        for unwrapped_at in [0,102,cutoff,cutoff+1]{
            let registry=ServiceRegistry::new(0).unwrap();
            {
                // Deliberately synthetic Registry DATA prerequisites, never a
                // native report, SupervisorReturn, join or ProductQuiesced.
                // All non-clock predicates are satisfied so this checks the
                // REAL consuming method's first final-time gate itself.
                let mut slots=registry.slots.lock().unwrap();
                slots.admission=Admission::Closed;slots.loan.closed=true;
                slots.maintenance=Some(Maintenance{binding:data.binding,cut:101,final_window:Some(window.snapshot())});
                slots.main_closed=true;slots.control_retired=true;
                slots.supervisor_joined=true;slots.book_consumed=true;
                let ticket=slots.calls[MAIN_LANE].enter(OP_CONSUME_BOOK,102).unwrap();
                assert!(slots.calls[MAIN_LANE].actual_return(ticket,OP_CONSUME_BOOK,103));
                assert!(slots.loan.idle_known() && slots.cells.iter().all(|cell|matches!(cell,Cell::Empty)));
                assert!(slots.calls.iter().all(|call|call.known_with(window.snapshot())));
            }
            let exclusive=match Arc::try_unwrap(registry){Ok(value)=>value,Err(_)=>panic!("sole synthetic Registry owner")};
            let retained=match exclusive.into_reclaimed(unwrapped_at){
                Err(same)=>same,Ok(_)=>panic!("late/lost/regressing final Registry time must retain DATA"),
            };
            assert!(!retained.unknown.load(Ordering::SeqCst));
            assert_eq!(retained.slots.lock().unwrap().calls[MAIN_LANE].last,103);
        }
    }

    #[test]
    fn native_no_entry_contention_defers_but_return_contention_stays_unknown(){
        let registry=ServiceRegistry::new(0).unwrap();
        {
            let held=registry.slots.lock().unwrap();
            assert!(registry.begin_call_enter(100).is_none());assert!(held.admission==Admission::Reserved);
            assert_eq!(held.calls[MAIN_LANE].entered,0);assert!(!held.loan.closed);
            assert!(!registry.accepting.load(Ordering::SeqCst));assert!(!registry.unknown.load(Ordering::SeqCst));
        }
        // DATA ledger fixture only: no native begin/pump is invoked here.
        let begun=registry.begin_call_enter(101).unwrap();
        assert!(registry.native_actual_return(MAIN_LANE,begun,OP_BEGIN,102));
        {
            let held=registry.slots.lock().unwrap();
            assert!(registry.native_enter(MAIN_LANE,OP_PUMP,103).is_none());
            assert_eq!(held.calls[MAIN_LANE].entered,1);assert!(held.admission==Admission::Open);
            assert!(registry.accepting.load(Ordering::SeqCst));assert!(!registry.unknown.load(Ordering::SeqCst));
        }
        let entered=registry.native_enter(MAIN_LANE,OP_PUMP,103).unwrap();
        let held=registry.slots.lock().unwrap();
        assert!(!registry.native_actual_return(MAIN_LANE,entered,OP_PUMP,104));
        assert!(registry.unknown.load(Ordering::SeqCst));assert!(!registry.accepting.load(Ordering::SeqCst));
        assert!(held.calls[MAIN_LANE].pending.is_some()); // no fictional recorded return
        drop(held);
        for operation in [OP_CLOSE_LISTENER,OP_CLOSE_MAIN,OP_RETIRE_CONTROL,OP_CONSUME_BOOK]{
            let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
            let caller=registry.reserve(501,100).unwrap();
            assert_eq!(registry.begin_maintenance_at(&caller,caller.maintenance_binding(),101),MaintenanceAdmission::Started);
            let lane=if operation==OP_RETIRE_CONTROL{CONTROL_LANE}else{MAIN_LANE};
            {
                let held=registry.slots.lock().unwrap();
                assert!(registry.native_enter(lane,operation,102).is_none());
                assert_eq!(held.calls[lane].entered,0);assert!(held.admission==Admission::Closed);
                assert!(held.loan.closed && held.loan.idle_known());assert!(!registry.unknown.load(Ordering::SeqCst));
            }
            let ticket=registry.native_enter(lane,operation,103).unwrap();
            {
                let held=registry.slots.lock().unwrap();
                assert!(held.admission==Admission::Closed && held.loan.closed && held.loan.idle_known());
                // This pre-entry convenience poll cannot distinguish contention.
                // The entered C teardown therefore MUST NOT call it again.
                assert!(!registry.listener_closed_known());assert_eq!(registry.loan_enter(104),0);
                assert_eq!(held.calls[lane].pending,Some((ticket,operation)));
                assert!(!registry.unknown.load(Ordering::SeqCst));
            }
            // DATA ledger fixture only: no C selector/return or finality receipt.
            assert!(registry.native_actual_return(lane,ticket,operation,105));
            assert!(!registry.unknown.load(Ordering::SeqCst));
        }
    }

}

#[cfg(all(test,feature="e2-native-fixture"))]
mod fixture_identity_admission_tests {
    use super::*;
    #[test]
    fn fixture_entered_checkpoint_never_relocks_registry_slots() {
        let registry=ServiceRegistry::new(0).unwrap();
        {
            let held=registry.slots.lock().unwrap();
            assert!(registry.fixture_native_enter(MAIN_LANE,OP_NEW,100).is_none());
            assert!(!registry.unknown.load(Ordering::SeqCst));
            assert_eq!(held.calls[MAIN_LANE].entered,0);
        }
        let mut entry=registry.fixture_native_enter(MAIN_LANE,OP_NEW,100).unwrap();
        assert!(entry.window.snapshot().is_none()); // no invented caller T/lease
        {
            let held=registry.slots.lock().unwrap();
            assert_eq!(entry.point(1,0,0,101,0),1);
            assert_eq!(entry.point(1,1,0,102,0),1);
            assert_eq!(held.calls[MAIN_LANE].pending,Some((entry.ticket,OP_NEW)));
            assert!(!registry.unknown.load(Ordering::SeqCst));
        }
        // DATA-only original-ticket test; no native operation or receipt exists.
        assert!(registry.native_actual_return(MAIN_LANE,entry.ticket,OP_NEW,103));
        assert!(entry.finish(103,true));
    }
    #[test]
    fn fixture_checkpoint_observes_fresh_same_domain_failure_cutoff() {
        let registry=ServiceRegistry::new(0).unwrap();assert!(registry.open_admission_once());
        let caller=registry.reserve(501,100).unwrap();
        assert_eq!(registry.begin_maintenance_at(&caller,caller.maintenance_binding(),101),MaintenanceAdmission::Started);
        let mut entry=registry.fixture_native_enter(MAIN_LANE,OP_CLOSE_MAIN,102).unwrap();
        let old=entry.window.snapshot().unwrap().cutoff().unwrap();
        {
            let held=registry.slots.lock().unwrap();
            assert_eq!(entry.point(9,0,1,103,0),1);
            assert_eq!(entry.point(9,1,1,104,0),1);
            caller.failure_at(100,false); // original earlier F, delayed DATA publication
            let current=entry.window.snapshot().unwrap();
            assert_eq!(current.first,Some(100));assert!(current.cutoff().unwrap()<old);
            assert_eq!(entry.point(11,0,1,current.cutoff().unwrap(),0),2);
            assert!(registry.unknown.load(Ordering::SeqCst));
            assert_eq!(held.calls[MAIN_LANE].pending,Some((entry.ticket,OP_CLOSE_MAIN)));
        }
        // Dispose only synthetic test DATA. Production retains this handle on
        // Unknown and does not manufacture an actual native return.
        drop(ManuallyDrop::into_inner(entry.window));
    }
}
