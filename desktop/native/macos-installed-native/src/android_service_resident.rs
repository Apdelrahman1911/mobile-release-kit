//! Resident fixed-service DATA and native control boundary. Native callbacks
//! never receive a publisher, filesystem book, descriptor, or worker handle.
use std::{cell::UnsafeCell, ffi::{c_int,c_void}, mem::ManuallyDrop, ptr::NonNull,
    sync::{Arc,Mutex,atomic::{AtomicBool,AtomicU8,Ordering}}};
use crate::{android_registration::{self as registration,Failure},
    android_catalog_query as query,android_service_prepare as prepare,
    android_service_control::{self as control,CallSummary,ControlWindow,Decision,FirstPrepare,NonceCounter,PayloadReservation,WindowData},
    android_service_lease::BackingLease,vault_helper_wire::uptime};

pub const SUPERVISOR_STACK:usize=1_048_576;
pub const PAYLOAD_STACK:usize=2_097_152;
pub const COORDINATOR_STACK:usize=1_048_576;
const NATIVE_FIXED_MAX:usize=16_384;
const CAPTURES_PER_CONTEXT:usize=512;
const LANES:usize=3; // accept, response, original native retirement
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
struct Preparation{first:FirstPrepare,taken:bool,setup_failed:bool}
struct Ledger{
    calls:[CallSummary;LANES],worker:JoinObservation,coordinator:JoinObservation,
    native_enter:Option<u64>,native_return:Option<u64>,payload_known:bool,reservation_released:bool,
}

/// Every possible native DATA borrower retains this same Arc. Window is NOT a
/// second independently retained Arc. No reverse DATA -> native object edge.
pub struct ServiceDomain{
    slot:usize,number:u64,account:u32,nonce:[u8;16],
    reservation:Arc<PayloadReservation>,registration:Arc<registration::Ingress>,query:Arc<query::Ingress>,
    window:ControlWindow,prepare:Mutex<Preparation>,ledger:Mutex<Ledger>,
    native:AtomicU8,reply:BackingLease,response:UnsafeCell<Box<[u8;query::REPLY_BYTES]>>,
}
// SAFETY: response is written only under the one exclusive reply lease. Native
// NSData keeps the same domain Arc and immutable backing until all lease facts.
// All other asynchronous fields are immutable, atomic or bounded DATA locks.
unsafe impl Sync for ServiceDomain{}
impl ServiceDomain{
    fn new(slot:usize,number:u64,account:u32,now:u64,reservation:Arc<PayloadReservation>)->Option<Self>{
        Some(Self{slot,number,account,nonce:prepare::nonce_for_counter(number)?,reservation,
            registration:Arc::new(registration::Ingress::new()),query:Arc::new(query::Ingress::new()),
            window:ControlWindow::new(now)?,prepare:Mutex::new(Preparation{first:FirstPrepare::new(),taken:false,setup_failed:false}),
            ledger:Mutex::new(Ledger{calls:std::array::from_fn(|_|CallSummary::new()),
                worker:JoinObservation::reserved(),coordinator:JoinObservation::reserved(),
                native_enter:None,native_return:None,payload_known:false,reservation_released:false}),
            native:AtomicU8::new(0),reply:BackingLease::reserved(),response:UnsafeCell::new(Box::new([0;query::REPLY_BYTES]))})
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
        if let Some(first)=window.retirement{
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
        self.window.watch(now);
        let mut state=match self.prepare.try_lock(){Ok(state)=>state,Err(_)=>{self.failure_at(now,true);return None;}};
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
    pub fn take_setup(&self)->Option<prepare::Bounds>{
        let mut state=self.prepare.try_lock().ok()?;
        if state.taken || state.setup_failed || state.first.phase()!=prepare::Phase::Pending{return None;}
        if !self.work_admitted(){
            state.setup_failed=true;state.first.unknown();self.failure_now(false);return None;
        }
        state.taken=true;state.first.request().map(|request|request.bounds)
    }
    pub fn work_admitted(&self)->bool{self.work_admitted_at(uptime().unwrap_or(0))}
    fn work_admitted_at(&self,now:u64)->bool{
        if !self.window.work_open(now){return false;}
        match self.role(){
            Some(ServiceRole::Registration)=>self.registration.signal().admitted_at(false,now),
            Some(ServiceRole::ReadOnlyQuery)=>self.query.signal().admitted_at(false,now),None=>false,
        }
    }
    /// Helper calls this only AFTER its one barrier successfully published GO.
    /// Both actual original handle creations must already have returned.
    pub fn ready_after_go(&self)->bool{
        let now=uptime().unwrap_or(0);
        if !self.work_admitted_at(now){return false;}
        let published=self.ledger.try_lock().is_ok_and(|ledger|ledger.worker.spawn==2 && ledger.coordinator.spawn==2);
        if !published{self.failure_at(now,true);return false;}
        match self.prepare.try_lock(){Ok(mut state) if state.taken && !state.setup_failed=>state.first.ready(),_=>false}
    }
    pub fn setup_failed(&self,unknown:bool){
        self.failure_now(unknown);
        if let Ok(mut state)=self.prepare.try_lock(){state.setup_failed=true;state.first.unknown();}
        else{self.failure_now(true);}
    }
    pub fn spawn_entered(&self,coordinator:bool)->bool{
        let now=uptime().unwrap_or(0);
        if !self.work_admitted_at(now){return false;}
        let Ok(mut ledger)=self.ledger.try_lock()else{self.failure_at(now,true);return false;};
        let target=if coordinator{&mut ledger.coordinator}else{&mut ledger.worker};
        if target.spawn!=0{self.failure_at(now,true);return false;}
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
        let no_owner=immutable_no_entry || state.setup_failed;
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
        (no_payload || ledger.payload_known) && ledger.worker.ended() && ledger.coordinator.ended()
    }
    fn final_known(self)->bool{
        // Caller has ACTUALLY unwrapped this exact domain Arc. There is no
        // callback producer able to race the final CF/R snapshot anymore.
        let window=self.window.into_final();
        let ledger=match self.ledger.into_inner(){Ok(ledger)=>ledger,Err(_)=>return false};
        let preparation=match self.prepare.into_inner(){Ok(state)=>state,Err(_)=>return false};
        let no_payload=!preparation.first.admitted() || preparation.setup_failed
            && matches!(ledger.worker.spawn,0|4);
        let payload=no_payload || ledger.payload_known;
        payload && self.native.load(Ordering::SeqCst)==2 && self.reply.idle_known()
            && window.cutoff().is_some() && !window.unknown
            && ledger.native_enter.is_some_and(|at|at>=window.acceptance)
            && ledger.native_return.is_some_and(|at|ledger.native_enter.is_some_and(|start|at>=start)
                && window.cutoff().is_some_and(|end|at<end))
            && ledger.worker.valid_with(window) && ledger.coordinator.valid_with(window)
            && ledger.calls.iter().all(|summary|summary.known_with(window))
    }
}

enum Cell{Empty,Live(Arc<ServiceDomain>),Reclaiming(u64),Tombstone}
pub struct ServiceRegistry{
    slots:Mutex<[Cell;control::LIVE_CONTEXTS]>,counter:NonceCounter,reservation:Arc<PayloadReservation>,
    accepting:AtomicBool,unknown:AtomicBool,fixed_bytes:usize,
}
fn arc_bytes<T>()->Option<usize>{
    // The recorded Rust Arc layout: two reference-count cells plus aligned T.
    #[repr(C)] struct Allocation<T>{counts:[usize;2],data:T}
    Some(std::mem::size_of::<Allocation<T>>())
}
impl ServiceRegistry{
    pub fn new(other_fixed:usize)->Option<Arc<Self>>{
        let per_context=arc_bytes::<ServiceDomain>()?
            .checked_add(registration::Ingress::service_high_water()?)?
            .checked_add(query::Ingress::service_high_water()?)?
            .checked_add(query::REPLY_BYTES)?.checked_add(CAPTURES_PER_CONTEXT)?;
        let fixed_bytes=arc_bytes::<Self>()?.checked_add(arc_bytes::<PayloadReservation>()?)?
            .checked_add(NATIVE_FIXED_MAX)?.checked_add(SUPERVISOR_STACK)?
            .checked_add(per_context.checked_mul(control::LIVE_CONTEXTS)?)?.checked_add(other_fixed)?;
        // Reserve both original stack capacities and the unchanged Publisher32MiB
        // (Query2MiB is smaller), never an extra64MiB per connection.
        let full=fixed_bytes.checked_add(PAYLOAD_STACK)?.checked_add(COORDINATOR_STACK)?
            .checked_add(32*1024*1024)?;
        if full>control::CONTROL_LIMIT{return None;}
        Some(Arc::new(Self{slots:Mutex::new(std::array::from_fn(|_|Cell::Empty)),counter:NonceCounter::new(),
            reservation:Arc::new(PayloadReservation::new()),accepting:AtomicBool::new(false),unknown:AtomicBool::new(false),fixed_bytes}))
    }
    pub fn payload_control_cap(&self,role:ServiceRole)->Option<usize>{
        let remainder=control::CONTROL_LIMIT.checked_sub(self.fixed_bytes)?
            .checked_sub(PAYLOAD_STACK)?.checked_sub(COORDINATOR_STACK)?;
        Some(remainder.min(if role==ServiceRole::Registration{32*1024*1024}else{2*1024*1024}))
    }
    pub fn close_admission(&self){self.accepting.store(false,Ordering::SeqCst);}
    pub fn empty_known(&self)->bool{
        !self.unknown.load(Ordering::SeqCst)
            && self.slots.try_lock().is_ok_and(|slots|slots.iter().all(|cell|matches!(cell,Cell::Empty)))
    }
    fn global_failure(&self){self.unknown.store(true,Ordering::SeqCst);self.close_admission();}
    fn reserve(&self,account:u32,now:u64)->Option<Arc<ServiceDomain>>{
        if account==0 || account==u32::MAX || !self.accepting.load(Ordering::SeqCst) || self.unknown.load(Ordering::SeqCst){return None;}
        let mut slots=self.slots.try_lock().ok()?;
        let index=slots.iter().position(|cell|matches!(cell,Cell::Empty))?;
        let Some((number,_))=self.counter.reserve()else{self.global_failure();return None;};
        let domain=Arc::new(ServiceDomain::new(index,number,account,now,self.reservation.clone())?);
        slots[index]=Cell::Live(domain.clone());Some(domain)
    }
    pub fn context(&self,index:usize)->Option<Arc<ServiceDomain>>{
        let slots=self.slots.try_lock().ok()?;
        match slots.get(index)?{Cell::Live(domain)=>Some(domain.clone()),_=>None}
    }
    fn take_for_reclaim(&self,index:usize,number:u64)->Option<Arc<ServiceDomain>>{
        let mut slots=self.slots.try_lock().ok()?;
        if !matches!(slots.get(index),Some(Cell::Live(domain)) if domain.number==number){return None;}
        match std::mem::replace(&mut slots[index],Cell::Reclaiming(number)){Cell::Live(domain)=>Some(domain),_=>None}
    }
    fn restore(&self,index:usize,number:u64,domain:Arc<ServiceDomain>){
        if let Ok(mut slots)=self.slots.try_lock(){
            if matches!(slots.get(index),Some(Cell::Reclaiming(held)) if *held==number){slots[index]=Cell::Live(domain);return;}
        }
        self.global_failure();std::mem::forget(domain); // retain lost DATA custody/charge
    }
    fn finish_reclaim(&self,index:usize,number:u64,known:bool){
        match self.slots.try_lock(){
            Ok(mut slots) if matches!(slots.get(index),Some(Cell::Reclaiming(held)) if *held==number)=>{
                slots[index]=if known{Cell::Empty}else{Cell::Tombstone};
            }
            _=>self.global_failure(),
        }
    }
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
    failure:unsafe extern "C" fn(*const c_void),
}
static API:ServiceApi=ServiceApi{reserve:reserve_callback,retain:retain_callback,release:release_callback,notify:notify_callback,
    enter:enter_callback,returned:return_callback,claim:claim_callback,response:response_callback,
    backing:backing_callback,finish:finish_callback,failure:global_callback};
unsafe extern "C" fn reserve_callback(context:*const c_void,account:u32,now:u64,slot:*mut u32,number:*mut u64)->*const c_void{
    if context.is_null() || slot.is_null() || number.is_null(){return std::ptr::null();}
    let registry=unsafe{&*context.cast::<ServiceRegistry>()};
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
        _=>{domain.failure_at(now,false);return 0;}
    };
    domain.window.watch(now);
    if !domain.window.snapshot().admits(now,cleanup){domain.failure_at(now,false);return 0;}
    let response=unsafe{&mut **domain.response.get()};
    let produced=match kind{
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
unsafe extern "C" fn global_callback(context:*const c_void){
    if let Some(registry)=unsafe{context.cast::<ServiceRegistry>().as_ref()}{registry.global_failure();}
}
unsafe extern "C"{
    fn mrk_android_service_new(context:*const c_void,api:*const ServiceApi)->*mut c_void;
    fn mrk_android_service_bind_control(book:*mut c_void)->c_int;
    fn mrk_android_service_begin(book:*mut c_void)->c_int;
    fn mrk_android_service_close_context(book:*mut c_void,slot:u32,number:u64,domain:*const c_void)->c_int;
    fn mrk_android_service_context_ready(book:*mut c_void,slot:u32,number:u64)->c_int;
    fn mrk_android_service_reclaim_context(book:*mut c_void,slot:u32,number:u64)->c_int;
    fn mrk_android_service_run(book:*mut c_void)->c_int;
}
/// Main listener custody is permanent resident-process state. Control owns only
/// native connection references; it never receives worker or filesystem books.
pub struct ServiceBook{pointer:Option<NonNull<c_void>>,registry:ManuallyDrop<Arc<ServiceRegistry>>,entered:bool}
pub struct ServiceControl{pointer:NonNull<c_void>,registry:Arc<ServiceRegistry>,bound:bool}
unsafe impl Send for ServiceControl{}
impl ServiceBook{
    pub fn new(registry:Arc<ServiceRegistry>)->Self{Self{pointer:None,registry:ManuallyDrop::new(registry),entered:false}}
    pub fn reserve_control(&mut self)->Result<ServiceControl,Failure>{
        if self.entered || self.pointer.is_some() || !registration::ClientBook::identity_available(){return Err(Failure::Unavailable);}
        self.entered=true;self.pointer=NonNull::new(unsafe{mrk_android_service_new(Arc::as_ptr(&self.registry).cast(),&API)});
        let Some(pointer)=self.pointer else{return Err(Failure::Native);};
        Ok(ServiceControl{pointer,registry:Arc::clone(&self.registry),bound:false})
    }
    pub fn begin(&mut self)->Result<(),Failure>{
        let Some(pointer)=self.pointer else{return Err(Failure::Unavailable);};
        self.registry.accepting.store(true,Ordering::SeqCst);
        if unsafe{mrk_android_service_begin(pointer.as_ptr())}!=1{self.registry.global_failure();return Err(Failure::Native);}Ok(())
    }
    pub fn run_forever(&mut self)->i32{
        self.pointer.map_or(2,|pointer|unsafe{mrk_android_service_run(pointer.as_ptr())})
    }
}
impl ServiceControl{
    pub fn bind(&mut self)->bool{
        if self.bound{return false;}
        self.bound=unsafe{mrk_android_service_bind_control(self.pointer.as_ptr())}==1;self.bound
    }
    /// One registered native owner, never waiting for coordinator/Arc exclusivity.
    pub fn retire(&mut self,domain:&Arc<ServiceDomain>){
        if !self.bound || !domain.route_retiring() || domain.native_return()!=NativeReturn::NotStarted{return;}
        let ready=unsafe{mrk_android_service_context_ready(self.pointer.as_ptr(),domain.slot as u32,domain.number)};
        if ready==0{return;}if ready!=1{domain.failure_now(true);return;}
        let now=uptime().unwrap_or(0);
        if !domain.native_entered(now){return;}
        // The endpoint may have an in-flight original response self-reference.
        // Consume ONLY this native owner's references now: no response backing,
        // DATA borrow, worker/coordinator join or exclusivity wait is allowed.
        let returned=unsafe{mrk_android_service_close_context(self.pointer.as_ptr(),domain.slot as u32,domain.number,Arc::as_ptr(domain).cast())};
        // ACTUAL last native control call returned. An inside-call flag was not
        // used as a return receipt. Every entered native original was summarized.
        domain.native_returned(uptime().unwrap_or(0),returned==1);
    }
    /// Caller has dropped all positively settled payload/coordinator DATA and
    /// its temporary domain clones BEFORE asking for exact registry exclusivity.
    pub fn reclaim(&mut self,index:usize,number:u64){
        if !self.bound{return;}
        let Some(domain)=self.registry.take_for_reclaim(index,number)else{return;};
        if !domain.reclaim_prerequisites(){self.registry.restore(index,number,domain);return;}
        match Arc::try_unwrap(domain){
            Err(domain)=>self.registry.restore(index,number,domain),
            Ok(domain)=>{
                let known=domain.final_known();
                let cleared=known && unsafe{mrk_android_service_reclaim_context(self.pointer.as_ptr(),index as u32,number)}==1;
                self.registry.finish_reclaim(index,number,cleared);
                if known && !cleared{self.registry.global_failure();}
            }
        }
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
        let domain=ServiceDomain::new(0,1,501,100,Arc::new(PayloadReservation::new())).unwrap();
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
        let domain=ServiceDomain::new(0,1,501,100,Arc::new(PayloadReservation::new())).unwrap();
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
        let domain=ServiceDomain::new(0,1,501,100,Arc::new(PayloadReservation::new())).unwrap();
        assert!(!domain.no_payload_created());
        assert!(!domain.release_payload_if_settled());
        domain.retire_at(101);
        assert!(domain.no_payload_created());
        domain.payload_settled(true);assert!(domain.release_payload_if_settled());
        assert!(domain.release_payload_if_settled()); // idempotent same local reservation
    }
    #[test]
    fn data_slot_limit_is_live_and_fresh_counter_can_exceed_eight(){
        let registry=ServiceRegistry::new(0).unwrap();registry.accepting.store(true,Ordering::SeqCst);
        for number in 1..=24{
            let domain=registry.reserve(501,100).unwrap();
            assert_eq!(domain.number(),number);assert_eq!(domain.nonce,prepare::nonce_for_counter(number).unwrap());
            domain.retire_at(101);local_control_data(&domain,102,103);
            let original=registry.take_for_reclaim(domain.slot(),number).unwrap();
            let slot=domain.slot();drop(domain);
            let data=match Arc::try_unwrap(original){Ok(data)=>data,Err(_)=>panic!("fixture has only registry DATA")};
            assert!(data.final_known());registry.finish_reclaim(slot,number,true);
        }
        let mut retained=Vec::new();
        for _ in 0..control::LIVE_CONTEXTS{retained.push(registry.reserve(501,100).unwrap());}
        assert!(registry.reserve(501,100).is_none());
        assert_eq!(retained.first().unwrap().number(),25);
    }
    #[test]
    fn last_data_holder_cannot_race_the_final_control_reconciliation(){
        let domain=Arc::new(ServiceDomain::new(0,1,501,100,Arc::new(PayloadReservation::new())).unwrap());
        domain.retire_at(100+prepare::CLEANUP_NS);
        local_control_data(&domain,101,100+11_000_000_000);
        let callback=domain.clone();
        let original=match Arc::try_unwrap(domain){Err(same)=>same,Ok(_)=>panic!("retained original must block exclusivity")};
        assert!(Arc::ptr_eq(&original,&callback));
        callback.failure_at(102,false);drop(callback);
        let exclusive=match Arc::try_unwrap(original){Ok(data)=>data,Err(_)=>panic!("last DATA holder was dropped")};
        assert!(!exclusive.final_known()); // earlier CF invalidates actual original return
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
}
