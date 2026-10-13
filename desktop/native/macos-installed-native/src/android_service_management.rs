//! Original fixed service-management phases, not IPC or toolchain authority.
//! The app supplies one T/W/H/F gate and queues this !Send manager ONLY from its
//! original non-main coordinator into the verified framework AppKit callback.
//! No nested app-owned pool, automatic registration, Drop cleanup or UI park.
use std::{ffi::{c_int,c_void},marker::PhantomData,ptr::NonNull,rc::Rc,time::Instant};

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Status { NotRegistered,Enabled,RequiresApproval,NotFound,Unavailable,Error }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Action { Observe,RequestRegistration,OpenApprovalSettings,UnregisterAfterQuiescence }
impl Action {
    fn code(self)->u32 { match self { Self::Observe=>0,Self::RequestRegistration=>1,Self::OpenApprovalSettings=>2,Self::UnregisterAfterQuiescence=>3 } }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Outcome { NotEntered,Observed,RegistrationRequested,AlreadyRegistered,NeedsApproval,
    SettingsRequested,Refused,Error,Unknown,DeniedByUser,Stopped,UnregisterAccepted }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Observation {
    pub action:Action,pub status:Status,pub outcome:Outcome,
    /// Positive facts only. On Unknown, false is not proof of nonentry when
    /// mutation_uncertain is true.
    pub mutation_entered:bool,pub mutation_returned:bool,pub mutation_uncertain:bool,
    pub native_settled:bool,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Phase { AllocateCell,AdmitAction,AcquireService,ObserveStatus,Mutate,
    ObserveResult,ReleaseService,RetireCell }
impl Phase {
    pub fn is_cleanup(self)->bool { matches!(self,Self::ReleaseService|Self::RetireCell) }
    fn code(self)->Option<u32> { match self {
        Self::AcquireService=>Some(2),Self::ObserveStatus=>Some(3),Self::Mutate=>Some(4),
        Self::ObserveResult=>Some(5),Self::ReleaseService=>Some(6),_=>None,
    } }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum CellCustody { Absent,Entering,Owned,Consumed,Unknown }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ServiceCustody { NotAcquired,Owned,Settled,Unknown }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Custody {
    pub action:Option<Action>,pub phase:Option<Phase>,pub action_admitted:bool,
    pub cell:CellCustody,pub service:ServiceCustody,pub in_call:bool,pub gate_entered:bool,
    pub unknown:bool,pub stopped:bool,pub first_failure:Option<Instant>,
    /// Last original native observation, NOT rewritten as Stopped. This keeps
    /// an already returned mutation result visible even when later work stops.
    pub observation:Option<Observation>,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Checkpoint {
    Before { phase:Phase,custody:Custody },
    Returned { phase:Phase,at:Instant,custody:Custody },
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Decision { Proceed,Defer,Stop,Unknown }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Progress { Deferred,Finished(Observation),Unknown(Observation) }

/// Fixture-only copied lookup facts. The fixed words never authorize a service
/// operation and say nothing about private SMAppService bundle selection.
#[cfg(feature="e2-native-fixture")]
#[repr(C)]
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
pub(crate) struct FixtureBundleLookup { pub(crate) words:[u32;4] }
#[cfg(feature="e2-native-fixture")]
impl FixtureBundleLookup {
    fn observed(self)->bool { self.words!=[0;4] }
    pub(crate) fn valid(self)->bool {
        if !self.observed() { return true; }
        let [bundle,executable,identifier,plist]=self.words;
        if !(1..=4).contains(&bundle) || !(1..=4).contains(&executable)
            || !(1..=4).contains(&identifier) || !(1..=6).contains(&plist) { return false; }
        match bundle {
            1=>matches!(plist,1|2|6),2=>matches!(plist,3|4|6),3=>plist==5,
            4=>executable==4 && identifier==4 && plist==6,_=>false,
        }
    }
    pub(crate) fn labels(self)->Option<[(&'static str,&'static str);4]> {
        if !self.observed() || !self.valid() { return None; }
        let [bundle,executable,identifier,plist]=self.words;
        let locations=["", "fixture-client", "fixture-outer", "other", "unavailable"];
        let executables=["", "fixture-client", "fixture-entry", "other", "unavailable"];
        let plists=["", "held-client-match", "client-identity-mismatch", "outer-library-absent",
            "outer-library-present", "other-bundle-not-read", "unavailable"];
        Some([("bundle",locations[bundle as usize]),("executable",executables[executable as usize]),
            ("identifier",locations[identifier as usize]),("plist",plists[plist as usize])])
    }
}
#[repr(C)]
#[derive(Clone,Copy,Debug,Default)]
struct Report {
    version:u32,action:u32,status:u32,outcome:u32,entered:u32,returned:u32,cleanup_known:u32,unknown:u32,
    phase:u32,service_state:u32,called:u32,reserved:u32,
    #[cfg(feature="e2-native-fixture")] fixture_lookup:FixtureBundleLookup,
}
fn decode(raw:Report,action:Action,phase:Phase)->Option<Observation> {
    #[cfg(feature="e2-native-fixture")]
    if !raw.fixture_lookup.valid() || raw.fixture_lookup.observed()
        && (action!=Action::Observe || !matches!(phase,Phase::ObserveStatus|Phase::ReleaseService)
            || raw.status==4) { return None; }
    if action==Action::UnregisterAfterQuiescence{return decode_maintenance(raw,phase);}
    if raw.version!=2 || raw.action!=action.code() || Some(raw.phase)!=phase.code()
        || raw.status>5 || raw.outcome>9 || raw.entered>1 || raw.returned>raw.entered
        || raw.cleanup_known>1 || raw.unknown>1 || raw.called!=1 || raw.reserved!=0
        || raw.service_state>5
        || (raw.unknown==1)!=(raw.outcome==8)
        || raw.unknown==1 && (raw.cleanup_known!=0 || raw.outcome!=8)
        || action==Action::Observe && (raw.entered!=0 || raw.returned!=0)
        || raw.unknown==0 && matches!(raw.service_state,0|1|3|5) { return None; }
    if matches!(phase,Phase::AcquireService|Phase::ObserveStatus) && raw.entered!=0 { return None; }
    let reservation_action=matches!(action,Action::RequestRegistration|Action::OpenApprovalSettings);
    let reservation_refused=reservation_action && phase==Phase::Mutate && raw.outcome==6
        && raw.service_state==2 && raw.entered==0 && raw.returned==0
        && match action {Action::RequestRegistration=>raw.status==0,
            Action::OpenApprovalSettings=>raw.status<=3,_=>false};
    if raw.unknown==0 {
        if phase==Phase::ReleaseService {
            if raw.cleanup_known!=1 || raw.service_state!=4 { return None; }
        } else if raw.cleanup_known!=0 { return None; }
        match phase {
            Phase::AcquireService if raw.status!=4 || raw.entered!=0 || raw.returned!=0
                || !((raw.service_state==2 && raw.outcome==0)
                    || (raw.service_state==4 && (raw.outcome==7 || reservation_action && raw.outcome==6))) => return None,
            Phase::ObserveStatus if raw.service_state!=2 || raw.entered!=0 || raw.returned!=0
                || raw.status==4 => return None,
            Phase::Mutate if raw.service_state!=2 || !reservation_refused && (raw.entered!=1 || raw.returned!=1)
                || action==Action::Observe => return None,
            Phase::ObserveResult if raw.service_state!=2 || raw.entered!=1 || raw.returned!=1
                || action!=Action::RequestRegistration || raw.status==4 => return None,
            _=>{},
        }
        if phase==Phase::ObserveStatus {
            let expected=if raw.status==5 { 7 } else { match action {
                Action::Observe=>1,Action::OpenApprovalSettings=>0,Action::UnregisterAfterQuiescence=>return None,
                Action::RequestRegistration=>match raw.status { 0=>0,1=>3,2=>4,3=>6,_=>return None },
            } };
            if raw.outcome!=expected { return None; }
        }
        if phase==Phase::Mutate && !reservation_refused && match action {
            Action::RequestRegistration=>raw.status!=0 || !matches!(raw.outcome,2|3|4|7|9),
            Action::OpenApprovalSettings=>raw.status>3 || raw.outcome!=5,
            Action::Observe|Action::UnregisterAfterQuiescence=>true,
        } { return None; }
        if phase==Phase::ObserveResult
            && (!matches!(raw.outcome,2|3|4|7|9) || raw.status==5 && raw.outcome!=7) { return None; }
    }
    let status=match raw.status { 0=>Status::NotRegistered,1=>Status::Enabled,2=>Status::RequiresApproval,
        3=>Status::NotFound,4=>Status::Unavailable,_=>Status::Error };
    let outcome=match raw.outcome { 0=>Outcome::NotEntered,1=>Outcome::Observed,2=>Outcome::RegistrationRequested,
        3=>Outcome::AlreadyRegistered,4=>Outcome::NeedsApproval,5=>Outcome::SettingsRequested,
        6=>Outcome::Refused,7=>Outcome::Error,8=>Outcome::Unknown,_=>Outcome::DeniedByUser };
    if outcome==Outcome::Observed && action!=Action::Observe
        || matches!(outcome,Outcome::RegistrationRequested|Outcome::AlreadyRegistered|Outcome::NeedsApproval|Outcome::DeniedByUser)
            && action!=Action::RequestRegistration
        || outcome==Outcome::SettingsRequested && action!=Action::OpenApprovalSettings
        || matches!(outcome,Outcome::RegistrationRequested|Outcome::SettingsRequested|Outcome::DeniedByUser) && raw.returned!=1 {
        return None;
    }
    Some(Observation { action,status,outcome,mutation_entered:raw.entered==1,
        mutation_returned:raw.returned==1,mutation_uncertain:raw.unknown==1 && raw.entered==1 && raw.returned==0,
        native_settled:false })
}
/// v3 alone interprets the last word. Bit0=BOOL returned, bit1=YES,
/// bit2=NSError present, bit3=exception. No private message crosses the seam.
fn decode_maintenance(raw:Report,phase:Phase)->Option<Observation>{
    let bits=raw.reserved;
    if raw.version!=3 || raw.action!=3 || Some(raw.phase)!=phase.code() || raw.status>5
        || !matches!(raw.outcome,0|6|7|8|10) || raw.entered>1 || raw.returned>raw.entered
        || raw.cleanup_known>1 || raw.unknown>1 || raw.called!=1 || raw.service_state>5
        || bits&!15!=0 || bits&6!=0 && bits&1==0 || (raw.returned==1)!=(bits&1==1)
        || (raw.unknown==1)!=(raw.outcome==8) || (raw.unknown==1)!=(bits&8!=0)
        || raw.unknown==1 && raw.cleanup_known!=0{return None;}
    if raw.unknown==0{
        if !matches!(raw.service_state,2|4){return None;}
        if (phase==Phase::ReleaseService)!=(raw.cleanup_known==1){return None;}
        match phase{
            Phase::AcquireService if raw.status!=4 || raw.entered!=0 || bits!=0
                || !matches!((raw.service_state,raw.outcome),(2,0)|(4,7))=>return None,
            Phase::ObserveStatus if raw.service_state!=2 || raw.entered!=0 || bits!=0 || raw.status==4
                || raw.outcome!=if raw.status==1{0}else if raw.status==5{7}else{6}=>return None,
            Phase::Mutate if raw.service_state!=2 || raw.status!=1 || raw.entered!=1 || raw.returned!=1
                || raw.outcome!=if bits==3{10}else{7}=>return None,
            Phase::ObserveResult if raw.service_state!=2 || raw.entered!=1 || raw.returned!=1
                || bits!=3 || raw.outcome!=10 || raw.status==4=>return None,
            Phase::ReleaseService if raw.service_state!=4=>return None,
            _=>{},
        }
        if raw.outcome==10 && (bits!=3 || raw.entered!=1 || raw.returned!=1){return None;}
    }
    let status=match raw.status{0=>Status::NotRegistered,1=>Status::Enabled,2=>Status::RequiresApproval,
        3=>Status::NotFound,4=>Status::Unavailable,_=>Status::Error};
    let outcome=match raw.outcome{0=>Outcome::NotEntered,6=>Outcome::Refused,7=>Outcome::Error,
        8=>Outcome::Unknown,10=>Outcome::UnregisterAccepted,_=>return None};
    Some(Observation{action:Action::UnregisterAfterQuiescence,status,outcome,mutation_entered:raw.entered==1,
        mutation_returned:raw.returned==1,mutation_uncertain:raw.entered==1 && raw.returned==0,native_settled:false})
}
unsafe extern "C" {
    fn mrk_android_management_new(action:u32)->*mut c_void;
    fn mrk_android_management_step(book:*mut c_void,phase:u32,output:*mut Report)->c_int;
    fn mrk_android_management_retire(book:*mut c_void,unentered:u32)->c_int;
}
// Fixed private native boundary. Tests inject only bounded DATA returns into
// this SAME phase engine; no alternate public owner, clock or native executor.
trait Native {
    fn allocate(&mut self,action:u32)->*mut c_void;
    fn step(&mut self,pointer:*mut c_void,phase:u32,report:&mut Report)->c_int;
    fn retire(&mut self,pointer:*mut c_void,unentered:bool)->c_int;
}
struct Calls;
impl Native for Calls {
    fn allocate(&mut self,action:u32)->*mut c_void { unsafe { mrk_android_management_new(action) } }
    fn step(&mut self,pointer:*mut c_void,phase:u32,report:&mut Report)->c_int {
        unsafe { mrk_android_management_step(pointer,phase,report) }
    }
    fn retire(&mut self,pointer:*mut c_void,unentered:bool)->c_int {
        unsafe { mrk_android_management_retire(pointer,u32::from(unentered)) }
    }
}

#[cfg(feature="e2-native-fixture")]
use crate::android_registration::{FixtureCheckpointApi,FixtureIdentityFacts,FixtureIdentityCustody};
#[cfg(feature="e2-native-fixture")]
pub(crate) const FIXTURE_IDENTITY_POOL_ALLOCATE:u32=2;
#[cfg(feature="e2-native-fixture")]
pub(crate) const FIXTURE_IDENTITY_POOL_INIT:u32=3;
#[cfg(feature="e2-native-fixture")]
pub(crate) const FIXTURE_IDENTITY_POOL_DRAIN:u32=12;
#[cfg(feature="e2-native-fixture")]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum FixtureIdentityOutcome { Success,Failure,Unknown }
#[cfg(feature="e2-native-fixture")]
#[derive(Clone,Copy,Debug)]
pub(crate) struct FixtureIdentityCheckpoint {
    pub phase:u32,pub returned:bool,pub cleanup:bool,pub raw_ns:u64,pub outcome:FixtureIdentityOutcome,
}
#[cfg(feature="e2-native-fixture")]
struct FixtureGate<'a> {
    gate:&'a mut dyn FnMut(FixtureIdentityCheckpoint)->Decision,poisoned:bool,
}
#[cfg(feature="e2-native-fixture")]
unsafe extern "C" fn fixture_identity_point(raw:*mut c_void,phase:u32,edge:u32,cleanup:u32,now:u64,outcome:u32)->u32 {
    let Some(bridge)=(unsafe{raw.cast::<FixtureGate<'_>>().as_mut()})else{return 2;};
    if bridge.poisoned || !(1..=13).contains(&phase) || edge>1 || cleanup>1 || outcome>2 {
        bridge.poisoned=true;return 2;
    }
    let outcome=match outcome {0=>FixtureIdentityOutcome::Success,1=>FixtureIdentityOutcome::Failure,_=>FixtureIdentityOutcome::Unknown};
    // No Rust panic may unwind across C. A caught callback remains Unknown and
    // retains all original native custody; this bridge never performs cleanup.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||(bridge.gate)(
        FixtureIdentityCheckpoint{phase,returned:edge==1,cleanup:cleanup==1,raw_ns:now,outcome}))) {
        Ok(Decision::Proceed)=>1,Ok(Decision::Stop)=>0,
        _=>{bridge.poisoned=true;2}
    }
}
#[cfg(feature="e2-native-fixture")]
unsafe extern "C" {
    fn mrk_e2_fixture_identity_project_bytes()->usize;
    fn mrk_e2_fixture_main_identity_new(api:*const FixtureCheckpointApi,out:*mut FixtureIdentityFacts)->*mut c_void;
    fn mrk_e2_fixture_identity_prepare(original:*mut c_void,api:*const FixtureCheckpointApi,out:*mut FixtureIdentityFacts)->c_int;
    fn mrk_e2_fixture_identity_recheck(original:*mut c_void,cleanup:u32,api:*const FixtureCheckpointApi,out:*mut FixtureIdentityFacts)->c_int;
    fn mrk_e2_fixture_identity_facts_read(original:*mut c_void,out:*mut FixtureIdentityFacts)->c_int;
    fn mrk_e2_fixture_identity_close(original:*mut *mut c_void,api:*const FixtureCheckpointApi,out:*mut FixtureIdentityFacts)->c_int;
    fn mrk_android_e2_fixture_management_new(action:u32,identity:*mut c_void)->*mut c_void;
}
/// Per-case ORIGINAL main identity/pool. No Clone, Send or Drop native cleanup.
#[cfg(feature="e2-native-fixture")]
pub(crate) struct FixtureMainIdentity {
    pointer:Option<NonNull<c_void>>,facts:FixtureIdentityFacts,started:bool,in_call:bool,poisoned:bool,
    _main:PhantomData<Rc<()>>,
}
#[cfg(feature="e2-native-fixture")]
impl FixtureMainIdentity {
    pub(crate) fn new()->Self { Self{pointer:None,facts:FixtureIdentityFacts::inert(),
        started:false,in_call:false,poisoned:false,_main:PhantomData} }
    pub(crate) fn project_owned_upper_bound()->Option<usize> {
        let provider=crate::android_service_budget::FIXTURE_IDENTITY_PROVIDER_MAX;
        let main=provider.checked_add(std::mem::size_of::<Self>())?
            .checked_add(std::mem::size_of::<FixtureGate<'static>>())?
            .checked_add(2*std::mem::size_of::<FixtureIdentityFacts>())?
            .checked_add(std::mem::size_of::<FixtureCheckpointApi>())?;
        // The other provider is already in ClientRequirements. This check is
        // the extra identity-only per-process ceiling, not a second charge.
        let combined=main.checked_add(provider)?.checked_add(std::mem::size_of::<FixtureIdentityFacts>())?;
        (combined<=crate::android_service_budget::FIXTURE_IDENTITY_PROCESS_MAX).then_some(main)
    }
    fn ptr(&self)->*mut c_void { self.pointer.map_or(std::ptr::null_mut(),NonNull::as_ptr) }
    pub(crate) fn facts(&self)->FixtureIdentityFacts {
        let mut facts=self.facts;if self.poisoned || self.in_call {facts.unknown=1;}facts
    }
    pub(crate) fn custody(&self)->FixtureIdentityCustody { self.facts().custody() }
    fn import(&mut self,next:FixtureIdentityFacts)->bool {
        if !next.valid() || next.role!=1 || next.calls<self.facts.calls || next.returns<self.facts.returns
            || next.allocated<self.facts.allocated || next.consumed<self.facts.consumed
            || next.allocation_entered<self.facts.allocation_entered || next.allocation_returned<self.facts.allocation_returned
            || next.failed<self.facts.failed || next.unknown<self.facts.unknown
            || next.last_ns<self.facts.last_ns {
            self.poisoned=true;return false;
        }
        self.facts=next;true
    }
    fn refresh(&mut self)->bool {
        if self.in_call || self.poisoned {return false;}
        if self.pointer.is_none(){return self.facts.valid();}
        let mut next=FixtureIdentityFacts::default();
        if unsafe{mrk_e2_fixture_identity_facts_read(self.ptr(),&mut next)}!=1 {self.poisoned=true;return false;}
        self.import(next)
    }
    fn run(&mut self,gate:&mut dyn FnMut(FixtureIdentityCheckpoint)->Decision,
        call:impl FnOnce(*mut c_void,*const FixtureCheckpointApi,*mut FixtureIdentityFacts)->(*mut c_void,bool))->bool {
        if self.in_call || self.poisoned {return false;}
        let mut bridge=FixtureGate{gate,poisoned:false};
        let api=FixtureCheckpointApi{context:(&mut bridge as *mut FixtureGate<'_>).cast(),point:fixture_identity_point};
        let mut next=FixtureIdentityFacts::default();self.in_call=true;
        let (pointer,ok)=call(self.ptr(),&api,&mut next);
        // Actual consuming NULL is authoritative even when later DATA/gate
        // validation fails. Never reintroduce or probe a consumed pointer.
        self.pointer=NonNull::new(pointer);self.in_call=false;
        let imported=self.import(next);self.poisoned|=bridge.poisoned;
        ok && imported && !self.poisoned && self.facts.unknown==0
    }
    pub(crate) fn prepare(&mut self,cleanup:bool,gate:&mut dyn FnMut(FixtureIdentityCheckpoint)->Decision)->bool {
        if cleanup || self.started || self.pointer.is_some() || self.in_call || self.poisoned
            || Self::project_owned_upper_bound().is_none() {return false;}
        self.started=true;
        let actual=unsafe{mrk_e2_fixture_identity_project_bytes()};
        if actual==0 || actual>crate::android_service_budget::FIXTURE_IDENTITY_PROVIDER_MAX {self.poisoned=true;return false;}
        if !self.run(gate,|_,api,out| {
            let pointer=unsafe{mrk_e2_fixture_main_identity_new(api,out)};(pointer,!pointer.is_null())
        }) || self.facts.failed!=0 {return false;}
        self.run(gate,|pointer,api,out| (pointer,unsafe{mrk_e2_fixture_identity_prepare(pointer,api,out)}==1))
    }
    pub(crate) fn recheck(&mut self,cleanup:bool,gate:&mut dyn FnMut(FixtureIdentityCheckpoint)->Decision)->bool {
        if self.pointer.is_none() {return false;}
        self.run(gate,|pointer,api,out| (pointer,unsafe{mrk_e2_fixture_identity_recheck(pointer,u32::from(cleanup),api,out)}==1))
    }
    pub(crate) fn close(&mut self,cleanup:bool,gate:&mut dyn FnMut(FixtureIdentityCheckpoint)->Decision)->bool {
        if !cleanup || self.in_call || self.poisoned {return false;}
        if self.pointer.is_none() {return matches!(self.custody(),FixtureIdentityCustody::NotEntered|FixtureIdentityCustody::ReturnedEmpty|FixtureIdentityCustody::Settled);}
        self.run(gate,|mut pointer,api,out| {
            let ok=unsafe{mrk_e2_fixture_identity_close(&mut pointer,api,out)}==1;(pointer,ok)
        })
    }
}
#[cfg(feature="e2-native-fixture")]
struct FixtureCalls<'a>{identity:&'a mut FixtureMainIdentity}
#[cfg(feature="e2-native-fixture")]
impl Native for FixtureCalls<'_> {
    fn allocate(&mut self,action:u32)->*mut c_void {
        let pointer=unsafe{mrk_android_e2_fixture_management_new(action,self.identity.ptr())};
        self.identity.refresh();pointer
    }
    fn step(&mut self,pointer:*mut c_void,phase:u32,report:&mut Report)->c_int {
        // Failed identity forbids another work selector; independent known
        // ReleaseService remains gated by the SAME original manager/clock.
        if phase!=6 && (self.identity.poisoned || self.identity.facts.failed!=0
            || self.identity.facts.unknown!=0 || self.identity.facts.borrow_count!=1) {return 0;}
        let returned=unsafe{mrk_android_management_step(pointer,phase,report)};
        self.identity.refresh();returned
    }
    fn retire(&mut self,pointer:*mut c_void,unentered:bool)->c_int {
        let returned=unsafe{mrk_android_management_retire(pointer,u32::from(unentered))};
        self.identity.refresh();returned
    }
}

/// Persistent TLS original. Unknown retains its actual pointer/ledger and
/// denies another allocation. It never enters cleanup from Drop or after H.
pub struct ServiceManager {
    pointer:Option<NonNull<c_void>>,active:Option<Action>,next:Phase,report:Report,
    observation:Option<Observation>,action_admitted:bool,cell:CellCustody,service:ServiceCustody,
    in_call:bool,in_gate:bool,unknown:bool,stopped:bool,deferred:bool,first:Option<Instant>,
    _main:PhantomData<Rc<()>>,
    #[cfg(feature="e2-native-fixture")] fixture_identity_address:usize,
}
impl Default for ServiceManager { fn default()->Self { Self::new() } }
impl ServiceManager {
    pub fn new()->Self { Self {
        pointer:None,active:None,next:Phase::AllocateCell,report:Report::default(),observation:None,
        action_admitted:false,cell:CellCustody::Absent,service:ServiceCustody::NotAcquired,
        in_call:false,in_gate:false,unknown:false,stopped:false,deferred:false,first:None,_main:PhantomData,
        #[cfg(feature="e2-native-fixture")] fixture_identity_address:0,
    } }
    /// The C cell includes four held protected ancestors plus one R gate for
    /// Register/Approval only. All five originals settle before cell retirement;
    /// unknown close retains the native cell. No extra heap/provider budget.
    pub const REGISTRATION_RESERVATION_ORIGINALS: usize = 5;
    /// Supplied C cell + complete Rust owner only, not framework/RSS storage.
    pub fn project_owned_upper_bound()->Option<usize> { 1024_usize.checked_add(std::mem::size_of::<Self>()) }
    /// The current original fixture Observe only; no FFI or new authority.
    #[cfg(feature="e2-native-fixture")]
    pub(crate) fn fixture_bundle_lookup(&self)->Option<FixtureBundleLookup> {
        let value=self.report.fixture_lookup;
        (self.fixture_identity_address!=0 && self.report.action==Action::Observe.code()
            && !self.in_call && !self.in_gate && !self.unknown && value.observed() && value.valid())
            .then_some(value)
    }
    /// Pure copied facts; no FFI, acquisition, clock renewal or settlement.
    pub fn custody(&self)->Custody {
        let mut observation=self.observation;
        if self.in_call && self.next==Phase::Mutate {
            if let Some(value)=observation.as_mut() { value.mutation_uncertain=true; }
        }
        Custody { action:self.active,phase:self.active.map(|_|self.next),action_admitted:self.action_admitted,
            cell:self.cell,service:self.service,in_call:self.in_call,gate_entered:self.in_gate,
            unknown:self.unknown || self.in_call || self.in_gate,stopped:self.stopped,
            first_failure:self.first,observation }
    }
    fn note(&mut self,at:Instant) { self.first=Some(self.first.map_or(at,|old|old.min(at))); }
    fn mark_unknown(&mut self,at:Instant)->Progress {
        self.note(at);self.unknown=true;self.deferred=false;
        let mut observation=self.observation.unwrap_or(Observation {
            action:self.active.unwrap_or(Action::Observe),status:Status::Error,outcome:Outcome::Unknown,
            mutation_entered:false,mutation_returned:false,mutation_uncertain:true,native_settled:false,
        });
        if self.in_call && self.next==Phase::Mutate { observation.mutation_uncertain=true; }
        observation.outcome=Outcome::Unknown;observation.native_settled=false;
        Progress::Unknown(observation)
    }
    fn checkpoint(&mut self,point:Checkpoint,gate:&mut dyn FnMut(Checkpoint)->Decision)->Decision {
        // A panic leaves entered custody sticky. It cannot be mistaken for a
        // returned callback or safely re-entered on the next invoke.
        self.in_gate=true;let decision=gate(point);self.in_gate=false;decision
    }
    fn before(&mut self,phase:Phase,gate:&mut dyn FnMut(Checkpoint)->Decision)->Decision {
        self.checkpoint(Checkpoint::Before { phase,custody:self.custody() },gate)
    }
    fn returned(&mut self,phase:Phase,at:Instant,gate:&mut dyn FnMut(Checkpoint)->Decision)->Decision {
        self.checkpoint(Checkpoint::Returned { phase,at,custody:self.custody() },gate)
    }
    fn stop_work(&mut self,at:Instant) {
        self.note(at);self.stopped=true;
        // A nil acquisition has no service reference, but its called C action
        // still owes the real empty Release phase before the cell may retire.
        // Service custody alone is not that cleanup-phase receipt.
        self.next=if self.report.called==1 && self.report.cleanup_known==0 {
            Phase::ReleaseService
        } else { Phase::RetireCell };
    }
    fn finish(&mut self)->Progress {
        let mut observation=self.observation.expect("the original action has an observation");
        observation.native_settled=true;
        if self.stopped { observation.outcome=Outcome::Stopped; }
        self.active=None;self.deferred=false;
        Progress::Finished(observation)
    }
    /// One finite original action, or a resumption of its sole pre-action
    /// Deferred slot. Only Before(AdmitAction) may Defer. The caller:
    /// * owns one original T/W/H/F, with cleanup=min(H,F+10s);
    /// * admits the exact consent/cohort with no pending at AdmitAction;
    /// * never waits on conditional pending after action admission;
    /// * imports every returned timestamp/failure before another entry;
    /// * gates final publication and real callback return separately.
    pub fn perform_phased(&mut self,action:Action,gate:&mut dyn FnMut(Checkpoint)->Decision)->Progress {
        #[cfg(feature="e2-native-fixture")]
        {
            if self.fixture_identity_address!=0 && (self.pointer.is_some() || self.active.is_some()) {
                return self.mark_unknown(Instant::now());
            }
            self.fixture_identity_address=0;
        }
        self.perform_with(action,gate,&mut Calls)
    }
    #[cfg(feature="e2-native-fixture")]
    pub(crate) fn perform_fixture_phased(&mut self,action:Action,identity:&mut FixtureMainIdentity,
        gate:&mut dyn FnMut(Checkpoint)->Decision)->Progress {
        if !identity.refresh() || identity.pointer.is_none() || identity.facts.ready!=1
            || identity.facts.failed!=0 || identity.facts.unknown!=0 || identity.facts.pool!=4 {
            return self.mark_unknown(Instant::now());
        }
        let address=identity.ptr() as usize;
        if self.pointer.is_some() || self.active.is_some() {
            if self.fixture_identity_address!=address {return self.mark_unknown(Instant::now());}
        } else {self.fixture_identity_address=address;}
        self.perform_with(action,gate,&mut FixtureCalls{identity})
    }
    fn perform_with(&mut self,action:Action,gate:&mut dyn FnMut(Checkpoint)->Decision,
        native:&mut impl Native)->Progress {
        if self.unknown || self.in_call || self.in_gate
            || self.active.is_some_and(|old|old!=action || !self.deferred) {
            return self.mark_unknown(Instant::now());
        }
        if self.active.is_none() {
            if self.pointer.is_some() { return self.mark_unknown(Instant::now()); }
            self.active=Some(action);self.next=Phase::AllocateCell;
            self.report=Report { version:if action==Action::UnregisterAfterQuiescence{3}else{2},action:action.code(),status:4,..Report::default() };
            self.observation=Some(Observation { action,status:Status::Unavailable,outcome:Outcome::NotEntered,
                mutation_entered:false,mutation_returned:false,mutation_uncertain:false,native_settled:false });
            self.action_admitted=false;self.cell=CellCustody::Absent;self.service=ServiceCustody::NotAcquired;
            self.stopped=false;self.first=None;
        }
        self.deferred=false;
        // Eight distinct phases; a single Work->Cleanup cut adds no cycle.
        for _ in 0..10 {
            let phase=self.next;
            match self.before(phase,gate) {
                Decision::Proceed=>{},
                Decision::Defer if phase==Phase::AdmitAction && !self.action_admitted=>{
                    self.deferred=true;return Progress::Deferred;
                },
                Decision::Stop if !phase.is_cleanup()=>{
                    self.stop_work(Instant::now());continue;
                },
                _=>return self.mark_unknown(Instant::now()),
            }
            if phase==Phase::AdmitAction {
                self.action_admitted=true;self.next=Phase::AcquireService;continue;
            }
            if phase==Phase::AllocateCell {
                self.cell=CellCustody::Entering;self.in_call=true;
                let pointer=native.allocate(action.code());let at=Instant::now();
                self.in_call=false;self.pointer=NonNull::new(pointer);
                self.cell=if self.pointer.is_some() { CellCustody::Owned } else { CellCustody::Absent };
                match self.returned(phase,at,gate) {
                    Decision::Proceed=>{},
                    Decision::Stop=>{ self.stop_work(at);continue; },
                    _=>return self.mark_unknown(at),
                }
                if self.pointer.is_none() { return self.finish(); }
                self.next=Phase::AdmitAction;continue;
            }
            if phase==Phase::RetireCell {
                let Some(pointer)=self.pointer else { return self.finish(); };
                self.in_call=true;
                let consumed=native.retire(pointer.as_ptr(),self.report.called==0);
                let at=Instant::now();self.in_call=false;
                if consumed==1 {
                    // Clear on the REAL consuming return BEFORE a late/failed
                    // callback can retain Unknown. Never touch this pointer again.
                    self.pointer=None;self.cell=CellCustody::Consumed;
                } else { self.cell=CellCustody::Unknown;self.unknown=true;self.note(at); }
                let decision=self.returned(phase,at,gate);
                if self.unknown || decision!=Decision::Proceed { return self.mark_unknown(at); }
                return self.finish();
            }
            let Some(pointer)=self.pointer else { return self.mark_unknown(Instant::now()); };
            let Some(code)=phase.code() else { return self.mark_unknown(Instant::now()); };
            if !self.action_admitted { return self.mark_unknown(Instant::now()); }
            if matches!(phase,Phase::AcquireService|Phase::ReleaseService) { self.service=ServiceCustody::Unknown; }
            self.in_call=true;let mut raw=Report::default();
            let returned=native.step(pointer.as_ptr(),code,&mut raw);
            let at=Instant::now();self.in_call=false;
            let decoded=(returned==1).then(||decode(raw,action,phase)).flatten().filter(|_| {
                #[cfg(feature="e2-native-fixture")]
                if self.report.fixture_lookup.observed() && raw.fixture_lookup!=self.report.fixture_lookup { return false; }
                raw.entered>=self.report.entered && raw.returned>=self.report.returned
            });
            if let Some(observation)=decoded {
                self.report=raw;
                // Preserve a positive original unregister fact if a later
                // status/release raises. Unknown is still absorbing separately.
                let preserve=action==Action::UnregisterAfterQuiescence && raw.unknown==1
                    && self.observation.is_some_and(|value|value.outcome==Outcome::UnregisterAccepted);
                if !preserve{self.observation=Some(observation);}
                if action==Action::UnregisterAfterQuiescence && phase==Phase::ObserveResult
                    && observation.status!=Status::NotRegistered{self.note(at);}
                self.service=match raw.service_state {
                    2=>ServiceCustody::Owned,4=>ServiceCustody::Settled,_=>ServiceCustody::Unknown,
                };
                if matches!(observation.outcome,Outcome::Refused|Outcome::Error|Outcome::Unknown|Outcome::DeniedByUser) { self.note(at); }
                self.unknown=raw.unknown==1;
            } else {
                self.unknown=true;self.service=ServiceCustody::Unknown;self.note(at);
                if phase==Phase::Mutate {
                    if let Some(value)=self.observation.as_mut() { value.mutation_uncertain=true; }
                }
            }
            let decision=self.returned(phase,at,gate);
            if self.unknown { return self.mark_unknown(at); }
            match decision {
                Decision::Proceed=>{},
                Decision::Stop if !phase.is_cleanup()=>{ self.stop_work(at);continue; },
                _=>return self.mark_unknown(at),
            }
            self.next=if self.first.is_some() && !phase.is_cleanup() {
                // An actual native failure forbids another work phase even if
                // a caller mistakenly returns Proceed after importing it.
                Phase::ReleaseService
            } else { match phase {
                Phase::AcquireService if raw.service_state==2=>Phase::ObserveStatus,
                Phase::ObserveStatus if raw.outcome==0=>Phase::Mutate,
                Phase::Mutate if matches!(action,Action::RequestRegistration|Action::UnregisterAfterQuiescence)=>Phase::ObserveResult,
                Phase::ReleaseService=>Phase::RetireCell,
                _=>Phase::ReleaseService,
            } };
        }
        self.mark_unknown(Instant::now())
    }
}

/// Source/build selection only. True is NOT a signature, service or Ready
/// observation. The missing shipping profile remains unavailable on all hosts.
pub fn signing_profile_configured() -> bool {
    option_env!("MRK_ANDROID_SIGNING_PROFILE_CONFIGURED") == Some("1")
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum IdentityPhase { AllocateCell, Inspect(u8), Release(u8), RetireCell }
impl IdentityPhase {
    pub fn is_cleanup(self)->bool { matches!(self,Self::Release(_)|Self::RetireCell) }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum IdentityResult { Verified,Unavailable,Refused,Unknown }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct IdentityCustody {
    pub phase:Option<IdentityPhase>,pub cell:CellCustody,pub references:[u32;12],
    pub entered:bool,pub in_call:bool,pub gate_entered:bool,pub verified:bool,pub failed:bool,
    pub unknown:bool,pub first_failure:Option<Instant>,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum IdentityCheckpoint {
    Before { phase:IdentityPhase,custody:IdentityCustody },
    Returned { phase:IdentityPhase,at:Instant,custody:IdentityCustody },
}
#[repr(C)]
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
struct IdentityReport {
    version:u32,phase:u32,calls:u32,returned:u32,verified:u32,failed:u32,unknown:u32,reserved:u32,
    states:[u32;12],
}
fn identity_slot(phase:u8)->Option<usize> { match phase {
    1=>Some(0),2=>Some(1),3=>Some(2),4=>Some(3),6=>Some(4),
    7=>Some(5),8=>Some(6),9=>Some(7),10=>Some(8),12=>Some(9),13=>Some(10),15=>Some(11),_=>None,
} }
fn identity_report(raw:IdentityReport,old:IdentityReport,phase:IdentityPhase)->bool {
    let code=match phase { IdentityPhase::Inspect(n) if (1..=17).contains(&n)=>u32::from(n),
        IdentityPhase::Release(n) if n<12=>32+u32::from(n),_=>return false };
    if raw.version!=1 || raw.phase!=code || raw.calls!=old.calls.saturating_add(1)
        || raw.calls>29 || raw.returned>raw.calls || raw.returned<old.returned || raw.reserved!=0
        || raw.verified>1 || raw.failed>1 || raw.unknown>1 || raw.failed<old.failed || raw.unknown<old.unknown
        || raw.verified<old.verified || raw.states.iter().any(|state|*state>5)
        || raw.unknown==1 && raw.failed!=1 || raw.unknown==0 && raw.returned!=raw.calls {
        return false;
    }
    if raw.unknown==1 { return true; } // Retained Unknown; never work/release authority.
    if raw.states.iter().any(|state|matches!(*state,1|3|5)) { return false; }
    match phase {
        IdentityPhase::Inspect(n)=>{
            if old.failed!=0 || old.unknown!=0 || old.phase+1!=u32::from(n) { return false; }
            let slot=identity_slot(n);
            for (index,(&before,&after)) in old.states.iter().zip(&raw.states).enumerate() {
                if Some(index)==slot {
                    if before!=0 || !matches!(after,2|4) || after==4 && raw.failed!=1 { return false; }
                } else if before!=after { return false; }
            }
            raw.verified==u32::from(n==17 && raw.failed==0)
        },
        IdentityPhase::Release(n)=>raw.verified==old.verified && raw.failed==old.failed
            && old.states[usize::from(n)]==2 && old.states.iter().zip(&raw.states).enumerate()
                .all(|(index,(before,after))|if index==usize::from(n){*after==4}else{before==after}),
        _=>false,
    }
}
unsafe extern "C" {
    fn mrk_android_signing_new()->*mut c_void;
    fn mrk_android_signing_step(book:*mut c_void,phase:u32,out:*mut IdentityReport)->c_int;
    fn mrk_android_signing_release(book:*mut c_void,slot:u32,out:*mut IdentityReport)->c_int;
    fn mrk_android_signing_retire(book:*mut c_void)->c_int;
}
/// One retained fixed signature original. Inert construction is safe anywhere;
/// native entry is restricted to one non-main worker by the native book itself.
/// The owning app stores this behind its original worker-only mutex. There is
/// deliberately no cleanup in Drop or a method accepting paths/requirements.
pub struct IdentityBook {
    pointer:Option<NonNull<c_void>>,report:IdentityReport,phase:Option<IdentityPhase>,cell:CellCustody,
    entered:bool,in_call:bool,in_gate:bool,unknown:bool,closed:bool,first:Option<Instant>,
}
// SAFETY: no native reference is exposed or dereferenced by Rust. Every entry
// checks the recorded process AND pthread; transfer cannot permit a different
// thread to operate the original. Unknown retains it without native Drop work.
unsafe impl Send for IdentityBook {}
impl Default for IdentityBook { fn default()->Self { Self::new() } }
impl IdentityBook {
    pub fn new()->Self { Self { pointer:None,report:IdentityReport { version:1,..IdentityReport::default() },
        phase:None,cell:CellCustody::Absent,entered:false,in_call:false,in_gate:false,unknown:false,closed:false,first:None } }
    pub fn project_owned_upper_bound()->Option<usize> { 1024_usize.checked_add(std::mem::size_of::<Self>()) }
    pub fn custody(&self)->IdentityCustody { IdentityCustody { phase:self.phase,cell:self.cell,references:self.report.states,
        entered:self.entered,in_call:self.in_call,gate_entered:self.in_gate,verified:self.report.verified==1,
        failed:self.report.failed==1,unknown:self.unknown||self.in_call||self.in_gate||self.report.unknown==1,first_failure:self.first } }
    fn note(&mut self,at:Instant) { self.first=Some(self.first.map_or(at,|first|first.min(at))); }
    fn unknown(&mut self,at:Instant)->IdentityResult { self.note(at);self.unknown=true;IdentityResult::Unknown }
    fn point(&mut self,phase:IdentityPhase,at:Option<Instant>,gate:&mut dyn FnMut(IdentityCheckpoint)->Decision)->Decision {
        self.phase=Some(phase);let custody=self.custody();self.in_gate=true;
        let result=gate(match at { Some(at)=>IdentityCheckpoint::Returned { phase,at,custody },
            None=>IdentityCheckpoint::Before { phase,custody } });self.in_gate=false;result
    }
    fn work_point(&mut self,phase:IdentityPhase,at:Option<Instant>,gate:&mut dyn FnMut(IdentityCheckpoint)->Decision)->bool {
        match self.point(phase,at,gate) {
            Decision::Proceed=>true,Decision::Stop=>{self.note(at.unwrap_or_else(Instant::now));false},
            _=>{self.unknown(at.unwrap_or_else(Instant::now));false},
        }
    }
    fn stopped(&self)->IdentityResult { if self.unknown {IdentityResult::Unknown}else{IdentityResult::Refused} }
    pub fn check_once(&mut self,gate:&mut dyn FnMut(IdentityCheckpoint)->Decision)->IdentityResult {
        if self.entered || self.closed || self.pointer.is_some() || self.in_call || self.in_gate || self.unknown {
            return self.unknown(Instant::now());
        }
        self.entered=true;
        if !signing_profile_configured() { return IdentityResult::Unavailable; }
        if !self.work_point(IdentityPhase::AllocateCell,None,gate) { return self.stopped(); }
        self.cell=CellCustody::Entering;self.in_call=true;
        // SAFETY: fixed no-argument allocator, no caller-selected identity.
        let pointer=unsafe { mrk_android_signing_new() };let at=Instant::now();self.in_call=false;
        self.pointer=NonNull::new(pointer);self.cell=if self.pointer.is_some(){CellCustody::Owned}else{CellCustody::Absent};
        if self.pointer.is_none() { self.note(at); }
        if !self.work_point(IdentityPhase::AllocateCell,Some(at),gate) || self.pointer.is_none() { return self.stopped(); }
        for number in 1..=17 {
            let phase=IdentityPhase::Inspect(number);
            if !self.work_point(phase,None,gate) { return self.stopped(); }
            let Some(pointer)=self.pointer else { return self.unknown(Instant::now()); };
            let mut raw=IdentityReport::default();self.in_call=true;
            // SAFETY: same exclusively borrowed original; native verifies the
            // exact thread and next phase, writes only the fixed report cell.
            let returned=unsafe { mrk_android_signing_step(pointer.as_ptr(),u32::from(number),&mut raw) };
            let at=Instant::now();self.in_call=false;
            if returned!=1 || !identity_report(raw,self.report,phase) { return self.unknown(at); }
            self.report=raw;
            if raw.failed==1 { self.note(at); }
            if raw.unknown==1 { self.unknown=true; }
            let proceed=self.work_point(phase,Some(at),gate);
            if !proceed || raw.failed==1 || self.unknown { return self.stopped(); }
        }
        if self.report.verified==1 { IdentityResult::Verified } else { self.unknown(Instant::now()) }
    }
    /// Cleanup never Defer/WAITs. Caller still owns the immutable W/H/F and
    /// imports native first-F BEFORE deciding each actual cleanup admission.
    pub fn settle(&mut self,gate:&mut dyn FnMut(IdentityCheckpoint)->Decision)->bool {
        if self.unknown || self.in_call || self.in_gate || self.report.unknown==1 { return false; }
        if self.closed { return self.settled(); }
        if self.pointer.is_none() { self.closed=true;return self.settled(); }
        for number in (0..12).rev() {
            if self.report.states[number]!=2 { continue; }
            let phase=IdentityPhase::Release(number as u8);
            if self.point(phase,None,gate)!=Decision::Proceed { self.unknown(Instant::now());return false; }
            let Some(pointer)=self.pointer else { self.unknown(Instant::now());return false; };
            let mut raw=IdentityReport::default();self.in_call=true;
            // SAFETY: exact same retained native slot; no duplicate release.
            let returned=unsafe { mrk_android_signing_release(pointer.as_ptr(),number as u32,&mut raw) };
            let at=Instant::now();self.in_call=false;
            if returned!=1 || !identity_report(raw,self.report,phase) { self.unknown(at);return false; }
            self.report=raw;if raw.unknown==1 { self.unknown=true;self.note(at); }
            if self.point(phase,Some(at),gate)!=Decision::Proceed || self.unknown { self.unknown(at);return false; }
        }
        let phase=IdentityPhase::RetireCell;
        if self.point(phase,None,gate)!=Decision::Proceed { self.unknown(Instant::now());return false; }
        let Some(pointer)=self.pointer else { self.unknown(Instant::now());return false; };
        self.in_call=true;
        // SAFETY: native consumes only the exact empty, returned original.
        let returned=unsafe { mrk_android_signing_retire(pointer.as_ptr()) };
        let at=Instant::now();self.in_call=false;
        if returned==1 { self.pointer=None;self.cell=CellCustody::Consumed; }
        else { self.cell=CellCustody::Unknown;self.unknown=true;self.note(at); }
        if self.point(phase,Some(at),gate)!=Decision::Proceed || self.unknown { self.unknown(at);return false; }
        self.closed=true;self.settled()
    }
    pub fn settled(&self)->bool { self.closed && !self.unknown && !self.in_call && !self.in_gate
        && self.pointer.is_none() && matches!(self.cell,CellCustody::Absent|CellCustody::Consumed)
        && self.report.unknown==0 && self.report.calls==self.report.returned
        && self.report.states.iter().all(|state|matches!(*state,0|4)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_report_requires_exact_phase_slot_and_consuming_return() {
        assert_eq!(std::mem::size_of::<IdentityReport>(),80);
        let old=IdentityReport { version:1,..IdentityReport::default() };
        let mut acquired=IdentityReport { version:1,phase:1,calls:1,returned:1,..IdentityReport::default() };
        acquired.states[0]=2;
        assert!(identity_report(acquired,old,IdentityPhase::Inspect(1)));
        for bad in [IdentityReport { verified:1,..acquired },IdentityReport { phase:2,..acquired },
            IdentityReport { returned:0,..acquired },IdentityReport { calls:2,..acquired },
            IdentityReport { states:[0;12],..acquired }] {
            assert!(!identity_report(bad,old,IdentityPhase::Inspect(1)));
        }
        let mut released=IdentityReport { phase:32,calls:2,returned:2,..acquired };
        released.states[0]=4;
        assert!(identity_report(released,acquired,IdentityPhase::Release(0)));
        assert!(!identity_report(released,released,IdentityPhase::Release(0)));
        assert!(!identity_report(IdentityReport { states:acquired.states,..released },acquired,IdentityPhase::Release(0)));
        let unknown=IdentityReport { failed:1,unknown:1,returned:0,..acquired };
        assert!(identity_report(unknown,old,IdentityPhase::Inspect(1))); // retained Unknown only
        assert!(!identity_report(IdentityReport { failed:0,..unknown },old,IdentityPhase::Inspect(1)));
    }
    #[test]
    fn denied_service_request_is_separate_from_approval_and_requires_real_mutation_return() {
        let denied=Report { version:2,action:1,status:0,outcome:9,entered:1,returned:1,
            phase:4,service_state:2,called:1,..Report::default() };
        let observation=decode(denied,Action::RequestRegistration,Phase::Mutate).unwrap();
        assert_eq!(observation.outcome,Outcome::DeniedByUser);
        assert!(observation.mutation_entered && observation.mutation_returned);
        for bad in [Report { returned:0,..denied },Report { action:0,..denied },Report { outcome:10,..denied }] {
            assert!(decode(bad,Action::RequestRegistration,Phase::Mutate).is_none());
        }
        let approval=Report { status:2,outcome:4,entered:0,returned:0,phase:3,..denied };
        assert_eq!(decode(approval,Action::RequestRegistration,Phase::ObserveStatus).unwrap().outcome,Outcome::NeedsApproval);
    }
    #[derive(Default)]
    struct NativeData {
        report:Report,entries:Vec<Phase>,bad_mutation_return:bool,error_status:bool,
        refused_status:bool,nil_acquire:bool,unentered_retired:bool,
        reservation_refused_at:Option<Phase>,bad_retire:bool,
    }
    impl Native for NativeData {
        fn allocate(&mut self,action:u32)->*mut c_void {
            self.entries.push(Phase::AllocateCell);
            self.report=Report { version:2,action,status:4,..Report::default() };
            NonNull::<u8>::dangling().as_ptr().cast()
        }
        fn step(&mut self,_pointer:*mut c_void,phase:u32,output:&mut Report)->c_int {
            let stage=match phase { 2=>Phase::AcquireService,3=>Phase::ObserveStatus,
                4=>Phase::Mutate,5=>Phase::ObserveResult,6=>Phase::ReleaseService,_=>panic!("not a fixed phase") };
            self.entries.push(stage);self.report.phase=phase;self.report.called=1;
            match stage {
                Phase::AcquireService=>{
                    if self.nil_acquire { self.report.service_state=4;self.report.outcome=7; }
                    else { self.report.service_state=2; }
                },
                Phase::ObserveStatus=>{
                    self.report.status=0;self.report.outcome=if self.report.action==0 { 1 } else { 0 };
                    if self.error_status { self.report.status=5;self.report.outcome=7; }
                    if self.refused_status { self.report.status=3;self.report.outcome=6; }
                },
                Phase::Mutate=>{
                    self.report.entered=1;self.report.returned=1;
                    self.report.outcome=if self.report.action==2 { 5 } else { 2 };
                },
                Phase::ObserveResult=>self.report.status=1,
                Phase::ReleaseService=>{ self.report.service_state=4;self.report.cleanup_known=1; },
                _=>unreachable!(),
            }
            if self.reservation_refused_at==Some(stage) {
                assert!(matches!(stage,Phase::AcquireService|Phase::Mutate));
                self.report.entered=0;self.report.returned=0;self.report.outcome=6;
                if stage==Phase::AcquireService {self.report.service_state=4;}
            }
            *output=self.report;
            if self.bad_mutation_return && stage==Phase::Mutate { 0 } else { 1 }
        }
        fn retire(&mut self,_pointer:*mut c_void,unentered:bool)->c_int {
            self.entries.push(Phase::RetireCell);self.unentered_retired=unentered;
            if unentered { assert_eq!(self.report.called,0);assert_eq!(self.report.service_state,0); }
            else { assert_eq!(self.report.phase,6);assert_eq!(self.report.service_state,4); }
            i32::from(!self.bad_retire)
        }
    }
    #[test]
    fn deferred_admission_retains_one_cell_and_resumes_only_that_original() {
        let mut manager=ServiceManager::new();let mut native=NativeData::default();
        assert_eq!(manager.perform_with(Action::Observe,&mut |point| match point {
            Checkpoint::Before { phase:Phase::AdmitAction,.. }=>Decision::Defer,_=>Decision::Proceed,
        },&mut native),Progress::Deferred);
        assert_eq!(native.entries,[Phase::AllocateCell]);
        assert_eq!(manager.custody().cell,CellCustody::Owned);
        assert!(!manager.custody().action_admitted);
        let result=manager.perform_with(Action::Observe,&mut |_|Decision::Proceed,&mut native);
        assert!(matches!(result,Progress::Finished(Observation { outcome:Outcome::Observed,native_settled:true,.. })));
        assert_eq!(native.entries.iter().filter(|phase|**phase==Phase::AllocateCell).count(),1);
        assert_eq!(manager.custody().cell,CellCustody::Consumed);
    }
    #[test]
    fn work_stop_never_enters_the_next_phase_and_uses_real_unentered_retirement() {
        for stopped in [Phase::AcquireService,Phase::ObserveStatus,Phase::Mutate,Phase::ObserveResult] {
            let mut manager=ServiceManager::new();let mut native=NativeData::default();
            let result=manager.perform_with(Action::RequestRegistration,&mut |point| match point {
                Checkpoint::Before { phase,.. } if phase==stopped=>Decision::Stop,_=>Decision::Proceed,
            },&mut native);
            assert!(matches!(result,Progress::Finished(Observation { outcome:Outcome::Stopped,native_settled:true,.. })));
            assert!(!native.entries.contains(&stopped));
            assert_eq!(native.unentered_retired,stopped==Phase::AcquireService);
            assert_eq!(native.entries.last(),Some(&Phase::RetireCell));
            if stopped==Phase::ObserveResult {
                // Cancellation does not erase the already returned native result.
                assert_eq!(manager.custody().observation.unwrap().outcome,Outcome::RegistrationRequested);
                assert!(manager.custody().observation.unwrap().mutation_returned);
            }
        }
    }
    #[test]
    fn late_consuming_returns_clear_only_real_custody_and_never_enter_another_phase() {
        for late in [Phase::ReleaseService,Phase::RetireCell] {
            let mut manager=ServiceManager::new();let mut native=NativeData::default();
            let result=manager.perform_with(Action::Observe,&mut |point| match point {
                Checkpoint::Returned { phase,.. } if phase==late=>Decision::Stop,_=>Decision::Proceed,
            },&mut native);
            assert!(matches!(result,Progress::Unknown(_)));
            assert_eq!(native.entries.last(),Some(&late));
            assert_eq!(manager.custody().cell,if late==Phase::RetireCell { CellCustody::Consumed } else { CellCustody::Owned });
            assert_eq!(manager.custody().service,ServiceCustody::Settled);
            let entries=native.entries.clone();
            assert!(matches!(manager.perform_with(Action::Observe,&mut |_|Decision::Proceed,&mut native),Progress::Unknown(_)));
            assert_eq!(native.entries,entries);
        }
    }
    #[test]
    fn malformed_mutation_return_is_uncertain_not_nonentry_and_cannot_cleanup_or_retry() {
        let mut manager=ServiceManager::new();
        let mut native=NativeData { bad_mutation_return:true,..NativeData::default() };
        let result=manager.perform_with(Action::RequestRegistration,&mut |_|Decision::Proceed,&mut native);
        assert!(matches!(result,Progress::Unknown(Observation { mutation_uncertain:true,.. })));
        assert_eq!(native.entries.last(),Some(&Phase::Mutate));
        assert_eq!(manager.custody().cell,CellCustody::Owned);
        assert_eq!(manager.custody().service,ServiceCustody::Unknown);
    }
    #[test]
    fn cleanup_denial_happens_before_native_entry_and_retains_actual_originals() {
        for denied in [Phase::ReleaseService,Phase::RetireCell] {
            let mut manager=ServiceManager::new();let mut native=NativeData::default();
            let result=manager.perform_with(Action::Observe,&mut |point| match point {
                Checkpoint::Before { phase,.. } if phase==denied=>Decision::Stop,_=>Decision::Proceed,
            },&mut native);
            assert!(matches!(result,Progress::Unknown(_)));
            assert!(!native.entries.contains(&denied));
            assert_eq!(manager.custody().cell,CellCustody::Owned);
            assert_eq!(manager.custody().service,if denied==Phase::ReleaseService { ServiceCustody::Owned } else { ServiceCustody::Settled });
        }
    }
    #[test]
    fn actual_native_failure_precedes_return_callback_and_all_cleanup_gates() {
        for action in [Action::RequestRegistration,Action::OpenApprovalSettings] {
            for refused in [Phase::AcquireService,Phase::Mutate] {
                let mut manager=ServiceManager::new();
                let mut native=NativeData {reservation_refused_at:Some(refused),..NativeData::default()};
                let result=manager.perform_with(action,&mut |_|Decision::Proceed,&mut native);
                assert!(matches!(result,Progress::Finished(Observation {outcome:Outcome::Refused,
                    mutation_entered:false,mutation_returned:false,native_settled:true,..})));
                assert!(!native.entries.contains(&Phase::ObserveResult));
                if refused==Phase::AcquireService {assert!(!native.entries.contains(&Phase::Mutate));}
                assert_eq!(native.entries.last(),Some(&Phase::RetireCell));
                assert_eq!(manager.custody().cell,CellCustody::Consumed);
            }
        }
        // Native reservation-close uncertainty is a refused cell consumption,
        // not permission to allocate/retry another action through the same TLS.
        let mut manager=ServiceManager::new();
        let mut native=NativeData {bad_retire:true,..NativeData::default()};
        assert!(matches!(manager.perform_with(Action::RequestRegistration,&mut |_|Decision::Proceed,&mut native),Progress::Unknown(_)));
        assert_eq!(manager.custody().cell,CellCustody::Unknown);
        let entries=native.entries.clone();
        assert!(matches!(manager.perform_with(Action::RequestRegistration,&mut |_|Decision::Proceed,&mut native),Progress::Unknown(_)));
        assert_eq!(native.entries,entries);
        for expected in [Outcome::Error,Outcome::Refused] {
            let mut manager=ServiceManager::new();
            let mut native=NativeData {
                error_status:expected==Outcome::Error,refused_status:expected==Outcome::Refused,
                ..NativeData::default()
            };
            let mut first=None;
            let result=manager.perform_with(Action::RequestRegistration,&mut |point| {
                match point {
                    Checkpoint::Returned { phase:Phase::ObserveStatus,at,custody }=>{
                        assert_eq!(custody.first_failure,Some(at));first=Some(at);
                    },
                    Checkpoint::Before { phase,custody } if phase.is_cleanup()=>{
                        assert!(first.is_some());assert_eq!(custody.first_failure,first);
                    },
                    _=>{},
                }
                Decision::Proceed
            },&mut native);
            assert!(matches!(result,Progress::Finished(Observation { outcome,native_settled:true,.. }) if outcome==expected));
            assert!(!native.entries.contains(&Phase::Mutate) && !native.entries.contains(&Phase::ObserveResult));
            assert_eq!(manager.custody().first_failure,first);
        }
    }
    #[test]
    fn nil_acquisition_stopped_on_return_consumes_real_empty_release_before_retire() {
        let mut manager=ServiceManager::new();
        let mut native=NativeData { nil_acquire:true,..NativeData::default() };
        let mut first=None;
        let result=manager.perform_with(Action::RequestRegistration,&mut |point| match point {
            Checkpoint::Returned { phase:Phase::AcquireService,at,custody }=>{
                assert_eq!(custody.service,ServiceCustody::Settled);
                assert_eq!(custody.first_failure,Some(at));first=Some(at);
                Decision::Stop
            },
            Checkpoint::Before { phase,custody } if phase.is_cleanup()=>{
                assert!(first.is_some());assert_eq!(custody.first_failure,first);
                Decision::Proceed
            },
            _=>Decision::Proceed,
        },&mut native);
        assert!(matches!(result,Progress::Finished(Observation { outcome:Outcome::Stopped,native_settled:true,.. })));
        assert_eq!(native.entries,[Phase::AllocateCell,Phase::AcquireService,Phase::ReleaseService,Phase::RetireCell]);
        assert!(!native.unentered_retired);
        assert_eq!(manager.custody().cell,CellCustody::Consumed);
        assert_eq!(manager.custody().service,ServiceCustody::Settled);
        assert_eq!(manager.custody().observation.unwrap().outcome,Outcome::Error);
        assert_eq!(manager.custody().first_failure,first);
    }
    #[test]
    fn callback_panic_after_retire_retains_unknown_ledger_not_a_freed_pointer() {
        let mut manager=ServiceManager::new();let mut native=NativeData::default();
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            manager.perform_with(Action::Observe,&mut |point| {
                if matches!(point,Checkpoint::Returned { phase:Phase::RetireCell,.. }) { panic!("return lost"); }
                Decision::Proceed
            },&mut native)
        }));
        assert!(result.is_err());
        assert_eq!(manager.custody().cell,CellCustody::Consumed);
        assert!(manager.custody().gate_entered && manager.custody().unknown);
        let entries=native.entries.clone();
        assert!(matches!(manager.perform_with(Action::Observe,&mut |_|Decision::Proceed,&mut native),Progress::Unknown(_)));
        assert_eq!(entries,native.entries);
    }
    #[test]
    fn native_report_cannot_fabricate_authority_or_inconsistent_phase_success() {
        // A refused R admission is not a registration call or successful
        // cleanup. Observe/Unregister never gain this registration-only shape.
        for action in [Action::RequestRegistration,Action::OpenApprovalSettings] {
            let acquired=Report {version:2,action:action.code(),status:4,outcome:6,
                phase:2,service_state:4,called:1,..Report::default()};
            let actual=decode(acquired,action,Phase::AcquireService).unwrap();
            assert_eq!(actual.outcome,Outcome::Refused);
            assert!(!actual.mutation_entered && !actual.mutation_returned && !actual.native_settled);
            let refused=Report {status:0,phase:4,service_state:2,..acquired};
            assert_eq!(decode(refused,action,Phase::Mutate).unwrap().outcome,Outcome::Refused);
            for bad in [Report {entered:1,..refused},Report {returned:1,..refused},
                Report {service_state:4,..refused},Report {cleanup_known:1,..refused},
                Report {status:4,..refused},Report {status:5,..refused}] {
                assert!(decode(bad,action,Phase::Mutate).is_none());
            }
            assert!(decode(Report {action:0,..acquired},Action::Observe,Phase::AcquireService).is_none());
            assert!(decode(refused,Action::UnregisterAfterQuiescence,Phase::Mutate).is_none());
        }
        assert_eq!(std::mem::size_of::<Report>(),if cfg!(feature="e2-native-fixture") {64}else{48});
        let observed=Report { version:2,action:0,status:1,outcome:1,phase:3,service_state:2,called:1,..Report::default() };
        let result=decode(observed,Action::Observe,Phase::ObserveStatus).unwrap();
        assert_eq!(result.status,Status::Enabled);
        assert!(!result.native_settled && !result.mutation_entered);
        for raw in [Report { entered:1,..observed },Report { outcome:8,..observed },
            Report { cleanup_known:1,..observed },Report { reserved:1,..observed },
            Report { service_state:5,..observed },Report { outcome:0,..observed }] {
            assert!(decode(raw,Action::Observe,Phase::ObserveStatus).is_none());
        }
        assert!(decode(observed,Action::RequestRegistration,Phase::ObserveStatus).is_none());
        for (status,outcome) in [(1,3),(2,4)] {
            let raw=Report { action:1,status,outcome,..observed };
            let result=decode(raw,Action::RequestRegistration,Phase::ObserveStatus).unwrap();
            assert!(!result.mutation_entered && !result.mutation_returned && !result.native_settled);
            assert!(decode(raw,Action::OpenApprovalSettings,Phase::ObserveStatus).is_none());
        }
    }
}

#[cfg(test)]
mod maintenance_report_tests{
    use super::*;
    #[test]
    fn bool_error_exception_and_version_are_independent_facts(){
        let good=Report{version:3,action:3,status:1,outcome:10,entered:1,returned:1,
            phase:4,service_state:2,called:1,reserved:3,..Report::default()};
        assert_eq!(decode(good,Action::UnregisterAfterQuiescence,Phase::Mutate).unwrap().outcome,Outcome::UnregisterAccepted);
        for bits in [1,5,7]{let failed=Report{reserved:bits,outcome:7,..good};
            assert_eq!(decode(failed,Action::UnregisterAfterQuiescence,Phase::Mutate).unwrap().outcome,Outcome::Error);}
        for bits in [0,2,4,6,16]{assert!(decode(Report{reserved:bits,..good},Action::UnregisterAfterQuiescence,Phase::Mutate).is_none());}
        assert!(decode(Report{version:2,..good},Action::UnregisterAfterQuiescence,Phase::Mutate).is_none());
        assert!(decode(good,Action::RequestRegistration,Phase::Mutate).is_none());
        let thrown=Report{outcome:8,returned:0,unknown:1,reserved:8,..good};
        assert!(decode(thrown,Action::UnregisterAfterQuiescence,Phase::Mutate).unwrap().mutation_uncertain);
        let final_status=Report{phase:5,status:0,..good};
        assert_eq!(decode(final_status,Action::UnregisterAfterQuiescence,Phase::ObserveResult).unwrap().status,Status::NotRegistered);
    }
}

#[cfg(all(test,feature="e2-native-fixture"))]
mod fixture_identity_bridge_tests {
    use super::*;
    unsafe extern "C" {
        fn mrk_e2_fixture_main_epoch_admits(rechecked:u32,spent:u32)->c_int;
    }
    #[test]
    fn actual_main_epoch_predicate_rejects_unrechecked_and_already_spent_data() {
        // Tests the SAME pure C comparison used by main_borrow, not a Rust
        // duplicate. Preparation->epoch0 and call-site binding are separately
        // source-reviewed; this DATA unit is not native-original qualification.
        for (checked,spent,expected) in [
            (0,0,0),(1,0,1),(1,1,0),(2,1,1),(1,2,0),(0,u32::MAX,0),(u32::MAX,u32::MAX,0),
        ] {
            assert_eq!(unsafe{mrk_e2_fixture_main_epoch_admits(checked,spent)},expected);
        }
    }
    #[test]
    fn callback_panic_and_defer_are_caught_before_the_c_boundary() {
        let mut panic_gate=|_:FixtureIdentityCheckpoint|->Decision {panic!("synthetic callback failure")};
        let mut bridge=FixtureGate{gate:&mut panic_gate,poisoned:false};
        let raw=(&mut bridge as *mut FixtureGate<'_>).cast();
        assert_eq!(unsafe{fixture_identity_point(raw,1,0,0,1,0)},2);
        assert!(bridge.poisoned);
        assert_eq!(unsafe{fixture_identity_point(raw,1,1,0,2,0)},2);
        let mut defer=|_:FixtureIdentityCheckpoint|Decision::Defer;
        let mut bridge=FixtureGate{gate:&mut defer,poisoned:false};
        assert_eq!(unsafe{fixture_identity_point((&mut bridge as *mut FixtureGate<'_>).cast(),1,0,0,1,0)},2);
        assert!(bridge.poisoned);
        assert!(FixtureMainIdentity::project_owned_upper_bound().is_some());
    }
}
