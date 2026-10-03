//! Original fixed service-management phases, not IPC or toolchain authority.
//! The app supplies one T/W/H/F gate and queues this !Send manager ONLY from its
//! original non-main coordinator into the verified framework AppKit callback.
//! No nested app-owned pool, automatic registration, Drop cleanup or UI park.
use std::{ffi::{c_int,c_void},marker::PhantomData,ptr::NonNull,rc::Rc,time::Instant};

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Status { NotRegistered,Enabled,RequiresApproval,NotFound,Unavailable,Error }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Action { Observe,RequestRegistration,OpenApprovalSettings }
impl Action {
    fn code(self)->u32 { match self { Self::Observe=>0,Self::RequestRegistration=>1,Self::OpenApprovalSettings=>2 } }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Outcome { NotEntered,Observed,RegistrationRequested,AlreadyRegistered,NeedsApproval,
    SettingsRequested,Refused,Error,Unknown,Stopped }
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

#[repr(C)]
#[derive(Clone,Copy,Debug,Default)]
struct Report {
    version:u32,action:u32,status:u32,outcome:u32,entered:u32,returned:u32,cleanup_known:u32,unknown:u32,
    phase:u32,service_state:u32,called:u32,reserved:u32,
}
fn decode(raw:Report,action:Action,phase:Phase)->Option<Observation> {
    if raw.version!=2 || raw.action!=action.code() || Some(raw.phase)!=phase.code()
        || raw.status>5 || raw.outcome>8 || raw.entered>1 || raw.returned>raw.entered
        || raw.cleanup_known>1 || raw.unknown>1 || raw.called!=1 || raw.reserved!=0
        || raw.service_state>5
        || (raw.unknown==1)!=(raw.outcome==8)
        || raw.unknown==1 && (raw.cleanup_known!=0 || raw.outcome!=8)
        || action==Action::Observe && (raw.entered!=0 || raw.returned!=0)
        || raw.unknown==0 && matches!(raw.service_state,0|1|3|5) { return None; }
    if matches!(phase,Phase::AcquireService|Phase::ObserveStatus) && raw.entered!=0 { return None; }
    if raw.unknown==0 {
        if phase==Phase::ReleaseService {
            if raw.cleanup_known!=1 || raw.service_state!=4 { return None; }
        } else if raw.cleanup_known!=0 { return None; }
        match phase {
            Phase::AcquireService if raw.status!=4 || raw.entered!=0 || raw.returned!=0
                || !((raw.service_state==2 && raw.outcome==0)
                    || (raw.service_state==4 && raw.outcome==7)) => return None,
            Phase::ObserveStatus if raw.service_state!=2 || raw.entered!=0 || raw.returned!=0
                || raw.status==4 => return None,
            Phase::Mutate if raw.service_state!=2 || raw.entered!=1 || raw.returned!=1
                || action==Action::Observe => return None,
            Phase::ObserveResult if raw.service_state!=2 || raw.entered!=1 || raw.returned!=1
                || action!=Action::RequestRegistration || raw.status==4 => return None,
            _=>{},
        }
        if phase==Phase::ObserveStatus {
            let expected=if raw.status==5 { 7 } else { match action {
                Action::Observe=>1,Action::OpenApprovalSettings=>0,
                Action::RequestRegistration=>match raw.status { 0=>0,1=>3,2=>4,3=>6,_=>return None },
            } };
            if raw.outcome!=expected { return None; }
        }
        if phase==Phase::Mutate && match action {
            Action::RequestRegistration=>raw.status!=0 || !matches!(raw.outcome,2|3|4|7),
            Action::OpenApprovalSettings=>raw.status>3 || raw.outcome!=5,
            Action::Observe=>true,
        } { return None; }
        if phase==Phase::ObserveResult
            && (!matches!(raw.outcome,2|3|4|7) || raw.status==5 && raw.outcome!=7) { return None; }
    }
    let status=match raw.status { 0=>Status::NotRegistered,1=>Status::Enabled,2=>Status::RequiresApproval,
        3=>Status::NotFound,4=>Status::Unavailable,_=>Status::Error };
    let outcome=match raw.outcome { 0=>Outcome::NotEntered,1=>Outcome::Observed,2=>Outcome::RegistrationRequested,
        3=>Outcome::AlreadyRegistered,4=>Outcome::NeedsApproval,5=>Outcome::SettingsRequested,
        6=>Outcome::Refused,7=>Outcome::Error,_=>Outcome::Unknown };
    if outcome==Outcome::Observed && action!=Action::Observe
        || matches!(outcome,Outcome::RegistrationRequested|Outcome::AlreadyRegistered|Outcome::NeedsApproval)
            && action!=Action::RequestRegistration
        || outcome==Outcome::SettingsRequested && action!=Action::OpenApprovalSettings
        || matches!(outcome,Outcome::RegistrationRequested|Outcome::SettingsRequested) && raw.returned!=1 {
        return None;
    }
    Some(Observation { action,status,outcome,mutation_entered:raw.entered==1,
        mutation_returned:raw.returned==1,mutation_uncertain:raw.unknown==1 && raw.entered==1 && raw.returned==0,
        native_settled:false })
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
/// Persistent TLS original. Unknown retains its actual pointer/ledger and
/// denies another allocation. It never enters cleanup from Drop or after H.
pub struct ServiceManager {
    pointer:Option<NonNull<c_void>>,active:Option<Action>,next:Phase,report:Report,
    observation:Option<Observation>,action_admitted:bool,cell:CellCustody,service:ServiceCustody,
    in_call:bool,in_gate:bool,unknown:bool,stopped:bool,deferred:bool,first:Option<Instant>,
    _main:PhantomData<Rc<()>>,
}
impl Default for ServiceManager { fn default()->Self { Self::new() } }
impl ServiceManager {
    pub fn new()->Self { Self {
        pointer:None,active:None,next:Phase::AllocateCell,report:Report::default(),observation:None,
        action_admitted:false,cell:CellCustody::Absent,service:ServiceCustody::NotAcquired,
        in_call:false,in_gate:false,unknown:false,stopped:false,deferred:false,first:None,_main:PhantomData,
    } }
    /// Supplied C cell + complete Rust owner only, not framework/RSS storage.
    pub fn project_owned_upper_bound()->Option<usize> { 1024_usize.checked_add(std::mem::size_of::<Self>()) }
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
        self.perform_with(action,gate,&mut Calls)
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
            self.report=Report { version:2,action:action.code(),status:4,..Report::default() };
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
                raw.entered>=self.report.entered && raw.returned>=self.report.returned
            });
            if let Some(observation)=decoded {
                self.report=raw;self.observation=Some(observation);
                self.service=match raw.service_state {
                    2=>ServiceCustody::Owned,4=>ServiceCustody::Settled,_=>ServiceCustody::Unknown,
                };
                if matches!(observation.outcome,Outcome::Refused|Outcome::Error|Outcome::Unknown) { self.note(at); }
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
                Phase::Mutate if action==Action::RequestRegistration=>Phase::ObserveResult,
                Phase::ReleaseService=>Phase::RetireCell,
                _=>Phase::ReleaseService,
            } };
        }
        self.mark_unknown(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct NativeData {
        report:Report,entries:Vec<Phase>,bad_mutation_return:bool,error_status:bool,
        refused_status:bool,nil_acquire:bool,unentered_retired:bool,
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
            *output=self.report;
            if self.bad_mutation_return && stage==Phase::Mutate { 0 } else { 1 }
        }
        fn retire(&mut self,_pointer:*mut c_void,unentered:bool)->c_int {
            self.entries.push(Phase::RetireCell);self.unentered_retired=unentered;
            if unentered { assert_eq!(self.report.called,0);assert_eq!(self.report.service_state,0); }
            else { assert_eq!(self.report.phase,6);assert_eq!(self.report.service_state,4); }
            1
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
        assert_eq!(std::mem::size_of::<Report>(),48);
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
