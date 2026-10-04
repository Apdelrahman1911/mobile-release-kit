//! Fixed nonshipping E2 native fixture. One original main, one owned client
//! worker per case, and no runtime case/path/environment selector.
//!
//! This module proves only the fixed synthetic fixture route. It never enables
//! production IdentityBook, app integration, overlap, or a shipping package.
//! All unresolved native/population/capture/join ownership parks in place.
//! The outer existing run_owned (990s work / 993s hard) remains authoritative.
use crate::{
    android_maintenance_client::{Client,Drain,Progress as ClientProgress,TailAdmission,FixtureClientObservation},
    android_maintenance_wire::{self as wire,Binding,Frame,Kind,Identity},
    android_registration::{Bounds,Signal,FrozenFailure,FixtureClientCustody,
        FixtureIdentityFacts,FixtureIdentityCustody},
    android_service_management::{self as management,Action,Status,Outcome,Phase,Checkpoint,
        Decision,Progress as MainProgress,Observation,Custody,CellCustody,ServiceCustody,
        ServiceManager,FixtureMainIdentity,FixtureIdentityCheckpoint,FixtureIdentityOutcome},
    vault_helper_wire::{ClockBridge,uptime},
};
use nix::libc;
use std::{
    any::Any,
    mem::{size_of,ManuallyDrop},
    panic::{catch_unwind,AssertUnwindSafe},
    sync::{Arc,Mutex,OnceLock,TryLockError,atomic::{AtomicBool,Ordering}},
    thread::{self,JoinHandle},
    time::{Duration,Instant},
};

const AUXILIARY_NS:u64=60_000_000_000;
const RESULT_BYTES:usize=32_768;
const WORKER_STACK_BYTES:usize=512*1024;
const PROJECT_BYTES_MAX:usize=2*1024*1024;
const IDENTITY_PROVIDER_BYTES:usize=24_576;
const IDENTITY_EXTRA_BYTES:usize=65_536;
const POLL:Duration=Duration::from_millis(2);
const RETAIN_POLL:Duration=Duration::from_secs(1);
const TARGET:&str="aarch64-apple-darwin";
// Same fixed provider ABI; actual header phases are independently source-bound.
const POOL_ALLOCATE:u32=management::FIXTURE_IDENTITY_POOL_ALLOCATE;
const POOL_INIT:u32=management::FIXTURE_IDENTITY_POOL_INIT;
const POOL_DRAIN:u32=management::FIXTURE_IDENTITY_POOL_DRAIN;
static ENTERED:AtomicBool=AtomicBool::new(false);

fn retain_unknown()->! { loop { thread::park_timeout(RETAIN_POLL); } }
fn raw_after(last:u64)->Option<u64> {
    let now=uptime()?;
    (now!=0 && now>=last && now<=wire::MAX_RAW).then_some(now)
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Case { MissingB,LocalF,Genuine }
impl Case {
    fn name(self)->&'static str { match self {
        Self::MissingB=>"missing-b-refused",
        Self::LocalF=>"local-f-before-admission",
        Self::Genuine=>"genuine-tail-unregister",
    } }
}
const CASES:[Case;3]=[Case::MissingB,Case::LocalF,Case::Genuine];
#[derive(Clone,Copy,PartialEq,Eq)]
enum ResultKind { Passed,Failed,Unavailable,Unexecuted }
impl ResultKind {
    fn text(self)->&'static str { match self {
        Self::Passed=>"passed",Self::Failed=>"failed",Self::Unavailable=>"unavailable",Self::Unexecuted=>"unexecuted",
    } }
    fn exit_code(self)->Option<i32> { match self {
        Self::Passed=>Some(0),Self::Failed=>Some(1),Self::Unavailable=>Some(77),Self::Unexecuted=>None,
    } }
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Closed { NotEntered,ReturnedEmpty,Settled }
impl Closed {
    fn text(self)->&'static str { match self {
        Self::NotEntered=>"not-entered",Self::ReturnedEmpty=>"returned-empty",Self::Settled=>"settled",
    } }
}
fn merge_closed(left:Closed,right:Closed)->Closed {
    if left==Closed::Settled || right==Closed::Settled { Closed::Settled }
    else if left==Closed::ReturnedEmpty || right==Closed::ReturnedEmpty { Closed::ReturnedEmpty }
    else { Closed::NotEntered }
}
fn identity_closed(value:FixtureIdentityCustody)->Option<Closed> { match value {
    FixtureIdentityCustody::NotEntered=>Some(Closed::NotEntered),
    FixtureIdentityCustody::ReturnedEmpty=>Some(Closed::ReturnedEmpty),
    FixtureIdentityCustody::Settled=>Some(Closed::Settled),
    FixtureIdentityCustody::Unresolved=>None,
} }
fn client_closed(value:FixtureClientCustody)->Option<Closed> {
    if value.unknown || !value.settled || !value.native.settled() { return None; }
    if !value.allocation_entered {
        return (!value.allocation_returned && !value.allocated && !value.consumed
            && value.native.entered==0).then_some(Closed::NotEntered);
    }
    if !value.allocation_returned { return None; }
    if !value.allocated { return (!value.consumed && value.native.entered==0).then_some(Closed::ReturnedEmpty); }
    value.consumed.then_some(Closed::Settled)
}

struct Build { source:&'static str,release:&'static str,identity:Identity }
impl Build {
    fn fixed()->Option<Self> {
        let source=option_env!("MRK_IMAGE_SOURCE_COMMIT")?;
        let release=option_env!("MRK_IMAGE_RELEASE_ID")?;
        if source.len()!=40 || source.bytes().all(|b|b==b'0')
            || !source.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || release.is_empty() || release.len()>63
            || !release.bytes().all(|b|b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b,b'_'|b'.'|b'-')) {
            return None;
        }
        Some(Self { source,release,identity:Identity::build()? })
    }
}

#[derive(Clone,Copy,PartialEq,Eq)]
enum LedgerPhase { Auxiliary,ProtocolCase }
/// One invocation-wide ledger. ProtocolCase freezes expenditure, not the
/// original raw monotonic history. Re-entry resumes the SAME remaining amount.
struct Auxiliary { phase:LedgerPhase,last:u64,remaining:u64,spent:u64,deadline:u64,valid:bool }
impl Auxiliary {
    fn new(now:u64)->Option<Self> {
        let deadline=now.checked_add(AUXILIARY_NS)?;
        (now!=0 && deadline<=wire::MAX_RAW).then_some(Self {
            phase:LedgerPhase::Auxiliary,last:now,remaining:AUXILIARY_NS,spent:0,deadline,valid:true,
        })
    }
    fn at(&mut self,now:u64)->bool {
        if !self.valid || now==0 || now<self.last || now>wire::MAX_RAW { self.valid=false; return false; }
        let elapsed=now-self.last;
        self.last=now;
        if self.phase==LedgerPhase::Auxiliary {
            let Some(remaining)=self.remaining.checked_sub(elapsed) else { self.valid=false; return false; };
            let Some(spent)=self.spent.checked_add(elapsed) else { self.valid=false; return false; };
            self.remaining=remaining; self.spent=spent;
            if spent>AUXILIARY_NS || remaining==0 || now>=self.deadline { self.valid=false; return false; }
        }
        true
    }
    fn sample(&mut self)->Option<u64> {
        let now=uptime()?;
        self.at(now).then_some(now)
    }
    fn auxiliary(&mut self)->Option<u64> {
        if self.phase!=LedgerPhase::Auxiliary { self.valid=false; return None; }
        self.sample()
    }
    fn begin_protocol(&mut self,origin:u64)->bool {
        if self.phase!=LedgerPhase::Auxiliary || !self.at(origin) { return false; }
        self.phase=LedgerPhase::ProtocolCase; true
    }
    fn resume(&mut self,now:u64)->bool {
        if self.phase!=LedgerPhase::ProtocolCase || !self.at(now) { return false; }
        let Some(deadline)=now.checked_add(self.remaining).filter(|end|*end<=wire::MAX_RAW) else {
            self.valid=false; return false;
        };
        self.deadline=deadline; self.phase=LedgerPhase::Auxiliary; true
    }
}

#[derive(Default)]
struct PoolTrace {
    allocate_returned:bool,acquired:bool,init_returned:bool,initialized:bool,
    drain_returned:bool,consumed:bool,unknown:bool,
}
impl PoolTrace {
    fn returned(&mut self,point:&FixtureIdentityCheckpoint)->bool {
        if !point.returned { return true; }
        let success=matches!(point.outcome,FixtureIdentityOutcome::Success);
        let unknown=matches!(point.outcome,FixtureIdentityOutcome::Unknown);
        match point.phase {
            POOL_ALLOCATE=>{
                if self.allocate_returned { return false; }
                self.allocate_returned=true; self.acquired=success; self.unknown|=unknown;
            },
            POOL_INIT=>{
                if !self.acquired || self.init_returned { return false; }
                self.init_returned=true; self.initialized=success; self.unknown|=unknown;
            },
            POOL_DRAIN=>{
                if !self.acquired || self.drain_returned { return false; }
                self.drain_returned=true; self.consumed=success; self.unknown|=unknown;
            },
            _=>{},
        }
        true
    }
    fn closed(&self,facts:FixtureIdentityFacts)->Option<Closed> {
        if self.unknown || !facts.valid() || facts.unknown!=0 || facts.in_call!=0 { return None; }
        if !self.allocate_returned {
            return (facts.pool==0 && !self.acquired && !self.init_returned && !self.drain_returned)
                .then_some(Closed::NotEntered);
        }
        if !self.acquired {
            return (facts.pool==6 && !self.init_returned && !self.drain_returned).then_some(Closed::ReturnedEmpty);
        }
        (self.drain_returned && self.consumed && facts.pool==6).then_some(Closed::Settled)
    }
}

#[derive(Default)]
struct ActionRecord {
    invoked:bool,finished:bool,allocation_returned:bool,allocated:bool,consumed:bool,
    service_acquired:bool,service_released:bool,mutation_entered:bool,mutation_returned:bool,
    mutation_uncertain:bool,unregistered:bool,unknown:bool,
    before:Option<(Phase,Instant)>,last:Option<Observation>,positive_unregister:Option<Observation>,
}
impl ActionRecord {
    fn returned(&mut self,phase:Phase,at:Instant,custody:Custody)->bool {
        if self.before.is_none_or(|(before,start)|before!=phase || at<start)
            || custody.in_call || custody.gate_entered { return false; }
        match phase {
            Phase::AllocateCell=>{
                if self.allocation_returned { return false; }
                self.allocation_returned=true;
                self.allocated=match custody.cell {
                    CellCustody::Owned=>true,CellCustody::Absent=>false,_=>return false,
                };
            },
            Phase::AcquireService=>{
                self.service_acquired|=custody.service==ServiceCustody::Owned;
            },
            Phase::ReleaseService=>{
                self.service_released|=custody.service==ServiceCustody::Settled;
            },
            Phase::RetireCell=>{
                if self.consumed { return false; }
                self.consumed=custody.cell==CellCustody::Consumed;
            },
            _=>{},
        }
        self.unknown|=custody.unknown;
        if let Some(observed)=custody.observation {
            self.mutation_entered|=observed.mutation_entered;
            self.mutation_returned|=observed.mutation_returned;
            self.mutation_uncertain|=observed.mutation_uncertain;
            self.last=Some(observed);
            if observed.action==Action::UnregisterAfterQuiescence && observed.outcome==Outcome::UnregisterAccepted {
                // Positive SAME-ACTION data survives any later failed release.
                self.positive_unregister=Some(observed);
                if phase==Phase::ObserveResult && observed.status==Status::NotRegistered
                    && observed.mutation_entered && observed.mutation_returned && !observed.mutation_uncertain {
                    self.unregistered=true;
                }
            }
        }
        true
    }
    fn closed(&self)->Option<Closed> {
        if !self.invoked { return Some(Closed::NotEntered); }
        if !self.finished || self.unknown || self.mutation_uncertain { return None; }
        if !self.allocation_returned {
            return (!self.allocated && !self.consumed && !self.service_acquired).then_some(Closed::NotEntered);
        }
        if !self.allocated {
            return (!self.consumed && !self.service_acquired).then_some(Closed::ReturnedEmpty);
        }
        (self.consumed && (!self.service_acquired || self.service_released)).then_some(Closed::Settled)
    }
}

struct Gate<'a> {
    auxiliary:&'a mut Auxiliary,clock:&'a ClockBridge,signal:Option<&'a Signal>,
    admission:Option<&'a TailAdmission>,force_cleanup:bool,start:u64,
    first:&'a mut Option<u64>,unknown:&'a mut bool,pool:&'a mut PoolTrace,
}
impl Gate<'_> {
    fn fail_unknown(&mut self)->Decision {
        *self.unknown=true;
        if let Some(signal)=self.signal { signal.failure_now(true); }
        Decision::Unknown
    }
    fn fail_clock(&mut self)->Decision {
        *self.unknown=true;
        if let Some(signal)=self.signal { signal.clock_unknown(); }
        Decision::Unknown
    }
    fn first_at(&mut self,at:u64,unknown:bool)->bool {
        if at<self.start || at>self.auxiliary.last || at==0 || at>wire::MAX_RAW { return false; }
        *self.first=Some(self.first.map_or(at,|old|old.min(at)));
        if let Some(signal)=self.signal {
            if signal.bounds().is_none_or(|bounds|at<bounds.origin) { return false; }
            signal.failure_at(at,unknown);
        }
        true
    }
    fn admit(&mut self,cleanup:bool,returned:Option<Instant>)->Decision {
        if *self.unknown { return Decision::Unknown; }
        let Some(now)=self.auxiliary.sample() else { return self.fail_clock(); };
        let instant=Instant::now();
        if returned.is_some_and(|at|at>instant) { return self.fail_unknown(); }
        if self.auxiliary.phase==LedgerPhase::Auxiliary {
            if self.signal.is_some() || self.admission.is_some() { return self.fail_unknown(); }
            return Decision::Proceed;
        }
        let Some(signal)=self.signal else { return self.fail_unknown(); };
        let cleanup=cleanup || self.force_cleanup;
        let tail_time=self.admission.is_none_or(|admission| {
            instant<admission.cutoff() && returned.is_none_or(|at|at<admission.cutoff())
        });
        if !tail_time {
            signal.failure_at(now,false);
            return if cleanup { self.fail_unknown() } else { Decision::Stop };
        }
        if signal.admitted_at(cleanup,now) { Decision::Proceed }
        else if cleanup || signal.unknown() { self.fail_unknown() }
        else { Decision::Stop }
    }
    fn identity(&mut self,point:FixtureIdentityCheckpoint)->Decision {
        if !(1..=13).contains(&point.phase) || !self.pool.returned(&point) { return self.fail_unknown(); }
        if !self.auxiliary.at(point.raw_ns) { return self.fail_clock(); }
        if point.returned {
            match point.outcome {
                FixtureIdentityOutcome::Success=>{},
                FixtureIdentityOutcome::Failure=>{
                    if !self.first_at(point.raw_ns,false) { return self.fail_unknown(); }
                },
                FixtureIdentityOutcome::Unknown=>{
                    let _=self.first_at(point.raw_ns,true);
                    return self.fail_unknown();
                },
            }
        }
        let decision=self.admit(point.cleanup,None);
        if decision!=Decision::Proceed { return decision; }
        if point.returned && matches!(point.outcome,FixtureIdentityOutcome::Failure) && !point.cleanup {
            Decision::Stop
        } else { Decision::Proceed }
    }
    fn management(&mut self,point:Checkpoint,record:&mut ActionRecord)->Decision {
        let (phase,returned,custody)=match point {
            Checkpoint::Before { phase,custody }=>(phase,None,custody),
            Checkpoint::Returned { phase,at,custody }=>(phase,Some(at),custody),
        };
        if let Some(at)=returned {
            if !record.returned(phase,at,custody) { return self.fail_unknown(); }
        }
        let Some(now)=self.auxiliary.sample() else { return self.fail_clock(); };
        if let Some(at)=custody.first_failure {
            let Some(first)=self.clock.earlier_endpoint(at) else { return self.fail_unknown(); };
            if first>now || !self.first_at(first,custody.unknown) { return self.fail_unknown(); }
        }
        if custody.unknown { return self.fail_unknown(); }
        let decision=self.admit(phase.is_cleanup(),returned);
        if returned.is_none() && decision==Decision::Proceed {
            record.before=Some((phase,Instant::now()));
        }
        decision
    }
}

#[derive(Clone,Copy,PartialEq,Eq)]
enum Go { Protocol,Cancel }
/// The only cross-thread owning slot. It can contain one REAL TailAdmission;
/// no Clone, serialization, bool permission, or second connection is available.
struct Offer {
    kind:Case,observation:FixtureClientObservation,identity:FixtureIdentityFacts,
    local_failure:Option<u64>,admission:Option<TailAdmission>,
}
#[derive(Default)]
struct OfferSlot { published:bool,taken:bool,value:Option<Offer> }
#[derive(Clone,Copy)]
struct ReturnedAction {
    kind:Case,operation:[u8;16],fixture_cleanup:bool,
    manager_settled:bool,unregistered:bool,admission_retired:bool,
}
struct Shared {
    go:OnceLock<Go>,offer:Mutex<OfferSlot>,returned:OnceLock<ReturnedAction>,
}
impl Shared {
    fn new()->Self { Self { go:OnceLock::new(),offer:Mutex::new(OfferSlot::default()),returned:OnceLock::new() } }
}
enum WorkerReport {
    Cancelled { returned_ns:u64 },
    Settled { returned_ns:u64,observation:FixtureClientObservation,
        identity:FixtureIdentityFacts,identity_custody:FixtureIdentityCustody },
}
struct Worker {
    kind:Case,operation:[u8;16],signal:Arc<Signal>,clock:Arc<ClockBridge>,shared:Arc<Shared>,
    auxiliary_deadline:u64,last:u64,client:Option<Client>,offer:Option<Offer>,
    pending_admission:Option<TailAdmission>,
    panic:Option<Box<dyn Any+Send>>,
}
impl Worker {
    fn protocol(&mut self,cleanup:bool)->Option<u64> {
        let now=match raw_after(self.last) {
            Some(now)=>now,None=>{self.signal.clock_unknown();return None;},
        };
        self.last=now;
        self.signal.admitted_at(cleanup,now).then_some(now)
    }
    fn wait_go(&mut self)->Option<Go> {
        loop {
            let now=raw_after(self.last)?; self.last=now;
            if let Some(go)=self.shared.go.get().copied() {
                if go==Go::Protocol {
                    // T was armed on the original Signal BEFORE this GO.
                    let bounds=self.signal.bounds()?;
                    if bounds.origin>=self.auxiliary_deadline || !self.signal.admitted_at(false,now) { return None; }
                } else if now>=self.auxiliary_deadline || self.signal.bounds().is_some() { return None; }
                return Some(go);
            }
            // Arm precedes GO. Observing that tiny interval is not a lost GO
            // and grants no native entry; only its original clock bounds wait.
            if let Some(bounds)=self.signal.bounds() {
                if bounds.origin>=self.auxiliary_deadline || !self.signal.admitted_at(false,now) { return None; }
            } else if now>=self.auxiliary_deadline { return None; }
            thread::park_timeout(POLL);
        }
    }
    fn publish_offer(&mut self)->Option<()> {
        if self.offer.is_none() { return None; }
        loop {
            self.protocol(true)?;
            let posted={
                match self.shared.offer.try_lock() {
                    Ok(mut slot)=>{
                        if slot.published || slot.taken || slot.value.is_some() { return None; }
                        slot.value=self.offer.take(); slot.published=true; true
                    },
                    Err(TryLockError::WouldBlock)=>false,
                    Err(TryLockError::Poisoned(_))=>{self.signal.failure_now(true);return None;},
                }
            };
            self.protocol(true)?;
            if posted { return Some(()); }
            thread::park_timeout(POLL);
        }
    }
    fn wait_action(&mut self)->Option<ReturnedAction> {
        loop {
            self.protocol(true)?;
            if let Some(returned)=self.shared.returned.get().copied() {
                let fixture_cleanup=self.kind!=Case::Genuine;
                if returned.kind!=self.kind || returned.operation!=self.operation
                    || returned.fixture_cleanup!=fixture_cleanup || !returned.manager_settled
                    || returned.admission_retired!=(self.kind==Case::Genuine) { return None; }
                return Some(returned);
            }
            thread::park_timeout(POLL);
        }
    }
    fn run(&mut self)->Option<WorkerReport> {
        // This is the one original native worker, never the ServiceManager lane.
        if unsafe { libc::pthread_main_np() }!=0 { return None; }
        if self.wait_go()?==Go::Cancel {
            if self.client.is_some() || self.offer.is_some() { return None; }
            let now=raw_after(self.last)?;
            if now>=self.auxiliary_deadline { return None; }
            self.last=now;
            return Some(WorkerReport::Cancelled { returned_ns:now });
        }
        self.protocol(false)?;
        self.client=Some(Client::new(Arc::clone(&self.signal),self.operation)?);
        self.protocol(false)?;
        let mut local_failure=None;
        if self.kind==Case::MissingB {
            self.client.as_mut()?.fixture_begin_missing_b().ok()?;
            self.protocol(false)?;
        } else {
            let drain=self.client.as_mut()?.begin().ok()?;
            self.protocol(false)?;
            if drain!=Drain::Started { return None; }
            loop {
                self.protocol(true)?;
                let step=self.client.as_mut()?.step().ok()?;
                self.protocol(true)?;
                match step {
                    ClientProgress::TailReceived=>break,
                    ClientProgress::Pending=>thread::park_timeout(POLL),
                    ClientProgress::Exited=>return None,
                }
            }
            let observation=self.client.as_ref()?.fixture_observation();
            let frame=Frame::decode(&observation.tail?)?;
            if frame.kind!=Kind::Tail || frame.tail?.first!=0 || Some(frame.binding)!=observation.binding
                || observation.eof || observation.exited || observation.admission_issued { return None; }
            let now=self.protocol(false)?;
            if self.signal.snapshot().first.is_some() || self.signal.unknown() { return None; }
            if self.kind==Case::LocalF {
                // A LOCAL actual raw observation on the SAME Signal, before
                // the FIRST admission attempt. No replacement signal/reset.
                self.signal.failure_at(now,false); local_failure=Some(now);
                self.pending_admission=self.client.as_mut()?.take_tail_admission(&self.clock);
                self.protocol(true)?;
            } else {
                self.pending_admission=self.client.as_mut()?.take_tail_admission(&self.clock);
                self.protocol(false)?;
            }
        }
        let observation=self.client.as_ref()?.fixture_observation();
        let identity=self.client.as_ref()?.fixture_identity_facts();
        if !identity.valid() || identity.unknown!=0 || identity.in_call!=0 || identity.ready!=1 { return None; }
        self.offer=Some(Offer { kind:self.kind,observation,identity,local_failure,admission:self.pending_admission.take() });
        // A surprisingly issued admission on LocalF remains owned in offer
        // on failure; it is not dropped/relabelled as an empty negative.
        let offered=self.offer.as_ref()?;
        let valid=match self.kind {
            Case::MissingB=>offered.observation.refused && offered.observation.watch_registered
                && offered.observation.tail.is_none() && offered.admission.is_none()
                && !offered.observation.admission_issued && !offered.observation.eof && !offered.observation.exited,
            Case::LocalF=>offered.admission.is_none() && !offered.observation.admission_issued
                && self.signal.first()==local_failure && local_failure.is_some() && !self.signal.unknown(),
            Case::Genuine=>offered.admission.as_ref().is_some_and(|value|value.operation()==self.operation)
                && offered.observation.admission_issued && self.signal.first().is_none() && !self.signal.unknown(),
        };
        if !valid { self.signal.failure_now(true); return None; }
        self.publish_offer()?;
        let returned=self.wait_action()?;
        // Returned action DATA is not exit/EOF proof and never issues another
        // admission. Even a negative result must observe the original peer.
        loop {
            self.protocol(true)?;
            let exited=if self.kind==Case::MissingB {
                self.client.as_mut()?.fixture_no_tail_exit().ok()?
            } else {
                self.client.as_mut()?.step().ok()?==ClientProgress::Exited
            };
            self.protocol(true)?;
            if exited { break; }
            thread::park_timeout(POLL);
        }
        let before_release=self.client.as_ref()?.fixture_observation();
        if !before_release.watch_registered || !before_release.exited
            || (self.kind==Case::MissingB && (before_release.eof || before_release.tail.is_some()))
            || (self.kind!=Case::MissingB && (!before_release.eof || before_release.tail.is_none()))
            || self.client.as_ref()?.final_observed()!=(self.kind==Case::Genuine) { return None; }
        // This original release consumes the same native slots, request DATA
        // and saved identity attachment. The actual main admission is already
        // retired, so the same-DATA exclusivity check can genuinely succeed.
        self.protocol(true)?;
        if !self.client.as_mut()?.release() { return None; }
        let now=self.protocol(true)?;
        if !self.client.as_ref()?.settled() { return None; }
        let observation=self.client.as_ref()?.fixture_observation();
        let identity=self.client.as_ref()?.fixture_identity_facts();
        let identity_custody=self.client.as_ref()?.fixture_identity_custody();
        if client_closed(observation.custody)!=Some(Closed::Settled)
            || !identity.valid() || identity.custody()!=identity_custody
            || identity_closed(identity_custody)!=Some(Closed::Settled) { return None; }
        // A later main result failure is retained by the main's action record.
        // No returned boolean here replaces its same-action positive custody.
        let _=returned.unregistered;
        Some(WorkerReport::Settled { returned_ns:now,observation,identity,identity_custody })
    }
}
fn worker_entry(worker:Worker)->WorkerReport {
    // The frame containing every original survives panic/unresolved work.
    let mut worker=ManuallyDrop::new(worker);
    match catch_unwind(AssertUnwindSafe(||worker.run())) {
        Ok(Some(report)) if worker.offer.is_none() && worker.pending_admission.is_none()
            && worker.client.as_ref().is_none_or(Client::settled)=>{
            // Only settled Client fields and ordinary Rust DATA remain. This
            // actual return still is NOT the main's required JoinHandle::join.
            unsafe { ManuallyDrop::drop(&mut worker); }
            report
        },
        Err(payload)=>{worker.panic=Some(payload);retain_unknown();},
        _=>retain_unknown(),
    }
}


// Main-only orchestration. The four records describe distinct actual manager
// invocations; the two unregister lanes never share an attempted/entered flag.
const OBSERVE:usize=0;
const REGISTER:usize=1;
const TESTED_UNREGISTER:usize=2;
const FIXTURE_CLEANUP:usize=3;

#[derive(Clone,Copy)]
struct Resources { main:Closed,client:Closed,identity:Closed,worker_joined:bool }
impl Resources {
    const fn unentered()->Self { Self { main:Closed::NotEntered,client:Closed::NotEntered,
        identity:Closed::NotEntered,worker_joined:false } }
    fn passed(self)->bool {
        self.main==Closed::Settled && self.client==Closed::Settled
            && self.identity==Closed::Settled && self.worker_joined
    }
}
#[derive(Clone,Copy)]
struct Row {
    kind:Case,outcome:ResultKind,started:u64,finished:u64,first:Option<u64>,
    operation:Option<[u8;16]>,binding:Option<Binding>,tail:Option<[u8;wire::BYTES]>,
    registered:bool,watch:bool,refused:bool,admission_issued:bool,
    tested_entered:bool,cleanup_entered:bool,eof:bool,note_exit:bool,resources:Resources,
}
impl Row {
    const fn unexecuted(kind:Case)->Self { Self {
        kind,outcome:ResultKind::Unexecuted,started:0,finished:0,first:None,
        operation:None,binding:None,tail:None,registered:false,watch:false,refused:false,
        admission_issued:false,tested_entered:false,cleanup_entered:false,eof:false,
        note_exit:false,resources:Resources::unentered(),
    } }
    fn data_valid(&self,build:&Build)->bool {
        if self.outcome==ResultKind::Unexecuted {
            return self.started==0 && self.finished==0 && self.first.is_none()
                && self.operation.is_none() && self.binding.is_none() && self.tail.is_none()
                && !self.registered && !self.watch && !self.refused && !self.admission_issued
                && !self.tested_entered && !self.cleanup_entered && !self.eof && !self.note_exit
                && self.resources.main==Closed::NotEntered && self.resources.client==Closed::NotEntered
                && self.resources.identity==Closed::NotEntered && !self.resources.worker_joined;
        }
        if self.started==0 || self.finished<self.started || self.finished>wire::MAX_RAW
            || self.first.is_some_and(|first|first<self.started || first>self.finished)
            || self.operation.is_some_and(|value|value==[0;16])
            || self.watch && !self.registered { return false; }
        if let Some(binding)=self.binding {
            if !binding.identity().valid() || !binding.identity().same_build(build.identity)
                || Some(binding.operation)!=self.operation { return false; }
        }
        if self.outcome!=ResultKind::Passed { return true; }
        if !self.resources.passed() || !self.registered || !self.watch || !self.note_exit
            || self.operation.is_none() || self.binding.is_none() { return false; }
        let binding=self.binding.expect("the preceding fixed DATA check");
        match self.kind {
            Case::MissingB=>binding.challenge_valid() && self.refused && self.tail.is_none()
                && self.first.is_none() && !self.admission_issued && !self.tested_entered
                && self.cleanup_entered && !self.eof,
            Case::LocalF|Case::Genuine=>{
                let Some(raw)=self.tail.as_ref() else { return false; };
                let Some(frame)=Frame::decode(raw) else { return false; };
                if frame.kind!=Kind::Tail || frame.binding!=binding
                    || frame.tail.is_none_or(|tail|tail.first!=0) || self.refused || !self.eof { return false; }
                if self.kind==Case::LocalF {
                    self.first.is_some() && !self.admission_issued && !self.tested_entered && self.cleanup_entered
                } else {
                    self.first.is_none() && self.admission_issued && self.tested_entered && !self.cleanup_entered
                }
            },
        }
    }
}

/// This capability is neither a TailAdmission nor a public unregister API. It
/// can be made only from this exact absent->own registered service pair, and it
/// permits one distinct fixture cleanup invocation in either negative case.
struct OwnFixtureRegistration { kind:Case,operation:[u8;16],cleanup_taken:bool }
impl OwnFixtureRegistration {
    fn from_returned(kind:Case,operation:[u8;16],observe:&ActionRecord,register:&ActionRecord,
        actual:Observation)->Option<Self> {
        let before=observe.last?;
        (observe.finished && observe.closed()==Some(Closed::Settled)
            && before.action==Action::Observe && before.outcome==Outcome::Observed
            && before.status==Status::NotRegistered && !before.mutation_entered
            && !before.mutation_returned && !before.mutation_uncertain
            && register.finished && register.closed()==Some(Closed::Settled)
            && actual.action==Action::RequestRegistration && actual.outcome==Outcome::RegistrationRequested
            && actual.status==Status::Enabled && actual.mutation_entered && actual.mutation_returned
            && !actual.mutation_uncertain && actual.native_settled
            && register.mutation_entered && register.mutation_returned && !register.mutation_uncertain)
            .then_some(Self { kind,operation,cleanup_taken:false })
    }
    fn take_cleanup(&mut self,kind:Case,operation:[u8;16])->bool {
        if self.kind!=kind || self.operation!=operation || kind==Case::Genuine || self.cleanup_taken { return false; }
        self.cleanup_taken=true;true
    }
}

/// The earlier Instant is comparison DATA retained after genuine admission
/// retirement; it never issues work permission. It keeps every later cleanup
/// checkpoint inside the SAME original tail window as the raw Signal.
fn identity_point(gate:&mut Gate<'_>,cutoff:Option<Instant>,point:FixtureIdentityCheckpoint)->Decision {
    if cutoff.is_some_and(|end|Instant::now()>=end) { return gate.fail_unknown(); }
    let returned=gate.identity(point);
    if cutoff.is_some_and(|end|Instant::now()>=end) { gate.fail_unknown() } else { returned }
}
fn manager_point(gate:&mut Gate<'_>,cutoff:Option<Instant>,point:Checkpoint,record:&mut ActionRecord)->Decision {
    if cutoff.is_some_and(|end|Instant::now()>=end) { return gate.fail_unknown(); }
    let returned=gate.management(point,record);
    if cutoff.is_some_and(|end|Instant::now()>=end) { gate.fail_unknown() } else { returned }
}
fn manager_idle(manager:&ServiceManager)->bool {
    let custody=manager.custody();
    custody.action.is_none() && !custody.in_call && !custody.gate_entered && !custody.unknown
        && matches!(custody.cell,CellCustody::Absent|CellCustody::Consumed)
        && matches!(custody.service,ServiceCustody::NotAcquired|ServiceCustody::Settled)
}

struct CaseOwner {
    kind:Case,started:u64,operation:[u8;16],signal:Arc<Signal>,shared:Arc<Shared>,
    identity:FixtureMainIdentity,pool:PoolTrace,records:[ActionRecord;4],
    worker:Option<JoinHandle<WorkerReport>>,worker_started:bool,worker_joined:bool,
    offered:Option<Offer>,admission:Option<TailAdmission>,admission_retired:bool,
    cutoff:Option<Instant>,registration:Option<OwnFixtureRegistration>,population_possible:bool,
    protocol_started:bool,first:Option<u64>,unknown:bool,tested_attempts:u8,cleanup_attempts:u8,
    settled:bool,panic:Option<Box<dyn Any+Send>>,
}
impl CaseOwner {
    fn new(kind:Case,started:u64,operation:[u8;16])->Self { Self {
        kind,started,operation,signal:Arc::new(Signal::reserved()),shared:Arc::new(Shared::new()),
        identity:FixtureMainIdentity::new(),pool:PoolTrace::default(),
        records:std::array::from_fn(|_|ActionRecord::default()),
        worker:None,worker_started:false,worker_joined:false,offered:None,admission:None,
        admission_retired:false,cutoff:None,registration:None,population_possible:false,
        protocol_started:false,first:None,unknown:false,tested_attempts:0,cleanup_attempts:0,
        settled:false,panic:None,
    } }
    fn protocol(&mut self,auxiliary:&mut Auxiliary,cleanup:bool)->Option<u64> {
        if !self.protocol_started || auxiliary.phase!=LedgerPhase::ProtocolCase || self.unknown { return None; }
        let now=auxiliary.sample()?;
        if self.cutoff.is_some_and(|end|Instant::now()>=end) { self.unknown=true; return None; }
        let FrozenFailure { first,cleanup:_,unknown }=self.signal.snapshot();
        if unknown { self.unknown=true; return None; }
        if let Some(first)=first {
            if first<self.started || first>now { self.unknown=true; return None; }
            self.first=Some(self.first.map_or(first,|old|old.min(first)));
        }
        self.signal.admitted_at(cleanup,now).then_some(now)
    }
    fn prepare_identity(&mut self,auxiliary:&mut Auxiliary,clock:&ClockBridge)->bool {
        let mut gate=Gate { auxiliary,clock,signal:None,admission:None,force_cleanup:false,
            start:self.started,first:&mut self.first,unknown:&mut self.unknown,pool:&mut self.pool };
        self.identity.prepare(false,&mut |point|identity_point(&mut gate,None,point))
    }
    fn action(&mut self,manager:&mut ServiceManager,auxiliary:&mut Auxiliary,clock:&ClockBridge,
        action:Action,index:usize,cleanup:bool)->Option<Observation> {
        if index>=self.records.len() || self.records[index].invoked || !manager_idle(manager) || self.unknown { return None; }
        let cutoff=self.cutoff;
        let mut gate=Gate { auxiliary,clock,signal:self.protocol_started.then_some(self.signal.as_ref()),
            admission:self.admission.as_ref(),force_cleanup:cleanup,start:self.started,
            first:&mut self.first,unknown:&mut self.unknown,pool:&mut self.pool };
        // A distinct recheck epoch on this held provider is mandatory for
        // EVERY manager allocation. prepare/feature readiness is not enough.
        if !self.identity.recheck(cleanup,&mut |point|identity_point(&mut gate,cutoff,point)) { return None; }
        let record=&mut self.records[index];
        record.invoked=true;
        let progress=manager.perform_fixture_phased(action,&mut self.identity,
            &mut |point|manager_point(&mut gate,cutoff,point,record));
        match progress {
            MainProgress::Finished(observation) if observation.native_settled && manager_idle(manager)=>{
                record.finished=true;
                record.closed()?;
                Some(observation)
            },
            _=>None,
        }
    }
    fn start_worker(&mut self,auxiliary:&mut Auxiliary,clock:&Arc<ClockBridge>)->bool {
        if self.worker_started || self.worker.is_some() || self.protocol_started { return false; }
        let Some(now)=auxiliary.auxiliary() else { return false; };
        let worker=Worker { kind:self.kind,operation:self.operation,signal:Arc::clone(&self.signal),
            clock:Arc::clone(clock),shared:Arc::clone(&self.shared),auxiliary_deadline:auxiliary.deadline,
            last:now,client:None,offer:None,pending_admission:None,panic:None };
        // No native Client exists in the captured inert Worker. A spawn error
        // may drop only ordinary reservation DATA, never acquired originals.
        match thread::Builder::new().stack_size(WORKER_STACK_BYTES).spawn(move||worker_entry(worker)) {
            Ok(handle)=>{self.worker=Some(handle);self.worker_started=true;auxiliary.auxiliary().is_some()},
            Err(_)=>false,
        }
    }
    fn arm_go(&mut self,auxiliary:&mut Auxiliary)->Option<()> {
        if !self.worker_started || self.worker.is_none() || self.protocol_started || self.first.is_some()
            || self.unknown || !self.population_possible || self.registration.is_none() { return None; }
        let origin=auxiliary.auxiliary()?;
        let bounds=Bounds { origin,work:origin.checked_add(wire::WORK_NS)?,hard:origin.checked_add(wire::HARD_NS)? };
        if !bounds.valid() || !auxiliary.begin_protocol(origin) { return None; }
        // T is armed on the ORIGINAL Signal before this sole Protocol GO.
        // Any failed arm/publication retains the already-created population.
        self.signal.arm(bounds).ok()?;
        self.protocol_started=true;
        self.protocol(auxiliary,false)?;
        self.shared.go.set(Go::Protocol).ok()?;
        self.protocol(auxiliary,false)?;
        Some(())
    }
    fn take_offer(&mut self,auxiliary:&mut Auxiliary)->Option<()> {
        if self.offered.is_some() || self.admission.is_some() { return None; }
        loop {
            self.protocol(auxiliary,true)?;
            let taken={
                match self.shared.offer.try_lock() {
                    Ok(mut slot)=>{
                        if slot.taken { return None; }
                        if slot.published {
                            if slot.value.is_none() { return None; }
                            // Transfer directly into the persistent owning
                            // frame; no temporary admission drops on failure.
                            self.offered=slot.value.take();slot.taken=true;true
                        } else {
                            if slot.value.is_some() { return None; }
                            false
                        }
                    },
                    Err(TryLockError::WouldBlock)=>false,
                    Err(TryLockError::Poisoned(_))=>{self.unknown=true;return None;},
                }
            };
            self.protocol(auxiliary,true)?;
            if taken { return Some(()); }
            thread::park_timeout(POLL);
        }
    }
}

impl CaseOwner {
    fn validate_offer(&mut self,auxiliary:&mut Auxiliary,clock:&ClockBridge,build:&Build,
        previous:&[Row],account:u32)->Option<()> {
        let now=self.protocol(auxiliary,true)?;
        let bounds=self.signal.bounds()?;
        let offered=self.offered.as_ref()?;
        let observation=offered.observation;
        let binding=observation.binding?;
        if offered.kind!=self.kind || binding.operation!=self.operation
            || binding.origin!=bounds.origin || binding.work!=bounds.work || binding.hard!=bounds.hard
            || binding.account!=account || !binding.identity().valid()
            || !binding.identity().same_build(build.identity)
            || previous.iter().any(|row|row.binding.is_some_and(|old|old.instance==binding.instance))
            || !observation.watch_registered || observation.eof || observation.exited
            || !offered.identity.valid() || offered.identity.role!=2 || offered.identity.ready!=1
            || offered.identity.allocated!=1 || offered.identity.consumed!=0
            || offered.identity.unknown!=0 || offered.identity.failed!=0 || offered.identity.in_call!=0
            || offered.identity.calls!=offered.identity.returns { return None; }
        match self.kind {
            Case::MissingB=>{
                if !binding.challenge_valid() || !observation.refused || observation.tail.is_some()
                    || observation.admission_issued || offered.admission.is_some()
                    || offered.local_failure.is_some() || self.signal.first().is_some() { return None; }
            },
            Case::LocalF|Case::Genuine=>{
                let frame=Frame::decode(&observation.tail?)?;
                let tail=frame.tail?;
                if frame.kind!=Kind::Tail || frame.binding!=binding || tail.first!=0
                    || observation.refused || now<tail.write_entered || now>=tail.cutoff { return None; }
                let cutoff=clock.earlier_instant_data(tail.cutoff)?;
                if cutoff<=Instant::now() { return None; }
                self.cutoff=Some(cutoff);
                if self.kind==Case::LocalF {
                    let first=offered.local_failure?;
                    if first<tail.write_entered || first>now || self.signal.first()!=Some(first)
                        || observation.admission_issued || offered.admission.is_some() { return None; }
                    self.first=Some(self.first.map_or(first,|old|old.min(first)));
                } else if offered.local_failure.is_some() || self.signal.first().is_some()
                    || !observation.admission_issued
                    || offered.admission.as_ref().is_none_or(|admission|
                        admission.operation()!=self.operation || admission.cutoff()!=cutoff) { return None; }
                let expected_cutoff=match self.signal.first() {
                    Some(first)=>tail.cutoff.min(first.checked_add(wire::CLEANUP_NS)?),
                    None=>tail.cutoff,
                };
                if self.signal.snapshot().cleanup!=Some(expected_cutoff) { return None; }
            },
        }
        // Only this move transfers the non-Clone same-DATA authority. A
        // copied binding, tail or earlier cutoff cannot authorize unregister.
        self.admission=self.offered.as_mut()?.admission.take();
        self.protocol(auxiliary,self.kind!=Case::Genuine)?;
        Some(())
    }
    fn unregister(&mut self,manager:&mut ServiceManager,auxiliary:&mut Auxiliary,clock:&ClockBridge)->Option<()> {
        let fixture_cleanup=self.kind!=Case::Genuine;
        let index=if fixture_cleanup {
            if self.admission.is_some() || self.tested_attempts!=0 || self.cleanup_attempts!=0
                || !self.registration.as_mut()?.take_cleanup(self.kind,self.operation) { return None; }
            self.cleanup_attempts=1;FIXTURE_CLEANUP
        } else {
            if self.cleanup_attempts!=0 || self.tested_attempts!=0
                || self.admission.as_ref().is_none_or(|admission|admission.operation()!=self.operation) { return None; }
            self.tested_attempts=1;TESTED_UNREGISTER
        };
        self.protocol(auxiliary,fixture_cleanup)?;
        let observation=self.action(manager,auxiliary,clock,Action::UnregisterAfterQuiescence,index,fixture_cleanup)?;
        self.protocol(auxiliary,true)?;
        if !observation.native_settled || self.records[index].closed()!=Some(Closed::Settled)
            || !manager_idle(manager) || self.identity.facts().borrow_count!=0 { return None; }
        // Preserve the SAME action's positive returned facts in records[index]
        // before any capture retirement, subsequent release, or failure.
        let unregistered=self.records[index].unregistered;
        if self.kind==Case::Genuine {
            self.protocol(auxiliary,true)?;
            let admission=self.admission.take()?;
            // This original consuming return must precede worker release,
            // which requires actual exclusive access to the same DATA arena.
            admission.retire();
            self.admission_retired=true;
            self.protocol(auxiliary,true)?;
        }
        let returned=ReturnedAction { kind:self.kind,operation:self.operation,fixture_cleanup,
            manager_settled:true,unregistered,admission_retired:self.admission_retired };
        if self.shared.returned.set(returned).is_err() { return None; }
        self.protocol(auxiliary,true)?;
        Some(())
    }
    fn join_worker(&mut self,auxiliary:&mut Auxiliary)->Option<WorkerReport> {
        if !self.worker_started || self.worker_joined || self.worker.is_none() { return None; }
        loop {
            if self.protocol_started { self.protocol(auxiliary,true)?; } else { auxiliary.auxiliary()?; }
            if self.worker.as_ref()?.is_finished() {
                // is_finished is only permission to attempt the ORIGINAL join.
                // The returned payload is neither a join nor native finality.
                let result=self.worker.take()?.join();
                self.worker_joined=true; // actual join returned, even on panic
                let report=match result {
                    Ok(report)=>report,
                    Err(payload)=>{self.panic=Some(payload);self.unknown=true;return None;},
                };
                let now=if self.protocol_started { self.protocol(auxiliary,true)? } else { auxiliary.auxiliary()? };
                let returned_ns=match &report {
                    WorkerReport::Cancelled{returned_ns}|WorkerReport::Settled{returned_ns,..}=>*returned_ns,
                };
                let lower=self.signal.bounds().map_or(self.started,|bounds|bounds.origin);
                if returned_ns<lower || returned_ns>now { self.unknown=true;return None; }
                return Some(report);
            }
            thread::park_timeout(POLL);
        }
    }
    fn cancel_worker(&mut self,auxiliary:&mut Auxiliary)->Option<()> {
        if self.protocol_started || self.population_possible || self.signal.bounds().is_some()
            || self.offered.is_some() || self.admission.is_some() { return None; }
        auxiliary.auxiliary()?;
        if !self.worker_started {
            return (self.worker.is_none() && !self.worker_joined && self.shared.go.get().is_none()).then_some(());
        }
        self.shared.go.set(Go::Cancel).ok()?;
        auxiliary.auxiliary()?;
        match self.join_worker(auxiliary)? {
            WorkerReport::Cancelled{..}=>Some(()),
            WorkerReport::Settled{..}=>None,
        }
    }
    fn close_identity(&mut self,manager:&ServiceManager,auxiliary:&mut Auxiliary,clock:&ClockBridge)->Option<Closed> {
        if !manager_idle(manager) || self.admission.is_some() || self.identity.facts().borrow_count!=0
            || self.worker.is_some() || self.worker_started!=self.worker_joined { return None; }
        for record in &self.records { record.closed()?; }
        let cutoff=self.cutoff;
        let mut gate=Gate { auxiliary,clock,signal:self.protocol_started.then_some(self.signal.as_ref()),
            admission:None,force_cleanup:true,start:self.started,first:&mut self.first,
            unknown:&mut self.unknown,pool:&mut self.pool };
        if !self.identity.close(true,&mut |point|identity_point(&mut gate,cutoff,point)) { return None; }
        let facts=self.identity.facts();
        let provider=identity_closed(self.identity.custody())?;
        let pool=self.pool.closed(facts)?;
        Some(merge_closed(provider,pool))
    }
    fn main_closed(&self)->Option<Closed> {
        let mut all=Closed::NotEntered;
        for record in &self.records { all=merge_closed(all,record.closed()?); }
        Some(all)
    }
    fn slots_final(&self,protocol:bool)->bool {
        if self.admission.is_some() || self.offered.as_ref().is_some_and(|offer|offer.admission.is_some()) { return false; }
        let Ok(slot)=self.shared.offer.try_lock() else { return false; };
        if slot.value.is_some() { return false; }
        if protocol {
            slot.published && slot.taken && self.shared.go.get()==Some(&Go::Protocol)
                && self.shared.returned.get().is_some()
        } else {
            !slot.published && !slot.taken && self.shared.returned.get().is_none()
                && self.shared.go.get().is_none_or(|go|*go==Go::Cancel)
        }
    }
    fn finish_pre_service(&mut self,manager:&ServiceManager,auxiliary:&mut Auxiliary,clock:&ClockBridge)->Option<Row> {
        // No receipt is allowed merely because registration failed: a real or
        // uncertain mutation, active manager or native ownership vetoes this.
        if self.protocol_started || self.population_possible || self.registration.is_some()
            || self.unknown || !manager_idle(manager)
            || self.records[REGISTER].mutation_entered || self.records[REGISTER].mutation_uncertain { return None; }
        self.cancel_worker(auxiliary)?;
        if !self.slots_final(false) { return None; }
        let identity=self.close_identity(manager,auxiliary,clock)?;
        let finished=auxiliary.auxiliary()?;
        if self.unknown || self.panic.is_some() { return None; }
        let row=Row { kind:self.kind,outcome:ResultKind::Unavailable,started:self.started,finished,first:self.first,
            operation:Some(self.operation),binding:None,tail:None,registered:false,watch:false,refused:false,
            admission_issued:false,tested_entered:false,cleanup_entered:false,eof:false,note_exit:false,
            resources:Resources { main:self.main_closed()?,client:Closed::NotEntered,identity,worker_joined:self.worker_joined } };
        self.settled=true;
        Some(row)
    }
    fn finish_protocol(&mut self,manager:&ServiceManager,auxiliary:&mut Auxiliary,clock:&ClockBridge)->Option<Row> {
        let report=self.join_worker(auxiliary)?;
        let WorkerReport::Settled { observation,identity:client_identity,identity_custody,.. }=report else { return None; };
        let offered=self.offered.as_ref()?;
        if observation.binding!=offered.observation.binding || observation.tail!=offered.observation.tail
            || observation.watch_registered!=offered.observation.watch_registered
            || observation.refused!=offered.observation.refused
            || observation.admission_issued!=offered.observation.admission_issued
            || !observation.exited || observation.eof!=(self.kind!=Case::MissingB)
            || client_closed(observation.custody)!=Some(Closed::Settled)
            || !client_identity.valid() || client_identity.role!=2 || client_identity.failed!=0
            || client_identity.calls<offered.identity.calls || client_identity.returns<offered.identity.returns
            || client_identity.allocation_entered!=offered.identity.allocation_entered
            || client_identity.allocation_returned!=offered.identity.allocation_returned
            || client_identity.allocated!=offered.identity.allocated
            || client_identity.custody()!=identity_custody
            || identity_closed(identity_custody)!=Some(Closed::Settled)
            || !self.slots_final(true) { return None; }
        let index=if self.kind==Case::Genuine { TESTED_UNREGISTER } else { FIXTURE_CLEANUP };
        if !self.records[index].unregistered || self.records[index].positive_unregister.is_none()
            || !self.population_possible || self.registration.is_none() { return None; }
        // Actual same-action unregister AND original peer exit, not service
        // status alone, discharge this invocation's registration population.
        self.population_possible=false;
        let main_identity=self.close_identity(manager,auxiliary,clock)?;
        let finished=self.protocol(auxiliary,true)?;
        let resources=Resources { main:self.main_closed()?,client:Closed::Settled,
            identity:merge_closed(main_identity,Closed::Settled),worker_joined:self.worker_joined };
        let expected_first=match self.kind {
            Case::LocalF=>self.offered.as_ref()?.local_failure,
            Case::MissingB|Case::Genuine=>None,
        };
        let counts=if self.kind==Case::Genuine {
            self.tested_attempts==1 && self.cleanup_attempts==0 && self.admission_retired
                && self.records[TESTED_UNREGISTER].mutation_entered && !self.records[FIXTURE_CLEANUP].mutation_entered
        } else {
            self.tested_attempts==0 && self.cleanup_attempts==1 && !self.admission_retired
                && !self.records[TESTED_UNREGISTER].mutation_entered && self.records[FIXTURE_CLEANUP].mutation_entered
        };
        let passed=resources.passed() && counts && self.first==expected_first && !self.unknown
            && self.signal.first()==expected_first && !self.signal.unknown();
        let row=Row { kind:self.kind,outcome:if passed {ResultKind::Passed}else{ResultKind::Failed},
            started:self.started,finished,first:self.first,operation:Some(self.operation),
            binding:observation.binding,tail:observation.tail,registered:true,watch:observation.watch_registered,
            refused:observation.refused,admission_issued:observation.admission_issued,
            tested_entered:self.records[TESTED_UNREGISTER].mutation_entered,
            cleanup_entered:self.records[FIXTURE_CLEANUP].mutation_entered,eof:observation.eof,note_exit:observation.exited,resources };
        // All original local/remote/capture/identity/join settlement precedes
        // resuming the original aggregate allowance. No new60s is created.
        if !auxiliary.resume(finished) { return None; }
        self.settled=true;
        Some(row)
    }
    fn run(&mut self,manager:&mut ServiceManager,auxiliary:&mut Auxiliary,clock:&Arc<ClockBridge>,
        build:&Build,previous:&[Row],account:u32)->Option<Row> {
        if !self.prepare_identity(auxiliary,clock) { return self.finish_pre_service(manager,auxiliary,clock); }
        if !self.start_worker(auxiliary,clock) { return self.finish_pre_service(manager,auxiliary,clock); }
        let observed=self.action(manager,auxiliary,clock,Action::Observe,OBSERVE,false);
        if observed.is_none_or(|value|value.outcome!=Outcome::Observed || value.status!=Status::NotRegistered
            || value.mutation_entered || value.mutation_returned || value.mutation_uncertain) {
            return self.finish_pre_service(manager,auxiliary,clock);
        }
        let registered=self.action(manager,auxiliary,clock,Action::RequestRegistration,REGISTER,false);
        self.population_possible=self.records[REGISTER].mutation_entered || self.records[REGISTER].mutation_uncertain
            || manager.custody().observation.is_some_and(|value|value.mutation_entered || value.mutation_uncertain);
        let Some(registered)=registered else { return self.finish_pre_service(manager,auxiliary,clock); };
        self.registration=OwnFixtureRegistration::from_returned(self.kind,self.operation,
            &self.records[OBSERVE],&self.records[REGISTER],registered);
        if self.registration.is_none() { return self.finish_pre_service(manager,auxiliary,clock); }
        self.arm_go(auxiliary)?;
        self.take_offer(auxiliary)?;
        self.validate_offer(auxiliary,clock,build,previous,account)?;
        self.unregister(manager,auxiliary,clock)?;
        self.finish_protocol(manager,auxiliary,clock)
    }
}


/// Fixed-capacity, allocation-free public DATA serializer. No raw native
/// errors, paths, account identifiers, framework messages or credentials enter.
struct ResultBuffer { bytes:[u8;RESULT_BYTES],used:usize }
impl ResultBuffer {
    fn new()->Self { Self {bytes:[0;RESULT_BYTES],used:0} }
    fn push(&mut self,value:&[u8])->Option<()> {
        let end=self.used.checked_add(value.len())?;
        if end>self.bytes.len() { return None; }
        self.bytes[self.used..end].copy_from_slice(value);self.used=end;Some(())
    }
    fn text(&mut self,value:&str)->Option<()> { self.push(value.as_bytes()) }
    fn string(&mut self,value:&str)->Option<()> {
        if !value.bytes().all(|byte|(32..=126).contains(&byte) && byte!=b'"' && byte!=b'\\') { return None; }
        self.text("\"")?;self.text(value)?;self.text("\"")
    }
    fn key(&mut self,value:&str)->Option<()> { self.string(value)?;self.text(":") }
    fn boolean(&mut self,value:bool)->Option<()> { self.text(if value {"true"}else{"false"}) }
    fn decimal(&mut self,value:u64)->Option<()> {
        if value>wire::MAX_RAW { return None; }
        let mut number=value;let mut bytes=[0_u8;20];let mut index=bytes.len();
        loop {
            index-=1;bytes[index]=b'0'+(number%10) as u8;number/=10;
            if number==0 { break; }
        }
        self.text("\"")?;self.push(&bytes[index..])?;self.text("\"")
    }
    fn hex(&mut self,value:Option<&[u8]>)->Option<()> {
        const HEX:&[u8;16]=b"0123456789abcdef";
        self.text("\"")?;
        if let Some(value)=value {
            for byte in value { self.push(&[HEX[(byte>>4) as usize],HEX[(byte&15) as usize]])?; }
        }
        self.text("\"")
    }
    fn case(&mut self,row:&Row)->Option<()> {
        self.text("{")?;
        self.key("case")?;self.string(row.kind.name())?;
        self.text(",")?;self.key("outcome")?;self.string(row.outcome.text())?;
        self.text(",")?;self.key("startedNs")?;self.decimal(row.started)?;
        self.text(",")?;self.key("finishedNs")?;self.decimal(row.finished)?;
        self.text(",")?;self.key("firstFailureNs")?;self.decimal(row.first.unwrap_or(0))?;
        self.text(",")?;self.key("operationHex")?;self.hex(row.operation.as_ref().map(|value|value.as_slice()))?;
        self.text(",")?;self.key("instanceHex")?;self.hex(row.binding.as_ref().map(|value|value.instance.as_slice()))?;
        self.text(",")?;self.key("tailHex")?;self.hex(row.tail.as_ref().map(|value|value.as_slice()))?;
        for (key,value) in [
            ("registered",row.registered),("watchRegistered",row.watch),("refused",row.refused),
            ("tailAdmissionIssued",row.admission_issued),("testedUnregisterEntered",row.tested_entered),
            ("fixtureCleanupUnregisterEntered",row.cleanup_entered),("eof",row.eof),("noteExit",row.note_exit),
            ("mainReturned",row.resources.main!=Closed::NotEntered),("mainClosed",row.resources.main==Closed::Settled),
            ("clientClosed",row.resources.client==Closed::Settled),("workerJoined",row.resources.worker_joined),
            ("identityClosed",row.resources.identity==Closed::Settled),
        ] {
            self.text(",")?;self.key(key)?;self.boolean(value)?;
        }
        self.text(",")?;self.key("resourceStates")?;self.text("{")?;
        self.key("main")?;self.string(row.resources.main.text())?;
        self.text(",")?;self.key("client")?;self.string(row.resources.client.text())?;
        self.text(",")?;self.key("worker")?;self.string(if row.resources.worker_joined {"joined"}else{"not-started"})?;
        self.text(",")?;self.key("identity")?;self.string(row.resources.identity.text())?;
        self.text("}}")
    }
    fn result(&mut self,build:&Build,rows:&[Row;3],outcome:ResultKind,auxiliary_ns:u64)->Option<()> {
        if self.used!=0 || outcome==ResultKind::Unexecuted || auxiliary_ns>AUXILIARY_NS { return None; }
        self.text("{\"schemaVersion\":1,")?;
        self.key("type")?;self.string("mrk-macos-e2-native-fixture-v1")?;
        self.text(",")?;self.key("fixtureProfile")?;self.string("e2-native-fixture-v1")?;
        self.text(",")?;self.key("sourceCommit")?;self.string(build.source)?;
        self.text(",")?;self.key("releaseId")?;self.string(build.release)?;
        self.text(",")?;self.key("target")?;self.string(TARGET)?;
        self.text(",")?;self.key("outcome")?;self.string(outcome.text())?;
        self.text(",\"nativeFinalityKnown\":true,")?;
        self.key("auxiliaryNanoseconds")?;self.decimal(auxiliary_ns)?;
        self.text(",\"syntheticIdentity\":true,\"productionIdentityQualified\":false,")?;
        self.text("\"actualAppIntegrationQualified\":false,\"overlapObserved\":false,\"overlapEvidence\":\"unexecuted\",\"cases\":[")?;
        for (index,row) in rows.iter().enumerate() {
            if index!=0 { self.text(",")?; }
            self.case(row)?;
        }
        self.text("]}\n")
    }
}

/// Source-defined allocation capacities, NOT a Foundation/runtime/RSS census.
/// Arc layout is the same two-counter+payload projection used by the core
/// ClientRequirements; no reference count is ever native-finality authority.
#[repr(C)]
struct ArcAllocation<T> { counts:[usize;2],value:T }
#[derive(Clone,Copy,PartialEq,Eq)]
struct ProjectCensus { peak:usize,final_data:usize,identity_extra:usize }
fn project_census()->Option<ProjectCensus> {
    let client=Client::requirements().admitted_upper_bound().ok()?;
    let native_main=ServiceManager::project_owned_upper_bound()?.checked_sub(size_of::<ServiceManager>())?;
    let identity=FixtureMainIdentity::project_owned_upper_bound()?;
    let native_identity=identity.checked_sub(size_of::<FixtureMainIdentity>())?;
    let identity_extra=identity.checked_add(IDENTITY_PROVIDER_BYTES)?
        .checked_add(8_usize.checked_mul(size_of::<FixtureIdentityFacts>())?)?
        .checked_add(size_of::<PoolTrace>())?;
    if IDENTITY_PROVIDER_BYTES!=crate::android_service_budget::FIXTURE_IDENTITY_PROVIDER_MAX
        || IDENTITY_EXTRA_BYTES!=crate::android_service_budget::FIXTURE_IDENTITY_PROCESS_MAX
        || identity_extra>IDENTITY_EXTRA_BYTES { return None; }
    // Invocation includes its output, three rows, current main case frame,
    // records, manager and provider wrapper. The explicit worker stack covers
    // its local Client/wire temporaries; the inert spawn capsule is separate.
    let mut peak=size_of::<Invocation>();
    for bytes in [
        WORKER_STACK_BYTES,size_of::<Worker>(),client,native_main,native_identity,
        size_of::<ArcAllocation<ClockBridge>>(),size_of::<ArcAllocation<Signal>>(),
        size_of::<ArcAllocation<Shared>>(),size_of::<Gate<'static>>(),
        size_of::<WorkerReport>(),2_usize.checked_mul(size_of::<Row>())?,
        crate::android_service_budget::maintenance_wire_high_water()?,
        // Bounded main scalar/formatter/checkpoint scratch, including the
        // fixed thirteen-entry (static key,bool) projection in ResultBuffer.
        4096,
    ] { peak=peak.checked_add(bytes)?; }
    let final_data=size_of::<Invocation>().checked_add(size_of::<ArcAllocation<ClockBridge>>())?;
    (peak<=PROJECT_BYTES_MAX && final_data<=peak).then_some(ProjectCensus {peak,final_data,identity_extra})
}

struct Invocation {
    build:Build,clock:Arc<ClockBridge>,auxiliary:Auxiliary,manager:ServiceManager,
    current:Option<CaseOwner>,rows:[Row;3],executed:usize,settled_cases:usize,
    census:Option<ProjectCensus>,result:ResultBuffer,outcome:Option<ResultKind>,
    native_finality_known:bool,write_attempted:bool,panic:Option<Box<dyn Any+Send>>,
}
impl Invocation {
    fn new(build:Build,clock:ClockBridge,auxiliary:Auxiliary)->Self { Self {
        build,clock:Arc::new(clock),auxiliary,manager:ServiceManager::new(),current:None,
        rows:[Row::unexecuted(Case::MissingB),Row::unexecuted(Case::LocalF),Row::unexecuted(Case::Genuine)],
        executed:0,settled_cases:0,census:None,result:ResultBuffer::new(),outcome:None,
        native_finality_known:false,write_attempted:false,panic:None,
    } }
    fn fresh_operation(&mut self)->Option<[u8;16]> {
        self.auxiliary.auxiliary()?;
        let mut operation=[0_u8;16];
        // Documented <=256-byte OS entropy API; no new file/process, retry,
        // environment-derived identifier, or fabricated resident instance.
        let returned=unsafe { libc::getentropy(operation.as_mut_ptr().cast(),operation.len()) };
        self.auxiliary.auxiliary()?;
        (returned==0 && operation!=[0;16]
            && !self.rows.iter().any(|row|row.operation==Some(operation))).then_some(operation)
    }
    fn drop_settled_case(&mut self)->Option<()> {
        let case=self.current.as_ref()?;
        if !case.settled || case.unknown || case.population_possible || case.panic.is_some()
            || case.worker.is_some() || case.worker_started!=case.worker_joined
            || case.admission.is_some() || !case.slots_final(case.protocol_started)
            || identity_closed(case.identity.custody()).is_none() || !manager_idle(&self.manager) { return None; }
        // These are now ordinary bounded DATA only. Native consuming calls,
        // remote exit and the actual original join have already returned.
        drop(self.current.take()?);
        self.settled_cases=self.settled_cases.checked_add(1)?;
        self.auxiliary.auxiliary()?;
        Some(())
    }
    fn validate_rows(&self)->Option<ResultKind> {
        if self.executed==0 || self.executed>CASES.len() || self.executed!=self.settled_cases { return None; }
        let mut previous=0;let mut terminal=None;
        for (index,row) in self.rows.iter().enumerate() {
            if row.kind!=CASES[index] || !row.data_valid(&self.build) { return None; }
            if row.outcome==ResultKind::Unexecuted {
                if terminal.is_none() || index<self.executed { return None; }
                continue;
            }
            if terminal.is_some() || index>=self.executed || row.started<previous { return None; }
            for old in &self.rows[..index] {
                if row.operation.is_some() && row.operation==old.operation
                    || row.binding.is_some_and(|binding|old.binding.is_some_and(|other|binding.instance==other.instance)) { return None; }
            }
            previous=row.finished;
            if row.outcome!=ResultKind::Passed { terminal=Some(row.outcome); }
        }
        let overall=terminal.unwrap_or(ResultKind::Passed);
        if overall==ResultKind::Passed && self.executed!=CASES.len() { return None; }
        Some(overall)
    }
    fn final_census(&self)->bool {
        self.current.is_none() && self.executed==self.settled_cases && manager_idle(&self.manager)
            && self.panic.is_none() && self.census.is_some_and(|old|project_census()==Some(old))
            && self.result.used<=RESULT_BYTES && self.auxiliary.phase==LedgerPhase::Auxiliary
            && self.auxiliary.valid
    }
    fn run(&mut self,account:u32)->Option<ResultKind> {
        self.census=project_census();
        self.census?;
        self.auxiliary.auxiliary()?;
        for (index,kind) in CASES.into_iter().enumerate() {
            if self.current.is_some() || self.executed!=index || self.settled_cases!=index
                || index!=0 && self.rows[index-1].outcome!=ResultKind::Passed { return None; }
            let started=self.auxiliary.auxiliary()?;
            let Some(operation)=self.fresh_operation() else {
                let finished=self.auxiliary.auxiliary()?;
                self.rows[index]=Row { outcome:ResultKind::Unavailable,started,finished,first:Some(finished),
                    ..Row::unexecuted(kind) };
                self.executed+=1;self.settled_cases+=1;break;
            };
            self.current=Some(CaseOwner::new(kind,started,operation));
            let row=self.current.as_mut()?.run(&mut self.manager,&mut self.auxiliary,&self.clock,
                &self.build,&self.rows[..index],account)?;
            if !row.data_valid(&self.build) { return None; }
            self.rows[index]=row;self.executed+=1;
            self.drop_settled_case()?;
            if row.outcome!=ResultKind::Passed { break; }
        }
        let outcome=self.validate_rows()?;
        self.auxiliary.auxiliary()?;
        if !self.final_census() { return None; }
        self.outcome=Some(outcome);
        // Derived only after every ORIGINAL category has actually settled.
        // This DATA flag never authorizes a native call, release, or join.
        self.native_finality_known=true;
        Some(outcome)
    }
    fn publish(&mut self,outcome:ResultKind)->! {
        if !self.native_finality_known || self.outcome!=Some(outcome)
            || self.validate_rows()!=Some(outcome) || !self.final_census() || self.write_attempted { retain_unknown(); }
        let Some(exit)=outcome.exit_code() else { retain_unknown(); };
        if self.auxiliary.auxiliary().is_none() { retain_unknown(); }
        // Honest PRE-publication snapshot. It cannot contain a fabricated
        // post-write time; serialization and the real write still consume the
        // same remaining allowance and are checked before any terminal exit.
        let snapshot=self.auxiliary.spent;
        if self.result.result(&self.build,&self.rows,outcome,snapshot).is_none()
            || self.auxiliary.auxiliary().is_none() || !self.final_census() { retain_unknown(); }
        self.write_attempted=true;
        let returned=unsafe { libc::write(libc::STDOUT_FILENO,self.result.bytes.as_ptr().cast(),self.result.used) };
        // A completed native receipt is not authority to excuse a late or
        // unknown output operation. No second line, raw-error dump or retry.
        if self.auxiliary.auxiliary().is_none() || !self.final_census() { retain_unknown(); }
        if returned<0 || usize::try_from(returned).ok()!=Some(self.result.used) {
            // All acquired native/population originals are already settled;
            // failed/partial output is a failure exit, never a passed receipt.
            unsafe { libc::_exit(1); }
        }
        unsafe { libc::_exit(exit); }
    }
}

/// Fixed installed fixture entry, never a normal product entrypoint. Unknown
/// owns and retains the entire original frame. Only its known-final terminal
/// path emits one bounded line and exits; the C facade never receives success.
pub fn enter()->! {
    if ENTERED.swap(true,Ordering::SeqCst) { retain_unknown(); }
    let account=unsafe { libc::getuid() };
    if unsafe { libc::pthread_main_np() }!=1 || account==0 || account==u32::MAX
        || unsafe { libc::geteuid() }!=account { retain_unknown(); }
    // The standalone fixture owns this process before its sole worker starts.
    // Catching a panic must not expose framework/private error messages through
    // the default hook; its payload remains in the retained owning frame.
    std::panic::set_hook(Box::new(|_|{}));
    let Some(now)=uptime() else { retain_unknown(); };
    let Some(auxiliary)=Auxiliary::new(now) else { retain_unknown(); };
    let Some(build)=Build::fixed() else { retain_unknown(); };
    let Some(clock)=ClockBridge::capture() else { retain_unknown(); };
    let mut invocation=ManuallyDrop::new(Invocation::new(build,clock,auxiliary));
    match catch_unwind(AssertUnwindSafe(||invocation.run(account))) {
        Ok(Some(outcome))=>invocation.publish(outcome),
        Err(payload)=>{invocation.panic=Some(payload);retain_unknown();},
        _=>retain_unknown(),
    }
}


#[cfg(test)]
mod fixture_data_tests {
    use super::*;
    fn build()->Build {
        let mut source=[b'1';40];source[0]=b'a';
        let mut release=[0;64];release[..7].copy_from_slice(b"fixture");
        let mut target=[0;24];target[..TARGET.len()].copy_from_slice(TARGET.as_bytes());
        Build { source:"a111111111111111111111111111111111111111",release:"fixture",
            identity:Identity {instance:[0;16],source,release,target} }
    }
    fn record(action:Action,outcome:Outcome,status:Status,mutation:bool)->ActionRecord {
        ActionRecord { invoked:true,finished:true,allocation_returned:true,allocated:true,consumed:true,
            service_acquired:true,service_released:true,mutation_entered:mutation,mutation_returned:mutation,
            last:Some(Observation {action,status,outcome,mutation_entered:mutation,mutation_returned:mutation,
                mutation_uncertain:false,native_settled:false}),..ActionRecord::default() }
    }
    #[test]
    fn aggregate_auxiliary_freezes_without_reset_and_expiry_is_absorbing() {
        let mut ledger=Auxiliary::new(100).unwrap();
        assert!(ledger.at(110));
        assert!(ledger.begin_protocol(120));
        assert_eq!(ledger.spent,20);
        assert!(ledger.at(2_000));
        assert!(ledger.resume(3_000));
        assert_eq!(ledger.remaining,AUXILIARY_NS-20);
        assert_eq!(ledger.deadline,3_000+AUXILIARY_NS-20);
        assert!(ledger.at(3_010));
        assert_eq!(ledger.spent,30);
        assert!(!ledger.at(3_009));
        assert!(!ledger.at(3_011));
        let mut expired=Auxiliary::new(100).unwrap();
        assert!(!expired.at(100+AUXILIARY_NS));
        assert!(!expired.begin_protocol(100+AUXILIARY_NS));
    }
    #[test]
    fn own_registration_cleanup_requires_actual_pair_and_is_one_shot() {
        let observed=record(Action::Observe,Outcome::Observed,Status::NotRegistered,false);
        let registered=record(Action::RequestRegistration,Outcome::RegistrationRequested,Status::Enabled,true);
        let actual=Observation {native_settled:true,..registered.last.unwrap()};
        let mut cleanup=OwnFixtureRegistration::from_returned(Case::MissingB,[1;16],&observed,&registered,actual).unwrap();
        assert!(cleanup.take_cleanup(Case::MissingB,[1;16]));
        assert!(!cleanup.take_cleanup(Case::MissingB,[1;16]));
        let mut genuine=OwnFixtureRegistration::from_returned(Case::Genuine,[2;16],&observed,&registered,actual).unwrap();
        assert!(!genuine.take_cleanup(Case::Genuine,[2;16]));
        let collision=record(Action::Observe,Outcome::Observed,Status::Enabled,false);
        assert!(OwnFixtureRegistration::from_returned(Case::MissingB,[1;16],&collision,&registered,actual).is_none());
        let mut unreturned=registered;
        unreturned.mutation_returned=false;
        assert!(OwnFixtureRegistration::from_returned(Case::MissingB,[1;16],&observed,&unreturned,actual).is_none());
    }
    #[test]
    fn positive_unregister_survives_later_unknown_without_false_settlement() {
        let now=Instant::now();
        let positive=Observation { action:Action::UnregisterAfterQuiescence,status:Status::NotRegistered,
            outcome:Outcome::UnregisterAccepted,mutation_entered:true,mutation_returned:true,
            mutation_uncertain:false,native_settled:false };
        let mut record=ActionRecord {invoked:true,before:Some((Phase::ObserveResult,now)),..ActionRecord::default()};
        let custody=Custody {action:Some(Action::UnregisterAfterQuiescence),phase:Some(Phase::ObserveResult),
            action_admitted:true,cell:CellCustody::Owned,service:ServiceCustody::Owned,
            in_call:false,gate_entered:false,unknown:false,stopped:false,first_failure:None,observation:Some(positive)};
        assert!(record.returned(Phase::ObserveResult,now,custody));
        record.before=Some((Phase::ReleaseService,now));
        assert!(record.returned(Phase::ReleaseService,now,Custody {
            phase:Some(Phase::ReleaseService),service:ServiceCustody::Unknown,unknown:true,
            observation:Some(Observation {outcome:Outcome::Unknown,..positive}),..custody
        }));
        assert!(record.unregistered);
        assert_eq!(record.positive_unregister,Some(positive));
        assert!(record.closed().is_none());
    }
    #[test]
    fn empty_and_unexecuted_resources_do_not_become_closes_or_joins() {
        let mut row=Row::unexecuted(Case::MissingB);
        assert!(row.data_valid(&build()));
        row.resources.main=Closed::ReturnedEmpty;
        assert!(!row.data_valid(&build()));
        row=Row::unexecuted(Case::MissingB);row.resources.worker_joined=true;
        assert!(!row.data_valid(&build()));
        assert!(!Resources {main:Closed::ReturnedEmpty,client:Closed::Settled,
            identity:Closed::Settled,worker_joined:true}.passed());
        assert!(identity_closed(FixtureIdentityCustody::Unresolved).is_none());
    }
    #[test]
    fn result_is_bounded_one_line_with_truthful_empty_resource_projection() {
        let mut first=Row::unexecuted(Case::MissingB);
        first.outcome=ResultKind::Unavailable;first.started=1;first.finished=2;
        first.resources.main=Closed::ReturnedEmpty;
        let rows=[first,Row::unexecuted(Case::LocalF),Row::unexecuted(Case::Genuine)];
        assert!(first.data_valid(&build()));
        let mut output=ResultBuffer::new();
        output.result(&build(),&rows,ResultKind::Unavailable,17).unwrap();
        let text=std::str::from_utf8(&output.bytes[..output.used]).unwrap();
        assert!(text.ends_with('\n'));
        assert_eq!(text.bytes().filter(|byte|*byte==b'\n').count(),1);
        assert!(text.contains("\"mainReturned\":true,\"mainClosed\":false,\"clientClosed\":false,\"workerJoined\":false"));
        assert!(text.contains("\"resourceStates\":{\"main\":\"returned-empty\",\"client\":\"not-entered\",\"worker\":\"not-started\",\"identity\":\"not-entered\"}"));
        assert!(text.contains("\"auxiliaryNanoseconds\":\"17\""));
        assert!(output.result(&build(),&rows,ResultKind::Unavailable,17).is_none());
        let mut full=ResultBuffer::new();full.used=RESULT_BYTES;
        assert!(full.text("x").is_none());
        assert_eq!(full.used,RESULT_BYTES);
        assert!(ResultBuffer::new().string("private\nmessage").is_none());
    }
    #[test]
    fn full_declared_project_census_includes_native_identity_and_one_worker_stack() {
        let census=project_census().unwrap();
        assert!(census.peak>WORKER_STACK_BYTES+2*IDENTITY_PROVIDER_BYTES);
        assert!(census.identity_extra>=2*IDENTITY_PROVIDER_BYTES);
        assert!(census.identity_extra<=IDENTITY_EXTRA_BYTES && census.peak<=PROJECT_BYTES_MAX);
        assert!(census.final_data<census.peak);
    }
}
