//! Fixed, authenticated Mac Android registration transport.
//!
//! The native callbacks below can only move bounded DATA through Ingress. They
//! never receive the publisher, filesystem callback, descriptor or native ACL/
//! lease book. Original Rust workers own all payload work. Status is comparison
//! DATA; the service coordinator must observe the actual same-original join.
//! No alternate peer, runtime service name, reverse callback or command exists.
use std::{
    ffi::{c_int, c_void},
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::{Arc, Mutex, OnceLock, TryLockError, atomic::{AtomicBool, AtomicU64, Ordering}},
    time::Instant,
};
use crate::vault_helper_wire::{uptime, ClockBridge};
use crate::android_service_prepare as prepare;
use crate::android_service_client_data::{self as client_data,ClientData,DataOwner};

pub const FRAME_BYTES: usize = 65_536;
pub const ENVELOPE_BYTES: usize = 32;
pub const CONTENT_BYTES: usize = FRAME_BYTES - ENVELOPE_BYTES;
pub const STATUS_BYTES: usize = 256;
pub const TERMINAL_BYTES: usize = STATUS_BYTES - 80;
pub const WORK_NS: u64 = 300_000_000_000;
pub const HARD_NS: u64 = 310_000_000_000;
pub const CLEANUP_NS: u64 = 10_000_000_000;
const MAGIC: &[u8; 8] = b"MRKAX01\0";
const STATUS_MAGIC: &[u8; 8] = b"MRKAXS01";
// Raw nanoseconds share one atomic failure/finality word. More than73 years
// of uninterrupted uptime is explicitly unavailable, never wrapped/rebased.
const FIRST_MASK: u64 = (1_u64 << 61) - 1;
const UNKNOWN_BIT: u64 = 1_u64 << 61;
const CLOCK_UNKNOWN_BIT: u64 = 1_u64 << 62;
const TERMINAL_BIT: u64 = 1_u64 << 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure { Unavailable, Bounds, Binding, Sequence, Busy, Stopped, Native, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds { pub origin: u64, pub work: u64, pub hard: u64 }
impl Bounds {
    pub fn valid(self) -> bool {
        self.origin != 0 && self.hard <= FIRST_MASK
            && self.work.checked_sub(self.origin) == Some(WORK_NS)
            && self.hard.checked_sub(self.origin) == Some(HARD_NS)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenFailure { pub first: Option<u64>, pub cleanup: Option<u64>, pub unknown: bool }

// Parent CLOCK_MONOTONIC and service CLOCK_UPTIME_RAW are DISTINCT domains.
// Frozen projected endpoints only contract this operation's existing waits.
// Relative rate/offset is NOT an invariant between these clocks. Every positive
// cut samples BOTH original domains; Parent first-F is NEVER translated.
struct RemovalClockData {
    start:u64,work:u64,hard:u64,uptime_work:u64,uptime_hard:u64,
    last_parent:AtomicU64,last_uptime:AtomicU64,
    parent_first:AtomicU64,work_stopped:AtomicBool,invalid:AtomicBool,
}
impl RemovalClockData {
    fn from_samples(start:u64,work:u64,hard:u64,u0:u64,p0:u64,p1:u64,u1:u64)->Option<Self>{
        if start==0 || work.checked_sub(start)!=Some(110_000_000_000)
            || hard.checked_sub(start)!=Some(120_000_000_000) || hard>FIRST_MASK
            || u0==0 || u0>u1 || u1>FIRST_MASK || p0<start || p0>p1 || p1>=work {return None;}
        let uptime_work=u0.checked_add(work.checked_sub(p1)?)?;
        let uptime_hard=u0.checked_add(hard.checked_sub(p1)?)?;
        if uptime_work<=u1 || uptime_work>=uptime_hard || uptime_hard>FIRST_MASK{return None;}
        Some(Self{start,work,hard,uptime_work,uptime_hard,
            last_parent:AtomicU64::new(p1),last_uptime:AtomicU64::new(u1),
            parent_first:AtomicU64::new(0),work_stopped:AtomicBool::new(false),invalid:AtomicBool::new(false)})
    }
    fn observe_samples(&self,previous_p:u64,previous_u:u64,u0:u64,p:u64,u1:u64)->bool{
        // Raw first-F remains MONOTONIC, even when a later consistency check
        // refuses. It is NOT written into Signal/Control's own failure clocks.
        if p>=self.work && p<=FIRST_MASK{let _=self.parent_first.compare_exchange(0,self.work,Ordering::SeqCst,Ordering::SeqCst);}
        let valid=u0!=0 && u0>=previous_u && u0<=u1 && u1<=FIRST_MASK
            && p>=previous_p && p>=self.start && p<FIRST_MASK;
        if valid{self.last_parent.fetch_max(p,Ordering::SeqCst);self.last_uptime.fetch_max(u1,Ordering::SeqCst);}
        if p>=self.work || u1>=self.uptime_work{self.work_stopped.store(true,Ordering::SeqCst);}
        if !valid || p>=self.hard || u1>=self.uptime_hard{self.invalid.store(true,Ordering::SeqCst);}
        // Known work-stop forbids work/final success, not still-known consuming
        // cleanup. Regression, missing samples and either hard bound never heal.
        valid && self.cleanup_allowed()
    }
    fn work_allowed(&self)->bool{!self.work_stopped.load(Ordering::SeqCst) && self.cleanup_allowed()}
    fn cleanup_allowed(&self)->bool{!self.invalid.load(Ordering::SeqCst)}
}
/// Fixed-purpose finite admission clock, NOT source/peer/consent authority.
/// Before native authentication its raw DATA only contracts source work. The
/// SAME object receives a genuine cutoff once, with no new clock bracket.
pub struct RemovalClock {
    data:RemovalClockData,bridge:ClockBridge,
    cutoff:OnceLock<crate::removal_coordinator::ParentCutoff>,
}
struct RemovalClockPoint { parent:u64,uptime:u64,valid:bool }
impl RemovalClock {
    pub fn capture_removal_data(start:u64,work:u64,hard:u64)->Option<Arc<Self>>{
        let u0=uptime()?;let p0=removal_parent_sample()?;let bridge=ClockBridge::capture()?;
        let p1=removal_parent_sample()?;let u1=uptime()?;
        Some(Arc::new(Self{data:RemovalClockData::from_samples(start,work,hard,u0,p0,p1,u1)?,
            bridge,cutoff:OnceLock::new()}))
    }
    pub fn authenticate_once(&self,cutoff:&crate::removal_coordinator::ParentCutoff)->bool{
        if self.data.start!=cutoff.start_ns() || self.data.work!=cutoff.work_ns() || self.data.hard!=cutoff.hard_ns()
            || self.work_sample().is_none() || self.cutoff.set(cutoff.clone()).is_err(){self.mark_unknown();return false;}
        self.work_sample().is_some()
    }
    fn observe(&self)->Option<RemovalClockPoint>{
        // Read both previous values BEFORE sampling; a concurrent later publish
        // must not turn an already sampled earlier observation into regression.
        let previous_p=self.data.last_parent.load(Ordering::SeqCst);
        let previous_u=self.data.last_uptime.load(Ordering::SeqCst);
        let sampled=(||Some((uptime()?,removal_parent_sample()?,uptime()?)))();
        let Some((u0,p,u1))=sampled else{self.mark_unknown();return None;};
        let valid=self.data.observe_samples(previous_p,previous_u,u0,p,u1);
        Some(RemovalClockPoint{parent:p,uptime:u1,valid})
    }
    pub fn work_sample(&self)->Option<u64>{
        self.observe().filter(|point|point.valid && self.data.work_allowed()
            && point.parent<self.data.work && point.uptime<self.data.uptime_work).map(|point|point.parent)
    }
    pub fn cleanup_sample(&self)->Option<u64>{
        self.observe().filter(|point|point.valid && point.parent<self.data.hard && point.uptime<self.data.uptime_hard).map(|point|point.parent)
    }
    pub fn cutoff(&self)->Option<&crate::removal_coordinator::ParentCutoff>{self.cutoff.get()}
    pub fn bridge(&self)->&ClockBridge{&self.bridge}
    pub fn uptime_work(&self)->u64{self.data.uptime_work}
    pub fn uptime_hard(&self)->u64{self.data.uptime_hard}
    pub fn parent_first(&self)->Option<u64>{let first=self.data.parent_first.load(Ordering::SeqCst);(first!=0).then_some(first)}
    pub fn work_stopped(&self)->bool{self.data.work_stopped.load(Ordering::SeqCst)}
    pub fn invalid(&self)->bool{self.data.invalid.load(Ordering::SeqCst)}
    pub fn unknown(&self)->bool{self.work_stopped() || self.invalid()}
    /// The same frozen own-domain work projection may only restrict work.
    /// This is STOP, not an invented Parent/UPTIME failure or lost native custody.
    pub fn mark_work_stopped(&self){self.data.work_stopped.store(true,Ordering::SeqCst);}
    pub fn mark_unknown(&self){self.data.invalid.store(true,Ordering::SeqCst);}
    pub fn project_owned_upper_bound()->Option<usize>{
        std::mem::size_of::<Self>().checked_add(2*std::mem::size_of::<usize>())?
            .checked_add(crate::removal_coordinator::ParentCutoff::project_owned_upper_bound()?)
    }
}
/// Actual Parent-domain sample. Also available in the helper build without
/// importing the AppKit confirmation adapter or changing helper wire Bounds.
fn removal_parent_sample()->Option<u64>{
    let mut value=nix::libc::timespec{tv_sec:0,tv_nsec:0};
    // SAFETY: the fixed syscall writes only this owned timespec; no pointer is retained.
    if unsafe{nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC,&mut value)}!=0{return None;}
    let seconds=u64::try_from(value.tv_sec).ok()?;let nanos=u64::try_from(value.tv_nsec).ok()?;
    if nanos>=1_000_000_000{return None;}
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos).filter(|value|*value!=0 && *value<=FIRST_MASK)
}

/// One bounded, independently runnable first-F/STOP mailbox. Failure publication
/// takes no Registry, Document, native-book or ingress lock. Failure/Unknown and
/// finality freeze share ONE atomic word: a callback cannot pass a separate
/// terminal flag then overwrite the immutable terminal result.
pub struct Signal {
    bounds: OnceLock<Bounds>, state: AtomicU64, maintenance_cutoff: AtomicU64,
    removal_clock: OnceLock<Arc<RemovalClock>>,
}
impl Signal {
    pub fn reserved() -> Self { Self {
        bounds: OnceLock::new(), state: AtomicU64::new(0), maintenance_cutoff: AtomicU64::new(0),
        removal_clock: OnceLock::new(),
    } }
    fn arm_at(&self, bounds: Bounds, now: u64) -> Result<(), Failure> {
        if !bounds.valid() || now < bounds.origin || now >= bounds.work
            || self.bounds.set(bounds).is_err()
        {
            self.unknown_clock(); return Err(Failure::Unknown);
        }
        if self.first().is_some_and(|first| first < bounds.origin || first > now)
            || self.state.load(Ordering::SeqCst) & TERMINAL_BIT != 0
        {
            self.unknown_clock(); return Err(Failure::Unknown);
        }
        Ok(())
    }
    pub fn arm(&self, bounds: Bounds) -> Result<(), Failure> {
        self.arm_at(bounds, uptime().ok_or_else(|| { self.unknown_clock(); Failure::Unknown })?)
    }
    /// SAME authenticated clock object, never the raw request DATA alone.
    pub fn bind_removal_clock(&self,clock:&Arc<RemovalClock>)->Result<(),Failure>{
        let Some(bounds)=self.bounds()else{self.unknown_clock();return Err(Failure::Unknown);};
        let now=uptime().ok_or_else(||{self.unknown_clock();Failure::Unknown})?;
        if clock.cutoff().is_none() || clock.work_sample().is_none() || now<bounds.origin || now>=bounds.work
            || clock.uptime_work()<=bounds.origin || clock.uptime_work()>bounds.work || clock.uptime_hard()>bounds.hard
            || self.state.load(Ordering::SeqCst)!=0 || self.removal_clock.set(clock.clone()).is_err(){
            self.unknown_clock();return Err(Failure::Unknown);
        }
        if self.admitted(false){Ok(())}else{Err(Failure::Unknown)}
    }
    pub fn removal_cutoff(&self)->Option<&crate::removal_coordinator::ParentCutoff>{self.removal_clock.get()?.cutoff()}
    pub fn removal_clock(&self)->Option<&Arc<RemovalClock>>{self.removal_clock.get()}
    pub fn work_endpoint(&self)->Option<u64>{
        self.bounds().map(|bounds|self.removal_clock.get().map_or(bounds.work,|clock|bounds.work.min(clock.uptime_work())))
    }
    fn update(&self, first: Option<u64>, flags: u64) {
        let mut old = self.state.load(Ordering::SeqCst);
        loop {
            if old & TERMINAL_BIT != 0 { return; }
            let present = old & FIRST_MASK;
            let earliest = match first {
                Some(first) if present == 0 => first,
                Some(first) => present.min(first),
                None => present,
            };
            let next = (old & !FIRST_MASK) | earliest | flags;
            match self.state.compare_exchange_weak(old, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return, Err(actual) => old = actual,
            }
        }
    }
    fn unknown_clock(&self) { self.update(None, UNKNOWN_BIT | CLOCK_UNKNOWN_BIT); }
    /// Absorbing invalid-clock state, with no invented accepted failure timestamp.
    pub fn clock_unknown(&self) { self.unknown_clock(); }
    /// Trusted local/native observation only. Deserialized time must pass
    /// accept_remote first. Zero/out-of-range/pre-origin is UNKNOWN clock.
    pub fn failure_at(&self, first: u64, unknown: bool) {
        if first == 0 || first > FIRST_MASK || self.bounds().is_some_and(|bounds| first < bounds.origin) {
            self.unknown_clock(); return;
        }
        self.update(Some(first), if unknown { UNKNOWN_BIT } else { 0 });
    }
    pub fn failure_now(&self, unknown: bool) { self.failure_at(uptime().unwrap_or(0), unknown); }
    pub fn local_failure(&self, clock: &ClockBridge, event: Instant, unknown: bool) {
        self.failure_at(clock.earlier_endpoint(event).unwrap_or(0), unknown);
    }
    pub fn first(&self) -> Option<u64> {
        let first = self.state.load(Ordering::SeqCst) & FIRST_MASK;
        (first != 0).then_some(first)
    }
    // The containing removal owner still checks its live Parent clock before
    // permission/finality. An already frozen Signal is immutable historical
    // DATA, not a grant, so later peer-clock expiry cannot rewrite its result.
    fn live_word_data(word:u64,parent_stopped:bool,parent_invalid:bool)->u64{
        if word&TERMINAL_BIT!=0{return word;}
        word | if parent_invalid{UNKNOWN_BIT|CLOCK_UNKNOWN_BIT}else if parent_stopped{UNKNOWN_BIT}else{0}
    }
    fn live_word(&self,word:u64)->u64{
        let clock=self.removal_clock.get();
        Self::live_word_data(word,clock.is_some_and(|clock|clock.work_stopped()),clock.is_some_and(|clock|clock.invalid()))
    }
    /// Own stored failures, not the additional live Parent STOP overlay. The
    /// SAME synchronizer must still import a genuine own Unknown concurrent
    /// with Parent STOP; subtracting a combined boolean would lose that fact.
    pub fn stored_unknown(&self)->bool{self.state.load(Ordering::SeqCst)&UNKNOWN_BIT!=0}
    pub fn stored_clock_unknown(&self)->bool{self.state.load(Ordering::SeqCst)&CLOCK_UNKNOWN_BIT!=0}
    pub fn unknown(&self) -> bool { self.live_word(self.state.load(Ordering::SeqCst))&UNKNOWN_BIT!=0 }
    pub fn bounds(&self) -> Option<Bounds> { self.bounds.get().copied() }
    fn snapshot_word(&self, word: u64) -> FrozenFailure {
        let word=self.live_word(word);
        let first = word & FIRST_MASK;
        let first = (first != 0).then_some(first);
        let cleanup = self.bounds().and_then(|bounds| {
            if word & CLOCK_UNKNOWN_BIT != 0 { return None; }
            match first {
                Some(first) if first >= bounds.origin => Some(first.checked_add(CLEANUP_NS)?.min(bounds.hard)),
                Some(_) => None, None => Some(bounds.hard),
            }
        });
        let narrow=self.maintenance_cutoff.load(Ordering::SeqCst);
        let cleanup=cleanup.map(|end|if narrow==0{end}else{end.min(narrow)});
        let cleanup=cleanup.map(|end|self.removal_clock.get().map_or(end,|clock|end.min(clock.uptime_hard())));
        FrozenFailure { first, cleanup, unknown: word & UNKNOWN_BIT != 0 }
    }
    pub fn snapshot(&self) -> FrozenFailure { self.snapshot_word(self.state.load(Ordering::SeqCst)) }
    pub fn cleanup(&self) -> Option<u64> { self.snapshot().cleanup }
    /// A normal maintenance R/cutoff only narrows this SAME Signal. It is not F.
    pub(crate) fn narrow_maintenance(&self, cutoff:u64, now:u64)->bool {
        let Some(bounds)=self.bounds()else{self.unknown_clock();return false;};
        if now<bounds.origin || now>FIRST_MASK || cutoff<=bounds.origin || cutoff>bounds.hard
            || self.state.load(Ordering::SeqCst)&TERMINAL_BIT!=0{self.unknown_clock();return false;}
        let _=self.maintenance_cutoff.fetch_update(Ordering::SeqCst,Ordering::SeqCst,
            |old|Some(if old==0{cutoff}else{old.min(cutoff)}));
        let retained=self.maintenance_cutoff.load(Ordering::SeqCst);
        if now>=retained{self.failure_at(retained,false);return false;}
        !self.unknown()
    }
    pub(crate) fn maintenance_tail(&self,first:u64,cutoff:u64,now:u64)->bool{
        // Import the original F BEFORE exposing any positive tail admission.
        if first!=0 {
            if first>now{self.unknown_clock();return false;}
            self.failure_at(first,false);
        }
        self.narrow_maintenance(cutoff,now) && first==0 && self.first().is_none()
            && !self.unknown() && self.admitted_at(false,now)
    }
    /// Validate comparison DATA against this exact original clock. A peer
    /// cannot select/extend W/H or import future/pre-origin F. Missing cleanup
    /// is accepted only with explicit peer Unknown, never as a renewed clock.
    fn accept_remote(&self, first: Option<u64>, cleanup: Option<u64>, unknown: bool, now: u64) -> bool {
        let Some(bounds) = self.bounds() else { self.unknown_clock(); return false; };
        let valid = now >= bounds.origin && now <= FIRST_MASK
            && first.is_none_or(|first| first >= bounds.origin && first <= now)
            && match cleanup {
                Some(actual) => first.map_or(Some(bounds.hard), |first| first.checked_add(CLEANUP_NS).map(|end| end.min(bounds.hard))) == Some(actual),
                None => unknown,
            };
        if !valid { self.failure_at(now, true); return false; }
        if let Some(first) = first { self.failure_at(first, unknown); }
        else if unknown { self.failure_at(now, true); }
        true
    }
    pub fn admitted_at(&self, cleanup: bool, now: u64) -> bool {
        let Some(bounds) = self.bounds() else { return false; };
        if now < bounds.origin || now > FIRST_MASK { self.unknown_clock(); return false; }
        // Genuine own UPTIME failure is recorded before the Parent veto. Never
        // replace it with raw Parent W or the supplemental projected cutoff.
        if (!cleanup || self.removal_clock.get().is_some()) && now>=bounds.work{self.failure_at(bounds.work,false);}
        let mut observed=now;
        if let Some(clock)=self.removal_clock.get(){
            let Some(point)=clock.observe()else{self.unknown_clock();return false;};
            if point.uptime>=bounds.work{self.failure_at(bounds.work,false);}
            if point.uptime<now || !point.valid || clock.cutoff().is_none(){self.unknown_clock();return false;}
            observed=point.uptime;
        }
        let word = self.state.load(Ordering::SeqCst);
        if word & (CLOCK_UNKNOWN_BIT | TERMINAL_BIT) != 0 { return false; }
        if cleanup { self.cleanup().is_some_and(|end| observed < end) }
        else { !self.unknown() && self.first().is_none() && observed < self.work_endpoint().unwrap_or(bounds.work)
            && self.cleanup().is_some_and(|end|observed<end) }
    }
    pub fn admitted(&self, cleanup: bool) -> bool {
        match uptime() { Some(now) => self.admitted_at(cleanup, now), None => { self.unknown_clock(); false } }
    }
    /// Service coordinator ONLY after its actual original worker join. DATA
    /// freeze is the stop/result linearization point, not a lease/join proof.
    fn freeze(&self) -> FrozenFailure {
        if self.state.load(Ordering::SeqCst)&TERMINAL_BIT==0 && self.removal_clock.get().is_some(){
            // Observe both live domains before the existing local terminal
            // linearization. Any observed Parent veto is folded into this word
            // without inventing an own-domain first-F. A later Parent event is
            // still the outer owner's obligation, not a mutable old terminal.
            let _=self.admitted(true);
        }
        let clock=self.removal_clock.get();
        self.freeze_parent_data(clock.is_some_and(|clock|clock.work_stopped()),clock.is_some_and(|clock|clock.invalid()))
    }
    fn freeze_parent_data(&self,parent_stopped:bool,parent_invalid:bool)->FrozenFailure{
        let mut old=self.state.load(Ordering::SeqCst);
        loop{
            if old&TERMINAL_BIT!=0{return self.snapshot_word(old);}
            // Fold observed Parent STOP into the SAME immutable terminal word.
            // A concurrent/repeated freeze cannot rewrite an earlier terminal.
            let next=Self::live_word_data(old,parent_stopped,parent_invalid)|TERMINAL_BIT;
            match self.state.compare_exchange_weak(old,next,Ordering::SeqCst,Ordering::SeqCst){
                Ok(_)=>return self.snapshot_word(next),Err(actual)=>old=actual,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb { Push, Status, Stop }
pub struct Envelope<'a> { pub nonce: [u8; 16], pub sequence: u32, pub verb: Verb, pub content: &'a [u8] }
impl<'a> Envelope<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, Failure> {
        if !(ENVELOPE_BYTES..=FRAME_BYTES).contains(&raw.len()) || &raw[..8] != MAGIC
            || raw[29..32] != [0; 3] { return Err(Failure::Bounds); }
        let nonce = raw[8..24].try_into().map_err(|_| Failure::Bounds)?;
        if nonce == [0; 16] { return Err(Failure::Binding); }
        let sequence = u32::from_be_bytes(raw[24..28].try_into().map_err(|_| Failure::Bounds)?);
        let content = &raw[ENVELOPE_BYTES..];
        let verb = match raw[28] {
            0 if sequence != 0 && sequence != u32::MAX && !content.is_empty() => Verb::Push,
            1 if sequence == 0 && content.is_empty() => Verb::Status,
            2 if sequence == 0 && content.len() == 8 => Verb::Stop,
            _ => return Err(Failure::Sequence),
        };
        Ok(Self { nonce, sequence, verb, content })
    }
    pub fn encode(nonce: [u8; 16], sequence: u32, verb: Verb, content: &[u8]) -> Result<Vec<u8>, Failure> {
        if content.len() > CONTENT_BYTES { return Err(Failure::Bounds); }
        let mut out = vec![0; ENVELOPE_BYTES + content.len()];
        out[..8].copy_from_slice(MAGIC); out[8..24].copy_from_slice(&nonce);
        out[24..28].copy_from_slice(&sequence.to_be_bytes());
        out[28] = match verb { Verb::Push => 0, Verb::Status => 1, Verb::Stop => 2 };
        out[ENVELOPE_BYTES..].copy_from_slice(content);
        Envelope::decode(&out)?;
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Phase { Reserved = 0, Active = 1, InputClosed = 2, Complete = 3, Refused = 4, Busy = 5, Unknown = 6 }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase, pub account: u32, pub nonce: [u8; 16],
    pub enqueued: u32, pub processed: u32, pub payload_bytes: u64,
    pub first: Option<u64>, pub cleanup: Option<u64>, pub unknown: bool,
    pub terminal: Vec<u8>,
}
impl Status {
    pub fn decode(raw: &[u8; STATUS_BYTES]) -> Option<Self> {
        if &raw[..8] != STATUS_MAGIC { return None; }
        let u32at = |at: usize| u32::from_be_bytes([raw[at], raw[at+1], raw[at+2], raw[at+3]]);
        let u64at = |at: usize| u64::from_be_bytes([raw[at], raw[at+1], raw[at+2], raw[at+3], raw[at+4], raw[at+5], raw[at+6], raw[at+7]]);
        let phase = match u32at(8) { 0 => Phase::Reserved, 1 => Phase::Active, 2 => Phase::InputClosed,
            3 => Phase::Complete, 4 => Phase::Refused, 5 => Phase::Busy, 6 => Phase::Unknown, _ => return None };
        let account = u32at(12);
        let nonce = raw[16..32].try_into().ok()?;
        let enqueued = u32at(32); let processed = u32at(36);
        let first = u64at(48); let cleanup = u64at(56); let unknown = u32at(64);
        let length = usize::try_from(u32at(68)).ok()?;
        if unknown > 1 || length > TERMINAL_BYTES || raw[72..80] != [0; 8]
            || raw[80+length..].iter().any(|byte| *byte != 0) || processed > enqueued
            || enqueued == u32::MAX || enqueued - processed > 1
            || matches!(phase, Phase::Active | Phase::InputClosed | Phase::Complete | Phase::Refused)
                && (account == 0 || account == u32::MAX || nonce == [0; 16])
            || phase == Phase::Complete && (unknown != 0 || first != 0 || length == 0)
            || !matches!(phase, Phase::Complete | Phase::Refused | Phase::Unknown) && length != 0 {
            return None;
        }
        Some(Self { phase, account, nonce, enqueued, processed, payload_bytes: u64at(40),
            first: (first != 0).then_some(first), cleanup: (cleanup != 0).then_some(cleanup),
            unknown: unknown == 1, terminal: raw[80..80+length].to_vec() })
    }
    fn encode(&self) -> [u8; STATUS_BYTES] {
        let mut out = [0; STATUS_BYTES]; out[..8].copy_from_slice(STATUS_MAGIC);
        out[8..12].copy_from_slice(&(self.phase as u32).to_be_bytes());
        out[12..16].copy_from_slice(&self.account.to_be_bytes()); out[16..32].copy_from_slice(&self.nonce);
        out[32..36].copy_from_slice(&self.enqueued.to_be_bytes()); out[36..40].copy_from_slice(&self.processed.to_be_bytes());
        out[40..48].copy_from_slice(&self.payload_bytes.to_be_bytes());
        out[48..56].copy_from_slice(&self.first.unwrap_or(0).to_be_bytes());
        out[56..64].copy_from_slice(&self.cleanup.unwrap_or(0).to_be_bytes());
        out[64..68].copy_from_slice(&u32::from(self.unknown).to_be_bytes());
        if self.terminal.len() <= TERMINAL_BYTES {
            out[68..72].copy_from_slice(&(self.terminal.len() as u32).to_be_bytes());
            out[80..80+self.terminal.len()].copy_from_slice(&self.terminal);
        }
        out
    }
}

struct Flow {
    queued: Option<Vec<u8>>, pending: Option<u32>, enqueued: u32, processed: u32,
    payload_bytes: u64, phase: Phase, terminal: Vec<u8>,
}
/// DATA-only fixed one-slot service queue. Its private identity binds a taken
/// frame to this original slot; equality of nonce/sequence never substitutes.
pub struct Ingress {
    identity: Arc<()>, binding: OnceLock<(u32, [u8; 16])>, flow: Mutex<Flow>,
    closed: AtomicBool, terminal: AtomicBool, signal: Arc<Signal>,
}
pub struct Packet {
    identity: Arc<()>, sequence: u32, account: u32, nonce: [u8; 16], content: Vec<u8>,
}
impl Packet {
    pub fn account(&self) -> u32 { self.account }
    pub fn nonce(&self) -> [u8; 16] { self.nonce }
    pub fn sequence(&self) -> u32 { self.sequence }
    pub fn content(&self) -> &[u8] { &self.content }
}
impl Ingress {
    #[cfg(feature = "android-registration-helper")]
    pub(crate) fn service_high_water() -> Option<usize> {
        #[repr(C)] struct ArcCell<T> { counts: [usize; 2], data: T }
        std::mem::size_of::<ArcCell<Self>>().checked_add(std::mem::size_of::<ArcCell<Signal>>())?
            .checked_add(std::mem::size_of::<ArcCell<()>>())?
            .checked_add(2 * CONTENT_BYTES)?.checked_add(2 * TERMINAL_BYTES)?.checked_add(STATUS_BYTES)
    }
    pub fn new() -> Self {
        Self { identity: Arc::new(()), binding: OnceLock::new(),
            flow: Mutex::new(Flow { queued: None, pending: None, enqueued: 0, processed: 0,
                payload_bytes: 0, phase: Phase::Reserved, terminal: Vec::new() }),
            closed: AtomicBool::new(false), terminal: AtomicBool::new(false),
            signal: Arc::new(Signal::reserved()) }
    }
    pub fn signal(&self) -> &Arc<Signal> { &self.signal }
    pub fn bound_account(&self) -> Option<u32> { self.binding.get().map(|binding| binding.0) }
    pub fn bound_nonce(&self) -> Option<[u8; 16]> { self.binding.get().map(|binding| binding.1) }
    /// Service prepare only, before original worker GO. Status/Stop can then
    /// address genuine prepared custody even when no Hello has entered.
    pub(crate) fn prepare_binding(&self, account: u32, nonce: [u8; 16], bounds: Bounds, now: u64) -> bool {
        if account == 0 || account == u32::MAX || !prepare::nonce_valid(&nonce)
            || self.closed.load(Ordering::SeqCst) || self.binding.get().is_some()
            || self.binding.set((account, nonce)).is_err() {
            self.signal.failure_at(now, true); return false;
        }
        self.signal.arm_at(bounds, now).is_ok()
    }
    pub fn take(&self) -> Result<Option<Packet>, Failure> {
        let mut flow = self.flow.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => Failure::Busy,
            TryLockError::Poisoned(_) => { self.signal.failure_now(true); Failure::Unknown }
        })?;
        let Some(content) = flow.queued.take() else { return Ok(None); };
        let (account, nonce) = *self.binding.get().ok_or(Failure::Unknown)?;
        let sequence = flow.pending.ok_or(Failure::Unknown)?;
        Ok(Some(Packet { identity: self.identity.clone(), sequence, account, nonce, content }))
    }
    /// The actual worker calls this only after the corresponding original
    /// effect returned. It is queue ACK DATA, never a finality/publication grant.
    pub fn acknowledge(&self, packet: Packet, payload_bytes: u64) -> Result<(), Failure> {
        if !Arc::ptr_eq(&self.identity, &packet.identity) {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let sequence = packet.sequence;
        // Retire the original DATA slot BEFORE exposing its ACK to the client.
        drop(packet);
        let mut flow = self.flow.lock().map_err(|_| { self.signal.failure_now(true); Failure::Unknown })?;
        if flow.pending != Some(sequence) || flow.queued.is_some() || flow.processed.checked_add(1) != Some(sequence)
            || payload_bytes < flow.payload_bytes {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        flow.pending = None; flow.processed = sequence; flow.payload_bytes = payload_bytes;
        Ok(())
    }
    pub fn seal(&self) -> Result<(), Failure> {
        let mut flow = self.flow.lock().map_err(|_| { self.signal.failure_now(true); Failure::Unknown })?;
        self.closed.store(true, Ordering::SeqCst); // Irreversible, even on refusal.
        if flow.pending.is_some() || flow.queued.is_some() {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        if !self.terminal.load(Ordering::SeqCst) { flow.phase = Phase::InputClosed; }
        Ok(())
    }
    /// Failure cleanup retires DATA only, never acknowledges a failed native
    /// effect. A packet already handed to the original worker must be returned
    /// by that same owner; a queue-empty Boolean cannot substitute.
    pub fn retire_failed_input(&self, packet: Option<Packet>) -> bool {
        self.closed.store(true, Ordering::SeqCst);
        let mut flow = match self.flow.lock() {
            Ok(flow) => flow,
            Err(_) => { self.signal.failure_now(true); return false; }
        };
        if let Some(packet) = packet {
            if !Arc::ptr_eq(&self.identity, &packet.identity) || flow.pending != Some(packet.sequence)
                || flow.queued.is_some() {
                self.signal.failure_now(true); return false;
            }
            drop(packet);
            flow.pending = None;
        } else if flow.queued.is_some() {
            // This original queue entry never left service DATA custody.
            drop(flow.queued.take()); flow.pending = None;
        } else if flow.pending.is_some() {
            self.signal.failure_now(true); return false;
        }
        if !self.terminal.load(Ordering::SeqCst) { flow.phase = Phase::InputClosed; }
        true
    }
    pub fn stop_new_input(&self) { self.closed.store(true, Ordering::SeqCst); }
    pub fn input_settled(&self) -> bool {
        self.closed.load(Ordering::SeqCst) && self.flow.try_lock()
            .is_ok_and(|flow| flow.pending.is_none() && flow.queued.is_none())
    }
    /// H only: no payload/native-book access is possible here. The caller must
    /// already have observed the genuine original Rust worker join; this method
    /// cannot prove that obligation. The terminal is never rewritten.
    pub fn publish_joined_terminal(&self, result: &[u8], success: bool, known: bool) -> Result<(), Failure> {
        if result.is_empty() || result.len() > TERMINAL_BYTES || !self.input_settled()
            || self.terminal.load(Ordering::SeqCst) {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let mut flow = self.flow.lock().map_err(|_| { self.signal.failure_now(true); Failure::Unknown })?;
        if self.terminal.load(Ordering::SeqCst) || flow.pending.is_some() || flow.queued.is_some() {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let frozen = self.signal.freeze();
        let positive = success && known && !frozen.unknown && frozen.first.is_none();
        flow.phase = if positive { Phase::Complete } else if known && !frozen.unknown { Phase::Refused } else { Phase::Unknown };
        flow.terminal.extend_from_slice(result);
        self.terminal.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn snapshot(&self) -> Status {
        let (account, nonce) = self.binding.get().copied().unwrap_or((0, [0; 16]));
        match self.flow.try_lock() {
            Ok(flow) => Status { phase: if self.signal.unknown() && !self.terminal.load(Ordering::SeqCst) { Phase::Unknown } else { flow.phase },
                account, nonce, enqueued: flow.enqueued, processed: flow.processed, payload_bytes: flow.payload_bytes,
                first: self.signal.first(), cleanup: self.signal.cleanup(), unknown: self.signal.unknown(), terminal: flow.terminal.clone() },
            Err(error) => {
                let poisoned = matches!(error, TryLockError::Poisoned(_));
                if poisoned { self.signal.failure_now(true); }
                Status { phase: if poisoned { Phase::Unknown } else { Phase::Busy }, account, nonce,
                    enqueued: 0, processed: 0, payload_bytes: 0,
                    first: self.signal.first(), cleanup: self.signal.cleanup(), unknown: self.signal.unknown(), terminal: Vec::new() }
            }
        }
    }
    pub(crate) fn exchange(&self, account: u32, raw: &[u8], now: u64) -> [u8; STATUS_BYTES] {
        let input = match Envelope::decode(raw) {
            Ok(input) if account != 0 && account != u32::MAX => input,
            _ => { self.signal.failure_at(now, false); return self.snapshot().encode(); }
        };
        // First payload never binds/rearms a prepared original.
        if self.binding.get() != Some(&(account, input.nonce)) {
            self.signal.failure_at(now, false); return self.snapshot().encode();
        }
        if self.terminal.load(Ordering::SeqCst) {
            return self.snapshot().encode(); // Same binding, immutable old terminal.
        }
        if input.verb == Verb::Stop {
            let first = u64::from_be_bytes(input.content.try_into().unwrap_or([0; 8]));
            if first == 0 || first > now || self.signal.bounds().is_none_or(|bound| first < bound.origin) {
                self.signal.failure_at(now, true);
            } else { self.signal.failure_at(first, false); }
            return self.snapshot().encode();
        }
        if input.verb == Verb::Status { return self.snapshot().encode(); }
        if self.closed.load(Ordering::SeqCst) || !self.signal.admitted_at(false, now) {
            self.signal.failure_at(now, false); return self.snapshot().encode();
        }
        let mut flow = match self.flow.try_lock() {
            Ok(flow) => flow,
            Err(_) => {
                // Failure reaches the independent mailbox before any contended
                // queue/status projection. Do not wait or queue another frame.
                self.signal.failure_at(now, true); return self.snapshot().encode();
            }
        };
        if self.closed.load(Ordering::SeqCst) || flow.pending.is_some() || flow.queued.is_some()
            || flow.enqueued.checked_add(1).filter(|next| *next != u32::MAX) != Some(input.sequence) {
            self.signal.failure_at(now, false);
        } else {
            flow.queued = Some(input.content.to_vec()); flow.pending = Some(input.sequence);
            flow.enqueued = input.sequence; flow.phase = Phase::Active;
        }
        drop(flow);
        self.snapshot().encode()
    }
}

// SAFETY: C owns only bounded DATA pointers for the duration of the synchronous
// callback. Its permanent context is a retained Ingress, not any payload owner.
unsafe extern "C" fn exchange_callback(context: *const c_void, account: u32,
    bytes: *const u8, length: usize, now: u64, out: *mut u8) -> c_int {
    if context.is_null() || bytes.is_null() || out.is_null() || length > FRAME_BYTES { return 0; }
    let ingress = unsafe { &*context.cast::<Ingress>() };
    let raw = unsafe { std::slice::from_raw_parts(bytes, length) };
    let status = ingress.exchange(account, raw, now);
    unsafe { std::ptr::copy_nonoverlapping(status.as_ptr(), out, STATUS_BYTES); }
    1
}
unsafe extern "C" fn admit_callback(context: *const c_void, cleanup: u32) -> u32 {
    if context.is_null() || cleanup > 1 { return 0; }
    let signal = unsafe { &*context.cast::<Signal>() };
    u32::from(signal.admitted(cleanup == 1))
}
unsafe extern "C" fn signal_callback(context: *const c_void, first: u64, unknown: u32) {
    if context.is_null() { return; }
    let signal = unsafe { &*context.cast::<Signal>() };
    signal.failure_at(first, unknown != 0);
}


#[cfg(feature="e2-native-fixture")]
#[repr(C)]
#[derive(Clone,Copy,Debug,Default)]
pub(crate) struct FixtureIdentityFacts {
    pub version:u32,pub bytes:u32,pub role:u32,pub allocated:u32,pub allocation_entered:u32,
    pub allocation_returned:u32,pub consumed:u32,pub ready:u32,pub failed:u32,pub unknown:u32,
    pub in_call:u32,pub calls:u32,pub returns:u32,pub phase:u32,pub borrow_count:u32,
    pub pool:u32,pub acl_frame:u32,pub acl_generation:u32,pub acl_resources:[u32;3],
    pub fds:[u32;28],pub cf:[u32;12],pub recheck_epoch:u32,pub spent_epoch:u32,pub reserved:u32,
    pub last_ns:u64,pub first_ns:u64,
}
#[cfg(feature="e2-native-fixture")]
const _: [();272]=[();std::mem::size_of::<FixtureIdentityFacts>()];
#[cfg(feature="e2-native-fixture")]
const _: [();84]=[();std::mem::offset_of!(FixtureIdentityFacts,fds)];
#[cfg(feature="e2-native-fixture")]
const _: [();196]=[();std::mem::offset_of!(FixtureIdentityFacts,cf)];
#[cfg(feature="e2-native-fixture")]
const _: [();256]=[();std::mem::offset_of!(FixtureIdentityFacts,last_ns)];
#[cfg(feature="e2-native-fixture")]
const _: [();264]=[();std::mem::offset_of!(FixtureIdentityFacts,first_ns)];
#[cfg(feature="e2-native-fixture")]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum FixtureIdentityCustody { NotEntered,ReturnedEmpty,Settled,Unresolved }
#[cfg(feature="e2-native-fixture")]
impl FixtureIdentityFacts {
    pub(crate) fn inert()->Self { Self { version:1,bytes:272,..Self::default() } }
    pub(crate) fn valid(&self)->bool {
        self.version==1 && self.bytes==272 && self.role<=3 && self.reserved==0
            && [self.allocated,self.allocation_entered,self.allocation_returned,self.consumed,
                self.ready,self.failed,self.unknown,self.in_call,self.borrow_count].iter().all(|v|*v<=1)
            && self.allocation_returned<=self.allocation_entered && self.allocated<=self.allocation_returned
            && self.consumed<=self.allocated && self.returns<=self.calls && self.calls<=131_072
            && self.calls-self.returns<=1 && self.in_call==self.calls-self.returns
            && self.phase<=13 && self.pool<=7 && self.acl_frame<=5 && self.acl_generation<=28
            && self.fds.iter().chain(self.cf.iter()).chain(self.acl_resources.iter()).all(|v|*v<=5)
            && self.spent_epoch<=self.recheck_epoch && self.last_ns<=((1_u64<<61)-1)
            && self.first_ns<=self.last_ns
    }
    pub(crate) fn custody(&self)->FixtureIdentityCustody {
        use FixtureIdentityCustody::*;
        if !self.valid() || self.unknown!=0 || self.in_call!=0 || self.calls!=self.returns { return Unresolved; }
        let empty=self.fds.iter().chain(self.cf.iter()).chain(self.acl_resources.iter()).all(|v|*v==0)
            && self.pool==0 && self.acl_frame==0 && self.borrow_count==0 && self.ready==0 && self.consumed==0;
        if self.allocation_entered==0 && self.allocated==0 && empty { return NotEntered; }
        if self.allocation_returned==1 && self.allocated==0 && empty { return ReturnedEmpty; }
        if self.allocated==1 && self.consumed==1 && self.ready==0 && self.borrow_count==0
            && matches!(self.pool,0|6) && matches!(self.acl_frame,0|4)
            && self.fds.iter().chain(self.cf.iter()).chain(self.acl_resources.iter()).all(|v|matches!(*v,0|4)) { return Settled; }
        Unresolved
    }
}
#[cfg(feature="e2-native-fixture")]
#[repr(C)]
pub(crate) struct FixtureCheckpointApi {
    pub context:*mut c_void,
    pub point:unsafe extern "C" fn(*mut c_void,u32,u32,u32,u64,u32)->u32,
}
#[cfg(feature="e2-native-fixture")]
unsafe extern "C" {
    fn mrk_android_e2_fixture_client_identity_facts(book:*mut c_void,out:*mut FixtureIdentityFacts)->c_int;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct NativeFacts {
    pub(crate) version: u32, pub(crate) entered: u32, pub(crate) native_call: u32, pub(crate) returned: u32, pub(crate) unknown: u32,
    pub(crate) slots: [u32; 8], pub(crate) calls: u32, pub(crate) returns: u32, pub(crate) first_call: u32, pub(crate) first_code: i32,
    pub(crate) callbacks: u32, pub(crate) callback_returns: u32, pub(crate) peer: u32, pub(crate) reserved: u32,
}
impl NativeFacts {
    pub(crate) fn valid(&self) -> bool {
        self.version == 1 && [self.entered, self.native_call, self.returned, self.unknown].iter().all(|value| *value <= 1)
            && self.slots.iter().all(|state| *state <= 5) && self.returns <= self.calls && self.calls - self.returns <= 1
            && self.callback_returns <= self.callbacks && self.callbacks - self.callback_returns <= 1
            && self.first_call <= self.calls && self.reserved == 0
    }
    pub(crate) fn quiescent(&self) -> bool {
        self.valid() && self.unknown == 0 && self.native_call == 0
            && self.calls == self.returns && self.callbacks == self.callback_returns
    }
    pub(crate) fn settled(&self) -> bool { self.quiescent() && self.slots.iter().all(|state| matches!(*state, 0 | 4)) }
}
unsafe extern "C" {
    fn mrk_android_identity_available() -> c_int;
    pub(crate) fn mrk_android_client_bytes() -> usize;
    fn mrk_android_client_new(context: *const c_void,
        notify: unsafe extern "C" fn(*const c_void, u64, u32),
        admit: unsafe extern "C" fn(*const c_void, u32) -> u32,
        data: *const client_data::Api) -> *mut c_void;
    fn mrk_android_maintenance_client_new(context:*const c_void,
        notify:unsafe extern "C" fn(*const c_void,u64,u32),admit:unsafe extern "C" fn(*const c_void,u32)->u32,
        data:*const client_data::Api)->*mut c_void;
    fn mrk_android_maintenance_exchange(book:*mut c_void,method:u32,input:*const u8,output:*mut u8)->c_int;
    #[cfg(feature = "e2-native-fixture")]
    fn mrk_android_e2_fixture_missing_b(book:*mut c_void,input:*const u8,output:*mut u8)->c_int;
    #[cfg(feature = "e2-native-fixture")]
    fn mrk_android_e2_fixture_no_tail_exit(book:*mut c_void,exited:*mut u32)->c_int;
    fn mrk_android_maintenance_watch(book:*mut c_void)->c_int;
    fn mrk_android_maintenance_receive(book:*mut c_void)->c_int;
    fn mrk_android_maintenance_step(book:*mut c_void,output:*mut u8,capacity:u32,bytes:*mut u32,eof:*mut u32,exited:*mut u32)->c_int;
    pub(crate) fn mrk_android_client_begin(book: *mut c_void) -> c_int;
    pub(crate) fn mrk_android_client_exchange(book: *mut c_void, input: *const u8, count: usize, cleanup: u32, output: *mut u8) -> c_int;
    pub(crate) fn mrk_android_client_prepare(book: *mut c_void, input: *const u8, output: *mut u8) -> c_int;
    pub(crate) fn mrk_android_client_facts(book: *mut c_void, out: *mut NativeFacts) -> c_int;
    pub(crate) fn mrk_android_client_release_one(book: *mut c_void, slot: u32) -> c_int;
    pub(crate) fn mrk_android_client_retire(book: *mut c_void) -> c_int;
}

#[cfg(feature = "e2-native-fixture")]
#[derive(Clone, Copy, Default)]
struct FixtureClientAllocation {
    entered:bool, returned:bool, allocated:bool, consumed:bool,
    missing_b_attempted:bool, missing_b_returned:bool,
}
/// Copied original bookkeeping, not a close or authorization operation. An
/// inert/empty ClientBook may retire Rust DATA without closing a native cell.
#[cfg(feature = "e2-native-fixture")]
#[derive(Clone, Copy)]
pub(crate) struct FixtureClientCustody {
    pub allocation_entered:bool, pub allocation_returned:bool, pub allocated:bool,
    pub consumed:bool, pub settled:bool, pub unknown:bool, pub native:NativeFacts,
}

/// Native connection originals, owned by the SAME pre-registered IPC worker.
/// new() is inert. No automatic destructor closes a connection or releases a
/// callback context. Unknown stays retained by the enclosing original owner.
pub struct ClientBook {
    pointer: Option<NonNull<c_void>>, signal: ManuallyDrop<Arc<Signal>>,
    facts: NativeFacts, started: bool, retired: bool, poisoned: bool, in_call: bool, bytes: usize, account: u32,
    prepare: Option<prepare::ClientAttempt>, prepare_last: u64, data: Option<DataOwner>, maintenance:bool,
    // Last genuinely decoded native maintenance reply, retained before any
    // returned-time veto. Comparison DATA only; never a tail/retirement token.
    maintenance_reply:Option<(u32,crate::android_maintenance_wire::Frame)>,
    #[cfg(feature="e2-native-fixture")] fixture_identity:FixtureIdentityFacts,
    #[cfg(feature = "e2-native-fixture")]
    e2_allocation:FixtureClientAllocation,
}
unsafe impl Send for ClientBook {}
impl ClientBook {
    pub fn new(signal: Arc<Signal>) -> Self {
        Self { pointer: None, signal: ManuallyDrop::new(signal), facts: NativeFacts { version: 1, ..NativeFacts::default() },
            started: false, retired: false, poisoned: false, in_call: false, bytes: 0, account: 0,
            prepare: None, prepare_last: 0, data: None, maintenance:false,
            maintenance_reply:None,
            #[cfg(feature="e2-native-fixture")] fixture_identity:FixtureIdentityFacts::inert(),
            #[cfg(feature = "e2-native-fixture")]
            e2_allocation:FixtureClientAllocation::default(),
        }
    }
    #[cfg(feature = "e2-native-fixture")]
    pub(crate) fn fixture_custody(&self)->FixtureClientCustody {
        FixtureClientCustody {
            allocation_entered:self.e2_allocation.entered, allocation_returned:self.e2_allocation.returned,
            allocated:self.e2_allocation.allocated, consumed:self.e2_allocation.consumed,
            settled:self.settled(), unknown:self.poisoned || self.in_call || self.facts.unknown!=0
                || self.e2_allocation.entered && !self.e2_allocation.returned,
            native:self.facts,
        }
    }
    pub(crate) fn new_maintenance(signal:Arc<Signal>)->Self{let mut book=Self::new(signal);book.maintenance=true;book}
    pub(crate) fn maintenance_account(&self)->u32{self.account}
    pub(crate) fn maintenance_endpoint_absent(&self)->bool{
        self.maintenance && !self.in_call && !self.poisoned && self.facts.quiescent() && self.facts.slots[6]==0
    }
    pub(crate) fn tail_capture(&self)->Option<client_data::TailCapture>{
        if !self.maintenance || self.retired || self.poisoned{return None;}
        self.data.as_ref()?.tail_capture()
    }
    pub fn identity_available() -> bool { unsafe { mrk_android_identity_available() == 1 } }
    fn ptr(&self) -> *mut c_void { self.pointer.map_or(std::ptr::null_mut(), NonNull::as_ptr) }
    fn refresh(&mut self) -> bool {
        let mut next = NativeFacts::default();
        if self.pointer.is_none() || unsafe { mrk_android_client_facts(self.ptr(), &mut next) } != 1
            || !next.valid() || next.calls < self.facts.calls || next.returns < self.facts.returns
            || next.callbacks < self.facts.callbacks || next.callback_returns < self.facts.callback_returns {
            self.poisoned = true; self.signal.failure_now(true); return false;
        }
        self.facts = next;
        #[cfg(feature="e2-native-fixture")]
        {
            let mut identity=FixtureIdentityFacts::default();
            if unsafe{mrk_android_e2_fixture_client_identity_facts(self.ptr(),&mut identity)}!=1
                || !identity.valid() || identity.calls<self.fixture_identity.calls
                || identity.returns<self.fixture_identity.returns || identity.allocated<self.fixture_identity.allocated
                || identity.consumed<self.fixture_identity.consumed || identity.role!=2
                || identity.failed<self.fixture_identity.failed || identity.unknown<self.fixture_identity.unknown
                || identity.last_ns<self.fixture_identity.last_ns {
                self.poisoned=true;self.signal.failure_now(true);return false;
            }
            self.fixture_identity=identity;
            if identity.unknown!=0 { self.signal.failure_at(identity.first_ns,true); }
            else if identity.failed!=0 { self.signal.failure_at(identity.first_ns,false); }
        }
        if next.unknown != 0 { self.signal.failure_now(true); }
        true
    }
    pub fn begin(&mut self) -> Result<(), Failure> {
        if self.started || self.retired || self.pointer.is_some() { return Err(Failure::Unknown); }
        self.started = true;
        if Self::allocation_requirements().admitted_upper_bound().is_err() {
            self.signal.failure_now(false); return Err(Failure::Unavailable);
        }
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        self.account = crate::real_user().map_err(|_| { self.signal.failure_now(false); Failure::Unavailable })?;
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        // Fixture begin validates its own attached native provider before XPC use.
        // No feature/global Boolean is substituted for ordinary profile readiness.
        #[cfg(not(feature="e2-native-fixture"))]
        if !Self::identity_available() { self.signal.failure_now(false); return Err(Failure::Unavailable); }
        self.in_call = true;
        let size = unsafe { mrk_android_client_bytes() };
        if !(1..=16_384).contains(&size) { self.in_call = false; self.poisoned = true; self.signal.failure_now(true); return Err(Failure::Bounds); }
        self.data = Some(DataOwner::new(ClientData::registration(Arc::clone(&self.signal))));
        let context = self.data.as_ref().map_or(std::ptr::null(), DataOwner::pointer);
        #[cfg(feature = "e2-native-fixture")]
        { self.e2_allocation.entered=true; }
        self.pointer = NonNull::new(unsafe {
            if self.maintenance{mrk_android_maintenance_client_new(context,client_data::notify,client_data::admit,&client_data::API)}
            else{mrk_android_client_new(context, client_data::notify, client_data::admit, &client_data::API)}
        });
        #[cfg(feature = "e2-native-fixture")]
        { self.e2_allocation.returned=true; self.e2_allocation.allocated=self.pointer.is_some(); }
        self.in_call = false;
        if self.pointer.is_none() { self.signal.failure_now(false); return Err(Failure::Native); }
        self.bytes = size;
        self.in_call = true; let outcome = unsafe { mrk_android_client_begin(self.ptr()) }; self.in_call = false;
        if !self.refresh() || outcome != 1 || !self.facts.quiescent() {
            self.signal.failure_now(self.poisoned); return Err(Failure::Native);
        }
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        Ok(())
    }
    fn retain_maintenance_reply_data(&mut self,method:u32,returned:c_int,
        output:&[u8;crate::android_maintenance_wire::BYTES]){
        if returned==1 && matches!(method,3|4|5){
            if let Some(frame)=crate::android_maintenance_wire::Frame::decode(output){
                self.maintenance_reply=Some((method,frame));
            }
        }
    }
    pub(crate) fn maintenance_exchange(&mut self,method:u32,input:&[u8;crate::android_maintenance_wire::BYTES])
        ->Result<[u8;crate::android_maintenance_wire::BYTES],Failure>{
        let cleanup=method==7;
        if !matches!(method,3|4|5|7) || !self.maintenance || !self.started || self.retired || self.poisoned
            || self.in_call || !self.facts.quiescent() || !self.request_available(cleanup){return Err(Failure::Stopped);}
        let mut output=[0;crate::android_maintenance_wire::BYTES];self.in_call=true;
        let returned=unsafe{mrk_android_maintenance_exchange(self.ptr(),method,input.as_ptr(),
            if cleanup{std::ptr::null_mut()}else{output.as_mut_ptr()})};self.in_call=false;
        // Preserve this actual returned frame before refresh/Signal admission
        // can refuse its late arrival. No decode here authorizes a later step.
        self.retain_maintenance_reply_data(method,returned,&output);
        if !self.refresh() || returned!=1 || !self.facts.quiescent() || self.facts.peer!=0{
            self.signal.failure_now(true);return Err(Failure::Native);
        }
        if !self.signal.admitted(cleanup){return Err(Failure::Stopped);}Ok(output)
    }
    /// The one fixed negative calls the SAME native method5 body, without B.
    /// Its return is still only bytes until Client verifies Refused + full A.
    #[cfg(feature = "e2-native-fixture")]
    pub(crate) fn fixture_missing_b(&mut self,input:&[u8;crate::android_maintenance_wire::BYTES])
        ->Result<[u8;crate::android_maintenance_wire::BYTES],Failure> {
        if !self.maintenance || !self.started || self.retired || self.poisoned || self.in_call
            || self.e2_allocation.missing_b_attempted || !self.facts.quiescent()
            || self.facts.slots[7]!=2 || self.facts.slots[6]!=0 || !self.request_available(false) {
            return Err(Failure::Stopped);
        }
        let mut output=[0;crate::android_maintenance_wire::BYTES];
        self.e2_allocation.missing_b_attempted=true; self.in_call=true;
        let returned=unsafe { mrk_android_e2_fixture_missing_b(self.ptr(),input.as_ptr(),output.as_mut_ptr()) };
        self.in_call=false; self.e2_allocation.missing_b_returned=true;
        if !self.refresh() || returned!=1 || !self.facts.quiescent() || self.facts.peer!=0
            || self.facts.slots[7]!=2 || self.facts.slots[6]!=0 {
            self.signal.failure_now(true); return Err(Failure::Native);
        }
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        Ok(output)
    }
    /// Only original NOTE_EXIT DATA. Client additionally requires its actually
    /// verified fixed Refused reply; no tail/EOF/capture/admission is created.
    #[cfg(feature = "e2-native-fixture")]
    pub(crate) fn fixture_no_tail_exit(&mut self)->Result<bool,Failure> {
        if !self.maintenance || !self.started || self.retired || self.poisoned || self.in_call
            || !self.e2_allocation.missing_b_attempted || !self.e2_allocation.missing_b_returned
            || !self.facts.quiescent() || self.facts.slots[7]!=2 || self.facts.slots[6]!=0
            || !self.signal.admitted(true) {
            return Err(Failure::Stopped);
        }
        let mut exited=0; self.in_call=true;
        let returned=unsafe { mrk_android_e2_fixture_no_tail_exit(self.ptr(),&mut exited) };
        self.in_call=false;
        if !self.refresh() || returned!=1 || exited>1 || !self.facts.quiescent()
            || self.facts.slots[7]!=2 || self.facts.slots[6]!=0 {
            self.signal.failure_now(true); return Err(Failure::Native);
        }
        if !self.signal.admitted(true) { return Err(Failure::Stopped); }
        Ok(exited==1)
    }
    pub(crate) fn maintenance_watch(&mut self)->Result<(),Failure>{
        if !self.maintenance || self.retired || self.poisoned || self.in_call || !self.signal.admitted(false){return Err(Failure::Stopped);}
        self.in_call=true;let returned=unsafe{mrk_android_maintenance_watch(self.ptr())};self.in_call=false;
        if !self.refresh() || returned!=1 || !self.facts.quiescent(){self.signal.failure_now(self.poisoned);return Err(Failure::Native);}
        Ok(())
    }
    pub(crate) fn maintenance_receive(&mut self)->Result<(),Failure>{
        if !self.maintenance || self.retired || self.poisoned || self.in_call || !self.signal.admitted(true){return Err(Failure::Stopped);}
        self.in_call=true;let returned=unsafe{mrk_android_maintenance_receive(self.ptr())};self.in_call=false;
        if !self.refresh() || returned!=1 || !self.facts.quiescent(){self.signal.failure_now(true);return Err(Failure::Native);}Ok(())
    }
    pub(crate) fn maintenance_step(&mut self,output:&mut[u8])->Result<(usize,bool,bool),Failure>{
        if !self.maintenance || self.retired || self.poisoned || self.in_call || !self.signal.admitted(true)
            || output.is_empty() || output.len()>crate::android_maintenance_wire::BYTES+1{return Err(Failure::Stopped);}
        let(mut bytes,mut eof,mut exited)=(0,0,0);self.in_call=true;
        let returned=unsafe{mrk_android_maintenance_step(self.ptr(),output.as_mut_ptr(),output.len() as u32,&mut bytes,&mut eof,&mut exited)};
        self.in_call=false;
        if !self.refresh() || returned!=1 || !self.facts.quiescent() || bytes as usize>output.len() || eof>1 || exited>1{
            self.signal.failure_now(true);return Err(Failure::Native);
        }Ok((bytes as usize,eof==1,exited==1))
    }
    #[cfg(feature="e2-native-fixture")]
    pub(crate) fn fixture_identity_custody(&self)->FixtureIdentityCustody { self.fixture_identity.custody() }
    #[cfg(feature="e2-native-fixture")]
    pub(crate) fn fixture_identity_facts(&self)->FixtureIdentityFacts { self.fixture_identity }
    pub fn allocation_requirements() -> crate::android_service_budget::ClientRequirements {
        crate::android_service_budget::client_requirements()
    }
    pub fn prepare_custody(&self) -> prepare::PeerCustody {
        self.prepare.as_ref().map_or(prepare::PeerCustody::PrepareNotEntered, prepare::ClientAttempt::state)
    }
    pub fn prepared_nonce(&self) -> Option<[u8; 16]> {
        self.prepare.as_ref().and_then(prepare::ClientAttempt::nonce)
    }
    pub fn peer_nonentry_known(&self) -> bool {
        self.prepare.as_ref().is_none_or(prepare::ClientAttempt::peer_nonentry_known)
    }
    fn request_available(&self, cleanup: bool) -> bool {
        loop {
            let Some(data) = self.data.as_ref() else { return false; };
            if data.idle_known() { return self.signal.admitted(cleanup); }
            if data.uncertain() || !self.signal.admitted(cleanup) { return false; }
            // DATA-only waiting on this same original worker/clock; no second
            // native pool/proxy/connection/arena is created while backing lives.
            std::thread::park_timeout(std::time::Duration::from_millis(2));
        }
    }
    /// One original native prepare call (or an identical Pending observation).
    /// The same registered pthread/connection/Signal survives every failure.
    pub fn prepare(&mut self) -> Result<prepare::Reply, Failure> {
        if self.maintenance{return Err(Failure::Binding);}
        if !self.started || self.retired || self.poisoned || self.in_call || !self.facts.quiescent()
            || !self.signal.admitted(false) { return Err(Failure::Stopped); }
        if !self.request_available(false) { return Err(Failure::Stopped); }
        let bounds = self.signal.bounds().ok_or(Failure::Unknown)?;
        let request = prepare::Request { bounds: prepare::Bounds { role: prepare::Role::Registration,
            origin: bounds.origin, work: bounds.work, hard: bounds.hard } };
        let input = request.encode().ok_or(Failure::Bounds)?;
        if self.prepare.is_none() { self.prepare = prepare::ClientAttempt::new(request); }
        let attempt = self.prepare.as_mut().ok_or(Failure::Unknown)?;
        if attempt.request() != request || !attempt.enter_native() { return Err(Failure::Binding); }
        // Possible server entry is already latched before entering Objective-C.
        let mut raw = [0; prepare::BYTES]; self.in_call = true;
        let returned = unsafe { mrk_android_client_prepare(self.ptr(), input.as_ptr(), raw.as_mut_ptr()) };
        self.in_call = false;
        let reply = if self.refresh() && returned == 1 && self.facts.quiescent() && self.facts.peer == 0 {
            prepare::Reply::decode(&raw)
        } else { None };
        let observed = uptime();
        let valid = match (reply, observed) {
            (Some(value), Some(now)) if value.bounds == request.bounds
                && value.bounds.accepts_observation(value.first, now, self.prepare_last) => {
                    self.prepare_last = now;
                    self.signal.accept_remote(value.first, value.bounds.cleanup(value.first), value.unknown, now)
                },
            _ => false,
        };
        if !valid {
            if let Some(attempt) = self.prepare.as_mut() { attempt.lost_reply(); }
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let reply = reply.ok_or(Failure::Unknown)?;
        if !self.prepare.as_mut().is_some_and(|attempt| attempt.accept_authenticated(reply)) {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        Ok(reply)
    }
    pub fn exchange(&mut self, input: &[u8], cleanup: bool) -> Result<Status, Failure> {
        let decoded = Envelope::decode(input)?;
        if cleanup && decoded.verb == Verb::Push { return Err(Failure::Bounds); }
        if self.prepared_nonce() != Some(decoded.nonce) || self.peer_nonentry_known()
            || decoded.verb == Verb::Push && self.prepare_custody() != prepare::PeerCustody::Ready {
            return Err(Failure::Binding);
        }
        if !self.started || self.retired || self.poisoned || self.in_call || !self.facts.quiescent()
            || !self.signal.admitted(cleanup) { return Err(Failure::Stopped); }
        if !self.request_available(cleanup) { return Err(Failure::Stopped); }
        let mut out = [0; STATUS_BYTES];
        self.in_call = true;
        let returned = unsafe { mrk_android_client_exchange(self.ptr(), input.as_ptr(), input.len(), u32::from(cleanup), out.as_mut_ptr()) };
        self.in_call = false;
        if !self.refresh() || returned != 1 || !self.facts.quiescent() || self.facts.peer != 0 {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let status = Status::decode(&out).ok_or_else(|| { self.signal.failure_now(true); Failure::Unknown })?;
        let envelope = Envelope::decode(input)?;
        if status.nonce != envelope.nonce || status.account != self.account {
            self.signal.failure_now(true); return Err(Failure::Binding);
        }
        let now = uptime().ok_or_else(|| { self.signal.unknown_clock(); Failure::Unknown })?;
        if !self.signal.accept_remote(status.first, status.cleanup, status.unknown, now) {
            return Err(Failure::Unknown);
        }
        if !self.signal.admitted(cleanup) { return Err(Failure::Stopped); }
        Ok(status)
    }
    /// One explicit release attempt per known object; independent known releases
    /// continue after a sibling error. No invalidate-as-finality shortcut.
    pub fn release(&mut self) -> bool {
        if self.retired { return self.settled(); }
        if self.in_call || self.poisoned { self.signal.failure_now(true); return false; }
        if self.facts.entered != 0 && !self.signal.admitted(true) { return false; }
        if self.pointer.is_none() {
            if self.data.as_mut().is_some_and(|data| !data.settle()) { return false; }
            self.data = None; self.retired = true;
            // Native allocator never entered/returned None, or its original
            // retire already returned. DATA exclusivity is independently actual.
            unsafe { ManuallyDrop::drop(&mut self.signal); }
            return true;
        }
        if !self.refresh() { return false; }
        // Actual acquisition order for a call is pool3, NSData5, proxy4.
        // Cleanup after a partial exchange must use that same dependency order,
        // not numeric slot order. Unused reservations7/6 carry no native object.
        for slot in [7, 6, 4, 5, 3, 2, 1, 0] {
            if self.facts.slots[slot] != 2 { continue; }
            if !self.signal.admitted(true) { return false; }
            self.in_call = true;
            let returned = unsafe { mrk_android_client_release_one(self.ptr(), slot as u32) };
            self.in_call = false;
            if !self.refresh() { return false; }
            if returned != 1 { self.signal.failure_now(true); }
        }
        if !self.facts.settled() || !self.request_available(true) { return false; }
        self.in_call = true;
        let retired = unsafe { mrk_android_client_retire(self.ptr()) };
        self.in_call = false;
        if retired != 1 { self.poisoned = true; self.signal.failure_now(true); return false; }
        self.pointer = None; self.bytes = 0;
        #[cfg(feature = "e2-native-fixture")]
        { self.e2_allocation.consumed=true; }
        if !self.signal.admitted(true) || self.data.as_mut().is_none_or(|data| !data.settle()) { return false; }
        self.data = None; self.retired = true;
        // Only actual native return PLUS same-DATA exclusivity ends this owner.
        unsafe { ManuallyDrop::drop(&mut self.signal); }
        true
    }
    pub fn settled(&self) -> bool { self.retired && self.pointer.is_none() && self.data.is_none()
        && !self.in_call && !self.poisoned && self.facts.settled() }
    pub fn retained_bytes(&self) -> Option<usize> {
        if self.settled() { Some(0) } else if !self.started { Some(0) } else { None }
    }
}

#[cfg(feature = "android-registration-helper")]
pub use crate::android_service_resident::{ServiceBook,ServiceControl,ServiceRegistry,ServiceDomain,ServiceRole};

#[cfg(test)]
mod tests {
    use super::*;
    fn bounds() -> Bounds { Bounds { origin: 10, work: 10 + WORK_NS, hard: 10 + HARD_NS } }
    #[test]
    fn never_started_client_retires_its_actual_signal_without_arming_or_native_entry() {
        // GO loss / failed installed-service Check occurs before ClockBridge
        // capture. This is the production inert release path, not a receipt
        // standing in for a connection that may already have been entered.
        let signal=Arc::new(Signal::reserved());
        let mut book=ClientBook::new(signal.clone());
        assert!(signal.bounds().is_none());assert!(book.peer_nonentry_known());
        assert!(!book.settled());assert!(book.release());assert!(book.settled());
        assert!(book.release());assert_eq!(book.retained_bytes(),Some(0));
        assert_eq!(Arc::strong_count(&signal),1);assert!(!signal.unknown());
    }
    #[test]
    fn removal_cutoff_contracts_same_signal_without_rearming_or_widening_wire(){
        // Pure fixed-cutoff DATA, with deliberately DISTINCT clock origins.
        // No native proof, clock sample, peer or service is manufactured here.
        let p=800_000_000_000;let u=3_000_000_000;
        let make=||RemovalClockData::from_samples(p,p+110_000_000_000,p+120_000_000_000,u,p+100,p+110,u+20).unwrap();
        let clock=make();assert_eq!(clock.uptime_work,u+110_000_000_000-110);
        assert_eq!(clock.uptime_hard,u+120_000_000_000-110);
        assert!(clock.observe_samples(p+110,u+20,u+100,p+200,u+120));
        assert_eq!(clock.parent_first.load(Ordering::SeqCst),0);assert!(clock.work_allowed());
        // Actual Parent W (including sleep with almost no UPTIME advance)
        // irreversibly stops work, but permits known consuming cleanup to H.
        for (before,after) in [(u+21,u+22),(u+109_999_999_900,u+109_999_999_920)]{
            let expiry=make();assert!(expiry.observe_samples(p+110,u+20,before,p+110_000_000_000,after));
            assert_eq!(expiry.parent_first.load(Ordering::SeqCst),p+110_000_000_000);
            assert!(!expiry.work_allowed());assert!(expiry.cleanup_allowed());
            assert!(expiry.observe_samples(p+110_000_000_000,after,after+1,p+110_000_000_001,after+2));
            assert!(!expiry.work_allowed());assert!(expiry.cleanup_allowed());
            assert!(!expiry.observe_samples(p+110_000_000_001,after+2,after+3,p+120_000_000_000,after+4));
            assert!(!expiry.cleanup_allowed());
            assert!(!expiry.observe_samples(p+120_000_000_000,after+4,after+5,p+120_000_000_001,after+6));
        }
        // The supplemental own projection contracts work/hard independently;
        // it never fabricates a Parent-domain first-F or permits resumed work.
        let projected=make();assert!(projected.observe_samples(p+110,u+20,
            projected.uptime_work-1,p+200,projected.uptime_work));
        assert!(!projected.work_allowed());assert!(projected.cleanup_allowed());
        assert_eq!(projected.parent_first.load(Ordering::SeqCst),0);
        assert!(!projected.observe_samples(p+200,projected.uptime_work,
            projected.uptime_hard-1,p+201,projected.uptime_hard));assert!(!projected.cleanup_allowed());
        // No relative offset/rate equality is claimed. Both actual domains are
        // checked, without rebase, tolerance or historical failure conversion.
        for (before,parent,after) in [(u+100,p+300,u+120),(u+100,p+150,u+120),
            (u+21,p+1_000_000_000,u+22)]{
            let drift=make();assert!(drift.observe_samples(p+110,u+20,before,parent,after));
            assert!(drift.work_allowed());assert_eq!(drift.parent_first.load(Ordering::SeqCst),0);
        }
        for (before,parent,after) in [(u+19,p+200,u+120),(u+100,p+109,u+120),
            (u+121,p+200,u+120),(0,p+200,u+120),(u+100,FIRST_MASK,u+120),
            (u+100,p+200,FIRST_MASK+1)]{
            let bad=make();assert!(!bad.observe_samples(p+110,u+20,before,parent,after));
            assert!(!bad.cleanup_allowed());
            assert!(!bad.observe_samples(p+110,u+20,u+100,p+200,u+120));
        }
        for args in [(0,110_000_000_000,120_000_000_000,u,p,p,u+1),
            (p,p+110_000_000_001,p+120_000_000_000,u,p,p,u+1),
            (p,p+110_000_000_000,p+120_000_000_000,u,p+110_000_000_000,p+110_000_000_000,u+1),
            (p,p+110_000_000_000,p+120_000_000_000,FIRST_MASK-1,p,p,FIRST_MASK)]{
            assert!(RemovalClockData::from_samples(args.0,args.1,args.2,args.3,args.4,args.5,args.6).is_none());
        }
        // A known Parent STOP overlays non-success without an own first-F.
        // A later genuine own Unknown must stay independently observable.
        let stopped=Signal::reserved();stopped.arm_at(bounds(),20).unwrap();
        assert!(!stopped.stored_unknown());
        assert_eq!(Signal::live_word_data(0,true,false),UNKNOWN_BIT);
        assert_eq!(stopped.snapshot_word(Signal::live_word_data(0,true,false)).cleanup,Some(bounds().hard));
        stopped.failure_at(30,true);assert!(stopped.stored_unknown());assert!(!stopped.stored_clock_unknown());
        assert_eq!(stopped.first(),Some(30));assert_eq!(stopped.cleanup(),Some(30+CLEANUP_NS));
        assert!(stopped.admitted_at(true,30+CLEANUP_NS-1));assert!(!stopped.admitted_at(true,30+CLEANUP_NS));
        let signal=Signal::reserved();signal.arm_at(bounds(),20).unwrap();
        signal.failure_at(30,false);signal.clock_unknown();
        assert_eq!(signal.first(),Some(30));assert!(signal.stored_clock_unknown());assert_eq!(signal.cleanup(),None);
        let absent=Signal::reserved();absent.arm_at(bounds(),20).unwrap();absent.clock_unknown();assert_eq!(absent.first(),None);
        let ordinary=Signal::reserved();ordinary.arm_at(bounds(),20).unwrap();
        assert_eq!(ordinary.work_endpoint(),Some(bounds().work));assert_eq!(ordinary.cleanup(),Some(bounds().hard));
        assert!(ordinary.admitted_at(false,bounds().origin+120_000_000_001));assert!(ordinary.removal_cutoff().is_none());
        assert_eq!(Signal::live_word_data(30,true,true),30|UNKNOWN_BIT|CLOCK_UNKNOWN_BIT);
        assert_eq!(Signal::live_word_data(30|TERMINAL_BIT,true,true),30|TERMINAL_BIT);
        let frozen=ordinary.freeze();ordinary.clock_unknown();ordinary.failure_at(40,true);
        assert_eq!(ordinary.snapshot(),frozen);assert_eq!(ordinary.freeze(),frozen);
        let terminal=Signal::reserved();terminal.arm_at(bounds(),20).unwrap();
        let stopped_terminal=terminal.freeze_parent_data(true,false);
        assert!(stopped_terminal.unknown);assert_eq!(stopped_terminal.first,None);
        assert_eq!(stopped_terminal.cleanup,Some(bounds().hard));assert!(!terminal.admitted_at(true,21));
        assert_eq!(terminal.freeze_parent_data(false,true),stopped_terminal);
        let invalid=Signal::reserved();invalid.arm_at(bounds(),20).unwrap();
        let invalid_terminal=invalid.freeze_parent_data(true,true);
        assert!(invalid_terminal.unknown);assert_eq!(invalid_terminal.cleanup,None);assert_eq!(invalid_terminal.first,None);

        // Real production return-retention reducer, entirely inert DATA here.
        // A later clock veto must not erase a decoded BeginDrain binding, but
        // that observation cannot start a client, settle a native cell or make
        // the stopped Signal admissible. The inline slot is capacity-accounted
        // by size_of::<ClientBook>/the enclosing maintenance Client.
        use crate::android_maintenance_wire as maintenance;
        #[cfg(all(target_os="macos",target_arch="x86_64"))]
        let target=b"x86_64-apple-darwin".as_slice();
        #[cfg(not(all(target_os="macos",target_arch="x86_64")))]
        let target=b"aarch64-apple-darwin".as_slice();
        let mut identity=maintenance::Identity{instance:[1;16],source:[b'1';40],release:[0;64],target:[0;24]};
        identity.release[..7].copy_from_slice(b"fixture");identity.target[..target.len()].copy_from_slice(target);
        let mut binding=maintenance::Binding::request(identity,[2;16],maintenance::Bounds{
            origin:100,work:100+maintenance::WORK_NS,hard:100+maintenance::HARD_NS}).unwrap();
        binding.instance=identity.instance;binding.number=9;binding.account=501;binding.slot=2;binding.acceptance=110;
        binding.nonce[..8].copy_from_slice(b"MRKACTX1");binding.nonce[8..].copy_from_slice(&binding.number.to_be_bytes());
        binding.cut=120;binding.cutoff=120+maintenance::CLEANUP_NS;
        let frame=maintenance::Frame{kind:maintenance::Kind::BeginDrainReply,
            code:maintenance::Code::Accepted,binding,tail:None};
        let raw=frame.encode().unwrap();let signal=Arc::new(Signal::reserved());
        let mut book=ClientBook::new_maintenance(signal.clone());assert!(book.maintenance_reply.is_none());
        for (method,returned) in [(5,0),(5,-1),(7,1),(99,1)]{
            book.retain_maintenance_reply_data(method,returned,&raw);assert!(book.maintenance_reply.is_none());
        }
        book.retain_maintenance_reply_data(5,1,&raw);assert_eq!(book.maintenance_reply,Some((5,frame)));
        signal.clock_unknown();assert!(!signal.admitted_at(false,130));
        assert_eq!(book.maintenance_reply,Some((5,frame)));assert!(!book.started);assert!(book.pointer.is_none());
        assert!(!book.settled());assert_eq!(signal.first(),None);
        book.retain_maintenance_reply_data(5,1,&[0;maintenance::BYTES]);
        book.retain_maintenance_reply_data(7,1,&raw);assert_eq!(book.maintenance_reply,Some((5,frame)));
        assert!(book.release());assert_eq!(Arc::strong_count(&signal),1);
    }

    #[test]
    fn earliest_failure_precedes_later_stop_and_cleanup_never_renews() {
        let signal = Signal::reserved(); signal.arm_at(bounds(), 20).unwrap();
        signal.failure_at(100, false); signal.failure_at(1_000, false);
        assert_eq!(signal.first(), Some(100)); assert_eq!(signal.cleanup(), Some(100 + CLEANUP_NS));
        signal.failure_at(80, true); assert_eq!(signal.cleanup(), Some(80 + CLEANUP_NS));
        assert!(!signal.admitted_at(false, 200)); assert!(signal.admitted_at(true, 200));
        assert!(!signal.admitted_at(true, 80 + CLEANUP_NS));
        signal.freeze(); signal.failure_at(60, false); assert_eq!(signal.first(), Some(80));
    }
    #[test]
    fn exact_envelope_bound_includes_outer_header() {
        let nonce = [1; 16];
        assert_eq!(Envelope::encode(nonce, 1, Verb::Push, &vec![1; CONTENT_BYTES]).unwrap().len(), FRAME_BYTES);
        assert!(Envelope::encode(nonce, 1, Verb::Push, &vec![1; CONTENT_BYTES + 1]).is_err());
        for (sequence, verb, data) in [(0, Verb::Push, b"x".as_slice()), (1, Verb::Status, b"".as_slice()),
            (0, Verb::Stop, b"x".as_slice()), (u32::MAX, Verb::Push, b"x".as_slice())] {
            assert!(Envelope::encode(nonce, sequence, verb, data).is_err());
        }
    }
    #[test]
    fn one_slot_ack_is_not_worker_or_lease_finality_and_seal_is_irreversible() {
        let ingress = Ingress::new(); assert!(ingress.prepare_binding(501, prepare::nonce_for_counter(1).unwrap(), bounds(), 20));
        let first = Envelope::encode(prepare::nonce_for_counter(1).unwrap(), 1, Verb::Push, b"metadata").unwrap();
        let status = Status::decode(&ingress.exchange(501, &first, 30)).unwrap();
        assert_eq!((status.enqueued, status.processed), (1, 0));
        let packet = ingress.take().unwrap().unwrap();
        assert!(ingress.take().unwrap().is_none());
        ingress.acknowledge(packet, 0).unwrap();
        ingress.seal().unwrap(); assert!(ingress.input_settled());
        let late = Envelope::encode(prepare::nonce_for_counter(1).unwrap(), 2, Verb::Push, b"late").unwrap();
        ingress.exchange(501, &late, 40);
        assert_eq!(ingress.signal.first(), Some(40)); assert!(ingress.take().unwrap().is_none());
        assert_ne!(ingress.snapshot().phase, Phase::Complete);
    }
    #[test]
    fn prepared_status_and_stop_exist_before_hello_without_rebinding() {
        let ingress=Ingress::new();let nonce=prepare::nonce_for_counter(7).unwrap();
        assert!(ingress.prepare_binding(501,nonce,bounds(),20));
        let status=Envelope::encode(nonce,0,Verb::Status,&[]).unwrap();
        let observed=Status::decode(&ingress.exchange(501,&status,21)).unwrap();
        assert_eq!((observed.account,observed.nonce,observed.enqueued),(501,nonce,0));
        let stop=Envelope::encode(nonce,0,Verb::Stop,&22u64.to_be_bytes()).unwrap();
        ingress.exchange(501,&stop,23);
        assert_eq!(ingress.signal().first(),Some(22));
        assert!(ingress.take().unwrap().is_none());
        let push=Envelope::encode(nonce,1,Verb::Push,b"never enters").unwrap();
        ingress.exchange(501,&push,24);assert!(ingress.take().unwrap().is_none());
        assert_eq!(ingress.signal().bounds(),Some(bounds()));
        assert!(!ingress.prepare_binding(501,prepare::nonce_for_counter(8).unwrap(),bounds(),25));
        assert_eq!(ingress.bound_nonce(),Some(nonce));
    }
    #[test]
    fn first_stop_mailbox_progresses_while_queue_is_contended() {
        let ingress = Ingress::new(); assert!(ingress.prepare_binding(501, prepare::nonce_for_counter(1).unwrap(), bounds(), 20));
        let first = Envelope::encode(prepare::nonce_for_counter(1).unwrap(), 1, Verb::Push, b"start").unwrap();
        ingress.exchange(501, &first, 30);
        let _held = ingress.flow.lock().unwrap();
        let stop = Envelope::encode(prepare::nonce_for_counter(1).unwrap(), 0, Verb::Stop, &40u64.to_be_bytes()).unwrap();
        ingress.exchange(501, &stop, 50);
        assert_eq!(ingress.signal.first(), Some(40));
        assert_eq!(ingress.signal.cleanup(), Some(40 + CLEANUP_NS));
    }
}

#[cfg(all(test,feature="e2-native-fixture"))]
mod fixture_identity_data_tests {
    use super::{FixtureIdentityFacts,FixtureIdentityCustody as Custody};
    #[test]
    fn identity_original_custody_never_comes_from_readiness_or_empty_defaults() {
        let mut f=FixtureIdentityFacts::inert();
        assert_eq!(f.custody(),Custody::NotEntered);
        f.role=1;f.allocation_entered=1;
        assert_eq!(f.custody(),Custody::Unresolved);
        f.allocation_returned=1;
        assert_eq!(f.custody(),Custody::ReturnedEmpty);
        f.allocated=1;f.ready=1;f.pool=4;f.fds[0]=2;
        assert_eq!(f.custody(),Custody::Unresolved);
        f.ready=0;f.consumed=1;f.pool=6;
        assert_eq!(f.custody(),Custody::Unresolved); // acquired FD still survives
        f.fds[0]=4;
        assert_eq!(f.custody(),Custody::Settled);
        f.unknown=1;
        assert_eq!(f.custody(),Custody::Unresolved); // consumed cannot erase ambiguity
    }
    #[test]
    fn identity_pending_phase_borrow_and_acl_originals_gate_finality() {
        let mut f=FixtureIdentityFacts{role:1,allocated:1,allocation_entered:1,
            allocation_returned:1,consumed:1,..FixtureIdentityFacts::inert()};
        f.calls=1;f.in_call=1;
        assert_eq!(f.custody(),Custody::Unresolved);
        f.returns=1;f.in_call=0;f.borrow_count=1;
        assert_eq!(f.custody(),Custody::Unresolved);
        f.borrow_count=0;f.acl_frame=4;f.acl_resources[0]=2;
        assert_eq!(f.custody(),Custody::Unresolved);
        f.acl_resources[0]=4;
        assert_eq!(f.custody(),Custody::Settled);
        f.first_ns=2;f.last_ns=1;
        assert!(!f.valid());assert_eq!(f.custody(),Custody::Unresolved);
    }
}
