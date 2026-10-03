//! Fixed private app/helper protocol. DATA decoding cannot create a native
//! candidate, launch permission, process identity, finality or publication right.
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};
use crate::wrapping_keychain::{self as wrapping, transport};

pub const REQUEST_BYTES: usize = 128;
pub const STOP_BYTES: usize = 40;
pub const NOTICE_BYTES: usize = 32;
pub const TERMINAL_BYTES: usize = 128 + 2 * transport::BYTES + 32;
pub const RESPONSE_LIMIT: usize = 16 * 1024;
// Closed fixed Rust/control storage only, not opaque Security/allocator/RSS.
pub const HELPER_CONTROL_ALLOWANCE: usize = 128 * 1024;
pub const CLEANUP_NS: u64 = 2_000_000_000;
pub const WORK_NS: u64 = 10_000_000_000;
const _: () = assert!(TERMINAL_BYTES + NOTICE_BYTES <= RESPONSE_LIMIT);
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Operation { Initialize, Lookup }
impl Operation {
    pub fn code(self) -> u32 { match self { Self::Initialize => 1, Self::Lookup => 2 } }
}
pub struct Request {
    pub operation: Operation, pub nonce: [u8; 16], pub vault: [u8; 16], pub generation: [u8; 16],
    pub work: u64, pub maximum_cleanup: u64, pub initial_key: Zeroizing<[u8; 32]>,
}
fn u32_at(b: &[u8], at: usize) -> u32 { u32::from_le_bytes(b[at..at+4].try_into().unwrap()) }
fn u64_at(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at+8].try_into().unwrap()) }
fn put32(b: &mut [u8], at: usize, n: u32) { b[at..at+4].copy_from_slice(&n.to_le_bytes()); }
fn put64(b: &mut [u8], at: usize, n: u64) { b[at..at+8].copy_from_slice(&n.to_le_bytes()); }
fn bounds(work: u64, cleanup: u64) -> bool {
    work != 0 && cleanup >= work && cleanup - work <= CLEANUP_NS
}
impl Request {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len()!=REQUEST_BYTES || &b[..8]!=b"MRKVKQ01" || u32_at(b,8)!=1
            || b[16..32]==[0;16] || b[112..128]!=[0;16] { return None; }
        let operation=match u32_at(b,12) { 1=>Operation::Initialize, 2=>Operation::Lookup, _=>return None };
        let vault=b[32..48].try_into().ok()?; let generation=b[48..64].try_into().ok()?;
        wrapping::Context::new(vault,generation).ok()?;
        let work=u64_at(b,64); let maximum_cleanup=u64_at(b,72);
        if !bounds(work,maximum_cleanup) || operation==Operation::Lookup && b[80..112]!=[0;32] { return None; }
        let mut initial_key=Zeroizing::new([0;32]); initial_key.copy_from_slice(&b[80..112]);
        Some(Self { operation, nonce:b[16..32].try_into().ok()?, vault,generation,work,maximum_cleanup,initial_key })
    }
    pub fn encode(&self, b: &mut [u8;REQUEST_BYTES]) -> bool {
        b.zeroize(); b[..8].copy_from_slice(b"MRKVKQ01"); put32(b,8,1);put32(b,12,self.operation.code());
        b[16..32].copy_from_slice(&self.nonce);b[32..48].copy_from_slice(&self.vault);b[48..64].copy_from_slice(&self.generation);
        put64(b,64,self.work);put64(b,72,self.maximum_cleanup);b[80..112].copy_from_slice(&*self.initial_key);
        Self::decode(b).is_some()
    }
}
pub struct Stop { pub first: u64, pub cleanup: u64 }
impl Stop {
    pub fn encode(&self, nonce: &[u8;16]) -> Option<[u8;STOP_BYTES]> {
        if self.first==0 || self.cleanup<self.first || self.cleanup-self.first>CLEANUP_NS { return None; }
        let mut b=[0;STOP_BYTES];b[..8].copy_from_slice(b"MRKVKS01");b[8..24].copy_from_slice(nonce);
        put64(&mut b,24,self.first);put64(&mut b,32,self.cleanup);Some(b)
    }
}
#[derive(Clone,Copy)]
pub struct Notice { pub first:u64, pub cleanup:u64, pub effect:u32, pub valid:bool }
impl Notice {
    pub fn decode(b:&[u8],request:&Request) -> Option<Self> {
        if b.len()!=NOTICE_BYTES || &b[..8]!=b"MRKVKN01" || u32_at(b,24)>3 || u32_at(b,28)>1 { return None; }
        let first=u64_at(b,8);let cleanup=u64_at(b,16);let effect=u32_at(b,24);
        if first==0 || cleanup<first || cleanup-first>CLEANUP_NS || cleanup>request.maximum_cleanup
            || request.operation==Operation::Lookup && effect!=0 { return None; }
        Some(Self{first,cleanup,effect,valid:u32_at(b,28)==1})
    }
}
/// Contains only validated complete native fact records. The candidate cell
/// stays in the original private byte buffer; this DATA view never lends it.
pub struct Terminal {
    pub first:u64,pub cleanup:u64,pub effect:u32,pub valid:bool,
    pub add:Option<transport::Receipt>,pub lookup:Option<transport::Receipt>,
    pub auth_settled:bool,pub filesystem_settled:bool,pub input_closed:bool,pub candidate:bool,
}
impl Terminal {
    pub fn decode(b:&[u8],request:&Request) -> Option<Self> {
        if b.len()!=TERMINAL_BYTES || &b[..8]!=b"MRKVKT01" || u32_at(b,8)!=1
            || u32_at(b,12)!=request.operation.code() || b[16..32]!=request.nonce
            || b[32..48]!=request.vault || b[48..64]!=request.generation
            || u64_at(b,64)!=request.work || u64_at(b,72)!=request.maximum_cleanup
            || (100..128).step_by(4).any(|at|u32_at(b,at)>1) || u32_at(b,96)>3 { return None; }
        let first=u64_at(b,80);let cleanup=u64_at(b,88);let effect=u32_at(b,96);
        if cleanup>request.maximum_cleanup || cleanup==0
            || first!=0 && (cleanup<first || cleanup-first>CLEANUP_NS)
            || request.operation==Operation::Lookup && (effect!=0 || u32_at(b,104)!=0) { return None; }
        let receipt=|present:bool,at:usize,operation| {
            if present { transport::decode(&b[at..at+transport::BYTES],operation).map(Some) }
            else { b[at..at+transport::BYTES].iter().all(|v|*v==0).then_some(None) }
        };
        let add=receipt(u32_at(b,104)==1,128,wrapping::Operation::AddOnly)?;
        let lookup=receipt(u32_at(b,108)==1,128+transport::BYTES,wrapping::Operation::Lookup)?;
        if add.as_ref().is_some_and(|r|r.effect_code()!=effect) { return None; }
        if request.operation==Operation::Initialize && lookup.is_some()
            && !add.as_ref().is_some_and(transport::Receipt::added) { return None; }
        let candidate=u32_at(b,124)==1;
        let value=Self{first,cleanup,effect,valid:u32_at(b,100)==1,add,lookup,
            auth_settled:u32_at(b,112)==1,filesystem_settled:u32_at(b,116)==1,input_closed:u32_at(b,120)==1,candidate};
        if candidate {
            if !value.success(request.operation) { return None; }
        } else if b[TERMINAL_BYTES-32..]!=[0;32] { return None; }
        Some(value)
    }
    pub fn success(&self,operation:Operation) -> bool {
        self.first==0 && self.valid && self.auth_settled && self.filesystem_settled && self.input_closed
            && self.candidate && self.lookup.as_ref().is_some_and(transport::Receipt::candidate_consumed)
            && match operation {
                Operation::Initialize=>self.effect==1 && self.add.as_ref().is_some_and(transport::Receipt::added),
                Operation::Lookup=>self.effect==0 && self.add.is_none(),
            }
    }
}
/// Helper-side fixed-field encoder. Callers supply actual retained receipts;
/// successful syntax alone is not native or process finality.
#[cfg(feature="vault-helper")]
pub fn terminal_encode(request:&Request,terminal:&Terminal,key:Option<&[u8;32]>,out:&mut[u8;TERMINAL_BYTES])->bool {
    out.zeroize();out[..8].copy_from_slice(b"MRKVKT01");put32(out,8,1);put32(out,12,request.operation.code());
    out[16..32].copy_from_slice(&request.nonce);out[32..48].copy_from_slice(&request.vault);out[48..64].copy_from_slice(&request.generation);
    put64(out,64,request.work);put64(out,72,request.maximum_cleanup);put64(out,80,terminal.first);put64(out,88,terminal.cleanup);
    put32(out,96,terminal.effect);
    for (at,value) in [(100,terminal.valid),(104,terminal.add.is_some()),(108,terminal.lookup.is_some()),
        (112,terminal.auth_settled),(116,terminal.filesystem_settled),(120,terminal.input_closed),(124,terminal.candidate)] { put32(out,at,u32::from(value)); }
    for (at,value) in [(128,&terminal.add),(128+transport::BYTES,&terminal.lookup)] {
        if let Some(value)=value { if !transport::encode(value,&mut out[at..at+transport::BYTES]) { out.zeroize();return false; } }
    }
    if terminal.candidate != key.is_some() { out.zeroize();return false; }
    if let Some(key)=key { out[TERMINAL_BYTES-32..].copy_from_slice(key); }
    let valid=Terminal::decode(out,request).is_some();if !valid { out.zeroize(); }valid
}
unsafe extern "C" { fn mrk_vault_uptime(out:*mut u64)->i32; }
pub fn uptime()->Option<u64> {
    let mut out=0;
    // SAFETY: a fixed scalar CLOCK_UPTIME_RAW observation, no pointer retained.
    (unsafe{mrk_vault_uptime(&mut out)}==1 && out!=0).then_some(out)
}
/// One original bracket; never recaptured after a failure or delayed delivery.
pub struct ClockBridge { before:Instant,after:Instant,raw:u64,last:u64 }
impl ClockBridge {
    pub fn capture()->Option<Self> {
        let before=Instant::now();let raw=uptime()?;let after=Instant::now();
        (after>=before).then_some(Self{before,after,raw,last:raw})
    }
    pub fn endpoint(&self,end:Instant)->Option<u64> {
        let delta=end.checked_duration_since(self.after)?;if delta.is_zero(){return None;}
        self.raw.checked_add(u64::try_from(delta.as_nanos()).ok()?)
    }
    pub fn earlier_endpoint(&self,end:Instant)->Option<u64> {
        // STOP can predate this bracket. Checked subtraction conservatively
        // preserves its original bound; never replace it with receipt-now.
        if end>=self.after {self.raw.checked_add(u64::try_from(end.duration_since(self.after).as_nanos()).ok()?)}
        else {self.raw.checked_sub(u64::try_from(self.after.duration_since(end).as_nanos()).ok()?).filter(|v|*v!=0)}
    }
    /// Pure inverse lower bound from this same original bracket. Query admission
    /// must separately authenticate origin<=event<=observed raw now and reject
    /// clock regression. This method alone grants NO admission/clock authority.
    /// Unlike failure_bound, admission-inclusive F may predate the bracket.
    /// No uptime call, last mutation, new bracket or post-close native call.
    pub fn earlier_instant_data(&self,event:u64)->Option<Instant> {
        if event==0 { return None; }
        if event>=self.raw {
            self.before.checked_add(Duration::from_nanos(event-self.raw))
        } else {
            self.before.checked_sub(Duration::from_nanos(self.raw-event))
        }
    }
    fn local_failure_bound(&self,event:Instant,observed:Instant,raw_now:u64)->Option<u64>{
        if event<self.after || event>observed || observed<self.after || raw_now<self.last{return None;}
        let bound=self.earlier_endpoint(event)?;
        (bound>=self.raw && bound<=raw_now).then_some(bound)
    }
    /// Helper-local F from this one retained bracket. An out-of-bracket/future
    /// event or regressed raw clock is Unknown, never converted using now.
    pub fn local_failure(&mut self,event:Instant)->Option<u64>{
        let observed=Instant::now();let now=uptime()?;
        let bound=self.local_failure_bound(event,observed,now)?;self.last=now;Some(bound)
    }
    pub fn failure_bound(&mut self,event:u64)->Option<Instant> {
        let now=uptime()?;if now<self.last || event<self.raw || event>now{return None;}
        self.last=now;self.before.checked_add(Duration::from_nanos(event-self.raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request()->Request {Request{operation:Operation::Lookup,nonce:[1;16],vault:[2;16],generation:[3;16],
        work:11,maximum_cleanup:12,initial_key:Zeroizing::new([0;32])}}
    #[test]
    fn request_refuses_extra_fields_identity_alias_and_lookup_secret() {
        let mut b=[0;REQUEST_BYTES];assert!(request().encode(&mut b));assert!(Request::decode(&b).is_some());
        for index in [8,12,80,112,127] {let mut bad=b;bad[index]^=128;assert!(Request::decode(&bad).is_none());}
        let mut bad=b;bad[48..64].copy_from_slice(&[2;16]);assert!(Request::decode(&bad).is_none());
        assert!(Request::decode(&b[..127]).is_none());
    }
    #[test]
    fn terminal_success_never_follows_syntax_or_an_empty_receipt() {
        let r=request();let mut b=[0;TERMINAL_BYTES];b[..8].copy_from_slice(b"MRKVKT01");
        put32(&mut b,8,1);put32(&mut b,12,2);b[16..32].copy_from_slice(&r.nonce);
        b[32..48].copy_from_slice(&r.vault);b[48..64].copy_from_slice(&r.generation);
        put64(&mut b,64,r.work);put64(&mut b,72,r.maximum_cleanup);put64(&mut b,88,r.maximum_cleanup);
        assert!(Terminal::decode(&b,&r).is_some());
        put32(&mut b,124,1);assert!(Terminal::decode(&b,&r).is_none());
    }
    #[test]
    fn helper_local_failure_uses_only_its_original_bracket_and_rejects_invalid_ordering(){
        let before=Instant::now();let after=before+Duration::from_nanos(5);
        let bridge=ClockBridge{before,after,raw:100,last:120};let observed=after+Duration::from_nanos(40);
        assert_eq!(bridge.local_failure_bound(after+Duration::from_nanos(20),observed,140),Some(120));
        for (event,at,raw) in [(before,observed,140),(observed+Duration::from_nanos(1),observed,140),
            (after,observed,119),(observed,observed,130)]{
            assert_eq!(bridge.local_failure_bound(event,at,raw),None);
        }
        // A late-reported EARLIER event remains a contraction, not a clock rewind.
        assert_eq!(bridge.local_failure_bound(after+Duration::from_nanos(1),observed,140),Some(101));
    }
    #[test]
    fn original_clock_mapping_is_earlier_and_checked_not_a_renewed_budget() {
        let before=Instant::now();let after=before+Duration::from_nanos(5);
        let bridge=ClockBridge{before,after,raw:100,last:100};
        assert_eq!(bridge.endpoint(after),None);
        assert_eq!(bridge.endpoint(after+Duration::from_nanos(10)),Some(110));
        assert_eq!(bridge.earlier_endpoint(before),Some(95));
        let near=ClockBridge{raw:u64::MAX,..bridge};assert_eq!(near.endpoint(after+Duration::from_nanos(1)),None);
    }
}


#[cfg(test)]
mod query_clock_data_tests {
    use super::*;
    #[test]
    fn admission_inclusive_inverse_is_pure_checked_and_keeps_pre_bracket_failure() {
        let before=Instant::now();
        let bridge=ClockBridge { before,after:before+Duration::from_nanos(7),raw:100,last:111 };
        assert_eq!(bridge.earlier_instant_data(99),before.checked_sub(Duration::from_nanos(1)));
        assert_eq!(bridge.earlier_instant_data(100),Some(before));
        assert_eq!(bridge.earlier_instant_data(107),before.checked_add(Duration::from_nanos(7)));
        assert_eq!(bridge.earlier_instant_data(0),None);
        assert_eq!(bridge.last,111); // no native read or mutable clock observation
        assert!(bridge.earlier_instant_data(99).is_none_or(|event|event<before));
        // Boundary arithmetic uses checked Instant operations, including hosts
        // whose Instant representation refuses a very old result.
        let edge=ClockBridge { before,after:before,raw:u64::MAX,last:u64::MAX };
        assert_eq!(edge.earlier_instant_data(1),
            before.checked_sub(Duration::from_nanos(u64::MAX-1)));
        let small=ClockBridge { before,after:before,raw:1,last:1 };
        assert_eq!(small.earlier_instant_data(u64::MAX),
            before.checked_add(Duration::from_nanos(u64::MAX-1),));
    }
}
