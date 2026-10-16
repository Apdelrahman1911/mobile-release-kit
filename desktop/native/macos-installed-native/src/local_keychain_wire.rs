//! Separate fixed local-journal wire. DATA never grants enrollment, project
//! exclusion, confirmation, helper finality or Store execution authority.
use zeroize::{Zeroize, Zeroizing};
use crate::{vault_helper_wire as vault, wrapping_keychain::{self as wrapping, transport}};
pub const REQUEST_BYTES: usize = 128;
pub const TERMINAL_BYTES: usize = 144 + 2 * transport::BYTES + 32;
pub const MAX_SEQUENCE: u32 = 513;
const _: () = assert!(REQUEST_BYTES == vault::REQUEST_BYTES && TERMINAL_BYTES + vault::NOTICE_BYTES <= vault::RESPONSE_LIMIT);
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose { LocalJournalKey, LocalCheckpoint }
impl Purpose {
    pub fn code(self)->u32 { match self { Self::LocalJournalKey=>1, Self::LocalCheckpoint=>2 } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Operation { AddRead, ReadRequired, ProbeAbsent }
impl Operation {
    pub fn code(self)->u32 { match self { Self::AddRead=>1, Self::ReadRequired=>2, Self::ProbeAbsent=>3 } }
}
/// Native-selected locator only; public DATA construction is not an owner loan.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Context { locator:[u8;32], purpose:Purpose, sequence:u32 }
impl Context {
    pub fn new(locator:[u8;32],purpose:Purpose,sequence:u32)->Option<Self> {
        if locator==[0;32] || !match purpose { Purpose::LocalJournalKey=>sequence==0,
            Purpose::LocalCheckpoint=>(1..=MAX_SEQUENCE).contains(&sequence) } { return None; }
        Some(Self{locator,purpose,sequence})
    }
    pub fn locator(&self)->&[u8;32] { &self.locator }
    pub fn purpose(&self)->Purpose { self.purpose }
    pub fn sequence(&self)->u32 { self.sequence }
}
pub struct Request { pub context:Context, pub operation:Operation, pub nonce:[u8;16],
    pub work:u64, pub maximum_cleanup:u64, pub value:Zeroizing<[u8;32]> }
fn u32_at(b:&[u8],at:usize)->u32 { u32::from_le_bytes(b[at..at+4].try_into().unwrap()) }
fn u64_at(b:&[u8],at:usize)->u64 { u64::from_le_bytes(b[at..at+8].try_into().unwrap()) }
fn put32(b:&mut[u8],at:usize,n:u32) { b[at..at+4].copy_from_slice(&n.to_le_bytes()); }
fn put64(b:&mut[u8],at:usize,n:u64) { b[at..at+8].copy_from_slice(&n.to_le_bytes()); }
impl Request {
    pub fn decode(b:&[u8])->Option<Self> {
        if b.len()!=REQUEST_BYTES || &b[..8]!=b"MRKLJQ01" || u32_at(b,8)!=1 || b[16..32]==[0;16]
            || u32_at(b,116)!=1 || u32_at(b,124)!=0 { return None; }
        let operation=match u32_at(b,12) {1=>Operation::AddRead,2=>Operation::ReadRequired,3=>Operation::ProbeAbsent,_=>return None};
        let purpose=match u32_at(b,112) {1=>Purpose::LocalJournalKey,2=>Purpose::LocalCheckpoint,_=>return None};
        let context=Context::new(b[32..64].try_into().ok()?,purpose,u32_at(b,120))?;
        let work=u64_at(b,64); let maximum_cleanup=u64_at(b,72);
        if work==0 || maximum_cleanup<work || maximum_cleanup-work>vault::CLEANUP_NS
            || operation!=Operation::AddRead && b[80..112]!=[0;32] { return None; }
        let mut value=Zeroizing::new([0;32]);value.copy_from_slice(&b[80..112]);
        Some(Self{context,operation,nonce:b[16..32].try_into().ok()?,work,maximum_cleanup,value})
    }
    pub fn encode(&self,b:&mut[u8;REQUEST_BYTES])->bool {
        b.zeroize();b[..8].copy_from_slice(b"MRKLJQ01");put32(b,8,1);put32(b,12,self.operation.code());
        b[16..32].copy_from_slice(&self.nonce);b[32..64].copy_from_slice(self.context.locator());
        put64(b,64,self.work);put64(b,72,self.maximum_cleanup);b[80..112].copy_from_slice(&*self.value);
        put32(b,112,self.context.purpose().code());put32(b,116,1);put32(b,120,self.context.sequence());
        Self::decode(b).is_some()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResultKind { None, Value, Absent }
impl ResultKind { fn code(self)->u32 { match self {Self::None=>0,Self::Value=>1,Self::Absent=>2} } }
pub struct Terminal { pub common:vault::Terminal, pub result:ResultKind }
impl Terminal {
    pub fn decode(b:&[u8],request:&Request)->Option<Self> {
        if b.len()!=TERMINAL_BYTES || &b[..8]!=b"MRKLJT01" || u32_at(b,8)!=1
            || u32_at(b,12)!=request.operation.code() || b[16..32]!=request.nonce || b[32..64]!=*request.context.locator()
            || u64_at(b,64)!=request.work || u64_at(b,72)!=request.maximum_cleanup
            || u32_at(b,128)!=request.context.purpose().code() || u32_at(b,132)!=1
            || u32_at(b,136)!=request.context.sequence() || (100..128).step_by(4).any(|at|u32_at(b,at)>1)
            || u32_at(b,96)>3 { return None; }
        let result=match u32_at(b,140) {0=>ResultKind::None,1=>ResultKind::Value,2=>ResultKind::Absent,_=>return None};
        let first=u64_at(b,80);let cleanup=u64_at(b,88);let effect=u32_at(b,96);
        if cleanup==0 || cleanup>request.maximum_cleanup || first!=0 && (cleanup<first || cleanup-first>vault::CLEANUP_NS)
            || request.operation!=Operation::AddRead && (effect!=0 || u32_at(b,104)!=0) { return None; }
        let receipt=|present:bool,at:usize,op| if present {transport::decode(&b[at..at+transport::BYTES],op).map(Some)}
            else {b[at..at+transport::BYTES].iter().all(|v|*v==0).then_some(None)};
        let add=receipt(u32_at(b,104)==1,144,wrapping::Operation::AddOnly)?;
        let lookup=receipt(u32_at(b,108)==1,144+transport::BYTES,wrapping::Operation::Lookup)?;
        if add.as_ref().is_some_and(|r|r.effect_code()!=effect)
            || request.operation==Operation::AddRead && lookup.is_some() && !add.as_ref().is_some_and(transport::Receipt::added) {return None;}
        let candidate=u32_at(b,124)==1;
        if candidate!=(result==ResultKind::Value) {return None;}
        let value=Self{common:vault::Terminal{first,cleanup,effect,valid:u32_at(b,100)==1,add,lookup,
            auth_settled:u32_at(b,112)==1,filesystem_settled:u32_at(b,116)==1,input_closed:u32_at(b,120)==1,candidate},result};
        if result!=ResultKind::None && !value.success(request.operation) {return None;}
        if result!=ResultKind::Value && b[TERMINAL_BYTES-32..]!=[0;32] {return None;}
        Some(value)
    }
    pub fn success(&self,operation:Operation)->bool {
        let t=&self.common;
        t.first==0 && t.valid && t.auth_settled && t.filesystem_settled && t.input_closed && match operation {
            Operation::ProbeAbsent=>self.result==ResultKind::Absent && !t.candidate && t.effect==0 && t.add.is_none()
                && t.lookup.as_ref().is_some_and(transport::Receipt::local_absent),
            Operation::ReadRequired=>self.result==ResultKind::Value && t.success(vault::Operation::Lookup),
            Operation::AddRead=>self.result==ResultKind::Value && t.success(vault::Operation::Initialize),
        }
    }
}
#[cfg(any(feature="vault-helper",test))]
pub fn terminal_encode(request:&Request,terminal:&Terminal,value:Option<&[u8;32]>,b:&mut[u8;TERMINAL_BYTES])->bool {
    b.zeroize();b[..8].copy_from_slice(b"MRKLJT01");put32(b,8,1);put32(b,12,request.operation.code());
    b[16..32].copy_from_slice(&request.nonce);b[32..64].copy_from_slice(request.context.locator());
    put64(b,64,request.work);put64(b,72,request.maximum_cleanup);
    let t=&terminal.common;put64(b,80,t.first);put64(b,88,t.cleanup);put32(b,96,t.effect);
    for(at,v) in [(100,t.valid),(104,t.add.is_some()),(108,t.lookup.is_some()),(112,t.auth_settled),
        (116,t.filesystem_settled),(120,t.input_closed),(124,t.candidate)] {put32(b,at,u32::from(v));}
    put32(b,128,request.context.purpose().code());put32(b,132,1);put32(b,136,request.context.sequence());put32(b,140,terminal.result.code());
    for(at,r) in [(144,&t.add),(144+transport::BYTES,&t.lookup)] {if let Some(r)=r {if !transport::encode(r,&mut b[at..at+transport::BYTES]) {b.zeroize();return false;}}}
    if (terminal.result==ResultKind::Value)!=value.is_some() {b.zeroize();return false;}
    if let Some(v)=value {b[TERMINAL_BYTES-32..].copy_from_slice(v);}
    let valid=Terminal::decode(b,request).is_some();if !valid {b.zeroize();}valid
}
/// Closed transport alternatives, not a configurable provider or authority type.
pub enum RequestEnvelope { Vault(vault::Request), Local(Request) }
impl RequestEnvelope {
    pub fn decode(b:&[u8])->Option<Self> { match b.get(..8)? {
        b"MRKVKQ01"=>vault::Request::decode(b).map(Self::Vault),b"MRKLJQ01"=>Request::decode(b).map(Self::Local),_=>None} }
    pub fn encode(&self,b:&mut[u8;REQUEST_BYTES])->bool {match self {Self::Vault(r)=>r.encode(b),Self::Local(r)=>r.encode(b)}}
    pub fn nonce(&self)->&[u8;16] {match self {Self::Vault(r)=>&r.nonce,Self::Local(r)=>&r.nonce}}
    pub fn work(&self)->u64 {match self {Self::Vault(r)=>r.work,Self::Local(r)=>r.work}}
    pub fn maximum_cleanup(&self)->u64 {match self {Self::Vault(r)=>r.maximum_cleanup,Self::Local(r)=>r.maximum_cleanup}}
    pub fn is_add(&self)->bool {match self {Self::Vault(r)=>r.operation==vault::Operation::Initialize,Self::Local(r)=>r.operation==Operation::AddRead}}
    pub fn is_probe(&self)->bool {matches!(self,Self::Local(r) if r.operation==Operation::ProbeAbsent)}
    pub fn wipe_value(&mut self) {match self {Self::Vault(r)=>r.initial_key.zeroize(),Self::Local(r)=>r.value.zeroize()}}
    pub fn terminal_bytes(&self)->usize {match self {Self::Vault(_)=>vault::TERMINAL_BYTES,Self::Local(_)=>TERMINAL_BYTES}}
    pub fn terminal_magic(&self)->&'static[u8;8] {match self {Self::Vault(_)=>b"MRKVKT01",Self::Local(_)=>b"MRKLJT01"}}
    pub fn notice(&self,b:&[u8])->Option<vault::Notice> {vault::Notice::decode_bounds(b,self.maximum_cleanup(),self.is_add())}
}
pub enum TerminalEnvelope { Vault(vault::Terminal), Local(Terminal) }
impl std::ops::Deref for TerminalEnvelope {type Target=vault::Terminal;fn deref(&self)->&Self::Target {match self {Self::Vault(t)=>t,Self::Local(t)=>&t.common}}}
impl TerminalEnvelope {
    pub fn decode(b:&[u8],r:&RequestEnvelope)->Option<Self> {match r {RequestEnvelope::Vault(r)=>vault::Terminal::decode(b,r).map(Self::Vault),RequestEnvelope::Local(r)=>Terminal::decode(b,r).map(Self::Local)}}
    pub fn success_for(&self,r:&RequestEnvelope)->bool {match(self,r) {(Self::Vault(t),RequestEnvelope::Vault(r))=>t.success(r.operation),(Self::Local(t),RequestEnvelope::Local(r))=>t.success(r.operation),_=>false}}
    pub fn absent(&self)->bool {matches!(self,Self::Local(t) if t.result==ResultKind::Absent)}
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request(purpose:Purpose,sequence:u32,operation:Operation)->Request {Request{context:Context::new([7;32],purpose,sequence).unwrap(),operation,
        nonce:[1;16],work:11,maximum_cleanup:12,value:Zeroizing::new([0;32])}}
    #[test]
    fn local_exact_context_and_legacy_discriminator() {
        for (purpose,sequence) in [(Purpose::LocalJournalKey,0),(Purpose::LocalCheckpoint,1),(Purpose::LocalCheckpoint,513)] {
            for operation in [Operation::AddRead,Operation::ReadRequired,Operation::ProbeAbsent] {
                let r=request(purpose,sequence,operation);let mut b=[0;128];assert!(r.encode(&mut b));
                assert!(Request::decode(&b).is_some());assert!(vault::Request::decode(&b).is_none());
                for at in [8,12,112,116,124,127] {let mut bad=b;bad[at]^=128;assert!(Request::decode(&bad).is_none());}
                assert!(Request::decode(&b[..127]).is_none());
            }
        }
        assert!(Context::new([7;32],Purpose::LocalCheckpoint,0).is_none());assert!(Context::new([7;32],Purpose::LocalCheckpoint,514).is_none());
        assert!(Context::new([7;32],Purpose::LocalJournalKey,1).is_none());assert!(Context::new([0;32],Purpose::LocalJournalKey,0).is_none());
    }
    #[test]
    fn lookup_never_transports_a_proposal_and_bounds_are_original() {
        let mut r=request(Purpose::LocalCheckpoint,1,Operation::ProbeAbsent);let mut b=[0;128];r.value[0]=1;assert!(!r.encode(&mut b));
        r.operation=Operation::AddRead;assert!(r.encode(&mut b));r.maximum_cleanup=r.work+vault::CLEANUP_NS+1;assert!(!r.encode(&mut b));
        r.maximum_cleanup=r.work-1;assert!(!r.encode(&mut b));
    }
    #[test]
    fn syntax_cannot_create_absence_or_value_and_context_cannot_alias() {
        let r=request(Purpose::LocalCheckpoint,1,Operation::ProbeAbsent);let mut b=[0;TERMINAL_BYTES];
        b[..8].copy_from_slice(b"MRKLJT01");put32(&mut b,8,1);put32(&mut b,12,r.operation.code());
        b[16..32].copy_from_slice(&r.nonce);b[32..64].copy_from_slice(r.context.locator());
        put64(&mut b,64,r.work);put64(&mut b,72,r.maximum_cleanup);put64(&mut b,88,r.maximum_cleanup);
        put32(&mut b,128,r.context.purpose().code());put32(&mut b,132,1);put32(&mut b,136,1);
        assert!(Terminal::decode(&b,&r).is_some());
        for at in [16,32,64,72,128,132,136] {let mut bad=b;bad[at]^=1;assert!(Terminal::decode(&bad,&r).is_none());}
        put32(&mut b,140,2);assert!(Terminal::decode(&b,&r).is_none());put32(&mut b,140,1);put32(&mut b,124,1);assert!(Terminal::decode(&b,&r).is_none());
    }
    #[test]
    fn positive_absence_is_local_probe_only_and_never_a_key() {
        let r=request(Purpose::LocalCheckpoint,513,Operation::ProbeAbsent);
        let t=Terminal{common:vault::Terminal{first:0,cleanup:12,effect:0,valid:true,add:None,
            lookup:Some(transport::local_absence_fixture()),auth_settled:true,filesystem_settled:true,input_closed:true,candidate:false},result:ResultKind::Absent};
        let mut b=[0;TERMINAL_BYTES];assert!(terminal_encode(&r,&t,None,&mut b));
        assert!(Terminal::decode(&b,&r).unwrap().success(Operation::ProbeAbsent));
        assert!(!t.success(Operation::ReadRequired));assert!(!t.success(Operation::AddRead));
        assert!(!t.common.success(vault::Operation::Lookup));
        assert!(!terminal_encode(&r,&t,Some(&[9;32]),&mut b));
        assert!(terminal_encode(&r,&t,None,&mut b));b[TERMINAL_BYTES-1]=1;assert!(Terminal::decode(&b,&r).is_none());
        for at in [80,100,112,116,120] {assert!(terminal_encode(&r,&t,None,&mut b));b[at]^=1;assert!(Terminal::decode(&b,&r).is_none());}
    }

}
