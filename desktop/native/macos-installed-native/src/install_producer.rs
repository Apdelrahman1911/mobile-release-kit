//! One fixed detached-signature original under the caller's existing W/H/F.
//! SignatureVerified means pinned-chain/signature correspondence AND settled
//! native references, NOT Developer-ID Application purpose or release authority.
//! The caller still owes strict current-product purpose/leaf checks, compiled
//! release correspondence, original descriptor/package POST and ordinary GO.
use std::{ffi::{c_int,c_void},os::{fd::{AsRawFd,BorrowedFd},unix::ffi::OsStrExt},path::Path,ptr::NonNull,time::Instant};
use crate::android_service_management::{CellCustody,Decision};

pub const DESCRIPTOR_LIMIT:usize=65536;
pub const CERTIFICATE_LIMIT:usize=16384;
const SLOTS:usize=26;
const STEPS:u8=29;
const RELEASE:u32=64;
const CELL_LIMIT:usize=131072;
const PATH_LIMIT:usize=1024;
const CODE_STEPS:u8=8;
const CODE_SLOTS:usize=6;
// Same 320KiB supplied-resource ceiling; includes bounded C path/stat stack.
const CODE_STACK_LIMIT:usize=8192;
const DOMAIN:&[u8]=b"MobileReleaseKit-package-producer-v2\0";

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum SignatureResult { SignatureVerified,Unavailable,Refused,Unknown }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum CurrentProductRole { EntryApp,PayloadApp }
impl CurrentProductRole {
    fn suffix(self)->&'static [u8] {match self {
        Self::EntryApp=>b"",Self::PayloadApp=>b"/Contents/Helpers/MobileReleaseKitPayload.app",
    }}
    fn executable(self)->&'static [u8] {match self {
        Self::EntryApp=>b"/Contents/MacOS/mrk-macos-entry",
        Self::PayloadApp=>b"/Contents/MacOS/mobile-release-kit-desktop",
    }}
}
/// One fixed App purpose fact, not package authority or uniform child signers.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum CurrentProductResult { PurposeVerified,Unavailable,Refused,Unknown }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ProducerOperation { DetachedSignature,CurrentProduct(CurrentProductRole) }
impl ProducerOperation {
    fn code(self)->u32 {match self {
        Self::DetachedSignature=>0,Self::CurrentProduct(CurrentProductRole::EntryApp)=>1,
        Self::CurrentProduct(CurrentProductRole::PayloadApp)=>2,
    }}
    fn steps(self)->u8 {if self==Self::DetachedSignature{STEPS}else{CODE_STEPS}}
    fn slots(self)->usize {if self==Self::DetachedSignature{SLOTS}else{CODE_SLOTS}}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum VerificationResult { Matched,Unavailable,Refused,Unknown }
#[derive(Clone,Copy)]
enum VerificationInput<'a> {
    Signature {descriptor:&'a [u8],signature:&'a [u8]},
    Current {outer:c_int,code:c_int,outer_path:&'a [u8]},
}
fn canonical_outer_path(path:&[u8],role:CurrentProductRole)->bool {
    path.len()>1 && path.len()<PATH_LIMIT && path[0]==b'/' && !path.contains(&0)
        && path[1..].split(|b|*b==b'/').all(|part|!part.is_empty()&&part!=b"."&&part!=b"..")
        && path.len().checked_add(role.suffix().len()).and_then(|n|n.checked_add(role.executable().len()))
            .is_some_and(|n|n<PATH_LIMIT)
}
impl VerificationInput<'_> {
    fn valid_for(self,operation:ProducerOperation)->bool {match (self,operation) {
        (Self::Signature{descriptor,signature},ProducerOperation::DetachedSignature)=>
            !descriptor.is_empty()&&descriptor.len()<=DESCRIPTOR_LIMIT&&matches!(signature.len(),256|384|512),
        (Self::Current{outer,code,outer_path},ProducerOperation::CurrentProduct(role))=>
            outer>=0&&code>=0&&canonical_outer_path(outer_path,role),
        _=>false,
    }}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ProducerPhase { SourceSelection,AllocateCell,Inspect(u8),Release(u8),RetireCell }
impl ProducerPhase {
    pub fn is_cleanup(self)->bool { matches!(self,Self::Release(_)|Self::RetireCell) }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct ProducerCustody {
    pub operation:ProducerOperation,pub phase:Option<ProducerPhase>,pub cell:CellCustody,pub references:[u32;SLOTS],
    pub entered:bool,pub in_call:bool,pub gate_entered:bool,
    /// Positive native fact only; it cannot replace settled()/purpose checks.
    pub signature_matched:bool,pub purpose_matched:Option<CurrentProductRole>,pub failed:bool,pub unknown:bool,
    pub calls:u32,pub returned:u32,pub first_failure:Option<Instant>,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ProducerCheckpoint {
    Before { phase:ProducerPhase,custody:ProducerCustody },
    Returned { phase:ProducerPhase,at:Instant,custody:ProducerCustody },
}
#[repr(C)]
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
struct Report {
    version:u32,phase:u32,calls:u32,returned:u32,matched:u32,failed:u32,unknown:u32,reserved:u32,
    states:[u32;SLOTS],
}
#[repr(C)]
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
struct SourceSigner {
    version:u32,rsa_bits:u32,team:[u8;10],leaf_sha1:[u8;20],leaf_sha256:[u8;32],public_key_pkcs1_sha256:[u8;32],
}
const _: [();136]=[();std::mem::size_of::<Report>()];
const _: [();104]=[();std::mem::size_of::<SourceSigner>()];

/// SOURCE correspondence only. The constructor is private; a descriptor cannot
/// choose a key or promote these bytes to a native certificate-purpose result.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct SourceSignerData { raw:SourceSigner }
impl SourceSignerData {
    pub fn team_data(&self)->&[u8;10] { &self.raw.team }
    pub fn leaf_sha1_data(&self)->&[u8;20] { &self.raw.leaf_sha1 }
    pub fn leaf_sha256_data(&self)->&[u8;32] { &self.raw.leaf_sha256 }
    pub fn public_key_pkcs1_sha256_data(&self)->&[u8;32] { &self.raw.public_key_pkcs1_sha256 }
    pub fn rsa_bits_data(&self)->u32 { self.raw.rsa_bits }
}
fn source_data(raw:SourceSigner)->Option<SourceSignerData> {
    (raw.version==1 && matches!(raw.rsa_bits,2048|3072|4096)
        && raw.team.iter().all(|b|b.is_ascii_uppercase()||b.is_ascii_digit())
        && raw.leaf_sha1.iter().any(|b|*b!=0) && raw.leaf_sha256.iter().any(|b|*b!=0)
        && raw.public_key_pkcs1_sha256.iter().any(|b|*b!=0)).then_some(SourceSignerData{raw})
}

unsafe extern "C" {
    fn mrk_install_producer_source(out:*mut SourceSigner)->c_int;
    fn mrk_install_producer_source_leaf_matches(der:*const u8,size:usize)->c_int;
    fn mrk_install_producer_new(descriptor:*const u8,size:usize,signature:*const u8,signature_size:usize)->*mut c_void;
    fn mrk_install_producer_code_new(role:u32,outer:c_int,code:c_int,outer_path:*const u8,path_size:usize)->*mut c_void;
    fn mrk_install_producer_step(cell:*mut c_void,phase:u32,out:*mut Report)->c_int;
    fn mrk_install_producer_release(cell:*mut c_void,slot:u32,out:*mut Report)->c_int;
    fn mrk_install_producer_retire(cell:*mut c_void)->c_int;
}
pub fn source_signer_data()->Option<SourceSignerData> {
    let mut raw=SourceSigner::default();
    // SAFETY: fixed SOURCE query copies only the bounded record, no references,
    // paths, key discovery, caller-selected policy or retained output pointer.
    if unsafe{mrk_install_producer_source(&mut raw)}!=1 { return None; }
    source_data(raw)
}
pub fn source_leaf_matches_data(der:&[u8])->bool {
    if der.is_empty() || der.len()>CERTIFICATE_LIMIT { return false; }
    // SAFETY: bounded slice lives throughout a SOURCE byte-comparison call.
    // Caller must establish these are the ACTUAL returned code-signing DER.
    unsafe{mrk_install_producer_source_leaf_matches(der.as_ptr(),der.len())==1}
}

fn phase_slot(phase:u8,operation:ProducerOperation)->Option<usize> {
    if operation!=ProducerOperation::DetachedSignature {return match phase {
        1..=4=>Some(usize::from(phase-1)),6=>Some(4),7=>Some(5),_=>None,
    };}
    match phase {
        1..=8=>Some(usize::from(phase-1)),9=>Some(8),10=>Some(10),11=>Some(11),12=>Some(12),
        13=>Some(13),14=>Some(14),15=>Some(15),16=>Some(16),20=>Some(17),22=>Some(18),
        23=>Some(19),24=>Some(20),25=>Some(21),26=>Some(22),27=>Some(23),28=>Some(24),29=>Some(25),_=>None,
    }
}
fn transition(raw:Report,old:Report,phase:ProducerPhase,operation:ProducerOperation)->bool {
    let call_limit=u32::from(operation.steps())+operation.slots() as u32;
    let code=match phase {
        ProducerPhase::Inspect(n) if (1..=operation.steps()).contains(&n)=>u32::from(n),
        ProducerPhase::Release(n) if usize::from(n)<operation.slots()=>RELEASE+u32::from(n),_=>return false,
    };
    if old.version!=1 || old.reserved!=operation.code() || old.unknown!=0 || old.returned!=old.calls || old.calls>=call_limit
        || old.states.iter().any(|s|!matches!(*s,0|2|4)) || old.states[operation.slots()..].iter().any(|s|*s!=0)
        || raw.version!=1 || raw.phase!=code || raw.calls!=old.calls+1 || raw.calls>call_limit
        || raw.reserved!=operation.code() || raw.matched>1 || raw.failed>1 || raw.unknown>1
        || raw.failed<old.failed || raw.matched<old.matched
        || raw.states.iter().any(|s|*s>5) { return false; }
    if raw.unknown==1 {
        if raw.failed!=1 || raw.returned!=old.returned || raw.matched!=old.matched {return false;}
    } else if raw.returned!=raw.calls || raw.states.iter().any(|s|matches!(*s,1|3|5)) {return false;}
    match phase {
        ProducerPhase::Inspect(n)=>{
            if old.failed!=0 || old.matched!=0 || old.phase+1!=u32::from(n) {return false;}
            let slot=phase_slot(n,operation);
            for (index,(&before,&after)) in old.states.iter().zip(&raw.states).enumerate() {
                if Some(index)==slot || operation==ProducerOperation::DetachedSignature && n==9 && index==9 {
                    if before!=0 || !matches!(after,2|4|5) || raw.unknown==0 && after==5 {return false;}
                    let error_slot=operation==ProducerOperation::DetachedSignature && ((n==9 && index==9)||n==22||n==29);
                    if raw.unknown==0 && ((error_slot && after==2)||(!error_slot && after==4)) && raw.failed!=1 {return false;}
                } else if before!=after {return false;}
            }
            raw.matched==u32::from(n==operation.steps() && raw.failed==0 && raw.unknown==0)
        },
        ProducerPhase::Release(n)=>{
            raw.matched==old.matched && (raw.unknown==1 || raw.failed==old.failed)
                && old.states[usize::from(n)]==2
                && old.states.iter().zip(&raw.states).enumerate().all(|(i,(before,after))|
                    if i==usize::from(n) {*after==if raw.unknown==1{5}else{4}} else {before==after})
        },_=>false,
    }
}

// Private bounded DATA substitution, like the existing identity book. Only the
// real Calls implementation is reachable through the public adapter methods.
trait Native {
    fn source(&mut self,out:&mut SourceSigner)->c_int;
    fn allocate(&mut self,input:VerificationInput<'_>,operation:ProducerOperation)->*mut c_void;
    fn step(&mut self,cell:*mut c_void,phase:u32,out:&mut Report)->c_int;
    fn release(&mut self,cell:*mut c_void,slot:u32,out:&mut Report)->c_int;
    fn retire(&mut self,cell:*mut c_void)->c_int;
}
struct Calls;
impl Native for Calls {
    fn source(&mut self,out:&mut SourceSigner)->c_int {unsafe{mrk_install_producer_source(out)}}
    fn allocate(&mut self,input:VerificationInput<'_>,operation:ProducerOperation)->*mut c_void {
        // Private input is constructed only from live slices/BorrowedFd by the
        // public wrappers. Native copies bytes, never owns/dupes/closes the FDs.
        match (input,operation) {
            (VerificationInput::Signature{descriptor,signature},ProducerOperation::DetachedSignature)=>
                unsafe{mrk_install_producer_new(descriptor.as_ptr(),descriptor.len(),signature.as_ptr(),signature.len())},
            (VerificationInput::Current{outer,code,outer_path},ProducerOperation::CurrentProduct(_))=>
                unsafe{mrk_install_producer_code_new(operation.code(),outer,code,outer_path.as_ptr(),outer_path.len())},
            _=>std::ptr::null_mut(),
        }
    }
    fn step(&mut self,cell:*mut c_void,phase:u32,out:&mut Report)->c_int {unsafe{mrk_install_producer_step(cell,phase,out)}}
    fn release(&mut self,cell:*mut c_void,slot:u32,out:&mut Report)->c_int {unsafe{mrk_install_producer_release(cell,slot,out)}}
    fn retire(&mut self,cell:*mut c_void)->c_int {unsafe{mrk_install_producer_retire(cell)}}
}

/// Inert construction, one original operation, explicit consuming close only.
/// No Drop cleanup, background work, private keys or independent deadline.
pub struct ProducerVerifier {
    operation:ProducerOperation,pointer:Option<NonNull<c_void>>,report:Report,phase:Option<ProducerPhase>,cell:CellCustody,
    entered:bool,in_call:bool,in_gate:bool,unknown:bool,closed:bool,first:Option<Instant>,
}
// SAFETY: exclusively borrowed calls never dereference a native pointer in Rust.
// Every native operation checks the original process/pthread/UID/GID. Moving the
// wrapper cannot transfer permission to enter on a foreign thread; refusal
// retains uncertainty and there is no Drop operation on that thread.
unsafe impl Send for ProducerVerifier {}
impl Default for ProducerVerifier {fn default()->Self{Self::new()}}
impl ProducerVerifier {
    pub fn new()->Self {Self::new_for(ProducerOperation::DetachedSignature)}
    fn new_for(operation:ProducerOperation)->Self {Self{operation,pointer:None,
        report:Report{version:1,reserved:operation.code(),..Report::default()},phase:None,
        cell:CellCustody::Absent,entered:false,in_call:false,in_gate:false,unknown:false,closed:false,first:None}}
    /// Bound supplied buffers/copies plus wrapper/report stack, not Security's
    /// private framework heap. Caller retains its EXISTING aggregate heap floor.
    pub fn project_owned_upper_bound()->Option<usize> {
        CELL_LIMIT.checked_add(6*CERTIFICATE_LIMIT)?.checked_add(CERTIFICATE_LIMIT)?
            .checked_add(DESCRIPTOR_LIMIT+DOMAIN.len())?.checked_add(512)?.checked_add(CODE_STACK_LIMIT)?
            .checked_add(std::mem::size_of::<Self>()+2*std::mem::size_of::<Report>()+std::mem::size_of::<SourceSigner>())
    }
    pub fn custody(&self)->ProducerCustody {ProducerCustody{operation:self.operation,phase:self.phase,cell:self.cell,references:self.report.states,
        entered:self.entered,in_call:self.in_call,gate_entered:self.in_gate,
        signature_matched:self.operation==ProducerOperation::DetachedSignature&&self.report.matched==1,
        purpose_matched:match self.operation{ProducerOperation::CurrentProduct(role) if self.report.matched==1=>Some(role),_=>None},
        failed:self.report.failed==1||self.first.is_some(),unknown:self.unknown||self.in_call||self.in_gate||self.report.unknown==1,
        calls:self.report.calls,returned:self.report.returned,first_failure:self.first}}
    fn note(&mut self,at:Instant){self.first=Some(self.first.map_or(at,|first|first.min(at)));}
    fn poison(&mut self,at:Instant)->VerificationResult{self.note(at);self.unknown=true;VerificationResult::Unknown}
    fn point(&mut self,phase:ProducerPhase,at:Option<Instant>,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->Decision {
        self.phase=Some(phase);let custody=self.custody();self.in_gate=true;
        let decision=gate(match at{Some(at)=>ProducerCheckpoint::Returned{phase,at,custody},
            None=>ProducerCheckpoint::Before{phase,custody}});self.in_gate=false;decision
    }
    fn work_point(&mut self,phase:ProducerPhase,at:Option<Instant>,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->bool {
        match self.point(phase,at,gate) {
            Decision::Proceed=>true,
            Decision::Stop|Decision::Defer=>{self.note(at.unwrap_or_else(Instant::now));false},
            Decision::Unknown=>{self.poison(at.unwrap_or_else(Instant::now));false},
        }
    }
    fn stopped(&self)->VerificationResult{if self.unknown{VerificationResult::Unknown}else{VerificationResult::Refused}}
    pub fn verify_and_close(&mut self,descriptor:&[u8],signature:&[u8],gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->SignatureResult {
        self.verify_with(descriptor,signature,gate,&mut Calls)
    }
    fn verify_with(&mut self,descriptor:&[u8],signature:&[u8],gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,native:&mut impl Native)->SignatureResult {
        match self.verify_input(VerificationInput::Signature{descriptor,signature},gate,native) {
            VerificationResult::Matched if self.operation==ProducerOperation::DetachedSignature=>SignatureResult::SignatureVerified,
            VerificationResult::Unavailable=>SignatureResult::Unavailable,
            VerificationResult::Refused=>SignatureResult::Refused,_=>SignatureResult::Unknown,
        }
    }
    fn verify_input(&mut self,input:VerificationInput<'_>,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,native:&mut impl Native)->VerificationResult {
        if self.entered||self.closed||self.pointer.is_some()||self.in_call||self.in_gate||self.unknown {return self.poison(Instant::now());}
        self.entered=true;
        let observed=self.inspect(input,gate,native);
        if !self.close_with(gate,native) {return VerificationResult::Unknown;}
        match observed {
            VerificationResult::Matched if self.first.is_none() && self.report.failed==0
                && self.report.matched==1=>VerificationResult::Matched,
            VerificationResult::Unavailable=>VerificationResult::Unavailable,
            VerificationResult::Unknown=>VerificationResult::Unknown,_=>VerificationResult::Refused,
        }
    }
    // A positive result from this PRIVATE method is provisional until close.
    fn inspect(&mut self,input:VerificationInput<'_>,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,native:&mut impl Native)->VerificationResult {
        if !input.valid_for(self.operation) {
            self.note(Instant::now());return VerificationResult::Refused;
        }
        let phase=ProducerPhase::SourceSelection;
        if !self.work_point(phase,None,gate){return self.stopped();}
        let mut selected=SourceSigner::default();self.in_call=true;
        let returned=native.source(&mut selected);let at=Instant::now();self.in_call=false;
        let signer=match returned {
            0 if selected==SourceSigner::default()=>{self.note(at);None},
            1=>match source_data(selected){Some(value)=>Some(value),None=>{self.poison(at);None}},
            _=>{self.poison(at);None},
        };
        if !self.work_point(phase,Some(at),gate)||self.unknown{return self.stopped();}
        let Some(signer)=signer else{return VerificationResult::Unavailable;};
        if let VerificationInput::Signature{signature,..}=input {
            if signature.len()!=signer.rsa_bits_data() as usize/8 {self.note(at);return VerificationResult::Refused;}
        }
        let phase=ProducerPhase::AllocateCell;
        if !self.work_point(phase,None,gate){return self.stopped();}
        self.cell=CellCustody::Entering;self.in_call=true;
        let pointer=native.allocate(input,self.operation);let at=Instant::now();self.in_call=false;
        self.pointer=NonNull::new(pointer);self.cell=if self.pointer.is_some(){CellCustody::Owned}else{CellCustody::Absent};
        if self.pointer.is_none(){self.note(at);}
        if !self.work_point(phase,Some(at),gate)||self.pointer.is_none(){return self.stopped();}
        for number in 1..=self.operation.steps() {
            let phase=ProducerPhase::Inspect(number);
            if !self.work_point(phase,None,gate){return self.stopped();}
            let Some(pointer)=self.pointer else{return self.poison(Instant::now());};
            let mut raw=Report::default();self.in_call=true;
            let returned=native.step(pointer.as_ptr(),u32::from(number),&mut raw);let at=Instant::now();self.in_call=false;
            if returned!=1||!transition(raw,self.report,phase,self.operation){return self.poison(at);}
            self.report=raw;if raw.failed==1{self.note(at);}if raw.unknown==1{self.unknown=true;}
            let proceed=self.work_point(phase,Some(at),gate);
            if !proceed||raw.failed==1||self.unknown{return self.stopped();}
        }
        if self.report.matched==1{VerificationResult::Matched}else{self.poison(Instant::now())}
    }
    /// No waiting, retry, Drop or replacement owner. Cleanup is admitted using
    /// the SAME enclosing absolute endpoint; its late/unknown result stays final.
    pub fn close(&mut self,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->bool {self.close_with(gate,&mut Calls)}
    fn close_with(&mut self,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,native:&mut impl Native)->bool {
        if self.unknown||self.in_call||self.in_gate||self.report.unknown==1{return false;}
        if self.closed{return self.settled();}
        if self.pointer.is_none(){self.closed=true;return self.settled();}
        for number in (0..self.operation.slots()).rev() {
            if self.report.states[number]!=2 {continue;}
            let phase=ProducerPhase::Release(number as u8);
            if self.point(phase,None,gate)!=Decision::Proceed{self.poison(Instant::now());return false;}
            let Some(pointer)=self.pointer else{self.poison(Instant::now());return false;};
            let mut raw=Report::default();self.in_call=true;
            let returned=native.release(pointer.as_ptr(),number as u32,&mut raw);let at=Instant::now();self.in_call=false;
            if returned!=1||!transition(raw,self.report,phase,self.operation){self.poison(at);return false;}
            self.report=raw;if raw.failed==1{self.note(at);}if raw.unknown==1{self.unknown=true;self.note(at);}
            if self.point(phase,Some(at),gate)!=Decision::Proceed||self.unknown{self.poison(at);return false;}
        }
        let phase=ProducerPhase::RetireCell;
        if self.point(phase,None,gate)!=Decision::Proceed{self.poison(Instant::now());return false;}
        let Some(pointer)=self.pointer else{self.poison(Instant::now());return false;};self.in_call=true;
        let returned=native.retire(pointer.as_ptr());let at=Instant::now();self.in_call=false;
        if returned==1{self.pointer=None;self.cell=CellCustody::Consumed;}else{self.cell=CellCustody::Unknown;self.poison(at);}
        if self.point(phase,Some(at),gate)!=Decision::Proceed||self.unknown{self.poison(at);return false;}
        self.closed=true;self.settled()
    }
    pub fn settled(&self)->bool {self.closed&&!self.unknown&&!self.in_call&&!self.in_gate&&self.pointer.is_none()
        && matches!(self.cell,CellCustody::Absent|CellCustody::Consumed)&&self.report.unknown==0
        && self.report.calls==self.report.returned&&self.report.states.iter().all(|s|matches!(*s,0|4))}
}

/// Root-capable STATIC App-purpose checks using the parent's borrowed original
/// directories. Parent owes its complete nofollow chain/content checks at every
/// checkpoint and BOTH App results plus descriptor/package authority before GO.
/// Strict nested validity does not attest a uniform signer for child components.
pub struct CurrentProductVerifier {inner:ProducerVerifier}
impl CurrentProductVerifier {
    pub fn new(role:CurrentProductRole)->Self {Self{inner:ProducerVerifier::new_for(ProducerOperation::CurrentProduct(role))}}
    pub fn project_owned_upper_bound()->Option<usize> {ProducerVerifier::project_owned_upper_bound()}
    pub fn custody(&self)->ProducerCustody {self.inner.custody()}
    pub fn verify_and_close(&mut self,outer:BorrowedFd<'_>,code:BorrowedFd<'_>,outer_path:&Path,
        gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->CurrentProductResult {
        // Both BorrowedFd lifetimes extend through all native work/close here.
        // Later close() only consumes CF originals; it never looks up these FDs.
        self.verify_with(VerificationInput::Current{outer:outer.as_raw_fd(),code:code.as_raw_fd(),
            outer_path:outer_path.as_os_str().as_bytes()},gate,&mut Calls)
    }
    fn verify_with(&mut self,input:VerificationInput<'_>,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,
        native:&mut impl Native)->CurrentProductResult {
        match self.inner.verify_input(input,gate,native) {
            VerificationResult::Matched if matches!(self.inner.operation,ProducerOperation::CurrentProduct(_))=>CurrentProductResult::PurposeVerified,
            VerificationResult::Unavailable=>CurrentProductResult::Unavailable,
            VerificationResult::Refused=>CurrentProductResult::Refused,_=>CurrentProductResult::Unknown,
        }
    }
    pub fn close(&mut self,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->bool {self.inner.close(gate)}
    pub fn settled(&self)->bool {self.inner.settled()}
}

#[cfg(test)]
mod tests {
    use super::*;
    // Bounded synthetic return DATA only; never a Security/purpose certificate
    // or a native passing receipt. The private trait is not a production API.
    struct DataCalls {report:Report,unavailable:bool,failed_at:Option<u8>,bad_at:Option<u8>,
        unknown_at:Option<u8>,release_unknown:bool,allocated:bool,releases:Vec<u8>,retired:bool}
    impl DataCalls {fn new()->Self{Self{report:Report{version:1,..Report::default()},unavailable:false,
        failed_at:None,bad_at:None,unknown_at:None,release_unknown:false,allocated:false,releases:Vec::new(),retired:false}}}
    impl Native for DataCalls {
        fn source(&mut self,out:&mut SourceSigner)->c_int{
            if self.unavailable{return 0;}
            *out=SourceSigner{version:1,rsa_bits:2048,team:*b"TEAM000001",leaf_sha1:[1;20],leaf_sha256:[2;32],public_key_pkcs1_sha256:[3;32]};1
        }
        fn allocate(&mut self,input:VerificationInput<'_>,operation:ProducerOperation)->*mut c_void{
            assert!(input.valid_for(operation));self.report.reserved=operation.code();
            self.allocated=true;NonNull::<u8>::dangling().as_ptr().cast()
        }
        fn step(&mut self,_:*mut c_void,n:u32,out:&mut Report)->c_int{
            self.report.phase=n;self.report.calls+=1;
            // Independently literal fixture layout, not transition() as oracle.
            let code=matches!(self.report.reserved,1|2);
            let slot=if code {match n{1..=4=>Some((n-1)as usize),6=>Some(4),7=>Some(5),_=>None}}
                else {match n{1..=8=>Some((n-1)as usize),9=>Some(8),10..=16=>Some(n as usize),
                    20=>Some(17),22=>Some(18),23..=29=>Some((n-4)as usize),_=>None}};
            if let Some(slot)=slot{assert_eq!(self.report.states[slot],0);self.report.states[slot]=if !code&&matches!(n,22|29){4}else{2};}
            if !code&&n==9{self.report.states[9]=4;}
            if self.failed_at==Some(n as u8){self.report.failed=1;if !code&&matches!(n,22|29){self.report.states[slot.unwrap()]=2;}}
            if self.unknown_at==Some(n as u8){self.report.failed=1;self.report.unknown=1;}
            else{self.report.returned+=1;if n==(if code{8}else{29})&&self.report.failed==0{self.report.matched=1;}}
            *out=self.report;if self.bad_at==Some(n as u8){out.phase+=1;}1
        }
        fn release(&mut self,_:*mut c_void,slot:u32,out:&mut Report)->c_int{
            assert_eq!(self.report.states[slot as usize],2);self.releases.push(slot as u8);
            self.report.phase=RELEASE+slot;self.report.calls+=1;
            if self.release_unknown{self.report.states[slot as usize]=5;self.report.failed=1;self.report.unknown=1;}
            else{self.report.states[slot as usize]=4;self.report.returned+=1;}
            *out=self.report;1
        }
        fn retire(&mut self,_:*mut c_void)->c_int{assert!(self.report.states.iter().all(|s|matches!(*s,0|4)));self.retired=true;1}
    }
    #[test]
    fn report_decoder_binds_slots_error_outputs_and_consuming_returns() {
        let old=Report{version:1,..Report::default()};let mut raw=Report{version:1,phase:1,calls:1,returned:1,..Report::default()};raw.states[0]=2;
        assert!(transition(raw,old,ProducerPhase::Inspect(1),ProducerOperation::DetachedSignature));
        for bad in [Report{matched:1,..raw},Report{phase:2,..raw},Report{returned:0,..raw},
            Report{calls:2,..raw},Report{states:[0;SLOTS],..raw},Report{reserved:1,..raw}] {
            assert!(!transition(bad,old,ProducerPhase::Inspect(1),ProducerOperation::DetachedSignature));
        }
        let mut native=DataCalls::new();let mut before=old;
        for n in 1..=29 {
            native.step(std::ptr::null_mut(),n,&mut raw);assert!(transition(raw,before,ProducerPhase::Inspect(n as u8),ProducerOperation::DetachedSignature));
            if n==9{let mut lost=raw;lost.states[9]=0;assert!(!transition(lost,before,ProducerPhase::Inspect(9),ProducerOperation::DetachedSignature));}
            if matches!(n,22|29){let mut error=raw;error.states[if n==22{18}else{25}]=2;assert!(!transition(error,before,ProducerPhase::Inspect(n as u8),ProducerOperation::DetachedSignature));}
            before=raw;
        }
        assert_eq!(raw.matched,1);
        native.release(std::ptr::null_mut(),24,&mut raw);assert!(transition(raw,before,ProducerPhase::Release(24),ProducerOperation::DetachedSignature));
        assert!(!transition(raw,raw,ProducerPhase::Release(24),ProducerOperation::DetachedSignature));
        for (mode,role) in [(1,CurrentProductRole::EntryApp),(2,CurrentProductRole::PayloadApp)] {
            let operation=ProducerOperation::CurrentProduct(role);
            let mut native=DataCalls::new();native.report.reserved=mode;
            let mut old=Report{version:1,reserved:mode,..Report::default()};
            for n in 1..=8 {
                native.step(std::ptr::null_mut(),n,&mut raw);
                assert!(transition(raw,old,ProducerPhase::Inspect(n as u8),operation));
                for wrong in [0,3-mode] {let mut bad=raw;bad.reserved=wrong;
                    assert!(!transition(bad,old,ProducerPhase::Inspect(n as u8),operation));}
                let mut extra=raw;extra.states[6]=2;
                assert!(!transition(extra,old,ProducerPhase::Inspect(n as u8),operation));
                if n<8{let mut early=raw;early.matched=1;
                    assert!(!transition(early,old,ProducerPhase::Inspect(n as u8),operation));}
                old=raw;
            }
            assert_eq!(raw.matched,1);assert_eq!(&raw.states[..6],&[2;6]);
            assert!(!transition(raw,old,ProducerPhase::Inspect(9),operation));
            native.release(std::ptr::null_mut(),5,&mut raw);
            assert!(transition(raw,old,ProducerPhase::Release(5),operation));
            assert!(!transition(raw,old,ProducerPhase::Release(6),operation));
        }
        assert_eq!(std::mem::size_of::<Report>(),136);assert_eq!(std::mem::size_of::<SourceSigner>(),104);
        assert!(ProducerVerifier::project_owned_upper_bound().unwrap()<=320*1024);
    }
    #[test]
    fn signature_result_requires_same_owner_finality_and_late_gate_refuses() {
        let mut native=DataCalls::new();let mut verifier=ProducerVerifier::new();let mut seen=Vec::new();
        let result=verifier.verify_with(b"{}",&[0;256],&mut |point|{seen.push(point);Decision::Proceed},&mut native);
        assert_eq!(result,SignatureResult::SignatureVerified);assert!(verifier.settled()&&native.retired);
        assert_eq!(native.releases.len(),23);assert!(native.releases.windows(2).all(|w|w[0]>w[1]));
        assert!(matches!(seen.last(),Some(ProducerCheckpoint::Returned{phase:ProducerPhase::RetireCell,..})));
        assert_eq!(verifier.verify_with(b"{}",&[0;256],&mut |_|Decision::Proceed,&mut native),SignatureResult::Unknown);
        let mut native=DataCalls::new();let mut verifier=ProducerVerifier::new();
        let result=verifier.verify_with(b"{}",&[0;256],&mut |point|match point {
            ProducerCheckpoint::Returned{phase:ProducerPhase::RetireCell,..}=>Decision::Stop,_=>Decision::Proceed},&mut native);
        assert_eq!(result,SignatureResult::Unknown);assert!(native.retired);assert!(!verifier.settled());
        let mut native=DataCalls::new();native.failed_at=Some(22);let mut verifier=ProducerVerifier::new();let mut failure_imported=false;
        let result=verifier.verify_with(b"{}",&[0;256],&mut |point|{if let ProducerCheckpoint::Returned{phase:ProducerPhase::Inspect(22),custody,..}=point {
            failure_imported=custody.failed&&custody.first_failure.is_some()&&custody.references[18]==2;}Decision::Proceed},&mut native);
        assert_eq!(result,SignatureResult::Refused);assert!(failure_imported&&verifier.settled()&&native.retired);
        assert_eq!(native.releases.first(),Some(&18));
        let mut native=DataCalls::new();let mut verifier=ProducerVerifier::new();
        assert_eq!(verifier.verify_with(b"{}",&[0;256],&mut |_|Decision::Defer,&mut native),SignatureResult::Refused);
        assert!(verifier.settled()&&!native.allocated);
        let mut native=DataCalls::new();native.unavailable=true;let mut verifier=ProducerVerifier::new();
        assert_eq!(verifier.verify_with(b"{}",&[0;256],&mut |_|Decision::Proceed,&mut native),SignatureResult::Unavailable);
        assert!(verifier.settled()&&!native.allocated);
        // Private inert raw scalars, never fabricated BorrowedFd or filesystem IO.
        let input=VerificationInput::Current{outer:11,code:12,outer_path:b"/private/mrk-purpose/Entry.app"};
        for role in [CurrentProductRole::EntryApp,CurrentProductRole::PayloadApp] {
            let mut native=DataCalls::new();let mut verifier=CurrentProductVerifier::new(role);
            assert_eq!(verifier.verify_with(input,&mut |_|Decision::Proceed,&mut native),CurrentProductResult::PurposeVerified);
            assert!(verifier.settled()&&native.retired);assert_eq!(native.releases,vec![5,4,3,2,1,0]);
            assert_eq!(verifier.custody().operation,ProducerOperation::CurrentProduct(role));
            assert!(!verifier.custody().signature_matched);assert_eq!(verifier.custody().purpose_matched,Some(role));
            assert_eq!(verifier.verify_with(input,&mut |_|Decision::Proceed,&mut native),CurrentProductResult::Unknown);
            let mut native=DataCalls::new();native.failed_at=Some(5);let mut verifier=CurrentProductVerifier::new(role);
            let mut observed=false;
            assert_eq!(verifier.verify_with(input,&mut |point|{if let ProducerCheckpoint::Returned{phase:ProducerPhase::Inspect(5),custody,..}=point{
                observed=custody.failed&&custody.first_failure.is_some()&&custody.purpose_matched.is_none();
            }Decision::Proceed},&mut native),CurrentProductResult::Refused);
            assert!(observed&&verifier.settled()&&native.retired);assert_eq!(native.releases,vec![3,2,1,0]);
            let mut native=DataCalls::new();native.unavailable=true;let mut verifier=CurrentProductVerifier::new(role);
            assert_eq!(verifier.verify_with(input,&mut |_|Decision::Proceed,&mut native),CurrentProductResult::Unavailable);
            assert!(verifier.settled()&&!native.allocated);
            let mut native=DataCalls::new();let mut verifier=CurrentProductVerifier::new(role);
            assert_eq!(verifier.verify_with(input,&mut |point|match point{
                ProducerCheckpoint::Returned{phase:ProducerPhase::RetireCell,..}=>Decision::Stop,_=>Decision::Proceed
            },&mut native),CurrentProductResult::Unknown);
            assert!(native.retired&&!verifier.settled());
        }
        for path in [b"relative".as_slice(),b"/",b"/a//b",b"/a/../b",b"/a/./b",b"/a/",b"/a\0b"] {
            let mut native=DataCalls::new();let mut verifier=CurrentProductVerifier::new(CurrentProductRole::EntryApp);
            assert_eq!(verifier.verify_with(VerificationInput::Current{outer:11,code:12,outer_path:path},
                &mut |_|Decision::Proceed,&mut native),CurrentProductResult::Refused);
            assert!(verifier.settled()&&!native.allocated);
        }
        assert!(!VerificationInput::Current{outer:-1,code:12,outer_path:b"/fixed.app"}.valid_for(ProducerOperation::CurrentProduct(CurrentProductRole::EntryApp)));
        let mut overlong=vec![b'a';PATH_LIMIT];overlong[0]=b'/';
        assert!(!canonical_outer_path(&overlong,CurrentProductRole::PayloadApp));
        assert!(!input.valid_for(ProducerOperation::DetachedSignature));
        assert!(!VerificationInput::Signature{descriptor:b"{}",signature:&[0;256]}.valid_for(ProducerOperation::CurrentProduct(CurrentProductRole::EntryApp)));
    }
    #[test]
    fn unknown_native_or_gate_custody_never_releases_or_publishes_success() {
        for malformed in [false,true] {
            let mut native=DataCalls::new();if malformed{native.bad_at=Some(9);}else{native.unknown_at=Some(9);}
            let mut verifier=ProducerVerifier::new();
            assert_eq!(verifier.verify_with(b"{}",&[0;256],&mut |_|Decision::Proceed,&mut native),SignatureResult::Unknown);
            assert!(!verifier.settled()&&!native.retired&&native.releases.is_empty());
            assert!(!verifier.close_with(&mut |_|Decision::Proceed,&mut native));
        }
        let mut native=DataCalls::new();native.release_unknown=true;let mut verifier=ProducerVerifier::new();
        assert_eq!(verifier.verify_with(b"{}",&[0;256],&mut |_|Decision::Proceed,&mut native),SignatureResult::Unknown);
        assert_eq!(native.releases.len(),1);assert!(!native.retired&&!verifier.settled());
        let mut native=DataCalls::new();let mut verifier=ProducerVerifier::new();
        let panic=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
            verifier.verify_with(b"{}",&[0;256],&mut |point|match point {
                ProducerCheckpoint::Returned{phase:ProducerPhase::Inspect(1),..}=>panic!("local gate DATA"),_=>Decision::Proceed},&mut native)
        }));
        assert!(panic.is_err()&&verifier.custody().gate_entered&&verifier.custody().unknown);
        assert!(!verifier.close_with(&mut |_|Decision::Proceed,&mut native)&&native.releases.is_empty()&&!native.retired);
        let input=VerificationInput::Current{outer:11,code:12,outer_path:b"/private/mrk-purpose/Entry.app"};
        for role in [CurrentProductRole::EntryApp,CurrentProductRole::PayloadApp] {
            for malformed in [false,true] {
                let mut native=DataCalls::new();if malformed{native.bad_at=Some(7);}else{native.unknown_at=Some(7);}
                let mut verifier=CurrentProductVerifier::new(role);
                assert_eq!(verifier.verify_with(input,&mut |_|Decision::Proceed,&mut native),CurrentProductResult::Unknown);
                assert!(!verifier.settled()&&!native.retired&&native.releases.is_empty());
                assert!(!verifier.inner.close_with(&mut |_|Decision::Proceed,&mut native));
            }
            let mut native=DataCalls::new();native.release_unknown=true;let mut verifier=CurrentProductVerifier::new(role);
            assert_eq!(verifier.verify_with(input,&mut |_|Decision::Proceed,&mut native),CurrentProductResult::Unknown);
            assert_eq!(native.releases.len(),1);assert!(!native.retired&&!verifier.settled());
            let mut native=DataCalls::new();let mut verifier=CurrentProductVerifier::new(role);
            let panic=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
                verifier.verify_with(input,&mut |point|match point{
                    ProducerCheckpoint::Returned{phase:ProducerPhase::Inspect(2),..}=>panic!("local purpose gate DATA"),_=>Decision::Proceed
                },&mut native)
            }));
            assert!(panic.is_err()&&verifier.custody().gate_entered&&verifier.custody().unknown);
            assert!(!verifier.inner.close_with(&mut |_|Decision::Proceed,&mut native)&&native.releases.is_empty()&&!native.retired);
        }
    }
}
