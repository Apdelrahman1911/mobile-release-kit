//! Fixed producer signature/purpose originals under the caller's existing W/H/F.
//! SignatureVerified means pinned-chain/signature correspondence AND settled
//! native references, NOT Developer-ID Application purpose or release authority.
//! The caller still owes strict current-product purpose/leaf checks, compiled
//! release correspondence, original descriptor/package POST and ordinary GO.
//! An explicitly feature-gated nonshipping signer shares this exact custody;
//! SignatureCreated is only provisional public signature DATA, never authority.
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
const RECOVERY_CODE_STEPS:u8=13;
const RECOVERY_CODE_SLOTS:usize=9;
// Same 320KiB supplied-resource ceiling; includes bounded C path/stat stack.
const CODE_STACK_LIMIT:usize=8192;
const DOMAIN:&[u8]=b"MobileReleaseKit-package-producer-v2\0";
const REMOVE_DOMAIN:&[u8]=b"MobileReleaseKit-remove-producer-v1\0";
const REMOVE_DESCRIPTOR_LIMIT:usize=16384;
const REMOVE_FILENAME:&[u8]=b"/mrk-macos-remove";
const _:()=assert!(REMOVE_DOMAIN.len()<=DOMAIN.len());
#[cfg(any(test,feature="package-producer-signing"))]
const SIGN_STEPS:u8=12;
#[cfg(any(test,feature="package-producer-signing"))]
const SIGN_SLOTS:usize=14;

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
pub enum ProducerOperation {
    DetachedSignature,CurrentProduct(CurrentProductRole),
    RemoveDetachedSignature,RemoveProgram,RemoveRecoveryProgram,
    #[cfg(any(test,feature="package-producer-signing"))]
    PackageSigning,
    #[cfg(any(test,feature="package-producer-signing"))]
    RemoveSigning,
}
impl ProducerOperation {
    fn code(self)->u32 {match self {
        Self::DetachedSignature=>0,Self::CurrentProduct(CurrentProductRole::EntryApp)=>1,
        Self::CurrentProduct(CurrentProductRole::PayloadApp)=>2,
        Self::RemoveDetachedSignature=>4,Self::RemoveProgram=>5,Self::RemoveRecoveryProgram=>7,
        #[cfg(any(test,feature="package-producer-signing"))]
        Self::PackageSigning=>3,
        #[cfg(any(test,feature="package-producer-signing"))]
        Self::RemoveSigning=>6,
    }}
    fn detached(self)->bool{matches!(self,Self::DetachedSignature|Self::RemoveDetachedSignature)}
    #[cfg(any(test,feature="package-producer-signing"))]
    fn signing(self)->bool{matches!(self,Self::PackageSigning|Self::RemoveSigning)}
    fn steps(self)->u8 {match self {
        Self::DetachedSignature|Self::RemoveDetachedSignature=>STEPS,Self::CurrentProduct(_)|Self::RemoveProgram=>CODE_STEPS,
        Self::RemoveRecoveryProgram=>RECOVERY_CODE_STEPS,
        #[cfg(any(test,feature="package-producer-signing"))]
        Self::PackageSigning|Self::RemoveSigning=>SIGN_STEPS,
    }}
    fn slots(self)->usize {match self {
        Self::DetachedSignature|Self::RemoveDetachedSignature=>SLOTS,Self::CurrentProduct(_)|Self::RemoveProgram=>CODE_SLOTS,
        Self::RemoveRecoveryProgram=>RECOVERY_CODE_SLOTS,
        #[cfg(any(test,feature="package-producer-signing"))]
        Self::PackageSigning|Self::RemoveSigning=>SIGN_SLOTS,
    }}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum VerificationResult { Matched,Unavailable,Refused,Unknown }
#[derive(Clone,Copy)]
enum VerificationInput<'a> {
    Signature {descriptor:&'a [u8],signature:&'a [u8]},
    Current {outer:c_int,code:c_int,outer_path:&'a [u8]},
    RemoveProgram {directory:c_int,program:c_int,directory_path:&'a [u8]},
    RecoveryProgram {directory:c_int,program:c_int,directory_path:&'a [u8]},
    #[cfg(any(test,feature="package-producer-signing"))]
    Signing {descriptor:&'a [u8]},
}
fn canonical_outer_path(path:&[u8],role:CurrentProductRole)->bool {
    path.len()>1 && path.len()<PATH_LIMIT && path[0]==b'/' && !path.contains(&0)
        && path[1..].split(|b|*b==b'/').all(|part|!part.is_empty()&&part!=b"."&&part!=b"..")
        && path.len().checked_add(role.suffix().len()).and_then(|n|n.checked_add(role.executable().len()))
            .is_some_and(|n|n<PATH_LIMIT)
}
fn canonical_remove_directory(path:&[u8])->bool{
    path.len()>1&&path.len()<PATH_LIMIT&&path[0]==b'/'&&!path.contains(&0)
        &&path[1..].split(|b|*b==b'/').all(|p|!p.is_empty()&&p!=b"."&&p!=b"..")
        &&path.len().checked_add(REMOVE_FILENAME.len()).is_some_and(|n|n<PATH_LIMIT)
}
impl VerificationInput<'_> {
    fn valid_for(self,operation:ProducerOperation)->bool {match (self,operation) {
        (Self::Signature{descriptor,signature},ProducerOperation::DetachedSignature)=>
            !descriptor.is_empty()&&descriptor.len()<=DESCRIPTOR_LIMIT&&matches!(signature.len(),256|384|512),
        (Self::Signature{descriptor,signature},ProducerOperation::RemoveDetachedSignature)=>
            !descriptor.is_empty()&&descriptor.len()<=REMOVE_DESCRIPTOR_LIMIT&&matches!(signature.len(),256|384|512),
        (Self::RemoveProgram{directory,program,directory_path},ProducerOperation::RemoveProgram)=>
            directory>=0&&program>=0&&canonical_remove_directory(directory_path),
        (Self::RecoveryProgram{directory,program,directory_path},ProducerOperation::RemoveRecoveryProgram)=>
            directory>=0&&program>=0&&canonical_remove_directory(directory_path),
        (Self::Current{outer,code,outer_path},ProducerOperation::CurrentProduct(role))=>
            outer>=0&&code>=0&&canonical_outer_path(outer_path,role),
        #[cfg(any(test,feature="package-producer-signing"))]
        (Self::Signing{descriptor},ProducerOperation::PackageSigning)=>!descriptor.is_empty()&&descriptor.len()<=DESCRIPTOR_LIMIT,
        #[cfg(any(test,feature="package-producer-signing"))]
        (Self::Signing{descriptor},ProducerOperation::RemoveSigning)=>!descriptor.is_empty()&&descriptor.len()<=REMOVE_DESCRIPTOR_LIMIT,
        _=>false,
    }}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ProducerPhase {
    SourceSelection,AllocateCell,Inspect(u8),Release(u8),RetireCell,
    #[cfg(any(test,feature="package-producer-signing"))]
    CopySignature,
}
impl ProducerPhase {
    pub fn is_cleanup(self)->bool { matches!(self,Self::Release(_)|Self::RetireCell) }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct ProducerCustody {
    pub operation:ProducerOperation,pub phase:Option<ProducerPhase>,pub cell:CellCustody,pub references:[u32;SLOTS],
    pub entered:bool,pub in_call:bool,pub gate_entered:bool,
    /// Positive native fact only; it cannot replace settled()/purpose checks.
    pub signature_matched:bool,pub purpose_matched:Option<CurrentProductRole>,
    pub remove_signature_matched:bool,pub remove_program_matched:bool,pub failed:bool,pub unknown:bool,
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
    fn mrk_remove_producer_new(descriptor:*const u8,size:usize,signature:*const u8,signature_size:usize)->*mut c_void;
    fn mrk_remove_producer_code_new(directory:c_int,program:c_int,path:*const u8,size:usize)->*mut c_void;
    fn mrk_remove_recovery_code_new(directory:c_int,program:c_int,path:*const u8,size:usize)->*mut c_void;
    fn mrk_install_producer_step(cell:*mut c_void,phase:u32,out:*mut Report)->c_int;
    fn mrk_install_producer_release(cell:*mut c_void,slot:u32,out:*mut Report)->c_int;
    fn mrk_install_producer_retire(cell:*mut c_void)->c_int;
}
#[cfg(feature="package-producer-signing")]
unsafe extern "C" {
    fn mrk_install_producer_sign_new(descriptor:*const u8,size:usize)->*mut c_void;
    fn mrk_remove_producer_sign_new(descriptor:*const u8,size:usize)->*mut c_void;
    fn mrk_install_producer_sign_copy(cell:*mut c_void,out:*mut u8,capacity:usize,size:*mut usize)->c_int;
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
    #[cfg(any(test,feature="package-producer-signing"))]
    if operation.signing() {return match phase {
        1..=8=>Some(usize::from(phase-1)),9=>Some(8),10=>Some(10),11=>Some(11),12=>Some(13),_=>None,
    };}
    if operation==ProducerOperation::RemoveRecoveryProgram {return match phase {
        1..=4=>Some(usize::from(phase-1)),6=>Some(4),7=>Some(5),9=>Some(6),11=>Some(7),12=>Some(8),_=>None,
    };}
    if !operation.detached() {return match phase {
        1..=4=>Some(usize::from(phase-1)),6=>Some(4),7=>Some(5),_=>None,
    };}
    match phase {
        1..=8=>Some(usize::from(phase-1)),9=>Some(8),10=>Some(10),11=>Some(11),12=>Some(12),
        13=>Some(13),14=>Some(14),15=>Some(15),16=>Some(16),20=>Some(17),22=>Some(18),
        23=>Some(19),24=>Some(20),25=>Some(21),26=>Some(22),27=>Some(23),28=>Some(24),29=>Some(25),_=>None,
    }
}
fn second_slot(phase:u8,operation:ProducerOperation)->Option<usize> {
    #[cfg(any(test,feature="package-producer-signing"))]
    if operation.signing() {return match phase{9=>Some(9),11=>Some(12),_=>None};}
    (operation.detached() && phase==9).then_some(9)
}
fn error_slot(phase:u8,slot:usize,operation:ProducerOperation)->bool {
    #[cfg(any(test,feature="package-producer-signing"))]
    if operation.signing() {return matches!((phase,slot),(9,9)|(11,12)|(12,13));}
    operation.detached() && ((phase==9 && slot==9)||phase==22||phase==29)
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
                if Some(index)==slot || Some(index)==second_slot(n,operation) {
                    if before!=0 || !matches!(after,2|4|5) || raw.unknown==0 && after==5 {return false;}
                    let is_error=error_slot(n,index,operation);
                    if raw.unknown==0 && ((is_error && after==2)||(!is_error && after==4)) && raw.failed!=1 {return false;}
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
    #[cfg(any(test,feature="package-producer-signing"))]
    fn signature_copy(&mut self,cell:*mut c_void,output:&mut [u8;512],size:&mut usize)->c_int;
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
            (VerificationInput::Signature{descriptor,signature},ProducerOperation::RemoveDetachedSignature)=>
                unsafe{mrk_remove_producer_new(descriptor.as_ptr(),descriptor.len(),signature.as_ptr(),signature.len())},
            (VerificationInput::RemoveProgram{directory,program,directory_path},ProducerOperation::RemoveProgram)=>
                unsafe{mrk_remove_producer_code_new(directory,program,directory_path.as_ptr(),directory_path.len())},
            (VerificationInput::RecoveryProgram{directory,program,directory_path},ProducerOperation::RemoveRecoveryProgram)=>
                unsafe{mrk_remove_recovery_code_new(directory,program,directory_path.as_ptr(),directory_path.len())},
            (VerificationInput::Current{outer,code,outer_path},ProducerOperation::CurrentProduct(_))=>
                unsafe{mrk_install_producer_code_new(operation.code(),outer,code,outer_path.as_ptr(),outer_path.len())},
            #[cfg(feature="package-producer-signing")]
            (VerificationInput::Signing{descriptor},ProducerOperation::PackageSigning)=>
                unsafe{mrk_install_producer_sign_new(descriptor.as_ptr(),descriptor.len())},
            #[cfg(feature="package-producer-signing")]
            (VerificationInput::Signing{descriptor},ProducerOperation::RemoveSigning)=>
                unsafe{mrk_remove_producer_sign_new(descriptor.as_ptr(),descriptor.len())},
            _=>std::ptr::null_mut(),
        }
    }
    fn step(&mut self,cell:*mut c_void,phase:u32,out:&mut Report)->c_int {unsafe{mrk_install_producer_step(cell,phase,out)}}
    fn release(&mut self,cell:*mut c_void,slot:u32,out:&mut Report)->c_int {unsafe{mrk_install_producer_release(cell,slot,out)}}
    fn retire(&mut self,cell:*mut c_void)->c_int {unsafe{mrk_install_producer_retire(cell)}}
    #[cfg(feature="package-producer-signing")]
    fn signature_copy(&mut self,cell:*mut c_void,output:&mut [u8;512],size:&mut usize)->c_int {
        unsafe{mrk_install_producer_sign_copy(cell,output.as_mut_ptr(),output.len(),size)}
    }
    // Portable report DATA tests must never acquire a real Keychain signer.
    #[cfg(all(test,not(feature="package-producer-signing")))]
    fn signature_copy(&mut self,_:*mut c_void,_:&mut [u8;512],_:&mut usize)->c_int {0}
}

/// Inert construction, one original operation, explicit consuming close only.
/// No Drop cleanup, background work, exported keys or independent deadline.
pub struct ProducerVerifier {
    operation:ProducerOperation,pointer:Option<NonNull<c_void>>,report:Report,phase:Option<ProducerPhase>,cell:CellCustody,
    entered:bool,in_call:bool,in_gate:bool,unknown:bool,closed:bool,first:Option<Instant>,
    signature_size:usize,
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
        cell:CellCustody::Absent,entered:false,in_call:false,in_gate:false,unknown:false,closed:false,first:None,signature_size:0}}
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
        remove_signature_matched:self.operation==ProducerOperation::RemoveDetachedSignature&&self.report.matched==1,
        remove_program_matched:self.operation==ProducerOperation::RemoveProgram&&self.report.matched==1,
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
        self.signature_size=signer.rsa_bits_data() as usize/8;
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

/// Fixed Remove-v1 detached signature, same original custody and raw-message
/// engine. No release/peer/exclusion authority follows from this result.
pub struct RemovalProducerVerifier{inner:ProducerVerifier}
impl Default for RemovalProducerVerifier{fn default()->Self{Self::new()}}
impl RemovalProducerVerifier{
    pub fn new()->Self{Self{inner:ProducerVerifier::new_for(ProducerOperation::RemoveDetachedSignature)}}
    pub fn project_owned_upper_bound()->Option<usize>{ProducerVerifier::project_owned_upper_bound()?.checked_add(std::mem::size_of::<Self>())}
    pub fn custody(&self)->ProducerCustody{self.inner.custody()}
    pub fn settled(&self)->bool{self.inner.settled()}
    pub fn close(&mut self,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->bool{self.inner.close(gate)}
    pub fn verify_and_close(&mut self,descriptor:&[u8],signature:&[u8],gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->SignatureResult{
        self.verify_with(descriptor,signature,gate,&mut Calls)
    }
    fn verify_with(&mut self,descriptor:&[u8],signature:&[u8],gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,native:&mut impl Native)->SignatureResult{
        match self.inner.verify_input(VerificationInput::Signature{descriptor,signature},gate,native){
            VerificationResult::Matched=>SignatureResult::SignatureVerified,VerificationResult::Unavailable=>SignatureResult::Unavailable,
            VerificationResult::Refused=>SignatureResult::Refused,_=>SignatureResult::Unknown,
        }
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum RemovalProgramResult{PurposeVerified,Unavailable,Refused,Unknown}
/// STATIC signed on-disk program only. Caller retains/adopts its complete
/// nofollow chain, file digest, filesystem/ACL policy and original POST. The
/// emitter need not be this program. Live Parent/peer ALSO must prove their
/// actual executed image/audit token/location; this wrapper does not do that.
pub struct RemovalProgramVerifier{inner:ProducerVerifier}
impl Default for RemovalProgramVerifier{fn default()->Self{Self::new()}}
impl RemovalProgramVerifier{
    pub fn new()->Self{Self{inner:ProducerVerifier::new_for(ProducerOperation::RemoveProgram)}}
    pub fn project_owned_upper_bound()->Option<usize>{ProducerVerifier::project_owned_upper_bound()?.checked_add(std::mem::size_of::<Self>())}
    pub fn custody(&self)->ProducerCustody{self.inner.custody()}
    pub fn settled(&self)->bool{self.inner.settled()}
    pub fn close(&mut self,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->bool{self.inner.close(gate)}
    pub fn verify_and_close(&mut self,directory:BorrowedFd<'_>,program:BorrowedFd<'_>,directory_path:&Path,
        gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->RemovalProgramResult{
        self.verify_with(VerificationInput::RemoveProgram{directory:directory.as_raw_fd(),program:program.as_raw_fd(),
            directory_path:directory_path.as_os_str().as_bytes()},gate,&mut Calls)
    }
    fn verify_with(&mut self,input:VerificationInput<'_>,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,native:&mut impl Native)->RemovalProgramResult{
        match self.inner.verify_input(input,gate,native){VerificationResult::Matched=>RemovalProgramResult::PurposeVerified,
            VerificationResult::Unavailable=>RemovalProgramResult::Unavailable,VerificationResult::Refused=>RemovalProgramResult::Refused,
            _=>RemovalProgramResult::Unknown}
    }
}

/// Actual current process plus its retained static standalone program. This
/// cannot substitute for the completed package, same-artifact genesis pair,
/// fresh absent-app observation or original R/M exclusion owed by the caller.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum RemovalRecoveryProgramResult{ExecutingSourceVerified,Unavailable,Refused,Unknown}
pub struct RemovalRecoveryProgramVerifier{inner:ProducerVerifier}
impl Default for RemovalRecoveryProgramVerifier{fn default()->Self{Self::new()}}
impl RemovalRecoveryProgramVerifier{
    pub fn new()->Self{Self{inner:ProducerVerifier::new_for(ProducerOperation::RemoveRecoveryProgram)}}
    pub fn project_owned_upper_bound()->Option<usize>{
        // Same26-reference native cell and existing stack; additionally reserve
        // a second bounded chain (at most8 certificates) and copied leaf DER.
        // Opaque Security framework heap still belongs to the caller's floor.
        ProducerVerifier::project_owned_upper_bound()?.checked_add(9*CERTIFICATE_LIMIT)?
            .checked_add(std::mem::size_of::<Self>())
    }
    pub fn custody(&self)->ProducerCustody{self.inner.custody()}
    pub fn settled(&self)->bool{self.inner.settled()}
    pub fn close(&mut self,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->bool{self.inner.close(gate)}
    pub fn verify_and_close(&mut self,directory:BorrowedFd<'_>,program:BorrowedFd<'_>,directory_path:&Path,
        gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->RemovalRecoveryProgramResult{
        self.verify_with(VerificationInput::RecoveryProgram{directory:directory.as_raw_fd(),program:program.as_raw_fd(),
            directory_path:directory_path.as_os_str().as_bytes()},gate,&mut Calls)
    }
    fn verify_with(&mut self,input:VerificationInput<'_>,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,native:&mut impl Native)->RemovalRecoveryProgramResult{
        match self.inner.verify_input(input,gate,native){VerificationResult::Matched=>RemovalRecoveryProgramResult::ExecutingSourceVerified,
            VerificationResult::Unavailable=>RemovalRecoveryProgramResult::Unavailable,VerificationResult::Refused=>RemovalRecoveryProgramResult::Refused,
            _=>RemovalRecoveryProgramResult::Unknown}
    }
}

/// Public signature bytes only. Creation does not authenticate Developer-ID
/// purpose, a completed package, or any ReleaseSet authority.
#[cfg(any(test,feature="package-producer-signing"))]
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct PackageSignatureData {bytes:[u8;512],size:usize}
#[cfg(any(test,feature="package-producer-signing"))]
impl PackageSignatureData {pub fn as_bytes(&self)->&[u8] {&self.bytes[..self.size]}}
#[cfg(any(test,feature="package-producer-signing"))]
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum PackageSignResult {SignatureCreated(PackageSignatureData),Unavailable,Refused,Unknown}

/// Explicit nonshipping packaging caller, same original CF engine and clock.
/// Only Calls can reach the feature-gated native signer. Tests substitute return
/// DATA privately; neither CONFIGURED0 nor synthetic DATA can sign a package.
#[cfg(any(test,feature="package-producer-signing"))]
pub struct PackageProducerSigner {inner:ProducerVerifier,copy_entered:bool,copy_returned:bool}
#[cfg(any(test,feature="package-producer-signing"))]
impl Default for PackageProducerSigner {fn default()->Self {Self::new()}}
#[cfg(any(test,feature="package-producer-signing"))]
impl PackageProducerSigner {
    pub fn new()->Self {Self{inner:ProducerVerifier::new_for(ProducerOperation::PackageSigning),copy_entered:false,copy_returned:false}}
    pub fn project_owned_upper_bound()->Option<usize> {
        ProducerVerifier::project_owned_upper_bound()?.checked_add(512+std::mem::size_of::<Self>()+1024)
    }
    pub fn custody(&self)->ProducerCustody {self.inner.custody()}
    pub fn settled(&self)->bool {self.inner.settled()&&(!self.copy_entered||self.copy_returned)}
    pub fn close(&mut self,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->bool {
        self.inner.close(gate)&&self.settled()
    }
    pub fn sign_and_close(&mut self,descriptor:&[u8],gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->PackageSignResult {
        self.sign_with(descriptor,gate,&mut Calls)
    }
    fn sign_with(&mut self,descriptor:&[u8],gate:&mut dyn FnMut(ProducerCheckpoint)->Decision,native:&mut impl Native)->PackageSignResult {
        if self.inner.entered||self.inner.closed||self.inner.pointer.is_some()||self.inner.in_call
            ||self.inner.in_gate||self.inner.unknown||self.copy_entered {
            self.inner.poison(Instant::now());return PackageSignResult::Unknown;
        }
        self.inner.entered=true;
        let observed=self.inner.inspect(VerificationInput::Signing{descriptor},gate,native);
        let mut output=[0;512];let mut size=0;
        if observed==VerificationResult::Matched && self.inner.first.is_none() {
            let phase=ProducerPhase::CopySignature;
            if self.inner.work_point(phase,None,gate) {
                if let Some(pointer)=self.inner.pointer {
                    self.copy_entered=true;self.inner.in_call=true;
                    let returned=native.signature_copy(pointer.as_ptr(),&mut output,&mut size);
                    let at=Instant::now();self.inner.in_call=false;self.copy_returned=true;
                    if returned!=1 || !matches!(size,256|384|512) || size!=self.inner.signature_size
                        || output[size..].iter().any(|b|*b!=0) {self.inner.poison(at);}
                    self.inner.work_point(phase,Some(at),gate);
                } else {self.inner.poison(Instant::now());}
            }
        }
        if !self.inner.close_with(gate,native)||!self.settled() {return PackageSignResult::Unknown;}
        match observed {
            VerificationResult::Matched if self.copy_entered&&self.copy_returned&&self.inner.first.is_none()
                &&self.inner.report.failed==0&&self.inner.report.matched==1=>
                    PackageSignResult::SignatureCreated(PackageSignatureData{bytes:output,size}),
            VerificationResult::Unavailable=>PackageSignResult::Unavailable,
            VerificationResult::Unknown=>PackageSignResult::Unknown,_=>PackageSignResult::Refused,
        }
    }
}

/// Nonshipping Remove-v1 signer only; same key selection/custody/copy/close.
#[cfg(any(test,feature="package-producer-signing"))]
pub struct RemovalProducerSigner{inner:PackageProducerSigner}
#[cfg(any(test,feature="package-producer-signing"))]
impl Default for RemovalProducerSigner{fn default()->Self{Self::new()}}
#[cfg(any(test,feature="package-producer-signing"))]
impl RemovalProducerSigner{
    pub fn new()->Self{Self{inner:PackageProducerSigner{inner:ProducerVerifier::new_for(ProducerOperation::RemoveSigning),copy_entered:false,copy_returned:false}}}
    pub fn project_owned_upper_bound()->Option<usize>{PackageProducerSigner::project_owned_upper_bound()?.checked_add(std::mem::size_of::<Self>())}
    pub fn custody(&self)->ProducerCustody{self.inner.custody()}
    pub fn settled(&self)->bool{self.inner.settled()}
    pub fn close(&mut self,gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->bool{self.inner.close(gate)}
    pub fn sign_and_close(&mut self,descriptor:&[u8],gate:&mut dyn FnMut(ProducerCheckpoint)->Decision)->PackageSignResult{
        self.inner.sign_with(descriptor,gate,&mut Calls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Bounded synthetic return DATA only; never a Security/purpose certificate
    // or a native passing receipt. The private trait is not a production API.
    struct DataCalls {report:Report,unavailable:bool,failed_at:Option<u8>,bad_at:Option<u8>,
        unknown_at:Option<u8>,release_unknown:bool,allocated:bool,releases:Vec<u8>,retired:bool,
        copy_bad:bool,copied:bool,failed_without_output:bool}
    impl DataCalls {fn new()->Self{Self{report:Report{version:1,..Report::default()},unavailable:false,
        failed_at:None,bad_at:None,unknown_at:None,release_unknown:false,allocated:false,releases:Vec::new(),retired:false,
        copy_bad:false,copied:false,failed_without_output:false}}}
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
            let code=matches!(self.report.reserved,1|2|5|7);
            let recovery=self.report.reserved==7;
            let sign=matches!(self.report.reserved,3|6);
            let slot=if sign {match n{1..=8=>Some((n-1)as usize),9=>Some(8),10=>Some(10),11=>Some(11),12=>Some(13),_=>None}}
                else if code {match n{1..=4=>Some((n-1)as usize),6=>Some(4),7=>Some(5),
                    9 if recovery=>Some(6),11 if recovery=>Some(7),12 if recovery=>Some(8),_=>None}}
                else {match n{1..=8=>Some((n-1)as usize),9=>Some(8),10..=16=>Some(n as usize),
                    20=>Some(17),22=>Some(18),23..=29=>Some((n-4)as usize),_=>None}};
            if let Some(slot)=slot{assert_eq!(self.report.states[slot],0);self.report.states[slot]=if sign&&n==12 || !sign&&!code&&matches!(n,22|29){4}else{2};}
            if !code&&n==9{self.report.states[9]=4;}
            if sign&&n==11{self.report.states[12]=4;}
            if self.failed_at==Some(n as u8){self.report.failed=1;if !code&&matches!(n,22|29){self.report.states[slot.unwrap()]=2;}}
            if sign&&self.failed_at==Some(n as u8)&&self.failed_without_output {self.report.states[slot.unwrap()]=4;}
            if self.unknown_at==Some(n as u8){self.report.failed=1;self.report.unknown=1;}
            else{self.report.returned+=1;if n==(if sign{12}else if recovery{13}else if code{8}else{29})&&self.report.failed==0{self.report.matched=1;}}
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
        fn signature_copy(&mut self,_:*mut c_void,output:&mut [u8;512],size:&mut usize)->c_int {
            assert!(matches!(self.report.reserved,3|6));assert_eq!(self.report.matched,1);assert!(!self.copied);
            self.copied=true;*size=if self.copy_bad{513}else{256};output[..256].fill(7);1
        }
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
        let operation=ProducerOperation::PackageSigning;
        let mut native=DataCalls::new();native.report.reserved=3;
        let mut old=Report{version:1,reserved:3,..Report::default()};
        for n in 1..=12 {
            native.step(std::ptr::null_mut(),n,&mut raw);
            assert!(transition(raw,old,ProducerPhase::Inspect(n as u8),operation));
            for mode in 0..=2 {let mut wrong=raw;wrong.reserved=mode;
                assert!(!transition(wrong,old,ProducerPhase::Inspect(n as u8),operation));}
            let mut extra=raw;extra.states[14]=2;
            assert!(!transition(extra,old,ProducerPhase::Inspect(n as u8),operation));
            if let Some(error)=match n {9=>Some(9),11=>Some(12),12=>Some(13),_=>None} {
                let mut lost=raw;lost.states[error]=0;
                assert!(!transition(lost,old,ProducerPhase::Inspect(n as u8),operation));
                let mut false_success=raw;false_success.states[error]=2;
                assert!(!transition(false_success,old,ProducerPhase::Inspect(n as u8),operation));
            }
            if n<12 {let mut early=raw;early.matched=1;
                assert!(!transition(early,old,ProducerPhase::Inspect(n as u8),operation));}
            old=raw;
        }
        assert_eq!(raw.matched,1);
        assert_eq!(&raw.states[..14],&[2,2,2,2,2,2,2,2,2,4,2,2,4,4]);
        assert!(!transition(raw,old,ProducerPhase::CopySignature,operation));
        assert!(!transition(raw,old,ProducerPhase::Inspect(13),operation));
        // The exact old operations remain 0/1/2/3. New removal purposes have
        // disjoint fixed values even when their native slot layout is shared.
        assert_eq!(ProducerOperation::DetachedSignature.code(),0);
        assert_eq!(ProducerOperation::CurrentProduct(CurrentProductRole::EntryApp).code(),1);
        assert_eq!(ProducerOperation::CurrentProduct(CurrentProductRole::PayloadApp).code(),2);
        assert_eq!(ProducerOperation::PackageSigning.code(),3);
        for(mode,operation,steps,slots)in [(4,ProducerOperation::RemoveDetachedSignature,29,26),
            (5,ProducerOperation::RemoveProgram,8,6),(6,ProducerOperation::RemoveSigning,12,14),
            (7,ProducerOperation::RemoveRecoveryProgram,13,9)]{
            assert_eq!(operation.code(),mode);assert_eq!(operation.steps(),steps);assert_eq!(operation.slots(),slots);
            let mut native=DataCalls::new();native.report.reserved=mode;
            let mut old=Report{version:1,reserved:mode,..Report::default()};
            for n in 1..=steps{
                native.step(std::ptr::null_mut(),u32::from(n),&mut raw);
                assert!(transition(raw,old,ProducerPhase::Inspect(n),operation));
                for foreign in 0..=7{if foreign!=mode{let mut bad=raw;bad.reserved=foreign;
                    assert!(!transition(bad,old,ProducerPhase::Inspect(n),operation));}}
                if mode==7{if let Some(slot)=match n{9=>Some(6),11=>Some(7),12=>Some(8),_=>None}{
                    let mut lost=raw;lost.states[slot]=0;assert!(!transition(lost,old,ProducerPhase::Inspect(n),operation));
                }}
                if slots<SLOTS{let mut extra=raw;extra.states[slots]=2;assert!(!transition(extra,old,ProducerPhase::Inspect(n),operation));}
                if n<steps{let mut early=raw;early.matched=1;assert!(!transition(early,old,ProducerPhase::Inspect(n),operation));}
                old=raw;
            }
            assert_eq!(raw.matched,1);assert!(!transition(raw,old,ProducerPhase::Inspect(steps+1),operation));
        }
        assert_eq!(REMOVE_DOMAIN,b"MobileReleaseKit-remove-producer-v1\0");assert_ne!(REMOVE_DOMAIN,DOMAIN);
        assert!(REMOVE_DOMAIN.len()<=DOMAIN.len());
        assert!(RemovalProducerVerifier::project_owned_upper_bound().unwrap()<=320*1024);
        assert!(RemovalProgramVerifier::project_owned_upper_bound().unwrap()<=320*1024);
        assert!(RemovalRecoveryProgramVerifier::project_owned_upper_bound().unwrap()<=512*1024);
        assert_eq!(RECOVERY_CODE_STEPS,13);assert_eq!(RECOVERY_CODE_SLOTS,9);
        assert!(RemovalProducerSigner::project_owned_upper_bound().unwrap()<=320*1024);
        assert_eq!(std::mem::size_of::<Report>(),136);assert_eq!(std::mem::size_of::<SourceSigner>(),104);
        assert!(ProducerVerifier::project_owned_upper_bound().unwrap()<=320*1024);
        assert!(PackageProducerSigner::project_owned_upper_bound().unwrap()<=320*1024);
    }
    #[test]
    fn signature_result_requires_same_owner_finality_and_late_gate_refuses() {
        // Same original decoder engine, DISTINCT static and executing-self
        // operation. All calls below are inert return DATA, never signed code.
        let recovery_input=VerificationInput::RecoveryProgram{directory:11,program:12,directory_path:b"/fixed"};
        let static_input=VerificationInput::RemoveProgram{directory:11,program:12,directory_path:b"/fixed"};
        assert!(!recovery_input.valid_for(ProducerOperation::RemoveProgram));
        assert!(!static_input.valid_for(ProducerOperation::RemoveRecoveryProgram));
        let mut native=DataCalls::new();let mut recovery=RemovalRecoveryProgramVerifier::new();let mut phases=Vec::new();
        let result=recovery.verify_with(recovery_input,&mut |point|{
            if let ProducerCheckpoint::Returned{phase:ProducerPhase::Inspect(n),custody,..}=point{
                phases.push(n);assert!(!custody.remove_program_matched&&!custody.remove_signature_matched
                    &&!custody.signature_matched&&custody.purpose_matched.is_none());
            } Decision::Proceed
        },&mut native);
        assert_eq!(result,RemovalRecoveryProgramResult::ExecutingSourceVerified);
        assert_eq!(phases,(1..=13).collect::<Vec<_>>());assert!(recovery.settled()&&native.retired);
        assert_eq!(native.releases,vec![8,7,6,5,4,3,2,1,0]);
        assert_eq!(recovery.custody().operation,ProducerOperation::RemoveRecoveryProgram);
        for input in [static_input,VerificationInput::Signature{descriptor:b"{}",signature:&[7;256]},
            VerificationInput::RecoveryProgram{directory:-1,program:12,directory_path:b"/fixed"},
            VerificationInput::RecoveryProgram{directory:11,program:12,directory_path:b"/fixed/../foreign"}]{
            let mut native=DataCalls::new();let mut recovery=RemovalRecoveryProgramVerifier::new();
            assert_eq!(recovery.verify_with(input,&mut |_|Decision::Proceed,&mut native),RemovalRecoveryProgramResult::Refused);
            assert!(recovery.settled()&&!native.allocated);
        }
        for phase in 1..=13{
            let mut native=DataCalls::new();native.failed_at=Some(phase);let mut recovery=RemovalRecoveryProgramVerifier::new();
            assert_eq!(recovery.verify_with(recovery_input,&mut |_|Decision::Proceed,&mut native),RemovalRecoveryProgramResult::Refused);
            assert!(recovery.settled()&&native.retired&&recovery.custody().first_failure.is_some());
            assert_eq!(native.report.matched,0);
        }
        let mut native=DataCalls::new();native.unavailable=true;let mut recovery=RemovalRecoveryProgramVerifier::new();
        assert_eq!(recovery.verify_with(recovery_input,&mut |_|Decision::Proceed,&mut native),RemovalRecoveryProgramResult::Unavailable);
        assert!(recovery.settled()&&!native.allocated);

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
        let mut native=DataCalls::new();let mut signer=PackageProducerSigner::new();
        let result=signer.sign_with(b"original descriptor DATA",&mut |_|Decision::Proceed,&mut native);
        let PackageSignResult::SignatureCreated(signature)=result else {panic!("DATA signature result");};
        assert_eq!(signature.as_bytes(),&[7;256]);
        assert!(signer.settled()&&native.retired&&native.copied);
        assert_eq!(native.releases,vec![11,10,8,7,6,5,4,3,2,1,0]);
        assert!(!signer.custody().signature_matched&&signer.custody().purpose_matched.is_none());
        assert_eq!(signer.sign_with(b"{}",&mut |_|Decision::Proceed,&mut native),PackageSignResult::Unknown);
        // Known failed headless Get/disable/key operation with proven restore is
        // represented by a normal failed phase; NOT an actual Keychain test.
        for phase in [3,4,6,7,11] {
            for absent in [false,true] {
                let mut native=DataCalls::new();native.failed_at=Some(phase);native.failed_without_output=absent;
                let mut signer=PackageProducerSigner::new();
                assert_eq!(signer.sign_with(b"{}",&mut |_|Decision::Proceed,&mut native),PackageSignResult::Refused);
                assert!(signer.settled()&&native.retired&&!native.copied);
            }
        }
        let mut native=DataCalls::new();native.unavailable=true;let mut signer=PackageProducerSigner::new();
        assert_eq!(signer.sign_with(b"{}",&mut |_|Decision::Proceed,&mut native),PackageSignResult::Unavailable);
        assert!(signer.settled()&&!native.allocated&&!native.copied);
        for descriptor in [b"".as_slice(),&vec![0;DESCRIPTOR_LIMIT+1]] {
            let mut native=DataCalls::new();let mut signer=PackageProducerSigner::new();
            assert_eq!(signer.sign_with(descriptor,&mut |_|Decision::Proceed,&mut native),PackageSignResult::Refused);
            assert!(signer.settled()&&!native.allocated);
        }
        for returned in [false,true] {
            let mut native=DataCalls::new();let mut signer=PackageProducerSigner::new();
            let result=signer.sign_with(b"{}",&mut |point| match point {
                ProducerCheckpoint::Before{phase:ProducerPhase::CopySignature,..} if !returned=>Decision::Stop,
                ProducerCheckpoint::Returned{phase:ProducerPhase::CopySignature,..} if returned=>Decision::Stop,
                _=>Decision::Proceed},&mut native);
            assert_eq!(result,PackageSignResult::Refused);assert!(signer.settled()&&native.retired);
            assert_eq!(native.copied,returned);
        }
        let mut native=DataCalls::new();let mut remove=RemovalProducerVerifier::new();
        assert_eq!(remove.verify_with(b"remove raw descriptor",&[0;256],&mut |_|Decision::Proceed,&mut native),SignatureResult::SignatureVerified);
        assert!(remove.settled()&&native.retired&&remove.custody().remove_signature_matched);
        assert!(!remove.custody().signature_matched&&!remove.custody().remove_program_matched&&remove.custody().purpose_matched.is_none());
        assert_eq!(remove.custody().operation,ProducerOperation::RemoveDetachedSignature);
        let mut native=DataCalls::new();native.failed_at=Some(22);let mut remove=RemovalProducerVerifier::new();
        let mut imported=false;
        assert_eq!(remove.verify_with(b"{}",&[0;256],&mut |point|{if let ProducerCheckpoint::Returned{phase:ProducerPhase::Inspect(22),custody,..}=point{
            imported=custody.failed&&custody.first_failure.is_some();}Decision::Proceed},&mut native),SignatureResult::Refused);
        assert!(imported&&remove.settled()&&native.retired&&!remove.custody().remove_signature_matched);
        let input=VerificationInput::RemoveProgram{directory:11,program:12,directory_path:b"/private/owned-remover"};
        let mut native=DataCalls::new();let mut program=RemovalProgramVerifier::new();
        assert_eq!(program.verify_with(input,&mut |_|Decision::Proceed,&mut native),RemovalProgramResult::PurposeVerified);
        assert!(program.settled()&&native.retired&&program.custody().remove_program_matched);
        assert!(!program.custody().signature_matched&&!program.custody().remove_signature_matched&&program.custody().purpose_matched.is_none());
        assert_eq!(native.releases,vec![5,4,3,2,1,0]);
        assert!(!input.valid_for(ProducerOperation::CurrentProduct(CurrentProductRole::EntryApp)));
        assert!(!input.valid_for(ProducerOperation::RemoveDetachedSignature));
        let old=VerificationInput::Current{outer:11,code:12,outer_path:b"/private/Entry.app"};
        assert!(!old.valid_for(ProducerOperation::RemoveProgram));
        for path in [b"relative".as_slice(),b"/",b"/a//b",b"/a/../b",b"/a/./b",b"/a/",b"/a\0b"]{
            let mut native=DataCalls::new();let mut program=RemovalProgramVerifier::new();
            assert_eq!(program.verify_with(VerificationInput::RemoveProgram{directory:11,program:12,directory_path:path},
                &mut |_|Decision::Proceed,&mut native),RemovalProgramResult::Refused);assert!(program.settled()&&!native.allocated);
        }
        assert!(!VerificationInput::RemoveProgram{directory:-1,program:12,directory_path:b"/fixed"}.valid_for(ProducerOperation::RemoveProgram));
        let mut native=DataCalls::new();native.failed_at=Some(5);let mut program=RemovalProgramVerifier::new();
        assert_eq!(program.verify_with(input,&mut |_|Decision::Proceed,&mut native),RemovalProgramResult::Refused);
        assert!(program.settled()&&native.retired&&!program.custody().remove_program_matched);
        let mut native=DataCalls::new();let mut signer=RemovalProducerSigner::new();
        assert!(matches!(signer.inner.sign_with(b"{}",&mut |_|Decision::Proceed,&mut native),PackageSignResult::SignatureCreated(_)));
        assert!(signer.settled()&&native.retired&&native.copied);assert_eq!(signer.custody().operation,ProducerOperation::RemoveSigning);
        for descriptor in [b"".as_slice(),&vec![0;REMOVE_DESCRIPTOR_LIMIT+1]]{
            let mut native=DataCalls::new();let mut signer=RemovalProducerSigner::new();
            assert_eq!(signer.inner.sign_with(descriptor,&mut |_|Decision::Proceed,&mut native),PackageSignResult::Refused);
            assert!(signer.settled()&&!native.allocated);
            let mut native=DataCalls::new();let mut remove=RemovalProducerVerifier::new();
            assert_eq!(remove.verify_with(descriptor,&[0;256],&mut |_|Decision::Proceed,&mut native),SignatureResult::Refused);
            assert!(remove.settled()&&!native.allocated);
        }
    }
    #[test]
    fn unknown_native_or_gate_custody_never_releases_or_publishes_success() {
        let recovery_input=VerificationInput::RecoveryProgram{directory:11,program:12,directory_path:b"/fixed"};
        for phase in [8,9,10,11,12,13]{for malformed in [false,true]{
            let mut native=DataCalls::new();if malformed{native.bad_at=Some(phase);}else{native.unknown_at=Some(phase);}
            let mut recovery=RemovalRecoveryProgramVerifier::new();
            assert_eq!(recovery.verify_with(recovery_input,&mut |_|Decision::Proceed,&mut native),RemovalRecoveryProgramResult::Unknown);
            assert!(!recovery.settled()&&!native.retired&&native.releases.is_empty());
            assert!(!recovery.inner.close_with(&mut |_|Decision::Proceed,&mut native));
            assert!(!native.retired&&native.releases.is_empty());
        }}
        for release_unknown in [false,true]{
            let mut native=DataCalls::new();native.release_unknown=release_unknown;let mut recovery=RemovalRecoveryProgramVerifier::new();
            assert_eq!(recovery.verify_with(recovery_input,&mut |point|match point{
                ProducerCheckpoint::Returned{phase:ProducerPhase::RetireCell,..}=>Decision::Stop,
                _=>Decision::Proceed},&mut native),RemovalRecoveryProgramResult::Unknown);
            assert!(!recovery.settled());assert_eq!(native.retired,!release_unknown);
        }
        let mut native=DataCalls::new();let mut recovery=RemovalRecoveryProgramVerifier::new();
        let panic=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
            recovery.verify_with(recovery_input,&mut |point|match point{
                ProducerCheckpoint::Returned{phase:ProducerPhase::Inspect(11),..}=>panic!("recovery original gate DATA"),
                _=>Decision::Proceed},&mut native)
        }));
        assert!(panic.is_err()&&recovery.custody().gate_entered&&recovery.custody().unknown);
        assert!(!recovery.inner.close_with(&mut |_|Decision::Proceed,&mut native)&&native.releases.is_empty()&&!native.retired);

        let input=VerificationInput::RemoveProgram{directory:11,program:12,directory_path:b"/private/owned-remover"};
        for failure in 0..3{
            let mut native=DataCalls::new();if failure==0{native.bad_at=Some(4);}else if failure==1{native.unknown_at=Some(4);}else{native.release_unknown=true;}
            let mut program=RemovalProgramVerifier::new();
            assert_eq!(program.verify_with(input,&mut |_|Decision::Proceed,&mut native),RemovalProgramResult::Unknown);
            assert!(!program.settled()&&!native.retired);
            let mut native=DataCalls::new();if failure==0{native.bad_at=Some(9);}else if failure==1{native.unknown_at=Some(9);}else{native.release_unknown=true;}
            let mut remove=RemovalProducerVerifier::new();
            assert_eq!(remove.verify_with(b"{}",&[0;256],&mut |_|Decision::Proceed,&mut native),SignatureResult::Unknown);
            assert!(!remove.settled()&&!native.retired);
        }
        for program_mode in [false,true]{
            let mut native=DataCalls::new();let mut gate=|point|match point{
                ProducerCheckpoint::Returned{phase:ProducerPhase::RetireCell,..}=>Decision::Stop,_=>Decision::Proceed};
            if program_mode{let mut program=RemovalProgramVerifier::new();
                assert_eq!(program.verify_with(input,&mut gate,&mut native),RemovalProgramResult::Unknown);assert!(!program.settled());}
            else{let mut remove=RemovalProducerVerifier::new();
                assert_eq!(remove.verify_with(b"{}",&[0;256],&mut gate,&mut native),SignatureResult::Unknown);assert!(!remove.settled());}
            assert!(native.retired); // actual consuming return is recorded, never rolled back.
        }
        let mut native=DataCalls::new();native.copy_bad=true;let mut signer=RemovalProducerSigner::new();
        assert_eq!(signer.inner.sign_with(b"{}",&mut |_|Decision::Proceed,&mut native),PackageSignResult::Unknown);
        assert!(!signer.settled()&&!native.retired);
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
        // Returned-unknown restoration, thrown key calls and malformed mode3
        // reports all veto CF cleanup and copied signature publication.
        for phase in [3,4,6,7,11] {
            for malformed in [false,true] {
                let mut native=DataCalls::new();let mut signer=PackageProducerSigner::new();
                if malformed {native.bad_at=Some(phase);} else {native.unknown_at=Some(phase);}
                assert_eq!(signer.sign_with(b"{}",&mut |_|Decision::Proceed,&mut native),PackageSignResult::Unknown);
                assert!(!signer.settled()&&!native.retired&&!native.copied&&native.releases.is_empty());
            }
        }
        let mut native=DataCalls::new();native.copy_bad=true;let mut signer=PackageProducerSigner::new();
        assert_eq!(signer.sign_with(b"{}",&mut |_|Decision::Proceed,&mut native),PackageSignResult::Unknown);
        assert!(native.copied&&!native.retired&&native.releases.is_empty()&&!signer.settled());
        for release_unknown in [false,true] {
            let mut native=DataCalls::new();native.release_unknown=release_unknown;
            let mut signer=PackageProducerSigner::new();
            let result=signer.sign_with(b"{}",&mut |point| match point {
                ProducerCheckpoint::Returned{phase:ProducerPhase::RetireCell,..}=>Decision::Stop,
                _=>Decision::Proceed},&mut native);
            assert_eq!(result,PackageSignResult::Unknown);assert!(native.copied&&!signer.settled());
            assert_eq!(native.retired,!release_unknown);
        }
        let mut native=DataCalls::new();let mut signer=PackageProducerSigner::new();
        let panic=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            signer.sign_with(b"{}",&mut |point| match point {
                ProducerCheckpoint::Returned{phase:ProducerPhase::CopySignature,..}=>panic!("local copy gate DATA"),
                _=>Decision::Proceed},&mut native)
        }));
        assert!(panic.is_err()&&signer.custody().gate_entered&&signer.custody().unknown);
        assert!(!signer.inner.close_with(&mut |_|Decision::Proceed,&mut native)&&native.releases.is_empty()&&!native.retired);
    }
}
