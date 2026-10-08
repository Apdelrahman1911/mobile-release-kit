//! Fixed removal-peer originals and the immutable shared cutoff. Only actual
//! same-channel/source/code admission reaches its private cutoff constructor.
//! Parsed DATA and the main-window sheet alone cannot authenticate a peer.
use std::{mem::size_of, sync::Arc};

const PARENT_WORK_NS: u64 = 110_000_000_000;
const PARENT_HARD_NS: u64 = 120_000_000_000;
// Same representable first-failure ceiling as the existing Android Signal.
const MAX_RAW: u64 = (1_u64 << 61) - 1;

struct AuthenticatedCutoffOriginal {
    request_id: [u8; 16],
    root_nonce: [u8; 16],
    start: u64,
    work: u64,
    hard: u64,
}
impl AuthenticatedCutoffOriginal {
    fn valid(&self) -> bool {
        self.request_id != [0; 16] && self.root_nonce != [0; 16]
            && self.start != 0 && self.hard <= MAX_RAW
            && self.work.checked_sub(self.start) == Some(PARENT_WORK_NS)
            && self.hard.checked_sub(self.start) == Some(PARENT_HARD_NS)
    }
}
// Match the existing source-bound Arc accounting convention in
// android_service_budget. Allocator/framework private memory is not claimed.
#[repr(C)]
struct ArcAllocation<T> { counts: [usize; 2], value: T }

/// A cloned reference preserves this SAME authenticated original, not merely
/// an equal deadline. No Serialize/Deserialize, public constructor or setter.
/// Keeping this proof does not prove peer/channel close, exit, or completion.
#[derive(Clone)]
pub struct ParentCutoff { original: Arc<AuthenticatedCutoffOriginal> }
impl ParentCutoff {
    // Only the native peer's actual authenticated Challenge admission below
    // may enter here. No public DATA constructor or renderer-selected decoder.
    fn from_authenticated_original(original: AuthenticatedCutoffOriginal) -> Option<Self> {
        original.valid().then(|| Self { original: Arc::new(original) })
    }
    pub fn start_ns(&self) -> u64 { self.original.start }
    pub fn work_ns(&self) -> u64 { self.original.work }
    pub fn hard_ns(&self) -> u64 { self.original.hard }
    pub fn same_original(&self, other: &Self) -> bool { Arc::ptr_eq(&self.original, &other.original) }
    /// Includes the handle plus one original allocation. Multiple handles to
    /// this original must be identity-deduplicated by their enclosing census.
    pub fn project_owned_upper_bound() -> Option<usize> {
        size_of::<Self>().checked_add(size_of::<ArcAllocation<AuthenticatedCutoffOriginal>>())
    }
    // Native crate tests only: cannot construct a Peer or confirmation proof,
    // and is absent from production and external app-crate test compilation.
    #[cfg(test)]
    pub(crate) fn test_original(start: u64) -> Option<Self> {
        Self::from_authenticated_original(AuthenticatedCutoffOriginal {
            request_id: [1; 16], root_nonce: [2; 16], start,
            work: start.checked_add(PARENT_WORK_NS)?,
            hard: start.checked_add(PARENT_HARD_NS)?,
        })
    }
}

// The immutable cutoff is shared across graphs. Native main UI must not enter
// helper/resident graphs; no feature grants a public cutoff constructor.
#[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
mod confirmation {
    use super::{ParentCutoff,MAX_RAW};
    use std::{ffi::c_void,marker::PhantomData,mem::size_of,ptr::NonNull,rc::Rc};
    unsafe extern "C" {
        fn mrk_removal_confirmation_bytes()->usize;
        fn mrk_removal_confirmation_reserve(start:u64,work:u64,hard:u64)->*mut c_void;
        fn mrk_removal_confirmation_start(original:*mut c_void)->i32;
        fn mrk_removal_confirmation_poll(original:*mut c_void)->i32;
        fn mrk_removal_confirmation_close(original:*mut c_void)->i32;
        fn mrk_removal_confirmation_retire(original:*mut c_void,accepted:*mut u32,nonce:*mut u8)->i32;
        fn mrk_removal_monotonic(now:*mut u64)->i32;
    }
    /// Actual raw Parent-domain observation. Never compare this integer with
    /// vault_helper_wire::uptime / CLOCK_UPTIME_RAW or an Instant projection.
    pub fn parent_monotonic()->Option<u64>{
        let mut now=0;
        // SAFETY: fixed output scalar, no retained address or native object.
        (unsafe{mrk_removal_monotonic(&mut now)}==1 && now!=0 && now<=MAX_RAW).then_some(now)
    }
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum ConfirmationPoll { Pending,Accepted,Declined,Closed,Refused,Unknown }
    // Returned DATA decoder, not native consumption/consent proof by itself.
    fn retired_consent_data(accepted:u32,nonce:[u8;16],now:Option<u64>,cutoff:&ParentCutoff)->Result<bool,()>{
        if !matches!((accepted,nonce==[0;16]),(0,true)|(1,false)){return Err(());}
        let now=now.ok_or(())?;
        if now<cutoff.start_ns() || now>=cutoff.hard_ns() || now>MAX_RAW{return Err(());}
        Ok(accepted==1 && now<cutoff.work_ns())
    }
    /// Accepted DATA from poll is not consent authority. Only known consuming
    /// retirement of the actual callback/window/book yields this non-Clone type.
    pub struct RemovalConfirmed { cutoff:ParentCutoff,app_nonce:[u8;16] }
    impl RemovalConfirmed {
        pub fn cutoff(&self)->&ParentCutoff{&self.cutoff}
        pub fn app_nonce(&self)->[u8;16]{self.app_nonce}
        pub fn project_owned_upper_bound()->Option<usize>{
            size_of::<Self>().checked_add(ParentCutoff::project_owned_upper_bound()?)
        }
    }
    /// One original retained by the existing main TLS callback, not Send/Sync.
    /// Drop performs no native cleanup and cannot certify callback settlement.
    /// Caller MUST retain a failed/unknown instance until actual retirement.
    pub struct RemovalConfirmation {
        original:Option<NonNull<c_void>>,cutoff:ParentCutoff,
        started:bool,close_attempted:bool,retire_attempted:bool,
        _main:PhantomData<Rc<()>>,
    }
    impl RemovalConfirmation {
        pub fn project_owned_upper_bound()->Option<usize>{
            // SAFETY: native sizeof/fixed-block calculation only, no allocation.
            let native=unsafe{mrk_removal_confirmation_bytes()};
            if native==0 || native>384{return None;}
            size_of::<Self>().checked_add(native)?
                .checked_add(ParentCutoff::project_owned_upper_bound()?)
        }
        pub fn reserve(cutoff:&ParentCutoff)->Option<Self>{
            Self::project_owned_upper_bound()?;
            // SAFETY: authenticated immutable endpoints, native enforces main
            // thread/ordinary account. Returned original owns all later refs.
            let original=NonNull::new(unsafe{mrk_removal_confirmation_reserve(
                cutoff.start_ns(),cutoff.work_ns(),cutoff.hard_ns())})?;
            Some(Self{original:Some(original),cutoff:cutoff.clone(),started:false,
                close_attempted:false,retire_attempted:false,_main:PhantomData})
        }
        pub fn start(&mut self)->bool{
            if self.started || self.close_attempted{return false;}
            let Some(original)=self.original else{return false;};self.started=true;
            // SAFETY: exclusive original, native main check, no Rust callback.
            unsafe{mrk_removal_confirmation_start(original.as_ptr())==1}
        }
        pub fn poll(&mut self)->ConfirmationPoll{
            let Some(original)=self.original else{return ConfirmationPoll::Closed;};
            // SAFETY: exact still-owned cell, main serialization enforced below.
            match unsafe{mrk_removal_confirmation_poll(original.as_ptr())}{
                0=>ConfirmationPoll::Pending,1=>ConfirmationPoll::Accepted,
                2=>ConfirmationPoll::Declined,3=>ConfirmationPoll::Closed,
                -2=>ConfirmationPoll::Refused,_=>ConfirmationPoll::Unknown,
            }
        }
        pub fn begin_close(&mut self)->bool{
            if self.close_attempted{return false;}
            let Some(original)=self.original else{return false;};self.close_attempted=true;
            // SAFETY: one consuming close attempt; failure keeps cell custody.
            unsafe{mrk_removal_confirmation_close(original.as_ptr())==1}
        }
        pub fn retire(&mut self)->Result<Option<RemovalConfirmed>,()>{
            if self.retire_attempted || !self.close_attempted{return Err(());}
            let original=self.original.ok_or(())?;
            // Call only after real Closed. No consuming retry while pending.
            if self.poll()!=ConfirmationPoll::Closed{return Err(());}
            self.retire_attempted=true;
            let mut accepted=0;let mut nonce=[0;16];
            // SAFETY: fixed outputs, original consumed ONLY by returned1.
            let consumed=unsafe{mrk_removal_confirmation_retire(original.as_ptr(),&mut accepted,nonce.as_mut_ptr())};
            if consumed!=1{return Err(());}
            self.original=None; // Record actual consumption before clock POST.
            // Exactly one POST sample. Consumed-but-late/unknown is Err, not a
            // successful decline; is_retired still preserves the actual free.
            if retired_consent_data(accepted,nonce,parent_monotonic(),&self.cutoff)?{
                Ok(Some(RemovalConfirmed{cutoff:self.cutoff.clone(),app_nonce:nonce}))
            }else{Ok(None)}
        }
        pub fn is_retired(&self)->bool{self.original.is_none()}
    }
    #[cfg(test)]
    pub(super) fn check_retirement_data(){
        let cutoff=ParentCutoff::test_original(5).unwrap();
        for (accepted,nonce,now,expected) in [
            (1,[3;16],Some(5),Ok(true)),(0,[0;16],Some(5),Ok(false)),
            (1,[3;16],Some(cutoff.work_ns()-1),Ok(true)),
            (1,[3;16],Some(cutoff.work_ns()),Ok(false)),
            (1,[3;16],Some(cutoff.hard_ns()-1),Ok(false)),
            (1,[3;16],Some(cutoff.hard_ns()),Err(())),
            (0,[0;16],Some(cutoff.hard_ns()),Err(())),
            (1,[3;16],Some(4),Err(())),(1,[3;16],None,Err(())),
            (0,[0;16],None,Err(())),(1,[0;16],Some(5),Err(())),
            (0,[3;16],Some(5),Err(())),(2,[0;16],Some(5),Err(())),
        ]{assert_eq!(retired_consent_data(accepted,nonce,now,&cutoff),expected);}
    }
}
#[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
pub use confirmation::{parent_monotonic,ConfirmationPoll,RemovalConfirmation,RemovalConfirmed};

// The caller's existing worker owns this synchronous adapter from creation to
// consuming retirement. No async callback, FD transfer or new executor lives
// here; only the already-reviewed confirmation runs on the main thread.
#[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
mod peer {
    use super::{AuthenticatedCutoffOriginal,ParentCutoff,MAX_RAW,PARENT_WORK_NS,PARENT_HARD_NS};
    use super::confirmation::{parent_monotonic,RemovalConfirmed};
    use crate::android_service_management::{CellCustody,Decision};
    use crate::install_producer::{ProducerVerifier,CurrentProductVerifier,CurrentProductRole,
        ProducerOperation,ProducerCustody,RemovalProducerVerifier,RemovalProgramVerifier};
    use std::{ffi::c_void,marker::PhantomData,mem::size_of,os::fd::{AsRawFd,BorrowedFd},
        panic::{catch_unwind,AssertUnwindSafe},ptr::NonNull,rc::Rc,time::Instant};

    pub const REMOVAL_FRAME_BYTES:usize=4100;
    pub const REMOVAL_BORROWED_ORIGINALS:usize=20;
    const OWNED_FDS:usize=3;
    const CF_SLOTS:usize=24;
    const NONE:u32=u32::MAX;
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    #[repr(u32)]
    pub enum RemovalPeerRole { Parent=1,App=2 }
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum RemovalTargetData { Arm64,Intel }
    /// Fixed decoded DATA only. It neither authenticates its origin nor mints
    /// a cutoff. Decoder input is the complete actual prefix+body, at most4100.
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub struct RemovalChallengeData {
        pub request_id:[u8;16],pub root_nonce:[u8;16],pub source:[u8;20],
        pub target:RemovalTargetData,pub release:[u8;128],pub release_len:u8,
        pub remove_producer:[u8;32],pub installed_producer:[u8;32],
        pub inventory:[u8;32],pub protocol:[u8;32],pub start:u64,pub work:u64,pub hard:u64,
    }
    impl RemovalChallengeData {
        pub fn valid_data(&self)->bool{
            let prefix=match self.target{RemovalTargetData::Arm64=>b"macos26-arm64-".as_slice(),RemovalTargetData::Intel=>b"macos26-x86_64-".as_slice()};
            let n=usize::from(self.release_len);
            self.request_id!=[0;16]&&self.root_nonce!=[0;16]&&self.request_id!=self.root_nonce&&self.source!=[0;20]
                &&[self.remove_producer,self.installed_producer,self.inventory,self.protocol].iter().all(|sha|*sha!=[0;32])
                &&n>prefix.len()&&n<=128&&self.release[..n].starts_with(prefix)
                &&self.release[..n].iter().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b"-_.".contains(b))
                &&self.release[n..].iter().all(|b|*b==0)
                &&(self.release[n-1].is_ascii_lowercase()||self.release[n-1].is_ascii_digit())
                &&self.start!=0&&self.hard<=MAX_RAW&&self.work.checked_sub(self.start)==Some(PARENT_WORK_NS)
                &&self.hard.checked_sub(self.start)==Some(PARENT_HARD_NS)
        }
    }
    /// SOURCE-selected noncapturing function. Never select it from a request,
    /// renderer value or plugin; the app supplies its existing closed decoder.
    pub type DecodeRemovalChallenge=fn(&[u8])->Option<RemovalChallengeData>;

    fn verified(c:ProducerCustody,operation:ProducerOperation)->bool{
        c.operation==operation&&!c.failed&&!c.unknown&&!c.in_call&&!c.gate_entered
            &&c.cell==CellCustody::Consumed&&c.calls>0&&c.calls==c.returned
            &&c.references.iter().all(|s|matches!(*s,0|4))
            &&match operation{
                ProducerOperation::DetachedSignature=>c.signature_matched,
                ProducerOperation::CurrentProduct(role)=>c.purpose_matched==Some(role),
                ProducerOperation::RemoveDetachedSignature=>c.remove_signature_matched,
                ProducerOperation::RemoveProgram=>c.remove_program_matched,
                ProducerOperation::RemoveRecoveryProgram=>false,
                #[cfg(any(test,feature="package-producer-signing"))]
                ProducerOperation::PackageSigning|ProducerOperation::RemoveSigning=>false,
            }
    }
    /// Borrows the actual successful native verifier instances and the same
    /// admitted signed originals. The enclosing SOURCE owner joins each raw
    /// slice to the SAME verifier invocation, current inventory/release and
    /// full original roster, and supplies that checkpoint on every operation.
    /// Neither a ProducerCustody copy nor a digest/enum can construct this.
    pub struct RemovalSourceOriginals<'a>{
        installed:&'a ProducerVerifier,entry:&'a CurrentProductVerifier,payload:&'a CurrentProductVerifier,
        remove:&'a RemovalProducerVerifier,program:Option<&'a RemovalProgramVerifier>,
        fds:[BorrowedFd<'a>;REMOVAL_BORROWED_ORIGINALS],raw:[&'a [u8];4],
        code_sha256:[[u8;32];3],request_sha256:[u8;32],
    }
    impl<'a> RemovalSourceOriginals<'a>{
        #[allow(clippy::too_many_arguments)]
        pub fn new(installed:&'a ProducerVerifier,entry:&'a CurrentProductVerifier,payload:&'a CurrentProductVerifier,
            remove:&'a RemovalProducerVerifier,program:Option<&'a RemovalProgramVerifier>,
            fds:[BorrowedFd<'a>;REMOVAL_BORROWED_ORIGINALS],raw:[&'a [u8];4],
            code_sha256:[[u8;32];3],request_sha256:[u8;32])->Option<Self>{
            let value=Self{installed,entry,payload,remove,program,fds,raw,code_sha256,request_sha256};
            value.current().then_some(value)
        }
        fn current(&self)->bool{
            self.installed.settled()&&verified(self.installed.custody(),ProducerOperation::DetachedSignature)
                &&self.entry.settled()&&verified(self.entry.custody(),ProducerOperation::CurrentProduct(CurrentProductRole::EntryApp))
                &&self.payload.settled()&&verified(self.payload.custody(),ProducerOperation::CurrentProduct(CurrentProductRole::PayloadApp))
                &&self.remove.settled()&&verified(self.remove.custody(),ProducerOperation::RemoveDetachedSignature)
                &&self.program.is_none_or(|p|p.settled()&&verified(p.custody(),ProducerOperation::RemoveProgram))
                &&!self.raw[0].is_empty()&&self.raw[0].len()<=65536&&matches!(self.raw[1].len(),256|384|512)
                &&!self.raw[2].is_empty()&&self.raw[2].len()<=16384&&matches!(self.raw[3].len(),256|384|512)
                &&self.code_sha256.iter().all(|sha|*sha!=[0;32])&&self.request_sha256!=[0;32]
                &&self.fds.iter().enumerate().all(|(i,fd)|fd.as_raw_fd()>=3
                    &&self.fds[..i].iter().all(|other|other.as_raw_fd()!=fd.as_raw_fd()))
        }
        fn input(&self,role:RemovalPeerRole,binding:&RemovalChallengeData)->RawInputs{
            RawInputs{version:1,role:role as u32,start:binding.start,work:binding.work,hard:binding.hard,
                request_id:binding.request_id,code_sha256:self.code_sha256,installed_sha256:binding.installed_producer,
                remove_sha256:binding.remove_producer,request_sha256:self.request_sha256,
                borrowed:self.fds.map(|fd|fd.as_raw_fd()),installed:self.raw[0].as_ptr(),installed_signature:self.raw[1].as_ptr(),
                remove:self.raw[2].as_ptr(),remove_signature:self.raw[3].as_ptr(),installed_size:self.raw[0].len(),
                installed_signature_size:self.raw[1].len(),remove_size:self.raw[2].len(),remove_signature_size:self.raw[3].len()}
        }
    }
    /// Full original public control metadata, not a publication/ownership proof
    /// on its own. Parent's checkpoint only rebaselines a real own Bind/Mode
    /// Returned transition; App and every later phase must require equality.
    #[repr(C)]
    #[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
    pub struct RemovalOriginalData{
        pub device:u64,pub inode:u64,pub links:u64,pub size:u64,
        pub modified_seconds:i64,pub changed_seconds:i64,
        pub mode:u32,pub uid:u32,pub gid:u32,pub flags:u32,pub modified_nanoseconds:u32,pub changed_nanoseconds:u32,
    }
    #[repr(C)]
    #[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
    struct Report{
        version:u32,role:u32,operation:u32,failed:u32,unknown:u32,calls:u32,returned:u32,
        stage:u32,frame_index:u32,frame_started:u32,frame_size:u32,frame_offset:u32,
        token_ready:u32,watch_ready:u32,exit_observed:u32,eof:u32,closed:u32,bind_returned:u32,
        fd_states:[u32;OWNED_FDS],cf_states:[u32;CF_SLOTS],peer_pid:u32,peer_uid:u32,peer_gid:u32,first_code:u32,
        last:u64,first_failure:u64,request_directory:RemovalOriginalData,socket_name:RemovalOriginalData,
    }
    #[repr(C)]
    struct RawInputs{
        version:u32,role:u32,start:u64,work:u64,hard:u64,request_id:[u8;16],code_sha256:[[u8;32];3],
        installed_sha256:[u8;32],remove_sha256:[u8;32],request_sha256:[u8;32],borrowed:[i32;20],
        installed:*const u8,installed_signature:*const u8,remove:*const u8,remove_signature:*const u8,
        installed_size:usize,installed_signature_size:usize,remove_size:usize,remove_signature_size:usize,
    }
    const _: [();72]=[();size_of::<RemovalOriginalData>()];
    const _: [();360]=[();size_of::<Report>()];
    const _: [();384]=[();size_of::<RawInputs>()];
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    #[repr(u32)]
    pub enum RemovalPeerOperation{Source=1,Open=2,Connect=3,Authenticate=4,BeginFrame=5,PollFrame=6,Recheck=7,WaitExit=8,Close=9}
    impl RemovalPeerOperation{fn cleanup(self)->bool{matches!(self,Self::WaitExit|Self::Close)}}
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    #[repr(u32)]
    pub enum RemovalNativePhase{
        Source=1,StaticUrl,StaticCode,RequirementText,Requirement,StaticValidity,StaticInfo,Certificate,
        OwnCode,DynamicValidity,DynamicInfo,Socket,SocketFlags,Bind,SocketMode,Listen,Connect,ConnectStatus,
        Accept,Token,AuditData,AuditAttributes,Guest,Kqueue,WatchFlags,WatchRegister,WatchPoll,Send,Receive,Release,Close,Retire,Boundary,
    }
    impl RemovalNativePhase{
        fn from_raw(value:u32)->Option<Self>{Some(match value{
            1=>Self::Source,2=>Self::StaticUrl,3=>Self::StaticCode,4=>Self::RequirementText,5=>Self::Requirement,
            6=>Self::StaticValidity,7=>Self::StaticInfo,8=>Self::Certificate,9=>Self::OwnCode,10=>Self::DynamicValidity,
            11=>Self::DynamicInfo,12=>Self::Socket,13=>Self::SocketFlags,14=>Self::Bind,15=>Self::SocketMode,
            16=>Self::Listen,17=>Self::Connect,18=>Self::ConnectStatus,19=>Self::Accept,20=>Self::Token,
            21=>Self::AuditData,22=>Self::AuditAttributes,23=>Self::Guest,24=>Self::Kqueue,25=>Self::WatchFlags,
            26=>Self::WatchRegister,27=>Self::WatchPoll,28=>Self::Send,29=>Self::Receive,30=>Self::Release,
            31=>Self::Close,32=>Self::Retire,33=>Self::Boundary,_=>return None})}
        fn cf_acquisition(self)->bool{matches!(self,Self::StaticUrl|Self::StaticCode|Self::RequirementText|Self::Requirement
            |Self::StaticInfo|Self::Certificate|Self::OwnCode|Self::DynamicInfo|Self::AuditData|Self::AuditAttributes|Self::Guest)}
        fn fd_acquisition(self)->bool{matches!(self,Self::Socket|Self::Accept|Self::Kqueue)}
        fn cleanup(self)->bool{matches!(self,Self::Release|Self::Close|Self::Retire)}
    }
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum RemovalPeerPhase{Allocate,Call(RemovalPeerOperation),Native{phase:RemovalNativePhase,slot:Option<u8>,cleanup:bool},CopyFrame,Retire}
    impl RemovalPeerPhase{fn cleanup(self)->bool{match self{
        Self::Call(op)=>op.cleanup(),Self::Native{cleanup,..}=>cleanup,Self::Retire=>true,_=>false,
    }}}
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub struct RemovalPeerCustody{
        pub role:RemovalPeerRole,pub cell:CellCustody,pub in_call:bool,pub in_gate:bool,pub failed:bool,pub unknown:bool,
        pub first_failure:Option<Instant>,pub native_first_code:u32,pub native_first_failure:u64,
        pub native_calls:u32,pub native_returns:u32,pub native_stage:u32,pub frame_index:u32,pub frame_pending:bool,
        pub frames_bytes:u32,pub fds:[u32;3],pub references:[u32;24],pub peer_pid:u32,pub peer_uid:u32,pub peer_gid:u32,
        pub actual_exit_observed:bool,pub native_closed:bool,pub last_parent_monotonic:u64,
        pub request_directory:RemovalOriginalData,pub socket_name:RemovalOriginalData,
    }
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum RemovalPeerCheckpoint{
        Before{phase:RemovalPeerPhase,custody:RemovalPeerCustody},
        Returned{phase:RemovalPeerPhase,at:Instant,custody:RemovalPeerCustody},
    }
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum RemovalPeerProgress{Pending,Ready,Refused,Unknown}
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum RemovalPeerError{Refused,Unknown}

    fn report_shape(raw:Report,old:Report,binding:&RemovalChallengeData)->bool{
        raw.version==1&&raw.role==old.role&&(1..=9).contains(&raw.operation)
            &&raw.stage<=4&&raw.stage>=old.stage&&raw.stage<=old.stage+1
            &&raw.frame_index<=4&&raw.frame_index>=old.frame_index&&raw.frame_index<=old.frame_index+1
            &&[raw.failed,raw.unknown,raw.frame_started,raw.token_ready,raw.watch_ready,raw.exit_observed,raw.eof,raw.closed,raw.bind_returned].iter().all(|b|*b<=1)
            &&raw.failed>=old.failed&&raw.unknown>=old.unknown&&raw.token_ready>=old.token_ready&&raw.watch_ready>=old.watch_ready
            &&raw.exit_observed>=old.exit_observed&&raw.closed>=old.closed&&raw.bind_returned>=old.bind_returned
            &&raw.frame_size<=4100&&raw.frame_offset<=4100&&raw.fd_states.iter().chain(&raw.cf_states).all(|s|*s<=5)
            &&raw.calls>=old.calls&&raw.returned>=old.returned&&raw.returned<=raw.calls&&raw.calls-raw.returned<=1
            &&raw.last>=old.last&&raw.last>=binding.start&&raw.last<=MAX_RAW
            &&(if raw.failed==0{raw.unknown==0&&raw.first_code==0&&raw.first_failure==0}
                else{(1..=81).contains(&raw.first_code)&&raw.first_failure>=binding.start&&raw.first_failure<=raw.last
                    &&(old.failed==0||(raw.first_code==old.first_code&&raw.first_failure==old.first_failure))})
            &&(raw.token_ready==0&&(raw.peer_pid,raw.peer_uid,raw.peer_gid)==(0,0,0)
                ||raw.token_ready==1&&raw.peer_pid>1
                    &&(raw.role==1&&raw.peer_uid!=0||raw.role==2&&raw.peer_uid==0&&raw.peer_gid==0)
                    &&(old.token_ready==0||(raw.peer_pid,raw.peer_uid,raw.peer_gid)==(old.peer_pid,old.peer_uid,old.peer_gid)))
            &&(raw.watch_ready==0||raw.token_ready==1)
            &&(raw.exit_observed==0||raw.watch_ready==1)
            &&(raw.closed==0||raw.unknown==0&&raw.calls==raw.returned
                &&raw.fd_states.iter().chain(&raw.cf_states).all(|s|matches!(*s,0|4)))
    }
    fn returned_transition(raw:Report,old:Report,phase:RemovalNativePhase,slot:Option<usize>)->bool{
        if phase==RemovalNativePhase::Boundary{return raw.calls==old.calls&&raw.returned==old.returned
            &&raw.fd_states==old.fd_states&&raw.cf_states==old.cf_states;}
        if old.calls.checked_add(1)!=Some(raw.calls)||old.returned.checked_add(1)!=Some(raw.returned){return false;}
        for (i,(&before,&after)) in old.cf_states.iter().zip(&raw.cf_states).enumerate(){
            if phase.cf_acquisition()&&slot==Some(i){
                if !matches!(before,0|4)||!matches!(after,2|4|5){return false;}
            }else if phase==RemovalNativePhase::Release&&slot==Some(i){
                if before!=2||!matches!(after,4|5){return false;}
            }else if before!=after{return false;}
        }
        for (i,(&before,&after)) in old.fd_states.iter().zip(&raw.fd_states).enumerate(){
            if phase.fd_acquisition()&&slot==Some(i){
                if before!=0||!(matches!(after,2|4|5)||phase==RemovalNativePhase::Accept&&after==0){return false;}
            }else if phase==RemovalNativePhase::Close&&slot==Some(i){
                if before!=2||!matches!(after,4|5){return false;}
            }else if before!=after{return false;}
        }
        true
    }
    struct Ledger{role:RemovalPeerRole,report:Report,cell:CellCustody,first:Option<Instant>,failed:bool,unknown:bool,
        in_call:bool,in_gate:bool,pending:Option<(RemovalNativePhase,Option<usize>)>}
    impl Ledger{
        fn new(role:RemovalPeerRole,binding:&RemovalChallengeData)->Self{Self{role,
            report:Report{version:1,role:role as u32,last:binding.start,..Report::default()},cell:CellCustody::Absent,
            first:None,failed:false,unknown:false,in_call:false,in_gate:false,pending:None}}
        fn note(&mut self,at:Instant,unknown:bool){self.first=Some(self.first.map_or(at,|first|first.min(at)));self.failed=true;self.unknown|=unknown;}
        fn custody(&self)->RemovalPeerCustody{let r=self.report;RemovalPeerCustody{
            role:self.role,cell:self.cell,in_call:self.in_call,in_gate:self.in_gate,failed:self.failed||r.failed==1,
            unknown:self.unknown||r.unknown==1,first_failure:self.first,native_first_code:r.first_code,native_first_failure:r.first_failure,
            native_calls:r.calls,native_returns:r.returned,native_stage:r.stage,frame_index:r.frame_index,frame_pending:r.frame_started==1,
            frames_bytes:r.frame_size,fds:r.fd_states,references:r.cf_states,peer_pid:r.peer_pid,peer_uid:r.peer_uid,peer_gid:r.peer_gid,
            actual_exit_observed:r.exit_observed==1,native_closed:r.closed==1,last_parent_monotonic:r.last,
            request_directory:r.request_directory,socket_name:r.socket_name}}
        fn gate(&mut self,phase:RemovalPeerPhase,before:bool,current:bool,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->bool{
            if self.in_gate{self.note(Instant::now(),true);return false;}
            if !current{self.note(Instant::now(),false);}
            if before&&!phase.cleanup()&&(self.failed||self.unknown){return false;}
            let custody=self.custody();self.in_gate=true;
            let at=Instant::now();
            let decision=catch_unwind(AssertUnwindSafe(||gate(if before{RemovalPeerCheckpoint::Before{phase,custody}}
                else{RemovalPeerCheckpoint::Returned{phase,at,custody}})));
            self.in_gate=false;
            match decision{Ok(Decision::Proceed) if current||phase.cleanup()=>true,
                Ok(Decision::Stop|Decision::Defer)=>{self.note(at,false);false},
                Ok(Decision::Proceed)=>false,_=>{self.note(at,true);false}}
        }
        fn authenticated(&self)->bool{let r=self.report;
            !self.failed&&!self.unknown&&r.failed==0&&r.unknown==0&&r.stage==4&&r.token_ready==1&&r.watch_ready==1
                &&r.calls>=20&&r.calls==r.returned&&r.exit_observed==0&&r.closed==0
                &&r.fd_states==(if self.role==RemovalPeerRole::Parent{[2,2,2]}else{[0,2,2]})
                &&r.cf_states[..20].iter().all(|s|*s==2)&&r.cf_states[20..].iter().all(|s|matches!(*s,0|4))
        }
        fn error(&self)->RemovalPeerError{if self.unknown||self.report.unknown==1{RemovalPeerError::Unknown}else{RemovalPeerError::Refused}}
    }
    type RawGate=unsafe extern "C" fn(*mut c_void,u32,u32,u32,u32,*const Report)->i32;
    struct Hook<'a>{ledger:&'a mut Ledger,binding:&'a RemovalChallengeData,current:&'a mut dyn FnMut()->bool,
        gate:&'a mut dyn FnMut(RemovalPeerCheckpoint)->Decision,operation:RemovalPeerOperation}
    unsafe extern "C" fn checkpoint(context:*mut c_void,before:u32,phase:u32,slot:u32,cleanup:u32,raw:*const Report)->i32{
        if context.is_null()||raw.is_null(){return -1;}
        // SAFETY: one synchronous non-retained callback while Hook is borrowed
        // exclusively by its native call on the original worker thread.
        let h=unsafe{&mut *context.cast::<Hook<'_>>()};
        let result=catch_unwind(AssertUnwindSafe(||{
            let raw=unsafe{*raw};let at=Instant::now();
            let Some(phase)=RemovalNativePhase::from_raw(phase)else{h.ledger.note(at,true);return -1;};
            let slot=if slot==NONE{None}else{Some(slot as usize)};
            if before>1||cleanup>1||slot.is_some_and(|s|s>=24)||raw.operation!=h.operation as u32
                ||!report_shape(raw,h.ledger.report,h.binding)
                ||cleanup==1&&!phase.cleanup()&&!matches!(phase,RemovalNativePhase::WatchPoll|RemovalNativePhase::Boundary)
                ||phase.cf_acquisition()&&slot.is_none()
                ||phase.fd_acquisition()&&slot.is_none_or(|s|s>=3){h.ledger.note(at,true);return -1;}
            let old=h.ledger.report;
            if before==1{
                if h.ledger.pending.is_some()||raw.calls!=old.calls||raw.returned!=old.returned||raw.fd_states!=old.fd_states||raw.cf_states!=old.cf_states
                    ||phase==RemovalNativePhase::Boundary{h.ledger.note(at,true);return -1;}
            }else if (phase!=RemovalNativePhase::Boundary&&h.ledger.pending!=Some((phase,slot)))
                ||!returned_transition(raw,old,phase,slot){h.ledger.note(at,true);return -1;}
            h.ledger.report=raw;
            if raw.failed==1{h.ledger.note(at,raw.unknown==1);}
            if before==0{h.ledger.pending=None;}
            let current=(h.current)();
            let admitted=h.ledger.gate(RemovalPeerPhase::Native{phase,slot:slot.map(|s|s as u8),cleanup:cleanup==1},before==1,current,h.gate);
            if admitted&&before==1{h.ledger.pending=Some((phase,slot));}
            if admitted{1}else if h.ledger.unknown{-1}else{0}
        }));
        match result{Ok(value)=>value,Err(_)=>{h.ledger.note(Instant::now(),true);-1}}
    }
    unsafe extern "C"{
        fn mrk_removal_peer_bytes()->usize;
        fn mrk_removal_peer_new(input:*const RawInputs)->*mut c_void;
        fn mrk_removal_peer_run(original:*mut c_void,operation:u32,frame:*const u8,size:usize,gate:RawGate,context:*mut c_void,out:*mut Report)->i32;
        fn mrk_removal_peer_copy(original:*mut c_void,out:*mut u8,size:*mut usize)->i32;
        fn mrk_removal_peer_retire(original:*mut c_void,out:*mut Report)->i32;
    }
    // Private substitution only for grouped inert returned-DATA tests. Public
    // methods always call Calls; there is no trait object or injectable backend.
    trait Native{
        fn now(&mut self)->Option<u64>;
        fn new(&mut self,input:&RawInputs)->*mut c_void;
        fn run(&mut self,p:*mut c_void,op:RemovalPeerOperation,frame:Option<&[u8]>,hook:&mut Hook<'_>,out:&mut Report)->i32;
        fn copy(&mut self,p:*mut c_void,out:&mut [u8;4100],size:&mut usize)->i32;
        fn retire(&mut self,p:*mut c_void,out:&mut Report)->i32;
    }
    struct Calls;
    impl Native for Calls{
        fn now(&mut self)->Option<u64>{parent_monotonic()}
        fn new(&mut self,input:&RawInputs)->*mut c_void{unsafe{mrk_removal_peer_new(input)}}
        fn run(&mut self,p:*mut c_void,op:RemovalPeerOperation,frame:Option<&[u8]>,hook:&mut Hook<'_>,out:&mut Report)->i32{
            let (bytes,size)=frame.map_or((std::ptr::null(),0),|b|(b.as_ptr(),b.len()));
            unsafe{mrk_removal_peer_run(p,op as u32,bytes,size,checkpoint,(hook as *mut Hook<'_>).cast(),out)}
        }
        fn copy(&mut self,p:*mut c_void,out:&mut [u8;4100],size:&mut usize)->i32{unsafe{mrk_removal_peer_copy(p,out.as_mut_ptr(),size)}}
        fn retire(&mut self,p:*mut c_void,out:&mut Report)->i32{unsafe{mrk_removal_peer_retire(p,out)}}
    }
    struct Core{ledger:Ledger,binding:RemovalChallengeData,pointer:Option<NonNull<c_void>>,buffer:[u8;4100],copied:bool,last_sample:u64,
        decoder_called:bool,cutoff:Option<ParentCutoff>,confirmed:bool,close_called:bool,retire_called:bool}
    impl Core{
        fn new(role:RemovalPeerRole,binding:RemovalChallengeData)->Self{Self{ledger:Ledger::new(role,&binding),binding,pointer:None,buffer:[0;4100],
            copied:false,last_sample:binding.start,decoder_called:false,cutoff:None,confirmed:false,close_called:false,retire_called:false}}
        fn clock(&mut self,native:&mut impl Native,cleanup:bool)->bool{
            let now=native.now();let valid=now.is_some_and(|now|now>=self.binding.start&&now>=self.ledger.report.last&&now>=self.last_sample
                &&now<(if cleanup{self.binding.hard}else{self.binding.work})&&now<=MAX_RAW);
            if let Some(now)=now.filter(|now|*now>=self.last_sample&&*now<=MAX_RAW){self.last_sample=now;}
            if !valid{self.ledger.note(Instant::now(),now.is_none());}valid
        }
        fn allocate(&mut self,input:&RawInputs,current:&mut dyn FnMut()->bool,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision,native:&mut impl Native)->bool{
            if self.pointer.is_some()||self.ledger.cell!=CellCustody::Absent||!self.binding.valid_data()
                ||!self.clock(native,false)||!self.ledger.gate(RemovalPeerPhase::Allocate,true,current(),gate){return false;}
            self.ledger.cell=CellCustody::Entering;self.ledger.in_call=true;
            let pointer=NonNull::new(native.new(input));
            // Returned actual allocation is recorded before any fallible POST.
            self.pointer=pointer;self.ledger.cell=if pointer.is_some(){CellCustody::Owned}else{CellCustody::Absent};self.ledger.in_call=false;
            if pointer.is_none(){self.ledger.note(Instant::now(),false);}
            let clock=self.clock(native,false);let post=self.ledger.gate(RemovalPeerPhase::Allocate,false,current(),gate);
            pointer.is_some()&&clock&&post&&!self.ledger.failed&&!self.ledger.unknown
        }
        fn final_report(&mut self,raw:Report,operation:RemovalPeerOperation,code:i32){
            let old=self.ledger.report;let at=Instant::now();
            let same_counts=raw.calls==old.calls&&raw.returned==old.returned;
            let unknown_entered=raw.unknown==1&&raw.failed==1&&old.calls.checked_add(1)==Some(raw.calls)&&raw.returned==old.returned;
            if !report_shape(raw,old,&self.binding)||raw.operation!=operation as u32
                ||!matches!(code,-2..=1)||(!same_counts&&!unknown_entered)
                ||same_counts&&(raw.fd_states!=old.fd_states||raw.cf_states!=old.cf_states)
                ||code>=0&&raw.unknown!=0||code>=0&&operation!=RemovalPeerOperation::Close&&raw.failed!=0{
                // Untrusted/malformed return cannot overwrite previous known
                // original facts. Retain pointer and every uncertain slot.
                self.ledger.note(at,true);return;
            }
            self.ledger.report=raw;self.ledger.pending=None;
            if raw.failed==1||code<0{self.ledger.note(at,raw.unknown==1||code==-1);}
        }
        fn invoke(&mut self,operation:RemovalPeerOperation,frame:Option<&[u8]>,current:&mut dyn FnMut()->bool,
            gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision,native:&mut impl Native)->RemovalPeerProgress{
            let Some(pointer)=self.pointer else{return RemovalPeerProgress::Refused;};
            if self.ledger.in_call||self.retire_called||self.close_called&&operation!=RemovalPeerOperation::Close
                ||!self.clock(native,operation.cleanup())
                ||!self.ledger.gate(RemovalPeerPhase::Call(operation),true,current(),gate){return self.progress(false);}
            self.ledger.in_call=true;let mut raw=self.ledger.report;
            let mut hook=Hook{ledger:&mut self.ledger,binding:&self.binding,current,gate,operation};
            let code=native.run(pointer.as_ptr(),operation,frame,&mut hook,&mut raw);
            self.ledger.in_call=false;self.final_report(raw,operation,code);
            // Actual consumes/partial returns remain in report if either POST
            // refuses. No late clock or formatter can repair earlier failure.
            let clock=self.clock(native,operation.cleanup());
            let post=self.ledger.gate(RemovalPeerPhase::Call(operation),false,current(),gate);
            if !clock||!post{return self.progress(false);}
            if operation==RemovalPeerOperation::BeginFrame&&code==1{self.copied=false;}
            self.progress(code==1)
        }
        fn progress(&self,ready:bool)->RemovalPeerProgress{
            if self.ledger.unknown||self.ledger.report.unknown==1{RemovalPeerProgress::Unknown}
            else if self.ledger.failed||self.ledger.report.failed==1{RemovalPeerProgress::Refused}
            else if ready{RemovalPeerProgress::Ready}else{RemovalPeerProgress::Pending}
        }
        fn copy(&mut self,current:&mut dyn FnMut()->bool,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision,native:&mut impl Native)->Result<usize,RemovalPeerError>{
            if self.copied||!self.ledger.authenticated()||self.ledger.report.frame_started!=0
                ||!(5..=4100).contains(&self.ledger.report.frame_size)||!self.clock(native,false)
                ||!self.ledger.gate(RemovalPeerPhase::CopyFrame,true,current(),gate){return Err(self.ledger.error());}
            let Some(pointer)=self.pointer else{return Err(RemovalPeerError::Refused);};
            self.ledger.in_call=true;let mut size=0;
            let code=native.copy(pointer.as_ptr(),&mut self.buffer,&mut size);self.ledger.in_call=false;
            if code==1{self.copied=true;} // Actual native copy consumed once.
            if code!=1||size!=self.ledger.report.frame_size as usize||!(5..=4100).contains(&size)
                ||u32::from_be_bytes(self.buffer[..4].try_into().expect("fixed prefix")) as usize!=size-4{
                self.ledger.note(Instant::now(),code!=0&&code!=1);
            }
            let clock=self.clock(native,false);let post=self.ledger.gate(RemovalPeerPhase::CopyFrame,false,current(),gate);
            if !clock||!post||self.ledger.failed||self.ledger.unknown{return Err(self.ledger.error());}
            if self.invoke(RemovalPeerOperation::Recheck,None,current,gate,native)!=RemovalPeerProgress::Ready{return Err(self.ledger.error());}
            Ok(size)
        }
        fn admit_challenge(&mut self,decoder:DecodeRemovalChallenge,current:&mut dyn FnMut()->bool,
            gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision,native:&mut impl Native)->Result<ParentCutoff,RemovalPeerError>{
            if self.ledger.role!=RemovalPeerRole::App||self.decoder_called||self.cutoff.is_some()
                ||self.ledger.report.frame_index!=1||!self.ledger.authenticated(){return Err(RemovalPeerError::Refused);}
            let size=self.copy(current,gate,native)?;self.decoder_called=true;
            let decoded=catch_unwind(AssertUnwindSafe(||decoder(&self.buffer[..size])));let unknown=decoded.is_err();
            if !matches!(decoded,Ok(Some(value)) if value.valid_data()&&value==self.binding){self.ledger.note(Instant::now(),unknown);return Err(self.ledger.error());}
            // Decoder is DATA work. Require current native source/token/code/
            // retained-watch POST AGAIN, then actual raw clock, before factory.
            if self.invoke(RemovalPeerOperation::Recheck,None,current,gate,native)!=RemovalPeerProgress::Ready||!self.clock(native,false){return Err(self.ledger.error());}
            let cutoff=ParentCutoff::from_authenticated_original(AuthenticatedCutoffOriginal{
                request_id:self.binding.request_id,root_nonce:self.binding.root_nonce,start:self.binding.start,work:self.binding.work,hard:self.binding.hard,
            }).ok_or(RemovalPeerError::Refused)?;
            self.cutoff=Some(cutoff.clone());Ok(cutoff)
        }
        fn retire(&mut self,current:&mut dyn FnMut()->bool,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision,native:&mut impl Native)->Result<Option<RemovalPeerRetired>,RemovalPeerError>{
            if self.retire_called||!self.close_called||self.ledger.report.closed!=1||self.ledger.report.unknown==1
                ||!self.clock(native,true)||!self.ledger.gate(RemovalPeerPhase::Retire,true,current(),gate){return Err(self.ledger.error());}
            let pointer=self.pointer.ok_or(RemovalPeerError::Refused)?;self.retire_called=true;self.ledger.in_call=true;
            let mut raw=self.ledger.report;let code=native.retire(pointer.as_ptr(),&mut raw);self.ledger.in_call=false;
            if code==1{self.pointer=None;self.ledger.cell=CellCustody::Consumed;} // BEFORE all POST, never reuse.
            if code!=1{self.ledger.note(Instant::now(),true);return Err(RemovalPeerError::Unknown);}
            self.final_report(raw,RemovalPeerOperation::Close,1);
            let clock=self.clock(native,true);let post=self.ledger.gate(RemovalPeerPhase::Retire,false,current(),gate);
            if !clock||!post||self.ledger.unknown{return Err(self.ledger.error());}
            let complete=!self.ledger.failed&&self.ledger.report.failed==0&&raw.frame_index==4&&raw.frame_started==0
                &&(self.ledger.role==RemovalPeerRole::Parent&&raw.exit_observed==1
                    ||self.ledger.role==RemovalPeerRole::App&&self.cutoff.is_some()&&self.confirmed);
            Ok(complete.then(||RemovalPeerRetired{role:self.ledger.role,binding:self.binding,cutoff:self.cutoff.clone(),peer_pid:raw.peer_pid,exit:raw.exit_observed==1}))
        }
    }
    /// Proof of this native peer's actual consuming retirement only, NOT
    /// service preparation, Document/task join, M/R exclusion or deletion.
    pub struct RemovalPeerRetired{role:RemovalPeerRole,binding:RemovalChallengeData,cutoff:Option<ParentCutoff>,peer_pid:u32,exit:bool}
    impl RemovalPeerRetired{
        pub fn role(&self)->RemovalPeerRole{self.role}
        pub fn binding_data(&self)->&RemovalChallengeData{&self.binding}
        pub fn cutoff(&self)->Option<&ParentCutoff>{self.cutoff.as_ref()}
        pub fn peer_pid_data(&self)->u32{self.peer_pid}
        pub fn original_peer_exit_observed(&self)->bool{self.exit}
    }
    /// !Send/!Sync and no native Drop. Unknown owns its same cell/references;
    /// caller retains it in the existing task/Closure, never drops for cleanup.
    pub struct RemovalPeer<'a>{source:RemovalSourceOriginals<'a>,core:Core,_worker:PhantomData<Rc<()>>}
    impl<'a> RemovalPeer<'a>{
        pub fn project_owned_upper_bound()->Option<usize>{
            let native=unsafe{mrk_removal_peer_bytes()}; // sizeof only, no allocation/API.
            if native==0||native>131072{return None;}
            size_of::<Self>().checked_add(native)?.checked_add(4*size_of::<Report>())?
                .checked_add(2*size_of::<RemovalChallengeData>())?.checked_add(size_of::<RawInputs>())?
                .checked_add(ParentCutoff::project_owned_upper_bound()?)
        }
        fn reserve(role:RemovalPeerRole,source:RemovalSourceOriginals<'a>,binding:RemovalChallengeData,
            gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->Self{
            let mut peer=Self{source,core:Core::new(role,binding),_worker:PhantomData};
            if !binding.valid_data()||!peer.source.current()||Self::project_owned_upper_bound().is_none_or(|n|n>196608){
                peer.core.ledger.note(Instant::now(),false);return peer;
            }
            let input=peer.source.input(role,&binding);let source=&peer.source;
            peer.core.allocate(&input,&mut ||source.current(),gate,&mut Calls);peer
        }
        pub fn parent(source:RemovalSourceOriginals<'a>,binding:RemovalChallengeData,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->Self{
            Self::reserve(RemovalPeerRole::Parent,source,binding,gate)
        }
        pub fn app(source:RemovalSourceOriginals<'a>,binding:RemovalChallengeData,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->Self{
            Self::reserve(RemovalPeerRole::App,source,binding,gate)
        }
        fn call(&mut self,op:RemovalPeerOperation,frame:Option<&[u8]>,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{
            let source=&self.source;self.core.invoke(op,frame,&mut ||source.current(),gate,&mut Calls)
        }
        pub fn admit_source(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{self.call(RemovalPeerOperation::Source,None,gate)}
        pub fn open(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{self.call(RemovalPeerOperation::Open,None,gate)}
        pub fn connect(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{self.call(RemovalPeerOperation::Connect,None,gate)}
        pub fn authenticate(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{self.call(RemovalPeerOperation::Authenticate,None,gate)}
        pub fn recheck(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{self.call(RemovalPeerOperation::Recheck,None,gate)}
        pub fn receive(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{self.call(RemovalPeerOperation::BeginFrame,None,gate)}
        pub fn poll_frame(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{self.call(RemovalPeerOperation::PollFrame,None,gate)}
        fn send_at(&mut self,index:u32,role:RemovalPeerRole,frame:&[u8],gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{
            if self.core.ledger.role!=role||self.core.ledger.report.frame_index!=index{return RemovalPeerProgress::Refused;}
            self.call(RemovalPeerOperation::BeginFrame,Some(frame),gate)
        }
        pub fn send_challenge(&mut self,frame:&[u8],gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{
            self.send_at(0,RemovalPeerRole::Parent,frame,gate)
        }
        pub fn send_confirmed(&mut self,consent:&RemovalConfirmed,frame:&[u8],gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{
            if self.core.cutoff.as_ref().is_none_or(|cutoff|!cutoff.same_original(consent.cutoff())){return RemovalPeerProgress::Refused;}
            let result=self.send_at(1,RemovalPeerRole::App,frame,gate);if result==RemovalPeerProgress::Ready{self.core.confirmed=true;}result
        }
        /// Caller MUST already possess its private current Completion witness
        /// and closed protocol state. Bytes/this method are not that witness.
        pub fn send_prepared(&mut self,frame:&[u8],gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{
            if !self.core.confirmed{return RemovalPeerProgress::Refused;}self.send_at(2,RemovalPeerRole::App,frame,gate)
        }
        pub fn send_quit_acknowledged(&mut self,frame:&[u8],gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{
            self.send_at(3,RemovalPeerRole::Parent,frame,gate)
        }
        pub fn admit_challenge(&mut self,decoder:DecodeRemovalChallenge,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->Result<ParentCutoff,RemovalPeerError>{
            let source=&self.source;self.core.admit_challenge(decoder,&mut ||source.current(),gate,&mut Calls)
        }
        /// Other fixed inbound frames remain DATA for the caller's one closed
        /// protocol-state parser. App Challenge cannot bypass its factory seam.
        pub fn received_frame(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->Result<&[u8],RemovalPeerError>{
            if self.core.ledger.role==RemovalPeerRole::App&&self.core.ledger.report.frame_index==1{return Err(RemovalPeerError::Refused);}
            let source=&self.source;let n=self.core.copy(&mut ||source.current(),gate,&mut Calls)?;Ok(&self.core.buffer[..n])
        }
        pub fn poll_original_exit(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{
            self.call(RemovalPeerOperation::WaitExit,None,gate)
        }
        pub fn close(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->RemovalPeerProgress{
            if self.core.close_called{return RemovalPeerProgress::Refused;}self.core.close_called=true;
            self.call(RemovalPeerOperation::Close,None,gate)
        }
        pub fn retire(&mut self,gate:&mut dyn FnMut(RemovalPeerCheckpoint)->Decision)->Result<Option<RemovalPeerRetired>,RemovalPeerError>{
            let source=&self.source;self.core.retire(&mut ||source.current(),gate,&mut Calls)
        }
        pub fn custody(&self)->RemovalPeerCustody{self.core.ledger.custody()}
        pub fn is_retired(&self)->bool{self.core.pointer.is_none()&&self.core.ledger.cell==CellCustody::Consumed}
        /// Includes known absence before/after a refused allocation, not a
        /// successful peer handshake. Only retire can return its private proof.
        pub fn settled(&self)->bool{self.core.pointer.is_none()&&!self.core.ledger.in_call&&!self.core.ledger.in_gate
            &&matches!(self.core.ledger.cell,CellCustody::Absent|CellCustody::Consumed)
            &&self.core.ledger.report.fd_states.iter().chain(&self.core.ledger.report.cf_states).all(|s|matches!(*s,0|4))}
    }

    #[cfg(test)]
    mod tests{
        use super::*;
        fn binding()->RemovalChallengeData{
            let mut release=[0;128];let text=b"macos26-arm64-remove-01";release[..text.len()].copy_from_slice(text);
            RemovalChallengeData{request_id:[1;16],root_nonce:[2;16],source:[3;20],target:RemovalTargetData::Arm64,
                release,release_len:text.len() as u8,remove_producer:[4;32],installed_producer:[5;32],inventory:[6;32],protocol:[7;32],
                start:5,work:5+PARENT_WORK_NS,hard:5+PARENT_HARD_NS}
        }
        fn report(role:RemovalPeerRole)->Report{
            let mut cf=[2;24];cf[20..].fill(4);
            Report{version:1,role:role as u32,operation:RemovalPeerOperation::Authenticate as u32,calls:40,returned:40,
                stage:4,token_ready:1,watch_ready:1,peer_pid:42,peer_uid:if role==RemovalPeerRole::Parent{501}else{0},
                fd_states:if role==RemovalPeerRole::Parent{[2,2,2]}else{[0,2,2]},cf_states:cf,last:5,
                ..Report::default()}
        }
        fn core()->Core{
            let mut core=Core::new(RemovalPeerRole::App,binding());core.pointer=Some(NonNull::dangling());
            core.ledger.cell=CellCustody::Owned;core.ledger.report=report(RemovalPeerRole::App);
            core.ledger.report.frame_index=1;core.ledger.report.frame_size=5;core.ledger.report.frame_offset=5;core
        }
        fn decode(bytes:&[u8])->Option<RemovalChallengeData>{(bytes==[0,0,0,1,b'{']).then(binding)}
        fn reject(_: &[u8])->Option<RemovalChallengeData>{None}
        fn panics(_: &[u8])->Option<RemovalChallengeData>{panic!("inert fixed decoder fault")}
        struct Fake{now:Option<u64>,frame:[u8;5],copies:usize,runs:usize,allocations:usize,retires:usize,
            late_copy:bool,late_retire:bool,allocate_null:bool}
        impl Fake{fn new()->Self{Self{now:Some(10),frame:[0,0,0,1,b'{'],copies:0,runs:0,allocations:0,retires:0,
            late_copy:false,late_retire:false,allocate_null:false}}}
        impl Native for Fake{
            fn now(&mut self)->Option<u64>{self.now}
            fn new(&mut self,_:&RawInputs)->*mut c_void{
                self.allocations+=1;if self.allocate_null{std::ptr::null_mut()}else{NonNull::<c_void>::dangling().as_ptr()}
            }
            fn run(&mut self,_:*mut c_void,op:RemovalPeerOperation,_:Option<&[u8]>,hook:&mut Hook<'_>,out:&mut Report)->i32{
                self.runs+=1;assert_eq!(op,RemovalPeerOperation::Recheck);
                let mut raw=hook.ledger.report;raw.operation=op as u32;raw.last=self.now.unwrap_or(raw.last);
                // Only a returned-DATA fixture. No socket, SecCode, watch, C
                // authentication or native proof is executed by these doubles.
                let admitted=unsafe{checkpoint((hook as *mut Hook<'_>).cast(),0,RemovalNativePhase::Boundary as u32,NONE,0,&raw)};
                if admitted!=1{raw.failed=1;raw.first_code=7;raw.first_failure=raw.last;raw.unknown=u32::from(admitted<0);}
                *out=raw;if admitted==1{1}else if admitted<0{-1}else{-2}
            }
            fn copy(&mut self,_:*mut c_void,out:&mut [u8;4100],size:&mut usize)->i32{
                self.copies+=1;out[..5].copy_from_slice(&self.frame);*size=5;
                if self.late_copy{self.now=Some(binding().work);}1
            }
            fn retire(&mut self,_:*mut c_void,out:&mut Report)->i32{
                self.retires+=1;out.operation=RemovalPeerOperation::Close as u32;
                if self.late_retire{self.now=Some(binding().hard);}1
            }
        }
        fn raw_input()->RawInputs{
            RawInputs{version:1,role:2,start:5,work:binding().work,hard:binding().hard,request_id:[1;16],code_sha256:[[8;32];3],
                installed_sha256:[5;32],remove_sha256:[4;32],request_sha256:[9;32],borrowed:std::array::from_fn(|i|3+i as i32),
                installed:std::ptr::null(),installed_signature:std::ptr::null(),remove:std::ptr::null(),remove_signature:std::ptr::null(),
                installed_size:0,installed_signature_size:0,remove_size:0,remove_signature_size:0}
        }
        #[test]
        fn peer_binding_and_actual_verifier_roles_are_closed_data(){
            let input=binding();assert!(input.valid_data());
            let changes:[fn(&mut RemovalChallengeData);17]=[
                |b|b.request_id=[0;16],|b|b.root_nonce=b.request_id,|b|b.root_nonce=[0;16],|b|b.source=[0;20],
                |b|b.remove_producer=[0;32],|b|b.installed_producer=[0;32],|b|b.inventory=[0;32],|b|b.protocol=[0;32],
                |b|b.start=0,|b|b.work-=1,|b|b.hard+=1,|b|b.release_len=0,
                |b|b.release[0]=b'/',|b|b.release[b.release_len as usize-1]=b'.',
                |b|b.release[127]=1,|b|b.target=RemovalTargetData::Intel,|b|{b.start=MAX_RAW;b.work=MAX_RAW;b.hard=MAX_RAW;},
            ];
            for change in changes{let mut bad=input;change(&mut bad);assert!(!bad.valid_data());}
            let mut max=input;max.release.fill(b'a');max.release[..14].copy_from_slice(b"macos26-arm64-");max.release_len=128;
            assert!(max.valid_data());
            let installed=ProducerVerifier::new();let entry=CurrentProductVerifier::new(CurrentProductRole::EntryApp);
            let payload=CurrentProductVerifier::new(CurrentProductRole::PayloadApp);let remove=RemovalProducerVerifier::new();let program=RemovalProgramVerifier::new();
            // These real empty Rust instances make no native entry. Neither
            // fresh/absent nor wrong-purpose custody can become SourceOriginals.
            for (value,role) in [(installed.custody(),ProducerOperation::DetachedSignature),
                (entry.custody(),ProducerOperation::CurrentProduct(CurrentProductRole::EntryApp)),
                (payload.custody(),ProducerOperation::CurrentProduct(CurrentProductRole::PayloadApp)),
                (remove.custody(),ProducerOperation::RemoveDetachedSignature),(program.custody(),ProducerOperation::RemoveProgram)]{
                assert!(!verified(value,role));
            }
            // Even a syntactically fully retired recovery result cannot stand
            // in for ANY current live-peer purpose or make operation7 a role.
            let recovery=ProducerCustody{operation:ProducerOperation::RemoveRecoveryProgram,phase:None,
                cell:CellCustody::Consumed,references:[4;26],entered:true,in_call:false,gate_entered:false,
                signature_matched:true,purpose_matched:Some(CurrentProductRole::EntryApp),
                remove_signature_matched:true,remove_program_matched:true,failed:false,unknown:false,
                calls:22,returned:22,first_failure:None};
            for role in [ProducerOperation::RemoveRecoveryProgram,ProducerOperation::DetachedSignature,
                ProducerOperation::CurrentProduct(CurrentProductRole::EntryApp),ProducerOperation::CurrentProduct(CurrentProductRole::PayloadApp),
                ProducerOperation::RemoveDetachedSignature,ProducerOperation::RemoveProgram]{assert!(!verified(recovery,role));}
            assert_eq!((size_of::<Report>(),size_of::<RawInputs>(),size_of::<RemovalOriginalData>()),(360,384,72));
            assert!(size_of::<RemovalPeer<'static>>()<65536); // task handle only
            assert!(RemovalPeer::project_owned_upper_bound().unwrap()<=196608); // native sizeof, no peer entry
        }
        #[test]
        fn peer_phase_ledger_rejects_cross_slot_replay_and_false_consumption(){
            let input=binding();let old=Report{version:1,role:2,operation:1,last:5,..Report::default()};
            let mut raw=old;raw.calls=1;raw.returned=1;raw.cf_states[0]=2;
            assert!(report_shape(raw,old,&input));assert!(returned_transition(raw,old,RemovalNativePhase::StaticUrl,Some(0)));
            for kind in 0..7{let mut bad=raw;match kind{0=>bad.cf_states[1]=2,1=>bad.fd_states[0]=2,
                2=>bad.returned=0,3=>bad.calls=2,4=>bad.cf_states[0]=3,5=>bad.cf_states[0]=0,_=>bad.cf_states[0]=1}
                assert!(!returned_transition(bad,old,RemovalNativePhase::StaticUrl,Some(0)));}
            let mut closed=raw;closed.calls=2;closed.returned=2;closed.cf_states[0]=4;
            assert!(returned_transition(closed,raw,RemovalNativePhase::Release,Some(0)));
            assert!(!returned_transition(closed,closed,RemovalNativePhase::Release,Some(0)));
            let mut unknown=closed;unknown.cf_states[0]=5;unknown.unknown=1;unknown.failed=1;unknown.first_code=12;unknown.first_failure=5;
            assert!(report_shape(unknown,raw,&input));assert!(returned_transition(unknown,raw,RemovalNativePhase::Release,Some(0)));
            unknown.closed=1;assert!(!report_shape(unknown,raw,&input));
            let mut pending=old;pending.calls=1;pending.returned=1;
            assert!(returned_transition(pending,old,RemovalNativePhase::Accept,Some(1)));
            assert!(!returned_transition(pending,old,RemovalNativePhase::Socket,Some(1)));
            let mut ledger=Ledger::new(RemovalPeerRole::App,&input);let mut observed=Vec::new();
            let mut current=||true;let mut gate=|point|{observed.push(point);Decision::Proceed};
            let mut hook=Hook{ledger:&mut ledger,binding:&input,current:&mut current,gate:&mut gate,operation:RemovalPeerOperation::Source};
            assert_eq!(unsafe{checkpoint((&mut hook as *mut Hook<'_>).cast(),1,2,0,0,&old)},1);
            assert_eq!(unsafe{checkpoint((&mut hook as *mut Hook<'_>).cast(),0,2,0,0,&raw)},1);
            assert_eq!(hook.ledger.report.cf_states[0],2);assert_eq!(hook.ledger.report.returned,1);
            assert_eq!(unsafe{checkpoint((&mut hook as *mut Hook<'_>).cast(),0,2,0,0,&raw)},-1);
            assert!(hook.ledger.unknown);assert_eq!(hook.ledger.report.cf_states[0],2);drop(hook);
            assert_eq!(observed.len(),2);
            let valid=report(RemovalPeerRole::App);
            for bad in [Report{peer_uid:501,..valid},Report{role:1,..valid},Report{watch_ready:0,exit_observed:1,..valid},
                Report{first_code:1,..valid},Report{last:4,..valid},Report{frame_index:5,..valid}]{assert!(!report_shape(bad,valid,&input));}

            // Exercise the actual C terminal-POST decision as DATA, not a
            // duplicated Rust rule or a live socket/process-exit qualification.
            unsafe extern "C"{
                fn mrk_removal_peer_ack_post_data(role:u32,index:u32,direction:u32,
                    expected:u32,before:u32,returned:i64,watch_result:i32)->i32;
            }
            let post=|role,index,direction,expected,before,returned,watch_result|unsafe{
                mrk_removal_peer_ack_post_data(role,index,direction,expected,before,returned,watch_result)};
            for (expected,before,returned) in [(5,0,5),(4100,0,4100),(4100,4097,3)]{
                // Whole terminal sends admit either the same watch pending or
                // the real NOTE_EXIT that arrived immediately after the send.
                for watch in [0,1]{assert_eq!(post(1,3,1,expected,before,returned,watch),1);}
                for watch in [-1,-2,2,i32::MAX]{assert_eq!(post(1,3,1,expected,before,returned,watch),-1);}
            }
            for (role,index,direction,expected,before,returned) in [
                (2,3,1,5,0,5),(0,3,1,5,0,5),(1,0,1,5,0,5),(1,1,1,5,0,5),
                (1,2,1,5,0,5),(1,4,1,5,0,5),(1,3,2,5,0,5),(1,3,0,5,0,5),
                (1,3,1,5,0,4),(1,3,1,4100,4097,2),(1,3,1,5,0,0),(1,3,1,5,0,-1),
                (1,3,1,5,0,6),(1,3,1,5,5,1),(1,3,1,5,6,1),(1,3,1,4,0,4),
                (1,3,1,4101,0,4101),(1,3,1,0,0,1),(1,3,1,5,0,i64::MAX),
            ]{
                // Not a complete Parent/Ack send: no terminal exception, even
                // when DATA alleges exit. The actual caller keeps p_recheck.
                for watch in [-1,0,1]{assert_eq!(post(role,index,direction,expected,before,returned,watch),0);}
            }
            let mut ack=report(RemovalPeerRole::Parent);
            ack.operation=RemovalPeerOperation::PollFrame as u32;
            ack.frame_index=3;ack.frame_started=1;ack.frame_offset=5;
            let mut exited=ack;exited.calls+=1;exited.returned+=1;exited.exit_observed=1;
            assert!(report_shape(exited,ack,&input));
            assert!(returned_transition(exited,ack,RemovalNativePhase::WatchPoll,Some(2)));
            let mut completed=exited;completed.frame_index=4;completed.frame_started=0;completed.frame_size=5;
            assert!(report_shape(completed,exited,&input));
            assert!(returned_transition(completed,exited,RemovalNativePhase::Boundary,None));
            let mut final_ledger=Ledger::new(RemovalPeerRole::Parent,&input);final_ledger.report=completed;
            assert!(!final_ledger.authenticated()); // A departed guest is not live authority.
            assert!(final_ledger.custody().actual_exit_observed);
        }
        #[test]
        fn peer_actual_challenge_copy_and_post_precede_single_cutoff_factory(){
            let mut good=core();let mut native=Fake::new();
            let proof=good.admit_challenge(decode,&mut ||true,&mut |_|Decision::Proceed,&mut native).unwrap();
            assert_eq!((native.copies,native.runs),(1,2));assert!(proof.same_original(good.cutoff.as_ref().unwrap()));
            assert!(good.admit_challenge(decode,&mut ||true,&mut |_|Decision::Proceed,&mut native).is_err());
            assert_eq!((native.copies,native.runs),(1,2));
            for mode in 0..8{
                let mut bad=core();let mut native=Fake::new();let decoder=match mode{0=>reject,1=>panics,_=>decode};
                match mode{2=>bad.binding.source[0]^=1,3=>bad.ledger.report.stage=3,4=>native.frame[3]=2,
                    5=>native.late_copy=true,6=>bad.ledger.report.watch_ready=0,_=>{}}
                let mut gate=|point|if mode==7&&matches!(point,RemovalPeerCheckpoint::Returned{phase:RemovalPeerPhase::CopyFrame,..}){Decision::Stop}else{Decision::Proceed};
                assert!(bad.admit_challenge(decoder,&mut ||true,&mut gate,&mut native).is_err());
                assert!(bad.cutoff.is_none());assert!(native.copies<=1);assert!(bad.pointer.is_some());
                if mode==5{assert!(bad.copied);assert!(!bad.decoder_called);}
            }
            let mut changed=core();let mut native=Fake::new();
            assert!(changed.admit_challenge(decode,&mut ||false,&mut |_|Decision::Proceed,&mut native).is_err());
            assert_eq!(native.copies,0);assert!(changed.cutoff.is_none());
        }
        #[test]
        fn peer_consuming_original_is_recorded_before_late_post_and_never_retried(){
            let mut core=Core::new(RemovalPeerRole::App,binding());let mut native=Fake::new();
            let mut gate=|point|if matches!(point,RemovalPeerCheckpoint::Returned{phase:RemovalPeerPhase::Allocate,..}){Decision::Stop}else{Decision::Proceed};
            assert!(!core.allocate(&raw_input(),&mut ||true,&mut gate,&mut native));
            assert_eq!(native.allocations,1);assert!(core.pointer.is_some());assert_eq!(core.ledger.cell,CellCustody::Owned);
            let first=core.ledger.first;
            core.close_called=true;core.ledger.report.operation=9;core.ledger.report.closed=1;
            core.ledger.report.fd_states=[4;3];core.ledger.report.cf_states=[4;24];
            native.late_retire=true;
            assert!(core.retire(&mut ||true,&mut |_|Decision::Proceed,&mut native).is_err());
            assert!(core.pointer.is_none());assert_eq!(core.ledger.cell,CellCustody::Consumed);assert_eq!(core.ledger.first,first);
            assert_eq!(native.retires,1);
            assert!(core.retire(&mut ||true,&mut |_|Decision::Proceed,&mut native).is_err());assert_eq!(native.retires,1);
            let mut uncertain=Core::new(RemovalPeerRole::Parent,binding());uncertain.pointer=Some(NonNull::dangling());
            uncertain.close_called=true;uncertain.ledger.cell=CellCustody::Owned;uncertain.ledger.report=report(RemovalPeerRole::Parent);
            uncertain.ledger.report.fd_states[1]=5;uncertain.ledger.report.unknown=1;
            let mut native=Fake::new();assert!(uncertain.retire(&mut ||true,&mut |_|Decision::Proceed,&mut native).is_err());
            assert_eq!(native.retires,0);assert!(uncertain.pointer.is_some());
            let mut absent=Core::new(RemovalPeerRole::App,binding());let mut native=Fake::new();native.allocate_null=true;
            assert!(!absent.allocate(&raw_input(),&mut ||true,&mut |_|Decision::Proceed,&mut native));
            assert_eq!(absent.ledger.cell,CellCustody::Absent);assert!(absent.pointer.is_none());
            let mut clock=Core::new(RemovalPeerRole::App,binding());let mut native=Fake::new();
            native.now=Some(binding().work);assert!(!clock.allocate(&raw_input(),&mut ||true,&mut |_|Decision::Proceed,&mut native));
            assert_eq!(native.allocations,0);
        }
    }
}
#[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
pub use peer::{DecodeRemovalChallenge,RemovalChallengeData,RemovalTargetData,RemovalSourceOriginals,
    RemovalOriginalData,RemovalPeerRole,RemovalNativePhase,RemovalPeerOperation,RemovalPeerPhase,RemovalPeerCustody,
    RemovalPeerCheckpoint,RemovalPeerProgress,RemovalPeerError,RemovalPeer,RemovalPeerRetired,
    REMOVAL_FRAME_BYTES,REMOVAL_BORROWED_ORIGINALS};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cutoff_preserves_same_original_not_equal_data_and_fixed_endpoints() {
        #[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
        super::confirmation::check_retirement_data();
        #[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
        super::notice::check_notice_data();
        let first = ParentCutoff::test_original(5).unwrap();
        let cloned = first.clone();
        let separate = ParentCutoff::test_original(5).unwrap();
        assert!(first.same_original(&cloned));
        assert!(!first.same_original(&separate));
        assert_eq!((first.start_ns(), first.work_ns(), first.hard_ns()),
            (5, 5 + PARENT_WORK_NS, 5 + PARENT_HARD_NS));
        drop(first);
        assert_eq!(cloned.hard_ns(), 5 + PARENT_HARD_NS);
        assert!(ParentCutoff::test_original(0).is_none());
        assert!(ParentCutoff::test_original(u64::MAX).is_none());
        assert!(ParentCutoff::test_original(MAX_RAW - PARENT_HARD_NS).is_some());
        assert!(ParentCutoff::test_original(MAX_RAW - PARENT_HARD_NS + 1).is_none());
        for (request_id, root_nonce, work, hard) in [
            ([0; 16], [2; 16], 5 + PARENT_WORK_NS, 5 + PARENT_HARD_NS),
            ([1; 16], [0; 16], 5 + PARENT_WORK_NS, 5 + PARENT_HARD_NS),
            ([1; 16], [2; 16], 5 + PARENT_WORK_NS - 1, 5 + PARENT_HARD_NS),
            ([1; 16], [2; 16], 5 + PARENT_WORK_NS, 5 + PARENT_HARD_NS + 1),
        ] {
            assert!(ParentCutoff::from_authenticated_original(AuthenticatedCutoffOriginal {
                request_id, root_nonce, start: 5, work, hard,
            }).is_none());
        }
        assert!(ParentCutoff::project_owned_upper_bound().unwrap() <= 128);
    }
}


// Fixed native hint, deliberately outside peer/confirmation authority.
#[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
mod notice {
    use std::{ffi::c_void,marker::PhantomData,mem::size_of,panic::{catch_unwind,AssertUnwindSafe},
        ptr::NonNull,rc::Rc,sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}},task::{Context,Poll,Waker},time::Instant};
    #[repr(C)]
    #[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
    struct Facts {version:u32,started:u32,registered:u32,active:u32,remove_attempted:u32,removed:u32,
        observer_destroyed:u32,unknown:u32,refs:[u32;2]}
    unsafe extern "C" {
        fn mrk_removal_notice_bytes()->usize;
        fn mrk_removal_notice_reserve(context:*mut c_void,hint:unsafe extern "C" fn(*mut c_void,*const u8))->*mut c_void;
        fn mrk_removal_notice_start(original:*mut c_void,out:*mut Facts)->i32;
        fn mrk_removal_notice_retire(original:*mut c_void,out:*mut Facts)->i32;
        fn mrk_removal_notice_post(text:*const u8,size:usize)->i32;
    }
    struct Inbox {pending:Option<[u8;16]>,waker:Option<Waker>}
    /// Single original inbox, not a message queue or a capability. Notification
    /// loss/duplicates/contention may discard hints; the finite socket attempt
    /// remains the only source of actual protocol progress.
    pub struct RemovalNoticeInbox {inner:Mutex<Inbox>,closed:AtomicBool,unknown:AtomicBool}
    impl RemovalNoticeInbox {
        pub fn reserved()->Arc<Self>{Arc::new(Self{inner:Mutex::new(Inbox{pending:None,waker:None}),
            closed:AtomicBool::new(false),unknown:AtomicBool::new(false)})}
        fn offer(&self,id:[u8;16]) {
            if id==[0;16]||self.closed.load(Ordering::SeqCst)||self.unknown.load(Ordering::SeqCst){return;}
            let Ok(mut inbox)=self.inner.try_lock()else{return;}; // never block AppKit
            if inbox.pending.is_some(){return;}
            inbox.pending=Some(id);let wake=inbox.waker.take();drop(inbox);
            if let Some(waker)=wake{waker.wake();}
        }
        pub fn poll_hint(&self,cx:&mut Context<'_>)->Poll<Option<[u8;16]>> {
            if self.closed.load(Ordering::SeqCst)||self.unknown.load(Ordering::SeqCst){return Poll::Ready(None);}
            let Ok(mut inbox)=self.inner.try_lock()else{return Poll::Pending;};
            if let Some(id)=inbox.pending.take(){return Poll::Ready(Some(id));}
            if inbox.waker.as_ref().is_none_or(|old|!old.will_wake(cx.waker())){inbox.waker=Some(cx.waker().clone());}
            Poll::Pending
        }
        pub fn closed(&self)->bool{self.closed.load(Ordering::SeqCst)}
        pub fn known(&self)->bool{!self.unknown.load(Ordering::SeqCst)}
        pub fn project_owned_upper_bound()->Option<usize>{size_of::<Self>().checked_add(2*size_of::<usize>())}
        fn finish(&self,known:bool) {
            self.closed.store(true,Ordering::SeqCst);if !known{self.unknown.store(true,Ordering::SeqCst);}
            if let Ok(mut inbox)=self.inner.try_lock(){inbox.pending=None;let wake=inbox.waker.take();drop(inbox);if let Some(waker)=wake{waker.wake();}}
            else{self.unknown.store(true,Ordering::SeqCst);}
        }
    }
    unsafe extern "C" fn hint(context:*mut c_void,id:*const u8) {
        if context.is_null()||id.is_null(){return;}
        // SAFETY: C owns no Rust allocation; the !Send original retains this
        // exact Arc until known observer destruction. Unknown Drop retains it.
        let inbox=unsafe{&*context.cast::<RemovalNoticeInbox>()};
        let result=catch_unwind(AssertUnwindSafe(||{
            let mut value=[0;16];unsafe{std::ptr::copy_nonoverlapping(id,value.as_mut_ptr(),16)};
            inbox.offer(value);
        }));
        if result.is_err(){inbox.unknown.store(true,Ordering::SeqCst);}
    }
    fn facts_valid(f:Facts)->bool {
        f.version==1&&[f.started,f.registered,f.active,f.remove_attempted,f.removed,f.observer_destroyed,f.unknown].iter().all(|v|*v<=1)
            &&f.refs.iter().all(|v|*v<=5)
            &&(f.registered==0||f.started==1&&f.removed==0)
            &&(f.observer_destroyed==0||f.refs[1]==4)
    }
    fn disabled_start_data(result:i32,f:Facts)->bool{
        // Native start0 has exactly these two known pre-registration returns:
        // center allocation nil, or retained center + observer allocation nil.
        // No observer was constructed; do NOT invent a dealloc callback.
        result==0&&facts_valid(f)&&f.started==1&&f.registered==0&&f.active==0
            &&f.remove_attempted==0&&f.removed==0&&f.observer_destroyed==0&&f.unknown==0
            &&matches!(f.refs,[4,0]|[2,4])
    }
    fn retired_data(f:Facts,original_observer_absent:bool)->bool{facts_valid(f)&&f.remove_attempted==1&&f.removed==1&&f.registered==0
        &&f.active==0&&f.unknown==0&&f.refs.iter().all(|v|matches!(*v,0|4))
        &&if original_observer_absent{f.observer_destroyed==0}else{f.refs[1]==4&&f.observer_destroyed==1}}
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum RemovalNoticeStart{Registered,DisabledKnown,Unknown}
    /// Main-thread-owned original. One retirement attempt; no cleanup in Drop.
    /// All ordinary app exit gates must also observe the main capture's return.
    pub struct RemovalNotice {pointer:Option<NonNull<c_void>>,inbox:Option<Arc<RemovalNoticeInbox>>,
        started:bool,disabled_known:bool,retire_attempted:bool,known:bool,facts:Facts,_main:PhantomData<Rc<()>>}
    impl RemovalNotice {
        pub fn project_owned_upper_bound()->Option<usize>{
            let native=unsafe{mrk_removal_notice_bytes()};if native==0||native>384{return None;}
            size_of::<Self>().checked_add(native)?.checked_add(RemovalNoticeInbox::project_owned_upper_bound()?)
        }
        pub fn reserve(inbox:&Arc<RemovalNoticeInbox>)->Option<Self>{
            Self::project_owned_upper_bound()?;
            let pointer=NonNull::new(unsafe{mrk_removal_notice_reserve(Arc::as_ptr(inbox).cast_mut().cast(),hint)})?;
            Some(Self{pointer:Some(pointer),inbox:Some(inbox.clone()),started:false,disabled_known:false,retire_attempted:false,
                known:true,facts:Facts{version:1,..Facts::default()},_main:PhantomData})
        }
        pub fn start(&mut self)->RemovalNoticeStart{
            if self.started||self.retire_attempted||!self.known{return RemovalNoticeStart::Unknown;}
            self.started=true;let Some(pointer)=self.pointer else{self.known=false;return RemovalNoticeStart::Unknown;};
            let result=unsafe{mrk_removal_notice_start(pointer.as_ptr(),&mut self.facts)};
            self.known=result>=0&&facts_valid(self.facts)&&self.facts.unknown==0;
            if self.known&&result==1&&self.facts.registered==1&&self.facts.refs==[2,2]{return RemovalNoticeStart::Registered;}
            self.disabled_known=disabled_start_data(result,self.facts);
            if self.disabled_known{return RemovalNoticeStart::DisabledKnown;}
            self.known=false;RemovalNoticeStart::Unknown
        }
        pub fn retire(&mut self,original_quit_end:Instant)->Result<(),()>{
            if self.retire_attempted||!self.known||Instant::now()>=original_quit_end{return Err(());}
            // Bind known absence to THIS preceding start0 (or this genuinely
            // never-started reserved cell), not just a final CLOSED enum.
            let observer_absent=self.disabled_known||(!self.started&&self.facts.refs==[0,0]);
            self.retire_attempted=true;let pointer=self.pointer.ok_or(())?;
            let result=unsafe{mrk_removal_notice_retire(pointer.as_ptr(),&mut self.facts)};
            if result==1{self.pointer=None;} // actual consume retained before final clock/data checks
            let known=result==1&&retired_data(self.facts,observer_absent)&&Instant::now()<original_quit_end;
            self.known=known;if let Some(inbox)=&self.inbox{inbox.finish(known);}
            if known&&self.inbox.as_ref().is_some_and(|inbox|inbox.known()){self.inbox.take();Ok(())}else{Err(())}
        }
        pub fn is_retired(&self)->bool{self.pointer.is_none()}
    }
    impl Drop for RemovalNotice {fn drop(&mut self){
        if self.pointer.is_some(){if let Some(inbox)=self.inbox.take(){
            inbox.finish(false);std::mem::forget(inbox); // native callback backing, NOT finality
        }}
    }}
    /// Only post the SOURCE-fixed name/id. Parent checks its own original work
    /// before/after this call. A successful void post conveys no delivery fact.
    pub fn post_removal_ready(request_id:&str)->bool{
        let bytes=request_id.as_bytes();if decode_id(bytes).is_none(){return false;}
        unsafe{mrk_removal_notice_post(bytes.as_ptr(),bytes.len())==1}
    }
    pub fn decode_removal_hint(text:&[u8])->Option<[u8;16]>{decode_id(text)}
    fn decode_id(text:&[u8])->Option<[u8;16]>{
        if text.len()!=32{return None;}
        fn half(b:u8)->Option<u8>{match b{b'0'..=b'9'=>Some(b-b'0'),b'a'..=b'f'=>Some(b-b'a'+10),_=>None}}
        let mut id=[0;16];for (i,out) in id.iter_mut().enumerate(){*out=half(text[2*i])?.checked_mul(16)?.checked_add(half(text[2*i+1])?)?;}
        (id!=[0;16]).then_some(id)
    }
    #[cfg(test)]
    pub(super) fn check_notice_data(){
        use std::task::Wake;struct NoWake;impl Wake for NoWake{fn wake(self:Arc<Self>) {}}
        let good=b"0123456789abcdef0123456789abcdef";let id=decode_id(good).unwrap();
        for bad in [b"".as_slice(),b"00000000000000000000000000000000",b"0123456789ABCDEF0123456789abcdef",b"0123456789abcdef0123456789abcde/",b"0123456789abcdef0123456789abcdef0"]{assert!(decode_id(bad).is_none());}
        let inbox=RemovalNoticeInbox::reserved();let waker=Waker::from(Arc::new(NoWake));let mut cx=Context::from_waker(&waker);
        assert!(inbox.poll_hint(&mut cx).is_pending());inbox.offer(id);inbox.offer([7;16]);
        assert_eq!(inbox.poll_hint(&mut cx),Poll::Ready(Some(id)));assert!(inbox.poll_hint(&mut cx).is_pending());
        inbox.finish(true);inbox.offer(id);assert_eq!(inbox.poll_hint(&mut cx),Poll::Ready(None));assert!(inbox.known());
        let done=Facts{version:1,started:1,remove_attempted:1,removed:1,observer_destroyed:1,refs:[4,4],..Facts::default()};
        assert!(retired_data(done,false));for bad in [Facts{active:1,..done},Facts{registered:1,..done},Facts{observer_destroyed:0,..done},
            Facts{unknown:1,..done},Facts{refs:[4,5],..done},Facts{remove_attempted:0,..done},Facts{removed:0,..done}]{assert!(!retired_data(bad,false));}
        for refs in [[4,0],[2,4]]{
            let refusal=Facts{version:1,started:1,refs,..Facts::default()};
            assert!(disabled_start_data(0,refusal));
            let closed=Facts{version:1,started:1,remove_attempted:1,removed:1,refs:if refs[1]==0{[4,0]}else{[4,4]},..Facts::default()};
            assert!(retired_data(closed,disabled_start_data(0,refusal)));
            assert!(!retired_data(closed,false)); // final CLOSED alone is NOT absence proof
            for changed in [Facts{unknown:1,..refusal},Facts{registered:1,..refusal},Facts{active:1,..refusal},
                Facts{refs:[2,2],..refusal},Facts{observer_destroyed:1,..refusal},Facts{remove_attempted:1,..refusal}]{
                assert!(!disabled_start_data(0,changed));
            }
            assert!(!disabled_start_data(-1,refusal));assert!(!disabled_start_data(1,refusal));
        }
        assert!(!retired_data(done,true)); // constructed observer still needs its actual dealloc
    }
}
#[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
pub use notice::{RemovalNotice,RemovalNoticeInbox,RemovalNoticeStart,decode_removal_hint,post_removal_ready};
