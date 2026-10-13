//! Thirteen fixed code originals and a separate parent-only worker gate.
//! No caller-selected filesystem walker, writes, unlock or Drop cleanup.
//! The tiny sibling launch adapter borrows only this same retained gate.
#![forbid(unsafe_code)]
use std::{mem::ManuallyDrop,os::fd::{AsFd,AsRawFd,BorrowedFd,OwnedFd},path::Path,time::Instant};
use nix::{fcntl::{self,AtFlags,OFlag},mount::MntFlags,
    sys::{stat::{self,FileStat,Mode,SFlag},statfs},unistd};
use crate::vault_filesystem::{Expected,Policy,SnapshotBook};

#[path = "../../../src-tauri/src/macos_install_fixed_paths.rs"]
mod paths;
pub const APP_BINARY:&str=paths::PAYLOAD_EXECUTABLE;
pub const HELPER_BINARY:&str=paths::VAULT_HELPER_BINARY;
pub const FIXED_CWD:&str=paths::PAYLOAD_HELPERS;
const APP:usize=10;const HELPER:usize=12;const COUNT:usize=13;
const NAMES:[&str;COUNT]=["/","Library","Application Support","MobileReleaseKit",paths::APP_NAME,"Contents","Helpers",paths::PAYLOAD_NAME,"Contents","MacOS","mobile-release-kit-desktop","Helpers","mrk-vault-keychain"];
const PARENT:[Option<usize>;COUNT]=[None,Some(0),Some(1),Some(2),Some(3),Some(4),Some(5),Some(6),Some(7),Some(8),Some(9),Some(8),Some(11)];
#[derive(Clone,Copy,PartialEq,Eq)]
enum State{Vacant,Opening,Held,NoHandle,Closing,Closed,Unknown}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Failure{Stopped,Ownership,Identity,Native,Unknown,Bounds}
#[derive(Clone,Copy,PartialEq,Eq)]
struct Identity{dev:i32,ino:u64,mode:u16,uid:u32,gid:u32,links:u16,size:i64,flags:u32,
    mtime:i64,mtime_ns:i64,ctime:i64,ctime_ns:i64}
impl Identity{fn of(s:&FileStat)->Self{Self{dev:s.st_dev,ino:s.st_ino,mode:s.st_mode,uid:s.st_uid,gid:s.st_gid,
    links:s.st_nlink,size:s.st_size,flags:s.st_flags,mtime:s.st_mtime,mtime_ns:s.st_mtime_nsec,ctime:s.st_ctime,ctime_ns:s.st_ctime_nsec}}}
struct Record{state:State,fd:Option<ManuallyDrop<OwnedFd>>,identity:Option<Identity>}
impl Record{fn new()->Self{Self{state:State::Vacant,fd:None,identity:None}}}
struct WorkerGate{
    original:Record,requested:bool,lock_entered:bool,lock_returned:bool,locked:bool,
    prepared:bool,spawn_entered:bool,postchecked:bool,retired:bool,unknown:bool,
}
impl WorkerGate{
    fn new()->Self{Self{original:Record::new(),requested:false,lock_entered:false,lock_returned:false,
        locked:false,prepared:false,spawn_entered:false,postchecked:false,retired:false,unknown:false}}
    fn quiescent(&self)->bool{!self.unknown && (!self.lock_entered || self.lock_returned)
        && !matches!(self.original.state,State::Opening|State::Closing|State::Unknown)}
    fn prepare_ready(&self)->bool{self.requested && self.locked && self.quiescent()
        && self.original.state==State::Held && !self.retired && !self.prepared && !self.spawn_entered}
    fn spawn_ready(&self)->bool{self.requested && self.locked && self.quiescent()
        && self.original.state==State::Held && !self.retired && self.prepared && !self.spawn_entered}
    fn settled(&self)->bool{
        self.quiescent() && self.original.fd.is_none() && if self.requested{
            self.retired && (!self.spawn_entered || self.postchecked)
                && matches!(self.original.state,State::Vacant|State::NoHandle|State::Closed)
        }else{self.original.state==State::Vacant && !self.lock_entered && !self.prepared && !self.spawn_entered}
    }
}
/// Observed parent-record DATA, never child admission or a release permit.
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
pub struct WorkerGateFacts{
    pub acquired:bool,pub spawn_entered:bool,pub postchecked:bool,pub closed:bool,pub unknown:bool,
}
#[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) struct WorkerHandoff{pub(crate) descriptor:i32,pub(crate) parent_pid:i32}
pub struct CodeOriginals{
    records:[Record;COUNT],gate:WorkerGate,acl:Option<SnapshotBook>,acl_entered:bool,acl_returned:bool,
    entered:bool,admitted:bool,closed:bool,first:Option<(Failure,Instant)>,
}
impl CodeOriginals{
    pub fn new()->Self{Self{records:std::array::from_fn(|_|Record::new()),gate:WorkerGate::new(),
        acl:None,acl_entered:false,acl_returned:false,entered:false,admitted:false,closed:false,first:None}}
    pub fn first_failure(&self)->Option<(Failure,Instant)>{
        match (self.first,self.acl.as_ref().and_then(SnapshotBook::first_failure)){
            (Some(a),Some((_,at))) if at<a.1=>Some((Failure::Native,at)),
            (None,Some((_,at)))=>Some((Failure::Native,at)),(a,_)=>a,
        }
    }
    fn fail(&mut self,p:Failure)->Failure{if self.first.is_none(){self.first=Some((p,Instant::now()));}p}
    fn check(stop:&mut dyn FnMut()->bool)->Result<(),Failure>{if stop(){Err(Failure::Stopped)}else{Ok(())}}
    fn fd(&self,i:usize)->Result<BorrowedFd<'_>,Failure>{
        self.records[i].fd.as_ref().map(|fd|(&**fd).as_fd()).ok_or(Failure::Unknown)
    }
    fn metadata(s:&FileStat,i:usize)->Result<Identity,Failure>{
        let leaf=matches!(i,APP|HELPER);
        if s.st_mode&SFlag::S_IFMT.bits()!=if leaf{SFlag::S_IFREG.bits()}else{SFlag::S_IFDIR.bits()}
            || s.st_uid!=0 || s.st_mode&0o7022!=0
            || leaf&&(s.st_mode&0o7777!=0o555 || s.st_gid!=0 || s.st_nlink!=1 || s.st_flags!=0
                || s.st_size<=0 || s.st_size>if i==HELPER{32*1024*1024}else{256*1024*1024}) {return Err(Failure::Ownership);}
        Ok(Identity::of(s))
    }
    fn named(&self,i:usize)->Result<FileStat,Failure>{
        match PARENT[i]{Some(p)=>stat::fstatat(self.fd(p)?,NAMES[i],AtFlags::AT_SYMLINK_NOFOLLOW),
            None=>stat::lstat(Path::new("/"))}.map_err(|_|Failure::Native)
    }
    fn inspect(&mut self,i:usize,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        Self::check(stop)?;
        let s=stat::fstat(self.fd(i)?).map_err(|_|Failure::Native)?;
        let actual=Self::metadata(&s,i)?;
        if self.records[i].identity!=Some(actual) || Self::metadata(&self.named(i)?,i)?!=actual{return Err(Failure::Identity);}
        Self::check(stop)?;
        let fs=statfs::fstatfs(self.fd(i)?).map_err(|_|Failure::Native)?;
        if fs.filesystem_type_name()!="apfs" || !fs.flags().contains(MntFlags::MNT_LOCAL)
            || fs.flags().intersects(MntFlags::MNT_UNION|MntFlags::MNT_AUTOMOUNTED|MntFlags::MNT_IGNORE_OWNERSHIP){return Err(Failure::Ownership);}
        Self::check(stop)?;
        if matches!(i,APP|HELPER){crate::no_xattrs(self.fd(i)?).map_err(|_|Failure::Native)?;Self::check(stop)?;}
        let expected=Expected{device:s.st_dev as u32 as u64,inode:s.st_ino,mode:u32::from(s.st_mode),
            owner:s.st_uid,group:s.st_gid,flags:s.st_flags};
        if !self.acl_returned{return Err(Failure::Unknown);}
        let (records,acl)=(&self.records,&mut self.acl);
        let fd=records[i].fd.as_ref().ok_or(Failure::Unknown)?;
        acl.as_mut().ok_or(Failure::Unknown)?
            .observe((&**fd).as_fd(),expected,if matches!(i,APP|HELPER){Policy::Empty}else{Policy::Ancestors},stop)
            .map_err(|_|Failure::Native)?;
        Self::check(stop)?;
        if Self::metadata(&stat::fstat(self.fd(i)?).map_err(|_|Failure::Native)?,i)?!=actual
            || Self::metadata(&self.named(i)?,i)?!=actual{return Err(Failure::Identity);}
        Ok(())
    }
    fn gate_fd(&self)->Result<BorrowedFd<'_>,Failure>{
        self.gate.original.fd.as_ref().map(|fd|(&**fd).as_fd()).ok_or(Failure::Unknown)
    }
    fn gate_named(&self)->Result<FileStat,Failure>{
        stat::fstatat(self.fd(3)?,paths::MAINTENANCE_GATE_NAME,AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_|Failure::Native)
    }
    fn gate_identity(s:&FileStat)->Result<Identity,Failure>{
        if s.st_mode!=(SFlag::S_IFREG.bits()|0o444) || s.st_uid!=0 || s.st_gid!=0 || s.st_nlink!=1
            || s.st_flags!=0 || s.st_size!=paths::MAINTENANCE_GATE_BYTES.len() as i64{return Err(Failure::Ownership);}
        Ok(Identity::of(s))
    }
    fn gate_parent(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        Self::check(stop)?;
        let s=stat::fstat(self.fd(3)?).map_err(|_|Failure::Native)?;
        if s.st_mode!=(SFlag::S_IFDIR.bits()|0o755) || s.st_uid!=0 || s.st_gid!=0
            || self.records[3].identity!=Some(Identity::of(&s))
            || Identity::of(&self.named(3)?)!=Identity::of(&s){return Err(Failure::Ownership);}
        crate::no_xattrs(self.fd(3)?).map_err(|_|Failure::Native)?;Self::check(stop)?;
        let expected=Expected{device:s.st_dev as u32 as u64,inode:s.st_ino,mode:u32::from(s.st_mode),
            owner:s.st_uid,group:s.st_gid,flags:s.st_flags};
        if !self.acl_returned{return Err(Failure::Unknown);}
        let (records,acl)=(&self.records,&mut self.acl);
        let original=records[3].fd.as_ref().ok_or(Failure::Unknown)?;
        acl.as_mut().ok_or(Failure::Unknown)?.observe((&**original).as_fd(),expected,Policy::Empty,stop)
            .map_err(|_|Failure::Native)?;
        Self::check(stop)?;
        if Identity::of(&stat::fstat(self.fd(3)?).map_err(|_|Failure::Native)?)!=Identity::of(&s)
            || Identity::of(&self.named(3)?)!=Identity::of(&s){return Err(Failure::Identity);}
        Ok(())
    }
    fn inspect_gate(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        Self::check(stop)?;
        if self.gate.original.state!=State::Held || self.gate.retired{return Err(Failure::Unknown);}
        let descriptor=self.gate_fd()?;
        if descriptor.as_raw_fd()<3 || fcntl::fcntl(descriptor,fcntl::FcntlArg::F_GETFD)
            .map_err(|_|Failure::Native)?!=fcntl::FdFlag::FD_CLOEXEC.bits(){return Err(Failure::Ownership);}
        let s=stat::fstat(descriptor).map_err(|_|Failure::Native)?;
        let expected_identity=Self::gate_identity(&s)?;
        if self.gate.original.identity!=Some(expected_identity) || Self::gate_identity(&self.gate_named()?)?!=expected_identity{
            return Err(Failure::Identity);
        }
        Self::check(stop)?;
        let fs=statfs::fstatfs(self.gate_fd()?).map_err(|_|Failure::Native)?;
        if fs.filesystem_type_name()!="apfs" || !fs.flags().contains(MntFlags::MNT_LOCAL)
            || fs.flags().intersects(MntFlags::MNT_UNION|MntFlags::MNT_AUTOMOUNTED|MntFlags::MNT_IGNORE_OWNERSHIP){return Err(Failure::Ownership);}
        Self::check(stop)?;crate::no_xattrs(self.gate_fd()?).map_err(|_|Failure::Native)?;Self::check(stop)?;
        let expected=Expected{device:s.st_dev as u32 as u64,inode:s.st_ino,mode:u32::from(s.st_mode),
            owner:s.st_uid,group:s.st_gid,flags:s.st_flags};
        if !self.acl_returned{return Err(Failure::Unknown);}
        let (gate,acl)=(&self.gate,&mut self.acl);
        let original=gate.original.fd.as_ref().ok_or(Failure::Unknown)?;
        acl.as_mut().ok_or(Failure::Unknown)?.observe((&**original).as_fd(),expected,Policy::Empty,stop)
            .map_err(|_|Failure::Native)?;
        Self::check(stop)?;
        // Caller admits this only before spawn or after actual child exit.
        // Fork shares file offsets; no seek/read is allowed during child use.
        if unistd::lseek(self.gate_fd()?,0,unistd::Whence::SeekSet).map_err(|_|Failure::Native)?!=0{return Err(Failure::Native);}
        Self::check(stop)?;
        let mut data=[0u8;31];
        let count=unistd::read(self.gate_fd()?,&mut data).map_err(|_|Failure::Native)?;
        if count!=paths::MAINTENANCE_GATE_BYTES.len() || &data[..count]!=paths::MAINTENANCE_GATE_BYTES{return Err(Failure::Identity);}
        Self::check(stop)?;
        if Self::gate_identity(&stat::fstat(self.gate_fd()?).map_err(|_|Failure::Native)?)?!=expected_identity
            || Self::gate_identity(&self.gate_named()?)?!=expected_identity{return Err(Failure::Identity);}
        Ok(())
    }
    fn open_gate(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        if !self.gate.requested || self.gate.original.state!=State::Vacant{return Err(Failure::Unknown);}
        self.gate_parent(stop)?;Self::check(stop)?;
        let expected=Self::gate_identity(&self.gate_named()?)?;Self::check(stop)?;
        self.gate.original.state=State::Opening;
        let opened=fcntl::openat(self.fd(3)?,paths::MAINTENANCE_GATE_NAME,
            OFlag::O_RDONLY|OFlag::O_NOFOLLOW|OFlag::O_NONBLOCK|OFlag::O_CLOEXEC,Mode::empty());
        match opened{
            Ok(fd)=>{self.gate.original.fd=Some(ManuallyDrop::new(fd));self.gate.original.state=State::Held;},
            Err(_)=>{self.gate.original.state=State::NoHandle;return Err(Failure::Native);}
        }
        self.gate.original.identity=Some(expected);self.inspect_gate(stop)
    }
    fn acquire_gate(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        self.open_gate(stop)?;Self::check(stop)?;
        self.gate.lock_entered=true;
        #[allow(deprecated)]
        let returned=fcntl::flock(self.gate_fd()?.as_raw_fd(),fcntl::FlockArg::LockSharedNonblock);
        self.gate.lock_returned=true;
        returned.map_err(|_|Failure::Native)?;self.gate.locked=true;
        Self::check(stop)?;self.inspect_gate(stop)
    }
    pub fn worker_gate_facts(&self)->WorkerGateFacts{WorkerGateFacts{
        acquired:self.gate.locked,spawn_entered:self.gate.spawn_entered,postchecked:self.gate.postchecked,
        closed:self.gate.original.state==State::Closed && self.gate.original.fd.is_none(),
        unknown:!self.gate.quiescent(),
    }}
    #[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
    pub(crate) fn prepare_worker_handoff(&mut self)->Result<WorkerHandoff,Failure>{
        let result=(||{
            if !self.admitted || self.closed || self.first_failure().is_some() || !self.gate.prepare_ready(){
                return Err(Failure::Unknown);
            }
            let descriptor=self.gate_fd()?.as_raw_fd();
            let parent_pid=i32::try_from(std::process::id()).map_err(|_|Failure::Bounds)?;
            if descriptor<3 || parent_pid<2{return Err(Failure::Ownership);}
            self.gate.prepared=true;Ok(WorkerHandoff{descriptor,parent_pid})
        })();
        if let Err(p)=result{self.fail(p);}result
    }
    #[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
    pub(crate) fn claim_worker_spawn(&mut self,expected:WorkerHandoff)->Result<BorrowedFd<'_>,Failure>{
        let valid=self.admitted && !self.closed && self.first_failure().is_none() && self.gate.spawn_ready()
            && self.gate_fd().is_ok_and(|fd|fd.as_raw_fd()==expected.descriptor)
            && i32::try_from(std::process::id()).ok()==Some(expected.parent_pid);
        if !valid{return Err(self.fail(Failure::Unknown));}
        self.gate.spawn_entered=true;self.gate_fd()
    }
    /// Cleanup-specific correspondence, not ordinary success-path recheck.
    /// The existing Child owner calls this ONLY after its real original exit.
    /// Prior application F does not forbid cleanup; unknown ACL state still does.
    pub fn check_worker_gate_after_exit(&mut self,expired:&mut dyn FnMut()->bool)->Result<(),Failure>{
        let result=(||{
            if !self.gate.requested || !self.gate.spawn_entered || !self.gate.locked || self.gate.postchecked
                || !self.gate.quiescent() || self.closed || !self.acl_returned{return Err(Failure::Unknown);}
            for i in 0..4{self.inspect(i,expired)?;}
            self.gate_parent(expired)?;self.inspect_gate(expired)?;Ok(())
        })();
        if let Err(p)=result{self.gate.unknown=true;self.fail(p);}else{self.gate.postchecked=true;}result
    }
    /// Separate last original. Actual child/native/pipe eligibility is owned by
    /// LookupBook; code/native settlement here deliberately excludes this gate.
    pub fn release_worker_gate(&mut self,expired:&mut dyn FnMut(Option<(Failure,Instant)>)->bool)->bool{
        if self.gate.settled(){return true;}
        if !self.code_settled() || !self.gate.quiescent()
            || self.gate.spawn_entered && !self.gate.postchecked{
            self.gate.unknown=true;self.fail(Failure::Unknown);return false;
        }
        if expired(self.first_failure()){self.gate.unknown=true;self.fail(Failure::Stopped);return false;}
        match self.gate.original.state{
            State::Vacant|State::NoHandle=>self.gate.retired=true,
            State::Held=>{
                self.gate.original.state=State::Closing;
                let original=self.gate.original.fd.take().map(ManuallyDrop::into_inner);
                match original.map(unistd::close){
                    Some(Ok(()))=>{self.gate.original.state=State::Closed;self.gate.retired=true;},
                    _=>{self.gate.original.state=State::Unknown;self.gate.unknown=true;self.fail(Failure::Unknown);}
                }
            },
            _=>{self.gate.unknown=true;self.fail(Failure::Unknown);}
        }
        if expired(self.first_failure()){self.gate.unknown=true;self.fail(Failure::Stopped);}
        self.gate.settled()
    }
    fn arm_acl(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        Self::check(stop)?;
        // new() is inert. The app reaches this arm only inside its original
        // registered blocking child after the start barrier; helper only after GO.
        // Entered without a usable returned frame is permanently Unknown.
        if self.acl_entered || self.acl.is_some(){return Err(Failure::Unknown);}
        self.acl_entered=true;
        self.acl=Some(SnapshotBook::new());
        if self.acl.as_ref().is_none_or(|acl|acl.retained_frame_bytes()==0){return Err(Failure::Unknown);}
        self.acl_returned=true;Self::check(stop)
    }
    fn open_code_original(&mut self,i:usize,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        Self::check(stop)?;let expected=Self::metadata(&self.named(i)?,i)?;Self::check(stop)?;
        let flags=OFlag::O_RDONLY|OFlag::O_NOFOLLOW|OFlag::O_NONBLOCK|OFlag::O_CLOEXEC
            |if matches!(i,APP|HELPER){OFlag::empty()}else{OFlag::O_DIRECTORY};
        self.records[i].state=State::Opening;
        let opened=match PARENT[i]{Some(p)=>fcntl::openat(self.fd(p)?,NAMES[i],flags,Mode::empty()),
            None=>fcntl::open(Path::new("/"),flags,Mode::empty())};
        match opened{Ok(fd)=>{self.records[i].fd=Some(ManuallyDrop::new(fd));self.records[i].state=State::Held;}
            Err(_)=>{self.records[i].state=State::NoHandle;return Err(Failure::Native);}}
        self.records[i].identity=Some(expected);self.inspect(i,stop)
    }
    fn acquire_inner(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        self.arm_acl(stop)?;
        for i in 0..COUNT{
            self.open_code_original(i,stop)?;
            if i==3 && self.gate.requested{self.acquire_gate(stop)?;}
        }
        Ok(())
    }
    pub fn acquire(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        if self.entered || self.closed{return Err(self.fail(Failure::Unknown));}self.entered=true;
        let result=self.acquire_inner(stop);if let Err(p)=result{self.fail(p);}else{self.admitted=true;}result
    }
    #[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
    pub fn acquire_for_helper_launch(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        if self.entered || self.closed || self.gate.requested{return Err(self.fail(Failure::Unknown));}
        self.gate.requested=true;self.acquire(stop)
    }
    pub fn recheck(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        if !self.admitted || self.closed || self.first.is_some(){return Err(self.fail(Failure::Unknown));}
        let result=(||{for i in 0..COUNT{self.inspect(i,stop)?;}Ok(())})();
        if let Err(p)=result{self.fail(p);}result
    }
    pub fn helper_fd(&self)->Result<BorrowedFd<'_>,Failure>{
        if !self.admitted || self.closed || self.first_failure().is_some(){return Err(Failure::Unknown);}self.fd(HELPER)
    }
    pub fn helper_bytes(&self)->Option<u64>{self.records[HELPER].identity.and_then(|id|u64::try_from(id.size).ok())}
    fn acl_settled(&self)->bool{match &self.acl{
        Some(acl)=>self.acl_entered && self.acl_returned && acl.settled(),
        None=>!self.acl_entered && !self.acl_returned,
    }}
    pub fn quiescent(&self)->bool{
        let native=match &self.acl{Some(acl)=>self.acl_entered && self.acl_returned && acl.quiescent(),
            None=>!self.acl_entered && !self.acl_returned};
        native && self.gate.quiescent() && self.records.iter().all(|r|!matches!(r.state,State::Opening|State::Closing|State::Unknown))
    }
    pub fn retained_bytes(&self)->Option<usize>{
        if !self.quiescent(){return None;}
        std::mem::size_of::<Self>().checked_add(self.acl.as_ref().map_or(0,SnapshotBook::retained_frame_bytes))
    }
    pub fn release(&mut self,expired:&mut dyn FnMut(Option<(Failure,Instant)>)->bool)->bool{
        self.release_code(expired) && self.gate.settled()
    }
    pub fn release_code(&mut self,expired:&mut dyn FnMut(Option<(Failure,Instant)>)->bool)->bool{
        if self.closed{return self.code_settled();}
        if self.acl_entered && !self.acl_returned{self.fail(Failure::Unknown);}
        let first=self.first;
        if self.acl_returned{if let Some(acl)=self.acl.as_mut(){
            let _=acl.release(&mut |failure|{
                let combined=match(first,failure){(Some(a),Some((_,at))) if at<a.1=>Some((Failure::Native,at)),
                    (None,Some((_,at)))=>Some((Failure::Native,at)),(a,_)=>a};expired(combined)
            });
        }}
        // Independent positive descriptors still close after one ACL/FD failure.
        // Unreturned/failed originals are never retried or reinterpreted as empty.
        for i in (0..COUNT).rev(){
            if self.records[i].state!=State::Held{continue;}
            if expired(self.first_failure()){self.fail(Failure::Stopped);break;}
            self.records[i].state=State::Closing;
            let original=self.records[i].fd.take().map(ManuallyDrop::into_inner);
            match original.map(unistd::close){Some(Ok(()))=>self.records[i].state=State::Closed,
                _=>{self.records[i].state=State::Unknown;self.fail(Failure::Unknown);}}
            if expired(self.first_failure()){self.fail(Failure::Stopped);break;}
        }
        self.closed=self.acl_settled() && self.records.iter().all(|r|matches!(r.state,State::Vacant|State::NoHandle|State::Closed));
        self.code_settled()
    }
    pub fn code_settled(&self)->bool{self.closed && self.acl_settled()
        && self.records.iter().all(|r|r.fd.is_none() && matches!(r.state,State::Vacant|State::NoHandle|State::Closed))}
    pub fn settled(&self)->bool{self.code_settled() && self.gate.settled()}
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn prearm_and_pre_go_stop_have_no_native_allocation(){
        let mut original=CodeOriginals::new();
        assert!(!original.acl_entered && !original.acl_returned && original.acl.is_none());
        assert_eq!(original.retained_bytes(),Some(std::mem::size_of::<CodeOriginals>()));
        assert_eq!(original.acquire(&mut ||true),Err(Failure::Stopped));
        assert!(!original.acl_entered && original.acl.is_none());
        assert!(original.release(&mut |_|false));assert!(original.settled());
    }
    #[cfg(not(any(feature="vault-helper",feature="android-registration-helper")))]
    #[test]
    fn parent_pre_stop_retires_only_an_inert_gate_and_cannot_reenter(){
        let mut original=CodeOriginals::new();
        assert!(original.gate.settled() && !original.gate.requested);
        assert_eq!(original.acquire_for_helper_launch(&mut ||true),Err(Failure::Stopped));
        assert!(original.gate.requested && !original.acl_entered && original.acl.is_none());
        assert!(!original.gate.settled());
        assert!(original.release_code(&mut |_|false));
        assert!(original.code_settled() && !original.settled());
        assert!(original.release_worker_gate(&mut |_|false) && original.settled());
        let first=original.first_failure();
        assert_eq!(original.acquire_for_helper_launch(&mut ||panic!("no new admission")),Err(Failure::Unknown));
        assert_eq!(original.first_failure(),first);
    }
    #[test]
    fn prepare_and_spawn_are_distinct_one_shot_state_claims(){
        // State DATA only; a Held tag here never fabricates a live descriptor.
        let mut gate=WorkerGate::new();
        assert!(!gate.prepare_ready() && !gate.spawn_ready());
        gate.requested=true;gate.original.state=State::Held;
        gate.lock_entered=true;gate.lock_returned=true;gate.locked=true;
        assert!(gate.prepare_ready() && !gate.spawn_ready());
        gate.prepared=true;assert!(!gate.prepare_ready() && gate.spawn_ready());
        gate.spawn_entered=true;assert!(!gate.prepare_ready() && !gate.spawn_ready());
        gate.spawn_entered=false;gate.unknown=true;assert!(!gate.spawn_ready());
        gate.unknown=false;gate.lock_returned=false;assert!(!gate.spawn_ready());
    }
    #[test]
    fn code_settlement_never_implies_gate_postcheck_or_unknown_close_finality(){
        for missing_postcheck in [false,true]{
            let mut original=CodeOriginals::new();original.closed=true;
            original.gate.requested=true;original.gate.spawn_entered=missing_postcheck;
            original.gate.original.state=State::Held; // Deliberately no descriptor.
            assert!(original.code_settled() && !original.settled());
            assert!(!original.release_worker_gate(&mut |_|false));
            assert!(!original.settled() && original.worker_gate_facts().unknown);
            assert_eq!(original.retained_bytes(),None);
            let first=original.first_failure();
            assert!(!original.release_worker_gate(&mut |_|panic!("unknown close is never retried")));
            assert_eq!(original.first_failure(),first);
        }
        let mut original=CodeOriginals::new();original.closed=true;original.gate.requested=true;
        assert!(!original.release_worker_gate(&mut |_|true));
        assert!(!original.release_worker_gate(&mut |_|panic!("expired cleanup cannot reopen")));
        assert_eq!(original.retained_bytes(),None);
    }
    #[test]
    fn even_a_closed_spawned_gate_requires_its_actual_postcheck(){
        let mut gate=WorkerGate::new();gate.requested=true;gate.retired=true;
        gate.original.state=State::Closed;gate.spawn_entered=true;
        assert!(!gate.settled());gate.postchecked=true;assert!(gate.settled());
        gate.unknown=true;assert!(!gate.settled());
    }
    #[test]
    fn cleanup_gate_correspondence_does_not_erase_a_previous_failure(){
        let mut original=CodeOriginals::new();let first=Instant::now();
        original.first=Some((Failure::Ownership,first));
        // Inert missing originals refuse before native entry; prior F remains.
        assert_eq!(original.check_worker_gate_after_exit(&mut ||panic!("no admitted original")),Err(Failure::Unknown));
        assert_eq!(original.first_failure(),Some((Failure::Ownership,first)));
        assert!(original.worker_gate_facts().unknown && !original.settled());
    }
    #[test]
    fn an_entered_unreturned_native_arm_is_never_empty_or_settled(){
        let mut original=CodeOriginals::new();original.entered=true;original.acl_entered=true;
        assert!(!original.quiescent());assert_eq!(original.retained_bytes(),None);
        assert!(!original.release(&mut |_|false));assert!(!original.settled());
        assert!(original.acl.is_none() && original.acl_entered && !original.acl_returned);
        assert_eq!(original.first_failure().map(|f|f.0),Some(Failure::Unknown));
    }
}

// Explicit ignored native control only. Absent from shipping app/helper graphs
// and ordinary DATA-only test selection; Root must admit its original owner.
#[cfg(all(test,debug_assertions,feature="installed-observation",
    not(any(feature="vault-helper",feature="android-registration-helper"))))]
#[path="vault_helper_gate_custody.rs"]
mod gate_custody_control;
