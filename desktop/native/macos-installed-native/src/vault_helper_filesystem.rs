//! Thirteen fixed installed code originals shared by app/helper admission, not a
//! caller-selected filesystem walker. No writes, execution or Drop cleanup.
#![forbid(unsafe_code)]
use std::{mem::ManuallyDrop,os::fd::{AsFd,BorrowedFd,OwnedFd},path::Path,time::Instant};
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
pub struct CodeOriginals{
    records:[Record;COUNT],acl:Option<SnapshotBook>,acl_entered:bool,acl_returned:bool,
    entered:bool,admitted:bool,closed:bool,first:Option<(Failure,Instant)>,
}
impl CodeOriginals{
    pub fn new()->Self{Self{records:std::array::from_fn(|_|Record{state:State::Vacant,fd:None,identity:None}),
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
    fn acquire_inner(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        Self::check(stop)?;
        // new() is inert. The app reaches this arm only inside its original
        // registered blocking child after the start barrier; helper only after GO.
        // Entered without a usable returned frame is permanently Unknown.
        if self.acl_entered || self.acl.is_some(){return Err(Failure::Unknown);}
        self.acl_entered=true;
        self.acl=Some(SnapshotBook::new());
        if self.acl.as_ref().is_none_or(|acl|acl.retained_frame_bytes()==0){return Err(Failure::Unknown);}
        self.acl_returned=true;
        Self::check(stop)?;
        for i in 0..COUNT{
            Self::check(stop)?;let expected=Self::metadata(&self.named(i)?,i)?;Self::check(stop)?;
            let flags=OFlag::O_RDONLY|OFlag::O_NOFOLLOW|OFlag::O_NONBLOCK|OFlag::O_CLOEXEC
                |if matches!(i,APP|HELPER){OFlag::empty()}else{OFlag::O_DIRECTORY};
            self.records[i].state=State::Opening;
            let opened=match PARENT[i]{Some(p)=>fcntl::openat(self.fd(p)?,NAMES[i],flags,Mode::empty()),
                None=>fcntl::open(Path::new("/"),flags,Mode::empty())};
            match opened{Ok(fd)=>{self.records[i].fd=Some(ManuallyDrop::new(fd));self.records[i].state=State::Held;}
                Err(_)=>{self.records[i].state=State::NoHandle;return Err(Failure::Native);}}
            self.records[i].identity=Some(expected);self.inspect(i,stop)?;
        }
        Ok(())
    }
    pub fn acquire(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Failure>{
        if self.entered || self.closed{return Err(self.fail(Failure::Unknown));}self.entered=true;
        let result=self.acquire_inner(stop);if let Err(p)=result{self.fail(p);}else{self.admitted=true;}result
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
        native && self.records.iter().all(|r|!matches!(r.state,State::Opening|State::Closing|State::Unknown))
    }
    pub fn retained_bytes(&self)->Option<usize>{
        if !self.quiescent(){return None;}
        std::mem::size_of::<Self>().checked_add(self.acl.as_ref().map_or(0,SnapshotBook::retained_frame_bytes))
    }
    pub fn release(&mut self,expired:&mut dyn FnMut(Option<(Failure,Instant)>)->bool)->bool{
        if self.closed{return self.settled();}
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
        self.settled()
    }
    pub fn settled(&self)->bool{self.closed && self.acl_settled()
        && self.records.iter().all(|r|r.fd.is_none() && matches!(r.state,State::Vacant|State::NoHandle|State::Closed))}
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
    #[test]
    fn an_entered_unreturned_native_arm_is_never_empty_or_settled(){
        let mut original=CodeOriginals::new();original.entered=true;original.acl_entered=true;
        assert!(!original.quiescent());assert_eq!(original.retained_bytes(),None);
        assert!(!original.release(&mut |_|false));assert!(!original.settled());
        assert!(original.acl.is_none() && original.acl_entered && !original.acl_returned);
        assert_eq!(original.first_failure().map(|f|f.0),Some(Failure::Unknown));
    }
}
