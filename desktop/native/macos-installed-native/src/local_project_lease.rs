//! One local-release project lease, never a pathname or generic lock provider.
//! Parent source custody validates the named ancestry; this book retains a dup
//! of that SAME open-file-description. Each fixed child inherits the same OFD.
//! Unknown consumes the sole close attempt and never earns quota credit.
use std::{mem::ManuallyDrop,os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd}};
use nix::{fcntl::{fcntl,FcntlArg,FdFlag,OFlag},sys::stat::fstat,unistd};
use crate::local_keychain_wire::{ProjectRoot,LeaseFacts};
#[derive(Clone,Copy,PartialEq,Eq)]
pub enum Failure { Refused, Busy, Native, Unknown }
#[derive(Clone,Copy,PartialEq,Eq)]
enum State { New, Acquiring, Held, Closing, Closed, Unknown }
pub struct ProjectLease {fd:Option<ManuallyDrop<OwnedFd>>,root:Option<ProjectRoot>,state:State,failed:bool}
impl ProjectLease {
    pub fn new()->Self {Self{fd:None,root:None,state:State::New,failed:false}}
    pub fn enter(&mut self,original:BorrowedFd<'_>,mut root:ProjectRoot)->Result<(),Failure>{
        if self.state!=State::New {return Err(Failure::Refused);}
        self.state=State::Acquiring;
        let attempt=(||{
            if !root.valid() || root.descriptor!=original.as_raw_fd() as u32 || root.uid!=unistd::geteuid().as_raw()
                || unistd::getuid()!=unistd::geteuid() || unistd::getgid()!=unistd::getegid() {return Err(Failure::Refused);}
            check(original,root,true)?;
            let raw=fcntl(original,FcntlArg::F_DUPFD_CLOEXEC(3)).map_err(|_|Failure::Native)?;
            // Register before metadata, quota or late-failure observations.
            self.fd=Some(ManuallyDrop::new(unsafe{OwnedFd::from_raw_fd(raw)}));
            root.descriptor=raw as u32;self.root=Some(root);
            if !root.valid(){return Err(Failure::Refused);}
            let fd=self.fd.as_ref().unwrap().as_fd();check(fd,root,true)?;
            let result=unsafe{nix::libc::flock(fd.as_raw_fd(),nix::libc::LOCK_EX|nix::libc::LOCK_NB)};
            let errno=if result == -1 {nix::errno::Errno::last()} else {nix::errno::Errno::UnknownErrno};
            if result!=0{return Err(if errno==nix::errno::Errno::EWOULDBLOCK {Failure::Busy}else{Failure::Unknown});}
            self.state=State::Held;check(fd,root,true)?;Ok(())
        })();
        if attempt.is_err(){self.failed=true;if self.fd.is_none(){self.state=State::Closed;}}
        attempt
    }
    pub fn checked(&self)->Result<(BorrowedFd<'_>,ProjectRoot),Failure>{
        if self.state!=State::Held || self.failed {return Err(Failure::Unknown);}
        let root=self.root.ok_or(Failure::Unknown)?;
        let fd=self.fd.as_ref().ok_or(Failure::Unknown)?.as_fd();check(fd,root,true)?;Ok((fd,root))
    }
    pub fn active_count(&self)->usize {usize::from(!matches!(self.state,State::New|State::Closed))}
    pub fn close(&mut self)->bool {
        if self.state==State::Closed {return true;}
        if self.state==State::New {self.state=State::Closed;return true;}
        if self.state==State::Closing || self.state==State::Unknown {return false;}
        // Original metadata failure does not authorize consumption of a reused FD.
        let same=self.root.zip(self.fd.as_ref()).is_some_and(|(root,fd)|check(fd.as_fd(),root,true).is_ok());
        if !same {self.state=State::Unknown;self.failed=true;return false;}
        self.state=State::Closing;
        let fd=self.fd.take().map(ManuallyDrop::into_inner);
        match fd.map(unistd::close){Some(Ok(()))=>self.state=State::Closed,_=>{self.state=State::Unknown;self.failed=true;}}
        self.state==State::Closed
    }
    pub fn settled(&self)->bool {self.state==State::Closed && self.fd.is_none()}
}
fn check(fd:BorrowedFd<'_>,root:ProjectRoot,cloexec:bool)->Result<(),Failure>{
    if !root.valid() || fd.as_raw_fd() as u32!=root.descriptor {return Err(Failure::Refused);}
    let s=fstat(fd).map_err(|_|Failure::Native)?;
    if (s.st_dev as u64,s.st_ino as u64,s.st_mode as u32,s.st_uid,s.st_gid)!=(root.device,root.inode,root.mode,root.uid,root.gid)
        || s.st_flags!=0 {return Err(Failure::Refused);}
    let flags=fcntl(fd,FcntlArg::F_GETFD).map_err(|_|Failure::Native)?;
    let access=fcntl(fd,FcntlArg::F_GETFL).map_err(|_|Failure::Native)?;
    if (flags & nix::libc::FD_CLOEXEC!=0)!=cloexec || access & nix::libc::O_ACCMODE!=OFlag::O_RDONLY.bits(){return Err(Failure::Refused);}
    Ok(())
}
/// The fixed launch holds the original borrow through spawn. This is child-only
/// scalar work; no allocation, locks, path, dup2, logging or parent flag change.
unsafe extern "C" {fn mrk_local_lease_child_inherit(fd:i32,dev:u64,ino:u64,mode:u32,uid:u32,gid:u32)->i32;}
pub unsafe fn inherit(original:BorrowedFd<'_>,root:ProjectRoot)->std::io::Result<()> {
    if original.as_raw_fd() as u32!=root.descriptor{return Err(std::io::Error::from_raw_os_error(nix::libc::EPERM));}
    let result=unsafe{mrk_local_lease_child_inherit(original.as_raw_fd(),root.device,root.inode,root.mode,root.uid,root.gid)};
    if result==0{Ok(())}else{Err(std::io::Error::from_raw_os_error(result))}
}

#[cfg(feature="vault-helper")]
pub struct InheritedLease {fd:Option<ManuallyDrop<OwnedFd>>,root:Option<ProjectRoot>,facts:LeaseFacts,unknown:bool}
#[cfg(feature="vault-helper")]
impl InheritedLease {
    pub fn new()->Self{Self{fd:None,root:None,facts:LeaseFacts::default(),unknown:false}}
    pub fn admit(&mut self,root:ProjectRoot)->bool {
        if self.root.is_some() || self.fd.is_some() || self.unknown || !root.valid()
            || root.uid!=unistd::geteuid().as_raw(){self.unknown=true;return false;}
        // Borrow first. The dedicated helper does not claim/close a number that
        // failed inherited-root identity and exact descriptor-role validation.
        let borrowed=unsafe{BorrowedFd::borrow_raw(root.descriptor as i32)};
        if check(borrowed,root,false).is_err(){self.unknown=true;return false;}
        self.root=Some(root);self.fd=Some(ManuallyDrop::new(unsafe{OwnedFd::from_raw_fd(root.descriptor as i32)}));
        if fcntl(borrowed,FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).is_err(){self.unknown=true;return false;}
        self.facts.admitted=true;self.post()
    }
    pub fn post(&mut self)->bool {
        let okay=self.root.zip(self.fd.as_ref()).is_some_and(|(root,fd)|check(fd.as_fd(),root,true).is_ok());
        if !okay{self.unknown=true;}okay && !self.unknown
    }
    pub fn finish(&mut self)->LeaseFacts {
        if self.facts.close_entered || self.unknown {return self.facts;}
        self.facts.postchecked=self.post();
        if !self.facts.postchecked{return self.facts;}
        self.facts.close_entered=true;
        let fd=self.fd.take().map(ManuallyDrop::into_inner);
        self.facts.closed=matches!(fd.map(unistd::close),Some(Ok(())));
        if !self.facts.closed{self.unknown=true;}self.facts
    }
    pub fn facts(&self)->LeaseFacts {self.facts}
}

/// One fixed descriptor role on the dedicated LOCAL Python command. Captured
/// original Arc is retained through the actual spawn; flags change only child.
pub fn inherit_command(command:&mut std::process::Command,lease:std::sync::Arc<ProjectLease>)->Result<(),Failure>{
    use std::os::unix::process::CommandExt;
    let (_,root)=lease.checked()?;
    unsafe {command.pre_exec(move||{
        let original=lease.fd.as_ref().ok_or_else(||std::io::Error::from_raw_os_error(nix::libc::EPERM))?;
        inherit(original.as_fd(),root)
    });}Ok(())
}
