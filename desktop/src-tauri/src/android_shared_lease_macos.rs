//! Original protected SH custody shared by the fixed query reader and app.
//! All constructors are inert. No root-only intent is opened by the app; helper
//! intent DATA is compared with independently observed original app leases.
//! Generic cleanup NEVER closes a lease. Every close-tail operand is moved out
//! only after all read/native/parent originals have positively settled.
#![forbid(unsafe_code)]
use std::{collections::BTreeMap,mem::ManuallyDrop,os::fd::{AsFd,OwnedFd},path::Path,sync::Arc,time::{Duration,Instant}};
use nix::{errno::Errno,fcntl::{self,AtFlags,OFlag},mount::MntFlags,
    sys::{stat::{self,FileStat,Mode,SFlag},statfs},unistd};
use sha2::{Digest,Sha256};
use mrk_macos_installed_native::{self as native,
    android_catalog_query::{self as query,Bounds,Role,Signal,FrozenFailure},
    android_lease::{self as lease,LockAttempt,LockState},
    vault_filesystem::{SnapshotBook,Expected,Policy,Failure as SnapshotFailure},
    vault_helper_wire::{uptime,ClockBridge}};
use crate::android_registration_protocol::records::{LeaseBinding,LeaseIdentityData,Intent,LEASE_HEADER_BYTES};

pub(crate) const ROW_LIMIT:usize=32;
pub(crate) const READ_SLOTS:usize=24;
pub(crate) const LIVE_READ_FDS:usize=24;
/// Query/SH control is an ADDITIVE bound, never a replacement for the existing
/// tool64/runtime48 live-FD limits or opaque native allocation accounting.
pub(crate) const QUERY_CONTROL_LIMIT:usize=2*1024*1024;
const SUPPORT:[&str;3]=["Library","Application Support","MobileReleaseKit"];

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum Issue {Busy,Interrupted,Refused,Unavailable,Stopped,Deadline,Bounds,Native,Unknown}
impl Issue {
    pub(crate) fn row_negative(self)->bool{matches!(self,Self::Busy|Self::Interrupted|Self::Refused)}
    pub(crate) fn uncertain(self)->bool{matches!(self,Self::Unknown|Self::Native)}
}
type Result<T>=std::result::Result<T,Issue>;
fn snapshot_issue(f:SnapshotFailure)->Issue{match f{
    SnapshotFailure::Refused=>Issue::Refused,SnapshotFailure::Native=>Issue::Native,
    SnapshotFailure::Bounds=>Issue::Bounds,SnapshotFailure::Stopped=>Issue::Stopped,SnapshotFailure::Unknown=>Issue::Unknown,
}}
pub(crate) fn hex(bytes:&[u8])->String{bytes.iter().map(|v|format!("{v:02x}")).collect()}
pub(crate) fn instance_data(value:&str)->Option<[u8;16]>{
    if value.len()!=32{return None;}let mut key=[0;16];
    for(i,pair)in value.as_bytes().chunks_exact(2).enumerate(){
        let one=|b|match b{b'0'..=b'9'=>Some(b-b'0'),b'a'..=b'f'=>Some(b-b'a'+10),_=>None};
        key[i]=one(pair[0])?.checked_mul(16)?.checked_add(one(pair[1])?)?;
    }(key!=[0;16]).then_some(key)
}

/// Read-only provenance for the SAME original query clock. A conservatively
/// mapped first may precede the owner's T by the original bracket width: never
/// clamp it back to T. Invalid mapping carries Unknown/None, not receipt-now F.
#[derive(Clone,Copy,Debug)]
pub(crate) struct RawFailureData {
    pub(crate) original:Bounds,pub(crate) first:Option<u64>,pub(crate) cleanup:Option<u64>,
    pub(crate) first_instant:Option<Instant>,pub(crate) cleanup_instant:Option<Instant>,pub(crate) unknown:bool,
}
/// Pure control validation; the caller obtained both mapped points from ONE
/// retained bracket. A future/non-mappable event must not turn into receipt-now F.
fn local_failure_bound_data(bounds:Bounds,chronological:bool,at:Option<u64>,observed:Option<u64>)->Option<u64>{
    let (at,observed)=(at?,observed?);
    (chronological && bounds.accepts_event(at,observed,observed)).then_some(at)
}
pub(crate) struct OriginalClock {bridge:ClockBridge,bounds:Bounds,signal:Arc<Signal>}
impl OriginalClock {
    pub(crate) fn for_app(role:Role,t:Instant,w:Instant,h:Instant,first:Option<Instant>,signal:Arc<Signal>)->Result<Arc<Self>>{
        if w.checked_duration_since(t)!=Some(Duration::from_nanos(role.work_ns()))
            || h.checked_duration_since(t)!=Some(Duration::from_nanos(role.hard_ns())){signal.clock_unknown();return Err(Issue::Unknown);}
        let bridge=ClockBridge::capture().ok_or_else(||{signal.clock_unknown();Issue::Unknown})?;
        let origin=bridge.earlier_endpoint(t).ok_or_else(||{signal.clock_unknown();Issue::Unknown})?;
        let bounds=Bounds{role,origin,work:origin.checked_add(role.work_ns()).ok_or(Issue::Bounds)?,
            hard:origin.checked_add(role.hard_ns()).ok_or(Issue::Bounds)?};
        if !bounds.valid() || bridge.earlier_endpoint(w)!=Some(bounds.work) || bridge.earlier_endpoint(h)!=Some(bounds.hard){
            signal.clock_unknown();return Err(Issue::Unknown);
        }
        signal.arm(bounds).map_err(|_|Issue::Unknown)?;
        let clock=Arc::new(Self{bridge,bounds,signal});
        if let Some(first)=first{clock.publish_local(first,false)?;}
        Ok(clock)
    }
    pub(crate) fn for_helper(signal:Arc<Signal>)->Result<Arc<Self>>{
        let bounds=signal.bounds().ok_or(Issue::Unknown)?;
        let bridge=ClockBridge::capture().ok_or_else(||{signal.clock_unknown();Issue::Unknown})?;
        let clock=Arc::new(Self{bridge,bounds,signal});
        let mut last=0;if !clock.point(&mut last,true,None){return Err(Issue::Stopped);}Ok(clock)
    }
    pub(crate) fn signal(&self)->&Arc<Signal>{&self.signal}
    pub(crate) fn bounds(&self)->Bounds{self.bounds}
    fn event(&self,at:Instant)->Result<u64>{
        let mapped=self.bridge.earlier_endpoint(at).ok_or(Issue::Unknown)?;
        let now=uptime().ok_or(Issue::Unknown)?;
        if at>Instant::now() || !self.bounds.accepts_event(mapped,now,now){return Err(Issue::Unknown);}
        Ok(mapped)
    }
    pub(crate) fn publish_local(&self,at:Instant,unknown:bool)->Result<()>{
        match self.event(at){Ok(raw)=>{self.signal.failure_at(raw,unknown);Ok(())},
            Err(_)=>{self.signal.clock_unknown();Err(Issue::Unknown)}}
    }
    /// Independent owner control ONLY, valid before/during/after the moved tail.
    /// Both Instants are genuine samples captured by the SAME original owner.
    /// No uptime/now/native/book lookup, new bracket or cutoff renewal occurs.
    pub(crate) fn publish_local_data(&self,at:Instant,observed:Instant,unknown:bool)->Result<()>{
        let mapped=local_failure_bound_data(self.bounds,at<=observed,
            self.bridge.earlier_endpoint(at),self.bridge.earlier_endpoint(observed));
        match mapped{
            Some(raw)=>{self.signal.failure_at(raw,unknown);Ok(())},
            None=>{self.signal.clock_unknown();Err(Issue::Unknown)},
        }
    }
    pub(crate) fn data(&self)->RawFailureData{
        let FrozenFailure{first,cleanup,unknown,..}=self.signal.snapshot();
        let first_instant=first.and_then(|at|self.bridge.earlier_instant_data(at));
        let cleanup_instant=cleanup.and_then(|at|self.bridge.earlier_instant_data(at));
        let invalid=first.is_some() && first_instant.is_none() || cleanup.is_some() && cleanup_instant.is_none();
        RawFailureData{original:self.bounds,first,cleanup,first_instant,cleanup_instant,unknown:unknown||invalid}
    }
    fn cutoff(&self,local:Option<u64>)->Option<u64>{
        let global=self.signal.snapshot().cleanup?;
        Some(local.map_or(global,|first|self.bounds.cleanup(Some(first)).unwrap_or(0).min(global)))
    }
    pub(crate) fn point(&self,last:&mut u64,cleanup:bool,local:Option<u64>)->bool{
        let Some(now)=uptime()else{self.signal.clock_unknown();return false;};
        if now<*last || now<self.bounds.origin || now>query::MAX_RAW{self.signal.clock_unknown();return false;}
        *last=now;
        self.signal.admitted_at(cleanup,now) && (!cleanup || self.cutoff(local).is_some_and(|end|now<end))
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum State{Reserved,Opening,Owned,NoHandle,Closing,Closed,Moved,Unknown}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct Identity{
    device:i32,inode:u64,mode:u16,uid:u32,gid:u32,links:u16,bytes:i64,
    mtime:i64,mtime_ns:i64,ctime:i64,ctime_ns:i64,flags:u32,
}
impl Identity{
    fn of(v:&FileStat)->Self{Self{device:v.st_dev,inode:v.st_ino,mode:v.st_mode,uid:v.st_uid,gid:v.st_gid,
        links:v.st_nlink,bytes:v.st_size,mtime:v.st_mtime,mtime_ns:v.st_mtime_nsec,ctime:v.st_ctime,ctime_ns:v.st_ctime_nsec,flags:v.st_flags}}
    fn expected(self)->Result<Expected>{Ok(Expected{device:self.device.try_into().map_err(|_|Issue::Refused)?,inode:self.inode,
        mode:self.mode.into(),owner:self.uid,group:self.gid,flags:self.flags})}
    fn lock_data(self)->Result<lease::Expected>{Ok(lease::Expected{
        device:self.device.try_into().map_err(|_|Issue::Refused)?,inode:self.inode,mode:self.mode.into(),owner:self.uid,group:self.gid,
        links:self.links.into(),bytes:self.bytes.try_into().map_err(|_|Issue::Refused)?,flags:self.flags,
        modified_seconds:self.mtime,modified_nanoseconds:self.mtime_ns.try_into().map_err(|_|Issue::Refused)?,
        changed_seconds:self.ctime,changed_nanoseconds:self.ctime_ns.try_into().map_err(|_|Issue::Refused)?,
    })}
    fn lease_data(self,header:[u8;32])->Result<LeaseIdentityData>{Ok(LeaseIdentityData{
        device:self.device.try_into().map_err(|_|Issue::Refused)?,inode:self.inode,mode:self.mode.into(),uid:self.uid,gid:self.gid,
        links:self.links.into(),bytes:self.bytes.try_into().map_err(|_|Issue::Refused)?,
        modified_seconds:self.mtime,modified_nanoseconds:self.mtime_ns.try_into().map_err(|_|Issue::Refused)?,
        changed_seconds:self.ctime,changed_nanoseconds:self.ctime_ns.try_into().map_err(|_|Issue::Refused)?,flags:self.flags,header_sha256:header,
    })}
}
struct Original{fd:Option<ManuallyDrop<OwnedFd>>,state:State,parent:Option<usize>,name:String,identity:Option<Identity>,policy:Policy,mode:Option<u16>}
/// A bounded read-only original pool. Each row has its OWN native frame: a
/// refused row's latched SnapshotBook is never recycled for another sibling.
pub(crate) struct ReadSlots{
    clock:Option<Arc<OriginalClock>>,originals:Vec<Original>,frame:Option<SnapshotBook>,entered:bool,frame_entered:bool,
    in_call:bool,unknown:bool,done:bool,first:Option<(Issue,Instant)>,first_raw:Option<u64>,last:u64,
}
impl ReadSlots{
    pub(crate) fn new()->Self{Self{clock:None,originals:Vec::new(),frame:None,entered:false,frame_entered:false,in_call:false,unknown:false,done:false,first:None,first_raw:None,last:0}}
    /// Dynamic first-party backing for one armed reader, not opaque native
    /// references. Self/clock/identity cells are charged by the containing owner.
    pub(crate) fn service_high_water()->Option<usize>{
        READ_SLOTS.checked_mul(std::mem::size_of::<Original>().checked_add(255)?)?
            .checked_add(native::vault_filesystem::SNAPSHOT_FRAME_BYTES)
    }
    pub(crate) fn arm(&mut self,clock:Arc<OriginalClock>)->Result<()>{
        if self.entered || self.clock.is_some(){return Err(Issue::Unknown);}
        // Reserve all original cells before any frame/FD entry; never grow a
        // live native owner's Vec, including late failure/cleanup paths.
        self.originals.try_reserve_exact(READ_SLOTS).map_err(|_|Issue::Bounds)?;
        if self.originals.capacity()!=READ_SLOTS{return Err(Issue::Bounds);}
        self.entered=true;self.clock=Some(clock);self.point(false)?;
        self.frame_entered=true;self.in_call=true;self.frame=Some(SnapshotBook::new());self.in_call=false;
        if self.frame.as_ref().is_none_or(|f|!f.not_started() || !(1..=native::vault_filesystem::SNAPSHOT_FRAME_BYTES).contains(&f.retained_frame_bytes())){
            return Err(self.fail(Issue::Bounds));
        }self.point(false)
    }
    fn clock(&self)->Result<&Arc<OriginalClock>>{self.clock.as_ref().ok_or(Issue::Unknown)}
    fn fail_at(&mut self,issue:Issue,at:Instant)->Issue{
        if self.first.is_none_or(|(_,first)|at<first){self.first=Some((issue,at));}
        if let Some(clock)=&self.clock{
            match clock.event(at){
                Ok(raw)=>{if !issue.row_negative(){
                    self.first_raw=Some(self.first_raw.map_or(raw,|first|first.min(raw)));
                    clock.signal.failure_at(raw,issue.uncertain());
                }},
                Err(_)=>{self.unknown=true;clock.signal.clock_unknown();},
            }
        }
        if issue.uncertain(){self.unknown=true;}issue
    }
    fn fail(&mut self,issue:Issue)->Issue{self.fail_at(issue,Instant::now())}
    pub(crate) fn failure(&self)->Option<(Issue,Instant)>{self.first}
    pub(crate) fn mark_unknown(&mut self){self.fail(Issue::Unknown);}
    fn point(&mut self,cleanup:bool)->Result<()>{
        if self.in_call || self.done{return Err(self.fail(Issue::Unknown));}
        if !cleanup{if let Some((issue,_))=self.first{return Err(issue);}}
        let Some(clock)=self.clock.clone()else{return Err(self.fail(Issue::Unknown));};
        if !clock.point(&mut self.last,cleanup,self.first_raw){
            let issue=if clock.signal.snapshot().cleanup.is_none(){Issue::Unknown}else{Issue::Stopped};
            return Err(self.fail(issue));
        }Ok(())
    }
    fn fd(&self,index:usize)->Result<&OwnedFd>{
        self.originals.get(index).filter(|o|o.state==State::Owned).and_then(|o|o.fd.as_ref()).map(|f|&**f).ok_or(Issue::Unknown)
    }
    fn id(&self,index:usize)->Result<Identity>{self.originals.get(index).and_then(|o|o.identity).ok_or(Issue::Unknown)}
    fn named(&mut self,parent:Option<usize>,name:&str,cleanup:bool)->Result<std::result::Result<FileStat,Errno>>{
        self.point(cleanup)?;
        // The returned scalar or Errno owns no descriptor. No publication can
        // bypass a lost/in-progress call in this original book.
        self.in_call=true;
        let value=match parent{Some(p)=>self.fd(p).map(|fd|stat::fstatat(fd,name,AtFlags::AT_SYMLINK_NOFOLLOW)),
            None=>Ok(stat::lstat(Path::new("/")))};
        self.in_call=false;let value=value.map_err(|issue|self.fail(issue))?;self.point(cleanup)?;Ok(value)
    }
    fn stat(&mut self,index:usize,cleanup:bool)->Result<FileStat>{
        self.point(cleanup)?;self.in_call=true;
        let value=self.fd(index).and_then(|fd|stat::fstat(fd).map_err(|_|Issue::Native));self.in_call=false;
        let value=value.map_err(|issue|self.fail(issue))?;self.point(cleanup)?;Ok(value)
    }
    fn shape(id:Identity,directory:bool,mode:Option<u16>)->bool{
        id.device!=0 && id.inode!=0 && id.uid==0 && id.mode&0o7022==0
            && id.mode&SFlag::S_IFMT.bits()==if directory{SFlag::S_IFDIR.bits()}else{SFlag::S_IFREG.bits()}
            && (directory || id.links==1)
            && mode.is_none_or(|m|id.gid==0 && id.mode&0o7777==m && id.flags==0)
    }
    pub(crate) fn open(&mut self,parent:Option<usize>,name:&str,directory:bool,mode:Option<u16>,policy:Policy)->Result<usize>{
        self.point(false)?;
        if self.originals.len()>=READ_SLOTS || self.originals.len()>=self.originals.capacity() || self.originals.iter().filter(|o|o.fd.is_some()).count()>=LIVE_READ_FDS
            || !(parent.is_none() && name=="/" || parent.is_some() && crate::android_toolchain_macos_policy::component(name)){
            return Err(self.fail(Issue::Bounds));
        }
        let mut owned_name=String::new();owned_name.try_reserve_exact(name.len()).map_err(|_|Issue::Bounds)?;
        if owned_name.capacity()>255{return Err(self.fail(Issue::Bounds));}
        owned_name.push_str(name);
        let index=self.originals.len();
        self.originals.push(Original{fd:None,state:State::Reserved,parent,name:owned_name,identity:None,policy,mode});
        let before=self.named(parent,name,false)?.map_err(|e|self.fail(if e==Errno::ENOENT{Issue::Interrupted}else{Issue::Native}))?;
        let id=Identity::of(&before);
        if !Self::shape(id,directory,mode){return Err(self.fail(Issue::Refused));}
        self.originals[index].identity=Some(id);
        self.point(false)?;
        let flags=OFlag::O_RDONLY|OFlag::O_NOFOLLOW|OFlag::O_CLOEXEC|OFlag::O_NONBLOCK
            |if directory{OFlag::O_DIRECTORY}else{OFlag::empty()};
        self.originals[index].state=State::Opening;self.in_call=true;
        let opened=if let Some(parent)=parent{fcntl::openat(self.fd(parent)?,name,flags,Mode::empty())}
            else{fcntl::open(Path::new("/"),flags,Mode::empty())};
        self.in_call=false;
        match opened{
            Ok(fd)=>{self.originals[index].fd=Some(ManuallyDrop::new(fd));self.originals[index].state=State::Owned;},
            Err(_)=>{self.originals[index].state=State::NoHandle;return Err(self.fail(Issue::Native));},
        }
        self.check(index,false)?;Ok(index)
    }
    pub(crate) fn optional(&mut self,parent:usize,name:&str,directory:bool,mode:Option<u16>,policy:Policy)->Result<Option<usize>>{
        match self.named(Some(parent),name,false)?{
            Err(Errno::ENOENT)=>{self.check(parent,false)?;Ok(None)},
            Err(_)=>Err(self.fail(Issue::Native)),
            Ok(_)=>self.open(Some(parent),name,directory,mode,policy).map(Some),
        }
    }
    pub(crate) fn support(&mut self)->Result<usize>{
        let mut parent=self.open(None,"/",true,None,Policy::Ancestors)?;
        for name in SUPPORT{parent=self.open(Some(parent),name,true,None,Policy::Ancestors)?;}Ok(parent)
    }
    pub(crate) fn identity_check(&mut self,index:usize,cleanup:bool)->Result<()>{
        let expected=self.id(index)?;let actual=Identity::of(&self.stat(index,cleanup)?);
        let (parent,name)={let original=&self.originals[index];(original.parent,original.name.clone())};
        let named=self.named(parent,&name,cleanup)?.map_err(|_|self.fail(Issue::Unknown))?;
        if actual!=expected || Identity::of(&named)!=expected{return Err(self.fail(Issue::Unknown));}Ok(())
    }
    fn protect(&mut self,index:usize,cleanup:bool)->Result<()>{
        self.point(cleanup)?;
        let id=self.id(index)?;let original=&self.originals[index];
        if !Self::shape(id,id.mode&SFlag::S_IFMT.bits()==SFlag::S_IFDIR.bits(),original.mode){return Err(self.fail(Issue::Refused));}
        let policy=original.policy;
        self.in_call=true;let filesystem=self.fd(index).and_then(|fd|statfs::fstatfs(fd).map_err(|_|Issue::Native));self.in_call=false;
        let filesystem=filesystem.map_err(|issue|self.fail(issue))?;self.point(cleanup)?;
        if filesystem.filesystem_type_name()!="apfs" || !filesystem.flags().contains(MntFlags::MNT_LOCAL)
            || filesystem.flags().intersects(MntFlags::MNT_UNION|MntFlags::MNT_AUTOMOUNTED|MntFlags::MNT_IGNORE_OWNERSHIP){
            return Err(self.fail(Issue::Refused));
        }
        let clock=self.clock()?.clone();let local=self.first_raw;let mut last=self.last;
        let expected=id.expected()?;
        let originals=&self.originals;let frame=self.frame.as_mut().ok_or(Issue::Unknown)?;
        let fd=originals[index].fd.as_ref().ok_or(Issue::Unknown)?.as_fd();
        let result=frame.observe(fd,expected,policy,&mut ||!clock.point(&mut last,cleanup,local));
        let failure=frame.first_failure();self.last=last;
        if let Some((issue,at))=failure{self.fail_at(snapshot_issue(issue),at);}
        if let Err(issue)=result{return Err(self.fail(snapshot_issue(issue)));}
        self.point(cleanup)?;
        if !matches!(policy,Policy::Ancestors){
            self.in_call=true;let result=self.fd(index).and_then(|fd|native::no_xattrs(fd.as_fd()).map_err(|_|Issue::Refused));self.in_call=false;
            if result.is_err(){return Err(self.fail(Issue::Refused));}self.point(cleanup)?;
        }Ok(())
    }
    pub(crate) fn check(&mut self,index:usize,cleanup:bool)->Result<()>{
        self.identity_check(index,cleanup)?;self.protect(index,cleanup)?;self.identity_check(index,cleanup)
    }
    pub(crate) fn read_exact(&mut self,index:usize,limit:usize,cleanup:bool)->Result<Vec<u8>>{
        let id=self.id(index)?;
        let size=usize::try_from(id.bytes).map_err(|_|self.fail(Issue::Refused))?;
        if size==0 || size>limit || limit>4*1024*1024{return Err(self.fail(Issue::Refused));}
        self.check(index,cleanup)?;
        self.point(cleanup)?;self.in_call=true;
        let position=self.fd(index).and_then(|fd|unistd::lseek(fd,0,unistd::Whence::SeekSet).map_err(|_|Issue::Native));self.in_call=false;
        if position!=Ok(0){return Err(self.fail(Issue::Native));}
        let mut output=vec![0;size];let mut at=0;
        while at<size{
            self.point(cleanup)?;self.in_call=true;
            let count=self.fd(index).and_then(|fd|unistd::read(fd,&mut output[at..]).map_err(|_|Issue::Native));self.in_call=false;
            let count=count.map_err(|_|self.fail(Issue::Native))?;
            if count==0{return Err(self.fail(Issue::Refused));}at+=count;self.point(cleanup)?;
        }
        self.point(cleanup)?;let mut extra=[0;1];self.in_call=true;
        let count=self.fd(index).and_then(|fd|unistd::read(fd,&mut extra).map_err(|_|Issue::Native));self.in_call=false;
        if count!=Ok(0){return Err(self.fail(Issue::Refused));}
        self.check(index,cleanup)?;Ok(output)
    }
    /// Fixed-root roster only. The caller enforces role-specific key/type rules;
    /// no arbitrary recursive walk or symlink following is supplied here.
    pub(crate) fn names(&mut self,parent:usize,limit:usize)->Result<BTreeMap<String,(u64,u8)>>{
        if limit>ROW_LIMIT{return Err(self.fail(Issue::Bounds));}
        self.check(parent,false)?;
        let mut names=BTreeMap::new();let mut block=[0;65536];let mut seen=0usize;
        self.point(false)?;self.in_call=true;
        let position=self.fd(parent).and_then(|fd|unistd::lseek(fd,0,unistd::Whence::SeekSet).map_err(|_|Issue::Native));self.in_call=false;
        if position!=Ok(0){return Err(self.fail(Issue::Native));}
        loop{
            self.point(false)?;self.in_call=true;
            let result=self.fd(parent).and_then(|fd|native::directory_block(fd.as_fd(),&mut block).map_err(|_|Issue::Native));self.in_call=false;
            let used=result.map_err(|_|self.fail(Issue::Native))?;
            self.point(false)?;if used==0{break;}if used>block.len(){return Err(self.fail(Issue::Unknown));}
            let mut at=0;
            while at<used{
                seen=seen.checked_add(1).ok_or(Issue::Bounds)?;
                if seen>limit+2 || used-at<11{return Err(self.fail(Issue::Bounds));}
                let inode=u64::from_ne_bytes(block[at..at+8].try_into().map_err(|_|Issue::Refused)?);
                let kind=block[at+8];let length=usize::from(u16::from_ne_bytes([block[at+9],block[at+10]]));
                let end=at.checked_add(11+length).filter(|end|*end<=used).ok_or(Issue::Refused)?;
                let name=std::str::from_utf8(&block[at+11..end]).map_err(|_|Issue::Refused)?;at=end;
                if matches!(name,"."|".."){continue;}
                if inode==0 || !crate::android_toolchain_macos_policy::component(name)
                    || names.len()>=limit || names.insert(name.to_owned(),(inode,kind)).is_some(){
                    return Err(self.fail(Issue::Refused));
                }
            }
        }
        self.check(parent,false)?;Ok(names)
    }
    pub(crate) fn child_directory_present(&mut self,parent:usize,name:&str)->Result<bool>{
        match self.named(Some(parent),name,false)?{
            Err(Errno::ENOENT)=>{self.check(parent,false)?;Ok(false)},
            Err(_)=>Err(self.fail(Issue::Native)),
            Ok(value)=>{
                let id=Identity::of(&value);
                if id.mode&SFlag::S_IFMT.bits()!=SFlag::S_IFDIR.bits() || id.uid!=0 || id.gid!=0 || id.flags!=0{
                    return Err(self.fail(Issue::Refused));
                }self.check(parent,false)?;Ok(true)
            }
        }
    }
    fn close_nonlease(&mut self,index:usize)->bool{
        match self.originals[index].state{
            State::Reserved=>self.originals[index].state=State::NoHandle,
            State::Owned=>{
                if self.point(true).is_err(){self.unknown=true;return false;}
                self.originals[index].state=State::Closing;self.in_call=true;
                let original=self.originals[index].fd.take();
                let result=original.map(|fd|unistd::close(ManuallyDrop::into_inner(fd)));
                self.in_call=false;
                if matches!(result,Some(Ok(()))){self.originals[index].state=State::Closed;}
                else{self.originals[index].state=State::Unknown;self.fail(Issue::Unknown);}
                if self.point(true).is_err(){self.unknown=true;}
            }
            State::NoHandle|State::Closed=>{},
            _=>{self.fail(Issue::Unknown);}
        }!self.unknown
    }
    /// ALL observations first, then original native releases, then independent
    /// nonlease consumes. No lease is consumed by this method, even on refusal.
    pub(crate) fn settle_observations(&mut self,lease_index:Option<usize>)->bool{
        if self.done{self.fail(Issue::Unknown);return false;}
        if !self.entered{self.done=true;return true;}
        if self.in_call{self.fail(Issue::Unknown);return false;}
        for index in 0..self.originals.len(){
            if self.originals[index].state==State::Owned && self.identity_check(index,true).is_err(){self.unknown=true;}
        }
        let clock=self.clock.clone();let local=self.first_raw;let mut last=self.last;
        let released=if let Some(frame)=self.frame.as_mut(){
            frame.release(&mut |failure|{
                let Some(clock)=&clock else{return true;};
                if let Some((f,at))=failure{
                    if !snapshot_issue(f).row_negative(){let _=clock.publish_local(at,snapshot_issue(f).uncertain());}
                }
                let raw=failure.filter(|(f,_)|!snapshot_issue(*f).row_negative()).and_then(|(_,at)|clock.event(at).ok());
                let local=match(local,raw){(Some(a),Some(b))=>Some(a.min(b)),(a,b)=>a.or(b)};
                !clock.point(&mut last,true,local)
            })
        }else{!self.frame_entered};
        self.last=last;if !released{self.fail(Issue::Unknown);}
        for index in (0..self.originals.len()).rev(){if lease_index!=Some(index){let _=self.close_nonlease(index);}}
        self.done=true;self.observations_settled(lease_index)
    }
    fn observations_settled(&self,lease_index:Option<usize>)->bool{
        self.done && !self.in_call && !self.unknown && (match self.frame.as_ref(){Some(frame)=>frame.settled(),None=>!self.frame_entered})
            && self.originals.iter().enumerate().all(|(i,o)|lease_index==Some(i)
                || o.fd.is_none() && matches!(o.state,State::Closed|State::NoHandle))
    }
    pub(crate) fn settled(&self)->bool{self.observations_settled(None)}
    pub(crate) fn retained_bytes(&self)->Option<usize>{
        if self.in_call || self.unknown{return None;}
        let frame=match &self.frame{Some(f) if f.quiescent()=>f.retained_frame_bytes(),Some(_)=>return None,None if !self.frame_entered=>0,None=>return None};
        self.originals.iter().try_fold(self.originals.capacity().checked_mul(std::mem::size_of::<Original>())?.checked_add(frame)?,
            |n,o|n.checked_add(o.name.capacity()))
    }
}

/// One original lease with independent native account/principal round-trip.
/// The header UUID is DATA until Policy::LeaseUser independently authenticates it.
pub(crate) struct SharedUseLeaseSlots{
    identity:OriginalUseIdentity,read:ReadSlots,attempt:LockAttempt,index:Option<usize>,binding:Option<LeaseBinding>,
    original:Option<LeaseIdentityData>,key:Option<[u8;16]>,taken:bool,
}
impl SharedUseLeaseSlots{
    pub(crate) fn new(identity:OriginalUseIdentity)->Self{Self{identity,read:ReadSlots::new(),attempt:LockAttempt::new(),index:None,binding:None,original:None,key:None,taken:false}}
    pub(crate) fn admit_once(&mut self,key:[u8;16],account:u32,clock:Arc<OriginalClock>)->Result<()>{
        if self.key.is_some() || key==[0;16] || account==0 || account==u32::MAX{return Err(Issue::Unknown);}
        self.key=Some(key);self.read.arm(clock.clone())?;
        let support=self.read.support()?;
        let leases=self.read.optional(support,"android-leases",true,Some(0o755),Policy::Empty)?.ok_or(Issue::Interrupted)?;
        let parent=self.read.optional(leases,&account.to_string(),true,Some(0o755),Policy::Empty)?.ok_or(Issue::Interrupted)?;
        let name=hex(&key)+".lock";
        // Read the fixed header before choosing the lease-only native policy.
        // No untrusted principal is passed to the root-only writer API.
        let index=self.read.open(Some(parent),&name,false,Some(0o400),Policy::Ancestors)?;
        self.index=Some(index);
        let header=self.read.read_exact(index,LEASE_HEADER_BYTES,false)?;
        if header.len()!=LEASE_HEADER_BYTES{return Err(self.read.fail(Issue::Refused));}
        let binding=LeaseBinding::decode(&header).map_err(|_|self.read.fail(Issue::Refused))?;
        if binding.account()!=account || binding.instance()!=key{return Err(self.read.fail(Issue::Refused));}
        self.read.originals[index].policy=Policy::LeaseUser{uid:account,principal:binding.principal()};
        self.read.check(index,false)?;
        let id=self.read.id(index)?;let expected=id.lock_data()?;
        let original=id.lease_data(Sha256::digest(&header).into())?;
        let mut last=self.read.last;
        let result=self.attempt.acquire(self.read.fd(index)?.as_fd(),expected,lease::Mode::Shared,&mut |failure|{
            // Busy/known lease refusal stays this row's negative DATA. Original
            // global STOP/native uncertainty remains independently latched.
            if let Some((failure,at))=failure{
                if !matches!(failure,lease::Failure::Busy|lease::Failure::Refused){let _=clock.publish_local(at,failure==lease::Failure::Unknown);}
            }
            !clock.point(&mut last,false,None)
        });
        self.read.last=last;
        if let Some((failure,at))=self.attempt.first_failure(){
            let issue=match failure{lease::Failure::Busy=>Issue::Busy,lease::Failure::Refused=>Issue::Refused,
                lease::Failure::Native=>Issue::Native,lease::Failure::Stopped=>Issue::Stopped,_=>Issue::Unknown};
            self.read.fail_at(issue,at);
        }
        if result.is_err(){return Err(self.read.failure().map_or(Issue::Unknown,|(f,_)|f));}
        self.binding=Some(binding);self.original=Some(original);
        self.check_held(false)
    }
    pub(crate) fn check_held(&mut self,cleanup:bool)->Result<()>{
        if self.taken || self.attempt.call_in_progress() || self.attempt.lock_state()!=LockState::Held(lease::Mode::Shared){
            return Err(self.read.fail(Issue::Unknown));
        }
        let index=self.index.ok_or(Issue::Unknown)?;
        self.read.check(index,cleanup)?;
        let header=self.read.read_exact(index,LEASE_HEADER_BYTES,cleanup)?;
        let binding=LeaseBinding::decode(&header).map_err(|_|self.read.fail(Issue::Unknown))?;
        let actual=self.read.id(index)?.lease_data(Sha256::digest(&header).into())?;
        if self.binding!=Some(binding) || self.original!=Some(actual){return Err(self.read.fail(Issue::Unknown));}Ok(())
    }
    pub(crate) fn authenticate_intent(&self,raw:&[u8])->Result<Intent>{
        if self.taken || self.attempt.lock_state()!=LockState::Held(lease::Mode::Shared) || self.read.failure().is_some(){return Err(Issue::Unknown);}
        let intent=Intent::decode(raw).map_err(|_|Issue::Refused)?;
        if !intent.matches_original_data(&self.binding.ok_or(Issue::Unknown)?,&self.original.ok_or(Issue::Unknown)?){return Err(Issue::Refused);}Ok(intent)
    }
    pub(crate) fn settle_observations(&mut self)->bool{
        let settled=self.read.settle_observations(self.index);
        settled && !self.attempt.call_in_progress() && !matches!(self.attempt.lock_state(),LockState::Calling|LockState::Unknown)
    }
    pub(crate) fn observations_settled(&self)->bool{self.read.observations_settled(self.index)
        && !self.attempt.call_in_progress() && !matches!(self.attempt.lock_state(),LockState::Calling|LockState::Unknown)}
    pub(crate) fn failure(&self)->Option<(Issue,Instant)>{self.read.failure()}
    pub(crate) fn retained_bytes(&self)->Option<usize>{self.read.retained_bytes()}
    fn take_close_operand(&mut self)->Result<Option<ManuallyDrop<OwnedFd>>>{
        if self.taken || !self.read.observations_settled(self.index) || self.attempt.call_in_progress()
            || matches!(self.attempt.lock_state(),LockState::Calling|LockState::Unknown){return Err(Issue::Unknown);}
        self.taken=true;
        let Some(index)=self.index else{return Ok(None);};
        let original=&mut self.read.originals[index];
        if original.state!=State::Owned{return Err(Issue::Unknown);}
        let fd=original.fd.take().ok_or(Issue::Unknown)?;original.state=State::Moved;Ok(Some(fd))
    }
}

/// Original identity is allocated only by a pre-GO containing wrapper. It is
/// not a caller-selected numeric ID, renderer DTO or persisted selection token.
#[derive(Clone)]
pub(crate) struct OriginalUseIdentity(Arc<()>);
impl OriginalUseIdentity {
    pub(crate) fn reserved()->Self{Self(Arc::new(()))}
    pub(crate) fn same_original(&self,other:&Self)->bool{Arc::ptr_eq(&self.0,&other.0)}
}
/// Expected per-row Busy/malformed DATA does not start an operation first-F:
/// only a global/native/clock/STOP failure contracts original cleanup time.
/// Fixed moved operands. Dropping an uncertain tail does NOT close a descriptor;
/// the containing original owner must retain it as outstanding custody.
pub(crate) struct LeaseCloseTail{
    identity:OriginalUseIdentity,originals:[Option<ManuallyDrop<OwnedFd>>;ROW_LIMIT],count:usize,clock:Arc<OriginalClock>,
    cutoff:Option<u64>,last:u64,prepared:bool,
}
pub(crate) struct FrozenCloseData{
    pub(crate) settled:bool,pub(crate) attempted:u32,pub(crate) closed:u32,pub(crate) remaining:u32,
    pub(crate) not_entered:u32,pub(crate) entered_unfinalized:u32,
    pub(crate) first_close_errno:Option<i32>,pub(crate) final_raw:Option<u64>,pub(crate) failure:RawFailureData,
    // Opaque retained originals cannot be looked up/retried through public APIs.
    _retained:ManuallyDrop<[Option<ManuallyDrop<OwnedFd>>;ROW_LIMIT]>,
    // GuardedClose privately keeps the untouched FD ONLY on proven non-entry.
    // Entered failed/late results are DATA, never reconstructed known-open FDs.
    _guarded:ManuallyDrop<[Option<lease::GuardedClose>;ROW_LIMIT]>,
}
type CloseLedger=[Option<(lease::CloseAdmission,lease::CloseData)>;ROW_LIMIT];
/// Additive transient control charge through the actual original tail return.
/// This contains scalar DATA only; FrozenCloseData separately retains originals.
pub(crate) const CLOSE_TAIL_LEDGER_BYTES:usize=std::mem::size_of::<CloseLedger>();
fn reconcile_closed_data(ledger:&CloseLedger,cutoff:Option<u64>,failure:(Option<u64>,bool),
    last:u64,remaining:u32,known:bool)->(bool,u32){
    // The SAME final snapshot qualifies BOTH the aggregate and every entered
    // result. Delayed earlier F can invalidate an already-returned sibling.
    let (failure_cleanup,unknown)=failure;
    let cutoff=match(cutoff,failure_cleanup){(Some(a),Some(b))=>Some(a.min(b)),_=>None};
    let entered_unfinalized=ledger.iter().flatten().filter(|(admission,data)|
        data.entered() && (unknown || !data.timely_success(*admission,cutoff))).count() as u32;
    (known && remaining==0 && entered_unfinalized==0 && !unknown
        && cutoff.is_some_and(|end|last<end),entered_unfinalized)
}
impl LeaseCloseTail{
    pub(crate) fn prepare(identity:&OriginalUseIdentity,clock:Arc<OriginalClock>,rows:&mut[SharedUseLeaseSlots])->Result<Self>{
        if rows.len()>ROW_LIMIT{return Err(Issue::Bounds);}
        // ALL eligibility/read/native/book lookups happen before ANY operand is
        // consumed. An error retains every already-taken FD inside this owner.
        if rows.iter().any(|row|!identity.same_original(&row.identity)
            || row.read.clock.as_ref().is_some_and(|original|!Arc::ptr_eq(original,&clock))
            || row.taken || !row.read.observations_settled(row.index)
            || row.attempt.call_in_progress() || matches!(row.attempt.lock_state(),LockState::Calling|LockState::Unknown)
            || row.index.is_some_and(|index|row.read.originals.get(index).is_none_or(|o|o.state!=State::Owned || o.fd.is_none()))){
            return Err(Issue::Unknown);
        }
        let mut last=rows.iter().map(|row|row.read.last).max().unwrap_or(0);
        if !clock.point(&mut last,true,None) || clock.signal.snapshot().unknown{return Err(Issue::Unknown);}
        let mut cutoff=clock.signal.snapshot().cleanup;
        for row in rows.iter(){
            if let Some(first)=row.read.first_raw{cutoff=match(cutoff,clock.bounds.cleanup(Some(first))){(Some(a),Some(b))=>Some(a.min(b)),_=>None};}
        }
        let mut originals=std::array::from_fn(|_|None);let mut count=0;let mut prepared=true;
        for row in rows.iter_mut(){
            match row.take_close_operand(){
                Ok(Some(fd))=>{originals[count]=Some(fd);count+=1;},Ok(None)=>{},
                Err(_)=>{clock.signal.failure_now(true);prepared=false;break;}
            }
        }
        // Unexpected movement failure returns retained operands, not an Err
        // that would abandon already-moved original custody.
        Ok(Self{identity:identity.clone(),originals,count,clock,cutoff,last,prepared})
    }
    /// Helper calls this in its SAME original reader after input retirement and
    /// all row/common observations; app exposes it ONLY via the private genuine
    /// original-join witness. Each shim performs mandatory pre-entry time inside
    /// that call. No row/book/FD/parent access follows the first consuming close.
    fn consume(mut self)->FrozenCloseData{
        // All result/custody storage exists BEFORE any consuming call.
        let mut guarded:[Option<lease::GuardedClose>;ROW_LIMIT]=std::array::from_fn(|_|None);
        let mut ledger:CloseLedger=std::array::from_fn(|_|None);
        let mut attempted=0;let mut closed=0;let mut not_entered=0;
        let mut first_close_errno=None;let mut final_raw=None;
        let bounds=self.clock.bounds;
        // Entry point is still before the first close; it covers an empty tail
        // too. Subsequent actual admission is INSIDE each independent shim.
        let mut known=self.prepared && self.cutoff.is_some()
            && self.clock.point(&mut self.last,true,None);
        for index in 0..self.count{
            let failure=self.clock.signal.snapshot(); // Independent pure control DATA.
            self.cutoff=match(self.cutoff,failure.cleanup){(Some(a),Some(b))=>Some(a.min(b)),_=>None};
            if !known || failure.unknown || self.cutoff.is_none_or(|end|self.last>=end){known=false;break;}
            let Some(cutoff)=self.cutoff else{known=false;break;};
            let Some(fd)=self.originals[index].take()else{
                self.clock.signal.clock_unknown();known=false;break;
            };
            let admission=lease::CloseAdmission{origin:bounds.origin,hard:bounds.hard,previous:self.last,cutoff};
            let result=lease::consume_original(ManuallyDrop::into_inner(fd),admission);
            let data=result.data();
            guarded[index]=Some(result); // Non-entry original custody is kept before reconciliation.
            ledger[index]=Some((admission,data));
            attempted+=u32::from(data.entered());
            not_entered+=u32::from(!data.entered());
            closed+=u32::from(data.returned_success());
            if first_close_errno.is_none(){first_close_errno=data.close_errno();}
            // Only the returned scalar/opaque result and independent first-F
            // atomics remain. No fd lookup, post-stat, retry, Drop or new sample.
            let failure=self.clock.signal.snapshot();
            self.cutoff=match(self.cutoff,failure.cleanup){(Some(a),Some(b))=>Some(a.min(b)),_=>None};
            final_raw=data.observation(admission);
            known=data.timely_success(admission,self.cutoff) && !failure.unknown;
            if let Some(at)=final_raw{self.last=at;}
            if !known{
                match final_raw{Some(at)=>self.clock.signal.failure_at(at,true),None=>self.clock.signal.clock_unknown()}
                break;
            }
        }
        let remaining=(self.count as u32).saturating_sub(attempted);
        let failure=self.clock.data(); // Pure inverse of the SAME original bracket.
        let (settled,entered_unfinalized)=reconcile_closed_data(&ledger,self.cutoff,
            (failure.cleanup,failure.unknown),self.last,remaining,known);
        FrozenCloseData{settled,
            attempted,closed,remaining,not_entered,entered_unfinalized,first_close_errno,final_raw,failure,
            _retained:ManuallyDrop::new(self.originals),_guarded:ManuallyDrop::new(guarded)}
    }
}
/// App-only gate type has no serializable/public Boolean join constructor.
#[cfg(not(feature="macos-android-registration-helper"))]
pub(crate) struct AppCloseTail{identity:OriginalUseIdentity,tail:LeaseCloseTail}
#[cfg(not(feature="macos-android-registration-helper"))]
impl AppCloseTail{
    pub(crate) fn prepared(tail:LeaseCloseTail)->Self{Self{identity:tail.identity.clone(),tail}}
    pub(crate) fn consume_after_original_joins(self,joins:crate::saved_command_owner::AndroidOriginalJoins)->FrozenCloseData{
        if joins.accepts_original(&self.identity){self.tail.consume()}
        else{
            let mut tail=self.tail;tail.prepared=false;tail.clock.signal.clock_unknown();tail.consume()
        }
    }
}
#[cfg(feature="macos-android-registration-helper")]
pub(crate) fn consume_helper_tail(tail:LeaseCloseTail)->FrozenCloseData{tail.consume()}

#[cfg(test)]
mod final_control_data_tests{
    use super::*;
    fn bounds()->Bounds{
        let role=Role::Catalog;let origin=100;
        Bounds{role,origin,work:origin+role.work_ns(),hard:origin+role.hard_ns()}
    }
    fn failure(first:Option<u64>,unknown:bool)->(Option<u64>,bool){
        (bounds().cleanup(first),unknown)
    }
    fn returned(after:u64)->(lease::CloseAdmission,lease::CloseData){
        (lease::CloseAdmission{origin:100,hard:bounds().hard,previous:100,cutoff:bounds().hard},
         lease::CloseData::Returned{before:after-1,returned:0,errno:0,after:Some(after)})
    }
    #[test]
    fn earlier_failure_between_last_return_and_final_snapshot_invalidates_aggregate(){
        let mut ledger:CloseLedger=std::array::from_fn(|_|None);
        let (admission,data)=returned(20_000_000_000);
        ledger[0]=Some((admission,data));
        assert!(data.timely_success(admission,Some(bounds().hard)));
        assert_eq!(reconcile_closed_data(&ledger,Some(bounds().hard),failure(None,false),
            20_000_000_000,0,true),(true,0));
        // Same actual successful close; newly delivered early F contracts final
        // cleanup below its return. Do not convert closed=1 into settlement.
        assert_eq!(reconcile_closed_data(&ledger,Some(bounds().hard),failure(Some(200),false),
            20_000_000_000,0,true),(false,1));
        assert!(data.entered() && data.returned_success());
        assert_eq!(reconcile_closed_data(&ledger,Some(bounds().hard),failure(None,true),
            20_000_000_000,0,true),(false,1));
    }
    #[test]
    fn narrowing_before_next_row_recounts_previous_entries_without_consuming_sibling(){
        let mut ledger:CloseLedger=std::array::from_fn(|_|None);
        ledger[0]=Some(returned(5_000_000_000));
        ledger[1]=Some(returned(20_000_000_000));
        // The next iteration sees F+10s, stops before moving sibling2, and keeps
        // remaining=1. Final DATA must still reclassify earlier entered row1.
        let final_failure=failure(Some(200),false);
        assert_eq!(reconcile_closed_data(&ledger,Some(bounds().hard),final_failure,
            20_000_000_000,1,false),(false,1));
        assert!(ledger[2].is_none());
        // A later/longer snapshot cannot renew the retained original cutoff;
        // known=false is sticky even when all close DATA would otherwise fit.
        assert_eq!(reconcile_closed_data(&ledger,Some(10_000_000_200),failure(None,false),
            20_000_000_000,0,true),(false,1));
        assert_eq!(reconcile_closed_data(&ledger,Some(bounds().hard),failure(None,false),
            20_000_000_000,0,false),(false,0));
    }
    #[test]
    fn owner_local_control_rejects_future_invalid_and_nonmappable_events(){
        let original=bounds();
        assert_eq!(local_failure_bound_data(original,true,Some(200),Some(300)),Some(200));
        for (chronological,at,observed) in [
            (false,Some(200),Some(300)), // actual future Instant, not receipt-now
            (true,None,Some(300)),(true,Some(200),None),
            (true,Some(0),Some(300)),(true,Some(99),Some(300)),
            (true,Some(301),Some(300)),(true,Some(200),Some(query::MAX_RAW+1)),
        ]{
            assert_eq!(local_failure_bound_data(original,chronological,at,observed),None);
        }
        assert_eq!(local_failure_bound_data(Bounds{work:original.work+1,..original},
            true,Some(200),Some(300)),None);
    }
}
