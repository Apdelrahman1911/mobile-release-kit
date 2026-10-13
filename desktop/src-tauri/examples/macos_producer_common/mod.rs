//! Private common file custody for the two fixed, nonshipping producer examples.
//! This is the existing producer Book, not another process or memory owner.
//! Containing command owner must admit retained parser/native allocation peaks.
use std::{cell::Cell,collections::BTreeMap,mem::ManuallyDrop,
    os::{fd::{AsFd,OwnedFd},unix::ffi::OsStrExt},path::{Path,PathBuf},time::{Duration,Instant}};
use nix::{fcntl::{self,AtFlags,OFlag},sys::{stat::{self,FileStat,Mode},uio::pread},unistd};
use sha2::{Digest,Sha256};
use mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData;
use mrk_macos_installed_native::{self as native,android_service_management::Decision,install_producer::ProducerCheckpoint};
pub(super) type Result<T> = std::result::Result<T,&'static str>;
pub(super) const PACKAGE_LIMIT:u64=512*1024*1024;
pub(super) const ORIGINAL_LIMIT:usize=80; // Remove two roots+six inputs+two writes+four rosters <=78
pub(super) const READ_LIMIT:u64=2*1024*1024*1024;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum ReadRole {Package,InstallDescriptor,RemoveDescriptor,Signature,Inventory,Program}
impl ReadRole {
    pub(super) fn policy(self)->(u64,bool,bool) {match self {
        Self::Package=>(PACKAGE_LIMIT,false,true),Self::InstallDescriptor=>(65536,true,false),
        Self::RemoveDescriptor=>(16384,true,false),Self::Signature=>(512,true,false),
        Self::Inventory=>(1048576,true,false),Self::Program=>(67108864,false,false),
    }}
}

pub(super) fn need(value:bool,reason:&'static str)->Result<()> {if value {Ok(())} else {Err(reason)}}
// Ordinary inputs/package outputs retain their existing at-most-five gate.
// The only sixth-row entry is a compile-fixed observer input roster; neither
// helper opens a reader or makes inode DATA an original-handle authority.
pub(super) fn roster_admission_data(wanted:&[(&str,u64)])->Result<()> {
    need(!wanted.is_empty()&&wanted.len()<=5,"root-roster-bound")
}
#[cfg(feature="macos-remove-observer-producer")]
pub(super) fn observer_input_roster_data(wanted:&[(&str,u64)])->Result<()> {
    const NAMES:[&str;6]=["remove-descriptor-input.json","producer.json","producer.sig",
        "install-inventory.json","mrk-macos-remove","installed-mrk-macos-remove"];
    need(wanted.len()==NAMES.len()&&wanted.iter().zip(NAMES).all(|((name,ino),expected)|
        *name==expected&&*ino!=0),"observer-input-roster")
}
pub(super) fn hash(bytes:&[u8])->String {format!("{:x}",Sha256::digest(bytes))}
pub(super) fn target()->MaintenanceTargetData {
    #[cfg(target_arch="aarch64")] {MaintenanceTargetData::Arm64}
    #[cfg(target_arch="x86_64")] {MaintenanceTargetData::Intel}
}
pub(super) fn components(path:&Path)->Result<Vec<String>> {
    let raw=path.as_os_str().as_bytes();
    need(raw.len()>1&&raw.len()<=1024&&raw[0]==b'/'&&!raw.contains(&0),"path-shape")?;
    let parts:Vec<_>=std::str::from_utf8(&raw[1..]).map_err(|_|"path-encoding")?.split('/').collect();
    need(parts.len()<=32&&parts.iter().all(|p|!p.is_empty()&&*p!="."&&*p!=".."&&p.len()<=255),"path-components")?;
    Ok(parts.into_iter().map(str::to_owned).collect())
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) struct Identity {dev:i64,pub(super) ino:u64,mode:u32,uid:u32,gid:u32,links:u64,pub(super) size:i64,
    mtime:i64,mtime_ns:i64,ctime:i64,ctime_ns:i64,flags:u32}
impl Identity {
    pub(super) fn of(s:&FileStat)->Self {Self{dev:i64::from(s.st_dev),ino:s.st_ino,mode:u32::from(s.st_mode),uid:s.st_uid,gid:s.st_gid,
        links:u64::from(s.st_nlink),size:s.st_size,mtime:s.st_mtime,mtime_ns:s.st_mtime_nsec,
        ctime:s.st_ctime,ctime_ns:s.st_ctime_nsec,flags:s.st_flags}}
    pub(super) fn object(self,other:Self)->bool {self.dev==other.dev&&self.ino==other.ino
        &&self.mode&0o170000==other.mode&0o170000&&self.uid==other.uid&&self.gid==other.gid}
    pub(super) fn ancestor(self,other:Self)->bool {self.object(other)&&self.mode==other.mode&&self.links==other.links&&self.flags==other.flags}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum State {Reserved,Acquiring,Owned,Closing,Closed,Absent,Unknown}
pub(super) fn final_ready_data(unknown:bool,pending:bool,within:bool,states:&[State])->bool {
    !unknown&&!pending&&within&&states.iter().all(|state|matches!(state,State::Closed|State::Absent))
}
struct Original {fd:Option<ManuallyDrop<OwnedFd>>,state:State,parent:Option<usize>,name:String,
    identity:Option<Identity>,exact:bool}
pub(super) struct Book {originals:Vec<Original>,work:Instant,pub(super) final_end:Instant,pub(super) cleanup:Cell<bool>,
    pub(super) unknown:Cell<bool>,pub(super) pending:Cell<bool>,issued:u64,uid:u32}
impl Book {
    pub(super) fn new(start:Instant)->Result<Self> {
        let uid=unistd::getuid().as_raw();
        need(uid!=0&&uid==unistd::geteuid().as_raw()&&unistd::getgid()==unistd::getegid(),"ordinary-user")?;
        Ok(Self{originals:Vec::with_capacity(ORIGINAL_LIMIT),work:start.checked_add(Duration::from_secs(110)).ok_or("clock")?,
            final_end:start.checked_add(Duration::from_secs(120)).ok_or("clock")?,cleanup:Cell::new(false),unknown:Cell::new(false),pending:Cell::new(false),issued:0,uid})
    }
    pub(super) fn tick(&self)->Result<()> {
        need(!self.unknown.get()&&!self.pending.get(),"original-unknown")?;
        need(Instant::now()<if self.cleanup.get() {self.final_end} else {self.work},"deadline")
    }
    pub(super) fn fd(&self,n:usize)->Result<&OwnedFd> {
        let row=self.originals.get(n).ok_or("original-slot")?;
        need(row.state==State::Owned,"original-not-owned")?;
        row.fd.as_deref().ok_or("original-no-handle")
    }
    pub(super) fn id(&self,n:usize)->Result<Identity> {self.originals.get(n).and_then(|r|r.identity).ok_or("original-unbound")}
    pub(super) fn observed(&self,n:usize)->Result<Identity> {
        self.tick()?;self.pending.set(true);
        let result=stat::fstat(self.fd(n)?);self.pending.set(false);
        let value=Identity::of(&result.map_err(|_|"original-stat")?);self.tick()?;Ok(value)
    }
    pub(super) fn named(&self,parent:Option<usize>,name:&str)->Result<Identity> {
        self.tick()?;self.pending.set(true);
        let result=if let Some(parent)=parent {stat::fstatat(self.fd(parent)?,name,AtFlags::AT_SYMLINK_NOFOLLOW)}
            else {stat::lstat(Path::new("/"))};self.pending.set(false);
        let value=Identity::of(&result.map_err(|_|"original-name")?);self.tick()?;Ok(value)
    }
    pub(super) fn check(&self,n:usize)->Result<()> {
        let row=&self.originals[n];let (parent,name,exact)=(row.parent,row.name.clone(),row.exact);
        let expected=self.id(n)?;let held=self.observed(n)?;let named=self.named(parent,&name)?;
        need(held==named&&if exact {held==expected} else {expected.ancestor(held)},"original-post")
    }
    pub(super) fn all(&self)->Result<()> {
        self.tick()?;
        for n in 0..self.originals.len() {
            if self.originals[n].state==State::Owned {self.check(n)?;}
            else {need(matches!(self.originals[n].state,State::Reserved|State::Closed|State::Absent),"original-pending")?;}
        }
        self.tick()
    }
    pub(super) fn reserve(&mut self,parent:Option<usize>,name:&str,exact:bool)->Result<usize> {
        self.tick()?;need(self.originals.len()<ORIGINAL_LIMIT,"original-limit")?;
        let n=self.originals.len();self.originals.push(Original{fd:None,state:State::Reserved,parent,name:name.to_owned(),identity:None,exact});Ok(n)
    }
    pub(super) fn adopt(&mut self,n:usize,result:nix::Result<OwnedFd>)->Result<()> {
        match result {
            Ok(fd)=>{self.originals[n].fd=Some(ManuallyDrop::new(fd));self.originals[n].state=State::Owned;Ok(())},
            Err(_)=>{self.originals[n].state=State::Absent;Err("original-open")},
        }
    }
    pub(super) fn open(&mut self,parent:Option<usize>,name:&str,directory:bool,exact:bool)->Result<usize> {
        let n=self.reserve(parent,name,exact)?;let before=self.named(parent,name)?;
        let kind=if directory {0o040000} else {0o100000};
        need(before.mode&0o170000==kind&&(directory||before.links==1),"original-type")?;
        self.originals[n].identity=Some(before);self.tick()?;self.originals[n].state=State::Acquiring;
        let flags=OFlag::O_RDONLY|OFlag::O_NOFOLLOW|OFlag::O_CLOEXEC|OFlag::O_NONBLOCK
            |if directory {OFlag::O_DIRECTORY} else {OFlag::empty()};
        let result=if let Some(parent)=parent {fcntl::openat(self.fd(parent)?,name,flags,Mode::empty())}
            else {fcntl::open(Path::new("/"),flags,Mode::empty())};
        self.adopt(n,result)?;self.check(n)?;Ok(n)
    }
    pub(super) fn parents(&mut self,path:&Path,final_directory:bool)->Result<usize> {
        let parts=components(path)?;let count=parts.len()-usize::from(!final_directory);
        let mut n=self.open(None,"/",true,false)?;let mut at=PathBuf::from("/");self.parent_policy(n,&at)?;
        for part in &parts[..count] {
            n=self.open(Some(n),part,true,false)?;at.push(part);self.parent_policy(n,&at)?;
        }
        Ok(n)
    }
    pub(super) fn parent_policy(&mut self,n:usize,path:&Path)->Result<()> {
        let id=self.id(n)?;
        // Shared trusted ancestors may change directory timestamps; bind
        // their original inode/type/owner/mode/links/flags, not others' files.
        let sticky=path==Path::new("/private/tmp")&&id.uid==0&&id.mode&0o7777==0o1777;
        need(id.mode&0o170000==0o040000&&(id.uid==0||id.uid==self.uid)
            &&(id.mode&0o7022==0||sticky),"parent-protection")
    }
    pub(super) fn private_root(&mut self,n:usize)->Result<()> {
        let id=self.observed(n)?;need(id.uid==self.uid&&id.mode&0o177777==0o040700&&id.flags==0,"private-root")?;
        self.originals[n].identity=Some(id);self.originals[n].exact=true;self.attributes(n)?;self.check(n)
    }
    pub(super) fn attributes(&self,n:usize)->Result<()> {
        self.tick()?;self.pending.set(true);
        let acl=native::empty_acl_observed(self.fd(n)?.as_fd());self.pending.set(false);
        if let Err(error)=acl {
            if error.free_result!=0||error.refusal_code.is_none() {self.unknown.set(true);}
            return Err("private-acl");
        }
        self.tick()?;self.pending.set(true);let result=native::no_xattrs(self.fd(n)?.as_fd());self.pending.set(false);
        result.map_err(|_|"private-attributes")?;self.tick()
    }
    pub(super) fn file_policy(&mut self,n:usize,limit:u64)->Result<()> {
        let id=self.id(n)?;
        need(id.mode&0o177777==0o100444&&id.uid==self.uid&&id.links==1&&id.flags==0
            &&id.size>0&&id.size as u64<=limit,"private-file")?;self.attributes(n)?;self.check(n)
    }
    pub(super) fn program_policy(&self,n:usize)->Result<()> {
        let id=self.id(n)?;
        need(id.mode&0o177777==0o100555&&id.uid==self.uid&&id.links==1&&id.flags==0
            &&id.size>0&&id.size as u64<=ReadRole::Program.policy().0,"private-program")?;
        self.attributes(n)?;self.check(n)
    }
    pub(super) fn read(&mut self,n:usize,role:ReadRole)->Result<(String,Vec<u8>)> {
        self.check(n)?;let size=u64::try_from(self.id(n)?.size).map_err(|_|"read-size")?;
        let(limit,keep,package)=role.policy();need(size<=limit,"read-limit")?;
        let mut saved=Vec::with_capacity(if keep {size as usize} else {0});
        let mut sha=Sha256::new();let mut offset=0u64;let mut buffer=[0u8;65536];
        loop {
            self.tick()?;let wanted=usize::try_from((size-offset).min(buffer.len() as u64)).map_err(|_|"read-size")?;
            let wanted=if wanted==0 {1} else {wanted};
            self.issued=self.issued.checked_add(wanted as u64).ok_or("read-budget")?;need(self.issued<=READ_LIMIT,"read-budget")?;
            self.pending.set(true);let result=pread(self.fd(n)?,&mut buffer[..wanted],offset as i64);self.pending.set(false);
            let count=result.map_err(|_|"read-original")?;self.tick()?;
            if count==0 {need(offset==size,"read-short")?;break;}
            need(offset+count as u64<=size,"read-extent")?;
            if offset==0&&package {need(count>=4&&&buffer[..4]==b"xar!","completed-package-magic")?;}
            sha.update(&buffer[..count]);if keep {saved.extend_from_slice(&buffer[..count]);}offset+=count as u64;
        }
        self.check(n)?;Ok((format!("{:x}",sha.finalize()),saved))
    }
    pub(super) fn close(&mut self,n:usize)->bool {
        if self.unknown.get()||self.pending.get() {return false;}
        if matches!(self.originals[n].state,State::Closed|State::Absent) {return true;}
        if self.originals[n].state==State::Reserved {self.originals[n].state=State::Absent;return true;}
        if self.originals[n].state!=State::Owned {self.unknown.set(true);return false;}
        let post=self.check(n).is_ok();
        if self.unknown.get()||self.pending.get() {return false;}
        // A known POST refusal does not invent FD uncertainty; close this
        // original, but retain the overall failure. Never retry a close.
        if self.tick().is_err() {self.unknown.set(true);return false;}
        self.originals[n].state=State::Closing;
        let Some(fd)=self.originals[n].fd.take() else {self.unknown.set(true);return false;};
        let result=unistd::close(ManuallyDrop::into_inner(fd));
        self.originals[n].state=if result.is_ok() {State::Closed} else {State::Unknown};
        if result.is_err()||self.tick().is_err() {self.unknown.set(true);return false;}
        post
    }
    pub(super) fn finish(&mut self)->bool {
        self.cleanup.set(true);let mut ok=self.all().is_ok();
        for n in (0..self.originals.len()).rev() {ok=self.close(n)&&ok;}
        let states:[State;ORIGINAL_LIMIT]=std::array::from_fn(|n|self.originals.get(n).map_or(State::Absent,|row|row.state));
        ok&&final_ready_data(self.unknown.get(),self.pending.get(),Instant::now()<self.final_end,&states)
    }
    pub(super) fn roster(&mut self,root:usize,wanted:&[(&str,u64)])->Result<()> {
        roster_admission_data(wanted)?;self.roster_exact(root,wanted)
    }
    #[cfg(feature="macos-remove-observer-producer")]
    pub(super) fn roster_observer_inputs(&mut self,root:usize,wanted:&[(&str,u64)])->Result<()> {
        observer_input_roster_data(wanted)?;self.roster_exact(root,wanted)
    }
    fn roster_exact(&mut self,root:usize,wanted:&[(&str,u64)])->Result<()> {
        self.check(root)?;let row=&self.originals[root];let(parent,name)=(row.parent,row.name.clone());
        let reader=self.open(parent,&name,true,true)?;need(self.id(reader)?==self.id(root)?,"roster-original")?;
        let result=(||->Result<()> {
            let mut found=BTreeMap::new();let mut buffer=[0u8;65536];
            for turn in 0..2 {
                self.tick()?;self.pending.set(true);let result=native::directory_block(self.fd(reader)?.as_fd(),&mut buffer);self.pending.set(false);
                let used=result.map_err(|_|"root-roster")?;self.tick()?;
                if used==0 {
                    need(found.len()==wanted.len()&&wanted.iter().all(|(name,ino)|found.get(*name)==Some(ino)),"root-roster")?;
                    return Ok(());
                }
                need(turn==0,"root-roster-bound")?;let mut offset=0;
                while offset<used {
                    need(used-offset>=11,"root-roster-record")?;
                    let ino=u64::from_ne_bytes(buffer[offset..offset+8].try_into().map_err(|_|"root-roster-record")?);
                    let kind=buffer[offset+8];let len=usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                    let end=offset.checked_add(11+len).filter(|end|*end<=used).ok_or("root-roster-record")?;
                    let name=std::str::from_utf8(&buffer[offset+11..end]).map_err(|_|"root-roster-name")?;offset=end;
                    if name=="."||name==".." {continue;}
                    need(kind==nix::libc::DT_REG&&wanted.iter().any(|(value,_)|*value==name)&&found.len()<wanted.len()
                        &&ino!=0&&found.insert(name.to_owned(),ino).is_none(),"root-roster-member")?;
                }
            }
            Err("root-roster-eof")
        })();
        let closed=self.close(reader);result?;need(closed,"root-roster-close")?;self.check(root)
    }
    pub(super) fn create(&mut self,root:usize,name:&str,bytes:&[u8])->Result<usize> {
        let role=match name {"producer.json"=>ReadRole::InstallDescriptor,"producer.sig"=>ReadRole::Signature,
            "remove-producer.json"=>ReadRole::RemoveDescriptor,"remove-producer.sig"=>ReadRole::Signature,
            _=>return Err("sidecar-shape")};
        need(!bytes.is_empty()&&bytes.len() as u64<=role.policy().0,"sidecar-shape")?;
        self.all()?;let n=self.reserve(Some(root),name,true)?;let root_before=self.id(root)?;
        self.originals[n].state=State::Acquiring;
        let flags=OFlag::O_RDWR|OFlag::O_CREAT|OFlag::O_EXCL|OFlag::O_NOFOLLOW|OFlag::O_CLOEXEC|OFlag::O_NONBLOCK;
        let result=fcntl::openat(self.fd(root)?,name,flags,Mode::from_bits_truncate(0o600));self.adopt(n,result)?;
        let initial=self.observed(n)?;need(initial.uid==self.uid&&initial.mode&0o177777==0o100600
            &&initial.links==1&&initial.size==0&&initial.flags==0,"sidecar-created")?;
        self.originals[n].identity=Some(initial);
        let now=self.observed(root)?;need(root_before.ancestor(now),"created-root-original")?;
        self.originals[root].identity=Some(now);self.check(root)?;self.check(n)?;
        let mut offset=0;
        while offset<bytes.len() {
            self.check(n)?;self.tick()?;self.pending.set(true);let result=unistd::write(self.fd(n)?,&bytes[offset..]);self.pending.set(false);
            let written=result.map_err(|_|"sidecar-write")?;need(written>0&&written<=bytes.len()-offset,"sidecar-write-bound")?;
            offset+=written;let observed=self.observed(n)?;
            need(initial.ancestor(observed)&&observed.size==offset as i64,"sidecar-written-original")?;
            self.originals[n].identity=Some(observed);self.check(n)?;
        }
        self.tick()?;self.pending.set(true);let sealed=stat::fchmod(self.fd(n)?,Mode::from_bits_truncate(0o444));self.pending.set(false);
        sealed.map_err(|_|"sidecar-mode")?;
        let observed=self.observed(n)?;need(initial.object(observed)&&observed.mode&0o177777==0o100444
            &&observed.links==1&&observed.flags==0&&observed.size==bytes.len() as i64,"sidecar-sealed-original")?;
        self.originals[n].identity=Some(observed);self.check(n)?;self.attributes(n)?;
        self.tick()?;self.pending.set(true);let persisted=native::sync(self.fd(n)?.as_fd(),true);self.pending.set(false);
        persisted.map_err(|_|"sidecar-persist")?;self.check(n)?;
        let (digest,readback)=self.read(n,role)?;need(digest==hash(bytes)&&readback==bytes,"sidecar-readback")?;
        Ok(n)
    }
    pub(super) fn native_point(&self,point:ProducerCheckpoint)->Decision {
        let (phase,at,custody)=match point {ProducerCheckpoint::Before{phase,custody}=>(phase,None,custody),
            ProducerCheckpoint::Returned{phase,at,custody}=>(phase,Some(at),custody)};
        self.cleanup.set(phase.is_cleanup());
        if custody.unknown||custody.in_call||custody.gate_entered {self.unknown.set(true);return Decision::Unknown;}
        if at.is_some_and(|at|at>=if self.cleanup.get() {self.final_end} else {self.work}) {return Decision::Stop;}
        if self.all().is_ok() {Decision::Proceed} else if self.unknown.get()||self.pending.get() {Decision::Unknown} else {Decision::Stop}
    }
}
