//! Original macOS Android tool custody. Nested in installed_runtime_macos;
//! it borrows the same native failure/close vocabulary, not a runtime permit.
//! No process, provider download, registration writer or clock owner lives here.
#![forbid(unsafe_code)]
use std::{collections::{BTreeMap, BTreeSet}, os::fd::{AsFd, OwnedFd}, path::Path, time::{Duration, Instant}};
use nix::{fcntl::{self, AtFlags, OFlag}, mount::MntFlags,
    sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use mrk_macos_installed_native::{self as native, vault_filesystem::{SnapshotBook, Expected, Policy, Failure as SnapshotFailure}};
use super::{AdmissionFailure as Failure, CloseOutcome};
use crate::android_registration_protocol::records::{ContentTotals,Intent};
use crate::{android_build_protocol::{MacToolchainSelection, RootIdentity, ToolchainBinding},
    android_toolchain_macos_policy::{self as policy, Alias, FileSpec, Inventory, Provider, Registration}};

type Result<T> = std::result::Result<T, Failure>;
fn current_native_profile() -> Result<crate::android_build_protocol::Profile> {
    crate::android_build_protocol::Profile::current()
        .filter(|profile| policy::native_catalog_supports(*profile)).ok_or(Failure::Inventory)
}
const LIVE_FDS: usize = 64; // Separate tool budget; never widens runtime's 48.
const ORIGINALS: usize = policy::ENTRY_LIMIT + 256;
const READ_LIMIT: u64 = 2 * policy::TOTAL_LIMIT + 2 * (policy::MANIFEST_LIMIT + policy::RECORD_LIMIT + policy::PROVIDER_LIMIT) as u64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: i32, inode: u64, mode: u16, uid: u32, gid: u32, links: u16, size: i64,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64, flags: u32,
}
impl Identity {
    fn of(s: &FileStat) -> Self { Self { device:s.st_dev, inode:s.st_ino, mode:s.st_mode, uid:s.st_uid, gid:s.st_gid,
        links:s.st_nlink, size:s.st_size, mtime:s.st_mtime, mtime_ns:s.st_mtime_nsec, ctime:s.st_ctime,
        ctime_ns:s.st_ctime_nsec, flags:s.st_flags } }
    fn expected(self) -> Result<Expected> {
        Ok(Expected { device:u64::try_from(self.device).map_err(|_|Failure::Identity)?, inode:self.inode,
            mode:u32::from(self.mode), owner:self.uid, group:self.gid, flags:self.flags })
    }
}
struct Original { state:State, fd:Option<OwnedFd>, parent:Option<usize>, name:String, identity:Option<Identity>, empty_acl:bool, readonly:bool }
struct OriginalAlias { parent:usize, name:String, identity:Identity, target:String }
struct Membership<'a> {
    files:BTreeMap<&'a str,&'a FileSpec>, aliases:BTreeMap<&'a str,&'a Alias>, launch:Vec<String>,
}
impl<'a> Membership<'a> {
    fn new(inventory:&'a Inventory) -> Self {
        Self { files:inventory.data.files.iter().map(|f|(f.path.as_str(),f)).collect(),
            aliases:inventory.data.aliases.iter().map(|a|(a.path.as_str(),a)).collect(), launch:inventory.data.roles.launch() }
    }
}
pub(crate) struct AndroidToolchainSlots {
    selected:Option<MacToolchainSelection>, originals:Vec<Original>, aliases:Vec<OriginalAlias>, root:Option<usize>,
    headers:[Option<usize>;3], inspection_started:bool, inspected:bool, prepared:bool, closed:bool, unknown:bool,
    frame:Option<SnapshotBook>, arm_entered:bool, frame_charge:usize, live_fds:usize, read_bytes:u64, failure:Option<(Failure,Instant)>, audit:watch::Receiver<Instant>,
}
fn native_failure(_:impl std::fmt::Debug) -> Failure { Failure::Native }
fn snapshot_failure(failure:SnapshotFailure) -> Failure { match failure {
    SnapshotFailure::Refused => Failure::Ownership, SnapshotFailure::Native => Failure::Native,
    SnapshotFailure::Bounds => Failure::Bounds, SnapshotFailure::Stopped => Failure::Stopped, SnapshotFailure::Unknown => Failure::Unknown,
} }
fn metadata(stat:&FileStat, directory:bool) -> Result<Identity> {
    let expected = if directory { SFlag::S_IFDIR } else { SFlag::S_IFREG };
    if stat.st_mode & SFlag::S_IFMT.bits() != expected.bits() || stat.st_uid != 0 || stat.st_mode & 0o7022 != 0
        || !directory && stat.st_nlink != 1 { return Err(Failure::Ownership); }
    Ok(Identity::of(stat))
}
impl AndroidToolchainSlots {
    /// Inert original reservation. The same already registered inspector arms
    /// its one retained native frame only after the original GO barrier.
    pub(crate) fn new(selected:MacToolchainSelection, audit:watch::Receiver<Instant>) -> Self {
        Self::new_selection(Some(selected), audit)
    }
    fn new_selection(selected:Option<MacToolchainSelection>, audit:watch::Receiver<Instant>) -> Self {
        Self { selected, originals:Vec::new(), aliases:Vec::new(), root:None, headers:[None;3],
            inspection_started:false, inspected:false, prepared:false, closed:false, unknown:false,
            frame:None, arm_entered:false, frame_charge:0, live_fds:0, read_bytes:0, failure:None, audit }
    }
    /// Only the actual fixed adapter frame is measurable here. Opaque native
    /// filesec/ACL/qualifier allocations make this census unknown until their
    /// original references are positively quiescent. A pointer slot is not an
    /// invented zero-byte or fixed-size receipt for those allocations.
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let native=match self.frame.as_ref(){
            Some(frame) if frame.quiescent()=>frame.retained_frame_bytes(),
            Some(_)=>return None,None if !self.arm_entered=>0,None=>return None,
        };
        let mut bytes=self.originals.capacity().checked_mul(std::mem::size_of::<Original>())?
            .checked_add(self.aliases.capacity().checked_mul(std::mem::size_of::<OriginalAlias>())?)?
            .checked_add(native)?;
        for original in &self.originals{bytes=bytes.checked_add(original.name.capacity())?;}
        for alias in &self.aliases{bytes=bytes.checked_add(alias.name.capacity())?.checked_add(alias.target.capacity())?;}
        if let Some(selected)=&self.selected{
            for value in[&selected.instance,&selected.record_sha256,&selected.inventory_sha256,&selected.os_provider_sha256]{
                bytes=bytes.checked_add(value.capacity())?;
            }
        }
        Some(bytes)
    }
    fn arm_once(&mut self,end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        if self.arm_entered || self.frame.is_some(){return Err(Failure::AlreadyUsed);}
        self.point(end,Some(stop))?;
        // Entered+None after unwind/lost return remains unknown. The actual
        // returned frame (even unsuccessful) is stored before later checks.
        self.arm_entered=true;
        self.frame=Some(SnapshotBook::new());
        self.frame_charge=self.frame.as_ref().map_or(0,SnapshotBook::retained_frame_bytes);
        if self.frame_charge==0 || self.frame_charge>16_384
            || self.frame.as_ref().is_none_or(|frame|!frame.not_started()){
            return Err(Failure::Bounds);
        }
        self.point(end,Some(stop))
    }
    pub(crate) fn first_failure(&self) -> Option<(Failure,Instant)> {
        match (self.failure,self.frame.as_ref().and_then(SnapshotBook::first_failure).map(|(f,t)|(snapshot_failure(f),t))) {
            (Some(a),Some(b)) => Some(if a.1<=b.1 {a}else{b}), (a,b) => a.or(b),
        }
    }
    fn fail(&mut self, failure:Failure) -> Failure {
        let observed=self.frame.as_ref().and_then(SnapshotBook::first_failure).map(|(f,t)|(snapshot_failure(f),t)).unwrap_or((failure,Instant::now()));
        if self.failure.is_none_or(|(_,at)|observed.1<at) {self.failure=Some(observed);}
        if failure==Failure::Unknown {self.unknown=true;}
        failure
    }
    fn point(&self,end:Instant,stop:Option<&watch::Receiver<bool>>) -> Result<()> {
        if self.closed || self.unknown {return Err(Failure::Unknown);}
        if self.audit.has_changed().is_err() {return Err(Failure::Unknown);}
        let deadline=if stop.is_none() {end.min(*self.audit.borrow())} else {end};
        if Instant::now()>=deadline {return Err(Failure::Deadline);}
        if stop.is_some_and(|s| *s.borrow() || s.has_changed().is_err()) {return Err(Failure::Stopped);}
        Ok(())
    }
    fn fd(&self,index:usize) -> Result<&OwnedFd> {
        self.originals.get(index).filter(|o|o.state==State::Owned).and_then(|o|o.fd.as_ref()).ok_or(Failure::Unknown)
    }
    fn filesystem(&mut self,index:usize,end:Instant,stop:Option<&watch::Receiver<bool>>) -> Result<()> {
        self.point(end,stop)?;
        let original=self.originals.get(index).ok_or(Failure::Unknown)?;
        let identity=original.identity.ok_or(Failure::Identity)?;
        let fd=original.fd.as_ref().ok_or(Failure::Unknown)?;
        let fs=statfs::fstatfs(fd).map_err(native_failure)?;
        if fs.filesystem_type_name()!="apfs" || !fs.flags().contains(MntFlags::MNT_LOCAL)
            || fs.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP)
            || original.readonly && !fs.flags().contains(MntFlags::MNT_RDONLY) {return Err(Failure::Ownership);}
        let policy=if original.empty_acl {Policy::Empty}else{Policy::Ancestors};
        let audit=self.audit.clone();
        let observed=self.frame.as_mut().ok_or(Failure::Unknown)?.observe(fd.as_fd(),identity.expected()?,policy,&mut || {
            audit.has_changed().is_err() || Instant::now()>=if stop.is_none(){end.min(*audit.borrow())}else{end}
                || stop.is_some_and(|s|*s.borrow() || s.has_changed().is_err())
        });
        if let Err(failure)=observed {return Err(self.fail(snapshot_failure(failure)));}
        self.point(end,stop)?;
        // Exact published tool payloads have no extended attributes. Protected
        // system/installation ancestry can carry native Apple metadata; its
        // root ownership, mutation-denying ACL and (for OS code) sealed readonly
        // APFS checks, not an artificial empty-xattr rule, establish authority.
        if self.originals[index].empty_acl {
            native::no_xattrs(self.fd(index)?.as_fd()).map_err(native_failure)?;
        }
        self.point(end,stop)
    }
    fn open(&mut self,parent:Option<usize>,name:&str,directory:bool,empty_acl:bool,readonly:bool,
        end:Instant,stop:&watch::Receiver<bool>) -> Result<usize> {
        self.point(end,Some(stop))?;
        if self.originals.len()>=ORIGINALS || self.live_fds>=LIVE_FDS
            || parent.is_some() && !policy::component(name) {return Err(Failure::Bounds);}
        let index=self.originals.len();
        self.originals.push(Original {state:State::Reserved,fd:None,parent,name:name.into(),identity:None,empty_acl,readonly});
        let before=if let Some(p)=parent {stat::fstatat(self.fd(p)?,name,AtFlags::AT_SYMLINK_NOFOLLOW)}
            else {stat::lstat(Path::new("/"))}.map_err(native_failure)?;
        let identity=metadata(&before,directory)?;
        self.point(end,Some(stop))?;
        self.originals[index].state=State::Acquiring;
        let flags=OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC
            | if directory{OFlag::O_DIRECTORY}else{OFlag::empty()};
        let opened=if let Some(p)=parent {fcntl::openat(self.fd(p)?,name,flags,Mode::empty())}
            else {fcntl::open(Path::new("/"),flags,Mode::empty())};
        match opened {
            Ok(fd)=>{self.originals[index].fd=Some(fd);self.originals[index].state=State::Owned;self.live_fds+=1;},
            Err(_)=>{self.originals[index].state=State::NoHandle;return Err(Failure::Native);},
        }
        self.point(end,Some(stop))?;
        let after=stat::fstat(self.fd(index)?).map_err(native_failure)?;
        if metadata(&after,directory)?!=identity {return Err(Failure::Identity);}
        self.originals[index].identity=Some(identity);
        self.check(index,end,Some(stop))?;
        Ok(index)
    }
    fn chain(&mut self,path:&Path,end:Instant,stop:&watch::Receiver<bool>) -> Result<usize> {
        let text=path.to_str().ok_or(Failure::Bounds)?;
        if !text.starts_with('/') || text.len()>4096 {return Err(Failure::Bounds);}
        let mut parent=self.open(None,"/",true,false,false,end,stop)?;
        for part in text[1..].split('/') {
            parent=self.open(Some(parent),part,true,false,false,end,stop)?;
        }
        Ok(parent)
    }
    fn check(&mut self,index:usize,end:Instant,stop:Option<&watch::Receiver<bool>>) -> Result<()> {
        self.point(end,stop)?;
        let original=self.originals.get(index).ok_or(Failure::Unknown)?;
        let expected=original.identity.ok_or(Failure::Identity)?;
        let current=Identity::of(&stat::fstat(self.fd(index)?).map_err(native_failure)?);
        let named=Identity::of(&if let Some(p)=original.parent {
            stat::fstatat(self.fd(p)?,original.name.as_str(),AtFlags::AT_SYMLINK_NOFOLLOW)
        }else{stat::lstat(Path::new("/"))}.map_err(native_failure)?);
        if current!=expected || named!=expected {return Err(Failure::Identity);}
        self.filesystem(index,end,stop)
    }
    fn read(&mut self,index:usize,size:u64,collect:usize,end:Instant,stop:&watch::Receiver<bool>) -> Result<(String,Vec<u8>)> {
        if size>policy::FILE_LIMIT || collect>policy::MANIFEST_LIMIT
            || self.originals[index].identity.is_none_or(|id|u64::try_from(id.size).ok()!=Some(size)) {return Err(Failure::Bounds);}
        self.check(index,end,Some(stop))?;
        unistd::lseek(self.fd(index)?,0,unistd::Whence::SeekSet).map_err(native_failure)?;
        let mut hash=Sha256::new();let mut bytes=Vec::new();let mut remaining=size;let mut block=[0u8;65536];
        while remaining>0 {
            self.point(end,Some(stop))?;
            let amount=usize::try_from(remaining.min(block.len() as u64)).map_err(native_failure)?;
            let n=unistd::read(self.fd(index)?,&mut block[..amount]).map_err(native_failure)?;
            if n==0 {return Err(Failure::Inventory);}
            self.read_bytes=self.read_bytes.checked_add(n as u64).ok_or(Failure::Bounds)?;
            if self.read_bytes>READ_LIMIT {return Err(Failure::Bounds);}
            hash.update(&block[..n]);
            let take=n.min(collect.saturating_sub(bytes.len()));bytes.extend_from_slice(&block[..take]);
            remaining-=n as u64;
        }
        self.check(index,end,Some(stop))?;
        Ok((hash.finalize().iter().map(|b|format!("{b:02x}")).collect(),bytes))
    }
    fn region(&mut self,index:usize,at:u64,bytes:usize,end:Instant,stop:&watch::Receiver<bool>) -> Result<Vec<u8>> {
        if bytes>256*1024+32 || at.checked_add(bytes as u64).is_none_or(|end|
            self.originals[index].identity.is_none_or(|id|u64::try_from(id.size).ok().is_none_or(|size|end>size))) {return Err(Failure::Bounds);}
        self.point(end,Some(stop))?;
        unistd::lseek(self.fd(index)?,i64::try_from(at).map_err(native_failure)?,unistd::Whence::SeekSet).map_err(native_failure)?;
        let mut out=vec![0;bytes];let mut used=0;
        while used<bytes {
            self.point(end,Some(stop))?;
            let count=unistd::read(self.fd(index)?,&mut out[used..]).map_err(native_failure)?;
            if count==0 {return Err(Failure::Inventory);}
            used+=count;self.read_bytes=self.read_bytes.checked_add(count as u64).ok_or(Failure::Bounds)?;
            if self.read_bytes>READ_LIMIT {return Err(Failure::Bounds);}
        }
        self.check(index,end,Some(stop))?;Ok(out)
    }
    fn native_file(&mut self,index:usize,spec:&FileSpec,prefix:&[u8],inventory:Option<&Inventory>,end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        let profile=current_native_profile()?;
        let authority=crate::android_native_macos_profile::authority(profile).ok_or(Failure::Inventory)?;
        if inventory.is_some_and(|inventory|!inventory.matches_profile(profile)){return Err(Failure::Inventory);}
        if inventory.is_some() {
            if policy::android_target_elf(spec,prefix).map_err(|_|Failure::Inventory)?
                || policy::gradle_foreign_launcher(spec).map_err(|_|Failure::Inventory)? {return Ok(());}
        }
        let gradle=inventory.is_some_and(|i|spec.path==i.data.roles.gradle);
        if gradle {
            if !prefix.starts_with(b"#!/bin/sh\n") && !prefix.starts_with(b"#!/bin/sh\r\n") {return Err(Failure::Inventory);}
            return Ok(());
        }
        let sdk=if inventory.is_some() {policy::sdk35_file(spec).map_err(|_|Failure::Inventory)?} else {None};
        if let Some(kind)=sdk.filter(|kind|kind.script()) {
            if !inventory.is_some_and(|inventory|policy::sdk35_script(kind,prefix,inventory)) {return Err(Failure::Inventory);}
            return Ok(());
        }
        let architecture=if sdk.is_some_and(|kind|kind.legacy()) {policy::MachArchitecture::X86_64}
            else {authority.architecture()};
        let mandatory=spec.mode&0o111!=0 || spec.path.ends_with(".dylib") || spec.path.ends_with(".jnilib");
        let recognizable=prefix.starts_with(&[0xcf,0xfa,0xed,0xfe]) || prefix.starts_with(&[0xfe,0xed,0xfa,0xcf])
            || prefix.starts_with(&[0xca,0xfe,0xba,0xbe]) || prefix.starts_with(&[0xca,0xfe,0xba,0xbf]);
        if !mandatory && !recognizable {return Ok(());}
        let slice=policy::native_slice(prefix,spec.size,architecture).ok_or(Failure::Inventory)?;
        let header=self.region(index,slice.offset,32,end,stop)?;
        let bytes=u32::from_le_bytes(header[20..24].try_into().map_err(native_failure)?) as usize;
        let body=self.region(index,slice.offset,bytes.checked_add(32).ok_or(Failure::Bounds)?,end,stop)?;
        let commands=policy::native_commands(&body,slice,architecture).ok_or(Failure::Inventory)?;
        let accepted=match inventory {
            Some(inventory)=>policy::local_loads_for(profile,&spec.path,&commands,inventory),
            None=>commands.loads.iter().all(|load|policy::system_load(load))
                && commands.rpaths.iter().all(|path|policy::OS_ROOTS.contains(&path.as_str()) || policy::system_load(path)),
        };
        if !accepted {return Err(Failure::Inventory);}
        Ok(())
    }
    fn header_raw(&mut self,root:usize,name:&str,limit:usize,end:Instant,stop:&watch::Receiver<bool>) -> Result<(String,Vec<u8>)> {
        let index=self.open(Some(root),name,false,true,false,end,stop)?;
        let slot=[policy::MANIFEST,policy::RECORD,policy::PROVIDER].iter().position(|value|*value==name).ok_or(Failure::Inventory)?;
        if self.headers[slot].replace(index).is_some(){return Err(Failure::AlreadyUsed);}
        let identity=self.originals[index].identity.ok_or(Failure::Identity)?;
        if identity.gid!=0 || identity.mode&0o7777!=0o444 || identity.size<=0 || identity.size as usize>limit {return Err(Failure::Ownership);}
        self.read(index,identity.size as u64,limit,end,stop)
    }
    fn header(&mut self,root:usize,name:&str,limit:usize,sha:&str,end:Instant,stop:&watch::Receiver<bool>) -> Result<Vec<u8>> {
        let (observed,raw)=self.header_raw(root,name,limit,end,stop)?;
        if observed!=sha {return Err(Failure::Inventory);}Ok(raw)
    }
    fn alias(&mut self,parent:usize,name:&str,expected:&Alias,end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        self.point(end,Some(stop))?;
        if self.aliases.len()>=policy::ALIAS_COUNT {return Err(Failure::Bounds);}
        let before=stat::fstatat(self.fd(parent)?,name,AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_failure)?;
        if before.st_mode&SFlag::S_IFMT.bits()!=SFlag::S_IFLNK.bits() || before.st_uid!=0 || before.st_gid!=0
            || before.st_nlink!=1 || !(1..=512).contains(&before.st_size) {return Err(Failure::Ownership);}
        self.point(end,Some(stop))?;
        let target=fcntl::readlinkat(self.fd(parent)?,name).map_err(native_failure)?;
        if target.to_str()!=Some(expected.target.as_str()) {return Err(Failure::Inventory);}
        self.aliases.push(OriginalAlias {parent,name:name.into(),identity:Identity::of(&before),target:expected.target.clone()});
        let after=stat::fstatat(self.fd(parent)?,name,AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_failure)?;
        if Identity::of(&after)!=Identity::of(&before) {return Err(Failure::Identity);}
        self.check(parent,end,Some(stop))
    }
    fn walk(&mut self,parent:usize,relative:&str,inventory:&Inventory,membership:&Membership<'_>,seen:&mut BTreeSet<String>,depth:usize,
        end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        if depth>16 {return Err(Failure::Bounds);}
        let mut buffer=[0u8;65536];let mut names=BTreeSet::new();
        loop {
            self.point(end,Some(stop))?;
            let used=native::directory_block(self.fd(parent)?.as_fd(),&mut buffer).map_err(native_failure)?;
            if used==0 {break;}
            let mut offset=0;
            while offset<used {
                if used-offset<11 {return Err(Failure::Inventory);}
                let inode=u64::from_ne_bytes(buffer[offset..offset+8].try_into().map_err(native_failure)?);
                let kind=buffer[offset+8];
                let length=usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let next=offset.checked_add(11+length).filter(|n|*n<=used).ok_or(Failure::Inventory)?;
                let name=std::str::from_utf8(&buffer[offset+11..next]).map_err(native_failure)?.to_owned();offset=next;
                if name=="." || name==".." {continue;}
                if !policy::component(&name) || inode==0 || !names.insert(name.to_ascii_lowercase()) {return Err(Failure::Inventory);}
                let path=if relative.is_empty(){name.clone()}else{format!("{relative}/{name}")};
                if seen.len()>=policy::ENTRY_LIMIT || !seen.insert(path.clone()) {return Err(Failure::Bounds);}
                if relative.is_empty() {
                    if let Some(index)=[policy::MANIFEST,policy::RECORD,policy::PROVIDER].iter().position(|value|*value==name).and_then(|slot|self.headers[slot]) {
                        if kind!=nix::libc::DT_REG || self.originals[index].identity.is_none_or(|id|id.inode!=inode) {return Err(Failure::Inventory);}
                        self.check(index,end,Some(stop))?;continue;
                    }
                }
                if let Some(alias)=membership.aliases.get(path.as_str()) {
                    if kind!=nix::libc::DT_LNK {return Err(Failure::Inventory);}
                    self.alias(parent,&name,alias,end,stop)?;continue;
                }
                let directory=inventory.directories.contains(&path);
                if directory && kind!=nix::libc::DT_DIR || !directory && kind!=nix::libc::DT_REG {return Err(Failure::Inventory);}
                let spec=if directory {None}else{Some(*membership.files.get(path.as_str()).ok_or(Failure::Inventory)?)};
                let index=self.open(Some(parent),&name,directory,true,false,end,stop)?;
                let id=self.originals[index].identity.ok_or(Failure::Identity)?;
                let mode=spec.map_or(0o555,|s|s.mode);
                if id.inode!=inode || id.gid!=0 || u32::from(id.mode&0o7777)!=mode {return Err(Failure::Ownership);}
                if directory {self.walk(index,&path,inventory,membership,seen,depth+1,end,stop)?;}
                else if let Some(spec)=spec {
                    let (hash,prefix)=self.read(index,spec.size,256,end,stop)?;
                    if hash!=spec.sha256 {return Err(Failure::Inventory);}
                    self.native_file(index,spec,&prefix,Some(inventory),end,stop)?;
                }
                let retain=membership.launch.iter().any(|p|p==&path || p.strip_prefix(&path).is_some_and(|rest|rest.starts_with('/')));
                if !retain && !self.close(index) {return Err(Failure::Unknown);}
            }
        }
        self.check(parent,end,Some(stop))
    }
    pub(crate) fn inspect_leased_once(&mut self,intent:&Intent,end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        if self.inspection_started || self.closed || self.arm_entered || self.frame.is_some() {return Err(Failure::AlreadyUsed);}
        self.inspection_started=true;
        // Same original blocking inspector, already registered before GO.
        let result=current_native_profile().and_then(|_|self.arm_once(end,stop))
            .and_then(|_|self.inspect_inner(intent,end,stop));
        if let Err(failure)=result {self.fail(failure);}
        result
    }
    fn inspect_inner(&mut self,intent:&Intent,end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        let selected=self.selected.clone().ok_or(Failure::Inventory)?;
        if !selected.valid() || self.frame_charge==0 || self.frame.as_ref().is_none_or(|frame|self.frame_charge!=frame.retained_frame_bytes()) {return Err(Failure::Bounds);}
        self.point(end,Some(stop))?;
        if native::real_user().map_err(native_failure)?!=selected.owner_uid {return Err(Failure::Ownership);}
        let root=self.chain(&selected.root_data(),end,stop)?;self.root=Some(root);
        self.originals[root].empty_acl=true;
        let id=self.originals[root].identity.ok_or(Failure::Identity)?;
        if id.gid!=0 || id.mode&0o7777!=0o555 {return Err(Failure::Ownership);}
        self.check(root,end,Some(stop))?;
        let record=self.header(root,policy::RECORD,policy::RECORD_LIMIT,&selected.record_sha256,end,stop)?;
        let (inventory,provider)=self.read_bound_content(root,&selected,&record,intent,end,stop)?;
        // Full recovery/Start requires genuine supplier correspondence as well
        // as the existing complete file, launcher, load and OS-provider checks.
        crate::android_supplier_macos::admit_for(current_native_profile()?,&inventory,&intent.content_data().supplier_record)
            .map_err(|_|Failure::Inventory)?;
        let membership=Membership::new(&inventory);
        let mut seen=BTreeSet::new();
        self.walk(root,"",&inventory,&membership,&mut seen,0,end,stop)?;
        let expected:BTreeSet<_>=inventory.directories.iter().cloned().chain(inventory.data.files.iter().map(|f|f.path.clone()))
            .chain(inventory.data.aliases.iter().map(|a|a.path.clone()))
            .chain([policy::RECORD.into(),policy::PROVIDER.into(),policy::MANIFEST.into()]).collect();
        if seen!=expected {return Err(Failure::Inventory);}
        // OS code is an explicitly selected sealed-system provider. It is not
        // copied into the Python runtime and no OS executable is taken from PATH.
        let mut os_paths:BTreeMap<String,usize>=BTreeMap::new();
        for path in policy::OS_ROOTS.iter().copied().chain(provider.files.iter().map(|f|f.path.as_str())) {
            let is_root=policy::OS_ROOTS.contains(&path);
            let parts:Vec<_>=path[1..].split('/').collect();let mut parent=None;let mut full=String::new();
            for (position,name) in parts.iter().enumerate() {
                full.push('/');full.push_str(name);
                if let Some(index)=os_paths.get(&full) {parent=Some(*index);continue;}
                if parent.is_none() {
                    let slash=if let Some(index)=os_paths.get("/"){*index}else{
                        let index=self.open(None,"/",true,false,false,end,stop)?;os_paths.insert("/".into(),index);index};
                    parent=Some(slash);
                }
                let directory=position+1<parts.len() || is_root;
                let index=self.open(parent,name,directory,false,true,end,stop)?;
                os_paths.insert(full.clone(),index);parent=Some(index);
            }
            if !is_root {
                let index=parent.ok_or(Failure::Unknown)?;
                let spec=provider.files.iter().find(|f|f.path==path).ok_or(Failure::Inventory)?;
                if self.originals[index].identity.is_none_or(|id|id.gid!=0 || u32::from(id.mode&0o7777)!=spec.mode) {return Err(Failure::Ownership);}
                let (hash,prefix)=self.read(index,spec.size,256,end,stop)?;
                if hash!=spec.sha256 {return Err(Failure::Inventory);}
                self.native_file(index,spec,&prefix,None,end,stop)?;
            }
        }
        self.inspected=true;
        self.check_current(end,Some(stop))
    }
    /// Narrow M2 hook over the SAME original metadata readers and validators.
    /// It compares copied totals, not copied+sealed-provider read-budget totals.
    fn read_bound_content(&mut self,root:usize,selected:&MacToolchainSelection,record:&[u8],intent:&Intent,
        end:Instant,stop:&watch::Receiver<bool>) -> Result<(Inventory,Provider)> {
        let profile=current_native_profile()?;
        if !Registration::parse_for(profile,record,selected.owner_uid,&selected.instance).is_some_and(|r|r.matches_for(profile,selected)){
            return Err(Failure::Inventory);
        }
        let provider_raw=self.header(root,policy::PROVIDER,policy::PROVIDER_LIMIT,&selected.os_provider_sha256,end,stop)?;
        let provider=Provider::parse_for(profile,&provider_raw,selected).ok_or(Failure::Inventory)?;
        let manifest_raw=self.header(root,policy::MANIFEST,policy::MANIFEST_LIMIT,&selected.inventory_sha256,end,stop)?;
        let inventory=policy::parse_manifest_for(profile,&manifest_raw,selected).ok_or(Failure::Inventory)?;
        let payload_bytes=inventory.data.files.iter().try_fold(0u64,|n,f|n.checked_add(f.size)).ok_or(Failure::Bounds)?;
        let metadata_bytes=(record.len() as u64).checked_add(provider_raw.len() as u64)
            .and_then(|n|n.checked_add(manifest_raw.len() as u64)).ok_or(Failure::Bounds)?;
        let totals=ContentTotals{
            files:inventory.data.files.len().try_into().map_err(|_|Failure::Bounds)?,
            directories:inventory.directories.len().try_into().map_err(|_|Failure::Bounds)?,
            aliases:inventory.data.aliases.len().try_into().map_err(|_|Failure::Bounds)?,
            payload_bytes,metadata_bytes,
        };
        let content=intent.content_data();
        let payload_digest:[u8;32]=Sha256::digest(&manifest_raw).into();
        let provider_digest:[u8;32]=Sha256::digest(&provider_raw).into();
        if content.payload_inventory!=payload_digest || content.os_provider!=provider_digest || content.totals!=totals {
            return Err(Failure::Inventory);
        }
        // Preserve the original larger full native/provider read-budget check.
        let read_total=provider.files.iter().try_fold(payload_bytes,|n,f|n.checked_add(f.size)).ok_or(Failure::Bounds)?;
        if read_total>policy::TOTAL_LIMIT{return Err(Failure::Bounds);}
        Ok((inventory,provider))
    }
    fn check_current(&mut self,end:Instant,stop:Option<&watch::Receiver<bool>>) -> Result<()> {
        self.point(end,stop)?;
        if native::real_user().map_err(native_failure)?!=self.selected.as_ref().ok_or(Failure::Inventory)?.owner_uid {return Err(Failure::Ownership);}
        for index in 0..self.originals.len() {
            if self.originals[index].state==State::Owned {self.check(index,end,stop)?;}
        }
        // Disposed non-launch descriptors are not reopened. Their complete
        // hash/name check and protected root ancestry established immutability.
        for alias in &self.aliases {
            if self.originals[alias.parent].state!=State::Owned {continue;}
            self.point(end,stop)?;
            let current=stat::fstatat(self.fd(alias.parent)?,alias.name.as_str(),AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_failure)?;
            if Identity::of(&current)!=alias.identity {return Err(Failure::Identity);}
            let target=fcntl::readlinkat(self.fd(alias.parent)?,alias.name.as_str()).map_err(native_failure)?;
            if target.to_str()!=Some(alias.target.as_str()) {return Err(Failure::Identity);}
        }
        self.point(end,stop)
    }
    pub(crate) fn binding_data(&self) -> Result<ToolchainBinding> {
        if !self.inspected || self.closed || self.unknown || self.first_failure().is_some() {return Err(Failure::Unknown);}
        let id=self.root.and_then(|i|self.originals[i].identity).ok_or(Failure::Identity)?;
        let selected=self.selected.as_ref().ok_or(Failure::Inventory)?;
        ToolchainBinding::new_macos_data(current_native_profile()?,&selected.root_data(),RootIdentity {device:id.device.to_string(),inode:id.inode.to_string(),
            mode:u32::from(id.mode),uid:id.uid,gid:id.gid},selected).map_err(|_|Failure::Inventory)
    }
    pub(crate) fn check_before_spawn(&mut self,end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        if !self.inspected || self.prepared || self.first_failure().is_some() {return Err(Failure::AlreadyUsed);}
        let result=self.check_current(end,Some(stop));
        if let Err(failure)=result {self.fail(failure);} else {self.prepared=true;}
        result
    }
    pub(crate) fn check_after_use(&mut self,end:Instant) -> Result<()> {
        if !self.prepared || self.first_failure().is_some() {return Err(Failure::Unknown);}
        let result=self.check_current(end,None);
        if let Err(failure)=result {self.fail(failure);}
        result
    }
    fn close(&mut self,index:usize) -> bool {
        let original=&mut self.originals[index];
        match original.state {
            State::Reserved=>original.state=State::NoHandle,
            State::Owned=>{
                original.state=State::Closing;
                match original.fd.take().map(unistd::close) {
                    Some(Ok(()))=>{original.state=State::Closed;self.live_fds-=1;},
                    _=>{original.state=State::Unknown;self.unknown=true;},
                }
            },
            State::NoHandle|State::Closed=>{},
            _=>self.unknown=true,
        }
        if self.unknown {self.fail(Failure::Unknown);}
        !self.unknown
    }
    fn fd_cleanup_expired(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,
        publish:&mut dyn FnMut(Failure,Instant)) -> bool {
        let first=self.first_failure();
        if let Some((failure,at))=first {publish(failure,at);}
        let expired=super::android_runtime::fd_cleanup_expired_at(end,cleanup,first.map(|(_,at)|at),Instant::now());
        if expired {
            self.unknown=true;self.fail(Failure::Unknown);
            if let Some((failure,at))=self.first_failure(){publish(failure,at);}
        }
        expired
    }
    pub(crate) fn settle_originals(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,publish:&mut dyn FnMut(Failure,Instant)) -> CloseOutcome {
        if self.closed {publish(Failure::Unknown,Instant::now());return CloseOutcome::Unknown;}
        // Keep cleanup independent of integrity reads; the caller supplies its
        // original monotonically shortening cleanup projection, never a reset.
        let cutoff=cleanup.clone();let original_failure=self.first_failure();
        if let Some((failure,at))=original_failure {publish(failure,at);}
        let released=match self.frame.as_mut() {
            Some(frame)=>frame.release(&mut |failure| {
                if let Some((failure,at))=failure {publish(snapshot_failure(failure),at);}
                let first=match(original_failure,failure) { (Some((_,a)),Some((_,b)))=>Some(a.min(b)),
                    (Some((_,at)),None)|(None,Some((_,at)))=>Some(at), _=>None };
                let deadline=first.and_then(|t|t.checked_add(Duration::from_secs(10))).map_or(end,|t|t.min(end));
                cutoff.has_changed().is_err() || Instant::now()>=deadline.min(*cutoff.borrow())
            }),
            None=>!self.arm_entered,
        };
        if !released {self.unknown=true;self.fail(Failure::Unknown);}
        // Publish the actual native failure before any later consuming close.
        // The callback only updates the original owner's failure/cutoff DATA;
        // it must never acquire Registry or DocumentBinding while borrowing us.
        if let Some((failure,at))=self.first_failure(){publish(failure,at);}
        // Native uncertainty cannot become success through FD closes. Known
        // independent positives may consume only within ORIGINAL cleanup time.
        // Retain expired positives; record a late real return without retry.
        for index in (0..self.originals.len()).rev() {
            if self.originals[index].state==State::Owned {
                if self.fd_cleanup_expired(end,cleanup,publish) {continue;}
                self.close(index);
                let _=self.fd_cleanup_expired(end,cleanup,publish);
            } else {self.close(index);}
            if let Some((failure,at))=self.first_failure(){publish(failure,at);}
        }
        self.closed=true;
        if self.settled(){CloseOutcome::Settled}else{CloseOutcome::Unknown}
    }
    pub(crate) fn settled(&self) -> bool {
        let native=match self.frame.as_ref() {
            Some(frame)=>frame.settled() && frame.retained_frame_bytes()==0,
            None=>!self.arm_entered,
        };
        self.closed && !self.unknown && self.live_fds==0 && native
            && self.originals.iter().all(|o|o.fd.is_none() && matches!(o.state,State::Closed|State::NoHandle))
    }
    pub(crate) fn mark_interrupted(&mut self) {self.unknown=true;self.fail(Failure::Unknown);}
}


/// One read-only metadata row. The containing compulsory M2 wrapper reserves
/// all32 inert instances before GO, binds each once under its independent SH,
/// and retains that SH through actual group settlement and owner joins.
#[derive(Clone,Debug)]
pub(crate) struct MetadataCandidate{
    pub(crate) selection:MacToolchainSelection,
    pub(crate) versions:crate::android_toolchain_catalog::Versions,
}
pub(crate) struct AndroidMetadataSlots{
    original:AndroidToolchainSlots,started:bool,
}
impl AndroidMetadataSlots{
    pub(crate) fn new(audit:watch::Receiver<Instant>)->Self{
        Self{original:AndroidToolchainSlots::new_selection(None,audit),started:false}
    }
    pub(crate) fn retained_bytes(&self)->Option<usize>{self.original.retained_bytes()}
    pub(crate) fn first_failure(&self)->Option<(Failure,Instant)>{self.original.first_failure()}
    pub(crate) fn mark_interrupted(&mut self){self.original.mark_interrupted();}
    pub(crate) fn settle_originals(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,
        publish:&mut dyn FnMut(Failure,Instant))->CloseOutcome{
        self.original.settle_originals(end,cleanup,publish)
    }
    pub(crate) fn settled(&self)->bool{self.original.settled()}
    pub(crate) fn inspect_once(&mut self,key:[u8;16],account:u32,generation:u32,intent:&Intent,
        end:Instant,stop:&watch::Receiver<bool>)->Result<MetadataCandidate>{
        if self.started || self.original.closed{return Err(Failure::AlreadyUsed);}
        self.started=true;
        let result=current_native_profile().and_then(|_|self.original.arm_once(end,stop))
            .and_then(|_|self.inspect_inner(key,account,generation,intent,end,stop));
        if let Err(failure)=result{self.original.fail(failure);}result
    }
    fn inspect_inner(&mut self,key:[u8;16],account:u32,generation:u32,intent:&Intent,
        end:Instant,stop:&watch::Receiver<bool>)->Result<MetadataCandidate>{
        if key==[0;16] || account==0 || account==u32::MAX || generation==0 || generation==u32::MAX
            || self.original.selected.is_some(){return Err(Failure::Inventory);}
        self.original.point(end,Some(stop))?;
        if native::real_user().map_err(native_failure)?!=account{return Err(Failure::Ownership);}
        let instance=crate::android_shared_lease_macos::hex(&key);
        let path=std::path::Path::new(crate::android_build_protocol::MAC_TOOLCHAIN_PREFIX)
            .join(account.to_string()).join(&instance);
        let root=self.original.chain(&path,end,stop)?;
        self.original.root=Some(root);self.original.originals[root].empty_acl=true;
        let id=self.original.originals[root].identity.ok_or(Failure::Identity)?;
        if id.gid!=0 || id.mode&0o7777!=0o555{return Err(Failure::Ownership);}
        self.original.check(root,end,Some(stop))?;
        let (record_sha256,record)=self.original.header_raw(root,policy::RECORD,policy::RECORD_LIMIT,end,stop)?;
        let parsed=Registration::parse_for(current_native_profile()?,&record,account,&instance).ok_or(Failure::Inventory)?;
        let selected=MacToolchainSelection{instance,owner_uid:account,catalog_generation:generation,
            record_sha256,inventory_sha256:parsed.inventory_sha256,os_provider_sha256:parsed.os_provider_sha256};
        if !selected.valid(){return Err(Failure::Inventory);}
        self.original.selected=Some(selected.clone());
        let (inventory,_provider)=self.original.read_bound_content(root,&selected,&record,intent,end,stop)?;
        let versions=&inventory.data.versions;
        let candidate=MetadataCandidate{selection:selected,versions:crate::android_toolchain_catalog::Versions{
            jdk_vendor:versions.jdk_vendor.clone(),jdk_version:versions.jdk_version.clone(),
            gradle_version:versions.gradle_version.clone(),agp_version:versions.agp_version.clone(),
            sdk_platform:versions.sdk_platform.clone(),sdk_build_tools_version:versions.sdk_build_tools_version.clone()}};
        self.original.check_current(end,Some(stop))?;
        Ok(candidate)
    }
}

// Historical inert-constructor DATA regression only. This does not provide a
// production unleased catalog entrypoint or Start compatibility path.
#[cfg(test)]
pub(crate) struct AndroidCatalogSlots{original:AndroidToolchainSlots}
#[cfg(test)]
impl AndroidCatalogSlots{
    pub(crate) fn new(audit:watch::Receiver<Instant>)->Self{Self{original:AndroidToolchainSlots::new_selection(None,audit)}}
    pub(crate) fn retained_bytes(&self)->Option<usize>{self.original.retained_bytes()}
    pub(crate) fn settle_originals(&mut self,end:Instant,publish:&mut dyn FnMut(Failure,Instant))->CloseOutcome{
        let cleanup=self.original.audit.clone();self.original.settle_originals(end,&cleanup,publish)
    }
    pub(crate) fn settled(&self)->bool{self.original.settled()}
}

#[cfg(test)]
mod inert_arm_tests {
    use super::*;
    #[test]
    fn independent_tool_fd_consumes_share_the_original_cleanup_clock_data() {
        assert!(super::super::android_runtime::fd_cleanup_data_check());
    }
    pub(super) fn android_catalog_constructor_is_inert_and_lost_frame_return_is_not_finality_data() {
        // Control DATA only: no SnapshotBook constructor/native API is called.
        assert_eq!(current_native_profile().ok(), crate::android_build_protocol::Profile::current()
            .filter(|profile|policy::native_catalog_supports(*profile)));
        assert!(crate::android_native_macos_profile::authority(crate::android_build_protocol::Profile::MacX64).is_none());
        let end=Instant::now()+Duration::from_secs(30);
        let (_send,read)=watch::channel(end);
        let mut catalog=AndroidCatalogSlots::new(read);
        assert!(catalog.original.frame.is_none() && !catalog.original.arm_entered);
        assert_eq!(catalog.retained_bytes(),Some(0));
        catalog.original.arm_entered=true;
        assert_eq!(catalog.retained_bytes(),None);
        let mut failure=None;
        assert_eq!(catalog.settle_originals(end,&mut |reason,at|failure=Some((reason,at))),CloseOutcome::Unknown);
        assert_eq!(failure.map(|(reason,_)|reason),Some(Failure::Unknown));
        assert!(!catalog.settled());
        assert_eq!(catalog.retained_bytes(),None);
    }
    #[test]
    fn android_catalog_constructor_is_inert_and_lost_frame_return_is_not_finality() { android_catalog_constructor_is_inert_and_lost_frame_return_is_not_finality_data(); }

}

// Explicit harness=false DATA bridge; ordinary libtest wrappers use these same
// inert bodies. No native custody, task, Prepare/Start or qualification is granted.
#[cfg(test)]
pub(super) fn assert_inert_arm_data_contract() {
    inert_arm_tests::android_catalog_constructor_is_inert_and_lost_frame_return_is_not_finality_data();
}
