//! Protected macOS Android registration publisher.
//!
//! The service callback receives only bounded DATA. This module is run by one
//! original Rust worker registered behind GO, never on an NSXPC callback. The
//! separate coordinator observes its actual JoinHandle. No tool is executed as
//! root; selected sources are never reopened by pathname in this process.
#![forbid(unsafe_code)]
use std::{
    collections::{BTreeMap, BTreeSet}, mem::ManuallyDrop,
    os::fd::{AsFd, OwnedFd}, path::Path, sync::Arc, time::Instant,
};
use nix::{errno::Errno, fcntl::{self, AtFlags, OFlag}, mount::MntFlags,
    sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};
use sha2::{Digest, Sha256};
use mrk_macos_installed_native::{self as native,
    android_registration::{Bounds, Ingress, Packet, Signal, TERMINAL_BYTES},
    android_lease::{self as lease, LockAttempt, LockState},
    vault_filesystem::{SnapshotBook, Expected, Policy, Failure as SnapshotFailure,
        lease_writer::{LeaseWriterBook, FreshExpected}},
    vault_helper_wire::ClockBridge};
use crate::{
    android_build_protocol::MacToolchainSelection,
    android_registration_protocol::{self as transfer, preparation::{Hello, Metadata, MetadataChunk},
        records::{LeaseBinding, LeaseIdentityData, ContentTotals, Intent, ACCOUNT_ATTEMPT_LIMIT, LEASE_HEADER_BYTES, INTENT_BYTES}},
    android_toolchain_macos_policy::{self as policy, Inventory, Provider, Registration, FileSpec},
};

type Result<T> = std::result::Result<T, Problem>;
const LIVE_FDS: usize = 64;
const ORIGINAL_CONTROL_BYTES: usize = 32 * 1024 * 1024;
const ORIGINAL_LIMIT: usize = policy::ENTRY_LIMIT * 36 + 512; // full path originals, max16 components
const READ_LIMIT: u64 = 2 * policy::TOTAL_LIMIT + 16 * 1024 * 1024;
const SUPPORT: [&str; 3] = ["Library", "Application Support", "MobileReleaseKit"];
// Includes simultaneously live packet copy, prefix/header/region/read/roster
// blocks, original path chains and recursion strings, bounded Intent codecs,
// terminal candidates/error prefixes and small native argument/format cells.
const IO_WORK_BYTES:usize=1024*1024;
const SUPPLIER_WORK_BYTES:usize=512*1024;
const ACCOUNT_NODE_BYTES:usize=512; // (i32,u64)/(u64,u64): <=472B/node
const NAME_NODE_BYTES:usize=512;    // String/ZST: <=384B/node
const ROSTER_NODE_BYTES:usize=1024; // String/(u64,u8): <=560B/node
fn arc_bytes<T>()->usize{
    #[repr(C)] struct Allocation<T>{counts:[usize;2],data:T}
    std::mem::size_of::<Allocation<T>>()
}
fn exact_name(name:&str)->Result<String>{
    let mut out=String::new();out.try_reserve_exact(name.len()).map_err(|_|Problem::Bounds)?;
    if out.capacity()!=name.len(){return Err(Problem::Bounds);}
    out.push_str(name);Ok(out)
}
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
struct RosterLimit{entries:usize,names:usize}
impl RosterLimit{
    fn account(suffix:usize)->Self{Self{entries:ACCOUNT_ATTEMPT_LIMIT,names:ACCOUNT_ATTEMPT_LIMIT*(32+suffix)}}
    fn accepts(self,entries:usize,names:usize)->bool{entries<=self.entries && names<=self.names}
}
fn child_name<'a>(path:&'a str,parent:&str)->Option<&'a str>{
    let (actual,name)=path.rsplit_once('/').unwrap_or(("",path));
    (actual==parent).then_some(name)
}
#[derive(Clone,Copy,Debug)]
struct EffectCensus{originals:usize,creations:usize,original_names:usize,creation_names:usize,accounted:usize,bytes:usize}
fn add(total:&mut usize,more:usize)->Option<()>{*total=total.checked_add(more)?;Some(())}
fn path_originals(path:&str,basename:bool,count:&mut usize,names:&mut usize)->Option<()>{
    let mut parts=path.split('/').peekable();
    while let Some(part)=parts.next(){
        if basename || parts.peek().is_some(){add(count,1)?;add(names,part.len())?;}
    }Some(())
}

pub(crate) use crate::android_registration_protocol::terminal::Problem;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State { Reserved, Calling, Held, NoHandle, Closing, Closed, Moved, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role { Ancestor, Directory, Reader, PayloadWriter, MetadataWriter, Lease }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect { Entered, Applied, Refused, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: i32, inode: u64, mode: u16, uid: u32, gid: u32, links: u16,
    bytes: i64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64, flags: u32,
}
impl Identity {
    fn of(value: &FileStat) -> Self {
        Self { device: value.st_dev, inode: value.st_ino, mode: value.st_mode, uid: value.st_uid,
            gid: value.st_gid, links: value.st_nlink, bytes: value.st_size, mtime: value.st_mtime,
            mtime_ns: value.st_mtime_nsec, ctime: value.st_ctime, ctime_ns: value.st_ctime_nsec, flags: value.st_flags }
    }
    fn same_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.uid == other.uid && self.gid == other.gid
            && self.mode & SFlag::S_IFMT.bits() == other.mode & SFlag::S_IFMT.bits() && self.flags == other.flags
    }
    fn expected(self) -> Result<Expected> {
        Ok(Expected { device: u64::try_from(self.device).map_err(|_| Problem::Ownership)?, inode: self.inode,
            mode: self.mode.into(), owner: self.uid, group: self.gid, flags: self.flags })
    }
    fn lock_expected(self) -> Result<lease::Expected> {
        Ok(lease::Expected { device: u64::try_from(self.device).map_err(|_| Problem::Ownership)?, inode: self.inode,
            mode: self.mode.into(), owner: self.uid, group: self.gid, links: self.links.into(),
            bytes: u64::try_from(self.bytes).map_err(|_| Problem::Ownership)?, flags: self.flags,
            modified_seconds: self.mtime, modified_nanoseconds: self.mtime_ns.try_into().map_err(|_| Problem::Ownership)?,
            changed_seconds: self.ctime, changed_nanoseconds: self.ctime_ns.try_into().map_err(|_| Problem::Ownership)? })
    }
}
struct Original {
    // Deliberately not ordinary RAII. Losing a worker must not silently unlock
    // the last EX before the coordinator knows what happened to other originals.
    fd: Option<ManuallyDrop<OwnedFd>>, state: State, role: Role, parent: Option<usize>,
    name: String, identity: Option<Identity>, immutable: bool,
}
struct Creation { parent: usize, name: String, effect: Effect, identity: Option<Identity>, allocated: Option<u64> }
struct Writing { file: usize, chain: Vec<usize>, ordinal: usize }
struct Prepared {
    hello: Hello, selected: MacToolchainSelection, inventory: Inventory, provider: Provider,
    raw: [Vec<u8>; 3], totals: ContentTotals,
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn unhex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 { return None; }
    let mut out = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let one = |byte| match byte { b'0'..=b'9' => Some(byte-b'0'), b'a'..=b'f' => Some(byte-b'a'+10), _ => None };
        out[index] = one(pair[0])?.checked_mul(16)?.checked_add(one(pair[1])?)?;
    }
    Some(out)
}
impl Prepared {
    fn from_metadata(metadata: Metadata, account: u32, cap:usize) -> Result<Self> {
        let (hello, raw) = metadata.into_complete().map_err(|_| Problem::Inventory)?;
        let selected = MacToolchainSelection { instance: hex(&hello.instance), owner_uid: account,
            // Parser comparison DATA only; never a user catalog selection.
            catalog_generation: 1, record_sha256: hex(&hello.hashes[1]),
            inventory_sha256: hex(&hello.hashes[0]), os_provider_sha256: hex(&hello.hashes[2]) };
        let raw_bytes=raw.iter().try_fold(0usize,|sum,bytes|sum.checked_add(bytes.capacity())).ok_or(Problem::Bounds)?;
        let selected_bytes=[&selected.instance,&selected.record_sha256,&selected.inventory_sha256,&selected.os_provider_sha256]
            .into_iter().try_fold(0usize,|sum,value|sum.checked_add(value.capacity())).ok_or(Problem::Bounds)?;
        let remaining=cap.checked_sub(Publisher::fixed_owned_bytes().ok_or(Problem::Bounds)?)
            .and_then(|n|n.checked_sub(raw_bytes)).and_then(|n|n.checked_sub(selected_bytes)).ok_or(Problem::Bounds)?;
        let inventory=policy::parse_manifest_bounded(&raw[0],&selected,remaining).ok_or(Problem::Inventory)?;
        let remaining=remaining.checked_sub(inventory.dynamic_bytes().ok_or(Problem::Bounds)?).ok_or(Problem::Bounds)?;
        let record=Registration::parse_bounded(&raw[1],account,&selected.instance,remaining).ok_or(Problem::Binding)?;
        if !record.matches(&selected){return Err(Problem::Binding);}
        drop(record); // no simultaneous discarded record String graph in Provider parsing
        let provider=Provider::parse_bounded(&raw[2],&selected,remaining).ok_or(Problem::Inventory)?;
        // A signed peer, version string or caller's claimed supplier SHA is not
        // complete archive→installed-byte provenance. The shipping catalogue
        // remains deliberately unavailable until genuine Mac supplier evidence
        // is independently reviewed and pinned; no Linux/source-path fallback.
        crate::android_supplier_macos::admit(&inventory, &hello.supplier_record).map_err(|_| Problem::SupplierUnavailable)?;
        let payload_bytes = inventory.data.files.iter().try_fold(0_u64, |sum, file| sum.checked_add(file.size)).ok_or(Problem::Bounds)?;
        let totals = ContentTotals { files: inventory.data.files.len().try_into().map_err(|_| Problem::Bounds)?,
            directories: inventory.directories.len().try_into().map_err(|_| Problem::Bounds)?,
            aliases: inventory.data.aliases.len().try_into().map_err(|_| Problem::Bounds)?,
            payload_bytes, metadata_bytes: raw.iter().map(|value| value.len() as u64).sum() };
        if totals.content_bytes().is_none_or(|bytes| bytes > transfer::MAX_BYTES)
            || totals.entries().is_none_or(|count| count as usize > transfer::MAX_FILES) { return Err(Problem::Bounds); }
        Ok(Self { hello, selected, inventory, provider, raw, totals })
    }
    fn paths(&self)->impl Iterator<Item=&str>{
        self.inventory.directories.iter().map(String::as_str)
            .chain(self.inventory.data.files.iter().map(|v|v.path.as_str()))
            .chain(self.inventory.data.aliases.iter().map(|v|v.path.as_str()))
    }
    fn roster_limit(&self,parent:&str,metadata:bool)->Option<RosterLimit>{
        let mut limit=RosterLimit::default();
        for path in self.paths(){
            if let Some(name)=child_name(path,parent){add(&mut limit.entries,1)?;add(&mut limit.names,name.len())?;}
        }
        if metadata && parent.is_empty(){
            for name in [policy::MANIFEST,policy::RECORD,policy::PROVIDER]{add(&mut limit.entries,1)?;add(&mut limit.names,name.len())?;}
        }
        Some(limit)
    }
    fn expected_child(&self,parent:&str,name:&str,metadata:bool)->bool{
        self.paths().any(|path|child_name(path,parent)==Some(name))
            || metadata && parent.is_empty() && [policy::MANIFEST,policy::RECORD,policy::PROVIDER].contains(&name)
    }
    fn dynamic_bytes(&self)->Option<usize>{
        let strings=[&self.selected.instance,&self.selected.record_sha256,&self.selected.inventory_sha256,&self.selected.os_provider_sha256]
            .into_iter().try_fold(0usize,|sum,value|sum.checked_add(value.capacity()))?;
        self.raw.iter().try_fold(strings,|sum,value|sum.checked_add(value.capacity()))?
            .checked_add(self.inventory.dynamic_bytes()?)?.checked_add(self.provider.dynamic_bytes()?)
    }
}
impl EffectCensus{
    fn for_prepared(prepared:&Prepared,account:u32,cap:usize)->Option<Self>{
        // Exactly the source traversal's original multiplicities; do not reserve
        // ORIGINAL_LIMIT worst-case descriptors or assume all names are255B.
        let account_digits=account.to_string().len();
        let fixed_names=["android","android-leases","android-registration","intent.json","stage"]
            .iter().map(|v|v.len()).sum::<usize>()+3*account_digits+32+37;
        let mut originals=14usize;
        let mut original_names=1+SUPPORT.iter().map(|v|v.len()).sum::<usize>()+fixed_names;
        let mut creation_names=fixed_names;
        for path in &prepared.inventory.directories{
            path_originals(path,true,&mut originals,&mut original_names)?;
            add(&mut creation_names,path.rsplit('/').next()?.len())?;
        }
        for file in &prepared.inventory.data.files{
            path_originals(&file.path,true,&mut originals,&mut original_names)?;
            add(&mut creation_names,file.path.rsplit('/').next()?.len())?;
        }
        for alias in &prepared.inventory.data.aliases{
            path_originals(&alias.path,false,&mut originals,&mut original_names)?;
            add(&mut creation_names,alias.path.rsplit('/').next()?.len())?;
        }
        for name in [policy::MANIFEST,policy::RECORD,policy::PROVIDER]{
            add(&mut originals,2)?;add(&mut original_names,name.len().checked_mul(2)?)?;add(&mut creation_names,name.len())?;
        }
        for file in &prepared.provider.files{
            add(&mut originals,1)?;add(&mut original_names,1)?;
            path_originals(file.path.strip_prefix('/')?,true,&mut originals,&mut original_names)?;
        }
        let mut basename_bytes=0usize;let mut path_bytes=0usize;let mut entries=0usize;
        for path in prepared.paths(){
            add(&mut entries,1)?;add(&mut path_bytes,path.len())?;add(&mut basename_bytes,path.rsplit('/').next()?.len())?;
        }
        for path in prepared.inventory.directories.iter().map(String::as_str)
            .chain(prepared.inventory.data.files.iter().map(|v|v.path.as_str())){
            add(&mut originals,1)?;add(&mut original_names,path.rsplit('/').next()?.len())?;
        }
        let creations=entries.checked_add(13)?;
        if originals>ORIGINAL_LIMIT || entries.checked_add(3)?>policy::ENTRY_LIMIT || creations>policy::ENTRY_LIMIT+64{return None;}
        let accounted=creations.checked_add(SUPPORT.len()+1)?;
        let mut bytes=Publisher::fixed_owned_bytes()?.checked_add(prepared.dynamic_bytes()?)?;
        for value in [
            originals.checked_mul(std::mem::size_of::<Original>())?,
            creations.checked_mul(std::mem::size_of::<Creation>())?,original_names,creation_names,
            prepared.inventory.data.files.len().checked_mul(std::mem::size_of::<transfer::File>())?,arc_bytes::<()>(),
            accounted.checked_add(1)?.checked_mul(ACCOUNT_NODE_BYTES)?,
            entries.checked_add(4)?.checked_mul(NAME_NODE_BYTES)?, // seen +3 metadata + split
            path_bytes.checked_add(policy::MANIFEST.len()+policy::RECORD.len()+policy::PROVIDER.len())?,
            // One map per recursion level. All retained child rosters together
            // have <=entries logical keys; +17 covers empty/split roots.
            entries.checked_add(20)?.checked_mul(ROSTER_NODE_BYTES)?,
            basename_bytes.checked_add(policy::MANIFEST.len()+policy::RECORD.len()+policy::PROVIDER.len())?,
            entries.checked_add(4)?.checked_mul(NAME_NODE_BYTES)?,
            basename_bytes.checked_add(policy::MANIFEST.len()+policy::RECORD.len()+policy::PROVIDER.len())?, // one active folded set
            // Fixed account rosters (including the two simultaneous rename
            // readbacks) and the account-attempt union, never ENTRY_LIMIT each.
            3*(ACCOUNT_ATTEMPT_LIMIT+1)*(ROSTER_NODE_BYTES+NAME_NODE_BYTES),
            6*ACCOUNT_ATTEMPT_LIMIT*37,
        ]{add(&mut bytes,value)?;}
        (bytes<=cap && cap<=ORIGINAL_CONTROL_BYTES).then_some(Self{originals,creations,original_names,creation_names,accounted,bytes})
    }
}

/// Reserved with service custody BEFORE original worker GO. Constructor is
/// inert: no native allocator, clock, directory, process or service is entered.
pub(crate) struct Publisher {
    ingress: Arc<Ingress>, signal: Arc<Signal>, clock: Option<ClockBridge>, originals: Vec<Original>,
    creations: Vec<Creation>, snapshot: Option<SnapshotBook>, lease_acl: LeaseWriterBook,
    lease_call: LockAttempt, entered: bool, in_native: bool, unknown: bool,
    first: Option<Problem>, errors: Vec<Problem>, hello: Option<Hello>, metadata: Option<Metadata>,
    prepared: Option<Arc<Prepared>>, transfer: Option<transfer::Transfer>, packet: Option<Packet>,
    writing: Option<Writing>, stage: Option<usize>, registration: Option<usize>, destination: Option<usize>,
    lease: Option<usize>, lease_binding: Option<LeaseBinding>, publish: Option<Effect>, stage_sealed: bool,
    stage_identity: Option<Identity>, read_bytes: u64, written_bytes: u64, content_files: u32,
    content_aliases: u32, accounted: BTreeMap<(i32, u64), (u64, u64)>, accounting_unknown: bool,
    final_started: bool, final_attempted: bool, final_closed: bool, last_raw: u64,
    final_result: Option<lease::GuardedClose>, control_cap: usize, control_precharged: bool,
    effects_prepared:bool,original_names_left:usize,creation_names_left:usize,account_limit:usize,
}
impl Publisher {
    pub(crate) fn new(ingress: Arc<Ingress>) -> Self {
        Self { signal: ingress.signal().clone(), ingress, clock: None, originals: Vec::new(), creations: Vec::new(),
            snapshot: None, lease_acl: LeaseWriterBook::new(), lease_call: LockAttempt::new(), entered: false,
            in_native: false, unknown: false, first: None, errors: Vec::new(), hello: None, metadata: None,
            prepared: None, transfer: None, packet: None, writing: None, stage: None, registration: None,
            destination: None, lease: None, lease_binding: None, publish: None, stage_sealed: false,
            stage_identity: None, read_bytes: 0, written_bytes: 0, content_files: 0, content_aliases: 0,
            accounted: BTreeMap::new(), accounting_unknown: false, final_started: false, final_attempted: false, final_closed: false,
            last_raw: 0, final_result: None, control_cap: ORIGINAL_CONTROL_BYTES, control_precharged: false,
            effects_prepared:false,original_names_left:0,creation_names_left:0,account_limit:0 }
    }
    /// Reserve the existing32MiB working role, not process RSS. Typed metadata
    /// parsing is bounded before entry; its admitted input shape then fixes the
    /// complete effect high-water before any native/frame/filesystem operation.
    pub(crate) fn service_precharge(&mut self,cap:usize)->Result<()> {
        if self.entered || self.control_precharged || cap==0 || cap>ORIGINAL_CONTROL_BYTES {
            return Err(Problem::Bounds);
        }
        let Some(bytes)=Self::service_high_water()else{return Err(Problem::Bounds);};
        if bytes>cap{return Err(Problem::Bounds);}
        self.errors.try_reserve_exact(64).map_err(|_|Problem::Bounds)?;
        if self.errors.capacity()!=64{return Err(Problem::Bounds);}
        self.control_cap=cap;self.control_precharged=true;Ok(())
    }
    fn fixed_owned_bytes()->Option<usize>{
        std::mem::size_of::<Self>().checked_add(arc_bytes::<Prepared>())?
            .checked_add(native::vault_filesystem::SNAPSHOT_FRAME_BYTES)?
            .checked_add(native::vault_filesystem::LEASE_WRITER_FRAME_BYTES)?
            .checked_add(policy::NATIVE_WORK_BYTES)?.checked_add(SUPPLIER_WORK_BYTES)?
            .checked_add(crate::android_supplier_macos::CACHE_WORK_BYTES)?
            .checked_add(IO_WORK_BYTES)?.checked_add(64*std::mem::size_of::<Problem>())
    }
    pub(crate) fn service_high_water()->Option<usize>{
        let minimum=Self::fixed_owned_bytes()?.checked_add(policy::MANIFEST_LIMIT)?
            .checked_add(policy::RECORD_LIMIT)?.checked_add(policy::PROVIDER_LIMIT)?;
        (minimum<=ORIGINAL_CONTROL_BYTES).then_some(ORIGINAL_CONTROL_BYTES)
    }
    fn prepare_effects(&mut self,prepared:&Prepared,account:u32)->Result<()>{
        if self.effects_prepared || !self.control_precharged || !self.originals.is_empty() || !self.creations.is_empty(){
            return Err(self.fail(Problem::Unknown));
        }
        let census=EffectCensus::for_prepared(prepared,account,self.control_cap).ok_or(Problem::Bounds)?;
        if census.bytes>self.control_cap{return Err(self.fail(Problem::Bounds));}
        self.originals.try_reserve_exact(census.originals).map_err(|_|Problem::Bounds)?;
        self.creations.try_reserve_exact(census.creations).map_err(|_|Problem::Bounds)?;
        if self.originals.capacity()!=census.originals || self.creations.capacity()!=census.creations{return Err(self.fail(Problem::Bounds));}
        let mut files=Vec::new();files.try_reserve_exact(prepared.inventory.data.files.len()).map_err(|_|Problem::Bounds)?;
        if files.capacity()!=prepared.inventory.data.files.len(){return Err(self.fail(Problem::Bounds));}
        for file in &prepared.inventory.data.files{
            files.push(transfer::File{bytes:file.size,sha256:unhex(&file.sha256).ok_or(Problem::Inventory)?});
        }
        self.transfer=Some(transfer::Transfer::new(transfer::Identity{transaction:prepared.hello.transaction,inventory:prepared.hello.hashes[0]},
            files,prepared.totals.entries().ok_or(Problem::Bounds)? as usize).map_err(|_|Problem::Bounds)?);
        self.original_names_left=census.original_names;self.creation_names_left=census.creation_names;
        self.account_limit=census.accounted;self.effects_prepared=true;Ok(())
    }
    fn fail(&mut self, problem: Problem) -> Problem {
        // Earliest F reaches the independent mailbox BEFORE any owner/queue
        // projection. No raw path/error/credential is copied to a result.
        self.signal.failure_now(problem == Problem::Unknown);
        if problem == Problem::Unknown { self.unknown = true; }
        if self.first.is_none() { self.first = Some(problem); }
        if self.errors.len() < 64 { self.errors.push(problem); } else { self.unknown = true; }
        problem
    }
    fn point(&mut self, cleanup: bool) -> Result<()> {
        // A moved tail cannot be re-entered even when its shim did NOT enter.
        if self.final_started || self.in_native {
            self.signal.clock_unknown(); self.unknown = true; return Err(Problem::Unknown);
        }
        let Some(now) = native::vault_helper_wire::uptime() else {
            self.signal.clock_unknown(); self.unknown = true; return Err(Problem::Unknown);
        };
        if now < self.last_raw || self.signal.bounds().is_none_or(|bounds| now < bounds.origin)
            || now >= (1_u64 << 61) {
            self.signal.clock_unknown(); self.unknown = true; return Err(Problem::Unknown);
        }
        self.last_raw = now;
        if !self.signal.admitted_at(cleanup, now) { return Err(self.fail(Problem::Stopped)); }
        Ok(())
    }
    fn fd(&self, index: usize) -> Result<&OwnedFd> {
        self.originals.get(index).filter(|value| value.state == State::Held)
            .and_then(|value| value.fd.as_ref()).map(|value| &**value).ok_or(Problem::Unknown)
    }
    fn identity(&self, index: usize) -> Result<Identity> { self.originals.get(index).and_then(|value| value.identity).ok_or(Problem::Unknown) }
    fn observed<T, E>(&mut self, value: std::result::Result<T, E>, problem: Problem) -> Result<T> {
        // No OwnedFd/native allocation is passed here: acquisitions are adopted
        // first, before any post-return check can fail.
        match value { Ok(value) => { self.point(false)?; Ok(value) }, Err(_) => Err(self.fail(problem)) }
    }
    fn reserve(&mut self, parent: Option<usize>, name: &str, role: Role) -> Result<usize> {
        self.point(false)?;
        if !self.effects_prepared || self.originals.len()>=self.originals.capacity() || self.originals.len()>=ORIGINAL_LIMIT
            || self.originals.iter().filter(|value|value.fd.is_some()).count()>=LIVE_FDS || name.len()>self.original_names_left
            || !(name=="/" && parent.is_none() || policy::component(name)){return Err(self.fail(Problem::Bounds));}
        let owned_name=exact_name(name)?;self.original_names_left-=owned_name.capacity();
        let index=self.originals.len();
        self.originals.push(Original{fd:None,state:State::Reserved,role,parent,name:owned_name,identity:None,immutable:false});
        Ok(index)
    }
    fn named(&mut self, parent: Option<usize>, name: &str, cleanup: bool) -> Result<FileStat> {
        self.point(cleanup)?; self.in_native = true;
        let observed = if let Some(parent) = parent {
            self.fd(parent).and_then(|fd| stat::fstatat(fd, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| Problem::Native))
        } else { stat::lstat(Path::new("/")).map_err(|_| Problem::Native) };
        self.in_native = false;
        let value = observed.map_err(|problem| self.fail(problem))?; self.point(cleanup)?; Ok(value)
    }
    fn fstat(&mut self, index: usize, cleanup: bool) -> Result<FileStat> {
        self.point(cleanup)?; self.in_native = true;
        let observed = self.fd(index).and_then(|fd| stat::fstat(fd).map_err(|_| Problem::Native));
        self.in_native = false;
        let value = observed.map_err(|problem| self.fail(problem))?; self.point(cleanup)?; Ok(value)
    }
    fn check_original(&mut self, index: usize, exact: bool, cleanup: bool) -> Result<()> {
        let before = self.identity(index)?; let actual = Identity::of(&self.fstat(index, cleanup)?);
        let parent = self.originals[index].parent; let name = self.originals[index].name.clone();
        let named = Identity::of(&self.named(parent, &name, cleanup)?);
        if named != actual || if exact { actual != before } else { !before.same_object(actual) } {
            return Err(self.fail(Problem::Ownership));
        }
        Ok(())
    }
    fn protect(&mut self, index: usize, mode: Option<u32>, policy: Policy) -> Result<()> {
        let value = self.fstat(index, false)?; let id = Identity::of(&value);
        if value.st_uid != 0 || value.st_mode & 0o7022 != 0
            || !matches!(value.st_mode & SFlag::S_IFMT.bits(), kind if kind == SFlag::S_IFREG.bits() || kind == SFlag::S_IFDIR.bits())
            || value.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFREG.bits() && value.st_nlink != 1
            || mode.is_some_and(|mode| value.st_gid != 0 || u32::from(value.st_mode & 0o7777) != mode || value.st_flags != 0) {
            return Err(self.fail(Problem::Ownership));
        }
        self.point(false)?; self.in_native = true;
        let filesystem = self.fd(index).and_then(|fd| statfs::fstatfs(fd).map_err(|_| Problem::Native));
        self.in_native = false; let filesystem = filesystem.map_err(|problem| self.fail(problem))?; self.point(false)?;
        if filesystem.filesystem_type_name() != "apfs" || !filesystem.flags().contains(MntFlags::MNT_LOCAL)
            || filesystem.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP) {
            return Err(self.fail(Problem::Ownership));
        }
        let signal = self.signal.clone();
        let fd = self.originals[index].fd.as_ref().ok_or(Problem::Unknown)?.as_fd();
        let book = self.snapshot.as_mut().ok_or(Problem::Unknown)?;
        let outcome = book.observe(fd, id.expected()?, policy, &mut || !signal.admitted(false));
        if let Some((problem, event)) = book.first_failure() {
            if let Some(clock) = &self.clock { signal.local_failure(clock, event, problem == SnapshotFailure::Unknown); }
            else { signal.failure_now(true); }
        }
        if outcome.is_err() { return Err(self.fail(Problem::Ownership)); }
        self.point(false)?;
        if !matches!(policy, Policy::Ancestors) {
            self.in_native = true;
            let outcome = self.fd(index).and_then(|fd| native::no_xattrs(fd.as_fd()).map_err(|_| Problem::Native));
            self.in_native = false;
            self.observed(outcome, Problem::Ownership)?;
        }
        Ok(())
    }
    fn adopt(&mut self, index: usize, opened: nix::Result<OwnedFd>, creation: Option<usize>) -> Result<usize> {
        match opened {
            Ok(fd) => {
                self.originals[index].fd = Some(ManuallyDrop::new(fd)); self.originals[index].state = State::Held;
                if let Some(effect) = creation { self.creations[effect].effect = Effect::Applied; }
            }
            Err(error) => {
                self.originals[index].state = State::NoHandle;
                if let Some(effect) = creation {
                    self.creations[effect].effect = if error == Errno::EEXIST { Effect::Refused } else { Effect::Unknown };
                    if error != Errno::EEXIST { self.unknown = true; self.accounting_unknown = true; }
                }
                return Err(self.fail(if error == Errno::EEXIST { Problem::Collision } else { Problem::Native }));
            }
        }
        self.point(false)?;
        let value = self.fstat(index, false)?;
        self.originals[index].identity = Some(Identity::of(&value));
        if let Some(effect) = creation { self.creations[effect].identity = Some(Identity::of(&value)); }
        self.check_original(index, true, false)?; Ok(index)
    }
    fn open(&mut self, parent: Option<usize>, name: &str, directory: bool, role: Role) -> Result<usize> {
        let index = self.reserve(parent, name, role)?;
        let before = Identity::of(&self.named(parent, name, false)?);
        let kind = if directory { SFlag::S_IFDIR } else { SFlag::S_IFREG };
        if before.mode & SFlag::S_IFMT.bits() != kind.bits() || !directory && before.links != 1 {
            return Err(self.fail(Problem::Ownership));
        }
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC
            | if directory { OFlag::O_DIRECTORY } else { OFlag::empty() };
        self.point(false)?; self.originals[index].state = State::Calling; self.in_native = true;
        let opened = if let Some(parent) = parent {
            let fd = self.fd(parent)?; fcntl::openat(fd, name, flags, Mode::empty())
        } else { fcntl::open(Path::new("/"), flags, Mode::empty()) };
        self.in_native = false; self.adopt(index, opened, None)?;
        if self.identity(index)? != before { return Err(self.fail(Problem::Ownership)); }
        Ok(index)
    }
    fn effect(&mut self, parent: usize, name: &str) -> Result<usize> {
        if !self.effects_prepared || self.creations.len()>=self.creations.capacity() || self.creations.len()>=policy::ENTRY_LIMIT+64
            || name.len()>self.creation_names_left || !policy::component(name){return Err(self.fail(Problem::Bounds));}
        let owned_name=exact_name(name)?;self.creation_names_left-=owned_name.capacity();
        let index=self.creations.len();
        self.creations.push(Creation{parent,name:owned_name,effect:Effect::Entered,identity:None,allocated:None});
        Ok(index)
    }
    fn create_file(&mut self, parent: usize, name: &str, role: Role) -> Result<usize> {
        let index = self.reserve(Some(parent), name, role)?; let effect = self.effect(parent, name)?;
        self.point(false)?; self.originals[index].state = State::Calling; self.in_native = true;
        let opened = fcntl::openat(self.fd(parent)?, name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600));
        self.in_native = false; self.adopt(index, opened, Some(effect))?;
        self.protect(index, Some(0o600), Policy::Empty)?;
        if self.identity(index)?.bytes != 0 { return Err(self.fail(Problem::Ownership)); }
        Ok(index)
    }
    fn normalize_new(&mut self, index: usize, mode: u32) -> Result<()> {
        let before = self.identity(index)?;
        if before.uid != 0 || before.mode & 0o7077 != 0 { return Err(self.fail(Problem::Ownership)); }
        self.check_original(index, true, false)?; self.point(false)?; self.in_native = true;
        let outcome = unistd::fchown(self.fd(index)?, Some(unistd::Uid::from_raw(0)), Some(unistd::Gid::from_raw(0)));
        self.in_native = false; self.observed(outcome, Problem::Ownership)?;
        self.point(false)?; self.in_native = true;
        let outcome = stat::fchmod(self.fd(index)?, Mode::from_bits_truncate(mode as u16));
        self.in_native = false; self.observed(outcome, Problem::Ownership)?;
        let actual = Identity::of(&self.fstat(index, false)?);
        if actual.device != before.device || actual.inode != before.inode || actual.uid != 0 || actual.gid != 0
            || u32::from(actual.mode & 0o7777) != mode { return Err(self.fail(Problem::Ownership)); }
        self.originals[index].identity = Some(actual);
        self.protect(index, Some(mode), Policy::Empty)
    }
    fn directory(&mut self, parent: usize, name: &str, fresh: bool, mode: u32) -> Result<usize> {
        let effect = self.effect(parent, name)?; self.point(false)?; self.in_native = true;
        let outcome = stat::mkdirat(self.fd(parent)?, name, Mode::from_bits_truncate(0o700));
        self.in_native = false;
        let created = match outcome {
            Ok(()) => { self.creations[effect].effect = Effect::Applied; true }
            Err(Errno::EEXIST) if !fresh => { self.creations[effect].effect = Effect::Refused; false }
            Err(error) => {
                self.creations[effect].effect = if error == Errno::EEXIST { Effect::Refused } else { Effect::Unknown };
                if error != Errno::EEXIST { self.unknown = true; self.accounting_unknown = true; }
                return Err(self.fail(if error == Errno::EEXIST { Problem::Collision } else { Problem::Native }));
            }
        };
        let index = self.open(Some(parent), name, true, Role::Directory)?;
        self.creations[effect].identity = Some(self.identity(index)?);
        if created { self.normalize_new(index, mode)?; }
        else { self.protect(index, Some(mode), Policy::Empty)?; }
        if created {
            self.creations[effect].identity = Some(self.identity(index)?);
            self.persist(parent, false, false)?; self.account(index, false)?;
        }
        Ok(index)
    }
    fn persist(&mut self, index: usize, file: bool, cleanup: bool) -> Result<()> {
        self.point(cleanup)?; self.in_native = true;
        let outcome = self.fd(index).and_then(|fd| native::sync(fd.as_fd(), file).map_err(|_| Problem::Persist));
        self.in_native = false;
        if let Err(problem) = outcome {
            self.signal.failure_now(true); self.unknown = true;
            return Err(self.fail(problem));
        }
        self.point(cleanup)
    }
    fn account(&mut self, index: usize, cleanup: bool) -> Result<()> {
        let value = self.fstat(index, cleanup)?;
        if !self.identity(index)?.same_object(Identity::of(&value)) {
            return Err(self.fail(Problem::Ownership));
        }
        let logical = u64::try_from(value.st_size).map_err(|_| Problem::Bounds)?;
        let allocated = u64::try_from(value.st_blocks).ok().and_then(|blocks| blocks.checked_mul(512)).ok_or(Problem::Bounds)?;
        let key = (value.st_dev, value.st_ino);
        if !self.accounted.contains_key(&key) && self.accounted.len() >= self.account_limit {
            return Err(self.fail(Problem::Bounds));
        }
        self.accounted.insert(key, (logical, allocated));
        for effect in &mut self.creations {
            if effect.identity.is_some_and(|identity| identity.device == value.st_dev && identity.inode == value.st_ino) {
                effect.allocated = Some(allocated);
            }
        }
        Ok(())
    }
    fn attributable(&self, index: usize) -> bool {
        let Some(original) = self.originals.get(index) else { return false; };
        // Complete current allocation of fixed MRK directories is a conservative
        // charge, not a claim to have freed their preexisting/shared storage.
        matches!(original.role, Role::Directory | Role::PayloadWriter | Role::MetadataWriter)
            || self.creations.iter().any(|effect| effect.effect == Effect::Applied
                && (effect.parent == index || effect.identity.is_some_and(|id|
                    original.identity.is_some_and(|actual| id.same_object(actual)))))
    }
    fn accounting_complete(&self) -> bool {
        !self.accounting_unknown && self.creations.iter().all(|creation|
            creation.effect == Effect::Refused || creation.effect == Effect::Applied
                && creation.identity.is_some() && creation.allocated.is_some())
            && self.accounted.values().try_fold(0_u64, |sum, (bytes, _)| sum.checked_add(*bytes)).is_some()
            && self.accounted.values().try_fold(0_u64, |sum, (_, bytes)| sum.checked_add(*bytes)).is_some()
    }
    fn close(&mut self, index: usize) -> bool {
        if matches!(self.originals[index].state, State::Closed | State::NoHandle) { return true; }
        if self.lease == Some(index) { self.fail(Problem::Unknown); return false; }
        if self.point(true).is_err() { return false; }
        if self.originals[index].state == State::Held && self.attributable(index) {
            // Refresh on the SAME held original, including failure cleanup,
            // BEFORE consuming it. A failed observation never becomes a zero
            // output count or a reason to retry/reopen an uncertain descriptor.
            if self.account(index, true).is_err() { self.accounting_unknown = true; }
            if self.point(true).is_err() { return false; }
        }
        match self.originals[index].state {
            State::Reserved => { self.originals[index].state = State::NoHandle; true }
            State::Closed | State::NoHandle => true,
            State::Held => {
                self.originals[index].state = State::Closing;
                let Some(fd) = self.originals[index].fd.take() else { self.fail(Problem::Unknown); return false; };
                self.in_native = true;
                let outcome = unistd::close(ManuallyDrop::into_inner(fd));
                self.in_native = false;
                self.originals[index].state = if outcome.is_ok() { State::Closed } else { State::Unknown };
                if outcome.is_err() { self.fail(Problem::Unknown); }
                // Actual known close stays Closed even if the original deadline
                // elapsed during the call. No retry or reopening is permitted.
                let timely = self.point(true).is_ok();
                outcome.is_ok() && timely
            }
            _ => { self.fail(Problem::Unknown); false }
        }
    }
    fn close_chain(&mut self, chain: Vec<usize>) -> Result<()> {
        let mut known = true;
        for index in chain.into_iter().rev() { known &= self.close(index); }
        if known { Ok(()) } else { Err(self.fail(Problem::Unknown)) }
    }
    fn path_parent(&mut self, path: &str, directory_mode: u32) -> Result<(usize, String, Vec<usize>)> {
        if !policy::relative(path) { return Err(self.fail(Problem::Inventory)); }
        let mut parent = self.stage.ok_or(Problem::Unknown)?; let mut chain = Vec::new();
        chain.try_reserve_exact(16).map_err(|_|Problem::Bounds)?;
        if chain.capacity()!=16{return Err(self.fail(Problem::Bounds));}
        let mut parts = path.split('/').peekable();
        while let Some(name) = parts.next() {
            if parts.peek().is_none() { return Ok((parent, exact_name(name)?, chain)); }
            if chain.len()>=chain.capacity(){return Err(self.fail(Problem::Bounds));}
            parent = self.open(Some(parent), name, true, Role::Directory)?;
            chain.push(parent); self.protect(parent, Some(directory_mode), Policy::Empty)?;
        }
        Err(self.fail(Problem::Inventory))
    }
    fn write(&mut self, index: usize, mut bytes: &[u8]) -> Result<()> {
        let ceiling = transfer::MAX_BYTES + INTENT_BYTES as u64 + LEASE_HEADER_BYTES as u64;
        if self.written_bytes.checked_add(bytes.len() as u64).is_none_or(|total| total > ceiling) {
            return Err(self.fail(Problem::Bounds));
        }
        while !bytes.is_empty() {
            self.point(false)?; self.in_native = true;
            let outcome = unistd::write(self.fd(index)?, bytes);
            self.in_native = false;
            let count = match outcome {
                Ok(count) if count > 0 && count <= bytes.len() => count,
                _ => { self.signal.failure_now(true); self.unknown = true; self.accounting_unknown = true; return Err(self.fail(Problem::Native)); }
            };
            self.written_bytes = self.written_bytes.checked_add(count as u64).ok_or(Problem::Bounds)?;
            bytes = &bytes[count..]; self.point(false)?;
        }
        Ok(())
    }
    fn seal_file(&mut self, index: usize, mode: u32) -> Result<()> {
        self.check_original(index, false, false)?;
        self.point(false)?; self.in_native = true;
        let outcome = stat::fchmod(self.fd(index)?, Mode::from_bits_truncate(mode as u16));
        self.in_native = false; self.observed(outcome, Problem::Ownership)?;
        self.protect(index, Some(mode), Policy::Empty)?; self.persist(index, true, false)?;
        let identity = Identity::of(&self.fstat(index, false)?);
        self.originals[index].identity = Some(identity); self.originals[index].immutable = true;
        self.check_original(index, true, false)?; self.account(index, false)?;
        if self.close(index) { Ok(()) } else { Err(self.fail(Problem::Unknown)) }
    }
    fn roster(&mut self,index:usize,limit:RosterLimit)->Result<BTreeMap<String,(u64,u8)>>{self.roster_inner(index,true,limit)}
    fn roster_inner(&mut self,index:usize,named:bool,limit:RosterLimit)->Result<BTreeMap<String,(u64,u8)>>{
        if limit.entries>policy::ENTRY_LIMIT || limit.names>limit.entries.checked_mul(255).ok_or(Problem::Bounds)?{
            return Err(self.fail(Problem::Bounds));
        }
        let before=Identity::of(&self.fstat(index,false)?);
        let mut names=BTreeMap::new();let mut folded=BTreeSet::new();let mut block=[0_u8;65536];
        let(mut name_bytes,mut rows)=(0usize,0usize);
        self.point(false)?; self.in_native = true;
        let outcome = unistd::lseek(self.fd(index)?, 0, unistd::Whence::SeekSet);
        self.in_native = false; self.observed(outcome, Problem::Native)?;
        loop {
            self.point(false)?; self.in_native = true;
            let outcome = native::directory_block(self.fd(index)?.as_fd(), &mut block);
            self.in_native = false; let used = self.observed(outcome, Problem::Native)?;
            if used==0{break;}if used>block.len(){return Err(self.fail(Problem::Unknown));}
            let mut offset=0;
            while offset<used{
                rows=rows.checked_add(1).ok_or(Problem::Bounds)?;
                if rows>limit.entries+2 || used-offset<11{return Err(self.fail(Problem::Inventory));}
                let inode = u64::from_ne_bytes(block[offset..offset+8].try_into().map_err(|_| Problem::Inventory)?);
                let kind = block[offset+8];
                let length = usize::from(u16::from_ne_bytes([block[offset+9], block[offset+10]]));
                let next = offset.checked_add(11+length).filter(|end| *end <= used).ok_or(Problem::Inventory)?;
                let name = std::str::from_utf8(&block[offset+11..next]).map_err(|_| Problem::Inventory)?; offset = next;
                if name == "." || name == ".." { continue; }
                let next_names=name_bytes.checked_add(name.len()).ok_or(Problem::Bounds)?;
                if inode==0 || !policy::component(name) || !limit.accepts(names.len()+1,next_names)
                    || !matches!(kind,nix::libc::DT_DIR|nix::libc::DT_REG|nix::libc::DT_LNK){
                    return Err(self.fail(Problem::Inventory));
                }
                // Size/name gates precede BOTH nodes and both String copies.
                let lowered=name.to_ascii_lowercase();
                if lowered.capacity()>name.len() || !folded.insert(lowered)
                    || names.insert(exact_name(name)?,(inode,kind)).is_some(){return Err(self.fail(Problem::Inventory));}
                name_bytes=next_names;
            }
        }
        let after = Identity::of(&self.fstat(index, false)?);
        if before != after { return Err(self.fail(Problem::Ownership)); }
        if named { self.check_original(index, false, false)?; }
        else if !self.identity(index)?.same_object(after) { return Err(self.fail(Problem::Ownership)); }
        Ok(names)
    }
    fn census(&mut self, lease_parent: usize, attempt_parent: usize) -> Result<()> {
        let mut attempts = BTreeSet::new();
        for (parent, suffix, kind) in [(lease_parent, ".lock", nix::libc::DT_REG), (attempt_parent, "", nix::libc::DT_DIR)] {
            for (name, (_, actual)) in self.roster(parent,RosterLimit::account(suffix.len()))? {
                let Some(instance) = name.strip_suffix(suffix) else { return Err(self.fail(Problem::Inventory)); };
                if actual != kind || unhex::<16>(instance).is_none() { return Err(self.fail(Problem::Inventory)); }
                attempts.insert(instance.to_owned());
                if attempts.len() >= ACCOUNT_ATTEMPT_LIMIT { return Err(self.fail(Problem::Bounds)); }
            }
        }
        Ok(())
    }
    fn start_filesystem(&mut self, prepared: Arc<Prepared>, account: u32) -> Result<()> {
        self.prepare_effects(&prepared,account)?;
        self.point(false)?; self.clock = ClockBridge::capture();
        if self.clock.is_none() { return Err(self.fail(Problem::Unknown)); }
        self.in_native = true; self.snapshot = Some(SnapshotBook::new()); self.in_native = false;
        self.point(false)?;
        let root = self.open(None, "/", true, Role::Ancestor)?; self.protect(root, None, Policy::Ancestors)?;
        let mut support = root;
        for name in SUPPORT { support = self.open(Some(support), name, true, Role::Ancestor)?; self.protect(support, None, Policy::Ancestors)?; }
        let android = self.directory(support, "android", false, 0o755)?;
        let destination = self.directory(android, &account.to_string(), false, 0o755)?;
        let leases = self.directory(support, "android-leases", false, 0o755)?;
        let lease_parent = self.directory(leases, &account.to_string(), false, 0o755)?;
        let attempts = self.directory(support, "android-registration", false, 0o700)?;
        let attempt_parent = self.directory(attempts, &account.to_string(), false, 0o700)?;
        self.census(lease_parent, attempt_parent)?;
        self.destination = Some(destination);
        let lease_name = prepared.selected.instance.clone() + ".lock";
        let lease_index = self.create_file(lease_parent, &lease_name, Role::Lease)?;
        self.lease = Some(lease_index);
        let expected = self.identity(lease_index)?.lock_expected()?;
        let signal = self.signal.clone(); let clock = self.clock.as_ref().ok_or(Problem::Unknown)?;
        let fd = self.originals[lease_index].fd.as_ref().ok_or(Problem::Unknown)?.as_fd();
        let acquired = self.lease_call.acquire(fd, expected, lease::Mode::FreshExclusive, &mut |first| {
            if let Some((problem, event)) = first { signal.local_failure(clock, event, problem == lease::Failure::Unknown); }
            !signal.admitted(false)
        });
        if acquired.is_err() { return Err(self.fail(Problem::Ownership)); }
        self.point(false)?;
        self.in_native = true;
        let principal = native::vault_filesystem::lease_writer::principal(account);
        self.in_native = false; let principal = self.observed(principal, Problem::Ownership)?;
        let binding = LeaseBinding::new(account, principal, prepared.hello.instance, prepared.hello.transaction).map_err(|_| Problem::Binding)?;
        self.write(lease_index, &binding.encode().map_err(|_| Problem::Binding)?)?;
        let before = Identity::of(&self.fstat(lease_index, false)?);
        self.originals[lease_index].identity = Some(before);
        let expected = FreshExpected { identity: before.expected()?, links: before.links.into(), bytes: before.bytes.try_into().map_err(|_| Problem::Bounds)?,
            modified_seconds: before.mtime, modified_nanoseconds: before.mtime_ns, changed_seconds: before.ctime, changed_nanoseconds: before.ctime_ns };
        let signal = self.signal.clone(); let clock = self.clock.as_ref().ok_or(Problem::Unknown)?;
        let fd = self.originals[lease_index].fd.as_ref().ok_or(Problem::Unknown)?.as_fd();
        let applied = self.lease_acl.apply(fd, expected, account, principal, &mut |first| {
            if let Some((problem, event)) = first { signal.local_failure(clock, event, problem == SnapshotFailure::Unknown); }
            !signal.admitted(false)
        });
        if applied.is_err() { return Err(self.fail(Problem::Ownership)); }
        self.point(false)?; self.in_native = true;
        let changed = stat::fchmod(self.fd(lease_index)?, Mode::from_bits_truncate(0o400));
        self.in_native = false; self.observed(changed, Problem::Ownership)?;
        self.protect(lease_index, Some(0o400), Policy::LeaseUser { uid: account, principal })?;
        self.persist(lease_index, true, false)?; self.persist(lease_parent, false, false)?;
        let original = Identity::of(&self.fstat(lease_index, false)?);
        self.originals[lease_index].identity = Some(original); self.originals[lease_index].immutable = true;
        self.check_original(lease_index, true, false)?; self.account(lease_index, false)?;
        // Read the exact finalized header back through THIS original EX-held
        // descriptor. Input bytes or a recomputed planned header are not durable
        // readback evidence, and a reopened path cannot replace this original.
        let (header_digest, header) = self.read(lease_index, LEASE_HEADER_BYTES as u64, LEASE_HEADER_BYTES)?;
        if LeaseBinding::decode(&header).map_err(|_| Problem::Binding)? != binding {
            return Err(self.fail(Problem::Binding));
        }
        let header_sha256 = unhex::<32>(&header_digest).ok_or(Problem::Binding)?;
        if binding.header_sha256().map_err(|_| Problem::Binding)? != header_sha256 {
            return Err(self.fail(Problem::Binding));
        }
        let lease_data = LeaseIdentityData {
            device: original.device.try_into().map_err(|_| Problem::Ownership)?, inode: original.inode, mode: original.mode.into(),
            uid: original.uid, gid: original.gid, links: original.links.into(), bytes: original.bytes.try_into().map_err(|_| Problem::Ownership)?,
            modified_seconds: original.mtime, modified_nanoseconds: original.mtime_ns.try_into().map_err(|_| Problem::Ownership)?,
            changed_seconds: original.ctime, changed_nanoseconds: original.ctime_ns.try_into().map_err(|_| Problem::Ownership)?,
            flags: original.flags, header_sha256 };
        let intent = Intent::new(binding, lease_data, prepared.hello.source_consent, prepared.hello.supplier_record,
            prepared.hello.hashes[0], prepared.hello.hashes[2], prepared.totals).map_err(|_| Problem::Binding)?;
        let registration = self.directory(attempt_parent, &prepared.selected.instance, true, 0o700)?;
        self.registration = Some(registration); self.lease_binding = Some(binding);
        let original_intent = self.create_file(registration, "intent.json", Role::MetadataWriter)?;
        self.write(original_intent, &intent.encode().map_err(|_| Problem::Inventory)?)?;
        self.seal_file(original_intent, 0o400)?; self.persist(registration, false, false)?; self.persist(attempt_parent, false, false)?;
        // No payload writer or stage exists before the ORIGINAL EX and durable
        // bound intent+parents. A crash here consumes the permanent attempt.
        let stage = self.directory(registration, "stage", true, 0o700)?; self.stage = Some(stage);
        for path in &prepared.inventory.directories {
            let (parent, name, chain) = self.path_parent(path, 0o700)?;
            let directory = self.directory(parent, &name, true, 0o700)?;
            if !self.close(directory) { return Err(self.fail(Problem::Unknown)); }
            self.close_chain(chain)?;
        }
        self.prepared = Some(prepared); Ok(())
    }
    fn payload(&mut self, raw: &[u8]) -> Result<bool> {
        let (frame, bytes) = transfer::Frame::decode(raw).map_err(|_| Problem::Transfer)?;
        let prepared = self.prepared.as_ref().ok_or(Problem::Unknown)?.clone();
        let permit = self.transfer.as_mut().ok_or(Problem::Unknown)?.admit(frame, bytes).map_err(|_| Problem::Transfer)?;
        match frame.kind {
            transfer::Kind::Begin => {
                if self.writing.is_some() { return Err(self.fail(Problem::Unknown)); }
                let spec = prepared.inventory.data.files.get(frame.file as usize).ok_or(Problem::Transfer)?;
                let (parent, name, chain) = self.path_parent(&spec.path, 0o700)?;
                let file = self.create_file(parent, &name, Role::PayloadWriter)?;
                self.writing = Some(Writing { file, chain, ordinal: frame.file as usize });
            }
            transfer::Kind::Data => {
                let file = self.writing.as_ref().filter(|writing| writing.ordinal == frame.file as usize).ok_or(Problem::Transfer)?.file;
                self.write(file, bytes)?;
            }
            transfer::Kind::End => {
                let writing = self.writing.as_ref().ok_or(Problem::Transfer)?;
                let file = writing.file;
                let spec = prepared.inventory.data.files.get(writing.ordinal).ok_or(Problem::Transfer)?;
                if self.fstat(file, false)?.st_size != i64::try_from(spec.size).map_err(|_| Problem::Bounds)? { return Err(self.fail(Problem::Inventory)); }
                self.seal_file(file, spec.mode)?;
                self.content_files = self.content_files.checked_add(1).ok_or(Problem::Bounds)?;
                let writing = self.writing.take().ok_or(Problem::Unknown)?;
                self.close_chain(writing.chain)?;
            }
            transfer::Kind::Finish => {
                if self.writing.is_some() { return Err(self.fail(Problem::Unknown)); }
                // Caller acknowledges/retires THIS original input packet and
                // seals ingress before acknowledging the Transfer Finish permit.
                let packet = self.packet.take().ok_or(Problem::Unknown)?;
                self.ingress.acknowledge(packet, self.transfer.as_ref().ok_or(Problem::Unknown)?.written()).map_err(|_| Problem::Unknown)?;
                self.ingress.seal().map_err(|_| Problem::Unknown)?;
                if !self.ingress.input_settled() { return Err(self.fail(Problem::Unknown)); }
            }
        }
        self.transfer.as_mut().ok_or(Problem::Unknown)?.acknowledge(permit).map_err(|_| Problem::Transfer)?;
        Ok(frame.kind == transfer::Kind::Finish)
    }
    fn read(&mut self, index: usize, size: u64, prefix_limit: usize) -> Result<(String, Vec<u8>)> {
        if size > policy::FILE_LIMIT || prefix_limit > 262176 { return Err(self.fail(Problem::Bounds)); }
        let mut prefix=Vec::new();prefix.try_reserve_exact(prefix_limit).map_err(|_|Problem::Bounds)?;
        if prefix.capacity()!=prefix_limit{return Err(self.fail(Problem::Bounds));}
        self.point(false)?;self.in_native=true;
        let outcome=unistd::lseek(self.fd(index)?,0,unistd::Whence::SeekSet);
        self.in_native=false;self.observed(outcome,Problem::Native)?;
        let mut hash=Sha256::new();let mut total=0_u64;let mut block=[0_u8;65536];
        loop {
            self.point(false)?; self.in_native = true;
            let outcome = unistd::read(self.fd(index)?, &mut block);
            self.in_native = false; let used = self.observed(outcome, Problem::Native)?;
            if used == 0 { break; }
            total = total.checked_add(used as u64).ok_or(Problem::Bounds)?;
            self.read_bytes = self.read_bytes.checked_add(used as u64).filter(|bytes| *bytes <= READ_LIMIT).ok_or(Problem::Bounds)?;
            if total > size { return Err(self.fail(Problem::Inventory)); }
            hash.update(&block[..used]);
            let keep = used.min(prefix_limit.saturating_sub(prefix.len())); prefix.extend_from_slice(&block[..keep]);
        }
        if total != size { return Err(self.fail(Problem::Inventory)); }
        self.check_original(index, true, false)?; Ok((hex(&hash.finalize()), prefix))
    }
    fn region(&mut self, index: usize, at: u64, size: usize) -> Result<Vec<u8>> {
        if size > 262176 || at.checked_add(size as u64).is_none_or(|end| end > self.identity(index).ok().map_or(0, |id| id.bytes as u64)) {
            return Err(self.fail(Problem::Bounds));
        }
        self.point(false)?; self.in_native = true;
        let outcome = unistd::lseek(self.fd(index)?, i64::try_from(at).map_err(|_| Problem::Bounds)?, unistd::Whence::SeekSet);
        self.in_native = false; self.observed(outcome, Problem::Native)?;
        let mut raw=Vec::new();raw.try_reserve_exact(size).map_err(|_|Problem::Bounds)?;
        if raw.capacity()!=size{return Err(self.fail(Problem::Bounds));}
        raw.resize(size,0);let mut offset=0;
        while offset < size {
            self.point(false)?; self.in_native = true; let outcome = unistd::read(self.fd(index)?, &mut raw[offset..]); self.in_native = false;
            let used = self.observed(outcome, Problem::Native)?;
            if used == 0 { return Err(self.fail(Problem::Inventory)); }
            offset += used; self.read_bytes = self.read_bytes.checked_add(used as u64).filter(|bytes| *bytes <= READ_LIMIT).ok_or(Problem::Bounds)?;
        }
        self.check_original(index, true, false)?; Ok(raw)
    }
    fn native_file(&mut self, index: usize, spec: &FileSpec, prefix: &[u8], inventory: &Inventory) -> Result<()> {
        if policy::android_target_elf(spec,prefix).map_err(|_|Problem::Inventory)?
            || policy::gradle_foreign_launcher(spec).map_err(|_|Problem::Inventory)?{return Ok(());}
        if spec.path == inventory.data.roles.gradle {
            return if prefix.starts_with(b"#!/bin/sh\n") || prefix.starts_with(b"#!/bin/sh\r\n") { Ok(()) } else { Err(self.fail(Problem::Inventory)) };
        }
        let sdk=policy::sdk35_file(spec).map_err(|_|Problem::Inventory)?;
        if let Some(kind)=sdk.filter(|kind|kind.script()){
            return if policy::sdk35_script(kind,prefix,inventory){Ok(())}else{Err(self.fail(Problem::Inventory))};
        }
        let mandatory = spec.mode & 0o111 != 0 || spec.path.ends_with(".dylib") || spec.path.ends_with(".jnilib");
        let recognizable = [[0xcf,0xfa,0xed,0xfe], [0xfe,0xed,0xfa,0xcf], [0xca,0xfe,0xba,0xbe], [0xca,0xfe,0xba,0xbf]]
            .iter().any(|magic| prefix.starts_with(magic));
        if !mandatory && !recognizable { return Ok(()); }
        let architecture=if sdk.is_some_and(|kind|kind.legacy()){policy::MachArchitecture::X86_64}else{policy::MachArchitecture::Arm64};
        let slice=policy::native_slice(prefix,spec.size,architecture).ok_or(Problem::Inventory)?;
        let header = self.region(index, slice.offset, 32)?;
        let bytes = u32::from_le_bytes(header[20..24].try_into().map_err(|_| Problem::Inventory)?) as usize;
        let body = self.region(index, slice.offset, bytes.checked_add(32).ok_or(Problem::Bounds)?)?;
        let commands=policy::native_commands(&body,slice,architecture).ok_or(Problem::Inventory)?;
        if !policy::local_loads(&spec.path, &commands, inventory) { return Err(self.fail(Problem::Inventory)); }
        Ok(())
    }
    fn os_provider(&mut self, prepared: &Prepared) -> Result<()> {
        for spec in &prepared.provider.files {
            let mut chain=Vec::new();chain.try_reserve_exact(17).map_err(|_|Problem::Bounds)?;
            if chain.capacity()!=17{return Err(self.fail(Problem::Bounds));}
            let root = self.open(None, "/", true, Role::Ancestor)?; chain.push(root);
            self.protect(root, None, Policy::Ancestors)?;
            let mut parent = root;
            let mut parts = spec.path.strip_prefix('/').ok_or(Problem::Inventory)?.split('/').peekable();
            let mut file = None;
            while let Some(name) = parts.next() {
                let directory = parts.peek().is_some();
                if chain.len()>=chain.capacity(){return Err(self.fail(Problem::Bounds));}
                parent = self.open(Some(parent), name, directory, if directory { Role::Ancestor } else { Role::Reader })?;
                chain.push(parent); self.protect(parent, None, Policy::Ancestors)?;
                if !directory { file = Some(parent); }
            }
            let index = file.ok_or(Problem::Inventory)?;
            let original = self.identity(index)?;
            if original.gid != 0 || u32::from(original.mode & 0o7777) != spec.mode || original.bytes != spec.size as i64 {
                return Err(self.fail(Problem::Ownership));
            }
            self.point(false)?; self.in_native = true;
            let outcome = statfs::fstatfs(self.fd(index)?);
            self.in_native = false; let filesystem = self.observed(outcome, Problem::Native)?;
            if !filesystem.flags().contains(MntFlags::MNT_RDONLY) { return Err(self.fail(Problem::Ownership)); }
            self.originals[index].immutable = true;
            let (hash, prefix) = self.read(index, spec.size, 256)?;
            if hash != spec.sha256 { return Err(self.fail(Problem::Inventory)); }
            if spec.mode & 0o111 != 0 {
                let slice = policy::arm64_slice(&prefix, spec.size).ok_or(Problem::Inventory)?;
                let header = self.region(index, slice.offset, 32)?;
                let size = u32::from_le_bytes(header[20..24].try_into().map_err(|_| Problem::Inventory)?) as usize;
                let raw = self.region(index, slice.offset, size.checked_add(32).ok_or(Problem::Bounds)?)?;
                let commands = policy::macho_commands(&raw, slice).ok_or(Problem::Inventory)?;
                if !commands.loads.iter().all(|path| policy::system_load(path))
                    || !commands.rpaths.iter().all(|path| policy::OS_ROOTS.contains(&path.as_str()) || policy::system_load(path)) {
                    return Err(self.fail(Problem::Inventory));
                }
            }
            for index in chain.iter().rev().copied() {
                self.check_original(index, self.originals[index].immutable, false)?;
            }
            self.close_chain(chain)?;
        }
        Ok(())
    }
    fn metadata_files(&mut self, prepared: &Prepared) -> Result<()> {
        let stage = self.stage.ok_or(Problem::Unknown)?;
        for (number, (name, raw)) in [policy::MANIFEST, policy::RECORD, policy::PROVIDER].into_iter().zip(&prepared.raw).enumerate() {
            let index = self.create_file(stage, name, Role::MetadataWriter)?;
            self.write(index, raw)?; self.seal_file(index, 0o444)?;
            // A new controlled readback original is permitted only after the
            // actual writer close returned positively. Never rescue Unknown.
            let reader = self.open(Some(stage), name, false, Role::Reader)?;
            self.protect(reader, Some(0o444), Policy::Empty)?;
            self.originals[reader].immutable = true;
            let (hash, _) = self.read(reader, raw.len() as u64, 0)?;
            if hash != hex(&prepared.hello.hashes[number]) { return Err(self.fail(Problem::Inventory)); }
            if !self.close(reader) { return Err(self.fail(Problem::Unknown)); }
        }
        Ok(())
    }
    fn aliases(&mut self, prepared: &Prepared) -> Result<()> {
        for alias in &prepared.inventory.data.aliases {
            let (parent, name, chain) = self.path_parent(&alias.path, 0o700)?;
            let effect = self.effect(parent, &name)?; self.point(false)?; self.in_native = true;
            let outcome = unistd::symlinkat(alias.target.as_str(), self.fd(parent)?, name.as_str());
            self.in_native = false;
            self.creations[effect].effect = match outcome { Ok(()) => Effect::Applied, Err(Errno::EEXIST) => Effect::Refused, Err(_) => Effect::Unknown };
            if outcome.is_err() {
                if self.creations[effect].effect == Effect::Unknown { self.accounting_unknown = true; self.unknown = true; }
                return Err(self.fail(Problem::Collision));
            }
            let value = self.named(Some(parent), &name, false)?; let identity = Identity::of(&value);
            if value.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFLNK.bits() || value.st_uid != 0 || value.st_gid != 0
                || value.st_nlink != 1 || value.st_size != alias.target.len() as i64 || value.st_flags != 0 { return Err(self.fail(Problem::Ownership)); }
            self.creations[effect].identity = Some(identity);
            let allocated = u64::try_from(value.st_blocks).ok().and_then(|blocks| blocks.checked_mul(512)).ok_or(Problem::Bounds)?;
            self.creations[effect].allocated=Some(allocated);
            let key=(value.st_dev,value.st_ino);
            if !self.accounted.contains_key(&key) && self.accounted.len()>=self.account_limit{return Err(self.fail(Problem::Bounds));}
            self.accounted.insert(key,(value.st_size as u64,allocated));
            self.content_aliases = self.content_aliases.checked_add(1).ok_or(Problem::Bounds)?;
            self.persist(parent, false, false)?; self.close_chain(chain)?;
        }
        Ok(())
    }
    fn seal_walk(&mut self, parent: usize, path: &str, prepared: &Prepared, seen: &mut BTreeSet<String>, depth: usize) -> Result<()> {
        if depth > 16 { return Err(self.fail(Problem::Bounds)); }
        let limit=prepared.roster_limit(path,false).ok_or(Problem::Bounds)?;
        for(name,(inode,kind))in self.roster(parent,limit)?{
            if !prepared.expected_child(path,&name,false){return Err(self.fail(Problem::Inventory));}
            let length=path.len().checked_add(name.len()).and_then(|n|n.checked_add(usize::from(!path.is_empty()))).ok_or(Problem::Bounds)?;
            if length>512 || seen.len()>=policy::ENTRY_LIMIT{return Err(self.fail(Problem::Bounds));}
            let mut relative=String::new();relative.try_reserve_exact(length).map_err(|_|Problem::Bounds)?;
            if relative.capacity()!=length{return Err(self.fail(Problem::Bounds));}
            if !path.is_empty(){relative.push_str(path);relative.push('/');}relative.push_str(&name);
            if !seen.insert(exact_name(&relative)?){return Err(self.fail(Problem::Inventory));}
            if let Some(alias) = prepared.inventory.data.aliases.iter().find(|alias| alias.path == relative) {
                let before = self.named(Some(parent), &name, false)?;
                if kind != nix::libc::DT_LNK || before.st_ino != inode || before.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFLNK.bits()
                    || before.st_uid != 0 || before.st_gid != 0 || before.st_nlink != 1 || before.st_flags != 0 { return Err(self.fail(Problem::Ownership)); }
                let mut target=[0_u8;native::vault_filesystem::LINK_TARGET_BYTES];
                self.point(false)?;self.in_native=true;
                let outcome=native::vault_filesystem::readlink_component(self.fd(parent)?.as_fd(),&name,&mut target);
                self.in_native=false;let length=self.observed(outcome,Problem::Native)?;
                if target[..length] != *alias.target.as_bytes() || self.named(Some(parent), &name, false).map(|s| Identity::of(&s))? != Identity::of(&before) {
                    return Err(self.fail(Problem::Inventory));
                }
                continue;
            }
            let directory = prepared.inventory.directories.contains(&relative);
            let spec = prepared.inventory.data.files.iter().find(|file| file.path == relative);
            if directory && kind != nix::libc::DT_DIR || !directory && kind != nix::libc::DT_REG
                || !directory && spec.is_none() { return Err(self.fail(Problem::Inventory)); }
            let index = self.open(Some(parent), &name, directory, if directory { Role::Directory } else { Role::Reader })?;
            if self.identity(index)?.inode != inode { return Err(self.fail(Problem::Ownership)); }
            let mode = if directory { 0o700 } else { spec.map_or(0o444, |spec| spec.mode) };
            self.protect(index, Some(mode), Policy::Empty)?;
            if directory { self.seal_walk(index, &relative, prepared, seen, depth+1)?; }
            else {
                self.originals[index].immutable = true;
                if let Some(spec) = spec {
                    let (hash, prefix) = self.read(index, spec.size, 256)?;
                    if hash != spec.sha256 { return Err(self.fail(Problem::Inventory)); }
                    self.native_file(index, spec, &prefix, &prepared.inventory)?;
                }
            }
            self.check_original(index, true, false)?;
            if !self.close(index) { return Err(self.fail(Problem::Unknown)); }
        }
        if depth == 0 { self.check_original(parent, false, false) }
        else { self.seal_directory(parent) }
    }
    fn seal_directory(&mut self, parent: usize) -> Result<()> {
        self.check_original(parent, false, false)?;
        self.point(false)?; self.in_native = true;
        let outcome = stat::fchmod(self.fd(parent)?, Mode::from_bits_truncate(0o555));
        self.in_native = false; self.observed(outcome, Problem::Ownership)?;
        self.protect(parent, Some(0o555), Policy::Empty)?; self.persist(parent, false, false)?;
        self.originals[parent].identity = Some(Identity::of(&self.fstat(parent, false)?));
        self.originals[parent].immutable = true; self.check_original(parent, true, false)?; self.account(parent, false)?;
        Ok(())
    }
    fn settle_native(&mut self) -> bool {
        let signal = self.signal.clone(); let clock = self.clock.as_ref();
        let map = |first: Option<(SnapshotFailure, Instant)>| {
            if let Some((problem, event)) = first {
                if let Some(clock) = clock { signal.local_failure(clock, event, problem == SnapshotFailure::Unknown); }
                else { signal.failure_now(true); }
            }
            !signal.admitted(true)
        };
        let mut retired = true;
        if !self.lease_acl.not_started() { retired &= self.lease_acl.release(&mut |first| map(first)); }
        if let Some(snapshot) = &mut self.snapshot { retired &= snapshot.release(&mut |first| map(first)); }
        if !retired { self.fail(Problem::Unknown); } retired
    }
    fn publication(&mut self) -> Result<()> {
        let prepared = self.prepared.as_ref().ok_or(Problem::Unknown)?.clone();
        if !self.ingress.input_settled() || !self.transfer.as_ref().is_some_and(transfer::Transfer::transfer_complete) {
            return Err(self.fail(Problem::Unknown));
        }
        self.os_provider(&prepared)?; self.aliases(&prepared)?;
        let stage = self.stage.ok_or(Problem::Unknown)?; let mut seen = BTreeSet::new();
        // All payload readers/writers settle and every payload child directory
        // is sealed BEFORE content metadata exists. The root alone stays0700
        // for these three fixed records; no other writer is scheduled afterward.
        self.seal_walk(stage, "", &prepared, &mut seen, 0)?;
        let expected_entries = prepared.totals.entries().ok_or(Problem::Bounds)? as usize;
        if seen.len().checked_add(3) != Some(expected_entries)
            || self.content_files != prepared.totals.files || self.content_aliases != prepared.totals.aliases { return Err(self.fail(Problem::Inventory)); }
        self.metadata_files(&prepared)?;
        for name in [policy::MANIFEST,policy::RECORD,policy::PROVIDER]{
            if !seen.insert(exact_name(name)?){return Err(self.fail(Problem::Inventory));}
        }
        let root_limit=prepared.roster_limit("",true).ok_or(Problem::Bounds)?;
        let observed_root=self.roster(stage,root_limit)?;
        if seen.len()!=expected_entries || observed_root.len()!=root_limit.entries
            || observed_root.keys().any(|name|!prepared.expected_child("",name,true)){return Err(self.fail(Problem::Inventory));}
        drop(observed_root); // no second bulk-collected comparison tree
        self.seal_directory(stage)?;
        self.stage_identity = Some(self.identity(stage)?); self.stage_sealed = true;
        let registration = self.registration.ok_or(Problem::Unknown)?;
        let destination = self.destination.ok_or(Problem::Unknown)?;
        let lease = self.lease.ok_or(Problem::Unknown)?;
        // Authenticate both named publication parents while their ORIGINAL
        // ancestry is still held. Only these parents and the sole EX survive E;
        // the later rename cannot silently substitute a path-reopened ancestor.
        for (index, mode) in [(registration, 0o700), (destination, 0o755)] {
            self.check_original(index, false, false)?;
            self.protect(index, Some(mode), Policy::Empty)?;
        }
        self.check_original(lease, true, false)?;
        let registration_before = Identity::of(&self.fstat(registration, false)?);
        let destination_before = Identity::of(&self.fstat(destination, false)?);
        // Lease and intent are already immutable. Retire ACL setter/snapshot
        // native allocations before any publication or last-close eligibility.
        if !self.settle_native() { return Err(self.fail(Problem::Unknown)); }
        for index in (0..self.originals.len()).rev() {
            if [registration, destination, lease].contains(&index) { continue; }
            if self.originals[index].state == State::Held {
                // All identity/membership readback precedes consumption. No
                // descriptor is reopened to replace this closing original.
                self.check_original(index, self.originals[index].immutable, false)?;
            }
            if !self.close(index) { return Err(self.fail(Problem::Unknown)); }
        }
        if self.originals.iter().enumerate().any(|(index, value)|
            ![registration, destination, lease].contains(&index) && !matches!(value.state, State::Closed | State::NoHandle)) {
            return Err(self.fail(Problem::Unknown));
        }
        let source_now = Identity::of(&self.named(Some(registration), "stage", false)?);
        if Some(source_now) != self.stage_identity { return Err(self.fail(Problem::Ownership)); }
        self.point(false)?;
        self.publish = Some(Effect::Entered); self.in_native = true;
        let outcome = native::publish_directory(self.fd(registration)?.as_fd(), "stage", self.fd(destination)?.as_fd(), &prepared.selected.instance);
        self.in_native = false;
        self.publish = Some(match outcome { Ok(()) => Effect::Applied, Err(ref error) if error.raw_os_error() == Some(Errno::EEXIST as i32) => Effect::Refused, _ => Effect::Unknown });
        if outcome.is_err() {
            if self.publish == Some(Effect::Unknown) { self.unknown = true; }
            return Err(self.fail(Problem::Collision));
        }
        // RENAME_EXCL is the only publication operation. No replacement or
        // retry is available; persistence failure keeps visible content pending.
        self.persist(registration, false, false)?; self.persist(destination, false, false)?;
        let named = Identity::of(&self.named(Some(destination), &prepared.selected.instance, false)?);
        let before = self.stage_identity.ok_or(Problem::Unknown)?;
        if !before.same_object(named) || before.mode != named.mode || before.links != named.links
            || before.bytes != named.bytes || before.mtime != named.mtime || before.mtime_ns != named.mtime_ns { return Err(self.fail(Problem::Ownership)); }
        // Parent-only verification: no payload accessor is recreated after E.
        for (index, before) in [(registration, registration_before), (destination, destination_before)] {
            let after = Identity::of(&self.fstat(index, false)?);
            if !before.same_object(after) || before.mode != after.mode {
                return Err(self.fail(Problem::Ownership));
            }
        }
        let source_members=self.roster_inner(registration,false,RosterLimit{entries:1,names:"intent.json".len()})?;
        let target_members=self.roster_inner(destination,false,RosterLimit::account(0))?;
        if source_members.keys().any(|name| name == "stage") || target_members.get(&prepared.selected.instance) != Some(&(before.inode, nix::libc::DT_DIR)) {
            return Err(self.fail(Problem::Ownership));
        }
        let parents_closed = self.close(registration) & self.close(destination);
        if !parents_closed { return Err(self.fail(Problem::Unknown)); }
        Ok(())
    }
    fn terminal_data(&self, success: bool, known: bool) -> [u8; TERMINAL_BYTES] {
        use crate::android_registration_protocol::terminal::{
            TerminalCandidate, CandidateDisposition, OutputAccountingData, ERROR_PREFIX,
        };
        let logical = self.accounted.values().try_fold(0_u64, |sum, (bytes, _)| sum.checked_add(*bytes));
        let allocated = self.accounted.values().try_fold(0_u64, |sum, (_, bytes)| sum.checked_add(*bytes));
        let (transaction, instance) = self.hello.map_or(([0; 16], [0; 16]), |hello| (hello.transaction, hello.instance));
        let candidate = TerminalCandidate {
            disposition: if success { CandidateDisposition::PreparedComplete }
                else if known { CandidateDisposition::Refused } else { CandidateDisposition::Unknown },
            first_problem: self.first, transaction, instance, written_bytes: self.written_bytes,
            accounting: OutputAccountingData { observed_logical_bytes: logical.unwrap_or(0),
                observed_allocated_bytes: allocated.unwrap_or(0),
                complete: self.accounting_complete() && logical.is_some() && allocated.is_some() },
            publication_applied: self.publish == Some(Effect::Applied),
            content_files: self.content_files, content_aliases: self.content_aliases,
            recorded_error_count: self.errors.len() as u32,
            error_prefix: self.errors.iter().take(ERROR_PREFIX).copied().collect(),
            pre_lease_dependencies_known: known,
        };
        candidate.encode().unwrap_or_else(|_| TerminalCandidate::unknown_bytes())
    }
    fn settled_except_lease(&self) -> bool {
        !self.in_native && !self.unknown && !self.signal.unknown() && !self.lease_call.call_in_progress()
            && !matches!(self.lease_call.lock_state(), LockState::Calling | LockState::Unknown)
            && self.accounting_complete()
            && self.snapshot.as_ref().is_none_or(SnapshotBook::settled)
            && (self.lease_acl.not_started() || self.lease_acl.native_settled())
            && self.originals.iter().enumerate().all(|(index, value)| self.lease == Some(index)
                || matches!(value.state, State::Closed | State::NoHandle))
            && self.ingress.input_settled() && self.packet.is_none()
    }
    fn finish(&mut self, mut outcome: Result<()>) -> WorkerEnd {
        if let Err(problem) = outcome { self.fail(problem); }
        if !self.ingress.retire_failed_input(self.packet.take()) { self.fail(Problem::Unknown); }
        // No broad delete. Unpublished/partial originals and permanent intent
        // remain at exact owned names for separately reviewed recovery.
        if !self.settle_native() { outcome = Err(Problem::Unknown); }
        for index in (0..self.originals.len()).rev() {
            if self.lease != Some(index) { let _ = self.close(index); }
        }
        let known_before = self.settled_except_lease();
        let success = outcome.is_ok() && self.first.is_none() && !self.signal.unknown()
            && self.signal.first().is_none() && self.publish == Some(Effect::Applied) && self.stage_sealed;
        // Freeze all terminal candidates BEFORE moving the EX. A concurrent
        // independent F may select Refused, never a stale PreparedComplete.
        let positive = self.terminal_data(success, known_before);
        let refused = self.terminal_data(false, known_before);
        let failed = self.terminal_data(false, false);
        if let Some(index) = self.lease {
            // The ORIGINAL EX is consumed last only with positive settlement of
            // every dependent original. On any uncertainty it remains retained.
            if !known_before || self.point(true).is_err() { return WorkerEnd { data: failed, success: false, known: false }; }
            let signal = self.signal.clone(); // Independent control, not a later book lookup.
            let Some(bounds) = signal.bounds() else { signal.clock_unknown(); return WorkerEnd { data: failed, success: false, known: false }; };
            let frozen = signal.snapshot();
            let Some(cutoff) = frozen.cleanup else { signal.clock_unknown(); return WorkerEnd { data: failed, success: false, known: false }; };
            if frozen.unknown || self.last_raw >= cutoff || self.final_result.is_some()
                || self.originals[index].state != State::Held {
                signal.clock_unknown(); return WorkerEnd { data: failed, success: false, known: false };
            }
            let admission = lease::CloseAdmission { origin: bounds.origin, hard: bounds.hard, previous: self.last_raw, cutoff };
            let Some(fd) = self.originals[index].fd.take() else {
                self.originals[index].state = State::Unknown; signal.clock_unknown();
                return WorkerEnd { data: failed, success: false, known: false };
            };
            self.originals[index].state = State::Moved;
            self.final_started = true;
            // LAST original operation: native shim installs non-dropping custody
            // then obtains its OWN mandatory pre-entry sample. There is no book,
            // parent, fd, source or out-of-band native query after this call.
            let result = lease::consume_original(ManuallyDrop::into_inner(fd), admission);
            let data = result.data();
            self.final_result = Some(result); // Preserves positively non-entered EX.
            self.final_attempted = data.entered();
            self.final_closed = data.returned_success();
            let frozen = signal.snapshot();
            let known = data.timely_success(admission, frozen.cleanup) && !frozen.unknown;
            if !known {
                match data.observation(admission) { Some(at) => signal.failure_at(at, true), None => signal.clock_unknown() }
                return WorkerEnd { data: failed, success: false, known: false };
            }
            let success = success && frozen.first.is_none();
            WorkerEnd { data: if success { positive } else { refused }, success, known: true }
        } else {
            WorkerEnd { data: refused, success: false, known: known_before && self.originals.iter().all(|value| matches!(value.state, State::Closed | State::NoHandle)) }
        }
    }
    fn body(&mut self) -> Result<()> {
        if self.entered || !self.control_precharged || self.signal.bounds().is_none() {
            return Err(self.fail(Problem::Unknown));
        }
        self.entered = true;
        loop {
            if let Some(bounds) = self.signal.bounds() {
                if !self.signal.admitted(false) { return Err(self.fail(Problem::Stopped)); }
                // Bounds were prepared before GO; Hello only compares them.
                if !bounds.valid() { return Err(self.fail(Problem::Unknown)); }
            } else if self.signal.first().is_some() || self.signal.unknown() { return Err(self.fail(Problem::Stopped)); }
            let packet = match self.ingress.take() {
                Ok(Some(packet)) => packet,
                Ok(None) | Err(native::android_registration::Failure::Busy) => { std::thread::park_timeout(std::time::Duration::from_millis(2)); continue; }
                Err(_) => return Err(self.fail(Problem::Unknown)),
            };
            let account = packet.account(); let nonce = packet.nonce();
            let content = packet.content().to_vec(); self.packet = Some(packet);
            if self.hello.is_none() {
                let hello = Hello::decode(&content).map_err(|_| Problem::Binding)?;
                if nonce != hello.transaction || self.ingress.bound_account() != Some(account)
                    || self.ingress.bound_nonce() != Some(nonce)
                    || self.signal.bounds() != Some(Bounds { origin: hello.origin, work: hello.work, hard: hello.hard }) {
                    return Err(self.fail(Problem::Binding));
                }
                self.metadata = Some(Metadata::new(hello).map_err(|_| Problem::Bounds)?); self.hello = Some(hello);
            } else if self.prepared.is_none() {
                let metadata = self.metadata.as_mut().ok_or(Problem::Unknown)?;
                metadata.push(MetadataChunk::decode(&content).map_err(|_| Problem::Inventory)?).map_err(|_| Problem::Inventory)?;
                if metadata.complete() {
                    let prepared = Arc::new(Prepared::from_metadata(self.metadata.take().ok_or(Problem::Unknown)?, account, self.control_cap)?);
                    self.start_filesystem(prepared, account)?;
                }
            } else if self.payload(&content)? {
                self.publication()?; return Ok(());
            }
            let packet = self.packet.take().ok_or(Problem::Unknown)?;
            let bytes = self.transfer.as_ref().map_or(0, transfer::Transfer::written);
            self.ingress.acknowledge(packet, bytes).map_err(|_| Problem::Unknown)?;
        }
    }
    /// Called only by the genuine original worker while the coordinator retains
    /// this same Publisher. Panics are caught OUTSIDE its locked custody.
    pub(crate) fn run(&mut self) -> WorkerEnd { let outcome = self.body(); self.finish(outcome) }
    pub(crate) fn mark_lost(&mut self) { self.unknown = true; self.signal.failure_now(true); }
}

/// Bounded DATA only. Existence is not a join receipt; only the coordinator's
/// actual original JoinHandle return can authorize H publication.
pub(crate) struct WorkerEnd { pub(crate) data: [u8; TERMINAL_BYTES], pub(crate) success: bool, pub(crate) known: bool }

#[cfg(test)]
mod allocation_data_tests{
    use super::*;
    // Synthetic DATA only: no supplier admission, identity, clock, FD or native
    // owner is claimed. The same closed proposal authority supplies the shape.
    fn prepared()->Prepared{
        let provider=policy::proposal_provider(policy::OS_FILES.iter().map(|path|FileSpec{
            path:(*path).into(),size:1,sha256:"e".repeat(64),
            mode:if path.ends_with(".plist"){0o644}else{0o755},
        }).collect()).unwrap();
        let os=policy::encode_provider(&provider).unwrap();
        let home="jdk/Test.jdk/Contents/Home";
        let mut files:Vec<FileSpec>=["java","javac","jarsigner","keytool"].iter().map(|name|FileSpec{
            path:format!("{home}/bin/{name}"),size:1,sha256:"e".repeat(64),mode:0o555,
        }).collect();
        for(path,mode,size,hash)in[
            ("gradle/bin/gradle",0o555,1,"e".repeat(64)),
            (policy::AAPT2,0o555,1,"e".repeat(64)),
            ("sdk/platforms/android-35/android.jar",0o444,1,"e".repeat(64)),
            ("jdk/Test.jdk/Contents/Home/lib/jli/libjli.dylib",0o444,1,"e".repeat(64)),
            ("bundletool/bundletool.jar",0o444,32_520_401,
                "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29".into()),
        ]{files.push(FileSpec{path:path.into(),size,sha256:hash,mode});}
        files.sort_by(|a,b|a.path.cmp(&b.path));
        let instance="a".repeat(32);let os_hash=os.digest_hex();
        let inventory=policy::proposal_inventory(policy::ProposalManifestData{
            versions:policy::Versions{jdk_vendor:"test".into(),jdk_version:"17.0.1".into(),gradle_version:"8.14.5".into(),
                agp_version:"8.9.2".into(),sdk_platform:"android-35".into(),sdk_platform_revision:"2".into(),sdk_build_tools_version:"35.0.0".into()},
            gradle_distribution:policy::Distribution{url:"https://services.gradle.org/distributions/gradle-8.14.5-bin.zip".into(),sha256:"e".repeat(64)},
            roles:policy::Roles{java:format!("{home}/bin/java"),javac:format!("{home}/bin/javac"),
                gradle:"gradle/bin/gradle".into(),bundletool:"bundletool/bundletool.jar".into(),sdk:"sdk".into()},
            files,aliases:vec![policy::Alias{path:format!("{home}/lib/jli/link.dylib"),target:"libjli.dylib".into(),
                canonical:format!("{home}/lib/jli/libjli.dylib")}],
        },&instance,&os_hash).unwrap();
        let manifest=policy::encode_inventory(&inventory).unwrap();
        let inventory_hash=manifest.digest_hex();
        let record=policy::encode_registration_proposal(501,&instance,&inventory_hash,&os_hash).unwrap();
        let selected=MacToolchainSelection{instance,owner_uid:501,catalog_generation:1,
            record_sha256:record.digest_hex(),inventory_sha256:inventory_hash,os_provider_sha256:os_hash};
        let raw=[manifest.bytes,record.bytes,os.bytes];
        let hello=Hello{transaction:[1;16],instance:[0xaa;16],origin:100,work:300_000_000_100,hard:310_000_000_100,
            lengths:std::array::from_fn(|i|raw[i].len() as u32),hashes:std::array::from_fn(|i|Sha256::digest(&raw[i]).into()),
            source_consent:[2;32],supplier_record:[3;32],source_generation:1,project_registration:1};
        let totals=ContentTotals{files:inventory.data.files.len() as u32,directories:inventory.directories.len() as u32,
            aliases:inventory.data.aliases.len() as u32,payload_bytes:inventory.data.files.iter().map(|f|f.size).sum(),
            metadata_bytes:raw.iter().map(|v|v.len() as u64).sum()};
        Prepared{hello,selected,inventory,provider,raw,totals}
    }
    #[test]
    fn effect_high_water_counts_original_multiplicity_and_refuses_before_effects(){
        let input=prepared();let census=EffectCensus::for_prepared(&input,501,ORIGINAL_CONTROL_BYTES).unwrap();
        let directories=input.inventory.directories.len();let files=input.inventory.data.files.len();let aliases=input.inventory.data.aliases.len();
        let depths=|path:&str|path.split('/').filter(|v|!v.is_empty()).count();
        let expected=14+input.inventory.directories.iter().map(|p|depths(p)).sum::<usize>()
            +input.inventory.data.files.iter().map(|f|depths(&f.path)).sum::<usize>()
            +input.inventory.data.aliases.iter().map(|a|depths(&a.path)-1).sum::<usize>()
            +6+input.provider.files.iter().map(|f|1+depths(&f.path)).sum::<usize>()+directories+files;
        assert_eq!(census.originals,expected);
        assert_eq!(census.creations,directories+files+aliases+13);
        assert_eq!(census.accounted,census.creations+SUPPORT.len()+1);
        assert!(census.bytes>Publisher::fixed_owned_bytes().unwrap()+input.dynamic_bytes().unwrap());
        assert!(EffectCensus::for_prepared(&input,501,census.bytes-1).is_none());
        assert!(EffectCensus::for_prepared(&input,501,census.bytes).is_some());
        let mut owner=Publisher::new(Arc::new(Ingress::new()));
        assert_eq!(Publisher::service_high_water(),Some(ORIGINAL_CONTROL_BYTES));
        assert_eq!(owner.service_precharge(ORIGINAL_CONTROL_BYTES-1),Err(Problem::Bounds));
        owner.service_precharge(ORIGINAL_CONTROL_BYTES).unwrap();
        owner.prepare_effects(&input,501).unwrap();
        assert_eq!(owner.originals.capacity(),census.originals);
        assert_eq!(owner.creations.capacity(),census.creations);
        assert_eq!(owner.original_names_left,census.original_names);
        assert_eq!(owner.creation_names_left,census.creation_names);
        assert_eq!(owner.errors.capacity(),64);
        assert!(!owner.entered && owner.clock.is_none() && owner.snapshot.is_none());
        assert!(owner.originals.is_empty() && owner.creations.is_empty());
        assert_eq!(owner.service_precharge(ORIGINAL_CONTROL_BYTES),Err(Problem::Bounds));
    }
    #[test]
    fn roster_and_component_budgets_bind_names_not_entry_limit_worst_case(){
        let input=prepared();
        let root=input.roster_limit("",false).unwrap();
        let metadata=input.roster_limit("",true).unwrap();
        assert_eq!(metadata.entries,root.entries+3);
        assert_eq!(metadata.names,root.names+policy::MANIFEST.len()+policy::RECORD.len()+policy::PROVIDER.len());
        assert!(metadata.accepts(metadata.entries,metadata.names));
        assert!(!metadata.accepts(metadata.entries+1,metadata.names));
        assert!(!metadata.accepts(metadata.entries,metadata.names+1));
        assert!(!input.expected_child("","unrelated",true));
        assert!(input.expected_child("",policy::MANIFEST,true));
        assert!(!input.expected_child("",policy::MANIFEST,false));
        let account=RosterLimit::account(5);
        assert_eq!((account.entries,account.names),(ACCOUNT_ATTEMPT_LIMIT,ACCOUNT_ATTEMPT_LIMIT*37));
        let(mut count,mut names)=(0usize,0usize);
        path_originals("jdk/Test.jdk/Contents/Home/bin/java",true,&mut count,&mut names).unwrap();
        assert_eq!((count,names),(6,"jdkTest.jdkContentsHomebinjava".len()));
        path_originals("x/y",false,&mut count,&mut names).unwrap();
        assert_eq!((count,names),(7,"jdkTest.jdkContentsHomebinjavax".len()));
        assert!(path_originals("x",true,&mut usize::MAX,&mut names).is_none());
    }
}
