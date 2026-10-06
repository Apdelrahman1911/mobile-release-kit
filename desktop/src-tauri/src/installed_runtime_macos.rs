//! Original Darwin installed-runtime inspection and one-use launch slots.
//! These slots plug into Supervisor/EditOwner; they are not another runner.
//! Protected one-shot installation and original writer finality are separate
//! prerequisites. Hashes or retained descriptors never make writable data safe.
#![forbid(unsafe_code)]
use std::{cell::{Cell, RefCell}, collections::{BTreeMap, BTreeSet}, os::{fd::{AsFd, OwnedFd}, unix::ffi::OsStrExt}, path::{Path, PathBuf}, time::Instant};
use nix::{fcntl::{self, AtFlags, OFlag}, mount::MntFlags, sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use mrk_macos_installed_native as native;
use native::vault_filesystem::{Expected, Failure as SnapshotFailure, Policy, SnapshotBook};
use crate::{error::BridgeError, protocol::{strict_json, PROTOCOL}, runtime::{self, VerifiedRuntime}};

#[path = "android_toolchain_macos.rs"]
mod android_tools;
pub(crate) use android_tools::AndroidToolchainSlots;
#[cfg(not(feature = "macos-android-registration-helper"))]
#[path = "android_leased_toolchain_macos.rs"]
mod android_leased;
#[cfg(not(feature = "macos-android-registration-helper"))]
pub(crate) use android_leased::{LeasedAndroidToolchainSlots, LeasedAndroidCatalogSlots,
    CatalogMode, CatalogCandidate, CatalogRow, RowCode, admission_issue as android_lease_admission_issue};
#[path = "android_runtime_macos.rs"]
mod android_runtime;
pub(crate) use android_runtime::{AndroidBuildRuntimeSlots, AndroidBuildInstalledRuntime};
#[path = "installation_observation_macos.rs"]
mod installation_observation;
pub(crate) use installation_observation::{InstallationSlots, native_problem as installation_native_problem};
#[cfg(not(feature = "macos-android-registration-helper"))]
#[path = "android_fixed_support_macos.rs"]
mod android_fixed_support;
#[cfg(not(feature = "macos-android-registration-helper"))]
pub(crate) use android_fixed_support::{FixedSupportSlots, FixedSupportReview};
#[cfg(not(feature = "macos-android-registration-helper"))]
#[path = "android_registration_source_macos.rs"]
mod android_registration_source;
#[cfg(not(feature = "macos-android-registration-helper"))]
pub(crate) use android_registration_source::{SourceSlots as AndroidRegistrationSourceSlots, SourceReview as AndroidRegistrationSourceReview, PayloadSink as AndroidRegistrationPayloadSink};

/// The full installation inspector and this separately retained fixed identity
/// book are subordinate to one original setup/Register worker and clock. The
/// inspector's consumed result never stands in for these live CF/FD originals.
#[cfg(not(feature = "macos-android-registration-helper"))]
pub(crate) struct AndroidServiceIdentitySlots {
    installation: InstallationSlots, original: Book,
    signing: native::android_service_management::IdentityBook,
    gate: crate::saved_command_owner::AndroidRegistrationWorkGate,
    entered: bool, checked: bool, closed: bool,
}
#[cfg(not(feature = "macos-android-registration-helper"))]
impl AndroidServiceIdentitySlots {
    pub(crate) fn new(gate: crate::saved_command_owner::AndroidRegistrationWorkGate) -> Self {
        let mut original=Book::new();original.registration_gate=Some(gate.clone());
        Self { installation:InstallationSlots::new_registered(gate.clone()),original,
            signing:native::android_service_management::IdentityBook::new(),gate,entered:false,checked:false,closed:false }
    }
    pub(crate) fn working_reservation_bytes()->Option<usize> {
        // InstallationSlots' unchanged16MiB complete inspector bound is the
        // larger phase. Its actual storage is consumed before the separate
        // fixed identity book allocates its ledger/record parser. Charge the
        // simultaneous inline/control/CF cells and bounded record DATA too.
        installation_observation::CONTROL_RESERVE.checked_add(2*1024*1024)?
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(native::android_service_management::IdentityBook::project_owned_upper_bound()?)
    }
    fn attempt<T>(&mut self,call:impl FnOnce(&mut Book)->Result<T>)->Result<T> {
        let result=call(&mut self.original);let at=Instant::now();
        if let Some((failure,first))=self.original.first_failure(){Self::note_failure(&self.gate,failure,first);}
        if let Err(failure)=&result{Self::note_failure(&self.gate,*failure,at);}
        result
    }
    fn note_failure(gate:&crate::saved_command_owner::AndroidRegistrationWorkGate,failure:AdmissionFailure,at:Instant){
        use crate::android_registration_app_protocol::Reason;
        gate.note(match failure{AdmissionFailure::Stopped=>Reason::Cancelled,AdmissionFailure::Deadline=>Reason::TimedOut,
            AdmissionFailure::Bounds=>Reason::InputLimit,AdmissionFailure::Unknown|AdmissionFailure::AlreadyUsed=>Reason::CleanupUnknown,
            _=>Reason::SigningUnavailable},at);
    }
    fn mode(book:&Book,index:usize,mode:u16,end:Instant,stop:&watch::Receiver<bool>)->Result<()> {
        book.point(end,stop)?;
        let identity=book.records.get(index).and_then(|record|record.identity).ok_or(AdmissionFailure::Identity)?;
        if identity.uid!=0 || identity.gid!=0 || identity.flags!=0 || identity.mode&0o7777!=mode {
            return Err(AdmissionFailure::Ownership);
        }
        native::no_xattrs(book.fd(index)?.as_fd()).map_err(native_error)?;
        book.check_name(index,end,stop)
    }
    fn fixed_payload(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<()> {
        use crate::macos_install_record as data;
        self.attempt(|book|book.arm_acl_once(end,stop))?;
        let roles=self.attempt(|book|book.protected_app_once(end,stop))?;
        let (contents,app,install)=(roles.contents,roles.payload,roles.install);
        self.attempt(|book|Self::mode(book,roles.entry,0o555,end,stop))?;
        self.attempt(|book|Self::mode(book,app,0o555,end,stop))?;
        self.attempt(|book|Self::mode(book,contents,0o555,end,stop))?;
        self.attempt(|book|Self::mode(book,install,0o755,end,stop))?;
        let versions=self.attempt(|book|book.open(Some(install),"versions",true,end,stop))?;
        self.attempt(|book|Self::mode(book,versions,0o755,end,stop))?;
        let release=self.attempt(|book|book.open(Some(versions),crate::macos_install_paths::RELEASE,true,end,stop))?;
        self.attempt(|book|Self::mode(book,release,0o755,end,stop))?;
        let mut read_data=|name:&str,limit:usize|->Result<Vec<u8>> {
            let index=self.attempt(|book|book.open(Some(release),name,false,end,stop))?;
            self.attempt(|book|Self::mode(book,index,0o444,end,stop))?;
            let size=self.original.records[index].identity.and_then(|id|u64::try_from(id.size).ok())
                .filter(|size|*size>0 && *size<=limit as u64).ok_or(AdmissionFailure::Bounds)?;
            self.attempt(|book|book.read(index,size,true,end,stop)).map(|(_,body)|body)
        };
        let descriptor=read_data(data::RECORD_NAME,data::RECORD_LIMIT)?;
        let inventory_bytes=read_data(data::INVENTORY_NAME,data::INVENTORY_LIMIT)?;
        let identity=|index:usize|->Result<data::DirectoryIdentity> {
            let id=self.original.records[index].identity.ok_or(AdmissionFailure::Identity)?;
            Ok(data::DirectoryIdentity {device:i64::from(id.dev),inode:id.ino,mode:u32::from(id.mode),uid:id.uid,gid:id.gid,flags:id.flags})
        };
        let manifest=option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").unwrap_or("");
        let expected=data::Expected {kind:data::Kind::Ordinary,source_commit:option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").unwrap_or(""),
            runtime_manifest:manifest,install_root:identity(install)?,release_directory:identity(release)?};
        data::Record::parse_data(&descriptor,&inventory_bytes,&expected).map_err(|_|AdmissionFailure::Inventory)?;
        let inventory=data::Inventory::parse(&inventory_bytes,manifest).map_err(|_|AdmissionFailure::Inventory)?;
        let layout=installed_code_layout()?;
        let index=inventory.index().map_err(|_|AdmissionFailure::Inventory)?;
        index.require_layout(layout).map_err(|_|AdmissionFailure::Inventory)?;
        // Rebind the complete SAME-live fixed facade/image/plist group to the
        // source-bound protected record before Security/framework service entry.
        // The only omission is selected by the compiled observer role above,
        // never inferred from this untrusted inventory.
        for (path,names,mode) in [
            (data::ENTRY_BINARY,&["Contents","MacOS","mrk-macos-entry"][..],0o555),
            (data::APP_BINARY,&["MacOS","mobile-release-kit-desktop"][..],0o555),
            (data::ANDROID_HELPER,&["Helpers","mrk-android-register"][..],0o555),
            (data::DESKTOP_IMAGE,&["Frameworks","libmrk_desktop_image.dylib"][..],0o555),
            (data::RESIDENT_IMAGE,&["Frameworks","libmrk_resident_image.dylib"][..],0o555),
            (data::ANDROID_SERVICE_PLIST,&["Library","LaunchDaemons","dev.mobile-release-kit.desktop.android-register.plist"][..],0o444),
        ] {
            if path==data::DESKTOP_IMAGE && layout==data::CodeLayout::ObserverExecutable {continue;}
            let row=index.files.get(path).ok_or(AdmissionFailure::Inventory)?;
            let mut parent=if path==data::ENTRY_BINARY {roles.entry}else{contents};
            for (position,name) in names.iter().enumerate() {
                let directory=position+1<names.len();
                parent=self.attempt(|book|book.open(Some(parent),name,directory,end,stop))?;
                self.attempt(|book|Self::mode(book,parent,if directory{0o555}else{mode},end,stop))?;
            }
            let collect=path==data::ANDROID_SERVICE_PLIST;
            let (hash,body)=self.attempt(|book|book.read(parent,row.size,collect,end,stop))?;
            if hash!=row.sha256 || row.executable!=(mode==0o555)
                || collect && body!=include_bytes!("../../macos-installed-inputs/dev.mobile-release-kit.desktop.android-register.plist") {
                return Err(AdmissionFailure::Inventory);
            }
        }
        self.recheck(end,stop)
    }
    pub(crate) fn check_once(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<()> {
        use native::android_service_management as management;
        if self.entered || self.closed{return Err(AdmissionFailure::AlreadyUsed);}
        self.entered=true;
        if !management::signing_profile_configured(){
            self.gate.note(crate::android_registration_app_protocol::Reason::SigningUnavailable,Instant::now());
            return Err(AdmissionFailure::Inventory);
        }
        let gate=self.gate.clone();
        let result=self.installation.run(end,stop,&mut |why,at|{
            use crate::installation::CheckReason as Problem;
            let reason=match why {Problem::CleanupUnknown=>crate::android_registration_app_protocol::Reason::CleanupUnknown,
                Problem::Deadline=>crate::android_registration_app_protocol::Reason::TimedOut,
                Problem::Cancelled=>crate::android_registration_app_protocol::Reason::Cancelled,
                _=>crate::android_registration_app_protocol::Reason::SigningUnavailable};
            gate.note(reason,at);
        },&mut |first|gate.source_cleanup_expired(first),&mut |_,_|{});
        if result.is_err(){return Err(if self.installation.settled(){AdmissionFailure::Inventory}else{AdmissionFailure::Unknown});}
        let result=self.fixed_payload(end,stop);let at=Instant::now();
        if let Err(failure)=result{Self::note_failure(&self.gate,failure,at);return Err(failure);}
        let result=self.signing.check_once(&mut |point|Self::signing_gate(&gate,point));
        match result {
            management::IdentityResult::Verified=>{self.recheck(end,stop)?;self.checked=true;Ok(())},
            management::IdentityResult::Unknown=>{gate.source_note(AdmissionFailure::Unknown,Instant::now());Err(AdmissionFailure::Unknown)},
            _=>{gate.note(crate::android_registration_app_protocol::Reason::SigningUnavailable,Instant::now());Err(AdmissionFailure::Inventory)},
        }
    }
    fn signing_gate(gate:&crate::saved_command_owner::AndroidRegistrationWorkGate,
        point:native::android_service_management::IdentityCheckpoint)->native::android_service_management::Decision {
        use native::android_service_management::{IdentityCheckpoint as Point,Decision};
        let (phase,custody,returned)=match point {Point::Before{phase,custody}=>(phase,custody,None),
            Point::Returned{phase,at,custody}=>(phase,custody,Some(at))};
        if let Some(at)=custody.first_failure{gate.note(crate::android_registration_app_protocol::Reason::SigningUnavailable,at);}
        if custody.unknown{gate.note(crate::android_registration_app_protocol::Reason::CleanupUnknown,
            custody.first_failure.or(returned).unwrap_or_else(Instant::now));}
        if phase.is_cleanup(){if gate.source_cleanup_expired(None){Decision::Unknown}else{Decision::Proceed}}
        else if gate.source_work().is_ok(){Decision::Proceed}else{Decision::Stop}
    }
    pub(crate) fn recheck(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<()> {
        for index in 0..self.original.records.len() {
            if self.original.records[index].state==State::Owned {
                self.attempt(|book|book.check_name(index,end,stop))?;
            }
        }
        self.gate.source_work()
    }
    pub(crate) fn settle(&mut self)->bool {
        if self.closed{return self.settled();}
        let gate=self.gate.clone();
        let signing=self.signing.settle(&mut |point|Self::signing_gate(&gate,point));
        // One signature failure never suppresses independently permitted FD/ACL
        // settlement. Both are retained on the same original if either is unknown.
        let files=self.original.settle(&mut |first|gate.source_cleanup_expired(first))==CloseOutcome::Settled;
        self.closed=true;signing && files && self.settled()
    }
    pub(crate) fn settled(&self)->bool {self.closed && self.installation.settled() && self.original.settled() && self.signing.settled()}
    pub(crate) fn checked(&self)->bool {self.checked && !self.closed}
    pub(crate) fn retained_bytes(&self)->Option<usize>{
        if !self.settled(){return None;}
        std::mem::size_of::<Self>().checked_add(self.original.retained_heap_bytes()?)?
            .checked_add(self.installation.control_bytes()?)
    }
}

pub(crate) use crate::macos_install_paths::{APP, PROTOCOL_SHA, runtime_root};
struct ProtectedApp { install: usize, entry: usize, payload: usize, contents: usize }
fn installed_code_layout() -> Result<crate::macos_install_record::CodeLayout> {
    use crate::macos_install_record::CodeLayout;
    match (cfg!(feature = "macos-installed-desktop-image"), cfg!(feature = "macos-installed-observation")) {
        (true, false) => Ok(CodeLayout::OrdinaryImage),
        (false, true) => Ok(CodeLayout::ObserverExecutable),
        _ => Err(AdmissionFailure::Inventory),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionFailure { Stopped, Deadline, Bounds, Native, Ownership, Inventory, Identity, AlreadyUsed, Unknown }
type Result<T> = std::result::Result<T, AdmissionFailure>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseOutcome { Settled, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { dev: i32, ino: u64, mode: u16, uid: u32, gid: u32, links: u16, size: i64,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64, flags: u32 }
impl Identity {
    fn of(s: &FileStat) -> Self { Self { dev: s.st_dev, ino: s.st_ino, mode: s.st_mode, uid: s.st_uid, gid: s.st_gid,
        links: s.st_nlink, size: s.st_size, mtime: s.st_mtime, mtime_ns: s.st_mtime_nsec, ctime: s.st_ctime, ctime_ns: s.st_ctime_nsec, flags: s.st_flags } }
    fn acl_expected(self) -> Result<Expected> {
        Ok(Expected { device: u64::try_from(self.dev).map_err(|_| AdmissionFailure::Identity)?, inode: self.ino,
            mode: u32::from(self.mode), owner: self.uid, group: self.gid, flags: self.flags })
    }
}
struct Record { state: State, fd: Option<OwnedFd>, parent: Option<usize>, name: String, identity: Option<Identity>, android_flags: Option<u32> }
struct Book { records: Vec<Record>, started: bool, inspected: bool, prepared: bool, unknown: bool, closed: bool,
    #[cfg(not(feature = "macos-android-registration-helper"))]
    registration_gate: Option<crate::saved_command_owner::AndroidRegistrationWorkGate>,
    android_acl: Option<std::sync::Mutex<android_runtime::Audit>>,
    // Constructors are DATA only. Entered survives a lost frame allocation.
    acl_entered: bool, acl: Option<RefCell<SnapshotBook>>,
    acl_invalid: Cell<bool>, acl_first: Cell<Option<(AdmissionFailure, Instant)>> }
fn map_acl_failure(failure: SnapshotFailure) -> AdmissionFailure { match failure {
    SnapshotFailure::Refused => AdmissionFailure::Ownership, SnapshotFailure::Native => AdmissionFailure::Native,
    SnapshotFailure::Bounds => AdmissionFailure::Bounds, SnapshotFailure::Stopped => AdmissionFailure::Stopped,
    SnapshotFailure::Unknown => AdmissionFailure::Unknown,
} }
fn earliest_failure(a: Option<(AdmissionFailure, Instant)>, b: Option<(AdmissionFailure, Instant)>)
    -> Option<(AdmissionFailure, Instant)> {
    match (a, b) { (Some(a), Some(b)) => Some(if a.1 <= b.1 { a } else { b }), (a, b) => a.or(b) }
}
fn selection_heap_bytes(selected: &VerifiedRuntime) -> Option<usize> {
    selected.python.capacity().checked_add(selected.bootstrap.capacity())?
        .checked_add(selected.core.capacity())?.checked_add(selected.cwd.capacity())
}
fn native_error<T>(_: T) -> AdmissionFailure { AdmissionFailure::Native }
fn checkpoint(end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
    if *stop.borrow() || stop.has_changed().is_err() { return Err(AdmissionFailure::Stopped); }
    if Instant::now() >= end { return Err(AdmissionFailure::Deadline); } Ok(())
}
fn digest(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }
fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn metadata(s: &FileStat, directory: bool) -> Result<Identity> {
    let kind = if directory { SFlag::S_IFDIR } else { SFlag::S_IFREG };
    if s.st_mode & SFlag::S_IFMT.bits() != kind.bits() || s.st_uid != 0 || s.st_mode & 0o7022 != 0
        || (!directory && s.st_nlink != 1) { return Err(AdmissionFailure::Ownership); }
    Ok(Identity::of(s))
}
impl Book {
    fn new() -> Self { Self { records: Vec::new(), started: false, inspected: false, prepared: false, unknown: false, closed: false,
        #[cfg(not(feature = "macos-android-registration-helper"))]
        registration_gate: None,
        android_acl: None, acl_entered: false, acl: None, acl_invalid: Cell::new(false), acl_first: Cell::new(None) } }
    fn point(&self,end:Instant,stop:&watch::Receiver<bool>)->Result<()> {
        #[cfg(not(feature = "macos-android-registration-helper"))]
        if let Some(gate)=&self.registration_gate{gate.source_work()?;}
        checkpoint(end,stop)
    }
    fn note_acl(&self, failure: AdmissionFailure, at: Instant) {
        self.acl_first.set(earliest_failure(self.acl_first.get(), Some((failure, at))));
        #[cfg(not(feature = "macos-android-registration-helper"))]
        if let Some(gate)=&self.registration_gate{gate.source_note(failure,at);}
    }
    fn invalid_acl(&self) -> AdmissionFailure {
        self.acl_invalid.set(true); self.note_acl(AdmissionFailure::Unknown, Instant::now()); AdmissionFailure::Unknown
    }
    fn first_failure(&self) -> Option<(AdmissionFailure, Instant)> {
        let native = match (self.acl_entered, &self.acl) {
            (false, None) => None,
            (true, Some(acl)) if self.android_acl.is_none() => match acl.try_borrow() {
                Ok(acl) => acl.first_failure().map(|(failure, at)| (map_acl_failure(failure), at)),
                Err(_) => { self.invalid_acl(); None },
            },
            _ => { self.invalid_acl(); None },
        };
        let first=earliest_failure(self.acl_first.get(), native);
        #[cfg(not(feature = "macos-android-registration-helper"))]
        let first=earliest_failure(first,self.registration_gate.as_ref().and_then(|gate|gate.source_first()));
        first
    }
    fn pristine(&self) -> bool { !self.started && !self.inspected && !self.prepared && !self.closed && !self.unknown
        && self.records.is_empty() && !self.acl_invalid.get() && self.acl_first.get().is_none() }
    fn never_started(&self) -> bool {
        self.pristine() && !self.acl_entered && self.acl.is_none() && self.android_acl.is_none()
    }
    fn inspection_ready(&self) -> bool {
        self.pristine() && if self.android_acl.is_some() {
            !self.acl_entered && self.acl.is_none() // Android's own arm/inspection is the only authority.
        } else {
            self.acl_entered && self.acl.as_ref().is_some_and(|acl| acl.try_borrow().is_ok_and(|acl|
                acl.not_started() && acl.quiescent() && acl.retained_frame_bytes() > 0))
        }
    }
    fn admission_custody_ready(&self) -> bool {
        if self.closed || self.unknown || self.acl_invalid.get() || self.acl_first.get().is_some() { return false; }
        match (self.android_acl.is_some(), self.acl_entered, &self.acl) {
            (true, false, None) => true, // Android retains its own sealed admission checks.
            (false, true, Some(cell)) => match cell.try_borrow() {
                Ok(acl) => acl.first_failure().is_none() && acl.quiescent() && !acl.settled()
                    && acl.retained_frame_bytes() > 0,
                Err(_) => { self.invalid_acl(); false },
            },
            _ => false,
        }
    }
    fn arm_acl_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if !self.never_started() { return Err(AdmissionFailure::AlreadyUsed); }
        self.point(end, stop)?;
        // Only the already-registered original inspector may enter here, AFTER
        // its original entry barrier. No coordinator/Registry native allocation.
        self.acl_entered = true;
        self.acl = Some(RefCell::new(SnapshotBook::new()));
        let acl = self.acl.as_ref().ok_or_else(|| self.invalid_acl())?.try_borrow().map_err(|_| self.invalid_acl())?;
        // new() returns an empty frame on allocation failure; retain that real
        // result before noting Bounds at its original return.
        let result = if acl.retained_frame_bytes() == 0 { Err(AdmissionFailure::Bounds) }
            else if !acl.not_started() || !acl.quiescent() { Err(AdmissionFailure::Unknown) } else { Ok(()) };
        drop(acl);
        if let Err(failure) = result { self.note_acl(failure, Instant::now()); return Err(failure); }
        self.point(end, stop)
    }
    fn common_settled(&self) -> bool {
        if self.acl_invalid.get() { return false; }
        match (self.android_acl.is_some(), self.acl_entered, &self.acl) {
            (true, false, None) => true, // Android finality is checked separately below.
            (false, false, None) => !self.started && self.records.is_empty(),
            (false, true, Some(acl)) => match acl.try_borrow() {
                Ok(acl) => acl.settled() && acl.quiescent(), Err(_) => { self.invalid_acl(); false },
            },
            _ => false,
        }
    }
    // Heap-only owned charge. The containing slot counts Book's inline layout
    // exactly once; frame bytes cannot bound live filesec/ACL/qualifier storage.
    fn retained_heap_bytes(&self) -> Option<usize> {
        if self.unknown || self.acl_invalid.get() || self.android_acl.is_some() { return None; }
        let frame = match (self.acl_entered, &self.acl) {
            (false, None) if !self.started && self.records.is_empty() => 0,
            (true, Some(acl)) => {
                let acl = acl.try_borrow().map_err(|_| self.invalid_acl()).ok()?;
                if !acl.quiescent() || (acl.retained_frame_bytes() == 0 && !acl.settled()) { return None; }
                acl.retained_frame_bytes()
            },
            _ => return None,
        };
        let mut bytes = self.records.capacity().checked_mul(std::mem::size_of::<Record>())?.checked_add(frame)?;
        for record in &self.records { bytes = bytes.checked_add(record.name.capacity())?; }
        Some(bytes)
    }
    fn fd(&self, index: usize) -> Result<&OwnedFd> { self.records.get(index).and_then(|r| r.fd.as_ref()).ok_or(AdmissionFailure::Unknown) }
    fn reserve(&mut self, parent: Option<usize>, name: &str) -> Result<usize> {
        if self.records.len() >= 8256 || self.records.iter().filter(|r| r.fd.is_some()).count() >= 48 { return Err(AdmissionFailure::Bounds); }
        let i = self.records.len(); self.records.push(Record { state: State::Reserved, fd: None, parent, name: name.into(), identity: None, android_flags: None }); Ok(i)
    }
    fn filesystem(&self, index: usize, identity: Identity, stopped: &mut dyn FnMut() -> bool) -> Result<()> {
        let fd = self.fd(index)?;
        let fs = statfs::fstatfs(fd).map_err(native_error)?;
        if fs.filesystem_type_name() != "apfs" || !fs.flags().contains(MntFlags::MNT_LOCAL)
            || fs.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP) {
            return Err(AdmissionFailure::Ownership);
        }
        if let Some(audit)=&self.android_acl {
            if self.acl_entered || self.acl.is_some() { return Err(self.invalid_acl()); }
            let record=&self.records[index];
            return audit.lock().map_err(|_|AdmissionFailure::Unknown)?.observe(fd.as_fd(),
                identity,record.android_flags.ok_or(AdmissionFailure::Identity)?);
        }
        if !self.acl_entered || self.acl_invalid.get() { return Err(self.invalid_acl()); }
        let expected = identity.acl_expected()?;
        let cell = self.acl.as_ref().ok_or_else(|| self.invalid_acl())?;
        let mut acl = cell.try_borrow_mut().map_err(|_| self.invalid_acl())?;
        let result = acl.observe_phased(fd.as_fd(), expected, Policy::Empty,&mut |phase,first|{
            #[cfg(not(feature = "macos-android-registration-helper"))]
            if let Some(gate)=&self.registration_gate {
                if phase==native::vault_filesystem::ObservePhase::Cleanup {
                    // SnapshotBook's successful ACL close tail is cleanup too.
                    // Never call a WAITing work predicate on this branch.
                    return gate.source_cleanup_expired(first.map(|(failure,at)|(map_acl_failure(failure),at)));
                }
                if gate.source_work().is_err(){return true;}
            }
            let _=(phase,first);stopped()
        }).map_err(map_acl_failure);
        if let Some((failure, at)) = acl.first_failure() { self.note_acl(map_acl_failure(failure), at); }
        result
    }
    fn open(&mut self, parent: Option<usize>, name: &str, directory: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        self.point(end, stop)?;
        let index = self.reserve(parent, name)?;
        let before = if let Some(parent) = parent {
            stat::fstatat(self.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        } else { stat::lstat(Path::new("/")) }.map_err(native_error)?;
        self.point(end, stop)?;
        let identity = metadata(&before, directory)?;
        if self.android_acl.is_some() {
            self.records[index].identity=Some(identity);self.records[index].android_flags=Some(before.st_flags);
        }
        self.records[index].state = State::Acquiring;
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC
            | if directory { OFlag::O_DIRECTORY } else { OFlag::empty() };
        let opened = if let Some(parent) = parent { fcntl::openat(self.fd(parent)?, name, flags, Mode::empty()) }
            else { fcntl::open(Path::new("/"), flags, Mode::empty()) };
        match opened {
            Ok(fd) => { self.records[index].fd = Some(fd); self.records[index].state = State::Owned; }
            Err(_) => { self.records[index].state = State::NoHandle; return Err(AdmissionFailure::Native); }
        }
        self.point(end, stop)?;
        let after = stat::fstat(self.fd(index)?).map_err(native_error)?;
        if metadata(&after, directory)? != identity { return Err(AdmissionFailure::Identity); }
        self.records[index].identity = Some(identity);
        self.filesystem(index, identity, &mut || self.point(end, stop).is_err())?;
        self.check_name(index, end, stop)?; Ok(index)
    }
    fn check_name(&self, index: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.point(end, stop)?;
        let record = &self.records[index]; let identity = record.identity.ok_or(AdmissionFailure::Identity)?;
        let actual = stat::fstat(self.fd(index)?).map_err(native_error)?;
        let named = if let Some(parent) = record.parent {
            stat::fstatat(self.fd(parent)?, record.name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
        } else { stat::lstat(Path::new("/")) }.map_err(native_error)?;
        if Identity::of(&actual) != identity || Identity::of(&named) != identity
            || record.android_flags.is_some_and(|flags|actual.st_flags!=flags || named.st_flags!=flags) { return Err(AdmissionFailure::Identity); }
        self.filesystem(index, identity, &mut || self.point(end, stop).is_err())?; self.point(end, stop)
    }
    fn chain(&mut self, path: &Path, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.first() != Some(&b'/') || bytes.len() > 4096 { return Err(AdmissionFailure::Bounds); }
        let mut parent = self.open(None, "/", true, end, stop)?;
        for name in bytes[1..].split(|b| *b == b'/') {
            if name.is_empty() || name == b"." || name == b".." { return Err(AdmissionFailure::Bounds); }
            let name = std::str::from_utf8(name).map_err(native_error)?;
            parent = self.open(Some(parent), name, true, end, stop)?;
        }
        Ok(parent)
    }
    fn read(&self, index: usize, size: u64, collect: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<(String, Vec<u8>)> {
        if size > 512 * 1024 * 1024 || (collect && size > 1024 * 1024) { return Err(AdmissionFailure::Bounds); }
        let fd = self.fd(index)?; native::no_xattrs(fd.as_fd()).map_err(native_error)?;
        if self.records[index].identity.is_none_or(|id| id.size < 0 || id.size as u64 != size) { return Err(AdmissionFailure::Inventory); }
        let mut hash = Sha256::new(); let mut bytes = Vec::new(); let mut count = 0u64; let mut block = [0u8; 65536];
        loop {
            self.point(end, stop)?;
            let n = unistd::read(fd, &mut block).map_err(native_error)?;
            if n == 0 { break; }
            count = count.checked_add(n as u64).ok_or(AdmissionFailure::Bounds)?;
            if count > size { return Err(AdmissionFailure::Inventory); }
            hash.update(&block[..n]); if collect { bytes.extend_from_slice(&block[..n]); }
        }
        if count != size { return Err(AdmissionFailure::Inventory); }
        self.check_name(index, end, stop)?;
        Ok((hash.finalize().iter().map(|b| format!("{b:02x}")).collect(), bytes))
    }
    fn close(&mut self, index: usize) -> bool {
        let record = &mut self.records[index];
        match record.state {
            State::Reserved => record.state = State::NoHandle,
            State::Owned => {
                record.state = State::Closing;
                match record.fd.take().map(unistd::close) {
                    Some(Ok(())) => record.state = State::Closed,
                    _ => { record.state = State::Unknown; self.unknown = true; }
                }
            }
            State::NoHandle | State::Closed => {}
            _ => self.unknown = true,
        }
        !self.unknown
    }
    fn walk(&mut self, parent: usize, relative: &str, files: &BTreeMap<String, PayloadFile>, directories: &BTreeSet<String>,
        observed: &mut BTreeSet<String>, selection: &VerifiedRuntime, depth: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if depth > 16 { return Err(AdmissionFailure::Bounds); }
        let mut buffer = [0u8; 65536]; let mut local = BTreeSet::new();
        loop {
            self.point(end, stop)?;
            let used = native::directory_block(self.fd(parent)?.as_fd(), &mut buffer).map_err(native_error)?;
            if used == 0 { break; }
            let mut offset = 0;
            while offset < used {
                if used - offset < 11 { return Err(AdmissionFailure::Inventory); }
                // The observer may inspect link metadata; payload rosters may
                // not, including the otherwise skipped manifest entry.
                if !matches!(buffer[offset+8], nix::libc::DT_DIR | nix::libc::DT_REG) { return Err(AdmissionFailure::Inventory); }
                let inode = u64::from_ne_bytes(buffer[offset..offset+8].try_into().map_err(native_error)?);
                let length = usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let next = offset.checked_add(11+length).filter(|n| *n <= used).ok_or(AdmissionFailure::Inventory)?;
                let name = std::str::from_utf8(&buffer[offset+11..next]).map_err(native_error)?.to_owned(); offset = next;
                if name == "." || name == ".." { continue; }
                if !runtime::safe_payload_path(&name) || name.contains('/') || inode == 0 || !local.insert(name.clone()) { return Err(AdmissionFailure::Inventory); }
                let path = if relative.is_empty() { name.clone() } else { format!("{relative}/{name}") };
                if path == "manifest.json" { continue; }
                if observed.len() >= 8192 || !observed.insert(path.clone()) { return Err(AdmissionFailure::Bounds); }
                let directory = directories.contains(&path);
                if !directory && !files.contains_key(&path) { return Err(AdmissionFailure::Inventory); }
                let index = self.open(Some(parent), &name, directory, end, stop)?;
                let id = self.records[index].identity.ok_or(AdmissionFailure::Identity)?;
                if id.ino != inode || id.gid != 0 || id.mode & 0o7777 != if directory || path == "python/bin/python3" { 0o555 } else { 0o444 } {
                    return Err(AdmissionFailure::Ownership);
                }
                native::no_xattrs(self.fd(index)?.as_fd()).map_err(native_error)?;
                if directory { self.walk(index, &path, files, directories, observed, selection, depth+1, end, stop)?; }
                else {
                    let expected = files.get(&path).ok_or(AdmissionFailure::Inventory)?;
                    if self.read(index, expected.size, false, end, stop)?.0 != expected.sha256 { return Err(AdmissionFailure::Inventory); }
                }
                // Original records survive every close. Keep the launch roots
                // and their ancestors; other inspected payloads need no live fd
                // because verified root ownership/ACL ancestry forbids mutation.
                let absolute = selection.cwd.join(&path);
                let retain = [&selection.python, &selection.core, &selection.bootstrap].iter().any(|p| p.starts_with(&absolute));
                if !retain {
                    self.point(end, stop)?;
                    if !self.close(index) { self.note_acl(AdmissionFailure::Unknown, Instant::now()); return Err(AdmissionFailure::Unknown); }
                    self.point(end, stop)?; // A late real consuming return never renews work.
                }
            }
        }
        self.check_name(parent, end, stop)
    }
    fn fixed_code_mode(&self, index: usize, mode: u16, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.point(end, stop)?;
        let id=self.records.get(index).and_then(|record|record.identity).ok_or(AdmissionFailure::Identity)?;
        if id.uid!=0 || id.gid!=0 || id.flags!=0 || id.mode&0o7777!=mode {return Err(AdmissionFailure::Ownership);}
        native::no_xattrs(self.fd(index)?.as_fd()).map_err(native_error)?;
        self.check_name(index,end,stop)
    }
    fn fixed_code_group(&mut self, outer_contents: usize, contents: usize,
        layout: crate::macos_install_record::CodeLayout, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        // Fixed names, the same retained Book and the same original clock/ACL
        // budget. This is roster/identity admission, not another lifecycle.
        for (root,names,mode) in [
            (outer_contents,&["MacOS","mrk-macos-entry"][..],0o555),
            (contents,&["Helpers","mrk-android-register"][..],0o555),
            (contents,&["Library","LaunchDaemons","dev.mobile-release-kit.desktop.android-register.plist"][..],0o444),
        ] {
            let mut parent=root;
            for (position,name) in names.iter().enumerate() {
                let directory=position+1<names.len();
                parent=self.open(Some(parent),name,directory,end,stop)?;
                self.fixed_code_mode(parent,if directory{0o555}else{mode},end,stop)?;
            }
            if mode==0o444 {
                let expected=include_bytes!("../../macos-installed-inputs/dev.mobile-release-kit.desktop.android-register.plist");
                let (_,body)=self.read(parent,expected.len() as u64,true,end,stop)?;
                if body!=expected {return Err(AdmissionFailure::Inventory);}
            }
        }
        let frameworks=self.open(Some(contents),"Frameworks",true,end,stop)?;
        self.fixed_code_mode(frameworks,0o555,end,stop)?;
        let names: &[&str]=match layout {
            crate::macos_install_record::CodeLayout::OrdinaryImage =>
                &["libmrk_desktop_image.dylib","libmrk_resident_image.dylib"],
            crate::macos_install_record::CodeLayout::ObserverExecutable => &["libmrk_resident_image.dylib"],
        };
        let mut seen=0u8;let mut buffer=[0u8;65536];
        loop {
            self.point(end,stop)?;
            let used=native::directory_block(self.fd(frameworks)?.as_fd(),&mut buffer).map_err(native_error)?;
            if used==0 {break;}
            if used>buffer.len() {return Err(AdmissionFailure::Bounds);}
            let mut offset=0;
            while offset<used {
                if used-offset<11 {return Err(AdmissionFailure::Inventory);}
                let inode=u64::from_ne_bytes(buffer[offset..offset+8].try_into().map_err(native_error)?);
                let kind=buffer[offset+8];
                let length=usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let next=offset.checked_add(11+length).filter(|n|*n<=used).ok_or(AdmissionFailure::Inventory)?;
                let name=std::str::from_utf8(&buffer[offset+11..next]).map_err(native_error)?;
                offset=next;
                if name=="." || name==".." {continue;}
                let position=names.iter().position(|expected|*expected==name).ok_or(AdmissionFailure::Inventory)?;
                let bit=1u8<<position;
                if inode==0 || kind!=nix::libc::DT_REG || seen&bit!=0 {return Err(AdmissionFailure::Inventory);}
                seen|=bit;
                let image=self.open(Some(frameworks),name,false,end,stop)?;
                self.fixed_code_mode(image,0o555,end,stop)?;
                if self.records[image].identity.is_none_or(|id|id.ino!=inode) {return Err(AdmissionFailure::Identity);}
            }
        }
        if seen!=(1u8<<names.len())-1 {return Err(AdmissionFailure::Inventory);}
        self.check_name(frameworks,end,stop)
    }
    // Private factoring of the existing installed-app proof, not a Resources
    // capability. FixedSupport uses the SAME retained Contents ancestor.
    fn protected_app_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<ProtectedApp> {
        if !self.inspection_ready() { return Err(AdmissionFailure::AlreadyUsed); }
        let layout=installed_code_layout()?;
        self.records.try_reserve_exact(8256).map_err(native_error)?; self.started = true;
        self.point(end, stop)?; native::real_user().map_err(native_error)?; self.point(end, stop)?;
        // A user-writable drag-copy or checkout app cannot select this runtime.
        let executable = Path::new(crate::macos_install_paths::PAYLOAD_EXECUTABLE);
        if std::env::current_exe().map_err(native_error)? != executable { return Err(AdmissionFailure::Ownership); }
        // Explicit retained role indices, never "payload.parent == install".
        let install = self.chain(Path::new(crate::macos_install_paths::INSTALL_ROOT), end, stop)?;
        let entry = self.open(Some(install), crate::macos_install_paths::APP_NAME, true, end, stop)?;
        let outer_contents = self.open(Some(entry), "Contents", true, end, stop)?;
        let helpers = self.open(Some(outer_contents), "Helpers", true, end, stop)?;
        let payload = self.open(Some(helpers), crate::macos_install_paths::PAYLOAD_NAME, true, end, stop)?;
        let contents = self.open(Some(payload), "Contents", true, end, stop)?;
        let app_parent = self.open(Some(contents), "MacOS", true, end, stop)?;
        let binary = self.open(Some(app_parent), "mobile-release-kit-desktop", false, end, stop)?;
        let id = self.records[binary].identity.ok_or(AdmissionFailure::Identity)?;
        if id.gid != 0 || id.mode & 0o7777 != 0o555 { return Err(AdmissionFailure::Ownership); }
        native::no_xattrs(self.fd(binary)?.as_fd()).map_err(native_error)?;
        self.fixed_code_group(outer_contents,contents,layout,end,stop)?;
        Ok(ProtectedApp { install, entry, payload, contents })
    }
    fn inspect(&mut self, selection: &VerifiedRuntime, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.protected_app_once(end, stop)?;
        if selection.cwd != runtime_root() { return Err(AdmissionFailure::Inventory); }
        let root = self.chain(&selection.cwd, end, stop)?;
        let id = self.records[root].identity.ok_or(AdmissionFailure::Identity)?;
        if id.gid != 0 || id.mode & 0o7777 != 0o555 { return Err(AdmissionFailure::Ownership); }
        native::no_xattrs(self.fd(root)?.as_fd()).map_err(native_error)?;
        let manifest = self.open(Some(root), "manifest.json", false, end, stop)?;
        let id = self.records[manifest].identity.ok_or(AdmissionFailure::Identity)?;
        if id.gid != 0 || id.mode & 0o7777 != 0o444 { return Err(AdmissionFailure::Ownership); }
        let size = u64::try_from(self.records[manifest].identity.ok_or(AdmissionFailure::Identity)?.size).map_err(native_error)?;
        let (hash, bytes) = self.read(manifest, size, true, end, stop)?;
        if Some(hash.as_str()) != option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256") { return Err(AdmissionFailure::Inventory); }
        let manifest: Manifest = serde_json::from_value(strict_json(&bytes).map_err(native_error)?).map_err(native_error)?;
        if manifest.schema_version != 1 || manifest.protocol != PROTOCOL || manifest.core_version != runtime::CORE_VERSION
            || !crate::macos_build_profile::MacBuildTarget::matches_compiled(&manifest.target) || manifest.protocol_sha256 != PROTOCOL_SHA
            || option_env!("MRK_BUNDLED_PROTOCOL_SHA256") != Some(PROTOCOL_SHA)
            || manifest.files.is_empty() || manifest.files.len() > 2048
            || digest(&serde_json::to_vec(&manifest.files).map_err(native_error)?) != manifest.inventory_sha256 { return Err(AdmissionFailure::Inventory); }
        let mut files = BTreeMap::new(); let mut directories = BTreeSet::new(); let mut folded = BTreeSet::new(); let mut total = 0u64;
        let mut previous = String::new();
        for file in manifest.files {
            if !runtime::safe_payload_path(&file.path) || !file.path.is_ascii() || file.path == "manifest.json" || !sha(&file.sha256)
                || file.path <= previous || file.size > 512*1024*1024 { return Err(AdmissionFailure::Inventory); }
            total = total.checked_add(file.size).ok_or(AdmissionFailure::Bounds)?;
            if total > 1024*1024*1024 || (file.path == "core.zip" && file.sha256 != manifest.core_sha256) { return Err(AdmissionFailure::Inventory); }
            previous = file.path.clone(); let mut name = file.path.as_str();
            while let Some((parent, _)) = name.rsplit_once('/') { directories.insert(parent.to_owned()); name = parent; }
            files.insert(file.path.clone(), file);
        }
        for required in runtime::REQUIRED_RUNTIME_RESOURCES { if !files.contains_key(required) { return Err(AdmissionFailure::Inventory); } }
        for name in files.keys().chain(directories.iter()) {
            if !folded.insert(name.to_ascii_lowercase()) { return Err(AdmissionFailure::Inventory); }
        }
        let mut observed = BTreeSet::new(); self.walk(root, "", &files, &directories, &mut observed, selection, 0, end, stop)?;
        if observed.len() != files.len() + directories.len() { return Err(AdmissionFailure::Inventory); }
        self.point(end, stop)?; self.inspected = true; Ok(())
    }
    fn prepare(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if !self.inspected || self.prepared || !self.admission_custody_ready() { return Err(AdmissionFailure::AlreadyUsed); }
        self.point(end, stop)?; native::real_user().map_err(native_error)?;
        for (index, record) in self.records.iter().enumerate() {
            if record.state == State::Owned { self.check_name(index, end, stop)?; }
        }
        self.point(end, stop)?; self.prepared = true; Ok(())
    }
    fn settle(&mut self, expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool) -> CloseOutcome {
        #[cfg(not(feature = "macos-android-registration-helper"))]
        let gate=self.registration_gate.clone();
        let mut expired=|first|{
            #[cfg(not(feature = "macos-android-registration-helper"))]
            let gate_expired=gate.as_ref().is_some_and(|gate|gate.source_cleanup_expired(first));
            #[cfg(feature = "macos-android-registration-helper")]
            let gate_expired=false;
            let owner_expired=expired(first);gate_expired || owner_expired
        };
        let first = self.first_failure();
        let denied = expired(first); // Also publish around native poisoned/early returns.
        if self.closed || self.android_acl.is_some() { return CloseOutcome::Unknown; }
        match (self.acl_entered, &self.acl) {
            (true, Some(cell)) => match cell.try_borrow_mut() {
                Ok(mut acl) => {
                    if !denied {
                        let _ = acl.release(&mut |native| expired(earliest_failure(first,
                            native.map(|(failure, at)| (map_acl_failure(failure), at)))));
                    }
                    if let Some((failure, at)) = acl.first_failure() { self.note_acl(map_acl_failure(failure), at); }
                },
                Err(_) => { self.invalid_acl(); },
            },
            (false, None) if !self.started && self.records.is_empty() => {},
            _ => { self.invalid_acl(); },
        }
        let _ = expired(self.first_failure());
        // A native failure never suppresses a separately permitted original FD
        // consume. Expiry retains positive records; there is no retry/Drop path.
        for index in (0..self.records.len()).rev() {
            if self.records[index].state == State::Owned {
                if expired(self.first_failure()) { continue; }
                if !self.close(index) { self.note_acl(AdmissionFailure::Unknown, Instant::now()); }
                let _ = expired(self.first_failure()); // Record a late real return, never renew its owner.
            } else { self.close(index); }
        }
        self.closed = true; if self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    fn settled(&self) -> bool { self.closed && !self.unknown && self.common_settled() && self.records.iter().all(|r|
        r.fd.is_none() && matches!(r.state, State::NoHandle | State::Closed))
        && self.android_acl.as_ref().is_none_or(|audit|audit.try_lock().is_ok_and(|audit|audit.settled())) }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest { schema_version: u32, protocol: u32, core_version: String, target: String, core_sha256: String,
    protocol_sha256: String, inventory_sha256: String, files: Vec<PayloadFile> }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadFile { path: String, sha256: String, size: u64 }

// Distinct sealed input and slot types; no passive→edit or cross-domain conversion.
// The whole registered Book is moved only by the existing owner's transfer.
macro_rules! slots {
    ($slots:ident, $capability:ident, $profile:ty) => {
        pub(crate) struct $slots { inspection: Option<Book>, acquisition: Option<$capability>, selection: Option<VerifiedRuntime>, settlement: bool }
        pub(crate) struct $capability { original: Book, selection: VerifiedRuntime, claimed: bool, no_effect: bool }
        impl $capability {
            pub(crate) fn prepare_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<&VerifiedRuntime> {
                self.prepare_once_observed(end, stop, &mut |_| {})
            }
            pub(crate) fn prepare_once_observed(&mut self, end: Instant, stop: &watch::Receiver<bool>,
                publish: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>)) -> Result<&VerifiedRuntime> {
                let result = if self.claimed { Err(AdmissionFailure::AlreadyUsed) } else { self.original.prepare(end, stop) };
                // G1: a non-ACL return has its own actual F. Capture before
                // first_failure (which can note Unknown) or the owner callback;
                // retain it in the SAME original latch with any earlier ACL F.
                if let Err(failure) = &result {
                    let detected_at = Instant::now();
                    self.original.note_acl(*failure, detected_at);
                }
                publish(self.original.first_failure()); // Original native return, before any later owner borrow/join.
                result?; Ok(&self.selection)
            }
            pub(crate) fn claim_once(&mut self) -> Result<()> {
                if self.claimed || !self.original.prepared || !self.original.admission_custody_ready() { return Err(AdmissionFailure::AlreadyUsed); }
                self.claimed = true; Ok(())
            }
            pub(crate) fn record_closed_spawn_gate(&mut self) { self.no_effect = true; }
        }
        impl $slots {
            pub(crate) fn new() -> Self { Self { inspection: Some(Book::new()), acquisition: None, selection: None, settlement: false } }
            pub(crate) fn never_started(&self) -> bool { !self.settlement && self.selection.is_none() && self.acquisition.is_none()
                && self.inspection.as_ref().is_some_and(Book::never_started) }
            pub(crate) fn arm_acl_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
                if !self.never_started() { return Err(AdmissionFailure::AlreadyUsed); }
                self.inspection.as_mut().ok_or(AdmissionFailure::Unknown)?.arm_acl_once(end, stop)
            }
            pub(crate) fn first_failure(&self) -> Option<(AdmissionFailure, Instant)> {
                match (&self.inspection, &self.acquisition) {
                    (Some(b), None) => b.first_failure(), (None, Some(c)) => c.original.first_failure(),
                    _ => Some((AdmissionFailure::Unknown, Instant::now())),
                }
            }
            pub(crate) fn retained_bytes(&self) -> Option<usize> {
                let mut bytes = std::mem::size_of::<Self>();
                match (&self.inspection, &self.acquisition) {
                    (Some(b), None) => { bytes = bytes.checked_add(b.retained_heap_bytes()?)?; },
                    (None, Some(c)) if self.selection.is_none() => {
                        bytes = bytes.checked_add(c.original.retained_heap_bytes()?)?.checked_add(selection_heap_bytes(&c.selection)?)?;
                    },
                    _ => return None,
                }
                if let Some(selected) = &self.selection { bytes = bytes.checked_add(selection_heap_bytes(selected)?)?; }
                Some(bytes)
            }
            pub(crate) fn inspect_once(&mut self, profile: $profile, end: Instant, stop: &watch::Receiver<bool>) -> std::result::Result<VerifiedRuntime, BridgeError> {
                if self.settlement || self.selection.is_some() || self.acquisition.is_some()
                    || !self.inspection.as_ref().is_some_and(Book::inspection_ready) { return Err(BridgeError::cleanup_unknown()); }
                self.selection = Some(profile.selection()?);
                let selection = self.selection.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
                let book = self.inspection.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
                book.inspect(selection, end, stop).map_err(|_| BridgeError::unavailable("The installed Mac runtime failed original custody inspection."))?;
                Ok(VerifiedRuntime { python: selection.python.clone(), bootstrap: selection.bootstrap.clone(), core: selection.core.clone(), cwd: selection.cwd.clone() })
            }
            pub(crate) fn transfer_once(&mut self) -> Result<()> {
                if self.settlement || self.acquisition.is_some() || self.selection.is_none()
                    || !self.inspection.as_ref().is_some_and(|b| b.inspected && b.admission_custody_ready()) { return Err(AdmissionFailure::AlreadyUsed); }
                let selection = self.selection.take().ok_or(AdmissionFailure::Unknown)?;
                let original = match self.inspection.take() { Some(b) => b, None => { self.selection = Some(selection); return Err(AdmissionFailure::Unknown); } };
                self.acquisition = Some($capability { original, selection, claimed: false, no_effect: false }); Ok(())
            }
            pub(crate) fn capability(&mut self) -> Result<&mut $capability> {
                if self.settlement { return Err(AdmissionFailure::AlreadyUsed); } self.acquisition.as_mut().ok_or(AdmissionFailure::AlreadyUsed)
            }
            pub(crate) fn no_child_effect(&self) -> bool { match (&self.inspection, &self.acquisition) {
                (Some(_), None) => true, (None, Some(c)) => !c.claimed || c.no_effect, _ => false } }
            pub(crate) fn mark_interrupted(&mut self) {
                if let Some(b) = &mut self.inspection { b.unknown = true; }
                if let Some(c) = &mut self.acquisition { c.original.unknown = true; }
            }
            pub(crate) fn settle_originals(&mut self, expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool) -> CloseOutcome {
                if self.settlement { return CloseOutcome::Unknown; } self.settlement = true;
                match (&mut self.inspection, &mut self.acquisition) {
                    (Some(b), None) => b.settle(expired), (None, Some(c)) => c.original.settle(expired), _ => CloseOutcome::Unknown }
            }
            pub(crate) fn settled(&self) -> bool { self.settlement && match (&self.inspection, &self.acquisition) {
                (Some(b), None) => b.settled(), (None, Some(c)) => c.original.settled(), _ => false } }
        }
    }
}
slots!(PassiveRuntimeSlots, PassiveInstalledRuntime, runtime::PassiveInstalledProfile);
slots!(GitHubReadOnlyRuntimeSlots, GitHubReadOnlyInstalledRuntime, runtime::GitHubReadOnlyInstalledProfile);
slots!(GitHubPreflightRuntimeSlots, GitHubPreflightInstalledRuntime, runtime::GitHubPreflightInstalledProfile);
slots!(GitHubReleaseRuntimeSlots, GitHubReleaseInstalledRuntime, runtime::GitHubReleaseInstalledProfile);
slots!(ConfigurationRuntimeSlots, ConfigurationInstalledRuntime, runtime::ConfigurationInstalledProfile);
slots!(GitHubWorkflowRuntimeSlots, GitHubWorkflowInstalledRuntime, runtime::GitHubWorkflowInstalledProfile);
slots!(MetadataTextRuntimeSlots, MetadataTextInstalledRuntime, runtime::MetadataTextInstalledProfile);
slots!(MetadataImagesRuntimeSlots, MetadataImagesInstalledRuntime, runtime::MetadataImagesInstalledProfile);
slots!(ReleaseVersionRuntimeSlots, ReleaseVersionInstalledRuntime, runtime::ReleaseVersionInstalledProfile);
slots!(IOSArchiveRuntimeSlots, IOSArchiveInstalledRuntime, runtime::IOSArchiveInstalledProfile);

// Inert checks over the same COMMON Book used by both new action slots.
// No SnapshotBook/native handle is created; entered/missing are negative DATA.
#[cfg(test)]
pub(crate) fn installed_github_actions_slots_data_check() -> bool {
    use std::any::TypeId;
    let types = [TypeId::of::<PassiveRuntimeSlots>(), TypeId::of::<GitHubReadOnlyRuntimeSlots>(),
        TypeId::of::<GitHubPreflightRuntimeSlots>(), TypeId::of::<GitHubReleaseRuntimeSlots>()];
    for (index, original) in types.iter().enumerate() { if types[index + 1..].contains(original) { return false; } }
    macro_rules! inert_action {
        ($slot:ty) => {{
            let mut empty = <$slot>::new();
            if !empty.never_started() || !empty.no_child_effect() || empty.settled()
                || empty.first_failure().is_some() || empty.capability().is_ok() || empty.transfer_once().is_ok()
                || empty.retained_bytes() != Some(std::mem::size_of::<$slot>()) { return false; }
            if empty.settle_originals(&mut |_| false) != CloseOutcome::Settled || !empty.settled()
                || empty.never_started() || empty.capability().is_ok()
                || empty.settle_originals(&mut |_| false) != CloseOutcome::Unknown { return false; }
            let mut missing = <$slot>::new();
            missing.inspection = None;
            if missing.never_started() || missing.no_child_effect() || missing.capability().is_ok()
                || missing.first_failure().is_none() || missing.retained_bytes().is_some()
                || missing.settle_originals(&mut |_| false) != CloseOutcome::Unknown || missing.settled() { return false; }
            let mut entered = <$slot>::new();
            entered.inspection.as_mut().unwrap().acl_entered = true;
            if entered.never_started() || entered.retained_bytes().is_some() || entered.transfer_once().is_ok()
                || entered.settle_originals(&mut |_| false) != CloseOutcome::Unknown || entered.settled() { return false; }
            let mut interrupted = <$slot>::new();
            interrupted.mark_interrupted();
            if interrupted.never_started() || interrupted.retained_bytes().is_some()
                || interrupted.settle_originals(&mut |_| false) != CloseOutcome::Unknown || interrupted.settled() { return false; }
            let now = Instant::now();
            let early = now.checked_sub(std::time::Duration::from_millis(1)).unwrap_or(now);
            let failed = <$slot>::new();
            let original = failed.inspection.as_ref().unwrap();
            original.note_acl(AdmissionFailure::Ownership, early);
            original.note_acl(AdmissionFailure::Native, now);
            original.invalid_acl();
            if failed.first_failure() != Some((AdmissionFailure::Ownership, early))
                || failed.retained_bytes().is_some() { return false; }
        }};
    }
    inert_action!(GitHubPreflightRuntimeSlots);
    inert_action!(GitHubReleaseRuntimeSlots);
    macro_rules! actual_prepare_return {
        ($capability:ident) => {{
            let selection = || VerifiedRuntime { python: PathBuf::from("/inert/python"),
                bootstrap: PathBuf::from("/inert/bootstrap"), core: PathBuf::from("/inert/core"),
                cwd: PathBuf::from("/inert") };
            let (_sender, stop) = watch::channel(false);
            let mut original = $capability { original: Book::new(), selection: selection(), claimed: false, no_effect: false };
            let before = Instant::now();
            let end = before + std::time::Duration::from_secs(10);
            let mut events = Vec::new(); let mut reported = None; let mut callback_at = None;
            // Calls the REAL original prepare_once_observed. The uninspected
            // Book's first guard returns before real_user, a frame or any FD.
            let refused = matches!(original.prepare_once_observed(end, &stop, &mut |first| {
                events.push("publish"); reported = first; callback_at = Some(Instant::now());
            }), Err(AdmissionFailure::AlreadyUsed));
            events.push("return");
            let later_claim_refused = original.claim_once().is_err();
            events.push("later-claim");
            let Some((failure, detected_at)) = reported else { return false; };
            if !refused || !later_claim_refused || events != ["publish", "return", "later-claim"]
                || failure != AdmissionFailure::AlreadyUsed || detected_at < before
                || !callback_at.is_some_and(|at| detected_at <= at)
                || original.original.first_failure() != reported || original.original.acl_entered
                || original.original.acl.is_some() || !original.original.records.is_empty()
                || original.original.retained_heap_bytes() != Some(0) { return false; }
            let mut repeated = None;
            if !matches!(original.prepare_once_observed(end, &stop, &mut |first| repeated = first),
                    Err(AdmissionFailure::AlreadyUsed)) || repeated != reported { return false; }
            let early = before.checked_sub(std::time::Duration::from_millis(1)).unwrap_or(before);
            let mut prior = $capability { original: Book::new(), selection: selection(), claimed: false, no_effect: false };
            prior.original.note_acl(AdmissionFailure::Ownership, early);
            let mut prior_report = None;
            if !matches!(prior.prepare_once_observed(end, &stop, &mut |first| prior_report = first),
                    Err(AdmissionFailure::AlreadyUsed))
                || prior_report != Some((AdmissionFailure::Ownership, early))
                || prior.original.first_failure() != prior_report { return false; }
            let mut entered = $capability { original: Book::new(), selection: selection(), claimed: false, no_effect: false };
            entered.original.acl_entered = true;
            let mut entered_report = None;
            if !matches!(entered.prepare_once_observed(end, &stop, &mut |first| entered_report = first),
                    Err(AdmissionFailure::AlreadyUsed))
                || !matches!(entered_report, Some((AdmissionFailure::AlreadyUsed, _)))
                || !entered.original.acl_invalid.get() || entered.original.retained_heap_bytes().is_some()
                || entered.original.first_failure() != entered_report
                || entered.original.settle(&mut |_| false) != CloseOutcome::Unknown
                || entered.original.settled() { return false; }
        }};
    }
    actual_prepare_return!(GitHubPreflightInstalledRuntime);
    actual_prepare_return!(GitHubReleaseInstalledRuntime);
    true
}
#[cfg(test)]
#[test]
fn installed_github_action_original_slots_are_inert_and_uncertainty_is_absorbing() {
    assert!(installed_github_actions_slots_data_check());
}

// This existing installed-shell DATA route never constructs a SnapshotBook or
// touches a descriptor. It tests missing/empty custody, not native free evidence.
#[cfg(test)]
pub(crate) fn common_acl_data_check() -> bool {
    macro_rules! empty_slots {
        ($($slot:ty),+ $(,)?) => { $({
            let mut slots = <$slot>::new();
            if !slots.never_started() || slots.retained_bytes() != Some(std::mem::size_of::<$slot>()) { return false; }
            if slots.settle_originals(&mut |_| false) != CloseOutcome::Settled || !slots.settled()
                || slots.never_started() || slots.settle_originals(&mut |_| false) != CloseOutcome::Unknown { return false; }
        })+ };
    }
    empty_slots!(PassiveRuntimeSlots, ConfigurationRuntimeSlots, IOSArchiveRuntimeSlots);
    let mut missing = Book::new();
    missing.acl_entered = true; // An entered-but-unreturned original is not empty.
    missing.records.push(Record { state: State::Closed, fd: None, parent: None, name: String::new(),
        identity: None, android_flags: None });
    if missing.never_started() || missing.admission_custody_ready() || missing.retained_heap_bytes().is_some()
        || missing.common_settled() || missing.settle(&mut |_| false) != CloseOutcome::Unknown || missing.settled() {
        return false;
    }
    let now = Instant::now();
    let early = now.checked_sub(std::time::Duration::from_millis(1)).unwrap_or(now);
    let failed = Book::new();
    failed.note_acl(AdmissionFailure::Ownership, early);
    failed.note_acl(AdmissionFailure::Native, now);
    failed.invalid_acl(); // Unknown cannot be cleared by a prior known refusal.
    if failed.first_failure() != Some((AdmissionFailure::Ownership, early)) || !failed.acl_invalid.get()
        || failed.retained_heap_bytes().is_some() || failed.common_settled() { return false; }
    let original = Identity { dev: 7, ino: 11, mode: 0o100444, uid: 0, gid: 0, links: 1, size: 0,
        mtime: 1, mtime_ns: 2, ctime: 3, ctime_ns: 4, flags: 0x1234 };
    let Ok(expected) = original.acl_expected() else { return false; };
    if (expected.device, expected.inode, expected.mode, expected.owner, expected.group, expected.flags)
        != (7, 11, 0o100444, 0, 0, 0x1234) { return false; }
    let mut negative = original; negative.dev = -1;
    negative.acl_expected().is_err()
}
slots!(OfflinePreflightRuntimeSlots, OfflinePreflightInstalledRuntime, runtime::OfflinePreflightInstalledProfile);
slots!(EnvironmentDiagnosticsRuntimeSlots, EnvironmentDiagnosticsInstalledRuntime, runtime::EnvironmentDiagnosticsInstalledProfile);
slots!(ProjectRecoveryRuntimeSlots, ProjectRecoveryInstalledRuntime, runtime::ProjectRecoveryInstalledProfile);

#[cfg(test)]
pub(crate) fn installed_doctor_recovery_slots_data_check() -> bool {
    // The actual COMMON Book is shared, not repaired or replaced here. Only
    // empty/missing/entered DATA: no SnapshotBook allocation or native return.
    use std::any::TypeId;
    if TypeId::of::<EnvironmentDiagnosticsRuntimeSlots>() == TypeId::of::<ProjectRecoveryRuntimeSlots>()
        || TypeId::of::<ProjectRecoveryRuntimeSlots>() == TypeId::of::<OfflinePreflightRuntimeSlots>()
        || TypeId::of::<EnvironmentDiagnosticsRuntimeSlots>() == TypeId::of::<AndroidBuildRuntimeSlots>() { return false; }
    macro_rules! inert_original {
        ($slot:ty) => {{
            let mut empty = <$slot>::new();
            if !empty.never_started() || !empty.no_child_effect() || empty.settled()
                || empty.first_failure().is_some() || empty.capability().is_ok() || empty.transfer_once().is_ok()
                || empty.retained_bytes() != Some(std::mem::size_of::<$slot>()) { return false; }
            if empty.settle_originals(&mut |_| false) != CloseOutcome::Settled || !empty.settled()
                || empty.never_started() || empty.capability().is_ok()
                || empty.settle_originals(&mut |_| false) != CloseOutcome::Unknown { return false; }
            let mut missing = <$slot>::new();
            missing.inspection = None;
            if missing.never_started() || missing.no_child_effect() || missing.capability().is_ok()
                || missing.first_failure().is_none() || missing.retained_bytes().is_some()
                || missing.settle_originals(&mut |_| false) != CloseOutcome::Unknown || missing.settled() { return false; }
            let mut entered = <$slot>::new();
            entered.inspection.as_mut().unwrap().acl_entered = true;
            if entered.never_started() || entered.retained_bytes().is_some() || entered.transfer_once().is_ok()
                || entered.settle_originals(&mut |_| false) != CloseOutcome::Unknown || entered.settled() { return false; }
            let mut interrupted = <$slot>::new();
            interrupted.mark_interrupted();
            if interrupted.never_started() || interrupted.retained_bytes().is_some()
                || interrupted.settle_originals(&mut |_| false) != CloseOutcome::Unknown || interrupted.settled() { return false; }
        }};
    }
    inert_original!(EnvironmentDiagnosticsRuntimeSlots);
    inert_original!(ProjectRecoveryRuntimeSlots);
    true
}
#[cfg(test)]
#[test]
fn installed_doctor_recovery_original_slots_are_inert_and_uncertainty_is_absorbing() {
    assert!(installed_doctor_recovery_slots_data_check());
}

#[cfg(test)]
pub(crate) fn installed_offline_slots_data_check() -> bool {
    // Empty memory-only slots: never call inspect, prepare, claim or settlement.
    // This is not native cleanup evidence; the shared Book's ACL finality is separate.
    let mut slots = OfflinePreflightRuntimeSlots::new();
    if !slots.never_started() || slots.settled() || slots.capability().is_ok()
        || slots.transfer_once().is_ok() { return false; }
    slots.mark_interrupted();
    !slots.never_started() && !slots.settled() && slots.capability().is_err()
        && slots.transfer_once().is_err()
}
#[cfg(test)]
#[test]
fn installed_offline_slots_refuse_without_original_inspection() {
    assert!(installed_offline_slots_data_check());
}

// The iOS owner lends its original, first-failure-shortened cleanup endpoint.
// STOP is expected during final settlement, not permission to renew a clock.
fn ios_audit_point(end: Instant, original: &watch::Receiver<Instant>) -> Result<()> {
    if original.has_changed().is_err() || Instant::now() >= end.min(*original.borrow()) {
        return Err(AdmissionFailure::Deadline);
    }
    Ok(())
}
impl Book {
    fn ios_check_after_use(&self, end: Instant, original: &watch::Receiver<Instant>) -> Result<()> {
        if !self.inspected || !self.admission_custody_ready() { return Err(AdmissionFailure::Unknown); }
        for (index, record) in self.records.iter().enumerate() {
            ios_audit_point(end, original)?;
            if record.state != State::Owned { continue; }
            let expected = record.identity.ok_or(AdmissionFailure::Identity)?;
            let actual = stat::fstat(self.fd(index)?).map_err(native_error)?;
            ios_audit_point(end, original)?;
            let named = if let Some(parent) = record.parent {
                stat::fstatat(self.fd(parent)?, record.name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            } else { stat::lstat(Path::new("/")) }.map_err(native_error)?;
            if Identity::of(&actual) != expected || Identity::of(&named) != expected { return Err(AdmissionFailure::Identity); }
            ios_audit_point(end, original)?;
            self.filesystem(index, expected, &mut || ios_audit_point(end, original).is_err())?;
            ios_audit_point(end, original)?;
        }
        Ok(())
    }
}
impl IOSArchiveRuntimeSlots {
    pub(crate) fn ios_check_after_use(&self, end: Instant, original: &watch::Receiver<Instant>) -> Result<()> {
        if self.settlement { return Err(AdmissionFailure::AlreadyUsed); }
        match (&self.inspection, &self.acquisition) {
            (None, Some(capability)) if capability.claimed => capability.original.ios_check_after_use(end, original),
            _ => Err(AdmissionFailure::AlreadyUsed),
        }
    }
}

struct IOSXcodeAlias { parent: usize, identity: Identity, target: PathBuf }
/// Distinct tool originals, reusing only Book's finite no-follow descriptor,
/// metadata and one-attempt close primitives. No runtime/tool interchange.
pub(crate) struct IOSXcodeSlots {
    original: Book, alias: Option<IOSXcodeAlias>, developer: Option<usize>, executable: Option<usize>,
    sdk: Option<usize>, developer_path: Option<PathBuf>, sdk_path: Option<PathBuf>,
    signing: Option<[usize; 3]>, recovery_security: Option<usize>, audit: watch::Receiver<Instant>, prepared: bool,
}
impl IOSXcodeSlots {
    pub(crate) fn new(audit: watch::Receiver<Instant>) -> Self {
        Self { original: Book::new(), alias: None, developer: None, executable: None, sdk: None,
            developer_path: None, sdk_path: None, signing: None, recovery_security: None, audit, prepared: false }
    }
    pub(crate) fn arm_acl_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.original.arm_acl_once(end, stop)
    }
    pub(crate) fn first_failure(&self) -> Option<(AdmissionFailure, Instant)> { self.original.first_failure() }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>().checked_add(self.original.retained_heap_bytes()?)?;
        if let Some(alias) = &self.alias { bytes = bytes.checked_add(alias.target.capacity())?; }
        if let Some(path) = &self.developer_path { bytes = bytes.checked_add(path.capacity())?; }
        if let Some(path) = &self.sdk_path { bytes = bytes.checked_add(path.capacity())?; }
        Some(bytes)
    }
    pub(crate) fn inspect_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.inspect_selected(end, stop, false)
    }
    pub(crate) fn inspect_signed_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.inspect_selected(end, stop, true)
    }
    pub(crate) fn inspect_recovery_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if !self.original.inspection_ready() { return Err(AdmissionFailure::AlreadyUsed); }
        self.original.records.try_reserve_exact(8).map_err(native_error)?;
        self.original.started = true;
        checkpoint(end, stop)?;
        native::real_user().map_err(native_error)?;
        // Recovery has no Xcode/config/material prerequisite. Retain only its
        // one fixed Security original in the same audited tool book.
        let bin = self.original.chain(Path::new("/usr/bin"), end, stop)?;
        self.recovery_security = Some(self.original.open(Some(bin), "security", false, end, stop)?);
        self.original.inspected = true;
        let _ = self.recovery_binding_data()?;
        self.check_current(end, stop)
    }
    fn inspect_selected(&mut self, end: Instant, stop: &watch::Receiver<bool>, signed: bool) -> Result<()> {
        use crate::ios_toolchain::{APPLICATIONS, SDK_COMPONENTS, STANDARD_APP, selection_alias_owner, sibling_target};
        if !self.original.inspection_ready() { return Err(AdmissionFailure::AlreadyUsed); }
        self.original.records.try_reserve_exact(32).map_err(native_error)?;
        self.original.started = true;
        checkpoint(end, stop)?;
        let account = native::real_user().map_err(native_error)?;
        let applications = self.original.chain(Path::new(APPLICATIONS), end, stop)?;
        checkpoint(end, stop)?;
        let named = stat::fstatat(self.original.fd(applications)?, STANDARD_APP, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?;
        let app = if named.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFLNK.bits() {
            if !selection_alias_owner(named.st_uid, account) || named.st_nlink != 1 || !(1..=1024).contains(&named.st_size) {
                return Err(AdmissionFailure::Ownership);
            }
            checkpoint(end, stop)?;
            let target = fcntl::readlinkat(self.original.fd(applications)?, STANDARD_APP).map_err(native_error)?;
            let target = PathBuf::from(target);
            let name = sibling_target(target.to_str().ok_or(AdmissionFailure::Bounds)?).ok_or(AdmissionFailure::Inventory)?.to_owned();
            self.alias = Some(IOSXcodeAlias { parent: applications, identity: Identity::of(&named), target });
            self.check_alias(end, stop)?;
            name
        } else { STANDARD_APP.to_owned() };
        // open() refuses a second alias and every symlink below this sibling.
        let mut parent = applications;
        for name in [app.as_str(), "Contents", "Developer"] {
            parent = self.original.open(Some(parent), name, true, end, stop)?;
        }
        self.developer = Some(parent);
        self.developer_path = Some(Path::new(APPLICATIONS).join(&app).join("Contents/Developer"));
        let mut tool = parent;
        for name in ["usr", "bin"] { tool = self.original.open(Some(tool), name, true, end, stop)?; }
        self.executable = Some(self.original.open(Some(tool), "xcodebuild", false, end, stop)?);
        let mut sdk = parent;
        let mut path = self.developer_path.clone().ok_or(AdmissionFailure::Unknown)?;
        for name in SDK_COMPONENTS {
            sdk = self.original.open(Some(sdk), name, true, end, stop)?;
            path.push(name);
        }
        self.sdk = Some(sdk); self.sdk_path = Some(path);
        if signed {
            // These fixed account/validator tools belong to the same retained
            // book and its pre/post audits/consuming closes. No PATH search or
            // second tools owner is introduced for the signed extension.
            let bin = self.original.chain(Path::new("/usr/bin"), end, stop)?;
            let security = self.original.open(Some(bin), "security", false, end, stop)?;
            let codesign = self.original.open(Some(bin), "codesign", false, end, stop)?;
            let openssl = self.original.open(Some(bin), "openssl", false, end, stop)?;
            self.signing = Some([security, codesign, openssl]);
        }
        self.original.inspected = true;
        let _ = self.binding_data()?;
        if signed { let _ = self.signing_binding_data()?; }
        self.check_current(end, stop)?;
        Ok(())
    }
    fn check_alias(&self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        let Some(alias) = &self.alias else { return Ok(()); };
        checkpoint(end, stop)?;
        let named = stat::fstatat(self.original.fd(alias.parent)?, crate::ios_toolchain::STANDARD_APP,
            AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?;
        if Identity::of(&named) != alias.identity { return Err(AdmissionFailure::Identity); }
        checkpoint(end, stop)?;
        let target = fcntl::readlinkat(self.original.fd(alias.parent)?, crate::ios_toolchain::STANDARD_APP).map_err(native_error)?;
        if PathBuf::from(target) != alias.target { return Err(AdmissionFailure::Identity); }
        checkpoint(end, stop)
    }
    pub(crate) fn check_before_spawn(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if !self.original.inspected || !self.original.admission_custody_ready() || self.prepared { return Err(AdmissionFailure::AlreadyUsed); }
        self.check_current(end, stop)?;
        self.prepared = true;
        Ok(())
    }
    fn check_current(&self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.check_alias(end, stop)?;
        for index in 0..self.original.records.len() { self.original.check_name(index, end, stop)?; }
        checkpoint(end, stop)
    }
    pub(crate) fn binding_data(&self) -> Result<crate::ios_archive_protocol::ToolchainBinding> {
        use crate::ios_archive_protocol::{RootIdentity, ToolchainBinding};
        if !self.original.inspected || !self.original.admission_custody_ready() { return Err(AdmissionFailure::Unknown); }
        let identity = |index: Option<usize>| -> Result<Identity> {
            self.original.records.get(index.ok_or(AdmissionFailure::Unknown)?).and_then(|r| r.identity).ok_or(AdmissionFailure::Identity)
        };
        let root = |id: Identity| RootIdentity { device: id.dev.to_string(), inode: id.ino.to_string(),
            mode: u32::from(id.mode), uid: id.uid, gid: id.gid };
        let developer = identity(self.developer)?; let sdk = identity(self.sdk)?;
        ToolchainBinding::new_data(crate::ios_archive_protocol::Profile::current().ok_or(AdmissionFailure::Inventory)?,self.developer_path.as_ref().ok_or(AdmissionFailure::Unknown)?, root(developer),
            self.tool_data(self.executable)?, self.sdk_path.as_ref().ok_or(AdmissionFailure::Unknown)?, root(sdk))
            .map_err(|_| AdmissionFailure::Inventory)
    }
    fn tool_data(&self, index: Option<usize>) -> Result<crate::ios_archive_protocol::ToolIdentity> {
        use crate::ios_archive_protocol::ToolIdentity;
        let tool = self.original.records.get(index.ok_or(AdmissionFailure::Unknown)?)
            .and_then(|record| record.identity).ok_or(AdmissionFailure::Identity)?;
        let nanos = |seconds: i64, remainder: i64| -> Result<String> {
            if !(0..1_000_000_000).contains(&remainder) { return Err(AdmissionFailure::Identity); }
            seconds.checked_mul(1_000_000_000).and_then(|s| s.checked_add(remainder)).filter(|n| *n >= 0)
                .map(|n| n.to_string()).ok_or(AdmissionFailure::Identity)
        };
        Ok(ToolIdentity { device: tool.dev.to_string(), inode: tool.ino.to_string(), mode: u32::from(tool.mode),
            uid: tool.uid, gid: tool.gid, links: u32::from(tool.links), size: u64::try_from(tool.size).map_err(native_error)?,
            mtime_ns: nanos(tool.mtime, tool.mtime_ns)?, ctime_ns: nanos(tool.ctime, tool.ctime_ns)? })
    }
    pub(crate) fn signing_binding_data(&self) -> Result<crate::ios_archive_protocol::SigningToolBindings> {
        if !self.original.inspected || !self.original.admission_custody_ready() { return Err(AdmissionFailure::Unknown); }
        let [security, codesign, openssl] = self.signing.ok_or(AdmissionFailure::Inventory)?;
        crate::ios_archive_protocol::SigningToolBindings::new_data(self.tool_data(Some(security))?,
            self.tool_data(Some(codesign))?, self.tool_data(Some(openssl))?).map_err(|_| AdmissionFailure::Inventory)
    }
    pub(crate) fn recovery_binding_data(&self) -> Result<crate::ios_archive_protocol::ToolIdentity> {
        if !self.original.inspected || !self.original.admission_custody_ready()
            || self.signing.is_some() || self.developer.is_some() || self.sdk.is_some() || self.executable.is_some() {
            return Err(AdmissionFailure::Inventory);
        }
        self.tool_data(self.recovery_security)
    }
    pub(crate) fn check_after_use(&self, end: Instant) -> Result<()> {
        self.original.ios_check_after_use(end, &self.audit)?;
        if let Some(alias) = &self.alias {
            ios_audit_point(end, &self.audit)?;
            let actual = stat::fstatat(self.original.fd(alias.parent)?, crate::ios_toolchain::STANDARD_APP,
                AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?;
            if Identity::of(&actual) != alias.identity { return Err(AdmissionFailure::Identity); }
            ios_audit_point(end, &self.audit)?;
            let target = fcntl::readlinkat(self.original.fd(alias.parent)?, crate::ios_toolchain::STANDARD_APP).map_err(native_error)?;
            if PathBuf::from(target) != alias.target { return Err(AdmissionFailure::Identity); }
            ios_audit_point(end, &self.audit)?;
        }
        Ok(())
    }
    pub(crate) fn mark_interrupted(&mut self) { self.original.unknown = true; }
    pub(crate) fn settle_originals(&mut self, expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool) -> CloseOutcome {
        self.original.settle(expired)
    }
    pub(crate) fn settled(&self) -> bool { self.original.settled() }
}

// Test-only DATA calls over the existing nested Android owners.
// Constructors remain inert; no original native frame or descriptor is minted.
#[cfg(test)]
pub(crate) fn installed_android_data_check() -> bool {
    android_runtime::assert_inert_arm_data_contract();
    android_tools::assert_inert_arm_data_contract();
    android_runtime::fd_cleanup_data_check()
}
#[cfg(test)]
mod installed_android_data_tests {
    #[test]
    fn original_android_data_contracts() {
        assert!(super::installed_android_data_check());
    }
}


// The fixed vault helper has separate code/input authority from Python passive/
//edit profiles. Reuse the protected-original/claim pattern and Slice A custody,
//not the runtime selector or a caller-provided executable/roster.
pub(crate) struct VaultHelperSlots{
    original:native::vault_helper_filesystem::CodeOriginals,inspected:bool,claimed:bool,postchecked:bool,
    first:Option<(AdmissionFailure,Instant)>,
    #[cfg(not(feature="macos-android-registration-helper"))]
    command:native::vault_helper_launch::FixedCommand,
}
impl VaultHelperSlots{
    pub(crate) fn new()->Self{Self{original:native::vault_helper_filesystem::CodeOriginals::new(),
        inspected:false,claimed:false,postchecked:false,first:None,
        #[cfg(not(feature="macos-android-registration-helper"))]
        command:native::vault_helper_launch::FixedCommand::new(),
    }}
    fn fail(&mut self,problem:AdmissionFailure)->AdmissionFailure{
        if self.first.is_none(){self.first=Some((problem,Instant::now()));}problem
    }
    pub(crate) fn first_failure(&self)->Option<(AdmissionFailure,Instant)>{
        match(self.first,self.original.first_failure()){
            (Some(a),Some((_,at))) if at<a.1=>Some((AdmissionFailure::Native,at)),
            (None,Some((_,at)))=>Some((AdmissionFailure::Native,at)),(a,_)=>a,
        }
    }
    fn acquire_for_command(&mut self,stop:&mut dyn FnMut()->bool)->Result<()>{
        #[cfg(not(feature="macos-android-registration-helper"))]
        {self.original.acquire_for_helper_launch(stop).map_err(|_|AdmissionFailure::Ownership)}
        #[cfg(feature="macos-android-registration-helper")]
        {let _=stop;Err(AdmissionFailure::Ownership)} // No vault transport in the Android helper role.
    }
    pub(crate) fn inspect_once(&mut self,stop:&mut dyn FnMut()->bool)->Result<()>{
        if self.inspected || self.claimed || self.first.is_some(){return Err(self.fail(AdmissionFailure::AlreadyUsed));}
        let result=(||{
            let expected=option_env!("MRK_MACOS_VAULT_HELPER_SHA256").ok_or(AdmissionFailure::Inventory)?;
            let size=option_env!("MRK_MACOS_VAULT_HELPER_BYTES").and_then(|s|s.parse::<u64>().ok()).ok_or(AdmissionFailure::Inventory)?;
            if !sha(expected) || size==0 || size>32*1024*1024{return Err(AdmissionFailure::Inventory);}
            self.acquire_for_command(stop)?;
            if self.original.helper_bytes()!=Some(size){return Err(AdmissionFailure::Inventory);}
            let mut hash=Sha256::new();let mut count=0u64;let mut block=[0u8;4096];
            loop{
                if stop(){return Err(AdmissionFailure::Stopped);}
                let n=unistd::read(self.original.helper_fd().map_err(|_|AdmissionFailure::Unknown)?,&mut block).map_err(native_error)?;
                if n==0{break;}
                count=count.checked_add(n as u64).ok_or(AdmissionFailure::Bounds)?;
                if count>size{return Err(AdmissionFailure::Inventory);}hash.update(&block[..n]);
            }
            if count!=size || format!("{:x}",hash.finalize())!=expected{return Err(AdmissionFailure::Inventory);}
            self.original.recheck(stop).map_err(|_|AdmissionFailure::Identity)?;Ok(())
        })();
        if let Err(p)=result{self.fail(p);}else{self.inspected=true;}result
    }
    pub(crate) fn prepare_command(&mut self)->Result<()>{
        if !self.inspected || self.claimed || self.first_failure().is_some(){return Err(self.fail(AdmissionFailure::AlreadyUsed));}
        #[cfg(not(feature="macos-android-registration-helper"))]
        let result=self.command.prepare(&mut self.original).map_err(|_|AdmissionFailure::Unknown);
        #[cfg(feature="macos-android-registration-helper")]
        let result=Err(AdmissionFailure::Ownership);
        if let Err(p)=result{self.fail(p);}result
    }
    pub(crate) fn command_ready(&self)->bool{
        #[cfg(not(feature="macos-android-registration-helper"))]
        {self.command.ready()}
        #[cfg(feature="macos-android-registration-helper")]
        {false}
    }
    fn command_storage_empty(&self)->bool{
        #[cfg(not(feature="macos-android-registration-helper"))]
        {self.command.storage_empty()}
        #[cfg(feature="macos-android-registration-helper")]
        {true}
    }
    pub(crate) fn retire_command_storage(&mut self){
        #[cfg(not(feature="macos-android-registration-helper"))]
        self.command.retire_prepared_storage();
    }
    pub(crate) fn claim_once(&mut self)->Result<()>{
        if !self.inspected || self.claimed || !self.command_ready() || self.first_failure().is_some(){return Err(self.fail(AdmissionFailure::AlreadyUsed));}
        self.claimed=true;Ok(())
    }
    pub(crate) fn spawn_original(&mut self)->std::io::Result<std::process::Child>{
        if !self.claimed || self.first_failure().is_some(){return Err(std::io::ErrorKind::PermissionDenied.into());}
        #[cfg(not(feature="macos-android-registration-helper"))]
        {self.command.spawn_once(&mut self.original)}
        #[cfg(feature="macos-android-registration-helper")]
        {Err(std::io::ErrorKind::PermissionDenied.into())}
    }
    pub(crate) fn check_after_use(&mut self,stop:&mut dyn FnMut()->bool)->Result<()>{
        if !self.claimed || self.postchecked{return Err(self.fail(AdmissionFailure::AlreadyUsed));}
        let result=self.original.recheck(stop).map_err(|_|AdmissionFailure::Identity);
        if let Err(p)=result{self.fail(p);}else{self.postchecked=true;}result
    }
    pub(crate) fn check_gate_after_exit(&mut self,expired:&mut dyn FnMut()->bool)->Result<()>{
        // A prior F still permits this original cleanup operation. Native ACL
        // ambiguity is not cleared, and the normal code recheck stays strict.
        if !self.claimed{return Err(self.fail(AdmissionFailure::AlreadyUsed));}
        let result=self.original.check_worker_gate_after_exit(expired).map_err(|_|AdmissionFailure::Identity);
        if let Err(p)=result{self.fail(p);}result
    }
    pub(crate) fn settle_originals(&mut self,expired:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool)->bool{
        let first=self.first;
        self.original.release_code(&mut |failure|{
            let combined=match(first,failure){(Some(a),Some((_,at))) if at<a.1=>Some((AdmissionFailure::Native,at)),
                (None,Some((_,at)))=>Some((AdmissionFailure::Native,at)),(a,_)=>a};expired(combined)
        })
    }
    pub(crate) fn settle_gate(&mut self,expired:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool)->bool{
        let first=self.first;
        self.original.release_worker_gate(&mut |failure|{
            let combined=match(first,failure){(Some(a),Some((_,at))) if at<a.1=>Some((AdmissionFailure::Native,at)),
                (None,Some((_,at)))=>Some((AdmissionFailure::Native,at)),(a,_)=>a};expired(combined)
        })
    }
    pub(crate) fn code_settled(&self)->bool{self.original.code_settled() && self.command_storage_empty()}
    pub(crate) fn gate_facts(&self)->native::vault_helper_filesystem::WorkerGateFacts{self.original.worker_gate_facts()}
    pub(crate) fn settled(&self)->bool{self.original.settled() && self.command_storage_empty()}
    pub(crate) fn retained_bytes(&self)->Option<usize>{self.original.retained_bytes()?.checked_add(std::mem::size_of::<Self>())}
}
