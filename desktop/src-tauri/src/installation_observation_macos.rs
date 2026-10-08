//! Read-only fixed installation correspondence, subordinate to DocumentBinding's
//! original blocking child. No launch capability, maintenance or alternate path.
use super::*;
use crate::{installation::{CheckReason as Problem, Matching},
    macos_install_paths as paths, macos_install_record::{self as data, Inventory, InventoryIndex},
    macos_install_maintenance::{ActionData, MaintenanceTargetData, ReleaseSetData},
    macos_install_producer::{self as producer_data, ProducerData},
    macos_install_transaction::{self as transaction, AppIdentityData, CapsuleData, CorrespondenceData,
        GenerationData, IntentData, StateData}};
use std::mem::size_of;
type InspectResult<T> = std::result::Result<T, Problem>;
pub(crate) const CONTROL_RESERVE: usize = 16 * 1024 * 1024;
const RECORDS: usize = 8256;
const NATIVE_FRAME_LIMIT: usize = 16384;

// Read-only linked DATA. This contains no previous outer-Installer exit proof,
// permission to install, or selected executable. A selected producer set comes
// from the original caller's authenticated package policy, never these files.
struct HistoricalRecord { intent: IntentData, state: StateData, capsule: CapsuleData }

// Route DATA only. A complete triple still owes signature, code-purpose and
// linked-state verification; a partial triple can never select legacy v1.
fn producer_route_data(state: bool, descriptor: bool, signature: bool, supplied: bool) -> InspectResult<bool> {
    match (state,descriptor,signature) {
        (true,true,true) => Ok(true),
        (false,false,false) if !supplied => Ok(false),
        _ => Err(Problem::Incomplete),
    }
}

// This cell belongs to the SAME original blocking inspector as Book. Public
// signed controls are retained outside hashed payload; no installation record
// selects its own expectations and no new thread/clock/root helper is created.
#[cfg(not(feature = "macos-android-registration-helper"))]
struct InstalledProducer {
    originals: [usize;6], descriptor: Vec<u8>, signature_bytes: Vec<u8>,
    signature: native::install_producer::ProducerVerifier,
    entry: native::install_producer::CurrentProductVerifier,
    payload: native::install_producer::CurrentProductVerifier,
}
#[cfg(not(feature = "macos-android-registration-helper"))]
impl InstalledProducer {
    fn new(originals: [usize;6], descriptor: Vec<u8>, signature_bytes: Vec<u8>) -> Self {
        use native::install_producer::{ProducerVerifier,CurrentProductVerifier,CurrentProductRole};
        Self { originals,descriptor,signature_bytes,signature:ProducerVerifier::new(),
            entry:CurrentProductVerifier::new(CurrentProductRole::EntryApp),
            payload:CurrentProductVerifier::new(CurrentProductRole::PayloadApp) }
    }
    fn planned_bytes() -> Option<usize> {
        native::install_producer::ProducerVerifier::project_owned_upper_bound()?
            .checked_add(native::install_producer::CurrentProductVerifier::project_owned_upper_bound()?.checked_mul(2)?)?
            .checked_add(size_of::<Self>())?.checked_add(8 * producer_data::DESCRIPTOR_LIMIT)?
            .checked_add(producer_data::SIGNATURE_LIMIT)
    }
    fn retained_bytes(&self) -> Option<usize> {
        if [self.signature.custody(),self.entry.custody(),self.payload.custody()].iter()
            .any(|c| c.unknown || c.in_call || c.gate_entered) { return None; }
        Self::planned_bytes()?.checked_add(self.descriptor.capacity())?.checked_add(self.signature_bytes.capacity())
    }
    fn post(book: &Book, originals: &[usize;6], end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        book.point(end,stop)?;
        for index in originals { book.check_name(*index,end,stop)?; }
        book.point(end,stop)
    }
    fn point(book: &Book, originals: &[usize;6], end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem,Instant), expired: &mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool,
        point: native::install_producer::ProducerCheckpoint) -> native::android_service_management::Decision {
        use native::{android_service_management::Decision,install_producer::ProducerCheckpoint};
        let (phase,custody) = match point {
            ProducerCheckpoint::Before{phase,custody} | ProducerCheckpoint::Returned{phase,custody,..} => (phase,custody),
        };
        if let Some(at) = custody.first_failure {
            let why = if custody.unknown { AdmissionFailure::Unknown } else { AdmissionFailure::Native };
            book.note_acl(why,at); publish(native_problem(why),at);
        }
        if custody.unknown { return Decision::Unknown; }
        if phase.is_cleanup() {
            // STOP closes only already owned originals inside the containing
            // owner's existing cleanup endpoint. No work or new interval here.
            let registration_expired = book.registration_gate.as_ref()
                .is_some_and(|gate| gate.source_cleanup_expired(book.first_failure()));
            let owner_expired = expired(book.first_failure());
            return if registration_expired || owner_expired { Decision::Stop } else { Decision::Proceed };
        }
        match Self::post(book,originals,end,stop) {
            Ok(()) => Decision::Proceed,
            Err(failure) => {
                let at = Instant::now(); book.note_acl(failure,at); publish(native_problem(failure),at);
                if matches!(failure,AdmissionFailure::Unknown | AdmissionFailure::Identity) { Decision::Unknown } else { Decision::Stop }
            },
        }
    }
    fn verify(&mut self, book: &Book, target: MaintenanceTargetData, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem,Instant), expired: &mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool) -> InspectResult<ReleaseSetData> {
        use native::install_producer::{SignatureResult,CurrentProductResult};
        let Self { originals,descriptor,signature_bytes,signature,entry,payload } = self;
        Self::post(book,originals,end,stop).map_err(native_problem)?;
        let signed = signature.verify_and_close(descriptor,signature_bytes,
            &mut |point| Self::point(book,originals,end,stop,publish,expired,point));
        if !signature.settled() { return Err(Problem::CleanupUnknown); }
        if signed != SignatureResult::SignatureVerified { return Err(match signed {
            SignatureResult::Unavailable => Problem::UnavailableProfile, SignatureResult::Unknown => Problem::CleanupUnknown,
            _ => Problem::RecordMismatch,
        }); }
        // Still comparison DATA until both fixed App purposes have matched.
        let parsed = ProducerData::parse_data(descriptor,target).map_err(|_| Problem::RecordMismatch)?;
        Self::post(book,originals,end,stop).map_err(native_problem)?;
        let signer = native::install_producer::source_signer_data().ok_or(Problem::UnavailableProfile)?;
        Self::post(book,originals,end,stop).map_err(native_problem)?;
        if !parsed.signing_policy_data().matches_source_data(signer.team_data(),signer.leaf_sha1_data(),signer.leaf_sha256_data()) {
            return Err(Problem::RecordMismatch);
        }
        let outer = book.fd(originals[2]).map_err(native_problem)?;
        let payload_fd = book.fd(originals[5]).map_err(native_problem)?;
        let entry_result = entry.verify_and_close(outer.as_fd(),outer.as_fd(),Path::new(paths::APP),
            &mut |point| Self::point(book,originals,end,stop,publish,expired,point));
        if !entry.settled() { return Err(Problem::CleanupUnknown); }
        if entry_result != CurrentProductResult::PurposeVerified { return Err(match entry_result {
            CurrentProductResult::Unavailable => Problem::UnavailableProfile,CurrentProductResult::Unknown => Problem::CleanupUnknown,
            _ => Problem::RecordMismatch,
        }); }
        let payload_result = payload.verify_and_close(outer.as_fd(),payload_fd.as_fd(),Path::new(paths::APP),
            &mut |point| Self::point(book,originals,end,stop,publish,expired,point));
        if !payload.settled() { return Err(Problem::CleanupUnknown); }
        if payload_result != CurrentProductResult::PurposeVerified { return Err(match payload_result {
            CurrentProductResult::Unavailable => Problem::UnavailableProfile,CurrentProductResult::Unknown => Problem::CleanupUnknown,
            _ => Problem::RecordMismatch,
        }); }
        Self::post(book,originals,end,stop).map_err(native_problem)?;
        Ok(parsed.release_set_data().clone())
    }
    fn settle(&mut self, book: &Book, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem,Instant),
        expired: &mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool) -> bool {
        let Self { originals,signature,entry,payload,.. } = self;
        let mut gate = |point| Self::point(book,originals,end,stop,publish,expired,point);
        let p = payload.close(&mut gate); let e = entry.close(&mut gate); let s = signature.close(&mut gate);
        p && e && s && payload.settled() && entry.settled() && signature.settled()
    }
}

fn problem(failure: AdmissionFailure, content: Problem) -> Problem {
    match failure {
        AdmissionFailure::Stopped => Problem::Cancelled,
        AdmissionFailure::Deadline => Problem::Deadline,
        AdmissionFailure::Bounds => Problem::Bounds,
        AdmissionFailure::Native => Problem::Native,
        AdmissionFailure::Ownership => Problem::Protection,
        AdmissionFailure::Inventory => content,
        AdmissionFailure::Identity | AdmissionFailure::AlreadyUsed | AdmissionFailure::Unknown => Problem::CleanupUnknown,
    }
}
pub(crate) fn native_problem(failure: AdmissionFailure) -> Problem { problem(failure, Problem::PayloadMismatch) }

pub(crate) struct InstallationSlots {
    book: Option<Book>, entered: bool, native_settled: bool, storage_disposed: bool,
    #[cfg(not(feature = "macos-android-registration-helper"))]
    producer: Option<InstalledProducer>,
    // Original positive returns, never substitute for a child/coordinator join.
    files: u32, bytes: u64,
}
impl InstallationSlots {
    pub(crate) fn new() -> Self {
        Self { book: Some(Book::new()), entered: false, native_settled: false, storage_disposed: false,
            #[cfg(not(feature = "macos-android-registration-helper"))]
            producer:None, files: 0, bytes: 0 }
    }
    #[cfg(not(feature = "macos-android-registration-helper"))]
    pub(crate) fn new_registered(gate: crate::saved_command_owner::AndroidRegistrationWorkGate) -> Self {
        // Same inert installation inspector, now subordinate to the caller's
        // original registration clock/cohort. No entry or observation here.
        let mut book = Book::new(); book.registration_gate = Some(gate);
        Self { book: Some(book), entered: false, native_settled: false, storage_disposed: false, producer:None, files: 0, bytes: 0 }
    }
    pub(crate) fn settled(&self) -> bool {
        self.producer_absent() && ((!self.entered && self.book.as_ref().is_some_and(Book::never_started))
            || (self.entered && self.native_settled && self.storage_disposed && self.book.is_none()))
    }
    pub(crate) fn storage_released(&self) -> bool { self.settled() }
    pub(crate) fn settlement_facts(&self) -> (bool, bool) { (self.native_settled, self.storage_disposed) }
    pub(crate) fn observed_settled(&self) -> bool {
        self.entered && self.native_settled && self.storage_disposed && self.book.is_none() && self.producer_absent()
    }
    fn producer_absent(&self) -> bool {
        #[cfg(not(feature = "macos-android-registration-helper"))]
        { self.producer.is_none() }
        #[cfg(feature = "macos-android-registration-helper")]
        { true }
    }
    pub(crate) fn control_bytes(&self) -> Option<usize> {
        let heap = match &self.book { Some(book) => book.retained_heap_bytes()?, None if self.storage_disposed => 0, _ => return None };
        #[cfg(not(feature = "macos-android-registration-helper"))]
        let producer = match &self.producer { Some(producer) => producer.retained_bytes()?, None => 0 };
        #[cfg(feature = "macos-android-registration-helper")]
        let producer = 0;
        size_of::<Self>().checked_add(heap)?.checked_add(producer)
    }
    fn note_native(&self, publish: &mut dyn FnMut(Problem, Instant)) {
        if let Some((failure, at)) = self.book.as_ref().and_then(Book::first_failure) {
            publish(native_problem(failure), at);
        }
    }
    fn reject<T>(&self, why: Problem, at: Instant, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<T> {
        self.note_native(publish); publish(why, at); Err(why)
    }
    fn attempt<T>(&mut self, content: Problem, publish: &mut dyn FnMut(Problem, Instant),
        call: impl FnOnce(&mut Book) -> Result<T>) -> InspectResult<T> {
        let Some(book) = self.book.as_mut() else { return self.reject(Problem::CleanupUnknown, Instant::now(), publish); };
        let returned = call(book);
        let at = Instant::now(); // Before a containing-owner/Document mutex or join.
        self.note_native(publish);
        match returned {
            Ok(value) => {
                // Every successful native return is quiescent. Check actual
                // retained capacities before permitting its next successor.
                match self.control_bytes() {
                    Some(bytes) if bytes <= CONTROL_RESERVE => Ok(value),
                    Some(_) => self.reject(Problem::Bounds, at, publish),
                    None => self.reject(Problem::CleanupUnknown, at, publish),
                }
            },
            Err(failure) => self.reject(problem(failure, content), at, publish),
        }
    }
    fn check(&self, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        let returned = checkpoint(end, stop);
        let at = Instant::now();
        match returned { Ok(()) => Ok(()), Err(failure) => self.reject(native_problem(failure), at, publish) }
    }
    fn directory_identity(&self, index: usize) -> InspectResult<data::DirectoryIdentity> {
        let id = self.book.as_ref().and_then(|book| book.records.get(index)).and_then(|r| r.identity)
            .ok_or(Problem::CleanupUnknown)?;
        let stable = data::DirectoryIdentity { device: i64::from(id.dev), inode: id.ino,
            mode: u32::from(id.mode), uid: id.uid, gid: id.gid, flags: id.flags };
        stable.valid().then_some(stable).ok_or(Problem::Protection)
    }
    fn protected(&mut self, index: usize, mode: u16, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        self.attempt(Problem::PayloadMismatch, publish, |book| {
            checkpoint(end, stop)?;
            let id = book.records.get(index).and_then(|r| r.identity).ok_or(AdmissionFailure::Identity)?;
            if id.uid != 0 || id.gid != 0 || id.mode & 0o7777 != mode || id.flags != 0 { return Err(AdmissionFailure::Ownership); }
            native::no_xattrs(book.fd(index)?.as_fd()).map_err(native_error)?;
            book.check_name(index, end, stop)
        })
    }
    fn open(&mut self, parent: Option<usize>, name: &str, directory: bool, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<usize> {
        self.attempt(Problem::PayloadMismatch, publish, |book| book.open(parent, name, directory, end, stop))
    }
    fn close(&mut self, index: usize, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        self.check(end, stop, publish)?;
        self.attempt(Problem::PayloadMismatch, publish, |book| {
            if book.close(index) { Ok(()) } else { Err(AdmissionFailure::Unknown) }
        })?;
        self.check(end, stop, publish)
    }
    // Missing is an observed negative, not a guess from Book::open's Native.
    // Hold/recheck the exact protected parent and repeat only the fixed no-follow
    // observation. The bounded recheck cannot renew work or cleanup.
    fn require_present(&mut self, parent: usize, name: &str, missing: Problem, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        self.check(end, stop, publish)?;
        self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, end, stop))?;
        let observed = match self.book.as_ref().and_then(|book| book.fd(parent).ok()) {
            Some(fd) => stat::fstatat(fd, name, AtFlags::AT_SYMLINK_NOFOLLOW),
            None => return self.reject(Problem::CleanupUnknown, Instant::now(), publish),
        };
        let first_at = Instant::now();
        match observed {
            Ok(_) => Ok(()),
            Err(nix::errno::Errno::ENOENT) => {
                let recheck_end = end.min(first_at + std::time::Duration::from_secs(2));
                // ENOENT becomes "missing" only after this bounded confirmation.
                // A stop/error breaks the confirmation immediately; never use
                // cleanup permission to issue another inspection. Either outcome
                // contracts cleanup from the ORIGINAL negative-return instant.
                let confirmed = (|| -> InspectResult<()> {
                    self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, recheck_end, stop))?;
                    self.check(recheck_end, stop, publish)?;
                    let repeated = match self.book.as_ref().and_then(|book| book.fd(parent).ok()) {
                        Some(fd) => stat::fstatat(fd, name, AtFlags::AT_SYMLINK_NOFOLLOW),
                        None => return self.reject(Problem::CleanupUnknown, Instant::now(), publish),
                    };
                    let repeated_at = Instant::now();
                    if !matches!(repeated, Err(nix::errno::Errno::ENOENT)) {
                        return self.reject(Problem::CleanupUnknown, repeated_at, publish);
                    }
                    self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, recheck_end, stop))
                })();
                self.reject(if confirmed.is_ok() { missing } else { Problem::CleanupUnknown }, first_at, publish)
            },
            Err(_) => self.reject(Problem::Native, first_at, publish),
        }
    }
    fn held_record(&mut self, parent: usize, name: &str, limit: usize, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<(usize,Vec<u8>)> {
        self.require_present(parent, name, Problem::Incomplete, end, stop, publish)?;
        let index = self.open(Some(parent), name, false, end, stop, publish)?;
        self.protected(index, 0o444, end, stop, publish)?;
        let size = self.book.as_ref().and_then(|book| book.records[index].identity)
            .and_then(|id| u64::try_from(id.size).ok()).filter(|size| *size > 0 && *size <= limit as u64);
        let Some(size) = size else { return self.reject(Problem::Bounds, Instant::now(), publish); };
        let (_, bytes) = self.attempt(Problem::RecordMismatch, publish, |book| book.read(index, size, true, end, stop))?;
        Ok((index,bytes))
    }
    fn read_record(&mut self, parent: usize, name: &str, limit: usize, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<Vec<u8>> {
        let (index,bytes) = self.held_record(parent,name,limit,end,stop,publish)?;
        self.close(index, end, stop, publish)?;
        Ok(bytes)
    }
    fn control_present(&mut self, parent: usize, name: &str, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem,Instant)) -> InspectResult<bool> {
        // Only ENOENT between complete unchanged-parent observations is an
        // absence. A symlink, denied lookup, or changed parent cannot choose v1.
        self.attempt(Problem::RecordMismatch,publish,|book| book.check_name(parent,end,stop))?;
        let observed = match self.book.as_ref().and_then(|book| book.fd(parent).ok()) {
            Some(fd) => stat::fstatat(fd,name,AtFlags::AT_SYMLINK_NOFOLLOW),
            None => return self.reject(Problem::CleanupUnknown,Instant::now(),publish),
        };
        let at = Instant::now();
        let present = match observed { Ok(_) => true, Err(nix::errno::Errno::ENOENT) => false,
            Err(_) => return self.reject(Problem::Native,at,publish) };
        self.attempt(Problem::RecordMismatch,publish,|book| book.check_name(parent,end,stop))?;
        Ok(present)
    }
    fn installed_selection(&mut self, install: usize, supplied: Option<&ReleaseSetData>, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem,Instant),
        cleanup_expired: &mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool) -> InspectResult<Option<ReleaseSetData>> {
        let target = MaintenanceTargetData::compiled().ok_or(Problem::UnavailableProfile)?;
        let (descriptor_name,signature_name) = producer_data::installed_control_names_data(target,paths::RELEASE)
            .map_err(|_| Problem::RecordMismatch)?;
        let state_present = self.control_present(install,transaction::STATE_NAME,end,stop,publish)?;
        let descriptor_present = self.control_present(install,&descriptor_name,end,stop,publish)?;
        let signature_present = self.control_present(install,&signature_name,end,stop,publish)?;
        let v2 = match producer_route_data(state_present,descriptor_present,signature_present,supplied.is_some()) {
            Ok(value) => value, Err(why) => return self.reject(why,Instant::now(),publish),
        };
        if !v2 {
            // The later exact legacy roster also refuses stray historical v2
            // names. Absence is not migration permission or a signing fallback.
            return Ok(None);
        }
        #[cfg(feature = "macos-android-registration-helper")]
        {
            // This inspector already requires NORMAL_MAC_PROFILE before I/O;
            // helper startup uses its own ServiceBook/Publisher/QueryReader and
            // never enters this UI reader. Do not feature-unify a signer there.
            let _ = cleanup_expired;
            return self.reject(Problem::UnavailableProfile,Instant::now(),publish);
        }
        #[cfg(not(feature = "macos-android-registration-helper"))]
        {
            if self.producer.is_some() { return self.reject(Problem::CleanupUnknown,Instant::now(),publish); }
            let planned = self.control_bytes().and_then(|n| InstalledProducer::planned_bytes()?.checked_add(n));
            if planned.is_none_or(|n| n > CONTROL_RESERVE) { return self.reject(Problem::Bounds,Instant::now(),publish); }
            let (descriptor_original,descriptor) = self.held_record(install,&descriptor_name,producer_data::DESCRIPTOR_LIMIT,end,stop,publish)?;
            let (signature_original,signature) = self.held_record(install,&signature_name,producer_data::SIGNATURE_LIMIT,end,stop,publish)?;
            let outer = self.open(Some(install),paths::APP_NAME,true,end,stop,publish)?;
            let contents = self.open(Some(outer),"Contents",true,end,stop,publish)?;
            let helpers = self.open(Some(contents),"Helpers",true,end,stop,publish)?;
            let payload = self.open(Some(helpers),paths::PAYLOAD_NAME,true,end,stop,publish)?;
            for original in [outer,contents,helpers,payload] { self.protected(original,0o555,end,stop,publish)?; }
            // Store every inert native wrapper before its first call. An error
            // retains this same cell and all borrowed FDs for original cleanup.
            self.producer = Some(InstalledProducer::new([descriptor_original,signature_original,outer,contents,helpers,payload],descriptor,signature));
            if self.control_bytes().is_none_or(|n| n > CONTROL_RESERVE) {
                return self.reject(Problem::Bounds,Instant::now(),publish);
            }
            let selected = match (self.producer.as_mut(),self.book.as_ref()) {
                (Some(producer),Some(book)) => producer.verify(book,target,end,stop,publish,cleanup_expired),
                _ => Err(Problem::CleanupUnknown),
            };
            let selected = match selected { Ok(value) => value,
                Err(why) => return self.reject(why,Instant::now(),publish) };
            if supplied.is_some_and(|old| old.target_data() != selected.target_data()
                || old.current_data() != selected.current_data() || old.predecessor_data() != selected.predecessor_data()) {
                return self.reject(Problem::RecordMismatch,Instant::now(),publish);
            }
            self.check(end,stop,publish)?;
            Ok(Some(selected))
        }
    }
    fn roster(&mut self, parent: usize, limit: usize, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<BTreeMap<String, (u64, u8)>> {
        let mut local = BTreeMap::new(); let mut buffer = [0u8; 65536];
        loop {
            self.check(end, stop, publish)?;
            let used = self.attempt(Problem::PayloadMismatch, publish, |book|
                native::directory_block(book.fd(parent)?.as_fd(), &mut buffer).map_err(native_error))?;
            if used == 0 { break; }
            let mut offset = 0;
            while offset < used {
                if used - offset < 11 { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
                // Eleven available bytes above prove this fixed array read.
                let inode = u64::from_ne_bytes([buffer[offset], buffer[offset+1], buffer[offset+2], buffer[offset+3],
                    buffer[offset+4], buffer[offset+5], buffer[offset+6], buffer[offset+7]]);
                let kind = buffer[offset+8];
                let length = usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let Some(next) = offset.checked_add(11 + length).filter(|n| *n <= used) else {
                    return self.reject(Problem::PayloadMismatch, Instant::now(), publish);
                };
                let name = match std::str::from_utf8(&buffer[offset+11..next]) {
                    Ok(name) => name, Err(_) => return self.reject(Problem::PayloadMismatch, Instant::now(), publish),
                };
                offset = next;
                if name == "." || name == ".." { continue; }
                if !matches!(kind, nix::libc::DT_DIR | nix::libc::DT_REG) || inode == 0
                    || !name.is_ascii() || name.contains('/')
                    || !(name == paths::APP_NAME || runtime::safe_payload_path(name)) {
                    return self.reject(Problem::PayloadMismatch, Instant::now(), publish);
                }
                if local.len() >= limit || local.insert(name.to_owned(), (inode, kind)).is_some() {
                    return self.reject(Problem::Bounds, Instant::now(), publish);
                }
            }
        }
        self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, end, stop))?;
        Ok(local)
    }
    fn match_fixed_roster(&mut self, parent: usize, names: &[&str], optional_stage: Option<&str>, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        let roster = self.roster(parent, names.len() + usize::from(optional_stage.is_some()), end, stop, publish)?;
        let expected = names.iter().all(|name| roster.contains_key(*name))
            && roster.keys().all(|name| names.contains(&name.as_str()) || optional_stage == Some(name.as_str()));
        if !expected { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
        if let Some(name) = optional_stage.filter(|name| roster.contains_key(*name)) {
            self.check(end, stop, publish)?;
            let before = self.attempt(Problem::PayloadMismatch, publish, |book|
                stat::fstatat(book.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error))?;
            if before.st_mode != (SFlag::S_IFDIR.bits() | 0o700) || before.st_uid != 0 || before.st_gid != 0
                || before.st_flags != 0 || roster[name] != (before.st_ino, nix::libc::DT_DIR) {
                return self.reject(Problem::Protection, Instant::now(), publish);
            }
            self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, end, stop))?;
            let after = self.attempt(Problem::PayloadMismatch, publish, |book|
                stat::fstatat(book.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error))?;
            if Identity::of(&before) != Identity::of(&after) {
                return self.reject(Problem::CleanupUnknown, Instant::now(), publish);
            }
            // The root-only staging directory is metadata-only. Never open it.
        }
        Ok(())
    }
    fn history_read(&mut self, parent: usize, name: &str, limit: usize, retained: &mut usize,
        base: usize, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<Vec<u8>> {
        // Typed history has only bounded ASCII fields/arrays. Charge eight times
        // all original bytes plus a per-record backing allowance BEFORE another
        // parser/read. The existing 4MiB parser/native-frame reserve remains in
        // base; actual Book capacities are still checked at every native return.
        let available = CONTROL_RESERVE.checked_sub(base).and_then(|n| n.checked_sub(*retained))
            .and_then(|n| n.checked_sub(4096)).map(|n| n / 8).unwrap_or(0);
        if available == 0 { return self.reject(Problem::Bounds, Instant::now(), publish); }
        let bytes = self.read_record(parent, name, limit.min(available), end, stop, publish)?;
        let charge = bytes.capacity().checked_mul(8).and_then(|n| n.checked_add(4096))
            .and_then(|n| retained.checked_add(n)).filter(|n| base.checked_add(*n).is_some_and(|v| v <= CONTROL_RESERVE));
        let Some(charge) = charge else { return self.reject(Problem::Bounds, Instant::now(), publish); };
        *retained = charge; Ok(bytes)
    }
    fn history_record(&mut self, install: usize, invocation: &str, state: StateData, selected: &ReleaseSetData,
        retained: &mut usize, base: usize, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<HistoricalRecord> {
        if state.invocation_data() != invocation || !state.mutation_recorded_data() {
            return self.reject(Problem::Incomplete, Instant::now(), publish);
        }
        let intent_name = transaction::intent_name_data(invocation).map_err(|_| Problem::RecordMismatch)?;
        let capsule_name = transaction::capsule_name_data(invocation).map_err(|_| Problem::RecordMismatch)?;
        let intent_bytes = self.history_read(install,&intent_name,transaction::INTENT_LIMIT,retained,base,end,stop,publish)?;
        let capsule_bytes = self.history_read(install,&capsule_name,transaction::CAPSULE_LIMIT,retained,base,end,stop,publish)?;
        let intent = match IntentData::parse_recorded_data(&intent_bytes,selected) {
            Ok(value) => value, Err(_) => return self.reject(Problem::RecordMismatch,Instant::now(),publish),
        };
        let capsule = match CapsuleData::parse_recorded_data(&capsule_bytes,selected) {
            Ok(value) => value, Err(_) => return self.reject(Problem::RecordMismatch,Instant::now(),publish),
        };
        if intent.invocation_data() != invocation || capsule.invocation_data() != invocation {
            return self.reject(Problem::RecordMismatch,Instant::now(),publish);
        }
        Ok(HistoricalRecord { intent,state,capsule })
    }
    fn app_identity(&self, index: usize) -> InspectResult<AppIdentityData> {
        let value = self.book.as_ref().and_then(|book| book.records.get(index)).and_then(|r| r.identity)
            .ok_or(Problem::CleanupUnknown)?;
        AppIdentityData::from_original_fields_data(i64::from(value.dev),value.ino,u32::from(value.mode),
            value.uid,value.gid,value.flags).map_err(|_| Problem::Protection)
    }
    fn private_stage(&mut self, install: usize, name: &str, inode: u64, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        self.check(end,stop,publish)?;
        let before = self.attempt(Problem::PayloadMismatch,publish,|book|
            stat::fstatat(book.fd(install)?,name,AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error))?;
        if before.st_mode != (SFlag::S_IFDIR.bits() | 0o700) || before.st_uid != 0 || before.st_gid != 0
            || before.st_flags != 0 || before.st_ino != inode {
            return self.reject(Problem::Protection,Instant::now(),publish);
        }
        self.attempt(Problem::PayloadMismatch,publish,|book| book.check_name(install,end,stop))?;
        let after = self.attempt(Problem::PayloadMismatch,publish,|book|
            stat::fstatat(book.fd(install)?,name,AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error))?;
        if Identity::of(&before) != Identity::of(&after) { return self.reject(Problem::CleanupUnknown,Instant::now(),publish); }
        // An ordinary nonroot reader does not open root's0700 receipt directory
        // or claim to have inspected its contents. Actual maintenance's new EX
        // owner reobserves the complete contents before any later mutation.
        Ok(())
    }
    fn v2_roster(&mut self, install: usize, versions: usize, current_record: &data::Record,
        install_root: data::DirectoryIdentity, release_directory: data::DirectoryIdentity,
        selected: &ReleaseSetData, base: usize, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<GenerationData> {
        let mut retained = crate::macos_install_maintenance::INPUT_LIMIT * 8;
        let raw = self.history_read(install,transaction::STATE_NAME,transaction::STATE_LIMIT,&mut retained,base,end,stop,publish)?;
        let state = match StateData::parse_data(&raw,selected) {
            Ok(value) => value, Err(_) => return self.reject(Problem::RecordMismatch,Instant::now(),publish),
        };
        let links:Vec<_> = state.evidence_data().map(|r| (r.invocation.to_owned(),r.intent_sha256.to_owned(),
            r.state_sha256.to_owned(),r.capsule_sha256.to_owned())).collect();
        let invocation = state.invocation_data().to_owned();
        let current = self.history_record(install,&invocation,state,selected,&mut retained,base,end,stop,publish)?;
        let mut history = BTreeMap::new();
        for (invocation,intent_sha,state_sha,capsule_sha) in links {
            let name = transaction::archived_state_name_data(&invocation).map_err(|_| Problem::RecordMismatch)?;
            let bytes = self.history_read(install,&name,transaction::STATE_LIMIT,&mut retained,base,end,stop,publish)?;
            let state = match StateData::parse_data(&bytes,selected) {
                Ok(value) => value, Err(_) => return self.reject(Problem::RecordMismatch,Instant::now(),publish),
            };
            if state.digest_data() != state_sha { return self.reject(Problem::RecordMismatch,Instant::now(),publish); }
            let record = self.history_record(install,&invocation,state,selected,&mut retained,base,end,stop,publish)?;
            if record.intent.digest_data() != intent_sha || record.capsule.digest_data() != capsule_sha
                || history.insert(invocation,record).is_some() {
                return self.reject(Problem::RecordMismatch,Instant::now(),publish);
            }
        }
        let mut names = BTreeSet::from([paths::APP_NAME.to_owned(),"versions".to_owned(),
            paths::MAINTENANCE_GATE_NAME.to_owned(),paths::REGISTRATION_GATE_NAME.to_owned(),transaction::STATE_NAME.to_owned()]);
        let current_controls = producer_data::installed_control_names_data(selected.target_data(),paths::RELEASE)
            .map_err(|_| Problem::RecordMismatch)?;
        names.insert(current_controls.0); names.insert(current_controls.1);
        let mut stages = BTreeSet::new();
        let mut requests = BTreeSet::new();
        for record in history.values().chain(std::iter::once(&current)) {
            self.check(end,stop,publish)?;
            if !requests.insert(record.intent.request_id_data()) {
                return self.reject(Problem::RecordMismatch,Instant::now(),publish);
            }
            let previous = match record.intent.previous_state_data() {
                None => None,
                Some((invocation,sha)) => {
                    let Some(old):Option<&HistoricalRecord> = history.get(invocation) else {
                        return self.reject(Problem::Incomplete,Instant::now(),publish);
                    };
                    if old.state.digest_data() != sha { return self.reject(Problem::RecordMismatch,Instant::now(),publish); }
                    Some((&old.state,&old.capsule))
                },
            };
            if transaction::correspondence_data(&record.intent,previous,Some(&record.state),Some(&record.capsule))
                != CorrespondenceData::MatchingRecordedData {
                return self.reject(Problem::RecordMismatch,Instant::now(),publish);
            }
            let invocation = record.state.invocation_data();
            names.insert(transaction::intent_name_data(invocation).map_err(|_| Problem::RecordMismatch)?);
            names.insert(transaction::capsule_name_data(invocation).map_err(|_| Problem::RecordMismatch)?);
            if invocation != current.state.invocation_data() {
                names.insert(transaction::archived_state_name_data(invocation).map_err(|_| Problem::RecordMismatch)?);
            }
            if record.intent.action_data() != ActionData::SamePackageNoop {
                let stage = format!(".install-{invocation}"); names.insert(stage.clone()); stages.insert(stage);
            }
        }
        let generation = current.state.current_data();
        if generation.release_data() != selected.current_data() || generation.instance_data() != current_record.instance()
            || generation.release_directory_data() != release_directory {
            return self.reject(Problem::RecordMismatch,Instant::now(),publish);
        }
        let mut version_names = BTreeSet::from([paths::RELEASE.to_owned()]);
        for old in current.state.retained_data() {
            self.check(end,stop,publish)?;
            // Only SOURCE-selected exact predecessors can name retained roots.
            // These metadata/identity checks do not claim historical payload
            // byte reinspection or old outer-process finality. Current payload
            // is still fully hashed below; a later writer rehashes every root.
            let binding = old.release_data().binding_data();
            let name = transaction::retained_app_name_data(old.retained_invocation_data().ok_or(Problem::RecordMismatch)?)
                .map_err(|_| Problem::RecordMismatch)?;
            if !names.insert(name.clone()) || !version_names.insert(binding.release.to_owned()) {
                return self.reject(Problem::RecordMismatch,Instant::now(),publish);
            }
            let old_app = self.open(Some(install),&name,true,end,stop,publish)?;
            self.protected(old_app,0o555,end,stop,publish)?;
            if self.app_identity(old_app)? != old.app_identity_data() { return self.reject(Problem::RecordMismatch,Instant::now(),publish); }
            let old_release = self.open(Some(versions),binding.release,true,end,stop,publish)?;
            self.protected(old_release,0o755,end,stop,publish)?;
            if self.directory_identity(old_release)? != old.release_directory_data() { return self.reject(Problem::RecordMismatch,Instant::now(),publish); }
            self.match_fixed_roster(old_release,&["runtime",data::INVENTORY_NAME,data::RECORD_NAME],None,end,stop,publish)?;
            // These two temporary originals are charged then released before
            // the next predecessor. They are never retained as a second core.
            let checkpoint_retained = retained;
            let controls = producer_data::installed_control_names_data(selected.target_data(),binding.release)
                .map_err(|_| Problem::RecordMismatch)?;
            if !names.insert(controls.0.clone()) || !names.insert(controls.1.clone()) {
                return self.reject(Problem::RecordMismatch,Instant::now(),publish);
            }
            let producer_bytes = self.history_read(install,&controls.0,producer_data::DESCRIPTOR_LIMIT,&mut retained,base,end,stop,publish)?;
            let signature_bytes = self.history_read(install,&controls.1,producer_data::SIGNATURE_LIMIT,&mut retained,base,end,stop,publish)?;
            let producer = ProducerData::parse_data(&producer_bytes,selected.target_data()).map_err(|_| Problem::RecordMismatch)?;
            if producer.release_set_data().current_data() != old.release_data() {
                return self.reject(Problem::RecordMismatch,Instant::now(),publish);
            }
            // Old public controls remain at their immutable original names.
            // This bounded DATA correspondence is not an old-signature or
            // historical-outer-success assertion by the current signer.
            let descriptor = self.history_read(old_release,data::RECORD_NAME,data::RECORD_LIMIT,&mut retained,base,end,stop,publish)?;
            let inventory = self.history_read(old_release,data::INVENTORY_NAME,data::INVENTORY_LIMIT,&mut retained,base,end,stop,publish)?;
            let expected = data::Expected { kind:data::Kind::Ordinary,source_commit:binding.source_commit,
                runtime_manifest:binding.runtime_manifest_sha256,install_root,release_directory:old.release_directory_data() };
            let record = match data::Record::parse_for_release_data(&descriptor,&inventory,&expected,old.release_data()) {
                Ok(value) => value, Err(_) => return self.reject(Problem::RecordMismatch,Instant::now(),publish),
            };
            if record.instance() != old.instance_data() { return self.reject(Problem::RecordMismatch,Instant::now(),publish); }
            let old_runtime = self.open(Some(old_release),"runtime",true,end,stop,publish)?;
            self.protected(old_runtime,0o555,end,stop,publish)?;
            self.close(old_runtime,end,stop,publish)?; self.close(old_release,end,stop,publish)?; self.close(old_app,end,stop,publish)?;
            drop(record); drop(inventory); drop(descriptor);
            drop(producer); drop(producer_bytes); drop(signature_bytes); retained = checkpoint_retained;
        }
        let actual = self.roster(install,names.len(),end,stop,publish)?;
        if actual.keys().cloned().collect::<BTreeSet<_>>() != names { return self.reject(Problem::PayloadMismatch,Instant::now(),publish); }
        for stage in stages {
            let Some((inode,kind)) = actual.get(&stage).copied() else { return self.reject(Problem::Incomplete,Instant::now(),publish); };
            if kind != nix::libc::DT_DIR { return self.reject(Problem::Protection,Instant::now(),publish); }
            self.private_stage(install,&stage,inode,end,stop,publish)?;
        }
        let version_roster = self.roster(versions,version_names.len(),end,stop,publish)?;
        if version_roster.keys().cloned().collect::<BTreeSet<_>>() != version_names
            || version_roster.values().any(|(_,kind)| *kind != nix::libc::DT_DIR) {
            return self.reject(Problem::PayloadMismatch,Instant::now(),publish);
        }
        // All temporary historical DATA is dropped before current payload walk.
        // Matching below continues to describe only that compiled current code.
        Ok(generation)
    }
    fn walk(&mut self, parent: usize, prefix: &str, index: &InventoryIndex<'_>, observed: &mut BTreeSet<String>,
        depth: usize, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant),
        read_returned: &mut dyn FnMut(u32, u64)) -> InspectResult<()> {
        if depth > 16 { return self.reject(Problem::Bounds, Instant::now(), publish); }
        let expected = index.files.keys().chain(index.directories.iter()).filter(|path|
            immediate_child(prefix, path)).count();
        if expected > data::FILE_LIMIT * 2 { return self.reject(Problem::Bounds, Instant::now(), publish); }
        // Bounds follow the inventory's immediate roster, not a per-depth4096
        // allocation. Extra names cannot accumulate at every retained ancestor.
        let roster = self.roster(parent, expected, end, stop, publish)?;
        if roster.len() != expected { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
        for (name, (inode, kind)) in roster {
            self.check(end, stop, publish)?;
            let path = format!("{prefix}/{name}");
            let directory = index.directories.contains(&path);
            if !directory && !index.files.contains_key(&path) || path.len() > 1024
                || observed.len() >= data::FILE_LIMIT * 2 || !observed.insert(path.clone()) {
                return self.reject(Problem::PayloadMismatch, Instant::now(), publish);
            }
            if kind != if directory { nix::libc::DT_DIR } else { nix::libc::DT_REG } {
                return self.reject(Problem::PayloadMismatch, Instant::now(), publish);
            }
            let item = self.open(Some(parent), &name, directory, end, stop, publish)?;
            if self.book.as_ref().and_then(|book| book.records[item].identity).is_none_or(|id| id.ino != inode) {
                return self.reject(Problem::CleanupUnknown, Instant::now(), publish);
            }
            let executable = index.files.get(&path).is_some_and(|entry| entry.executable);
            self.protected(item, if directory || executable { 0o555 } else { 0o444 }, end, stop, publish)?;
            if directory { self.walk(item, &path, index, observed, depth+1, end, stop, publish, read_returned)?; }
            else {
                let Some(entry) = index.files.get(&path) else { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); };
                let hash = self.attempt(Problem::PayloadMismatch, publish, |book| book.read(item, entry.size, false, end, stop))?.0;
                if hash != entry.sha256 { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
                let Some(files) = self.files.checked_add(1).filter(|n| *n <= data::FILE_LIMIT as u32) else {
                    return self.reject(Problem::Bounds, Instant::now(), publish);
                };
                let Some(bytes) = self.bytes.checked_add(entry.size).filter(|n| *n <= data::PAYLOAD_LIMIT) else {
                    return self.reject(Problem::Bounds, Instant::now(), publish);
                };
                self.files = files; self.bytes = bytes;
                // Read-only scalar progress, and the sole permitted test pause
                // hook: this original child, after a real successful full read.
                read_returned(self.files, self.bytes);
                self.check(end, stop, publish)?;
            }
            self.close(item, end, stop, publish)?;
        }
        self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, end, stop))
    }
    fn inspect(&mut self, supplied: Option<&ReleaseSetData>, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant),
        cleanup_expired: &mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool,
        read_returned: &mut dyn FnMut(u32, u64)) -> InspectResult<Matching> {
        self.check(end, stop, publish)?;
        if !crate::installation::NORMAL_MAC_PROFILE { return self.reject(Problem::UnavailableProfile, Instant::now(), publish); }
        let user = native::real_user(); let user_at = Instant::now();
        if user.is_err() { return self.reject(Problem::Protection, user_at, publish); }
        self.check(end, stop, publish)?;
        let executable = std::env::current_exe(); let executable_at = Instant::now();
        if executable.as_ref().is_err() { return self.reject(Problem::Native, executable_at, publish); }
        if executable.as_deref().ok() != Some(Path::new(paths::PAYLOAD_EXECUTABLE)) {
            return self.reject(Problem::WrongLocation, executable_at, publish);
        }
        self.attempt(Problem::PayloadMismatch, publish, |book| book.arm_acl_once(end, stop))?;
        self.attempt(Problem::PayloadMismatch, publish, |book| {
            if !book.inspection_ready() { return Err(AdmissionFailure::AlreadyUsed); }
            book.records.try_reserve_exact(RECORDS).map_err(|_| AdmissionFailure::Bounds)?;
            book.started = true; Ok(())
        })?;
        let root = self.open(None, "/", true, end, stop, publish)?;
        let library = self.open(Some(root), "Library", true, end, stop, publish)?;
        let support = self.open(Some(library), "Application Support", true, end, stop, publish)?;
        self.require_present(support, "MobileReleaseKit", Problem::Missing, end, stop, publish)?;
        let install = self.open(Some(support), "MobileReleaseKit", true, end, stop, publish)?;
        self.protected(install, 0o755, end, stop, publish)?;
        self.require_present(install, paths::MAINTENANCE_GATE_NAME, Problem::Incomplete, end, stop, publish)?;
        {
            let gate_data = self.read_record(install, paths::MAINTENANCE_GATE_NAME, paths::MAINTENANCE_GATE_BYTES.len(), end, stop, publish)?;
            if gate_data != paths::MAINTENANCE_GATE_BYTES { return self.reject(Problem::RecordMismatch, Instant::now(), publish); }
        }
        self.require_present(install, paths::REGISTRATION_GATE_NAME, Problem::Incomplete, end, stop, publish)?;
        {
            // One additional closed Book record; the fixed38B original is
            // consumed before producer/payload work. This is not R_EX evidence.
            let reservation_data = self.read_record(install, paths::REGISTRATION_GATE_NAME, paths::REGISTRATION_GATE_BYTES.len(), end, stop, publish)?;
            if reservation_data != paths::REGISTRATION_GATE_BYTES { return self.reject(Problem::RecordMismatch, Instant::now(), publish); }
        }
        let authenticated = self.installed_selection(install,supplied,end,stop,publish,cleanup_expired)?;
        let selected = authenticated.as_ref();
        if let Some(selected) = selected {
            let value = selected.current_data().binding_data();
            if MaintenanceTargetData::compiled() != Some(selected.target_data()) || value.release != paths::RELEASE
                || value.package_version != paths::PACKAGE_VERSION || value.package_identifier != paths::PACKAGE_ID
                || value.bundle_identifier != paths::BUNDLE_ID || value.protocol_sha256 != paths::PROTOCOL_SHA
                || value.source_commit != option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").unwrap_or("")
                || value.runtime_manifest_sha256 != option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").unwrap_or("") {
                return self.reject(Problem::RecordMismatch,Instant::now(),publish);
            }
        }
        self.require_present(install, "versions", Problem::Incomplete, end, stop, publish)?;
        let versions = self.open(Some(install), "versions", true, end, stop, publish)?;
        self.protected(versions, 0o755, end, stop, publish)?;
        self.require_present(versions, paths::RELEASE, Problem::Incomplete, end, stop, publish)?;
        let release = self.open(Some(versions), paths::RELEASE, true, end, stop, publish)?;
        self.protected(release, 0o755, end, stop, publish)?;
        let descriptor = self.read_record(release, data::RECORD_NAME, data::RECORD_LIMIT, end, stop, publish)?;
        let inventory_bytes = self.read_record(release, data::INVENTORY_NAME, data::INVENTORY_LIMIT, end, stop, publish)?;
        let install_root = match self.directory_identity(install) {
            Ok(value) => value, Err(why) => return self.reject(why, Instant::now(), publish),
        };
        let release_directory = match self.directory_identity(release) {
            Ok(value) => value, Err(why) => return self.reject(why, Instant::now(), publish),
        };
        let source = option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").unwrap_or("");
        let manifest = option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").unwrap_or("");
        let expected = data::Expected { kind: data::Kind::Ordinary, source_commit: source, runtime_manifest: manifest,
            install_root, release_directory };
        let parsed_record = match selected {
            Some(selected) => data::Record::parse_for_release_data(&descriptor,&inventory_bytes,&expected,selected.current_data()),
            None => data::Record::parse_data(&descriptor,&inventory_bytes,&expected),
        };
        let record = match parsed_record {
            Ok(record) => record, Err(_) => return self.reject(Problem::RecordMismatch, Instant::now(), publish),
        };
        self.check(end, stop, publish)?;
        let inventory = match Inventory::parse(&inventory_bytes, manifest) {
            Ok(inventory) => inventory, Err(_) => return self.reject(Problem::RecordMismatch, Instant::now(), publish),
        };
        let index = match inventory.index() { Ok(index) => index, Err(_) => return self.reject(Problem::RecordMismatch, Instant::now(), publish) };
        // No opaque current native allocation receives zero credit. This native
        // snapshot is quiescent here; every live/native frame must be accountable.
        let Some(native_bytes) = self.control_bytes() else { return self.reject(Problem::CleanupUnknown, Instant::now(), publish); };
        let planned = control_bound(&descriptor, &inventory_bytes, &inventory, &index, native_bytes);
        let Some(planned) = planned.filter(|bytes| *bytes <= CONTROL_RESERVE) else {
            return self.reject(Problem::Bounds, Instant::now(), publish);
        };
        // Prove a required absence before checking a complete roster; an absent
        // app/runtime is incomplete, not an unexplained generic mismatch.
        self.require_present(install, paths::APP_NAME, Problem::Incomplete, end, stop, publish)?;
        self.require_present(release, "runtime", Problem::Incomplete, end, stop, publish)?;
        let generation = if let Some(selected) = selected {
            Some(self.v2_roster(install,versions,&record,install_root,release_directory,selected,planned,end,stop,publish)?)
        } else {
            // Legacy engineering read-only roster remains closed; current code
            // additionally requires permanent R. It cannot migrate/adopt a v2
            // layout or wildcard predecessor names.
            self.match_fixed_roster(install, &[paths::APP_NAME, "versions", paths::MAINTENANCE_GATE_NAME, paths::REGISTRATION_GATE_NAME], Some(&format!(".install-{}", record.instance())), end, stop, publish)?;
            self.match_fixed_roster(versions, &[paths::RELEASE], None, end, stop, publish)?;
            None
        };
        self.match_fixed_roster(release, &["runtime", data::INVENTORY_NAME, data::RECORD_NAME], None, end, stop, publish)?;
        let app = self.open(Some(install), paths::APP_NAME, true, end, stop, publish)?;
        self.protected(app, 0o555, end, stop, publish)?;
        if let Some(generation) = generation {
            if self.app_identity(app)? != generation.app_identity_data() { return self.reject(Problem::RecordMismatch,Instant::now(),publish); }
        }
        let runtime = self.open(Some(release), "runtime", true, end, stop, publish)?;
        self.protected(runtime, 0o555, end, stop, publish)?;
        let mut observed = BTreeSet::from(["app".to_owned(), "runtime".to_owned()]);
        self.walk(app, "app", &index, &mut observed, 0, end, stop, publish, read_returned)?;
        self.walk(runtime, "runtime", &index, &mut observed, 0, end, stop, publish, read_returned)?;
        if observed.len() != index.files.len() + index.directories.len() || self.files as usize != index.files.len()
            || self.bytes != index.payload_bytes { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
        let Some(book) = self.book.as_ref() else { return self.reject(Problem::CleanupUnknown, Instant::now(), publish); };
        let count = book.records.len();
        for original in 0..count {
            if self.book.as_ref().is_some_and(|book| book.records[original].state == State::Owned) {
                self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(original, end, stop))?;
            }
        }
        self.check(end, stop, publish)?;
        match Matching::checked(self.files as usize, self.bytes) {
            Some(result) => Ok(result), None => self.reject(Problem::Bounds, Instant::now(), publish),
        }
    }
    pub(crate) fn run(&mut self, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant),
        cleanup_expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool,
        read_returned: &mut dyn FnMut(u32, u64)) -> InspectResult<Matching> {
        self.run_selected(None,end,stop,publish,cleanup_expired,read_returned)
    }
    /// Optional extra DATA correspondence from an existing caller. It cannot
    /// bypass the same original installed-control signature/purpose admission;
    /// the installation never chooses or downgrades its own expected release.
    pub(crate) fn run_for_selected_release_data(&mut self, selected: &ReleaseSetData, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant),
        cleanup_expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool,
        read_returned: &mut dyn FnMut(u32, u64)) -> InspectResult<Matching> {
        self.run_selected(Some(selected),end,stop,publish,cleanup_expired,read_returned)
    }
    fn run_selected(&mut self, selected: Option<&ReleaseSetData>, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant), cleanup_expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool,
        read_returned: &mut dyn FnMut(u32, u64)) -> InspectResult<Matching> {
        if self.entered || !self.book.as_ref().is_some_and(Book::never_started) {
            return self.reject(Problem::CleanupUnknown, Instant::now(), publish);
        }
        self.entered = true;
        let result = self.inspect(selected,end, stop, publish, cleanup_expired, read_returned);
        let at = Instant::now();
        if let Err(why) = result { self.note_native(publish); publish(why, at); }
        // Stop means no more inspection, not permission to skip independently
        // allowed original cleanup. There is no second worker or new interval.
        #[cfg(not(feature = "macos-android-registration-helper"))]
        let producer_cleaned = match (self.producer.as_mut(),self.book.as_ref()) {
            (None,_) => true,
            (Some(producer),Some(book)) => producer.settle(book,end,stop,publish,cleanup_expired),
            _ => false,
        };
        #[cfg(feature = "macos-android-registration-helper")]
        let producer_cleaned = true;
        // Native borrowers retire first. Unknown native custody retains this
        // original cell AND Book descriptors; no Drop/FD close substitutes.
        let cleaned = producer_cleaned && self.book.as_mut()
            .is_some_and(|book| book.settle(cleanup_expired) == CloseOutcome::Settled && book.settled());
        self.note_native(publish);
        self.native_settled = cleaned;
        if cleaned {
            // Only already-closed DATA leaves the original. Drop is explicitly
            // not a native settle operation; its real return precedes credit.
            let closed = self.book.take();
            drop(closed);
            #[cfg(not(feature = "macos-android-registration-helper"))]
            {
                let producer = self.producer.take(); drop(producer);
            }
            self.storage_disposed = true;
        } else { publish(Problem::CleanupUnknown, Instant::now()); }
        if !self.settled() { return Err(Problem::CleanupUnknown); }
        // An original refusal has already set STOP. Do not replace that
        // diagnosis with a later checkpoint's generic Cancelled.
        if result.is_ok() { self.check(end, stop, publish)?; }
        result
    }
}

fn immediate_child(parent: &str, path: &str) -> bool {
    path.strip_prefix(parent).and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|name| !name.is_empty() && !name.contains('/'))
}

// Conservative complete backing bound: existing strict JSON is node/depth
// bounded while parsing, and only <=1MiB DATA is collected. The parser arena is
// gone before the indexed walk. Reserve 4MiB for its transient nodes/control,
// native frame <=16KiB, Book's entire8256-cell ledger, bounded recursion/blocks,
// copied/indexed String backing, directory/observed nodes and streamed rosters.
// Exact current capacities are checked too; opaque live SDK memory is Unknown.
fn control_bound(descriptor: &Vec<u8>, raw: &Vec<u8>, inventory: &Inventory, index: &InventoryIndex<'_>, native_bytes: usize) -> Option<usize> {
    let mut bytes = (4usize * 1024 * 1024).checked_add(NATIVE_FRAME_LIMIT)?
        .checked_add(17usize.checked_mul(65536)?)? // Bounded retained walk frames.
        .checked_add(128 * 1024)? // Read block, fixed rosters and control/signal DATA.
        .checked_add(RECORDS.checked_mul(size_of::<Record>())?)?
        .checked_add(native_bytes)?.checked_add(descriptor.capacity())?.checked_add(raw.capacity())?
        .checked_add(inventory.files.capacity().checked_mul(size_of::<data::Entry>())?)?;
    for entry in &inventory.files { bytes = bytes.checked_add(entry.path.capacity())?.checked_add(entry.sha256.capacity())?; }
    for path in index.files.keys().chain(index.directories.iter()) {
        // Original index + observed path + transient constructed path,
        // historical Book names and at most one full immediate roster per path.
        // The extra2048 charges worst-case512-byte unknown short names plus
        // BTree/String/node/control overhead before their mismatch is rejected.
        bytes = bytes.checked_add(path.capacity().checked_mul(4)?)?.checked_add(2048)?;
    }
    Some(bytes)
}

#[cfg(test)]
#[test]
fn installation_roster_uses_fixed_app_name_and_global_inventory_bound() {
    assert!(!runtime::safe_payload_path(paths::APP_NAME));
    assert!(paths::APP_NAME == "Mobile Release Kit.app");
    let paths = ["app/Contents", "app/Contents/Info.plist", "app/Contents/MacOS",
        data::APP_BINARY, "runtime/python", "runtime/python/bin"];
    assert_eq!(paths.iter().filter(|path| immediate_child("app", path)).count(), 1);
    assert_eq!(paths.iter().filter(|path| immediate_child("app/Contents", path)).count(), 2);
    assert!(!immediate_child("app", "application/Contents"));
    assert!(!immediate_child("app", "app/"));
    assert!(!immediate_child("app/Contents", "app/Contents/MacOS/nested"));
    for bits in 0..8 {
        let state = bits & 1 != 0; let descriptor = bits & 2 != 0; let signature = bits & 4 != 0;
        assert_eq!(producer_route_data(state,descriptor,signature,false),
            match bits { 0 => Ok(false), 7 => Ok(true), _ => Err(Problem::Incomplete) });
        assert_eq!(producer_route_data(state,descriptor,signature,true),
            if bits == 7 { Ok(true) } else { Err(Problem::Incomplete) });
    }
    #[cfg(not(feature = "macos-android-registration-helper"))]
    {
        let original = InstallationSlots::new();
        assert!(original.producer_absent() && original.settled());
        assert!(InstalledProducer::planned_bytes().is_some_and(|n| n > 0 && n < CONTROL_RESERVE));
        // Inert wrappers are not consuming-close facts until their original
        // owner actually invokes close. No native/Security entry in this DATA.
        let cell = InstalledProducer::new([0;6],Vec::new(),Vec::new());
        assert!(!cell.signature.settled() && !cell.entry.settled() && !cell.payload.settled());
        assert!(cell.retained_bytes().is_some_and(|n| n > 0 && n < CONTROL_RESERVE));
    }
}
