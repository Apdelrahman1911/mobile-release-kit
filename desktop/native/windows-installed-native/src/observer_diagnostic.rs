//! The one qualification-only append leaf. Ordinary OriginalFile sharing and
//! success result writers are deliberately unchanged. No Drop closes a handle.
use super::*;
use crate::ui_observer_diagnostic_data as data;
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
use data::{Event, Frame, JournalOrder, Latch, Refusal, Snapshot};
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Both authorities are allocated from the original UI admission, never from
/// timeout/finality. Shared latches cannot be reset by a new cursor or helper.
#[cfg(test)]
pub(crate) struct ObserverDiagnosticClock {
    entry: u64, execution_tick: u64, execution_end: Instant,
    diagnostic: Option<(u64, Instant)>,
    execution_latched: std::sync::atomic::AtomicBool,
    diagnostic_latched: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
impl ObserverDiagnosticClock {
    pub(crate) fn new(entry: u64, execution_end: Instant) -> Result<Self> {
        let execution_tick = entry.checked_add(data::EXECUTION_MS).ok_or(Error::Bounds)?;
        let diagnostic = entry.checked_add(data::DIAGNOSTIC_MS).zip(
            execution_end.checked_add(std::time::Duration::from_millis(data::DIAGNOSTIC_MS - data::EXECUTION_MS)));
        Ok(Self { entry, execution_tick, execution_end, diagnostic,
            execution_latched: std::sync::atomic::AtomicBool::new(false),
            diagnostic_latched: std::sync::atomic::AtomicBool::new(false) })
    }
    pub(crate) fn permitted(&self, failure: bool) -> bool {
        let (tick, end, latched) = if failure {
            let Some((tick, end)) = self.diagnostic else { return false; };
            (tick, end, &self.diagnostic_latched)
        } else { (self.execution_tick, self.execution_end, &self.execution_latched) };
        data::window_sample(self.entry, tick, unsafe { SI::GetTickCount64() }, Instant::now() < end, latched)
    }
    fn ceiling(&self) -> Instant { self.diagnostic.map_or(self.execution_end, |(_, end)| end) }
}

const APPEND_ACCESS: u32 = FS::FILE_APPEND_DATA | FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::SYNCHRONIZE;
#[repr(C, align(8))]
struct StreamBuffer([u8; 40]);

fn observer_role(role: UiRole) -> bool { matches!(role, UiRole::ProjectDraft | UiRole::QuitPassive | UiRole::DocumentLoss) }
fn fixed_leaf(role: UiRole, output: &Path) -> Result<PathBuf> {
    need(observer_role(role) && output.file_name().and_then(|name| name.to_str()) == Some(role.name("output").as_str()))?;
    fixed_path(output.to_str().ok_or(Error::Unsafe)?)?;
    Ok(output.join(role.name(data::SUFFIX)))
}

fn append_acl(parent: &[u8], account: &[u8]) -> Result<(Box<Aligned>, usize)> {
    let principals = [(system_sid(), FS::FILE_ALL_ACCESS), (builtin(544), FS::FILE_ALL_ACCESS),
        (parent.to_vec(), FS::FILE_ALL_ACCESS), (account.to_vec(), APPEND_ACCESS)];
    need(principals.iter().enumerate().all(|(i, (sid, _))| principals[..i].iter().all(|(prior, _)| prior != sid)))?;
    let size = 8 + principals.iter().map(|(sid, _)| 8 + sid.len()).sum::<usize>();
    need(size < BUFFER && size <= u16::MAX as usize)?;
    let mut acl = Box::new(Aligned([0; BUFFER]));
    acl.0[0] = 2; acl.0[2..4].copy_from_slice(&(size as u16).to_le_bytes()); acl.0[4..6].copy_from_slice(&4u16.to_le_bytes());
    let mut at = 8;
    for (sid, rights) in principals {
        need(security::sid_at(&sid, 0, sid.len())?.bytes() == sid)?;
        let length = 8 + sid.len();
        acl.0[at + 2..at + 4].copy_from_slice(&(length as u16).to_le_bytes());
        acl.0[at + 4..at + 8].copy_from_slice(&rights.to_le_bytes());
        acl.0[at + 8..at + length].copy_from_slice(&sid); at += length;
    }
    Ok((acl, size))
}
fn descriptor_matches(raw: &[u8], acl: &[u8], parent: &[u8], account: &[u8]) -> Result<()> {
    need(raw.len() >= 20 && raw.len() <= BUFFER && raw[0] == 1 && raw[1] == 0)?;
    let control = decode::u16_at(raw, 2)?;
    let required = S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED;
    let known = S::SE_OWNER_DEFAULTED | S::SE_GROUP_DEFAULTED | S::SE_DACL_PRESENT | S::SE_DACL_DEFAULTED
        | S::SE_SACL_PRESENT | S::SE_SACL_DEFAULTED | S::SE_DACL_AUTO_INHERIT_REQ | S::SE_SACL_AUTO_INHERIT_REQ
        | S::SE_DACL_AUTO_INHERITED | S::SE_SACL_AUTO_INHERITED | S::SE_DACL_PROTECTED | S::SE_SACL_PROTECTED | S::SE_SELF_RELATIVE;
    need(control & required == required && control & !known == 0
        && control & S::SE_DACL_AUTO_INHERITED == 0 && decode::u32_at(raw, 12)? == 0)?;
    let dacl = decode::u32_at(raw, 16)? as usize;
    need(dacl >= 20 && dacl % 4 == 0 && decode::span(raw, dacl, acl.len())? == acl)?;
    let principal = |offset| -> Result<(Vec<u8>, (usize, usize))> {
        let start = decode::u32_at(raw, offset)? as usize;
        need(start >= 20 && start % 4 == 0)?;
        let sid = security::sid_at(raw, start, raw.len())?.bytes().to_vec();
        need(start + sid.len() <= dacl || start >= dacl + acl.len())?;
        let end = start + sid.len(); Ok((sid, (start, end)))
    };
    let (owner, owner_range) = principal(4)?; let (group, group_range) = principal(8)?;
    need(group_range == owner_range || group_range.1 <= owner_range.0 || group_range.0 >= owner_range.1)?;
    need([system_sid(), builtin(544), parent.to_vec()].contains(&owner) && owner != account && group != account)
}

#[derive(Clone)]
struct Identity { volume: u64, id: [u8; 16], creation: i64, attributes: u32 }
impl Identity {
    fn of(stamp: &Stamp) -> Self { Self { volume: stamp.volume, id: stamp.id, creation: stamp.creation, attributes: stamp.attributes } }
    fn parse(value: &str) -> Result<Self> {
        artifact_identity(value)?; let fields: Vec<_> = value.split(':').collect();
        let mut id = [0; 16]; id.copy_from_slice(&unhex(fields[1])?);
        Ok(Self { volume: fields[0].parse().map_err(|_| Error::Unsafe)?, id,
            creation: fields[2].parse().map_err(|_| Error::Unsafe)?, attributes: fields[5].parse().map_err(|_| Error::Unsafe)? })
    }
    fn matches(&self, stamp: &Stamp) -> bool {
        self.volume == stamp.volume && self.id == stamp.id && self.creation == stamp.creation
            && self.attributes == stamp.attributes && stamp.links == 1 && stamp.size >= 0 && stamp.size as usize <= data::BYTE_LIMIT
    }
}

// This type alone can open the append journal with write sharing. It is never
// used for ordinary inputs/results, and never shares DELETE. The parent creates
// the EMPTY file read-only and retains that SAME original through child finality;
// there is no transient writer close/reopen or identity gap.
struct JournalFile { original: OriginalFile, streams: Box<StreamBuffer>, stream_return: i32 }
impl JournalFile {
    fn new(path: &Path, end: Instant) -> Result<Self> {
        Ok(Self { original: OriginalFile::new_until(path, false, end)?, streams: Box::new(StreamBuffer([0; 40])), stream_return: 0 })
    }
    fn check(&mut self, permitted: &dyn Fn() -> bool) -> Result<()> { need(permitted())?; self.original.body().timely() }
    fn open(&mut self, parent_create: bool, security: *const S::SECURITY_ATTRIBUTES, permitted: &dyn Fn() -> bool) -> Result<()> {
        self.check(permitted)?;
        let b = self.original.body(); need(b.state == SlotState::Reserved && !b.active)?;
        b.state = SlotState::Acquiring; b.active = true;
        b.handle = unsafe { FS::CreateFileW(b.path.as_ptr(), if parent_create { FS::FILE_GENERIC_READ } else { APPEND_ACCESS },
            FS::FILE_SHARE_READ | if parent_create { FS::FILE_SHARE_WRITE } else { 0 }, security,
            if parent_create { FS::CREATE_NEW } else { FS::OPEN_EXISTING },
            FS::FILE_FLAG_OPEN_REPARSE_POINT | FS::FILE_ATTRIBUTE_ARCHIVE, null_mut()) };
        b.error = if valid_handle(b.handle) { 0 } else { unsafe { F::GetLastError() } };
        if valid_handle(b.handle) { b.active = false; b.state = SlotState::Owned; }
        else if b.error != 0 && b.error != F::ERROR_IO_PENDING && b.handle == F::INVALID_HANDLE_VALUE {
            b.active = false; b.state = SlotState::NoHandle; self.check(permitted)?; return Err(Error::Unavailable);
        } else { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        self.check(permitted)
    }
    fn named(&mut self, path: &Path, permitted: &dyn Fn() -> bool) -> Result<()> {
        self.check(permitted)?; self.original.named(path)?; self.check(permitted)
    }
    fn stamp(&mut self, permitted: &dyn Fn() -> bool) -> Result<Stamp> {
        // Refresh the borrowed original document checkpoint before AND after
        // every native effect, including each member of the metadata group.
        for which in 0..4 {
            self.check(permitted)?; self.original.info(which, &mut InputTrace::default())?; self.check(permitted)?;
        }
        let b = self.original.body();
        need(!b.standard.Directory && !b.standard.DeletePending && b.standard.EndOfFile >= 0
            && b.standard.EndOfFile as usize <= data::BYTE_LIMIT && b.standard.AllocationSize >= 0
            && b.standard.NumberOfLinks == 1 && b.tag.FileAttributes == b.basic.FileAttributes
            && b.basic.FileAttributes & (FS::FILE_ATTRIBUTE_REPARSE_POINT | FS::FILE_ATTRIBUTE_DIRECTORY) == 0
            && b.id.FileId.Identifier != [0; 16])?;
        Ok(Stamp { volume: b.id.VolumeSerialNumber, id: b.id.FileId.Identifier, creation: b.basic.CreationTime,
            write: b.basic.LastWriteTime, change: b.basic.ChangeTime, size: b.standard.EndOfFile,
            allocation: b.standard.AllocationSize, links: b.standard.NumberOfLinks, attributes: b.basic.FileAttributes })
    }
    fn descriptor(&mut self, acl: &[u8], parent: &[u8], account: &[u8], permitted: &dyn Fn() -> bool) -> Result<()> {
        self.check(permitted)?; let raw = self.original.descriptor()?; self.check(permitted)?;
        descriptor_matches(&raw, acl, parent, account)
    }
    fn streams(&mut self, permitted: &dyn Fn() -> bool) -> Result<()> {
        self.check(permitted)?; self.streams.0.fill(0);
        let b = self.original.body(); need(b.state == SlotState::Owned && !b.active)?; b.active = true;
        self.stream_return = unsafe { FS::GetFileInformationByHandleEx(b.handle, FS::FileStreamInfo,
            self.streams.0.as_mut_ptr().cast(), self.streams.0.len() as u32) };
        b.error = if self.stream_return != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = self.stream_return == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        self.check(permitted)?; need(self.stream_return != 0)?;
        decode::streams(&self.streams.0, FileKind::File)
    }
    fn append(&mut self, raw: &[u8], permitted: &dyn Fn() -> bool) -> Result<()> {
        self.check(permitted)?; self.original.write(raw, data::RECORD_LIMIT)?; self.check(permitted)
    }
    #[cfg(test)]
    fn read(&mut self, permitted: &dyn Fn() -> bool) -> Result<Vec<u8>> {
        // SAME pinned parent original and bounded full EOF. The selected90/110
        // gate surrounds EVERY metadata member and the one ReadFile, not just
        // a compound OriginalFile::read call whose ceiling may be110s.
        let before = self.stamp(permitted)?;
        let b = self.original.body(); b.raw = vec![0; before.size as usize + 1]; b.count = 0;
        self.check(permitted)?;
        let b = self.original.body(); need(b.state == SlotState::Owned && !b.active)?; b.active = true;
        let returned = unsafe { FS::ReadFile(b.handle, b.raw.as_mut_ptr(), b.raw.len() as u32, &mut b.count, null_mut()) };
        b.error = if returned != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = returned == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        self.check(permitted)?;
        let b = self.original.body(); need(returned != 0 && b.count as i64 == before.size)?;
        let raw = b.raw[..b.count as usize].to_vec();
        need(self.stamp(permitted)? == before)?; Ok(raw)
    }
    fn close(&mut self) -> Result<()> { self.original.close() } // Original close is allowed late, never retried.
}

/// Existing native owner retains this object BEFORE create enters. No new
/// process/thread/timer, no caller-selected path and no inherited handle.
#[cfg(test)]
pub(crate) struct ObserverDiagnosticOriginal {
    file: JournalFile, path: PathBuf, role: UiRole, parent: Vec<u8>, account: Vec<u8>,
    acl: Box<Aligned>, acl_size: usize, descriptor: Box<S::SECURITY_DESCRIPTOR>, attributes: Box<S::SECURITY_ATTRIBUTES>,
    initialized: i32, dacl_return: i32, control_return: i32, created: Option<Stamp>, binding: Option<String>,
    clock: Arc<ObserverDiagnosticClock>, read_started: bool,
}
#[cfg(test)]
impl ObserverDiagnosticOriginal {
    pub(crate) fn new(role: UiRole, output: &Path, parent: &[u8], account: &[u8], clock: Arc<ObserverDiagnosticClock>) -> Result<Self> {
        let path = fixed_leaf(role, output)?; let (acl, acl_size) = append_acl(parent, account)?;
        Ok(Self { file: JournalFile::new(&path, clock.ceiling())?, path, role, parent: parent.to_vec(), account: account.to_vec(),
            acl, acl_size, descriptor: Box::new(S::SECURITY_DESCRIPTOR::default()), attributes: Box::new(S::SECURITY_ATTRIBUTES::default()),
            initialized: 0, dacl_return: 0, control_return: 0, created: None, binding: None, clock, read_started: false })
    }
    pub(crate) fn create(&mut self, request_sha: &str) -> Result<()> {
        need(self.created.is_none() && self.binding.is_none() && is_hex(request_sha, 64))?;
        let clock = Arc::clone(&self.clock); let permitted = || clock.permitted(false);
        self.file.check(&permitted)?;
        self.initialized = unsafe { S::InitializeSecurityDescriptor((&mut *self.descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), 1) };
        self.file.check(&permitted)?; need(self.initialized != 0)?;
        self.file.check(&permitted)?;
        self.dacl_return = unsafe { S::SetSecurityDescriptorDacl((&mut *self.descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
            1, self.acl.0.as_ptr().cast(), 0) };
        self.file.check(&permitted)?; need(self.dacl_return != 0)?;
        self.file.check(&permitted)?;
        self.control_return = unsafe { S::SetSecurityDescriptorControl((&mut *self.descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
            S::SE_DACL_PROTECTED, S::SE_DACL_PROTECTED) };
        self.file.check(&permitted)?; need(self.control_return != 0)?;
        self.attributes.nLength = size_of::<S::SECURITY_ATTRIBUTES>() as u32;
        self.attributes.lpSecurityDescriptor = (&mut *self.descriptor as *mut S::SECURITY_DESCRIPTOR).cast();
        self.attributes.bInheritHandle = 0;
        self.file.open(true, &*self.attributes, &permitted)?;
        self.file.named(&self.path, &permitted)?;
        let stamp = self.file.stamp(&permitted)?; need(stamp.size == 0)?;
        self.file.descriptor(&self.acl.0[..self.acl_size], &self.parent, &self.account, &permitted)?;
        self.file.streams(&permitted)?; need(self.file.stamp(&permitted)? == stamp)?;
        self.binding = Some(format!("1|{request_sha}|{}", stamp.wire())); self.created = Some(stamp); Ok(())
    }
    pub(crate) fn binding(&self, role: UiRole, output: &Path) -> Result<&str> {
        need(self.role == role && self.path == fixed_leaf(role, output)?)?;
        self.binding.as_deref().ok_or(Error::State)
    }
    pub(crate) fn name(&self) -> String { self.role.name(data::SUFFIX) }
    // Caller first opens a retained share-read-only NativeBook cursor under the
    // SAME output original. It excludes writers before this original full EOF.
    pub(crate) fn poststate(&mut self, failure: bool) -> Result<(Stamp, Vec<u8>)> {
        need(!self.read_started)?; self.read_started = true;
        let clock = Arc::clone(&self.clock); let permitted = || clock.permitted(failure);
        let expected = Identity::of(self.created.as_ref().ok_or(Error::State)?);
        self.file.named(&self.path, &permitted)?; let before = self.file.stamp(&permitted)?; need(expected.matches(&before))?;
        self.file.descriptor(&self.acl.0[..self.acl_size], &self.parent, &self.account, &permitted)?;
        self.file.streams(&permitted)?;
        let raw = self.file.read(&permitted)?;
        self.file.descriptor(&self.acl.0[..self.acl_size], &self.parent, &self.account, &permitted)?;
        self.file.streams(&permitted)?;
        need(self.file.stamp(&permitted)? == before && raw.len() == before.size as usize)?;
        Ok((before, raw)) // Raw partial tail is DATA; parsing cannot decide readiness.
    }
    pub(crate) fn close(&mut self) -> Result<()> { self.file.close() }
    pub(crate) fn is_closed(&self) -> bool { self.file.original.is_closed() }
    pub(crate) fn unresolved(&self) -> bool {
        self.file.original.body.active || matches!(self.file.original.body.state,
            SlotState::Acquiring | SlotState::Closing | SlotState::Unknown)
    }
}

/// Fixed observer context contains only Rust DATA/atomics, not a transported
/// HANDLE. Every append cursor and all native buffers stay on its actual caller.
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
pub struct ObserverDiagnostic {
    path: PathBuf, identity: Identity, parent: Vec<u8>, account: Vec<u8>, acl: Box<Aligned>, acl_size: usize,
    end: Instant, order: JournalOrder, latch: Latch, startup: AtomicU64, bytes: AtomicUsize,
}
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
impl ObserverDiagnostic {
    pub fn admit(end: Instant) -> Result<Self> {
        deadline(Some(end))?; let role = require_normal_ui_qualification()?;
        let request_raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
        let request = UiRequest::parse(request_raw.as_bytes())?;
        let output = fixed_path(&std::env::var("MRK_WINDOWS_NORMAL_UI_OUTPUT").map_err(|_| Error::State)?)?;
        request.at_root(output.parent().ok_or(Error::Unsafe)?)?;
        need(std::env::current_dir().map_err(|_| Error::Unavailable)? == output)?;
        let path = fixed_leaf(role, &output)?;
        let raw = std::env::var(data::IDENTITY_ENV).map_err(|_| Error::State)?;
        need(raw.len() <= 228 && raw.is_ascii())?;
        let values: Vec<_> = raw.split('|').collect();
        need(values.len() == 3 && values[0] == "1" && is_hex(values[1], 64)
            && fullwalk_digest(request_raw.as_bytes(), end, false)? == values[1])?;
        let identity = Identity::parse(values[2])?;
        let parent = unhex(&std::env::var("MRK_WINDOWS_PARENT_SID").map_err(|_| Error::State)?)?;
        let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
        let (acl, acl_size) = append_acl(&parent, &account)?;
        deadline(Some(end))?;
        Ok(Self { path, identity, parent, account, acl, acl_size, end, order: JournalOrder::default(),
            latch: Latch::default(), startup: AtomicU64::new(0), bytes: AtomicUsize::new(0) })
    }
    pub fn refuse(&self, reason: Refusal) { self.latch.refuse(reason); }
    pub fn observe(&self, snapshot: Snapshot) { self.latch.observe(snapshot); }
    pub fn unavailable(&self) { self.order.unavailable(); }
    fn startup_word(&self) -> Option<u64> { match self.startup.load(Ordering::SeqCst) { 0 => None, word => Some(word) } }
    pub fn admitted(&self) { self.emit(Event::MainAdmitted, self.latch.snapshot(), self.startup_word(), &|| true); }
    pub fn progress(&self, permitted: &dyn Fn() -> bool) {
        let snapshot = self.latch.snapshot();
        self.emit(Event::Step(snapshot.step), snapshot, self.startup_word(), permitted);
        if self.latch.first().is_some() { self.emit(Event::ObserverRefusal, snapshot, self.startup_word(), permitted); }
    }
    pub fn builder_returned(&self, permitted: &dyn Fn() -> bool) {
        self.emit(Event::BuilderReturned, self.latch.snapshot(), self.startup_word(), permitted); self.progress(permitted);
    }
    pub fn startup(&self, raw: u64, permitted: &dyn Fn() -> bool) {
        let Some(word) = crate::ui_startup_data::Word::decode(raw) else { self.order.unavailable(); return; };
        // Caller already performed original adoption/invalidation. Do not read
        // the HWND, invent a startup sample, or call a production drive method.
        self.startup.store(raw, Ordering::SeqCst);
        self.emit(if word.first_refusal { Event::StartupRefusal } else { Event::Startup(word.event) },
            self.latch.snapshot(), Some(raw), permitted);
    }
    fn emit(&self, event: Event, snapshot: Snapshot, startup: Option<u64>, permitted: &dyn Fn() -> bool) {
        let Some(permit) = self.order.begin(event) else { return; };
        let mut raw = Frame::default();
        if permit.record(&mut raw, snapshot, startup, self.latch.first()).is_err()
            || self.append_original(raw.bytes(), permitted).is_err() { self.order.disable(); }
        // Permit drops only an atomic gate. No mutex spans any native operation.
    }
    fn append_original(&self, raw: &[u8], permitted: &dyn Fn() -> bool) -> Result<()> {
        use data::{AppendPhase as P, AppendReturn as R};
        let previous = self.bytes.load(Ordering::SeqCst);
        let next = data::next_bytes(previous, raw.len()).ok_or(Error::Bounds)?;
        let mut file = JournalFile::new(&self.path, self.end)?;
        let observed = data::append_once(|phase| {
            let returned = (|| -> Result<()> { match phase {
                P::Inspect => {
                    file.open(false, null(), permitted)?; file.named(&self.path, permitted)?;
                    let before = file.stamp(permitted)?; need(self.identity.matches(&before) && before.size as usize == previous)?;
                    file.descriptor(&self.acl.0[..self.acl_size], &self.parent, &self.account, permitted)?;
                    file.streams(permitted)
                },
                P::Write => file.append(raw, permitted),
                P::InspectWritten => {
                    let after = file.stamp(permitted)?;
                    need(self.identity.matches(&after) && after.size as usize == next)?;
                    file.streams(permitted)
                },
                P::Close => file.close(), // Late original close is permitted, never retried.
            } })();
            match returned { Ok(()) => R::Complete, Err(Error::Unknown) => R::Unresolved, Err(_) => R::Refused }
        });
        if observed == R::Unresolved {
            loop { std::thread::park(); std::hint::black_box((&mut file, self, permitted)); }
        }
        need(observed == R::Complete)?; file.check(permitted)?; self.bytes.store(next, Ordering::SeqCst); Ok(())
    }
}
