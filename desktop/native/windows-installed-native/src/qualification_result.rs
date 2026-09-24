//! Qualification-only DATA result seam and the single retained file writer.
//! Never compiled by a normal production/native unit. Account lifecycle and
//! process creation remain exclusively in the cfg(test) ordinary owner.
//! Unknown retains the actual owning stack, original buffers and security inputs.
use super::*;
use std::path::{Path, PathBuf};
use std::time::Instant;
use windows_sys::Win32::Security::Cryptography as BC;

pub(super) const FLAGS: [&str; 4] = ["--exact", "--ignored", "--nocapture", "--test-threads=1"];
pub(super) const LIMIT: usize = 4096;
pub(super) const OWNER_LIMIT: usize = 65536;
pub(super) const APP_ARTIFACT_LIMIT: usize = 512 << 20;
const ORDINARY_ARTIFACT_LIMIT: usize = 128 << 20;
pub(super) const FULLWALK_CHILD: &str = "installed_runtime_windows::tests::native_protected_version_walk_and_original_settlement";
pub(super) const FULLWALK_OWNER: &str = "ordinary_owner::hosted_protected_version_fullwalk_contract";
pub(super) const FULLWALK_REQUEST: &str = "fullwalk-request.txt";
pub(super) const FULLWALK_OUTPUT: &str = "fullwalk-output";
pub(super) const FULLWALK_RESULT: &str = "fullwalk-result.private.json";
pub(super) const PASSIVE_CHILD: &str = "supervisor::windows_passive_tests::native_installed_passive_original_owner_contract";
pub(super) const PASSIVE_OWNER: &str = "ordinary_owner::hosted_installed_passive_original_handle_contract";
pub(super) const PASSIVE_REQUEST: &str = "passive-request.txt";
pub(super) const PASSIVE_OUTPUT: &str = "passive-output";
pub(super) const PASSIVE_RESULT: &str = "passive-result.private.json";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ResultRole { Fullwalk, Passive }
impl ResultRole {
    fn child(self) -> &'static str { match self { Self::Fullwalk => FULLWALK_CHILD, Self::Passive => PASSIVE_CHILD } }
    fn owner(self) -> &'static str { match self { Self::Fullwalk => FULLWALK_OWNER, Self::Passive => PASSIVE_OWNER } }
    fn output(self) -> &'static str { match self { Self::Fullwalk => FULLWALK_OUTPUT, Self::Passive => PASSIVE_OUTPUT } }
    fn result(self) -> &'static str { match self { Self::Fullwalk => FULLWALK_RESULT, Self::Passive => PASSIVE_RESULT } }
    fn request_env(self) -> &'static str { match self { Self::Fullwalk => "MRK_WINDOWS_FULLWALK_REQUEST", Self::Passive => "MRK_WINDOWS_PASSIVE_REQUEST" } }
    fn output_env(self) -> &'static str { match self { Self::Fullwalk => "MRK_WINDOWS_FULLWALK_OUTPUT", Self::Passive => "MRK_WINDOWS_PASSIVE_OUTPUT" } }
    fn identity_env(self) -> &'static str { match self { Self::Fullwalk => "MRK_WINDOWS_FULLWALK_ARTIFACT_IDENTITY", Self::Passive => "MRK_WINDOWS_PASSIVE_ARTIFACT_IDENTITY" } }
    fn command(self, path: &str, owner: bool) -> String {
        format!("\"{path}\" {} {}", if owner { self.owner() } else { self.child() }, FLAGS.join(" "))
    }
}

pub(super) fn need(value: bool) -> Result<()> { if value { Ok(()) } else { Err(Error::Unsafe) } }
// Only closed labels, original statuses and u16 ACL control facts may leave.
// This stack-owned snapshot is independent of FileBody.error, which close reuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputRole {
    Ancestor, Request, Binding, Command, Directory, Artifact, Output,
    AclRoot, AclTarget, AclTriple, AclDebug, AclDeps, AclArtifact, AclOutput, Parent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputCheck {
    AncestorCount, FileCount, PathText, PathUnits, OpenState, OpenReturned,
    InfoState, InfoClass, BasicInfoReturned, StandardInfoReturned, TagInfoReturned, IdInfoReturned,
    StampDirectory, StampDeletePending, StampSize, StampAllocation, StampLinks,
    StampAttributes, StampReparse, StampIdentity,
    NameText, NameState, NameReturned, NameCount, NameUtf16, NameExact,
    ReadFileKind, ReadSize, ReadLimit, ReadReturned, ReadCount, ReadStable,
    RequestEnvelope, RequestUtf8, RequestLines, RequestHeader, RequestKey, RequestValue,
    RequestValues, RequestArtifactPath, RequestBytes, RequestBytesRange, RequestIdentity,
    BindingSourceAvailable, BindingSource, BindingTree, BindingRun, BindingRuntimeRun,
    BindingRuntimeTree, BindingImage, CommandUnits, CommandDigest, HashLimit, HashReturned,
    ArtifactIdentity, ArtifactBytes, ArtifactDigest, ArtifactStable,
    OutputCreate, DescriptorState, DescriptorReturned, DescriptorLength,
    AclLayout, AclOwner, AclGroup, AclAccount, AclMask, AclMutation, AclCapacity,
    AclInitialize, AclDacl, AclControlInput, AclSetState, AclSetReturned, AclStamp, AclControl,
    AclOwnerEqual, AclGroupEqual, AclRevision, AclAces, AclChanged, AclDeadline,
    AclTransitions, ParentPrimary, ParentUser, ParentIdentity, ParentSettlement,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputStatus { Win32(u32), NtStatus(i32) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InputFault {
    role: InputRole, slot: Option<u8>, check: InputCheck, status: Option<InputStatus>,
    control: Option<(u16, u16)>,
}
#[derive(Clone, Copy, Default)]
pub(super) struct InputTrace {
    role: Option<InputRole>, slot: Option<u8>, pub first: Option<InputFault>,
}
impl InputTrace {
    pub fn at(&mut self, role: InputRole, slot: Option<u8>) {
        self.role = Some(role); self.slot = slot.filter(|value| *value < 40);
    }
    pub fn record(&mut self, check: InputCheck, status: Option<InputStatus>) {
        if self.first.is_none() {
            if let Some(role) = self.role { self.first = Some(InputFault { role, slot: self.slot, check, status, control: None }); }
        }
    }
    pub(super) fn observed<T>(&mut self, result: Result<T>, check: InputCheck) -> Result<T> {
        if result.is_err() { self.record(check, None); }
        result
    }
    pub fn need(&mut self, value: bool, check: InputCheck) -> Result<()> { self.observed(need(value), check) }
    pub fn control(&mut self, expected: u16, observed: u16) -> Result<()> {
        let unfaulted = self.first.is_none();
        let result = self.need(expected == observed, InputCheck::AclControl);
        if unfaulted {
            if let Some(first) = self.first.as_mut() { first.control = Some((expected, observed)); }
        }
        result
    }
}

pub(super) fn hex(raw: &[u8]) -> String { raw.iter().map(|b| format!("{b:02x}")).collect() }
pub(super) fn is_hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn decimal(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())
}
pub(super) fn unhex(value: &str) -> Result<Vec<u8>> {
    need(value.len() <= 136 && value.len() % 2 == 0 && is_hex(value, value.len()))?;
    value.as_bytes().chunks_exact(2).map(|pair| {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        Ok(digit(pair[0]) * 16 + digit(pair[1]))
    }).collect()
}
pub(super) fn digest(raw: &[u8]) -> Result<String> {
    digest_traced(raw, &mut InputTrace::default())
}
pub(super) fn digest_traced(raw: &[u8], trace: &mut InputTrace) -> Result<String> {
    digest_bounded(raw, ORDINARY_ARTIFACT_LIMIT, trace)
}
pub(super) fn digest_app_traced(raw: &[u8], trace: &mut InputTrace) -> Result<String> {
    digest_bounded(raw, APP_ARTIFACT_LIMIT, trace)
}
fn digest_bounded(raw: &[u8], ceiling: usize, trace: &mut InputTrace) -> Result<String> {
    trace.need(matches!(ceiling, ORDINARY_ARTIFACT_LIMIT | APP_ARTIFACT_LIMIT)
        && raw.len() <= ceiling, InputCheck::HashLimit)?;
    let mut output = [0u8; 32];
    // Documented CNG pseudo-handle: borrowed, never closed. No provider/import,
    // key, random fallback, package dependency or hand-written hash algorithm.
    let status = unsafe { BC::BCryptHash(BC::BCRYPT_SHA256_ALG_HANDLE, null(), 0,
        raw.as_ptr(), raw.len() as u32, output.as_mut_ptr(), output.len() as u32) };
    if status != 0 { trace.record(InputCheck::HashReturned, Some(InputStatus::NtStatus(status))); }
    need(status == 0)?;
    Ok(hex(&output))
}

pub(super) fn fixed_path(value: &str) -> Result<PathBuf> {
    need(value.len() <= 1024 && value.is_ascii() && !value.bytes().any(|b| b < 32 || matches!(b, b'"' | b'%' | b'=')))?;
    let path = PathBuf::from(value);
    need(path.is_absolute() && value.as_bytes().get(1) == Some(&b':')
        && value.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && value.as_bytes().get(2) == Some(&b'\\')
        && !value.contains('/') && !value.starts_with("\\\\")
        && value.split('\\').skip(1).all(|part| decode::component(part)))?;
    Ok(path)
}
pub(super) fn fixed_directories(root: &Path) -> [(&'static str, PathBuf); 4] {
    let target = root.join("target");
    let triple = target.join("x86_64-pc-windows-msvc");
    let debug = triple.join("debug");
    let deps = debug.join("deps");
    [("target", target), ("target/x86_64-pc-windows-msvc", triple),
        ("target/x86_64-pc-windows-msvc/debug", debug),
        ("target/x86_64-pc-windows-msvc/debug/deps", deps)]
}

pub(super) fn complete_write(ok: bool, actual: u32, expected: usize, closed: bool) -> bool {
    complete_write_bounded(ok,actual,expected,closed,OWNER_LIMIT)
}
#[cfg(test)]
pub(super) fn complete_fixture_write(ok:bool,actual:u32,expected:usize,closed:bool) -> bool {
    complete_write_bounded(ok,actual,expected,closed,ORDINARY_ARTIFACT_LIMIT)
}
fn complete_write_bounded(ok:bool,actual:u32,expected:usize,closed:bool,limit:usize) -> bool {
    ok && expected>0 && expected<=limit && limit<=ORDINARY_ARTIFACT_LIMIT && actual as usize==expected && closed
}

pub(super) fn builtin(rid: u32) -> Vec<u8> {
    [vec![1, 2, 0, 0, 0, 0, 0, 5], 32u32.to_le_bytes().to_vec(), rid.to_le_bytes().to_vec()].concat()
}
pub(super) fn system_sid() -> Vec<u8> { [vec![1, 1, 0, 0, 0, 0, 0, 5], 18u32.to_le_bytes().to_vec()].concat() }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    pub volume: u64, pub id: [u8; 16], pub creation: i64, pub write: i64, pub change: i64,
    pub size: i64, pub allocation: i64, pub links: u32, pub attributes: u32,
}
impl Stamp {
    pub fn wire(&self) -> String {
        format!("{}:{}:{}:{}:{}:{}", self.volume, hex(&self.id), self.creation,
            self.write, self.change, self.attributes)
    }
    pub(super) fn json(&self) -> String {
        format!("{{\"volume\":{},\"fileId\":\"{}\",\"creation\":{},\"write\":{},\"change\":{},\"size\":{},\"allocation\":{},\"links\":{},\"attributes\":{}}}",
            self.volume, hex(&self.id), self.creation, self.write, self.change,
            self.size, self.allocation, self.links, self.attributes)
    }
}
pub(super) fn acl_stamp(before: &Stamp, after: &Stamp) -> bool {
    let mut admitted = before.clone(); admitted.change = after.change;
    admitted == *after && after.change >= before.change
}

// An absolute reporting boundary supplied by the original caller, never a new
// clock. Expiry is absorbing; it refuses effects, not original close settlement.
pub(super) fn reporting_effect(now: Instant, end: Instant, latched: &mut bool) -> Result<()> {
    *latched |= now >= end;
    need(!*latched)
}
fn deadline(end: Option<Instant>) -> Result<()> {
    match end { Some(end) => need(Instant::now() < end), None => Ok(()) }
}

pub(super) struct FileBody {
    path: Vec<u16>, pub(super) handle: F::HANDLE, pub(super) state: SlotState, pub(super) active: bool,
    pub(super) error: u32, count: u32, raw: Vec<u8>, security: Box<Aligned>,
    end: Option<Instant>, deadline_latched: bool,
    basic: FS::FILE_BASIC_INFO, standard: FS::FILE_STANDARD_INFO,
    tag: FS::FILE_ATTRIBUTE_TAG_INFO, id: FS::FILE_ID_INFO,
    final_name: Vec<u16>, _pin: PhantomPinned,
}
impl FileBody {
    fn timely(&mut self) -> Result<()> {
        match self.end {
            Some(end) => reporting_effect(Instant::now(), end, &mut self.deadline_latched),
            None => Ok(()), // Ordinary owner semantics and its existing clock are unchanged.
        }
    }
}
pub(super) struct OriginalFile { body: Held<FileBody>, pub(super) directory: bool }
impl OriginalFile {
    pub(super) fn is_closed(&self) -> bool { self.body.state == SlotState::Closed && !self.body.active }
    fn new_until(path: &Path, directory: bool, end: Instant) -> Result<Self> {
        let mut file = Self::new(path, directory)?;
        file.body().end = Some(end);
        Ok(file)
    }
    #[cfg(test)]
    pub(super) fn fixture_new(path: &Path, directory: bool, end: Instant) -> Result<Self> {
        Self::new_until(path, directory, end)
    }
    pub(super) fn new(path: &Path, directory: bool) -> Result<Self> {
        Self::new_traced(path, directory, &mut InputTrace::default())
    }
    pub(super) fn new_traced(path: &Path, directory: bool, trace: &mut InputTrace) -> Result<Self> {
        let value = trace.observed(path.to_str().ok_or(Error::Unsafe), InputCheck::PathText)?;
        trace.need(value.encode_utf16().count() <= 1024, InputCheck::PathUnits)?;
        Ok(Self { body: ManuallyDrop::new(Box::pin(FileBody {
            path: wide(value), handle: null_mut(), state: SlotState::Reserved, active: false,
            error: 0, count: 0, raw: Vec::new(), security: Box::new(Aligned([0; BUFFER])),
            end: None, deadline_latched: false,
            basic: FS::FILE_BASIC_INFO::default(), standard: FS::FILE_STANDARD_INFO::default(),
            tag: FS::FILE_ATTRIBUTE_TAG_INFO::default(), id: FS::FILE_ID_INFO::default(),
            final_name: vec![0; 32768], _pin: PhantomPinned,
        })), directory })
    }
    pub(super) fn body(&mut self) -> &mut FileBody {
        // No movement of the pinned body; all native pointers refer to this
        // original's retained complete buffers, never temporary output storage.
        unsafe { self.body.as_mut().get_unchecked_mut() }
    }
    pub(super) fn open(&mut self, access: u32, create: bool, security: *const S::SECURITY_ATTRIBUTES) -> Result<()> {
        self.open_traced(access, create, security, &mut InputTrace::default())
    }
    pub(super) fn open_traced(&mut self, access: u32, create: bool, security: *const S::SECURITY_ATTRIBUTES, trace: &mut InputTrace) -> Result<()> {
        let directory = self.directory; let b = self.body();
        if b.state != SlotState::Reserved { return trace.observed(Err(Error::State), InputCheck::OpenState); }
        b.timely()?;
        b.state = SlotState::Acquiring; b.active = true;
        b.handle = unsafe { FS::CreateFileW(b.path.as_ptr(), access,
            FS::FILE_SHARE_READ | if directory { FS::FILE_SHARE_WRITE } else { 0 },
            security, if create { FS::CREATE_NEW } else { FS::OPEN_EXISTING },
            FS::FILE_FLAG_OPEN_REPARSE_POINT | if directory { FS::FILE_FLAG_BACKUP_SEMANTICS } else { 0 }, null_mut()) };
        b.error = if valid_handle(b.handle) { 0 } else { unsafe { F::GetLastError() } };
        if !valid_handle(b.handle) { trace.record(InputCheck::OpenReturned, Some(InputStatus::Win32(b.error))); }
        if valid_handle(b.handle) { b.active = false; b.state = SlotState::Owned; b.timely() }
        else if b.error != 0 && b.error != F::ERROR_IO_PENDING && b.handle == F::INVALID_HANDLE_VALUE {
            b.active = false; b.state = SlotState::NoHandle; b.timely()?; Err(Error::Unavailable)
        } else { b.state = SlotState::Unknown; Err(Error::Unknown) }
    }
    fn info(&mut self, which: u8, trace: &mut InputTrace) -> Result<()> {
        let b = self.body();
        if b.state != SlotState::Owned || b.active { return trace.observed(Err(Error::State), InputCheck::InfoState); }
        let (class, output, size, check) = match which {
            0 => (FS::FileBasicInfo, (&mut b.basic as *mut FS::FILE_BASIC_INFO).cast(), size_of::<FS::FILE_BASIC_INFO>(), InputCheck::BasicInfoReturned),
            1 => (FS::FileStandardInfo, (&mut b.standard as *mut FS::FILE_STANDARD_INFO).cast(), size_of::<FS::FILE_STANDARD_INFO>(), InputCheck::StandardInfoReturned),
            2 => (FS::FileAttributeTagInfo, (&mut b.tag as *mut FS::FILE_ATTRIBUTE_TAG_INFO).cast(), size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>(), InputCheck::TagInfoReturned),
            3 => (FS::FileIdInfo, (&mut b.id as *mut FS::FILE_ID_INFO).cast(), size_of::<FS::FILE_ID_INFO>(), InputCheck::IdInfoReturned),
            _ => return trace.observed(Err(Error::State), InputCheck::InfoClass),
        };
        b.timely()?;
        b.active = true;
        let ok = unsafe { FS::GetFileInformationByHandleEx(b.handle, class, output, size as u32) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        if ok == 0 { trace.record(check, Some(InputStatus::Win32(b.error))); }
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        b.timely()?;
        need(ok != 0)
    }
    pub(super) fn stamp(&mut self) -> Result<Stamp> {
        self.stamp_traced(&mut InputTrace::default())
    }
    pub(super) fn stamp_traced(&mut self, trace: &mut InputTrace) -> Result<Stamp> {
        for which in 0..4 { self.info(which, trace)?; }
        let directory = self.directory; let b = self.body();
        trace.need(b.standard.Directory == directory, InputCheck::StampDirectory)?;
        trace.need(!b.standard.DeletePending, InputCheck::StampDeletePending)?;
        trace.need(b.standard.EndOfFile >= 0, InputCheck::StampSize)?;
        trace.need(b.standard.AllocationSize >= 0, InputCheck::StampAllocation)?;
        trace.need(b.standard.NumberOfLinks == 1, InputCheck::StampLinks)?;
        trace.need(b.tag.FileAttributes == b.basic.FileAttributes, InputCheck::StampAttributes)?;
        trace.need(b.basic.FileAttributes & FS::FILE_ATTRIBUTE_REPARSE_POINT == 0, InputCheck::StampReparse)?;
        trace.need(b.id.FileId.Identifier != [0; 16], InputCheck::StampIdentity)?;
        Ok(Stamp { volume: b.id.VolumeSerialNumber, id: b.id.FileId.Identifier,
            creation: b.basic.CreationTime, write: b.basic.LastWriteTime, change: b.basic.ChangeTime,
            size: b.standard.EndOfFile, allocation: b.standard.AllocationSize,
            links: b.standard.NumberOfLinks, attributes: b.basic.FileAttributes })
    }
    pub(super) fn named(&mut self, expected: &Path) -> Result<()> {
        self.named_traced(expected, &mut InputTrace::default())
    }
    pub(super) fn named_traced(&mut self, expected: &Path, trace: &mut InputTrace) -> Result<()> {
        let text = trace.observed(expected.to_str().ok_or(Error::Unsafe), InputCheck::NameText)?;
        let b = self.body();
        if b.state != SlotState::Owned || b.active { return trace.observed(Err(Error::State), InputCheck::NameState); }
        b.timely()?;
        b.active = true;
        b.count = unsafe { FS::GetFinalPathNameByHandleW(b.handle, b.final_name.as_mut_ptr(),
            b.final_name.len() as u32, FS::FILE_NAME_NORMALIZED | FS::VOLUME_NAME_DOS) };
        b.error = if b.count != 0 { 0 } else { unsafe { F::GetLastError() } };
        if b.count == 0 { trace.record(InputCheck::NameReturned, Some(InputStatus::Win32(b.error))); }
        b.active = b.count == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        b.timely()?;
        trace.need(b.count > 0 && (b.count as usize) < b.final_name.len(), InputCheck::NameCount)?;
        let actual = trace.observed(String::from_utf16(&b.final_name[..b.count as usize]).map_err(|_| Error::Unsafe), InputCheck::NameUtf16)?;
        trace.need(actual.strip_prefix("\\\\?\\") == Some(text), InputCheck::NameExact)
    }
    pub(super) fn read(&mut self, limit: usize) -> Result<Vec<u8>> {
        self.read_traced(limit, &mut InputTrace::default())
    }
    pub(super) fn read_traced(&mut self, limit: usize, trace: &mut InputTrace) -> Result<Vec<u8>> {
        self.read_bounded(limit, ORDINARY_ARTIFACT_LIMIT, trace)
    }
    pub(super) fn read_app_traced(&mut self, trace: &mut InputTrace) -> Result<Vec<u8>> {
        // Only the fixed fullwalk app route uses its already-admitted512MiB
        // artifact ceiling. Ordinary calls retain their original128MiB ceiling.
        self.read_bounded(APP_ARTIFACT_LIMIT, APP_ARTIFACT_LIMIT, trace)
    }
    fn read_bounded(&mut self, limit: usize, ceiling: usize, trace: &mut InputTrace) -> Result<Vec<u8>> {
        let before = self.stamp_traced(trace)?;
        trace.need(!self.directory, InputCheck::ReadFileKind)?;
        trace.need(before.size >= 0 && before.size as usize <= limit, InputCheck::ReadSize)?;
        trace.need(matches!(ceiling, ORDINARY_ARTIFACT_LIMIT | APP_ARTIFACT_LIMIT) && limit <= ceiling, InputCheck::ReadLimit)?;
        let b = self.body();
        b.raw = vec![0; before.size as usize + 1]; b.count = 0;
        b.timely()?;
        b.active = true;
        let ok = unsafe { FS::ReadFile(b.handle, b.raw.as_mut_ptr(), b.raw.len() as u32, &mut b.count, null_mut()) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        if ok == 0 { trace.record(InputCheck::ReadReturned, Some(InputStatus::Win32(b.error))); }
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        b.timely()?;
        trace.need(ok != 0 && b.count as i64 == before.size, InputCheck::ReadCount)?;
        let value = b.raw[..b.count as usize].to_vec();
        let after = self.stamp_traced(trace)?;
        trace.need(after == before, InputCheck::ReadStable)?;
        Ok(value)
    }
    pub(super) fn descriptor(&mut self) -> Result<Vec<u8>> {
        self.descriptor_traced(&mut InputTrace::default())
    }
    pub(super) fn descriptor_traced(&mut self, trace: &mut InputTrace) -> Result<Vec<u8>> {
        let b = self.body();
        if b.state != SlotState::Owned || b.active { return trace.observed(Err(Error::State), InputCheck::DescriptorState); }
        b.timely()?;
        b.count = 0; b.active = true;
        let ok = unsafe { S::GetKernelObjectSecurity(b.handle,
            S::OWNER_SECURITY_INFORMATION | S::GROUP_SECURITY_INFORMATION | S::DACL_SECURITY_INFORMATION,
            b.security.0.as_mut_ptr().cast(), BUFFER as u32, &mut b.count) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        if ok == 0 { trace.record(InputCheck::DescriptorReturned, Some(InputStatus::Win32(b.error))); }
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        b.timely()?;
        need(ok != 0)?;
        trace.need(b.count as usize <= BUFFER && b.count >= 20, InputCheck::DescriptorLength)?;
        Ok(b.security.0[..b.count as usize].to_vec())
    }
    fn write(&mut self, value: &[u8], limit: usize) -> Result<()> {
        need(limit <= OWNER_LIMIT)?;
        self.write_bounded(value, limit)
    }
    // Only the closed cfg(test) fixture publisher can request payload writes.
    // The app-safe/result entry above retains its original64KiB bound.
    #[cfg(test)]
    pub(super) fn write_fixture_payload(&mut self, value: &[u8]) -> Result<()> {
        self.write_bounded(value, ORDINARY_ARTIFACT_LIMIT)
    }
    fn write_bounded(&mut self, value: &[u8], limit: usize) -> Result<()> {
        need(!value.is_empty() && value.len() <= limit && limit <= ORDINARY_ARTIFACT_LIMIT)?;
        let b = self.body();
        if b.state != SlotState::Owned || b.active || !b.raw.is_empty() { return Err(Error::State); }
        b.raw = value.to_vec(); b.count = 0;
        b.timely()?;
        b.active = true;
        let ok = unsafe { FS::WriteFile(b.handle, b.raw.as_ptr(), b.raw.len() as u32, &mut b.count, null_mut()) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        b.timely()?;
        // Exactly one attempt. An ordinary short write is still failure; the
        // caller must then explicitly close the same original, not retry it.
        need(complete_write_bounded(ok != 0, b.count, value.len(), true, limit))
    }
    pub(super) fn close(&mut self) -> Result<()> {
        let b = self.body();
        match b.state {
            SlotState::Reserved | SlotState::NoHandle | SlotState::Closed => return Ok(()),
            SlotState::Owned if !b.active => (),
            _ => return Err(Error::Unknown),
        }
        b.state = SlotState::Closing;
        let ok = unsafe { F::CloseHandle(b.handle) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.state = if ok != 0 { SlotState::Closed } else { SlotState::Unknown };
        if ok != 0 { Ok(()) } else { Err(Error::Unknown) }
    }
}
impl Drop for OriginalFile {
    fn drop(&mut self) {
        let b = self.body();
        if !b.active && matches!(b.state, SlotState::Reserved | SlotState::NoHandle | SlotState::Closed) {
            unsafe { ManuallyDrop::drop(&mut self.body); }
        }
        // Never CloseHandle in Drop. Uncertain buffers/originals are retained.
    }
}
pub(super) fn close_files(files: &mut [OriginalFile]) -> bool {
    // A later original can be a child of any earlier directory. On the first
    // uncertain close stop, retaining every remaining ancestor without retry.
    for file in files.iter_mut().rev() {
        if file.close().is_err() { return false; }
    }
    true
}
pub(super) fn owned_file(files: &mut Vec<OriginalFile>, path: &Path, directory: bool, access: u32) -> Result<usize> {
    owned_file_traced(files, path, directory, access, &mut InputTrace::default())
}
pub(super) fn owned_file_traced(files: &mut Vec<OriginalFile>, path: &Path, directory: bool, access: u32, trace: &mut InputTrace) -> Result<usize> {
    trace.need(files.len() < 40, InputCheck::FileCount)?;
    let index = files.len(); files.push(OriginalFile::new_traced(path, directory, trace)?);
    files[index].open_traced(access, false, null(), trace)?;
    files[index].named_traced(path, trace)?; files[index].stamp_traced(trace)?;
    Ok(index)
}

pub(super) fn args_are(target: &str, image: &Path) -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    need(args.len() == 6 && Path::new(&args[0]) == image && args[1] == target
        && args[2..].iter().map(String::as_str).eq(FLAGS))
}

pub(super) fn write_one(path: &Path, raw: &[u8], limit: usize, security: *const S::SECURITY_ATTRIBUTES) -> Result<()> {
    write_one_until(path, raw, limit, security, None)
}
#[cfg(test)]
pub(super) fn write_fixture_record(path: &Path, raw: &[u8], limit: usize, end: Instant) -> Result<()> {
    need(limit <= OWNER_LIMIT)?;
    write_one_until(path, raw, limit, null(), Some(end))
}
fn write_one_until(path: &Path, raw: &[u8], limit: usize, security: *const S::SECURITY_ATTRIBUTES, end: Option<Instant>) -> Result<()> {
    let mut file = OriginalFile::new(path, false)?;
    file.body().end = end;
    let observation = (|| -> Result<()> {
        file.open(FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES, true, security)?;
        file.named(path)?; file.stamp()?;
        file.write(raw, limit)
    })();
    if matches!(observation, Err(Error::Unknown)) {
        diagnostic_data("result-original-operation", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut file, security)); }
    }
    let closed = file.close();
    if closed.is_err() {
        diagnostic_data("result-original-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut file, security)); }
    }
    let timely = file.body().timely(); // close is permitted late; reporting success is not
    observation?;
    timely
}

pub(super) fn child_security(parent: &[u8], account: &[u8]) -> Result<(Box<Aligned>, Box<S::SECURITY_DESCRIPTOR>)> {
    child_security_until(parent, account, None)
}
fn child_security_until(parent: &[u8], account: &[u8], end: Option<Instant>) -> Result<(Box<Aligned>, Box<S::SECURITY_DESCRIPTOR>)> {
    // Only the single new result file. No inherited grant or standard Users ACE.
    let mut acl = Box::new(Aligned([0; BUFFER]));
    let principals = [(system_sid(), FS::FILE_ALL_ACCESS), (builtin(544), FS::FILE_ALL_ACCESS),
        (parent.to_vec(), FS::FILE_ALL_ACCESS), (account.to_vec(), FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES)];
    let size = 8 + principals.iter().map(|(sid, _)| 8 + sid.len()).sum::<usize>();
    need(size < BUFFER && size < u16::MAX as usize)?;
    acl.0[0] = 2; acl.0[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    acl.0[4..6].copy_from_slice(&(principals.len() as u16).to_le_bytes());
    let mut at = 8;
    for (sid, rights) in principals {
        security::sid_at(&sid, 0, sid.len())?;
        let length = 8 + sid.len();
        acl.0[at + 2..at + 4].copy_from_slice(&(length as u16).to_le_bytes());
        acl.0[at + 4..at + 8].copy_from_slice(&rights.to_le_bytes());
        acl.0[at + 8..at + length].copy_from_slice(&sid); at += length;
    }
    let mut descriptor = Box::new(S::SECURITY_DESCRIPTOR::default());
    deadline(end)?;
    let initialized = unsafe { S::InitializeSecurityDescriptor((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), 1) };
    deadline(end)?; need(initialized != 0)?;
    deadline(end)?;
    let dacl = unsafe { S::SetSecurityDescriptorDacl((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
        1, acl.0.as_ptr().cast(), 0) };
    deadline(end)?; need(dacl != 0)?;
    deadline(end)?;
    let protected = unsafe { S::SetSecurityDescriptorControl((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
        S::SE_DACL_PROTECTED, S::SE_DACL_PROTECTED) };
    deadline(end)?; need(protected != 0)?;
    Ok((acl, descriptor))
}

pub(super) type LaunchDiagnostic = (bool, u32, Option<u32>, [u32; 8]);
// DATA-only formatter, shared with the existing inert regression. The longest
// closed stage/role/check, optional u16 control words, null slot, max u32s
// and min NTSTATUS stay below the unchanged768-byte buffer (inert regression).
pub(super) fn write_refusal(output: &mut impl std::io::Write, stage: &'static str,
    launch: Option<LaunchDiagnostic>, unknown: bool, fault: Option<InputFault>) -> std::io::Result<()> {
    let (returned, error, exit) = launch.map_or((false, 0, None), |value| (value.0, value.1, value.2));
    write!(output, "MRK_WINDOWS_ORDINARY_OWNER_REFUSED={{\"stage\":\"{stage}\",\"createReturned\":{returned},\"createError\":{error},\"exitCode\":")?;
    match exit { Some(code) => write!(output, "{code}")?, None => write!(output, "null")? }
    if let Some((_, _, _, value)) = launch {
        write!(output, ",\"wait\":{},\"waitError\":{},\"settleWait\":{},\"settleError\":{},\"exitError\":{},\"terminateError\":{},\"processCloseError\":{},\"threadCloseError\":{}",
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7])?;
    }
    if let Some(value) = fault {
        write!(output, ",\"firstInputFault\":{{\"role\":\"{:?}\",\"slot\":", value.role)?;
        match value.slot { Some(slot) => write!(output, "{slot}")?, None => write!(output, "null")? }
        write!(output, ",\"check\":\"{:?}\",\"status\":", value.check)?;
        match value.status {
            Some(InputStatus::Win32(code)) => write!(output, "{{\"domain\":\"win32\",\"code\":{code}}}")?,
            Some(InputStatus::NtStatus(code)) => write!(output, "{{\"domain\":\"ntstatus\",\"code\":{code}}}")?,
            None => write!(output, "null")?,
        }
        if let Some((expected, observed)) = value.control {
            write!(output, ",\"control\":{{\"expected\":{expected},\"observed\":{observed}}}")?;
        }
        write!(output, "}}")?;
    }
    writeln!(output, ",\"unknown\":{unknown},\"cleanupNotRetried\":true}}")
}

pub(super) fn diagnostic_data(stage: &'static str, facts: Option<LaunchDiagnostic>, unknown: bool, fault: Option<InputFault>) {
    use std::io::Write;
    let mut raw = [0u8; 768];
    let mut output = std::io::Cursor::new(raw.as_mut_slice());
    let formatted = write_refusal(&mut output, stage, facts, unknown, fault);
    let size = output.position() as usize;
    // Never publish an ignored formatting error/truncated JSON as a record.
    // This fallback changes no owner result or settlement decision.
    let bytes: &[u8] = if formatted.is_ok() { &raw[..size] } else if unknown {
        b"MRK_WINDOWS_ORDINARY_OWNER_REFUSED={\"stage\":\"diagnostic-format\",\"unknown\":true,\"cleanupNotRetried\":true}\n"
    } else {
        b"MRK_WINDOWS_ORDINARY_OWNER_REFUSED={\"stage\":\"diagnostic-format\",\"unknown\":false,\"cleanupNotRetried\":true}\n"
    };
    let _ = std::io::stdout().lock().write(bytes);
}

// Closed owned observation DATA only. No raw SID, handle, path, arbitrary JSON,
// callback or executable selector can enter the public qualification interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullwalkFacts {
    pub target: String,
    pub manifest_sha256: String,
    pub protocol_sha256: String,
    pub inventory_sha256: String,
    pub core_sha256: String,
    pub account_sid_sha256: String,
    pub files: usize,
    /// Actual aggregate native entry observations, including ancestors and dots.
    pub entries: usize,
    pub payload_bytes: u64,
    pub version_identity: FileIdentity,
    /// Existing fixed order: python/python.exe, engine_bootstrap.py, core.zip.
    pub selected_identities: [FileIdentity; 3],
}
/// Actual original-owner observations only. The app fills these after each
/// real owner/borrow/child/IO/native/management join; this writer grants none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassiveFacts {
    pub version: FullwalkFacts,
    pub completed_methods: usize,
    pub settled_owners: usize,
    pub payload_images: usize,
    pub system_images: usize,
    pub stopped_before_claim: bool,
    pub stopped_owned_child: bool,
}
impl PassiveFacts {
    fn validate(&self) -> Result<()> {
        self.version.validate()?;
        need(self.completed_methods == 5 && self.settled_owners == 9
            && (22..=33).contains(&self.payload_images) && (1..=31).contains(&self.system_images)
            && self.stopped_before_claim && self.stopped_owned_child)
    }
    fn json(&self) -> String {
        format!("{{\"completedMethods\":{},\"settledOriginalOwners\":{},\"payloadImages\":{},\"systemImages\":{},\"stoppedBeforeClaim\":{},\"stoppedOwnedChild\":{},\"productionEnabled\":false}}",
            self.completed_methods, self.settled_owners, self.payload_images, self.system_images,
            self.stopped_before_claim, self.stopped_owned_child)
    }
}
impl FullwalkFacts {
    pub(super) fn validate(&self) -> Result<()> {
        need(self.target == "x86_64-pc-windows-msvc"
            && [&self.manifest_sha256, &self.protocol_sha256, &self.inventory_sha256,
                &self.core_sha256, &self.account_sid_sha256].into_iter().all(|s| is_hex(s, 64))
            && self.files > 0 && self.files < MAX_FILES
            && self.entries > self.files && self.entries <= MAX_ENTRIES
            && self.payload_bytes > 0 && self.payload_bytes <= MAX_TOTAL_BYTES)?;
        fullwalk_identities(self.version_identity, &self.selected_identities)
    }
}
fn fullwalk_identities(version: FileIdentity, selected: &[FileIdentity; 3]) -> Result<()> {
    need(version.volume_serial != 0 && version.file_id != [0; 16])?;
    for (index, identity) in selected.iter().enumerate() {
        need(identity.volume_serial == version.volume_serial && identity.file_id != [0; 16]
            && *identity != version && !selected[..index].contains(identity))?;
    }
    Ok(())
}
fn fullwalk_identity(value: &str) -> Result<FileIdentity> {
    let (volume, id) = value.split_once(':').ok_or(Error::Unsafe)?;
    need(decimal(volume) && is_hex(id, 32) && id != "0".repeat(32))?;
    let volume_serial = volume.parse::<u64>().map_err(|_| Error::Unsafe)?;
    let mut file_id = [0u8; 16]; file_id.copy_from_slice(&unhex(id)?);
    Ok(FileIdentity { volume_serial, file_id })
}
fn identity_json(identity: FileIdentity) -> String {
    format!("{{\"volume\":{},\"fileId\":\"{}\"}}", identity.volume_serial, hex(&identity.file_id))
}
fn artifact_identity(value: &str) -> Result<()> {
    need(value.len() <= 160)?;
    let fields: Vec<_> = value.split(':').collect();
    need(fields.len() == 6 && is_hex(fields[1], 32) && fields[1] != "0".repeat(32)
        && decimal(fields[0]) && fields[0].parse::<u64>().is_ok()
        && fields[2..5].iter().all(|value| decimal(value) && value.parse::<i64>().is_ok())
        && decimal(fields[5]) && fields[5].parse::<u32>().is_ok())
}
fn positive_size(value: &str, ceiling: usize) -> Result<usize> {
    need(decimal(value))?;
    let number = value.parse().map_err(|_| Error::Unsafe)?;
    need(number > 0 && number <= ceiling)?;
    Ok(number)
}

#[derive(Clone)]
pub(super) struct FullwalkArtifact {
    pub path: String, pub bytes: usize, pub sha: String, pub identity: String,
    pub command_sha: String, pub messages_bytes: usize, pub messages_sha: String, pub argv_sha: String,
}
impl FullwalkArtifact {
    pub fn matches(&self, stamp: &Stamp) -> bool { self.matches_identity(stamp, &self.identity) }
    fn matches_identity(&self, stamp: &Stamp, identity: &str) -> bool {
        stamp.wire() == identity && stamp.size == self.bytes as i64 && stamp.links == 1
    }
}
#[derive(Clone)]
pub(super) struct FullwalkRequest {
    pub role: ResultRole,
    pub source: String, pub tree: String, pub run: String,
    pub app: FullwalkArtifact, pub owner: FullwalkArtifact,
    pub manifest_sha: String, pub protocol_sha: String, pub inventory_sha: String, pub core_sha: String,
    pub files: usize, pub payload_bytes: u64,
    pub publication_bytes: usize, pub publication_sha: String,
    pub version: FileIdentity, pub selected: [FileIdentity; 3],
}
impl FullwalkRequest {
    pub fn parse(raw: &[u8]) -> Result<Self> { Self::parse_traced(raw, &mut InputTrace::default()) }
    pub fn parse_traced(raw: &[u8], trace: &mut InputTrace) -> Result<Self> {
        Self::parse_role(raw, trace, ResultRole::Fullwalk)
    }
    pub fn parse_passive(raw: &[u8], trace: &mut InputTrace) -> Result<Self> {
        Self::parse_role(raw, trace, ResultRole::Passive)
    }
    fn parse_role(raw: &[u8], trace: &mut InputTrace, role: ResultRole) -> Result<Self> {
        trace.need(raw.len() <= LIMIT && raw.is_ascii() && raw.ends_with(b"\n")
            && !raw.contains(&b'\r'), InputCheck::RequestEnvelope)?;
        let text = trace.observed(std::str::from_utf8(raw).map_err(|_| Error::Unsafe), InputCheck::RequestUtf8)?;
        let lines: Vec<_> = text.lines().collect();
        trace.need(lines.len() == 35, InputCheck::RequestLines)?;
        trace.need(lines[0] == (match role { ResultRole::Fullwalk => "MRK_WINDOWS_FULLWALK_REQUEST_V1",
            ResultRole::Passive => "MRK_WINDOWS_INSTALLED_PASSIVE_REQUEST_V1" }), InputCheck::RequestHeader)?;
        let mut values = Vec::with_capacity(34);
        for (line, key) in lines[1..].iter().zip([
            "role", "test", "sourceSha", "sourceTree", "runId", "attempt",
            "appArtifact", "appArtifactBytes", "appArtifactSha256", "appArtifactIdentity", "appCommandSha256",
            "appCompileMessagesBytes", "appCompileMessagesSha256", "appCompileArgvSha256",
            "ownerArtifact", "ownerArtifactBytes", "ownerArtifactSha256", "ownerArtifactIdentity", "ownerCommandSha256",
            "ownerCompileMessagesBytes", "ownerCompileMessagesSha256", "ownerCompileArgvSha256",
            "manifestSha256", "protocolSha256", "inventorySha256", "coreSha256", "payloadFiles", "payloadBytes",
            "publicationReceiptBytes", "publicationReceiptSha256", "versionIdentity",
            "selectedPythonIdentity", "selectedBootstrapIdentity", "selectedCoreIdentity",
        ]) {
            let (name, value) = trace.observed(line.split_once('=').ok_or(Error::Unsafe), InputCheck::RequestKey)?;
            trace.need(name == key, InputCheck::RequestKey)?;
            trace.need(!value.is_empty(), InputCheck::RequestValue)?; values.push(value);
        }
        trace.need(values[0] == (match role { ResultRole::Fullwalk => "protected-version-fullwalk", ResultRole::Passive => "installed-passive" })
            && values[1] == role.child()
            && is_hex(values[2], 40) && values[2] != "0".repeat(40)
            && is_hex(values[3], 40) && values[3] != "0".repeat(40)
            && decimal(values[4]) && values[5] == "1", InputCheck::RequestValues)?;
        let mut artifact = |at: usize, ceiling: usize, prefix: &str| -> Result<FullwalkArtifact> {
            let path = trace.observed(fixed_path(values[at]), InputCheck::RequestArtifactPath)?;
            let name = path.file_name().and_then(|v| v.to_str()).ok_or(Error::Unsafe)?;
            let hash = name.strip_prefix(prefix).and_then(|v| v.strip_suffix(".exe")).ok_or(Error::Unsafe)?;
            trace.need(is_hex(hash, 16), InputCheck::RequestArtifactPath)?;
            let bytes = trace.observed(positive_size(values[at + 1], ceiling), InputCheck::RequestBytesRange)?;
            for index in [at + 2, at + 4, at + 6, at + 7] {
                trace.need(is_hex(values[index], 64), InputCheck::RequestValues)?;
            }
            trace.observed(artifact_identity(values[at + 3]), InputCheck::RequestIdentity)?;
            let messages_bytes = trace.observed(positive_size(values[at + 5], 16 << 20), InputCheck::RequestBytesRange)?;
            Ok(FullwalkArtifact { path: values[at].to_owned(), bytes, sha: values[at + 2].to_owned(),
                identity: values[at + 3].to_owned(), command_sha: values[at + 4].to_owned(),
                messages_bytes, messages_sha: values[at + 6].to_owned(), argv_sha: values[at + 7].to_owned() })
        };
        let app = artifact(6, APP_ARTIFACT_LIMIT, "mobile_release_desktop-")?;
        let owner = artifact(14, ORDINARY_ARTIFACT_LIMIT, "mrk_windows_installed_native-")?;
        trace.need(app.path != owner.path
            && !app.identity.split(':').take(2).eq(owner.identity.split(':').take(2)), InputCheck::RequestArtifactPath)?;
        for index in [22, 23, 24, 25, 29] { trace.need(is_hex(values[index], 64), InputCheck::RequestValues)?; }
        let files = trace.observed(positive_size(values[26], MAX_FILES - 1), InputCheck::RequestBytesRange)?;
        let payload_bytes = trace.observed(positive_size(values[27], MAX_TOTAL_BYTES as usize), InputCheck::RequestBytesRange)? as u64;
        let publication_bytes = trace.observed(positive_size(values[28], OWNER_LIMIT), InputCheck::RequestBytesRange)?;
        let version = trace.observed(fullwalk_identity(values[30]), InputCheck::RequestIdentity)?;
        let selected = [fullwalk_identity(values[31])?, fullwalk_identity(values[32])?, fullwalk_identity(values[33])?];
        trace.observed(fullwalk_identities(version, &selected), InputCheck::RequestIdentity)?;
        Ok(Self { role, source: values[2].to_owned(), tree: values[3].to_owned(), run: values[4].to_owned(), app, owner,
            manifest_sha: values[22].to_owned(), protocol_sha: values[23].to_owned(),
            inventory_sha: values[24].to_owned(), core_sha: values[25].to_owned(), files, payload_bytes,
            publication_bytes, publication_sha: values[29].to_owned(), version, selected })
    }
    pub fn at_root(&self, root: &Path) -> Result<()> {
        let deps = fixed_directories(root)[3].1.clone();
        for artifact in [&self.app, &self.owner] {
            let path = fixed_path(&artifact.path)?;
            let basename = path.file_name().ok_or(Error::Unsafe)?;
            need(deps.join(basename).to_str() == Some(artifact.path.as_str()))?;
        }
        Ok(())
    }
    pub fn compiled_traced(&self, trace: &mut InputTrace) -> Result<()> {
        // This feature-only module cannot depend on cfg(test) hosted_tests.
        // These are compiled/environment DATA checks, not another token query.
        let source = trace.observed(option_env!("GITHUB_SHA").ok_or(Error::State), InputCheck::BindingSourceAvailable)?;
        trace.need(source == self.source, InputCheck::BindingSource)?;
        trace.need(option_env!("MRK_WINDOWS_SOURCE_TREE") == Some(self.tree.as_str()), InputCheck::BindingTree)?;
        trace.need(option_env!("GITHUB_RUN_ID") == Some(self.run.as_str()), InputCheck::BindingRun)?;
        for (name, expected) in [
            ("MRK_DESKTOP_HOSTED_CHECKS", "windows-installed-native-v1"), ("GITHUB_ACTIONS", "true"),
            ("RUNNER_ENVIRONMENT", "github-hosted"), ("RUNNER_OS", "Windows"), ("RUNNER_ARCH", "X64"),
            ("ImageOS", "win25-vs2026"), ("GITHUB_RUN_ATTEMPT", "1"), ("GITHUB_SHA", self.source.as_str()),
        ] {
            trace.need(std::env::var(name).as_deref() == Ok(expected), InputCheck::BindingSource)?;
        }
        trace.need(std::env::var("GITHUB_RUN_ID").as_deref() == Ok(self.run.as_str()), InputCheck::BindingRuntimeRun)?;
        trace.need(std::env::var("MRK_WINDOWS_SOURCE_TREE").as_deref() == Ok(self.tree.as_str()), InputCheck::BindingRuntimeTree)
    }
    pub fn check_commands(&self, trace: &mut InputTrace) -> Result<()> { self.commands_until(None, trace) }
    fn commands_until(&self, end: Option<Instant>, trace: &mut InputTrace) -> Result<()> {
        for (command, expected) in [
            (self.role.command(&self.app.path, false), &self.app.command_sha),
            (self.role.command(&self.owner.path, true), &self.owner.command_sha),
        ] {
            trace.need(command.encode_utf16().count() <= 1023, InputCheck::CommandUnits)?;
            deadline(end)?;
            let actual = digest_traced(&command.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>(), trace);
            deadline(end)?;
            trace.need(actual? == *expected, InputCheck::CommandDigest)?;
        }
        Ok(())
    }
    pub fn app_after(&self, identity: &str) -> Result<()> {
        artifact_identity(identity)?;
        let before: Vec<_> = self.app.identity.split(':').collect();
        let after: Vec<_> = identity.split(':').collect();
        need([0, 1, 2, 3, 5].into_iter().all(|index| before[index] == after[index])
            && after[4].parse::<i64>().map_err(|_| Error::Unsafe)? >= before[4].parse::<i64>().map_err(|_| Error::Unsafe)?)
    }
    pub fn expected(&self, account_sha: &str, entries: usize) -> FullwalkFacts {
        // Expected comparison DATA only. The child writer receives the actual
        // copied VersionObservation; this constructor never writes a receipt.
        FullwalkFacts { target: "x86_64-pc-windows-msvc".to_owned(), manifest_sha256: self.manifest_sha.clone(),
            protocol_sha256: self.protocol_sha.clone(), inventory_sha256: self.inventory_sha.clone(),
            core_sha256: self.core_sha.clone(), account_sid_sha256: account_sha.to_owned(), files: self.files,
            entries, payload_bytes: self.payload_bytes, version_identity: self.version, selected_identities: self.selected }
    }
    pub fn result(&self, request_sha: &str, actual: &FullwalkFacts) -> Result<String> {
        need(self.role == ResultRole::Fullwalk)?;
        self.result_kind(request_sha, actual, None)
    }
    pub fn passive_result(&self, request_sha: &str, actual: &PassiveFacts) -> Result<String> {
        need(self.role == ResultRole::Passive)?; actual.validate()?;
        self.result_kind(request_sha, &actual.version, Some(actual))
    }
    fn result_kind(&self, request_sha: &str, actual: &FullwalkFacts, passive: Option<&PassiveFacts>) -> Result<String> {
        actual.validate()?;
        need(is_hex(request_sha, 64) && *actual == self.expected(&actual.account_sid_sha256, actual.entries))?;
        let observed = format!("{{\"target\":\"{}\",\"manifestSha256\":\"{}\",\"protocolSha256\":\"{}\",\"inventorySha256\":\"{}\",\"coreSha256\":\"{}\",\"files\":{},\"entries\":{},\"payloadBytes\":{},\"versionIdentity\":{},\"selectedIdentities\":[{},{},{}],\"inspectionComplete\":true,\"bookSettled\":true}}",
            actual.target, actual.manifest_sha256, actual.protocol_sha256, actual.inventory_sha256, actual.core_sha256,
            actual.files, actual.entries, actual.payload_bytes, identity_json(actual.version_identity),
            identity_json(actual.selected_identities[0]), identity_json(actual.selected_identities[1]), identity_json(actual.selected_identities[2]));
        let child = self.role.child();
        let extra = passive.map(|facts| format!(",\"passive\":{}", facts.json())).unwrap_or_default();
        let raw = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"requestSha256\":\"{}\",\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"ownerArtifactSha256\":\"{}\",\"accountSidSha256\":\"{}\",\"test\":\"{child}\",\"observation\":{}{extra},\"resultFile\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-child-exit-zero-required\"}}}}\n",
            self.source, self.tree, self.run, request_sha, self.app.bytes, self.app.sha,
            self.app.command_sha, self.owner.sha, actual.account_sid_sha256, observed);
        need(raw.len() <= LIMIT)?;
        Ok(raw)
    }
    pub fn accept_result(&self, raw: &[u8], request_sha: &str, account_sha: &str) -> Result<usize> {
        need(!raw.is_empty() && raw.len() <= LIMIT && raw.is_ascii())?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
        let tail = text.split_once("\"entries\":").ok_or(Error::Unsafe)?.1;
        let count = tail.split_once(',').ok_or(Error::Unsafe)?.0;
        let entries = positive_size(count, MAX_ENTRIES)?;
        // All bytes, keys, actual identities, outcomes, order and final LF must
        // match. Only the bounded ACTUAL ancestor/dot-inclusive count is variable.
        need(raw == self.result(request_sha, &self.expected(account_sha, entries))?.as_bytes())?;
        Ok(entries)
    }
    pub fn accept_passive_result(&self, raw: &[u8], request_sha: &str, account_sha: &str) -> Result<usize> {
        need(self.role == ResultRole::Passive && !raw.is_empty() && raw.len() <= LIMIT && raw.is_ascii())?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
        let count = |key: &str, limit| -> Result<usize> {
            let tail = text.split_once(&format!("\"{key}\":" )).ok_or(Error::Unsafe)?.1;
            positive_size(tail.split_once(',').ok_or(Error::Unsafe)?.0, limit)
        };
        let entries = count("entries", MAX_ENTRIES)?;
        let facts = PassiveFacts { version: self.expected(account_sha, entries), completed_methods: 5, settled_owners: 9,
            payload_images: count("payloadImages", 33)?, system_images: count("systemImages", 31)?,
            stopped_before_claim: true, stopped_owned_child: true };
        // Comparison DATA only; the writer never obtains facts from this
        // expected-value constructor. Exact bytes reject duplicate/extra keys.
        need(raw == self.passive_result(request_sha, &facts)?.as_bytes())?;
        Ok(entries)
    }
}
pub(super) fn fullwalk_command(path: &str) -> String { format!("\"{path}\" {FULLWALK_CHILD} {}", FLAGS.join(" ")) }
fn fullwalk_owner_command(path: &str) -> String { format!("\"{path}\" {FULLWALK_OWNER} {}", FLAGS.join(" ")) }
pub(super) fn passive_command(path: &str) -> String { ResultRole::Passive.command(path, false) }

#[cfg(feature = "qualification-result")]
fn fullwalk_digest(raw: &[u8], end: Instant, app: bool) -> Result<String> {
    deadline(Some(end))?;
    let result = if app { digest_app_traced(raw, &mut InputTrace::default()) } else { digest(raw) };
    deadline(Some(end))?;
    result
}
/// Write the sole fixed fullwalk result after the actual app book has settled.
/// No path/launcher/raw-SID API is exposed. Unknown never returns or drops its
/// original/security inputs; even a known late close cannot return success.
#[cfg(feature = "qualification-result")]
pub fn write_fullwalk_result_once(actual: &FullwalkFacts, end: Instant) -> Result<()> {
    write_installed_result(ResultRole::Fullwalk, actual, None, end)
}
#[cfg(feature = "qualification-result")]
pub fn write_passive_result_once(actual: &PassiveFacts, end: Instant) -> Result<()> {
    actual.validate()?;
    write_installed_result(ResultRole::Passive, &actual.version, Some(actual), end)
}
#[cfg(feature = "qualification-result")]
pub fn require_passive_qualification() -> Result<()> {
    let raw = std::env::var(ResultRole::Passive.request_env()).map_err(|_| Error::State)?;
    let request = FullwalkRequest::parse_passive(raw.as_bytes(), &mut InputTrace::default())?;
    request.compiled_traced(&mut InputTrace::default())?;
    need(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256") == Some(request.manifest_sha.as_str())
        && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(request.protocol_sha.as_str()))?;
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    need(artifact.to_str() == Some(request.app.path.as_str()))?;
    args_are(PASSIVE_CHILD, &artifact)
}
#[cfg(feature = "qualification-result")]
fn write_installed_result(role: ResultRole, actual: &FullwalkFacts, passive: Option<&PassiveFacts>, end: Instant) -> Result<()> {
    deadline(Some(end))?;
    actual.validate()?;
    let get = |name| std::env::var(name).map_err(|_| Error::State);
    let raw_request = get(role.request_env())?;
    let request = FullwalkRequest::parse_role(raw_request.as_bytes(), &mut InputTrace::default(), role)?;
    request.compiled_traced(&mut InputTrace::default())?;
    need(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256") == Some(request.manifest_sha.as_str())
        && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(request.protocol_sha.as_str()))?;
    let output = fixed_path(&get(role.output_env())?)?;
    let root = output.parent().ok_or(Error::Unsafe)?;
    need(output.file_name().and_then(|v| v.to_str()) == Some(role.output())
        && root.file_name().and_then(|v| v.to_str()) == Some(format!("mrk-windows-installed-native-{}-1", request.run).as_str()))?;
    request.at_root(root)?;
    deadline(Some(end))?;
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    deadline(Some(end))?;
    need(artifact.to_str() == Some(request.app.path.as_str()))?;
    args_are(role.child(), &artifact)?;
    request.commands_until(Some(end), &mut InputTrace::default())?;
    let after_identity = get(role.identity_env())?;
    request.app_after(&after_identity)?; // request's original pre-ACL identity stays intact
    let account = unhex(&get("MRK_WINDOWS_ORDINARY_SID")?)?;
    let parent = unhex(&get("MRK_WINDOWS_PARENT_SID")?)?;
    security::sid_at(&account, 0, account.len())?;
    security::sid_at(&parent, 0, parent.len())?;
    need(account.len() == 28 && parent.len() == 28 && account != parent
        && account != system_sid() && account != builtin(544)
        && fullwalk_digest(&account, end, false)? == actual.account_sid_sha256)?;
    let request_sha = fullwalk_digest(raw_request.as_bytes(), end, false)?;
    let value = match passive { Some(facts) => request.passive_result(&request_sha, facts)?, None => request.result(&request_sha, actual)? }; // validates all copied observation DATA before IO
    deadline(Some(end))?;
    let cwd = std::env::current_dir().map_err(|_| Error::Unavailable)?;
    deadline(Some(end))?;
    need(cwd == output)?;
    let mut file = OriginalFile::new_until(&artifact, false, end)?;
    let observation = (|| -> Result<()> {
        file.open(FS::FILE_GENERIC_READ, false, null())?; file.named(&artifact)?;
        let before = file.stamp()?;
        need(request.app.matches_identity(&before, &after_identity))?;
        let bytes = file.read_app_traced(&mut InputTrace::default())?;
        need(bytes.len() == request.app.bytes && fullwalk_digest(&bytes, end, true)? == request.app.sha)?;
        need(file.stamp()? == before)
    })();
    if matches!(observation, Err(Error::Unknown)) {
        diagnostic_data("result-original-operation", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut file, &request, actual)); }
    }
    let closed = file.close(); // same original, also after ordinary read/hash/deadline refusal
    if closed.is_err() {
        diagnostic_data("result-original-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut file, &request, actual)); }
    }
    let timely = file.body().timely();
    observation?; timely?;
    let (acl, mut descriptor) = child_security_until(&parent, &account, Some(end))?;
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    let result = write_one_until(&output.join(role.result()), value.as_bytes(), LIMIT, &attributes, Some(end));
    // Unknown parks inside the shared writer: these actual caller-owned inputs
    // are still live on this same owning stack. No self-close receipt is emitted.
    std::hint::black_box((&acl, &descriptor, &attributes));
    result
}

// Normal-UI qualification is a separate closed wire. The historical ordinary,
// Fullwalk and intentionally poisoned Passive parsers above are not widened.
#[cfg(feature = "desktop-ui")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiRole { Prerequisite, NormalSmoke, ProjectDraft, QuitPassive, DocumentLoss }
#[cfg(feature = "desktop-ui")]
impl UiRole {
    pub fn label(self) -> &'static str { match self {
        Self::Prerequisite => "prerequisite", Self::NormalSmoke => "normal-smoke",
        Self::ProjectDraft => "project-draft", Self::QuitPassive => "quit-passive", Self::DocumentLoss => "document-loss",
    } }
    pub(super) fn parse(value: &str) -> Result<Self> { match value {
        "prerequisite" => Ok(Self::Prerequisite), "normal-smoke" => Ok(Self::NormalSmoke),
        "project-draft" => Ok(Self::ProjectDraft), "quit-passive" => Ok(Self::QuitPassive),
        "document-loss" => Ok(Self::DocumentLoss), _ => Err(Error::Unsafe),
    } }
    pub(super) fn owner(self) -> &'static str { match self {
        Self::Prerequisite => "ordinary_owner::hosted_normal_ui_prerequisite_original_handle_contract",
        Self::NormalSmoke => "ordinary_owner::hosted_normal_ui_smoke_original_handle_contract",
        Self::ProjectDraft => "ordinary_owner::hosted_normal_ui_project_original_handle_contract",
        Self::QuitPassive => "ordinary_owner::hosted_normal_ui_quit_original_handle_contract",
        Self::DocumentLoss => "ordinary_owner::hosted_normal_ui_document_original_handle_contract",
    } }
    pub(super) fn entry(self) -> &'static str { match self {
        Self::Prerequisite => "hosted_ui_tests::hosted_normal_ui_prerequisites_contract",
        Self::NormalSmoke => "normal-process-main", _ => "observer-process-main",
    } }
    pub(super) fn name(self, suffix: &str) -> String { format!("normal-ui-{}-{suffix}", self.label()) }
    pub(super) fn command(self, path: &str, owner: bool) -> String {
        if owner || self == Self::Prerequisite {
            format!("\"{path}\" {} {}", if owner { self.owner() } else { self.entry() }, FLAGS.join(" "))
        } else { format!("\"{path}\"") }
    }
    pub(super) fn app_messages(self) -> &'static str { match self {
        Self::Prerequisite => "compile-messages.jsonl", Self::NormalSmoke => "normal-app-compile-messages.jsonl",
        _ => "observer-compile-messages.jsonl",
    } }
    fn checks(self) -> &'static [&'static str] { match self {
        Self::ProjectDraft => &["native-picker-cancel", "native-project-selected", "draft-hydrated-edited",
            "validate-suggest-preview", "refresh-draft-preserved", "source-change-observed", "only-labelled-fixture-mutation"],
        Self::QuitPassive => &["native-quit-cancel", "native-quit-confirm", "passive-original-outstanding", "original-owner-retired"],
        Self::DocumentLoss => &["native-picker-outstanding", "passive-original-outstanding", "original-document-loss", "no-late-publication", "no-rebind"],
        _ => &[],
    } }
    pub(super) fn process_args(self, artifact: &Path, owner: bool) -> Result<()> {
        if owner || self == Self::Prerequisite { args_are(if owner { self.owner() } else { self.entry() }, artifact) }
        else {
            let args: Vec<_> = std::env::args_os().collect();
            need(args.len() == 1 && args[0] == artifact.as_os_str())
        }
    }
}

#[cfg(feature = "desktop-ui")]
pub(super) const UI_REQUEST_FIELDS: [&str; 35] = [
    "role", "test", "sourceSha", "sourceTree", "runId", "attempt",
    "appArtifact", "appArtifactBytes", "appArtifactSha256", "appArtifactIdentity", "appCommandSha256",
    "appCompileMessagesBytes", "appCompileMessagesSha256", "appCompileArgvSha256",
    "ownerArtifact", "ownerArtifactBytes", "ownerArtifactSha256", "ownerArtifactIdentity", "ownerCommandSha256",
    "ownerCompileMessagesBytes", "ownerCompileMessagesSha256", "ownerCompileArgvSha256",
    "manifestSha256", "protocolSha256", "inventorySha256", "coreSha256", "payloadFiles", "payloadBytes",
    "publicationReceiptBytes", "publicationReceiptSha256", "versionIdentity",
    "selectedPythonIdentity", "selectedBootstrapIdentity", "selectedCoreIdentity", "appVersion",
];
#[cfg(feature = "desktop-ui")]
#[derive(Clone)]
pub(super) struct UiRequest {
    pub role: UiRole, pub source: String, pub tree: String, pub run: String,
    pub app: FullwalkArtifact, pub owner: FullwalkArtifact,
    pub runtime: Option<FullwalkRequest>, pub app_version: String,
}
#[cfg(feature = "desktop-ui")]
fn ui_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && (2..=6).contains(&value.split('.').count())
        && value.split('.').all(|part| !part.is_empty() && part.len() <= 10 && part.bytes().all(|b| b.is_ascii_digit()))
}
#[cfg(feature = "desktop-ui")]
impl UiRequest {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        need(!raw.is_empty() && raw.len() <= LIMIT && raw.is_ascii() && raw.ends_with(b"\n") && !raw.contains(&b'\r'))?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
        let lines: Vec<_> = text.lines().collect();
        need(lines.len() == 36 && lines[0] == "MRK_WINDOWS_NORMAL_UI_REQUEST_V1")?;
        let mut v = Vec::with_capacity(UI_REQUEST_FIELDS.len());
        for (line, key) in lines[1..].iter().zip(UI_REQUEST_FIELDS) {
            let (name, value) = line.split_once('=').ok_or(Error::Unsafe)?;
            need(name == key && !value.is_empty())?; v.push(value);
        }
        let role = UiRole::parse(v[0])?;
        need(v[1] == role.entry() && is_hex(v[2], 40) && v[2] != "0".repeat(40)
            && is_hex(v[3], 40) && v[3] != "0".repeat(40) && decimal(v[4]) && v[4].parse::<u64>().is_ok()
            && v[5] == "1" && ui_version(v[34]))?;
        let artifact = |offset: usize, limit| -> Result<FullwalkArtifact> {
            fixed_path(v[offset])?; artifact_identity(v[offset + 3])?;
            need([2, 4, 6, 7].into_iter().all(|i| is_hex(v[offset + i], 64)))?;
            Ok(FullwalkArtifact { path: v[offset].to_owned(), bytes: positive_size(v[offset + 1], limit)?,
                sha: v[offset + 2].to_owned(), identity: v[offset + 3].to_owned(), command_sha: v[offset + 4].to_owned(),
                messages_bytes: positive_size(v[offset + 5], 16 << 20)?, messages_sha: v[offset + 6].to_owned(),
                argv_sha: v[offset + 7].to_owned() })
        };
        let app = artifact(6, if role == UiRole::Prerequisite { ORDINARY_ARTIFACT_LIMIT } else { APP_ARTIFACT_LIMIT })?;
        let owner = artifact(14, ORDINARY_ARTIFACT_LIMIT)?;
        let runtime = if role == UiRole::Prerequisite {
            need(v[22..34].iter().all(|value| *value == "-") && app.path == owner.path && app.bytes == owner.bytes
                && app.sha == owner.sha && app.identity == owner.identity && app.messages_bytes == owner.messages_bytes
                && app.messages_sha == owner.messages_sha && app.argv_sha == owner.argv_sha)?;
            None
        } else {
            need(v[22..26].iter().all(|value| is_hex(value, 64)) && is_hex(v[29], 64))?;
            let version = fullwalk_identity(v[30])?;
            let selected = [fullwalk_identity(v[31])?, fullwalk_identity(v[32])?, fullwalk_identity(v[33])?];
            fullwalk_identities(version, &selected)?;
            Some(FullwalkRequest { role: ResultRole::Passive, source: v[2].to_owned(), tree: v[3].to_owned(), run: v[4].to_owned(),
                app: app.clone(), owner: owner.clone(), manifest_sha: v[22].to_owned(), protocol_sha: v[23].to_owned(),
                inventory_sha: v[24].to_owned(), core_sha: v[25].to_owned(), files: positive_size(v[26], MAX_FILES - 1)?,
                payload_bytes: positive_size(v[27], MAX_TOTAL_BYTES as usize)? as u64,
                publication_bytes: positive_size(v[28], OWNER_LIMIT)?, publication_sha: v[29].to_owned(), version, selected })
        };
        let result = Self { role, source: v[2].to_owned(), tree: v[3].to_owned(), run: v[4].to_owned(), app, owner,
            runtime, app_version: v[34].to_owned() };
        for (path, expected, owner) in [(&result.app.path, &result.app.command_sha, false),
            (&result.owner.path, &result.owner.command_sha, true)] {
            let command = role.command(path, owner);
            need(command.encode_utf16().count() <= 1023
                && digest(&command.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>())? == *expected)?;
        }
        Ok(result)
    }
    pub fn compiled(&self) -> Result<()> {
        need(option_env!("GITHUB_SHA") == Some(self.source.as_str())
            && option_env!("MRK_WINDOWS_SOURCE_TREE") == Some(self.tree.as_str())
            && option_env!("GITHUB_RUN_ID") == Some(self.run.as_str())
            && option_env!("MRK_WINDOWS_UI_APP_VERSION") == Some(self.app_version.as_str()))?;
        for (name, expected) in [
            ("MRK_DESKTOP_HOSTED_CHECKS", "windows-installed-native-v1"), ("GITHUB_ACTIONS", "true"),
            ("RUNNER_ENVIRONMENT", "github-hosted"), ("RUNNER_OS", "Windows"), ("RUNNER_ARCH", "X64"),
            ("ImageOS", "win25-vs2026"), ("GITHUB_RUN_ATTEMPT", "1"), ("GITHUB_SHA", self.source.as_str()),
            ("GITHUB_RUN_ID", self.run.as_str()), ("MRK_WINDOWS_SOURCE_TREE", self.tree.as_str()),
            ("MRK_DESKTOP_DISPATCH_SCOPE", "windows-normal-project-ui"),
            ("GITHUB_REF", "refs/heads/verify/desktop-windows-normal-project-ui"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ] { need(std::env::var(name).as_deref() == Ok(expected))?; }
        Ok(())
    }
    pub fn at_root(&self, root: &Path) -> Result<()> {
        need(root.file_name().and_then(|name| name.to_str()) == Some(format!("mrk-windows-installed-native-{}-1", self.run).as_str()))?;
        let debug = root.join("target/x86_64-pc-windows-msvc/debug");
        let fixed_exe = |value: &str, prefix: &str| -> Result<()> {
            let path = fixed_path(value)?;
            let name = path.file_name().and_then(|value| value.to_str()).ok_or(Error::Unsafe)?;
            let hash = name.strip_prefix(prefix).and_then(|value| value.strip_suffix(".exe")).ok_or(Error::Unsafe)?;
            need(path.parent() == Some(debug.join("deps").as_path()) && is_hex(hash, 16))
        };
        fixed_exe(&self.owner.path, "mrk_windows_installed_native-")?;
        match self.role {
            UiRole::Prerequisite => need(self.app.path == self.owner.path),
            UiRole::NormalSmoke => need(Path::new(&self.app.path) == root.join("mobile-release-kit-desktop.exe")),
            _ => fixed_exe(&self.app.path, "installed_shell_observation-"),
        }
    }
    pub fn app_after(&self, identity: &str) -> Result<()> {
        artifact_identity(identity)?;
        let before: Vec<_> = self.app.identity.split(':').collect(); let after: Vec<_> = identity.split(':').collect();
        need([0, 1, 2, 3, 5].into_iter().all(|index| before[index] == after[index])
            && after[4].parse::<i64>().map_err(|_| Error::Unsafe)? >= before[4].parse::<i64>().map_err(|_| Error::Unsafe)?)
    }
    fn envelope(&self, request_sha: &str, account_sha: &str, observation: &str) -> Result<String> {
        need(is_hex(request_sha, 64) && is_hex(account_sha, 64))?;
        let text = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"role\":\"{}\",\"requestSha256\":\"{request_sha}\",\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"accountSidSha256\":\"{account_sha}\",\"observation\":{observation},\"resultFile\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-child-exit-zero-required\"}}}}\n",
            self.source, self.tree, self.run, self.role.label(), self.app.bytes, self.app.sha, self.app.command_sha);
        need(text.len() <= LIMIT)?; Ok(text)
    }
    fn case_observation(&self) -> Result<String> {
        need(!self.role.checks().is_empty())?;
        let checks = self.role.checks().iter().map(|value| format!("\"{value}\"")).collect::<Vec<_>>().join(",");
        Ok(format!("{{\"runtimeBindingMatched\":true,\"verifiedMethods\":{},\"checks\":[{checks}],\"finality\":{{\"dialogsSettled\":true,\"sourcesSettled\":true,\"passiveOwnersSettled\":true,\"documentHooksSettled\":true,\"relayJoined\":true,\"exitReady\":true}}}}",
            if self.role == UiRole::ProjectDraft { 6 } else { 0 }))
    }
    pub fn probe_result(&self, request_sha: &str, account_sha: &str, reason: Option<&str>, version: Option<&str>) -> Result<String> {
        need(self.role == UiRole::Prerequisite)?;
        let available = reason.is_none();
        let (reason, version) = match (reason, version) {
            (None, Some(version)) if ui_version(version) => ("null".to_owned(), format!("\"{version}\"")),
            (Some(reason), None) if UI_PROBE_REASONS.contains(&reason) => (format!("\"{reason}\""), "null".to_owned()),
            _ => return Err(Error::Unsafe),
        };
        self.envelope(request_sha, account_sha, &format!("{{\"available\":{available},\"reason\":{reason},\"ordinaryAccountMatched\":true,\"ordinaryContext\":{available},\"interactiveDesktop\":{available},\"managedRuntime\":{available},\"overrideFree\":{available},\"privateParent\":{available},\"runtimeVersion\":{version},\"originalsSettled\":true,\"noWebviewCreated\":true}}"))
    }
    pub fn accept_child(&self, raw: &[u8], request_sha: &str, account_sha: &str) -> Result<bool> {
        need(raw.len() <= LIMIT && raw.is_ascii())?;
        if self.role != UiRole::Prerequisite {
            need(raw == self.envelope(request_sha, account_sha, &self.case_observation()?)?.as_bytes())?; return Ok(true);
        }
        for reason in UI_PROBE_REASONS {
            if raw == self.probe_result(request_sha, account_sha, Some(reason), None)?.as_bytes() { return Ok(false); }
        }
        let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
        let version = text.split_once("\"runtimeVersion\":\"").and_then(|(_, tail)| tail.split_once('"'))
            .map(|(value, _)| value).ok_or(Error::Unsafe)?;
        need(raw == self.probe_result(request_sha, account_sha, None, Some(version))?.as_bytes())?;
        Ok(true)
    }
}
#[cfg(feature = "desktop-ui")]
const UI_PROBE_REASONS: [&str; 7] = ["ordinary-context", "interactive-desktop", "managed-webview2", "webview2-overrides",
    "private-user-data-parent", "native-failure", "original-state"];

/// Engineering-only DATA from the actual original runtime and GUI owners.
/// Array order is fixed by UiRole::checks and the six named finality keys above.
/// A result writer validates these facts but cannot acquire or settle an owner.
#[cfg(feature = "desktop-ui")]
pub struct UiCaseFacts {
    pub version: FullwalkFacts, pub verified_methods: usize,
    pub checks: [bool; 7], pub finality: [bool; 6],
}

/// The one original native owner's uptime endpoint, not a fresh ninety seconds.
/// Call once at child process-main entry and retain the returned Instant.
#[cfg(feature = "desktop-ui")]
pub fn normal_ui_deadline() -> Result<Instant> {
    let value = std::env::var("MRK_WINDOWS_NORMAL_UI_END_TICK_MS").map_err(|_| Error::State)?;
    need(decimal(&value))?;
    let endpoint = value.parse::<u64>().map_err(|_| Error::Unsafe)?;
    let local = Instant::now();
    let now = unsafe { SI::GetTickCount64() };
    let remaining = endpoint.checked_sub(now).ok_or(Error::Unsafe)?;
    need(remaining > 0 && remaining <= 90_000)?;
    local.checked_add(std::time::Duration::from_millis(remaining)).ok_or(Error::Unsafe)
}

// Fixed synthetic project DATA, never project hooks or external signing inputs.
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_SOURCE: &[u8] = b"plugins { id(\"com.android.application\") }\nandroid { defaultConfig { applicationId = \"org.example.mrk.observed\" } }\n";
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_VERSION: &[u8] = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n";
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_KEEP: &[u8] = b"MRK_WINDOWS_NORMAL_UI_KEEP\n";
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_CONFIG: &[u8] = b"{\"android\":{\"applicationId\":\"org.example.mrk.observed\",\"enabled\":true,\"identityStatus\":\"unverified\"},\"ios\":{\"enabled\":false},\"metadata\":{\"androidLocales\":[\"en-US\"],\"iosLocales\":[],\"root\":\"release/store\"},\"projectChecks\":{\"androidArtifact\":[],\"iosArtifact\":[],\"preflight\":[]},\"schemaVersion\":1,\"services\":{\"androidFirebase\":\"disabled\",\"iosFirebase\":\"disabled\"},\"source\":{\"candidateBranch\":\"main\",\"productionBranch\":\"main\"},\"version\":{\"buildKey\":\"BUILD_NUMBER\",\"nameKey\":\"VERSION_NAME\",\"source\":\"version.properties\"}}\n";
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_CONFIG_AFTER: &[u8] = b"{\"android\":{\"applicationId\":\"org.example.mrk.observed\",\"enabled\":true,\"identityStatus\":\"unverified\"},\"ios\":{\"enabled\":false},\"metadata\":{\"androidLocales\":[\"en-US\"],\"iosLocales\":[],\"root\":\"release/store\"},\"projectChecks\":{\"androidArtifact\":[],\"iosArtifact\":[],\"preflight\":[]},\"schemaVersion\":1,\"services\":{\"androidFirebase\":\"disabled\",\"iosFirebase\":\"disabled\"},\"source\":{\"candidateBranch\":\"next\",\"productionBranch\":\"main\"},\"version\":{\"buildKey\":\"BUILD_NUMBER\",\"nameKey\":\"VERSION_NAME\",\"source\":\"version.properties\"}}\n";

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn normal_ui_project() -> Result<PathBuf> {
    require_normal_ui_qualification()?;
    let raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
    let request = UiRequest::parse(raw.as_bytes())?;
    let output = fixed_path(&std::env::var("MRK_WINDOWS_NORMAL_UI_OUTPUT").map_err(|_| Error::State)?)?;
    request.at_root(output.parent().ok_or(Error::Unsafe)?)?;
    need(output.file_name().and_then(|name| name.to_str()) == Some(request.role.name("output").as_str())
        && std::env::current_dir().map_err(|_| Error::Unavailable)? == output)?;
    Ok(output.join("project"))
}

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
static UI_FIXTURE_MUTATION_CLAIMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
static UI_FIXTURE_VERIFIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// One explicit fixture-only CREATE_NEW, not the application's Save path.
/// The ProjectDraft fixture starts without config so genuine Suggest/Adopt is
/// visible. No caller chooses a path/bytes or receives a general write permit.
#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn mutate_normal_ui_fixture(end: Instant) -> Result<()> {
    need(require_normal_ui_qualification()? == UiRole::ProjectDraft)?;
    deadline(Some(end))?;
    need(!UI_FIXTURE_MUTATION_CLAIMED.swap(true, std::sync::atomic::Ordering::SeqCst))?;
    let path = normal_ui_project()?.join("release/mobile-release.json");
    let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
    let parent = unhex(&std::env::var("MRK_WINDOWS_PARENT_SID").map_err(|_| Error::State)?)?;
    need(account.len() == 28 && parent.len() == 28 && account != parent)?;
    let (mut acl, mut descriptor) = child_security_until(&parent, &account, Some(end))?;
    // This is readable synthetic input, unlike the write-only result file.
    // Amend only this new, private descriptor before any borrower enters it.
    let account_ace = 8 + (8 + system_sid().len()) + (8 + builtin(544).len()) + (8 + parent.len());
    need(&acl.0[account_ace + 8..account_ace + 8 + account.len()] == account.as_slice())?;
    acl.0[account_ace + 4..account_ace + 8].copy_from_slice(&(FS::FILE_GENERIC_READ | FS::FILE_GENERIC_WRITE).to_le_bytes());
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    let mut original = OriginalFile::new_until(&path, false, end)?;
    let mut position = 0i64;
    let observed = (|| -> Result<()> {
        // Atomic absence check/creation. Collision is never opened or replaced.
        original.open(FS::FILE_GENERIC_READ | FS::FILE_GENERIC_WRITE, true, &attributes)?;
        original.named(&path)?;
        let before = original.stamp()?;
        need(before.size == 0 && before.links == 1)?;
        original.write(UI_FIXTURE_CONFIG_AFTER, LIMIT)?; // ONE WriteFile only.
        ui_fixture_seek(&mut original, &mut position)?;
        need(original.read(LIMIT)? == UI_FIXTURE_CONFIG_AFTER)?;
        let after = original.stamp()?;
        need(before.volume == after.volume && before.id == after.id && before.creation == after.creation
            && after.size == UI_FIXTURE_CONFIG_AFTER.len() as i64 && after.allocation >= after.size && before.links == after.links
            && before.attributes == after.attributes && after.write >= before.write && after.change >= before.change)
    })();
    if matches!(observed, Err(Error::Unknown)) {
        diagnostic_data("ui-fixture-mutation", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &mut position, &acl, &descriptor, &attributes)); }
    }
    if original.close().is_err() {
        diagnostic_data("ui-fixture-mutation-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &mut position, &acl, &descriptor, &attributes)); }
    }
    observed?; deadline(Some(end))
}

/// Complete bounded fixture readback before the child report. It cannot turn
/// the later parent original-exit/identity gate into a pre-close child receipt.
#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn verify_normal_ui_fixture(end: Instant) -> Result<()> {
    UI_FIXTURE_VERIFIED.store(false, std::sync::atomic::Ordering::SeqCst);
    let role = require_normal_ui_qualification()?;
    need(UI_FIXTURE_MUTATION_CLAIMED.load(std::sync::atomic::Ordering::SeqCst) == (role == UiRole::ProjectDraft))?;
    let project = normal_ui_project()?;
    let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
    let mut native = NativeBook::new();
    let mut originals: Vec<(Original, Metadata)> = Vec::with_capacity(24);
    let observed = (|| -> Result<()> {
        deadline(Some(end))?;
        need(native.observe_user_once()?.user.bytes() == account.as_slice())?;
        let (drive, parts) = decode::dos_location(project.to_str().ok_or(Error::Unsafe)?)?;
        need(parts.len() < 16)?;
        let device = native.mapping(&drive)?;
        let canonical = format!("{device}\\");
        let root = native.reserve(Kind::Directory, None, &canonical, canonical.clone())?;
        native.call(Call::Open(root.index), null_mut(), Vec::new())?;
        native.noninherited(root.index)?; native.local_ntfs(&root)?;
        let metadata = native.metadata(&root)?; originals.push((root, metadata));
        for name in parts {
            deadline(Some(end))?;
            let original = native.open_child(&originals.last().ok_or(Error::State)?.0, &name, FileKind::Directory)?;
            let metadata = native.metadata(&original)?; originals.push((original, metadata));
        }
        let project_index = originals.len() - 1;
        let mut directory_indices = vec![project_index];
        for name in ["app", "release"] {
            let original = native.open_child(&originals[project_index].0, name, FileKind::Directory)?;
            let metadata = native.metadata(&original)?;
            directory_indices.push(originals.len()); originals.push((original, metadata));
        }
        let config = if role == UiRole::ProjectDraft { UI_FIXTURE_CONFIG_AFTER } else { UI_FIXTURE_CONFIG };
        let mut children: Vec<(usize, &str, usize)> = vec![(project_index, "app", directory_indices[1]),
            (project_index, "release", directory_indices[2])];
        for (parent, name, bytes) in [(directory_indices[1], "build.gradle.kts", UI_FIXTURE_SOURCE),
            (project_index, "version.properties", UI_FIXTURE_VERSION), (project_index, "keep.txt", UI_FIXTURE_KEEP),
            (directory_indices[2], "mobile-release.json", config)] {
            deadline(Some(end))?;
            let original = native.open_child(&originals[parent].0, name, FileKind::File)?;
            let metadata = native.metadata(&original)?;
            native.no_alternate_streams(&original)?;
            need(metadata.size == bytes.len() as u64 && native.read_next(&original, LIMIT)? == bytes
                && native.read_next(&original, 1)?.is_empty() && native.metadata(&original)? == metadata)?;
            children.push((parent, name, originals.len())); originals.push((original, metadata));
        }
        for index in directory_indices {
            let mut names = std::collections::BTreeSet::new();
            loop {
                deadline(Some(end))?;
                let Some(batch) = native.next_entries(&originals[index].0)? else { break; };
                for entry in batch {
                    need(names.insert(entry.name.clone()) && names.len() <= 6)?;
                    if entry.name == "." { need(entry.file_id == originals[index].1.identity.file_id)?; continue; }
                    if entry.name == ".." {
                        let parent = if index == project_index { project_index - 1 } else { project_index };
                        need(entry.file_id == originals[parent].1.identity.file_id)?; continue;
                    }
                    let (_, _, child) = children.iter().find(|(parent, name, _)| *parent == index && *name == entry.name)
                        .ok_or(Error::Unsafe)?;
                    need(entry.file_id == originals[*child].1.identity.file_id && entry.kind == originals[*child].1.kind)?;
                }
            }
            let expected: std::collections::BTreeSet<_> = children.iter().filter(|(parent, _, _)| *parent == index)
                .map(|(_, name, _)| name.to_string()).chain([".".to_owned(), "..".to_owned()]).collect();
            need(names == expected)?;
        }
        for (original, before) in originals.iter().rev() {
            deadline(Some(end))?; need(native.metadata(original)? == *before)?;
        }
        need(native.mapping(&drive)? == device)?; native.recheck_user()?; deadline(Some(end))
    })();
    if matches!(observed, Err(Error::Unknown)) || native.is_unknown() {
        diagnostic_data("ui-fixture-readback", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut native, &originals)); }
    }
    if native.settle_once() != CloseOutcome::Settled || !native.settled() {
        diagnostic_data("ui-fixture-readback-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut native, &originals)); }
    }
    observed?; deadline(Some(end))?;
    UI_FIXTURE_VERIFIED.store(true, std::sync::atomic::Ordering::SeqCst); Ok(())
}

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
fn ui_fixture_seek(original: &mut OriginalFile, position: &mut i64) -> Result<()> {
    let b = original.body();
    need(b.state == SlotState::Owned && !b.active)?; b.timely()?; b.active = true;
    let returned = unsafe { FS::SetFilePointerEx(b.handle, 0, position, FS::FILE_BEGIN) };
    b.error = if returned != 0 { 0 } else { unsafe { F::GetLastError() } };
    b.active = returned == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
    if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
    b.timely()?; need(returned != 0 && *position == 0)
}

#[cfg(feature = "desktop-ui")]
fn ui_digest(raw: &[u8], end: Instant, app: bool) -> Result<String> {
    deadline(Some(end))?;
    let result = if app { digest_app_traced(raw, &mut InputTrace::default()) } else { digest(raw) };
    deadline(Some(end))?; result
}

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn require_normal_ui_qualification() -> Result<UiRole> {
    let raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
    let request = UiRequest::parse(raw.as_bytes())?; request.compiled()?;
    need(!request.role.checks().is_empty())?;
    let runtime = request.runtime.as_ref().ok_or(Error::State)?;
    need(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256") == Some(runtime.manifest_sha.as_str())
        && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(runtime.protocol_sha.as_str()))?;
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    need(artifact.to_str() == Some(request.app.path.as_str()))?;
    request.role.process_args(&artifact, false)?;
    Ok(request.role)
}

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn write_normal_ui_result_once(actual: &UiCaseFacts, end: Instant) -> Result<()> {
    deadline(Some(end))?;
    let role = require_normal_ui_qualification()?;
    let request_raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
    let request = UiRequest::parse(request_raw.as_bytes())?;
    let runtime = request.runtime.as_ref().ok_or(Error::State)?;
    actual.version.validate()?;
    need(UI_FIXTURE_VERIFIED.load(std::sync::atomic::Ordering::SeqCst)
        && actual.verified_methods == if role == UiRole::ProjectDraft { 6 } else { 0 }
        && actual.checks.iter().enumerate().all(|(index, value)| *value == (index < role.checks().len()))
        && actual.finality == [true; 6]
        && actual.version.manifest_sha256 == runtime.manifest_sha && actual.version.protocol_sha256 == runtime.protocol_sha
        && actual.version.inventory_sha256 == runtime.inventory_sha && actual.version.core_sha256 == runtime.core_sha
        && actual.version.files == runtime.files && actual.version.payload_bytes == runtime.payload_bytes
        && actual.version.version_identity == runtime.version && actual.version.selected_identities == runtime.selected)?;
    let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
    need(fullwalk_digest(&account, end, false)? == actual.version.account_sid_sha256)?;
    let value = request.envelope(&fullwalk_digest(request_raw.as_bytes(), end, false)?,
        &actual.version.account_sid_sha256, &request.case_observation()?)?;
    write_ui_child(&request, &value, end)
}

#[cfg(feature = "desktop-ui")]
pub(super) fn write_ui_child(request: &UiRequest, value: &str, end: Instant) -> Result<()> {
    deadline(Some(end))?; request.compiled()?;
    let get = |name| std::env::var(name).map_err(|_| Error::State);
    let output = fixed_path(&get("MRK_WINDOWS_NORMAL_UI_OUTPUT")?)?;
    let root = output.parent().ok_or(Error::Unsafe)?; request.at_root(root)?;
    need(output.file_name().and_then(|name| name.to_str()) == Some(request.role.name("output").as_str())
        && std::env::current_dir().map_err(|_| Error::Unavailable)? == output)?;
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    need(artifact.to_str() == Some(request.app.path.as_str()))?; request.role.process_args(&artifact, false)?;
    let identity = get("MRK_WINDOWS_NORMAL_UI_ARTIFACT_IDENTITY")?; request.app_after(&identity)?;
    let account = unhex(&get("MRK_WINDOWS_ORDINARY_SID")?)?;
    let parent = unhex(&get("MRK_WINDOWS_PARENT_SID")?)?;
    security::sid_at(&account, 0, account.len())?; security::sid_at(&parent, 0, parent.len())?;
    need(account.len() == 28 && parent.len() == 28 && account != parent && account != system_sid() && account != builtin(544))?;
    let mut artifact_original = OriginalFile::new_until(&artifact, false, end)?;
    let observed = (|| -> Result<()> {
        artifact_original.open(FS::FILE_GENERIC_READ, false, null())?; artifact_original.named(&artifact)?;
        let before = artifact_original.stamp()?;
        need(request.app.matches_identity(&before, &identity))?;
        let bytes = artifact_original.read_app_traced(&mut InputTrace::default())?;
        need(bytes.len() == request.app.bytes && ui_digest(&bytes, end, true)? == request.app.sha
            && artifact_original.stamp()? == before)
    })();
    if matches!(observed, Err(Error::Unknown)) {
        diagnostic_data("ui-result-artifact", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut artifact_original, request, value)); }
    }
    if artifact_original.close().is_err() {
        diagnostic_data("ui-result-artifact-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut artifact_original, request, value)); }
    }
    observed?; deadline(Some(end))?;
    let (acl, mut descriptor) = child_security_until(&parent, &account, Some(end))?;
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    let written = write_one_until(&output.join(request.role.name("result.private.json")), value.as_bytes(), LIMIT, &attributes, Some(end));
    std::hint::black_box((&acl, &descriptor, &attributes)); written?; deadline(Some(end))
}
