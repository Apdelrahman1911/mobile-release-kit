//! Fixed privileged package producer. This is not an installed-runtime owner.
//!
//! The safe executable registers this actual object in a process-lifetime
//! OnceLock<Mutex<_>> BEFORE admit_once. No worker, callback, cleanup, retry,
//! privilege adjustment, child process or destructor supplies native finality.
//! SHA256/strict manifest policy remains in the safe application; the only data
//! interface here is the fixed roster, bounded sizes and original byte chunks.
use super::*;
use super::{AdmissionRole as R, AdmissionOp as O, AdmissionCheck as C};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::SystemServices as SS;

const TARGET: &str = "x86_64-pc-windows-msvc";
const MANIFEST: usize = 7;
const MANIFEST_LIMIT: usize = 1024 * 1024;
const OPERATION: Duration = Duration::from_secs(180);

/// Literal DATA roster, not caller-selected destinations or executable authority.
pub const PUBLICATION_PAYLOADS: [&str; 47] = [
    "android_build_bootstrap.py",
    "config_edit_bootstrap.py",
    "core.zip",
    "engine_bootstrap.py",
    "environment_bootstrap.py",
    "github-ca.pem",
    "github_connection_bootstrap.py",
    "manifest.json",
    "offline_preflight_bootstrap.py",
    "python/LICENSE.txt",
    "python/MRK-EMBEDDED-NOTICES.txt",
    "python/_asyncio.pyd",
    "python/_bz2.pyd",
    "python/_ctypes.pyd",
    "python/_decimal.pyd",
    "python/_elementtree.pyd",
    "python/_hashlib.pyd",
    "python/_lzma.pyd",
    "python/_multiprocessing.pyd",
    "python/_overlapped.pyd",
    "python/_queue.pyd",
    "python/_remote_debugging.pyd",
    "python/_socket.pyd",
    "python/_sqlite3.pyd",
    "python/_ssl.pyd",
    "python/_uuid.pyd",
    "python/_wmi.pyd",
    "python/_zoneinfo.pyd",
    "python/_zstd.pyd",
    "python/libcrypto-3.dll",
    "python/libffi-8.dll",
    "python/libssl-3.dll",
    "python/libtommath.dll",
    "python/pyexpat.pyd",
    "python/python.cat",
    "python/python.exe",
    "python/python3.dll",
    "python/python314._pth",
    "python/python314.dll",
    "python/python314.zip",
    "python/pythonw.exe",
    "python/select.pyd",
    "python/sqlite3.dll",
    "python/unicodedata.pyd",
    "python/vcruntime140.dll",
    "python/vcruntime140_1.dll",
    "python/winsound.pyd",
];

fn need(value: bool) -> Result<()> { if value { Ok(()) } else { Err(Error::Unsafe) } }
fn digest_name(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sid(authority: u8, sub: &[u32]) -> Vec<u8> {
    let mut raw = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, authority];
    for value in sub { raw.extend(value.to_le_bytes()); }
    raw
}
fn admins() -> Vec<u8> { sid(5, &[32, 544]) }
fn system() -> Vec<u8> { sid(5, &[18]) }
fn users() -> Vec<u8> { sid(5, &[32, 545]) }
fn image_payload(index: usize) -> Result<bool> {
    let path = PUBLICATION_PAYLOADS.get(index).ok_or(Error::State)?;
    Ok(path.ends_with(".exe") || path.ends_with(".dll") || path.ends_with(".pyd"))
}
fn users_mask(kind: FileKind, image: bool) -> u32 {
    FS::FILE_GENERIC_READ | if kind == FileKind::Directory || image { FS::FILE_GENERIC_EXECUTE } else { 0 }
}

// Exact noninheriting protected DACLs. An input or existing shared ancestor NEVER
// enters this constructor's mutation path. The group is supplied at creation,
// but GetKernelObjectSecurity(OWNER|DACL) does not return it: compare parsed facts.
fn descriptor(kind: FileKind, image: bool, sealed: bool) -> Result<Vec<u8>> {
    let owner = admins();
    let mut entries = vec![(system(), FS::FILE_ALL_ACCESS), (owner.clone(), FS::FILE_ALL_ACCESS)];
    if sealed { entries.push((users(), users_mask(kind, image))); }
    let mut acl = vec![0u8; size_of::<S::ACL>()];
    acl[0] = 2;
    for (principal, mask) in &entries {
        let length = 8 + principal.len();
        acl.extend([0, 0]);
        acl.extend((length as u16).to_le_bytes());
        acl.extend(mask.to_le_bytes());
        acl.extend(principal);
    }
    let length = acl.len() as u16;
    acl[2..4].copy_from_slice(&length.to_le_bytes());
    acl[4..6].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    let header = size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>();
    need(header == 20)?;
    let mut raw = vec![0u8; header];
    raw[0] = 1;
    raw[2..4].copy_from_slice(&(S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED).to_le_bytes());
    raw[4..8].copy_from_slice(&(header as u32).to_le_bytes());
    raw[8..12].copy_from_slice(&(header as u32).to_le_bytes());
    raw[16..20].copy_from_slice(&((header + owner.len()) as u32).to_le_bytes());
    raw.extend(owner);
    raw.extend(acl);
    exact_security(&security::descriptor(&raw, kind, AuthorityScope::ImmutableVersion)?, kind, image, sealed)?;
    Ok(raw)
}
fn exact_security(facts: &SecurityFacts, kind: FileKind, image: bool, sealed: bool) -> Result<()> {
    need(facts.owner.bytes() == admins()
        && facts.control == (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED)
        && facts.revision == 2 && facts.aces.len() == if sealed { 3 } else { 2 })?;
    for (i, ace) in facts.aces.iter().enumerate() {
        let principal = match i { 0 => system(), 1 => admins(), _ => users() };
        let mask = if i < 2 { FS::FILE_ALL_ACCESS } else { users_mask(kind, image) };
        need(ace.allow && ace.flags == 0 && ace.sid.bytes() == principal && ace.mask == mask)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Facts { metadata: Metadata, security: SecurityFacts }
fn same_object(a: &Metadata, b: &Metadata) -> bool {
    same_object_observed(a, b, None)
}
fn same_object_observed(a: &Metadata, b: &Metadata, trace: Option<CopyRefusal<'_>>) -> bool {
    copy_guard(a.identity == b.identity, CopyMember::Identity, trace)
        && copy_guard(a.kind == b.kind, CopyMember::Kind, trace)
        && copy_guard(a.attributes == b.attributes, CopyMember::Attributes, trace)
        && copy_guard(a.links == b.links, CopyMember::Links, trace)
        && copy_guard(a.creation == b.creation, CopyMember::Creation, trace)
}
fn child_transition(a: &Metadata, b: &Metadata) -> bool {
    // Used ONLY immediately after one recorded successful exclusive child create.
    // Directory index allocation/size can change in either direction on NTFS.
    same_object(a, b) && a.kind == FileKind::Directory && b.write >= a.write && b.change >= a.change
}
fn write_transition(a: &Metadata, b: &Metadata, size: u64) -> bool {
    write_transition_observed(a, b, size, None)
}
fn write_transition_observed(a: &Metadata, b: &Metadata, size: u64, trace: Option<CopyRefusal<'_>>) -> bool {
    if !(same_object_observed(a, b, trace) && copy_guard(a.kind == FileKind::File, CopyMember::Kind, trace)
        && copy_guard(a.size == 0, CopyMember::InitialSize, trace)) { return false; }
    let written_size = b.size;
    if !copy_guard(written_size == size, CopyMember::Size, trace) { return false; }
    let written_allocation = b.allocation_size;
    copy_allocation_guard(written_allocation >= size, trace, || CopyAllocation::BelowSize)
        && copy_guard(b.write >= a.write, CopyMember::WriteTime, trace)
        && copy_guard(b.change >= a.change, CopyMember::ChangeTime, trace)
}
fn writer_close_transition(a: &Metadata, b: &Metadata) -> bool {
    writer_close_transition_observed(a, b, None)
}
fn writer_close_transition_observed(a: &Metadata, b: &Metadata, trace: Option<CopyRefusal<'_>>) -> bool {
    if !(same_object_observed(a, b, trace) && copy_guard(a.kind == FileKind::File, CopyMember::Kind, trace)) { return false; }
    let (written_size, observed_size) = (a.size, b.size);
    if !copy_guard(written_size == observed_size, CopyMember::Size, trace) { return false; }
    let (written_allocation, observed_allocation) = (a.allocation_size, b.allocation_size);
    copy_allocation_guard(written_allocation == observed_allocation, trace,
        || changed_allocation(observed_allocation, written_allocation, observed_size))
        && copy_guard(b.write >= a.write, CopyMember::WriteTime, trace)
        && copy_guard(b.change >= a.change, CopyMember::ChangeTime, trace)
}
fn source_unchanged_observed(new: &Facts, old: &Facts, trace: Option<CopyRefusal<'_>>) -> bool {
    // Exactly the original derived Facts/Metadata Eq order, with new on the left.
    // Do not reuse same_object: size/allocation precede links/creation here.
    let (a, b) = (&new.metadata, &old.metadata);
    if !(copy_guard(a.identity == b.identity, CopyMember::Identity, trace)
        && copy_guard(a.kind == b.kind, CopyMember::Kind, trace)
        && copy_guard(a.attributes == b.attributes, CopyMember::Attributes, trace)) { return false; }
    let (new_size, old_size) = (a.size, b.size);
    if !copy_guard(new_size == old_size, CopyMember::Size, trace) { return false; }
    let (new_allocation, old_allocation) = (a.allocation_size, b.allocation_size);
    copy_allocation_guard(new_allocation == old_allocation, trace,
        || changed_allocation(new_allocation, old_allocation, new_size))
        && copy_guard(a.links == b.links, CopyMember::Links, trace)
        && copy_guard(a.creation == b.creation, CopyMember::Creation, trace)
        && copy_guard(a.write == b.write, CopyMember::WriteTime, trace)
        && copy_guard(a.change == b.change, CopyMember::ChangeTime, trace)
        && copy_guard(new.security == old.security, CopyMember::Security, trace)
}
fn acl_transition(a: &Metadata, b: &Metadata) -> bool {
    same_object(a, b) && a.size == b.size && a.allocation_size == b.allocation_size
        && a.write == b.write && b.change >= a.change
}

// Positive privileged admission is deliberately separate from security::token_facts,
// whose ordinary-reader policy MUST keep rejecting these contexts.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Installer {
    identity: TokenIdentity, user: Sid, integrity: Sid, elevation_type: u32,
    groups: Vec<GroupFact>, privileges: Vec<(u64, u32)>,
}
#[derive(Clone, Copy)]
struct InstallerData<'a>(Refusal<'a>);
impl InstallerData<'_> {
fn pointed_sid(self, raw: &[u8], field: usize, minimum: usize) -> Result<Sid> {
    let d = decode::Observed::new(self.0);
    let pointer = usize::try_from(d.u64_at(raw, field)?).map_err(|_| self.0.unsafe_at(C::PointerValue))?;
    let at = pointer.checked_sub(raw.as_ptr() as usize).ok_or_else(|| self.0.unsafe_at(C::PointerOffset))?;
    self.0.need(at >= minimum, C::PointerMinimum)?;
    self.0.need(at % 4 == 0, C::PointerAlignment)?;
    security::Observed::new(self.0).sid_at(raw, at, raw.len()) // no unvalidated pointer dereference
}
fn installer_groups(self, raw: &[u8], count: u32) -> Result<Vec<GroupFact>> {
    let header = offset_of!(S::TOKEN_GROUPS, Groups);
    let d = decode::Observed::new(self.0);
    self.0.need(count <= 256, C::GroupCount)?;
    self.0.need(raw.len() <= BUFFER, C::GroupSize)?;
    self.0.need(d.u32_at(raw, 0)? == count, C::GroupCountMatch)?;
    let extent = header.checked_add(count as usize * size_of::<S::SID_AND_ATTRIBUTES>()).ok_or(Error::Bounds)?;
    d.span(raw, 0, extent)?;
    let known = (SS::SE_GROUP_MANDATORY | SS::SE_GROUP_ENABLED_BY_DEFAULT | SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER
        | SS::SE_GROUP_USE_FOR_DENY_ONLY | SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED
        | SS::SE_GROUP_RESOURCE | SS::SE_GROUP_LOGON_ID) as u32;
    let mut result: Vec<GroupFact> = Vec::new();
    for i in 0..count as usize {
        let trace = self.0.index(AdmissionIndex::Group, i);
        let d = decode::Observed::new(trace);
        let base = header + i * size_of::<S::SID_AND_ATTRIBUTES>();
        let principal = Self(trace).pointed_sid(raw, base + offset_of!(S::SID_AND_ATTRIBUTES, Sid), extent)?;
        let attributes = d.u32_at(raw, base + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))?;
        trace.need(attributes & !known == 0, C::GroupFlags)?;
        trace.need(!(attributes & SS::SE_GROUP_USE_FOR_DENY_ONLY as u32 != 0 && attributes & SS::SE_GROUP_ENABLED as u32 != 0), C::GroupDenyEnabled)?;
        trace.need(!result.iter().any(|g| g.sid == principal), C::GroupDuplicate)?;
        result.push(GroupFact { sid: principal, attributes });
    }
    // Explicit Administrators ownership in new SECURITY_ATTRIBUTES is possible
    // without adjusting privileges only with this actually enabled owner group.
    self.0.need(result.iter().any(|g| g.sid.bytes() == admins()
        && g.attributes & (SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER) as u32
            == (SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER) as u32
        && g.attributes & (SS::SE_GROUP_USE_FOR_DENY_ONLY | SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_RESOURCE) as u32 == 0), C::AdminOwner)?;
    Ok(result)
}
fn installer_privileges(self, raw: &[u8], count: u32) -> Result<Vec<(u64, u32)>> {
    let head = offset_of!(S::TOKEN_PRIVILEGES, Privileges);
    let step = size_of::<S::LUID_AND_ATTRIBUTES>();
    let d = decode::Observed::new(self.0);
    self.0.need(count <= 64, C::PrivilegesCount)?;
    self.0.need(raw.len() == head + count as usize * step, C::PrivilegesSize)?;
    self.0.need(d.u32_at(raw, 0)? == count, C::PrivilegesCountMatch)?;
    let mut result = Vec::new();
    for i in 0..count as usize {
        let trace = self.0.index(AdmissionIndex::Privilege, i);
        let d = decode::Observed::new(trace);
        let at = head + i * step;
        let luid = d.u64_at(raw, at + offset_of!(S::LUID_AND_ATTRIBUTES, Luid))?;
        let attributes = d.u32_at(raw, at + offset_of!(S::LUID_AND_ATTRIBUTES, Attributes))?;
        trace.need(luid != 0, C::PrivilegeLuid)?;
        trace.need(!result.iter().any(|(prior, _)| *prior == luid), C::PrivilegeDuplicate)?;
        trace.need(attributes & !(S::SE_PRIVILEGE_ENABLED | S::SE_PRIVILEGE_ENABLED_BY_DEFAULT | S::SE_PRIVILEGE_USED_FOR_ACCESS) == 0, C::PrivilegeFlags)?;
        result.push((luid, attributes));
    }
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
fn installer_facts(self, identity: TokenIdentity, token_type: u32, elevated: u32, elevation_type: u32,
    ui_access: u32, virtualization: u32, restricted: u32, app_container: u32,
    user: &[u8], integrity: &[u8], groups: &[u8], privileges: &[u8]) -> Result<Installer> {
    self.0.need(token_type == S::TokenPrimary as u32, C::TokenPrimary)?;
    self.0.need(elevated == 1, C::Elevated)?;
    self.0.need(ui_access == 0, C::UiAccess)?;
    self.0.need(virtualization == 0, C::Virtualization)?;
    self.0.need(restricted == 0, C::Restricted)?;
    self.0.need(app_container == 0, C::AppContainer)?;
    self.0.need(user.len() <= BUFFER, C::UserBuffer)?;
    self.0.need(integrity.len() <= BUFFER, C::IntegrityBuffer)?;
    let u = Self(self.0.role(R::User));
    let principal = u.pointed_sid(user, offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid), size_of::<S::TOKEN_USER>())?;
    u.0.need(decode::Observed::new(u.0).u32_at(user, offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))? == 0, C::UserAttributes)?;
    let i = Self(self.0.role(R::Integrity));
    let label = i.pointed_sid(integrity, offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid), size_of::<S::TOKEN_MANDATORY_LABEL>())?;
    i.0.need(decode::Observed::new(i.0).u32_at(integrity, offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))?
        == (SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED) as u32, C::IntegrityAttributes)?;
    if principal.bytes() == system() {
        i.0.need(label.bytes() == sid(16, &[16384]), C::SystemIntegrity)?;
        self.0.need([S::TokenElevationTypeDefault as u32, S::TokenElevationTypeFull as u32].contains(&elevation_type), C::SystemElevation)?;
    } else {
        let bytes = principal.bytes();
        u.0.need(bytes.len() == 28 && bytes[1] == 5 && bytes[2..8] == [0, 0, 0, 0, 0, 5]
            && decode::Observed::new(u.0).u32_at(bytes, 8)? == 21, C::AccountShape)?;
        i.0.need(label.bytes() == sid(16, &[12288]), C::AccountIntegrity)?;
        // Default means no linked token, not absence of elevation. The independent
        // elevated == 1/High checks above and admin-owner/group/privilege checks below
        // remain mandatory; no Limited/unknown kind or normalization is allowed.
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_elevation_type
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_elevation
        self.0.need([S::TokenElevationTypeDefault as u32, S::TokenElevationTypeFull as u32].contains(&elevation_type), C::AccountElevation)?;
    }
    Ok(Installer { identity, user: principal, integrity: label, elevation_type,
        groups: Self(self.0.role(R::Groups)).installer_groups(groups, identity.groups)?,
        privileges: Self(self.0.role(R::Privileges)).installer_privileges(privileges, identity.privileges)? })
}

}
fn installer_groups(raw: &[u8], count: u32) -> Result<Vec<GroupFact>> { InstallerData(Refusal::none()).installer_groups(raw, count) }
#[allow(clippy::too_many_arguments)]
fn installer_facts(identity: TokenIdentity, token_type: u32, elevated: u32, elevation_type: u32,
    ui_access: u32, virtualization: u32, restricted: u32, app_container: u32,
    user: &[u8], integrity: &[u8], groups: &[u8], privileges: &[u8]) -> Result<Installer> {
    InstallerData(Refusal::none()).installer_facts(identity, token_type, elevated, elevation_type, ui_access,
        virtualization, restricted, app_container, user, integrity, groups, privileges)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage { Fresh, Manifest, Copying, Sealing, ExposureAttempted, RootClosed, Complete }
#[derive(Clone, Copy, Debug, Default)]
struct CopyProof { source_eof: bool, flushed: bool, writer_closed: bool, source_closed: bool, readback_eof: bool, readback_closed: bool }
impl CopyProof {
    fn complete(self) -> bool {
        self.source_eof && self.flushed && self.writer_closed && self.source_closed && self.readback_eof && self.readback_closed
    }
}
struct Order {
    stage: Stage, copies: usize, sealed_files: usize, inventories: bool, python_closed: bool,
    grant_attempted: bool, exposure: bool, failed: bool, unknown: bool,
}
impl Order {
    fn new() -> Self {
        Self { stage: Stage::Fresh, copies: 0, sealed_files: 0, inventories: false,
            python_closed: false, grant_attempted: false, exposure: false, failed: false, unknown: false }
    }
    fn live(&self, stage: Stage) -> Result<()> { need(!self.failed && !self.unknown && self.stage == stage) }
    fn copied(&mut self, index: usize, proof: CopyProof) -> Result<()> {
        self.live(Stage::Copying)?;
        need(index == self.copies && index < PUBLICATION_PAYLOADS.len() && proof.complete())?;
        self.copies += 1; Ok(())
    }
    fn seal(&mut self) -> Result<()> {
        self.live(Stage::Copying)?;
        need(self.copies == PUBLICATION_PAYLOADS.len() && self.inventories)?;
        self.stage = Stage::Sealing; Ok(())
    }
    fn expose(&mut self) -> Result<()> {
        self.live(Stage::Sealing)?;
        need(self.copies == PUBLICATION_PAYLOADS.len() && self.inventories
            && self.sealed_files == PUBLICATION_PAYLOADS.len() && self.python_closed)?;
        // BEFORE SetKernelObjectSecurity, never inferred from its return.
        self.exposure = true; self.stage = Stage::ExposureAttempted; Ok(())
    }
    fn fail(&mut self, unknown: bool) { self.failed = true; self.unknown |= unknown; }
    fn completed(&mut self, settled: bool) -> Result<()> {
        self.live(Stage::RootClosed)?; need(self.exposure && settled)?;
        self.stage = Stage::Complete; Ok(())
    }
}

#[derive(Clone, Copy)]
enum Effect { Directory(usize), Writer, Control(bool), Write, Flush, Seal, Scalar(S::TOKEN_INFORMATION_CLASS) }

// Normalize while copying retained Rust DATA. Neither this value nor its Debug
// representation carries a handle, raw scalar/count magnitude, path or native buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedReturn { label: &'static str, code: Option<u32> }
impl ObservedReturn {
    fn from_return(value: Option<Returned>) -> Self {
        let (label, code) = match value {
            None => ("none", None),
            Some(Returned::Scalar(_)) => ("scalar", None),
            Some(Returned::Boolean(value, error)) => (if value == 0 { "bool-zero" } else { "bool-nonzero" }, Some(error)),
            Some(Returned::Count(value, error)) => (if value == 0 { "count-zero" } else { "count-positive" }, Some(error)),
            Some(Returned::Nt(status)) => ("nt", Some(status as u32)),
            Some(Returned::Hresult(status)) => ("hr", Some(status as u32)),
        };
        Self { label, code }
    }
    fn append(self, line: &mut String) {
        line.push_str(self.label);
        if let Some(code) = self.code {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            line.push(':');
            for shift in (0..8).rev() { line.push(HEX[((code >> (shift * 4)) & 15) as usize] as char); }
        }
    }
}
/// Closed observation of the caller's exact-four invariant, not an OS fault.
/// Sentinel means equality to u32::MAX, not proof that output was unwritten.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedScalarLength { Unobserved, Sentinel, Zero, One, Two, Three, Four, OverFour }
impl ObservedScalarLength {
    fn from_count(count: u32) -> Self {
        match count {
            u32::MAX => Self::Sentinel, 0 => Self::Zero, 1 => Self::One,
            2 => Self::Two, 3 => Self::Three, 4 => Self::Four, _ => Self::OverFour,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Unobserved => "none", Self::Sentinel => "sentinel", Self::Zero => "zero",
            Self::One => "one", Self::Two => "two", Self::Three => "three",
            Self::Four => "four", Self::OverFour => "over4",
        }
    }
}
fn observed_query(call: Call) -> &'static str {
    match call {
        Call::Architecture => "architecture", Call::Folder => "folder",
        Call::WindowsDirectory => "windows-directory", Call::SystemDirectory => "system-directory",
        Call::Mapping => "mapping", Call::DriveType => "drive-type", Call::Open(_) => "nt-create",
        Call::ProcessToken(_) => "process-token", Call::ThreadToken(_) => "thread-token", Call::Close(_) => "close",
        #[cfg(test)]
        Call::QualificationSourceToken(_) => "qualification-source-token",
        #[cfg(test)]
        Call::QualificationRestrictedToken(_) => "qualification-filtered-token",
        Call::Info(class, _) => match class {
            FS::FileBasicInfo => "info-basic", FS::FileStandardInfo => "info-standard",
            FS::FileAttributeTagInfo => "info-tag", FS::FileIdInfo => "info-id",
            FS::FileCaseSensitiveInfo => "info-case", _ => "info-other",
        },
        Call::HandleInfo => "handle-info", Call::FinalName => "final-name", Call::FileType => "file-type",
        Call::VolumeName => "volume-name", Call::VolumeDevice => "volume-device", Call::Streams => "streams",
        Call::Security => "security", Call::Privilege(_) => "privilege", Call::Read(_) => "read", Call::Entries => "entries",
        Call::Token(class) => match class {
            S::TokenStatistics => "token-statistics", S::TokenType => "token-type",
            S::TokenElevation => "token-elevation", S::TokenElevationType => "token-elevation-type",
            S::TokenUIAccess => "token-ui-access", S::TokenVirtualizationEnabled => "token-virtualization",
            S::TokenUser => "token-user", S::TokenIntegrityLevel => "token-integrity",
            S::TokenGroups => "token-groups", S::TokenPrivileges => "token-privileges", _ => "token-other",
        },
    }
}
fn observed_mutation(effect: Effect) -> &'static str {
    match effect {
        Effect::Directory(_) => "directory", Effect::Writer => "writer",
        Effect::Control(false) => "control-file", Effect::Control(true) => "control-directory",
        Effect::Write => "write", Effect::Flush => "flush", Effect::Seal => "seal",
        Effect::Scalar(S::TokenHasRestrictions) => "has-restrictions",
        Effect::Scalar(S::TokenIsAppContainer) => "is-app-container", Effect::Scalar(_) => "scalar-other",
    }
}
fn observed_phase(phase: Phase) -> &'static str {
    match phase { Phase::Prepared => "prepared", Phase::Entered => "entered", Phase::Returned => "returned", Phase::Complete => "complete" }
}
fn observed_refusal(refusal: Option<CompletionRefusal>) -> &'static str {
    match refusal {
        None => "none", Some(CompletionRefusal::OpenInvalidHandle) => "open-invalid-handle",
        Some(CompletionRefusal::OpenIoStatus) => "open-iosb-status", Some(CompletionRefusal::OpenNotOpened) => "open-not-opened",
        Some(CompletionRefusal::OpenDuplicate) => "open-duplicate", Some(CompletionRefusal::TokenInvalidHandle) => "token-invalid-handle",
        Some(CompletionRefusal::TokenDuplicate) => "token-duplicate",
    }
}
/// Closed, copied first-failure DATA only. This is never ownership or finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationFrameObservation {
    qcall: &'static str, qphase: &'static str, qret: ObservedReturn, qrefusal: &'static str,
    mcall: &'static str, mphase: &'static str, mret: ObservedReturn, mcount: ObservedScalarLength,
}
impl PublicationFrameObservation {
    fn from_frames(query: Option<(Call, Phase, Option<Returned>, Option<CompletionRefusal>)>,
        mutation: Option<(Effect, Phase, Option<Returned>, ObservedScalarLength)>) -> Self {
        let (qcall, qphase, qret, qrefusal) = query.map_or(("none", "none", ObservedReturn::from_return(None), "none"),
            |(call, phase, returned, refusal)| (observed_query(call), observed_phase(phase), ObservedReturn::from_return(returned), observed_refusal(refusal)));
        let (mcall, mphase, mret, mcount) = mutation.map_or(("none", "none", ObservedReturn::from_return(None), ObservedScalarLength::Unobserved),
            |(effect, phase, returned, length)| (observed_mutation(effect), observed_phase(phase), ObservedReturn::from_return(returned), length));
        Self { qcall, qphase, qret, qrefusal, mcall, mphase, mret, mcount }
    }
    /// Bounded companion line; reads only this normalized copy, never an owner.
    pub fn diagnostic_line(self) -> Option<String> {
        let mut line = String::with_capacity(256);
        line.push_str("MRK_WINDOWS_RUNTIME_PUBLISH_FRAME_V2=qcall="); line.push_str(self.qcall);
        line.push_str(";qphase="); line.push_str(self.qphase); line.push_str(";qret="); self.qret.append(&mut line);
        line.push_str(";qrefusal="); line.push_str(self.qrefusal);
        line.push_str(";mcall="); line.push_str(self.mcall); line.push_str(";mphase="); line.push_str(self.mphase);
        line.push_str(";mret="); self.mret.append(&mut line);
        line.push_str(";mcount="); line.push_str(self.mcount.label()); line.push('\n');
        if line.len() <= 256 { Some(line) } else { None }
    }
}
struct Mutation {
    effect: Effect, phase: Cell<Phase>, returned: Cell<Option<Returned>>, slot: Option<usize>,
    length_observation: Cell<ObservedScalarLength>,
    path: Vec<u16>, descriptor: UnsafeCell<Aligned>, attributes: S::SECURITY_ATTRIBUTES,
    handle: F::HANDLE, output: *mut F::HANDLE, data: Vec<u8>, count: UnsafeCell<u32>, scalar: UnsafeCell<u32>,
    _pin: PhantomPinned,
}
struct MutationComplete { frame: Pin<Box<Mutation>> }
impl MutationComplete {
    fn scalar(&self) -> Result<u32> {
        need(self.frame.phase.get() == Phase::Complete
            && matches!(self.frame.effect, Effect::Scalar(S::TokenHasRestrictions | S::TokenIsAppContainer)))?;
        // SAFETY: definite completion ended native access to this pinned,
        // completely initialized DWORD object. An accepted needed-size of one
        // does NOT assert a one-byte ABI or four native-written output bytes.
        Ok(unsafe { *self.frame.scalar.get() })
    }
}
fn mutation_return(ok: i32, error: u32) -> Result<()> {
    if ok != 0 { return if error == 0 { Ok(()) } else { Err(Error::Unknown) }; }
    if error == 0 || error == F::ERROR_IO_PENDING { Err(Error::Unknown) } else { Err(Error::Unavailable) }
}
fn write_return(ok: i32, error: u32, written: u32, requested: usize) -> Result<()> {
    mutation_return(ok, error)?;
    if requested == 0 || requested > BUFFER || written as usize > requested { return Err(Error::Unknown); }
    need(written as usize == requested) // short/zero is failure, never a write-repair loop
}
fn scalar_initial(effect: Effect) -> u32 {
    if matches!(effect, Effect::Scalar(S::TokenHasRestrictions)) { u32::from_ne_bytes([0xff, 0, 0, 0]) }
    else { u32::MAX }
}
fn scalar_value(value: u32) -> Result<u32> { need(value <= 1)?; Ok(value) }
fn scalar_count_return(effect: Effect, count: u32, observed: &Cell<ObservedScalarLength>) -> Result<()> {
    if observed.get() == ObservedScalarLength::Unobserved {
        observed.set(ObservedScalarLength::from_count(count));
    }
    // The original count still decides admission; the first diagnostic never does.
    let accepted = match effect {
        Effect::Scalar(S::TokenHasRestrictions) => matches!(count, 1 | 4),
        Effect::Scalar(S::TokenIsAppContainer) => count == 4,
        _ => false,
    };
    if accepted { Ok(()) } else { Err(Error::Unknown) }
}
fn later_originals_closed(states: impl IntoIterator<Item = SlotState>) -> bool {
    let mut any = false;
    for state in states { any = true; if state != SlotState::Closed { return false; } }
    any // NoHandle, Unknown or no earlier original never authorizes adoption
}

struct Directory {
    role: R,
    initial: usize, control: Option<usize>, parent: Option<usize>, dos: String,
    scope: AuthorityScope, facts: Facts, entries: Option<Vec<DirectoryEntry>>, created: bool,
}
impl Directory { fn current(&self) -> usize { self.control.unwrap_or(self.initial) } }
struct Creation { path: String, parent: usize, entered: bool, returned: Option<(i32, u32)> }
// Set once, after BOTH shared ancestors are admitted, before the exact target-D
// CreateDirectoryW intent. Neither a generic failure nor a last component is a role.
struct TargetCreation { intent: usize, versions: usize, parent: usize, path: String }
#[derive(Clone, Copy, Eq, PartialEq)]
enum TransferStage { Copy, SourceEof, Readback, ReadbackEof }
struct Transfer {
    index: usize, stage: TransferStage, source: usize, writer: usize, readback: Option<usize>,
    source_facts: Facts, created: Facts, readback_facts: Option<Facts>, copied: u64, reread: u64, proof: CopyProof,
}
struct Copied {
    source: usize, writer: usize, readback: usize, source_facts: Facts, destination: Facts,
    proof: CopyProof, control: Option<usize>, sealed_closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyEdge {
    Order, SourceEof, Installer, Flush, WriterCheck, WriteTransition, WriterClose, SourceCheck,
    SourceUnchanged, SourceClose, ParentCheck, ReadbackReserve, ReadbackOpen, ReadbackNoninherited,
    ReadbackCheck, WriterCloseTransition,
}
impl CopyEdge {
    fn label(self) -> &'static str {
        match self {
            Self::Order => "order", Self::SourceEof => "source-eof", Self::Installer => "installer",
            Self::Flush => "flush", Self::WriterCheck => "writer-check", Self::WriteTransition => "write-transition",
            Self::WriterClose => "writer-close", Self::SourceCheck => "source-check", Self::SourceUnchanged => "source-unchanged",
            Self::SourceClose => "source-close", Self::ParentCheck => "parent-check", Self::ReadbackReserve => "readback-reserve",
            Self::ReadbackOpen => "readback-open", Self::ReadbackNoninherited => "readback-noninherited",
            Self::ReadbackCheck => "readback-check", Self::WriterCloseTransition => "writer-close-transition",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyMember { None, Identity, Kind, Attributes, Links, Creation, InitialSize, Size, Allocation, WriteTime, ChangeTime, Security }
impl CopyMember {
    fn label(self) -> &'static str {
        match self {
            Self::None => "none", Self::Identity => "identity", Self::Kind => "kind", Self::Attributes => "attributes",
            Self::Links => "links", Self::Creation => "creation", Self::InitialSize => "initial-size", Self::Size => "size",
            Self::Allocation => "allocation", Self::WriteTime => "write-time", Self::ChangeTime => "change-time", Self::Security => "security",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyAllocation { None, BelowSize, Shrank, Grew }
impl CopyAllocation {
    fn label(self) -> &'static str {
        match self { Self::None => "none", Self::BelowSize => "below-size", Self::Shrank => "shrank", Self::Grew => "grew" }
    }
}
/// Closed first-Unsafe finish-copy DATA; no handle, raw size or native output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationCopyObservation { edge: CopyEdge, member: CopyMember, allocation: CopyAllocation }
impl PublicationCopyObservation {
    fn legal(self) -> bool {
        use CopyEdge as E; use CopyMember as M; use CopyAllocation as A;
        match (self.edge, self.member, self.allocation) {
            (E::WriteTransition, M::Allocation, A::BelowSize)
            | (E::SourceUnchanged | E::WriterCloseTransition, M::Allocation, A::BelowSize | A::Shrank | A::Grew)
            | (E::WriteTransition, M::Identity | M::Kind | M::Attributes | M::Links | M::Creation | M::InitialSize
                | M::Size | M::WriteTime | M::ChangeTime | M::Security, A::None)
            | (E::SourceUnchanged | E::WriterCloseTransition, M::Identity | M::Kind | M::Attributes | M::Links | M::Creation
                | M::Size | M::WriteTime | M::ChangeTime | M::Security, A::None)
            | (E::Order | E::SourceEof | E::Installer | E::Flush | E::WriterCheck | E::WriterClose | E::SourceCheck
                | E::SourceClose | E::ParentCheck | E::ReadbackReserve | E::ReadbackOpen | E::ReadbackNoninherited
                | E::ReadbackCheck, M::None, A::None) => true,
            _ => false,
        }
    }
    pub fn diagnostic_line(self) -> Option<String> {
        if !self.legal() { return None; }
        let mut line = String::with_capacity(128);
        line.push_str("MRK_WINDOWS_RUNTIME_PUBLISH_COPY_V1=edge="); line.push_str(self.edge.label());
        line.push_str(";member="); line.push_str(self.member.label());
        line.push_str(";allocation="); line.push_str(self.allocation.label()); line.push('\n');
        if line.len() <= 256 { Some(line) } else { None }
    }
}
#[derive(Clone, Copy)]
struct CopyRefusal<'a> { first: &'a Cell<Option<PublicationCopyObservation>>, edge: CopyEdge }
impl CopyRefusal<'_> {
    fn record(self, member: CopyMember, allocation: impl FnOnce() -> CopyAllocation) {
        if self.first.get().is_none() {
            self.first.set(Some(PublicationCopyObservation { edge: self.edge, member, allocation: allocation() }));
        }
    }
}
// Receive each already-evaluated Result once; nested refusals are edge-only.
fn copy_result<T>(result: Result<T>, first: &Cell<Option<PublicationCopyObservation>>, edge: CopyEdge) -> Result<T> {
    if matches!(result.as_ref(), Err(Error::Unsafe)) {
        CopyRefusal { first, edge }.record(CopyMember::None, || CopyAllocation::None);
    }
    result
}
fn copy_guard(value: bool, member: CopyMember, trace: Option<CopyRefusal<'_>>) -> bool {
    if !value { if let Some(trace) = trace { trace.record(member, || CopyAllocation::None); } }
    value
}
fn copy_allocation_guard(value: bool, trace: Option<CopyRefusal<'_>>, allocation: impl FnOnce() -> CopyAllocation) -> bool {
    if !value { if let Some(trace) = trace { trace.record(CopyMember::Allocation, allocation); } }
    value
}
fn changed_allocation(new: u64, old: u64, size: u64) -> CopyAllocation {
    // Called only after unequal allocations, from cached operands of the reached
    // original comparisons. Equal/passed/earlier refusals never classify here.
    if new < size { CopyAllocation::BelowSize } else if new < old { CopyAllocation::Shrank } else { CopyAllocation::Grew }
}

/// The actual non-cloneable owner. Register it before invoking a native method;
/// retain it after panic/poison/Unknown. Its Drop is NOT a settlement mechanism.
pub struct Publication {
    book: NativeBook, mutation: Option<Held<Mutation>>, end: Instant, expired: bool, order: Order,
    digest: String, installer: Option<Installer>, location: Option<KnownLocation>,
    directories: Vec<Directory>, creations: Vec<Creation>, target_creation: Option<TargetCreation>, source_dirs: Vec<usize>,
    source_root: Option<usize>, source_python: Option<usize>, mrk: Option<usize>,
    output_dirs: Vec<usize>, version: Option<usize>, python: Option<usize>,
    manifest: Vec<u8>, manifest_original: Option<usize>, manifest_facts: Option<Facts>,
    sizes: Option<[u64; 47]>, transfer: Option<Transfer>, copied: Vec<Copied>, settlement_attempted: bool,
    copy_failure: Cell<Option<PublicationCopyObservation>>,
}
// SAFETY: only the serialized owner moves. All native arguments/output cells
// are in pinned allocations, and no borrowed handle or UnsafeCell escapes. Like
// NativeBook this is NOT Sync. The executable never moves work between threads;
// admission is nevertheless reobserved on the actual calling thread each time.
unsafe impl Send for Publication {}

impl Publication {
    /// Only copied first-refusal DATA, before failure settlement changes any owner.
    pub fn retained_admission_observation(&self) -> Option<PublicationAdmissionObservation> { self.book.admission.first.get() }
    /// Copy the first finish-copy refusal only; never query frames, outputs or time.
    pub fn retained_copy_observation(&self) -> Option<PublicationCopyObservation> { self.copy_failure.get() }
    fn with_role<T>(&mut self, role: R, body: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let before = self.book.admission.role.replace(role);
        let result = body(self);
        self.book.admission.role.set(before);
        result
    }
    /// Call only for the first Admit/Unknown result, before settlement can
    /// change frames. Copy no UnsafeCell/native output, handle, clock or input.
    pub fn retained_frame_observation(&self) -> PublicationFrameObservation {
        let query = self.book.active.as_ref().map(|held| {
            let frame = held.as_ref().get_ref();
            (frame.call, frame.phase.get(), frame.returned.get(), frame.completion_refusal.get())
        });
        let mutation = self.mutation.as_ref().map(|held| {
            let frame = held.as_ref().get_ref();
            (frame.effect, frame.phase.get(), frame.returned.get(), frame.length_observation.get())
        });
        PublicationFrameObservation::from_frames(query, mutation)
    }
    /// No native effect. D must already be the safe app's compiled manifest hash.
    pub fn new(digest: &str) -> Result<Self> {
        need(digest_name(digest))?;
        let end = Instant::now().checked_add(OPERATION).ok_or(Error::Bounds)?;
        Ok(Self { book: NativeBook::new(), mutation: None, end, expired: false, order: Order::new(),
            digest: digest.to_owned(), installer: None, location: None, directories: Vec::new(), creations: Vec::new(), target_creation: None,
            source_dirs: Vec::new(), source_root: None, source_python: None, mrk: None,
            output_dirs: Vec::new(), version: None, python: None,
            manifest: Vec::new(), manifest_original: None, manifest_facts: None,
            sizes: None, transfer: None, copied: Vec::new(), settlement_attempted: false, copy_failure: Cell::new(None) })
    }
    fn tick(&mut self) -> Result<()> {
        self.expired |= Instant::now() >= self.end;
        if self.expired { Err(Error::Bounds) } else { Ok(()) }
    }
    fn ready(&mut self) -> Result<()> {
        if self.order.unknown || self.book.is_unknown() || self.mutation.is_some() { return Err(Error::Unknown); }
        if self.order.failed || self.settlement_attempted { return Err(Error::State); }
        self.book.clear()?; self.tick()
    }
    fn step<T>(&mut self, body: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = self.ready().and_then(|_| body(self)).and_then(|value| { self.tick()?; Ok(value) });
        if let Err(error) = result.as_ref() {
            self.order.fail(*error == Error::Unknown || self.book.is_unknown() || self.mutation.is_some());
        }
        result
    }
    fn key(&self, index: usize) -> Original { Original { book: Arc::clone(&self.book.identity), index } }
    fn closed(&self, index: usize) -> bool { self.book.slot(index).is_ok_and(|s| s.state == SlotState::Closed) }
    fn close(&mut self, index: usize) -> Result<()> {
        // Expiry does not cancel an original close. Active mutation storage DOES
        // forbid it, even when NativeBook's independent query arena is empty.
        if self.mutation.is_some() { return Err(Error::Unknown); }
        self.book.close_index(index)
    }
    fn checked(&mut self, index: usize, scope: AuthorityScope) -> Result<Facts> {
        self.ready()?; let key = self.key(index);
        self.book.noninherited(index)?;
        let metadata = self.book.metadata(&key)?;
        let trace = self.book.admission.at(O::Metadata);
        trace.need(metadata.identity.volume_serial != 0, C::VolumeSerial)?;
        trace.need(metadata.links == 1, C::Links)?;
        trace.need(metadata.creation > 0, C::CreationTime)?;
        trace.need(metadata.write > 0, C::WriteTime)?;
        trace.need(metadata.change > 0, C::ChangeTime)?;
        self.book.no_alternate_streams(&key)?;
        let security = self.book.security(&key, scope)?;
        let after = self.book.metadata(&key)?;
        self.book.admission.at(O::Metadata).need(after == metadata, C::MetadataChanged)?; self.tick()?;
        Ok(Facts { metadata, security })
    }
    fn recheck_dir(&mut self, index: usize) -> Result<()> {
        let dir = self.directories.get(index).ok_or(Error::State)?;
        let (slot, scope, before, role) = (dir.current(), dir.scope, dir.facts.clone(), dir.role);
        self.with_role(role, |this| {
            let after = this.checked(slot, scope)?;
            this.book.admission.at(O::Metadata).need(after == before, C::DirectoryChanged)
        })
    }
    fn after_child(&mut self, parent: usize) -> Result<()> {
        let dir = self.directories.get(parent).ok_or(Error::State)?;
        let (slot, scope, before) = (dir.current(), dir.scope, dir.facts.clone());
        let after = self.checked(slot, scope)?;
        need(child_transition(&before.metadata, &after.metadata) && before.security == after.security)?;
        self.directories[parent].facts = after; Ok(())
    }
    fn unique_identity(&self, metadata: &Metadata) -> Result<()> {
        let trace = self.book.admission.at(O::Identity);
        if let Some(root) = self.directories.first() { trace.need(root.facts.metadata.identity.volume_serial == metadata.identity.volume_serial, C::VolumeChanged)?; }
        trace.need(!self.directories.iter().any(|d| d.facts.metadata.identity == metadata.identity)
            && !self.copied.iter().any(|c| c.source_facts.metadata.identity == metadata.identity || c.destination.metadata.identity == metadata.identity), C::IdentityAlias)
    }
    fn collect_installer(&mut self, index: usize) -> Result<Installer> {
        self.ready()?;
        self.book.admission.role.set(R::ThreadBefore); self.book.absent_thread_token()?;
        self.book.admission.role.set(R::StatisticsBefore);
        let before = self.book.token(index, S::TokenStatistics)?;
        let trace = self.book.admission.at(O::TokenData);
        let initial = security::Observed::new(trace).statistics(before.bytes_in(before.count_in(trace)?, trace)?)?;
        let mut scalar = |class, role| -> Result<u32> {
            self.book.admission.role.set(role);
            let value = self.book.token(index, class)?;
            let trace = self.book.admission.at(O::TokenData);
            trace.need(value.count_in(trace)? == 4, C::ScalarWidth)?;
            decode::Observed::new(trace).u32_at(value.bytes_in(4, trace)?, 0)
        };
        let token_type = scalar(S::TokenType, R::TokenType)?;
        let elevated = scalar(S::TokenElevation, R::Elevation)?;
        let elevation_type = scalar(S::TokenElevationType, R::ElevationType)?;
        let ui_access = scalar(S::TokenUIAccess, R::UiAccess)?;
        let virtualization = scalar(S::TokenVirtualizationEnabled, R::Virtualization)?;
        self.book.admission.role.set(R::Restrictions);
        let restricted = self.scalar(index, S::TokenHasRestrictions)?;
        self.book.admission.role.set(R::AppContainer);
        let app_container = self.scalar(index, S::TokenIsAppContainer)?;
        self.book.admission.role.set(R::User);
        let user = self.book.token(index, S::TokenUser)?;
        self.book.admission.role.set(R::Integrity);
        let integrity = self.book.token(index, S::TokenIntegrityLevel)?;
        self.book.admission.role.set(R::Groups);
        let groups = self.book.token(index, S::TokenGroups)?;
        self.book.admission.role.set(R::Privileges);
        let privileges = self.book.token(index, S::TokenPrivileges)?;
        let trace = self.book.admission.at(O::InstallerPolicy).role(R::Installer);
        let token_data = self.book.admission.at(O::TokenData);
        let u = token_data.role(R::User); let i = token_data.role(R::Integrity);
        let g = token_data.role(R::Groups); let p = token_data.role(R::Privileges);
        let facts = InstallerData(trace).installer_facts(initial, token_type, elevated, elevation_type, ui_access, virtualization,
            restricted, app_container, user.bytes_in(user.count_in(u)?, u)?, integrity.bytes_in(integrity.count_in(i)?, i)?,
            groups.bytes_in(groups.count_in(g)?, g)?, privileges.bytes_in(privileges.count_in(p)?, p)?)?;
        self.book.admission.role.set(R::StatisticsAfter);
        let after = self.book.token(index, S::TokenStatistics)?;
        let trace = self.book.admission.at(O::TokenData);
        trace.need(security::Observed::new(trace).statistics(after.bytes_in(after.count_in(trace)?, trace)?)? == initial, C::StatisticsChanged)?;
        self.book.admission.role.set(R::ThreadAfter); self.book.absent_thread_token()?;
        self.tick()?; Ok(facts)
    }
    fn open_process_token(&mut self) -> Result<usize> {
        self.book.admission.role.set(R::Primary);
        let key = self.book.reserve(Kind::ProcessToken, None, "", String::new())?;
        let result = self.book.call(Call::ProcessToken(key.index), null_mut(), Vec::new())?;
        self.book.admission.at(O::TokenOpen).need(matches!(result.arena.returned()?, Returned::Boolean(v, 0) if v != 0), C::PrimaryOpen)?;
        self.book.noninherited(key.index)?; Ok(key.index)
    }
    fn admit_installer(&mut self) -> Result<()> {
        self.book.admission.role.set(R::Installer);
        self.book.admission.at(O::Owner).need(self.installer.is_none() && self.book.user.is_none() && self.book.process_token.is_none(), C::InstallerFresh)?;
        let arch = self.book.call(Call::Architecture, null_mut(), Vec::new())?;
        let trace = self.book.admission.at(O::Architecture);
        let d = decode::Observed::new(trace);
        trace.need(d.u16_at(arch.bytes_in(4, trace)?, 0)? == SI::IMAGE_FILE_MACHINE_UNKNOWN, C::ArchitectureProcess)?;
        trace.need(d.u16_at(arch.bytes_in(4, trace)?, 2)? == SI::IMAGE_FILE_MACHINE_AMD64, C::ArchitectureNative)?;
        let index = self.open_process_token()?;
        self.book.process_token = Some(index);
        self.installer = Some(self.collect_installer(index)?); Ok(())
    }
    fn recheck_installer(&mut self) -> Result<()> {
        self.ready()?;
        let initial = self.installer.clone().ok_or(Error::State)?;
        let original = self.book.process_token.ok_or(Error::State)?;
        need(self.collect_installer(original)? == initial)?;
        // A new bounded *observation* of the CURRENT primary token detects token
        // replacement. It is not a replacement for the retained original token.
        let current = self.open_process_token()?;
        need(self.collect_installer(current)? == initial)?;
        self.close(current)?; self.book.absent_thread_token()?; self.tick()
    }
    fn recheck_location(&mut self) -> Result<()> {
        self.ready()?;
        let location = self.location.as_ref().ok_or(Error::State)?;
        self.book.recheck_location(location)?; self.tick()
    }

    // NativeBook's ordinary reserve() retains its one-path-ever rule unchanged.
    // ONLY these fixed readback/control roles can reserve a distinct original,
    // after EVERY earlier same-path original is positively Closed (not NoHandle).
    fn reserve_later(&mut self, parent: usize, name: &str, kind: FileKind, previous: usize) -> Result<usize> {
        self.ready()?; need(decode::component(name))?;
        let parent_slot = self.directories.get(parent).ok_or(Error::State)?.current();
        self.book.handle(parent_slot)?;
        let parent_name = &self.book.slot(parent_slot)?.canonical;
        let canonical = format!("{}{}{}", parent_name, if parent_name.ends_with('\\') { "" } else { "\\" }, name);
        need(self.book.slot(previous)?.canonical == canonical && self.book.slot(previous)?.kind == kind.into()
            && self.closed(previous) && later_originals_closed(self.book.slots.iter()
                .filter(|s| s.canonical == canonical).map(|s| s.state)))?;
        let live = self.book.slots.iter().filter(|s| !matches!(s.state, SlotState::NoHandle | SlotState::Closed)).count();
        if self.book.slots.len() >= MAX_RECORDS || live >= MAX_LIVE
            || kind == FileKind::File && self.book.slots.iter().filter(|s| s.kind == Kind::File).count() >= MAX_FILES
            || canonical.encode_utf16().count() >= NAME_UNITS { return Err(Error::Bounds); }
        self.book.slots.try_reserve(1).map_err(|_| Error::Bounds)?;
        let index = self.book.slots.len();
        self.book.slots.push(ManuallyDrop::new(Box::pin(Slot { output: UnsafeCell::new(null_mut()),
            state: SlotState::Reserved, kind: kind.into(), parent: Some(parent_slot), name: wide(name), canonical,
            read_bytes: 0, read_ended: false, directory_ended: false, directory_mode: DirectoryMode::Unstarted, _pin: PhantomPinned })));
        Ok(index)
    }
    fn mutate(&mut self, effect: Effect, slot: Option<usize>, dos: &str, raw: &[u8], data: Vec<u8>) -> Result<MutationComplete> {
        self.ready()?;
        self.book.admission.at(O::MutationInput).need(data.len() <= BUFFER, C::MutationData)?;
        self.book.admission.at(O::MutationInput).need(raw.len() <= BUFFER, C::MutationDescriptor)?;
        let acquiring = matches!(effect, Effect::Writer | Effect::Control(_));
        let handle = if acquiring || matches!(effect, Effect::Directory(_)) { null_mut() }
            else { self.book.handle(slot.ok_or(Error::State)?)? };
        let path = if matches!(effect, Effect::Directory(_) | Effect::Writer | Effect::Control(_)) {
            // DOS input is derived solely from the retained OS location + literal
            // components. All intermediate parents are held, canonical and safe.
            need(!dos.starts_with("\\") && !dos.contains('\0') && dos.encode_utf16().count() < NAME_UNITS)?;
            wide(&format!("\\\\?\\{dos}"))
        } else { Vec::new() };
        let mut frame = Box::pin(Mutation { effect, phase: Cell::new(Phase::Prepared), returned: Cell::new(None), slot,
            length_observation: Cell::new(ObservedScalarLength::Unobserved),
            path, descriptor: UnsafeCell::new(Aligned([0; BUFFER])), attributes: S::SECURITY_ATTRIBUTES::default(),
            handle, output: null_mut(), data, count: UnsafeCell::new(u32::MAX), scalar: UnsafeCell::new(scalar_initial(effect)), _pin: PhantomPinned });
        // SAFETY: pinned, exclusively held, not yet entered. Register all pointers
        // and original output cells before publishing the mutation arena.
        let setup = unsafe { frame.as_mut().get_unchecked_mut() };
        if !raw.is_empty() {
            let buffer = unsafe { &mut *setup.descriptor.get() };
            buffer.0[..raw.len()].copy_from_slice(raw);
            setup.attributes.lpSecurityDescriptor = setup.descriptor.get().cast();
        }
        setup.attributes.nLength = size_of::<S::SECURITY_ATTRIBUTES>() as u32;
        setup.attributes.bInheritHandle = 0;
        if acquiring {
            let original = self.book.slot(slot.ok_or(Error::State)?)?;
            need(original.state == SlotState::Reserved)?; setup.output = original.output.get();
        }
        self.mutation = Some(ManuallyDrop::new(frame));
        if acquiring { self.book.slot_mut(slot.ok_or(Error::State)?)?.state = SlotState::Acquiring; }
        if let Effect::Directory(i) = effect { self.creations.get_mut(i).ok_or(Error::State)?.entered = true; }
        self.book.started = true;
        let frame = self.mutation.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        frame.phase.set(Phase::Entered);
        // SAFETY: no overlapping call, callback or async mode. Every native
        // pointer is pinned and already owned. The first operation after return
        // records the actual scalar (and immediate same-thread GetLastError).
        let returned = unsafe { invoke_mutation(frame) };
        frame.returned.set(Some(returned)); frame.phase.set(Phase::Returned);
        self.finish_mutation()
    }
    fn mutation_unknown<T>(&mut self) -> Result<T> {
        self.book.mark_interrupted(); self.order.fail(true); Err(Error::Unknown)
    }
    fn finish_mutation(&mut self) -> Result<MutationComplete> {
        let frame = self.mutation.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        if frame.phase.get() != Phase::Returned { return self.mutation_unknown(); }
        let (ok, error) = match frame.returned.get() { Some(Returned::Boolean(v, e)) => (v, e), _ => return self.mutation_unknown() };
        let (effect, slot) = (frame.effect, frame.slot);
        if let Effect::Directory(i) = effect { self.creations[i].returned = Some((ok, error)); }
        let outcome = mutation_return(ok, error);
        if outcome == Err(Error::Unknown) { return self.mutation_unknown(); }
        if matches!(effect, Effect::Writer | Effect::Control(_)) {
            let index = slot.ok_or(Error::Unknown)?;
            if self.book.slot(index)?.state != SlotState::Acquiring { return self.mutation_unknown(); }
            // SAFETY: only definite synchronous nonpending completion reaches the
            // registered output. NULL contradicts CreateFileW's failure sentinel.
            let handle = unsafe { *self.book.slot(index)?.output.get() };
            if ok == 0 {
                if handle != F::INVALID_HANDLE_VALUE { return self.mutation_unknown(); }
                self.book.slot_mut(index)?.state = SlotState::NoHandle;
            } else {
                if !valid_handle(handle) || self.book.duplicate_live(index, handle) { return self.mutation_unknown(); }
                self.book.slot_mut(index)?.state = SlotState::Owned;
            }
        }
        let frame = self.mutation.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        let outcome = if matches!(effect, Effect::Write) && outcome.is_ok() {
            // SAFETY: known completion, not a failed or pending output count.
            write_return(ok, error, unsafe { *frame.count.get() }, frame.data.len())
        } else if matches!(effect, Effect::Scalar(_)) && outcome.is_ok() {
            // SAME authorized read; class-local needed-size compatibility never
            // derives a write extent or authorizes another output observation.
            let count = unsafe { *frame.count.get() };
            scalar_count_return(effect, count, &frame.length_observation)
        } else { outcome };
        if outcome == Err(Error::Unknown) { return self.mutation_unknown(); }
        frame.phase.set(Phase::Complete);
        let held = self.mutation.take().ok_or(Error::Unknown)?;
        let complete = MutationComplete { frame: ManuallyDrop::into_inner(held) };
        outcome?; self.tick()?; Ok(complete)
    }
    fn scalar(&mut self, index: usize, class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
        self.book.admission.at(O::Scalar).need([S::TokenHasRestrictions, S::TokenIsAppContainer].contains(&class), C::ScalarCompletion)?;
        let complete = self.mutate(Effect::Scalar(class), Some(index), "", &[], Vec::new())?;
        let trace = self.book.admission.at(O::Scalar);
        trace.result(scalar_value(trace.result(complete.scalar(), C::ScalarCompletion)?), C::ScalarCanonical)
    }

    fn add_directory(&mut self, slot: usize, parent: Option<usize>, dos: String, scope: AuthorityScope, created: bool, role: R) -> Result<usize> {
        self.with_role(role, |this| {
        let facts = this.checked(slot, scope)?; this.unique_identity(&facts.metadata)?;
        if created { exact_security(&facts.security, FileKind::Directory, false, false)?; }
        let index = this.directories.len();
        this.directories.push(Directory { role, initial: slot, control: None, parent, dos, scope, facts, entries: None, created });
        Ok(index)
        })
    }
    fn entries(&mut self, index: usize, selected: Option<&str>) -> Result<Vec<DirectoryEntry>> {
        let role = self.directories.get(index).ok_or(Error::State)?.role;
        self.with_role(role, |this| {
        if let Some(entries) = &this.directories.get(index).ok_or(Error::State)?.entries { return Ok(entries.clone()); }
        this.recheck_dir(index)?;
        let slot = this.directories[index].current(); let key = this.key(slot);
        let mut entries = Vec::new();
        loop {
            this.ready()?;
            let batch = match selected { Some(name) => this.book.next_ancestor_entries(&key, name)?, None => this.book.next_entries(&key)? };
            this.tick()?;
            match batch { Some(batch) => entries.extend(batch), None => break }
        }
        let own = &this.directories[index].facts.metadata;
        let parent = this.directories[index].parent.map(|i| &this.directories[i].facts.metadata);
        check_entry_frame_in(&entries, own, parent, this.book.admission.at(O::Directory))?;
        this.recheck_dir(index)?;
        this.directories[index].entries = Some(entries.clone()); Ok(entries)
        })
    }
    fn selected(&mut self, parent: usize, name: &str) -> Result<Option<DirectoryEntry>> {
        let entries = self.entries(parent, Some(name))?;
        selected_entry_in(&entries, name, self.book.admission.at(O::Directory))
    }
    fn child_path(&self, parent: usize, name: &str) -> Result<String> {
        self.book.admission.at(O::Directory).need(decode::component(name), C::Component)?;
        let path = &self.directories.get(parent).ok_or(Error::State)?.dos;
        Ok(format!("{}{}{}", path, if path.ends_with('\\') { "" } else { "\\" }, name))
    }
    fn existing_dir(&mut self, parent: usize, name: &str, scope: AuthorityScope, role: R) -> Result<usize> {
        self.with_role(role, |this| {
        let entry = this.selected(parent, name)?.ok_or(Error::Unavailable)?;
        this.book.admission.at(O::Directory).need(entry.kind == FileKind::Directory, C::DirectoryKind)?; this.recheck_dir(parent)?;
        let parent_key = this.key(this.directories[parent].current());
        let key = this.book.open_child(&parent_key, name, FileKind::Directory)?;
        let path = this.child_path(parent, name)?;
        let index = this.add_directory(key.index, Some(parent), path, scope, false, role)?;
        match_entry_in(&entry, &this.directories[index].facts.metadata, this.book.admission.at(O::Directory))?; this.recheck_dir(parent)?; Ok(index)
        })
    }
    fn new_dir(&mut self, parent: usize, name: &str) -> Result<usize> {
        self.recheck_installer()?; self.recheck_location()?; self.recheck_dir(parent)?;
        let path = self.child_path(parent, name)?;
        // Exclusive creation result is NOT a directory handle. Retain its exact
        // intent before entry; only a separate subsequent open gets an original.
        let intent = self.creations.len();
        need(intent < 4 && !self.creations.iter().any(|c| c.path == path))?;
        self.creations.push(Creation { path: path.clone(), parent, entered: false, returned: None });
        let raw = descriptor(FileKind::Directory, false, false)?;
        self.mutate(Effect::Directory(intent), None, &path, &raw, Vec::new())?;
        need(self.creations[intent].parent == parent && self.creations[intent].entered
            && self.creations[intent].returned.is_some_and(|(ok, error)| ok != 0 && error == 0))?;
        let parent_key = self.key(self.directories[parent].current());
        let original = self.book.open_child(&parent_key, name, FileKind::Directory)?;
        let index = self.add_directory(original.index, Some(parent), path, AuthorityScope::ImmutableVersion, true, R::Owner)?;
        self.after_child(parent)?; self.output_dirs.push(index); Ok(index)
    }
    fn shared_dir(&mut self, parent: usize, name: &str) -> Result<usize> {
        if self.selected(parent, name)?.is_some() { self.existing_dir(parent, name, AuthorityScope::AncestorOutsideVersion, R::Owner) }
        else { self.new_dir(parent, name) } // collision during creation is terminal, never adoption
    }
    fn open_source(&mut self, index: usize) -> Result<(usize, Facts)> {
        self.with_role(if index == MANIFEST { R::Manifest } else { R::Owner }, |this| {
        let (parent, name) = this.payload_parent(index, true)?;
        let entries = this.directories[parent].entries.as_ref().ok_or(Error::State)?;
        let entry = selected_entry_in(entries, name, this.book.admission.at(O::Directory))?.ok_or_else(|| this.book.admission.at(O::Directory).unsafe_at(C::SourceEntry))?;
        this.book.admission.at(O::Directory).need(entry.kind == FileKind::File, C::SourceKind)?; this.recheck_dir(parent)?;
        let parent_key = this.key(this.directories[parent].current());
        let key = this.book.open_child(&parent_key, name, FileKind::File)?;
        let facts = this.checked(key.index, AuthorityScope::ImmutableVersion)?;
        match_entry_in(&entry, &facts.metadata, this.book.admission.at(O::Directory))?; this.unique_identity(&facts.metadata)?;
        this.recheck_dir(parent)?; Ok((key.index, facts))
        })
    }
    fn payload_parent(&self, index: usize, source: bool) -> Result<(usize, &'static str)> {
        let path = *PUBLICATION_PAYLOADS.get(index).ok_or(Error::State)?;
        let (directory, name) = if let Some(name) = path.strip_prefix("python/") {
            (if source { self.source_python } else { self.python }, name)
        } else { (if source { self.source_root } else { self.version }, path) };
        Ok((directory.ok_or(Error::State)?, name))
    }

    /// Read the ONE bounded original manifest to genuine EOF. Caller must decode
    /// these same cached bytes against compiled D/Q before create_once.
    pub fn admit_once(&mut self) -> Result<Vec<u8>> {
        // Diagnostic-only scope. Never reset a first refusal, including reentry.
        self.book.admission.active.set(true); self.book.admission.role.set(R::Owner);
        let result = self.step(|this| {
            this.book.admission.at(O::Owner).result(this.order.live(Stage::Fresh), C::OrderFresh)?;
            this.admit_installer()?;
            this.book.admission.role.set(R::ProgramFiles);
            let location = this.book.location(LocationKind::ProgramFiles)?;
            let trace = this.book.admission.at(O::Location);
            trace.need(Arc::ptr_eq(&this.book.identity, &location.book), C::LocationOwner)?;
            trace.need(this.book.user.is_none(), C::LocationOrdinaryUser)?;
            trace.need(!this.book.roots_started, C::LocationStarted)?;
            {
                let mapped = this.book.mapping(&location.drive)?;
                this.book.admission.at(O::Mapping).need(mapped == location.device, C::MappingChanged)?;
            }
            let name = format!("{}\\", location.device);
            let key = this.book.reserve(Kind::Directory, None, &name, name.clone())?;
            this.book.admission.role.set(R::Volume);
            this.book.call(Call::Open(key.index), null_mut(), Vec::new())?;
            this.book.noninherited(key.index)?; this.book.local_ntfs(&key)?;
            let components = location.components.clone();
            let root_dos = format!("{}\\", location.drive);
            this.location = Some(location); this.book.roots_started = true;
            let mut parent = this.add_directory(key.index, None, root_dos, AuthorityScope::AncestorOutsideVersion, false, R::Volume)?;
            for component in components { parent = this.existing_dir(parent, &component, AuthorityScope::AncestorOutsideVersion, R::ProgramFiles)?; }
            this.book.admission.role.set(R::ProgramFiles); this.recheck_location()?;
            let mrk = this.existing_dir(parent, "Mobile Release Kit", AuthorityScope::AncestorOutsideVersion, R::Mrk)?;
            this.mrk = Some(mrk);
            let input = this.existing_dir(mrk, "runtime-input", AuthorityScope::AncestorOutsideVersion, R::RuntimeInput)?;
            let target = this.existing_dir(input, TARGET, AuthorityScope::AncestorOutsideVersion, R::Target)?;
            let digest = this.digest.clone();
            let root = this.existing_dir(target, &digest, AuthorityScope::ImmutableVersion, R::Version)?;
            this.source_root = Some(root);
            // Strict root/python cursors are each bound exactly once, through EOF.
            let root_entries = this.entries(root, None)?;
            exact_names_in(&root_entries, false, this.book.admission.at(O::Inventory).role(R::Version))?;
            let python = this.existing_dir(root, "python", AuthorityScope::ImmutableVersion, R::Python)?;
            this.source_python = Some(python);
            {
                let python_entries = this.entries(python, None)?;
                exact_names_in(&python_entries, true, this.book.admission.at(O::Inventory).role(R::Python))?;
            }
            this.source_dirs = vec![input, target, root, python];
            let (manifest, facts) = this.open_source(MANIFEST)?;
            this.book.admission.role.set(R::Manifest);
            this.book.admission.at(O::Read).need(facts.metadata.size > 0 && facts.metadata.size <= MANIFEST_LIMIT as u64, C::ManifestSize)?;
            this.manifest_original = Some(manifest); this.manifest_facts = Some(facts.clone());
            loop {
                this.ready()?;
                let chunk = this.book.read_next(&this.key(manifest), BUFFER)?; this.tick()?;
                if chunk.is_empty() { break; }
                let size = this.manifest.len().checked_add(chunk.len()).ok_or(Error::Bounds)?;
                this.book.admission.at(O::Read).need(size <= MANIFEST_LIMIT, C::ManifestLimit)?;
                this.book.admission.at(O::Read).need(size as u64 <= facts.metadata.size, C::ManifestReportedSize)?;
                this.manifest.extend(chunk);
            }
            // Keep original short-circuit: no final native query after size refusal.
            this.book.admission.at(O::FinalManifest).need(this.manifest.len() as u64 == facts.metadata.size, C::ManifestFinalSize)?;
            let after = this.checked(manifest, AuthorityScope::ImmutableVersion)?;
            this.book.admission.at(O::FinalManifest).need(after == facts, C::ManifestFinalFacts)?;
            this.order.stage = Stage::Manifest; Ok(this.manifest.clone())
        });
        self.book.admission.active.set(false);
        result
    }
    /// The safe app has authenticated D/Q, all37 suppliers and this exact roster.
    /// Sizes count BOTH source and readback under the original aggregate budget.
    pub fn create_once(&mut self, sizes: [u64; 47]) -> Result<()> {
        self.step(|this| {
            this.order.live(Stage::Manifest)?;
            need(sizes[MANIFEST] == this.manifest.len() as u64 && sizes.iter().all(|n| *n <= MAX_FILE_BYTES))?;
            let total = sizes.iter().try_fold(0u64, |sum, n| sum.checked_add(*n).ok_or(Error::Bounds))?;
            need(total.checked_mul(2).is_some_and(|n| n <= MAX_TOTAL_BYTES))?;
            this.sizes = Some(sizes); this.recheck_installer()?; this.recheck_location()?;
            let mrk = this.mrk.ok_or(Error::State)?;
            let versions = this.shared_dir(mrk, "versions")?;
            let target = this.shared_dir(versions, TARGET)?;
            let digest = this.digest.clone();
            need(this.target_creation.is_none())?;
            this.target_creation = Some(TargetCreation { intent: this.creations.len(), versions,
                parent: target, path: this.child_path(target, &digest)? });
            // Never inspect/adopt an occupied D, including byte-identical D.
            let version = this.new_dir(target, &digest)?; this.version = Some(version);
            let python = this.new_dir(version, "python")?; this.python = Some(python);
            this.order.stage = Stage::Copying; Ok(())
        })
    }
    pub fn start_copy(&mut self, index: usize) -> Result<()> {
        self.step(|this| {
            this.order.live(Stage::Copying)?; need(this.transfer.is_none() && index == this.order.copies && index < 47)?;
            let size = this.sizes.as_ref().ok_or(Error::State)?[index];
            let (source, source_facts) = if index == MANIFEST {
                (this.manifest_original.ok_or(Error::State)?, this.manifest_facts.clone().ok_or(Error::State)?)
            } else { this.open_source(index)? };
            need(source_facts.metadata.size == size && this.checked(source, AuthorityScope::ImmutableVersion)? == source_facts)?;
            let (parent, name) = this.payload_parent(index, false)?;
            this.recheck_installer()?; this.recheck_location()?; this.recheck_dir(parent)?;
            let parent_slot = this.directories[parent].current();
            let canonical = format!("{}\\{name}", this.book.slot(parent_slot)?.canonical);
            let writer = this.book.reserve(Kind::File, Some(parent_slot), name, canonical)?.index;
            let path = this.child_path(parent, name)?;
            let raw = descriptor(FileKind::File, image_payload(index)?, false)?;
            this.mutate(Effect::Writer, Some(writer), &path, &raw, Vec::new())?;
            let created = this.checked(writer, AuthorityScope::ImmutableVersion)?;
            this.unique_identity(&created.metadata)?;
            need(created.metadata.identity != source_facts.metadata.identity && created.metadata.size == 0)?;
            exact_security(&created.security, FileKind::File, image_payload(index)?, false)?;
            this.after_child(parent)?;
            this.transfer = Some(Transfer { index, stage: TransferStage::Copy, source, writer, readback: None,
                source_facts, created, readback_facts: None, copied: 0, reread: 0, proof: CopyProof::default() });
            Ok(())
        })
    }
    /// One actual source chunk is retained by the pinned WriteFile arena. Only
    /// exact successful writes return bytes for the safe caller's SHA256 update.
    pub fn copy_next(&mut self) -> Result<Vec<u8>> {
        self.step(|this| {
            this.order.live(Stage::Copying)?;
            let t = this.transfer.as_ref().ok_or(Error::State)?;
            need(t.stage == TransferStage::Copy)?;
            let (index, source, writer, copied) = (t.index, t.source, t.writer, t.copied);
            let size = this.sizes.as_ref().ok_or(Error::State)?[index];
            let chunk = if index == MANIFEST {
                // Cache came from this original's genuine successful EOF; never
                // a second filename/source, reread, seek or synthetic EOF receipt.
                need(this.book.slot(source)?.read_ended && this.book.slot(source)?.read_bytes == size)?;
                let start = usize::try_from(copied).map_err(|_| Error::Bounds)?;
                this.manifest.get(start..start.saturating_add(BUFFER).min(this.manifest.len())).ok_or(Error::State)?.to_vec()
            } else { this.book.read_next(&this.key(source), BUFFER)? };
            this.tick()?;
            if chunk.is_empty() {
                need(copied == size && this.book.slot(source)?.read_ended)?;
                let t = this.transfer.as_mut().ok_or(Error::State)?;
                t.proof.source_eof = true; t.stage = TransferStage::SourceEof; return Ok(chunk);
            }
            let after = copied.checked_add(chunk.len() as u64).ok_or(Error::Bounds)?;
            need(after <= size)?; this.recheck_installer()?;
            let complete = this.mutate(Effect::Write, Some(writer), "", &[], chunk)?;
            this.transfer.as_mut().ok_or(Error::State)?.copied = after;
            Ok(complete.frame.data.clone())
        })
    }
    /// Call ONLY after the safe app accepted exact source length/hash/EOF. Flush
    /// and once-close the actual writer before any distinct readback original.
    pub fn finish_copy(&mut self) -> Result<()> {
        self.step(|this| {
            copy_result(this.order.live(Stage::Copying), &this.copy_failure, CopyEdge::Order)?;
            let t = this.transfer.as_ref().ok_or(Error::State)?;
            copy_result(need(t.stage == TransferStage::SourceEof && t.proof.source_eof), &this.copy_failure, CopyEdge::SourceEof)?;
            let (index, source, writer, before, source_before) = (t.index, t.source, t.writer, t.created.clone(), t.source_facts.clone());
            copy_result(this.recheck_installer(), &this.copy_failure, CopyEdge::Installer)?;
            copy_result(this.mutate(Effect::Flush, Some(writer), "", &[], Vec::new()), &this.copy_failure, CopyEdge::Flush)?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.flushed = true;
            let written = copy_result(this.checked(writer, AuthorityScope::ImmutableVersion), &this.copy_failure, CopyEdge::WriterCheck)?;
            {
                let trace = Some(CopyRefusal { first: &this.copy_failure, edge: CopyEdge::WriteTransition });
                need(write_transition_observed(&before.metadata, &written.metadata, this.sizes.as_ref().ok_or(Error::State)?[index], trace)
                    && copy_guard(before.security == written.security, CopyMember::Security, trace))?;
            }
            copy_result(this.close(writer), &this.copy_failure, CopyEdge::WriterClose)?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.writer_closed = true;
            {
                // Preserve the returned Facts temporary's original drop boundary
                // before source close; no additional query or retained owner data.
                let source_now = copy_result(this.checked(source, AuthorityScope::ImmutableVersion), &this.copy_failure, CopyEdge::SourceCheck)?;
                need(source_unchanged_observed(&source_now, &source_before,
                    Some(CopyRefusal { first: &this.copy_failure, edge: CopyEdge::SourceUnchanged })))?;
            }
            copy_result(this.close(source), &this.copy_failure, CopyEdge::SourceClose)?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.source_closed = true;
            this.ready()?;
            let (parent, name) = this.payload_parent(index, false)?;
            copy_result(this.recheck_dir(parent), &this.copy_failure, CopyEdge::ParentCheck)?;
            let readback = copy_result(this.reserve_later(parent, name, FileKind::File, writer), &this.copy_failure, CopyEdge::ReadbackReserve)?;
            copy_result(this.book.call(Call::Open(readback), null_mut(), Vec::new()), &this.copy_failure, CopyEdge::ReadbackOpen)?;
            copy_result(this.book.noninherited(readback), &this.copy_failure, CopyEdge::ReadbackNoninherited)?;
            let observed = copy_result(this.checked(readback, AuthorityScope::ImmutableVersion), &this.copy_failure, CopyEdge::ReadbackCheck)?;
            {
                let trace = Some(CopyRefusal { first: &this.copy_failure, edge: CopyEdge::WriterCloseTransition });
                need(writer_close_transition_observed(&written.metadata, &observed.metadata, trace)
                    && copy_guard(written.security == observed.security, CopyMember::Security, trace))?;
            }
            let t = this.transfer.as_mut().ok_or(Error::State)?;
            t.readback = Some(readback); t.readback_facts = Some(observed); t.stage = TransferStage::Readback; Ok(())
        })
    }
    pub fn readback_next(&mut self) -> Result<Vec<u8>> {
        self.step(|this| {
            this.order.live(Stage::Copying)?;
            let t = this.transfer.as_ref().ok_or(Error::State)?;
            need(t.stage == TransferStage::Readback)?;
            let (index, readback, before) = (t.index, t.readback.ok_or(Error::State)?, t.reread);
            let chunk = this.book.read_next(&this.key(readback), BUFFER)?; this.tick()?;
            let count = before.checked_add(chunk.len() as u64).ok_or(Error::Bounds)?;
            let size = this.sizes.as_ref().ok_or(Error::State)?[index]; need(count <= size)?;
            let t = this.transfer.as_mut().ok_or(Error::State)?; t.reread = count;
            if chunk.is_empty() { need(count == size)?; t.proof.readback_eof = true; t.stage = TransferStage::ReadbackEof; }
            Ok(chunk)
        })
    }
    /// Call only after the safe caller's exact readback length/hash/EOF check.
    pub fn finish_readback(&mut self) -> Result<()> {
        self.step(|this| {
            this.order.live(Stage::Copying)?;
            let t = this.transfer.as_ref().ok_or(Error::State)?;
            need(t.stage == TransferStage::ReadbackEof)?;
            let (index, readback, before) = (t.index, t.readback.ok_or(Error::State)?, t.readback_facts.clone().ok_or(Error::State)?);
            need(this.book.slot(readback)?.read_ended && this.checked(readback, AuthorityScope::ImmutableVersion)? == before)?;
            this.close(readback)?;
            let t = this.transfer.as_mut().ok_or(Error::State)?; t.proof.readback_closed = true;
            this.order.copied(index, t.proof)?;
            let t = this.transfer.take().ok_or(Error::State)?;
            this.copied.push(Copied { source: t.source, writer: t.writer, readback, source_facts: t.source_facts,
                destination: before, proof: t.proof, control: None, sealed_closed: false });
            Ok(())
        })
    }

    fn inventories(&mut self) -> Result<()> {
        need(self.transfer.is_none() && self.copied.len() == 47)?;
        for copied in &self.copied {
            need(copied.proof.complete() && self.closed(copied.source) && self.closed(copied.writer) && self.closed(copied.readback))?;
        }
        for i in 0..self.directories.len() { self.recheck_dir(i)?; }
        for source in [true, false] {
            for python in [false, true] {
                let index = match (source, python) {
                    (true, false) => self.source_root, (true, true) => self.source_python,
                    (false, false) => self.version, (false, true) => self.python,
                }.ok_or(Error::State)?;
                let entries = self.entries(index, None)?; exact_names(&entries, python)?;
                let mut expected = BTreeMap::new();
                for (i, path) in PUBLICATION_PAYLOADS.iter().enumerate() {
                    if path.starts_with("python/") == python {
                        let leaf = path.strip_prefix("python/").unwrap_or(path);
                        let metadata = if source { &self.copied[i].source_facts.metadata } else { &self.copied[i].destination.metadata };
                        expected.insert(leaf.to_string(), metadata.clone());
                    }
                }
                if !python {
                    let child = if source { self.source_python } else { self.python }.ok_or(Error::State)?;
                    expected.insert("python".to_owned(), self.directories[child].facts.metadata.clone());
                }
                exact_entries(&entries, &expected)?; self.recheck_dir(index)?;
            }
        }
        self.order.inventories = true; Ok(())
    }
    fn open_directory_control(&mut self, index: usize) -> Result<()> {
        need(self.directories[index].created && self.directories[index].control.is_none())?;
        let (parent, previous, path, before) = {
            let d = &self.directories[index]; (d.parent.ok_or(Error::State)?, d.initial, d.dos.clone(), d.facts.clone())
        };
        self.recheck_dir(parent)?; self.recheck_installer()?; self.recheck_location()?;
        let name = path.rsplit('\\').next().ok_or(Error::State)?;
        let slot = self.reserve_later(parent, name, FileKind::Directory, previous)?;
        self.directories[index].control = Some(slot);
        self.mutate(Effect::Control(true), Some(slot), &path, &[], Vec::new())?;
        need(self.checked(slot, AuthorityScope::ImmutableVersion)? == before)?; Ok(())
    }
    fn seal_control(&mut self, slot: usize, before: &Facts, image: bool, expose: bool) -> Result<Facts> {
        self.recheck_installer()?; self.recheck_location()?;
        need(self.checked(slot, AuthorityScope::ImmutableVersion)? == *before)?;
        let raw = descriptor(before.metadata.kind, image, true)?;
        if expose { self.order.expose()?; }
        // Traverse bypass makes even a failed first descendant seal possibly
        // observable. Never wait for its postchecks/close to record that risk.
        self.order.grant_attempted = true;
        self.mutate(Effect::Seal, Some(slot), "", &raw, Vec::new())?;
        let after = self.checked(slot, AuthorityScope::ImmutableVersion)?;
        need(acl_transition(&before.metadata, &after.metadata))?;
        exact_security(&after.security, before.metadata.kind, image, true)?; Ok(after)
    }
    fn seal_directory(&mut self, index: usize, expose: bool) -> Result<()> {
        let dir = &self.directories[index];
        need(dir.created && dir.control.is_some())?;
        let (slot, before) = (dir.current(), dir.facts.clone());
        self.directories[index].facts = self.seal_control(slot, &before, false, expose)?; Ok(())
    }
    fn seal_file(&mut self, index: usize) -> Result<()> {
        let copied = self.copied.get(index).ok_or(Error::State)?;
        need(copied.control.is_none() && !copied.sealed_closed && copied.proof.complete())?;
        let (before, previous) = (copied.destination.clone(), copied.readback);
        let (parent, name) = self.payload_parent(index, false)?;
        self.recheck_dir(parent)?; self.recheck_installer()?; self.recheck_location()?;
        let slot = self.reserve_later(parent, name, FileKind::File, previous)?;
        self.copied[index].control = Some(slot);
        let path = self.child_path(parent, name)?;
        self.mutate(Effect::Control(false), Some(slot), &path, &[], Vec::new())?;
        need(self.checked(slot, AuthorityScope::ImmutableVersion)? == before)?;
        let after = self.seal_control(slot, &before, image_payload(index)?, false)?;
        self.close(slot)?;
        self.copied[index].destination = after; self.copied[index].sealed_closed = true;
        self.order.sealed_files += 1; self.recheck_dir(parent)?; Ok(())
    }
    /// Final consumer-admission grant, NOT atomic whole-tree secrecy/durability.
    /// Already sealed complete children may be readable via traverse bypass.
    pub fn seal_once(&mut self) -> Result<()> {
        self.step(|this| {
            this.order.live(Stage::Copying)?; this.inventories()?; this.order.seal()?;
            // All47 source/data-writer/readback originals are known closed before
            // the first ordinary grant. Retire unchanged source directories too.
            for index in this.source_dirs.clone().into_iter().rev() {
                this.recheck_dir(index)?; this.close(this.directories[index].initial)?;
            }
            // Initial new-directory readers have no WRITE_DAC. Close bottom-up,
            // then acquire distinct same-ID minimal controls top-down. Existing
            // versions/T ancestors remain admitted and are NEVER ACL-repaired.
            for index in this.output_dirs.clone().into_iter().rev() {
                this.recheck_dir(index)?; this.close(this.directories[index].initial)?;
            }
            let version = this.version.ok_or(Error::State)?;
            let python = this.python.ok_or(Error::State)?;
            for index in this.output_dirs.clone() {
                this.open_directory_control(index)?;
                if index != version && index != python {
                    // Missing shared versions/T were also born trusted-only. No
                    // early grant: their seal occurs after ALL copy/inventory
                    // gates, before the final D consumer-admission point. Their
                    // original controls stay retained as ancestor dependencies.
                    this.seal_directory(index, false)?;
                }
            }
            for index in 0..PUBLICATION_PAYLOADS.len() { this.seal_file(index)?; }
            this.seal_directory(python, false)?;
            this.close(this.directories[python].current())?; this.order.python_closed = true;
            need(this.copied.iter().all(|c| c.sealed_closed && c.control.is_some_and(|slot| this.closed(slot))))?;
            for index in 0..this.directories.len() {
                if this.book.slot(this.directories[index].current())?.state == SlotState::Owned { this.recheck_dir(index)?; }
            }
            // No source/data writer or descendant control survives this gate.
            // The root control and necessary ancestor/token originals remain.
            this.seal_directory(version, true)?;
            this.recheck_location()?; this.recheck_installer()?; this.recheck_dir(version)?;
            this.close(this.directories[version].current())?;
            this.order.stage = Stage::RootClosed;
            for index in this.output_dirs.clone().into_iter().rev() {
                if index != version && index != python {
                    this.recheck_dir(index)?; this.close(this.directories[index].current())?;
                }
            }
            for index in 0..this.directories.len() {
                if this.book.slot(this.directories[index].current())?.state == SlotState::Owned { this.recheck_dir(index)?; }
            }
            this.recheck_location()?; this.recheck_installer()?; this.tick()?;
            this.settlement_attempted = true;
            let settled = this.book.settle_once() == CloseOutcome::Settled && this.book.settled();
            this.tick()?; this.order.completed(settled)
        })
    }
    pub fn published_and_settled(&self) -> bool {
        self.order.stage == Stage::Complete && !self.order.failed && !self.order.unknown && !self.expired
            && Instant::now() < self.end && self.order.exposure && self.mutation.is_none() && self.book.settled()
    }
    pub fn possibly_exposed(&self) -> bool { self.order.grant_attempted || self.order.exposure }
    /// Only the recorded original target-D `(0, ERROR_ALREADY_EXISTS)` after
    /// actual failure settlement. Not adoption, retry, absence or cleanup proof.
    pub fn occupied_target_and_settled(&self) -> bool {
        if !self.settlement_attempted || !self.book.settled() || self.book.is_unknown()
            || self.mutation.is_some() || self.expired || Instant::now() >= self.end
            || !self.order.failed || self.order.unknown || self.order.stage != Stage::Manifest
            || self.order.copies != 0 || self.order.sealed_files != 0 || self.order.inventories
            || self.order.python_closed || self.possibly_exposed() || self.transfer.is_some()
            || !self.copied.is_empty() || !self.output_dirs.is_empty()
            || self.version.is_some() || self.python.is_some()
            || self.directories.iter().any(|directory| directory.created) { return false; }
        let Some(role) = &self.target_creation else { return false; };
        // The narrow duplicate-success case has no preceding output creation.
        if role.intent != 0 || self.creations.len() != 1 { return false; }
        let creation = &self.creations[role.intent];
        let Some(mrk) = self.mrk else { return false; };
        let Some(versions) = self.directories.get(role.versions) else { return false; };
        let Some(target) = self.directories.get(role.parent) else { return false; };
        creation.parent == role.parent && creation.path == role.path && creation.entered
            && creation.returned == Some((0, F::ERROR_ALREADY_EXISTS))
            && versions.parent == Some(mrk) && target.parent == Some(role.versions)
            && self.child_path(mrk, "versions").is_ok_and(|path| path == versions.dos)
            && self.child_path(role.versions, TARGET).is_ok_and(|path| path == target.dos)
            && self.child_path(role.parent, &self.digest).is_ok_and(|path| path == role.path)
    }
    /// Exactly one failure settlement. A returned close failure permits other
    /// independent known originals to close once. Any active native arena retains
    /// EVERYTHING it might reference; no replacement handle or Drop-as-finality.
    pub fn fail_and_settle_once(&mut self) -> CloseOutcome {
        self.order.fail(self.book.is_unknown() || self.mutation.is_some());
        if self.settlement_attempted { return if self.book.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        self.settlement_attempted = true;
        if self.mutation.is_some() { self.book.mark_interrupted(); return CloseOutcome::Unknown; }
        let outcome = self.book.settle_once();
        if outcome == CloseOutcome::Unknown { self.order.fail(true); }
        outcome
    }
}

unsafe fn invoke_mutation(frame: &Mutation) -> Returned {
    // SAFETY: mutate() pinned and registered every input/output before entry;
    // no asynchronous flag, callback or borrowed temporary is involved.
    unsafe {
        match frame.effect {
            Effect::Directory(_) => boolean(FS::CreateDirectoryW(frame.path.as_ptr(), &frame.attributes)),
            Effect::Writer | Effect::Control(_) => {
                let (access, disposition, flags) = match frame.effect {
                    Effect::Writer => (F::GENERIC_WRITE | FS::READ_CONTROL | FS::FILE_READ_ATTRIBUTES,
                        FS::CREATE_NEW, FS::FILE_ATTRIBUTE_NORMAL | FS::FILE_FLAG_OPEN_REPARSE_POINT),
                    Effect::Control(directory) => (FS::WRITE_DAC | FS::READ_CONTROL | FS::FILE_READ_ATTRIBUTES | FS::SYNCHRONIZE,
                        FS::OPEN_EXISTING, FS::FILE_FLAG_OPEN_REPARSE_POINT | if directory { FS::FILE_FLAG_BACKUP_SEMANTICS } else { 0 }),
                    _ => unreachable!(),
                };
                // Record the actual HANDLE before GetLastError or any other work.
                *frame.output = FS::CreateFileW(frame.path.as_ptr(), access, FS::FILE_SHARE_READ,
                    &frame.attributes, disposition, flags, null_mut());
                let value = *frame.output;
                if valid_handle(value) { Returned::Boolean(1, 0) }
                else { Returned::Boolean(0, F::GetLastError()) }
            }
            Effect::Write => boolean(FS::WriteFile(frame.handle, frame.data.as_ptr(), frame.data.len() as u32, frame.count.get(), null_mut())),
            Effect::Flush => boolean(FS::FlushFileBuffers(frame.handle)),
            Effect::Seal => boolean(S::SetKernelObjectSecurity(frame.handle,
                S::DACL_SECURITY_INFORMATION | S::PROTECTED_DACL_SECURITY_INFORMATION, frame.descriptor.get().cast())),
            Effect::Scalar(class) => boolean(S::GetTokenInformation(frame.handle, class, frame.scalar.get().cast(), 4, frame.count.get())),
        }
    }
}
fn check_entry_frame(entries: &[DirectoryEntry], own: &Metadata, parent: Option<&Metadata>) -> Result<()> {
    check_entry_frame_in(entries, own, parent, Refusal::none())
}
fn check_entry_frame_in(entries: &[DirectoryEntry], own: &Metadata, parent: Option<&Metadata>, trace: Refusal<'_>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let row = trace.index(AdmissionIndex::Directory, index);
        row.need(seen.insert(entry.name.to_ascii_lowercase()), C::EntryDuplicate)?;
        if entry.name == "." || entry.name == ".." {
            row.need(entry.kind == FileKind::Directory, C::DotKind)?;
            let bound = if entry.name == "." { Some(own) } else { parent };
            if let Some(bound) = bound { row.need(entry.file_id == bound.identity.file_id, C::DotIdentity)?; }
        }
    }
    Ok(())
}
fn selected_entry(entries: &[DirectoryEntry], name: &str) -> Result<Option<DirectoryEntry>> {
    selected_entry_in(entries, name, Refusal::none())
}
fn selected_entry_in(entries: &[DirectoryEntry], name: &str, trace: Refusal<'_>) -> Result<Option<DirectoryEntry>> {
    let mut selected = None;
    for (index, entry) in entries.iter().enumerate().filter(|(_, entry)| entry.name.eq_ignore_ascii_case(name)) {
        let row = trace.index(AdmissionIndex::Directory, index);
        row.need(entry.name == name, C::SelectedCase)?;
        row.need(selected.is_none(), C::SelectedDuplicate)?;
        selected = Some(entry.clone());
    }
    Ok(selected)
}
fn match_entry(entry: &DirectoryEntry, metadata: &Metadata) -> Result<()> { match_entry_in(entry, metadata, Refusal::none()) }
fn match_entry_in(entry: &DirectoryEntry, metadata: &Metadata, trace: Refusal<'_>) -> Result<()> {
    trace.need(entry.kind == metadata.kind, C::EntryKind)?;
    trace.need(entry.file_id == metadata.identity.file_id, C::EntryIdentity)?;
    trace.need(entry.attributes == metadata.attributes, C::EntryAttributes)
}
fn exact_names(entries: &[DirectoryEntry], python: bool) -> Result<()> { exact_names_in(entries, python, Refusal::none()) }
fn exact_names_in(entries: &[DirectoryEntry], python: bool, trace: Refusal<'_>) -> Result<()> {
    let mut expected: BTreeSet<String> = PUBLICATION_PAYLOADS.iter().filter(|p| p.starts_with("python/") == python)
        .map(|p| p.strip_prefix("python/").unwrap_or(p).to_string()).collect();
    if !python { expected.insert("python".to_owned()); }
    for (index, entry) in entries.iter().enumerate().filter(|(_, e)| e.name != "." && e.name != "..") {
        let row = trace.index(AdmissionIndex::Directory, index);
        row.need(expected.remove(&entry.name), C::RosterName)?;
        row.need(entry.kind == if !python && entry.name == "python" { FileKind::Directory } else { FileKind::File }, C::RosterKind)?;
    }
    trace.need(expected.is_empty(), C::RosterMissing)
}
fn exact_entries(entries: &[DirectoryEntry], expected: &BTreeMap<String, Metadata>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for entry in entries.iter().filter(|e| e.name != "." && e.name != "..") {
        need(seen.insert(entry.name.clone()))?;
        match_entry(entry, expected.get(&entry.name).ok_or(Error::Unsafe)?)?;
    }
    need(seen.len() == expected.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_buffer(principal: &[u8], header: usize, pointer_at: usize, attributes_at: usize, attributes: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; header + principal.len()];
        bytes[header..].copy_from_slice(principal);
        let pointer = bytes.as_ptr() as usize + header;
        bytes[pointer_at..pointer_at + 8].copy_from_slice(&(pointer as u64).to_le_bytes());
        bytes[attributes_at..attributes_at + 4].copy_from_slice(&attributes.to_le_bytes());
        bytes // final allocation never resizes; parser validates rather than dereferences the pointer
    }
    #[test]
    fn installer_admission_is_positive_bounded_and_not_ordinary_refusal() -> Result<()> {
        use crate::tests::{admission_trace, admission_fault};
        let identity = TokenIdentity { token_id: 1, authentication_id: 2, modified_id: 3, groups: 1, privileges: 0 };
        let group_head = offset_of!(S::TOKEN_GROUPS, Groups);
        let group_attributes = group_head + offset_of!(S::SID_AND_ATTRIBUTES, Attributes);
        let mut groups = token_buffer(&admins(), group_head + size_of::<S::SID_AND_ATTRIBUTES>(),
            group_head + offset_of!(S::SID_AND_ATTRIBUTES, Sid), group_attributes,
            (SS::SE_GROUP_MANDATORY | SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER) as u32);
        groups[..4].copy_from_slice(&1u32.to_le_bytes());
        let privileges = vec![0u8; offset_of!(S::TOKEN_PRIVILEGES, Privileges)];
        for (local_system, elevation_type) in [
            (false, S::TokenElevationTypeDefault), (false, S::TokenElevationTypeFull),
            (true, S::TokenElevationTypeDefault), (true, S::TokenElevationTypeFull),
        ] {
            let elevation_type = elevation_type as u32;
            let principal = if local_system { system() } else { sid(5, &[21, 1, 2, 3, 1001]) };
            let user = token_buffer(&principal, size_of::<S::TOKEN_USER>(),
                offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
                offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes), 0);
            let integrity = token_buffer(&sid(16, &[if local_system { 16384 } else { 12288 }]), size_of::<S::TOKEN_MANDATORY_LABEL>(),
                offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
                offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes),
                (SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED) as u32);
            let trace = admission_trace(R::Installer);
            let plain = installer_facts(identity, S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0, 0,
                &user, &integrity, &groups, &privileges);
            assert_eq!(InstallerData(trace.at(O::InstallerPolicy)).installer_facts(identity, S::TokenPrimary as u32,
                1, elevation_type, 0, 0, 0, 0, &user, &integrity, &groups, &privileges), plain);
            assert!(plain.is_ok() && trace.first.get().is_none());
            let accepted = plain?;
            assert_eq!(accepted.identity, identity);
            assert_eq!(accepted.elevation_type, elevation_type);
            let other_kind = if elevation_type == S::TokenElevationTypeDefault as u32 {
                S::TokenElevationTypeFull as u32
            } else { S::TokenElevationTypeDefault as u32 };
            let other = installer_facts(identity, S::TokenPrimary as u32, 1, other_kind, 0, 0, 0, 0,
                &user, &integrity, &groups, &privileges)?;
            assert_ne!(accepted, other); // full Installer equality must retain elevation-kind drift
            assert_eq!(security::token_facts(identity, S::TokenPrimary as u32, 1, elevation_type, 0, 0,
                &user, &integrity, &groups, &privileges, &[1, 2, 3, 4, 5]), Err(Error::Unsafe));
            for (kind, elevated, elevation, ui, virtualized, restricted, app, check) in [
                (S::TokenImpersonation as u32, 1, elevation_type, 0, 0, 0, 0, C::TokenPrimary),
                (S::TokenPrimary as u32, 0, elevation_type, 0, 0, 0, 0, C::Elevated),
                (S::TokenPrimary as u32, 2, elevation_type, 0, 0, 0, 0, C::Elevated),
                (S::TokenPrimary as u32, u32::MAX, elevation_type, 0, 0, 0, 0, C::Elevated),
                (S::TokenPrimary as u32, 1, S::TokenElevationTypeLimited as u32, 0, 0, 0, 0,
                    if local_system { C::SystemElevation } else { C::AccountElevation }),
                (S::TokenPrimary as u32, 1, 0, 0, 0, 0, 0,
                    if local_system { C::SystemElevation } else { C::AccountElevation }),
                (S::TokenPrimary as u32, 1, 4, 0, 0, 0, 0,
                    if local_system { C::SystemElevation } else { C::AccountElevation }),
                (S::TokenPrimary as u32, 1, u32::MAX, 0, 0, 0, 0,
                    if local_system { C::SystemElevation } else { C::AccountElevation }),
                (S::TokenPrimary as u32, 1, elevation_type, 1, 0, 0, 0, C::UiAccess),
                (S::TokenPrimary as u32, 1, elevation_type, 0, 1, 0, 0, C::Virtualization),
                (S::TokenPrimary as u32, 1, elevation_type, 0, 0, 1, 0, C::Restricted),
                (S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0x100, 0, C::Restricted),
                (S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0x01000000, 0, C::Restricted),
                (S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0, 1, C::AppContainer),
            ] {
                let trace = admission_trace(R::Installer);
                let observed = InstallerData(trace.at(O::InstallerPolicy)).installer_facts(identity, kind, elevated, elevation,
                    ui, virtualized, restricted, app, &user, &integrity, &groups, &privileges);
                assert_eq!(observed, installer_facts(identity, kind, elevated, elevation, ui, virtualized, restricted, app,
                    &user, &integrity, &groups, &privileges));
                assert_eq!(observed, Err(Error::Unsafe));
                admission_fault(&trace, R::Installer, O::InstallerPolicy, check, None);
            }
        }
        {
            // Full-policy Default rows, not merely a successful enum-membership test.
            let elevation_type = S::TokenElevationTypeDefault as u32;
            let integrity_flags = (SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED) as u32;
            let user = token_buffer(&sid(5, &[21, 1, 2, 3, 1001]), size_of::<S::TOKEN_USER>(),
                offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
                offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes), 0);
            let integrity = token_buffer(&sid(16, &[12288]), size_of::<S::TOKEN_MANDATORY_LABEL>(),
                offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
                offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes), integrity_flags);
            for (principal, user_flags, level, flags, role, check) in [
                (admins(), 0, 12288, integrity_flags, R::User, C::AccountShape),
                (sid(5, &[21, 1, 2, 3, 1001]), 1, 12288, integrity_flags, R::User, C::UserAttributes),
                (sid(5, &[21, 1, 2, 3, 1001]), 0, 8192, integrity_flags, R::Integrity, C::AccountIntegrity),
                (sid(5, &[21, 1, 2, 3, 1001]), 0, 16384, integrity_flags, R::Integrity, C::AccountIntegrity),
                (sid(5, &[21, 1, 2, 3, 1001]), 0, 12288, SS::SE_GROUP_INTEGRITY as u32, R::Integrity, C::IntegrityAttributes),
            ] {
                let bad_user = token_buffer(&principal, size_of::<S::TOKEN_USER>(),
                    offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
                    offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes), user_flags);
                let bad_integrity = token_buffer(&sid(16, &[level]), size_of::<S::TOKEN_MANDATORY_LABEL>(),
                    offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
                    offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes), flags);
                let trace = admission_trace(R::Installer);
                let observed = InstallerData(trace.at(O::InstallerPolicy)).installer_facts(identity, S::TokenPrimary as u32,
                    1, elevation_type, 0, 0, 0, 0, &bad_user, &bad_integrity, &groups, &privileges);
                assert_eq!(observed, installer_facts(identity, S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0, 0,
                    &bad_user, &bad_integrity, &groups, &privileges));
                assert_eq!(observed, Err(Error::Unsafe));
                admission_fault(&trace, role, O::InstallerPolicy, check, None);
            }
            for (principal, flags, check, ordinal) in [
                (admins(), SS::SE_GROUP_ENABLED as u32, C::AdminOwner, None),
                (admins(), SS::SE_GROUP_OWNER as u32, C::AdminOwner, None),
                (admins(), (SS::SE_GROUP_OWNER | SS::SE_GROUP_USE_FOR_DENY_ONLY) as u32, C::AdminOwner, None),
                (admins(), (SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER | SS::SE_GROUP_USE_FOR_DENY_ONLY) as u32, C::GroupDenyEnabled, Some(0)),
                (sid(5, &[32, 545]), (SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER) as u32, C::AdminOwner, None),
                (admins(), 0x08000000, C::GroupFlags, Some(0)),
            ] {
                let mut bad_groups = token_buffer(&principal, group_head + size_of::<S::SID_AND_ATTRIBUTES>(),
                    group_head + offset_of!(S::SID_AND_ATTRIBUTES, Sid), group_attributes, flags);
                bad_groups[..4].copy_from_slice(&1u32.to_le_bytes());
                let trace = admission_trace(R::Installer);
                let observed = InstallerData(trace.at(O::InstallerPolicy)).installer_facts(identity, S::TokenPrimary as u32,
                    1, elevation_type, 0, 0, 0, 0, &user, &integrity, &bad_groups, &privileges);
                assert_eq!(observed, installer_facts(identity, S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0, 0,
                    &user, &integrity, &bad_groups, &privileges));
                assert_eq!(observed, Err(Error::Unsafe));
                admission_fault(&trace, R::Groups, O::InstallerPolicy, check, ordinal);
            }
            let with_privilege = TokenIdentity { privileges: 1, ..identity };
            let head = offset_of!(S::TOKEN_PRIVILEGES, Privileges);
            for (flags, refused) in [(S::SE_PRIVILEGE_ENABLED | S::SE_PRIVILEGE_ENABLED_BY_DEFAULT, false), (0x08000000, true)] {
                let mut raw = vec![0u8; head + size_of::<S::LUID_AND_ATTRIBUTES>()];
                raw[..4].copy_from_slice(&1u32.to_le_bytes());
                let luid_at = head + offset_of!(S::LUID_AND_ATTRIBUTES, Luid);
                raw[luid_at..luid_at + 8].copy_from_slice(&1u64.to_le_bytes());
                let flags_at = head + offset_of!(S::LUID_AND_ATTRIBUTES, Attributes);
                raw[flags_at..flags_at + 4].copy_from_slice(&flags.to_le_bytes());
                let trace = admission_trace(R::Installer);
                let observed = InstallerData(trace.at(O::InstallerPolicy)).installer_facts(with_privilege, S::TokenPrimary as u32,
                    1, elevation_type, 0, 0, 0, 0, &user, &integrity, &groups, &raw);
                assert_eq!(observed, installer_facts(with_privilege, S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0, 0,
                    &user, &integrity, &groups, &raw));
                if refused {
                    assert_eq!(observed, Err(Error::Unsafe));
                    admission_fault(&trace, R::Privileges, O::InstallerPolicy, C::PrivilegeFlags, Some(0));
                } else {
                    let facts = observed?;
                    assert_eq!(facts.identity, with_privilege);
                    assert_eq!(facts.elevation_type, elevation_type);
                    assert_eq!(facts.privileges, vec![(1, flags)]);
                    assert!(trace.first.get().is_none());
                }
            }
        }
        for (flags, check, index) in [(0x08000000, C::GroupFlags, Some(0)),
            ((SS::SE_GROUP_USE_FOR_DENY_ONLY | SS::SE_GROUP_ENABLED) as u32, C::GroupDenyEnabled, Some(0)),
            (0, C::AdminOwner, None)] {
            groups[group_attributes..group_attributes + 4].copy_from_slice(&flags.to_le_bytes());
            let trace = admission_trace(R::Groups);
            assert_eq!(InstallerData(trace.at(O::InstallerPolicy)).installer_groups(&groups, 1), installer_groups(&groups, 1));
            admission_fault(&trace, R::Groups, O::InstallerPolicy, check, index);
        }
        let group_pointer = group_head + offset_of!(S::SID_AND_ATTRIBUTES, Sid);
        let extent = group_head + size_of::<S::SID_AND_ATTRIBUTES>();
        for (pointer, check) in [(0, C::PointerOffset), (groups.as_ptr() as usize, C::PointerMinimum),
            (groups.as_ptr() as usize + extent + 1, C::PointerAlignment)] {
            groups[group_pointer..group_pointer + 8].copy_from_slice(&(pointer as u64).to_le_bytes());
            let trace = admission_trace(R::Groups);
            assert_eq!(InstallerData(trace.at(O::InstallerPolicy)).installer_groups(&groups, 1), installer_groups(&groups, 1));
            admission_fault(&trace, R::Groups, O::InstallerPolicy, check, Some(0));
        }
        let pointer = groups.as_ptr() as usize + extent;
        groups[group_pointer..group_pointer + 8].copy_from_slice(&(pointer as u64).to_le_bytes());
        let extent = group_head + 2 * size_of::<S::SID_AND_ATTRIBUTES>();
        let mut duplicate = token_buffer(&admins(), extent, group_pointer, group_attributes,
            (SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER) as u32);
        duplicate[..4].copy_from_slice(&2u32.to_le_bytes());
        let second = group_head + size_of::<S::SID_AND_ATTRIBUTES>() + offset_of!(S::SID_AND_ATTRIBUTES, Sid);
        let pointer = duplicate.as_ptr() as usize + extent;
        duplicate[second..second + 8].copy_from_slice(&(pointer as u64).to_le_bytes());
        let trace = admission_trace(R::Groups);
        assert_eq!(InstallerData(trace.at(O::InstallerPolicy)).installer_groups(&duplicate, 2), installer_groups(&duplicate, 2));
        admission_fault(&trace, R::Groups, O::InstallerPolicy, C::GroupDuplicate, Some(1));
        let head = offset_of!(S::TOKEN_PRIVILEGES, Privileges); let step = size_of::<S::LUID_AND_ATTRIBUTES>();
        for (luid, flags, check) in [(0u64, 0u32, C::PrivilegeLuid), (1, 0x08000000, C::PrivilegeDuplicate),
            (2, 0x08000000, C::PrivilegeFlags)] {
            let mut raw = vec![0u8; head + 2 * step]; raw[..4].copy_from_slice(&2u32.to_le_bytes());
            raw[head..head + 8].copy_from_slice(&1u64.to_le_bytes());
            raw[head + step..head + step + 8].copy_from_slice(&luid.to_le_bytes());
            let at = head + step + offset_of!(S::LUID_AND_ATTRIBUTES, Attributes);
            raw[at..at + 4].copy_from_slice(&flags.to_le_bytes());
            let trace = admission_trace(R::Privileges);
            assert_eq!(InstallerData(trace.at(O::InstallerPolicy)).installer_privileges(&raw, 2),
                InstallerData(Refusal::none()).installer_privileges(&raw, 2));
            admission_fault(&trace, R::Privileges, O::InstallerPolicy, check, Some(1));
        }
        groups[group_attributes..group_attributes + 4].copy_from_slice(&(SS::SE_GROUP_USE_FOR_DENY_ONLY as u32).to_le_bytes());
        need(installer_groups(&groups, 1).is_err())?;
        groups[group_head..group_head + 8].copy_from_slice(&0u64.to_le_bytes());
        need(installer_groups(&groups, 1).is_err())
    }

    #[test]
    fn fixed_roster_and_production_masks() -> Result<()> {
        {
            use CopyEdge as E; use CopyMember as M; use CopyAllocation as A;
            let edges = [(E::Order, "order"), (E::SourceEof, "source-eof"), (E::Installer, "installer"),
                (E::Flush, "flush"), (E::WriterCheck, "writer-check"), (E::WriteTransition, "write-transition"),
                (E::WriterClose, "writer-close"), (E::SourceCheck, "source-check"), (E::SourceUnchanged, "source-unchanged"),
                (E::SourceClose, "source-close"), (E::ParentCheck, "parent-check"), (E::ReadbackReserve, "readback-reserve"),
                (E::ReadbackOpen, "readback-open"), (E::ReadbackNoninherited, "readback-noninherited"),
                (E::ReadbackCheck, "readback-check"), (E::WriterCloseTransition, "writer-close-transition")];
            let members = [(M::None, "none"), (M::Identity, "identity"), (M::Kind, "kind"), (M::Attributes, "attributes"),
                (M::Links, "links"), (M::Creation, "creation"), (M::InitialSize, "initial-size"), (M::Size, "size"),
                (M::Allocation, "allocation"), (M::WriteTime, "write-time"), (M::ChangeTime, "change-time"), (M::Security, "security")];
            let allocations = [(A::None, "none"), (A::BelowSize, "below-size"), (A::Shrank, "shrank"), (A::Grew, "grew")];
            let common = [M::Identity, M::Kind, M::Attributes, M::Links, M::Creation, M::Size, M::WriteTime, M::ChangeTime, M::Security];
            for (edge, edge_label) in edges {
                assert_eq!(edge.label(), edge_label);
                for (member, member_label) in members {
                    assert_eq!(member.label(), member_label);
                    for (allocation, allocation_label) in allocations {
                        assert_eq!(allocation.label(), allocation_label);
                        let allowed = if member == M::Allocation {
                            match edge {
                                E::WriteTransition => allocation == A::BelowSize,
                                E::SourceUnchanged | E::WriterCloseTransition => [A::BelowSize, A::Shrank, A::Grew].contains(&allocation),
                                _ => false,
                            }
                        } else {
                            allocation == A::None && match edge {
                                E::WriteTransition => common.contains(&member) || member == M::InitialSize,
                                E::SourceUnchanged | E::WriterCloseTransition => common.contains(&member),
                                _ => member == M::None,
                            }
                        };
                        let line = PublicationCopyObservation { edge, member, allocation }.diagnostic_line();
                        assert_eq!(line.is_some(), allowed);
                        if let Some(line) = line {
                            assert_eq!(line, format!("MRK_WINDOWS_RUNTIME_PUBLISH_COPY_V1=edge={edge_label};member={member_label};allocation={allocation_label}\n"));
                            assert!(line.is_ascii() && line.len() <= 256 && line.bytes().filter(|b| *b == b'\n').count() == 1);
                        }
                    }
                }
                // Comparison refusals carry members, not a guessed nested edge.
                if [E::WriteTransition, E::SourceUnchanged, E::WriterCloseTransition].contains(&edge) { continue; }
                let first = Cell::new(None);
                for _ in 0..2 { copy_result(Ok(()), &first, edge)?; }
                let value = Box::new(7u8); let address = &*value as *const u8;
                let returned = copy_result(Ok(value), &first, edge)?;
                assert_eq!(&*returned as *const u8, address);
                assert!(first.get().is_none()); // Earlier successful copies leave no edge marker.
                for error in [Error::Unavailable, Error::Unsafe, Error::Bounds, Error::State, Error::Unknown] {
                    let saved = Cell::new(None); let evaluations = Cell::new(0);
                    let result = copy_result({ evaluations.set(evaluations.get() + 1); Err::<u8, _>(error) }, &saved, edge);
                    assert_eq!(result, Err(error)); assert_eq!(evaluations.get(), 1);
                    assert_eq!(saved.get(), if error == Error::Unsafe {
                        Some(PublicationCopyObservation { edge, member: M::None, allocation: A::None })
                    } else { None });
                }
                assert_eq!(copy_result(Err::<(), _>(Error::Unsafe), &first, edge), Err(Error::Unsafe));
                let saved = first.get();
                for later in [E::Order, E::ReadbackOpen] {
                    assert_eq!(copy_result(Err::<(), _>(Error::Unsafe), &first, later), Err(Error::Unsafe));
                    copy_result(Ok(()), &first, later)?;
                    assert_eq!(copy_result(Err::<(), _>(Error::Unknown), &first, later), Err(Error::Unknown));
                    assert_eq!(first.get(), saved);
                }
            }
        }
        {
            use crate::tests::{admission_trace, admission_fault};
            let own = metadata(FileKind::Directory);
            let file = DirectoryEntry { name: "manifest.json".to_owned(), file_id: [1; 16], kind: FileKind::File, attributes: FS::FILE_ATTRIBUTE_ARCHIVE };
            let alias = DirectoryEntry { name: "Manifest.json".to_owned(), ..file.clone() };
            let trace = admission_trace(R::Manifest);
            assert_eq!(selected_entry_in(&[alias.clone()], &file.name, trace.at(O::Directory)), selected_entry(&[alias], &file.name));
            admission_fault(&trace, R::Manifest, O::Directory, C::SelectedCase, Some(0));
            let trace = admission_trace(R::Version);
            let duplicate = [file.clone(), file.clone()];
            assert_eq!(check_entry_frame_in(&duplicate, &own, None, trace.at(O::Directory)), check_entry_frame(&duplicate, &own, None));
            admission_fault(&trace, R::Version, O::Directory, C::EntryDuplicate, Some(1));
            let trace = admission_trace(R::Manifest);
            assert_eq!(selected_entry_in(&duplicate, &file.name, trace.at(O::Directory)), selected_entry(&duplicate, &file.name));
            admission_fault(&trace, R::Manifest, O::Directory, C::SelectedDuplicate, Some(1));
            let trace = admission_trace(R::Manifest);
            assert_eq!(match_entry_in(&file, &own, trace.at(O::Directory)), match_entry(&file, &own));
            admission_fault(&trace, R::Manifest, O::Directory, C::EntryKind, None);
            let trace = admission_trace(R::Python);
            assert_eq!(exact_names_in(&[file.clone()], true, trace.at(O::Inventory)), exact_names(&[file], true));
            admission_fault(&trace, R::Python, O::Inventory, C::RosterName, Some(0));
            let trace = admission_trace(R::Version);
            assert_eq!(exact_names_in(&[], false, trace.at(O::Inventory)), exact_names(&[], false));
            admission_fault(&trace, R::Version, O::Inventory, C::RosterMissing, None);
        }
        need(PUBLICATION_PAYLOADS.len() == 47 && PUBLICATION_PAYLOADS[MANIFEST] == "manifest.json")?;
        need(PUBLICATION_PAYLOADS.windows(2).all(|p| p[0] < p[1]))?;
        need(PUBLICATION_PAYLOADS.iter().filter(|p| p.starts_with("python/")).count() == 38)?;
        for (i, path) in PUBLICATION_PAYLOADS.iter().enumerate() {
            need(path.split('/').all(decode::component) && path.matches('/').count() <= 1)?;
            let image = image_payload(i)?;
            let raw = descriptor(FileKind::File, image, true)?;
            let facts = security::descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion)?;
            exact_security(&facts, FileKind::File, image, true)?;
            let mask = facts.aces[2].mask;
            need((mask & FS::FILE_EXECUTE != 0) == image)?;
            need(mask & (FS::FILE_WRITE_DATA | FS::FILE_APPEND_DATA | FS::FILE_WRITE_EA | FS::FILE_WRITE_ATTRIBUTES
                | FS::DELETE | FS::FILE_DELETE_CHILD | FS::WRITE_DAC | FS::WRITE_OWNER) == 0)?;
        }
        let raw = descriptor(FileKind::Directory, false, true)?;
        exact_security(&security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion)?, FileKind::Directory, false, true)
    }
    #[test]
    fn real_return_classification_never_repairs_a_write_or_invents_a_flush() -> Result<()> {
        let has = Effect::Scalar(S::TokenHasRestrictions);
        let app = Effect::Scalar(S::TokenIsAppContainer);
        // Existing selected inert policy also proves the closed diagnostic
        // vocabulary: input ordinals/classes/return magnitudes never leak.
        for (call, label) in [
            (Call::Architecture, "architecture"), (Call::Folder, "folder"),
            (Call::WindowsDirectory, "windows-directory"), (Call::SystemDirectory, "system-directory"),
            (Call::Mapping, "mapping"), (Call::DriveType, "drive-type"), (Call::Open(usize::MAX), "nt-create"),
            (Call::ProcessToken(usize::MAX), "process-token"), (Call::ThreadToken(usize::MAX), "thread-token"),
            (Call::QualificationSourceToken(usize::MAX), "qualification-source-token"),
            (Call::QualificationRestrictedToken(usize::MAX), "qualification-filtered-token"),
            (Call::Close(usize::MAX), "close"), (Call::Info(FS::FileBasicInfo, usize::MAX), "info-basic"),
            (Call::Info(FS::FileStandardInfo, 0), "info-standard"), (Call::Info(FS::FileAttributeTagInfo, 0), "info-tag"),
            (Call::Info(FS::FileIdInfo, 0), "info-id"), (Call::Info(FS::FileCaseSensitiveInfo, 0), "info-case"),
            (Call::Info(i32::MAX, usize::MAX), "info-other"), (Call::HandleInfo, "handle-info"),
            (Call::FinalName, "final-name"), (Call::FileType, "file-type"), (Call::VolumeName, "volume-name"),
            (Call::VolumeDevice, "volume-device"), (Call::Streams, "streams"), (Call::Security, "security"),
            (Call::Token(S::TokenStatistics), "token-statistics"), (Call::Token(S::TokenType), "token-type"),
            (Call::Token(S::TokenElevation), "token-elevation"), (Call::Token(S::TokenElevationType), "token-elevation-type"),
            (Call::Token(S::TokenUIAccess), "token-ui-access"), (Call::Token(S::TokenVirtualizationEnabled), "token-virtualization"),
            (Call::Token(S::TokenUser), "token-user"), (Call::Token(S::TokenIntegrityLevel), "token-integrity"),
            (Call::Token(S::TokenGroups), "token-groups"), (Call::Token(S::TokenPrivileges), "token-privileges"),
            (Call::Token(i32::MAX), "token-other"), (Call::Read(usize::MAX), "read"), (Call::Entries, "entries"),
        ] { assert_eq!(observed_query(call), label); }
        for name in [PrivilegeName::ChangeNotify, PrivilegeName::Shutdown, PrivilegeName::Undock,
            PrivilegeName::IncreaseWorkingSet, PrivilegeName::TimeZone] {
            assert_eq!(observed_query(Call::Privilege(name)), "privilege");
        }
        for (effect, label) in [(Effect::Directory(usize::MAX), "directory"), (Effect::Writer, "writer"),
            (Effect::Control(false), "control-file"), (Effect::Control(true), "control-directory"),
            (Effect::Write, "write"), (Effect::Flush, "flush"), (Effect::Seal, "seal"),
            (Effect::Scalar(S::TokenHasRestrictions), "has-restrictions"),
            (Effect::Scalar(S::TokenIsAppContainer), "is-app-container"), (Effect::Scalar(i32::MAX), "scalar-other")] {
            assert_eq!(observed_mutation(effect), label);
        }
        for (phase, label) in [(Phase::Prepared, "prepared"), (Phase::Entered, "entered"),
            (Phase::Returned, "returned"), (Phase::Complete, "complete")] { assert_eq!(observed_phase(phase), label); }
        for (refusal, label) in [(None, "none"), (Some(CompletionRefusal::OpenInvalidHandle), "open-invalid-handle"),
            (Some(CompletionRefusal::OpenIoStatus), "open-iosb-status"), (Some(CompletionRefusal::OpenNotOpened), "open-not-opened"),
            (Some(CompletionRefusal::OpenDuplicate), "open-duplicate"), (Some(CompletionRefusal::TokenInvalidHandle), "token-invalid-handle"),
            (Some(CompletionRefusal::TokenDuplicate), "token-duplicate")] { assert_eq!(observed_refusal(refusal), label); }
        for (returned, expected) in [(None, "none"), (Some(Returned::Scalar(0)), "scalar"),
            (Some(Returned::Scalar(u32::MAX)), "scalar"), (Some(Returned::Boolean(0, 0)), "bool-zero:00000000"),
            (Some(Returned::Boolean(1, u32::MAX)), "bool-nonzero:ffffffff"),
            (Some(Returned::Boolean(i32::MIN, 5)), "bool-nonzero:00000005"),
            (Some(Returned::Count(0, F::ERROR_IO_PENDING)), "count-zero:000003e5"),
            (Some(Returned::Count(u32::MAX, 0)), "count-positive:00000000"),
            (Some(Returned::Nt(F::STATUS_PENDING)), "nt:00000103"), (Some(Returned::Nt(0)), "nt:00000000"),
            (Some(Returned::Nt(i32::MIN)), "nt:80000000"), (Some(Returned::Hresult(-1)), "hr:ffffffff"),
            (Some(Returned::Hresult(HRESULT_PENDING)), "hr:8000000a")] {
            let mut line = String::new(); ObservedReturn::from_return(returned).append(&mut line);
            assert_eq!(line, expected);
        }
        assert_eq!(ObservedScalarLength::Unobserved.label(), "none");
        for (count, expected) in [(0, "zero"), (1, "one"), (2, "two"), (3, "three"),
            (4, "four"), (5, "over4"), (u32::MAX - 1, "over4"), (u32::MAX, "sentinel")] {
            for effect in [has, app, Effect::Scalar(i32::MAX), Effect::Flush] {
                let observed = Cell::new(ObservedScalarLength::Unobserved);
                let admitted = match effect {
                    Effect::Scalar(S::TokenHasRestrictions) => matches!(count, 1 | 4),
                    Effect::Scalar(S::TokenIsAppContainer) => count == 4,
                    _ => false,
                };
                assert_eq!(scalar_count_return(effect, count, &observed), if admitted { Ok(()) } else { Err(Error::Unknown) });
                assert_eq!(observed.get().label(), expected);
            }
        }
        assert_eq!(scalar_initial(has).to_ne_bytes(), [0xff, 0, 0, 0]);
        for effect in [app, Effect::Scalar(i32::MAX), Effect::Flush] { assert_eq!(scalar_initial(effect), u32::MAX); }
        let largest = PublicationFrameObservation::from_frames(
            Some((Call::Token(S::TokenVirtualizationEnabled), Phase::Returned,
                Some(Returned::Count(u32::MAX, u32::MAX)), Some(CompletionRefusal::TokenInvalidHandle))),
            Some((Effect::Control(true), Phase::Returned, Some(Returned::Count(u32::MAX, u32::MAX)), ObservedScalarLength::Sentinel)))
            .diagnostic_line().ok_or(Error::State)?;
        assert!(largest.is_ascii() && largest.len() <= 224 && largest.bytes().filter(|b| *b == b'\n').count() == 1);
        assert!(151 + largest.len() <= 375); // Below the unchanged combined512 cap.
        let mut owner = Publication::new(&"d".repeat(64))?;
        let absent = owner.retained_frame_observation();
        assert_eq!(absent, PublicationFrameObservation::from_frames(None, None));
        crate::tests::enter_inert(&mut owner.book, Call::Token(S::TokenElevation), null_mut())?;
        owner.book.arena()?.phase.set(Phase::Returned);
        owner.book.arena()?.returned.set(Some(Returned::Boolean(1, 0)));
        // This fixture never enters mutate/invoke. Invalid returns must leave
        // its raw output storage unobserved; snapshots copy only retained DATA.
        let mutation = |effect, phase, returned| ManuallyDrop::new(Box::pin(Mutation {
            effect, phase: Cell::new(phase),
            returned: Cell::new(returned), slot: None,
            length_observation: Cell::new(ObservedScalarLength::Unobserved),
            path: Vec::new(), descriptor: UnsafeCell::new(Aligned([0; BUFFER])), attributes: S::SECURITY_ATTRIBUTES::default(),
            handle: null_mut(), output: null_mut(), data: Vec::new(), count: UnsafeCell::new(u32::MAX),
            scalar: UnsafeCell::new(scalar_initial(effect)), _pin: PhantomPinned,
        }));
        owner.mutation = Some(mutation(has, Phase::Returned, Some(Returned::Boolean(0, F::ERROR_IO_PENDING))));
        let saved = owner.retained_frame_observation();
        assert_eq!(saved.diagnostic_line().as_deref(), Some("MRK_WINDOWS_RUNTIME_PUBLISH_FRAME_V2=qcall=token-elevation;qphase=returned;qret=bool-nonzero:00000000;qrefusal=none;mcall=has-restrictions;mphase=returned;mret=bool-zero:000003e5;mcount=none\n"));
        owner.book.arena()?.returned.set(Some(Returned::Boolean(0, 5)));
        assert_ne!(saved, owner.retained_frame_observation());
        for (phase, returned, expected) in [
            (Phase::Prepared, Some(Returned::Boolean(1, 0)), Error::Unknown),
            (Phase::Entered, Some(Returned::Boolean(1, 0)), Error::Unknown),
            (Phase::Complete, Some(Returned::Boolean(1, 0)), Error::Unknown),
            (Phase::Returned, None, Error::Unknown),
            (Phase::Returned, Some(Returned::Scalar(0)), Error::Unknown),
            (Phase::Returned, Some(Returned::Count(4, 0)), Error::Unknown),
            (Phase::Returned, Some(Returned::Nt(0)), Error::Unknown),
            (Phase::Returned, Some(Returned::Hresult(0)), Error::Unknown),
            (Phase::Returned, Some(Returned::Boolean(0, 0)), Error::Unknown),
            (Phase::Returned, Some(Returned::Boolean(0, F::ERROR_IO_PENDING)), Error::Unknown),
            (Phase::Returned, Some(Returned::Boolean(1, F::ERROR_ACCESS_DENIED)), Error::Unknown),
            (Phase::Returned, Some(Returned::Boolean(0, F::ERROR_ACCESS_DENIED)), Error::Unavailable),
        ] {
            let mut refused = Publication::new(&"d".repeat(64))?;
            refused.mutation = Some(mutation(has, phase, returned));
            assert_eq!(refused.finish_mutation().err(), Some(expected));
            assert_eq!(refused.retained_frame_observation().mcount, ObservedScalarLength::Unobserved);
            // Drop only this never-native test arena; an actual Unknown is retained.
            if let Some(frame) = refused.mutation.take() { drop(ManuallyDrop::into_inner(frame)); }
        }
        let frame = owner.mutation.as_ref().ok_or(Error::State)?.as_ref().get_ref();
        frame.returned.set(Some(Returned::Boolean(1, 0)));
        assert_eq!(scalar_count_return(has, 2, &frame.length_observation), Err(Error::Unknown));
        let length_saved = owner.retained_frame_observation();
        assert_eq!(length_saved.mcount, ObservedScalarLength::Two);
        assert!(length_saved.diagnostic_line().ok_or(Error::State)?.ends_with(";mcount=two\n"));
        // Pure DATA classification, not a second native call. The new argument
        // still drives class-local refusal while the first category stays fixed.
        assert_eq!(scalar_count_return(has, 4, &frame.length_observation), Ok(()));
        assert_eq!(scalar_count_return(has, 1, &frame.length_observation), Ok(()));
        assert_eq!(scalar_count_return(app, 1, &frame.length_observation), Err(Error::Unknown));
        assert_eq!(scalar_count_return(has, 3, &frame.length_observation), Err(Error::Unknown));
        assert_eq!(length_saved, owner.retained_frame_observation());
        // Release only the two never-native fixture allocations, not live owners.
        drop(ManuallyDrop::into_inner(owner.book.active.take().ok_or(Error::State)?));
        drop(ManuallyDrop::into_inner(owner.mutation.take().ok_or(Error::State)?));
        assert_eq!(owner.retained_frame_observation(), absent);
        assert_eq!(length_saved.mcount, ObservedScalarLength::Two);
        assert_eq!(saved.qret, ObservedReturn::from_return(Some(Returned::Boolean(1, 0))));
        // Only never-native fixtures write these initialized objects. A short
        // fixture write models one possibility, never an observed OS extent.
        for effect in [has, app, Effect::Scalar(i32::MAX)] {
            for count in [0, 1, 2, 3, 4, 5, u32::MAX] {
                for (written, bytes) in [(0, [0u8; 4]), (1, [0; 4]), (4, [0; 4]),
                    (1, [1, 0, 0, 0]), (1, [0xff, 0, 0, 0]),
                    (4, [0, 1, 0, 0]), (4, [0, 0, 0, 1])] {
                    let mut fixture = Publication::new(&"d".repeat(64))?;
                    fixture.book.admission.active.set(true);
                    fixture.book.admission.role.set(if matches!(effect, Effect::Scalar(S::TokenHasRestrictions)) { R::Restrictions } else { R::AppContainer });
                    fixture.mutation = Some(mutation(effect, Phase::Returned, Some(Returned::Boolean(1, 0))));
                    let frame = fixture.mutation.as_ref().ok_or(Error::State)?.as_ref().get_ref();
                    let mut expected = scalar_initial(effect).to_ne_bytes();
                    expected[..written].copy_from_slice(&bytes[..written]);
                    // SAFETY: this pinned fixture has never entered native code.
                    unsafe {
                        *frame.count.get() = count;
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), frame.scalar.get().cast::<u8>(), written);
                    }
                    let allowed = match effect {
                        Effect::Scalar(S::TokenHasRestrictions) => matches!(count, 1 | 4),
                        Effect::Scalar(S::TokenIsAppContainer) => count == 4,
                        _ => false,
                    };
                    if allowed {
                        let complete = fixture.finish_mutation()?;
                        assert_eq!(complete.frame.length_observation.get(), ObservedScalarLength::from_count(count));
                        let trace = fixture.book.admission.at(O::Scalar);
                        let value = trace.result(complete.scalar(), C::ScalarCompletion)?; // the production one-read consumer
                        assert_eq!(value, u32::from_ne_bytes(expected));
                        assert_eq!(trace.result(scalar_value(value), C::ScalarCanonical), if value <= 1 { Ok(value) } else { Err(Error::Unsafe) });
                        if value > 1 {
                            crate::tests::admission_fault(&fixture.book.admission, fixture.book.admission.role.get(), O::Scalar, C::ScalarCanonical, None);
                        } else { assert!(fixture.retained_admission_observation().is_none()); }
                        assert_eq!(scalar_value(value).is_ok_and(|v| v == 0), expected == [0; 4]);
                        assert!(fixture.mutation.is_none() && !fixture.book.is_unknown());
                    } else {
                        assert_eq!(fixture.finish_mutation().err(), Some(Error::Unknown));
                        assert!(fixture.retained_admission_observation().is_none());
                        assert!(fixture.book.is_unknown() && fixture.mutation.is_some());
                        assert_eq!(fixture.retained_frame_observation().mcount, ObservedScalarLength::from_count(count));
                        // No scalar consumer exists on the failed completion.
                        drop(ManuallyDrop::into_inner(fixture.mutation.take().ok_or(Error::State)?));
                    }
                }
            }
        }
        need(write_return(1, 0, 4, 4).is_ok())?;
        for count in [0, 1, 3] { need(write_return(1, 0, count, 4) == Err(Error::Unsafe))?; }
        need(write_return(1, 0, 5, 4) == Err(Error::Unknown))?;
        need(mutation_return(0, F::ERROR_ACCESS_DENIED) == Err(Error::Unavailable))?;
        need(mutation_return(0, 0) == Err(Error::Unknown))?;
        need(mutation_return(0, F::ERROR_IO_PENDING) == Err(Error::Unknown))?;
        need(mutation_return(1, F::ERROR_ACCESS_DENIED) == Err(Error::Unknown))
    }
    #[test]
    fn collision_never_adopts_and_only_known_closed_originals_allow_later_roles() -> Result<()> {
        need(mutation_return(0, F::ERROR_ALREADY_EXISTS) == Err(Error::Unavailable))?;
        need(mutation_return(0, F::ERROR_FILE_EXISTS) == Err(Error::Unavailable))?;
        need(later_originals_closed([SlotState::Closed, SlotState::Closed]))?;
        for state in [SlotState::Reserved, SlotState::Acquiring, SlotState::Owned, SlotState::NoHandle,
            SlotState::Closing, SlotState::Unknown] {
            need(!later_originals_closed([SlotState::Closed, state]))?;
        }
        need(!later_originals_closed([]))?;
        let valid = occupied_owner()?;
        need(valid.occupied_target_and_settled())?;
        for case in 0..37 {
            let mut owner = occupied_owner()?;
            match case {
                0 => owner.target_creation = None,
                1 => owner.target_creation.as_mut().ok_or(Error::State)?.intent = 1,
                2 => owner.creations[0].parent = 1,
                3 => owner.creations[0].path.push_str("\\python"),
                4 => owner.creations[0].entered = false,
                5 => owner.creations[0].returned = None,
                6 => owner.creations[0].returned = Some((0, F::ERROR_FILE_EXISTS)),
                7 => owner.creations[0].returned = Some((0, F::ERROR_ACCESS_DENIED)),
                8 => owner.creations[0].returned = Some((0, F::ERROR_IO_PENDING)),
                9 => owner.creations[0].returned = Some((1, F::ERROR_ALREADY_EXISTS)),
                10 => owner.creations[0].returned = Some((1, 0)),
                11 => owner.book.retiring = false,
                12 => owner.book.unknown = true,
                13 => owner.settlement_attempted = false,
                14 => owner.end = Instant::now(),
                15 => owner.order.grant_attempted = true,
                16 => owner.order.copies = 1,
                17 => owner.version = Some(3),
                18 => owner.directories[1].created = true,
                19 => owner.target_creation.as_mut().ok_or(Error::State)?.parent = 1,
                20 => owner.creations.push(Creation { path: "other".to_owned(), parent: 0,
                    entered: true, returned: Some((1, 0)) }),
                21 => owner.expired = true,
                22 => owner.order.unknown = true,
                23 => owner.order.stage = Stage::Copying,
                24 => owner.order.sealed_files = 1,
                25 => owner.order.inventories = true,
                26 => owner.order.python_closed = true,
                27 => owner.order.exposure = true,
                28 => owner.python = Some(2),
                29 => owner.output_dirs.push(2),
                30 => owner.target_creation.as_mut().ok_or(Error::State)?.versions = 0,
                31 => owner.target_creation.as_mut().ok_or(Error::State)?.path.push_str("\\source-input"),
                32 => owner.creations[0].returned = Some((0, 0)),
                33 => owner.mrk = None,
                34 => owner.directories[1].parent = None,
                35 => owner.directories[2].dos.push_str("-other"),
                _ => owner.order.failed = false,
            }
            need(!owner.occupied_target_and_settled())?;
        }
        Ok(())
    }
    fn occupied_owner() -> Result<Publication> {
        // Bounded policy DATA only: no invented HANDLE or native operation.
        // Exercise the very same predicate as the fixed entry after settlement.
        let mut owner = Publication::new(&"a".repeat(64))?;
        let paths = [r"C:\Program Files\Mobile Release Kit".to_owned(),
            r"C:\Program Files\Mobile Release Kit\versions".to_owned(),
            format!(r"C:\Program Files\Mobile Release Kit\versions\{TARGET}")];
        let raw = descriptor(FileKind::Directory, false, true)?;
        let facts = Facts { metadata: metadata(FileKind::Directory),
            security: security::descriptor(&raw, FileKind::Directory, AuthorityScope::AncestorOutsideVersion)? };
        for (i, dos) in paths.into_iter().enumerate() {
            owner.directories.push(Directory { role: R::Owner, initial: i, control: None, parent: i.checked_sub(1), dos,
                scope: AuthorityScope::AncestorOutsideVersion, facts: facts.clone(), entries: None, created: false });
        }
        let path = owner.child_path(2, &owner.digest)?;
        owner.target_creation = Some(TargetCreation { intent: 0, versions: 1, parent: 2, path: path.clone() });
        owner.creations.push(Creation { path, parent: 2, entered: true, returned: Some((0, F::ERROR_ALREADY_EXISTS)) });
        owner.mrk = Some(0); owner.order.stage = Stage::Manifest; owner.order.failed = true;
        owner.settlement_attempted = true; owner.book.retiring = true;
        Ok(owner)
    }
    fn proof() -> CopyProof { CopyProof { source_eof: true, flushed: true, writer_closed: true, source_closed: true, readback_eof: true, readback_closed: true } }
    #[test]
    fn live_order_requires_all_original_closures_and_never_relabels_exposure() -> Result<()> {
        for missing in 0..6 {
            let mut order = Order::new(); order.stage = Stage::Copying;
            let mut bad = proof();
            match missing { 0 => bad.source_eof = false, 1 => bad.flushed = false, 2 => bad.writer_closed = false,
                3 => bad.source_closed = false, 4 => bad.readback_eof = false, _ => bad.readback_closed = false }
            need(order.copied(0, bad).is_err() && order.seal().is_err() && order.expose().is_err())?;
        }
        let mut order = Order::new(); order.stage = Stage::Copying;
        for i in 0..47 { order.copied(i, proof())?; }
        need(order.seal().is_err())?; order.inventories = true; order.seal()?;
        need(order.expose().is_err())?; order.sealed_files = 47;
        need(order.expose().is_err())?; order.python_closed = true; order.expose()?;
        need(order.completed(true).is_err())?; order.stage = Stage::RootClosed;
        need(order.completed(false).is_err())?; order.completed(true)?;
        for after in [false, true] {
            let mut order = Order::new();
            if after { order.stage = Stage::ExposureAttempted; order.exposure = true; }
            order.fail(true); order.fail(false);
            need(order.unknown && order.exposure == after && order.expose().is_err() && order.completed(true).is_err())?;
        }
        Ok(())
    }
    fn metadata(kind: FileKind) -> Metadata {
        Metadata { identity: FileIdentity { volume_serial: 1, file_id: [1; 16] }, kind,
            attributes: if kind == FileKind::Directory { FS::FILE_ATTRIBUTE_DIRECTORY } else { FS::FILE_ATTRIBUTE_ARCHIVE },
            size: 0, allocation_size: 0, links: 1, creation: 1, write: 1, change: 1 }
    }
    #[test]
    fn intentional_transitions_do_not_hide_identity_or_immutable_drift() -> Result<()> {
        let file = metadata(FileKind::File); let mut written = file.clone();
        written.size = 4; written.allocation_size = 4096; written.write = 2; written.change = 2;
        need(write_transition(&file, &written, 4))?;
        let mut closed = written.clone(); closed.write = 3; closed.change = 3;
        need(writer_close_transition(&written, &closed))?;
        let mut sealed = closed.clone(); sealed.change = 4; need(acl_transition(&closed, &sealed))?;
        sealed.write += 1; need(!acl_transition(&closed, &sealed))?;
        {
            use CopyEdge as E; use CopyMember as M; use CopyAllocation as A;
            let security = security::descriptor(&descriptor(FileKind::File, false, false)?, FileKind::File, AuthorityScope::ImmutableVersion)?;
            let initial = Facts { metadata: file.clone(), security: security.clone() };
            let copied = Facts { metadata: written.clone(), security: security.clone() };
            let readback = Facts { metadata: closed.clone(), security };
            let observe = |edge, before: &Facts, after: &Facts, first: &Cell<Option<PublicationCopyObservation>>| {
                let trace = Some(CopyRefusal { first, edge });
                match edge {
                    E::WriteTransition => write_transition_observed(&before.metadata, &after.metadata, 4, trace)
                        && copy_guard(before.security == after.security, M::Security, trace),
                    E::WriterCloseTransition => writer_close_transition_observed(&before.metadata, &after.metadata, trace)
                        && copy_guard(before.security == after.security, M::Security, trace),
                    E::SourceUnchanged => source_unchanged_observed(after, before, trace),
                    _ => unreachable!(),
                }
            };
            let plain = |edge, before: &Facts, after: &Facts| match edge {
                E::WriteTransition => write_transition(&before.metadata, &after.metadata, 4) && before.security == after.security,
                E::WriterCloseTransition => writer_close_transition(&before.metadata, &after.metadata) && before.security == after.security,
                E::SourceUnchanged => after == before,
                _ => unreachable!(),
            };
            let drift = |member, before: &mut Facts, after: &mut Facts| match member {
                M::Identity => after.metadata.identity.file_id = [2; 16], M::Kind => after.metadata.kind = FileKind::Directory,
                M::Attributes => after.metadata.attributes ^= FS::FILE_ATTRIBUTE_HIDDEN, M::Links => after.metadata.links += 1,
                M::Creation => after.metadata.creation += 1, M::InitialSize => before.metadata.size = 1,
                M::Size => after.metadata.size += 1, M::Allocation => after.metadata.allocation_size = 0,
                M::WriteTime => after.metadata.write = 0, M::ChangeTime => after.metadata.change = 0,
                M::Security => after.security.revision ^= 1, M::None => unreachable!(),
            };
            let write_members = [M::Identity, M::Kind, M::Attributes, M::Links, M::Creation, M::InitialSize,
                M::Size, M::Allocation, M::WriteTime, M::ChangeTime, M::Security];
            let close_members = [M::Identity, M::Kind, M::Attributes, M::Links, M::Creation,
                M::Size, M::Allocation, M::WriteTime, M::ChangeTime, M::Security];
            let source_members = [M::Identity, M::Kind, M::Attributes, M::Size, M::Allocation,
                M::Links, M::Creation, M::WriteTime, M::ChangeTime, M::Security];
            for edge in [E::WriteTransition, E::WriterCloseTransition, E::SourceUnchanged] {
                let (before, after, members): (&Facts, &Facts, &[M]) = match edge {
                    E::WriteTransition => (&initial, &copied, &write_members),
                    E::WriterCloseTransition => (&copied, &readback, &close_members),
                    E::SourceUnchanged => (&copied, &copied, &source_members),
                    _ => unreachable!(),
                };
                let first = Cell::new(None);
                for _ in 0..2 {
                    assert!(observe(edge, before, after, &first));
                    assert!(plain(edge, before, after)); assert!(first.get().is_none());
                }
                for (position, member) in members.iter().copied().enumerate() {
                    for simultaneous in [false, true] {
                        let (mut a, mut b) = (before.clone(), after.clone());
                        drift(member, &mut a, &mut b);
                        if simultaneous { for later in &members[position + 1..] { drift(*later, &mut a, &mut b); } }
                        let first = Cell::new(None);
                        let result = need(observe(edge, &a, &b, &first));
                        assert_eq!(result, need(plain(edge, &a, &b))); assert_eq!(result, Err(Error::Unsafe));
                        assert_eq!(first.get(), Some(PublicationCopyObservation { edge, member,
                            allocation: if member == M::Allocation { A::BelowSize } else { A::None } }));
                    }
                }
                if edge != E::SourceUnchanged {
                    let (mut a, mut b) = (before.clone(), after.clone());
                    a.metadata.kind = FileKind::Directory; b.metadata.kind = FileKind::Directory;
                    for (links, member) in [(1, M::Kind), (2, M::Links)] {
                        b.metadata.links = links;
                        let first = Cell::new(None);
                        assert!(!observe(edge, &a, &b, &first)); assert!(!plain(edge, &a, &b));
                        assert_eq!(first.get(), Some(PublicationCopyObservation { edge, member, allocation: A::None }));
                    }
                }
            }
            // Allocation contraction/growth remains a refusal, not a new policy.
            // A growing allocation still labels below-size when that relation wins.
            for (size, old, new, allocation) in [(4, 4096, 3, A::BelowSize), (4, 4096, 4, A::Shrank),
                (4, 4096, 4095, A::Shrank), (4, 4096, 4097, A::Grew), (4, 2, 3, A::BelowSize),
                (0, 1, 0, A::Shrank), (0, 0, 1, A::Grew), (u64::MAX, u64::MAX, u64::MAX - 1, A::BelowSize),
                (u64::MAX - 1, u64::MAX - 1, u64::MAX, A::Grew)] {
                for edge in [E::SourceUnchanged, E::WriterCloseTransition] {
                    let (mut a, mut b) = (copied.clone(), copied.clone());
                    a.metadata.size = size; b.metadata.size = size;
                    a.metadata.allocation_size = old; b.metadata.allocation_size = new;
                    let first = Cell::new(None);
                    assert_eq!(need(observe(edge, &a, &b, &first)), Err(Error::Unsafe));
                    assert!(!plain(edge, &a, &b));
                    assert_eq!(first.get(), Some(PublicationCopyObservation { edge, member: M::Allocation, allocation }));
                }
            }
            for (size, allocation) in [(0, 0), (4, 0), (4, 4096), (u64::MAX, u64::MAX)] {
                let mut a = copied.clone(); a.metadata.size = size; a.metadata.allocation_size = allocation;
                for edge in [E::SourceUnchanged, E::WriterCloseTransition] {
                    let first = Cell::new(None);
                    assert!(observe(edge, &a, &a, &first)); assert!(plain(edge, &a, &a)); assert!(first.get().is_none());
                }
            }
            for (size, allocation, accepted) in [(0, 0, true), (4, 3, false), (4, 4, true),
                (u64::MAX, u64::MAX, true), (u64::MAX, u64::MAX - 1, false)] {
                let mut b = written.clone(); b.size = size; b.allocation_size = allocation;
                let first = Cell::new(None);
                let result = write_transition_observed(&file, &b, size, Some(CopyRefusal { first: &first, edge: E::WriteTransition }));
                assert_eq!(result, write_transition(&file, &b, size)); assert_eq!(result, accepted);
                assert_eq!(first.get(), if accepted { None } else {
                    Some(PublicationCopyObservation { edge: E::WriteTransition, member: M::Allocation, allocation: A::BelowSize })
                });
            }
            let first = Cell::new(None); let classifications = Cell::new(0);
            let trace = Some(CopyRefusal { first: &first, edge: E::WriterCloseTransition });
            let classify = || { classifications.set(classifications.get() + 1); A::Grew };
            assert!(copy_allocation_guard(true, trace, &classify));
            assert!(!copy_allocation_guard(false, None, &classify));
            assert_eq!(classifications.get(), 0); assert!(first.get().is_none());
            assert!(!copy_guard(false, M::Size, trace));
            let saved = first.get();
            assert!(!copy_allocation_guard(false, trace, &classify));
            assert_eq!(classifications.get(), 0); assert_eq!(first.get(), saved);
            let fresh = Cell::new(None);
            assert!(!copy_allocation_guard(false, Some(CopyRefusal { first: &fresh, edge: E::WriterCloseTransition }), &classify));
            assert_eq!(classifications.get(), 1);
        }
        written.identity.file_id = [2; 16]; need(!write_transition(&file, &written, 4))?;
        let directory = metadata(FileKind::Directory); let mut child = directory.clone();
        child.size = 64; child.allocation_size = 4096; child.write = 2; child.change = 2;
        need(child_transition(&directory, &child))?; child.links = 2;
        need(!child_transition(&directory, &child))
    }
    #[test]
    fn original_unknown_retains_mutation_storage_without_close_retry() -> Result<()> {
        let mut owner = Publication::new(&"a".repeat(64))?;
        owner.book.admission.active.set(true); owner.book.admission.role.set(R::Restrictions);
        assert_eq!(owner.book.admission.at(O::Scalar).result(scalar_value(2), C::ScalarCanonical), Err(Error::Unsafe));
        let first = owner.retained_admission_observation();
        owner.book.admission.active.set(false);
        assert!(owner.retained_copy_observation().is_none());
        assert_eq!(copy_result(Err::<(), _>(Error::Unsafe), &owner.copy_failure, CopyEdge::WriterCheck), Err(Error::Unsafe));
        let copy = owner.retained_copy_observation();
        let copy_line = copy.and_then(PublicationCopyObservation::diagnostic_line);
        owner.mutation = Some(ManuallyDrop::new(Box::pin(Mutation { effect: Effect::Flush,
            phase: Cell::new(Phase::Entered), returned: Cell::new(None), slot: None, path: Vec::new(),
            length_observation: Cell::new(ObservedScalarLength::Unobserved),
            descriptor: UnsafeCell::new(Aligned([0; BUFFER])), attributes: S::SECURITY_ATTRIBUTES::default(),
            handle: null_mut(), output: null_mut(), data: Vec::new(), count: UnsafeCell::new(u32::MAX), scalar: UnsafeCell::new(scalar_initial(Effect::Flush)), _pin: PhantomPinned })));
        // Pure ownership control: no fabricated HANDLE and no native call.
        need(owner.fail_and_settle_once() == CloseOutcome::Unknown && owner.mutation.is_some())?;
        need(owner.fail_and_settle_once() == CloseOutcome::Unknown && owner.mutation.is_some())?;
        assert_eq!(owner.retained_admission_observation(), first);
        need(!owner.published_and_settled() && !owner.occupied_target_and_settled()
            && owner.ready() == Err(Error::Unknown))?;
        assert_eq!(owner.finish_copy(), Err(Error::Unknown));
        assert_eq!(copy_result(Err::<(), _>(Error::Unsafe), &owner.copy_failure, CopyEdge::ReadbackOpen), Err(Error::Unsafe));
        assert_eq!(owner.retained_copy_observation(), copy);
        assert_eq!(copy.and_then(PublicationCopyObservation::diagnostic_line), copy_line);
        assert!(owner.mutation.is_some());
        Ok(())
    }
    #[test]
    fn even_the_first_descendant_grant_is_possibly_exposed_on_failure() -> Result<()> {
        let mut owner = Publication::new(&"a".repeat(64))?;
        need(!owner.possibly_exposed())?;
        owner.order.grant_attempted = true; owner.order.fail(false);
        need(owner.possibly_exposed() && !owner.order.exposure && owner.order.sealed_files == 0
            && !owner.published_and_settled())
    }
}

// Real native proof is a separate, explicitly ignored selector. Never place it
// in publication::tests or call it from the inert/source preflight route.
#[cfg(test)]
mod scalar_qualification {
    use super::*;
    use crate::qualification_fixture as fixture;
    use crate::qualification_result::{args_are, decimal, diagnostic_data, fixed_path, is_hex, write_fixture_record, LIMIT};

    const TEST: &str = "publication::scalar_qualification::hosted_has_restrictions_false_only_contract";
    const RESULT: &str = "producer-scalar-result.private.txt";
    const HEADER: &str = "MRK_WINDOWS_HAS_RESTRICTIONS_QUALIFICATION_V1";
    const FIELDS: [&str; 25] = ["profile", "sourceSha", "sourceTree", "runId", "attempt", "qualifierTest",
        "artifactSha256", "precheckSha256", "commandSha256", "sourceReturn", "sourceCount", "sourceValue", "sourceAdmitted",
        "derivedReturn", "derivedCount", "derivedValue", "derivedAdmitted", "createCalls", "filterFlags", "restrictingSidInputs",
        "tokenOriginals", "tokenOriginalsClosed", "parentBookSettled", "unknown", "resultCloseGate"];

    struct ScalarFact { length: ObservedScalarLength, zero: bool, admitted: bool }
    fn observe(original: &mut Publication, index: usize) -> Result<ScalarFact> {
        let complete = original.mutate(Effect::Scalar(S::TokenHasRestrictions), Some(index), "", &[], Vec::new())?;
        need(matches!(complete.frame.returned.get(), Some(Returned::Boolean(v, 0)) if v != 0))?;
        let length = complete.frame.length_observation.get(); // no second raw count read
        let value = complete.scalar()?; // SAME completed typed-object read as production
        let admitted = match scalar_value(value) {
            Ok(flag) => flag == 0,
            Err(Error::Unsafe) if value > 1 => false, // real noncanonical nonzero, not an arbitrary query failure
            _ => return Err(Error::Unknown),
        };
        Ok(ScalarFact { length, zero: value == 0, admitted })
    }

    #[test]
    #[ignore = "same-call count-one false and actual filtered-token refusal; fixed disposable production verification only"]
    fn hosted_has_restrictions_false_only_contract() -> Result<()> {
        fixture::profile()?;
        need(fixture::active_profile()? == fixture::PRODUCTION_PROFILE)?;
        fixture::outcome("MRK_WINDOWS_ORDINARY_PREFLIGHT_STEP_OUTCOME")?;
        let root = fixed_path(&std::env::var("MRK_DESKTOP_CI_ROOT").map_err(|_| Error::State)?)?;
        let temp = fixed_path(&std::env::var("RUNNER_TEMP").map_err(|_| Error::State)?)?;
        let run = std::env::var("GITHUB_RUN_ID").map_err(|_| Error::State)?;
        need(decimal(&run) && root == temp.join(format!("mrk-windows-installed-native-{run}-1"))
            && std::env::current_dir().map_err(|_| Error::Unavailable)? == root)?;
        let image = std::env::current_exe().map_err(|_| Error::Unavailable)?;
        args_are(TEST, &image)?;
        let artifact = fixed_path(&std::env::var("MRK_WINDOWS_NATIVE_ARTIFACT").map_err(|_| Error::State)?)?;
        let leaf = artifact.file_name().and_then(|v| v.to_str()).ok_or(Error::Unsafe)?;
        need(image == artifact && artifact.parent() == Some(root.join("target").join(TARGET).join("debug").join("deps").as_path())
            && leaf.strip_prefix("mrk_windows_installed_native-").and_then(|v| v.strip_suffix(".exe")).is_some_and(|v| is_hex(v, 16)))?;
        let mut record = fixture::Wire { values: BTreeMap::new() };
        for (key, value) in [("profile", fixture::PRODUCTION_PROFILE), ("sourceSha", option_env!("GITHUB_SHA").ok_or(Error::State)?),
            ("sourceTree", option_env!("MRK_WINDOWS_SOURCE_TREE").ok_or(Error::State)?), ("runId", run.as_str()),
            ("attempt", "1"), ("qualifierTest", TEST)] { record.put(key, value); }
        for (key, name) in [("artifactSha256", "MRK_WINDOWS_NATIVE_ARTIFACT_SHA256"), ("precheckSha256", "MRK_WINDOWS_PRECHECK_SHA256")] {
            let value = std::env::var(name).map_err(|_| Error::State)?;
            need(is_hex(&value, 64))?; record.put(key, value);
        }
        record.binding()?;
        record.put("commandSha256", fixture::command_sha(artifact.to_str().ok_or(Error::Unsafe)?, TEST)?);
        let mut original = Publication::new(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or(Error::State)?)?;
        let mut create_calls = 0usize;
        // No early return/panic can skip the single settlement of both ORIGINAL
        // token slots. No local HANDLE is acquired and adopted after entry.
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(ScalarFact, ScalarFact)> {
            let source = original.book.reserve(Kind::ProcessToken, None, "", String::new())?;
            let acquired = original.book.call(Call::QualificationSourceToken(source.index), null_mut(), Vec::new())?;
            need(matches!(acquired.arena.returned()?, Returned::Boolean(v, 0) if v != 0))?;
            let source_fact = observe(&mut original, source.index)?;
            // Count4-only evidence does not reproduce the observed count1 case.
            need(source_fact.length == ObservedScalarLength::One && source_fact.zero && source_fact.admitted)?;
            let derived = original.book.reserve(Kind::ProcessToken, Some(source.index), "", String::new())?;
            let source_handle = original.book.handle(source.index)?;
            create_calls += 1;
            let created = original.book.call(Call::QualificationRestrictedToken(derived.index), source_handle, Vec::new())?;
            need(matches!(created.arena.returned()?, Returned::Boolean(v, 0) if v != 0))?;
            let derived_fact = observe(&mut original, derived.index)?;
            need(matches!(derived_fact.length, ObservedScalarLength::One | ObservedScalarLength::Four)
                && !derived_fact.zero && !derived_fact.admitted)?;
            Ok((source_fact, derived_fact))
        })).unwrap_or(Err(Error::Unknown));
        let owned = original.book.slots.iter().filter(|s| s.state == SlotState::Owned).count();
        if matches!(observed, Err(Error::Unknown)) { original.book.mark_interrupted(); }
        let settlement = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| original.fail_and_settle_once()))
            .unwrap_or(CloseOutcome::Unknown);
        if settlement != CloseOutcome::Settled || !original.book.settled() || original.book.is_unknown() {
            diagnostic_data("scalar-qualification-original-settlement", None, true, None);
            loop { std::thread::park(); std::hint::black_box(&mut original); }
        }
        let (source, derived) = observed?;
        let closed = original.book.slots.iter().filter(|s| s.state == SlotState::Closed).count();
        need(create_calls == 1 && owned == 2 && closed == owned && original.book.slots.len() == 2)?;
        for (prefix, actual) in [("source", source), ("derived", derived)] {
            record.put(&format!("{prefix}Return"), "bool-nonzero");
            record.put(&format!("{prefix}Count"), actual.length.label());
            record.put(&format!("{prefix}Value"), if actual.zero { "zero" } else { "nonzero" });
            record.put(&format!("{prefix}Admitted"), actual.admitted);
        }
        record.put("createCalls", create_calls); record.put("filterFlags", S::DISABLE_MAX_PRIVILEGE);
        record.put("restrictingSidInputs", 0); record.put("tokenOriginals", owned); record.put("tokenOriginalsClosed", closed);
        record.put("parentBookSettled", original.book.settled()); record.put("unknown", original.book.is_unknown());
        record.put("resultCloseGate", "original-scalar-exit-zero-required");
        let raw = record.encoded(HEADER, &FIELDS, LIMIT)?;
        original.tick()?;
        // Reuse the existing pinned, create-new, one-write original receipt
        // writer and explicit close. Unknown retains its owning stack too.
        write_fixture_record(&root.join(RESULT), &raw, LIMIT, original.end)?;
        original.tick()
    }
}
