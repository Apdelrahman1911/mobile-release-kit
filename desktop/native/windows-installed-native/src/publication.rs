//! Fixed privileged package producer. This is not an installed-runtime owner.
//!
//! The safe executable registers this actual object in a process-lifetime
//! OnceLock<Mutex<_>> BEFORE admit_once. No worker, callback, cleanup, retry,
//! privilege adjustment, child process or destructor supplies native finality.
//! SHA256/strict manifest policy remains in the safe application; the only data
//! interface here is the fixed roster, bounded sizes and original byte chunks.
use super::*;
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
    a.identity == b.identity && a.kind == b.kind && a.attributes == b.attributes
        && a.links == b.links && a.creation == b.creation
}
fn child_transition(a: &Metadata, b: &Metadata) -> bool {
    // Used ONLY immediately after one recorded successful exclusive child create.
    // Directory index allocation/size can change in either direction on NTFS.
    same_object(a, b) && a.kind == FileKind::Directory && b.write >= a.write && b.change >= a.change
}
fn write_transition(a: &Metadata, b: &Metadata, size: u64) -> bool {
    same_object(a, b) && a.kind == FileKind::File && a.size == 0
        && b.size == size && b.allocation_size >= size && b.write >= a.write && b.change >= a.change
}
fn writer_close_transition(a: &Metadata, b: &Metadata) -> bool {
    same_object(a, b) && a.kind == FileKind::File && a.size == b.size && a.allocation_size == b.allocation_size
        && b.write >= a.write && b.change >= a.change
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
fn pointed_sid(raw: &[u8], field: usize, minimum: usize) -> Result<Sid> {
    let pointer = usize::try_from(decode::u64_at(raw, field)?).map_err(|_| Error::Unsafe)?;
    let at = pointer.checked_sub(raw.as_ptr() as usize).ok_or(Error::Unsafe)?;
    need(at >= minimum && at % 4 == 0)?;
    security::sid_at(raw, at, raw.len()) // no unvalidated pointer dereference
}
fn installer_groups(raw: &[u8], count: u32) -> Result<Vec<GroupFact>> {
    let header = offset_of!(S::TOKEN_GROUPS, Groups);
    need(count <= 256 && raw.len() <= BUFFER && decode::u32_at(raw, 0)? == count)?;
    let extent = header.checked_add(count as usize * size_of::<S::SID_AND_ATTRIBUTES>()).ok_or(Error::Bounds)?;
    decode::span(raw, 0, extent)?;
    let known = (SS::SE_GROUP_MANDATORY | SS::SE_GROUP_ENABLED_BY_DEFAULT | SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER
        | SS::SE_GROUP_USE_FOR_DENY_ONLY | SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED
        | SS::SE_GROUP_RESOURCE | SS::SE_GROUP_LOGON_ID) as u32;
    let mut result: Vec<GroupFact> = Vec::new();
    for i in 0..count as usize {
        let base = header + i * size_of::<S::SID_AND_ATTRIBUTES>();
        let principal = pointed_sid(raw, base + offset_of!(S::SID_AND_ATTRIBUTES, Sid), extent)?;
        let attributes = decode::u32_at(raw, base + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))?;
        need(attributes & !known == 0
            && !(attributes & SS::SE_GROUP_USE_FOR_DENY_ONLY as u32 != 0 && attributes & SS::SE_GROUP_ENABLED as u32 != 0)
            && !result.iter().any(|g| g.sid == principal))?;
        result.push(GroupFact { sid: principal, attributes });
    }
    // Explicit Administrators ownership in new SECURITY_ATTRIBUTES is possible
    // without adjusting privileges only with this actually enabled owner group.
    need(result.iter().any(|g| g.sid.bytes() == admins()
        && g.attributes & (SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER) as u32
            == (SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER) as u32
        && g.attributes & (SS::SE_GROUP_USE_FOR_DENY_ONLY | SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_RESOURCE) as u32 == 0))?;
    Ok(result)
}
fn installer_privileges(raw: &[u8], count: u32) -> Result<Vec<(u64, u32)>> {
    let head = offset_of!(S::TOKEN_PRIVILEGES, Privileges);
    let step = size_of::<S::LUID_AND_ATTRIBUTES>();
    need(count <= 64 && raw.len() == head + count as usize * step && decode::u32_at(raw, 0)? == count)?;
    let mut result = Vec::new();
    for i in 0..count as usize {
        let at = head + i * step;
        let luid = decode::u64_at(raw, at + offset_of!(S::LUID_AND_ATTRIBUTES, Luid))?;
        let attributes = decode::u32_at(raw, at + offset_of!(S::LUID_AND_ATTRIBUTES, Attributes))?;
        need(luid != 0 && !result.iter().any(|(prior, _)| *prior == luid)
            && attributes & !(S::SE_PRIVILEGE_ENABLED | S::SE_PRIVILEGE_ENABLED_BY_DEFAULT | S::SE_PRIVILEGE_USED_FOR_ACCESS) == 0)?;
        result.push((luid, attributes));
    }
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
fn installer_facts(identity: TokenIdentity, token_type: u32, elevated: u32, elevation_type: u32,
    ui_access: u32, virtualization: u32, restricted: u32, app_container: u32,
    user: &[u8], integrity: &[u8], groups: &[u8], privileges: &[u8]) -> Result<Installer> {
    need(token_type == S::TokenPrimary as u32 && elevated == 1 && ui_access == 0
        && virtualization == 0 && restricted == 0 && app_container == 0
        && user.len() <= BUFFER && integrity.len() <= BUFFER)?;
    let principal = pointed_sid(user, offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid), size_of::<S::TOKEN_USER>())?;
    need(decode::u32_at(user, offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))? == 0)?;
    let label = pointed_sid(integrity, offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid), size_of::<S::TOKEN_MANDATORY_LABEL>())?;
    need(decode::u32_at(integrity, offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))?
        == (SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED) as u32)?;
    if principal.bytes() == system() {
        need(label.bytes() == sid(16, &[16384])
            && [S::TokenElevationTypeDefault as u32, S::TokenElevationTypeFull as u32].contains(&elevation_type))?;
    } else {
        let bytes = principal.bytes();
        need(bytes.len() == 28 && bytes[1] == 5 && bytes[2..8] == [0, 0, 0, 0, 0, 5]
            && decode::u32_at(bytes, 8)? == 21 && label.bytes() == sid(16, &[12288])
            && elevation_type == S::TokenElevationTypeFull as u32)?;
    }
    Ok(Installer { identity, user: principal, integrity: label, elevation_type,
        groups: installer_groups(groups, identity.groups)?,
        privileges: installer_privileges(privileges, identity.privileges)? })
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
// representation carries a handle, scalar/count magnitude, path or native buffer.
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
fn observed_query(call: Call) -> &'static str {
    match call {
        Call::Architecture => "architecture", Call::Folder => "folder",
        Call::WindowsDirectory => "windows-directory", Call::SystemDirectory => "system-directory",
        Call::Mapping => "mapping", Call::DriveType => "drive-type", Call::Open(_) => "nt-create",
        Call::ProcessToken(_) => "process-token", Call::ThreadToken(_) => "thread-token", Call::Close(_) => "close",
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
    mcall: &'static str, mphase: &'static str, mret: ObservedReturn,
}
impl PublicationFrameObservation {
    fn from_frames(query: Option<(Call, Phase, Option<Returned>, Option<CompletionRefusal>)>,
        mutation: Option<(Effect, Phase, Option<Returned>)>) -> Self {
        let (qcall, qphase, qret, qrefusal) = query.map_or(("none", "none", ObservedReturn::from_return(None), "none"),
            |(call, phase, returned, refusal)| (observed_query(call), observed_phase(phase), ObservedReturn::from_return(returned), observed_refusal(refusal)));
        let (mcall, mphase, mret) = mutation.map_or(("none", "none", ObservedReturn::from_return(None)),
            |(effect, phase, returned)| (observed_mutation(effect), observed_phase(phase), ObservedReturn::from_return(returned)));
        Self { qcall, qphase, qret, qrefusal, mcall, mphase, mret }
    }
    /// Bounded companion line; reads only this normalized copy, never an owner.
    pub fn diagnostic_line(self) -> Option<String> {
        let mut line = String::with_capacity(256);
        line.push_str("MRK_WINDOWS_RUNTIME_PUBLISH_FRAME_V1=qcall="); line.push_str(self.qcall);
        line.push_str(";qphase="); line.push_str(self.qphase); line.push_str(";qret="); self.qret.append(&mut line);
        line.push_str(";qrefusal="); line.push_str(self.qrefusal);
        line.push_str(";mcall="); line.push_str(self.mcall); line.push_str(";mphase="); line.push_str(self.mphase);
        line.push_str(";mret="); self.mret.append(&mut line); line.push('\n');
        if line.len() <= 256 { Some(line) } else { None }
    }
}
struct Mutation {
    effect: Effect, phase: Cell<Phase>, returned: Cell<Option<Returned>>, slot: Option<usize>,
    path: Vec<u16>, descriptor: UnsafeCell<Aligned>, attributes: S::SECURITY_ATTRIBUTES,
    handle: F::HANDLE, output: *mut F::HANDLE, data: Vec<u8>, count: UnsafeCell<u32>, scalar: UnsafeCell<u32>,
    _pin: PhantomPinned,
}
struct MutationComplete { frame: Pin<Box<Mutation>> }
fn mutation_return(ok: i32, error: u32) -> Result<()> {
    if ok != 0 { return if error == 0 { Ok(()) } else { Err(Error::Unknown) }; }
    if error == 0 || error == F::ERROR_IO_PENDING { Err(Error::Unknown) } else { Err(Error::Unavailable) }
}
fn write_return(ok: i32, error: u32, written: u32, requested: usize) -> Result<()> {
    mutation_return(ok, error)?;
    if requested == 0 || requested > BUFFER || written as usize > requested { return Err(Error::Unknown); }
    need(written as usize == requested) // short/zero is failure, never a write-repair loop
}
fn later_originals_closed(states: impl IntoIterator<Item = SlotState>) -> bool {
    let mut any = false;
    for state in states { any = true; if state != SlotState::Closed { return false; } }
    any // NoHandle, Unknown or no earlier original never authorizes adoption
}

struct Directory {
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
}
// SAFETY: only the serialized owner moves. All native arguments/output cells
// are in pinned allocations, and no borrowed handle or UnsafeCell escapes. Like
// NativeBook this is NOT Sync. The executable never moves work between threads;
// admission is nevertheless reobserved on the actual calling thread each time.
unsafe impl Send for Publication {}

impl Publication {
    /// Call only for the first Admit/Unknown result, before settlement can
    /// change frames. Copy no UnsafeCell/native output, handle, clock or input.
    pub fn retained_frame_observation(&self) -> PublicationFrameObservation {
        let query = self.book.active.as_ref().map(|held| {
            let frame = held.as_ref().get_ref();
            (frame.call, frame.phase.get(), frame.returned.get(), frame.completion_refusal.get())
        });
        let mutation = self.mutation.as_ref().map(|held| {
            let frame = held.as_ref().get_ref();
            (frame.effect, frame.phase.get(), frame.returned.get())
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
            sizes: None, transfer: None, copied: Vec::new(), settlement_attempted: false })
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
        need(metadata.identity.volume_serial != 0 && metadata.links == 1
            && metadata.creation > 0 && metadata.write > 0 && metadata.change > 0)?;
        self.book.no_alternate_streams(&key)?;
        let security = self.book.security(&key, scope)?;
        need(self.book.metadata(&key)? == metadata)?; self.tick()?;
        Ok(Facts { metadata, security })
    }
    fn recheck_dir(&mut self, index: usize) -> Result<()> {
        let dir = self.directories.get(index).ok_or(Error::State)?;
        let (slot, scope, before) = (dir.current(), dir.scope, dir.facts.clone());
        need(self.checked(slot, scope)? == before)
    }
    fn after_child(&mut self, parent: usize) -> Result<()> {
        let dir = self.directories.get(parent).ok_or(Error::State)?;
        let (slot, scope, before) = (dir.current(), dir.scope, dir.facts.clone());
        let after = self.checked(slot, scope)?;
        need(child_transition(&before.metadata, &after.metadata) && before.security == after.security)?;
        self.directories[parent].facts = after; Ok(())
    }
    fn unique_identity(&self, metadata: &Metadata) -> Result<()> {
        if let Some(root) = self.directories.first() { need(root.facts.metadata.identity.volume_serial == metadata.identity.volume_serial)?; }
        need(!self.directories.iter().any(|d| d.facts.metadata.identity == metadata.identity)
            && !self.copied.iter().any(|c| c.source_facts.metadata.identity == metadata.identity || c.destination.metadata.identity == metadata.identity))
    }
    fn collect_installer(&mut self, index: usize) -> Result<Installer> {
        self.ready()?; self.book.absent_thread_token()?;
        let before = self.book.token(index, S::TokenStatistics)?;
        let initial = security::statistics(before.bytes(before.count()?)?)?;
        let mut scalar = |class| -> Result<u32> {
            let value = self.book.token(index, class)?;
            need(value.count()? == 4)?; decode::u32_at(value.bytes(4)?, 0)
        };
        let token_type = scalar(S::TokenType)?;
        let elevated = scalar(S::TokenElevation)?;
        let elevation_type = scalar(S::TokenElevationType)?;
        let ui_access = scalar(S::TokenUIAccess)?;
        let virtualization = scalar(S::TokenVirtualizationEnabled)?;
        let restricted = self.scalar(index, S::TokenHasRestrictions)?;
        let app_container = self.scalar(index, S::TokenIsAppContainer)?;
        let user = self.book.token(index, S::TokenUser)?;
        let integrity = self.book.token(index, S::TokenIntegrityLevel)?;
        let groups = self.book.token(index, S::TokenGroups)?;
        let privileges = self.book.token(index, S::TokenPrivileges)?;
        let facts = installer_facts(initial, token_type, elevated, elevation_type, ui_access, virtualization,
            restricted, app_container, user.bytes(user.count()?)?, integrity.bytes(integrity.count()?)?,
            groups.bytes(groups.count()?)?, privileges.bytes(privileges.count()?)?)?;
        let after = self.book.token(index, S::TokenStatistics)?;
        need(security::statistics(after.bytes(after.count()?)?)? == initial)?;
        self.book.absent_thread_token()?; self.tick()?; Ok(facts)
    }
    fn open_process_token(&mut self) -> Result<usize> {
        let key = self.book.reserve(Kind::ProcessToken, None, "", String::new())?;
        let result = self.book.call(Call::ProcessToken(key.index), null_mut(), Vec::new())?;
        need(matches!(result.arena.returned()?, Returned::Boolean(v, 0) if v != 0))?;
        self.book.noninherited(key.index)?; Ok(key.index)
    }
    fn admit_installer(&mut self) -> Result<()> {
        need(self.installer.is_none() && self.book.user.is_none() && self.book.process_token.is_none())?;
        let arch = self.book.call(Call::Architecture, null_mut(), Vec::new())?;
        need(decode::u16_at(arch.bytes(4)?, 0)? == SI::IMAGE_FILE_MACHINE_UNKNOWN
            && decode::u16_at(arch.bytes(4)?, 2)? == SI::IMAGE_FILE_MACHINE_AMD64)?;
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
        need(data.len() <= BUFFER && raw.len() <= BUFFER)?;
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
            path, descriptor: UnsafeCell::new(Aligned([0; BUFFER])), attributes: S::SECURITY_ATTRIBUTES::default(),
            handle, output: null_mut(), data, count: UnsafeCell::new(u32::MAX), scalar: UnsafeCell::new(u32::MAX), _pin: PhantomPinned });
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
            if unsafe { *frame.count.get() } != 4 { Err(Error::Unknown) } else { Ok(()) }
        } else { outcome };
        if outcome == Err(Error::Unknown) { return self.mutation_unknown(); }
        frame.phase.set(Phase::Complete);
        let held = self.mutation.take().ok_or(Error::Unknown)?;
        let complete = MutationComplete { frame: ManuallyDrop::into_inner(held) };
        outcome?; self.tick()?; Ok(complete)
    }
    fn scalar(&mut self, index: usize, class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
        need([S::TokenHasRestrictions, S::TokenIsAppContainer].contains(&class))?;
        let complete = self.mutate(Effect::Scalar(class), Some(index), "", &[], Vec::new())?;
        // SAFETY: Complete certifies the exact four-byte synchronous output.
        let value = unsafe { *complete.frame.scalar.get() };
        need(value <= 1)?; Ok(value)
    }

    fn add_directory(&mut self, slot: usize, parent: Option<usize>, dos: String, scope: AuthorityScope, created: bool) -> Result<usize> {
        let facts = self.checked(slot, scope)?; self.unique_identity(&facts.metadata)?;
        if created { exact_security(&facts.security, FileKind::Directory, false, false)?; }
        let index = self.directories.len();
        self.directories.push(Directory { initial: slot, control: None, parent, dos, scope, facts, entries: None, created });
        Ok(index)
    }
    fn entries(&mut self, index: usize, selected: Option<&str>) -> Result<Vec<DirectoryEntry>> {
        if let Some(entries) = &self.directories.get(index).ok_or(Error::State)?.entries { return Ok(entries.clone()); }
        self.recheck_dir(index)?;
        let slot = self.directories[index].current(); let key = self.key(slot);
        let mut entries = Vec::new();
        loop {
            self.ready()?;
            let batch = match selected { Some(name) => self.book.next_ancestor_entries(&key, name)?, None => self.book.next_entries(&key)? };
            self.tick()?;
            match batch { Some(batch) => entries.extend(batch), None => break }
        }
        let own = &self.directories[index].facts.metadata;
        let parent = self.directories[index].parent.map(|i| &self.directories[i].facts.metadata);
        check_entry_frame(&entries, own, parent)?;
        self.recheck_dir(index)?;
        self.directories[index].entries = Some(entries.clone()); Ok(entries)
    }
    fn selected(&mut self, parent: usize, name: &str) -> Result<Option<DirectoryEntry>> {
        let entries = self.entries(parent, Some(name))?;
        selected_entry(&entries, name)
    }
    fn child_path(&self, parent: usize, name: &str) -> Result<String> {
        need(decode::component(name))?;
        let path = &self.directories.get(parent).ok_or(Error::State)?.dos;
        Ok(format!("{}{}{}", path, if path.ends_with('\\') { "" } else { "\\" }, name))
    }
    fn existing_dir(&mut self, parent: usize, name: &str, scope: AuthorityScope) -> Result<usize> {
        let entry = self.selected(parent, name)?.ok_or(Error::Unavailable)?;
        need(entry.kind == FileKind::Directory)?; self.recheck_dir(parent)?;
        let parent_key = self.key(self.directories[parent].current());
        let key = self.book.open_child(&parent_key, name, FileKind::Directory)?;
        let path = self.child_path(parent, name)?;
        let index = self.add_directory(key.index, Some(parent), path, scope, false)?;
        match_entry(&entry, &self.directories[index].facts.metadata)?; self.recheck_dir(parent)?; Ok(index)
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
        let index = self.add_directory(original.index, Some(parent), path, AuthorityScope::ImmutableVersion, true)?;
        self.after_child(parent)?; self.output_dirs.push(index); Ok(index)
    }
    fn shared_dir(&mut self, parent: usize, name: &str) -> Result<usize> {
        if self.selected(parent, name)?.is_some() { self.existing_dir(parent, name, AuthorityScope::AncestorOutsideVersion) }
        else { self.new_dir(parent, name) } // collision during creation is terminal, never adoption
    }
    fn open_source(&mut self, index: usize) -> Result<(usize, Facts)> {
        let (parent, name) = self.payload_parent(index, true)?;
        let entries = self.directories[parent].entries.as_ref().ok_or(Error::State)?;
        let entry = selected_entry(entries, name)?.ok_or(Error::Unsafe)?;
        need(entry.kind == FileKind::File)?; self.recheck_dir(parent)?;
        let parent_key = self.key(self.directories[parent].current());
        let key = self.book.open_child(&parent_key, name, FileKind::File)?;
        let facts = self.checked(key.index, AuthorityScope::ImmutableVersion)?;
        match_entry(&entry, &facts.metadata)?; self.unique_identity(&facts.metadata)?;
        self.recheck_dir(parent)?; Ok((key.index, facts))
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
        self.step(|this| {
            this.order.live(Stage::Fresh)?; this.admit_installer()?;
            let location = this.book.location(LocationKind::ProgramFiles)?;
            need(Arc::ptr_eq(&this.book.identity, &location.book) && this.book.user.is_none() && !this.book.roots_started)?;
            need(this.book.mapping(&location.drive)? == location.device)?;
            let name = format!("{}\\", location.device);
            let key = this.book.reserve(Kind::Directory, None, &name, name.clone())?;
            this.book.call(Call::Open(key.index), null_mut(), Vec::new())?;
            this.book.noninherited(key.index)?; this.book.local_ntfs(&key)?;
            let components = location.components.clone();
            let root_dos = format!("{}\\", location.drive);
            this.location = Some(location); this.book.roots_started = true;
            let mut parent = this.add_directory(key.index, None, root_dos, AuthorityScope::AncestorOutsideVersion, false)?;
            for component in components { parent = this.existing_dir(parent, &component, AuthorityScope::AncestorOutsideVersion)?; }
            this.recheck_location()?;
            let mrk = this.existing_dir(parent, "Mobile Release Kit", AuthorityScope::AncestorOutsideVersion)?;
            this.mrk = Some(mrk);
            let input = this.existing_dir(mrk, "runtime-input", AuthorityScope::AncestorOutsideVersion)?;
            let target = this.existing_dir(input, TARGET, AuthorityScope::AncestorOutsideVersion)?;
            let digest = this.digest.clone();
            let root = this.existing_dir(target, &digest, AuthorityScope::ImmutableVersion)?;
            this.source_root = Some(root);
            // Strict root/python cursors are each bound exactly once, through EOF.
            let root_entries = this.entries(root, None)?;
            exact_names(&root_entries, false)?;
            let python = this.existing_dir(root, "python", AuthorityScope::ImmutableVersion)?;
            this.source_python = Some(python);
            exact_names(&this.entries(python, None)?, true)?;
            this.source_dirs = vec![input, target, root, python];
            let (manifest, facts) = this.open_source(MANIFEST)?;
            need(facts.metadata.size > 0 && facts.metadata.size <= MANIFEST_LIMIT as u64)?;
            this.manifest_original = Some(manifest); this.manifest_facts = Some(facts.clone());
            loop {
                this.ready()?;
                let chunk = this.book.read_next(&this.key(manifest), BUFFER)?; this.tick()?;
                if chunk.is_empty() { break; }
                let size = this.manifest.len().checked_add(chunk.len()).ok_or(Error::Bounds)?;
                need(size <= MANIFEST_LIMIT && size as u64 <= facts.metadata.size)?;
                this.manifest.extend(chunk);
            }
            need(this.manifest.len() as u64 == facts.metadata.size
                && this.checked(manifest, AuthorityScope::ImmutableVersion)? == facts)?;
            this.order.stage = Stage::Manifest; Ok(this.manifest.clone())
        })
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
            this.order.live(Stage::Copying)?;
            let t = this.transfer.as_ref().ok_or(Error::State)?;
            need(t.stage == TransferStage::SourceEof && t.proof.source_eof)?;
            let (index, source, writer, before, source_before) = (t.index, t.source, t.writer, t.created.clone(), t.source_facts.clone());
            this.recheck_installer()?;
            this.mutate(Effect::Flush, Some(writer), "", &[], Vec::new())?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.flushed = true;
            let written = this.checked(writer, AuthorityScope::ImmutableVersion)?;
            need(write_transition(&before.metadata, &written.metadata, this.sizes.as_ref().ok_or(Error::State)?[index])
                && before.security == written.security)?;
            this.close(writer)?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.writer_closed = true;
            need(this.checked(source, AuthorityScope::ImmutableVersion)? == source_before)?;
            this.close(source)?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.source_closed = true;
            this.ready()?;
            let (parent, name) = this.payload_parent(index, false)?; this.recheck_dir(parent)?;
            let readback = this.reserve_later(parent, name, FileKind::File, writer)?;
            this.book.call(Call::Open(readback), null_mut(), Vec::new())?;
            this.book.noninherited(readback)?;
            let observed = this.checked(readback, AuthorityScope::ImmutableVersion)?;
            need(writer_close_transition(&written.metadata, &observed.metadata) && written.security == observed.security)?;
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
    let mut seen = BTreeSet::new();
    for entry in entries {
        need(seen.insert(entry.name.to_ascii_lowercase()))?;
        if entry.name == "." || entry.name == ".." {
            need(entry.kind == FileKind::Directory)?;
            let bound = if entry.name == "." { Some(own) } else { parent };
            if let Some(bound) = bound { need(entry.file_id == bound.identity.file_id)?; }
        }
    }
    Ok(())
}
fn selected_entry(entries: &[DirectoryEntry], name: &str) -> Result<Option<DirectoryEntry>> {
    let mut selected = None;
    for entry in entries.iter().filter(|entry| entry.name.eq_ignore_ascii_case(name)) {
        need(entry.name == name && selected.is_none())?; selected = Some(entry.clone());
    }
    Ok(selected)
}
fn match_entry(entry: &DirectoryEntry, metadata: &Metadata) -> Result<()> {
    need(entry.kind == metadata.kind && entry.file_id == metadata.identity.file_id && entry.attributes == metadata.attributes)
}
fn exact_names(entries: &[DirectoryEntry], python: bool) -> Result<()> {
    let mut expected: BTreeSet<String> = PUBLICATION_PAYLOADS.iter().filter(|p| p.starts_with("python/") == python)
        .map(|p| p.strip_prefix("python/").unwrap_or(p).to_string()).collect();
    if !python { expected.insert("python".to_owned()); }
    for entry in entries.iter().filter(|e| e.name != "." && e.name != "..") {
        need(expected.remove(&entry.name) && entry.kind == if !python && entry.name == "python" { FileKind::Directory } else { FileKind::File })?;
    }
    need(expected.is_empty())
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
        let identity = TokenIdentity { token_id: 1, authentication_id: 2, modified_id: 3, groups: 1, privileges: 0 };
        let group_head = offset_of!(S::TOKEN_GROUPS, Groups);
        let group_attributes = group_head + offset_of!(S::SID_AND_ATTRIBUTES, Attributes);
        let mut groups = token_buffer(&admins(), group_head + size_of::<S::SID_AND_ATTRIBUTES>(),
            group_head + offset_of!(S::SID_AND_ATTRIBUTES, Sid), group_attributes,
            (SS::SE_GROUP_MANDATORY | SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER) as u32);
        groups[..4].copy_from_slice(&1u32.to_le_bytes());
        let privileges = vec![0u8; offset_of!(S::TOKEN_PRIVILEGES, Privileges)];
        for local_system in [false, true] {
            let principal = if local_system { system() } else { sid(5, &[21, 1, 2, 3, 1001]) };
            let user = token_buffer(&principal, size_of::<S::TOKEN_USER>(),
                offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
                offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes), 0);
            let integrity = token_buffer(&sid(16, &[if local_system { 16384 } else { 12288 }]), size_of::<S::TOKEN_MANDATORY_LABEL>(),
                offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
                offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes),
                (SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED) as u32);
            let elevation_type = (if local_system { S::TokenElevationTypeDefault } else { S::TokenElevationTypeFull }) as u32;
            need(installer_facts(identity, S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0, 0,
                &user, &integrity, &groups, &privileges).is_ok())?;
            for (kind, elevated, elevation, ui, virtualized, restricted, app) in [
                (S::TokenImpersonation as u32, 1, elevation_type, 0, 0, 0, 0),
                (S::TokenPrimary as u32, 0, elevation_type, 0, 0, 0, 0),
                (S::TokenPrimary as u32, 1, S::TokenElevationTypeLimited as u32, 0, 0, 0, 0),
                (S::TokenPrimary as u32, 1, elevation_type, 1, 0, 0, 0),
                (S::TokenPrimary as u32, 1, elevation_type, 0, 1, 0, 0),
                (S::TokenPrimary as u32, 1, elevation_type, 0, 0, 1, 0),
                (S::TokenPrimary as u32, 1, elevation_type, 0, 0, 0, 1),
            ] {
                need(installer_facts(identity, kind, elevated, elevation, ui, virtualized, restricted, app,
                    &user, &integrity, &groups, &privileges).is_err())?;
            }
        }
        groups[group_attributes..group_attributes + 4].copy_from_slice(&(SS::SE_GROUP_USE_FOR_DENY_ONLY as u32).to_le_bytes());
        need(installer_groups(&groups, 1).is_err())?;
        groups[group_head..group_head + 8].copy_from_slice(&0u64.to_le_bytes());
        need(installer_groups(&groups, 1).is_err())
    }

    #[test]
    fn fixed_roster_and_production_masks() -> Result<()> {
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
        // Existing selected inert policy also proves the closed diagnostic
        // vocabulary: input ordinals/classes/return magnitudes never leak.
        for (call, label) in [
            (Call::Architecture, "architecture"), (Call::Folder, "folder"),
            (Call::WindowsDirectory, "windows-directory"), (Call::SystemDirectory, "system-directory"),
            (Call::Mapping, "mapping"), (Call::DriveType, "drive-type"), (Call::Open(usize::MAX), "nt-create"),
            (Call::ProcessToken(usize::MAX), "process-token"), (Call::ThreadToken(usize::MAX), "thread-token"),
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
        let largest = PublicationFrameObservation::from_frames(
            Some((Call::Token(S::TokenVirtualizationEnabled), Phase::Returned,
                Some(Returned::Count(u32::MAX, u32::MAX)), Some(CompletionRefusal::TokenInvalidHandle))),
            Some((Effect::Control(true), Phase::Returned, Some(Returned::Count(u32::MAX, u32::MAX)))))
            .diagnostic_line().ok_or(Error::State)?;
        assert!(largest.is_ascii() && largest.len() <= 208 && largest.bytes().filter(|b| *b == b'\n').count() == 1);
        assert!(151 + largest.len() <= 512);
        let mut owner = Publication::new(&"d".repeat(64))?;
        let absent = owner.retained_frame_observation();
        assert_eq!(absent, PublicationFrameObservation::from_frames(None, None));
        crate::tests::enter_inert(&mut owner.book, Call::Token(S::TokenElevation), null_mut())?;
        owner.book.arena()?.phase.set(Phase::Returned);
        owner.book.arena()?.returned.set(Some(Returned::Boolean(1, 0)));
        // This fixture never enters mutate/invoke. Its output storage stays
        // unobserved; only the retained Rust effect/phase/return is copied.
        owner.mutation = Some(ManuallyDrop::new(Box::pin(Mutation {
            effect: Effect::Scalar(S::TokenHasRestrictions), phase: Cell::new(Phase::Returned),
            returned: Cell::new(Some(Returned::Boolean(0, F::ERROR_IO_PENDING))), slot: None,
            path: Vec::new(), descriptor: UnsafeCell::new(Aligned([0; BUFFER])), attributes: S::SECURITY_ATTRIBUTES::default(),
            handle: null_mut(), output: null_mut(), data: Vec::new(), count: UnsafeCell::new(u32::MAX),
            scalar: UnsafeCell::new(u32::MAX), _pin: PhantomPinned,
        })));
        let saved = owner.retained_frame_observation();
        assert_eq!(saved.diagnostic_line().as_deref(), Some("MRK_WINDOWS_RUNTIME_PUBLISH_FRAME_V1=qcall=token-elevation;qphase=returned;qret=bool-nonzero:00000000;qrefusal=none;mcall=has-restrictions;mphase=returned;mret=bool-zero:000003e5\n"));
        owner.book.arena()?.returned.set(Some(Returned::Boolean(0, 5)));
        assert_ne!(saved, owner.retained_frame_observation());
        // Release only the two never-native fixture allocations, not live owners.
        drop(ManuallyDrop::into_inner(owner.book.active.take().ok_or(Error::State)?));
        drop(ManuallyDrop::into_inner(owner.mutation.take().ok_or(Error::State)?));
        assert_eq!(owner.retained_frame_observation(), absent);
        assert_eq!(saved.qret, ObservedReturn::from_return(Some(Returned::Boolean(1, 0))));
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
            owner.directories.push(Directory { initial: i, control: None, parent: i.checked_sub(1), dos,
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
        written.identity.file_id = [2; 16]; need(!write_transition(&file, &written, 4))?;
        let directory = metadata(FileKind::Directory); let mut child = directory.clone();
        child.size = 64; child.allocation_size = 4096; child.write = 2; child.change = 2;
        need(child_transition(&directory, &child))?; child.links = 2;
        need(!child_transition(&directory, &child))
    }
    #[test]
    fn original_unknown_retains_mutation_storage_without_close_retry() -> Result<()> {
        let mut owner = Publication::new(&"a".repeat(64))?;
        owner.mutation = Some(ManuallyDrop::new(Box::pin(Mutation { effect: Effect::Flush,
            phase: Cell::new(Phase::Entered), returned: Cell::new(None), slot: None, path: Vec::new(),
            descriptor: UnsafeCell::new(Aligned([0; BUFFER])), attributes: S::SECURITY_ATTRIBUTES::default(),
            handle: null_mut(), output: null_mut(), data: Vec::new(), count: UnsafeCell::new(u32::MAX), scalar: UnsafeCell::new(u32::MAX), _pin: PhantomPinned })));
        // Pure ownership control: no fabricated HANDLE and no native call.
        need(owner.fail_and_settle_once() == CloseOutcome::Unknown && owner.mutation.is_some())?;
        need(owner.fail_and_settle_once() == CloseOutcome::Unknown && owner.mutation.is_some())?;
        need(!owner.published_and_settled() && !owner.occupied_target_and_settled()
            && owner.ready() == Err(Error::Unknown))
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
