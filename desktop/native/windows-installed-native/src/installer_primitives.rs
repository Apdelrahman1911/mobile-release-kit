//! Private shared installer mechanics. No worker, public mutation interface or clock.
//! The original enclosing owner retains both the book and active pinned frame.
use super::*;
use super::{AdmissionRole as R, AdmissionOp as O, AdmissionCheck as C};
use std::collections::{BTreeMap, BTreeSet};
use windows_sys::Win32::System::SystemServices as SS;

pub(super) type MutationSlot = Option<Held<Mutation>>;

pub(super) fn need(value: bool) -> Result<()> { if value { Ok(()) } else { Err(Error::Unsafe) } }

/// CHECK-only loan from the actual fixed installer controller. This interface
/// selects no operation/path and is neither authentication nor an executor.
/// Production implements it solely by borrowing the original ActiveInstallerGuard.
#[cfg(all(feature = "installer-acquisition", feature = "runtime-publication"))]
pub trait InstallerBoundary {
    fn producing_boundary(&self) -> Result<()>;
    // Same hard endpoint/custody, deliberately permitting cooperative STOP.
    // Lost custody uses the existing controller abort path, not skipped cleanup.
    fn settlement_boundary(&self);
    /// Closed nonshipping observation point only. The actual native return is
    /// already retained; the real controller may request its existing STOP.
    /// No injected return, changed native effect, command or new executor.
    #[cfg(feature = "installer-selection-fixture")]
    fn selection_fixture_return_boundary(&self,
        _point: super::installer_selection_fixture_data::SelectionFixturePoint) {}
}

pub(super) fn sid(authority: u8, sub: &[u32]) -> Vec<u8> {
    let mut raw = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, authority];
    for value in sub { raw.extend(value.to_le_bytes()); }
    raw
}
pub(super) fn admins() -> Vec<u8> { sid(5, &[32, 544]) }
pub(super) fn system() -> Vec<u8> { sid(5, &[18]) }
pub(super) fn users() -> Vec<u8> { sid(5, &[32, 545]) }

pub(super) fn users_mask(kind: FileKind, image: bool) -> u32 {
    FS::FILE_GENERIC_READ | if kind == FileKind::Directory || image { FS::FILE_GENERIC_EXECUTE } else { 0 }
}

// Exact noninheriting protected DACLs. An input or existing shared ancestor NEVER
// enters this constructor's mutation path. The group is supplied at creation,
// but GetKernelObjectSecurity(OWNER|DACL) does not return it: compare parsed facts.
pub(super) fn descriptor(kind: FileKind, image: bool, sealed: bool) -> Result<Vec<u8>> {
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
pub(super) fn exact_security(facts: &SecurityFacts, kind: FileKind, image: bool, sealed: bool) -> Result<()> {
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
pub(super) struct Facts { pub(super) metadata: Metadata, pub(super) security: SecurityFacts }
pub(super) fn same_object(a: &Metadata, b: &Metadata) -> bool {
    same_object_observed(a, b, None)
}
pub(super) fn same_object_observed(a: &Metadata, b: &Metadata, trace: Option<CopyRefusal<'_>>) -> bool {
    copy_guard(a.identity == b.identity, CopyMember::Identity, trace)
        && copy_guard(a.kind == b.kind, CopyMember::Kind, trace)
        && copy_guard(a.attributes == b.attributes, CopyMember::Attributes, trace)
        && copy_guard(a.links == b.links, CopyMember::Links, trace)
        && copy_guard(a.creation == b.creation, CopyMember::Creation, trace)
}
pub(super) fn child_transition(a: &Metadata, b: &Metadata) -> bool {
    // Used ONLY immediately after one recorded successful exclusive child create.
    // Directory index allocation/size can change in either direction on NTFS.
    same_object(a, b) && a.kind == FileKind::Directory && b.write >= a.write && b.change >= a.change
}
pub(super) fn write_transition(a: &Metadata, b: &Metadata, size: u64) -> bool {
    write_transition_observed(a, b, size, None)
}
pub(super) fn write_transition_observed(a: &Metadata, b: &Metadata, size: u64, trace: Option<CopyRefusal<'_>>) -> bool {
    if !(same_object_observed(a, b, trace) && copy_guard(a.kind == FileKind::File, CopyMember::Kind, trace)
        && copy_guard(a.size == 0, CopyMember::InitialSize, trace)) { return false; }
    let written_size = b.size;
    if !copy_guard(written_size == size, CopyMember::Size, trace) { return false; }
    let written_allocation = b.allocation_size;
    copy_allocation_guard(written_allocation >= size, trace, || CopyAllocation::BelowSize)
        && copy_guard(b.write >= a.write, CopyMember::WriteTime, trace)
        && copy_guard(b.change >= a.change, CopyMember::ChangeTime, trace)
}
pub(super) fn writer_close_transition(a: &Metadata, b: &Metadata) -> bool {
    writer_close_transition_observed(a, b, None)
}
pub(super) fn writer_close_transition_observed(a: &Metadata, b: &Metadata, trace: Option<CopyRefusal<'_>>) -> bool {
    if !(same_object_observed(a, b, trace) && copy_guard(a.kind == FileKind::File, CopyMember::Kind, trace)) { return false; }
    let (written_size, observed_size) = (a.size, b.size);
    if !copy_guard(written_size == observed_size, CopyMember::Size, trace) { return false; }
    let (written_allocation, observed_allocation) = (a.allocation_size, b.allocation_size);
    // Closing this own writer may release allocation slack, never logical data.
    copy_allocation_guard(observed_size <= observed_allocation && observed_allocation <= written_allocation, trace,
        || changed_allocation(observed_allocation, written_allocation, observed_size))
        && copy_guard(b.write >= a.write, CopyMember::WriteTime, trace)
        && copy_guard(b.change >= a.change, CopyMember::ChangeTime, trace)
}
pub(super) fn source_unchanged_observed(new: &Facts, old: &Facts, trace: Option<CopyRefusal<'_>>) -> bool {
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
pub(super) fn acl_transition(a: &Metadata, b: &Metadata) -> bool {
    same_object(a, b) && a.size == b.size && a.allocation_size == b.allocation_size
        && a.write == b.write && b.change >= a.change
}

// Positive privileged admission is deliberately separate from security::token_facts,
// whose ordinary-reader policy MUST keep rejecting these contexts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Installer {
    pub(super) identity: TokenIdentity, pub(super) user: Sid, pub(super) integrity: Sid, pub(super) elevation_type: u32,
    pub(super) groups: Vec<GroupFact>, pub(super) privileges: Vec<(u64, u32)>,
}
#[derive(Clone, Copy)]
pub(super) struct InstallerData<'a>(pub(super) Refusal<'a>);
impl InstallerData<'_> {
pub(super) fn pointed_sid(self, raw: &[u8], field: usize, minimum: usize) -> Result<Sid> {
    let d = decode::Observed::new(self.0);
    let pointer = usize::try_from(d.u64_at(raw, field)?).map_err(|_| self.0.unsafe_at(C::PointerValue))?;
    let at = pointer.checked_sub(raw.as_ptr() as usize).ok_or_else(|| self.0.unsafe_at(C::PointerOffset))?;
    self.0.need(at >= minimum, C::PointerMinimum)?;
    self.0.need(at % 4 == 0, C::PointerAlignment)?;
    security::Observed::new(self.0).sid_at(raw, at, raw.len()) // no unvalidated pointer dereference
}
pub(super) fn installer_groups(self, raw: &[u8], count: u32) -> Result<Vec<GroupFact>> {
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
pub(super) fn installer_privileges(self, raw: &[u8], count: u32) -> Result<Vec<(u64, u32)>> {
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
pub(super) fn installer_facts(self, identity: TokenIdentity, token_type: u32, elevated: u32, elevation_type: u32,
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
pub(super) fn installer_groups(raw: &[u8], count: u32) -> Result<Vec<GroupFact>> { InstallerData(Refusal::none()).installer_groups(raw, count) }
#[allow(clippy::too_many_arguments)]
pub(super) fn installer_facts(identity: TokenIdentity, token_type: u32, elevated: u32, elevation_type: u32,
    ui_access: u32, virtualization: u32, restricted: u32, app_container: u32,
    user: &[u8], integrity: &[u8], groups: &[u8], privileges: &[u8]) -> Result<Installer> {
    InstallerData(Refusal::none()).installer_facts(identity, token_type, elevated, elevation_type, ui_access,
        virtualization, restricted, app_container, user, integrity, groups, privileges)
}


#[derive(Clone, Copy, Debug, Default)]
pub(super) struct CopyProof { pub(super) source_eof: bool, pub(super) flushed: bool, pub(super) writer_closed: bool, pub(super) source_closed: bool, pub(super) readback_eof: bool, pub(super) readback_closed: bool }
impl CopyProof {
    pub(super) fn complete(self) -> bool {
        self.source_eof && self.flushed && self.writer_closed && self.source_closed && self.readback_eof && self.readback_closed
    }
}

#[derive(Clone, Copy)]
pub(super) enum Effect { Directory(usize), Writer, Control(bool), Write, Flush, Seal, Scalar(S::TOKEN_INFORMATION_CLASS) }

// Normalize while copying retained Rust DATA. Neither this value nor its Debug
// representation carries a handle, raw scalar/count magnitude, path or native buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ObservedReturn { pub(super) label: &'static str, pub(super) code: Option<u32> }
impl ObservedReturn {
    pub(super) fn from_return(value: Option<Returned>) -> Self {
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
    pub(super) fn append(self, line: &mut String) {
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
pub(super) enum ObservedScalarLength { Unobserved, Sentinel, Zero, One, Two, Three, Four, OverFour }
impl ObservedScalarLength {
    pub(super) fn from_count(count: u32) -> Self {
        match count {
            u32::MAX => Self::Sentinel, 0 => Self::Zero, 1 => Self::One,
            2 => Self::Two, 3 => Self::Three, 4 => Self::Four, _ => Self::OverFour,
        }
    }
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Unobserved => "none", Self::Sentinel => "sentinel", Self::Zero => "zero",
            Self::One => "one", Self::Two => "two", Self::Three => "three",
            Self::Four => "four", Self::OverFour => "over4",
        }
    }
}
pub(super) fn observed_query(call: Call) -> &'static str {
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
pub(super) fn observed_mutation(effect: Effect) -> &'static str {
    match effect {
        Effect::Directory(_) => "directory", Effect::Writer => "writer",
        Effect::Control(false) => "control-file", Effect::Control(true) => "control-directory",
        Effect::Write => "write", Effect::Flush => "flush", Effect::Seal => "seal",
        Effect::Scalar(S::TokenHasRestrictions) => "has-restrictions",
        Effect::Scalar(S::TokenIsAppContainer) => "is-app-container", Effect::Scalar(_) => "scalar-other",
    }
}
pub(super) fn observed_phase(phase: Phase) -> &'static str {
    match phase { Phase::Prepared => "prepared", Phase::Entered => "entered", Phase::Returned => "returned", Phase::Complete => "complete" }
}
pub(super) fn observed_refusal(refusal: Option<CompletionRefusal>) -> &'static str {
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
    pub(super) qcall: &'static str, pub(super) qphase: &'static str, pub(super) qret: ObservedReturn, pub(super) qrefusal: &'static str,
    pub(super) mcall: &'static str, pub(super) mphase: &'static str, pub(super) mret: ObservedReturn, pub(super) mcount: ObservedScalarLength,
}
impl PublicationFrameObservation {
    pub(super) fn from_frames(query: Option<(Call, Phase, Option<Returned>, Option<CompletionRefusal>)>,
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
pub(super) struct Mutation {
    pub(super) effect: Effect, pub(super) phase: Cell<Phase>, pub(super) returned: Cell<Option<Returned>>, pub(super) slot: Option<usize>,
    pub(super) length_observation: Cell<ObservedScalarLength>,
    pub(super) path: Vec<u16>, pub(super) descriptor: UnsafeCell<Aligned>, pub(super) attributes: S::SECURITY_ATTRIBUTES,
    pub(super) handle: F::HANDLE, pub(super) output: *mut F::HANDLE, pub(super) data: Vec<u8>, pub(super) count: UnsafeCell<u32>, pub(super) scalar: UnsafeCell<u32>,
    pub(super) _pin: PhantomPinned,
}
pub(super) struct MutationComplete { pub(super) frame: Pin<Box<Mutation>> }
impl MutationComplete {
    pub(super) fn scalar(&self) -> Result<u32> {
        need(self.frame.phase.get() == Phase::Complete
            && matches!(self.frame.effect, Effect::Scalar(S::TokenHasRestrictions | S::TokenIsAppContainer)))?;
        // SAFETY: definite completion ended native access to this pinned,
        // completely initialized DWORD object. An accepted needed-size of one
        // does NOT assert a one-byte ABI or four native-written output bytes.
        Ok(unsafe { *self.frame.scalar.get() })
    }
}
pub(super) fn mutation_return(ok: i32, error: u32) -> Result<()> {
    if ok != 0 { return if error == 0 { Ok(()) } else { Err(Error::Unknown) }; }
    if error == 0 || error == F::ERROR_IO_PENDING { Err(Error::Unknown) } else { Err(Error::Unavailable) }
}
pub(super) fn write_return(ok: i32, error: u32, written: u32, requested: usize) -> Result<()> {
    mutation_return(ok, error)?;
    if requested == 0 || requested > BUFFER || written as usize > requested { return Err(Error::Unknown); }
    need(written as usize == requested) // short/zero is failure, never a write-repair loop
}
pub(super) fn scalar_initial(effect: Effect) -> u32 {
    if matches!(effect, Effect::Scalar(S::TokenHasRestrictions)) { u32::from_ne_bytes([0xff, 0, 0, 0]) }
    else { u32::MAX }
}
pub(super) fn scalar_value(value: u32) -> Result<u32> { need(value <= 1)?; Ok(value) }
pub(super) fn scalar_count_return(effect: Effect, count: u32, observed: &Cell<ObservedScalarLength>) -> Result<()> {
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
pub(super) fn later_originals_closed(states: impl IntoIterator<Item = SlotState>) -> bool {
    let mut any = false;
    for state in states { any = true; if state != SlotState::Closed { return false; } }
    any // NoHandle, Unknown or no earlier original never authorizes adoption
}

pub(super) struct Creation { pub(super) path: String, pub(super) parent: usize, pub(super) entered: bool, pub(super) returned: Option<(i32, u32)> }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CopyEdge {
    Order, SourceEof, Installer, Flush, WriterCheck, WriteTransition, WriterClose, SourceCheck,
    SourceUnchanged, SourceClose, ParentCheck, ReadbackReserve, ReadbackOpen, ReadbackNoninherited,
    ReadbackCheck, WriterCloseTransition,
}
impl CopyEdge {
    pub(super) fn label(self) -> &'static str {
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
pub(super) enum CopyMember { None, Identity, Kind, Attributes, Links, Creation, InitialSize, Size, Allocation, WriteTime, ChangeTime, Security }
impl CopyMember {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::None => "none", Self::Identity => "identity", Self::Kind => "kind", Self::Attributes => "attributes",
            Self::Links => "links", Self::Creation => "creation", Self::InitialSize => "initial-size", Self::Size => "size",
            Self::Allocation => "allocation", Self::WriteTime => "write-time", Self::ChangeTime => "change-time", Self::Security => "security",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CopyAllocation { None, BelowSize, Shrank, Grew }
impl CopyAllocation {
    pub(super) fn label(self) -> &'static str {
        match self { Self::None => "none", Self::BelowSize => "below-size", Self::Shrank => "shrank", Self::Grew => "grew" }
    }
}
/// Closed first-Unsafe finish-copy DATA; no handle, raw size or native output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationCopyObservation { pub(super) edge: CopyEdge, pub(super) member: CopyMember, pub(super) allocation: CopyAllocation }
impl PublicationCopyObservation {
    pub(super) fn legal(self) -> bool {
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
pub(super) struct CopyRefusal<'a> { pub(super) first: &'a Cell<Option<PublicationCopyObservation>>, pub(super) edge: CopyEdge }
impl CopyRefusal<'_> {
    pub(super) fn record(self, member: CopyMember, allocation: impl FnOnce() -> CopyAllocation) {
        if self.first.get().is_none() {
            self.first.set(Some(PublicationCopyObservation { edge: self.edge, member, allocation: allocation() }));
        }
    }
}
// Receive each already-evaluated Result once; nested refusals are edge-only.
pub(super) fn copy_result<T>(result: Result<T>, first: &Cell<Option<PublicationCopyObservation>>, edge: CopyEdge) -> Result<T> {
    if matches!(result.as_ref(), Err(Error::Unsafe)) {
        CopyRefusal { first, edge }.record(CopyMember::None, || CopyAllocation::None);
    }
    result
}
pub(super) fn copy_guard(value: bool, member: CopyMember, trace: Option<CopyRefusal<'_>>) -> bool {
    if !value { if let Some(trace) = trace { trace.record(member, || CopyAllocation::None); } }
    value
}
pub(super) fn copy_allocation_guard(value: bool, trace: Option<CopyRefusal<'_>>, allocation: impl FnOnce() -> CopyAllocation) -> bool {
    if !value { if let Some(trace) = trace { trace.record(CopyMember::Allocation, allocation); } }
    value
}
pub(super) fn changed_allocation(new: u64, old: u64, size: u64) -> CopyAllocation {
    // Called only after a reached allocation refusal, using cached operands.
    // Equal-but-under-EOF close observations also classify as BelowSize;
    // passed comparisons and earlier refusals never classify here.
    if new < size { CopyAllocation::BelowSize } else if new < old { CopyAllocation::Shrank } else { CopyAllocation::Grew }
}

pub(super) unsafe fn invoke_mutation(frame: &Mutation) -> Returned {
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
pub(super) fn check_entry_frame(entries: &[DirectoryEntry], own: &Metadata, parent: Option<&Metadata>) -> Result<()> {
    check_entry_frame_in(entries, own, parent, Refusal::none())
}
pub(super) fn check_entry_frame_in(entries: &[DirectoryEntry], own: &Metadata, parent: Option<&Metadata>, trace: Refusal<'_>) -> Result<()> {
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
pub(super) fn selected_entry(entries: &[DirectoryEntry], name: &str) -> Result<Option<DirectoryEntry>> {
    selected_entry_in(entries, name, Refusal::none())
}
pub(super) fn selected_entry_in(entries: &[DirectoryEntry], name: &str, trace: Refusal<'_>) -> Result<Option<DirectoryEntry>> {
    let mut selected = None;
    for (index, entry) in entries.iter().enumerate().filter(|(_, entry)| entry.name.eq_ignore_ascii_case(name)) {
        let row = trace.index(AdmissionIndex::Directory, index);
        row.need(entry.name == name, C::SelectedCase)?;
        row.need(selected.is_none(), C::SelectedDuplicate)?;
        selected = Some(entry.clone());
    }
    Ok(selected)
}
pub(super) fn match_entry(entry: &DirectoryEntry, metadata: &Metadata) -> Result<()> { match_entry_in(entry, metadata, Refusal::none()) }
pub(super) fn match_entry_in(entry: &DirectoryEntry, metadata: &Metadata, trace: Refusal<'_>) -> Result<()> {
    trace.need(entry.kind == metadata.kind, C::EntryKind)?;
    trace.need(entry.file_id == metadata.identity.file_id, C::EntryIdentity)?;
    trace.need(entry.attributes == metadata.attributes, C::EntryAttributes)
}

pub(super) fn exact_entries(entries: &[DirectoryEntry], expected: &BTreeMap<String, Metadata>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for entry in entries.iter().filter(|e| e.name != "." && e.name != "..") {
        need(seen.insert(entry.name.clone()))?;
        match_entry(entry, expected.get(&entry.name).ok_or(Error::Unsafe)?)?;
    }
    need(seen.len() == expected.len())
}

// Caller performs its own ready/clock/global-failure checks. This function
// registers all original outputs in the same owner before native entry.
#[allow(clippy::too_many_arguments)]
pub(super) fn enter_registered_mutation(book: &mut NativeBook, mutation: &mut MutationSlot,
    creations: &mut [Creation], effect: Effect, slot: Option<usize>, dos: &str,
    raw: &[u8], data: Vec<u8>) -> Result<()> {
        book.admission.at(O::MutationInput).need(data.len() <= BUFFER, C::MutationData)?;
        book.admission.at(O::MutationInput).need(raw.len() <= BUFFER, C::MutationDescriptor)?;
        let acquiring = matches!(effect, Effect::Writer | Effect::Control(_));
        let handle = if acquiring || matches!(effect, Effect::Directory(_)) { null_mut() }
            else { book.handle(slot.ok_or(Error::State)?)? };
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
            let original = book.slot(slot.ok_or(Error::State)?)?;
            need(original.state == SlotState::Reserved)?; setup.output = original.output.get();
        }
        *mutation = Some(ManuallyDrop::new(frame));
        if acquiring { book.slot_mut(slot.ok_or(Error::State)?)?.state = SlotState::Acquiring; }
        if let Effect::Directory(i) = effect { creations.get_mut(i).ok_or(Error::State)?.entered = true; }
        book.started = true;
        let frame = mutation.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        frame.phase.set(Phase::Entered);
        // SAFETY: no overlapping call, callback or async mode. Every native
        // pointer is pinned and already owned. The first operation after return
        // records the actual scalar (and immediate same-thread GetLastError).
        let returned = unsafe { invoke_mutation(frame) };
        frame.returned.set(Some(returned)); frame.phase.set(Phase::Returned);
        Ok(())
}

pub(super) fn mutation_unknown<T>(book: &mut NativeBook) -> Result<T> {
    book.mark_interrupted(); Err(Error::Unknown)
}
// DATA accounting is optional for Publication and retained by acquisition.
// A failed Boolean result has no authorized count observation. A contradictory
// successful count cannot become a known persisted byte count.
#[derive(Default, Debug)]
pub(super) struct WriteAccounting {
    pub(super) confirmed_bytes: u64,
    pub(super) definite_calls: u64,
    pub(super) unknown_count: bool,
}
impl WriteAccounting {
    pub(super) fn observe(&mut self, written: u32, requested: usize) {
        if requested == 0 || requested > BUFFER || written as usize > requested {
            self.unknown_count = true; return;
        }
        match (self.confirmed_bytes.checked_add(u64::from(written)), self.definite_calls.checked_add(1)) {
            (Some(bytes), Some(calls)) => { self.confirmed_bytes = bytes; self.definite_calls = calls; },
            _ => self.unknown_count = true,
        }
    }
}
pub(super) fn finish_registered_mutation(book: &mut NativeBook, mutation: &mut MutationSlot,
    creations: &mut [Creation], mut accounting: Option<&mut WriteAccounting>) -> Result<MutationComplete> {
        let frame = mutation.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        if matches!(frame.effect, Effect::Write) && (frame.phase.get() != Phase::Returned
            || !matches!(frame.returned.get(), Some(Returned::Boolean(v, 0)) if v != 0)) {
            if let Some(ledger) = accounting.as_deref_mut() { ledger.unknown_count = true; }
        }
        if frame.phase.get() != Phase::Returned { return mutation_unknown(book); }
        let (ok, error) = match frame.returned.get() { Some(Returned::Boolean(v, e)) => (v, e), _ => return mutation_unknown(book) };
        let (effect, slot) = (frame.effect, frame.slot);
        if let Effect::Directory(i) = effect { creations[i].returned = Some((ok, error)); }
        let outcome = mutation_return(ok, error);
        if outcome == Err(Error::Unknown) { return mutation_unknown(book); }
        if matches!(effect, Effect::Writer | Effect::Control(_)) {
            let index = slot.ok_or(Error::Unknown)?;
            if book.slot(index)?.state != SlotState::Acquiring { return mutation_unknown(book); }
            // SAFETY: only definite synchronous nonpending completion reaches the
            // registered output. NULL contradicts CreateFileW's failure sentinel.
            let handle = unsafe { *book.slot(index)?.output.get() };
            if ok == 0 {
                if handle != F::INVALID_HANDLE_VALUE { return mutation_unknown(book); }
                book.slot_mut(index)?.state = SlotState::NoHandle;
            } else {
                if !valid_handle(handle) || book.duplicate_live(index, handle) { return mutation_unknown(book); }
                book.slot_mut(index)?.state = SlotState::Owned;
            }
        }
        let frame = mutation.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        let outcome = if matches!(effect, Effect::Write) && outcome.is_ok() {
            // SAFETY: known completion, not a failed or pending output count.
            let written = unsafe { *frame.count.get() };
            if let Some(ledger) = accounting.as_deref_mut() { ledger.observe(written, frame.data.len()); }
            write_return(ok, error, written, frame.data.len())
        } else if matches!(effect, Effect::Scalar(_)) && outcome.is_ok() {
            // SAME authorized read; class-local needed-size compatibility never
            // derives a write extent or authorizes another output observation.
            let count = unsafe { *frame.count.get() };
            scalar_count_return(effect, count, &frame.length_observation)
        } else { outcome };
        if outcome == Err(Error::Unknown) { return mutation_unknown(book); }
        frame.phase.set(Phase::Complete);
        let held = mutation.take().ok_or(Error::Unknown)?;
        let complete = MutationComplete { frame: ManuallyDrop::into_inner(held) };
        outcome?; Ok(complete)
}
