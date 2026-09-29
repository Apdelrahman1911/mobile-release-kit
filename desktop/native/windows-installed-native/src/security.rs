//! Conservative owner/DACL and current-primary-token DATA policy. Unknown ACEs
//! are refused, not evaluated with an approximation of Windows Authz semantics.
use super::{AuthorityScope, Error, FileKind, Result, Refusal, AdmissionCheck as C, AdmissionIndex, BUFFER};
use super::decode::{span, u32_at, u64_at};
use std::mem::{offset_of, size_of};
use windows_sys::Win32::{Foundation as F, Security as S, Storage::FileSystem as FS};
use windows_sys::Win32::System::SystemServices as SS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sid { bytes: Vec<u8> }
impl Sid {
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    fn is(&self, authority: u8, sub: &[u32]) -> bool {
        self.bytes.len() == 8 + sub.len() * 4 && self.bytes[0] == 1 && self.bytes[1] as usize == sub.len()
            && self.bytes[2..8] == [0, 0, 0, 0, 0, authority]
            && sub.iter().enumerate().all(|(i, n)| u32_at(&self.bytes, 8 + i * 4) == Ok(*n))
    }
    fn trusted(&self) -> bool {
        self.is(5, &[18]) || self.is(5, &[32, 544]) || self.is(5, &[80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464])
    }
    fn account(&self) -> bool {
        self.bytes.len() == 28 && self.bytes[1] == 5 && self.bytes[2..8] == [0, 0, 0, 0, 0, 5]
            && u32_at(&self.bytes, 8) == Ok(21)
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Observed<'a>(Refusal<'a>);
impl<'a> Observed<'a> {
    pub(crate) fn new(trace: Refusal<'a>) -> Self { Self(trace) }
    pub(crate) fn sid_at(self, raw: &[u8], offset: usize, end: usize) -> Result<Sid> {
        let d = super::decode::Observed::new(self.0);
        let head = d.span(raw, offset, 8)?;
        if head[0] != 1 { return Err(self.0.unsafe_at(C::SidRevision)); }
        if head[1] > 15 { return Err(self.0.unsafe_at(C::SidCount)); }
        let length = 8usize.checked_add(head[1] as usize * 4).ok_or(Error::Bounds)?;
        if offset.checked_add(length).ok_or(Error::Bounds)? > end { return Err(self.0.unsafe_at(C::SidExtent)); }
        Ok(Sid { bytes: d.span(raw, offset, length)?.to_vec() })
    }
}
pub(crate) fn sid_at(raw: &[u8], offset: usize, end: usize) -> Result<Sid> { Observed::new(Refusal::none()).sid_at(raw, offset, end) }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AceFact { pub allow: bool, pub flags: u8, pub mask: u32, pub sid: Sid }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityFacts { pub owner: Sid, pub control: u16, pub revision: u8, pub aces: Vec<AceFact> }
impl SecurityFacts {
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        let mut total = self.owner.bytes.capacity()
            .checked_add(self.aces.capacity().checked_mul(size_of::<AceFact>())?)?;
        for ace in &self.aces { total = total.checked_add(ace.sid.bytes.capacity())?; }
        Some(total)
    }
}
#[derive(Clone, Copy)]
enum DescriptorPurpose<'a> { Runtime(FileKind, AuthorityScope), PrivateCredential(&'a Sid) }
impl Observed<'_> {
fn expand(self, mask: u32) -> Result<u32> {
    let generic = F::GENERIC_READ | F::GENERIC_WRITE | F::GENERIC_EXECUTE | F::GENERIC_ALL;
    if mask & !(generic | FS::FILE_ALL_ACCESS) != 0 { return Err(self.0.unsafe_at(C::AceMask)); }
    let mut effective = mask & !generic;
    for (flag, rights) in [(F::GENERIC_READ, FS::FILE_GENERIC_READ), (F::GENERIC_WRITE, FS::FILE_GENERIC_WRITE),
        (F::GENERIC_EXECUTE, FS::FILE_GENERIC_EXECUTE), (F::GENERIC_ALL, FS::FILE_ALL_ACCESS)] {
        if mask & flag != 0 { effective |= rights; }
    }
    Ok(effective)
}
fn ace_rights(self, ace: &AceFact) -> Result<u32> {
    let allowed_flags = S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE | S::NO_PROPAGATE_INHERIT_ACE | S::INHERIT_ONLY_ACE | S::INHERITED_ACE;
    let flags = ace.flags as u32;
    if flags & !allowed_flags != 0 { return Err(self.0.unsafe_at(C::AceFlags)); }
    if flags & (S::NO_PROPAGATE_INHERIT_ACE | S::INHERIT_ONLY_ACE) != 0
        && flags & (S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE) == 0 { return Err(self.0.unsafe_at(C::AceInheritance)); }
    self.expand(ace.mask) // Reject unknown masks even for deny/inherit-only.
}
fn safe_ace(self, ace: &AceFact, kind: FileKind, scope: AuthorityScope) -> Result<()> {
    let effective = self.ace_rights(ace)?;
    if !ace.allow || ace.flags as u32 & S::INHERIT_ONLY_ACE != 0 || ace.sid.trusted() { return Ok(()); }
    let mut dangerous = FS::DELETE | FS::FILE_DELETE_CHILD | FS::WRITE_DAC | FS::WRITE_OWNER
        | FS::FILE_WRITE_EA | FS::FILE_WRITE_ATTRIBUTES;
    if kind == FileKind::File || scope == AuthorityScope::ImmutableVersion {
        dangerous |= FS::FILE_WRITE_DATA | FS::FILE_APPEND_DATA; // directory ADD_FILE/ADD_SUBDIRECTORY
    }
    if effective & dangerous != 0 { Err(self.0.unsafe_at(C::AceDangerousRights)) } else { Ok(()) }
}
fn private_ace(self, ace: &AceFact, user: &Sid) -> Result<()> {
    let effective = self.ace_rights(ace)?;
    if !ace.allow || ace.flags as u32 & S::INHERIT_ONLY_ACE != 0 || ace.sid == *user || ace.sid.trusted() {
        return Ok(());
    }
    // Like ordinary POSIX metadata, these rights disclose no credential content
    // and cannot modify it. Extended-attribute reads are deliberately excluded.
    let metadata_only = FS::READ_CONTROL | FS::SYNCHRONIZE | FS::FILE_READ_ATTRIBUTES;
    if effective & !metadata_only != 0 { Err(self.0.unsafe_at(C::AceDangerousRights)) } else { Ok(()) }
}
}
fn overlap(a: (usize, usize), b: (usize, usize)) -> bool { a.0 < b.1 && b.0 < a.1 }
pub(crate) fn descriptor(raw: &[u8], kind: FileKind, scope: AuthorityScope) -> Result<SecurityFacts> {
    Observed::new(Refusal::none()).descriptor(raw, kind, scope)
}
impl Observed<'_> {
pub(crate) fn descriptor(self, raw: &[u8], kind: FileKind, scope: AuthorityScope) -> Result<SecurityFacts> {
    self.descriptor_for(raw, DescriptorPurpose::Runtime(kind, scope))
}
pub(crate) fn credential_descriptor(self, raw: &[u8], user: &Sid) -> Result<SecurityFacts> {
    self.descriptor_for(raw, DescriptorPurpose::PrivateCredential(user))
}
fn descriptor_for(self, raw: &[u8], purpose: DescriptorPurpose<'_>) -> Result<SecurityFacts> {
    let d = super::decode::Observed::new(self.0);
    if raw.len() > BUFFER || raw.len() < size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>() { return Err(self.0.unsafe_at(C::DescriptorSize)); }
    let header = size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>();
    let revision = raw[offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Revision)];
    let control = d.u16_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Control))?;
    let known = S::SE_OWNER_DEFAULTED | S::SE_GROUP_DEFAULTED | S::SE_DACL_PRESENT | S::SE_DACL_DEFAULTED
        | S::SE_SACL_PRESENT | S::SE_SACL_DEFAULTED | S::SE_DACL_AUTO_INHERIT_REQ | S::SE_SACL_AUTO_INHERIT_REQ
        | S::SE_DACL_AUTO_INHERITED | S::SE_SACL_AUTO_INHERITED | S::SE_DACL_PROTECTED | S::SE_SACL_PROTECTED | S::SE_SELF_RELATIVE;
    if revision != 1 { return Err(self.0.unsafe_at(C::DescriptorRevision)); }
    if raw[offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Sbz1)] != 0 { return Err(self.0.unsafe_at(C::DescriptorReserved)); }
    if control & !known != 0 { return Err(self.0.unsafe_at(C::DescriptorControl)); }
    if control & (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT) != (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT) { return Err(self.0.unsafe_at(C::DescriptorRequired)); }
    if d.u32_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Sacl))? != 0 { return Err(self.0.unsafe_at(C::DescriptorSacl)); }
    let owner_at = d.u32_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Owner))? as usize;
    let acl_at = d.u32_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl))? as usize;
    if owner_at < header || owner_at % 4 != 0 { return Err(self.0.unsafe_at(C::OwnerOffset)); }
    if acl_at < header || acl_at % 4 != 0 { return Err(self.0.unsafe_at(C::AclOffset)); }
    let owner = self.sid_at(raw, owner_at, raw.len())?;
    let owner_allowed = match purpose {
        DescriptorPurpose::Runtime(_, _) => owner.trusted(),
        DescriptorPurpose::PrivateCredential(user) => owner == *user,
    };
    if !owner_allowed { return Err(self.0.unsafe_at(C::OwnerTrust)); }
    let acl = d.span(raw, acl_at, size_of::<S::ACL>())?;
    let acl_revision = acl[offset_of!(S::ACL, AclRevision)];
    if !matches!(acl_revision, 2 | 4) { return Err(self.0.unsafe_at(C::AclRevision)); }
    if acl[offset_of!(S::ACL, Sbz1)] != 0 || d.u16_at(acl, offset_of!(S::ACL, Sbz2))? != 0 { return Err(self.0.unsafe_at(C::AclReserved)); }
    let size = d.u16_at(acl, offset_of!(S::ACL, AclSize))? as usize;
    let count = d.u16_at(acl, offset_of!(S::ACL, AceCount))? as usize;
    if size < size_of::<S::ACL>() || size % 4 != 0 { return Err(self.0.unsafe_at(C::AclSize)); }
    if count > 2048 { return Err(self.0.unsafe_at(C::AclCount)); }
    d.span(raw, acl_at, size)?;
    let acl_end = acl_at.checked_add(size).ok_or(Error::Bounds)?;
    let owner_range = (owner_at, owner_at + owner.bytes.len());
    if overlap(owner_range, (acl_at, acl_end)) { return Err(self.0.unsafe_at(C::OwnerAclOverlap)); }
    let group_at = d.u32_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Group))? as usize;
    if group_at != 0 {
        if group_at < header || group_at % 4 != 0 { return Err(self.0.unsafe_at(C::GroupOffset)); }
        let group = self.sid_at(raw, group_at, raw.len())?;
        let range = (group_at, group_at + group.bytes.len());
        if overlap(range, (acl_at, acl_end)) || (range != owner_range && overlap(range, owner_range)) { return Err(self.0.unsafe_at(C::GroupOverlap)); }
    }
    let mut aces = Vec::new();
    aces.try_reserve(count).map_err(|_| Error::Bounds)?;
    let mut offset = acl_at + size_of::<S::ACL>();
    for index in 0..count {
        let trace = self.0.index(AdmissionIndex::Ace, index);
        let d = super::decode::Observed::new(trace);
        let observed = Self(trace);
        let head = d.span(raw, offset, size_of::<S::ACE_HEADER>())?;
        let ace_type = head[offset_of!(S::ACE_HEADER, AceType)] as u32;
        // Refuse EVERY unsupported ACE before considering INHERIT_ONLY or allow.
        let allow = match ace_type { SS::ACCESS_ALLOWED_ACE_TYPE => true, SS::ACCESS_DENIED_ACE_TYPE => false, _ => return Err(trace.unsafe_at(C::AceType)) };
        let size = d.u16_at(head, offset_of!(S::ACE_HEADER, AceSize))? as usize;
        let sid_offset = offset_of!(S::ACCESS_ALLOWED_ACE, SidStart);
        let end = offset.checked_add(size).ok_or(Error::Bounds)?;
        if size < sid_offset + 8 || size % 4 != 0 || end > acl_end { return Err(trace.unsafe_at(C::AceSize)); }
        let sid = observed.sid_at(raw, offset + sid_offset, end)?;
        if offset + sid_offset + sid.bytes.len() != end { return Err(trace.unsafe_at(C::AceSidSize)); }
        let ace = AceFact { allow, flags: head[offset_of!(S::ACE_HEADER, AceFlags)],
            mask: d.u32_at(raw, offset + offset_of!(S::ACCESS_ALLOWED_ACE, Mask))?, sid };
        match purpose {
            DescriptorPurpose::Runtime(kind, scope) => observed.safe_ace(&ace, kind, scope)?,
            DescriptorPurpose::PrivateCredential(user) => observed.private_ace(&ace, user)?,
        }
        aces.push(ace); offset = end;
    }
    // Remaining bytes belong to ACL free space, not implicit extra ACEs. The
    // caller retains actual inheritance/defaulted/control facts and every ACE.
    Ok(SecurityFacts { owner, control, revision: acl_revision, aces })
}
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenIdentity { pub token_id: u64, pub authentication_id: u64, pub modified_id: u64, pub groups: u32, pub privileges: u32 }
pub(crate) fn statistics(raw: &[u8]) -> Result<TokenIdentity> { Observed::new(Refusal::none()).statistics(raw) }
impl Observed<'_> {
pub(crate) fn statistics(self, raw: &[u8]) -> Result<TokenIdentity> {
    let d = super::decode::Observed::new(self.0);
    if raw.len() != size_of::<S::TOKEN_STATISTICS>() { return Err(self.0.unsafe_at(C::StatisticsSize)); }
    if d.u32_at(raw, offset_of!(S::TOKEN_STATISTICS, TokenType))? != S::TokenPrimary as u32 { return Err(self.0.unsafe_at(C::StatisticsType)); }
    let groups = d.u32_at(raw, offset_of!(S::TOKEN_STATISTICS, GroupCount))?;
    let privileges = d.u32_at(raw, offset_of!(S::TOKEN_STATISTICS, PrivilegeCount))?;
    if groups > 256 { return Err(self.0.unsafe_at(C::StatisticsGroups)); }
    if privileges > 64 { return Err(self.0.unsafe_at(C::StatisticsPrivileges)); }
    Ok(TokenIdentity { token_id: d.u64_at(raw, offset_of!(S::TOKEN_STATISTICS, TokenId))?,
        authentication_id: d.u64_at(raw, offset_of!(S::TOKEN_STATISTICS, AuthenticationId))?,
        modified_id: d.u64_at(raw, offset_of!(S::TOKEN_STATISTICS, ModifiedId))?, groups, privileges })
}
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupFact { pub sid: Sid, pub attributes: u32 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenFacts { pub identity: TokenIdentity, pub user: Sid, pub elevation_type: u32, pub groups: Vec<GroupFact>, pub privileges: Vec<(u64, u32)> }
impl TokenFacts {
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        let mut bytes = self.user.bytes.capacity()
            .checked_add(self.groups.capacity().checked_mul(size_of::<GroupFact>())?)?
            .checked_add(self.privileges.capacity().checked_mul(size_of::<(u64, u32)>())?)?;
        for group in &self.groups { bytes = bytes.checked_add(group.sid.bytes.capacity())?; }
        Some(bytes)
    }
}
fn pointed_sid(raw: &[u8], field: usize, minimum: usize) -> Result<Sid> {
    let pointer = usize::try_from(u64_at(raw, field)?).map_err(|_| Error::Unsafe)?;
    let offset = pointer.checked_sub(raw.as_ptr() as usize).ok_or(Error::Unsafe)?;
    if offset < minimum || offset % 4 != 0 { return Err(Error::Unsafe); }
    sid_at(raw, offset, raw.len()) // never dereference an unvalidated native pointer
}
fn groups(raw: &[u8], count: u32) -> Result<Vec<GroupFact>> {
    let header = offset_of!(S::TOKEN_GROUPS, Groups);
    if raw.len() > BUFFER || u32_at(raw, offset_of!(S::TOKEN_GROUPS, GroupCount))? != count || count > 256 { return Err(Error::Unsafe); }
    let extent = header.checked_add(count as usize * size_of::<S::SID_AND_ATTRIBUTES>()).ok_or(Error::Bounds)?;
    span(raw, 0, extent)?;
    let known = (SS::SE_GROUP_MANDATORY | SS::SE_GROUP_ENABLED_BY_DEFAULT | SS::SE_GROUP_ENABLED | SS::SE_GROUP_OWNER
        | SS::SE_GROUP_USE_FOR_DENY_ONLY | SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED | SS::SE_GROUP_RESOURCE | SS::SE_GROUP_LOGON_ID) as u32;
    let mut result = Vec::new();
    for i in 0..count as usize {
        let base = header + i * size_of::<S::SID_AND_ATTRIBUTES>();
        let sid = pointed_sid(raw, base + offset_of!(S::SID_AND_ATTRIBUTES, Sid), extent)?;
        let attributes = u32_at(raw, base + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))?;
        if attributes & !known != 0 || attributes & SS::SE_GROUP_USE_FOR_DENY_ONLY as u32 != 0 && attributes & SS::SE_GROUP_ENABLED as u32 != 0 { return Err(Error::Unsafe); }
        // A merely disabled trusted group may be enableable. All such groups,
        // not just Administrators, must be deny-only in this ordinary profile.
        if sid.trusted() && (attributes & SS::SE_GROUP_ENABLED as u32 != 0
            || attributes & SS::SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0) { return Err(Error::Unsafe); }
        result.push(GroupFact { sid, attributes });
    }
    Ok(result)
}
pub(crate) fn privileges(raw: &[u8], count: u32, allowed: &[u64; 5]) -> Result<Vec<(u64, u32)>> {
    let header = offset_of!(S::TOKEN_PRIVILEGES, Privileges);
    let element = size_of::<S::LUID_AND_ATTRIBUTES>();
    if count > 64 || raw.len() != header + count as usize * element
        || u32_at(raw, offset_of!(S::TOKEN_PRIVILEGES, PrivilegeCount))? != count { return Err(Error::Unsafe); }
    let mut result = Vec::new();
    for i in 0..count as usize {
        let at = header + i * element;
        let luid = u64_at(raw, at + offset_of!(S::LUID_AND_ATTRIBUTES, Luid))?;
        let attributes = u32_at(raw, at + offset_of!(S::LUID_AND_ATTRIBUTES, Attributes))?;
        // Presence matters: a disabled unapproved privilege may still be enabled.
        if !allowed.contains(&luid) || result.iter().any(|(prior, _)| *prior == luid)
            || attributes & !(S::SE_PRIVILEGE_ENABLED | S::SE_PRIVILEGE_ENABLED_BY_DEFAULT | S::SE_PRIVILEGE_USED_FOR_ACCESS) != 0 { return Err(Error::Unsafe); }
        result.push((luid, attributes));
    }
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn token_facts(identity: TokenIdentity, token_type: u32, elevated: u32, elevation_type: u32,
    ui_access: u32, virtualization: u32, user: &[u8], integrity: &[u8], group_bytes: &[u8], privilege_bytes: &[u8], allowed: &[u64; 5]) -> Result<TokenFacts> {
    if [user.len(), integrity.len(), group_bytes.len(), privilege_bytes.len()].iter().any(|n| *n > BUFFER)
        || token_type != S::TokenPrimary as u32 || elevated != 0 || ui_access != 0 || virtualization != 0
        || ![S::TokenElevationTypeDefault as u32, S::TokenElevationTypeLimited as u32].contains(&elevation_type)
        || user.len() < size_of::<S::TOKEN_USER>() || integrity.len() < size_of::<S::TOKEN_MANDATORY_LABEL>() { return Err(Error::Unsafe); }
    let user_sid = pointed_sid(user, offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid), size_of::<S::TOKEN_USER>())?;
    if !user_sid.account() || u32_at(user, offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))? != 0 { return Err(Error::Unsafe); }
    let label = pointed_sid(integrity, offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid), size_of::<S::TOKEN_MANDATORY_LABEL>())?;
    let attributes = u32_at(integrity, offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes))?;
    if !label.is(16, &[8192]) || attributes != (SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED) as u32 { return Err(Error::Unsafe); }
    Ok(TokenFacts { identity, user: user_sid, elevation_type, groups: groups(group_bytes, identity.groups)?,
        privileges: privileges(privilege_bytes, identity.privileges, allowed)? })
}

#[cfg(test)]
mod credential_tests {
    use super::*;
    fn sid(authority: u8, sub: &[u32]) -> Sid {
        let mut bytes = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, authority];
        for value in sub { bytes.extend_from_slice(&value.to_le_bytes()); }
        sid_at(&bytes, 0, bytes.len()).unwrap()
    }
    fn account() -> Sid { sid(5, &[21, 11, 22, 33, 1001]) }
    fn descriptor_bytes(owner: &Sid, aces: &[(bool, u8, u32, Sid)]) -> Vec<u8> {
        let header = size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>();
        let acl_at = header + owner.bytes.len();
        let acl_size = size_of::<S::ACL>() + aces.iter().map(|ace| 8 + ace.3.bytes.len()).sum::<usize>();
        let mut raw = vec![0u8; acl_at + acl_size];
        raw[0] = 1;
        raw[2..4].copy_from_slice(&(S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT).to_le_bytes());
        raw[4..8].copy_from_slice(&(header as u32).to_le_bytes());
        raw[16..20].copy_from_slice(&(acl_at as u32).to_le_bytes());
        raw[header..acl_at].copy_from_slice(&owner.bytes);
        raw[acl_at] = 2;
        raw[acl_at + 2..acl_at + 4].copy_from_slice(&(acl_size as u16).to_le_bytes());
        raw[acl_at + 4..acl_at + 6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
        let mut offset = acl_at + size_of::<S::ACL>();
        for (allow, flags, mask, sid) in aces {
            let size = 8 + sid.bytes.len();
            raw[offset] = if *allow { SS::ACCESS_ALLOWED_ACE_TYPE as u8 } else { SS::ACCESS_DENIED_ACE_TYPE as u8 };
            raw[offset + 1] = *flags;
            raw[offset + 2..offset + 4].copy_from_slice(&(size as u16).to_le_bytes());
            raw[offset + 4..offset + 8].copy_from_slice(&mask.to_le_bytes());
            raw[offset + 8..offset + size].copy_from_slice(&sid.bytes);
            offset += size;
        }
        raw
    }
    fn private(raw: &[u8], user: &Sid) -> Result<SecurityFacts> {
        Observed::new(Refusal::none()).credential_descriptor(raw, user)
    }
    #[test]
    fn credential_owner_policy_does_not_relax_immutable_runtime_policy() {
        let user = account(); let system = sid(5, &[18]);
        let raw = descriptor_bytes(&user, &[(true, 0, FS::FILE_ALL_ACCESS, user.clone()),
            (true, 0, FS::FILE_ALL_ACCESS, system.clone())]);
        assert!(private(&raw, &user).is_ok());
        assert!(descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion).is_err());
        let raw = descriptor_bytes(&system, &[(true, 0, FS::FILE_GENERIC_READ, user.clone())]);
        assert!(descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion).is_ok());
        assert!(private(&raw, &user).is_err());
        assert!(private(&descriptor_bytes(&user, &[]), &sid(5, &[21, 11, 22, 33, 1002])).is_err());
    }
    #[test]
    fn private_acl_rejects_foreign_content_and_control_even_after_a_deny() {
        let user = account(); let everyone = sid(1, &[0]);
        let harmless = FS::READ_CONTROL | FS::SYNCHRONIZE | FS::FILE_READ_ATTRIBUTES;
        assert!(private(&descriptor_bytes(&user, &[(true, 0, harmless, everyone.clone())]), &user).is_ok());
        for right in [FS::FILE_READ_DATA, FS::FILE_READ_EA, FS::FILE_WRITE_DATA, FS::FILE_APPEND_DATA,
            FS::FILE_WRITE_EA, FS::FILE_EXECUTE, FS::FILE_DELETE_CHILD, FS::FILE_WRITE_ATTRIBUTES,
            FS::DELETE, FS::WRITE_DAC, FS::WRITE_OWNER, F::GENERIC_READ, F::GENERIC_WRITE, F::GENERIC_EXECUTE, F::GENERIC_ALL] {
            let raw = descriptor_bytes(&user, &[(false, 0, right, everyone.clone()), (true, 0, right, everyone.clone())]);
            assert!(private(&raw, &user).is_err(), "foreign right {right:x}");
        }
    }
    #[test]
    fn private_acl_still_checks_unsupported_deny_and_inherit_only_records() {
        let user = account(); let everyone = sid(1, &[0]);
        let inherited = (S::OBJECT_INHERIT_ACE | S::INHERIT_ONLY_ACE) as u8;
        assert!(private(&descriptor_bytes(&user, &[(true, inherited, FS::FILE_ALL_ACCESS, everyone.clone())]), &user).is_ok());
        for (allow, flags, mask) in [(false, 0, 0x02000000), (true, inherited, 0x02000000), (false, 0x80, 0)] {
            assert!(private(&descriptor_bytes(&user, &[(allow, flags, mask, everyone.clone())]), &user).is_err());
        }
        let mut raw = descriptor_bytes(&user, &[(false, inherited, 0, everyone)]);
        let ace = size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>() + user.bytes.len() + size_of::<S::ACL>();
        raw[ace] = SS::ACCESS_ALLOWED_OBJECT_ACE_TYPE as u8;
        assert!(private(&raw, &user).is_err());
        let mut no_dacl = descriptor_bytes(&user, &[]);
        no_dacl[16..20].fill(0); assert!(private(&no_dacl, &user).is_err());
    }
    #[test]
    fn security_retention_accounts_for_ace_and_sid_capacities() {
        let user = account();
        let facts = private(&descriptor_bytes(&user, &[(true, 0, FS::FILE_ALL_ACCESS, user.clone())]), &user).unwrap();
        assert_eq!(facts.retained_heap_bytes(), Some(facts.owner.bytes.capacity()
            + facts.aces.capacity() * size_of::<AceFact>() + facts.aces[0].sid.bytes.capacity()));
    }
}

#[cfg(test)]
mod token_retained_capacity_data_tests {
    use super::*;
    #[test]
    fn token_retention_charges_actual_group_privilege_and_private_sid_capacities() {
        // Allocation DATA only. No token acquisition or admission is fabricated.
        let mut groups = Vec::with_capacity(4);
        groups.push(GroupFact { sid: Sid { bytes: Vec::with_capacity(64) }, attributes: 0 });
        let facts = TokenFacts { identity: TokenIdentity { token_id: 0, authentication_id: 0, modified_id: 0, groups: 0, privileges: 0 },
            user: Sid { bytes: Vec::with_capacity(32) }, elevation_type: 0, groups, privileges: Vec::with_capacity(8) };
        assert_eq!(facts.retained_heap_bytes(), Some(facts.user.bytes.capacity()
            + facts.groups.capacity() * size_of::<GroupFact>()
            + facts.privileges.capacity() * size_of::<(u64, u32)>()
            + facts.groups[0].sid.bytes.capacity()));
    }
}
