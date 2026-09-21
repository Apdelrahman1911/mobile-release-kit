//! Conservative owner/DACL and current-primary-token DATA policy. Unknown ACEs
//! are refused, not evaluated with an approximation of Windows Authz semantics.
use super::{AuthorityScope, Error, FileKind, Result, BUFFER};
use super::decode::{span, u16_at, u32_at, u64_at};
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
pub(crate) fn sid_at(raw: &[u8], offset: usize, end: usize) -> Result<Sid> {
    let head = span(raw, offset, 8)?;
    if head[0] != 1 || head[1] > 15 { return Err(Error::Unsafe); }
    let length = 8usize.checked_add(head[1] as usize * 4).ok_or(Error::Bounds)?;
    if offset.checked_add(length).ok_or(Error::Bounds)? > end { return Err(Error::Unsafe); }
    Ok(Sid { bytes: span(raw, offset, length)?.to_vec() })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AceFact { pub allow: bool, pub flags: u8, pub mask: u32, pub sid: Sid }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityFacts { pub owner: Sid, pub control: u16, pub revision: u8, pub aces: Vec<AceFact> }
fn expand(mask: u32) -> Result<u32> {
    let generic = F::GENERIC_READ | F::GENERIC_WRITE | F::GENERIC_EXECUTE | F::GENERIC_ALL;
    if mask & !(generic | FS::FILE_ALL_ACCESS) != 0 { return Err(Error::Unsafe); }
    let mut effective = mask & !generic;
    for (flag, rights) in [(F::GENERIC_READ, FS::FILE_GENERIC_READ), (F::GENERIC_WRITE, FS::FILE_GENERIC_WRITE),
        (F::GENERIC_EXECUTE, FS::FILE_GENERIC_EXECUTE), (F::GENERIC_ALL, FS::FILE_ALL_ACCESS)] {
        if mask & flag != 0 { effective |= rights; }
    }
    Ok(effective)
}
fn safe_ace(ace: &AceFact, kind: FileKind, scope: AuthorityScope) -> Result<()> {
    let allowed_flags = S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE | S::NO_PROPAGATE_INHERIT_ACE | S::INHERIT_ONLY_ACE | S::INHERITED_ACE;
    let flags = ace.flags as u32;
    if flags & !allowed_flags != 0 || (flags & (S::NO_PROPAGATE_INHERIT_ACE | S::INHERIT_ONLY_ACE) != 0
        && flags & (S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE) == 0) { return Err(Error::Unsafe); }
    let effective = expand(ace.mask)?; // reject unknown mask even for deny/inherit-only
    if !ace.allow || flags & S::INHERIT_ONLY_ACE != 0 || ace.sid.trusted() { return Ok(()); }
    let mut dangerous = FS::DELETE | FS::FILE_DELETE_CHILD | FS::WRITE_DAC | FS::WRITE_OWNER
        | FS::FILE_WRITE_EA | FS::FILE_WRITE_ATTRIBUTES;
    if kind == FileKind::File || scope == AuthorityScope::ImmutableVersion {
        dangerous |= FS::FILE_WRITE_DATA | FS::FILE_APPEND_DATA; // directory ADD_FILE/ADD_SUBDIRECTORY
    }
    if effective & dangerous != 0 { Err(Error::Unsafe) } else { Ok(()) }
}
fn overlap(a: (usize, usize), b: (usize, usize)) -> bool { a.0 < b.1 && b.0 < a.1 }
pub(crate) fn descriptor(raw: &[u8], kind: FileKind, scope: AuthorityScope) -> Result<SecurityFacts> {
    if raw.len() > BUFFER || raw.len() < size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>() { return Err(Error::Unsafe); }
    let header = size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>();
    let revision = raw[offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Revision)];
    let control = u16_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Control))?;
    let known = S::SE_OWNER_DEFAULTED | S::SE_GROUP_DEFAULTED | S::SE_DACL_PRESENT | S::SE_DACL_DEFAULTED
        | S::SE_SACL_PRESENT | S::SE_SACL_DEFAULTED | S::SE_DACL_AUTO_INHERIT_REQ | S::SE_SACL_AUTO_INHERIT_REQ
        | S::SE_DACL_AUTO_INHERITED | S::SE_SACL_AUTO_INHERITED | S::SE_DACL_PROTECTED | S::SE_SACL_PROTECTED | S::SE_SELF_RELATIVE;
    if revision != 1 || raw[offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Sbz1)] != 0 || control & !known != 0
        || control & (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT) != (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT)
        || u32_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Sacl))? != 0 { return Err(Error::Unsafe); }
    let owner_at = u32_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Owner))? as usize;
    let acl_at = u32_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl))? as usize;
    if owner_at < header || owner_at % 4 != 0 || acl_at < header || acl_at % 4 != 0 { return Err(Error::Unsafe); }
    let owner = sid_at(raw, owner_at, raw.len())?;
    if !owner.trusted() { return Err(Error::Unsafe); }
    let acl = span(raw, acl_at, size_of::<S::ACL>())?;
    let acl_revision = acl[offset_of!(S::ACL, AclRevision)];
    if !matches!(acl_revision, 2 | 4) || acl[offset_of!(S::ACL, Sbz1)] != 0 || u16_at(acl, offset_of!(S::ACL, Sbz2))? != 0 { return Err(Error::Unsafe); }
    let size = u16_at(acl, offset_of!(S::ACL, AclSize))? as usize;
    let count = u16_at(acl, offset_of!(S::ACL, AceCount))? as usize;
    if size < size_of::<S::ACL>() || size % 4 != 0 || count > 2048 { return Err(Error::Unsafe); }
    span(raw, acl_at, size)?;
    let acl_end = acl_at.checked_add(size).ok_or(Error::Bounds)?;
    let owner_range = (owner_at, owner_at + owner.bytes.len());
    if overlap(owner_range, (acl_at, acl_end)) { return Err(Error::Unsafe); }
    let group_at = u32_at(raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Group))? as usize;
    if group_at != 0 {
        if group_at < header || group_at % 4 != 0 { return Err(Error::Unsafe); }
        let group = sid_at(raw, group_at, raw.len())?;
        let range = (group_at, group_at + group.bytes.len());
        if overlap(range, (acl_at, acl_end)) || (range != owner_range && overlap(range, owner_range)) { return Err(Error::Unsafe); }
    }
    let mut aces = Vec::new();
    aces.try_reserve(count).map_err(|_| Error::Bounds)?;
    let mut offset = acl_at + size_of::<S::ACL>();
    for _ in 0..count {
        let head = span(raw, offset, size_of::<S::ACE_HEADER>())?;
        let ace_type = head[offset_of!(S::ACE_HEADER, AceType)] as u32;
        // Refuse EVERY unsupported ACE before considering INHERIT_ONLY or allow.
        let allow = match ace_type { SS::ACCESS_ALLOWED_ACE_TYPE => true, SS::ACCESS_DENIED_ACE_TYPE => false, _ => return Err(Error::Unsafe) };
        let size = u16_at(head, offset_of!(S::ACE_HEADER, AceSize))? as usize;
        let sid_offset = offset_of!(S::ACCESS_ALLOWED_ACE, SidStart);
        let end = offset.checked_add(size).ok_or(Error::Bounds)?;
        if size < sid_offset + 8 || size % 4 != 0 || end > acl_end { return Err(Error::Unsafe); }
        let sid = sid_at(raw, offset + sid_offset, end)?;
        if offset + sid_offset + sid.bytes.len() != end { return Err(Error::Unsafe); }
        let ace = AceFact { allow, flags: head[offset_of!(S::ACE_HEADER, AceFlags)],
            mask: u32_at(raw, offset + offset_of!(S::ACCESS_ALLOWED_ACE, Mask))?, sid };
        safe_ace(&ace, kind, scope)?;
        aces.push(ace); offset = end;
    }
    // Remaining bytes belong to ACL free space, not implicit extra ACEs. The
    // caller retains actual inheritance/defaulted/control facts and every ACE.
    Ok(SecurityFacts { owner, control, revision: acl_revision, aces })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenIdentity { pub token_id: u64, pub authentication_id: u64, pub modified_id: u64, pub groups: u32, pub privileges: u32 }
pub(crate) fn statistics(raw: &[u8]) -> Result<TokenIdentity> {
    if raw.len() != size_of::<S::TOKEN_STATISTICS>() || u32_at(raw, offset_of!(S::TOKEN_STATISTICS, TokenType))? != S::TokenPrimary as u32 { return Err(Error::Unsafe); }
    let groups = u32_at(raw, offset_of!(S::TOKEN_STATISTICS, GroupCount))?;
    let privileges = u32_at(raw, offset_of!(S::TOKEN_STATISTICS, PrivilegeCount))?;
    if groups > 256 || privileges > 64 { return Err(Error::Unsafe); }
    Ok(TokenIdentity { token_id: u64_at(raw, offset_of!(S::TOKEN_STATISTICS, TokenId))?,
        authentication_id: u64_at(raw, offset_of!(S::TOKEN_STATISTICS, AuthenticationId))?,
        modified_id: u64_at(raw, offset_of!(S::TOKEN_STATISTICS, ModifiedId))?, groups, privileges })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupFact { pub sid: Sid, pub attributes: u32 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenFacts { pub identity: TokenIdentity, pub user: Sid, pub elevation_type: u32, pub groups: Vec<GroupFact>, pub privileges: Vec<(u64, u32)> }
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
