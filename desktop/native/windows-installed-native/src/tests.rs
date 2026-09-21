//! Inert source-contract definitions, not native success evidence. These tests
//! never call invoke(), NativeBook::call(), an original read/open/close operation,
//! or any OS API. Only production state transitions and bounded DATA decoders run.
use super::*;
use windows_sys::Win32::System::SystemServices as SS;

// Every arena/handle below is an inert fixture, never entered into the OS. It is
// therefore safe to release these allocations, unlike real unresolved storage.
struct Inert { book: NativeBook }
impl Inert { fn new() -> Self { Self { book: NativeBook::new() } } }
impl Drop for Inert {
    fn drop(&mut self) {
        if let Some(frame) = self.book.active.take() { drop(ManuallyDrop::into_inner(frame)); }
        for slot in self.book.slots.drain(..) { drop(ManuallyDrop::into_inner(slot)); }
    }
}
fn enter_inert(book: &mut NativeBook, call: Call, handle: F::HANDLE) -> Result<()> {
    assert!(book.active.is_none());
    let output_handle = match call {
        Call::Open(i) | Call::ProcessToken(i) | Call::ThreadToken(i) => book.slot(i)?.output.get(),
        _ => null_mut(),
    };
    book.active = Some(ManuallyDrop::new(Box::pin(Arena {
        call, phase: Cell::new(Phase::Prepared), returned: Cell::new(None),
        input: Vec::new(), handle, output_handle, unicode: F::UNICODE_STRING::default(),
        attributes: OBJECT_ATTRIBUTES::default(), directory: false,
        bytes: UnsafeCell::new(Aligned([0; BUFFER])), count: UnsafeCell::new(u32::MAX),
        iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK {
            Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: usize::MAX,
        }), _pin: PhantomPinned,
    })));
    book.mark_entered(call)
}
fn return_inert(book: &mut NativeBook, returned: Returned, output: Option<F::HANDLE>,
    status: i32, information: usize) -> Result<Complete> {
    let frame = book.arena()?;
    // SAFETY: fixture allocations have never been passed to native code. There
    // is no concurrent writer and these are their real, pinned output addresses.
    unsafe {
        if let Some(value) = output {
            assert!(!frame.output_handle.is_null()); *frame.output_handle = value;
        }
        *frame.iosb.get() = IO::IO_STATUS_BLOCK {
            Anonymous: IO::IO_STATUS_BLOCK_0 { Status: status }, Information: information,
        };
    }
    frame.returned.set(Some(returned)); frame.phase.set(Phase::Returned);
    let call = frame.call;
    book.finish(call, returned)
}
fn own_inert(book: &mut NativeBook, original: &Original, number: usize) -> Result<()> {
    enter_inert(book, Call::Open(original.index), null_mut())?;
    return_inert(book, Returned::Nt(F::STATUS_SUCCESS), Some(number as F::HANDLE),
        F::STATUS_SUCCESS, WP::FILE_OPENED as usize)?;
    Ok(())
}

#[test]
fn original_destinations_are_stable_registered_and_book_bound() -> Result<()> {
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    assert!(book.never_started());
    let first = book.reserve(Kind::File, None, "first", "first".to_owned())?;
    let destination = book.slot(first.index)?.output.get();
    for i in 0..32 {
        let name = format!("entry-{i}"); book.reserve(Kind::File, None, &name, name.clone())?;
    }
    assert_eq!(book.slot(first.index)?.output.get(), destination);
    assert!(matches!(book.reserve(Kind::File, None, "first", "first".to_owned()), Err(Error::State)));
    let mut other = Inert::new();
    let foreign = other.book.reserve(Kind::File, None, "foreign", "foreign".to_owned())?;
    assert_eq!(book.index(&foreign), Err(Error::State));
    enter_inert(book, Call::Open(first.index), null_mut())?;
    assert_eq!(book.arena()?.output_handle, destination);
    assert_eq!(book.state(&first)?, SlotState::Acquiring);
    assert!(book.started && book.active.is_some());
    return_inert(book, Returned::Nt(F::STATUS_SUCCESS), Some(11usize as F::HANDLE),
        F::STATUS_SUCCESS, WP::FILE_OPENED as usize)?;
    assert_eq!(book.state(&first)?, SlotState::Owned);
    assert!(book.active.is_none());
    Ok(())
}

#[test]
fn pending_and_lost_completion_keep_the_exact_arena_and_slots() -> Result<()> {
    for (call, returned) in [
        (Call::Open(0), Returned::Nt(F::STATUS_PENDING)),
        (Call::ProcessToken(0), Returned::Boolean(0, F::ERROR_IO_PENDING)),
        (Call::Read(1), Returned::Boolean(0, F::ERROR_IO_PENDING)),
        (Call::FinalName, Returned::Count(0, F::ERROR_IO_PENDING)),
        (Call::Folder, Returned::Hresult(HRESULT_PENDING)),
    ] {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        let kind = if matches!(call, Call::ProcessToken(_)) { Kind::ProcessToken } else { Kind::File };
        let key = book.reserve(kind, None, "pending", "pending".to_owned())?;
        let acquiring = matches!(call, Call::Open(_) | Call::ProcessToken(_));
        if !acquiring { own_inert(book, &key, 21)?; }
        let destination = book.slot(key.index)?.output.get();
        enter_inert(book, call, if acquiring { null_mut() } else { 21usize as F::HANDLE })?;
        let arena = book.arena()? as *const Arena;
        assert!(matches!(return_inert(book, returned, None, F::STATUS_PENDING, usize::MAX), Err(Error::Unknown)));
        assert!(book.is_unknown());
        assert_eq!(book.arena()? as *const Arena, arena);
        assert_eq!(book.slot(key.index)?.output.get(), destination);
        assert_eq!(book.state(&key)?, if acquiring { SlotState::Acquiring } else { SlotState::Owned });
        assert!(!book.settled());
    }
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    let key = book.reserve(Kind::File, None, "lost", "lost".to_owned())?;
    enter_inert(book, Call::Open(key.index), null_mut())?;
    // Simulated loss only; no real worker exists in these definitions.
    book.mark_interrupted();
    assert!(matches!(return_inert(book, Returned::Nt(F::STATUS_SUCCESS), Some(22usize as F::HANDLE),
        F::STATUS_SUCCESS, WP::FILE_OPENED as usize), Err(Error::Unknown)));
    assert_eq!(book.state(&key)?, SlotState::Acquiring); // Unknown never promotes
    assert!(book.active.is_some());
    Ok(())
}

#[test]
fn acquisition_needs_a_definite_consistent_receipt() -> Result<()> {
    for (status, handle, io, information, no_handle) in [
        (F::STATUS_ACCESS_DENIED, null_mut(), F::STATUS_PENDING, usize::MAX, true),
        (F::STATUS_ACCESS_DENIED, 31usize as F::HANDLE, F::STATUS_PENDING, usize::MAX, false),
        (F::STATUS_SUCCESS, null_mut(), F::STATUS_SUCCESS, WP::FILE_OPENED as usize, false),
        (F::STATUS_SUCCESS, F::INVALID_HANDLE_VALUE, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, false),
        (F::STATUS_SUCCESS, 32usize as F::HANDLE, F::STATUS_PENDING, WP::FILE_OPENED as usize, false),
        (F::STATUS_SUCCESS, 33usize as F::HANDLE, F::STATUS_SUCCESS, usize::MAX, false),
        (1, null_mut(), F::STATUS_SUCCESS, WP::FILE_OPENED as usize, false),
    ] {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        let key = book.reserve(Kind::File, None, "receipt", "receipt".to_owned())?;
        enter_inert(book, Call::Open(key.index), null_mut())?;
        let result = return_inert(book, Returned::Nt(status), Some(handle), io, information);
        if no_handle {
            assert!(matches!(result, Err(Error::Unavailable)));
            assert_eq!(book.state(&key)?, SlotState::NoHandle);
            assert!(book.active.is_none() && !book.is_unknown());
            assert!(matches!(book.reserve(Kind::File, None, "receipt", "receipt".to_owned()), Err(Error::State)));
        } else {
            assert!(matches!(result, Err(Error::Unknown)));
            assert!(book.active.is_some() && book.is_unknown());
        }
    }
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    let first = book.reserve(Kind::File, None, "one", "one".to_owned())?;
    own_inert(book, &first, 34)?;
    let second = book.reserve(Kind::File, None, "two", "two".to_owned())?;
    enter_inert(book, Call::Open(second.index), null_mut())?;
    assert!(matches!(return_inert(book, Returned::Nt(F::STATUS_SUCCESS), Some(34usize as F::HANDLE),
        F::STATUS_SUCCESS, WP::FILE_OPENED as usize), Err(Error::Unknown)));
    assert_eq!(book.state(&first)?, SlotState::Owned);
    Ok(())
}

#[test]
fn close_retires_before_entry_and_failure_is_never_retried() -> Result<()> {
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    let first = book.reserve(Kind::File, None, "close-one", "close-one".to_owned())?;
    own_inert(book, &first, 41)?;
    let other = book.reserve(Kind::File, None, "close-two", "close-two".to_owned())?;
    own_inert(book, &other, 42)?;
    book.retiring = true;
    enter_inert(book, Call::Close(first.index), 41usize as F::HANDLE)?;
    assert_eq!(book.state(&first)?, SlotState::Closing);
    // SAFETY: inert cell, not a native borrower or OS write destination.
    assert!(unsafe { *book.slot(first.index)?.output.get() }.is_null());
    assert_eq!(book.arena()?.handle, 41usize as F::HANDLE);
    assert!(matches!(return_inert(book, Returned::Boolean(0, F::ERROR_INVALID_HANDLE), None, 0, 0), Err(Error::Unknown)));
    assert_eq!(book.state(&first)?, SlotState::Unknown);
    assert!(book.active.is_none()); // completed close has no pending output buffer
    enter_inert(book, Call::Close(other.index), 42usize as F::HANDLE)?;
    return_inert(book, Returned::Boolean(1, 0), None, 0, 0)?;
    assert_eq!(book.state(&other)?, SlotState::Closed);
    assert!(book.is_unknown() && !book.settled());
    assert!(matches!(enter_inert(book, Call::Close(first.index), 41usize as F::HANDLE), Err(Error::Unknown)));
    assert!(matches!(return_inert(book, Returned::Boolean(1, 0), None, 0, 0), Err(Error::Unknown)));
    assert_eq!(book.state(&first)?, SlotState::Unknown);
    Ok(())
}

fn put16(raw: &mut [u8], at: usize, value: u16) { raw[at..at+2].copy_from_slice(&value.to_le_bytes()); }
fn put32(raw: &mut [u8], at: usize, value: u32) { raw[at..at+4].copy_from_slice(&value.to_le_bytes()); }
fn put64(raw: &mut [u8], at: usize, value: u64) { raw[at..at+8].copy_from_slice(&value.to_le_bytes()); }
fn sid(authority: u8, sub: &[u32]) -> Vec<u8> {
    let mut raw = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, authority];
    for n in sub { raw.extend_from_slice(&n.to_le_bytes()); } raw
}
fn descriptor(owner: &[u8], aces: &[(u8, u8, u32, Vec<u8>)]) -> Vec<u8> {
    let mut raw = vec![0; size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>()];
    raw[offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Revision)] = 1;
    put16(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Control), S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT);
    let owner_at = raw.len(); raw.extend_from_slice(owner);
    let acl_at = raw.len(); raw.resize(acl_at + size_of::<S::ACL>(), 0);
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Owner), owner_at as u32);
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl), acl_at as u32);
    raw[acl_at + offset_of!(S::ACL, AclRevision)] = 2;
    put16(&mut raw, acl_at + offset_of!(S::ACL, AceCount), aces.len() as u16);
    for (kind, flags, mask, principal) in aces {
        let at = raw.len(); let size = offset_of!(S::ACCESS_ALLOWED_ACE, SidStart) + principal.len();
        raw.resize(at + size, 0);
        raw[at + offset_of!(S::ACE_HEADER, AceType)] = *kind;
        raw[at + offset_of!(S::ACE_HEADER, AceFlags)] = *flags;
        put16(&mut raw, at + offset_of!(S::ACE_HEADER, AceSize), size as u16);
        put32(&mut raw, at + offset_of!(S::ACCESS_ALLOWED_ACE, Mask), *mask);
        raw[at + offset_of!(S::ACCESS_ALLOWED_ACE, SidStart)..at+size].copy_from_slice(principal);
    }
    let size = raw.len() - acl_at;
    put16(&mut raw, acl_at + offset_of!(S::ACL, AclSize), size as u16); raw
}

#[test]
fn acl_distinguishes_sibling_creation_from_replacement_and_mutation() -> Result<()> {
    let owner = sid(5, &[18]); let everyone = sid(1, &[0]);
    let allow = SS::ACCESS_ALLOWED_ACE_TYPE as u8; let deny = SS::ACCESS_DENIED_ACE_TYPE as u8;
    let raw = descriptor(&owner, &[(allow, 0, F::GENERIC_READ, everyone.clone())]);
    let facts = security::descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion)?;
    assert_eq!(facts.owner.bytes(), owner.as_slice()); assert_eq!(facts.aces.len(), 1);
    for right in [FS::DELETE, FS::FILE_DELETE_CHILD, FS::WRITE_DAC, FS::WRITE_OWNER,
        FS::FILE_WRITE_EA, FS::FILE_WRITE_ATTRIBUTES, FS::FILE_WRITE_DATA, FS::FILE_APPEND_DATA, F::GENERIC_WRITE] {
        let raw = descriptor(&owner, &[(deny, 0, right, everyone.clone()), (allow, 0, right, everyone.clone())]);
        assert_eq!(security::descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    }
    let sibling = descriptor(&owner, &[(allow, 0, FS::FILE_WRITE_DATA | FS::FILE_APPEND_DATA, everyone.clone())]);
    assert!(security::descriptor(&sibling, FileKind::Directory, AuthorityScope::AncestorOutsideVersion).is_ok());
    assert_eq!(security::descriptor(&sibling, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let replacement = descriptor(&owner, &[(allow, 0, FS::FILE_DELETE_CHILD, everyone.clone())]);
    assert_eq!(security::descriptor(&replacement, FileKind::Directory, AuthorityScope::AncestorOutsideVersion), Err(Error::Unsafe));
    let flags = (S::OBJECT_INHERIT_ACE | S::INHERIT_ONLY_ACE) as u8;
    let inherited = descriptor(&owner, &[(allow, flags, F::GENERIC_ALL, everyone.clone())]);
    assert!(security::descriptor(&inherited, FileKind::Directory, AuthorityScope::AncestorOutsideVersion).is_ok());
    let unsupported = descriptor(&owner, &[(255, flags, F::GENERIC_READ, everyone.clone())]);
    assert_eq!(security::descriptor(&unsupported, FileKind::Directory, AuthorityScope::AncestorOutsideVersion), Err(Error::Unsafe));
    let unknown_mask = descriptor(&owner, &[(deny, 0, 0x02000000, everyone.clone())]);
    assert_eq!(security::descriptor(&unknown_mask, FileKind::File, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let untrusted_owner = descriptor(&everyone, &[(allow, 0, F::GENERIC_READ, everyone.clone())]);
    assert_eq!(security::descriptor(&untrusted_owner, FileKind::File, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    Ok(())
}

#[test]
fn acl_bounds_and_actual_trusted_sid_are_required() -> Result<()> {
    let owner = sid(5, &[80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464]);
    let mut raw = descriptor(&owner, &[]);
    assert!(security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion).is_ok());
    assert_eq!(security::descriptor(&raw[..raw.len()-1], FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let acl_at = decode::u32_at(&raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl))?;
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl), 0);
    assert_eq!(security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl), acl_at);
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Group), acl_at);
    assert_eq!(security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let system = sid(5, &[18]);
    let mut overlapping = descriptor(&system, &[(SS::ACCESS_ALLOWED_ACE_TYPE as u8, 0, F::GENERIC_READ, system.clone())]);
    let dacl = decode::u32_at(&overlapping, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl))? as usize;
    // Valid trusted owner SID, but illegally borrowed from inside its DACL ACE.
    let owner_in_ace = dacl + size_of::<S::ACL>() + offset_of!(S::ACCESS_ALLOWED_ACE, SidStart);
    put32(&mut overlapping, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Owner), owner_in_ace as u32);
    assert_eq!(security::descriptor(&overlapping, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let lookalike = descriptor(&sid(5, &[80, 956008885, 3418522649, 1831038044, 1853292631, 2271478465]), &[]);
    assert_eq!(security::descriptor(&lookalike, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    Ok(())
}

fn token_sid(header: usize, field: usize, attributes: usize, flags: u32, principal: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; header + principal.len()]; raw[header..].copy_from_slice(principal);
    let address = raw.as_ptr() as usize + header;
    put64(&mut raw, field, address as u64); put32(&mut raw, attributes, flags); raw
}
#[test]
fn token_context_pointer_bounds_and_enableable_authority_are_checked() -> Result<()> {
    let allowed = [101, 102, 103, 104, 105];
    let identity = TokenIdentity { token_id: 1, authentication_id: 2, modified_id: 3, groups: 1, privileges: 1 };
    let user_field = offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid);
    let mut user = token_sid(size_of::<S::TOKEN_USER>(), user_field,
        offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes), 0, &sid(5, &[21, 11, 22, 33, 1001]));
    let mut integrity = token_sid(size_of::<S::TOKEN_MANDATORY_LABEL>(),
        offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
        offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes),
        (SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED) as u32, &sid(16, &[8192]));
    let group_header = offset_of!(S::TOKEN_GROUPS, Groups);
    let group_attribute = group_header + offset_of!(S::SID_AND_ATTRIBUTES, Attributes);
    let mut groups = token_sid(group_header + size_of::<S::SID_AND_ATTRIBUTES>(),
        group_header + offset_of!(S::SID_AND_ATTRIBUTES, Sid), group_attribute,
        SS::SE_GROUP_USE_FOR_DENY_ONLY as u32, &sid(5, &[32, 544]));
    put32(&mut groups, offset_of!(S::TOKEN_GROUPS, GroupCount), 1);
    let privilege = offset_of!(S::TOKEN_PRIVILEGES, Privileges);
    let mut privileges = vec![0; privilege + size_of::<S::LUID_AND_ATTRIBUTES>()];
    put32(&mut privileges, offset_of!(S::TOKEN_PRIVILEGES, PrivilegeCount), 1);
    put64(&mut privileges, privilege + offset_of!(S::LUID_AND_ATTRIBUTES, Luid), allowed[0]);
    let check = |u: &[u8], i: &[u8], g: &[u8], p: &[u8], elevated: u32| security::token_facts(identity,
        S::TokenPrimary as u32, elevated, S::TokenElevationTypeLimited as u32, 0, 0, u, i, g, p, &allowed);
    assert!(check(&user, &integrity, &groups, &privileges, 0).is_ok());
    assert_eq!(check(&user, &integrity, &groups, &privileges, 1), Err(Error::Unsafe));
    let address = user.as_ptr() as usize;
    for pointer in [0, address, address + user.len(), address + size_of::<S::TOKEN_USER>() + 1] {
        put64(&mut user, user_field, pointer as u64);
        assert_eq!(check(&user, &integrity, &groups, &privileges, 0), Err(Error::Unsafe));
    }
    put64(&mut user, user_field, (address + size_of::<S::TOKEN_USER>()) as u64);
    put32(&mut integrity, size_of::<S::TOKEN_MANDATORY_LABEL>() + 8, 12288); // high, not medium
    assert_eq!(check(&user, &integrity, &groups, &privileges, 0), Err(Error::Unsafe));
    put32(&mut integrity, size_of::<S::TOKEN_MANDATORY_LABEL>() + 8, 8192);
    for flags in [0, SS::SE_GROUP_ENABLED as u32, (SS::SE_GROUP_ENABLED | SS::SE_GROUP_USE_FOR_DENY_ONLY) as u32] {
        put32(&mut groups, group_attribute, flags);
        assert_eq!(check(&user, &integrity, &groups, &privileges, 0), Err(Error::Unsafe));
    }
    put32(&mut groups, group_attribute, SS::SE_GROUP_USE_FOR_DENY_ONLY as u32);
    put64(&mut privileges, privilege + offset_of!(S::LUID_AND_ATTRIBUTES, Luid), 999); // present but disabled
    assert_eq!(check(&user, &integrity, &groups, &privileges, 0), Err(Error::Unsafe));
    Ok(())
}

fn entry(name: &str, id: [u8; 16]) -> Vec<u8> {
    let text: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let header = offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileName);
    let mut raw = vec![0; header + text.len()]; raw[header..].copy_from_slice(&text);
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileNameLength), text.len() as u32);
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes), FS::FILE_ATTRIBUTE_NORMAL);
    let at = offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileId); raw[at..at+16].copy_from_slice(&id); raw
}
#[test]
fn metadata_and_directory_keep_the_full_identity_not_a_low_half() -> Result<()> {
    let mut basic = vec![0; size_of::<FS::FILE_BASIC_INFO>()];
    let mut standard = vec![0; size_of::<FS::FILE_STANDARD_INFO>()];
    let mut tag = vec![0; size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>()];
    let mut id = vec![0; size_of::<FS::FILE_ID_INFO>()];
    put32(&mut basic, offset_of!(FS::FILE_BASIC_INFO, FileAttributes), FS::FILE_ATTRIBUTE_NORMAL);
    put32(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, NumberOfLinks), 1);
    put64(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, EndOfFile), 37);
    put64(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, AllocationSize), 4096);
    put32(&mut tag, offset_of!(FS::FILE_ATTRIBUTE_TAG_INFO, FileAttributes), FS::FILE_ATTRIBUTE_NORMAL);
    put64(&mut id, offset_of!(FS::FILE_ID_INFO, VolumeSerialNumber), 0x1122334455667788);
    let mut full = [0u8; 16]; full[0] = 1; full[15] = 0x80;
    let at = offset_of!(FS::FILE_ID_INFO, FileId); id[at..at+16].copy_from_slice(&full);
    let before = decode::metadata(FileKind::File, &basic, &standard, &tag, &id)?;
    assert_eq!(before.identity, FileIdentity { volume_serial: 0x1122334455667788, file_id: full });
    put64(&mut basic, offset_of!(FS::FILE_BASIC_INFO, LastAccessTime), 1234);
    assert_eq!(decode::metadata(FileKind::File, &basic, &standard, &tag, &id)?, before);
    id[at+15] = 0x81;
    assert_ne!(decode::metadata(FileKind::File, &basic, &standard, &tag, &id)?.identity, before.identity);
    standard[offset_of!(FS::FILE_STANDARD_INFO, Directory)] = 2; // not a Rust bool
    assert_eq!(decode::metadata(FileKind::File, &basic, &standard, &tag, &id), Err(Error::Unsafe));
    let mut raw = entry("original.dll", full);
    // Undefined ordinary ReparsePointTag is not read as an authority assertion.
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, ReparsePointTag), 0xdeadbeef);
    let entries = decode::directory(&raw)?;
    assert_eq!(entries.len(), 1); assert_eq!(entries[0].file_id, full);
    assert_eq!(decode::directory(&raw[..raw.len()-1]), Err(Error::Unsafe));
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, NextEntryOffset), 8);
    assert_eq!(decode::directory(&raw), Err(Error::Unsafe));
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, NextEntryOffset), 0);
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes), 0x80000000);
    assert_eq!(decode::directory(&raw), Err(Error::Unsafe));
    Ok(())
}

fn stream(name: &str) -> Vec<u8> {
    let text: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let header = offset_of!(N::FILE_STREAM_INFORMATION, StreamName);
    let mut raw = vec![0; header + text.len()]; raw[header..].copy_from_slice(&text);
    put32(&mut raw, offset_of!(N::FILE_STREAM_INFORMATION, StreamNameLength), text.len() as u32); raw
}
#[test]
fn stream_and_component_refusals_cannot_be_treated_as_absence() -> Result<()> {
    let unnamed = stream("::$DATA");
    assert_eq!(decode::streams(&unnamed, FileKind::File), Ok(()));
    assert_eq!(decode::streams(&[], FileKind::Directory), Ok(()));
    assert_eq!(decode::streams(&[], FileKind::File), Err(Error::Unsafe));
    assert_eq!(decode::streams(&stream(":hidden:$DATA"), FileKind::File), Err(Error::Unsafe));
    assert_eq!(decode::streams(&unnamed[..unnamed.len()-1], FileKind::File), Err(Error::Unsafe));
    let mut multiple = unnamed.clone();
    put32(&mut multiple, offset_of!(N::FILE_STREAM_INFORMATION, NextEntryOffset), 8);
    assert_eq!(decode::streams(&multiple, FileKind::File), Err(Error::Unsafe));
    for name in ["", ".", "..", "NUL", "COM1.txt", "LPT¹", "trailing.", "trailing ", "a:b", "a\\b", "a\0b"] {
        assert!(!decode::component(name));
    }
    for name in ["C:\\Program Files", "D:\\Windows\\System32"] { assert!(decode::dos_location(name).is_ok()); }
    for name in ["\\\\host\\share", "C:relative", "C:\\", "C:\\Windows\\..", "C:\\Windows\\"] {
        assert!(decode::dos_location(name).is_err());
    }
    let mapped: Vec<u8> = "\\Device\\HarddiskVolume3\0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(decode::mapping(&mapped)?, "\\Device\\HarddiskVolume3");
    let subst: Vec<u8> = "\\??\\C:\\elsewhere\0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(decode::mapping(&subst), Err(Error::Unsafe));
    Ok(())
}
