//! One fresh WebView2 user-data directory. Uses the existing original-handle
//! book/decoders/budgets; no pathname recursive deletion or shared cache cleanup.
use super::*;

struct OpenFrame {
    index: usize,
    attributes: OBJECT_ATTRIBUTES,
    unicode: F::UNICODE_STRING,
    security: Vec<u8>,
    iosb: UnsafeCell<IO::IO_STATUS_BLOCK>,
    deletion: UnsafeCell<FS::FILE_DISPOSITION_INFO>,
    returned: bool,
    deletion_entered: Cell<bool>,
    _pin: PhantomPinned,
}
pub(super) struct Profile {
    root: Option<Original>,
    frames: Vec<Held<OpenFrame>>,
    path: PathBuf,
    name: String,
    created: bool,
    unknown: bool,
    final_attempted: bool,
    removed: bool,
}
impl Profile {
    pub(super) fn new() -> Self { Self { root: None, frames: Vec::new(), path: PathBuf::new(),
        name: String::new(), created: false, unknown: false, final_attempted: false, removed: false } }
    pub(super) fn path(&self) -> UiResult<&Path> {
        if self.created && !self.unknown && !self.final_attempted { Ok(&self.path) } else { Err(UiError::State) }
    }
    pub(super) fn create(&mut self, prerequisites: &mut Prerequisites) -> UiResult<()> {
        if self.root.is_some() || self.created || self.final_attempted { return Err(UiError::State); }
        prerequisites.recheck()?;
        let parent = prerequisites.parent.ok_or(UiError::State)?;
        let parent_index = prerequisites.paths[parent].original.index;
        let user = prerequisites.native.user.as_ref().ok_or(UiError::State)?.user.clone();
        let mut nonce = [0u8; 16];
        if unsafe { windows_sys::Win32::Security::Cryptography::BCryptGenRandom(null_mut(),
            nonce.as_mut_ptr(), nonce.len() as u32, windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG) } != F::STATUS_SUCCESS {
            return Err(UiError::NativeFailure);
        }
        self.name = "mrk-webview2-".to_owned();
        for byte in nonce { use std::fmt::Write; write!(&mut self.name, "{byte:02x}").map_err(|_| UiError::NativeFailure)?; }
        self.path = PathBuf::from(&prerequisites.local_data).join(&self.name);
        let original = self.reserve(&mut prerequisites.native, parent_index, &self.name.clone(), FileKind::Directory)?;
        let index = original.index;
        self.root = Some(original); // BEFORE FILE_CREATE, including pending/partial return.
        let admitted = (|| {
            // Include post-create handle admission in the same failure latch as
            // metadata/DACL admission; it may fail after the create was real.
            self.open(&mut prerequisites.native, index, true, Some(&user))?;
            let root = self.root.as_ref().ok_or(UiError::State)?;
            mapped(prerequisites.native.metadata(root), UiError::UserDataParent)?;
            let descriptor = mapped(prerequisites.native.original_call(root.index, Call::Security), UiError::UserDataParent)?;
            let count = mapped(descriptor.count(), UiError::UserDataParent)?;
            root_descriptor(mapped(descriptor.bytes(count), UiError::UserDataParent)?, &user)
        })();
        self.finish_admission(admitted)
    }
    fn finish_admission(&mut self, admitted: UiResult<()>) -> UiResult<()> {
        if self.unknown || self.created && admitted.is_err() {
            // The create was real, but its identity/private-descriptor contract
            // did not hold. Do not follow it with recursive cleanup of contents
            // whose private ownership could not be established.
            self.unknown = true; return Err(UiError::CleanupUnknown);
        }
        admitted // A positively proved no-create refusal remains distinguishable.
    }
    fn reserve(&mut self, book: &mut NativeBook, parent: usize, name: &str, kind: FileKind) -> UiResult<Original> {
        if self.unknown || !decode::component(name) { return Err(UiError::State); }
        let parent_name = mapped(book.slot(parent), UiError::UserDataParent)?.canonical.clone();
        let canonical = format!("{parent_name}\\{name}");
        if canonical.encode_utf16().count() >= NAME_UNITS { return Err(UiError::UserDataParent); }
        mapped(book.reserve(kind.into(), Some(parent), name, canonical), UiError::UserDataParent)
    }
    fn open(&mut self, book: &mut NativeBook, index: usize, create: bool, user: Option<&Sid>) -> UiResult<()> {
        if self.unknown { return Err(UiError::CleanupUnknown); }
        let slot = mapped(book.slot(index), UiError::State)?;
        let directory = slot.kind == Kind::Directory;
        let parent = mapped(book.handle(slot.parent.ok_or(UiError::State)?), UiError::State)?;
        let output = slot.output.get();
        let name = slot.name.as_ptr(); let name_bytes = (slot.name.len() - 1) * 2;
        let security = if create { private_descriptor(user.ok_or(UiError::State)?)? } else { Vec::new() };
        let frame = Box::pin(OpenFrame {
            index,
            attributes: OBJECT_ATTRIBUTES { Length: size_of::<OBJECT_ATTRIBUTES>() as u32, RootDirectory: parent,
                ObjectName: null(), Attributes: F::OBJ_DONT_REPARSE,
                SecurityDescriptor: null(), SecurityQualityOfService: null() },
            unicode: F::UNICODE_STRING { Length: name_bytes as u16, MaximumLength: (name_bytes + 2) as u16, Buffer: name.cast_mut() },
            security, iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK { Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: usize::MAX }),
            deletion: UnsafeCell::new(FS::FILE_DISPOSITION_INFO { DeleteFile: true }),
            returned: false, deletion_entered: Cell::new(false), _pin: PhantomPinned,
        });
        self.frames.push(ManuallyDrop::new(frame));
        let frame = self.frames.last_mut().ok_or(UiError::State)?;
        // Fields are initialized only after the exact original is pinned/retained.
        let frame = unsafe { frame.as_mut().get_unchecked_mut() };
        frame.attributes.ObjectName = &frame.unicode;
        if create { frame.attributes.SecurityDescriptor = frame.security.as_ptr().cast(); }
        mapped(book.slot_mut(index), UiError::State)?.state = SlotState::Acquiring;
        let status = unsafe { N::NtCreateFile(output,
            FS::SYNCHRONIZE | FS::READ_CONTROL | FS::DELETE | FS::FILE_READ_ATTRIBUTES
                | if directory { FS::FILE_LIST_DIRECTORY | FS::FILE_TRAVERSE } else { 0 },
            &frame.attributes, frame.iosb.get(), null(), if create { FS::FILE_ATTRIBUTE_DIRECTORY } else { 0 },
            if create { FS::FILE_SHARE_READ | FS::FILE_SHARE_WRITE } else { FS::FILE_SHARE_READ },
            if create { N::FILE_CREATE } else { N::FILE_OPEN }, N::FILE_SYNCHRONOUS_IO_NONALERT | N::FILE_OPEN_REPARSE_POINT
                | if directory { N::FILE_DIRECTORY_FILE } else { N::FILE_NON_DIRECTORY_FILE }, null(), 0) };
        // A pending acquisition may still reference its parent, name, descriptor,
        // output cell and IOSB. Retain ALL; do not call book settlement in this case.
        if status == F::STATUS_PENDING || status != F::STATUS_SUCCESS && (status as u32 >> 30) != 3 {
            self.unknown = true; return Err(UiError::CleanupUnknown);
        }
        frame.returned = true;
        let handle = unsafe { *output };
        if status != F::STATUS_SUCCESS {
            if !handle.is_null() { self.unknown = true; return Err(UiError::CleanupUnknown); }
            mapped(book.slot_mut(index), UiError::State)?.state = SlotState::NoHandle;
            return Err(UiError::NativeFailure); // collision is refusal, never OPEN_IF/adoption/retry
        }
        let iosb = unsafe { &*frame.iosb.get() };
        if !valid_handle(handle) || unsafe { iosb.Anonymous.Status } != F::STATUS_SUCCESS
            || iosb.Information != if create { WP::FILE_CREATED as usize } else { WP::FILE_OPENED as usize }
            || book.duplicate_live(index, handle) { self.unknown = true; return Err(UiError::CleanupUnknown); }
        mapped(book.slot_mut(index), UiError::State)?.state = SlotState::Owned;
        // A later metadata/inheritance refusal cannot turn this actual create
        // into "no profile" and silently leave its fresh directory behind.
        if create { self.created = true; }
        mapped(book.noninherited(index), UiError::UserDataParent)
    }
    pub(super) fn settle_once(&mut self, prerequisites: &mut Prerequisites, browser_settled: bool,
        end: std::time::Instant) -> UiResult<()> {
        if self.final_attempted { return if self.removed && !self.unknown { Ok(()) } else { Err(UiError::CleanupUnknown) }; }
        if !browser_settled || self.unknown { return Err(UiError::CleanupUnknown); }
        self.final_attempted = true;
        let result = self.cleanup(prerequisites, end);
        if result.is_err() { self.unknown = true; }
        result
    }
    fn cleanup(&mut self, prerequisites: &mut Prerequisites, end: std::time::Instant) -> UiResult<()> {
        cleanup_checkpoint(end)?;
        if !self.created {
            // An entered ambiguous FILE_CREATE was rejected before this point.
            self.removed = true; return Ok(());
        }
        let root = self.root.as_ref().ok_or(UiError::State)?.index;
        self.remove_tree(&mut prerequisites.native, root, 0, end)?;
        let parent = prerequisites.parent.ok_or(UiError::State)?;
        // Same retained parent cursor, only this original fresh name. Prove the
        // poststate without opening/deleting a replacement at a reused pathname.
        loop {
            cleanup_checkpoint(end)?;
            let entries = mapped(prerequisites.native.next_ancestor_entries(&prerequisites.paths[parent].original, &self.name), UiError::CleanupUnknown)?;
            let Some(entries) = entries else { break; };
            if entries.iter().any(|entry| entry.name.eq_ignore_ascii_case(&self.name)) { return Err(UiError::CleanupUnknown); }
        }
        cleanup_checkpoint(end)?; self.removed = true; Ok(())
    }
    fn remove_tree(&mut self, book: &mut NativeBook, index: usize, depth: usize, end: std::time::Instant) -> UiResult<()> {
        cleanup_checkpoint(end)?;
        if depth > 20 { return Err(UiError::CleanupUnknown); }
        // A private key for an ALREADY retained original; never path adoption.
        let original = Original { book: Arc::clone(&book.identity), index };
        let metadata = mapped(book.metadata(&original), UiError::CleanupUnknown)?;
        cleanup_checkpoint(end)?;
        mapped(book.no_alternate_streams(&original), UiError::CleanupUnknown)?;
        if metadata.kind == FileKind::Directory {
            let mut names = BTreeSet::new(); let mut entries = Vec::new();
            loop {
                cleanup_checkpoint(end)?;
                let batch = mapped(book.next_entries(&original), UiError::CleanupUnknown)?;
                let Some(batch) = batch else { break; };
                for entry in batch {
                    if !names.insert(entry.name.to_ascii_lowercase()) { return Err(UiError::CleanupUnknown); }
                    if entry.name == "." {
                        if entry.file_id != metadata.identity.file_id { return Err(UiError::CleanupUnknown); }
                        continue;
                    }
                    if entry.name == ".." { continue; }
                    entries.push(entry);
                }
            }
            // Collect this directory to its genuine EOF BEFORE deleting children;
            // mutation cannot make a live enumeration silently skip a sibling.
            for entry in entries {
                cleanup_checkpoint(end)?;
                let child = self.reserve(book, index, &entry.name, entry.kind)?;
                self.open(book, child.index, false, None)?;
                cleanup_checkpoint(end)?;
                let current = mapped(book.metadata(&child), UiError::CleanupUnknown)?;
                if current.identity.volume_serial != metadata.identity.volume_serial || current.identity.file_id != entry.file_id
                    || current.kind != entry.kind || current.attributes != entry.attributes { return Err(UiError::CleanupUnknown); }
                self.remove_tree(book, child.index, depth + 1, end)?;
            }
        }
        cleanup_checkpoint(end)?;
        let handle = mapped(book.handle(index), UiError::CleanupUnknown)?;
        // Original handle disposition only. No recursive pathname delete,
        // no reparse traversal, no readonly-attribute reset, no privileged bypass.
        let frame = self.frames.iter().find(|frame| frame.index == index).ok_or(UiError::State)?;
        if frame.deletion_entered.replace(true) { return Err(UiError::CleanupUnknown); }
        if unsafe { FS::SetFileInformationByHandle(handle, FS::FileDispositionInfo,
            frame.deletion.get().cast(), size_of::<FS::FILE_DISPOSITION_INFO>() as u32) } == 0 { return Err(UiError::CleanupUnknown); }
        // If the original call returned after its endpoint, retain this original
        // disposition/handle; do not start another deletion/close under a new clock.
        cleanup_checkpoint(end)?;
        mapped(book.close_once(&original), UiError::CleanupUnknown)
    }
    pub(super) fn settled(&self) -> bool { self.final_attempted && self.removed && !self.unknown }
}
fn root_descriptor(raw: &[u8], user: &Sid) -> UiResult<()> {
    let facts = private_parent_descriptor(raw, user)?;
    let flags = (S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE) as u8;
    let system: &[u8] = &[1,1,0,0,0,0,0,5,18,0,0,0];
    if facts.owner != *user || facts.control & S::SE_DACL_PROTECTED == 0 || facts.aces.len() != 2
        || !facts.aces.iter().all(|ace| ace.allow && ace.flags == flags && ace.mask == FS::FILE_ALL_ACCESS)
        || facts.aces[0].sid != *user || facts.aces[1].sid.bytes() != system {
        return Err(UiError::UserDataParent);
    }
    Ok(())
}
impl Drop for Profile {
    fn drop(&mut self) {
        // No native close/delete in Drop. Unexpected pending frames keep their
        // exact allocations. Normal explicit finality permits deallocation only.
        if !self.settled() { return; }
        for frame in &mut self.frames { unsafe { ManuallyDrop::drop(frame); } }
    }
}
fn private_descriptor(user: &Sid) -> UiResult<Vec<u8>> {
    let system: &[u8] = &[1,1,0,0,0,0,0,5,18,0,0,0];
    let acl_offset = 20 + user.bytes().len();
    let acl_len = 8 + 8 + user.bytes().len() + 8 + system.len();
    if acl_offset % 4 != 0 || acl_len > u16::MAX as usize { return Err(UiError::UserDataParent); }
    let mut data = vec![0u8; acl_offset + acl_len];
    data[0] = 1;
    data[2..4].copy_from_slice(&(S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED).to_le_bytes());
    data[4..8].copy_from_slice(&20u32.to_le_bytes());
    data[16..20].copy_from_slice(&(acl_offset as u32).to_le_bytes());
    data[20..acl_offset].copy_from_slice(user.bytes());
    data[acl_offset] = 2;
    data[acl_offset + 2..acl_offset + 4].copy_from_slice(&(acl_len as u16).to_le_bytes());
    data[acl_offset + 4..acl_offset + 6].copy_from_slice(&2u16.to_le_bytes());
    let mut offset = acl_offset + 8;
    for sid in [user.bytes(), system] {
        data[offset] = 0; data[offset + 1] = (S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE) as u8;
        data[offset + 2..offset + 4].copy_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
        data[offset + 4..offset + 8].copy_from_slice(&FS::FILE_ALL_ACCESS.to_le_bytes());
        data[offset + 8..offset + 8 + sid.len()].copy_from_slice(sid); offset += 8 + sid.len();
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn synthetic_user() -> UiResult<Sid> {
        let mut bytes = vec![1,5,0,0,0,0,0,5];
        for sub in [21u32, 101, 102, 103, 1001] { bytes.extend_from_slice(&sub.to_le_bytes()); }
        mapped(security::sid_at(&bytes, 0, bytes.len()), UiError::State)
    }
    #[test]
    fn fresh_scope_dacl_is_exact_and_not_an_immutable_runtime_policy() -> UiResult<()> {
        let user = synthetic_user()?; let raw = private_descriptor(&user)?;
        root_descriptor(&raw, &user)?;
        assert!(security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion).is_err());
        let acl = 20 + user.bytes().len();
        let mut inherited_only = raw.clone();
        inherited_only[acl + 9] |= S::INHERIT_ONLY_ACE as u8;
        assert_eq!(root_descriptor(&inherited_only, &user), Err(UiError::UserDataParent));
        let mut unprotected = raw;
        unprotected[2..4].copy_from_slice(&(S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT).to_le_bytes());
        assert_eq!(root_descriptor(&unprotected, &user), Err(UiError::UserDataParent));
        Ok(())
    }
    #[test]
    fn profile_descriptor_refuses_foreign_mutation_or_malformed_offsets() -> UiResult<()> {
        let user = synthetic_user()?; let raw = private_descriptor(&user)?;
        let acl = 20 + user.bytes().len();
        let system_sid = acl + 8 + 8 + user.bytes().len() + 8;
        let mut foreign = raw.clone();
        foreign[system_sid..system_sid + 12].copy_from_slice(&[1,1,0,0,0,0,0,1,0,0,0,0]); // Everyone
        assert_eq!(private_parent_descriptor(&foreign, &user), Err(UiError::UserDataParent));
        for offset in [0u32, 4, 21, raw.len() as u32] {
            let mut malformed = raw.clone(); malformed[16..20].copy_from_slice(&offset.to_le_bytes());
            assert_eq!(root_descriptor(&malformed, &user), Err(UiError::UserDataParent));
        }
        Ok(())
    }
    #[test]
    fn expired_cleanup_retains_scope_state_and_cannot_retry_with_a_new_clock() {
        // No profile/native object is constructed. The actual production
        // endpoint guard must refuse BEFORE any enumeration/delete/close call.
        let mut profile = Profile::new(); let mut prerequisites = Prerequisites::new();
        assert_eq!(profile.settle_once(&mut prerequisites, true, std::time::Instant::now()), Err(UiError::CleanupUnknown));
        assert!(profile.final_attempted && profile.unknown && !profile.removed);
        assert_eq!(profile.settle_once(&mut prerequisites, true,
            std::time::Instant::now() + std::time::Duration::from_secs(5)), Err(UiError::CleanupUnknown));
        assert!(!profile.settled());
    }
    #[test]
    fn post_create_admission_failure_never_authorizes_profile_cleanup() {
        // Inert injected outcomes only: no file is created or native call made.
        for error in [UiError::UserDataParent, UiError::NativeFailure, UiError::State, UiError::CleanupUnknown] {
            let mut profile = Profile::new(); profile.created = true;
            assert_eq!(profile.finish_admission(Err(error)), Err(UiError::CleanupUnknown));
            assert_eq!(profile.finish_admission(Ok(())), Err(UiError::CleanupUnknown));
            assert_eq!(profile.settle_once(&mut Prerequisites::new(), true,
                std::time::Instant::now() + std::time::Duration::from_secs(2)), Err(UiError::CleanupUnknown));
            assert!(profile.unknown && !profile.final_attempted && !profile.removed);
        }
        let mut no_create = Profile::new();
        assert_eq!(no_create.finish_admission(Err(UiError::NativeFailure)), Err(UiError::NativeFailure));
        assert!(!no_create.unknown && !no_create.created);
        no_create.unknown = true; // Pending acquisition is never a no-create proof.
        assert_eq!(no_create.finish_admission(Ok(())), Err(UiError::CleanupUnknown));
    }
}
