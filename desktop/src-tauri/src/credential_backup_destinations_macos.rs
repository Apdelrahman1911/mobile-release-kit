//! Fixed two-file backup sink in the actual macOS SourceBook family.
//!
//! Same OriginalWork, actual closed native selections and one IO deadline.
//! Both original empty private files are acquired/admitted before a recovery
//! code or encrypted output is generated. No arbitrary filename, byte getter,
//! callback sink, automatic deletion, overwrite, retry or restart adoption.
//! A native return here is NOT the parent child/coordinator join or Delivered.
use super::*;
use crate::{asset_session::OriginalWork, vault_crypto::backup, vault_format};
use std::{mem::ManuallyDrop, os::fd::BorrowedFd, sync::Weak, time::{Duration, Instant}};
use nix::{errno::Errno, unistd::Whence};
use mrk_macos_installed_native::{self as native, vault_filesystem::{SnapshotBook, Expected,
    Policy, Failure, ObservePhase, SNAPSHOT_FRAME_BYTES}};
use zeroize::{Zeroize, Zeroizing};

const ROOTS: usize = 33;
const CODE_BYTES: usize = b"mrk-recovery-v1-".len() + 64;
const BLOCK: usize = 64 * 1024;
const FAILURE_CLEANUP: Duration = Duration::from_secs(2); // Existing owner/storage policy.
const CONTROL_BYTES: usize =
    DESCRIPTOR_LIMIT * (std::mem::size_of::<Descriptor>() + 255 + std::mem::size_of::<DirectorySnapshot>())
    + 32 * (std::mem::size_of::<OriginAlias>() + 16)
    + (ROOTS + 2) * (std::mem::size_of::<Vec<&[u8]>>() + (COMPONENT_LIMIT - 1) * std::mem::size_of::<&[u8]>())
    + ROOTS * (std::mem::size_of::<RegisteredRoot>() + PATH_LIMIT + std::mem::size_of::<DirectoryIdentity>())
    + 2 * (COMPONENT_LIMIT + 1) * std::mem::size_of::<usize>()
    + 2 * PATH_LIMIT + SNAPSHOT_FRAME_BYTES + BLOCK + 1 + std::mem::size_of::<BackupDestinations>() + 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Handle { Reserved, Entered, Owned, NoHandle, Closing, Closed, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect { NotStarted, Entered, Applied, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Reserved, Admitting, Ready, Publishing, Returned, Failed }

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectorySnapshot { index: usize, identity: DirectoryIdentity, flags: u32 }
impl DirectorySnapshot {
    fn expected(self) -> Expected { Expected { device: self.identity.dev, inode: self.identity.ino,
        mode: self.identity.mode, owner: self.identity.uid, group: self.identity.gid, flags: self.flags } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct OutputKey { file: FileIdentity, flags: u32 }
impl OutputKey {
    fn of(stat: &FileStat, uid: u32) -> Result<Self, Reason> {
        let file = file_identity(stat)?;
        if file.common.uid != uid || file.common.mode & 0o7777 != 0o600 || file.nlink != 1 || stat.st_flags != 0
            || !(0..1_000_000_000).contains(&file.mtime.1) || !(0..1_000_000_000).contains(&file.ctime.1) {
            return Err(Reason::SourceRefused);
        }
        Ok(Self { file, flags: stat.st_flags })
    }
    fn expected(self) -> Expected { Expected { device: self.file.common.dev, inode: self.file.common.ino,
        mode: self.file.common.mode, owner: self.file.common.uid, group: self.file.common.gid, flags: self.flags } }
    fn same_original(self, other: Self) -> bool {
        self.file.common == other.file.common && self.flags == other.flags && self.file.nlink == other.file.nlink
    }
}

struct Output {
    fd: Option<ManuallyDrop<OwnedFd>>, handle: Handle, parent: Option<usize>,
    pending: String, published: String, key: Option<OutputKey>,
    creation: Effect, write: Effect, file_sync: Effect, publication: Effect, directory_sync: Effect,
    written: usize, expected_bytes: Option<usize>, verified: bool,
}
impl Output {
    fn reserved() -> Self { Self { fd: None, handle: Handle::Reserved, parent: None, pending: String::new(),
        published: String::new(), key: None, creation: Effect::NotStarted, write: Effect::NotStarted,
        file_sync: Effect::NotStarted, publication: Effect::NotStarted, directory_sync: Effect::NotStarted,
        written: 0, expected_bytes: None, verified: false } }
    fn fd(&self) -> Result<BorrowedFd<'_>, Reason> {
        if self.handle != Handle::Owned { return Err(Reason::CleanupUnknown); }
        self.fd.as_ref().map(|fd| fd.as_fd()).ok_or(Reason::CleanupUnknown)
    }
    fn closed(&self) -> bool { matches!(self.handle, Handle::NoHandle | Handle::Closed) && self.fd.is_none() }
    fn effects_known(&self) -> bool {
        [self.creation, self.write, self.file_sync, self.publication, self.directory_sync]
            .iter().all(|effect| !matches!(effect, Effect::Entered | Effect::Unknown))
            // A returned rename is not durable publication. STOP can arrive
            // before the first directory-sync entry; preserve NotStarted as
            // the genuine native fact but refuse disposal of that unsynced
            // publication just as for an uncertain sync return.
            && (self.publication != Effect::Applied || self.directory_sync == Effect::Applied)
    }
    fn completed(&self) -> bool {
        self.closed() && self.verified && self.expected_bytes == Some(self.written)
            && [self.creation, self.write, self.file_sync, self.publication, self.directory_sync]
                .iter().all(|effect| *effect == Effect::Applied)
    }
}

/// Private original custody, not a reusable write capability. Creation is only
/// reached by the native SelectedPair's fixed export handoff. It grants no IO
/// until the retained original child/current-vault gates admit this SAME owner.
pub(crate) struct BackupDestinations {
    owner: Weak<OriginalWork>, paths: [PathBuf; 2], book: SourceBook,
    acl: Option<SnapshotBook>, ancestors: Vec<DirectorySnapshot>, outputs: [Output; 2],
    comparison: Zeroizing<Vec<u8>>, phase: Phase, closed: bool,
    first: Option<(Reason, Instant)>, uid: Option<u32>,
}
impl BackupDestinations {
    #[cfg(test)]
    pub(crate) fn unknown_effect_predicate_data(owner: &Arc<OriginalWork>) -> Self {
        // Inert negative DATA only. No FD/ACL/native call exists; no valid
        // selector/current scope/verified output can be produced by this row.
        let mut book = SourceBook::new(); book.terminal = true;
        let mut outputs = [Output::reserved(), Output::reserved()];
        for output in &mut outputs { output.handle = Handle::NoHandle; }
        outputs[1].publication = Effect::Unknown;
        Self { owner: Arc::downgrade(owner), paths: [PathBuf::new(), PathBuf::new()], book,
            acl: None, ancestors: Vec::new(), outputs, comparison: Zeroizing::new(Vec::new()),
            phase: Phase::Failed, closed: true, first: Some((Reason::SourceRefused, Instant::now())), uid: None }
    }
    #[cfg(test)]
    pub(crate) fn unsynced_publication_predicate_data(owner: &Arc<OriginalWork>) -> Self {
        // Exact negative gap DATA: the rename returned, all native originals
        // are closed, but directory sync was never entered. No native receipt,
        // valid selector scope or recovery adoption can be obtained here.
        let mut value = Self::unknown_effect_predicate_data(owner);
        let out = &mut value.outputs[1];
        out.creation = Effect::Applied; out.write = Effect::Applied; out.file_sync = Effect::Applied;
        out.publication = Effect::Applied; out.directory_sync = Effect::NotStarted;
        value
    }
    /// No filesystem/key generation. Sole production caller is the closed
    /// native SelectedPair; no renderer/CLI path adapter calls this function.
    pub(crate) fn new(owner: &Arc<OriginalWork>, paths: [PathBuf; 2]) -> Result<Self, Reason> {
        if !owner.credential_backup_destination_scope() || paths[0] == paths[1]
            || paths.iter().any(|path| path.capacity() > PATH_LIMIT) { return Err(Reason::SourceRefused); }
        for path in &paths { if parts(path)?.is_empty() { return Err(Reason::SourceRefused); } }
        Ok(Self { owner: Arc::downgrade(owner), paths, book: SourceBook::new(), acl: None,
            ancestors: Vec::new(), outputs: [Output::reserved(), Output::reserved()],
            comparison: Zeroizing::new(Vec::new()), phase: Phase::Reserved, closed: false, first: None, uid: None })
    }
    fn current(&self, owner: &Arc<OriginalWork>) -> bool {
        self.owner.upgrade().is_some_and(|original| Arc::ptr_eq(&original, owner))
            && owner.credential_backup_destination_scope()
    }
    fn fail_at(&mut self, owner: &OriginalWork, reason: Reason, at: Instant) {
        if self.first.is_none() { self.first = Some((reason, at)); }
        owner.credential_backup_sink_failed_at(reason, at);
        self.phase = Phase::Failed;
    }
    fn fail(&mut self, owner: &OriginalWork, reason: Reason) {
        // A native snapshot can retain its first failure before returning to
        // this wrapper. Import that original Instant, never restamp it after
        // its cleanup or let a later generic error become the first failure.
        if let Some((failure, at)) = self.acl.as_ref().and_then(SnapshotBook::first_failure) {
            self.fail_at(owner, acl_reason(failure), at);
        }
        self.fail_at(owner, reason, Instant::now());
    }
    pub(crate) fn not_started(&self) -> bool {
        self.phase == Phase::Reserved && !self.closed && self.first.is_none() && self.uid.is_none()
            && self.book.not_started() && self.acl.is_none() && self.ancestors.capacity() == 0
            && self.comparison.capacity() == 0 && self.outputs.iter().all(|out| out.handle == Handle::Reserved
                && out.fd.is_none() && out.parent.is_none() && out.creation == Effect::NotStarted)
    }
    /// Native originals only, separate from uncertain effects/private disposal.
    pub(crate) fn native_settled(&self) -> bool {
        self.not_started() || self.closed && self.book.settled()
            && self.acl.as_ref().is_none_or(SnapshotBook::settled) && self.outputs.iter().all(Output::closed)
    }
    pub(crate) fn disposal_ready(&self) -> bool {
        self.native_settled() && self.outputs.iter().all(Output::effects_known)
    }
    pub(crate) fn candidate_ready(&self, owner: &Arc<OriginalWork>) -> bool {
        self.current(owner) && self.phase == Phase::Returned && self.first.is_none()
            && self.native_settled() && self.outputs.iter().all(Output::completed)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>().checked_add(self.book.retained_bytes()?)?
            .checked_add(self.paths[0].capacity())?.checked_add(self.paths[1].capacity())?
            .checked_add(self.ancestors.capacity().checked_mul(std::mem::size_of::<DirectorySnapshot>())?)?
            .checked_add(self.acl.as_ref().map_or(0, SnapshotBook::retained_frame_bytes))?
            .checked_add(self.comparison.capacity())?;
        for out in &self.outputs { bytes = bytes.checked_add(out.pending.capacity())?.checked_add(out.published.capacity())?; }
        Some(bytes)
    }

    /// Both original directories and empty no-clobber files before code/key
    /// allocation. Failure preserves any original/partial names and closes all
    /// independent originals once; there is no cleanup-by-path or retry arm.
    pub(crate) fn admit(&mut self, roots: &[RegisteredRoot], allowance: usize, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        if !self.current(owner) || !self.not_started() { return Err(Reason::SourceChanged); }
        self.phase = Phase::Admitting;
        match self.admit_inner(roots, allowance, owner) {
            Ok(()) => { self.phase = Phase::Ready; Ok(()) },
            Err(reason) => { self.fail(owner, reason); self.close_all(owner); Err(self.failure(reason)) },
        }
    }
    fn admit_inner(&mut self, roots: &[RegisteredRoot], allowance: usize, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        let mut stop = || owner.interrupted(); checkpoint(&mut stop)?;
        if !(1..=ROOTS).contains(&roots.len()) || allowance < CONTROL_BYTES || allowance > vault_format::WORKING_BYTES
            || roots.iter().any(|root| root.path.capacity() > PATH_LIMIT) { return Err(Reason::Capacity); }
        let selected = [parts(&self.paths[0])?, parts(&self.paths[1])?];
        let mut root_parts = Vec::new(); root_parts.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
        if root_parts.capacity() > ROOTS { return Err(Reason::Capacity); }
        for root in roots {
            root.identity.posix()?; root_parts.push(parts(&root.path)?);
            if self.paths.iter().any(|path| path.starts_with(&root.path)) { return Err(Reason::ProjectOverlap); }
        }
        let capacity = roster_limit(root_parts.iter().map(Vec::len)
            .chain(selected.iter().map(|parts| parts.len() + source_extra(parts))), 1)?;
        self.book.begin(capacity, 0, 2)?; self.book.root(&mut stop)?; self.book.anchor_private(&mut stop)?;
        self.uid = Some(unistd::geteuid().as_raw());
        let mut root_ids = Vec::new(); root_ids.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
        if root_ids.capacity() > ROOTS { return Err(Reason::Capacity); }
        for (root, parts) in roots.iter().zip(&root_parts) {
            let (chain, _) = self.book.chain(parts, false, &mut stop)?;
            let identity = self.book.directory(*chain.last().ok_or(Reason::SourceRefused)?)?;
            if ProjectIdentity::Posix(identity) != root.identity { return Err(Reason::SourceChanged); }
            root_ids.push(identity);
        }
        let mut chains = [Vec::new(), Vec::new()];
        for (index, parts) in selected.iter().enumerate() {
            let (chain, _) = self.book.chain(parts, true, &mut stop)?;
            for ancestor in &chain {
                let actual = self.book.directory(*ancestor)?;
                if root_ids.iter().any(|root| actual.same_object(*root)) { return Err(Reason::ProjectOverlap); }
            }
            self.outputs[index].parent = Some(*chain.last().ok_or(Reason::SourceRefused)?);
            chains[index] = chain;
        }
        let parents = [self.outputs[0].parent.ok_or(Reason::SourceRefused)?, self.outputs[1].parent.ok_or(Reason::SourceRefused)?];
        if self.book.directory(parents[0])?.same_object(self.book.directory(parents[1])?) { return Err(Reason::SourceRefused); }
        drop((selected, root_parts, root_ids));
        self.ancestors.try_reserve_exact(self.book.slots.len()).map_err(|_| Reason::Capacity)?;
        if self.ancestors.capacity() > DESCRIPTOR_LIMIT { return Err(Reason::Capacity); }
        self.acl = Some(SnapshotBook::new()); // Retained on this original before its first native observation.
        for index in chains.iter().flatten().copied() {
            if self.ancestors.iter().any(|held| held.index == index) { continue; }
            checkpoint(&mut stop)?;
            let stat = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceRefused)?; checkpoint(&mut stop)?;
            let identity = directory_identity(&stat)?;
            let uid = self.uid.ok_or(Reason::CleanupUnknown)?;
            if identity != self.book.directory(index)? || !directory_policy(identity, self.book.slots[index].role, uid)
                || parents.contains(&index) && identity.uid != uid { return Err(Reason::SourceRefused); }
            let snapshot = DirectorySnapshot { index, identity, flags: stat.st_flags };
            self.ancestors.push(snapshot); // Original expected flags never replaced by a later observation.
            self.observe_directory(snapshot, owner)?;
        }
        // Random PUBLIC filename identity only. The recovery key/code is not
        // generated until this entire method returns with both private FDs.
        let mut id = [0u8; 16]; getrandom::fill(&mut id).map_err(|_| Reason::SourceRefused)?;
        let names = output_names(id)?;
        for (out, (pending, published)) in self.outputs.iter_mut().zip(names) { out.pending = pending; out.published = published; }
        self.recheck_directories(owner)?;
        for index in 0..2 { self.absent(index, true, owner)?; self.absent(index, false, owner)?; }
        for index in 0..2 { self.create_empty(index, owner)?; }
        // A readback block (including the EOF byte) is zeroizing BEFORE the
        // first read. Its future allocation is included in the pre-entry quote.
        self.comparison.try_reserve_exact(BLOCK + 1).map_err(|_| Reason::Capacity)?;
        if self.comparison.capacity() > BLOCK + 1 { return Err(Reason::Capacity); }
        self.comparison.resize(BLOCK + 1, 0);
        for index in 0..2 { self.verify_unchanged(index, owner)?; self.absent(index, false, owner)?; }
        self.recheck_directories(owner)?;
        if self.retained_bytes().is_none_or(|bytes| bytes > allowance) { return Err(Reason::Capacity); }
        checkpoint(&mut stop)
    }

    fn observe_directory(&mut self, expected: DirectorySnapshot, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        let fd = self.book.fd(expected.index)?.as_fd();
        observe(self.acl.as_mut().ok_or(Reason::CleanupUnknown)?, fd, expected.expected(), Policy::Ancestors, owner)?;
        let actual = stat::fstat(fd).map_err(|_| Reason::SourceChanged)?;
        checkpoint(&mut || owner.interrupted())?;
        if directory_identity(&actual)? != expected.identity || actual.st_flags != expected.flags { return Err(Reason::SourceChanged); }
        Ok(())
    }
    fn recheck_directories(&mut self, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        self.book.terminal_check(&mut || owner.interrupted())?;
        for n in 0..self.ancestors.len() { self.observe_directory(self.ancestors[n], owner)?; }
        self.book.terminal_check(&mut || owner.interrupted())
    }
    fn parent(&self, index: usize) -> Result<&OwnedFd, Reason> {
        self.book.fd(self.outputs.get(index).and_then(|out| out.parent).ok_or(Reason::CleanupUnknown)?)
    }
    fn absent(&self, index: usize, pending: bool, owner: &OriginalWork) -> Result<(), Reason> {
        checkpoint(&mut || owner.interrupted())?;
        let out = self.outputs.get(index).ok_or(Reason::CleanupUnknown)?;
        let name = if pending { &out.pending } else { &out.published };
        let result = stat::fstatat(self.parent(index)?, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW);
        checkpoint(&mut || owner.interrupted())?;
        match result { Err(Errno::ENOENT) => Ok(()), _ => Err(Reason::SourceChanged) }
    }
    fn create_empty(&mut self, index: usize, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        checkpoint(&mut || owner.interrupted())?;
        if self.outputs[index].handle != Handle::Reserved || self.outputs[index].creation != Effect::NotStarted {
            return Err(Reason::CleanupUnknown);
        }
        self.outputs[index].handle = Handle::Entered; self.outputs[index].creation = Effect::Entered;
        let opened = fcntl::openat(self.parent(index)?, self.outputs[index].pending.as_str(),
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::from_bits_truncate(0o600));
        match opened {
            Ok(fd) => { let out = &mut self.outputs[index]; out.fd = Some(ManuallyDrop::new(fd));
                out.handle = Handle::Owned; out.creation = Effect::Applied; },
            Err(_) => { let out = &mut self.outputs[index]; out.handle = Handle::NoHandle;
                out.creation = Effect::Unknown; return Err(Reason::SourceRefused); },
        }
        checkpoint(&mut || owner.interrupted())?;
        let actual = self.inspect_output(index, owner)?;
        if actual.file.size != 0 { return Err(Reason::SourceChanged); }
        self.outputs[index].key = Some(actual);
        self.verify_unchanged(index, owner)
    }
    fn inspect_output(&mut self, index: usize, owner: &Arc<OriginalWork>) -> Result<OutputKey, Reason> {
        checkpoint(&mut || owner.interrupted())?;
        let out = &self.outputs[index]; let fd = out.fd()?;
        let fs = statfs::fstatfs(fd).map_err(|_| Reason::UnsupportedFilesystem)?; checkpoint(&mut || owner.interrupted())?;
        if !admitted_filesystem(fs.filesystem_type_name(), fs.flags()) { return Err(Reason::UnsupportedFilesystem); }
        let actual = stat::fstat(fd).map_err(|_| Reason::SourceRefused)?; checkpoint(&mut || owner.interrupted())?;
        let expected = OutputKey::of(&actual, self.uid.ok_or(Reason::CleanupUnknown)?)?;
        observe(self.acl.as_mut().ok_or(Reason::CleanupUnknown)?, fd, expected.expected(), Policy::Empty, owner)?;
        native::no_xattrs(fd).map_err(|_| Reason::SourceRefused)?; checkpoint(&mut || owner.interrupted())?;
        let after = stat::fstat(fd).map_err(|_| Reason::SourceChanged)?; checkpoint(&mut || owner.interrupted())?;
        if OutputKey::of(&after, self.uid.ok_or(Reason::CleanupUnknown)?)? != expected { return Err(Reason::SourceChanged); }
        Ok(expected)
    }
    fn verify_unchanged(&mut self, index: usize, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        let expected = self.outputs[index].key.ok_or(Reason::CleanupUnknown)?;
        if self.inspect_output(index, owner)? != expected { return Err(Reason::SourceChanged); }
        self.named_matches(index, expected, owner)
    }
    fn named_matches(&self, index: usize, expected: OutputKey, owner: &OriginalWork) -> Result<(), Reason> {
        checkpoint(&mut || owner.interrupted())?;
        let out = &self.outputs[index];
        let name = match out.publication { Effect::NotStarted => &out.pending, Effect::Applied => &out.published,
            _ => return Err(Reason::CleanupUnknown) };
        let named = stat::fstatat(self.parent(index)?, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| Reason::SourceChanged)?;
        checkpoint(&mut || owner.interrupted())?;
        if OutputKey::of(&named, self.uid.ok_or(Reason::CleanupUnknown)?)? != expected { return Err(Reason::SourceChanged); }
        Ok(())
    }

    /// Internal concrete pair seam used ONLY by ExportedBackup::publish_to.
    /// Not two independent outputs and not a public path/FD/bytes endpoint.
    /// The caller borrows its retained ExportedBackup throughout this call.
    pub(crate) fn publish_pair(&mut self, encrypted: &[u8], code: &[u8], owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        if !self.current(owner) || self.phase != Phase::Ready || self.closed || self.first.is_some() {
            return Err(Reason::SourceChanged);
        }
        self.phase = Phase::Publishing;
        let result = (|| {
            if encrypted.is_empty() || encrypted.len() > backup::BACKUP_LIMIT || code.len() != CODE_BYTES
                || !code.starts_with(b"mrk-recovery-v1-") { return Err(Reason::SourceRefused); }
            self.recheck_directories(owner)?;
            for index in 0..2 { self.verify_unchanged(index, owner)?; self.absent(index, false, owner)?; }
            // Code first; every successful byte count belongs to this original
            // before STOP/error observation. Neither output may be rerun.
            self.write_one(1, code, owner)?; self.write_one(0, encrypted, owner)?;
            self.recheck_directories(owner)?;
            self.publish_one(1, code, owner)?; self.publish_one(0, encrypted, owner)?;
            self.recheck_directories(owner)?;
            for (index, bytes) in [(1, code), (0, encrypted)] {
                self.verify_unchanged(index, owner)?; self.readback(index, bytes, owner)?;
                self.absent(index, true, owner)?; self.outputs[index].verified = true;
            }
            self.recheck_directories(owner)
        })();
        if let Err(reason) = result { self.fail(owner, reason); }
        let closed = self.close_all(owner);
        if !closed { return Err(Reason::CleanupUnknown); }
        if let Err(reason) = result { return Err(self.failure(reason)); }
        if !self.current(owner) { self.fail(owner, Reason::UserCancelled); return Err(Reason::UserCancelled); }
        self.phase = Phase::Returned;
        Ok(()) // Parent STILL owes exact vault/context rematch and real joins.
    }
    fn write_one(&mut self, index: usize, bytes: &[u8], owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        self.verify_unchanged(index, owner)?;
        let original = self.outputs[index].key.ok_or(Reason::CleanupUnknown)?;
        if original.file.size != 0 || self.outputs[index].write != Effect::NotStarted { return Err(Reason::SourceChanged); }
        self.outputs[index].expected_bytes = Some(bytes.len()); self.outputs[index].write = Effect::Entered;
        while self.outputs[index].written < bytes.len() {
            checkpoint(&mut || owner.interrupted())?;
            let at = self.outputs[index].written; let end = bytes.len().min(at.saturating_add(BLOCK));
            let written = match unistd::write(self.outputs[index].fd()?, &bytes[at..end]) {
                Ok(n) if n > 0 && n <= end - at => n,
                _ => { self.outputs[index].write = Effect::Unknown; return Err(Reason::SourceRefused); },
            };
            self.outputs[index].written += written;
            checkpoint(&mut || owner.interrupted())?;
        }
        self.outputs[index].write = Effect::Applied;
        self.outputs[index].file_sync = Effect::Entered;
        match native::sync(self.outputs[index].fd()?, true) {
            Ok(()) => self.outputs[index].file_sync = Effect::Applied,
            Err(_) => { self.outputs[index].file_sync = Effect::Unknown; return Err(Reason::VaultDurabilityUnknown); },
        }
        checkpoint(&mut || owner.interrupted())?;
        let after = self.inspect_output(index, owner)?;
        if !original.same_original(after) || usize::try_from(after.file.size).ok() != Some(bytes.len()) { return Err(Reason::SourceChanged); }
        self.outputs[index].key = Some(after); // Only own actual write may change size/time.
        self.named_matches(index, after, owner)?; self.readback(index, bytes, owner)?;
        self.verify_unchanged(index, owner)
    }
    fn readback(&mut self, index: usize, expected: &[u8], owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        checkpoint(&mut || owner.interrupted())?;
        let offset = unistd::lseek(self.outputs[index].fd()?, 0, Whence::SeekSet).map_err(|_| Reason::SourceRefused)?;
        checkpoint(&mut || owner.interrupted())?;
        if offset != 0 || self.comparison.len() != BLOCK + 1 { return Err(Reason::CleanupUnknown); }
        let mut consumed = 0usize;
        loop {
            checkpoint(&mut || owner.interrupted())?;
            let remaining = expected.len().checked_sub(consumed).ok_or(Reason::SourceChanged)?;
            let bound = BLOCK.min(remaining.saturating_add(1));
            let read = unistd::read(self.outputs[index].fd()?, &mut self.comparison[..bound]).map_err(|_| Reason::SourceRefused)?;
            checkpoint(&mut || owner.interrupted())?;
            if read == 0 { if consumed != expected.len() { return Err(Reason::SourceChanged); } break; }
            let end = consumed.checked_add(read).filter(|end| *end <= expected.len()).ok_or(Reason::SourceChanged)?;
            if self.comparison[..read] != expected[consumed..end] { return Err(Reason::SourceChanged); }
            consumed = end; self.comparison[..read].zeroize();
        }
        self.comparison.as_mut_slice().zeroize(); Ok(())
    }
    fn publish_one(&mut self, index: usize, bytes: &[u8], owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        self.recheck_directories(owner)?; self.verify_unchanged(index, owner)?; self.absent(index, false, owner)?;
        let before = self.outputs[index].key.ok_or(Reason::CleanupUnknown)?;
        self.outputs[index].publication = Effect::Entered;
        let out = &self.outputs[index];
        let returned = native::publish_directory(self.parent(index)?.as_fd(), &out.pending, self.parent(index)?.as_fd(), &out.published);
        match returned {
            Ok(()) => self.outputs[index].publication = Effect::Applied,
            Err(_) => { self.outputs[index].publication = Effect::Unknown; return Err(Reason::SourceChanged); },
        }
        checkpoint(&mut || owner.interrupted())?;
        self.outputs[index].directory_sync = Effect::Entered;
        match native::sync(self.parent(index)?.as_fd(), false) {
            Ok(()) => self.outputs[index].directory_sync = Effect::Applied,
            Err(_) => { self.outputs[index].directory_sync = Effect::Unknown; return Err(Reason::VaultDurabilityUnknown); },
        }
        checkpoint(&mut || owner.interrupted())?;
        let after = self.inspect_output(index, owner)?;
        if !before.same_original(after) || before.file.size != after.file.size || before.file.mtime != after.file.mtime {
            return Err(Reason::SourceChanged);
        }
        self.outputs[index].key = Some(after); // Rename may change ctime, not original/bytes/mtime.
        self.named_matches(index, after, owner)?; self.absent(index, true, owner)?; self.readback(index, bytes, owner)?;
        self.verify_unchanged(index, owner)
    }

    /// Called on a codec/current-record failure AFTER destination admission but
    /// before pair publication. No secret/key generation is repeated on retry.
    pub(crate) fn abort(&mut self, owner: &Arc<OriginalWork>, reason: Reason) -> bool {
        if !self.owner.upgrade().is_some_and(|held| Arc::ptr_eq(&held, owner)) { return false; }
        self.fail(owner, reason); self.close_all(owner)
    }
    fn failure(&self, reason: Reason) -> Reason {
        if !self.native_settled() { Reason::CleanupUnknown } else { self.first.map_or(reason, |first| first.0) }
    }
    fn close_all(&mut self, owner: &Arc<OriginalWork>) -> bool {
        if self.closed { return self.native_settled(); }
        // Import the native first failure BEFORE any independent cleanup.
        if let Some((failure, at)) = self.acl.as_ref().and_then(SnapshotBook::first_failure) { self.fail_at(owner, acl_reason(failure), at); }
        let first = self.first.map(|first| first.1);
        let mut known = true;
        if let Some(acl) = &mut self.acl {
            let released = acl.release(&mut |failure| {
                if let Some((reason, at)) = failure { owner.credential_backup_sink_failed_at(acl_reason(reason), at); }
                cleanup_expired(owner, earlier(first, failure.map(|failure| failure.1)))
            });
            if !released { known = false; self.fail(owner, Reason::CleanupUnknown); }
        }
        for index in [1, 0] {
            let out = &mut self.outputs[index];
            match out.handle {
                Handle::Reserved => out.handle = Handle::NoHandle,
                Handle::Closed | Handle::NoHandle => {},
                Handle::Owned => {
                    out.handle = Handle::Closing;
                    let closed = out.fd.take().is_some_and(|fd| unistd::close(ManuallyDrop::into_inner(fd)).is_ok());
                    out.handle = if closed { Handle::Closed } else { Handle::Unknown };
                    if !closed { known = false; self.fail(owner, Reason::CleanupUnknown); }
                },
                _ => { known = false; self.fail(owner, Reason::CleanupUnknown); },
            }
        }
        // A failed ACL/file close NEVER skips other independent directories.
        if !self.book.close_all_observing(&mut |reason| owner.credential_backup_failed(reason)) {
            known = false; self.fail(owner, Reason::CleanupUnknown);
        }
        self.closed = true;
        known && self.native_settled()
    }
}

fn directory_policy(identity: DirectoryIdentity, role: PhysicalRole, uid: u32) -> bool {
    // Reuse the real canonical /private/tmp sticky exception, not a text alias.
    role.protected(identity) && ([0, uid].contains(&identity.uid) && identity.mode & 0o022 == 0
        || role == PhysicalRole::Tmp && identity.uid == 0 && identity.mode & 0o1000 != 0)
}
fn output_names(id: [u8; 16]) -> Result<[(String, String); 2], Reason> {
    if id == [0; 16] { return Err(Reason::SourceRefused); }
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut token = [0u8; 32];
    for (index, byte) in id.iter().copied().enumerate() { token[index * 2] = DIGITS[(byte >> 4) as usize]; token[index * 2 + 1] = DIGITS[(byte & 15) as usize]; }
    let token = std::str::from_utf8(&token).map_err(|_| Reason::CleanupUnknown)?;
    let mut names = [(String::new(), String::new()), (String::new(), String::new())];
    for (index, (prefix, suffix)) in [("mrk-backup-", ".mrkbackup"), ("mrk-recovery-", ".mrkcode")].into_iter().enumerate() {
        let length = prefix.len() + token.len() + suffix.len();
        let mut published = String::new(); published.try_reserve_exact(length).map_err(|_| Reason::Capacity)?;
        if published.capacity() > length { return Err(Reason::Capacity); }
        published.push_str(prefix); published.push_str(token); published.push_str(suffix);
        let mut pending = String::new(); pending.try_reserve_exact(length + 8).map_err(|_| Reason::Capacity)?;
        if pending.capacity() > length + 8 { return Err(Reason::Capacity); }
        pending.push_str(&published); pending.push_str(".pending"); names[index] = (pending, published);
    }
    Ok(names)
}
fn acl_reason(failure: Failure) -> Reason { match failure {
    Failure::Refused | Failure::Native => Reason::SourceRefused, Failure::Bounds => Reason::Capacity,
    Failure::Stopped => Reason::UserCancelled, Failure::Unknown => Reason::CleanupUnknown,
} }
fn earlier(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> { match (a, b) {
    (Some(a), Some(b)) => Some(a.min(b)), (Some(at), None) | (None, Some(at)) => Some(at), (None, None) => None,
} }
fn cleanup_expired(owner: &OriginalWork, first: Option<Instant>) -> bool {
    owner.credential_backup_sink_cleanup_expired() || first.is_some_and(|at|
        at.checked_add(FAILURE_CLEANUP).is_none_or(|end| Instant::now() >= end))
}
fn observe(acl: &mut SnapshotBook, fd: BorrowedFd<'_>, expected: Expected, policy: Policy, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
    let result = acl.observe_phased(fd, expected, policy, &mut |phase, first| {
        if let Some((failure, at)) = first { owner.credential_backup_sink_failed_at(acl_reason(failure), at); }
        match phase { ObservePhase::Work => owner.interrupted(),
            ObservePhase::Cleanup => cleanup_expired(owner, first.map(|first| first.1)) }
    });
    if let Some((failure, at)) = acl.first_failure() { owner.credential_backup_sink_failed_at(acl_reason(failure), at); }
    result.map_err(acl_reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_pair_names_and_zero_identity_never_use_user_components() {
        assert!(output_names([0; 16]).is_err());
        let names = output_names([7; 16]).unwrap();
        assert_ne!(names[0].1, names[1].1);
        for (index, (pending, published)) in names.iter().enumerate() {
            assert_eq!(pending, &format!("{published}.pending"));
            assert!(published.starts_with(if index == 0 { "mrk-backup-" } else { "mrk-recovery-" }));
            assert!(published.ends_with(if index == 0 { ".mrkbackup" } else { ".mrkcode" }));
            assert!(!published.contains('/') && published.len() < 128 && pending.len() < 128);
        }
    }
    #[test]
    fn closed_descriptor_data_never_erases_unknown_effect_or_means_delivery() {
        let mut out = Output::reserved(); out.handle = Handle::NoHandle;
        assert!(out.closed() && out.effects_known() && !out.completed());
        out.creation = Effect::Unknown;
        assert!(out.closed() && !out.effects_known() && !out.completed());
        out.creation = Effect::Applied; out.write = Effect::Entered;
        assert!(!out.effects_known() && !out.completed());
        out.write = Effect::Applied; out.written = CODE_BYTES; out.expected_bytes = Some(CODE_BYTES);
        out.file_sync = Effect::Applied; out.publication = Effect::Applied;
        assert!(!out.effects_known() && !out.completed());
        out.directory_sync = Effect::Unknown;
        assert!(!out.effects_known() && !out.completed());
        out.directory_sync = Effect::Applied; out.verified = true;
        assert!(out.completed()); // Predicate DATA, never calls candidate_ready/native IO.
        out.handle = Handle::Unknown;
        assert!(!out.closed() && !out.completed());
    }
    #[test]
    fn arbitrary_path_data_on_an_ordinary_owner_never_acquires_a_sink() {
        let original = OriginalWork::artifact_unentered_original_data();
        assert!(BackupDestinations::new(&original, ["/private/synthetic/a".into(), "/private/synthetic/b".into()]).is_err());
        assert!(original.artifact_refusal_settled() == false); // No receipts changed.
    }
    #[test]
    fn closed_native_predicates_cannot_erase_pair_effect_uncertainty() {
        let owner = OriginalWork::artifact_unentered_original_data();
        let destination = BackupDestinations::unknown_effect_predicate_data(&owner);
        assert!(destination.native_settled()); // Negative DATA only, not an actual native return.
        assert!(!destination.disposal_ready() && !destination.candidate_ready(&owner));
        assert!(destination.retained_bytes().unwrap() > 0);
        assert!(CONTROL_BYTES <= 1024 * 1024);
    }
    #[test]
    fn renamed_but_unsynced_directory_is_retained_without_claiming_sync_entry() {
        let owner = OriginalWork::artifact_unentered_original_data();
        let destination = BackupDestinations::unsynced_publication_predicate_data(&owner);
        assert!(destination.outputs[1].publication == Effect::Applied);
        assert!(destination.outputs[1].directory_sync == Effect::NotStarted);
        assert!(destination.outputs.iter().all(Output::closed));
        assert!(destination.native_settled()); // Negative DATA, not native finality.
        assert!(!destination.disposal_ready() && !destination.candidate_ready(&owner));
        assert!(destination.retained_bytes().unwrap() > 0);
    }
}
