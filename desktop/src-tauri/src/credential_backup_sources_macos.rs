//! Closed, private backup-pair capture, nested in the actual macOS SourceBook.
//!
//! The original credential operation retains this entire object BEFORE GO.
//! Its two paths come from that operation's native picker phases, never an IPC
//! pathname, FileKind/JKS disguise or lookup of an ambient recovery code. This
//! object is NOT picker authorization. Root must supply the original selector
//! and document gates before calling it; no public route is enabled here.
//!
//! Reuse the existing private APFS/no-follow/ACL/EOF/recheck/one-close owner.
//! Neither input is adopted for deletion. In particular the recovery-code read
//! buffer, its partial bytes and EOF sentinel are zeroizing from allocation.
use super::*;
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
use crate::asset_session::OriginalWork;
use crate::{credential_format, vault_crypto as crypto, vault_format as format};
use crypto::backup;
use zeroize::{Zeroize, Zeroizing};

const CODE_BYTES: usize = b"mrk-recovery-v1-".len() + 64;
const ROOTS: usize = 33; // The fixed native project roster (<=32) plus this vault.
// Finite first-party control quote, not a provider/RSS bound. The same SourceBook
// already caps descriptor/alias/name allocation. Include every simultaneous
// borrowed spelling, caller-owned root clone, one chain and the actual retained
// pair wrapper before either private read allocation. Counting full rosters is
// deliberately conservative; no descriptor or source identity deduplication.
const SOURCE_CONTROL_BYTES: usize =
    DESCRIPTOR_LIMIT * (std::mem::size_of::<Descriptor>() + 255)
    + 32 * (std::mem::size_of::<OriginAlias>() + 16)
    + (ROOTS + 2) * (std::mem::size_of::<Vec<&[u8]>>()
        + (COMPONENT_LIMIT - 1) * std::mem::size_of::<&[u8]>())
    + ROOTS * (std::mem::size_of::<RegisteredRoot>() + PATH_LIMIT
        + std::mem::size_of::<DirectoryIdentity>())
    + 2 * (COMPONENT_LIMIT + 1) * std::mem::size_of::<usize>()
    + 2 * PATH_LIMIT + std::mem::size_of::<BackupSources>() + 4096;

struct PrivatePair {
    encrypted: Zeroizing<Vec<u8>>,
    code: Zeroizing<Vec<u8>>,
}

/// No Clone/Debug/Serde or private byte getter. All native acquisition facts,
/// partially read bytes and authenticated input remain in this original owner.
pub(crate) struct BackupSources {
    book: SourceBook,
    paths: [PathBuf; 2], // backup, recovery code; never projected or logged
    raw: PrivatePair,
    restored: Option<backup::ImportedBackup>,
    capture_started: bool,
    captured: bool,
    authentication_started: bool,
    transition_bytes: usize,
    first: Option<Reason>,
    #[cfg(all(test, debug_assertions))]
    component_expected: Option<ComponentExpectedPair>,
}

impl BackupSources {
    /// Native-only construction. A pair of paths is DATA, not permission to
    /// read; the containing OriginalWork must still admit both real pickers.
    pub(crate) fn new(paths: [PathBuf; 2]) -> Result<Self, Reason> {
        if paths[0] == paths[1] || paths.iter().any(|path| path.capacity() > PATH_LIMIT) {
            return Err(Reason::SourceRefused);
        }
        for path in &paths {
            if parts(path)?.is_empty() { return Err(Reason::SourceRefused); }
        }
        Ok(Self {
            book: SourceBook::new(), paths,
            raw: PrivatePair { encrypted: Zeroizing::new(Vec::new()), code: Zeroizing::new(Vec::new()) },
            restored: None, capture_started: false, captured: false,
            authentication_started: false, transition_bytes: 0, first: None,
            #[cfg(all(test, debug_assertions))]
            component_expected: None,
        })
    }

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn compare_installed_picker_pair(mut self, owner: &Arc<OriginalWork>, pair: ComponentPair) -> Result<Self, Reason> {
        if !owner.installed_backup_import_scope() || self.capture_started || self.authentication_started
            || !self.book.not_started() || self.component_expected.is_some() { return Err(Reason::SourceChanged); }
        let (paths, expected) = pair.into_parts();
        if self.paths != paths { return Err(Reason::SourceChanged); }
        self.component_expected = Some(expected); // Actual selected paths never replaced.
        Ok(self)
    }

    /// Test-only same-output comparison; no selected-path or native receipt
    /// can be supplied. All ordinary capture/currentness/cleanup stays below.
    #[cfg(all(test, debug_assertions))]
    pub(crate) fn new_component_restore(pair: ComponentPair) -> Result<Self, Reason> {
        let (paths, expected) = pair.into_parts();
        let mut value = Self::new(paths)?;
        value.component_expected = Some(expected);
        Ok(value)
    }

    fn fail(&mut self, reason: Reason) {
        if self.first.is_none() { self.first = Some(reason); }
    }

    pub(crate) fn not_started(&self) -> bool {
        !self.capture_started && !self.captured && !self.authentication_started
            && self.first.is_none() && self.transition_bytes == 0 && self.restored.is_none()
            && self.raw.encrypted.capacity() == 0 && self.raw.code.capacity() == 0
            && self.book.not_started()
    }

    /// Original native quiescence ONLY; this does not dispose private input,
    /// establish worker/coordinator joins, or make the operation reusable.
    pub(crate) fn native_settled(&self) -> bool {
        self.book.not_started() || self.book.settled()
    }

    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.book.retained_bytes()?)?
            .checked_add(self.paths[0].capacity())?.checked_add(self.paths[1].capacity())?
            .checked_add(self.raw.encrypted.capacity())?.checked_add(self.raw.code.capacity())?
            .checked_add(self.transition_bytes)?
            .checked_add(self.restored.as_ref().map_or(Some(0), backup::ImportedBackup::retained_bytes)?)
    }

    /// One attempt over the whole native project+vault exclusion roster. The
    /// containing operation supplies its original working-memory quote.
    pub(crate) fn capture(&mut self, roots: &[RegisteredRoot], allowance: usize,
        owner: &crate::asset_session::OriginalWork) -> Result<(), Reason> {
        if self.capture_started || self.authentication_started || self.first.is_some() || !self.book.not_started() {
            owner.credential_backup_failed(Reason::CleanupUnknown);
            return Err(Reason::CleanupUnknown);
        }
        self.capture_started = true; // Refusal/STOP is not a retry opportunity.
        let mut stop = || owner.interrupted();
        let mut result = self.capture_inner(roots, allowance, &mut stop);
        if let Err(reason) = result { self.fail(reason); owner.credential_backup_failed(reason); }
        if result.is_ok() {
            result = self.book.terminal_check(&mut stop);
            if let Err(reason) = result { self.fail(reason); owner.credential_backup_failed(reason); }
        }
        // First failure is retained before independent native cleanup. The
        // same finite SourceBook attempts every original close once, including
        // on an ACL/read/terminal-check failure; ambiguous closes stay Unknown.
        // This observer calls only the fixed original failure latch. It cannot
        // publish input, output, close receipts or extend the original clock.
        if !self.book.close_all_observing(&mut |reason| owner.credential_backup_failed(reason)) {
            self.fail(Reason::CleanupUnknown);
            return Err(Reason::CleanupUnknown);
        }
        result?; // The fixed failure latch's STOP cannot replace that failure.
        if let Err(reason) = checkpoint(&mut stop) {
            self.fail(reason);
            owner.credential_backup_failed(reason);
            return Err(reason);
        }
        if !self.book.settled() {
            self.fail(Reason::CleanupUnknown);
            owner.credential_backup_failed(Reason::CleanupUnknown);
            return Err(Reason::CleanupUnknown);
        }
        self.captured = true;
        Ok(())
    }

    fn capture_inner(&mut self, roots: &[RegisteredRoot], allowance: usize,
        stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        checkpoint(stop)?;
        if !(1..=ROOTS).contains(&roots.len()) || roots.iter().any(|root| root.path.capacity() > PATH_LIMIT)
            || allowance > format::WORKING_BYTES
            || allowance < SOURCE_CONTROL_BYTES + CODE_BYTES + 1 {
            return Err(Reason::Capacity);
        }
        let selected = [parts(&self.paths[0])?, parts(&self.paths[1])?];
        let mut root_parts = Vec::new();
        root_parts.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
        if root_parts.capacity() > ROOTS { return Err(Reason::Capacity); }
        for root in roots {
            root.identity.posix()?;
            root_parts.push(parts(&root.path)?);
            if self.paths.iter().any(|path| path.starts_with(&root.path)) {
                return Err(Reason::ProjectOverlap);
            }
        }
        let mut source_depths = [0usize; 2];
        for (index, components) in selected.iter().enumerate() {
            let (_, parents) = components.split_last().ok_or(Reason::SourceRefused)?;
            source_depths[index] = parents.len() + source_extra(parents);
        }
        // Shared '/', canonical /private anchor and TWO leaves. Do not reset
        // the ordinary operation.source book used later for vault exclusion.
        let capacity = roster_limit(root_parts.iter().map(Vec::len).chain(source_depths), 3)?;
        self.book.begin(capacity, 0, 2)?;
        self.book.root(stop)?;
        self.book.anchor_private(stop)?;
        let mut root_ids = Vec::new();
        root_ids.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
        if root_ids.capacity() > ROOTS { return Err(Reason::Capacity); }
        for (root, components) in roots.iter().zip(&root_parts) {
            let (chain, _) = self.book.chain(components, false, stop)?;
            let identity = self.book.directory(*chain.last().ok_or(Reason::SourceRefused)?)?;
            if ProjectIdentity::Posix(identity) != root.identity { return Err(Reason::SourceChanged); }
            root_ids.push(identity);
        }
        let mut inputs = [None, None];
        for (index, components) in selected.iter().enumerate() {
            let (name, parents) = components.split_last().ok_or(Reason::SourceRefused)?;
            let (chain, _) = self.book.chain(parents, true, stop)?;
            for ancestor in &chain {
                let actual = self.book.directory(*ancestor)?;
                if root_ids.iter().any(|root| actual.same_object(*root)) { return Err(Reason::ProjectOverlap); }
            }
            let parent = *chain.last().ok_or(Reason::SourceRefused)?;
            let leaf = self.book.child(parent, name, true, stop)?;
            let file = match self.book.slots[leaf].identity {
                Some(Identity::File(file)) => file, _ => return Err(Reason::SourceRefused),
            };
            #[cfg(all(test, debug_assertions))]
            if self.component_expected.as_ref().is_some_and(|expected|
                !self.book.directory(parent).is_ok_and(|parent|
                    expected.matches(index, parent, file))) {
                return Err(Reason::SourceChanged);
            }
            let size = usize::try_from(file.size).map_err(|_| Reason::MaterialLimit)?;
            if !input_size(index, size) { return Err(Reason::MaterialLimit); }
            self.book.private_acl(leaf, 0, stop)?;
            inputs[index] = Some((leaf, file, size));
        }
        let (backup_leaf, backup_file, backup_size) = inputs[0].ok_or(Reason::SourceRefused)?;
        let (code_leaf, code_file, code_size) = inputs[1].ok_or(Reason::SourceRefused)?;
        if backup_file.common.same_object(code_file.common) { return Err(Reason::SourceRefused); }
        let capacity = backup_size.checked_add(1).and_then(|n| n.checked_add(code_size + 1))
            .and_then(|n| n.checked_add(SOURCE_CONTROL_BYTES)).ok_or(Reason::Capacity)?;
        if capacity > allowance { return Err(Reason::Capacity); }
        // Code first: an invalid code never causes the larger backup read.
        // Both buffers live in self before their first original read syscall.
        read_private(&mut self.book, code_leaf, code_size, &mut self.raw.code, stop)?;
        drop(backup::RecoveryCode::parse(&self.raw.code).map_err(|_| Reason::SourceRefused)?);
        read_private(&mut self.book, backup_leaf, backup_size, &mut self.raw.encrypted, stop)?;
        if self.retained_bytes().is_none_or(|bytes| bytes > allowance) { return Err(Reason::Capacity); }
        Ok(())
    }

    /// Authenticating does not grant source/worker finality, trust or Bind.
    /// The original object retains the in-place decode charge across the move
    /// and keeps authenticated plaintext BEFORE any later STOP/fallible call.
    pub(crate) fn authenticate(&mut self, allowance: usize,
        stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if !self.captured || !self.book.settled() || self.authentication_started || self.first.is_some() {
            return Err(Reason::SourceRefused);
        }
        if let Err(reason) = checkpoint(stop) { self.fail(reason); return Err(reason); }
        self.authentication_started = true;
        let result = (|| {
            let occupied = self.retained_bytes().ok_or(Reason::Capacity)?;
            let cipher = self.raw.encrypted.capacity();
            let allowance = allowance.checked_sub(occupied.checked_sub(cipher).ok_or(Reason::Capacity)?)
                .ok_or(Reason::Capacity)?;
            let code = backup::RecoveryCode::parse(&self.raw.code).map_err(|_| Reason::SourceRefused)?;
            self.transition_bytes = cipher;
            let encrypted = std::mem::take(&mut *self.raw.encrypted);
            let restored = backup::import(encrypted, code, allowance).map_err(crypto_failure);
            match restored {
                Ok(restored) => { self.restored = Some(restored); self.transition_bytes = 0; },
                Err(reason) => {
                    // The synchronous codec has returned and zeroized its
                    // failed plaintext; an unwind instead retains this debit.
                    self.transition_bytes = 0;
                    return Err(reason);
                },
            }
            self.raw.code.zeroize();
            checkpoint(stop)
        })();
        if let Err(reason) = result { self.fail(reason); }
        result
    }

    /// Fixed NEW-record encryption only, never a plaintext getter, restored
    /// old ID/revision, existing-record replacement or assignment capability.
    pub(crate) fn seal_new(&self, key: &crypto::VaultKey, record: format::Id, allowance: usize,
        stop: &mut dyn FnMut() -> bool) -> Result<crypto::SealedRecord, Reason> {
        checkpoint(stop)?;
        if self.first.is_some() || !self.book.settled() || self.transition_bytes != 0 {
            return Err(Reason::SourceRefused);
        }
        let restored = self.restored.as_ref().ok_or(Reason::SourceRefused)?;
        if let Some(bytes) = restored.file() {
            let file = restored.descriptor.kind.file().ok_or(Reason::VaultCorrupt)?;
            let observation = credential_format::inspect(file, bytes, stop).map_err(|_| Reason::UserCancelled)?;
            if !observation.is_observed() { return Err(Reason::UnsupportedFormat); }
        }
        checkpoint(stop)?;
        let sealed = key.seal_record(record, None, &restored.descriptor, &restored.fields, restored.file(), allowance)
            .map_err(crypto_failure)?;
        checkpoint(stop)?;
        Ok(sealed)
    }

    pub(crate) fn kind(&self) -> Result<crate::asset_commands::Kind, Reason> {
        if self.first.is_some() || !self.book.settled() { return Err(Reason::SourceRefused); }
        self.restored.as_ref().map(|value| value.descriptor.kind).ok_or(Reason::SourceRefused)
    }

    pub(crate) fn matches_authenticated_readback(&self, record: &crypto::AuthenticatedRecord) -> bool {
        self.captured && self.authentication_started && self.first.is_none()
            && self.transition_bytes == 0 && self.book.settled()
            && self.restored.as_ref().is_some_and(|restored| restored.matches_authenticated_readback(record))
    }
}

fn input_size(index: usize, size: usize) -> bool {
    match index { 0 => size > 0 && size <= backup::BACKUP_LIMIT, 1 => size == CODE_BYTES, _ => false }
}

fn crypto_failure(error: crypto::Error) -> Reason {
    match error {
        crypto::Error::Bounds | crypto::Error::Allocation => Reason::Capacity,
        crypto::Error::Random | crypto::Error::Format | crypto::Error::Authentication => Reason::SourceRefused,
    }
}

fn read_private(book: &mut SourceBook, leaf: usize, size: usize, bytes: &mut Zeroizing<Vec<u8>>,
    stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
    if !bytes.is_empty() || bytes.capacity() != 0 { return Err(Reason::CleanupUnknown); }
    let capacity = size.checked_add(1).ok_or(Reason::MaterialLimit)?;
    bytes.try_reserve_exact(capacity).map_err(|_| Reason::Capacity)?;
    if bytes.capacity() > capacity { return Err(Reason::Capacity); }
    bytes.resize(capacity, 0);
    let mut used = 0usize;
    loop {
        checkpoint(stop)?;
        let end = capacity.min(used.saturating_add(1024 * 1024));
        let read = unistd::read(book.fd(leaf)?, &mut bytes[used..end]).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        if read == 0 {
            if used != size { return Err(Reason::SourceChanged); }
            break;
        }
        used = used.checked_add(read).filter(|used| *used <= size).ok_or(Reason::SourceChanged)?;
    }
    bytes.truncate(size); // Keep/count the allocated EOF sentinel until disposal.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // These early DATA refusals perform NO native open/read/ACL/close. They do
    // not qualify macOS capture or original worker/custody finality.
    #[test]
    fn backup_and_exact_code_are_distinct_fixed_input_roles() {
        assert_eq!(CODE_BYTES, 79);
        assert!(SOURCE_CONTROL_BYTES <= 1024 * 1024);
        assert!(input_size(0, backup::BACKUP_LIMIT));
        assert!(!input_size(0, backup::BACKUP_LIMIT + 1));
        assert!(!input_size(0, 0));
        assert!(input_size(1, 79));
        for length in [0, 78, 80, 128, usize::MAX] { assert!(!input_size(1, length)); }
        assert!(!input_size(2, 79));
    }

    #[test]
    fn invalid_or_same_path_pair_never_constructs_source_authority() {
        for paths in [
            ["/inert/same", "/inert/same"], ["relative", "/inert/code"],
            ["/inert/../backup", "/inert/code"], ["/inert/backup", "/inert//code"],
            ["/", "/inert/code"],
        ] {
            assert!(BackupSources::new(paths.map(PathBuf::from)).is_err());
        }
        let mut input = BackupSources::new(["/inert/backup", "/inert/code"].map(PathBuf::from)).unwrap();
        assert!(input.not_started());
        assert!(input.native_settled());
        assert!(input.authenticate(format::WORKING_BYTES, &mut || false).is_err());
        assert!(input.kind().is_err());
        assert!(input.retained_bytes().unwrap() >= std::mem::size_of::<BackupSources>());
    }
}
