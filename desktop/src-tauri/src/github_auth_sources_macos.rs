//! Actual selected-user/config/tool originals, nested in asset_source_macos.
//! SAME SourceBook + native Account + SnapshotBook, no second filesystem or
//! process engine. The original native invocation retains this object across
//! BOTH captures and the existing HTTP /user connection, not just gh EOF.
//! No Drop cleanup. All methods run only in the containing registered blocking
//! call; a lost call/join/close keeps these originals and their admission debit.
use super::*;
use crate::{github_auth_capture_wire as wire, github_auth_nomination::StockGhNomination};
use mrk_macos_installed_native::{
    local_account::Account,
    vault_filesystem::{Expected, Failure, Policy, SnapshotBook},
};
use sha2::{Digest, Sha256};
use std::time::Instant;
use zeroize::Zeroizing;
use crate::github_auth_accounts as accounts;

const SOURCE_LIMIT: usize = 64;
pub(crate) struct GhAuthSources {
    book: SourceBook,
    account: Account,
    acl_entered: bool,
    acl: Option<SnapshotBook>,
    started: bool,
    finished: bool,
    close_failed: bool,
    first: Option<Reason>,
    native: Option<wire::Native>,
    accounts: Option<accounts::Witness>,
    indices: [Option<usize>; 3],
}
impl Drop for GhAuthSources {
    fn drop(&mut self) {
        // No implicit descriptor close after an original handoff/owner fault.
        // The containing owner must retain and settle this object explicitly;
        // this defensive leak is NOT a recovery or native settlement path.
        if !self.book.settled() {
            let original = std::mem::replace(&mut self.book, SourceBook::new());
            std::mem::forget(original);
        }
    }
}
impl GhAuthSources {
    pub(crate) fn new() -> Self {
        Self {
            book: SourceBook::new(),
            account: Account::new(),
            acl_entered: false,
            acl: None,
            started: false,
            finished: false,
            close_failed: false,
            first: None,
            native: None,
            accounts: None,
            indices: [None; 3],
        }
    }
    pub(crate) fn not_started(&self) -> bool {
        !self.started
            && !self.finished
            && !self.acl_entered
            && self.acl.is_none()
            && self.book.not_started()
    }
    pub(crate) fn first_failure(&self) -> Option<(Failure, Instant)> {
        self.acl.as_ref().and_then(SnapshotBook::first_failure)
    }
    fn remember<T>(&mut self, result: Result<T, Reason>) -> Result<T, Reason> {
        if let Err(reason) = result.as_ref() {
            self.first.get_or_insert(*reason);
        }
        result
    }
    pub(crate) fn working_bytes() -> Option<usize> {
        SOURCE_LIMIT
            .checked_mul(std::mem::size_of::<Descriptor>() + 255)?
            .checked_add(std::mem::size_of::<Self>())?
            // Hash scratch + private full config snapshot + finite parser stack.
            .checked_add(32768 + wire::CONFIG_LIMIT as usize + 3 * 4096 + 4096 + 16384)?
            .checked_add(mrk_macos_installed_native::vault_filesystem::SNAPSHOT_FRAME_BYTES)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.book
            .retained_bytes()?
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(
                self.acl
                    .as_ref()
                    .map_or(0, SnapshotBook::retained_frame_bytes),
            )?
            .checked_add(
                self.native
                    .as_ref()
                    .map_or(Some(0), wire::Native::retained_bytes)?,
            )?
            .checked_add(self.accounts.as_ref().map_or(Some(0), accounts::Witness::retained_bytes)?)
    }
    fn snapshot(
        &self,
        index: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<wire::Snapshot, Reason> {
        self.snapshot_read(index, stop, false).map(|(snapshot, _)| snapshot)
    }
    fn snapshot_read(&self, index: usize, stop: &mut dyn FnMut() -> bool, collect: bool)
        -> Result<(wire::Snapshot, Option<Vec<String>>), Reason> {
        checkpoint(stop)?;
        let actual = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let id = file_identity(&actual)?;
        if self.book.slots[index].identity != Some(Identity::File(id)) {
            return Err(Reason::SourceChanged);
        }
        let nanos = |(seconds, nanos): (i64, i64)| -> Result<i64, Reason> {
            if !(0..1_000_000_000).contains(&nanos) {
                return Err(Reason::SourceRefused);
            }
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|v| v.checked_add(nanos))
                .ok_or(Reason::SourceRefused)
        };
        let identity = (
            id.common.dev,
            id.common.ino,
            id.common.mode,
            id.common.uid,
            id.common.gid,
            id.nlink,
            id.size,
            nanos(id.mtime)?,
            nanos(id.ctime)?,
        );
        let maximum = if Some(index) == self.indices[0] {
            wire::TOOL_LIMIT
        } else {
            wire::CONFIG_LIMIT
        };
        if id.size == 0 || id.size > maximum {
            return Err(Reason::MaterialLimit);
        }
        unistd::lseek(self.book.fd(index)?, 0, unistd::Whence::SeekSet)
            .map_err(|_| Reason::SourceRefused)?;
        let mut buffer = Zeroizing::new([0u8; 32768]);
        // The same held bytes/hash, never a later path reopen or claimed schema.
        // Retain no plaintext beyond this bounded native call; parser borrows.
        let mut config = if Some(index) == self.indices[1] || collect {
            Some(Zeroizing::new(vec![0u8; id.size as usize]))
        } else {
            None
        };
        let mut count = 0u64;
        let mut hash = Sha256::new();
        loop {
            checkpoint(stop)?;
            let used = unistd::read(self.book.fd(index)?, &mut buffer[..])
                .map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if used == 0 {
                break;
            }
            count = count
                .checked_add(used as u64)
                .ok_or(Reason::MaterialLimit)?;
            if count > id.size {
                return Err(Reason::SourceChanged);
            }
            hash.update(&buffer[..used]);
            if let Some(config) = config.as_mut() {
                config[count as usize - used..count as usize].copy_from_slice(&buffer[..used]);
            }
        }
        if count != id.size {
            return Err(Reason::SourceChanged);
        }
        checkpoint(stop)?;
        let after = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if file_identity(&after)? != id {
            return Err(Reason::SourceChanged);
        }
        if Some(index) == self.indices[1] && config
            .as_ref()
            .is_some_and(|raw| !wire::config_schema_one(raw))
        {
            return Err(Reason::SourceRefused);
        }
        let names = if collect {
            Some(accounts::names(config.as_ref().ok_or(Reason::SourceRefused)?).ok_or(Reason::SourceRefused)?)
        } else { None };
        Ok((wire::Snapshot {
            identity,
            sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        }, names))
    }
    // Reuse SourceBook's actual reserve/adopt/held descriptor states. No image,
    // archive, credential or SavedConfiguration authority is borrowed as gh.
    fn tool(&mut self, parent: usize, stop: &mut dyn FnMut() -> bool) -> Result<usize, Reason> {
        checkpoint(stop)?;
        let index = self.book.reserve(Some(parent), b"gh")?;
        let before = stat::fstatat(self.book.fd(parent)?, "gh", AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let expected = file_identity(&before)?;
        let (_, uid, _) = self.account.selected().map_err(|_| Reason::SourceChanged)?;
        if expected.nlink != 1
            || expected.size == 0
            || expected.size > wire::TOOL_LIMIT
            || !matches!(expected.common.uid, 0) && expected.common.uid != uid
            || expected.common.mode & 0o7022 != 0
            || expected.common.mode & 0o111 == 0
        {
            return Err(Reason::SourceRefused);
        }
        self.book.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::openat(
            self.book.fd(parent)?,
            "gh",
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        );
        self.book.adopt(index, opened)?;
        checkpoint(stop)?;
        filesystem(self.book.fd(index)?, stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let named = stat::fstatat(self.book.fd(parent)?, "gh", AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if file_identity(&held)? != expected || file_identity(&named)? != expected {
            return Err(Reason::SourceChanged);
        }
        self.book.slots[index].identity = Some(Identity::File(expected));
        Ok(index)
    }
    pub(crate) fn inspect_selected(
        &mut self,
        executable: &Path,
        nomination: &StockGhNomination,
        runtime_live: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if !self.not_started() {
            return Err(Reason::CleanupUnknown);
        }
        self.started = true;
        let result = (|| {
            checkpoint(stop)?;
            self.account.acquire().map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let (home, uid, gid) = self.account.selected().map_err(|_| Reason::SourceRefused)?;
            let home = PathBuf::from(home);
            let config = home.join(".config/gh");
            let components = parts(executable)?;
            if components.last() != Some(&b"gh".as_slice()) || executable.starts_with(&config) {
                return Err(Reason::SourceRefused);
            }
            let parents = &components[..components.len() - 1];
            let config_parts = parts(&config)?;
            let slots = roster_limit([parents.len(), config_parts.len()], 3)?;
            // Distinct originals (not inode deduplication); reserve this capture
            // and the subsequent original HTTP pipes/management bookkeeping.
            if slots > SOURCE_LIMIT
                || slots
                    .checked_add(runtime_live)
                    .and_then(|n| n.checked_add(32))
                    .is_none_or(|n| n > 256)
            {
                return Err(Reason::Capacity);
            }
            self.book.begin(slots, 0, 0)?;
            self.acl_entered = true; // Before the native frame constructor.
            self.acl = Some(SnapshotBook::new());
            self.book.root(stop)?;
            let (tool_parents, _) = self.book.chain(parents, false, stop)?;
            let parent = *tool_parents.last().ok_or(Reason::SourceRefused)?;
            let tool = self.tool(parent, stop)?;
            self.indices[0] = Some(tool);
            let tool_snapshot = self.snapshot(tool, stop)?;
            if !nomination.matches_actual_sha256(&tool_snapshot.sha256) {
                return Err(Reason::SourceRefused);
            }
            let (config_parents, _) = self.book.chain(&config_parts, false, stop)?;
            let parent = *config_parents.last().ok_or(Reason::SourceRefused)?;
            if self.book.directory(parent)?.uid != uid {
                return Err(Reason::SourceRefused);
            }
            let config_index = self.book.child(parent, b"config.yml", true, stop)?;
            self.indices[1] = Some(config_index);
            let hosts_index = self.book.child(parent, b"hosts.yml", true, stop)?;
            self.indices[2] = Some(hosts_index);
            let native = wire::Native {
                uid,
                gid,
                home: home.to_str().ok_or(Reason::SourceRefused)?.into(),
                config: config.to_str().ok_or(Reason::SourceRefused)?.into(),
                executable: executable.to_str().ok_or(Reason::SourceRefused)?.into(),
                tool: tool_snapshot,
                files: wire::Files {
                    config: self.snapshot(config_index, stop)?,
                    hosts: self.snapshot(hosts_index, stop)?,
                },
            };
            if !native.valid() {
                return Err(Reason::SourceRefused);
            }
            self.native = Some(native);
            self.post_inner(stop)?;
            if self
                .retained_bytes()
                .zip(Self::working_bytes())
                .is_none_or(|(actual, limit)| actual > limit)
            {
                return Err(Reason::Capacity);
            }
            Ok(())
        })();
        self.remember(result)
    }
    // SAME finite SourceBook/account/ACL facet; config-only mode never mints
    // Native/tool/capture authority and never opens a keyring or gh executable.
    pub(crate) fn inspect_accounts(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if !self.not_started() { return Err(Reason::CleanupUnknown); }
        self.started = true;
        let result = (|| {
            checkpoint(stop)?; self.account.acquire().map_err(|_| Reason::SourceRefused)?; checkpoint(stop)?;
            let (home, uid, gid) = self.account.selected().map_err(|_| Reason::SourceChanged)?;
            let home = PathBuf::from(home); let config = home.join(".config/gh");
            let config_parts = parts(&config)?;
            let slots = roster_limit(std::iter::once(config_parts.len()), 2)?;
            if slots > SOURCE_LIMIT || slots.checked_add(32).is_none_or(|n| n > 256) { return Err(Reason::Capacity); }
            self.book.begin(slots, 0, 0)?; self.acl_entered = true; self.acl = Some(SnapshotBook::new()); self.book.root(stop)?;
            let (parents, _) = self.book.chain(&config_parts, false, stop)?;
            let parent = *parents.last().ok_or(Reason::SourceRefused)?;
            if self.book.directory(parent)?.uid != uid { return Err(Reason::SourceRefused); }
            let config_index = self.book.child(parent, b"config.yml", true, stop)?; self.indices[1] = Some(config_index);
            let hosts_index = self.book.child(parent, b"hosts.yml", true, stop)?; self.indices[2] = Some(hosts_index);
            let config_snapshot = self.snapshot(config_index, stop)?; // original prelaunch schema guard unchanged
            let (hosts, logins) = self.snapshot_read(hosts_index, stop, true)?;
            let witness = accounts::Witness { uid, gid, home: home.to_str().ok_or(Reason::SourceRefused)?.into(),
                config: config.to_str().ok_or(Reason::SourceRefused)?.into(), files: wire::Files { config: config_snapshot, hosts },
                logins: logins.ok_or(Reason::SourceRefused)? };
            if !witness.valid() { return Err(Reason::SourceRefused); }
            self.accounts = Some(witness); self.post_inner(stop)?;
            if self.retained_bytes().zip(Self::working_bytes()).is_none_or(|(n, limit)| n > limit) { return Err(Reason::Capacity); }
            Ok(())
        })(); self.remember(result)
    }
    pub(crate) fn accounts_witness(&self) -> Result<&accounts::Witness, Reason> {
        if self.finished || self.first.is_some() { return Err(Reason::SourceChanged); }
        self.accounts.as_ref().ok_or(Reason::SourceRefused)
    }
    fn post_inner(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        checkpoint(stop)?;
        let (_, uid, _) = self.account.selected().map_err(|_| Reason::SourceChanged)?;
        // Every original ancestry/name, not just a pathname or a file hash.
        for index in 0..self.book.slots.len() {
            checkpoint(stop)?;
            let slot = &self.book.slots[index];
            let expected = slot.identity.ok_or(Reason::SourceChanged)?;
            let file = matches!(expected, Identity::File(_));
            let fd = self.book.fd(index)?;
            filesystem(fd, stop)?;
            let held = stat::fstat(fd).map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            let named = if let Some(parent) = slot.parent {
                stat::fstatat(
                    self.book.fd(parent)?,
                    OsStr::from_bytes(&slot.name),
                    AtFlags::AT_SYMLINK_NOFOLLOW,
                )
            } else {
                stat::lstat(Path::new("/"))
            }
            .map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if identity(&held, file)? != expected
                || identity(&named, file)? != expected
                || held.st_flags != 0
                || named.st_flags != 0
                || held.st_mode & 0o7022 != 0
                || held.st_uid != 0 && held.st_uid != uid
            {
                return Err(Reason::SourceChanged);
            }
            let actual = common(&held)?;
            let acl_expected = Expected {
                device: actual.dev,
                inode: actual.ino,
                mode: actual.mode,
                owner: actual.uid,
                group: actual.gid,
                flags: held.st_flags,
            };
            let policy = if file {
                Policy::Empty
            } else {
                Policy::Ancestors
            };
            self.acl
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .observe(fd.as_fd(), acl_expected, policy, stop)
                .map_err(|failure| {
                    if failure == Failure::Unknown {
                        Reason::CleanupUnknown
                    } else {
                        Reason::SourceRefused
                    }
                })?;
            checkpoint(stop)?;
        }
        if let Some(native) = &self.native {
            for (index, expected) in self.indices.iter().zip([&native.tool, &native.files.config, &native.files.hosts]) {
                if &self.snapshot(index.ok_or(Reason::SourceChanged)?, stop)? != expected { return Err(Reason::SourceChanged); }
            }
        } else if let Some(accounts) = &self.accounts {
            for (index, expected) in self.indices[1..].iter().zip([&accounts.files.config, &accounts.files.hosts]) {
                if &self.snapshot(index.ok_or(Reason::SourceChanged)?, stop)? != expected { return Err(Reason::SourceChanged); }
            }
        } else { return Err(Reason::SourceChanged); }
        Ok(())
    }
    pub(crate) fn post(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if self.finished || self.first.is_some() || self.native.is_none() {
            return Err(Reason::SourceChanged);
        }
        let result = self.post_inner(stop);
        self.remember(result)
    }
    pub(crate) fn native_snapshot(&self) -> Result<&wire::Native, Reason> {
        if self.finished || self.first.is_some() {
            return Err(Reason::SourceChanged);
        }
        self.native.as_ref().ok_or(Reason::SourceRefused)
    }
    pub(crate) fn close(
        &mut self,
        expired: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool,
    ) -> Result<(), Reason> {
        if self.finished {
            return if self.settled() {
                Ok(())
            } else {
                Err(Reason::CleanupUnknown)
            };
        }
        // The original parent must first join BOTH capture workers and the
        // existing HTTP owner. This method cannot infer that from DTO flags.
        self.finished = true;
        self.close_failed = true; // Includes a panic/late/lost consuming return.
        if !self.account.call_settled() || self.acl_entered && self.acl.is_none() {
            return Err(Reason::CleanupUnknown);
        }
        if let Some(acl) = self.acl.as_mut() {
            if !acl.release(expired) || !acl.settled() {
                return Err(Reason::CleanupUnknown);
            }
        }
        if expired(self.first_failure()) {
            return Err(Reason::CleanupUnknown);
        }
        let closed = self.book.close_all();
        if !closed || expired(self.first_failure()) {
            return Err(Reason::CleanupUnknown);
        }
        self.close_failed = false;
        Ok(())
    }
    pub(crate) fn settled(&self) -> bool {
        self.finished
            && !self.close_failed
            && self.account.call_settled()
            && self.book.settled()
            && (!self.acl_entered || self.acl.as_ref().is_some_and(SnapshotBook::settled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_empty_source_close_is_absorbing_not_repaired_by_second_call() {
        // Constructor/empty SourceBook DATA only. No filesystem, ACL, account,
        // keyring, native source admission or invented positive original runs.
        let mut sources = GhAuthSources::new();
        let mut calls = 0;
        assert!(sources
            .close(&mut |_| {
                calls += 1;
                calls == 2
            })
            .is_err());
        assert_eq!(calls, 2);
        assert!(!sources.settled());
        assert!(sources
            .close(&mut |_| panic!("unknown close must not retry"))
            .is_err());
        assert!(!sources.not_started());
    }
    #[test]
    fn missing_original_acl_constructor_return_cannot_settle() {
        let mut sources = GhAuthSources::new();
        sources.acl_entered = true; // Inert lost-return state, not a native call.
        assert!(sources.close(&mut |_| false).is_err());
        assert!(!sources.settled());
        assert!(sources.close(&mut |_| false).is_err());
    }
}
