//! Rename-only facet of the SAME GitLocal SourceBook. Two original ref locks
//! remain until all other original descriptors close, then one checked unlink
//! per lock and their original sole closes. No parallel owner or cleanup loop.
use super::*;
use crate::git_rename_protocol as rename;

struct Edge {
    parent: usize,
    name: Vec<u8>,
    original: Option<(usize, wire::Snapshot)>,
    maximum: u64,
}
struct RefLock {
    index: usize,
    unlink_claimed: bool,
    unlinked: bool,
}
struct Returned {
    step: wire::Publication,
    old: Option<usize>,
    old_snapshot: Option<wire::Snapshot>,
    successor: usize,
    snapshot: wire::Snapshot,
    maximum: u64,
}
pub(super) struct State {
    source: Option<Edge>,
    target: Option<Edge>,
    branch_log: Option<Edge>,
    new_log: Option<Edge>,
    head_log: Option<Edge>,
    packed: Option<Edge>,
    locks: Vec<RefLock>,
    parent_before: Option<wire::FileIdentity>,
    parent_current: Option<wire::FileIdentity>,
    projection: Option<rename::Sources>,
    returned: Vec<Returned>,
}
impl State {
    fn new() -> Result<Self, Reason> {
        let mut locks = Vec::new();
        locks.try_reserve_exact(2).map_err(|_| Reason::Capacity)?;
        let mut returned = Vec::new();
        returned
            .try_reserve_exact(6)
            .map_err(|_| Reason::Capacity)?;
        if locks.capacity() > 2 || returned.capacity() > 6 {
            return Err(Reason::Capacity);
        }
        Ok(Self {
            source: None,
            target: None,
            branch_log: None,
            new_log: None,
            head_log: None,
            packed: None,
            locks,
            parent_before: None,
            parent_current: None,
            projection: None,
            returned,
        })
    }
    pub(super) fn working_bytes() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(7 * (PATH_LIMIT + 2048))?
            .checked_add(6 * std::mem::size_of::<Returned>())?
            .checked_add(2 * std::mem::size_of::<RefLock>())
    }
    pub(super) fn extra(review: Option<&wire::Review>) -> Option<usize> {
        let Some(r) = review.and_then(wire::Review::rename_details) else {
            return Some(0);
        };
        // Full original ref/log chains, all old/new snapshots, two locks and
        // six possible successor entries. No alias/dedup/future-close credit.
        r.branch.split('/').count().checked_mul(2)?.checked_add(19)
    }
}
fn full(stat: &FileStat) -> Result<wire::FileIdentity, Reason> {
    let d = metadata_identity(stat)?;
    let nanos = |v: (i64, i64)| -> Result<i64, Reason> {
        if !(0..1_000_000_000).contains(&v.1) {
            return Err(Reason::SourceRefused);
        }
        v.0.checked_mul(1_000_000_000)
            .and_then(|s| s.checked_add(v.1))
            .ok_or(Reason::SourceRefused)
    };
    Ok((
        d.common.dev,
        d.common.ino,
        d.common.mode,
        d.common.uid,
        d.common.gid,
        d.nlink,
        d.size,
        nanos(d.mtime)?,
        nanos(d.ctime)?,
    ))
}
fn group_supported(original: wire::FileIdentity, parent: DirectoryIdentity) -> bool {
    original.4 == parent.gid
}

impl GitLocalSources {
    pub(crate) fn retain_rename_unknown(&mut self) {
        self.first = Some(Reason::CleanupUnknown);
        self.close_failed = true;
    }
    fn rename_parent(
        &self,
        index: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<wire::FileIdentity, Reason> {
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if directory_identity(&held)? != self.book.directory(index)? || held.st_flags != 0 {
            return Err(Reason::SourceChanged);
        }
        full(&held)
    }
    fn rename_edge(
        &mut self,
        parent: usize,
        name: &[u8],
        uid: u32,
        maximum: u64,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<Edge, Reason> {
        checkpoint(stop)?;
        let original = match stat::fstatat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => None,
            Ok(_) => {
                let index = self.file(parent, name, uid, maximum, false, stop)?;
                Some((index, self.snapshot(index, maximum, stop)?))
            }
            Err(_) => return Err(Reason::SourceRefused),
        };
        checkpoint(stop)?;
        Ok(Edge {
            parent,
            name: copy_bytes(name)?,
            original,
            maximum,
        })
    }
    fn rename_log_parent(
        &mut self,
        git: usize,
        reference: &str,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize, Reason> {
        let mut parent = self.book.child(git, b"logs", false, stop)?;
        let pieces: Vec<_> = reference.split('/').collect();
        for piece in &pieces[..pieces.len() - 1] {
            parent = self.book.child(parent, piece.as_bytes(), false, stop)?;
        }
        Ok(parent)
    }
    pub(super) fn capture_rename(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if self.rename.is_some() {
            return Err(Reason::SourceChanged);
        }
        let review = self
            .review
            .as_ref()
            .and_then(wire::Review::rename_details)
            .filter(|r| r.valid())
            .ok_or(Reason::SourceRefused)?
            .clone();
        let native = self.native.as_ref().ok_or(Reason::SourceRefused)?.clone();
        if native.files.head.sha256 != rename::hash(format!("ref: {}\n", review.branch).as_bytes())
            || native.files.config.sha256 != review.original_config
            || native.files.config.identity.6 > rename::CONFIG_LIMIT
            || !native.files.index.as_ref().is_some_and(|s| {
                s.sha256 == review.expected_index && s.identity.6 <= rename::INDEX_LIMIT
            })
        {
            return Err(Reason::SourceChanged);
        }
        self.rename = Some(State::new()?); // Retain before any lock acquisition.
        let git = self.git.ok_or(Reason::SourceChanged)?;
        let git_parent = self.book.directory(git)?;
        if !group_supported(native.files.head.identity, git_parent)
            || review.config_moved && !group_supported(native.files.config.identity, git_parent)
        {
            return Err(Reason::SourceRefused);
        }
        let pieces: Vec<_> = review.branch.split('/').collect();
        let mut parent = git;
        for piece in &pieces[..pieces.len() - 1] {
            parent = self.book.child(parent, piece.as_bytes(), false, stop)?;
        }
        let old = pieces.last().ok_or(Reason::SourceRefused)?.as_bytes();
        let new = review
            .target_ref
            .rsplit('/')
            .next()
            .ok_or(Reason::SourceRefused)?
            .as_bytes();
        let source = self.rename_edge(parent, old, native.uid, 65, stop)?;
        if !source
            .original
            .as_ref()
            .is_some_and(|(_, s)| s.sha256 == rename::hash(format!("{}\n", review.head).as_bytes()))
        {
            return Err(Reason::SourceChanged);
        }
        let target = self.rename_edge(parent, new, native.uid, 65, stop)?;
        if target.original.is_some() {
            return Err(Reason::SourceChanged);
        }
        self.rename.as_mut().ok_or(Reason::SourceChanged)?.source = Some(source);
        self.rename.as_mut().ok_or(Reason::SourceChanged)?.target = Some(target);
        // The fixed core refuses a packed shadow of the selected loose ref.
        // Capture a present complete packed file; no native resolver/inference.
        let packed = self.rename_edge(git, b"packed-refs", native.uid, 65536, stop)?;
        self.rename.as_mut().ok_or(Reason::SourceChanged)?.packed = Some(packed);
        let log_parent = self.rename_log_parent(git, &review.branch, stop)?;
        let old_log = self.rename_edge(log_parent, old, native.uid, rename::LOG_LIMIT, stop)?;
        let new_log = self.rename_edge(log_parent, new, native.uid, rename::LOG_LIMIT, stop)?;
        if new_log.original.is_some() {
            return Err(Reason::SourceChanged);
        }
        let logs = self.book.child(git, b"logs", false, stop)?;
        let head_log = self.rename_edge(logs, b"HEAD", native.uid, rename::LOG_LIMIT, stop)?;
        match (&old_log.original, &head_log.original) {
            (Some((_, a)), Some((_, b)))
                if review.logging
                    && a.sha256 == review.original_log
                    && b.sha256 == review.original_head_log =>
            {
                if !group_supported(a.identity, self.book.directory(log_parent)?)
                    || !group_supported(b.identity, self.book.directory(logs)?)
                {
                    return Err(Reason::SourceRefused);
                }
            }
            (None, None) if !review.logging => {}
            _ => return Err(Reason::SourceChanged),
        }
        {
            let state = self.rename.as_mut().ok_or(Reason::SourceChanged)?;
            state.branch_log = Some(old_log);
            state.new_log = Some(new_log);
            state.head_log = Some(head_log);
        }
        let before = self.rename_parent(parent, stop)?;
        if before.3 != native.uid || before.2 & 0o7022 != 0 {
            return Err(Reason::SourceRefused);
        }
        {
            let state = self.rename.as_mut().ok_or(Reason::SourceChanged)?;
            state.parent_before = Some(before);
            state.parent_current = Some(before);
        }
        for name in [old, new] {
            self.check_rename_locks(stop)?;
            let name = format!(
                "{}.lock",
                std::str::from_utf8(name).map_err(|_| Reason::SourceRefused)?
            );
            let index = self.book.reserve(Some(parent), name.as_bytes())?;
            self.rename
                .as_mut()
                .ok_or(Reason::SourceChanged)?
                .locks
                .push(RefLock {
                    index,
                    unlink_claimed: false,
                    unlinked: false,
                });
            self.book.slots[index].state = OriginalState::Acquiring;
            let opened = fcntl::openat(
                self.book.fd(parent)?,
                OsStr::from_bytes(name.as_bytes()),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            );
            self.book.adopt(index, opened)?; // Actual FD retained before checks/STOP.
            checkpoint(stop)?;
            let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
            let identity = file_identity(&held)?;
            self.book.slots[index].identity = Some(Identity::File(identity));
            let after = self.rename_parent(parent, stop)?;
            self.rename
                .as_mut()
                .ok_or(Reason::SourceChanged)?
                .parent_current = Some(after);
            if !rename::parent_transition(before, after)
                || identity.common.mode != 0o100600
                || identity.common.uid != native.uid
                || identity.nlink != 1
                || identity.size != 0
                || held.st_flags != 0
            {
                return Err(Reason::SourceChanged);
            }
            self.check_rename_locks(stop)?;
        }
        let state = self.rename.as_ref().ok_or(Reason::SourceChanged)?;
        let snapshot = |edge: &Option<Edge>| {
            edge.as_ref()
                .and_then(|e| e.original.as_ref())
                .map(|r| r.1.clone())
        };
        let identities = state
            .locks
            .iter()
            .map(|l| {
                stat::fstat(self.book.fd(l.index)?)
                    .map_err(|_| Reason::SourceChanged)
                    .and_then(|s| full(&s))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if identities.len() != 2 {
            return Err(Reason::SourceChanged);
        }
        let projection = rename::Sources {
            source_ref: review.branch.clone(),
            ref_locks: rename::RefLocks {
                source_identity: identities[0],
                target_identity: identities[1],
                parent_before: before,
                parent_locked: state.parent_current.ok_or(Reason::SourceChanged)?,
            },
            reference: snapshot(&state.source).ok_or(Reason::SourceChanged)?,
            branch_log: snapshot(&state.branch_log),
            head_log: snapshot(&state.head_log),
        };
        if !projection.valid(&native, &review) {
            return Err(Reason::SourceChanged);
        }
        self.rename
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .projection = Some(projection);
        Ok(())
    }
    pub(crate) fn rename_projection(&self) -> Result<Option<&rename::Sources>, Reason> {
        if self.finished || self.first.is_some() {
            return Err(Reason::SourceChanged);
        }
        self.rename
            .as_ref()
            .map(|s| s.projection.as_ref().ok_or(Reason::SourceChanged))
            .transpose()
    }
    fn check_rename_locks(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let state = self.rename.as_ref().ok_or(Reason::SourceChanged)?;
        let parent = state.source.as_ref().ok_or(Reason::SourceChanged)?.parent;
        // A missing expected parent and a failed original read are not a
        // match. Preserve the original error before any lock retirement.
        let expected_parent = state.parent_current.ok_or(Reason::SourceChanged)?;
        if self.rename_parent(parent, stop)? != expected_parent {
            return Err(Reason::SourceChanged);
        }
        for lock in &state.locks {
            if lock.unlink_claimed || lock.unlinked {
                return Err(Reason::CleanupUnknown);
            }
            let slot = &self.book.slots[lock.index];
            if matches!(
                slot.state,
                OriginalState::Reserved | OriginalState::NoHandle
            ) {
                continue;
            }
            let expected = match slot.identity {
                Some(Identity::File(v)) => v,
                _ => return Err(Reason::SourceChanged),
            };
            checkpoint(stop)?;
            let held = stat::fstat(self.book.fd(lock.index)?).map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            let named = stat::fstatat(
                self.book.fd(parent)?,
                OsStr::from_bytes(&slot.name),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if file_identity(&held)? != expected
                || file_identity(&named)? != expected
                || held.st_flags != 0
                || named.st_flags != 0
            {
                return Err(Reason::SourceChanged);
            }
        }
        Ok(())
    }
    pub(super) fn rename_is_old(&self, index: usize) -> bool {
        self.rename
            .as_ref()
            .is_some_and(|s| s.returned.iter().any(|r| r.old == Some(index)))
    }
    pub(super) fn rename_old_identity(
        &self,
        index: usize,
        held: &FileStat,
    ) -> Result<FileIdentity, Reason> {
        let receipt = self
            .rename
            .as_ref()
            .and_then(|s| s.returned.iter().find(|r| r.old == Some(index)))
            .ok_or(Reason::SourceChanged)?;
        let original = match self.book.slots[index].identity {
            Some(Identity::File(v)) => v,
            _ => return Err(Reason::SourceChanged),
        };
        let successor = match self.book.slots[receipt.successor].identity {
            Some(Identity::File(v)) => v,
            _ => return Err(Reason::SourceChanged),
        };
        let current = file_identity(held)?;
        if receipt.step == wire::Publication::RenameRefReturned {
            if held.st_flags != 0
                || receipt
                    .old_snapshot
                    .as_ref()
                    .is_none_or(|s| !rename::moved_original(s.identity, receipt.snapshot.identity))
                || current != successor
                || current.common != original.common
                || current.nlink != 1
                || current.size != original.size
                || current.mtime != original.mtime
            {
                return Err(Reason::SourceChanged);
            }
        } else if receipt.old_snapshot.is_none()
            || !unlinked_original(current, original, successor, held.st_flags as u64)
        {
            return Err(Reason::SourceChanged);
        }
        Ok(current)
    }
    pub(super) fn rename_snapshot_original(
        &self,
        index: usize,
        maximum: u64,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<wire::Snapshot, Reason> {
        let receipt = self
            .rename
            .as_ref()
            .and_then(|s| s.returned.iter().find(|r| r.old == Some(index)))
            .ok_or(Reason::SourceChanged)?;
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        let actual = self.rename_old_identity(index, &held)?;
        let hashed = self.snapshot_identity(index, actual, maximum, stop)?;
        let original = receipt.old_snapshot.as_ref().ok_or(Reason::SourceChanged)?;
        if hashed.sha256 != original.sha256 {
            return Err(Reason::SourceChanged);
        }
        Ok(original.clone())
    }
    fn rename_absent(&self, edge: &Edge, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        checkpoint(stop)?;
        if !matches!(
            stat::fstatat(
                self.book.fd(edge.parent)?,
                OsStr::from_bytes(&edge.name),
                AtFlags::AT_SYMLINK_NOFOLLOW
            ),
            Err(nix::errno::Errno::ENOENT)
        ) {
            return Err(Reason::SourceChanged);
        }
        checkpoint(stop)
    }
    pub(super) fn post_rename(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let Some(state) = &self.rename else {
            return Ok(());
        };
        self.check_rename_locks(stop)?;
        for edge in [
            &state.source,
            &state.target,
            &state.branch_log,
            &state.new_log,
            &state.head_log,
        ] {
            let edge = edge.as_ref().ok_or(Reason::SourceChanged)?;
            if let Some((index, snapshot)) = &edge.original {
                if self.snapshot_original(*index, edge.maximum, stop)? != *snapshot {
                    return Err(Reason::SourceChanged);
                }
                if state.returned.iter().any(|r| {
                    r.old == Some(*index)
                        && matches!(
                            r.step,
                            wire::Publication::RenameRefReturned
                                | wire::Publication::RenameOldLogReturned
                        )
                }) {
                    self.rename_absent(edge, stop)?;
                }
            } else if !state.returned.iter().any(|r| {
                self.book.slots[r.successor].parent == Some(edge.parent)
                    && self.book.slots[r.successor].name == edge.name
            }) {
                self.rename_absent(edge, stop)?;
            }
        }
        let packed = state.packed.as_ref().ok_or(Reason::SourceChanged)?;
        if let Some((index, snapshot)) = &packed.original {
            if self.snapshot(*index, 65536, stop)? != *snapshot {
                return Err(Reason::SourceChanged);
            }
        } else {
            self.rename_absent(packed, stop)?;
        }
        for r in &state.returned {
            if self.snapshot(r.successor, r.maximum, stop)? != r.snapshot {
                return Err(Reason::SourceChanged);
            }
        }
        self.check_rename_locks(stop)
    }
    fn rename_successor(
        &mut self,
        step: wire::Publication,
        parent: usize,
        name: &[u8],
        old: Option<(usize, wire::Snapshot)>,
        maximum: u64,
        expected: &str,
        mode: u32,
        group: u32,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let uid = self.native.as_ref().ok_or(Reason::SourceChanged)?.uid;
        let index = self.file(parent, name, uid, maximum, false, stop)?;
        let snapshot = self.snapshot(index, maximum, stop)?;
        if snapshot.sha256 != expected
            || snapshot.identity.2 != mode
            || snapshot.identity.4 != group
        {
            return Err(Reason::SourceChanged);
        }
        if step == wire::Publication::RenameRefReturned
            && old
                .as_ref()
                .is_none_or(|v| !rename::moved_original(v.1.identity, snapshot.identity))
        {
            return Err(Reason::SourceChanged);
        }
        let state = self.rename.as_mut().ok_or(Reason::SourceChanged)?;
        if state.returned.len() >= 6 {
            return Err(Reason::Capacity);
        }
        state.returned.push(Returned {
            step,
            old: old.as_ref().map(|v| v.0),
            old_snapshot: old.map(|v| v.1),
            successor: index,
            snapshot,
            maximum,
        });
        Ok(())
    }
    pub(super) fn rename_returned(
        &mut self,
        publication: &GitLocalPublication,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
        let review = self.review.as_ref().ok_or(Reason::SourceChanged)?;
        let state = self.rename.as_ref().ok_or(Reason::SourceChanged)?;
        if !state.returned.is_empty() {
            return Err(Reason::SourceChanged);
        }
        let (intent, marker) = publication.rename_for(
            self.operation_id.as_deref().ok_or(Reason::SourceChanged)?,
            native,
            review,
            state.projection.as_ref().ok_or(Reason::SourceChanged)?,
        )?;
        let intent = intent.clone();
        let steps = rename::steps(intent.logging, intent.config_moved);
        let last = steps
            .iter()
            .position(|v| *v == marker)
            .ok_or(Reason::SourceChanged)?;
        for step in &steps[..=last] {
            use wire::Publication::*;
            if *step == RenameOldLogReturned {
                let state = self.rename.as_ref().ok_or(Reason::SourceChanged)?;
                let old = state.branch_log.as_ref().ok_or(Reason::SourceChanged)?;
                self.rename_absent(old, stop)?;
                let (old, original) = old.original.clone().ok_or(Reason::SourceChanged)?;
                let new = state
                    .returned
                    .iter()
                    .find(|r| r.step == RenameNewLogReturned)
                    .ok_or(Reason::SourceChanged)?;
                let receipt = Returned {
                    step: *step,
                    old: Some(old),
                    old_snapshot: Some(original),
                    successor: new.successor,
                    snapshot: new.snapshot.clone(),
                    maximum: new.maximum,
                };
                self.rename
                    .as_mut()
                    .ok_or(Reason::SourceChanged)?
                    .returned
                    .push(receipt);
                continue;
            }
            let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
            let state = self.rename.as_ref().ok_or(Reason::SourceChanged)?;
            let (parent, name, original, maximum, expected, mode, group) = match *step {
                RenameNewLogReturned => {
                    let edge = state.new_log.as_ref().ok_or(Reason::SourceChanged)?;
                    let old = state
                        .branch_log
                        .as_ref()
                        .and_then(|e| e.original.as_ref())
                        .ok_or(Reason::SourceChanged)?;
                    (
                        edge.parent,
                        edge.name.clone(),
                        None,
                        rename::LOG_LIMIT,
                        intent.candidate_log.clone(),
                        old.1.identity.2,
                        old.1.identity.4,
                    )
                }
                RenameRefReturned => {
                    let source = state.source.as_ref().ok_or(Reason::SourceChanged)?;
                    let target = state.target.as_ref().ok_or(Reason::SourceChanged)?;
                    let old = source.original.clone().ok_or(Reason::SourceChanged)?;
                    let mode = old.1.identity.2;
                    let group = old.1.identity.4;
                    (
                        target.parent,
                        target.name.clone(),
                        Some(old),
                        65,
                        rename::hash(format!("{}\n", intent.expected_head).as_bytes()),
                        mode,
                        group,
                    )
                }
                RenameHeadLogReturned => {
                    let edge = state.head_log.as_ref().ok_or(Reason::SourceChanged)?;
                    let old = edge.original.clone().ok_or(Reason::SourceChanged)?;
                    let mode = old.1.identity.2;
                    let group = old.1.identity.4;
                    (
                        edge.parent,
                        edge.name.clone(),
                        Some(old),
                        rename::LOG_LIMIT,
                        intent.candidate_head_log.clone(),
                        mode,
                        group,
                    )
                }
                RenameHeadReturned => (
                    self.git.ok_or(Reason::SourceChanged)?,
                    b"HEAD".to_vec(),
                    Some((
                        self.indices[1].ok_or(Reason::SourceChanged)?,
                        native.files.head.clone(),
                    )),
                    2048,
                    rename::hash(format!("ref: {}\n", intent.target_ref).as_bytes()),
                    native.files.head.identity.2,
                    native.files.head.identity.4,
                ),
                RenameConfigReturned => (
                    self.git.ok_or(Reason::SourceChanged)?,
                    b"config".to_vec(),
                    Some((
                        self.indices[2].ok_or(Reason::SourceChanged)?,
                        native.files.config.clone(),
                    )),
                    rename::CONFIG_LIMIT,
                    intent.candidate_config.clone(),
                    native.files.config.identity.2,
                    native.files.config.identity.4,
                ),
                _ => return Err(Reason::SourceChanged),
            };
            self.rename_successor(
                *step, parent, &name, original, maximum, &expected, mode, group, stop,
            )?;
            if *step == RenameRefReturned {
                let source = self
                    .rename
                    .as_ref()
                    .and_then(|s| s.source.as_ref())
                    .ok_or(Reason::SourceChanged)?;
                self.rename_absent(source, stop)?;
                let current = self.rename_parent(source.parent, stop)?;
                if !self
                    .rename
                    .as_ref()
                    .and_then(|s| s.parent_current)
                    .is_some_and(|before| rename::parent_transition(before, current))
                {
                    return Err(Reason::SourceChanged);
                }
                self.rename
                    .as_mut()
                    .ok_or(Reason::SourceChanged)?
                    .parent_current = Some(current);
            }
        }
        Ok(())
    }
    pub(super) fn close_rename_book(
        &mut self,
        expired: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool,
    ) -> bool {
        let Some(state) = self.rename.as_ref() else {
            return self.close_switch_book(expired);
        };
        if state.locks.is_empty() {
            return self.book.close_all();
        }
        let Some(parent) = state.source.as_ref().map(|e| e.parent) else {
            return false;
        };
        let first = self.first_failure();
        if expired(first) || self.check_rename_locks(&mut || expired(first)).is_err() {
            return false;
        }
        let indices: Vec<_> = state.locks.iter().map(|l| l.index).collect();
        let mut known = true;
        for at in (0..self.book.slots.len()).rev() {
            if at != parent && !indices.contains(&at) {
                if expired(first) {
                    known = false;
                    break;
                }
                known = SourceBook::close_slot(&mut self.book.slots[at], &mut |_| {
                    expired(Some((Failure::Unknown, Instant::now())));
                }) && known;
            }
        }
        if !known || expired(first) || self.check_rename_locks(&mut || expired(first)).is_err() {
            return false;
        }
        for position in (0..indices.len()).rev() {
            let index = indices[position];
            if matches!(
                self.book.slots[index].state,
                OriginalState::NoHandle | OriginalState::Reserved
            ) {
                if !SourceBook::close_slot(&mut self.book.slots[index], &mut |_| {
                    expired(Some((Failure::Unknown, Instant::now())));
                }) {
                    return false;
                }
                continue;
            }
            let before = match self.rename.as_ref().and_then(|s| s.parent_current) {
                Some(v) => v,
                None => return false,
            };
            self.rename.as_mut().unwrap().locks[position].unlink_claimed = true;
            let removed = match self.book.fd(parent) {
                Ok(fd) => unistd::unlinkat(
                    fd,
                    OsStr::from_bytes(&self.book.slots[index].name),
                    unistd::UnlinkatFlags::NoRemoveDir,
                )
                .is_ok(),
                Err(_) => false,
            };
            if !removed || expired(first) {
                return false;
            }
            let after = match self.rename_parent(parent, &mut || expired(first)) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let absent = match self.book.fd(parent) {
                Ok(fd) => matches!(
                    stat::fstatat(
                        fd,
                        OsStr::from_bytes(&self.book.slots[index].name),
                        AtFlags::AT_SYMLINK_NOFOLLOW
                    ),
                    Err(nix::errno::Errno::ENOENT)
                ),
                Err(_) => false,
            };
            if !rename::parent_transition(before, after)
                || !absent
                || expired(first)
                || self.rename_parent(parent, &mut || expired(first)).ok() != Some(after)
            {
                return false;
            }
            {
                let state = self.rename.as_mut().unwrap();
                state.locks[position].unlinked = true;
                state.parent_current = Some(after);
            }
            if !SourceBook::close_slot(&mut self.book.slots[index], &mut |_| {
                expired(Some((Failure::Unknown, Instant::now())));
            }) {
                return false;
            }
            // The other still-held original is rechecked without accepting a
            // repeat of the already-consumed unlink. No vector/slot reset.
            for earlier in &indices[..position] {
                let slot = &self.book.slots[*earlier];
                if matches!(
                    slot.state,
                    OriginalState::Reserved | OriginalState::NoHandle
                ) {
                    continue;
                }
                let held = match self
                    .book
                    .fd(*earlier)
                    .and_then(|fd| stat::fstat(fd).map_err(|_| Reason::SourceChanged))
                {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let named = match self.book.fd(parent).and_then(|fd| {
                    stat::fstatat(
                        fd,
                        OsStr::from_bytes(&slot.name),
                        AtFlags::AT_SYMLINK_NOFOLLOW,
                    )
                    .map_err(|_| Reason::SourceChanged)
                }) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                if !matches!(slot.identity,Some(Identity::File(v)) if file_identity(&held).ok()==Some(v)&&file_identity(&named).ok()==Some(v))
                    || held.st_flags != 0
                    || named.st_flags != 0
                    || expired(first)
                {
                    return false;
                }
            }
        }
        if expired(first)
            || !SourceBook::close_slot(&mut self.book.slots[parent], &mut |_| {
                expired(Some((Failure::Unknown, Instant::now())));
            })
        {
            return false;
        }
        self.book.terminal = true;
        !expired(first) && self.book.settled()
    }
}

#[cfg(test)]
#[path = "git_rename_source_tests.rs"]
mod tests;
