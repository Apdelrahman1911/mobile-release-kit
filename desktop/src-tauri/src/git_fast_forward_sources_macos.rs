//! Fast-forward-only facet of the SAME GitLocalSources/SourceBook. No new native
//! owner/executor, caller FD, command runner or generic destination publisher.
//! Its one target-ref lock is held until all other original source closes are
//! known, then exact unlink/postcheck/one final FD close. Ambiguity is retained.
use super::*;
use crate::{git_fast_forward_protocol as forward, git_switch_protocol as switch};

struct Edge {
    parent: usize,
    name: Vec<u8>,
    original: Option<(usize, wire::Snapshot)>,
    maximum: u64,
}
struct Returned {
    old: Option<usize>,
    old_snapshot: Option<wire::Snapshot>,
    successor: usize,
    snapshot: wire::Snapshot,
    maximum: u64,
    appended: bool,
}
pub(super) struct State {
    target: Option<Edge>,
    reference: Option<Edge>,
    files: Vec<Edge>,
    log: Option<Edge>,
    branch_log: Option<Edge>,
    lock: Option<usize>,
    parent_before: Option<wire::FileIdentity>,
    parent_locked: Option<wire::FileIdentity>,
    projection: Option<forward::Sources>,
    returned: Vec<Returned>,
    log_tail: Option<Vec<u8>>,
    unlink_claimed: bool,
    unlinked: bool,
}
impl State {
    fn new() -> Result<Self, Reason> {
        let mut files = Vec::new();
        files
            .try_reserve_exact(switch::MAX_FILES)
            .map_err(|_| Reason::Capacity)?;
        let mut returned = Vec::new();
        returned
            .try_reserve_exact(switch::MAX_FILES + 4)
            .map_err(|_| Reason::Capacity)?;
        if files.capacity() > switch::MAX_FILES || returned.capacity() > switch::MAX_FILES + 4 {
            return Err(Reason::Capacity);
        }
        Ok(Self {
            target: None,
            reference: None,
            files,
            log: None,
            branch_log: None,
            lock: None,
            parent_before: None,
            parent_locked: None,
            projection: None,
            returned,
            log_tail: None,
            unlink_claimed: false,
            unlinked: false,
        })
    }
    pub(super) fn working_bytes() -> Option<usize> {
        // SourceBook's unchanged 128-slot ceiling is already charged by its
        // parent. Additional fixed wrappers, paths/snapshots and compare copy.
        std::mem::size_of::<Self>()
            .checked_add((switch::MAX_FILES + 5) * (PATH_LIMIT + 2048))?
            .checked_add((switch::MAX_FILES + 4) * std::mem::size_of::<Returned>())?
            .checked_add(switch::MAX_FILES * std::mem::size_of::<Edge>())?
            .checked_add(65536 + 2048)
    }
    pub(super) fn extra(review: Option<&wire::Review>) -> Option<usize> {
        let Some(review) = review.and_then(wire::Review::fast_forward_details) else {
            return Some(0);
        };
        // Existing physical parents only; over-capacity is a pre-effect
        // refusal. No credit for aliases/duplicate parents or future closes.
        let paths = review
            .files
            .iter()
            .try_fold(0usize, |n, f| n.checked_add(f.path.split('/').count()))?;
        paths
            .checked_add(review.target_ref.split('/').count())?
            .checked_add(review.branch.split('/').count().checked_mul(2)?)?
            .checked_add(switch::MAX_FILES + 20)
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
    switch::replacement_group(
        original,
        (parent.dev, parent.ino, parent.mode, parent.uid, parent.gid),
    )
}
// The real worker has already checked its exact configured identity and
// fixed OLD->TARGET CAS. Native independently checks the original log prefix,
// one fixed-message append and both actual log tails, never fabricating one.
fn appended_tail<'a>(
    bytes: &'a [u8],
    original_size: usize,
    original_hash: &str,
    head: &str,
    target: &str,
) -> Option<&'a [u8]> {
    if bytes.len() > 65536
        || original_size > bytes.len()
        || switch::hash(&bytes[..original_size]) != original_hash
    {
        return None;
    }
    let tail = &bytes[original_size..];
    if tail.len() > 2048 {
        return None;
    }
    let text = std::str::from_utf8(tail).ok()?;
    let prefix = format!("{head} {target} ");
    let body = text
        .strip_prefix(&prefix)?
        .strip_suffix(&format!("\t{}\n", forward::MESSAGE))?;
    if body.chars().any(char::is_control) {
        return None;
    }
    let (who_time, zone) = body.rsplit_once(' ')?;
    if zone.len() != 5
        || !matches!(zone.as_bytes()[0], b'+' | b'-')
        || !zone[1..].bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let (who, time) = who_time.rsplit_once(' ')?;
    if time.is_empty() || time.len() > 12 || !time.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (name, email) = who.strip_suffix('>')?.rsplit_once(" <")?;
    if name.trim().is_empty() || email.is_empty() || email.contains(['<', '>']) {
        return None;
    }
    Some(tail)
}
impl GitLocalSources {
    pub(crate) fn retain_fast_forward_unknown(&mut self) {
        // Classification may only become more conservative. The original
        // Supervisor/ACL first-failure clocks remain untouched; retaining a
        // prior SourceChanged label here must not let close drop this lock.
        self.first = Some(Reason::CleanupUnknown);
        self.close_failed = true;
    }
    fn fast_forward_edge(
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
    fn fast_forward_parent(
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
    pub(super) fn capture_fast_forward(
        &mut self,
        project: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if self.fast_forward.is_some() {
            return Err(Reason::SourceChanged);
        }
        let review = self
            .review
            .as_ref()
            .and_then(wire::Review::fast_forward_details)
            .filter(|r| r.valid())
            .ok_or(Reason::SourceRefused)?
            .clone();
        let native = self.native.as_ref().ok_or(Reason::SourceRefused)?.clone();
        if native.files.head.sha256 != switch::hash(format!("ref: {}\n", review.branch).as_bytes())
            || !native.files.index.as_ref().is_some_and(|s| {
                s.sha256 == review.expected_index && s.identity.6 <= switch::INDEX_LIMIT
            })
        {
            return Err(Reason::SourceChanged);
        }
        self.fast_forward = Some(State::new()?); // Retained before lock acquisition/effects.
        let git = self.git.ok_or(Reason::SourceChanged)?;
        let git_parent = self.book.directory(git)?;
        if !native
            .files
            .index
            .as_ref()
            .is_some_and(|s| group_supported(s.identity, git_parent))
        {
            return Err(Reason::SourceRefused);
        }
        let components: Vec<_> = review.target_ref.split('/').collect();
        let mut parent = git;
        for name in &components[..components.len() - 1] {
            parent = self.book.child(parent, name.as_bytes(), false, stop)?;
        }
        let leaf = components.last().ok_or(Reason::SourceRefused)?.as_bytes();
        let edge = self.fast_forward_edge(parent, leaf, native.uid, 65, stop)?;
        if !edge.original.as_ref().is_some_and(|(_, v)| {
            v.sha256 == switch::hash(format!("{}\n", review.target_oid).as_bytes())
        }) {
            return Err(Reason::SourceChanged); // This first slice never resolves/adopts a packed target.
        }
        self.fast_forward
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .target = Some(edge);
        let ref_parts: Vec<_> = review.branch.split('/').collect();
        let mut ref_parent = git;
        for name in &ref_parts[..ref_parts.len() - 1] {
            ref_parent = self.book.child(ref_parent, name.as_bytes(), false, stop)?;
        }
        let reference = self.fast_forward_edge(
            ref_parent,
            ref_parts.last().ok_or(Reason::SourceRefused)?.as_bytes(),
            native.uid,
            65,
            stop,
        )?;
        let ref_parent_identity = self.book.directory(ref_parent)?;
        if !reference.original.as_ref().is_some_and(|(_, v)| {
            v.sha256 == switch::hash(format!("{}\n", review.head).as_bytes())
                && group_supported(v.identity, ref_parent_identity)
        }) {
            return Err(Reason::SourceChanged);
        }
        self.fast_forward
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .reference = Some(reference);
        for selected in &review.files {
            let parts: Vec<_> = selected.path.split('/').collect();
            let mut parent = project;
            for name in &parts[..parts.len() - 1] {
                parent = self.book.child(parent, name.as_bytes(), false, stop)?;
            }
            let edge = self.fast_forward_edge(
                parent,
                parts.last().ok_or(Reason::SourceRefused)?.as_bytes(),
                native.uid,
                switch::FILE_LIMIT,
                stop,
            )?;
            let (_, snapshot) = edge.original.as_ref().ok_or(Reason::SourceChanged)?;
            if snapshot.sha256 != selected.source_sha256
                || snapshot.identity.2 != selected.mode_bits()
            {
                return Err(Reason::SourceChanged);
            }
            if !group_supported(snapshot.identity, self.book.directory(parent)?) {
                return Err(Reason::SourceRefused);
            }
            let state = self.fast_forward.as_mut().ok_or(Reason::SourceChanged)?;
            if state.files.len() >= switch::MAX_FILES {
                return Err(Reason::Capacity);
            }
            state.files.push(edge);
        }
        let logs = self.book.child(git, b"logs", false, stop)?;
        let log = self.fast_forward_edge(logs, b"HEAD", native.uid, switch::LOG_LIMIT, stop)?;
        match (&log.original, review.head_log.original_kind.as_str()) {
            (Some((_, s)), "file") if s.sha256 == review.head_log.original_sha256 => {}
            (None, "absent") => {}
            _ => return Err(Reason::SourceChanged),
        }
        let log_parent = self.book.directory(logs)?;
        if log
            .original
            .as_ref()
            .is_some_and(|(_, s)| !group_supported(s.identity, log_parent))
        {
            return Err(Reason::SourceRefused);
        }
        self.fast_forward.as_mut().ok_or(Reason::SourceChanged)?.log = Some(log);
        let mut branch_parent = logs;
        for name in &ref_parts[..ref_parts.len() - 1] {
            branch_parent = self
                .book
                .child(branch_parent, name.as_bytes(), false, stop)?;
        }
        let branch_log = self.fast_forward_edge(
            branch_parent,
            ref_parts.last().ok_or(Reason::SourceRefused)?.as_bytes(),
            native.uid,
            switch::LOG_LIMIT,
            stop,
        )?;
        match (
            &branch_log.original,
            review.branch_log.original_kind.as_str(),
        ) {
            (Some((_, s)), "file") if s.sha256 == review.branch_log.original_sha256 => {}
            (None, "absent") => {}
            _ => return Err(Reason::SourceChanged),
        }
        let log_parent_identity = self.book.directory(branch_parent)?;
        if branch_log
            .original
            .as_ref()
            .is_some_and(|(_, s)| !group_supported(s.identity, log_parent_identity))
        {
            return Err(Reason::SourceRefused);
        }
        self.fast_forward
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .branch_log = Some(branch_log);
        // Actual exclusive lock on the exact admitted target parent. No Git
        // command will be asked to acquire this lock, and Python cannot own it.
        let before = self.fast_forward_parent(parent, stop)?;
        if before.3 != native.uid || before.2 & 0o7022 != 0 {
            return Err(Reason::SourceRefused);
        }
        self.fast_forward
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .parent_before = Some(before);
        let name = format!(
            "{}.lock",
            std::str::from_utf8(leaf).map_err(|_| Reason::SourceRefused)?
        );
        let index = self.book.reserve(Some(parent), name.as_bytes())?;
        self.fast_forward
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .lock = Some(index);
        self.book.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::openat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name.as_bytes()),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        );
        self.book.adopt(index, opened)?; // Actual returned FD retained before any check/STOP.
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        let identity = file_identity(&held)?;
        self.book.slots[index].identity = Some(Identity::File(identity));
        checkpoint(stop)?;
        let after = self.fast_forward_parent(parent, stop)?;
        self.fast_forward
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .parent_locked = Some(after);
        if !switch::parent_transition(before, after)
            || identity.common.mode != 0o100600
            || identity.common.uid != native.uid
            || identity.nlink != 1
            || identity.size != 0
            || held.st_flags != 0
        {
            return Err(Reason::SourceChanged);
        }
        self.check_fast_forward_lock(stop)?;
        let state = self.fast_forward.as_ref().ok_or(Reason::SourceChanged)?;
        let mut files = Vec::new();
        files
            .try_reserve_exact(review.files.len())
            .map_err(|_| Reason::Capacity)?;
        if files.capacity() > switch::MAX_FILES {
            return Err(Reason::Capacity);
        }
        for (row, edge) in review.files.iter().zip(&state.files) {
            files.push(switch::NamedSnapshot {
                path: row.path.clone(),
                snapshot: edge
                    .original
                    .as_ref()
                    .ok_or(Reason::SourceChanged)?
                    .1
                    .clone(),
            });
        }
        let projection = forward::Sources {
            target_lock: switch::TargetLock {
                identity: full(&held)?,
                parent_before: before,
                parent_locked: after,
            },
            head_log: state
                .log
                .as_ref()
                .ok_or(Reason::SourceChanged)?
                .original
                .as_ref()
                .map(|v| v.1.clone()),
            branch_log: state
                .branch_log
                .as_ref()
                .ok_or(Reason::SourceChanged)?
                .original
                .as_ref()
                .map(|v| v.1.clone()),
            current_ref: switch::NamedSnapshot {
                path: review.branch.clone(),
                snapshot: state
                    .reference
                    .as_ref()
                    .and_then(|e| e.original.as_ref())
                    .ok_or(Reason::SourceChanged)?
                    .1
                    .clone(),
            },
            files,
        };
        if !projection.valid(&native, &review) {
            return Err(Reason::SourceChanged);
        }
        self.fast_forward
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .projection = Some(projection);
        Ok(())
    }
    pub(crate) fn fast_forward_projection(&self) -> Result<Option<&forward::Sources>, Reason> {
        if self.finished || self.first.is_some() {
            return Err(Reason::SourceChanged);
        }
        self.fast_forward
            .as_ref()
            .map(|s| s.projection.as_ref().ok_or(Reason::SourceChanged))
            .transpose()
    }
    fn check_fast_forward_lock(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let state = self.fast_forward.as_ref().ok_or(Reason::SourceChanged)?;
        let index = state.lock.ok_or(Reason::SourceChanged)?;
        let parent = state.target.as_ref().ok_or(Reason::SourceChanged)?.parent;
        if state.unlink_claimed || state.unlinked {
            return Err(Reason::CleanupUnknown);
        }
        let expected = match self.book.slots[index].identity {
            Some(Identity::File(v)) => v,
            _ => return Err(Reason::SourceChanged),
        };
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let named = stat::fstatat(
            self.book.fd(parent)?,
            OsStr::from_bytes(&self.book.slots[index].name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if expected != file_identity(&held)?
            || expected != file_identity(&named)?
            || held.st_flags != 0
            || named.st_flags != 0
            || Some(self.fast_forward_parent(parent, stop)?) != state.parent_locked
        {
            return Err(Reason::SourceChanged);
        }
        Ok(())
    }
    pub(super) fn fast_forward_is_old(&self, index: usize) -> bool {
        self.fast_forward
            .as_ref()
            .is_some_and(|s| s.returned.iter().any(|r| r.old == Some(index)))
    }
    pub(super) fn fast_forward_old_identity(
        &self,
        index: usize,
        held: &FileStat,
    ) -> Result<FileIdentity, Reason> {
        let state = self.fast_forward.as_ref().ok_or(Reason::SourceChanged)?;
        let receipt = state
            .returned
            .iter()
            .find(|r| r.old == Some(index))
            .ok_or(Reason::SourceChanged)?;
        let original = match self.book.slots[index].identity {
            Some(Identity::File(v)) => v,
            _ => return Err(Reason::SourceChanged),
        };
        let successor = match self.book.slots[receipt.successor].identity {
            Some(Identity::File(v)) => v,
            _ => return Err(Reason::SourceChanged),
        };
        let actual = file_identity(held)?;
        let known = if receipt.appended {
            actual == successor
                && actual.common == original.common
                && actual.nlink == 1
                && actual.size >= original.size
                && held.st_flags == 0
        } else {
            unlinked_original(actual, original, successor, held.st_flags as u64)
        };
        if receipt.old_snapshot.is_none() || !known {
            return Err(Reason::SourceChanged);
        }
        Ok(actual)
    }
    pub(super) fn fast_forward_snapshot_original(
        &self,
        index: usize,
        maximum: u64,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<wire::Snapshot, Reason> {
        let receipt = self
            .fast_forward
            .as_ref()
            .and_then(|s| s.returned.iter().find(|r| r.old == Some(index)))
            .ok_or(Reason::SourceChanged)?;
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        let actual = self.fast_forward_old_identity(index, &held)?;
        let expected = receipt.old_snapshot.as_ref().ok_or(Reason::SourceChanged)?;
        if receipt.appended {
            let bytes = self.fast_forward_read(index, actual, maximum, stop)?;
            if bytes.len() < expected.identity.6 as usize
                || switch::hash(&bytes[..expected.identity.6 as usize]) != expected.sha256
                || switch::hash(&bytes) != receipt.snapshot.sha256
            {
                return Err(Reason::SourceChanged);
            }
        } else if self.snapshot_identity(index, actual, maximum, stop)?.sha256 != expected.sha256 {
            return Err(Reason::SourceChanged);
        }
        Ok(expected.clone()) // DATA only; actual original slot/FD never replaced.
    }
    fn check_fast_forward_edge(
        &self,
        edge: &Edge,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if let Some((index, original)) = &edge.original {
            if self.snapshot_original(*index, edge.maximum, stop)? != *original {
                return Err(Reason::SourceChanged);
            }
        } else if !self.fast_forward.as_ref().is_some_and(|s| {
            s.returned.iter().any(|r| {
                r.old.is_none()
                    && self.book.slots[r.successor].parent == Some(edge.parent)
                    && self.book.slots[r.successor].name == edge.name
            })
        }) {
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
            checkpoint(stop)?;
        }
        Ok(())
    }
    pub(super) fn post_fast_forward(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let Some(state) = &self.fast_forward else {
            return Ok(());
        };
        self.check_fast_forward_lock(stop)?;
        self.check_fast_forward_edge(state.target.as_ref().ok_or(Reason::SourceChanged)?, stop)?;
        self.check_fast_forward_edge(state.reference.as_ref().ok_or(Reason::SourceChanged)?, stop)?;
        for edge in &state.files {
            self.check_fast_forward_edge(edge, stop)?;
        }
        self.check_fast_forward_edge(state.log.as_ref().ok_or(Reason::SourceChanged)?, stop)?;
        self.check_fast_forward_edge(
            state.branch_log.as_ref().ok_or(Reason::SourceChanged)?,
            stop,
        )?;
        for receipt in &state.returned {
            if self.snapshot(receipt.successor, receipt.maximum, stop)? != receipt.snapshot {
                return Err(Reason::SourceChanged);
            }
        }
        self.check_fast_forward_lock(stop)
    }
    fn fast_forward_successor(
        &mut self,
        parent: usize,
        name: &[u8],
        old: Option<(usize, wire::Snapshot)>,
        maximum: u64,
        expected: &str,
        size: Option<u64>,
        mode: Option<u32>,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let uid = self.native.as_ref().ok_or(Reason::SourceChanged)?.uid;
        let index = self.file(parent, name, uid, maximum, false, stop)?;
        let snapshot = self.snapshot(index, maximum, stop)?;
        let group = old
            .as_ref()
            .map(|v| v.1.identity.4)
            .unwrap_or(self.book.directory(parent)?.gid);
        if snapshot.sha256 != expected
            || snapshot.identity.4 != group
            || size.is_some_and(|s| s != snapshot.identity.6)
            || mode.is_some_and(|m| m != snapshot.identity.2)
        {
            return Err(Reason::SourceChanged);
        }
        let state = self.fast_forward.as_mut().ok_or(Reason::SourceChanged)?;
        if state.returned.len() >= switch::MAX_FILES + 4 {
            return Err(Reason::Capacity);
        }
        state.returned.push(Returned {
            old: old.as_ref().map(|v| v.0),
            old_snapshot: old.map(|v| v.1),
            successor: index,
            snapshot,
            maximum,
            appended: false,
        });
        Ok(())
    }
    // All bounded reads use the SAME actual SourceBook descriptor. A failed
    // read is not a new named open/second source, and one-close custody remains.
    fn fast_forward_read(
        &self,
        index: usize,
        expected: FileIdentity,
        maximum: u64,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, Reason> {
        checkpoint(stop)?;
        if expected.size > maximum || maximum > 65536 {
            return Err(Reason::Capacity);
        }
        let size = usize::try_from(expected.size).map_err(|_| Reason::Capacity)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(size)
            .map_err(|_| Reason::Capacity)?;
        if bytes.capacity() > 65536 {
            return Err(Reason::Capacity);
        }
        bytes.resize(size, 0);
        let fd = self.book.fd(index)?;
        if file_identity(&stat::fstat(fd).map_err(|_| Reason::SourceChanged)?)? != expected {
            return Err(Reason::SourceChanged);
        }
        unistd::lseek(fd, 0, unistd::Whence::SeekSet).map_err(|_| Reason::SourceChanged)?;
        let mut at = 0;
        while at < size {
            checkpoint(stop)?;
            let n = unistd::read(fd, &mut bytes[at..]).map_err(|_| Reason::SourceChanged)?;
            if n == 0 {
                return Err(Reason::SourceChanged);
            }
            at += n;
        }
        let mut end = [0u8; 1];
        checkpoint(stop)?;
        if unistd::read(fd, &mut end).map_err(|_| Reason::SourceChanged)? != 0
            || file_identity(&stat::fstat(fd).map_err(|_| Reason::SourceChanged)?)? != expected
        {
            return Err(Reason::SourceChanged);
        }
        checkpoint(stop)?;
        Ok(bytes)
    }
    fn fast_forward_log_returned(
        &mut self,
        branch: bool,
        intent: &forward::Intent,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let state = self.fast_forward.as_ref().ok_or(Reason::SourceChanged)?;
        let edge = if branch {
            state.branch_log.as_ref()
        } else {
            state.log.as_ref()
        }
        .ok_or(Reason::SourceChanged)?;
        let (parent, name, old) = (edge.parent, edge.name.clone(), edge.original.clone());
        let uid = self.native.as_ref().ok_or(Reason::SourceChanged)?.uid;
        let index = self.file(parent, &name, uid, 65536, false, stop)?;
        let snapshot = self.snapshot(index, 65536, stop)?;
        let identity = match self.book.slots[index].identity {
            Some(Identity::File(v)) => v,
            _ => return Err(Reason::SourceChanged),
        };
        let mode = old.as_ref().map(|v| v.1.identity.2).unwrap_or(0o100644);
        let group = old
            .as_ref()
            .map(|v| v.1.identity.4)
            .unwrap_or(self.book.directory(parent)?.gid);
        if snapshot.identity.2 != mode || snapshot.identity.4 != group {
            return Err(Reason::SourceChanged);
        }
        let bytes = self.fast_forward_read(index, identity, 65536, stop)?;
        let old_size = old.as_ref().map(|v| v.1.identity.6).unwrap_or(0);
        let old_hash = if branch {
            &intent.original_branch_log
        } else {
            &intent.original_head_log
        };
        // Absent stamp uses the core's fixed absent digest, not hash(empty).
        let prefix_hash = if old.is_some() {
            old_hash.clone()
        } else {
            switch::hash(b"")
        };
        let tail = appended_tail(
            &bytes,
            old_size as usize,
            &prefix_hash,
            &intent.expected_head,
            &intent.target_oid,
        )
        .ok_or(Reason::SourceChanged)?;
        let state = self.fast_forward.as_mut().ok_or(Reason::SourceChanged)?;
        if state
            .log_tail
            .as_ref()
            .is_some_and(|v| v.as_slice() != tail)
        {
            return Err(Reason::SourceChanged);
        }
        if state.log_tail.is_none() {
            let mut copy = Vec::new();
            copy.try_reserve_exact(tail.len())
                .map_err(|_| Reason::Capacity)?;
            if copy.capacity() > 2048 {
                return Err(Reason::Capacity);
            }
            copy.extend_from_slice(tail);
            state.log_tail = Some(copy);
        }
        if state.returned.len() >= switch::MAX_FILES + 4 {
            return Err(Reason::Capacity);
        }
        let appended = old.as_ref().is_some_and(|(_, v)| {
            v.identity.0 == snapshot.identity.0 && v.identity.1 == snapshot.identity.1
        });
        state.returned.push(Returned {
            old: old.as_ref().map(|v| v.0),
            old_snapshot: old.map(|v| v.1),
            successor: index,
            snapshot,
            maximum: 65536,
            appended,
        });
        Ok(())
    }
    pub(super) fn fast_forward_returned(
        &mut self,
        publication: &GitLocalPublication,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
        let review = self.review.as_ref().ok_or(Reason::SourceChanged)?;
        let state = self.fast_forward.as_ref().ok_or(Reason::SourceChanged)?;
        if !state.returned.is_empty() {
            return Err(Reason::SourceChanged);
        }
        let (intent, marker) = publication.fast_forward_for(
            self.operation_id.as_deref().ok_or(Reason::SourceChanged)?,
            native,
            review,
            state.projection.as_ref().ok_or(Reason::SourceChanged)?,
        )?;
        let intent = intent.clone();
        let review = review
            .fast_forward_details()
            .ok_or(Reason::SourceChanged)?
            .clone();
        if !matches!(
            marker,
            wire::Publication::FfWorktreeReturned
                | wire::Publication::FfIndexReturned
                | wire::Publication::FfRefReturned
        ) {
            return Err(Reason::SourceChanged);
        }
        for (at, file) in review.files.iter().enumerate() {
            let edge = &self
                .fast_forward
                .as_ref()
                .ok_or(Reason::SourceChanged)?
                .files[at];
            let (parent, name, original) = (edge.parent, edge.name.clone(), edge.original.clone());
            self.fast_forward_successor(
                parent,
                &name,
                original,
                switch::FILE_LIMIT,
                &file.target_sha256,
                Some(file.target_size),
                Some(file.mode_bits()),
                stop,
            )?;
        }
        if matches!(
            marker,
            wire::Publication::FfIndexReturned | wire::Publication::FfRefReturned
        ) {
            let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
            let original = native.files.index.clone().ok_or(Reason::SourceChanged)?;
            let mode = original.identity.2;
            self.fast_forward_successor(
                self.git.ok_or(Reason::SourceChanged)?,
                b"index",
                Some((self.indices[3].ok_or(Reason::SourceChanged)?, original)),
                switch::INDEX_LIMIT,
                &intent.candidate_index,
                None,
                Some(mode),
                stop,
            )?;
        }
        if marker == wire::Publication::FfRefReturned {
            let edge = self
                .fast_forward
                .as_ref()
                .and_then(|s| s.reference.as_ref())
                .ok_or(Reason::SourceChanged)?;
            let (parent, name, old) = (edge.parent, edge.name.clone(), edge.original.clone());
            let mode = old.as_ref().ok_or(Reason::SourceChanged)?.1.identity.2;
            let bytes = format!("{}\n", intent.target_oid);
            self.fast_forward_successor(
                parent,
                &name,
                old,
                65,
                &switch::hash(bytes.as_bytes()),
                Some(bytes.len() as u64),
                Some(mode),
                stop,
            )?;
            if intent.head_log_enabled {
                self.fast_forward_log_returned(false, &intent, stop)?;
            }
            if intent.branch_log_enabled {
                self.fast_forward_log_returned(true, &intent, stop)?;
            }
        }
        Ok(())
    }
    pub(super) fn close_fast_forward_book(
        &mut self,
        expired: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool,
    ) -> bool {
        let Some(state) = self.fast_forward.as_ref() else {
            return self.close_rename_book(expired);
        };
        let Some(index) = state.lock else {
            return self.book.close_all();
        };
        if self.book.slots[index].state == OriginalState::NoHandle {
            return self.book.close_all();
        }
        let Some(parent) = state.target.as_ref().map(|t| t.parent) else {
            return false;
        };
        let first = self.first_failure();
        if expired(first)
            || self
                .check_fast_forward_lock(&mut || expired(first))
                .is_err()
        {
            return false;
        }
        // SAME slots and one-attempt close helper; no moved-out descriptors,
        // substitute Book, vector reset or synthetic prior-close success.
        let mut known = true;
        for at in (0..self.book.slots.len()).rev() {
            if at != index && at != parent {
                if expired(first) {
                    known = false;
                    break;
                }
                known = SourceBook::close_slot(&mut self.book.slots[at], &mut |_| {
                    // Report to the SAME original failure/cleanup clock. No
                    // fresh timer or later retry window is introduced here.
                    expired(Some((Failure::Unknown, Instant::now())));
                }) && known;
            }
        }
        if !known
            || expired(first)
            || self
                .check_fast_forward_lock(&mut || expired(first))
                .is_err()
        {
            return false;
        }
        let Some(before) = self.fast_forward.as_ref().and_then(|s| s.parent_locked) else {
            return false;
        };
        self.fast_forward.as_mut().unwrap().unlink_claimed = true; // Retire BEFORE sole consuming unlink.
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
        let after = match self.fast_forward_parent(parent, &mut || expired(first)) {
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
        if !switch::parent_transition(before, after)
            || !absent
            || expired(first)
            || self
                .fast_forward_parent(parent, &mut || expired(first))
                .ok()
                != Some(after)
        {
            return false;
        }
        self.fast_forward.as_mut().unwrap().unlinked = true;
        // Missing/uncertain post-unlink observation above keeps these ORIGINAL
        // FDs held. A close ambiguity below is never retried or called success.
        if !SourceBook::close_slot(&mut self.book.slots[index], &mut |_| {
            expired(Some((Failure::Unknown, Instant::now())));
        }) {
            return false;
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
mod tests {
    use super::*;
    #[test]
    fn actual_append_comparison_requires_same_prefix_one_fixed_message_and_old_to_target() {
        let old = b"original log line\n";
        let head = "1".repeat(40);
        let target = "2".repeat(40);
        let tail = format!(
            "{head} {target} Fixture <fixture@example.invalid> 1234567890 +0000\t{}\n",
            forward::MESSAGE
        );
        let bytes = [old.as_slice(), tail.as_bytes()].concat();
        assert_eq!(
            appended_tail(&bytes, old.len(), &switch::hash(old), &head, &target),
            Some(tail.as_bytes())
        );
        assert!(appended_tail(
            &bytes,
            old.len(),
            &switch::hash(b"different"),
            &head,
            &target
        )
        .is_none());
        assert!(appended_tail(&bytes, old.len(), &switch::hash(old), &target, &head).is_none());
        let double = [bytes.as_slice(), tail.as_bytes()].concat();
        assert!(appended_tail(&double, old.len(), &switch::hash(old), &head, &target).is_none());
        let changed = String::from_utf8(bytes.clone())
            .unwrap()
            .replace(forward::MESSAGE, "other action");
        assert!(appended_tail(
            changed.as_bytes(),
            old.len(),
            &switch::hash(old),
            &head,
            &target
        )
        .is_none());
        let controls = String::from_utf8(bytes)
            .unwrap()
            .replace("Fixture <", "Fixture\n<");
        assert!(appended_tail(
            controls.as_bytes(),
            old.len(),
            &switch::hash(old),
            &head,
            &target
        )
        .is_none());
    }
    #[test]
    fn absent_log_comparison_accepts_only_bounded_complete_single_append() {
        let head = "1".repeat(40);
        let target = "2".repeat(40);
        let good = format!(
            "{head} {target} Fixture <fixture@example.invalid> 1 -0100\t{}\n",
            forward::MESSAGE
        );
        assert!(appended_tail(good.as_bytes(), 0, &switch::hash(b""), &head, &target).is_some());
        for bad in [
            good.replace(" 1 -0100", " -1 -0100"),
            good.replace(" 1 -0100", " 1 0100"),
            good.replace("Fixture <fixture@example.invalid>", " <>"),
            good.replace("Fixture", &"x".repeat(2050)),
        ] {
            assert!(appended_tail(bad.as_bytes(), 0, &switch::hash(b""), &head, &target).is_none());
        }
    }
}
