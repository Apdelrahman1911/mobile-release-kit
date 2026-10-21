//! Fetch facet of the SAME GitLocal SourceBook. The candidate job creates one
//! durable .keep before acknowledging publication; it is not a download owner.
//! Only the original child/FD8/ACK return witness may admit exact hard-linked
//! pack/index/ref successors. Unknown retains the keep and all original routes.
use super::*;
use crate::{git_fetch_protocol as fetch, git_local_protocol::fetch_worker as codec};

const LOG_LIMIT: u64 = 128 * 1024;
const LOG_TAIL: u64 = 2048;
const MESSAGE: &str = "MRK: fetch reviewed remote branch";
const KEEP_LIMIT: u64 = 256;

struct Edge {
    parent: usize,
    name: Vec<u8>,
    original: Option<(usize, wire::Snapshot)>,
    maximum: u64,
}
struct Successor {
    old: Option<(usize, wire::Snapshot)>,
    index: usize,
    snapshot: wire::Snapshot,
    maximum: u64,
    appended: bool,
}
struct Marker {
    index: usize,
    intent: fetch::Intent,
    data: Option<codec::Keep>,
    // This changes only after the exact child publication has been admitted.
    // Ordinary pre-ACK posts still require the original creation transition.
    parent_now: Option<codec::CoreDirectory>,
    unlink_claimed: bool,
    unlinked: bool,
}
pub(super) struct State {
    shell: (usize, wire::Snapshot),
    pack: Option<usize>,
    target: Option<Edge>,
    packed: Option<Edge>,
    // Either the actual log edge or the first absent physical parent. A missing
    // log directory is never created/adopted by this native facet.
    log: Option<Edge>,
    missing_log_parent: Option<(usize, Vec<u8>)>,
    marker: Option<Marker>,
    returned: Vec<Successor>,
    publication: Option<codec::Returned>,
}
impl State {
    fn new(shell: (usize, wire::Snapshot)) -> Result<Self, Reason> {
        let mut returned = Vec::new();
        returned
            .try_reserve_exact(4)
            .map_err(|_| Reason::Capacity)?;
        if returned.capacity() > 4 {
            return Err(Reason::Capacity);
        }
        Ok(Self {
            shell,
            pack: None,
            target: None,
            packed: None,
            log: None,
            missing_log_parent: None,
            marker: None,
            returned,
            publication: None,
        })
    }
    pub(super) fn extra(kind: wire::Kind, review: Option<&wire::Review>) -> Option<usize> {
        if kind != wire::Kind::Fetch {
            return Some(0);
        }
        match review {
            None => Some(2), // Existing Book root + protected /bin + sh.
            Some(wire::Review::Fetch(r)) => r
                .target_ref
                .split('/')
                .count()
                .checked_mul(2)?
                .checked_add(16),
            _ => None,
        }
    }
    pub(super) fn working_bytes() -> Option<usize> {
        // Fixed wrappers are added to, never substituted for, every existing
        // Source facet and the parent's full 128-slot reservation. Log prefix
        // checks stream through 32KiB; no hidden 128KiB log copy is allocated.
        std::mem::size_of::<Self>()
            .checked_add(8 * (PATH_LIMIT + 2048))?
            .checked_add(65536 + 32768 + 4096)?
            .checked_add(8 * (std::mem::size_of::<Edge>() + std::mem::size_of::<Successor>()))
    }
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn nanos(v: (i64, i64)) -> Result<u64, Reason> {
    if v.0 < 0 || !(0..1_000_000_000).contains(&v.1) {
        return Err(Reason::SourceRefused);
    }
    (v.0 as u64)
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(v.1 as u64))
        .ok_or(Reason::SourceRefused)
}
fn core_file(v: FileIdentity) -> Result<codec::CoreOwnedFile, Reason> {
    Ok([
        v.common.dev,
        v.common.ino,
        u64::from(v.common.mode),
        v.size,
        nanos(v.mtime)?,
        nanos(v.ctime)?,
        u64::from(v.common.uid),
        u64::from(v.common.gid),
        v.nlink,
    ])
}
fn core_directory(v: &FileStat) -> Result<codec::CoreDirectory, Reason> {
    directory_identity(v)?;
    let f = core_file(metadata_identity(v)?)?;
    Ok(f[..8].try_into().map_err(|_| Reason::SourceRefused)?)
}
fn same_parent(a: codec::CoreDirectory, b: codec::CoreDirectory) -> bool {
    a[..3] == b[..3] && a[6..] == b[6..]
}
fn append_tail(tail: &[u8], old: Option<&str>, new: &str) -> bool {
    if tail.is_empty() || tail.len() > LOG_TAIL as usize {
        return false;
    }
    let Ok(text) = std::str::from_utf8(tail) else {
        return false;
    };
    let zero = "0".repeat(40);
    let prefix = format!("{} {new} ", old.unwrap_or(&zero));
    let Some(body) = text
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(&format!("\t{MESSAGE}\n")))
    else {
        return false;
    };
    if body.chars().any(char::is_control) {
        return false;
    }
    let Some((who_time, zone)) = body.rsplit_once(' ') else {
        return false;
    };
    if zone.len() != 5
        || !matches!(zone.as_bytes()[0], b'+' | b'-')
        || !zone[1..].bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let Some((who, time)) = who_time.rsplit_once(' ') else {
        return false;
    };
    if time.is_empty() || time.len() > 12 || !time.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some((name, email)) = who.strip_suffix('>').and_then(|s| s.rsplit_once(" <")) else {
        return false;
    };
    !name.trim().is_empty() && !email.is_empty() && !email.contains(['<', '>'])
}

impl GitLocalSources {
    pub(crate) fn retain_fetch_unknown(&mut self) {
        self.first = Some(Reason::CleanupUnknown);
        self.close_failed = true;
    }
    pub(super) fn fetch_holds_marker(&self) -> bool {
        self.fetch
            .as_ref()
            .and_then(|s| s.marker.as_ref())
            .is_some_and(|m| {
                !matches!(
                    self.book.slots[m.index].state,
                    OriginalState::NoHandle | OriginalState::Closed
                )
            })
    }
    fn fetch_edge(
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
    fn fetch_parent(
        &self,
        index: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<codec::CoreDirectory, Reason> {
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if directory_identity(&held)? != self.book.directory(index)? || held.st_flags != 0 {
            return Err(Reason::SourceChanged);
        }
        core_directory(&held)
    }
    pub(super) fn capture_fetch(
        &mut self,
        objects: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if self.fetch.is_some() {
            return Err(Reason::SourceChanged);
        }
        let native = self.native.as_ref().ok_or(Reason::SourceChanged)?.clone();
        let mut nominated=crate::runtime::git_fetch::matches_tool(&native.tool);
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        {if self.fetch_observation.is_some(){nominated=self.observed_fetch_tool(stop)?;}}
        if !nominated {
            return Err(Reason::SourceRefused);
        }
        // Fixed interpreter used by the two stock-Git exec shims. This is an
        // original root-owned source, not PATH discovery or a version claim.
        let bin = self.book.child(0, b"bin", false, stop)?;
        let d = self.book.directory(bin)?;
        if d.uid != 0 || d.mode & 0o7022 != 0 {
            return Err(Reason::SourceRefused);
        }
        let shell = self.file(bin, b"sh", 0, wire::TOOL_LIMIT, true, stop)?;
        self.fetch = Some(State::new((
            shell,
            self.snapshot(shell, wire::TOOL_LIMIT, stop)?,
        ))?);
        let Some(review) = self
            .review
            .as_ref()
            .and_then(wire::Review::fetch_details)
            .cloned()
        else {
            return Ok(());
        };
        if !review.valid() || review.up_to_date() {
            return Err(Reason::SourceRefused);
        }
        let head = match (&review.branch, &review.head) {
            (Some(name), _) => format!("ref: {name}\n"),
            (None, Some(oid)) => format!("{oid}\n"),
            _ => return Err(Reason::SourceRefused),
        };
        if native.files.head.sha256 != hash(head.as_bytes()) {
            return Err(Reason::SourceChanged);
        }
        let git = self.git.ok_or(Reason::SourceChanged)?;
        let pack = self.book.child(objects, b"pack", false, stop)?;
        let pack_id = self.book.directory(pack)?;
        if pack_id.uid != native.uid || pack_id.gid != native.gid {
            return Err(Reason::SourceRefused);
        }
        self.fetch.as_mut().ok_or(Reason::SourceChanged)?.pack = Some(pack);
        let parts: Vec<_> = review.target_ref.split('/').collect();
        if parts.len() > 32 || parts.len() < 4 {
            return Err(Reason::SourceRefused);
        }
        let mut parent = git;
        for part in &parts[..parts.len() - 1] {
            parent = self.book.child(parent, part.as_bytes(), false, stop)?;
        }
        let ref_parent = self.book.directory(parent)?;
        if ref_parent.uid != native.uid || ref_parent.gid != native.gid {
            return Err(Reason::SourceRefused);
        }
        let target = self.fetch_edge(
            parent,
            parts.last().ok_or(Reason::SourceRefused)?.as_bytes(),
            native.uid,
            65,
            stop,
        )?;
        if let Some((_, original)) = &target.original {
            if review
                .expected_target
                .as_ref()
                .map(|v| hash(format!("{v}\n").as_bytes()))
                .as_ref()
                != Some(&original.sha256)
            {
                return Err(Reason::SourceChanged);
            }
        }
        self.fetch.as_mut().ok_or(Reason::SourceChanged)?.target = Some(target);
        // Missing loose target alone does not prove absence; the unchanged
        // original packed-refs plus the core's expected-old Git CAS decide.
        let packed = self.fetch_edge(git, b"packed-refs", native.uid, 65536, stop)?;
        self.fetch.as_mut().ok_or(Reason::SourceChanged)?.packed = Some(packed);
        let mut parent = git;
        for part in std::iter::once("logs").chain(parts[..parts.len() - 1].iter().copied()) {
            checkpoint(stop)?;
            match stat::fstatat(self.book.fd(parent)?, part, AtFlags::AT_SYMLINK_NOFOLLOW) {
                Err(nix::errno::Errno::ENOENT) => {
                    self.fetch
                        .as_mut()
                        .ok_or(Reason::SourceChanged)?
                        .missing_log_parent = Some((parent, copy_bytes(part.as_bytes())?));
                    checkpoint(stop)?;
                    return Ok(());
                }
                Ok(_) => {
                    parent = self.book.child(parent, part.as_bytes(), false, stop)?;
                }
                Err(_) => return Err(Reason::SourceRefused),
            }
        }
        let log_parent = self.book.directory(parent)?;
        if log_parent.uid != native.uid || log_parent.gid != native.gid {
            return Err(Reason::SourceRefused);
        }
        let log = self.fetch_edge(
            parent,
            parts.last().ok_or(Reason::SourceRefused)?.as_bytes(),
            native.uid,
            LOG_LIMIT,
            stop,
        )?;
        self.fetch.as_mut().ok_or(Reason::SourceChanged)?.log = Some(log);
        Ok(())
    }
    /// Original candidate job only. Preparing was durably admitted before GO.
    /// This fixed keep must be durable before the same candidate ACK permits
    /// the worker's FIRST original object hard link. No ref is changed here.
    pub(crate) fn prepare_fetch_keep(
        &mut self,
        intent: &wire::Intent,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let value = intent
            .fetch_details()
            .filter(|v| v.valid())
            .ok_or(Reason::SourceRefused)?
            .clone();
        let review = self.review.as_ref().ok_or(Reason::SourceChanged)?;
        if !intent.matches(review) || self.finished || self.first.is_some() || self.post_claimed {
            return Err(Reason::SourceChanged);
        }
        let state = self.fetch.as_ref().ok_or(Reason::SourceChanged)?;
        if state.marker.is_some() || !state.returned.is_empty() {
            return Err(Reason::CleanupUnknown);
        }
        let parent = state.pack.ok_or(Reason::SourceChanged)?;
        self.post_inner(stop)?;
        let before = self.fetch_parent(parent, stop)?;
        let name = format!("pack-{}.keep", value.pack_oid);
        let body = format!("mrk-git-fetch/1 {}\n", value.review_digest);
        let index = self.book.reserve(Some(parent), name.as_bytes())?;
        self.fetch.as_mut().ok_or(Reason::SourceChanged)?.marker = Some(Marker {
            index,
            intent: value.clone(),
            data: None,
            parent_now: None,
            unlink_claimed: false,
            unlinked: false,
        });
        self.book.slots[index].state = OriginalState::Acquiring;
        let result = fcntl::openat(
            self.book.fd(parent)?,
            name.as_str(),
            OFlag::O_RDWR
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK
                | OFlag::O_CREAT
                | OFlag::O_EXCL,
            Mode::S_IRUSR | Mode::S_IWUSR,
        );
        self.book.adopt(index, result)?;
        // From here an error keeps this exact inode/route. It cannot be removed
        // merely because open/write/fsync raised or a pathname now looks equal.
        let result = (|| {
            checkpoint(stop)?;
            filesystem(self.book.fd(index)?, stop)?;
            let created = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
            let created_id = file_identity(&created)?;
            let n = self.native.as_ref().ok_or(Reason::SourceChanged)?;
            if created_id.common.mode != 0o100600
                || created_id.common.uid != n.uid
                || created_id.common.gid != n.gid
                || created_id.nlink != 1
                || created_id.size != 0
                || created.st_flags != 0
            {
                return Err(Reason::SourceRefused);
            }
            let mut at = 0;
            while at < body.len() {
                checkpoint(stop)?;
                let count = unistd::write(self.book.fd(index)?, &body.as_bytes()[at..])
                    .map_err(|_| Reason::SourceRefused)?;
                if count == 0 || count > body.len() - at {
                    return Err(Reason::SourceRefused);
                }
                at += count;
            }
            checkpoint(stop)?;
            unistd::fsync(self.book.fd(index)?).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            unistd::fsync(self.book.fd(parent)?).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
            let named = stat::fstatat(
                self.book.fd(parent)?,
                name.as_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| Reason::SourceChanged)?;
            let held_id = file_identity(&held)?;
            if held_id != file_identity(&named)?
                || held_id.common != created_id.common
                || held_id.nlink != 1
                || held_id.size != body.len() as u64
                || held.st_flags != 0
                || named.st_flags != 0
            {
                return Err(Reason::SourceChanged);
            }
            self.book.slots[index].identity = Some(Identity::File(held_id));
            if self.snapshot(index, KEEP_LIMIT, stop)?.sha256 != hash(body.as_bytes()) {
                return Err(Reason::SourceChanged);
            }
            let after = self.fetch_parent(parent, stop)?;
            let data = codec::Keep {
                pack_oid: value.pack_oid.clone(),
                review_digest: value.review_digest.clone(),
                identity: core_file(held_id)?,
                parent_before: before,
                parent_after: after,
            };
            if !data.valid(&value, self.native.as_ref().ok_or(Reason::SourceChanged)?) {
                return Err(Reason::SourceChanged);
            }
            let marker = self
                .fetch
                .as_mut()
                .and_then(|s| s.marker.as_mut())
                .ok_or(Reason::SourceChanged)?;
            marker.data = Some(data);
            marker.parent_now = Some(after);
            self.post_inner(stop)
        })();
        if result.is_err() {
            self.retain_fetch_unknown();
            return Err(Reason::CleanupUnknown);
        }
        result
    }
    pub(crate) fn fetch_keep(&self) -> Result<Option<&codec::Keep>, Reason> {
        if self.finished || self.first.is_some() {
            return Err(Reason::SourceChanged);
        }
        self.fetch
            .as_ref()
            .and_then(|s| s.marker.as_ref())
            .map(|m| m.data.as_ref().ok_or(Reason::SourceChanged))
            .transpose()
    }
    fn check_fetch_keep(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let state = self.fetch.as_ref().ok_or(Reason::SourceChanged)?;
        let marker = state.marker.as_ref().ok_or(Reason::SourceChanged)?;
        if marker.unlink_claimed || marker.unlinked {
            return Err(Reason::CleanupUnknown);
        }
        let data = marker.data.as_ref().ok_or(Reason::CleanupUnknown)?;
        let parent = state.pack.ok_or(Reason::SourceChanged)?;
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(marker.index)?).map_err(|_| Reason::SourceChanged)?;
        let named = stat::fstatat(
            self.book.fd(parent)?,
            OsStr::from_bytes(&self.book.slots[marker.index].name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Reason::SourceChanged)?;
        if core_file(file_identity(&held)?)? != data.identity
            || file_identity(&held)? != file_identity(&named)?
            || held.st_flags != 0
            || named.st_flags != 0
            || self.fetch_parent(parent, stop)? != marker.parent_now.ok_or(Reason::SourceChanged)?
            || self.snapshot(marker.index, KEEP_LIMIT, stop)?.sha256 != hash(&data.body())
        {
            return Err(Reason::SourceChanged);
        }
        checkpoint(stop)
    }
    pub(super) fn fetch_is_old(&self, index: usize) -> bool {
        self.fetch.as_ref().is_some_and(|s| {
            s.returned
                .iter()
                .any(|v| v.old.as_ref().is_some_and(|o| o.0 == index))
        })
    }
    pub(super) fn fetch_old_identity(
        &self,
        index: usize,
        held: &FileStat,
    ) -> Result<FileIdentity, Reason> {
        let item = self
            .fetch
            .as_ref()
            .and_then(|s| {
                s.returned
                    .iter()
                    .find(|v| v.old.as_ref().is_some_and(|o| o.0 == index))
            })
            .ok_or(Reason::SourceChanged)?;
        let Some(Identity::File(original)) = self.book.slots[index].identity else {
            return Err(Reason::SourceChanged);
        };
        let Some(Identity::File(successor)) = self.book.slots[item.index].identity else {
            return Err(Reason::SourceChanged);
        };
        let current = file_identity(held)?;
        let allowed = if item.appended {
            current == successor
                && current.common == original.common
                && current.nlink == original.nlink
                && current.size >= original.size
                && current.size <= original.size + LOG_TAIL
                && held.st_flags == 0
        } else {
            unlinked_original(current, original, successor, held.st_flags as u64)
        };
        if !allowed {
            return Err(Reason::SourceChanged);
        }
        Ok(current)
    }
    pub(super) fn fetch_snapshot_original(
        &self,
        index: usize,
        maximum: u64,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<wire::Snapshot, Reason> {
        let item = self
            .fetch
            .as_ref()
            .and_then(|s| {
                s.returned
                    .iter()
                    .find(|v| v.old.as_ref().is_some_and(|o| o.0 == index))
            })
            .ok_or(Reason::SourceChanged)?;
        let original = &item.old.as_ref().ok_or(Reason::SourceChanged)?.1;
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        let current = self.fetch_old_identity(index, &held)?;
        if item.appended {
            if maximum != LOG_LIMIT {
                return Err(Reason::SourceChanged);
            }
            self.fetch_log_prefix(index, current, Some(original), stop)?;
        } else if self
            .snapshot_identity(index, current, maximum, stop)?
            .sha256
            != original.sha256
        {
            return Err(Reason::SourceChanged);
        }
        Ok(original.clone())
    }
    fn fetch_log_prefix(
        &self,
        index: usize,
        expected: FileIdentity,
        original: Option<&wire::Snapshot>,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let prefix_size = original.map_or(0, |s| s.identity.6);
        if prefix_size > LOG_LIMIT
            || expected.size < prefix_size
            || expected.size > prefix_size + LOG_TAIL
        {
            return Err(Reason::SourceChanged);
        }
        unistd::lseek(self.book.fd(index)?, 0, unistd::Whence::SeekSet)
            .map_err(|_| Reason::SourceRefused)?;
        let mut buffer = Zeroizing::new([0u8; 32768]);
        let mut prefix = Sha256::new();
        let mut tail = Zeroizing::new([0u8; LOG_TAIL as usize]);
        let mut count = 0u64;
        let mut tail_count = 0usize;
        loop {
            checkpoint(stop)?;
            let n = unistd::read(self.book.fd(index)?, &mut buffer[..])
                .map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if n == 0 {
                break;
            }
            let p = usize::try_from(prefix_size.saturating_sub(count).min(n as u64))
                .map_err(|_| Reason::Capacity)?;
            prefix.update(&buffer[..p]);
            if n - p > tail.len().saturating_sub(tail_count) {
                return Err(Reason::SourceChanged);
            }
            tail[tail_count..tail_count + n - p].copy_from_slice(&buffer[p..n]);
            tail_count += n - p;
            count = count.checked_add(n as u64).ok_or(Reason::Capacity)?;
            if count > expected.size {
                return Err(Reason::SourceChanged);
            }
        }
        let digest = prefix
            .finalize()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let intent = &self
            .fetch
            .as_ref()
            .and_then(|s| s.marker.as_ref())
            .ok_or(Reason::SourceChanged)?
            .intent;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        if count != expected.size
            || file_identity(&held)? != expected
            || held.st_flags != 0
            || digest != original.map_or_else(|| hash(b""), |s| s.sha256.clone())
            || !append_tail(
                &tail[..tail_count],
                intent.expected_target.as_deref(),
                &intent.candidate_ref_oid,
            )
        {
            return Err(Reason::SourceChanged);
        }
        checkpoint(stop)
    }
    fn fetch_successor(
        &mut self,
        parent: usize,
        name: &[u8],
        receipt: codec::CoreOwnedFile,
        digest: &str,
        maximum: u64,
        old: Option<(usize, wire::Snapshot)>,
        appended: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if self
            .fetch
            .as_ref()
            .is_none_or(|s| s.returned.len() >= 4 || s.publication.is_some())
        {
            return Err(Reason::SourceChanged);
        }
        checkpoint(stop)?;
        let index = self.book.reserve(Some(parent), name)?;
        let named = stat::fstatat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Reason::SourceChanged)?;
        let expected = file_identity(&named)?;
        let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
        if core_file(expected)? != receipt
            || expected.common.uid != native.uid
            || expected.common.gid != native.gid
            || expected.common.mode & 0o7022 != 0
            || !matches!(expected.nlink, 1 | 2)
            || expected.size > maximum
            || named.st_flags != 0
        {
            return Err(Reason::SourceChanged);
        }
        self.book.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::openat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        );
        self.book.adopt(index, opened)?;
        checkpoint(stop)?;
        filesystem(self.book.fd(index)?, stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        let named = stat::fstatat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Reason::SourceChanged)?;
        if file_identity(&held)? != expected
            || file_identity(&named)? != expected
            || held.st_flags != 0
            || named.st_flags != 0
        {
            return Err(Reason::SourceChanged);
        }
        self.book.slots[index].identity = Some(Identity::File(expected));
        let snapshot = self.snapshot(index, maximum, stop)?;
        if snapshot.sha256 != digest {
            return Err(Reason::SourceChanged);
        }
        if appended {
            self.fetch_log_prefix(index, expected, old.as_ref().map(|o| &o.1), stop)?;
        }
        self.fetch
            .as_mut()
            .ok_or(Reason::SourceChanged)?
            .returned
            .push(Successor {
                old,
                index,
                snapshot,
                maximum,
                appended,
            });
        Ok(())
    }
    pub(super) fn fetch_returned(
        &mut self,
        publication: &GitLocalPublication,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let state = self.fetch.as_ref().ok_or(Reason::SourceChanged)?;
        let marker = state.marker.as_ref().ok_or(Reason::SourceChanged)?;
        let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
        let (intent, returned) = publication.fetch_for(
            self.operation_id.as_deref().ok_or(Reason::SourceChanged)?,
            native,
            self.review.as_ref().ok_or(Reason::SourceChanged)?,
            marker.data.as_ref().ok_or(Reason::SourceChanged)?,
        )?;
        if intent != &marker.intent
            || !state.returned.is_empty()
            || state.publication.is_some()
            || !returned.valid(intent, native)
        {
            return Err(Reason::SourceChanged);
        }
        let (intent, returned, pack) = (
            intent.clone(),
            returned.clone(),
            state.pack.ok_or(Reason::SourceChanged)?,
        );
        self.fetch_successor(
            pack,
            format!("pack-{}.pack", intent.pack_oid).as_bytes(),
            returned.pack,
            &intent.pack_sha256,
            fetch::FILE_LIMIT,
            None,
            false,
            stop,
        )?;
        if let Some(index) = returned.index {
            self.fetch_successor(
                pack,
                format!("pack-{}.idx", intent.pack_oid).as_bytes(),
                index,
                &intent.index_sha256,
                fetch::FILE_LIMIT,
                None,
                false,
                stop,
            )?;
        }
        if let Some(reference) = &returned.reference {
            let edge = self
                .fetch
                .as_ref()
                .and_then(|s| s.target.as_ref())
                .ok_or(Reason::SourceChanged)?;
            let (parent, name, old) = (edge.parent, edge.name.clone(), edge.original.clone());
            let parent_stat = self.fetch_parent(parent, stop)?;
            if parent_stat[..6] != reference.parent {
                return Err(Reason::SourceChanged);
            }
            let named = stat::fstatat(
                self.book.fd(parent)?,
                OsStr::from_bytes(&name),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| Reason::SourceChanged)?;
            let receipt = core_file(file_identity(&named)?)?;
            if receipt[..6] != reference.identity || receipt[8] != 1 {
                return Err(Reason::SourceChanged);
            }
            self.fetch_successor(
                parent,
                &name,
                receipt,
                &hash(format!("{}\n", intent.candidate_ref_oid).as_bytes()),
                65,
                old,
                false,
                stop,
            )?;
            let log = returned.log.as_ref().ok_or(Reason::SourceChanged)?;
            if let Some(edge) = self.fetch.as_ref().and_then(|s| s.log.as_ref()) {
                let (parent, name, old) = (edge.parent, edge.name.clone(), edge.original.clone());
                if self.fetch_parent(parent, stop)?
                    != returned.log_parent.ok_or(Reason::SourceChanged)?
                {
                    return Err(Reason::SourceChanged);
                }
                match log.kind.as_str() {
                    "absent" if old.is_none() => self.fetch_absent(parent, &name, stop)?,
                    "file" => {
                        let named = stat::fstatat(
                            self.book.fd(parent)?,
                            OsStr::from_bytes(&name),
                            AtFlags::AT_SYMLINK_NOFOLLOW,
                        )
                        .map_err(|_| Reason::SourceChanged)?;
                        let receipt = core_file(file_identity(&named)?)?;
                        if receipt[..6] != log.identity.ok_or(Reason::SourceChanged)?
                            || receipt[8] != 1
                        {
                            return Err(Reason::SourceChanged);
                        }
                        // A disabled existing log is unchanged, not an append.
                        if old.as_ref().is_some_and(|(_, s)| {
                            s.sha256 == log.sha256 && s.identity.6 == receipt[3]
                        }) {
                            if self.snapshot(
                                old.as_ref().ok_or(Reason::SourceChanged)?.0,
                                LOG_LIMIT,
                                stop,
                            )? != old.as_ref().ok_or(Reason::SourceChanged)?.1
                            {
                                return Err(Reason::SourceChanged);
                            }
                        } else {
                            self.fetch_successor(
                                parent,
                                &name,
                                receipt,
                                &log.sha256,
                                LOG_LIMIT + LOG_TAIL,
                                old,
                                true,
                                stop,
                            )?;
                        }
                    }
                    _ => return Err(Reason::SourceChanged),
                }
            } else if log.kind != "absent" || returned.log_parent.is_some() {
                return Err(Reason::SourceChanged);
            }
        }
        let parent_now = self.fetch_parent(pack, stop)?;
        let state = self.fetch.as_mut().ok_or(Reason::SourceChanged)?;
        let marker = state.marker.as_mut().ok_or(Reason::SourceChanged)?;
        if !same_parent(marker.parent_now.ok_or(Reason::SourceChanged)?, parent_now) {
            return Err(Reason::SourceChanged);
        }
        marker.parent_now = Some(parent_now);
        state.publication = Some(returned);
        self.check_fetch_keep(stop)
    }
    fn fetch_absent(
        &self,
        parent: usize,
        name: &[u8],
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        checkpoint(stop)?;
        if !matches!(
            stat::fstatat(
                self.book.fd(parent)?,
                OsStr::from_bytes(name),
                AtFlags::AT_SYMLINK_NOFOLLOW
            ),
            Err(nix::errno::Errno::ENOENT)
        ) {
            return Err(Reason::SourceChanged);
        }
        checkpoint(stop)
    }
    pub(super) fn post_fetch(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let Some(state) = &self.fetch else {
            return Ok(());
        };
        if self.snapshot(state.shell.0, wire::TOOL_LIMIT, stop)? != state.shell.1 {
            return Err(Reason::SourceChanged);
        }
        for edge in [&state.target, &state.packed, &state.log]
            .into_iter()
            .flatten()
        {
            let replaced = state.returned.iter().any(|r| {
                self.book.slots[r.index].parent == Some(edge.parent)
                    && self.book.slots[r.index].name == edge.name
            });
            if let Some((index, snapshot)) = &edge.original {
                if self.snapshot_original(*index, edge.maximum, stop)? != *snapshot {
                    return Err(Reason::SourceChanged);
                }
            } else if !replaced {
                self.fetch_absent(edge.parent, &edge.name, stop)?;
            }
        }
        if let Some((parent, name)) = &state.missing_log_parent {
            self.fetch_absent(*parent, name, stop)?;
        }
        for item in &state.returned {
            if self.snapshot(item.index, item.maximum, stop)? != item.snapshot {
                return Err(Reason::SourceChanged);
            }
        }
        if state.marker.is_some() {
            self.check_fetch_keep(stop)?;
        }
        Ok(())
    }
    pub(super) fn close_fetch_book(
        &mut self,
        expired: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool,
    ) -> bool {
        let Some(state) = self.fetch.as_ref() else {
            return self.close_fast_forward_book(expired);
        };
        let Some(marker) = state.marker.as_ref() else {
            return self.close_fast_forward_book(expired);
        };
        let (index, parent) = (
            marker.index,
            match state.pack {
                Some(p) => p,
                None => return false,
            },
        );
        if self.book.slots[index].state == OriginalState::NoHandle {
            return self.close_fast_forward_book(expired);
        }
        let first = self.first_failure();
        if expired(first) || self.check_fetch_keep(&mut || expired(first)).is_err() {
            return false;
        }
        // This is called only after original runtime/child/pipe closure.
        // Keep+parent outlive every other source close, including the old ref.
        let mut known = true;
        for at in (0..self.book.slots.len()).rev() {
            if at != index && at != parent {
                if expired(first) {
                    known = false;
                    break;
                }
                known = SourceBook::close_slot(&mut self.book.slots[at], &mut |_| {
                    expired(Some((Failure::Unknown, Instant::now())));
                }) && known;
            }
        }
        if !known || expired(first) || self.check_fetch_keep(&mut || expired(first)).is_err() {
            return false;
        }
        let before = match self.fetch_parent(parent, &mut || expired(first)) {
            Ok(p) => p,
            Err(_) => return false,
        };
        self.fetch
            .as_mut()
            .unwrap()
            .marker
            .as_mut()
            .unwrap()
            .unlink_claimed = true;
        let removed = self.book.fd(parent).is_ok_and(|fd| {
            unistd::unlinkat(
                fd,
                OsStr::from_bytes(&self.book.slots[index].name),
                unistd::UnlinkatFlags::NoRemoveDir,
            )
            .is_ok()
        });
        if !removed || expired(first) {
            return false;
        }
        // Exact same parent/absence after the sole unlink, before either final
        // descriptor closes. A later retry cannot turn an ambiguous unlink into
        // an owned deletion merely by finding the name absent.
        let after = match self.fetch_parent(parent, &mut || expired(first)) {
            Ok(p) => p,
            Err(_) => return false,
        };
        if !same_parent(before, after)
            || self
                .fetch_absent(parent, &self.book.slots[index].name, &mut || expired(first))
                .is_err()
            || self.fetch_parent(parent, &mut || expired(first)).ok() != Some(after)
            || expired(first)
        {
            return false;
        }
        self.fetch
            .as_mut()
            .unwrap()
            .marker
            .as_mut()
            .unwrap()
            .unlinked = true;
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
    fn fixed_log_suffix_requires_one_old_to_new_transition_and_real_identity() {
        let a = "1".repeat(40);
        let b = "2".repeat(40);
        let line = format!("{a} {b} Fixture <fixture@example.invalid> 123 +0000\t{MESSAGE}\n");
        assert!(append_tail(line.as_bytes(), Some(&a), &b));
        for bad in [
            line.repeat(2),
            line.replace(MESSAGE, "other"),
            line.replace("Fixture <", "Fixture\n<"),
            line.replace("123 +0000", "-1 +0000"),
        ] {
            assert!(!append_tail(bad.as_bytes(), Some(&a), &b));
        }
        assert!(!append_tail(line.as_bytes(), Some(&b), &a));
    }
    #[test]
    fn original_parent_transition_never_accepts_changed_inode_mode_owner_or_group() {
        let before = [1, 2, 0o040700, 16, 10, 11, 501, 20];
        let mut after = before;
        after[3] = 32;
        after[4] = 12;
        after[5] = 13;
        assert!(same_parent(before, after));
        for at in [0, 1, 2, 6, 7] {
            let mut wrong = after;
            wrong[at] += 1;
            assert!(!same_parent(before, wrong));
        }
    }
    #[test]
    fn source_extra_is_fixed_before_io_and_never_credits_old_facets() {
        let r = wire::Review::Fetch(crate::git_fetch_protocol::tests::review());
        assert_eq!(State::extra(wire::Kind::Fetch, None), Some(2));
        assert_eq!(State::extra(wire::Kind::Fetch, Some(&r)), Some(24));
        assert_eq!(State::extra(wire::Kind::Stage, None), Some(0));
        let mut deepest = crate::git_fetch_protocol::tests::review();
        deepest.target_ref = format!("refs/remotes/origin/{}", vec!["x"; 29].join("/"));
        assert_eq!(
            State::extra(wire::Kind::Fetch, Some(&wire::Review::Fetch(deepest))),
            Some(80)
        );
        // The unchanged outer per-source128 and total256 guards decide fit;
        // a large extra is not permission to raise either limit.
        assert_eq!(SOURCE_LIMIT, 128);
        assert!(SOURCE_LIMIT + 67 + 32 <= 256);
        assert!(State::working_bytes().unwrap() > std::mem::size_of::<State>());
    }
}
