//! Initialization-only facet of the SAME GitLocal SourceBook. Prepare has no
//! mkdir or Git execution. Apply's original Preparing ACK precedes inspection;
//! one private worktree then belongs to that original invocation, not a path
//! supplied by the renderer. Candidate DATA never enables a moved-name check.
use super::*;
use crate::git_init_protocol as init;

const NAME_LIMIT: usize = 4096;
const NAME_BYTES: usize = 256 * 1024;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Creation {
    Reserved,
    Entered,
    Absent,
    Created,
    Removing,
    Removed,
    Unknown,
}
fn creation_result(result: &Result<(), nix::errno::Errno>) -> Creation {
    match result {
        Ok(()) => Creation::Created,
        Err(nix::errno::Errno::EEXIST) => Creation::Absent, // Foreign collision, never adopted.
        Err(_) => Creation::Unknown, // In particular EINTR: do not infer no mkdir effect.
    }
}
struct Created {
    index: usize,
    state: Creation,
}
struct Captured {
    directories: Vec<(String, usize)>,
    files: Vec<(String, usize, wire::Snapshot)>,
    intent: init::Intent,
    complete: bool,
}
pub(super) struct State {
    project: usize,
    chain: Vec<usize>,
    native: init::Native,
    creations: Vec<Created>,
    captured: Option<Captured>,
    moved: bool,
    retirement_entered: bool,
    retired: bool,
}
impl State {
    pub(super) fn extra(kind: wire::Kind) -> usize {
        // Four originally created directories, six generated directories and
        // two generated files. Same Book capacity/FD ceiling, never new quota.
        if kind == wire::Kind::Initialize {
            12
        } else {
            0
        }
    }
}
fn data(d: DirectoryIdentity) -> wire::DirectoryIdentity {
    (d.dev, d.ino, d.mode, d.uid, d.gid)
}
fn ascii_equal(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}
fn supported_names(names: &[Vec<u8>], project: bool, private: Option<&str>, moved: bool) -> bool {
    for name in names {
        if ascii_equal(name, b".git") && !(project && moved && name == b".git") {
            return false;
        }
        if project
            && (ascii_equal(name, b".gitmodules")
                || ascii_equal(name, b"commondir")
                || ascii_equal(name, b"gitdir"))
        {
            return false;
        }
        if project
            && name.len() >= init::PREFIX.len()
            && name[..init::PREFIX.len()].eq_ignore_ascii_case(init::PREFIX.as_bytes())
            && private.map(str::as_bytes) != Some(name.as_slice())
        {
            return false;
        }
    }
    !(project
        && names.iter().any(|v| ascii_equal(v, b"HEAD"))
        && names
            .iter()
            .any(|v| ascii_equal(v, b"objects") || ascii_equal(v, b"refs")))
}

impl GitLocalSources {
    pub(super) fn init_names(
        &self,
        index: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<Vec<u8>>, Reason> {
        checkpoint(stop)?;
        unistd::lseek(self.book.fd(index)?, 0, unistd::Whence::SeekSet)
            .map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        // Exact existing borrowed-FD primitive. It neither duplicates a FD nor
        // leaves an fdopendir stream outside this original Book.
        let mut block = [0u8; 65536];
        let mut names = Vec::new();
        names
            .try_reserve_exact(NAME_LIMIT)
            .map_err(|_| Reason::Capacity)?;
        if names.capacity() > NAME_LIMIT {
            return Err(Reason::Capacity);
        }
        let mut bytes = 0usize;
        let mut dots = 0u8;
        loop {
            checkpoint(stop)?;
            let used = mrk_macos_installed_native::directory_block(
                self.book.fd(index)?.as_fd(),
                &mut block,
            )
            .map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if used == 0 {
                break;
            }
            if used > block.len() {
                return Err(Reason::SourceRefused);
            }
            let mut at = 0usize;
            while at < used {
                if used - at < 11 {
                    return Err(Reason::SourceRefused);
                }
                let inode = u64::from_ne_bytes(
                    block[at..at + 8]
                        .try_into()
                        .map_err(|_| Reason::SourceRefused)?,
                );
                let len = usize::from(u16::from_ne_bytes([block[at + 9], block[at + 10]]));
                let next = at
                    .checked_add(11 + len)
                    .filter(|v| *v <= used)
                    .ok_or(Reason::SourceRefused)?;
                let name = &block[at + 11..next];
                if inode == 0
                    || name.is_empty()
                    || name.len() > 255
                    || name.contains(&0)
                    || name.contains(&b'/')
                {
                    return Err(Reason::SourceRefused);
                }
                if name == b"." || name == b".." {
                    let bit = if name == b"." { 1 } else { 2 };
                    if block[at + 8] != nix::libc::DT_DIR || dots & bit != 0 {
                        return Err(Reason::SourceRefused);
                    }
                    dots |= bit;
                } else {
                    bytes = bytes.checked_add(name.len()).ok_or(Reason::Capacity)?;
                    if names.len() >= NAME_LIMIT || bytes > NAME_BYTES {
                        return Err(Reason::Capacity);
                    }
                    names.push(copy_bytes(name)?);
                }
                at = next;
            }
        }
        names.sort();
        if names.windows(2).any(|v| v[0] == v[1]) {
            return Err(Reason::SourceChanged);
        }
        Ok(names)
    }
    fn init_roster(
        &self,
        index: usize,
        expected: &[&[u8]],
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let names = self.init_names(index, stop)?;
        if names.len() != expected.len()
            || !names.iter().zip(expected).all(|(a, b)| a.as_slice() == *b)
        {
            return Err(Reason::SourceChanged);
        }
        Ok(())
    }
    fn init_absence(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let state = self.initialization.as_ref().ok_or(Reason::SourceChanged)?;
        for index in &state.chain {
            let names = self.init_names(*index, stop)?;
            if !supported_names(
                &names,
                *index == state.project,
                state.native.candidate.as_ref().map(|c| c.name.as_str()),
                state.moved,
            ) {
                return Err(Reason::SourceRefused);
            }
        }
        Ok(())
    }
    fn init_created_directory(
        &mut self,
        parent: usize,
        name: &[u8],
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize, Reason> {
        checkpoint(stop)?;
        let index = self.book.reserve(Some(parent), name)?;
        let state = self.initialization.as_mut().ok_or(Reason::CleanupUnknown)?;
        if state.creations.len() >= 4 {
            return Err(Reason::Capacity);
        }
        state.creations.push(Created {
            index,
            state: Creation::Reserved,
        }); // BEFORE mkdir, even if it never returns.
        state
            .creations
            .last_mut()
            .ok_or(Reason::CleanupUnknown)?
            .state = Creation::Entered;
        let created = stat::mkdirat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            Mode::from_bits_truncate(0o700),
        );
        let entry = self
            .initialization
            .as_mut()
            .ok_or(Reason::CleanupUnknown)?
            .creations
            .last_mut()
            .ok_or(Reason::CleanupUnknown)?;
        entry.state = creation_result(&created);
        if created.is_err() {
            self.book.slots[index].state = OriginalState::NoHandle;
            return Err(Reason::SourceRefused);
        }
        // A failed/late capture retains Created and cannot be cleaned by name.
        checkpoint(stop)?;
        let named = stat::fstatat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Reason::SourceChanged)?;
        let expected = directory_identity(&named)?;
        let root = self
            .initialization
            .as_ref()
            .ok_or(Reason::CleanupUnknown)?
            .native
            .directory;
        if expected.dev != root.0
            || expected.uid != root.3
            || expected.mode & 0o7777 != 0o700
            || named.st_flags != 0
        {
            return Err(Reason::SourceRefused);
        }
        self.book.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::openat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            directory_flags(),
            Mode::empty(),
        );
        self.book.adopt(index, opened)?;
        checkpoint(stop)?;
        filesystem(self.book.fd(index)?, stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let named = stat::fstatat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if directory_identity(&held)? != expected
            || directory_identity(&named)? != expected
            || held.st_flags != 0
            || named.st_flags != 0
        {
            return Err(Reason::SourceChanged);
        }
        self.book.slots[index].identity = Some(Identity::Directory(expected));
        self.init_roster(index, &[], stop)?;
        Ok(index)
    }
    pub(super) fn inspect_init(
        &mut self,
        root: &RegisteredRoot,
        chain: Vec<usize>,
        tool: usize,
        uid: u32,
        gid: u32,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if self.initialization.is_some() || self.native.is_some() {
            return Err(Reason::SourceChanged);
        }
        let project = *chain.last().ok_or(Reason::SourceRefused)?;
        let mut creations = Vec::new();
        creations
            .try_reserve_exact(4)
            .map_err(|_| Reason::Capacity)?;
        if creations.capacity() > 4 {
            return Err(Reason::Capacity);
        }
        self.initialization = Some(State {
            project,
            chain,
            creations,
            captured: None,
            moved: false,
            retirement_entered: false,
            retired: false,
            native: init::Native {
                uid,
                gid,
                root: root.path.to_str().ok_or(Reason::SourceRefused)?.into(),
                directory: data(self.book.directory(project)?),
                tool: self.snapshot(tool, wire::TOOL_LIMIT, stop)?,
                candidate: None,
            },
        });
        self.init_absence(stop)?;
        if let Some(review) = &self.review {
            if review.init_details().is_none() {
                return Err(Reason::SourceRefused);
            }
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).map_err(|_| Reason::SourceRefused)?;
            let name = format!(
                "{}{}",
                init::PREFIX,
                nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            // One draw, one exclusive mkdir. Collision is refusal, never retry.
            let outer = self.init_created_directory(project, name.as_bytes(), stop)?;
            let worktree = self.init_created_directory(outer, b"worktree", stop)?;
            let git = self.init_created_directory(worktree, b".git", stop)?;
            let template = self.init_created_directory(outer, b"empty-template", stop)?;
            let candidate = init::CandidateSources {
                name,
                outer: data(self.book.directory(outer)?),
                worktree: data(self.book.directory(worktree)?),
                git: data(self.book.directory(git)?),
                template: data(self.book.directory(template)?),
            };
            self.initialization
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .native
                .candidate = Some(candidate);
        }
        let state = self.initialization.as_ref().ok_or(Reason::CleanupUnknown)?;
        if !state.native.valid(if self.review.is_some() {
            wire::Phase::Apply
        } else {
            wire::Phase::Prepare
        }) {
            return Err(Reason::SourceRefused);
        }
        self.post_inner(stop)
    }
    pub(crate) fn init_projection(&self) -> Result<Option<&init::Native>, Reason> {
        if self.finished || self.first.is_some() {
            return Err(Reason::SourceChanged);
        }
        Ok(self.initialization.as_ref().map(|s| &s.native))
    }
    fn init_indices(&self) -> Result<[usize; 4], Reason> {
        let s = self.initialization.as_ref().ok_or(Reason::SourceChanged)?;
        if s.creations.len() != 4 || s.creations.iter().any(|c| c.state != Creation::Created) {
            return Err(Reason::SourceChanged);
        }
        Ok([
            s.creations[0].index,
            s.creations[1].index,
            s.creations[2].index,
            s.creations[3].index,
        ])
    }
    pub(super) fn init_named(&self, index: usize) -> Option<(usize, &[u8])> {
        let s = self.initialization.as_ref()?;
        if !s.moved || s.creations.get(2)?.index != index {
            return None;
        }
        Some((s.project, b".git"))
    }
    fn init_manifest(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let s = self.initialization.as_ref().ok_or(Reason::SourceChanged)?;
        let Some(c) = &s.captured else { return Ok(()) };
        if !c.complete {
            return Err(Reason::CleanupUnknown);
        }
        let mut directories = Vec::new();
        let mut files = Vec::new();
        for (name, index) in &c.directories {
            let expected: &[&[u8]] = match name.as_str() {
                "" => &[b"HEAD", b"config", b"objects", b"refs"],
                "objects" => &[b"info", b"pack"],
                "refs" => &[b"heads", b"tags"],
                _ => &[],
            };
            self.init_roster(*index, expected, stop)?;
            directories.push((name.clone(), data(self.book.directory(*index)?)));
        }
        for (name, index, snapshot) in &c.files {
            let now = self.snapshot(
                *index,
                if name == "HEAD" {
                    64
                } else {
                    init::CONFIG_LIMIT
                },
                stop,
            )?;
            if &now != snapshot {
                return Err(Reason::SourceChanged);
            }
            files.push((name.clone(), now));
        }
        let digest =
            init::manifest_digest(&directories, &files).map_err(|_| Reason::SourceRefused)?;
        if digest != c.intent.candidate_manifest
            || files[0].1.sha256 != c.intent.candidate_head
            || files[1].1.sha256 != c.intent.candidate_config
        {
            return Err(Reason::SourceChanged);
        }
        Ok(())
    }
    /// Original candidate job calls once BEFORE the durable Candidate CAS/ACK.
    /// Full finite native originals are rooted before their first open/hash.
    pub(crate) fn capture_init(
        &mut self,
        intent: &wire::Intent,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if self.finished || self.first.is_some() || self.post_claimed {
            return Err(Reason::SourceChanged);
        }
        let result = (|| {
            let input = intent
                .init_details()
                .filter(|v| v.valid())
                .ok_or(Reason::SourceRefused)?;
            let s = self.initialization.as_ref().ok_or(Reason::SourceRefused)?;
            if s.captured.is_some()
                || s.moved
                || !self.review.as_ref().is_some_and(|r| intent.matches(r))
            {
                return Err(Reason::SourceChanged);
            }
            let [_, _, git, _] = self.init_indices()?;
            let uid = s.native.uid;
            let mut directories = Vec::new();
            directories
                .try_reserve_exact(init::DIRECTORY_NAMES.len())
                .map_err(|_| Reason::Capacity)?;
            let mut files = Vec::new();
            files.try_reserve_exact(2).map_err(|_| Reason::Capacity)?;
            if directories.capacity() > 7 || files.capacity() > 2 {
                return Err(Reason::Capacity);
            }
            directories.push((String::new(), git));
            self.initialization
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .captured = Some(Captured {
                directories,
                files,
                intent: input.clone(),
                complete: false,
            });
            for name in &init::DIRECTORY_NAMES[1..] {
                let (parent_name, leaf) = name.rsplit_once('/').unwrap_or(("", name));
                let parent = self
                    .initialization
                    .as_ref()
                    .and_then(|s| s.captured.as_ref())
                    .and_then(|c| c.directories.iter().find(|v| v.0 == parent_name))
                    .map(|v| v.1)
                    .ok_or(Reason::SourceChanged)?;
                let index = self.book.child(parent, leaf.as_bytes(), false, stop)?;
                let d = self.book.directory(index)?;
                if d.dev != self.book.directory(git)?.dev || d.uid != uid || d.mode & 0o7022 != 0 {
                    return Err(Reason::SourceRefused);
                }
                self.initialization
                    .as_mut()
                    .and_then(|s| s.captured.as_mut())
                    .ok_or(Reason::CleanupUnknown)?
                    .directories
                    .push(((*name).into(), index));
            }
            for (name, limit) in [("HEAD", 64), ("config", init::CONFIG_LIMIT)] {
                let index = self.file(git, name.as_bytes(), uid, limit, false, stop)?;
                let snapshot = self.snapshot(index, limit, stop)?;
                self.initialization
                    .as_mut()
                    .and_then(|s| s.captured.as_mut())
                    .ok_or(Reason::CleanupUnknown)?
                    .files
                    .push((name.into(), index, snapshot));
            }
            self.initialization
                .as_mut()
                .and_then(|s| s.captured.as_mut())
                .ok_or(Reason::CleanupUnknown)?
                .complete = true;
            self.post_inner(stop)
        })();
        if result.is_err() {
            self.first = Some(Reason::CleanupUnknown);
            self.close_failed = true;
            return Err(Reason::CleanupUnknown);
        }
        result
    }
    pub(super) fn post_init(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let s = self.initialization.as_ref().ok_or(Reason::SourceChanged)?;
        if self.snapshot(
            self.indices[0].ok_or(Reason::SourceChanged)?,
            wire::TOOL_LIMIT,
            stop,
        )? != s.native.tool
        {
            return Err(Reason::SourceChanged);
        }
        self.init_absence(stop)?;
        if s.native.candidate.is_some() {
            let [outer, worktree, _, template] = self.init_indices()?;
            self.init_roster(outer, &[b"empty-template", b"worktree"], stop)?;
            self.init_roster(template, &[], stop)?;
            self.init_roster(worktree, if s.moved { &[] } else { &[b".git"] }, stop)?;
        }
        self.init_manifest(stop)
    }
    pub(super) fn init_returned(
        &mut self,
        publication: Option<&GitLocalPublication>,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if let Some(publication) = publication {
            let s = self.initialization.as_ref().ok_or(Reason::SourceChanged)?;
            let intent = publication.init_for(
                self.operation_id.as_deref().ok_or(Reason::SourceChanged)?,
                &s.native,
                self.review.as_ref().ok_or(Reason::SourceChanged)?,
            )?;
            if s.moved
                || !s
                    .captured
                    .as_ref()
                    .is_some_and(|c| c.complete && &c.intent == intent)
            {
                return Err(Reason::SourceChanged);
            }
            self.initialization
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .moved = true;
        }
        self.post_inner(stop)
    }
    pub(super) fn retire_init(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let Some(s) = self.initialization.as_mut() else {
            return Ok(());
        };
        if s.retirement_entered {
            return Err(Reason::CleanupUnknown);
        }
        s.retirement_entered = true;
        // A produced/acknowledged tree without original positive publication
        // stays retained. Absence, cancelled DATA and a closed pipe prove none.
        if s.captured.is_some() && !s.moved {
            return Err(Reason::CleanupUnknown);
        }
        for at in (0..s.creations.len()).rev() {
            let s = self.initialization.as_ref().ok_or(Reason::CleanupUnknown)?;
            if at == 2 && s.moved {
                continue;
            } // NEVER consume the published .git.
            let creation = &s.creations[at];
            if matches!(creation.state, Creation::Reserved | Creation::Absent) {
                continue;
            }
            if creation.state != Creation::Created {
                return Err(Reason::CleanupUnknown);
            }
            let index = creation.index;
            self.init_roster(index, &[], stop)?;
            let slot = &self.book.slots[index];
            let parent = slot.parent.ok_or(Reason::CleanupUnknown)?;
            let name = slot.name.clone();
            checkpoint(stop)?;
            let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
            let named = stat::fstatat(
                self.book.fd(parent)?,
                OsStr::from_bytes(&name),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if Some(Identity::Directory(directory_identity(&held)?)) != slot.identity
                || Some(Identity::Directory(directory_identity(&named)?)) != slot.identity
                || held.st_flags != 0
                || named.st_flags != 0
            {
                return Err(Reason::SourceChanged);
            }
            self.book.private_acl(index, 1, stop)?;
            self.initialization
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .creations[at]
                .state = Creation::Removing;
            let removed = unistd::unlinkat(
                self.book.fd(parent)?,
                OsStr::from_bytes(&name),
                unistd::UnlinkatFlags::RemoveDir,
            );
            self.initialization
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .creations[at]
                .state = if removed.is_ok() {
                Creation::Removed
            } else {
                Creation::Unknown
            };
            removed.map_err(|_| Reason::CleanupUnknown)?;
            checkpoint(stop)?;
            if !matches!(
                stat::fstatat(
                    self.book.fd(parent)?,
                    OsStr::from_bytes(&name),
                    AtFlags::AT_SYMLINK_NOFOLLOW
                ),
                Err(nix::errno::Errno::ENOENT)
            ) {
                return Err(Reason::SourceChanged);
            }
            checkpoint(stop)?;
        }
        self.initialization
            .as_mut()
            .ok_or(Reason::CleanupUnknown)?
            .retired = true;
        Ok(())
    }
    pub(super) fn init_retired(&self) -> bool {
        self.initialization.as_ref().is_none_or(|s| s.retired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn init_absence_data_rejects_alias_bare_submodule_and_foreign_candidates() {
        for n in [
            b".git".to_vec(),
            b".GIT".to_vec(),
            b".gitmodules".to_vec(),
            b"commondir".to_vec(),
            format!("{}{}", init::PREFIX, "a".repeat(32)).into_bytes(),
        ] {
            assert!(!supported_names(&[n], true, None, false));
        }
        assert!(!supported_names(
            &[b"HEAD".to_vec(), b"objects".to_vec()],
            true,
            None,
            false
        ));
        assert!(supported_names(
            &[b"src".to_vec(), b"README".to_vec()],
            true,
            None,
            false
        ));
        assert!(!supported_names(&[b".git".to_vec()], false, None, true));
        assert!(supported_names(&[b".git".to_vec()], true, None, true)); // comparison-only, not a moved receipt
        assert!(!supported_names(&[b".GIT".to_vec()], true, None, true));
    }
    #[test]
    fn init_candidate_additional_roster_is_finite_and_old_actions_unchanged() {
        assert_eq!(State::extra(wire::Kind::Initialize), 12);
        for k in [
            wire::Kind::Stage,
            wire::Kind::Unstage,
            wire::Kind::Commit,
            wire::Kind::BranchCreate,
            wire::Kind::BranchSwitch,
            wire::Kind::BranchRename,
            wire::Kind::FastForward,
        ] {
            assert_eq!(State::extra(k), 0)
        }
        assert!(
            init::MANIFEST_BACKING
                >= NAME_BYTES + NAME_LIMIT * std::mem::size_of::<Vec<u8>>() + 65536
        );
        assert!(creation_result(&Ok(())) == Creation::Created);
        assert!(creation_result(&Err(nix::errno::Errno::EEXIST)) == Creation::Absent);
        assert!(creation_result(&Err(nix::errno::Errno::EINTR)) == Creation::Unknown);
        assert!(creation_result(&Err(nix::errno::Errno::EIO)) == Creation::Unknown);
    }
}
