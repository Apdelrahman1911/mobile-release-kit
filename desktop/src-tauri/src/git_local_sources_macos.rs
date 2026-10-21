//! Fixed GitLocal child of the EXISTING SourceBook/Account/SnapshotBook.
//! No separate native IO executor. Original old index/ref descriptors survive
//! their exact acknowledged replacement and receive their original sole close.
//! A parsed child result or candidate alone never enables a source exception.
use super::*;
use crate::git_local_protocol as wire;
use crate::supervisor::GitLocalPublication;
use mrk_macos_installed_native::{
    local_account::Account,
    vault_filesystem::{Expected, Failure, Policy, SnapshotBook},
};
use sha2::{Digest, Sha256};
use std::time::Instant;
use zeroize::Zeroizing;

#[path="git_switch_sources_macos.rs"]
mod switch_sources;
#[path="git_rename_sources_macos.rs"]
mod rename_sources;
#[path="git_fast_forward_sources_macos.rs"]
mod fast_forward_sources;
#[path="git_init_sources_macos.rs"]
mod init_sources;
#[path="git_fetch_sources_macos.rs"]
mod fetch_sources;
#[path="git_push_sources_macos.rs"]
mod push_sources;
#[path="git_upstream_sources_macos.rs"]
mod upstream_sources;

#[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
#[path="git_fetch_observation_sources_macos.rs"]
mod fetch_observation;

#[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
#[path="git_push_observation_sources_macos.rs"]
mod push_observation;

const SOURCE_LIMIT: usize = 128;
struct RefEdge {
    parent: usize,
    name: Vec<u8>,
    original: Option<(usize, wire::Snapshot)>,
}
struct Replacement {
    old: Option<usize>,
    old_snapshot: Option<wire::Snapshot>,
    successor: usize,
    successor_snapshot: wire::Snapshot,
    intent: wire::Intent,
}
// Only the metadata part of the receipt-bound exception. This does not mint
// a replacement: the actual retained old FD and both byte hashes are still
// checked by snapshot_original/post_inner and closed by the original Book.
fn unlinked_original(current:FileIdentity,original:FileIdentity,successor:FileIdentity,flags:u64)->bool {
    current.common==original.common && current.nlink==0 && current.size==original.size
        && current.mtime==original.mtime && flags==0
        && (successor.common.dev!=current.common.dev || successor.common.ino!=current.common.ino)
}
// Comparison-only selection. Actual HEAD hashing, physical parent/absence
// checks and positive publication custody remain in the original SourceBook.
fn reference_selection(review:&wire::Review)->Result<(String,String,bool),Reason> {
    if !review.valid() {return Err(Reason::SourceRefused)}
    let head = match (review.branch(),review.head()) {
        (Some(reference),_)=>format!("ref: {reference}\n"),
        (None,Some(head)) if review.action()==wire::Kind::BranchCreate=>format!("{head}\n"),
        _=>return Err(Reason::SourceRefused),
    };
    let (name,absent) = match review {
        wire::Review::Branch(v)=>(v.target_ref.clone(),true),
        wire::Review::Files(v) if v.action==wire::Kind::Commit=>(v.branch.clone().ok_or(Reason::SourceRefused)?,false),
        _=>return Err(Reason::SourceRefused),
    };
    Ok((head,name,absent))
}
pub(crate) struct GitLocalSources {
    book: SourceBook,
    account: Account,
    acl: Option<SnapshotBook>,
    acl_entered: bool,
    started: bool,
    finished: bool,
    close_failed: bool,
    first: Option<Reason>,
    native: Option<wire::Native>,
    git: Option<usize>,
    indices: [Option<usize>; 4],
    operation_id: Option<String>,
    review: Option<wire::Review>,
    reference: Option<RefEdge>,
    replacement: Option<Replacement>,
    post_claimed: bool,
    switch:Option<switch_sources::State>,
    rename:Option<rename_sources::State>,
    fast_forward:Option<fast_forward_sources::State>,
    initialization:Option<init_sources::State>,
    fetch:Option<fetch_sources::State>,
    push:Option<push_sources::State>,
    upstream:Option<upstream_sources::State>,
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    push_observation:Option<std::sync::Arc<crate::shell::installed_observation::git_push::Control>>,
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    push_observation_file:Option<(usize,wire::Snapshot)>,
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    fetch_observation:Option<std::sync::Arc<crate::shell::installed_observation::git_fetch::Control>>,
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    fetch_observation_file:Option<(usize,wire::Snapshot)>,
}
impl Drop for GitLocalSources {
    fn drop(&mut self) {
        // Defensive retention only, never a successful closure or retry route.
        if !self.book.settled() {
            let book = std::mem::replace(&mut self.book, SourceBook::new());
            std::mem::forget(book);
        }
    }
}
impl GitLocalSources {
    pub(crate) fn new() -> Self {
        Self {
            book: SourceBook::new(),
            account: Account::new(),
            acl: None,
            acl_entered: false,
            started: false,
            finished: false,
            close_failed: false,
            first: None,
            native: None,
            git: None,
            indices: [None; 4],
            operation_id: None, review: None, reference: None, replacement: None,
            post_claimed: false, switch:None, rename:None, fast_forward:None,initialization:None,fetch:None,push:None,upstream:None,
            #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
            push_observation:None,
            #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
            push_observation_file:None,
            #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
            fetch_observation:None,
            #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
            fetch_observation_file:None,
        }
    }
    pub(crate) fn not_started(&self) -> bool {
        !self.started && !self.finished && !self.acl_entered && self.acl.is_none() && self.book.not_started()
    }
    fn fetch_observation_extra(&self)->usize {
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if self.fetch_observation.is_some(){return 1}
        0
    }
    fn push_observation_extra(&self)->usize {
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if self.push_observation.is_some(){return 1}
        0
    }
    pub(crate) fn working_bytes() -> Option<usize> {
        SOURCE_LIMIT
            .checked_mul(std::mem::size_of::<Descriptor>() + 255)?
            .checked_add(std::mem::size_of::<Self>() + 65536 + 5 * PATH_LIMIT + 4096)?
            .checked_add(if cfg!(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64"))){128}else{0})?
            .checked_add(if cfg!(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64"))){128}else{0})?
            .checked_add(mrk_macos_installed_native::vault_filesystem::SNAPSHOT_FRAME_BYTES)?
            .checked_add(switch_sources::State::working_bytes()?)?
            .checked_add(rename_sources::State::working_bytes()?)?
            .checked_add(fast_forward_sources::State::working_bytes()?)?
            .checked_add(fetch_sources::State::working_bytes()?)?
            .checked_add(push_sources::State::working_bytes()?)?
            .checked_add(upstream_sources::State::working_bytes()?)
    }
    pub(crate) fn first_failure(&self) -> Option<(Failure, Instant)> {
        self.acl.as_ref().and_then(SnapshotBook::first_failure)
    }
    pub(crate) fn mark_interrupted(&mut self) {
        self.first.get_or_insert(Reason::CleanupUnknown);
        self.close_failed = true;
    }
    fn remember<T>(&mut self, result: Result<T, Reason>) -> Result<T, Reason> {
        if let Err(reason) = &result {
            self.first.get_or_insert(*reason);
        }
        result
    }
    fn file(
        &mut self,
        parent: usize,
        name: &[u8],
        uid: u32,
        maximum: u64,
        executable: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize, Reason> {
        checkpoint(stop)?;
        let index = self.book.reserve(Some(parent), name)?;
        let before = stat::fstatat(self.book.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let expected = file_identity(&before)?;
        if expected.common.uid != uid
            || expected.nlink != 1
            || expected.common.mode & 0o7022 != 0
            || expected.size > maximum
            || executable && (expected.size == 0 || expected.common.mode & 0o111 == 0)
            || before.st_flags != 0
        {
            return Err(Reason::SourceRefused);
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
        checkpoint(stop)?;
        let named = stat::fstatat(self.book.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if file_identity(&held)? != expected || file_identity(&named)? != expected {
            return Err(Reason::SourceChanged);
        }
        self.book.slots[index].identity = Some(Identity::File(expected));
        Ok(index)
    }
    fn snapshot(&self, index: usize, maximum: u64, stop: &mut dyn FnMut() -> bool) -> Result<wire::Snapshot, Reason> {
        checkpoint(stop)?;
        let expected = match self.book.slots[index].identity {
            Some(Identity::File(value)) => value,
            _ => return Err(Reason::SourceChanged),
        };
        self.snapshot_identity(index, expected, maximum, stop)
    }
    fn snapshot_identity(&self, index: usize, expected: FileIdentity, maximum: u64,
        stop: &mut dyn FnMut() -> bool) -> Result<wire::Snapshot, Reason> {
        checkpoint(stop)?;
        if expected.size > maximum {
            return Err(Reason::Capacity);
        }
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if file_identity(&held)? != expected {
            return Err(Reason::SourceChanged);
        }
        let nanos = |v: (i64, i64)| -> Result<i64, Reason> {
            if !(0..1_000_000_000).contains(&v.1) {
                return Err(Reason::SourceRefused);
            }
            v.0.checked_mul(1_000_000_000)
                .and_then(|s| s.checked_add(v.1))
                .ok_or(Reason::SourceRefused)
        };
        unistd::lseek(self.book.fd(index)?, 0, unistd::Whence::SeekSet).map_err(|_| Reason::SourceRefused)?;
        let mut buffer = Zeroizing::new([0u8; 32768]);
        let mut hash = Sha256::new();
        let mut count = 0u64;
        loop {
            checkpoint(stop)?;
            let count_now = unistd::read(self.book.fd(index)?, &mut buffer[..]).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if count_now == 0 {
                break;
            }
            count = count.checked_add(count_now as u64).ok_or(Reason::Capacity)?;
            if count > expected.size {
                return Err(Reason::SourceChanged);
            }
            hash.update(&buffer[..count_now]);
        }
        let after = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if count != expected.size || file_identity(&after)? != expected {
            return Err(Reason::SourceChanged);
        }
        Ok(wire::Snapshot {
            identity: (
                expected.common.dev,
                expected.common.ino,
                expected.common.mode,
                expected.common.uid,
                expected.common.gid,
                expected.nlink,
                expected.size,
                nanos(expected.mtime)?,
                nanos(expected.ctime)?,
            ),
            sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        })
    }
    fn capture_reference(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let review = self.review.as_ref().ok_or(Reason::SourceRefused)?;
        // HEAD binds the reviewed SOURCE, not the new target. No checkout.
        let (original_head,name,absent) = reference_selection(review)?;
        if !crate::git_read_protocol::branch(&name) || name.split('/').count() > 32 {
            return Err(Reason::SourceRefused);
        }
        let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
        let sha = |bytes: &[u8]| -> String { Sha256::digest(bytes).iter().map(|b|format!("{b:02x}")).collect() };
        if native.files.head.sha256 != sha(original_head.as_bytes()) {
            return Err(Reason::SourceChanged);
        }
        let uid = native.uid;
        let expected = review.head().map(|head| sha(format!("{head}\n").as_bytes()));
        let parts: Vec<Vec<u8>> = name.split('/').map(|v|v.as_bytes().to_vec()).collect();
        let mut parent = self.git.ok_or(Reason::SourceChanged)?;
        // Only existing physical parents. No nested-parent creation, custom
        // resolver or target directory replacement is admitted for branches.
        for part in &parts[..parts.len()-1] { parent = self.book.child(parent, part, false, stop)?; }
        let leaf = parts.last().ok_or(Reason::SourceRefused)?.clone();
        checkpoint(stop)?;
        let original = match stat::fstatat(self.book.fd(parent)?, OsStr::from_bytes(&leaf), AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(nix::errno::Errno::ENOENT) => None,
            Ok(_) if absent => return Err(Reason::SourceChanged),
            Ok(_) => {
                let index = self.file(parent, &leaf, uid, 65, false, stop)?;
                let snapshot = self.snapshot(index, 65, stop)?;
                if expected.as_ref() != Some(&snapshot.sha256) { return Err(Reason::SourceChanged); }
                Some((index, snapshot))
            }
            Err(_) => return Err(Reason::SourceRefused),
        };
        // A missing loose ref says nothing about packed refs. The SAME fixed
        // core inventory and expected-zero (create)/old (commit) CAS decide.
        self.reference = Some(RefEdge { parent, name:leaf, original });
        checkpoint(stop)
    }

    fn old_identity(&self, index: usize, held: &FileStat) -> Result<FileIdentity, Reason> {
        let replacement = self.replacement.as_ref().filter(|v|v.old == Some(index)).ok_or(Reason::SourceChanged)?;
        let original = match self.book.slots[index].identity { Some(Identity::File(v)) => v, _ => return Err(Reason::SourceChanged) };
        let current = file_identity(held)?;
        let Some(Identity::File(successor))=self.book.slots[replacement.successor].identity else {return Err(Reason::SourceChanged)};
        if replacement.old_snapshot.is_none() || !unlinked_original(current,original,successor,held.st_flags as u64) {
            return Err(Reason::SourceChanged);
        }
        Ok(current)
    }
    fn snapshot_original(&self, index: usize, maximum: u64, stop: &mut dyn FnMut() -> bool) -> Result<wire::Snapshot, Reason> {
        if self.upstream_is_old(index) {return self.upstream_snapshot_original(index,maximum,stop)}
        if self.fetch_is_old(index) {return self.fetch_snapshot_original(index,maximum,stop)}
        if self.fast_forward_is_old(index) {return self.fast_forward_snapshot_original(index,maximum,stop)}
        if self.rename_is_old(index) {return self.rename_snapshot_original(index,maximum,stop)}
        if self.switch_is_old(index) {return self.switch_snapshot_original(index,maximum,stop)}
        let Some(replacement) = self.replacement.as_ref().filter(|v|v.old==Some(index)) else {return self.snapshot(index,maximum,stop)};
        checkpoint(stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        let actual = self.old_identity(index,&held)?;
        let hashed = self.snapshot_identity(index,actual,maximum,stop)?;
        let original = replacement.old_snapshot.as_ref().ok_or(Reason::SourceChanged)?;
        if hashed.sha256 != original.sha256 {return Err(Reason::SourceChanged)}
        // Comparison projection only. The actual descriptor/identity slot is
        // never replaced or reset; its original sole close remains in Book.
        Ok(original.clone())
    }

    /// Called only by the original native-settlement arm after its actual
    /// child/pipe/ACK jobs returned. Publication is a private original-native
    /// witness; candidate-shaped DATA alone cannot call this exception.
    pub(crate) fn post_returned(&mut self, publication: Option<&GitLocalPublication>,
        stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if self.finished || self.first.is_some() || self.post_claimed {
            if self.upstream.is_some() {self.retain_upstream_unknown();return Err(Reason::CleanupUnknown)}
            if self.fetch_holds_marker() {self.retain_fetch_unknown();return Err(Reason::CleanupUnknown)}
            if self.fast_forward.is_some() {self.retain_fast_forward_unknown();return Err(Reason::CleanupUnknown)}
            if self.rename.is_some() {self.retain_rename_unknown();return Err(Reason::CleanupUnknown)}
            if self.switch.is_some() {self.retain_switch_unknown();return Err(Reason::CleanupUnknown)}
            return Err(Reason::SourceChanged)
        }
        self.post_claimed = true;
        let result = (|| {
            if self.initialization.is_some() {return self.init_returned(publication,stop)}
            if let Some(publication) = publication {
                let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
                let review = self.review.as_ref().ok_or(Reason::SourceChanged)?;
                if review.action()==wire::Kind::SetUpstream {self.upstream_returned(publication,stop)?;return self.post_inner(stop)}
                if review.action().is_push() {self.push_returned(publication,stop)?;return self.post_inner(stop)}
                if review.action()==wire::Kind::Fetch {
                    self.fetch_returned(publication,stop)?;return self.post_inner(stop)
                }
                if review.action()==wire::Kind::FastForward {
                    self.fast_forward_returned(publication,stop)?;return self.post_inner(stop)
                }
                if review.action()==wire::Kind::BranchRename {
                    self.rename_returned(publication,stop)?;return self.post_inner(stop)
                }
                if review.action()==wire::Kind::BranchSwitch {
                    self.switch_returned(publication,stop)?;return self.post_inner(stop)
                }
                let intent = publication.intent_for(self.operation_id.as_deref().ok_or(Reason::SourceChanged)?,native,review)?.clone();
                if self.replacement.is_some() {return Err(Reason::SourceChanged)}
                let uid = native.uid;
                let (parent,name,old,old_snapshot,expected,maximum) = match intent.action() {
                    wire::Kind::Commit|wire::Kind::BranchCreate=>{
                        let edge = self.reference.as_ref().ok_or(Reason::SourceChanged)?;
                        if intent.action()==wire::Kind::BranchCreate && edge.original.is_some() {return Err(Reason::SourceChanged)}
                        let head = intent.reference_oid().ok_or(Reason::SourceChanged)?;
                        let digest = Sha256::digest(format!("{head}\n").as_bytes()).iter().map(|b|format!("{b:02x}")).collect::<String>();
                        (edge.parent,edge.name.clone(),edge.original.as_ref().map(|v|v.0),edge.original.as_ref().map(|v|v.1.clone()),digest,65)
                    },
                    wire::Kind::Stage|wire::Kind::Unstage=>{
                        (self.git.ok_or(Reason::SourceChanged)?,b"index".to_vec(),self.indices[3],native.files.index.clone(),
                            intent.candidate_index().ok_or(Reason::SourceChanged)?.to_owned(),wire::INDEX_LIMIT)
                    },
                    wire::Kind::BranchSwitch|wire::Kind::BranchRename|wire::Kind::FastForward|wire::Kind::Initialize|wire::Kind::Fetch|wire::Kind::Push|wire::Kind::PushNewBranch|wire::Kind::SetUpstream=>return Err(Reason::SourceChanged),
                };
                let successor = self.file(parent,&name,uid,maximum,false,stop)?;
                let successor_snapshot = self.snapshot(successor,maximum,stop)?;
                if successor_snapshot.sha256 != expected {return Err(Reason::SourceChanged)}
                self.replacement = Some(Replacement {old,old_snapshot,successor,successor_snapshot,intent});
            }
            self.post_inner(stop)
        })();
        if result.is_err() && self.upstream.is_some() {self.retain_upstream_unknown();return Err(Reason::CleanupUnknown)}
        if result.is_err() && self.fetch_holds_marker() {self.retain_fetch_unknown();return Err(Reason::CleanupUnknown)}
        if result.is_err() && self.initialization.is_some() {self.first=Some(Reason::CleanupUnknown);self.close_failed=true;return Err(Reason::CleanupUnknown)}
        // After a child return, a missing/failed exact switch-source rematch
        // cannot release the target lock as a harmless stale-source refusal.
        if result.is_err() && self.fast_forward.is_some() {self.retain_fast_forward_unknown();return Err(Reason::CleanupUnknown)}
        if result.is_err() && self.rename.is_some() {self.retain_rename_unknown();return Err(Reason::CleanupUnknown)}
        if result.is_err() && self.switch.is_some() {self.retain_switch_unknown();return Err(Reason::CleanupUnknown)}
        self.remember(result)
    }
    pub(crate) fn inspect(&mut self, root: &RegisteredRoot, runtime_live: usize, id: &str,
        kind:wire::Kind, review: Option<&wire::Review>, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if !self.not_started() {
            return Err(Reason::CleanupUnknown);
        }
        self.started = true;
        let result = (|| {
            checkpoint(stop)?;
            if !crate::protocol::valid_id(id) || review.is_some_and(|v| !v.valid() || v.action()!=kind) { return Err(Reason::SourceRefused); }
            self.operation_id = Some(id.into()); self.review = review.cloned();
            self.account.acquire().map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let (_, uid, gid) = self.account.selected().map_err(|_| Reason::SourceRefused)?;
            let project_parts = parts(&root.path)?;
            let tool_parts = parts(Path::new(wire::TOOL_PATH))?;
            let parent_parts = &tool_parts[..tool_parts.len() - 1];
            let extra=(42usize).checked_add(source_extra(&project_parts))
                .and_then(|n|n.checked_add(self.fetch_observation_extra()))
                .and_then(|n|n.checked_add(self.push_observation_extra()))
                .and_then(|n|switch_sources::State::extra(review).and_then(|s|n.checked_add(s)))
                .and_then(|n|rename_sources::State::extra(review).and_then(|s|n.checked_add(s)))
                .and_then(|n|fast_forward_sources::State::extra(review).and_then(|s|n.checked_add(s)))
                .and_then(|n|n.checked_add(init_sources::State::extra(kind)))
                .and_then(|n|fetch_sources::State::extra(kind,review).and_then(|s|n.checked_add(s)))
                .and_then(|n|push_sources::State::extra(kind,review).and_then(|s|n.checked_add(s)))
                .and_then(|n|n.checked_add(self.upstream.as_ref().map_or(Some(0),upstream_sources::State::extra)?)).ok_or(Reason::Capacity)?;
            let capacity = roster_limit([project_parts.len(), parent_parts.len()], extra)?;
            if capacity > SOURCE_LIMIT
                || capacity
                    .checked_add(runtime_live)
                    .and_then(|n| n.checked_add(32))
                    .is_none_or(|n| n > 256)
            {
                return Err(Reason::Capacity);
            }
            self.book.begin(capacity, 0, 1)?;
            self.acl_entered = true;
            self.acl = Some(SnapshotBook::new());
            self.book.root(stop)?;
            self.book.anchor_private(stop)?;
            let (project_chain, _) = self.book.chain(&project_parts, true, stop)?;
            let project = *project_chain.last().ok_or(Reason::SourceRefused)?;
            if self.book.directory(project)? != root.identity.posix()? {
                return Err(Reason::SourceChanged);
            }
            // Ordinary repository opens/order stay unchanged. Init has no
            // existing Git directory and must never manufacture these facts.
            let ordinary=if kind!=wire::Kind::Initialize {
                let git=self.book.child(project,b".git",false,stop)?;self.git=Some(git);
                Some((git,self.book.child(git,b"objects",false,stop)?))
            } else {None};
            let (tool_chain, _) = self.book.chain(parent_parts, false, stop)?;
            // This fixed provider is not nominated through a user-writable
            // executable prefix. Held and named identities are rechecked by
            // post_inner; the Python worker freezes and verifies the same tool.
            for index in &tool_chain {
                let directory = self.book.directory(*index)?;
                if directory.uid != 0 || directory.mode & 0o7022 != 0 {
                    return Err(Reason::SourceRefused);
                }
            }
            let tool_parent = *tool_chain.last().ok_or(Reason::SourceRefused)?;
            let tool = self.file(tool_parent, b"git", 0, wire::TOOL_LIMIT, true, stop)?;
            self.indices[0] = Some(tool);
            if kind==wire::Kind::Initialize {return self.inspect_init(root,project_chain,tool,uid,gid,stop)}
            let (git,objects)=ordinary.ok_or(Reason::SourceRefused)?;
            let head = self.file(git, b"HEAD", uid, 2048, false, stop)?;
            self.indices[1] = Some(head);
            let config = self.file(git, b"config", uid, 65536, false, stop)?;
            self.indices[2] = Some(config);
            checkpoint(stop)?;
            match stat::fstatat(self.book.fd(git)?, "index", AtFlags::AT_SYMLINK_NOFOLLOW) {
                Err(nix::errno::Errno::ENOENT) => {}
                Ok(_) => {
                    self.indices[3] = Some(self.file(git, b"index", uid, wire::INDEX_LIMIT, false, stop)?);
                }
                Err(_) => return Err(Reason::SourceRefused),
            }
            let directory = |index| -> Result<wire::DirectoryIdentity, Reason> {
                let d = self.book.directory(index)?;
                Ok((d.dev, d.ino, d.mode, d.uid, d.gid))
            };
            let native = wire::Native {
                uid,
                gid,
                root: root.path.to_str().ok_or(Reason::SourceRefused)?.into(),
                directories: wire::Directories {
                    root: directory(project)?,
                    git: directory(git)?,
                    objects: directory(objects)?,
                },
                tool: self.snapshot(tool, wire::TOOL_LIMIT, stop)?,
                files: wire::Files {
                    head: self.snapshot(head, 2048, stop)?,
                    config: self.snapshot(config, 65536, stop)?,
                    index: self.indices[3].map(|i| self.snapshot(i, wire::INDEX_LIMIT, stop)).transpose()?,
                },
            };
            if !native.valid() {
                return Err(Reason::SourceRefused);
            }
            self.native = Some(native);
            if kind==wire::Kind::Fetch {self.capture_fetch(objects,stop)?;}
            if kind.is_push() {self.capture_push(kind,stop)?;}
            if review.is_some_and(|v|v.action()==wire::Kind::FastForward) {self.capture_fast_forward(project,stop)?;}
            if review.is_some_and(|v|v.action()==wire::Kind::BranchRename) {self.capture_rename(stop)?;}
            if review.is_some_and(|v|v.action()==wire::Kind::BranchSwitch) {self.capture_switch(project,stop)?;}
            if review.is_some_and(|v| matches!(v.action(),wire::Kind::Commit|wire::Kind::BranchCreate)) { self.capture_reference(stop)?; }
            if self.upstream.is_some(){self.capture_upstream(stop)?;}
            self.post_inner(stop)
        })();
        self.remember(result)
    }
    fn post_inner(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let (_, uid, _) = self.account.selected().map_err(|_| Reason::SourceChanged)?;
        for index in 0..self.book.slots.len() {
            checkpoint(stop)?;
            let slot = &self.book.slots[index];
            let expected = slot.identity.ok_or(Reason::SourceChanged)?;
            let file = matches!(expected, Identity::File(_));
            let fd = self.book.fd(index)?;
            filesystem(fd, stop)?;
            let held = stat::fstat(fd).map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if self.upstream_is_retired_working(index) {
                self.upstream_retired_identity(index,&held)?;
            } else if self.upstream_is_old(index) {
                self.upstream_old_identity(index,&held)?;
            } else if self.fetch_is_old(index) {
                self.fetch_old_identity(index,&held)?;
            } else if self.fast_forward_is_old(index) {
                self.fast_forward_old_identity(index,&held)?;
            } else if self.rename_is_old(index) {
                self.rename_old_identity(index,&held)?;
            } else if self.switch_is_old(index) {
                self.switch_old_identity(index,&held)?;
            } else if self.replacement.as_ref().is_some_and(|v|v.old==Some(index)) {
                self.old_identity(index,&held)?;
            } else {
                let named = if let Some((parent,name))=self.init_named(index) {
                    stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(name),AtFlags::AT_SYMLINK_NOFOLLOW)
                } else if let Some(parent) = slot.parent {
                    stat::fstatat(self.book.fd(parent)?, OsStr::from_bytes(&slot.name), AtFlags::AT_SYMLINK_NOFOLLOW)
                } else { stat::lstat(Path::new("/")) }.map_err(|_|Reason::SourceChanged)?;
                checkpoint(stop)?;
                if identity(&held,file)? != expected || identity(&named,file)? != expected
                    || held.st_flags != 0 || named.st_flags != 0 { return Err(Reason::SourceChanged); }
            }
            if held.st_uid != 0 && held.st_uid != uid {
                return Err(Reason::SourceChanged);
            }
            // Existing protected temporary ancestors may be sticky; no other
            // group/other writable directory can nominate a Git executable.
            if held.st_mode & 0o7022 != 0 && !(slot.role == PhysicalRole::Tmp && held.st_mode & 0o1000 != 0) {
                return Err(Reason::SourceRefused);
            }
            let actual = common(&held)?;
            self.acl
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .observe(
                    fd.as_fd(),
                    Expected {
                        device: actual.dev,
                        inode: actual.ino,
                        mode: actual.mode,
                        owner: actual.uid,
                        group: actual.gid,
                        flags: held.st_flags,
                    },
                    if file { Policy::Empty } else { Policy::Ancestors },
                    stop,
                )
                .map_err(|failure| {
                    if failure == Failure::Unknown {
                        Reason::CleanupUnknown
                    } else {
                        Reason::SourceRefused
                    }
                })?;
            checkpoint(stop)?;
        }
        for alias in &self.book.aliases {
            self.book.check_alias(alias, stop)?;
        }
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        self.post_fetch_observation(stop)?;
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        self.post_push_observation(stop)?;
        if self.initialization.is_some() {return self.post_init(stop)}
        let original = self.native.as_ref().ok_or(Reason::SourceChanged)?;
        for (index, expected, maximum) in [
            (self.indices[0], Some(&original.tool), wire::TOOL_LIMIT),
            (self.indices[1], Some(&original.files.head), 2048),
            (self.indices[2], Some(&original.files.config), 65536),
            (self.indices[3], original.files.index.as_ref(), wire::INDEX_LIMIT),
        ] {
            match (index, expected) {
                (Some(index), Some(expected)) if self.snapshot_original(index, maximum, stop)? == *expected => {}
                (None, None) if self.replacement.as_ref().is_some_and(|v|matches!(v.intent.action(),wire::Kind::Stage|wire::Kind::Unstage)) => {}
                (None, None) => {
                    checkpoint(stop)?;
                    if !matches!(
                        stat::fstatat(
                            self.book.fd(self.git.ok_or(Reason::SourceChanged)?)?,
                            "index",
                            AtFlags::AT_SYMLINK_NOFOLLOW
                        ),
                        Err(nix::errno::Errno::ENOENT)
                    ) {
                        return Err(Reason::SourceChanged);
                    }
                    checkpoint(stop)?;
                }
                _ => return Err(Reason::SourceChanged),
            }
        }
        if let Some(edge) = &self.reference {
            if let Some((index,expected)) = &edge.original {
                if self.snapshot_original(*index,65,stop)? != *expected {return Err(Reason::SourceChanged)}
            } else if !self.replacement.as_ref().is_some_and(|v|matches!(v.intent.action(),wire::Kind::Commit|wire::Kind::BranchCreate)) {
                checkpoint(stop)?;
                if !matches!(stat::fstatat(self.book.fd(edge.parent)?,OsStr::from_bytes(&edge.name),AtFlags::AT_SYMLINK_NOFOLLOW),
                    Err(nix::errno::Errno::ENOENT)) {return Err(Reason::SourceChanged)}
                checkpoint(stop)?;
            }
        }
        if let Some(replacement) = &self.replacement {
            let maximum = if matches!(replacement.intent.action(),wire::Kind::Commit|wire::Kind::BranchCreate) {65} else {wire::INDEX_LIMIT};
            if self.snapshot(replacement.successor,maximum,stop)? != replacement.successor_snapshot {return Err(Reason::SourceChanged)}
        }
        self.post_fast_forward(stop)?;
        self.post_switch(stop)?;
        self.post_rename(stop)?;
        self.post_fetch(stop)?;
        self.post_push(stop)?;
        self.post_upstream(stop)
    }
    pub(crate) fn post(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if self.finished || self.first.is_some() || self.post_claimed {
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
    pub(crate) fn close(&mut self, expired: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool) -> Result<(), Reason> {
        if self.finished {
            return if self.settled() { Ok(()) } else { Err(Reason::CleanupUnknown) };
        }
        self.finished = true;
        self.close_failed = true;
        if !self.account.call_settled() || self.first == Some(Reason::CleanupUnknown) || self.acl_entered && self.acl.is_none() {
            return Err(Reason::CleanupUnknown);
        }
        if !self.upstream_retirable(){return Err(Reason::CleanupUnknown)}
        let original_failure=self.first_failure();
        if self.retire_init(&mut ||expired(original_failure)).is_err() {return Err(Reason::CleanupUnknown)}
        if let Some(acl) = self.acl.as_mut() {
            if !acl.release(expired) || !acl.settled() {
                return Err(Reason::CleanupUnknown);
            }
        }
        if expired(self.first_failure()) || !self.close_fetch_book(expired) || expired(self.first_failure()) {
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
            && self.init_retired()
            && self.upstream_retirable()
            && (!self.acl_entered || self.acl.as_ref().is_some_and(SnapshotBook::settled))
    }
}

#[cfg(test)]
#[path="git_local_sources_macos_tests.rs"]
mod tests;

#[cfg(test)]
#[path="git_branch_source_tests.rs"]
mod branch_tests;
