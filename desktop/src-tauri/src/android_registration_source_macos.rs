//! One read-only picked-tool source original, distinct from credential SourceBook.
//! Native calls enter only on its already registered source worker after GO.
//! Complete selected closures and the planned payload-ordinal frontier have
//! separate original records; neither is a retry/rescue for a failed read.
#![forbid(unsafe_code)]
use super::*;
use std::{cmp::Ordering, mem::size_of};
use crate::{
    android_supplier_macos::{self as supplier, Recipe, ProposalDocuments},
    android_supplier_macos_source::*,
    android_toolchain_macos_policy::{self as policy, Alias, FileSpec},
    android_registration_app_protocol as app,
    android_tool_sources::Role,
    asset_source::RegisteredRoot,
};

const LIVE_FDS: usize = 64;
const SDK_METADATA_BYTES: usize = 32 * 1024;
// Optional package.xml originals are read once during this source's complete
// selected-package pass; generated payloads open no second picked descriptor.
const ORIGINALS: usize = 2 * policy::ENTRY_LIMIT + 512 + 2;
const ANCESTORS: usize = 48;
const BLOCK: usize = 65536;
const READ_LIMIT: u64 = 4 * policy::TOTAL_LIMIT;
const NATIVE_HEADER: usize = 256 * 1024 + 32;
const NATIVE_PARSE: usize = 4 * 1024 * 1024;
type Publish<'a> = dyn FnMut(AdmissionFailure, Instant) + 'a;

/// Source can emit file bytes, never shared Finish or a source-join receipt.
pub(crate) trait PayloadSink {
    fn begin(&mut self, ordinal: u32, bytes: u64) -> Result<()>;
    fn chunk(&mut self, bytes: &[u8]) -> Result<()>;
    fn end(&mut self, ordinal: u32, bytes: u64) -> Result<()>;
}
enum Name { Static(&'static str), Owned(String) }
impl Name { fn text(&self) -> &str { match self { Self::Static(v) => v, Self::Owned(v) => v } } }
struct Original {
    state: State, fd: Option<OwnedFd>, parent: Option<usize>, name: Name,
    identity: Option<Identity>, selected: bool, readonly: bool, retained: bool,
}
struct AliasOriginal { parent: usize, name: &'static str, identity: Identity, target: String }
enum MemberKind { Directory(u32), File(FileSpec), Alias(Alias, u32) }
struct Member { group: SourceGroup, relative: &'static str, identity: Identity, kind: MemberKind }
impl Member {
    fn data(&self) -> SourceMemberData<'_> {
        SourceMemberData { group: self.group, kind: match &self.kind {
            MemberKind::Directory(mode) => SourceMemberKind::Directory { relative: self.relative, mode: *mode },
            MemberKind::File(file) => SourceMemberKind::File(file),
            MemberKind::Alias(data, mode) => SourceMemberKind::Alias { data, mode: *mode },
        } }
    }
    fn same(&self, other: &Self) -> bool {
        self.group == other.group && self.relative == other.relative && self.identity == other.identity
            && match (&self.kind, &other.kind) {
                (MemberKind::Directory(a), MemberKind::Directory(b)) => a == b,
                (MemberKind::File(a), MemberKind::File(b)) => file_same(a, b),
                (MemberKind::Alias(a, am), MemberKind::Alias(b, bm)) =>
                    am == bm && a.path == b.path && a.target == b.target && a.canonical == b.canonical,
                _ => false,
            }
    }
    fn heap_bytes(&self) -> Option<usize> {
        match &self.kind {
            MemberKind::Directory(_) => Some(0),
            MemberKind::File(file) => file.path.capacity().checked_add(file.sha256.capacity()),
            MemberKind::Alias(alias, _) => alias.path.capacity().checked_add(alias.target.capacity())?.checked_add(alias.canonical.capacity()),
        }
    }
}
#[derive(Clone, Copy, Default)]
struct Count { bytes: u64, files: u32, entries: u32, aliases: u32 }
struct ProviderFile { identity: Identity, file: FileSpec }
/// Genuine optional picked DATA, never generated-payload or consent authority.
/// Its original identity/whole bytes survive the SAME consuming close in Review.
struct ObservedSdkMetadata { identity: Identity, file: FileSpec, contents: Vec<u8> }
impl ObservedSdkMetadata {
    fn data(&self) -> PickedSdkMetadataData<'_> {
        PickedSdkMetadataData { file: &self.file, contents: &self.contents }
    }
    fn same(&self, other: &Self) -> bool {
        self.identity == other.identity && file_same(&self.file, &other.file) && self.contents == other.contents
    }
    fn heap_bytes(&self) -> Option<usize> {
        self.file.path.capacity().checked_add(self.file.sha256.capacity())?.checked_add(self.contents.capacity())
    }
}
fn optional_sdk_metadata_reservation_bytes() -> Option<usize> {
    // Two retained Review originals plus two fresh reproof originals. Fixed
    // inline records are conservatively included with their path/hash storage;
    // neither generated XML nor an opaque native allocation is substituted.
    4usize.checked_mul(SDK_METADATA_BYTES.checked_add(size_of::<ObservedSdkMetadata>())?
        .checked_add(size_of::<Identity>() + size_of::<PickedSdkMetadataData<'static>>())?
        .checked_add(512 + 64)?)
}
struct Closure {
    roots: [Vec<Identity>; 3], members: Vec<Member>, provider_roots: Vec<Identity>, provider: Vec<ProviderFile>,
    counts: [Count; 3], layout: JdkLayout,
    optional_sdk_metadata: [Option<ObservedSdkMetadata>; 2],
    sdk_metadata_parents: [Identity; 2],
}
impl Closure {
    fn same(&self, other: &Self) -> bool {
        self.layout == other.layout && self.roots == other.roots && self.provider_roots == other.provider_roots
            && self.sdk_metadata_parents == other.sdk_metadata_parents
            && self.optional_sdk_metadata.iter().zip(&other.optional_sdk_metadata).all(|(old, new)| match (old, new) {
                (None, None) => true, (Some(old), Some(new)) => old.same(new), _ => false,
            })
            && self.members.len() == other.members.len()
            && self.members.iter().zip(&other.members).all(|(a, b)| a.same(b))
            && self.provider.len() == other.provider.len()
            && self.provider.iter().zip(&other.provider).all(|(a, b)| a.identity == b.identity && file_same(&a.file, &b.file))
    }
    fn retained_bytes(&self) -> Option<usize> {
        let mut bytes = size_of::<Self>().checked_add(self.members.capacity().checked_mul(size_of::<Member>())?)?
            .checked_add(self.provider.capacity().checked_mul(size_of::<ProviderFile>())?)?
            .checked_add(self.provider_roots.capacity().checked_mul(size_of::<Identity>())?)?;
        for chain in &self.roots { bytes = bytes.checked_add(chain.capacity().checked_mul(size_of::<Identity>())?)?; }
        for member in &self.members { bytes = bytes.checked_add(member.heap_bytes()?)?; }
        for metadata in self.optional_sdk_metadata.iter().flatten() { bytes = bytes.checked_add(metadata.heap_bytes()?)?; }
        for file in &self.provider { bytes = bytes.checked_add(file.file.path.capacity())?.checked_add(file.file.sha256.capacity())?; }
        Some(bytes)
    }
}
/// Frozen complete comparison data. No live reader is moved into Review.
pub(crate) struct SourceReview {
    recipe: Recipe, closure: Closure, support: FixedSupportReview, proposal: ProposalDocuments,
    account: u32, instance: String,
}
impl SourceReview {
    pub(crate) fn proposal(&self) -> &ProposalDocuments { &self.proposal }
    pub(crate) fn account(&self) -> u32 { self.account }
    pub(crate) fn instance(&self) -> &str { &self.instance }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        size_of::<Self>().checked_add(self.closure.retained_bytes()?.checked_sub(size_of::<Closure>())?)?
            .checked_add(self.support.retained_bytes()?.checked_sub(size_of::<FixedSupportReview>())?)?
            .checked_add(self.proposal.retained_bytes()?.checked_sub(size_of::<ProposalDocuments>())?)?
            .checked_add(self.instance.capacity())
    }
    pub(crate) fn sources(&self) -> Vec<app::Source> {
        [Role::Jdk, Role::Sdk, Role::Gradle].into_iter().zip(self.closure.counts)
            .zip(self.recipe.source_versions()).map(|((role, count), version)| app::Source {
                role, version: Some(version.to_owned()), logical_bytes: count.bytes as u32, files: count.files,
                entries: count.entries, aliases: count.aliases, complete: true, compatibility: app::Compatibility::Compatible,
            }).collect()
    }
}
pub(crate) struct SourceSlots {
    originals: Vec<Original>, aliases: Vec<AliasOriginal>, roots: [Option<usize>; 3],
    observed: Vec<Option<Member>>, closure: Option<Closure>, recipe: Option<Recipe>,
    optional_sdk_metadata: [Option<ObservedSdkMetadata>; 2],
    // None here means UNPROVED, not absence. Only a complete selected-parent
    // walk followed by that SAME parent's POST installs an identity in a slot.
    sdk_metadata_parents: [Option<Identity>; 2],
    proposal: Option<ProposalDocuments>, instance: Option<String>, support: FixedSupportSlots,
    frame: Option<SnapshotBook>, frame_entered: bool, frame_settled: bool, live: usize, read_bytes: u64,
    account: Option<u32>, begun: bool, settled: bool, unknown: bool, reproof: bool, streamed: bool,
    first: Option<(AdmissionFailure, Instant)>, audit: watch::Receiver<Instant>,
    gate: Option<crate::saved_command_owner::AndroidRegistrationWorkGate>,
}
impl SourceSlots {
    #[cfg(test)]
    pub(crate) fn new(audit: watch::Receiver<Instant>) -> Self {
        Self::new_original(audit,None)
    }
    pub(crate) fn new_registered(audit:watch::Receiver<Instant>,gate:crate::saved_command_owner::AndroidRegistrationWorkGate)->Self{
        Self::new_original(audit,Some(gate))
    }
    fn new_original(audit:watch::Receiver<Instant>,gate:Option<crate::saved_command_owner::AndroidRegistrationWorkGate>)->Self{
        Self { originals: Vec::new(), aliases: Vec::new(), roots: [None; 3], observed: Vec::new(),
            closure: None, recipe: None, optional_sdk_metadata: [None, None], sdk_metadata_parents: [None; 2],
            proposal: None, instance: None, support: FixedSupportSlots::new_registered(gate.clone()),
            frame: None, frame_entered: false, frame_settled: false, live: 0, read_bytes: 0, account: None,
            begun: false, settled: false, unknown: false, reproof: false, streamed: false, first: None, audit, gate }
    }
    /// App-owned maximum including two planned descriptor passes, all original
    /// identities and simultaneous borrowed proposal views. Opaque native
    /// allocation admission remains separate and cannot be fabricated here.
    pub(crate) fn working_reservation_bytes() -> Option<usize> {
        size_of::<Self>().checked_add(ORIGINALS.checked_mul(size_of::<Original>())?)?
            .checked_add((policy::ENTRY_LIMIT + 256).checked_mul(size_of::<Member>() + size_of::<Option<Member>>()
                + size_of::<SourceMemberData<'static>>())?)?
            .checked_add(policy::FILE_COUNT.checked_mul(512 + 64)?)?
            .checked_add(policy::ALIAS_COUNT.checked_mul(size_of::<AliasOriginal>() + 3 * 512)?)?
            .checked_add(512 * 255 + (3 * (ANCESTORS + 4) + 128) * size_of::<Identity>() + 16 * size_of::<(SourceGroup, &'static str, usize)>())?
            .checked_add(18 * BLOCK + NATIVE_HEADER + NATIVE_PARSE)?
            .checked_add(policy::OS_FILES.len().checked_mul(2 * size_of::<FileSpec>() + size_of::<ProviderFile>() + 2 * (512 + 64))?)?
            .checked_add(FixedSupportSlots::working_reservation_bytes()?)?
            .checked_add(optional_sdk_metadata_reservation_bytes()?)?
            .checked_add(size_of::<SourceReview>() + size_of::<Closure>() + 65536 + 4096)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let native = if self.settled {
            if !self.frame_settled { return None; } 0
        } else { match &self.frame {
            Some(frame) if frame.quiescent() => frame.retained_frame_bytes(),
            None if !self.frame_entered => 0, _ => return None,
        } };
        if self.unknown { return None; }
        let mut bytes = size_of::<Self>().checked_add(native)?
            .checked_add(self.originals.capacity().checked_mul(size_of::<Original>())?)?
            .checked_add(self.aliases.capacity().checked_mul(size_of::<AliasOriginal>())?)?
            .checked_add(self.observed.capacity().checked_mul(size_of::<Option<Member>>())?)?
            .checked_add(self.support.retained_bytes()?.checked_sub(size_of::<FixedSupportSlots>())?)?;
        for original in &self.originals { if let Name::Owned(name) = &original.name { bytes = bytes.checked_add(name.capacity())?; } }
        for alias in &self.aliases { bytes = bytes.checked_add(alias.target.capacity())?; }
        for member in self.observed.iter().flatten() { bytes = bytes.checked_add(member.heap_bytes()?)?; }
        for metadata in self.optional_sdk_metadata.iter().flatten() { bytes = bytes.checked_add(metadata.heap_bytes()?)?; }
        if let Some(closure) = &self.closure { bytes = bytes.checked_add(closure.retained_bytes()?.checked_sub(size_of::<Closure>())?)?; }
        if let Some(proposal) = &self.proposal { bytes = bytes.checked_add(proposal.retained_bytes()?.checked_sub(size_of::<ProposalDocuments>())?)?; }
        if let Some(instance) = &self.instance { bytes = bytes.checked_add(instance.capacity())?; }
        Some(bytes)
    }
    pub(crate) fn first_failure(&self) -> Option<(AdmissionFailure, Instant)> {
        let first=earliest_failure(self.first,self.gate.as_ref().and_then(|gate|gate.source_first()));
        if self.settled { return first; }
        earliest_failure(earliest_failure(first, self.support.first_failure()),
            self.frame.as_ref().and_then(SnapshotBook::first_failure).map(|(f, at)| (map_acl_failure(f), at)))
    }
    fn note(&mut self, failure: AdmissionFailure, at: Instant, publish: &mut Publish<'_>) {
        self.first = earliest_failure(self.first_failure(), Some((failure, at)));
        if failure == AdmissionFailure::Unknown { self.unknown = true; }
        if let Some(gate)=&self.gate{gate.source_note(failure,at);}
        if let Some((failure, at)) = self.first { publish(failure, at); }
    }
    fn point(&self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if self.unknown || self.settled || self.audit.has_changed().is_err() { return Err(AdmissionFailure::Unknown); }
        if let Some(gate)=&self.gate{gate.source_work()?;}
        // No watch::Ref survives into a genuine pending WAIT.
        let audit_end=*self.audit.borrow();
        checkpoint(end.min(audit_end), stop)
    }
    fn fd(&self, index: usize) -> Result<&OwnedFd> {
        self.originals.get(index).filter(|o| o.state == State::Owned).and_then(|o| o.fd.as_ref()).ok_or(AdmissionFailure::Unknown)
    }
    fn identity(&self, index: usize) -> Result<Identity> {
        self.originals.get(index).and_then(|o| o.identity).ok_or(AdmissionFailure::Identity)
    }
    fn reserve(&mut self, parent: Option<usize>, name: Name, selected: bool, readonly: bool) -> Result<usize> {
        if self.originals.len() >= ORIGINALS || self.originals.len() == self.originals.capacity() || self.live >= LIVE_FDS {
            return Err(AdmissionFailure::Bounds);
        }
        let index = self.originals.len();
        self.originals.push(Original { state: State::Reserved, fd: None, parent, name, identity: None, selected, readonly, retained: false });
        Ok(index)
    }
    fn permissions(&self, value: &FileStat, directory: bool, readonly: bool) -> Result<Identity> {
        let kind = if directory { SFlag::S_IFDIR } else { SFlag::S_IFREG };
        let account = self.account.ok_or(AdmissionFailure::Unknown)?;
        if value.st_mode & SFlag::S_IFMT.bits() != kind.bits()
            || !matches!(value.st_uid, 0) && value.st_uid != account
            || value.st_mode & 0o7000 != 0 || value.st_mode & 0o022 != 0
            || !directory && value.st_nlink != 1 || readonly && value.st_uid != 0 {
            return Err(AdmissionFailure::Ownership);
        }
        Ok(Identity::of(value))
    }
    fn filesystem(&mut self, index: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.point(end, stop)?;
        let original = self.originals.get(index).ok_or(AdmissionFailure::Unknown)?;
        let fd = original.fd.as_ref().ok_or(AdmissionFailure::Unknown)?;
        let identity = original.identity.ok_or(AdmissionFailure::Identity)?;
        let fs = statfs::fstatfs(fd).map_err(native_error)?;
        if fs.filesystem_type_name() != "apfs" || !fs.flags().contains(MntFlags::MNT_LOCAL)
            || fs.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP)
            || original.readonly && !fs.flags().contains(MntFlags::MNT_RDONLY) { return Err(AdmissionFailure::Ownership); }
        let policy = if original.selected { Policy::Empty } else { Policy::Ancestors };
        let audit = self.audit.clone();
        let gate=self.gate.clone();
        let result = self.frame.as_mut().ok_or(AdmissionFailure::Unknown)?.observe_phased(fd.as_fd(), identity.acl_expected()?, policy,
            &mut |phase,first|{
                use native::vault_filesystem::ObservePhase;
                if phase==ObservePhase::Cleanup {
                    if let Some(gate)=&gate{return gate.source_cleanup_expired(first.map(|(failure,at)|(map_acl_failure(failure),at)));}
                }else if let Some(gate)=&gate{if gate.source_work().is_err(){return true;}}
                let audit_end=*audit.borrow();
                audit.has_changed().is_err() || checkpoint(end.min(audit_end), stop).is_err()
            }).map_err(map_acl_failure);
        result?;
        self.point(end,stop)?;
        if self.originals[index].selected { native::no_xattrs(self.fd(index)?.as_fd()).map_err(native_error)?; }
        self.point(end, stop)
    }
    fn open(&mut self, parent: Option<usize>, name: Name, directory: bool, selected: bool, readonly: bool,
        end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        self.point(end, stop)?;
        let index = self.reserve(parent, name, selected, readonly)?;
        let name = self.originals[index].name.text();
        let before = if let Some(parent) = parent { stat::fstatat(self.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW) }
            else { stat::lstat(Path::new("/")) }.map_err(native_error)?;
        let identity = self.permissions(&before, directory, readonly)?;
        self.originals[index].identity = Some(identity);
        self.point(end, stop)?;
        self.originals[index].state = State::Acquiring;
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC
            | if directory { OFlag::O_DIRECTORY } else { OFlag::empty() };
        let opened = if let Some(parent) = parent { fcntl::openat(self.fd(parent)?, self.originals[index].name.text(), flags, Mode::empty()) }
            else { fcntl::open(Path::new("/"), flags, Mode::empty()) };
        match opened {
            Ok(fd) => { self.originals[index].fd = Some(fd); self.originals[index].state = State::Owned; self.live += 1; },
            Err(_) => { self.originals[index].state = State::NoHandle; return Err(AdmissionFailure::Native); },
        }
        self.point(end, stop)?;
        if Identity::of(&stat::fstat(self.fd(index)?).map_err(native_error)?) != identity { return Err(AdmissionFailure::Identity); }
        self.check(index, end, stop)?;
        Ok(index)
    }
    fn check(&mut self, index: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.point(end, stop)?;
        let original = &self.originals[index];
        let identity = original.identity.ok_or(AdmissionFailure::Identity)?;
        let held = stat::fstat(self.fd(index)?).map_err(native_error)?;
        let named = if let Some(parent) = original.parent {
            stat::fstatat(self.fd(parent)?, original.name.text(), AtFlags::AT_SYMLINK_NOFOLLOW)
        } else { stat::lstat(Path::new("/")) }.map_err(native_error)?;
        if Identity::of(&held) != identity || Identity::of(&named) != identity { return Err(AdmissionFailure::Identity); }
        self.filesystem(index, end, stop)
    }
    fn close(&mut self, index: usize) -> bool {
        let original = &mut self.originals[index];
        match original.state {
            State::Reserved => original.state = State::NoHandle,
            State::Owned => {
                original.state = State::Closing;
                match original.fd.take().map(unistd::close) {
                    Some(Ok(())) => { original.state = State::Closed; self.live -= 1; },
                    _ => { original.state = State::Unknown; self.unknown = true; },
                }
            },
            State::Closed | State::NoHandle => {},
            _ => self.unknown = true,
        }
        !self.unknown
    }
    fn close_checked(&mut self, index: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.check(index, end, stop)?;
        if !self.close(index) { return Err(AdmissionFailure::Unknown); }
        self.point(end, stop)
    }
    fn chain(&mut self, root: &RegisteredRoot, end: Instant, stop: &watch::Receiver<bool>) -> Result<Vec<usize>> {
        let path = root.path.to_str().ok_or(AdmissionFailure::Bounds)?;
        if !path.starts_with('/') || path.len() > 4096 || path == "/" { return Err(AdmissionFailure::Bounds); }
        let mut chain = vec_with(ANCESTORS)?;
        chain.push(self.open(None, Name::Static("/"), true, false, false, end, stop)?);
        for part in path[1..].split('/') {
            if part.is_empty() || part == "." || part == ".." || part.len() > 255 || chain.len() == ANCESTORS {
                return Err(AdmissionFailure::Bounds);
            }
            let parent = *chain.last().ok_or(AdmissionFailure::Unknown)?;
            chain.push(self.open(Some(parent), Name::Owned(text_owned(part, 255)?), true, false, false, end, stop)?);
        }
        let picked = *chain.last().ok_or(AdmissionFailure::Unknown)?;
        let actual = self.identity(picked)?;
        let registered = root.identity.posix().map_err(|_| AdmissionFailure::Identity)?.workflow_identity();
        if actual.dev.to_string() != registered.device || actual.ino.to_string() != registered.inode
            || u32::from(actual.mode) != registered.mode || actual.uid != registered.uid || actual.gid != registered.gid {
            return Err(AdmissionFailure::Identity);
        }
        for index in &chain { self.originals[*index].retained = true; }
        self.originals[picked].selected = true;
        self.check(picked, end, stop)?;
        Ok(chain)
    }
    fn child(&mut self, parent: usize, name: &'static str, directory: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        if let Some(index) = self.originals.iter().position(|o| o.state == State::Owned && o.parent == Some(parent) && o.name.text() == name) {
            self.originals[index].selected = true; self.check(index, end, stop)?; return Ok(index);
        }
        self.open(Some(parent), Name::Static(name), directory, true, false, end, stop)
    }
    fn read(&mut self, index: usize, bytes: u64, prefix: usize, end: Instant, stop: &watch::Receiver<bool>,
        mut sink: Option<&mut dyn FnMut(&[u8]) -> Result<()>>) -> Result<(String, Vec<u8>)> {
        if bytes > policy::FILE_LIMIT || prefix > BLOCK || self.identity(index)?.size != i64::try_from(bytes).map_err(native_error)? {
            return Err(AdmissionFailure::Bounds);
        }
        self.check(index, end, stop)?;
        if unistd::lseek(self.fd(index)?, 0, unistd::Whence::SeekSet).map_err(native_error)? != 0 { return Err(AdmissionFailure::Native); }
        let mut kept = vec_with(prefix)?; let mut hash = Sha256::new(); let mut at = 0u64; let mut block = [0; BLOCK];
        while at < bytes {
            self.point(end, stop)?;
            let take = usize::try_from((bytes - at).min(BLOCK as u64)).map_err(native_error)?;
            let count = unistd::read(self.fd(index)?, &mut block[..take]).map_err(native_error)?;
            if count == 0 { return Err(AdmissionFailure::Inventory); }
            self.charge_read(count)?; at += count as u64; hash.update(&block[..count]);
            let take = count.min(prefix - kept.len()); kept.extend_from_slice(&block[..take]);
            if let Some(sink) = sink.as_mut() { sink(&block[..count])?; }
        }
        self.point(end, stop)?;
        if unistd::read(self.fd(index)?, &mut block[..1]).map_err(native_error)? != 0 { return Err(AdmissionFailure::Identity); }
        self.check(index, end, stop)?;
        Ok((hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect(), kept))
    }
    fn charge_read(&mut self, bytes: usize) -> Result<()> {
        self.read_bytes = self.read_bytes.checked_add(bytes as u64).filter(|bytes| *bytes <= READ_LIMIT).ok_or(AdmissionFailure::Bounds)?;
        Ok(())
    }
    fn begin(&mut self, roots: &[RegisteredRoot; 3], end: Instant, stop: &watch::Receiver<bool>)
        -> Result<([Vec<Identity>; 3], JdkLayout, String, String)> {
        if self.begun || self.settled || self.frame_entered || self.frame.is_some() { return Err(AdmissionFailure::AlreadyUsed); }
        self.originals.try_reserve_exact(ORIGINALS).map_err(native_error)?;
        self.aliases.try_reserve_exact(policy::ALIAS_COUNT).map_err(native_error)?;
        if self.originals.capacity() != ORIGINALS || self.aliases.capacity() != policy::ALIAS_COUNT { return Err(AdmissionFailure::Bounds); }
        self.begun = true;
        self.point(end, stop)?; self.account = Some(native::real_user().map_err(native_error)?); self.point(end, stop)?;
        if matches!(self.account, None | Some(0) | Some(u32::MAX)) { return Err(AdmissionFailure::Ownership); }
        self.frame_entered = true; self.frame = Some(SnapshotBook::new());
        if !self.frame.as_ref().is_some_and(|frame| frame.not_started() && frame.quiescent()
            && (1..=16384).contains(&frame.retained_frame_bytes())) { return Err(AdmissionFailure::Bounds); }
        let mut identities: [Vec<Identity>; 3] = std::array::from_fn(|_| Vec::new());
        let mut jdk_home = None; let mut layout = None;
        for (role, root) in roots.iter().enumerate() {
            let chain = self.chain(root, end, stop)?;
            let picked = *chain.last().ok_or(AdmissionFailure::Unknown)?;
            let mut observed = vec_with(chain.len() + 4)?;
            for index in &chain { observed.push(self.identity(*index)?); }
            identities[role] = observed;
            if role == 0 {
                let name = self.originals[picked].name.text();
                if name.ends_with(".jdk") {
                    layout = Some(JdkLayout::Bundle); self.roots[0] = Some(picked);
                    let contents = self.child(picked, "Contents", true, end, stop)?;
                    jdk_home = Some(self.child(contents, "Home", true, end, stop)?);
                } else if name == "Home" && chain.len() >= 3 {
                    let contents = chain[chain.len() - 2]; let bundle = chain[chain.len() - 3];
                    if self.originals[contents].name.text() != "Contents" || !self.originals[bundle].name.text().ends_with(".jdk")
                        || self.originals[picked].parent != Some(contents) || self.originals[contents].parent != Some(bundle) {
                        return Err(AdmissionFailure::Inventory);
                    }
                    // These are the SAME held ancestry indexes, not a lexical
                    // ".jdk" guess or a DirectoryIdentity::vault_original factory.
                    layout = Some(JdkLayout::HomeInSameBundle); self.roots[0] = Some(bundle); jdk_home = Some(picked);
                } else { return Err(AdmissionFailure::Inventory); }
            } else { self.roots[role] = Some(picked); }
        }
        let release = self.child(jdk_home.ok_or(AdmissionFailure::Inventory)?, "release", false, end, stop)?;
        let size = u64::try_from(self.identity(release)?.size).map_err(native_error)?;
        if size == 0 || size > BLOCK as u64 { return Err(AdmissionFailure::Bounds); }
        let (_, bytes) = self.read(release, size, size as usize, end, stop, None)?;
        let (vendor, version) = release_layout(&bytes)?;
        Ok((identities, layout.ok_or(AdmissionFailure::Inventory)?, vendor, version))
    }
    pub(crate) fn inspect_once(&mut self, roots: &[RegisteredRoot; 3], instance: &str, supplier_reservation: usize,
        end: Instant, stop: &watch::Receiver<bool>, publish: &mut Publish<'_>) -> Result<()> {
        let result = (|| {
            let (root_data, layout, vendor, version) = self.begin(roots, end, stop)?;
            let recipe = supplier::recipe(&SourceLayouts { jdk: layout, jdk_vendor: &vendor, jdk_version: &version })
                .map_err(|_| AdmissionFailure::Inventory)?;
            if recipe.working_reservation_bytes().ok().is_none_or(|bytes| bytes > supplier_reservation)
                || supplier::max_working_reservation_bytes().ok() != Some(supplier_reservation) { return Err(AdmissionFailure::Bounds); }
            self.observe(&recipe, root_data, end, stop)?;
            let closure = self.closure.as_ref().ok_or(AdmissionFailure::Unknown)?;
            let mut members = vec_with(closure.members.len())?;
            for member in &closure.members { members.push(member.data()); }
            let (support, archive_members) = self.support.review()?.observations();
            let observations = SourceObservations { members: &members, support: &support, archive_members: &archive_members,
                optional_sdk_metadata: std::array::from_fn(|slot| closure.optional_sdk_metadata[slot].as_ref().map(ObservedSdkMetadata::data)) };
            let mut provider = vec_with(closure.provider.len())?;
            for file in &closure.provider { provider.push(copy_file(&file.file)?); }
            let proposal = recipe.finalize_proposal(instance, self.account.ok_or(AdmissionFailure::Unknown)?, &observations, &provider)
                .map_err(|_| AdmissionFailure::Inventory)?;
            self.instance = Some(text_owned(instance, 32)?);
            payload_open_plan(proposal.payload_map())?;
            self.proposal = Some(proposal); self.recipe = Some(recipe);
            self.check_remaining(end, stop)
        })();
        if let Err(failure) = result { self.note(failure, Instant::now(), publish); }
        result
    }
    pub(crate) fn reprove_once(&mut self, roots: &[RegisteredRoot; 3], reviewed: &SourceReview, supplier_reservation: usize,
        end: Instant, stop: &watch::Receiver<bool>, publish: &mut Publish<'_>) -> Result<()> {
        let result = (|| {
            let (root_data, layout, vendor, version) = self.begin(roots, end, stop)?;
            if self.account != Some(reviewed.account) || layout != reviewed.closure.layout
                || reviewed.recipe.jdk_layout() != layout
                || reviewed.recipe.working_reservation_bytes().ok().is_none_or(|bytes| bytes > supplier_reservation) {
                return Err(AdmissionFailure::Identity);
            }
            // Only prove the small layout against the SAME reviewed reference.
            // Never regenerate instance, proposal, consent or reviewed documents.
            let observed_recipe = supplier::recipe(&SourceLayouts { jdk: layout, jdk_vendor: &vendor, jdk_version: &version })
                .map_err(|_| AdmissionFailure::Inventory)?;
            let old = reviewed.recipe.source_roster(); let new = observed_recipe.source_roster();
            if !std::ptr::eq(old.members, new.members) || !std::ptr::eq(old.support, new.support)
                || !std::ptr::eq(old.archive_members, new.archive_members)
                || !std::ptr::eq(old.optional_sdk_metadata, new.optional_sdk_metadata) { return Err(AdmissionFailure::Inventory); }
            self.observe(&reviewed.recipe, root_data, end, stop)?;
            if !self.closure.as_ref().is_some_and(|closure| closure.same(&reviewed.closure))
                || self.support.review()? != &reviewed.support { return Err(AdmissionFailure::Identity); }
            self.reproof = true;
            self.check_remaining(end, stop)
        })();
        if let Err(failure) = result { self.note(failure, Instant::now(), publish); }
        result
    }
    fn observe(&mut self, recipe: &Recipe, mut roots: [Vec<Identity>; 3], end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        let roster = recipe.source_roster();
        optional_sdk_metadata_roster(roster)?;
        if roster.members.is_empty() || roster.members.len() > policy::ENTRY_LIMIT || !self.observed.is_empty()
            || self.optional_sdk_metadata.iter().any(Option::is_some) || self.sdk_metadata_parents.iter().any(Option::is_some) {
            return Err(AdmissionFailure::Bounds);
        }
        self.observed = vec_with(roster.members.len())?;
        for _ in roster.members { self.observed.push(None); }
        for tree in roster.trees {
            let role = group_index(tree.group).ok_or(AdmissionFailure::Inventory)?;
            let root = self.roots[role].ok_or(AdmissionFailure::Unknown)?;
            let mut parent = root; let mut prefix = String::new();
            if !tree.prefix.is_empty() {
                if !policy::relative(tree.prefix) { return Err(AdmissionFailure::Inventory); }
                for part in tree.prefix.split('/') {
                    if !prefix.is_empty() { prefix.push('/'); } prefix.push_str(part);
                    parent = self.child(parent, part, true, end, stop)?;
                    // Selected SDK package prefix ancestry is part of the fresh
                    // review comparison without enumerating the broad SDK.
                    if roots[role].len() == roots[role].capacity() { return Err(AdmissionFailure::Bounds); }
                    roots[role].push(self.identity(parent)?);
                    self.originals[parent].retained = true;
                }
                let position = member_index(roster, tree.group, tree.prefix)?;
                self.directory_observed(position, parent, roster.members[position])?;
            }
            self.walk(parent, tree.group, tree.prefix, roster, 0, end, stop)?;
            if parent != root && !self.originals[parent].retained { self.close_checked(parent, end, stop)?; }
        }
        if self.observed.iter().any(Option::is_none) { return Err(AdmissionFailure::Inventory); }
        let sdk_metadata_parents = self.frozen_sdk_metadata_parents()?;
        let mut members = vec_with(self.observed.len())?; let mut counts = [Count::default(); 3];
        for member in &mut self.observed {
            let member = member.take().ok_or(AdmissionFailure::Unknown)?;
            let count = &mut counts[group_index(member.group).ok_or(AdmissionFailure::Inventory)?];
            count.entries = count.entries.checked_add(1).ok_or(AdmissionFailure::Bounds)?;
            match &member.kind {
                MemberKind::File(file) => {
                    count.files = count.files.checked_add(1).ok_or(AdmissionFailure::Bounds)?;
                    count.bytes = count.bytes.checked_add(file.size).ok_or(AdmissionFailure::Bounds)?;
                },
                MemberKind::Alias(_, _) => count.aliases = count.aliases.checked_add(1).ok_or(AdmissionFailure::Bounds)?,
                MemberKind::Directory(_) => {},
            }
            members.push(member);
        }
        // These are actual picked SDK bytes/entries, even though the compiled
        // metadata payload is independent of their optional presence.
        for metadata in self.optional_sdk_metadata.iter().flatten() {
            let count = &mut counts[1];
            count.entries = count.entries.checked_add(1).ok_or(AdmissionFailure::Bounds)?;
            count.files = count.files.checked_add(1).ok_or(AdmissionFailure::Bounds)?;
            count.bytes = count.bytes.checked_add(metadata.file.size).ok_or(AdmissionFailure::Bounds)?;
        }
        let support_end=end.min(*self.audit.borrow());
        self.support.inspect_once(recipe, support_end, stop)?;
        let (provider_roots, provider) = self.provider(end, stop)?;
        let picked = counts.iter().try_fold((0u64, 0u32, 0u32, 0u32), |(b, f, e, a), c|
            Some((b.checked_add(c.bytes)?, f.checked_add(c.files)?, e.checked_add(c.entries)?, a.checked_add(c.aliases)?)))
            .ok_or(AdmissionFailure::Bounds)?;
        let all_bytes = provider.iter().try_fold(picked.0.checked_add(self.support.review()?.logical_bytes().ok_or(AdmissionFailure::Bounds)?)
            .ok_or(AdmissionFailure::Bounds)?, |sum, file| sum.checked_add(file.file.size)).ok_or(AdmissionFailure::Bounds)?;
        if all_bytes > policy::TOTAL_LIMIT || picked.1 as usize + 3 + provider.len() > policy::FILE_COUNT
            || picked.2 as usize + 3 + provider_roots.len() > policy::ENTRY_LIMIT || picked.3 as usize > policy::ALIAS_COUNT {
            return Err(AdmissionFailure::Bounds);
        }
        self.closure = Some(Closure { roots, members, provider_roots, provider, counts, layout: recipe.jdk_layout(),
            optional_sdk_metadata: std::mem::replace(&mut self.optional_sdk_metadata, [None, None]), sdk_metadata_parents });
        Ok(())
    }
    fn frozen_sdk_metadata_parents(&self) -> Result<[Identity; 2]> {
        Ok([self.sdk_metadata_parents[0].ok_or(AdmissionFailure::Inventory)?,
            self.sdk_metadata_parents[1].ok_or(AdmissionFailure::Inventory)?])
    }
    fn sdk_metadata_observed(&mut self, slot: usize, parent: usize, expected: &'static OptionalSdkMetadataSpec,
        inode: u64, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if self.optional_sdk_metadata[slot].is_some() || self.sdk_metadata_parents[slot].is_some() {
            return Err(AdmissionFailure::Inventory);
        }
        let leaf = expected.relative.rsplit('/').next().ok_or(AdmissionFailure::Inventory)?;
        let index = self.child(parent, leaf, false, end, stop)?;
        let identity = self.identity(index)?; let mode = u32::from(identity.mode & 0o7777);
        if identity.ino != inode { return Err(AdmissionFailure::Identity); }
        if !expected.modes.contains(&mode) { return Err(AdmissionFailure::Ownership); }
        let bytes = usize::try_from(identity.size).map_err(native_error)?;
        if bytes == 0 || bytes > expected.max_bytes || expected.max_bytes != SDK_METADATA_BYTES {
            return Err(AdmissionFailure::Bounds);
        }
        // Complete bytes from this SAME selected original; existing read does
        // endpoint/ancestry, full EOF/hash and held/named POST before closure.
        let (hash, contents) = self.read(index, bytes as u64, bytes, end, stop, None)?;
        if contents.len() != bytes || contents.capacity() > SDK_METADATA_BYTES || hash.capacity() > 64 {
            return Err(AdmissionFailure::Bounds);
        }
        self.optional_sdk_metadata[slot] = Some(ObservedSdkMetadata { identity,
            file: FileSpec { path: text_owned(expected.relative, 512)?, size: bytes as u64, sha256: hash, mode }, contents });
        self.close_checked(index, end, stop)
    }
    fn directory_observed(&mut self, position: usize, index: usize, expected: SourceMemberSpec) -> Result<()> {
        let identity = self.identity(index)?; let mode = u32::from(identity.mode & 0o7777);
        let SourceKindSpec::Directory { modes } = expected.kind else { return Err(AdmissionFailure::Inventory); };
        if !modes.contains(&mode) || self.observed[position].is_some() { return Err(AdmissionFailure::Inventory); }
        self.observed[position] = Some(Member { group: expected.group, relative: expected.relative, identity, kind: MemberKind::Directory(mode) });
        Ok(())
    }
    fn walk(&mut self, parent: usize, group: SourceGroup, relative: &str, roster: SourceRoster, depth: usize,
        end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if depth > 16 { return Err(AdmissionFailure::Bounds); }
        let mut buffer = [0; BLOCK];
        loop {
            self.point(end, stop)?;
            let used = native::directory_block(self.fd(parent)?.as_fd(), &mut buffer).map_err(native_error)?;
            if used == 0 { break; }
            if used > buffer.len() { return Err(AdmissionFailure::Bounds); }
            let mut cursor = 0;
            while cursor < used {
                if used - cursor < 11 { return Err(AdmissionFailure::Inventory); }
                let inode = u64::from_ne_bytes(buffer[cursor..cursor + 8].try_into().map_err(native_error)?);
                let kind = buffer[cursor + 8];
                let count = usize::from(u16::from_ne_bytes([buffer[cursor + 9], buffer[cursor + 10]]));
                let next = cursor.checked_add(11 + count).filter(|next| *next <= used).ok_or(AdmissionFailure::Bounds)?;
                let name = std::str::from_utf8(&buffer[cursor + 11..next]).map_err(native_error)?;
                cursor = next;
                if matches!(name, "." | "..") { continue; }
                if !policy::component(name) || name.contains('/') || inode == 0 { return Err(AdmissionFailure::Inventory); }
                let path = if relative.is_empty() { text_owned(name, 512)? } else {
                    if relative.len() + 1 + name.len() > 512 { return Err(AdmissionFailure::Bounds); }
                    format!("{relative}/{name}")
                };
                if let Some(slot) = optional_sdk_metadata_index(roster.optional_sdk_metadata, group, &path)? {
                    if kind != nix::libc::DT_REG { return Err(AdmissionFailure::Inventory); }
                    self.sdk_metadata_observed(slot, parent, &roster.optional_sdk_metadata[slot], inode, end, stop)?;
                    continue;
                }
                let position = member_index(roster, group, &path)?;
                if self.observed[position].is_some() { return Err(AdmissionFailure::Inventory); }
                let expected = roster.members[position];
                let leaf = expected.relative.rsplit('/').next().ok_or(AdmissionFailure::Inventory)?;
                match expected.kind {
                    SourceKindSpec::Alias { .. } if kind == nix::libc::DT_LNK => {
                        self.alias(position, parent, leaf, expected, inode, end, stop)?;
                    },
                    SourceKindSpec::Directory { .. } if kind == nix::libc::DT_DIR => {
                        let index = self.child(parent, leaf, true, end, stop)?;
                        if self.identity(index)?.ino != inode { return Err(AdmissionFailure::Identity); }
                        self.directory_observed(position, index, expected)?;
                        self.walk(index, group, &path, roster, depth + 1, end, stop)?;
                        if !self.originals[index].retained { self.close_checked(index, end, stop)?; }
                    },
                    SourceKindSpec::File { bytes, sha256, modes } if kind == nix::libc::DT_REG => {
                        let index = self.child(parent, leaf, false, end, stop)?;
                        let identity = self.identity(index)?; let mode = u32::from(identity.mode & 0o7777);
                        if identity.ino != inode || !modes.contains(&mode) { return Err(AdmissionFailure::Ownership); }
                        let (hash, _) = self.read(index, bytes, 0, end, stop, None)?;
                        if hash != sha256 { return Err(AdmissionFailure::Inventory); }
                        self.observed[position] = Some(Member { group, relative: expected.relative, identity,
                            kind: MemberKind::File(FileSpec { path: text_owned(expected.relative, 512)?, size: bytes, sha256: hash, mode }) });
                        self.close_checked(index, end, stop)?;
                    },
                    _ => return Err(AdmissionFailure::Inventory),
                }
            }
        }
        self.check_aliases(parent, end, stop)?;
        self.check(parent, end, stop)?;
        if group == SourceGroup::Sdk {
            for (slot, spec) in roster.optional_sdk_metadata.iter().enumerate() {
                if spec.relative.rsplit_once('/').is_some_and(|(directory, _)| directory == relative) {
                    if self.sdk_metadata_parents[slot].is_some() { return Err(AdmissionFailure::Inventory); }
                    // A missing optional name is known absent only here: after
                    // complete enumeration and full SAME-parent held/named POST.
                    self.sdk_metadata_parents[slot] = Some(self.identity(parent)?);
                }
            }
        }
        Ok(())
    }
    fn alias(&mut self, position: usize, parent: usize, name: &'static str, expected: SourceMemberSpec,
        inode: u64, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.point(end, stop)?;
        if self.aliases.len() >= policy::ALIAS_COUNT { return Err(AdmissionFailure::Bounds); }
        let SourceKindSpec::Alias { target, canonical, modes } = expected.kind else { return Err(AdmissionFailure::Inventory); };
        let before = stat::fstatat(self.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?;
        let identity = Identity::of(&before); let mode = u32::from(identity.mode & 0o7777);
        if before.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFLNK.bits() || identity.ino != inode || identity.links != 1
            || !(1..=512).contains(&identity.size) || !modes.contains(&mode)
            || identity.uid != 0 && Some(identity.uid) != self.account { return Err(AdmissionFailure::Ownership); }
        let data = Alias { path: text_owned(expected.relative, 512)?, target: text_owned(target, 512)?,
            canonical: text_owned(canonical, 512)? };
        if policy::alias_target(&data).as_deref() != Some(canonical) { return Err(AdmissionFailure::Inventory); }
        self.point(end, stop)?;
        let actual = fcntl::readlinkat(self.fd(parent)?, name).map_err(native_error)?;
        if actual.to_str() != Some(target) { return Err(AdmissionFailure::Inventory); }
        self.aliases.push(AliasOriginal { parent, name, identity, target: text_owned(target, 512)? });
        if Identity::of(&stat::fstatat(self.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?) != identity {
            return Err(AdmissionFailure::Identity);
        }
        self.observed[position] = Some(Member { group: expected.group, relative: expected.relative, identity, kind: MemberKind::Alias(data, mode) });
        self.check(parent, end, stop)
    }
    fn check_aliases(&self, parent: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        for original in self.aliases.iter().filter(|original| original.parent == parent) {
            self.point(end, stop)?;
            let actual = stat::fstatat(self.fd(parent)?, original.name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?;
            if Identity::of(&actual) != original.identity || fcntl::readlinkat(self.fd(parent)?, original.name).map_err(native_error)?.to_str()
                != Some(original.target.as_str()) { return Err(AdmissionFailure::Identity); }
            self.point(end, stop)?;
        }
        Ok(())
    }

    fn region(&mut self, index: usize, at: u64, count: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<Vec<u8>> {
        let size = u64::try_from(self.identity(index)?.size).map_err(native_error)?;
        if count > NATIVE_HEADER || at.checked_add(count as u64).is_none_or(|last| last > size) {
            return Err(AdmissionFailure::Bounds);
        }
        self.point(end, stop)?;
        let offset = i64::try_from(at).map_err(native_error)?;
        if unistd::lseek(self.fd(index)?, offset, unistd::Whence::SeekSet).map_err(native_error)? != offset {
            return Err(AdmissionFailure::Native);
        }
        let mut bytes = vec_with(count)?; bytes.resize(count, 0);
        let mut used = 0;
        while used < count {
            self.point(end, stop)?;
            let read = unistd::read(self.fd(index)?, &mut bytes[used..]).map_err(native_error)?;
            if read == 0 { return Err(AdmissionFailure::Inventory); }
            used += read; self.charge_read(read)?;
        }
        self.check(index, end, stop)?;
        Ok(bytes)
    }
    fn provider_native(&mut self, index: usize, file: &FileSpec, prefix: &[u8], end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        let mandatory = file.mode & 0o111 != 0 || file.path.ends_with(".dylib") || file.path.ends_with(".jnilib");
        let recognized = prefix.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) || prefix.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
            || prefix.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) || prefix.starts_with(&[0xca, 0xfe, 0xba, 0xbf]);
        if !mandatory && !recognized { return Ok(()); }
        let slice = policy::arm64_slice(prefix, file.size).ok_or(AdmissionFailure::Inventory)?;
        let header = self.region(index, slice.offset, 32, end, stop)?;
        let count = u32::from_le_bytes(header[20..24].try_into().map_err(native_error)?) as usize;
        let body = self.region(index, slice.offset, count.checked_add(32).ok_or(AdmissionFailure::Bounds)?, end, stop)?;
        // SAME shared Mach-O/system-load semantics as the installed tool reader,
        // not a second inventory or native policy registry.
        let commands = policy::macho_commands(&body, slice).ok_or(AdmissionFailure::Inventory)?;
        if !commands.loads.iter().all(|load| policy::system_load(load))
            || !commands.rpaths.iter().all(|path| policy::OS_ROOTS.contains(&path.as_str()) || policy::system_load(path)) {
            return Err(AdmissionFailure::Inventory);
        }
        Ok(())
    }
    fn provider(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<(Vec<Identity>, Vec<ProviderFile>)> {
        // This ledger indexes only closed shared OS_ROOTS/OS_FILES, never PATH or
        // user/provider-supplied filenames. Each original is opened once.
        let first = self.originals.len();
        let slash = self.open(None, Name::Static("/"), true, false, false, end, stop)?;
        let mut files = vec_with(policy::OS_FILES.len())?;
        for path in policy::OS_ROOTS.into_iter().chain(policy::OS_FILES) {
            let root = policy::OS_ROOTS.contains(&path);
            if !path.starts_with('/') || !policy::relative(&path[1..]) { return Err(AdmissionFailure::Inventory); }
            let count = path[1..].split('/').count(); let mut parent = slash;
            for (position, part) in path[1..].split('/').enumerate() {
                let directory = position + 1 < count || root;
                if let Some(index) = (first..self.originals.len()).find(|index| {
                    let original = &self.originals[*index];
                    original.parent == Some(parent) && original.name.text() == part && original.state == State::Owned
                }) {
                    self.check(index, end, stop)?;
                    if (self.identity(index)?.mode & SFlag::S_IFMT.bits() == SFlag::S_IFDIR.bits()) != directory {
                        return Err(AdmissionFailure::Inventory);
                    }
                    parent = index;
                } else {
                    parent = self.open(Some(parent), part.into(), directory, false, true, end, stop)?;
                }
            }
            if !root {
                let identity = self.identity(parent)?; let mode = u32::from(identity.mode & 0o7777);
                if identity.uid != 0 || identity.gid != 0 || !matches!(mode, 0o444 | 0o555) {
                    return Err(AdmissionFailure::Ownership);
                }
                let size = u64::try_from(identity.size).map_err(native_error)?;
                let (hash, prefix) = self.read(parent, size, 256, end, stop, None)?;
                let file = FileSpec { path: text_owned(path, 512)?, size, sha256: hash, mode };
                self.provider_native(parent, &file, &prefix, end, stop)?;
                files.push(ProviderFile { identity, file });
            }
        }
        if self.originals.len() - first > 128 { return Err(AdmissionFailure::Bounds); }
        let mut identities = vec_with(self.originals.len() - first)?;
        for index in first..self.originals.len() { identities.push(self.identity(index)?); }
        // Every OS parent/leaf is checked before this ORIGINAL tail consumes
        // any of its FDs. There is no later provider probe/reopen-as-rescue.
        for index in (first..self.originals.len()).rev() { self.check(index, end, stop)?; }
        for index in (first..self.originals.len()).rev() {
            self.point(end, stop)?;
            if !self.close(index) { return Err(AdmissionFailure::Unknown); }
            self.point(end, stop)?;
        }
        Ok((identities, files))
    }
    fn check_remaining(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        for index in (0..self.originals.len()).rev() {
            if self.originals[index].state == State::Owned {
                self.check_aliases(index, end, stop)?;
                self.check(index, end, stop)?;
            }
        }
        self.point(end, stop)
    }
    fn stream_compiled_sdk_metadata(&self, payload: &PayloadSource, end: Instant, stop: &watch::Receiver<bool>,
        sink: &mut dyn PayloadSink) -> Result<()> {
        self.point(end, stop)?;
        let PayloadOrigin::CompiledSdkMetadata(kind) = payload.origin else { return Err(AdmissionFailure::Inventory); };
        let compiled = crate::android_sdk_metadata_macos::compiled_sdk_metadata(kind);
        // These immutable compiled bytes are the ONLY payload authority.
        // Optional picked contents are comparison DATA and are never read here.
        if compiled.kind != kind || compiled.file.mode != 0o444
            || compiled.file.path != payload.installed.path || compiled.file.size != payload.installed.size
            || compiled.file.sha256 != payload.installed.sha256 || compiled.file.mode != payload.installed.mode
            || compiled.bytes.is_empty() || compiled.bytes.len() > SDK_METADATA_BYTES
            || compiled.file.size != compiled.bytes.len() as u64 || digest(compiled.bytes) != compiled.file.sha256 {
            return Err(AdmissionFailure::Inventory);
        }
        self.point(end, stop)?;
        // At most32KiB; no fictitious picked file, reopen, archive member, native
        // allocation or source-side Finish. The same IPC sink still owns ACK.
        sink.chunk(compiled.bytes)?;
        self.point(end, stop)
    }
    /// Canonical ordinals are the shared supplier map, not filesystem directory
    /// order. A second descriptor frontier is planned as part of THIS original.
    /// It never recovers a failed descriptor/read or reruns reproof/stream.
    pub(crate) fn stream_payloads(&mut self, reviewed: &SourceReview, end: Instant, stop: &watch::Receiver<bool>,
        sink: &mut dyn PayloadSink, publish: &mut Publish<'_>) -> Result<()> {
        let result = (|| {
            if !self.reproof || self.streamed || self.settled || self.first_failure().is_some() {
                return Err(AdmissionFailure::AlreadyUsed);
            }
            self.streamed = true;
            let map = reviewed.proposal.payload_map();
            let planned = payload_open_plan(map)?;
            if self.originals.len().checked_add(planned).is_none_or(|count| count > ORIGINALS) {
                return Err(AdmissionFailure::Bounds);
            }
            let roster = reviewed.recipe.source_roster();
            let mut frontier: Vec<(SourceGroup, &'static str, usize)> = vec_with(16)?;
            let mut total = 0u64;
            for (position, payload) in map.iter().enumerate() {
                self.point(end, stop)?;
                let ordinal = u32::try_from(position).map_err(native_error)?;
                sink.begin(ordinal, payload.installed.size)?;
                match payload.origin {
                    PayloadOrigin::DirectOriginal(OriginalSource::Picked { group, relative }) => {
                        let role = group_index(group).ok_or(AdmissionFailure::Inventory)?;
                        let root = self.roots[role].ok_or(AdmissionFailure::Unknown)?;
                        let (directory, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
                        let mut common = 0;
                        for (before_group, prefix, _) in &frontier {
                            if *before_group == group && (directory == *prefix || directory.strip_prefix(*prefix)
                                .is_some_and(|rest| rest.starts_with('/'))) { common += 1; } else { break; }
                        }
                        while frontier.len() > common {
                            let (_, _, index) = frontier.pop().ok_or(AdmissionFailure::Unknown)?;
                            if !self.originals[index].retained { self.close_checked(index, end, stop)?; }
                        }
                        let mut parent = frontier.last().map_or(root, |item| item.2);
                        let consumed = frontier.last().map_or(0, |item| item.1.len());
                        let suffix = if consumed == 0 { directory } else { directory[consumed..].strip_prefix('/').unwrap_or("") };
                        let mut prefix_len = if consumed == 0 { 0 } else { consumed + 1 };
                        if !suffix.is_empty() {
                            for part in suffix.split('/') {
                                prefix_len += part.len();
                                let prefix = &directory[..prefix_len];
                                let index = if let Some(index) = self.originals.iter().position(|original| original.retained
                                    && original.state == State::Owned && original.parent == Some(parent) && original.name.text() == part) {
                                    self.check(index, end, stop)?; index
                                } else {
                                    let index = self.open(Some(parent), Name::Static(part), true, true, false, end, stop)?;
                                    let observed = &reviewed.closure.members[member_index(roster, group, prefix)?];
                                    if !matches!(observed.kind, MemberKind::Directory(_)) || self.identity(index)? != observed.identity {
                                        return Err(AdmissionFailure::Identity);
                                    }
                                    index
                                };
                                if frontier.len() >= 16 { return Err(AdmissionFailure::Bounds); }
                                frontier.push((group, prefix, index)); parent = index; prefix_len += 1;
                            }
                        }
                        let expected = &reviewed.closure.members[member_index(roster, group, relative)?];
                        let MemberKind::File(file) = &expected.kind else { return Err(AdmissionFailure::Inventory); };
                        if file.size != payload.installed.size || file.sha256 != payload.installed.sha256 {
                            return Err(AdmissionFailure::Inventory);
                        }
                        let index = self.open(Some(parent), Name::Static(leaf), false, true, false, end, stop)?;
                        if self.identity(index)? != expected.identity { return Err(AdmissionFailure::Identity); }
                        let (hash, _) = self.read(index, file.size, 0, end, stop, Some(&mut |bytes| sink.chunk(bytes)))?;
                        if hash != file.sha256 { return Err(AdmissionFailure::Inventory); }
                        self.close_checked(index, end, stop)?;
                    },
                    PayloadOrigin::DirectOriginal(OriginalSource::Support(asset)) => {
                        let support_end=end.min(*self.audit.borrow());
                        self.support.stream(asset, None, support_end, stop, &mut |bytes| sink.chunk(bytes))?;
                    },
                    PayloadOrigin::CompiledSdkMetadata(_) => {
                        self.stream_compiled_sdk_metadata(payload, end, stop, sink)?;
                    },
                    PayloadOrigin::MemberOfSameOriginalArchive { asset, archive, member } => {
                        let (actual, _) = reviewed.support.observations();
                        if !actual.iter().any(|value| value.asset == asset && value.archive == archive)
                            || member.bytes != payload.installed.size || member.sha256 != payload.installed.sha256 {
                            return Err(AdmissionFailure::Inventory);
                        }
                        let support_end=end.min(*self.audit.borrow());
                        self.support.stream(asset, Some(member), support_end, stop, &mut |bytes| sink.chunk(bytes))?;
                    },
                }
                // End is offered only after actual EOF/hash/identity checks.
                // The sink does not ACK locally; it waits for expected IPC ACK.
                sink.end(ordinal, payload.installed.size)?;
                total = total.checked_add(payload.installed.size).ok_or(AdmissionFailure::Bounds)?;
            }
            while let Some((_, _, index)) = frontier.pop() {
                if !self.originals[index].retained { self.close_checked(index, end, stop)?; }
            }
            if total != reviewed.proposal.payload_bytes() { return Err(AdmissionFailure::Inventory); }
            self.check_remaining(end, stop)
        })();
        if let Err(failure) = result { self.note(failure, Instant::now(), publish); }
        result
    }
    /// Executed by the SAME source worker before its genuine final return.
    /// Frozen scalar data, never a worker/queue-created SourceJoined capability.
    pub(crate) fn settle_originals(&mut self,
        expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool) -> CloseOutcome {
        if self.settled { return CloseOutcome::Unknown; }
        let gate=self.gate.clone();
        let mut expired=|first|{
            let gate_expired=gate.as_ref().is_some_and(|gate|gate.source_cleanup_expired(first));
            let owner_expired=expired(first);gate_expired || owner_expired
        };
        let mut first = self.first_failure();
        let denied = expired(first);
        if !denied {
            match self.frame.as_mut() {
                Some(frame) => {
                    let known = frame.release(&mut |failure| {
                        first = earliest_failure(first, failure.map(|(failure, at)| (map_acl_failure(failure), at)));
                        expired(first)
                    });
                    self.frame_settled = known;
                    if !known {
                        // Failed release retains the original native frame. Its
                        // already-recorded DATA preserves the actual earlier F.
                        first = earliest_failure(first, frame.first_failure().map(|(failure, at)| (map_acl_failure(failure), at)));
                    }
                },
                None if !self.frame_entered && !self.begun => self.frame_settled = true,
                _ => self.unknown = true,
            }
        } else if !self.frame_entered && self.frame.is_none() && !self.begun { self.frame_settled = true; }
        let _ = expired(first);
        // Independently admissible source/support closes still proceed if a
        // sibling native release is unknown. No STOP-based skipped cleanup.
        for index in (0..self.originals.len()).rev() {
            if self.originals[index].state == State::Owned {
                if expired(first) { continue; }
                if !self.close(index) { first = earliest_failure(first, Some((AdmissionFailure::Unknown, Instant::now()))); }
                let _ = expired(first);
            } else { self.close(index); }
        }
        let support = self.support.settle_originals(&mut |failure| {
            first = earliest_failure(first, failure); expired(first)
        });
        self.first = first;
        self.settled = true;
        self.unknown |= !self.frame_settled || support != CloseOutcome::Settled || self.live != 0
            || self.originals.iter().any(|original| original.fd.is_some() || !matches!(original.state, State::Closed | State::NoHandle));
        if self.unknown {
            self.first = earliest_failure(self.first, Some((AdmissionFailure::Unknown, Instant::now())));
            let _ = expired(self.first); CloseOutcome::Unknown
        } else { CloseOutcome::Settled }
    }
    pub(crate) fn settled(&self) -> bool { self.settled && !self.unknown && self.frame_settled && self.live == 0 }
    pub(crate) fn take_inspection_review(&mut self) -> Result<SourceReview> {
        // No native/book probes after retirement. This checks only frozen
        // source-worker DATA; owner still must consume actual source JoinHandle.
        if !self.settled() || self.first.is_some() || self.reproof || self.streamed { return Err(AdmissionFailure::Unknown); }
        let instance = self.instance.take().ok_or(AdmissionFailure::Inventory)?;
        if instance.len() != 32 || !instance.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err(AdmissionFailure::Inventory);
        }
        Ok(SourceReview { recipe: self.recipe.take().ok_or(AdmissionFailure::Inventory)?,
            closure: self.closure.take().ok_or(AdmissionFailure::Inventory)?,
            support: self.support.take_review()?, proposal: self.proposal.take().ok_or(AdmissionFailure::Inventory)?,
            account: self.account.ok_or(AdmissionFailure::Unknown)?, instance })
    }
}
impl From<&'static str> for Name { fn from(value: &'static str) -> Self { Self::Static(value) } }
fn group_index(group: SourceGroup) -> Option<usize> {
    match group { SourceGroup::Jdk => Some(0), SourceGroup::Sdk => Some(1), SourceGroup::Gradle => Some(2), SourceGroup::FixedSupport => None }
}
fn folded(left: &str, right: &str) -> Ordering {
    left.bytes().map(|byte| byte.to_ascii_lowercase()).cmp(right.bytes().map(|byte| byte.to_ascii_lowercase()))
}
fn optional_sdk_metadata_roster(roster: SourceRoster) -> Result<()> {
    for (slot, spec) in roster.optional_sdk_metadata.iter().enumerate() {
        if !matches!((slot, spec.kind), (0, SdkMetadataKind::Platform35Revision2) | (1, SdkMetadataKind::BuildTools35))
            || spec.max_bytes != SDK_METADATA_BYTES || !policy::relative(spec.relative)
            || spec.modes.len() != 2 || !spec.modes.contains(&0o444) || !spec.modes.contains(&0o644) {
            return Err(AdmissionFailure::Inventory);
        }
        let (parent, leaf) = spec.relative.rsplit_once('/').ok_or(AdmissionFailure::Inventory)?;
        if leaf != "package.xml" || !roster.trees.iter().any(|tree| tree.group == SourceGroup::Sdk && tree.prefix == parent)
            || roster.members.iter().any(|member| member.group == SourceGroup::Sdk && folded(member.relative, spec.relative) == Ordering::Equal) {
            return Err(AdmissionFailure::Inventory);
        }
        let position = member_index(roster, SourceGroup::Sdk, parent)?;
        if !matches!(roster.members[position].kind, SourceKindSpec::Directory { .. }) {
            return Err(AdmissionFailure::Inventory);
        }
    }
    if folded(roster.optional_sdk_metadata[0].relative, roster.optional_sdk_metadata[1].relative) == Ordering::Equal {
        return Err(AdmissionFailure::Inventory);
    }
    Ok(())
}
fn optional_sdk_metadata_index(specs: &[OptionalSdkMetadataSpec; 2], group: SourceGroup, relative: &str) -> Result<Option<usize>> {
    if group != SourceGroup::Sdk { return Ok(None); }
    for (slot, spec) in specs.iter().enumerate() {
        if folded(spec.relative, relative) == Ordering::Equal {
            if spec.relative != relative { return Err(AdmissionFailure::Inventory); }
            return Ok(Some(slot));
        }
    }
    Ok(None) // Caller still requires ordinary exact mandatory membership.
}
fn member_index(roster: SourceRoster, group: SourceGroup, relative: &str) -> Result<usize> {
    let position = roster.members.binary_search_by(|member| member.group.cmp(&group)
        .then_with(|| folded(member.relative, relative))).map_err(|_| AdmissionFailure::Inventory)?;
    // Folded lookup detects collisions; exact spelling remains compulsory.
    if roster.members[position].relative != relative { return Err(AdmissionFailure::Inventory); }
    Ok(position)
}
fn file_same(left: &FileSpec, right: &FileSpec) -> bool {
    left.path == right.path && left.size == right.size && left.sha256 == right.sha256 && left.mode == right.mode
}
fn copy_file(value: &FileSpec) -> Result<FileSpec> {
    Ok(FileSpec { path: text_owned(&value.path, 512)?, size: value.size, sha256: text_owned(&value.sha256, 64)?, mode: value.mode })
}
fn vec_with<T>(count: usize) -> Result<Vec<T>> {
    let mut out = Vec::new(); out.try_reserve_exact(count).map_err(native_error)?;
    if out.capacity() != count { return Err(AdmissionFailure::Bounds); }
    Ok(out)
}
fn text_owned(value: &str, maximum: usize) -> Result<String> {
    if value.len() > maximum { return Err(AdmissionFailure::Bounds); }
    let mut out = String::new(); out.try_reserve_exact(value.len()).map_err(native_error)?;
    if out.capacity() != value.len() { return Err(AdmissionFailure::Bounds); }
    out.push_str(value); Ok(out)
}
/// Bounded declarative JDK release fields, never shell evaluation or sourced
/// vendor code. Unknown fields stay data; duplicate keys/escapes are refused.
fn release_layout(raw: &[u8]) -> Result<(String, String)> {
    if raw.is_empty() || raw.len() > BLOCK || !raw.ends_with(b"\n") { return Err(AdmissionFailure::Inventory); }
    let text = std::str::from_utf8(raw).map_err(native_error)?;
    let mut vendor = None; let mut version = None; let mut keys: Vec<&str> = vec_with(128)?;
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() { continue; }
        let (key, value) = line.split_once('=').ok_or(AdmissionFailure::Inventory)?;
        if key.is_empty() || key.len() > 64 || !key.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || keys.len() == 128 || keys.contains(&key) || value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
            return Err(AdmissionFailure::Inventory);
        }
        keys.push(key);
        let value = &value[1..value.len() - 1];
        if value.len() > 4096 || value.bytes().any(|byte| byte < 0x20 || byte >= 0x7f || matches!(byte, b'"' | b'\\')) {
            return Err(AdmissionFailure::Inventory);
        }
        if key == "IMPLEMENTOR" { vendor = Some(text_owned(value, 128)?); }
        if key == "JAVA_VERSION" { version = Some(text_owned(value, 64)?); }
    }
    Ok((vendor.filter(|value| !value.is_empty()).ok_or(AdmissionFailure::Inventory)?,
        version.filter(|value| !value.is_empty()).ok_or(AdmissionFailure::Inventory)?))
}
fn payload_open_plan(map: &[PayloadSource]) -> Result<usize> {
    if map.is_empty() || map.len() > policy::FILE_COUNT { return Err(AdmissionFailure::Bounds); }
    let mut previous: Option<(SourceGroup, &str)> = None; let mut count = 0usize;
    for payload in map {
        if let PayloadOrigin::DirectOriginal(OriginalSource::Picked { group, relative }) = payload.origin {
            if group_index(group).is_none() || !policy::relative(relative) { return Err(AdmissionFailure::Inventory); }
            let directory = relative.rsplit_once('/').map_or("", |(parent, _)| parent);
            let common = previous.filter(|(before, _)| *before == group).map_or(0, |(_, before)| {
                before.split('/').zip(directory.split('/')).take_while(|(a, b)| !a.is_empty() && a == b).count()
            });
            let directories = if directory.is_empty() { 0 } else { directory.split('/').count() };
            count = count.checked_add(directories.checked_sub(common).ok_or(AdmissionFailure::Bounds)?)
                .and_then(|count| count.checked_add(1)).ok_or(AdmissionFailure::Bounds)?;
            previous = Some((group, directory));
        }
    }
    if count > policy::ENTRY_LIMIT + 256 { return Err(AdmissionFailure::Bounds); }
    Ok(count)
}

#[cfg(test)]
mod optional_sdk_metadata_tests {
    use super::*;
    // Synthetic private comparison DATA only. These helpers create no Recipe,
    // Review, original FD/native book, worker, consent or availability receipt.
    fn identity(ino: u64, mode: u16, size: i64) -> Identity {
        Identity { dev: 7, ino, mode, uid: 501, gid: 20, links: 1, size,
            mtime: 1, mtime_ns: 2, ctime: 3, ctime_ns: 4, flags: 0 }
    }
    fn observed(contents: &[u8]) -> ObservedSdkMetadata {
        ObservedSdkMetadata { identity: identity(11, 0o100644, contents.len() as i64),
            file: FileSpec { path: "platforms/android-35/package.xml".to_owned(), size: contents.len() as u64,
                sha256: digest(contents), mode: 0o644 }, contents: contents.to_vec() }
    }
    fn closure(metadata: [Option<ObservedSdkMetadata>; 2]) -> Closure {
        Closure { roots: std::array::from_fn(|_| Vec::new()), members: Vec::new(),
            provider_roots: Vec::new(), provider: Vec::new(), counts: [Count::default(); 3], layout: JdkLayout::Bundle,
            optional_sdk_metadata: metadata,
            sdk_metadata_parents: [identity(21, 0o40755, 0), identity(22, 0o40755, 0)] }
    }
    static SPECS: [OptionalSdkMetadataSpec; 2] = [
        OptionalSdkMetadataSpec { kind: SdkMetadataKind::Platform35Revision2, relative: "platforms/android-35/package.xml",
            max_bytes: SDK_METADATA_BYTES, modes: &[0o444, 0o644] },
        OptionalSdkMetadataSpec { kind: SdkMetadataKind::BuildTools35, relative: "build-tools/35.0.0/package.xml",
            max_bytes: SDK_METADATA_BYTES, modes: &[0o444, 0o644] },
    ];
    #[test]
    fn absence_cannot_freeze_an_unobserved_parent() {
        let (_audit_sender, audit) = watch::channel(Instant::now());
        let mut source = SourceSlots::new(audit);
        assert!(source.frozen_sdk_metadata_parents().is_err());
        source.sdk_metadata_parents[0] = Some(identity(21, 0o40755, 0));
        assert!(source.frozen_sdk_metadata_parents().is_err());
        source.sdk_metadata_parents[1] = Some(identity(22, 0o40755, 0));
        assert!(source.frozen_sdk_metadata_parents().is_ok());
        // This DATA assertion is not proof that a directory was actually walked.
        // The production setter is exclusively after complete walk + SAME POST.
    }
    #[test]
    fn optional_appearance_disappearance_and_replacement_refuse_reproof() {
        let absent = closure([None, None]);
        let present = closure([Some(observed(b"original metadata")), None]);
        assert!(absent.same(&closure([None, None])));
        assert!(!absent.same(&present) && !present.same(&absent));
        assert!(present.same(&closure([Some(observed(b"original metadata")), None])));
        let mut changed = closure([Some(observed(b"original metadata")), None]);
        changed.optional_sdk_metadata[0].as_mut().unwrap().identity.ino += 1;
        assert!(!present.same(&changed));
        let mut changed = closure([Some(observed(b"original metadata")), None]);
        changed.optional_sdk_metadata[0].as_mut().unwrap().file.mode = 0o444;
        assert!(!present.same(&changed));
        let mut changed = closure([Some(observed(b"original metadata")), None]);
        changed.optional_sdk_metadata[0].as_mut().unwrap().file.sha256 = "0".repeat(64);
        assert!(!present.same(&changed));
        let mut changed = closure([Some(observed(b"original metadata")), None]);
        changed.optional_sdk_metadata[0].as_mut().unwrap().contents[0] ^= 1;
        assert!(!present.same(&changed)); // Whole bytes matter independently of a copied hash scalar.
        let mut changed = closure([None, None]);
        changed.sdk_metadata_parents[0].ctime_ns += 1;
        assert!(!absent.same(&changed)); // Even unchanged absence remains same-parent bound.
    }
    #[test]
    fn optional_lookup_is_exact_fixed_sdk_scope() {
        assert_eq!(optional_sdk_metadata_index(&SPECS, SourceGroup::Sdk, SPECS[0].relative).ok(), Some(Some(0)));
        assert_eq!(optional_sdk_metadata_index(&SPECS, SourceGroup::Sdk, SPECS[1].relative).ok(), Some(Some(1)));
        assert!(optional_sdk_metadata_index(&SPECS, SourceGroup::Sdk, "platforms/android-35/Package.xml").is_err());
        assert_eq!(optional_sdk_metadata_index(&SPECS, SourceGroup::Jdk, SPECS[0].relative).ok(), Some(None));
        assert_eq!(optional_sdk_metadata_index(&SPECS, SourceGroup::Sdk, "platforms/android-35/extra.xml").ok(), Some(None));
        // None delegates to ordinary mandatory membership; it is never an ignore.
    }
    #[derive(Default)]
    struct Sink { chunks: usize, bytes: Vec<u8> }
    impl PayloadSink for Sink {
        fn begin(&mut self, _: u32, _: u64) -> Result<()> { Err(AdmissionFailure::Inventory) }
        fn chunk(&mut self, bytes: &[u8]) -> Result<()> {
            if bytes.len() > SDK_METADATA_BYTES || self.bytes.len() + bytes.len() > 2 * SDK_METADATA_BYTES {
                return Err(AdmissionFailure::Bounds);
            }
            self.chunks += 1; self.bytes.extend_from_slice(bytes); Ok(())
        }
        fn end(&mut self, _: u32, _: u64) -> Result<()> { Err(AdmissionFailure::Inventory) }
    }
    fn generated(kind: SdkMetadataKind) -> PayloadSource {
        PayloadSource { installed: crate::android_sdk_metadata_macos::compiled_sdk_metadata(kind).file,
            origin: PayloadOrigin::CompiledSdkMetadata(kind) }
    }
    #[test]
    fn compiled_copy_ignores_picked_bytes_and_opens_no_fictitious_original() {
        let end = Instant::now() + std::time::Duration::from_secs(60);
        let (_audit_sender, audit) = watch::channel(end);
        let (_stop_sender, stop) = watch::channel(false);
        let mut source = SourceSlots::new(audit);
        source.optional_sdk_metadata[0] = Some(observed(b"not generated payload authority"));
        let map = [generated(SdkMetadataKind::BuildTools35), generated(SdkMetadataKind::Platform35Revision2)];
        assert_eq!(payload_open_plan(&map).ok(), Some(0));
        let mut sink = Sink::default();
        for payload in &map {
            let start = sink.bytes.len();
            assert!(source.stream_compiled_sdk_metadata(payload, end, &stop, &mut sink).is_ok());
            let PayloadOrigin::CompiledSdkMetadata(kind) = payload.origin else { unreachable!(); };
            assert_eq!(&sink.bytes[start..], crate::android_sdk_metadata_macos::compiled_sdk_metadata(kind).bytes);
        }
        assert_eq!(sink.chunks, 2);
        assert_eq!(sink.bytes.len() as u64, map.iter().map(|payload| payload.installed.size).sum::<u64>());
        assert!(source.originals.is_empty() && source.frame.is_none() && !source.frame_entered);
        // This exercises the private bounded chunk helper, not reproof, ACK,
        // worker joins, actual End/Finish, protected publication or native GO.
    }
    #[test]
    fn compiled_payload_mismatch_and_stop_refuse_before_copy() {
        let end = Instant::now() + std::time::Duration::from_secs(60);
        let (_audit_sender, audit) = watch::channel(end);
        let (stop_sender, stop) = watch::channel(false);
        let source = SourceSlots::new(audit);
        let payload = generated(SdkMetadataKind::Platform35Revision2);
        let mut changed = payload; changed.installed.size += 1;
        let mut sink = Sink::default();
        assert!(source.stream_compiled_sdk_metadata(&changed, end, &stop, &mut sink).is_err());
        changed = payload; changed.origin = PayloadOrigin::CompiledSdkMetadata(SdkMetadataKind::BuildTools35);
        assert!(source.stream_compiled_sdk_metadata(&changed, end, &stop, &mut sink).is_err());
        changed = payload; changed.installed.sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(source.stream_compiled_sdk_metadata(&changed, end, &stop, &mut sink).is_err());
        changed = payload; changed.installed.mode = 0o644;
        assert!(source.stream_compiled_sdk_metadata(&changed, end, &stop, &mut sink).is_err());
        stop_sender.send_replace(true);
        assert!(source.stream_compiled_sdk_metadata(&payload, end, &stop, &mut sink).is_err());
        assert!(sink.bytes.is_empty() && sink.chunks == 0 && source.originals.is_empty());
    }
    #[test]
    fn optional_budget_includes_four_whole_original_buffers() {
        let four_buffers = 4 * SDK_METADATA_BYTES;
        let reserved = optional_sdk_metadata_reservation_bytes().unwrap();
        assert!(reserved >= four_buffers + 4 * (512 + 64));
        assert!(SourceSlots::working_reservation_bytes().unwrap() >= reserved);
        let bytes = vec![b'x'; SDK_METADATA_BYTES];
        let value = observed(&bytes);
        assert!(value.heap_bytes().unwrap() >= SDK_METADATA_BYTES);
        assert_eq!(value.data().contents, bytes.as_slice());
        // This bound is app-owned SOURCE arithmetic, not a native/RSS claim.
    }
}
