//! Original read-only Darwin source custody for project selection and private
//! session assets, public listing images and project-relative field selection. Never a runtime,
//! snapshot/Save, signing or continuing write capability.
//! The SAME SourceBook lives outside its blocking worker until every original
//! acquisition/native call/one-use close and that worker's actual join settle.
#![forbid(unsafe_code)]

use super::*;
use std::{ffi::OsStr, os::{fd::{AsFd, OwnedFd}, unix::ffi::OsStrExt}};
use nix::{fcntl::{self, AtFlags, OFlag}, mount::MntFlags,
    sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};

#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalState { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Identity { Directory(DirectoryIdentity), File(FileIdentity) }
#[derive(Clone, Copy, PartialEq, Eq)]
enum CallState { NotStarted, Entered, Settled, Unknown }
impl CallState { fn settled(self) -> bool { matches!(self, Self::NotStarted | Self::Settled) } }
#[derive(Clone, Copy, PartialEq, Eq)]
enum PhysicalRole { Other, Root, Private, Var, Tmp }
impl PhysicalRole {
    fn children(self) -> &'static [(&'static [u8], Self)] {
        match self { Self::Root => &[(b"private", Self::Private)],
            Self::Private => &[(b"var", Self::Var), (b"tmp", Self::Tmp)], _ => &[] }
    }
    fn name(self) -> Option<&'static [u8]> {
        match self { Self::Private => Some(b"private"), Self::Var => Some(b"var"), Self::Tmp => Some(b"tmp"), _ => None }
    }
    fn protected(self, value: DirectoryIdentity) -> bool {
        match self {
            Self::Root | Self::Private | Self::Var => value.uid == 0 && value.mode & 0o022 == 0,
            Self::Tmp => value.uid == 0 && (value.mode & 0o022 == 0 || value.mode & 0o1000 != 0),
            Self::Other => true,
        }
    }
}
struct Descriptor {
    state: OriginalState, fd: Option<OwnedFd>, parent: Option<usize>, name: Vec<u8>,
    identity: Option<Identity>, role: PhysicalRole, acl: [CallState; 2],
}
struct LeafProbe { parent: usize, name: Vec<u8>, identity: FileIdentity }
// Original canonical directory facts, also used for alternate System/Data
// firmlink spellings. Recognizing only the textual parent chain would miss
// the same private/var/tmp object reached through that ordinary APFS view.
struct PhysicalAnchors { private: usize, var: DirectoryIdentity, tmp: DirectoryIdentity }

pub(crate) struct SourceBook {
    slots: Vec<Descriptor>, probes: Vec<LeafProbe>, aliases: Vec<OriginAlias>, anchors: Option<PhysicalAnchors>, begun: bool, terminal: bool,
}
// Finite first-party control bound for the image lane, separate from the raw
// image bytes. Count maximum descriptor/name/alias rosters, both borrowed path
// projections, original ancestries, destination-preservation spellings, fixed
// row/string wrappers and the size+1 EOF bytes. No provider-internal RSS claim.
pub(crate) const PUBLIC_IMAGES_SOURCE_CONTROL_BYTES: usize =
    DESCRIPTOR_LIMIT * (std::mem::size_of::<Descriptor>() + 255)
    + 32 * (std::mem::size_of::<LeafProbe>() + 255 + std::mem::size_of::<OriginAlias>() + 16)
    + (PUBLIC_IMAGE_FILES + 1) * (COMPONENT_LIMIT + 1) * std::mem::size_of::<&[u8]>()
    + (2 * PUBLIC_IMAGE_FILES + 1) * PATH_LIMIT
    + 2 * (COMPONENT_LIMIT + 1) * std::mem::size_of::<usize>()
    + PUBLIC_IMAGE_FILES * ((COMPONENT_LIMIT + 1) * std::mem::size_of::<DirectoryIdentity>()
        + PATH_LIMIT + std::mem::size_of::<CapturedPublicImage>()
        + std::mem::size_of::<(usize, FileIdentity, Vec<DirectoryIdentity>, Option<OriginAlias>)>() + 512)
    + std::mem::size_of::<SourceBook>() + 4096;
impl SourceBook {
    pub(crate) fn new() -> Self { Self { slots: Vec::new(), probes: Vec::new(), aliases: Vec::new(), anchors: None, begun: false, terminal: false } }
    pub(crate) fn not_started(&self) -> bool { !self.begun && self.slots.is_empty() && self.probes.is_empty() && self.aliases.is_empty() && self.anchors.is_none() }
    pub(crate) fn settled(&self) -> bool {
        self.terminal && self.slots.iter().all(|slot|
            matches!(slot.state, OriginalState::Closed | OriginalState::NoHandle) && slot.fd.is_none()
                && slot.acl.iter().all(|call| call.settled()))
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut bytes = self.slots.capacity().checked_mul(std::mem::size_of::<Descriptor>())?
            .checked_add(self.probes.capacity().checked_mul(std::mem::size_of::<LeafProbe>())?)?
            .checked_add(self.aliases.capacity().checked_mul(std::mem::size_of::<OriginAlias>())?)?;
        for slot in &self.slots { bytes = bytes.checked_add(slot.name.capacity())?; }
        for probe in &self.probes { bytes = bytes.checked_add(probe.name.capacity())?; }
        for alias in &self.aliases { bytes = bytes.checked_add(alias.name.capacity())?.checked_add(alias.target.capacity())?; }
        Some(bytes)
    }
    fn begin(&mut self, capacity: usize, probes: usize, aliases: usize) -> Result<(), Reason> {
        if !self.not_started() || self.terminal { return Err(Reason::CleanupUnknown); }
        if capacity == 0 || capacity > DESCRIPTOR_LIMIT || probes > 32 || aliases > 32 { return Err(Reason::Capacity); }
        self.slots.try_reserve_exact(capacity).map_err(|_| Reason::Capacity)?;
        self.probes.try_reserve_exact(probes).map_err(|_| Reason::Capacity)?;
        self.aliases.try_reserve_exact(aliases).map_err(|_| Reason::Capacity)?;
        if self.slots.capacity() > DESCRIPTOR_LIMIT || self.probes.capacity() > 32 || self.aliases.capacity() > 32 {
            return Err(Reason::Capacity);
        }
        self.begun = true; Ok(())
    }
    fn reserve(&mut self, parent: Option<usize>, name: &[u8]) -> Result<usize, Reason> {
        if !self.begun || self.terminal || self.slots.len() >= self.slots.capacity()
            || self.slots.len() >= DESCRIPTOR_LIMIT { return Err(Reason::Capacity); }
        let name = copy_bytes(name)?;
        let index = self.slots.len();
        self.slots.push(Descriptor { state: OriginalState::Reserved, fd: None, parent, name, identity: None,
            role: PhysicalRole::Other, acl: [CallState::NotStarted; 2] });
        Ok(index)
    }
    fn fd(&self, index: usize) -> Result<&OwnedFd, Reason> {
        self.slots.get(index).filter(|slot| slot.state == OriginalState::Owned)
            .and_then(|slot| slot.fd.as_ref()).ok_or(Reason::CleanupUnknown)
    }
    fn directory(&self, index: usize) -> Result<DirectoryIdentity, Reason> {
        match self.slots.get(index).and_then(|slot| slot.identity) { Some(Identity::Directory(id)) => Ok(id), _ => Err(Reason::SourceRefused) }
    }
    fn adopt(&mut self, index: usize, result: nix::Result<OwnedFd>) -> Result<(), Reason> {
        match result {
            Ok(fd) => { self.slots[index].fd = Some(fd); self.slots[index].state = OriginalState::Owned; Ok(()) }
            Err(_) => { self.slots[index].state = OriginalState::NoHandle; Err(Reason::SourceRefused) }
        }
    }
    fn root(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<usize, Reason> {
        checkpoint(stop)?;
        let index = self.reserve(None, b"/")?;
        if index != 0 { return Err(Reason::CleanupUnknown); }
        let before = stat::lstat(Path::new("/")).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let expected = directory_identity(&before)?;
        if !PhysicalRole::Root.protected(expected) { return Err(Reason::SourceRefused); }
        self.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::open(Path::new("/"), directory_flags(), Mode::empty());
        self.adopt(index, opened)?; // Adopt the actual result even after late STOP.
        checkpoint(stop)?;
        filesystem(self.fd(index)?, stop)?;
        let actual = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let named = stat::lstat(Path::new("/")).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        if directory_identity(&actual)? != expected || directory_identity(&named)? != expected { return Err(Reason::SourceChanged); }
        self.slots[index].identity = Some(Identity::Directory(expected)); self.slots[index].role = PhysicalRole::Root;
        Ok(index)
    }
    fn physical_role(&self, parent: usize, expected: DirectoryIdentity, stop: &mut dyn FnMut() -> bool) -> Result<PhysicalRole, Reason> {
        if let Some(anchors) = &self.anchors {
            for (physical, role) in [(self.directory(anchors.private)?, PhysicalRole::Private),
                (anchors.var, PhysicalRole::Var), (anchors.tmp, PhysicalRole::Tmp)] {
                if physical.same_object(expected) {
                    if physical != expected || !role.protected(physical) { return Err(Reason::SourceChanged); }
                    return Ok(role);
                }
            }
        }
        for (name, role) in self.slots[parent].role.children() {
            checkpoint(stop)?;
            let named = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let physical = directory_identity(&named)?;
            if physical.same_object(expected) {
                if physical != expected || !role.protected(physical) { return Err(Reason::SourceChanged); }
                return Ok(*role);
            }
        }
        Ok(PhysicalRole::Other)
    }
    fn anchor_private(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if self.anchors.is_some() { return Err(Reason::CleanupUnknown); }
        let private = self.child(0, b"private", false, stop)?;
        let named = |name: &[u8], role: PhysicalRole, stop: &mut dyn FnMut() -> bool| -> Result<DirectoryIdentity, Reason> {
            checkpoint(stop)?;
            let stat = stat::fstatat(self.fd(private)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let id = directory_identity(&stat)?;
            if !role.protected(id) { return Err(Reason::SourceRefused); } Ok(id)
        };
        let var = named(b"var", PhysicalRole::Var, stop)?;
        let tmp = named(b"tmp", PhysicalRole::Tmp, stop)?;
        self.anchors = Some(PhysicalAnchors { private, var, tmp }); Ok(())
    }
    fn child(&mut self, parent: usize, name: &[u8], file: bool, stop: &mut dyn FnMut() -> bool) -> Result<usize, Reason> {
        self.child_policy(parent, name, file, LeafPolicy::Private, stop)
    }
    fn child_policy(&mut self, parent: usize, name: &[u8], file: bool, policy: LeafPolicy,
        stop: &mut dyn FnMut() -> bool) -> Result<usize, Reason> {
        checkpoint(stop)?;
        let index = self.reserve(Some(parent), name)?;
        let before = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let expected = identity(&before, file)?;
        let role = match expected {
            Identity::Directory(id) => self.physical_role(parent, id, stop)?,
            Identity::File(id) => { if !policy.permits(id) { return Err(Reason::SourceRefused); } PhysicalRole::Other },
        };
        self.slots[index].state = OriginalState::Acquiring;
        let flags = if file { OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK } else { directory_flags() };
        let opened = fcntl::openat(self.fd(parent)?, OsStr::from_bytes(name), flags, Mode::empty());
        self.adopt(index, opened)?;
        checkpoint(stop)?;
        filesystem(self.fd(index)?, stop)?;
        let actual = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let named = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        if identity(&actual, file)? != expected || identity(&named, file)? != expected { return Err(Reason::SourceChanged); }
        self.slots[index].identity = Some(expected); self.slots[index].role = role;
        Ok(index)
    }
    fn chain(&mut self, components: &[&[u8]], aliases: bool, stop: &mut dyn FnMut() -> bool) -> Result<(Vec<usize>, Option<OriginAlias>), Reason> {
        let mut indices = Vec::new(); indices.try_reserve_exact(components.len() + 2).map_err(|_| Reason::Capacity)?;
        if indices.capacity() > COMPONENT_LIMIT + 1 { return Err(Reason::Capacity); }
        indices.push(0); let mut parent = 0; let mut skip = 0;
        let mut alias = None;
        if aliases && !components.is_empty() {
            checkpoint(stop)?;
            let before = stat::fstatat(self.fd(0)?, OsStr::from_bytes(components[0]), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if before.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFLNK.bits() {
                let expected = metadata_identity(&before)?;
                // Only these fixed system links can reach readlinkat. The
                // no-follow original root and physical-role checks remain held.
                if !alias_metadata(components[0], expected) || self.aliases.len() >= self.aliases.capacity() { return Err(Reason::SourceRefused); }
                let target = fcntl::readlinkat(self.fd(0)?, OsStr::from_bytes(components[0])).map_err(|_| Reason::SourceRefused)?;
                checkpoint(stop)?;
                if !alias_target(components[0], target.as_bytes()) { return Err(Reason::SourceRefused); }
                let observed = OriginAlias { name: copy_bytes(components[0])?, target: copy_bytes(target.as_bytes())?, identity: expected };
                self.check_alias(&observed, stop)?;
                // Metadata DATA only; no link descriptor/resource is duplicated.
                alias = Some(OriginAlias { name: copy_bytes(&observed.name)?, target: copy_bytes(&observed.target)?, identity: observed.identity });
                self.aliases.push(observed);
                parent = self.child(0, b"private", false, stop)?; indices.push(parent);
                parent = self.child(parent, components[0], false, stop)?; indices.push(parent); skip = 1;
            }
        }
        for component in &components[skip..] { parent = self.child(parent, component, false, stop)?; indices.push(parent); }
        Ok((indices, alias))
    }
    fn check_alias(&self, alias: &OriginAlias, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        checkpoint(stop)?;
        let named = stat::fstatat(self.fd(0)?, OsStr::from_bytes(&alias.name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if metadata_identity(&named)? != alias.identity || !alias_metadata(&alias.name, alias.identity) { return Err(Reason::SourceChanged); }
        let target = fcntl::readlinkat(self.fd(0)?, OsStr::from_bytes(&alias.name)).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if target.as_bytes() != alias.target || !alias_target(&alias.name, target.as_bytes()) { return Err(Reason::SourceChanged); }
        Ok(())
    }
    fn private_acl(&mut self, index: usize, phase: usize, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        checkpoint(stop)?;
        if phase >= 2 || self.slots[index].acl[phase] != CallState::NotStarted { return Err(Reason::CleanupUnknown); }
        self.slots[index].acl[phase] = CallState::Entered;
        let result = mrk_macos_installed_native::empty_acl_observed(self.fd(index)?.as_fd());
        // Retire native temporaries according to THIS call before observing
        // late STOP; uncertain ACL release cannot be repaired by closing the FD.
        let known = result.as_ref().map_or_else(|failure| failure.refusal_code.is_some() && failure.free_result == 0, |_| true);
        self.slots[index].acl[phase] = if known { CallState::Settled } else { CallState::Unknown };
        if !known { return Err(Reason::CleanupUnknown); }
        checkpoint(stop)?;
        result.map_err(|_| Reason::SourceRefused)
    }
    fn terminal_check(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if let Some(anchors) = &self.anchors {
            for (name, expected) in [(b"var".as_slice(), anchors.var), (b"tmp".as_slice(), anchors.tmp)] {
                checkpoint(stop)?;
                let named = stat::fstatat(self.fd(anchors.private)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|_| Reason::SourceChanged)?;
                checkpoint(stop)?;
                if directory_identity(&named)? != expected { return Err(Reason::SourceChanged); }
            }
        }
        for alias in &self.aliases { self.check_alias(alias, stop)?; }
        for probe in self.probes.iter().rev() {
            checkpoint(stop)?;
            let named = stat::fstatat(self.fd(probe.parent)?, OsStr::from_bytes(&probe.name), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| Reason::ExclusionUnconfirmed)?;
            checkpoint(stop)?;
            if file_identity(&named)? != probe.identity { return Err(Reason::ExclusionUnconfirmed); }
        }
        for index in (0..self.slots.len()).rev() {
            checkpoint(stop)?;
            let slot = &self.slots[index]; let expected = slot.identity.ok_or(Reason::SourceChanged)?;
            filesystem(self.fd(index)?, stop)?;
            let actual = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            let file = matches!(expected, Identity::File(_));
            if identity(&actual, file)? != expected { return Err(Reason::SourceChanged); }
            let named = if let Some(parent) = slot.parent {
                stat::fstatat(self.fd(parent)?, OsStr::from_bytes(&slot.name), AtFlags::AT_SYMLINK_NOFOLLOW)
            } else { stat::lstat(Path::new("/")) }.map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if identity(&named, file)? != expected { return Err(Reason::SourceChanged); }
            if let (Some(parent), Some(name)) = (slot.parent, slot.role.name()) {
                // Bind exact protected spelling even for another case spelling
                // of the same APFS object; no textual alias grants a role.
                let physical = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|_| Reason::SourceChanged)?;
                checkpoint(stop)?;
                if identity(&physical, false)? != expected { return Err(Reason::SourceChanged); }
            }
            if file { self.private_acl(index, 1, stop)?; }
        }
        Ok(())
    }
    fn close_all(&mut self) -> bool {
        self.close_all_observing(&mut |_| {})
    }
    fn close_all_observing(&mut self, failed: &mut dyn FnMut(Reason)) -> bool {
        // Continue independent original closes; never retry EINTR or reconstruct
        // a numeric descriptor, and never equate Drop with known settlement.
        let mut known = true;
        for slot in self.slots.iter_mut().rev() {
            if !slot.acl.iter().all(|call| call.settled()) { known = false; failed(Reason::CleanupUnknown); }
            match slot.state {
                OriginalState::Reserved => { slot.state = OriginalState::NoHandle; }
                OriginalState::NoHandle | OriginalState::Closed => {}
                OriginalState::Owned => {
                    slot.state = OriginalState::Closing;
                    match slot.fd.take() {
                        Some(fd) => match unistd::close(fd) {
                            Ok(()) => { slot.state = OriginalState::Closed; }
                            Err(_) => { slot.state = OriginalState::Unknown; known = false; failed(Reason::CleanupUnknown); }
                        },
                        None => { slot.state = OriginalState::Unknown; known = false; failed(Reason::CleanupUnknown); }
                    }
                }
                OriginalState::Acquiring | OriginalState::Closing | OriginalState::Unknown => { known = false; failed(Reason::CleanupUnknown); }
            }
        }
        self.terminal = true; known && self.settled()
    }
    fn finish<T>(&mut self, result: Result<T, Reason>, stop: &mut dyn FnMut() -> bool) -> Result<T, Reason> {
        let result = result.and_then(|value| { self.terminal_check(stop)?; Ok(value) });
        // The existing OriginalWork supplies the finite cleanup clock and join.
        if !self.close_all() { return Err(Reason::CleanupUnknown); }
        checkpoint(stop)?; result
    }
    fn finish_public_images<T>(&mut self, result: Result<T, Reason>, stop: &mut dyn FnMut() -> bool,
        failed: &mut dyn FnMut(Reason)) -> Result<T, Reason> {
        let result = result.and_then(|value| { self.terminal_check(stop)?; Ok(value) });
        // The original image failure hook does not take source/document/GUI
        // locks. Latch the first failure before any original consuming close.
        if let Err(reason) = &result { failed(*reason); }
        if !self.close_all_observing(failed) { return Err(Reason::CleanupUnknown); }
        match result {
            Err(reason) => Err(reason),
            Ok(value) => match checkpoint(stop) {
                Ok(()) => Ok(value), Err(reason) => { failed(reason); Err(reason) },
            },
        }
    }
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, Reason> {
    let mut out = Vec::new(); out.try_reserve_exact(bytes.len()).map_err(|_| Reason::Capacity)?;
    if out.capacity() > bytes.len() { return Err(Reason::Capacity); }
    out.extend_from_slice(bytes); Ok(out)
}
fn checkpoint(stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> { if stop() { Err(Reason::UserCancelled) } else { Ok(()) } }
fn directory_flags() -> OFlag { OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NONBLOCK }
fn common(stat: &FileStat) -> Result<DirectoryIdentity, Reason> {
    Ok(DirectoryIdentity { dev: u64::try_from(stat.st_dev).map_err(|_| Reason::SourceRefused)?,
        ino: stat.st_ino, mode: u32::from(stat.st_mode), uid: stat.st_uid, gid: stat.st_gid })
}
fn directory_identity(stat: &FileStat) -> Result<DirectoryIdentity, Reason> {
    if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFDIR.bits() { return Err(Reason::SourceRefused); } common(stat)
}
fn metadata_identity(stat: &FileStat) -> Result<FileIdentity, Reason> {
    Ok(FileIdentity { common: common(stat)?, nlink: u64::from(stat.st_nlink),
        size: u64::try_from(stat.st_size).map_err(|_| Reason::SourceRefused)?,
        mtime: (stat.st_mtime, stat.st_mtime_nsec), ctime: (stat.st_ctime, stat.st_ctime_nsec) })
}
fn file_identity(stat: &FileStat) -> Result<FileIdentity, Reason> {
    if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFREG.bits() { return Err(Reason::SourceRefused); } metadata_identity(stat)
}
fn identity(stat: &FileStat, file: bool) -> Result<Identity, Reason> {
    if file { file_identity(stat).map(Identity::File) } else { directory_identity(stat).map(Identity::Directory) }
}
fn alias_metadata(name: &[u8], observed: FileIdentity) -> bool {
    matches!(name, b"tmp" | b"var") && observed.common.mode & u32::from(SFlag::S_IFMT.bits()) == u32::from(SFlag::S_IFLNK.bits())
        && observed.common.uid == 0 && matches!(observed.size, 11 | 12)
}
fn alias_target(name: &[u8], target: &[u8]) -> bool {
    match name { b"tmp" => matches!(target, b"private/tmp" | b"/private/tmp"),
        b"var" => matches!(target, b"private/var" | b"/private/var"), _ => false }
}
fn admitted_filesystem(name: &str, flags: MntFlags) -> bool {
    name == "apfs" && flags.contains(MntFlags::MNT_LOCAL)
        && !flags.intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP)
}
fn filesystem(fd: &OwnedFd, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
    checkpoint(stop)?;
    let observed = statfs::fstatfs(fd).map_err(|_| Reason::UnsupportedFilesystem)?;
    checkpoint(stop)?;
    if !admitted_filesystem(observed.filesystem_type_name(), observed.flags()) { return Err(Reason::UnsupportedFilesystem); }
    // System/Data firmlinks can cross device IDs. Every actual descriptor must
    // satisfy this local policy; Linux xdev or path-text aliases do not apply.
    Ok(())
}
fn parts(path: &Path) -> Result<Vec<&[u8]>, Reason> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > PATH_LIMIT || bytes[0] != b'/' || bytes.contains(&0)
        || path.to_str().is_none() { return Err(Reason::SourceRefused); }
    let mut components = Vec::new(); components.try_reserve_exact(COMPONENT_LIMIT - 1).map_err(|_| Reason::Capacity)?;
    if components.capacity() > COMPONENT_LIMIT - 1 { return Err(Reason::Capacity); }
    if bytes == b"/" { return Ok(components); }
    for name in bytes[1..].split(|byte| *byte == b'/') {
        if name.is_empty() || name == b"." || name == b".." || name.len() > 255 || components.len() >= COMPONENT_LIMIT - 1 { return Err(Reason::SourceRefused); }
        components.push(name);
    }
    Ok(components)
}
fn source_extra(components: &[&[u8]]) -> usize { usize::from(components.first().is_some_and(|name| matches!(*name, b"tmp" | b"var"))) }
pub(crate) fn path_hint(path: &Path) -> Result<(), Reason> { parts(path).map(|_| ()) }
pub(crate) fn suffix(kind: FileKind, path: &Path) -> Result<(), Reason> {
    let components = parts(path)?;
    let leaf = components.last().ok_or(Reason::SourceRefused)?;
    let suffix = leaf.rsplit(|byte| *byte == b'.').next().ok_or(Reason::SourceRefused)?;
    let supported = match kind {
        FileKind::AppleP12 => suffix.eq_ignore_ascii_case(b"p12") || suffix.eq_ignore_ascii_case(b"pfx"),
        FileKind::AppleProfile => suffix.eq_ignore_ascii_case(b"mobileprovision"),
        FileKind::IosFirebase => suffix.eq_ignore_ascii_case(b"plist"),
        FileKind::AscP8 => suffix.eq_ignore_ascii_case(b"p8"),
        FileKind::AndroidKeystore => suffix.eq_ignore_ascii_case(b"jks") || suffix.eq_ignore_ascii_case(b"keystore"),
        FileKind::AndroidFirebase => suffix.eq_ignore_ascii_case(b"json"),
    };
    if !supported || !leaf.contains(&b'.') { return Err(Reason::UnsupportedFormat); } Ok(())
}

pub(crate) fn capture(book: &mut SourceBook, path: PathBuf, roots: &[RegisteredRoot], kind: FileKind,
    stop: &mut dyn FnMut() -> bool) -> Result<CapturedSource, Reason> {
    suffix(kind, &path)?;
    if roots.is_empty() || roots.len() > 64 { return Err(Reason::Capacity); }
    let source = parts(&path)?;
    let (leaf_name, parents) = source.split_last().ok_or(Reason::SourceRefused)?;
    let mut root_parts = Vec::new(); root_parts.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
    for root in roots { root.identity.posix()?; root_parts.push(parts(&root.path)?); }
    // One shared root, one canonical private anchor, and the actual source
    // leaf, plus every requested ancestry (including the permitted alias step).
    let capacity = roster_limit(root_parts.iter().map(Vec::len).chain(std::iter::once(parents.len() + source_extra(parents))), 2)?;
    book.begin(capacity, 0, 1)?;
    let result = (|| {
        book.root(stop)?;
        book.anchor_private(stop)?;
        let mut root_ids = Vec::new(); root_ids.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
        for (root, components) in roots.iter().zip(&root_parts) {
            let (chain, _) = book.chain(components, false, stop)?;
            let id = book.directory(*chain.last().ok_or(Reason::SourceRefused)?)?;
            if ProjectIdentity::Posix(id) != root.identity { return Err(Reason::SourceChanged); } root_ids.push(id);
        }
        let (indices, alias) = book.chain(parents, true, stop)?;
        let mut ancestry = Vec::new(); ancestry.try_reserve_exact(indices.len()).map_err(|_| Reason::Capacity)?;
        for index in &indices {
            let id = book.directory(*index)?;
            if root_ids.iter().any(|root| id.same_object(*root)) { return Err(Reason::ProjectOverlap); }
            ancestry.push(id);
        }
        let leaf = book.child(*indices.last().ok_or(Reason::SourceRefused)?, leaf_name, true, stop)?;
        let file = match book.slots[leaf].identity { Some(Identity::File(id)) => id, _ => return Err(Reason::SourceRefused) };
        let size = usize::try_from(file.size).map_err(|_| Reason::MaterialLimit)?;
        if size == 0 || size > material_limit(kind) { return Err(Reason::MaterialLimit); }
        book.private_acl(leaf, 0, stop)?;
        let capacity = size.checked_add(1).ok_or(Reason::MaterialLimit)?;
        let mut bytes = Vec::new(); bytes.try_reserve_exact(capacity).map_err(|_| Reason::Capacity)?;
        if bytes.capacity() > capacity { return Err(Reason::Capacity); } bytes.resize(capacity, 0);
        let mut used = 0usize;
        loop {
            checkpoint(stop)?;
            let end = capacity.min(used.saturating_add(1024 * 1024));
            let read = unistd::read(book.fd(leaf)?, &mut bytes[used..end]).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if read == 0 { if used != size { return Err(Reason::SourceChanged); } break; }
            used = used.checked_add(read).ok_or(Reason::SourceChanged)?;
            if used > size { return Err(Reason::SourceChanged); }
        }
        bytes.truncate(size); // Retained capacity includes the actual EOF sentinel.
        Ok(CapturedSource { bytes, origin: Arc::new(OriginWitness { path: path.clone(), ancestry, leaf: file, alias }) })
    })();
    book.finish(result, stop)
}

pub(crate) fn capture_public_images(book: &mut SourceBook, paths: Vec<PathBuf>, root: &RegisteredRoot, byte_limit: usize,
    stop: &mut dyn FnMut() -> bool, failed: &mut dyn FnMut(Reason)) -> Result<CapturedPublicImageBatch, Reason> {
    use sha2::{Digest, Sha256};
    if !(1..=PUBLIC_IMAGE_FILES).contains(&paths.len()) || paths.capacity() > PUBLIC_IMAGE_FILES
        || paths.iter().any(|path| path.capacity() > PATH_LIMIT)
        || !(1..=PUBLIC_IMAGE_BATCH_BYTES).contains(&byte_limit) { return Err(Reason::MaterialLimit); }
    let expected_root = root.identity.posix()?;
    let root_parts = parts(&root.path)?;
    let mut spellings = Vec::new(); spellings.try_reserve_exact(paths.len()).map_err(|_| Reason::Capacity)?;
    let mut names = Vec::new(); names.try_reserve_exact(paths.len()).map_err(|_| Reason::Capacity)?;
    if spellings.capacity() > PUBLIC_IMAGE_FILES || names.capacity() > PUBLIC_IMAGE_FILES { return Err(Reason::Capacity); }
    for (ordinal, path) in paths.iter().enumerate() {
        let spelling = parts(path)?;
        let name = spelling.last().ok_or(Reason::SourceRefused)?;
        let display_name = public_image_display_name(name, ordinal)?;
        if display_name.capacity() > 255 { return Err(Reason::Capacity); }
        names.push(display_name);
        spellings.push(spelling);
    }
    // One root and one held canonical /private anchor, then every original
    // registered/selected ancestry and leaf, including each possible alias step.
    let capacity = roster_limit(std::iter::once(root_parts.len()).chain(spellings.iter().map(|parts| {
        let parents = &parts[..parts.len() - 1]; parents.len() + source_extra(parents)
    })), paths.len() + 1)?;
    book.begin(capacity, 0, paths.len())?;
    let result = (|| {
        book.root(stop)?;
        book.anchor_private(stop)?;
        // Registered project roots retain the existing no-alias policy. Only
        // selected public input paths may use the already bounded system aliases.
        let (root_chain, _) = book.chain(&root_parts, false, stop)?;
        let root_id = book.directory(*root_chain.last().ok_or(Reason::SourceRefused)?)?;
        if root_id != expected_root { return Err(Reason::SourceChanged); }
        let root_depth = root_chain.len() - 1;
        let mut originals = Vec::new(); originals.try_reserve_exact(paths.len()).map_err(|_| Reason::Capacity)?;
        let mut protected_sources = Vec::new(); protected_sources.try_reserve_exact(paths.len()).map_err(|_| Reason::Capacity)?;
        if originals.capacity() > PUBLIC_IMAGE_FILES || protected_sources.capacity() > PUBLIC_IMAGE_FILES { return Err(Reason::Capacity); }
        let mut total = 0;
        for (path, spelling) in paths.iter().zip(&spellings) {
            let (name, parents) = spelling.split_last().ok_or(Reason::SourceRefused)?;
            let (chain, alias) = book.chain(parents, true, stop)?;
            let mut ancestry = Vec::new(); ancestry.try_reserve_exact(chain.len()).map_err(|_| Reason::Capacity)?;
            if ancestry.capacity() > COMPONENT_LIMIT + 1 { return Err(Reason::Capacity); }
            for index in &chain { ancestry.push(book.directory(*index)?); }
            let parent = *chain.last().ok_or(Reason::SourceRefused)?;
            let leaf = book.child_policy(parent, name, true, LeafPolicy::PublicImage, stop)?;
            let file = match book.slots[leaf].identity { Some(Identity::File(id)) => id, _ => return Err(Reason::SourceRefused) };
            if originals.iter().any(|(_, previous, _, _): &(usize, FileIdentity, Vec<DirectoryIdentity>, Option<OriginAlias>)|
                previous.common.same_object(file.common)) { return Err(Reason::SourceRefused); }
            let (_, next) = public_image_size(total, file.size)?; total = next;
            if total > byte_limit { return Err(Reason::MaterialLimit); }
            // Public mode is NOT permission to bypass the actual same-FD ACL
            // observation or its original native allocation/free outcomes.
            book.private_acl(leaf, 0, stop)?;
            if let Some(relative) = public_protected_source(path, root, root_depth, &ancestry, root_id)? {
                if relative.capacity() > PATH_LIMIT { return Err(Reason::Capacity); }
                protected_sources.push(relative);
            }
            originals.push((leaf, file, ancestry, alias));
        }
        let mut images = Vec::new(); images.try_reserve_exact(paths.len()).map_err(|_| Reason::Capacity)?;
        if images.capacity() > PUBLIC_IMAGE_FILES { return Err(Reason::Capacity); }
        // All sizes and original objects are admitted before any payload buffer.
        // At most24MiB and ten explicit EOF sentinel bytes can be retained here.
        for ((path, display_name), (leaf, file, ancestry, alias)) in paths.iter().zip(names).zip(originals) {
            let original_path = path.to_path_buf();
            if original_path.capacity() > PATH_LIMIT { return Err(Reason::Capacity); }
            let (size, _) = public_image_size(0, file.size)?;
            let capacity = size.checked_add(1).ok_or(Reason::MaterialLimit)?;
            let mut bytes = Vec::new(); bytes.try_reserve_exact(capacity).map_err(|_| Reason::Capacity)?;
            if bytes.capacity() > capacity { return Err(Reason::Capacity); }
            bytes.resize(capacity, 0);
            let mut used = 0usize; let mut hash = Sha256::new();
            loop {
                checkpoint(stop)?;
                let end = capacity.min(used.saturating_add(1024 * 1024));
                let read = unistd::read(book.fd(leaf)?, &mut bytes[used..end]).map_err(|_| Reason::SourceRefused)?;
                checkpoint(stop)?;
                if read == 0 { if used != size { return Err(Reason::SourceChanged); } break; }
                let next = used.checked_add(read).ok_or(Reason::SourceChanged)?;
                if next > size { return Err(Reason::SourceChanged); }
                hash.update(&bytes[used..next]); used = next;
            }
            bytes.truncate(size);
            let item_id = public_image_token(stop)?;
            if images.iter().any(|image: &CapturedPublicImage| image.item_id == item_id) { return Err(Reason::SourceRefused); }
            images.push(CapturedPublicImage { item_id, display_name, bytes, sha256: format!("{:x}", hash.finalize()),
                origin: OriginWitness { path: original_path, ancestry, leaf: file, alias } });
        }
        Ok(CapturedPublicImageBatch { images, protected_sources })
    })();
    book.finish_public_images(result, stop, failed)
}

pub(crate) fn probe_project(book: &mut SourceBook, path: PathBuf, origins: &[Arc<OriginWitness>],
    stop: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> {
    probe_project_excluding_vault(book,path,origins,None,stop)
}
pub(crate) fn probe_project_excluding_vault(book: &mut SourceBook, path: PathBuf, origins: &[Arc<OriginWitness>],
    vault: Option<&RegisteredRoot>, stop: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> {
    if origins.len() > 32 { return Err(Reason::Capacity); }
    let project_parts = parts(&path)?;
    let mut origin_parts = Vec::new(); origin_parts.try_reserve_exact(origins.len()).map_err(|_| Reason::Capacity)?;
    for origin in origins { origin_parts.push(parts(&origin.path)?); }
    let vault_parts=vault.map(|root| parts(&root.path)).transpose()?;
    let capacity = roster_limit(std::iter::once(project_parts.len()).chain(origin_parts.iter()
        .map(|parts| parts.len().saturating_sub(1) + source_extra(&parts[..parts.len().saturating_sub(1)])))
        .chain(vault_parts.iter().map(Vec::len)), usize::from(!origins.is_empty()))?;
    book.begin(capacity, origins.len(), origins.len())?;
    let result = (|| {
        book.root(stop)?;
        if !origins.is_empty() { book.anchor_private(stop)?; }
        let (project_chain, _) = book.chain(&project_parts, false, stop)?;
        let project = book.directory(*project_chain.last().ok_or(Reason::SourceRefused)?)?;
        if let (Some(vault),Some(components))=(vault,&vault_parts) {
            let (vault_chain,_)=book.chain(components,false,stop)?;
            let current=book.directory(*vault_chain.last().ok_or(Reason::ExclusionUnconfirmed)?)?;
            if ProjectIdentity::Posix(current) != vault.identity { return Err(Reason::ExclusionUnconfirmed); }
            reject_ancestry_overlap(book,&project_chain,&vault_chain,stop)?;
        }
        for (origin, components) in origins.iter().zip(&origin_parts) {
            let (leaf_name, parents) = components.split_last().ok_or(Reason::ExclusionUnconfirmed)?;
            let (chain, alias) = book.chain(parents, true, stop)?;
            if chain.len() != origin.ancestry.len() || alias != origin.alias { return Err(Reason::ExclusionUnconfirmed); }
            for (index, expected) in chain.iter().zip(&origin.ancestry) {
                let id = book.directory(*index)?;
                if id != *expected { return Err(Reason::ExclusionUnconfirmed); }
                if id.same_object(project) { return Err(Reason::ProjectOverlap); }
            }
            let parent = *chain.last().ok_or(Reason::ExclusionUnconfirmed)?;
            checkpoint(stop)?;
            // Fresh parent metadata only; no source leaf open/read/hash or
            // recapture. All saved originals are checked, not just a path prefix.
            let named = stat::fstatat(book.fd(parent)?, OsStr::from_bytes(leaf_name), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| Reason::ExclusionUnconfirmed)?;
            checkpoint(stop)?;
            if file_identity(&named)? != origin.leaf { return Err(Reason::ExclusionUnconfirmed); }
            if book.probes.len() >= book.probes.capacity() { return Err(Reason::Capacity); }
            book.probes.push(LeafProbe { parent, name: copy_bytes(leaf_name)?, identity: origin.leaf });
        }
        Ok(ProjectProbe { path: path.clone(), identity: ProjectIdentity::Posix(project) })
    })();
    book.finish(result, stop)
}


// Original physical identity, not path text or a cached registry generation.
// APFS firmlink/case spellings may differ while the same device/inode overlaps.
fn reject_ancestry_overlap(book: &SourceBook, project: &[usize], vault: &[usize],
    stop: &mut dyn FnMut() -> bool) -> Result<(),Reason> {
    let project_root=book.directory(*project.last().ok_or(Reason::ExclusionUnconfirmed)?)?;
    let vault_root=book.directory(*vault.last().ok_or(Reason::ExclusionUnconfirmed)?)?;
    for index in project {
        checkpoint(stop)?;
        if book.directory(*index)?.same_object(vault_root) { return Err(Reason::ProjectOverlap); }
    }
    for index in vault {
        checkpoint(stop)?;
        if book.directory(*index)?.same_object(project_root) { return Err(Reason::ProjectOverlap); }
    }
    checkpoint(stop)
}
pub(crate) fn probe_vault_exclusion(book: &mut SourceBook, vault: Option<&RegisteredRoot>,
    projects: &[RegisteredRoot], stop: &mut dyn FnMut() -> bool) -> Result<VaultAbsentExclusion,Reason> {
    if projects.len() > 32 { return Err(Reason::Capacity); }
    let vault_parts=vault.map(|root| parts(&root.path)).transpose()?;
    let mut project_parts=Vec::new(); project_parts.try_reserve_exact(projects.len()).map_err(|_| Reason::Capacity)?;
    for project in projects { project_parts.push(parts(&project.path)?); }
    let capacity=roster_limit(vault_parts.iter().map(Vec::len).chain(project_parts.iter().map(Vec::len)),0)?;
    book.begin(capacity,0,0)?;
    let result=(|| {
        book.root(stop)?;
        let vault_chain=if let (Some(vault),Some(components))=(vault,&vault_parts) {
            let (chain,_)=book.chain(components,false,stop)?;
            if ProjectIdentity::Posix(book.directory(*chain.last().ok_or(Reason::ExclusionUnconfirmed)?)?) != vault.identity {
                return Err(Reason::ExclusionUnconfirmed);
            }
            Some(chain)
        } else { None };
        let mut project_roots=Vec::new(); project_roots.try_reserve_exact(projects.len()).map_err(|_| Reason::Capacity)?;
        for (project,components) in projects.iter().zip(&project_parts) {
            let (chain,_)=book.chain(components,false,stop)?;
            let current=book.directory(*chain.last().ok_or(Reason::ExclusionUnconfirmed)?)?;
            if ProjectIdentity::Posix(current) != project.identity { return Err(Reason::ExclusionUnconfirmed); }
            if let Some(vault_chain)=&vault_chain { reject_ancestry_overlap(book,&chain,vault_chain,stop)?; }
            project_roots.push(current);
        }
        Ok(VaultAbsentExclusion { project_roots })
    })();
    // Terminal same-held/name checks and actual one-use closes precede this
    // probe's return. The existing document owner separately requires child join.
    book.finish(result,stop)
}

struct ProjectPathSpelling<'a> { components: Vec<&'a [u8]>, root_depth: usize, relative_path: String }
fn project_path_spelling<'a>(root: &Path, path: &'a Path, field: ProjectPathField) -> Result<ProjectPathSpelling<'a>, Reason> {
    // Match the existing field policy without normalizing a native selection.
    // The real root is subsequently checked and held by this same SourceBook.
    let root_parts = parts(root)?;
    let components = parts(path)?;
    if components.len() <= root_parts.len() || !components.starts_with(&root_parts) { return Err(Reason::SourceRefused); }
    let start = root.as_os_str().as_bytes().len() + usize::from(!root_parts.is_empty());
    let relative = std::str::from_utf8(&path.as_os_str().as_bytes()[start..]).map_err(|_| Reason::SourceRefused)?;
    if !crate::release_version_protocol::relative_display_path(relative)
        || !field.accepts_basename(relative.rsplit('/').next().ok_or(Reason::SourceRefused)?) { return Err(Reason::SourceRefused); }
    let relative_path = crate::asset_commands::copy_text(relative).map_err(|error| error.reason)?;
    Ok(ProjectPathSpelling { components, root_depth: root_parts.len(), relative_path })
}
fn project_path_file_leaf(file: FileIdentity, parent: DirectoryIdentity) -> bool {
    file.common.mode & u32::from(SFlag::S_IFMT.bits()) == u32::from(SFlag::S_IFREG.bits())
        && file.nlink == 1 && file.common.dev == parent.dev
}
pub(crate) fn probe_project_path(book: &mut SourceBook, root: &RegisteredRoot, path: PathBuf, field: ProjectPathField,
    stop: &mut dyn FnMut() -> bool) -> Result<ProjectPathProbe, Reason> {
    let root_identity = root.identity.posix()?;
    let spelling = project_path_spelling(&root.path, &path, field)?;
    let file = !field.directory();
    let capacity = roster_limit([spelling.components.len() - usize::from(file)], 0)?;
    book.begin(capacity, usize::from(file), 0)?;
    let result = (|| {
        book.root(stop)?;
        let (chain, _) = book.chain(&spelling.components[..spelling.root_depth], false, stop)?;
        let mut parent = *chain.last().ok_or(Reason::SourceRefused)?;
        if book.directory(parent)? != root_identity { return Err(Reason::SourceChanged); }
        let (leaf, parents) = spelling.components[spelling.root_depth..].split_last().ok_or(Reason::SourceRefused)?;
        for name in parents { parent = book.child(parent, name, false, stop)?; }
        if field.directory() {
            book.child(parent, leaf, false, stop)?;
        } else {
            let name = copy_bytes(leaf)?;
            let parent_identity = book.directory(parent)?;
            checkpoint(stop)?;
            // Version-file selection is metadata DATA only. Do not open or
            // read the leaf, or relax the private credential capture policy.
            let metadata = stat::fstatat(book.fd(parent)?, OsStr::from_bytes(leaf), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let identity = file_identity(&metadata)?;
            if !project_path_file_leaf(identity, parent_identity) { return Err(Reason::SourceRefused); }
            if book.probes.len() >= book.probes.capacity() { return Err(Reason::Capacity); }
            book.probes.push(LeafProbe { parent, name, identity });
        }
        Ok(ProjectPathProbe { relative_path: spelling.relative_path })
    })();
    // Final original-root/leaf rechecks and consuming closes are unchanged.
    book.finish(result, stop)
}

#[cfg(test)]
pub(crate) fn assert_installed_macos_images_source_contract() {
    // Existing harness=false entry calls these actual inert definitions. No
    // native file, descriptor, ACL temporary or successful capture is invented.
    tests::public_images_keep_private_leaf_policy_and_full_roster_bounds();
    tests::image_failure_is_reported_before_independent_cleanup_and_unknown_stays_unknown();
    tests::only_local_ownership_aware_apfs_is_admitted();
    tests::root_aliases_are_exact_and_physical_protection_is_not_path_text();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vault_exclusion_compares_both_physical_ancestries_not_spellings() {
        let identity=|dev,ino| DirectoryIdentity { dev,ino,mode:0o40700,uid:501,gid:20 };
        let mut book=SourceBook::new(); book.begin(6,0,0).unwrap();
        for (dev,ino) in [(1,2),(2,10),(2,20),(2,30),(3,20),(2,40)] {
            let at=book.reserve(None,b"inert").unwrap();
            book.slots[at].identity=Some(Identity::Directory(identity(dev,ino)));
        }
        assert_eq!(reject_ancestry_overlap(&book,&[0,1,2],&[0,1,2,3],&mut || false),Err(Reason::ProjectOverlap));
        assert_eq!(reject_ancestry_overlap(&book,&[0,1,2,3],&[0,1,2],&mut || false),Err(Reason::ProjectOverlap));
        assert_eq!(reject_ancestry_overlap(&book,&[0,1,2],&[0,1,5],&mut || false),Ok(()));
        assert_eq!(reject_ancestry_overlap(&book,&[0,1,2],&[0,4],&mut || false),Ok(()));
        assert_eq!(reject_ancestry_overlap(&book,&[0,1,2],&[0,1,5],&mut || true),Err(Reason::UserCancelled));
        assert!(book.close_all()); // Reserved DATA slots only: no close syscall.
    }

    #[test]
    fn project_fields_are_strict_descendant_data_not_credential_capture() {
        let root = Path::new("/inert/project");
        for (path, field, relative) in [
            ("/inert/project/inputs/VERSION", ProjectPathField::VersionSource, "inputs/VERSION"),
            ("/inert/project/ios/App.xcodeproj", ProjectPathField::IosProject, "ios/App.xcodeproj"),
            ("/inert/project/ios/App.xcworkspace", ProjectPathField::IosWorkspace, "ios/App.xcworkspace"),
            ("/inert/project/metadata", ProjectPathField::MetadataRoot, "metadata"),
        ] {
            let selected = project_path_spelling(root, Path::new(path), field).unwrap();
            assert_eq!(selected.root_depth, 2); assert_eq!(selected.relative_path, relative);
        }
        let parent = DirectoryIdentity { dev: 1, ino: 2, mode: 0o40755, uid: 501, gid: 20 };
        let registered = RegisteredRoot { path: root.to_path_buf(), identity: ProjectIdentity::Posix(parent) };
        for (path, field) in [
            ("/inert/project2/VERSION", ProjectPathField::VersionSource),
            ("/inert/project", ProjectPathField::MetadataRoot),
            ("/inert/project/../VERSION", ProjectPathField::VersionSource),
            ("/inert/project//VERSION", ProjectPathField::VersionSource),
            ("/inert/project/secrets/VERSION", ProjectPathField::VersionSource),
            ("/inert/project/App.XCODEPROJ", ProjectPathField::IosProject),
            ("/inert/project/App.xcodeproj", ProjectPathField::IosWorkspace),
        ] {
            let mut book = SourceBook::new();
            assert!(matches!(probe_project_path(&mut book, &registered, PathBuf::from(path), field, &mut || true), Err(Reason::SourceRefused)));
            assert!(book.not_started() && !book.settled()); // No native entry.
        }
        let file = FileIdentity { common: DirectoryIdentity { ino: 3, mode: 0o100644, ..parent },
            nlink: 1, size: 0, mtime: (1, 2), ctime: (3, 4) };
        assert!(project_path_file_leaf(file, parent)); assert!(!private_file(file.common.mode));
        assert!(project_path_file_leaf(FileIdentity { size: u64::MAX, ..file }, parent));
        for nlink in [0, 2] { assert!(!project_path_file_leaf(FileIdentity { nlink, ..file }, parent)); }
        assert!(!project_path_file_leaf(FileIdentity { common: DirectoryIdentity { dev: 2, ..file.common }, ..file }, parent));
        for mode in [0o40755, 0o120777, 0o10600, 0o20600] {
            assert!(!project_path_file_leaf(FileIdentity { common: DirectoryIdentity { mode, ..file.common }, ..file }, parent));
        }
    }
    #[test]
    fn project_spellings_are_bounded_without_canonicalization() {
        assert!(parts(Path::new("/Users/owner/project")).is_ok());
        assert!(parts(Path::new("/System/Volumes/Data/Users/owner/project")).is_ok());
        for path in ["", "relative", "//Users", "/Users/", "/Users/./project", "/Users/../project", "/nul\0project"] { assert!(parts(Path::new(path)).is_err()); }
        assert!(parts(Path::new(&format!("/{}", "a".repeat(256)))).is_err());
        assert!(parts(Path::new(&format!("/{}", vec!["a"; COMPONENT_LIMIT].join("/")))).is_err());
    }
    #[test]
    pub(super) fn only_local_ownership_aware_apfs_is_admitted() {
        assert!(admitted_filesystem("apfs", MntFlags::MNT_LOCAL));
        assert!(admitted_filesystem("apfs", MntFlags::MNT_LOCAL | MntFlags::MNT_RDONLY));
        for name in ["hfs", "nfs", "smbfs", "webdav", "autofs", "APFS", ""] { assert!(!admitted_filesystem(name, MntFlags::MNT_LOCAL)); }
        assert!(!admitted_filesystem("apfs", MntFlags::empty()));
        for flag in [MntFlags::MNT_UNION, MntFlags::MNT_AUTOMOUNTED, MntFlags::MNT_IGNORE_OWNERSHIP] { assert!(!admitted_filesystem("apfs", MntFlags::MNT_LOCAL | flag)); }
    }
    #[test]
    fn original_book_never_reuses_or_relabels_unknown_acquisitions() {
        let mut book = SourceBook::new(); assert!(book.not_started()); assert!(!book.settled());
        book.begin(1, 0, 0).unwrap(); let index = book.reserve(None, b"/").unwrap();
        assert!(!book.not_started()); assert!(!book.settled());
        book.slots[index].state = OriginalState::Acquiring; // DATA only; no descriptor.
        assert!(!book.close_all()); assert!(!book.settled());
        assert!(!book.close_all()); assert!(book.begin(1, 0, 0).is_err());
        book.slots[index].state = OriginalState::Unknown; assert!(!book.close_all()); assert!(!book.settled());
    }
    #[test]
    fn private_asset_suffixes_admit_android_without_broadening_apple_formats() {
        for (kind, path) in [(FileKind::AppleP12, "/inert/cert.P12"), (FileKind::AppleP12, "/inert/cert.pfx"),
            (FileKind::AppleProfile, "/inert/app.mobileprovision"), (FileKind::IosFirebase, "/inert/google.PLIST"),
            (FileKind::AscP8, "/inert/AuthKey.P8"),
            (FileKind::AndroidKeystore, "/inert/upload.production.JKS"),
            (FileKind::AndroidKeystore, "/inert/upload.keystore"), (FileKind::AndroidKeystore, "/inert/key.jks.jks"),
            (FileKind::AndroidFirebase, "/inert/google-services.JSON")] {
            assert!(suffix(kind, Path::new(path)).is_ok());
        }
        for (kind, path) in [(FileKind::AppleP12, "/inert/p12"), (FileKind::AppleP12, "/inert/cert.pem"),
            (FileKind::AppleProfile, "/inert/profile.plist"), (FileKind::AppleProfile, "/inert/app.mobileprovision.p12"),
            (FileKind::AndroidKeystore, "/inert/key.p12"), (FileKind::AndroidKeystore, "/inert/key.pfx"),
            (FileKind::AndroidKeystore, "/inert/key.jks.p12"), (FileKind::AndroidKeystore, "/inert/jks"),
            (FileKind::AndroidFirebase, "/inert/config.json.bak"), (FileKind::AndroidFirebase, "/inert/config.plist"),
            (FileKind::AndroidFirebase, "/inert/json"),
            (FileKind::AscP8, "/inert/p8"), (FileKind::AscP8, "/inert/key.pem"), (FileKind::AscP8, "/inert/key.p8.p12")] {
            assert!(suffix(kind, Path::new(path)).is_err());
        }
    }
    #[test]
    pub(super) fn root_aliases_are_exact_and_physical_protection_is_not_path_text() {
        let root = DirectoryIdentity { dev: 1, ino: 2, mode: 0o40755, uid: 0, gid: 0 };
        assert!(PhysicalRole::Root.protected(root) && PhysicalRole::Private.protected(root) && PhysicalRole::Var.protected(root));
        assert!(!PhysicalRole::Private.protected(DirectoryIdentity { uid: 501, ..root }));
        assert!(!PhysicalRole::Var.protected(DirectoryIdentity { mode: 0o40775, ..root }));
        assert!(PhysicalRole::Tmp.protected(DirectoryIdentity { mode: 0o41777, ..root }));
        assert!(!PhysicalRole::Tmp.protected(DirectoryIdentity { mode: 0o40777, ..root }));
        let link = FileIdentity { common: DirectoryIdentity { mode: 0o120755, ..root }, nlink: 1, size: 11, mtime: (1, 2), ctime: (3, 4) };
        assert!(alias_metadata(b"tmp", link)); assert!(alias_metadata(b"var", link));
        for name in [b"TMP".as_slice(), b"Private", b"home", b"../tmp"] { assert!(!alias_metadata(name, link)); }
        assert!(!alias_metadata(b"tmp", FileIdentity { common: root, ..link }));
        assert!(!alias_metadata(b"tmp", FileIdentity { common: DirectoryIdentity { uid: 501, ..link.common }, ..link }));
        for (name, target) in [(b"tmp".as_slice(), b"private/tmp".as_slice()), (b"tmp", b"/private/tmp"), (b"var", b"private/var"), (b"var", b"/private/var")] { assert!(alias_target(name, target)); }
        for target in [b"private/var".as_slice(), b"//private/tmp", b"/private/../tmp", b"/private/tmp/", b"/private/TMP"] { assert!(!alias_target(b"tmp", target)); }
    }
    #[test]
    fn entered_native_checks_remain_uncertain_after_descriptor_book_retirement() {
        for state in [CallState::Entered, CallState::Unknown] {
            let mut book = SourceBook::new(); book.begin(1, 0, 0).unwrap(); let i = book.reserve(None, b"/").unwrap();
            book.slots[i].state = OriginalState::NoHandle; book.slots[i].acl[0] = state;
            assert!(!book.close_all()); assert!(!book.settled()); assert!(!book.close_all());
        }
        let mut book = SourceBook::new(); book.begin(1, 0, 0).unwrap(); let i = book.reserve(None, b"/").unwrap();
        book.slots[i].acl = [CallState::Settled; 2]; assert!(book.close_all());
        assert!(book.retained_bytes().unwrap() >= std::mem::size_of::<Descriptor>() + 1);
    }
    #[test]
    fn protected_objects_are_recognized_even_from_another_firmlink_parent_role() {
        // Predicate DATA only. No open/ACL call is entered and these synthetic
        // identities are never a capture/project qualification receipt.
        let private = DirectoryIdentity { dev: 2, ino: 3, mode: 0o40755, uid: 0, gid: 0 };
        let var = DirectoryIdentity { ino: 4, ..private };
        let tmp = DirectoryIdentity { ino: 5, mode: 0o41777, ..private };
        let mut book = SourceBook::new(); book.begin(1, 0, 0).unwrap();
        let index = book.reserve(None, b"inert").unwrap();
        book.slots[index].identity = Some(Identity::Directory(private));
        book.anchors = Some(PhysicalAnchors { private: index, var, tmp });
        assert!(book.slots[index].role == PhysicalRole::Other);
        for (id, role) in [(private, PhysicalRole::Private), (var, PhysicalRole::Var), (tmp, PhysicalRole::Tmp)] {
            assert!(book.physical_role(index, id, &mut || panic!("no native call in identity predicate")).unwrap() == role);
            assert!(matches!(book.physical_role(index, DirectoryIdentity { uid: 501, ..id }, &mut || false), Err(Reason::SourceChanged)));
        }
        assert!(book.close_all());
    }
    #[test]
    fn complete_alias_rosters_are_bounded_before_any_native_acquisition() {
        assert_eq!(source_extra(&[b"tmp", b"owned"]), 1); assert_eq!(source_extra(&[b"private", b"tmp"]), 0);
        assert!(roster_limit([510], 1).is_ok()); assert!(roster_limit([511], 1).is_err());
        let mut book = SourceBook::new(); assert!(book.begin(513, 0, 0).is_err()); assert!(book.not_started());
        assert!(book.begin(1, 33, 0).is_err()); assert!(book.not_started());
        assert!(book.begin(1, 0, 33).is_err()); assert!(book.not_started());
        // Early STOP proves only that no original was acquired, never APFS
        // capture/identity/cleanup qualification on a synthetic fixture.
        let result = probe_project(&mut book, "/inert/project".into(), &[], &mut || true);
        assert!(matches!(result, Err(Reason::UserCancelled))); assert!(book.settled());
    }
    #[test]
    pub(super) fn public_images_keep_private_leaf_policy_and_full_roster_bounds() {
        let common = DirectoryIdentity { dev: 1, ino: 2, mode: 0o100644, uid: 501, gid: 20 };
        let file = FileIdentity { common, nlink: 1, size: 10, mtime: (1, 2), ctime: (3, 4) };
        for mode in [0o100444, 0o100644, 0o100664] {
            let image = FileIdentity { common: DirectoryIdentity { mode, ..common }, ..file };
            assert!(LeafPolicy::PublicImage.permits(image));
            assert!(!LeafPolicy::Private.permits(image));
        }
        assert!(LeafPolicy::Private.permits(FileIdentity { common: DirectoryIdentity { mode: 0o100600, ..common }, ..file }));
        for nlink in [0, 2, u64::MAX] { assert!(!LeafPolicy::PublicImage.permits(FileIdentity { nlink, ..file })); }
        for bits in [0o1000, 0o2000, 0o4000] {
            assert!(!LeafPolicy::PublicImage.permits(FileIdentity { common: DirectoryIdentity { mode: common.mode | bits, ..common }, ..file }));
        }
        assert!(PUBLIC_IMAGES_SOURCE_CONTROL_BYTES <= 512 * 1024);
        let project = DirectoryIdentity { mode: 0o40700, ..common };
        let root = RegisteredRoot { path: "/private/tmp/project".into(), identity: ProjectIdentity::Posix(project) };
        let directory = DirectoryIdentity { dev: 1, ino: 1, mode: 0o40755, uid: 0, gid: 0 };
        let ancestry = [directory, DirectoryIdentity { ino: 3, ..directory }, DirectoryIdentity { ino: 4, ..directory }, project];
        assert_eq!(public_protected_source(Path::new("/private/tmp/project/assets/source.png"), &root, 3, &ancestry, project),
            Ok(Some("assets/source.png".into())));
        assert_eq!(public_protected_source(Path::new("/tmp/project/assets/source.png"), &root, 3, &ancestry, project),
            Err(Reason::SourceRefused)); // physical alias cannot omit source preservation
        assert_eq!(public_protected_source(Path::new("/private/tmp/project/assets/source.png"), &root, 3, &ancestry[..3], project),
            Err(Reason::SourceRefused)); // lexical prefix cannot invent physical containment
        let mut overallocated = Vec::with_capacity(PUBLIC_IMAGE_FILES + 1); overallocated.push(PathBuf::from("/inert/a.png"));
        for paths in [Vec::new(), vec![PathBuf::from("/inert/a.png"); PUBLIC_IMAGE_FILES + 1], overallocated,
            vec![PathBuf::from("/inert/../a.png")], vec![PathBuf::from("/inert/signing.p12")]] {
            let mut book = SourceBook::new();
            assert!(capture_public_images(&mut book, paths, &root, PUBLIC_IMAGE_BATCH_BYTES,
                &mut || panic!("up-front refusal must not enter native acquisition"), &mut |_| {}).is_err());
            assert!(book.not_started() && !book.settled());
        }
    }
    #[test]
    pub(super) fn image_failure_is_reported_before_independent_cleanup_and_unknown_stays_unknown() {
        for native_unknown in [false, true] {
            let mut book = SourceBook::new(); book.begin(3, 0, 0).unwrap();
            let first = book.reserve(None, b"first").unwrap();
            let middle = book.reserve(None, b"middle").unwrap();
            let last = book.reserve(None, b"last").unwrap();
            // State DATA only. Neither branch owns a descriptor or invokes a
            // native close, but both run the real failure/settlement ordering.
            if native_unknown {
                book.slots[middle].state = OriginalState::NoHandle;
                book.slots[middle].acl[0] = CallState::Entered;
            } else { book.slots[middle].state = OriginalState::Acquiring; }
            let mut failures = Vec::new();
            assert_eq!(book.finish_public_images::<()>(Err(Reason::SourceChanged), &mut || true,
                &mut |reason| failures.push(reason)), Err(Reason::CleanupUnknown));
            assert_eq!(failures, vec![Reason::SourceChanged, Reason::CleanupUnknown]);
            assert!(matches!(book.slots[first].state, OriginalState::NoHandle));
            assert!(matches!(book.slots[last].state, OriginalState::NoHandle));
            assert!(!book.settled() && book.terminal);
        }
        let mut book = SourceBook::new(); book.begin(1, 0, 0).unwrap(); book.reserve(None, b"never-opened").unwrap();
        let mut failures = Vec::new();
        assert_eq!(book.finish_public_images::<()>(Err(Reason::SourceChanged), &mut || true,
            &mut |reason| failures.push(reason)), Err(Reason::SourceChanged));
        assert_eq!(failures, vec![Reason::SourceChanged]); assert!(book.settled());
    }
}
