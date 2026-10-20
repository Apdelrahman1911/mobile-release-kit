//! Fixed conventional locations, on the SAME acquisition SourceSlots.
//! No PATH/environment scan, process, SourceSnapshot constructor or tool lease.
use super::*;
use crate::tool_acquisition_protocol::discovery::{self as data, Discovery};
use mrk_macos_installed_native::local_account::Account;
use std::path::PathBuf;
#[path = "android_registration_source_sdkman_macos.rs"]
mod sdkman;

pub(super) const HEAP_BOUND: usize = 3 * (4096 + 255);
pub(super) const PATH_WORK: usize = 4096;
struct Absent {
    parent: usize,
    name: String,
}
pub(super) struct DiscoveryWork {
    // Retained BEFORE getpwuid_r. The containing original worker owns its call
    // and return; the later native joins cannot be replaced by this DATA.
    account: Account,
    account_entered: bool,
    // Slot3 is only the exact SDKMAN fallback for role2. The original fixed
    // Gradle path/absence stays in slot2 through POST and consuming closes.
    paths: [Option<PathBuf>; 4],
    absent: [Option<Absent>; 4],
    searched: u8,
    present: u8,
    finding: Option<Discovery>,
}
impl DiscoveryWork {
    pub(super) fn new() -> Self {
        Self {
            account: Account::new(),
            account_entered: false,
            paths: std::array::from_fn(|_| None),
            absent: std::array::from_fn(|_| None),
            searched: 0,
            present: 0,
            finding: None,
        }
    }
    pub(super) fn heap_bytes(&self) -> Option<usize> {
        let mut bytes = 0usize;
        for path in self.paths.iter().flatten() {
            bytes = bytes.checked_add(path.capacity())?;
        }
        for absent in self.absent.iter().flatten() {
            bytes = bytes.checked_add(absent.name.capacity())?;
        }
        (bytes <= HEAP_BOUND).then_some(bytes)
    }
    pub(super) fn call_settled(&self) -> bool {
        self.account.call_settled()
    }
}

fn fixed_path(role: usize, home: Option<&str>) -> Result<PathBuf> {
    let (base, suffix) = match role {
        0 => (data::JDK, ""),
        1 => (home.ok_or(AdmissionFailure::Ownership)?, data::SDK_SUFFIX),
        2 => (data::GRADLE, ""),
        sdkman::SLOT => (home.ok_or(AdmissionFailure::Ownership)?, sdkman::SUFFIX),
        _ => return Err(AdmissionFailure::Inventory),
    };
    let bytes = base
        .len()
        .checked_add(suffix.len())
        .filter(|n| *n <= 4096)
        .ok_or(AdmissionFailure::Bounds)?;
    if !base.starts_with('/')
        || base == "/"
        || base[1..].split('/').any(|p| {
            p.is_empty()
                || p == "."
                || p == ".."
                || p.len() > 255
                || p.chars().any(char::is_control)
                || p.contains('\\')
        })
    {
        return Err(AdmissionFailure::Ownership);
    }
    let mut text = String::new();
    text.try_reserve_exact(bytes).map_err(native_error)?;
    text.push_str(base);
    text.push_str(suffix);
    if text.capacity() > bytes || text[1..].split('/').count() >= ANCESTORS {
        return Err(AdmissionFailure::Bounds);
    }
    Ok(text.into())
}

impl SourceSlots {
    fn discovery_path(
        &mut self,
        location: usize,
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<()> {
        self.point(end, stop)?;
        let work = &mut self.acquisition.as_mut().ok_or(AdmissionFailure::Unknown)?.discovery;
        if location >= work.paths.len() || work.paths[location].is_some() {
            return Err(AdmissionFailure::Inventory);
        }
        let needs_home = matches!(location, 1 | sdkman::SLOT);
        if needs_home && !work.account_entered {
            work.account_entered = true; // One original call, including failed entry.
            work.account.acquire().map_err(|_| AdmissionFailure::Ownership)?;
        }
        self.point(end, stop)?;
        let work = &mut self.acquisition.as_mut().ok_or(AdmissionFailure::Unknown)?.discovery;
        let home = if needs_home {
            let (home, uid, _) = work.account.selected().map_err(|_| AdmissionFailure::Ownership)?;
            if Some(uid) != self.account { return Err(AdmissionFailure::Ownership); }
            Some(home)
        } else { None };
        work.paths[location] = Some(fixed_path(location, home)?);
        // Same reservation, not a fourth4096-byte allocation allowance.
        work.heap_bytes().ok_or(AdmissionFailure::Bounds)?;
        Ok(())
    }
    /// One retained fixed path. None means only actual held-parent ENOENT;
    /// failed/unsafe/present-but-incompatible sources never take the fallback.
    fn discovery_location(
        &mut self,
        location: usize,
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<Option<usize>> {
        let work = &self.acquisition.as_ref().ok_or(AdmissionFailure::Unknown)?.discovery;
        let path = work.paths.get(location).and_then(Option::as_ref)
            .and_then(|p| p.to_str()).ok_or(AdmissionFailure::Bounds)?;
        // The path stays retained on every failure. Only its bounded stack
        // copy is used while the SAME source arrays mutate below.
        let mut bytes = [0u8; PATH_WORK];
        bytes[..path.len()].copy_from_slice(path.as_bytes());
        let path = std::str::from_utf8(&bytes[..path.len()]).map_err(native_error)?;
        let slash = self.open(None, Name::Static("/"), true, false, false, end, stop)?;
        self.originals[slash].retained = true;
        let mut parent = slash;
        for part in path[1..].split('/') {
            self.check(parent, end, stop)?;
            let absent = absent_entry(
                stat::fstatat(self.fd(parent)?, part, AtFlags::AT_SYMLINK_NOFOLLOW).map(|_| ()),
            )?;
            self.check(parent, end, stop)?;
            if absent {
                self.acquisition.as_mut().ok_or(AdmissionFailure::Unknown)?.discovery.absent[location] =
                    Some(Absent { parent, name: text_owned(part, 255)? });
                return Ok(None);
            }
            parent = self.open(Some(parent), Name::Owned(text_owned(part, 255)?),
                true, false, false, end, stop)?;
            self.originals[parent].retained = true;
        }
        self.originals[parent].selected = true;
        self.check(parent, end, stop)?;
        Ok(Some(parent))
    }
    fn discovery_check_absent(
        &mut self,
        location: usize,
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<()> {
        let absent = self.acquisition.as_ref().ok_or(AdmissionFailure::Unknown)?.discovery
            .absent.get(location).and_then(Option::as_ref).ok_or(AdmissionFailure::Inventory)?;
        let parent = absent.parent;
        let mut bytes = [0u8; 255];
        let len = absent.name.len();
        bytes[..len].copy_from_slice(absent.name.as_bytes());
        let name = std::str::from_utf8(&bytes[..len]).map_err(native_error)?;
        self.check(parent, end, stop)?;
        let absent = absent_entry(
            stat::fstatat(self.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW).map(|_| ()),
        )?;
        self.check(parent, end, stop)?;
        if !absent { return Err(AdmissionFailure::Identity); }
        Ok(())
    }
    /// Prepare ONLY unchosen fixed paths; explicit picks always win. Opening
    /// these read-only originals never installs a selected-source snapshot.
    pub(super) fn discovery_begin(
        &mut self,
        roots: &[Option<RegisteredRoot>; 3],
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<()> {
        // Preserve the existing SDK lookup's account-call order. With an
        // explicit SDK pick, the account is needed only after primary Gradle
        // absence; the fallback uses this same one-shot original below.
        if roots[1].is_none() {
            self.point(end, stop)?;
            let work = &mut self.acquisition.as_mut().ok_or(AdmissionFailure::Unknown)?.discovery;
            if work.account_entered { return Err(AdmissionFailure::Inventory); }
            work.account_entered = true;
            work.account.acquire().map_err(|_| AdmissionFailure::Ownership)?;
            self.point(end, stop)?;
        }
        for (role, root) in roots.iter().enumerate() {
            if root.is_some() {
                continue;
            }
            self.discovery_path(role, end, stop)?;
            self.acquisition.as_mut().ok_or(AdmissionFailure::Unknown)?.discovery.searched |= 1 << role;
            let mut selected = self.discovery_location(role, end, stop)?;
            if role == 2 && selected.is_none() {
                selected = self.discovery_sdkman_gradle(end, stop)?;
            }
            if let Some(parent) = selected {
                self.roots[role] = Some(parent);
                self.acquisition
                    .as_mut()
                    .ok_or(AdmissionFailure::Unknown)?
                    .discovery
                    .present |= 1 << role;
            }
        }
        Ok(())
    }
    pub(super) fn discovery_finish(
        &mut self,
        parts: Partition,
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<()> {
        for location in 0..4 {
            if self.acquisition.as_ref().ok_or(AdmissionFailure::Unknown)?.discovery.absent[location].is_some() {
                self.discovery_check_absent(location, end, stop)?;
            }
        }
        self.point(end, stop)?;
        let work = &mut self
            .acquisition
            .as_mut()
            .ok_or(AdmissionFailure::Unknown)?
            .discovery;
        work.finding = Some(
            Discovery::observed(work.searched, work.present, parts)
                .ok_or(AdmissionFailure::Inventory)?,
        );
        Ok(())
    }
    pub(super) fn discovery_fingerprint(&self, hash: &mut Sha256) -> Result<()> {
        let work = &self
            .acquisition
            .as_ref()
            .ok_or(AdmissionFailure::Unknown)?
            .discovery;
        hash.update(data::SCOPE.as_bytes());
        hash.update([0, work.searched, work.present]);
        for (role, path) in work.paths.iter().enumerate() {
            hash.update([role as u8]);
            if let Some(path) = path {
                hash.update(path.as_os_str().as_encoded_bytes());
            }
            hash.update([0]);
            if let Some(absent) = &work.absent[role] {
                hash.update(absent.name.as_bytes());
                hash.update([0]);
                let mut at = Some(absent.parent);
                while let Some(index) = at {
                    let original = self.originals.get(index).ok_or(AdmissionFailure::Unknown)?;
                    hash_identity(hash, self.identity(index)?);
                    hash.update(original.name.text().as_bytes());
                    hash.update([0]);
                    at = original.parent;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn acquisition_discovery(&self) -> Option<Discovery> {
        self.acquisition_finding()?; // SAME positively closed, successful read.
        self.acquisition.as_ref()?.discovery.finding
    }
    /// Location only, after this source's positive close. The outer owner must
    /// still join and check project requirements before offering a native picker.
    pub(crate) fn acquisition_discovered_directory(&self, role: usize) -> Option<&Path> {
        let finding = self.acquisition_discovery()?;
        if role >= 3 || finding.candidate_roles() & (1 << role) == 0 {
            return None;
        }
        let work = &self.acquisition.as_ref()?.discovery;
        let location = if role == 2 && work.paths[sdkman::SLOT].is_some() { sdkman::SLOT } else { role };
        work.paths[location].as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_lookup_paths_require_native_account_home_and_keep_unentered_account_settled() {
        assert_eq!(fixed_path(0, None).unwrap(), Path::new(data::JDK));
        assert_eq!(fixed_path(2, None).unwrap(), Path::new(data::GRADLE));
        assert_eq!(
            fixed_path(1, Some("/Users/inert-fixture")).unwrap(),
            Path::new("/Users/inert-fixture/Library/Android/sdk")
        );
        for home in [
            None,
            Some("/"),
            Some("relative"),
            Some("/Users/../other"),
            Some("/Users/bad\nname"),
        ] {
            assert!(fixed_path(1, home).is_err());
        }
        assert!(fixed_path(4, Some("/Users/inert-fixture")).is_err());
        let work = DiscoveryWork::new(); // No native call, FD or fake positive source.
        assert!(work.call_settled());
        assert_eq!(work.heap_bytes(), Some(0));
        assert!(work.finding.is_none());
        assert_eq!(work.searched, 0);
    }
}
