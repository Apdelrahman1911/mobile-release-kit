//! Fixed synthetic C inputs under the existing ordinary UI/account owner.
//! No caller-supplied path/data, recursion, executable, release or credential.
use super::*;
use crate::{CredentialError, CredentialOrigin, CredentialSnapshot, DirectoryFenceClass,
    DirectoryFenceObservation, DirectoryFenceProbe, ProjectBook, RegisteredProject};

pub(crate) const INPUT_NAMES: [&str; 5] = ["input.jks", "replacement.keystore", "google-services.json", "GoogleService-Info.plist", "foreign-readable.jks"];
const JKS: &[u8] = b"\xfe\xed\xfe\xed\0\0\0\2\0\0\0\0";
const REPLACEMENT: &[u8] = b"\xfe\xed\xfe\xed\0\0\0\1\0\0\0\0";
const ANDROID: &[u8] = b"{\"project_info\":{\"project_id\":\"mrk-synthetic\"},\"client\":[{\"client_info\":{\"android_client_info\":{\"package_name\":\"org.example.mrk.observed\"}}}]}\n";
const IOS: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>BUNDLE_ID</key><string>org.example.mrk.observed</string></dict></plist>\n";
pub(crate) fn input_bytes(index: usize, changed: bool) -> Result<&'static [u8]> { match index {
    0 => Ok(JKS), 1 => Ok(if changed { JKS } else { REPLACEMENT }), 2 => Ok(ANDROID), 3 => Ok(IOS), 4 => Ok(JKS), _ => Err(Error::Unsafe),
} }

#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
static CLAIMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
static VERIFIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(super) fn verified() -> bool {
    #[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
    { VERIFIED.load(std::sync::atomic::Ordering::SeqCst) }
    #[cfg(not(all(feature = "qualification-result", feature = "windows-installed-observation")))]
    { false } // No observer fixture exists in the ordinary writer profile.
}

#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
pub struct UiCredentialFixture {
    end: Instant, project: PathBuf, directory: PathBuf, project_id: FileIdentity, directory_id: FileIdentity,
    files: Vec<Stamp>, books: Vec<ProjectBook>, origins: Vec<CredentialOrigin>,
    native_checked: bool, mutated: bool, stale_checked: bool, verified: bool,
    directory_fence: DirectoryFenceProbe, directory_fence_attempted: bool, directory_fence_panicked: bool,
}
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
impl UiCredentialFixture {
    pub fn create(end: Instant) -> Result<Self> {
        need(require_normal_ui_qualification()? == UiRole::CredentialSession)?; deadline(Some(end))?;
        need(!CLAIMED.swap(true, std::sync::atomic::Ordering::SeqCst))?;
        let project = normal_ui_project()?;
        // The existing parent-owned output directory is already outside the
        // project and admits fixed child CREATE_NEW files. Reuse it instead of
        // adding a fifth directory to the original four-directory owner.
        let directory = project.parent().ok_or(Error::Unsafe)?.to_path_buf();
        let mut books = Vec::with_capacity(16);
        let mut identities = Vec::with_capacity(2);
        for path in [&project, &directory] {
            let mut original = ProjectBook::new();
            let result = original.probe_once(path.to_str().ok_or(Error::Unsafe)?, &mut || Instant::now() >= end);
            if !original.settled() && !original.never_started() {
                diagnostic_data("ui-credential-fixture-probe", None, true, None);
                loop { std::thread::park(); std::hint::black_box((&mut original, &books)); }
            }
            let identity = result?; need(original.settled())?; identities.push(identity); books.push(original);
        }
        need(identities[0] != identities[1])?;
        let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
        let parent = unhex(&std::env::var("MRK_WINDOWS_PARENT_SID").map_err(|_| Error::State)?)?;
        need(account.len() == 28 && parent.len() == 28 && account != parent)?;
        let mut files = Vec::with_capacity(INPUT_NAMES.len());
        for (index, name) in INPUT_NAMES.iter().enumerate() {
            files.push(create_private_file(&directory.join(name), input_bytes(index, false)?, &account, &parent, index == 4, end)?);
        }
        // DATA construction only. The retained ordinary relay runs this same
        // probe later, outside process main and before selecting a project.
        let directory_fence = DirectoryFenceProbe::new(directory.to_str().ok_or(Error::Unsafe)?, identities[1])?;
        let mut fixture = Self { end, project, directory, project_id: identities[0], directory_id: identities[1],
            files, books, origins: Vec::with_capacity(4), native_checked: false, mutated: false, stale_checked: false, verified: false,
            directory_fence, directory_fence_attempted: false, directory_fence_panicked: false };
        fixture.native_checks()?; Ok(fixture)
    }
    /// One fixed A0 observation, not a credential/storage capability. The
    /// owner supplies its existing run STOP and absolute cleanup cutoff.
    pub fn directory_fence_once(&mut self, stop: &mut dyn FnMut() -> bool,
        cleanup_expired: &mut dyn FnMut() -> bool) -> Result<DirectoryFenceObservation> {
        need(require_normal_ui_qualification()? == UiRole::CredentialSession && self.native_checked
            && !self.mutated && !self.verified && !self.directory_fence_attempted
            && self.directory_fence.never_started()
            && self.books.iter().all(|book| book.settled() || book.never_started()))?;
        self.directory_fence_attempted = true; // Reserve before the only entry.
        let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.directory_fence.run_once(stop)));
        // Even a returning unwind owes one cleanup attempt on THIS retained
        // probe. Unknown active storage is handled by its existing settle gate.
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.directory_fence.settle_once(cleanup_expired)));
        self.directory_fence_panicked |= returned.is_err() || cleanup.is_err();
        let observed = self.directory_fence.observation();
        if self.directory_fence_panicked || !self.directory_fence.settled()
            || !matches!(observed.classification, Some(DirectoryFenceClass::Supported | DirectoryFenceClass::Unavailable
                | DirectoryFenceClass::RefusedBeforeFence | DirectoryFenceClass::Stopped)) {
            // No diagnostic/native follow-up, owner drop, replay or successful
            // relay join. Keep the exact original probe, fixture and buffers.
            loop { std::thread::park(); std::hint::black_box(&mut *self); }
        }
        Ok(observed) // A known settled negative is useful A0 DATA, not support.
    }
    pub fn path(&self, index: usize) -> Result<PathBuf> {
        need(index < 4 && self.native_checked && !self.verified)?;
        Ok(self.directory.join(INPUT_NAMES[index]))
    }
    fn capture(&mut self, path: &Path, limit: usize, stop_now: bool) -> std::result::Result<CredentialSnapshot, CredentialError> {
        self.capture_registered(path, limit, stop_now, false)
    }
    fn capture_registered(&mut self, path: &Path, limit: usize, stop_now: bool, input_directory_is_project: bool)
        -> std::result::Result<CredentialSnapshot, CredentialError> {
        deadline(Some(self.end))?;
        if self.books.len() >= 16 { return Err(Error::Bounds.into()); }
        self.books.push(ProjectBook::new()); let original = self.books.last_mut().ok_or(Error::State)?;
        let (project, identity) = if input_directory_is_project { (&self.directory, self.directory_id) } else { (&self.project, self.project_id) };
        let result = original.capture_credential_once(path.to_str().ok_or(Error::Unsafe)?,
            &[RegisteredProject { path: project.to_str().ok_or(Error::Unsafe)?, identity }], limit,
            &mut || stop_now || Instant::now() >= self.end);
        if matches!(result, Err(CredentialError::Native(Error::Unknown | Error::State)))
            || !original.settled() && !original.never_started() {
            diagnostic_data("ui-credential-fixture-capture", None, true, None);
            loop { std::thread::park(); std::hint::black_box(&mut *self); }
        }
        deadline(Some(self.end))?; result
    }
    fn native_checks(&mut self) -> Result<()> {
        need(!self.native_checked && !self.mutated && self.origins.is_empty())?;
        for index in 0..4 {
            let path = self.directory.join(INPUT_NAMES[index]);
            let result = self.capture(&path, LIMIT, false).map_err(|_| Error::Unsafe)?;
            need(result.bytes == input_bytes(index, false)?)?;
            self.origins.push(result.origin);
        }
        let private = self.directory.join(INPUT_NAMES[0]);
        need(matches!(self.capture(&self.directory.join(INPUT_NAMES[4]), LIMIT, false), Err(CredentialError::Native(Error::Unsafe))))?;
        need(matches!(self.capture(&private, JKS.len() - 1, false), Err(CredentialError::MaterialLimit)))?;
        need(matches!(self.capture(&private, LIMIT, true), Err(CredentialError::Native(Error::Unavailable))))?;
        need(matches!(self.capture(&PathBuf::from(format!("{}:unselected", private.to_str().ok_or(Error::Unsafe)?)), LIMIT, false),
            Err(CredentialError::Native(Error::Unsafe))))?;
        // Use a genuine private ordinary-child source, and the full identity
        // already probed for its actual containing directory. A parent-created
        // project leaf would fail private ownership before reaching exclusion.
        need(matches!(self.capture_registered(&private, LIMIT, false, true), Err(CredentialError::ProjectOverlap)))?;
        // Actual ordinary-account write and delete handles; no bytes/deletion
        // are performed. The existing source's no-write/no-delete sharing must
        // refuse both, while every original is retained to consuming close.
        for access in [FS::FILE_GENERIC_WRITE, FS::DELETE] {
            let mut conflicting = OriginalFile::new_until(&private, false, self.end)?;
            let result = (|| -> Result<()> {
                conflicting.open(access | FS::FILE_READ_ATTRIBUTES, false, null())?; conflicting.named(&private)?;
                need(conflicting.stamp()? == self.files[0])?;
                need(matches!(self.capture(&private, LIMIT, false), Err(CredentialError::Native(Error::Unavailable))))
            })();
            if matches!(result, Err(Error::Unknown)) {
                diagnostic_data("ui-credential-fixture-sharing", None, true, None);
                loop { std::thread::park(); std::hint::black_box((&mut conflicting, &mut *self)); }
            }
            if conflicting.close().is_err() {
                diagnostic_data("ui-credential-fixture-sharing-close", None, true, None);
                loop { std::thread::park(); std::hint::black_box((&mut conflicting, &mut *self)); }
            }
            result?;
        }
        need(self.books.iter().all(|book| book.settled() || book.never_started()))?;
        self.native_checked = true; deadline(Some(self.end))
    }
    pub fn mutate_original_once(&mut self) -> Result<()> {
        need(require_normal_ui_qualification()? == UiRole::CredentialSession && self.native_checked && !self.mutated && !self.verified)?;
        self.mutated = true; // Never retry a possibly performed fixed mutation.
        let path = self.directory.join(INPUT_NAMES[1]);
        let mut original = OriginalFile::new_until(&path, false, self.end)?; let mut position = 0;
        let result = (|| -> Result<()> {
            original.open(FS::FILE_GENERIC_READ | FS::FILE_GENERIC_WRITE, false, null())?; original.named(&path)?;
            need(original.stamp()? == self.files[1] && original.read(LIMIT)? == REPLACEMENT)?;
            ui_fixture_seek(&mut original, &mut position)?; original.write(JKS, LIMIT)?;
            ui_fixture_seek(&mut original, &mut position)?; need(original.read(LIMIT)? == JKS)?;
            let after = original.stamp()?;
            need(same_object(&self.files[1], &after) && after.size == JKS.len() as i64)
        })();
        if matches!(result, Err(Error::Unknown)) {
            diagnostic_data("ui-credential-fixture-mutation", None, true, None);
            loop { std::thread::park(); std::hint::black_box((&mut original, &mut position, &mut *self)); }
        }
        if original.close().is_err() {
            diagnostic_data("ui-credential-fixture-mutation-close", None, true, None);
            loop { std::thread::park(); std::hint::black_box((&mut original, &mut position, &mut *self)); }
        }
        result?;
        let after = read_file(&path, JKS, self.end)?;
        need(same_object(&self.files[1], &after) && after != self.files[1])?;
        self.files[1] = after;
        need(self.books.len() < 16)?; self.books.push(ProjectBook::new());
        let original = self.books.last_mut().ok_or(Error::State)?;
        let result = original.probe_excluding_credentials_once(self.project.to_str().ok_or(Error::Unsafe)?,
            &[self.origins.get(1).ok_or(Error::State)?], &mut || Instant::now() >= self.end);
        if !original.settled() || matches!(result, Err(CredentialError::Native(Error::Unknown | Error::State))) {
            diagnostic_data("ui-credential-fixture-stale", None, true, None);
            loop { std::thread::park(); std::hint::black_box(&mut *self); }
        }
        need(matches!(result, Err(CredentialError::ExclusionUnconfirmed)))?;
        self.stale_checked = true; deadline(Some(self.end))
    }
    pub fn verify_once(&mut self) -> Result<()> {
        need(self.native_checked && self.mutated && self.stale_checked && !self.verified)?;
        let fence = self.directory_fence.observation();
        need(self.directory_fence_attempted && !self.directory_fence_panicked && self.directory_fence.settled()
            && matches!(fence.classification, Some(DirectoryFenceClass::Supported | DirectoryFenceClass::Unavailable
                | DirectoryFenceClass::RefusedBeforeFence)) && !fence.stop_observed && !fence.cleanup.expired)?;
        self.verified = true;
        for (index, name) in INPUT_NAMES.iter().enumerate() {
            need(read_file(&self.directory.join(name), input_bytes(index, true)?, self.end)? == self.files[index])?;
        }
        for (path, expected) in [(&self.project, self.project_id), (&self.directory, self.directory_id)] {
            let mut original = ProjectBook::new();
            let result = original.probe_once(path.to_str().ok_or(Error::Unsafe)?, &mut || Instant::now() >= self.end);
            if !original.settled() {
                diagnostic_data("ui-credential-fixture-final", None, true, None);
                loop { std::thread::park(); std::hint::black_box((&mut original, &*self)); }
            }
            need(result? == expected)?;
        }
        need(self.books.iter().all(|book| book.settled() || book.never_started()))?; deadline(Some(self.end))?;
        VERIFIED.store(true, std::sync::atomic::Ordering::SeqCst); Ok(())
    }
}

#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
fn same_object(before: &Stamp, after: &Stamp) -> bool {
    before.volume == after.volume && before.id == after.id && before.creation == after.creation
        && before.size == after.size && before.attributes == after.attributes && before.links == 1 && after.links == 1
        && after.write >= before.write && after.change >= before.change
}
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
fn create_private_file(path: &Path, bytes: &[u8], account: &[u8], parent: &[u8], foreign: bool, end: Instant) -> Result<Stamp> {
    let (mut acl, mut descriptor) = child_security_until(parent, account, Some(end))?;
    // Reuse this new private descriptor storage, BEFORE its first native
    // borrower. The parent is not granted private content or control rights.
    // The deliberate fifth negative fixture differs by just parent read-data.
    let parent_ace = 8 + (8 + system_sid().len()) + (8 + builtin(544).len());
    let account_ace = parent_ace + 8 + parent.len();
    need(&acl.0[parent_ace + 8..parent_ace + 8 + parent.len()] == parent
        && &acl.0[account_ace + 8..account_ace + 8 + account.len()] == account)?;
    let parent_rights = if foreign { FS::FILE_GENERIC_READ } else { FS::READ_CONTROL | FS::SYNCHRONIZE | FS::FILE_READ_ATTRIBUTES };
    acl.0[parent_ace + 4..parent_ace + 8].copy_from_slice(&parent_rights.to_le_bytes());
    acl.0[account_ace + 4..account_ace + 8].copy_from_slice(&FS::FILE_ALL_ACCESS.to_le_bytes());
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    let mut original = OriginalFile::new_until(path, false, end)?;
    let result = (|| -> Result<Stamp> {
        original.open(FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES, true, &attributes)?;
        original.named(path)?; let before = original.stamp()?;
        need(before.size == 0 && before.links == 1)?; original.write(bytes, LIMIT)?;
        let created = original.stamp()?;
        need(created.volume == before.volume && created.id == before.id && created.creation == before.creation
            && created.size == bytes.len() as i64 && created.links == 1)?; Ok(created)
    })();
    if matches!(result, Err(Error::Unknown)) {
        diagnostic_data("ui-credential-fixture-create", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &acl, &descriptor, &attributes)); }
    }
    if original.close().is_err() {
        diagnostic_data("ui-credential-fixture-create-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &acl, &descriptor, &attributes)); }
    }
    let before = result?; let after = read_file(path, bytes, end)?;
    need(same_object(&before, &after))?; Ok(after)
}
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
fn read_file(path: &Path, bytes: &[u8], end: Instant) -> Result<Stamp> {
    let mut original = OriginalFile::new_until(path, false, end)?;
    let result = (|| -> Result<Stamp> {
        original.open(FS::FILE_GENERIC_READ, false, null())?; original.named(path)?;
        let before = original.stamp()?;
        need(before.links == 1 && before.size == bytes.len() as i64 && original.read(LIMIT)? == bytes
            && original.stamp()? == before)?; Ok(before)
    })();
    if matches!(result, Err(Error::Unknown)) {
        diagnostic_data("ui-credential-fixture-read", None, true, None);
        loop { std::thread::park(); std::hint::black_box(&mut original); }
    }
    if original.close().is_err() {
        diagnostic_data("ui-credential-fixture-read-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box(&mut original); }
    }
    deadline(Some(end))?; result
}
