//! SG1 fixture-only direct GTK qualification. SOURCE ONLY; execution pins absent.
//! Only this integration target's actual main can mint the consumed admission.
use super::*;
use std::{fs::{self, File, OpenOptions}, future::Future, io::{Read, Write, Stdout}, os::fd::{AsFd, OwnedFd},
    os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Component, Path, PathBuf},
    sync::{OnceLock, atomic::AtomicU8}, thread::ThreadId, time::{Duration, Instant}};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use crate::{asset_session::FixtureSelection, supervisor::session_gtk_probe as passive_probe};
type Check<T> = Result<T, &'static str>;
const WITNESS: &[u8;18] = b"MRK_SHELL_EXIT_V1\n";
const DISARMED:u8=0; const SEALING:u8=1; const ARMED:u8=2; const SPENT:u8=3; const REFUSED:u8=4;
// Covers the fixed source roster, both bounded128-member closure inventories,
// ancestry checks and native/receipt originals without limit reuse.
const FILE_LIMIT:u32=512;
const NOT_VERIFIED:&[&str]=&["production-enablement","native-other-cases","credential-validity-or-unlock",
    "assessment-prepare-keep-save-assign","edit-authorization","packaged-runtime-custody","physical-ux",
    "reload-rebind-unknown-recovery","producer-stdout-close","mobile-builds-stores-installers"];
fn check(b:bool,c:&'static str)->Check<()> {if b {Ok(())} else {Err(c)}}
fn hash(bytes:&[u8])->String {format!("{:x}",Sha256::digest(bytes))}
fn digest(s:&str,n:usize)->bool {s.len()==n && s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))}
fn env(n:&str)->Check<String> {std::env::var(n).map_err(|_|"sg1_input_missing")}
#[path="session_gtk_qualification/native_contract.rs"] mod native_contract;
use native_contract::NativeAdmission;
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { device: u64, inode: u64, mode: u32, owner: u32 }
impl Identity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self { device:metadata.dev(), inode:metadata.ino(), mode:metadata.mode(), owner:metadata.uid() }
    }
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileCounts { opened: u32, close_attempted: u32, close_settled: u32, unknown: bool }
struct Files { counts: FileCounts, active: Option<File> }
struct FileBook(Mutex<Files>);
impl FileBook {
    fn new() -> Self { Self(Mutex::new(Files { counts:FileCounts { opened:0, close_attempted:0, close_settled:0, unknown:false }, active:None })) }
    fn locked(&self) -> Check<std::sync::MutexGuard<'_, Files>> {
        self.0.lock().map_err(|error| { error.into_inner().counts.unknown = true; "fixture_file_book_poisoned" })
    }
    fn ready(files: &mut Files) -> Check<()> {
        if files.active.is_some() || files.counts.opened != files.counts.close_attempted
            || files.counts.opened != files.counts.close_settled { files.counts.unknown = true; }
        check(!files.counts.unknown && files.counts.opened < FILE_LIMIT, "fixture_file_custody_unknown")
    }
    fn register(files: &mut Files, original: File) {
        // The original is in the retained book BEFORE any metadata/read/write.
        files.active = Some(original);
        files.counts.opened += 1; // ready() established the fixed nonwrapping bound.
    }
    fn close(files: &mut Files) -> Check<()> {
        let Some(original) = files.active.take() else {
            files.counts.unknown = true;
            return Err("fixture_original_missing");
        };
        files.counts.close_attempted += 1;
        let descriptor: OwnedFd = original.into();
        match nix::unistd::close(descriptor) {
            Ok(()) => { files.counts.close_settled += 1; Ok(()) },
            Err(_) => { files.counts.unknown = true; Err("fixture_original_close_unknown") },
        } // No retry, raw-number probe, reopen, or Drop-based positive receipt.
    }
    fn counts(&self) -> Check<FileCounts> {
        let mut files = self.locked()?;
        Self::ready(&mut files)?;
        Ok(files.counts)
    }
    fn read(&self, path: &Path, limit: u64) -> Check<Vec<u8>> {
        let mut files = self.locked()?;
        Self::ready(&mut files)?;
        let named = fs::symlink_metadata(path).map_err(|_| "fixture_read_metadata")?;
        check(named.is_file() && named.nlink() == 1 && named.len() <= limit, "fixture_read_shape")?;
        let original = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path).map_err(|_| "fixture_read_open")?;
        Self::register(&mut files, original);
        let mut bytes = Vec::new();
        let (read, opened, finished) = {
            let file = files.active.as_mut().ok_or("fixture_original_missing")?;
            let opened = file.metadata();
            let read = if opened.as_ref().is_ok_and(|entry| entry.is_file() && entry.nlink() == 1
                && entry.len() == named.len() && Identity::of(entry) == Identity::of(&named)) {
                (&mut *file).take(limit + 1).read_to_end(&mut bytes)
            } else { Err(std::io::Error::other("fixture opened identity changed")) };
            (read, opened, file.metadata())
        };
        Self::close(&mut files)?;
        let opened = opened.map_err(|_| "fixture_read_metadata")?;
        let finished = finished.map_err(|_| "fixture_read_metadata")?;
        let after = fs::symlink_metadata(path).map_err(|_| "fixture_read_metadata")?;
        check(read.is_ok() && bytes.len() as u64 == named.len() && opened.len() == named.len()
            && finished.len() == named.len() && after.len() == named.len()
            && [&opened, &finished, &after].iter().all(|entry| Identity::of(entry) == Identity::of(&named) && entry.nlink() == 1), "fixture_read_changed")?;
        Ok(bytes)
    }
    fn write_new(&self, path: &Path, bytes: &[u8]) -> Check<Identity> {
        check(bytes.len() <= 64 * 1024, "shell_receipt_bound")?;
        let mut files = self.locked()?;
        Self::ready(&mut files)?;
        let original = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|_| "fixture_receipt_open")?;
        Self::register(&mut files, original);
        let (wrote, metadata) = {
            let file = files.active.as_mut().ok_or("fixture_original_missing")?;
            (file.write_all(bytes), file.metadata())
        };
        Self::close(&mut files)?;
        let metadata = metadata.map_err(|_| "fixture_receipt_metadata")?;
        let named = fs::symlink_metadata(path).map_err(|_| "fixture_receipt_metadata")?;
        check(wrote.is_ok() && metadata.is_file() && metadata.mode() & 0o7777 == 0o600 && metadata.nlink() == 1
            && metadata.len() == bytes.len() as u64 && Identity::of(&metadata) == Identity::of(&named)
            && named.nlink() == 1 && named.len() == metadata.len(), "fixture_receipt_write")?;
        Ok(Identity::of(&metadata))
    }
    fn empty_directory(&self, path: &Path) -> Check<()> {
        // RawDir borrows our retained original File and buffer; it owns no
        // hidden DIR/duplicate/Drop-close. No new dependency or unsafe source.
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        {
            let mut files = self.locked()?;
            Self::ready(&mut files)?;
            let named = fs::symlink_metadata(path).map_err(|_| "fixture_directory_metadata")?;
            check(named.is_dir(), "fixture_directory_shape")?;
            let original = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY | nix::libc::O_NONBLOCK)
                .open(path).map_err(|_| "fixture_directory_open")?;
            Self::register(&mut files, original);
            let valid = {
                let original = files.active.as_ref().ok_or("fixture_original_missing")?;
                let same = original.metadata().is_ok_and(|entry| Identity::of(&entry) == Identity::of(&named));
                let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 8192];
                let mut entries = rustix::fs::RawDir::new(original.as_fd(), &mut buffer);
                let (mut dot, mut dotdot) = (false, false);
                let mut valid = same;
                while valid {
                    let Some(entry) = entries.next() else { break; };
                    match entry {
                        Ok(entry) if entry.file_type() == rustix::fs::FileType::Directory && entry.file_name().to_bytes() == b"."
                            && entry.ino() == named.ino() && !dot => { dot = true; },
                        Ok(entry) if entry.file_type() == rustix::fs::FileType::Directory && entry.file_name().to_bytes() == b".."
                            && entry.ino() != 0 && !dotdot => { dotdot = true; },
                        _ => { valid = false; break; },
                    }
                }
                valid && dot && dotdot
            };
            Self::close(&mut files)?;
            check(valid && fs::symlink_metadata(path).is_ok_and(|entry| Identity::of(&entry) == Identity::of(&named)), "synthetic_directory_not_empty")
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        { let _ = path; Err("positive_directory_iterator_close_not_admitted") }
    }
}

struct Source { path: &'static str, bytes: &'static [u8] }
macro_rules! source { ($path:literal) => { Source { path:$path, bytes:include_bytes!(concat!("../../../", $path)) } }; }
const SOURCES: &[Source] = &[
    // Fixed first-party superset: real frontend/assets/build inputs, native
    // modules (including cfg(test) transitive files), and core import/data tree.
    source!(".github/workflows/desktop-environment-diagnostics-native.yml"),
    source!(".github/workflows/desktop-github-connection-tls.yml"),
    source!(".github/workflows/desktop-github-workflow-apply-native.yml"),
    source!("desktop/config_edit_bootstrap.py"),
    source!("desktop/engine_bootstrap.py"),
    source!("desktop/environment_bootstrap.py"),
    source!("desktop/github_connection_bootstrap.py"),
    source!("desktop/index.html"),
    source!("desktop/native/linux-mount-observation/Cargo.toml"),
    source!("desktop/native/linux-mount-observation/src/lib.rs"),
    source!("desktop/native/session_gtk_input_linux.c"),
    source!("desktop/package-lock.json"),
    source!("desktop/package.json"),
    source!("desktop/rust-toolchain.toml"),
    source!("desktop/src-tauri/Cargo.lock"),
    source!("desktop/src-tauri/Cargo.toml"),
    source!("desktop/src-tauri/build.rs"),
    source!("desktop/src-tauri/capabilities/main.json"),
    source!("desktop/src-tauri/icons/icon.ico"),
    source!("desktop/src-tauri/icons/icon.png"),
    source!("desktop/src-tauri/icons/icon.svg"),
    source!("desktop/src-tauri/src/asset_commands.rs"),
    source!("desktop/src-tauri/src/asset_session.rs"),
    source!("desktop/src-tauri/src/asset_source.rs"),
    source!("desktop/src-tauri/src/bridge.rs"),
    source!("desktop/src-tauri/src/credential_assessment.rs"),
    source!("desktop/src-tauri/src/credential_format.rs"),
    source!("desktop/src-tauri/src/document_lifetime.rs"),
    source!("desktop/src-tauri/src/edit_commands.rs"),
    source!("desktop/src-tauri/src/edit_hosted_tests.rs"),
    source!("desktop/src-tauri/src/edit_owner.rs"),
    source!("desktop/src-tauri/src/edit_protocol.rs"),
    source!("desktop/src-tauri/src/environment.rs"),
    source!("desktop/src-tauri/src/environment_diagnostics_hosted_tests.rs"),
    source!("desktop/src-tauri/src/environment_diagnostics_owner.rs"),
    source!("desktop/src-tauri/src/environment_diagnostics_protocol.rs"),
    source!("desktop/src-tauri/src/error.rs"),
    source!("desktop/src-tauri/src/github_commands.rs"),
    source!("desktop/src-tauri/src/github_connection_protocol.rs"),
    source!("desktop/src-tauri/src/github_connection_session.rs"),
    source!("desktop/src-tauri/src/github_workflow_edit_protocol.rs"),
    source!("desktop/src-tauri/src/hosted_tests.rs"),
    source!("desktop/src-tauri/src/installed_runtime.rs"),
    source!("desktop/src-tauri/src/lib.rs"),
    source!("desktop/src-tauri/src/main.rs"),
    source!("desktop/src-tauri/src/metadata_text_commands.rs"),
    source!("desktop/src-tauri/src/metadata_text_edit_protocol.rs"),
    source!("desktop/src-tauri/src/passive_management_tests.rs"),
    source!("desktop/src-tauri/src/protocol.rs"),
    source!("desktop/src-tauri/src/release_version_protocol.rs"),
    source!("desktop/src-tauri/src/runtime.rs"),
    source!("desktop/src-tauri/src/session_gtk_qualification.rs"),
    source!("desktop/src-tauri/src/session_gtk_qualification/native_contract.rs"),
    source!("desktop/src-tauri/src/shell.rs"),
    source!("desktop/src-tauri/src/supervisor.rs"),
    source!("desktop/src-tauri/tauri.conf.json"),
    source!("desktop/src-tauri/tests/fixtures/github_core/_desktop_github_engine.py"),
    source!("desktop/src-tauri/tests/fixtures/github_tls/api-expired.pem"),
    source!("desktop/src-tauri/tests/fixtures/github_tls/api-valid.pem"),
    source!("desktop/src-tauri/tests/fixtures/github_tls/other-root-ca.pem"),
    source!("desktop/src-tauri/tests/fixtures/github_tls/root-ca.pem"),
    source!("desktop/src-tauri/tests/fixtures/github_tls/server-key.pem"),
    source!("desktop/src-tauri/tests/fixtures/github_tls/wrong-san.pem"),
    source!("desktop/src-tauri/tests/fixtures/github_tls_namespace.sh"),
    source!("desktop/src-tauri/tests/fixtures/github_tls_peer.py"),
    source!("desktop/src-tauri/tests/fixtures/passive_core/__init__.py"),
    source!("desktop/src-tauri/tests/fixtures/passive_core/_desktop_engine.py"),
    source!("desktop/src-tauri/tests/session_gtk_qualification.rs"),
    source!("desktop/src-tauri/tests/session_gtk_recipe.js"),
    source!("desktop/src/App.tsx"),
    source!("desktop/src/api.ts"),
    source!("desktop/src/assetSessionController.ts"),
    source!("desktop/src/assetSessionHelp.ts"),
    source!("desktop/src/assetSessionProtocol.ts"),
    source!("desktop/src/assetSessionTypes.ts"),
    source!("desktop/src/bridge.ts"),
    source!("desktop/src/catalog.ts"),
    source!("desktop/src/certainty.ts"),
    source!("desktop/src/components/Common.tsx"),
    source!("desktop/src/components/ConfigSave.tsx"),
    source!("desktop/src/components/CredentialSession.tsx"),
    source!("desktop/src/components/DraftEditor.tsx"),
    source!("desktop/src/components/DraftReview.tsx"),
    source!("desktop/src/components/DraftSuggestions.tsx"),
    source!("desktop/src/components/EnvironmentDiagnostics.tsx"),
    source!("desktop/src/components/Fields.tsx"),
    source!("desktop/src/components/GitHubConnection.tsx"),
    source!("desktop/src/components/GitHubWorkflowApply.tsx"),
    source!("desktop/src/components/Icon.tsx"),
    source!("desktop/src/components/MetadataTextEditor.tsx"),
    source!("desktop/src/components/RemovedFields.tsx"),
    source!("desktop/src/configEdit.ts"),
    source!("desktop/src/configEditController.ts"),
    source!("desktop/src/configEditProtocol.ts"),
    source!("desktop/src/credentialGuide.ts"),
    source!("desktop/src/drafts.ts"),
    source!("desktop/src/environment.ts"),
    source!("desktop/src/environmentDiagnosticsController.ts"),
    source!("desktop/src/environmentDiagnosticsProtocol.ts"),
    source!("desktop/src/environmentDiagnosticsTypes.ts"),
    source!("desktop/src/githubConnectionController.ts"),
    source!("desktop/src/githubConnectionProtocol.ts"),
    source!("desktop/src/githubConnectionTypes.ts"),
    source!("desktop/src/githubSetupController.ts"),
    source!("desktop/src/githubSetupProtocol.ts"),
    source!("desktop/src/githubWorkflowEdit.ts"),
    source!("desktop/src/githubWorkflowEditController.ts"),
    source!("desktop/src/githubWorkflowEditProtocol.ts"),
    source!("desktop/src/githubWorkflowEditTypes.ts"),
    source!("desktop/src/main.tsx"),
    source!("desktop/src/metadataText.ts"),
    source!("desktop/src/metadataTextEditController.ts"),
    source!("desktop/src/metadataTextProtocol.ts"),
    source!("desktop/src/pages/Credentials.tsx"),
    source!("desktop/src/pages/Dashboard.tsx"),
    source!("desktop/src/pages/Environment.tsx"),
    source!("desktop/src/pages/Future.tsx"),
    source!("desktop/src/pages/GitHub.tsx"),
    source!("desktop/src/pages/Metadata.tsx"),
    source!("desktop/src/preparation.ts"),
    source!("desktop/src/preview.ts"),
    source!("desktop/src/releaseVersion.ts"),
    source!("desktop/src/styles.css"),
    source!("desktop/src/types.ts"),
    source!("desktop/tools/qualify_session_gtk.py"),
    source!("desktop/tsconfig.json"),
    source!("desktop/vite.config.mjs"),
    source!("pyproject.toml"),
    source!("src/mobile_release/__init__.py"),
    source!("src/mobile_release/__main__.py"),
    source!("src/mobile_release/_command_process.py"),
    source!("src/mobile_release/_desktop_edit_control.py"),
    source!("src/mobile_release/_desktop_edit_engine.py"),
    source!("src/mobile_release/_desktop_edit_protocol.py"),
    source!("src/mobile_release/_desktop_engine.py"),
    source!("src/mobile_release/_desktop_environment_control.py"),
    source!("src/mobile_release/_desktop_environment_engine.py"),
    source!("src/mobile_release/_desktop_environment_protocol.py"),
    source!("src/mobile_release/_desktop_github_engine.py"),
    source!("src/mobile_release/_github_connection_transport.py"),
    source!("src/mobile_release/_lifetime_evidence.py"),
    source!("src/mobile_release/_native_process.py"),
    source!("src/mobile_release/_profile_callers.py"),
    source!("src/mobile_release/_profile_process.py"),
    source!("src/mobile_release/_store_lane_contract.py"),
    source!("src/mobile_release/_store_lane_evidence.py"),
    source!("src/mobile_release/_store_lane_files.py"),
    source!("src/mobile_release/android.py"),
    source!("src/mobile_release/android_upload_validation.py"),
    source!("src/mobile_release/api/__init__.py"),
    source!("src/mobile_release/api/_catalog.py"),
    source!("src/mobile_release/api/_credential_assessment.py"),
    source!("src/mobile_release/api/_credential_guide.py"),
    source!("src/mobile_release/api/_environment.py"),
    source!("src/mobile_release/api/_github_connection.py"),
    source!("src/mobile_release/api/_github_setup.py"),
    source!("src/mobile_release/api/_json.py"),
    source!("src/mobile_release/api/_metadata_text.py"),
    source!("src/mobile_release/api/_preview.py"),
    source!("src/mobile_release/api/_release_version.py"),
    source!("src/mobile_release/api/_snapshot.py"),
    source!("src/mobile_release/api/_snapshot_windows.py"),
    source!("src/mobile_release/api/_snapshot_windows_native.py"),
    source!("src/mobile_release/api/contracts.py"),
    source!("src/mobile_release/api/data/credential-guide-v1.json"),
    source!("src/mobile_release/api/data/field-help.json"),
    source!("src/mobile_release/api/data/github-connection-v1.json"),
    source!("src/mobile_release/api/data/github-setup-v1.json"),
    source!("src/mobile_release/api/data/metadata-text-help-v1.json"),
    source!("src/mobile_release/api/data/project.schema.json"),
    source!("src/mobile_release/build_inputs.py"),
    source!("src/mobile_release/cancellation.py"),
    source!("src/mobile_release/checked_files.py"),
    source!("src/mobile_release/cli.py"),
    source!("src/mobile_release/config.py"),
    source!("src/mobile_release/config_edit.py"),
    source!("src/mobile_release/config_payloads.py"),
    source!("src/mobile_release/credential_policy.py"),
    source!("src/mobile_release/credential_requirements.py"),
    source!("src/mobile_release/credentials.py"),
    source!("src/mobile_release/data/apple-profile-roots.pem"),
    source!("src/mobile_release/discovery.py"),
    source!("src/mobile_release/environment_diagnostics.py"),
    source!("src/mobile_release/environment_diagnostics_tools.py"),
    source!("src/mobile_release/errors.py"),
    source!("src/mobile_release/github_workflow_edit.py"),
    source!("src/mobile_release/init_transaction.py"),
    source!("src/mobile_release/init_workspace_custody.py"),
    source!("src/mobile_release/inspection.py"),
    source!("src/mobile_release/ios.py"),
    source!("src/mobile_release/ios_artifacts.py"),
    source!("src/mobile_release/ios_der.py"),
    source!("src/mobile_release/ios_entitlements.py"),
    source!("src/mobile_release/ios_plist_binary.py"),
    source!("src/mobile_release/ios_profile_auth.py"),
    source!("src/mobile_release/ios_profile_trust.py"),
    source!("src/mobile_release/ios_profiles.py"),
    source!("src/mobile_release/ios_upload_validation.py"),
    source!("src/mobile_release/local_signing.py"),
    source!("src/mobile_release/macho.py"),
    source!("src/mobile_release/metadata.py"),
    source!("src/mobile_release/metadata_text.py"),
    source!("src/mobile_release/metadata_text_edit.py"),
    source!("src/mobile_release/owned_process.py"),
    source!("src/mobile_release/preflight.py"),
    source!("src/mobile_release/provenance.py"),
    source!("src/mobile_release/reporting.py"),
    source!("src/mobile_release/stores.py"),
    source!("src/mobile_release/toolchain_policy.py"),
    source!("src/mobile_release/tooling.py"),
    source!("src/mobile_release/workflow.py"),
    source!("src/mobile_release/workflow_payloads.py"),
    source!("templates/workflows/mobile-candidate.yml"),
    source!("templates/workflows/mobile-external-testing.yml"),
    source!("templates/workflows/mobile-preflight.yml"),
    source!("templates/workflows/mobile-production-submit.yml"),
    source!("tests/native_desktop_config.py"),
    source!("tests/native_desktop_config_eof.py"),
    source!("tests/native_desktop_environment.py"),
    source!("tests/workflow/command_bootstrap_fixture.py"),
];
fn inherited_stdout() -> Check<Stdout> {
    use nix::{fcntl::{fcntl, FcntlArg, FdFlag, OFlag}, sys::stat::{fstat, SFlag}};
    let stdout = std::io::stdout(); // Borrow the launcher's original; no duplicate/owned File/raw fd.
    let metadata = fstat(&stdout).map_err(|_| "shell_stdout_fstat")?;
    let flags = OFlag::from_bits_truncate(fcntl(&stdout, FcntlArg::F_GETFL).map_err(|_| "shell_stdout_flags")?);
    check(SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFIFO)
        && flags.contains(OFlag::O_NONBLOCK) && flags.intersects(OFlag::O_WRONLY | OFlag::O_RDWR), "shell_stdout_not_original_nonblocking_pipe")?;
    let flags = FdFlag::from_bits_truncate(fcntl(&stdout, FcntlArg::F_GETFD).map_err(|_| "shell_stdout_flags")?);
    fcntl(&stdout, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC)).map_err(|_| "shell_stdout_cloexec")?;
    check(FdFlag::from_bits_truncate(fcntl(&stdout, FcntlArg::F_GETFD).map_err(|_| "shell_stdout_flags")?).contains(FdFlag::FD_CLOEXEC), "shell_stdout_cloexec")?;
    // Pipe identity, flags and CLOEXEC are necessary, not writer/descendant proof.
    Ok(stdout)
}

/// Retained ORIGINAL fixture task, registered before start(). A cancelled join
/// leaves its original slot retained and Unknown; no repoll, abort or replacement.
pub(super) struct OriginalTask<T> { handle: AsyncMutex<Option<tauri::async_runtime::JoinHandle<T>>>, join: AtomicU8 }
impl<T: Send + 'static> OriginalTask<T> {
    fn new() -> Arc<Self> { Arc::new(Self { handle:AsyncMutex::new(None), join:AtomicU8::new(0) }) }
    pub(super) fn start(&self, future: impl Future<Output = T> + Send + 'static) -> Check<()> {
        let mut slot = self.handle.try_lock().map_err(|_| "shell_original_task_slot_busy")?;
        check(slot.is_none() && self.join.load(Ordering::SeqCst) == 0, "shell_original_task_reused")?;
        let gate = Arc::new(Notify::new());
        let start = gate.clone();
        *slot = Some(tauri::async_runtime::spawn(async move { start.notified().await; future.await }));
        gate.notify_one(); // Original handle was retained before this first poll.
        Ok(())
    }
    async fn join(&self, context: &Qualification, bound: Option<Duration>) -> Check<T> {
        check(self.join.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_ok(), "shell_original_join_reused")?;
        let mut guard = JoinGuard { context, state:&self.join, settled:false };
        let mut slot = self.handle.lock().await;
        let original = slot.as_mut().ok_or("shell_original_task_missing")?;
        let returned = match bound {
            Some(bound) => tokio::time::timeout(bound, original).await.ok(),
            None => Some(original.await),
        };
        let value = match returned { Some(Ok(value)) => value, _ => return Err("shell_original_join_unknown") };
        slot.take(); // Only this positive original await consumes the stable slot.
        self.join.store(2, Ordering::SeqCst);
        guard.settled = true;
        Ok(value)
    }
    fn joined(&self) -> bool { self.join.load(Ordering::SeqCst) == 2 }
}
struct JoinGuard<'a> { context: &'a Qualification, state: &'a AtomicU8, settled: bool }
impl Drop for JoinGuard<'_> {
    fn drop(&mut self) {
        if !self.settled { self.state.store(3, Ordering::SeqCst); self.context.refuse(); }
    }
}

fn exact_path(name:&str)->Check<PathBuf> {
    let p=PathBuf::from(env(name)?);
    check(p.is_absolute() && p.as_os_str().len()<=256 && !p.components().any(|c|matches!(c,Component::ParentDir|Component::CurDir))
        && p.canonicalize().map_err(|_|"sg1_path_missing")?==p,"sg1_exact_path")?; Ok(p)
}
impl Identity {
    fn value(self)->Value {json!({"device":self.device.to_string(),"inode":self.inode.to_string(),"mode":self.mode,"owner":self.owner})}
}
impl FileBook {
    // Independent admission-only directory originals, not source-capture proof.
    // The synthetic source itself is NEVER opened by this fixture book.
    fn ancestry(&self,path:&Path,file:bool)->Check<Vec<Value>> {
        let mut result=Vec::new(); let mut current=PathBuf::from("/");
        let components:Vec<_>=path.components().filter_map(|c|if let Component::Normal(n)=c {Some(n)} else {None}).collect();
        check(!components.is_empty() && components.len()<=12,"sg1_ancestry_bound")?;
        for index in 0..=components.len() {
            if index>0 {current.push(components[index-1]);}
            let named=fs::symlink_metadata(&current).map_err(|_|"sg1_ancestry_stat")?;
            if file && index==components.len() {
                check(named.is_file() && named.mode()==0o100600 && named.nlink()==1 && named.len()==12 && named.uid()!=0,"sg1_synthetic_shape")?;
            } else {
                check(named.is_dir(),"sg1_ancestry_not_directory")?;
                let mut book=self.locked()?; Self::ready(&mut book)?;
                let fd=OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW|nix::libc::O_DIRECTORY|nix::libc::O_NONBLOCK)
                    .open(&current).map_err(|_|"sg1_ancestry_open")?;
                Self::register(&mut book,fd);
                let valid={let fd=book.active.as_ref().ok_or("sg1_ancestry_original")?;
                    fd.metadata().is_ok_and(|m|Identity::of(&m)==Identity::of(&named))
                        && nix::sys::statfs::fstatfs(fd).is_ok_and(|f|f.filesystem_type()==nix::sys::statfs::EXT4_SUPER_MAGIC)};
                Self::close(&mut book)?; check(valid,"sg1_whole_ancestry_ext_required")?;
            }
            check(fs::symlink_metadata(&current).is_ok_and(|m|Identity::of(&m)==Identity::of(&named)),"sg1_ancestry_changed")?;
            result.push(Identity::of(&named).value());
        } Ok(result)
    }
}
struct Inputs {
    root:PathBuf, root_identity:Identity, project:PathBuf, source:PathBuf,
    project_chain:Vec<Value>, source_chain:Vec<Value>, bindings:Value, files:FileBook,
}
impl Inputs {
    fn admit(native:&NativeAdmission,files:FileBook)->Check<Self> {
        check(std::env::args_os().count()==1 && env("MRK_SESSION_GTK_CASE")?=="SG1"
            && env("MRK_SESSION_GTK_SCOPE")?=="session-gtk-five-dialog-v1","sg1_fixed_inputs")?;
        let manifest=PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        check(std::env::current_dir().map_err(|_|"sg1_cwd")?==manifest,"sg1_cwd")?;
        let repository=manifest.parent().and_then(Path::parent).ok_or("sg1_layout")?;
        let root=exact_path("MRK_SESSION_GTK_ROOT")?;
        check(root==native.run_root() && !root.starts_with(repository) && !repository.starts_with(&root),"sg1_run_root")?;
        check(exact_path("MRK_DESKTOP_DEV_CORE")?==repository.join("src"),"sg1_core_source")?;
        let python=exact_path("MRK_DESKTOP_DEV_PYTHON")?;
        let project=root.join("project"); let source=root.join("outside/synthetic.jks");
        let project_chain=files.ancestry(&project,false)?; let source_chain=files.ancestry(&source,true)?;
        check(project_chain.last()==Some(&native.fixtures()["project"]) && source_chain.last()==Some(&native.fixtures()["source"])
            && !source_chain.iter().any(|id|id==&native.fixtures()["project"]),"sg1_fixture_originals")?;
        files.empty_directory(&project)?; files.empty_directory(&root.join("app"))?;
        let source_sha=env("MRK_SESSION_GTK_SOURCE_SHA")?; let frontend_sha=env("MRK_SESSION_GTK_FRONTEND_SHA256")?;
        check(digest(&source_sha,40) && option_env!("MRK_SESSION_GTK_SOURCE_SHA")==Some(source_sha.as_str())
            && digest(&frontend_sha,64) && option_env!("MRK_SESSION_GTK_FRONTEND_SHA256")==Some(frontend_sha.as_str()),"sg1_compile_binding")?;
        let mut sources=serde_json::Map::new();
        for source in SOURCES {
            let bytes=files.read(&repository.join(source.path),2*1024*1024)?;
            check(bytes==source.bytes,"sg1_source_changed")?; sources.insert(source.path.into(),hash(&bytes).into());
        }
        let exe=std::env::current_exe().map_err(|_|"sg1_executable")?;
        let artifact=hash(&files.read(&exe,256*1024*1024)?);
        check(artifact==native.app_binary()?,"sg1_artifact")?;
        let python_sha=hash(&files.read(&python,64*1024*1024)?);
        check(native.python_binary()?==python_sha,"sg1_python")?;
        let root_identity=Identity::of(&fs::symlink_metadata(&root).map_err(|_|"sg1_root")?);
        let bindings=json!({"sourceSha":source_sha,"frontendSha256":frontend_sha,"artifactSha256":artifact,
            "pythonSha256":python_sha,"sourceHashes":sources,"native":native.binding(),"fixtureOnly":true});
        let value=Self {root,root_identity,project,source,project_chain,source_chain,bindings,files};
        value.files.write_new(&value.root.join("app/incomplete.json"),b"{\"scope\":\"session-gtk-five-dialog-v1\",\"status\":\"incomplete\"}\n")?;
        Ok(value)
    }
    fn unchanged(&self)->Check<()> {
        check(fs::symlink_metadata(&self.root).is_ok_and(|m|Identity::of(&m)==self.root_identity)
            && fs::symlink_metadata(&self.project).is_ok_and(|m|Some(&Identity::of(&m).value())==self.project_chain.last())
            && fs::symlink_metadata(&self.source).is_ok_and(|m|Some(&Identity::of(&m).value())==self.source_chain.last()
                && m.nlink()==1 && m.len()==12),"sg1_fixture_changed")
    }
    fn source(&self,op:u32,facts:&Value)->Check<()> {
        if matches!(op,1|4|5) {
            return check(facts==&json!({"notStarted":true,"originals":[],"reads":0,"eof":null}),"sg1_unexpected_source_work");
        }
        let slots=facts["originals"].as_array().ok_or("sg1_source_slots")?;
        let mut expected=self.project_chain.clone();
        if op==3 {expected.extend(self.source_chain.iter().skip(1).cloned());}
        check(matches!(op,2|3) && facts["notStarted"]==false && slots.len()==expected.len(),"sg1_source_roster")?;
        for (index,(slot,id)) in slots.iter().zip(&expected).enumerate() {
            let parent=if index==0 {Value::Null} else if op==3 && index==self.project_chain.len() {json!(0)} else {json!(index-1)};
            check(slot["slot"]==index && slot["parent"]==parent && &slot["identity"]==id
                && slot["size"]==if op==3 && index+1==slots.len() {json!(12)} else {Value::Null},"sg1_source_identity")?;
        }
        if op==2 {check(facts["reads"]==0 && facts["eof"].is_null(),"sg1_probe_read")?;}
        else {
            let eof=facts["eof"]["ordinal"].as_u64().ok_or("sg1_eof")?;
            let leaf=slots.last().ok_or("sg1_source_leaf")?;
            check((2..=13).contains(&facts["reads"].as_u64().ok_or("sg1_reads")?) && facts["eof"]["bytes"]==12
                && leaf["order"][3].as_u64().is_some_and(|n|n<eof)
                && slots.iter().all(|s|s["order"][4].as_u64().is_some_and(|n|n>eof)),"sg1_original_read_eof_order")?;
        } Ok(())
    }
}

#[derive(Clone,Copy,PartialEq,Eq,Serialize)]
#[serde(rename_all="kebab-case")]
pub(crate) enum EventKind {
    Navigation,LoadStarted,LoadFinished,HookInstalled,DocumentLost,
    CoordinatorRegistered,CoordinatorJoined,ChildRegistered,ChildJoined,
    ConstructDispatch,ConstructEnter,Adopted,Show,ResponseEnter,ResponseDecision,Filename,ResponseLeave,
    TopologyTagged,TopologyChecked,TopologyRetired,
    CloseDispatch,CloseEnter,CloseAck,CloseLeave,DestroyEnter,DestroyLeave,
    ReleaseDispatch,ReleaseEnter,HandlersDetached,Released,ReleaseLeave,
    ProjectPublished,HeaderObserved,CandidatePublished,QuitStop,CloseStimulus,ClosePrevented,
    RelayJoined,Checkpoint,CommandEnter,CommandReturn,RecipeReturned,
}
#[derive(Clone,Copy,Serialize)]
#[serde(rename_all="camelCase")]
struct Event {ordinal:u32,kind:EventKind,operation:u32,detail:u32,main_thread:bool}
#[derive(Clone,Copy,PartialEq,Eq,Serialize)]
#[serde(rename_all="kebab-case")]
pub(super) enum Command {AppInfo,Catalog,EditStatus,AssetStatus,Project,Open,Context,Choose,EnvironmentStatus,Forbidden}
#[derive(Clone,Serialize)]
struct CommandFact {kind:Command,stage:u32,entered:u32,returned:Option<u32>,reply:u32}
#[derive(Clone,PartialEq,Eq)]
pub(super) struct TopologyTags {operation:u32,main_id:String,dialog_id:String}
impl TopologyTags {
    pub(super) fn operation(&self)->u32 {self.operation}
    pub(super) fn main_id(&self)->&str {&self.main_id}
    pub(super) fn dialog_id(&self)->&str {&self.dialog_id}
}
#[derive(Clone,Serialize)]
#[serde(rename_all="camelCase")]
struct OwnershipProof {
    method:&'static str,operation:u32,main_id:String,dialog_id:String,
    tag_ordinal:u32,check_ordinal:u32,checked_ns:String,transient_for_main:bool,
}
struct TopologySlot {
    tags:TopologyTags,tag_ordinal:Option<u32>,requested:bool,proof:Option<OwnershipProof>,
    consumed:bool,retire_ordinal:Option<u32>,
}
struct Record {
    events:Vec<Event>,commands:Vec<CommandFact>,stage:u32,project_id:Option<String>,sources:[Option<Value>;5],
    topology:[Option<TopologySlot>;5],topology_main_retired:bool,
    diagnostics_bootstrap:Option<crate::environment_diagnostics_protocol::Status>,
}
impl Record {
    fn event(&mut self,kind:EventKind,operation:u32,detail:u32,main_thread:bool)->Check<u32> {
        check(self.events.len()<512,"sg1_event_bound")?; let ordinal=self.events.len() as u32+1;
        self.events.push(Event {ordinal,kind,operation,detail,main_thread}); Ok(ordinal)
    }
    fn complete(&self,c:Command,stage:u32,reply:u32)->bool {
        self.commands.iter().filter(|f|f.kind==c && f.stage==stage && f.returned.is_some() && f.reply==reply).count()==1
    }
}
// The capability has no public constructor, serde implementation or Clone.
// It carries no path/IPC authority and is moved exactly once by actual main.
pub(crate) struct FixtureAdmission {context:Option<Arc<Qualification>>}
impl FixtureAdmission {
    pub(crate) fn consume(mut self)->Check<Arc<Qualification>> {self.context.take().ok_or("sg1_permit_spent")}
}
struct Probes {bridge:Arc<DesktopBridge>,passive:passive_probe::Probe}
pub(crate) struct Qualification {
    main:ThreadId,phase:AtomicU8,failed:AtomicBool,wrote:AtomicBool,stdout:Stdout,
    input:Inputs,native:NativeAdmission,document:OnceLock<DocumentBinding>,probes:OnceLock<Probes>,
    record:Mutex<Record>,recipe:Arc<OriginalTask<Check<()>>>,relay_ok:AtomicBool,
}
impl Qualification {
    pub(crate) fn refuse(&self) {self.failed.store(true,Ordering::SeqCst); self.phase.store(REFUSED,Ordering::SeqCst);}
    pub(crate) fn permits(&self,document:&DocumentBinding)->bool {
        // Called with the actual document gate held: no Q mutex here.
        !self.failed.load(Ordering::SeqCst) && self.phase.load(Ordering::SeqCst)<=SEALING
            && self.document.get().is_some_and(|bound|bound.same_original(document))
    }
    pub(crate) fn bind_original(&self,document:DocumentBinding)->Check<()> {
        check(std::thread::current().id()==self.main && self.document.set(document).is_ok(),"sg1_original_binding_once")
    }
    fn record(&self)->Check<std::sync::MutexGuard<'_,Record>> {
        check(!self.failed.load(Ordering::SeqCst) && self.phase.load(Ordering::SeqCst)<=SEALING,"sg1_closed_or_unknown")?;
        self.record.try_lock().map_err(|_|{self.refuse();"sg1_observation_contention"})
    }
    pub(crate) fn event(&self,kind:EventKind,op:u32,detail:u32) {
        let result=self.record().and_then(|mut b|b.event(kind,op,detail,std::thread::current().id()==self.main));
        if result.is_err() {self.refuse();}
    }
    pub(super) fn topology_failed(&self)->bool {self.failed.load(Ordering::SeqCst)}
    pub(super) fn topology_clock(&self)->Check<u64> {
        check(std::thread::current().id()==self.main,"sg1_topology_main_clock")?; native_contract::now_ns()
    }
    pub(super) fn topology_begin(&self,n:u32)->Check<TopologyTags> {
        check(std::thread::current().id()==self.main && (1..=5).contains(&n),"sg1_topology_tag_thread_operation")?;
        let (main_id,dialog_id)=self.native.identity_tags(n)?;
        let tags=TopologyTags {operation:n,main_id,dialog_id}; let mut b=self.record()?;
        check(b.stage==n && !b.topology_main_retired && b.topology[n as usize-1].is_none()
            && b.topology.iter().take(n as usize-1).all(|slot|slot.as_ref().is_some_and(|s|s.consumed && s.retire_ordinal.is_some())),"sg1_topology_tag_once")?;
        b.topology[n as usize-1]=Some(TopologySlot {tags:tags.clone(),tag_ordinal:None,requested:false,proof:None,consumed:false,retire_ordinal:None});
        Ok(tags)
    }
    pub(super) fn topology_tagged(&self,observed:super::owned_gtk::topology::Tagged)->Check<()> {
        let tags=observed.into_tags();let n=tags.operation;
        check(std::thread::current().id()==self.main && (1..=5).contains(&n),"sg1_topology_tag_thread_operation")?;
        let mut b=self.record()?;let slot=b.topology[n as usize-1].as_ref().ok_or("sg1_topology_tag_unreserved")?;
        check(b.stage==n && slot.tags==tags && slot.tag_ordinal.is_none() && !slot.requested && slot.proof.is_none(),"sg1_topology_tag_original")?;
        let ordinal=b.event(EventKind::TopologyTagged,n,1,true)?;
        b.topology[n as usize-1].as_mut().ok_or("sg1_topology_slot")?.tag_ordinal=Some(ordinal);Ok(())
    }
    fn topology_request(&self,n:u32)->Check<()> {
        check(std::thread::current().id()!=self.main && (1..=5).contains(&n),"sg1_topology_request_thread_operation")?;
        let mut b=self.record()?;check(b.stage==n,"sg1_topology_request_stage")?;
        let slot=b.topology[n as usize-1].as_mut().ok_or("sg1_topology_untagged")?;
        check(slot.tag_ordinal.is_some() && !slot.requested && slot.proof.is_none() && !slot.consumed && slot.retire_ordinal.is_none(),"sg1_topology_request_once")?;
        slot.requested=true;Ok(())
    }
    pub(super) fn topology_check_ready(&self,n:u32)->Check<()> {
        check(std::thread::current().id()==self.main && (1..=5).contains(&n),"sg1_topology_check_thread_operation")?;
        let b=self.record()?;let slot=b.topology[n as usize-1].as_ref().ok_or("sg1_topology_check_unreserved")?;
        check(b.stage==n && slot.tag_ordinal.is_some() && slot.requested && slot.proof.is_none()
            && !slot.consumed && slot.retire_ordinal.is_none(),"sg1_topology_check_once")
    }
    pub(super) fn topology_checked(&self,observed:super::owned_gtk::topology::Checked)->Check<()> {
        let (tags,at_ns)=observed.into_parts();let n=tags.operation;self.topology_check_ready(n)?;
        let mut b=self.record()?;let slot=b.topology[n as usize-1].as_ref().ok_or("sg1_topology_slot")?;
        check(slot.tags==tags && slot.proof.is_none(),"sg1_topology_check_tags")?;
        let tagged=slot.tag_ordinal.ok_or("sg1_topology_no_tag_ordinal")?;
        let checked=b.event(EventKind::TopologyChecked,n,1,true)?;
        // Only the source-sealed actual owned_gtk getter/readback witness reaches
        // this constructor. This is not a loose caller true or a native actor relation.
        b.topology[n as usize-1].as_mut().ok_or("sg1_topology_slot")?.proof=Some(OwnershipProof {
            method:"gtk-window-get-transient-for",operation:n,main_id:tags.main_id,dialog_id:tags.dialog_id,
            tag_ordinal:tagged,check_ordinal:checked,checked_ns:at_ns.to_string(),transient_for_main:true,
        });Ok(())
    }
    fn topology_consume(&self,n:u32)->Check<Option<OwnershipProof>> {
        check(std::thread::current().id()!=self.main && (1..=5).contains(&n),"sg1_topology_consume_thread_operation")?;
        let mut b=self.record()?;check(b.stage==n,"sg1_topology_consume_stage")?;
        let slot=b.topology[n as usize-1].as_mut().ok_or("sg1_topology_slot")?;
        check(slot.requested && !slot.consumed && slot.retire_ordinal.is_none(),"sg1_topology_consume_once")?;
        let Some(proof)=slot.proof.clone() else {return Ok(None);};
        slot.consumed=true;Ok(Some(proof))
    }
    pub(super) fn topology_retire_ready(&self,n:u32)->Check<()> {
        check(std::thread::current().id()==self.main && (1..=5).contains(&n),"sg1_topology_retire_thread_operation")?;
        let b=self.record()?;let slot=b.topology[n as usize-1].as_ref().ok_or("sg1_topology_retire_untagged")?;
        check(b.stage==n && !b.topology_main_retired && slot.requested && slot.proof.is_some()
            && slot.consumed && slot.retire_ordinal.is_none(),"sg1_topology_retire_once")
    }
    pub(super) fn topology_retired(&self,observed:super::owned_gtk::topology::Retired)->Check<()> {
        let (n,main_retired)=observed.into_parts();self.topology_retire_ready(n)?;
        check(main_retired==(n==5),"sg1_topology_main_weak_retirement")?;
        let mut b=self.record()?;let ordinal=b.event(EventKind::TopologyRetired,n,1,true)?;
        b.topology[n as usize-1].as_mut().ok_or("sg1_topology_slot")?.retire_ordinal=Some(ordinal);
        if n==5 {b.topology_main_retired=true;}Ok(())
    }
    fn topology_prefix(&self,b:&Record)->Check<Value> {
        check(b.topology_main_retired,"sg1_topology_main_weak_book_not_retired")?;
        let mut facts=Vec::with_capacity(5);
        for (index,slot) in b.topology.iter().enumerate() {
            let slot=slot.as_ref().ok_or("sg1_topology_missing_original")?;
            let proof=slot.proof.as_ref().ok_or("sg1_topology_uncompleted_check")?;
            check(slot.requested && slot.consumed && proof.operation==index as u32+1,"sg1_topology_unconsumed_check")?;
            facts.push(json!({"proof":proof,"retireOrdinal":slot.retire_ordinal.ok_or("sg1_topology_unretired_weak_book")?}));
        }Ok(Value::Array(facts))
    }
    pub(super) fn lifecycle(&self,kind:EventKind,detail:u32) {
        if kind==EventKind::DocumentLost && matches!(self.phase.load(Ordering::SeqCst),ARMED|SPENT) {return;}
        self.event(kind,0,detail);
        if kind==EventKind::DocumentLost || detail==0 {self.refuse();}
    }
    pub(crate) fn original_joined(&self,op:u32,normal:bool,source:Option<Value>) {
        let result:Check<()>=(|| {
            check((1..=5).contains(&op) && normal,"sg1_original_join")?;
            let source=source.ok_or("sg1_original_source_missing")?; self.input.source(op,&source)?;
            let mut b=self.record()?; check(b.sources[op as usize-1].is_none(),"sg1_join_repeated")?;
            b.event(EventKind::CoordinatorJoined,op,1,std::thread::current().id()==self.main)?;
            b.sources[op as usize-1]=Some(source); Ok(())
        })(); if result.is_err() {self.refuse();}
    }
    pub(crate) fn context_input(&self,id:&str)->bool {
        self.record().is_ok_and(|b|b.stage==3 && b.project_id.as_deref()==Some(id))
    }
    pub(super) fn command(self:&Arc<Self>,kind:Command)->Check<CommandGuard> {
        let mut b=self.record()?; let stage=b.stage;
        let expected=match stage {0=>matches!(kind,Command::AppInfo|Command::Catalog|Command::EditStatus|Command::AssetStatus|Command::EnvironmentStatus),
            1|2=>kind==Command::Project,3=>match kind {Command::Open=>true,Command::Context=>b.complete(Command::Open,3,1),
                Command::Choose=>b.complete(Command::Context,3,1),_=>false},_=>false};
        if !expected || kind==Command::Forbidden || b.commands.iter().any(|c|c.kind==kind && c.stage==stage) || b.commands.len()==10 {
            drop(b); self.refuse(); return Err("sg1_command_not_in_recipe");
        }
        let entered=b.event(EventKind::CommandEnter,stage,kind as u32,std::thread::current().id()==self.main)?;
        let index=b.commands.len(); b.commands.push(CommandFact {kind,stage,entered,returned:None,reply:0});
        Ok(CommandGuard {context:self.clone(),index,done:false})
    }
    pub(super) fn attach(&self,bridge:Arc<DesktopBridge>)->Check<()> {
        let passive=passive_probe::Probe::attach(&bridge.supervisor)?;
        self.probes.set(Probes {bridge,passive}).map_err(|_|"sg1_probes_reused")
    }
    pub(super) fn start(self:&Arc<Self>,app:tauri::AppHandle)->Check<()> {
        let q=self.clone(); self.recipe.start(async move {
            let result=q.run_recipe(app).await;
            if result.is_err() {q.refuse();} else {q.event(EventKind::RecipeReturned,0,1);}
            result
        })
    }
    pub(super) fn relay_joined(&self,ok:bool) {
        self.event(EventKind::RelayJoined,0,u32::from(ok));
        if !ok || self.relay_ok.swap(true,Ordering::SeqCst) {self.refuse();}
    }
    pub(super) fn close_prevented(&self)->bool {
        let allowed=self.record().is_ok_and(|b|matches!(b.stage,1|4|5)
            && b.events.iter().filter(|e|e.kind==EventKind::CloseStimulus).count()
                ==b.events.iter().filter(|e|e.kind==EventKind::ClosePrevented).count()+1);
        if !allowed {self.refuse();return false;}
        self.event(EventKind::ClosePrevented,0,1); true
    }
    fn doc(&self)->Check<&DocumentBinding> {self.document.get().ok_or("sg1_no_original_document")}
    fn probes(&self)->Check<&Probes> {self.probes.get().ok_or("sg1_no_original_probes")}
    async fn until(&self,condition:impl Fn()->bool)->Check<()> {
        let end=Instant::now()+Duration::from_secs(8);
        for _ in 0..400 {
            check(!self.failed.load(Ordering::SeqCst) && Instant::now()<end,"sg1_checkpoint_endpoint")?;
            if condition() {return Ok(());} tokio::time::sleep(Duration::from_millis(20)).await;
        } Err("sg1_checkpoint_poll_bound")
    }
    fn mark(&self,stage:u32)->Check<u32> {
        let mut b=self.record()?;
        check(stage==b.stage+1 && b.commands.iter().all(|c|c.returned.is_some()),"sg1_stage_order")?;
        b.stage=stage; b.event(EventKind::Checkpoint,stage,1,std::thread::current().id()==self.main)
    }
    fn eval(&self,app:&tauri::AppHandle,action:&str)->Check<()> {
        let project_id=self.record()?.project_id.clone();
        let request=json!({"action":action,"projectId":project_id});
        let script=format!("({})({});",include_str!("../tests/session_gtk_recipe.js"),request);
        app.get_webview_window(MAIN_WINDOW).ok_or("sg1_no_window")?.eval(&script).map_err(|_|"sg1_eval")
    }
    fn close(&self,app:&tauri::AppHandle)->Check<()> {
        self.event(EventKind::CloseStimulus,0,1);
        app.get_webview_window(MAIN_WINDOW).ok_or("sg1_no_window")?.close().map_err(|_|"sg1_close_stimulus")
    }
    fn has(&self,kind:EventKind,op:u32)->bool {self.record().is_ok_and(|b|b.events.iter().any(|e|e.kind==kind && e.operation==op))}
    async fn native_dialog(self:&Arc<Self>,n:u32,app:&tauri::AppHandle)->Check<()> {
        self.until(||self.has(EventKind::Show,n)).await?;
        let shown={let b=self.record()?;b.events.iter().find(|e|e.kind==EventKind::Show && e.operation==n).ok_or("sg1_show")?.ordinal};
        self.native.presented(&self.input.files,n).await?;
        if n==1 {
            self.close(app)?;
            self.until(||self.record().is_ok_and(|b|b.events.iter().filter(|e|e.kind==EventKind::ClosePrevented).count()==1)).await?;
            check(self.doc()?.fixture_picker_preserved(),"sg1_picker_close_changed_original")?;
        }
        // One data-only main-thread continuation, inside the existing PRESENTED
        // endpoint; it owns no GTK wrapper/task/FD and may not wait for input.
        let end=self.native.topology_endpoint(n)?;self.topology_request(n)?;
        let weak=Arc::downgrade(self);
        app.get_webview_window(MAIN_WINDOW).ok_or("sg1_no_window")?
            .run_on_main_thread(move || super::owned_gtk::topology::inspect(weak,n)).map_err(|_|"sg1_topology_dispatch")?;
        let mut completed=None;
        for attempt in 0..400 {
            self.native.topology_tick(end)?;
            if let Some(proof)=self.topology_consume(n)? {completed=Some(proof);break;}
            check(attempt<399,"sg1_topology_check_missing")?;tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let proof=completed.ok_or("sg1_topology_check_missing")?;
        let ordinal={let mut b=self.record()?;b.event(EventKind::Checkpoint,n,2,std::thread::current().id()==self.main)?};
        self.native.go(&self.input.files,n,shown,ordinal,&proof).await?;
        // Native proof gates ONLY next fixture action/seal. Actual response/STOP
        // and every close/release continuation run independently of these reads.
        self.native.completed(&self.input.files,n).await
    }
    async fn run_recipe(self:&Arc<Self>,app:tauri::AppHandle)->Check<()> {
        self.until(||self.doc().is_ok_and(|d|d.fixture_bootstrap()) && self.record().is_ok_and(|b|
            [Command::AppInfo,Command::Catalog,Command::EditStatus,Command::AssetStatus,Command::EnvironmentStatus].iter().all(|c|b.complete(*c,0,1)))
            && self.probes().is_ok_and(|p|p.bridge.supervisor.can_exit())).await?;
        self.probes()?.passive.bootstrap().await?; self.probes()?.bridge.edits.session_gtk_idle(false)?;
        self.mark(1)?; self.eval(&app,"project")?; self.native_dialog(1,&app).await?;
        self.until(||self.doc().is_ok_and(|d|d.fixture_cancelled()) && self.record().is_ok_and(|b|b.complete(Command::Project,1,2))).await?;
        self.dialog_facts(1)?;
        self.mark(2)?; self.eval(&app,"project")?; self.native_dialog(2,&app).await?;
        self.until(||self.doc().ok().and_then(|d|d.fixture_project()).is_some() && self.record().is_ok_and(|b|b.complete(Command::Project,2,3))).await?;
        let (project,identity)=self.doc()?.fixture_project().ok_or("sg1_project_missing")?;
        check(identity==self.native.fixtures()["project"] && self.record()?.project_id.as_deref()==Some(project.id.as_str()),"sg1_returned_project_identity")?;
        self.dialog_facts(2)?;
        self.mark(3)?; self.eval(&app,"jks")?; self.native_dialog(3,&app).await?;
        self.until(||self.doc().ok().and_then(|d|d.fixture_selection()).is_some() && self.record().is_ok_and(|b|b.complete(Command::Choose,3,1))).await?;
        let selection:FixtureSelection=self.doc()?.fixture_selection().ok_or("sg1_selection_missing")?; self.dialog_facts(3)?;
        self.mark(4)?; self.close(&app)?; self.native_dialog(4,&app).await?;
        self.until(||self.doc().is_ok_and(|d|d.fixture_cancel_preserved(&selection))).await?; self.dialog_facts(4)?;
        self.probes()?.bridge.edits.session_gtk_idle(false)?;
        self.mark(5)?; self.close(&app)?; self.native_dialog(5,&app).await?;
        // Helper completion precedes app Exit by construction: the outer emits
        // it after original helper wait/EOF/close, without waiting for this app.
        self.native.settled(&self.input.files).await?;
        Ok(())
    }
    fn dialog_facts(&self,n:u32)->Check<()> {
        let b=self.record()?; let events:Vec<_>=b.events.iter().filter(|e|e.operation==n).collect();
        let one=|kind:EventKind,main:Option<bool>|->Check<u32> {
            let list:Vec<_>=events.iter().filter(|e|e.kind==kind).collect();
            let detail=match kind {EventKind::CoordinatorRegistered=>u32::from(n>=4),
                EventKind::ConstructEnter=>if n<=2 {1} else if n==3 {2} else {3},_=>1};
            check(list.len()==1 && main.is_none_or(|m|list[0].main_thread==m) && list[0].detail==detail,"sg1_original_callback_roster")?; Ok(list[0].ordinal)
        };
        let registered=one(EventKind::CoordinatorRegistered,None)?;
        let dispatch=one(EventKind::ConstructDispatch,Some(false))?; let construct=one(EventKind::ConstructEnter,Some(true))?;
        let adopt=one(EventKind::Adopted,Some(true))?; let show=one(EventKind::Show,Some(true))?;
        let decisions:Vec<_>=events.iter().filter(|e|e.kind==EventKind::ResponseDecision).collect();
        // admitted_response's declined bit is quit-only: a project Cancel is
        // not accepted (0), while genuine pre-STOP Quit Cancel is declined (2).
        check(decisions.len()==1 && decisions[0].main_thread && decisions[0].detail==match n {1=>0,4=>2,_=>1},"sg1_first_native_decision")?;
        let responses:Vec<_>=events.iter().filter(|e|e.kind==EventKind::ResponseEnter).collect();
        let leaves:Vec<_>=events.iter().filter(|e|e.kind==EventKind::ResponseLeave).collect();
        // One actual user response plus at most one close-generated DeleteEvent.
        // The direct-GTK emission audit must justify this exact multiplicity.
        check((1..=2).contains(&responses.len()) && responses.len()==leaves.len(),"sg1_response_multiplicity")?;
        let close_dispatch=one(EventKind::CloseDispatch,Some(false))?; let close=one(EventKind::CloseEnter,Some(true))?;
        let destroy=one(EventKind::DestroyEnter,Some(true))?; let destroyed=one(EventKind::DestroyLeave,Some(true))?;
        let ack=one(EventKind::CloseAck,Some(true))?; let close_leave=one(EventKind::CloseLeave,Some(true))?;
        let release_dispatch=one(EventKind::ReleaseDispatch,Some(false))?; let release=one(EventKind::ReleaseEnter,Some(true))?;
        let handlers=one(EventKind::HandlersDetached,Some(true))?; let released=one(EventKind::Released,Some(true))?;
        let release_leave=one(EventKind::ReleaseLeave,Some(true))?; let joined=one(EventKind::CoordinatorJoined,None)?;
        let tagged=one(EventKind::TopologyTagged,Some(true))?;let checked=one(EventKind::TopologyChecked,Some(true))?;
        let retired=one(EventKind::TopologyRetired,Some(true))?;
        let topology=b.topology[n as usize-1].as_ref().ok_or("sg1_topology_original_slot")?;
        let proof=topology.proof.as_ref().ok_or("sg1_topology_original_proof")?;
        check(topology.requested && topology.consumed && topology.tag_ordinal==Some(tagged) && topology.retire_ordinal==Some(retired)
            && proof.operation==n && proof.tag_ordinal==tagged && proof.check_ordinal==checked
            && proof.main_id==topology.tags.main_id && proof.dialog_id==topology.tags.dialog_id
            && proof.transient_for_main && proof.method=="gtk-window-get-transient-for","sg1_topology_original_event_links")?;
        check(adopt<tagged && tagged<show && show<checked && checked<responses[0].ordinal
            && handlers<retired && retired<released,"sg1_topology_tag_check_retire_order")?;
        // GTK3 close() acknowledges a queued delete request, not destruction.
        // The worker may dispatch release after the destroyed flag is set but
        // before DestroyLeave; queued main-thread ReleaseEnter is its unwind barrier.
        check(registered<dispatch && dispatch<construct && construct<adopt && adopt<show && show<responses[0].ordinal
            && responses[0].ordinal<decisions[0].ordinal && decisions[0].ordinal<leaves[0].ordinal
            && leaves[0].ordinal<close && decisions[0].ordinal<close_dispatch && close_dispatch<close
            && close<ack && ack<close_leave && close_leave<destroy && destroy<destroyed
            && ack<release_dispatch && destroy<release_dispatch && destroyed<release
            && close_leave<release && release_dispatch<release
            && release<handlers && handlers<released && released<release_leave && release_leave<joined,"sg1_unwind_disposal_join_order")?;
        for (index,(enter,leave)) in responses.iter().zip(&leaves).enumerate() {
            check(enter.main_thread && leave.main_thread && leave.detail==1 && enter.ordinal<leave.ordinal,"sg1_response_unwind")?;
            if index==0 {check(enter.detail==if matches!(n,2|3|5) {1} else {2},"sg1_original_response_class")?;}
            else {check(enter.detail==3 && close_leave<enter.ordinal && leave.ordinal<destroy,"sg1_disposal_response_only")?;}
        }
        let reads:Vec<_>=events.iter().filter(|e|e.kind==EventKind::Filename).collect();
        check(reads.len()==usize::from(matches!(n,2|3)) && reads.iter().all(|e|e.main_thread && e.detail==1
            && decisions[0].ordinal<e.ordinal && e.ordinal<leaves[0].ordinal),"sg1_filename_once_after_acceptance")?;
        let stops:Vec<_>=events.iter().filter(|e|e.kind==EventKind::QuitStop).collect();
        check(stops.len()==usize::from(n==5) && stops.iter().all(|e|e.main_thread && e.detail==1
            && decisions[0].ordinal<e.ordinal && e.ordinal<leaves[0].ordinal),"sg1_actual_ok_stop_before_unwind")?;
        check(b.sources[n as usize-1].is_some(),"sg1_missing_original_source_book")?;
        Ok(())
    }
    fn final_events(&self,b:&Record)->Check<()> {
        let one=|kind:EventKind,operation:u32,detail:u32,main:Option<bool>|->Check<u32> {
            let found:Vec<_>=b.events.iter().filter(|e|e.kind==kind && e.operation==operation && e.detail==detail).collect();
            check(found.len()==1 && main.is_none_or(|m|found[0].main_thread==m),"sg1_event_original_once")?;
            Ok(found[0].ordinal)
        };
        let count=|kind:EventKind|b.events.iter().filter(|e|e.kind==kind).count();
        let first=one(EventKind::Checkpoint,1,1,Some(false))?;
        let finished=one(EventKind::LoadFinished,0,1,Some(true))?;
        for kind in [EventKind::Navigation,EventKind::LoadStarted,EventKind::HookInstalled] {
            // The existing lifetime permits Navigation either side of Started;
            // never invent an ordering between those two original callbacks.
            check(count(kind)==1 && one(kind,0,1,Some(true))?<finished,"sg1_original_lifecycle_order")?;
        }
        check(count(EventKind::LoadFinished)==1 && count(EventKind::DocumentLost)==0 && finished<first,"sg1_original_lifecycle_complete")?;
        let expected=[(Command::AppInfo,0,1),(Command::Catalog,0,1),(Command::EditStatus,0,1),(Command::AssetStatus,0,1),(Command::EnvironmentStatus,0,1),
            (Command::Project,1,2),(Command::Project,2,3),(Command::Open,3,1),(Command::Context,3,1),(Command::Choose,3,1)];
        check(b.commands.len()==expected.len() && count(EventKind::CommandEnter)==10 && count(EventKind::CommandReturn)==10
            && expected.iter().all(|(kind,stage,reply)|b.complete(*kind,*stage,*reply)),"sg1_exact_command_roster")?;
        for c in &b.commands {
            let returned=c.returned.ok_or("sg1_command_unreturned")?;
            let enter=b.events.get(c.entered as usize-1).ok_or("sg1_command_enter")?;
            let leave=b.events.get(returned as usize-1).ok_or("sg1_command_leave")?;
            check(enter.kind==EventKind::CommandEnter && enter.operation==c.stage && enter.detail==c.kind as u32
                && leave.kind==EventKind::CommandReturn && leave.operation==c.stage && leave.detail==c.reply
                && c.entered<returned && (c.stage!=0 || returned<first),"sg1_actual_command_links")?;
        }
        check(count(EventKind::Checkpoint)==10 && count(EventKind::CoordinatorRegistered)==5
            && count(EventKind::CoordinatorJoined)==5 && count(EventKind::TopologyTagged)==5
            && count(EventKind::TopologyChecked)==5 && count(EventKind::TopologyRetired)==5,"sg1_exact_original_roster")?;
        for n in 1..=5 {
            let stage=one(EventKind::Checkpoint,n,1,Some(false))?;
            let go=one(EventKind::Checkpoint,n,2,Some(false))?;
            let registered=one(EventKind::CoordinatorRegistered,n,u32::from(n>=4),None)?;
            let shown=one(EventKind::Show,n,1,Some(true))?;
            let joined=one(EventKind::CoordinatorJoined,n,1,None)?;
            let decision=one(EventKind::ResponseDecision,n,match n {1=>0,4=>2,_=>1},Some(true))?;
            let checked=one(EventKind::TopologyChecked,n,1,Some(true))?;
            let first_response=b.events.iter().find(|e|e.kind==EventKind::ResponseEnter && e.operation==n).ok_or("sg1_original_response")?.ordinal;
            check(stage<registered && shown<checked && checked<go && go<first_response && first_response<decision,"sg1_checkpoint_dialog_order")?;
            if n<5 {check(joined<one(EventKind::Checkpoint,n+1,1,Some(false))?,"sg1_original_join_before_next_stage")?;}
        }
        let stimuli:Vec<_>=b.events.iter().filter(|e|e.kind==EventKind::CloseStimulus).collect();
        let prevented:Vec<_>=b.events.iter().filter(|e|e.kind==EventKind::ClosePrevented).collect();
        check(stimuli.len()==3 && prevented.len()==3,"sg1_close_stimuli")?;
        for ((stimulus,prevent),n) in stimuli.iter().zip(&prevented).zip([1,4,5]) {
            check(stimulus.operation==0 && stimulus.detail==1 && !stimulus.main_thread && prevent.operation==0
                && prevent.detail==1 && prevent.main_thread && stimulus.ordinal<prevent.ordinal
                && one(EventKind::Checkpoint,n,1,Some(false))?<stimulus.ordinal
                && prevent.ordinal<one(EventKind::Checkpoint,n,2,Some(false))?,"sg1_actual_prevented_close")?;
            if n==1 {check(one(EventKind::Show,1,1,Some(true))?<stimulus.ordinal
                && prevent.ordinal<one(EventKind::TopologyChecked,1,1,Some(true))?,"sg1_picker_shown_close")?;}
            else {check(prevent.ordinal<one(EventKind::CoordinatorRegistered,n,1,None)?,"sg1_close_original_quit")?;}
        }
        let children:Vec<_>=b.events.iter().filter(|e|e.kind==EventKind::ChildRegistered).map(|e|(e.operation,e.detail)).collect();
        let joins:Vec<_>=b.events.iter().filter(|e|e.kind==EventKind::ChildJoined).map(|e|(e.operation,e.detail)).collect();
        check(children==[(2,1),(3,2),(3,3)] && joins==[(2,3),(3,5),(3,7)],"sg1_child_incarnations")?;
        for (op,tag) in [(2,1),(3,2),(3,3)] {
            let child=one(EventKind::ChildRegistered,op,tag,Some(false))?;
            let join=one(EventKind::ChildJoined,op,tag*2+1,Some(false))?;
            check(child<join && join<one(EventKind::CoordinatorJoined,op,1,None)?,"sg1_child_original_joins")?;
            if tag==2 {check(join<one(EventKind::ConstructDispatch,3,1,Some(false))?,"sg1_tokens_before_dialog")?;}
            else {check(one(EventKind::ReleaseLeave,op,1,Some(true))?<child,"sg1_release_before_source_child")?;}
        }
        check(count(EventKind::HeaderObserved)==1 && count(EventKind::ProjectPublished)==1
            && count(EventKind::CandidatePublished)==1 && count(EventKind::QuitStop)==1
            && count(EventKind::RelayJoined)==1 && count(EventKind::RecipeReturned)==1,"sg1_singleton_final_facts")?;
        let header=one(EventKind::HeaderObserved,3,1,Some(false))?;
        check(one(EventKind::ChildRegistered,3,3,Some(false))?<header && header<one(EventKind::ChildJoined,3,7,Some(false))?,"sg1_header_in_original_capture")?;
        for (op,publication) in [(2,EventKind::ProjectPublished),(3,EventKind::CandidatePublished)] {
            check(one(EventKind::CoordinatorJoined,op,1,None)?<one(publication,op,1,None)?,"sg1_join_before_publication")?;
        }
        check(one(EventKind::CoordinatorJoined,5,1,None)?<one(EventKind::RelayJoined,0,1,Some(false))?
            && one(EventKind::Checkpoint,5,2,Some(false))?<one(EventKind::RecipeReturned,0,1,Some(false))?,"sg1_final_original_tails")?;
        Ok(())
    }
    pub(super) async fn seal(self:&Arc<Self>)->Check<()> {
        check(self.phase.compare_exchange(DISARMED,SEALING,Ordering::SeqCst,Ordering::SeqCst).is_ok(),"sg1_seal_once")?;
        let guard=Preclose {context:self,armed:false};
        self.recipe.join(self,Some(Duration::from_secs(8))).await??;
        check(self.recipe.joined() && self.relay_ok.load(Ordering::SeqCst) && self.doc()?.can_exit() && self.doc()?.fixture_final(),"sg1_final_original_conjunction")?;
        let passive=self.probes()?.passive.final_facts().await?; let edit=self.probes()?.bridge.edits.session_gtk_idle(true)?;
        let diagnostics_owner=&self.probes()?.bridge.diagnostics;
        let diagnostics_final=diagnostics_owner.status(crate::environment_diagnostics_protocol::Availability::Available)
            .map_err(|_|"sg1_diagnostics_final_status")?;
        check(diagnostics_owner.can_exit() && !diagnostics_owner.disabled() && diagnostics_owner.stopping()
            && diagnostics_final.schema_version==1 && diagnostics_final.status_revision<u32::MAX
            && !diagnostics_final.capability.available
            && diagnostics_final.capability.reason==crate::environment_diagnostics_protocol::Availability::Shutdown
            && diagnostics_final.active.is_none() && diagnostics_final.last_terminal.is_none(),"sg1_diagnostics_never_started")?;
        self.native.closed()?; self.input.unchanged()?;
        for n in 1..=5 {self.dialog_facts(n)?;}
        let prefix={let b=self.record()?;
            check(b.stage==5,"sg1_final_stage")?; self.final_events(&b)?;
            let native_ownership=self.topology_prefix(&b)?;
            let diagnostics_bootstrap=b.diagnostics_bootstrap.as_ref().ok_or("sg1_diagnostics_bootstrap_missing")?;
            json!({"scope":"session-gtk-five-dialog-v1","case":"SG1","fixtureOnly":true,"events":b.events,
                "commands":b.commands,"sources":b.sources,"nativeOwnership":native_ownership,"passive":passive,"edit":edit,"relayJoin":"ok","recipeJoin":"ok",
                "diagnosticsBootstrap":diagnostics_bootstrap,"diagnosticsFinal":diagnostics_final,
                "documentBound":true,"selectedCancelPreserved":true,
                "frontendSubscriptions":{"sourcePinned":true,"names":["config-edit-state","asset-session-state","environment-diagnostics-state-changed"],
                    "evidence":"real-status-command-after-awaited-listen-in-pinned-controller"}})
        };
        let bytes=crate::edit_protocol::bounded(&prefix,64*1024).map_err(|_|"sg1_prefix_bound")?;
        self.input.files.write_new(&self.input.root.join("app/prefix.json"),&bytes)?;
        let before=self.input.files.counts()?;
        let receipt=json!({"scope":"session-gtk-five-dialog-v1","case":"SG1","status":"preclosed-fixture-only",
            "bindings":self.input.bindings,"prefixSha256":hash(&bytes),"filesBeforeReceipt":before,
            "lastFile":"positive-consuming-close-before-Exit-witness","notVerified":NOT_VERIFIED});
        let bytes=crate::edit_protocol::bounded(&receipt,64*1024).map_err(|_|"sg1_receipt_bound")?;
        self.input.files.write_new(&self.input.root.join("app/final.json"),&bytes)?;
        let after=self.input.files.counts()?;
        check(after.opened==before.opened+1 && after.close_attempted==after.opened && after.close_settled==after.opened
            && !after.unknown && self.doc()?.can_exit() && self.doc()?.fixture_final(),"sg1_preclosed_files_and_originals")?;
        guard.arm()
    }
    pub(super) fn actual_exit(&self,ready:bool) {
        if std::thread::current().id()!=self.main || !ready || self.failed.load(Ordering::SeqCst)
            || self.phase.compare_exchange(ARMED,SPENT,Ordering::SeqCst,Ordering::SeqCst).is_err() {self.refuse();return;}
        // Sole whole borrowed nonblocking write; no formatter, retry, flush,
        // owned stdout/drop close, ExitRequested writer or post-run repair.
        self.wrote.store(nix::unistd::write(&self.stdout,WITNESS).is_ok_and(|n|n==WITNESS.len()),Ordering::SeqCst);
    }
}
struct Preclose<'a> {context:&'a Qualification,armed:bool}
impl Preclose<'_> {
    fn arm(mut self)->Check<()> {
        check(!self.context.failed.load(Ordering::SeqCst)
            && self.context.phase.compare_exchange(SEALING,ARMED,Ordering::SeqCst,Ordering::SeqCst).is_ok(),"sg1_arm")?;
        self.armed=true; Ok(())
    }
}
impl Drop for Preclose<'_> {fn drop(&mut self) {if !self.armed {self.context.refuse();}}}
pub(super) struct CommandGuard {context:Arc<Qualification>,index:usize,done:bool}
impl CommandGuard {
    fn finish(mut self,reply:u32,project:Option<&Project>) {
        let result:Check<()>=(|| {
            check(reply!=0,"sg1_command_result")?; let mut b=self.context.record()?;
            let (stage,kind)={let c=b.commands.get(self.index).ok_or("sg1_command_original")?;check(c.returned.is_none(),"sg1_reply_twice")?;(c.stage,c.kind)};
            if let Some(project)=project {check(stage==2 && kind==Command::Project && b.project_id.is_none(),"sg1_project_reply")?;b.project_id=Some(project.id.clone());}
            let n=b.event(EventKind::CommandReturn,stage,reply,std::thread::current().id()==self.context.main)?;
            b.commands[self.index].returned=Some(n);b.commands[self.index].reply=reply;Ok(())
        })(); if result.is_err() {self.context.refuse();} self.done=true;
    }
    pub(super) fn info(self,r:&Result<AppInfo,BridgeError>) {let ok=r.as_ref().is_ok_and(|i|i.runtime.state=="available" && i.capabilities.is_some());self.finish(u32::from(ok),None);}
    pub(super) fn value(self,r:&Result<Value,BridgeError>) {self.finish(u32::from(r.is_ok()),None);}
    pub(super) fn edit(self,r:&Result<ConfigEditStatus,BridgeError>) {self.finish(u32::from(r.is_ok()),None);}
    pub(super) fn asset(self,r:&Result<AssetStatus,AssetError>) {self.finish(u32::from(r.is_ok()),None);}
    pub(super) fn environment_status_returned(self,r:&Result<crate::environment_diagnostics_protocol::Status,BridgeError>) {
        use crate::environment_diagnostics_protocol::Availability;
        // The actual awaited-listen Status can precede LoadFinished or overlap
        // passive bootstrap. Record that observation, never invent an idle
        // capability or start diagnostics to make the recipe pass.
        let accepted:Check<()>=(|| {
            let status=r.as_ref().map_err(|_|"sg1_diagnostics_bootstrap_reply")?;
            check(status.schema_version==1 && status.status_revision<u32::MAX && !status.capability.available
                && matches!(status.capability.reason,Availability::Busy|Availability::DocumentLost|Availability::RuntimeUnqualified)
                && status.active.is_none() && status.last_terminal.is_none(),"sg1_diagnostics_bootstrap_unavailable")?;
            let mut b=self.context.record()?;
            let original=b.commands.get(self.index).ok_or("sg1_command_original")?;
            check(original.kind==Command::EnvironmentStatus && original.stage==0 && original.returned.is_none()
                && b.diagnostics_bootstrap.is_none(),"sg1_diagnostics_bootstrap_once")?;
            b.diagnostics_bootstrap=Some(status.clone()); Ok(())
        })();
        self.finish(u32::from(accepted.is_ok()),None);
    }
    pub(super) fn project(self,r:&Result<Option<Project>,AssetError>) {
        match r {Ok(None)=>self.finish(2,None),Ok(Some(p))=>self.finish(3,Some(p)),Err(_)=>self.finish(0,None)}
    }
}
impl Drop for CommandGuard {fn drop(&mut self) {if !self.done {self.context.refuse();}}}

pub(crate) fn main()->std::process::ExitCode {
    // Record actual main BEFORE builder/GTK/library work. No linked normal run
    // calls this entry; absent reviewed host/API pins refuse before the builder.
    let main=std::thread::current().id();
    let admitted:Check<Arc<Qualification>>=(|| {
        native_contract::audit_gate()?;
        let stdout=inherited_stdout()?; let files=FileBook::new();
        let native=NativeAdmission::admit(&files,&stdout)?;
        let input=Inputs::admit(&native,files)?;
        Ok(Arc::new(Qualification {main,phase:AtomicU8::new(DISARMED),failed:AtomicBool::new(false),wrote:AtomicBool::new(false),
            stdout,input,native,document:OnceLock::new(),probes:OnceLock::new(),
            record:Mutex::new(Record {events:Vec::with_capacity(512),commands:Vec::with_capacity(10),stage:0,project_id:None,sources:std::array::from_fn(|_|None),
                topology:std::array::from_fn(|_|None),topology_main_retired:false,diagnostics_bootstrap:None}),
            recipe:OriginalTask::new(),relay_ok:AtomicBool::new(false)}))
    })();
    let context:Arc<Qualification>=match admitted {Ok(q)=>q,Err(_)=>{eprintln!("SG1 admission refused; no native qualification was run.");return std::process::ExitCode::FAILURE;}};
    let permit=FixtureAdmission {context:Some(context.clone())};
    super::run_builder(super::builder().manage(context.clone()).manage(Mutex::new(Some(permit))));
    if context.phase.load(Ordering::SeqCst)==SPENT && context.wrote.load(Ordering::SeqCst) && !context.failed.load(Ordering::SeqCst) {
        std::process::ExitCode::SUCCESS
    } else {std::process::ExitCode::FAILURE}
}
