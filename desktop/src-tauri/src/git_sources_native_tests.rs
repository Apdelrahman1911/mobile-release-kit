//! Opt-in tests of real Account/SourceBook/ACL custody on the owner Mac.
//! Only a newly created private fixture is written. No Git mutation, app
//! installation, service registration, credentials or network access.
use super::*;
use std::{fs, os::unix::fs::{DirBuilderExt, PermissionsExt}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

struct Fixture(RegisteredRoot);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("mrk-git-source-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        for child in [".git", ".git/objects"] {
            fs::DirBuilder::new().mode(0o700).create(path.join(child)).unwrap();
        }
        for (name, bytes) in [("HEAD", "ref: refs/heads/main\n"),
            ("config", "[core]\nrepositoryformatversion = 0\nbare = false\n")] {
            fs::write(path.join(".git").join(name), bytes).unwrap();
            fs::set_permissions(path.join(".git").join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let identity = directory_identity(&stat::lstat(&path).unwrap()).unwrap();
        Self(RegisteredRoot { path, identity: ProjectIdentity::Posix(identity) })
    }
    // Called only after positive settlement. A failed close/panic preserves the
    // private fixture and its original paths for inspection instead of erasing it.
    fn remove(self) { fs::remove_dir_all(&self.0.path).unwrap(); }
}

#[test]
#[ignore = "requires real macOS CLT Git and a private canonical TMPDIR"]
fn native_git_read_sources_inspect_recheck_and_close() {
    let fixture = Fixture::new();
    let mut sources = GitReadSources::new();
    let end = Instant::now() + Duration::from_secs(30);
    let result = sources.inspect(&fixture.0,
        crate::installed_runtime::GitReadRuntimeSlots::source_runtime_fd_bound(), &mut || Instant::now() >= end);
    let post = result.and_then(|()| sources.post(&mut || Instant::now() >= end));
    let close = sources.close(&mut |_| Instant::now() >= end);
    assert!(close.is_ok() && sources.settled(), "real originals must settle: {close:?}");
    fixture.remove();
    assert_eq!(post, Ok(()), "actual CLT Git and private repository source inspection");
}

#[test]
#[ignore = "requires real macOS CLT Git and a private canonical TMPDIR"]
fn native_git_local_sources_inspect_recheck_and_close() {
    let fixture = Fixture::new();
    let mut sources = GitLocalSources::new();
    let end = Instant::now() + Duration::from_secs(30);
    let result = sources.inspect(&fixture.0,
        crate::installed_runtime::GitLocalRuntimeSlots::source_runtime_fd_bound(), "native-source-check",
        crate::git_local_protocol::Kind::Stage, None, &mut || Instant::now() >= end);
    let post = result.and_then(|()| sources.post(&mut || Instant::now() >= end));
    let close = sources.close(&mut |_| Instant::now() >= end);
    assert!(close.is_ok() && sources.settled(), "real originals must settle: {close:?}");
    fixture.remove();
    assert_eq!(post, Ok(()), "actual CLT Git and private repository source inspection");
}
