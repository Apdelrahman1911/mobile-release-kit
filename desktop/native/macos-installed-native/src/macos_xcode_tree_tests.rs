//! Explicit disposable-Mac filesystem checks of existing copier primitives.
//! These private test roots are NOT Apple/SELF/Parent or publication authority.
#![cfg(all(test, feature = "xcode-setup", target_os = "macos"))]
use super::{
    macos_xcode_copy::{self as copy, Failure, Work},
    macos_xcode_tree::{CopierFiles, SourceTree},
};
use nix::{libc, sys::statfs};
use std::{
    ffi::{CStr, CString},
    fs,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[track_caller]
fn error(failure: Failure) -> std::io::Error {
    let site = std::panic::Location::caller();
    std::io::Error::other(format!("{failure:?} at {}:{}", site.file(), site.line()))
}
fn require(value: bool, why: &str) -> TestResult {
    if value {
        Ok(())
    } else {
        Err(std::io::Error::other(why).into())
    }
}
fn path_c(path: &Path) -> TestResult<CString> {
    Ok(CString::new(path.as_os_str().as_bytes())?)
}
// Only newly created nodes inside this exclusive test root are normalized.
// Darwin may inherit a temporary parent's group even for a root creator.
fn root_owner(path: &Path) -> TestResult {
    let path = path_c(path)?;
    if unsafe { libc::lchown(path.as_ptr(), 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn directory(path: &Path, mode: u32) -> TestResult {
    fs::DirBuilder::new().mode(mode).create(path)?;
    root_owner(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn file(path: &Path, bytes: &[u8], mode: u32) -> TestResult {
    fs::write(path, bytes)?;
    root_owner(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn fixture(label: &str) -> (PathBuf, fs::Metadata, Work, Instant) {
    // This is a test precondition, never a skipped-success fallback.
    assert_eq!(
        unsafe { libc::getuid() },
        0,
        "disposable macOS root fixture required"
    );
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "disposable macOS root fixture required"
    );
    let root = std::env::temp_dir().join(format!(
        "mrk-xcode-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    directory(&root, 0o700).unwrap();
    let identity = fs::symlink_metadata(&root).unwrap();
    let end = Instant::now() + Duration::from_secs(60);
    (
        root,
        identity,
        Work {
            end,
            parent: unsafe { libc::getppid() },
        },
        end + Duration::from_secs(5),
    )
}
fn finish(
    root: &Path,
    original: &fs::Metadata,
    inputs: Vec<OwnedFd>,
    tables_closed: bool,
    observed: TestResult,
) {
    let mut inputs_closed = true;
    for fd in inputs.into_iter().rev() {
        inputs_closed &= nix::unistd::close(fd).is_ok();
    }
    let same = fs::symlink_metadata(root).is_ok_and(|now| {
        now.is_dir()
            && (now.dev(), now.ino(), now.mode(), now.uid(), now.gid())
                == (
                    original.dev(),
                    original.ino(),
                    original.mode(),
                    original.uid(),
                    original.gid(),
                )
    });
    // Unknown originals never grant deletion underneath them. Retain this exact
    // exclusive fixture for disposable-host cleanup and fail honestly.
    if !tables_closed || !inputs_closed || !same {
        panic!(
            "fixture retained: original closure/root identity unconfirmed at {}",
            root.display()
        );
    }
    let cleanup = fs::remove_dir_all(root);
    assert!(
        cleanup.is_ok(),
        "own temporary fixture cleanup failed: {cleanup:?}"
    );
    observed.expect("actual copier/retirement fixture");
}
// Test diagnostics for the two shared read boundaries. Only fixed operation
// labels and errno are reported; never enumerate/log fixture file contents.
fn probe_directory(fd: std::os::fd::BorrowedFd<'_>) -> TestResult {
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
        return Err(std::io::Error::other(format!("directory rewind errno={:?}", std::io::Error::last_os_error().raw_os_error())).into());
    }
    let mut block = [0u8; 65536];
    let observed = super::directory_block(fd, &mut block);
    let reset = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) };
    let reset_error = if reset != 0 { Some(std::io::Error::last_os_error().raw_os_error()) } else { None };
    observed.map_err(|error| std::io::Error::other(format!("directory-block errno={:?}", error.raw_os_error())))?;
    require(reset == 0, &format!("directory reset errno={reset_error:?}"))
}
fn probe_symlink(path: &Path, inputs: &mut Vec<OwnedFd>) -> TestResult {
    let path = path_c(path)?;
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::other(format!("symlink-open errno={:?}", std::io::Error::last_os_error().raw_os_error())).into());
    }
    // Adopt before any fallible check; the existing fixture finish owns close.
    inputs.push(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::other(format!("symlink-stat errno={:?}", std::io::Error::last_os_error().raw_os_error())).into());
    }
    require(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFLNK, "probe opened referent instead of alias")
}
const ATTR: &CStr = c"dev.mobile-release-kit.setup-fixture";
const ATTRIBUTE: &[u8] = b"bounded visible xattr\0fixture";
fn set_attribute(path: &Path) -> TestResult {
    let path = path_c(path)?;
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            ATTR.as_ptr(),
            ATTRIBUTE.as_ptr().cast(),
            ATTRIBUTE.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn check_attribute(path: &Path) -> TestResult {
    let path = path_c(path)?;
    let mut bytes = [0u8; 64];
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            ATTR.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    require(
        n as usize == ATTRIBUTE.len() && &bytes[..n as usize] == ATTRIBUTE,
        "xattr bytes changed",
    )
}

#[test]
#[ignore = "requires explicit disposable macOS root/APFS fixture"]
fn copier_copies_real_bytes_links_attributes_and_retires_only_its_stage() {
    let (root, root_id, work, cleanup) = fixture("copy-native");
    let mut inputs: Vec<OwnedFd> = Vec::new();
    let mut tables_closed = true;
    let observed = (|| -> TestResult {
        let source = root.join("Xcode.app");
        let versions = source.join("Versions");
        let version = versions.join("A");
        directory(&source, 0o755)?;
        directory(&versions, 0o755)?;
        directory(&version, 0o755)?;
        file(&version.join("data"), b"original bytes", 0o644)?;
        fs::hard_link(version.join("data"), version.join("hardlink"))?;
        file(&version.join("tool"), b"not executed", 0o755)?;
        symlink("A", versions.join("Current"))?;
        set_attribute(&version.join("data"))?;
        let source_data = fs::symlink_metadata(version.join("data"))?;
        require(
            source_data.ino() == fs::symlink_metadata(version.join("hardlink"))?.ino(),
            "source hardlink fixture missing",
        )?;
        let pending = root.join("pending");
        directory(&pending, 0o700)?;
        directory(&pending.join("Xcode.app"), 0o700)?;
        inputs.push(fs::File::open(&root)?.into());
        inputs.push(fs::File::open(&source)?.into());
        inputs.push(fs::File::open(&pending)?.into());
        probe_directory(inputs[1].as_fd())?;
        probe_symlink(&versions.join("Current"), &mut inputs)?;
        let mut files = CopierFiles::new(cleanup, inputs.len()).map_err(|failure| error(failure))?;
        let body = (|| -> TestResult {
            let source_id = copy::fstat(inputs[1].as_fd(), &work).map_err(|failure| error(failure))?;
            let stage_id = copy::fstat(inputs[2].as_fd(), &work).map_err(|failure| error(failure))?;
            let created = copy::named(inputs[2].as_fd(), c"Xcode.app", &work).map_err(|failure| error(failure))?;
            // A public source755 is legitimate copy input but not a protected
            // prepared tree. The private pending700 is refused even by the
            // original source gate; neither check changes its retained inode.
            require(
                SourceTree::original(
                    inputs[1].as_fd(),
                    inputs[0].as_fd(),
                    c"Xcode.app",
                    source_id,
                    &work,
                )
                .and_then(SourceTree::protected)
                .is_err(),
                "writable source accepted as a protected payload",
            )?;
            require(
                SourceTree::original(
                    inputs[2].as_fd(),
                    inputs[0].as_fd(),
                    c"pending",
                    stage_id,
                    &work,
                )
                .and_then(SourceTree::protected)
                .is_err(),
                "private unfinished root accepted as a protected payload",
            )?;
            require(
                copy::fstat(inputs[2].as_fd(), &work).map_err(|failure| error(failure))? == stage_id,
                "protected refusal changed the private pending original",
            )?;
            let mut tree = SourceTree::original(
                inputs[1].as_fd(),
                inputs[0].as_fd(),
                c"Xcode.app",
                source_id,
                &work,
            )
            .map_err(|failure| error(failure))?;
            let allocation = u64::from(statfs::fstatfs(inputs[2].as_fd())?.block_size());
            let census = tree.census(&mut files, allocation).map_err(|failure| error(failure))?;
            let sealed = tree
                .copy_to(
                    &mut files,
                    inputs[2].as_fd(),
                    stage_id,
                    created.device() as u64,
                    created.inode(),
                    &census,
                )
                .map_err(|failure| error(failure))?;
            require(
                sealed.identity
                    == copy::fstat(files.fd(sealed.slot).map_err(|failure| error(failure))?, &work).map_err(|failure| error(failure))?,
                "sealed original changed",
            )?;
            require(sealed.digest != [0; 32], "sealed digest absent")?;
            {
                // Borrow this same retained slot, never dup/open another FD.
                // Its raw borrow ends before original pool closure below.
                let output_raw = files.fd(sealed.slot).map_err(|failure| error(failure))?.as_raw_fd();
                let output_fd = unsafe { BorrowedFd::borrow_raw(output_raw) };
                let protected = SourceTree::original(
                    output_fd,
                    inputs[2].as_fd(),
                    c"Xcode.app",
                    sealed.identity,
                    &work,
                )
                .and_then(SourceTree::protected)
                .map_err(|failure| error(failure))?;
                let original_live = files.live();
                let first = protected.census(&mut files, allocation).map_err(|failure| error(failure))?;
                let second = protected.census(&mut files, allocation).map_err(|failure| error(failure))?;
                require(
                    first == second && files.live() == original_live,
                    "protected repeated census changed the tree or retained extra originals",
                )?;
                require(
                    copy::fstat(output_fd, &work).map_err(|failure| error(failure))? == sealed.identity,
                    "protected census changed the sealed original",
                )?;
            }
            let output = pending.join("Xcode.app");
            let copied = output.join("Versions/A/data");
            let copied_id = fs::symlink_metadata(&copied)?;
            let hard_id = fs::symlink_metadata(output.join("Versions/A/hardlink"))?;
            require(
                copied_id.ino() != source_data.ino()
                    && hard_id.ino() != source_data.ino()
                    && copied_id.ino() != hard_id.ino(),
                "output adopted a source/hardlink inode",
            )?;
            for path in [
                &output,
                &output.join("Versions"),
                &output.join("Versions/A"),
                &output.join("Versions/A/tool"),
            ] {
                let id = fs::symlink_metadata(path)?;
                require(
                    id.mode() & 0o7777 == 0o555 && id.uid() == 0 && id.gid() == 0,
                    "output directory/executable ownership or mode",
                )?;
            }
            for path in [&copied, &output.join("Versions/A/hardlink")] {
                let id = fs::symlink_metadata(path)?;
                require(
                    id.mode() & 0o7777 == 0o444
                        && id.uid() == 0
                        && id.gid() == 0
                        && id.nlink() == 1,
                    "output regular ownership/mode/links",
                )?;
                require(fs::read(path)? == b"original bytes", "copied bytes changed")?;
                check_attribute(path)?;
            }
            require(
                fs::read_link(output.join("Versions/Current"))? == Path::new("A"),
                "alias bytes changed",
            )?;
            check_attribute(&version.join("data"))?;
            require(
                copy::fstat(inputs[1].as_fd(), &work).map_err(|failure| error(failure))? == source_id,
                "source root changed",
            )?;
            require(files.close_all(), "copy originals close unconfirmed")?;
            let pending_now = copy::fstat(inputs[2].as_fd(), &work).map_err(|failure| error(failure))?;
            files
                .retire_pending(
                    inputs[2].as_fd(),
                    pending_now,
                    created.device() as u64,
                    created.inode(),
                    work.parent,
                )
                .map_err(|failure| error(failure))?;
            require(
                fs::read_dir(&pending)?.next().is_none(),
                "pending payload remains",
            )?;
            require(
                fs::read(version.join("data"))? == b"original bytes",
                "retirement changed source",
            )?;
            Ok(())
        })();
        if body.is_err() {
            files.note_failure();
        }
        tables_closed &= files.close_all();
        body
    })();
    finish(&root, &root_id, inputs, tables_closed, observed);
}

#[test]
#[ignore = "requires explicit disposable macOS root/APFS fixture"]
fn retirement_checks_recorded_identity_and_never_follows_partial_or_sealed_aliases() {
    let (root, root_id, work, cleanup) = fixture("retire-native");
    let mut inputs: Vec<OwnedFd> = Vec::new();
    let mut tables_closed = true;
    let observed = (|| -> TestResult {
        let pending = root.join("pending");
        let app = pending.join("Xcode.app");
        let sealed = app.join("sealed");
        directory(&pending, 0o700)?;
        directory(&app, 0o700)?;
        directory(&sealed, 0o700)?;
        file(&app.join("partial"), b"partial", 0o600)?;
        file(&sealed.join("data"), b"sealed", 0o444)?;
        fs::set_permissions(&sealed, fs::Permissions::from_mode(0o555))?;
        let sentinel = root.join("outside-pending");
        file(&sentinel, b"must survive", 0o644)?;
        let sentinel_id = fs::symlink_metadata(&sentinel)?;
        let alias = app.join("external");
        symlink("../../outside-pending", &alias)?;
        root_owner(&alias)?;
        let alias_c = path_c(&alias)?;
        // Darwin fchmodat is exported by the pinned libc crate; NOFOLLOW
        // changes only this test-owned alias, never the outside sentinel.
        if unsafe {
            libc::fchmodat(libc::AT_FDCWD, alias_c.as_ptr(), 0o500, libc::AT_SYMLINK_NOFOLLOW)
        } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        require(
            fs::symlink_metadata(&alias)?.mode() & 0o777 == 0o500,
            "non0777 alias fixture missing",
        )?;
        inputs.push(fs::File::open(&pending)?.into());
        probe_directory(inputs[0].as_fd())?;
        probe_symlink(&alias, &mut inputs)?;
        let pending_id = copy::fstat(inputs[0].as_fd(), &work).map_err(|failure| error(failure))?;
        let app_id = copy::named(inputs[0].as_fd(), c"Xcode.app", &work).map_err(|failure| error(failure))?;
        let mut rejected = CopierFiles::new(cleanup, inputs.len()).map_err(|failure| error(failure))?;
        let refusal = rejected.retire_pending(
            inputs[0].as_fd(),
            pending_id,
            app_id.device() as u64,
            app_id
                .inode()
                .checked_add(1)
                .ok_or_else(|| error(Failure::Bounds))?,
            work.parent,
        );
        tables_closed &= rejected.close_all();
        require(tables_closed, "refused table close unconfirmed")?;
        require(
            matches!(refusal, Err(Failure::Binding)),
            "wrong recorded stage identity not refused",
        )?;
        require(
            copy::named(inputs[0].as_fd(), c"Xcode.app", &work).map_err(|failure| error(failure))? == app_id,
            "refusal changed stage",
        )?;
        require(
            fs::read(app.join("partial"))? == b"partial"
                && fs::read(sealed.join("data"))? == b"sealed"
                && fs::read_link(&alias)? == Path::new("../../outside-pending"),
            "refusal changed contents",
        )?;
        // Separate primitive call after the rejected table positively closed;
        // same original endpoint, not a Parent recovery/authorization bypass.
        let mut accepted = CopierFiles::new(cleanup, inputs.len()).map_err(|failure| error(failure))?;
        let retired = accepted.retire_pending(
            inputs[0].as_fd(),
            pending_id,
            app_id.device() as u64,
            app_id.inode(),
            work.parent,
        );
        tables_closed &= accepted.close_all();
        retired.map_err(|failure| error(failure))?;
        require(
            fs::read_dir(&pending)?.next().is_none(),
            "retired payload remains",
        )?;
        let after = fs::symlink_metadata(&sentinel)?;
        require(
            (
                after.dev(),
                after.ino(),
                after.mode(),
                after.uid(),
                after.gid(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            ) == (
                sentinel_id.dev(),
                sentinel_id.ino(),
                sentinel_id.mode(),
                sentinel_id.uid(),
                sentinel_id.gid(),
                sentinel_id.len(),
                sentinel_id.mtime(),
                sentinel_id.mtime_nsec(),
                sentinel_id.ctime(),
                sentinel_id.ctime_nsec(),
            ),
            "external referent metadata changed",
        )?;
        require(
            fs::read(&sentinel)? == b"must survive",
            "external referent bytes changed",
        )?;
        Ok(())
    })();
    finish(&root, &root_id, inputs, tables_closed, observed);
}
