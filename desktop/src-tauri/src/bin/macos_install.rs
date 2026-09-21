//! One-shot scripts-only standard Installer entry. Installer never lays files
//! into the final app/runtime destinations. This process alone owns all copy
//! writers; no Python, app, copy helper, daemon or general publisher runs as root.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() { eprintln!("This Installer supports macOS 26 ARM64 only."); std::process::exit(1); }
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() { std::process::exit(installer::run()); }

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod installer {
    use std::{collections::{BTreeMap, BTreeSet}, os::fd::{AsFd, OwnedFd}, path::Path, time::{Duration, Instant}};
    use nix::{errno::Errno, fcntl::{self, AtFlags, OFlag}, mount::MntFlags,
        sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use mobile_release_desktop::{macos_install_paths as paths, protocol::strict_json, runtime::safe_payload_path};
    use mrk_macos_installed_native as native;
    type Result<T> = std::result::Result<T, &'static str>;
    const FILES: usize = 2048; // Also fits strict_json's independent node bound.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Role { Reader, PayloadWriter, ReceiptWriter }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Identity { dev: i64, ino: u64, mode: u32, uid: u32, gid: u32, links: u64, size: i64,
        mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64 }
    impl Identity {
        fn of(s: &FileStat) -> Self { Self { dev: i64::from(s.st_dev), ino: s.st_ino, mode: u32::from(s.st_mode),
            uid: s.st_uid, gid: s.st_gid, links: u64::from(s.st_nlink), size: s.st_size,
            mtime: s.st_mtime, mtime_ns: s.st_mtime_nsec, ctime: s.st_ctime, ctime_ns: s.st_ctime_nsec } }
        fn same_object(self, other: Self) -> bool { self.dev == other.dev && self.ino == other.ino
            && self.mode & 0o170000 == other.mode & 0o170000 && self.uid == other.uid && self.gid == other.gid }
    }
    struct Original { fd: Option<OwnedFd>, state: State, role: Role, parent: Option<usize>, name: String, identity: Option<Identity> }
    // A mkdir effect gets its own record BEFORE the call, including effects
    // that returned successfully but whose subsequent open/verification failed.
    struct Creation { parent: usize, name: String, state: &'static str, identity: Option<Identity> }
    struct Install {
        originals: Vec<Original>, creations: Vec<Creation>, end: Instant, unknown: bool,
        stage: Option<usize>, stage_name: Option<String>, app: Option<usize>, runtime: Option<usize>,
        runtime_publication: &'static str, app_publication: &'static str, payload_verified: bool,
        #[cfg(feature = "macos-installed-installer-fixture")]
        fixture: Option<fixture::Context>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Inventory { schema_version: u32, release: String, runtime_manifest_sha256: String, files: Vec<Entry> }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry { path: String, sha256: String, size: u64, executable: bool }
    fn check(ok: bool, why: &'static str) -> Result<()> { if ok { Ok(()) } else { Err(why) } }
    fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
    fn component(value: &str) -> bool { value.is_ascii() && value.len() <= 255 && safe_payload_path(value) && !value.contains('/') }
    fn created_directory_private(id: Identity) -> bool {
        id.mode & 0o170000 == 0o040000 && id.uid == 0 && id.mode & 0o7077 == 0
    }
    fn created_directory_normalized(before: Identity, actual: Identity, named: Identity, mode: u32) -> bool {
        created_directory_private(before) && actual == named && before.dev == actual.dev && before.ino == actual.ino
            && actual.mode == (0o040000 | mode) && actual.uid == 0 && actual.gid == 0
    }
    // Consumes only the result of the SAME original one-use close. The inert
    // regression feeds this recorder DATA, never a fake/invalid descriptor.
    fn record_close_result(original: &mut Original, result: Option<nix::Result<()>>) -> bool {
        if original.state == State::Closing && original.fd.is_none() && matches!(result, Some(Ok(()))) {
            original.state = State::Closed; true
        } else { original.state = State::Unknown; false }
    }
    struct FinalResult { state: &'static str, reason: Option<&'static str>, exit: i32, deadline_met: bool }
    fn final_result(result: Result<()>, originals_settled: bool, unknown: bool, runtime: &str, app: &str,
        end: Instant, observed_after_closes: Instant) -> FinalResult {
        let deadline_met = observed_after_closes < end;
        // Preserve an earlier failure; otherwise record actual final close
        // uncertainty before the final time veto. Late known closes stay Closed.
        let reason = result.err().or_else(|| (!originals_settled).then_some("original-close-unknown"))
            .or_else(|| (!deadline_met).then_some("deadline"));
        let published = runtime == "confirmed" || app == "confirmed";
        let complete = reason.is_none() && deadline_met && originals_settled && !unknown
            && runtime == "confirmed" && app == "confirmed";
        let state = if complete { "installed" } else if published { "partial-installation-retained" }
            else if unknown { "unknown-retained" } else { "refused-staging-retained" };
        FinalResult { state, reason, exit: if complete { 0 } else if published { 20 } else { 1 }, deadline_met }
    }
    #[derive(Clone, Copy)]
    enum AclRole { InputDirectory, InputInventory, SystemRoot, SystemLibrary, SystemSupport, Other }
    impl AclRole {
        fn name(self) -> &'static str { match self {
            Self::InputDirectory => "input-directory", Self::InputInventory => "input-inventory", Self::SystemRoot => "system-root",
            Self::SystemLibrary => "system-library", Self::SystemSupport => "system-support", Self::Other => "other-protected-object",
        } }
    }
    fn acl_diagnostic(role: AclRole, failure: &native::AclFailure) {
        // Failure-only, finite scalar diagnostics. This is not a receipt or
        // evidence of finality. A failed/broken stderr must not panic past closes.
        let line = format!("MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role={};phase={};result={};call={};errno={};freeCall={};freeErrno={}\n",
            role.name(), failure.phase, failure.refusal_code.unwrap_or(0), failure.call_result, failure.native_errno,
            failure.free_result, failure.free_errno);
        if line.len() <= 512 {
            let _ = std::io::Write::write_all(&mut std::io::stderr().lock(), line.as_bytes());
        }
    }
    fn flags(directory: bool) -> OFlag { OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC
        | if directory { OFlag::O_DIRECTORY } else { OFlag::empty() } }
    const EXPORT_LIMIT: usize = 65536;
    #[cfg(not(feature = "macos-installed-installer-fixture"))]
    const EXPORT_KIND: &str = "ordinary";
    #[cfg(feature = "macos-installed-installer-fixture")]
    const EXPORT_KIND: &str = "fixture";
    fn export_name(kind: &str, source: &str, inventory: &str, manifest: &str) -> Result<String> {
        check(matches!(kind, "ordinary" | "fixture") && source.len() == 40
            && source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) && sha(inventory) && sha(manifest), "export-binding")?;
        let name = format!("MobileReleaseKit-InstallerResult-v1-{kind}-{source}-{inventory}-{manifest}.json");
        check(component(&name), "export-name")?; Ok(name)
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ExportDocument<'a> { schema_version: u32, kind: &'a str, source_commit: &'a str,
        inventory_sha256: &'a str, runtime_manifest_sha256: &'a str, transport_state: &'a str, result: &'a serde_json::Value }
    struct ExportBytes(Vec<u8>);
    impl std::io::Write for ExportBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.0.len().checked_add(bytes.len()).is_some_and(|n| n < EXPORT_LIMIT) {
                return Err(std::io::Error::other("bounded Installer export"));
            }
            self.0.extend_from_slice(bytes); Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    fn export_write_progress(written: usize, total: usize, returned: nix::Result<usize>) -> Result<usize> {
        let count = returned.map_err(|_| "export-write-refused")?;
        check(total <= EXPORT_LIMIT && written < total && count > 0 && count <= total - written, "export-write-progress")?;
        written.checked_add(count).ok_or("export-write-progress")
    }
    fn export_final(result: Result<()>, settled: bool, unknown: bool, end: Instant, after_closes: Instant) -> Result<()> {
        result?; check(settled && !unknown, "export-close-unknown")?; check(after_closes < end, "export-deadline")
    }
    // Exactly four original descriptors, entirely separate from Install's
    // immutable completed books. No new installation, retry, cleanup or clock.
    struct Export { originals: Vec<Original>, end: Instant, unknown: bool }
    impl Export {
        fn new(end: Instant) -> Self { Self { originals: Vec::with_capacity(4), end, unknown: false } }
        fn clock(&self) -> Result<()> { check(!self.unknown && Instant::now() < self.end, "export-deadline-or-unknown") }
        fn fd(&self, n: usize) -> Result<&OwnedFd> { self.originals.get(n).and_then(|r| r.fd.as_ref()).ok_or("export-original-missing") }
        fn reserve(&mut self, parent: Option<usize>, name: &str, role: Role) -> Result<usize> {
            self.clock()?; check(self.originals.len() < 4, "export-original-bound")?;
            let n = self.originals.len(); self.originals.push(Original { fd:None, state:State::Reserved, role,
                parent, name:name.into(), identity:None }); Ok(n)
        }
        fn named(&self, n: usize) -> Result<Identity> {
            self.clock()?; let original = &self.originals[n];
            let actual = if let Some(parent) = original.parent {
                stat::fstatat(self.fd(parent)?, original.name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            } else { stat::lstat(Path::new("/")) }.map_err(|_| "export-named-refused")?;
            self.clock()?; Ok(Identity::of(&actual))
        }
        fn observed(&self, n: usize) -> Result<Identity> {
            self.clock()?; let actual = stat::fstat(self.fd(n)?).map_err(|_| "export-stat-refused")?;
            self.clock()?; Ok(Identity::of(&actual))
        }
        fn adopt(&mut self, n: usize, opened: nix::Result<OwnedFd>) -> Result<()> {
            // Custody precedes even a late-return veto. An unsuccessful O_EXCL
            // may still have an effect; no unknown/partial filename is reused.
            match opened {
                Ok(fd) => { self.originals[n].fd = Some(fd); self.originals[n].state = State::Owned; }
                Err(_) => { self.originals[n].state = State::NoHandle; return Err("export-open-refused"); }
            }
            self.clock()
        }
        fn correspondence(&self, n: usize, exact: bool) -> Result<()> {
            let original = self.originals[n].identity.ok_or("export-identity-missing")?;
            let actual = self.observed(n)?; let named = self.named(n)?;
            check(if exact { actual == named && original == actual } else {
                original.same_object(actual) && original.mode == actual.mode
                    && actual.same_object(named) && actual.mode == named.mode
            }, "export-original-correspondence")
        }
        fn protected(&self, n: usize, directory: bool, mode: Option<u32>, role: AclRole) -> Result<()> {
            let id = self.observed(n)?;
            check(id.mode & 0o170000 == if directory { 0o040000 } else { 0o100000 }
                && id.uid == 0 && id.mode & 0o7022 == 0 && (directory || id.links == 1)
                && mode.is_none_or(|mode| id.gid == 0 && id.mode & 0o7777 == mode), "export-protection-refused")?;
            self.clock()?; let fs = statfs::fstatfs(self.fd(n)?).map_err(|_| "export-mount-refused")?; self.clock()?;
            check(fs.filesystem_type_name() == "apfs" && fs.flags().contains(MntFlags::MNT_LOCAL)
                && !fs.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP), "export-mount-refused")?;
            self.clock()?; native::empty_acl_observed(self.fd(n)?.as_fd()).map_err(|failure| {
                acl_diagnostic(role, &failure); "export-acl-refused"
            })?; self.clock()
        }
        fn directory(&mut self, parent: Option<usize>, name: &str, role: AclRole) -> Result<usize> {
            let n = self.reserve(parent, name, Role::Reader)?;
            let before = self.named(n)?; check(before.mode & 0o170000 == 0o040000, "export-parent-type")?;
            self.originals[n].identity = Some(before); self.clock()?; self.originals[n].state = State::Acquiring;
            let opened = if let Some(parent) = parent { fcntl::openat(self.fd(parent)?, name, flags(true), Mode::empty()) }
                else { fcntl::open(Path::new("/"), flags(true), Mode::empty()) };
            self.adopt(n, opened)?; self.correspondence(n, false)?; self.protected(n, true, None, role)?; Ok(n)
        }
        fn close(&mut self, n: usize) -> bool {
            let original = &mut self.originals[n];
            match original.state {
                State::Reserved => original.state = State::NoHandle,
                State::Owned => {
                    original.state = State::Closing;
                    let result = original.fd.take().map(unistd::close);
                    if !record_close_result(original, result) { self.unknown = true; }
                }
                State::Closed | State::NoHandle => {}, _ => self.unknown = true,
            }
            !self.unknown
        }
        fn persist(&self, n: usize, file: bool) -> Result<()> {
            self.clock()?; native::sync(self.fd(n)?.as_fd(), file).map_err(|_| "export-persistence-refused")?; self.clock()
        }
        fn write(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
            self.clock()?; check(!bytes.is_empty() && bytes.len() <= EXPORT_LIMIT, "export-byte-bound")?;
            let root = self.directory(None, "/", AclRole::SystemRoot)?;
            let library = self.directory(Some(root), "Library", AclRole::SystemLibrary)?;
            let support = self.directory(Some(library), "Application Support", AclRole::SystemSupport)?;
            let n = self.reserve(Some(support), name, Role::ReceiptWriter)?;
            self.clock()?; self.originals[n].state = State::Acquiring;
            let opened = fcntl::openat(self.fd(support)?, name, OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK, Mode::from_bits_truncate(0o600));
            self.adopt(n, opened)?;
            let original = self.observed(n)?;
            // Darwin may inherit the protected parent's group. Bind this fresh
            // private original first; only its later normalization requires0:0.
            check(original.mode == 0o100600 && original.uid == 0 && original.links == 1 && original.size == 0,
                "export-private-original")?;
            self.originals[n].identity = Some(original);
            self.correspondence(n, true)?; self.protected(n, false, None, AclRole::Other)?;
            let mut written = 0;
            while written < bytes.len() {
                self.clock()?; let actual = unistd::write(self.fd(n)?, &bytes[written..]);
                written = export_write_progress(written, bytes.len(), actual)?; self.clock()?;
            }
            let before_seal = self.observed(n)?;
            check(original.same_object(before_seal) && before_seal.mode == original.mode && before_seal.links == 1
                && before_seal.size == bytes.len() as i64 && before_seal == self.named(n)?, "export-written-size-or-identity")?;
            self.clock()?; unistd::fchown(self.fd(n)?, Some(unistd::Uid::from_raw(0)), Some(unistd::Gid::from_raw(0)))
                .map_err(|_| "export-owner")?; self.clock()?;
            stat::fchmod(self.fd(n)?, Mode::from_bits_truncate(0o444)).map_err(|_| "export-mode")?; self.clock()?;
            self.protected(n, false, Some(0o444), AclRole::Other)?;
            native::no_xattrs(self.fd(n)?.as_fd()).map_err(|_| "export-attributes")?; self.clock()?;
            let sealed = self.observed(n)?;
            check(sealed.dev == original.dev && sealed.ino == original.ino && sealed.mode == 0o100444 && sealed.uid == 0 && sealed.gid == 0
                && sealed.links == 1 && sealed.size == bytes.len() as i64, "export-sealed-size-or-identity")?;
            self.originals[n].identity = Some(sealed); self.correspondence(n, true)?;
            self.persist(n, true)?; self.correspondence(n, true)?;
            check(self.close(n), "export-writer-close-unknown")?; self.clock()?;
            self.persist(support, false)?;
            check(self.named(n)? == sealed, "export-closed-leaf-correspondence")?;
            for (n, role) in [(root, AclRole::SystemRoot), (library, AclRole::SystemLibrary), (support, AclRole::SystemSupport)] {
                self.protected(n, true, None, role)?; self.correspondence(n, false)?;
            }
            Ok(())
        }
        fn finish(&mut self, mut result: Result<()>) -> Result<()> {
            // Close each original once in reverse order even after failure or
            // expiry. Preserve the first error; ambiguous close is absorbing.
            for n in (0..self.originals.len()).rev() {
                if !self.close(n) && result.is_ok() { result = Err("export-close-unknown"); }
            }
            let settled = self.originals.iter().all(|r| r.fd.is_none() && matches!(r.state, State::Closed | State::NoHandle));
            export_final(result, settled, self.unknown, self.end, Instant::now())
        }
    }
    fn export_result(result: &serde_json::Value, end: Instant) -> Result<()> {
        let mut export = Export::new(end);
        let operation = (|| {
            export.clock()?;
            let source = option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").ok_or("export-source-binding")?;
            let inventory = option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256").ok_or("export-inventory-binding")?;
            let manifest = option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or("export-manifest-binding")?;
            let name = export_name(EXPORT_KIND, source, inventory, manifest)?;
            let document = ExportDocument { schema_version:1, kind:EXPORT_KIND, source_commit:source,
                inventory_sha256:inventory, runtime_manifest_sha256:manifest,
                transport_state:"pending-original-export-finalization", result };
            let mut bytes = ExportBytes(Vec::with_capacity(EXPORT_LIMIT));
            serde_json::to_writer(&mut bytes, &document).map_err(|_| "export-json-bound")?;
            bytes.0.push(b'\n'); export.clock()?;
            export.write(&name, &bytes.0)
        })();
        export.finish(operation)
    }
    fn export_failure_diagnostic(reason: &'static str) {
        // Best effort, finite non-authoritative failure only. Never an operation
        // after a successful export finality/deadline decision.
        let _ = std::io::Write::write_all(&mut std::io::stderr().lock(),
            format!("MRK_MACOS_INSTALL_EXPORT_REFUSED={reason}\n").as_bytes());
    }
    fn transport_exit(original_exit: i32, exported: Result<()>) -> i32 {
        if original_exit != 0 { original_exit } else if exported.is_ok() { 0 }
        else if cfg!(feature = "macos-installed-installer-fixture") { 1 } else { 20 }
    }
    fn finish_transport(record: &serde_json::Value, original_exit: i32, end: Instant) -> i32 {
        let exported = if original_exit == 0 { export_result(record, end) } else { Err("original-installation-failed") };
        let exit = transport_exit(original_exit, exported);
        if exit != 0 {
            if original_exit == 0 { if let Err(reason) = exported { export_failure_diagnostic(reason); } }
            let marker = if EXPORT_KIND == "fixture" { "MRK_MACOS_INSTALL_FIXTURE_RESULT" } else { "MRK_MACOS_INSTALL_RESULT" };
            // Preserve failure diagnostics, but never depend on Installer
            // forwarding them and never perform stdout work after success.
            let _ = std::io::Write::write_all(&mut std::io::stdout().lock(), format!("{marker}={record}\n").as_bytes());
        }
        exit
    }
    impl Install {
        fn new() -> Self {
            Self { originals: Vec::new(), creations: Vec::new(), end: Instant::now()+Duration::from_secs(120), unknown:false,
                stage:None,stage_name:None,app:None,runtime:None,runtime_publication:"not-attempted",app_publication:"not-attempted",payload_verified:false,
                #[cfg(feature = "macos-installed-installer-fixture")]
                fixture: None }
        }
        fn clock(&self) -> Result<()> { check(Instant::now() < self.end && !self.unknown, "deadline-or-unknown") }
        fn fd(&self, n: usize) -> Result<&OwnedFd> { self.originals.get(n).and_then(|r| r.fd.as_ref()).ok_or("original-missing") }
        fn identity(&self, n: usize) -> Result<Identity> { self.originals.get(n).and_then(|r| r.identity).ok_or("identity-missing") }
        fn reserve(&mut self, parent: Option<usize>, name: &str, role: Role) -> Result<usize> {
            self.clock()?;
            check(self.originals.len() < 24576 && self.originals.iter().filter(|r| r.fd.is_some()).count() < 96, "original-bound")?;
            let n = self.originals.len(); self.originals.push(Original { fd: None, state: State::Reserved, role, parent, name: name.into(), identity: None }); Ok(n)
        }
        fn named(&self, parent: Option<usize>, name: &str) -> nix::Result<FileStat> {
            if let Some(parent) = parent {
                let fd = self.originals.get(parent).and_then(|r| r.fd.as_ref()).ok_or(Errno::EBADF)?;
                stat::fstatat(fd, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            } else { stat::lstat(Path::new("/")) }
        }
        fn adopt(&mut self, n: usize, result: nix::Result<OwnedFd>) -> Result<usize> {
            match result {
                Ok(fd) => { self.originals[n].fd = Some(fd); self.originals[n].state = State::Owned; Ok(n) }
                Err(_error) => {
                    self.originals[n].state = State::NoHandle;
                    #[cfg(feature = "macos-installed-installer-fixture")]
                    self.fixture_open_error(n, _error);
                    Err("open-refused")
                }
            }
        }
        fn open(&mut self, parent: Option<usize>, name: &str, directory: bool) -> Result<usize> {
            let n = self.reserve(parent, name, Role::Reader)?;
            let before = self.named(parent, name).map_err(|_| "named-refused")?;
            check(before.st_mode & SFlag::S_IFMT.bits() == if directory { SFlag::S_IFDIR.bits() } else { SFlag::S_IFREG.bits() }
                && (directory || before.st_nlink == 1), "input-type")?;
            self.originals[n].state = State::Acquiring;
            let opened = if let Some(parent) = parent { fcntl::openat(self.fd(parent)?, name, flags(directory), Mode::empty()) }
                else { fcntl::open(Path::new("/"), flags(directory), Mode::empty()) };
            self.adopt(n, opened)?;
            let id = Identity::of(&before); self.originals[n].identity = Some(id); self.check_name(n, true)?; Ok(n)
        }
        fn create_file(&mut self, parent: usize, name: &str, role: Role) -> Result<usize> {
            check(component(name), "file-component")?;
            let n = self.reserve(Some(parent), name, role)?; self.originals[n].state = State::Acquiring;
            let flags = OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
            let opened = fcntl::openat(self.fd(parent)?, name, flags, Mode::from_bits_truncate(0o600));
            self.adopt(n, opened)?;
            self.originals[n].identity = Some(Identity::of(&stat::fstat(self.fd(n)?).map_err(|_| "created-stat")?));
            self.protected(n, false, Some(0o600))?; self.check_name(n, true)?; Ok(n)
        }
        fn check_name(&self, n: usize, exact: bool) -> Result<()> {
            self.clock()?;
            let original = &self.originals[n]; let expected = self.identity(n)?;
            let actual = Identity::of(&stat::fstat(self.fd(n)?).map_err(|_| "original-stat")?);
            let named = Identity::of(&self.named(original.parent, &original.name).map_err(|_| "original-name")?);
            check(actual == named && if exact { actual == expected } else { expected.same_object(actual) }, "original-correspondence")
        }
        fn protected(&self, n: usize, directory: bool, mode: Option<u32>) -> Result<()> {
            self.protected_as(n, directory, mode, AclRole::Other)
        }
        fn protected_as(&self, n: usize, directory: bool, mode: Option<u32>, role: AclRole) -> Result<()> {
            let fd = self.fd(n)?; let s = stat::fstat(fd).map_err(|_| "stat-refused")?;
            let kind = if directory { SFlag::S_IFDIR } else { SFlag::S_IFREG };
            // Existing system ancestors may have a non-wheel root-owned group.
            // They must never be writable by that group, or chmod'ed to pass.
            check(s.st_mode & SFlag::S_IFMT.bits() == kind.bits() && s.st_uid == 0
                && s.st_mode & 0o7022 == 0 && (directory || s.st_nlink == 1)
                && mode.is_none_or(|mode| s.st_gid == 0 && u32::from(s.st_mode) & 0o7777 == mode), "protection-refused")?;
            let fs = statfs::fstatfs(fd).map_err(|_| "mount-refused")?;
            check(fs.filesystem_type_name() == "apfs" && fs.flags().contains(MntFlags::MNT_LOCAL)
                && !fs.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP), "mount-refused")?;
            native::empty_acl_observed(fd.as_fd()).map_err(|failure| {
                acl_diagnostic(role, &failure); "acl-refused"
            })
        }
        fn persist(&mut self, n: usize, file: bool) -> Result<()> {
            self.clock()?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            let point = self.fixture_persist_point(n, file);
            let actual = native::sync(self.fd(n)?.as_fd(), file);
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_persist_return(point, actual.is_ok(), actual.as_ref().err().and_then(std::io::Error::raw_os_error));
            actual.map_err(|_| "persistence-refused")?; // Actual native error wins.
            self.clock()?; // The SAME original synchronous call may return late.
            #[cfg(feature = "macos-installed-installer-fixture")]
            if self.fixture_report_persistence_failure(point) { return Err("fixture-reported-persistence-failure"); }
            Ok(())
        }
        fn directory(&mut self, parent: usize, name: &str, fresh: bool, mode: u32) -> Result<usize> {
            self.clock()?; check((component(name) || name == paths::APP_NAME) && self.creations.len() < 4096, "directory-bound")?;
            let permissions = Mode::from_bits(mode.try_into().map_err(|_| "created-directory-mode")?)
                .ok_or("created-directory-mode")?;
            let effect = self.creations.len();
            self.creations.push(Creation { parent, name: name.into(), state: "attempting", identity: None });
            match stat::mkdirat(self.fd(parent)?, name, Mode::from_bits_truncate(0o700)) {
                Ok(()) => self.creations[effect].state = "created",
                Err(Errno::EEXIST) if !fresh => self.creations[effect].state = "existing-not-modified",
                Err(_) => { self.creations[effect].state = "refused"; return Err("directory-occupied-or-refused"); }
            }
            let n = self.open(Some(parent), name, true)?;
            self.creations[effect].identity = Some(self.identity(n)?);
            if self.creations[effect].state == "created" {
                self.protected(n, true, None)?;
                let before = self.identity(n)?;
                check(created_directory_private(before), "created-directory-protection")?;
                // Darwin inherits the protected parent's group. Normalize only
                // our newly created private original, never an existing object.
                self.check_name(n, true)?; self.clock()?;
                unistd::fchown(self.fd(n)?, Some(unistd::Uid::from_raw(0)), Some(unistd::Gid::from_raw(0)))
                    .map_err(|_| "created-directory-owner")?;
                self.clock()?; // A failed/late original ownership call cannot reach chmod.
                stat::fchmod(self.fd(n)?, permissions).map_err(|_| "created-directory-mode")?; self.clock()?;
                let actual = Identity::of(&stat::fstat(self.fd(n)?).map_err(|_| "created-directory-stat")?); self.clock()?;
                let named = Identity::of(&self.named(Some(parent), name).map_err(|_| "created-directory-name")?); self.clock()?;
                check(created_directory_normalized(before, actual, named, mode), "created-directory-normalized-identity")?;
                self.originals[n].identity = Some(actual);
                self.creations[effect].identity = Some(actual);
            }
            self.protected(n, true, Some(mode))?; self.check_name(n, true)?;
            native::no_xattrs(self.fd(n)?.as_fd()).map_err(|_| "directory-attributes")?;
            self.persist(parent, false)?; Ok(n)
        }
        fn close(&mut self, n: usize) -> bool {
            let r = &mut self.originals[n];
            match r.state {
                State::Reserved => r.state = State::NoHandle,
                State::Owned => {
                    r.state = State::Closing;
                    let result = r.fd.take().map(unistd::close);
                    if !record_close_result(r, result) { self.unknown = true; }
                }
                State::Closed | State::NoHandle => {}, _ => self.unknown = true,
            }
            !self.unknown
        }
        fn forward_close(&mut self, n: usize, reason: &'static str) -> Result<()> {
            check(self.close(n), reason)?;
            self.clock() // Deadline refusal never rewrites a positive close.
        }
        fn read(&self, n: usize, size: u64, collect: bool) -> Result<(String, Vec<u8>)> {
            check(size <= 512*1024*1024 && (!collect || size <= 1024*1024)
                && self.identity(n)?.size >= 0 && self.identity(n)?.size as u64 == size, "read-bound")?;
            let mut bytes = Vec::new(); let mut hash = Sha256::new(); let mut count = 0u64; let mut block = [0u8;65536];
            loop {
                self.clock()?; let used = unistd::read(self.fd(n)?, &mut block).map_err(|_| "read-refused")?;
                if used == 0 { break; } count = count.checked_add(used as u64).ok_or("read-bound")?;
                check(count <= size, "size-changed")?; hash.update(&block[..used]); if collect { bytes.extend_from_slice(&block[..used]); }
            }
            check(count == size, "size-changed")?; self.check_name(n, true)?;
            Ok((hash.finalize().iter().map(|b| format!("{b:02x}")).collect(), bytes))
        }
        fn write_all(&self, n: usize, mut bytes: &[u8]) -> Result<()> {
            while !bytes.is_empty() { self.clock()?; let count = unistd::write(self.fd(n)?, bytes).map_err(|_| "write-refused")?;
                check(count != 0, "write-zero")?; bytes = &bytes[count..]; } Ok(())
        }
        fn seal_file(&mut self, n: usize, executable: bool) -> Result<()> {
            self.check_name(n, false)?;
            unistd::fchown(self.fd(n)?, Some(unistd::Uid::from_raw(0)), Some(unistd::Gid::from_raw(0))).map_err(|_| "file-owner")?;
            stat::fchmod(self.fd(n)?, Mode::from_bits_truncate(if executable { 0o555 } else { 0o444 })).map_err(|_| "file-mode")?;
            self.protected(n, false, Some(if executable { 0o555 } else { 0o444 }))?;
            native::no_xattrs(self.fd(n)?.as_fd()).map_err(|_| "file-attributes")?;
            self.persist(n, true)?; self.forward_close(n, "file-close-unknown")
        }
        fn payload_writers_settled(&self) -> bool { self.originals.iter().filter(|r| r.role == Role::PayloadWriter)
            .all(|r| r.fd.is_none() && matches!(r.state, State::Closed | State::NoHandle)) }
        fn original_summary(&self, n: Option<usize>) -> serde_json::Value { n.and_then(|n| self.originals[n].identity)
            .map_or(serde_json::Value::Null, |id| serde_json::json!({"device":id.dev,"inode":id.ino})) }
        fn creation_summary(&self) -> Vec<serde_json::Value> {
            self.creations.iter().filter(|c| c.name == "MobileReleaseKit" || c.name == "versions" || c.name == paths::RELEASE || c.name.starts_with(".install-"))
                .take(4).map(|c| serde_json::json!({"name":c.name,"state":c.state,"parentOriginal":c.parent,
                    "object":c.identity.map(|id| serde_json::json!({"device":id.dev,"inode":id.ino}))})).collect()
        }
        fn receipt(&mut self, phase: &str) -> Result<()> {
            let stage = self.stage.ok_or("stage-missing")?;
            let bytes = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"release":paths::RELEASE,"phase":phase,
                "runtimePublication":self.runtime_publication,"appPublication":self.app_publication,
                "payloadVerified":self.payload_verified,"payloadWritersSettled":self.payload_writers_settled(),
                "originalSettlement":"pending-final-closes","stage":self.original_summary(self.stage),
                "runtime":self.original_summary(self.runtime),"app":self.original_summary(self.app),"createdAncestors":self.creation_summary(),
                "inventorySha256":option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256")})).map_err(|_| "receipt-shape")?;
            let n = self.create_file(stage, &format!("{phase}.json"), Role::ReceiptWriter)?;
            self.write_all(n, &bytes)?; self.seal_file(n, false)?; self.persist(stage, false)
        }
        fn absent(&self, parent: usize, name: &str) -> Result<()> {
            match self.named(Some(parent), name) {
                Err(Errno::ENOENT) => Ok(()), Ok(_) => Err("destination-occupied"), Err(_) => Err("destination-observation-refused")
            }
        }
        fn roster(&self, n: usize) -> Result<BTreeMap<String, u64>> {
            let mut found = BTreeMap::new(); let mut block = [0u8;65536];
            loop {
                self.clock()?; let used = native::directory_block(self.fd(n)?.as_fd(), &mut block).map_err(|_| "directory-roster")?;
                if used == 0 { break; } let mut offset = 0;
                while offset < used {
                    check(used-offset >= 11,"directory-record")?;
                    let inode = u64::from_ne_bytes(block[offset..offset+8].try_into().map_err(|_| "directory-record")?);
                    let length = usize::from(u16::from_ne_bytes([block[offset+9],block[offset+10]]));
                    let next = offset.checked_add(11+length).filter(|n| *n <= used).ok_or("directory-record")?;
                    let name = std::str::from_utf8(&block[offset+11..next]).map_err(|_| "directory-name")?; offset = next;
                    if name == "." || name == ".." { continue; }
                    check(component(name) && inode != 0 && found.len() < 4096 && found.insert(name.to_owned(), inode).is_none(), "directory-duplicate-or-bound")?;
                }
            }
            Ok(found)
        }
        fn copy_file(&mut self, source_parent: usize, target_parent: usize, name: &str, inode: u64, item: &Entry) -> Result<()> {
            let source = self.open(Some(source_parent), name, false)?;
            self.protected(source, false, Some(if item.executable { 0o555 } else { 0o444 }))?;
            native::no_xattrs(self.fd(source)?.as_fd()).map_err(|_| "source-attributes")?;
            check(self.identity(source)?.ino == inode && self.identity(source)?.size >= 0 && self.identity(source)?.size as u64 == item.size, "source-identity-size")?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_before_payload_create(target_parent, name)?;
            let target = self.create_file(target_parent, name, Role::PayloadWriter)?;
            let mut block = [0u8;65536]; let mut count = 0u64; let mut digest = Sha256::new();
            loop {
                self.clock()?; let n = unistd::read(self.fd(source)?, &mut block).map_err(|_| "copy-read")?;
                if n == 0 { break; } count = count.checked_add(n as u64).ok_or("copy-bound")?;
                check(count <= item.size, "copy-size")?; digest.update(&block[..n]); self.write_all(target, &block[..n])?;
            }
            let actual: String = digest.finalize().iter().map(|b| format!("{b:02x}")).collect();
            check(count == item.size && actual == item.sha256, "copy-hash")?; self.check_name(source, true)?;
            self.seal_file(target, item.executable)?; self.forward_close(source, "source-close")?;
            let readback = self.open(Some(target_parent), name, false)?;
            check(self.identity(target)?.same_object(self.identity(readback)?), "copy-original-correspondence")?;
            self.protected(readback, false, Some(if item.executable { 0o555 } else { 0o444 }))?;
            native::no_xattrs(self.fd(readback)?.as_fd()).map_err(|_| "payload-attributes")?;
            check(self.read(readback, item.size, false)?.0 == item.sha256, "copy-readback")?;
            self.forward_close(readback, "readback-close")
        }
        fn copy_tree(&mut self, path: &str, source_parent: usize, target_parent: usize,
            files: &BTreeMap<String, &Entry>, directories: &BTreeSet<String>, depth: usize) -> Result<usize> {
            check(depth <= 16, "directory-depth")?;
            let name = path.rsplit('/').next().ok_or("directory-name")?;
            let source = self.open(Some(source_parent), name, true)?; self.protected(source, true, Some(0o555))?;
            native::no_xattrs(self.fd(source)?.as_fd()).map_err(|_| "source-attributes")?;
            let target = self.directory(target_parent, name, true, 0o700)?;
            let expected: BTreeSet<String> = files.keys().chain(directories.iter()).filter_map(|name|
                name.rsplit_once('/').filter(|(parent,_)| *parent == path).map(|(_,leaf)| leaf.to_owned())).collect();
            let input = self.roster(source)?;
            check(input.keys().cloned().collect::<BTreeSet<_>>() == expected, "source-exact-roster")?;
            for name in &expected {
                let child = format!("{path}/{name}");
                if let Some(item) = files.get(&child) { self.copy_file(source, target, name, input[name], item)?; }
                else {
                    let n = self.copy_tree(&child, source, target, files, directories, depth+1)?;
                    self.forward_close(n, "directory-close")?;
                }
            }
            check(self.roster(target)?.keys().cloned().collect::<BTreeSet<_>>() == expected, "staging-exact-roster")?;
            self.check_name(source, true)?; self.forward_close(source, "source-directory-close")?;
            self.seal_directory(target)?; Ok(target)
        }
        fn seal_directory(&mut self, target: usize) -> Result<()> {
            self.check_name(target, false)?;
            stat::fchmod(self.fd(target)?, Mode::from_bits_truncate(0o555)).map_err(|_| "directory-seal")?;
            self.protected(target, true, Some(0o555))?;
            native::no_xattrs(self.fd(target)?.as_fd()).map_err(|_| "directory-attributes")?;
            self.persist(target, false)?;
            self.originals[target].identity = Some(Identity::of(&stat::fstat(self.fd(target)?).map_err(|_| "sealed-directory-stat")?));
            self.check_name(target, true)
        }
        fn publish(&mut self, root: usize, stage: usize, source: &str, destination: usize, name: &str, runtime: bool) -> Result<()> {
            self.clock()?; self.check_name(root, true)?; self.check_name(stage, false)?; self.check_name(destination, false)?;
            if runtime { self.runtime_publication = "attempting"; } else { self.app_publication = "attempting"; }
            let publication = native::publish_directory(self.fd(stage)?.as_fd(), source, self.fd(destination)?.as_fd(), name);
            if let Err(error) = publication {
                // No retry/fallback and no deletion. EEXIST is the exclusive
                // primitive's documented refusal. Other failures stay Unknown.
                let state = if error.raw_os_error() == Some(Errno::EEXIST as i32) { "occupied-refused" } else { self.unknown = true; "unknown" };
                if runtime { self.runtime_publication = state; } else { self.app_publication = state; }
                return Err("exclusive-publication-refused-or-unknown");
            }
            if runtime { self.runtime_publication = "confirmed"; } else { self.app_publication = "confirmed"; }
            let original = self.identity(root)?;
            let current = Identity::of(&stat::fstat(self.fd(root)?).map_err(|_| "published-stat")?);
            check(original.same_object(current) && original.mode == current.mode && original.links == current.links, "published-original")?;
            self.originals[root].parent = Some(destination); self.originals[root].name = name.into(); self.originals[root].identity = Some(current);
            self.check_name(root, true)?; self.protected(root, true, Some(0o555))?; self.absent(stage, source)?;
            self.persist(stage, false)?; self.persist(destination, false)
        }
        fn input(&mut self, source: &str) -> Result<(usize, Inventory)> {
            check(unistd::getuid().is_root() && unistd::geteuid().is_root() && unistd::getgid().as_raw() == 0
                && unistd::getegid().as_raw() == 0, "administrator-required")?;
            native::platform().map_err(|_| "macos26-arm64-required")?;
            check(source.starts_with('/') && source.len() <= 4096 && source[1..].split('/').count() <= 32, "source-spelling")?;
            let mut input = self.open(None, "/", true)?;
            for name in source[1..].split('/') {
                check(component(name), "source-spelling")?; input = self.open(Some(input), name, true)?;
            }
            // Installer's fully extracted scripts resource is input DATA. Its
            // protected subtree has no remaining extraction/copy writer. Root
            // administrators/Installer itself are trusted, not concurrent foes.
            self.protected_as(input, true, Some(0o555), AclRole::InputDirectory)?;
            native::no_xattrs(self.fd(input)?.as_fd()).map_err(|_| "input-attributes")?;
            let expected_input: BTreeSet<String> = ["app", "runtime", "install-inventory.json"].into_iter().map(str::to_owned).collect();
            check(self.roster(input)?.keys().cloned().collect::<BTreeSet<_>>() == expected_input, "input-exact-roster")?;
            let manifest = self.open(Some(input), "install-inventory.json", false)?; self.protected_as(manifest, false, Some(0o444), AclRole::InputInventory)?;
            native::no_xattrs(self.fd(manifest)?.as_fd()).map_err(|_| "inventory-attributes")?;
            let size = u64::try_from(self.identity(manifest)?.size).map_err(|_| "inventory-size")?;
            let (digest, bytes) = self.read(manifest, size, true)?;
            check(Some(digest.as_str()) == option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256"), "inventory-anchor")?;
            let inventory: Inventory = serde_json::from_value(strict_json(&bytes).map_err(|_| "inventory-json")?).map_err(|_| "inventory-shape")?;
            check(inventory.schema_version == 1 && inventory.release == paths::RELEASE && !inventory.files.is_empty() && inventory.files.len() <= FILES
                && sha(&inventory.runtime_manifest_sha256)
                && Some(inventory.runtime_manifest_sha256.as_str()) == option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")
                && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(paths::PROTOCOL_SHA), "inventory-binding")?;
            self.forward_close(manifest, "inventory-close")?;
            Ok((input, inventory))
        }
        fn support_root(&mut self) -> Result<usize> {
            let root = self.open(None, "/", true)?; self.protected_as(root, true, None, AclRole::SystemRoot)?;
            let library = self.open(Some(root), "Library", true)?; self.protected_as(library, true, None, AclRole::SystemLibrary)?;
            let support = self.open(Some(library), "Application Support", true)?; self.protected_as(support, true, None, AclRole::SystemSupport)?;
            Ok(support)
        }
        fn install(&mut self, source: &str) -> Result<()> {
            let (input, inventory) = self.input(source)?;
            let mut files = BTreeMap::new(); let mut directories = BTreeSet::from(["app".to_owned(),"runtime".to_owned()]);
            let mut total = 0u64; let mut previous = "";
            for item in &inventory.files {
                check(item.path.is_ascii() && safe_payload_path(&item.path) && item.path.len() <= 1024 && item.path.split('/').count() <= 17
                    && (item.path.starts_with("app/Contents/") || item.path.starts_with("runtime/"))
                    && item.path.as_str() > previous && sha(&item.sha256), "inventory-path")?;
                check(item.executable == matches!(item.path.as_str(), "app/Contents/MacOS/mobile-release-kit-desktop" | "runtime/python/bin/python3"), "inventory-executable-scope")?;
                total = total.checked_add(item.size).ok_or("inventory-bound")?; check(total <= 512*1024*1024, "inventory-bound")?;
                previous = &item.path; files.insert(item.path.clone(), item);
                let mut path = item.path.as_str(); while let Some((parent,_)) = path.rsplit_once('/') { directories.insert(parent.to_owned()); path = parent; }
            }
            check(directories.len() <= 2048 && files.contains_key("app/Contents/MacOS/mobile-release-kit-desktop")
                && files.contains_key("app/Contents/Info.plist") && files.contains_key("runtime/python/bin/python3")
                && files.get("runtime/manifest.json").is_some_and(|f| f.sha256 == inventory.runtime_manifest_sha256), "inventory-required")?;
            let mut folded = BTreeSet::new(); for name in files.keys().chain(directories.iter()) { check(folded.insert(name.to_ascii_lowercase()), "inventory-collision")?; }
            let support = self.support_root()?;
            #[cfg(not(feature = "macos-installed-installer-fixture"))]
            let destination = self.directory(support, "MobileReleaseKit", false, 0o755)?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            let destination = self.fixture_destination(support)?;
            self.absent(destination, paths::APP_NAME)?;
            let versions = self.directory(destination, "versions", false, 0o755)?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_before_release_absence(versions)?;
            self.absent(versions, paths::RELEASE)?;
            let mut nonce = [0u8;16]; getrandom::fill(&mut nonce).map_err(|_| "stage-identity")?;
            let name = format!(".install-{}", nonce.iter().map(|b| format!("{b:02x}")).collect::<String>());
            self.stage_name = Some(name.clone()); // Reserve the effect identity before mkdir.
            let stage = self.directory(destination, &name, true, 0o700)?; self.stage = Some(stage);
            self.receipt("staging-created")?;
            let app = self.copy_tree("app", input, stage, &files, &directories, 0)?; self.app = Some(app);
            let runtime = self.copy_tree("runtime", input, stage, &files, &directories, 0)?; self.runtime = Some(runtime);
            self.check_name(input, true)?;
            check(self.payload_writers_settled() && !self.unknown, "writer-finality")?;
            self.payload_verified = true; self.persist(stage, false)?; self.receipt("prepared")?;
            // The fresh version parent is also exclusively created; failure
            // preserves an existing user's version and our unpublished staging.
            self.absent(destination, paths::APP_NAME)?;
            let release = self.directory(versions, paths::RELEASE, true, 0o755)?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_before_runtime_publication(release)?;
            self.publish(runtime, stage, "runtime", release, "runtime", true)?;
            self.receipt("runtime-publication-confirmed")?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_before_app_publication(destination)?;
            self.publish(app, stage, "app", destination, paths::APP_NAME, false)?;
            // Not an "installed/settled" receipt: remaining original descriptors
            // still have to close. Only final exit/output can report that fact.
            self.receipt("both-publications-confirmed")?; Ok(())
        }
        fn originals_settled(&self) -> bool {
            !self.unknown && self.originals.iter().all(|r| r.fd.is_none() && matches!(r.state, State::Closed | State::NoHandle))
        }
        fn settle_originals(&mut self) -> bool {
            // Actual original closes continue even after an error/expiry. No
            // rollback, repair, overwrite, retry or deletion anywhere.
            for n in (0..self.originals.len()).rev() { self.close(n); }
            self.originals_settled()
        }
        fn finish(&mut self, result: Result<()>) -> FinalResult {
            let settled = self.settle_originals();
            // Sample AFTER every final close; an earlier Ok is not timely finality.
            final_result(result, settled, self.unknown, self.runtime_publication, self.app_publication, self.end, Instant::now())
        }
        fn result_record(&self, result: &FinalResult) -> serde_json::Value {
            serde_json::json!({"schemaVersion":1,"state":result.state,"reason":result.reason,"release":paths::RELEASE,
                "runtimePublication":self.runtime_publication,"appPublication":self.app_publication,"staging":self.stage_name,
                "payloadVerified":self.payload_verified,"payloadWritersSettled":self.payload_writers_settled(),"originalsSettled":self.originals_settled(),
                "deadlineMetAfterFinalCloses":result.deadline_met,"createdAncestors":self.creation_summary(),"cleanup":"original-closes-only-no-deletion",
                "sourceCommit":option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT"),"inventorySha256":option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256"),
                "runtimeManifestSha256":option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")})
        }
    }
    #[cfg(not(feature = "macos-installed-installer-fixture"))]
    pub(super) fn run() -> i32 {
        let mut install = Install::new();
        let args: Vec<String> = std::env::args().collect();
        let result = if args.len() == 2 { install.install(&args[1]) } else { Err("fixed-scripts-input-required") };
        let final_result = install.finish(result);
        finish_transport(&install.result_record(&final_result), final_result.exit, install.end)
    }
    #[cfg(feature = "macos-installed-installer-fixture")]
    pub(super) fn run() -> i32 { fixture::run() }

    // Exactly seven separately named cases, inside the one approved standard
    // Installer fixture package. This module/entry/hooks do not exist in the
    // ordinary installer, and accept no scenario/destination/environment override.
    #[cfg(feature = "macos-installed-installer-fixture")]
    mod fixture {
        use super::*;
        const MARKER: &[u8] = b"MRK_MACOS_INSTALLER_FIXTURE_OCCUPANT\n";
        const BASE_PREFIX: &str = "MobileReleaseKit-InstallerFixture-";
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Case { OccupiedApp, OccupiedRelease, RuntimeCollision, StagingCollision, FirstOnly, BeforePersistence, AfterPersistence }
        const CASES: [Case; 7] = [Case::OccupiedApp, Case::OccupiedRelease, Case::RuntimeCollision, Case::StagingCollision,
            Case::FirstOnly, Case::BeforePersistence, Case::AfterPersistence];
        impl Case {
            fn name(self) -> &'static str { match self {
                Self::OccupiedApp => "occupied-app", Self::OccupiedRelease => "occupied-release",
                Self::RuntimeCollision => "runtime-publication-collision", Self::StagingCollision => "staging-file-collision",
                Self::FirstOnly => "first-publication-second-refusal", Self::BeforePersistence => "prepublication-persistence-report",
                Self::AfterPersistence => "postruntime-persistence-report" } }
            fn expected(self) -> (&'static str, &'static str, &'static str, &'static str, bool, i32) { match self {
                Self::OccupiedApp | Self::OccupiedRelease => ("destination-occupied","not-attempted","not-attempted","refused-staging-retained",false,1),
                Self::RuntimeCollision => ("exclusive-publication-refused-or-unknown","occupied-refused","not-attempted","refused-staging-retained",true,1),
                Self::StagingCollision => ("open-refused","not-attempted","not-attempted","refused-staging-retained",false,1),
                Self::FirstOnly => ("exclusive-publication-refused-or-unknown","confirmed","occupied-refused","partial-installation-retained",true,20),
                Self::BeforePersistence => ("fixture-reported-persistence-failure","not-attempted","not-attempted","refused-staging-retained",false,1),
                Self::AfterPersistence => ("fixture-reported-persistence-failure","confirmed","not-attempted","partial-installation-retained",true,20) } }
        }
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub(super) enum PersistPoint { BeforePublication, AfterRuntimeRename }
        impl PersistPoint { fn name(self) -> &'static str { match self {
            Self::BeforePublication => "payload-file-before-any-publication", Self::AfterRuntimeRename => "stage-directory-after-runtime-rename" } } }
        struct Persistence { point: PersistPoint, native_ok: bool, native_errno: Option<i32>, injected: bool }
        struct Witness { parent: usize, name: String, before: Identity, after: Option<Identity>, sha256: String, visible: Option<String> }
        pub(super) struct Context { base: String, case: Case, witness: Option<Witness>, absence_observed: bool,
            staging_errno: Option<i32>, persistence: Option<Persistence> }
        impl Context {
            fn new(base: &str, case: Case) -> Self { Self { base: base.into(), case, witness: None, absence_observed: false,
                staging_errno: None, persistence: None } }
        }
        fn marker_hash() -> String { Sha256::digest(MARKER).iter().map(|b| format!("{b:02x}")).collect() }
        fn witness_identity(id: Identity) -> serde_json::Value {
            serde_json::json!({"device":id.dev,"inode":id.ino,"mode":id.mode & 0o7777,"uid":id.uid,"gid":id.gid,
                "links":id.links,"size":id.size,"mtimeSeconds":id.mtime,"mtimeNanoseconds":id.mtime_ns,
                "ctimeSeconds":id.ctime,"ctimeNanoseconds":id.ctime_ns})
        }
        impl Install {
            fn fixture_case(&self) -> Result<Case> { self.fixture.as_ref().map(|f| f.case).ok_or("fixture-context-missing") }
            fn fixture_file_occupant(&mut self, parent: usize, name: &str, visible: Option<String>) -> Result<Witness> {
                let writer = self.create_file(parent, name, Role::ReceiptWriter)?;
                self.write_all(writer, MARKER)?; self.seal_file(writer, false)?;
                let reader = self.open(Some(parent), name, false)?;
                self.protected(reader, false, Some(0o444))?;
                native::no_xattrs(self.fd(reader)?.as_fd()).map_err(|_| "fixture-occupant-attributes")?;
                let before = self.identity(reader)?;
                check(self.identity(writer)?.same_object(before) && self.read(reader, MARKER.len() as u64, false)?.0 == marker_hash(), "fixture-occupant-before")?;
                self.forward_close(reader, "fixture-occupant-close")?;
                Ok(Witness { parent, name:name.into(), before, after:None, sha256:marker_hash(), visible })
            }
            fn fixture_directory_occupant(&mut self, parent: usize, name: &str, visible: String) -> Result<()> {
                let directory = self.directory(parent, name, true, 0o700)?;
                let witness = self.fixture_file_occupant(directory, "occupied.txt", Some(visible))?;
                self.seal_directory(directory)?;
                self.fixture.as_mut().ok_or("fixture-context-missing")?.witness = Some(witness); Ok(())
            }
            pub(super) fn fixture_destination(&mut self, support: usize) -> Result<usize> {
                let context = self.fixture.as_ref().ok_or("fixture-context-missing")?;
                let base = context.base.clone(); let case = context.case;
                let root = self.open(Some(support), &base, true)?; self.protected(root, true, Some(0o755))?;
                let destination = self.directory(root, case.name(), true, 0o755)?;
                if case == Case::OccupiedApp {
                    self.fixture_directory_occupant(destination, paths::APP_NAME, format!("{}/occupied.txt", paths::APP_NAME))?;
                }
                Ok(destination)
            }
            pub(super) fn fixture_before_release_absence(&mut self, versions: usize) -> Result<()> {
                if self.fixture_case()? == Case::OccupiedRelease {
                    let release = self.directory(versions, paths::RELEASE, true, 0o755)?;
                    self.fixture_directory_occupant(release, "runtime", format!("versions/{}/runtime/occupied.txt", paths::RELEASE))?;
                }
                Ok(())
            }
            pub(super) fn fixture_before_runtime_publication(&mut self, release: usize) -> Result<()> {
                if self.fixture_case()? == Case::RuntimeCollision {
                    self.absent(release, "runtime")?;
                    self.fixture.as_mut().ok_or("fixture-context-missing")?.absence_observed = true;
                    self.fixture_directory_occupant(release, "runtime", format!("versions/{}/runtime/occupied.txt", paths::RELEASE))?;
                }
                Ok(())
            }
            pub(super) fn fixture_before_app_publication(&mut self, destination: usize) -> Result<()> {
                if self.fixture_case()? == Case::FirstOnly {
                    self.absent(destination, paths::APP_NAME)?;
                    self.fixture.as_mut().ok_or("fixture-context-missing")?.absence_observed = true;
                    self.fixture_directory_occupant(destination, paths::APP_NAME, format!("{}/occupied.txt", paths::APP_NAME))?;
                }
                Ok(())
            }
            pub(super) fn fixture_before_payload_create(&mut self, parent: usize, name: &str) -> Result<()> {
                if self.fixture_case()? == Case::StagingCollision && self.fixture.as_ref().is_some_and(|f| f.witness.is_none()) {
                    self.absent(parent, name)?;
                    self.fixture.as_mut().ok_or("fixture-context-missing")?.absence_observed = true;
                    // Remains inside protected0700 staging. Nonroot observers
                    // never open/chmod that tree; this original verifies its own marker.
                    let witness = self.fixture_file_occupant(parent, name, None)?;
                    self.fixture.as_mut().ok_or("fixture-context-missing")?.witness = Some(witness);
                }
                Ok(())
            }
            pub(super) fn fixture_open_error(&mut self, index: usize, error: Errno) {
                let Some(context) = self.fixture.as_mut() else { return; };
                let Some(witness) = &context.witness else { return; };
                let original = &self.originals[index];
                if context.case == Case::StagingCollision && original.role == Role::PayloadWriter
                    && original.parent == Some(witness.parent) && original.name == witness.name {
                    if context.staging_errno.is_some() { self.unknown = true; }
                    else { context.staging_errno = Some(error as i32); }
                }
            }
            pub(super) fn fixture_persist_point(&self, index: usize, file: bool) -> Option<PersistPoint> {
                let context = self.fixture.as_ref()?;
                if context.persistence.is_some() { return None; }
                match context.case {
                    Case::BeforePersistence if file && self.originals[index].role == Role::PayloadWriter
                        && self.runtime_publication == "not-attempted" && self.app_publication == "not-attempted" => Some(PersistPoint::BeforePublication),
                    Case::AfterPersistence if !file && Some(index) == self.stage
                        && self.runtime_publication == "confirmed" && self.app_publication == "not-attempted" => Some(PersistPoint::AfterRuntimeRename),
                    _ => None,
                }
            }
            pub(super) fn fixture_persist_return(&mut self, point: Option<PersistPoint>, native_ok: bool, native_errno: Option<i32>) {
                let Some(point) = point else { return; };
                let Some(context) = self.fixture.as_mut() else { self.unknown = true; return; };
                if context.persistence.is_some() { self.unknown = true; return; }
                context.persistence = Some(Persistence { point, native_ok, native_errno, injected:false });
            }
            pub(super) fn fixture_report_persistence_failure(&mut self, point: Option<PersistPoint>) -> bool {
                let Some(point) = point else { return false; };
                let Some(observed) = self.fixture.as_mut().and_then(|f| f.persistence.as_mut()) else { self.unknown = true; return false; };
                if observed.point != point || !observed.native_ok || observed.injected { self.unknown = true; return false; }
                observed.injected = true; true // Explicitly reported policy fault AFTER actual native success, not OS EIO.
            }
            fn fixture_verify_witness(&mut self) -> Result<()> {
                let Some(witness) = self.fixture.as_ref().and_then(|f| f.witness.as_ref()) else { return Ok(()); };
                let parent = witness.parent; let name = witness.name.clone(); let before = witness.before; let expected = witness.sha256.clone();
                self.check_name(parent, false)?;
                let reader = self.open(Some(parent), &name, false)?;
                let after = self.identity(reader)?;
                check(after == before && self.read(reader, MARKER.len() as u64, false)?.0 == expected, "fixture-occupant-changed")?;
                self.protected(reader, false, Some(0o444))?;
                native::no_xattrs(self.fd(reader)?.as_fd()).map_err(|_| "fixture-occupant-attributes")?;
                self.forward_close(reader, "fixture-occupant-final-close")?;
                self.fixture.as_mut().and_then(|f| f.witness.as_mut()).ok_or("fixture-witness-missing")?.after = Some(after); Ok(())
            }
        }
        fn case_observation(install: &Install, case: Case, result: &FinalResult, proof: Result<()>) -> (serde_json::Value, bool) {
            let Some(context) = install.fixture.as_ref() else { return (serde_json::Value::Null, false); };
            let (reason,runtime,app,state,verified,exit) = case.expected();
            let occupant_ok = match case {
                Case::BeforePersistence | Case::AfterPersistence => context.witness.is_none(),
                _ => context.witness.as_ref().is_some_and(|w| w.after == Some(w.before) && w.sha256 == marker_hash()),
            };
            let native_collision_ok = match case {
                Case::StagingCollision => context.absence_observed && context.staging_errno == Some(Errno::EEXIST as i32),
                Case::RuntimeCollision | Case::FirstOnly => context.absence_observed && context.staging_errno.is_none(),
                _ => !context.absence_observed && context.staging_errno.is_none(),
            };
            let persistence_ok = match case {
                Case::BeforePersistence | Case::AfterPersistence => context.persistence.as_ref().is_some_and(|p|
                    p.native_ok && p.native_errno.is_none() && p.injected && p.point == if case == Case::BeforePersistence {
                        PersistPoint::BeforePublication } else { PersistPoint::AfterRuntimeRename }),
                _ => context.persistence.is_none(),
            };
            let passed = proof.is_ok() && occupant_ok && native_collision_ok && persistence_ok && !install.unknown
                && install.originals_settled() && result.deadline_met && result.reason == Some(reason) && result.state == state && result.exit == exit
                && install.runtime_publication == runtime && install.app_publication == app && install.payload_verified == verified
                && install.payload_writers_settled();
            let witness = context.witness.as_ref().map(|w| serde_json::json!({"visibleRelativePath":w.visible,"sha256":w.sha256,
                "before":witness_identity(w.before),"after":w.after.map(witness_identity),"verifiedByOriginalInstaller":w.after == Some(w.before)}));
            let persistence = context.persistence.as_ref().map(|p| serde_json::json!({"point":p.point.name(),"actualNativeSucceeded":p.native_ok,
                "actualNativeErrno":p.native_errno,"injectedReportedFailure":p.injected}));
            (serde_json::json!({"case":case.name(),"passed":passed,"proofError":proof.err(),"originalResult":install.result_record(result),"originalExit":result.exit,
                "occupant":witness,"absenceObservedBeforeCollision":context.absence_observed,"stagingOpenErrno":context.staging_errno,"persistence":persistence}), passed)
        }
        pub(super) fn run() -> i32 {
            let args: Vec<String> = std::env::args().collect();
            let source_commit = option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT");
            let source_bound = source_commit.is_some_and(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            let table = close_deadline_policy_table();
            let mut setup = Install::new(); let mut base = None;
            let setup_result = (|| {
                check(args.len() == 2 && source_bound && table, "fixture-fixed-source-input-or-policy-table")?;
                let _ = setup.input(&args[1])?; // SAME compiled input binding, before fixture effects.
                let support = setup.support_root()?;
                let mut nonce = [0u8;16]; getrandom::fill(&mut nonce).map_err(|_| "fixture-base-identity")?;
                let source = source_commit.ok_or("fixture-source-binding")?;
                let name = format!("{BASE_PREFIX}{}-{}", &source[..12], nonce.iter().map(|b| format!("{b:02x}")).collect::<String>());
                base = Some(name.clone()); // Retain identity before exclusive mkdir.
                let root = setup.directory(support, &name, true, 0o755)?;
                setup.persist(root, false)
            })();
            let setup_settled = setup.settle_originals(); let setup_timely = Instant::now() < setup.end;
            let mut passed = setup_result.is_ok() && setup_settled && setup_timely;
            let mut records = Vec::new(); let mut originals = vec![setup]; // Retain exact books even on unexpected Unknown.
            if passed {
                if let Some(base) = base.as_ref() {
                    for case in CASES {
                        let mut install = Install::new(); install.fixture = Some(Context::new(base, case));
                        let result = install.install(&args[1]);
                        // Do not start evidence reads after an unexpected failure,
                        // native Unknown or the original endpoint. Never retry installation.
                        let proof = if result == Err(case.expected().0) && !install.unknown && Instant::now() < install.end {
                            install.fixture_verify_witness()
                        } else { Err("unexpected-native-case-result") };
                        let outcome = install.finish(result);
                        let (record, observed) = case_observation(&install, case, &outcome, proof);
                        records.push(record); originals.push(install);
                        if !observed { passed = false; break; }
                    }
                } else { passed = false; }
            }
            passed = passed && records.len() == CASES.len() && originals.iter().all(Install::originals_settled);
            // A successful aggregate uses one export-only endpoint;
            // original setup/case clocks and books are never renewed.
            let export_end = Instant::now() + Duration::from_secs(10);
            let record = serde_json::json!({"schemaVersion":1,"sourceCommit":source_commit,
                "inventorySha256":option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256"),"runtimeManifestSha256":option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
                "fixtureBase":base,"setupError":setup_result.err(),"setupOriginalsSettled":setup_settled,"setupDeadlineMet":setup_timely,
                "inertCloseDeadlinePolicyTable":table,"fixedCasesComplete":records.len() == CASES.len(),"passed":passed,"cases":records,
                "genuineConcurrentRaceObserved":false,"nativeCloseFailureInjected":false,"applicationLaunched":false,"guiSaveQualified":false,
                "qualification":"native-installer-collisions-and-injected-policy-only"});
            finish_transport(&record, if passed { 0 } else { 1 }, export_end)
        }
    }

    // Inert policy table shared by the focused nonroot unit definition and the
    // fixed fixture package. No invalid descriptor, native close error or race
    // is manufactured; positive originals in the seven cases close once for real.
    #[cfg(any(test, feature = "macos-installed-installer-fixture"))]
    fn close_deadline_policy_table() -> bool {
        let before = Instant::now(); let end = before + Duration::from_secs(1);
        let mut closed = Original { fd: None, state: State::Closing, role: Role::Reader,
            parent: None, name: "inert-close-result".into(), identity: None };
        if !record_close_result(&mut closed, Some(Ok(()))) || closed.state != State::Closed { return false; }
        let timely = final_result(Ok(()), true, false, "confirmed", "confirmed", end, before);
        if (timely.state,timely.reason,timely.exit,timely.deadline_met) != ("installed",None,0,true) { return false; }
        for observed in [end, end + Duration::from_nanos(1)] {
            let late = final_result(Ok(()), true, false, "confirmed", "confirmed", end, observed);
            if (late.state,late.reason,late.exit,late.deadline_met) != ("partial-installation-retained",Some("deadline"),20,false)
                || closed.state != State::Closed { return false; }
            let earlier = final_result(Err("earlier-persistence-failure"), true, false, "confirmed", "occupied-refused", end, observed);
            if (earlier.state,earlier.reason,earlier.exit) != ("partial-installation-retained",Some("earlier-persistence-failure"),20) { return false; }
        }
        let mut unknown = Original { fd: None, state: State::Closing, role: Role::Reader,
            parent: None, name: "inert-close-error-result".into(), identity: None };
        if record_close_result(&mut unknown, Some(Err(Errno::EIO))) || unknown.state != State::Unknown { return false; }
        for observed in [before, end, end + Duration::from_nanos(1)] {
            let failed = final_result(Ok(()), false, true, "confirmed", "confirmed", end, observed);
            if (failed.state,failed.reason,failed.exit) != ("partial-installation-retained",Some("original-close-unknown"),20) { return false; }
            let earlier = final_result(Err("first-copy-refusal"), false, true, "not-attempted", "not-attempted", end, observed);
            if (earlier.state,earlier.reason,earlier.exit) != ("unknown-retained",Some("first-copy-refusal"),1) { return false; }
            if closed.state != State::Closed { return false; } // Unrelated positive close remains positive.
        }
        if record_close_result(&mut unknown, Some(Ok(()))) || unknown.state != State::Unknown { return false; }
        // DATA-only normalization of a fresh private inherited-group original.
        // Existing objects never enter this branch; no native ownership is mocked.
        let inherited = Identity { dev:1, ino:2, mode:0o040700, uid:0, gid:80, links:2, size:0,
            mtime:0, mtime_ns:0, ctime:0, ctime_ns:0 };
        let normalized = Identity { mode:0o040755, gid:0, ctime:1, ..inherited };
        if !created_directory_private(inherited) || !created_directory_normalized(inherited, normalized, normalized, 0o755) { return false; }
        for invalid in [Identity { uid:501, ..inherited }, Identity { mode:0o040770, ..inherited }, Identity { mode:0o100700, ..inherited }] {
            if created_directory_private(invalid) || created_directory_normalized(invalid, normalized, normalized, 0o755) { return false; }
        }
        for changed in [Identity { ino:3, ..normalized }, Identity { gid:80, ..normalized }, Identity { mode:0o040777, ..normalized }] {
            if created_directory_normalized(inherited, changed, changed, 0o755)
                || created_directory_normalized(inherited, normalized, changed, 0o755) { return false; }
        }
        // DATA-only export progress/finality cases. These are not native EIO,
        // ambiguous-close, filesystem-persistence or Installer observations.
        if export_write_progress(0, 9, Ok(4)) != Ok(4) || export_write_progress(4, 9, Ok(5)) != Ok(9)
            || export_write_progress(0, 9, Ok(0)).is_ok() || export_write_progress(4, 9, Ok(6)).is_ok()
            || export_write_progress(0, 9, Err(Errno::EIO)) != Err("export-write-refused") { return false; }
        if export_final(Ok(()), true, false, end, before) != Ok(())
            || export_final(Ok(()), true, false, end, end) != Err("export-deadline")
            || export_final(Ok(()), false, true, end, end) != Err("export-close-unknown")
            || export_final(Err("original-write-failure"), false, true, end, end) != Err("original-write-failure") { return false; }
        for original_exit in [1, 20] {
            if transport_exit(original_exit, Ok(())) != original_exit
                || transport_exit(original_exit, Err("export-close-unknown")) != original_exit { return false; }
        }
        if transport_exit(0, Ok(())) != 0 || transport_exit(0, Err("export-close-unknown")) == 0 { return false; }
        let source = "a".repeat(40); let digest = "b".repeat(64);
        if export_name("ordinary", &source, &digest, &digest).is_err() || export_name("fixture", &source, &digest, &digest).is_err()
            || export_name("other", &source, &digest, &digest).is_ok() || export_name("ordinary", "A", &digest, &digest).is_ok() { return false; }
        let mut bounded = ExportBytes(Vec::with_capacity(EXPORT_LIMIT));
        if std::io::Write::write_all(&mut bounded, &vec![b'x'; EXPORT_LIMIT - 1]).is_err()
            || std::io::Write::write_all(&mut bounded, b"x").is_ok() { return false; }
        closed.state == State::Closed && unknown.state == State::Unknown
    }
    #[cfg(test)]
    mod tests {
        #[test]
        fn original_final_deadline_vetoes_late_known_closes_without_erasing_first_error() {
            assert!(super::close_deadline_policy_table());
        }
    }
}
