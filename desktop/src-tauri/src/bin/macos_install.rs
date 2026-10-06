//! One-shot scripts-only standard Installer entry. Installer never lays files
//! into the final app/runtime destinations. This process alone owns all copy
//! writers; no Python, app, copy helper, daemon or general publisher runs as root.
#[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
fn main() { eprintln!("This Installer requires LP64 ARM64 or Intel macOS 26."); std::process::exit(1); }
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn main() { std::process::exit(installer::run()); }

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod installer {
    use std::{collections::{BTreeMap, BTreeSet}, os::fd::{AsFd, AsRawFd, OwnedFd}, path::Path, time::{Duration, Instant}};
    use nix::{errno::Errno, fcntl::{self, AtFlags, OFlag}, mount::MntFlags,
        sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};
    use sha2::{Digest, Sha256};
    use mobile_release_desktop::{macos_install_paths as paths,
        macos_install_record::{self as installation_record, Entry, Inventory}, runtime::safe_payload_path};
    use mrk_macos_installed_native as native;
    type Result<T> = std::result::Result<T, &'static str>;
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown, KernelExitRetained }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Role { Reader, PayloadWriter, MetadataWriter, ReceiptWriter, GateWriter, GateParticipant }
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
    // Separate fixed30B effect. InstallationMetadata remains exactly two files.
    // These are original returned-effect observations, not authority from JSON.
    struct MaintenanceGate {
        entered: bool, creation: &'static str, written: u64, sealed: bool, persisted: bool, parent_persisted: bool,
        parent: Option<usize>, writer: Option<usize>, participant: Option<usize>, verified: bool,
        lock_attempted: bool, exclusive_acquired: bool,
    }
    impl MaintenanceGate {
        fn new() -> Self { Self { entered:false,creation:"not-attempted",written:0,sealed:false,persisted:false,
            parent_persisted:false,parent:None,writer:None,participant:None,verified:false,lock_attempted:false,exclusive_acquired:false } }
    }
    struct Install {
        originals: Vec<Original>, creations: Vec<Creation>, end: Instant, unknown: bool,
        // `end` remains the original legacy-entry clock. The private B2 path
        // never uses it: both processes receive this same absolute deadline.
        worker_deadline: Option<worker::Deadline>, worker_stderr_is_gate: bool, worker_go_eof: bool,
        payload_written: u64, payload_write_calls: u64,
        stage: Option<usize>, stage_name: Option<String>, app: Option<usize>, runtime: Option<usize>,
        runtime_publication: &'static str, app_publication: &'static str, payload_verified: bool,
        metadata: installation_record::Progress,
        gate: MaintenanceGate,
        #[cfg(feature = "macos-installed-installer-fixture")]
        fixture: Option<fixture::Context>,
    }
    struct PreparedFresh {
        input: usize, inventory: Inventory, inventory_bytes: Vec<u8>,
        destination: usize, versions: usize,
    }
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
        final_result_after_deadline(result, originals_settled, unknown, runtime, app, observed_after_closes < end)
    }
    fn final_result_after_deadline(result: Result<()>, originals_settled: bool, unknown: bool,
        runtime: &str, app: &str, deadline_met: bool) -> FinalResult {
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
                worker_deadline:None,worker_stderr_is_gate:false,worker_go_eof:false,payload_written:0,payload_write_calls:0,
                stage:None,stage_name:None,app:None,runtime:None,runtime_publication:"not-attempted",app_publication:"not-attempted",payload_verified:false,
                metadata:installation_record::Progress::default(),
                gate:MaintenanceGate::new(),
                #[cfg(feature = "macos-installed-installer-fixture")]
                fixture: None }
        }
        fn clock(&self) -> Result<()> {
            check(!self.unknown, "deadline-or-unknown")?;
            match self.worker_deadline.as_ref() {
                Some(deadline) => deadline.check_work().map(|_| ()),
                None => check(Instant::now() < self.end, "deadline-or-unknown"),
            }
        }
        fn fd(&self, n: usize) -> Result<&OwnedFd> { self.originals.get(n).and_then(|r| r.fd.as_ref()).ok_or("original-missing") }
        fn identity(&self, n: usize) -> Result<Identity> { self.originals.get(n).and_then(|r| r.identity).ok_or("identity-missing") }
        fn reserve(&mut self, parent: Option<usize>, name: &str, role: Role) -> Result<usize> {
            self.clock()?;
            let extra = if self.worker_deadline.is_some() { worker::EXTRA_LIVE } else { 0 };
            check(self.originals.len() < 24576 && self.originals.iter().filter(|r| r.fd.is_some()).count() + extra < 96, "original-bound")?;
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
                Ok(fd) => {
                    self.originals[n].fd = Some(fd); self.originals[n].state = State::Owned;
                    if self.originals[n].role == Role::MetadataWriter { self.metadata.opened()?; }
                    if self.originals[n].role == Role::GateWriter { self.gate.creation = "created"; }
                    Ok(n)
                }
                Err(_error) => {
                    self.originals[n].state = State::NoHandle;
                    #[cfg(feature = "macos-installed-installer-fixture")]
                    self.fixture_open_error(n, _error);
                    Err("open-refused")
                }
            }
        }
        fn open(&mut self, parent: Option<usize>, name: &str, directory: bool) -> Result<usize> {
            self.open_role(parent, name, directory, Role::Reader)
        }
        fn open_role(&mut self, parent: Option<usize>, name: &str, directory: bool, role: Role) -> Result<usize> {
            let n = self.reserve(parent, name, role)?;
            if role == Role::GateParticipant { self.gate.participant = Some(n); }
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
            let n = self.reserve(Some(parent), name, role)?;
            if role == Role::MetadataWriter { self.metadata.attempted()?; }
            if role == Role::GateWriter { self.gate.writer = Some(n); self.gate.creation = "attempting"; }
            self.originals[n].state = State::Acquiring;
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
                // The private worker's fd2 is the read-only, process-lifetime
                // gate, not a log. Its bounded result reports the refusal.
                if !self.worker_stderr_is_gate { acl_diagnostic(role, &failure); } "acl-refused"
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
            if file && self.originals[n].role == Role::GateWriter { self.gate.persisted = true; }
            if !file && self.gate.parent == Some(n) && self.gate.writer.is_some() { self.gate.parent_persisted = true; }
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
        fn write_all(&mut self, n: usize, mut bytes: &[u8]) -> Result<()> {
            while !bytes.is_empty() {
                self.clock()?;
                let count = unistd::write(self.fd(n)?, bytes).map_err(|_| "write-refused")?;
                check(count != 0 && count <= bytes.len(), "write-zero-or-bound")?;
                if self.originals[n].role == Role::PayloadWriter {
                    // Record a returned write before any following deadline
                    // veto. This is not a promise about a future close.
                    self.payload_written = self.payload_written.checked_add(count as u64).ok_or("payload-write-count")?;
                    self.payload_write_calls = self.payload_write_calls.checked_add(1).ok_or("payload-write-count")?;
                }
                if self.originals[n].role == Role::MetadataWriter { self.metadata.wrote(count)?; }
                if self.originals[n].role == Role::GateWriter {
                    self.gate.written = self.gate.written.checked_add(count as u64).ok_or("gate-write-bound")?;
                    check(self.gate.written <= paths::MAINTENANCE_GATE_BYTES.len() as u64, "gate-write-bound")?;
                }
                bytes = &bytes[count..];
            }
            Ok(())
        }
        fn seal_file(&mut self, n: usize, executable: bool) -> Result<()> {
            self.check_name(n, false)?;
            unistd::fchown(self.fd(n)?, Some(unistd::Uid::from_raw(0)), Some(unistd::Gid::from_raw(0))).map_err(|_| "file-owner")?;
            stat::fchmod(self.fd(n)?, Mode::from_bits_truncate(if executable { 0o555 } else { 0o444 })).map_err(|_| "file-mode")?;
            if self.originals[n].role == Role::GateWriter { self.gate.sealed = true; }
            self.protected(n, false, Some(if executable { 0o555 } else { 0o444 }))?;
            native::no_xattrs(self.fd(n)?.as_fd()).map_err(|_| "file-attributes")?;
            self.persist(n, true)?; self.forward_close(n, "file-close-unknown")
        }
        fn payload_writers_settled(&self) -> bool { self.originals.iter().filter(|r| r.role == Role::PayloadWriter)
            .all(|r| r.fd.is_none() && matches!(r.state, State::Closed | State::NoHandle)) }
        fn metadata_writers_settled(&self) -> bool {
            self.originals.iter().filter(|r| r.role == Role::MetadataWriter)
                .all(|r| r.fd.is_none() && matches!(r.state, State::Closed | State::NoHandle))
        }
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
                "installationMetadata":self.metadata.snapshot(self.metadata_writers_settled()),
                "maintenanceGate":self.gate_record(),
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
                    // Native metadata can describe links, but no Installer
                    // source or publication roster permits them.
                    check(matches!(block[offset+8], nix::libc::DT_DIR | nix::libc::DT_REG), "directory-roster")?;
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
        fn input(&mut self, source: &str) -> Result<(usize, Inventory, Vec<u8>)> {
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
            let inventory = Inventory::parse(&bytes,
                option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or("inventory-binding")?)?;
            check(option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(paths::PROTOCOL_SHA), "inventory-binding")?;
            self.forward_close(manifest, "inventory-close")?;
            Ok((input, inventory, bytes))
        }
        fn support_root(&mut self) -> Result<usize> {
            let root = self.open(None, "/", true)?; self.protected_as(root, true, None, AclRole::SystemRoot)?;
            let library = self.open(Some(root), "Library", true)?; self.protected_as(library, true, None, AclRole::SystemLibrary)?;
            let support = self.open(Some(library), "Application Support", true)?; self.protected_as(support, true, None, AclRole::SystemSupport)?;
            Ok(support)
        }
        fn gate_protected(&self, reader: usize) -> Result<()> {
            self.protected(reader, false, Some(0o444))?;
            let s = stat::fstat(self.fd(reader)?).map_err(|_| "gate-stat")?;
            check(s.st_flags == 0 && s.st_size == paths::MAINTENANCE_GATE_BYTES.len() as i64, "gate-shape")?;
            native::no_xattrs(self.fd(reader)?.as_fd()).map_err(|_| "gate-attributes")?;
            self.check_name(reader, true)
        }
        fn maintenance_gate(&mut self, destination: usize) -> Result<()> {
            self.clock()?; check(!self.gate.entered, "gate-already-entered")?; self.gate.entered = true;
            self.gate.parent = Some(destination);
            match self.named(Some(destination), paths::MAINTENANCE_GATE_NAME) {
                Err(Errno::ENOENT) => {
                    let writer = self.create_file(destination, paths::MAINTENANCE_GATE_NAME, Role::GateWriter)?;
                    self.write_all(writer, paths::MAINTENANCE_GATE_BYTES)?;
                    self.seal_file(writer, false)?;
                    self.persist(destination, false)?;
                },
                Ok(_) => self.gate.creation = "existing-not-modified",
                Err(_) => return Err("gate-name-refused"),
            }
            // Existing occupants are never chmod'ed, truncated, repaired or
            // replaced. A lost original create is never retried as admission.
            let reader = self.open_role(Some(destination), paths::MAINTENANCE_GATE_NAME, false, Role::GateParticipant)?;
            if let Some(writer) = self.gate.writer {
                check(self.identity(writer)?.same_object(self.identity(reader)?), "gate-created-correspondence")?;
            }
            self.gate_protected(reader)?;
            let (_, body) = self.read(reader, paths::MAINTENANCE_GATE_BYTES.len() as u64, true)?;
            check(body == paths::MAINTENANCE_GATE_BYTES, "gate-content")?;
            self.gate.verified = true; self.clock()?;
            self.gate.lock_attempted = true;
            #[allow(deprecated)] // Borrow the original; Flock's Drop must not unlock it early.
            let locked = fcntl::flock(self.fd(reader)?.as_raw_fd(), fcntl::FlockArg::LockExclusiveNonblock);
            locked.map_err(|_| "gate-busy-or-refused")?;
            self.gate.exclusive_acquired = true;
            self.clock()?; self.gate_protected(reader)
        }
        fn gate_record(&self) -> serde_json::Value {
            let state = |index: Option<usize>| -> &'static str {
                match index.and_then(|i| self.originals.get(i)).map(|r| r.state) {
                    None => "not-attempted", Some(State::Reserved) => "reserved", Some(State::Acquiring) => "acquiring",
                    Some(State::Owned) => "owned", Some(State::NoHandle) => "no-handle", Some(State::Closing) => "closing",
                    Some(State::Closed) => "closed", Some(State::Unknown) => "unknown",
                    Some(State::KernelExitRetained) => "kernel-exit-retained",
                }
            };
            serde_json::json!({"schemaVersion":1,"entered":self.gate.entered,"creation":self.gate.creation,
                "fixedBytes":paths::MAINTENANCE_GATE_BYTES.len(),"writtenBytes":self.gate.written,
                "sealed":self.gate.sealed,"filePersisted":self.gate.persisted,"writer":state(self.gate.writer),
                "parentPersisted":self.gate.parent_persisted,
                "verified":self.gate.verified,"exclusiveAttempted":self.gate.lock_attempted,
                "exclusiveAcquired":self.gate.exclusive_acquired,"participant":state(self.gate.participant),
                "cleanup":"original-closes-only-permanent-gate-retained"})
        }
        fn install(&mut self, source: &str) -> Result<()> {
            let prepared = self.prepare_fresh(source)?;
            let mut nonce = [0u8;16]; getrandom::fill(&mut nonce).map_err(|_| "stage-identity")?;
            check(nonce.iter().any(|byte| *byte != 0), "stage-identity")?;
            let invocation = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
            self.install_prepared(prepared, &invocation)
        }
        fn prepare_fresh(&mut self, source: &str) -> Result<PreparedFresh> {
            let (input, inventory, inventory_bytes) = self.input(source)?;
            self.prepare_fresh_input(input, inventory, inventory_bytes)
        }
        fn prepare_fresh_input(&mut self, input: usize, inventory: Inventory, inventory_bytes: Vec<u8>) -> Result<PreparedFresh> {
            let indexed = inventory.index()?;
            check(indexed.payload_bytes.checked_add(inventory_bytes.len() as u64)
                .and_then(|n| n.checked_add(installation_record::RECORD_LIMIT as u64))
                .and_then(|n| n.checked_add(paths::MAINTENANCE_GATE_BYTES.len() as u64))
                .is_some_and(|n| n <= installation_record::PAYLOAD_LIMIT), "inventory-bound")?;
            check(indexed.files.len().checked_add(3).is_some_and(|n| n <= installation_record::FILE_LIMIT), "installed-file-bound")?;
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
            self.maintenance_gate(destination)?;
            Ok(PreparedFresh { input, inventory, inventory_bytes, destination, versions })
        }
        fn install_prepared(&mut self, prepared: PreparedFresh, invocation: &str) -> Result<()> {
            check(!self.worker_stderr_is_gate || self.worker_go_eof, "worker-go-eof-required")?;
            check(worker::invocation_valid(invocation), "stage-identity")?;
            let PreparedFresh { input, inventory, inventory_bytes, destination, versions } = prepared;
            let indexed = inventory.index()?;
            let files = indexed.files; let directories = indexed.directories;
            let name = format!(".install-{invocation}");
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
            self.record_metadata(destination, release, &name[9..], &inventory_bytes)?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_before_app_publication(destination)?;
            self.publish(app, stage, "app", destination, paths::APP_NAME, false)?;
            // Not an "installed/settled" receipt: remaining original descriptors
            // still have to close. Only final exit/output can report that fact.
            self.receipt("both-publications-confirmed")?; Ok(())
        }
        fn recorded_directory(&self, n: usize) -> Result<installation_record::DirectoryIdentity> {
            self.clock()?; self.check_name(n, false)?; self.protected(n, true, Some(0o755))?;
            native::no_xattrs(self.fd(n)?.as_fd()).map_err(|_| "installation-directory-attributes")?;
            let actual = stat::fstat(self.fd(n)?).map_err(|_| "installation-directory-stat")?;
            let original = &self.originals[n];
            let named = self.named(original.parent, &original.name).map_err(|_| "installation-directory-name")?;
            self.clock()?;
            check(Identity::of(&actual) == Identity::of(&named) && actual.st_flags == 0 && named.st_flags == 0,
                "installation-directory-correspondence")?;
            let data = installation_record::DirectoryIdentity { device:i64::from(actual.st_dev),inode:actual.st_ino,
                mode:u32::from(actual.st_mode),uid:actual.st_uid,gid:actual.st_gid,flags:actual.st_flags };
            check(data.valid(), "installation-directory-policy")?; Ok(data)
        }
        fn metadata_file(&mut self, release: usize, name: &str, bytes: &[u8]) -> Result<()> {
            let writer = self.create_file(release, name, Role::MetadataWriter)?;
            self.write_all(writer, bytes)?; self.seal_file(writer, false)?;
            let reader = self.open(Some(release), name, false)?;
            check(self.identity(writer)?.same_object(self.identity(reader)?), "installation-file-original")?;
            self.protected(reader, false, Some(0o444))?;
            native::no_xattrs(self.fd(reader)?.as_fd()).map_err(|_| "installation-file-attributes")?;
            check(stat::fstat(self.fd(reader)?).map_err(|_| "installation-file-flags")?.st_flags == 0,
                "installation-file-flags")?;
            let expected: String = format!("{:x}", Sha256::digest(bytes));
            check(self.read(reader, bytes.len() as u64, false)?.0 == expected, "installation-file-readback")?;
            check(stat::fstat(self.fd(reader)?).map_err(|_| "installation-file-flags")?.st_flags == 0,
                "installation-file-flags")?;
            self.forward_close(reader, "installation-readback-close")
        }
        fn record_metadata(&mut self, destination: usize, release: usize, instance: &str, inventory: &[u8]) -> Result<()> {
            #[cfg(not(feature = "macos-installed-installer-fixture"))]
            let kind = installation_record::Kind::Ordinary;
            #[cfg(feature = "macos-installed-installer-fixture")]
            let kind = installation_record::Kind::Fixture;
            let expected = installation_record::Expected { kind,
                source_commit:option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").ok_or("installation-source-binding")?,
                runtime_manifest:option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or("installation-runtime-binding")?,
                install_root:self.recorded_directory(destination)?,release_directory:self.recorded_directory(release)? };
            let record = installation_record::Record::encode(instance, inventory, &expected)?;
            self.clock()?;
            let total = (inventory.len() as u64).checked_add(record.len() as u64).ok_or("installation-metadata-plan")?;
            self.metadata.begin(total)?;
            self.metadata_file(release, installation_record::INVENTORY_NAME, inventory)?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_before_descriptor(release)?;
            self.metadata_file(release, installation_record::RECORD_NAME, &record)?;
            check(self.recorded_directory(destination)? == expected.install_root
                && self.recorded_directory(release)? == expected.release_directory, "installation-directory-changed")?;
            let expected_roster: BTreeSet<String> = ["runtime", installation_record::INVENTORY_NAME, installation_record::RECORD_NAME]
                .into_iter().map(str::to_owned).collect();
            check(self.roster(release)?.keys().cloned().collect::<BTreeSet<_>>() == expected_roster, "installation-release-roster")?;
            self.persist(release, false)?;
            self.check_name(release, false)?; self.clock()?;
            // Both metadata_file calls returned only after their real writer and
            // readback closes. The same original parent sync has just returned.
            // This does not describe outstanding ancestors or the whole install.
            self.metadata.record(self.metadata_writers_settled())
        }
        fn originals_settled(&self) -> bool {
            !self.unknown && self.originals.iter().all(|r| r.fd.is_none() && matches!(r.state, State::Closed | State::NoHandle))
        }
        fn settle_originals(&mut self) -> bool {
            // Actual original closes continue even after an error/expiry. No
            // rollback, repair, overwrite, retry or deletion anywhere.
            // The permanent participant is last. Its EX continues to exclude
            // ordinary entry until every other original capability is retired.
            let gate = self.gate.participant;
            for n in (0..self.originals.len()).rev() { if Some(n) != gate { self.close(n); } }
            if let Some(n) = gate {
                let others_settled = !self.unknown && self.originals.iter().enumerate()
                    .filter(|(index, _)| *index != n)
                    .all(|(_, r)| r.fd.is_none() && matches!(r.state, State::Closed | State::NoHandle));
                if others_settled { self.close(n); }
                else if let Some(fd) = self.originals[n].fd.take() {
                    // Do not release EX after an unknown earlier close. No new
                    // wrapper/Drop owner may retire it; only kernel process exit.
                    std::mem::forget(fd);
                    self.originals[n].state = State::KernelExitRetained;
                    self.unknown = true;
                }
            }
            self.originals_settled()
        }
        fn finish(&mut self, mut result: Result<()>) -> FinalResult {
            if result.is_ok() {
                result = match self.gate.participant {
                    Some(reader) if self.gate.verified && (self.gate.exclusive_acquired
                        || self.worker_stderr_is_gate && self.worker_go_eof && self.worker_deadline.is_some()
                            && !self.gate.lock_attempted) => self.gate_protected(reader),
                    _ => Err("gate-finality-missing"),
                };
            }
            let settled = self.settle_originals();
            // Sample AFTER every final close; an earlier Ok is not timely finality.
            match self.worker_deadline.as_ref() {
                Some(deadline) => {
                    let timely = deadline.check_total().is_ok();
                    final_result_after_deadline(result, settled, self.unknown || deadline.is_unknown(),
                        self.runtime_publication, self.app_publication, timely)
                }
                None => final_result(result, settled, self.unknown, self.runtime_publication, self.app_publication, self.end, Instant::now()),
            }
        }
        fn result_record(&self, result: &FinalResult) -> serde_json::Value {
            serde_json::json!({"schemaVersion":1,"state":result.state,"reason":result.reason,"release":paths::RELEASE,
                "runtimePublication":self.runtime_publication,"appPublication":self.app_publication,"staging":self.stage_name,
                "payloadVerified":self.payload_verified,"payloadWritersSettled":self.payload_writers_settled(),
                "installationMetadata":self.metadata.snapshot(self.metadata_writers_settled()),"originalsSettled":self.originals_settled(),
                "maintenanceGate":self.gate_record(),
                "deadlineMetAfterFinalCloses":result.deadline_met,"createdAncestors":self.creation_summary(),"cleanup":"original-closes-only-no-deletion",
                "sourceCommit":option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT"),"inventorySha256":option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256"),
                "runtimeManifestSha256":option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")})
        }
    }
    // B2 is deliberately private and is not selected by either run() below.
    // B3 must bind genuine package/context admission and the outer parent's
    // result/export finality before wiring this fixed role into an entry.
    #[allow(dead_code)]
    mod worker {
        use super::*;
        use std::{cell::Cell, mem::ManuallyDrop, os::fd::BorrowedFd,
            process::{Child, Command, ExitStatus, Stdio}};
        use nix::{poll::{poll, PollFd, PollFlags}, sys::uio::pread,
            time::{clock_gettime, ClockId}};
        use serde_json::{json, Map, Value};
        use mobile_release_desktop::protocol::strict_json;

        const SECOND: u64 = 1_000_000_000;
        const TOTAL: u64 = 120 * SECOND;
        const SETTLEMENT: u64 = 10 * SECOND;
        const ROLE: &str = "--mrk-installer-private-writer-v2";
        const INIT_LIMIT: usize = 16 * 1024;
        const CONTROL_LIMIT: usize = 2 * 1024;
        const RESULT_LIMIT: usize = 64 * 1024;
        const SELF_LIMIT: u64 = 64 * 1024 * 1024;
        // Three inherited standard descriptors and one transferred Command
        // gate reference are accounted independently of the existing book.
        pub(super) const EXTRA_LIVE: usize = 4;

        pub(super) fn invocation_valid(value: &str) -> bool {
            value.len() == 32 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && value.bytes().any(|b| b != b'0')
        }
        fn monotonic() -> Result<u64> {
            let value = clock_gettime(ClockId::CLOCK_MONOTONIC).map_err(|_| "worker-clock-call")?;
            let seconds = u64::try_from(value.tv_sec()).map_err(|_| "worker-clock-value")?;
            let nanos = u64::try_from(value.tv_nsec()).map_err(|_| "worker-clock-value")?;
            check(nanos < SECOND, "worker-clock-value")?;
            seconds.checked_mul(SECOND).and_then(|n| n.checked_add(nanos)).ok_or("worker-clock-value")
        }
        fn time_data(start: u64, end: u64, last: u64, now: u64, work: bool) -> Result<u64> {
            check(start.checked_add(TOTAL) == Some(end) && last >= start && now >= last, "worker-clock-regressed")?;
            let limit = if work { end.checked_sub(SETTLEMENT).ok_or("worker-clock-value")? } else { end };
            check(now < limit, if work { "worker-work-deadline" } else { "worker-final-deadline" })?;
            Ok(now)
        }
        pub(super) struct Deadline { start: u64, end: u64, last: Cell<u64>, unknown: Cell<bool> }
        impl Deadline {
            fn start() -> Result<Self> {
                let start = monotonic()?;
                let end = start.checked_add(TOTAL).ok_or("worker-clock-value")?;
                Ok(Self { start, end, last: Cell::new(start), unknown: Cell::new(false) })
            }
            fn inherit(end: u64) -> Result<Self> {
                let start = end.checked_sub(TOTAL).ok_or("worker-clock-value")?;
                let now = monotonic()?;
                time_data(start, end, start, now, true)?;
                Ok(Self { start, end, last: Cell::new(now), unknown: Cell::new(false) })
            }
            fn observe(&self, work: bool) -> Result<u64> {
                check(!self.unknown.get(), "worker-clock-unknown")?;
                let now = match monotonic() {
                    Ok(now) => now,
                    Err(error) => { self.unknown.set(true); return Err(error); }
                };
                if now < self.last.get() || now < self.start {
                    self.unknown.set(true); return Err("worker-clock-regressed");
                }
                // Expiry never rewrites the last real returned observation.
                self.last.set(now);
                time_data(self.start, self.end, now, now, work)
            }
            pub(super) fn check_work(&self) -> Result<u64> { self.observe(true) }
            pub(super) fn check_total(&self) -> Result<u64> { self.observe(false) }
            pub(super) fn is_unknown(&self) -> bool { self.unknown.get() }
            fn poll_ms(&self, work: bool) -> Result<u16> {
                let now = self.observe(work)?;
                let end = if work { self.end - SETTLEMENT } else { self.end };
                Ok(((end - now).div_ceil(1_000_000).min(20)) as u16)
            }
        }
        impl Install {
            fn with_worker_deadline(deadline: Deadline, stderr_is_gate: bool) -> Self {
                // Do not call new(): that would create a second 120s budget.
                // The legacy-only Instant field is an inert marker here and
                // cannot select a worker clock or its private result transport.
                Self { originals: Vec::new(), creations: Vec::new(), end: Instant::now(), unknown:false,
                    worker_deadline:Some(deadline),worker_stderr_is_gate:stderr_is_gate,worker_go_eof:false,
                    payload_written:0,payload_write_calls:0,
                    stage:None,stage_name:None,app:None,runtime:None,runtime_publication:"not-attempted",
                    app_publication:"not-attempted",payload_verified:false,
                    metadata:installation_record::Progress::default(),gate:MaintenanceGate::new(),
                    #[cfg(feature = "macos-installed-installer-fixture")]
                    fixture:None }
            }
            fn shared_deadline(&self) -> Result<&Deadline> { self.worker_deadline.as_ref().ok_or("worker-clock-missing") }
            fn worker_reserve(&mut self, name: &str) -> Result<usize> {
                check(self.originals.iter().filter(|r| r.fd.is_some()).count() + EXTRA_LIVE < 96, "worker-original-bound")?;
                self.reserve(None, name, Role::Reader)
            }
            fn control_original(&mut self, n: usize, fd: Option<OwnedFd>) -> Result<()> {
                // The slot was reserved before spawn/taking the returned pipe.
                // Install BOTH returned handles before any fallible validation,
                // so a rejected first pipe cannot hide the second in Child.
                self.originals[n].state = State::Acquiring;
                let Some(fd) = fd else {
                    self.originals[n].state = State::NoHandle;
                    return Err("worker-control-pipe-missing");
                };
                self.adopt(n, Ok(fd)).map(|_| ())
            }
            fn validate_control_original(&self, n: usize, write: bool) -> Result<()> {
                pipe_data(self.fd(n)?.as_fd(), write, self.shared_deadline()?)?;
                nonblocking(self.fd(n)?.as_fd(), self.shared_deadline()?)?;
                Ok(())
            }
        }
        fn identity_data(id: Identity) -> Value {
            json!({"device":id.dev,"inode":id.ino,"mode":id.mode,"uid":id.uid,"gid":id.gid,
                "links":id.links,"bytes":id.size,"mtime":id.mtime,"mtimeNanos":id.mtime_ns,
                "ctime":id.ctime,"ctimeNanos":id.ctime_ns})
        }
        fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>> {
            let map = value.as_object().ok_or("worker-frame-shape")?;
            check(map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)), "worker-frame-shape")?;
            Ok(map)
        }
        fn packet(bytes: &[u8], limit: usize) -> Result<Value> {
            check(!bytes.is_empty() && bytes.len() <= limit, "worker-frame-bound")?;
            strict_json(bytes).map_err(|_| "worker-frame-json")
        }
        fn frame(value: &Value, limit: usize) -> Result<Vec<u8>> {
            let bytes = serde_json::to_vec(value).map_err(|_| "worker-frame-json")?;
            check(!bytes.is_empty() && bytes.len() <= limit, "worker-frame-bound")?;
            let size = u32::try_from(bytes.len()).map_err(|_| "worker-frame-bound")?;
            let mut result = Vec::with_capacity(bytes.len() + 4);
            result.extend_from_slice(&size.to_be_bytes()); result.extend_from_slice(&bytes); Ok(result)
        }
        fn frame_size(prefix: &[u8], limit: usize) -> Result<usize> {
            check(prefix.len() == 4, "worker-frame-size")?;
            let size = u32::from_be_bytes(prefix.try_into().map_err(|_| "worker-frame-size")?) as usize;
            check(size > 0 && size <= limit, "worker-frame-bound")?; Ok(size)
        }
        fn pipe_data(fd: BorrowedFd<'_>, write: bool, deadline: &Deadline) -> Result<Value> {
            deadline.check_work()?;
            let value = stat::fstat(fd).map_err(|_| "worker-pipe-stat")?;
            deadline.check_work()?;
            let access = OFlag::from_bits_truncate(fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL).map_err(|_| "worker-pipe-flags")?);
            deadline.check_work()?;
            check(value.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFIFO.bits()
                && value.st_uid == 0 && value.st_gid == 0
                && access & OFlag::O_ACCMODE == if write { OFlag::O_WRONLY } else { OFlag::O_RDONLY },
                "worker-pipe-kind")?;
            Ok(json!({"device":i64::from(value.st_dev),"inode":value.st_ino,
                "mode":u32::from(value.st_mode),"uid":value.st_uid,"gid":value.st_gid}))
        }
        fn pipe_shape(value: &Value) -> Result<()> {
            object(value,&["device","inode","mode","uid","gid"])?;
            let mode = value["mode"].as_u64().and_then(|n| u32::try_from(n).ok()).ok_or("worker-pipe-shape")?;
            check(value["device"].as_i64().is_some() && value["inode"].as_u64().is_some()
                && value["uid"].as_u64() == Some(0) && value["gid"].as_u64() == Some(0)
                && mode & 0o170000 == 0o010000, "worker-pipe-shape")
        }
        fn nonblocking(fd: BorrowedFd<'_>, deadline: &Deadline) -> Result<()> {
            deadline.check_work()?;
            let before = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL).map_err(|_| "worker-pipe-flags")?;
            deadline.check_work()?;
            fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(OFlag::from_bits_truncate(before) | OFlag::O_NONBLOCK))
                .map_err(|_| "worker-pipe-flags")?;
            deadline.check_work()?;
            let after = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL).map_err(|_| "worker-pipe-flags")?;
            deadline.check_work()?;
            check(OFlag::from_bits_truncate(after).contains(OFlag::O_NONBLOCK), "worker-pipe-flags")
        }
        fn wait_ready(fd: BorrowedFd<'_>, write: bool, deadline: &Deadline, work: bool) -> Result<()> {
            let flags = if write { PollFlags::POLLOUT } else { PollFlags::POLLIN };
            let mut items = [PollFd::new(fd, flags)];
            loop {
                let timeout = deadline.poll_ms(work)?;
                match poll(&mut items, timeout) {
                    Ok(_) => { deadline.observe(work)?; return Ok(()); }
                    Err(Errno::EINTR) => (),
                    Err(_) => return Err("worker-pipe-poll"),
                }
            }
        }
        fn write_frame(fd: BorrowedFd<'_>, value: &Value, limit: usize, deadline: &Deadline, work: bool) -> Result<()> {
            let bytes = frame(value, limit)?; let mut used = 0;
            while used < bytes.len() {
                deadline.observe(work)?;
                match unistd::write(fd, &bytes[used..]) {
                    Ok(n) if n > 0 && n <= bytes.len() - used => { used += n; deadline.observe(work)?; }
                    Ok(_) => return Err("worker-pipe-write-bound"),
                    Err(Errno::EINTR) => (),
                    Err(Errno::EAGAIN) => wait_ready(fd, true, deadline, work)?,
                    Err(_) => return Err("worker-pipe-write"),
                }
            }
            Ok(())
        }
        fn read_exact(fd: BorrowedFd<'_>, bytes: &mut [u8], deadline: &Deadline) -> Result<()> {
            let mut used = 0;
            while used < bytes.len() {
                deadline.check_work()?;
                match unistd::read(fd, &mut bytes[used..]) {
                    Ok(0) => return Err("worker-command-early-eof"),
                    Ok(n) if n <= bytes.len() - used => { used += n; deadline.check_work()?; }
                    Ok(_) => return Err("worker-pipe-read-bound"),
                    Err(Errno::EINTR) => (),
                    Err(Errno::EAGAIN) => wait_ready(fd, false, deadline, true)?,
                    Err(_) => return Err("worker-pipe-read"),
                }
            }
            Ok(())
        }
        fn read_frame(fd: BorrowedFd<'_>, limit: usize, deadline: &Deadline) -> Result<(Value, Vec<u8>)> {
            let mut prefix = [0;4]; read_exact(fd, &mut prefix, deadline)?;
            let mut bytes = vec![0;frame_size(&prefix, limit)?]; read_exact(fd, &mut bytes, deadline)?;
            Ok((packet(&bytes, limit)?, bytes))
        }
        fn command_eof(fd: BorrowedFd<'_>, deadline: &Deadline) -> Result<()> {
            let mut extra = [0u8;1];
            loop {
                deadline.check_work()?;
                match unistd::read(fd, &mut extra) {
                    Ok(0) => { deadline.check_work()?; return Ok(()); }
                    Ok(_) => return Err("worker-command-trailing"),
                    Err(Errno::EINTR) => (),
                    Err(Errno::EAGAIN) => wait_ready(fd, false, deadline, true)?,
                    Err(_) => return Err("worker-pipe-read"),
                }
            }
        }
        fn hash(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
        fn target() -> &'static str {
            if cfg!(target_arch = "aarch64") { "aarch64-apple-darwin" } else { "x86_64-apple-darwin" }
        }
        fn compile_binding() -> Result<Value> {
            let source = option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").ok_or("worker-compile-binding")?;
            let inventory = option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256").ok_or("worker-compile-binding")?;
            let runtime = option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or("worker-compile-binding")?;
            check(source.len() == 40 && source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && sha(inventory) && sha(runtime)
                && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(paths::PROTOCOL_SHA), "worker-compile-binding")?;
            Ok(json!({"target":target(),"release":paths::RELEASE,"sourceCommit":source,
                "inventorySha256":inventory,"runtimeManifestSha256":runtime,"protocolSha256":paths::PROTOCOL_SHA}))
        }
        struct Source {
            script: usize, image: usize, input: usize, image_sha: String,
            executable: String, directory: String, source: String,
        }
        impl Install {
            fn worker_source(&mut self, source: &str, input: usize) -> Result<Source> {
                self.clock()?;
                let script = self.originals.get(input).and_then(|r| r.parent).ok_or("worker-script-parent")?;
                check(self.originals[input].name == "input", "worker-script-input")?;
                self.protected(script, true, Some(0o755))?;
                native::no_xattrs(self.fd(script)?.as_fd()).map_err(|_| "worker-script-attributes")?;
                let directory = source.strip_suffix("/input").filter(|s| !s.is_empty()).ok_or("worker-script-input")?;
                let executable = format!("{directory}/mrk-macos-install");
                let actual = std::env::current_exe().map_err(|_| "worker-self-image")?;
                check(actual.as_os_str() == std::ffi::OsStr::new(&executable), "worker-self-image")?;
                let image = self.open(Some(script), "mrk-macos-install", false)?;
                self.protected(image, false, Some(0o555))?;
                native::no_xattrs(self.fd(image)?.as_fd()).map_err(|_| "worker-self-attributes")?;
                let size = u64::try_from(self.identity(image)?.size).map_err(|_| "worker-self-bound")?;
                check(size > 0 && size <= SELF_LIMIT, "worker-self-bound")?;
                let image_sha = self.read(image, size, false)?.0;
                Ok(Source { script,image,input,image_sha,executable,directory:directory.into(),source:source.into() })
            }
            fn source_post(&self, source: &Source) -> Result<()> {
                self.clock()?;
                for index in [source.script,source.image,source.input] { self.check_name(index, true)?; }
                self.protected(source.script, true, Some(0o755))?;
                self.protected(source.image, false, Some(0o555))?;
                self.protected(source.input, true, Some(0o555))?;
                self.clock()
            }
        }
        fn source_data(book: &Install, source: &Source) -> Result<Value> {
            Ok(json!({"script":identity_data(book.identity(source.script)?),"image":identity_data(book.identity(source.image)?),
                "input":identity_data(book.identity(source.input)?),"imageSha256":source.image_sha}))
        }
        fn control(kind: &str, invocation: &str, init_sha: &str, end: u64, parent: u32, child: u32,
            worker_command: &Value, worker_result: &Value) -> Value {
            json!({"schemaVersion":2,"kind":kind,"invocation":invocation,"initSha256":init_sha,
                "endNanos":end,"parent":parent,"child":child,
                "writerCommandEndpoint":worker_command,"writerResultEndpoint":worker_result})
        }
        fn valid_control(value: &Value, expected: &Value) -> Result<()> {
            check(value == expected, "worker-control-binding")
        }
        // Compile-literal diagnostic vocabulary only. Unmapped downstream
        // errors stay a fixed refusal, never a raw path or returned private text.
        const FAILURE_LABELS: &[&str] = &[
            "aarch64-apple-darwin", "acl-refused", "administrator-required", "both-publications-confirmed",
            "copy-bound", "copy-hash", "copy-original-correspondence", "copy-read",
            "copy-readback", "copy-size", "created-directory-mode", "created-directory-name",
            "created-directory-normalized-identity", "created-directory-owner", "created-directory-protection", "created-directory-stat",
            "created-stat", "deadline", "deadline-or-unknown", "destination-observation-refused",
            "destination-occupied", "directory-attributes", "directory-bound", "directory-close",
            "directory-depth", "directory-duplicate-or-bound", "directory-name", "directory-occupied-or-refused",
            "directory-record", "directory-roster", "directory-seal", "earlier-persistence-failure",
            "exclusive-publication-refused-or-unknown", "existing-not-modified", "export-acl-refused", "export-attributes",
            "export-binding", "export-byte-bound", "export-close-unknown", "export-closed-leaf-correspondence",
            "export-deadline", "export-deadline-or-unknown", "export-identity-missing", "export-inventory-binding",
            "export-json-bound", "export-manifest-binding", "export-mode", "export-mount-refused",
            "export-name", "export-named-refused", "export-open-refused", "export-original-bound",
            "export-original-correspondence", "export-original-missing", "export-owner", "export-parent-type",
            "export-persistence-refused", "export-private-original", "export-protection-refused", "export-sealed-size-or-identity",
            "export-source-binding", "export-stat-refused", "export-write-progress", "export-write-refused",
            "export-writer-close-unknown", "export-written-size-or-identity", "file-attributes", "file-close-unknown",
            "file-component", "file-mode", "file-owner", "first-copy-refusal",
            "first-publication-second-refusal", "fixed-scripts-input-required", "fixture-base-identity", "fixture-context-missing",
            "fixture-fixed-source-input-or-policy-table", "fixture-occupant-attributes", "fixture-occupant-before", "fixture-occupant-changed",
            "fixture-occupant-close", "fixture-occupant-final-close", "fixture-reported-persistence-failure", "fixture-source-binding",
            "fixture-witness-missing", "gate-already-entered", "gate-attributes", "gate-busy-or-refused",
            "gate-content", "gate-created-correspondence", "gate-finality-missing", "gate-name-refused",
            "gate-shape", "gate-stat", "gate-write-bound", "identity-missing",
            "inert-close-error-result", "inert-close-result", "input-attributes", "input-directory",
            "input-exact-roster", "input-inventory", "input-type", "installation-directory-attributes",
            "installation-directory-changed", "installation-directory-correspondence", "installation-directory-name", "installation-directory-policy",
            "installation-directory-stat", "installation-file-attributes", "installation-file-flags", "installation-file-original",
            "installation-file-readback", "installation-metadata-plan", "installation-readback-close", "installation-release-roster",
            "installation-runtime-binding", "installation-source-binding", "installed-file-bound", "inventory-anchor",
            "inventory-attributes", "inventory-binding", "inventory-bound", "inventory-close",
            "inventory-size", "kernel-exit-retained", "macos-installed-installer-fixture", "macos26-arm64-required",
            "metadata-descriptor-collision", "mount-refused", "mrk-macos-install", "named-refused",
            "native-installer-collisions-and-injected-policy-only", "no-handle", "not-attempted", "occupied-app",
            "occupied-refused", "occupied-release", "open-refused", "original-bound",
            "original-close-unknown", "original-closes-only-no-deletion", "original-closes-only-permanent-gate-retained", "original-correspondence",
            "original-installation-failed", "original-missing", "original-name", "original-stat",
            "original-write-failure", "other-original-refusal", "other-protected-object", "partial-installation-retained",
            "payload-attributes", "payload-file-before-any-publication", "payload-write-count", "pending-final-closes",
            "pending-original-export-finalization", "persistence-refused", "postruntime-persistence-report", "pre-exit-writer-result",
            "prepublication-persistence-report", "private-writer-init", "protection-refused", "published-original",
            "published-stat", "read-bound", "read-refused", "readback-close",
            "receipt-shape", "refused-staging-retained", "runtime-publication-collision", "runtime-publication-confirmed",
            "sealed-directory-stat", "size-changed", "source-attributes", "source-close",
            "source-directory-close", "source-exact-roster", "source-identity-size", "source-spelling",
            "stage-directory-after-runtime-rename", "stage-identity", "stage-missing", "staging-created",
            "staging-exact-roster", "staging-file-collision", "stat-refused", "system-library",
            "system-root", "system-support", "unexpected-native-case-result", "unknown-retained",
            "worker-clock-call", "worker-clock-missing", "worker-clock-regressed", "worker-clock-unknown",
            "worker-clock-value", "worker-command-close-unknown", "worker-command-early-eof", "worker-command-original",
            "worker-command-trailing", "worker-compile-binding", "worker-control-binding", "worker-control-pipe-missing",
            "worker-exited-before-go", "worker-final-deadline", "worker-fixture-route-unavailable", "worker-frame-bound",
            "worker-frame-json", "worker-frame-shape", "worker-frame-size", "worker-gate-binding",
            "worker-gate-bytes", "worker-gate-duplicate", "worker-gate-flags", "worker-gate-original",
            "worker-gate-read", "worker-gate-readonly", "worker-gate-stat", "worker-go-eof-required",
            "worker-init-binding", "worker-invocation", "worker-joined-result-refused", "worker-original-bound",
            "worker-original-child", "worker-original-termination-refused", "worker-original-wait-unknown", "worker-parent",
            "worker-parent-changed", "worker-parent-exclusive-required", "worker-parent-once", "worker-pipe-flags",
            "worker-pipe-kind", "worker-pipe-poll", "worker-pipe-post", "worker-pipe-read",
            "worker-pipe-read-bound", "worker-pipe-shape", "worker-pipe-stat", "worker-pipe-write",
            "worker-pipe-write-bound", "worker-platform", "worker-result-binding", "worker-result-bound",
            "worker-result-close-unknown", "worker-result-incomplete", "worker-result-original", "worker-result-read",
            "worker-result-reason", "worker-result-shape", "worker-result-trailing", "worker-role",
            "worker-script-attributes", "worker-script-input", "worker-script-parent", "worker-self-attributes",
            "worker-self-bound", "worker-self-image", "worker-source-binding", "worker-source-original",
            "worker-source-post", "worker-spawn-unknown", "worker-work-deadline", "write-refused",
            "write-zero-or-bound", "writer-finality",
        ];
        fn closed_reason(label: &str) -> &'static str {
            FAILURE_LABELS.iter().copied().find(|known| *known == label).unwrap_or("other-original-refusal")
        }
        fn outcome_data(exit: i32, state: &str, originals: bool, payload: bool, verified: bool,
            runtime: &str, app: &str, timely: bool, unknown: bool, writes: u64, bytes: u64) -> bool {
            let published = runtime == "confirmed" || app == "confirmed";
            matches!(exit, 0 | 1 | 20)
                && matches!(state, "installed" | "partial-installation-retained" | "unknown-retained" | "refused-staging-retained")
                && bytes <= installation_record::PAYLOAD_LIMIT
                && (writes == 0) == (bytes == 0) && bytes >= writes
                && (!originals || payload)
                && (exit != 20 || state == "partial-installation-retained" && published)
                && (state != "partial-installation-retained" || exit == 20 && published)
                && (exit != 1 || !published && if unknown { state == "unknown-retained" } else { state == "refused-staging-retained" })
                && (exit != 0 || state == "installed" && originals && payload && verified && timely && !unknown
                    && runtime == "confirmed" && app == "confirmed" && writes > 0)
                && (state != "installed" || exit == 0)
        }
        struct PreExit {
            exit: i32, state: String, originals: bool, payload: bool, verified: bool,
            runtime: String, app: String, timely: bool, unknown: bool, writes: u64, bytes: u64,
            reason: Option<String>,
        }
        impl PreExit {
            fn from_original(book: &Install, result: &FinalResult) -> Self {
                Self { exit:result.exit,state:result.state.into(),originals:book.originals_settled(),
                    payload:book.payload_writers_settled(),verified:book.payload_verified,
                    runtime:book.runtime_publication.into(),app:book.app_publication.into(),
                    timely:result.deadline_met,unknown:book.unknown || book.worker_deadline.as_ref().is_some_and(Deadline::is_unknown),
                    writes:book.payload_write_calls,bytes:book.payload_written,
                    reason:result.reason.map(|label| closed_reason(label).to_owned()) }
            }
            fn data(&self, invocation: &str, init_sha: &str) -> Value {
                json!({"schemaVersion":2,"kind":"pre-exit-writer-result","invocation":invocation,"initSha256":init_sha,
                    "exitCode":self.exit,"state":self.state,"reason":self.reason,"originalsClosed":self.originals,"payloadClosed":self.payload,
                    "payloadVerified":self.verified,"runtimePublication":self.runtime,"appPublication":self.app,
                    "withinOriginalDeadline":self.timely,"unknown":self.unknown,
                    "payloadWriteCount":self.writes,"payloadWriteBytes":self.bytes,
                    "stdoutClosed":false,"inheritedGateClosed":false,"selfJoined":false})
            }
            fn parse(value: &Value, invocation: &str, init_sha: &str) -> Result<Self> {
                object(value, &["schemaVersion","kind","invocation","initSha256","exitCode","state","reason","originalsClosed",
                    "payloadClosed","payloadVerified","runtimePublication","appPublication","withinOriginalDeadline",
                    "unknown","payloadWriteCount","payloadWriteBytes","stdoutClosed","inheritedGateClosed","selfJoined"])?;
                check(value["schemaVersion"] == 2 && value["kind"] == "pre-exit-writer-result"
                    && value["invocation"] == invocation && value["initSha256"] == init_sha
                    && value["stdoutClosed"] == false && value["inheritedGateClosed"] == false && value["selfJoined"] == false,
                    "worker-result-binding")?;
                let boolean = |key: &str| value[key].as_bool().ok_or("worker-result-shape");
                let text = |key: &str| value[key].as_str().map(str::to_owned).ok_or("worker-result-shape");
                let result = Self { exit:value["exitCode"].as_i64().and_then(|n| i32::try_from(n).ok()).ok_or("worker-result-shape")?,
                    state:text("state")?,originals:boolean("originalsClosed")?,payload:boolean("payloadClosed")?,
                    verified:boolean("payloadVerified")?,runtime:text("runtimePublication")?,app:text("appPublication")?,
                    timely:boolean("withinOriginalDeadline")?,unknown:boolean("unknown")?,
                    writes:value["payloadWriteCount"].as_u64().ok_or("worker-result-shape")?,
                    bytes:value["payloadWriteBytes"].as_u64().ok_or("worker-result-shape")?,
                    reason:if value["reason"].is_null() { None } else { Some(text("reason")?) } };
                check(result.reason.as_deref().is_none_or(|label| closed_reason(label) == label)
                    && (result.exit != 0 || result.reason.is_none()), "worker-result-reason")?;
                for publication in [&result.runtime,&result.app] {
                    check(matches!(publication.as_str(), "not-attempted" | "attempting" | "confirmed" | "occupied-refused" | "unknown"),
                        "worker-result-shape")?;
                }
                check(outcome_data(result.exit,&result.state,result.originals,result.payload,result.verified,
                    &result.runtime,&result.app,result.timely,result.unknown,result.writes,result.bytes), "worker-result-shape")?;
                Ok(result)
            }
        }
        // Private native fact: deliberately not Serialize/Deserialize, not a
        // bool supplied by a package, and not the outer parent's finality.
        struct JoinedWriter { invocation: String, child: u32, outcome: PreExit, observed_at: u64 }
        impl JoinedWriter {
            fn successful(&self) -> bool { self.outcome.exit == 0 }
        }
        fn joined_data(frame: bool, eof: bool, output_close: bool, command_close: bool,
            wait: Option<i32>, reported: i32, source_post: bool, timely: bool, uncertainty: bool) -> bool {
            frame && eof && output_close && command_close && wait == Some(reported)
                && source_post && timely && !uncertainty
        }
        struct Parent {
            book: Install, entered: bool, command: Option<ManuallyDrop<Command>>, child: Option<Child>,
            source: Option<Source>, invocation: String, init_sha: String,
            command_original: Option<usize>, output_original: Option<usize>,
            command_close: bool, output_close: bool, output_eof: bool, output_admitted: bool,
            wait: Option<ExitStatus>, wait_unknown: bool, termination_attempted: bool,
            errors: Vec<&'static str>, command_gate_kernel_retained: bool, parent_book_settled: bool,
        }
        impl Parent {
            fn new() -> Result<Self> {
                // This sample precedes input/gate/file admission.
                Ok(Self { book:Install::with_worker_deadline(Deadline::start()?,false),entered:false,
                    command:None,child:None,source:None,invocation:String::new(),init_sha:String::new(),
                    command_original:None,output_original:None,command_close:false,output_close:false,output_eof:false,output_admitted:false,
                    wait:None,wait_unknown:false,termination_attempted:false,errors:Vec::new(),
                    command_gate_kernel_retained:false,parent_book_settled:false })
            }
            fn note(&mut self, error: &'static str) {
                if !self.errors.contains(&error) && self.errors.len() < 16 { self.errors.push(error); }
            }
            fn settlement_time(&mut self) -> bool {
                match self.book.shared_deadline().and_then(Deadline::check_total) {
                    Ok(_) => true,
                    Err(error) => { self.note(error); false }
                }
            }
            fn original_wait(&mut self) {
                if self.wait.is_some() || self.wait_unknown { return; }
                if !self.settlement_time() { return; }
                match self.child.as_mut().map(Child::try_wait) {
                    Some(Ok(Some(value))) => self.wait = Some(value),
                    Some(Ok(None)) => (),
                    _ => { self.wait_unknown = true; self.note("worker-original-wait-unknown"); }
                }
                // Retain a genuinely returned wait even if the next sample is
                // late; it is a known join, never a timely-success claim.
                self.settlement_time();
            }
            fn terminate_original(&mut self) {
                self.original_wait();
                if self.wait.is_some() || self.wait_unknown || self.termination_attempted { return; }
                if !self.settlement_time() { return; }
                // One retained, not-reaped Child; never find/adopt by PID.
                self.termination_attempted = true;
                if !matches!(self.child.as_mut().map(Child::kill), Some(Ok(()))) {
                    self.note("worker-original-termination-refused");
                }
                self.settlement_time();
            }
            fn close_command(&mut self) {
                if let Some(n) = self.command_original.take() {
                    self.command_close = self.book.close(n);
                    if !self.command_close { self.note("worker-command-close-unknown"); }
                    self.settlement_time();
                }
            }
            fn admit_and_go(&mut self, source: &str) -> Result<()> {
                check(!self.entered, "worker-parent-once")?; self.entered = true;
                // Existing fixture destinations have their own original owner.
                // B3 will integrate a reviewed fixed fixture route, not a path flag.
                check(!cfg!(feature = "macos-installed-installer-fixture"), "worker-fixture-route-unavailable")?;
                let (input,inventory,inventory_bytes) = self.book.input(source)?;
                let actual = self.book.worker_source(source,input)?;
                // Authenticate fixed self/source before even the parent's fixed
                // ancestor/gate creation; the child remains the sole payload writer.
                self.book.source_post(&actual)?;
                let _prepared = self.book.prepare_fresh_input(input,inventory,inventory_bytes)?;
                let gate = self.book.gate.participant.ok_or("worker-gate-original")?;
                check(self.book.gate.exclusive_acquired && self.book.gate.lock_attempted, "worker-parent-exclusive-required")?;
                self.book.gate_protected(gate)?; self.book.source_post(&actual)?;
                let mut nonce = [0u8;16]; getrandom::fill(&mut nonce).map_err(|_| "worker-invocation")?;
                self.invocation = nonce.iter().map(|b| format!("{b:02x}")).collect();
                check(invocation_valid(&self.invocation), "worker-invocation")?;
                let end = self.book.shared_deadline()?.end;
                // Include temporary ends of two pipes and the standard spawn
                // error channel as headroom, not extra permitted live book FDs.
                check(self.book.originals.iter().filter(|r| r.fd.is_some()).count() + EXTRA_LIVE + 2 + 6 < 96
                    && self.book.originals.len() + 2 < 24576, "worker-original-bound")?;
                let command_n = self.book.worker_reserve("<private-command>")?;
                self.command_original = Some(command_n);
                let output_n = self.book.worker_reserve("<private-result>")?;
                self.output_original = Some(output_n);
                // Each source/gate original remains held before this transfer.
                let duplicate = self.book.fd(gate)?.as_fd().try_clone_to_owned().map_err(|_| "worker-gate-duplicate")?;
                let mut command = Command::new(&actual.executable);
                command.arg(ROLE).arg(end.to_string()).arg(&self.invocation)
                    .current_dir(&actual.directory).env_clear()
                    .env("LANG","C").env("LC_ALL","C").env("TZ","UTC")
                    .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::from(duplicate));
                self.command = Some(ManuallyDrop::new(command));
                self.command_gate_kernel_retained = true;
                self.source = Some(actual);
                self.book.shared_deadline()?.check_work()?;
                // Original call is made once. On Err there is no adoption/retry
                // and no assertion that an unobserved child never existed.
                let child = self.command.as_mut().ok_or("worker-command-original")?.spawn();
                match child {
                    Ok(child) => self.child = Some(child),
                    Err(_) => { self.wait_unknown = true; return Err("worker-spawn-unknown"); }
                }
                let input = self.child.as_mut().and_then(|c| c.stdin.take()).map(OwnedFd::from);
                let output = self.child.as_mut().and_then(|c| c.stdout.take()).map(OwnedFd::from);
                let input_owned = self.book.control_original(command_n, input);
                let output_owned = self.book.control_original(output_n, output);
                input_owned?; output_owned?;
                self.book.validate_control_original(command_n, true)?;
                self.book.validate_control_original(output_n, false)?;
                self.output_admitted = true;
                let parent = std::process::id();
                let child = self.child.as_ref().ok_or("worker-original-child")?.id();
                let actual = self.source.as_ref().ok_or("worker-source-original")?;
                let command_before = pipe_data(self.book.fd(command_n)?.as_fd(),true,self.book.shared_deadline()?)?;
                let result_before = pipe_data(self.book.fd(output_n)?.as_fd(),false,self.book.shared_deadline()?)?;
                let init = json!({"schemaVersion":2,"kind":"private-writer-init","invocation":self.invocation,"endNanos":end,
                    "parent":parent,"child":child,"compile":compile_binding()?,"source":source_data(&self.book,actual)?,
                    "gate":identity_data(self.book.identity(gate)?),
                    "parentCommandEndpoint":command_before,"parentResultEndpoint":result_before});
                let bytes = serde_json::to_vec(&init).map_err(|_| "worker-frame-json")?;
                self.init_sha = hash(&bytes);
                write_frame(self.book.fd(command_n)?.as_fd(), &init, INIT_LIMIT, self.book.shared_deadline()?, true)?;
                let ready = read_frame(self.book.fd(output_n)?.as_fd(), CONTROL_LIMIT, self.book.shared_deadline()?)?.0;
                let worker_command = &ready["writerCommandEndpoint"];
                let worker_result = &ready["writerResultEndpoint"];
                pipe_shape(worker_command)?; pipe_shape(worker_result)?;
                valid_control(&ready,&control("ready",&self.invocation,&self.init_sha,end,parent,child,worker_command,worker_result))?;
                self.book.source_post(actual)?; self.book.gate_protected(gate)?;
                // XNU gives opposite pipe endpoints different inode facts.
                // Recheck each OWN original; remote endpoint numbers confer no authority.
                check(command_before == pipe_data(self.book.fd(command_n)?.as_fd(),true,self.book.shared_deadline()?)?
                    && result_before == pipe_data(self.book.fd(output_n)?.as_fd(),false,self.book.shared_deadline()?)?,
                    "worker-pipe-post")?;
                self.original_wait(); check(self.wait.is_none() && !self.wait_unknown, "worker-exited-before-go")?;
                write_frame(self.book.fd(command_n)?.as_fd(),&control("go",&self.invocation,&self.init_sha,end,parent,child,worker_command,worker_result),
                    CONTROL_LIMIT,self.book.shared_deadline()?,true)?;
                // Actual EOF is part of the child's pre-mutation barrier.
                self.close_command();
                check(self.command_close, "worker-command-close-unknown")
            }
            fn collect(&mut self) -> Result<Vec<u8>> {
                let mut bytes = Vec::new(); let mut length = None; let mut readable = self.output_admitted;
                loop {
                    if let Err(error) = self.book.shared_deadline().and_then(Deadline::check_total) {
                        self.note(error); break;
                    }
                    if let Err(error) = self.book.shared_deadline().and_then(Deadline::check_work) { self.note(error); }
                    if !self.errors.is_empty() {
                        self.close_command(); self.terminate_original();
                    }
                    if readable {
                        let mut block = [0u8;4096];
                        let read = self.output_original.ok_or("worker-result-original")
                            .and_then(|n| self.book.fd(n)).map(|fd| unistd::read(fd,&mut block));
                        match read {
                            Err(error) => { self.note(error); readable = false; }
                            Ok(Ok(0)) => { self.output_eof = true; readable = false; }
                            Ok(Ok(used)) => {
                                if bytes.len().checked_add(used).is_none_or(|n| n > RESULT_LIMIT + 4) {
                                    self.note("worker-result-bound"); readable = false;
                                } else {
                                    bytes.extend_from_slice(&block[..used]);
                                    if length.is_none() && bytes.len() >= 4 {
                                        match frame_size(&bytes[..4],RESULT_LIMIT) {
                                            Ok(size) => length = Some(size + 4),
                                            Err(error) => { self.note(error); readable = false; }
                                        }
                                    }
                                    if length.is_some_and(|size| bytes.len() > size) {
                                        self.note("worker-result-trailing"); readable = false;
                                    }
                                }
                            }
                            Ok(Err(Errno::EINTR | Errno::EAGAIN)) => (),
                            Ok(Err(_)) => { self.note("worker-result-read"); readable = false; }
                        }
                        self.settlement_time();
                    }
                    if !readable {
                        if let Some(n) = self.output_original.take() {
                            self.output_close = self.book.close(n);
                            if !self.output_close { self.note("worker-result-close-unknown"); }
                        }
                    }
                    self.original_wait();
                    if self.wait_unknown || self.wait.is_some() && !readable { break; }
                    let timeout = match self.book.shared_deadline().and_then(|clock| clock.poll_ms(false)) {
                        Ok(timeout) => timeout, Err(error) => { self.note(error); break; }
                    };
                    let mut descriptors = if let Some(n) = self.output_original {
                        match self.book.fd(n) {
                            Ok(fd) => vec![PollFd::new(fd.as_fd(), PollFlags::POLLIN)],
                            Err(_) => Vec::new(),
                        }
                    } else { Vec::new() };
                    let polled = poll(&mut descriptors,timeout);
                    drop(descriptors); // No borrowed book FD across mutable result recording.
                    match polled {
                        Ok(_) | Err(Errno::EINTR) => (),
                        Err(_) => self.note("worker-pipe-poll"),
                    }
                    self.settlement_time();
                }
                // No new grace period. These are original consuming closes,
                // never a claim of timely completion after the endpoint.
                self.close_command();
                if let Some(n) = self.output_original.take() {
                    self.output_close = self.book.close(n);
                    if !self.output_close { self.note("worker-result-close-unknown"); }
                }
                check(self.output_eof && length == Some(bytes.len()), "worker-result-incomplete")?;
                Ok(bytes[4..].to_vec())
            }
            fn run_fresh(&mut self, source: &str) -> Result<JoinedWriter> {
                check(!self.entered, "worker-parent-once")?;
                if let Err(error) = self.admit_and_go(source) { self.note(error); }
                if self.child.is_none() { return Err(self.errors.first().copied().unwrap_or("worker-original-child")); }
                let bytes = match self.collect() {
                    Ok(bytes) => bytes, Err(error) => { self.note(error); return Err(error); }
                };
                let value = packet(&bytes,RESULT_LIMIT)?;
                let outcome = PreExit::parse(&value,&self.invocation,&self.init_sha)?;
                let source_post = self.source.as_ref().is_some_and(|source| self.book.source_post(source).is_ok());
                if !source_post { self.note("worker-source-post"); }
                let observed_at = self.book.shared_deadline()?.check_total()?;
                let status = self.wait.as_ref().and_then(ExitStatus::code);
                check(joined_data(true,self.output_eof,self.output_close,self.command_close,status,outcome.exit,
                    source_post,true,self.wait_unknown || !self.errors.is_empty()), "worker-joined-result-refused")?;
                let child = self.child.as_ref().ok_or("worker-original-child")?.id();
                Ok(JoinedWriter { invocation:self.invocation.clone(),child,outcome,observed_at })
            }
            fn settle_parent_originals(&mut self) -> bool {
                // B3 invokes this only after its parent's evidence writers.
                // The one-use Command/config OFD remains KernelExitRetained:
                // its Drop would not provide an errno-observed close receipt.
                self.close_command();
                if let Some(n) = self.output_original.take() {
                    if !self.book.close(n) { self.note("worker-result-close-unknown"); }
                }
                if self.wait_unknown || self.child.is_some() && self.wait.is_none() { self.book.unknown = true; }
                self.parent_book_settled = self.book.settle_originals();
                self.settlement_time();
                self.parent_book_settled
            }
        }
        fn gate_bytes(fd: BorrowedFd<'_>, deadline: &Deadline) -> Result<()> {
            let mut bytes = [0u8;31]; let mut used = 0;
            loop {
                deadline.check_work()?;
                match pread(fd,&mut bytes[used..],used as i64) {
                    Ok(0) => break,
                    Ok(n) if n <= bytes.len() - used => {
                        used += n;
                        check(used <= paths::MAINTENANCE_GATE_BYTES.len(), "worker-gate-bytes")?;
                        deadline.check_work()?;
                    }
                    Ok(_) => return Err("worker-gate-bytes"),
                    Err(Errno::EINTR) => (),
                    Err(_) => return Err("worker-gate-read"),
                }
            }
            deadline.check_work()?;
            check(&bytes[..used] == paths::MAINTENANCE_GATE_BYTES, "worker-gate-bytes")
        }
        fn worker_input_path() -> Result<String> {
            let executable = std::env::current_exe().map_err(|_| "worker-self-image")?;
            check(executable.file_name() == Some(std::ffi::OsStr::new("mrk-macos-install")), "worker-self-image")?;
            let directory = executable.parent().and_then(Path::to_str).ok_or("worker-script-parent")?;
            Ok(format!("{directory}/input"))
        }
        fn prepare_worker(book: &mut Install, init: &Value, gate_fd: BorrowedFd<'_>, invocation: &str, end: u64) -> Result<PreparedFresh> {
            object(init,&["schemaVersion","kind","invocation","endNanos","parent","child","compile","source","gate","parentCommandEndpoint","parentResultEndpoint"])?;
            check(init["schemaVersion"] == 2 && init["kind"] == "private-writer-init" && init["invocation"] == invocation
                && init["endNanos"].as_u64() == Some(end)
                && init["parent"].as_u64() == Some(unistd::getppid().as_raw() as u64)
                && init["parent"].as_u64().is_some_and(|p| p > 1)
                && init["child"].as_u64() == Some(u64::from(std::process::id()))
                && init["compile"] == compile_binding()?, "worker-init-binding")?;
            // Only observations of the parent's own endpoints. Its opposite
            // ends need not share inode numbers with our inherited originals.
            pipe_shape(&init["parentCommandEndpoint"])?; pipe_shape(&init["parentResultEndpoint"])?;
            let source_path = worker_input_path()?;
            let (input,inventory,inventory_bytes) = book.input(&source_path)?;
            let index = inventory.index()?;
            check(index.payload_bytes.checked_add(inventory_bytes.len() as u64)
                .and_then(|n| n.checked_add(installation_record::RECORD_LIMIT as u64))
                .and_then(|n| n.checked_add(paths::MAINTENANCE_GATE_BYTES.len() as u64))
                .is_some_and(|n| n <= installation_record::PAYLOAD_LIMIT)
                && index.files.len().checked_add(3).is_some_and(|n| n <= installation_record::FILE_LIMIT), "inventory-bound")?;
            let source = book.worker_source(&source_path,input)?;
            check(init["source"] == source_data(book,&source)?, "worker-source-binding")?;
            let support = book.support_root()?;
            let destination = book.open(Some(support),"MobileReleaseKit",true)?;
            book.protected(destination,true,Some(0o755))?;
            let versions = book.open(Some(destination),"versions",true)?;
            book.protected(versions,true,Some(0o755))?;
            book.absent(destination,paths::APP_NAME)?; book.absent(versions,paths::RELEASE)?;
            let access = fcntl::fcntl(gate_fd,fcntl::FcntlArg::F_GETFL).map_err(|_| "worker-gate-flags")?;
            check(OFlag::from_bits_truncate(access) & OFlag::O_ACCMODE == OFlag::O_RDONLY, "worker-gate-readonly")?;
            let original = Identity::of(&stat::fstat(gate_fd).map_err(|_| "worker-gate-stat")?);
            check(init["gate"] == identity_data(original), "worker-gate-binding")?;
            let n = book.reserve(Some(destination),paths::MAINTENANCE_GATE_NAME,Role::GateParticipant)?;
            book.originals[n].state = State::Acquiring;
            let duplicated = gate_fd.try_clone_to_owned().map_err(|_| "worker-gate-duplicate");
            match duplicated {
                Ok(fd) => { book.adopt(n,Ok(fd))?; }
                Err(error) => { book.originals[n].state = State::NoHandle; return Err(error); }
            }
            book.originals[n].identity = Some(original);
            book.gate.entered = true; book.gate.parent = Some(destination); book.gate.participant = Some(n);
            book.gate_protected(n)?; gate_bytes(book.fd(n)?.as_fd(),book.shared_deadline()?)?;
            // Shape and bytes do not prove EX. Only the original parent's
            // admission/GO supplies that handoff; the worker never flocks.
            book.gate.verified = true;
            book.source_post(&source)?;
            Ok(PreparedFresh { input,inventory,inventory_bytes,destination,versions })
        }
        fn dispatch_private(args: &[String]) -> i32 {
            // Intentionally not called by the current ordinary or fixture run.
            // The deadline is decoded BEFORE the first potentially blocking read.
            let admitted = (|| {
                check(args.len() == 4 && args[1] == ROLE && invocation_valid(&args[3]), "worker-role")?;
                let end = args[2].parse::<u64>().map_err(|_| "worker-clock-value")?;
                check(args[2] == end.to_string(), "worker-clock-value")?;
                let clock = Deadline::inherit(end)?;
                check(unistd::getuid().is_root() && unistd::geteuid().is_root()
                    && unistd::getgid().as_raw() == 0 && unistd::getegid().as_raw() == 0, "administrator-required")?;
                native::platform().map_err(|_| "worker-platform")?;
                Ok((clock,end))
            })();
            let Ok((clock,end)) = admitted else { return 1; };
            let mut book = Install::with_worker_deadline(clock,true);
            let stdin = std::io::stdin(); let stdout = std::io::stdout(); let stderr = std::io::stderr();
            let mut init_sha = String::new();
            let attempt = (|| {
                let command_endpoint = pipe_data(stdin.as_fd(),false,book.shared_deadline()?)?;
                let result_endpoint = pipe_data(stdout.as_fd(),true,book.shared_deadline()?)?;
                nonblocking(stdin.as_fd(),book.shared_deadline()?)?; nonblocking(stdout.as_fd(),book.shared_deadline()?)?;
                let (init,bytes) = read_frame(stdin.as_fd(),INIT_LIMIT,book.shared_deadline()?)?;
                init_sha = hash(&bytes);
                let prepared = prepare_worker(&mut book,&init,stderr.as_fd(),&args[3],end)?;
                let parent = u32::try_from(unistd::getppid().as_raw()).map_err(|_| "worker-parent")?;
                let child = std::process::id();
                write_frame(stdout.as_fd(),&control("ready",&args[3],&init_sha,end,parent,child,&command_endpoint,&result_endpoint),
                    CONTROL_LIMIT,book.shared_deadline()?,true)?;
                let go = read_frame(stdin.as_fd(),CONTROL_LIMIT,book.shared_deadline()?)?.0;
                valid_control(&go,&control("go",&args[3],&init_sha,end,parent,child,&command_endpoint,&result_endpoint))?;
                command_eof(stdin.as_fd(),book.shared_deadline()?)?;
                check(command_endpoint == pipe_data(stdin.as_fd(),false,book.shared_deadline()?)?
                    && result_endpoint == pipe_data(stdout.as_fd(),true,book.shared_deadline()?)?, "worker-pipe-post")?;
                check(unistd::getppid().as_raw() == parent as i32, "worker-parent-changed")?;
                book.worker_go_eof = true; // Actual complete GO and EOF, not parsed permission DATA alone.
                book.install_prepared(prepared,&args[3])
            })();
            let result = book.finish(attempt);
            let outcome = PreExit::from_original(&book,&result);
            // No claim to have closed fd1/fd2 or joined ourselves. The parent's
            // actual EOF and original wait can later establish those facts.
            let sent = book.shared_deadline().and_then(|deadline|
                write_frame(stdout.as_fd(),&outcome.data(&args[3],&init_sha),RESULT_LIMIT,deadline,false));
            if sent.is_ok() { result.exit } else if result.exit == 0 { 1 } else { result.exit }
        }
        #[cfg(test)]
        mod tests {
            use super::*;
            #[test]
            fn same_absolute_endpoint_reserves_settlement_and_rejects_backwards_or_overflow() {
                let start = 20 * SECOND; let end = start + TOTAL;
                assert_eq!(time_data(start,end,start,start,true),Ok(start));
                assert!(time_data(start,end,start,end-SETTLEMENT,true).is_err());
                assert!(time_data(start,end,start,end-SETTLEMENT,false).is_ok());
                assert!(time_data(start,end,start,end,false).is_err());
                assert!(time_data(start,end,start+2,start+1,true).is_err());
                assert!(time_data(u64::MAX-10,5,u64::MAX-10,u64::MAX-10,false).is_err());
                assert!(time_data(start,end+1,start,start,true).is_err());
            }
            #[test]
            fn private_frames_require_fixed_binding_shapes_bounds_and_no_future_finality() {
                let invocation = "11111111111111111111111111111111"; let sha = "a".repeat(64);
                assert!(invocation_valid(invocation)); assert!(!invocation_valid(&"0".repeat(32)));
                let endpoint = json!({"device":0,"inode":14,"mode":0o010660,"uid":0,"gid":0});
                let opposite = json!({"device":0,"inode":15,"mode":0o010660,"uid":0,"gid":0});
                assert!(pipe_shape(&endpoint).is_ok() && pipe_shape(&opposite).is_ok());
                assert_ne!(endpoint,opposite); // Different Darwin endpoints are not equality evidence.
                let expected = control("go",invocation,&sha,TOTAL,10,11,&endpoint,&opposite);
                let encoded = frame(&expected,CONTROL_LIMIT).unwrap();
                assert_eq!(frame_size(&encoded[..4],CONTROL_LIMIT).unwrap(),encoded.len()-4);
                assert!(valid_control(&packet(&encoded[4..],CONTROL_LIMIT).unwrap(),&expected).is_ok());
                for field in ["invocation","initSha256","parent","child","endNanos","kind","writerCommandEndpoint","writerResultEndpoint"] {
                    let mut changed = expected.clone(); changed[field] = Value::Null;
                    assert!(valid_control(&changed,&expected).is_err());
                }
                assert!(packet(br#"{"kind":"go","kind":"go"}"#,CONTROL_LIMIT).is_err());
                assert!(frame_size(&0u32.to_be_bytes(),CONTROL_LIMIT).is_err());
                assert!(frame_size(&(CONTROL_LIMIT as u32+1).to_be_bytes(),CONTROL_LIMIT).is_err());
                let result = PreExit { exit:0,state:"installed".into(),originals:true,payload:true,verified:true,
                    runtime:"confirmed".into(),app:"confirmed".into(),timely:true,unknown:false,writes:1,bytes:1,reason:None };
                let data = result.data(invocation,&sha);
                assert!(PreExit::parse(&data,invocation,&sha).is_ok());
                for field in ["stdoutClosed","inheritedGateClosed","selfJoined"] {
                    let mut changed = data.clone(); changed[field] = json!(true);
                    assert!(PreExit::parse(&changed,invocation,&sha).is_err());
                }
                let mut extra = data.clone(); extra["trusted"] = json!(true);
                assert!(PreExit::parse(&extra,invocation,&sha).is_err());
                let mut private = data.clone(); private["reason"] = json!("/private/unexpected/value");
                assert!(PreExit::parse(&private,invocation,&sha).is_err());
                assert_eq!(closed_reason("/private/unexpected/value"),"other-original-refusal");
                assert!(PreExit::parse(&json!([]),invocation,&sha).is_err());
            }
            #[test]
            fn original_join_requires_eof_closes_matching_return_and_timely_sources() {
                assert!(joined_data(true,true,true,true,Some(0),0,true,true,false));
                for failed in 0..8 {
                    let mut facts = [true;7]; let mut wait = Some(0);
                    if failed < 7 { facts[failed] = false; } else { wait = None; }
                    assert!(!joined_data(facts[0],facts[1],facts[2],facts[3],wait,0,facts[4],facts[5],!facts[6]));
                }
                assert!(!joined_data(true,true,true,true,Some(1),0,true,true,false));
                // A known failure can be a genuinely joined failure, but never
                // becomes an applied/successful operation by joining alone.
                assert!(joined_data(true,true,true,true,Some(1),1,true,true,false));
                // Successful short writes count syscalls, not descriptor records.
                assert!(outcome_data(0,"installed",true,true,true,"confirmed","confirmed",true,false,24577,24577));
                assert!(!outcome_data(0,"installed",true,true,true,"confirmed","confirmed",true,false,24577,24576));
                assert!(!outcome_data(0,"installed",true,true,true,"confirmed","confirmed",true,false,
                    installation_record::PAYLOAD_LIMIT + 1, installation_record::PAYLOAD_LIMIT + 1));
                assert!(!outcome_data(1,"installed",true,true,true,"confirmed","confirmed",true,false,1,1));
                assert!(!outcome_data(20,"refused-staging-retained",true,true,false,"not-attempted","not-attempted",true,false,0,0));
                assert!(!outcome_data(1,"refused-staging-retained",true,false,false,"not-attempted","not-attempted",true,false,0,0));
                for (closed,timely,unknown,writes) in [(false,true,false,1),(true,false,false,1),
                    (true,true,true,1),(true,true,false,0)] {
                    assert!(!outcome_data(0,"installed",closed,true,true,"confirmed","confirmed",timely,unknown,writes,1));
                }
            }
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

    // Exactly eight separately named cases, inside the one approved standard
    // Installer fixture package. This module/entry/hooks do not exist in the
    // ordinary installer, and accept no scenario/destination/environment override.
    #[cfg(feature = "macos-installed-installer-fixture")]
    mod fixture {
        use super::*;
        const MARKER: &[u8] = b"MRK_MACOS_INSTALLER_FIXTURE_OCCUPANT\n";
        const BASE_PREFIX: &str = "MobileReleaseKit-InstallerFixture-";
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Case { OccupiedApp, OccupiedRelease, RuntimeCollision, StagingCollision, FirstOnly, BeforePersistence, AfterPersistence, MetadataCollision }
        const CASES: [Case; 8] = [Case::OccupiedApp, Case::OccupiedRelease, Case::RuntimeCollision, Case::StagingCollision,
            Case::FirstOnly, Case::BeforePersistence, Case::AfterPersistence, Case::MetadataCollision];
        impl Case {
            fn name(self) -> &'static str { match self {
                Self::OccupiedApp => "occupied-app", Self::OccupiedRelease => "occupied-release",
                Self::RuntimeCollision => "runtime-publication-collision", Self::StagingCollision => "staging-file-collision",
                Self::FirstOnly => "first-publication-second-refusal", Self::BeforePersistence => "prepublication-persistence-report",
                Self::AfterPersistence => "postruntime-persistence-report", Self::MetadataCollision => "metadata-descriptor-collision" } }
            fn expected(self) -> (&'static str, &'static str, &'static str, &'static str, bool, i32) { match self {
                Self::OccupiedApp | Self::OccupiedRelease => ("destination-occupied","not-attempted","not-attempted","refused-staging-retained",false,1),
                Self::RuntimeCollision => ("exclusive-publication-refused-or-unknown","occupied-refused","not-attempted","refused-staging-retained",true,1),
                Self::StagingCollision => ("open-refused","not-attempted","not-attempted","refused-staging-retained",false,1),
                Self::FirstOnly => ("exclusive-publication-refused-or-unknown","confirmed","occupied-refused","partial-installation-retained",true,20),
                Self::BeforePersistence => ("fixture-reported-persistence-failure","not-attempted","not-attempted","refused-staging-retained",false,1),
                Self::AfterPersistence => ("fixture-reported-persistence-failure","confirmed","not-attempted","partial-installation-retained",true,20),
                Self::MetadataCollision => ("open-refused","confirmed","not-attempted","partial-installation-retained",true,20) } }
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
            pub(super) fn fixture_before_descriptor(&mut self, release: usize) -> Result<()> {
                if self.fixture_case()? == Case::MetadataCollision {
                    self.absent(release, installation_record::RECORD_NAME)?;
                    self.fixture.as_mut().ok_or("fixture-context-missing")?.absence_observed = true;
                    let visible = format!("versions/{}/{}", paths::RELEASE, installation_record::RECORD_NAME);
                    let witness = self.fixture_file_occupant(release, installation_record::RECORD_NAME, Some(visible))?;
                    self.persist(release, false)?;
                    self.fixture.as_mut().ok_or("fixture-context-missing")?.witness = Some(witness);
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
                if ((context.case == Case::StagingCollision && original.role == Role::PayloadWriter)
                    || (context.case == Case::MetadataCollision && original.role == Role::MetadataWriter))
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
                Case::StagingCollision | Case::MetadataCollision => context.absence_observed && context.staging_errno == Some(Errno::EEXIST as i32),
                Case::RuntimeCollision | Case::FirstOnly => context.absence_observed && context.staging_errno.is_none(),
                _ => !context.absence_observed && context.staging_errno.is_none(),
            };
            let persistence_ok = match case {
                Case::BeforePersistence | Case::AfterPersistence => context.persistence.as_ref().is_some_and(|p|
                    p.native_ok && p.native_errno.is_none() && p.injected && p.point == if case == Case::BeforePersistence {
                        PersistPoint::BeforePublication } else { PersistPoint::AfterRuntimeRename }),
                _ => context.persistence.is_none(),
            };
            let metadata = install.metadata.snapshot(install.metadata_writers_settled());
            let metadata_ok = match case {
                Case::FirstOnly => metadata["state"] == "recorded" && metadata["openedFiles"] == 2,
                Case::MetadataCollision => metadata["state"] == "incomplete" && metadata["attemptedFiles"] == 2
                    && metadata["openedFiles"] == 1 && metadata["writtenBytes"].as_u64().is_some_and(|n| n > 0),
                _ => metadata["state"] == "not-attempted",
            };
            let passed = proof.is_ok() && occupant_ok && native_collision_ok && persistence_ok && metadata_ok && !install.unknown
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
